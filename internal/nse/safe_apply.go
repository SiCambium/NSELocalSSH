package nse

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// RiskLevel classifies whether a config change could plausibly cut off
// management access to the device if it goes wrong.
type RiskLevel int

const (
	RiskNone RiskLevel = iota
	RiskLockout
)

// ClassifyRisk maps a change's section name to a RiskLevel. WAN interface
// edits, physical LAN port switchport/shutdown edits, a VLAN's
// management-access flag, management ssh/https/http toggles, HA, the
// admin password, outbound filter rule edits, GEO IP filtering, and the
// free-text CLI overrides are all RiskLockout — the overrides are
// unparseable ahead of time, so they can never be judged safe by
// inspection; a LAN port's VLAN/trunk assignment can plausibly carry the
// session doing the editing (e.g. the local 172.23.0.1 UI wired directly
// into that port); a wrong filter rule (or a botched delete-and-recreate
// reorder) can block the traffic carrying the session doing the editing
// just as easily as a WAN or management-access mistake can; and GEO IP
// filtering in "allow only" mode with the wrong country list (or none at
// all) can cut off remote management from the operator's own location.
func ClassifyRisk(section string) RiskLevel {
	switch section {
	case "wan", "lan-port", "vlan-management-access", "vlan-inter-vlan-routing", "management-service", "high-availability", "admin-password", "outbound-filter", "geo-ip", "overrides":
		return RiskLockout
	default:
		return RiskNone
	}
}

// ConfigBlock is one change to apply: the CLI lines to send, its risk
// level, and (for risky changes) the top-level keys ExtractStanza should
// use to pull a rollback pre-image out of a `show config` snapshot taken
// just before applying.
type ConfigBlock struct {
	Name  string
	Lines []string
	Risk  RiskLevel
	Keys  []string

	// Undo, when set, replaces the stanza pre-image as the rollback.
	//
	// Replaying the pre-image only works for settings the device states
	// explicitly. A flag whose enabled state is the *absence* of a leaf —
	// inter-vlan-routing and port-scan both work this way — cannot be
	// restored by replaying a stanza that never mentioned it: the lines
	// apply cleanly, the undo reports OK, and nothing changes. Verified
	// live: disabling inter-VLAN routing on a VLAN and letting the confirm
	// window lapse left the change in place.
	//
	// Callers that own such a flag pass the explicit inverse here.
	Undo []string
}

// saveOnlyFailed reports whether every one of a block's own config lines
// succeeded and only the trailing SaveConfigLine did not. n is the number
// of config lines the block asked for, so results[n] is the save.
func saveOnlyFailed(results []LineResult, n int) bool {
	if len(results) != n+1 || results[n].OK {
		return false
	}
	for _, r := range results[:n] {
		if !r.OK {
			return false
		}
	}
	return true
}

func saveFailedReason(detail string) string {
	if detail == "" {
		detail = "device did not acknowledge the save"
	}
	return "change is live, but saving it to the startup config failed (it will not survive a reboot): " + detail
}

// ApplyOutcome is returned to the API layer (and the frontend) after an
// apply attempt.
type ApplyOutcome struct {
	Status       string       `json:"status"` // applied | provisional | rejected | rolled_back | unreachable
	Reason       string       `json:"reason,omitempty"`
	ConfirmToken string       `json:"confirm_token,omitempty"`
	ExpiresIn    int          `json:"expires_in,omitempty"`
	Lines        []LineResult `json:"lines,omitempty"`
}

type pendingChange struct {
	block     ConfigBlock
	preImage  []string
	expiresAt time.Time
}

// SafeApplier reduces the damage a risky config change can do: snapshot,
// apply, verify the device still accepts a brand-new connection (not the
// shared session, which can survive `management ssh` being disabled and so
// proves nothing), then hold the change provisional until a human confirms
// it within a short window, undoing it otherwise.
//
// Be precise about what this can and cannot do. The undo is delivered over
// SSH to the device being changed. If the change is one that severed
// access — which is the entire category this exists for — the undo cannot
// be delivered either, and no amount of retrying changes that. This
// mechanism reliably catches a change that is wrong but leaves the device
// reachable; it cannot rescue one that locks you out.
//
// What covers the lockout case is that a lockout-risk change is never
// written to the startup config until confirmed, so the device still boots
// the previous configuration and a power-cycle recovers it. That is the
// safety net worth relying on, and it is the one this code must not
// undermine by saving a change before it is confirmed.
// FailedUndo records an automatic undo that did not land. There is
// nowhere else for this to surface: the expiry loop runs in the
// background with no HTTP request to answer, and the operator may well be
// looking at a device they can no longer reach.
type FailedUndo struct {
	Section string    `json:"section"`
	At      time.Time `json:"at"`
	Detail  string    `json:"detail"`
}

type SafeApplier struct {
	client *Client

	mu      sync.Mutex
	pending map[string]pendingChange

	failedMu sync.Mutex
	failed   []FailedUndo
}

// recordFailedUndo stores an undo failure for FailedUndos to report.
func (a *SafeApplier) recordFailedUndo(section string, err error, undo ApplyResult) {
	detail := "the undo did not complete"
	switch {
	case err != nil:
		detail = err.Error()
	case undo.Error != "":
		detail = undo.Error
	}
	a.failedMu.Lock()
	defer a.failedMu.Unlock()
	// Bounded: this is a breadcrumb trail, not a log.
	if len(a.failed) >= 20 {
		a.failed = a.failed[1:]
	}
	a.failed = append(a.failed, FailedUndo{Section: section, At: time.Now(), Detail: detail})
}

// FailedUndos returns the undo failures recorded so far, oldest first.
func (a *SafeApplier) FailedUndos() []FailedUndo {
	a.failedMu.Lock()
	defer a.failedMu.Unlock()
	return append([]FailedUndo(nil), a.failed...)
}

// NewSafeApplier starts the background expiry loop that undoes any
// provisional change never confirmed in time — where it can; see the type
// comment for when it cannot. Callers should keep the
// returned value for the lifetime of the server; there is no Stop, since
// the process exiting is the only time this needs to go away.
func NewSafeApplier(client *Client) *SafeApplier {
	a := &SafeApplier{client: client, pending: map[string]pendingChange{}}
	go a.expireLoop()
	return a
}

// Apply sends block.Lines. Non-risky blocks are applied directly. Risky
// blocks are snapshotted first; a partial failure is undone immediately,
// a change after which the device stops answering is reported as such
// (the undo is attempted, never assumed — see lockoutReason), and a
// successful, reachable change is held provisional pending Confirm.
//
// Persisting to the startup config (SaveConfigLine) is deliberately
// asymmetric:
//
//   - A non-risky change is saved as part of the same sequence.
//   - A risky change is NOT saved until Confirm. Saving a change that is
//     still provisional would defeat the whole mechanism: if it turned out
//     to have cut off management access, the bad config would already be
//     the one the device boots into, and a power-cycle — the operator's
//     last resort — would restore it rather than escape it.
//   - No rollback path saves. The startup config is still the pre-change
//     one, which is exactly what a rollback is trying to get back to, so
//     there is nothing to persist and a save would only risk capturing a
//     half-undone state.
//
// The upshot is the one guarantee this code can actually make: an
// unconfirmed lockout-risk change never reaches persistent storage, so a
// power-cycle undoes it even when nothing can reach the device over the
// network.
func (a *SafeApplier) Apply(block ConfigBlock) (ApplyOutcome, error) {
	if block.Risk == RiskNone {
		// SaveConfigLine rides along in the same sequence so it is sent
		// only if every config line before it succeeded — ApplyLines stops
		// at the first error — and so the UI sees its result alongside
		// theirs.
		lines := append(append([]string{}, block.Lines...), SaveConfigLine)
		result, err := a.client.ApplyLines(lines, 20*time.Second)
		if err != nil {
			return ApplyOutcome{Status: "rejected", Reason: err.Error()}, err
		}
		if !result.OK {
			// ApplyLines reports the whole sequence as failed if any line
			// failed, but the two failures mean opposite things to the
			// operator: a config line failing means nothing took effect,
			// while only the trailing save failing means the change IS
			// live and merely won't survive a reboot. Calling the second
			// one "rejected" would invite a retry of a change that already
			// applied.
			if saveOnlyFailed(result.Lines, len(block.Lines)) {
				return ApplyOutcome{Status: "applied", Reason: saveFailedReason(result.Error), Lines: result.Lines}, nil
			}
			return ApplyOutcome{Status: "rejected", Reason: result.Error, Lines: result.Lines}, nil
		}
		return ApplyOutcome{Status: "applied", Lines: result.Lines}, nil
	}

	rawBefore, err := a.client.Run("show config", 25*time.Second)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("snapshotting config before risky change: %w", err)
	}
	preImage := ExtractStanza(rawBefore, block.Keys)
	if len(block.Undo) > 0 {
		preImage = block.Undo
	}

	result, err := a.client.ApplyLines(block.Lines, 20*time.Second)
	if err != nil {
		return ApplyOutcome{}, err
	}
	if !result.OK {
		// Partial failure: undo whatever went through before returning.
		_, _ = a.client.ApplyLines(preImage, 20*time.Second)
		return ApplyOutcome{Status: "rejected", Reason: result.Error, Lines: result.Lines}, nil
	}

	if !a.checkReachable() {
		// The undo is attempted — the device may have become reachable
		// again in the meantime — but it travels over the same SSH the
		// change just broke, so it is reported on, never assumed.
		undo, err := a.client.ApplyLines(preImage, 20*time.Second)
		if err != nil || !undo.OK {
			return ApplyOutcome{
				Status: "unreachable",
				Reason: lockoutReason(err, undo),
				Lines:  result.Lines,
			}, nil
		}
		return ApplyOutcome{Status: "rolled_back", Reason: "device stopped answering after the change, so it was undone", Lines: result.Lines}, nil
	}

	token := newToken()
	const window = 60 * time.Second
	a.mu.Lock()
	a.pending[token] = pendingChange{block: block, preImage: preImage, expiresAt: time.Now().Add(window)}
	a.mu.Unlock()
	return ApplyOutcome{Status: "provisional", ConfirmToken: token, ExpiresIn: int(window.Seconds()), Lines: result.Lines}, nil
}

// lockoutReason explains a change that both broke access to the device
// and could not be undone, and says what will actually recover it.
//
// The undo has to travel over the same SSH the change just broke, so in
// the one situation this whole mechanism exists for it cannot run. What
// does recover the device is that a lockout-risk change is never written
// to the startup config until it is confirmed (see Apply): the device
// still boots the previous configuration.
func lockoutReason(err error, undo ApplyResult) string {
	detail := "the device stopped answering"
	switch {
	case err != nil:
		detail += " and the undo could not be delivered: " + err.Error()
	case undo.Error != "":
		detail += " and the undo was rejected: " + undo.Error
	}
	return detail + ". The change is still live on the device. It was never saved to the " +
		"startup configuration, so power-cycling the device restores the configuration from " +
		"before this change; recovering any other way needs console or physical access."
}

// PendingCount reports how many changes are applied but still awaiting
// confirmation. A provisional change is tied to the device it was applied
// to — its rollback pre-image is that device's config — so the connection
// must not be repointed while one is outstanding. See Server.SwitchDevice.
func (a *SafeApplier) PendingCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}

// Confirm commits a provisional change, cancelling its auto-rollback and
// persisting it to the startup config — the first point at which a
// lockout-risk change has been proven survivable and is therefore safe to
// make permanent.
//
// A save that fails here is reported but does not undo anything: the
// change is confirmed and live in the running config either way, and the
// operator has already said they want it. The distinction that matters to
// them is "kept, but will not survive a reboot", so it is surfaced as a
// reason on an otherwise successful outcome rather than as an error.
func (a *SafeApplier) Confirm(token string) (ApplyOutcome, error) {
	a.mu.Lock()
	_, ok := a.pending[token]
	if ok {
		delete(a.pending, token)
	}
	a.mu.Unlock()
	if !ok {
		return ApplyOutcome{}, fmt.Errorf("no pending change for that token (already confirmed, rolled back, or expired)")
	}
	result, err := a.client.ApplyLines([]string{SaveConfigLine}, 20*time.Second)
	switch {
	case err != nil:
		return ApplyOutcome{Status: "applied", Reason: saveFailedReason(err.Error())}, nil
	case !result.OK:
		return ApplyOutcome{Status: "applied", Reason: saveFailedReason(result.Error), Lines: result.Lines}, nil
	}
	return ApplyOutcome{Status: "applied", Lines: result.Lines}, nil
}

func (a *SafeApplier) expireLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.mu.Lock()
		now := time.Now()
		var expired []pendingChange
		for token, pc := range a.pending {
			if now.After(pc.expiresAt) {
				expired = append(expired, pc)
				delete(a.pending, token)
			}
		}
		a.mu.Unlock()
		for _, pc := range expired {
			undo, err := a.client.ApplyLines(pc.preImage, 20*time.Second)
			if err != nil || !undo.OK {
				// Same limitation as the unreachable branch in Apply: if
				// the change took the device away, this cannot bring it
				// back. Record it so the failure is not silent.
				a.recordFailedUndo(pc.block.Name, err, undo)
			}
		}
	}
}

// checkReachable proves the device accepts a brand-new SSH login — not
// merely that the shared session's already-open channel is still alive,
// since an already-authenticated channel can survive `management ssh`
// being disabled and so would prove nothing about the failure mode this
// exists to catch.
func (a *SafeApplier) checkReachable() bool {
	cfg := a.client.Snapshot()
	for i := 0; i < 3; i++ {
		if probeSSH(cfg, 8*time.Second) {
			return true
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

func probeSSH(cfg Config, timeout time.Duration) bool {
	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.Password)},
		HostKeyCallback: TrustedHostKeyCallback(KnownHostsPath()),
		Timeout:         timeout,
	}
	conn, err := ssh.Dial("tcp", cfg.Addr(), sshCfg)
	if err != nil {
		return false
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()
	return true
}

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
