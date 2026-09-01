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
	case "wan", "lan-port", "vlan-management-access", "management-service", "high-availability", "admin-password", "outbound-filter", "geo-ip", "overrides":
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
}

// ApplyOutcome is returned to the API layer (and the frontend) after an
// apply attempt.
type ApplyOutcome struct {
	Status       string       `json:"status"` // applied | provisional | rejected | rolled_back
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

// SafeApplier is the safety mechanism behind every risky config change:
// snapshot, apply, verify the device is still reachable via a brand-new
// connection (not the shared session, which can survive `management ssh`
// being disabled and so proves nothing), and either auto-roll-back
// immediately on failure or hold the change provisional until a human
// confirms it within a short window.
type SafeApplier struct {
	client *Client

	mu      sync.Mutex
	pending map[string]pendingChange
}

// NewSafeApplier starts the background expiry loop that auto-rolls-back
// any provisional change never confirmed in time. Callers should keep the
// returned value for the lifetime of the server; there is no Stop, since
// the process exiting is the only time this needs to go away.
func NewSafeApplier(client *Client) *SafeApplier {
	a := &SafeApplier{client: client, pending: map[string]pendingChange{}}
	go a.expireLoop()
	return a
}

// Apply sends block.Lines. Non-risky blocks are applied directly. Risky
// blocks are snapshotted first; a partial failure is undone immediately,
// a full failure to reconnect afterward is rolled back immediately, and a
// successful, reachable change is held provisional pending Confirm.
func (a *SafeApplier) Apply(block ConfigBlock) (ApplyOutcome, error) {
	if block.Risk == RiskNone {
		result, err := a.client.ApplyLines(block.Lines, 20*time.Second)
		if err != nil {
			return ApplyOutcome{Status: "rejected", Reason: err.Error()}, err
		}
		if !result.OK {
			return ApplyOutcome{Status: "rejected", Reason: result.Error, Lines: result.Lines}, nil
		}
		return ApplyOutcome{Status: "applied", Lines: result.Lines}, nil
	}

	rawBefore, err := a.client.Run("show config", 25*time.Second)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("snapshotting config before risky change: %w", err)
	}
	preImage := ExtractStanza(rawBefore, block.Keys)

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
		_, _ = a.client.ApplyLines(preImage, 20*time.Second)
		return ApplyOutcome{Status: "rolled_back", Reason: "device unreachable after change", Lines: result.Lines}, nil
	}

	token := newToken()
	const window = 60 * time.Second
	a.mu.Lock()
	a.pending[token] = pendingChange{block: block, preImage: preImage, expiresAt: time.Now().Add(window)}
	a.mu.Unlock()
	return ApplyOutcome{Status: "provisional", ConfirmToken: token, ExpiresIn: int(window.Seconds()), Lines: result.Lines}, nil
}

// Confirm commits a provisional change, cancelling its auto-rollback.
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
	return ApplyOutcome{Status: "applied"}, nil
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
			_, _ = a.client.ApplyLines(pc.preImage, 20*time.Second)
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
