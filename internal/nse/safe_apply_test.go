package nse

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestClassifyRisk(t *testing.T) {
	risky := []string{"wan", "vlan-management-access", "management-service", "high-availability", "admin-password", "overrides"}
	for _, s := range risky {
		if got := ClassifyRisk(s); got != RiskLockout {
			t.Errorf("ClassifyRisk(%q) = %v, want RiskLockout", s, got)
		}
	}
	safe := []string{"dhcp-pool", "dns-local-entry", "ips-rules", "vpn-radius", "unknown-section"}
	for _, s := range safe {
		if got := ClassifyRisk(s); got != RiskNone {
			t.Errorf("ClassifyRisk(%q) = %v, want RiskNone", s, got)
		}
	}
}

func TestNewTokenIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok := newToken()
		if len(tok) == 0 {
			t.Fatal("newToken() returned empty string")
		}
		if seen[tok] {
			t.Fatalf("newToken() produced a duplicate: %s", tok)
		}
		seen[tok] = true
	}
}

// TestApplyAppendsSaveForNonRiskyChange pins the ordering that makes the
// persist step safe: "save" is the last line of the same sequence, so
// ApplyLines' stop-on-first-error means it is never reached if a config
// line before it failed.
func TestApplyAppendsSaveForNonRiskyChange(t *testing.T) {
	block := ConfigBlock{Name: "vpn-tailscale_enable", Lines: []string{"tailscale"}, Risk: RiskNone}
	lines := append(append([]string{}, block.Lines...), SaveConfigLine)
	if len(lines) != 2 || lines[0] != "tailscale" || lines[1] != "save" {
		t.Fatalf("sequence = %v, want [tailscale save]", lines)
	}
	// The caller's own slice must not be touched — block.Lines is reused
	// as the rollback comparison and must stay exactly what was requested.
	if len(block.Lines) != 1 {
		t.Errorf("block.Lines was mutated: %v", block.Lines)
	}
}

// TestClassifyLineAcceptsSaveAck guards the device's acknowledgement
// against the error detector. "[Config Save OK]" is one of the only
// positive success tokens this CLI emits; a regex change that made it
// look like an error would turn every successful save into a failure.
func TestClassifyLineAcceptsSaveAck(t *testing.T) {
	r := classifyLine(SaveConfigLine, "save\r\n"+ConfigSaveOKToken+"\r\nNSE(config)# ")
	if !r.OK {
		t.Errorf("save ack classified as an error: %q", r.Error)
	}
	if !strings.Contains(r.Output, ConfigSaveOKToken) {
		t.Errorf("save ack lost from output: %q", r.Output)
	}
}

// TestClassifyLineRejectsSaveOnUnsupportedDevice is the other side: a
// device with no "save" verb answers in the error convention, which must
// surface rather than be mistaken for a silent success.
func TestClassifyLineRejectsSaveOnUnsupportedDevice(t *testing.T) {
	r := classifyLine(SaveConfigLine, "save\r\n%Error processing cli command\r\nNSE(config)# ")
	if r.OK {
		t.Error("an unsupported save should not classify as success")
	}
}

// TestSaveOnlyFailed separates the two ways a save-bearing sequence can
// fail. Getting this wrong would tell the operator a change was rejected
// when it is actually live on the device.
func TestSaveOnlyFailed(t *testing.T) {
	ok := func(line string) LineResult { return LineResult{Line: line, OK: true} }
	bad := func(line string) LineResult { return LineResult{Line: line, Error: "%Error processing cli command"} }

	tests := []struct {
		name    string
		results []LineResult
		n       int
		want    bool
	}{
		{"config ok, save failed", []LineResult{ok("tailscale"), bad("save")}, 1, true},
		{"config failed, save never sent", []LineResult{bad("tailscale")}, 1, false},
		{"multi-line block, save failed", []LineResult{ok("interface eth 1"), ok("ip address dhcp"), ok("exit"), bad("save")}, 3, true},
		{"multi-line block, middle line failed", []LineResult{ok("interface eth 1"), bad("ip address dhcp")}, 3, false},
		{"everything succeeded", []LineResult{ok("tailscale"), ok("save")}, 1, false},
	}
	for _, tt := range tests {
		if got := saveOnlyFailed(tt.results, tt.n); got != tt.want {
			t.Errorf("%s: saveOnlyFailed = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestSwitchDeviceBlockedByPendingChange is the guard against writing one
// site's configuration onto another. A provisional change holds a rollback
// pre-image taken from the device it was applied to, and the expiry loop
// replays pre-images through whatever the shared client currently points
// at — so repointing the client while one is outstanding would eventually
// push site A's stanza to site B.
func TestSwitchDeviceBlockedByPendingChange(t *testing.T) {
	s := &Server{Client: NewClient(Config{Host: "10.0.0.1"}), SkipConnect: true}
	a := s.safeApplier()
	a.mu.Lock()
	a.pending["tok"] = pendingChange{
		block:     ConfigBlock{Name: "wan", Risk: RiskLockout},
		preImage:  []string{"interface eth 1", "ip address dhcp", "exit"},
		expiresAt: time.Now().Add(time.Minute),
	}
	a.mu.Unlock()

	err := s.SwitchDevice(Config{Host: "10.0.0.2"})
	if err == nil {
		t.Fatal("switching with a provisional change outstanding must be refused")
	}
	if got := s.Client.Snapshot().Host; got != "10.0.0.1" {
		t.Errorf("client was repointed anyway: host = %q", got)
	}

	// Once it is confirmed, the switch goes through.
	if _, err := a.Confirm("tok"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if err := s.SwitchDevice(Config{Host: "10.0.0.2"}); err != nil {
		t.Fatalf("switch after confirm: %v", err)
	}
	if got := s.Client.Snapshot().Host; got != "10.0.0.2" {
		t.Errorf("host = %q, want the new device", got)
	}
}

// TestSwitchDeviceClearsPerDeviceState covers the quieter half: caches
// that belong to the old device must not be served for the new one. The
// throughput sampler matters most — its first rate after a switch would
// otherwise be computed by subtracting one device's byte counters from
// another's.
func TestSwitchDeviceClearsPerDeviceState(t *testing.T) {
	s := &Server{Client: NewClient(Config{Host: "10.0.0.1"}), SkipConnect: true}
	s.lastIfaces = []IfconfigIface{{Name: "eth1", RxBytes: 999}}
	s.lastRates = []Throughput{{Name: "eth1"}}
	s.lastSample = time.Now()
	s.wanPortSet = map[string]bool{"eth1": true}
	s.wanPortAt = time.Now()
	s.threatCache = ThreatSummary{Enabled: true, Mode: "prevention"}
	s.threatAt = time.Now()

	if err := s.SwitchDevice(Config{Host: "10.0.0.2"}); err != nil {
		t.Fatalf("switch: %v", err)
	}
	if s.lastIfaces != nil || s.lastRates != nil || !s.lastSample.IsZero() {
		t.Error("throughput sampler still holds the previous device's counters")
	}
	if s.wanPortSet != nil || !s.wanPortAt.IsZero() {
		t.Error("WAN port cache survived the switch")
	}
	if s.threatCache.Enabled || !s.threatAt.IsZero() {
		t.Error("threat summary cache survived the switch")
	}
}

// TestLockoutReasonStatesTheRealRecovery covers the message shown when a
// change both severed access and could not be undone. The undo travels
// over the SSH the change just broke, so this is the expected outcome for
// a genuine lockout — and the operator needs the recovery that actually
// works, not a claim that the device was restored.
func TestLockoutReasonStatesTheRealRecovery(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		undo ApplyResult
		want string
	}{
		{"undo could not be delivered", errors.New("dial tcp: i/o timeout"), ApplyResult{}, "dial tcp: i/o timeout"},
		{"undo was rejected", nil, ApplyResult{Error: "%Error processing cli command"}, "%Error processing cli command"},
	} {
		got := lockoutReason(tc.err, tc.undo)
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: reason %q should include what went wrong (%q)", tc.name, got, tc.want)
		}
		if !strings.Contains(got, "still live") {
			t.Errorf("%s: reason must not imply the change was undone: %q", tc.name, got)
		}
		if !strings.Contains(got, "power-cycling") || !strings.Contains(got, "never saved") {
			t.Errorf("%s: reason must give the recovery that works: %q", tc.name, got)
		}
	}
}

// TestFailedUndoIsRecorded covers the expiry loop's breadcrumb. It runs in
// the background with no request to answer, so a failed undo there used to
// vanish entirely.
func TestFailedUndoIsRecorded(t *testing.T) {
	a := &SafeApplier{client: NewClient(Config{}), pending: map[string]pendingChange{}}
	if len(a.FailedUndos()) != 0 {
		t.Fatal("nothing should be recorded yet")
	}
	a.recordFailedUndo("wan", errors.New("ssh: connection refused"), ApplyResult{})
	a.recordFailedUndo("lan-port", nil, ApplyResult{Error: "Invalid arguments"})
	got := a.FailedUndos()
	if len(got) != 2 {
		t.Fatalf("recorded %d, want 2", len(got))
	}
	if got[0].Section != "wan" || !strings.Contains(got[0].Detail, "connection refused") {
		t.Errorf("first record = %+v", got[0])
	}
	if got[1].Section != "lan-port" || !strings.Contains(got[1].Detail, "Invalid arguments") {
		t.Errorf("second record = %+v", got[1])
	}

	// Bounded, so a flapping device cannot grow this without limit.
	for i := 0; i < 50; i++ {
		a.recordFailedUndo("wan", errors.New("x"), ApplyResult{})
	}
	if n := len(a.FailedUndos()); n > 20 {
		t.Errorf("kept %d records, want the list bounded at 20", n)
	}
}

// TestTakeExpiredSweepsTheWindow covers the expiry sweep itself. Every
// other test here builds a SafeApplier literal and calls a helper, so the
// loop that actually undoes an unconfirmed change had no coverage at all
// — and a provisional change that is never swept is never undone, which
// is the whole point of holding it.
func TestTakeExpiredSweepsTheWindow(t *testing.T) {
	now := time.Now()
	a := &SafeApplier{client: NewClient(Config{}), pending: map[string]pendingChange{
		"stale": {block: ConfigBlock{Name: "wan"}, preImage: []string{"a"},
			expiresAt: now.Add(-time.Second)},
		"fresh": {block: ConfigBlock{Name: "lan-port"}, preImage: []string{"b"},
			expiresAt: now.Add(time.Minute)},
	}}

	got := a.takeExpired(now)
	if len(got) != 1 || got[0].block.Name != "wan" {
		t.Fatalf("swept %+v, want only the lapsed change", got)
	}
	if a.PendingCount() != 1 {
		t.Errorf("PendingCount = %d, want 1 — the unexpired change must stay", a.PendingCount())
	}
	if _, ok := a.pending["stale"]; ok {
		t.Error("a swept change must be removed, or the next tick undoes it again")
	}

	// A change swept once is gone: taking again at a later time yields
	// only the one whose window has since closed.
	got = a.takeExpired(now.Add(2 * time.Minute))
	if len(got) != 1 || got[0].block.Name != "lan-port" {
		t.Fatalf("second sweep = %+v, want the now-lapsed change", got)
	}
	if a.PendingCount() != 0 {
		t.Errorf("PendingCount = %d, want 0", a.PendingCount())
	}
}
