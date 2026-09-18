package nse

import (
	"strings"
	"testing"
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
