package nse

import "testing"

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
