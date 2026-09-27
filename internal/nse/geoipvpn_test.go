package nse

import (
	"strings"
	"testing"
)

// TestGeoIPNotConfiguredRulesItOut is the case seen on the live device: geo-ip
// appears nowhere in `show config` at all, and ParseGeoIP defaults both
// directions to "none". That is a definitive negative for the playbook's geo-ip
// node — no country check exists, so nothing can be dropped by one — and
// answering it from config is far better than letting the node read as a
// coin-flip and escalate.
func TestGeoIPNotConfiguredRulesItOut(t *testing.T) {
	inbound, outbound := ParseGeoIP("interface eth 1\n type wan\n!")
	if inbound.Mode != GeoIPModeNone || outbound.Mode != GeoIPModeNone {
		t.Fatalf("absent geo-ip config must default to none, got %q/%q", inbound.Mode, outbound.Mode)
	}

	got := GeoIPCouldDropTunnel(inbound, []string{"10.20.0.0/16"})
	if got.Possible {
		t.Error("mode none must not be reported as a possible cause")
	}
	if !strings.Contains(got.Reason, "not configured") {
		t.Errorf("reason should say it is unconfigured: %q", got.Reason)
	}
}

// TestGeoIPActiveWithUnlistedSubnetIsTheD10Precondition covers the positive
// case. Candidate D10's documented workaround is to add the tunnel's remote
// subnets to the inbound allowlist, so a remote subnet that is NOT in the
// allowlist while filtering is active is exactly the precondition.
func TestGeoIPActiveWithUnlistedSubnetIsTheD10Precondition(t *testing.T) {
	inbound := GeoIPDirection{
		Mode:      "allow",
		Countries: []string{"GB", "IE"},
		Exceptions: []IPRange{
			{StartIP: "203.0.113.0", EndIP: "203.0.113.255"},
		},
	}
	got := GeoIPCouldDropTunnel(inbound, []string{"10.20.0.0/16"})
	if !got.Possible {
		t.Fatal("an active filter with an unlisted remote subnet is the D10 precondition")
	}
	if len(got.Unprotected) != 1 || got.Unprotected[0] != "10.20.0.0/16" {
		t.Errorf("unprotected = %q", got.Unprotected)
	}
	// The reason must not overclaim: the precondition is not the outcome.
	if !strings.Contains(got.Reason, "precondition") {
		t.Errorf("reason must be framed as a precondition, not a confirmed drop: %q", got.Reason)
	}
	if !strings.Contains(got.Reason, "nft counters") {
		t.Errorf("reason should say what would actually confirm it: %q", got.Reason)
	}
}

// TestGeoIPAllowlistedSubnetIsExempt covers the mitigated case: filtering is on
// but the operator already applied the workaround.
func TestGeoIPAllowlistedSubnetIsExempt(t *testing.T) {
	inbound := GeoIPDirection{
		Mode: "block",
		Exceptions: []IPRange{
			{StartIP: "10.20.0.0", EndIP: "10.20.255.255"},
		},
	}
	got := GeoIPCouldDropTunnel(inbound, []string{"10.20.0.0/16"})
	if got.Possible {
		t.Errorf("a fully-allowlisted subnet must be exempt: %+v", got)
	}
	if len(got.Unprotected) != 0 {
		t.Errorf("unprotected = %q, want none", got.Unprotected)
	}
}

// TestGeoIPPartialOverlapIsNotCovered pins the deliberate strictness. A subnet
// only half inside the allowlist still has hosts the country check would
// reject, so calling it covered would hide a real cause.
func TestGeoIPPartialOverlapIsNotCovered(t *testing.T) {
	inbound := GeoIPDirection{
		Mode: "allow",
		Exceptions: []IPRange{
			// Covers only the lower half of 10.20.0.0/16.
			{StartIP: "10.20.0.0", EndIP: "10.20.127.255"},
		},
	}
	got := GeoIPCouldDropTunnel(inbound, []string{"10.20.0.0/16"})
	if !got.Possible {
		t.Error("a partially-covered subnet must still be reported as at risk")
	}
}

func TestGeoIPAllowlistCoverage(t *testing.T) {
	ranges := []IPRange{{StartIP: "10.0.0.0", EndIP: "10.0.255.255"}}
	for _, tc := range []struct {
		subnet string
		want   bool
		why    string
	}{
		{"10.0.1.0/24", true, "fully inside"},
		{"10.0.0.0/16", true, "exactly the range"},
		{"10.0.0.5", true, "single address inside"},
		{"10.1.0.0/16", false, "outside"},
		{"10.0.0.0/8", false, "wider than the range"},
		{"not-an-ip", false, "unparseable must not be claimed as covered"},
		{"2001:db8::/32", false, "IPv6 is not evaluated, so not claimed covered"},
	} {
		if got := geoIPAllowlistCovers(ranges, tc.subnet); got != tc.want {
			t.Errorf("%s (%s): got %v want %v", tc.subnet, tc.why, got, tc.want)
		}
	}
}

// TestGeoIPReversedAllowlistRange covers an allowlist entry stored with start
// and end the wrong way round; it should still be honoured rather than silently
// matching nothing.
func TestGeoIPReversedAllowlistRange(t *testing.T) {
	ranges := []IPRange{{StartIP: "10.0.255.255", EndIP: "10.0.0.0"}}
	if !geoIPAllowlistCovers(ranges, "10.0.1.0/24") {
		t.Error("a reversed start/end range should still cover addresses within it")
	}
}
