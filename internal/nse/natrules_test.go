package nse

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestParseNATRulesFromCapture reads the committed capture, which is the
// only evidence for this syntax.
func TestParseNATRulesFromCapture(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_subblocks.txt")
	if err != nil {
		t.Fatal(err)
	}
	forwards, snats := ParseNATRules(string(raw))

	wantFwd := []PortForwardRule{{
		Interface: "eth1", Index: 1, Port: 9090,
		LANIP: "10.0.0.50", Protocol: "tcp", LANPort: 9090,
	}}
	if !reflect.DeepEqual(forwards, wantFwd) {
		t.Errorf("port forwards = %+v, want %+v", forwards, wantFwd)
	}
	if len(snats) != 2 {
		t.Fatalf("source-NAT rules = %d, want 2", len(snats))
	}
	if snats[0].LANSubnet != "10.1.0.0/24" || snats[0].Overload != "disable" ||
		snats[0].PublicIP != "203.0.113.1-203.0.113.254" || snats[0].Index != 1 {
		t.Errorf("first source-NAT rule = %+v", snats[0])
	}
	if snats[1].Index != 2 || snats[1].LANSubnet != "10.2.0.0/24" {
		t.Errorf("second source-NAT rule = %+v", snats[1])
	}
}

// TestNATSpellingIsQuotedNotReconstructed is the test PR #25 described
// wanting and the reason this syntax is worth a capture at all: "lan-IP"
// and "public-IP" capitalise IP mid-word, and "lan-IP" takes a bare
// address under port-forward-rule but the word "address" first under
// source-nat-rule. Tidying either breaks the device, not the test's
// aesthetics.
func TestNATSpellingIsQuotedNotReconstructed(t *testing.T) {
	fwd := PortForwardLeaves(PortForwardRule{Port: 9090, LANIP: "10.0.0.50", Protocol: "tcp", LANPort: 9090})
	wantFwd := []string{"port 9090", "lan-IP 10.0.0.50", "protocol tcp", "lan-port 9090"}
	if !reflect.DeepEqual(fwd, wantFwd) {
		t.Errorf("port-forward leaves =\n  %v\nwant\n  %v", fwd, wantFwd)
	}
	snat := SourceNATLeaves(SourceNATRule{LANSubnet: "10.1.0.0/24", Overload: "disable", PublicIP: "203.0.113.1-203.0.113.254"})
	wantSnat := []string{"lan-IP address 10.1.0.0/24", "overload disable", "public-IP 203.0.113.1-203.0.113.254"}
	if !reflect.DeepEqual(snat, wantSnat) {
		t.Errorf("source-NAT leaves =\n  %v\nwant\n  %v", snat, wantSnat)
	}
	// Spelled out, so a bulk lowercase of the file fails here first.
	for _, line := range append(fwd, snat...) {
		if strings.Contains(line, "lan-ip") || strings.Contains(line, "public-ip") {
			t.Errorf("%q was tidied to lowercase; the device spells it lan-IP / public-IP", line)
		}
	}
	if fwd[1] == "lan-IP address 10.0.0.50" {
		t.Error("port-forward's lan-IP takes a bare address, not the word 'address' first")
	}
	if snat[0] == "lan-IP 10.1.0.0/24" {
		t.Error("source-NAT's lan-IP takes the word 'address' first")
	}
}

// TestSourceNATOverloadOptional matches the capture, where one rule
// carried no overload leaf at all.
func TestSourceNATOverloadOptional(t *testing.T) {
	got := SourceNATLeaves(SourceNATRule{LANSubnet: "10.1.0.0/24", PublicIP: "203.0.113.5"})
	want := []string{"lan-IP address 10.1.0.0/24", "public-IP 203.0.113.5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestRuleRoundTrip is the property the rollback path depends on: what we
// write parses back to what we started from.
func TestRuleRoundTrip(t *testing.T) {
	fwd := PortForwardRule{Interface: "eth2", Index: 3, Port: 443, LANIP: "10.0.0.9", Protocol: "tcp", LANPort: 8443}
	snat := SourceNATRule{Interface: "eth2", Index: 4, LANSubnet: "10.9.0.0/16", Overload: "enable", PublicIP: "203.0.113.7"}
	// Rendered the way the device prints it, not the way we send it. The
	// two differ: `show config` indents a block's contents and closes it
	// by the next sibling's indent, while the lines we send are flat and
	// carry an explicit "exit". Parsing reads the former.
	cfg := "interface eth 2\n type wan\n" +
		asDevicePrints("port-forward-rule 3", PortForwardLeaves(fwd)) +
		asDevicePrints("source-nat-rule 4", SourceNATLeaves(snat)) + "!\n"

	gotFwd, gotSnat := ParseNATRules(cfg)
	if len(gotFwd) != 1 || gotFwd[0] != fwd {
		t.Errorf("port forward round trip = %+v, want %+v", gotFwd, fwd)
	}
	if len(gotSnat) != 1 || gotSnat[0] != snat {
		t.Errorf("source NAT round trip = %+v, want %+v", gotSnat, snat)
	}
}

// asDevicePrints renders a rule block the way `show config` does: the
// header one level in, its contents deeper, and no explicit exit.
func asDevicePrints(header string, leaves []string) string {
	var b strings.Builder
	b.WriteString(" " + header + "\n")
	for _, l := range leaves {
		b.WriteString("   " + l + "\n")
	}
	return b.String()
}

func TestNextRuleIndexSkipsGaps(t *testing.T) {
	for _, tc := range []struct {
		used []int
		want int
	}{
		{nil, 1},
		{[]int{1}, 2},
		{[]int{1, 2, 4}, 3},
		{[]int{2, 3}, 1},
	} {
		if got := NextRuleIndex(tc.used); got != tc.want {
			t.Errorf("NextRuleIndex(%v) = %d, want %d", tc.used, got, tc.want)
		}
	}
}

func TestNATValidation(t *testing.T) {
	ok := PortForwardRule{Port: 80, LANIP: "10.0.0.5", Protocol: "tcp", LANPort: 8080}
	if err := ValidatePortForward(ok); err != nil {
		t.Errorf("valid rule rejected: %v", err)
	}
	for _, bad := range []PortForwardRule{
		{Port: 0, LANIP: "10.0.0.5", Protocol: "tcp", LANPort: 80},
		{Port: 80, LANIP: "", Protocol: "tcp", LANPort: 80},
		{Port: 80, LANIP: "not-an-ip", Protocol: "tcp", LANPort: 80},
		{Port: 80, LANIP: "10.0.0.5", Protocol: "sctp", LANPort: 80},
		{Port: 80, LANIP: "10.0.0.5", Protocol: "tcp", LANPort: 70000},
	} {
		if err := ValidatePortForward(bad); err == nil {
			t.Errorf("invalid rule accepted: %+v", bad)
		}
	}

	if err := ValidateSourceNAT(SourceNATRule{LANSubnet: "10.1.0.0/24", PublicIP: "203.0.113.1-203.0.113.254"}); err != nil {
		t.Errorf("valid source NAT rejected: %v", err)
	}
	for _, bad := range []SourceNATRule{
		{LANSubnet: "10.1.0.0", PublicIP: "203.0.113.1"},
		{LANSubnet: "10.1.0.0/24", PublicIP: ""},
		{LANSubnet: "10.1.0.0/24", PublicIP: "nope"},
		{LANSubnet: "10.1.0.0/24", PublicIP: "203.0.113.1", Overload: "maybe"},
	} {
		if err := ValidateSourceNAT(bad); err == nil {
			t.Errorf("invalid source NAT accepted: %+v", bad)
		}
	}
}

// TestOverloadAbsentMeansEnabled pins the convention a live write test
// established: the device prints "overload disable" but prints nothing at
// all when overload is on. Reading an absent leaf as unknown — or as
// disabled — reports the opposite of what the rule does.
func TestOverloadAbsentMeansEnabled(t *testing.T) {
	cfg := `interface eth 1
 type wan
 source-nat-rule 1
   lan-IP address 192.168.120.0/24
   public-IP 192.168.220.211-192.168.220.220
 source-nat-rule 2
   lan-IP address 192.168.209.0/24
   overload disable
   public-IP 192.168.109.1-192.168.109.254
!`
	_, snats := ParseNATRules(cfg)
	if len(snats) != 2 {
		t.Fatalf("parsed %d rules, want 2", len(snats))
	}
	if snats[0].Overload != OverloadEnabled {
		t.Errorf("rule with no overload leaf = %q, want %q — absence is the default, and the default is on",
			snats[0].Overload, OverloadEnabled)
	}
	if snats[1].Overload != OverloadDisabled {
		t.Errorf("rule with an explicit leaf = %q, want %q", snats[1].Overload, OverloadDisabled)
	}
}

// TestAddCarriesAnExplicitInverse covers the defect that safe-apply's
// default rollback cannot reach. Its pre-image is a snapshot of the
// stanza taken *before* the change, so it can restore a leaf that was
// edited but has no way to remove an entity that did not exist when it
// was taken. Proved live: a port-forward add was left unconfirmed, the
// window lapsed, the undo reported OK, and the rule was still there.
func TestAddCarriesAnExplicitInverse(t *testing.T) {
	add := natRuleBlock(1, "port-forward-add",
		BuildRuleLines("port-forward-rule 2", PortForwardLeaves(PortForwardRule{
			Port: 9443, LANIP: "10.1.3.251", Protocol: "tcp", LANPort: 443})),
		[]string{RuleDeleteLine("port-forward-rule", 2)})

	want := []string{"interface eth 1", "no port-forward-rule 2", "exit"}
	if !slices.Equal(add.Undo, want) {
		t.Errorf("undo = %q, want %q — an add is only undone by a delete", add.Undo, want)
	}

	// A delete needs no explicit inverse: its pre-image does contain the
	// rule, so replaying the stanza recreates it at the same index.
	del := natRuleBlock(1, "port-forward-delete",
		[]string{RuleDeleteLine("port-forward-rule", 2)}, nil)
	if del.Undo != nil {
		t.Errorf("delete undo = %q, want none — the stanza pre-image restores it", del.Undo)
	}
}

// TestKeylessBlockHasNoPreImage pins why the geo-ip actions have to build
// their own inverse. That block carried no Keys, and a Keys-less block
// snapshots nothing at all — so its rollback was sending zero lines and
// reporting success, for a change classified as lockout-risk precisely
// because blocking your own country locks you out.
func TestKeylessBlockHasNoPreImage(t *testing.T) {
	raw := "firewall geo-ip-restrictions inbound mode block\nfirewall geo-ip-restrictions inbound countries CN,RU\n"
	if got := ExtractStanza(raw, nil); len(got) != 0 {
		t.Fatalf("ExtractStanza with no keys = %q, want empty", got)
	}
}
