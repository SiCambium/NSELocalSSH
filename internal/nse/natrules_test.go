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
	nat := ParseNATRules(string(raw))
	forwards, snats := nat.PortForwards, nat.SourceNATs

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

	parsed := ParseNATRules(cfg)
	gotFwd, gotSnat := parsed.PortForwards, parsed.SourceNATs
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
	snats := ParseNATRules(cfg).SourceNATs
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

// TestNATOneOneLeavesSpelling pins the argument forms taken from the
// device's own context help. "lan-IP" is BARE here, as under
// port-forward-rule and unlike source-nat-rule, which puts the word
// "address" first — the single irregularity most likely to be tidied by
// someone reading only one of the three blocks.
func TestNATOneOneLeavesSpelling(t *testing.T) {
	got := NATOneOneLeaves(NATOneOneRule{
		LANIP: "192.168.200.50", PublicIP: "203.0.113.7", Protocol: "any",
		RuleName: "web_host", AllowedSourceType: AllowedSourceIPAddress,
		AllowedSource: "192.168.200.20-192.168.200.80",
	})
	want := []string{
		"lan-IP 192.168.200.50",
		"public-IP 203.0.113.7",
		"protocol any",
		"rule-name web_host",
		"allowed-sources ip-address 192.168.200.20-192.168.200.80",
	}
	if !slices.Equal(got, want) {
		t.Errorf("leaves =\n%q\nwant\n%q", got, want)
	}

	// Everything but the two addresses is optional.
	got = NATOneOneLeaves(NATOneOneRule{LANIP: "10.0.0.5", PublicIP: "203.0.113.9"})
	if want := []string{"lan-IP 10.0.0.5", "public-IP 203.0.113.9"}; !slices.Equal(got, want) {
		t.Errorf("minimal rule = %q, want %q", got, want)
	}
}

func TestValidateNATOneOne(t *testing.T) {
	ok := NATOneOneRule{LANIP: "192.168.200.50", PublicIP: "203.0.113.7"}
	if err := ValidateNATOneOne(ok); err != nil {
		t.Fatalf("minimal valid rule rejected: %v", err)
	}
	for _, r := range []NATOneOneRule{
		{LANIP: "192.168.200.0/24", PublicIP: "203.0.113.0/24"},
		{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", Protocol: "any"},
		{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", AllowedSourceType: AllowedSourceIPAddress, AllowedSource: "192.168.1.0/24"},
		{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", AllowedSourceType: AllowedSourceIPAddress, AllowedSource: "192.168.1.5-192.168.1.9"},
		{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", AllowedSourceType: AllowedSourceIPGroup, AllowedSource: "trusted"},
		{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", RuleName: "web_host_1"},
	} {
		if err := ValidateNATOneOne(r); err != nil {
			t.Errorf("valid rule %+v rejected: %v", r, err)
		}
	}

	for _, tc := range []struct {
		name string
		rule NATOneOneRule
	}{
		{"no lan ip", NATOneOneRule{PublicIP: "203.0.113.7"}},
		{"no public ip", NATOneOneRule{LANIP: "10.0.0.5"}},
		{"lan ip not an address", NATOneOneRule{LANIP: "not-an-ip", PublicIP: "203.0.113.7"}},
		{"protocol not offered by this block", NATOneOneRule{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", Protocol: "icmp"}},
		{"source without a type", NATOneOneRule{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", AllowedSource: "192.168.1.1"}},
		{"unknown source type", NATOneOneRule{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", AllowedSourceType: "mac", AllowedSource: "x"}},
		{"ip-group with no name", NATOneOneRule{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", AllowedSourceType: AllowedSourceIPGroup}},
		// A space would be read as the start of another argument.
		{"rule name with a space", NATOneOneRule{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", RuleName: "web host"}},
		// The device rejected "claude-test" with "rule-name may only
		// contain letters, digits, and underscores" — a hyphen is out,
		// which a generic no-whitespace guard would have let through.
		{"rule name with a hyphen", NATOneOneRule{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", RuleName: "claude-test"}},
		{"rule name with a dot", NATOneOneRule{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", RuleName: "web.host"}},
		{"rule name too long", NATOneOneRule{LANIP: "10.0.0.5", PublicIP: "203.0.113.7", RuleName: strings.Repeat("a", 65)}},
	} {
		if err := ValidateNATOneOne(tc.rule); err == nil {
			t.Errorf("%s: accepted, want rejected", tc.name)
		}
	}
}

// TestParseNATOneOne round-trips the block through the tree parser,
// including the two allowed-sources forms and a rule that sets only the
// required pair.
func TestParseNATOneOne(t *testing.T) {
	cfg := `interface eth 1
 type wan
 nat-one-one 1
   lan-IP 192.168.200.50
   public-IP 203.0.113.7
   protocol any
   rule-name web_host
   allowed-sources ip-address 192.168.200.20-192.168.200.80
 nat-one-one 2
   lan-IP 10.0.0.5
   public-IP 203.0.113.9
   allowed-sources ip-group trusted
 source-nat-rule 1
   lan-IP address 192.168.120.0/24
   public-IP 192.168.220.211-192.168.220.220
!`
	got := ParseNATRules(cfg).OneOne
	want := []NATOneOneRule{
		{Interface: "eth1", Index: 1, LANIP: "192.168.200.50", PublicIP: "203.0.113.7",
			Protocol: "any", RuleName: "web_host",
			AllowedSourceType: AllowedSourceIPAddress, AllowedSource: "192.168.200.20-192.168.200.80"},
		{Interface: "eth1", Index: 2, LANIP: "10.0.0.5", PublicIP: "203.0.113.9",
			AllowedSourceType: AllowedSourceIPGroup, AllowedSource: "trusted"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parsed\n%+v\nwant\n%+v", got, want)
	}

	// The sibling source-nat-rule keeps its own "address" spelling, and
	// its lan-IP must not be read as a bare one.
	if snats := ParseNATRules(cfg).SourceNATs; len(snats) != 1 || snats[0].LANSubnet != "192.168.120.0/24" {
		t.Errorf("sibling source-nat-rule misparsed: %+v", snats)
	}
}

func TestNATOneManyLeavesSpelling(t *testing.T) {
	got := NATOneManyLeaves(NATOneManyRule{
		LANIP: "192.168.120.98", LANPort: 443, PublicIP: "192.168.220.232", Port: 9443,
		Protocol: "tcp", RuleName: "web_dnat",
		AllowedSourceType: AllowedSourceIPGroup, AllowedSource: "trusted",
	})
	want := []string{
		"lan-IP 192.168.120.98",
		"lan-port 443",
		"public-IP 192.168.220.232",
		"port 9443",
		"protocol tcp",
		"rule-name web_dnat",
		"allowed-sources ip-group trusted",
	}
	if !slices.Equal(got, want) {
		t.Errorf("leaves =\n%q\nwant\n%q", got, want)
	}
}

func TestValidateNATOneMany(t *testing.T) {
	ok := NATOneManyRule{LANIP: "10.0.0.5", LANPort: 443, PublicIP: "203.0.113.7", Port: 9443, Protocol: "tcp"}
	if err := ValidateNATOneMany(ok); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*NATOneManyRule)
	}{
		{"no protocol — this block has no \"any\" to fall back on", func(r *NATOneManyRule) { r.Protocol = "" }},
		{"protocol any is not offered here", func(r *NATOneManyRule) { r.Protocol = "any" }},
		{"port out of range", func(r *NATOneManyRule) { r.Port = 0 }},
		{"lan port out of range", func(r *NATOneManyRule) { r.LANPort = 70000 }},
		{"lan ip not an address", func(r *NATOneManyRule) { r.LANIP = "nope" }},
		{"rule name with a hyphen", func(r *NATOneManyRule) { r.RuleName = "web-dnat" }},
		{"source value without a type", func(r *NATOneManyRule) { r.AllowedSource = "10.0.0.1" }},
	} {
		r := ok
		tc.mut(&r)
		if err := ValidateNATOneMany(r); err == nil {
			t.Errorf("%s: accepted, want rejected", tc.name)
		}
	}
}

// TestParseNATOneMany also guards the "port" / "lan-port" prefix overlap:
// a naive prefix match for "port " must not pick up "lan-port ".
func TestParseNATOneMany(t *testing.T) {
	cfg := `interface eth 1
 type wan
 nat-one-many 1
   lan-IP 192.168.120.98
   lan-port 443
   public-IP 192.168.220.232
   port 9443
   protocol tcp
   rule-name web_dnat
   allowed-sources ip-group trusted
 nat-one-one 1
   lan-IP 10.0.0.5
   public-IP 203.0.113.9
!`
	parsed := ParseNATRules(cfg)
	want := []NATOneManyRule{{
		Interface: "eth1", Index: 1,
		LANIP: "192.168.120.98", LANPort: 443,
		PublicIP: "192.168.220.232", Port: 9443,
		Protocol: "tcp", RuleName: "web_dnat",
		AllowedSourceType: AllowedSourceIPGroup, AllowedSource: "trusted",
	}}
	if !slices.Equal(parsed.OneMany, want) {
		t.Errorf("parsed\n%+v\nwant\n%+v", parsed.OneMany, want)
	}
	// The sibling 1:1 rule keeps its own identity and gains no ports.
	if len(parsed.OneOne) != 1 || parsed.OneOne[0].LANIP != "10.0.0.5" {
		t.Errorf("sibling nat-one-one misparsed: %+v", parsed.OneOne)
	}
}
