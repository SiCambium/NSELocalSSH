package nse

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// flattenRaw extracts the semantic content lines from a raw show-config
// dump: every leaf/header line, normalized, in order, skipping the
// bookkeeping tokens ("!", "exit") and blank lines that only exist to
// signal structure rather than carry content.
func flattenRaw(t *testing.T, raw string) []string {
	t.Helper()
	var out []string
	for _, line := range linesOf(raw, "show config") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "!" || trimmed == "exit" {
			continue
		}
		out = append(out, normalizeSpaces(trimmed))
	}
	return out
}

// flattenTree walks a parsed Block depth-first and extracts the same
// content: every block header (when it's opened) and every leaf line, in
// traversal order.
func flattenTree(b *Block) []string {
	var out []string
	for _, child := range b.Children {
		if child.Block != nil {
			out = append(out, child.Block.Header)
			out = append(out, flattenTree(child.Block)...)
		} else {
			out = append(out, normalizeSpaces(child.Line))
		}
	}
	return out
}

func assertRoundTrip(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tree := ParseBlockTree(string(raw))
	want := flattenRaw(t, string(raw))
	got := flattenTree(tree)
	if len(want) != len(got) {
		t.Fatalf("%s: content line count mismatch: raw=%d parsed=%d\nraw=%v\nparsed=%v", path, len(want), len(got), want, got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("%s: content mismatch at line %d:\n  raw:    %q\n  parsed: %q", path, i, want[i], got[i])
		}
	}
}

func TestParseBlockTreeRoundTripFull(t *testing.T) {
	assertRoundTrip(t, "testdata/show_config_full.txt")
}

func TestParseBlockTreeRoundTripLAN(t *testing.T) {
	assertRoundTrip(t, "testdata/show_config_lan.txt")
}

func TestParseBlockTreeRoundTripSubBlocks(t *testing.T) {
	assertRoundTrip(t, "testdata/show_config_subblocks.txt")
}

// TestParseBlockTreeIndentedSubBlocks covers the contexts this device
// opens without any name the parser could know in advance. The capture
// mirrors the structures of a live firmware-2.3-r6 unit (values
// generalized): port-forward/source-nat rules nested in an interface and
// closed only by the next sibling's indent, a "wireguard" context inside
// vpn-server, and an "ike-eap" context entered and left immediately.
func TestParseBlockTreeIndentedSubBlocks(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_subblocks.txt")
	if err != nil {
		t.Fatal(err)
	}
	tree := ParseBlockTree(string(raw))

	eth1 := tree.Find("interface eth 1")
	if eth1 == nil {
		t.Fatal("interface eth 1 not parsed as a block")
	}
	// Each rule is its own block and a sibling of the others — not
	// swallowed by the rule before it, which is what a flat parse did.
	if n := len(eth1.FindAll("source-nat-rule ")); n != 2 {
		t.Errorf("source-nat-rule blocks under eth1 = %d, want 2", n)
	}
	pf := eth1.Find("port-forward-rule 1")
	if pf == nil {
		t.Fatal("port-forward-rule 1 not parsed as a block")
	}
	if _, ok := pf.Leaf("lan-port 9090"); !ok {
		t.Error("port-forward-rule 1 lost its own children")
	}
	if snat := eth1.Find("source-nat-rule 1"); snat == nil {
		t.Error("source-nat-rule 1 was swallowed by port-forward-rule 1")
	} else if _, ok := snat.Leaf("overload disable"); !ok {
		t.Error("source-nat-rule 1 lost its children")
	}

	// A sub-context's implicit end must not pop its parent: every rule
	// block has to come back out inside eth1, so the stanza stays whole.
	lines := ExtractStanza(string(raw), []string{"interface eth 1"})
	if lines[len(lines)-1] != "exit" || !slices.Contains(lines, "public-IP 203.0.113.1-203.0.113.254") {
		t.Errorf("eth1 rollback stanza is not self-contained:\n%s", strings.Join(lines, "\n"))
	}
}

// TestParseBlockTreeStrayExitKeepsParent is the regression test for the
// damaging half of the old behavior: an unrecognized context's "exit"
// used to pop the nearest *recognized* ancestor instead, silently
// truncating the rollback pre-image for a section that was never at fault.
func TestParseBlockTreeStrayExitKeepsParent(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_subblocks.txt")
	if err != nil {
		t.Fatal(err)
	}
	vpn := ParseBlockTree(string(raw)).Find("vpn-server")
	if vpn == nil {
		t.Fatal("vpn-server not parsed as a block")
	}
	// "ike-eap" is entered and left immediately — a real, empty context.
	// Read as a leaf, its "exit" would close vpn-server and drop
	// everything after it.
	if ike := vpn.Find("ike-eap"); ike == nil {
		t.Error("ike-eap should be an (empty) block, not a leaf")
	} else if len(ike.Children) != 0 {
		t.Errorf("ike-eap should have no children, got %d", len(ike.Children))
	}
	wg := vpn.Find("wireguard")
	if wg == nil {
		t.Fatal("vpn-server lost its wireguard sub-block")
	}
	if _, ok := wg.Leaf("listen-port 1"); !ok {
		t.Error("wireguard sub-block lost its children")
	}
}

// TestParseBlockTreeBareKeywordStaysLeaf is the other side of the coin:
// the same "wireguard" keyword is a context in vpn-server and a plain flag
// under vpn-client and radius-server users-list. Only indentation tells
// them apart, which is why this can't be a blockOpeners entry.
func TestParseBlockTreeBareKeywordStaysLeaf(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_subblocks.txt")
	if err != nil {
		t.Fatal(err)
	}
	tree := ParseBlockTree(string(raw))
	client := tree.Find("vpn-client")
	if client == nil {
		t.Fatal("vpn-client not parsed as a block")
	}
	if client.Find("wireguard") != nil {
		t.Error("the bare \"wireguard\" flag under vpn-client became a block")
	}
	if _, ok := client.Leaf("wireguard full-tunnel"); !ok {
		t.Error("vpn-client lost its wireguard leaves")
	}
	users := tree.Find("radius-server users-list 10")
	if users == nil {
		t.Fatal("radius-server users-list 10 not parsed as a block")
	}
	if u := users.Find("wireguard-user 1"); u == nil {
		t.Error("wireguard-user 1 should be a block")
	} else if _, ok := u.Leaf("ip-address 10.10.100.2"); !ok {
		t.Error("wireguard-user 1 lost its children")
	}
}

func TestParseBlockTreeRoundTripTunnels(t *testing.T) {
	assertRoundTrip(t, "testdata/show_config_tunnels.txt")
}

func TestParseBlockTreeNesting(t *testing.T) {
	raw := `show config
!
interface eth 1
 type wan
 wan-name wan1
!
dns-server
 filter-mode filtering
 dns-filter policy 1
    name Ad_Blocking
    deny-categories malware-sites
    exit
 no dns-override
!
filter  global-filter
  stateful
  filter precedence 1
     rule-name rule_1
     exit
!
NSE-Caravan(config)# `

	tree := ParseBlockTree(raw)

	eth1 := tree.Find("interface eth 1")
	if eth1 == nil {
		t.Fatal("expected interface eth 1 block")
	}
	if line, ok := eth1.Leaf("wan-name"); !ok || line != "wan-name wan1" {
		t.Fatalf("wan-name leaf = %q, %v", line, ok)
	}

	dnsSrv := tree.Find("dns-server")
	if dnsSrv == nil {
		t.Fatal("expected dns-server block")
	}
	if _, ok := dnsSrv.Leaf("no dns-override"); !ok {
		t.Fatal("expected 'no dns-override' leaf inside dns-server, not swallowed by the nested policy block")
	}
	policy := dnsSrv.Find("dns-filter policy 1")
	if policy == nil {
		t.Fatal("expected nested dns-filter policy 1 block")
	}
	if _, ok := policy.Leaf("name Ad_Blocking"); !ok {
		t.Fatal("expected name leaf inside dns-filter policy 1")
	}

	// Double-space quirk ("filter  global-filter") must still be recognized
	// and normalized in the header.
	gf := tree.Find("filter global-filter")
	if gf == nil {
		t.Fatal("expected filter global-filter block despite double-space in source")
	}
	if p1 := gf.Find("filter precedence 1"); p1 == nil {
		t.Fatal("expected nested filter precedence 1 block")
	}
}

func TestBlockToLinesAlwaysEmitsExit(t *testing.T) {
	raw := `show config
!
interface eth 3
 type lan
 switchport mode access
 switchport access vlan 1
!
NSE-Caravan(config)# `
	tree := ParseBlockTree(raw)
	lines := tree.ToLines()
	want := []string{
		"interface eth 3",
		"type lan",
		"switchport mode access",
		"switchport access vlan 1",
		"exit",
	}
	if len(lines) != len(want) {
		t.Fatalf("ToLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("ToLines()[%d] = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestExtractStanza(t *testing.T) {
	raw := `show config
!
hostname NSE-Caravan
!
interface eth 1
 type wan
 wan-name wan1
!
interface eth 2
 type wan
 wan-name wan2
!
NSE-Caravan(config)# `
	got := ExtractStanza(raw, []string{"interface eth 1", "hostname"})
	want := []string{
		"interface eth 1",
		"type wan",
		"wan-name wan1",
		"exit",
		"hostname NSE-Caravan",
	}
	if len(got) != len(want) {
		t.Fatalf("ExtractStanza() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ExtractStanza()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestNATRuleContextsOpenBlocks covers the four per-WAN NAT rule
// contexts. An unrecognized sub-context does two damaging things at once
// — it flattens its children into the parent, and its stray "exit" pops
// the nearest recognized ancestor, truncating that ancestor's stanza —
// and ExtractStanza builds the rollback pre-image out of this tree.
//
// The empty-rule case is the reason these need an explicit opener:
// indentation alone cannot see a block with no leaves under it.
func TestNATRuleContextsOpenBlocks(t *testing.T) {
	raw := `interface eth 1
 type wan
 nat-one-one 1
   lan-IP 10.1.3.50
   public-IP 203.0.113.7
   protocol any
 nat-one-many 1
   lan-IP 10.1.3.51
   lan-port 443
   port 9443
   protocol tcp
   public-IP 203.0.113.8
 port-forward-rule 3
 source-nat-rule 1
   lan-IP address 192.168.120.0/24
   public-IP 192.168.220.211-192.168.220.220
!`
	eth := ParseBlockTree(raw).Find("interface eth 1")
	if eth == nil {
		t.Fatal("interface eth 1 not found")
	}
	for _, header := range []string{"nat-one-one 1", "nat-one-many 1", "port-forward-rule 3", "source-nat-rule 1"} {
		if eth.Find(header) == nil {
			t.Errorf("%q did not open a block — its leaves flatten into the parent and its exit truncates the stanza", header)
		}
	}

	// port-forward-rule 3 has no leaves at all. Indentation cannot detect
	// it; only the explicit opener can.
	if blk := eth.Find("port-forward-rule 3"); blk != nil && len(blk.ToLines()) != 0 {
		t.Errorf("empty rule should have no leaves, got %q", blk.ToLines())
	}

	// The sibling blocks must not absorb each other's leaves.
	oneOne := eth.Find("nat-one-one 1")
	if oneOne == nil {
		t.Fatal("nat-one-one 1 missing")
	}
	for _, leaf := range oneOne.ToLines() {
		if strings.Contains(leaf, "lan-port") || strings.Contains(leaf, "10.1.3.51") {
			t.Errorf("nat-one-one 1 absorbed a sibling's leaf: %q", leaf)
		}
	}
}
