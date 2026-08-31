package nse

import (
	"os"
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
