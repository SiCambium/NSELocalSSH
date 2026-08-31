package nse

import "testing"

// This mirrors the exact structure confirmed live on a real 2.3-r6 unit:
// "group N" and "application-group N" close with "!", but "ip group N"
// closes with nothing at all — just a blank line before the next
// top-level entry (see the blocktree.go fallback this depends on).
const groupsFixture = `show config
!
group 63
 name ProbeUG
 source-subnet 10.99.0.0/24
!
interface eth 1
 type wan
!

ip group 2
 name ProbeIG
 address 10.99.1.0/24

timezone Europe/London
hostname NSE-Caravan
!
application-group 15
 name ProbeAG
 application instagram
 category app-detect
!
intrusion-prevention
!
NSE-Caravan(config)# `

func TestParseGroupsConfig(t *testing.T) {
	cfg := ParseGroupsConfig(groupsFixture)

	if len(cfg.UserGroups) != 1 {
		t.Fatalf("UserGroups = %+v, want 1 entry", cfg.UserGroups)
	}
	ug := cfg.UserGroups[0]
	if ug.ID != 63 || ug.Name != "ProbeUG" || ug.SourceSubnet != "10.99.0.0/24" {
		t.Fatalf("user group = %+v", ug)
	}

	if len(cfg.IPGroups) != 1 {
		t.Fatalf("IPGroups = %+v, want 1 entry", cfg.IPGroups)
	}
	ig := cfg.IPGroups[0]
	if ig.ID != 2 || ig.Name != "ProbeIG" || ig.Address != "10.99.1.0/24" {
		t.Fatalf("ip group = %+v", ig)
	}

	if len(cfg.AppGroups) != 1 {
		t.Fatalf("AppGroups = %+v, want 1 entry", cfg.AppGroups)
	}
	ag := cfg.AppGroups[0]
	if ag.ID != 15 || ag.Name != "ProbeAG" {
		t.Fatalf("app group = %+v", ag)
	}
	if len(ag.Applications) != 1 || ag.Applications[0] != "instagram" {
		t.Fatalf("app group applications = %v", ag.Applications)
	}
	if len(ag.Categories) != 1 || ag.Categories[0] != "app-detect" {
		t.Fatalf("app group categories = %v", ag.Categories)
	}
}

// TestParseGroupsConfigDoesNotSwallowFollowingSections is the specific
// regression this exists to guard: since "ip group N" has no closing "!"
// or "exit" in the device's own show config rendering, hostname/timezone
// (and everything else that follows) must still parse as top-level
// entries, not get nested inside the still-nominally-open ip group block.
func TestParseGroupsConfigDoesNotSwallowFollowingSections(t *testing.T) {
	tree := ParseBlockTree(groupsFixture)
	if _, ok := tree.Leaf("hostname"); !ok {
		t.Fatal("hostname should be a top-level leaf, not swallowed by the unterminated ip group block")
	}
	if _, ok := tree.Leaf("timezone"); !ok {
		t.Fatal("timezone should be a top-level leaf, not swallowed by the unterminated ip group block")
	}
	if blk := tree.Find("application-group 15"); blk == nil {
		t.Fatal("application-group 15 should be its own top-level block, not nested inside ip group 2")
	}
}
