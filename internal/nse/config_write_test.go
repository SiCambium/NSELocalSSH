package nse

import "testing"

func TestNetworkAddress(t *testing.T) {
	cases := []struct {
		ip, mask, want string
	}{
		{"172.21.0.1", "255.255.0.0", "172.21.0.0"},
		{"192.168.21.1", "255.255.255.0", "192.168.21.0"},
		{"10.5.130.7", "255.255.255.192", "10.5.130.0"},
		{"172.16.0.1", "255.255.0.0", "172.16.0.0"},
	}
	for _, c := range cases {
		got, err := NetworkAddress(c.ip, c.mask)
		if err != nil {
			t.Fatalf("NetworkAddress(%q, %q) error: %v", c.ip, c.mask, err)
		}
		if got != c.want {
			t.Errorf("NetworkAddress(%q, %q) = %q, want %q", c.ip, c.mask, got, c.want)
		}
	}
}

func TestNetworkAddressRejectsInvalid(t *testing.T) {
	if _, err := NetworkAddress("not-an-ip", "255.255.255.0"); err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if _, err := NetworkAddress("172.21.0.1", "not-a-mask"); err == nil {
		t.Fatal("expected error for invalid mask")
	}
}

func TestDHCPPoolLinesIncludesOptionalDomain(t *testing.T) {
	lines := DHCPPoolLines(DHCPScope{
		StartIP: "172.23.1.30", EndIP: "172.23.1.253",
		Router: "172.23.0.1", DNS: "172.23.0.1", Domain: "Workgroup",
		LeaseDays: 0, LeaseHours: 2, LeaseMins: 0,
		NetworkIP: "172.23.0.0", NetworkMask: "255.255.0.0",
	})
	want := []string{
		"address-range 172.23.1.30 172.23.1.253",
		"default-router 172.23.0.1",
		"dns-server 172.23.0.1",
		"domain-name Workgroup",
		"lease 0 2 0",
		"network 172.23.0.0 255.255.0.0",
	}
	if len(lines) != len(want) {
		t.Fatalf("DHCPPoolLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestDHCPPoolLinesIncludesOptions pins the option form a live NSE prints
// in `show config` — "option <code> <type> <value>". This test previously
// asserted "dhcp-option <code> <value>", which was wrong on both counts:
// the keyword had been taken from a cnMaestro JSON export (which cannot
// evidence a CLI keyword) and the type token was missing entirely.
func TestDHCPPoolLinesIncludesOptions(t *testing.T) {
	lines := DHCPPoolLines(DHCPScope{
		StartIP: "172.21.1.30", EndIP: "172.21.1.250",
		Router: "172.21.0.1", DNS: "172.21.0.1",
		LeaseDays: 0, LeaseHours: 2, LeaseMins: 0,
		NetworkIP: "172.21.0.0", NetworkMask: "255.255.0.0",
		Options: []DHCPOption{
			{Code: 6, Value: "10.110.12.111"},              // type inferred: IP
			{Code: 15, Value: "example.local"},             // type inferred: text
			{Code: 43, Type: "IP", Value: "192.168.200.1"}, // explicit
		},
	})
	last3 := lines[len(lines)-3:]
	want := []string{
		"option 6 IP 10.110.12.111",
		"option 15 text example.local",
		"option 43 IP 192.168.200.1",
	}
	for i := range want {
		if last3[i] != want[i] {
			t.Errorf("option line %d = %q, want %q", i, last3[i], want[i])
		}
	}
}

// TestDHCPOptionRoundTrip checks that what we write parses back to what we
// started with — the property the rollback path relies on, since
// ExtractStanza replays `show config` lines straight back through
// ApplyLines.
func TestDHCPOptionRoundTrip(t *testing.T) {
	for _, want := range []DHCPOption{
		{Code: 43, Type: "IP", Value: "192.168.200.1"},
		{Code: 60, Type: "text", Value: "something.cambium.com"},
		{Code: 15, Type: "text", Value: "example.local"},
	} {
		line := DHCPOptionLine(want.Code, want.Type, want.Value)
		got, ok := ParseDHCPOptionLeaf(line)
		if !ok {
			t.Errorf("%q did not parse back", line)
			continue
		}
		if got != want {
			t.Errorf("round trip of %q gave %+v, want %+v", line, got, want)
		}
	}
}

// TestParseDHCPOptionLeafTolerates covers the forms this might meet: a
// device that prints no type token, a value containing spaces, and lines
// that are not options at all.
func TestParseDHCPOptionLeafTolerates(t *testing.T) {
	if got, ok := ParseDHCPOptionLeaf("option 15 example.local"); !ok ||
		got.Code != 15 || got.Type != "text" || got.Value != "example.local" {
		t.Errorf("two-token form = %+v, ok=%v", got, ok)
	}
	if got, ok := ParseDHCPOptionLeaf("option 6 IP 10.0.0.1"); !ok || got.Type != "IP" {
		t.Errorf("typed form = %+v, ok=%v", got, ok)
	}
	if got, ok := ParseDHCPOptionLeaf("option 252 text http://wpad/wpad.dat auto"); !ok ||
		got.Value != "http://wpad/wpad.dat auto" {
		t.Errorf("value with spaces = %+v, ok=%v", got, ok)
	}
	for _, bad := range []string{"option", "option 15", "option abc text x", "lease 0 2 0"} {
		if _, ok := ParseDHCPOptionLeaf(bad); ok {
			t.Errorf("%q should not parse as an option", bad)
		}
	}
}

func TestWANEnableLinesNegatesAccessSwitchport(t *testing.T) {
	lines := WANEnableLines("wan3", PortVLAN{Interface: "eth3", Mode: "access", AccessVLAN: "1"})
	want := []string{
		"no switchport access vlan 1",
		"no switchport mode access",
		"type wan",
		"wan-name wan3",
		"ip address dhcp",
	}
	if len(lines) != len(want) {
		t.Fatalf("WANEnableLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestWANEnableLinesNegatesTrunkSwitchport(t *testing.T) {
	lines := WANEnableLines("wan4", PortVLAN{Interface: "eth5", Mode: "trunk", NativeVLAN: "1", AllowedVLANs: "1,30,100"})
	want := []string{
		"no switchport trunk allowed vlan 1,30,100",
		"no switchport trunk native vlan 1",
		"no switchport mode trunk",
		"type wan",
		"wan-name wan4",
		"ip address dhcp",
	}
	if len(lines) != len(want) {
		t.Fatalf("WANEnableLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestWANEnableLinesNoNegationForFreshPort(t *testing.T) {
	lines := WANEnableLines("wan3", PortVLAN{})
	want := []string{"type wan", "wan-name wan3", "ip address dhcp"}
	if len(lines) != len(want) {
		t.Fatalf("WANEnableLines() = %v, want %v", lines, want)
	}
}

func TestWANPromoteLinesUsesGivenIPModeLeaves(t *testing.T) {
	lines := WANPromoteLines("wan2", PortVLAN{Interface: "eth4", Mode: "access", AccessVLAN: "1"}, []string{"ip address 203.0.113.5 255.255.255.0", "default-gateway 203.0.113.1 4"})
	want := []string{
		"no switchport access vlan 1",
		"no switchport mode access",
		"type wan",
		"wan-name wan2",
		"ip address 203.0.113.5 255.255.255.0",
		"default-gateway 203.0.113.1 4",
	}
	if len(lines) != len(want) {
		t.Fatalf("WANPromoteLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestWANRevertToLANLines(t *testing.T) {
	lines := WANRevertToLANLines("1")
	want := []string{
		"no pppoe-server enable",
		"load-balance mode disabled",
		"type lan",
		"switchport mode access",
		"switchport access vlan 1",
		"no shutdown",
	}
	if len(lines) != len(want) {
		t.Fatalf("WANRevertToLANLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestLANPortAccessLinesNegatesTrunkFirst(t *testing.T) {
	lines := LANPortAccessLines(PortVLAN{Interface: "eth5", Mode: "trunk", NativeVLAN: "1", AllowedVLANs: "1,30"}, "30")
	want := []string{
		"no switchport trunk allowed vlan 1,30",
		"no switchport trunk native vlan 1",
		"no switchport mode trunk",
		"switchport mode access",
		"switchport access vlan 30",
	}
	if len(lines) != len(want) {
		t.Fatalf("LANPortAccessLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestLANPortTrunkLinesNegatesAccessFirst(t *testing.T) {
	lines := LANPortTrunkLines(PortVLAN{Interface: "eth3", Mode: "access", AccessVLAN: "1"}, "1", "1,30,100")
	want := []string{
		"no switchport access vlan 1",
		"no switchport mode access",
		"switchport mode trunk",
		"switchport trunk native vlan 1",
		"switchport trunk allowed vlan 1,30,100",
	}
	if len(lines) != len(want) {
		t.Fatalf("LANPortTrunkLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestLANPortAccessLinesNoNegationForFreshPort(t *testing.T) {
	lines := LANPortAccessLines(PortVLAN{}, "1")
	want := []string{"switchport mode access", "switchport access vlan 1"}
	if len(lines) != len(want) {
		t.Fatalf("LANPortAccessLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestFilterRuleLayer3Line(t *testing.T) {
	got := FilterRuleLayer3Line("deny", "any", FilterAddrSpec("192.168.20.0", "255.255.255.0"), "any", FilterAddrSpec("172.21.0.0", "255.255.0.0"), "any")
	want := "layer3-filter deny proto any 192.168.20.0/255.255.255.0 any 172.21.0.0/255.255.0.0 any in"
	if got != want {
		t.Errorf("FilterRuleLayer3Line() = %q, want %q", got, want)
	}
}

func TestFilterRuleLayer3LineWithGroupNames(t *testing.T) {
	got := FilterRuleLayer3Line("deny", "any", "Enterprise-Users", "any", "Guest", "any")
	want := "layer3-filter deny proto any Enterprise-Users any Guest any in"
	if got != want {
		t.Errorf("FilterRuleLayer3Line() = %q, want %q", got, want)
	}
}

func TestBuildFilterRuleCreateLines(t *testing.T) {
	lines := BuildFilterRuleCreateLines(4, "test_probe_a", "layer3-filter deny proto any 203.0.113.0/255.255.255.0 any 198.51.100.0/255.255.255.0 any in")
	want := []string{
		"filter precedence 4",
		"unique_id 4",
		"rule-name test_probe_a",
		"layer3-filter deny proto any 203.0.113.0/255.255.255.0 any 198.51.100.0/255.255.255.0 any in",
		"exit",
	}
	if len(lines) != len(want) {
		t.Fatalf("BuildFilterRuleCreateLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestFilterRuleDeleteLine(t *testing.T) {
	if got, want := FilterRuleDeleteLine(4), "no filter precedence 4"; got != want {
		t.Errorf("FilterRuleDeleteLine(4) = %q, want %q", got, want)
	}
}

func TestReplaceFilterRulesLinesDeletesAllThenRecreatesInNewOrder(t *testing.T) {
	current := []FilterRule{
		{Precedence: "1", Name: "rule_1", Rule: "deny proto any 192.168.20.0/255.255.255.0 any 172.21.0.0/255.255.0.0 any in"},
		{Precedence: "2", Name: "rule_2", Rule: "deny proto any 192.168.20.0/255.255.255.0 any 172.23.0.0/255.255.0.0 any in"},
		{Precedence: "3", Name: "rule_3", Rule: "deny proto any 192.168.20.0/255.255.255.0 any 172.18.0.0/255.255.0.0 any in"},
	}
	// Simulate "move rule_3 up": swap indices 1 and 2.
	newOrder := []FilterRule{current[0], current[2], current[1]}
	lines := ReplaceFilterRulesLines(current, newOrder)
	want := []string{
		"filter global-filter",
		"no filter precedence 1",
		"no filter precedence 2",
		"no filter precedence 3",
		"filter precedence 1",
		"unique_id 1",
		"rule-name rule_1",
		"layer3-filter deny proto any 192.168.20.0/255.255.255.0 any 172.21.0.0/255.255.0.0 any in",
		"exit",
		"filter precedence 2",
		"unique_id 2",
		"rule-name rule_3",
		"layer3-filter deny proto any 192.168.20.0/255.255.255.0 any 172.18.0.0/255.255.0.0 any in",
		"exit",
		"filter precedence 3",
		"unique_id 3",
		"rule-name rule_2",
		"layer3-filter deny proto any 192.168.20.0/255.255.255.0 any 172.23.0.0/255.255.0.0 any in",
		"exit",
		"exit",
	}
	if len(lines) != len(want) {
		t.Fatalf("ReplaceFilterRulesLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestLANPortShutdownLine(t *testing.T) {
	if got, want := LANPortShutdownLine(true), "no shutdown"; got != want {
		t.Errorf("LANPortShutdownLine(true) = %q, want %q", got, want)
	}
	if got, want := LANPortShutdownLine(false), "shutdown"; got != want {
		t.Errorf("LANPortShutdownLine(false) = %q, want %q", got, want)
	}
}

func TestManagementLineBuilders(t *testing.T) {
	if got, want := HostnameLine("NSE-Caravan"), "hostname NSE-Caravan"; got != want {
		t.Errorf("HostnameLine() = %q, want %q", got, want)
	}
	if got, want := TimezoneLine("Europe/London"), "timezone Europe/London"; got != want {
		t.Errorf("TimezoneLine() = %q, want %q", got, want)
	}
	if got, want := NTPServerLine("time.google.com"), "ntp server time.google.com"; got != want {
		t.Errorf("NTPServerLine() = %q, want %q", got, want)
	}
	lines := SyslogHostLines("172.22.0.9", "514", 5)
	want := []string{"logging host 172.22.0.9 514", "logging syslog 5"}
	if len(lines) != len(want) {
		t.Fatalf("SyslogHostLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestDNSLineBuilders(t *testing.T) {
	if got, want := DNSFilterModeLine("filtering"), "filter-mode filtering"; got != want {
		t.Errorf("DNSFilterModeLine() = %q, want %q", got, want)
	}
	if got, want := DNSOverrideLine(false), "no dns-override"; got != want {
		t.Errorf("DNSOverrideLine(false) = %q, want %q", got, want)
	}
	if got, want := DNSOverrideLine(true), "dns-override"; got != want {
		t.Errorf("DNSOverrideLine(true) = %q, want %q", got, want)
	}
	if got, want := DNSServerLine(true), "ip dns server"; got != want {
		t.Errorf("DNSServerLine(true) = %q, want %q", got, want)
	}
	if got, want := DNSServerLine(false), "no ip dns server"; got != want {
		t.Errorf("DNSServerLine(false) = %q, want %q", got, want)
	}
}

func TestNameServerLinesDiffsCurrentAndDesired(t *testing.T) {
	lines := NameServerLines([]string{"1.1.1.2", "8.8.8.8"}, []string{"8.8.8.8", "9.9.9.9"})
	want := []string{"no ip name-server 1.1.1.2", "ip name-server 9.9.9.9"}
	if len(lines) != len(want) {
		t.Fatalf("NameServerLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestNameServerLinesNoChange(t *testing.T) {
	lines := NameServerLines([]string{"1.1.1.2"}, []string{"1.1.1.2"})
	if len(lines) != 0 {
		t.Fatalf("expected no lines for identical lists, got %v", lines)
	}
}

func TestIPSLineBuilders(t *testing.T) {
	if got, want := IPSEnableLine(true), "intrusion-prevention"; got != want {
		t.Errorf("IPSEnableLine(true) = %q, want %q", got, want)
	}
	if got, want := IPSEnableLine(false), "no intrusion-prevention"; got != want {
		t.Errorf("IPSEnableLine(false) = %q, want %q", got, want)
	}
	if got, want := IPSModeLine("prevention"), "intrusion-prevention mode prevention"; got != want {
		t.Errorf("IPSModeLine() = %q, want %q", got, want)
	}
	if got, want := IPSRuleSetLine("balanced"), "intrusion-prevention rule-set balanced"; got != want {
		t.Errorf("IPSRuleSetLine() = %q, want %q", got, want)
	}
	if got, want := IPSRuleTypeLine("snort-vrt"), "intrusion-prevention rule-type snort-vrt"; got != want {
		t.Errorf("IPSRuleTypeLine() = %q, want %q", got, want)
	}
	if got, want := IPSAutoUpdateLine(true), "intrusion-prevention auto-update"; got != want {
		t.Errorf("IPSAutoUpdateLine(true) = %q, want %q", got, want)
	}
	if got, want := IPSAutoUpdateIntervalLine("12-hours"), "intrusion-prevention auto-update interval 12-hours"; got != want {
		t.Errorf("IPSAutoUpdateIntervalLine() = %q, want %q", got, want)
	}
}

func TestVPNLineBuilders(t *testing.T) {
	if got, want := TailscaleEnableLine(true), "tailscale"; got != want {
		t.Errorf("TailscaleEnableLine(true) = %q, want %q", got, want)
	}
	if got, want := TailscaleEnableLine(false), "no tailscale"; got != want {
		t.Errorf("TailscaleEnableLine(false) = %q, want %q", got, want)
	}
	if got, want := TailscaleAcceptRoutesLine(true), "tailscale accept-routes"; got != want {
		t.Errorf("TailscaleAcceptRoutesLine(true) = %q, want %q", got, want)
	}
	if got, want := TailscaleAdvertiseRoutesLine([]string{"172.21.0.0/16", "172.23.0.0/16"}), "tailscale advertise-routes 172.21.0.0/16,172.23.0.0/16"; got != want {
		t.Errorf("TailscaleAdvertiseRoutesLine() = %q, want %q", got, want)
	}
	if got, want := SiteToSiteEnableLine(true), "site-to-site-vpn"; got != want {
		t.Errorf("SiteToSiteEnableLine(true) = %q, want %q", got, want)
	}
	if got, want := RADIUSModeLine(true), "radius-server mode enable"; got != want {
		t.Errorf("RADIUSModeLine(true) = %q, want %q", got, want)
	}
	lines := BuildRADIUSClientLines(1, RADIUSClientLines("Demo1", "s3cret", "172.22.0.0", 16))
	want := []string{
		"radius-server client-list 1",
		"name Demo1",
		"secret s3cret",
		"address 172.22.0.0",
		"prefix-length 16",
		"exit",
	}
	if len(lines) != len(want) {
		t.Fatalf("BuildRADIUSClientLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestDOSProtectionLineBuilders(t *testing.T) {
	if got, want := DOSProtectionIPSpoofLine(true), "firewall dos-protection ip-spoof"; got != want {
		t.Errorf("DOSProtectionIPSpoofLine(true) = %q, want %q", got, want)
	}
	if got, want := DOSProtectionIPSpoofLine(false), "no firewall dos-protection ip-spoof"; got != want {
		t.Errorf("DOSProtectionIPSpoofLine(false) = %q, want %q", got, want)
	}
	if got, want := DOSProtectionIPSpoofLogLine(true), "firewall dos-protection ip-spoof-log"; got != want {
		t.Errorf("DOSProtectionIPSpoofLogLine(true) = %q, want %q", got, want)
	}
	if got, want := DOSProtectionSmurfLine(true), "firewall dos-protection smurf-attack"; got != want {
		t.Errorf("DOSProtectionSmurfLine(true) = %q, want %q", got, want)
	}
	if got, want := DOSProtectionICMPFragLine(true), "firewall dos-protection icmp-frag"; got != want {
		t.Errorf("DOSProtectionICMPFragLine(true) = %q, want %q", got, want)
	}
}

func TestUserGroupLineBuilders(t *testing.T) {
	lines := BuildUserGroupLines(64, []string{UserGroupNameLine("ProbeUG"), UserGroupSourceSubnetLine("10.99.0.0/24")})
	want := []string{"group 64", "name ProbeUG", "source-subnet 10.99.0.0/24", "exit"}
	if len(lines) != len(want) {
		t.Fatalf("BuildUserGroupLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
	if got, want := UserGroupDeleteLine(64), "no group 64"; got != want {
		t.Errorf("UserGroupDeleteLine() = %q, want %q", got, want)
	}
}

func TestIPGroupLineBuilders(t *testing.T) {
	lines := BuildIPGroupLines(1, []string{IPGroupNameLine("ProbeIG"), IPGroupAddressLine("192.168.50.0/24")})
	want := []string{"ip group 1", "name ProbeIG", "address 192.168.50.0/24", "exit"}
	if len(lines) != len(want) {
		t.Fatalf("BuildIPGroupLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
	if got, want := IPGroupDeleteLine(1), "no ip group 1"; got != want {
		t.Errorf("IPGroupDeleteLine() = %q, want %q", got, want)
	}
}

func TestAppGroupLineBuilders(t *testing.T) {
	lines := BuildAppGroupLines(16, []string{AppGroupNameLine("ProbeAG"), AppGroupApplicationLine("instagram")})
	want := []string{"application-group 16", "name ProbeAG", "application instagram", "exit"}
	if len(lines) != len(want) {
		t.Fatalf("BuildAppGroupLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
	if got, want := AppGroupDeleteLine(16), "no application-group 16"; got != want {
		t.Errorf("AppGroupDeleteLine() = %q, want %q", got, want)
	}
	if got, want := AppGroupCategoryLine("app-detect"), "category app-detect"; got != want {
		t.Errorf("AppGroupCategoryLine() = %q, want %q", got, want)
	}
}

func TestPPPoEEnableLinesFullConfig(t *testing.T) {
	lines := PPPoEEnableLines(PPPoEConfig{
		User: "isp-user", Password: "isp-pass", MTU: 1492, MSSClamp: true,
		ACName: "AC1", ServiceName: "SVC1",
	})
	want := []string{
		"pppoe-server enable",
		"pppoe-server user isp-user",
		"pppoe-server password isp-pass",
		"pppoe-server mtu 1492",
		"pppoe-server tcp-mss-clamp",
		"pppoe-server ac-name AC1",
		"pppoe-server service-name SVC1",
	}
	if len(lines) != len(want) {
		t.Fatalf("PPPoEEnableLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestPPPoEEnableLinesOmitsOptionalFields(t *testing.T) {
	lines := PPPoEEnableLines(PPPoEConfig{User: "u", Password: "p", MTU: 1400})
	want := []string{
		"pppoe-server enable",
		"pppoe-server user u",
		"pppoe-server password p",
		"pppoe-server mtu 1400",
	}
	if len(lines) != len(want) {
		t.Fatalf("PPPoEEnableLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestPPPoEModeLinesResetsIPAddress(t *testing.T) {
	lines := PPPoEModeLines(PPPoEConfig{User: "u", Password: "p", MTU: 1492})
	want := []string{
		"pppoe-server enable",
		"pppoe-server user u",
		"pppoe-server password p",
		"pppoe-server mtu 1492",
		"ip address dhcp",
	}
	if len(lines) != len(want) {
		t.Fatalf("PPPoEModeLines() = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestPPPoEDisableLine(t *testing.T) {
	if got, want := PPPoEDisableLine(), "no pppoe-server enable"; got != want {
		t.Errorf("PPPoEDisableLine() = %q, want %q", got, want)
	}
}

func TestConnectionHealthLineBuilders(t *testing.T) {
	if got, want := WANNumHostsFailLine(1), "load-balance num-hosts-fail-interface-down 1"; got != want {
		t.Errorf("WANNumHostsFailLine() = %q, want %q", got, want)
	}
	if got, want := WANPingFailureDetectTimeLine(5), "load-balance ping failure-detect-time 5"; got != want {
		t.Errorf("WANPingFailureDetectTimeLine() = %q, want %q", got, want)
	}
	if got, want := WANPingIntervalLine(2), "load-balance ping interval 2"; got != want {
		t.Errorf("WANPingIntervalLine() = %q, want %q", got, want)
	}
	if got, want := WANPingTimeoutLine(2), "load-balance ping timeout 2"; got != want {
		t.Errorf("WANPingTimeoutLine() = %q, want %q", got, want)
	}
}

func TestDeviceAccessPingLine(t *testing.T) {
	if got, want := DeviceAccessPingLine(true), "device-access allowed-service ping"; got != want {
		t.Errorf("DeviceAccessPingLine(true) = %q, want %q", got, want)
	}
	if got, want := DeviceAccessPingLine(false), "no device-access allowed-service ping"; got != want {
		t.Errorf("DeviceAccessPingLine(false) = %q, want %q", got, want)
	}
}

func TestDHCPPoolLinesOmitsEmptyDomain(t *testing.T) {
	lines := DHCPPoolLines(DHCPScope{
		StartIP: "172.21.1.30", EndIP: "172.21.1.250",
		Router: "172.21.0.1", DNS: "172.21.0.1",
		LeaseDays: 0, LeaseHours: 2, LeaseMins: 0,
		NetworkIP: "172.21.0.0", NetworkMask: "255.255.0.0",
	})
	for _, l := range lines {
		if l == "domain-name " {
			t.Fatalf("should not emit an empty domain-name line: %v", lines)
		}
	}
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines without domain, got %d: %v", len(lines), lines)
	}
}

func TestGeoIPModeLine(t *testing.T) {
	if got, want := GeoIPModeLine("inbound", "allow"), "firewall geo-ip-restrictions inbound mode allow"; got != want {
		t.Errorf("GeoIPModeLine() = %q, want %q", got, want)
	}
	if got, want := GeoIPModeLine("outbound", "none"), "firewall geo-ip-restrictions outbound mode none"; got != want {
		t.Errorf("GeoIPModeLine() = %q, want %q", got, want)
	}
}

func TestGeoIPCountriesLine(t *testing.T) {
	got := GeoIPCountriesLine("inbound", []string{"US", "GB", "DE"})
	want := "firewall geo-ip-restrictions inbound countries US,GB,DE"
	if got != want {
		t.Errorf("GeoIPCountriesLine() = %q, want %q", got, want)
	}
}

func TestGeoIPExceptionAddAndDeleteLines(t *testing.T) {
	add := GeoIPExceptionAddLine("outbound", "203.0.113.1", "203.0.113.10")
	wantAdd := "firewall geo-ip-allowlist outbound address-range start-address end-address 203.0.113.1 203.0.113.10"
	if add != wantAdd {
		t.Errorf("GeoIPExceptionAddLine() = %q, want %q", add, wantAdd)
	}
	del := GeoIPExceptionDeleteLine("outbound", "203.0.113.1", "203.0.113.10")
	wantDel := "no " + wantAdd
	if del != wantDel {
		t.Errorf("GeoIPExceptionDeleteLine() = %q, want %q", del, wantDel)
	}
}

func TestIPSOinkcodeLine(t *testing.T) {
	if got, want := IPSOinkcodeLine("abc123"), "intrusion-prevention oinkcode abc123"; got != want {
		t.Errorf("IPSOinkcodeLine() = %q, want %q", got, want)
	}
}
