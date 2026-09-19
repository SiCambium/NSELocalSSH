package nse

import (
	"strings"
	"testing"
)

// scope mirrors VLAN 40 on the live NSE 4000 this was verified against:
// 192.168.40.0/24, SVI .1, dynamic range .50-.99.
func testScope() DHCPPoolSettings {
	return DHCPPoolSettings{Pool: 4, AddressRange: "192.168.40.50 192.168.40.99"}
}

func TestValidateMACBindingAccepts(t *testing.T) {
	if err := ValidateMACBinding("02:1a:2b:3c:4d:5e", "192.168.40.200", "192.168.40.1", "255.255.255.0", testScope(), nil); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateMACBindingRejects(t *testing.T) {
	cases := []struct{ name, mac, ip string }{
		{"malformed mac", "02:1a:2b:3c:4d", "192.168.40.200"},
		{"malformed ip", "02:1a:2b:3c:4d:5e", "not-an-ip"},
		// Both of the following were accepted by the device itself.
		{"outside vlan subnet", "02:1a:2b:3c:4d:5e", "10.99.99.99"},
		{"inside dynamic range", "02:1a:2b:3c:4d:5e", "192.168.40.60"},
		{"vlan gateway", "02:1a:2b:3c:4d:5e", "192.168.40.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateMACBinding(c.mac, c.ip, "192.168.40.1", "255.255.255.0", testScope(), nil); err == nil {
				t.Fatalf("expected rejection for %s/%s", c.mac, c.ip)
			}
		})
	}
}

func TestValidateMACBindingRejectsDuplicatesRegardlessOfCase(t *testing.T) {
	existing := []MACBinding{{Pool: 4, MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.40.202"}}
	if err := ValidateMACBinding("aa:bb:cc:dd:ee:ff", "192.168.40.203", "192.168.40.1", "255.255.255.0", testScope(), existing); err == nil {
		t.Fatal("expected duplicate MAC to be rejected across case")
	}
	if err := ValidateMACBinding("02:1a:2b:3c:4d:5e", "192.168.40.202", "192.168.40.1", "255.255.255.0", testScope(), existing); err == nil {
		t.Fatal("expected duplicate IP to be rejected")
	}
}

// Removal is case-sensitive on the device and the IP is mandatory, so the
// emitted line must carry both, spelled as stored.
func TestDHCPBindLines(t *testing.T) {
	if got := DHCPBindLine("AA:BB:CC:DD:EE:FF", "192.168.40.202"); got != "bind AA:BB:CC:DD:EE:FF 192.168.40.202" {
		t.Fatalf("bind line %q", got)
	}
	if got := DHCPNoBindLine("AA:BB:CC:DD:EE:FF", "192.168.40.202"); got != "no bind AA:BB:CC:DD:EE:FF 192.168.40.202" {
		t.Fatalf("no bind line %q", got)
	}
}

func TestFindBindingReturnsDeviceCasing(t *testing.T) {
	existing := []MACBinding{{Pool: 4, MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.40.202"}}
	got, ok := findBinding(existing, "aa:bb:cc:dd:ee:ff", "192.168.40.202")
	if !ok || got.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("expected stored casing, got %+v ok=%v", got, ok)
	}
	if _, ok := findBinding(existing, "aa:bb:cc:dd:ee:ff", "192.168.40.99"); ok {
		t.Fatal("expected mismatched IP to miss")
	}
}

// A rejected `bind` is reported on a line with no "%" prefix. Before this
// was recognized, the write path reported such a failure as applied.
func TestClassifyLineCatchesDHCPPoolError(t *testing.T) {
	raw := "bind 02:1a:2b:3c:4d:5e 192.168.40.200\nError setting dhcp pool parameters: The input mac is already bound\n"
	r := classifyLine("bind 02:1a:2b:3c:4d:5e 192.168.40.200", raw)
	if r.OK {
		t.Fatalf("expected rejection, got %+v", r)
	}
}

func TestMergeBindingDescriptionsMatchesAcrossCase(t *testing.T) {
	cloud := CloudConfig{LANInterfaces: []LANInterface{{
		VLANID: 1,
		DHCPPoolConfig: DHCPPoolConfig{BindList: []DHCPBind{
			{IP: "192.168.10.10", MAC: "BC:E6:7C:B3:35:C1", Desc: "cnMatrix TX2020R-P"},
		}},
	}}}
	got := MergeBindingDescriptions([]MACBinding{{Pool: 1, MAC: "bc:e6:7c:b3:35:c1", IP: "192.168.10.10"}}, cloud)
	if got[0].Description != "cnMatrix TX2020R-P" {
		t.Fatalf("desc not merged: %+v", got[0])
	}
}

func TestBindingsByVLANGroupsThroughPoolLookup(t *testing.T) {
	cloud := CloudConfig{LANInterfaces: []LANInterface{
		{VLANID: 40, DHCPPoolConfig: DHCPPoolConfig{StartAddress: "192.168.40.50"}},
		{VLANID: 30, DHCPPoolConfig: DHCPPoolConfig{StartAddress: "192.168.30.50"}},
	}}
	lan := LANConfig{
		DHCPPools: []DHCPPoolSettings{
			{Pool: 4, AddressRange: "192.168.40.50 192.168.40.99"},
			{Pool: 3, AddressRange: "192.168.30.50 192.168.30.99"},
		},
		Bindings: []MACBinding{{Pool: 4, MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.40.202"}},
	}
	got := bindingsByVLAN(cloud, lan)
	if len(got["40"]) != 1 || got["40"][0].IP != "192.168.40.202" {
		t.Fatalf("vlan 40 %+v", got["40"])
	}
	// A VLAN with no reservations must still be present, as an empty list
	// rather than a missing key, so the UI renders an empty table.
	if got["30"] == nil || len(got["30"]) != 0 {
		t.Fatalf("vlan 30 %+v", got["30"])
	}
}

// A VLAN's rate limit is the rule with no unique_id. An operator-authored
// rule shaping the same subnet carries one, and must never be matched as a
// VLAN's rate limit — editing the VLAN would otherwise delete it.
func TestRateLimitRuleForSubnetIgnoresOperatorRules(t *testing.T) {
	spec := "192.168.30.0/255.255.255.0"
	operator := FilterRule{
		ID: "16", Name: "Everything_Allow", Precedence: "16", Kind: "layer3",
		Rule:  "permit ip " + spec + " any any",
		Extra: []string{"rate-limit sta Mbps 50"},
	}
	vlanRule := FilterRule{
		Precedence: "17", Kind: "layer3",
		Rule:  "permit ip " + spec + " any any",
		Extra: []string{"rate-limit sta Mbps 100"},
	}
	got, prec := rateLimitRuleForSubnet([]FilterRule{operator, vlanRule}, spec)
	if got == nil || prec != 17 {
		t.Fatalf("expected the unmarked rule at 17, got %+v prec=%d", got, prec)
	}
	// With only the operator rule present there is nothing to match.
	if got, _ := rateLimitRuleForSubnet([]FilterRule{operator}, spec); got != nil {
		t.Fatalf("operator rule must not match: %+v", got)
	}
	// Nor should a different subnet.
	if got, _ := rateLimitRuleForSubnet([]FilterRule{vlanRule}, "192.168.99.0/255.255.255.0"); got != nil {
		t.Fatalf("wrong subnet matched: %+v", got)
	}
}

// The generated rule must carry neither unique_id nor rule-name, matching
// what cnMaestro writes — that absence is what marks it as a VLAN's limit.
func TestVLANRateLimitRuleShape(t *testing.T) {
	lines := FilterRuleLeafLines(18, VLANRateLimitRule("192.168.30.0/255.255.255.0", 100))
	want := []string{
		"filter precedence 18",
		"layer3-filter permit ip 192.168.30.0/255.255.255.0 any any",
		"rate-limit sta Mbps 100",
		"exit",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines: %v", len(lines), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

// An operator rule keeps both markers when replayed.
func TestFilterRuleLeafLinesKeepsOperatorMarkers(t *testing.T) {
	lines := FilterRuleLeafLines(5, FilterRule{ID: "5", Name: "Block_IoT", Kind: "layer3", Rule: "deny ip any any any"})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "unique_id 5") || !strings.Contains(joined, "rule-name Block_IoT") {
		t.Fatalf("operator markers dropped:\n%s", joined)
	}
}

// The default route is what separates a WAN that is carrying traffic from
// one that is merely plugged in. The device prints interfaces uppercase
// ("ETH3") while the config names the same port "eth3".
func TestDefaultRouteInterfaces(t *testing.T) {
	routes := []Route{
		{Destination: "0.0.0.0", Mask: "0.0.0.0", Gateway: "104.6.184.1", Interface: "ETH3"},
		{Destination: "104.6.184.0", Mask: "255.255.252.0", Gateway: "0.0.0.0", Interface: "ETH3"},
		{Destination: "192.168.10.0", Mask: "255.255.255.0", Gateway: "0.0.0.0", Interface: "VLAN1"},
		{Destination: "100.65.113.39", Mask: "255.255.255.255", Gateway: "172.31.255.2", Interface: "ETH1"},
	}
	got := defaultRouteInterfaces(routes)
	if len(got) != 1 {
		t.Fatalf("expected exactly the default route, got %v", got)
	}
	if got["eth3"] != "104.6.184.1" {
		t.Fatalf("eth3 gateway = %q, want 104.6.184.1 (map: %v)", got["eth3"], got)
	}
	// A host route on a link, however specific, is not a default route —
	// ETH1 carries several here and is still not the active WAN.
	if _, ok := got["eth1"]; ok {
		t.Fatalf("host routes must not count as a default route: %v", got)
	}
}

// Two live WANs: only the one holding the default route is active.
func TestDefaultRouteInterfacesWithTwoUplinks(t *testing.T) {
	got := defaultRouteInterfaces([]Route{
		{Destination: "0.0.0.0", Mask: "0.0.0.0", Gateway: "10.0.0.1", Interface: "ETH1"},
		{Destination: "0.0.0.0", Mask: "0.0.0.0", Gateway: "104.6.184.1", Interface: "ETH3"},
	})
	if len(got) != 2 || got["eth1"] != "10.0.0.1" || got["eth3"] != "104.6.184.1" {
		t.Fatalf("both default routes should be reported: %v", got)
	}
}

// "auto-vlan-msg-auth" is a separate setting that shares this leaf's
// prefix and survives auto-VLAN being switched off — CONFIRMED live. A
// prefix match would report a port as auto-VLAN enabled purely because
// msg-auth is set.
func TestParsePortAutoVLANIgnoresMsgAuthLeaf(t *testing.T) {
	raw := "show config\n!\n" +
		"interface eth 2\n type lan\n auto-vlan\n auto-vlan-msg-auth\n no shutdown\n exit\n!\n" +
		"interface eth 4\n type lan\n auto-vlan-msg-auth\n no shutdown\n exit\n!\n" +
		"interface eth 5\n type lan\n no shutdown\n exit\n!\n"
	byIface := map[string]PortVLAN{}
	for _, p := range ParseLANConfig(raw).Ports {
		byIface[p.Interface] = p
	}
	if !byIface["eth2"].AutoVLAN {
		t.Error("eth2 has the auto-vlan leaf and should read as enabled")
	}
	if byIface["eth4"].AutoVLAN {
		t.Error("eth4 has only auto-vlan-msg-auth and must not read as enabled")
	}
	if byIface["eth5"].AutoVLAN {
		t.Error("eth5 has neither leaf and must not read as enabled")
	}
}

func TestLANPortAutoVLANLine(t *testing.T) {
	if got := LANPortAutoVLANLine(true); got != "auto-vlan" {
		t.Fatalf("enable = %q", got)
	}
	if got := LANPortAutoVLANLine(false); got != "no auto-vlan" {
		t.Fatalf("disable = %q", got)
	}
}
