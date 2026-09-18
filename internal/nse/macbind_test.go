package nse

import "testing"

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
