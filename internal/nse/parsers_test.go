package nse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readDump(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseVersion(t *testing.T) {
	v := ParseVersion(readDump(t, "show_version.txt"))
	if !strings.Contains(v.Identity, "NSE 3000") {
		t.Fatalf("identity=%q", v.Identity)
	}
	if v.SoftwareVersion != "2.3-r6" || v.Hostname != "NSE-Caravan" || v.Model != "NSE 3000" {
		t.Fatalf("%+v", v)
	}
	if v.Serial == "" || v.MAC == "" || v.DeviceAgent == "" || v.Uptime == "" || v.RegulatoryDomain == "" || v.BuildDate == "" {
		t.Fatalf("incomplete version %+v", v)
	}
}

func TestParseClock(t *testing.T) {
	c := ParseClock(readDump(t, "probe_show_clock.txt"))
	if !strings.Contains(c.Clock, "2026") || !strings.Contains(c.Clock, "BST") {
		t.Fatalf("clock=%q", c.Clock)
	}
}

func TestParseConntrack(t *testing.T) {
	c := ParseConntrack(readDump(t, "probe_service_show_conntrack.txt"))
	if c.Limit != 262144 || c.Usage != 240 || c.Flows != 157 || c.NAT != 157 {
		t.Fatalf("%+v", c)
	}
}

func TestParseInterfaceBrief(t *testing.T) {
	rows := ParseInterfaceBrief(readDump(t, "probe_show_interface_brief.txt"))
	if len(rows) != 6 {
		t.Fatalf("got %d rows", len(rows))
	}
	want := []string{"eth1", "eth2", "eth3", "eth4", "eth5", "eth6"}
	for i, name := range want {
		if rows[i].Interface != name {
			t.Fatalf("row %d: %q", i, rows[i].Interface)
		}
	}
	if rows[0].Status != "UP" || rows[1].Status != "DOWN" {
		t.Fatalf("status %s %s", rows[0].Status, rows[1].Status)
	}
}

func TestParseRoute(t *testing.T) {
	rows := ParseRoute(readDump(t, "probe_show_route.txt"))
	if rows[0].Destination != "0.0.0.0" || rows[0].Gateway != "192.168.1.1" {
		t.Fatalf("%+v", rows[0])
	}
	found := false
	for _, r := range rows {
		if r.Interface == "VLAN100" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing VLAN100")
	}
}

func TestParseARP(t *testing.T) {
	rows := ParseARP(readDump(t, "probe_show_arp.txt"))
	found, incomplete := false, false
	for _, r := range rows {
		if r.IP == "172.23.1.36" {
			found = true
		}
		if !r.Complete {
			incomplete = true
		}
	}
	if !found || !incomplete {
		t.Fatalf("found=%v incomplete=%v n=%d", found, incomplete, len(rows))
	}
}

func TestParseManagement(t *testing.T) {
	m := ParseManagement(readDump(t, "probe_show_management.txt"))
	if m.CLI["ssh"] != "Enabled" {
		t.Fatalf("cli=%v", m.CLI)
	}
	if m.GUI["http"] != "Enabled" || m.GUI["https"] != "Enabled" {
		t.Fatalf("gui=%v", m.GUI)
	}
	if !strings.Contains(strings.ToLower(m.Remote["status"]), "cnmaestro") {
		t.Fatalf("remote=%v", m.Remote)
	}
}

func TestParseDHCPPool(t *testing.T) {
	p, ok := ParseDHCPPool(readDump(t, "probe_show_dhcp-pool_1.txt"), 1)
	if !ok {
		t.Fatal("expected pool")
	}
	if p.Status != "UP" || len(p.Leases) == 0 || p.Leases[0].IP != "172.21.1.30" {
		t.Fatalf("%+v", p)
	}
}

func TestParseIPDHCP(t *testing.T) {
	blocks := ParseIPDHCP(readDump(t, "probe_show_ip_dhcp.txt"))
	if blocks[0].Interface != "ETH1" || blocks[0].Options["ip"] != "192.168.1.171" {
		t.Fatalf("%+v", blocks[0])
	}
}

func TestParseEvents(t *testing.T) {
	rows := ParseEvents(readDump(t, "probe_show_events.txt"))
	found := false
	for _, r := range rows {
		if strings.Contains(r.Code, "WANLB") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing WANLB event")
	}
}

func TestParseLLDP(t *testing.T) {
	rows := ParseLLDPNeighbors(readDump(t, "probe_show_lldp_neighbors.txt"))
	if rows[0].SysName != "XV3-8Caravan2" || rows[0].Interface != "ETH6" {
		t.Fatalf("%+v", rows[0])
	}
}

func TestParseMemory(t *testing.T) {
	m := ParseMemory(readDump(t, "probe_service_show_memory.txt"))
	if m.TotalKB != 3901040 || m.UsedPct <= 0 {
		t.Fatalf("%+v", m)
	}
	if m.MemTotalKB != 3901040 || len(m.Rows) < 10 {
		t.Fatalf("rows=%d memtotal=%d", len(m.Rows), m.MemTotalKB)
	}
}

func TestParseTop(t *testing.T) {
	c := ParseTop(readDump(t, "probe_service_show_top.txt"))
	if c.IdlePct != 97 || c.UsedPct != 3 || c.Load1 != "0.08" {
		t.Fatalf("%+v", c)
	}
}

func TestParseIfconfig(t *testing.T) {
	rows := ParseIfconfig(readDump(t, "probe_service_show_ifconfig.txt"), nil)
	byName := map[string]IfconfigIface{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	wan := byName["eth0"]
	if wan.CLIName != "eth1" || wan.Role != "wan" || wan.IPv4 != "192.168.1.171" || wan.RxBytes < 1 {
		t.Fatalf("wan %+v", wan)
	}
	lan := byName["eth5"]
	if lan.CLIName != "eth6" || lan.Role != "lan" || !lan.Running {
		t.Fatalf("lan %+v", lan)
	}
	vlan := byName["br0.100"]
	if vlan.Kind != "vlan" || vlan.VLAN != 100 || vlan.Label != "vlan100" {
		t.Fatalf("vlan %+v", vlan)
	}
	vpn := byName["ts-host"]
	if vpn.Kind != "vpn" || vpn.Label != "Tailscale" {
		t.Fatalf("vpn %+v", vpn)
	}
}

func TestParseIfconfigGroundTruthOverridesIPHeuristic(t *testing.T) {
	rows := ParseIfconfig(readDump(t, "probe_service_show_ifconfig.txt"), map[string]bool{"eth1": true, "eth6": true})
	byName := map[string]IfconfigIface{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	// eth0 (CLI eth1) has an IP and is in the WAN set: still WAN.
	if wan := byName["eth0"]; wan.Role != "wan" {
		t.Fatalf("expected eth1 to stay wan when in the known set, got %+v", wan)
	}
	// eth5 (CLI eth6) has no IP but is asserted as WAN ground truth: must
	// override the old "no IP => lan" heuristic, since a WAN port awaiting
	// DHCP or with an unplugged cable is still a WAN port.
	if wan := byName["eth5"]; wan.Role != "wan" || wan.Label != "eth6 (WAN)" {
		t.Fatalf("expected eth6 to be classified wan from ground truth, got %+v", wan)
	}
}

func TestRatesFromSamples(t *testing.T) {
	a := []IfconfigIface{{Name: "eth0", RxBytes: 1000, TxBytes: 2000, Role: "wan", Kind: "physical"}}
	b := []IfconfigIface{{Name: "eth0", RxBytes: 1000 + 125000, TxBytes: 2000 + 250000, Role: "wan", Kind: "physical", Label: "eth1 (WAN)"}}
	rates := RatesFromSamples(a, b, time.Second)
	if len(rates) != 1 {
		t.Fatalf("n=%d", len(rates))
	}
	if rates[0].RxBps != 1_000_000 || rates[0].TxBps != 2_000_000 {
		t.Fatalf("%+v", rates[0])
	}
	if !rates[0].Active {
		t.Fatal("expected active")
	}
}

func TestParseConntrackFlows(t *testing.T) {
	rows := ParseConntrackFlows(readDump(t, "show_conntrack.txt"))
	if len(rows) != 5 {
		t.Fatalf("got %d rows %+v", len(rows), rows)
	}
	if rows[0].Protocol != "TCP" || rows[0].OriginSrc != "172.23.1.36" || rows[0].TxBytes != 5835 || rows[0].Direction != "LAN TO WAN" {
		t.Fatalf("%+v", rows[0])
	}
	if rows[2].HostName != "laptop" {
		t.Fatalf("host %+v", rows[2])
	}
}

func TestParseConfigFilter(t *testing.T) {
	rows := ParseConfigFilter(readDump(t, "probe_show_config_filter.txt"))
	if len(rows) != 3 || rows[0].Name != "rule_1" {
		t.Fatalf("%+v", rows)
	}
}

func TestParseConfigFilterDPIKindsAndExtra(t *testing.T) {
	raw := `show config filter
!
filter  global-filter
  stateful
  application-control
  filter precedence 1
     unique_id 1
     rule-name rule_apps
     application-group deny Social-Media
     allowed-sources user-group Enterprise-Users
     exit
  filter precedence 2
     unique_id 2
     rule-name rule_cat
     category-control Gambling deny-takeover
     exit
!
NSE-Caravan(config)# `
	rows := ParseConfigFilter(raw)
	if len(rows) != 2 {
		t.Fatalf("got %d rows: %+v", len(rows), rows)
	}
	appRule := rows[0]
	if appRule.Kind != "application_group" || appRule.Rule != "application-group deny Social-Media" {
		t.Fatalf("appRule = %+v", appRule)
	}
	if len(appRule.Extra) != 1 || appRule.Extra[0] != "allowed-sources user-group Enterprise-Users" {
		t.Fatalf("appRule.Extra = %+v", appRule.Extra)
	}
	if got := appRule.FullLine(); got != "application-group deny Social-Media" {
		t.Fatalf("appRule.FullLine() = %q", got)
	}
	catRule := rows[1]
	if catRule.Kind != "category" || catRule.Rule != "category-control Gambling deny-takeover" {
		t.Fatalf("catRule = %+v", catRule)
	}
	if got := catRule.FullLine(); got != "category-control Gambling deny-takeover" {
		t.Fatalf("catRule.FullLine() = %q", got)
	}
}

func TestFilterRuleFullLineDefaultsToLayer3(t *testing.T) {
	r := FilterRule{Rule: "deny proto any 1.1.1.0/255.255.255.0 any 2.2.2.0/255.255.255.0 any in"}
	want := "layer3-filter " + r.Rule
	if got := r.FullLine(); got != want {
		t.Fatalf("FullLine() = %q, want %q", got, want)
	}
}

func TestParseConnectedClients(t *testing.T) {
	raw := "show connected-clients\n" +
		" MAC ADDRESS        IP ADDRESS       HOSTNAME         TYPE             TYPE NAME        BRAND            OS               OS VER   LAST SEEN\n" +
		" bc:a9:93:0d:89:62  192.168.21.30    XV3-8Caravan2    Enterprise WiFi  Cambium Networks Cambium Networks Cambium OS                2026-08-31 23:50:54\n" +
		" 72:54:e6:a4:31:c4  172.23.1.36      MacBookAir       LAPTOP           MacBook Air      Apple            macOS            10.15.7  2026-09-01 00:05:24\n" +
		" 92:46:68:fc:bd:9c  172.23.1.40      Watch            TELEVISION                        Apple            watchOS                   2026-08-31 22:59:55\n" +
		" ec:a1:38:71:58:d1  172.23.1.32      none             TABLET           Fire 7 (2022)    Amazon           Android          11       2026-08-31 23:56:11\n" +
		"NSE-Caravan(config)# "
	clients := ParseConnectedClients(raw)
	if len(clients) != 4 {
		t.Fatalf("got %d clients: %+v", len(clients), clients)
	}
	c0 := clients[0]
	if c0.MAC != "bc:a9:93:0d:89:62" || c0.IP != "192.168.21.30" || c0.Hostname != "XV3-8Caravan2" {
		t.Fatalf("client 0 = %+v", c0)
	}
	if c0.Type != "Enterprise WiFi" || c0.TypeName != "Cambium Networks" || c0.Brand != "Cambium Networks" || c0.OS != "Cambium OS" {
		t.Fatalf("client 0 fingerprint = %+v", c0)
	}
	if c0.OSVer != "" || c0.LastSeen != "2026-08-31 23:50:54" {
		t.Fatalf("client 0 os_ver/last_seen = %+v", c0)
	}
	c1 := clients[1]
	if c1.OS != "macOS" || c1.OSVer != "10.15.7" {
		t.Fatalf("client 1 (MacBookAir) = %+v", c1)
	}
	// This row's empty TYPE NAME column is the case that breaks a naive
	// split-on-whitespace parser (only one padding space remains).
	c2 := clients[2]
	if c2.Type != "TELEVISION" || c2.TypeName != "" || c2.Brand != "Apple" || c2.OS != "watchOS" {
		t.Fatalf("client 2 (Watch) = %+v", c2)
	}
	c3 := clients[3]
	if c3.TypeName != "Fire 7 (2022)" || c3.Brand != "Amazon" || c3.OS != "Android" || c3.OSVer != "11" {
		t.Fatalf("client 3 (Fire) = %+v", c3)
	}
}

func TestParseConnectedClientsEmpty(t *testing.T) {
	if got := ParseConnectedClients("show connected-clients\nNSE-Caravan(config)# "); len(got) != 0 {
		t.Fatalf("got %d clients, want 0: %+v", len(got), got)
	}
}

func TestParseTailscaleStatus(t *testing.T) {
	peers := ParseTailscaleStatus(readDump(t, "show_tailscale_status.txt"))
	if len(peers) < 5 {
		t.Fatalf("got %d peers", len(peers))
	}
	if peers[0].Name != "nse-caravan" || peers[0].IP != "100.93.196.62" {
		t.Fatalf("%+v", peers[0])
	}
	offline := false
	for _, p := range peers {
		if p.Name == "g11-8" && p.Offline {
			offline = true
		}
	}
	if !offline {
		t.Fatal("expected g11-8 offline")
	}
	for _, p := range peers {
		if p.Name == "iphone-13-pro-max" {
			if p.TxBytes != 348 || p.RxBytes != 500 {
				t.Fatalf("iphone-13-pro-max tx/rx: %+v", p)
			}
		}
		if p.Name == "g11-8" && p.LastSeen != "23d ago" {
			t.Fatalf("g11-8 last_seen: %+v", p)
		}
		if p.Name == "nse4khome" && !p.Exit {
			t.Fatalf("nse4khome should be an exit node: %+v", p)
		}
	}
}

func TestParseOutboundFirewallCounters(t *testing.T) {
	raw := `show counters outbound_firewall
-----------------------------------------------
| RuleId    : 1
| Name      : rule_1
| Comment   : outbound_firewall: drop L3 src 192.168.20.0/24 dst 172.21.0.0/16
| Packets   : 0
| Bytes     : 0

-----------------------------------------------
| RuleId    : 2
| Name      : rule_2
| Comment   : outbound_firewall: drop L3 src 192.168.20.0/24 dst 172.23.0.0/16
| Packets   : 12
| Bytes     : 4096

NSE-Caravan(config)# `
	rows := ParseOutboundFirewallCounters(raw)
	if len(rows) != 2 {
		t.Fatalf("got %d rows: %+v", len(rows), rows)
	}
	if rows[0].RuleID != "1" || rows[0].Name != "rule_1" || rows[0].Packets != 0 {
		t.Fatalf("row 0: %+v", rows[0])
	}
	if rows[1].Packets != 12 || rows[1].Bytes != 4096 {
		t.Fatalf("row 1: %+v", rows[1])
	}
	wantComment := "outbound_firewall: drop L3 src 192.168.20.0/24 dst 172.21.0.0/16"
	if rows[0].Comment != wantComment {
		t.Fatalf("comment = %q, want %q", rows[0].Comment, wantComment)
	}
}

func TestParseVPNSessionsEmpty(t *testing.T) {
	s := ParseVPNSessions(readDump(t, "show_vpn_sessions_wireguard.txt"))
	if !s.EmptyJSON {
		t.Fatalf("%+v", s)
	}
	if len(s.Rows) != 0 {
		t.Fatalf("rows=%v", s.Rows)
	}
}

func TestParsePing(t *testing.T) {
	p := ParsePing(readDump(t, "ping_starlink_dish.txt"))
	if !p.OK || p.LossPct != "0%" || p.Transmitted != 3 || p.Received != 3 {
		t.Fatalf("%+v", p)
	}
}

func TestParseTunnelConfig(t *testing.T) {
	c := ParseTunnelConfig(readDump(t, "show_config_tunnels.txt"))
	if !c.Starlink.Enabled || c.Starlink.DishIP != "192.168.100.1" || c.Starlink.DishMode != "router" || c.Starlink.Interface != "eth 1" {
		t.Fatalf("starlink %+v", c.Starlink)
	}
	if !c.VPNServer.Enabled || c.VPNServer.Interface != "wan1" || !c.VPNServer.MFA {
		t.Fatalf("vpn %+v", c.VPNServer)
	}
	if strings.Contains(c.VPNServer.AddressRange, "crypt") {
		t.Fatal("secret leaked")
	}
	if !c.Tailscale.Enabled || !c.Tailscale.AcceptRoutes {
		t.Fatalf("tailscale %+v", c.Tailscale)
	}
	if c.Tailscale.AuthKeySet && c.Tailscale.AdvertiseRoutes == "" {
		t.Fatalf("advertise missing %+v", c.Tailscale)
	}
}

func TestSanitizeShowConfigTunnels(t *testing.T) {
	got := SanitizeCLIOutput(readDump(t, "show_config_tunnels.txt"))
	if strings.Contains(got, "$crypt$") {
		t.Fatalf("crypt leftover:\n%s", got)
	}
}

func TestParseLANConfig(t *testing.T) {
	lan := ParseLANConfig(readDump(t, "show_config_lan.txt"))
	if !lan.Authoritative {
		t.Fatal("expected authoritative DHCP")
	}
	if len(lan.VLANs) != 4 {
		t.Fatalf("vlans=%d %+v", len(lan.VLANs), lan.VLANs)
	}
	if lan.VLANs[0].ID != 1 || lan.VLANs[0].Address != "172.21.0.1" || lan.VLANs[0].ManagementAccess != "all" {
		t.Fatalf("vlan1 %+v", lan.VLANs[0])
	}
	foundTrunk := false
	for _, p := range lan.Ports {
		if p.Interface == "eth5" && p.Mode == "trunk" && p.AllowedVLANs == "1,30,100,200" {
			foundTrunk = true
			if !p.Shutdown {
				t.Fatalf("eth5 should be shutdown: %+v", p)
			}
		}
		if p.Interface == "eth3" {
			if p.Speed != "100" || p.Duplex != "full" || p.Advertise != "1000" {
				t.Fatalf("eth3 speed/duplex/advertise: %+v", p)
			}
			if p.Shutdown {
				t.Fatalf("eth3 should not be shutdown: %+v", p)
			}
		}
	}
	if !foundTrunk {
		t.Fatalf("ports %+v", lan.Ports)
	}
	if len(lan.DHCPPools) != 2 {
		t.Fatalf("pools=%d", len(lan.DHCPPools))
	}
	if lan.DHCPPools[0].AddressRange != "172.21.1.30 172.21.1.250" || lan.DHCPPools[0].Lease != "0d 2h 0m" {
		t.Fatalf("pool1 %+v", lan.DHCPPools[0])
	}
	if len(lan.Bindings) != 3 {
		t.Fatalf("bindings=%d %+v", len(lan.Bindings), lan.Bindings)
	}
	if lan.Bindings[0].MAC != "bc:a9:93:0d:89:62" || lan.Bindings[0].IP != "172.21.1.10" {
		t.Fatalf("bind0 %+v", lan.Bindings[0])
	}
	// Trailing fields on a bind line are DHCP options, not a description:
	// the device rejects free text there.
	if lan.Bindings[1].Options != "60 text Cambium-WiFi-AP" || lan.Bindings[1].Description != "" {
		t.Fatalf("options %+v", lan.Bindings[1])
	}
	// MAC case must survive parsing — `no bind` matches case-sensitively.
	if lan.Bindings[2].MAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("expected device casing preserved, got %+v", lan.Bindings[2])
	}
}

func TestParseGeoIPDefaultsToNoneWhenUnconfigured(t *testing.T) {
	inbound, outbound := ParseGeoIP("show config\n!\nhostname foo\n!\n")
	if inbound.Mode != "none" || outbound.Mode != "none" {
		t.Fatalf("expected mode 'none' when unconfigured, got inbound=%q outbound=%q", inbound.Mode, outbound.Mode)
	}
	if len(inbound.Countries) != 0 || len(outbound.Countries) != 0 {
		t.Fatalf("expected empty country lists, got inbound=%v outbound=%v", inbound.Countries, outbound.Countries)
	}
	if len(inbound.Exceptions) != 0 || len(outbound.Exceptions) != 0 {
		t.Fatalf("expected empty exception lists, got inbound=%v outbound=%v", inbound.Exceptions, outbound.Exceptions)
	}
}

func TestParseGeoIPParsesBothDirectionsIndependently(t *testing.T) {
	raw := `show config
!
firewall geo-ip-restrictions inbound mode allow
firewall geo-ip-restrictions inbound countries US,GB,DE
firewall geo-ip-allowlist inbound address-range start-address end-address 203.0.113.1 203.0.113.10
firewall geo-ip-restrictions outbound mode block
firewall geo-ip-restrictions outbound countries CN
!
`
	inbound, outbound := ParseGeoIP(raw)
	if inbound.Mode != "allow" {
		t.Errorf("inbound.Mode = %q, want allow", inbound.Mode)
	}
	if len(inbound.Countries) != 3 || inbound.Countries[0] != "US" || inbound.Countries[2] != "DE" {
		t.Errorf("inbound.Countries = %v", inbound.Countries)
	}
	if len(inbound.Exceptions) != 1 || inbound.Exceptions[0].StartIP != "203.0.113.1" || inbound.Exceptions[0].EndIP != "203.0.113.10" {
		t.Errorf("inbound.Exceptions = %v", inbound.Exceptions)
	}
	if outbound.Mode != "block" {
		t.Errorf("outbound.Mode = %q, want block", outbound.Mode)
	}
	if len(outbound.Countries) != 1 || outbound.Countries[0] != "CN" {
		t.Errorf("outbound.Countries = %v", outbound.Countries)
	}
	if len(outbound.Exceptions) != 0 {
		t.Errorf("outbound.Exceptions = %v, want none", outbound.Exceptions)
	}
}
