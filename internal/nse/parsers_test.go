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
	if lan.Bindings[1].Description != "camera-porch" {
		t.Fatalf("desc %+v", lan.Bindings[1])
	}
}
