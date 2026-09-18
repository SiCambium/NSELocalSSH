package nse

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func loadShowConfigFull(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/show_config_full.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func loadCloudJSONConfig(t *testing.T) CloudConfig {
	t.Helper()
	body, err := os.ReadFile("testdata/cloud_json_config.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg CloudConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestCloudConfigFromShowConfigMatchesCloudJSON is the anchor for the
// whole fallback: both testdata captures were taken from the same device
// at the same moment, so a field derived from `show config` must equal the
// one cloud-json-config reported — for everything `show config` actually
// expresses. The handful of fields it doesn't are zeroed out of the
// expectation here and listed in CloudConfigFromShowConfig's doc comment;
// the comparison is otherwise whole-struct, so any new CloudConfig field
// that the fallback forgets to populate fails this test.
func TestCloudConfigFromShowConfigMatchesCloudJSON(t *testing.T) {
	got := CloudConfigFromShowConfig(loadShowConfigFull(t))
	want := loadCloudJSONConfig(t)

	want.Source = CloudSourceShowConfig
	// Not in `show config` at all — a separate `show feature-license`.
	want.FeatureLicense = nil
	// The other direction: CambiumRemote is derived from `show config` and
	// tagged json:"-", so it is absent from the cloud snapshot rather than
	// missing from the derivation. The reference capture is linked.
	if !got.CambiumRemote {
		t.Error("the reference capture carries `management cambium-remote` and should read as linked")
	}
	want.CambiumRemote = got.CambiumRemote
	for i := range want.LANInterfaces {
		want.LANInterfaces[i].Name = ""
		// Same direction as CambiumRemote: the reference cloud snapshot
		// predates inter_vlan_routing and carries no such key, so it
		// unmarshals false while the derivation correctly defaults it to
		// true. The default is pinned by
		// TestFallbackInterVLANRoutingDefaultsOn and the leaf parsing by
		// TestFallbackInterVLANRoutingDisabled, since this comparison
		// cannot check it.
		if !got.LANInterfaces[i].InterVLANRouting {
			t.Errorf("vlan %d: derivation should default inter-VLAN routing on", got.LANInterfaces[i].VLANID)
		}
		want.LANInterfaces[i].InterVLANRouting = got.LANInterfaces[i].InterVLANRouting
	}
	for i := range want.WANInterfaces {
		want.WANInterfaces[i].SpareIPMode = ""
		want.WANInterfaces[i].TrafficShaping = ""
		want.WANInterfaces[i].DynDNSConfig.Mode = ""
	}
	// Compared separately — see TestCloudConfigFallbackSnortCategories.
	got.SnortRuleCategory, want.SnortRuleCategory = nil, nil

	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Errorf("derived config differs from cloud-json-config\ngot:\n%s\nwant:\n%s", gotJSON, wantJSON)
	}
}

// TestCloudConfigFallbackSnortCategories pins the one place the two
// sources legitimately disagree in length: cloud-json-config reports a
// synthetic "community" entry that has no "rule-category" line behind it
// (snort-community takes no rule-category child at all — see
// config_handlers_threat.go). Every other entry must match exactly,
// including the "snort3-" prefix the CLI adds and the JSON doesn't.
func TestCloudConfigFallbackSnortCategories(t *testing.T) {
	got := CloudConfigFromShowConfig(loadShowConfigFull(t))
	want := loadCloudJSONConfig(t)

	inWant := map[string]bool{}
	for _, c := range want.SnortRuleCategory {
		inWant[c.Category] = true
	}
	for _, c := range got.SnortRuleCategory {
		if !inWant[c.Category] {
			t.Errorf("derived category %q is not in cloud-json-config's list", c.Category)
		}
		delete(inWant, c.Category)
	}
	if len(inWant) != 1 || !inWant["community"] {
		t.Errorf("expected exactly the synthetic \"community\" entry to be missing, got %v", inWant)
	}
	if got.IPSRuleType != "snort-vrt" {
		t.Errorf("rule type = %q, want snort-vrt (the bare rule-type leaf, not a rule-category one)", got.IPSRuleType)
	}
}

// TestCloudConfigFallbackDHCPPoolPairing guards the subnet-matching that
// pairs each VLAN with its DHCP pool. Pool numbers are unrelated to VLAN
// IDs on this device (VLAN 30's pool is "ip dhcp pool 2"), and
// poolNumberForVLAN relies on the start address landing on the right VLAN,
// so a mispairing here would silently edit the wrong scope.
func TestCloudConfigFallbackDHCPPoolPairing(t *testing.T) {
	got := CloudConfigFromShowConfig(loadShowConfigFull(t))
	want := map[int]string{1: "172.21.1.30", 30: "192.168.21.30", 100: "172.23.1.30", 200: "172.16.1.20"}
	if len(got.LANInterfaces) != len(want) {
		t.Fatalf("got %d VLANs, want %d", len(got.LANInterfaces), len(want))
	}
	for _, v := range got.LANInterfaces {
		wantStart, ok := want[v.VLANID]
		if !ok {
			t.Errorf("unexpected VLAN %d", v.VLANID)
			continue
		}
		if v.DHCPPoolConfig.StartAddress != wantStart {
			t.Errorf("VLAN %d pool start = %q, want %q", v.VLANID, v.DHCPPoolConfig.StartAddress, wantStart)
		}
		if !v.DHCPPoolConfig.Enable {
			t.Errorf("VLAN %d pool should be enabled", v.VLANID)
		}
	}

	// The same pairing the edit path actually uses.
	pools := ParseLANConfig(loadShowConfigFull(t)).DHCPPools
	for vlanID, wantPool := range map[int]int{1: 1, 30: 2, 100: 3, 200: 4} {
		if n := poolNumberForVLAN(vlanID, got, pools); n != wantPool {
			t.Errorf("poolNumberForVLAN(%d) = %d, want %d", vlanID, n, wantPool)
		}
	}
}

// TestCloudConfigFallbackNoSecrets is the fallback's half of the
// no-secret-fields policy the rest of cloudconfig.go keeps: `show config`
// carries the admin password hash, the oinkcode, the tailscale auth-key,
// the RADIUS secret and the VPN shared-secret in cleartext, and none of
// them may survive into a struct the frontend is handed.
func TestCloudConfigFallbackNoSecrets(t *testing.T) {
	raw := loadShowConfigFull(t)
	cfg := CloudConfigFromShowConfig(raw)
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	low := strings.ToLower(string(body))
	for _, needle := range []string{"redacted_for_testdata", "$crypt$", "secret", "auth-key", "oinkcode"} {
		if strings.Contains(low, needle) {
			t.Errorf("derived config leaks %q", needle)
		}
	}
	// Guard the guard: the source really does contain what we're looking for.
	if !strings.Contains(raw, "REDACTED_FOR_TESTDATA") {
		t.Fatal("testdata no longer carries secret-shaped values; this test proves nothing")
	}
}

// TestCloudConfigFallbackPortScanDefaultsOn pins the one leaf whose
// absence does not mean "off". The reference capture has no port-scan leaf
// under any VLAN and cloud-json-config reports port_scan true for all of
// them; a live device prints "no port-scan" only under the VLAN where it
// was actually disabled.
func TestCloudConfigFallbackPortScanDefaultsOn(t *testing.T) {
	raw := `interface vlan 10
 management-access all
 ip address 10.0.10.1 255.255.255.0
!
interface vlan 20
 management-access all
 no port-scan
 ip address 10.0.20.1 255.255.255.0
!
interface vlan 30
 port-scan
 ip address 10.0.30.1 255.255.255.0
!`
	want := map[int]bool{10: true, 20: false, 30: true}
	for _, v := range CloudConfigFromShowConfig(raw).LANInterfaces {
		if v.PortScan != want[v.VLANID] {
			t.Errorf("VLAN %d port_scan = %v, want %v", v.VLANID, v.PortScan, want[v.VLANID])
		}
	}
}

// TestClientCloudJSONMissThreshold covers the give-up rule: a reply in the
// CLI's error convention is believed at once, anything else (a live
// device's "could not open file", or a desynced read) has to repeat.
func TestClientCloudJSONMissThreshold(t *testing.T) {
	c := NewClient(Config{})
	c.noteCloudJSONMiss(false)
	if c.CloudJSONUnsupported() {
		t.Error("one non-definitive miss should not be conclusive")
	}
	c.noteCloudJSONHit()
	c.noteCloudJSONMiss(false)
	if c.CloudJSONUnsupported() {
		t.Error("a good reply in between should reset the count")
	}
	c.noteCloudJSONMiss(false)
	if !c.CloudJSONUnsupported() {
		t.Errorf("%d consecutive misses should be conclusive", cloudJSONMissLimit)
	}

	c = NewClient(Config{})
	c.noteCloudJSONMiss(true)
	if !c.CloudJSONUnsupported() {
		t.Error("an error-convention reply should be believed at once")
	}
}

// TestCloudConfigFromShowConfigEmpty makes sure the deriver degrades to a
// zero value rather than panicking when handed nothing useful — the case
// FetchCloudConfig turns into a "returned nothing recognizable" error.
func TestCloudConfigFromShowConfigEmpty(t *testing.T) {
	for _, raw := range []string{"", "show config\n", "%Error processing cli command\n"} {
		cfg := CloudConfigFromShowConfig(raw)
		if cfg.SystemName != "" || len(cfg.LANInterfaces) != 0 || len(cfg.WANInterfaces) != 0 {
			t.Errorf("CloudConfigFromShowConfig(%q) = %+v, want empty", raw, cfg)
		}
	}
}

// TestClientCloudJSONCapability covers the bookkeeping that keeps the
// fallback cheap: a device that rejected cloud-json-config is remembered,
// the derived config is reused only within its TTL, every write drops it,
// and pointing the client at a different device resets both.
func TestClientCloudJSONCapability(t *testing.T) {
	c := NewClient(Config{Host: "10.0.0.1", User: "admin", Password: "x"})
	if c.CloudJSONUnsupported() {
		t.Fatal("a fresh client should try cloud-json-config")
	}
	c.noteCloudJSONMiss(true)
	if !c.CloudJSONUnsupported() {
		t.Fatal("rejection should be remembered")
	}

	if _, ok := c.cachedDerivedConfig(time.Minute); ok {
		t.Fatal("nothing cached yet")
	}
	c.storeDerivedConfig(CloudConfig{SystemName: "NSE-Test"})
	got, ok := c.cachedDerivedConfig(time.Minute)
	if !ok || got.SystemName != "NSE-Test" {
		t.Fatalf("cachedDerivedConfig = %+v, %v; want the stored config", got, ok)
	}
	if _, ok := c.cachedDerivedConfig(0); ok {
		t.Error("an expired entry should not be served")
	}

	c.invalidateDerivedConfig()
	if _, ok := c.cachedDerivedConfig(time.Minute); ok {
		t.Error("a write should drop the cached config")
	}

	c.storeDerivedConfig(CloudConfig{SystemName: "NSE-Test"})
	// Switching devices fails to connect here, which is fine: the reset
	// happens before the dial.
	_ = c.ApplyConfig(Config{Host: "10.0.0.2", User: "admin", Password: "y"})
	if c.CloudJSONUnsupported() {
		t.Error("a different device should be tried afresh")
	}
	if _, ok := c.cachedDerivedConfig(time.Minute); ok {
		t.Error("a different device's config must not be served from cache")
	}
}

// TestCloudJSONDetail checks the error message that turned a bare "no JSON
// object found" into something that says what the device actually replied.
func TestCloudJSONDetail(t *testing.T) {
	if got := cloudJSONDetail(nil); got != "" {
		t.Errorf("nil = %q, want empty", got)
	}
	if got := cloudJSONDetail(&LineResult{OK: true}); got != "" {
		t.Errorf("no error = %q, want empty", got)
	}
	// A device that answers outside the error convention still gets its
	// words reported — this is what a live NSE3000 actually says.
	if got := cloudJSONDetail(&LineResult{OK: true, Output: "could not open file"}); got != " (could not open file)" {
		t.Errorf("non-conventional reply = %q", got)
	}
	r := classifyLine(cloudJSONCommand, cloudJSONCommand+"\r\n%Error processing cli command\r\nNSE(config)# ")
	if r.OK {
		t.Fatal("an error-convention reply should classify as a rejection")
	}
	if got := cloudJSONDetail(&r); got != " (%Error processing cli command)" {
		t.Errorf("detail = %q", got)
	}
	long := &LineResult{Error: "%Error " + string(make([]byte, 400))}
	if got := cloudJSONDetail(long); len(got) > 124 {
		t.Errorf("detail not capped: %d bytes", len(got))
	}
}

// TestEnrichFromCloudJSONNeverOverwritesLiveConfig is the guard on the bug
// that caused this design. cloud-json-config is a cnMaestro-facing
// snapshot that does not track local CLI edits — confirmed live, where it
// went on reporting an old monitor-host list after the change had applied
// AND been saved. Anything the CLI can write must therefore come from
// `show config` and never be touched by the enrichment.
func TestEnrichFromCloudJSONNeverOverwritesLiveConfig(t *testing.T) {
	live := CloudConfig{
		SystemName: "NSE-live",
		LANInterfaces: []LANInterface{{
			VLANID: 10, IPAddr: "10.0.10.1", SubnetMask: "255.255.255.0",
			ManagementAccess: "enable", PortScan: true,
			DHCPPoolConfig: DHCPPoolConfig{Enable: true, StartAddress: "10.0.10.50"},
		}},
		WANInterfaces: []WANInterface{{
			Name: "wan1", LANIntf: "eth1", IPMode: "dynamic", SourceNAT: "enable",
			LoadBalanceConfig: LoadBalanceConfig{
				Mode:         "backup",
				MonitorHosts: []string{"8.8.8.8", "1.1.1.1"},
			},
			BandwidthConfig: BandwidthConfig{UplinkBandwidth: "40"},
		}},
		IPS: true, IPSMode: "prevention", DNSServer: "enable",
		Tailscale: CloudTailscale{Enable: true},
	}
	// A snapshot that disagrees about everything the CLI can change.
	stale := CloudConfig{
		SystemName: "NSE-stale",
		LANInterfaces: []LANInterface{{
			VLANID: 10, Name: "Guest WiFi", IPAddr: "192.168.99.1",
			SubnetMask: "255.255.0.0", ManagementAccess: "disable", PortScan: false,
			DHCPPoolConfig: DHCPPoolConfig{StartAddress: "192.168.99.50"},
			RateLimitRules: RateLimitRules{RateLimit: "disable"},
		}},
		WANInterfaces: []WANInterface{{
			Name: "wanX", LANIntf: "eth1", IPMode: "static", SourceNAT: "disable",
			LoadBalanceConfig: LoadBalanceConfig{
				Mode:         "shared",
				MonitorHosts: []string{"8.8.8.8"},
			},
			BandwidthConfig: BandwidthConfig{UplinkBandwidth: "999"},
			SpareIPMode:     "dynamic",
			TrafficShaping:  "disable",
			DynDNSConfig:    DynDNSConfig{Mode: "disable"},
		}},
		IPS: false, IPSMode: "detection", DNSServer: "disable",
		Tailscale: CloudTailscale{Enable: false},
	}

	got := live
	enrichFromCloudJSON(&got, stale)

	// The whole point: the live monitor-host list must survive.
	wanted := []string{"8.8.8.8", "1.1.1.1"}
	if !reflect.DeepEqual(got.WANInterfaces[0].LoadBalanceConfig.MonitorHosts, wanted) {
		t.Errorf("monitor hosts = %v, want %v — a stale snapshot overwrote a live value",
			got.WANInterfaces[0].LoadBalanceConfig.MonitorHosts, wanted)
	}
	for _, c := range []struct {
		field string
		got   any
		want  any
	}{
		{"SystemName", got.SystemName, "NSE-live"},
		{"WAN name", got.WANInterfaces[0].Name, "wan1"},
		{"WAN ip_mode", got.WANInterfaces[0].IPMode, "dynamic"},
		{"WAN source_nat", got.WANInterfaces[0].SourceNAT, "enable"},
		{"WAN lb mode", got.WANInterfaces[0].LoadBalanceConfig.Mode, "backup"},
		{"WAN uplink", got.WANInterfaces[0].BandwidthConfig.UplinkBandwidth, "40"},
		{"VLAN ip", got.LANInterfaces[0].IPAddr, "10.0.10.1"},
		{"VLAN mask", got.LANInterfaces[0].SubnetMask, "255.255.255.0"},
		{"VLAN mgmt access", got.LANInterfaces[0].ManagementAccess, "enable"},
		{"VLAN port_scan", got.LANInterfaces[0].PortScan, true},
		{"DHCP start", got.LANInterfaces[0].DHCPPoolConfig.StartAddress, "10.0.10.50"},
		{"IPS", got.IPS, true},
		{"IPS mode", got.IPSMode, "prevention"},
		{"DNS server", got.DNSServer, "enable"},
		{"Tailscale enable", got.Tailscale.Enable, true},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v — enrichment must not touch CLI-writable fields", c.field, c.got, c.want)
		}
	}

	// And it must still do its actual job: fill what `show config` can't say.
	if got.LANInterfaces[0].Name != "Guest WiFi" {
		t.Errorf("VLAN label = %q, want the cloud-json one", got.LANInterfaces[0].Name)
	}
	if got.LANInterfaces[0].RateLimitRules.RateLimit != "disable" {
		t.Errorf("rate limit = %q, want the cloud-json one", got.LANInterfaces[0].RateLimitRules.RateLimit)
	}
	if got.WANInterfaces[0].SpareIPMode != "dynamic" || got.WANInterfaces[0].TrafficShaping != "disable" {
		t.Error("display-only WAN fields were not filled in")
	}
	if got.WANInterfaces[0].DynDNSConfig.Mode != "disable" {
		t.Error("dyndns mode was not filled in")
	}
}

// TestEnrichFromCloudJSONHandlesMismatch covers a snapshot describing a
// device that has since been reconfigured — VLANs and ports that no longer
// line up must simply be skipped, not matched by position.
func TestEnrichFromCloudJSONHandlesMismatch(t *testing.T) {
	live := CloudConfig{
		LANInterfaces: []LANInterface{{VLANID: 10}, {VLANID: 20}},
		WANInterfaces: []WANInterface{{LANIntf: "eth1"}},
	}
	stale := CloudConfig{
		LANInterfaces: []LANInterface{{VLANID: 20, Name: "Twenty"}, {VLANID: 99, Name: "Gone"}},
		WANInterfaces: []WANInterface{{LANIntf: "eth4", Name: "wan9"}},
	}
	got := live
	enrichFromCloudJSON(&got, stale)
	if got.LANInterfaces[0].Name != "" {
		t.Errorf("VLAN 10 picked up a label from a different VLAN: %q", got.LANInterfaces[0].Name)
	}
	if got.LANInterfaces[1].Name != "Twenty" {
		t.Errorf("VLAN 20 label = %q, want matching by id", got.LANInterfaces[1].Name)
	}
	if got.WANInterfaces[0].Name != "" {
		t.Errorf("eth1 picked up eth4's name: %q", got.WANInterfaces[0].Name)
	}
}

// TestFallbackWANInterfacesBeyondSixPorts guards against the fixed
// eth1-eth6 scan this used to do. An NSE4000 has ten ethernet ports, so a
// WAN on eth7 or above was simply invisible.
func TestFallbackWANInterfacesBeyondSixPorts(t *testing.T) {
	raw := `interface eth 1
 type lan
 switchport mode access
!
interface eth 8
 type wan
 wan-name wan2
 ip address dhcp
 load-balance mode shared
 load-balance monitor-hosts 8.8.8.8,1.1.1.1
!
interface eth 10
 type wan
 wan-name wan3
 ip address dhcp
!`
	wans := CloudConfigFromShowConfig(raw).WANInterfaces
	if len(wans) != 2 {
		t.Fatalf("found %d WANs, want 2 (eth8 and eth10)", len(wans))
	}
	if wans[0].LANIntf != "eth8" || wans[1].LANIntf != "eth10" {
		t.Errorf("WAN ports = %q, %q; want eth8, eth10 in order", wans[0].LANIntf, wans[1].LANIntf)
	}
	if wans[0].PortNumber() != 8 {
		t.Errorf("PortNumber() = %d, want 8 — the default-gateway index depends on it", wans[0].PortNumber())
	}
	if got := wans[0].LoadBalanceConfig.MonitorHosts; len(got) != 2 || got[1] != "1.1.1.1" {
		t.Errorf("monitor hosts = %v", got)
	}
}

// Inter-VLAN routing is enabled by default and the device prints nothing
// for it; only the negative leaf ever appears. Both directions are pinned
// here because the whole-struct comparison above cannot check this field —
// the reference cloud snapshot predates the key.
func TestFallbackInterVLANRoutingDefaultsOn(t *testing.T) {
	cfg := CloudConfigFromShowConfig("show config\n!\ninterface vlan 40\n ip address 192.168.40.1 255.255.255.0\n exit\n!\n")
	if len(cfg.LANInterfaces) != 1 {
		t.Fatalf("lan interfaces = %d", len(cfg.LANInterfaces))
	}
	if !cfg.LANInterfaces[0].InterVLANRouting {
		t.Fatal("absent leaf must read as enabled")
	}
}

func TestFallbackInterVLANRoutingDisabled(t *testing.T) {
	cfg := CloudConfigFromShowConfig("show config\n!\ninterface vlan 40\n ip address 192.168.40.1 255.255.255.0\n no inter-vlan-routing\n exit\n!\n")
	if len(cfg.LANInterfaces) != 1 {
		t.Fatalf("lan interfaces = %d", len(cfg.LANInterfaces))
	}
	if cfg.LANInterfaces[0].InterVLANRouting {
		t.Fatal("\"no inter-vlan-routing\" must read as disabled")
	}
}

func TestVLANInterVLANRoutingLine(t *testing.T) {
	if got := VLANInterVLANRoutingLine(true); got != "inter-vlan-routing" {
		t.Fatalf("enable line %q", got)
	}
	if got := VLANInterVLANRoutingLine(false); got != "no inter-vlan-routing" {
		t.Fatalf("disable line %q", got)
	}
	// A cross-VLAN management session is routed traffic, so turning this
	// off can sever the session doing the editing.
	if ClassifyRisk("vlan-inter-vlan-routing") != RiskLockout {
		t.Fatal("inter-VLAN routing changes must go through safe-apply")
	}
}

// A VLAN's rate limit lives in the filter table, not under the VLAN. The
// reference capture has no such rule (every VLAN reads "disable", which
// the whole-struct comparison above now checks), so the enabled case is
// pinned here against the shape confirmed live on an NSE 4000.
func TestFallbackRateLimitFromFilterRule(t *testing.T) {
	raw := `show config
!
interface vlan 40
 ip address 192.168.40.1 255.255.255.0
 exit
!
interface vlan 30
 ip address 192.168.30.1 255.255.255.0
 exit
!
filter  global-filter
  filter precedence 17
     layer3-filter permit ip 192.168.40.0/255.255.255.0 any any
     rate-limit sta Mbps 100
     exit
  exit
!
`
	cfg := CloudConfigFromShowConfig(raw)
	byID := map[int]LANInterface{}
	for _, l := range cfg.LANInterfaces {
		byID[l.VLANID] = l
	}
	if got := byID[40].RateLimitRules; got.RateLimit != "enable" || got.Limit != "100" {
		t.Fatalf("vlan 40 rate limit = %+v, want enable/100", got)
	}
	// A VLAN with no matching rule is not rate limited.
	if got := byID[30].RateLimitRules; got.RateLimit != "disable" {
		t.Fatalf("vlan 30 rate limit = %+v, want disable", got)
	}
}

// The source address sits after "ip", or after "proto <proto>".
func TestLayer3FilterSource(t *testing.T) {
	cases := map[string]string{
		"layer3-filter permit ip 192.168.40.0/255.255.255.0 any any":                       "192.168.40.0/255.255.255.0",
		"layer3-filter permit proto udp 192.168.20.0/255.255.255.0 any 10.0.0.0/8 1900 in": "192.168.20.0/255.255.255.0",
	}
	for line, want := range cases {
		if got := layer3FilterSource([]string{line}); got != want {
			t.Errorf("source of %q = %q, want %q", line, got, want)
		}
	}
}
