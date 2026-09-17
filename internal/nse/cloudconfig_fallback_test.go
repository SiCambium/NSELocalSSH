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
	for i := range want.LANInterfaces {
		want.LANInterfaces[i].Name = ""
		want.LANInterfaces[i].RateLimitRules = RateLimitRules{}
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
