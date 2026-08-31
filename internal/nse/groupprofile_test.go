package nse

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNetworkSrcMarshalJSONDynamicKeys(t *testing.T) {
	n := NetworkSrc{
		DHCPAuthoritative: true,
		LANInterfaces:     []profileLANInterface{},
		Ports: []PortVLAN{
			{Interface: "eth1", Type: "wan"}, // must be excluded — covered by wan_interfaces instead
			{Interface: "eth3", Type: "lan", Mode: "access", AccessVLAN: "100"},
			{Interface: "eth5", Type: "lan", Mode: "trunk", NativeVLAN: "1", AllowedVLANs: "1,30,100,200"},
		},
	}
	body, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, key := range []string{"interface_eth1_mode", "interface_eth1_type", "interface_eth1_access_vlan"} {
		if _, ok := out[key]; ok {
			t.Errorf("WAN port eth1 should not produce dynamic key %q", key)
		}
	}

	if out["interface_eth3_mode"] != "access" || out["interface_eth3_type"] != "lan" {
		t.Fatalf("eth3 mode/type = %v/%v", out["interface_eth3_mode"], out["interface_eth3_type"])
	}
	if v, ok := out["interface_eth3_access_vlan"].(float64); !ok || v != 100 {
		t.Fatalf("eth3 access_vlan = %v", out["interface_eth3_access_vlan"])
	}
	if _, ok := out["interface_eth3_native_vlan"]; ok {
		t.Error("access port should not have a native_vlan key")
	}

	if out["interface_eth5_mode"] != "trunk" {
		t.Fatalf("eth5 mode = %v", out["interface_eth5_mode"])
	}
	if v, ok := out["interface_eth5_native_vlan"].(float64); !ok || v != 1 {
		t.Fatalf("eth5 native_vlan = %v", out["interface_eth5_native_vlan"])
	}
	if out["interface_eth5_allowed_vlan"] != "1,30,100,200" {
		t.Fatalf("eth5 allowed_vlan = %v", out["interface_eth5_allowed_vlan"])
	}
	if _, ok := out["interface_eth3_desc"]; !ok {
		t.Error("expected an explicit (null) _desc key, matching a real cnMaestro export")
	}
	if out["dhcp_authoritative"] != true {
		t.Errorf("dhcp_authoritative = %v", out["dhcp_authoritative"])
	}
}

func TestParseHighAvailabilityStatus(t *testing.T) {
	raw := `show config
!
high-availability role primary
high-availability port eth6
high-availability
!
NSE-Caravan(config)# `
	st := ParseHighAvailabilityStatus(raw)
	if st.Mode != "enable" || st.Role != "primary" || st.Interface != "6" {
		t.Fatalf("ParseHighAvailabilityStatus() = %+v", st)
	}
}

func TestParseHighAvailabilityStatusDisabled(t *testing.T) {
	st := ParseHighAvailabilityStatus("show config\n!\nhostname foo\n!\n")
	if st.Mode != "disable" {
		t.Fatalf("expected disable, got %+v", st)
	}
}

func TestBuildGroupProfileAgainstRealFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/cloud_json_config.json")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := "service show cloud-json-config\r\n" + string(body) + "\r\nNSE-Caravan(config)# "
	var cloud CloudConfig
	if err := json.Unmarshal([]byte(extractJSONObject(wrapped)), &cloud); err != nil {
		t.Fatalf("Unmarshal cloud config: %v", err)
	}
	cfgRaw, err := os.ReadFile("testdata/show_config_full.txt")
	if err != nil {
		t.Fatal(err)
	}
	lan := ParseLANConfig(string(cfgRaw))
	groups := ParseGroupsConfig(string(cfgRaw))

	profile := BuildGroupProfile(cloud, groups, lan, string(cfgRaw))

	if len(profile.Src.WAN.WANInterfaces) != 2 {
		t.Fatalf("WAN interfaces = %d, want 2", len(profile.Src.WAN.WANInterfaces))
	}
	if profile.Src.Hidden.SystemName != "NSE-Caravan" {
		t.Errorf("system_name = %q", profile.Src.Hidden.SystemName)
	}
	if profile.Src.Management.TZName != "Europe/London" {
		t.Errorf("tz_name = %q", profile.Src.Management.TZName)
	}
	if !profile.Src.ThreatProtection.IPS || profile.Src.ThreatProtection.IPSMode != "prevention" {
		t.Errorf("threat protection = %+v", profile.Src.ThreatProtection)
	}
	if !profile.Src.VPN.Tailscale.Enable {
		t.Error("expected tailscale enabled")
	}
	if len(profile.Src.VPN.RADIUSClientList) != 1 || profile.Src.VPN.RADIUSClientList[0].Name != "Demo1" {
		t.Errorf("radius clients = %+v", profile.Src.VPN.RADIUSClientList)
	}
	if profile.Src.HA.HighAvailability.Mode != "enable" || profile.Src.HA.HighAvailability.Role != "primary" {
		t.Errorf("ha = %+v", profile.Src.HA.HighAvailability)
	}
	if len(profile.Src.Firewall.FilterConfig) == 0 {
		t.Error("expected at least one filter_config entry")
	}

	// The whole thing must actually be valid, secret-free JSON.
	body2, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("Marshal full profile: %v", err)
	}
	full := string(body2)
	for _, secret := range []string{"$crypt$", "oinkcode", "auth_key", "shared-secret", "shared_secret"} {
		if strings.Contains(full, secret) {
			t.Errorf("exported profile JSON contains secret-shaped substring %q", secret)
		}
	}
}
