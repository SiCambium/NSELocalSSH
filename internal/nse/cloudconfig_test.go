package nse

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCloudConfigParsesRealFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/cloud_json_config.json")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the SSH envelope: command echo, CRLF-terminated JSON, prompt.
	wrapped := "service show cloud-json-config\r\n" + string(body) + "\r\nNSE-Caravan(config)# "

	obj := extractJSONObject(wrapped)
	if obj == "" {
		t.Fatal("extractJSONObject found nothing")
	}
	var cfg CloudConfig
	if err := json.Unmarshal([]byte(obj), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(cfg.WANInterfaces) != 2 {
		t.Fatalf("WANInterfaces = %d, want 2", len(cfg.WANInterfaces))
	}
	wan1 := cfg.WANInterfaces[0]
	if wan1.Name != "wan1" || wan1.LANIntf != "eth1" || wan1.PortNumber() != 1 {
		t.Fatalf("wan1 = %+v", wan1)
	}
	if !wan1.StarlinkEnable || wan1.StarlinkDishIP != "192.168.100.1" {
		t.Fatalf("wan1 starlink fields wrong: %+v", wan1)
	}
	if wan1.LoadBalanceConfig.TrafficSharePercentage != "95" {
		t.Fatalf("wan1 load balance = %+v", wan1.LoadBalanceConfig)
	}
	if len(wan1.LoadBalanceConfig.MonitorHosts) != 2 {
		t.Fatalf("wan1 monitor hosts = %v", wan1.LoadBalanceConfig.MonitorHosts)
	}

	if len(cfg.LANInterfaces) == 0 {
		t.Fatal("expected at least one LAN interface")
	}
	native := cfg.LANInterfaces[0]
	if native.Name != "native" || native.VLANID != 1 || native.IPAddr != "172.21.0.1" {
		t.Fatalf("native VLAN = %+v", native)
	}
	if !native.PortScan {
		t.Fatalf("expected port_scan true on native VLAN, got %+v", native)
	}

	if !cfg.FeatureLicense["device_fingerprint"] {
		t.Fatalf("feature_license = %+v", cfg.FeatureLicense)
	}

	// Management.
	if cfg.TZName != "Europe/London" || len(cfg.NTPServer) != 1 || cfg.NTPServer[0].Address != "time.google.com" {
		t.Fatalf("management fields wrong: tz=%q ntp=%+v", cfg.TZName, cfg.NTPServer)
	}
	if len(cfg.SyslogServer) != 1 || cfg.SyslogServer[0].IP != "172.22.0.9" || cfg.SyslogServer[0].Port != "514" {
		t.Fatalf("syslog server wrong: %+v", cfg.SyslogServer)
	}

	// Threat Protection.
	if !cfg.IPS || cfg.IPSMode != "prevention" || cfg.IPSRuleType != "snort-vrt" {
		t.Fatalf("IPS fields wrong: ips=%v mode=%q type=%q", cfg.IPS, cfg.IPSMode, cfg.IPSRuleType)
	}
	if len(cfg.SnortRuleCategory) == 0 || cfg.SnortRuleCategory[0].Category != "app-detect" {
		t.Fatalf("snort rule category wrong: %+v", cfg.SnortRuleCategory)
	}

	// DNS.
	if len(cfg.NameServer) != 2 || cfg.NameServer[1].IP != "8.8.8.8" {
		t.Fatalf("name servers wrong: %+v", cfg.NameServer)
	}

	// Firewall.
	if len(cfg.FilterConfig) == 0 || cfg.FilterConfig[0].FilterRule.Action != "deny" {
		t.Fatalf("filter config wrong: %+v", cfg.FilterConfig)
	}
	if !cfg.DOSProtectionSpoof {
		t.Fatalf("dos protection spoof should be true")
	}

	// VPN.
	if !cfg.Tailscale.Enable || cfg.Tailscale.AdvertiseRoutes == "" {
		t.Fatalf("tailscale fields wrong: %+v", cfg.Tailscale)
	}
	if len(cfg.RADIUSClientList) != 1 || cfg.RADIUSClientList[0].Netmask != "16" {
		t.Fatalf("radius client list wrong: %+v", cfg.RADIUSClientList)
	}
	if !cfg.VPNServerMFA {
		t.Fatalf("vpn_server_mfa should be true")
	}
}

func TestExtractJSONObjectHandlesEnvelope(t *testing.T) {
	wrapped := "show something\r\n{\"a\":1}\r\nNSE-Caravan(config)# "
	if got := extractJSONObject(wrapped); got != `{"a":1}` {
		t.Fatalf("extractJSONObject() = %q", got)
	}
}
