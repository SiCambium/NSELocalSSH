package nse

import "testing"

// Shapes taken verbatim from a live NSE3000 on 2.3-r6, with every value
// that could carry a credential replaced. The point of the fixture is the
// key names and the enable/disable spelling, not the numbers.
const serviceConfigCapture = `service show config
{
  "interface_eth": {
    "1": {
      "type": "wan",
      "wan_name": "wan1",
      "vlan": "",
      "ip_mode": "dhcp",
      "periodic_speedtest": "enable",
      "dyndns_mode": "disable",
      "dyndns_provider_id": "1"
    },
    "2": {
      "type": "wan",
      "wan_name": "wan2",
      "vlan": "30",
      "ip_mode": "dhcp",
      "periodic_speedtest": "disable",
      "dyndns_mode": "enable"
    }
  }
}
NSE-TEST(config)#`

func TestParseServiceConfig(t *testing.T) {
	svc, ok := ParseServiceConfig(serviceConfigCapture)
	if !ok {
		t.Fatal("a real capture should parse")
	}
	if got := svc.InterfaceEth["1"].PeriodicSpeedtest; got != "enable" {
		t.Errorf("eth1 periodic_speedtest = %q, want enable", got)
	}
	if got := svc.InterfaceEth["2"].VLAN; got != "30" {
		t.Errorf("eth2 vlan = %q, want 30", got)
	}
}

func TestParseServiceConfigRejectsRubbish(t *testing.T) {
	for _, raw := range []string{"", "%Error processing cli command", "{}", "not json"} {
		if _, ok := ParseServiceConfig(raw); ok {
			t.Errorf("ParseServiceConfig(%q) claimed a usable config", raw)
		}
	}
}

func TestEnrichFromServiceConfigFillsWhatShowConfigCannot(t *testing.T) {
	svc, ok := ParseServiceConfig(serviceConfigCapture)
	if !ok {
		t.Fatal("fixture did not parse")
	}
	cfg := CloudConfig{WANInterfaces: []WANInterface{
		{LANIntf: "eth1"},
		{LANIntf: "eth2"},
	}}
	enrichFromServiceConfig(&cfg, svc)

	if !cfg.WANInterfaces[0].Speedtest {
		t.Error("eth1 speedtest should be on: the device's own store says enable")
	}
	if cfg.WANInterfaces[1].Speedtest {
		t.Error("eth2 speedtest should be off")
	}
	if got := cfg.WANInterfaces[1].VLAN; got != "30" {
		t.Errorf("eth2 VLAN = %q, want 30", got)
	}
	if got := cfg.WANInterfaces[0].DynDNSConfig.Mode; got != "disable" {
		t.Errorf("eth1 dyndns mode = %q, want disable", got)
	}
}

// The whole reason this enrichment is allowed to exist: it may only fill
// fields the CLI cannot write. A value that came from `show config` is
// the running configuration and must survive untouched, or a change that
// did apply would be redrawn with its old value.
func TestEnrichFromServiceConfigNeverOverwritesLiveConfig(t *testing.T) {
	svc, _ := ParseServiceConfig(serviceConfigCapture)
	cfg := CloudConfig{WANInterfaces: []WANInterface{{
		LANIntf:        "eth2",
		Name:           "from-show-config",
		VLAN:           "99",
		SpareIPMode:    "static",
		TrafficShaping: "enable",
		DynDNSConfig:   DynDNSConfig{Mode: "enable"},
	}}}
	enrichFromServiceConfig(&cfg, svc)

	w := cfg.WANInterfaces[0]
	if w.Name != "from-show-config" {
		t.Errorf("Name was overwritten with %q", w.Name)
	}
	if w.VLAN != "99" {
		t.Errorf("VLAN was overwritten with %q", w.VLAN)
	}
	if w.SpareIPMode != "static" {
		t.Errorf("SpareIPMode was overwritten with %q", w.SpareIPMode)
	}
	if w.TrafficShaping != "enable" {
		t.Errorf("TrafficShaping was overwritten with %q", w.TrafficShaping)
	}
	if w.DynDNSConfig.Mode != "enable" {
		t.Errorf("DynDNS mode was overwritten with %q", w.DynDNSConfig.Mode)
	}
}

// An unrecognized spelling must read as "not set", never as "off": a
// field defaulting to false is how the speedtest flag spent this whole
// project reading Disabled on a device that had it enabled.
func TestEnableDisableLeavesUnknownAlone(t *testing.T) {
	if _, known := enableDisable("sometimes"); known {
		t.Error("an unrecognized value should not be treated as a decision")
	}
	if on, known := enableDisable("Enabled"); !known || !on {
		t.Error("Enabled should read as on")
	}
}
