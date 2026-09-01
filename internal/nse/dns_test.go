package nse

import "testing"

func TestParseDNSAdvancedConfig(t *testing.T) {
	raw := `show config
!
dns-server
 filter-mode filtering
 local-host nas.lan 172.21.1.50
 local-host printer.lan 172.21.1.60
 forward-zone corp.example 10.1.1.1
 dns-override
 dns-override bypass-list ip-group Enterprise-Servers
 dns-filter policy 1
    name Ad_Blocking
    safe-search disabled
    deny-sources all
    deny-categories malware-sites
    deny-categories spyware-and-adware
    exit
 no dns-override
 exit
!
NSE-Caravan(config)# `
	cfg := ParseDNSAdvancedConfig(raw)
	if len(cfg.LocalHosts) != 2 {
		t.Fatalf("got %d local hosts: %+v", len(cfg.LocalHosts), cfg.LocalHosts)
	}
	if cfg.LocalHosts[0].Domain != "nas.lan" || cfg.LocalHosts[0].IP != "172.21.1.50" {
		t.Fatalf("local host 0 = %+v", cfg.LocalHosts[0])
	}
	if len(cfg.ForwardZones) != 1 || cfg.ForwardZones[0].Domain != "corp.example" || cfg.ForwardZones[0].Server != "10.1.1.1" {
		t.Fatalf("forward zones = %+v", cfg.ForwardZones)
	}
	if len(cfg.BypassGroups) != 1 || cfg.BypassGroups[0] != "Enterprise-Servers" {
		t.Fatalf("bypass groups = %+v", cfg.BypassGroups)
	}
	if len(cfg.FilterPolicies) != 1 {
		t.Fatalf("got %d filter policies: %+v", len(cfg.FilterPolicies), cfg.FilterPolicies)
	}
	p := cfg.FilterPolicies[0]
	if p.ID != 1 || p.Name != "Ad_Blocking" || p.SafeSearch != "disabled" || p.DenySources != "all" {
		t.Fatalf("policy = %+v", p)
	}
	if len(p.DenyCategories) != 2 || p.DenyCategories[0] != "malware-sites" || p.DenyCategories[1] != "spyware-and-adware" {
		t.Fatalf("policy categories = %+v", p.DenyCategories)
	}
}

func TestParseDNSAdvancedConfigEmptyWhenNoBlock(t *testing.T) {
	cfg := ParseDNSAdvancedConfig("hostname foo\n")
	if len(cfg.LocalHosts) != 0 || len(cfg.ForwardZones) != 0 || len(cfg.BypassGroups) != 0 || len(cfg.FilterPolicies) != 0 {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}
