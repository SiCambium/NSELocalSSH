package nse

import "strings"

// DNSLocalHost, DNSForwardZone, and DNSFilterPolicy mirror cnMaestro's DNS
// tab: "Local DNS Entries" (static domain->IP overrides), "Conditional
// Forwarding Rules" (per-domain upstream resolver), and the "DNS Filter
// Mode"/"Policies" table. None of this is exposed via cloud-json-config,
// so (like Groups) it's parsed from the raw `show config` block tree.
// "local-host"/"forward-zone" command names and the dns-filter policy
// mechanism are CONFIRMED (NSE AI CLI research citing the design doc and,
// for dns-filter policy, a live capture from this exact device showing a
// real "Ad_Blocking" policy); the <domain> <ip>/<domain> <server> argument
// order for local-host/forward-zone is BEST-GUESS (inferred from the
// sibling "safe-search <domain> <ip>" leaf's confirmed order) since no
// live capture with either populated has been observed.
type DNSLocalHost struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

type DNSForwardZone struct {
	Domain string `json:"domain"`
	Server string `json:"server"`
}

// DNSFilterPolicy's Name/SafeSearch/DenySources("all")/DenyCategories
// fields and structure are CONFIRMED from a live capture of this device's
// own "Ad_Blocking" policy. DenySources holds the raw leaf value verbatim
// ("all", or best-guess "user-group <name>" by analogy with filter rules'
// "allowed-sources user-group <name>") so either form round-trips.
type DNSFilterPolicy struct {
	ID             int      `json:"id"`
	Name           string   `json:"name"`
	SafeSearch     string   `json:"safe_search"`
	DenySources    string   `json:"deny_sources"`
	DenyCategories []string `json:"deny_categories"`
}

type DNSAdvancedConfig struct {
	LocalHosts     []DNSLocalHost    `json:"local_hosts"`
	ForwardZones   []DNSForwardZone  `json:"forward_zones"`
	BypassGroups   []string          `json:"bypass_groups"`
	FilterPolicies []DNSFilterPolicy `json:"filter_policies"`
}

// ParseDNSAdvancedConfig parses the local-host/forward-zone/dns-override
// bypass-list/dns-filter policy leaves out of the "dns-server" submode in
// a raw `show config` capture.
func ParseDNSAdvancedConfig(raw string) DNSAdvancedConfig {
	var cfg DNSAdvancedConfig
	blk := ParseBlockTree(raw).Find("dns-server")
	if blk == nil {
		return cfg
	}
	for _, line := range leavesWithPrefix(blk, "local-host ") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			cfg.LocalHosts = append(cfg.LocalHosts, DNSLocalHost{Domain: fields[0], IP: fields[1]})
		}
	}
	for _, line := range leavesWithPrefix(blk, "forward-zone ") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			cfg.ForwardZones = append(cfg.ForwardZones, DNSForwardZone{Domain: fields[0], Server: fields[1]})
		}
	}
	cfg.BypassGroups = leavesWithPrefix(blk, "dns-override bypass-list ip-group ")
	for _, pblk := range blk.FindAll("dns-filter policy ") {
		cfg.FilterPolicies = append(cfg.FilterPolicies, DNSFilterPolicy{
			ID:             blockID(pblk.Header),
			Name:           leafValue(pblk, "name "),
			SafeSearch:     leafValue(pblk, "safe-search "),
			DenySources:    leafValue(pblk, "deny-sources "),
			DenyCategories: leavesWithPrefix(pblk, "deny-categories "),
		})
	}
	return cfg
}
