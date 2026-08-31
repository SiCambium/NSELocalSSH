package nse

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// GroupProfile mirrors cnMaestro's own NSE Group export/import JSON
// schema, confirmed field-for-field against a real downloaded export
// (SimonSNSE4000-NSE_Group-*.json). This is a distinct concept from
// internal/nse/profiles.go, which stores this app's own SSH connection
// credentials — GroupProfile is a device-configuration snapshot.
//
// This is export-first: BuildGroupProfile only ever reads from the
// device. Sections with no confirmed CLI write syntax anywhere in this
// app (NAT 1:1/1:many, port-forward, GEO IP, DNS filter policies,
// WireGuard/IPsec/L2TP client VPN, groups) are emitted as null/empty —
// exactly what a device with those features unconfigured would produce —
// rather than guessed at. No secret-shaped field (passwords, PSKs, the
// Tailscale auth-key, the IPS oinkcode, RADIUS/DynDNS passwords) is ever
// populated, matching cloudconfig.go's policy: never modeled, so never at
// risk of being exported.
//
// This tool targets one physical device per connection, not a template
// shared across many — so unlike a real cnMaestro Group export, values
// are always literal (no "${VAR=default}" placeholders).
type GroupProfile struct {
	Description *string         `json:"description"`
	Types       []string        `json:"types"`
	Mode        []string        `json:"mode"`
	Adv         string          `json:"adv"`
	Policies    any             `json:"policies"`
	Src         GroupProfileSrc `json:"src"`
	AutoSync    bool            `json:"auto_sync"`
}

type GroupProfileSrc struct {
	HA               HASrc               `json:"ha"`
	DNS              DNSSrc              `json:"dns"`
	VPN              VPNSrc              `json:"vpn"`
	WAN              WANSrc              `json:"wan"`
	Basic            BasicSrc            `json:"basic"`
	Groups           GroupsSrc           `json:"groups"`
	Hidden           HiddenSrc           `json:"hidden"`
	Network          NetworkSrc          `json:"network"`
	Firewall         FirewallSrc         `json:"firewall"`
	Management       ManagementSrc       `json:"management"`
	ThreatProtection ThreatProtectionSrc `json:"threatProtection"`
}

type BasicSrc struct {
	HAInternal bool `json:"ha_internal"`
}

// HighAvailabilityStatus is parsed from `show config`'s bare
// "high-availability" / "high-availability role X" / "high-availability
// port ethN" lines — a read-only view; this app has no HA write support
// yet (HA is classified RiskLockout and deliberately unimplemented).
type HighAvailabilityStatus struct {
	Mode      string `json:"mode"` // "enable" | "disable", inferred from the bare keyword's presence
	Role      string `json:"role"`
	Interface string `json:"interface"` // eth port number as a string, e.g. "6"
}

type HASrc struct {
	HighAvailability HighAvailabilityStatus `json:"high_availability"`
}

func ParseHighAvailabilityStatus(cfgRaw string) HighAvailabilityStatus {
	st := HighAvailabilityStatus{Mode: "disable"}
	tree := ParseBlockTree(cfgRaw)
	for _, child := range tree.Children {
		if child.Block != nil {
			continue
		}
		switch {
		case child.Line == "high-availability":
			st.Mode = "enable"
		case strings.HasPrefix(child.Line, "high-availability role "):
			st.Role = strings.TrimPrefix(child.Line, "high-availability role ")
		case strings.HasPrefix(child.Line, "high-availability port eth"):
			st.Interface = strings.TrimPrefix(child.Line, "high-availability port eth")
		}
	}
	return st
}

type HiddenSrc struct {
	SystemName string `json:"system_name"`
}

// GroupsSrc's real per-item schema is unconfirmed (every captured export
// has had these fields unpopulated), so they're always emitted null here
// rather than guessed — this app's own Groups section (config-groups.js)
// is the way to manage these live; this profile field is for interop only
// once a real populated example is available to confirm the key names.
type GroupsSrc struct {
	IPGroups          any `json:"ip_groups"`
	UserGroups        any `json:"user_groups"`
	ApplicationGroups any `json:"application_groups"`
}

type ManagementSrc struct {
	TZName       string       `json:"tz_name"`
	NTPServer    []NTPServer  `json:"ntp_server"`
	SyslogServer []SyslogHost `json:"syslog_server"`
}

type ThreatProtectionSrc struct {
	IPS               bool           `json:"ips"`
	IPSMode           string         `json:"ips_mode"`
	IPSRuleSet        string         `json:"ips_rule_set"`
	IPSRuleType       string         `json:"ips_rule_type"`
	IPSAutoUpdate     bool           `json:"ips_auto_update"`
	IPSUpdateInterval string         `json:"ips_update_interval"`
	SnortRuleCategory []SnortRuleCat `json:"snort_vrt_rule_category"`
	// ips_oinkcode deliberately omitted: it's a directly-usable secret
	// (confirmed cleartext, not a hash — see NSE3000-CLI-REFERENCE.md).
}

type dnsFilterConfiguration struct {
	FilterMode string `json:"filter_mode"`
}

type dnsFiltersSrc struct {
	Policies      any                    `json:"policies"` // unconfirmed schema for a populated policy, same reasoning as GroupsSrc
	Configuration dnsFilterConfiguration `json:"configuration"`
}

type DNSSrc struct {
	DNSServer               string           `json:"dns_server"`
	DNSFilters              dnsFiltersSrc    `json:"dns_filters"`
	LocalHosts              any              `json:"local_hosts"`
	NameServer              []NameServerHost `json:"name_server"`
	DNSOverride             bool             `json:"dns_override"`
	ForwardingZones         any              `json:"forwarding_zones"`
	LoggingSyslogDNSMasq    bool             `json:"logging_syslog_dnsmasq"`
	DNSOverrideBypassList   any              `json:"dns_override_bypass_list"`
	LearnDNSServersFromDHCP bool             `json:"learn_dns_servers_from_dhcp"`
}

type profileTailscale struct {
	Enable          bool   `json:"enable"`
	AcceptRoutes    bool   `json:"accept_routes"`
	AdvertiseRoutes string `json:"advertise_routes"`
	// auth_key deliberately omitted: a real, directly-usable secret.
}

type profileRADIUSClient struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Netmask string `json:"netmask"`
	// secret deliberately omitted.
}

type VPNSrc struct {
	Tailscale          profileTailscale      `json:"tailscale"`
	SiteToSite         bool                  `json:"site_to_site"`
	VPNServerInterface string                `json:"vpn_server_interface"`
	RADIUSClientList   []profileRADIUSClient `json:"radius_client_list"`
	// WireGuard/IPsec/L2TP client VPN and site-to-site tunnel parameters
	// are not modeled: no confirmed CLI write syntax exists for them in
	// this app yet, so there's nothing to faithfully export beyond what's
	// already covered by the fields above.
}

type WANSrc struct {
	WANInterfaces []WANInterface `json:"wan_interfaces"`
}

type profileDHCPBind struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
	Desc string `json:"desc"`
}

// profileDHCPOption's shape is UNCONFIRMED — every captured real export
// has had an empty dhcp_options array, so "code"/"value" here are a
// best-effort guess matching this app's own DHCPOption naming, not a
// verified cnMaestro key. Populated only if this app's own (equally
// unconfirmed) dhcp-option read path ever returns data.
type profileDHCPOption struct {
	Code  int    `json:"code"`
	Value string `json:"value"`
}

type profileDHCPPoolConfig struct {
	DHCPOptions        []profileDHCPOption `json:"dhcp_options"`
	Enable             bool                `json:"dhcp_pool_enable"`
	BindList           []profileDHCPBind   `json:"dhcp_pool_bind_list"`
	EndAddress         string              `json:"dhcp_pool_end_address"`
	StartAddress       string              `json:"dhcp_pool_start_address"`
	LeaseTimeDay       int                 `json:"dhcp_pool_lease_time_day"`
	LeaseTimeHour      int                 `json:"dhcp_pool_lease_time_hour"`
	LeaseTimeMinute    int                 `json:"dhcp_pool_lease_time_minute"`
	PrimaryDNSServer   string              `json:"dhcp_pool_primary_dns_server,omitempty"`
	SecondaryDNSServer string              `json:"dhcp_pool_secondary_dns_server,omitempty"`
}

type profileLANInterface struct {
	DHCP             string                `json:"dhcp"`
	Name             string                `json:"name"`
	IPAddr           string                `json:"ip_addr"`
	IPMode           string                `json:"ip_mode"`
	VLANID           int                   `json:"vlan_id"`
	PortScan         bool                  `json:"port_scan"`
	SubnetMask       string                `json:"subnet_mask"`
	DeviceIdentity   bool                  `json:"device_identity"`
	DHCPPoolConfig   profileDHCPPoolConfig `json:"dhcp_pool_config"`
	RateLimitRules   RateLimitRules        `json:"rate_limit_rules"`
	ManagementAccess string                `json:"management_access"`
}

var profileEthRE = regexp.MustCompile(`^eth(\d+)$`)

// NetworkSrc carries lan_interfaces plus cnMaestro's dynamic
// "interface_eth{N}_{suffix}" keys for non-WAN physical ports — their
// names are data-dependent (one set of keys per LAN port actually present
// on the device), so they need a custom marshaler rather than a fixed
// struct field per key. Only the fields this app has confirmed read data
// for are emitted (mode, type, and the switchport-mode-dependent VLAN
// keys) — phy_speed/phy_duplex/lldp_pba/shutdown/tag_native/phy_advertise
// are real keys in cnMaestro's own export but this app doesn't parse them
// from `show config`, so they're left out rather than guessed.
type NetworkSrc struct {
	IPRoute           any                   `json:"ip_route"`
	LANInterfaces     []profileLANInterface `json:"lan_interfaces"`
	DHCPAuthoritative bool                  `json:"dhcp_authoritative"`
	Ports             []PortVLAN            `json:"-"`
}

func (n NetworkSrc) MarshalJSON() ([]byte, error) {
	base := map[string]any{
		"ip_route":           n.IPRoute,
		"lan_interfaces":     n.LANInterfaces,
		"dhcp_authoritative": n.DHCPAuthoritative,
	}
	for _, p := range n.Ports {
		if p.Type == "wan" {
			continue // WAN ports are covered by wan_interfaces, not these dynamic keys — confirmed absent from a real export.
		}
		m := profileEthRE.FindStringSubmatch(p.Interface)
		if m == nil {
			continue
		}
		prefix := "interface_eth" + m[1]
		base[prefix+"_desc"] = nil
		base[prefix+"_mode"] = p.Mode
		base[prefix+"_type"] = p.Type
		switch p.Mode {
		case "access":
			if v, err := strconv.Atoi(p.AccessVLAN); err == nil {
				base[prefix+"_access_vlan"] = v
			}
		case "trunk":
			if v, err := strconv.Atoi(p.NativeVLAN); err == nil {
				base[prefix+"_native_vlan"] = v
			}
			if p.AllowedVLANs != "" {
				base[prefix+"_allowed_vlan"] = p.AllowedVLANs
			}
		}
	}
	return json.Marshal(base)
}

type profileFilterEntry struct {
	Desc       *string       `json:"desc"`
	Name       string        `json:"name"`
	FilterRule DPIFilterRule `json:"filter_rule"`
}

type profileDeviceAccess struct {
	IPGroup         any `json:"ip_group"`
	AllowedServices any `json:"allowed_services"`
}

type FirewallSrc struct {
	NATOneOne                any                  `json:"nat_one_one"`
	NATOneMany               any                  `json:"nat_one_many"`
	DeviceAccess             profileDeviceAccess  `json:"device_access"`
	FilterConfig             []profileFilterEntry `json:"filter_config"`
	PortForwardRule          any                  `json:"port_forward_rule"`
	GeoIPInboundMode         any                  `json:"geoip_inbound_mode"`
	GeoIPOutboundMode        any                  `json:"geoip_outbound_mode"`
	DOSProtectionIPSpoof     bool                 `json:"dos_protection_ip_spoof"`
	DOSProtectionICMPFrag    bool                 `json:"dos_protection_icmp_frag"`
	GeoIPInboundAllowList    any                  `json:"geoip_inbound_allow_list"`
	GeoIPOutboundAllowList   any                  `json:"geoip_outbound_allow_list"`
	DOSProtectionIPSpoofLog  bool                 `json:"dos_protection_ip_spoof_log"`
	DOSProtectionSmurfAttack bool                 `json:"dos_protection_smurf_attack"`
}

// BuildGroupProfile assembles a cnMaestro-compatible NSE Group profile
// from already-fetched device state. cfgRaw is a fresh `show config`
// capture (needed for HA and the physical-port dynamic keys, neither of
// which cloud-json-config carries); cloud and groups come from
// FetchCloudConfig / ParseGroupsConfig respectively.
func BuildGroupProfile(cloud CloudConfig, groups GroupsConfig, lan LANConfig, cfgRaw string) GroupProfile {
	nameServers := make([]NameServerHost, len(cloud.NameServer))
	copy(nameServers, cloud.NameServer)

	radiusClients := make([]profileRADIUSClient, 0, len(cloud.RADIUSClientList))
	for i, c := range cloud.RADIUSClientList {
		radiusClients = append(radiusClients, profileRADIUSClient{ID: i + 1, Name: c.Name, Address: c.Address, Netmask: c.Netmask})
	}

	lanInterfaces := make([]profileLANInterface, 0, len(cloud.LANInterfaces))
	for _, v := range cloud.LANInterfaces {
		dhcpMode := "none"
		if v.DHCPPoolConfig.Enable {
			dhcpMode = "dhcp_pool"
		}
		lanInterfaces = append(lanInterfaces, profileLANInterface{
			DHCP: dhcpMode, Name: v.Name, IPAddr: v.IPAddr, IPMode: v.IPMode, VLANID: v.VLANID,
			PortScan: v.PortScan, SubnetMask: v.SubnetMask, ManagementAccess: v.ManagementAccess,
			DeviceIdentity: cloud.FeatureLicense["device_fingerprint"],
			RateLimitRules: v.RateLimitRules,
			DHCPPoolConfig: profileDHCPPoolConfig{
				Enable: v.DHCPPoolConfig.Enable, StartAddress: v.DHCPPoolConfig.StartAddress,
				EndAddress: v.DHCPPoolConfig.EndAddress, PrimaryDNSServer: v.DHCPPoolConfig.PrimaryDNS,
				LeaseTimeDay: v.DHCPPoolConfig.LeaseTimeDay, LeaseTimeHour: v.DHCPPoolConfig.LeaseTimeHour,
				LeaseTimeMinute: v.DHCPPoolConfig.LeaseTimeMinute,
				BindList:        dhcpBindsForPool(v.DHCPPoolConfig.StartAddress, lan),
				DHCPOptions:     []profileDHCPOption{},
			},
		})
	}

	filterConfig := make([]profileFilterEntry, 0, len(cloud.FilterConfig))
	for _, f := range cloud.FilterConfig {
		filterConfig = append(filterConfig, profileFilterEntry{Name: f.Name, FilterRule: f.FilterRule})
	}

	return GroupProfile{
		Mode:     []string{"security-gateway"},
		Types:    []string{},
		Adv:      "",
		AutoSync: false, // exported snapshots default to not-auto-syncing; the user decides whether to enable it on import
		Src: GroupProfileSrc{
			HA:     HASrc{HighAvailability: ParseHighAvailabilityStatus(cfgRaw)},
			Basic:  BasicSrc{},
			Hidden: HiddenSrc{SystemName: cloud.SystemName},
			Management: ManagementSrc{
				TZName: cloud.TZName, NTPServer: cloud.NTPServer, SyslogServer: cloud.SyslogServer,
			},
			ThreatProtection: ThreatProtectionSrc{
				IPS: cloud.IPS, IPSMode: cloud.IPSMode, IPSRuleSet: cloud.IPSRuleSet, IPSRuleType: cloud.IPSRuleType,
				IPSAutoUpdate: cloud.IPSAutoUpdate, IPSUpdateInterval: cloud.IPSUpdateInterval,
				SnortRuleCategory: cloud.SnortRuleCategory,
			},
			DNS: DNSSrc{
				DNSServer: cloud.DNSServer, NameServer: nameServers, DNSOverride: cloud.DNSOverride,
				LearnDNSServersFromDHCP: cloud.LearnDNSFromDHCP, LoggingSyslogDNSMasq: cloud.LoggingSyslogDNSMasq,
				DNSFilters: dnsFiltersSrc{Configuration: dnsFilterConfiguration{FilterMode: dnsFilterMode(cfgRaw)}},
			},
			VPN: VPNSrc{
				Tailscale: profileTailscale{
					Enable: cloud.Tailscale.Enable, AcceptRoutes: cloud.Tailscale.AcceptRoutes,
					AdvertiseRoutes: cloud.Tailscale.AdvertiseRoutes,
				},
				SiteToSite: cloud.SiteToSite, VPNServerInterface: cloud.VPNServerIface,
				RADIUSClientList: radiusClients,
			},
			WAN:    WANSrc{WANInterfaces: cloud.WANInterfaces},
			Groups: GroupsSrc{},
			Network: NetworkSrc{
				LANInterfaces: lanInterfaces, DHCPAuthoritative: cloud.DHCPAuthoritative, Ports: lan.Ports,
			},
			Firewall: FirewallSrc{
				FilterConfig: filterConfig, DOSProtectionIPSpoof: cloud.DOSProtectionSpoof,
				DOSProtectionICMPFrag: cloud.DOSProtectionFrag, DOSProtectionIPSpoofLog: cloud.DOSProtectionLog,
				DOSProtectionSmurfAttack: cloud.DOSProtectionSmurf,
			},
		},
	}
}

// dhcpBindsForPool finds the "ip dhcp pool N" belonging to a VLAN by
// matching its cloud-json-config start address against each parsed
// pool's address-range — the same start-address matching
// poolNumberForVLAN uses, since pool numbers are independent bookkeeping
// unrelated to VLAN ID (confirmed: VLAN 30's pool is "ip dhcp pool 2",
// not "pool 30"). NOTE: the underlying MACBinding parser itself uses
// unconfirmed candidate CLI keywords (see parsers.go), so until that's
// corrected against a live capture this will typically return an empty
// list even on a device with real bindings configured.
func dhcpBindsForPool(startAddress string, lan LANConfig) []profileDHCPBind {
	if startAddress == "" {
		return []profileDHCPBind{}
	}
	var pool *DHCPPoolSettings
	for i := range lan.DHCPPools {
		if strings.HasPrefix(lan.DHCPPools[i].AddressRange, startAddress+" ") {
			pool = &lan.DHCPPools[i]
			break
		}
	}
	if pool == nil {
		return []profileDHCPBind{}
	}
	out := make([]profileDHCPBind, 0, len(pool.Bindings))
	for _, b := range pool.Bindings {
		out = append(out, profileDHCPBind{IP: b.IP, MAC: b.MAC, Desc: b.Description})
	}
	return out
}
