package nse

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CloudConfig is the structured device configuration returned by
// `service show cloud-json-config`. Field names mirror the device's own
// JSON keys, which (not coincidentally) match cnMaestro's NSE Group export
// schema almost exactly — this command appears to be the same source
// cnMaestro itself reads from.
//
// Only the fields needed so far are modeled; unmodeled keys are simply
// dropped on read and never round-tripped, which is intentional: this type
// is the read/display model, not a lossless mirror. `service show ...`
// commands can carry secrets in cleartext on this firmware (confirmed for
// `service show config`), so no secret-shaped field (passwords, keys,
// oinkcodes, shared secrets) is modeled here — it is never exposed to the
// frontend because it was never unmarshaled in the first place.
type CloudConfig struct {
	// Source records which device command this was built from —
	// CloudSourceJSON or CloudSourceShowConfig. Set by FetchCloudConfig,
	// never unmarshaled from the device, and surfaced to the frontend so a
	// section that loses fields in fallback mode can say so instead of
	// rendering a derived zero value as if it were fact.
	Source string `json:"-"`

	SystemName        string          `json:"system_name"`
	DHCPAuthoritative bool            `json:"dhcp_authoritative"`
	WANInterfaces     []WANInterface  `json:"wan_interfaces"`
	LANInterfaces     []LANInterface  `json:"lan_interfaces"`
	FeatureLicense    map[string]bool `json:"feature_license"`

	// Management (safe subset only — see config_management.go for what's
	// deliberately excluded, e.g. admin password and SSH/HTTPS toggles).
	// CambiumRemote is whether the device is linked to cnMaestro, from the
	// "management cambium-remote" leaf. Tagged json:"-" because it is read
	// from `show config` rather than the cloud snapshot — a device being
	// delinked is exactly the moment that snapshot stops being updated.
	CambiumRemote bool `json:"-"`

	TZName        string       `json:"tz_name"`
	NTPServer     []NTPServer  `json:"ntp_server"`
	SyslogServer  []SyslogHost `json:"syslog_server"`
	LoggingSyslog string       `json:"logging_syslog_sev"`

	// Threat Protection (IPS).
	IPS               bool           `json:"ips"`
	IPSMode           string         `json:"ips_mode"`
	IPSRuleSet        string         `json:"ips_rule_set"`
	IPSRuleType       string         `json:"ips_rule_type"`
	IPSAutoUpdate     bool           `json:"ips_auto_update"`
	IPSUpdateInterval string         `json:"ips_update_interval"`
	SnortRuleCategory []SnortRuleCat `json:"snort_vrt_rule_category"`

	// DNS.
	DNSServer            string           `json:"dns_server"` // "enable" | "disable"
	DNSOverride          bool             `json:"dns_override"`
	LearnDNSFromDHCP     bool             `json:"learn_dns_servers_from_dhcp"`
	LoggingSyslogDNSMasq bool             `json:"logging_syslog_dnsmasq"`
	NameServer           []NameServerHost `json:"name_server"`

	// Firewall.
	FilterConfig       []FilterEntry `json:"filter_config"`
	DOSProtectionSpoof bool          `json:"dos_protection_ip_spoof"`
	DOSProtectionSmurf bool          `json:"dos_protection_smurf_attack"`
	DOSProtectionFrag  bool          `json:"dos_protection_icmp_frag"`
	DOSProtectionLog   bool          `json:"dos_protection_ip_spoof_log"`

	// VPN.
	Tailscale        CloudTailscale `json:"tailscale"`
	SiteToSite       bool           `json:"site_to_site"`
	L2TPClientVPN    bool           `json:"l2tp_client_vpn"`
	VPNServerMFA     bool           `json:"vpn_server_mfa"`
	VPNServerIface   string         `json:"vpn_server_interface"`
	RADIUSClientList []RADIUSClient `json:"radius_client_list"`
}

type NTPServer struct {
	Address string `json:"server_address"`
}

type NameServerHost struct {
	IP string `json:"server_ip"`
}

type SnortRuleCat struct {
	Category string `json:"category"`
}

type SyslogHost struct {
	IP   string `json:"server_ip"`
	Port string `json:"server_port"`
}

// DPIFilterRule is the nested rule object inside cloud-json-config's
// filter_config entries — distinct from parsers.go's FilterRule, which
// models the flatter `show config filter` text-command output.
type DPIFilterRule struct {
	ID       int    `json:"id"`
	Type     string `json:"type"`
	Action   string `json:"action"`
	Proto    string `json:"proto"`
	Src      string `json:"src"`
	SrcMask  string `json:"src_mask"`
	SPort    string `json:"sport"`
	Dest     string `json:"dest"`
	DestMask string `json:"dest_mask"`
	DPort    string `json:"dport"`
}

type FilterEntry struct {
	Name       string        `json:"name"`
	FilterRule DPIFilterRule `json:"filter_rule"`
}

// CloudTailscale is cloud-json-config's tailscale object — distinct from
// parsers.go's TailscaleConfig, which models `show tailscale status`
// runtime output.
type CloudTailscale struct {
	Enable          bool   `json:"enable"`
	AcceptRoutes    bool   `json:"accept_routes"`
	AdvertiseRoutes string `json:"advertise_routes"`
}

type RADIUSClient struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Netmask string `json:"netmask"`
}

type BandwidthConfig struct {
	UplinkBandwidth   string `json:"uplink_bandwidth"`
	DownlinkBandwidth string `json:"downlink_bandwidth"`
}

type LoadBalanceConfig struct {
	Mode                      string   `json:"lb_mode"`
	MonitorHosts              []string `json:"lb_monitor-hosts"`
	NumHostsFailInterfaceDown string   `json:"lb_num-hosts-fail-interface-down"`
	PingFailureDetectTime     string   `json:"lb_ping-failure-detect-time"`
	PingInterval              string   `json:"lb_ping-interval"`
	PingTimeout               string   `json:"lb_ping-timeout"`
	TrafficSharePercentage    string   `json:"lb_traffic-share-percentage"`
	// BackupLinkPriority only appears when lb_mode is "backup". The key
	// name is confirmed from a real cnMaestro NSE Group export file
	// (cloud-json-config has matched that schema field-for-field
	// everywhere else it's been checked this session), but NOT
	// independently re-confirmed against this device's own
	// cloud-json-config output, since neither WAN was in backup mode when
	// this was added — this device's own live capture was checked and
	// simply has no backup-mode WAN to confirm the key against.
	BackupLinkPriority string `json:"lb_backup-link-priority,omitempty"`
}

// DynDNSConfig deliberately does not model the "password" key even though
// it's a real field cnMaestro's export includes — same no-secret-fields
// policy as the rest of this file. Username/DNSHostname are not secrets
// and are safe to carry through a profile export. Same confirmation
// caveat as BackupLinkPriority above: key names are from a real
// cnMaestro export, not independently re-confirmed live (this device's
// dyndns is disabled on both WANs, so neither field is ever populated
// here to check against).
type DynDNSConfig struct {
	Mode        string `json:"dyndns_mode"`
	Provider    string `json:"provider"`
	ServerName  string `json:"server_name"`
	Username    string `json:"username,omitempty"`
	DNSHostname string `json:"dnshostname,omitempty"`
}

// WANInterface is one entry of cloud-json-config's wan_interfaces array,
// e.g. wan1/wan2. LANIntf is the underlying physical port ("eth1").
type WANInterface struct {
	Name                           string            `json:"name"`
	LANIntf                        string            `json:"lan_intf"`
	IPMode                         string            `json:"ip_mode"` // "dynamic" | "static"
	VLAN                           string            `json:"vlan"`
	Stateful                       bool              `json:"stateful"`
	SourceNAT                      string            `json:"source_nat"` // "enable" | "disable"
	SpareIPMode                    string            `json:"spare_ip_mode"`
	Speedtest                      bool              `json:"speedtest"`
	TrafficShaping                 string            `json:"traffic_shaping"`
	FailoverPolicyState            bool              `json:"failover_policy_state"`
	StarlinkEnable                 bool              `json:"starlink_enable"`
	StarlinkDishIP                 string            `json:"starlink_dish_ip"`
	StarlinkDishMode               string            `json:"starlink_dish_mode"`
	StarlinkDishPort               string            `json:"starlink_dish_port"`
	StarlinkDishGRPCReflectionIP   string            `json:"starlink_dish_grpc_reflection_ip"`
	StarlinkDishGRPCReflectionPort string            `json:"starlink_dish_grpc_reflection_port"`
	BandwidthConfig                BandwidthConfig   `json:"bandwidth_config"`
	LoadBalanceConfig              LoadBalanceConfig `json:"load_balance_config"`
	DynDNSConfig                   DynDNSConfig      `json:"dyndns_config"`
}

// PortNumber returns the eth port number this WAN rides on (1 for "eth1"),
// which is also the confirmed `default-gateway <gw> <N>` index for this
// interface. Returns 0 if LANIntf isn't in the expected "ethN" form.
func (w WANInterface) PortNumber() int {
	n := strings.TrimPrefix(w.LANIntf, "eth")
	var out int
	if _, err := fmt.Sscanf(n, "%d", &out); err != nil {
		return 0
	}
	return out
}

// DHCPBind is one entry of dhcp_pool_bind_list. This is the only place a
// reservation's human-readable label exists on the device — `show config`
// emits just "bind <MAC> <IP>", and no CLI verb reads or writes "desc".
type DHCPBind struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
	Desc string `json:"desc"`
}

type DHCPPoolConfig struct {
	Enable          bool   `json:"dhcp_pool_enable"`
	StartAddress    string `json:"dhcp_pool_start_address"`
	EndAddress      string `json:"dhcp_pool_end_address"`
	PrimaryDNS      string `json:"dhcp_pool_primary_dns_server"`
	SecondaryDNS    string `json:"dhcp_pool_secondary_dns_server"`
	LeaseTimeDay    int    `json:"dhcp_pool_lease_time_day"`
	LeaseTimeHour   int    `json:"dhcp_pool_lease_time_hour"`
	LeaseTimeMinute int    `json:"dhcp_pool_lease_time_minute"`

	// BindList lags `show config`: a reservation written over the CLI
	// shows up in `show config` immediately but was still absent here on
	// the next read (observed live). Treat `show config` as authoritative
	// for which reservations exist, and this only as the source of Desc.
	BindList []DHCPBind `json:"dhcp_pool_bind_list"`

	// Options are the pool's custom DHCP options, read from `show config`
	// (see fallbackDHCPPool). cloud-json-config carries a dhcp_options
	// array of its own, but its field names have never been observed
	// populated, so it is not unmarshaled here — these come from the CLI.
	Options []DHCPPoolOption `json:"dhcp_options"`
}

// DHCPPoolOption is one custom option as the frontend sees it.
type DHCPPoolOption struct {
	Code  int    `json:"code"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type RateLimitRules struct {
	RateLimit string `json:"rate_limit"`
}

// LANInterface is one entry of cloud-json-config's lan_interfaces array —
// really a VLAN, despite the name (matches the device's own key). PortScan
// and (by convention elsewhere in this file) device-fingerprint gate
// behind the `port-scan`/`device-fingerprint` feature-license flags.
type LANInterface struct {
	Name             string         `json:"name"`
	VLANID           int            `json:"vlan_id"`
	IPMode           string         `json:"ip_mode"`
	IPAddr           string         `json:"ip_addr"`
	SubnetMask       string         `json:"subnet_mask"`
	ManagementAccess string         `json:"management_access"` // "enable" | "disable"
	PortScan         bool           `json:"port_scan"`
	DHCPPoolConfig   DHCPPoolConfig `json:"dhcp_pool_config"`
	RateLimitRules   RateLimitRules `json:"rate_limit_rules"`
}

// extractJSONObject pulls the outermost {...} object out of raw SSH
// output, tolerant of command echo, trailing prompt, and CRLF line
// endings — more robust than stripCLI's line-based approach for a command
// whose payload is a single JSON blob rather than CLI-formatted text.
func extractJSONObject(raw string) string {
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end < start {
		return ""
	}
	return raw[start : end+1]
}

const cloudJSONCommand = "service show cloud-json-config"

// Values for CloudConfig.Source.
const (
	CloudSourceShowConfig = "show-config"
	// CloudSourceEnriched means `show config` supplied the configuration
	// and cloud-json-config filled in the few cnMaestro-side labels the
	// CLI has no words for.
	CloudSourceEnriched = "show-config+cloud-json"
)

// configTTL is how long a freshly read configuration is reused.
// Deliberately short — just long enough to collapse one page load's burst
// of FetchCloudConfig calls into a single `show config` (see
// Client.cachedDerivedConfig). Every write clears it (see RunSequence).
const configTTL = 3 * time.Second

// FetchCloudConfig returns the device's configuration, read from
// `show config`.
//
// It used to prefer `service show cloud-json-config`, whose JSON maps
// field-for-field onto cnMaestro's Group export schema, and fall back to
// `show config` only where that command was unavailable. That was
// backwards. Measured live on an NSE4000 running 2.4-r1: after a
// load-balance monitor-host change, `show config` showed the new list
// immediately while cloud-json-config went on reporting the old one for
// about seven minutes — through an explicit `save` that returned
// "[Config Save OK]" — before catching up. The JSON is a periodically
// regenerated cnMaestro-facing snapshot, not the running config.
//
// Minutes of lag is fatal for a read-back. SafeApplier holds a
// lockout-risk change provisional for sixty seconds, so a UI reading that
// snapshot cannot show such a change as applied inside the window it has
// to be confirmed in: the operator sees the old value, has no reason to
// press Confirm, and the change is genuinely rolled back. A successful
// edit that reverts itself is far worse than a slow one. On a unit that
// is never cloud-managed the snapshot may never populate at all.
//
// cloud-json-config is still consulted, but only to fill in fields that no
// CLI command can express and that no local edit can change — VLAN labels
// and rate-limit rules, plus the display-only WAN fields the profile
// export carries. enrichFromCloudJSON is the whitelist, and nothing the
// CLI can write may ever be added to it.
func FetchCloudConfig(c *Client, timeout time.Duration) (CloudConfig, error) {
	if cfg, ok := c.cachedDerivedConfig(configTTL); ok {
		return cfg, nil
	}
	showTimeout := timeout
	if showTimeout < 25*time.Second {
		showTimeout = 25 * time.Second
	}
	raw, err := c.Run("show config", showTimeout)
	if err != nil {
		return CloudConfig{}, fmt.Errorf("reading `show config`: %w", err)
	}
	cfg := CloudConfigFromShowConfig(raw)
	if len(cfg.LANInterfaces) == 0 && len(cfg.WANInterfaces) == 0 && cfg.SystemName == "" {
		return CloudConfig{}, fmt.Errorf("`show config` returned nothing recognizable")
	}
	if cloud, ok := fetchCloudJSON(c, timeout); ok {
		enrichFromCloudJSON(&cfg, cloud)
		cfg.Source = CloudSourceEnriched
	}
	c.storeDerivedConfig(cfg)
	return cfg, nil
}

// fetchCloudJSON reads cloud-json-config, reporting whether it produced
// anything usable. Every failure is non-fatal: the configuration has
// already been read by this point, and all this can add is labels.
func fetchCloudJSON(c *Client, timeout time.Duration) (CloudConfig, bool) {
	if c.CloudJSONUnsupported() {
		return CloudConfig{}, false
	}
	raw, err := c.Run(cloudJSONCommand, timeout)
	if err != nil {
		return CloudConfig{}, false
	}
	if body := extractJSONObject(raw); body != "" {
		var cloud CloudConfig
		if err := json.Unmarshal([]byte(body), &cloud); err != nil {
			return CloudConfig{}, false
		}
		c.noteCloudJSONHit()
		return cloud, true
	}
	rejected := classifyLine(cloudJSONCommand, raw)
	c.noteCloudJSONMiss(!rejected.OK)
	return CloudConfig{}, false
}

// enrichFromCloudJSON copies across the only fields worth taking from a
// snapshot that may be arbitrarily out of date: ones the CLI cannot
// express, so no local change can ever make the snapshot disagree with the
// device.
//
// Every field here must satisfy that test. A VLAN's label and rate-limit
// rule are cnMaestro-side metadata with no `show config` leaf. The WAN
// fields are display-only values the profile export carries and this app
// never writes. Adding anything the CLI can set would reintroduce exactly
// the bug this function exists alongside — a stale read overwriting a
// change that actually applied.
//
// Existing values always win: `show config` is the authority, and a blank
// is only filled, never overwritten.
func enrichFromCloudJSON(cfg *CloudConfig, cloud CloudConfig) {
	byVLAN := make(map[int]LANInterface, len(cloud.LANInterfaces))
	for _, v := range cloud.LANInterfaces {
		byVLAN[v.VLANID] = v
	}
	for i := range cfg.LANInterfaces {
		src, ok := byVLAN[cfg.LANInterfaces[i].VLANID]
		if !ok {
			continue
		}
		if cfg.LANInterfaces[i].Name == "" {
			cfg.LANInterfaces[i].Name = src.Name
		}
		if cfg.LANInterfaces[i].RateLimitRules.RateLimit == "" {
			cfg.LANInterfaces[i].RateLimitRules = src.RateLimitRules
		}
	}

	byPort := make(map[string]WANInterface, len(cloud.WANInterfaces))
	for _, w := range cloud.WANInterfaces {
		byPort[w.LANIntf] = w
	}
	for i := range cfg.WANInterfaces {
		src, ok := byPort[cfg.WANInterfaces[i].LANIntf]
		if !ok {
			continue
		}
		w := &cfg.WANInterfaces[i]
		if w.Name == "" {
			w.Name = src.Name
		}
		if w.SpareIPMode == "" {
			w.SpareIPMode = src.SpareIPMode
		}
		if w.TrafficShaping == "" {
			w.TrafficShaping = src.TrafficShaping
		}
		if w.VLAN == "" {
			w.VLAN = src.VLAN
		}
		if w.DynDNSConfig.Mode == "" {
			w.DynDNSConfig.Mode = src.DynDNSConfig.Mode
		}
	}
}

// cloudJSONDetail renders the device's own rejection of cloud-json-config
// for an error message, so the failure explains itself instead of leaving
// the operator to guess. The CLI's error lines carry no secrets (they are
// "%Error ..." / "Invalid arguments"), but the value is length-capped and
// single-lined regardless.
func cloudJSONDetail(r *LineResult) string {
	if r == nil {
		return ""
	}
	// A non-conventional reply ("could not open file") is not recorded as
	// an Error, but it is still exactly what the operator needs to see.
	detail := r.Error
	if detail == "" {
		detail = r.Output
	}
	if detail == "" {
		return ""
	}
	detail = strings.Join(strings.Fields(detail), " ")
	if len(detail) > 120 {
		detail = detail[:120]
	}
	return " (" + detail + ")"
}
