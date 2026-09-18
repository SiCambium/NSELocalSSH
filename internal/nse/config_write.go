package nse

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ApplyResult summarizes a RunSequence for callers that just want a
// pass/fail verdict plus the detail, without re-walking LineResult.
type ApplyResult struct {
	Lines []LineResult `json:"lines"`
	OK    bool         `json:"ok"`
	Error string       `json:"error,omitempty"`
}

// SaveConfigLine is the CLI command that persists the running config to
// the device's startup config. Without it, every change this app makes
// lives only in the running config and is lost on reboot.
//
// CONFIRMED live on an NSE4000 running 2.4-r1: the bare "save" command
// returns "[Config Save OK]" and leaves the running config byte-identical.
// That token is notable — this CLI has no general success token, so
// success is normally inferred from the absence of an error line (see
// classifyLine). Whether older firmware prints the same token is unknown,
// so it is treated as confirmation when present rather than required:
// a save is judged failed only by the usual error convention.
//
// NSE3000-CLI-REFERENCE.md previously listed "save"/"apply" as untested
// precisely to avoid persisting probe changes; "save" is now confirmed,
// "apply" remains untested and unused.
const SaveConfigLine = "save"

// ConfigSaveOKToken is the positive acknowledgement SaveConfigLine prints.
const ConfigSaveOKToken = "[Config Save OK]"

// ApplyLines sends a sequence of CLI lines via RunSequence, stopping at
// the first line whose output matches the CLI's error convention.
func (c *Client) ApplyLines(lines []string, timeout time.Duration) (ApplyResult, error) {
	results, err := c.RunSequence(lines, timeout, true)
	if err != nil {
		return ApplyResult{Lines: results, Error: err.Error()}, err
	}
	out := ApplyResult{Lines: results, OK: true}
	for _, r := range results {
		if !r.OK {
			out.OK = false
			out.Error = r.Error
			break
		}
	}
	return out, nil
}

// BuildInterfaceEthLines wraps leaf lines with the confirmed
// "interface eth N ... exit" submode envelope.
func BuildInterfaceEthLines(n int, leaves []string) []string {
	out := make([]string, 0, len(leaves)+2)
	out = append(out, fmt.Sprintf("interface eth %d", n))
	out = append(out, leaves...)
	out = append(out, "exit")
	return out
}

// BuildInterfaceVLANLines wraps leaf lines with the confirmed
// "interface vlan N ... exit" submode envelope.
func BuildInterfaceVLANLines(id int, leaves []string) []string {
	out := make([]string, 0, len(leaves)+2)
	out = append(out, fmt.Sprintf("interface vlan %d", id))
	out = append(out, leaves...)
	out = append(out, "exit")
	return out
}

// WANStaticIPLines returns the leaf lines to set a WAN port to a static
// IP. CONFIRMED against a real firmware-2.3-r6 `show config` export: the
// mask is dotted-decimal (not /prefix), and default-gateway takes a
// trailing numeric index that matches the physical port number (gwIndex
// 1 for eth1, 2 for eth2 — see WANInterface.PortNumber).
func WANStaticIPLines(ip, mask, gateway string, gwIndex int) []string {
	return []string{
		fmt.Sprintf("ip address %s %s", ip, mask),
		fmt.Sprintf("default-gateway %s %d", gateway, gwIndex),
	}
}

// WANDHCPLines returns the leaf line to set a WAN port back to DHCP.
// CONFIRMED: "ip address dhcp" is a real, currently-active line in this
// device's own `show config`. Whether a previously-set default-gateway
// also needs an explicit "no default-gateway <N>" to fully clear is
// unconfirmed — this is intentionally left out rather than guessed; if a
// stale gateway line turns out to linger after switching to DHCP, that's
// the next thing to verify live (through the safe-apply path, not blind).
func WANDHCPLines() []string {
	return []string{"ip address dhcp"}
}

// PPPoEConfig is the set of fields the CONFIRMED "pppoe-server ..." leaves
// (inside "interface eth N", after "type wan") accept. Confirmed from a
// real v1.9 `show config` capture with a WAN actually set to PPPoE; the
// device's own local web UI (a separate management surface from cnMaestro
// and SSH, same admin login) independently confirms the same field set
// plus documented bounds (MTU 500-1492, default 1492).
type PPPoEConfig struct {
	User        string
	Password    string
	MTU         int // 500-1492 per the local web UI; not independently confirmed from a CLI-side range check
	MSSClamp    bool
	ACName      string // optional
	ServiceName string // optional
}

// PPPoEEnableLines returns the leaves to enable PPPoE on a WAN eth
// interface. CONFIRMED order and syntax from a real capture: "pppoe-server
// enable" first, MTU and tcp-mss-clamp are independent toggles/values, and
// ac-name/service-name are optional (only emitted when set).
func PPPoEEnableLines(cfg PPPoEConfig) []string {
	lines := []string{
		"pppoe-server enable",
		"pppoe-server user " + cfg.User,
		"pppoe-server password " + cfg.Password,
		fmt.Sprintf("pppoe-server mtu %d", cfg.MTU),
	}
	if cfg.MSSClamp {
		lines = append(lines, "pppoe-server tcp-mss-clamp")
	}
	if cfg.ACName != "" {
		lines = append(lines, "pppoe-server ac-name "+cfg.ACName)
	}
	if cfg.ServiceName != "" {
		lines = append(lines, "pppoe-server service-name "+cfg.ServiceName)
	}
	return lines
}

// PPPoEDisableLine turns PPPoE off. CONFIRMED bare form is "pppoe-server
// enable"; the negated form follows this device's established no-prefix
// convention but is UNCONFIRMED.
func PPPoEDisableLine() string { return "no pppoe-server enable" }

// PPPoEModeLines returns the full leaf set to switch a WAN into PPPoE
// mode: PPPoEEnableLines plus WANDHCPLines(). The trailing "ip address
// dhcp" matches the one real confirmed PPPoE capture exactly (it ends
// with this same line) and resets away from a prior static IP/gateway the
// same way switching to plain DHCP mode already does — PPPoE negotiates
// its own address over the PPP link regardless of what was configured
// before.
func PPPoEModeLines(cfg PPPoEConfig) []string {
	return append(PPPoEEnableLines(cfg), WANDHCPLines()...)
}

// WANMonitorHostsLine returns the CONFIRMED full-line-replace form for
// load-balance monitor-hosts — re-sending this line replaces the entire
// list; there is no per-host add/remove verb.
func WANMonitorHostsLine(hosts []string) string {
	return "load-balance monitor-hosts " + strings.Join(hosts, ",")
}

// WANNumHostsFailLine sets how many monitor hosts must fail before the
// interface is declared down. CONFIRMED top-level leaf from a real
// capture ("load-balance num-hosts-fail-interface-down 1").
func WANNumHostsFailLine(n int) string {
	return fmt.Sprintf("load-balance num-hosts-fail-interface-down %d", n)
}

// WANPingFailureDetectTimeLine sets the interval (seconds) for declaring
// the link down. CONFIRMED leaf ("load-balance ping failure-detect-time
// 5"); the cnMaestro UI documents a 5-60 second range.
func WANPingFailureDetectTimeLine(seconds int) string {
	return fmt.Sprintf("load-balance ping failure-detect-time %d", seconds)
}

// WANPingIntervalLine sets how often monitor hosts are pinged. CONFIRMED
// leaf ("load-balance ping interval 2"); the cnMaestro UI documents a
// 2-10 second range.
func WANPingIntervalLine(seconds int) string {
	return fmt.Sprintf("load-balance ping interval %d", seconds)
}

// WANPingTimeoutLine sets the ping timeout. CONFIRMED leaf ("load-balance
// ping timeout 2"); the cnMaestro UI documents a 1-10 second range.
func WANPingTimeoutLine(seconds int) string {
	return fmt.Sprintf("load-balance ping timeout %d", seconds)
}

// WANTrafficSharePercentageLine sets the load-balance traffic share for a
// WAN in "shared" mode.
func WANTrafficSharePercentageLine(percent int) string {
	return fmt.Sprintf("load-balance traffic-share-percentage %d", percent)
}

// WANBandwidthLines sets the reported uplink/downlink capacity used for
// traffic shaping and dashboards.
func WANBandwidthLines(uplinkMbps, downlinkMbps int) []string {
	return []string{
		fmt.Sprintf("uplink-bandwidth Mbps %d", uplinkMbps),
		fmt.Sprintf("downlink-bandwidth Mbps %d", downlinkMbps),
	}
}

// VLANIPLine sets a VLAN interface's IP address and dotted-decimal mask.
func VLANIPLine(ip, mask string) string {
	return fmt.Sprintf("ip address %s %s", ip, mask)
}

// VLANManagementAccessLine enables or disables management access on a
// VLAN. This is classified RiskLockout by ClassifyRisk: disabling it on
// the VLAN carrying the current session cuts off local access.
func VLANManagementAccessLine(enable bool) string {
	if enable {
		return "management-access all"
	}
	return "no management-access"
}

// NetworkAddress computes the network address for an IP/dotted-decimal
// mask pair (e.g. 172.21.0.1 + 255.255.0.0 -> 172.21.0.0), needed for the
// DHCP pool "network" line, which is confirmed to want the network
// address rather than the VLAN's own gateway IP.
func NetworkAddress(ip, mask string) (string, error) {
	parsedIP := net.ParseIP(ip).To4()
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IPv4 address %q", ip)
	}
	parsedMask := net.ParseIP(mask).To4()
	if parsedMask == nil {
		return "", fmt.Errorf("invalid dotted-decimal mask %q", mask)
	}
	netIP := parsedIP.Mask(net.IPMask(parsedMask))
	return netIP.String(), nil
}

// VLANCreateLines returns the CONFIRMED lines to create a new VLAN
// interface: "interface vlan N" / "ip address ..." / optional
// "management-access all", closed with "exit" by BuildInterfaceVLANLines.
func VLANCreateLines(ip, mask string, managementAccess bool) []string {
	lines := []string{VLANIPLine(ip, mask)}
	if managementAccess {
		lines = append(lines, VLANManagementAccessLine(true))
	}
	return lines
}

// DHCPOption is one custom "dhcp-option <code> <value>" line.
type DHCPOption struct {
	Code  int
	Value string
}

// DHCPScope is the set of fields the CONFIRMED "ip dhcp pool N" block
// accepts (address-range, default-router, dns-server, optional
// domain-name, lease, network, custom options) — see
// NSE3000-CLI-REFERENCE.md and DHCPOptionLine.
type DHCPScope struct {
	StartIP     string
	EndIP       string
	Router      string
	DNS         string
	Domain      string // optional
	LeaseDays   int
	LeaseHours  int
	LeaseMins   int
	NetworkIP   string
	NetworkMask string
	Options     []DHCPOption // optional
}

// DHCPPoolLines builds the leaf lines for an "ip dhcp pool N" block. The
// same lines are used to create a new pool or overwrite an existing one —
// every other confirmed setter on this device works by resending the
// value, and no separate "edit" form has been observed.
func DHCPPoolLines(s DHCPScope) []string {
	lines := []string{
		fmt.Sprintf("address-range %s %s", s.StartIP, s.EndIP),
		fmt.Sprintf("default-router %s", s.Router),
		fmt.Sprintf("dns-server %s", s.DNS),
	}
	if s.Domain != "" {
		lines = append(lines, fmt.Sprintf("domain-name %s", s.Domain))
	}
	lines = append(lines,
		fmt.Sprintf("lease %d %d %d", s.LeaseDays, s.LeaseHours, s.LeaseMins),
		fmt.Sprintf("network %s %s", s.NetworkIP, s.NetworkMask),
	)
	for _, opt := range s.Options {
		lines = append(lines, DHCPOptionLine(opt.Code, opt.Value))
	}
	return lines
}

// DHCPOptionLine returns the CONFIRMED "dhcp-option <code> <value>" leaf
// line for a custom DHCP option inside an "ip dhcp pool N" block. String
// values are emitted unquoted, matching the real 2.3 export (e.g. option
// 15 "example.local" appears with no quotes) — do not add quoting here.
func DHCPOptionLine(code int, value string) string {
	return fmt.Sprintf("dhcp-option %d %s", code, value)
}

// BuildDHCPPoolLines wraps leaf lines with the confirmed
// "ip dhcp pool N ... exit" envelope. Note this is a top-level context —
// a sibling of "interface vlan N", not nested inside it — so it needs its
// own RunSequence/ApplyLines call, not to be concatenated onto a VLAN
// block.
func BuildDHCPPoolLines(pool int, leaves []string) []string {
	out := make([]string, 0, len(leaves)+2)
	out = append(out, fmt.Sprintf("ip dhcp pool %d", pool))
	out = append(out, leaves...)
	out = append(out, "exit")
	return out
}

// WANLoadBalanceModeLine sets a WAN's load-balance mode. CONFIRMED values:
// "shared" (splits traffic by traffic-share-percentage), "backup" (this
// link is only used when others fail), or "disabled". Whether "backup"
// also needs an explicit backup-link-priority line to behave correctly is
// unconfirmed — see the caller for how that's surfaced.
func WANLoadBalanceModeLine(mode string) string {
	return "load-balance mode " + mode
}

// WANBackupLinkPriorityLine sets the failover order among backup-mode
// links (0 = highest priority .. 10 = lowest, per NSE AI's 2.1 reference;
// unconfirmed for 2.3).
func WANBackupLinkPriorityLine(priority int) string {
	return fmt.Sprintf("load-balance backup-link-priority %d", priority)
}

// HostnameLine sets the device hostname. CONFIRMED top-level line from a
// real `show config` export ("hostname NSE-Caravan").
func HostnameLine(name string) string {
	return "hostname " + name
}

// TimezoneLine sets the display timezone (IANA name, e.g. "Europe/London").
// CONFIRMED top-level line from a real `show config` export.
func TimezoneLine(tz string) string {
	return "timezone " + tz
}

// NTPServerLine sets the NTP server. CONFIRMED top-level line
// ("ntp server time.google.com"); only one server has ever been observed
// configured on this device, and — matching every other confirmed setter
// here — resending the line is assumed to replace rather than add a
// second server, not add-only. Unconfirmed whether the device supports
// more than one simultaneously configured NTP server at all.
func NTPServerLine(address string) string {
	return "ntp server " + address
}

// SyslogHostLines sets the remote syslog destination and the minimum
// severity forwarded to it (0-7, syslog severity scale — 5 is "notice" in
// the real capture). CONFIRMED top-level lines ("logging host <ip> <port>",
// "logging syslog <sev>"); both are independent singleton settings, not a
// list, so resending replaces the previous value.
func SyslogHostLines(ip, port string, severity int) []string {
	return []string{
		fmt.Sprintf("logging host %s %s", ip, port),
		fmt.Sprintf("logging syslog %d", severity),
	}
}

// BuildDNSServerLines wraps leaf lines with the confirmed
// "dns-server ... exit" submode envelope.
func BuildDNSServerLines(leaves []string) []string {
	out := make([]string, 0, len(leaves)+2)
	out = append(out, "dns-server")
	out = append(out, leaves...)
	out = append(out, "exit")
	return out
}

// DNSFilterModeLine sets content-filter mode inside the dns-server submode.
// CONFIRMED value from a real capture: "filtering"; "learning" is the
// documented other option (cnMaestro's "Learning/Filtering" toggle, gated
// by the dns-filter license flag) but has not itself been observed live.
func DNSFilterModeLine(mode string) string {
	return "filter-mode " + mode
}

// DNSOverrideLine toggles DNS override inside the dns-server submode.
// CONFIRMED form via a real capture: "no dns-override" when off.
func DNSOverrideLine(enable bool) string {
	if enable {
		return "dns-override"
	}
	return "no dns-override"
}

// DNSServerLine toggles the device's own DNS resolver. CONFIRMED top-level
// line ("ip dns server"); the negated form follows this device's
// established no-prefix convention but has not itself been observed live.
func DNSServerLine(enable bool) string {
	if enable {
		return "ip dns server"
	}
	return "no ip dns server"
}

// NameServerLines diffs current against desired and returns the lines to
// remove entries no longer wanted and add new ones. "ip name-server <ip>"
// additions are CONFIRMED (real lines in a live capture); "no ip
// name-server <ip>" removal follows this device's established no-prefix
// convention but is UNCONFIRMED — this is a list of independent lines, not
// a singleton value, so (unlike hostname/timezone/etc.) resending the new
// set alone cannot drop a stale entry.
func NameServerLines(current, desired []string) []string {
	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	var lines []string
	for _, ip := range current {
		if !has(desired, ip) {
			lines = append(lines, "no ip name-server "+ip)
		}
	}
	for _, ip := range desired {
		if !has(current, ip) {
			lines = append(lines, "ip name-server "+ip)
		}
	}
	return lines
}

// DNSLocalHostLine builds a "local-host <domain> <ip>" leaf for a static
// DNS override inside the dns-server submode. The "local-host" command
// name is CONFIRMED (NSE AI CLI research citing the design doc's
// "dns_server_local_hosts" key); the <domain> <ip> argument order is
// BEST-GUESS, inferred from the sibling "safe-search <domain> <ip>" leaf's
// confirmed order — if it's backwards, the device rejects the whole
// change and nothing is applied.
func DNSLocalHostLine(domain, ip string) string {
	return "local-host " + domain + " " + ip
}

// DNSLocalHostDeleteLine follows this device's established no-prefix
// deletion convention; UNCONFIRMED for this specific leaf.
func DNSLocalHostDeleteLine(domain, ip string) string {
	return "no local-host " + domain + " " + ip
}

// DNSForwardZoneLine builds a "forward-zone <domain> <server-ip>" leaf for
// conditional DNS forwarding inside the dns-server submode. Same
// confirmation level as DNSLocalHostLine: command name confirmed, argument
// order best-guess.
func DNSForwardZoneLine(domain, server string) string {
	return "forward-zone " + domain + " " + server
}

// DNSForwardZoneDeleteLine follows this device's established no-prefix
// deletion convention; UNCONFIRMED for this specific leaf.
func DNSForwardZoneDeleteLine(domain, server string) string {
	return "no forward-zone " + domain + " " + server
}

// DNSOverrideBypassGroupLine references an IP Group that bypasses the
// "Block external DNS servers" override (dns-override). CONFIRMED syntax
// from NSE AI CLI research citing the design doc's
// "dns_server_override_bypass_list" key.
func DNSOverrideBypassGroupLine(groupName string) string {
	return "dns-override bypass-list ip-group " + groupName
}

// DNSOverrideBypassGroupDeleteLine follows this device's established
// no-prefix deletion convention; UNCONFIRMED for this specific leaf.
func DNSOverrideBypassGroupDeleteLine(groupName string) string {
	return "no dns-override bypass-list ip-group " + groupName
}

// BuildDNSFilterPolicyLines wraps leaf lines in the "dns-filter policy <N>
// ... exit" envelope, nested inside the dns-server submode. CONFIRMED
// structure from a live capture of this exact device's own "Ad_Blocking"
// policy (name/safe-search/deny-sources/deny-categories leaves, closed by
// "exit").
func BuildDNSFilterPolicyLines(id int, leaves []string) []string {
	out := []string{fmt.Sprintf("dns-filter policy %d", id)}
	out = append(out, leaves...)
	return append(out, "exit")
}

// DNSFilterPolicyDeleteLine follows this device's established no-prefix
// deletion convention (confirmed for "no group <N>" / "no ip group <N>" /
// "no application-group <N>"); UNCONFIRMED for this specific leaf.
func DNSFilterPolicyDeleteLine(id int) string {
	return fmt.Sprintf("no dns-filter policy %d", id)
}

func DNSFilterPolicyNameLine(name string) string { return "name " + name }

// DNSFilterPolicySafeSearchLine's "disabled" value is CONFIRMED from a
// live capture; "enabled" is BEST-GUESS, inferred as the natural opposite
// value for the same leaf (the device's own capture only ever showed it
// turned off).
func DNSFilterPolicySafeSearchLine(enable bool) string {
	if enable {
		return "safe-search enabled"
	}
	return "safe-search disabled"
}

// DNSFilterPolicyDenySourcesAllLine is CONFIRMED from a live capture
// ("deny-sources all").
func DNSFilterPolicyDenySourcesAllLine() string { return "deny-sources all" }

// DNSFilterPolicyDenySourcesGroupLine is BEST-GUESS, by analogy with
// filter rules' confirmed "allowed-sources user-group <name>" leaf —
// cnMaestro's DNS Filter Policies table offers "All" or "User Group" as
// the source scope, and only "all" has been observed live for this leaf.
func DNSFilterPolicyDenySourcesGroupLine(groupName string) string {
	return "deny-sources user-group " + groupName
}

// DNSFilterPolicyDenyCategoryLine is CONFIRMED from a live capture — a
// real policy on this device repeats one "deny-categories <category>"
// line per category (malware-sites, spyware-and-adware, spam-urls,
// bot-nets, keyloggers-and-monitoring, phishing-and-other-frauds are the
// six categories actually observed; other category names are accepted
// as free text since the device's full category vocabulary isn't
// enumerated anywhere in the CLI reference).
func DNSFilterPolicyDenyCategoryLine(category string) string {
	return "deny-categories " + category
}

// DNSFilterPolicyMaxIndex is an UNCONFIRMED, conservative ceiling for
// `dns-filter policy <N>` — no live capture or CLI reference entry gives
// an explicit limit for this specific list. Chosen to match the other
// confirmed 16-entry indexed lists (ip group, application-group) rather
// than risk testing higher. Unlike WAN/management edits, a rejected or
// out-of-range index here can't cause a device lockout (dns-filter
// policies don't touch the management/WAN path) — worst case is a CLI
// parser hiccup on the current SSH session, which the client already
// recovers from by reconnecting.
const DNSFilterPolicyMaxIndex = 16

// IPSEnableLine toggles intrusion-prevention as a whole. CONFIRMED bare
// top-level keyword; the negated form follows this device's established
// no-prefix convention but is UNCONFIRMED.
func IPSEnableLine(enable bool) string {
	if enable {
		return "intrusion-prevention"
	}
	return "no intrusion-prevention"
}

// IPSModeLine sets prevention vs. detection. CONFIRMED values from
// NSE3000-CLI-REFERENCE.md: "prevention" or "detection".
func IPSModeLine(mode string) string {
	return "intrusion-prevention mode " + mode
}

// IPSRuleSetLine sets the Snort rule tweak tier. CONFIRMED top-level line
// form and CONFIRMED value "balanced" (real live capture); "connectivity"
// and "security" are inferred 1:1 from cnMaestro's own 3-option "Rules"
// dropdown and NSE AI CLI research describing this as a direct
// pass-through value (not independently captured on the wire for those
// two, but low-risk to offer since a wrong value is simply rejected by
// the device rather than partially applied).
func IPSRuleSetLine(ruleSet string) string {
	return "intrusion-prevention rule-set " + ruleSet
}

// IPSRuleTypeLine sets the rule type. CONFIRMED top-level line form and
// CONFIRMED values (via NSE AI CLI research, matching cnMaestro's own
// rule-type dropdown 1:1): "snort-community", "snort-vrt", "et-open"
// (cnMaestro label "emerging-threats open"), "et-pro" (cnMaestro label
// "emerging-threats pro") — the cnMaestro labels are display text only,
// not the real CLI values. snort-vrt and et-pro require an oinkcode (see
// IPSOinkcodeLine); snort-community and et-open don't. Changing rule-type
// triggers a fresh rule download and likely discards the previously
// selected category list (unconfirmed exactly what happens to it, but
// confirmed that categories are scoped per rule-type).
func IPSRuleTypeLine(ruleType string) string {
	return "intrusion-prevention rule-type " + ruleType
}

// IPSOinkcodeLine sets the oinkcode used to authenticate Snort VRT /
// Emerging Threats Pro rule downloads. CONFIRMED CLI line
// ("intrusion-prevention oinkcode <code>") from NSE3000-CLI-REFERENCE.md
// and a real (redacted) capture. The code itself is a secret and is never
// read back or logged anywhere in this app — this is a write-only field,
// the same pattern already used for the PPPoE password.
func IPSOinkcodeLine(code string) string {
	return "intrusion-prevention oinkcode " + code
}

// IPSAutoUpdateLine toggles automatic rule updates. CONFIRMED bare
// top-level keyword; the negated form is UNCONFIRMED (follows the same
// no-prefix convention as IPSEnableLine).
func IPSAutoUpdateLine(enable bool) string {
	if enable {
		return "intrusion-prevention auto-update"
	}
	return "no intrusion-prevention auto-update"
}

// IPSAutoUpdateIntervalLine sets the auto-update interval (e.g.
// "12-hours", the only value seen in a live capture). The full set of
// accepted values is unconfirmed.
func IPSAutoUpdateIntervalLine(interval string) string {
	return "intrusion-prevention auto-update interval " + interval
}

// TailscaleEnableLine toggles Tailscale as a whole. CONFIRMED bare
// top-level keyword; the negated form follows this device's established
// no-prefix convention but is UNCONFIRMED.
func TailscaleEnableLine(enable bool) string {
	if enable {
		return "tailscale"
	}
	return "no tailscale"
}

// TailscaleAuthKeyLine sets the pre-authentication key this device uses to
// join a tailnet. CONFIRMED: "tailscale auth-key <key>" is a real,
// currently-active line in this device's own `show config`.
//
// The key is write-only everywhere it appears in this app, the same way
// the IPS oinkcode is: it is never read back, never returned in a GET, and
// redacted out of the ApplyOutcome that echoes the applied lines (see
// redactOutcome). cloud-json-config reports it as "*masked*", so there is
// nothing to read back even where that command works.
//
// There is deliberately no "clear the key" counterpart: "no tailscale
// auth-key" would follow this device's negation convention but is
// unconfirmed, and guessing at it buys little, since re-keying is done by
// setting a new key.
func TailscaleAuthKeyLine(key string) string {
	return "tailscale auth-key " + key
}

// TailscaleAcceptRoutesLine toggles accepting routes advertised by other
// tailnet peers. Both forms CONFIRMED live on an NSE4000 running 2.4-r1:
// applying each in turn added and then removed the "tailscale
// accept-routes" line in `show config`, leaving the device byte-identical
// to where it started.
func TailscaleAcceptRoutesLine(enable bool) string {
	if enable {
		return "tailscale accept-routes"
	}
	return "no tailscale accept-routes"
}

// TailscaleAdvertiseRoutesLine sets the full comma-separated CIDR list this
// device advertises to the tailnet. CONFIRMED full-line-replace form from a
// real capture ("tailscale advertise-routes 172.21.0.0/16,172.23.0.0/16").
func TailscaleAdvertiseRoutesLine(cidrs []string) string {
	return "tailscale advertise-routes " + strings.Join(cidrs, ",")
}

// SiteToSiteEnableLine toggles the site-to-site VPN context as a whole.
// This only covers the on/off switch — configuring an actual IPsec tunnel
// (remote address, PSK, subnets) is out of scope: those fields have no
// value confirmed from a live capture (this unit has none configured), and
// getting IPsec parameters wrong silently breaks connectivity to a remote
// site rather than erroring, which is a bad thing to guess at. The bare
// "site-to-site-vpn" keyword is CONFIRMED as the context-enter form; the
// negated form is UNCONFIRMED.
func SiteToSiteEnableLine(enable bool) string {
	if enable {
		return "site-to-site-vpn"
	}
	return "no site-to-site-vpn"
}

// RADIUSModeLine toggles the RADIUS server as a whole. CONFIRMED top-level
// line ("radius-server mode enable"); the disabled form's exact wording
// ("mode disable" vs "no radius-server mode") is UNCONFIRMED — "mode
// disable" is used here since it mirrors the confirmed enable form most
// directly.
func RADIUSModeLine(enable bool) string {
	if enable {
		return "radius-server mode enable"
	}
	return "radius-server mode disable"
}

// BuildRADIUSClientLines wraps leaf lines with the confirmed
// "radius-server client-list N ... " envelope. Unlike the other block
// types here, a real capture shows this block closed with "!" rather than
// "exit" — but "exit" is used regardless, since it's confirmed elsewhere on
// this firmware to always be accepted as a safe, explicit way to leave any
// submode (ToLines makes the same choice when serializing captured
// config).
func BuildRADIUSClientLines(id int, leaves []string) []string {
	out := make([]string, 0, len(leaves)+2)
	out = append(out, fmt.Sprintf("radius-server client-list %d", id))
	out = append(out, leaves...)
	out = append(out, "exit")
	return out
}

// RADIUSClientDeleteLine follows this device's established no-prefix
// deletion convention. BEST-GUESS (high confidence) per NSE AI CLI
// research: no live capture shows "no radius-server client-list <N>", but
// this exact pattern ("no <command> <index>") is confirmed for every
// other indexed list on this device (group, ip group, application-group).
func RADIUSClientDeleteLine(id int) string {
	return fmt.Sprintf("no radius-server client-list %d", id)
}

// RADIUSClientLines builds the leaf lines for one RADIUS client entry.
// CONFIRMED field names and format from a real capture (name, secret,
// address, prefix-length — a bare integer, not a dotted mask). Editing an
// existing client re-sends this same block at its existing index: the NSE
// CLI is confirmed idempotent (re-issuing a config command overwrites the
// previous leaf value, no separate edit mode) per NSE AI CLI research.
func RADIUSClientLines(name, secret, address string, prefixLength int) []string {
	return []string{
		"name " + name,
		"secret " + secret,
		"address " + address,
		fmt.Sprintf("prefix-length %d", prefixLength),
	}
}

// dosProtectionLines is shared by the four DoS-protection toggles below,
// all CONFIRMED bare top-level keywords from a real capture; the negated
// form follows this device's established no-prefix convention but is
// UNCONFIRMED for these specific keywords.
func dosProtectionLine(keyword string, enable bool) string {
	if enable {
		return "firewall dos-protection " + keyword
	}
	return "no firewall dos-protection " + keyword
}

// DOSProtectionIPSpoofLine toggles anti IP-spoofing protection.
func DOSProtectionIPSpoofLine(enable bool) string { return dosProtectionLine("ip-spoof", enable) }

// DOSProtectionIPSpoofLogLine toggles logging of spoofed-IP hits.
func DOSProtectionIPSpoofLogLine(enable bool) string {
	return dosProtectionLine("ip-spoof-log", enable)
}

// DOSProtectionSmurfLine toggles Smurf-attack protection.
func DOSProtectionSmurfLine(enable bool) string { return dosProtectionLine("smurf-attack", enable) }

// DOSProtectionICMPFragLine toggles ICMP-fragment protection.
func DOSProtectionICMPFragLine(enable bool) string { return dosProtectionLine("icmp-frag", enable) }

// BuildUserGroupLines wraps leaf lines with the confirmed "group N ...
// exit" envelope, and NameGroupDeleteLine returns the confirmed top-level
// deletion form. All three group types (user/IP/application) follow this
// exact same shape — confirmed live: materialize with a leaf, verify via
// `show config` diff, delete with the top-level "no ..." form, verify the
// diff reverts fully.
func BuildUserGroupLines(id int, leaves []string) []string {
	out := make([]string, 0, len(leaves)+2)
	out = append(out, fmt.Sprintf("group %d", id))
	out = append(out, leaves...)
	out = append(out, "exit")
	return out
}

// UserGroupNameLine sets a user group's name. CONFIRMED leaf.
func UserGroupNameLine(name string) string { return "name " + name }

// UserGroupSourceSubnetLine sets a user group's membership CIDR. CONFIRMED
// leaf and format (plain CIDR slash notation, e.g. "192.168.60.0/24").
func UserGroupSourceSubnetLine(cidr string) string { return "source-subnet " + cidr }

// UserGroupDeleteLine returns the confirmed top-level deletion form.
func UserGroupDeleteLine(id int) string { return fmt.Sprintf("no group %d", id) }

// UserGroupMaxIndex is the confirmed-safe ceiling for `group <N>` (user
// groups). The CLI reference tree documents 1-64; live-tested on a real
// 2.3-r6 unit that index 65 hard-fails the CLI parser exactly like `ip
// group 17` does (session drop, no clean "%Error" text) — same
// diff-and-cleanup discipline confirmed no config was left behind.
const UserGroupMaxIndex = 64

// BuildIPGroupLines wraps leaf lines with the confirmed "ip group N ...
// exit" envelope. Unlike group N / application-group N, entering "ip
// group N" alone (with no leaves at all) already materializes a change in
// `show config` — confirmed live.
func BuildIPGroupLines(id int, leaves []string) []string {
	out := make([]string, 0, len(leaves)+2)
	out = append(out, fmt.Sprintf("ip group %d", id))
	out = append(out, leaves...)
	out = append(out, "exit")
	return out
}

// IPGroupNameLine sets an IP group's name. CONFIRMED leaf.
func IPGroupNameLine(name string) string { return "name " + name }

// IPGroupAddressLine sets an IP group's address/range. CONFIRMED leaf and
// format (plain CIDR slash notation, e.g. "192.168.50.0/24" — the device's
// own help text also allows a single IP or an address range, but only the
// CIDR form has been tested live).
func IPGroupAddressLine(addr string) string { return "address " + addr }

// IPGroupDeleteLine returns the confirmed top-level deletion form.
func IPGroupDeleteLine(id int) string { return fmt.Sprintf("no ip group %d", id) }

// IPGroupMaxIndex is the conservative, confirmed-safe ceiling for `ip
// group <N>`. The v2.1 CLI tree documents 1-16; the v2.3 backend daemon
// actually reads slots up to 64, but live testing on a real 2.3-r6 unit
// showed index 17 hard-fails the CLI parser (session drop, no clean
// "%Error" text) rather than being gracefully rejected — so this app
// never offers higher than 16 even though the daemon could in principle
// store more.
const IPGroupMaxIndex = 16

// BuildAppGroupLines wraps leaf lines with the confirmed
// "application-group N ... exit" envelope.
func BuildAppGroupLines(id int, leaves []string) []string {
	out := make([]string, 0, len(leaves)+2)
	out = append(out, fmt.Sprintf("application-group %d", id))
	out = append(out, leaves...)
	out = append(out, "exit")
	return out
}

// AppGroupNameLine sets an application group's name. CONFIRMED leaf.
func AppGroupNameLine(name string) string { return "name " + name }

// AppGroupApplicationLine adds one application to the group. CONFIRMED
// leaf, validated server-side against a real DPI catalog (e.g.
// "instagram" is accepted); an unrecognized name is cleanly rejected with
// the device's normal "%Error processing cli command" line rather than
// silently accepted.
func AppGroupApplicationLine(name string) string { return "application " + name }

// AppGroupCategoryLine adds one DPI category to the group. CONFIRMED
// leaf, same server-side validation as AppGroupApplicationLine — the
// valid category token list itself is not enumerated anywhere confirmed,
// so a bad value here fails clean rather than corrupting anything.
func AppGroupCategoryLine(name string) string { return "category " + name }

// AppGroupDeleteLine returns the confirmed top-level deletion form.
func AppGroupDeleteLine(id int) string { return fmt.Sprintf("no application-group %d", id) }

// AppGroupMaxIndex is the confirmed-safe ceiling for `application-group
// <N>`. Live-tested on a real 2.3-r6 unit that index 17 hard-fails the CLI
// parser exactly like `ip group 17` and `group 65` do (session drop, no
// clean "%Error" text) — same diff-and-cleanup discipline confirmed no
// config was left behind.
const AppGroupMaxIndex = 16

// DeviceAccessPingLine toggles whether the device responds to ICMP pings
// arriving on a WAN interface. CONFIRMED CLI line from a real capture
// ("device-access allowed-service ping", alongside ssh/http/https); the
// negated form follows this device's established no-prefix convention but
// is UNCONFIRMED.
func DeviceAccessPingLine(enable bool) string {
	if enable {
		return "device-access allowed-service ping"
	}
	return "no device-access allowed-service ping"
}

// negateSwitchportLines returns the "no ..." lines needed to clear a
// port's existing switchport config before applying a different mode or
// role. Shared by WANEnableLines/WANPromoteLines (LAN -> WAN) and the
// LANPortAccessLines/LANPortTrunkLines builders below (access <-> trunk).
// Whether the device actually needs this before a role/mode change is
// UNCONFIRMED — the recommended safe, idempotent form (confirmed pattern
// via NSE AI CLI research, not yet runtime-proven on this device) is to
// explicitly negate whatever switchport config is present first, since a
// "no switchport ..." against config that's already absent is expected to
// be a harmless no-op either way.
func negateSwitchportLines(current PortVLAN) []string {
	var lines []string
	switch current.Mode {
	case "access":
		if current.AccessVLAN != "" {
			lines = append(lines, "no switchport access vlan "+current.AccessVLAN)
		}
		lines = append(lines, "no switchport mode access")
	case "trunk":
		if current.AllowedVLANs != "" {
			lines = append(lines, "no switchport trunk allowed vlan "+current.AllowedVLANs)
		}
		if current.NativeVLAN != "" {
			lines = append(lines, "no switchport trunk native vlan "+current.NativeVLAN)
		}
		lines = append(lines, "no switchport mode trunk")
	}
	return lines
}

// WANEnableLines returns the lines to turn a currently-non-WAN eth port
// into a WAN, bringing it up on DHCP by default (the safest starting
// state — a static IP can be applied as a separate follow-up change).
// current is the port's existing switchport config (zero value if the
// port has none).
func WANEnableLines(wanName string, current PortVLAN) []string {
	lines := negateSwitchportLines(current)
	return append(lines,
		"type wan",
		fmt.Sprintf("wan-name %s", wanName),
		"ip address dhcp",
	)
}

// WANPromoteLines is WANEnableLines' general form for the "change WAN
// port" swap: the same switchport-negation + "type wan"/"wan-name"
// envelope, but ending with the target IP mode's own leaves (dhcp,
// static, or PPPoE) instead of always defaulting to DHCP — so a static or
// PPPoE WAN can move to a different physical port without losing its
// mode.
func WANPromoteLines(wanName string, current PortVLAN, ipModeLeaves []string) []string {
	lines := negateSwitchportLines(current)
	lines = append(lines, "type wan", fmt.Sprintf("wan-name %s", wanName))
	return append(lines, ipModeLeaves...)
}

// WANRevertToLANLines returns the lines to convert a WAN eth port back to
// a plain LAN switchport, for the "move this WAN to a different physical
// port" swap workflow: the old port reverts to LAN (this function) while
// a different port is promoted via WANPromoteLines.
//
// Mirrors WANEnableLines' own accepted-risk pattern: PPPoE and
// load-balance mode are explicitly cleared with their CONFIRMED "no"
// forms first (harmless no-op if already absent), then "type lan" plus a
// plain access-mode switchport config is applied — matching every real
// LAN port capture seen on this device. Whether "type lan" alone also
// purges the WAN-only ip-address/gateway/wan-name/bandwidth leaves is
// UNCONFIRMED; this relies on the same safe-apply reachability check and
// auto-rollback as every other WAN change to catch it if not.
func WANRevertToLANLines(accessVLAN string) []string {
	return []string{
		PPPoEDisableLine(),
		WANLoadBalanceModeLine("disabled"),
		"type lan",
		"switchport mode access",
		"switchport access vlan " + accessVLAN,
		"no shutdown",
	}
}

// LANPortAccessLines sets a LAN port to access mode on the given VLAN,
// negating trunk config first if the port is currently a trunk. CONFIRMED
// syntax ("switchport mode access" / "switchport access vlan N") from
// this device's own `show config`.
func LANPortAccessLines(current PortVLAN, vlanID string) []string {
	lines := negateSwitchportLines(current)
	return append(lines, "switchport mode access", "switchport access vlan "+vlanID)
}

// LANPortTrunkLines sets a LAN port to trunk mode with the given native
// VLAN and comma-separated allowed-VLAN list, negating access config
// first if the port is currently in access mode. CONFIRMED syntax from
// this device's own `show config`.
func LANPortTrunkLines(current PortVLAN, nativeVLAN, allowedVLANs string) []string {
	lines := negateSwitchportLines(current)
	return append(lines,
		"switchport mode trunk",
		"switchport trunk native vlan "+nativeVLAN,
		"switchport trunk allowed vlan "+allowedVLANs,
	)
}

// LANPortShutdownLine toggles whether a LAN port is administratively up.
// CONFIRMED: every LAN port in this device's own `show config` carries
// "no shutdown" as its enabled state; the disabled form follows the same
// no-prefix convention used throughout this CLI.
func LANPortShutdownLine(enable bool) string {
	if enable {
		return "no shutdown"
	}
	return "shutdown"
}

// LANPortSpeedLine forces a LAN port's link speed. CONFIRMED leaf and
// enum from the CLI reference tree: "speed" takes exactly 10|100|auto —
// notably not 1000, unlike the separate advertise leaf below. Validate
// against LANPortSpeedValues before calling.
func LANPortSpeedLine(speed string) string {
	return "speed " + speed
}

// LANPortSpeedValues is the CONFIRMED enum for LANPortSpeedLine.
var LANPortSpeedValues = []string{"10", "100", "auto"}

// LANPortDuplexLine forces a LAN port's duplex mode. CONFIRMED leaf and
// enum from the CLI reference tree: "duplex" takes exactly full|half —
// there is no "auto" duplex value (unlike speed/advertise).
func LANPortDuplexLine(duplex string) string {
	return "duplex " + duplex
}

// LANPortDuplexValues is the CONFIRMED enum for LANPortDuplexLine.
var LANPortDuplexValues = []string{"full", "half"}

// LANPortAdvertiseLine sets what a LAN port advertises during
// auto-negotiation. CONFIRMED leaf and enum from the CLI reference tree:
// "advertise" takes 10|100|1000|auto — this is the one place gigabit is
// selectable; the forced "speed" leaf above does not offer 1000.
func LANPortAdvertiseLine(val string) string {
	return "advertise " + val
}

// LANPortAdvertiseValues is the CONFIRMED enum for LANPortAdvertiseLine.
var LANPortAdvertiseValues = []string{"10", "100", "1000", "auto"}

// --- Outbound filter rules (firewall) --------------------------------
//
// CONFIRMED live on this device (2026-08-31): both creating a rule and
// deleting one by precedence work exactly as below, and deleting a rule
// does NOT renumber the ones after it — precedence gaps persist. There is
// no confirmed way to reorder a rule in place or overwrite an
// already-occupied precedence slot, so every edit (add, delete, move up/
// down) is implemented the same way: delete every existing rule and
// recreate the full list in the new order at fresh consecutive precedence
// numbers starting at 1. This is built entirely from the two confirmed
// primitives below, so it never needs to guess at in-place renumbering or
// slot-overwrite behavior.

// FilterRuleLayer3Line builds a "layer3-filter ..." line from structured
// fields. CONFIRMED format and field order from a real live capture
// ("layer3-filter deny proto any SRC/MASK SPORT DST/MASK DPORT in").
// "deny" is the only action value ever captured; "allow" is untested but
// safe to offer since ReplaceFilterRulesLines is applied as one sequence
// through the safe-apply path — a rejected line fails the whole change
// cleanly rather than partially applying. src/dst are as described on
// FilterRuleContent.
func FilterRuleLayer3Line(action, protocol, src, srcPort, dst, dstPort string) string {
	return "layer3-filter " + FilterRuleContent(action, protocol, src, srcPort, dst, dstPort)
}

// FilterAddrSpec formats an IP/mask pair into the token FilterRuleContent
// expects for a plain address-based source or destination.
func FilterAddrSpec(addr, mask string) string {
	return addr + "/" + mask
}

// FilterRuleContent builds just the fields portion of a layer3-filter
// line, without the leading "layer3-filter " keyword — this is the form
// stored in FilterRule.Rule (see parsers.go's ParseConfigFilter) and
// reused verbatim by ReplaceFilterRulesLines when recreating a rule.
// src and dst are each either an "IP/MASK" pair (see FilterAddrSpec) or a
// bare group name: CONFIRMED via a real v2.3 capture that a previously
// created User Group or IP Group's name can be used directly in the
// address slot in place of an IP/mask pair, e.g. "layer3-filter deny
// proto any Enterprise-Users any Guest any in" where Enterprise-Users and
// Guest are group names, not IPs — the two forms occupy the exact same
// position and are otherwise indistinguishable to this line builder.
func FilterRuleContent(action, protocol, src, srcPort, dst, dstPort string) string {
	return fmt.Sprintf("%s proto %s %s %s %s %s in", action, protocol, src, srcPort, dst, dstPort)
}

// FilterRuleDeleteLine is the CONFIRMED (live-tested) line to remove one
// rule by precedence, issued inside "filter global-filter".
func FilterRuleDeleteLine(precedence int) string {
	return fmt.Sprintf("no filter precedence %d", precedence)
}

// BuildFilterRuleCreateLines returns the leaves for one rule inside
// "filter global-filter". CONFIRMED order/syntax from a real capture.
// unique_id always mirrors precedence — every real capture observed (the
// device's original 3 rules, plus 2 live-tested additions) has unique_id
// equal to precedence; there's no evidence they're ever meant to diverge.
// contentLine is the match leaf (e.g. "layer3-filter ..." or
// "application-group deny <name>"); extraLines are appended verbatim
// before "exit" (e.g. a preserved "allowed-sources user-group <name>").
func BuildFilterRuleCreateLines(precedence int, ruleName, contentLine string, extraLines ...string) []string {
	lines := []string{
		fmt.Sprintf("filter precedence %d", precedence),
		fmt.Sprintf("unique_id %d", precedence),
		"rule-name " + ruleName,
		contentLine,
	}
	lines = append(lines, extraLines...)
	return append(lines, "exit")
}

// FilterRuleApplicationGroupLine builds an "application-group <action>
// <name>" match leaf, referencing a previously-created Application
// Group. CONFIRMED syntax and "deny" action from a real v2.3 capture
// (`application-group deny instagram`); "allow" is untested but offered
// for the same reason "allow" is offered on layer3-filter — the whole
// change is one safe-apply sequence, so a rejected value fails cleanly.
func FilterRuleApplicationGroupLine(action, groupName string) string {
	return "application-group " + action + " " + groupName
}

// FilterRuleCategoryControlLine builds a "category-control <category>
// <action>" match leaf for DPI-category-based filtering. CONFIRMED
// syntax from a real v2.3 capture, but only the "deny-takeover" action
// value was actually observed there (and that capture's own context
// suggests deny-takeover may be a failover-policy-specific variant, not
// this table's plain block/allow). "deny"/"allow" are offered here as
// the natural fit for a plain outbound filter rule, by analogy with
// every other rule kind in this table — unconfirmed, but safe-apply
// protected the same way "allow" already is elsewhere in this file.
func FilterRuleCategoryControlLine(category, action string) string {
	return "category-control " + category + " " + action
}

// BuildFilterGlobalFilterLines wraps leaf lines in the confirmed
// "filter global-filter ... exit" envelope. Leaves "stateful" and
// "application-control" (separate top-level toggles inside this block)
// alone — this never touches them, so they persist unchanged.
func BuildFilterGlobalFilterLines(leaves []string) []string {
	out := append([]string{"filter global-filter"}, leaves...)
	return append(out, "exit")
}

// ReplaceFilterRulesLines returns the full sequence to delete every rule
// in current and recreate newOrder at fresh consecutive precedence
// numbers starting at 1, preserving each rule's name and raw
// layer3-filter line exactly. See the package-level note above for why
// every edit goes through a full delete-and-recreate rather than
// in-place renumbering.
func ReplaceFilterRulesLines(current []FilterRule, newOrder []FilterRule) []string {
	var leaves []string
	for _, r := range current {
		precedence, _ := strconv.Atoi(r.Precedence)
		leaves = append(leaves, FilterRuleDeleteLine(precedence))
	}
	for i, r := range newOrder {
		leaves = append(leaves, BuildFilterRuleCreateLines(i+1, r.Name, r.FullLine(), r.Extra...)...)
	}
	return BuildFilterGlobalFilterLines(leaves)
}

// --- GEO IP filtering --------------------------------------------------
//
// CONFIRMED via NSE AI CLI research (2026-08-31) from the CLI reference
// tree and design docs — not from a live capture, since this device has
// never had GEO IP filtering configured. direction is "inbound"
// (cnMaestro's "WAN to LAN Filters") or "outbound" ("LAN to WAN
// Filters"); mode is "allow" (cnMaestro "Allow Only (Deny by default)"),
// "block" ("Deny Only (Allow by default)"), or "none".

// GeoIPModeLine sets the GEO IP filtering mode for one direction.
func GeoIPModeLine(direction, mode string) string {
	return fmt.Sprintf("firewall geo-ip-restrictions %s mode %s", direction, mode)
}

// GeoIPCountriesLine sets the full country list for one direction in one
// line — CONFIRMED as a whole-value set (not additive), matching every
// other single-line list setting already confirmed elsewhere in this
// CLI (e.g. WAN monitor-hosts). Countries are ISO 3166-1 alpha-2 codes.
func GeoIPCountriesLine(direction string, countries []string) string {
	return fmt.Sprintf("firewall geo-ip-restrictions %s countries %s", direction, strings.Join(countries, ","))
}

// GeoIPExceptionAddLine adds one always-allowed IP range exception for
// one direction. CONFIRMED line form; repeatable — each call adds one
// more range rather than replacing the list.
func GeoIPExceptionAddLine(direction, startIP, endIP string) string {
	return fmt.Sprintf("firewall geo-ip-allowlist %s address-range start-address end-address %s %s", direction, startIP, endIP)
}

// GeoIPExceptionDeleteLine removes one exception by its exact start/end
// pair. UNCONFIRMED negation form (follows this CLI's established
// no-prefix convention for a fully self-contained, non-indexed leaf
// line); applied through the safe-apply path so a rejection fails
// cleanly rather than partially applying.
func GeoIPExceptionDeleteLine(direction, startIP, endIP string) string {
	return "no " + GeoIPExceptionAddLine(direction, startIP, endIP)
}
