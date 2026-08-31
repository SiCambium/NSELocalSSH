package nse

import (
	"fmt"
	"net"
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

// IPSRuleSetLine sets the Snort rule set (e.g. "balanced"). CONFIRMED
// top-level line form; the set of valid values beyond "balanced" is
// unconfirmed.
func IPSRuleSetLine(ruleSet string) string {
	return "intrusion-prevention rule-set " + ruleSet
}

// IPSRuleTypeLine sets the rule type (e.g. "snort-vrt"). CONFIRMED
// top-level line form.
func IPSRuleTypeLine(ruleType string) string {
	return "intrusion-prevention rule-type " + ruleType
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

// TailscaleAcceptRoutesLine toggles accepting routes advertised by other
// tailnet peers. CONFIRMED bare keyword; the negated form is UNCONFIRMED.
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

// RADIUSClientLines builds the leaf lines for one RADIUS client entry.
// CONFIRMED field names and format from a real capture (name, secret,
// address, prefix-length — a bare integer, not a dotted mask).
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
