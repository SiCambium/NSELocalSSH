package nse

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// CloudConfigFromShowConfig derives a CloudConfig from a raw `show config`
// capture, for devices where `service show cloud-json-config` is not
// available (older/other firmware, a model that doesn't ship the command,
// or an account without service-command rights). `show config` is the one
// read command this project treats as always present — it is the source
// the CLI reference itself was recovered from.
//
// Every field here is mapped from a line confirmed present in a real
// `show config` capture (see testdata/show_config_full.txt), and
// cloudconfig_fallback_test.go pins the mapping against that device's own
// cloud-json-config output for the same moment in time.
//
// Fields `show config` does not express, left at their zero value rather
// than guessed:
//
//   - FeatureLicense — a separate command (`show feature-license`), see
//     Server.currentLicense; callers that need it should fetch it there.
//   - LANInterface.Name / RateLimitRules — the device prints no leaf for
//     these even when cloud-json-config reports them set.
//   - WANInterface.SpareIPMode / Speedtest / TrafficShaping /
//     FailoverPolicyState / VLAN — no confirmed leaf.
//   - DynDNSConfig.Mode — confirmed NOT derivable: the capture has
//     "dynamic-dns service-id 1" on eth1 while cloud-json-config reports
//     dyndns_mode "disable", so the service-id leaf is not an enable flag.
//   - LearnDNSFromDHCP — no confirmed leaf.
//
// Secrets are never read here, matching the rest of cloudconfig.go: the
// oinkcode, tailscale auth-key, RADIUS secret, VPN shared-secret and admin
// password all appear in `show config` and are all deliberately skipped.
func CloudConfigFromShowConfig(raw string) CloudConfig {
	tree := ParseBlockTree(raw)
	top := topLeaves(tree)

	var cfg CloudConfig
	cfg.Source = CloudSourceShowConfig
	cfg.SystemName = valueAfter(top, "hostname ")
	cfg.TZName = valueAfter(top, "timezone ")
	cfg.DHCPAuthoritative = hasLeaf(top, "ip dhcp server authoritative")
	// The bare leaf is the link; "management cambium-remote
	// validate-server-cert" is a separate sub-option and must not count.
	cfg.CambiumRemote = hasLeaf(top, "management cambium-remote")

	applyFallbackManagement(&cfg, top)
	applyFallbackDNS(&cfg, tree, top)
	applyFallbackIPS(&cfg, top)
	applyFallbackFirewall(&cfg, tree, top)
	applyFallbackVPN(&cfg, tree, top)
	cfg.LANInterfaces = fallbackLANInterfaces(tree)
	cfg.WANInterfaces = fallbackWANInterfaces(tree)

	// cloud-json-config reports "stateful" per WAN, but the CLI only has
	// the one global-filter leaf behind it — fan the single value out.
	if blk := tree.Find("filter global-filter"); blk != nil {
		if _, ok := blk.Leaf("stateful"); ok {
			for i := range cfg.WANInterfaces {
				cfg.WANInterfaces[i].Stateful = true
			}
		}
	}
	return cfg
}

// topLeaves returns the top-level (non-block) lines of a parsed config
// tree, which is where most of this device's scalar settings live.
func topLeaves(b *Block) []string {
	out := make([]string, 0, len(b.Children))
	for _, child := range b.Children {
		if child.Block == nil {
			out = append(out, normalizeSpaces(child.Line))
		}
	}
	return out
}

func hasLeaf(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// valueAfter returns the remainder of the first line starting with prefix.
func valueAfter(lines []string, prefix string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(l, prefix))
		}
	}
	return ""
}

// valuesAfter returns the remainder of every line starting with prefix.
func valuesAfter(lines []string, prefix string) []string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			out = append(out, strings.TrimSpace(strings.TrimPrefix(l, prefix)))
		}
	}
	return out
}

// boolLeaf resolves the CLI's three-state convention for a flag: the bare
// line means on, a "no "-prefixed line means off, and absence means the
// caller's default.
func boolLeaf(lines []string, name string, def bool) bool {
	if hasLeaf(lines, name) {
		return true
	}
	if hasLeaf(lines, "no "+name) {
		return false
	}
	return def
}

func applyFallbackManagement(cfg *CloudConfig, top []string) {
	for _, v := range valuesAfter(top, "ntp server ") {
		cfg.NTPServer = append(cfg.NTPServer, NTPServer{Address: strings.Fields(v)[0]})
	}
	// "logging host <ip> [port]".
	for _, v := range valuesAfter(top, "logging host ") {
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		host := SyslogHost{IP: fields[0]}
		if len(fields) > 1 {
			host.Port = fields[1]
		}
		cfg.SyslogServer = append(cfg.SyslogServer, host)
	}
	// "logging syslog <severity>" shares its prefix with the unrelated
	// "logging syslog dnsmasq" flag, so only a numeric argument counts as
	// the severity.
	for _, v := range valuesAfter(top, "logging syslog ") {
		if _, err := strconv.Atoi(v); err == nil {
			cfg.LoggingSyslog = v
			break
		}
	}
	cfg.LoggingSyslogDNSMasq = hasLeaf(top, "logging syslog dnsmasq")
}

func applyFallbackDNS(cfg *CloudConfig, tree *Block, top []string) {
	if boolLeaf(top, "ip dns server", false) {
		cfg.DNSServer = "enable"
	} else {
		cfg.DNSServer = "disable"
	}
	for _, v := range valuesAfter(top, "ip name-server ") {
		for _, ip := range strings.Fields(v) {
			cfg.NameServer = append(cfg.NameServer, NameServerHost{IP: ip})
		}
	}
	if blk := tree.Find("dns-server"); blk != nil {
		cfg.DNSOverride = blockBoolLeaf(blk, "dns-override", false)
	}
}

// blockBoolLeaf is boolLeaf for the leaves of one sub-context block.
func blockBoolLeaf(b *Block, name string, def bool) bool {
	return boolLeaf(blockLeaves(b), name, def)
}

func blockLeaves(b *Block) []string {
	out := make([]string, 0, len(b.Children))
	for _, child := range b.Children {
		if child.Block == nil {
			out = append(out, normalizeSpaces(child.Line))
		}
	}
	return out
}

func applyFallbackIPS(cfg *CloudConfig, top []string) {
	cfg.IPS = hasLeaf(top, "intrusion-prevention")
	cfg.IPSMode = valueAfter(top, "intrusion-prevention mode ")
	cfg.IPSRuleSet = valueAfter(top, "intrusion-prevention rule-set ")
	cfg.IPSAutoUpdate = hasLeaf(top, "intrusion-prevention auto-update")
	cfg.IPSUpdateInterval = valueAfter(top, "intrusion-prevention auto-update interval ")

	// "intrusion-prevention rule-type <type>" sets the active rule type;
	// "intrusion-prevention rule-type <type> rule-category <cat>" enables
	// one category within it. The category form shares the shorter form's
	// prefix, so match on field count rather than prefix alone.
	for _, v := range valuesAfter(top, "intrusion-prevention rule-type ") {
		fields := strings.Fields(v)
		switch {
		case len(fields) == 1:
			cfg.IPSRuleType = fields[0]
		case len(fields) == 3 && fields[1] == "rule-category":
			cfg.SnortRuleCategory = append(cfg.SnortRuleCategory, SnortRuleCat{Category: snortCategoryName(fields[2])})
		}
	}
}

// snortCategoryName normalizes a rule-category leaf to the form
// cloud-json-config reports. CONFIRMED by diffing this device's own
// `show config` against its cloud-json-config for the same moment: the
// CLI spells Snort VRT categories "snort3-malware-cnc" while the JSON
// reports "malware-cnc". Other rule types (et-open's "emerging-activex")
// carry no such prefix in either form, so only the exact "snort3-" prefix
// is stripped.
func snortCategoryName(raw string) string {
	return strings.TrimPrefix(raw, "snort3-")
}

func applyFallbackFirewall(cfg *CloudConfig, tree *Block, top []string) {
	// Exact matches, not prefixes: "ip-spoof" is a prefix of
	// "ip-spoof-log".
	cfg.DOSProtectionSpoof = hasLeaf(top, "firewall dos-protection ip-spoof")
	cfg.DOSProtectionLog = hasLeaf(top, "firewall dos-protection ip-spoof-log")
	cfg.DOSProtectionSmurf = hasLeaf(top, "firewall dos-protection smurf-attack")
	cfg.DOSProtectionFrag = hasLeaf(top, "firewall dos-protection icmp-frag")

	blk := tree.Find("filter global-filter")
	if blk == nil {
		return
	}
	// Only layer3-filter rules have a cloud-json-config filter_config
	// shape. DPI rules (application-group / category-control) live in the
	// same block but are modeled differently there, so they're left to the
	// /api/config/firewall "outbound_filter_rules" view, which reads the
	// same block directly via ParseConfigFilter.
	for _, rule := range blk.FindAll("filter precedence ") {
		leaves := blockLeaves(rule)
		line := valueAfter(leaves, "layer3-filter ")
		if line == "" {
			continue
		}
		entry := FilterEntry{Name: valueAfter(leaves, "rule-name ")}
		entry.FilterRule = parseLayer3FilterRule(line)
		entry.FilterRule.ID, _ = strconv.Atoi(valueAfter(leaves, "unique_id "))
		cfg.FilterConfig = append(cfg.FilterConfig, entry)
	}
}

// parseLayer3FilterRule parses the argument list of a confirmed
// "layer3-filter" leaf, e.g.
//
//	layer3-filter deny proto any 192.168.20.0/255.255.255.0 any 172.21.0.0/255.255.0.0 any in
//
// into cloud-json-config's split src/src_mask/dest/dest_mask shape.
func parseLayer3FilterRule(args string) DPIFilterRule {
	rule := DPIFilterRule{Type: "layer3-filter"}
	fields := strings.Fields(args)
	if len(fields) < 7 || fields[1] != "proto" {
		return rule
	}
	rule.Action = fields[0]
	rule.Proto = fields[2]
	rule.Src, rule.SrcMask = splitAddrMask(fields[3])
	rule.SPort = fields[4]
	rule.Dest, rule.DestMask = splitAddrMask(fields[5])
	rule.DPort = fields[6]
	return rule
}

func splitAddrMask(spec string) (addr, mask string) {
	addr, mask, _ = strings.Cut(spec, "/")
	return addr, mask
}

func applyFallbackVPN(cfg *CloudConfig, tree *Block, top []string) {
	cfg.Tailscale = CloudTailscale{
		Enable:          hasLeaf(top, "tailscale"),
		AcceptRoutes:    hasLeaf(top, "tailscale accept-routes"),
		AdvertiseRoutes: valueAfter(top, "tailscale advertise-routes "),
	}
	cfg.SiteToSite = tree.Find("site-to-site-vpn") != nil

	// cloud-json-config's l2tp_client_vpn is the client-VPN server block's
	// own presence — confirmed by the capture, which has a "vpn-server"
	// block and reports l2tp_client_vpn true.
	if blk := tree.Find("vpn-server"); blk != nil {
		leaves := blockLeaves(blk)
		cfg.L2TPClientVPN = true
		cfg.VPNServerIface = valueAfter(leaves, "interface ")
		cfg.VPNServerMFA = hasLeaf(leaves, "mfa")
	}

	for _, blk := range tree.FindAll("radius-server client-list ") {
		leaves := blockLeaves(blk)
		cfg.RADIUSClientList = append(cfg.RADIUSClientList, RADIUSClient{
			Name:    valueAfter(leaves, "name "),
			Address: valueAfter(leaves, "address "),
			Netmask: valueAfter(leaves, "prefix-length "),
		})
	}
}

// fallbackLANInterfaces builds cloud-json-config's lan_interfaces (really
// VLANs) from the "interface vlan N" blocks, pairing each with the
// "ip dhcp pool N" whose network it contains. Pool numbers are unrelated
// to VLAN IDs on this device (see poolNumberForVLAN), so the pairing is by
// subnet, not by number.
func fallbackLANInterfaces(tree *Block) []LANInterface {
	pools := tree.FindAll("ip dhcp pool ")
	var out []LANInterface
	for _, blk := range tree.FindAll("interface vlan ") {
		id, err := strconv.Atoi(strings.TrimPrefix(blk.Header, "interface vlan "))
		if err != nil {
			continue
		}
		leaves := blockLeaves(blk)
		iface := LANInterface{VLANID: id}
		if addr := valueAfter(leaves, "ip address "); addr != "" {
			fields := strings.Fields(addr)
			iface.IPMode = "static"
			iface.IPAddr = fields[0]
			if len(fields) > 1 {
				iface.SubnetMask = fields[1]
			}
		}
		// The write path only ever emits "management-access all" or
		// "no management-access" (see VLANManagementAccessLine), so the
		// presence of the positive leaf is the whole flag.
		if valueAfter(leaves, "management-access ") != "" {
			iface.ManagementAccess = "enable"
		} else {
			iface.ManagementAccess = "disable"
		}
		// Vulnerability Scan defaults to on: a live NSE3000 prints
		// "no port-scan" under the one VLAN where it's been turned off and
		// nothing at all under the others, and the reference device (no
		// port-scan leaf under any VLAN) reports port_scan true for every
		// VLAN in cloud-json-config. So absence means on, not off.
		iface.PortScan = boolLeaf(leaves, "port-scan", true)
		if pool := poolForSubnet(pools, iface.IPAddr, iface.SubnetMask); pool != nil {
			iface.DHCPPoolConfig = fallbackDHCPPool(pool)
		}
		out = append(out, iface)
	}
	return out
}

// poolForSubnet returns the DHCP pool block whose "network" leaf covers
// the given VLAN address, or nil.
func poolForSubnet(pools []*Block, ip, mask string) *Block {
	if ip == "" || mask == "" {
		return nil
	}
	want := maskedIP(ip, mask)
	if want == "" {
		return nil
	}
	for _, pool := range pools {
		network := valueAfter(blockLeaves(pool), "network ")
		if network == "" {
			continue
		}
		fields := strings.Fields(network)
		if len(fields) < 2 {
			continue
		}
		if maskedIP(fields[0], fields[1]) == want {
			return pool
		}
	}
	return nil
}

func maskedIP(ip, mask string) string {
	parsed := net.ParseIP(ip).To4()
	m := net.ParseIP(mask).To4()
	if parsed == nil || m == nil {
		return ""
	}
	return parsed.Mask(net.IPv4Mask(m[0], m[1], m[2], m[3])).String()
}

func fallbackDHCPPool(blk *Block) DHCPPoolConfig {
	leaves := blockLeaves(blk)
	// A pool that exists in the running config is a pool that's enabled;
	// the device drops the whole block when it isn't. Options start as an
	// empty slice rather than nil so the shape matches what
	// cloud-json-config produces and the frontend always sees a list.
	out := DHCPPoolConfig{Enable: true, Options: []DHCPPoolOption{}}
	if r := strings.Fields(valueAfter(leaves, "address-range ")); len(r) >= 2 {
		out.StartAddress, out.EndAddress = r[0], r[1]
	}
	if dns := strings.Fields(valueAfter(leaves, "dns-server ")); len(dns) >= 1 {
		out.PrimaryDNS = dns[0]
	}
	// "lease <days> <hours> <minutes>".
	if lease := strings.Fields(valueAfter(leaves, "lease ")); len(lease) >= 3 {
		out.LeaseTimeDay, _ = strconv.Atoi(lease[0])
		out.LeaseTimeHour, _ = strconv.Atoi(lease[1])
		out.LeaseTimeMinute, _ = strconv.Atoi(lease[2])
	}
	// Custom options, which nothing read before: the frontend showed an
	// always-empty list because they were only ever modeled on the write
	// side. A pool can carry several, so every matching leaf is taken.
	for _, leaf := range leaves {
		if !strings.HasPrefix(leaf, "option ") {
			continue
		}
		if opt, ok := ParseDHCPOptionLeaf(leaf); ok {
			out.Options = append(out.Options, DHCPPoolOption{Code: opt.Code, Type: opt.Type, Value: opt.Value})
		}
	}
	return out
}

// fallbackWANInterfaces builds cloud-json-config's wan_interfaces from the
// "interface eth N" blocks marked "type wan".
func fallbackWANInterfaces(tree *Block) []WANInterface {
	var out []WANInterface
	// Walk the blocks the device actually printed rather than a fixed
	// port range: an NSE4000 has ten ethernet ports, and scanning only
	// eth1-eth6 would make a WAN on eth7 or above invisible.
	for _, blk := range ethInterfaceBlocks(tree) {
		n := blk.port
		leaves := blockLeaves(blk.block)
		if valueAfter(leaves, "type ") != "wan" {
			continue
		}
		wan := WANInterface{
			Name:    valueAfter(leaves, "wan-name "),
			LANIntf: fmt.Sprintf("eth%d", n),
		}
		switch {
		case hasLeaf(leaves, "ip address dhcp"):
			wan.IPMode = "dynamic"
		case valueAfter(leaves, "ip address ") != "":
			wan.IPMode = "static"
		}
		if hasLeaf(leaves, "ip nat inside") {
			wan.SourceNAT = "enable"
		} else {
			wan.SourceNAT = "disable"
		}
		wan.BandwidthConfig = BandwidthConfig{
			// "uplink-bandwidth Mbps 40" — cloud-json-config carries the
			// bare number, so the unit keyword is dropped. Mbps is the only
			// unit this device has been observed to emit; if another one
			// exists, the number would need scaling rather than truncating.
			UplinkBandwidth:   lastFieldOf(valueAfter(leaves, "uplink-bandwidth ")),
			DownlinkBandwidth: lastFieldOf(valueAfter(leaves, "downlink-bandwidth ")),
		}
		wan.LoadBalanceConfig = fallbackLoadBalance(leaves)
		wan.StarlinkEnable = hasLeaf(leaves, "starlink")
		wan.StarlinkDishMode = valueAfter(leaves, "starlink dish-mode ")
		wan.StarlinkDishIP = valueAfter(leaves, "starlink dish-ip ")
		wan.StarlinkDishPort = valueAfter(leaves, "starlink dish-port ")
		wan.StarlinkDishGRPCReflectionIP = valueAfter(leaves, "starlink dish-grpc-reflection-ip ")
		wan.StarlinkDishGRPCReflectionPort = valueAfter(leaves, "starlink dish-grpc-reflection-port ")
		wan.DynDNSConfig = fallbackDynDNS(tree, valueAfter(leaves, "dynamic-dns service-id "))
		out = append(out, wan)
	}
	return out
}

// ethBlock pairs an "interface eth N" block with its parsed port number.
type ethBlock struct {
	port  int
	block *Block
}

// ethInterfaceBlocks returns every "interface eth N" block the device
// printed, in port order. Port counts differ by model (six on an NSE3000,
// ten on an NSE4000), so nothing here may assume a range.
func ethInterfaceBlocks(tree *Block) []ethBlock {
	var out []ethBlock
	for _, blk := range tree.FindAll("interface eth ") {
		n, err := strconv.Atoi(strings.TrimPrefix(blk.Header, "interface eth "))
		if err != nil {
			continue
		}
		out = append(out, ethBlock{port: n, block: blk})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].port < out[j].port })
	return out
}

func lastFieldOf(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func fallbackLoadBalance(leaves []string) LoadBalanceConfig {
	lb := LoadBalanceConfig{
		Mode:                      valueAfter(leaves, "load-balance mode "),
		NumHostsFailInterfaceDown: valueAfter(leaves, "load-balance num-hosts-fail-interface-down "),
		PingFailureDetectTime:     valueAfter(leaves, "load-balance ping failure-detect-time "),
		PingInterval:              valueAfter(leaves, "load-balance ping interval "),
		PingTimeout:               valueAfter(leaves, "load-balance ping timeout "),
		TrafficSharePercentage:    valueAfter(leaves, "load-balance traffic-share-percentage "),
		BackupLinkPriority:        valueAfter(leaves, "load-balance backup-link-priority "),
	}
	if hosts := valueAfter(leaves, "load-balance monitor-hosts "); hosts != "" {
		lb.MonitorHosts = strings.Split(hosts, ",")
	}
	return lb
}

// fallbackDynDNS resolves a WAN's "dynamic-dns service-id N" leaf against
// the matching top-level "ip dns dynamic services-list N" block. Mode is
// deliberately left empty — see the CloudConfigFromShowConfig doc comment.
func fallbackDynDNS(tree *Block, serviceID string) DynDNSConfig {
	if serviceID == "" {
		return DynDNSConfig{}
	}
	// Exact header match, not Find's prefix match: service-id 1 must not
	// pick up "services-list 10".
	var blk *Block
	for _, candidate := range tree.FindAll("ip dns dynamic services-list ") {
		if candidate.Header == "ip dns dynamic services-list "+serviceID {
			blk = candidate
			break
		}
	}
	if blk == nil {
		return DynDNSConfig{}
	}
	leaves := blockLeaves(blk)
	return DynDNSConfig{
		Provider:    valueAfter(leaves, "provider "),
		ServerName:  valueAfter(leaves, "server-name "),
		Username:    valueAfter(leaves, "username "),
		DNSHostname: valueAfter(leaves, "dnshostname "),
	}
}
