package nse

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// isIPv4 reports whether s is a dotted-quad address.
func isIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

// Port-forward and source-NAT rules live as sub-contexts inside an
// "interface eth N" block. CONFIRMED from a live capture (kept as
// testdata/show_config_subblocks.txt):
//
//	port-forward-rule 1          source-nat-rule 1
//	  port 9090                    lan-IP address 10.1.0.0/24
//	  lan-IP 10.0.0.50             overload disable
//	  protocol tcp                 public-IP 203.0.113.1-203.0.113.254
//	  lan-port 9090
//
// The spelling is irregular and is quoted rather than reconstructed:
// "lan-IP" and "public-IP" capitalise IP mid-word, and "lan-IP" takes a
// bare address under port-forward-rule but the word "address" first under
// source-nat-rule. Tests below fail if either is tidied.
//
// "overload" is printed only when it is off. CONFIRMED by writing both
// forms to a live device and reading the result back: "overload disable"
// came back verbatim, "overload enable" came back as no line at all. The
// device prints only the non-default value, so an absent leaf means
// overload is ENABLED — the same "absence is the default" convention as
// per-VLAN port-scan. Reading an absent leaf as unknown, or as disabled,
// would report the opposite of the truth.

// PortForwardRule forwards one WAN port to a host behind the device.
type PortForwardRule struct {
	Interface string `json:"interface"`
	Index     int    `json:"index"`
	Port      int    `json:"port"`
	LANIP     string `json:"lan_ip"`
	Protocol  string `json:"protocol"`
	LANPort   int    `json:"lan_port"`
}

// SourceNATRule rewrites the source address of traffic leaving a WAN.
//
// Overload is what separates the two NAT modes, not the shape of the
// public address: enabled, many LAN hosts share the public address by
// port (1:many); disabled, each LAN host takes its own address from the
// range (1:1). Never empty when read — see OverloadEnabled.
type SourceNATRule struct {
	Interface string `json:"interface"`
	Index     int    `json:"index"`
	LANSubnet string `json:"lan_subnet"`
	Overload  string `json:"overload"`
	PublicIP  string `json:"public_ip"`
}

// Overload values as the device spells them.
const (
	OverloadEnabled  = "enable"
	OverloadDisabled = "disable"
)

// NATOneOneRule maps one public address onto one LAN address in both
// directions. CONFIRMED from the device's context help:
//
//	nat-one-one 1                 (rule id {1-64})
//	  lan-IP <addr>               <eg 192.168.200.50 | 192.168.200.0/24>
//	  public-IP <addr>            <eg 192.168.200.50 | 192.168.200.0/24>
//	  protocol <tcp|udp|any>
//	  rule-name <name>            max 64 chars, names a counter
//	  allowed-sources ip-address <addr>   single | CIDR | start-end range
//	  allowed-sources ip-group <name>
//
// Note "lan-IP" takes a BARE address here, as it does under
// port-forward-rule and unlike source-nat-rule, which puts the word
// "address" first. The irregularity is per block and is quoted, never
// reconstructed.
//
// "description" is deliberately not modelled: its argument form was not
// probed, and this CLI has already proved that a leaf's shape cannot be
// inferred from its name.
type NATOneOneRule struct {
	Interface string `json:"interface"`
	Index     int    `json:"index"`
	LANIP     string `json:"lan_ip"`
	PublicIP  string `json:"public_ip"`
	Protocol  string `json:"protocol,omitempty"`
	RuleName  string `json:"rule_name,omitempty"`

	// AllowedSourceType is "ip-address" or "ip-group"; AllowedSource is
	// the value that follows it. Empty means the rule accepts any source.
	AllowedSourceType string `json:"allowed_source_type,omitempty"`
	AllowedSource     string `json:"allowed_source,omitempty"`
}

// Allowed-sources sub-keywords, as the device spells them.
const (
	AllowedSourceIPAddress = "ip-address"
	AllowedSourceIPGroup   = "ip-group"
)

// NATOneOneProtocols is the set the device's help lists for this block.
// Note it includes "any", which port-forward-rule does not offer.
var NATOneOneProtocols = []string{"tcp", "udp", "any"}

// NATRules is everything the NAT sub-contexts of the eth interfaces hold.
// Grouped rather than returned as a widening tuple: the device has four
// such contexts and ParseNATRules walks the tree once for all of them.
type NATRules struct {
	PortForwards []PortForwardRule `json:"port_forward_rules"`
	SourceNATs   []SourceNATRule   `json:"source_nat_rules"`
	OneOne       []NATOneOneRule   `json:"nat_one_one_rules"`
}

// PortForwardProtocols is the set this app will write. Only "tcp" has
// been seen in a capture; "udp" is accepted because the pairing is
// universal, but neither it nor any third value is confirmed for this CLI.
var PortForwardProtocols = []string{"tcp", "udp"}

// ParseNATRules reads both rule kinds out of a `show config` capture,
// walking whichever eth interfaces the device printed rather than a fixed
// port range.
func ParseNATRules(cfgRaw string) NATRules {
	tree := ParseBlockTree(cfgRaw)
	out := NATRules{
		PortForwards: []PortForwardRule{},
		SourceNATs:   []SourceNATRule{},
		OneOne:       []NATOneOneRule{},
	}
	forwards, snats := out.PortForwards, out.SourceNATs
	for _, eth := range ethInterfaceBlocks(tree) {
		name := fmt.Sprintf("eth%d", eth.port)
		for _, blk := range eth.block.FindAll("port-forward-rule ") {
			idx, err := strconv.Atoi(strings.TrimPrefix(blk.Header, "port-forward-rule "))
			if err != nil {
				continue
			}
			leaves := blockLeaves(blk)
			r := PortForwardRule{Interface: name, Index: idx,
				LANIP:    valueAfter(leaves, "lan-IP "),
				Protocol: valueAfter(leaves, "protocol "),
			}
			r.Port, _ = strconv.Atoi(valueAfter(leaves, "port "))
			r.LANPort, _ = strconv.Atoi(valueAfter(leaves, "lan-port "))
			forwards = append(forwards, r)
		}
		for _, blk := range eth.block.FindAll("source-nat-rule ") {
			idx, err := strconv.Atoi(strings.TrimPrefix(blk.Header, "source-nat-rule "))
			if err != nil {
				continue
			}
			leaves := blockLeaves(blk)
			// An absent overload leaf means enabled; only the
			// non-default "disable" is ever printed.
			overload := valueAfter(leaves, "overload ")
			if overload == "" {
				overload = OverloadEnabled
			}
			snats = append(snats, SourceNATRule{Interface: name, Index: idx,
				LANSubnet: valueAfter(leaves, "lan-IP address "),
				Overload:  overload,
				PublicIP:  valueAfter(leaves, "public-IP "),
			})
		}
		for _, blk := range eth.block.FindAll("nat-one-one ") {
			idx, err := strconv.Atoi(strings.TrimPrefix(blk.Header, "nat-one-one "))
			if err != nil {
				continue
			}
			leaves := blockLeaves(blk)
			r := NATOneOneRule{Interface: name, Index: idx,
				LANIP:    valueAfter(leaves, "lan-IP "),
				PublicIP: valueAfter(leaves, "public-IP "),
				Protocol: valueAfter(leaves, "protocol "),
				RuleName: valueAfter(leaves, "rule-name "),
			}
			for _, kind := range []string{AllowedSourceIPAddress, AllowedSourceIPGroup} {
				if v := valueAfter(leaves, "allowed-sources "+kind+" "); v != "" {
					r.AllowedSourceType, r.AllowedSource = kind, v
					break
				}
			}
			out.OneOne = append(out.OneOne, r)
		}
	}
	out.PortForwards, out.SourceNATs = forwards, snats
	return out
}

// maxNATRuleIndex is the device's stated ceiling: entering a rule
// context without an id answers "Enter rule id {1-64}".
const maxNATRuleIndex = 64

// NextRuleIndex returns the lowest unused index for a rule kind on one
// interface. Indexes are per interface and per kind, as the capture shows
// a port-forward-rule 1 and a source-nat-rule 1 coexisting on eth1.
func NextRuleIndex(used []int) int {
	taken := map[int]bool{}
	for _, n := range used {
		taken[n] = true
	}
	for i := 1; ; i++ {
		if !taken[i] {
			return i
		}
	}
}

// PortForwardLeaves builds the body of a port-forward-rule block. The
// order matches the capture; "lan-IP" takes a bare address here.
func PortForwardLeaves(r PortForwardRule) []string {
	return []string{
		fmt.Sprintf("port %d", r.Port),
		"lan-IP " + r.LANIP,
		"protocol " + r.Protocol,
		fmt.Sprintf("lan-port %d", r.LANPort),
	}
}

// SourceNATLeaves builds the body of a source-nat-rule block. Note
// "lan-IP address" here against the bare "lan-IP" above — the same
// keyword, two argument forms, in sibling blocks.
//
// "overload enable" is sent when asked for even though the device will
// not print it back. Sending it is confirmed accepted, and relying on the
// default instead would mean a rule written here reads differently from
// one written with it.
func SourceNATLeaves(r SourceNATRule) []string {
	leaves := []string{"lan-IP address " + r.LANSubnet}
	if r.Overload != "" {
		leaves = append(leaves, "overload "+r.Overload)
	}
	return append(leaves, "public-IP "+r.PublicIP)
}

// BuildRuleLines wraps a rule body in its sub-context, inside the
// interface block the caller supplies. The trailing "exit" leaves the
// rule context; BuildInterfaceEthLines adds the one that leaves the
// interface.
func BuildRuleLines(header string, leaves []string) []string {
	out := make([]string, 0, len(leaves)+2)
	out = append(out, header)
	out = append(out, leaves...)
	return append(out, "exit")
}

// NATOneOneLeaves builds the body of a nat-one-one block.
//
// CONFIRMED live end to end: every leaf below was accepted on an NSE4000
// and `show config` printed them back verbatim, in exactly this order.
func NATOneOneLeaves(r NATOneOneRule) []string {
	leaves := []string{"lan-IP " + r.LANIP, "public-IP " + r.PublicIP}
	if r.Protocol != "" {
		leaves = append(leaves, "protocol "+r.Protocol)
	}
	if r.RuleName != "" {
		leaves = append(leaves, "rule-name "+r.RuleName)
	}
	if r.AllowedSourceType != "" {
		leaves = append(leaves, "allowed-sources "+r.AllowedSourceType+" "+r.AllowedSource)
	}
	return leaves
}

// ValidateNATOneOne rejects a rule the device would refuse, or that would
// smuggle a second command into a line.
func ValidateNATOneOne(r NATOneOneRule) error {
	if !isIPv4OrCIDR(r.LANIP) {
		return fmt.Errorf("lan_ip must be an IPv4 address or CIDR, got %q", r.LANIP)
	}
	if !isIPv4OrCIDR(r.PublicIP) {
		return fmt.Errorf("public_ip must be an IPv4 address or CIDR, got %q", r.PublicIP)
	}
	if r.Protocol != "" && !slices.Contains(NATOneOneProtocols, r.Protocol) {
		return fmt.Errorf("protocol must be one of %s", strings.Join(NATOneOneProtocols, ", "))
	}
	if err := validateRuleName(r.RuleName); err != nil {
		return err
	}
	switch r.AllowedSourceType {
	case "":
		if r.AllowedSource != "" {
			return fmt.Errorf("allowed_source_type is required when allowed_source is set")
		}
	case AllowedSourceIPAddress:
		if !isIPv4OrCIDR(r.AllowedSource) && !isIPv4Range(r.AllowedSource) {
			return fmt.Errorf("allowed_source must be an address, CIDR, or start-end range, got %q", r.AllowedSource)
		}
	case AllowedSourceIPGroup:
		if err := validateRuleWord("allowed_source", r.AllowedSource, 64); err != nil {
			return err
		}
		if r.AllowedSource == "" {
			return fmt.Errorf("allowed_source is required for an ip-group")
		}
	default:
		return fmt.Errorf("allowed_source_type must be %q or %q", AllowedSourceIPAddress, AllowedSourceIPGroup)
	}
	return nil
}

// ruleNameChars is the device's own rule, quoted from its rejection of
// "claude-test": "rule-name may only contain letters, digits, and
// underscores". A hyphen is refused, so this is narrower than the "no
// whitespace" guard a free-text leaf would otherwise get. The help says
// max 64 characters.
var ruleNameChars = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// validateRuleName guards the rule-name leaf, which names a traffic
// counter rather than addressing anything.
func validateRuleName(v string) error {
	if v == "" {
		return nil
	}
	if len(v) > 64 {
		return fmt.Errorf("rule_name must be 64 characters or fewer")
	}
	if !ruleNameChars.MatchString(v) {
		return fmt.Errorf("rule_name may only contain letters, digits, and underscores")
	}
	return nil
}

// validateRuleWord guards a free-text leaf whose character set the device
// has not stated (an ip-group name). Whitespace is refused rather than
// quoted: an unquoted space would be read as the start of another
// argument, and no capture shows this CLI accepting a quoted value.
func validateRuleWord(field, v string, max int) error {
	if v == "" {
		return nil
	}
	if len(v) > max {
		return fmt.Errorf("%s must be %d characters or fewer", field, max)
	}
	if strings.ContainsFunc(v, unicode.IsSpace) {
		return fmt.Errorf("%s cannot contain spaces", field)
	}
	return nil
}

// isIPv4OrCIDR accepts either a bare dotted quad or an IPv4 CIDR, the two
// forms the device's help shows for lan-IP and public-IP.
func isIPv4OrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if isIPv4(s) {
		return true
	}
	ip, _, err := net.ParseCIDR(s)
	return err == nil && ip.To4() != nil
}

// isIPv4Range accepts the "start-end" form the allowed-sources help shows
// alongside a single address and a CIDR.
func isIPv4Range(s string) bool {
	start, end, ok := strings.Cut(strings.TrimSpace(s), "-")
	return ok && isIPv4(start) && isIPv4(end)
}

// RuleDeleteLine removes a rule by index. CONFIRMED live for both
// blocks: "no port-forward-rule 2" and "no source-nat-rule 3" were each
// sent inside the owning "interface eth N" submode and accepted, and a
// re-read of show config showed the rule gone.
func RuleDeleteLine(kind string, index int) string {
	return fmt.Sprintf("no %s %d", kind, index)
}

// ValidatePortForward rejects a rule the device would refuse, so the
// error names the field rather than arriving as a CLI parse failure.
func ValidatePortForward(r PortForwardRule) error {
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if r.LANPort < 1 || r.LANPort > 65535 {
		return fmt.Errorf("lan_port must be between 1 and 65535")
	}
	if strings.TrimSpace(r.LANIP) == "" {
		return fmt.Errorf("lan_ip is required")
	}
	if !isIPv4(r.LANIP) {
		return fmt.Errorf("lan_ip must be an IPv4 address")
	}
	for _, p := range PortForwardProtocols {
		if r.Protocol == p {
			return nil
		}
	}
	return fmt.Errorf("protocol must be one of: %s", strings.Join(PortForwardProtocols, ", "))
}

// ValidateSourceNAT does the same for a source-NAT rule. public-IP was a
// range in the capture ("a.b.c.1-a.b.c.254"); a single address is
// accepted too, since a 1:1 mapping is the documented cnMaestro case.
func ValidateSourceNAT(r SourceNATRule) error {
	if strings.TrimSpace(r.LANSubnet) == "" {
		return fmt.Errorf("lan_subnet is required")
	}
	if !strings.Contains(r.LANSubnet, "/") {
		return fmt.Errorf("lan_subnet must be a CIDR, e.g. 10.1.0.0/24")
	}
	if strings.TrimSpace(r.PublicIP) == "" {
		return fmt.Errorf("public_ip is required")
	}
	for _, part := range strings.SplitN(r.PublicIP, "-", 2) {
		if !isIPv4(strings.TrimSpace(part)) {
			return fmt.Errorf("public_ip must be an IPv4 address or a range like 203.0.113.1-203.0.113.254")
		}
	}
	switch r.Overload {
	case "", OverloadEnabled, OverloadDisabled:
		return nil
	}
	return fmt.Errorf("overload must be 'enable' or 'disable'")
}
