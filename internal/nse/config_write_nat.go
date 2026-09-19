package nse

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Port forwarding and source NAT.
//
// CONFIRMED shape, from a live firmware-2.3-r6 capture
// (testdata/show_config_subblocks.txt). Both are sub-contexts of a WAN
// port, and the leaf spellings are irregular enough that they are quoted
// here rather than reconstructed:
//
//	interface eth 1
//	 port-forward-rule 1
//	   port 9090
//	   lan-IP 10.0.0.50
//	   protocol tcp
//	   lan-port 9090
//	 source-nat-rule 1
//	   lan-IP address 10.1.0.0/24
//	   overload disable
//	   public-IP 203.0.113.1-203.0.113.254
//
// Note `lan-IP` and `public-IP`: capitalised mid-word, and `lan-IP` takes
// a bare address under port-forward-rule but the word `address` first
// under source-nat-rule. Neither is a typo here.
//
// UNCONFIRMED: the trailing `exit` and the `no port-forward-rule N`
// removal form. The capture prints neither, because this renderer ends
// these blocks when the next sibling begins. Both follow the convention
// the rest of this CLI uses and that ExtractStanza already replays, and
// both go through the apply path that reports a rejected line rather than
// assuming success.

// PortForwardRule is one inbound publication.
type PortForwardRule struct {
	WANPort  int    // the port reached from outside
	LANIP    string // the internal host
	Protocol string // tcp | udp
	LANPort  int    // the port on that host
}

// ValidatePortForward refuses a rule before it can publish the wrong
// host. This is the one write in the app whose failure mode is not a
// rejected command but a service quietly exposed to the internet, so the
// checking happens here and not on the device.
func ValidatePortForward(r PortForwardRule) error {
	ip := net.ParseIP(strings.TrimSpace(r.LANIP))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("the internal address %q is not an IPv4 address", r.LANIP)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("0.0.0.0 would publish every host on the LAN, not one")
	}
	if !ip.IsPrivate() && !ip.IsLoopback() {
		return fmt.Errorf("%s is not a private address; a port-forward target is a host on this LAN", r.LANIP)
	}
	switch strings.ToLower(r.Protocol) {
	case "tcp", "udp":
	default:
		return fmt.Errorf("protocol must be tcp or udp, not %q", r.Protocol)
	}
	for label, p := range map[string]int{"external port": r.WANPort, "internal port": r.LANPort} {
		if p < 1 || p > 65535 {
			return fmt.Errorf("%s must be between 1 and 65535", label)
		}
	}
	return nil
}

// PortForwardLines builds the rule inside its WAN port's context.
func PortForwardLines(eth, index int, r PortForwardRule) []string {
	return BuildInterfaceEthLines(eth, []string{
		fmt.Sprintf("port-forward-rule %d", index),
		fmt.Sprintf(" port %d", r.WANPort),
		" lan-IP " + strings.TrimSpace(r.LANIP),
		" protocol " + strings.ToLower(r.Protocol),
		fmt.Sprintf(" lan-port %d", r.LANPort),
		" exit",
	})
}

// PortForwardDeleteLines removes a rule by its index.
func PortForwardDeleteLines(eth, index int) []string {
	return BuildInterfaceEthLines(eth, []string{
		fmt.Sprintf("no port-forward-rule %d", index),
	})
}

// SourceNATRule maps a LAN subnet onto one or more public addresses.
type SourceNATRule struct {
	LANSubnet string // CIDR
	PublicIP  string // single address, or "first-last"
	Overload  bool   // many-to-one
}

// ValidateSourceNAT checks what the device would otherwise accept and
// then behave surprisingly about.
func ValidateSourceNAT(r SourceNATRule) error {
	if _, _, err := net.ParseCIDR(strings.TrimSpace(r.LANSubnet)); err != nil {
		return fmt.Errorf("the LAN subnet %q is not a CIDR such as 10.1.0.0/24", r.LANSubnet)
	}
	pub := strings.TrimSpace(r.PublicIP)
	if pub == "" {
		return fmt.Errorf("no public address given")
	}
	// The capture carries a range as "first-last"; a single address is
	// the degenerate case of the same field.
	for _, part := range strings.SplitN(pub, "-", 2) {
		if ip := net.ParseIP(strings.TrimSpace(part)); ip == nil || ip.To4() == nil {
			return fmt.Errorf("%q is not an IPv4 address or an IPv4 range", r.PublicIP)
		}
	}
	return nil
}

// SourceNATLines builds the rule inside its WAN port's context.
func SourceNATLines(eth, index int, r SourceNATRule) []string {
	overload := "disable"
	if r.Overload {
		overload = "enable"
	}
	return BuildInterfaceEthLines(eth, []string{
		fmt.Sprintf("source-nat-rule %d", index),
		" lan-IP address " + strings.TrimSpace(r.LANSubnet),
		" overload " + overload,
		" public-IP " + strings.TrimSpace(r.PublicIP),
		" exit",
	})
}

func SourceNATDeleteLines(eth, index int) []string {
	return BuildInterfaceEthLines(eth, []string{
		fmt.Sprintf("no source-nat-rule %d", index),
	})
}

// ethIndexOf turns "eth3" into 3. A port name this app did not derive
// from the device is a request error, not something to interpolate into
// a config command.
func ethIndexOf(name string) (int, error) {
	n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(name), "eth"))
	if err != nil || n < 1 || n > 64 {
		return 0, fmt.Errorf("%q is not a port name such as eth1", name)
	}
	return n, nil
}
