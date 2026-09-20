package nse

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// WireGuard client VPN.
//
// The device speaks WireGuard in three distinct roles, and only two of
// them matter for letting a laptop or a phone reach the site:
//
//	vpn-server > wireguard                     the device as concentrator
//	radius-server users-list N > wireguard-user M   one peer
//	vpn-client > wireguard                     the device as someone's client
//
// The third is not handled here. The first two are, and the capture in
// testdata/show_config_subblocks.txt settles their shape:
//
//	vpn-server
//	 wireguard
//	  interface 198.51.100.7
//	  virtual-interface 10.10.100.1/24
//	  listen-port 1
//	  offline-interval 4
//	  exit
//	 exit
//
//	radius-server users-list 10
//	 name someuser
//	 wireguard
//	 wireguard-user 1
//	   name someuser_phone
//	   public-key <key>
//	   ip-address 10.10.100.2
//	   exit
//
// A peer carries a public key and an address, which is a textbook
// road-warrior entry: the client generates its own pair and hands over
// only the public half. The name in that capture is "someuser_phone",
// which is the clearest evidence this is the phone-and-laptop case rather
// than a device-to-device tunnel.
//
// UNCONFIRMED, and called out at each use: the removal form for a peer,
// the trailing exit on these sub-contexts (the capture's renderer ends
// them when the next sibling begins, though ExtractStanza already replays
// such blocks with an explicit exit), and whether the server block accepts
// a private-key leaf.

// --- Keys ---------------------------------------------------------------
//
// WireGuard keys are X25519. golang.org/x/crypto is already a dependency
// here (it is what speaks SSH), so generating a pair costs no new
// dependency and a client's private half never has to leave this process.

// WireGuardKeypair is an X25519 pair in WireGuard's own base64 format.
type WireGuardKeypair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// NewWireGuardKeypair generates a peer's keys, clamping the private key
// as the WireGuard spec requires.
func NewWireGuardKeypair() (WireGuardKeypair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return WireGuardKeypair{}, fmt.Errorf("generating a private key: %w", err)
	}
	// Curve25519 clamping: clear the low three bits, clear the top bit,
	// set the second-highest. wg does the same to anything handed to it.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return WireGuardKeypair{}, fmt.Errorf("deriving the public key: %w", err)
	}
	return WireGuardKeypair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// PublicKeyFor derives the public half of a private key. This is what
// makes pushing a generated key to the device useful: the server's public
// key is then known by construction and never has to be read back, which
// matters because no captured command returns it.
func PublicKeyFor(privateKey string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("not a WireGuard private key: expected 32 base64-encoded bytes")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("deriving the public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// ValidWireGuardKey reports whether a string is shaped like a WireGuard
// key. Peers hand these over by copy and paste, so a truncated one is the
// likely mistake and it must not reach the device.
func ValidWireGuardKey(k string) bool {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
	return err == nil && len(raw) == 32
}

// --- Server -------------------------------------------------------------

// WireGuardServer is the concentrator's own settings.
type WireGuardServer struct {
	// Interface is what clients dial: this device's WAN address, or the
	// name it is published under.
	Interface string `json:"interface"`
	// VirtualInterface is the tunnel subnet in CIDR, the device's own end.
	VirtualInterface string `json:"virtual_interface"`
	ListenPort       int    `json:"listen_port"`
	OfflineInterval  int    `json:"offline_interval,omitempty"`
}

func ValidateWireGuardServer(s WireGuardServer) error {
	if ip := net.ParseIP(strings.TrimSpace(s.Interface)); ip == nil && !validHostname(s.Interface) {
		return fmt.Errorf("the endpoint %q is neither an address nor a hostname", s.Interface)
	}
	ip, _, err := net.ParseCIDR(strings.TrimSpace(s.VirtualInterface))
	if err != nil {
		return fmt.Errorf("the tunnel subnet %q is not a CIDR such as 10.10.100.1/24", s.VirtualInterface)
	}
	if ip.To4() == nil {
		return fmt.Errorf("the tunnel subnet must be IPv4")
	}
	if s.ListenPort < 1 || s.ListenPort > 65535 {
		return fmt.Errorf("the listen port must be between 1 and 65535")
	}
	return nil
}

func validHostname(h string) bool {
	h = strings.TrimSpace(h)
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		if !(r == '.' || r == '-' || (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// WireGuardServerLines renders the server block inside vpn-server.
func WireGuardServerLines(s WireGuardServer) []string {
	body := []string{
		"wireguard",
		" interface " + strings.TrimSpace(s.Interface),
		" virtual-interface " + strings.TrimSpace(s.VirtualInterface),
		fmt.Sprintf(" listen-port %d", s.ListenPort),
	}
	if s.OfflineInterval > 0 {
		body = append(body, fmt.Sprintf(" offline-interval %d", s.OfflineInterval))
	}
	body = append(body, " exit")
	return append([]string{"vpn-server"}, append(body, "exit")...)
}

// --- Peers --------------------------------------------------------------

// WireGuardPeer is one client entry under a RADIUS user.
type WireGuardPeer struct {
	UserList  int    `json:"user_list"`
	Index     int    `json:"index"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	IPAddress string `json:"ip_address"`
}

// ValidateWireGuardPeer checks a peer against the tunnel it is joining.
func ValidateWireGuardPeer(p WireGuardPeer, tunnel string) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("the peer needs a name")
	}
	if !ValidWireGuardKey(p.PublicKey) {
		return fmt.Errorf("the public key is not 32 base64-encoded bytes; a truncated paste is the usual cause")
	}
	ip := net.ParseIP(strings.TrimSpace(p.IPAddress))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("%q is not an IPv4 address", p.IPAddress)
	}
	// A peer outside the tunnel subnet is not rejected by the device, it
	// is simply never routed, which is the worst kind of wrong: the
	// tunnel comes up and nothing works.
	if tunnel != "" {
		if _, subnet, err := net.ParseCIDR(strings.TrimSpace(tunnel)); err == nil && !subnet.Contains(ip) {
			return fmt.Errorf("%s is outside the tunnel subnet %s, so the peer would never be routed", p.IPAddress, tunnel)
		}
	}
	if p.UserList < 1 || p.Index < 1 {
		return fmt.Errorf("a peer needs a user list and an index, both starting at 1")
	}
	return nil
}

// WireGuardPeerLines renders one peer inside its RADIUS user's list.
func WireGuardPeerLines(p WireGuardPeer) []string {
	return []string{
		fmt.Sprintf("radius-server users-list %d", p.UserList),
		" wireguard",
		fmt.Sprintf(" wireguard-user %d", p.Index),
		"  name " + strings.TrimSpace(p.Name),
		"  public-key " + strings.TrimSpace(p.PublicKey),
		"  ip-address " + strings.TrimSpace(p.IPAddress),
		"  exit",
		"exit",
	}
}

// WireGuardPeerDeleteLines removes a peer. UNCONFIRMED: no capture shows
// a removal, so this follows the no-prefix convention the rest of this
// CLI uses, and it goes through the apply path that reports a rejected
// line rather than assuming success.
func WireGuardPeerDeleteLines(userList, index int) []string {
	return []string{
		fmt.Sprintf("radius-server users-list %d", userList),
		fmt.Sprintf(" no wireguard-user %d", index),
		"exit",
	}
}
