package nse

import (
	"fmt"
	"sort"
	"strings"
)

// The client configuration file.
//
// This is the piece that used to live only in the cloud console. A
// WireGuard client config is plain text and every field in it is known
// locally except one:
//
//	[Interface]
//	PrivateKey = generated here, never sent to the device
//	Address    = the address assigned to this peer
//
//	[Peer]
//	PublicKey  = the server's public key      <- the only unknown
//	Endpoint   = interface + listen-port, both read from the config
//	AllowedIPs = the subnets this client should reach
//
// The server's public key is not printed by any command that has been
// captured: `show config`'s vpn-server block carries no key leaf at all,
// and `show vpn-sessions wireguard` returned an empty JSON error on a
// device with WireGuard unconfigured. Redaction is not the explanation —
// the same capture preserves `wireguard private-key <redacted>` under
// vpn-client, so a key line under vpn-server would have survived as a
// redacted line if it existed.
//
// So the key is supplied rather than discovered, and there are two honest
// ways to have it. Either the operator reads it from the cloud console
// while that still exists, or the device accepts a private-key leaf in
// its wireguard block, in which case this app generates the pair, pushes
// the private half and knows the public half by construction. The second
// is better in every way that matters — the configuration becomes
// reproducible, and a replaced device can be given the same key so no
// client needs reconfiguring — but it is UNCONFIRMED until someone tries
// it on a lab unit.
//
// Either way the rendering below is the same, and it refuses to produce a
// file with a placeholder where the key should be. A client config that
// looks complete and cannot connect is worse than one that says what is
// missing.

// WireGuardClientConfig is everything needed to render one client file.
type WireGuardClientConfig struct {
	// PeerName is used for the filename and a comment, nothing else.
	PeerName string
	// PrivateKey is this client's own, generated locally.
	PrivateKey string
	// Address is the tunnel address assigned to this peer, with prefix.
	Address string
	// ServerPublicKey is the concentrator's public key.
	ServerPublicKey string
	// Endpoint is host:port as the client will dial it.
	Endpoint string
	// AllowedIPs are the subnets routed into the tunnel. Empty means a
	// full tunnel, which is stated rather than assumed.
	AllowedIPs []string
	// DNS is optional; a split tunnel usually wants the site's resolver.
	DNS string
	// Keepalive in seconds. Non-zero matters behind NAT, which is most
	// clients most of the time.
	Keepalive int
}

// RenderWireGuardClientConfig produces the .conf a client imports.
//
// It fails rather than emitting a placeholder: every field below is
// required for the tunnel to come up, and a file that looks finished but
// silently cannot connect costs more to debug than a refusal costs to
// read.
func RenderWireGuardClientConfig(c WireGuardClientConfig) (string, error) {
	switch {
	case !ValidWireGuardKey(c.PrivateKey):
		return "", fmt.Errorf("the client private key is missing or malformed")
	case !ValidWireGuardKey(c.ServerPublicKey):
		return "", fmt.Errorf("the server public key is missing: no captured command returns it, so it has to be supplied (see wireguard_client.go)")
	case strings.TrimSpace(c.Address) == "":
		return "", fmt.Errorf("the peer has no tunnel address")
	case strings.TrimSpace(c.Endpoint) == "":
		return "", fmt.Errorf("the endpoint is empty: a client needs a host and a port to dial")
	}

	allowed := "0.0.0.0/0"
	if len(c.AllowedIPs) > 0 {
		clean := make([]string, 0, len(c.AllowedIPs))
		for _, a := range c.AllowedIPs {
			if a = strings.TrimSpace(a); a != "" {
				clean = append(clean, a)
			}
		}
		if len(clean) > 0 {
			sort.Strings(clean)
			allowed = strings.Join(clean, ", ")
		}
	}

	var b strings.Builder
	if name := strings.TrimSpace(c.PeerName); name != "" {
		fmt.Fprintf(&b, "# %s\n", name)
	}
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", strings.TrimSpace(c.PrivateKey))
	fmt.Fprintf(&b, "Address = %s\n", strings.TrimSpace(c.Address))
	if dns := strings.TrimSpace(c.DNS); dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", strings.TrimSpace(c.ServerPublicKey))
	fmt.Fprintf(&b, "Endpoint = %s\n", strings.TrimSpace(c.Endpoint))
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Keepalive)
	}
	return b.String(), nil
}

// WireGuardEndpoint assembles what a client dials from the server block.
func WireGuardEndpoint(s WireGuardServer) string {
	host := strings.TrimSpace(s.Interface)
	if host == "" || s.ListenPort < 1 {
		return ""
	}
	return fmt.Sprintf("%s:%d", host, s.ListenPort)
}
