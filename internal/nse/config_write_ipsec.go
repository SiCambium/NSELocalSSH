package nse

import (
	"fmt"
	"net"
	"strings"
)

// Site-to-site IPsec.
//
// Until now this app could only turn the site-to-site feature on and off;
// a tunnel still had to be defined in the cloud console. That is the gap
// this closes, and it is the one place in this package where the evidence
// is weaker than usual, so it is stated up front.
//
// UNCONFIRMED, all of it. The command tree comes from
// NSE3000-CLI-REFERENCE.md, which took it from Cambium community
// material rather than from a live capture: the unit this project was
// written against has no site-to-site tunnel configured, so `show config`
// has never printed one here. What is confirmed is only that the
// `site-to-site-vpn` context exists and can be entered.
//
// Everything below is therefore written to fail loudly rather than
// quietly. The lines go through SafeApplier like every other write, which
// reports a rejected line instead of assuming success, and the whole
// block is classified as lockout risk — not because a tunnel cuts the SSH
// session, but because an unverified multi-line sub-context is exactly
// what ClassifyRisk's own comment says cannot be judged safe by
// inspection.
//
// Confirm it on a lab unit, then come back and downgrade this comment.
//
// Secrets: a tunnel has a pre-shared key at each end. They are written
// and never read back, matching how this package treats every other
// credential — nothing here ever parses a PSK out of a config.

// IPsecPhase is one half of the IKE proposal. The device prints
// encryption as a space-separated list of algorithms.
type IPsecPhase struct {
	Encryption  []string `json:"encryption"`
	Integrity   string   `json:"integrity"`
	DHGroup     int      `json:"dh_group"`
	KeyLifetime int      `json:"key_lifetime"`
	// PFS applies to phase 2 only, where the capture spells it
	// "pfs dh-group N" rather than a bare "dh-group N".
	PFS bool `json:"pfs"`
}

// IPsecTunnel is one site-to-site tunnel.
type IPsecTunnel struct {
	Index         int    `json:"index"`
	Name          string `json:"name"`
	IKEVersion    string `json:"ike_version"` // ikev1 | ikev2
	Role          string `json:"role"`        // initiator | responder
	RemoteAddress string `json:"remote_address"`
	RemoteID      string `json:"remote_id,omitempty"`
	LocalID       string `json:"local_id,omitempty"`
	RemoteSubnets string `json:"remote_subnets"`
	LocalSubnets  string `json:"local_subnets"`
	DPDInterval   int    `json:"dpd_interval,omitempty"`

	// Written, never read back.
	RemotePSK string `json:"-"`
	LocalPSK  string `json:"-"`

	Phase1 IPsecPhase `json:"phase1"`
	Phase2 IPsecPhase `json:"phase2"`
}

var ipsecIntegrity = map[string]bool{
	"sha1": true, "sha256": true, "sha384": true, "sha512": true, "md5": true,
}

// ipsecEncryption is the set seen in the reference tree. An algorithm
// outside it is refused rather than sent: a rejected proposal brings the
// tunnel down in a way that reads as a remote-end problem.
var ipsecEncryption = map[string]bool{
	"aes128": true, "aes192": true, "aes256": true,
	"aes128-gcm16": true, "aes192-gcm16": true, "aes256-gcm16": true,
	"3des": true,
}

func validateIPsecPhase(label string, p IPsecPhase) error {
	if len(p.Encryption) == 0 {
		return fmt.Errorf("%s has no encryption algorithm", label)
	}
	for _, e := range p.Encryption {
		if !ipsecEncryption[strings.ToLower(strings.TrimSpace(e))] {
			return fmt.Errorf("%s: %q is not an encryption algorithm this device is known to accept", label, e)
		}
	}
	if !ipsecIntegrity[strings.ToLower(strings.TrimSpace(p.Integrity))] {
		return fmt.Errorf("%s: %q is not an integrity algorithm", label, p.Integrity)
	}
	// Both ends must agree on the DH group or the tunnel never forms, so
	// an out-of-range value is refused here rather than negotiated away.
	if p.DHGroup < 1 || p.DHGroup > 32 {
		return fmt.Errorf("%s: the DH group must be between 1 and 32", label)
	}
	if p.KeyLifetime < 1 || p.KeyLifetime > 24 {
		return fmt.Errorf("%s: the key lifetime must be between 1 and 24 hours", label)
	}
	return nil
}

// ValidateIPsecTunnel checks what can be checked without the device.
func ValidateIPsecTunnel(t IPsecTunnel) error {
	if t.Index < 1 {
		return fmt.Errorf("the tunnel needs an index, starting at 1")
	}
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("the tunnel needs a name")
	}
	switch strings.ToLower(t.IKEVersion) {
	case "ikev1", "ikev2":
	default:
		return fmt.Errorf("the IKE version must be ikev1 or ikev2, not %q", t.IKEVersion)
	}
	switch strings.ToLower(t.Role) {
	case "initiator", "responder":
	default:
		return fmt.Errorf("the role must be initiator or responder, not %q", t.Role)
	}
	if ip := net.ParseIP(strings.TrimSpace(t.RemoteAddress)); ip == nil && !validHostname(t.RemoteAddress) {
		return fmt.Errorf("the remote address %q is neither an address nor a hostname", t.RemoteAddress)
	}
	if err := validateSubnetList("remote subnets", t.RemoteSubnets); err != nil {
		return err
	}
	if err := validateSubnetList("local subnets", t.LocalSubnets); err != nil {
		return err
	}
	// A pre-shared key is the tunnel's only authentication. An empty one
	// is not a tunnel with no password, it is a tunnel that will not come
	// up, and the failure surfaces at the remote end.
	if strings.TrimSpace(t.RemotePSK) == "" || strings.TrimSpace(t.LocalPSK) == "" {
		return fmt.Errorf("both pre-shared keys are required")
	}
	if err := validateIPsecPhase("IKE phase 1", t.Phase1); err != nil {
		return err
	}
	return validateIPsecPhase("IKE phase 2", t.Phase2)
}

func validateSubnetList(label, list string) error {
	parts := strings.Split(strings.TrimSpace(list), ",")
	if len(parts) == 0 || strings.TrimSpace(list) == "" {
		return fmt.Errorf("%s: at least one subnet is required", label)
	}
	for _, p := range parts {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(p)); err != nil {
			return fmt.Errorf("%s: %q is not a CIDR such as 10.1.0.0/24", label, strings.TrimSpace(p))
		}
	}
	return nil
}

func ipsecPhaseLines(phase int, p IPsecPhase) []string {
	group := fmt.Sprintf("  dh-group %d", p.DHGroup)
	if phase == 2 && p.PFS {
		group = fmt.Sprintf("  pfs dh-group %d", p.DHGroup)
	}
	return []string{
		fmt.Sprintf(" ike phase %d", phase),
		"  encryption " + strings.Join(p.Encryption, " "),
		"  integrity " + strings.ToLower(strings.TrimSpace(p.Integrity)),
		group,
		fmt.Sprintf("  key-lifetime %d", p.KeyLifetime),
		"  exit",
	}
}

// IPsecTunnelLines renders one tunnel inside the site-to-site context.
func IPsecTunnelLines(t IPsecTunnel) []string {
	lines := []string{
		"site-to-site-vpn",
		fmt.Sprintf("vpn ipsec %d", t.Index),
		" name " + strings.TrimSpace(t.Name),
		" ike-version " + strings.ToLower(t.IKEVersion),
		" role " + strings.ToLower(t.Role),
		" remote-address " + strings.TrimSpace(t.RemoteAddress),
	}
	if id := strings.TrimSpace(t.RemoteID); id != "" {
		lines = append(lines, " remote-id "+id)
	}
	if id := strings.TrimSpace(t.LocalID); id != "" {
		lines = append(lines, " local-id "+id)
	}
	if t.DPDInterval > 0 {
		lines = append(lines, fmt.Sprintf(" dead-peer-detection interval %d", t.DPDInterval))
	}
	lines = append(lines,
		" remote-subnets "+strings.TrimSpace(t.RemoteSubnets),
		" local-subnets "+strings.TrimSpace(t.LocalSubnets),
		" remote-psk "+strings.TrimSpace(t.RemotePSK),
		" local-psk "+strings.TrimSpace(t.LocalPSK),
	)
	lines = append(lines, ipsecPhaseLines(1, t.Phase1)...)
	lines = append(lines, ipsecPhaseLines(2, t.Phase2)...)
	return append(lines, " exit", "exit")
}

// IPsecTunnelDeleteLines removes a tunnel by index. UNCONFIRMED, like the
// rest of this file, and doubly so: no capture shows a removal.
func IPsecTunnelDeleteLines(index int) []string {
	return []string{
		"site-to-site-vpn",
		fmt.Sprintf(" no vpn ipsec %d", index),
		"exit",
	}
}
