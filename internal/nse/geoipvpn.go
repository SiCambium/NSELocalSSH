package nse

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Geo-IP interaction with site-to-site IPsec.
//
// This exists because the S2S diagnosis playbook's geo-ip node ("is decrypted
// inner traffic being dropped by the Geo-IP firewall?") is mostly a
// *deterministic* question on this platform, not a judgement call, and answering
// it from config beats asking a model to guess.
//
// The mechanism, per the playbook's candidate D10: NSE uses policy-based IPsec,
// so there is no virtual tunnel interface. After xfrm decrypts an ESP packet the
// inner packet's ingress interface is still the physical WAN, so if the
// geoip_firewall forward chain does not exempt IPsec-decrypted traffic, the
// inner RFC1918 source address fails the country-IP check and is dropped. The
// documented workaround is to add the tunnel's remote subnets to the Geo-IP
// inbound allowlist.
//
// Two of candidate D10's three declared evidence sources (`ip_xfrm_policy` and
// `nft (geoip)`) need a shell this CLI does not provide. `show config` is the
// third and the only reachable one — which is enough for the precondition,
// though not to prove a drop actually happened.
//
// Geo-ip lines are absent entirely from `show config` when the feature has never
// been configured; ParseGeoIP already defaults both directions to "none", the
// same absence-is-the-default convention as `overload` and per-VLAN port-scan.

// GeoIPModeNone is the mode string meaning no country filtering is applied.
const GeoIPModeNone = "none"

// GeoIPVPNRisk reports whether geo-ip filtering *could* be dropping a tunnel's
// decrypted inbound traffic, with a line of evidence text explaining why.
//
// It deliberately answers the precondition, not the outcome. Proving traffic was
// actually dropped needs the nft counters, which are unreachable here — so a
// true result means "this is possible and worth checking", never "this is
// happening". Reason is written to be read by a human and by a model.
type GeoIPVPNRisk struct {
	// Possible is true only when inbound filtering is active AND at least one
	// of the tunnel's remote subnets is outside the allowlist.
	Possible bool `json:"possible"`

	// Mode is the inbound geo-ip mode as configured ("none" when unset).
	Mode string `json:"mode"`

	// Unprotected lists the tunnel's remote subnets that no allowlist entry
	// covers. These are the ones the documented workaround would add.
	Unprotected []string `json:"unprotected_subnets"`

	// Reason is a single evidence line stating the finding and how it was
	// reached, suitable for inclusion verbatim in assembled evidence.
	Reason string `json:"reason"`
}

// GeoIPCouldDropTunnel evaluates the geo-ip precondition for one tunnel.
//
// remoteSubnets are the tunnel's far-side subnets — the source addresses of
// decrypted inbound traffic, which is what the country check would reject.
func GeoIPCouldDropTunnel(inbound GeoIPDirection, remoteSubnets []string) GeoIPVPNRisk {
	mode := strings.TrimSpace(inbound.Mode)
	if mode == "" {
		mode = GeoIPModeNone
	}
	risk := GeoIPVPNRisk{Mode: mode, Unprotected: []string{}}

	if mode == GeoIPModeNone {
		risk.Reason = "geo-ip inbound filtering is not configured (mode none), so the " +
			"forward chain applies no country check and cannot drop decrypted tunnel traffic"
		return risk
	}

	for _, subnet := range remoteSubnets {
		if s := strings.TrimSpace(subnet); s != "" && !geoIPAllowlistCovers(inbound.Exceptions, s) {
			risk.Unprotected = append(risk.Unprotected, s)
		}
	}

	if len(risk.Unprotected) == 0 {
		risk.Reason = fmt.Sprintf(
			"geo-ip inbound filtering is active (mode %s) but every remote subnet of this "+
				"tunnel is covered by the geo-ip allowlist, so decrypted traffic is exempt", mode)
		return risk
	}

	risk.Possible = true
	risk.Reason = fmt.Sprintf(
		"geo-ip inbound filtering is active (mode %s, countries %s) and these remote subnets "+
			"of this tunnel are NOT in the geo-ip allowlist: %s. Decrypted inbound traffic from "+
			"them carries an RFC1918 source with no country, so the forward chain's country "+
			"check can drop it. This is the precondition only — confirming an actual drop needs "+
			"the nft counters, which this CLI cannot read",
		mode, joinOrNone(inbound.Countries), strings.Join(risk.Unprotected, ", "))
	return risk
}

func joinOrNone(v []string) string {
	if len(v) == 0 {
		return "(none listed)"
	}
	return strings.Join(v, ",")
}

// geoIPAllowlistCovers reports whether any allowlist range fully contains the
// given subnet or address. Partial overlap is deliberately NOT treated as
// covered: a subnet half inside the allowlist still has hosts the country check
// would reject, and reporting it safe would hide a real cause.
func geoIPAllowlistCovers(ranges []IPRange, subnet string) bool {
	lo, hi, ok := ipv4SpanOf(subnet)
	if !ok {
		// Unparseable input is not claimed to be covered — the honest answer
		// for something we cannot evaluate is "still at risk".
		return false
	}
	for _, r := range ranges {
		rl, rok := ipv4ToUint(r.StartIP)
		rh, hok := ipv4ToUint(r.EndIP)
		if !rok || !hok {
			continue
		}
		if rl > rh {
			rl, rh = rh, rl
		}
		if lo >= rl && hi <= rh {
			return true
		}
	}
	return false
}

// ipv4SpanOf returns the inclusive first and last address of a CIDR, or the
// single address twice for a bare IP.
func ipv4SpanOf(s string) (lo, hi uint32, ok bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		_, network, err := net.ParseCIDR(s)
		if err != nil || network.IP.To4() == nil {
			return 0, 0, false
		}
		base := binary.BigEndian.Uint32(network.IP.To4())
		mask := binary.BigEndian.Uint32(net.IP(network.Mask).To4())
		return base & mask, (base & mask) | ^mask, true
	}
	v, good := ipv4ToUint(s)
	return v, v, good
}

func ipv4ToUint(s string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip.To4()), true
}
