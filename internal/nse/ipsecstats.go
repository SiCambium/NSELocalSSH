package nse

import (
	"regexp"
	"strconv"
	"strings"
)

// IPsec SA statistics come from `show site-to-site-vpn statistics <name|all>`,
// the only view of SA state this CLI exposes (bare `show site-to-site-vpn` is
// rejected; the `statistics` subcommand is mandatory). See
// NSE3000-CLI-REFERENCE.md for how that was established.
//
// **This is a snapshot refreshed roughly every 5 minutes, not a live read.**
// `service show debug-logs vpn` IS live, so the two can disagree by up to five
// minutes: a tunnel that just came up still reads as absent here, one that just
// dropped still reads as installed. Anything that consults both must treat the
// log as authoritative and say which source is stale — the same trap
// `service show cloud-json-config` set, where a ~7-minute-old snapshot made a
// successful change look failed.
//
// The record shape, per the device's documented output:
//
//	<Name> : <IKE_STATE>, <n>                      <- note SPACE before colon
//	local  <ip>[<port>]
//	remote <ip>[<port>]
//	<IKE proposal>                                 <- AES_CBC-256/HMAC_SHA2_256_128/...
//	established <N>s ago
//	<Name>: <CHILD_STATE>, <mode>, ESP:<proposal>  <- note NO space before colon
//	installed <N>s ago, rekeying in <M>s
//	in   <bytes> bytes   <packets> packets
//	out  <bytes> bytes   <packets> packets
//	local subnets :  <subnet>                      <- space before colon
//	remote subnets:  <subnet>                      <- no space before colon
//
// Records are separated by a 45-dash rule, but the rule is not reliable as a
// delimiter: the first record follows one and the last may have none. Records
// are therefore started by the IKE-header regex and dash rules are skipped.

var (
	// ikeSAHeaderRE matches the IKE SA line. The " : " (space-colon-space) and
	// the trailing ", <n>" are what distinguish it from the child header.
	ikeSAHeaderRE = regexp.MustCompile(`^(\S.*?) : ([A-Z_]+), (\d+)\s*$`)

	// childSAHeaderRE matches the Child SA line. Anchoring on ", <MODE>, ESP:"
	// is what keeps it from also matching the IKE header — a bare
	// "^(\S.*?): " does match "Name : ESTABLISHED, 2", because the lazy group
	// simply absorbs the name plus its trailing space.
	childSAHeaderRE = regexp.MustCompile(`^(\S.*?): ([A-Z_]+), ([A-Z_]+), ESP:(\S*)\s*$`)

	// endpointRE matches `local  1.2.3.4[500]` / `remote 5.6.7.8[4500]`.
	endpointRE = regexp.MustCompile(`^(local|remote)\s+(\S+?)\[(\d+)\]\s*$`)

	// establishedRE allows an EMPTY duration: a CONNECTING tunnel prints
	// "established s ago" with no number at all.
	establishedRE = regexp.MustCompile(`^established\s+(\d*)s ago\s*$`)

	// installedRE likewise; rekey may be absent.
	installedRE = regexp.MustCompile(`^installed\s+(\d*)s ago(?:, rekeying in\s+(\d*)s)?\s*$`)

	// counterRE matches `in   152350 bytes   1456 packets`. Runs of spaces are
	// the separators.
	counterRE = regexp.MustCompile(`^(in|out)\s+(\d+) bytes\s+(\d+) packets\s*$`)

	// subnetsRE covers both spellings: "local subnets :" has a space before the
	// colon and "remote subnets:" does not.
	subnetsRE = regexp.MustCompile(`^(local|remote) subnets\s*:\s*(.*?)\s*$`)

	// dashRuleRE is the record separator. Length is not pinned to 45 so a
	// firmware that changes it does not silently break record splitting.
	dashRuleRE = regexp.MustCompile(`^-{5,}\s*$`)
)

// s2sStatsCommandPrefix is the command these records come from, minus its
// mandatory <name|all> argument.
const s2sStatsCommandPrefix = "show site-to-site-vpn statistics"

// IKE and Child SA states as the device spells them.
const (
	IKEEstablished  = "ESTABLISHED"
	IKEConnecting   = "CONNECTING"
	ChildInstalled  = "INSTALLED"
	ChildTerminated = "TERMINATED"
)

// IPsecSAStats is one tunnel's record.
//
// The duration fields are pointers because the device prints an empty value
// for a CONNECTING tunnel ("established s ago"), and "unknown" is not the same
// answer as "0 seconds ago" — one means the tunnel never came up, the other
// means it came up this instant.
type IPsecSAStats struct {
	Name string `json:"name"`

	IKEState  string `json:"ike_state"`  // ESTABLISHED | CONNECTING
	IKENumber int    `json:"ike_number"` // the trailing ", <n>"

	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`

	// NATT is inferred from the port: 4500 is UDP-encapsulated, 500 is not.
	NATT bool `json:"nat_t"`

	IKEProposal    string `json:"ike_proposal,omitempty"` // "-///" while CONNECTING
	EstablishedAgo *int   `json:"established_ago,omitempty"`

	// A tunnel can be CONNECTING at the IKE layer while still showing a stale
	// TERMINATED child, so ChildState is independent of IKEState and may be
	// empty when no child record was printed.
	ChildState   string `json:"child_state,omitempty"` // INSTALLED | TERMINATED
	ChildMode    string `json:"child_mode,omitempty"`  // TUNNEL
	ESPProposal  string `json:"esp_proposal,omitempty"`
	InstalledAgo *int   `json:"installed_ago,omitempty"`
	RekeyIn      *int   `json:"rekey_in,omitempty"`

	InBytes    int64 `json:"in_bytes"`
	InPackets  int64 `json:"in_packets"`
	OutBytes   int64 `json:"out_bytes"`
	OutPackets int64 `json:"out_packets"`

	LocalSubnets  []string `json:"local_subnets"`
	RemoteSubnets []string `json:"remote_subnets"`
}

// Established reports whether the IKE SA is up.
func (s IPsecSAStats) Established() bool { return s.IKEState == IKEEstablished }

// ChildInstalled reports whether a Child SA is installed — the question the
// diagnosis playbook's root node asks.
func (s IPsecSAStats) ChildSAInstalled() bool { return s.ChildState == ChildInstalled }

// OneWayTraffic reports traffic arriving but none leaving, or vice versa. This
// is the asymmetric-traffic signal: counters that increment in only one
// direction mean the SA is up but return traffic is not making it back.
func (s IPsecSAStats) OneWayTraffic() bool {
	return (s.InBytes > 0) != (s.OutBytes > 0)
}

// ParseS2SStatistics parses `show site-to-site-vpn statistics <name|all>`.
//
// An empty body is a real answer meaning "no established SA", not a failure —
// against a tunnel that has never come up the device prints nothing at all
// between the echoed command and the prompt. Callers must not conflate that
// with a command that errored: doing so turns "cannot tell" into a confident
// "the tunnel is down".
func ParseS2SStatistics(raw string) []IPsecSAStats {
	out := []IPsecSAStats{}
	var cur *IPsecSAStats

	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}

	// The command prefix is enough: stripCLI matches the echoed line with
	// HasPrefix, so it covers both "statistics all" and "statistics <name>".
	for _, line := range linesOf(raw, s2sStatsCommandPrefix) {
		trimmed := strings.TrimRight(line, " \t")
		if strings.TrimSpace(trimmed) == "" || dashRuleRE.MatchString(trimmed) {
			continue
		}

		// A new IKE header ends the previous record. Checked before the child
		// header because the child pattern is the looser of the two.
		if m := ikeSAHeaderRE.FindStringSubmatch(trimmed); m != nil {
			flush()
			n, _ := strconv.Atoi(m[3])
			cur = &IPsecSAStats{
				Name:          strings.TrimSpace(m[1]),
				IKEState:      m[2],
				IKENumber:     n,
				LocalSubnets:  []string{},
				RemoteSubnets: []string{},
			}
			continue
		}
		if cur == nil {
			continue // preamble (the echoed command) or unrecognised text
		}

		if m := childSAHeaderRE.FindStringSubmatch(trimmed); m != nil {
			cur.ChildState, cur.ChildMode, cur.ESPProposal = m[2], m[3], m[4]
			continue
		}
		if m := endpointRE.FindStringSubmatch(trimmed); m != nil {
			port, _ := strconv.Atoi(m[3])
			if m[1] == "local" {
				cur.LocalAddr, cur.LocalPort = m[2], port
			} else {
				cur.RemoteAddr, cur.RemotePort = m[2], port
			}
			// Either endpoint on 4500 means UDP encapsulation is in use.
			if port == 4500 {
				cur.NATT = true
			}
			continue
		}
		if m := establishedRE.FindStringSubmatch(trimmed); m != nil {
			cur.EstablishedAgo = optionalInt(m[1])
			continue
		}
		if m := installedRE.FindStringSubmatch(trimmed); m != nil {
			cur.InstalledAgo = optionalInt(m[1])
			cur.RekeyIn = optionalInt(m[2])
			continue
		}
		if m := counterRE.FindStringSubmatch(trimmed); m != nil {
			b, _ := strconv.ParseInt(m[2], 10, 64)
			p, _ := strconv.ParseInt(m[3], 10, 64)
			if m[1] == "in" {
				cur.InBytes, cur.InPackets = b, p
			} else {
				cur.OutBytes, cur.OutPackets = b, p
			}
			continue
		}
		if m := subnetsRE.FindStringSubmatch(trimmed); m != nil {
			vals := splitSubnets(m[2])
			if m[1] == "local" {
				cur.LocalSubnets = append(cur.LocalSubnets, vals...)
			} else {
				cur.RemoteSubnets = append(cur.RemoteSubnets, vals...)
			}
			continue
		}

		// Anything left between the endpoints and "established" is the IKE
		// crypto proposal. "-///" is the CONNECTING placeholder; it is kept
		// verbatim rather than blanked, because a caller distinguishing "no
		// proposal negotiated" from "field absent" needs to see it.
		if cur.IKEProposal == "" && cur.ChildState == "" {
			cur.IKEProposal = strings.TrimSpace(trimmed)
		}
	}
	flush()
	return out
}

// optionalInt returns nil for an empty capture, so "no value printed" stays
// distinguishable from a printed zero.
func optionalInt(s string) *int {
	if s == "" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &n
}

// splitSubnets handles one or several subnets on a line. Splitting on commas
// and whitespace only — never on "-", because tunnel names and ranges both use
// it and the same helper shape gets copied around.
func splitSubnets(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
