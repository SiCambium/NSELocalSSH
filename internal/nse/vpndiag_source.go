package nse

import (
	"fmt"
	"strings"
	"time"

	"nse-cli/internal/vpndiag"
)

// The playbook declares logical evidence sources named after a different
// platform's commands (swanctl_list_sas, swanctl_counters, ...). Mapping those
// names onto what this CLI can actually produce is this file's whole job, and it
// is deliberately the only environment-specific piece: the playbook JSON is
// shared with an upstream implementation and must not be forked to describe one
// device.
//
// What was established by probing a live NSE4000 (see NSE3000-CLI-REFERENCE.md):
//
//	swanctl_list_sas    -> show site-to-site-vpn statistics <name>   ~5 min stale
//	swanctl_counters    -> the same output (it carries in/out counters)
//	swanctl_list_conns  -> the vpn ipsec N stanza of show config
//	s2s_vpn_log         -> service show debug-logs vpn                LIVE
//	show_config         -> show config, sanitised
//
// There is no shell on this device, so swanctl itself is unreachable even though
// strongSwan is running.

// Timeouts are per command. `service show debug-logs vpn` returned 735 KB in
// 3.1s on the probed device, so 30s is generous rather than tight; `show config`
// is the slower of the two in practice.
const (
	vpnDiagLogTimeout    = 30 * time.Second
	vpnDiagConfigTimeout = 25 * time.Second
	vpnDiagStatsTimeout  = 25 * time.Second
)

// sshEvidenceSource implements vpndiag.EvidenceSource over the shared CLI
// session.
//
// Every read is one Run call holding the client's global mutex, so a diagnosis
// serialises behind (and blocks) the dashboard. That is why a diagnosis is
// operator-initiated and its result is cached, never polled.
type sshEvidenceSource struct {
	run func(cmd string, timeout time.Duration) (string, error)

	// cache memoises per source name within one diagnosis, because several
	// logical sources map onto the same command and each one costs an SSH
	// round-trip under the shared lock.
	cache map[string]vpndiag.SourceResult
}

func newSSHEvidenceSource(c *Client) *sshEvidenceSource {
	return &sshEvidenceSource{
		run:   c.Run,
		cache: map[string]vpndiag.SourceResult{},
	}
}

// staleSnapshotNote is attached to the SA statistics so both the operator and
// the model know the two evidence sources are not contemporaneous. The log is
// live; this snapshot is not. Without saying so, a diagnosis can silently
// reconcile a contradiction that is really just five minutes of skew.
const staleSnapshotNote = "snapshot refreshed roughly every 5 minutes, so it may lag the live log below; " +
	"where the two disagree the log is authoritative"

func (s *sshEvidenceSource) Read(name, scope string) (vpndiag.SourceResult, error) {
	key := name + "\x00" + scope
	if got, ok := s.cache[key]; ok {
		return got, nil
	}
	got, err := s.read(name, scope)
	if err != nil {
		return vpndiag.SourceResult{}, err
	}
	s.cache[key] = got
	return got, nil
}

func (s *sshEvidenceSource) read(name, scope string) (vpndiag.SourceResult, error) {
	switch name {
	case "swanctl_list_sas", "swanctl_counters":
		// One command answers both: it reports SA state and carries the in/out
		// byte and packet counters. Passing the tunnel name scopes it at the
		// device, so the result is already narrowed and the playbook's
		// swanctl-shaped block regex must not be applied on top of it.
		raw, err := s.runChecked(
			s2sStatsCommandPrefix+" "+statsArgFor(scope), vpnDiagStatsTimeout)
		if err != nil {
			return vpndiag.SourceResult{}, err
		}
		body := stripCLI(raw, s2sStatsCommandPrefix)
		if strings.TrimSpace(body) == "" {
			// Empty is a REAL answer here, not a missing source: this device
			// prints nothing at all when no SA exists. Saying "unavailable"
			// would throw away a genuine finding.
			body = "(no SA records — the device reports no established security association for this tunnel)"
		}
		return vpndiag.SourceResult{
			Text: body, Available: true, PreScoped: true, Note: staleSnapshotNote,
		}, nil

	case "swanctl_list_conns":
		// The configured connections, from config rather than from a daemon.
		raw, err := s.runChecked("show config", vpnDiagConfigTimeout)
		if err != nil {
			return vpndiag.SourceResult{}, err
		}
		stanza := ipsecStanzaFor(SanitizeCLIOutput(stripCLI(raw, "show config")), scope)
		if strings.TrimSpace(stanza) == "" {
			return vpndiag.SourceResult{
				Text:      fmt.Sprintf("(no `vpn ipsec` stanza named %q in the running config)", scope),
				Available: true, PreScoped: true,
			}, nil
		}
		return vpndiag.SourceResult{
			Text: stanza, Available: true, PreScoped: true,
			Note: "from the running config, not from the IKE daemon",
		}, nil

	case "show_config":
		raw, err := s.runChecked("show config", vpnDiagConfigTimeout)
		if err != nil {
			return vpndiag.SourceResult{}, err
		}
		// Sanitised, always. This output carries cleartext PSKs, and the state
		// it lands in is sent off the box.
		return vpndiag.SourceResult{
			Text: SanitizeCLIOutput(stripCLI(raw, "show config")), Available: true,
		}, nil

	case "s2s_vpn_log":
		raw, err := s.runChecked("service show debug-logs vpn", vpnDiagLogTimeout)
		if err != nil {
			return vpndiag.SourceResult{}, err
		}
		return vpndiag.SourceResult{
			Text: stripCLI(raw, "service show debug-logs vpn"), Available: true,
			Note: "live at the moment of reading",
		}, nil

	case "show_feature_license":
		raw, err := s.runChecked("show feature-license", vpnDiagConfigTimeout)
		if err != nil {
			return vpndiag.SourceResult{}, err
		}
		return vpndiag.SourceResult{Text: stripCLI(raw, "show feature-license"), Available: true}, nil
	}

	// Anything else the playbook asks for is genuinely unavailable — say so
	// rather than returning empty text that would read as a negative finding.
	return vpndiag.SourceResult{Available: false}, nil
}

// runChecked runs a command and turns this CLI's error-shaped output into a real
// error.
//
// Run() does not classify errors: a rejected command comes back with a nil error
// and "%Error processing cli command" as ordinary output. Feeding that into
// evidence would present an error message to the model as if it were device
// state.
func (s *sshEvidenceSource) runChecked(cmd string, timeout time.Duration) (string, error) {
	out, err := s.run(cmd, timeout)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		if cliErrorLineRE.MatchString(strings.TrimSpace(line)) {
			return "", fmt.Errorf("the device rejected %q: %s", cmd, strings.TrimSpace(line))
		}
	}
	return out, nil
}

// statsArgFor picks the statistics argument. The subcommand is mandatory and
// takes <site name | all>; an empty scope means every tunnel.
func statsArgFor(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return "all"
	}
	return scope
}

// ipsecStanzaFor cuts the `vpn ipsec N` block whose `name` leaf matches scope.
//
// The name is on a CHILD line, not the block header, so it cannot be recovered
// from a header pattern — which is exactly why the playbook's generic
// block-header enumeration cannot be used on this platform.
func ipsecStanzaFor(showConfig, scope string) string {
	blocks := ipsecStanzas(showConfig)
	if b, ok := blocks[scope]; ok {
		return b
	}
	return ""
}

// ipsecStanzas returns every `vpn ipsec N` stanza keyed by its `name` leaf.
func ipsecStanzas(showConfig string) map[string]string {
	out := map[string]string{}
	var cur []string
	name := ""
	inBlock := false

	for _, line := range strings.Split(strings.ReplaceAll(showConfig, "\r", ""), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "vpn ipsec "):
			if inBlock && name != "" {
				out[name] = strings.Join(cur, "\n")
			}
			inBlock, name, cur = true, "", []string{line}
		case inBlock && trimmed == "!":
			if name != "" {
				out[name] = strings.Join(cur, "\n")
			}
			inBlock, name, cur = false, "", nil
		case inBlock:
			cur = append(cur, line)
			if strings.HasPrefix(trimmed, "name ") {
				name = strings.TrimSpace(strings.TrimPrefix(trimmed, "name "))
			}
		}
	}
	if inBlock && name != "" {
		out[name] = strings.Join(cur, "\n")
	}
	return out
}

// IPsecTunnelNames lists the configured site-to-site tunnels by name.
//
// This is the enumeration path on this platform. The playbook's generic
// `enumerate` block reads a swanctl connection list, which does not exist here,
// so tunnel identity comes from config instead.
func IPsecTunnelNames(showConfig string) []string {
	stanzas := ipsecStanzas(showConfig)
	out := make([]string, 0, len(stanzas))
	for name := range stanzas {
		out = append(out, name)
	}
	return sortedStrings(out)
}

func sortedStrings(in []string) []string {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
	return in
}
