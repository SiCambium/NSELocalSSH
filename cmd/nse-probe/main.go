// Command nse-probe runs a list of read-only commands against a live device
// and dumps what each one returns. A throwaway dev tool, not part of the
// shipped app — edit the list for whatever question you are answering.
//
// Everything here must be a `show` or `service show` form. This tool exists to
// establish what a device actually supports, so it is pointed at production
// hardware; nothing in the list may change configuration.
//
// Current question: which CLI command, if any, reports IPsec Child-SA state and
// SA byte counters? The on-box VPN diagnosis playbook
// (jev-vpn-debug-onbox/playbooks/s2s-vpn-troubleshooting.tree.json) asks for
// `swanctl --list-sas` / `--counters`, but this CLI has no shell to run swanctl
// from, so an NSE-CLI equivalent has to be found or ruled out. A confirmed
// absence is a useful result: it is what justifies the playbook's root node
// escalating rather than guessing.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"nse-cli/internal/nse"
)

// probe is one candidate command. Short timeouts on the speculative ones: a
// command the CLI does not recognise answers immediately, so only the commands
// expected to produce real output need a long one.
type probe struct {
	cmd     string
	timeout time.Duration
}

func main() {
	cfg := nse.LoadConfig()
	fmt.Fprintf(os.Stderr, "probing %s as %s (read-only)\n", cfg.Addr(), cfg.User)

	probes := []probe{
		// Confirmed to exist — baseline, and the log source the playbook needs.
		{"show vpn", 20 * time.Second},
		{"show vpn-sessions ipsec", 20 * time.Second},
		{"service show debug-logs vpn", 25 * time.Second},

		// Child-SA state candidates.
		{"show ipsec", 10 * time.Second},
		{"show ipsec sa", 10 * time.Second},
		{"show ipsec status", 10 * time.Second},
		{"show ipsec tunnel", 10 * time.Second},
		{"show crypto ipsec sa", 10 * time.Second},
		{"show vpn ipsec", 10 * time.Second},
		{"show vpn ipsec sa", 10 * time.Second},
		{"show site-to-site-vpn", 10 * time.Second},
		{"show site-to-site", 10 * time.Second},
		{"show s2s", 10 * time.Second},
		{"show tunnel", 10 * time.Second},
		{"show tunnels", 10 * time.Second},

		// The `service show <x>` family is the CLI's curated window onto Linux
		// state; if swanctl output is exposed anywhere, it is most likely here.
		{"service show ipsec", 15 * time.Second},
		{"service show ipsec sa", 15 * time.Second},
		{"service show swanctl", 15 * time.Second},
		{"service show strongswan", 15 * time.Second},
		{"service show charon", 15 * time.Second},
		{"service show vpn", 15 * time.Second},
		{"service show xfrm", 15 * time.Second},
		{"service show ip xfrm state", 15 * time.Second},

		// Counter candidates for n_traffic_ok.
		{"show vpn statistics", 10 * time.Second},
		{"show ipsec statistics", 10 * time.Second},
		{"service show ip -s link", 15 * time.Second},
	}

	type result struct {
		cmd   string
		bytes int
		state string // ok | rejected | error
		first string
	}
	var results []result

	for _, p := range probes {
		fmt.Fprintf(os.Stderr, "\n########## %s ##########\n", p.cmd)
		out, err := c(cfg).Run(p.cmd, p.timeout)
		text := strings.ReplaceAll(out, "\r", "")
		body := stripEcho(text, p.cmd)

		r := result{cmd: p.cmd, bytes: len(strings.TrimSpace(body)), state: "ok"}
		switch {
		case err != nil:
			r.state = "error"
			r.first = err.Error()
			fmt.Fprintf(os.Stderr, "ERR %v\n", err)
		case looksRejected(body):
			r.state = "rejected"
			r.first = firstMeaningful(body)
		default:
			r.first = firstMeaningful(body)
		}
		results = append(results, r)

		shown := text
		if len(shown) > 3000 {
			shown = shown[:3000] + "\n...[truncated]...\n"
		}
		fmt.Print(shown, "\n")
	}

	// Summary last, on stderr, so it survives redirecting stdout to a capture.
	fmt.Fprintf(os.Stderr, "\n\n================ SUMMARY ================\n")
	sort.SliceStable(results, func(i, j int) bool { return results[i].state < results[j].state })
	for _, r := range results {
		fmt.Fprintf(os.Stderr, "%-9s %5db  %-30s %s\n", r.state, r.bytes, r.cmd, trunc(r.first, 70))
	}
}

// client is built once and reused: the CLI keeps one shell, and reconnecting
// per command would be slower and noisier.
var shared *nse.Client

func c(cfg nse.Config) *nse.Client {
	if shared == nil {
		shared = nse.NewClient(cfg)
	}
	return shared
}

// looksRejected spots this CLI's error shapes. Run() does not classify them --
// it returns a nil error and the error text as ordinary output -- so a caller
// that does not check ends up treating "%Error processing cli command" as data.
func looksRejected(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "%") ||
			strings.HasPrefix(l, "Invalid ") ||
			strings.HasPrefix(l, "Error ") ||
			strings.Contains(l, "Unknown command") ||
			strings.Contains(l, "Incomplete command") {
			return true
		}
	}
	return false
}

// stripEcho drops the echoed command and the trailing prompt line, which is
// what internal/nse does before parsing. Duplicated rather than exported from
// there: this is a throwaway tool and does not justify widening that API.
func stripEcho(text, cmd string) string {
	var keep []string
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || t == cmd || strings.HasSuffix(t, ")#") || strings.HasSuffix(t, ")# "+cmd) {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

func firstMeaningful(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return l
		}
	}
	return ""
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
