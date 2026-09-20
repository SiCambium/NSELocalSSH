package nse

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Latency history from the device's own monitor-host pings.
//
// The WAN load balancer pings each interface's monitor hosts continuously
// to decide whether that link is alive, and `service show debug-logs
// wanlb` prints what it measured. Reading that is strictly better than
// this app issuing its own pings: it costs no extra ICMP, it does not
// hold the shared SSH lock for seconds at a time, and it arrives with
// history the app was not running for.
//
// Two record shapes appear in that log. `pingtools` prints one line per
// packet; `interfacehealthchecker` prints the summary the balancer
// actually acts on, once per host per cycle. The summary is what is
// parsed here, because it is both cheaper to read and closer to the
// decision being made.
//
// CONFIRMED from a live NSE3000 on 2.3-r6:
//
//	{"Interface":"eth1","Package":"interfacehealthchecker","level":"debug",
//	 "msg":"Ping stats for 1.1.1.1: {0 21.443417ms 52.545039ms 243.228697ms}\n",
//	 "time":"2026-09-19T11:29:35-03:00"}
//
// The three durations are ascending in every captured sample, on both a
// LAN-local gateway (758µs / 1.2ms / 8.4ms) and a public resolver, so
// they are read as min, mean and max. The leading integer is UNCONFIRMED:
// it has been 0 in every line captured so far, which is consistent with a
// lost-packet count but proves nothing, so it is carried as Lost and
// nothing is decided from it.
var wanlbPingStatsRE = regexp.MustCompile(
	`^Ping stats for ([^:]+): \{(\d+) (\S+) (\S+) (\S+)\}`)

// LatencySample is one monitor host as the device measured it.
type LatencySample struct {
	At    time.Time `json:"at"`
	Iface string    `json:"iface"` // CLI name, translated from the kernel's
	Host  string    `json:"host"`
	MinMs float64   `json:"min_ms"`
	AvgMs float64   `json:"avg_ms"`
	MaxMs float64   `json:"max_ms"`
	Lost  int       `json:"lost"`
}

type wanlbLine struct {
	Interface string `json:"Interface"`
	Package   string `json:"Package"`
	Msg       string `json:"msg"`
	Time      string `json:"time"`
}

// ParseWANLBLatency pulls every monitor-host summary out of a wanlb debug
// log. Lines it does not recognise — keepalives, per-packet noise,
// anything a future firmware adds — are skipped rather than guessed at.
//
// Samples come back oldest first, which is the order a time series wants
// and the reverse of how the device prints them.
func ParseWANLBLatency(raw string) []LatencySample {
	var out []LatencySample
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec wanlbLine
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Package != "interfacehealthchecker" {
			continue
		}
		m := wanlbPingStatsRE.FindStringSubmatch(strings.TrimSpace(rec.Msg))
		if m == nil {
			continue
		}
		at, err := time.Parse(time.RFC3339, rec.Time)
		if err != nil {
			continue
		}
		min, ok1 := durationMs(m[3])
		avg, ok2 := durationMs(m[4])
		max, ok3 := durationMs(m[5])
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		lost, _ := strconv.Atoi(m[2])

		// The log carries the kernel's interface name; everything the
		// operator sees, and every other series in the history store,
		// uses the CLI's. eth0 in the log is eth1 on the box.
		iface := cliEthFromLinux(rec.Interface)
		if iface == "" {
			iface = rec.Interface
		}
		out = append(out, LatencySample{
			At: at, Iface: iface, Host: m[1],
			MinMs: min, AvgMs: avg, MaxMs: max, Lost: lost,
		})
	}
	// Oldest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// durationMs parses a Go duration string ("758.168µs", "21.443417ms")
// into milliseconds. The device writes these with Go's own formatter, so
// Go's own parser is the right reader for them.
func durationMs(s string) (float64, bool) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false
	}
	return float64(d) / float64(time.Millisecond), true
}
