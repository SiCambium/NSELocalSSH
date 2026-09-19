package nse

import (
	"testing"
	"time"
)

// Verbatim shapes from a live NSE3000 on 2.3-r6, including the keepalive
// and per-packet lines that share the log and must be ignored.
const wanlbCapture = `{"Interface":"eth0","Module":"utm","Package":"interfacehealthchecker","level":"debug","msg":"Ping stats for 192.168.50.1: {0 758.168µs 1.226734ms 8.406285ms}\n","time":"2026-09-19T11:29:36-03:00"}
{"Interface":"eth1","Module":"utm","Package":"interfacehealthchecker","level":"debug","msg":"Ping stats for 1.1.1.1: {0 21.443417ms 52.545039ms 243.228697ms}\n","time":"2026-09-19T11:29:35-03:00"}
{"level":"debug","msg":"Keeping alive","time":"2026-09-19T11:29:08-03:00"}
{"Host":"8.8.8.8","Interface":"eth1","Module":"utm","Package":"pingtools","level":"debug","msg":"26 bytes from 8.8.8.8: icmp_seq=7740 time=46.297548ms ttl=117 src=192.168.1.184 psrc=192.168.1.184\n","time":"2026-09-19T11:27:14-03:00"}
not json at all
`

func TestParseWANLBLatency(t *testing.T) {
	got := ParseWANLBLatency(wanlbCapture)
	if len(got) != 2 {
		t.Fatalf("got %d samples, want the 2 health-checker summaries (keepalive, per-packet and rubbish lines skipped): %+v", len(got), got)
	}

	// Oldest first: the device prints newest first, a series wants the
	// other order.
	if !got[0].At.Before(got[1].At) {
		t.Errorf("samples are not oldest-first: %v then %v", got[0].At, got[1].At)
	}

	pub := got[0]
	if pub.Host != "1.1.1.1" {
		t.Fatalf("first sample host = %q, want 1.1.1.1", pub.Host)
	}
	if pub.MinMs != 21.443417 || pub.AvgMs != 52.545039 || pub.MaxMs != 243.228697 {
		t.Errorf("min/avg/max = %v/%v/%v, want 21.443417/52.545039/243.228697", pub.MinMs, pub.AvgMs, pub.MaxMs)
	}
	// The log is written with the kernel's names; every other series in
	// the app uses the CLI's.
	if pub.Iface != "eth2" {
		t.Errorf("interface = %q, want the CLI name eth2 for kernel eth1", pub.Iface)
	}

	// Sub-millisecond durations carry the micro sign and must not be read
	// as milliseconds: 758.168µs is 0.758ms, not 758ms.
	lan := got[1]
	if lan.MinMs > 1 {
		t.Errorf("758.168µs parsed as %v ms; want well under 1", lan.MinMs)
	}
	if lan.Iface != "eth1" {
		t.Errorf("interface = %q, want the CLI name eth1 for kernel eth0", lan.Iface)
	}
	if want := time.Date(2026, 9, 19, 11, 29, 36, 0, lan.At.Location()); !lan.At.Equal(want) {
		t.Errorf("timestamp = %v, want %v", lan.At, want)
	}
}

func TestParseWANLBLatencyIgnoresRubbish(t *testing.T) {
	for _, raw := range []string{
		"",
		"%Error processing cli command",
		`{"level":"debug","msg":"Keeping alive","time":"2026-09-19T11:29:08-03:00"}`,
		// Right package, unparseable summary: skipped, never guessed at.
		`{"Interface":"eth0","Package":"interfacehealthchecker","msg":"Ping stats for x: broken\n","time":"2026-09-19T11:29:36-03:00"}`,
		// Right shape, unusable timestamp.
		`{"Interface":"eth0","Package":"interfacehealthchecker","msg":"Ping stats for 1.1.1.1: {0 1ms 2ms 3ms}\n","time":"yesterday"}`,
	} {
		if got := ParseWANLBLatency(raw); len(got) != 0 {
			t.Errorf("ParseWANLBLatency(%q) returned %+v, want nothing", raw, got)
		}
	}
}
