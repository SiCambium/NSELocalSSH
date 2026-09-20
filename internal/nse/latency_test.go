package nse

import "testing"

func TestPingAverageMs(t *testing.T) {
	raw := `ping 192.168.100.1
PING 192.168.100.1 (192.168.100.1): 56 data bytes
64 bytes from 192.168.100.1: seq=0 ttl=63 time=1.431 ms

--- 192.168.100.1 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 1.333/1.422/1.502 ms
`
	got, ok := PingAverageMs(raw)
	if !ok {
		t.Fatal("a summary carrying min/avg/max should yield an average")
	}
	if got != 1.422 {
		t.Errorf("average = %v, want the middle figure 1.422", got)
	}
}

// A host that answered nothing prints no min/avg/max line at all. That
// has to read as "no measurement", never as zero milliseconds, which
// would chart an unreachable host as the fastest one on the page.
func TestPingAverageMsTotalLossIsNotZero(t *testing.T) {
	raw := `ping 1.1.1.1
PING 1.1.1.1 (1.1.1.1): 56 data bytes

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 0 packets received, 100% packet loss
`
	if got, ok := PingAverageMs(raw); ok {
		t.Errorf("total loss reported an average of %v; want no measurement", got)
	}
}

func TestPingAverageMsIgnoresRubbish(t *testing.T) {
	for _, raw := range []string{"", "% Invalid arguments", "ping: bad address"} {
		if _, ok := PingAverageMs(raw); ok {
			t.Errorf("PingAverageMs(%q) claimed a measurement", raw)
		}
	}
}
