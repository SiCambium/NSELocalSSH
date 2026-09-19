package nse

import (
	"os"
	"strings"
	"testing"
)

func TestParseGatewayPrecedence(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_full.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := ParseGatewayPrecedence(string(raw))
	if got["ip"]["static"] != 1 || got["ip"]["dhcpc"] != 2 || got["ip"]["pppoe"] != 3 {
		t.Errorf("ip precedence = %v, want static 1, dhcpc 2, pppoe 3", got["ip"])
	}
	// The v6 list carries "auto-config/dhcpc" as one token, slash and all.
	if got["ipv6"]["auto-config/dhcpc"] != 2 {
		t.Errorf("ipv6 precedence = %v, want auto-config/dhcpc at 2", got["ipv6"])
	}
}

// Two sources claiming the same rank is not something to send and let
// the device arbitrate: whichever it picks becomes the route off the
// site, and nobody asked for a coin toss.
func TestGatewayLinesRefusesAmbiguousOrdering(t *testing.T) {
	lines, msg := gatewayLines(gatewayRequest{Family: "ip", Order: map[string]int{"static": 1, "dhcpc": 1}})
	if msg == "" {
		t.Fatalf("a duplicate rank was accepted: %v", lines)
	}
	if !strings.Contains(msg, "rank 1") {
		t.Errorf("message %q should name the clashing rank", msg)
	}
}

func TestGatewayLinesValidation(t *testing.T) {
	for _, tc := range []struct{ name, want string; req gatewayRequest }{
		{"bad family", "ip or ipv6", gatewayRequest{Family: "ipx", Order: map[string]int{"static": 1}}},
		{"empty", "no ordering", gatewayRequest{Family: "ip"}},
		{"unknown source", "not a gateway source", gatewayRequest{Family: "ip", Order: map[string]int{"carrier-pigeon": 1}}},
		{"rank zero", "between 1 and", gatewayRequest{Family: "ip", Order: map[string]int{"static": 0}}},
		{"v4 source on v6", "not a gateway source", gatewayRequest{Family: "ipv6", Order: map[string]int{"dhcpc": 1}}},
	} {
		lines, msg := gatewayLines(tc.req)
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%s: message %q, want it to mention %q", tc.name, msg, tc.want)
		}
		if len(lines) != 0 {
			t.Errorf("%s: refused request still produced %v", tc.name, lines)
		}
	}
}

func TestGatewayLinesRendersTheConfirmedForm(t *testing.T) {
	lines, msg := gatewayLines(gatewayRequest{Family: "ip", Order: map[string]int{"static": 2, "dhcpc": 1}})
	if msg != "" {
		t.Fatalf("refused: %s", msg)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"ip gw-source-precedence dhcpc 1", "ip gw-source-precedence static 2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}
