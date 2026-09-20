package nse

import (
	"strings"
	"testing"
)

// The leaf spellings are irregular and came from one capture. If a
// refactor "tidies" lan-IP into lan-ip, the device stops understanding
// the rule and this catches it.
func TestPortForwardLinesMatchTheCapture(t *testing.T) {
	got := PortForwardLines(1, 1, PortForwardRule{WANPort: 9090, LANIP: "10.0.0.50", Protocol: "tcp", LANPort: 9090})
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"interface eth 1",
		"port-forward-rule 1",
		" port 9090",
		" lan-IP 10.0.0.50",
		" protocol tcp",
		" lan-port 9090",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "lan-ip") {
		t.Error("lan-IP was lower-cased; the device's own capture capitalises it")
	}
}

func TestSourceNATLinesMatchTheCapture(t *testing.T) {
	got := SourceNATLines(1, 2, SourceNATRule{LANSubnet: "10.1.0.0/24", PublicIP: "203.0.113.1-203.0.113.254"})
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"source-nat-rule 2",
		" lan-IP address 10.1.0.0/24",
		" overload disable",
		" public-IP 203.0.113.1-203.0.113.254",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

// A port-forward that publishes the wrong host is not a rejected command,
// it is a service on the internet. The checking happens before the device
// sees anything.
func TestValidatePortForwardRefusesDangerousRules(t *testing.T) {
	ok := PortForwardRule{WANPort: 443, LANIP: "192.168.1.10", Protocol: "tcp", LANPort: 443}
	if err := ValidatePortForward(ok); err != nil {
		t.Fatalf("a reasonable rule was refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		rule PortForwardRule
		want string
	}{
		{"unspecified address", PortForwardRule{WANPort: 443, LANIP: "0.0.0.0", Protocol: "tcp", LANPort: 443}, "every host"},
		{"public target", PortForwardRule{WANPort: 443, LANIP: "8.8.8.8", Protocol: "tcp", LANPort: 443}, "not a private address"},
		{"not an address", PortForwardRule{WANPort: 443, LANIP: "nope", Protocol: "tcp", LANPort: 443}, "not an IPv4"},
		{"bad protocol", PortForwardRule{WANPort: 443, LANIP: "10.0.0.1", Protocol: "icmp", LANPort: 443}, "tcp or udp"},
		{"port zero", PortForwardRule{WANPort: 0, LANIP: "10.0.0.1", Protocol: "tcp", LANPort: 443}, "between 1 and 65535"},
		{"port too high", PortForwardRule{WANPort: 443, LANIP: "10.0.0.1", Protocol: "tcp", LANPort: 70000}, "between 1 and 65535"},
	} {
		err := ValidatePortForward(tc.rule)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

func TestValidateSourceNAT(t *testing.T) {
	if err := ValidateSourceNAT(SourceNATRule{LANSubnet: "10.1.0.0/24", PublicIP: "203.0.113.5"}); err != nil {
		t.Errorf("a single public address was refused: %v", err)
	}
	if err := ValidateSourceNAT(SourceNATRule{LANSubnet: "10.1.0.0/24", PublicIP: "203.0.113.1-203.0.113.254"}); err != nil {
		t.Errorf("a range was refused: %v", err)
	}
	for _, tc := range []struct{ name string; rule SourceNATRule }{
		{"subnet without a prefix", SourceNATRule{LANSubnet: "10.1.0.0", PublicIP: "203.0.113.5"}},
		{"no public address", SourceNATRule{LANSubnet: "10.1.0.0/24"}},
		{"nonsense range", SourceNATRule{LANSubnet: "10.1.0.0/24", PublicIP: "203.0.113.1-nope"}},
	} {
		if err := ValidateSourceNAT(tc.rule); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestEthIndexOf(t *testing.T) {
	if n, err := ethIndexOf("eth3"); err != nil || n != 3 {
		t.Errorf("ethIndexOf(eth3) = %d, %v", n, err)
	}
	for _, bad := range []string{"", "eth", "ethX", "eth0abc", "../etc"} {
		if _, err := ethIndexOf(bad); err == nil {
			t.Errorf("ethIndexOf(%q) was accepted", bad)
		}
	}
}
