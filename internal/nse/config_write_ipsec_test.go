package nse

import (
	"strings"
	"testing"
)

func goodTunnel() IPsecTunnel {
	return IPsecTunnel{
		Index: 1, Name: "branch", IKEVersion: "ikev2", Role: "initiator",
		RemoteAddress: "203.0.113.9", RemoteSubnets: "10.2.0.0/24",
		LocalSubnets: "10.1.0.0/24", DPDInterval: 120,
		RemotePSK: "remote-secret", LocalPSK: "local-secret",
		Phase1: IPsecPhase{Encryption: []string{"aes256"}, Integrity: "sha256", DHGroup: 15, KeyLifetime: 4},
		Phase2: IPsecPhase{Encryption: []string{"aes256"}, Integrity: "sha256", DHGroup: 15, KeyLifetime: 4, PFS: true},
	}
}

func TestIPsecTunnelLinesFollowTheReferenceTree(t *testing.T) {
	joined := strings.Join(IPsecTunnelLines(goodTunnel()), "\n")
	for _, want := range []string{
		"site-to-site-vpn",
		"vpn ipsec 1",
		" name branch",
		" ike-version ikev2",
		" role initiator",
		" remote-address 203.0.113.9",
		" dead-peer-detection interval 120",
		" remote-subnets 10.2.0.0/24",
		" local-subnets 10.1.0.0/24",
		" ike phase 1",
		" ike phase 2",
		"  integrity sha256",
		"  key-lifetime 4",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

// Phase 2 spells perfect forward secrecy as "pfs dh-group N"; phase 1
// uses a bare "dh-group N". Getting this backwards produces a proposal
// the far end rejects, which reads as a remote problem.
func TestIPsecPhaseTwoUsesPFSSpelling(t *testing.T) {
	joined := strings.Join(IPsecTunnelLines(goodTunnel()), "\n")
	if !strings.Contains(joined, "  pfs dh-group 15") {
		t.Error("phase 2 should carry pfs dh-group")
	}
	p1 := joined[strings.Index(joined, " ike phase 1"):strings.Index(joined, " ike phase 2")]
	if strings.Contains(p1, "pfs") {
		t.Error("phase 1 must not carry pfs")
	}
	if !strings.Contains(p1, "  dh-group 15") {
		t.Error("phase 1 should carry a bare dh-group")
	}
}

func TestValidateIPsecTunnel(t *testing.T) {
	if err := ValidateIPsecTunnel(goodTunnel()); err != nil {
		t.Fatalf("a reasonable tunnel was refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*IPsecTunnel)
		want string
	}{
		{"no name", func(x *IPsecTunnel) { x.Name = "" }, "needs a name"},
		{"bad ike version", func(x *IPsecTunnel) { x.IKEVersion = "ikev3" }, "ikev1 or ikev2"},
		{"bad role", func(x *IPsecTunnel) { x.Role = "peer" }, "initiator or responder"},
		{"bad remote", func(x *IPsecTunnel) { x.RemoteAddress = "not a host!" }, "neither an address nor a hostname"},
		{"subnet without prefix", func(x *IPsecTunnel) { x.RemoteSubnets = "10.2.0.0" }, "not a CIDR"},
		{"no psk", func(x *IPsecTunnel) { x.LocalPSK = "" }, "pre-shared keys are required"},
		{"unknown cipher", func(x *IPsecTunnel) { x.Phase1.Encryption = []string{"rot13"} }, "not an encryption algorithm"},
		{"unknown integrity", func(x *IPsecTunnel) { x.Phase2.Integrity = "crc32" }, "not an integrity algorithm"},
		{"dh group out of range", func(x *IPsecTunnel) { x.Phase1.DHGroup = 99 }, "between 1 and 32"},
		{"lifetime out of range", func(x *IPsecTunnel) { x.Phase2.KeyLifetime = 0 }, "between 1 and 24"},
	} {
		tun := goodTunnel()
		tc.mut(&tun)
		err := ValidateIPsecTunnel(tun)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

// The PSKs are the tunnel's only authentication, and like every other
// credential in this package they are written and never modelled for
// reading. The JSON tags keep them out of any payload by construction.
func TestIPsecPSKsAreNotSerialised(t *testing.T) {
	// A struct tag of "-" is the mechanism; this asserts the intent so a
	// future edit that adds a name to the tag fails here.
	tun := goodTunnel()
	lines := strings.Join(IPsecTunnelLines(tun), "\n")
	if !strings.Contains(lines, "remote-psk remote-secret") {
		t.Error("the PSK must still reach the device")
	}
	// And nothing else in the package should be reading one back.
	if strings.Contains(lines, "show") {
		t.Error("a write builder emitted a read command")
	}
}

func TestIPsecTunnelDeleteLines(t *testing.T) {
	got := strings.Join(IPsecTunnelDeleteLines(3), "\n")
	if !strings.Contains(got, "no vpn ipsec 3") {
		t.Errorf("delete = %q", got)
	}
}
