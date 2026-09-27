package nse

import (
	"regexp"
	"testing"
)

// The fixtures below are built from the device's documented output format, not
// captured from a live box: the only NSE reachable during development had a
// tunnel that never established, so it only ever printed the empty case (see
// TestParseS2SStatisticsEmptyIsNoSA). They should be replaced with a real
// redacted capture the first time this runs against an established tunnel.
//
// Two colon conventions carry the record structure and are easy to "tidy" into
// a bug, so they are asserted explicitly:
//
//	IKE header:   "Name : STATE, n"      space-colon-space
//	Child header: "Name: STATE, MODE, …" no space before the colon
const twoTunnels = `show site-to-site-vpn statistics all
---------------------------------------------
Papercut_SCDC : ESTABLISHED, 2
local  203.0.113.4[4500]
remote 198.51.100.9[4500]
AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072
established 86213s ago
Papercut_SCDC: INSTALLED, TUNNEL, ESP:AES_GCM_16-256
installed 3417s ago, rekeying in 24783s
in   152350 bytes   1456 packets
out  98211 bytes   1102 packets
local subnets :  10.1.3.0/24
remote subnets:  10.20.0.0/16
---------------------------------------------
BeaverVillage-50E<->MainOffice : CONNECTING, 7
local  203.0.113.4[500]
remote 198.51.100.77[500]
-///
established s ago
BeaverVillage-50E<->MainOffice: TERMINATED, TUNNEL, ESP:
in   0 bytes   0 packets
out  0 bytes   0 packets
local subnets :  192.168.200.0/24
remote subnets:  172.16.0.0/12`

func TestParseS2SStatisticsRecordStructure(t *testing.T) {
	got := ParseS2SStatistics(twoTunnels)
	if len(got) != 2 {
		t.Fatalf("parsed %d records, want 2: %+v", len(got), got)
	}

	a := got[0]
	if a.Name != "Papercut_SCDC" {
		t.Errorf("name = %q", a.Name)
	}
	if a.IKEState != IKEEstablished || a.IKENumber != 2 {
		t.Errorf("ike = %q/%d, want ESTABLISHED/2", a.IKEState, a.IKENumber)
	}
	if a.LocalAddr != "203.0.113.4" || a.LocalPort != 4500 {
		t.Errorf("local = %q[%d]", a.LocalAddr, a.LocalPort)
	}
	if a.RemoteAddr != "198.51.100.9" || a.RemotePort != 4500 {
		t.Errorf("remote = %q[%d]", a.RemoteAddr, a.RemotePort)
	}
	// Port 4500 means UDP encapsulation; 500 means none.
	if !a.NATT {
		t.Error("port 4500 on both ends must be read as NAT-T")
	}
	if a.IKEProposal != "AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072" {
		t.Errorf("ike proposal = %q", a.IKEProposal)
	}
	if a.EstablishedAgo == nil || *a.EstablishedAgo != 86213 {
		t.Errorf("established ago = %v", a.EstablishedAgo)
	}
	if a.ChildState != ChildInstalled || a.ChildMode != "TUNNEL" {
		t.Errorf("child = %q/%q", a.ChildState, a.ChildMode)
	}
	if a.ESPProposal != "AES_GCM_16-256" {
		t.Errorf("esp = %q", a.ESPProposal)
	}
	if a.InstalledAgo == nil || *a.InstalledAgo != 3417 {
		t.Errorf("installed ago = %v", a.InstalledAgo)
	}
	if a.RekeyIn == nil || *a.RekeyIn != 24783 {
		t.Errorf("rekey in = %v", a.RekeyIn)
	}
	// Runs of spaces separate the counter fields.
	if a.InBytes != 152350 || a.InPackets != 1456 || a.OutBytes != 98211 || a.OutPackets != 1102 {
		t.Errorf("counters = in %d/%d out %d/%d", a.InBytes, a.InPackets, a.OutBytes, a.OutPackets)
	}
	// "local subnets :" has a space before the colon, "remote subnets:" does not.
	if len(a.LocalSubnets) != 1 || a.LocalSubnets[0] != "10.1.3.0/24" {
		t.Errorf("local subnets = %q", a.LocalSubnets)
	}
	if len(a.RemoteSubnets) != 1 || a.RemoteSubnets[0] != "10.20.0.0/16" {
		t.Errorf("remote subnets = %q", a.RemoteSubnets)
	}
	if !a.Established() || !a.ChildSAInstalled() {
		t.Error("an ESTABLISHED/INSTALLED record must report as up")
	}
}

// TestParseS2SStatisticsTunnelNameWithArrow covers a name containing "<->" and
// a hyphen. Splitting a record on "-" would shred both the name and the dash
// rule detection.
func TestParseS2SStatisticsTunnelNameWithArrow(t *testing.T) {
	got := ParseS2SStatistics(twoTunnels)
	b := got[1]
	if b.Name != "BeaverVillage-50E<->MainOffice" {
		t.Fatalf("name = %q, want the full name including <-> and the hyphen", b.Name)
	}
	if b.LocalPort != 500 || b.NATT {
		t.Errorf("port 500 must not be read as NAT-T (port=%d natt=%v)", b.LocalPort, b.NATT)
	}
}

// TestParseS2SStatisticsConnectingPlaceholders covers the CONNECTING case: the
// crypto line is "-///" and the duration is printed with NO number at all
// ("established s ago"). A nil duration must stay nil — "unknown" and "0
// seconds ago" are different answers, one meaning the tunnel never came up and
// the other that it came up this instant.
func TestParseS2SStatisticsConnectingPlaceholders(t *testing.T) {
	b := ParseS2SStatistics(twoTunnels)[1]
	if b.IKEState != IKEConnecting {
		t.Errorf("ike state = %q, want CONNECTING", b.IKEState)
	}
	if b.EstablishedAgo != nil {
		t.Errorf("established ago = %v, want nil — the device printed no number", *b.EstablishedAgo)
	}
	if b.IKEProposal != "-///" {
		t.Errorf("ike proposal = %q, want the literal -/// placeholder kept", b.IKEProposal)
	}
	// An IKE SA that is only CONNECTING can still carry a stale TERMINATED
	// child, so the two states are independent.
	if b.ChildState != ChildTerminated {
		t.Errorf("child state = %q, want TERMINATED alongside a CONNECTING IKE SA", b.ChildState)
	}
	if b.ESPProposal != "" {
		t.Errorf("esp proposal = %q, want empty", b.ESPProposal)
	}
	if b.Established() || b.ChildSAInstalled() {
		t.Error("a CONNECTING/TERMINATED record must not report as up")
	}
}

// TestParseS2SStatisticsEmptyIsNoSA pins the one case observed live. Against a
// tunnel that had never established the device printed nothing between the
// echoed command and the prompt — no header, no "no SAs" line. That empty body
// is a real answer ("no SA"), and a caller that treats it as a failure turns
// "cannot tell" into a confident "the tunnel is down".
func TestParseS2SStatisticsEmptyIsNoSA(t *testing.T) {
	for _, raw := range []string{
		"show site-to-site-vpn statistics all\nNSE-00009C(config)# ",
		"show site-to-site-vpn statistics azure\n\nNSE-00009C(config)# ",
		"",
	} {
		got := ParseS2SStatistics(raw)
		if len(got) != 0 {
			t.Errorf("parsed %d records from empty output %q, want 0", len(got), raw)
		}
		if got == nil {
			t.Error("must return an empty slice, not nil, so it encodes as [] not null")
		}
	}
}

// TestParseS2SStatisticsNoTrailingRule covers the separator quirk: the first
// record follows a dash rule and the last may have none, so records have to be
// started by the IKE header rather than delimited by the rule.
func TestParseS2SStatisticsNoTrailingRule(t *testing.T) {
	if n := len(ParseS2SStatistics(twoTunnels)); n != 2 {
		t.Fatalf("got %d records", n)
	}
	// Same input with a trailing rule appended must parse identically.
	withRule := twoTunnels + "\n---------------------------------------------"
	if n := len(ParseS2SStatistics(withRule)); n != 2 {
		t.Errorf("a trailing dash rule changed the record count to %d", n)
	}
}

// TestOneWayTraffic covers the asymmetric-traffic signal: bytes in with none
// out (or the reverse) means the SA is up but return traffic is not arriving.
func TestOneWayTraffic(t *testing.T) {
	for _, tc := range []struct {
		name       string
		in, out    int64
		wantOneWay bool
	}{
		{"symmetric", 1000, 900, false},
		{"inbound only", 1000, 0, true},
		{"outbound only", 0, 1000, true},
		{"idle tunnel", 0, 0, false},
	} {
		s := IPsecSAStats{InBytes: tc.in, OutBytes: tc.out}
		if got := s.OneWayTraffic(); got != tc.wantOneWay {
			t.Errorf("%s: in=%d out=%d OneWayTraffic()=%v want %v", tc.name, tc.in, tc.out, got, tc.wantOneWay)
		}
	}
}

// TestS2SStatisticsHeadersAreDistinguished is the regression guard for the
// gotcha most likely to be "cleaned up" by someone reading one header in
// isolation: the child pattern "^(\S.*?): " also matches the IKE header,
// because the lazy group happily absorbs the name plus its trailing space.
// Only the ", <MODE>, ESP:" anchor separates them.
func TestS2SStatisticsHeadersAreDistinguished(t *testing.T) {
	ike := "Papercut_SCDC : ESTABLISHED, 2"
	child := "Papercut_SCDC: INSTALLED, TUNNEL, ESP:AES_GCM_16-256"

	if !ikeSAHeaderRE.MatchString(ike) {
		t.Error("IKE regex must match the IKE header")
	}
	if ikeSAHeaderRE.MatchString(child) {
		t.Error("IKE regex must NOT match the child header")
	}
	if !childSAHeaderRE.MatchString(child) {
		t.Error("child regex must match the child header")
	}
	if childSAHeaderRE.MatchString(ike) {
		t.Error("child regex must NOT match the IKE header — the ESP: anchor is what prevents it")
	}

	// Demonstrate the trap rather than just describing it: the obvious child
	// pattern matches the IKE header too, because the lazy group absorbs
	// "Papercut_SCDC" plus its trailing space and leaves ": " to match.
	loose := regexp.MustCompile(`^(\S.*?): `)
	if !loose.MatchString(ike) {
		t.Error("expected the loose pattern to match the IKE header — if it no longer does, " +
			"the ESP: anchor may no longer be necessary and this guard can be revisited")
	}
	if m := loose.FindStringSubmatch(ike); m != nil && m[1] != "Papercut_SCDC " {
		t.Errorf("loose pattern captured %q; the trailing space is what makes it match", m[1])
	}
}
