package nse

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A capture shaped like the reference tree, with the PSK lines present so
// the test can prove they are not read back.
const ipsecCapture = `show config
!
site-to-site-vpn
 bypass-lan
 vpn ipsec 1
  name branch-office
  ike-version ikev2
  role initiator
  dead-peer-detection interval 120
  remote-address 203.0.113.9
  remote-subnets 10.2.0.0/24
  local-subnets 10.1.0.0/24
  remote-psk $crypt$1$SHOULD_NOT_BE_READ
  local-psk $crypt$1$SHOULD_NOT_BE_READ
  ike phase 1
   encryption aes192 aes128-gcm16
   integrity sha256
   dh-group 15
   key-lifetime 4
   exit
  ike phase 2
   encryption aes192
   integrity sha256
   pfs dh-group 15
   key-lifetime 4
   exit
  exit
 exit
!
`

func TestParseIPsecTunnels(t *testing.T) {
	got := ParseIPsecTunnels(ipsecCapture)
	if len(got) != 1 {
		t.Fatalf("tunnels = %d, want 1: %+v", len(got), got)
	}
	tun := got[0]
	if tun.Index != 1 || tun.Name != "branch-office" {
		t.Errorf("tunnel = %+v", tun)
	}
	if tun.IKEVersion != "ikev2" || tun.Role != "initiator" {
		t.Errorf("ike/role = %q/%q", tun.IKEVersion, tun.Role)
	}
	if tun.RemoteAddress != "203.0.113.9" || tun.DPDInterval != 120 {
		t.Errorf("remote/dpd = %q/%d", tun.RemoteAddress, tun.DPDInterval)
	}
	if len(tun.Phase1.Encryption) != 2 || tun.Phase1.DHGroup != 15 {
		t.Errorf("phase 1 = %+v", tun.Phase1)
	}
	if !tun.Phase2.PFS || tun.Phase2.DHGroup != 15 {
		t.Errorf("phase 2 = %+v, want PFS with group 15", tun.Phase2)
	}
}

// The pre-shared keys are the tunnel's only authentication. This package
// writes credentials and never models them for reading, so they must be
// absent from the parsed tunnel rather than merely redacted.
func TestParseIPsecTunnelsNeverReadsThePSKs(t *testing.T) {
	got := ParseIPsecTunnels(ipsecCapture)
	if len(got) != 1 {
		t.Fatal("fixture did not parse")
	}
	if got[0].RemotePSK != "" || got[0].LocalPSK != "" {
		t.Errorf("a PSK was read out of the config: %q / %q", got[0].RemotePSK, got[0].LocalPSK)
	}
}

func TestParseIPsecTunnelsOnADeviceWithout(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_full.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := ParseIPsecTunnels(string(raw)); len(got) != 0 {
		t.Errorf("a device with no tunnels reported %+v", got)
	}
}

func postIPsec(t *testing.T, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	req := httptest.NewRequest(http.MethodPost, "/api/config/ipsec", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	s.handleConfigIPsec(rec, req)
	return rec
}

func TestIPsecRejectsBadInputBeforeTheDevice(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no psk", `{"action":"tunnel_save","tunnel":{"index":1,"name":"a","ike_version":"ikev2","role":"initiator","remote_address":"1.2.3.4","remote_subnets":"10.2.0.0/24","local_subnets":"10.1.0.0/24","phase1":{"encryption":["aes256"],"integrity":"sha256","dh_group":15,"key_lifetime":4},"phase2":{"encryption":["aes256"],"integrity":"sha256","dh_group":15,"key_lifetime":4}}}`, "pre-shared keys are required"},
		{"delete with no index", `{"action":"tunnel_delete"}`, "no tunnel given"},
		{"unknown action", `{"action":"nope"}`, "unknown action"},
	} {
		rec := postIPsec(t, tc.body, "http://127.0.0.1:8080")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d, want 400 (%s)", tc.name, rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: body %s, want %q", tc.name, rec.Body.String(), tc.want)
		}
	}
}

func TestIPsecBlocksCrossOrigin(t *testing.T) {
	rec := postIPsec(t, `{"action":"tunnel_delete","index":1}`, "http://evil.example")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestParseDynDNSProviders(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_full.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := ParseDynDNSProviders(string(raw))
	if len(got) == 0 {
		t.Skip("this capture has no dynamic DNS provider list")
	}
	if got[0].Provider == "" {
		t.Errorf("provider not read: %+v", got[0])
	}
}

func TestDynDNSLines(t *testing.T) {
	got := strings.Join(DynDNSProviderLines(DynDNSProvider{ID: 1, Provider: "noip", ServerName: "dynupdate.no-ip.com"}), "\n")
	for _, want := range []string{"ip dns dynamic services-list 1", " provider noip", " server-name dynupdate.no-ip.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	attach := strings.Join(DynDNSAttachLines(1, 1), "\n")
	if !strings.Contains(attach, "dynamic-dns service-id 1") || !strings.Contains(attach, "interface eth 1") {
		t.Errorf("attach = %q", attach)
	}
}
