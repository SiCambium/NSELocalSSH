package nse

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const restoreCapture = `show config
!
hostname NSE-TEST
timezone Europe/London
ntp server time.google.com
!
interface eth 1
 type wan
 wan-name wan1
 ip address dhcp
!
interface vlan 1
 management-access all
 ip address 172.21.0.1 255.255.0.0
 exit
!
interface vlan 30
 ip address 172.30.0.1 255.255.255.0
 exit
!
ip dhcp pool 1
 network 172.21.0.0 255.255.0.0
 default-router 172.21.0.1
!
`

func testRestoreServer() *Server {
	return &Server{Client: NewClient(Config{}), SkipConnect: true}
}

func postRestore(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()
	s.handleRestore(rec, req)
	return rec
}

// A preview must reach the device not at all. Everything it needs is in
// the capture the operator supplied.
func TestRestorePreviewSendsNothingToTheDevice(t *testing.T) {
	s := testRestoreServer()
	rec := postRestore(t, s, `{"section":"vlans","config":`+jsonString(restoreCapture)+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"applied":false`) {
		t.Error("a preview must report applied:false")
	}
	for _, want := range []string{"interface vlan 1", "interface vlan 30", "management-access all"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview is missing %q", want)
		}
	}
	// A DHCP pool is not a VLAN interface and must not ride along.
	if strings.Contains(body, "ip dhcp pool 1") {
		t.Error("the vlans section pulled in a DHCP pool")
	}
}

// Keys come from the supplied capture, so a device with two VLANs
// restores two. Nothing assumes a fixed range, the same rule that governs
// physical ports.
func TestRestoreKeysComeFromTheCapture(t *testing.T) {
	sec, _ := restoreSection("vlans")
	got := keysIn(restoreCapture, sec)
	if len(got) != 2 || got[0] != "interface vlan 1" || got[1] != "interface vlan 30" {
		t.Errorf("keys = %v, want the two VLANs present in the capture", got)
	}
	dhcp, _ := restoreSection("dhcp")
	if got := keysIn(restoreCapture, dhcp); len(got) != 1 {
		t.Errorf("dhcp keys = %v, want exactly the one pool", got)
	}
}

func TestRestoreRejectsBadInput(t *testing.T) {
	s := testRestoreServer()
	for _, tc := range []struct{ name, body string }{
		{"unknown section", `{"section":"nope","config":"hostname x"}`},
		{"no config", `{"section":"vlans","config":""}`},
		{"nothing matching", `{"section":"vlans","config":"hostname only\n"}`},
	} {
		if rec := postRestore(t, s, tc.body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d, want 400 (%s)", tc.name, rec.Code, rec.Body.String())
		}
	}
}

// Replaying a saved config is a write, and a write that can cut off the
// site. Another page does not get to start one.
func TestRestoreBlocksCrossOrigin(t *testing.T) {
	s := testRestoreServer()
	req := httptest.NewRequest(http.MethodPost, "/api/restore",
		strings.NewReader(`{"section":"vlans","config":"interface vlan 1\n exit\n","apply":true}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleRestore(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

// The sections a caller may name are a closed list carrying the risk each
// one inherits, so a UI cannot invent one.
func TestRestoreSectionsAreDeclaredWithTheirRisk(t *testing.T) {
	s := testRestoreServer()
	req := httptest.NewRequest(http.MethodGet, "/api/restore", nil)
	rec := httptest.NewRecorder()
	s.handleRestore(rec, req)
	body := rec.Body.String()
	for _, want := range []string{`"id":"vlans"`, `"id":"lan-ports"`, `"risk":"lockout"`} {
		if !strings.Contains(body, want) {
			t.Errorf("section list is missing %q: %s", want, body)
		}
	}
}

// Encoding a string as JSON is a solved problem. Hand-rolling the
// escaping here produced invalid JSON and a failure that said nothing
// about the code under test.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
