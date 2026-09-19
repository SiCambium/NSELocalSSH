package nse

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestParseManagementServices(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_full.txt")
	if err != nil {
		t.Fatal(err)
	}
	state, ports, idle := parseManagementServices(string(raw))

	// From the capture: ssh, http, https present as bare lines; telnet
	// and radius-auth present as negated lines.
	for name, want := range map[string]bool{
		"ssh": true, "http": true, "https": true, "telnet": false, "radius-auth": false,
	} {
		if state[name] != want {
			t.Errorf("%s = %v, want %v", name, state[name], want)
		}
	}
	if ports["https"] != 443 || ports["http"] != 80 {
		t.Errorf("ports = %v, want https 443 and http 80", ports)
	}
	if idle != 300 {
		t.Errorf("ssh idle-timeout = %d, want 300", idle)
	}
}

func TestManagementServiceLines(t *testing.T) {
	if got := managementServiceLine("https", true); got != "management https" {
		t.Errorf("enable = %q", got)
	}
	if got := managementServiceLine("telnet", false); got != "no management telnet" {
		t.Errorf("disable = %q", got)
	}
	if got := managementPortLine("https", 8443); got != "management https port 8443" {
		t.Errorf("port = %q", got)
	}
	if got := managementSSHIdleTimeoutLine(600); got != "management ssh idle-timeout 600" {
		t.Errorf("idle = %q", got)
	}
}

// The rollback pre-image has to be able to find whichever of the two
// forms the device currently prints, so a toggle claims both.
func TestManagementKeysClaimBothForms(t *testing.T) {
	got := managementKeys([]string{"no management telnet"})
	if len(got) != 2 || got[0] != "management telnet" || got[1] != "no management telnet" {
		t.Errorf("keys = %v", got)
	}
}

func TestServicesLinesValidation(t *testing.T) {
	yes, no := true, false
	p80, pBad := 80, 0
	tooShort, ok := 5, 600
	for _, tc := range []struct {
		name string
		req  servicesRequest
		want string // substring of the expected refusal, "" means accepted
	}{
		{"unknown service", servicesRequest{Action: "toggle", Service: "gopher", Enable: &yes}, "unknown service"},
		{"no state", servicesRequest{Action: "toggle", Service: "https"}, "no state"},
		{"disabling ssh", servicesRequest{Action: "toggle", Service: "ssh", Enable: &no}, "SSH only"},
		{"enabling ssh is fine", servicesRequest{Action: "toggle", Service: "ssh", Enable: &yes}, ""},
		{"port on telnet", servicesRequest{Action: "port", Service: "telnet", Port: &p80}, "no port setting"},
		{"port zero", servicesRequest{Action: "port", Service: "https", Port: &pBad}, "between 1 and 65535"},
		{"timeout too short", servicesRequest{Action: "ssh_idle_timeout", Seconds: &tooShort}, "between 60"},
		{"timeout fine", servicesRequest{Action: "ssh_idle_timeout", Seconds: &ok}, ""},
		{"unknown action", servicesRequest{Action: "reboot"}, "unknown action"},
	} {
		lines, msg := servicesLines(tc.req)
		if tc.want == "" {
			if msg != "" || len(lines) == 0 {
				t.Errorf("%s: refused with %q", tc.name, msg)
			}
			continue
		}
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%s: message %q, want it to mention %q", tc.name, msg, tc.want)
		}
		if len(lines) != 0 {
			t.Errorf("%s: a refused request still produced lines %v", tc.name, lines)
		}
	}
}

func TestServicesBlocksCrossOrigin(t *testing.T) {
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	req := httptest.NewRequest(http.MethodPost, "/api/config/services",
		strings.NewReader(`{"action":"toggle","service":"telnet","enable":true}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigServices(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
