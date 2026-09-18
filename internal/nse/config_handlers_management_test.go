package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigManagementBlocksCrossOrigin(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/management", strings.NewReader(`{"action":"hostname","hostname":"NSE-New"}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigManagement(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigManagementRejectsUnknownAction(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/management", strings.NewReader(`{"action":"delete_everything"}`))
	rec := httptest.NewRecorder()
	s.handleConfigManagement(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigManagementHostnameRequiresValue(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/management", strings.NewReader(`{"action":"hostname"}`))
	rec := httptest.NewRecorder()
	s.handleConfigManagement(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigManagementTimezoneRequiresValue(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/management", strings.NewReader(`{"action":"timezone"}`))
	rec := httptest.NewRecorder()
	s.handleConfigManagement(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigManagementSyslogRequiresAllFields(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/management", strings.NewReader(`{"action":"syslog","syslog_ip":"172.22.0.9"}`))
	rec := httptest.NewRecorder()
	s.handleConfigManagement(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigManagementSyslogRejectsBadSeverity(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/management", strings.NewReader(`{"action":"syslog","syslog_ip":"172.22.0.9","syslog_port":"514","severity":9}`))
	rec := httptest.NewRecorder()
	s.handleConfigManagement(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigManagementRejectsBadMethod(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/config/management", nil)
	rec := httptest.NewRecorder()
	s.handleConfigManagement(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

// TestCambiumRemoteLine pins both forms. The positive line is CONFIRMED
// from a live `show config`; the negated one is what the device expects to
// delink.
func TestCambiumRemoteLine(t *testing.T) {
	if got := CambiumRemoteLine(true); got != "management cambium-remote" {
		t.Errorf("enable = %q", got)
	}
	if got := CambiumRemoteLine(false); got != "no management cambium-remote" {
		t.Errorf("disable = %q", got)
	}
}

// TestConfigManagementCambiumRemoteRequiresEnable guards against a
// delink-by-omission: a request that forgets the field must not fall
// through to a default.
func TestConfigManagementCambiumRemoteRequiresEnable(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/management",
		strings.NewReader(`{"action":"cambium_remote"}`))
	rec := httptest.NewRecorder()
	s.handleConfigManagement(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

// TestCambiumRemoteReadFromShowConfig covers the read side, including the
// distinction that matters: "management cambium-remote
// validate-server-cert" is a sub-option, not the link itself, so a device
// carrying only that must not read as linked.
func TestCambiumRemoteReadFromShowConfig(t *testing.T) {
	linked := CloudConfigFromShowConfig(`management https
management cambium-remote
management cambium-remote validate-server-cert
hostname NSE-Test
interface vlan 1
 ip address 10.0.0.1 255.255.255.0
!`)
	if !linked.CambiumRemote {
		t.Error("a device with the bare leaf should read as linked")
	}

	delinked := CloudConfigFromShowConfig(`management https
management cambium-remote validate-server-cert
hostname NSE-Test
interface vlan 1
 ip address 10.0.0.1 255.255.255.0
!`)
	if delinked.CambiumRemote {
		t.Error("validate-server-cert alone is a sub-option, not the link")
	}

	none := CloudConfigFromShowConfig(`management https
hostname NSE-Test
interface vlan 1
 ip address 10.0.0.1 255.255.255.0
!`)
	if none.CambiumRemote {
		t.Error("no leaf at all should read as delinked")
	}
}

// TestCambiumRemoteAppliesAndSaves pins the behaviour the operator asked
// for: delinking is not a lockout risk, so it applies directly and the
// save rides along in the same sequence rather than waiting on a confirm.
func TestCambiumRemoteAppliesAndSaves(t *testing.T) {
	if got := ClassifyRisk("management"); got != RiskNone {
		t.Fatalf("ClassifyRisk(management) = %v, want RiskNone so the change saves immediately", got)
	}
	block := ConfigBlock{Name: "management-cambium_remote",
		Lines: []string{CambiumRemoteLine(false)}, Risk: ClassifyRisk("management")}
	sent := append(append([]string{}, block.Lines...), SaveConfigLine)
	want := []string{"no management cambium-remote", "save"}
	if len(sent) != len(want) || sent[0] != want[0] || sent[1] != want[1] {
		t.Errorf("sequence = %v, want %v", sent, want)
	}
}
