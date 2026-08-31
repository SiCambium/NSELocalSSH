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
