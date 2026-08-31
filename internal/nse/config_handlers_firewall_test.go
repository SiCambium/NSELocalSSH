package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigFirewallBlocksCrossOrigin(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"dos_ip_spoof","enable":true}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallRejectsUnknownAction(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"delete_everything","enable":true}`))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestDeviceAccessPingEnabledParsesRealLine(t *testing.T) {
	raw := "show config\n!\ndevice-access allowed-service ssh\ndevice-access allowed-service ping\n!\n"
	if !deviceAccessPingEnabled(raw) {
		t.Fatal("expected ping to be detected as enabled")
	}
	if deviceAccessPingEnabled("show config\n!\nhostname foo\n!\n") {
		t.Fatal("expected ping to be detected as disabled when absent")
	}
}

func TestConfigFirewallRequiresEnable(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"dos_ip_spoof"}`))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
