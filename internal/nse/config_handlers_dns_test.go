package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigDNSBlocksCrossOrigin(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"dns_override","enable":true}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDNSRejectsUnknownAction(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"delete_everything"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDNSFilterModeRejectsInvalid(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"filter_mode","filter_mode":"bogus"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDNSOverrideRequiresEnable(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"dns_override"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestDNSFilterModeParsesConfigBlock(t *testing.T) {
	raw := "dns-server\n filter-mode filtering\n no dns-override\n exit\n"
	if got, want := dnsFilterMode(raw), "filtering"; got != want {
		t.Fatalf("dnsFilterMode() = %q, want %q", got, want)
	}
}

func TestDNSFilterModeEmptyWhenNoBlock(t *testing.T) {
	if got := dnsFilterMode("hostname foo\n"); got != "" {
		t.Fatalf("dnsFilterMode() = %q, want empty", got)
	}
}
