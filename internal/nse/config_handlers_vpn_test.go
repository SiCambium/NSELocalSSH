package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigVPNBlocksCrossOrigin(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(`{"action":"tailscale_enable","enable":true}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigVPN(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigVPNRejectsUnknownAction(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(`{"action":"delete_everything"}`))
	rec := httptest.NewRecorder()
	s.handleConfigVPN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigVPNTailscaleEnableRequiresValue(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(`{"action":"tailscale_enable"}`))
	rec := httptest.NewRecorder()
	s.handleConfigVPN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigVPNRadiusClientCreateRequiresFields(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(`{"action":"radius_client_create","name":"Demo"}`))
	rec := httptest.NewRecorder()
	s.handleConfigVPN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigVPNRadiusClientEditRequiresID(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"radius_client_edit","name":"Demo","secret":"s3cret","address":"172.22.0.0","prefix_length":16}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigVPN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigVPNRadiusClientEditRequiresFields(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(`{"action":"radius_client_edit","id":1,"name":"Demo"}`))
	rec := httptest.NewRecorder()
	s.handleConfigVPN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigVPNRadiusClientEditAcceptsValid(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"radius_client_edit","id":1,"name":"Demo","secret":"s3cret","address":"172.22.0.0","prefix_length":16}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigVPN(rec, req)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("radius_client_edit rejected as invalid input: %s", rec.Body.String())
	}
}

func TestConfigVPNRadiusClientDeleteRequiresID(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(`{"action":"radius_client_delete"}`))
	rec := httptest.NewRecorder()
	s.handleConfigVPN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
