package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testConfigServer(t *testing.T) *Server {
	t.Helper()
	return &Server{Client: NewClient(Config{}), SkipConnect: true}
}

func TestConfigNetworkBlocksCrossOrigin(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"vlan_ip","vlan_id":1,"ip":"1.2.3.4","mask":"255.255.255.0"}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkRequiresVLANID(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"vlan_ip","ip":"1.2.3.4","mask":"255.255.255.0"}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigNetworkRejectsUnknownAction(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/network", strings.NewReader(`{"action":"delete_everything","vlan_id":1}`))
	rec := httptest.NewRecorder()
	s.handleConfigNetwork(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANBlocksCrossOrigin(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"ip_mode","port":1,"mode":"dhcp"}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANRequiresPort(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"ip_mode","mode":"dhcp"}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANStaticRequiresFields(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"ip_mode","port":1,"mode":"static"}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANPPPoERequiresUserAndPassword(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"ip_mode","port":1,"mode":"pppoe"}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANPPPoERejectsBadMTU(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"ip_mode","port":1,"mode":"pppoe","pppoe_user":"u","pppoe_password":"p","pppoe_mtu":100}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANConnectionHealthRejectsBadNumHostsFail(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"connection_health","port":1,"num_hosts_fail":0,"failure_detect_time":5,"ping_interval":2,"ping_timeout":2}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANConnectionHealthRejectsBadFailureDetectTime(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"connection_health","port":1,"num_hosts_fail":1,"failure_detect_time":61,"ping_interval":2,"ping_timeout":2}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANConnectionHealthRejectsBadPingInterval(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"connection_health","port":1,"num_hosts_fail":1,"failure_detect_time":5,"ping_interval":1,"ping_timeout":2}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANConnectionHealthRejectsBadPingTimeout(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"connection_health","port":1,"num_hosts_fail":1,"failure_detect_time":5,"ping_interval":2,"ping_timeout":11}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigWANConnectionHealthAcceptsValidValues(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"connection_health","port":1,"num_hosts_fail":1,"failure_detect_time":5,"ping_interval":2,"ping_timeout":2}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	// SkipConnect means the actual apply will fail against a real
	// connection, but validation must pass first (not a 400).
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("valid connection_health values rejected: code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestPPPoEStatusByPortParsesEnabledWAN(t *testing.T) {
	raw := `show config
!
interface eth 2
 type wan
 pppoe-server enable
 pppoe-server user isp-user
 pppoe-server password $crypt$1$redacted
 pppoe-server mtu 1492
 pppoe-server tcp-mss-clamp
 ip address dhcp
!
NSE-Caravan(config)# `
	status := pppoeStatusByPort(raw)
	st, ok := status[2]
	if !ok {
		t.Fatalf("expected pppoe status for port 2, got %+v", status)
	}
	if !st.Enabled || st.User != "isp-user" || st.MTU != 1492 || !st.MSSClamp {
		t.Fatalf("pppoe status = %+v", st)
	}
	if _, ok := status[1]; ok {
		t.Fatalf("port 1 has no pppoe config, should not appear")
	}
}

func TestConfigWANRejectsBadPercent(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(`{"action":"traffic_share","port":1,"percent":150}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigConfirmRejectsUnknownToken(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/confirm", strings.NewReader(`{"token":"does-not-exist"}`))
	rec := httptest.NewRecorder()
	s.handleConfigConfirm(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigConfirmBlocksCrossOrigin(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/confirm", strings.NewReader(`{"token":"x"}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigConfirm(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
