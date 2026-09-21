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

// The whole arrangement is judged together, because none of these
// entries means anything on its own. Every rejection here is a state the
// device must never be asked to hold.
func TestConfigWANLoadBalanceRejectsBadSets(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"shares add up to more than 100", `{"action":"load_balance","links":[{"port":1,"mode":"shared","percent":100},{"port":2,"mode":"shared","percent":50}]}`},
		{"nothing carries traffic", `{"action":"load_balance","links":[{"port":1,"mode":"backup","priority":0},{"port":2,"mode":"disabled"}]}`},
		{"empty", `{"action":"load_balance","links":[]}`},
		{"duplicate port", `{"action":"load_balance","links":[{"port":1,"mode":"shared","percent":50},{"port":1,"mode":"shared","percent":50}]}`},
		{"percent out of range", `{"action":"load_balance","links":[{"port":1,"mode":"shared","percent":150}]}`},
		{"priority out of range", `{"action":"load_balance","links":[{"port":1,"mode":"shared","percent":100},{"port":2,"mode":"backup","priority":99}]}`},
		{"unknown mode", `{"action":"load_balance","links":[{"port":1,"mode":"primary","percent":100}]}`},
		{"missing port", `{"action":"load_balance","links":[{"mode":"shared","percent":100}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testConfigServer(t)
			req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			s.handleConfigWAN(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// A whole arrangement carries no port of its own, so it has to survive
// the single-port guard every other WAN action depends on. Reaching the
// device, and failing there offline, is the proof that it did.
func TestConfigWANLoadBalanceAcceptsWholeArrangement(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"load_balance","links":[` +
		`{"port":2,"mode":"shared","percent":40},` +
		`{"port":1,"mode":"shared","percent":60},` +
		`{"port":3,"mode":"backup","priority":1},` +
		`{"port":4,"mode":"disabled"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("valid arrangement rejected: %s", rec.Body.String())
	}
}

// Shares that leave headroom are a ratio the device divides exactly as
// written, so they are accepted; only exceeding 100 is refused.
func TestConfigWANLoadBalanceAcceptsSharesUnderOneHundred(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan",
		strings.NewReader(`{"action":"load_balance","links":[{"port":1,"mode":"shared","percent":60},{"port":2,"mode":"shared","percent":30}]}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("90%% total rejected: %s", rec.Body.String())
	}
}

// One link carrying everything is the ordinary single-WAN case, not an
// unbalanced set.
func TestConfigWANLoadBalanceAcceptsLoneLink(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/wan",
		strings.NewReader(`{"action":"load_balance","links":[{"port":1,"mode":"shared","percent":100}]}`))
	rec := httptest.NewRecorder()
	s.handleConfigWAN(rec, req)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("lone link rejected: %s", rec.Body.String())
	}
}
