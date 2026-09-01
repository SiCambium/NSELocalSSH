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

func TestConfigDNSFilterModeAcceptsDisabled(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"filter_mode","filter_mode":"disabled"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("filter_mode=disabled rejected as invalid input: %s", rec.Body.String())
	}
}

func TestConfigDNSLocalHostAddRequiresFields(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"local_host_add","domain":"nas.lan"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDNSLocalHostAddAcceptsValid(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"local_host_add","domain":"nas.lan","ip":"172.21.1.50"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("local_host_add rejected as invalid input: %s", rec.Body.String())
	}
}

func TestConfigDNSForwardZoneAddRequiresFields(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"forward_zone_add","domain":"corp.example"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDNSBypassGroupAddRequiresGroupName(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"bypass_group_add"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDNSFilterPolicySaveRequiresIDAndName(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"filter_policy_save","id":0,"name":"Ad_Blocking"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDNSFilterPolicySaveRejectsOutOfRangeID(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"filter_policy_save","id":99,"name":"Ad_Blocking"}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDNSFilterPolicySaveGroupSourceRequiresName(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_policy_save","id":1,"name":"Ad_Blocking","deny_source_type":"group"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigDNSFilterPolicySaveAcceptsValid(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_policy_save","id":1,"name":"Ad_Blocking","safe_search":true,"deny_categories":["malware-sites","spam-urls"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("filter_policy_save rejected as invalid input: %s", rec.Body.String())
	}
}

func TestConfigDNSFilterPolicyDeleteRejectsOutOfRangeID(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/dns", strings.NewReader(`{"action":"filter_policy_delete","id":0}`))
	rec := httptest.NewRecorder()
	s.handleConfigDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
