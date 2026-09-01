package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigThreatBlocksCrossOrigin(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/threat", strings.NewReader(`{"action":"enable","enable":true}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigThreat(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigThreatRejectsUnknownAction(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/threat", strings.NewReader(`{"action":"delete_everything"}`))
	rec := httptest.NewRecorder()
	s.handleConfigThreat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigThreatModeRejectsInvalid(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/threat", strings.NewReader(`{"action":"mode","mode":"bogus"}`))
	rec := httptest.NewRecorder()
	s.handleConfigThreat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigThreatRuleSetRequiresValue(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/threat", strings.NewReader(`{"action":"rule_set"}`))
	rec := httptest.NewRecorder()
	s.handleConfigThreat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigThreatRuleTypeRejectsUnknownValue(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/threat", strings.NewReader(`{"action":"rule_type","rule_type":"emerging-threats-open"}`))
	rec := httptest.NewRecorder()
	s.handleConfigThreat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigThreatRuleTypeAcceptsAllFourConfirmedValues(t *testing.T) {
	s := testConfigServer(t)
	for _, rt := range []string{"snort-community", "snort-vrt", "et-open", "et-pro"} {
		req := httptest.NewRequest(http.MethodPost, "/api/config/threat", strings.NewReader(`{"action":"rule_type","rule_type":"`+rt+`"}`))
		rec := httptest.NewRecorder()
		s.handleConfigThreat(rec, req)
		// SkipConnect means the actual SSH apply fails with a 502 further
		// down; what this test guards is that the value itself clears
		// validation instead of being rejected as unknown (400).
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("rule_type %q was rejected as invalid: %s", rt, rec.Body.String())
		}
	}
}

func TestConfigThreatRuleSetRejectsUnknownValue(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/threat", strings.NewReader(`{"action":"rule_set","rule_set":"strict"}`))
	rec := httptest.NewRecorder()
	s.handleConfigThreat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigThreatOinkcodeRequiresCode(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/threat", strings.NewReader(`{"action":"oinkcode"}`))
	rec := httptest.NewRecorder()
	s.handleConfigThreat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigThreatAutoUpdateRequiresEnable(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/threat", strings.NewReader(`{"action":"auto_update"}`))
	rec := httptest.NewRecorder()
	s.handleConfigThreat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
