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

func TestSortedFilterRulesOrdersByNumericPrecedence(t *testing.T) {
	raw := `show config
!
filter  global-filter
  stateful
  application-control
  filter precedence 10
     unique_id 10
     rule-name rule_ten
     layer3-filter deny proto any 1.1.1.0/255.255.255.0 any 2.2.2.0/255.255.255.0 any in
     exit
  filter precedence 2
     unique_id 2
     rule-name rule_two
     layer3-filter deny proto any 1.1.1.0/255.255.255.0 any 2.2.2.0/255.255.255.0 any in
     exit
!
NSE-Caravan(config)# `
	rules := sortedFilterRules(raw)
	if len(rules) != 2 || rules[0].Name != "rule_two" || rules[1].Name != "rule_ten" {
		t.Fatalf("sortedFilterRules() = %+v, want rule_two before rule_ten (numeric, not lexical, order)", rules)
	}
}

func TestConfigFirewallFilterAddRequiresFields(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"filter_add","name":"test"}`))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallFilterAddRejectsBadRuleAction(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","src_addr":"1.1.1.0","src_mask":"255.255.255.0","dst_addr":"2.2.2.0","dst_mask":"255.255.255.0","rule_action":"reject"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallFilterAddGroupSourceRequiresGroupName(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","src_type":"group","dst_addr":"2.2.2.0","dst_mask":"255.255.255.0"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallFilterAddRejectsBadEndpointType(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","src_type":"vlan","dst_addr":"2.2.2.0","dst_mask":"255.255.255.0"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallFilterAddAcceptsGroupEndpointsForBothSides(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","src_type":"group","src_group":"Enterprise-Users","dst_type":"group","dst_group":"Guest"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	// SkipConnect means the actual SSH apply fails with a 502 further
	// down; what this test guards is that group endpoints on both sides
	// clear validation instead of being rejected as invalid input.
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("group endpoints were rejected as invalid input: %s", rec.Body.String())
	}
}

func TestConfigFirewallFilterAddAcceptsAllEndpointsForBothSides(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","src_type":"all","dst_type":"all"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	// SkipConnect means the actual SSH apply fails with a 502 further
	// down; what this test guards is that "all" endpoints on both sides
	// clear validation instead of being rejected as invalid input.
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("all endpoints were rejected as invalid input: %s", rec.Body.String())
	}
}

func TestConfigFirewallFilterAddApplicationGroupRequiresGroupName(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","rule_type":"application_group"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallFilterAddAcceptsApplicationGroup(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","rule_type":"application_group","app_group_name":"Social-Media"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	// SkipConnect means the actual SSH apply fails with a 502 further
	// down; what this test guards is that an application-group rule
	// clears validation instead of being rejected as invalid input.
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("application_group rule was rejected as invalid input: %s", rec.Body.String())
	}
}

func TestConfigFirewallFilterAddCategoryRequiresCategory(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","rule_type":"category"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallFilterAddAcceptsCategory(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","rule_type":"category","category":"Gambling"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	// SkipConnect means the actual SSH apply fails with a 502 further
	// down; what this test guards is that a category rule clears
	// validation instead of being rejected as invalid input.
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("category rule was rejected as invalid input: %s", rec.Body.String())
	}
}

func TestConfigFirewallFilterAddRejectsBadRuleType(t *testing.T) {
	s := testConfigServer(t)
	body := `{"action":"filter_add","name":"test","rule_type":"port_forward"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallFilterDeleteRequiresPrecedence(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"filter_delete"}`))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallGeoModeRequiresValidDirection(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"geo_mode","geo_direction":"sideways","geo_mode":"allow"}`))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallGeoModeRejectsUnknownMode(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"geo_mode","geo_direction":"inbound","geo_mode":"deny-all"}`))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallGeoModeAcceptsValidValues(t *testing.T) {
	s := testConfigServer(t)
	for _, mode := range []string{"allow", "block", "none"} {
		req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"geo_mode","geo_direction":"inbound","geo_mode":"`+mode+`"}`))
		rec := httptest.NewRecorder()
		s.handleConfigFirewall(rec, req)
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("mode %q was rejected as invalid: %s", mode, rec.Body.String())
		}
	}
}

func TestConfigFirewallGeoExceptionAddRequiresIPs(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"geo_exception_add","geo_direction":"outbound"}`))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigFirewallFilterMoveRequiresValidDirection(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/firewall", strings.NewReader(`{"action":"filter_move","precedence":1,"direction":"sideways"}`))
	rec := httptest.NewRecorder()
	s.handleConfigFirewall(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
