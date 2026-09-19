package nse

import (
	"net"
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

// The source restriction scopes every allowed-service, so reading it
// wrong understates how locked down a device is.
func TestParseDeviceAccessSources(t *testing.T) {
	raw := "show config\n" +
		"device-access allowed-service https\n" +
		"device-access allowed-service ssh\n" +
		"device-access ip-address 192.168.20.2-192.168.20.14\n" +
		"device-access ip-address 10.0.0.0/8\n" +
		"device-access ip-group Trusted_Users\n"
	got := parseDeviceAccessSources(raw)
	if len(got.IPAddresses) != 2 || got.IPAddresses[0] != "192.168.20.2-192.168.20.14" || got.IPAddresses[1] != "10.0.0.0/8" {
		t.Fatalf("addresses = %v", got.IPAddresses)
	}
	if len(got.IPGroups) != 1 || got.IPGroups[0] != "Trusted_Users" {
		t.Fatalf("groups = %v", got.IPGroups)
	}
	if !got.Restricted() {
		t.Fatal("expected restricted")
	}
}

// An allowed-service line is not a source line: mistaking one for the
// other would report an unrestricted device as restricted.
func TestParseDeviceAccessSourcesUnrestricted(t *testing.T) {
	got := parseDeviceAccessSources("show config\ndevice-access allowed-service ssh\ndevice-access allowed-service ping\n")
	if got.Restricted() {
		t.Fatalf("expected no restriction, got %+v", got)
	}
	// Empty slices, not nil, so the frontend always sees a list.
	if got.IPAddresses == nil || got.IPGroups == nil {
		t.Fatalf("expected empty slices, got %+v", got)
	}
}

// The guard that refuses a self-excluding restriction is only as good as
// this matcher, so each shape the device writes is pinned — including the
// hyphenated range the reference device actually uses.
func TestIPMatchesAccessSpec(t *testing.T) {
	cases := []struct {
		ip, spec string
		want     bool
	}{
		{"192.168.20.2", "192.168.20.2-192.168.20.14", true},
		{"192.168.20.14", "192.168.20.2-192.168.20.14", true},
		{"192.168.20.15", "192.168.20.2-192.168.20.14", false},
		{"192.168.20.1", "192.168.20.2-192.168.20.14", false},
		{"192.168.20.2", "192.168.20.0/24", true},
		{"192.168.21.2", "192.168.20.0/24", false},
		{"10.1.2.3", "10.0.0.0/8", true},
		{"192.168.20.2", "192.168.20.2", true},
		{"192.168.20.3", "192.168.20.2", false},
	}
	for _, c := range cases {
		got, err := IPMatchesAccessSpec(net.ParseIP(c.ip), c.spec)
		if err != nil {
			t.Fatalf("%s in %s: unexpected error %v", c.ip, c.spec, err)
		}
		if got != c.want {
			t.Errorf("%s in %s = %v, want %v", c.ip, c.spec, got, c.want)
		}
	}
}

// An unreadable spec must error rather than answer false: a false would
// be read as "you are outside this range" and block a legitimate change,
// and a true would wave through one that locks the operator out.
func TestIPMatchesAccessSpecRejectsGarbage(t *testing.T) {
	for _, spec := range []string{"", "not-an-ip", "192.168.20.2-", "192.168.20.0/99", "1.2.3.4-banana"} {
		if _, err := IPMatchesAccessSpec(net.ParseIP("192.168.20.2"), spec); err == nil {
			t.Errorf("expected an error for %q", spec)
		}
	}
}

// The counters name a rule but not what it matches, so the details come
// from the config — parsed into the same fields cnMaestro shows.
func TestParseFilterRuleBody(t *testing.T) {
	p := ParseFilterRuleBody("permit proto tcp 192.168.40.0/255.255.255.0 any 192.168.20.240/255.255.255.254 53 in")
	if p == nil {
		t.Fatal("expected the proto form to parse")
	}
	for _, c := range []struct{ got, want, field string }{
		{p.Action, "permit", "action"},
		{p.Protocol, "tcp", "protocol"},
		{p.Source, "192.168.40.0", "source"},
		{p.SourceMask, "255.255.255.0", "source mask"},
		{p.SourcePort, "any", "source port"},
		{p.Destination, "192.168.20.240", "destination"},
		{p.DestinationMask, "255.255.255.254", "destination mask"},
		{p.DestinationPort, "53", "destination port"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}
}

// The "ip" form a VLAN rate-limit rule uses, and shapes that must not be
// guessed at: an unparseable body returns nil so the caller shows the raw
// line rather than a confidently mislabelled breakdown.
func TestParseFilterRuleBodyOtherShapes(t *testing.T) {
	p := ParseFilterRuleBody("permit ip 192.168.40.0/255.255.255.0 any any")
	if p == nil || p.Source != "192.168.40.0" || p.SourceMask != "255.255.255.0" || p.Action != "permit" {
		t.Fatalf("ip form = %+v", p)
	}
	for _, bad := range []string{"", "permit", "permit proto tcp", "application-group deny instagram"} {
		if got := ParseFilterRuleBody(bad); got != nil {
			t.Errorf("%q should not parse, got %+v", bad, got)
		}
	}
}

// An endpoint is "address/mask", or a bare token like "any" or a group.
func TestSplitFilterEndpoint(t *testing.T) {
	if a, m := splitFilterEndpoint("192.168.20.0/255.255.255.0"); a != "192.168.20.0" || m != "255.255.255.0" {
		t.Fatalf("got %q %q", a, m)
	}
	if a, m := splitFilterEndpoint("any"); a != "any" || m != "" {
		t.Fatalf("got %q %q", a, m)
	}
}
