package nse

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func postNAT(t *testing.T, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	req := httptest.NewRequest(http.MethodPost, "/api/config/nat", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	s.handleConfigNAT(rec, req)
	return rec
}

// Indexes come from the device, never from the caller, so two rules
// cannot be created onto the same slot and silently replace each other.
func TestRuleIndexesComeFromTheDevice(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_subblocks.txt")
	if err != nil {
		t.Fatal(err)
	}
	pf := existingRuleIndexes(string(raw), "eth1", "port-forward-rule")
	if len(pf) != 1 || pf[0] != 1 {
		t.Errorf("port-forward indexes = %v, want [1] from the capture", pf)
	}
	snat := existingRuleIndexes(string(raw), "eth1", "source-nat-rule")
	if len(snat) != 2 {
		t.Errorf("source-nat indexes = %v, want the two in the capture", snat)
	}
	if got := nextRuleIndex(pf); got != 2 {
		t.Errorf("next port-forward index = %d, want 2", got)
	}
	if got := nextRuleIndex(snat); got != 3 {
		t.Errorf("next source-nat index = %d, want 3", got)
	}
	// A gap is reused rather than skipped past.
	if got := nextRuleIndex([]int{1, 3}); got != 2 {
		t.Errorf("next index over a gap = %d, want 2", got)
	}
}

// A bad rule is refused before the device is contacted at all, so the
// request never reaches the point of publishing a host.
func TestNATRefusesBadRulesBeforeReachingTheDevice(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"public target", `{"action":"port_forward_add","interface":"eth1","wan_port":443,"lan_ip":"8.8.8.8","protocol":"tcp","lan_port":443}`, "not a private address"},
		{"bad protocol", `{"action":"port_forward_add","interface":"eth1","wan_port":443,"lan_ip":"10.0.0.5","protocol":"icmp","lan_port":443}`, "tcp or udp"},
		{"bad interface", `{"action":"port_forward_add","interface":"wan1","wan_port":443,"lan_ip":"10.0.0.5","protocol":"tcp","lan_port":443}`, "port name"},
		{"subnet without prefix", `{"action":"source_nat_add","interface":"eth1","lan_subnet":"10.1.0.0","public_ip":"203.0.113.5"}`, "CIDR"},
		{"delete with no index", `{"action":"port_forward_delete","interface":"eth1"}`, "no rule given"},
		{"unknown action", `{"action":"nope","interface":"eth1"}`, "unknown action"},
	} {
		rec := postNAT(t, tc.body, "http://127.0.0.1:8080")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d, want 400 (%s)", tc.name, rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: body %s, want it to mention %q", tc.name, rec.Body.String(), tc.want)
		}
	}
}

func TestNATBlocksCrossOrigin(t *testing.T) {
	rec := postNAT(t, `{"action":"port_forward_add","interface":"eth1","wan_port":443,"lan_ip":"10.0.0.5","protocol":"tcp","lan_port":443}`, "http://evil.example")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
