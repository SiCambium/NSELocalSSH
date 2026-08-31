package nse

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDebugRejectsUnknownCommand(t *testing.T) {
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	req := httptest.NewRequest(http.MethodPost, "/api/debug", strings.NewReader(`{"id":"save"}`))
	rec := httptest.NewRecorder()
	s.handleDebug(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestDebugRejectsInjectionInHost(t *testing.T) {
	cmd, ok := lookupDebugCommand("nslookup")
	if !ok {
		t.Fatal("missing nslookup")
	}
	if _, err := cmd.Build("google.com; save"); err == nil {
		t.Fatal("expected reject")
	}
	if _, err := cmd.Build("example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestDebugBuildPoolAndDaemon(t *testing.T) {
	pool, _ := lookupDebugCommand("show-dhcp-pool")
	got, err := pool.Build("3")
	if err != nil || got != "show dhcp-pool 3" {
		t.Fatalf("pool %q %v", got, err)
	}
	if _, err := pool.Build("99"); err == nil {
		t.Fatal("expected bad pool")
	}
	d, _ := lookupDebugCommand("service-show-debug-logs-daemon")
	got, err = d.Build("tailscaled")
	if err != nil || got != "service show debug-logs tailscaled" {
		t.Fatalf("daemon %q %v", got, err)
	}
	if _, err := d.Build("not-a-daemon"); err == nil {
		t.Fatal("expected unknown daemon")
	}
}

func TestSanitizeCLIOutputRedactsSecrets(t *testing.T) {
	raw := "vpn-server\n shared-secret $crypt$1$SECRET\n tailscale auth-key $crypt$abc\n hostname NSE-Caravan\n"
	got := SanitizeCLIOutput(raw)
	if strings.Contains(got, "SECRET") || strings.Contains(got, "$crypt$") {
		t.Fatalf("secret leaked: %s", got)
	}
	if !strings.Contains(got, "hostname NSE-Caravan") {
		t.Fatalf("lost hostname: %s", got)
	}
}

func TestDebugListHasGroups(t *testing.T) {
	s := &Server{Client: NewClient(Config{})}
	req := httptest.NewRequest(http.MethodGet, "/api/debug", nil)
	rec := httptest.NewRecorder()
	s.handleDebug(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	var body struct {
		Commands []map[string]any `json:"commands"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Commands) < 10 {
		t.Fatalf("too few commands: %d", len(body.Commands))
	}
}
