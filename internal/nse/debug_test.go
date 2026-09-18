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

// TestSanitizeRedactsWireGuardPrivateKey is the regression test for a live
// leak: the device's own WireGuard private key rendered in full through
// the Config viewer and the debug console, because redaction matched
// "auth-key" and "shared-secret" but not "private-key".
func TestSanitizeRedactsWireGuardPrivateKey(t *testing.T) {
	const priv = "VEVTVC1QUklWQVRFLUtFWS1OT1QtUkVBTC0wMDAwMDA="
	const radius = "SUPERSECRETRADIUS"
	raw := `vpn-client 
 wireguard 
 wireguard private-key ` + priv + `
 wireguard ip-address 10.69.42.52
 wireguard peer-public-key VEVTVC1QRUVSLVBVQkxJQy1LRVktTk9ULVJFQUwtMDA=
 wireguard end-point 198.51.100.9:51820
!
radius-server client-list 1
 name Demo
 secret ` + radius + `
!
ike phase 1
 key-lifetime 28800
!`
	got := SanitizeCLIOutput(raw)

	if strings.Contains(got, priv) {
		t.Errorf("the WireGuard private key survived redaction:\n%s", got)
	}
	if strings.Contains(got, radius) {
		t.Errorf("the RADIUS shared secret survived redaction:\n%s", got)
	}
	// Redaction should still say what was hidden.
	if !strings.Contains(got, "wireguard private-key <redacted>") {
		t.Errorf("redaction lost the context of what it hid:\n%s", got)
	}
	if !strings.Contains(got, "secret <redacted>") {
		t.Errorf("RADIUS secret redaction lost its keyword:\n%s", got)
	}

	// And it must not over-redact. A public key is published to peers by
	// design, and key-lifetime is a timer, not key material.
	for _, keep := range []string{
		"peer-public-key VEVTVC1QRUVSLVBVQkxJQy1LRVktTk9ULVJFQUwtMDA=",
		"key-lifetime 28800",
		"wireguard ip-address 10.69.42.52",
		"wireguard end-point 198.51.100.9:51820",
		"name Demo",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("over-redacted, lost %q:\n%s", keep, got)
		}
	}
}

// TestSecretLineDoesNotOverMatch pins the narrowness of the patterns. A
// substring search for "key" would swallow key-lifetime and the public
// keys; a substring search for "secret" would be broader than the one
// bare RADIUS leaf it is meant for.
func TestSecretLineDoesNotOverMatch(t *testing.T) {
	for _, secret := range []string{
		"wireguard private-key abc=",
		"secret abc",
		"shared-secret abc",
		"tailscale auth-key abc",
		"management user admin password $crypt$0$abc",
		"intrusion-prevention oinkcode abc",
		"local-psk abc",
	} {
		if !secretLine(secret) {
			t.Errorf("secretLine(%q) = false, want true", secret)
		}
	}
	for _, safe := range []string{
		"public-key abc=",
		"wireguard peer-public-key abc=",
		"key-lifetime 28800",
		"deny-categories keyloggers-and-monitoring",
		"wireguard full-tunnel",
		"name Demo",
		"ip address dhcp",
	} {
		if secretLine(safe) {
			t.Errorf("secretLine(%q) = true, want false — over-redaction loses real information", safe)
		}
	}
}
