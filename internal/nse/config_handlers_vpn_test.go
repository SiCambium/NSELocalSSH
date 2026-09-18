package nse

import (
	"encoding/json"
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

// TestConfigVPNTailscaleAuthKeyRequired covers the validation on the
// write-only auth key.
func TestConfigVPNTailscaleAuthKeyRequired(t *testing.T) {
	for _, body := range []string{
		`{"action":"tailscale_auth_key"}`,
		`{"action":"tailscale_auth_key","auth_key":"   "}`,
	} {
		s := testConfigServer(t)
		req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleConfigVPN(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d body %s", body, rec.Code, rec.Body.String())
		}
	}
}

// TestConfigVPNTailscaleAuthKeyRejectsLineBreak is the CLI-injection
// guard. Client.runLocked terminates each command with a carriage return,
// so a key carrying its own CR or LF would reach the device as a second,
// caller-chosen command — here, one that would disable SSH.
func TestConfigVPNTailscaleAuthKeyRejectsLineBreak(t *testing.T) {
	for _, key := range []string{
		"tskey-abc\rno management ssh",
		"tskey-abc\nno management ssh",
	} {
		body, err := json.Marshal(map[string]string{"action": "tailscale_auth_key", "auth_key": key})
		if err != nil {
			t.Fatal(err)
		}
		s := testConfigServer(t)
		req := httptest.NewRequest(http.MethodPost, "/api/config/vpn", strings.NewReader(string(body)))
		rec := httptest.NewRecorder()
		s.handleConfigVPN(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("key %q: code %d — it must never reach the device", key, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "single line") {
			t.Errorf("key %q: body %s", key, rec.Body.String())
		}
	}
}

// TestRedactOutcomeHidesSecrets makes sure the applied-lines echo can
// never carry a secret back to the caller. SafeApplier returns the exact
// lines it sent, and for these three actions that line is the secret.
func TestRedactOutcomeHidesSecrets(t *testing.T) {
	secrets := []string{"tskey-auth-SUPERSECRET", "OINKSECRET123", "RADIUSSECRET"}
	outcome := redactOutcome(ApplyOutcome{Status: "applied", Lines: []LineResult{
		{Line: "tailscale auth-key " + secrets[0], OK: true},
		{Line: "intrusion-prevention oinkcode " + secrets[1], OK: true},
		{Line: "secret " + secrets[2], OK: true},
		{Line: "tailscale accept-routes", OK: true},
	}})
	body, err := json.Marshal(outcome)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(body), secret) {
			t.Errorf("outcome leaks %q:\n%s", secret, body)
		}
	}
	// Non-secret lines must survive intact, or the outcome stops being
	// useful for showing what was applied.
	if outcome.Lines[3].Line != "tailscale accept-routes" {
		t.Errorf("non-secret line was mangled: %q", outcome.Lines[3].Line)
	}
	if !strings.Contains(outcome.Lines[0].Line, "auth-key") {
		t.Errorf("redaction should keep the keyword for context: %q", outcome.Lines[0].Line)
	}
}
