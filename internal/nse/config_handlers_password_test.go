package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postPassword(t *testing.T, s *Server, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/config/password", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	s.handleConfigPassword(rec, req)
	return rec
}

func TestAdminPasswordRejectsBadInput(t *testing.T) {
	s := &Server{Client: NewClient(Config{User: "admin", Password: "old-one"}), SkipConnect: true}
	for _, tc := range []struct{ name, body string }{
		{"mismatch", `{"password":"abcdefgh","confirm":"abcdefgi"}`},
		{"empty", `{"password":"","confirm":""}`},
		{"too short", `{"password":"short1","confirm":"short1"}`},
		{"contains a space", `{"password":"has a space","confirm":"has a space"}`},
		{"contains a newline", "{\"password\":\"two\nlines\",\"confirm\":\"two\nlines\"}"},
	} {
		rec := postPassword(t, s, tc.body, "http://127.0.0.1:8080")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d, want 400 (%s)", tc.name, rec.Code, rec.Body.String())
		}
	}
	// Nothing rejected may have moved the credential this app authenticates with.
	if got := s.Client.Snapshot().Password; got != "old-one" {
		t.Errorf("credential = %q after rejected requests, want the original", got)
	}
}

func TestAdminPasswordBlocksCrossOrigin(t *testing.T) {
	s := &Server{Client: NewClient(Config{User: "admin", Password: "old-one"}), SkipConnect: true}
	rec := postPassword(t, s, `{"password":"abcdefgh","confirm":"abcdefgh"}`, "http://evil.example")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	if got := s.Client.Snapshot().Password; got != "old-one" {
		t.Errorf("a blocked request still moved the credential to %q", got)
	}
}

// The failure this handler exists to prevent: an apply that does not
// stand must leave this app holding the credential that still works,
// otherwise the tool locks itself out of a device that never changed.
func TestAdminPasswordPutsTheCredentialBackWhenTheApplyFails(t *testing.T) {
	s := &Server{Client: NewClient(Config{Host: "127.0.0.1", Port: "1", User: "admin", Password: "old-one"}), SkipConnect: true}
	rec := postPassword(t, s, `{"password":"a-new-password","confirm":"a-new-password"}`, "http://127.0.0.1:8080")
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), `"credential_moved":true`) {
		t.Fatal("the apply cannot have succeeded against a port that answers nothing")
	}
	if got := s.Client.Snapshot().Password; got != "old-one" {
		t.Errorf("credential = %q after a failed apply, want the original restored", got)
	}
}

func TestAdminPasswordLine(t *testing.T) {
	if got := AdminPasswordLine("admin", "s3cret-pass"); got != "management user admin password s3cret-pass" {
		t.Errorf("AdminPasswordLine = %q", got)
	}
}
