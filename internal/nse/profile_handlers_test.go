package nse

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProfileExportRejectsBadMethod(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/profile/export", nil)
	rec := httptest.NewRecorder()
	s.handleProfileExport(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestUnsafeFilenameCharsSanitizesHostname(t *testing.T) {
	if got, want := unsafeFilenameChars.ReplaceAllString(`evil"; rm -rf /`, "_"), "evil_rm_-rf_"; got != want {
		t.Errorf("sanitized = %q, want %q", got, want)
	}
	if got, want := unsafeFilenameChars.ReplaceAllString("NSE-Caravan", "_"), "NSE-Caravan"; got != want {
		t.Errorf("normal hostname changed: got %q, want %q", got, want)
	}
}
