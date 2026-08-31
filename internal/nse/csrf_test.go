package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSaveSettingsBlocksCrossOrigin(t *testing.T) {
	s := testSettingsServer(t)
	body := `{"action":"save","slot":1,"host":"10.9.8.7","user":"admin","password":"pw","port":"22"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleSettings(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	if store, err := ReadProfiles(s.profilesFile()); err == nil {
		if p := store.Get(1); p != nil && p.Host == "10.9.8.7" {
			t.Fatal("cross-origin request must not have been able to change the profile")
		}
	}
}

func TestSaveSettingsAllowsSameOrigin(t *testing.T) {
	s := testSettingsServer(t)
	body := `{"action":"save","slot":1,"host":"10.9.8.7","user":"admin","password":"pw","port":"22"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()
	s.handleSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestSaveSettingsBlocksSecFetchSiteCrossSite(t *testing.T) {
	s := testSettingsServer(t)
	body := `{"action":"save","slot":1,"host":"10.9.8.7","user":"admin","password":"pw","port":"22"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	s.handleSettings(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestDebugRunBlocksCrossOrigin(t *testing.T) {
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	req := httptest.NewRequest(http.MethodPost, "/api/debug", strings.NewReader(`{"id":"show-version"}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleDebug(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
