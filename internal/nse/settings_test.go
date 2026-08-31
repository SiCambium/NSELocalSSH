package nse

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func testSettingsServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	return &Server{
		Client: NewClient(Config{
			Host:     "172.23.0.1",
			User:     "admin",
			Password: "secret",
			Port:     "22",
		}),
		SettingsPath: filepath.Join(dir, ".env"),
		SkipConnect:  true,
	}
}

func TestGetSettingsOmitsPassword(t *testing.T) {
	s := testSettingsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	rec := httptest.NewRecorder()
	s.handleSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["host"] != "172.23.0.1" || body["user"] != "admin" {
		t.Fatalf("%v", body)
	}
	if _, ok := body["password"]; ok {
		t.Fatal("password should not be returned")
	}
	if body["password_set"] != true {
		t.Fatalf("password_set=%v", body["password_set"])
	}
	profiles, _ := body["profiles"].([]any)
	if len(profiles) != MaxProfiles {
		t.Fatalf("want %d slots, got %d", MaxProfiles, len(profiles))
	}
}

func TestSaveSettingsRequiresHost(t *testing.T) {
	s := testSettingsServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"user":"admin","password":"x"}`))
	rec := httptest.NewRecorder()
	s.handleSettings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestSaveSettingsNamesSlotAfterIP(t *testing.T) {
	s := testSettingsServer(t)
	body := `{"action":"save","slot":2,"host":"10.9.8.7","user":"admin","password":"pw","port":"22"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["name"] != "10.9.8.7" || resp["active_id"] != float64(2) {
		t.Fatalf("%v", resp)
	}
	store, err := ReadProfiles(s.profilesFile())
	if err != nil {
		t.Fatal(err)
	}
	p := store.Get(2)
	if p == nil || p.Name != "10.9.8.7" || p.Password != "pw" {
		t.Fatalf("%+v", p)
	}
}

func TestClearProfileSlot(t *testing.T) {
	s := testSettingsServer(t)
	store := ProfileStore{}
	_ = store.Upsert(Profile{ID: 1, Host: "1.1.1.1", User: "admin", Password: "x", Port: "22"})
	if err := WriteProfiles(s.profilesFile(), store); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"action":"clear","slot":1}`))
	rec := httptest.NewRecorder()
	s.handleSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	got, err := ReadProfiles(s.profilesFile())
	if err != nil {
		t.Fatal(err)
	}
	if got.Get(1) != nil {
		t.Fatalf("slot still present %+v", got)
	}
}

func TestPrefsLiveConntrack(t *testing.T) {
	s := testSettingsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	rec := httptest.NewRecorder()
	s.handleSettings(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["live_conntrack"] != false {
		t.Fatalf("default live_conntrack=%v", body["live_conntrack"])
	}

	req = httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"action":"prefs","live_conntrack":true}`))
	rec = httptest.NewRecorder()
	s.handleSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	got := ReadPrefs(s.prefsFile())
	if !got.LiveConntrack {
		t.Fatalf("prefs %+v", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	rec = httptest.NewRecorder()
	s.handleSettings(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["live_conntrack"] != true {
		t.Fatalf("live_conntrack=%v", body["live_conntrack"])
	}
}
