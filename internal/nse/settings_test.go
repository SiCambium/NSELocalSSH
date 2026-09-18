package nse

import (
	"encoding/json"
	"fmt"
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
	// The list holds real connections now, not a fixed set of padded
	// slots: the server's current device is adopted as the only entry.
	conns, _ := body["connections"].([]any)
	if len(conns) != 1 {
		t.Fatalf("want 1 connection, got %d: %v", len(conns), conns)
	}
	first, _ := conns[0].(map[string]any)
	if first["host"] != "172.23.0.1" || first["active"] != true {
		t.Fatalf("current connection not listed as active: %v", first)
	}
	if _, ok := first["password"]; ok {
		t.Fatal("a connection must never carry its password to the frontend")
	}
	if first["password_set"] != true {
		t.Fatalf("password_set=%v", first["password_set"])
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

// TestSaveConnectionKeepsTypedName is the behaviour a connection manager
// needs and the old five-slot code actively prevented: Upsert used to
// overwrite Name with Host, so a site could never be labelled.
func TestSaveConnectionKeepsTypedName(t *testing.T) {
	s := testSettingsServer(t)
	body := `{"action":"save","id":2,"name":"Leeds branch","host":"10.9.8.7","user":"admin","password":"pw","port":"22"}`
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
	if resp["name"] != "Leeds branch" || resp["active_id"] != float64(2) {
		t.Fatalf("%v", resp)
	}
	store, err := ReadProfiles(s.profilesFile())
	if err != nil {
		t.Fatal(err)
	}
	p := store.Get(2)
	if p == nil || p.Name != "Leeds branch" || p.Password != "pw" {
		t.Fatalf("%+v", p)
	}
}

// TestSaveConnectionWithoutNameFallsBackToHost keeps the old display
// behaviour for entries that have no label, without storing the host as
// if the user had typed it as a name.
func TestSaveConnectionWithoutNameFallsBackToHost(t *testing.T) {
	s := testSettingsServer(t)
	body := `{"action":"save","host":"10.9.8.7","user":"admin","password":"pw"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	store, err := ReadProfiles(s.profilesFile())
	if err != nil {
		t.Fatal(err)
	}
	p := store.Get(store.ActiveID)
	if p == nil {
		t.Fatal("nothing saved")
	}
	if p.Name != "" {
		t.Errorf("Name = %q, want empty (the host is a fallback, not a stored name)", p.Name)
	}
	if p.Label() != "10.9.8.7" {
		t.Errorf("Label() = %q, want the host", p.Label())
	}
}

// TestSaveConnectionAllocatesID covers adding sites without picking a
// slot: id 0 means "new", and IDs keep climbing so a delete can't make a
// later save land on a stale UI reference.
func TestSaveConnectionAllocatesID(t *testing.T) {
	store := ProfileStore{}
	first, err := store.Upsert(Profile{Host: "10.0.0.1", User: "admin", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Upsert(Profile{Host: "10.0.0.2", User: "admin", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != 1 || second.ID != 2 {
		t.Fatalf("ids = %d, %d; want 1, 2", first.ID, second.ID)
	}
	store.Clear(second.ID)
	third, err := store.Upsert(Profile{Host: "10.0.0.3", User: "admin", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if third.ID == second.ID {
		t.Errorf("id %d was reused after a delete", third.ID)
	}
}

// TestSaveConnectionBeyondOldSlotLimit is the point of the change: more
// than the five slots the old store allowed. The count includes the
// connection the server was already pointed at, which LoadOrInitProfiles
// adopts into the list on first write so the site you are on never
// silently goes missing from the manager.
func TestSaveConnectionBeyondOldSlotLimit(t *testing.T) {
	s := testSettingsServer(t)
	for i := 1; i <= 8; i++ {
		body := fmt.Sprintf(`{"action":"save","name":"Site %d","host":"10.0.0.%d","user":"admin","password":"pw"}`, i, i)
		req := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleSettings(rec, req)
		if rec.Code != 200 {
			t.Fatalf("site %d: code %d body %s", i, rec.Code, rec.Body.String())
		}
	}
	store, err := ReadProfiles(s.profilesFile())
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Profiles) != 9 {
		t.Fatalf("stored %d connections, want 9 (8 saved + the adopted current one)", len(store.Profiles))
	}
	if store.Get(1) == nil || store.Get(1).Host != "172.23.0.1" {
		t.Errorf("the connection the server started on was not adopted: %+v", store.Get(1))
	}
	// Every ID distinct, and all eight labels preserved.
	seen := map[int]bool{}
	labels := map[string]bool{}
	for _, p := range store.Profiles {
		if seen[p.ID] {
			t.Errorf("duplicate id %d", p.ID)
		}
		seen[p.ID] = true
		labels[p.Label()] = true
	}
	for i := 1; i <= 8; i++ {
		if !labels[fmt.Sprintf("Site %d", i)] {
			t.Errorf("lost the label for Site %d", i)
		}
	}
}

func TestClearProfileSlot(t *testing.T) {
	s := testSettingsServer(t)
	store := ProfileStore{}
	_, _ = store.Upsert(Profile{ID: 1, Host: "1.1.1.1", User: "admin", Password: "x", Port: "22"})
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
