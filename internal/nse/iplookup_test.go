package nse

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPLookupRejectsPrivateAddress(t *testing.T) {
	c := newIPOrgCache()
	if _, err := c.LookupIPOrg("192.168.1.1"); err == nil {
		t.Fatal("expected an error for a private address")
	}
}

func TestIPLookupRejectsInvalidAddress(t *testing.T) {
	c := newIPOrgCache()
	if _, err := c.LookupIPOrg("not-an-ip"); err == nil {
		t.Fatal("expected an error for an invalid address")
	}
}

func TestIPLookupCache(t *testing.T) {
	c := newIPOrgCache()
	c.set("8.8.8.8", IPOrgInfo{IP: "8.8.8.8", Org: "Google"})
	info, ok := c.get("8.8.8.8")
	if !ok || info.Org != "Google" {
		t.Fatalf("expected cached entry, got %+v ok=%v", info, ok)
	}
}

func TestHandleIPLookupRequiresPrefEnabled(t *testing.T) {
	s := testSettingsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/iplookup?ip=8.8.8.8", nil)
	rec := httptest.NewRecorder()
	s.handleIPLookup(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestHandleIPLookupRequiresIPParam(t *testing.T) {
	s := testSettingsServer(t)
	prefs := ReadPrefs(s.prefsFile())
	prefs.IPLookup = true
	if err := WritePrefs(s.prefsFile(), prefs); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/iplookup", nil)
	rec := httptest.NewRecorder()
	s.handleIPLookup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
