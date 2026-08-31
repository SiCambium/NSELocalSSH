package nse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigGroupsBlocksCrossOrigin(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/groups", strings.NewReader(`{"action":"user_group_delete","id":1}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	s.handleConfigGroups(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigGroupsRejectsUnknownAction(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/groups", strings.NewReader(`{"action":"delete_everything"}`))
	rec := httptest.NewRecorder()
	s.handleConfigGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigGroupsUserGroupSaveRequiresFields(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/groups", strings.NewReader(`{"action":"user_group_save","id":1}`))
	rec := httptest.NewRecorder()
	s.handleConfigGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigGroupsUserGroupRejectsOutOfRangeID(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/groups", strings.NewReader(`{"action":"user_group_save","id":65,"name":"x","source_subnet":"10.0.0.0/24"}`))
	rec := httptest.NewRecorder()
	s.handleConfigGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigGroupsIPGroupRejectsOutOfRangeID(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/groups", strings.NewReader(`{"action":"ip_group_save","id":17,"name":"x","address":"10.0.0.0/24"}`))
	rec := httptest.NewRecorder()
	s.handleConfigGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigGroupsAppGroupSaveRequiresApplication(t *testing.T) {
	s := testConfigServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/config/groups", strings.NewReader(`{"action":"app_group_save","id":1,"name":"x"}`))
	rec := httptest.NewRecorder()
	s.handleConfigGroups(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
