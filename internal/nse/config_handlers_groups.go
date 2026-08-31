package nse

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleConfigGroups serves and edits User/IP/Application groups. None of
// this is exposed via cloud-json-config or any `show` verb, so it's read
// from a fresh `show config` via ParseGroupsConfig, unlike most other
// sections here.
func (s *Server) handleConfigGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigGroups(w, r)
	case http.MethodPost:
		s.handlePostConfigGroups(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetConfigGroups(w http.ResponseWriter, _ *http.Request) {
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	cfg := ParseGroupsConfig(cfgRaw)
	writeJSON(w, map[string]any{
		"user_groups": orEmpty(cfg.UserGroups),
		"ip_groups":   orEmpty(cfg.IPGroups),
		"app_groups":  orEmpty(cfg.AppGroups),
	})
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

type groupsRequest struct {
	Action       string   `json:"action"`
	ID           int      `json:"id"`
	Name         string   `json:"name"`
	SourceSubnet string   `json:"source_subnet"`
	Address      string   `json:"address"`
	Applications []string `json:"applications"`
	Categories   []string `json:"categories"`
}

func (s *Server) handlePostConfigGroups(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req groupsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var lines []string
	switch req.Action {
	case "user_group_save":
		if req.ID < 1 || req.ID > UserGroupMaxIndex {
			writeSettingsError(w, http.StatusBadRequest, "id must be between 1 and 64")
			return
		}
		if req.Name == "" || req.SourceSubnet == "" {
			writeSettingsError(w, http.StatusBadRequest, "name and source_subnet are required")
			return
		}
		lines = BuildUserGroupLines(req.ID, []string{UserGroupNameLine(req.Name), UserGroupSourceSubnetLine(req.SourceSubnet)})
	case "user_group_delete":
		if req.ID < 1 || req.ID > UserGroupMaxIndex {
			writeSettingsError(w, http.StatusBadRequest, "id must be between 1 and 64")
			return
		}
		lines = []string{UserGroupDeleteLine(req.ID)}
	case "ip_group_save":
		if req.ID < 1 || req.ID > IPGroupMaxIndex {
			writeSettingsError(w, http.StatusBadRequest, "id must be between 1 and 16")
			return
		}
		if req.Name == "" || req.Address == "" {
			writeSettingsError(w, http.StatusBadRequest, "name and address are required")
			return
		}
		lines = BuildIPGroupLines(req.ID, []string{IPGroupNameLine(req.Name), IPGroupAddressLine(req.Address)})
	case "ip_group_delete":
		if req.ID < 1 || req.ID > IPGroupMaxIndex {
			writeSettingsError(w, http.StatusBadRequest, "id must be between 1 and 16")
			return
		}
		lines = []string{IPGroupDeleteLine(req.ID)}
	case "app_group_save":
		if req.ID < 1 || req.ID > AppGroupMaxIndex {
			writeSettingsError(w, http.StatusBadRequest, "id must be between 1 and 16")
			return
		}
		if req.Name == "" || len(req.Applications) == 0 {
			writeSettingsError(w, http.StatusBadRequest, "name and at least one application are required")
			return
		}
		leaves := []string{AppGroupNameLine(req.Name)}
		for _, app := range req.Applications {
			if app != "" {
				leaves = append(leaves, AppGroupApplicationLine(app))
			}
		}
		for _, cat := range req.Categories {
			if cat != "" {
				leaves = append(leaves, AppGroupCategoryLine(cat))
			}
		}
		lines = BuildAppGroupLines(req.ID, leaves)
	case "app_group_delete":
		if req.ID < 1 || req.ID > AppGroupMaxIndex {
			writeSettingsError(w, http.StatusBadRequest, "id must be between 1 and 16")
			return
		}
		lines = []string{AppGroupDeleteLine(req.ID)}
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
		return
	}

	// None of the three group types can affect the session's own
	// management access (they're referenced by name from firewall rules,
	// not applied directly), so this is RiskNone rather than routed
	// through SafeApplier.
	block := ConfigBlock{Name: "groups-" + req.Action, Lines: lines, Risk: RiskNone}
	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, outcome)
}
