package nse

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleConfigThreat serves and edits the confirmed-syntax subset of
// Threat Protection (intrusion-prevention): enable, mode, rule set, rule
// type, and auto-update. Per-category rule enable/disable
// (snort_vrt_rule_category) is read-only for now: it's a list like
// name_server, but unlike name_server its exact per-item CLI verb (add vs.
// toggle) has never been observed, so it isn't guessed at here. The IPS
// oinkcode is a secret and is never modeled at all (see cloudconfig.go).
func (s *Server) handleConfigThreat(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigThreat(w, r)
	case http.MethodPost:
		s.handlePostConfigThreat(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetConfigThreat(w http.ResponseWriter, _ *http.Request) {
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"ips":                 cloud.IPS,
		"ips_mode":            cloud.IPSMode,
		"ips_rule_set":        cloud.IPSRuleSet,
		"ips_rule_type":       cloud.IPSRuleType,
		"ips_auto_update":     cloud.IPSAutoUpdate,
		"ips_update_interval": cloud.IPSUpdateInterval,
		"snort_category":      cloud.SnortRuleCategory,
	})
}

type threatRequest struct {
	Action   string `json:"action"`
	Enable   *bool  `json:"enable"`
	Mode     string `json:"mode"`     // "prevention" | "detection"
	RuleSet  string `json:"rule_set"` // e.g. "balanced"
	RuleType string `json:"rule_type"`
	Interval string `json:"interval"` // e.g. "12-hours"
}

func (s *Server) handlePostConfigThreat(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req threatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var lines []string
	switch req.Action {
	case "enable":
		if req.Enable == nil {
			writeSettingsError(w, http.StatusBadRequest, "enable is required")
			return
		}
		lines = []string{IPSEnableLine(*req.Enable)}
	case "mode":
		switch req.Mode {
		case "prevention", "detection":
		default:
			writeSettingsError(w, http.StatusBadRequest, "mode must be 'prevention' or 'detection'")
			return
		}
		lines = []string{IPSModeLine(req.Mode)}
	case "rule_set":
		if req.RuleSet == "" {
			writeSettingsError(w, http.StatusBadRequest, "rule_set is required")
			return
		}
		lines = []string{IPSRuleSetLine(req.RuleSet)}
	case "rule_type":
		if req.RuleType == "" {
			writeSettingsError(w, http.StatusBadRequest, "rule_type is required")
			return
		}
		lines = []string{IPSRuleTypeLine(req.RuleType)}
	case "auto_update":
		if req.Enable == nil {
			writeSettingsError(w, http.StatusBadRequest, "enable is required")
			return
		}
		lines = []string{IPSAutoUpdateLine(*req.Enable)}
		if *req.Enable && req.Interval != "" {
			lines = append(lines, IPSAutoUpdateIntervalLine(req.Interval))
		}
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
		return
	}

	block := ConfigBlock{Name: "threat-" + req.Action, Lines: lines, Risk: ClassifyRisk("threat-protection")}
	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, outcome)
}
