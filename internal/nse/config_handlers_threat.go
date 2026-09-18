package nse

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleConfigThreat serves and edits the confirmed-syntax subset of
// Threat Protection (intrusion-prevention): enable, mode, rule set, rule
// type, oinkcode, and auto-update. Per-category rule enable/disable
// (snort_vrt_rule_category) is deliberately read-only, and NOT just
// because the CLI syntax was unconfirmed — a second round of NSE AI
// research (2026-08-31) found the actual command path:
//
//	intrusion-prevention rule-type et-open rule-category emerging-activex
//	intrusion-prevention rule-type et-pro rule-category emerging-activex
//	intrusion-prevention rule-type snort-vrt rule-category <name>
//
// is CONFIRMED real and typeable for et-open/et-pro/snort-vrt (not for
// snort-community, which has no rule-category child at all), one category
// per line with no multi-value or bulk-replace form. But per that same
// research, the firmware's own rule-processing engine has an unimplemented
// TODO stub for per-category SID handling ("sid processing not
// implemented yet for categories", snort.py:989-997) — meaning a category
// toggle can be accepted into config without ever changing which Snort
// rules actually load. Building an interactive on/off control here would
// give a false sense of working protection, which is worse than not
// having the control at all, so this stays read-only until that firmware
// gap is independently verified fixed. The rule-set tier (see
// IPSRuleSetLine) is the confirmed-working way to broaden/narrow
// coverage on this firmware. The oinkcode is accepted write-only (see
// IPSOinkcodeLine) and is never read back, logged, or included in the GET
// response — same secret-handling policy as everywhere else in this app
// (see cloudconfig.go's file-level doc comment).
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
		writeDeviceError(w, err)
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
	RuleSet  string `json:"rule_set"` // "connectivity" | "balanced" | "security"
	RuleType string `json:"rule_type"`
	Interval string `json:"interval"` // e.g. "12-hours"
	Code     string `json:"code"`     // oinkcode, write-only
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
		switch req.RuleSet {
		case "connectivity", "balanced", "security":
		default:
			writeSettingsError(w, http.StatusBadRequest, "rule_set must be 'connectivity', 'balanced', or 'security'")
			return
		}
		lines = []string{IPSRuleSetLine(req.RuleSet)}
	case "rule_type":
		switch req.RuleType {
		case "snort-community", "snort-vrt", "et-open", "et-pro":
		default:
			writeSettingsError(w, http.StatusBadRequest, "rule_type must be 'snort-community', 'snort-vrt', 'et-open', or 'et-pro'")
			return
		}
		lines = []string{IPSRuleTypeLine(req.RuleType)}
	case "oinkcode":
		if req.Code == "" {
			writeSettingsError(w, http.StatusBadRequest, "code is required")
			return
		}
		lines = []string{IPSOinkcodeLine(req.Code)}
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
		writeDeviceError(w, err)
		return
	}
	// The oinkcode action's applied line carries the code itself.
	writeJSON(w, redactOutcome(outcome))
}
