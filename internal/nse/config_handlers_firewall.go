package nse

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleConfigFirewall serves and edits the confirmed-syntax subset of
// Firewall: the four DoS-protection toggles. Outbound filter rules, GEO IP
// filtering, port-forward, and NAT 1:1/1:many are read-only for now — per
// plan, their CLI syntax beyond the one filter example in
// NSE3000-CLI-REFERENCE.md is unconfirmed, and a wrong guess on firewall
// rules is a security-relevant mistake, not just a cosmetic one. They ship
// as export-only until verified on a lab unit.
func (s *Server) handleConfigFirewall(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigFirewall(w, r)
	case http.MethodPost:
		s.handlePostConfigFirewall(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetConfigFirewall(w http.ResponseWriter, _ *http.Request) {
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{
		"dos_protection_ip_spoof":     cloud.DOSProtectionSpoof,
		"dos_protection_ip_spoof_log": cloud.DOSProtectionLog,
		"dos_protection_smurf_attack": cloud.DOSProtectionSmurf,
		"dos_protection_icmp_frag":    cloud.DOSProtectionFrag,
		"filter_config":               cloud.FilterConfig,
		"respond_to_icmp_from_wan":    deviceAccessPingEnabled(cfgRaw),
	})
}

// deviceAccessPingEnabled checks for the confirmed top-level
// "device-access allowed-service ping" line — not modeled in
// cloud-json-config at all, so read straight from `show config`.
func deviceAccessPingEnabled(cfgRaw string) bool {
	tree := ParseBlockTree(cfgRaw)
	_, ok := tree.Leaf("device-access allowed-service ping")
	return ok
}

type firewallRequest struct {
	Action string `json:"action"`
	Enable *bool  `json:"enable"`
}

func (s *Server) handlePostConfigFirewall(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req firewallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Enable == nil {
		writeSettingsError(w, http.StatusBadRequest, "enable is required")
		return
	}

	var line string
	switch req.Action {
	case "dos_ip_spoof":
		line = DOSProtectionIPSpoofLine(*req.Enable)
	case "dos_ip_spoof_log":
		line = DOSProtectionIPSpoofLogLine(*req.Enable)
	case "dos_smurf":
		line = DOSProtectionSmurfLine(*req.Enable)
	case "dos_icmp_frag":
		line = DOSProtectionICMPFragLine(*req.Enable)
	case "respond_to_icmp_from_wan":
		line = DeviceAccessPingLine(*req.Enable)
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
		return
	}

	block := ConfigBlock{Name: "firewall-" + req.Action, Lines: []string{line}, Risk: ClassifyRisk("firewall")}
	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, outcome)
}
