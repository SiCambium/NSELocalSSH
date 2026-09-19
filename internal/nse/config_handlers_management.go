package nse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// handleConfigManagement serves and edits the safe subset of Management:
// hostname, timezone, NTP, and remote syslog. Deliberately excluded (per
// plan): admin password and the management ssh/https/http toggles — those
// gate the very access this app depends on and get no UI here at all, not
// even behind a warning banner.
func (s *Server) handleConfigManagement(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigManagement(w, r)
	case http.MethodPost:
		s.handlePostConfigManagement(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetConfigManagement(w http.ResponseWriter, _ *http.Request) {
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"hostname":       cloud.SystemName,
		"tz_name":        cloud.TZName,
		"ntp_server":     cloud.NTPServer,
		"syslog_server":  cloud.SyslogServer,
		"logging_syslog": cloud.LoggingSyslog,
		"cambium_remote": cloud.CambiumRemote,
	})
}

type managementRequest struct {
	Action   string `json:"action"`
	Enable   *bool  `json:"enable"`
	Hostname string `json:"hostname"`
	TZName   string `json:"tz_name"`
	NTP      string `json:"ntp_server"`
	NTP2     string `json:"ntp_server_2"`
	SyslogIP string `json:"syslog_ip"`
	SyslogPt string `json:"syslog_port"`
	Severity *int   `json:"severity"`
}

func (s *Server) handlePostConfigManagement(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req managementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var lines []string
	switch req.Action {
	case "hostname":
		if req.Hostname == "" {
			writeSettingsError(w, http.StatusBadRequest, "hostname is required")
			return
		}
		lines = []string{HostnameLine(req.Hostname)}
	case "timezone":
		if req.TZName == "" {
			writeSettingsError(w, http.StatusBadRequest, "tz_name is required")
			return
		}
		lines = []string{TimezoneLine(req.TZName)}
	case "ntp_server":
		if req.NTP == "" {
			writeSettingsError(w, http.StatusBadRequest, "ntp_server is required")
			return
		}
		desired := []string{req.NTP}
		if req.NTP2 != "" {
			if req.NTP2 == req.NTP {
				writeSettingsError(w, http.StatusBadRequest, "the two NTP servers must be different")
				return
			}
			desired = append(desired, req.NTP2)
		}
		if len(desired) > MaxNTPServers {
			writeSettingsError(w, http.StatusBadRequest, fmt.Sprintf("this device holds at most %d NTP servers", MaxNTPServers))
			return
		}
		// The device adds rather than replaces and caps the list at two, so
		// the current servers have to be known before anything is sent —
		// otherwise setting a server on a device with both slots filled
		// just fails as an attempted third.
		cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
		if err != nil {
			writeSettingsError(w, http.StatusBadGateway, err.Error())
			return
		}
		var current []string
		for _, n := range cloud.NTPServer {
			if n.Address != "" {
				current = append(current, n.Address)
			}
		}
		lines = NTPServerSetLines(current, desired)
		if len(lines) == 0 {
			writeJSON(w, ApplyOutcome{Status: "applied", Reason: "NTP servers already set to those values"})
			return
		}
	case "cambium_remote":
		if req.Enable == nil {
			writeSettingsError(w, http.StatusBadRequest, "enable is required")
			return
		}
		lines = []string{CambiumRemoteLine(*req.Enable)}
	case "syslog":
		if req.SyslogIP == "" || req.SyslogPt == "" || req.Severity == nil {
			writeSettingsError(w, http.StatusBadRequest, "syslog_ip, syslog_port, and severity are required")
			return
		}
		if *req.Severity < 0 || *req.Severity > 7 {
			writeSettingsError(w, http.StatusBadRequest, "severity must be between 0 and 7")
			return
		}
		lines = SyslogHostLines(req.SyslogIP, req.SyslogPt, *req.Severity)
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
		return
	}

	block := ConfigBlock{Name: "management-" + req.Action, Lines: lines, Risk: ClassifyRisk("management")}
	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, outcome)
}
