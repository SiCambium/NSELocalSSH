package nse

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// handleConfigDNS serves and edits the confirmed-syntax subset of DNS:
// content-filter mode, DNS override, the resolver toggle, and the static
// name-server list. dns-filter policy authoring (Ad Blocking-style rule
// sets) is read-only for now — its nested syntax hasn't been confirmed
// beyond the one example in NSE3000-CLI-REFERENCE.md.
func (s *Server) handleConfigDNS(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigDNS(w, r)
	case http.MethodPost:
		s.handlePostConfigDNS(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetConfigDNS(w http.ResponseWriter, _ *http.Request) {
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	cfgRaw, err := s.Client.Run("show config", 25*time.Second)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"dns_server":     cloud.DNSServer,
		"dns_override":   cloud.DNSOverride,
		"filter_mode":    dnsFilterMode(cfgRaw),
		"name_server":    cloud.NameServer,
		"snort_category": cloud.SnortRuleCategory,
	})
}

// dnsFilterMode reads the "filter-mode <value>" leaf out of the
// "dns-server" submode block in a raw `show config` capture.
func dnsFilterMode(cfgRaw string) string {
	tree := ParseBlockTree(cfgRaw)
	blk := tree.Find("dns-server")
	if blk == nil {
		return ""
	}
	line, ok := blk.Leaf("filter-mode ")
	if !ok {
		return ""
	}
	return strings.TrimPrefix(line, "filter-mode ")
}

type dnsRequest struct {
	Action     string   `json:"action"`
	FilterMode string   `json:"filter_mode"` // "learning" | "filtering"
	Enable     *bool    `json:"enable"`
	NameServer []string `json:"name_server"`
}

func (s *Server) handlePostConfigDNS(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req dnsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var lines []string
	switch req.Action {
	case "filter_mode":
		switch req.FilterMode {
		case "learning", "filtering":
		default:
			writeSettingsError(w, http.StatusBadRequest, "filter_mode must be 'learning' or 'filtering'")
			return
		}
		lines = BuildDNSServerLines([]string{DNSFilterModeLine(req.FilterMode)})
	case "dns_override":
		if req.Enable == nil {
			writeSettingsError(w, http.StatusBadRequest, "enable is required")
			return
		}
		lines = BuildDNSServerLines([]string{DNSOverrideLine(*req.Enable)})
	case "dns_server":
		if req.Enable == nil {
			writeSettingsError(w, http.StatusBadRequest, "enable is required")
			return
		}
		lines = []string{DNSServerLine(*req.Enable)}
	case "name_server":
		cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
		if err != nil {
			writeSettingsError(w, http.StatusBadGateway, err.Error())
			return
		}
		current := make([]string, 0, len(cloud.NameServer))
		for _, n := range cloud.NameServer {
			current = append(current, n.IP)
		}
		lines = NameServerLines(current, req.NameServer)
		if len(lines) == 0 {
			writeJSON(w, ApplyOutcome{Status: "applied"})
			return
		}
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
		return
	}

	block := ConfigBlock{Name: "dns-" + req.Action, Lines: lines, Risk: ClassifyRisk("dns")}
	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, outcome)
}
