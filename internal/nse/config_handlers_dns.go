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
	adv := ParseDNSAdvancedConfig(cfgRaw)
	writeJSON(w, map[string]any{
		"dns_server":      cloud.DNSServer,
		"dns_override":    cloud.DNSOverride,
		"filter_mode":     dnsFilterMode(cfgRaw),
		"name_server":     cloud.NameServer,
		"snort_category":  cloud.SnortRuleCategory,
		"local_hosts":     orEmpty(adv.LocalHosts),
		"forward_zones":   orEmpty(adv.ForwardZones),
		"bypass_groups":   orEmpty(adv.BypassGroups),
		"filter_policies": orEmpty(adv.FilterPolicies),
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
	FilterMode string   `json:"filter_mode"` // "disabled" | "learning" | "filtering"
	Enable     *bool    `json:"enable"`
	NameServer []string `json:"name_server"`

	// Local DNS entries / conditional forwarding.
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Server string `json:"server"`

	// DNS override bypass-list.
	GroupName string `json:"group_name"`

	// DNS filter policy.
	ID             int      `json:"id"`
	Name           string   `json:"name"`
	SafeSearch     *bool    `json:"safe_search"`
	DenySourceType string   `json:"deny_source_type"` // "all" | "group"
	DenySourceName string   `json:"deny_source_name"`
	DenyCategories []string `json:"deny_categories"`
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
		case "disabled", "learning", "filtering":
		default:
			writeSettingsError(w, http.StatusBadRequest, "filter_mode must be 'disabled', 'learning', or 'filtering'")
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
	case "local_host_add":
		if req.Domain == "" || req.IP == "" {
			writeSettingsError(w, http.StatusBadRequest, "domain and ip are required")
			return
		}
		lines = BuildDNSServerLines([]string{DNSLocalHostLine(req.Domain, req.IP)})
	case "local_host_delete":
		if req.Domain == "" || req.IP == "" {
			writeSettingsError(w, http.StatusBadRequest, "domain and ip are required")
			return
		}
		lines = BuildDNSServerLines([]string{DNSLocalHostDeleteLine(req.Domain, req.IP)})
	case "forward_zone_add":
		if req.Domain == "" || req.Server == "" {
			writeSettingsError(w, http.StatusBadRequest, "domain and server are required")
			return
		}
		lines = BuildDNSServerLines([]string{DNSForwardZoneLine(req.Domain, req.Server)})
	case "forward_zone_delete":
		if req.Domain == "" || req.Server == "" {
			writeSettingsError(w, http.StatusBadRequest, "domain and server are required")
			return
		}
		lines = BuildDNSServerLines([]string{DNSForwardZoneDeleteLine(req.Domain, req.Server)})
	case "bypass_group_add":
		if req.GroupName == "" {
			writeSettingsError(w, http.StatusBadRequest, "group_name is required")
			return
		}
		lines = BuildDNSServerLines([]string{DNSOverrideBypassGroupLine(req.GroupName)})
	case "bypass_group_delete":
		if req.GroupName == "" {
			writeSettingsError(w, http.StatusBadRequest, "group_name is required")
			return
		}
		lines = BuildDNSServerLines([]string{DNSOverrideBypassGroupDeleteLine(req.GroupName)})
	case "filter_policy_save":
		if req.ID < 1 || req.ID > DNSFilterPolicyMaxIndex {
			writeSettingsError(w, http.StatusBadRequest, "id must be between 1 and 16")
			return
		}
		if req.Name == "" {
			writeSettingsError(w, http.StatusBadRequest, "name is required")
			return
		}
		leaves := []string{DNSFilterPolicyNameLine(req.Name)}
		if req.SafeSearch != nil {
			leaves = append(leaves, DNSFilterPolicySafeSearchLine(*req.SafeSearch))
		}
		switch req.DenySourceType {
		case "group":
			if req.DenySourceName == "" {
				writeSettingsError(w, http.StatusBadRequest, "deny_source_name is required when deny_source_type is 'group'")
				return
			}
			leaves = append(leaves, DNSFilterPolicyDenySourcesGroupLine(req.DenySourceName))
		case "", "all":
			leaves = append(leaves, DNSFilterPolicyDenySourcesAllLine())
		default:
			writeSettingsError(w, http.StatusBadRequest, "deny_source_type must be 'all' or 'group'")
			return
		}
		for _, cat := range req.DenyCategories {
			if cat != "" {
				leaves = append(leaves, DNSFilterPolicyDenyCategoryLine(cat))
			}
		}
		lines = BuildDNSServerLines(BuildDNSFilterPolicyLines(req.ID, leaves))
	case "filter_policy_delete":
		if req.ID < 1 || req.ID > DNSFilterPolicyMaxIndex {
			writeSettingsError(w, http.StatusBadRequest, "id must be between 1 and 16")
			return
		}
		lines = BuildDNSServerLines([]string{DNSFilterPolicyDeleteLine(req.ID)})
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
