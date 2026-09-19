package nse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// handleConfigFirewall serves and edits the confirmed-syntax subset of
// Firewall: the four DoS-protection toggles, outbound filter rules
// (add/delete/reorder, with IP, Group, or "All" source/destination), and
// GEO IP filtering (both directions). Port-forward and NAT 1:1/1:many
// remain read-only — their CLI syntax beyond the confirmed pieces in
// NSE3000-CLI-REFERENCE.md is unconfirmed, and a wrong guess there risks
// exposing an internal host rather than just a rejected command. They
// ship as export-only until verified on a lab unit.
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
		writeDeviceError(w, err)
		return
	}
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	geoInbound, geoOutbound := ParseGeoIP(cfgRaw)
	writeJSON(w, map[string]any{
		"dos_protection_ip_spoof":     cloud.DOSProtectionSpoof,
		"dos_protection_ip_spoof_log": cloud.DOSProtectionLog,
		"dos_protection_smurf_attack": cloud.DOSProtectionSmurf,
		"dos_protection_icmp_frag":    cloud.DOSProtectionFrag,
		"filter_config":               cloud.FilterConfig,
		"outbound_filter_rules":       sortedFilterRules(cfgRaw),
		"respond_to_icmp_from_wan":    deviceAccessPingEnabled(cfgRaw),
		"device_access_sources":       parseDeviceAccessSources(cfgRaw),
		"geo_ip_inbound":              geoInbound,
		"geo_ip_outbound":             geoOutbound,
	})
}

// sortedFilterRules parses the live outbound filter rule list and orders
// it by numeric precedence — the order it's actually evaluated in, and
// the order the editable table and the move-up/move-down actions below
// operate on.
func sortedFilterRules(cfgRaw string) []FilterRule {
	rules := ParseConfigFilter(cfgRaw)
	sort.Slice(rules, func(i, j int) bool {
		pi, _ := strconv.Atoi(rules[i].Precedence)
		pj, _ := strconv.Atoi(rules[j].Precedence)
		return pi < pj
	})
	return rules
}

// deviceAccessPingEnabled checks for the confirmed top-level
// "device-access allowed-service ping" line — not modeled in
// cloud-json-config at all, so read straight from `show config`.
func deviceAccessPingEnabled(cfgRaw string) bool {
	tree := ParseBlockTree(cfgRaw)
	_, ok := tree.Leaf("device-access allowed-service ping")
	return ok
}

// DeviceAccessSources is the source restriction on management access.
//
// cnMaestro presents this under Device Access as "IP Group" and "IP
// Address / Source Subnet", with the note that a service is reachable
// from everywhere unless one of these is set. It is not per-service: the
// restriction applies to every allowed-service on the box, so the same
// lines that scope a ping also scope SSH and HTTPS.
//
// That makes it the most dangerous setting this app can read, which is
// why it is worth showing: a device answering only a narrow source range
// looks identical to an unrestricted one in every other view.
type DeviceAccessSources struct {
	IPAddresses []string `json:"ip_addresses"`
	IPGroups    []string `json:"ip_groups"`
}

// Restricted reports whether management access is scoped at all.
func (d DeviceAccessSources) Restricted() bool {
	return len(d.IPAddresses) > 0 || len(d.IPGroups) > 0
}

// parseDeviceAccessSources reads the source restriction from `show
// config`. "device-access ip-address <spec>" is CONFIRMED live — one is
// configured on the reference device as a hyphenated range. The
// "ip-group" spelling mirrors how cnMaestro labels the neighbouring field
// and how groups are named elsewhere in this config; it has NOT been seen
// on a device, so it is read defensively and never written.
func parseDeviceAccessSources(cfgRaw string) DeviceAccessSources {
	out := DeviceAccessSources{IPAddresses: []string{}, IPGroups: []string{}}
	for _, line := range strings.Split(cfgRaw, "\n") {
		t := strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
		if v := strings.TrimPrefix(t, "device-access ip-address "); v != t && v != "" {
			out.IPAddresses = append(out.IPAddresses, v)
		}
		if v := strings.TrimPrefix(t, "device-access ip-group "); v != t && v != "" {
			out.IPGroups = append(out.IPGroups, v)
		}
	}
	return out
}

type firewallRequest struct {
	Action string `json:"action"`
	Enable *bool  `json:"enable"`

	// Outbound filter rule fields, used by "filter_add", "filter_delete",
	// and "filter_move".
	Name       string `json:"name"`
	RuleType   string `json:"rule_type"`   // "ip" (default) | "application_group" | "category"
	RuleAction string `json:"rule_action"` // "deny" (confirmed) | "allow" (unconfirmed)
	Protocol   string `json:"protocol"`
	SrcType    string `json:"src_type"` // "ip" | "group" | "all"
	SrcAddr    string `json:"src_addr"`
	SrcMask    string `json:"src_mask"`
	SrcGroup   string `json:"src_group"`
	SrcPort    string `json:"src_port"`
	DstType    string `json:"dst_type"` // "ip" | "group" | "all"
	DstAddr    string `json:"dst_addr"`
	DstMask    string `json:"dst_mask"`
	DstGroup   string `json:"dst_group"`
	DstPort    string `json:"dst_port"`
	Precedence int    `json:"precedence"`
	Direction  string `json:"direction"` // "up" | "down", for "filter_move"

	// DPI-based filter rule fields, used by "filter_add" when rule_type
	// is "application_group" or "category".
	AppGroupName string `json:"app_group_name"`
	Category     string `json:"category"`

	// GEO IP fields, used by "geo_mode", "geo_countries",
	// "geo_exception_add", and "geo_exception_delete".
	GeoDirection string   `json:"geo_direction"` // "inbound" | "outbound"
	GeoMode      string   `json:"geo_mode"`      // "allow" | "block" | "none"
	Countries    []string `json:"countries"`
	StartIP      string   `json:"start_ip"`
	EndIP        string   `json:"end_ip"`
}

var filterBoolActions = map[string]bool{
	"dos_ip_spoof":             true,
	"dos_ip_spoof_log":         true,
	"dos_smurf":                true,
	"dos_icmp_frag":            true,
	"respond_to_icmp_from_wan": true,
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

	if filterBoolActions[req.Action] {
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
		}
		block := ConfigBlock{Name: "firewall-" + req.Action, Lines: []string{line}, Risk: ClassifyRisk("firewall")}
		outcome, err := s.safeApplier().Apply(block)
		if err != nil {
			writeDeviceError(w, err)
			return
		}
		writeJSON(w, outcome)
		return
	}

	switch req.Action {
	case "filter_add", "filter_edit", "filter_delete", "filter_move":
		s.handlePostOutboundFilterRule(w, req)
	case "geo_mode", "geo_countries", "geo_exception_add", "geo_exception_delete":
		s.handlePostGeoIP(w, req)
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
	}
}

// handlePostGeoIP implements the GEO IP filtering actions: setting a
// direction's mode, replacing its country list, and adding/removing an
// always-allowed IP-range exception. See config_write.go's GeoIP* line
// builders for the CONFIRMED-but-never-live-captured CLI syntax.
func (s *Server) handlePostGeoIP(w http.ResponseWriter, req firewallRequest) {
	if req.GeoDirection != "inbound" && req.GeoDirection != "outbound" {
		writeSettingsError(w, http.StatusBadRequest, "geo_direction must be 'inbound' or 'outbound'")
		return
	}

	var lines []string
	switch req.Action {
	case "geo_mode":
		switch req.GeoMode {
		case "allow", "block", "none":
		default:
			writeSettingsError(w, http.StatusBadRequest, "geo_mode must be 'allow', 'block', or 'none'")
			return
		}
		lines = []string{GeoIPModeLine(req.GeoDirection, req.GeoMode)}
	case "geo_countries":
		lines = []string{GeoIPCountriesLine(req.GeoDirection, req.Countries)}
	case "geo_exception_add":
		if req.StartIP == "" || req.EndIP == "" {
			writeSettingsError(w, http.StatusBadRequest, "start_ip and end_ip are required")
			return
		}
		lines = []string{GeoIPExceptionAddLine(req.GeoDirection, req.StartIP, req.EndIP)}
	case "geo_exception_delete":
		if req.StartIP == "" || req.EndIP == "" {
			writeSettingsError(w, http.StatusBadRequest, "start_ip and end_ip are required")
			return
		}
		lines = []string{GeoIPExceptionDeleteLine(req.GeoDirection, req.StartIP, req.EndIP)}
	}

	block := ConfigBlock{Name: "geo-ip-" + req.Action, Lines: lines, Risk: ClassifyRisk("geo-ip")}
	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, outcome)
}

// filterEndpointSpec resolves one filter-rule endpoint (source or
// destination) to the token FilterRuleContent expects: an "ip" endpoint
// (formatted "addr/mask"), a "group" endpoint (the group's bare name,
// referencing a previously-created User Group or IP Group — CONFIRMED
// interchangeable with an IP/mask in this exact position, see
// FilterRuleContent's doc comment), or an "all" endpoint (the literal
// "any"). "any" is already CONFIRMED valid in this exact layer3-filter
// grammar for the protocol and port fields either side of this one
// (FilterRuleContent's doc comment); cnMaestro's own Add Filter Rule form
// offers "All" as a third option alongside IP and Group for both source
// and destination, so the device is expected to accept it here too, but
// that specific combination hasn't been live-captured — if it's wrong,
// ReplaceFilterRulesLines applies as one sequence and the whole change is
// rejected and rolled back rather than partially applied. Defaults to
// "ip" when type is empty, since that's the form every existing rule on
// this device already uses.
func filterEndpointSpec(kind, addr, mask, group string) (string, error) {
	switch kind {
	case "", "ip":
		if addr == "" || mask == "" {
			return "", fmt.Errorf("address and mask are required")
		}
		return FilterAddrSpec(addr, mask), nil
	case "group":
		if group == "" {
			return "", fmt.Errorf("group is required")
		}
		return group, nil
	case "all":
		return "any", nil
	default:
		return "", fmt.Errorf("type must be 'ip', 'group', or 'all'")
	}
}

// handlePostOutboundFilterRule implements add/delete/move-up/move-down
// for the ordered outbound filter rule list. Every edit reads the
// device's current rule list, computes the intended new order, and
// applies ReplaceFilterRulesLines — see that function's doc comment for
// why a full delete-and-recreate is used instead of in-place renumbering.
func (s *Server) handlePostOutboundFilterRule(w http.ResponseWriter, req firewallRequest) {
	var newRule FilterRule
	if req.Action == "filter_add" || req.Action == "filter_edit" {
		if req.Action == "filter_edit" && req.Precedence < 1 {
			writeSettingsError(w, http.StatusBadRequest, "precedence is required")
			return
		}
		if req.Name == "" {
			writeSettingsError(w, http.StatusBadRequest, "name is required")
			return
		}
		action := req.RuleAction
		if action == "" {
			action = "deny"
		}
		if action != "deny" && action != "allow" && action != "permit" {
			writeSettingsError(w, http.StatusBadRequest, "rule_action must be 'deny' or 'allow'")
			return
		}
		// The CLI keyword is "permit"; "allow" is the UI's word for it.
		action = NormalizeFilterAction(action)
		switch req.RuleType {
		case "application_group":
			if req.AppGroupName == "" {
				writeSettingsError(w, http.StatusBadRequest, "app_group_name is required")
				return
			}
			newRule = FilterRule{Name: req.Name, Rule: FilterRuleApplicationGroupLine(action, req.AppGroupName), Kind: "application_group"}
		case "category":
			if req.Category == "" {
				writeSettingsError(w, http.StatusBadRequest, "category is required")
				return
			}
			newRule = FilterRule{Name: req.Name, Rule: FilterRuleCategoryControlLine(req.Category, action), Kind: "category"}
		case "", "ip":
			src, err := filterEndpointSpec(req.SrcType, req.SrcAddr, req.SrcMask, req.SrcGroup)
			if err != nil {
				writeSettingsError(w, http.StatusBadRequest, "source: "+err.Error())
				return
			}
			dst, err := filterEndpointSpec(req.DstType, req.DstAddr, req.DstMask, req.DstGroup)
			if err != nil {
				writeSettingsError(w, http.StatusBadRequest, "destination: "+err.Error())
				return
			}
			protocol := req.Protocol
			if protocol == "" {
				protocol = "any"
			}
			srcPort, dstPort := req.SrcPort, req.DstPort
			if srcPort == "" {
				srcPort = "any"
			}
			if dstPort == "" {
				dstPort = "any"
			}
			content := FilterRuleContent(action, protocol, src, srcPort, dst, dstPort)
			newRule = FilterRule{Name: req.Name, Rule: content}
		default:
			writeSettingsError(w, http.StatusBadRequest, "rule_type must be 'ip', 'application_group', or 'category'")
			return
		}
	} else {
		if req.Precedence < 1 {
			writeSettingsError(w, http.StatusBadRequest, "precedence is required")
			return
		}
		if req.Action == "filter_move" && req.Direction != "up" && req.Direction != "down" {
			writeSettingsError(w, http.StatusBadRequest, "direction must be 'up' or 'down'")
			return
		}
	}

	cfgRaw, err := s.Client.Run("show config", 25*time.Second)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	current := sortedFilterRules(cfgRaw)

	var newOrder []FilterRule
	switch req.Action {
	case "filter_add":
		// Marked so the rewrite gives it a unique_id: an unmarked rule is
		// how a VLAN's rate limit is identified, and a rule added here is
		// the operator's own.
		newOrder = append(append([]FilterRule{}, current...), MarkOperatorRule(newRule))
	case "filter_edit":
		idx := -1
		for i, rule := range current {
			if rule.Precedence == strconv.Itoa(req.Precedence) {
				idx = i
				break
			}
		}
		if idx < 0 {
			writeSettingsError(w, http.StatusBadRequest, "no rule at that precedence")
			return
		}
		// A rule with no unique_id is a VLAN's per-client rate limit, not
		// an operator rule. Editing it here would rewrite it as one and
		// orphan it from the VLAN that owns it, so it is refused rather
		// than silently reassigned.
		if current[idx].ID == "" {
			writeSettingsError(w, http.StatusBadRequest, "this rule holds a VLAN's rate limit — change it from that VLAN instead")
			return
		}
		// Leaves this editor does not model (a DPI rule's
		// "allowed-sources user-group", say) would otherwise be dropped.
		newRule.ID = current[idx].ID
		newRule.Extra = current[idx].Extra
		newOrder = append([]FilterRule{}, current...)
		newOrder[idx] = newRule
	case "filter_delete":
		for _, rule := range current {
			if rule.Precedence != strconv.Itoa(req.Precedence) {
				newOrder = append(newOrder, rule)
			}
		}
		if len(newOrder) == len(current) {
			writeSettingsError(w, http.StatusBadRequest, "no rule at that precedence")
			return
		}
	case "filter_move":
		idx := -1
		for i, rule := range current {
			if rule.Precedence == strconv.Itoa(req.Precedence) {
				idx = i
				break
			}
		}
		if idx < 0 {
			writeSettingsError(w, http.StatusBadRequest, "no rule at that precedence")
			return
		}
		swapWith := idx - 1
		if req.Direction == "down" {
			swapWith = idx + 1
		}
		if swapWith < 0 || swapWith >= len(current) {
			writeSettingsError(w, http.StatusBadRequest, "rule is already at that end of the list")
			return
		}
		newOrder = append([]FilterRule{}, current...)
		newOrder[idx], newOrder[swapWith] = newOrder[swapWith], newOrder[idx]
	}

	block := ConfigBlock{
		Name:  "outbound-filter-" + req.Action,
		Lines: ReplaceFilterRulesLines(current, newOrder),
		Risk:  ClassifyRisk("outbound-filter"),
		Keys:  []string{"filter global-filter"},
	}
	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, outcome)
}
