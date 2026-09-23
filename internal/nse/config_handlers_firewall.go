package nse

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
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

// wanPortNames lists the eth ports currently carrying a WAN role, which
// is where a port-forward or source-NAT rule can go.
func wanPortNames(cfgRaw string) []string {
	out := []string{}
	for _, eth := range ethInterfaceBlocks(ParseBlockTree(cfgRaw)) {
		if valueAfter(blockLeaves(eth.block), "type ") == "wan" {
			out = append(out, fmt.Sprintf("eth%d", eth.port))
		}
	}
	return out
}

// ethPortNumber turns "eth3" into 3.
func ethPortNumber(name string) (int, error) {
	n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(name), "eth"))
	if err != nil || n < 1 {
		return 0, fmt.Errorf("interface must be an eth port, e.g. eth3")
	}
	return n, nil
}

// natRuleBlock builds the ConfigBlock for a port-forward or source-NAT
// change.
//
// Classified with the WAN sections rather than as a plain change. A
// port-forward alone cannot cut off management, but a source-NAT rule
// rewrites the source address of traffic leaving the device, and one
// covering the subnet an operator reaches it from can break the return
// path — the same reasoning that puts outbound filter rules in that list.
// Both kinds edit an "interface eth N" stanza, so the snapshot key is the
// whole interface, and an undo restores every rule on it rather than just
// the one edited.
func natRuleBlock(port int, name string, leaves, undo []string) ConfigBlock {
	b := ConfigBlock{
		Name:  name,
		Lines: BuildInterfaceEthLines(port, leaves),
		Risk:  ClassifyRisk("wan"),
		Keys:  []string{fmt.Sprintf("interface eth %d", port)},
	}
	if len(undo) > 0 {
		b.Undo = BuildInterfaceEthLines(port, undo)
	}
	return b
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
	portForwards, sourceNATs := ParseNATRules(cfgRaw)
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
		"port_forward_rules":          portForwards,
		"source_nat_rules":            sourceNATs,
		"wan_ports":                   wanPortNames(cfgRaw),
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

	// Port-forward and source-NAT fields. Interface is the eth port the
	// rule lives on; Index identifies an existing rule for deletion and is
	// allocated by the server on add.
	Interface string `json:"interface"`
	Index     int    `json:"index"`
	WANPort   int    `json:"wan_port"`
	LANIP     string `json:"lan_ip"`
	LANPort   int    `json:"lan_port"`
	LANSubnet string `json:"lan_subnet"`
	PublicIP  string `json:"public_ip"`
	Overload  string `json:"overload"`

	// Device Access source restriction. Empty clears it.
	DeviceAccessIPAddress string `json:"device_access_ip_address"`
	Precedence            int    `json:"precedence"`
	Direction             string `json:"direction"` // "up" | "down", for "filter_move"

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
	case "device_access_ip_address":
		s.handlePostDeviceAccessSource(w, req)
	case "port_forward_add", "port_forward_delete", "source_nat_add", "source_nat_delete":
		s.handlePostNATRule(w, req)
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
	}
}

// handlePostNATRule implements the port-forward and source-NAT actions.
//
// There is no edit: a rule is deleted and re-added. Nothing confirms that
// re-sending a leaf inside an existing rule block replaces it rather than
// appending, and getting that wrong would leave a half-changed rule. The
// whole sequence applies as one block through safe-apply, so a delete that
// succeeds followed by an add that fails is undone together.
func (s *Server) handlePostNATRule(w http.ResponseWriter, req firewallRequest) {
	port, err := ethPortNumber(req.Interface)
	if err != nil {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	if !slices.Contains(wanPortNames(cfgRaw), req.Interface) {
		writeSettingsError(w, http.StatusBadRequest,
			fmt.Sprintf("%s is not a WAN port; these rules apply to a WAN interface", req.Interface))
		return
	}
	forwards, snats := ParseNATRules(cfgRaw)

	var leaves []string
	var name string

	// undo is set only for the two add actions. Safe-apply's default
	// rollback replays a snapshot of the interface stanza taken before
	// the change, which can restore a leaf that was edited but cannot
	// remove an entity that did not exist when it was taken. Proved
	// live: a port-forward add was left unconfirmed, the window lapsed,
	// the undo reported OK, and the rule was still on the device. A
	// delete needs nothing here — its pre-image does contain the rule,
	// so replaying the stanza recreates it at the same index.
	var undo []string

	switch req.Action {
	case "port_forward_add":
		rule := PortForwardRule{Port: req.WANPort, LANIP: strings.TrimSpace(req.LANIP),
			Protocol: strings.TrimSpace(req.Protocol), LANPort: req.LANPort}
		if err := ValidatePortForward(rule); err != nil {
			writeSettingsError(w, http.StatusBadRequest, err.Error())
			return
		}
		var used []int
		for _, r := range forwards {
			if r.Interface == req.Interface {
				used = append(used, r.Index)
			}
		}
		idx := NextRuleIndex(used)
		name = "port-forward-add"
		leaves = BuildRuleLines(fmt.Sprintf("port-forward-rule %d", idx), PortForwardLeaves(rule))
		undo = []string{RuleDeleteLine("port-forward-rule", idx)}

	case "port_forward_delete":
		if req.Index < 1 {
			writeSettingsError(w, http.StatusBadRequest, "index is required")
			return
		}
		name = "port-forward-delete"
		leaves = []string{RuleDeleteLine("port-forward-rule", req.Index)}

	case "source_nat_add":
		rule := SourceNATRule{LANSubnet: strings.TrimSpace(req.LANSubnet),
			Overload: strings.TrimSpace(req.Overload), PublicIP: strings.TrimSpace(req.PublicIP)}
		if err := ValidateSourceNAT(rule); err != nil {
			writeSettingsError(w, http.StatusBadRequest, err.Error())
			return
		}
		var used []int
		for _, r := range snats {
			if r.Interface == req.Interface {
				used = append(used, r.Index)
			}
		}
		idx := NextRuleIndex(used)
		name = "source-nat-add"
		leaves = BuildRuleLines(fmt.Sprintf("source-nat-rule %d", idx), SourceNATLeaves(rule))
		undo = []string{RuleDeleteLine("source-nat-rule", idx)}

	case "source_nat_delete":
		if req.Index < 1 {
			writeSettingsError(w, http.StatusBadRequest, "index is required")
			return
		}
		name = "source-nat-delete"
		leaves = []string{RuleDeleteLine("source-nat-rule", req.Index)}
	}

	outcome, err := s.safeApplier().Apply(natRuleBlock(port, name, leaves, undo))
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, outcome)
}

// handlePostGeoIP implements the GEO IP filtering actions: setting a
// direction's mode, replacing its country list, and adding/removing an
// always-allowed IP-range exception. See config_write.go's GeoIP* line
// builders for the CONFIRMED-but-never-live-captured CLI syntax.
// handlePostDeviceAccessSource sets or clears the source restriction on
// management access.
//
// This is the most dangerous write in the app, and not because of the
// service it names. The restriction is not per-service: it scopes SSH and
// HTTPS as well as ping, so a range that excludes the operator removes
// the very channel every other recovery path in this code depends on —
// safe-apply's rollback included, since that is delivered over SSH to the
// device that has just stopped accepting it.
//
// So there is a guard ahead of safe-apply: the address this session
// reaches the device from must fall inside the new restriction, or the
// change is refused before a line is sent. Clearing the restriction is
// always allowed, since it only ever widens access.
func (s *Server) handlePostDeviceAccessSource(w http.ResponseWriter, req firewallRequest) {
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	current := parseDeviceAccessSources(cfgRaw)
	var currentSpec string
	if len(current.IPAddresses) > 0 {
		currentSpec = current.IPAddresses[0]
	}

	spec := strings.TrimSpace(req.DeviceAccessIPAddress)
	if spec == currentSpec {
		writeJSON(w, ApplyOutcome{Status: "applied", Reason: "already set to that value"})
		return
	}

	var lines, undo []string
	if spec == "" {
		if currentSpec == "" {
			writeSettingsError(w, http.StatusBadRequest, "there is no source restriction to clear")
			return
		}
		lines = []string{DeviceAccessIPAddressRemoveLine(currentSpec)}
		undo = []string{DeviceAccessIPAddressLine(currentSpec)}
	} else {
		local := s.Client.LocalAddr()
		if local == "" {
			writeSettingsError(w, http.StatusBadGateway, "could not determine which address this session reaches the device from, so a restriction cannot be checked for safety")
			return
		}
		ip := net.ParseIP(local)
		if ip == nil {
			writeSettingsError(w, http.StatusBadGateway, "could not parse this session's local address "+local)
			return
		}
		inside, err := IPMatchesAccessSpec(ip, spec)
		if err != nil {
			writeSettingsError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !inside {
			writeSettingsError(w, http.StatusBadRequest, fmt.Sprintf(
				"refusing: this session reaches the device from %s, which is outside %s — applying it would cut off SSH and HTTPS, including the connection any rollback would travel over. Set a range that includes %s, or change this from a console you cannot lose.",
				local, spec, local))
			return
		}
		// Singleton: setting a value replaces whatever is there, so this
		// is one line either way. The undo restores the previous value,
		// or clears it if there was none — a stanza pre-image cannot,
		// since the restriction is a top-level leaf that was absent.
		lines = []string{DeviceAccessIPAddressLine(spec)}
		if currentSpec == "" {
			undo = []string{DeviceAccessIPAddressRemoveLine(spec)}
		} else {
			undo = []string{DeviceAccessIPAddressLine(currentSpec)}
		}
	}

	outcome, err := s.safeApplier().Apply(ConfigBlock{
		Name:  "device-access-ip-address",
		Lines: lines,
		Risk:  ClassifyRisk("management-service"),
		Undo:  undo,
	})
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, outcome)
}

func (s *Server) handlePostGeoIP(w http.ResponseWriter, req firewallRequest) {
	if req.GeoDirection != "inbound" && req.GeoDirection != "outbound" {
		writeSettingsError(w, http.StatusBadRequest, "geo_direction must be 'inbound' or 'outbound'")
		return
	}
	// Argument validation comes first, before anything touches the
	// device: a malformed request must be refused without spending an
	// SSH round-trip on it.
	switch req.Action {
	case "geo_mode":
		switch req.GeoMode {
		case "allow", "block", "none":
		default:
			writeSettingsError(w, http.StatusBadRequest, "geo_mode must be 'allow', 'block', or 'none'")
			return
		}
	case "geo_exception_add", "geo_exception_delete":
		if req.StartIP == "" || req.EndIP == "" {
			writeSettingsError(w, http.StatusBadRequest, "start_ip and end_ip are required")
			return
		}
	}

	// These are flat top-level lines, not a submode block, so there is no
	// stanza for safe-apply to snapshot: this block used to carry no Keys
	// at all, which made ExtractStanza return nothing and the rollback a
	// no-op — the change was held provisional for 60 seconds and then
	// "undone" by sending zero lines. Every action here builds its own
	// explicit inverse from the config as it stands now.
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	inbound, outbound := ParseGeoIP(cfgRaw)
	before := inbound
	if req.GeoDirection == "outbound" {
		before = outbound
	}

	var lines, undo []string
	switch req.Action {
	case "geo_mode":
		lines = []string{GeoIPModeLine(req.GeoDirection, req.GeoMode)}
		undo = []string{GeoIPModeLine(req.GeoDirection, before.Mode)}
	case "geo_countries":
		lines = []string{GeoIPCountriesLine(req.GeoDirection, req.Countries)}
		if len(before.Countries) > 0 {
			undo = []string{GeoIPCountriesLine(req.GeoDirection, before.Countries)}
		} else {
			// No previous list to restore, and no confirmed line clears
			// one — "countries" with an empty value is not a form the
			// device has been seen to accept. Restoring the mode is the
			// honest partial: it switches the restriction back off, which
			// is what an absent list meant in practice, but it leaves the
			// list itself behind for the next mode change to pick up.
			undo = []string{GeoIPModeLine(req.GeoDirection, before.Mode)}
		}
	case "geo_exception_add":
		lines = []string{GeoIPExceptionAddLine(req.GeoDirection, req.StartIP, req.EndIP)}
		undo = []string{GeoIPExceptionDeleteLine(req.GeoDirection, req.StartIP, req.EndIP)}
	case "geo_exception_delete":
		lines = []string{GeoIPExceptionDeleteLine(req.GeoDirection, req.StartIP, req.EndIP)}
		undo = []string{GeoIPExceptionAddLine(req.GeoDirection, req.StartIP, req.EndIP)}
	}

	block := ConfigBlock{Name: "geo-ip-" + req.Action, Lines: lines,
		Risk: ClassifyRisk("geo-ip"), Undo: undo}
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

	// The forward direction deletes every existing rule and rewrites the
	// list, so the exact inverse is the same call with the two lists
	// swapped. The stanza pre-image safe-apply would otherwise use is
	// wrong here for anything that adds a rule: replaying the old stanza
	// re-asserts the old rules but never deletes the new one, leaving a
	// list that matches neither state.
	block := ConfigBlock{
		Name:  "outbound-filter-" + req.Action,
		Lines: ReplaceFilterRulesLines(current, newOrder),
		Undo:  ReplaceFilterRulesLines(newOrder, current),
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
