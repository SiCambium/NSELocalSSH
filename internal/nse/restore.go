package nse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// Restore: replaying a saved configuration back onto a device.
//
// This is deliberately per section, never the whole device at once.
// Applying an entire configuration touches WAN, LAN ports, VLANs, DHCP,
// firewall and management in one batch, and several of those can cut off
// the session doing the work. One section at a time is reviewable, is
// covered by the confirmation window, and leaves the operator a device
// they can still reach if a section was wrong.
//
// The machinery is the one that already exists. ExtractStanza cuts a
// section out of a `show config` capture, which is the same function
// SafeApplier uses to build a rollback pre-image, and the lines it
// produces are applied through the same SafeApplier. Restore is rollback
// pointed at a file instead of at a snapshot taken moments ago.
//
// **A replay cannot restore a setting whose enabled state is the absence
// of a leaf.** ConfigBlock.Undo documents this for rollback and it is
// equally true here: inter-VLAN routing and port scan are on when no line
// mentions them, so replaying a stanza that never mentioned them changes
// nothing while reporting success. Those two are called out to the
// operator rather than silently mis-restored.

// RestoreSection names a slice of configuration that can be replayed as a
// unit. Keys are matched against the top level of the supplied capture,
// so a device with four VLANs restores four and a device with one
// restores one: nothing here assumes a shape.
type RestoreSection struct {
	ID       string
	Label    string
	Match    *regexp.Regexp
	RiskName string // the ClassifyRisk section this maps to
	Caveat   string
}

var restoreSections = []RestoreSection{
	{ID: "vlans", Label: "VLAN interfaces", Match: regexp.MustCompile(`^interface vlan \d+$`), RiskName: "vlan-management-access",
		Caveat: "Inter-VLAN routing and vulnerability scan are on when no line mentions them, so a replay cannot turn them back on. Check both after restoring."},
	{ID: "dhcp", Label: "DHCP pools", Match: regexp.MustCompile(`^ip dhcp pool \d+$`), RiskName: "dhcp"},
	{ID: "dns", Label: "DNS", Match: regexp.MustCompile(`^(dns-server|ip name-server .+|ip dns server)$`), RiskName: "dns"},
	{ID: "firewall", Label: "Outbound filter", Match: regexp.MustCompile(`^filter global-filter$`), RiskName: "outbound-filter"},
	{ID: "groups", Label: "User, IP and application groups", Match: regexp.MustCompile(`^(group|ip group|application-group) \d+$`), RiskName: "groups"},
	{ID: "threat", Label: "Threat protection", Match: regexp.MustCompile(`^intrusion-prevention( .+)?$`), RiskName: "threat"},
	{ID: "management", Label: "Hostname, timezone, NTP, syslog", Match: regexp.MustCompile(`^(hostname .+|timezone .+|ntp server .+|logging .+)$`), RiskName: "management-service"},
	{ID: "lan-ports", Label: "LAN port switching", Match: regexp.MustCompile(`^interface eth \d+$`), RiskName: "lan-port",
		Caveat: "This includes every physical port in the capture, WAN ports included. Restoring it onto a device cabled differently can take the link you are using."},
}

// riskName spells a RiskLevel for the API. It is an int constant, so a
// plain string conversion would render it as one Unicode rune rather than
// as a word anyone could read.
func riskName(r RiskLevel) string {
	if r == RiskLockout {
		return "lockout"
	}
	return "none"
}

func restoreSection(id string) (RestoreSection, bool) {
	for _, s := range restoreSections {
		if s.ID == id {
			return s, true
		}
	}
	return RestoreSection{}, false
}

// keysIn lists the top-level entries of a capture that a section claims,
// in the order the device printed them.
func keysIn(raw string, sec RestoreSection) []string {
	tree := ParseBlockTree(raw)
	var keys []string
	for _, child := range tree.Children {
		line := child.Line
		if child.Block != nil {
			line = child.Block.Header
		}
		if sec.Match.MatchString(line) {
			keys = append(keys, line)
		}
	}
	return keys
}

type restoreRequest struct {
	Section string `json:"section"`
	Config  string `json:"config"`
	Apply   bool   `json:"apply"`
}

// handleRestore previews or replays one section of a saved configuration.
//
// Preview is the default and Apply must be asked for explicitly, because
// the failure mode of getting this wrong is a site that cannot be reached
// to correct it. A preview sends nothing to the device at all.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		out := make([]map[string]string, 0, len(restoreSections))
		for _, sec := range restoreSections {
			item := map[string]string{"id": sec.ID, "label": sec.Label, "risk": riskName(ClassifyRisk(sec.RiskName))}
			if sec.Caveat != "" {
				item["caveat"] = sec.Caveat
			}
			out = append(out, item)
		}
		writeJSON(w, map[string]any{"sections": out})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}

	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	sec, ok := restoreSection(req.Section)
	if !ok {
		writeSettingsError(w, http.StatusBadRequest, "unknown section")
		return
	}
	if req.Config == "" {
		writeSettingsError(w, http.StatusBadRequest, "no configuration supplied")
		return
	}

	keys := keysIn(req.Config, sec)
	if len(keys) == 0 {
		writeSettingsError(w, http.StatusBadRequest,
			fmt.Sprintf("the supplied configuration has nothing under %q", sec.Label))
		return
	}
	lines := ExtractStanza(req.Config, keys)
	if len(lines) == 0 {
		writeSettingsError(w, http.StatusBadRequest, "nothing to replay")
		return
	}

	if !req.Apply {
		writeJSON(w, map[string]any{
			"section": sec.ID,
			"label":   sec.Label,
			"keys":    keys,
			"lines":   lines,
			"risk":    ClassifyRisk(sec.RiskName),
			"caveat":  sec.Caveat,
			"applied": false,
		})
		return
	}

	outcome, err := s.safeApplier().Apply(ConfigBlock{
		Name:  "restore " + sec.ID,
		Lines: lines,
		Risk:  ClassifyRisk(sec.RiskName),
		Keys:  keys,
	})
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"section": sec.ID,
		"label":   sec.Label,
		"keys":    keys,
		"lines":   lines,
		"caveat":  sec.Caveat,
		"applied": true,
		"outcome": outcome,
	})
}
