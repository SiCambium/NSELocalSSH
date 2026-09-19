package nse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Port forwarding and source NAT, the last large gap between this tool
// and what the cloud console could do.
//
// These shipped read-only because their CLI syntax was unconfirmed. It is
// confirmed now, from a live capture, and the builders in
// config_write_nat.go quote it leaf by leaf.
//
// Indexes are allocated from what the device currently has rather than
// taken from the caller, so two rules cannot be created onto the same
// slot and silently replace one another.

var ruleIndexRE = regexp.MustCompile(`^(port-forward-rule|source-nat-rule) (\d+)$`)

// existingRuleIndexes lists the rule numbers already in use on one port,
// for one kind of rule.
func existingRuleIndexes(raw, ethName, kind string) []int {
	tree := ParseBlockTree(raw)
	blk := tree.Find("interface " + strings.Replace(ethName, "eth", "eth ", 1))
	if blk == nil {
		return nil
	}
	var out []int
	for _, child := range blk.Children {
		if child.Block == nil {
			continue
		}
		if m := ruleIndexRE.FindStringSubmatch(strings.TrimSpace(child.Block.Header)); m != nil && m[1] == kind {
			if n, err := strconv.Atoi(m[2]); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

func nextRuleIndex(used []int) int {
	taken := map[int]bool{}
	for _, n := range used {
		taken[n] = true
	}
	for i := 1; i <= 256; i++ {
		if !taken[i] {
			return i
		}
	}
	return 0
}

type natRequest struct {
	Action    string `json:"action"`
	Interface string `json:"interface"` // "eth1"
	Index     int    `json:"index"`
	// Port forward
	WANPort  int    `json:"wan_port"`
	LANIP    string `json:"lan_ip"`
	Protocol string `json:"protocol"`
	LANPort  int    `json:"lan_port"`
	// Source NAT
	LANSubnet string `json:"lan_subnet"`
	PublicIP  string `json:"public_ip"`
	Overload  bool   `json:"overload"`
}

func (s *Server) handleConfigNAT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req natRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	eth, err := ethIndexOf(req.Interface)
	if err != nil {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Validation first, and the device only afterwards. A rule this app
	// already knows to be wrong should cost nothing: contacting the
	// device to fetch a config that the request was never going to use
	// turns a bad request into a gateway error and hides what was
	// actually wrong with it. A delete never needs `show config` at all.
	var (
		lines []string
		kind  string
		build func(idx int) []string
	)
	switch req.Action {
	case "port_forward_add":
		rule := PortForwardRule{WANPort: req.WANPort, LANIP: req.LANIP, Protocol: req.Protocol, LANPort: req.LANPort}
		if err := ValidatePortForward(rule); err != nil {
			writeSettingsError(w, http.StatusBadRequest, err.Error())
			return
		}
		kind = "port-forward-rule"
		build = func(idx int) []string { return PortForwardLines(eth, idx, rule) }

	case "source_nat_add":
		rule := SourceNATRule{LANSubnet: req.LANSubnet, PublicIP: req.PublicIP, Overload: req.Overload}
		if err := ValidateSourceNAT(rule); err != nil {
			writeSettingsError(w, http.StatusBadRequest, err.Error())
			return
		}
		kind = "source-nat-rule"
		build = func(idx int) []string { return SourceNATLines(eth, idx, rule) }

	case "port_forward_delete":
		if req.Index < 1 {
			writeSettingsError(w, http.StatusBadRequest, "no rule given")
			return
		}
		lines = PortForwardDeleteLines(eth, req.Index)

	case "source_nat_delete":
		if req.Index < 1 {
			writeSettingsError(w, http.StatusBadRequest, "no rule given")
			return
		}
		lines = SourceNATDeleteLines(eth, req.Index)

	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
		return
	}

	// Only an add needs to know what is already there, so only an add
	// pays for the read.
	if build != nil {
		raw, ok := s.cli(w, "show config", 25*time.Second)
		if !ok {
			return
		}
		idx := nextRuleIndex(existingRuleIndexes(raw, req.Interface, kind))
		if idx == 0 {
			writeSettingsError(w, http.StatusBadRequest, "this port has no free rule slot")
			return
		}
		lines = build(idx)
	}

	// A WAN port's stanza is the rollback pre-image, the same key the WAN
	// section uses, so an interrupted change restores the whole port
	// rather than half a rule.
	outcome, err := s.safeApplier().Apply(ConfigBlock{
		Name:  "nat",
		Lines: lines,
		Risk:  ClassifyRisk("wan"),
		Keys:  []string{fmt.Sprintf("interface eth %d", eth)},
	})
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, map[string]any{"outcome": outcome, "lines": lines})
}
