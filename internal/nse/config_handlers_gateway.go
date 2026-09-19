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

// Gateway source precedence: which way of learning a default gateway
// wins when more than one offers you one.
//
// CONFIRMED live on an NSE3000 running 2.3-r6, five lines present in the
// running config:
//
//	ip gw-source-precedence static 1
//	ip gw-source-precedence dhcpc 2
//	ip gw-source-precedence pppoe 3
//	ipv6 gw-source-precedence static 1
//	ipv6 gw-source-precedence auto-config/dhcpc 2
//
// The device's own configuration store carries the matching keys
// (gw_precedence_static, gw_precedence_dhcpc, gw_precedence_pppoe, and
// the two v6 forms), so both halves agree on what this is.
//
// This matters more without a cloud than with one. On a unit with a
// static WAN and a DHCP WAN, the order here decides which link the device
// treats as its way out, and it was previously readable only by scrolling
// the raw config.

// gatewaySources are the values this CLI accepts, per family. The v6
// list is not the v4 list: it carries "auto-config/dhcpc" as one token,
// slash included, which is how the device prints it.
var gatewaySources = map[string][]string{
	"ip":   {"static", "dhcpc", "pppoe"},
	"ipv6": {"static", "auto-config/dhcpc", "pppoe"},
}

func GatewayPrecedenceLine(family, source string, rank int) string {
	return fmt.Sprintf("%s gw-source-precedence %s %d", family, source, rank)
}

// ParseGatewayPrecedence reads the current ordering out of `show config`.
func ParseGatewayPrecedence(raw string) map[string]map[string]int {
	out := map[string]map[string]int{"ip": {}, "ipv6": {}}
	for _, child := range ParseBlockTree(raw).Children {
		if child.Block != nil {
			continue
		}
		f := strings.Fields(strings.TrimSpace(child.Line))
		if len(f) != 4 || f[1] != "gw-source-precedence" {
			continue
		}
		if _, known := out[f[0]]; !known {
			continue
		}
		if rank, err := strconv.Atoi(f[3]); err == nil {
			out[f[0]][f[2]] = rank
		}
	}
	return out
}

type gatewayRequest struct {
	Family string         `json:"family"` // ip | ipv6
	Order  map[string]int `json:"order"`  // source -> rank
}

func (s *Server) handleConfigGateway(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		raw, ok := s.cli(w, "show config", 25*time.Second)
		if !ok {
			return
		}
		writeJSON(w, map[string]any{
			"precedence": ParseGatewayPrecedence(raw),
			"sources":    gatewaySources,
		})
	case http.MethodPost:
		if !isSameOrigin(r) {
			writeCrossOriginBlocked(w)
			return
		}
		var req gatewayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		lines, errMsg := gatewayLines(req)
		if errMsg != "" {
			writeSettingsError(w, http.StatusBadRequest, errMsg)
			return
		}
		outcome, err := s.safeApplier().Apply(ConfigBlock{
			Name:  "gateway precedence",
			Lines: lines,
			Risk:  ClassifyRisk("wan"),
			Keys:  gatewayKeys(req.Family),
		})
		if err != nil {
			writeDeviceError(w, err)
			return
		}
		writeJSON(w, map[string]any{"outcome": outcome, "lines": lines})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// gatewayLines validates an ordering and renders it. Ranks are checked
// for duplicates: two sources claiming rank 1 is not something to send
// and let the device arbitrate, because whichever it picks is then the
// route off this site.
func gatewayLines(req gatewayRequest) ([]string, string) {
	valid, ok := gatewaySources[req.Family]
	if !ok {
		return nil, "family must be ip or ipv6"
	}
	if len(req.Order) == 0 {
		return nil, "no ordering given"
	}
	allowed := map[string]bool{}
	for _, v := range valid {
		allowed[v] = true
	}
	seen := map[int]string{}
	names := make([]string, 0, len(req.Order))
	for name := range req.Order {
		names = append(names, name)
	}
	sort.Strings(names)

	lines := make([]string, 0, len(names))
	for _, name := range names {
		rank := req.Order[name]
		if !allowed[name] {
			return nil, fmt.Sprintf("%q is not a gateway source for %s", name, req.Family)
		}
		if rank < 1 || rank > len(valid) {
			return nil, fmt.Sprintf("rank for %q must be between 1 and %d", name, len(valid))
		}
		if other, clash := seen[rank]; clash {
			return nil, fmt.Sprintf("%q and %q both claim rank %d", other, name, rank)
		}
		seen[rank] = name
		lines = append(lines, GatewayPrecedenceLine(req.Family, name, rank))
	}
	return lines, ""
}

func gatewayKeys(family string) []string {
	var keys []string
	for _, src := range gatewaySources[family] {
		keys = append(keys, family+" gw-source-precedence "+src)
	}
	return keys
}
