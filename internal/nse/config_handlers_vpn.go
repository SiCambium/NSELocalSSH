package nse

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// handleConfigVPN serves and edits the confirmed-syntax subset of VPN:
// Tailscale (enable, accept-routes, advertise-routes — matching exactly
// what CloudConfig models, deliberately excluding the auth-key secret),
// a site-to-site on/off toggle (tunnel parameters are out of scope — see
// SiteToSiteEnableLine), and RADIUS client creation. The client VPN server
// (vpn-server) and WireGuard are not covered here: WireGuard's server-side
// config is documented as cnMaestro-only on this firmware, and vpn-server
// carries a shared secret with no read-back precedent to build a safe edit
// flow around yet.
func (s *Server) handleConfigVPN(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigVPN(w, r)
	case http.MethodPost:
		s.handlePostConfigVPN(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// radiusClientWithID adds the client-list index cloud-json-config doesn't
// expose (radius_client_list is a plain JSON array with no id field). The
// index is derived from array position on the assumption that entries are
// sequential starting at 1 with no gaps — the same assumption
// radius_client_create already makes via len(list)+1.
type radiusClientWithID struct {
	RADIUSClient
	ID int `json:"id"`
}

func (s *Server) handleGetConfigVPN(w http.ResponseWriter, _ *http.Request) {
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	clients := make([]radiusClientWithID, 0, len(cloud.RADIUSClientList))
	for i, c := range cloud.RADIUSClientList {
		clients = append(clients, radiusClientWithID{RADIUSClient: c, ID: i + 1})
	}
	// Whether an auth key is set is useful to show; the key itself is
	// never read back. cloud-json-config reports it as "*masked*" and is
	// not modeled at all, so this comes from the presence of the
	// "tailscale auth-key" leaf in `show config`.
	authKeySet := false
	if cfgRaw, err := s.Client.Run("show config", 25*time.Second); err == nil {
		authKeySet = ParseTunnelConfig(cfgRaw).Tailscale.AuthKeySet
	}
	writeJSON(w, map[string]any{
		"tailscale":              cloud.Tailscale,
		"tailscale_auth_key_set": authKeySet,
		"site_to_site":           cloud.SiteToSite,
		"radius_client_list":     clients,
	})
}

type vpnRequest struct {
	Action    string   `json:"action"`
	Enable    *bool    `json:"enable"`
	Routes    []string `json:"routes"` // advertise-routes CIDRs
	ID        int      `json:"id"`
	Name      string   `json:"name"`
	Secret    string   `json:"secret"`
	AuthKey   string   `json:"auth_key"` // Tailscale auth key, write-only
	Address   string   `json:"address"`
	PrefixLen int      `json:"prefix_length"`
}

func (s *Server) handlePostConfigVPN(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req vpnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var lines []string
	switch req.Action {
	case "tailscale_enable":
		if req.Enable == nil {
			writeSettingsError(w, http.StatusBadRequest, "enable is required")
			return
		}
		lines = []string{TailscaleEnableLine(*req.Enable)}
	case "tailscale_accept_routes":
		if req.Enable == nil {
			writeSettingsError(w, http.StatusBadRequest, "enable is required")
			return
		}
		lines = []string{TailscaleAcceptRoutesLine(*req.Enable)}
	case "tailscale_auth_key":
		key := strings.TrimSpace(req.AuthKey)
		if key == "" {
			writeSettingsError(w, http.StatusBadRequest, "auth_key is required")
			return
		}
		if containsCLILineBreak(key) {
			writeSettingsError(w, http.StatusBadRequest, "auth_key must be a single line")
			return
		}
		lines = []string{TailscaleAuthKeyLine(key)}
	case "tailscale_advertise_routes":
		routes := make([]string, 0, len(req.Routes))
		for _, r := range req.Routes {
			if r = strings.TrimSpace(r); r != "" {
				routes = append(routes, r)
			}
		}
		lines = []string{TailscaleAdvertiseRoutesLine(routes)}
	case "site_to_site_enable":
		if req.Enable == nil {
			writeSettingsError(w, http.StatusBadRequest, "enable is required")
			return
		}
		lines = []string{SiteToSiteEnableLine(*req.Enable)}
	case "radius_client_create":
		if req.Name == "" || req.Secret == "" || req.Address == "" || req.PrefixLen <= 0 {
			writeSettingsError(w, http.StatusBadRequest, "name, secret, address, and prefix_length are required")
			return
		}
		cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
		if err != nil {
			writeSettingsError(w, http.StatusBadGateway, err.Error())
			return
		}
		id := len(cloud.RADIUSClientList) + 1
		lines = append([]string{RADIUSModeLine(true)},
			BuildRADIUSClientLines(id, RADIUSClientLines(req.Name, req.Secret, req.Address, req.PrefixLen))...)
	case "radius_client_edit":
		if req.ID < 1 {
			writeSettingsError(w, http.StatusBadRequest, "id is required")
			return
		}
		if req.Name == "" || req.Secret == "" || req.Address == "" || req.PrefixLen <= 0 {
			writeSettingsError(w, http.StatusBadRequest, "name, secret, address, and prefix_length are required")
			return
		}
		lines = BuildRADIUSClientLines(req.ID, RADIUSClientLines(req.Name, req.Secret, req.Address, req.PrefixLen))
	case "radius_client_delete":
		if req.ID < 1 {
			writeSettingsError(w, http.StatusBadRequest, "id is required")
			return
		}
		lines = []string{RADIUSClientDeleteLine(req.ID)}
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
		return
	}

	block := ConfigBlock{Name: "vpn-" + req.Action, Lines: lines, Risk: ClassifyRisk("vpn")}
	outcome, err := s.safeApplier().Apply(block)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, redactOutcome(outcome))
}
