package nse

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"nse-cli/internal/vpndiag"
)

// On-box site-to-site VPN diagnosis.
//
// Gathers evidence over SSH, assembles it per the playbook, and — only if a key
// is configured and egress is enabled — asks Jev for a probability per decision
// node and walks the tree locally.
//
// The evidence is useful on its own, so the endpoint returns 200 with the
// assembled state whenever the verdict cannot be produced. A tool that refuses
// to show an operator what it found because it could not reach a paid API would
// be worse than no tool.

type vpnDiagRequest struct {
	Tunnel string `json:"tunnel"`
}

type vpnDiagResponse struct {
	Tunnel string `json:"tunnel"`

	// Evidence is the exact text a verdict was (or would be) reasoned over.
	// Always returned: it is the part an operator can check.
	Evidence string   `json:"evidence"`
	Notes    []string `json:"notes,omitempty"`

	// Playbook identifies which tree was walked, so a verdict can be traced to
	// the data that produced it.
	Playbook string `json:"playbook"`
	Title    string `json:"title,omitempty"`

	// Advisory is false when no verdict was produced. The reason says why.
	Advisory bool            `json:"advisory"`
	Reason   string          `json:"reason,omitempty"`
	Result   *vpndiag.Result `json:"result,omitempty"`
	CostUSD  float64         `json:"cost_usd,omitempty"`
	InTokens int             `json:"input_tokens,omitempty"`
}

// handleVPNDiagnose runs one diagnosis.
//
// POST because it is state-changing in every practical sense: it takes the
// shared SSH lock for several seconds and, when configured, spends money.
func (s *Server) handleVPNDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req vpnDiagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	tunnel := strings.TrimSpace(req.Tunnel)
	if tunnel == "" {
		writeSettingsError(w, http.StatusBadRequest, "tunnel is required")
		return
	}
	// The tunnel name is interpolated into a CLI command, so refuse anything
	// that could carry a second command with it. validateCLILine catches
	// CR/LF at the point of sending; this is the earlier, clearer refusal.
	if strings.ContainsAny(tunnel, "\r\n;|&") {
		writeSettingsError(w, http.StatusBadRequest, "tunnel name contains characters that are not allowed")
		return
	}

	tree, err := vpndiag.LoadFS(vpndiag.Playbooks(), vpndiag.DocS2S)
	if err != nil {
		writeSettingsError(w, http.StatusInternalServerError, "the diagnosis playbook could not be loaded: "+err.Error())
		return
	}

	// Confirm the tunnel exists before spending an expensive read on it, and so
	// a typo gets a useful message instead of empty evidence.
	cfgRaw, ok := s.cli(w, "show config", vpnDiagConfigTimeout)
	if !ok {
		return
	}
	names := IPsecTunnelNames(SanitizeCLIOutput(stripCLI(cfgRaw, "show config")))
	if !containsString(names, tunnel) {
		writeSettingsError(w, http.StatusBadRequest, "no site-to-site tunnel named "+tunnel+
			" is configured; configured tunnels: "+describeNames(names))
		return
	}

	state, notes, err := tree.GatherState(newSSHEvidenceSource(s.Client), tunnel)
	if err != nil {
		writeDeviceError(w, err)
		return
	}

	resp := vpnDiagResponse{
		Tunnel:   tunnel,
		Evidence: state,
		Notes:    notes,
		Playbook: tree.DocID,
		Title:    tree.Title,
	}

	client := s.jevClient()
	switch {
	case !ReadPrefs(s.prefsFile()).VPNDiagnose:
		resp.Reason = "AI-assisted diagnosis is turned off. The evidence below was gathered locally; " +
			"enable it in Settings to have a candidate cause suggested."
	case !client.Configured():
		resp.Reason = "No OpenRouter API key is configured, so no candidate cause was requested. " +
			"The evidence below was gathered locally and is complete."
	default:
		ctx, cancel := context.WithTimeout(r.Context(), vpndiag.DefaultTimeout)
		defer cancel()
		answers, derr := client.Decide(ctx, state, tree.Questions())
		if derr != nil {
			// Degrade, never fail: the evidence is the durable part.
			resp.Reason = "The decision service could not be reached, so no candidate cause was " +
				"suggested (" + derr.Error() + "). The evidence below was still gathered."
			break
		}
		result, werr := tree.Walk(answers.Answers)
		if werr != nil {
			resp.Reason = "The playbook could not be walked: " + werr.Error()
			break
		}
		resp.Advisory = true
		resp.Result = result
		resp.CostUSD = answers.Usage.Cost
		resp.InTokens = answers.Usage.InputTokens
	}

	writeJSON(w, resp)
}

// jevClient builds the decision client from configuration. The key is read here
// and passed in, so internal/vpndiag never touches the environment itself.
func (s *Server) jevClient() *vpndiag.Client {
	return &vpndiag.Client{
		APIKey:  strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")),
		BaseURL: os.Getenv("OPENROUTER_BASE_URL"),
		Model:   os.Getenv("JEV_MODEL"),
		HTTP:    &http.Client{Timeout: vpndiag.DefaultTimeout},
	}
}

// handleVPNDiagTunnels lists the tunnels a diagnosis can be run against, and
// whether a verdict is available at all.
func (s *Server) handleVPNDiagTunnels(w http.ResponseWriter, r *http.Request) {
	cfgRaw, ok := s.cli(w, "show config", vpnDiagConfigTimeout)
	if !ok {
		return
	}
	clean := SanitizeCLIOutput(stripCLI(cfgRaw, "show config"))
	statsRaw, _ := s.Client.Run(s2sStatsCommandPrefix+" all", vpnDiagStatsTimeout)

	// Index the SA snapshot by name so a tunnel with no record is reported as
	// having none, rather than being left out.
	byName := map[string]IPsecSAStats{}
	for _, st := range ParseS2SStatistics(statsRaw) {
		byName[st.Name] = st
	}

	inbound, _ := ParseGeoIP(clean)
	type row struct {
		Name  string        `json:"name"`
		SA    *IPsecSAStats `json:"sa,omitempty"`
		GeoIP GeoIPVPNRisk  `json:"geoip"`
	}
	rows := []row{}
	for _, name := range IPsecTunnelNames(clean) {
		r := row{Name: name}
		if st, ok := byName[name]; ok {
			r.SA = &st
			r.GeoIP = GeoIPCouldDropTunnel(inbound, st.RemoteSubnets)
		} else {
			r.GeoIP = GeoIPCouldDropTunnel(inbound, nil)
		}
		rows = append(rows, r)
	}

	writeJSON(w, map[string]any{
		"tunnels":          rows,
		"sa_snapshot_note": staleSnapshotNote,
		"advisory_enabled": ReadPrefs(s.prefsFile()).VPNDiagnose && s.jevClient().Configured(),
		"api_key_set":      s.jevClient().Configured(),
	})
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func describeNames(names []string) string {
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}
