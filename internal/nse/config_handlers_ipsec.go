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

// Site-to-site IPsec tunnels, and dynamic DNS.
//
// Both were previously read-only or absent. IPsec is the larger of the
// two and carries the weaker evidence: see config_write_ipsec.go, where
// the whole command tree is marked UNCONFIRMED because it comes from
// community material rather than a live capture.
//
// Because of that, every tunnel write is classified as lockout risk. Not
// because a tunnel cuts the SSH session — it does not — but because
// ClassifyRisk's own reasoning applies: an unverified multi-line
// sub-context cannot be judged safe by inspection, so it gets the path
// that snapshots first, proves the device still answers, and holds the
// change unsaved until a human confirms it.

var ipsecTunnelRE = regexp.MustCompile(`^vpn ipsec (\d+)$`)

// ParseIPsecTunnels reads the tunnels out of a `show config` capture.
//
// Pre-shared keys are deliberately not read. They are the tunnel's only
// authentication, and this package's rule is that a credential is written
// and never modelled — so a tunnel comes back describing itself with its
// secrets simply absent rather than redacted, which cannot leak by
// accident later.
func ParseIPsecTunnels(raw string) []IPsecTunnel {
	out := []IPsecTunnel{}
	tree := ParseBlockTree(raw)
	sts := tree.Find("site-to-site-vpn")
	if sts == nil {
		return out
	}
	for _, child := range sts.Children {
		if child.Block == nil {
			continue
		}
		m := ipsecTunnelRE.FindStringSubmatch(strings.TrimSpace(child.Block.Header))
		if m == nil {
			continue
		}
		idx, _ := strconv.Atoi(m[1])
		t := IPsecTunnel{Index: idx}
		for _, leaf := range child.Block.Children {
			if leaf.Block != nil {
				if phase := strings.TrimSpace(leaf.Block.Header); strings.HasPrefix(phase, "ike phase ") {
					n, _ := strconv.Atoi(strings.TrimPrefix(phase, "ike phase "))
					p := parseIPsecPhase(leaf.Block)
					if n == 1 {
						t.Phase1 = p
					} else {
						t.Phase2 = p
					}
				}
				continue
			}
			k, v, ok := strings.Cut(strings.TrimSpace(leaf.Line), " ")
			if !ok {
				continue
			}
			switch k {
			case "name":
				t.Name = v
			case "ike-version":
				t.IKEVersion = v
			case "role":
				t.Role = v
			case "remote-address":
				t.RemoteAddress = v
			case "remote-id":
				t.RemoteID = v
			case "local-id":
				t.LocalID = v
			case "remote-subnets":
				t.RemoteSubnets = v
			case "local-subnets":
				t.LocalSubnets = v
			case "dead-peer-detection":
				fields := strings.Fields(v)
				if len(fields) == 2 && fields[0] == "interval" {
					t.DPDInterval, _ = strconv.Atoi(fields[1])
				}
				// remote-psk and local-psk are intentionally not read.
			}
		}
		out = append(out, t)
	}
	return out
}

func parseIPsecPhase(b *Block) IPsecPhase {
	var p IPsecPhase
	for _, leaf := range b.Children {
		if leaf.Block != nil {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(leaf.Line), " ")
		if !ok {
			continue
		}
		switch k {
		case "encryption":
			p.Encryption = strings.Fields(v)
		case "integrity":
			p.Integrity = v
		case "dh-group":
			p.DHGroup, _ = strconv.Atoi(v)
		case "pfs":
			p.PFS = true
			if g, _, ok := strings.Cut(v, " "); ok || g != "" {
				p.DHGroup, _ = strconv.Atoi(strings.TrimPrefix(v, "dh-group "))
			}
		case "key-lifetime":
			p.KeyLifetime, _ = strconv.Atoi(v)
		}
	}
	return p
}

type ipsecRequest struct {
	Action    string      `json:"action"`
	Tunnel    IPsecTunnel `json:"tunnel"`
	RemotePSK string      `json:"remote_psk"`
	LocalPSK  string      `json:"local_psk"`
	Index     int         `json:"index"`
}

func (s *Server) handleConfigIPsec(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		raw, ok := s.cli(w, "show config", 25*time.Second)
		if !ok {
			return
		}
		writeJSON(w, map[string]any{
			"tunnels": ParseIPsecTunnels(raw),
			"note":    "Pre-shared keys are never read back. The CLI syntax for these tunnels is unconfirmed: it comes from community documentation, not from a device capture, so writes go through the confirmation path.",
		})
	case http.MethodPost:
		if !isSameOrigin(r) {
			writeCrossOriginBlocked(w)
			return
		}
		var req ipsecRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		switch req.Action {
		case "tunnel_save":
			t := req.Tunnel
			t.RemotePSK, t.LocalPSK = req.RemotePSK, req.LocalPSK
			if err := ValidateIPsecTunnel(t); err != nil {
				writeSettingsError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.applyIPsec(w, IPsecTunnelLines(t))
		case "tunnel_delete":
			if req.Index < 1 {
				writeSettingsError(w, http.StatusBadRequest, "no tunnel given")
				return
			}
			s.applyIPsec(w, IPsecTunnelDeleteLines(req.Index))
		default:
			writeSettingsError(w, http.StatusBadRequest, "unknown action")
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) applyIPsec(w http.ResponseWriter, lines []string) {
	outcome, err := s.safeApplier().Apply(ConfigBlock{
		Name: "ipsec tunnel", Lines: lines,
		// Lockout class by the same reasoning ClassifyRisk gives for
		// free-text overrides: unverified syntax cannot be judged safe by
		// inspection, so it gets the path that can undo itself.
		Risk: RiskLockout,
		Keys: []string{"site-to-site-vpn"},
	})
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	// The lines are echoed without their PSKs so an operator can see what
	// was sent without the response becoming another copy of the secret.
	safe := make([]string, 0, len(lines))
	for _, l := range lines {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "remote-psk ") || strings.HasPrefix(t, "local-psk ") {
			k, _, _ := strings.Cut(t, " ")
			safe = append(safe, " "+k+" <not shown>")
			continue
		}
		safe = append(safe, l)
	}
	writeJSON(w, map[string]any{"outcome": outcome, "lines": safe})
}

// --- Dynamic DNS ---------------------------------------------------------
//
// CONFIRMED from a real capture: the provider list is its own numbered
// sub-context, and a WAN points at one by id.
//
//	ip dns dynamic services-list 1
//	 provider noip
//	 server-name dynupdate.no-ip.com
//	 exit
//
//	interface eth 1
//	 dynamic-dns service-id 1
//
// A provider's username and password are not modelled, for the same
// reason as every other credential here.

type DynDNSProvider struct {
	ID         int    `json:"id"`
	Provider   string `json:"provider"`
	ServerName string `json:"server_name"`
}

var dyndnsListRE = regexp.MustCompile(`^ip dns dynamic services-list (\d+)$`)

func ParseDynDNSProviders(raw string) []DynDNSProvider {
	out := []DynDNSProvider{}
	for _, child := range ParseBlockTree(raw).Children {
		if child.Block == nil {
			continue
		}
		m := dyndnsListRE.FindStringSubmatch(strings.TrimSpace(child.Block.Header))
		if m == nil {
			continue
		}
		id, _ := strconv.Atoi(m[1])
		p := DynDNSProvider{ID: id}
		for _, leaf := range child.Block.Children {
			if leaf.Block != nil {
				continue
			}
			k, v, ok := strings.Cut(strings.TrimSpace(leaf.Line), " ")
			if !ok {
				continue
			}
			switch k {
			case "provider":
				p.Provider = v
			case "server-name":
				p.ServerName = v
			}
		}
		out = append(out, p)
	}
	return out
}

// DynDNSProviderLines writes one provider entry.
func DynDNSProviderLines(p DynDNSProvider) []string {
	return []string{
		fmt.Sprintf("ip dns dynamic services-list %d", p.ID),
		" provider " + strings.TrimSpace(p.Provider),
		" server-name " + strings.TrimSpace(p.ServerName),
		"exit",
	}
}

// DynDNSAttachLines points a WAN port at a provider entry. CONFIRMED leaf
// ("dynamic-dns service-id 1" is live in a real capture).
func DynDNSAttachLines(eth, serviceID int) []string {
	return BuildInterfaceEthLines(eth, []string{
		fmt.Sprintf("dynamic-dns service-id %d", serviceID),
	})
}
