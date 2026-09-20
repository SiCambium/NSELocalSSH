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

// WireGuard client VPN: reading the current state, writing the server and
// its peers, and handing an operator a client file they can import.
//
// The whole point of this endpoint is that it needs no cloud. A peer is
// added by generating a keypair here, sending only the public half to the
// device, and rendering the private half straight into the client file
// the operator downloads. The private key is never stored, never logged,
// and never sent anywhere.

var wgUserListRE = regexp.MustCompile(`^radius-server users-list (\d+)$`)
var wgUserRE = regexp.MustCompile(`^wireguard-user (\d+)$`)

// ParseWireGuardConfig reads the server block and every peer out of a
// `show config` capture.
//
// Secrets are not modelled, matching the rest of this package: a peer's
// public key is published to it by design and is read, but nothing that
// could be a credential is.
func ParseWireGuardConfig(raw string) (WireGuardServer, []WireGuardPeer) {
	var srv WireGuardServer
	peers := []WireGuardPeer{}
	tree := ParseBlockTree(raw)

	if vs := tree.Find("vpn-server"); vs != nil {
		if wg := vs.Find("wireguard"); wg != nil {
			for _, child := range wg.Children {
				if child.Block != nil {
					continue
				}
				f := strings.Fields(strings.TrimSpace(child.Line))
				if len(f) != 2 {
					continue
				}
				switch f[0] {
				case "interface":
					srv.Interface = f[1]
				case "virtual-interface":
					srv.VirtualInterface = f[1]
				case "listen-port":
					srv.ListenPort, _ = strconv.Atoi(f[1])
				case "offline-interval":
					srv.OfflineInterval, _ = strconv.Atoi(f[1])
				}
			}
		}
	}

	for _, child := range tree.Children {
		if child.Block == nil {
			continue
		}
		m := wgUserListRE.FindStringSubmatch(strings.TrimSpace(child.Block.Header))
		if m == nil {
			continue
		}
		list, _ := strconv.Atoi(m[1])
		for _, sub := range child.Block.Children {
			if sub.Block == nil {
				continue
			}
			um := wgUserRE.FindStringSubmatch(strings.TrimSpace(sub.Block.Header))
			if um == nil {
				continue
			}
			idx, _ := strconv.Atoi(um[1])
			p := WireGuardPeer{UserList: list, Index: idx}
			for _, leaf := range sub.Block.Children {
				if leaf.Block != nil {
					continue
				}
				f := strings.SplitN(strings.TrimSpace(leaf.Line), " ", 2)
				if len(f) != 2 {
					continue
				}
				switch f[0] {
				case "name":
					p.Name = f[1]
				case "public-key":
					p.PublicKey = f[1]
				case "ip-address":
					p.IPAddress = f[1]
				}
			}
			peers = append(peers, p)
		}
	}
	return srv, peers
}

type wireguardRequest struct {
	Action string `json:"action"`
	// Server
	Server WireGuardServer `json:"server"`
	// Peer
	UserList int    `json:"user_list"`
	Index    int    `json:"index"`
	Name     string `json:"name"`
	// PublicKey is optional on a peer_add: given, the client keeps its own
	// private key and this app never sees it, which is the better story.
	// Absent, a pair is generated here and the private half comes back
	// once, in the rendered client config.
	PublicKey string `json:"public_key"`
	IPAddress string `json:"ip_address"`
	// Client file
	ServerPublicKey string   `json:"server_public_key"`
	AllowedIPs      []string `json:"allowed_ips"`
	DNS             string   `json:"dns"`
}

func (s *Server) handleConfigWireGuard(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		raw, ok := s.cli(w, "show config", 25*time.Second)
		if !ok {
			return
		}
		srv, peers := ParseWireGuardConfig(raw)
		writeJSON(w, map[string]any{
			"server":   srv,
			"peers":    peers,
			"endpoint": WireGuardEndpoint(srv),
			// Said plainly rather than left for someone to discover: the
			// client file cannot be completed without this, and no
			// captured command returns it.
			"server_public_key_known": false,
			"note":                    "The server's public key is not printed by any command captured from this firmware. Supply it to download a client config, or push a generated private key once that leaf is confirmed on a lab unit.",
		})
	case http.MethodPost:
		s.handlePostConfigWireGuard(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePostConfigWireGuard(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req wireguardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	switch req.Action {
	case "server_save":
		if err := ValidateWireGuardServer(req.Server); err != nil {
			writeSettingsError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.applyWireGuard(w, "wireguard server", WireGuardServerLines(req.Server), []string{"vpn-server"})

	case "peer_add":
		s.addWireGuardPeer(w, req)

	case "peer_delete":
		if req.UserList < 1 || req.Index < 1 {
			writeSettingsError(w, http.StatusBadRequest, "no peer given")
			return
		}
		s.applyWireGuard(w, "wireguard peer", WireGuardPeerDeleteLines(req.UserList, req.Index),
			[]string{fmt.Sprintf("radius-server users-list %d", req.UserList)})

	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
	}
}

// addWireGuardPeer writes the peer and, when it generated the keypair,
// returns the client config once.
//
// The private key is in that response and nowhere else. It is not stored,
// not logged and not recoverable: losing it means issuing a new pair,
// which is the correct trade for a credential that grants access to a
// customer's network.
func (s *Server) addWireGuardPeer(w http.ResponseWriter, req wireguardRequest) {
	raw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	srv, peers := ParseWireGuardConfig(raw)

	peer := WireGuardPeer{
		UserList: req.UserList, Index: req.Index,
		Name: req.Name, PublicKey: req.PublicKey, IPAddress: req.IPAddress,
	}
	if peer.Index < 1 {
		peer.Index = nextWireGuardPeerIndex(peers, peer.UserList)
	}

	var generated WireGuardKeypair
	if strings.TrimSpace(peer.PublicKey) == "" {
		kp, err := NewWireGuardKeypair()
		if err != nil {
			writeSettingsError(w, http.StatusInternalServerError, err.Error())
			return
		}
		generated = kp
		peer.PublicKey = kp.PublicKey
	}

	if err := ValidateWireGuardPeer(peer, srv.VirtualInterface); err != nil {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}

	outcome, err := s.safeApplier().Apply(ConfigBlock{
		Name:  "wireguard peer",
		Lines: WireGuardPeerLines(peer),
		Risk:  ClassifyRisk("vpn"),
		Keys:  []string{fmt.Sprintf("radius-server users-list %d", peer.UserList)},
	})
	if err != nil {
		writeDeviceError(w, err)
		return
	}

	resp := map[string]any{"outcome": outcome, "peer": peer}
	if generated.PrivateKey != "" {
		cfg, rerr := RenderWireGuardClientConfig(WireGuardClientConfig{
			PeerName:        peer.Name,
			PrivateKey:      generated.PrivateKey,
			Address:         peer.IPAddress + "/32",
			ServerPublicKey: req.ServerPublicKey,
			Endpoint:        WireGuardEndpoint(srv),
			AllowedIPs:      req.AllowedIPs,
			DNS:             req.DNS,
			Keepalive:       25,
		})
		if rerr != nil {
			// The peer is on the device either way; only the convenience
			// of a ready-made file was lost, and saying which is the
			// difference between a puzzle and a next step.
			resp["client_config_error"] = rerr.Error()
			resp["client_private_key"] = generated.PrivateKey
		} else {
			resp["client_config"] = cfg
		}
		resp["client_config_note"] = "This is the only time the private key is shown. It is not stored anywhere."
	}
	writeJSON(w, resp)
}

// nextWireGuardPeerIndex picks a free slot in one user list, from what
// the device already has rather than from a counter this app keeps.
func nextWireGuardPeerIndex(peers []WireGuardPeer, list int) int {
	taken := map[int]bool{}
	for _, p := range peers {
		if p.UserList == list {
			taken[p.Index] = true
		}
	}
	for i := 1; i <= 256; i++ {
		if !taken[i] {
			return i
		}
	}
	return 0
}

func (s *Server) applyWireGuard(w http.ResponseWriter, name string, lines, keys []string) {
	outcome, err := s.safeApplier().Apply(ConfigBlock{
		Name: name, Lines: lines, Risk: ClassifyRisk("vpn"), Keys: keys,
	})
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	writeJSON(w, map[string]any{"outcome": outcome, "lines": lines})
}
