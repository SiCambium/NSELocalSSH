package nse

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestParseWireGuardConfig(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_subblocks.txt")
	if err != nil {
		t.Fatal(err)
	}
	srv, peers := ParseWireGuardConfig(string(raw))

	if srv.Interface != "198.51.100.7" {
		t.Errorf("interface = %q, want 198.51.100.7", srv.Interface)
	}
	if srv.VirtualInterface != "10.10.100.1/24" {
		t.Errorf("virtual-interface = %q", srv.VirtualInterface)
	}
	if srv.ListenPort != 1 || srv.OfflineInterval != 4 {
		t.Errorf("listen-port/offline-interval = %d/%d, want 1/4", srv.ListenPort, srv.OfflineInterval)
	}

	if len(peers) != 1 {
		t.Fatalf("peers = %d, want the one in the capture: %+v", len(peers), peers)
	}
	p := peers[0]
	if p.UserList != 10 || p.Index != 1 {
		t.Errorf("peer list/index = %d/%d, want 10/1", p.UserList, p.Index)
	}
	if p.Name != "someuser_phone" || p.IPAddress != "10.10.100.2" {
		t.Errorf("peer = %+v", p)
	}
	// The capture's key is a redaction placeholder, but the field must be
	// read: a peer's public key is published to it by design.
	if p.PublicKey == "" {
		t.Error("the peer's public key was not read")
	}
}

// The bare "wireguard" line under vpn-client is a flag, not a block, and
// reading it as a server block would invent a configuration that is not
// there. blocktree already pins this; this checks the consequence.
func TestParseWireGuardConfigIgnoresTheClientRole(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_subblocks.txt")
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := ParseWireGuardConfig(string(raw))
	// vpn-client in that capture carries an end-point of 198.51.100.9;
	// the server's interface is .7. Reading the wrong role would show it.
	if strings.Contains(srv.Interface, "198.51.100.9") {
		t.Error("the vpn-client block leaked into the server settings")
	}
}

func TestParseWireGuardConfigOnADeviceWithout(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_config_full.txt")
	if err != nil {
		t.Fatal(err)
	}
	srv, peers := ParseWireGuardConfig(string(raw))
	if srv.Interface != "" || srv.ListenPort != 0 {
		t.Errorf("a device without WireGuard reported a server: %+v", srv)
	}
	if len(peers) != 0 {
		t.Errorf("a device without WireGuard reported peers: %+v", peers)
	}
}

func TestNextWireGuardPeerIndex(t *testing.T) {
	peers := []WireGuardPeer{
		{UserList: 10, Index: 1}, {UserList: 10, Index: 3}, {UserList: 11, Index: 1},
	}
	if got := nextWireGuardPeerIndex(peers, 10); got != 2 {
		t.Errorf("next index for list 10 = %d, want the gap at 2", got)
	}
	if got := nextWireGuardPeerIndex(peers, 12); got != 1 {
		t.Errorf("next index for an empty list = %d, want 1", got)
	}
}

func postWireGuard(t *testing.T, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{Client: NewClient(Config{}), SkipConnect: true}
	req := httptest.NewRequest(http.MethodPost, "/api/config/wireguard", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	s.handleConfigWireGuard(rec, req)
	return rec
}

func TestWireGuardRejectsBadInputBeforeTheDevice(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"bad server subnet", `{"action":"server_save","server":{"interface":"1.2.3.4","virtual_interface":"10.10.100.1","listen_port":51820}}`, "CIDR"},
		{"bad endpoint", `{"action":"server_save","server":{"interface":"not a host!","virtual_interface":"10.10.100.1/24","listen_port":51820}}`, "neither an address nor a hostname"},
		{"delete with no peer", `{"action":"peer_delete"}`, "no peer given"},
		{"unknown action", `{"action":"nope"}`, "unknown action"},
	} {
		rec := postWireGuard(t, tc.body, "http://127.0.0.1:8080")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d, want 400 (%s)", tc.name, rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: body %s, want it to mention %q", tc.name, rec.Body.String(), tc.want)
		}
	}
}

func TestWireGuardBlocksCrossOrigin(t *testing.T) {
	rec := postWireGuard(t, `{"action":"peer_delete","user_list":10,"index":1}`, "http://evil.example")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
