package nse

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewWireGuardKeypairIsUsable(t *testing.T) {
	kp, err := NewWireGuardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidWireGuardKey(kp.PrivateKey) || !ValidWireGuardKey(kp.PublicKey) {
		t.Fatalf("keypair is not in WireGuard's format: %+v", kp)
	}
	// Clamping is not cosmetic: an unclamped private key is a different
	// key to every other implementation, and the tunnel silently fails.
	raw, _ := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if raw[0]&7 != 0 {
		t.Error("the low three bits of the private key are not cleared")
	}
	if raw[31]&128 != 0 {
		t.Error("the top bit of the private key is not cleared")
	}
	if raw[31]&64 == 0 {
		t.Error("the second-highest bit of the private key is not set")
	}

	// The public half must be derivable from the private half, which is
	// the whole reason pushing a generated key to the device would let
	// this app know the server's public key without reading it back.
	derived, err := PublicKeyFor(kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if derived != kp.PublicKey {
		t.Errorf("PublicKeyFor = %q, want %q", derived, kp.PublicKey)
	}

	other, _ := NewWireGuardKeypair()
	if other.PrivateKey == kp.PrivateKey {
		t.Error("two generated keypairs are identical")
	}
}

func TestValidWireGuardKey(t *testing.T) {
	kp, _ := NewWireGuardKeypair()
	if !ValidWireGuardKey(kp.PublicKey) {
		t.Error("a generated key was rejected")
	}
	// A truncated paste is the usual real-world mistake.
	for _, bad := range []string{"", "not base64!", kp.PublicKey[:20], base64.StdEncoding.EncodeToString([]byte("short"))} {
		if ValidWireGuardKey(bad) {
			t.Errorf("ValidWireGuardKey(%q) accepted", bad)
		}
	}
}

func TestWireGuardServerLinesMatchTheCapture(t *testing.T) {
	got := WireGuardServerLines(WireGuardServer{
		Interface: "198.51.100.7", VirtualInterface: "10.10.100.1/24",
		ListenPort: 51820, OfflineInterval: 4,
	})
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"vpn-server",
		"wireguard",
		" interface 198.51.100.7",
		" virtual-interface 10.10.100.1/24",
		" listen-port 51820",
		" offline-interval 4",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestValidateWireGuardServer(t *testing.T) {
	ok := WireGuardServer{Interface: "vpn.example.com", VirtualInterface: "10.10.100.1/24", ListenPort: 51820}
	if err := ValidateWireGuardServer(ok); err != nil {
		t.Fatalf("a reasonable server was refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		srv  WireGuardServer
		want string
	}{
		{"endpoint nonsense", WireGuardServer{Interface: "not a host!", VirtualInterface: "10.10.100.1/24", ListenPort: 1}, "neither an address nor a hostname"},
		{"subnet without prefix", WireGuardServer{Interface: "1.2.3.4", VirtualInterface: "10.10.100.1", ListenPort: 1}, "CIDR"},
		{"port out of range", WireGuardServer{Interface: "1.2.3.4", VirtualInterface: "10.10.100.1/24", ListenPort: 0}, "between 1 and 65535"},
	} {
		err := ValidateWireGuardServer(tc.srv)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

func TestWireGuardPeerLinesMatchTheCapture(t *testing.T) {
	kp, _ := NewWireGuardKeypair()
	got := WireGuardPeerLines(WireGuardPeer{
		UserList: 10, Index: 1, Name: "someuser_phone",
		PublicKey: kp.PublicKey, IPAddress: "10.10.100.2",
	})
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"radius-server users-list 10",
		" wireguard",
		" wireguard-user 1",
		"  name someuser_phone",
		"  ip-address 10.10.100.2",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

// A peer outside the tunnel subnet is not rejected by the device: the
// tunnel comes up and nothing routes, which is far harder to diagnose
// than a refusal.
func TestValidateWireGuardPeerCatchesAnAddressOutsideTheTunnel(t *testing.T) {
	kp, _ := NewWireGuardKeypair()
	p := WireGuardPeer{UserList: 1, Index: 1, Name: "laptop", PublicKey: kp.PublicKey, IPAddress: "192.168.5.10"}
	err := ValidateWireGuardPeer(p, "10.10.100.1/24")
	if err == nil || !strings.Contains(err.Error(), "outside the tunnel subnet") {
		t.Errorf("err = %v, want it to catch the address being outside the tunnel", err)
	}
	p.IPAddress = "10.10.100.2"
	if err := ValidateWireGuardPeer(p, "10.10.100.1/24"); err != nil {
		t.Errorf("an in-subnet peer was refused: %v", err)
	}
}

func TestValidateWireGuardPeerRejectsATruncatedKey(t *testing.T) {
	kp, _ := NewWireGuardKeypair()
	p := WireGuardPeer{UserList: 1, Index: 1, Name: "laptop", PublicKey: kp.PublicKey[:20], IPAddress: "10.10.100.2"}
	err := ValidateWireGuardPeer(p, "")
	if err == nil || !strings.Contains(err.Error(), "truncated paste") {
		t.Errorf("err = %v, want it to name the likely cause", err)
	}
}

func TestRenderWireGuardClientConfig(t *testing.T) {
	client, _ := NewWireGuardKeypair()
	server, _ := NewWireGuardKeypair()
	out, err := RenderWireGuardClientConfig(WireGuardClientConfig{
		PeerName:        "laptop",
		PrivateKey:      client.PrivateKey,
		Address:         "10.10.100.2/32",
		ServerPublicKey: server.PublicKey,
		Endpoint:        "vpn.example.com:51820",
		AllowedIPs:      []string{"10.10.100.0/24", "172.21.0.0/16"},
		DNS:             "172.21.0.1",
		Keepalive:       25,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[Interface]",
		"PrivateKey = " + client.PrivateKey,
		"Address = 10.10.100.2/32",
		"DNS = 172.21.0.1",
		"[Peer]",
		"PublicKey = " + server.PublicKey,
		"Endpoint = vpn.example.com:51820",
		"AllowedIPs = 10.10.100.0/24, 172.21.0.0/16",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The server's key must never be confused with the client's.
	if strings.Contains(out, "PrivateKey = "+server.PrivateKey) {
		t.Fatal("the server private key reached a client config")
	}
}

// A file that looks finished and silently cannot connect costs more to
// debug than a refusal costs to read, so the missing server key is an
// error rather than a placeholder.
func TestRenderWireGuardClientConfigRefusesIncompleteInput(t *testing.T) {
	client, _ := NewWireGuardKeypair()
	server, _ := NewWireGuardKeypair()
	full := WireGuardClientConfig{
		PrivateKey: client.PrivateKey, Address: "10.10.100.2/32",
		ServerPublicKey: server.PublicKey, Endpoint: "host:51820",
	}
	for _, tc := range []struct {
		name string
		mut  func(*WireGuardClientConfig)
		want string
	}{
		{"no server key", func(c *WireGuardClientConfig) { c.ServerPublicKey = "" }, "server public key is missing"},
		{"no client key", func(c *WireGuardClientConfig) { c.PrivateKey = "" }, "client private key"},
		{"no address", func(c *WireGuardClientConfig) { c.Address = "" }, "no tunnel address"},
		{"no endpoint", func(c *WireGuardClientConfig) { c.Endpoint = "" }, "endpoint is empty"},
	} {
		c := full
		tc.mut(&c)
		out, err := RenderWireGuardClientConfig(c)
		if err == nil {
			t.Errorf("%s: rendered anyway:\n%s", tc.name, out)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

// Empty AllowedIPs means a full tunnel, and that is stated rather than
// left to the client's default.
func TestRenderWireGuardClientConfigDefaultsToAFullTunnel(t *testing.T) {
	client, _ := NewWireGuardKeypair()
	server, _ := NewWireGuardKeypair()
	out, err := RenderWireGuardClientConfig(WireGuardClientConfig{
		PrivateKey: client.PrivateKey, Address: "10.10.100.2/32",
		ServerPublicKey: server.PublicKey, Endpoint: "host:51820",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "AllowedIPs = 0.0.0.0/0") {
		t.Errorf("want an explicit full tunnel, got:\n%s", out)
	}
}

func TestWireGuardEndpoint(t *testing.T) {
	if got := WireGuardEndpoint(WireGuardServer{Interface: "1.2.3.4", ListenPort: 51820}); got != "1.2.3.4:51820" {
		t.Errorf("endpoint = %q", got)
	}
	if got := WireGuardEndpoint(WireGuardServer{Interface: "", ListenPort: 51820}); got != "" {
		t.Errorf("an endpoint without a host should be empty, got %q", got)
	}
}
