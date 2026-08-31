package nse

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func genKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestTrustedHostKeyCallbackTrustsFirstKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	cb := TrustedHostKeyCallback(path)
	key := genKey(t)
	if err := cb("172.23.0.1:22", nil, key); err != nil {
		t.Fatalf("first connect should be trusted: %v", err)
	}
	// Reload from disk to prove it persisted, not just cached in-memory.
	cb2 := TrustedHostKeyCallback(path)
	if err := cb2("172.23.0.1:22", nil, key); err != nil {
		t.Fatalf("same key on reload should still be trusted: %v", err)
	}
}

func TestTrustedHostKeyCallbackRejectsChangedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	cb := TrustedHostKeyCallback(path)
	first := genKey(t)
	if err := cb("172.23.0.1:22", nil, first); err != nil {
		t.Fatalf("first connect should be trusted: %v", err)
	}
	second := genKey(t)
	err := cb("172.23.0.1:22", nil, second)
	if err == nil {
		t.Fatal("expected rejection of a different host key for the same address")
	}
	if !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestTrustedHostKeyCallbackIsolatesAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts.json")
	cb := TrustedHostKeyCallback(path)
	a := genKey(t)
	b := genKey(t)
	if err := cb("172.23.0.1:22", nil, a); err != nil {
		t.Fatal(err)
	}
	if err := cb("10.0.0.1:22", nil, b); err != nil {
		t.Fatalf("different address should be trusted independently: %v", err)
	}
}
