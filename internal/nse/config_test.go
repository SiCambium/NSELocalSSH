package nse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvFileCandidatesWritableLast(t *testing.T) {
	exe := filepath.Join("/Applications", "NSE Status.app", "Contents", "MacOS", "nse-app")
	wd := "/Users/simon/proj"
	home := "/Users/simon"
	got := EnvFileCandidates(exe, wd, home)
	wantLast := WritableSettingsPathFrom(exe, wd, home)
	if len(got) == 0 || got[len(got)-1] != wantLast {
		t.Fatalf("last=%v want %q", got, wantLast)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, filepath.Join("/Applications", "NSE Status.app", "Contents", "Resources", ".env")) {
		t.Fatalf("missing packaged .env: %v", got)
	}
}

func TestWritableSettingsPathFromApp(t *testing.T) {
	exe := filepath.Join("/Applications", "NSE Status.app", "Contents", "MacOS", "nse-app")
	got := WritableSettingsPathFrom(exe, "/tmp", "/Users/simon")
	want := filepath.Join("/Users/simon", "Library", "Application Support", "NSE Status", ".env")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestEnvFileCandidatesProjectDotEnvLastWhenNotApp(t *testing.T) {
	got := EnvFileCandidates("/usr/local/bin/nse-status", "/Users/simon/proj", "/Users/simon")
	wantLast := filepath.Join("/Users/simon/proj", ".env")
	if got[len(got)-1] != wantLast {
		t.Fatalf("last=%v want %q", got, wantLast)
	}
}

func TestWritableSettingsPathFromCwd(t *testing.T) {
	got := WritableSettingsPathFrom("/usr/local/bin/nse-status", "/Users/simon/proj", "/Users/simon")
	want := filepath.Join("/Users/simon/proj", ".env")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestWriteEnvFilePreservesCommentsAndUpdatesKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("# keep me\nNSE_HOST=old\nNSE_LISTEN=127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteEnvFile(path, map[string]string{
		"NSE_HOST":     "10.1.2.3",
		"NSE_USER":     "admin",
		"NSE_PASSWORD": "secret",
		"NSE_PORT":     "22",
	}); err != nil {
		t.Fatal(err)
	}
	got := string(mustRead(t, path))
	if !strings.Contains(got, "# keep me") {
		t.Fatalf("lost comment: %s", got)
	}
	if !strings.Contains(got, "NSE_HOST=10.1.2.3") {
		t.Fatalf("host not updated: %s", got)
	}
	if !strings.Contains(got, "NSE_LISTEN=127.0.0.1:8080") {
		t.Fatalf("lost listen: %s", got)
	}
	if !strings.Contains(got, "NSE_PASSWORD=secret") {
		t.Fatalf("password missing: %s", got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
