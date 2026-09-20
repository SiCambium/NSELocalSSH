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

// TestWritableSettingsPathKeepsAnExistingInstall is the migration
// guarantee. The default used to be the working directory unconditionally,
// so moving it without this would strand every existing installation —
// including a developer's repo checkout, which is the normal way to run
// from source.
func TestWritableSettingsPathKeepsAnExistingInstall(t *testing.T) {
	appDir := t.TempDir()
	for _, name := range settingsFileNames {
		wd := t.TempDir()
		if err := os.WriteFile(filepath.Join(wd, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		got := WritableSettingsPathIn("/usr/local/bin/nse-status", wd, "/Users/simon", appDir)
		if want := filepath.Join(wd, ".env"); got != want {
			t.Errorf("with %s present: got %q, want the working directory to be kept (%q)", name, got, want)
		}
	}
}

// TestWritableSettingsPathUsesTheUserDirectoryWhenFresh covers the point
// of the change: the same binary used to keep different credentials
// depending on which directory it was started from.
func TestWritableSettingsPathUsesTheUserDirectoryWhenFresh(t *testing.T) {
	appDir := t.TempDir()
	got := WritableSettingsPathIn("/usr/local/bin/nse-status", t.TempDir(), "/Users/simon", appDir)
	if want := filepath.Join(appDir, ".env"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestWritableSettingsPathFallsBackWithoutAUserDirectory keeps the old
// behaviour for a platform that cannot name a config directory.
func TestWritableSettingsPathFallsBackWithoutAUserDirectory(t *testing.T) {
	wd := t.TempDir()
	got := WritableSettingsPathIn("/usr/local/bin/nse-status", wd, "/Users/simon", "")
	if want := filepath.Join(wd, ".env"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestAppDirNamePerPlatform pins the naming convention: a display-style
// name where the platform uses one, the XDG form elsewhere.
func TestAppDirNamePerPlatform(t *testing.T) {
	for goos, want := range map[string]string{
		"windows": "NSE Status",
		"darwin":  "NSE Status",
		"linux":   "nse-status",
		"freebsd": "nse-status",
	} {
		if got := appDirName(goos); got != want {
			t.Errorf("appDirName(%q) = %q, want %q", goos, got, want)
		}
	}
}

// TestEnvFileCandidatesStillReadsTheOldLocations makes sure a settings
// file written by an older build is still found after the default moved.
func TestEnvFileCandidatesStillReadsTheOldLocations(t *testing.T) {
	appDir := t.TempDir()
	wd := t.TempDir()
	got := strings.Join(EnvFileCandidatesIn("/usr/local/bin/nse-status", wd, "/Users/simon", appDir), "\n")
	for _, want := range []string{
		filepath.Join(wd, ".env"),
		filepath.Join("/Users/simon", ".config", "nse-status", ".env"),
		filepath.Join("/Users/simon", "Library", "Application Support", "NSE Status", ".env"),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("candidates should still include %q:\n%s", want, got)
		}
	}
	// And the writable one is still last, so it wins.
	lines := strings.Split(got, "\n")
	if want := filepath.Join(appDir, ".env"); lines[len(lines)-1] != want {
		t.Errorf("last = %q, want %q", lines[len(lines)-1], want)
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
