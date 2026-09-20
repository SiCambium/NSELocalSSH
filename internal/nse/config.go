package nse

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func parseDotEnv(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 {
			if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
				v = v[1 : len(v)-1]
			}
		}
		if k != "" {
			out[k] = v
		}
	}
	return out
}

func LoadDotEnv(path string) {
	for k, v := range parseDotEnv(path) {
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type Config struct {
	Host     string
	User     string
	Password string
	Port     string
	Listen   string
}

func LoadConfig() Config {
	exe, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	wd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	merged := map[string]string{}
	for _, path := range EnvFileCandidates(exe, wd, home) {
		for k, v := range parseDotEnv(path) {
			merged[k] = v
		}
	}
	for k, v := range merged {
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
	cfg := Config{
		Host:     env("NSE_HOST", "172.23.0.1"),
		User:     env("NSE_USER", "admin"),
		Password: env("NSE_PASSWORD", ""),
		Port:     env("NSE_PORT", "22"),
		Listen:   env("NSE_LISTEN", "127.0.0.1:8080"),
	}
	return applyActiveProfile(cfg)
}

func applyActiveProfile(cfg Config) Config {
	path := ProfilesPath(WritableSettingsPath())
	store, err := ReadProfiles(path)
	if err != nil {
		return cfg
	}
	p := store.Get(store.ActiveID)
	if p == nil || p.Host == "" {
		return cfg
	}
	cfg.Host = p.Host
	if p.User != "" {
		cfg.User = p.User
	}
	if p.Password != "" {
		cfg.Password = p.Password
	}
	if p.Port != "" {
		cfg.Port = p.Port
	}
	ApplyEnv(cfg)
	return cfg
}

// EnvFileCandidates returns .env paths from lowest to highest priority.
// Later files override earlier ones. The writable settings file always wins.
func EnvFileCandidates(exe, wd, home string) []string {
	return EnvFileCandidatesIn(exe, wd, home, UserAppDir())
}

// EnvFileCandidatesIn is EnvFileCandidates with the per-user application
// directory supplied, so tests need not depend on the host's real one.
func EnvFileCandidatesIn(exe, wd, home, appDir string) []string {
	writable := WritableSettingsPathIn(exe, wd, home, appDir)
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if p == filepath.Clean(writable) {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	if exe != "" {
		dir := filepath.Dir(exe)
		if filepath.Base(dir) == "MacOS" {
			contents := filepath.Dir(dir)
			add(filepath.Join(contents, "Resources", ".env"))
			appBundle := filepath.Dir(contents)
			add(filepath.Join(filepath.Dir(appBundle), ".env"))
		}
		add(filepath.Join(dir, ".env"))
	}
	if wd != "" {
		add(filepath.Join(wd, ".env"))
	} else {
		add(".env")
	}
	if appDir != "" {
		add(filepath.Join(appDir, ".env"))
	}
	if home != "" {
		// Read the historical locations too, so a settings file written by
		// an older build is still found after the default moved.
		add(filepath.Join(home, ".config", "nse-status", ".env"))
		add(filepath.Join(home, "Library", "Application Support", "NSE Status", ".env"))
	}
	out = append(out, filepath.Clean(writable))
	return out
}

// appDirName is the per-user directory this app keeps its data in. Windows
// and macOS both conventionally use a display-style name under their own
// config root; everything else follows the lowercase, hyphenated XDG form.
func appDirName(goos string) string {
	if goos == "windows" || goos == "darwin" {
		return "NSE Status"
	}
	return "nse-status"
}

// UserAppDir is the platform's per-user configuration directory for this
// app: %APPDATA%\NSE Status on Windows, ~/Library/Application Support/NSE
// Status on macOS, and $XDG_CONFIG_HOME/nse-status (usually ~/.config)
// elsewhere. Empty if the platform cannot say, in which case callers fall
// back to the working directory as before.
func UserAppDir() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, appDirName(runtime.GOOS))
}

// settingsFileNames are the files whose presence marks a directory as an
// existing installation.
var settingsFileNames = []string{".env", "profiles.json", "prefs.json", "overrides.json", "known_hosts.json"}

// hasExistingSettings reports whether a directory already holds this app's
// data.
func hasExistingSettings(dir string) bool {
	if dir == "" {
		return false
	}
	for _, name := range settingsFileNames {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

func WritableSettingsPath() string {
	exe, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	wd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	return WritableSettingsPathIn(exe, wd, home, UserAppDir())
}

// WritableSettingsPathFrom is kept for callers that do not supply an
// application directory; it resolves the platform's own.
func WritableSettingsPathFrom(exe, wd, home string) string {
	return WritableSettingsPathIn(exe, wd, home, UserAppDir())
}

// WritableSettingsPathIn decides where settings, saved connections and
// host keys are written.
//
// The order matters more than any single location:
//
//  1. Inside a macOS .app bundle, Application Support — a bundle's own
//     directory is not writable and the working directory is wherever
//     Finder happened to launch from.
//  2. A working directory that already holds this app's data keeps it.
//     The default used to be the working directory unconditionally, so
//     moving it without this would strand every existing installation —
//     including a developer's repo checkout, which is the normal way to
//     run from source.
//  3. Otherwise the platform's per-user directory. The old default meant
//     the same binary kept different credentials depending on which
//     directory it was started from, silently.
//  4. Failing all that, the working directory, as before.
func WritableSettingsPathIn(exe, wd, home, appDir string) string {
	if exe != "" && filepath.Base(filepath.Dir(exe)) == "MacOS" && home != "" {
		return filepath.Join(home, "Library", "Application Support", "NSE Status", ".env")
	}
	if hasExistingSettings(wd) {
		return filepath.Join(wd, ".env")
	}
	if appDir != "" {
		return filepath.Join(appDir, ".env")
	}
	if wd != "" {
		return filepath.Join(wd, ".env")
	}
	if home != "" {
		return filepath.Join(home, "Library", "Application Support", "NSE Status", ".env")
	}
	return ".env"
}

func envEncode(v string) string {
	if strings.ContainsAny(v, " \t#\"'") {
		return strconv.Quote(v)
	}
	return v
}

func WriteEnvFile(path string, updates map[string]string) error {
	if path == "" {
		return fmt.Errorf("settings path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return err
	}
	var lines []string
	if raw, err := os.ReadFile(path); err == nil {
		lines = strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			out = append(out, line)
			continue
		}
		k, _, ok := strings.Cut(trim, "=")
		if !ok {
			out = append(out, line)
			continue
		}
		k = strings.TrimSpace(k)
		if v, yes := updates[k]; yes {
			out = append(out, k+"="+envEncode(v))
			seen[k] = true
			continue
		}
		out = append(out, line)
	}
	for _, k := range []string{"NSE_HOST", "NSE_USER", "NSE_PASSWORD", "NSE_PORT"} {
		if seen[k] {
			continue
		}
		if v, ok := updates[k]; ok {
			out = append(out, k+"="+envEncode(v))
		}
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o600)
}

func ApplyEnv(cfg Config) {
	_ = os.Setenv("NSE_HOST", cfg.Host)
	_ = os.Setenv("NSE_USER", cfg.User)
	_ = os.Setenv("NSE_PASSWORD", cfg.Password)
	_ = os.Setenv("NSE_PORT", cfg.Port)
}

func (c Config) Addr() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}
