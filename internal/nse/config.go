package nse

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
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
	writable := WritableSettingsPathFrom(exe, wd, home)
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
	if home != "" {
		add(filepath.Join(home, ".config", "nse-status", ".env"))
		add(filepath.Join(home, "Library", "Application Support", "NSE Status", ".env"))
	}
	out = append(out, filepath.Clean(writable))
	return out
}

func WritableSettingsPath() string {
	exe, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	wd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	return WritableSettingsPathFrom(exe, wd, home)
}

func WritableSettingsPathFrom(exe, wd, home string) string {
	if exe != "" && filepath.Base(filepath.Dir(exe)) == "MacOS" && home != "" {
		return filepath.Join(home, "Library", "Application Support", "NSE Status", ".env")
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
