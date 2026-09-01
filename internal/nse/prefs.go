package nse

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Prefs struct {
	LiveConntrack bool `json:"live_conntrack"`
	IPLookup      bool `json:"ip_lookup"`
}

func PrefsPath(settingsPath string) string {
	dir := filepath.Dir(settingsPath)
	if dir == "" || dir == "." {
		return "prefs.json"
	}
	return filepath.Join(dir, "prefs.json")
}

func ReadPrefs(path string) Prefs {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Prefs{}
	}
	var p Prefs
	if err := json.Unmarshal(raw, &p); err != nil {
		return Prefs{}
	}
	return p
}

func WritePrefs(path string, p Prefs) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}
