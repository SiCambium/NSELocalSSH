package nse

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Configuration change journal.
//
// The device keeps no history of its own configuration. It will tell you
// what the config is now and nothing about what it was, so "who changed
// the firewall last Tuesday" has been a question only the cloud console
// could answer. After the cloud, nobody can.
//
// This is that answer, kept locally. Every time the app reads `show
// config` — which it does constantly, for the dashboard and before every
// risky change — the text is hashed. A hash that differs from the last
// one recorded means the running configuration moved, so the new text is
// filed with a timestamp.
//
// **Entries are redacted before they are stored.** A journal is read far
// more often than a backup and tends to be kept for longer, so it holds
// the same secret-stripped text the Config tab shows rather than the
// cleartext a restore would need. That makes it a change log, not a
// backup: /api/backup is the thing that can rebuild a site.
const (
	journalMaxEntries = 60
	journalMaxBytes   = 8 << 20
)

type JournalEntry struct {
	At     time.Time `json:"at"`
	Hash   string    `json:"hash"`
	Config string    `json:"config,omitempty"`
	Lines  int       `json:"lines"`
}

type ConfigJournal struct {
	mu      sync.Mutex
	path    string
	entries map[string][]JournalEntry // device -> newest last
}

func JournalPath(settingsPath string) string {
	dir := filepath.Dir(settingsPath)
	if dir == "" || dir == "." {
		return "journal.json"
	}
	return filepath.Join(dir, "journal.json")
}

func NewConfigJournal(path string) *ConfigJournal {
	j := &ConfigJournal{path: path, entries: map[string][]JournalEntry{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return j
	}
	var loaded map[string][]JournalEntry
	if err := json.Unmarshal(data, &loaded); err == nil && loaded != nil {
		j.entries = loaded
	}
	return j
}

// Record files a configuration if it differs from the last one filed for
// this device. Returns true when something was actually recorded, which
// is the signal that the running configuration changed.
func (j *ConfigJournal) Record(device, raw string, now time.Time) bool {
	if j == nil || device == "" || raw == "" {
		return false
	}
	clean := SanitizeCLIOutput(stripCLI(raw, "show config"))
	sum := sha256.Sum256([]byte(clean))
	hash := hex.EncodeToString(sum[:])

	j.mu.Lock()
	defer j.mu.Unlock()
	list := j.entries[device]
	if n := len(list); n > 0 && list[n-1].Hash == hash {
		return false
	}
	// A capture that came back empty or error-shaped is not a change, it
	// is a failed read, and filing it would report a configuration wipe
	// that never happened.
	if len(clean) < 40 {
		return false
	}
	list = append(list, JournalEntry{At: now, Hash: hash, Config: clean, Lines: countLines(clean)})
	if len(list) > journalMaxEntries {
		list = list[len(list)-journalMaxEntries:]
	}
	j.entries[device] = list
	j.flushLocked()
	return true
}

func countLines(s string) int {
	n := 0
	for _, c := range s {
		if c == '\n' {
			n++
		}
	}
	return n + 1
}

// Entries lists a device's journal newest first. Bodies are dropped
// unless one entry is asked for by hash, because a listing of sixty full
// configurations is megabytes nobody asked to download.
func (j *ConfigJournal) Entries(device, hash string) []JournalEntry {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	src := j.entries[device]
	out := make([]JournalEntry, 0, len(src))
	for i := len(src) - 1; i >= 0; i-- {
		e := src[i]
		if hash == "" || e.Hash != hash {
			e.Config = ""
		}
		out = append(out, e)
	}
	return out
}

func (j *ConfigJournal) flushLocked() {
	if j.path == "" {
		return
	}
	data, err := json.Marshal(j.entries)
	if err != nil || len(data) > journalMaxBytes {
		return
	}
	tmp := j.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) != nil {
		return
	}
	if os.Rename(tmp, j.path) != nil {
		_ = os.Remove(tmp)
	}
}

func (s *Server) handleJournal(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	entries := s.Journal.Entries(s.Client.Cfg.Host, hash)
	if entries == nil {
		entries = []JournalEntry{}
	}
	writeJSON(w, map[string]any{
		"entries": entries,
		"note":    "Secrets are stripped from every entry. This is a change log, not a backup: /api/backup is the copy that can rebuild a site.",
	})
}
