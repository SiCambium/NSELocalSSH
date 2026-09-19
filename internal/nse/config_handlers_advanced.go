package nse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// The Advanced section is the free-text CLI escape hatch — the equivalent
// of cnMaestro's user-defined overrides, for settings this app has no
// control for. See overrides.go for why the text is sent verbatim rather
// than parsed.
//
// The stored text is per saved connection and records what was last sent
// to that device, not what is currently on it: the device can be changed
// elsewhere, and a lockout-risk change that is never confirmed gets rolled
// back after it was stored. The UI has to say so.

type overridesRequest struct {
	Text string `json:"text"`
	// Preview asks what would be sent without sending it.
	Preview bool `json:"preview"`
}

func (s *Server) handleConfigOverrides(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfigOverrides(w, r)
	case http.MethodPost:
		s.handlePostConfigOverrides(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// activeConnectionKey identifies which saved connection the stored text
// belongs to. Falling back to the device address keeps overrides separate
// per device even before anything has been saved as a connection.
func (s *Server) activeConnectionKey() string {
	cfg := s.Client.Snapshot()
	store := LoadOrInitProfiles(s.profilesFile(), cfg)
	if store.ActiveID > 0 {
		return strconv.Itoa(store.ActiveID)
	}
	return cfg.Host
}

func (s *Server) handleGetConfigOverrides(w http.ResponseWriter, _ *http.Request) {
	stored := ReadOverrides(OverridesPath(s.settingsFile()))[s.activeConnectionKey()]
	resp := map[string]any{
		"text":       stored.Text,
		"applied_at": nil,
		"guard_line": disableSSHLine,
		"max_bytes":  maxOverrideBytes,
		"line_count": len(OverrideLines(stored.Text)),
		"connection": s.activeConnectionKey(),
	}
	if !stored.AppliedAt.IsZero() {
		resp["applied_at"] = stored.AppliedAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, resp)
}

func (s *Server) handlePostConfigOverrides(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req overridesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(req.Text) > maxOverrideBytes {
		writeSettingsError(w, http.StatusBadRequest,
			fmt.Sprintf("override text is %d bytes; the limit is %d", len(req.Text), maxOverrideBytes))
		return
	}

	lines := OverrideLines(req.Text)
	if err := GuardOverrideLines(lines); err != nil {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}
	keys := OverrideTopLevelKeys(lines)

	// The preview needs the current config to say which entries are new,
	// and so does the apply path — reading it once here keeps the two
	// answers consistent with each other.
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	newEntries := OverrideNewEntries(keys, cfgRaw)

	if req.Preview {
		writeJSON(w, map[string]any{
			"lines":       lines,
			"keys":        keys,
			"new_entries": newEntries,
			"snapshot":    ExtractStanza(cfgRaw, keys),
		})
		return
	}

	// Clearing the box stores the empty text without sending anything:
	// there is no "unsend" for lines already applied, and inventing one
	// would mean guessing at negation syntax for arbitrary commands.
	if len(lines) == 0 {
		if err := s.storeOverride(req.Text); err != nil {
			writeSettingsError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]any{"status": "applied", "lines": []LineResult{},
			"reason": "nothing to send; the saved text was cleared. Anything already applied stays on the device."})
		return
	}

	outcome, err := s.safeApplier().Apply(ConfigBlock{
		Name:  "overrides",
		Lines: lines,
		Risk:  ClassifyRisk("overrides"),
		Keys:  keys,
	})
	if err != nil {
		writeDeviceError(w, err)
		return
	}
	// Stored on anything but an outright rejection: the text reached the
	// device, which is what this records. A provisional change that is
	// never confirmed is rolled back afterwards, which is exactly why the
	// stored copy is labelled as last-applied rather than as active.
	if outcome.Status != "rejected" {
		if err := s.storeOverride(req.Text); err != nil {
			writeSettingsError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, redactOutcome(outcome))
}

func (s *Server) storeOverride(text string) error {
	path := OverridesPath(s.settingsFile())
	store := ReadOverrides(path)
	store[s.activeConnectionKey()] = StoredOverride{Text: text, AppliedAt: time.Now().UTC()}
	return WriteOverrides(path, store)
}
