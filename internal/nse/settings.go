package nse

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type settingsRequest struct {
	Action string `json:"action"`
	// ID identifies a saved connection. Zero means "a new one" on save.
	// Slot is the old five-slot field, still accepted so an older frontend
	// (or a bookmarked request) keeps working; ID wins when both are set.
	ID            int    `json:"id"`
	Slot          int    `json:"slot"`
	Name          string `json:"name"`
	Host          string `json:"host"`
	User          string `json:"user"`
	Password      string `json:"password"`
	Port          string `json:"port"`
	LiveConntrack *bool  `json:"live_conntrack"`
	IPLookup      *bool  `json:"ip_lookup"`
	VPNDiagnose   *bool  `json:"vpn_diagnose"`

	// APIKey is write-only, like Password: an empty string means "keep the
	// existing key", and it is never read back — see handleGetSettings, which
	// reports only whether one is set.
	APIKey *string `json:"api_key"`
}

func (s *Server) settingsFile() string {
	if s.SettingsPath != "" {
		return s.SettingsPath
	}
	return WritableSettingsPath()
}

func (s *Server) profilesFile() string {
	return ProfilesPath(s.settingsFile())
}

func (s *Server) prefsFile() string {
	return PrefsPath(s.settingsFile())
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetSettings(w, r)
	case http.MethodPost, http.MethodPut:
		s.handleSaveSettings(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	cfg := s.Client.Snapshot()
	store := LoadOrInitProfiles(s.profilesFile(), cfg)
	active := store.ActiveID
	if active == 0 {
		active = 1
	}
	cur := store.Get(active)
	host, user, port, pwSet := cfg.Host, cfg.User, cfg.Port, cfg.Password != ""
	if cur != nil && cur.Host != "" {
		host, user, port, pwSet = cur.Host, cur.User, cur.Port, cur.Password != ""
	}
	writeJSON(w, map[string]any{
		"host":           host,
		"user":           user,
		"port":           port,
		"password_set":   pwSet,
		"file":           s.settingsFile(),
		"profiles_file":  s.profilesFile(),
		"active_id":      active,
		"connections":    publicConnections(store),
		"profiles":       publicConnections(store),
		"live_conntrack": ReadPrefs(s.prefsFile()).LiveConntrack,
		"ip_lookup":      ReadPrefs(s.prefsFile()).IPLookup,
		"vpn_diagnose":   ReadPrefs(s.prefsFile()).VPNDiagnose,
		// Never the key itself, only whether one exists — the same treatment
		// the device password gets.
		"api_key_set": strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")) != "",
	})
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req settingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "save"
	}

	cfg := s.Client.Snapshot()
	store := LoadOrInitProfiles(s.profilesFile(), cfg)

	// A save may legitimately carry no id (a brand-new connection); open
	// and clear must name an existing one.
	id := req.ID
	if id == 0 {
		id = req.Slot
	}
	if action != "save" && action != "prefs" {
		if id < 1 {
			writeSettingsError(w, http.StatusBadRequest, "id is required")
			return
		}
		if store.Get(id) == nil {
			writeSettingsError(w, http.StatusNotFound, "no saved connection with that id")
			return
		}
	}

	switch action {
	case "open":
		s.openProfile(w, store, id)
	case "clear":
		s.clearProfile(w, store, id)
	case "save":
		s.saveProfile(w, store, id, req, cfg)
	case "prefs":
		s.savePrefs(w, req)
	case "api_key":
		s.saveAPIKey(w, req)
	case "api_key_clear":
		s.clearAPIKey(w)
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
	}
}

// saveAPIKey stores the OpenRouter key used for AI-assisted VPN diagnosis.
//
// Write-only, like the device password: an empty value means "keep what is
// there" rather than "clear it", and clearing is an explicit action. The key
// lands in the same 0600 .env as the device credentials and is never returned.
func (s *Server) saveAPIKey(w http.ResponseWriter, req settingsRequest) {
	if req.APIKey == nil {
		writeSettingsError(w, http.StatusBadRequest, "api_key is required")
		return
	}
	key := strings.TrimSpace(*req.APIKey)
	if key == "" {
		// Distinguish "leave it alone" from "remove it": the frontend sends the
		// clear action when the operator means to remove the key.
		writeJSON(w, map[string]any{"ok": true, "api_key_set": os.Getenv("OPENROUTER_API_KEY") != ""})
		return
	}
	// A value carrying a newline would corrupt the .env and could smuggle a
	// second assignment into it.
	if strings.ContainsAny(key, "\r\n") {
		writeSettingsError(w, http.StatusBadRequest, "the API key cannot contain a line break")
		return
	}
	if err := WriteEnvFile(s.settingsFile(), map[string]string{"OPENROUTER_API_KEY": key}); err != nil {
		writeSettingsError(w, http.StatusInternalServerError, "could not save the API key: "+err.Error())
		return
	}
	// Take effect without a restart, matching how the device credentials behave.
	os.Setenv("OPENROUTER_API_KEY", key)
	writeJSON(w, map[string]any{"ok": true, "api_key_set": true})
}

// clearAPIKey removes the stored key.
func (s *Server) clearAPIKey(w http.ResponseWriter) {
	if err := WriteEnvFile(s.settingsFile(), map[string]string{"OPENROUTER_API_KEY": ""}); err != nil {
		writeSettingsError(w, http.StatusInternalServerError, "could not clear the API key: "+err.Error())
		return
	}
	os.Unsetenv("OPENROUTER_API_KEY")
	writeJSON(w, map[string]any{"ok": true, "api_key_set": false})
}

func (s *Server) savePrefs(w http.ResponseWriter, req settingsRequest) {
	if req.LiveConntrack == nil && req.IPLookup == nil && req.VPNDiagnose == nil {
		writeSettingsError(w, http.StatusBadRequest, "live_conntrack, ip_lookup or vpn_diagnose is required")
		return
	}
	prefs := ReadPrefs(s.prefsFile())
	if req.LiveConntrack != nil {
		prefs.LiveConntrack = *req.LiveConntrack
	}
	if req.IPLookup != nil {
		prefs.IPLookup = *req.IPLookup
	}
	if req.VPNDiagnose != nil {
		prefs.VPNDiagnose = *req.VPNDiagnose
	}
	if err := WritePrefs(s.prefsFile(), prefs); err != nil {
		writeSettingsError(w, http.StatusInternalServerError, "could not save settings: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"ok":             true,
		"live_conntrack": prefs.LiveConntrack,
		"ip_lookup":      prefs.IPLookup,
		"vpn_diagnose":   prefs.VPNDiagnose,
	})
}

func (s *Server) saveProfile(w http.ResponseWriter, store ProfileStore, slot int, req settingsRequest, cur Config) {
	host := strings.TrimSpace(req.Host)
	user := strings.TrimSpace(req.User)
	port := strings.TrimSpace(req.Port)
	if host == "" {
		writeSettingsError(w, http.StatusBadRequest, "IP address / host is required")
		return
	}
	if user == "" {
		writeSettingsError(w, http.StatusBadRequest, "username is required")
		return
	}
	if port == "" {
		port = "22"
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		writeSettingsError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}
	password := req.Password
	if password == "" {
		if existing := store.Get(slot); existing != nil && existing.Password != "" {
			password = existing.Password
		} else {
			password = cur.Password
		}
	}
	if password == "" {
		writeSettingsError(w, http.StatusBadRequest, "password is required")
		return
	}
	prof := Profile{ID: slot, Name: strings.TrimSpace(req.Name), Host: host, User: user, Password: password, Port: port}
	saved, err := store.Upsert(prof)
	if err != nil {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Saving a connection also selects it — that is what the old slot
	// behaviour did, and it is what you want after editing the site you
	// are looking at. Upsert no longer does it implicitly.
	store.ActiveID = saved.ID
	s.persistAndConnect(w, store, saved)
}

func (s *Server) openProfile(w http.ResponseWriter, store ProfileStore, slot int) {
	prof := store.Get(slot)
	if prof == nil || prof.Host == "" {
		writeSettingsError(w, http.StatusBadRequest, "that slot is empty")
		return
	}
	store.ActiveID = slot
	s.persistAndConnect(w, store, *prof)
}

func (s *Server) clearProfile(w http.ResponseWriter, store ProfileStore, slot int) {
	store.Clear(slot)
	if err := WriteProfiles(s.profilesFile(), store); err != nil {
		writeSettingsError(w, http.StatusInternalServerError, "could not save settings: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"ok":          true,
		"cleared":     true,
		"active_id":   store.ActiveID,
		"connections": publicConnections(store),
		"profiles":    publicConnections(store),
	})
}

func (s *Server) persistAndConnect(w http.ResponseWriter, store ProfileStore, prof Profile) {
	// Checked before anything is written: if the switch is going to be
	// refused, neither the profile store nor the .env should have moved on
	// to a device we are not actually going to connect to.
	if a := s.safeApplier(); a.PendingCount() > 0 {
		writeSettingsError(w, http.StatusConflict,
			"a configuration change on the current device is still awaiting confirmation; confirm it or wait for it to roll back before switching")
		return
	}
	if err := WriteProfiles(s.profilesFile(), store); err != nil {
		writeSettingsError(w, http.StatusInternalServerError, "could not save settings: "+err.Error())
		return
	}
	cfg := s.Client.Snapshot()
	cfg.Host = prof.Host
	cfg.User = prof.User
	cfg.Port = prof.Port
	cfg.Password = prof.Password
	if err := WriteEnvFile(s.settingsFile(), map[string]string{
		"NSE_HOST":     cfg.Host,
		"NSE_USER":     cfg.User,
		"NSE_PASSWORD": cfg.Password,
		"NSE_PORT":     cfg.Port,
	}); err != nil {
		writeSettingsError(w, http.StatusInternalServerError, "could not save settings: "+err.Error())
		return
	}
	ApplyEnv(cfg)
	// SwitchDevice clears the per-device caches the old connection left
	// behind, and refuses outright if a change there is still provisional.
	connErr := s.SwitchDevice(cfg)
	resp := map[string]any{
		"ok":           true,
		"saved":        true,
		"host":         cfg.Host,
		"user":         cfg.User,
		"port":         cfg.Port,
		"password_set": true,
		"file":         s.settingsFile(),
		"active_id":    store.ActiveID,
		"name":         prof.Name,
		"connections":  publicConnections(store),
		"profiles":     publicConnections(store),
		"connected":    connErr == nil,
	}
	if connErr != nil {
		resp["detail"] = connErr.Error()
	}
	writeJSON(w, resp)
}

func writeSettingsError(w http.ResponseWriter, code int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}
