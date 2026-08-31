package nse

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type settingsRequest struct {
	Action        string `json:"action"`
	Slot          int    `json:"slot"`
	Host          string `json:"host"`
	User          string `json:"user"`
	Password      string `json:"password"`
	Port          string `json:"port"`
	LiveConntrack *bool  `json:"live_conntrack"`
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
		"profiles":       publicSlots(store),
		"live_conntrack": ReadPrefs(s.prefsFile()).LiveConntrack,
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
	slot := req.Slot
	if slot == 0 {
		slot = 1
	}
	if slot < 1 || slot > MaxProfiles {
		writeSettingsError(w, http.StatusBadRequest, "slot must be between 1 and 5")
		return
	}

	cfg := s.Client.Snapshot()
	store := LoadOrInitProfiles(s.profilesFile(), cfg)

	switch action {
	case "open":
		s.openProfile(w, store, slot)
	case "clear":
		s.clearProfile(w, store, slot)
	case "save":
		s.saveProfile(w, store, slot, req, cfg)
	case "prefs":
		s.savePrefs(w, req)
	default:
		writeSettingsError(w, http.StatusBadRequest, "unknown action")
	}
}

func (s *Server) savePrefs(w http.ResponseWriter, req settingsRequest) {
	if req.LiveConntrack == nil {
		writeSettingsError(w, http.StatusBadRequest, "live_conntrack is required")
		return
	}
	prefs := ReadPrefs(s.prefsFile())
	prefs.LiveConntrack = *req.LiveConntrack
	if err := WritePrefs(s.prefsFile(), prefs); err != nil {
		writeSettingsError(w, http.StatusInternalServerError, "could not save settings: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"ok":             true,
		"live_conntrack": prefs.LiveConntrack,
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
	prof := Profile{ID: slot, Name: host, Host: host, User: user, Password: password, Port: port}
	if err := store.Upsert(prof); err != nil {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.persistAndConnect(w, store, prof)
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
		"ok":        true,
		"cleared":   true,
		"active_id": store.ActiveID,
		"profiles":  publicSlots(store),
	})
}

func (s *Server) persistAndConnect(w http.ResponseWriter, store ProfileStore, prof Profile) {
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
	var connErr error
	if !s.SkipConnect {
		connErr = s.Client.ApplyConfig(cfg)
	} else {
		s.Client.mu.Lock()
		s.Client.Cfg = cfg
		s.Client.mu.Unlock()
	}
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
		"profiles":     publicSlots(store),
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
