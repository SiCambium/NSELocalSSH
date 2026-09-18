package nse

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxProfiles bounds the saved-connection list. It is a sanity limit on a
// hand-maintained local file, not the old five-slot model: connections are
// identified by a stable ID, not by which of five slots they occupy.
const MaxProfiles = 200

// Profile is one saved connection — a site. Name is a human label ("Leeds
// branch"), free to differ from Host; older files that predate labels, and
// entries saved without one, fall back to the host at read time rather
// than having the label overwritten on save.
//
// Password is stored in cleartext in profiles.json (mode 0600), the same
// as it has always been. That is a deliberate, accepted trade-off rather
// than an oversight, and worth revisiting if this file ever holds a large
// number of customer sites.
type Profile struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Port     string `json:"port"`
}

// Label is what the UI shows for a connection: its name if it has one,
// otherwise the host it points at.
func (p Profile) Label() string {
	if strings.TrimSpace(p.Name) != "" {
		return p.Name
	}
	return p.Host
}

type ProfileStore struct {
	ActiveID int `json:"active_id"`
	// NextIDSeq is the ID allocator's high-water mark, persisted so that
	// deleting the newest connection cannot make the next one reuse its
	// ID. Without it a stale reference in an open tab could act on a
	// different site than the one it was rendered for. Files written
	// before this field existed simply start from the highest ID present.
	NextIDSeq int       `json:"next_id,omitempty"`
	Profiles  []Profile `json:"profiles"`
}

func ProfilesPath(settingsPath string) string {
	dir := filepath.Dir(settingsPath)
	if dir == "" || dir == "." {
		return "profiles.json"
	}
	return filepath.Join(dir, "profiles.json")
}

func (s ProfileStore) Get(id int) *Profile {
	for i := range s.Profiles {
		if s.Profiles[i].ID == id {
			p := s.Profiles[i]
			return &p
		}
	}
	return nil
}

// NextID allocates an unused connection ID and advances the high-water
// mark, so an ID is never handed out twice even across a delete.
func (s *ProfileStore) NextID() int {
	next := s.NextIDSeq
	for _, p := range s.Profiles {
		if p.ID >= next {
			next = p.ID + 1
		}
	}
	if next < 1 {
		next = 1
	}
	s.NextIDSeq = next + 1
	return next
}

// Upsert adds or replaces a connection. An ID of 0 means "new": one is
// allocated. Unlike the old five-slot version this does NOT overwrite
// Name with Host — a label the user typed is the whole point of a
// connection manager.
func (s *ProfileStore) Upsert(p Profile) (Profile, error) {
	if p.ID == 0 {
		if len(s.Profiles) >= MaxProfiles {
			return Profile{}, fmt.Errorf("cannot store more than %d connections", MaxProfiles)
		}
		p.ID = s.NextID()
	}
	if p.ID < 1 {
		return Profile{}, fmt.Errorf("connection id must be positive")
	}
	if p.Port == "" {
		p.Port = "22"
	}
	p.Name = strings.TrimSpace(p.Name)
	found := false
	for i := range s.Profiles {
		if s.Profiles[i].ID == p.ID {
			s.Profiles[i] = p
			found = true
			break
		}
	}
	if !found {
		s.Profiles = append(s.Profiles, p)
	}
	return p, nil
}

func (s *ProfileStore) Clear(id int) {
	var keep []Profile
	for _, p := range s.Profiles {
		if p.ID != id {
			keep = append(keep, p)
		}
	}
	s.Profiles = keep
	if s.ActiveID == id {
		if len(keep) > 0 {
			s.ActiveID = keep[0].ID
		} else {
			s.ActiveID = 0
		}
	}
}

func ReadProfiles(path string) (ProfileStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ProfileStore{}, err
	}
	var store ProfileStore
	if err := json.Unmarshal(raw, &store); err != nil {
		return ProfileStore{}, err
	}
	if store.Profiles == nil {
		store.Profiles = []Profile{}
	}
	return store, nil
}

func WriteProfiles(path string, store ProfileStore) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

func LoadOrInitProfiles(path string, current Config) ProfileStore {
	store, err := ReadProfiles(path)
	if err == nil {
		return store
	}
	store = ProfileStore{ActiveID: 1, Profiles: []Profile{}}
	if current.Host != "" {
		p, err := store.Upsert(Profile{
			ID:       1,
			Host:     current.Host,
			User:     current.User,
			Password: current.Password,
			Port:     current.Port,
		})
		if err == nil {
			store.ActiveID = p.ID
		}
	}
	return store
}

// publicConnections renders the saved connections for the frontend,
// ordered by label so a long list stays navigable, and never including a
// password — only whether one is set.
func publicConnections(store ProfileStore) []map[string]any {
	out := make([]map[string]any, 0, len(store.Profiles))
	for _, p := range store.Profiles {
		if p.Host == "" {
			continue
		}
		out = append(out, map[string]any{
			"id":           p.ID,
			"name":         p.Name,
			"label":        p.Label(),
			"host":         p.Host,
			"user":         p.User,
			"port":         p.Port,
			"password_set": p.Password != "",
			"active":       p.ID == store.ActiveID,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		li := strings.ToLower(out[i]["label"].(string))
		lj := strings.ToLower(out[j]["label"].(string))
		if li != lj {
			return li < lj
		}
		return out[i]["id"].(int) < out[j]["id"].(int)
	})
	return out
}
