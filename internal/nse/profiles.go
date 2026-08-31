package nse

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const MaxProfiles = 5

type Profile struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Port     string `json:"port"`
}

type ProfileStore struct {
	ActiveID int       `json:"active_id"`
	Profiles []Profile `json:"profiles"`
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

func (s *ProfileStore) Upsert(p Profile) error {
	if p.ID < 1 || p.ID > MaxProfiles {
		return fmt.Errorf("slot must be between 1 and %d", MaxProfiles)
	}
	p.Name = p.Host
	if p.Port == "" {
		p.Port = "22"
	}
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
	s.ActiveID = p.ID
	return nil
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
		_ = store.Upsert(Profile{
			ID:       1,
			Name:     current.Host,
			Host:     current.Host,
			User:     current.User,
			Password: current.Password,
			Port:     current.Port,
		})
	}
	return store
}

func publicSlots(store ProfileStore) []map[string]any {
	byID := map[int]Profile{}
	for _, p := range store.Profiles {
		byID[p.ID] = p
	}
	slots := make([]map[string]any, 0, MaxProfiles)
	for id := 1; id <= MaxProfiles; id++ {
		p, ok := byID[id]
		if !ok || p.Host == "" {
			slots = append(slots, map[string]any{
				"id":           id,
				"name":         "",
				"host":         "",
				"user":         "",
				"port":         "22",
				"password_set": false,
				"empty":        true,
			})
			continue
		}
		slots = append(slots, map[string]any{
			"id":           p.ID,
			"name":         p.Name,
			"host":         p.Host,
			"user":         p.User,
			"port":         p.Port,
			"password_set": p.Password != "",
			"empty":        false,
		})
	}
	return slots
}
