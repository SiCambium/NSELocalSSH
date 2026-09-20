package nse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Changing the device's administrator password.
//
// This is the one setting a factory-fresh unit must have changed before
// it is left in a customer's rack, so it is the gate on configuring a
// site from scratch without the cloud.
//
// It is also the most delicate write in the app, for a reason that has
// nothing to do with the CLI. SafeApplier proves a risky change did not
// cut off access by opening a brand-new SSH login, and that login reads
// the client's stored credential at dial time. Change the password and
// leave the stored credential alone, and the probe authenticates with the
// password the change just invalidated: it fails, the change is reported
// unreachable, and a change that worked perfectly is rolled back. The
// credential therefore moves *before* the apply and moves back if the
// apply does not stand.

// AdminPasswordLine sets the administrator password.
//
// UNCONFIRMED. `show config` prints this leaf as
//
//	management user admin password $crypt$0$<value>
//
// which is CONFIRMED as the read form, and the device stores the value
// obfuscated. What is *not* confirmed is that the same leaf accepts a
// plaintext password and does the obfuscation itself, which is the
// assumption here. Nothing in the captures proves it either way.
//
// Being wrong is safe in one direction only: if the device stores the
// plaintext literally, the next login needs that literal string, which is
// what this app then holds. If it rejects the line outright, the error
// surfaces and nothing changed. If it were to store something neither the
// old nor the new password unlocks, the safe-apply probe fails and the
// change is undone — and the device still boots the old config, because
// nothing is saved until confirmed.
//
// Confirm this on a lab unit before relying on it in the field.
func AdminPasswordLine(user, password string) string {
	return fmt.Sprintf("management user %s password %s", user, password)
}

type adminPasswordRequest struct {
	Password string `json:"password"`
	Confirm  string `json:"confirm"`
}

// validateAdminPassword refuses what the device or this app cannot carry.
// It deliberately does not impose a complexity policy: that belongs to
// the operator's own rules, and inventing one here would reject passwords
// the device accepts.
func validateAdminPassword(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("the new password is empty")
	case len(p) < 8:
		return fmt.Errorf("the new password is shorter than 8 characters")
	case strings.ContainsAny(p, "\r\n"):
		// Caught globally too, but saying it here names the real problem.
		return fmt.Errorf("the new password contains a line break")
	case strings.ContainsAny(p, " \t"):
		return fmt.Errorf("the new password contains a space or tab, which the CLI would read as the end of the value")
	}
	return nil
}

func (s *Server) handleConfigPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}
	var req adminPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSettingsError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Password != req.Confirm {
		writeSettingsError(w, http.StatusBadRequest, "the two passwords do not match")
		return
	}
	if err := validateAdminPassword(req.Password); err != nil {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}

	before := s.Client.Snapshot()
	user := before.User
	if user == "" {
		user = "admin"
	}

	// The credential moves first, so the reachability probe dials with
	// the password the device is about to have.
	s.Client.SetPasswordInPlace(req.Password)

	outcome, err := s.safeApplier().Apply(ConfigBlock{
		Name:  "admin password",
		Lines: []string{AdminPasswordLine(user, req.Password)},
		Risk:  ClassifyRisk("admin-password"),
		Keys:  []string{"management user " + user + " password"},
	})
	if err != nil || outcome.Status == "error" || outcome.Status == "unreachable" {
		// The change did not stand. Put the credential back, or this app
		// is the thing that can no longer reach the device.
		s.Client.SetPasswordInPlace(before.Password)
		if err != nil {
			writeDeviceError(w, err)
			return
		}
		writeJSON(w, map[string]any{"outcome": outcome, "credential_kept": true})
		return
	}

	// Saved connections hold the password too, and a restart would
	// otherwise come back with the old one.
	saved := s.persistPassword(req.Password)

	writeJSON(w, map[string]any{
		"outcome":          outcome,
		"credential_moved": true,
		"profile_updated":  saved,
	})
}

// persistPassword writes the new credential into the live connection's
// saved profile. A failure here is reported rather than fatal: the
// running app still works, it is the next start that would surprise
// someone, and they need to be told which it is.
func (s *Server) persistPassword(password string) bool {
	path := s.profilesFile()
	store, err := ReadProfiles(path)
	if err != nil {
		return false
	}
	p := store.Get(store.ActiveID)
	if p == nil {
		return false
	}
	updated := *p
	updated.Password = password
	if _, err := store.Upsert(updated); err != nil {
		return false
	}
	return WriteProfiles(path, store) == nil
}
