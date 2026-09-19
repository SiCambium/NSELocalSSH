package nse

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Advanced overrides are a free-text CLI escape hatch, matching what
// cnMaestro offers for settings this app has no control for. The text is
// sent to the device verbatim, one line at a time, in the order written.
//
// It is deliberately NOT run through ParseBlockTree. That parser reads
// `show config` output, where a block's contents are indented, and it
// closes a block when a line is not indented past it. Hand-typed CLI is
// not indented:
//
//	interface eth 3
//	no proxy-arp
//	exit
//
// so the parser would close "interface eth 3" immediately and send
// "no proxy-arp" as a top-level command — a different command entirely.
// The device tracks context itself as lines arrive, exactly as it does
// when a human pastes into the CLI, so passing the lines through
// unchanged is both simpler and more faithful.

// maxOverrideBytes bounds the stored text. Generous for a handful of
// stanzas, small enough that a paste accident cannot fill a config file.
const maxOverrideBytes = 64 * 1024

// OverrideLines turns override text into the lines to send: blank lines
// and "!" separators are dropped, everything else is passed through with
// only surrounding whitespace trimmed.
//
// "!" is a separator in `show config` output rather than a command; the
// device has never been observed to accept one as input, so sending them
// would risk an error partway through a sequence that is otherwise fine.
func OverrideLines(text string) []string {
	var out []string
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line == "!" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// OverrideTopLevelKeys returns the top-level config entries the override
// touches, for SafeApplier to snapshot as a rollback pre-image.
//
// Context is tracked the way the device tracks it: a line that opens a
// known sub-context descends a level, "exit" comes back up, and only
// lines at depth zero name a top-level entry. Nesting is counted rather
// than assumed one-deep, since a sub-context can itself contain one
// ("filter global-filter" holding "filter precedence 1").
func OverrideTopLevelKeys(lines []string) []string {
	var keys []string
	seen := map[string]bool{}
	depth := 0
	for _, line := range lines {
		normalized := normalizeSpaces(line)
		if normalized == "exit" {
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth == 0 && !seen[normalized] {
			seen[normalized] = true
			keys = append(keys, normalized)
		}
		if isBlockOpener(normalized) {
			depth++
		}
	}
	return keys
}

// OverrideNewEntries reports which of an override's top-level keys do not
// exist in the device's current config.
//
// This matters because a rollback can only restore what it snapshotted.
// ExtractStanza finds nothing for an entry that did not exist, so undoing
// a change that CREATED one leaves it behind — and emitting "no <header>"
// to remove it would be guessing at syntax this project has never
// confirmed. The honest handling is to say so before applying.
func OverrideNewEntries(keys []string, currentConfig string) []string {
	tree := ParseBlockTree(currentConfig)
	var out []string
	for _, key := range keys {
		if tree.Find(key) != nil {
			continue
		}
		if _, ok := tree.Leaf(key); ok {
			continue
		}
		out = append(out, key)
	}
	return out
}

// disableSSHLine is the one override line that is refused outright.
const disableSSHLine = "no management ssh"

// GuardOverrideLines rejects an override that would sever the transport
// this app runs on.
//
// This is not a general "that looks dangerous" filter — the whole point of
// an escape hatch is to reach settings the UI will not offer, and
// SafeApplier plus not-saving-until-confirmed already means a
// power-cycle recovers a bad change. "no management ssh" is different in
// kind: it disables the SSH service that both the change and its undo
// travel over, so the undo provably cannot be delivered. Refusing it is
// the only point at which that outcome can still be avoided.
//
// It is matched exactly, after whitespace normalization, so that
// "no management ssh idle-timeout 300" — which changes a sub-setting and
// leaves SSH enabled — still goes through.
func GuardOverrideLines(lines []string) error {
	for i, line := range lines {
		if normalizeSpaces(line) == disableSSHLine {
			return fmt.Errorf("line %d is %q, which disables the SSH service this app and its own rollback both depend on; "+
				"the change could not be undone afterwards. Change it from the device console instead", i+1, disableSSHLine)
		}
	}
	return nil
}

// StoredOverride is the text last applied to one connection. It records
// what was sent, not what is currently on the device: the device can be
// changed elsewhere, and a lockout-risk change that is never confirmed is
// rolled back after it was stored.
type StoredOverride struct {
	Text      string    `json:"text"`
	AppliedAt time.Time `json:"applied_at"`
}

// OverrideStore maps a saved connection's ID to its last-applied text.
type OverrideStore map[string]StoredOverride

// OverridesPath puts overrides.json beside the writable settings file,
// with profiles.json, prefs.json and known_hosts.json.
func OverridesPath(settingsPath string) string {
	dir := filepath.Dir(settingsPath)
	if dir == "" || dir == "." {
		return "overrides.json"
	}
	return filepath.Join(dir, "overrides.json")
}

func ReadOverrides(path string) OverrideStore {
	raw, err := os.ReadFile(path)
	if err != nil {
		return OverrideStore{}
	}
	var store OverrideStore
	if err := json.Unmarshal(raw, &store); err != nil {
		return OverrideStore{}
	}
	if store == nil {
		store = OverrideStore{}
	}
	return store
}

func WriteOverrides(path string, store OverrideStore) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}
