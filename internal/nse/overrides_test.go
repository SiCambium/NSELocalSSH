package nse

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestOverrideLinesSendsVerbatim is the point of the whole design: the
// text goes to the device as written, because the device tracks context
// itself. Running it through ParseBlockTree instead would close
// "interface eth 3" immediately — hand-typed CLI is not indented — and
// send "no proxy-arp" as a top-level command.
func TestOverrideLinesSendsVerbatim(t *testing.T) {
	text := "!\ninterface eth 3\nno proxy-arp\nexit\n!\n!\nfilter  global-filter\nno application-control\n! \n"
	got := OverrideLines(text)
	want := []string{
		"interface eth 3",
		"no proxy-arp",
		"exit",
		"filter  global-filter",
		"no application-control",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines =\n  %v\nwant\n  %v", got, want)
	}
	// "no proxy-arp" must stay inside its interface, i.e. immediately
	// after the header and before the exit.
	if got[0] != "interface eth 3" || got[1] != "no proxy-arp" {
		t.Error("the sub-context line escaped its block")
	}
}

func TestOverrideLinesHandlesCRLFAndBlanks(t *testing.T) {
	got := OverrideLines("\r\n  hostname Branch  \r\n\r\n!\r\n  timezone Europe/London\r\n")
	want := []string{"hostname Branch", "timezone Europe/London"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestOverrideTopLevelKeys covers what gets snapshotted for rollback.
// Only depth-zero entries name a top-level stanza; a line inside a
// sub-context must not become a key of its own.
func TestOverrideTopLevelKeys(t *testing.T) {
	keys := OverrideTopLevelKeys(OverrideLines(
		"interface eth 3\nno proxy-arp\nexit\nfilter  global-filter\nno application-control\nexit\nno snmp-server\n"))
	want := []string{"interface eth 3", "filter global-filter", "no snmp-server"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
}

// TestOverrideTopLevelKeysNested guards the depth counting: a sub-context
// inside a sub-context must not be mistaken for a top-level entry when
// its exit is reached.
func TestOverrideTopLevelKeysNested(t *testing.T) {
	keys := OverrideTopLevelKeys(OverrideLines(
		"filter global-filter\nfilter precedence 1\nrule-name r1\nexit\nstateful\nexit\nhostname Branch\n"))
	want := []string{"filter global-filter", "hostname Branch"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
}

// TestOverrideTopLevelKeysTolerateMissingExit covers a half-written
// override. An unbalanced exit must not drive the depth negative and turn
// every later line into a key.
func TestOverrideTopLevelKeysTolerateMissingExit(t *testing.T) {
	keys := OverrideTopLevelKeys(OverrideLines("exit\nexit\nhostname Branch\ninterface eth 3\nno proxy-arp\n"))
	want := []string{"hostname Branch", "interface eth 3"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
}

// TestOverrideNewEntries covers the limitation the preview has to state:
// a rollback restores what it snapshotted, so an entry the override
// creates cannot be undone automatically.
func TestOverrideNewEntries(t *testing.T) {
	current := "hostname NSE-Test\ninterface eth 3\n type lan\n!\n"
	keys := []string{"interface eth 3", "interface vlan 999", "hostname NSE-Test", "no snmp-server"}
	got := OverrideNewEntries(keys, current)
	want := []string{"interface vlan 999", "no snmp-server"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("new entries = %v, want %v", got, want)
	}
}

// TestGuardRefusesDisablingSSH is the one refusal. Everything else an
// override can do is recoverable by power-cycling, because a
// lockout-risk change is not saved until confirmed — but disabling SSH
// takes away the channel the undo itself travels over.
func TestGuardRefusesDisablingSSH(t *testing.T) {
	for _, bad := range []string{
		"no management ssh",
		"  no   management   ssh  ",
	} {
		err := GuardOverrideLines([]string{"hostname Branch", bad})
		if err == nil {
			t.Errorf("GuardOverrideLines(%q) = nil, want a refusal", bad)
			continue
		}
		if !strings.Contains(err.Error(), "line 2") {
			t.Errorf("refusal should say which line: %v", err)
		}
	}
}

// TestGuardAllowsEverythingElse keeps the guard narrow. It exists for one
// provable case, not as a general judgement about danger — including
// lines that only change an SSH sub-setting, and ones that are risky but
// recoverable.
func TestGuardAllowsEverythingElse(t *testing.T) {
	for _, ok := range []string{
		"management ssh",
		"no management ssh idle-timeout 300",
		"management ssh idle-timeout 600",
		"no management https",
		"no management telnet",
		"no management cambium-remote",
		"no proxy-arp",
		"shutdown",
	} {
		if err := GuardOverrideLines([]string{ok}); err != nil {
			t.Errorf("GuardOverrideLines(%q) = %v, want nil", ok, err)
		}
	}
}

func TestOverrideStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overrides.json")
	if got := ReadOverrides(path); len(got) != 0 {
		t.Fatalf("a missing file should read as empty, got %v", got)
	}
	now := time.Now().UTC().Truncate(time.Second)
	store := OverrideStore{"3": {Text: "no snmp-server", AppliedAt: now}}
	if err := WriteOverrides(path, store); err != nil {
		t.Fatal(err)
	}
	got := ReadOverrides(path)
	if got["3"].Text != "no snmp-server" || !got["3"].AppliedAt.Equal(now) {
		t.Errorf("round trip = %+v", got["3"])
	}
	// filepath.Join is correct to use here and correct to return
	// backslashes on Windows, so the expectation has to be built the same
	// way rather than written as a POSIX literal. As a hardcoded string
	// this failed on every Windows run and on no CI run.
	settings := filepath.Join("tmp", "x", ".env")
	want := filepath.Join("tmp", "x", "overrides.json")
	if got := OverridesPath(settings); got != want {
		t.Errorf("OverridesPath(%q) = %q, want %q", settings, got, want)
	}
}
