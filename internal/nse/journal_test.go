package nse

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const journalCfgA = `show config
!
hostname NSE-TEST
timezone Europe/London
management user admin password $crypt$0$SUPERSECRET
!
interface vlan 1
 ip address 172.21.0.1 255.255.0.0
 exit
!
`

func TestJournalRecordsOnlyWhenTheConfigChanged(t *testing.T) {
	j := NewConfigJournal(filepath.Join(t.TempDir(), "journal.json"))
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

	if !j.Record("dev", journalCfgA, now) {
		t.Fatal("the first capture should be recorded")
	}
	if j.Record("dev", journalCfgA, now.Add(time.Minute)) {
		t.Error("an identical capture was recorded again")
	}
	changed := strings.Replace(journalCfgA, "timezone Europe/London", "timezone America/Sao_Paulo", 1)
	if !j.Record("dev", changed, now.Add(2*time.Minute)) {
		t.Error("a changed capture was not recorded")
	}
	if got := len(j.Entries("dev", "")); got != 2 {
		t.Errorf("entries = %d, want 2", got)
	}
}

// A journal is read more often and kept longer than a backup, so it holds
// the redacted text. Storing the admin hash here would spread a secret
// into a file whose whole purpose is to be browsed.
func TestJournalStoresRedactedText(t *testing.T) {
	j := NewConfigJournal(filepath.Join(t.TempDir(), "journal.json"))
	j.Record("dev", journalCfgA, time.Now())

	entries := j.Entries("dev", "")
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	full := j.Entries("dev", entries[0].Hash)
	if full[0].Config == "" {
		t.Fatal("asking for one entry by hash should return its body")
	}
	if strings.Contains(full[0].Config, "SUPERSECRET") {
		t.Error("the stored configuration still carries the admin secret")
	}
	if !strings.Contains(full[0].Config, "hostname NSE-TEST") {
		t.Error("redaction removed more than the secret")
	}
}

// A listing of sixty configurations is megabytes nobody asked to
// download, so bodies only come back for the entry asked for.
func TestJournalListingOmitsBodies(t *testing.T) {
	j := NewConfigJournal(filepath.Join(t.TempDir(), "journal.json"))
	j.Record("dev", journalCfgA, time.Now())
	if got := j.Entries("dev", "")[0].Config; got != "" {
		t.Errorf("a listing carried a body of %d bytes", len(got))
	}
}

// A failed read is not a configuration wipe, and filing it as one would
// put a fictional change in the operator's history.
func TestJournalIgnoresFailedReads(t *testing.T) {
	j := NewConfigJournal(filepath.Join(t.TempDir(), "journal.json"))
	j.Record("dev", journalCfgA, time.Now())
	for _, junk := range []string{"", "show config\n", "%Error processing cli command\n"} {
		if j.Record("dev", junk, time.Now()) {
			t.Errorf("a failed read (%q) was filed as a change", junk)
		}
	}
	if got := len(j.Entries("dev", "")); got != 1 {
		t.Errorf("entries = %d, want the single real one", got)
	}
}

func TestJournalSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	j := NewConfigJournal(path)
	j.Record("dev", journalCfgA, time.Now())

	if got := len(NewConfigJournal(path).Entries("dev", "")); got != 1 {
		t.Errorf("reloaded entries = %d, want 1", got)
	}
}

func TestJournalKeepsDevicesApart(t *testing.T) {
	j := NewConfigJournal(filepath.Join(t.TempDir(), "journal.json"))
	j.Record("site-a", journalCfgA, time.Now())
	if got := len(j.Entries("site-b", "")); got != 0 {
		t.Errorf("site-b has %d entries from site-a's config", got)
	}
}
