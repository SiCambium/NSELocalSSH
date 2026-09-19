package nse

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryFoldAveragesWithinABucket(t *testing.T) {
	h := &HistoryStore{devices: map[string]*historyDevice{}}
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	// Three samples inside the same minute average, rather than the last
	// one winning: a bucket is the rate over its window.
	h.Record("dev", "eth1", 100, 10, base.Add(5*time.Second))
	h.Record("dev", "eth1", 200, 20, base.Add(25*time.Second))
	h.Record("dev", "eth1", 300, 30, base.Add(45*time.Second))

	got := h.Range("dev", time.Hour, base.Add(time.Minute))
	if len(got) != 1 || len(got[0].Points) != 1 {
		t.Fatalf("want one series with one bucket, got %+v", got)
	}
	p := got[0].Points[0]
	if p.RxBps != 200 || p.TxBps != 20 || p.N != 3 {
		t.Errorf("bucket = %+v, want mean rx 200 tx 20 over 3 samples", p)
	}
	if p.T != base.Unix() {
		t.Errorf("bucket start = %d, want the truncated minute %d", p.T, base.Unix())
	}
}

func TestHistoryDropsWhatAgedOut(t *testing.T) {
	h := &HistoryStore{devices: map[string]*historyDevice{}}
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	h.Record("dev", "eth1", 1, 1, base)
	later := base.Add(historyFineSpan + time.Hour)
	h.Record("dev", "eth1", 2, 2, later)

	pts := h.Range("dev", historyFineSpan, later)[0].Points
	for _, p := range pts {
		if p.T == base.Unix() {
			t.Fatal("a sample older than the fine span should have been dropped")
		}
	}
	if len(pts) != 1 {
		t.Errorf("want only the recent bucket, got %d", len(pts))
	}
}

func TestHistoryKeepsDevicesApart(t *testing.T) {
	h := &HistoryStore{devices: map[string]*historyDevice{}}
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	h.Record("site-a", "eth1", 100, 1, now)
	h.Record("site-b", "eth1", 900, 9, now)

	a := h.Range("site-a", time.Hour, now)
	if len(a) != 1 || a[0].Points[0].RxBps != 100 {
		t.Errorf("site-a = %+v, want only its own sample", a)
	}
	if got := h.Range("site-c", time.Hour, now); len(got) != 0 {
		t.Errorf("an unsampled device should have no history, got %+v", got)
	}
}

func TestHistoryRangePicksResolutionFromWindow(t *testing.T) {
	h := &HistoryStore{devices: map[string]*historyDevice{}}
	base := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	// Two samples a minute apart: two fine buckets, one coarse bucket.
	h.Record("dev", "eth1", 100, 1, base)
	h.Record("dev", "eth1", 300, 3, base.Add(time.Minute))
	now := base.Add(2 * time.Minute)

	if n := len(h.Range("dev", time.Hour, now)[0].Points); n != 2 {
		t.Errorf("a one-hour window should read the minute series, got %d points", n)
	}
	if n := len(h.Range("dev", 7*24*time.Hour, now)[0].Points); n != 1 {
		t.Errorf("a seven-day window should read the quarter-hour series, got %d points", n)
	}
}

func TestHistorySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	h := NewHistoryStore(path)
	h.Record("dev", "eth1", 512, 64, now)
	h.Flush()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("history file was not written: %v", err)
	}

	reopened := NewHistoryStore(path)
	got := reopened.Range("dev", time.Hour, now)
	if len(got) != 1 || len(got[0].Points) != 1 || got[0].Points[0].RxBps != 512 {
		t.Errorf("reloaded history = %+v, want the sample written before the restart", got)
	}
}

func TestNewHistoryStoreToleratesRubbishOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// History is a convenience. A corrupt file starts empty rather than
	// taking the app down with it.
	h := NewHistoryStore(path)
	if got := h.Range("dev", time.Hour, time.Now()); len(got) != 0 {
		t.Errorf("want an empty store, got %+v", got)
	}
}
