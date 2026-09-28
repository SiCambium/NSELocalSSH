package nse

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Local throughput history.
//
// The device keeps none: `show interface brief` and ifconfig report byte
// counters, and the rate is this app's own subtraction of two samples. So
// a chart covering anything longer than "since you opened the window"
// needs the samples kept here, which is what this file does.
//
// Two resolutions, because one does not serve both questions. A minute
// bucket answers "what happened this afternoon" and a quarter-hour bucket
// answers "is this week worse than last", and keeping minute resolution
// for a month would be 43,200 points per series to answer a question
// nobody asks at that zoom.
//
// A bucket holds the mean rate over its window, not the last sample in
// it. For a rate that is the honest aggregate: the last sample of a
// minute is one instant, and showing it as the minute would make a chart
// that disagrees with itself every time the poll interval changed.
const (
	historyFine       = time.Minute
	historyFineSpan   = 24 * time.Hour
	historyCoarse     = 15 * time.Minute
	historyCoarseSpan = 30 * 24 * time.Hour
	historyFlushEvery = time.Minute
)

// HistoryPoint is one bucket: the window's start, and the mean rate over
// it. Count rides along so a bucket still open can be updated in place
// without keeping every sample that formed it.
type HistoryPoint struct {
	T     int64   `json:"t"`
	RxBps float64 `json:"rx"`
	TxBps float64 `json:"tx"`
	N     int     `json:"n"`
}

type historySeries struct {
	Fine   []HistoryPoint `json:"fine"`
	Coarse []HistoryPoint `json:"coarse"`
}

type historyDevice struct {
	Series map[string]*historySeries `json:"series"`
}

// HistoryStore is one file holding every device this installation has
// sampled, keyed by host. Sites are kept apart because a rate from one
// device says nothing about another, and SwitchDevice must not smear them
// together.
//
// ponytail: the whole file is rewritten on each flush. At a minute's
// cadence and a few sites that is a few hundred kilobytes a minute, which
// is nothing; if this ever holds dozens of sites, an append-only log per
// device is the upgrade.
type HistoryStore struct {
	mu        sync.Mutex
	path      string
	devices   map[string]*historyDevice
	dirty     bool
	lastFlush time.Time
}

func HistoryPath(settingsPath string) string {
	dir := filepath.Dir(settingsPath)
	if dir == "" || dir == "." {
		return "history.json"
	}
	return filepath.Join(dir, "history.json")
}

// NewHistoryStore loads what is on disk, or starts empty. A malformed or
// unreadable file is not fatal: history is a convenience, and refusing to
// start the app over it would be the wrong trade.
func NewHistoryStore(path string) *HistoryStore {
	h := &HistoryStore{path: path, devices: map[string]*historyDevice{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return h
	}
	var loaded map[string]*historyDevice
	if err := json.Unmarshal(data, &loaded); err != nil || loaded == nil {
		return h
	}
	for k, v := range loaded {
		if v != nil && v.Series != nil {
			h.devices[k] = v
		}
	}
	return h
}

// Record folds one rate sample into both resolutions for one interface.
func (h *HistoryStore) Record(device, iface string, rxBps, txBps float64, now time.Time) {
	if h == nil || device == "" || iface == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	d := h.devices[device]
	if d == nil {
		d = &historyDevice{Series: map[string]*historySeries{}}
		h.devices[device] = d
	}
	s := d.Series[iface]
	if s == nil {
		s = &historySeries{}
		d.Series[iface] = s
	}

	s.Fine = fold(s.Fine, now, historyFine, historyFineSpan, rxBps, txBps)
	s.Coarse = fold(s.Coarse, now, historyCoarse, historyCoarseSpan, rxBps, txBps)
	h.dirty = true

	if time.Since(h.lastFlush) >= historyFlushEvery {
		h.flushLocked(now)
	}
}

// fold adds a sample to the bucket it belongs in, averaging in place when
// that bucket is already open, and drops whatever has aged out of span.
func fold(points []HistoryPoint, now time.Time, bucket, span time.Duration, rx, tx float64) []HistoryPoint {
	start := now.Truncate(bucket).Unix()
	if n := len(points); n > 0 && points[n-1].T == start {
		p := &points[n-1]
		p.RxBps = (p.RxBps*float64(p.N) + rx) / float64(p.N+1)
		p.TxBps = (p.TxBps*float64(p.N) + tx) / float64(p.N+1)
		p.N++
		return points
	}
	points = append(points, HistoryPoint{T: start, RxBps: rx, TxBps: tx, N: 1})

	cutoff := now.Add(-span).Unix()
	first := 0
	for first < len(points) && points[first].T < cutoff {
		first++
	}
	if first > 0 {
		points = append(points[:0], points[first:]...)
	}
	return points
}

// HistorySeriesOut is what the API hands the frontend: one interface's
// points over the requested window, already at the right resolution.
type HistorySeriesOut struct {
	Name   string         `json:"name"`
	Points []HistoryPoint `json:"points"`
}

// Range returns every interface's history for a device over the window,
// choosing resolution from the window: anything up to a day is worth
// minute detail, anything longer is not.
func (h *HistoryStore) Range(device string, window time.Duration, now time.Time) []HistorySeriesOut {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	d := h.devices[device]
	if d == nil {
		return []HistorySeriesOut{}
	}
	cutoff := now.Add(-window).Unix()
	out := make([]HistorySeriesOut, 0, len(d.Series))
	for name, s := range d.Series {
		src := s.Coarse
		if window <= historyFineSpan {
			src = s.Fine
		}
		pts := make([]HistoryPoint, 0, len(src))
		for _, p := range src {
			if p.T >= cutoff {
				pts = append(pts, p)
			}
		}
		out = append(out, HistorySeriesOut{Name: name, Points: pts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Flush writes the store out regardless of cadence. Called on shutdown so
// the last minute of samples is not lost.
func (h *HistoryStore) Flush() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.flushLocked(time.Now())
}

// flushLocked writes via a temporary file and a rename, so a crash or a
// full disk mid-write leaves the previous history intact rather than a
// truncated file that the next start would discard entirely.
func (h *HistoryStore) flushLocked(now time.Time) {
	if !h.dirty || h.path == "" {
		return
	}
	data, err := json.Marshal(h.devices)
	if err != nil {
		return
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, h.path); err != nil {
		_ = os.Remove(tmp)
		return
	}
	h.dirty = false
	h.lastFlush = now
}
