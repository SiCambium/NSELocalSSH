package nse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Dev live-reload.
//
// The UI ships embedded (see web/embed.go), so editing web/static during
// development changes nothing until the binary is rebuilt and restarted.
// Setting NSE_DEV_STATIC to that directory serves the files from disk
// instead and turns on a reload channel the page subscribes to, so a saved
// edit shows up on the next repaint.
//
// This is deliberately opt-in and env-gated rather than a build tag: it
// serves arbitrary files out of a directory and streams an unauthenticated
// event, neither of which belongs in a shipped build. With the variable
// unset, none of it is registered and /api/dev/enabled 404s, which is what
// the page uses to decide whether to connect at all.
const devStaticEnv = "NSE_DEV_STATIC"

func devStaticDir() string {
	dir := os.Getenv(devStaticEnv)
	if dir == "" {
		return ""
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return ""
	}
	return dir
}

// devFingerprint hashes every file's path, size and mtime under dir. Any
// edit, addition or deletion changes it. Polling is used rather than an
// fsnotify dependency: this is a handful of files on a dev box, and the
// cost of a walk every few hundred milliseconds is not worth a new
// third-party dependency in a tool that ships to operators.
func devFingerprint(dir string) string {
	var entries []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		entries = append(entries, fmt.Sprintf("%s:%d:%d", path, info.Size(), info.ModTime().UnixNano()))
		return nil
	})
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(fmt.Sprint(entries)))
	return hex.EncodeToString(sum[:])
}

func (s *Server) registerDevReload(mux *http.ServeMux, dir string) {
	mux.HandleFunc("/api/dev/enabled", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"dev": true, "static": dir})
	})

	mux.HandleFunc("/api/dev/reload", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher.Flush()

		last := devFingerprint(dir)
		ticker := time.NewTicker(400 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if now := devFingerprint(dir); now != last {
					last = now
					fmt.Fprint(w, "data: reload\n\n")
					flusher.Flush()
				}
			}
		}
	})
}
