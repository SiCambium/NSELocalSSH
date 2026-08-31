package main

import (
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os/exec"

	webview "github.com/webview/webview_go"

	"nse-cli/internal/nse"
	"nse-cli/web"
)

func main() {
	cfg := nse.LoadConfig()
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("NSE 3000 Status")
	w.SetSize(1280, 860, webview.HintNone)

	client := nse.NewClient(cfg)
	defer client.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		w.SetHtml(errorHTML("Could not start the local status server", err.Error()))
		w.Run()
		return
	}
	defer ln.Close()

	srv := &nse.Server{Client: client, Static: web.Static, SettingsPath: nse.WritableSettingsPath()}
	go func() {
		if err := http.Serve(ln, srv.Handler()); err != nil && err != http.ErrServerClosed {
			log.Printf("status server: %v", err)
		}
	}()

	url := "http://" + ln.Addr().String()
	if cfg.Password == "" {
		url += "/#settings"
	}

	// Exposed to the page as window.nseOpenInBrowser() so the UI's "Open in
	// Browser" button can hand the same session off to the system default
	// browser. This is additive, not a mode switch: the app window and its
	// server keep running regardless of what happens to that browser tab,
	// so closing the browser never affects "app mode" — the .app bundle
	// only ever launches this binary, so double-clicking the icon always
	// comes up as the native window.
	if err := w.Bind("nseOpenInBrowser", func() {
		if err := exec.Command("open", url).Start(); err != nil {
			log.Printf("open in browser: %v", err)
		}
	}); err != nil {
		log.Printf("bind nseOpenInBrowser: %v", err)
	}

	log.Printf("NSE desktop app serving %s (device %s)", url, cfg.Addr())
	w.Navigate(url)
	w.Run()
}

func errorHTML(title, detail string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NSE 3000 Status</title>
<style>
body{font:15px/1.45 -apple-system,BlinkMacSystemFont,sans-serif;background:#111827;color:#e5e7eb;margin:0;padding:48px}
h1{font-size:22px;margin:0 0 12px}
p{color:#9ca3af;max-width:42rem}
</style></head>
<body><h1>%s</h1><p>%s</p></body></html>`, html.EscapeString(title), html.EscapeString(detail))
}
