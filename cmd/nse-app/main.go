package main

import (
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	webview "github.com/webview/webview_go"

	"nse-cli/internal/nse"
	"nse-cli/web"
)

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("nse-app %s\n", nse.BuildVersion)
		os.Exit(0)
	}

	cfg := nse.LoadConfig()
	w := webview.New(false)
	defer w.Destroy()
	// The window title is set before the device is contacted, so it stays
	// model-neutral; the page header shows the real model once show version
	// comes back.
	w.SetTitle("Cambium NSE Status")
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
		// Nothing configured yet: open on Connections, which is where a
		// device is added, rather than on the preferences page.
		url += "/#connections"
	}

	// Exposed to the page as window.nseOpenInBrowser() so the UI's "Open in
	// Browser" button can hand the same session off to the system default
	// browser. This is additive, not a mode switch: the app window and its
	// server keep running regardless of what happens to that browser tab,
	// so closing the browser never affects "app mode" — the .app bundle
	// only ever launches this binary, so double-clicking the icon always
	// comes up as the native window.
	if err := w.Bind("nseOpenInBrowser", func() {
		if err := openInBrowser(url); err != nil {
			log.Printf("open in browser: %v", err)
		}
	}); err != nil {
		log.Printf("bind nseOpenInBrowser: %v", err)
	}

	log.Printf("NSE desktop app %s serving %s (device %s)", nse.BuildVersion, url, cfg.Addr())
	w.Navigate(url)
	w.Run()
}

// browserOpenCommand returns the command that hands a URL to the system's
// default browser on the given GOOS. Split out from openInBrowser so the
// per-platform choice is testable from any host — this binary only builds
// natively for each target (the webview binding needs each platform's own
// C headers), so a cross-compile would never catch a mistake here.
//
// Windows uses url.dll's FileProtocolHandler rather than `cmd /c start`,
// which would need its own quoting dance for the empty-title argument.
// Anything that isn't macOS or Windows gets xdg-open, the freedesktop.org
// standard — correct for the Linux/GTK build and a reasonable default for
// the BSDs.
func browserOpenCommand(goos, url string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{url}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return "xdg-open", []string{url}
	}
}

// openInBrowser launches the URL in the system browser without waiting for
// it: the app window and its server keep running either way, so a browser
// that is slow to start, or missing entirely, must never block the UI
// thread that called this.
func openInBrowser(url string) error {
	name, args := browserOpenCommand(runtime.GOOS, url)
	return runBrowserCommand(name, args)
}

// runBrowserCommand starts the launcher and reports a failure to start —
// most usefully "the launcher isn't installed", which on a minimal Linux
// desktop is a real possibility for xdg-open. The old code discarded this
// distinction, so the button's only failure mode was doing nothing.
func runBrowserCommand(name string, args []string) error {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	// Reap the child rather than leaving a zombie for the life of the app.
	go func() { _ = cmd.Wait() }()
	return nil
}

func errorHTML(title, detail string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Cambium NSE Status</title>
<style>
body{font:15px/1.45 -apple-system,BlinkMacSystemFont,sans-serif;background:#111827;color:#e5e7eb;margin:0;padding:48px}
h1{font-size:22px;margin:0 0 12px}
p{color:#9ca3af;max-width:42rem}
</style></head>
<body><h1>%s</h1><p>%s</p></body></html>`, html.EscapeString(title), html.EscapeString(detail))
}
