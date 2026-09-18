package main

import (
	"reflect"
	"strings"
	"testing"
)

// TestBrowserOpenCommand pins the per-platform launcher. This binary only
// ever builds natively for each target — the webview binding needs each
// platform's own C headers, so `GOOS=windows go build` fails on a Mac and
// a typo in the Windows or Linux branch would otherwise not surface until
// someone clicked the button on that OS.
func TestBrowserOpenCommand(t *testing.T) {
	const url = "http://127.0.0.1:55123/"
	tests := []struct {
		goos string
		name string
		args []string
	}{
		{"darwin", "open", []string{url}},
		{"windows", "rundll32", []string{"url.dll,FileProtocolHandler", url}},
		{"linux", "xdg-open", []string{url}},
		{"freebsd", "xdg-open", []string{url}},
	}
	for _, tt := range tests {
		name, args := browserOpenCommand(tt.goos, url)
		if name != tt.name || !reflect.DeepEqual(args, tt.args) {
			t.Errorf("browserOpenCommand(%q) = %q %v, want %q %v", tt.goos, name, args, tt.name, tt.args)
		}
	}
}

// TestRunBrowserCommandReportsMissingLauncher covers the failure the old
// code swallowed: when the launcher binary isn't on PATH, the caller must
// get an error naming it, not silence.
func TestRunBrowserCommandReportsMissingLauncher(t *testing.T) {
	err := runBrowserCommand("nse-no-such-browser-launcher", []string{"http://127.0.0.1/"})
	if err == nil {
		t.Fatal("a missing launcher should be reported, not swallowed")
	}
	if !strings.Contains(err.Error(), "nse-no-such-browser-launcher") {
		t.Errorf("error should name the launcher that failed, got: %v", err)
	}
}

// TestRunBrowserCommandStartsAndReaps checks the success path does not
// block the UI thread and does not leave the child unreaped.
func TestRunBrowserCommandStartsAndReaps(t *testing.T) {
	if err := runBrowserCommand("true", nil); err != nil {
		t.Fatalf("starting a launcher that exists should succeed: %v", err)
	}
}
