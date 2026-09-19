package nse

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Site backup.
//
// The profile export beside this is deliberately lossy: it mirrors
// cnMaestro's Group schema, models only display-safe fields, and omits
// every secret by design. That makes it a good interop artifact and a
// useless backup, because a site cannot be rebuilt without its PSKs,
// RADIUS secrets and PPPoE credentials.
//
// This is the other artifact: everything needed to reconstruct the
// device, in the device's own words. `show config` is the running CLI
// configuration and replays as CLI. `service show config` is the internal
// store, which carries the fields `show config` declines to print.
//
// **It contains every secret in cleartext**, because a backup that
// redacts them cannot restore the site — that is the whole trade, and it
// is the operator's to make, not this code's to make quietly. Nothing is
// written to disk by the app: the capture streams to the browser as a
// download and lands wherever the operator chooses to put it. The file
// says what it holds on its first line.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// A download that hands out every credential on the device is not a
	// thing another site's page gets to trigger in a tab this operator
	// happens to have open.
	if !isSameOrigin(r) {
		writeCrossOriginBlocked(w)
		return
	}

	running, ok := s.cli(w, "show config", 30*time.Second)
	if !ok {
		return
	}
	// The internal store is a bonus, not a requirement: a firmware that
	// refuses it still produces a usable running-config backup.
	store, storeErr := s.Client.Run("service show config", 40*time.Second)

	ver, _ := s.Client.Run("show version", 20*time.Second)
	v := ParseVersion(ver)
	name := v.Hostname
	if name == "" {
		name = s.Client.Cfg.Host
	}
	taken := time.Now()

	var b strings.Builder
	fmt.Fprintf(&b, "# NSE site backup\n")
	fmt.Fprintf(&b, "#\n")
	fmt.Fprintf(&b, "# WARNING: this file contains this device's secrets in cleartext,\n")
	fmt.Fprintf(&b, "# including administrator credentials, VPN and RADIUS shared secrets,\n")
	fmt.Fprintf(&b, "# PPPoE and Tailscale credentials and the IPS oinkcode. It is a full\n")
	fmt.Fprintf(&b, "# backup precisely because of that. Store it where you would store the\n")
	fmt.Fprintf(&b, "# device password itself, and rotate everything in it if it leaks.\n")
	fmt.Fprintf(&b, "#\n")
	fmt.Fprintf(&b, "# Device   %s\n", name)
	fmt.Fprintf(&b, "# Model    %s\n", v.Model)
	fmt.Fprintf(&b, "# Serial   %s\n", v.Serial)
	fmt.Fprintf(&b, "# Firmware %s\n", v.SoftwareVersion)
	fmt.Fprintf(&b, "# Address  %s\n", s.Client.Cfg.Addr())
	fmt.Fprintf(&b, "# Taken    %s\n", taken.Format(time.RFC3339))
	fmt.Fprintf(&b, "# Tool     nse-status %s\n", BuildVersion)
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "########## show config ##########\n")
	fmt.Fprintf(&b, "# The running CLI configuration. These lines replay as CLI.\n\n")
	b.WriteString(strings.TrimRight(stripCLI(running, "show config"), "\n"))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "########## service show config ##########\n")
	if storeErr != nil {
		fmt.Fprintf(&b, "# Unavailable on this firmware: %v\n", storeErr)
	} else {
		fmt.Fprintf(&b, "# The device's internal configuration store, carrying the fields\n")
		fmt.Fprintf(&b, "# `show config` does not print as CLI lines.\n\n")
		b.WriteString(strings.TrimRight(stripCLI(store, "service show config"), "\n"))
	}
	b.WriteString("\n")

	filename := unsafeFilenameChars.ReplaceAllString(name, "_")
	if filename == "" {
		filename = "nse"
	}
	filename = fmt.Sprintf("%s-backup-%s.txt", filename, taken.Format("20060102-1504"))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write([]byte(b.String()))
}
