# NSE Local SSH

A local-first read/write configuration tool for Cambium NSE3000/NSE4000 firewalls. It talks to the device directly over SSH — no cloud (cnMaestro) dependency — so it works before a unit is cloud-connected, or any time a change is faster to make locally than through a cloud round-trip.

This is a personal tool, not an official Cambium product.

## What it does

**Status dashboard** (read-only, polls `show` / `service show` commands): Overview, Throughput, Details, Memory, Connection tracking, Interfaces, VLANs, Routing, DHCP (pools + MAC bindings), Neighbors, Tunnels (Starlink, client VPN, Tailscale), Traffic, Events, and a raw Config viewer with secrets stripped.

**Configuration** (read/write, applied over the same SSH session): Network (VLANs, DHCP scopes, physical LAN port switchport config), WAN (DHCP/static/PPPoE, load balancing, bandwidth, connection health, enabling a LAN port as a new WAN, moving a WAN to a different physical port), Management, Groups (User/IP/Application), DNS, Threat Protection, Firewall, and VPN.

**License-aware UI**: reads `show feature-license` and greys out (rather than hides) any control gated behind NSE Security Plus, matching cnMaestro's own convention.

**Multi-site connections**: saved connections for every site you manage, each with its own label, address, username and SSH port. Switch between them from the header, or manage the list in Settings. One connection is live at a time — opening a site closes the previous SSH session — and a switch is refused while a configuration change on the current device is still awaiting confirmation, since its rollback snapshot belongs to that device and must not be replayed onto another. Connections live in `profiles.json` next to the settings `.env`, **including their passwords in cleartext** (file mode `0600`); treat that file accordingly.

**Profile export**: produces a JSON profile in the same schema as cnMaestro's own NSE Group export, so a profile built here is interchangeable with cnMaestro's profile library.

**Works without `service show cloud-json-config`**: configuration reads prefer that command, whose JSON matches cnMaestro's export schema field-for-field, but not every firmware, model, or account has it. When the device rejects it, the same structure is derived from `show config` instead — the one read command every unit supports. A few values exist only in the JSON (VLAN names, the per-VLAN port-scan flag, and the feature license, which is read from its own command on export); the UI marks those as unknown rather than guessing, and everything else — VLANs, DHCP scopes, WAN settings, DNS, threat protection, firewall, VPN, management — is identical either way.

### Safety mechanism

Any change that could plausibly lock you out of the device (WAN edits, LAN port VLAN/trunk assignment, management access, HA, the admin password, free-text CLI overrides) goes through a safe-apply path instead of being sent directly:

1. Snapshot the device's current config for the affected section(s).
2. Apply the change.
3. Open a **brand-new** SSH connection (not the one that made the change — an already-open channel can survive some settings changes and would prove nothing) to confirm the device is still reachable.
4. If unreachable, or if the change only partially applied, automatically roll back to the snapshot.
5. If reachable, hold the change **provisional** for 60 seconds — confirm it in the UI, or it rolls back automatically.

Everything else applies directly and reports success or failure immediately.

## Running it

### Desktop app (macOS)

Builds a native window (WKWebView) around the Go backend — no browser tab required. A menu action can also open the same running session in a real browser without disrupting the app window.

```bash
cp .env.example .env   # set NSE_PASSWORD
sh scripts/package-macos.sh
open "dist/NSE Status.app"
```

Use **Settings** in the app to set the device's IP address, username, and password. The desktop app stores those in `~/Library/Application Support/NSE Status/.env`.

### Browser only

```bash
cp .env.example .env   # set NSE_PASSWORD
go run ./cmd/nse-status
```

Open http://127.0.0.1:8080

### Windows

Both modes run on Windows. The quickest route is a prebuilt binary from the repo's [Releases](https://github.com/SiCambium/NSELocalSSH/releases) page — no toolchain needed:

- `NSE-Status-windows-amd64.exe` — the desktop app (native window via WebView2).
- `nse-status_<version>_windows_amd64.exe` — browser mode; serves http://127.0.0.1:8080 and prints to a console window.

To build from source instead, browser mode needs nothing but Go:

```powershell
copy .env.example .env   # then set NSE_PASSWORD
go build -o nse-status.exe ./cmd/nse-status
.\nse-status.exe
```

The desktop app additionally needs CGO and a C++ toolchain (MinGW-w64, e.g. `choco install mingw`), and must be built **on** Windows — it does not cross-compile from macOS or Linux, because the WebView2 binding needs the Windows C headers:

```powershell
$env:CGO_ENABLED=1
go build -ldflags "-H windowsgui -s -w" -o NSE-Status-windows-amd64.exe ./cmd/nse-app
```

Browser mode alone *does* cross-compile from any OS, which is how the release binaries are produced:

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o nse-status.exe ./cmd/nse-status
```

Settings can be entered through the **Settings** tab in the UI, or put in a `.env` file next to the executable. Create that file from a terminal (`copy .env.example .env`) rather than File Explorer, which will silently save it as `.env.txt`. Note that the Settings tab writes to a `.env` in the *working directory*, so launch the app from the folder you want it to keep settings in.

Two Windows-specific caveats:

- The desktop app needs the **WebView2 runtime**. It ships with Windows 11 and current Windows 10; on older installs, get Microsoft's Evergreen bootstrapper.
- The release binaries are unsigned, so SmartScreen shows a "Windows protected your PC" prompt on first run — *More info* → *Run anyway*. (The macOS build is ad-hoc signed only, and gets the equivalent Gatekeeper prompt.)

### Dev probe utilities

`cmd/nse-probe` and `cmd/nse-statsprobe` are small ad-hoc tools for running specific read-only `show` commands against a live device during development — not part of the app itself.

## Project layout

- `internal/nse/` — SSH client, CLI output parsers, config-write line builders, HTTP handlers, safe-apply logic.
- `web/static/` — vanilla JS/HTML/CSS frontend (no build step).
- `cmd/nse-app/` — desktop app entry point (webview).
- `cmd/nse-status/` — browser-mode entry point.
- `NSE3000-CLI-REFERENCE.md` — reverse-engineered CLI reference this project is built against.

## Security notes

- `service show config` / `show config` output can contain real secrets (passwords, PSKs, RADIUS/PPPoE/Tailscale credentials, the IPS oinkcode). The app redacts all of these before displaying or logging anything; `$crypt$N$...` values are reversible, not one-way hashes, and are treated accordingly.
- SSH host keys are pinned on first connect (TOFU) and verified on every subsequent connection.
- Every state-changing HTTP endpoint checks that the request's `Origin`/`Referer` matches the app's own origin.
- No CLI write syntax is shipped without either a confirmed real capture or a documented, explicit "unconfirmed" note in code — and unconfirmed paths still go through the safe-apply rollback mechanism above.
