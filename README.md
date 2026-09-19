# NSE Local SSH

A local-first read/write configuration tool for Cambium NSE3000/NSE4000 firewalls. It talks to the device directly over SSH — no cloud (cnMaestro) dependency — so it works before a unit is cloud-connected, or any time a change is faster to make locally than through a cloud round-trip.

This is a personal tool, not an official Cambium product.

## What it does

**Status dashboard** (read-only, polls `show` / `service show` commands): Overview, Throughput, Details, Memory, Connection tracking, Interfaces, VLANs, Routing, DHCP (pools + MAC bindings), Neighbors, Devices, VPN tunnels (Starlink, client VPN), Tailscale, Firewall counters, Traffic, Events, and a raw Config viewer with secret-bearing lines redacted.

**Configuration** (read/write, applied over the same SSH session): Network (VLANs, DHCP scopes, physical LAN port switchport config), WAN (DHCP/static/PPPoE, load balancing, bandwidth, connection health, enabling a LAN port as a new WAN, moving a WAN to a different physical port), Management, Groups (User/IP/Application), DNS, Threat Protection, Firewall, and VPN. Also the administrator password, the management services (SSH/HTTPS/HTTP/Telnet/RADIUS-auth, their ports and the SSH idle timeout), gateway source precedence, and port forwarding with source NAT.

Turning SSH **off** is refused rather than attempted: this tool reaches the device over SSH only, so it cannot be the thing that removes the channel its own safety check runs over. The refusal names the alternative.

**License-aware UI**: reads `show feature-license` and greys out (rather than hides) any control gated behind NSE Security Plus, matching cnMaestro's own convention.

**Multi-site connections**: saved connections for every site you manage, each with its own label, address, username and SSH port. The header always shows which device you are looking at and drops down to switch; **Connections** is a top-level tab for adding, renaming and deleting them. One connection is live at a time — opening a site closes the previous SSH session — and a switch is refused while a configuration change on the current device is still awaiting confirmation, since the snapshot that would undo it belongs to that device and must not be replayed onto another. Connections live in `profiles.json` next to the settings `.env`, **including their passwords in cleartext** (file mode `0600`); treat that file accordingly.

**Profile export**: produces a JSON profile in the same schema as cnMaestro's own NSE Group export. A handful of fields exist only in cnMaestro's own view of the device (VLAN labels, rate-limit rules, some display-only WAN values), so an export from a unit that has never been cloud-managed will have those blank.

**Reads the running config, not a cloud snapshot**: configuration comes from `show config`, the one read command every unit supports. `service show cloud-json-config` looks tempting — its JSON matches cnMaestro's export schema field-for-field — but it is a periodically regenerated snapshot that was measured lagging the running config by about seven minutes, including across an explicit `save`, and on a unit that is never cloud-managed it may never populate. Reading it back made a change that had actually applied look like it had failed. It is still used, but only to fill in labels the CLI has no words for (a VLAN's name and rate-limit rule); everything the CLI can change is read from the device's live configuration.

**Diagnostics**: the whitelist of read-only device commands — `ping`, `nslookup`, `speedtest`, every `show`, and the per-daemon debug logs — has a screen. Commands that cost time or bandwidth say so on the card and ask before running, because a speed test spends the site's bandwidth and a conntrack dump can load the device's CPU.

**Local history**: throughput and monitor-host latency are recorded to `history.json` next to the settings file, at two resolutions — one-minute buckets for 24 hours, quarter-hour buckets for 30 days — and the window self-trims, so the file does not grow without bound. A bucket holds the mean over its window, not the last sample in it, which is the honest aggregate for a rate. The device keeps no history of its own, so without this a chart can only cover the time the window has been open.

Latency costs nothing extra: `service show debug-logs wanlb` already carries the load balancer's own per-cycle ping summaries against each WAN's monitor hosts, so reading that is both cheaper than issuing pings and brings measurements from before the app was started.

**Configuration journal**: every `show config` the app reads is hashed, and a hash that differs from the last one filed means the running configuration moved, so the new text is recorded with a timestamp. The device keeps no configuration history at all, so this is the only local answer to "what changed, and when". Entries are stored with secrets stripped — a journal is browsed far more often than a backup, so it holds the redacted text and is explicitly not a restore artifact.

**Site backup and section restore**: `/api/backup` streams `show config` plus the device's internal configuration store as one file. **It contains the device's secrets in cleartext**, because a backup that redacts them cannot rebuild a site; the file says so on its first line. Restore is per section (VLANs, DHCP, DNS, firewall, groups, threat, management, LAN ports), previews by default, and replays through the same safe-apply path as any other risky change. Replaying a whole device in one go is deliberately not offered.

**First-run readiness**: `/api/provisioning` reads the device and reports what a new unit still needs before it should be left in a rack — hostname, timezone, NTP, WAN, DHCP, name servers, a syslog target, a backup taken. The administrator password is always reported as outstanding: the device stores it obfuscated, so no check can tell a factory password from a chosen one, and pretending otherwise would be worse than asking.

**Offline demo mode**: `-demo <dir>` replays the recorded captures in `internal/nse/testdata/` instead of dialling a device, so the UI can be developed, reviewed and demonstrated with no hardware present. It is read-only by construction — a command with no recorded output fails exactly as an unknown command does, which means every config write fails too.

```bash
go run ./cmd/nse-status -demo internal/nse/testdata
```

### Safety mechanism

Any change that could plausibly lock you out of the device — WAN edits, LAN port VLAN/trunk assignment, a VLAN's management-access flag, management services, HA, the admin password, outbound filter rules, GEO IP filtering, and free-text CLI overrides — goes through a safe-apply path instead of being sent directly:

1. Snapshot the device's current config for the affected section(s).
2. Apply the change.
3. Open a **brand-new** SSH connection (not the one that made the change — an already-open channel can survive some settings changes and would prove nothing) to confirm the device is still reachable.
4. If the change only partially applied, undo it from the snapshot.
5. If reachable, hold the change **provisional** for 60 seconds — confirm it in the UI, or it is undone.
6. The change is only written to the device's startup config once you confirm it.

**What this does and does not protect against.** The undo in steps 4 and 5 is delivered over SSH to the device being changed. If a change severs access — the very category this exists for — the undo cannot be delivered either, and the tool says so rather than claiming a rollback it could not perform. This mechanism reliably catches a change that is *wrong but leaves the device reachable*; it cannot rescue one that locks you out.

What covers the lockout case is step 6: a risky change is never saved until you confirm it, so the device still boots the previous configuration and **power-cycling it recovers**. Anything beyond that needs console or physical access.

Everything else applies directly and reports success or failure immediately. Either way the change is written to the device's startup config with `save` once it is settled — without that, a change lives only in the running config and is lost on reboot.

## Running it

### Desktop app (macOS)

Builds a native window (WKWebView) around the Go backend — no browser tab required. An **Open in Browser** button hands the same running session to your default browser without disrupting the app window.

```bash
cp .env.example .env   # set NSE_PASSWORD
sh scripts/package-macos.sh
open "dist/NSE Status.app"
```

Use the **Connections** tab in the app to add the device's address, username and password. The desktop app stores those in `~/Library/Application Support/NSE Status/`.

### Browser only

Needs Go 1.25 or newer (see `go.mod`).

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

Device details can be entered through the **Connections** tab in the UI, or put in a `.env` file next to the executable. Create that file from a terminal (`copy .env.example .env`) rather than File Explorer, which will silently save it as `.env.txt`. Note that the app writes saved connections to the *working directory*, so launch it from the folder you want it to keep them in.

Two Windows-specific caveats:

- The desktop app needs the **WebView2 runtime**. It ships with Windows 11 and current Windows 10; on older installs, get Microsoft's Evergreen bootstrapper.
- The release binaries are unsigned, so SmartScreen shows a "Windows protected your PC" prompt on first run — *More info* → *Run anyway*. (The macOS build is ad-hoc signed only, and gets the equivalent Gatekeeper prompt.)

### Linux

Browser mode is pure Go and needs nothing beyond the toolchain:

```bash
cp .env.example .env   # set NSE_PASSWORD
go build -o nse-status ./cmd/nse-status
./nse-status
```

Prebuilt `nse-status_<version>_linux_{amd64,arm64}` binaries are on the [Releases](https://github.com/SiCambium/NSELocalSSH/releases) page, along with `linux_armv6` / `linux_armv7` builds for 32-bit Raspberry Pi (Pi Zero/1 and Pi 2/3/4 respectively; 64-bit Pi OS uses the arm64 build).

The desktop app uses GTK and WebKit2GTK, so it needs those headers and must be built on Linux:

```bash
sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.0-dev pkg-config
CGO_ENABLED=1 go build -o NSE-Status ./cmd/nse-app
```

CI pins this job to Ubuntu 22.04: 24.04 dropped the `libwebkit2gtk-4.0-dev` package the binding depends on.

### Verifying a download

Each release carries a `SHA256SUMS` file covering every attached artifact:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Every binary also reports the release it came from, which the filename alone cannot be trusted to tell you once it has been renamed or moved:

```bash
./nse-status --version          # e.g. "nse-status v0.3.0"
```

A build made straight from a working tree reports `dev`.

### Dev probe utilities

`cmd/nse-probe` and `cmd/nse-statsprobe` are small ad-hoc tools for running specific read-only `show` commands against a live device during development — not part of the app itself.

## Project layout

- `internal/nse/` — SSH client, CLI output parsers, config-write line builders, HTTP handlers, safe-apply logic.
- `web/static/` — vanilla JS/HTML/CSS frontend (no build step).
- `cmd/nse-app/` — desktop app entry point (webview).
- `cmd/nse-status/` — browser-mode entry point.
- `scripts/` — build and packaging scripts; `.github/workflows/release.yml` builds the release artifacts for every platform.
- `NSE3000-CLI-REFERENCE.md` — reverse-engineered CLI reference this project is built against, including what has and has not been confirmed live.
- `CLAUDE.md` — orientation for working in this codebase.

## Security notes

- `service show config` / `show config` output can contain real secrets in cleartext — the admin password hash, VPN and RADIUS shared secrets, PPPoE and Tailscale credentials, WireGuard private keys, the IPS oinkcode. Lines carrying any of those are redacted before being displayed or written anywhere. Redaction is keyword-based, so it is only as complete as its pattern list: the list is in `secretLine` (`parsers.go`), and anything added to the CLI that carries a credential under a new keyword needs adding there. It deliberately does **not** redact WireGuard `public-key` / `peer-public-key`, which are published to peers by design, or `key-lifetime`, which is a timer. (`$crypt$N$...` values are reversible, not one-way hashes, and are treated accordingly.)
- A CLI command cannot span lines. The app builds commands by interpolating request text in dozens of places (a hostname, a RADIUS client's name, a secret, a DNS domain), and the SSH session terminates each command with a carriage return — so a value carrying its own CR or LF would run the remainder as a second command on the firewall. Every command is checked at the point it is sent, rather than relying on each handler to remember, and a batch containing one is refused before any of it reaches the device.
- SSH host keys are pinned on first connect (TOFU) and verified on every subsequent connection.
- Every state-changing HTTP endpoint checks that the request's `Origin`/`Referer` matches the app's own origin.
- Every CLI write builder carries a note in code recording how its syntax was established, and unconfirmed paths still go through the safe-apply path above with the limits described there. The intent is that nothing ships without a real capture behind it, but the marks are only as good as the evidence they cite: a builder was found marked CONFIRMED on the strength of a cnMaestro JSON export, which cannot evidence a CLI keyword at all, and another cites a capture that is not in this repo. Treat a CONFIRMED note as a claim to check, not a guarantee.
