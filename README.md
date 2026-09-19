# NSE Local SSH

A local-first read/write configuration tool for Cambium NSE3000/NSE4000 firewalls. It talks to the device directly over SSH — no cloud (cnMaestro) dependency — so it works before a unit is cloud-connected, or any time a change is faster to make locally than through a cloud round-trip.

This is a personal tool, not an official Cambium product.

## What it does

**Status dashboard** (read-only, polls `show` / `service show` commands): Overview, Throughput, Details, Memory, Connection tracking, Interfaces, VLANs, Routing, DHCP (pools + MAC bindings), Neighbors, Devices, VPN tunnels (Starlink, client VPN), Tailscale, Firewall counters, Traffic, Events, and a raw Config viewer with secret-bearing lines redacted.

**Configuration** (read/write, applied over the same SSH session): Network (VLANs, DHCP scopes, physical LAN port switchport config), WAN (DHCP/static/PPPoE, load balancing, bandwidth, connection health, enabling a LAN port as a new WAN, moving a WAN to a different physical port), Management, Groups (User/IP/Application), DNS, Threat Protection, Firewall, VPN, and Advanced.

**Advanced overrides**: a free-text CLI box for settings that have no control of their own — the equivalent of cnMaestro's user-defined overrides. The text is sent to the device verbatim, line by line, because the device tracks command context itself exactly as it does when you paste into the CLI; nothing here tries to interpret it. A preview shows the precise lines that will be sent, the config stanzas that will be snapshotted for the undo, and any entries that are new and therefore cannot be undone automatically. The text is stored per connection as a record of what was last sent — not of what is currently on the device. `no management ssh` is refused: everything else an override can do is recoverable by power-cycling, since a lockout-risk change is not saved until confirmed, but disabling SSH takes away the channel the undo itself travels over.

**License-aware UI**: reads `show feature-license` and greys out (rather than hides) any control gated behind NSE Security Plus, matching cnMaestro's own convention.

**Multi-site connections**: saved connections for every site you manage, each with its own label, address, username and SSH port. The header always shows which device you are looking at and drops down to switch; **Connections** is a top-level tab for adding, renaming and deleting them. One connection is live at a time — opening a site closes the previous SSH session — and a switch is refused while a configuration change on the current device is still awaiting confirmation, since the snapshot that would undo it belongs to that device and must not be replayed onto another. Connections live in `profiles.json` next to the settings `.env`, **including their passwords in cleartext** (file mode `0600`); treat that file accordingly.

**Profile export**: produces a JSON profile in the same schema as cnMaestro's own NSE Group export. A handful of fields exist only in cnMaestro's own view of the device (VLAN labels, rate-limit rules, some display-only WAN values), so an export from a unit that has never been cloud-managed will have those blank.

**Reads the running config, not a cloud snapshot**: configuration comes from `show config`, the one read command every unit supports. `service show cloud-json-config` looks tempting — its JSON matches cnMaestro's export schema field-for-field — but it is a periodically regenerated snapshot that was measured lagging the running config by about seven minutes, including across an explicit `save`, and on a unit that is never cloud-managed it may never populate. Reading it back made a change that had actually applied look like it had failed. It is still used, but only to fill in labels the CLI has no words for (a VLAN's name and rate-limit rule); everything the CLI can change is read from the device's live configuration.

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

**You do not need to clone this repository, and you do not need Go.** To run
the tool, download one file and double-click it. Building from source is a
separate path, further down.

#### Running it

1. Open the [Releases](https://github.com/SiCambium/NSELocalSSH/releases) page
   and download one of:

   - `NSE-Status-windows-amd64.exe` — a normal desktop window. Start here.
   - `nse-status_<version>_windows_amd64.exe` — the same tool served to your
     browser at http://127.0.0.1:8080, with a console window alongside it.

2. Put it in a folder of its own, for example `C:\Users\<you>\NSE-Status`.
   This matters: the app keeps your saved connections next to the executable,
   so give it somewhere stable rather than the Downloads folder.

3. Double-click it. Windows will say *"Windows protected your PC"*, because
   the release binaries are not code-signed. Choose **More info**, then
   **Run anyway**.

4. Add your device on the **Connections** screen: address, username,
   password, and the SSH port if it is not 22. That is the whole setup.

Nothing else is required. There is no installer, no service, and no
configuration file to write by hand.

#### Where it keeps things

Beside the executable, in the folder you chose:

| File | What it holds |
|---|---|
| `profiles.json` | your saved connections, **including their passwords in cleartext** (file mode 0600) |
| `history.json` | throughput and latency, 24 hours in detail and 30 days aggregated |
| `journal.json` | the configuration change log, with secrets stripped |
| `known_hosts.json` | the SSH host keys pinned on first connect |
| `prefs.json` | your own UI preferences |

Treat that folder the way you would treat a password manager's data.

#### If it will not start

- **The window opens blank.** The desktop build needs the **WebView2
  runtime**. It ships with Windows 11 and current Windows 10; on an older
  install, get Microsoft's Evergreen bootstrapper. The browser build has no
  such requirement.
- **Nothing happens at all.** Run it from a terminal (`.\NSE-Status-windows-amd64.exe`)
  so you can read the error it prints.
- **It cannot reach the device.** The tool speaks SSH only. Check that SSH is
  enabled on the NSE and that port 22 is reachable from this machine:
  `Test-NetConnection <device-ip> -Port 22`.

#### Building from source

Only needed to change the code. Browser mode needs nothing but Go 1.25+:

```powershell
git clone https://github.com/SiCambium/NSELocalSSH.git
cd NSELocalSSH
go build -o nse-status.exe ./cmd/nse-status
.\nse-status.exe
```

For UI work, serve `web/static` from disk so an edit needs no rebuild:

```powershell
$env:NSE_DEV_STATIC = "$PWD\web\static"
go run ./cmd/nse-status
```

The desktop app additionally needs CGO and a C++ toolchain (MinGW-w64, e.g.
`choco install mingw`), and must be built **on** Windows — it does not
cross-compile from macOS or Linux, because the WebView2 binding needs the
Windows C headers:

```powershell
$env:CGO_ENABLED=1
go build -ldflags "-H windowsgui -s -w" -o NSE-Status-windows-amd64.exe ./cmd/nse-app
```

Browser mode alone *does* cross-compile from any OS, which is how the release
binaries are produced:

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o nse-status.exe ./cmd/nse-status
```

Device details can also come from a `.env` file next to the executable instead
of the Connections screen. Create it from a terminal (`copy .env.example .env`)
rather than File Explorer, which will silently save it as `.env.txt`.

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
