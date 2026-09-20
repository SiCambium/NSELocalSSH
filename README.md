# NSE Local SSH

A local-first read/write configuration tool for Cambium NSE3000/NSE4000 firewalls. It talks to the device directly over SSH — no cloud (cnMaestro) dependency — so it works before a unit is cloud-connected, or any time a change is faster to make locally than through a cloud round-trip.

This is a personal tool, not an official Cambium product.

## What it does

**Status dashboard** (read-only, polls `show` / `service show` commands): Overview, Throughput, Details, Memory, Connection tracking, Interfaces, VLANs, Routing, DHCP (pools + MAC bindings), Neighbors, Devices, VPN tunnels (Starlink, client VPN), Tailscale, Firewall counters, Traffic, Events, and a raw Config viewer with secret-bearing lines redacted.

**Configuration** (read/write, applied over the same SSH session): Network (VLANs, DHCP scopes, physical LAN port switchport config), WAN (DHCP/static/PPPoE, load balancing, bandwidth, connection health, enabling a LAN port as a new WAN, moving a WAN to a different physical port), Management, Groups (User/IP/Application), DNS, Threat Protection, Firewall, VPN, and Advanced. Also the administrator password, the management services (SSH/HTTPS/HTTP/Telnet/RADIUS-auth, their ports and the SSH idle timeout), gateway source precedence, and port forwarding with source NAT.

**Advanced overrides**: a free-text CLI box for settings that have no control of their own — the equivalent of cnMaestro's user-defined overrides. The text is sent to the device verbatim, line by line, because the device tracks command context itself exactly as it does when you paste into the CLI; nothing here tries to interpret it. A preview shows the precise lines that will be sent, the config stanzas that will be snapshotted for the undo, and any entries that are new and therefore cannot be undone automatically. The text is stored per connection as a record of what was last sent — not of what is currently on the device.

**Disabling SSH is refused, wherever it is asked for.** An override carrying `no management ssh` is rejected, and so is the management-services control for it. Everything else either of them can do is recoverable by power-cycling, because a lockout-risk change is not saved until confirmed — but disabling SSH takes away the channel the undo itself travels over, and the channel this tool has. The refusal names the alternative: the console, or the web interface, with another way in already proven.

**License-aware UI**: reads `show feature-license` and greys out (rather than hides) any control gated behind NSE Security Plus, matching cnMaestro's own convention.

**Multi-site connections**: saved connections for every site you manage, each with its own label, address, username and SSH port. The header always shows which device you are looking at and drops down to switch; **Connections** is a top-level tab for adding, renaming and deleting them. One connection is live at a time — opening a site closes the previous SSH session — and a switch is refused while a configuration change on the current device is still awaiting confirmation, since the snapshot that would undo it belongs to that device and must not be replayed onto another. See [Where it keeps your data](#where-it-keeps-your-data) for where connections are stored and what that file contains.

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

## Install

You do not need to clone this repository and you do not need Go. Download one file from the [Releases](https://github.com/SiCambium/NSELocalSSH/releases) page and run it. Building from source is a separate path, further down.

Two builds are offered for each platform:

- **Desktop app** — a normal application window. Start here.
- **`nse-status`** — the same tool served to your browser at http://127.0.0.1:8080, with a console window alongside.

### macOS

```bash
unzip NSE-Status-macOS-universal.zip
open "NSE Status.app"
```

Universal (Apple silicon and Intel). The build is ad-hoc signed rather than notarized, so Gatekeeper will say the developer is unidentified: **right-click → Open**, then **Open** again.

### Windows

Download `NSE-Status-windows-amd64.exe` and double-click it. Windows will say *"Windows protected your PC"*, because the release binaries are not code-signed — choose **More info**, then **Run anyway**.

The desktop build needs the **WebView2 runtime**. It ships with Windows 11 and current Windows 10; on an older install, get Microsoft's Evergreen bootstrapper. The browser build has no such requirement.

### Linux

```bash
chmod +x nse-status_<version>_linux_amd64
./nse-status_<version>_linux_amd64
```

`arm64`, and `armv6`/`armv7` for 32-bit Raspberry Pi (Pi Zero/1 and Pi 2/3/4 respectively; 64-bit Pi OS uses `arm64`). The desktop build needs GTK and WebKit2GTK; the browser build needs nothing.

### First run

Open the **Connections** tab, add the device's address, username and password, and the SSH port if it is not 22. That is the whole setup — there is no installer, no service, and no configuration file to write by hand.

## Where it keeps your data

In a per-user directory, the same set of files on every platform:

| Platform | Location |
|---|---|
| Windows | `%APPDATA%\NSE Status\` |
| macOS | `~/Library/Application Support/NSE Status/` |
| Linux | `$XDG_CONFIG_HOME/nse-status/`, usually `~/.config/nse-status/` |

| File | What it holds |
|---|---|
| `.env` | the connection the app starts on |
| `profiles.json` | your saved connections, **including their passwords in cleartext** (file mode `0600`) |
| `overrides.json` | the Advanced CLI text last applied, per connection |
| `known_hosts.json` | the SSH host keys pinned on first connect |
| `prefs.json` | your own UI preferences |

Treat that directory the way you would treat a password manager's data.

If the directory you run from already contains any of these files, that directory is used instead and nothing moves — so an existing setup, including a repo checkout you have been running from source, keeps working exactly as it did.

## Verifying a download

Each release carries a `SHA256SUMS` file covering every attached artifact:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Every binary also reports the release it came from, which the filename alone cannot be trusted to tell you once it has been renamed or moved:

```bash
./nse-status --version          # e.g. "nse-status v0.5.1"
```

A build made straight from a working tree reports `dev`.

## If it will not start

- **The window opens blank.** The desktop build needs its platform's web view — WebView2 on Windows, WebKit2GTK on Linux. The browser build does not.
- **Nothing happens at all.** Run it from a terminal so you can read the error it prints.
- **It cannot reach the device.** The tool speaks SSH only. Check that SSH is enabled on the NSE and that the port is reachable: `Test-NetConnection <device-ip> -Port 22` on Windows, `nc -z <device-ip> 22` elsewhere.

## Building from source

Only needed to change the code. Browser mode needs nothing but Go 1.25+ and cross-compiles from any OS to any other:

```bash
git clone https://github.com/SiCambium/NSELocalSSH.git
cd NSELocalSSH
go build -o nse-status ./cmd/nse-status
./nse-status
```

For UI work, serve `web/static` from disk so an edit needs no rebuild:

```bash
NSE_DEV_STATIC="$PWD/web/static" go run ./cmd/nse-status
```

The desktop app needs CGO and each platform's own toolchain, and **must be built on the platform it targets** — the web view binding needs that platform's C headers:

| Platform | Needs | Build |
|---|---|---|
| macOS | Xcode command line tools | `sh scripts/package-macos.sh` |
| Windows | MinGW-w64 (`choco install mingw`) | `go build -ldflags "-H windowsgui" -o NSE-Status.exe ./cmd/nse-app` |
| Linux | `libgtk-3-dev libwebkit2gtk-4.0-dev pkg-config` | `go build -o NSE-Status ./cmd/nse-app` |

CI pins the Linux desktop job to Ubuntu 22.04: 24.04 dropped the `libwebkit2gtk-4.0-dev` package the binding depends on.

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
