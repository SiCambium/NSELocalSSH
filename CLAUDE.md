# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A local-first read/write configuration GUI for Cambium NSE3000/NSE4000 firewalls, driven entirely over SSH against the device's undocumented CLI (no cnMaestro/cloud dependency). Go backend + embedded vanilla-JS frontend, shipped either as a browser-mode server (`cmd/nse-status`) or a native desktop window (`cmd/nse-app`, webview_go). See `README.md` for the feature list and `NSE3000-CLI-REFERENCE.md` for the reverse-engineered CLI this project is built against.

## Commands

The Go toolchain is at `/opt/homebrew/bin/go` and is **not on the default PATH** in this environment — prefix with `export PATH="/opt/homebrew/bin:$PATH"`.

```bash
go test ./...                                   # all tests (only internal/nse has any)
go test ./internal/nse -run TestParseLANConfig  # single test
go test ./internal/nse -run 'TestConfig.*VPN' -v
go vet ./...

go run ./cmd/nse-status          # browser mode, http://127.0.0.1:8080
sh scripts/package-macos.sh      # local .app into dist/ (copies ./.env into the bundle)
sh scripts/build-portable.sh     # cross-compile nse-status for all platforms into build/
sh scripts/build-release.sh v0.3 # portable + macOS app
```

There is no linter config and no frontend build step — `web/static/*` is served straight from `embed.FS`, so a JS/CSS edit just needs a rebuild of the Go binary (or a reload in `go run` mode after restart).

Device credentials come from `.env` (`NSE_HOST`, `NSE_USER`, `NSE_PASSWORD`, `NSE_PORT`); `cp .env.example .env` to start. `LoadConfig` merges several candidate paths (exe dir, cwd, `~/.config/nse-status/`, `~/Library/Application Support/NSE Status/`) and env vars win over files; `WritableSettingsPath()` picks where the Settings UI writes back — inside a `.app` bundle that is Application Support, otherwise `./.env`. `prefs.json`, `profiles.json`, and `known_hosts.json` all live next to the writable `.env`.

Tags matching `v*` trigger `.github/workflows/release.yml`, which builds the portable binaries plus native desktop apps for macOS/Windows/Linux and uploads them to the release.

## Architecture

### One shared SSH shell, serialized

`internal/nse/client.go` holds a single persistent SSH session behind a mutex. SSH on this device drops straight into `(config)#` — there is no `enable`/`configure terminal`. Command completion is detected by matching a **prompt regex** on the output stream (there is no exit status), `--More--` pagers are auto-advanced with a space, and CLI failure is inferred from error-shaped lines (`%...`, `Invalid ...`) because the CLI has no success token.

- `Run` = one command. `RunSequence` = a multi-line sequence (enter sub-context, set leaves, `exit`) holding the lock for the *whole* sequence — the hazard is a dashboard poll injecting a `show` mid-sub-context, not writer/writer races.
- `unwindLocked` walks back to the top-level prompt with `exit` after every sequence, and drops the whole shell if it can't (the next `ensure()` reconnects cleanly).
- Host keys are pinned TOFU (`hostkeys.go`) and verified on every connect, including the safe-apply probe connection.

### Two read paths

1. **Text `show` output → parsers.** `parsers.go` (plus `dns.go`, `throughput.go`, `license.go`) turn CLI text into JSON structs. `stripCLI`/`linesOf` drop the echoed command and prompts first.
2. **`service show cloud-json-config` → `cloudconfig.go`.** Structured JSON whose keys match cnMaestro's own NSE Group export schema. Deliberately lossy: only display-safe fields are modeled, and **no secret-shaped field is ever unmarshaled**, so secrets can't leak to the frontend by accident. `groupprofile.go` builds the exportable cnMaestro-compatible profile from it.

**`show config` is the authority; the JSON is not.** `FetchCloudConfig` reads `show config` and derives the whole `CloudConfig` from it (`CloudConfigFromShowConfig`, `cloudconfig_fallback.go`). cloud-json-config is a *periodically regenerated cnMaestro-facing snapshot* — measured lagging the running config by ~7 minutes on an NSE4000/2.4-r1, across an explicit `save` — so reading it back made a successful change look failed, and inside SafeApplier's 60-second confirmation window that turned into a real rollback. It is still consulted, but only through `enrichFromCloudJSON`, which fills fields the CLI cannot express and no local edit can change (VLAN label and rate-limit, display-only WAN fields). **Never add a CLI-writable field to that whitelist** — `TestEnrichFromCloudJSONNeverOverwritesLiveConfig` pins it.

The result is cached for `configTTL` and dropped by every `RunSequence` (i.e. every write). A device that rejects the JSON command is remembered on the `Client` so the dead round-trip is paid at most twice, not per read.

**Port counts are model-specific** — six on an NSE3000, ten on an NSE4000 — so never loop a fixed `eth1..eth6` range; walk `ethInterfaceBlocks(tree)` instead.

**When adding a field to `CloudConfig`, add its `show config` derivation too.** `TestCloudConfigFromShowConfigMatchesCloudJSON` compares the whole struct against the paired testdata captures, so a field left unmapped fails the test unless it's added to that test's explicit "not expressible in `show config`" list — and that list belongs in `CloudConfigFromShowConfig`'s doc comment with the reason.

Expensive/rarely-changing reads (`wanPorts`, `threatSummary`) are cached ~30s on `Server` and return the last-known value on error so a transient failure doesn't blank the dashboard.

### Write path: line builders → ConfigBlock → SafeApplier

Every write follows the same shape:

1. `config_write.go` builds the CLI **lines** (leaf lines + `BuildInterfaceEthLines`/`BuildInterfaceVLANLines`-style sub-mode envelopes). This file is pure string construction and is where the heaviest test coverage lives.
2. A `config_handlers_*.go` POST handler validates the request, builds a `ConfigBlock{Name, Lines, Risk: ClassifyRisk(section), Keys}`, and hands it to `s.safeApplier().Apply(...)`.
3. `safe_apply.go` applies it. `RiskNone` → direct apply. `RiskLockout` → snapshot `show config`, apply, prove the device still accepts a **brand-new SSH login** (an already-open channel survives `management ssh` being disabled and proves nothing), auto-roll-back on partial failure or unreachability, otherwise hold **provisional** for 60s until `POST /api/config/confirm` with the returned token — an unconfirmed change is rolled back by the background expiry loop.

`Keys` are the top-level config keys `ExtractStanza` (in `blocktree.go`) uses to cut the rollback pre-image out of the snapshot. `blocktree.go` parses `show config` into nested context blocks using the `blockOpeners` regex list — **add a regex there when a new CLI sub-context is supported**, or its stanza will be flattened into leaves and rollback for that section will be wrong. `blocktree_test.go` round-trip tests against `testdata/show_config_*.txt` guard this.

`ClassifyRisk` is the lockout list: `wan`, `lan-port`, `vlan-management-access`, `management-service`, `high-availability`, `admin-password`, `outbound-filter`, `geo-ip`, `overrides`. Anything that could plausibly cut the session doing the editing belongs here; free-text CLI overrides are always risky because they can't be judged by inspection.

### Connections (multi-site)

`profiles.json` (next to the writable `.env`, see `ProfilesPath`) holds the saved connections — one per site, with a stable auto-incrementing ID, a free-text `Name`, and the credentials. `Profile.Label()` falls back to the host when there's no name. `ProfileStore.NextIDSeq` is a persisted high-water mark so a delete can never make the next connection reuse an ID a UI element still refers to.

Exactly one connection is live: `Server` holds a single `*Client`. **Switching goes through `Server.SwitchDevice`, never `Client.ApplyConfig` directly** — everything cached on `Server` is per-device (throughput sampler, WAN port set, threat summary) and would otherwise be served for the wrong site; the throughput sampler in particular would subtract one device's byte counters from another's. `SwitchDevice` also refuses outright while `SafeApplier.PendingCount() > 0`, because a provisional change's rollback pre-image is the *old* device's config and the expiry loop replays pre-images through whatever the shared client currently points at.

### HTTP layer

`server.go` `Handler()` registers all routes on one mux: read-only `/api/<tab>` endpoints for the dashboard, `/api/config/<section>` GET+POST for configuration, `/api/debug`, `/api/license`, `/api/settings`, `/api/profile/export`. **Every state-changing endpoint must call `isSameOrigin(r)` and `writeCrossOriginBlocked(w)` on failure** — that is the only CSRF defense, and `csrf_test.go` enumerates the endpoints.

### Frontend

`web/static/` is plain globals-on-`window`, loaded in order by `index.html` — no modules, no bundler. `app.js` owns the Status page (tab list, polling, caches). `config-common.js` exposes `window.NSEConfig` with the shared `esc`/`getJSON`/`postJSON`/`openModal`/`fetchLicense`/`licenseGate`/`renderOutcome` helpers; each `config-<section>.js` destructures those at the top and ends with `window.NSEConfig.registerSection("<id>", { load })`. Adding a section means: a `NAV` entry in `config-common.js`, a new `config-<id>.js`, a `<script>` tag in `index.html`, and a backend `/api/config/<id>` handler.

`renderOutcome` is what surfaces the `provisional` status and its confirm countdown, so any new risky section gets the confirm UX for free by going through it.

## Conventions that matter

- **CLI syntax is evidence-based.** Write-path functions in `config_write.go` carry a `CONFIRMED` comment citing a real capture, or an explicit `UNCONFIRMED` note explaining what wasn't verified. Never invent CLI syntax silently; if it must be guessed, say so in the comment and make sure it routes through the safe-apply path. Update `NSE3000-CLI-REFERENCE.md` when new syntax is confirmed live.
- **Secrets never reach the UI or logs.** `show config` / `service show config` contain cleartext passwords, PSKs, RADIUS/PPPoE/Tailscale credentials and the IPS oinkcode; `$crypt$N$...` values are reversible, not hashes. `debug.go`'s `redactSecretLine` strips them before display, `cloudconfig.go` avoids modeling them at all, and `cli_dump/` is gitignored for the same reason.
- **License gating greys out, never hides.** `show feature-license`'s 7 flags gate NSE Security Plus features; the frontend wraps gated controls in `licenseGate(...)` to match cnMaestro's convention. See `license.go` for which flag maps to which UI control.
- **Tests run offline.** Parser tests read golden captures from `internal/nse/testdata/`; handler tests construct `&Server{Client: NewClient(Config{}), SkipConnect: true}` so validation/routing/CSRF paths are exercised and the SSH apply predictably fails with a 502 past that point. New device output belongs in `testdata/` as a redacted capture.
- `cmd/nse-probe` and `cmd/nse-statsprobe` are throwaway dev tools for running read-only `show` commands against a live device; they are not part of the shipped app.
