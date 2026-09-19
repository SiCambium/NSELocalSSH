const TAB_IDS = [
  "overview",
  "throughput",
  "details",
  "memory",
  "conntrack",
  "interfaces",
  "vlans",
  "routing",
  "dhcp",
  "neighbors",
  "devices",
  "tunnels",
  "tailscale",
  "firewallcounters",
  "traffic",
  "events",
  "config",
];
const tabs = [...document.querySelectorAll(".tabs button")];
const panels = Object.fromEntries(TAB_IDS.map((id) => [id, document.getElementById(`panel-${id}`)]));

let current = "overview";
let dhcpSub = "pools";
// Which VLAN's pool the DHCP page is narrowed to, by pool number, or null
// for all of them. Kept next to dhcpSub because both are view state the
// page rebuilds from, not data.
let dhcpPoolFilter = null;
// 0 means "nothing chosen yet", so the first load of the Settings page
// edits whichever connection is actually live rather than whichever one
// happens to hold id 1.
let selectedSlot = 0;
let timer = null;

const cache = {};
const AUTO_KEY = "nse-auto-refresh";
const AUTO_INTERVAL_KEY = "nse-auto-refresh-ms";
const AUTO_INTERVALS = [1000, 2000, 5000, 10000, 20000, 30000, 60000];
let loading = false;
let liveConntrack = false;

function bytes(n) {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function kb(n) {
  if (n == null || n === "") return "0 B";
  const v = Number(n);
  if (Number.isNaN(v)) return "0 B";
  return bytes(v * 1024);
}

function bps(n) {
  if (n == null || Number.isNaN(Number(n))) return "—";
  const v = Number(n);
  const abs = Math.abs(v);
  if (abs >= 1e9) return `${(v / 1e9).toFixed(2)} Gbps`;
  if (abs >= 1e6) return `${(v / 1e6).toFixed(2)} Mbps`;
  if (abs >= 1e3) return `${(v / 1e3).toFixed(1)} kbps`;
  return `${v.toFixed(0)} bps`;
}

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function table(headers, rows) {
  if (!rows.length) return `<p class="muted">No rows.</p>`;
  return `<div class="table-wrap"><table><thead><tr>${headers
    .map((h) => `<th>${esc(h)}</th>`)
    .join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function stat(label, value) {
  return `<div class="stat"><label>${esc(label)}</label><strong>${esc(value || "—")}</strong></div>`;
}

// --- Sortable tables --------------------------------------------------
// Click any table header to sort its rows by that column; click again to
// reverse. Applies to every table in the app (Status tabs, Configuration
// sections, anything added later) via one delegated listener, so no
// per-table wiring is needed anywhere content gets rendered. Sort state
// persists across re-renders (auto-refresh replaces a panel's innerHTML
// wholesale every few seconds) by keying on the table's header text and
// re-applying after each DOM change — a MutationObserver is disconnected
// for the duration of our own row-reordering so that doesn't recursively
// retrigger itself. Some pages (e.g. Throughput) render more than one
// table with identical headers side by side, so the header text alone
// isn't a unique key: it's combined with the table's position among
// same-header tables within its own panel/section, scoped there rather
// than page-wide so unrelated hidden tabs never affect the count.
(function () {
  const sortState = new Map(); // header fingerprint -> {col, dir}
  const UNIT_MULT = {
    "": 1, bps: 1, kbps: 1e3, mbps: 1e6, gbps: 1e9,
    b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3, tb: 1024 ** 4, "%": 1,
  };

  function headerText(table) {
    return Array.from(table.querySelectorAll("thead th"))
      .map((th) => th.textContent.replace(/[▲▼]/g, "").trim())
      .join("|");
  }

  function fingerprint(table) {
    const base = headerText(table);
    const container = table.closest('[id^="panel-"], .config-section') || document.body;
    const siblings = Array.from(container.querySelectorAll("table")).filter((t) => headerText(t) === base);
    return `${base}#${siblings.indexOf(table)}`;
  }

  function cellSortValue(text) {
    text = (text || "").trim();
    const m = /^(-?[\d,]+(?:\.\d+)?)\s*([a-zA-Z%]*)$/.exec(text);
    if (m && UNIT_MULT[m[2].toLowerCase()] != null) {
      return { num: parseFloat(m[1].replace(/,/g, "")) * UNIT_MULT[m[2].toLowerCase()] };
    }
    return { str: text.toLowerCase() };
  }

  function compareRows(a, b, col, dir) {
    const av = cellSortValue(a.children[col] && a.children[col].textContent);
    const bv = cellSortValue(b.children[col] && b.children[col].textContent);
    const result =
      av.num != null && bv.num != null
        ? av.num - bv.num
        : String(av.str ?? av.num ?? "").localeCompare(String(bv.str ?? bv.num ?? ""), undefined, { numeric: true });
    return dir === "asc" ? result : -result;
  }

  function markHeader(table, col, dir) {
    table.querySelectorAll("thead th").forEach((th, i) => {
      th.classList.remove("sort-asc", "sort-desc");
      if (i === col) th.classList.add(dir === "asc" ? "sort-asc" : "sort-desc");
    });
  }

  function applySort(table, col, dir) {
    const tbody = table.querySelector("tbody");
    if (!tbody) return;
    const rows = Array.from(tbody.children).filter((r) => r.tagName === "TR");
    if (rows.length < 2) return;
    rows.sort((a, b) => compareRows(a, b, col, dir));
    observer.disconnect();
    rows.forEach((r) => tbody.appendChild(r));
    observer.observe(document.body, { childList: true, subtree: true });
    markHeader(table, col, dir);
  }

  document.addEventListener("click", (e) => {
    const th = e.target.closest("thead th");
    if (!th) return;
    const table = th.closest("table");
    if (!table) return;
    const col = Array.from(th.parentElement.children).indexOf(th);
    const fp = fingerprint(table);
    const prev = sortState.get(fp);
    const dir = prev && prev.col === col && prev.dir === "asc" ? "desc" : "asc";
    sortState.set(fp, { col, dir });
    applySort(table, col, dir);
  });

  const observer = new MutationObserver(() => {
    document.querySelectorAll("table").forEach((table) => {
      const saved = sortState.get(fingerprint(table));
      if (saved) applySort(table, saved.col, saved.dir);
    });
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();

// The header's connection dot. It sits next to the words "Connected to",
// so it reports whether the device is actually answering — not merely
// which connection is selected, which is what the dots inside the menu
// mean. Nothing ever set it before, so it stayed at its unknown-state grey
// for the life of the page while the menu below it showed green.
//
// Liveness is not in any payload: /api/health echoes the configured host
// without touching the device, and a connection entry carries only
// `active`. The one real signal is whether the last fetch came back, which
// is the same thing the poll-state text reports.
function setConnDot(state) {
  const dot = document.getElementById("conn-dot");
  if (!dot) return;
  dot.classList.toggle("on", state === "on");
  dot.classList.toggle("down", state === "down");
  dot.title =
    state === "on"
      ? "Device is answering"
      : state === "down"
      ? "Device is not answering"
      : "Not contacted yet";
}

// The Configuration pages talk to the device too, and while they are open
// nothing else is polling — so their traffic is the only liveness signal
// there is. config-common.js reports through this.
window.NSEHeader = { setConnDot };

async function load(tab, force = false, quiet = false) {
  const state = document.getElementById("poll-state");
  const err = document.getElementById("error");
  if (!force && cache[tab]) {
    render(tab, cache[tab]);
    return;
  }
  if (loading) return;
  loading = true;
  if (!quiet) state.textContent = "Loading…";
  err.hidden = true;
  try {
    const res = await fetch(`/api/${tab}`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || res.statusText);
    }
    const data = await res.json();
    cache[tab] = data;
    render(tab, data);
    state.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    setConnDot("on");
    if ((tab === "overview" || tab === "throughput") && !data.rates_ready) {
      setTimeout(() => {
        if (current === tab) load(tab, true, true);
      }, 1200);
    }
  } catch (e) {
    err.hidden = false;
    err.textContent = e.message;
    state.textContent = "Error";
    setConnDot("down");
  } finally {
    loading = false;
  }
}

function render(tab, data) {
  const el = panels[tab];
  if (tab === "overview") el.innerHTML = renderOverview(data);
  if (tab === "throughput") el.innerHTML = renderThroughput(data);
  if (tab === "details") el.innerHTML = renderDetails(data);
  if (tab === "memory") el.innerHTML = renderMemory(data);
  if (tab === "conntrack") el.innerHTML = renderConntrack(data);
  if (tab === "interfaces") el.innerHTML = renderInterfaces(data);
  if (tab === "vlans") el.innerHTML = renderVlans(data);
  if (tab === "routing") el.innerHTML = renderRouting(data);
  if (tab === "dhcp") el.innerHTML = renderDhcp(data);
  if (tab === "neighbors") el.innerHTML = renderNeighbors(data);
  if (tab === "devices") el.innerHTML = renderDevices(data);
  if (tab === "tunnels") el.innerHTML = renderTunnels(data);
  if (tab === "tailscale") el.innerHTML = renderTailscale(data);
  if (tab === "firewallcounters") el.innerHTML = renderFirewallCounters(data);
  if (tab === "traffic") el.innerHTML = renderTraffic(data);
  if (tab === "events") el.innerHTML = renderEvents(data);
  if (tab === "config") el.innerHTML = renderConfig(data);
}

function statsFromMap(obj) {
  return Object.entries(obj || {})
    .map(([k, v]) => stat(k.replaceAll("_", " "), v))
    .join("");
}

function maestroStatus(remote) {
  const raw = (remote && (remote.state || remote.device_status || remote.status)) || "";
  const low = String(raw).toLowerCase();
  if (!raw) return "—";
  if (low.includes("disconnect") || low.includes("offline") || low.includes("fail")) return raw;
  if (low.includes("connect") || low.includes("cnmaestro")) return "Connected";
  return raw;
}

function ratesNote(d) {
  if (d.rates_ready) {
    const sec = d.sample_interval ? ` over ${(Number(d.sample_interval) / 1000).toFixed(1)}s` : "";
    return `<p class="muted">Live rates${sec}. Values use kbps, Mbps or Gbps from byte counters.</p>`;
  }
  return `<p class="muted">Collecting a second sample for live rates. Leave auto-refresh on, or click Refresh once more.</p>`;
}

function throughputTable(rows, empty) {
  const list = rows || [];
  return table(
    ["Name", "RX", "TX", "Total", "Address"],
    list.map(
      (r) => `<tr>
        <td>${esc(r.label || r.cli_name || r.name)}</td>
        <td class="mono">${bps(r.rx_bps)}</td>
        <td class="mono">${bps(r.tx_bps)}</td>
        <td class="mono">${bps(Number(r.rx_bps || 0) + Number(r.tx_bps || 0))}</td>
        <td class="mono">${esc(r.ipv4 || "")}</td>
      </tr>`
    )
  ) || (empty ? `<p class="muted">${esc(empty)}</p>` : "");
}

// The device model comes from the first line of `show version` (parsed into
// version.model). Only /api/overview and /api/details carry it, so remember the
// last value — the Configuration and Settings pages must keep the same brand
// line even though their payloads have no version block.
let deviceModel = "";

// Establishes the header before anything else runs, so the model name and
// the connection dot are right on whichever page the app opens on.
// Previously both were side effects of the Status page rendering, which
// meant a reload on Configuration sat on a generic name and a grey dot
// until the user visited Status and came back.
async function initHeader() {
  try {
    const res = await fetch("/api/identity");
    if (!res.ok) throw new Error("identity unavailable");
    const data = await res.json();
    setBrand(data.version || {});
    setConnDot("on");
  } catch (e) {
    setConnDot("down");
  }
}

function setBrand(v) {
  if (v && v.model) deviceModel = v.model;
  const label = deviceModel ? `Cambium ${deviceModel}` : "Cambium NSE";
  const kicker = document.getElementById("kicker");
  if (kicker) kicker.textContent = label;
  document.title = deviceModel ? `${deviceModel} Status` : "NSE Status";
}

function renderOverview(d) {
  const v = d.version || {};
  const remote = d.remote || {};
  const mem = d.memory || {};
  const cpu = d.cpu || {};
  const usedPct = mem.used_pct != null ? mem.used_pct : 0;
  const cpuPct = cpu.used_pct != null ? cpu.used_pct : 0;
  setBrand(v);
  document.getElementById("title").textContent = v.hostname || v.identity || "Status";
  document.getElementById("clock").textContent = (d.clock && d.clock.clock) || "";
  const wan = d.wan_throughput || [];
  const wanGrid = wan.length
    ? wan
        .map(
          (w) =>
            `${stat(`${w.label || w.cli_name || "WAN"} RX`, bps(w.rx_bps))}${stat(
              `${w.label || w.cli_name || "WAN"} TX`,
              bps(w.tx_bps)
            )}`
        )
        .join("")
    : stat("WAN throughput", d.rates_ready ? "No WAN traffic" : "Sampling…");
  return `
    <div class="grid">
      ${stat("Name", v.hostname || v.identity)}
      ${stat("Model", v.model)}
      ${stat("Firmware", v.software_version)}
      ${stat("Uptime", v.uptime)}
      ${stat("cnMaestro", maestroStatus(remote))}
    </div>
    <h2>CPU</h2>
    <div class="stat">
      <label>Used</label>
      <strong>${esc(cpuPct)}% · load ${esc(cpu.load1 || "—")} ${esc(cpu.load5 || "")} ${esc(cpu.load15 || "")}</strong>
      <div class="bar"><span style="width:${cpuPct}%"></span></div>
    </div>
    <p class="muted">${esc(cpu.user_pct != null ? `usr ${cpu.user_pct}%  sys ${cpu.sys_pct}%  irq ${cpu.irq_pct}%  sirq ${cpu.softirq_pct}%  idle ${cpu.idle_pct}%` : "")}</p>
    <h2>WAN throughput</h2>
    <div class="grid">${wanGrid}</div>
    ${ratesNote(d)}
    <h2>Memory</h2>
    <div class="stat">
      <label>Used / total</label>
      <strong>${kb(mem.used_kb)} / ${kb(mem.total_kb)} (${usedPct}%)</strong>
      <div class="bar"><span style="width:${usedPct}%"></span></div>
    </div>
    <p class="muted">Full breakdown is on the Memory tab. Extra device fields are on Details.</p>
    <h2>Threat Protection</h2>
    <div class="grid">${threatProtectionGrid(d.threat_protection)}</div>
    <p class="muted">${threatProtectionNote(d.threat_protection)}</p>
  `;
}

// threatProtectionGrid/threatProtectionNote summarize the same
// secret-free intrusion-prevention state as Configuration > Threat
// Protection's own display (see config-threat.js) — duplicated here as a
// small, stable 4-item lookup rather than sharing state across files.
const THREAT_RULE_TYPE_LABELS = {
  "snort-community": "Snort Community",
  "snort-vrt": "Snort VRT",
  "et-open": "Emerging Threats Open",
  "et-pro": "Emerging Threats Pro",
};

function threatProtectionGrid(t) {
  t = t || {};
  const ruleType = THREAT_RULE_TYPE_LABELS[t.rule_type] || t.rule_type || "-";
  return [
    stat("Intrusion prevention", t.enabled ? "Enabled" : "Disabled"),
    stat("Mode", t.mode || "-"),
    stat("Rule type", ruleType),
    stat("Rules tier", t.rule_set || "-"),
    stat("Auto-update", t.auto_update ? `Enabled (${esc(t.update_interval || "-")})` : "Disabled"),
  ].join("");
}

function threatProtectionNote(t) {
  t = t || {};
  if (!t.auto_update) {
    return "This firmware doesn't report a rule database version or last-update time. Auto-update is off, so rules only change when set manually on the Configuration > Threat Protection tab.";
  }
  return `This firmware doesn't report a rule database version or last-update time — auto-update being enabled (every ${esc(t.update_interval || "-")}) is the closest available signal that rules are staying current.`;
}

function renderThroughput(d) {
  const all = d.throughput || [];
  const physical = all.filter((r) => r.kind === "physical" && (r.active || r.rx_bytes || r.tx_bytes));
  const vlans = all.filter((r) => r.kind === "vlan");
  const vpns = all.filter((r) => r.kind === "vpn");
  const flowing = physical.filter((r) => r.active || r.running);
  return `
    <h2>Interfaces with traffic</h2>
    ${ratesNote(d)}
    ${throughputTable(flowing.length ? flowing : physical, "No interface counters yet.")}
    <h2>VLANs</h2>
    ${throughputTable(vlans, "No VLAN interfaces.")}
    <h2>VPN</h2>
    ${throughputTable(vpns, "No VPN interfaces with counters (Tailscale, WireGuard, L2TP).")}
  `;
}

function renderDetails(d) {
  const v = d.version || {};
  const m = d.management || {};
  const rem = d.remote || {};
  setBrand(v);
  document.getElementById("title").textContent = v.identity || "Status";
  document.getElementById("clock").textContent = (d.clock && d.clock.clock) || "";
  const root = (d.disks || []).find((x) => x.mounted === "/") || {};
  return `
    <h2>Device</h2>
    <div class="grid">
      ${stat("Identity", v.identity)}
      ${stat("Hostname", v.hostname)}
      ${stat("Build date", v.build_date)}
      ${stat("Device-Agent", v.device_agent)}
      ${stat("Serial", v.serial)}
      ${stat("MAC", v.mac)}
      ${stat("Regulatory", v.regulatory_domain)}
      ${stat("Clock", d.clock && d.clock.clock)}
      ${stat("USB", d.usb && d.usb.usb)}
    </div>
    <h2>Management</h2>
    <div class="grid">
      ${stat("cnMaestro", maestroStatus(rem.summary || {}))}
      ${statsFromMap(m.remote)}
      ${statsFromMap(m.gui)}
      ${statsFromMap(m.cli)}
    </div>
    <h2>Power</h2>
    <div class="grid">${statsFromMap(d.power)}</div>
    <h2>Disk</h2>
    ${table(
      ["Filesystem", "Use", "Mounted"],
      (d.disks || [])
        .filter((x) => x.mounted === "/" || x.mounted === "/mnt/flash" || x.mounted === "/var/log")
        .map(
          (x) =>
            `<tr><td class="mono">${esc(x.filesystem)}</td><td>${esc(x.use_pct)}</td><td class="mono">${esc(x.mounted)}</td></tr>`
        )
    )}
    <p class="muted">${esc(root.filesystem ? `Root ${root.used} used of ${root.blocks} (1K blocks)` : "")}</p>
    <h2>cnMaestro detail</h2>
    <pre class="muted" style="white-space:pre-wrap;font-family:var(--mono);font-size:12px">${esc((rem.raw || "").trim())}</pre>
  `;
}

function renderMemory(d) {
  const mem = d.memory || {};
  const usedPct = mem.used_pct != null ? mem.used_pct : 0;
  const rows = table(
    ["Key", "Value"],
    (mem.rows || []).map((r) => {
      const val = r.kb != null && r.extra ? `${r.kb} ${r.extra}` : r.raw || r.kb || "";
      return `<tr><td>${esc(r.key)}</td><td class="mono">${esc(r.raw && r.key !== "Mem" && r.key !== "Swap" ? val : r.raw || val)}</td></tr>`;
    })
  );
  return `
    <h2>Summary</h2>
    <div class="stat">
      <label>Used / total</label>
      <strong>${kb(mem.used_kb)} / ${kb(mem.total_kb)} (${usedPct}%)</strong>
      <div class="bar"><span style="width:${usedPct}%"></span></div>
    </div>
    <div class="grid">
      ${stat("Free", kb(mem.free_kb))}
      ${stat("Available", kb(mem.available_kb))}
      ${stat("Cached", kb(mem.cache_kb))}
      ${stat("Shared", kb(mem.shared_kb))}
      ${stat("Swap used", kb(mem.swap_used_kb))}
    </div>
    <h2>Kernel memory</h2>
    ${rows}
  `;
}

// ipOrgCache is a client-side cache of IP -> ownership info already
// fetched from /api/iplookup, keyed by IP. It exists alongside the
// server-side cache so repeated re-renders of this table (it redraws
// from scratch on every poll) don't need a network round-trip just to
// keep showing something already looked up this session.
const ipOrgCache = new Map();
const ipOrgQueue = [];
const ipOrgQueued = new Set();
let ipOrgQueueRunning = false;
let ipOrgRerenderTimer = null;

function ipOrgCell(ip, lookupEnabled) {
  if (!ip) return "-";
  if (!lookupEnabled) return esc(ip);
  if (ipOrgCache.has(ip)) {
    const info = ipOrgCache.get(ip);
    const label = info && (info.org || info.isp);
    return label ? `${esc(ip)}<br><span class="muted">${esc(label)}</span>` : esc(ip);
  }
  scheduleIPLookup(ip);
  return `${esc(ip)}<br><span class="muted">…</span>`;
}

// scheduleIPLookup fires automatically for every not-yet-seen destination
// IP once lookups are enabled — no per-row button. Requests are queued
// and run one at a time (with a short gap between them) rather than all
// at once, so enabling this on a busy table doesn't burst dozens of
// parallel requests at a free lookup service in one go.
function scheduleIPLookup(ip) {
  if (ipOrgCache.has(ip) || ipOrgQueued.has(ip)) return;
  ipOrgQueued.add(ip);
  ipOrgQueue.push(ip);
  runIPOrgQueue();
}

async function runIPOrgQueue() {
  if (ipOrgQueueRunning) return;
  ipOrgQueueRunning = true;
  while (ipOrgQueue.length) {
    const ip = ipOrgQueue.shift();
    try {
      const res = await fetch(`/api/iplookup?ip=${encodeURIComponent(ip)}`);
      const data = await res.json().catch(() => null);
      ipOrgCache.set(ip, res.ok ? data : null);
      ipOrgQueued.delete(ip);
    } catch (e) {
      // Network-level failure (not a definitive answer from our own
      // backend) — leave it unqueued and uncached so a later render can
      // retry rather than being stuck showing "…" forever.
      ipOrgQueued.delete(ip);
    }
    requestIPOrgRerender();
    await new Promise((r) => setTimeout(r, 150));
  }
  ipOrgQueueRunning = false;
}

// requestIPOrgRerender coalesces bursts of queue completions (many IPs
// resolving within milliseconds of each other) into a single table
// rebuild instead of one per lookup.
function requestIPOrgRerender() {
  clearTimeout(ipOrgRerenderTimer);
  ipOrgRerenderTimer = setTimeout(() => {
    if (cache.conntrack) render("conntrack", cache.conntrack);
  }, 150);
}

function renderConntrack(d) {
  const ct = d.summary || {};
  const ctPct = ct.limit ? Math.min(100, Math.round((Number(ct.usage) / Number(ct.limit)) * 100)) : 0;
  const live = d.live_enabled === true;
  const lookupEnabled = d.ip_lookup_enabled === true;
  const flows = live
    ? table(
        ["Proto", "Src", "Dst", "NAT'd To", "TX", "RX", "State", "Direction", "App", "Host"],
        (d.flows || []).map(
          (f) => `<tr>
        <td>${esc(f.protocol)}</td>
        <td class="mono">${esc(f.origin_src)}${f.src_port ? `:${esc(f.src_port)}` : ""}</td>
        <td class="mono">${ipOrgCell(f.origin_dst, lookupEnabled)}${f.dst_port ? `:${esc(f.dst_port)}` : ""}</td>
        <td class="mono">${f.nated_ip ? `${esc(f.nated_ip)}${f.nated_port ? `:${esc(f.nated_port)}` : ""}` : "-"}</td>
        <td class="mono">${bytes(f.tx_bytes)}</td>
        <td class="mono">${bytes(f.rx_bytes)}</td>
        <td>${esc(f.tcp_state)}</td>
        <td>${esc(f.direction)}</td>
        <td>${esc(f.application)}</td>
        <td>${esc(f.host_name)}</td>
      </tr>`
        )
      )
    : `<p class="muted">Live table is off. Turn it on only when you need it.</p>`;
  const countNote = live
    ? `${esc(String((d.flows || []).length))} entries from show conntrack. Byte counts are per flow lifetime, not current rate.`
    : "Summary counters above still refresh. The per-flow table is not fetched.";
  return `
    <h2>Summary</h2>
    <div class="grid">
      ${stat("Limit", ct.limit)}
      ${stat("Usage", ct.usage)}
      ${stat("Flows", ct.flows)}
      ${stat("NAT", ct.nat)}
    </div>
    <div class="stat">
      <label>Conntrack used</label>
      <strong>${esc(ct.usage || 0)} / ${esc(ct.limit || 0)} (${ctPct}%)</strong>
      <div class="bar"><span style="width:${ctPct}%"></span></div>
    </div>
    <h2>Live connections</h2>
    <label class="check-row">
      <input type="checkbox" id="conntrack-live" ${live ? "checked" : ""}>
      Show live connection table
    </label>
    <p class="warn">Warning: if there are too many connections, fetching this table can overload the NSE CPU and stall this app. Leave it off unless you need the table.</p>
    <label class="check-row">
      <input type="checkbox" id="conntrack-iplookup" ${lookupEnabled ? "checked" : ""}>
      Look up who owns a destination IP
    </label>
    <p class="muted">Off by default: this is the only feature in this app that sends anything to a third party — a free lookup service (ipwho.is) — instead of talking only to your device. When on, every destination IP shown below is looked up automatically (one at a time, not all at once) and cached, so each address is only ever looked up once.</p>
    <p class="muted">${countNote}</p>
    ${flows}
  `;
}

function renderInterfaces(d) {
  const ifaces = table(
    ["Interface", "MAC", "Status", "Speed", "Duplex", "Advertising"],
    (d.interfaces || []).map(
      (p) => `<tr>
        <td class="mono">${esc(p.interface)}</td>
        <td class="mono">${esc(p.mac)}</td>
        <td class="${p.status === "UP" ? "up" : "down"}">${esc(p.status)}</td>
        <td>${esc(p.speed)}</td>
        <td>${esc(p.duplex)}</td>
        <td>${esc(p.advertising)}</td>
      </tr>`
    )
  );
  const wan = (d.wan_dhcp || [])
    .map((w) => {
      const o = w.options || {};
      return `<div class="grid">
        ${stat("WAN interface", w.interface)}
        ${stat("Address", o.ip)}
        ${stat("Gateway", o.router)}
        ${stat("DNS", o.dns)}
        ${stat("Lease (s)", o.lease)}
        ${stat("Server", o.serverid)}
      </div>`;
    })
    .join("");
  const pppoe = table(
    ["Type", "Status", "VLAN", "Address", "Uptime"],
    (d.pppoe || []).map(
      (p) =>
        `<tr><td>${esc(p.type)}</td><td>${esc(p.status)}</td><td>${esc(p.vlan)}</td><td class="mono">${esc(p.address)}</td><td>${esc(p.uptime)}</td></tr>`
    )
  );
  return `<h2>Ethernet</h2>${ifaces}<h2>WAN DHCP client</h2>${wan || '<p class="muted">No WAN DHCP lease.</p>'}<h2>PPPoE</h2>${pppoe}`;
}

function renderRouting(d) {
  const routes = table(
    ["Destination", "Mask", "Gateway", "Flags", "Metric", "Interface"],
    (d.routes || []).map(
      (r) => `<tr>
        <td class="mono">${esc(r.destination)}</td>
        <td class="mono">${esc(r.mask)}</td>
        <td class="mono">${esc(r.gateway)}</td>
        <td>${esc(r.flags)}</td>
        <td>${esc(r.metric)}</td>
        <td>${esc(r.interface)}</td>
      </tr>`
    )
  );
  const arp = table(
    ["IP", "MAC", "Iface", "State"],
    (d.arp || []).map(
      (a) => `<tr>
        <td class="mono">${esc(a.ip)}</td>
        <td class="mono">${esc(a.mac)}</td>
        <td class="mono">${esc(a.iface)}</td>
        <td>${a.complete ? "complete" : "incomplete"}</td>
      </tr>`
    )
  );
  return `<h2>IPv4 routes</h2>${routes}<h2>ARP</h2>${arp}`;
}

function renderVlans(d) {
  const vlans = table(
    ["VLAN", "Address", "Mask", "Management"],
    (d.vlans || []).map(
      (v) =>
        `<tr><td class="mono">${esc(v.name || v.id)}</td><td class="mono">${esc(v.address)}</td><td class="mono">${esc(v.mask)}</td><td>${esc(v.management_access || "—")}</td></tr>`
    )
  );
  const ports = table(
    ["Port", "Type", "Mode", "Access", "Native", "Allowed"],
    (d.ports || [])
      .filter((p) => p.type === "lan" || p.mode)
      .map(
        (p) => `<tr>
          <td class="mono">${esc(p.interface)}</td>
          <td>${esc(p.type)}</td>
          <td>${esc(p.mode)}</td>
          <td class="mono">${esc(p.access_vlan)}</td>
          <td class="mono">${esc(p.native_vlan)}</td>
          <td class="mono">${esc(p.allowed_vlans)}</td>
        </tr>`
      )
  );
  return `<h2>VLAN interfaces</h2>${vlans}<h2>LAN switchports</h2>${ports}`;
}

function renderDhcp(d) {
  return `
    ${renderDhcpUsage(d)}
    <nav class="subtabs" id="dhcp-subtabs">
      <button type="button" data-sub="pools" class="${dhcpSub === "pools" ? "active" : ""}">Pools</button>
      <button type="button" data-sub="macs" class="${dhcpSub === "macs" ? "active" : ""}">MAC bound</button>
    </nav>
    ${dhcpSub === "macs" ? renderMacBound(d) : renderDhcpPools(d)}
  `;
}

// cnMaestro's subnet table carries a "Leases Used" bar per VLAN, which is
// the quickest way to see which pool is filling up. It sits above the
// subtabs, not inside one: it summarises the whole page, and putting it
// under Pools meant it vanished on the MAC bound tab, which is where
// someone hunting for a device is most likely to be standing. Here the same numbers
// were only visible by scrolling into each pool's own block and reading
// two separate stats, so a pool near exhaustion looked like any other.
//
// The device reports both figures directly: "allocated" is the pool's
// capacity and "usage" the number of leases handed out. They are strings,
// and are absent on a pool slot that is not configured.
function vlanFromPoolInterface(iface) {
  const m = /^br\d+\.(\d+)$/.exec(iface || "");
  return m ? m[1] : "";
}

function dhcpUsageRows(d) {
  const live = Object.fromEntries((d.pools || []).map((p) => [p.pool, p]));
  return (d.pool_config || [])
    .map((c) => {
      const p = live[c.pool] || {};
      const used = parseInt(p.usage, 10);
      const total = parseInt(p.allocated, 10);
      return {
        pool: c.pool,
        vlan: vlanFromPoolInterface(p.interface),
        range: c.address_range || "",
        used: Number.isNaN(used) ? null : used,
        total: Number.isNaN(total) ? null : total,
      };
    })
    .sort((a, b) => (parseInt(a.vlan, 10) || 0) - (parseInt(b.vlan, 10) || 0));
}

function renderDhcpUsage(d) {
  const rows = dhcpUsageRows(d);
  if (!rows.length) return "";
  const cells = rows
    .map((r) => {
      // A pool with no capacity reported gets no bar rather than a
      // misleading empty one, and never a division by zero.
      const known = r.used != null && r.total != null && r.total > 0;
      const pct = known ? Math.min(100, Math.round((r.used / r.total) * 100)) : 0;
      const bar = known
        ? `<div class="bar"><span style="width:${pct}%"></span></div>`
        : `<span class="muted">-</span>`;
      const count = known ? `${r.used} / ${r.total}` : "-";
      const selected = dhcpPoolFilter === r.pool;
      return `<tr data-pool="${esc(r.pool)}" class="row-pick${selected ? " is-picked" : ""}" title="${selected ? "Show every VLAN again" : `Show only VLAN ${esc(r.vlan || r.pool)}`}">
        <td>${esc(r.vlan || "-")}</td>
        <td>${esc(r.pool)}</td>
        <td class="mono">${esc(r.range)}</td>
        <td style="min-width:140px">${bar}</td>
        <td class="mono">${esc(count)}</td>
      </tr>`;
    });
  const picked = rows.find((r) => r.pool === dhcpPoolFilter);
  const banner = picked
    ? `<p class="muted">Showing VLAN ${esc(picked.vlan || picked.pool)} only. <button type="button" class="row-edit" data-pool-clear>Show all</button></p>`
    : `<p class="muted">Select a row to show just that VLAN below.</p>`;
  return `<h2>Leases used</h2>
    ${table(["VLAN", "Pool", "Range", "", "Used"], cells)}
    ${banner}`;
}

function renderDhcpPools(d) {
  const cfgs = (d.pool_config || []).filter((c) => dhcpPoolFilter === null || c.pool === dhcpPoolFilter);
  const live = Object.fromEntries((d.pools || []).map((p) => [p.pool, p]));
  const blocks = cfgs
    .map((c) => {
      const p = live[c.pool] || {};
      const leases = table(
        ["MAC", "IP", "Hostname", "Expires"],
        (p.leases || []).map(
          (l) =>
            `<tr><td class="mono">${esc(l.mac)}</td><td class="mono">${esc(l.ip)}</td><td>${esc(l.hostname)}</td><td class="mono">${esc(l.expires)}</td></tr>`
        )
      );
      return `<h2>Pool ${esc(c.pool)}${p.status ? ` · ${esc(p.status)}` : ""}${p.interface ? ` · ${esc(p.interface)}` : ""}</h2>
        <div class="grid">
          ${stat("Range", c.address_range)}
          ${stat("Network", c.network)}
          ${stat("Router", c.router)}
          ${stat("DNS", c.dns)}
          ${stat("Lease", c.lease)}
          ${stat("Domain", c.domain)}
          ${stat("Allocated", p.allocated)}
          ${stat("Usage", p.usage)}
        </div>
        ${leases}`;
    })
    .join("");
  const extra = (d.pools || []).filter((p) => !cfgs.some((c) => c.pool === p.pool));
  const extras = extra
    .map((p) => {
      const leases = table(
        ["MAC", "IP", "Hostname", "Expires"],
        (p.leases || []).map(
          (l) =>
            `<tr><td class="mono">${esc(l.mac)}</td><td class="mono">${esc(l.ip)}</td><td>${esc(l.hostname)}</td><td class="mono">${esc(l.expires)}</td></tr>`
        )
      );
      return `<h2>Pool ${esc(p.pool)} · ${esc(p.status)} · ${esc(p.interface)}</h2>
        <div class="grid">${stat("Allocated", p.allocated)}${stat("Usage", p.usage)}</div>
        ${leases}`;
    })
    .join("");
  const auth = d.authoritative ? "Authoritative DHCP server" : "DHCP server";
  return `<p class="muted">${esc(auth)}</p>${blocks || extras || `<p class="muted">No DHCP pools returned.</p>`}`;
}

function renderMacBound(d) {
  const rows = table(
    ["Pool", "MAC", "IP", "Description"],
    (d.bindings || [])
      .filter((b) => dhcpPoolFilter === null || b.pool === dhcpPoolFilter)
      .map(
      (b) =>
        `<tr><td>${esc(b.pool)}</td><td class="mono">${esc(b.mac)}</td><td class="mono">${esc(b.ip)}</td><td>${esc(b.description)}</td></tr>`
    )
  );
  return `<h2>MAC bound addresses</h2>
    <p class="muted">Reservations from DHCP pool config. Bound IPs are usually outside the dynamic range.</p>
    ${rows}`;
}

function renderNeighbors(d) {
  const lldp = (d.lldp || [])
    .map((n) => {
      const fields = Object.entries(n.fields || {})
        .map(([k, v]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`)
        .join("");
      return `<h2>${esc(n.sysname || n.interface || "Neighbor")}</h2>
        <p class="muted">${esc(n.header || "")}</p>
        <div class="table-wrap"><table><tbody>${fields}</tbody></table></div>`;
    })
    .join("");
  const rem = d.remote || {};
  return `
    <div class="grid">
      ${stat("Device", rem.summary && rem.summary.device_status)}
      ${stat("State", rem.summary && rem.summary.state)}
      ${stat("Cambium-ID", d.cambium && d.cambium.cambium_id)}
    </div>
    <h2>cnMaestro detail</h2>
    <pre class="muted" style="white-space:pre-wrap;font-family:var(--mono);font-size:12px">${esc(
      rem.raw || ""
    )}</pre>
    <h2>LLDP</h2>
    ${lldp || '<p class="muted">No LLDP neighbors.</p>'}
  `;
}

function renderDevices(d) {
  const clients = d.clients || [];
  const rows = table(
    ["MAC", "IP Address", "Hostname", "Type", "Type Name", "Brand", "OS", "OS Version", "Last Seen"],
    clients.map(
      (c) =>
        `<tr>
          <td class="mono">${esc(c.mac)}</td>
          <td class="mono">${esc(c.ip)}</td>
          <td>${esc(c.hostname)}</td>
          <td>${esc(c.type)}</td>
          <td>${esc(c.type_name)}</td>
          <td>${esc(c.brand)}</td>
          <td>${esc(c.os)}</td>
          <td>${esc(c.os_version)}</td>
          <td class="mono">${esc(c.last_seen)}</td>
        </tr>`
    )
  );
  return `
    <h2>Connected Devices</h2>
    <p class="muted">Device-identification fingerprints (type, brand, OS) for hosts the NSE has seen on the LAN — this is the result of Vulnerability Scan/Device Identification, gated by the same per-VLAN toggles on the Config page's Network tab. Discovered open ports aren't exposed by this CLI, only the identification result.</p>
    ${rows || '<p class="muted">No connected clients found.</p>'}
  `;
}

function renderTraffic(d) {
  const apps = (d.by_application || []).slice(0, 40);
  const cats = d.by_category || [];
  const appTable = table(
    ["Application", "TX", "RX", "Total"],
    apps.map(
      (a) =>
        `<tr><td>${esc(a.name)}</td><td class="mono">${bytes(a.tx_bytes)}</td><td class="mono">${bytes(a.rx_bytes)}</td><td class="mono">${bytes(
          a.tx_bytes + a.rx_bytes
        )}</td></tr>`
    )
  );
  const catTable = table(
    ["Category", "TX", "RX", "Total"],
    cats.map(
      (a) =>
        `<tr><td>${esc(a.name)}</td><td class="mono">${bytes(a.tx_bytes)}</td><td class="mono">${bytes(a.rx_bytes)}</td><td class="mono">${bytes(
          a.tx_bytes + a.rx_bytes
        )}</td></tr>`
    )
  );
  return `<h2>Applications (top 40 by bytes)</h2>${appTable}<h2>Categories</h2>${catTable}`;
}

function renderTunnels(d) {
  const cfg = d.config || {};
  const sl = cfg.starlink || {};
  const vpn = cfg.vpn_server || {};
  const ping = d.starlink_ping || {};
  const wan = (d.wan_dhcp || [])[0] || {};
  const o = wan.options || {};
  const sessions = d.vpn || [];
  const wanIface = (d.interfaces || []).find((p) => p.interface === "eth1") || {};

  const vpnBlocks = sessions
    .map((s) => {
      const label = s.kind || "vpn";
      if (s.empty_json) {
        return `<p><strong>${esc(label)}</strong> — no active sessions (empty JSON from CLI).</p>`;
      }
      if (s.error) {
        return `<p><strong>${esc(label)}</strong> — ${esc(s.error)}</p>`;
      }
      return `<p><strong>${esc(label)}</strong> — ${esc(String((s.rows || []).length))} session(s)</p>`;
    })
    .join("");

  return `
    <h2>Starlink</h2>
    <div class="grid">
      ${stat("Enabled", sl.enabled ? "yes" : "no")}
      ${stat("WAN", sl.wan_name || sl.interface || "—")}
      ${stat("Dish mode", sl.dish_mode)}
      ${stat("Dish IP", sl.dish_ip)}
      ${stat("Dish ping", ping.ok ? `ok · ${ping.rtt || ping.loss_pct}` : ping.loss_pct || "fail")}
      ${stat("WAN1 link", wanIface.status)}
      ${stat("WAN address", o.ip)}
      ${stat("WAN gateway", o.router)}
    </div>
    <h2>Client VPN (L2TP / IPsec / WireGuard)</h2>
    <div class="grid">
      ${stat("Server", vpn.enabled ? "enabled" : "disabled")}
      ${stat("Listen WAN", vpn.interface)}
      ${stat("Client pool", vpn.address_range)}
      ${stat("MFA", vpn.mfa ? "on" : "off")}
    </div>
    ${vpnBlocks}
    <p class="muted">Active session tables come from <span class="mono">show vpn-sessions …</span>. Empty JSON means the service is up but no clients are connected, or the NSE returned no session payload.</p>
  `;
}

function renderTailscale(d) {
  const cfg = d.config || {};
  const peers = d.peers || [];
  const self = peers.find((p) => p.self);
  const others = peers.filter((p) => !p.self);
  const onlineCount = others.filter((p) => !p.offline).length;

  const peerRows = table(
    ["Host Name", "OS", "IP Address", "Status", "TX", "RX", "Exit Node", "Last Seen"],
    others.map((p) => {
      const cls = p.offline ? "down" : "up";
      const status = p.offline ? "Offline" : p.idle ? "Idle" : "Online";
      return `<tr>
        <td>${esc(p.name)}</td>
        <td>${esc(p.os)}</td>
        <td class="mono">${esc(p.ip)}${p.direct_addr ? ` <span class="muted">(direct ${esc(p.direct_addr)})</span>` : ""}</td>
        <td class="${cls}">${esc(status)}</td>
        <td class="mono">${p.tx_bytes ? bytes(p.tx_bytes) : "-"}</td>
        <td class="mono">${p.rx_bytes ? bytes(p.rx_bytes) : "-"}</td>
        <td>${p.exit_node ? "Yes" : "No"}</td>
        <td>${esc(p.last_seen || (p.offline ? "-" : "now"))}</td>
      </tr>`;
    })
  );

  return `
    <h2>Tailscale</h2>
    <div class="grid">
      ${stat("Enabled", cfg.enabled ? "yes" : "no")}
      ${stat("Accept routes", cfg.accept_routes ? "yes" : "no")}
      ${stat("Advertise routes", cfg.advertise_routes || "-")}
      ${stat("Auth key", cfg.auth_key_set ? "set" : "none")}
    </div>
    <h2>Tailnet Peers</h2>
    <div class="grid">
      ${stat("Total peers", others.length)}
      ${stat("Online", onlineCount)}
      ${stat("This device", self ? self.name : "-")}
    </div>
    <p class="muted">From <span class="mono">show tailscale status</span> — this device's own CLI output, not the Tailscale admin console. There's no confirmed way to get DERP relay/latency-per-region or a distinct "Relay Server" per peer from this device's CLI, so those columns from cnMaestro's Tailnet page aren't shown here.</p>
    ${peerRows || '<p class="muted">No peers.</p>'}
  `;
}

function renderFirewallCounters(d) {
  const rows = d.outbound_firewall || [];
  const table1 = table(
    ["Rule ID", "Name", "Packets", "Bytes", "Comment"],
    rows.map(
      (r) => `<tr>
        <td>${esc(r.rule_id)}</td>
        <td>${esc(r.name)}</td>
        <td class="mono">${esc(r.packets)}</td>
        <td class="mono">${esc(r.bytes)}</td>
        <td class="mono">${esc(r.comment || "-")}</td>
      </tr>`
    )
  );
  return `
    <h2>Outbound Firewall</h2>
    <p class="muted">Per-rule hit counters from <span class="mono">show counters outbound_firewall</span>.</p>
    ${table1 || '<p class="muted">No filter rules found.</p>'}
    <h2>DNAT / Traffic Shaping / Flow Preferences</h2>
    <p class="muted">Not tracked here — this app doesn't yet support configuring NAT, traffic shaping, or flow preference rules, so there's nothing to show counters for.</p>
  `;
}

function renderEvents(d) {
  return table(
    ["Time", "Code", "Message"],
    (d.events || []).map(
      (e) =>
        `<tr><td class="mono">${esc(e.time)}</td><td class="mono">${esc(e.code)}</td><td>${esc(e.message)}</td></tr>`
    )
  );
}

function renderConfig(d) {
  const text = d.config || "";
  return `<h2>Running config <span class="muted">show config · secrets stripped</span></h2>
    <p class="muted">Passwords, PSKs, auth keys, and $crypt$ values are redacted. This is the live CLI config, not a writable editor.</p>
    <pre class="debug-out">${esc(text || "(empty)")}</pre>`;
}

function activate(tab, force = false) {
  current = tab;
  tabs.forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  Object.entries(panels).forEach(([id, el]) => el.classList.toggle("active", id === tab));
  load(tab, force);
}

let page = "status";

function showPage(next, force = false) {
  page = next;
  document.querySelectorAll(".menu button").forEach((b) => {
    b.classList.toggle("active", b.dataset.page === next);
  });
  document.getElementById("page-status").hidden = next !== "status";
  document.getElementById("page-settings").hidden = next !== "settings";
  document.getElementById("page-connections").hidden = next !== "connections";
  const configPage = document.getElementById("page-config");
  if (configPage) configPage.hidden = next !== "config";
  document.getElementById("status-tabs").hidden = next !== "status";
  document.getElementById("refresh").hidden = next !== "status";
  document.getElementById("auto-refresh-label").hidden = next !== "status";
  if (next === "connections") {
    document.getElementById("title").textContent = "Connections";
    loadSettings();
    location.hash = "connections";
    return;
  }
  if (next === "settings") {
    document.getElementById("title").textContent = "Settings";
    loadSettings();
    location.hash = "settings";
    return;
  }
  if (next === "config") {
    document.getElementById("title").textContent = "Configuration";
    location.hash = "config";
    if (window.NSEConfig) window.NSEConfig.onShow();
    return;
  }
  location.hash = "";
  activate(current, force);
}

async function loadSettings() {
  const err = document.getElementById("error");
  const note = document.getElementById("settings-note");
  err.hidden = true;
  try {
    const res = await fetch("/api/settings");
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    // renderProfileSlots refreshes `connections`, so it runs before the
    // form is filled from it.
    renderProfileSlots(data);
    // Keep editing whatever is selected; fall back to the live connection.
    if (!connById(selectedSlot)) selectedSlot = data.active_id || 0;
    fillConnForm(connById(selectedSlot));
    applyLiveConntrack(data.live_conntrack);
    document.getElementById("settings-file").textContent = data.file ? `Saved in ${data.file}` : "";
    note.textContent = "";
  } catch (e) {
    err.hidden = false;
    err.textContent = e.message;
  }
}

// --- Connection manager ------------------------------------------------
//
// One connection is live at a time: opening a site closes the previous
// SSH session. The header switcher is the quick path; the Settings page
// is where connections are added, renamed and deleted.

let connections = [];
let connFilter = "";

function connById(id) {
  return connections.find((c) => c.id === id) || null;
}

function activeConn() {
  return connections.find((c) => c.active) || null;
}

function renderConnSwitcher() {
  const label = document.getElementById("conn-current-label");
  const menu = document.getElementById("conn-menu");
  const cur = activeConn();
  label.textContent = cur ? cur.label : "No connection";
  if (!cur) setConnDot("unknown");
  // Always rendered, including with a single site. It is the only
  // persistent indication of *which device* everything on screen refers
  // to, and hiding it until a second connection exists meant there was
  // nothing to discover the feature from in the state every new user
  // starts in.
  const items = connections
    .map(
      (c) => `<button type="button" class="conn-menu-item${c.active ? " active" : ""}" data-conn="${c.id}">
        <span class="conn-dot${c.active ? " on" : ""}"></span>
        <span class="conn-menu-text">
          <span class="conn-menu-name">${esc(c.label)}</span>
          <span class="conn-menu-host mono">${esc(c.user)}@${esc(c.host)}:${esc(c.port)}</span>
        </span>
      </button>`
    )
    .join("");
  menu.innerHTML = `${items || '<p class="conn-menu-empty muted">No saved connections yet.</p>'}
    <div class="conn-menu-sep"></div>
    <button type="button" class="conn-menu-item conn-menu-manage" data-conn-manage="1">
      ${connections.length ? "Manage connections…" : "Add a connection…"}
    </button>`;
}

function renderConnList(data) {
  const el = document.getElementById("conn-list");
  if (!el) return;
  const needle = connFilter.trim().toLowerCase();
  const shown = needle
    ? connections.filter(
        (c) => c.label.toLowerCase().includes(needle) || c.host.toLowerCase().includes(needle)
      )
    : connections;
  if (!connections.length) {
    el.innerHTML = `<p class="muted">No saved connections yet. Add one below.</p>`;
    return;
  }
  if (!shown.length) {
    el.innerHTML = `<p class="muted">Nothing matches "${esc(connFilter)}".</p>`;
    return;
  }
  el.innerHTML = shown
    .map(
      (c) => `<button type="button" class="conn-row${c.active ? " active" : ""}${c.id === selectedSlot ? " selected" : ""}" data-conn="${c.id}">
        <span class="conn-dot${c.active ? " on" : ""}"></span>
        <span class="conn-row-name">${esc(c.label)}</span>
        <span class="conn-row-host mono">${esc(c.user)}@${esc(c.host)}:${esc(c.port)}</span>
        ${c.active ? '<span class="conn-row-tag">connected</span>' : ""}
      </button>`
    )
    .join("");
}

function fillConnForm(conn) {
  document.getElementById("set-slot").value = String(conn ? conn.id : 0);
  document.getElementById("set-name").value = conn ? conn.name || "" : "";
  document.getElementById("set-host").value = conn ? conn.host : "";
  document.getElementById("set-user").value = conn ? conn.user : "admin";
  document.getElementById("set-port").value = conn ? conn.port : "22";
  const pw = document.getElementById("set-password");
  pw.value = "";
  pw.placeholder = conn && conn.password_set ? "Leave blank to keep the current password" : "Required";
  document.getElementById("conn-form-heading").textContent = conn
    ? `Edit ${conn.label}`
    : "New connection";
  document.getElementById("settings-clear").hidden = !conn;
}

function renderProfileSlots(data) {
  connections = data.connections || data.profiles || [];
  renderConnSwitcher();
  renderConnList(data);
}

async function openConnection(id) {
  const err = document.getElementById("error");
  const note = document.getElementById("settings-note");
  err.hidden = true;
  note.textContent = "Connecting…";
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "open", id }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    // Every cached panel belongs to the site we just left.
    Object.keys(cache).forEach((k) => delete cache[k]);
    selectedSlot = data.active_id || id;
    await loadSettings();
    if (data.connected) {
      note.textContent = `Connected to ${data.name || data.host}`;
      setConnDot("on");
      if (page === "status") load(current, true, true);
    } else {
      setConnDot("down");
      note.textContent = "Selected, but SSH did not connect yet.";
      err.hidden = false;
      err.textContent = data.detail || "Could not connect";
    }
  } catch (e) {
    note.textContent = "";
    err.hidden = false;
    err.textContent = e.message;
  }
}

// Header switcher.
const connMenu = document.getElementById("conn-menu");
const connCurrentBtn = document.getElementById("conn-current");

function closeConnMenu() {
  connMenu.hidden = true;
  connCurrentBtn.setAttribute("aria-expanded", "false");
}

connCurrentBtn.addEventListener("click", () => {
  const opening = connMenu.hidden;
  connMenu.hidden = !opening;
  connCurrentBtn.setAttribute("aria-expanded", opening ? "true" : "false");
});
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") closeConnMenu();
});
connMenu.addEventListener("click", async (ev) => {
  const manage = ev.target.closest("[data-conn-manage]");
  if (manage) {
    closeConnMenu();
    showPage("connections");
    return;
  }
  const btn = ev.target.closest("[data-conn]");
  if (!btn) return;
  closeConnMenu();
  const id = Number(btn.dataset.conn);
  if (id === (activeConn() || {}).id) return;
  await openConnection(id);
});
document.addEventListener("click", (ev) => {
  if (connMenu.hidden) return;
  if (ev.target.closest("#conn-switcher")) return;
  closeConnMenu();
});

// Settings-page list: clicking a row selects it for editing and connects.
document.getElementById("conn-list").addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-conn]");
  if (!btn) return;
  const id = Number(btn.dataset.conn);
  selectedSlot = id;
  fillConnForm(connById(id));
  renderConnList();
  if (id !== (activeConn() || {}).id) await openConnection(id);
});

document.getElementById("conn-filter").addEventListener("input", (ev) => {
  connFilter = ev.target.value;
  renderConnList();
});

document.getElementById("conn-new").addEventListener("click", () => {
  selectedSlot = 0;
  fillConnForm(null);
  renderConnList();
  document.getElementById("set-name").focus();
});

document.getElementById("settings-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = document.getElementById("error");
  const note = document.getElementById("settings-note");
  const btn = document.getElementById("settings-save");
  err.hidden = true;
  note.textContent = "Saving…";
  btn.disabled = true;
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "save",
        id: Number(document.getElementById("set-slot").value || 0),
        name: document.getElementById("set-name").value,
        host: document.getElementById("set-host").value,
        user: document.getElementById("set-user").value,
        password: document.getElementById("set-password").value,
        port: document.getElementById("set-port").value,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    Object.keys(cache).forEach((k) => delete cache[k]);
    selectedSlot = data.active_id || selectedSlot;
    await loadSettings();
    if (data.connected) {
      note.textContent = `Saved ${data.name || data.host}`;
      setConnDot("on");
    } else {
      setConnDot("down");
      note.textContent = "Saved, but SSH did not connect yet.";
      err.hidden = false;
      err.textContent = data.detail || "Could not connect";
    }
  } catch (e) {
    note.textContent = "";
    err.hidden = false;
    err.textContent = e.message;
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("settings-clear").addEventListener("click", async () => {
  const id = Number(document.getElementById("set-slot").value || 0);
  const conn = connById(id);
  if (!conn) return;
  if (!window.confirm(`Delete the saved connection "${conn.label}"? This does not change the device.`)) return;
  const err = document.getElementById("error");
  const note = document.getElementById("settings-note");
  err.hidden = true;
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "clear", id }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    selectedSlot = data.active_id || 0;
    await loadSettings();
    note.textContent = `Deleted ${conn.label}`;
  } catch (e) {
    err.hidden = false;
    err.textContent = e.message;
  }
});

document.getElementById("panel-dhcp").addEventListener("click", (ev) => {
  const clear = ev.target.closest("[data-pool-clear]");
  const row = ev.target.closest("[data-pool]");
  const sub = ev.target.closest("[data-sub]");
  if (clear) {
    dhcpPoolFilter = null;
  } else if (row) {
    // Clicking the selected VLAN again clears the filter, so the row is
    // its own way back out.
    const pool = parseInt(row.dataset.pool, 10);
    dhcpPoolFilter = dhcpPoolFilter === pool ? null : pool;
  } else if (sub) {
    // The filter deliberately survives a subtab switch: it names a VLAN,
    // and both subtabs show that VLAN's data.
    dhcpSub = sub.dataset.sub;
  } else {
    return;
  }
  if (cache.dhcp) render("dhcp", cache.dhcp);
});

function applyLiveConntrack(on) {
  liveConntrack = !!on;
  const box = document.getElementById("set-live-conntrack");
  if (box) box.checked = liveConntrack;
  const pageBox = document.getElementById("conntrack-live");
  if (pageBox) pageBox.checked = liveConntrack;
}

async function persistLiveConntrack(on) {
  applyLiveConntrack(on);
  const err = document.getElementById("error");
  err.hidden = true;
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "prefs", live_conntrack: liveConntrack }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    delete cache.conntrack;
    if (page === "status" && current === "conntrack") load("conntrack", true);
  } catch (e) {
    err.hidden = false;
    err.textContent = e.message;
  }
}

document.getElementById("set-live-conntrack").addEventListener("change", (ev) => {
  persistLiveConntrack(ev.target.checked);
});
document.getElementById("panel-conntrack").addEventListener("change", (ev) => {
  const liveBox = ev.target.closest("#conntrack-live");
  if (liveBox) {
    persistLiveConntrack(liveBox.checked);
    return;
  }
  const lookupBox = ev.target.closest("#conntrack-iplookup");
  if (lookupBox) persistIPLookup(lookupBox.checked);
});

async function persistIPLookup(on) {
  const err = document.getElementById("error");
  err.hidden = true;
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "prefs", ip_lookup: on }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    if (page === "status" && current === "conntrack") load("conntrack", true);
  } catch (e) {
    err.hidden = false;
    err.textContent = e.message;
  }
}


tabs.forEach((b) => b.addEventListener("click", () => activate(b.dataset.tab)));
document.querySelectorAll(".menu button").forEach((b) => {
  b.addEventListener("click", () => showPage(b.dataset.page));
});
document.getElementById("refresh").addEventListener("click", () => load(current, true));

// The "Open in Browser" button only makes sense inside the native app
// window, where window.nseOpenInBrowser is bound by cmd/nse-app. It's
// absent when this page is already loaded in a real browser (nse-status,
// or a tab opened via this very button), so the button stays hidden there.
if (typeof window.nseOpenInBrowser === "function") {
  const openBtn = document.getElementById("open-in-browser");
  openBtn.hidden = false;
  openBtn.addEventListener("click", () => window.nseOpenInBrowser());
}

const autoBox = document.getElementById("auto-refresh");
const autoInterval = document.getElementById("auto-refresh-interval");
autoBox.checked = localStorage.getItem(AUTO_KEY) !== "0";
{
  const saved = Number(localStorage.getItem(AUTO_INTERVAL_KEY));
  autoInterval.value = String(AUTO_INTERVALS.includes(saved) ? saved : 5000);
}

function autoRefreshMs() {
  const ms = Number(autoInterval.value);
  return AUTO_INTERVALS.includes(ms) ? ms : 5000;
}

function startAutoRefresh() {
  if (timer) clearInterval(timer);
  timer = setInterval(() => {
    if (page === "status" && autoBox.checked && current !== "config") load(current, true, true);
  }, autoRefreshMs());
}

autoBox.addEventListener("change", () => {
  localStorage.setItem(AUTO_KEY, autoBox.checked ? "1" : "0");
  startAutoRefresh();
});
autoInterval.addEventListener("change", () => {
  localStorage.setItem(AUTO_INTERVAL_KEY, String(autoRefreshMs()));
  startAutoRefresh();
});

// afterScripts defers work until every <script> tag in the document has
// executed. app.js runs first, so at this point config-common.js and the
// section modules it hosts do not exist yet — and showPage("config") calls
// window.NSEConfig.onShow(), which would silently no-op and leave the
// Configuration page blank.
//
// This used to be a setTimeout(fn, 0), which only *usually* wins that
// race: a timer callback runs whenever the parser next yields, which may
// be before the remaining script tags have run. When it lost, a deep link
// or reload onto #config rendered an empty page with no error anywhere.
// DOMContentLoaded is the event that actually guarantees what is needed.
function afterScripts(fn) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", fn, { once: true });
  } else {
    fn();
  }
}

if (location.hash === "#settings") {
  showPage("settings");
} else if (location.hash === "#connections") {
  afterScripts(() => showPage("connections"));
} else if (location.hash === "#config") {
  afterScripts(() => showPage("config"));
} else {
  activate("overview", true);
}

// The switcher lives in the header, so it has to know the connection list
// on every page — not just the two that call loadSettings(). This runs
// unconditionally at startup for that reason; it used to be tucked inside
// the no-hash branch, which left the switcher showing "—" and an empty
// menu whenever the app opened straight onto Status.
fetch("/api/settings")
  .then((r) => r.json())
  .then((d) => {
    renderProfileSlots(d);
    applyLiveConntrack(d.live_conntrack);
    if (!d.password_set && !location.hash) showPage("connections");
  })
  .catch(() => {});

startAutoRefresh();
initHeader();
