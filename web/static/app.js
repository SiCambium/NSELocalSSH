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
  "tunnels",
  "traffic",
  "events",
  "config",
];
const tabs = [...document.querySelectorAll(".tabs button")];
const panels = Object.fromEntries(TAB_IDS.map((id) => [id, document.getElementById(`panel-${id}`)]));

let current = "overview";
let dhcpSub = "pools";
let selectedSlot = 1;
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
    if ((tab === "overview" || tab === "throughput") && !data.rates_ready) {
      setTimeout(() => {
        if (current === tab) load(tab, true, true);
      }, 1200);
    }
  } catch (e) {
    err.hidden = false;
    err.textContent = e.message;
    state.textContent = "Error";
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
  if (tab === "tunnels") el.innerHTML = renderTunnels(data);
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

function renderOverview(d) {
  const v = d.version || {};
  const remote = d.remote || {};
  const mem = d.memory || {};
  const cpu = d.cpu || {};
  const usedPct = mem.used_pct != null ? mem.used_pct : 0;
  const cpuPct = cpu.used_pct != null ? cpu.used_pct : 0;
  document.getElementById("title").textContent = v.hostname || v.identity || "NSE 3000";
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
  `;
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
  document.getElementById("title").textContent = v.identity || "NSE 3000";
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

function renderConntrack(d) {
  const ct = d.summary || {};
  const ctPct = ct.limit ? Math.min(100, Math.round((Number(ct.usage) / Number(ct.limit)) * 100)) : 0;
  const live = d.live_enabled === true;
  const flows = live
    ? table(
        ["Proto", "Src", "Dst", "TX", "RX", "State", "Direction", "App", "Host"],
        (d.flows || []).map(
          (f) => `<tr>
        <td>${esc(f.protocol)}</td>
        <td class="mono">${esc(f.origin_src)}${f.src_port ? `:${esc(f.src_port)}` : ""}</td>
        <td class="mono">${esc(f.origin_dst)}${f.dst_port ? `:${esc(f.dst_port)}` : ""}</td>
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
    <nav class="subtabs" id="dhcp-subtabs">
      <button type="button" data-sub="pools" class="${dhcpSub === "pools" ? "active" : ""}">Pools</button>
      <button type="button" data-sub="macs" class="${dhcpSub === "macs" ? "active" : ""}">MAC bound</button>
    </nav>
    ${dhcpSub === "macs" ? renderMacBound(d) : renderDhcpPools(d)}
  `;
}

function renderDhcpPools(d) {
  const cfgs = d.pool_config || [];
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
    (d.bindings || []).map(
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

function renderTraffic(d) {
  const apps = (d.by_application || []).slice(0, 40);
  const cats = d.by_category || [];
  const rules = table(
    ["ID", "Name", "Precedence", "Rule"],
    (d.filter_rules || []).map(
      (r) =>
        `<tr><td>${esc(r.id)}</td><td>${esc(r.name)}</td><td>${esc(r.precedence)}</td><td class="mono">${esc(r.rule)}</td></tr>`
    )
  );
  const counters = table(
    ["Name", "Prec", "Type", "Packets", "Bytes"],
    (d.filter_counters || []).map(
      (r) =>
        `<tr><td>${esc(r.name)}</td><td>${esc(r.precedence)}</td><td>${esc(r.type)}</td><td>${esc(r.packets)}</td><td>${esc(r.bytes)}</td></tr>`
    )
  );
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
  return `<h2>Firewall rules</h2>${rules}<h2>Filter counters</h2>${counters}<h2>Applications (top 40 by bytes)</h2>${appTable}<h2>Categories</h2>${catTable}`;
}

function renderTunnels(d) {
  const cfg = d.config || {};
  const sl = cfg.starlink || {};
  const vpn = cfg.vpn_server || {};
  const tsCfg = cfg.tailscale || {};
  const ping = d.starlink_ping || {};
  const wan = (d.wan_dhcp || [])[0] || {};
  const o = wan.options || {};
  const peers = d.tailscale || [];
  const sessions = d.vpn || [];
  const wanIface = (d.interfaces || []).find((p) => p.interface === "eth1") || {};

  const peerRows = table(
    ["IP", "Name", "User", "OS", "Status"],
    peers.map((p) => {
      const cls = p.offline ? "down" : "up";
      const name = p.self ? `${p.name} (this NSE)` : p.name;
      return `<tr>
        <td class="mono">${esc(p.ip)}</td>
        <td>${esc(name)}</td>
        <td>${esc(p.user)}</td>
        <td>${esc(p.os)}</td>
        <td class="${cls}">${esc(p.status)}</td>
      </tr>`;
    })
  );

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
    <h2>Tailscale</h2>
    <div class="grid">
      ${stat("Enabled", tsCfg.enabled ? "yes" : "no")}
      ${stat("Accept routes", tsCfg.accept_routes ? "yes" : "no")}
      ${stat("Advertise", tsCfg.advertise_routes)}
      ${stat("Auth key", tsCfg.auth_key_set ? "set" : "none")}
    </div>
    ${peerRows}
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
  const configPage = document.getElementById("page-config");
  if (configPage) configPage.hidden = next !== "config";
  document.getElementById("status-tabs").hidden = next !== "status";
  document.getElementById("refresh").hidden = next !== "status";
  document.getElementById("auto-refresh-label").hidden = next !== "status";
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
    selectedSlot = data.active_id || selectedSlot || 1;
    const slot = (data.profiles || []).find((p) => p.id === selectedSlot) || data;
    fillSettingsForm({ ...slot, id: selectedSlot }, data);
    renderProfileSlots(data);
    applyLiveConntrack(data.live_conntrack);
    document.getElementById("settings-file").textContent = data.file ? `Saved in ${data.file}` : "";
    note.textContent = "";
  } catch (e) {
    err.hidden = false;
    err.textContent = e.message;
  }
}

function fillSettingsForm(slot, data) {
  document.getElementById("set-slot").value = String(slot.id || selectedSlot);
  document.getElementById("set-host").value = slot.host || "";
  document.getElementById("set-user").value = slot.user || data.user || "admin";
  document.getElementById("set-port").value = slot.port || "22";
  document.getElementById("set-password").value = "";
  document.getElementById("set-password").placeholder = slot.password_set
    ? "Leave blank to keep the current password"
    : "Required";
}

function renderProfileSlots(data) {
  const el = document.getElementById("profile-slots");
  const profiles = data.profiles || [];
  el.innerHTML = profiles
    .map((p) => {
      const label = p.empty ? `Empty` : p.name || p.host;
      const cls = [
        "profile-slot",
        p.id === selectedSlot ? "selected" : "",
        p.id === data.active_id ? "active" : "",
        p.empty ? "empty" : "",
      ]
        .filter(Boolean)
        .join(" ");
      return `<button type="button" class="${cls}" data-slot="${p.id}" data-empty="${p.empty ? "1" : "0"}">
        <span class="slot-num">${p.id}</span>
        <span class="slot-name">${esc(label)}</span>
      </button>`;
    })
    .join("");
}

async function openSlot(slot) {
  const err = document.getElementById("error");
  const note = document.getElementById("settings-note");
  err.hidden = true;
  note.textContent = "Opening…";
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "open", slot }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    Object.keys(cache).forEach((k) => delete cache[k]);
    selectedSlot = data.active_id || slot;
    await loadSettings();
    if (data.connected) {
      note.textContent = `Opened ${data.name || data.host}`;
    } else {
      note.textContent = "Opened, but SSH did not connect yet.";
      err.hidden = false;
      err.textContent = data.detail || "Could not connect";
    }
  } catch (e) {
    note.textContent = "";
    err.hidden = false;
    err.textContent = e.message;
  }
}

document.getElementById("profile-slots").addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-slot]");
  if (!btn) return;
  const slot = Number(btn.dataset.slot);
  selectedSlot = slot;
  document.getElementById("set-slot").value = String(slot);
  if (btn.dataset.empty === "1") {
    document.querySelectorAll(".profile-slot").forEach((b) => {
      b.classList.toggle("selected", Number(b.dataset.slot) === slot);
    });
    document.getElementById("set-host").value = "";
    document.getElementById("set-password").value = "";
    document.getElementById("set-password").placeholder = "Required";
    document.getElementById("settings-note").textContent = `Editing empty slot ${slot}`;
    return;
  }
  await openSlot(slot);
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
        slot: Number(document.getElementById("set-slot").value || selectedSlot),
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
    } else {
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
  const slot = Number(document.getElementById("set-slot").value || selectedSlot);
  const err = document.getElementById("error");
  const note = document.getElementById("settings-note");
  err.hidden = true;
  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "clear", slot }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    selectedSlot = data.active_id || slot;
    await loadSettings();
    note.textContent = `Cleared slot ${slot}`;
  } catch (e) {
    err.hidden = false;
    err.textContent = e.message;
  }
});

document.getElementById("panel-dhcp").addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-sub]");
  if (!b) return;
  dhcpSub = b.dataset.sub;
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
  const box = ev.target.closest("#conntrack-live");
  if (!box) return;
  persistLiveConntrack(box.checked);
});

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

if (location.hash === "#settings") {
  showPage("settings");
} else if (location.hash === "#config") {
  // Deferred: config-common.js (and the section modules it hosts) load via
  // later <script> tags that haven't run yet at this point in app.js's own
  // synchronous execution, so window.NSEConfig.onShow() — which showPage
  // calls for the config page — would silently no-op and leave the page
  // blank. Deferring to a fresh task runs this after every script tag has
  // executed.
  setTimeout(() => showPage("config"), 0);
} else {
  activate("overview", true);
  fetch("/api/settings")
    .then((r) => r.json())
    .then((d) => {
      applyLiveConntrack(d.live_conntrack);
      if (!d.password_set) showPage("settings");
    })
    .catch(() => {});
}
startAutoRefresh();
