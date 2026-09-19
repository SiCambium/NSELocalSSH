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
  "debug",
];
const tabs = [...document.querySelectorAll(".tabs button")];
const panels = Object.fromEntries(TAB_IDS.map((id) => [id, document.getElementById(`panel-${id}`)]));

let current = "overview";
let dhcpSub = "pools";
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

// `widths` is optional: a list of CSS widths, one per column. Without it
// a table sizes its own columns from its own content, which is right for
// a table standing alone and wrong for a page like Throughput that draws
// three tables of the same five columns one under another — each sized
// itself independently, so the same column landed in a different place
// in every table and the three read as unrelated grids. Passing widths
// fixes the layout so they line up.
function table(headers, rows, widths) {
  if (!rows.length) return `<p class="muted">No rows.</p>`;
  const cols = widths
    ? `<colgroup>${widths.map((w) => `<col style="width:${w}">`).join("")}</colgroup>`
    : "";
  return `<div class="table-wrap"><table${widths ? ' class="fixed"' : ""}>${cols}<thead><tr>${headers
    .map((h) => `<th>${esc(h)}</th>`)
    .join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function stat(label, value) {
  return `<div class="stat"><label>${esc(label)}</label><strong>${esc(value || "—")}</strong></div>`;
}

// --- Table tools ---------------------------------------------------------
// One delegated layer gives every table in the app the same three
// controls, with no per-table wiring anywhere: click a heading to sort by
// that column and click again to reverse it, type in the filter row to
// narrow the table a column at a time, and open a long table past its
// first five rows. Renderers keep emitting plain <table> markup and get
// all of it, including tables added later and the ones the Configuration
// sections draw.
//
// None of this can be kept in the DOM, because a Status panel is rebuilt
// from scratch by every poll. State lives here, keyed by a fingerprint of
// the table's headings plus its position among same-heading tables in its
// own panel — Throughput draws several tables with identical headings
// side by side, so heading text alone is not unique — and is re-applied
// after each render.
//
// The MutationObserver that notices those renders is disconnected while
// this code touches the DOM itself, or it would retrigger itself forever.
(function () {
  // Ten rows is what a long table opens with, and one click from there
  // opens all of them. Ten is the count the owner asked for.
  const ROW_LIMIT = 10;
  // What counts as long. Below this a table is shown whole and carries no
  // controls, because a filter row and a "show all" on an eight-row table
  // is chrome with nothing to do, and collapsing thirteen rows to ten
  // buys nothing. Fifteen also clears the largest fixed-size table in the
  // app: a chassis has six ports on an NSE3000 and ten on an NSE4000, so
  // Ethernet always shows every port at once.
  const LONG_TABLE = 15;
  // A single-column table has nothing to filter against that its own
  // heading does not already say.
  const FILTER_MIN_COLS = 2;

  const state = new Map(); // fingerprint -> {sort, filters, expanded}
  const UNIT_MULT = {
    "": 1, bps: 1, kbps: 1e3, mbps: 1e6, gbps: 1e9,
    b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3, tb: 1024 ** 4, "%": 1,
  };

  function stateOf(fp) {
    let s = state.get(fp);
    if (!s) {
      s = { sort: null, filters: {}, expanded: false };
      state.set(fp, s);
    }
    return s;
  }

  // The headings are the first row of the thead. The filter row lives in
  // the thead too, so every lookup here says which row it means: reading
  // "every th in thead" would fold the filter inputs into the fingerprint
  // and make them a sort target.
  function headerCells(table) {
    const row = table.querySelector("thead tr");
    return row ? Array.from(row.children) : [];
  }

  function headerText(table) {
    return headerCells(table)
      .map((th) => th.textContent.replace(/[▲▼]/g, "").trim())
      .join("|");
  }

  function fingerprint(table) {
    const base = headerText(table);
    const container = table.closest('[id^="panel-"], .config-section') || document.body;
    const siblings = Array.from(container.querySelectorAll("table")).filter((t) => headerText(t) === base);
    return `${base}#${siblings.indexOf(table)}`;
  }

  function dataRows(table) {
    const tbody = table.querySelector("tbody");
    if (!tbody) return [];
    return Array.from(tbody.children).filter(
      (r) => r.tagName === "TR" && !r.classList.contains("more-row-tr")
    );
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

  function markHeader(table, sort) {
    headerCells(table).forEach((th, i) => {
      th.classList.add("sortable");
      th.classList.remove("sort-asc", "sort-desc");
      th.tabIndex = 0;
      th.setAttribute("role", "columnheader");
      const active = sort && i === sort.col;
      if (active) th.classList.add(sort.dir === "asc" ? "sort-asc" : "sort-desc");
      th.setAttribute("aria-sort", active ? (sort.dir === "asc" ? "ascending" : "descending") : "none");
      const name = th.textContent.replace(/[▲▼]/g, "").trim();
      th.title = `Sort by ${name}`;
    });
  }

  // The control that reveals the filter row. It goes at the right end of
  // the heading that names the table — the plate's own h2 — because that
  // is where the reader is already looking to decide which table this is,
  // and because a row of eight empty fields on every long table is a lot
  // of chrome to carry for something used occasionally.
  //
  // One heading names one table everywhere in this app, so the button can
  // hold its table directly and does not need a lookup. A table with no
  // heading above it keeps its filter row shown, which is the only way it
  // could be reached.
  function filterToggle(table, s) {
    const plate = table.closest(".plate");
    const heading = plate && plate.querySelector(":scope > h2");
    if (!heading) return null;
    let btn = Array.from(heading.querySelectorAll(".filter-toggle")).find((b) => b._table === table);
    if (!btn) {
      btn = document.createElement("button");
      btn.type = "button";
      btn.className = "filter-toggle";
      btn.innerHTML = icon("filter");
      btn._table = table;
      heading.appendChild(btn);
    }
    btn.setAttribute("aria-pressed", String(!!s.filterOpen));
    btn.classList.toggle("active", !!s.filterOpen);
    btn.title = s.filterOpen ? "Hide the filter row" : "Filter this table";
    btn.setAttribute("aria-label", btn.title);
    return btn;
  }

  // Adds or removes the filter row. Values are restored from the saved
  // state, never read back from the markup, because the markup was thrown
  // away and rebuilt by the last poll.
  function enhance(table, s) {
    const cells = headerCells(table);
    const rows = dataRows(table);
    const thead = table.querySelector("thead");
    if (!thead) return;
    let row = thead.querySelector(".col-filter");
    const long = rows.length > LONG_TABLE;
    const btn = long && cells.length >= FILTER_MIN_COLS ? filterToggle(table, s) : null;
    // With a button to open it, the row starts hidden. Without one there
    // is nothing to open it with, so it stays shown.
    const wanted =
      cells.length >= FILTER_MIN_COLS &&
      long &&
      (!btn || s.filterOpen || Object.values(s.filters).some((v) => v.trim()));
    if (!wanted) {
      if (row) row.remove();
      return;
    }
    if (!row) {
      row = document.createElement("tr");
      row.className = "col-filter";
      row.innerHTML = cells
        .map(
          (th, i) =>
            `<th><input type="search" class="col-filter-input" data-col="${i}" placeholder="Filter"
              aria-label="Filter by ${esc(th.textContent.trim())}"></th>`
        )
        .join("");
      thead.appendChild(row);
    }
    row.querySelectorAll("input").forEach((input) => {
      const saved = s.filters[input.dataset.col] || "";
      if (input.value !== saved) input.value = saved;
    });
  }

  // Sort, then filter, then cut to the first five. Visibility is set with
  // style.display rather than the hidden attribute, which a table row's
  // own display rule overrides.
  function apply(table, s) {
    const rows = dataRows(table);
    const tbody = table.querySelector("tbody");
    if (!tbody) return;
    if (s.sort && rows.length > 1) {
      rows.sort((a, b) => compareRows(a, b, s.sort.col, s.sort.dir));
      rows.forEach((r) => tbody.appendChild(r));
    }
    markHeader(table, s.sort);

    const terms = Object.entries(s.filters)
      .map(([col, v]) => [col, v.trim().toLowerCase()])
      .filter(([, v]) => v);
    const collapsible = rows.length > LONG_TABLE;
    let matched = 0;
    rows.forEach((r) => {
      const keep = terms.every(([col, v]) =>
        ((r.children[col] && r.children[col].textContent) || "").toLowerCase().includes(v)
      );
      const visible = keep && (!collapsible || s.expanded || matched < ROW_LIMIT);
      if (keep) matched += 1;
      r.style.display = visible ? "" : "none";
    });

    const cols = headerCells(table).length || 1;
    let more = tbody.querySelector(".more-row-tr:not(.no-match-tr)");
    if (collapsible && matched > ROW_LIMIT) {
      if (!more) {
        more = document.createElement("tr");
        more.className = "more-row-tr";
      }
      const shown = s.expanded ? matched : ROW_LIMIT;
      more.innerHTML = `<td class="more-cell" colspan="${cols}">
        <button type="button" class="box-go">${
          s.expanded ? `Show first ${ROW_LIMIT}` : `Show all ${matched}`
        }${icon("arrow")}</button>
        <span class="muted">${shown} of ${matched}${terms.length ? ` matching, ${rows.length} total` : ""}</span>
      </td>`;
      tbody.appendChild(more);
    } else if (more) {
      more.remove();
    }

    // A filter that matches nothing has to say so, or the table reads as
    // broken rather than as filtered.
    let none = tbody.querySelector(".no-match-tr");
    if (terms.length && matched === 0 && rows.length) {
      if (!none) {
        none = document.createElement("tr");
        none.className = "more-row-tr no-match-tr";
        none.innerHTML = `<td class="more-cell" colspan="${cols}">
          <span class="muted">No row matches this filter.</span></td>`;
        tbody.appendChild(none);
      }
    } else if (none) {
      none.remove();
    }
  }

  // --- Section plates ----------------------------------------------------
  // A detail page is a run of h2 headings with their content trailing
  // after them, all on one white field. Read at a glance, "User Groups"
  // and "IP Groups" run together: nothing says where one ends and the
  // next begins except a heading that is only slightly larger than the
  // text under it.
  //
  // So each heading and everything up to the next heading is wrapped in
  // its own plate — a separate white card on the page's ground — which is
  // the same move the cabinet makes: two things that are not the same
  // thing get two labels, not one label with a gap in it.
  //
  // It happens here rather than in twenty renderers because every page in
  // the app is built the same way, including the Configuration sections
  // in their own files, and this way they all get it and keep it. Moving
  // a node with appendChild preserves its listeners, so the buttons the
  // section modules wired up still work.
  //
  // Idempotent by construction: once wrapped, a panel has no h2 among its
  // own children, so a second pass does nothing and the observer that
  // watches for renders does not retrigger itself.
  function plateSections(root) {
    const kids = Array.from(root.children);
    if (!kids.some((el) => el.tagName === "H2")) return;
    let plate = null;
    kids.forEach((el) => {
      if (el.tagName === "H2") {
        plate = document.createElement("section");
        plate.className = "plate";
        root.insertBefore(plate, el);
      } else if (el.dataset && el.dataset.plateBreak !== undefined) {
        // Something that belongs to the page rather than to the section
        // above it — a page-level action that trails the last card, which
        // would otherwise be swallowed by that card's plate.
        plate = null;
      }
      if (plate) plate.appendChild(el);
    });
  }

  // A table inside a dashboard box (class "flat") is a four-line reading,
  // not a data table, and gets none of this.
  function eligible(table) {
    return !table.classList.contains("flat") && headerCells(table).length > 0;
  }

  function refresh(table) {
    observer.disconnect();
    if (table) {
      const s = stateOf(fingerprint(table));
      enhance(table, s);
      apply(table, s);
      observer.observe(document.body, { childList: true, subtree: true });
      return;
    }
    document
      .querySelectorAll('[id^="panel-"], .config-section')
      .forEach((root) => plateSections(root));
    Array.from(document.querySelectorAll("table")).forEach((t) => {
      if (!eligible(t)) return;
      const s = stateOf(fingerprint(t));
      enhance(t, s);
      apply(t, s);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  document.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const th = e.target.closest && e.target.closest("thead th.sortable");
    if (!th || th.closest(".col-filter")) return;
    e.preventDefault();
    th.click();
  });

  document.addEventListener("click", (e) => {
    const toggle = e.target.closest(".filter-toggle");
    if (toggle && toggle._table) {
      const s = stateOf(fingerprint(toggle._table));
      s.filterOpen = !s.filterOpen;
      // Closing clears what was typed. A hidden filter still narrowing
      // the rows is a table that lies about what the device holds.
      if (!s.filterOpen) s.filters = {};
      refresh(toggle._table);
      const input = toggle._table.querySelector(".col-filter-input");
      if (s.filterOpen && input) input.focus();
      return;
    }
    const openBtn = e.target.closest(".more-cell button");
    if (openBtn) {
      const table = openBtn.closest("table");
      stateOf(fingerprint(table)).expanded = !stateOf(fingerprint(table)).expanded;
      refresh(table);
      return;
    }
    const th = e.target.closest("thead th");
    if (!th || th.closest(".col-filter")) return;
    const table = th.closest("table");
    if (!table || !eligible(table)) return;
    const col = Array.from(th.parentElement.children).indexOf(th);
    const s = stateOf(fingerprint(table));
    s.sort = { col, dir: s.sort && s.sort.col === col && s.sort.dir === "asc" ? "desc" : "asc" };
    refresh(table);
  });

  // Filtering touches only its own table and never the thead, so the
  // input keeps focus and the caret keeps its place while typing.
  document.addEventListener("input", (e) => {
    const input = e.target.closest(".col-filter-input");
    if (!input) return;
    const table = input.closest("table");
    if (!table) return;
    const s = stateOf(fingerprint(table));
    s.filters[input.dataset.col] = input.value;
    observer.disconnect();
    apply(table, s);
    observer.observe(document.body, { childList: true, subtree: true });
  });

  // Renders arrive in bursts — a panel's innerHTML, then the IP-lookup
  // rerender behind it — so the work is coalesced into one pass a frame.
  let queued = false;
  const observer = new MutationObserver(() => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      refresh();
    });
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // The poll rebuilds the panel, which would pull the filter input out
  // from under the cursor mid-word. While a filter has focus, the table
  // being worked in holds still.
  window.NSETableBusy = () =>
    !!(document.activeElement && document.activeElement.closest && document.activeElement.closest(".col-filter"));
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
  // Diagnostics lives in its own file; it owns its panel entirely.
  if (tab === "debug" && window.NSEDiagnostics) window.NSEDiagnostics.render(el, data);
}

// The label-block form of statsFromMap: a flat CLI map turned into the
// [label, value] pairs readout() draws. Keys arrive snake_cased from the
// parsers, and a key is a label, not an identifier.
function pairsOf(obj) {
  return Object.entries(obj || {}).map(([k, v]) => [k.replaceAll("_", " "), v]);
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
    ),
    // Interfaces, VLANs and VPN are the same five columns three times
    // over on one page, so they are given one set of widths.
    ["28%", "15%", "15%", "15%", "27%"]
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


// --- Icons ---------------------------------------------------------------
// Authored here rather than pulled from a font or a CDN: this binary has
// to run at a site with no internet. One stroke weight, one cap style,
// one 24-unit grid, so they read as a set rather than as clip art.
const ICON = {
  up: '<path d="M20 6 9 17l-5-5"/>',
  down: '<path d="M18 6 6 18M6 6l12 12"/>',
  cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/>',
  memory: '<rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 11v2M10 11v2M14 11v2M18 11v2"/>',
  shield: '<path d="M12 3l7 3v5c0 4.4-3 8.2-7 9-4-.8-7-4.6-7-9V6z"/>',
  link: '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
  cloud: '<path d="M17.5 19a4.5 4.5 0 0 0 .5-9 6 6 0 0 0-11.6-1.6A4 4 0 0 0 7 19z"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  bell: '<path d="M18 8a6 6 0 1 0-12 0c0 7-3 8-3 8h18s-3-1-3-8"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  users: '<path d="M16 20v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 20v-2a4 4 0 0 0-3-3.87"/>',
  filter: '<path d="M4 6.5h16M7.5 12h9M10.5 17.5h3"/>',
};

function icon(name, cls) {
  const body = ICON[name];
  if (!body) return "";
  return `<svg class="icon ${cls || ""}" viewBox="0 0 24 24" aria-hidden="true" fill="none"
    stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
}

// --- Meter ---------------------------------------------------------------
// A single ratio against a limit, which is a meter on a same-ramp track,
// drawn as the dial the request asked for. The ticks are the point: every
// division is ten percentage points, so the needle position can be read
// as a number and not merely as "quite full".
const METER_ARC = Math.PI * 48;

function meter(opts) {
  const pct = Math.max(0, Math.min(100, Number(opts.pct) || 0));
  let ticks = "";
  for (let i = 0; i <= 10; i++) {
    const rad = ((-90 + i * 18) * Math.PI) / 180;
    const major = i % 5 === 0;
    const r0 = major ? 50 : 52;
    const sx = (60 + r0 * Math.sin(rad)).toFixed(1);
    const sy = (64 - r0 * Math.cos(rad)).toFixed(1);
    const ex = (60 + 57 * Math.sin(rad)).toFixed(1);
    const ey = (64 - 57 * Math.cos(rad)).toFixed(1);
    ticks += `<line x1="${sx}" y1="${sy}" x2="${ex}" y2="${ey}" class="meter-tick${major ? " major" : ""}"/>`;
  }
  const dash = ((METER_ARC * pct) / 100).toFixed(2);
  return `<div class="meter">
    <svg class="meter-dial" viewBox="0 0 120 86" role="img" aria-label="${esc(opts.label)}: ${pct}% of 100%">
      ${ticks}
      <path class="meter-track" d="M12 64A48 48 0 0 1 108 64"/>
      <path class="meter-value" d="M12 64A48 48 0 0 1 108 64"
        stroke-dasharray="${dash} ${METER_ARC.toFixed(2)}"/>
      <text class="meter-figure" x="60" y="58" text-anchor="middle">${pct}<tspan class="meter-unit">%</tspan></text>
      <text class="meter-min" x="9" y="80">0</text>
      <text class="meter-max" x="111" y="80" text-anchor="end">100</text>
    </svg>
    <p class="meter-label">${icon(opts.icon)}${esc(opts.label)}</p>
    <p class="meter-sub">${opts.sub || ""}</p>
  </div>`;
}

// The port legend: the device's own ports drawn as the connectors they
// are, in the order they sit on the chassis, green when in service and
// red when there is no link. This is how the cloud console draws the same
// widget, so an operator arriving from it reads the panel without being
// taught, and it is the cabinet legend this interface is built around.
//
// State is carried three ways: the outline colour, the word in the
// tooltip, and the up/down count underneath. Never colour alone.
//
// The six-port stagger is the physical NSE3000 faceplate (two ports, then
// a two-by-two block). Any other count falls back to a plain row, because
// the layout of a chassis this code has never seen is not something to
// guess at. Port COUNT always comes from the device.
const PORT_JACK =
  '<path d="M5 4h24a3 3 0 0 1 3 3v11a3 3 0 0 1-3 3h-6v3H13v-3H5a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3z"/>';

// A dense label/value list. Each pair is [label, value, kind], where kind
// is "mono" for an identifier, "list" for a field that genuinely holds
// several values, and omitted for ordinary prose.
//
// Kind is declared, never inferred. An earlier version split any value
// containing whitespace, which is right for "8.8.8.8 8.8.4.4" and wrong
// for everything else: it broke "NSE-MARIO-PEDERNEIRAS NSE 3000" into
// three lines and a clock reading into six. A heuristic that cannot tell
// a list from a sentence does not belong in a readout.
function readout(pairs) {
  const rows = pairs
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([label, value, kind]) => {
      let body;
      if (kind === "list") {
        const parts = String(value).trim().split(/[\s,]+/).filter(Boolean);
        body = `<span class="multi">${parts.map((x) => `<span>${esc(x)}</span>`).join("")}</span>`;
      } else if (kind === "mono") {
        body = `<span class="mono">${esc(value)}</span>`;
      } else {
        body = esc(value);
      }
      return `<dt class="legend">${esc(label)}</dt><dd>${body}</dd>`;
    })
    .join("");
  return `<dl class="readout-list">${rows}</dl>`;
}

// --- View controls -------------------------------------------------------
// Filters and row limits live outside the rendered markup, because a panel
// is rebuilt from scratch on every poll and anything kept in the DOM would
// be thrown away every few seconds. The renderer reads this, the delegated
// handler writes it and asks for a redraw.
const viewState = {
  eventSeverity: "all",
};

// Cisco-style severity bands, the same ones the Overview counts with.
const SEVERITY_BANDS = {
  critical: (n) => n >= 0 && n <= 2,
  major: (n) => n === 3,
  minor: (n) => n === 4,
  info: (n) => n >= 5,
};

function chips(key, current, options) {
  return `<div class="chips" role="group">${options
    .map(
      ([value, label, count]) =>
        `<button type="button" class="chip ${value === current ? "active" : ""} chip-${esc(value)}"
          data-chip="${esc(key)}" data-chip-value="${esc(value)}">${esc(label)}${
          count != null ? `<span class="chip-count">${count}</span>` : ""
        }</button>`
    )
    .join("")}</div>`;
}

document.addEventListener("click", (e) => {
  const chip = e.target.closest && e.target.closest("[data-chip]");
  if (chip) {
    viewState[chip.dataset.chip] = chip.dataset.chipValue;
    activate(current, true);
    return;
  }
});

function portLegend(ports) {
  if (!ports || !ports.length) return "";
  const up = ports.filter((p) => p.up).length;
  const jacks = ports
    .map((p, i) => {
      const state = p.up ? "up" : "down";
      const reading = p.up
        ? `${p.speed || "up"}${p.duplex ? ` ${p.duplex.toLowerCase()}` : ""}`
        : "no link";
      const num = (p.name || "").replace(/^\D+/, "") || String(i + 1);
      return `<span class="pport ${state}" style="--slot:${i + 1}"
          title="${esc(p.name)} · ${esc(p.role.toUpperCase())} · ${p.up ? "Up" : "Down"} · ${esc(reading)}">
        <svg class="pport-jack" viewBox="0 0 34 26" aria-hidden="true" fill="none"
          stroke="currentColor" stroke-width="2.2" stroke-linejoin="round">${PORT_JACK}</svg>
        <span class="pport-num">${esc(num)}</span>
        <span class="pport-role">${esc(p.role)}</span>
      </span>`;
    })
    .join("");
  return `<div class="faceplate" data-count="${ports.length}">${jacks}</div>
    <p class="faceplate-sum">
      <span class="tally up">${up} up</span>
      <span class="tally down">${ports.length - up} down</span>
      <span class="muted">${ports.length} ports</span>
    </p>`;
}

// A box that leads somewhere names where it goes and is reachable by
// keyboard, so it is a button rather than a div with a click handler.
function boxLink(tab, label) {
  return `<button type="button" class="box-go" data-goto="${esc(tab)}">${esc(label)}${icon("arrow")}</button>`;
}

function renderOverview(d) {
  const v = d.version || {};
  const remote = d.remote || {};
  const mem = d.memory || {};
  const cpu = d.cpu || {};
  const t = d.threat_protection || {};
  const al = d.alarms || {};
  const memPct = mem.used_pct != null ? mem.used_pct : 0;
  const cpuPct = cpu.used_pct != null ? cpu.used_pct : 0;
  setBrand(v);
  document.getElementById("title").textContent = v.hostname || v.identity || "Status";

  const wan = d.wan_throughput || [];
  const totalRx = wan.reduce((a, w) => a + (Number(w.rx_bps) || 0), 0);
  const totalTx = wan.reduce((a, w) => a + (Number(w.tx_bps) || 0), 0);
  const ports = d.ports || [];
  const portsUp = ports.filter((p) => p.up).length;

  const wanRows = wan.length
    ? wan
        .map(
          (w) => `<tr>
            <td class="wan-name">${esc(w.label || w.cli_name || "WAN")}</td>
            <td><span class="state-dot ${w.rx_bps != null ? "is-on" : "is-off"}"></span>${w.rx_bps != null ? "Online" : "No data"}</td>
            <td class="num">${esc(bps(w.rx_bps))}</td>
            <td class="num">${esc(bps(w.tx_bps))}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="4" class="box-empty">${d.rates_ready ? "No WAN traffic right now." : "Sampling throughput…"}</td></tr>`;

  const ips = t.enabled;
  const maestro = maestroOn(remote);

  return `
    <div class="dash">
      <section class="box hero">
        <h2>${icon("cloud")}Management status</h2>
        <p class="hero-badge ${maestro ? "is-on" : "is-off"}">
          <span class="state-dot ${maestro ? "is-on" : "is-off"}"></span>${esc(maestroStatus(remote))}
        </p>
        <p class="hero-figure">${esc(v.uptime || "—")}</p>
        <p class="legend">Device uptime</p>
      </section>

      <section class="box hero">
        <h2>${icon("link")}Total WAN throughput</h2>
        <div class="hero-pair">
          <div><p class="hero-figure">${esc(bps(totalRx))}</p><p class="legend">Total downlink</p></div>
          <div><p class="hero-figure">${esc(bps(totalTx))}</p><p class="legend">Total uplink</p></div>
        </div>
        ${boxLink("throughput", "Throughput detail")}
      </section>

      <section class="box hero">
        <h2>${icon("users")}Clients</h2>
        <div class="hero-pair">
          <div><p class="hero-figure">${d.lan_clients != null ? d.lan_clients : "—"}</p><p class="legend">LAN clients</p></div>
        </div>
        ${boxLink("devices", "Client list")}
      </section>

      <section class="box hero">
        <h2>${icon("link")}Ports in service</h2>
        <div class="hero-pair">
          <div><p class="hero-figure">${portsUp}</p><p class="legend">Up</p></div>
          <div><p class="hero-figure">${ports.length - portsUp}</p><p class="legend">Down</p></div>
        </div>
        ${boxLink("interfaces", "Interface detail")}
      </section>

      <section class="box box-alarms">
        <h2>${icon("bell")}Alarms</h2>
        <p class="legend">${al.total != null ? `${al.total} events the device still holds` : "no event data"}</p>
        <div class="alarm-row">
          <span class="alarm critical"><b>${al.critical != null ? al.critical : "—"}</b><span class="legend">Critical</span></span>
          <span class="alarm major"><b>${al.major != null ? al.major : "—"}</b><span class="legend">Major</span></span>
          <span class="alarm minor"><b>${al.minor != null ? al.minor : "—"}</b><span class="legend">Minor</span></span>
        </div>
        ${boxLink("events", "All events")}
      </section>

      <section class="box box-ports">
        <h2>${icon("link")}Port status</h2>
        ${portLegend(ports) || '<p class="box-empty">No port data.</p>'}
        ${boxLink("interfaces", "Interface detail")}
      </section>

      <section class="box box-meter">
        ${meter({ pct: cpuPct, label: "CPU", icon: "cpu",
          sub: `load ${esc(cpu.load1 || "—")} · ${esc(cpu.load5 || "—")} · ${esc(cpu.load15 || "—")}` })}
      </section>

      <section class="box box-meter">
        ${meter({ pct: memPct, label: "Memory", icon: "memory",
          sub: `${esc(kb(mem.used_kb))} of ${esc(kb(mem.total_kb))}` })}
      </section>

      <section class="box box-wan">
        <h2>${icon("link")}WAN interface metrics</h2>
        <table class="flat">
          <thead><tr><th>Interface</th><th>Status</th><th class="num">Downlink</th><th class="num">Uplink</th></tr></thead>
          <tbody>${wanRows}</tbody>
        </table>
      </section>

      <section class="box box-device">
        <h2>${icon("clock")}Device</h2>
        <dl class="readout">
          <dt class="legend">Model</dt><dd>${esc(v.model || "—")}</dd>
          <dt class="legend">Firmware</dt><dd>${esc(v.software_version || "—")}</dd>
          <dt class="legend">Serial</dt><dd class="mono">${esc(v.serial || "—")}</dd>
        </dl>
        ${boxLink("details", "Device detail")}
      </section>

      <section class="box box-state">
        <h2>${icon("shield")}Threat protection</h2>
        <p class="state-line ${ips ? "is-on" : "is-off"}">
          ${icon(ips ? "up" : "down", "state-icon")}
          <strong>${ips ? "On" : "Off"}</strong>
          <span class="muted">${ips ? esc(t.mode || "") : "not running"}</span>
        </p>
        ${boxLink("config:threat", "Threat settings")}
      </section>
    </div>
  `;
}

// cnMaestro's own wording varies by firmware, so "connected" is matched
// rather than assumed, and anything else counts as not connected.
function maestroOn(remote) {
  return /connect/i.test(String((remote && remote.state) || "")) &&
    !/dis/i.test(String((remote && remote.state) || ""));
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
  const root = (d.disks || []).find((x) => x.mounted === "/") || {};
  return `
    <h2>Device</h2>
    <div class="readout-cols">
      <div>${readout([
        ["Identity", v.identity],
        ["Hostname", v.hostname],
        ["Serial", v.serial, "mono"],
        ["MAC", v.mac, "mono"],
      ])}</div>
      <div>${readout([
        ["Build date", v.build_date],
        ["Device-Agent", v.device_agent],
        ["Regulatory", v.regulatory_domain],
        ["Clock", d.clock && d.clock.clock],
        ["USB", d.usb && d.usb.usb],
      ])}</div>
    </div>
    <h2>Management</h2>
    <div class="readout-cols">
      <div>
        <h3>Cloud</h3>
        ${readout([["cnMaestro", maestroStatus(rem.summary || {})]].concat(pairsOf(m.remote)))}
      </div>
      <div>
        <h3>Web interface</h3>
        ${readout(pairsOf(m.gui))}
      </div>
      <div>
        <h3>Command line</h3>
        ${readout(pairsOf(m.cli))}
      </div>
    </div>
    <h2>Power</h2>
    <div class="readout-cols"><div>${readout(pairsOf(d.power))}</div></div>
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

function stateMark(up) {
  return `<span class="state-mark" aria-hidden="true">${up ? "●" : "✕"}</span>`;
}

function roleChip(role) {
  if (!role) return '<span class="muted">—</span>';
  const r = String(role).toLowerCase();
  return `<span class="role-chip ${r === "wan" ? "ink" : ""}">${esc(r.toUpperCase())}</span>`;
}

function renderInterfaces(d) {
  // Role comes from the same derivation the Overview legend uses, so a
  // port cannot read WAN on one screen and be unlabelled on this one.
  const roleOf = {};
  (d.ports || []).forEach((p) => {
    roleOf[p.name] = p.role;
  });
  const ifaces = table(
    ["Interface", "Role", "MAC", "Status", "Speed", "Duplex", "Advertising"],
    (d.interfaces || []).map(
      (p) => `<tr>
        <td class="mono">${esc(p.interface)}</td>
        <td>${roleChip(roleOf[p.interface])}</td>
        <td class="mono">${esc(p.mac)}</td>
        <td class="${p.status === "UP" ? "up" : "down"}">${stateMark(p.status === "UP")}${esc(p.status)}</td>
        <td>${esc(p.speed)}</td>
        <td>${esc(p.duplex)}</td>
        <td>${esc(p.advertising)}</td>
      </tr>`
    )
  );
  const wan = (d.wan_dhcp || [])
    .map((w) => {
      const o = w.options || {};
      return `<div>
        <h3>${esc(w.interface)}</h3>
        ${readout([
          ["Address", o.ip, "mono"],
          ["Subnet mask", o.subnet, "mono"],
          ["Gateway", o.router, "mono"],
          ["DNS servers", o.dns, "list"],
          ["Domain", o.domain],
          ["Lease", o.lease ? `${o.lease} s` : ""],
          ["DHCP server", o.serverid, "mono"],
        ])}
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
  return `<h2>Ethernet</h2>${ifaces}
    <h2>WAN DHCP client</h2>
    <div class="readout-cols">${wan || '<p class="muted">No WAN DHCP lease.</p>'}</div>
    <h2>PPPoE</h2>${pppoe}`;
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
          ${stat("Addresses in pool", p.allocated)}
          ${stat("Leases in use", p.usage)}
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
        <div class="grid">${stat("Addresses in pool", p.allocated)}${stat("Leases in use", p.usage)}</div>
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
  const byBytes = (a, b) => b.tx_bytes + b.rx_bytes - (a.tx_bytes + a.rx_bytes);
  const apps = (d.by_application || []).slice().sort(byBytes);
  const cats = (d.by_category || []).slice().sort(byBytes);
  const trafficRow = (a) =>
    `<tr><td>${esc(a.name)}</td><td class="mono">${bytes(a.tx_bytes)}</td><td class="mono">${bytes(
      a.rx_bytes
    )}</td><td class="mono">${bytes(a.tx_bytes + a.rx_bytes)}</td></tr>`;
  return `<h2>Applications</h2>
    <p class="muted">Ranked by total bytes.</p>
    ${table(["Application", "TX", "RX", "Total"], apps.map(trafficRow))}
    <h2>Categories</h2>
    ${table(["Category", "TX", "RX", "Total"], cats.map(trafficRow))}`;
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
  const all = d.events || [];
  const band = viewState.eventSeverity;
  const count = (name) => all.filter((e) => SEVERITY_BANDS[name](e.severity)).length;
  const rows = band === "all" ? all : all.filter((e) => SEVERITY_BANDS[band](e.severity));
  return `
    ${chips("eventSeverity", band, [
      ["all", "All", all.length],
      ["critical", "Critical", count("critical")],
      ["major", "Major", count("major")],
      ["minor", "Minor", count("minor")],
      ["info", "Info", count("info")],
    ])}
    ${table(
      ["Time", "Severity", "Code", "Message"],
      rows.map(
        (e) =>
          `<tr><td class="mono">${esc(e.time)}</td><td>${severityTag(e.severity)}</td><td class="mono">${esc(
            e.code
          )}</td><td>${esc(e.message)}</td></tr>`
      )
    )}`;
}

// The band as a word, so severity is never carried by colour alone.
function severityTag(n) {
  if (n == null || n < 0) return '<span class="sev sev-none">—</span>';
  if (n <= 2) return '<span class="sev sev-critical">Critical</span>';
  if (n === 3) return '<span class="sev sev-major">Major</span>';
  if (n === 4) return '<span class="sev sev-minor">Minor</span>';
  return '<span class="sev sev-info">Info</span>';
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

// --- Rail ----------------------------------------------------------------
const RAIL_KEY = "nse.rail.collapsed";

function setRail(collapsed) {
  document.getElementById("app").classList.toggle("rail-collapsed", collapsed);
  const btn = document.getElementById("rail-toggle");
  btn.setAttribute("aria-expanded", String(!collapsed));
  btn.title = collapsed ? "Expand menu" : "Collapse menu";
  try {
    localStorage.setItem(RAIL_KEY, collapsed ? "1" : "0");
  } catch (e) {
    /* private window, blocked storage: the rail still works, it just forgets */
  }
}

(function initRail() {
  let collapsed = false;
  try {
    collapsed = localStorage.getItem(RAIL_KEY) === "1";
  } catch (e) {
    /* same */
  }
  setRail(collapsed);
  document.getElementById("rail-toggle").addEventListener("click", () => {
    setRail(!document.getElementById("app").classList.contains("rail-collapsed"));
  });
})();

// Boxes on the dashboard lead to the view that holds the detail. Bound
// once by delegation rather than per render, because the dashboard is
// rebuilt on every poll and per-element listeners would accumulate.
document.addEventListener("click", (e) => {
  const go = e.target.closest && e.target.closest("[data-goto]");
  if (!go) return;
  const target = go.dataset.goto;
  if (target.startsWith("config:")) {
    showPage("config");
    if (window.NSEConfig) window.NSEConfig.show(target.slice("config:".length));
    return;
  }
  showPage("status");
  activate(target, true);
});

function showPage(next, force = false) {
  page = next;
  document.body.dataset.page = next;
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
    if (window.NSETableBusy && window.NSETableBusy()) return;
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
