// Diagnostics.
//
// The backend has carried a whitelist of about forty read-only commands
// since early on — ping, nslookup, speedtest, per-daemon logs, every
// `show` the device answers — reachable at /api/debug and wired to
// nothing. The only trace of it in the UI was the .debug-out class, which
// the running-config view borrowed. This is the front for it.
//
// Two rules shape the screen. Commands that cost something say so before
// they run, because "speedtest" spends a customer's bandwidth and
// "show conntrack" can load the device's CPU. And an argument is a real
// input with a real validation message, not a free-text box that fails on
// the device a round trip later.
(function () {
  const esc = (s) =>
    String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );

  // Kept outside the panel because the Status page rebuilds a panel's
  // innerHTML on every poll, so anything held in the DOM is discarded.
  const state = { group: null, running: null, result: null, args: {} };

  const HOST_RE = /^[A-Za-z0-9._-]+$/;

  function argField(cmd) {
    const v = esc(state.args[cmd.id] || "");
    switch (cmd.arg) {
      case "host":
        return `<input type="text" class="diag-arg" data-arg="${esc(cmd.id)}" value="${v}"
          placeholder="hostname or IP" spellcheck="false" autocomplete="off">`;
      case "pool":
        return `<input type="number" min="1" class="diag-arg" data-arg="${esc(cmd.id)}" value="${v}"
          placeholder="pool number">`;
      case "daemon":
        return `<select class="diag-arg" data-arg="${esc(cmd.id)}">
          <option value="">choose a daemon…</option>
          ${(cmd.choices || [])
            .map(
              (d) =>
                `<option value="${esc(d)}"${state.args[cmd.id] === d ? " selected" : ""}>${esc(d)}</option>`
            )
            .join("")}
        </select>`;
      default:
        return "";
    }
  }

  function cmdRow(cmd) {
    const busy = state.running === cmd.id;
    return `<div class="diag-cmd${cmd.heavy ? " is-heavy" : ""}">
      <div class="diag-cmd-head">
        <code class="diag-name">${esc(cmd.command)}</code>
        ${cmd.heavy ? '<span class="diag-cost">costs time or bandwidth</span>' : ""}
      </div>
      ${cmd.note ? `<p class="diag-note">${esc(cmd.note)}</p>` : ""}
      <div class="diag-cmd-run">
        ${argField(cmd)}
        <button type="button" class="row-edit" data-run="${esc(cmd.id)}"${busy ? " disabled" : ""}>${
      busy ? "Running…" : "Run"
    }</button>
      </div>
    </div>`;
  }

  function render(el, data) {
    const cmds = (data && data.commands) || [];
    const groups = [];
    cmds.forEach((c) => {
      let g = groups.find((x) => x.name === c.group);
      if (!g) groups.push((g = { name: c.group, items: [] }));
      g.items.push(c);
    });
    if (!state.group && groups.length) state.group = groups[0].name;
    const active = groups.find((g) => g.name === state.group) || groups[0];

    const r = state.result;
    const output = r
      ? `<div class="diag-result">
          <p class="diag-result-head">
            <code>${esc(r.command)}</code>
            <span class="muted">${r.ms} ms</span>
          </p>
          ${r.detail ? `<p class="apply-error">${esc(r.detail)}</p>` : ""}
          <pre class="debug-out">${esc(r.output || "(no output)")}</pre>
        </div>`
      : `<p class="muted">Run a command to see its output here. Nothing is sent to the device until you press Run.</p>`;

    el.innerHTML = `
      <h2>Diagnostics</h2>
      <p class="muted">Read-only commands, run one at a time against the connected device. Output from <code>show config</code> has its secrets stripped before it reaches this page.</p>
      <div class="chips">${groups
        .map(
          (g) =>
            `<button type="button" class="chip ${g.name === active.name ? "active" : ""}"
              data-diag-group="${esc(g.name)}">${esc(g.name)}<span class="chip-count">${g.items.length}</span></button>`
        )
        .join("")}</div>
      <div class="diag-grid">${active ? active.items.map(cmdRow).join("") : ""}</div>
      ${output}`;
  }

  async function run(id, cmds) {
    const cmd = cmds.find((c) => c.id === id);
    if (!cmd) return;

    const arg = (state.args[id] || "").trim();
    if (cmd.arg && !arg) {
      state.result = { command: cmd.command, ms: 0, output: "", detail: "This command needs an argument." };
      return true;
    }
    if (cmd.arg === "host" && !HOST_RE.test(arg)) {
      state.result = {
        command: cmd.command,
        ms: 0,
        output: "",
        detail: "A host is letters, digits, dots, dashes or underscores. Nothing else is sent to the device.",
      };
      return true;
    }
    // The device is told what it costs, and so is the person pressing it.
    if (cmd.heavy && !window.confirm(`${cmd.command}\n\n${cmd.note || "This command is slow or expensive."}\n\nRun it now?`)) {
      return false;
    }

    state.running = id;
    state.result = null;
    try {
      const res = await fetch("/api/debug", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, arg }),
      });
      const body = await res.json().catch(() => ({}));
      state.result = res.ok
        ? body
        : { command: cmd.command, ms: 0, output: "", detail: body.detail || res.statusText };
    } catch (e) {
      state.result = { command: cmd.command, ms: 0, output: "", detail: String(e.message || e) };
    } finally {
      state.running = null;
    }
    return true;
  }

  // One delegated listener for the whole screen, because the panel is
  // replaced wholesale on every poll and per-element handlers would be
  // rebound (and leaked) each time.
  document.addEventListener("click", async (e) => {
    const group = e.target.closest && e.target.closest("[data-diag-group]");
    if (group) {
      state.group = group.dataset.diagGroup;
      window.NSEDiagnostics.refresh();
      return;
    }
    const runBtn = e.target.closest && e.target.closest("[data-run]");
    if (!runBtn) return;
    const cmds = (window.NSEDiagnostics.data() || {}).commands || [];
    state.running = runBtn.dataset.run;
    window.NSEDiagnostics.refresh();
    if (await run(runBtn.dataset.run, cmds)) window.NSEDiagnostics.refresh();
    else {
      state.running = null;
      window.NSEDiagnostics.refresh();
    }
  });

  document.addEventListener("input", (e) => {
    const field = e.target.closest && e.target.closest("[data-arg]");
    if (field) state.args[field.dataset.arg] = field.value;
  });
  document.addEventListener("change", (e) => {
    const field = e.target.closest && e.target.closest("select[data-arg]");
    if (field) {
      state.args[field.dataset.arg] = field.value;
      window.NSEDiagnostics.refresh();
    }
  });

  let lastEl = null;
  let lastData = null;
  window.NSEDiagnostics = {
    render(el, data) {
      lastEl = el;
      lastData = data;
      render(el, data);
    },
    refresh() {
      if (lastEl) render(lastEl, lastData);
    },
    data() {
      return lastData;
    },
  };
})();
