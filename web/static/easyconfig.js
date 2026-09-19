// Easy Config: the first-run wizard.
//
// One question at a time, in the order a unit out of its box needs them
// answered. The sequence is not a script this file invents — it comes
// from /api/provisioning, which reads the device and reports what is
// still outstanding — so a step that is already satisfied is shown as
// done rather than asked again, and a device that is half configured
// resumes rather than restarting.
//
// Every step is answered here. The wizard configures the device rather
// than handing the operator to another screen, because a first run that
// bounces between pages is not a first run, it is a tour.
//
// What it asks for each subject is only what a first run needs: which
// port carries the internet and whether it gets its address
// automatically, the address this device answers on and the range it
// hands out. Load balancing, bandwidth, PPPoE, trunking, MAC
// reservations and the rest are real settings with real screens, and
// each step carries a quiet link to the one that owns it.
(function () {
  const esc = (s) =>
    String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );

  // Steps the operator has ticked by hand. The admin password cannot be
  // checked — the device stores it obfuscated, so nothing can tell a
  // factory password from a chosen one — and the backup is an action
  // taken outside the device entirely. Both are per-session and not
  // persisted: claiming a password was changed because a checkbox
  // survived a restart is exactly the wrong thing to remember.
  const acknowledged = new Set();

  const state = { index: 0, steps: [], loading: false, error: "", outcome: "", editing: null };

  // How each step is answered. "inline" carries its own field; "section"
  // hands over to the screen that owns the subject; "manual" is a thing
  // the operator does and confirms.
  const HOW = {
    "admin-password": { kind: "inline", form: "password" },
    hostname: { kind: "inline", form: "text", label: "Device name", placeholder: "branch-office-nse" },
    timezone: { kind: "inline", form: "timezone", label: "Timezone" },
    ntp: { kind: "inline", form: "text", label: "NTP server", placeholder: "time.google.com" },
    dns: { kind: "inline", form: "text", label: "Name servers", placeholder: "1.1.1.1, 8.8.8.8" },
    logging: { kind: "inline", form: "syslog" },
    wan: { kind: "inline", form: "wan" },
    lan: { kind: "inline", form: "lan" },
    backup: { kind: "manual", form: "backup" },
  };

  async function load() {
    state.loading = true;
    state.error = "";
    render();
    try {
      const res = await fetch("/api/provisioning");
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || res.statusText);
      }
      const data = await res.json();
      state.steps = data.steps || [];
      // Resume where the device actually is: land on the first step that
      // is neither done nor already acknowledged.
      const first = state.steps.findIndex((s) => !isDone(s));
      state.index = first === -1 ? Math.max(0, state.steps.length - 1) : first;
      state.editing = null;
    } catch (e) {
      state.error = e.message;
    } finally {
      state.loading = false;
      render();
    }
  }

  const isDone = (step) => step.done || acknowledged.has(step.id);

  async function post(url, body) {
    state.outcome = "";
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || res.statusText);
    return data;
  }

  // --- Step bodies -------------------------------------------------------

  function inlineField(step, how) {
    // Pre-filled from step.value, never from step.detail. Detail is prose
    // for a human ("2 NTP servers configured"); putting that in a text
    // field would send the sentence to the device.
    const current = step.value || "";
    return `<label class="ec-field">
        <span class="legend">${esc(how.label)}</span>
        <input type="text" id="ec-input" spellcheck="false" autocomplete="off"
          value="${esc(current)}" placeholder="${esc(how.placeholder || "")}">
      </label>`;
  }

  function passwordField() {
    return `<div class="ec-field">
        <label><span class="legend">New password</span>
          <input type="password" id="ec-pw" autocomplete="new-password"></label>
        <label><span class="legend">Repeat it</span>
          <input type="password" id="ec-pw2" autocomplete="new-password"></label>
        <p class="muted">The device stores this obfuscated, so nothing here can tell a factory password from one you chose. Change it on a new unit, then confirm below.</p>
      </div>`;
  }

  // The IANA zone list comes from the browser: Intl carries the same tz
  // database the device names its zones from, so there is nothing to
  // vendor, bundle or keep current. The same source the Management
  // screen already uses.
  //
  // Grouped by region rather than served as one four-hundred-entry list,
  // because a flat select of that length is a scroll, not a choice. On a
  // runtime without supportedValuesOf it degrades to the text field it
  // replaces rather than offering an empty dropdown.
  function timezoneField(step) {
    let zones = [];
    try {
      zones = typeof Intl.supportedValuesOf === "function" ? Intl.supportedValuesOf("timeZone") : [];
    } catch (e) {
      zones = [];
    }
    // The device spells a zone with spaces where IANA uses underscores:
    // it reports "America/Sao Paulo" for what the tz database calls
    // America/Sao_Paulo. Matching has to ignore that difference, or the
    // current zone never lines up with a list entry and opening this
    // step would look like it had changed the setting.
    //
    // What is sent is the IANA spelling, which is what the Management
    // screen already sends. Whether the device also accepts the spaced
    // form is unconfirmed, and consistency with the existing screen is
    // worth more than a second convention.
    const key = (z) => String(z).replace(/[_\s]+/g, "_").toLowerCase();
    const reported = step.value || "";
    let current = reported;
    if (!zones.length) {
      return `<label class="ec-field">
          <span class="legend">Timezone</span>
          <input type="text" id="ec-input" spellcheck="false" value="${esc(current)}"
            placeholder="Europe/London">
          <span class="muted">This browser does not expose the zone list, so type the IANA name.</span>
        </label>`;
    }
    const match = zones.find((z) => key(z) === key(reported));
    if (match) {
      current = match;
    } else if (reported) {
      // A zone the browser does not know still has to be selectable, or
      // opening this step would silently change it.
      zones = [reported].concat(zones);
    }

    const groups = new Map();
    zones.forEach((z) => {
      const area = z.indexOf("/") === -1 ? "Other" : z.slice(0, z.indexOf("/"));
      if (!groups.has(area)) groups.set(area, []);
      groups.get(area).push(z);
    });
    const options = Array.from(groups.keys())
      .sort()
      .map(
        (area) =>
          `<optgroup label="${esc(area)}">${groups
            .get(area)
            .map(
              (z) =>
                `<option value="${esc(z)}"${z === current ? " selected" : ""}>${esc(
                  z.slice(z.indexOf("/") + 1).replace(/_/g, " ")
                )}</option>`
            )
            .join("")}</optgroup>`
      )
      .join("");
    return `<label class="ec-field">
        <span class="legend">Timezone</span>
        <select id="ec-input">${options}</select>
      </label>`;
  }

  function syslogField() {
    return `<div class="ec-field">
        <label><span class="legend">Syslog server</span>
          <input type="text" id="ec-syslog-ip" spellcheck="false" placeholder="10.0.0.20"></label>
        <label><span class="legend">Port</span>
          <input type="text" id="ec-syslog-port" inputmode="numeric" value="514"></label>
        <p class="muted">This device keeps a short, bounded event list and no long history of its own. A syslog target is how anything survives a reboot.</p>
      </div>`;
  }

  // A first run needs one question answered about the internet link:
  // which port, and does it get its address automatically. Load
  // balancing, bandwidth, PPPoE and connection health are real settings
  // with their own screen; putting them here would make a worse copy of
  // it. The link to that screen stays, for after the basics are in.
  function wanField() {
    return `<div class="ec-field">
        <label><span class="legend">Port</span>
          <select id="ec-wan-port">
            <option value="1">eth1</option>
            <option value="2">eth2</option>
          </select></label>
        <label><span class="legend">Address</span>
          <select id="ec-wan-mode">
            <option value="dhcp">Automatic (DHCP)</option>
            <option value="static">Static</option>
          </select></label>
        <div id="ec-wan-static" hidden>
          <label><span class="legend">IP address</span>
            <input type="text" id="ec-wan-ip" spellcheck="false" placeholder="203.0.113.10"></label>
          <label><span class="legend">Subnet mask</span>
            <input type="text" id="ec-wan-mask" spellcheck="false" placeholder="255.255.255.0"></label>
          <label><span class="legend">Gateway</span>
            <input type="text" id="ec-wan-gw" spellcheck="false" placeholder="203.0.113.1"></label>
        </div>
        <p class="muted">Load balancing, bandwidth and PPPoE live on the WAN screen. This asks only what a first run needs.
          <button type="button" class="ec-link" data-ec-section="wan">Open the WAN screen</button></p>
      </div>`;
  }

  // The LAN question is the address this device answers on and the range
  // it hands out. Everything else about a VLAN has its own screen.
  function lanField() {
    return `<div class="ec-field">
        <label><span class="legend">VLAN</span>
          <input type="text" id="ec-lan-vlan" inputmode="numeric" value="1"></label>
        <label><span class="legend">Address of this device</span>
          <input type="text" id="ec-lan-ip" spellcheck="false" placeholder="192.168.10.1"></label>
        <label><span class="legend">Subnet mask</span>
          <input type="text" id="ec-lan-mask" spellcheck="false" placeholder="255.255.255.0"></label>
        <label><span class="legend">Hand out addresses from</span>
          <input type="text" id="ec-lan-start" spellcheck="false" placeholder="192.168.10.50"></label>
        <label><span class="legend">Up to</span>
          <input type="text" id="ec-lan-end" spellcheck="false" placeholder="192.168.10.200"></label>
        <p class="muted">Clients are told to use this device as their gateway and resolver.
          <button type="button" class="ec-link" data-ec-section="network">Open the Network screen</button></p>
      </div>`;
  }

  function backupField() {
    return `<div class="ec-field">
        <p class="muted">The backup carries this device's secrets in cleartext, because one that redacts them cannot rebuild the site. Store it where you would store the device password.</p>
        <p><button type="button" class="row-edit" id="ec-backup">Download the backup</button></p>
      </div>`;
  }

  function stepBody(step) {
    const how = HOW[step.id];
    if (!how) return "";
    if (isDone(step) && state.editing !== step.id) {
      // Done is not read-only. A site being reconfigured, or a value
      // typed wrong the first time, needs the same field back.
      return `<p class="ec-done">${esc(step.detail || "Already set.")}</p>
        ${
          how.kind === "manual"
            ? ""
            : `<p><button type="button" class="ec-link" id="ec-edit">Change it</button></p>`
        }`;
    }
    switch (how.kind) {
      case "section":
        return `<p class="muted">${esc(how.hint)}</p>
          <p><button type="button" class="row-edit" data-ec-section="${esc(how.target)}">Open the ${esc(how.target)} screen</button></p>
          <p class="muted">Come back when it is set and press Next; this page re-reads the device rather than taking your word for it.</p>`;
      case "manual":
        return backupField();
      default:
        if (how.form === "password") return passwordField();
        if (how.form === "syslog") return syslogField();
        return inlineField(step, how);
    }
  }

  // --- Applying ----------------------------------------------------------

  async function applyStep(step) {
    const how = HOW[step.id];
    const val = (id) => {
      const el = document.getElementById(id);
      return el ? el.value.trim() : "";
    };
    switch (step.id) {
      case "admin-password": {
        const pw = val("ec-pw");
        if (!pw) throw new Error("Enter the new password, or tick it as already changed.");
        await post("/api/config/password", { password: pw, confirm: val("ec-pw2") });
        return "Password changed. This app is now using the new one.";
      }
      case "hostname":
        await post("/api/config/management", { action: "hostname", hostname: val("ec-input") });
        return "Name set.";
      case "timezone":
        await post("/api/config/management", { action: "timezone", tz_name: val("ec-input") });
        return "Timezone set.";
      case "ntp":
        await post("/api/config/management", { action: "ntp_server", ntp_server: val("ec-input") });
        return "Time server set.";
      case "dns": {
        const servers = val("ec-input").split(/[\s,]+/).filter(Boolean);
        if (!servers.length) throw new Error("Enter at least one name server.");
        await post("/api/config/dns", { action: "name_server", name_server: servers });
        return "Name servers set.";
      }
      case "wan": {
        const port = Number(val("ec-wan-port")) || 1;
        const mode = val("ec-wan-mode") || "dhcp";
        const body = { action: "ip_mode", port, mode };
        if (mode === "static") {
          body.ip = val("ec-wan-ip");
          body.mask = val("ec-wan-mask");
          body.gateway = val("ec-wan-gw");
          if (!body.ip || !body.mask || !body.gateway) {
            throw new Error("A static WAN needs an address, a mask and a gateway.");
          }
        }
        await post("/api/config/wan", body);
        return mode === "dhcp"
          ? "The link will take its address automatically."
          : "Static address set on the link.";
      }
      case "lan": {
        const vlan = Number(val("ec-lan-vlan")) || 1;
        const ip = val("ec-lan-ip");
        const mask = val("ec-lan-mask");
        if (!ip || !mask) throw new Error("The device needs an address and a mask on this VLAN.");
        // Two writes, in the order the device needs them: the interface
        // has to hold the address before a scope can hand out neighbours
        // of it.
        await post("/api/config/network", { action: "vlan_ip", vlan_id: vlan, ip, mask });
        const start = val("ec-lan-start");
        const end = val("ec-lan-end");
        if (start && end) {
          await post("/api/config/network", {
            action: "dhcp_scope",
            vlan_id: vlan,
            dhcp: { start_ip: start, end_ip: end, router: ip, dns: ip, lease_hours: 12 },
          });
          return "Address set and the scope is handing out leases.";
        }
        return "Address set. No range given, so nothing is handed out yet.";
      }
      case "logging":
        await post("/api/config/management", {
          action: "syslog",
          syslog_ip: val("ec-syslog-ip"),
          syslog_port: val("ec-syslog-port") || "514",
        });
        return "Syslog target set.";
      default:
        // section and manual steps are acknowledged, not applied.
        acknowledged.add(step.id);
        return "";
    }
  }

  // --- Render ------------------------------------------------------------

  function render() {
    const el = document.getElementById("page-easyconfig");
    if (!el || el.hidden) return;

    if (state.loading && !state.steps.length) {
      el.innerHTML = `<h2>Easy Config</h2><p class="muted">Reading the device…</p>`;
      return;
    }
    if (state.error && !state.steps.length) {
      el.innerHTML = `<h2>Easy Config</h2><p class="apply-error">${esc(state.error)}</p>
        <p><button type="button" class="row-edit" id="ec-retry">Try again</button></p>`;
      return;
    }

    const total = state.steps.length;
    const step = state.steps[state.index];
    if (!step) {
      el.innerHTML = `<h2>Easy Config</h2><p class="muted">Nothing to configure.</p>`;
      return;
    }
    const remaining = state.steps.filter((s) => !isDone(s)).length;

    el.innerHTML = `
      <h2>Easy Config</h2>
      <p class="muted">Step ${state.index + 1} of ${total}. ${
      remaining === 0 ? "Everything is answered." : `${remaining} still outstanding.`
    }</p>
      <ol class="ec-rail">${state.steps
        .map(
          (s, i) =>
            `<li class="${isDone(s) ? "is-done" : ""} ${i === state.index ? "is-current" : ""}"
              title="${esc(s.label)}"></li>`
        )
        .join("")}</ol>

      <section class="ec-step">
        <h3>${esc(step.label)}${step.blocker && !isDone(step) ? ' <span class="ec-blocker">required</span>' : ""}</h3>
        ${stepBody(step)}
        ${state.outcome ? `<p class="apply-ok">${esc(state.outcome)}</p>` : ""}
        ${state.error ? `<p class="apply-error">${esc(state.error)}</p>` : ""}
        <div class="ec-actions">
          <button type="button" class="row-edit" id="ec-back" ${state.index === 0 ? "disabled" : ""}>Back</button>
          ${
            isDone(step) && state.editing !== step.id
              ? `<button type="button" class="row-edit" id="ec-next">Next</button>`
              : `<button type="button" class="row-edit" id="ec-apply">${
                  HOW[step.id] && HOW[step.id].kind === "inline" ? "Apply and continue" : "I have done this"
                }</button>
                 <button type="button" class="row-edit" id="ec-${
                   state.editing === step.id ? "cancel" : "skip"
                 }">${state.editing === step.id ? "Cancel" : "Skip for now"}</button>`
          }
        </div>
      </section>`;
  }

  // One delegated listener: the panel is re-rendered wholesale, so
  // per-element handlers would be rebound every time.
  document.addEventListener("change", (e) => {
    if (e.target && e.target.id === "ec-wan-mode") {
      const box = document.getElementById("ec-wan-static");
      if (box) box.hidden = e.target.value !== "static";
    }
  });

  document.addEventListener("click", async (e) => {
    const t = e.target;
    if (!t.closest || !t.closest("#page-easyconfig")) return;

    if (t.id === "ec-retry") return load();
    if (t.id === "ec-edit") {
      state.editing = state.steps[state.index].id;
      state.error = state.outcome = "";
      return render();
    }
    if (t.id === "ec-cancel") {
      state.editing = null;
      state.error = state.outcome = "";
      return render();
    }
    if (t.id === "ec-back") {
      state.index = Math.max(0, state.index - 1);
      state.editing = null;
      state.error = state.outcome = "";
      return render();
    }
    if (t.id === "ec-next" || t.id === "ec-skip") {
      state.index = Math.min(state.steps.length - 1, state.index + 1);
      state.editing = null;
      state.error = state.outcome = "";
      return render();
    }
    const section = (t.dataset && t.dataset.ecSection) ||
      (t.closest("[data-ec-section]") && t.closest("[data-ec-section]").dataset.ecSection);
    if (section) {
      showPage("config");
      if (window.NSEConfig) window.NSEConfig.show(section);
      return;
    }
    if (t.id === "ec-backup") {
      window.location.href = "/api/backup";
      acknowledged.add("backup");
      return render();
    }
    if (t.id === "ec-apply") {
      const step = state.steps[state.index];
      state.error = "";
      try {
        state.outcome = await applyStep(step);
        // The device is re-read rather than trusted: a step is done when
        // the device says so, not when a button was pressed.
        await load();
      } catch (err) {
        state.error = err.message;
        render();
      }
    }
  });

  window.NSEEasyConfig = { load, render };
})();
