// Management configuration section: hostname, timezone, NTP, remote
// syslog, and the cnMaestro link. Read-only by default; a single Edit button opens every field at
// once since there are only a handful and they're independent singleton
// settings, not a list. None of these are lockout-risk (see
// ClassifyRisk("management") in safe_apply.go), so changes apply
// immediately rather than going through the provisional confirm flow.
//
// Deliberately absent: admin password, and the management ssh/https/http
// toggles — those gate the very access this app depends on, so they get no
// UI here, not even behind a warning banner.
(function () {
  const { esc, postJSON, getJSON, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;

  async function load() {
    const panel = document.getElementById("config-management-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      cache = await getJSON("/api/config/management");
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  function firstNTP() {
    return ((cache.ntp_server || [])[0] || {}).server_address || "";
  }

  function firstSyslog() {
    const s = (cache.syslog_server || [])[0] || {};
    return { ip: s.server_ip || "", port: s.server_port || "" };
  }

  function render() {
    const panel = document.getElementById("config-management-panel");
    const syslog = firstSyslog();
    panel.innerHTML = `
      <h2>Management</h2>
      <div class="grid">
        ${stat("Hostname", cache.hostname)}
        ${stat("Timezone", cache.tz_name)}
        ${stat("NTP server", firstNTP() || "-")}
        ${stat("Syslog host", syslog.ip ? `${syslog.ip}:${syslog.port}` : "-")}
        ${stat("Syslog severity", cache.logging_syslog)}
        ${stat("cnMaestro", cache.cambium_remote ? "Linked" : "Delinked")}
      </div>
      <p><button type="button" class="row-edit" id="edit-management-btn">Edit</button></p>

      <h3>cnMaestro</h3>
      <p class="muted">${
        cache.cambium_remote
          ? "This device is linked to cnMaestro for cloud management."
          : "This device is not linked to cnMaestro. It is managed locally only."
      }</p>
      <p><button type="button" class="row-edit" id="cambium-remote-btn">${
        cache.cambium_remote ? "Delink from cnMaestro" : "Link to cnMaestro"
      }</button></p>
    `;
    document.getElementById("edit-management-btn").addEventListener("click", editManagement);
    document.getElementById("cambium-remote-btn").addEventListener("click", toggleCambiumRemote);
  }

  // Delinking is kept out of the Edit modal and behind its own explicit
  // confirmation. It is not a lockout risk — local access is unaffected,
  // so it applies and saves immediately — but it is awkward to undo: the
  // config leaf comes back by sending the positive line, while actually
  // reconnecting generally needs the device re-claimed in cnMaestro,
  // which this app cannot do.
  function toggleCambiumRemote() {
    const enable = !cache.cambium_remote;
    const body = enable
      ? `<p class="warn">This re-adds the <span class="mono">management cambium-remote</span> setting. The device may still need to be claimed in cnMaestro before it actually reconnects — that part cannot be done from here.</p>
         <div id="cfg-cambium-outcome"></div>`
      : `<p class="warn">This sends <span class="mono">no management cambium-remote</span>, ending cloud management of this device. Local access over SSH and this app are unaffected.</p>
         <p class="muted">Re-linking sets the option back, but the device will generally also need to be re-claimed in cnMaestro, which cannot be done from here. cnMaestro will no longer push configuration to this device, so any local changes stop being overwritten — and stop being backed up.</p>
         <div id="cfg-cambium-outcome"></div>`;
    openModal(enable ? "Link to cnMaestro" : "Delink from cnMaestro", body, async (el) => {
      const outcome = await postJSON("/api/config/management", { action: "cambium_remote", enable });
      await renderOutcome(el.querySelector("#cfg-cambium-outcome"), outcome);
      await load();
    });
  }

  function editManagement() {
    const ntp = firstNTP();
    const syslog = firstSyslog();
    const severity = parseInt(cache.logging_syslog, 10);
    const body = `
      <label>Hostname <input id="cfg-mgmt-hostname" type="text" value="${esc(cache.hostname)}"></label>
      <label>Timezone (IANA name, e.g. Europe/London) <input id="cfg-mgmt-tz" type="text" value="${esc(cache.tz_name)}"></label>
      <label>NTP server <input id="cfg-mgmt-ntp" type="text" value="${esc(ntp)}"></label>
      <h3>Remote syslog</h3>
      <label>Host <input id="cfg-mgmt-syslog-ip" type="text" value="${esc(syslog.ip)}" placeholder="e.g. 172.22.0.9"></label>
      <label>Port <input id="cfg-mgmt-syslog-port" type="text" value="${esc(syslog.port)}" placeholder="e.g. 514"></label>
      <label>Severity (0 = emergency .. 7 = debug)
        <input id="cfg-mgmt-syslog-sev" type="number" min="0" max="7" value="${Number.isNaN(severity) ? 5 : severity}">
      </label>
      <div id="cfg-mgmt-outcome"></div>
    `;
    openModal("Edit Management", body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-mgmt-outcome");
      const hostname = el.querySelector("#cfg-mgmt-hostname").value.trim();
      if (hostname && hostname !== cache.hostname) {
        const outcome = await postJSON("/api/config/management", { action: "hostname", hostname });
        await renderOutcome(outcomeEl, outcome);
      }

      const tz = el.querySelector("#cfg-mgmt-tz").value.trim();
      if (tz && tz !== cache.tz_name) {
        const outcome = await postJSON("/api/config/management", { action: "timezone", tz_name: tz });
        await renderOutcome(outcomeEl, outcome);
      }

      const newNTP = el.querySelector("#cfg-mgmt-ntp").value.trim();
      if (newNTP && newNTP !== ntp) {
        const outcome = await postJSON("/api/config/management", { action: "ntp_server", ntp_server: newNTP });
        await renderOutcome(outcomeEl, outcome);
      }

      const syslogIP = el.querySelector("#cfg-mgmt-syslog-ip").value.trim();
      const syslogPort = el.querySelector("#cfg-mgmt-syslog-port").value.trim();
      const syslogSev = parseInt(el.querySelector("#cfg-mgmt-syslog-sev").value, 10);
      if (syslogIP && syslogPort && (syslogIP !== syslog.ip || syslogPort !== syslog.port || syslogSev !== severity)) {
        const outcome = await postJSON("/api/config/management", {
          action: "syslog",
          syslog_ip: syslogIP,
          syslog_port: syslogPort,
          severity: syslogSev,
        });
        await renderOutcome(outcomeEl, outcome);
      }

      await load();
    });
  }

  window.NSEConfig.registerSection("management", { load });
})();
