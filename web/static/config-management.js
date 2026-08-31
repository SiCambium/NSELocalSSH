// Management configuration section: hostname, timezone, NTP, remote
// syslog. Read-only by default; a single Edit button opens every field at
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
      </div>
      <p><button type="button" class="row-edit" id="edit-management-btn">Edit</button></p>
    `;
    document.getElementById("edit-management-btn").addEventListener("click", editManagement);
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
