// Firewall configuration section: DoS-protection toggles (the only
// confirmed-syntax write here) plus a read-only view of outbound filter
// rules. Filter rules, GEO IP, port-forward, and NAT are export-only for
// now — see config_handlers_firewall.go for why.
(function () {
  const { esc, postJSON, getJSON, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;

  async function load() {
    const panel = document.getElementById("config-firewall-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      cache = await getJSON("/api/config/firewall");
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  function render() {
    const panel = document.getElementById("config-firewall-panel");
    const rules = cache.filter_config || [];
    const ruleRows = rules
      .map((f) => {
        const r = f.filter_rule || {};
        return `<tr>
          <td>${esc(f.name)}</td>
          <td>${esc(r.action)}</td>
          <td>${esc(r.proto)}</td>
          <td class="mono">${esc(r.src)}/${esc(r.src_mask)}</td>
          <td class="mono">${esc(r.dest)}/${esc(r.dest_mask)}</td>
        </tr>`;
      })
      .join("");
    panel.innerHTML = `
      <h2>Device Access</h2>
      <div class="grid">
        ${stat("Respond to ICMP pings from WAN", cache.respond_to_icmp_from_wan ? "Enabled" : "Disabled")}
      </div>
      <h2>DoS Protection</h2>
      <div class="grid">
        ${stat("Anti IP-spoofing", cache.dos_protection_ip_spoof ? "Enabled" : "Disabled")}
        ${stat("IP-spoof logging", cache.dos_protection_ip_spoof_log ? "Enabled" : "Disabled")}
        ${stat("Smurf-attack protection", cache.dos_protection_smurf_attack ? "Enabled" : "Disabled")}
        ${stat("ICMP-fragment protection", cache.dos_protection_icmp_frag ? "Enabled" : "Disabled")}
      </div>
      <p><button type="button" class="row-edit" id="edit-firewall-btn">Edit</button></p>

      <h2>Outbound Filter Rules</h2>
      <p class="muted">Read-only — creating or editing filter rules, GEO IP rules, port-forwards, and NAT isn't supported here yet; use cnMaestro for those.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Action</th><th>Protocol</th><th>Source</th><th>Destination</th></tr></thead>
        <tbody>${ruleRows || '<tr><td colspan="5" class="muted">No filter rules found.</td></tr>'}</tbody>
      </table></div>
    `;
    document.getElementById("edit-firewall-btn").addEventListener("click", editFirewall);
  }

  function editFirewall() {
    const body = `
      <label class="check-row"><input id="cfg-fw-icmp" type="checkbox" ${cache.respond_to_icmp_from_wan ? "checked" : ""}> Respond to ICMP pings from WAN</label>
      <label class="check-row"><input id="cfg-fw-spoof" type="checkbox" ${cache.dos_protection_ip_spoof ? "checked" : ""}> Anti IP-spoofing</label>
      <label class="check-row"><input id="cfg-fw-spoof-log" type="checkbox" ${cache.dos_protection_ip_spoof_log ? "checked" : ""}> Log IP-spoof hits</label>
      <label class="check-row"><input id="cfg-fw-smurf" type="checkbox" ${cache.dos_protection_smurf_attack ? "checked" : ""}> Smurf-attack protection</label>
      <label class="check-row"><input id="cfg-fw-frag" type="checkbox" ${cache.dos_protection_icmp_frag ? "checked" : ""}> ICMP-fragment protection</label>
      <div id="cfg-fw-outcome"></div>
    `;
    openModal("Edit DoS Protection", body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-fw-outcome");
      const checks = [
        ["cfg-fw-icmp", "respond_to_icmp_from_wan", cache.respond_to_icmp_from_wan],
        ["cfg-fw-spoof", "dos_ip_spoof", cache.dos_protection_ip_spoof],
        ["cfg-fw-spoof-log", "dos_ip_spoof_log", cache.dos_protection_ip_spoof_log],
        ["cfg-fw-smurf", "dos_smurf", cache.dos_protection_smurf_attack],
        ["cfg-fw-frag", "dos_icmp_frag", cache.dos_protection_icmp_frag],
      ];
      for (const [id, action, was] of checks) {
        const enable = el.querySelector(`#${id}`).checked;
        if (enable !== !!was) {
          const outcome = await postJSON("/api/config/firewall", { action, enable });
          await renderOutcome(outcomeEl, outcome);
        }
      }
      await load();
    });
  }

  window.NSEConfig.registerSection("firewall", { load });
})();
