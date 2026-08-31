// Threat Protection (intrusion-prevention) configuration section.
// Per-category Snort rule enable/disable is read-only — see
// config_handlers_threat.go for why.
(function () {
  const { esc, postJSON, getJSON, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;

  async function load() {
    const panel = document.getElementById("config-threat-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      cache = await getJSON("/api/config/threat");
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  function render() {
    const panel = document.getElementById("config-threat-panel");
    const categories = (cache.snort_category || []).map((c) => c.category).join(", ") || "-";
    panel.innerHTML = `
      <h2>Threat Protection</h2>
      <div class="grid">
        ${stat("Intrusion prevention", cache.ips ? "Enabled" : "Disabled")}
        ${stat("Mode", cache.ips_mode || "-")}
        ${stat("Rule set", cache.ips_rule_set || "-")}
        ${stat("Rule type", cache.ips_rule_type || "-")}
        ${stat("Auto-update", cache.ips_auto_update ? `Enabled (${esc(cache.ips_update_interval || "-")})` : "Disabled")}
      </div>
      <p class="muted">Active rule categories: ${esc(categories)}</p>
      <p><button type="button" class="row-edit" id="edit-threat-btn">Edit</button></p>
    `;
    document.getElementById("edit-threat-btn").addEventListener("click", editThreat);
  }

  function editThreat() {
    const body = `
      <label class="check-row"><input id="cfg-threat-enable" type="checkbox" ${cache.ips ? "checked" : ""}> Intrusion prevention enabled</label>
      <label>Mode
        <select id="cfg-threat-mode">
          <option value="prevention" ${cache.ips_mode === "prevention" ? "selected" : ""}>Prevention</option>
          <option value="detection" ${cache.ips_mode === "detection" ? "selected" : ""}>Detection</option>
        </select>
      </label>
      <label>Rule set <input id="cfg-threat-ruleset" type="text" value="${esc(cache.ips_rule_set)}"></label>
      <label>Rule type <input id="cfg-threat-ruletype" type="text" value="${esc(cache.ips_rule_type)}"></label>
      <label class="check-row"><input id="cfg-threat-auto" type="checkbox" ${cache.ips_auto_update ? "checked" : ""}> Automatic rule updates</label>
      <label>Update interval (e.g. 12-hours)
        <input id="cfg-threat-interval" type="text" value="${esc(cache.ips_update_interval)}">
      </label>
      <div id="cfg-threat-outcome"></div>
    `;
    openModal("Edit Threat Protection", body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-threat-outcome");
      const enable = el.querySelector("#cfg-threat-enable").checked;
      if (enable !== !!cache.ips) {
        const outcome = await postJSON("/api/config/threat", { action: "enable", enable });
        await renderOutcome(outcomeEl, outcome);
      }

      const mode = el.querySelector("#cfg-threat-mode").value;
      if (mode !== cache.ips_mode) {
        const outcome = await postJSON("/api/config/threat", { action: "mode", mode });
        await renderOutcome(outcomeEl, outcome);
      }

      const ruleSet = el.querySelector("#cfg-threat-ruleset").value.trim();
      if (ruleSet && ruleSet !== cache.ips_rule_set) {
        const outcome = await postJSON("/api/config/threat", { action: "rule_set", rule_set: ruleSet });
        await renderOutcome(outcomeEl, outcome);
      }

      const ruleType = el.querySelector("#cfg-threat-ruletype").value.trim();
      if (ruleType && ruleType !== cache.ips_rule_type) {
        const outcome = await postJSON("/api/config/threat", { action: "rule_type", rule_type: ruleType });
        await renderOutcome(outcomeEl, outcome);
      }

      const autoUpdate = el.querySelector("#cfg-threat-auto").checked;
      const interval = el.querySelector("#cfg-threat-interval").value.trim();
      if (autoUpdate !== !!cache.ips_auto_update || (autoUpdate && interval !== cache.ips_update_interval)) {
        const outcome = await postJSON("/api/config/threat", { action: "auto_update", enable: autoUpdate, interval });
        await renderOutcome(outcomeEl, outcome);
      }

      await load();
    });
  }

  window.NSEConfig.registerSection("threat", { load });
})();
