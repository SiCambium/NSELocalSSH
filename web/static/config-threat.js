// Threat Protection (intrusion-prevention) configuration section.
// Per-category Snort rule enable/disable is read-only — the CLI command
// to toggle one is real, but NSE AI research confirmed the firmware's
// own rule engine has an unimplemented stub for per-category filtering,
// so toggling one could be silently inert — see config_handlers_threat.go
// for the full account.
(function () {
  const { esc, postJSON, getJSON, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;

  // The four rule types are CONFIRMED CLI values (via NSE AI CLI
  // research, matching cnMaestro's own dropdown 1:1) — cnMaestro's UI
  // labels ("emerging-threats open"/"pro") are display text only, not
  // the real CLI strings (et-open / et-pro).
  const RULE_TYPES = [
    { value: "snort-community", label: "Snort Community" },
    { value: "snort-vrt", label: "Snort VRT" },
    { value: "et-open", label: "Emerging Threats Open" },
    { value: "et-pro", label: "Emerging Threats Pro" },
  ];
  const NEEDS_OINKCODE = new Set(["snort-vrt", "et-pro"]);
  const RULE_SETS = [
    { value: "connectivity", label: "Connectivity" },
    { value: "balanced", label: "Balanced" },
    { value: "security", label: "Security" },
  ];

  function ruleTypeLabel(value) {
    const found = RULE_TYPES.find((t) => t.value === value);
    return found ? found.label : value || "-";
  }

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
    const needsOinkcode = NEEDS_OINKCODE.has(cache.ips_rule_type);
    panel.innerHTML = `
      <h2>Threat Protection</h2>
      <div class="grid">
        ${stat("Intrusion prevention", cache.ips ? "Enabled" : "Disabled")}
        ${stat("Mode", cache.ips_mode || "-")}
        ${stat("Rules tier", cache.ips_rule_set || "-")}
        ${stat("Rule type", ruleTypeLabel(cache.ips_rule_type))}
        ${stat("Auto-update", cache.ips_auto_update ? `Enabled (${esc(cache.ips_update_interval || "-")})` : "Disabled")}
      </div>
      ${needsOinkcode ? '<p class="muted">This rule type needs an Oink Code — set one below if you haven\'t already.</p>' : ""}
      <p class="muted">Active rule categories (read-only — the CLI to toggle a category exists, but this firmware's own rule engine has an unimplemented stub for per-category filtering, so a toggle could be accepted without actually changing anything; use the Rules tier above for confirmed-working coverage changes): ${esc(categories)}</p>
      <p class="muted">This firmware doesn't report a rule database version or last-update time — see the Overview tab for what's available.</p>
      <p><button type="button" class="row-edit" id="edit-threat-btn">Edit</button></p>
    `;
    document.getElementById("edit-threat-btn").addEventListener("click", editThreat);
  }

  function editThreat() {
    const ruleTypeOptions = RULE_TYPES.map(
      (t) => `<option value="${t.value}" ${cache.ips_rule_type === t.value ? "selected" : ""}>${esc(t.label)}</option>`
    ).join("");
    const ruleSetOptions = RULE_SETS.map(
      (s) => `<option value="${s.value}" ${cache.ips_rule_set === s.value ? "selected" : ""}>${esc(s.label)}</option>`
    ).join("");
    const needsOinkcode = NEEDS_OINKCODE.has(cache.ips_rule_type);
    const body = `
      <label class="check-row"><input id="cfg-threat-enable" type="checkbox" ${cache.ips ? "checked" : ""}> Intrusion prevention enabled</label>
      <label>Mode
        <select id="cfg-threat-mode">
          <option value="prevention" ${cache.ips_mode === "prevention" ? "selected" : ""}>Prevention</option>
          <option value="detection" ${cache.ips_mode === "detection" ? "selected" : ""}>Detection</option>
        </select>
      </label>
      <label>Rule type
        <select id="cfg-threat-ruletype">${ruleTypeOptions}</select>
      </label>
      <p class="muted">Snort VRT and Emerging Threats Pro need an Oink Code; Snort Community and Emerging Threats Open don't. Changing rule type triggers a fresh rule download and most likely resets the active category list.</p>
      <div id="cfg-threat-oinkcode-field" ${needsOinkcode ? "" : "hidden"}>
        <label>Oink Code
          <input id="cfg-threat-oinkcode" type="password" placeholder="paste your snort.org / ET Pro code here">
        </label>
        <p class="muted">Write-only — the stored code can't be read back, so this stays blank even when one is already set. Leave it blank to leave the existing code unchanged.</p>
      </div>
      <label>Rules tier
        <select id="cfg-threat-ruleset">${ruleSetOptions}</select>
      </label>
      <label class="check-row"><input id="cfg-threat-auto" type="checkbox" ${cache.ips_auto_update ? "checked" : ""}> Automatic rule updates</label>
      <label>Update interval (e.g. 12-hours)
        <input id="cfg-threat-interval" type="text" value="${esc(cache.ips_update_interval)}">
      </label>
      <div id="cfg-threat-outcome"></div>
    `;
    const modalEl = openModal("Edit Threat Protection", body, async (el) => {
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

      const ruleType = el.querySelector("#cfg-threat-ruletype").value;
      if (ruleType !== cache.ips_rule_type) {
        const outcome = await postJSON("/api/config/threat", { action: "rule_type", rule_type: ruleType });
        await renderOutcome(outcomeEl, outcome);
      }

      const oinkcode = el.querySelector("#cfg-threat-oinkcode").value;
      if (oinkcode) {
        const outcome = await postJSON("/api/config/threat", { action: "oinkcode", code: oinkcode });
        await renderOutcome(outcomeEl, outcome);
      }

      const ruleSet = el.querySelector("#cfg-threat-ruleset").value;
      if (ruleSet !== cache.ips_rule_set) {
        const outcome = await postJSON("/api/config/threat", { action: "rule_set", rule_set: ruleSet });
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
    modalEl.querySelector("#cfg-threat-ruletype").addEventListener("change", (e) => {
      modalEl.querySelector("#cfg-threat-oinkcode-field").hidden = !NEEDS_OINKCODE.has(e.target.value);
    });
  }

  window.NSEConfig.registerSection("threat", { load });
})();
