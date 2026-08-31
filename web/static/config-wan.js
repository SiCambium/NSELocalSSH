// WAN configuration section. Read-only by default; every WAN interface
// card has a single Edit button that opens the only place values become
// editable. Every write here goes through the safe-apply path (see
// safe_apply.go) since a wrong static IP, gateway, or monitor-host list
// can take the WAN link down.
(function () {
  const { esc, postJSON, getJSON, fetchLicense, licenseGate, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;
  let license = null;

  async function load() {
    const panel = document.getElementById("config-wan-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      const [data, lic] = await Promise.all([getJSON("/api/config/wan"), fetchLicense()]);
      cache = data;
      license = lic;
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  function render() {
    const panel = document.getElementById("config-wan-panel");
    const wans = cache.wans || [];
    const cards = wans.map(renderCard).join("") || `<p class="muted">No WAN interfaces found.</p>`;
    const addBtnHTML = `<button type="button" class="row-edit" id="add-wan-btn">Enable a port as WAN</button>`;
    // A base (non-Security-Plus) unit is limited to 2 WAN ports; a 3rd or
    // later requires the overlay-wan license, confirmed by diffing a paid
    // vs. free cnMaestro account against this WAN tab's own "Add Virtual
    // WAN" control.
    const addBtn = wans.length >= 2 ? licenseGate(license, "overlay_wan", addBtnHTML) : addBtnHTML;
    panel.innerHTML = `<p>${addBtn}</p>${cards}`;
    panel.querySelectorAll(".row-edit[data-port]").forEach((btn) => {
      btn.addEventListener("click", () => editWAN(parseInt(btn.dataset.port, 10)));
    });
    panel.querySelectorAll("[data-change-port]").forEach((btn) => {
      btn.addEventListener("click", () => changePort(parseInt(btn.dataset.changePort, 10)));
    });
    const addWanBtn = document.getElementById("add-wan-btn");
    if (addWanBtn) addWanBtn.addEventListener("click", addWAN);
  }

  function portOf(w) {
    const m = /^eth(\d+)$/.exec(w.lan_intf || "");
    return m ? parseInt(m[1], 10) : 0;
  }

  function availablePorts() {
    const wanPorts = new Set((cache.wans || []).map(portOf));
    return (cache.ports || []).filter((p) => {
      const m = /^eth(\d+)$/.exec(p.interface || "");
      return m && !wanPorts.has(parseInt(m[1], 10));
    });
  }

  function pppoeOf(port) {
    return (cache.pppoe || {})[port] || null;
  }

  function renderCard(w) {
    const port = portOf(w);
    const lb = w.load_balance_config || {};
    const bw = w.bandwidth_config || {};
    const starlink = w.starlink_enable
      ? `<div class="grid">
          ${stat("Starlink dish IP", w.starlink_dish_ip)}
          ${stat("Starlink dish mode", w.starlink_dish_mode)}
          ${stat("Starlink dish port", w.starlink_dish_port)}
        </div>`
      : "";
    const pppoe = pppoeOf(port);
    const pppoeBlock = pppoe
      ? `<div class="grid">
          ${stat("PPPoE user", pppoe.user)}
          ${stat("PPPoE MTU", pppoe.mtu)}
          ${stat("PPPoE MSS clamping", pppoe.mss_clamp ? "Enabled" : "Disabled")}
          ${stat("PPPoE AC name", pppoe.ac_name || "-")}
          ${stat("PPPoE service name", pppoe.service_name || "-")}
        </div>`
      : "";
    return `<h2>${esc(w.name)} <span class="muted">(${esc(w.lan_intf)})</span></h2>
      <div class="grid">
        ${stat("IP mode", pppoe ? "pppoe" : w.ip_mode)}
        ${stat("Source NAT", w.source_nat)}
        ${stat("Load balance mode", lb.lb_mode)}
        ${stat("Traffic share", (lb["lb_traffic-share-percentage"] || "-") + "%")}
        ${stat("Monitor hosts", (lb["lb_monitor-hosts"] || []).join(", "))}
        ${stat("Uplink", (bw.uplink_bandwidth || "-") + " Mbps")}
        ${stat("Downlink", (bw.downlink_bandwidth || "-") + " Mbps")}
      </div>
      ${pppoeBlock}
      ${starlink}
      <p>
        <button type="button" class="row-edit" data-port="${port}">Edit</button>
        <button type="button" class="row-edit" data-change-port="${port}">Change port</button>
      </p>`;
  }

  function editWAN(port) {
    const w = (cache.wans || []).find((x) => portOf(x) === port);
    if (!w) return;
    const lb = w.load_balance_config || {};
    const bw = w.bandwidth_config || {};
    const pppoe = pppoeOf(port);
    const isStatic = !pppoe && w.ip_mode === "static";
    const isPPPoE = !!pppoe;
    const currentMode = isPPPoE ? "pppoe" : isStatic ? "static" : "dhcp";
    const lbMode = lb.lb_mode || "shared";
    const body = `
      <label>IP mode
        <select id="cfg-wan-mode">
          <option value="dhcp" ${currentMode === "dhcp" ? "selected" : ""}>DHCP</option>
          <option value="static" ${currentMode === "static" ? "selected" : ""}>Static</option>
          <option value="pppoe" ${currentMode === "pppoe" ? "selected" : ""}>PPPoE</option>
        </select>
      </label>
      <div id="cfg-wan-static-fields" ${isStatic ? "" : "hidden"}>
        <label>IP address <input id="cfg-wan-ip" type="text" placeholder="e.g. 203.0.113.10"></label>
        <label>Subnet mask <input id="cfg-wan-mask" type="text" placeholder="e.g. 255.255.255.0"></label>
        <label>Gateway <input id="cfg-wan-gw" type="text" placeholder="e.g. 203.0.113.1"></label>
      </div>
      <div id="cfg-wan-pppoe-fields" ${isPPPoE ? "" : "hidden"}>
        <label>PPPoE user name <input id="cfg-wan-pppoe-user" type="text" value="${esc(pppoe ? pppoe.user : "")}"></label>
        <label>PPPoE password <input id="cfg-wan-pppoe-password" type="password"></label>
        ${pppoe ? '<p class="muted">The stored password can\'t be read back, so it must be re-entered every time you save this form, even if it hasn\'t changed.</p>' : ""}
        <label>AC Name (optional) <input id="cfg-wan-pppoe-ac" type="text" value="${esc(pppoe ? pppoe.ac_name || "" : "")}"></label>
        <label>Service Name (optional) <input id="cfg-wan-pppoe-service" type="text" value="${esc(pppoe ? pppoe.service_name || "" : "")}"></label>
        <label>MTU (500-1492) <input id="cfg-wan-pppoe-mtu" type="number" min="500" max="1492" value="${pppoe ? pppoe.mtu : 1492}"></label>
        <label class="check-row"><input id="cfg-wan-pppoe-mss" type="checkbox" ${pppoe && pppoe.mss_clamp ? "checked" : ""}> TCP MSS clamping</label>
      </div>
      <label>Load balance mode
        <select id="cfg-wan-lbmode">
          <option value="shared" ${lbMode === "shared" ? "selected" : ""}>Shared</option>
          <option value="backup" ${lbMode === "backup" ? "selected" : ""}>Backup</option>
          <option value="disabled" ${lbMode === "disabled" ? "selected" : ""}>Disabled</option>
        </select>
      </label>
      <div id="cfg-wan-priority-field" ${lbMode === "backup" ? "" : "hidden"}>
        <label>Backup priority (0 = highest, 10 = lowest)
          <input id="cfg-wan-priority" type="number" min="0" max="10" value="0">
        </label>
      </div>
      <label>Monitor hosts (comma separated)
        <input id="cfg-wan-hosts" type="text" value="${esc((lb["lb_monitor-hosts"] || []).join(","))}">
      </label>
      <h3>Connection Health</h3>
      <label>Number of host failures to declare interface down
        <input id="cfg-wan-numfail" type="number" min="1" value="${esc(lb["lb_num-hosts-fail-interface-down"] || "1")}">
      </label>
      <label>Failure detect time (5-60 seconds)
        <input id="cfg-wan-faildetect" type="number" min="5" max="60" value="${esc(lb["lb_ping-failure-detect-time"] || "5")}">
      </label>
      <label>Ping interval (2-10 seconds)
        <input id="cfg-wan-pinginterval" type="number" min="2" max="10" value="${esc(lb["lb_ping-interval"] || "2")}">
      </label>
      <label>Ping timeout (1-10 seconds)
        <input id="cfg-wan-pingtimeout" type="number" min="1" max="10" value="${esc(lb["lb_ping-timeout"] || "2")}">
      </label>
      <label>Traffic share % (when load-balance mode is shared)
        <input id="cfg-wan-share" type="number" min="0" max="100" value="${esc(lb["lb_traffic-share-percentage"] || "")}">
      </label>
      <label>Uplink Mbps <input id="cfg-wan-up" type="number" min="1" value="${esc(bw.uplink_bandwidth || "")}"></label>
      <label>Downlink Mbps <input id="cfg-wan-down" type="number" min="1" value="${esc(bw.downlink_bandwidth || "")}"></label>
      <p class="warn">WAN changes are applied through the safe-apply path: they're verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed or if the device becomes unreachable.</p>
      <div id="cfg-wan-outcome"></div>
    `;
    const modalEl = openModal(`Edit ${w.name}`, body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-wan-outcome");
      const mode = el.querySelector("#cfg-wan-mode").value;
      if (mode === "static") {
        const ip = el.querySelector("#cfg-wan-ip").value.trim();
        const mask = el.querySelector("#cfg-wan-mask").value.trim();
        const gw = el.querySelector("#cfg-wan-gw").value.trim();
        if (!ip || !mask || !gw) throw new Error("IP, mask, and gateway are all required for a static WAN");
        const outcome = await postJSON("/api/config/wan", { action: "ip_mode", port, mode, ip, mask, gateway: gw });
        await renderOutcome(outcomeEl, outcome);
      } else if (mode === "pppoe") {
        const pppoeUser = el.querySelector("#cfg-wan-pppoe-user").value.trim();
        const pppoePassword = el.querySelector("#cfg-wan-pppoe-password").value;
        if (!pppoeUser || !pppoePassword) throw new Error("PPPoE user name and password are required");
        const outcome = await postJSON("/api/config/wan", {
          action: "ip_mode",
          port,
          mode,
          pppoe_user: pppoeUser,
          pppoe_password: pppoePassword,
          pppoe_ac_name: el.querySelector("#cfg-wan-pppoe-ac").value.trim(),
          pppoe_service_name: el.querySelector("#cfg-wan-pppoe-service").value.trim(),
          pppoe_mtu: parseInt(el.querySelector("#cfg-wan-pppoe-mtu").value, 10) || 1492,
          pppoe_mss_clamp: el.querySelector("#cfg-wan-pppoe-mss").checked,
        });
        await renderOutcome(outcomeEl, outcome);
      } else if (isStatic || isPPPoE) {
        // Only send the mode switch if it actually changed.
        const outcome = await postJSON("/api/config/wan", { action: "ip_mode", port, mode: "dhcp" });
        await renderOutcome(outcomeEl, outcome);
      }

      const newLBMode = el.querySelector("#cfg-wan-lbmode").value;
      if (newLBMode !== lbMode) {
        const req = { action: "load_balance_mode", port, lb_mode: newLBMode };
        if (newLBMode === "backup") {
          req.priority = parseInt(el.querySelector("#cfg-wan-priority").value, 10) || 0;
        }
        const outcome = await postJSON("/api/config/wan", req);
        await renderOutcome(outcomeEl, outcome);
      }

      const hosts = el
        .querySelector("#cfg-wan-hosts")
        .value.split(",")
        .map((h) => h.trim())
        .filter(Boolean);
      if (hosts.length && hosts.join(",") !== (lb["lb_monitor-hosts"] || []).join(",")) {
        const outcome = await postJSON("/api/config/wan", { action: "monitor_hosts", port, hosts });
        await renderOutcome(outcomeEl, outcome);
      }

      const numFail = parseInt(el.querySelector("#cfg-wan-numfail").value, 10);
      const failDetect = parseInt(el.querySelector("#cfg-wan-faildetect").value, 10);
      const pingInterval = parseInt(el.querySelector("#cfg-wan-pinginterval").value, 10);
      const pingTimeout = parseInt(el.querySelector("#cfg-wan-pingtimeout").value, 10);
      if (
        String(numFail) !== String(lb["lb_num-hosts-fail-interface-down"] || "1") ||
        String(failDetect) !== String(lb["lb_ping-failure-detect-time"] || "5") ||
        String(pingInterval) !== String(lb["lb_ping-interval"] || "2") ||
        String(pingTimeout) !== String(lb["lb_ping-timeout"] || "2")
      ) {
        const outcome = await postJSON("/api/config/wan", {
          action: "connection_health",
          port,
          num_hosts_fail: numFail,
          failure_detect_time: failDetect,
          ping_interval: pingInterval,
          ping_timeout: pingTimeout,
        });
        await renderOutcome(outcomeEl, outcome);
      }

      const share = parseInt(el.querySelector("#cfg-wan-share").value, 10);
      if (!Number.isNaN(share) && String(share) !== String(lb["lb_traffic-share-percentage"] || "")) {
        const outcome = await postJSON("/api/config/wan", { action: "traffic_share", port, percent: share });
        await renderOutcome(outcomeEl, outcome);
      }

      const up = parseInt(el.querySelector("#cfg-wan-up").value, 10);
      const down = parseInt(el.querySelector("#cfg-wan-down").value, 10);
      if (
        !Number.isNaN(up) &&
        !Number.isNaN(down) &&
        (String(up) !== String(bw.uplink_bandwidth || "") || String(down) !== String(bw.downlink_bandwidth || ""))
      ) {
        const outcome = await postJSON("/api/config/wan", { action: "bandwidth", port, uplink_mbps: up, downlink_mbps: down });
        await renderOutcome(outcomeEl, outcome);
      }

      await load();
    });
    modalEl.querySelector("#cfg-wan-mode").addEventListener("change", (e) => {
      modalEl.querySelector("#cfg-wan-static-fields").hidden = e.target.value !== "static";
      modalEl.querySelector("#cfg-wan-pppoe-fields").hidden = e.target.value !== "pppoe";
    });
    modalEl.querySelector("#cfg-wan-lbmode").addEventListener("change", (e) => {
      modalEl.querySelector("#cfg-wan-priority-field").hidden = e.target.value !== "backup";
    });
  }

  function addWAN() {
    const ports = availablePorts();
    if (!ports.length) {
      openModal("Enable a port as WAN", `<p class="muted">Every physical port is already a WAN or is in use. Free up a LAN port first.</p>`, async () => {});
      return;
    }
    const options = ports.map((p) => `<option value="${esc(p.interface)}">${esc(p.interface)} (currently ${esc(p.type || "unused")})</option>`).join("");
    const nextWanNum = (cache.wans || []).length + 1;
    const body = `
      <label>Port
        <select id="cfg-new-wan-port">${options}</select>
      </label>
      <label>WAN name
        <input id="cfg-new-wan-name" type="text" value="wan${nextWanNum}">
      </label>
      <label>Uplink Mbps (optional)
        <input id="cfg-new-wan-up" type="number" min="1" placeholder="e.g. 100">
      </label>
      <label>Downlink Mbps (optional)
        <input id="cfg-new-wan-down" type="number" min="1" placeholder="e.g. 100">
      </label>
      <p class="warn">This changes a port from LAN to WAN (defaulting to DHCP). It's applied through the safe-apply path: verified reachable over a fresh connection, and rolled back automatically within 60 seconds if not confirmed. If this port is currently carrying LAN traffic, converting it will interrupt that traffic.</p>
      <div id="cfg-new-wan-outcome"></div>
    `;
    openModal("Enable a port as WAN", body, async (el) => {
      const portStr = el.querySelector("#cfg-new-wan-port").value;
      const port = parseInt(/^eth(\d+)$/.exec(portStr)[1], 10);
      const name = el.querySelector("#cfg-new-wan-name").value.trim();
      if (!name) throw new Error("WAN name is required");
      const up = parseInt(el.querySelector("#cfg-new-wan-up").value, 10);
      const down = parseInt(el.querySelector("#cfg-new-wan-down").value, 10);
      const req = { action: "enable", port, name };
      if (!Number.isNaN(up) && !Number.isNaN(down)) {
        req.uplink_mbps = up;
        req.downlink_mbps = down;
      }
      const outcome = await postJSON("/api/config/wan", req);
      await renderOutcome(el.querySelector("#cfg-new-wan-outcome"), outcome);
      await load();
    });
  }

  // changePort moves an existing WAN from its current physical port to a
  // different one — the "swap eth ports" workflow: the old port reverts to
  // a plain LAN access port (VLAN 1) while the chosen port is promoted to
  // WAN, carrying forward the same name/IP mode/bandwidth. Both interfaces
  // are changed in one atomic, safe-apply-guarded step.
  function changePort(port) {
    const w = (cache.wans || []).find((x) => portOf(x) === port);
    if (!w) return;
    const ports = availablePorts();
    if (!ports.length) {
      openModal("Change port", `<p class="muted">Every other physical port is already a WAN or in use. Free up a LAN port first.</p>`, async () => {});
      return;
    }
    const pppoe = pppoeOf(port);
    const isStatic = !pppoe && w.ip_mode === "static";
    const isPPPoE = !!pppoe;
    const currentMode = isPPPoE ? "pppoe" : isStatic ? "static" : "dhcp";
    const bw = w.bandwidth_config || {};
    const options = ports.map((p) => `<option value="${esc(p.interface)}">${esc(p.interface)} (currently ${esc(p.type || "unused")})</option>`).join("");
    const body = `
      <p class="muted">Moves ${esc(w.name)} from eth${port} to a different physical port. eth${port} reverts to a plain LAN access port (VLAN 1).</p>
      <label>New port
        <select id="cfg-chg-port">${options}</select>
      </label>
      <label>IP mode
        <select id="cfg-chg-mode">
          <option value="dhcp" ${currentMode === "dhcp" ? "selected" : ""}>DHCP</option>
          <option value="static" ${currentMode === "static" ? "selected" : ""}>Static</option>
          <option value="pppoe" ${currentMode === "pppoe" ? "selected" : ""}>PPPoE</option>
        </select>
      </label>
      <div id="cfg-chg-static-fields" ${isStatic ? "" : "hidden"}>
        <label>IP address <input id="cfg-chg-ip" type="text" value="${isStatic ? esc(w.ip_addr || "") : ""}" placeholder="e.g. 203.0.113.10"></label>
        <label>Subnet mask <input id="cfg-chg-mask" type="text" value="${isStatic ? esc(w.subnet_mask || "") : ""}" placeholder="e.g. 255.255.255.0"></label>
        <label>Gateway <input id="cfg-chg-gw" type="text" placeholder="e.g. 203.0.113.1"></label>
      </div>
      <div id="cfg-chg-pppoe-fields" ${isPPPoE ? "" : "hidden"}>
        <label>PPPoE user name <input id="cfg-chg-pppoe-user" type="text" value="${esc(pppoe ? pppoe.user : "")}"></label>
        <label>PPPoE password <input id="cfg-chg-pppoe-password" type="password"></label>
        ${pppoe ? '<p class="muted">The stored password can\'t be read back, so it must be re-entered here.</p>' : ""}
        <label>MTU (500-1492) <input id="cfg-chg-pppoe-mtu" type="number" min="500" max="1492" value="${pppoe ? pppoe.mtu : 1492}"></label>
      </div>
      <label>Uplink Mbps (optional) <input id="cfg-chg-up" type="number" min="1" value="${esc(bw.uplink_bandwidth || "")}"></label>
      <label>Downlink Mbps (optional) <input id="cfg-chg-down" type="number" min="1" value="${esc(bw.downlink_bandwidth || "")}"></label>
      <p class="warn">This reassigns two physical ports at once and is applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically (restoring both ports to their exact prior config) within 60 seconds if not confirmed or if the device becomes unreachable. Whether "type lan" fully clears the old port's WAN-only settings is unconfirmed — if this port looks odd afterward, its exact prior config is only ever a rollback away.</p>
      <div id="cfg-chg-outcome"></div>
    `;
    const modalEl = openModal(`Change port for ${w.name}`, body, async (el) => {
      const newPortStr = el.querySelector("#cfg-chg-port").value;
      const newPort = parseInt(/^eth(\d+)$/.exec(newPortStr)[1], 10);
      const mode = el.querySelector("#cfg-chg-mode").value;
      const req = { action: "change_port", port, new_port: newPort, name: w.name, mode };
      if (mode === "static") {
        req.ip = el.querySelector("#cfg-chg-ip").value.trim();
        req.mask = el.querySelector("#cfg-chg-mask").value.trim();
        req.gateway = el.querySelector("#cfg-chg-gw").value.trim();
        if (!req.ip || !req.mask || !req.gateway) throw new Error("IP, mask, and gateway are all required for a static WAN");
      } else if (mode === "pppoe") {
        req.pppoe_user = el.querySelector("#cfg-chg-pppoe-user").value.trim();
        req.pppoe_password = el.querySelector("#cfg-chg-pppoe-password").value;
        req.pppoe_mtu = parseInt(el.querySelector("#cfg-chg-pppoe-mtu").value, 10) || 1492;
        if (!req.pppoe_user || !req.pppoe_password) throw new Error("PPPoE user name and password are required");
      }
      const up = parseInt(el.querySelector("#cfg-chg-up").value, 10);
      const down = parseInt(el.querySelector("#cfg-chg-down").value, 10);
      if (!Number.isNaN(up) && !Number.isNaN(down)) {
        req.uplink_mbps = up;
        req.downlink_mbps = down;
      }
      const outcome = await postJSON("/api/config/wan", req);
      await renderOutcome(el.querySelector("#cfg-chg-outcome"), outcome);
      await load();
    });
    modalEl.querySelector("#cfg-chg-mode").addEventListener("change", (e) => {
      modalEl.querySelector("#cfg-chg-static-fields").hidden = e.target.value !== "static";
      modalEl.querySelector("#cfg-chg-pppoe-fields").hidden = e.target.value !== "pppoe";
    });
  }

  window.NSEConfig.registerSection("wan", { load });
})();
