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
    // Promoting a LAN port to WAN is a different job from tuning the WAN
    // links that already exist: it changes what a physical port is. It
    // sits above the links as a page action rather than trailing the last
    // card, where it read as one more control belonging to that card.
    const addBtnHTML = `<button type="button" class="row-edit primary" id="add-wan-btn">Turn a LAN port into a WAN</button>`;
    // A base (non-Security-Plus) unit is limited to 2 WAN ports; a 3rd or
    // later requires the overlay-wan license, confirmed by diffing a paid
    // vs. free cnMaestro account against this WAN tab's own "Add Virtual
    // WAN" control.
    const addBtn = wans.length >= 2 ? licenseGate(license, "overlay_wan", addBtnHTML) : addBtnHTML;
    // Named and explained rather than left as a lone button: promoting a
    // port is the one action on this page that changes the hardware's
    // wiring, and a button on its own at the page edge read as a minor
    // control rather than the different job it is.
    const promote = `<section class="plate service-strip">
      <div>
        <h2>Port roles</h2>
        <p class="muted">Every port is a LAN port until it is promoted. Promoting one moves it out of the LAN and gives it its own uplink.</p>
      </div>
      ${addBtn}
    </section>`;
    panel.innerHTML = `${promote}${loadBalanceSummary(wans)}${cards}`;
    panel.querySelectorAll(".row-edit[data-port]").forEach((btn) => {
      btn.addEventListener("click", () => editWAN(parseInt(btn.dataset.port, 10)));
    });
    panel.querySelectorAll("[data-change-port]").forEach((btn) => {
      btn.addEventListener("click", () => changePort(parseInt(btn.dataset.changePort, 10)));
    });
    const addWanBtn = document.getElementById("add-wan-btn");
    if (addWanBtn) addWanBtn.addEventListener("click", addWAN);
  }

  // --- Load balancing ----------------------------------------------------
  // Load balancing is the reason most people open this page, and it was
  // the one thing the page did not show: each WAN card carried its own
  // "lb_mode" and "traffic share %" as two more rows of CLI vocabulary,
  // and nothing anywhere said which link the traffic actually leaves by,
  // or what happens when it fails. That is a property of the set of WANs,
  // not of any one of them, so it is stated once, above the cards, in the
  // order someone asks it: what carries traffic now, what takes over, and
  // what is out of the rotation.

  function lbOf(w) {
    return w.load_balance_config || {};
  }

  function shareOf(w) {
    const n = parseInt(lbOf(w)["lb_traffic-share-percentage"], 10);
    return Number.isNaN(n) ? 0 : n;
  }

  function priorityOf(w) {
    const n = parseInt(lbOf(w)["lb_backup-link-priority"], 10);
    return Number.isNaN(n) ? 0 : n;
  }

  function roleOf(w) {
    const mode = (lbOf(w).lb_mode || "").toLowerCase();
    if (mode === "shared") return "active";
    if (mode === "backup") return "backup";
    return "off";
  }

  // The role as the operator would say it out loud, used both on the card
  // heading and in the summary.
  function roleLabel(w) {
    const role = roleOf(w);
    if (role === "active") return `Carrying traffic · ${shareOf(w)}%`;
    if (role === "backup") return `Standby · priority ${priorityOf(w)}`;
    return "Not in load balancing";
  }

  function loadBalanceSummary(wans) {
    if (!wans.length) return "";
    const active = wans.filter((w) => roleOf(w) === "active");
    const backup = wans
      .filter((w) => roleOf(w) === "backup")
      .sort((a, b) => priorityOf(a) - priorityOf(b));
    const off = wans.filter((w) => roleOf(w) === "off");
    const total = active.reduce((sum, w) => sum + shareOf(w), 0);

    // The bar is the division of outbound traffic, drawn to scale. With
    // one active link it is a single full-width band, which is the true
    // picture: everything leaves by that link.
    const bar = active.length
      ? `<div class="lb-bar" role="img" aria-label="${esc(
          active.map((w) => `${w.name} ${shareOf(w)}%`).join(", ")
        )}">${active
          .map(
            (w, i) =>
              `<span class="lb-seg lb-seg-${(i % 4) + 1}" style="flex: ${Math.max(shareOf(w), 1)}">
                 <span class="lb-seg-name">${esc(w.name || w.lan_intf)}</span>
                 <span class="lb-seg-pct">${shareOf(w)}%</span>
               </span>`
          )
          .join("")}</div>`
      : `<p class="box-empty">No link is set to carry traffic. Every WAN here is either standby or out of load balancing.</p>`;

    // One sentence, built from the same numbers the bar is drawn from.
    let sentence;
    if (active.length === 1) {
      sentence = `Everything leaves by ${active[0].name}.`;
    } else if (active.length > 1) {
      sentence = `Outbound traffic is split across ${active.length} links: ${active
        .map((w) => `${w.name} ${shareOf(w)}%`)
        .join(", ")}.`;
    } else {
      sentence = "Nothing is set to carry traffic right now.";
    }
    if (backup.length === 1) {
      sentence += ` ${backup[0].name} takes over if the active link fails.`;
    } else if (backup.length > 1) {
      sentence += ` ${backup.map((w) => w.name).join(", then ")} take over in that order if the active links fail.`;
    } else if (active.length === 1) {
      sentence += " There is no standby link: if it fails, the site is offline.";
    }

    const warn =
      active.length && total !== 100
        ? `<p class="warn">The active shares add up to ${total}%, not 100%. The device splits traffic by the ratio between them, so this still works, but the numbers will not read the way an operator expects.</p>`
        : "";

    const standbyRow = backup.length
      ? `<p class="lb-row"><span class="legend">Standby</span>${backup
          .map((w) => `<span class="role-chip role-backup">${esc(w.name)} · priority ${priorityOf(w)}</span>`)
          .join("")}</p>`
      : "";
    const offRow = off.length
      ? `<p class="lb-row"><span class="legend">Out of rotation</span>${off
          .map((w) => `<span class="role-chip role-off">${esc(w.name)}</span>`)
          .join("")}</p>`
      : "";

    return `<h2>Load balancing</h2>
      <p class="lb-sentence">${esc(sentence)}</p>
      ${bar}
      ${standbyRow}
      ${offRow}
      ${warn}
      <p class="muted">Set each link's role and share on its own card below. A link is declared down after the
        number of failed pings set under Connection check, and traffic moves to the next link in line.</p>`;
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

  // "Active" is two facts, not one: the port's link is up, and it is the
  // port holding the default route. A backup WAN behind a healthy primary
  // is plugged in and idle, so a dot driven by link state alone would call
  // it active. The three states are kept distinct rather than collapsed
  // into on/off, because "up but not carrying traffic" is exactly what an
  // operator checking a failover pair wants to see.
  function wanLinkState(w) {
    const port = String(w.lan_intf || "").toLowerCase();
    const link = (cache.link || {})[port] || {};
    const up = String(link.status || "").toUpperCase() === "UP";
    const gateway = (cache.default_routes || {})[port];
    if (up && gateway) return { cls: "on", label: "Active", detail: `carrying the default route via ${gateway}` };
    if (up) return { cls: "idle", label: "Standby", detail: "link is up but not carrying the default route" };
    return { cls: "down", label: "Down", detail: "no link on this port" };
  }

  function wanStatusHTML(w) {
    const st = wanLinkState(w);
    const link = (cache.link || {})[String(w.lan_intf || "").toLowerCase()] || {};
    const speed = link.speed && link.speed !== "N/A" ? ` ${esc(link.speed)}` : "";
    return `<span class="wan-status" title="${esc(st.detail)}"><span class="conn-dot ${st.cls}"></span>${esc(st.label)}${speed}</span>`;
  }

  // A card is one link, read top to bottom the way someone standing in
  // front of the rack asks about it: what is this link's job, how does it
  // get its address, how fast is it, and how does the device decide it
  // has died. The raw CLI vocabulary the card used to print ("dynamic",
  // "enable") is translated, because nobody configures a WAN by those
  // words.
  function ipModeLabel(w, pppoe) {
    if (pppoe) return "PPPoE";
    return (w.ip_mode || "").toLowerCase() === "static" ? "Static" : "DHCP";
  }

  function healthSentence(lb) {
    const fails = lb["lb_num-hosts-fail-interface-down"] || "1";
    const interval = lb["lb_ping-interval"] || "2";
    const timeout = lb["lb_ping-timeout"] || "2";
    const detect = lb["lb_ping-failure-detect-time"] || "5";
    return `Pings every ${interval}s, gives up after ${timeout}s, and declares the link down once ${fails} host(s) stay unreachable for ${detect}s.`;
  }

  function renderCard(w) {
    const port = portOf(w);
    const lb = lbOf(w);
    const bw = w.bandwidth_config || {};
    const pppoe = pppoeOf(port);
    const role = roleOf(w);

    const starlink = w.starlink_enable
      ? `<h3>Starlink</h3>
         ${readout([
           ["Dish address", w.starlink_dish_ip, "mono"],
           ["Dish mode", w.starlink_dish_mode],
           ["Dish port", w.starlink_dish_port, "mono"],
         ])}`
      : "";

    const pppoeBlock = pppoe
      ? `<h3>PPPoE</h3>
         ${readout([
           ["User name", pppoe.user],
           ["MTU", pppoe.mtu],
           ["MSS clamping", pppoe.mss_clamp ? "On" : "Off"],
           ["AC name", pppoe.ac_name || "-"],
           ["Service name", pppoe.service_name || "-"],
         ])}`
      : "";

    // A device that has never had a "wan-name" set prints no such leaf, so
    // in show-config fallback mode the name can be empty — fall back to the
    // physical port rather than rendering a headless card. "Change port"
    // still needs a real name and says so if one is missing.
    const title = w.name ? esc(w.name) : "Unnamed WAN";
    return `<h2>${title} <span class="wan-port">${esc(w.lan_intf)}</span>
        <span class="role-chip role-${role}">${esc(roleLabel(w))}</span>
        ${wanStatusHTML(w)}</h2>
      <div class="readout-cols">
        <div>
          <h3>Connection</h3>
          ${readout([
            ["Address", ipModeLabel(w, pppoe)],
            ["Source NAT", (w.source_nat || "").toLowerCase() === "enable" ? "On" : "Off"],
            ["Uplink", bw.uplink_bandwidth ? `${bw.uplink_bandwidth} Mbps` : "-"],
            ["Downlink", bw.downlink_bandwidth ? `${bw.downlink_bandwidth} Mbps` : "-"],
          ])}
        </div>
        <div>
          <h3>Connection check</h3>
          ${readout([
            ["Monitor hosts", (lb["lb_monitor-hosts"] || []).join(" ") || "none", "list"],
          ])}
          <p class="muted">${esc(healthSentence(lb))}</p>
        </div>
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
      <fieldset class="form-section">
        <legend>How this link gets its address</legend>
        <label>Address mode
          <select id="cfg-wan-mode">
            <option value="dhcp" ${currentMode === "dhcp" ? "selected" : ""}>DHCP</option>
            <option value="static" ${currentMode === "static" ? "selected" : ""}>Static</option>
            <option value="pppoe" ${currentMode === "pppoe" ? "selected" : ""}>PPPoE</option>
          </select>
        </label>
        <div id="cfg-wan-static-fields" class="field-grid" ${isStatic ? "" : "hidden"}>
          <label>IP address <input id="cfg-wan-ip" type="text" placeholder="e.g. 203.0.113.10"></label>
          <label>Subnet mask <input id="cfg-wan-mask" type="text" placeholder="e.g. 255.255.255.0"></label>
          <label>Gateway <input id="cfg-wan-gw" type="text" placeholder="e.g. 203.0.113.1"></label>
        </div>
        <div id="cfg-wan-pppoe-fields" ${isPPPoE ? "" : "hidden"}>
          <div class="field-grid">
            <label>User name <input id="cfg-wan-pppoe-user" type="text" value="${esc(pppoe ? pppoe.user : "")}"></label>
            <label>Password <input id="cfg-wan-pppoe-password" type="password"></label>
            <label>AC name (optional) <input id="cfg-wan-pppoe-ac" type="text" value="${esc(pppoe ? pppoe.ac_name || "" : "")}"></label>
            <label>Service name (optional) <input id="cfg-wan-pppoe-service" type="text" value="${esc(pppoe ? pppoe.service_name || "" : "")}"></label>
            <label>MTU (500-1492) <input id="cfg-wan-pppoe-mtu" type="number" min="500" max="1492" value="${pppoe ? pppoe.mtu : 1492}"></label>
          </div>
          <label class="check-row"><input id="cfg-wan-pppoe-mss" type="checkbox" ${pppoe && pppoe.mss_clamp ? "checked" : ""}> TCP MSS clamping</label>
          ${pppoe ? '<p class="muted">The stored password cannot be read back, so it must be re-entered every time you save this form, even if it has not changed.</p>' : ""}
        </div>
      </fieldset>

      <fieldset class="form-section">
        <legend>What this link does for load balancing</legend>
        <label>Role
          <select id="cfg-wan-lbmode">
            <option value="shared" ${lbMode === "shared" ? "selected" : ""}>Carry traffic</option>
            <option value="backup" ${lbMode === "backup" ? "selected" : ""}>Stand by as backup</option>
            <option value="disabled" ${lbMode === "disabled" ? "selected" : ""}>Stay out of load balancing</option>
          </select>
        </label>
        <div id="cfg-wan-share-field" ${lbMode === "shared" ? "" : "hidden"}>
          <label>Share of outbound traffic (%)
            <input id="cfg-wan-share" type="number" min="0" max="100" value="${esc(lb["lb_traffic-share-percentage"] || "")}">
          </label>
          <p class="muted">The device splits traffic by the ratio between the links that carry it. With one such link, this is 100%.</p>
        </div>
        <div id="cfg-wan-priority-field" ${lbMode === "backup" ? "" : "hidden"}>
          <label>Takeover order
            <input id="cfg-wan-priority" type="number" min="0" max="10" value="${esc(lb["lb_backup-link-priority"] || "0")}">
          </label>
          <p class="muted">0 takes over first, 10 last.</p>
        </div>
      </fieldset>

      <fieldset class="form-section">
        <legend>How the device decides this link is down</legend>
        <label>Monitor hosts (comma separated)
          <input id="cfg-wan-hosts" type="text" value="${esc((lb["lb_monitor-hosts"] || []).join(","))}">
        </label>
        <div class="field-grid">
          <label>Failed hosts
            <input id="cfg-wan-numfail" type="number" min="1" value="${esc(lb["lb_num-hosts-fail-interface-down"] || "1")}">
          </label>
          <label>Detect (s)
            <input id="cfg-wan-faildetect" type="number" min="5" max="60" value="${esc(lb["lb_ping-failure-detect-time"] || "5")}">
          </label>
          <label>Interval (s)
            <input id="cfg-wan-pinginterval" type="number" min="2" max="10" value="${esc(lb["lb_ping-interval"] || "2")}">
          </label>
          <label>Timeout (s)
            <input id="cfg-wan-pingtimeout" type="number" min="1" max="10" value="${esc(lb["lb_ping-timeout"] || "2")}">
          </label>
        </div>
        <p class="muted">Detect 5-60 s, interval 2-10 s, timeout 1-10 s.</p>
      </fieldset>

      <fieldset class="form-section">
        <legend>Link speed the device shapes to</legend>
        <div class="field-grid">
          <label>Uplink (Mbps) <input id="cfg-wan-up" type="number" min="1" value="${esc(bw.uplink_bandwidth || "")}"></label>
          <label>Downlink (Mbps) <input id="cfg-wan-down" type="number" min="1" value="${esc(bw.downlink_bandwidth || "")}"></label>
        </div>
      </fieldset>

      <p class="warn">WAN changes go through the safe-apply path: the device must still accept a fresh connection afterwards, and the change is undone within 60 seconds unless you confirm it. If a change cuts off access entirely, that undo cannot reach the device either — but the change is not saved until you confirm, so power-cycling the device restores the previous configuration.</p>
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
      const newPriority = parseInt(el.querySelector("#cfg-wan-priority").value, 10) || 0;
      const priorityChanged =
        newLBMode === "backup" && String(newPriority) !== String(lb["lb_backup-link-priority"] || "0");
      if (newLBMode !== lbMode || priorityChanged) {
        const req = { action: "load_balance_mode", port, lb_mode: newLBMode };
        if (newLBMode === "backup") req.priority = newPriority;
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
      modalEl.querySelector("#cfg-wan-share-field").hidden = e.target.value !== "shared";
    });
    modalEl.classList.add("modal-wide");
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
      <p class="warn">This reassigns two physical ports at once, through the safe-apply path: the device must still accept a fresh connection afterwards, and both ports are restored to their exact prior config within 60 seconds unless you confirm. If the change cuts off access entirely, that undo cannot reach the device either — but nothing is saved until you confirm, so power-cycling restores the previous configuration. Whether "type lan" fully clears the old port's WAN-only settings is unconfirmed; if this port looks odd afterward, its prior config is one undo away.</p>
      <div id="cfg-chg-outcome"></div>
    `;
    const modalEl = openModal(`Change port for ${w.name || w.lan_intf}`, body, async (el) => {
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
