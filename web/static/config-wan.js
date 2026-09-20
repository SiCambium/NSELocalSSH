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
    // Promoting a port is an action, not a subject. Given an <h2> and a
    // plate of its own it opened the page as an equal of Load balancing,
    // which is what the page is actually about, and pushed the links
    // themselves below the fold. It keeps its explanation and its place at
    // the top, at the weight of a toolbar rather than a section.
    const promote = `<div class="port-roles">
      <span class="legend">Port roles</span>
      <p>Every port is a LAN port until it is promoted. Promoting one moves it out of the LAN and gives it its own uplink.</p>
      ${addBtn}
    </div>`;
    panel.innerHTML = `${promote}${cards}${loadBalanceSummary(wans)}`;
    panel.querySelectorAll(".row-edit[data-port]").forEach((btn) => {
      btn.addEventListener("click", () => editWAN(parseInt(btn.dataset.port, 10)));
    });
    panel.querySelectorAll("[data-change-port]").forEach((btn) => {
      btn.addEventListener("click", () => changePort(parseInt(btn.dataset.changePort, 10)));
    });
    const addWanBtn = document.getElementById("add-wan-btn");
    if (addWanBtn) addWanBtn.addEventListener("click", addWAN);
    wireEditor();
  }

  // --- Load balancing ----------------------------------------------------
  // Load balancing is the reason most people open this page, and it was
  // the one thing the page did not show: each WAN card carried its own
  // "lb_mode" and "traffic share %" as two more rows of CLI vocabulary,
  // and nothing anywhere said which link the traffic actually leaves by,
  // or what happens when it fails. That is a property of the set of WANs,
  // not of any one of them, so it is stated once, below the cards, in the
  // order someone asks it: what carries traffic now, what takes over, and
  // what is out of the rotation. It sits after the links because it is
  // about them: the summary and the split editor both name links the
  // reader has to have met first.

  function lbOf(w) {
    return w.load_balance_config || {};
  }

  function shareOf(w) {
    const n = parseInt(lbOf(w)["lb_traffic-share-percentage"], 10);
    return Number.isNaN(n) ? 0 : n;
  }

  // What a link is really getting, once the device has treated the shares
  // as a ratio. Equal to the raw share whenever the set totals 100.
  function effectiveShare(w, total) {
    if (!total) return 0;
    return Math.round((shareOf(w) / total) * 100);
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

  // The table below is the state of load balancing, read from the device
  // and editable in place, so this section carries no separate reading of
  // it. A sentence naming the carrying link, a bar drawn to its share and
  // chips listing the standby links each restated a row of that table in
  // another form, and the reader had to check which one was current.
  function loadBalanceSummary(wans) {
    if (!wans.length) return "";
    const active = wans.filter((w) => roleOf(w) === "active");
    const total = active.reduce((sum, w) => sum + shareOf(w), 0);

    // The one thing the table cannot say. A device can be holding a set
    // that comes to more than 100 -- written by cnMaestro, or by the CLI
    // -- and the device divides by the ratio regardless, so a row reading
    // 50% is really getting a third. The rows show what is stored; this
    // says what it means until someone corrects it.
    const warn =
      active.length > 1 && total > 100
        ? `<p class="warn">These shares come to ${total}%. The device divides traffic by the ratio between
             them, so ${active
               .map((w) => `${esc(w.name)} is really getting ${effectiveShare(w, total)}%`)
               .join(" and ")}.</p>`
        : "";

    // Role and share are one decision, so they are made in one place.
    // Splitting them, role on each WAN's own card and share here, meant
    // neither view was complete: a share typed on a card could only be
    // judged against links that card could not show. That is how a device
    // ends up dividing traffic 150 ways.
    //
    // Every link gets a row whatever its role, because taking one out of
    // the rotation and giving its traffic to another is a single change,
    // and here it is a single save.
    const editor = wans.length
      ? `<div class="lb-editor" id="lb-edit">
           <table class="flat lb-table">
             <thead><tr><th>Link</th><th>Role</th><th class="num">Share</th>
             <th>Takeover order <span class="th-note">0 first, 10 last</span></th></tr></thead>
             <tbody>${wans
               .map((w) => {
                 const role = roleOf(w);
                 const port = portOf(w);
                 return `<tr data-lb-row="${port}">
                   <td><strong>${esc(w.name || w.lan_intf)}</strong>
                       <span class="muted">${esc(w.lan_intf)}</span></td>
                   <td>
                     <select data-lb-role="${port}" data-lb-saved-role="${role}">
                       <option value="active"${role === "active" ? " selected" : ""}>Carry traffic</option>
                       <option value="backup"${role === "backup" ? " selected" : ""}>Stand by as backup</option>
                       <option value="off"${role === "off" ? " selected" : ""}>Out of rotation</option>
                     </select>
                   </td>
                   <td class="num">
                     <span class="lb-num lb-cell-share"${role === "active" ? "" : " hidden"}>
                       <input type="number" min="0" max="100" step="1" inputmode="numeric"
                              aria-label="Share of outbound traffic for ${esc(w.name || w.lan_intf)}"
                              data-lb-port="${port}" data-lb-saved="${shareOf(w)}" value="${shareOf(w)}">
                       <span class="lb-num-unit">%</span>
                     </span>
                     <span class="muted lb-cell-dash"${role === "active" ? " hidden" : ""}>&mdash;</span>
                   </td>
                   <td>
                     <span class="lb-num lb-cell-prio"${role === "backup" ? "" : " hidden"}>
                       <input type="number" min="0" max="10" step="1" inputmode="numeric"
                              aria-label="Takeover order for ${esc(w.name || w.lan_intf)}"
                              data-lb-prio="${port}" data-lb-saved-prio="${priorityOf(w)}"
                              value="${priorityOf(w)}">
                     </span>
                     <span class="muted lb-cell-dash"${role === "backup" ? " hidden" : ""}>&mdash;</span>
                   </td>
                 </tr>`;
               })
               .join("")}</tbody>
           </table>
           <div class="lb-actions">
             <span class="lb-edit-total" id="lb-edit-total"></span>
             <button type="button" class="row-edit" id="lb-even">Split evenly</button>
             <button type="button" class="row-edit primary" id="lb-save" disabled>Save load balancing</button>
           </div>
           <div class="lb-edit-outcome" id="lb-outcome"></div>
         </div>`
      : "";

    return `<h2 class="lb-heading">Load balancing</h2>
      ${warn}
      ${editor}`;
  }

  // --- The load balancing editor ------------------------------------

  const MODE_OF = { active: "shared", backup: "backup", off: "disabled" };

  function lbRows() {
    return Array.from(document.querySelectorAll("#lb-edit [data-lb-row]"));
  }

  function roleSelect(row) {
    return row.querySelector("[data-lb-role]");
  }

  function shareInput(row) {
    return row.querySelector("[data-lb-port]");
  }

  function activeInputs() {
    return lbRows()
      .filter((r) => roleSelect(r).value === "active")
      .map(shareInput);
  }

  // A row shows the one number its role takes and nothing else, so the
  // table never offers a share for a link that carries no traffic or a
  // takeover order for one that is not standing by.
  function syncRow(row) {
    const role = roleSelect(row).value;
    row.querySelector(".lb-cell-share").hidden = role !== "active";
    row.querySelector(".lb-cell-prio").hidden = role !== "backup";
    const dashes = row.querySelectorAll(".lb-cell-dash");
    dashes[0].hidden = role === "active";
    dashes[1].hidden = role === "backup";
  }

  // Moves the difference into the other carrying links. Proportionally,
  // so an established 70/30 pair keeps its proportion when a third link
  // takes a slice, and evenly when there is no proportion to keep. The
  // last field absorbs the rounding so the set lands on exactly 100.
  function absorb(fields, changed) {
    const value = Math.min(100, Math.max(0, parseInt(changed.value, 10) || 0));
    changed.value = String(value);
    const others = fields.filter((f) => f !== changed);
    if (!others.length) {
      changed.value = "100";
      return;
    }
    const remainder = 100 - value;
    const base = others.reduce((sum, f) => sum + (parseInt(f.value, 10) || 0), 0);
    let spent = 0;
    others.forEach((f, i) => {
      let share;
      if (i === others.length - 1) share = remainder - spent;
      else if (base > 0) share = Math.round(((parseInt(f.value, 10) || 0) / base) * remainder);
      else share = Math.round(remainder / others.length);
      share = Math.min(100, Math.max(0, share));
      spent += share;
      f.value = String(share);
    });
  }

  function spreadEvenly(fields) {
    const each = Math.floor(100 / fields.length);
    fields.forEach((f, i) => {
      f.value = String(i === fields.length - 1 ? 100 - each * (fields.length - 1) : each);
    });
  }

  // Everything the editor reports follows from the rows, so it is read
  // from them in one place: the running total, whether the arrangement
  // can be saved, and whether anything has actually changed.
  function refreshEditor() {
    const rows = lbRows();
    const fields = activeInputs();
    const total = fields.reduce((sum, f) => sum + (parseInt(f.value, 10) || 0), 0);
    const changed = rows.some((r) => {
      const sel = roleSelect(r);
      if (sel.value !== sel.dataset.lbSavedRole) return true;
      if (sel.value === "active") {
        const f = shareInput(r);
        return (parseInt(f.value, 10) || 0) !== (parseInt(f.dataset.lbSaved, 10) || 0);
      }
      if (sel.value === "backup") {
        const f = r.querySelector("[data-lb-prio]");
        return (parseInt(f.value, 10) || 0) !== (parseInt(f.dataset.lbSavedPrio, 10) || 0);
      }
      return false;
    });

    const totalEl = document.getElementById("lb-edit-total");
    const evenBtn = document.getElementById("lb-even");
    const saveBtn = document.getElementById("lb-save");
    let blocked = "";
    if (!fields.length) blocked = "At least one link has to carry traffic.";
    else if (total > 100) blocked = `The shares add up to ${total}%, which is more than 100%.`;

    if (totalEl) {
      totalEl.textContent =
        blocked || (fields.length > 1 ? `Shares add up to ${total}%` : "");
      totalEl.classList.toggle("bad", Boolean(blocked));
    }
    if (evenBtn) evenBtn.hidden = fields.length < 2;
    if (saveBtn) saveBtn.disabled = Boolean(blocked) || !changed;
  }

  function wireEditor() {
    const rows = lbRows();
    if (!rows.length) return;

    rows.forEach((row) => {
      roleSelect(row).addEventListener("change", () => {
        syncRow(row);
        // A link joining or leaving the rotation changes what the rest
        // are dividing, so the shares are re-spread rather than left to
        // add up to whatever they happened to before.
        const fields = activeInputs();
        if (fields.length) spreadEvenly(fields);
        refreshEditor();
      });
      const share = shareInput(row);
      if (share) {
        share.addEventListener("input", () => {
          absorb(activeInputs(), share);
          refreshEditor();
        });
      }
      const prio = row.querySelector("[data-lb-prio]");
      if (prio) prio.addEventListener("input", refreshEditor);
    });

    const evenBtn = document.getElementById("lb-even");
    if (evenBtn) {
      evenBtn.addEventListener("click", () => {
        spreadEvenly(activeInputs());
        refreshEditor();
      });
    }

    const saveBtn = document.getElementById("lb-save");
    if (saveBtn) {
      saveBtn.addEventListener("click", async () => {
        const links = lbRows().map((r) => {
          const role = roleSelect(r).value;
          const link = { port: parseInt(r.dataset.lbRow, 10), mode: MODE_OF[role] };
          if (role === "active") link.percent = parseInt(shareInput(r).value, 10) || 0;
          if (role === "backup") link.priority = parseInt(r.querySelector("[data-lb-prio]").value, 10) || 0;
          return link;
        });
        saveBtn.disabled = true;
        const outcomeEl = document.getElementById("lb-outcome");
        try {
          const outcome = await postJSON("/api/config/wan", { action: "load_balance", links });
          await renderOutcome(outcomeEl, outcome);
          await load();
        } catch (e) {
          outcomeEl.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
          saveBtn.disabled = false;
        }
      });
    }

    refreshEditor();
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

      <p class="muted">This link's role in load balancing, its share of outbound traffic and its
        takeover order are set together under Load balancing, where the other links are visible.</p>


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
