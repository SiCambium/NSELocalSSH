// Network configuration section: VLANs and physical LAN ports. Read-only
// by default — every row shows current values as plain text; an explicit
// Edit (or Add VLAN) button is the only place values become editable.
(function () {
  const { esc, postJSON, getJSON, fetchLicense, licenseGate, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;
  let license = null;

  async function load() {
    const panel = document.getElementById("config-network-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      const [data, lic] = await Promise.all([getJSON("/api/config/network"), fetchLicense()]);
      cache = data;
      license = lic;
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  // Speed and duplex appear in `show config` only when they have been
  // FORCED. An auto-negotiating port emits no speed/duplex/advertise lines
  // at all, so reading the config alone showed every port as "auto" / "-"
  // even while the link was up and negotiated. These cells prefer the
  // forced value when there is one and fall back to the negotiated state
  // from `show interface brief`, labelling which is which.

  function linkFor(iface) {
    return (cache.link || {})[String(iface || "").toLowerCase()] || {};
  }

  // The device writes "N/A" into every column of a down port.
  function liveValue(v) {
    return !v || v === "N/A" ? "" : v;
  }

  function speedCell(p) {
    if (p.speed) return `${esc(p.speed)} Mbps <span class="muted">forced</span>`;
    const live = liveValue(linkFor(p.interface).speed);
    return live ? `${esc(live)} <span class="muted">negotiated</span>` : "-";
  }

  function duplexCell(p) {
    if (p.duplex) return `${esc(p.duplex)} <span class="muted">forced</span>`;
    const live = liveValue(linkFor(p.interface).duplex);
    if (!live) return "-";
    const pretty = live.charAt(0).toUpperCase() + live.slice(1).toLowerCase();
    return `${esc(pretty)} <span class="muted">negotiated</span>`;
  }

  // "Not set" says nothing about what the port is actually doing, so the
  // negotiated state is shown alongside it. Reads as empty on a down port,
  // where the device reports N/A for every column.
  function linkStateHintHTML(iface) {
    const l = linkFor(iface);
    const speed = liveValue(l.speed);
    const duplex = liveValue(l.duplex);
    if (!speed && !duplex) {
      return `<p class="muted">Link is down, so there is no negotiated speed or duplex to report.</p>`;
    }
    const pretty = duplex ? duplex.charAt(0).toUpperCase() + duplex.slice(1).toLowerCase() : "unknown";
    return `<p class="muted">Currently negotiated: ${esc(speed || "unknown")}, ${esc(pretty)} duplex. Leaving these unset keeps auto-negotiation, which is what the device does today.</p>`;
  }

  // Config is read from `show config`, which has no leaf for a VLAN's
  // label — that only exists in cloud-json-config, and only on a device
  // that has been cloud-managed. Fall back to the id so a row is never
  // blank; everything else in this table comes from the live config.
  function vlanName(v) {
    if (v.name) return esc(v.name);
    return `<span class="muted">VLAN ${v.vlan_id}</span>`;
  }

  function render() {
    const panel = document.getElementById("config-network-panel");
    const vlans = cache.vlans || [];
    const ports = cache.ports || [];

    const vlanRows = vlans
      .map((v) => {
        const scanBadge = licenseGate(
          license,
          "port_scan",
          v.port_scan ? '<span class="badge-on">On</span>' : '<span class="badge-off">Off</span>'
        );
        return `<tr>
          <td>${v.vlan_id}</td>
          <td>${vlanName(v)}</td>
          <td class="mono">${esc(v.ip_addr)}</td>
          <td class="mono">${esc(v.subnet_mask)}</td>
          <td>${v.management_access === "enable" ? "Enabled" : "Disabled"}</td>
          <td>${scanBadge}</td>
          <td><button type="button" class="row-edit" data-vlan="${v.vlan_id}">Edit</button></td>
        </tr>`;
      })
      .join("");

    const lanPorts = ports.filter((p) => p.type !== "wan");
    const portRows = lanPorts
      .map(
        (p) => `<tr>
          <td>${esc(p.interface)}</td>
          <td>${esc(p.mode || "-")}</td>
          <td>${esc(p.mode === "trunk" ? p.native_vlan || "-" : p.access_vlan || "-")}</td>
          <td>${esc(p.allowed_vlans || "-")}</td>
          <td>${speedCell(p)}</td>
          <td>${duplexCell(p)}</td>
          <td><button type="button" class="row-edit" data-port="${esc(p.interface)}">Edit</button></td>
        </tr>`
      )
      .join("");

    panel.innerHTML = `
      <h2>VLANs</h2>
      <p><button type="button" class="row-edit" id="add-vlan-btn">Add VLAN</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Name</th><th>IP Address</th><th>Subnet Mask</th><th>Management Access</th><th>Vulnerability Scan</th><th></th></tr></thead>
        <tbody>${vlanRows || '<tr><td colspan="7" class="muted">No VLANs found.</td></tr>'}</tbody>
      </table></div>

      <h2>LAN Ports</h2>
      <p class="muted">WAN ports aren't shown here — manage them from the WAN tab instead.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>Port</th><th>Mode</th><th>VLAN</th><th>Allowed VLANs</th><th>Speed</th><th>Duplex</th><th></th></tr></thead>
        <tbody>${portRows || '<tr><td colspan="7" class="muted">No LAN ports found.</td></tr>'}</tbody>
      </table></div>
    `;

    panel.querySelectorAll("[data-vlan]").forEach((btn) => {
      btn.addEventListener("click", () => editVLAN(parseInt(btn.dataset.vlan, 10)));
    });
    panel.querySelectorAll("[data-port]").forEach((btn) => {
      btn.addEventListener("click", () => editPort(btn.dataset.port));
    });
    document.getElementById("add-vlan-btn").addEventListener("click", addVLAN);
  }

  function editPort(iface) {
    const p = (cache.ports || []).find((x) => x.interface === iface);
    if (!p) return;
    const port = parseInt(/^eth(\d+)$/.exec(iface)[1], 10);
    const mode = p.mode === "trunk" ? "trunk" : "access";
    const vlanOptions = (cache.vlans || [])
      .map(
        (v) =>
          `<option value="${v.vlan_id}" ${String(v.vlan_id) === p.access_vlan ? "selected" : ""}>${
            v.name ? `${v.vlan_id} (${esc(v.name)})` : v.vlan_id
          }</option>`
      )
      .join("");
    const body = `
      <label>Mode
        <select id="cfg-port-mode">
          <option value="access" ${mode === "access" ? "selected" : ""}>Access</option>
          <option value="trunk" ${mode === "trunk" ? "selected" : ""}>Trunk</option>
        </select>
      </label>
      <div id="cfg-port-access-fields" ${mode === "access" ? "" : "hidden"}>
        <label>Access VLAN
          <select id="cfg-port-access-vlan">${vlanOptions}</select>
        </label>
      </div>
      <div id="cfg-port-trunk-fields" ${mode === "trunk" ? "" : "hidden"}>
        <label>Native VLAN <input id="cfg-port-native-vlan" type="text" value="${esc(p.native_vlan || "1")}"></label>
        <label>Allowed VLANs (comma separated) <input id="cfg-port-allowed-vlans" type="text" value="${esc(p.allowed_vlans || "")}"></label>
      </div>
      <p class="warn">Changing a LAN port's VLAN assignment can disconnect whatever is plugged into it — or, if this port is carrying the session doing the editing (e.g. a direct connection to the 172.23.0.1 local UI), lock you out. This change is applied through the safe-apply path: it's verified reachable over a fresh connection before it's kept, and rolled back automatically if not confirmed within 60 seconds.</p>
      <label>Speed
        <select id="cfg-port-speed">
          <option value="auto" ${(!p.speed || p.speed === "auto") ? "selected" : ""}>Auto</option>
          <option value="100" ${p.speed === "100" ? "selected" : ""}>100 Mbps (forced)</option>
          <option value="10" ${p.speed === "10" ? "selected" : ""}>10 Mbps (forced)</option>
        </select>
      </label>
      <label>Duplex
        <select id="cfg-port-duplex">
          <option value="" ${!p.duplex ? "selected" : ""}>Not set (auto-negotiate)</option>
          <option value="full" ${p.duplex === "full" ? "selected" : ""}>Full</option>
          <option value="half" ${p.duplex === "half" ? "selected" : ""}>Half</option>
        </select>
      </label>
      ${linkStateHintHTML(p.interface)}
      <label>Advertise (auto-negotiation)
        <select id="cfg-port-advertise">
          <option value="auto" ${(!p.advertise || p.advertise === "auto") ? "selected" : ""}>Auto</option>
          <option value="1000" ${p.advertise === "1000" ? "selected" : ""}>1000 Mbps</option>
          <option value="100" ${p.advertise === "100" ? "selected" : ""}>100 Mbps</option>
          <option value="10" ${p.advertise === "10" ? "selected" : ""}>10 Mbps</option>
        </select>
      </label>
      <p class="muted">"Speed" forces the link rate — it only offers 10/100/Auto, not gigabit, per this device's own CLI. "Advertise" controls what's offered during auto-negotiation and does include 1000 Mbps. Forcing a mismatched speed/duplex against the far end can badly degrade or drop the link.</p>
      <label class="check-row"><input id="cfg-port-enabled" type="checkbox" ${!p.shutdown ? "checked" : ""}> Port enabled</label>
      <div id="cfg-port-outcome"></div>
    `;
    const modalEl = openModal(`Edit ${iface}`, body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-port-outcome");
      const newMode = el.querySelector("#cfg-port-mode").value;
      const req = { action: "port_switchport", port, mode: newMode };
      if (newMode === "access") {
        req.access_vlan = el.querySelector("#cfg-port-access-vlan").value;
      } else {
        req.native_vlan = el.querySelector("#cfg-port-native-vlan").value.trim();
        req.allowed_vlans = el.querySelector("#cfg-port-allowed-vlans").value.trim();
        if (!req.native_vlan || !req.allowed_vlans) throw new Error("Native VLAN and allowed VLANs are required for trunk mode");
      }
      const outcome = await postJSON("/api/config/network", req);
      await renderOutcome(outcomeEl, outcome);

      const speed = el.querySelector("#cfg-port-speed").value;
      const duplex = el.querySelector("#cfg-port-duplex").value;
      const advertise = el.querySelector("#cfg-port-advertise").value;
      if (speed !== (p.speed || "auto") || duplex !== (p.duplex || "") || advertise !== (p.advertise || "auto")) {
        const speedOutcome = await postJSON("/api/config/network", { action: "port_speed", port, speed, duplex, advertise });
        await renderOutcome(outcomeEl, speedOutcome);
      }

      const enabled = el.querySelector("#cfg-port-enabled").checked;
      if (enabled !== !p.shutdown) {
        const shutdownOutcome = await postJSON("/api/config/network", { action: "port_shutdown", port, enabled });
        await renderOutcome(outcomeEl, shutdownOutcome);
      }

      await load();
    });
    modalEl.querySelector("#cfg-port-mode").addEventListener("change", (e) => {
      modalEl.querySelector("#cfg-port-access-fields").hidden = e.target.value !== "access";
      modalEl.querySelector("#cfg-port-trunk-fields").hidden = e.target.value !== "trunk";
    });
  }

  // dhcpScopeFieldsHTML renders the shared start/end/router/dns/domain/
  // lease inputs used by both the "Add VLAN" and "Edit VLAN" modals.
  function dhcpScopeFieldsHTML(prefix, d) {
    return `
      <label>DHCP start address <input id="${prefix}-start" type="text" value="${esc(d.start)}"></label>
      <label>DHCP end address <input id="${prefix}-end" type="text" value="${esc(d.end)}"></label>
      <label>Router (default gateway) <input id="${prefix}-router" type="text" value="${esc(d.router)}"></label>
      <label>Primary DNS <input id="${prefix}-dns" type="text" value="${esc(d.dns)}"></label>
      <label>Secondary DNS (optional) <input id="${prefix}-dns2" type="text" value="${esc(d.dnsSecondary || "")}"></label>
      <label>Domain (optional) <input id="${prefix}-domain" type="text" value="${esc(d.domain)}"></label>
      <div class="field-group">
        <span class="field-legend">Lease time</span>
        <span class="field-row">
          <label>Days <input id="${prefix}-lease-d" type="number" min="0" value="${d.leaseDays}"></label>
          <label>Hours <input id="${prefix}-lease-h" type="number" min="0" max="23" value="${d.leaseHours}"></label>
          <label>Minutes <input id="${prefix}-lease-m" type="number" min="0" max="59" value="${d.leaseMins}"></label>
        </span>
      </div>
      <label>Custom DHCP options (one per line, "&lt;code&gt; &lt;value&gt;" or "&lt;code&gt; IP|text &lt;value&gt;", e.g. "15 example.local" or "43 IP 192.168.200.1")
        <textarea id="${prefix}-options" rows="3" style="background:var(--bg-2);color:var(--text);border:1px solid var(--line);padding:8px 10px;font:inherit;text-transform:none">${esc(d.optionsText || "")}</textarea>
      </label>`;
  }

  function readDHCPScope(modalEl, prefix) {
    const val = (id) => modalEl.querySelector(`#${prefix}-${id}`).value.trim();
    const num = (id) => parseInt(modalEl.querySelector(`#${prefix}-${id}`).value, 10) || 0;
    const options = val("options")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        // "<code> <value>" or "<code> <type> <value>". The device prints
        // the typed form; the untyped one is accepted and the backend
        // infers the token, so an existing entry can be edited without
        // knowing the convention.
        const parts = line.split(/\s+/);
        const code = parseInt(parts[0], 10);
        if (Number.isNaN(code) || parts.length < 2) return null;
        let type = "";
        let rest = parts.slice(1);
        if (rest.length > 1 && (rest[0] === "IP" || rest[0] === "text")) {
          type = rest[0];
          rest = rest.slice(1);
        }
        const value = rest.join(" ").trim();
        return value ? { code, type, value } : null;
      })
      .filter(Boolean);
    return {
      start_ip: val("start"),
      end_ip: val("end"),
      router: val("router"),
      dns: val("dns"),
      dns_secondary: val("dns2"),
      domain: val("domain"),
      lease_days: num("lease-d"),
      lease_hours: num("lease-h"),
      lease_mins: num("lease-m"),
      options,
    };
  }

  // formatOptionsText turns the pool's options back into the textarea
  // form, keeping the device's own type token so a round trip through
  // this form does not silently rewrite it.
  function formatOptionsText(options) {
    return (options || [])
      .map((o) => {
        if (!o || o.code == null || o.value == null) return null;
        return o.type ? `${o.code} ${o.type} ${o.value}` : `${o.code} ${o.value}`;
      })
      .filter(Boolean)
      .join("\n");
  }

  // --- MAC binding list -------------------------------------------------
  // Mirrors cnMaestro, which nests this under a VLAN's DHCP tab. On the
  // device the reservations actually live on the DHCP *pool*, not the VLAN
  // SVI; the backend does the VLAN-to-pool lookup so the UI can stay
  // VLAN-shaped.
  //
  // Add and Remove apply immediately rather than on the modal's Save,
  // because each reservation is its own CLI line and the device reports
  // per-line errors (a duplicate MAC, say) that belong next to the row
  // that caused them.

  function bindingsFor(vlanID) {
    return (cache.bindings || {})[String(vlanID)] || [];
  }

  function macBindingRowsHTML(bindings) {
    if (!bindings.length) {
      return `<tr><td colspan="4" class="muted">No reservations on this VLAN.</td></tr>`;
    }
    return bindings
      .map(
        (b) => `<tr>
          <td class="mono">${esc(b.mac)}</td>
          <td class="mono">${esc(b.ip)}</td>
          <td>${esc(b.description || "-")}</td>
          <td><button type="button" class="row-edit" data-unbind-mac="${esc(b.mac)}" data-unbind-ip="${esc(b.ip)}">Remove</button></td>
        </tr>`
      )
      .join("");
  }

  function macBindingSectionHTML(bindings) {
    return `
      <h3>MAC binding list</h3>
      <p class="muted">DHCP reservations for this VLAN. The address must be inside the VLAN's subnet and outside the DHCP range above — the device accepts addresses that are neither, and silently never hands them out. Descriptions come from cnMaestro and are read-only: the device CLI has no command that sets them.</p>
      <table class="table">
        <thead><tr><th>MAC</th><th>IP address</th><th>Description</th><th></th></tr></thead>
        <tbody id="cfg-bind-rows">${macBindingRowsHTML(bindings)}</tbody>
      </table>
      <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin-top:8px">
        <label style="flex:1 1 200px;margin:0">MAC
          <input id="cfg-bind-mac" type="text" placeholder="aa:bb:cc:dd:ee:ff" style="text-transform:none">
        </label>
        <label style="flex:1 1 160px;margin:0">IP address
          <input id="cfg-bind-ip" type="text" placeholder="192.168.40.200" style="text-transform:none">
        </label>
        <button type="button" class="row-edit" id="cfg-bind-add">Add</button>
      </div>
      <div id="cfg-bind-outcome"></div>`;
  }

  function wireMACBindings(vlanID) {
    const modalEl = document.querySelector(".modal");
    if (!modalEl) return;
    const outcomeEl = modalEl.querySelector("#cfg-bind-outcome");
    const rowsEl = modalEl.querySelector("#cfg-bind-rows");

    const post = async (body) => {
      outcomeEl.innerHTML = "";
      try {
        const outcome = await postJSON("/api/config/network", body);
        await renderOutcome(outcomeEl, outcome);
        // Re-read rather than patching locally: the device is the only
        // authority on the stored MAC spelling, which a later Remove has
        // to match exactly.
        cache = await getJSON("/api/config/network");
        rowsEl.innerHTML = macBindingRowsHTML(bindingsFor(vlanID));
        wireRemove();
        render();
      } catch (e) {
        outcomeEl.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
      }
    };

    const wireRemove = () => {
      rowsEl.querySelectorAll("[data-unbind-mac]").forEach((btn) => {
        btn.addEventListener("click", () =>
          post({
            action: "mac_bind_delete",
            vlan_id: vlanID,
            mac: btn.dataset.unbindMac,
            bind_ip: btn.dataset.unbindIp,
          })
        );
      });
    };

    wireRemove();
    modalEl.querySelector("#cfg-bind-add").addEventListener("click", () => {
      const mac = modalEl.querySelector("#cfg-bind-mac").value.trim();
      const ip = modalEl.querySelector("#cfg-bind-ip").value.trim();
      if (!mac || !ip) {
        outcomeEl.innerHTML = `<p class="apply-error">Enter both a MAC address and an IP address.</p>`;
        return;
      }
      post({ action: "mac_bind_add", vlan_id: vlanID, mac, bind_ip: ip });
    });
  }

  function editVLAN(vlanID) {
    const v = (cache.vlans || []).find((x) => x.vlan_id === vlanID);
    if (!v) return;
    const dp = v.dhcp_pool_config || {};
    const dhcp = {
      start: dp.dhcp_pool_start_address || "",
      end: dp.dhcp_pool_end_address || "",
      router: v.ip_addr || "",
      dns: dp.dhcp_pool_primary_dns_server || "",
      dnsSecondary: dp.dhcp_pool_secondary_dns_server || "",
      domain: "",
      leaseDays: dp.dhcp_pool_lease_time_day || 0,
      leaseHours: dp.dhcp_pool_lease_time_hour ?? 2,
      leaseMins: dp.dhcp_pool_lease_time_minute || 0,
      optionsText: formatOptionsText(dp.dhcp_options),
    };
    const body = `
      <label>IP address
        <input id="cfg-vlan-ip" type="text" value="${esc(v.ip_addr)}">
      </label>
      <label>Subnet mask
        <input id="cfg-vlan-mask" type="text" value="${esc(v.subnet_mask)}">
      </label>
      <label class="check-row">
        <input id="cfg-vlan-mgmt" type="checkbox" ${v.management_access === "enable" ? "checked" : ""}>
        Management access
      </label>
      <p class="warn">Changing management access on the VLAN carrying this session can lock you out. This change is applied through the safe-apply path: it's verified reachable over a fresh connection before it's kept, and rolled back automatically if not confirmed within 60 seconds.</p>
      <h3>DHCP scope</h3>
      ${dhcpScopeFieldsHTML("cfg-vlan-dhcp", dhcp)}
      ${macBindingSectionHTML(bindingsFor(vlanID))}
      <div id="cfg-vlan-outcome"></div>
    `;
    openModal(v.name ? `Edit VLAN ${vlanID} (${v.name})` : `Edit VLAN ${vlanID}`, body, async (modalEl) => {
      const ip = modalEl.querySelector("#cfg-vlan-ip").value.trim();
      const mask = modalEl.querySelector("#cfg-vlan-mask").value.trim();
      const mgmt = modalEl.querySelector("#cfg-vlan-mgmt").checked;
      const outcomeEl = modalEl.querySelector("#cfg-vlan-outcome");

      if (ip !== v.ip_addr || mask !== v.subnet_mask) {
        const outcome = await postJSON("/api/config/network", { action: "vlan_ip", vlan_id: vlanID, ip, mask });
        await renderOutcome(outcomeEl, outcome);
      }
      if (mgmt !== (v.management_access === "enable")) {
        const outcome = await postJSON("/api/config/network", {
          action: "vlan_management_access",
          vlan_id: vlanID,
          management_access: mgmt,
        });
        await renderOutcome(outcomeEl, outcome);
      }

      const scope = readDHCPScope(modalEl, "cfg-vlan-dhcp");
      const optionsChanged =
        JSON.stringify(scope.options) !==
        JSON.stringify(
          (dhcp.optionsText || "")
            .split("\n")
            .map((l) => l.trim())
            .filter(Boolean)
            .map((l) => {
              const sp = l.indexOf(" ");
              return { code: parseInt(l.slice(0, sp), 10), value: l.slice(sp + 1) };
            })
        );
      const changed =
        scope.start_ip !== dhcp.start ||
        scope.end_ip !== dhcp.end ||
        scope.router !== dhcp.router ||
        scope.dns !== dhcp.dns ||
        scope.dns_secondary !== dhcp.dnsSecondary ||
        scope.domain !== dhcp.domain ||
        scope.lease_days !== dhcp.leaseDays ||
        scope.lease_hours !== dhcp.leaseHours ||
        scope.lease_mins !== dhcp.leaseMins ||
        optionsChanged;
      if (changed && scope.start_ip && scope.end_ip && scope.router && scope.dns) {
        const outcome = await postJSON("/api/config/network", {
          action: "dhcp_scope",
          vlan_id: vlanID,
          ip,
          mask,
          dhcp: scope,
        });
        await renderOutcome(outcomeEl, outcome);
      }

      await load();
    });
    // Wired after openModal so the buttons exist in the DOM. Add/Remove
    // act immediately and are independent of this modal's Save.
    wireMACBindings(vlanID);
  }

  function addVLAN() {
    const dhcp = { start: "", end: "", router: "", dns: "", dnsSecondary: "", domain: "", leaseDays: 0, leaseHours: 2, leaseMins: 0 };
    const body = `
      <label>VLAN ID (1-4094)
        <input id="cfg-new-vlan-id" type="number" min="1" max="4094">
      </label>
      <label>IP address
        <input id="cfg-new-vlan-ip" type="text" placeholder="e.g. 172.24.0.1">
      </label>
      <label>Subnet mask
        <input id="cfg-new-vlan-mask" type="text" placeholder="e.g. 255.255.255.0">
      </label>
      <label class="check-row">
        <input id="cfg-new-vlan-mgmt" type="checkbox" checked>
        Management access
      </label>
      <h3>DHCP scope (optional — leave start/end blank to skip)</h3>
      ${dhcpScopeFieldsHTML("cfg-new-vlan-dhcp", dhcp)}
      <div id="cfg-new-vlan-outcome"></div>
    `;
    openModal("Add VLAN", body, async (modalEl) => {
      const vlanID = parseInt(modalEl.querySelector("#cfg-new-vlan-id").value, 10);
      const ip = modalEl.querySelector("#cfg-new-vlan-ip").value.trim();
      const mask = modalEl.querySelector("#cfg-new-vlan-mask").value.trim();
      const mgmt = modalEl.querySelector("#cfg-new-vlan-mgmt").checked;
      if (!vlanID || vlanID < 1 || vlanID > 4094) throw new Error("VLAN ID must be between 1 and 4094");
      if (!ip || !mask) throw new Error("IP address and subnet mask are required");

      const scope = readDHCPScope(modalEl, "cfg-new-vlan-dhcp");
      const req = { action: "vlan_create", vlan_id: vlanID, ip, mask, management_access: mgmt };
      if (scope.start_ip && scope.end_ip) {
        if (!scope.router || !scope.dns) throw new Error("Router and DNS are required to configure DHCP");
        req.dhcp = scope;
      }
      const outcome = await postJSON("/api/config/network", req);
      await renderOutcome(modalEl.querySelector("#cfg-new-vlan-outcome"), outcome);
      await load();
    });
  }

  window.NSEConfig.registerSection("network", { load });
})();
