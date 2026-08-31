// VPN configuration section: Tailscale (enable, accept-routes,
// advertise-routes), a site-to-site on/off toggle, and RADIUS client
// creation. See config_handlers_vpn.go for what's deliberately excluded
// (WireGuard server config, vpn-server, tunnel-level site-to-site fields)
// and why.
(function () {
  const { esc, postJSON, getJSON, fetchLicense, licenseGate, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;
  let license = null;

  async function load() {
    const panel = document.getElementById("config-vpn-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      const [data, lic] = await Promise.all([getJSON("/api/config/vpn"), fetchLicense()]);
      cache = data;
      license = lic;
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  function render() {
    const panel = document.getElementById("config-vpn-panel");
    const ts = cache.tailscale || {};
    const radius = cache.radius_client_list || [];
    const radiusRows = radius
      .map(
        (c) => `<tr>
          <td>${esc(c.name)}</td>
          <td class="mono">${esc(c.address)}</td>
          <td class="mono">${esc(c.netmask)}</td>
        </tr>`
      )
      .join("");
    const tailscaleHTML = `<div class="grid">
      ${stat("Tailscale", ts.enable ? "Enabled" : "Disabled")}
      ${stat("Accept routes", ts.accept_routes ? "Enabled" : "Disabled")}
      ${stat("Advertise routes", ts.advertise_routes || "-")}
    </div>`;
    panel.innerHTML = `
      <h2>Tailscale</h2>
      ${licenseGate(license, "tailscale", tailscaleHTML)}
      <p><button type="button" class="row-edit" id="edit-tailscale-btn">Edit</button></p>

      <h2>Site-to-Site VPN</h2>
      <div class="grid">${stat("Site-to-site VPN", cache.site_to_site ? "Enabled" : "Disabled")}</div>
      <p class="muted">This only toggles site-to-site on or off. Configuring an actual IPsec tunnel (remote address, PSK, subnets) isn't supported here yet.</p>
      <p><button type="button" class="row-edit" id="edit-s2s-btn">${cache.site_to_site ? "Disable" : "Enable"}</button></p>

      <h2>RADIUS Clients</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Address</th><th>Netmask</th></tr></thead>
        <tbody>${radiusRows || '<tr><td colspan="3" class="muted">No RADIUS clients found.</td></tr>'}</tbody>
      </table></div>
      <p><button type="button" class="row-edit" id="add-radius-btn">Add RADIUS client</button></p>
    `;
    document.getElementById("edit-tailscale-btn").addEventListener("click", editTailscale);
    document.getElementById("edit-s2s-btn").addEventListener("click", toggleSiteToSite);
    document.getElementById("add-radius-btn").addEventListener("click", addRADIUSClient);
  }

  function editTailscale() {
    const ts = cache.tailscale || {};
    const body = `
      <label class="check-row"><input id="cfg-ts-enable" type="checkbox" ${ts.enable ? "checked" : ""}> Tailscale enabled</label>
      <label class="check-row"><input id="cfg-ts-accept" type="checkbox" ${ts.accept_routes ? "checked" : ""}> Accept routes from peers</label>
      <label>Advertise routes (comma-separated CIDRs)
        <input id="cfg-ts-advertise" type="text" value="${esc(ts.advertise_routes || "")}" placeholder="e.g. 172.21.0.0/16,172.23.0.0/16">
      </label>
      <p class="muted">Joining a tailnet requires an auth key, which isn't handled here — authorize this device from your Tailscale admin console after enabling.</p>
      <div id="cfg-ts-outcome"></div>
    `;
    openModal("Edit Tailscale", body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-ts-outcome");
      const enable = el.querySelector("#cfg-ts-enable").checked;
      if (enable !== !!ts.enable) {
        const outcome = await postJSON("/api/config/vpn", { action: "tailscale_enable", enable });
        await renderOutcome(outcomeEl, outcome);
      }
      const accept = el.querySelector("#cfg-ts-accept").checked;
      if (accept !== !!ts.accept_routes) {
        const outcome = await postJSON("/api/config/vpn", { action: "tailscale_accept_routes", enable: accept });
        await renderOutcome(outcomeEl, outcome);
      }
      const routes = el
        .querySelector("#cfg-ts-advertise")
        .value.split(",")
        .map((r) => r.trim())
        .filter(Boolean);
      if (routes.join(",") !== (ts.advertise_routes || "")) {
        const outcome = await postJSON("/api/config/vpn", { action: "tailscale_advertise_routes", routes });
        await renderOutcome(outcomeEl, outcome);
      }
      await load();
    });
  }

  function toggleSiteToSite() {
    const enable = !cache.site_to_site;
    const body = `
      <p class="warn">This ${enable ? "enables" : "disables"} the site-to-site VPN context. No tunnel is configured either way — this is only the on/off switch.</p>
      <div id="cfg-s2s-outcome"></div>
    `;
    openModal(enable ? "Enable Site-to-Site VPN" : "Disable Site-to-Site VPN", body, async (el) => {
      const outcome = await postJSON("/api/config/vpn", { action: "site_to_site_enable", enable });
      await renderOutcome(el.querySelector("#cfg-s2s-outcome"), outcome);
      await load();
    });
  }

  function addRADIUSClient() {
    const body = `
      <label>Name <input id="cfg-radius-name" type="text" placeholder="e.g. Demo1"></label>
      <label>Shared secret <input id="cfg-radius-secret" type="password"></label>
      <label>Network address <input id="cfg-radius-address" type="text" placeholder="e.g. 172.22.0.0"></label>
      <label>Prefix length <input id="cfg-radius-prefix" type="number" min="1" max="32" value="24"></label>
      <div id="cfg-radius-outcome"></div>
    `;
    openModal("Add RADIUS Client", body, async (el) => {
      const name = el.querySelector("#cfg-radius-name").value.trim();
      const secret = el.querySelector("#cfg-radius-secret").value;
      const address = el.querySelector("#cfg-radius-address").value.trim();
      const prefixLength = parseInt(el.querySelector("#cfg-radius-prefix").value, 10);
      if (!name || !secret || !address || !prefixLength) {
        throw new Error("Name, secret, address, and prefix length are all required");
      }
      const outcome = await postJSON("/api/config/vpn", {
        action: "radius_client_create",
        name,
        secret,
        address,
        prefix_length: prefixLength,
      });
      await renderOutcome(el.querySelector("#cfg-radius-outcome"), outcome);
      await load();
    });
  }

  window.NSEConfig.registerSection("vpn", { load });
})();
