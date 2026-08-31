// DNS configuration section: content-filter mode, DNS override, resolver
// toggle, name servers. dns-filter policy authoring (Ad Blocking-style
// rule sets) is read-only — see config_handlers_dns.go for why.
(function () {
  const { esc, postJSON, getJSON, fetchLicense, licenseGate, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;
  let license = null;

  async function load() {
    const panel = document.getElementById("config-dns-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      const [data, lic] = await Promise.all([getJSON("/api/config/dns"), fetchLicense()]);
      cache = data;
      license = lic;
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  function nameServerIPs() {
    return (cache.name_server || []).map((n) => n.server_ip).filter(Boolean);
  }

  function render() {
    const panel = document.getElementById("config-dns-panel");
    const filterModeHTML = `${stat("Content filter mode", cache.filter_mode || "-")}`;
    panel.innerHTML = `
      <h2>DNS</h2>
      <div class="grid">
        ${stat("DNS resolver", cache.dns_server === "enable" ? "Enabled" : "Disabled")}
        ${stat("DNS override", cache.dns_override ? "Enabled" : "Disabled")}
        ${licenseGate(license, "dns_filter", filterModeHTML)}
        ${stat("Name servers", nameServerIPs().join(", ") || "-")}
      </div>
      <p><button type="button" class="row-edit" id="edit-dns-btn">Edit</button></p>
    `;
    document.getElementById("edit-dns-btn").addEventListener("click", editDNS);
  }

  function editDNS() {
    const servers = nameServerIPs();
    const dnsFilterEnabled = !!(license && license.dns_filter);
    const body = `
      <label class="check-row"><input id="cfg-dns-resolver" type="checkbox" ${cache.dns_server === "enable" ? "checked" : ""}> DNS resolver enabled</label>
      <label class="check-row"><input id="cfg-dns-override" type="checkbox" ${cache.dns_override ? "checked" : ""}> DNS override enabled</label>
      ${
        dnsFilterEnabled
          ? `<label>Content filter mode
              <select id="cfg-dns-filter-mode">
                <option value="learning" ${cache.filter_mode === "learning" ? "selected" : ""}>Learning</option>
                <option value="filtering" ${cache.filter_mode === "filtering" ? "selected" : ""}>Filtering</option>
              </select>
            </label>`
          : `<p class="license-banner">Content filter mode is available with NSE Security Plus.</p>`
      }
      <label>Name servers (comma separated)
        <input id="cfg-dns-servers" type="text" value="${esc(servers.join(","))}">
      </label>
      <div id="cfg-dns-outcome"></div>
    `;
    openModal("Edit DNS", body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-dns-outcome");
      const resolverOn = el.querySelector("#cfg-dns-resolver").checked;
      if (resolverOn !== (cache.dns_server === "enable")) {
        const outcome = await postJSON("/api/config/dns", { action: "dns_server", enable: resolverOn });
        await renderOutcome(outcomeEl, outcome);
      }

      const overrideOn = el.querySelector("#cfg-dns-override").checked;
      if (overrideOn !== !!cache.dns_override) {
        const outcome = await postJSON("/api/config/dns", { action: "dns_override", enable: overrideOn });
        await renderOutcome(outcomeEl, outcome);
      }

      if (dnsFilterEnabled) {
        const newMode = el.querySelector("#cfg-dns-filter-mode").value;
        if (newMode !== cache.filter_mode) {
          const outcome = await postJSON("/api/config/dns", { action: "filter_mode", filter_mode: newMode });
          await renderOutcome(outcomeEl, outcome);
        }
      }

      const newServers = el
        .querySelector("#cfg-dns-servers")
        .value.split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (newServers.join(",") !== servers.join(",")) {
        const outcome = await postJSON("/api/config/dns", { action: "name_server", name_server: newServers });
        await renderOutcome(outcomeEl, outcome);
      }

      await load();
    });
  }

  window.NSEConfig.registerSection("dns", { load });
})();
