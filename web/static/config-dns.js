// DNS configuration section: content-filter mode, DNS override (+ IP Group
// bypass exceptions), resolver toggle, name servers, Local DNS Entries,
// Conditional Forwarding, and DNS Filter Policies. See config_handlers_dns.go
// and internal/nse/dns.go for the confirmation level of each CLI leaf —
// local-host/forward-zone's argument order is best-guess, everything else
// here is confirmed (dns-filter policy structure confirmed from a live
// capture of this exact device's own "Ad_Blocking" policy).
(function () {
  const { esc, postJSON, getJSON, fetchLicense, licenseGate, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;
  let license = null;
  let groups = null;

  // DNS_FILTER_CATEGORIES are the six categories CONFIRMED from a live
  // capture of this device's own DNS filter policy — other category names
  // may exist (cnMaestro's category list may be broader) but aren't
  // enumerated anywhere in the CLI reference, so an "other" free-text
  // field is offered alongside these.
  const DNS_FILTER_CATEGORIES = [
    "malware-sites",
    "spyware-and-adware",
    "spam-urls",
    "bot-nets",
    "keyloggers-and-monitoring",
    "phishing-and-other-frauds",
  ];

  async function load() {
    const panel = document.getElementById("config-dns-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      const [data, lic, gr] = await Promise.all([getJSON("/api/config/dns"), fetchLicense(), getJSON("/api/config/groups")]);
      cache = data;
      license = lic;
      groups = gr;
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  function nameServerIPs() {
    return (cache.name_server || []).map((n) => n.server_ip).filter(Boolean);
  }

  function ipGroupNames() {
    return (groups && groups.ip_groups ? groups.ip_groups : []).map((g) => g.name).filter(Boolean);
  }

  function render() {
    const panel = document.getElementById("config-dns-panel");
    const filterModeHTML = `${stat("Content filter mode", cache.filter_mode || "-")}`;
    const dnsFilterEnabled = !!(license && license.dns_filter);

    const bypassRows = (cache.bypass_groups || [])
      .map(
        (name) => `<tr>
          <td>${esc(name)}</td>
          <td><button type="button" class="row-edit" data-delete-bypass="${esc(name)}">Delete</button></td>
        </tr>`
      )
      .join("");

    const localHostRows = (cache.local_hosts || [])
      .map(
        (h) => `<tr>
          <td>${esc(h.domain)}</td>
          <td class="mono">${esc(h.ip)}</td>
          <td><button type="button" class="row-edit" data-delete-local-host="${esc(h.domain)}|${esc(h.ip)}">Delete</button></td>
        </tr>`
      )
      .join("");

    const forwardZoneRows = (cache.forward_zones || [])
      .map(
        (z) => `<tr>
          <td>${esc(z.domain)}</td>
          <td class="mono">${esc(z.server)}</td>
          <td><button type="button" class="row-edit" data-delete-forward-zone="${esc(z.domain)}|${esc(z.server)}">Delete</button></td>
        </tr>`
      )
      .join("");

    const policyRows = (cache.filter_policies || [])
      .map(
        (p) => `<tr>
          <td>${esc(p.id)}</td>
          <td>${esc(p.name)}</td>
          <td>${esc(p.safe_search || "-")}</td>
          <td>${esc(p.deny_sources || "-")}</td>
          <td>${esc((p.deny_categories || []).join(", ") || "-")}</td>
          <td>
            <button type="button" class="row-edit" data-edit-policy="${esc(p.id)}">Edit</button>
            <button type="button" class="row-edit" data-delete-policy="${esc(p.id)}">Delete</button>
          </td>
        </tr>`
      )
      .join("");
    const policiesHTML = `
      <h2>DNS Filter Policies</h2>
      <p class="muted">Ad-Blocking-style rule sets: deny specific content categories, scoped to all traffic or a User Group. Confirmed structure from a live capture of this device's own policy.</p>
      <p><button type="button" class="row-edit" id="add-policy-btn">Add Policy</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Name</th><th>Safe Search</th><th>Source</th><th>Deny Categories</th><th></th></tr></thead>
        <tbody>${policyRows || '<tr><td colspan="6" class="muted">No filter policies configured.</td></tr>'}</tbody>
      </table></div>
    `;

    panel.innerHTML = `
      <h2>DNS</h2>
      <div class="grid">
        ${stat("DNS resolver", cache.dns_server === "enable" ? "Enabled" : "Disabled")}
        ${stat("DNS override (block external DNS)", cache.dns_override ? "Enabled" : "Disabled")}
        ${licenseGate(license, "dns_filter", filterModeHTML)}
        ${stat("Name servers", nameServerIPs().join(", ") || "-")}
      </div>
      <p><button type="button" class="row-edit" id="edit-dns-btn">Edit</button></p>

      <h2>DNS Override Exceptions</h2>
      <p class="muted">IP Groups that bypass "Block external DNS servers" when it's enabled above.</p>
      <p><button type="button" class="row-edit" id="add-bypass-btn">Add Exception</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>IP Group</th><th></th></tr></thead>
        <tbody>${bypassRows || '<tr><td colspan="2" class="muted">No exceptions.</td></tr>'}</tbody>
      </table></div>

      <h2>Local DNS Entries</h2>
      <p class="muted">Static domain → IP overrides served by this device's own resolver. Argument order is best-guess (not yet confirmed on a live capture) — if it's backwards, the device rejects the whole change and nothing is applied.</p>
      <p><button type="button" class="row-edit" id="add-local-host-btn">Add Entry</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>Domain</th><th>IP Address</th><th></th></tr></thead>
        <tbody>${localHostRows || '<tr><td colspan="3" class="muted">No local DNS entries.</td></tr>'}</tbody>
      </table></div>

      <h2>Conditional Forwarding</h2>
      <p class="muted">Forwards queries for a specific domain to a specific upstream DNS server instead of the default. Argument order is best-guess, same caveat as Local DNS Entries.</p>
      <p><button type="button" class="row-edit" id="add-forward-zone-btn">Add Rule</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>Domain</th><th>Forward To</th><th></th></tr></thead>
        <tbody>${forwardZoneRows || '<tr><td colspan="3" class="muted">No conditional forwarding rules.</td></tr>'}</tbody>
      </table></div>

      ${licenseGate(license, "dns_filter", policiesHTML)}
    `;
    document.getElementById("edit-dns-btn").addEventListener("click", editDNS);
    document.getElementById("add-bypass-btn").addEventListener("click", addBypassGroup);
    document.getElementById("add-local-host-btn").addEventListener("click", addLocalHost);
    document.getElementById("add-forward-zone-btn").addEventListener("click", addForwardZone);
    if (dnsFilterEnabled) {
      document.getElementById("add-policy-btn").addEventListener("click", () => editPolicy(null));
      panel.querySelectorAll("[data-edit-policy]").forEach((btn) => {
        btn.addEventListener("click", () => editPolicy(parseInt(btn.dataset.editPolicy, 10)));
      });
      panel.querySelectorAll("[data-delete-policy]").forEach((btn) => {
        btn.addEventListener("click", () => deletePolicy(parseInt(btn.dataset.deletePolicy, 10)));
      });
    }
    panel.querySelectorAll("[data-delete-bypass]").forEach((btn) => {
      btn.addEventListener("click", () => deleteBypassGroup(btn.dataset.deleteBypass));
    });
    panel.querySelectorAll("[data-delete-local-host]").forEach((btn) => {
      const [domain, ip] = btn.dataset.deleteLocalHost.split("|");
      btn.addEventListener("click", () => deleteLocalHost(domain, ip));
    });
    panel.querySelectorAll("[data-delete-forward-zone]").forEach((btn) => {
      const [domain, server] = btn.dataset.deleteForwardZone.split("|");
      btn.addEventListener("click", () => deleteForwardZone(domain, server));
    });
  }

  function editDNS() {
    const servers = nameServerIPs();
    const dnsFilterEnabled = !!(license && license.dns_filter);
    const body = `
      <label class="check-row"><input id="cfg-dns-resolver" type="checkbox" ${cache.dns_server === "enable" ? "checked" : ""}> DNS resolver enabled</label>
      <label class="check-row"><input id="cfg-dns-override" type="checkbox" ${cache.dns_override ? "checked" : ""}> Block external DNS servers (dns-override)</label>
      ${
        dnsFilterEnabled
          ? `<label>Content filter mode
              <select id="cfg-dns-filter-mode">
                <option value="disabled" ${cache.filter_mode === "disabled" ? "selected" : ""}>Disabled</option>
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

  function addBypassGroup() {
    const names = ipGroupNames();
    const options = names.length
      ? names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("")
      : '<option value="">No IP Groups configured yet</option>';
    const body = `
      <label>IP Group <select id="cfg-bypass-group">${options}</select></label>
      <p class="muted">Add one on the Groups tab first if none exist.</p>
      <div id="cfg-bypass-outcome"></div>
    `;
    openModal("Add DNS Override Exception", body, async (el) => {
      const groupName = el.querySelector("#cfg-bypass-group").value;
      if (!groupName) throw new Error("Select an IP Group, or add one on the Groups tab first");
      const outcome = await postJSON("/api/config/dns", { action: "bypass_group_add", group_name: groupName });
      await renderOutcome(el.querySelector("#cfg-bypass-outcome"), outcome);
      await load();
    });
  }

  function deleteBypassGroup(groupName) {
    const body = `
      <p class="warn">Remove ${esc(groupName)} from the DNS override exception list?</p>
      <div id="cfg-bypass-delete-outcome"></div>
    `;
    openModal("Delete DNS Override Exception", body, async (el) => {
      const outcome = await postJSON("/api/config/dns", { action: "bypass_group_delete", group_name: groupName });
      await renderOutcome(el.querySelector("#cfg-bypass-delete-outcome"), outcome);
      await load();
    });
  }

  function addLocalHost() {
    const body = `
      <label>Domain <input id="cfg-local-host-domain" type="text" placeholder="e.g. nas.lan"></label>
      <label>IP Address <input id="cfg-local-host-ip" type="text" placeholder="e.g. 172.21.1.50"></label>
      <div id="cfg-local-host-outcome"></div>
    `;
    openModal("Add Local DNS Entry", body, async (el) => {
      const domain = el.querySelector("#cfg-local-host-domain").value.trim();
      const ip = el.querySelector("#cfg-local-host-ip").value.trim();
      if (!domain || !ip) throw new Error("Domain and IP address are required");
      const outcome = await postJSON("/api/config/dns", { action: "local_host_add", domain, ip });
      await renderOutcome(el.querySelector("#cfg-local-host-outcome"), outcome);
      await load();
    });
  }

  function deleteLocalHost(domain, ip) {
    const body = `
      <p class="warn">Remove the local DNS entry ${esc(domain)} → ${esc(ip)}?</p>
      <div id="cfg-local-host-delete-outcome"></div>
    `;
    openModal("Delete Local DNS Entry", body, async (el) => {
      const outcome = await postJSON("/api/config/dns", { action: "local_host_delete", domain, ip });
      await renderOutcome(el.querySelector("#cfg-local-host-delete-outcome"), outcome);
      await load();
    });
  }

  function addForwardZone() {
    const body = `
      <label>Domain <input id="cfg-forward-zone-domain" type="text" placeholder="e.g. corp.example"></label>
      <label>Forward To (DNS server IP) <input id="cfg-forward-zone-server" type="text" placeholder="e.g. 10.1.1.1"></label>
      <div id="cfg-forward-zone-outcome"></div>
    `;
    openModal("Add Conditional Forwarding Rule", body, async (el) => {
      const domain = el.querySelector("#cfg-forward-zone-domain").value.trim();
      const server = el.querySelector("#cfg-forward-zone-server").value.trim();
      if (!domain || !server) throw new Error("Domain and forward-to server are required");
      const outcome = await postJSON("/api/config/dns", { action: "forward_zone_add", domain, server });
      await renderOutcome(el.querySelector("#cfg-forward-zone-outcome"), outcome);
      await load();
    });
  }

  function deleteForwardZone(domain, server) {
    const body = `
      <p class="warn">Remove the conditional forwarding rule ${esc(domain)} → ${esc(server)}?</p>
      <div id="cfg-forward-zone-delete-outcome"></div>
    `;
    openModal("Delete Conditional Forwarding Rule", body, async (el) => {
      const outcome = await postJSON("/api/config/dns", { action: "forward_zone_delete", domain, server });
      await renderOutcome(el.querySelector("#cfg-forward-zone-delete-outcome"), outcome);
      await load();
    });
  }

  function nextPolicyID() {
    const used = new Set((cache.filter_policies || []).map((p) => p.id));
    for (let i = 1; i <= 16; i++) {
      if (!used.has(i)) return i;
    }
    return 1;
  }

  function editPolicy(id) {
    const existing = id != null ? (cache.filter_policies || []).find((p) => p.id === id) : null;
    const policyID = id != null ? id : nextPolicyID();
    const existingCats = new Set(existing ? existing.deny_categories || [] : []);
    const otherCats = [...existingCats].filter((c) => !DNS_FILTER_CATEGORIES.includes(c));
    const isGroupSource = existing && existing.deny_sources && existing.deny_sources.startsWith("user-group ");
    const groupSourceName = isGroupSource ? existing.deny_sources.slice("user-group ".length) : "";
    const names = ipGroupNames();
    const groupOptions = names.length
      ? names.map((n) => `<option value="${esc(n)}" ${n === groupSourceName ? "selected" : ""}>${esc(n)}</option>`).join("")
      : '<option value="">No User/IP Groups configured yet</option>';
    const catCheckboxes = DNS_FILTER_CATEGORIES.map(
      (c) => `<label class="check-row"><input type="checkbox" class="cfg-policy-cat" value="${esc(c)}" ${existingCats.has(c) ? "checked" : ""}> ${esc(c)}</label>`
    ).join("");
    const body = `
      <label>ID <input id="cfg-policy-id" type="number" min="1" max="16" value="${esc(policyID)}" ${existing ? "disabled" : ""}></label>
      <label>Name <input id="cfg-policy-name" type="text" value="${esc(existing ? existing.name : "")}" placeholder="e.g. Ad_Blocking"></label>
      <label class="check-row"><input id="cfg-policy-safe-search" type="checkbox" ${existing && existing.safe_search === "enabled" ? "checked" : ""}> Safe search enabled</label>
      <label>Source
        <select id="cfg-policy-source-type">
          <option value="all" ${!isGroupSource ? "selected" : ""}>All</option>
          <option value="group" ${isGroupSource ? "selected" : ""}>User Group</option>
        </select>
      </label>
      <p class="muted">"User Group" source is best-guess (by analogy with filter rules' confirmed "allowed-sources user-group" leaf) — only "All" has been observed live.</p>
      <div id="cfg-policy-group-fields" ${isGroupSource ? "" : "hidden"}>
        <label>User/IP Group <select id="cfg-policy-source-group">${groupOptions}</select></label>
      </div>
      <p>Deny categories (six confirmed from a live capture; add others as free text below):</p>
      ${catCheckboxes}
      <label>Other categories (comma separated)
        <input id="cfg-policy-other-cats" type="text" value="${esc(otherCats.join(","))}">
      </label>
      <p class="warn">Applied through the safe-apply path, same as filter rules.</p>
      <div id="cfg-policy-outcome"></div>
    `;
    const modalEl = openModal(existing ? `Edit DNS Filter Policy ${policyID}` : "Add DNS Filter Policy", body, async (el) => {
      const name = el.querySelector("#cfg-policy-name").value.trim();
      if (!name) throw new Error("Name is required");
      const safeSearch = el.querySelector("#cfg-policy-safe-search").checked;
      const sourceType = el.querySelector("#cfg-policy-source-type").value;
      let denySourceName = "";
      if (sourceType === "group") {
        denySourceName = el.querySelector("#cfg-policy-source-group").value;
        if (!denySourceName) throw new Error("Select a User/IP Group, or add one on the Groups tab first");
      }
      const categories = [...el.querySelectorAll(".cfg-policy-cat:checked")].map((c) => c.value);
      const otherCategories = el
        .querySelector("#cfg-policy-other-cats")
        .value.split(",")
        .map((c) => c.trim())
        .filter(Boolean);
      const outcome = await postJSON("/api/config/dns", {
        action: "filter_policy_save",
        id: policyID,
        name,
        safe_search: safeSearch,
        deny_source_type: sourceType,
        deny_source_name: denySourceName,
        deny_categories: [...categories, ...otherCategories],
      });
      await renderOutcome(el.querySelector("#cfg-policy-outcome"), outcome);
      await load();
    });
    modalEl.querySelector("#cfg-policy-source-type").addEventListener("change", (e) => {
      modalEl.querySelector("#cfg-policy-group-fields").hidden = e.target.value !== "group";
    });
  }

  function deletePolicy(id) {
    const existing = (cache.filter_policies || []).find((p) => p.id === id);
    const body = `
      <p class="warn">Permanently delete DNS filter policy ${esc(existing ? existing.name : id)}?</p>
      <div id="cfg-policy-delete-outcome"></div>
    `;
    openModal("Delete DNS Filter Policy", body, async (el) => {
      const outcome = await postJSON("/api/config/dns", { action: "filter_policy_delete", id });
      await renderOutcome(el.querySelector("#cfg-policy-delete-outcome"), outcome);
      await load();
    });
  }

  window.NSEConfig.registerSection("dns", { load });
})();
