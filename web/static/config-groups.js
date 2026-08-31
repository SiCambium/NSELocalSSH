// Groups configuration section: User Groups, IP Groups, Application
// Groups (cnMaestro's "Groups" tab). None of this is exposed via
// cloud-json-config, so it's parsed from a fresh `show config` block tree
// — see groups.go. Every write is a full save-or-delete of one group by
// its numeric slot; there's no partial-field edit since the confirmed
// syntax always resends every leaf.
(function () {
  const { esc, postJSON, getJSON, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;

  async function load() {
    const panel = document.getElementById("config-groups-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      cache = await getJSON("/api/config/groups");
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  function render() {
    const panel = document.getElementById("config-groups-panel");
    const userRows = (cache.user_groups || [])
      .map(
        (g) => `<tr>
          <td>${g.id}</td>
          <td>${esc(g.name)}</td>
          <td class="mono">${esc(g.source_subnet)}</td>
          <td>
            <button type="button" class="row-edit" data-kind="user" data-id="${g.id}">Edit</button>
            <button type="button" class="row-edit" data-kind="user-delete" data-id="${g.id}">Delete</button>
          </td>
        </tr>`
      )
      .join("");
    const ipRows = (cache.ip_groups || [])
      .map(
        (g) => `<tr>
          <td>${g.id}</td>
          <td>${esc(g.name)}</td>
          <td class="mono">${esc(g.address)}</td>
          <td>
            <button type="button" class="row-edit" data-kind="ip" data-id="${g.id}">Edit</button>
            <button type="button" class="row-edit" data-kind="ip-delete" data-id="${g.id}">Delete</button>
          </td>
        </tr>`
      )
      .join("");
    const appRows = (cache.app_groups || [])
      .map(
        (g) => `<tr>
          <td>${g.id}</td>
          <td>${esc(g.name)}</td>
          <td>${esc((g.applications || []).join(", "))}</td>
          <td>${esc((g.categories || []).join(", "))}</td>
          <td>
            <button type="button" class="row-edit" data-kind="app" data-id="${g.id}">Edit</button>
            <button type="button" class="row-edit" data-kind="app-delete" data-id="${g.id}">Delete</button>
          </td>
        </tr>`
      )
      .join("");

    panel.innerHTML = `
      <h2>User Groups</h2>
      <p class="muted">IDs 1-64 only — index 65 crashes the device's CLI parser instead of rejecting cleanly (confirmed live).</p>
      <p><button type="button" class="row-edit" id="add-user-group-btn">Add User Group</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Name</th><th>Source Subnet</th><th></th></tr></thead>
        <tbody>${userRows || '<tr><td colspan="4" class="muted">No user groups found.</td></tr>'}</tbody>
      </table></div>

      <h2>IP Groups</h2>
      <p class="muted">IDs 1-16 only — this device's CLI parser doesn't accept higher indices reliably (confirmed live).</p>
      <p><button type="button" class="row-edit" id="add-ip-group-btn">Add IP Group</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Name</th><th>Address</th><th></th></tr></thead>
        <tbody>${ipRows || '<tr><td colspan="4" class="muted">No IP groups found.</td></tr>'}</tbody>
      </table></div>

      <h2>Application Groups</h2>
      <p class="muted">IDs 1-16 only — index 17 crashes the device's CLI parser instead of rejecting cleanly (confirmed live). Application and category names are validated by the device itself — an unrecognized name is cleanly rejected, not silently ignored.</p>
      <p><button type="button" class="row-edit" id="add-app-group-btn">Add Application Group</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Name</th><th>Applications</th><th>Categories</th><th></th></tr></thead>
        <tbody>${appRows || '<tr><td colspan="5" class="muted">No application groups found.</td></tr>'}</tbody>
      </table></div>
    `;

    panel.querySelectorAll('[data-kind="user"]').forEach((b) => b.addEventListener("click", () => editUserGroup(parseInt(b.dataset.id, 10))));
    panel.querySelectorAll('[data-kind="user-delete"]').forEach((b) => b.addEventListener("click", () => deleteGroup("user_group_delete", parseInt(b.dataset.id, 10))));
    panel.querySelectorAll('[data-kind="ip"]').forEach((b) => b.addEventListener("click", () => editIPGroup(parseInt(b.dataset.id, 10))));
    panel.querySelectorAll('[data-kind="ip-delete"]').forEach((b) => b.addEventListener("click", () => deleteGroup("ip_group_delete", parseInt(b.dataset.id, 10))));
    panel.querySelectorAll('[data-kind="app"]').forEach((b) => b.addEventListener("click", () => editAppGroup(parseInt(b.dataset.id, 10))));
    panel.querySelectorAll('[data-kind="app-delete"]').forEach((b) => b.addEventListener("click", () => deleteGroup("app_group_delete", parseInt(b.dataset.id, 10))));
    document.getElementById("add-user-group-btn").addEventListener("click", () => editUserGroup(null));
    document.getElementById("add-ip-group-btn").addEventListener("click", () => editIPGroup(null));
    document.getElementById("add-app-group-btn").addEventListener("click", () => editAppGroup(null));
  }

  function nextID(list, max) {
    const used = new Set((list || []).map((g) => g.id));
    for (let i = 1; i <= max; i++) if (!used.has(i)) return i;
    return null;
  }

  function deleteGroup(action, id) {
    const body = `<p class="warn">This permanently removes group ${id}. If it's referenced by name from a firewall rule, that rule will no longer match anything.</p><div id="cfg-group-del-outcome"></div>`;
    openModal(`Delete group ${id}`, body, async (el) => {
      const outcome = await postJSON("/api/config/groups", { action, id });
      await renderOutcome(el.querySelector("#cfg-group-del-outcome"), outcome);
      await load();
    });
  }

  function editUserGroup(id) {
    const existing = id != null ? (cache.user_groups || []).find((g) => g.id === id) : null;
    const groupID = id != null ? id : nextID(cache.user_groups, 64);
    if (groupID == null) {
      openModal("Add User Group", `<p class="muted">All 64 user group slots are in use.</p>`, async () => {});
      return;
    }
    const body = `
      <label>Name <input id="cfg-ug-name" type="text" value="${esc(existing ? existing.name : "")}"></label>
      <label>Source subnet (CIDR) <input id="cfg-ug-subnet" type="text" value="${esc(existing ? existing.source_subnet : "")}" placeholder="e.g. 192.168.60.0/24"></label>
      <div id="cfg-ug-outcome"></div>
    `;
    openModal(existing ? `Edit User Group ${groupID}` : "Add User Group", body, async (el) => {
      const name = el.querySelector("#cfg-ug-name").value.trim();
      const subnet = el.querySelector("#cfg-ug-subnet").value.trim();
      if (!name || !subnet) throw new Error("Name and source subnet are required");
      const outcome = await postJSON("/api/config/groups", { action: "user_group_save", id: groupID, name, source_subnet: subnet });
      await renderOutcome(el.querySelector("#cfg-ug-outcome"), outcome);
      await load();
    });
  }

  function editIPGroup(id) {
    const existing = id != null ? (cache.ip_groups || []).find((g) => g.id === id) : null;
    const groupID = id != null ? id : nextID(cache.ip_groups, 16);
    if (groupID == null) {
      openModal("Add IP Group", `<p class="muted">All 16 IP group slots are in use.</p>`, async () => {});
      return;
    }
    const body = `
      <label>Name <input id="cfg-ig-name" type="text" value="${esc(existing ? existing.name : "")}"></label>
      <label>Address (single IP, network/CIDR, or range)
        <input id="cfg-ig-address" type="text" value="${esc(existing ? existing.address : "")}" placeholder="e.g. 192.168.50.0/24">
      </label>
      <div id="cfg-ig-outcome"></div>
    `;
    openModal(existing ? `Edit IP Group ${groupID}` : "Add IP Group", body, async (el) => {
      const name = el.querySelector("#cfg-ig-name").value.trim();
      const address = el.querySelector("#cfg-ig-address").value.trim();
      if (!name || !address) throw new Error("Name and address are required");
      const outcome = await postJSON("/api/config/groups", { action: "ip_group_save", id: groupID, name, address });
      await renderOutcome(el.querySelector("#cfg-ig-outcome"), outcome);
      await load();
    });
  }

  function editAppGroup(id) {
    const existing = id != null ? (cache.app_groups || []).find((g) => g.id === id) : null;
    const groupID = id != null ? id : nextID(cache.app_groups, 16);
    if (groupID == null) {
      openModal("Add Application Group", `<p class="muted">All 16 application group slots are in use.</p>`, async () => {});
      return;
    }
    const body = `
      <label>Name <input id="cfg-ag-name" type="text" value="${esc(existing ? existing.name : "")}"></label>
      <label>Applications (comma separated, e.g. instagram,netflix)
        <input id="cfg-ag-apps" type="text" value="${esc((existing && existing.applications || []).join(","))}">
      </label>
      <label>Categories (comma separated, optional)
        <input id="cfg-ag-cats" type="text" value="${esc((existing && existing.categories || []).join(","))}">
      </label>
      <p class="muted">The device validates these names itself against its DPI catalog — an unrecognized name is rejected cleanly rather than accepted silently.</p>
      <div id="cfg-ag-outcome"></div>
    `;
    openModal(existing ? `Edit Application Group ${groupID}` : "Add Application Group", body, async (el) => {
      const name = el.querySelector("#cfg-ag-name").value.trim();
      const applications = el
        .querySelector("#cfg-ag-apps")
        .value.split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const categories = el
        .querySelector("#cfg-ag-cats")
        .value.split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (!name || applications.length === 0) throw new Error("Name and at least one application are required");
      const outcome = await postJSON("/api/config/groups", { action: "app_group_save", id: groupID, name, applications, categories });
      await renderOutcome(el.querySelector("#cfg-ag-outcome"), outcome);
      await load();
    });
  }

  window.NSEConfig.registerSection("groups", { load });
})();
