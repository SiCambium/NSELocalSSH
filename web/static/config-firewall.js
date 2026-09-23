// Firewall configuration section: DoS-protection toggles, outbound filter
// rules (add / delete / reorder, including User/IP Group source and
// destination references), GEO IP filtering (mode / countries /
// exceptions, both directions), and a read-only view of Port Forward/NAT
// (still export-only — their exact CLI argument syntax isn't confirmed
// yet, unlike filter rules and GEO IP; see config_handlers_firewall.go).
(function () {
  const { esc, postJSON, getJSON, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;
  let groups = null;

  // ISO 3166-1 alpha-2 country codes, for the GEO IP filtering country
  // picker — CONFIRMED as the expected code format via NSE AI CLI
  // research ("firewall geo-ip-restrictions <dir> countries <ISO
  // 3166-1 alpha-2 codes>").
  const COUNTRIES = [
    ["AF", "Afghanistan"], ["AL", "Albania"], ["DZ", "Algeria"], ["AD", "Andorra"], ["AO", "Angola"],
    ["AR", "Argentina"], ["AM", "Armenia"], ["AU", "Australia"], ["AT", "Austria"], ["AZ", "Azerbaijan"],
    ["BS", "Bahamas"], ["BH", "Bahrain"], ["BD", "Bangladesh"], ["BY", "Belarus"], ["BE", "Belgium"],
    ["BZ", "Belize"], ["BJ", "Benin"], ["BT", "Bhutan"], ["BO", "Bolivia"], ["BA", "Bosnia and Herzegovina"],
    ["BW", "Botswana"], ["BR", "Brazil"], ["BN", "Brunei"], ["BG", "Bulgaria"], ["BF", "Burkina Faso"],
    ["BI", "Burundi"], ["KH", "Cambodia"], ["CM", "Cameroon"], ["CA", "Canada"], ["CV", "Cabo Verde"],
    ["CF", "Central African Republic"], ["TD", "Chad"], ["CL", "Chile"], ["CN", "China"], ["CO", "Colombia"],
    ["KM", "Comoros"], ["CG", "Congo"], ["CD", "Congo (DRC)"], ["CR", "Costa Rica"], ["CI", "Côte d'Ivoire"],
    ["HR", "Croatia"], ["CU", "Cuba"], ["CY", "Cyprus"], ["CZ", "Czechia"], ["DK", "Denmark"],
    ["DJ", "Djibouti"], ["DM", "Dominica"], ["DO", "Dominican Republic"], ["EC", "Ecuador"], ["EG", "Egypt"],
    ["SV", "El Salvador"], ["GQ", "Equatorial Guinea"], ["ER", "Eritrea"], ["EE", "Estonia"], ["SZ", "Eswatini"],
    ["ET", "Ethiopia"], ["FJ", "Fiji"], ["FI", "Finland"], ["FR", "France"], ["GA", "Gabon"],
    ["GM", "Gambia"], ["GE", "Georgia"], ["DE", "Germany"], ["GH", "Ghana"], ["GR", "Greece"],
    ["GD", "Grenada"], ["GT", "Guatemala"], ["GN", "Guinea"], ["GW", "Guinea-Bissau"], ["GY", "Guyana"],
    ["HT", "Haiti"], ["HN", "Honduras"], ["HK", "Hong Kong"], ["HU", "Hungary"], ["IS", "Iceland"],
    ["IN", "India"], ["ID", "Indonesia"], ["IR", "Iran"], ["IQ", "Iraq"], ["IE", "Ireland"],
    ["IL", "Israel"], ["IT", "Italy"], ["JM", "Jamaica"], ["JP", "Japan"], ["JO", "Jordan"],
    ["KZ", "Kazakhstan"], ["KE", "Kenya"], ["KI", "Kiribati"], ["KP", "North Korea"], ["KR", "South Korea"],
    ["KW", "Kuwait"], ["KG", "Kyrgyzstan"], ["LA", "Laos"], ["LV", "Latvia"], ["LB", "Lebanon"],
    ["LS", "Lesotho"], ["LR", "Liberia"], ["LY", "Libya"], ["LI", "Liechtenstein"], ["LT", "Lithuania"],
    ["LU", "Luxembourg"], ["MO", "Macao"], ["MG", "Madagascar"], ["MW", "Malawi"], ["MY", "Malaysia"],
    ["MV", "Maldives"], ["ML", "Mali"], ["MT", "Malta"], ["MR", "Mauritania"], ["MU", "Mauritius"],
    ["MX", "Mexico"], ["MD", "Moldova"], ["MC", "Monaco"], ["MN", "Mongolia"], ["ME", "Montenegro"],
    ["MA", "Morocco"], ["MZ", "Mozambique"], ["MM", "Myanmar"], ["NA", "Namibia"], ["NP", "Nepal"],
    ["NL", "Netherlands"], ["NZ", "New Zealand"], ["NI", "Nicaragua"], ["NE", "Niger"], ["NG", "Nigeria"],
    ["MK", "North Macedonia"], ["NO", "Norway"], ["OM", "Oman"], ["PK", "Pakistan"], ["PA", "Panama"],
    ["PG", "Papua New Guinea"], ["PY", "Paraguay"], ["PE", "Peru"], ["PH", "Philippines"], ["PL", "Poland"],
    ["PT", "Portugal"], ["QA", "Qatar"], ["RO", "Romania"], ["RU", "Russia"], ["RW", "Rwanda"],
    ["SA", "Saudi Arabia"], ["SN", "Senegal"], ["RS", "Serbia"], ["SC", "Seychelles"], ["SL", "Sierra Leone"],
    ["SG", "Singapore"], ["SK", "Slovakia"], ["SI", "Slovenia"], ["SO", "Somalia"], ["ZA", "South Africa"],
    ["SS", "South Sudan"], ["ES", "Spain"], ["LK", "Sri Lanka"], ["SD", "Sudan"], ["SR", "Suriname"],
    ["SE", "Sweden"], ["CH", "Switzerland"], ["SY", "Syria"], ["TW", "Taiwan"], ["TJ", "Tajikistan"],
    ["TZ", "Tanzania"], ["TH", "Thailand"], ["TG", "Togo"], ["TO", "Tonga"], ["TT", "Trinidad and Tobago"],
    ["TN", "Tunisia"], ["TR", "Turkey"], ["TM", "Turkmenistan"], ["UG", "Uganda"], ["UA", "Ukraine"],
    ["AE", "United Arab Emirates"], ["GB", "United Kingdom"], ["US", "United States"], ["UY", "Uruguay"],
    ["UZ", "Uzbekistan"], ["VU", "Vanuatu"], ["VE", "Venezuela"], ["VN", "Vietnam"], ["YE", "Yemen"],
    ["ZM", "Zambia"], ["ZW", "Zimbabwe"],
  ];

  // parseFilterRule pulls the structured fields back out of a rule's raw
  // "deny proto any SRC SPORT DST DPORT in" string — CONFIRMED format
  // (see FilterRuleContent in config_write.go). SRC/DST are each either
  // "any", an "addr/mask" pair, or a bare group name — endpointLabel below
  // tells those apart for display. Returns null for anything that doesn't
  // match, so an unexpected/malformed rule from elsewhere still renders
  // (as a raw-text fallback) instead of breaking.
  function parseFilterRule(rule) {
    const m = /^(\S+) proto (\S+) (\S+) (\S+) (\S+) (\S+) in$/.exec(rule || "");
    if (!m) return null;
    return {
      action: m[1], protocol: m[2],
      src: m[3], srcPort: m[4],
      dst: m[5], dstPort: m[6],
    };
  }

  // endpointLabel renders a parsed src/dst token for the table: "Any" for
  // the literal "any", the addr/mask as-is for an IP/mask pair, or the
  // bare name for a group reference.
  function endpointLabel(token) {
    if (token === "any") return "Any";
    return token;
  }

  async function load() {
    const panel = document.getElementById("config-firewall-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      const [fw, gr] = await Promise.all([getJSON("/api/config/firewall"), getJSON("/api/config/groups")]);
      cache = fw;
      groups = gr;
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  // groupNames lists every configured User Group and IP Group name —
  // both are interchangeable in a layer3-filter source/destination slot
  // (see FilterRuleContent's doc comment), so they're offered together.
  function groupNames() {
    const g = groups || {};
    return [...(g.user_groups || []), ...(g.ip_groups || [])].map((x) => x.name).filter(Boolean);
  }

  // appGroupNames lists every configured Application Group name, for the
  // "Application Group" filter rule type's group picker (see the Groups
  // tab — these are DPI application groupings, distinct from the
  // User/IP groups groupNames() above).
  function appGroupNames() {
    const g = groups || {};
    return (g.app_groups || []).map((x) => x.name).filter(Boolean);
  }

  // parseDPIRule pulls action/target out of an application-group or
  // category-control match leaf, for the same table row layout used by
  // IP-based rules — src column becomes the group/category name, dst is
  // left blank since these rule kinds have no destination endpoint.
  function parseDPIRule(kind, rule) {
    if (kind === "application_group") {
      const m = /^application-group (\S+) (.+)$/.exec(rule || "");
      if (!m) return null;
      return { action: m[1], protocol: "-", target: m[2] };
    }
    if (kind === "category") {
      const m = /^category-control (\S+) (.+)$/.exec(rule || "");
      if (!m) return null;
      return { action: m[2], protocol: "-", target: m[1] };
    }
    return null;
  }

  // The source restriction is not per-service: it scopes every
  // allowed-service on the device, so the same lines that scope a ping
  // also scope SSH and HTTPS. A box answering only a narrow range looks
  // identical to an unrestricted one everywhere else in this UI, which is
  // why it is worth stating plainly.
  function deviceAccessSources() {
    const d = cache.device_access_sources || {};
    return { ips: d.ip_addresses || [], groups: d.ip_groups || [] };
  }

  function deviceAccessSourcesLabel() {
    const { ips, groups } = deviceAccessSources();
    const parts = [...groups.map((g) => `group ${g}`), ...ips];
    return parts.length ? esc(parts.join(", ")) : "Any";
  }

  function deviceAccessSourcesNote() {
    const { ips, groups } = deviceAccessSources();
    if (!ips.length && !groups.length) {
      return `<p class="muted">No source restriction: every allowed service answers from anywhere it is reachable.</p>`;
    }
    return `<p class="warn">Management access — SSH and HTTPS included, not just ping — is restricted to these sources.</p>`;
  }

  function render() {
    const panel = document.getElementById("config-firewall-panel");
    const rules = cache.outbound_filter_rules || [];
    const ruleRows = rules
      .map((rule, i) => {
        const dpi = parseDPIRule(rule.kind, rule.rule);
        const f = dpi ? null : parseFilterRule(rule.rule);
        const action = dpi ? dpi.action : f ? f.action : "-";
        const protocol = dpi ? dpi.protocol : f ? f.protocol : "-";
        const src = dpi
          ? `<span class="mono">${esc(dpi.target)}</span>`
          : f
          ? `${esc(endpointLabel(f.src))}:${esc(f.srcPort)}`
          : `<span class="mono">${esc(rule.rule)}</span>`;
        const dst = dpi ? "-" : f ? `${esc(endpointLabel(f.dst))}:${esc(f.dstPort)}` : "-";
        return `<tr>
          <td>${esc(rule.precedence)}</td>
          <td>${esc(rule.name)}</td>
          <td>${esc(ruleTypeLabel(rule.kind))}</td>
          <td>${esc(action)}</td>
          <td>${esc(protocol)}</td>
          <td class="mono">${src}</td>
          <td class="mono">${dst}</td>
          <td>
            <button type="button" class="row-edit" data-move="up" data-precedence="${esc(rule.precedence)}" ${i === 0 ? "disabled" : ""}>&uarr;</button>
            <button type="button" class="row-edit" data-move="down" data-precedence="${esc(rule.precedence)}" ${i === rules.length - 1 ? "disabled" : ""}>&darr;</button>
            <button type="button" class="row-edit" data-edit-precedence="${esc(rule.precedence)}" ${rule.id ? "" : "disabled title=\"This rule holds a VLAN's rate limit — edit it from that VLAN\""}>Edit</button>
            <button type="button" class="row-edit" data-delete-precedence="${esc(rule.precedence)}">Delete</button>
          </td>
        </tr>`;
      })
      .join("");
    panel.innerHTML = `
      <h2>Device Access</h2>
      <div class="grid">
        ${stat("Respond to ICMP pings from WAN", cache.respond_to_icmp_from_wan ? "Enabled" : "Disabled")}
        ${stat("Allowed sources", deviceAccessSourcesLabel())}
      </div>
      ${deviceAccessSourcesNote()}
      <h2>DoS Protection</h2>
      <div class="grid">
        ${stat("Anti IP-spoofing", cache.dos_protection_ip_spoof ? "Enabled" : "Disabled")}
        ${stat("IP-spoof logging", cache.dos_protection_ip_spoof_log ? "Enabled" : "Disabled")}
        ${stat("Smurf-attack protection", cache.dos_protection_smurf_attack ? "Enabled" : "Disabled")}
        ${stat("ICMP-fragment protection", cache.dos_protection_icmp_frag ? "Enabled" : "Disabled")}
      </div>
      <p><button type="button" class="row-edit" id="edit-firewall-btn">Edit</button></p>

      <h2>Outbound Filter Rules</h2>
      <p class="muted">Filters LAN-to-WAN (or other subnet) traffic, evaluated top to bottom. Every add, delete, or reorder here rewrites the whole list — deleting and recreating every rule in the new order is the only device-confirmed way to change it, since there's no confirmed in-place renumbering. Applied through the safe-apply path, same as WAN and LAN port changes.</p>
      <p><button type="button" class="row-edit" id="add-filter-rule-btn">Add New</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>#</th><th>Name</th><th>Type</th><th>Action</th><th>Protocol</th><th>Source</th><th>Destination</th><th></th></tr></thead>
        <tbody>${ruleRows || '<tr><td colspan="8" class="muted">No filter rules found.</td></tr>'}</tbody>
      </table></div>

      <h2>GEO IP Filtering</h2>
      <p class="muted">Blocks or allows traffic by country. Applied through the safe-apply path, same as filter rules — a wrong mode/country list here can cut off remote access from your own location just as a WAN mistake can.</p>
      ${geoDirectionHTML("inbound", "WAN to LAN", cache.geo_ip_inbound)}
      ${geoDirectionHTML("outbound", "LAN to WAN", cache.geo_ip_outbound)}

      <h2>Port Forwarding</h2>
      <p class="muted">Forwards a port on a WAN interface to a host behind the device. Applied through the safe-apply path, like the rules above.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>WAN</th><th>#</th><th>WAN port</th><th>Protocol</th><th>To host</th><th>To port</th><th></th></tr></thead>
        <tbody>${portForwardRows() || '<tr><td colspan="7" class="muted">No port-forward rules.</td></tr>'}</tbody>
      </table></div>
      <p>${wanPortsAvailable() ? '<button type="button" class="row-edit" id="add-port-forward-btn">Add port forward</button>' : '<span class="muted">No WAN interface to add one to.</span>'}</p>

      <h2>Source NAT</h2>
      <p class="muted">Rewrites the source address of traffic leaving a WAN. <strong>Overload</strong> is what separates the two modes: on, many LAN hosts share the public address by port (1:many); off, each takes its own address from the range (1:1). The device prints nothing when overload is on, so a rule showing <span class="mono">enable</span> may have no line of its own in the config. A rule covering the subnet you reach this device from can break your own return path, so it goes through the same confirmation as a WAN change.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>WAN</th><th>#</th><th>LAN subnet</th><th>Public address</th><th>Overload</th><th></th></tr></thead>
        <tbody>${sourceNATRows() || '<tr><td colspan="6" class="muted">No source-NAT rules.</td></tr>'}</tbody>
      </table></div>
      <p>${wanPortsAvailable() ? '<button type="button" class="row-edit" id="add-source-nat-btn">Add source NAT</button>' : '<span class="muted">No WAN interface to add one to.</span>'}</p>

      <h2>1:1 NAT</h2>
      <p class="muted">Maps one public address onto one LAN address in <em>both</em> directions, with no ports involved — unlike a port forward, which only redirects one inbound port. Anything arriving on the public address reaches the LAN host, so restrict it with <strong>allowed sources</strong> unless you mean it to be open. A rule on the address you manage this device through would capture your own session, so it goes through the same confirmation as a WAN change.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>WAN</th><th>#</th><th>Public IP</th><th>LAN IP</th><th>Protocol</th><th>Allowed sources</th><th>Rule name</th><th></th></tr></thead>
        <tbody>${natOneOneRows() || '<tr><td colspan="8" class="muted">No 1:1 NAT rules.</td></tr>'}</tbody>
      </table></div>
      <p>${wanPortsAvailable() ? '<button type="button" class="row-edit" id="add-nat-one-one-btn">Add 1:1 NAT</button>' : '<span class="muted">No WAN interface to add one to.</span>'}</p>
    `;
    document.getElementById("edit-firewall-btn").addEventListener("click", editFirewall);
    const addPF = document.getElementById("add-port-forward-btn");
    if (addPF) addPF.addEventListener("click", addPortForward);
    const addSN = document.getElementById("add-source-nat-btn");
    if (addSN) addSN.addEventListener("click", addSourceNAT);
    const addOO = document.getElementById("add-nat-one-one-btn");
    if (addOO) addOO.addEventListener("click", addNATOneOne);
    panel.querySelectorAll("[data-del-oo]").forEach((btn) => {
      btn.addEventListener("click", () =>
        deleteNATRule("nat_one_one_delete", btn.dataset.iface, parseInt(btn.dataset.delOo, 10), "1:1 NAT"));
    });
    panel.querySelectorAll("[data-del-pf]").forEach((btn) => {
      btn.addEventListener("click", () =>
        deleteNATRule("port_forward_delete", btn.dataset.iface, parseInt(btn.dataset.delPf, 10), "port forward"));
    });
    panel.querySelectorAll("[data-del-sn]").forEach((btn) => {
      btn.addEventListener("click", () =>
        deleteNATRule("source_nat_delete", btn.dataset.iface, parseInt(btn.dataset.delSn, 10), "source NAT"));
    });
    document.getElementById("add-filter-rule-btn").addEventListener("click", addFilterRule);
    panel.querySelectorAll("[data-move]").forEach((btn) => {
      btn.addEventListener("click", () => moveFilterRule(parseInt(btn.dataset.precedence, 10), btn.dataset.move));
    });
    panel.querySelectorAll("[data-edit-precedence]").forEach((btn) => {
      btn.addEventListener("click", () => editFilterRule(parseInt(btn.dataset.editPrecedence, 10)));
    });
    panel.querySelectorAll("[data-delete-precedence]").forEach((btn) => {
      btn.addEventListener("click", () => deleteFilterRule(parseInt(btn.dataset.deletePrecedence, 10)));
    });
    panel.querySelectorAll("[data-geo-edit]").forEach((btn) => {
      btn.addEventListener("click", () => editGeoDirection(btn.dataset.geoEdit));
    });
    panel.querySelectorAll("[data-geo-add-exception]").forEach((btn) => {
      btn.addEventListener("click", () => addGeoException(btn.dataset.geoAddException));
    });
    panel.querySelectorAll("[data-geo-delete-exception]").forEach((btn) => {
      const [direction, startIP, endIP] = btn.dataset.geoDeleteException.split("|");
      btn.addEventListener("click", () => deleteGeoException(direction, startIP, endIP));
    });
  }

  function geoModeLabel(mode) {
    if (mode === "allow") return "Allow Only (Deny by default)";
    if (mode === "block") return "Deny Only (Allow by default)";
    return "None";
  }

  function geoDirectionHTML(direction, label, data) {
    data = data || { mode: "none", countries: [], exceptions: [] };
    const exceptionRows = (data.exceptions || [])
      .map(
        (ex) => `<tr>
          <td class="mono">${esc(ex.start_ip)}</td>
          <td class="mono">${esc(ex.end_ip)}</td>
          <td><button type="button" class="row-edit" data-geo-delete-exception="${esc(direction)}|${esc(ex.start_ip)}|${esc(ex.end_ip)}">Delete</button></td>
        </tr>`
      )
      .join("");
    return `
      <h3>${esc(label)}</h3>
      <div class="grid">
        ${stat("Mode", geoModeLabel(data.mode))}
        ${stat("Countries", (data.countries || []).join(", ") || "-")}
      </div>
      <p><button type="button" class="row-edit" data-geo-edit="${esc(direction)}">Edit</button></p>
      <p class="muted">Exceptions — IP ranges always allowed regardless of the mode/country list above.</p>
      <p><button type="button" class="row-edit" data-geo-add-exception="${esc(direction)}">Add Exception</button></p>
      <div class="table-wrap"><table>
        <thead><tr><th>Start IP</th><th>End IP</th><th></th></tr></thead>
        <tbody>${exceptionRows || '<tr><td colspan="3" class="muted">No exceptions.</td></tr>'}</tbody>
      </table></div>
    `;
  }

  // filterEndpointFieldsHTML renders the All / IP+Mask / Group toggle
  // shared by the source and destination sections of the Add Filter Rule
  // form — a group name is CONFIRMED interchangeable with an IP/mask in
  // this position (see FilterRuleContent's doc comment), and "All" sends
  // the literal "any" (see filterEndpointSpec's doc comment for why).
  // pre is an existing endpoint's values when editing, or undefined when
  // adding. Selecting the right option up front matters as much as filling
  // the inputs: a form that opens on "All" while showing a subnet would
  // silently widen the rule if saved without touching it.
  function filterEndpointFieldsHTML(prefix, title, pre) {
    pre = pre || { type: "all", port: "any" };
    const names = groupNames();
    const groupOptions = names.length
      ? names
          .map((n) => `<option value="${esc(n)}" ${n === pre.group ? "selected" : ""}>${esc(n)}</option>`)
          .join("")
      : '<option value="">No groups configured yet</option>';
    const sel = (v) => (pre.type === v ? "selected" : "");
    return `
      <h3>${esc(title)}</h3>
      <label>Type
        <select id="${prefix}-type">
          <option value="all" ${sel("all")}>All</option>
          <option value="ip" ${sel("ip")}>IP Address / Subnet</option>
          <option value="group" ${sel("group")}>Group</option>
        </select>
      </label>
      <div id="${prefix}-ip-fields" ${pre.type === "ip" ? "" : "hidden"}>
        <label>Address <input id="${prefix}-addr" type="text" value="${esc(pre.addr || "")}" placeholder="e.g. 192.168.20.0"></label>
        <label>Mask <input id="${prefix}-mask" type="text" value="${esc(pre.mask || "")}" placeholder="e.g. 255.255.255.0"></label>
      </div>
      <div id="${prefix}-group-fields" ${pre.type === "group" ? "" : "hidden"}>
        <label>Group <select id="${prefix}-group">${groupOptions}</select></label>
      </div>
      <label>Port <input id="${prefix}-port" type="text" value="${esc(pre.port || "any")}"></label>
    `;
  }

  // The stored rule keeps an endpoint as one token: "any", an
  // "addr/mask" pair, or a bare group name.
  function parseEndpointToken(token, port) {
    if (!token || token === "any") return { type: "all", port: port || "any" };
    const i = token.indexOf("/");
    if (i > 0) return { type: "ip", addr: token.slice(0, i), mask: token.slice(i + 1), port: port || "any" };
    return { type: "group", group: token, port: port || "any" };
  }

  function ruleTypeLabel(kind) {
    if (kind === "application_group") return "Application Group";
    if (kind === "category") return "DPI Category";
    return "IP Based";
  }

  // Turns a stored rule back into the form's own shape, so Edit opens
  // showing what the rule actually is.
  function prefillFromRule(rule) {
    const dpi = parseDPIRule(rule.kind, rule.rule);
    if (dpi && rule.kind === "application_group") {
      return { name: rule.name, type: "application_group", action: dpi.action, appGroup: dpi.target };
    }
    if (dpi && rule.kind === "category") {
      return { name: rule.name, type: "category", action: dpi.action, category: dpi.target };
    }
    const f = parseFilterRule(rule.rule) || {};
    return {
      name: rule.name,
      type: "ip",
      // The device spells the permissive action "permit"; the form offers
      // it as "Allow" and the backend maps it back.
      action: f.action === "permit" ? "allow" : f.action || "deny",
      protocol: f.protocol || "any",
      src: parseEndpointToken(f.src, f.srcPort),
      dst: parseEndpointToken(f.dst, f.dstPort),
    };
  }

  function readFilterEndpoint(el, prefix) {
    const type = el.querySelector(`#${prefix}-type`).value;
    const port = el.querySelector(`#${prefix}-port`).value.trim() || "any";
    if (type === "all") {
      return { type, port };
    }
    if (type === "group") {
      const group = el.querySelector(`#${prefix}-group`).value;
      if (!group) throw new Error("Select a group, or add one on the Groups tab first");
      return { type, group, port };
    }
    const addr = el.querySelector(`#${prefix}-addr`).value.trim();
    const mask = el.querySelector(`#${prefix}-mask`).value.trim();
    if (!addr || !mask) throw new Error("Address and mask are required");
    return { type, addr, mask, port };
  }

  function wireEndpointToggle(modalEl, prefix) {
    modalEl.querySelector(`#${prefix}-type`).addEventListener("change", (e) => {
      modalEl.querySelector(`#${prefix}-ip-fields`).hidden = e.target.value !== "ip";
      modalEl.querySelector(`#${prefix}-group-fields`).hidden = e.target.value !== "group";
    });
  }

  // One form serves Add and Edit. They differ only in what is prefilled
  // and which action is posted, and keeping them in one place is what stops
  // a field added to one from being missing in the other.
  function filterRuleFormHTML(pre) {
    pre = pre || { type: "ip", action: "deny", protocol: "any" };
    const appNames = appGroupNames();
    const appGroupOptions = appNames.length
      ? appNames
          .map((n) => `<option value="${esc(n)}" ${n === pre.appGroup ? "selected" : ""}>${esc(n)}</option>`)
          .join("")
      : '<option value="">No application groups configured yet</option>';
    const typeSel = (v) => (pre.type === v ? "selected" : "");
    const actionSel = (v) => (pre.action === v ? "selected" : "");
    return `
      <label>Name <input id="cfg-filter-name" type="text" value="${esc(pre.name || "")}" placeholder="e.g. block_guest_to_office"></label>
      <label>Rule Type
        <select id="cfg-filter-type">
          <option value="ip" ${typeSel("ip")}>IP Based</option>
          <option value="application_group" ${typeSel("application_group")}>Application Group</option>
          <option value="category" ${typeSel("category")}>DPI Category</option>
        </select>
      </label>
      <label>Action
        <select id="cfg-filter-action">
          <option value="deny" ${actionSel("deny")}>Deny</option>
          <option value="allow" ${actionSel("allow")}>Allow (permit)</option>
        </select>
      </label>
      <div id="cfg-filter-ip-fields" ${pre.type === "ip" ? "" : "hidden"}>
        <label>Protocol <input id="cfg-filter-proto" type="text" value="${esc(pre.protocol || "any")}" placeholder="any, tcp, udp, icmp..."></label>
        ${filterEndpointFieldsHTML("cfg-filter-src", "Source", pre.src)}
        ${filterEndpointFieldsHTML("cfg-filter-dst", "Destination", pre.dst)}
        <p class="muted">"All" sends the literal "any" as the address, matching the same token already confirmed for protocol and port in this exact rule format.</p>
      </div>
      <div id="cfg-filter-appgroup-fields" ${pre.type === "application_group" ? "" : "hidden"}>
        <label>Application Group <select id="cfg-filter-appgroup">${appGroupOptions}</select></label>
        <p class="muted">References a group from the Groups tab's Application Groups list — add one there first if none exist.</p>
      </div>
      <div id="cfg-filter-category-fields" ${pre.type === "category" ? "" : "hidden"}>
        <label>Category <input id="cfg-filter-category" type="text" value="${esc(pre.category || "")}" placeholder="e.g. Gambling, Social-Media"></label>
        <p class="muted">Not validated against a known category list — this device's exact set of DPI category names hasn't been confirmed. If the name is wrong, the device rejects the whole change and nothing is applied.</p>
      </div>
      <div id="cfg-filter-outcome"></div>`;
  }

  function readFilterRuleForm(el) {
    const name = el.querySelector("#cfg-filter-name").value.trim();
    if (!name) throw new Error("Name is required");
    const ruleType = el.querySelector("#cfg-filter-type").value;
    const payload = {
      name,
      rule_type: ruleType,
      rule_action: el.querySelector("#cfg-filter-action").value,
    };
    if (ruleType === "application_group") {
      const appGroupName = el.querySelector("#cfg-filter-appgroup").value;
      if (!appGroupName) throw new Error("Select an application group, or add one on the Groups tab first");
      payload.app_group_name = appGroupName;
    } else if (ruleType === "category") {
      const category = el.querySelector("#cfg-filter-category").value.trim();
      if (!category) throw new Error("Category is required");
      payload.category = category;
    } else {
      const src = readFilterEndpoint(el, "cfg-filter-src");
      const dst = readFilterEndpoint(el, "cfg-filter-dst");
      payload.protocol = el.querySelector("#cfg-filter-proto").value.trim() || "any";
      payload.src_type = src.type;
      payload.src_addr = src.addr;
      payload.src_mask = src.mask;
      payload.src_group = src.group;
      payload.src_port = src.port;
      payload.dst_type = dst.type;
      payload.dst_addr = dst.addr;
      payload.dst_mask = dst.mask;
      payload.dst_group = dst.group;
      payload.dst_port = dst.port;
    }
    return payload;
  }

  function wireFilterRuleForm(modalEl) {
    wireEndpointToggle(modalEl, "cfg-filter-src");
    wireEndpointToggle(modalEl, "cfg-filter-dst");
    modalEl.querySelector("#cfg-filter-type").addEventListener("change", (e) => {
      modalEl.querySelector("#cfg-filter-ip-fields").hidden = e.target.value !== "ip";
      modalEl.querySelector("#cfg-filter-appgroup-fields").hidden = e.target.value !== "application_group";
      modalEl.querySelector("#cfg-filter-category-fields").hidden = e.target.value !== "category";
    });
  }

  function addFilterRule() {
    const body =
      filterRuleFormHTML(null) +
      `<p class="warn">New rules are added at the end of the list (lowest priority) — use the &uarr;/&darr; buttons afterward to move it into place. Applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed.</p>`;
    const modalEl = openModal("Add Filter Rule", body, async (el) => {
      const payload = Object.assign({ action: "filter_add" }, readFilterRuleForm(el));
      const outcome = await postJSON("/api/config/firewall", payload);
      await renderOutcome(el.querySelector("#cfg-filter-outcome"), outcome);
      await load();
    });
    wireFilterRuleForm(modalEl);
  }

  function editFilterRule(precedence) {
    const rule = (cache.outbound_filter_rules || []).find(
      (r) => parseInt(r.precedence, 10) === precedence
    );
    if (!rule) return;
    const body =
      filterRuleFormHTML(prefillFromRule(rule)) +
      `<p class="warn">The rule keeps its position (${esc(rule.precedence)}) — use the &uarr;/&darr; buttons to move it. Applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed.</p>`;
    const modalEl = openModal(`Edit Filter Rule ${rule.precedence}`, body, async (el) => {
      const payload = Object.assign(
        { action: "filter_edit", precedence: precedence },
        readFilterRuleForm(el)
      );
      const outcome = await postJSON("/api/config/firewall", payload);
      await renderOutcome(el.querySelector("#cfg-filter-outcome"), outcome);
      await load();
    });
    wireFilterRuleForm(modalEl);
  }

  function moveFilterRule(precedence, direction) {
    const rule = (cache.outbound_filter_rules || []).find((r) => parseInt(r.precedence, 10) === precedence);
    const label = direction === "up" ? "up" : "down";
    const body = `
      <p>Move <strong>${esc(rule ? rule.name : precedence)}</strong> ${label} one position?</p>
      <p class="warn">This rewrites the whole filter list (delete and recreate every rule in the new order) and is applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed.</p>
      <div id="cfg-filter-move-outcome"></div>
    `;
    openModal(`Move rule ${label}`, body, async (el) => {
      const outcome = await postJSON("/api/config/firewall", { action: "filter_move", precedence, direction });
      await renderOutcome(el.querySelector("#cfg-filter-move-outcome"), outcome);
      await load();
    });
  }

  function deleteFilterRule(precedence) {
    const rule = (cache.outbound_filter_rules || []).find((r) => parseInt(r.precedence, 10) === precedence);
    const body = `
      <p class="warn">This permanently removes ${esc(rule ? rule.name : "rule " + precedence)} and rewrites the whole filter list. Applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed.</p>
      <div id="cfg-filter-delete-outcome"></div>
    `;
    openModal("Delete filter rule", body, async (el) => {
      const outcome = await postJSON("/api/config/firewall", { action: "filter_delete", precedence });
      await renderOutcome(el.querySelector("#cfg-filter-delete-outcome"), outcome);
      await load();
    });
  }

  // --- Port forwarding and source NAT ---------------------------------
  //
  // Both live as sub-contexts inside an "interface eth N" block and are
  // written with the device's own irregular spelling (lan-IP, public-IP —
  // see natrules.go). There is no edit: a rule is deleted and re-added,
  // because nothing confirms that re-sending a leaf inside an existing
  // rule replaces it rather than appending.

  function wanPortsAvailable() {
    return (cache.wan_ports || []).length > 0;
  }

  function portForwardRows() {
    return (cache.port_forward_rules || [])
      .map(
        (r) => `<tr>
          <td class="mono">${esc(r.interface)}</td>
          <td>${r.index}</td>
          <td class="mono">${r.port}</td>
          <td>${esc(r.protocol)}</td>
          <td class="mono">${esc(r.lan_ip)}</td>
          <td class="mono">${r.lan_port}</td>
          <td><button type="button" class="row-edit" data-del-pf="${r.index}" data-iface="${esc(r.interface)}">Delete</button></td>
        </tr>`
      )
      .join("");
  }

  // The device prints "overload disable" and prints nothing when overload
  // is on, so the read path fills an absent leaf in as "enable". Show the
  // mode alongside, since the keyword on its own says nothing about which
  // kind of NAT the rule performs.
  function overloadLabel(v) {
    if (v === "disable") return 'disable <span class="muted">(1:1)</span>';
    if (v === "enable") return 'enable <span class="muted">(1:many)</span>';
    return esc(v || "-");
  }

  function sourceNATRows() {
    return (cache.source_nat_rules || [])
      .map(
        (r) => `<tr>
          <td class="mono">${esc(r.interface)}</td>
          <td>${r.index}</td>
          <td class="mono">${esc(r.lan_subnet)}</td>
          <td class="mono">${esc(r.public_ip)}</td>
          <td>${overloadLabel(r.overload)}</td>
          <td><button type="button" class="row-edit" data-del-sn="${r.index}" data-iface="${esc(r.interface)}">Delete</button></td>
        </tr>`
      )
      .join("");
  }

  function natOneOneRows() {
    return (cache.nat_one_one_rules || [])
      .map((r) => {
        const src = r.allowed_source_type
          ? `${esc(r.allowed_source_type === "ip-group" ? "group " : "")}${esc(r.allowed_source)}`
          : '<span class="warn-text">any</span>';
        return `<tr>
          <td class="mono">${esc(r.interface)}</td>
          <td>${r.index}</td>
          <td class="mono">${esc(r.public_ip)}</td>
          <td class="mono">${esc(r.lan_ip)}</td>
          <td>${esc(r.protocol || "any")}</td>
          <td class="mono">${src}</td>
          <td>${esc(r.rule_name || "-")}</td>
          <td><button type="button" class="row-edit" data-del-oo="${r.index}" data-iface="${esc(r.interface)}">Delete</button></td>
        </tr>`;
      })
      .join("");
  }

  function wanSelect(id) {
    const opts = (cache.wan_ports || []).map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("");
    return `<label>WAN interface <select id="${id}">${opts}</select></label>`;
  }

  function addPortForward() {
    const body = `
      ${wanSelect("cfg-pf-iface")}
      <label>WAN port <input id="cfg-pf-port" type="number" min="1" max="65535" placeholder="e.g. 9090"></label>
      <label>Protocol
        <select id="cfg-pf-proto"><option value="tcp">tcp</option><option value="udp">udp</option></select>
      </label>
      <p class="muted">Only tcp has been seen on a real device; udp is offered because the pairing is universal, but it is not confirmed for this CLI. A value the device rejects fails the whole change cleanly.</p>
      <label>Forward to host <input id="cfg-pf-ip" type="text" placeholder="e.g. 10.0.0.50"></label>
      <label>Forward to port <input id="cfg-pf-lanport" type="number" min="1" max="65535" placeholder="e.g. 9090"></label>
      <div id="cfg-pf-outcome"></div>
    `;
    openModal("Add port forward", body, async (el) => {
      const outcome = await postJSON("/api/config/firewall", {
        action: "port_forward_add",
        interface: el.querySelector("#cfg-pf-iface").value,
        wan_port: parseInt(el.querySelector("#cfg-pf-port").value, 10) || 0,
        protocol: el.querySelector("#cfg-pf-proto").value,
        lan_ip: el.querySelector("#cfg-pf-ip").value.trim(),
        lan_port: parseInt(el.querySelector("#cfg-pf-lanport").value, 10) || 0,
      });
      await renderOutcome(el.querySelector("#cfg-pf-outcome"), outcome);
      await load();
    });
  }

  function addSourceNAT() {
    const body = `
      ${wanSelect("cfg-sn-iface")}
      <label>LAN subnet (CIDR) <input id="cfg-sn-subnet" type="text" placeholder="e.g. 10.1.0.0/24"></label>
      <label>Public address or range
        <input id="cfg-sn-public" type="text" placeholder="e.g. 203.0.113.5 or 203.0.113.1-203.0.113.254">
      </label>
      <label>Overload
        <select id="cfg-sn-overload">
          <option value="enable">enable — many hosts share the address, by port (1:many)</option>
          <option value="disable">disable — one address each, from the range (1:1)</option>
        </select>
      </label>
      <p class="warn">This rewrites the source address of traffic leaving the WAN. A rule covering the subnet you reach this device from can break your own return path — confirm it promptly, or it is undone.</p>
      <div id="cfg-sn-outcome"></div>
    `;
    openModal("Add source NAT", body, async (el) => {
      const outcome = await postJSON("/api/config/firewall", {
        action: "source_nat_add",
        interface: el.querySelector("#cfg-sn-iface").value,
        lan_subnet: el.querySelector("#cfg-sn-subnet").value.trim(),
        public_ip: el.querySelector("#cfg-sn-public").value.trim(),
        overload: el.querySelector("#cfg-sn-overload").value,
      });
      await renderOutcome(el.querySelector("#cfg-sn-outcome"), outcome);
      await load();
    });
  }

  function addNATOneOne() {
    const body = `
      ${wanSelect("cfg-oo-iface")}
      <label>Public address <input id="cfg-oo-public" type="text" placeholder="e.g. 203.0.113.7 or 203.0.113.0/24"></label>
      <label>LAN address <input id="cfg-oo-lan" type="text" placeholder="e.g. 192.168.200.50 or 192.168.200.0/24"></label>
      <label>Protocol
        <select id="cfg-oo-proto">
          <option value="any">any</option>
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
        </select>
      </label>
      <label>Allowed sources
        <select id="cfg-oo-srctype">
          <option value="">any source</option>
          <option value="ip-address">IP address, range or subnet</option>
          <option value="ip-group">IP group</option>
        </select>
      </label>
      <label>Allowed source value
        <input id="cfg-oo-src" type="text" placeholder="e.g. 192.168.1.0/24, 192.168.1.5-192.168.1.9, or a group name">
      </label>
      <label>Rule name (optional, names a traffic counter)
        <input id="cfg-oo-name" type="text" placeholder="no spaces, max 64 characters">
      </label>
      <p class="warn">This maps the whole public address to the LAN host in both directions. Left open to any source it exposes that host; and a rule on the address you manage this device through would capture your own session — confirm it promptly, or it is undone.</p>
      <div id="cfg-oo-outcome"></div>
    `;
    openModal("Add 1:1 NAT", body, async (el) => {
      const outcome = await postJSON("/api/config/firewall", {
        action: "nat_one_one_add",
        interface: el.querySelector("#cfg-oo-iface").value,
        public_ip: el.querySelector("#cfg-oo-public").value.trim(),
        lan_ip: el.querySelector("#cfg-oo-lan").value.trim(),
        protocol: el.querySelector("#cfg-oo-proto").value,
        allowed_source_type: el.querySelector("#cfg-oo-srctype").value,
        allowed_source: el.querySelector("#cfg-oo-src").value.trim(),
        rule_name: el.querySelector("#cfg-oo-name").value.trim(),
      });
      await renderOutcome(el.querySelector("#cfg-oo-outcome"), outcome);
      await load();
    });
  }

  function deleteNATRule(action, iface, index, label) {
    const body = `
      <p class="warn">Delete ${esc(label)} rule ${index} on ${esc(iface)}?</p>
      <p class="muted">Removal uses the device's <span class="mono">no &lt;rule&gt; &lt;n&gt;</span> convention, confirmed live for port-forward and source-NAT rules. If the device rejects it the change fails cleanly and nothing is removed.</p>
      <div id="cfg-nat-del-outcome"></div>
    `;
    openModal(`Delete ${label} rule`, body, async (el) => {
      const outcome = await postJSON("/api/config/firewall", { action, interface: iface, index });
      await renderOutcome(el.querySelector("#cfg-nat-del-outcome"), outcome);
      await load();
    });
  }

  function editFirewall() {
    const body = `
      <label class="check-row"><input id="cfg-fw-icmp" type="checkbox" ${cache.respond_to_icmp_from_wan ? "checked" : ""}> Respond to ICMP pings from WAN</label>
      <label>Allowed sources (IP address, range or subnet)
        <input id="cfg-fw-da-source" type="text" value="${esc((deviceAccessSources().ips || [])[0] || "")}" placeholder="empty = reachable from anywhere">
      </label>
      <p class="muted">Applies to every service above, SSH and HTTPS included — not just ping. One value only: setting it replaces whatever is there. A range that excludes the address this session connects from is refused before anything is sent, because the rollback would travel over the connection it cuts.</p>
      <label class="check-row"><input id="cfg-fw-spoof" type="checkbox" ${cache.dos_protection_ip_spoof ? "checked" : ""}> Anti IP-spoofing</label>
      <label class="check-row"><input id="cfg-fw-spoof-log" type="checkbox" ${cache.dos_protection_ip_spoof_log ? "checked" : ""}> Log IP-spoof hits</label>
      <label class="check-row"><input id="cfg-fw-smurf" type="checkbox" ${cache.dos_protection_smurf_attack ? "checked" : ""}> Smurf-attack protection</label>
      <label class="check-row"><input id="cfg-fw-frag" type="checkbox" ${cache.dos_protection_icmp_frag ? "checked" : ""}> ICMP-fragment protection</label>
      <div id="cfg-fw-outcome"></div>
    `;
    openModal("Edit DoS Protection", body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-fw-outcome");
      const checks = [
        ["cfg-fw-icmp", "respond_to_icmp_from_wan", cache.respond_to_icmp_from_wan],
        ["cfg-fw-spoof", "dos_ip_spoof", cache.dos_protection_ip_spoof],
        ["cfg-fw-spoof-log", "dos_ip_spoof_log", cache.dos_protection_ip_spoof_log],
        ["cfg-fw-smurf", "dos_smurf", cache.dos_protection_smurf_attack],
        ["cfg-fw-frag", "dos_icmp_frag", cache.dos_protection_icmp_frag],
      ];
      for (const [id, action, was] of checks) {
        const enable = el.querySelector(`#${id}`).checked;
        if (enable !== !!was) {
          const outcome = await postJSON("/api/config/firewall", { action, enable });
          await renderOutcome(outcomeEl, outcome);
        }
      }

      // Sent last, so the toggles above are already applied if this one is
      // refused — and it is the one the backend can refuse outright, when
      // the range would exclude the session applying it.
      const source = el.querySelector("#cfg-fw-da-source").value.trim();
      const sourceWas = (deviceAccessSources().ips || [])[0] || "";
      if (source !== sourceWas) {
        const outcome = await postJSON("/api/config/firewall", {
          action: "device_access_ip_address",
          device_access_ip_address: source,
        });
        await renderOutcome(outcomeEl, outcome);
      }
      await load();
    });
  }

  function editGeoDirection(direction) {
    const data = (direction === "inbound" ? cache.geo_ip_inbound : cache.geo_ip_outbound) || { mode: "none", countries: [] };
    const selected = new Set(data.countries || []);
    // data-search carries name and code together, so either finds a
    // country without the filter having to read the DOM's rendered text.
    // Matching is plain substring over both, so a short query is broad —
    // "de" finds Germany, but also Bangladesh, Cape Verde, Denmark and
    // Sweden, whose names contain those letters. That is the right
    // trade: it keeps "united" working, and the alternative of matching
    // codes only would make the names unsearchable.
    const countryList = COUNTRIES.map(
      ([code, name]) =>
        `<label class="check-row" data-country data-search="${esc((name + " " + code).toLowerCase())}"><input type="checkbox" value="${code}" ${selected.has(code) ? "checked" : ""}> ${esc(name)} (${code})</label>`
    ).join("");
    const label = direction === "inbound" ? "WAN to LAN" : "LAN to WAN";
    const body = `
      <label>Mode
        <select id="cfg-geo-mode">
          <option value="none" ${data.mode === "none" ? "selected" : ""}>None</option>
          <option value="allow" ${data.mode === "allow" ? "selected" : ""}>Allow Only (Deny by default)</option>
          <option value="block" ${data.mode === "block" ? "selected" : ""}>Deny Only (Allow by default)</option>
        </select>
      </label>
      <label>Countries
        <input id="cfg-geo-search" type="search" placeholder="Search by name or code, e.g. Germany or DE" autocomplete="off">
      </label>
      <p class="muted" id="cfg-geo-count"></p>
      <div id="cfg-geo-list" style="max-height:220px;overflow-y:auto;border:1px solid var(--line);padding:8px 10px;border-radius:6px">${countryList}</div>
      <p class="muted" id="cfg-geo-empty" hidden>No country matches that search.</p>
      <p class="warn">Applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed. If you manage this device remotely from a country you then exclude, you can lock yourself out.</p>
      <div id="cfg-geo-outcome"></div>
    `;
    const modalEl = openModal(`Edit GEO IP — ${label}`, body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-geo-outcome");
      const mode = el.querySelector("#cfg-geo-mode").value;
      if (mode !== data.mode) {
        const outcome = await postJSON("/api/config/firewall", { action: "geo_mode", geo_direction: direction, geo_mode: mode });
        await renderOutcome(outcomeEl, outcome);
      }
      const countries = Array.from(
        el.querySelectorAll('#cfg-geo-list input[type="checkbox"]:checked')
      ).map((c) => c.value);
      if (countries.join(",") !== (data.countries || []).join(",")) {
        const outcome = await postJSON("/api/config/firewall", { action: "geo_countries", geo_direction: direction, countries });
        await renderOutcome(outcomeEl, outcome);
      }
      await load();
    });
    wireCountrySearch(modalEl);
  }

  // Filtering hides rows rather than re-rendering the list, so a country
  // checked and then filtered out of view stays checked and is still
  // submitted — re-rendering would silently drop those selections. The
  // count is there for the same reason: with a filter applied, the list on
  // screen is not the whole of what will be saved.
  function wireCountrySearch(modalEl) {
    if (!modalEl) return;
    const search = modalEl.querySelector("#cfg-geo-search");
    const list = modalEl.querySelector("#cfg-geo-list");
    const countEl = modalEl.querySelector("#cfg-geo-count");
    const emptyEl = modalEl.querySelector("#cfg-geo-empty");
    if (!search || !list) return;
    const rows = [...list.querySelectorAll("[data-country]")];

    const updateCount = () => {
      const selected = list.querySelectorAll('input[type="checkbox"]:checked').length;
      const hidden = rows.filter((r) => r.hidden).length;
      const suffix = hidden ? ` — ${rows.length - hidden} of ${rows.length} shown` : "";
      countEl.textContent = `${selected} selected${suffix}`;
    };

    search.addEventListener("input", () => {
      const q = search.value.trim().toLowerCase();
      let shown = 0;
      rows.forEach((row) => {
        const match = !q || row.dataset.search.includes(q);
        row.hidden = !match;
        if (match) shown++;
      });
      emptyEl.hidden = shown !== 0;
      updateCount();
    });

    list.addEventListener("change", updateCount);
    updateCount();
  }

  function addGeoException(direction) {
    const label = direction === "inbound" ? "WAN to LAN" : "LAN to WAN";
    const body = `
      <label>Start IP <input id="cfg-geo-ex-start" type="text" placeholder="e.g. 203.0.113.1"></label>
      <label>End IP <input id="cfg-geo-ex-end" type="text" placeholder="e.g. 203.0.113.10"></label>
      <p class="warn">Applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed.</p>
      <div id="cfg-geo-ex-outcome"></div>
    `;
    openModal(`Add Exception — ${label}`, body, async (el) => {
      const startIP = el.querySelector("#cfg-geo-ex-start").value.trim();
      const endIP = el.querySelector("#cfg-geo-ex-end").value.trim();
      if (!startIP || !endIP) throw new Error("Start IP and end IP are required");
      const outcome = await postJSON("/api/config/firewall", { action: "geo_exception_add", geo_direction: direction, start_ip: startIP, end_ip: endIP });
      await renderOutcome(el.querySelector("#cfg-geo-ex-outcome"), outcome);
      await load();
    });
  }

  function deleteGeoException(direction, startIP, endIP) {
    const body = `
      <p class="warn">This removes the exception for ${esc(startIP)}–${esc(endIP)}. Applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed. The delete syntax here is unconfirmed (follows this CLI's usual "no" convention) — if it's wrong, the change is rejected and rolled back rather than partially applied.</p>
      <div id="cfg-geo-ex-del-outcome"></div>
    `;
    openModal("Delete GEO IP exception", body, async (el) => {
      const outcome = await postJSON("/api/config/firewall", { action: "geo_exception_delete", geo_direction: direction, start_ip: startIP, end_ip: endIP });
      await renderOutcome(el.querySelector("#cfg-geo-ex-del-outcome"), outcome);
      await load();
    });
  }

  window.NSEConfig.registerSection("firewall", { load });
})();
