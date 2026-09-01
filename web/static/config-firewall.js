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
          <td>${esc(action)}</td>
          <td>${esc(protocol)}</td>
          <td class="mono">${src}</td>
          <td class="mono">${dst}</td>
          <td>
            <button type="button" class="row-edit" data-move="up" data-precedence="${esc(rule.precedence)}" ${i === 0 ? "disabled" : ""}>&uarr;</button>
            <button type="button" class="row-edit" data-move="down" data-precedence="${esc(rule.precedence)}" ${i === rules.length - 1 ? "disabled" : ""}>&darr;</button>
            <button type="button" class="row-edit" data-delete-precedence="${esc(rule.precedence)}">Delete</button>
          </td>
        </tr>`;
      })
      .join("");
    panel.innerHTML = `
      <h2>Device Access</h2>
      <div class="grid">
        ${stat("Respond to ICMP pings from WAN", cache.respond_to_icmp_from_wan ? "Enabled" : "Disabled")}
      </div>
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
        <thead><tr><th>#</th><th>Name</th><th>Action</th><th>Protocol</th><th>Source</th><th>Destination</th><th></th></tr></thead>
        <tbody>${ruleRows || '<tr><td colspan="7" class="muted">No filter rules found.</td></tr>'}</tbody>
      </table></div>

      <h2>GEO IP Filtering</h2>
      <p class="muted">Blocks or allows traffic by country. Applied through the safe-apply path, same as filter rules — a wrong mode/country list here can cut off remote access from your own location just as a WAN mistake can.</p>
      ${geoDirectionHTML("inbound", "WAN to LAN", cache.geo_ip_inbound)}
      ${geoDirectionHTML("outbound", "LAN to WAN", cache.geo_ip_outbound)}

      <h2>Port Forward / NAT</h2>
      <p class="muted">Read-only for now — this device's port-forward and NAT (1:1 / 1:many) commands exist but their exact CLI argument syntax isn't confirmed yet, unlike filter rules and GEO IP above; use cnMaestro for those until that's verified.</p>
    `;
    document.getElementById("edit-firewall-btn").addEventListener("click", editFirewall);
    document.getElementById("add-filter-rule-btn").addEventListener("click", addFilterRule);
    panel.querySelectorAll("[data-move]").forEach((btn) => {
      btn.addEventListener("click", () => moveFilterRule(parseInt(btn.dataset.precedence, 10), btn.dataset.move));
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
  function filterEndpointFieldsHTML(prefix, title) {
    const names = groupNames();
    const groupOptions = names.length
      ? names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("")
      : '<option value="">No groups configured yet</option>';
    return `
      <h3>${esc(title)}</h3>
      <label>Type
        <select id="${prefix}-type">
          <option value="all">All</option>
          <option value="ip">IP Address / Subnet</option>
          <option value="group">Group</option>
        </select>
      </label>
      <div id="${prefix}-ip-fields" hidden>
        <label>Address <input id="${prefix}-addr" type="text" placeholder="e.g. 192.168.20.0"></label>
        <label>Mask <input id="${prefix}-mask" type="text" placeholder="e.g. 255.255.255.0"></label>
      </div>
      <div id="${prefix}-group-fields" hidden>
        <label>Group <select id="${prefix}-group">${groupOptions}</select></label>
      </div>
      <label>Port <input id="${prefix}-port" type="text" value="any"></label>
    `;
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

  function addFilterRule() {
    const appNames = appGroupNames();
    const appGroupOptions = appNames.length
      ? appNames.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("")
      : '<option value="">No application groups configured yet</option>';
    const body = `
      <label>Name <input id="cfg-filter-name" type="text" placeholder="e.g. block_guest_to_office"></label>
      <label>Rule Type
        <select id="cfg-filter-type">
          <option value="ip">IP Based</option>
          <option value="application_group">Application Group</option>
          <option value="category">DPI Category</option>
        </select>
      </label>
      <label>Action
        <select id="cfg-filter-action">
          <option value="deny">Deny</option>
          <option value="allow">Allow</option>
        </select>
      </label>
      <p class="muted">"Deny" is confirmed on this device; "Allow" hasn't been independently verified — if it's wrong, the device will reject the whole change and nothing is applied.</p>
      <div id="cfg-filter-ip-fields">
        <label>Protocol <input id="cfg-filter-proto" type="text" value="any" placeholder="any, tcp, udp, icmp..."></label>
        ${filterEndpointFieldsHTML("cfg-filter-src", "Source")}
        ${filterEndpointFieldsHTML("cfg-filter-dst", "Destination")}
        <p class="muted">"All" sends the literal "any" as the address, matching the same token already confirmed for protocol and port in this exact rule format — not independently live-captured for this position, but if it's wrong the device rejects the whole change and nothing is applied.</p>
      </div>
      <div id="cfg-filter-appgroup-fields" hidden>
        <label>Application Group <select id="cfg-filter-appgroup">${appGroupOptions}</select></label>
        <p class="muted">References a group from the Groups tab's Application Groups list — add one there first if none exist.</p>
      </div>
      <div id="cfg-filter-category-fields" hidden>
        <label>Category <input id="cfg-filter-category" type="text" placeholder="e.g. Gambling, Social-Media"></label>
        <p class="muted">Not validated against a known category list — this device's exact set of DPI category names hasn't been confirmed. If the name is wrong, the device rejects the whole change and nothing is applied.</p>
      </div>
      <p class="warn">New rules are added at the end of the list (lowest priority) — use the &uarr;/&darr; buttons afterward to move it into place. Applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed.</p>
      <div id="cfg-filter-outcome"></div>
    `;
    const modalEl = openModal("Add Filter Rule", body, async (el) => {
      const name = el.querySelector("#cfg-filter-name").value.trim();
      if (!name) throw new Error("Name is required");
      const ruleType = el.querySelector("#cfg-filter-type").value;
      const ruleAction = el.querySelector("#cfg-filter-action").value;
      const payload = { action: "filter_add", name, rule_type: ruleType, rule_action: ruleAction };
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
      const outcome = await postJSON("/api/config/firewall", payload);
      await renderOutcome(el.querySelector("#cfg-filter-outcome"), outcome);
      await load();
    });
    wireEndpointToggle(modalEl, "cfg-filter-src");
    wireEndpointToggle(modalEl, "cfg-filter-dst");
    modalEl.querySelector("#cfg-filter-type").addEventListener("change", (e) => {
      modalEl.querySelector("#cfg-filter-ip-fields").hidden = e.target.value !== "ip";
      modalEl.querySelector("#cfg-filter-appgroup-fields").hidden = e.target.value !== "application_group";
      modalEl.querySelector("#cfg-filter-category-fields").hidden = e.target.value !== "category";
    });
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

  function editFirewall() {
    const body = `
      <label class="check-row"><input id="cfg-fw-icmp" type="checkbox" ${cache.respond_to_icmp_from_wan ? "checked" : ""}> Respond to ICMP pings from WAN</label>
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
      await load();
    });
  }

  function editGeoDirection(direction) {
    const data = (direction === "inbound" ? cache.geo_ip_inbound : cache.geo_ip_outbound) || { mode: "none", countries: [] };
    const selected = new Set(data.countries || []);
    const countryList = COUNTRIES.map(
      ([code, name]) =>
        `<label class="check-row"><input type="checkbox" value="${code}" ${selected.has(code) ? "checked" : ""}> ${esc(name)} (${code})</label>`
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
      <label>Countries</label>
      <div style="max-height:220px;overflow-y:auto;border:1px solid var(--line);padding:8px 10px;border-radius:6px">${countryList}</div>
      <p class="warn">Applied through the safe-apply path: verified reachable over a fresh connection before being kept, and rolled back automatically within 60 seconds if not confirmed. If you manage this device remotely from a country you then exclude, you can lock yourself out.</p>
      <div id="cfg-geo-outcome"></div>
    `;
    openModal(`Edit GEO IP — ${label}`, body, async (el) => {
      const outcomeEl = el.querySelector("#cfg-geo-outcome");
      const mode = el.querySelector("#cfg-geo-mode").value;
      if (mode !== data.mode) {
        const outcome = await postJSON("/api/config/firewall", { action: "geo_mode", geo_direction: direction, geo_mode: mode });
        await renderOutcome(outcomeEl, outcome);
      }
      const countries = Array.from(el.querySelectorAll('input[type="checkbox"]:checked')).map((c) => c.value);
      if (countries.join(",") !== (data.countries || []).join(",")) {
        const outcome = await postJSON("/api/config/firewall", { action: "geo_countries", geo_direction: direction, countries });
        await renderOutcome(outcomeEl, outcome);
      }
      await load();
    });
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
