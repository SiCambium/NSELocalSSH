// Shared building blocks for the Configuration page: every section
// (config-network.js, config-wan.js, and future ones) reuses these rather
// than reimplementing its own modal/fetch/license-gate/provisional-apply
// handling.
(function () {
  const NAV = [
    { id: "network", label: "Network" },
    { id: "wan", label: "WAN" },
    { id: "management", label: "Management" },
    { id: "groups", label: "Groups" },
    { id: "dns", label: "DNS" },
    { id: "threat", label: "Threat Protection" },
    { id: "firewall", label: "Firewall" },
    { id: "vpn", label: "VPN" },
    { id: "advanced", label: "Advanced" },
  ];
  let currentSection = "network";
  let licenseCache = null;

  function esc(s) {
    return String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  }

  // Every call here is a round trip to the device, so success and failure
  // are exactly the liveness signal the header's dot needs while a
  // Configuration page is open and the Status poll is not running.
  function reportLiveness(ok) {
    if (window.NSEHeader) window.NSEHeader.setConnDot(ok ? "on" : "down");
  }

  async function postJSON(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      reportLiveness(false);
      throw new Error(data.detail || res.statusText);
    }
    reportLiveness(true);
    return data;
  }

  async function getJSON(url) {
    const res = await fetch(url);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      reportLiveness(false);
      throw new Error(data.detail || res.statusText);
    }
    reportLiveness(true);
    return data;
  }

  async function fetchLicense(force = false) {
    if (licenseCache && !force) return licenseCache;
    const data = await getJSON("/api/license");
    licenseCache = data.license || {};
    return licenseCache;
  }

  // licenseGate wraps controlHTML with a disabled look plus a banner when
  // the named feature flag is off, matching cnMaestro's own "grey it out,
  // don't hide it" convention for Security Plus gated features.
  function licenseGate(license, flagName, controlHTML, label = "NSE Security Plus") {
    const enabled = !!(license && license[flagName]);
    if (enabled) return controlHTML;
    return `<div class="license-gated">
      <div class="license-gated-control">${controlHTML}</div>
      <p class="license-banner">This feature is available with ${esc(label)}.</p>
    </div>`;
  }

  // --- Modal -----------------------------------------------------------

  let modalRoot = null;
  function ensureModalRoot() {
    if (modalRoot) return modalRoot;
    modalRoot = document.createElement("div");
    modalRoot.id = "config-modal-root";
    document.body.appendChild(modalRoot);
    return modalRoot;
  }

  function closeModal() {
    if (modalRoot) modalRoot.innerHTML = "";
  }

  // openModal renders a titled dialog with bodyHTML and a Save/Cancel
  // footer. onSubmit receives the modal element so it can read its own
  // form fields; return false (or throw) to keep the modal open with an
  // error shown, return a truthy result to close it.
  function openModal(title, bodyHTML, onSubmit) {
    const root = ensureModalRoot();
    root.innerHTML = `
      <div class="modal-overlay" data-role="overlay">
        <div class="modal" role="dialog" aria-modal="true">
          <div class="modal-header">
            <h2>${esc(title)}</h2>
            <button type="button" class="modal-close" data-role="close" aria-label="Close">&times;</button>
          </div>
          <div class="modal-body">${bodyHTML}</div>
          <p class="modal-error" hidden></p>
          <div class="modal-footer">
            <button type="button" class="modal-cancel" data-role="cancel">Cancel</button>
            <button type="button" class="modal-save" data-role="save">Save</button>
          </div>
        </div>
      </div>`;
    const overlay = root.querySelector('[data-role="overlay"]');
    const modalEl = root.querySelector(".modal");
    const errEl = root.querySelector(".modal-error");
    const saveBtn = root.querySelector('[data-role="save"]');
    const close = () => closeModal();
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) close();
    });
    root.querySelector('[data-role="close"]').addEventListener("click", close);
    root.querySelector('[data-role="cancel"]').addEventListener("click", close);
    // Deliberately never auto-closes on success: a risky change's outcome
    // (in particular the provisional confirm-countdown banner) renders
    // inside the modal body, and yanking the modal away the instant
    // onSubmit resolves would destroy that UI before the user can act on
    // it. The user closes the modal themselves once they've seen the
    // result, via Cancel or the × button.
    saveBtn.addEventListener("click", async () => {
      errEl.hidden = true;
      saveBtn.disabled = true;
      saveBtn.textContent = "Saving…";
      try {
        await onSubmit(modalEl);
      } catch (e) {
        errEl.hidden = false;
        errEl.textContent = e.message || String(e);
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = "Save";
      }
    });
    return modalEl;
  }

  // --- Safe-apply provisional/confirm banner ----------------------------

  // renderOutcome shows the result of a POST that went through
  // SafeApplier: applied changes just report success; provisional changes
  // get a countdown banner with a Confirm button; rejected/rolled-back
  // changes are shown as errors. Returns a promise that resolves once the
  // outcome is fully settled (confirmed, or auto-rolled-back).
  function renderOutcome(container, outcome) {
    // An expiry can land while this page is open, so re-check whenever a
    // change has just been applied.
    setTimeout(refreshFailedUndos, 0);
    return new Promise((resolve) => {
      if (outcome.status === "applied") {
        // An "applied" outcome can still carry a reason — the change took
        // effect but persisting it to the startup config didn't, which the
        // operator needs to know because it won't survive a reboot.
        container.innerHTML = outcome.reason
          ? `<p class="apply-ok">Applied.</p><p class="warn">${esc(outcome.reason)}</p>`
          : `<p class="apply-ok">Applied and saved.</p>`;
        resolve(outcome);
        return;
      }
      if (outcome.status === "rejected") {
        container.innerHTML = `<p class="apply-error">Rejected: ${esc(outcome.reason || "unknown error")}</p>`;
        resolve(outcome);
        return;
      }
      if (outcome.status === "rolled_back") {
        container.innerHTML = `<p class="apply-error">Undone: ${esc(outcome.reason || "the device stopped answering after the change")}</p>`;
        resolve(outcome);
        return;
      }
      // The change broke access to the device AND the undo could not be
      // delivered over the connection it broke. Nothing in this app can
      // fix that, so it says so plainly and gives the recovery that does
      // work — the change was never saved, so a power-cycle restores.
      if (outcome.status === "unreachable") {
        container.innerHTML = `<p class="apply-error"><strong>The device is not responding and could not be restored automatically.</strong></p>
          <p class="warn">${esc(outcome.reason || "")}</p>`;
        resolve(outcome);
        return;
      }
      if (outcome.status === "provisional") {
        let remaining = outcome.expires_in || 60;
        // Built once. An earlier version re-rendered this whole block on
        // every tick of the countdown, which destroyed and recreated the
        // Confirm button sixty times — and a click only fires when
        // mousedown and mouseup land on the same element, so a press that
        // straddled a tick produced no event at all. The change then
        // expired unconfirmed and a later click reported "no pending
        // change for that token". Only the seconds are updated now; the
        // button and its listener are never replaced.
        container.innerHTML = `<div class="apply-provisional">
          <p>Applied, and the device still accepts a new SSH login. Confirm within <strong data-role="countdown">${remaining}s</strong> to save it. Otherwise it is undone and nothing is written to the startup config.</p>
          <button type="button" class="modal-save" data-role="confirm-apply">Confirm</button>
        </div>`;
        const countdownEl = container.querySelector('[data-role="countdown"]');
        const confirmBtn = container.querySelector('[data-role="confirm-apply"]');

        let settled = false;
        const finish = (html) => {
          if (settled) return;
          settled = true;
          clearInterval(timer);
          container.innerHTML = html;
          resolve(outcome);
        };

        confirmBtn.addEventListener("click", async () => {
          if (settled) return;
          // Stop the countdown and disable immediately, so a second click
          // cannot send the same token twice.
          clearInterval(timer);
          confirmBtn.disabled = true;
          confirmBtn.textContent = "Confirming…";
          try {
            await postJSON("/api/config/confirm", { token: outcome.confirm_token });
            finish(`<p class="apply-ok">Confirmed and saved.</p>`);
          } catch (e) {
            finish(`<p class="apply-error">${esc(e.message)}</p>`);
          }
        });

        const timer = setInterval(() => {
          remaining -= 1;
          if (remaining <= 0) {
            finish(`<p class="apply-error">Timed out waiting for confirmation — the change was undone.</p>`);
            return;
          }
          countdownEl.textContent = `${remaining}s`;
        }, 1000);
        return;
      }
      container.innerHTML = `<p class="apply-error">Unexpected response.</p>`;
      resolve(outcome);
    });
  }

  // --- Section nav (top-level Configuration tabs) -----------------------

  function renderNav() {
    const nav = document.getElementById("config-nav");
    if (!nav) return;
    nav.innerHTML = NAV.map(
      (n) =>
        `<button type="button" data-config-section="${n.id}" class="${n.id === currentSection ? "active" : ""}">${esc(n.label)}</button>`
    ).join("");
    nav.querySelectorAll("button").forEach((b) => {
      b.addEventListener("click", () => selectSection(b.dataset.configSection));
    });
  }

  // --- Failed automatic undos -------------------------------------------
  //
  // SafeApplier's expiry loop runs in the background with no request to
  // answer, so an undo that did not land had nowhere to be reported. It
  // was recorded and never read. A device left holding a change the
  // operator believes was undone is exactly the state this app exists to
  // prevent, so the record gets a banner that stays until it is cleared.
  async function refreshFailedUndos() {
    const box = document.getElementById("failed-undo-banner");
    if (!box) return;
    let rows = [];
    try {
      const data = await getJSON("/api/config/failed-undos");
      rows = data.failed_undos || [];
    } catch (err) {
      // The banner is a safety signal, not a feature: if it cannot be
      // fetched, say nothing rather than claim all is well.
      box.hidden = true;
      return;
    }
    if (!rows.length) {
      box.hidden = true;
      box.innerHTML = "";
      return;
    }
    box.hidden = false;
    box.innerHTML = `
      <h3>An automatic undo did not complete</h3>
      <p>A change was held pending confirmation, was not confirmed in time, and the undo sent when the window closed did not land. <strong>The change may still be on the device.</strong> Check the section below and undo it by hand if it is.</p>
      <p class="muted">It was never written to the device's startup config, so a power-cycle still restores the previous configuration.</p>
      <ul>${rows
        .map((r) => `<li><span class="mono">${esc(r.section)}</span> — ${esc(r.detail)} <span class="muted">(${esc(new Date(r.at).toLocaleString())})</span></li>`)
        .join("")}</ul>
      <p><button type="button" class="row-edit" id="failed-undo-clear">Dismiss</button></p>
    `;
    document.getElementById("failed-undo-clear").addEventListener("click", async () => {
      await postJSON("/api/config/failed-undos", {});
      await refreshFailedUndos();
    });
  }

  function selectSection(id) {
    currentSection = id;
    renderNav();
    document.querySelectorAll("#page-config .config-section").forEach((el) => {
      el.hidden = el.dataset.section !== id;
    });
    const mod = sectionModules[id];
    if (mod) mod.load();
    refreshFailedUndos();
  }

  const sectionModules = {};
  function registerSection(id, mod) {
    sectionModules[id] = mod;
  }

  function onShow() {
    renderNav();
    document.querySelectorAll("#page-config .config-section").forEach((el) => {
      el.hidden = el.dataset.section !== currentSection;
    });
    const mod = sectionModules[currentSection];
    if (mod) mod.load();
    refreshFailedUndos();
  }

  window.NSEConfig = {
    esc,
    postJSON,
    getJSON,
    fetchLicense,
    licenseGate,
    openModal,
    closeModal,
    renderOutcome,
    registerSection,
    onShow,
  };

  // A plain navigation (not fetch) so the browser's own download handling
  // picks up the server's Content-Disposition: attachment header.
  const exportBtn = document.getElementById("export-profile-btn");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      window.location.href = "/api/profile/export";
    });
  }
})();
