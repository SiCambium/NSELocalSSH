// Advanced: the free-text CLI escape hatch, for settings this app has no
// control for — the equivalent of cnMaestro's user-defined overrides.
//
// The text is sent to the device verbatim, line by line, because the
// device tracks command context itself exactly as it does when a human
// pastes into the CLI. Nothing here tries to interpret it, so the preview
// is the main safety feature: it shows the precise lines that will be
// sent, which config stanzas will be snapshotted for the undo, and which
// entries are new and therefore cannot be undone automatically.
(function () {
  const { esc, postJSON, getJSON, openModal, renderOutcome } = window.NSEConfig;
  let cache = null;

  async function load() {
    const panel = document.getElementById("config-advanced-panel");
    panel.innerHTML = `<p class="muted">Loading…</p>`;
    try {
      cache = await getJSON("/api/config/overrides");
      render();
    } catch (e) {
      panel.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  function appliedLabel() {
    if (!cache.applied_at) return "Never applied from here.";
    const when = new Date(cache.applied_at);
    const stamp = Number.isNaN(when.getTime()) ? cache.applied_at : when.toLocaleString();
    // Deliberately "last applied", not "active": the device can be changed
    // elsewhere, and a risky change that was never confirmed is rolled
    // back after this text was stored.
    return `Last applied from here ${esc(stamp)}. This is what was last sent, not necessarily what is on the device now.`;
  }

  function render() {
    const panel = document.getElementById("config-advanced-panel");
    panel.innerHTML = `
      <h2>Advanced</h2>
      <p class="muted">CLI configuration sent to the device as written, for settings with no control elsewhere in this app. Saved per connection and re-sent whenever you change it.</p>
      <p class="warn">Nothing here is validated beyond the device's own reply. Every line is applied through the safe-apply path, so a change that leaves the device unreachable is not saved and a power-cycle recovers it — but <strong>${esc(cache.guard_line)}</strong> is refused outright, because it would disable the very channel the undo travels over.</p>
      <label>Override text
        <textarea id="cfg-adv-text" rows="14" spellcheck="false"
          placeholder="interface eth 3&#10;no proxy-arp&#10;exit&#10;&#10;filter global-filter&#10;no application-control&#10;exit">${esc(cache.text || "")}</textarea>
      </label>
      <p class="muted">${appliedLabel()}</p>
      <div class="settings-actions">
        <button type="button" id="cfg-adv-preview">Preview</button>
        <button type="button" id="cfg-adv-apply">Apply and save</button>
        <span id="cfg-adv-note" class="muted"></span>
      </div>
      <div id="cfg-adv-outcome"></div>
    `;
    document.getElementById("cfg-adv-preview").addEventListener("click", preview);
    document.getElementById("cfg-adv-apply").addEventListener("click", apply);
  }

  function currentText() {
    return document.getElementById("cfg-adv-text").value;
  }

  function previewBody(p) {
    const lines = (p.lines || []).map((l) => esc(l)).join("\n");
    const newEntries = p.new_entries || [];
    const snapshot = (p.snapshot || []).map((l) => esc(l)).join("\n");
    return `
      <p class="muted">These exact lines will be sent, in this order:</p>
      <pre class="mono cfg-adv-pre">${lines || "(nothing — the text is empty)"}</pre>
      ${
        newEntries.length
          ? `<p class="warn">These entries do not exist on the device yet, so they would be created. The undo restores what was snapshotted, so it cannot remove them again — you would need to delete them yourself:</p>
             <pre class="mono cfg-adv-pre">${newEntries.map((k) => esc(k)).join("\n")}</pre>`
          : ""
      }
      <p class="muted">If the change has to be undone, this is what would be restored:</p>
      <pre class="mono cfg-adv-pre">${snapshot || "(nothing — none of these entries exist yet)"}</pre>
    `;
  }

  async function preview() {
    const note = document.getElementById("cfg-adv-note");
    note.textContent = "Reading the device…";
    try {
      const p = await postJSON("/api/config/overrides", { text: currentText(), preview: true });
      note.textContent = "";
      openModal("Preview", previewBody(p), async () => true);
    } catch (e) {
      note.textContent = "";
      document.getElementById("cfg-adv-outcome").innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
    }
  }

  async function apply() {
    const note = document.getElementById("cfg-adv-note");
    const outcomeEl = document.getElementById("cfg-adv-outcome");
    outcomeEl.innerHTML = "";
    note.textContent = "Reading the device…";
    let p;
    try {
      p = await postJSON("/api/config/overrides", { text: currentText(), preview: true });
    } catch (e) {
      note.textContent = "";
      outcomeEl.innerHTML = `<p class="apply-error">${esc(e.message)}</p>`;
      return;
    }
    note.textContent = "";
    // Always show what is about to happen before sending it. The text is
    // unvalidated and applies as one sequence, so this is the last point
    // at which a mistake is cheap.
    const body = `${previewBody(p)}<div id="cfg-adv-modal-outcome"></div>`;
    openModal("Apply override", body, async (el) => {
      const outcome = await postJSON("/api/config/overrides", { text: currentText() });
      await renderOutcome(el.querySelector("#cfg-adv-modal-outcome"), outcome);
      await load();
    });
  }

  window.NSEConfig.registerSection("advanced", { load });
})();
