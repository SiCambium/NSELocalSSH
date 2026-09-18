// Dev-only live reload. Reloads the page whenever a file under the
// directory named by NSE_DEV_STATIC changes, so UI edits are visible
// without rebuilding the embedded assets.
//
// /api/dev/enabled only exists when the server was started in dev mode, so
// in a shipped build this costs one request that 404s and nothing else —
// no EventSource is opened and no reconnect loop runs.
(function () {
  fetch("/api/dev/enabled")
    .then((res) => {
      if (!res.ok) return;
      const source = new EventSource("/api/dev/reload");
      source.onmessage = () => window.location.reload();
      // The browser retries an EventSource on its own, which is what we
      // want while the dev server restarts; nothing to do on error but
      // stay quiet about it.
      source.onerror = () => {};
    })
    .catch(() => {});
})();
