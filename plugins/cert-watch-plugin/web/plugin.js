/* TuxWall Certificate Watch plugin — expiry table view. */
(function () {
  "use strict";
  let root = null;
  let api = null;

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function sevBadge(days) {
    if (days < 0) return '<span class="badge badge-err">expired</span>';
    if (days <= 7) return '<span class="badge badge-err">%d days</span>'.replace("%d", days);
    if (days <= 14) return '<span class="badge">%d days</span>'.replace("%d", days);
    if (days <= 30) return '<span class="badge badge-ok">%d days</span>'.replace("%d", days);
    return '<span class="badge badge-ok">%d days</span>'.replace("%d", days);
  }

  async function render() {
    if (!root) return;
    root.innerHTML = '<div class="cw-loading muted">Checking certificates…</div>';
    let d = null;
    try { d = await api.api("refresh", {}); }
    catch (err) {
      root.innerHTML = '<div class="cw-error">Check failed: ' + esc(err.message) + "</div>";
      return;
    }
    if (!d || !d.ok) {
      root.innerHTML = '<div class="cw-error">Check failed: ' + esc((d && d.error) || "unknown") + "</div>";
      return;
    }
    const rows = (d.certs || []).map((c) => `
      <tr>
        <td class="mono">${esc(c.endpoint)}</td>
        <td>${esc(c.subject || "—")}
          ${c.sans ? '<div class="cw-sans muted mono">' + esc(c.sans) + "</div>" : ""}</td>
        <td class="muted">${esc(c.issuer || "—")}</td>
        <td class="mono">${esc(c.not_after)}</td>
        <td>${sevBadge(c.days)}</td>
        <td class="cw-renew muted">${esc(c.renewal || "—")}</td>
      </tr>`).join("");
    const probs = (d.problems || []).map((p) =>
      '<div class="cw-problem">⚠ ' + esc(p.endpoint) + " — " + esc(p.error) + "</div>"
    ).join("");
    root.innerHTML = `
      <div class="cw-wrap">
        ${probs ? '<div class="cw-problems">' + probs + "</div>" : ""}
        <div class="table-wrap">
          <table class="cw-table">
            <thead>
              <tr>
                <th>Endpoint</th><th>Certificate</th><th>Issuer</th>
                <th>Expires</th><th>Time left</th><th>Renewal</th>
              </tr>
            </thead>
            <tbody>
              ${rows || '<tr><td colspan="6" class="empty">No readable endpoints — add some in the plugin settings.</td></tr>'}
            </tbody>
          </table>
        </div>
        <p class="cw-note muted">
          Checks connect to each endpoint and read the certificate the service actually presents.
          Healthy certificates (&gt;30 days) stay silent in the incident timeline; the warning ladder is
          info at 30 days, warning at the configured threshold, critical (webhook) near expiry.
          Renewal hints come from the plugin settings; Let's Encrypt certs get a certbot command automatically.
        </p>
      </div>`;
  }

  function mount(el, pluginApi) {
    root = el;
    api = pluginApi;
    root.innerHTML = '<div class="cw-loading muted">Loading Certificate Watch…</div>';
    render();
  }

  function refresh(pluginApi) {
    api = pluginApi;
    render();
  }

  window.TuxWallPlugins.register("cert-watch", { mount, refresh });
})();
