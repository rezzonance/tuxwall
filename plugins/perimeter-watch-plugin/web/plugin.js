/* TuxWall Perimeter Watch plugin — external exposure + reputation view. */
(function () {
  "use strict";
  let root = null;
  let api = null;

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function portBadge(p, unexpected) {
    return unexpected
      ? '<span class="pw-port pw-bad">' + esc(p) + "</span>"
      : '<span class="pw-port pw-ok">' + esc(p) + "</span>";
  }

  async function render() {
    if (!root) return;
    root.innerHTML = '<div class="pw-loading muted">Auditing perimeter…</div>';
    let d = null;
    try { d = await api.api("refresh", {}); }
    catch (err) {
      root.innerHTML = '<div class="pw-error">Audit failed: ' + esc(err.message) + "</div>";
      return;
    }
    if (!d || !d.ok) {
      root.innerHTML = '<div class="pw-error">Audit failed: ' + esc((d && d.error) || "unknown") + "</div>";
      return;
    }
    const cards = (d.results || []).map((r) => {
      let body = "";
      if (r.shodan_error) {
        body += '<div class="pw-problem">⚠ Exposure check unreachable: ' + esc(r.shodan_error) + "</div>";
      }
      if (r.shodan) {
        const s = r.shodan;
        const ports = (s.ports || []).length
          ? (s.ports || []).map((p) => portBadge(p, (s.unexpected || []).includes(p))).join(" ")
          : '<span class="muted">nothing observed open (healthy)</span>';
        body += `
          <div class="pw-section"><b>Observed ports</b><div class="pw-ports">${ports}</div></div>
          <div class="pw-section"><b>Expected</b><div class="pw-ports muted">${esc((d.expected || []).join(", ")) || "—"}</div></div>`;
        if ((s.tags || []).length) {
          body += '<div class="pw-section"><b>Shodan tags</b><div class="pw-tags muted">' + esc(s.tags.join(", ")) + "</div></div>";
        }
        if ((s.vulns || []).length) {
          body += '<div class="pw-section"><b>Vulnerabilities</b><div class="pw-vulns">' +
            (s.vulns || []).map((v) => '<span class="pw-port pw-bad">' + esc(v) + "</span>").join(" ") + "</div></div>";
        }
        if ((s.cpes || []).length) {
          body += '<div class="pw-section"><b>Software seen</b><div class="pw-cpes muted mono">' + esc(s.cpes.join("<br>")) + "</div></div>";
        }
      }
      if (r.reputation_checked) {
        if (r.reputation_error) {
          body += '<div class="pw-note muted">CrowdSec reputation unreachable from this network — not an incident, shown for awareness.</div>';
        } else if (r.reputation && r.reputation.listed) {
          body += '<div class="pw-problem">⚠ Listed in CrowdSec threat intel — categories: ' +
            esc((r.reputation.categories || []).join(", ")) + "</div>";
        } else {
          body += '<div class="pw-okline">CrowdSec reputation: clean (not listed)</div>';
        }
      }
      return `
        <div class="card pw-card">
          <div class="card-head"><h2 class="pw-ip mono">${esc(r.ip)}</h2>
          <span class="muted">external view</span></div>
          ${body}
        </div>`;
    }).join("");
    root.innerHTML = `
      <div class="pw-wrap">
        ${cards || '<div class="pw-loading muted">No IP data.</div>'}
        <p class="pw-note muted">
          Exposure data from Shodan InternetDB (keyless): ports the internet can currently observe open,
          checked against your intentional set (services + honeypot + canary traps — green expected, red unexpected).
          Reputation from CrowdSec CTI when your DNS allows it; unreachable reputation is deliberately not an incident.
          Audited every few minutes with the incident cycle.
        </p>
      </div>`;
  }

  function mount(el, pluginApi) {
    root = el;
    api = pluginApi;
    root.innerHTML = '<div class="pw-loading muted">Loading Perimeter Watch…</div>';
    render();
  }

  function refresh(pluginApi) {
    api = pluginApi;
    render();
  }

  window.TuxWallPlugins.register("perimeter-watch", { mount, refresh });
})();
