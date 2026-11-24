/* Settings ▸ Security ▸ HTTPS card. Data: GET /api/https/status (admin);
   changes: POST /api/https/settings {enabled|redirect|hsts}, /api/https/
   regenerate, /api/https/custom-cert {cert,key}|{clear}; CA download:
   GET /api/https/ca.crt (also http://<router>/tuxwall-ca.crt while TuxWall
   serves HTTPS). With an HTTPS site set up outside TuxWall ("owner-managed")
   the card only reports it - no switch that would fight that setup.
   Markup lives in index.html (#https-card); styles are the shared card /
   community-settings classes (cs-set*, fw-switch, badge). */
(() => {
  "use strict";

  const API = "/api/https";
  let data = null;
  let error = "";
  let busy = false;
  let loadedAt = 0;
  let isAdmin = false;

  const card = () => document.getElementById("https-card");
  const body = () => document.getElementById("https-body");
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
  const confirmDlg = (msg) => (window.twConfirm || ((m) => Promise.resolve(window.confirm(m))))(msg);
  const day = (ts) => (ts ? new Date(ts * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "?");
  const cn = (dn) => {
    const m = /(?:^|,)CN=([^,]+)/.exec(dn || "");
    return m ? m[1] : (dn || "");
  };
  const expiry = (c) => (c && c.not_after
    ? `expires ${day(c.not_after)} (${c.days_left} day${c.days_left === 1 ? "" : "s"})` : "expiry unknown");
  const names = (c) => (c ? [...(c.dns || []), ...(c.ip || [])] : []);

  function modeView(d) {
    if (!d) return { badge: "", label: "…", line: error ? `Status unavailable: ${error}` : "Loading…" };
    if (d.ok === false) return { badge: "", label: "Unavailable", line: d.error || "Status unavailable" };
    switch (d.mode) {
      case "active":
        return {
          badge: "badge-ok", label: "On",
          line: `On — ${d.urls.join(" · ")}. ` + (d.redirect ? "Plain http on these addresses redirects to https."
            : "Plain http still serves the dashboard (redirect off" + (d.redirect_marker ? ": /etc/tuxwall/no-https-redirect" : "") + ")."),
        };
      case "owner-managed": {
        const sites = (d.owner_sites || []).map((s) => {
          const c = s.cert;
          const cert = c && !c.error ? ` — certificate from ${cn(c.issuer)}, ${expiry(c)}` : "";
          return `${s.file} (${s.listen.join(", ")})${cert}`;
        });
        return {
          badge: "badge-ok", label: "Your setup",
          line: sites.length
            ? `HTTPS is served by a custom nginx site: ${sites.join("; ")}. TuxWall leaves nginx alone.`
            : `HTTPS is set up outside TuxWall: ${(d.reasons || []).join("; ")}. TuxWall leaves nginx alone.`,
        };
      }
      case "disabled":
        return { badge: "", label: "Off", line: `Off — the dashboard is served over plain http (${(d.reasons || []).join("; ")}).` };
      case "no-addresses":
        return { badge: "", label: "Waiting", line: `No LAN/VPN address to listen on yet (${(d.reasons || []).join("; ")}).` };
      default:
        return { badge: "", label: d.mode || "?", line: (d.reasons || []).join("; ") };
    }
  }

  function row(kind, title, desc, status, ctl) {
    return `
      <div class="cs-set-row" data-kind="${kind}">
        <div class="cs-set-copy">
          <span class="cs-set-title" id="https-${kind}-t">${title}</span>
          ${desc ? `<span class="cs-set-desc" id="https-${kind}-d">${desc}</span>` : ""}
          <span class="cs-set-status" id="https-${kind}-s">${status}</span>
        </div>
        ${ctl ? `<div class="cs-set-ctl">${ctl}</div>` : ""}
      </div>`;
  }

  function sw(kind, checked, disabled) {
    return `<label class="fw-switch cs-switch">
        <input type="checkbox" role="switch" data-https="${kind}" aria-labelledby="https-${kind}-t" aria-describedby="https-${kind}-s"${checked ? " checked" : ""}${disabled ? " disabled" : ""}>
        <span class="fw-switch-slider"></span>
      </label>`;
  }

  function trustHelp(d) {
    const url = (d && d.ca_http && d.ca_http[0]) || "http://<router>/tuxwall-ca.crt";
    return `
      <details class="theme-format-details">
        <summary class="muted">How to trust the CA on your devices</summary>
        <ul class="muted">
          <li><b>Windows</b> (Edge, Chrome): open the file → <i>Install Certificate</i> → <i>Local Machine</i> → <i>Place all certificates in</i> <i>Trusted Root Certification Authorities</i>.</li>
          <li><b>macOS</b> (Safari, Chrome): open the file (Keychain Access, <i>System</i> keychain) → double-click <i>${esc((d && d.ca && d.ca.name) || "TuxWall Local CA")}</i> → <i>Trust</i> → <i>Always Trust</i>.</li>
          <li><b>iPhone / iPad</b>: open <code>${esc(url)}</code> in Safari → <i>Allow</i> → Settings → <i>Profile Downloaded</i> → <i>Install</i>; then Settings → General → About → <i>Certificate Trust Settings</i> → switch the CA on.</li>
          <li><b>Android</b>: Settings → Security → <i>Encryption &amp; credentials</i> → <i>Install a certificate</i> → <i>CA certificate</i> → pick the file (Chrome trusts it; some apps do not).</li>
          <li><b>Linux</b>: <code>sudo cp tuxwall-ca.crt /usr/local/share/ca-certificates/ &amp;&amp; sudo update-ca-certificates</code>; Chrome/Chromium: Settings → Privacy and security → Security → <i>Manage certificates</i> → <i>Authorities</i> → Import.</li>
          <li><b>Firefox</b> (own certificate store): Settings → Privacy &amp; Security → <i>View Certificates</i> → <i>Authorities</i> → <i>Import</i> → tick <i>Trust this CA to identify websites</i>.</li>
        </ul>
        <p class="muted">Compare the SHA-256 fingerprint shown above before trusting. This CA can only vouch for private addresses and local names (it is name-constrained), so trusting it cannot be used to impersonate other websites.</p>
      </details>`;
  }

  function render() {
    const el = body();
    const c = card();
    if (!el || !c) return;
    c.hidden = !isAdmin;
    if (!isAdmin) return;
    const d = data;
    const mv = modeView(d);
    const badge = document.getElementById("https-badge");
    if (badge) {
      badge.textContent = mv.label;
      badge.className = "badge" + (mv.badge ? " " + mv.badge : "");
    }
    if (!d || d.ok === false) {
      el.innerHTML = `<div class="cs-set">${row("mode", "Dashboard HTTPS", "", esc(mv.line), "")}</div>
        <div class="card-toolbar"><button class="btn btn-sm" type="button" data-https-act="reload">Re-check</button></div>`;
      bind();
      return;
    }
    const active = d.mode === "active";
    const owner = d.mode === "owner-managed";
    const canChange = d.installed && !busy;
    const rows = [];
    let modeStatus = esc(mv.line);
    if (active && d.applied === false) modeStatus += " Not applied to nginx yet — use Apply now.";
    if (!d.installed) modeStatus += " TuxWall's own certificate and switches arrive with the next package upgrade.";
    else if (owner) modeStatus += " TuxWall's own certificate is still kept up to date in /etc/tuxwall/tls if you want to switch to it.";
    rows.push(row("mode", "Dashboard HTTPS",
      "Encrypts the dashboard (password, session cookie) on the LAN and VPN.",
      modeStatus,
      owner ? "" : sw("enabled", active || (d.enabled_setting && d.mode === "no-addresses"), !canChange || d.no_https_marker)));
    if (active) {
      rows.push(row("redirect", "Redirect http → https",
        "Turn off only for integrations that cannot use https yet (port 80 keeps serving the dashboard).",
        d.redirect_marker ? "Off: /etc/tuxwall/no-https-redirect is present." : (d.redirect ? "On" : "Off"),
        sw("redirect", d.redirect, !canChange || d.redirect_marker)));
      rows.push(row("hsts", "HSTS (strict transport security)",
        "Browsers then refuse plain http and certificate warnings for a year. Only switch on once every device trusts the CA.",
        d.hsts ? "On (max-age one year)" : "Off",
        sw("hsts", d.hsts, !canChange)));
    }
    const cert = d.cert;
    if (d.in_use === "custom" && d.custom) {
      const cc = d.custom;
      rows.push(row("cert", "Certificate in use: yours",
        esc(cc.path),
        cc.error ? `Problem: ${esc(cc.error)}` : esc(`${cn(cc.subject)} from ${cn(cc.issuer)}, ${expiry(cc)}; names: ${names(cc).join(", ") || "none"}`), ""));
    } else if (cert && !cert.error) {
      let st = `Issued by ${cn(cert.issuer)}, ${expiry(cert)}; names: ${names(cert).join(", ")}.`;
      if (!d.sans_current) st += " Addresses or names changed — renewed by the daily check, or regenerate now.";
      if ((d.not_coverable || []).length) st += ` Not covered by this CA: ${d.not_coverable.join(", ")}.`;
      rows.push(row("cert", "TuxWall certificate", "Renewed automatically 30 days before it expires and when LAN/VPN addresses change.",
        esc(st), ""));
    } else if (d.installed) {
      rows.push(row("cert", "TuxWall certificate", "", "Not created yet — Regenerate creates it.", ""));
    }
    if (d.ca && !d.ca.error) {
      rows.push(row("ca", "Certificate authority (CA)",
        "Trust it once per device and browser to remove the certificate warning.",
        esc(`${d.ca.name || cn(d.ca.subject)} · valid until ${day(d.ca.not_after)} · SHA-256 ${d.ca.fingerprint_sha256 || "?"}`), ""));
    }
    const tools = [];
    if (d.ca && !d.ca.error) {
      tools.push(`<a class="btn btn-sm btn-primary" href="${API}/ca.crt" download="tuxwall-ca.crt">Download CA certificate</a>`);
    }
    if (active && d.installed && d.applied === false) {
      tools.push(`<button class="btn btn-sm btn-primary" type="button" data-https-act="apply"${busy ? " disabled" : ""}>Apply now</button>`);
    }
    if (active && d.installed && d.in_use !== "custom") {
      tools.push(`<button class="btn btn-sm" type="button" data-https-act="regenerate"${busy ? " disabled" : ""}>Regenerate certificate</button>`);
    }
    tools.push(`<button class="btn btn-sm" type="button" data-https-act="reload"${busy ? " disabled" : ""}>Re-check</button>`);
    if (location.protocol === "http:" && active && d.urls && d.urls.length) {
      tools.push(`<a class="btn btn-sm" href="https://${esc(location.host)}${esc(location.pathname)}#settings">Open over HTTPS</a>`);
    }
    let own = "";
    if (active && d.installed) {
      const cc = d.custom || {};
      own = `
        <details class="theme-format-details"${d.custom ? " open" : ""}>
          <summary class="muted">Use my own certificate</summary>
          <p class="muted">Files on the router (PEM, unencrypted key), e.g. from your own CA. The pair is checked with openssl and <code>nginx -t</code> before it is used; renewal is up to you.</p>
          <div class="alerts-grid">
            <label class="fw-field alerts-wide"><span>Certificate (full chain)</span>
              <input type="text" id="https-own-cert" placeholder="/etc/ssl/certs/router.pem" autocomplete="off" spellcheck="false" value="${esc(cc.path || "")}"></label>
            <label class="fw-field alerts-wide"><span>Private key</span>
              <input type="text" id="https-own-key" placeholder="/etc/ssl/private/router.key" autocomplete="off" spellcheck="false" value="${esc(cc.key_path || "")}"></label>
          </div>
          <div class="card-toolbar">
            <button class="btn btn-sm" type="button" data-https-act="own"${busy ? " disabled" : ""}>Use these files</button>
            ${d.custom ? `<button class="btn btn-sm" type="button" data-https-act="own-clear"${busy ? " disabled" : ""}>Back to the TuxWall certificate</button>` : ""}
          </div>
        </details>`;
    }
    el.innerHTML = `
      <div class="cs-set">${rows.join("")}<p class="cs-set-msg" id="https-msg" role="status" aria-live="polite"></p></div>
      <div class="card-toolbar">${tools.join("")}</div>
      ${d.ca && !d.ca.error ? trustHelp(d) : ""}
      ${own}`;
    bind();
  }

  function say(text) {
    const m = document.getElementById("https-msg");
    if (m) m.textContent = text || "";
  }

  function bind() {
    const el = body();
    if (!el) return;
    el.querySelectorAll("[data-https]").forEach((inp) => inp.addEventListener("change", () => onToggle(inp)));
    el.querySelectorAll("[data-https-act]").forEach((b) => b.addEventListener("click", () => onAction(b.dataset.httpsAct)));
  }

  async function load() {
    try {
      const res = await fetch(API + "/status", { cache: "no-store", credentials: "same-origin" });
      if (res.status === 401 || res.status === 403) { isAdmin = false; render(); return; }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      data = await res.json();
      error = "";
      loadedAt = Date.now();
    } catch (err) {
      error = err.message || String(err);
    }
    render();
  }

  async function post(path, payload, doneMsg) {
    busy = true;
    render();
    say("Working… (certificate, nginx -t, reload)");
    let msg = "";
    try {
      const res = await fetch(API + path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        cache: "no-store",
        body: JSON.stringify(payload || {}),
      });
      let d = null;
      try { d = await res.json(); } catch (_) { d = null; }
      if (d && d.status) data = d.status;
      if (!res.ok || !d || !d.ok) throw new Error((d && (d.error || d.message)) || `HTTP ${res.status}`);
      msg = doneMsg || d.message || "Done.";
    } catch (err) {
      // a fetch TypeError = the connection dropped: switching the port 443
      // setup can need a short nginx restart (the change itself went through)
      msg = err instanceof TypeError
        ? "The connection dropped while nginx restarted - reload the page in a few seconds."
        : `Not changed: ${err.message || err}`;
    } finally {
      busy = false;
      render();
      say(msg);
    }
    return data;
  }

  async function onToggle(inp) {
    const kind = inp.dataset.https;
    const want = !!inp.checked;
    inp.checked = !want;                    // stays truthful until the server agrees
    if (busy) return;
    if (kind === "enabled" && !want) {
      if (!await confirmDlg("Turn TuxWall HTTPS off? The dashboard is then served over plain http only (passwords and the session cookie travel unencrypted on the LAN).")) return;
    }
    if (kind === "redirect" && !want) {
      if (!await confirmDlg("Stop redirecting http to https? Browsers that open http:// keep using the unencrypted dashboard. Use this only for integrations that cannot do https yet.")) return;
    }
    if (kind === "hsts" && want) {
      if (!await confirmDlg("Switch HSTS on? For a year, browsers that saw it refuse plain http for this router and do not let you click through certificate warnings. If a device does not trust the TuxWall CA (or the certificate breaks), that device cannot open the dashboard by this name or address until it does. Only continue when every device you use trusts the CA.")) return;
    }
    const d = await post("/settings", { [kind]: want });
    if (kind === "enabled" && d) {
      if (!want && location.protocol === "https:" && d.mode !== "active") {
        say("HTTPS is off. Open the dashboard at http://" + location.host + "/");
      } else if (want && location.protocol === "http:" && d.mode === "active") {
        say("HTTPS is on. Use “Open over HTTPS” (trust the CA first to avoid the browser warning).");
      }
    }
  }

  async function onAction(act) {
    if (busy) return;
    if (act === "reload") { say(""); await load(); return; }
    if (act === "apply") {
      await post("/settings", { enabled: true }, "HTTPS applied (nginx -t passed, reloaded).");
      return;
    }
    if (act === "regenerate") {
      if (!await confirmDlg("Issue a new server certificate now? The CA stays the same, so devices that trust it keep working.")) return;
      await post("/regenerate", {}, "New certificate issued and nginx reloaded.");
      return;
    }
    if (act === "own") {
      const cert = (document.getElementById("https-own-cert") || {}).value || "";
      const key = (document.getElementById("https-own-key") || {}).value || "";
      if (!cert.trim() || !key.trim()) { say("Enter both file paths."); return; }
      await post("/custom-cert", { cert: cert.trim(), key: key.trim() }, "Your certificate is in use.");
      return;
    }
    if (act === "own-clear") {
      await post("/custom-cert", { clear: true }, "Back to the TuxWall certificate.");
    }
  }

  function setAdmin(v) {
    isAdmin = !!v;
    if (isAdmin && (!data || Date.now() - loadedAt > 30000)) load();
    else render();
  }

  document.addEventListener("tw:role", (e) => setAdmin(e.detail && e.detail.admin));
  document.addEventListener("click", (e) => {
    const t = e.target.closest && e.target.closest('#settings-subtabs [data-settings-pane="security"]');
    if (t && isAdmin && !busy && Date.now() - loadedAt > 5000) load();
  });
  window.twHttpsSettings = { refresh: load, get data() { return data; } };
})();
