/* Suricata rule suppression (3.3.7): the "Suppress rule" dialog (opened from
   Security > Sensors alert rows - dashboard.js renderSuricata - and from IDS
   findings in the Clients device panel - devices.js) and the "Suppressed
   rules" card on Security > Sensors with Unsuppress.
   Scope: network-wide (default; `suppress gen_id 1, sig_id N`) or one device
   (its current v4/v6 addresses, `track by_either`; addresses change, so the
   dialog says network-wide is the robust choice for INFO/POLICY rules).
   Rules that are not INFO/POLICY-like get a warning, never a block.
   Data: GET /api/security/suricata/suppress, POST {action add|remove}
   (admin + same Origin; 202 + background job: suricata -T, write TuxWall's
   block in threshold.config, reload-rules, restore on failure).
   Markup: index.html #sur-s-modal, #sur-sup-card; shared classes only
   (modal, dev-q-mode, alerts-grid, fw-field, vl-info, badge, btn, table-wrap). */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
  const confirmDlg = (msg) => (window.twConfirm || ((m) => Promise.resolve(window.confirm(m))))(msg);
  const num = (n) => (Number(n) || 0).toLocaleString();
  const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "—");
  // the classes device monitoring ignores as noise (suricata_suppress.LOW_RISK_PREFIXES)
  const LOW_RISK = ["SURICATA ", "ET INFO", "ET POLICY", "ET SCAN", "ET HUNTING", "ET DNS ", "ET GAMES", "ET CHAT",
    "ET P2P", "ET USER_AGENTS", "GPL ICMP", "ET DROP", "ET CINS", "ET DSHIELD", "ET COMPROMISED", "ET TOR",
    "ET 3CORESEC", "GPL SCAN", "GPL POLICY", "ET VOIP", "GPL INFO"];
  const API = "/api/security/suricata/suppress";

  let isAdmin = false;
  let data = null;
  let pollTimer = null;
  let pending = null;            // the dialog's alert

  const risky = (sig) => !LOW_RISK.some((p) => String(sig || "").toUpperCase().startsWith(p));

  async function getJSON(url) {
    const res = await fetch(url, { cache: "no-store", credentials: "same-origin" });
    let d = null;
    try { d = await res.json(); } catch (_) { d = null; }
    if (!res.ok) throw new Error((d && d.error) || `HTTP ${res.status}`);
    return d || {};
  }

  async function post(body) {
    const res = await fetch(API, {
      method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
      cache: "no-store", body: JSON.stringify(body || {}),
    });
    let d = null;
    try { d = await res.json(); } catch (_) { d = null; }
    return { status: res.status, ok: res.ok && d && d.ok !== false, data: d || {} };
  }

  // ── dialog ───────────────────────────────────────────────────────────────
  /** a = {sid, sig, category, severity, device?, device_name?, ip?, addrs?} */
  function open(a) {
    const m = $("sur-s-modal");
    if (!m || !isAdmin || !a || !a.sid) return;
    pending = a;
    const warn = risky(a.sig);
    const devLabel = a.device_name || a.ip || "";
    const canDevice = !!(a.device || a.ip);
    const addrs = (a.addrs || []).filter(Boolean);
    const opt = (val, checked, title, sub) => `<label class="dev-q-mode"><input type="radio" name="sur-s-scope" value="${val}"${checked ? " checked" : ""}>
          <span><b>${title}</b><br><span class="muted">${sub}</span></span></label>`;
    $("sur-s-body").innerHTML = `
      <h3 id="sur-s-title">Suppress Suricata rule</h3>
      <p class="muted dev-small"><b>${esc(a.sig || "Signature")}</b><br>SID <span class="mono">${esc(a.sid)}</span>${a.category ? ` · ${esc(a.category)}` : ""}${a.severity ? ` · ${esc(String(a.severity).toUpperCase())}` : ""}</p>
      ${warn ? `<div class="vl-info sur-s-warn"><p><b>This is not an INFO or POLICY rule.</b> Malware, trojan, exploit and attack-response signatures point at real attacks — suppressing one can hide an infected device. Prefer <b>Only this device</b>, or mark the finding expected in the device panel.</p></div>` : ""}
      <div class="dev-q-modes">
        ${opt("network", true, "Network-wide", `<span class="mono">suppress gen_id 1, sig_id ${esc(a.sid)}</span> — the robust choice for INFO/POLICY rules`)}
        ${canDevice ? opt("device", false, `Only this device${devLabel ? `: ${esc(devLabel)}` : ""}`,
          `Matches its current addresses${addrs.length ? ` (${addrs.map((x) => `<span class="mono">${esc(x)}</span>`).join(", ")})` : ""} as source or destination. Addresses change (new DHCP lease, IPv6 privacy addresses) — the rule then stops matching and the alerts come back.`) : ""}
      </div>
      <div class="alerts-grid dev-q-grid">
        <label class="fw-field"><span>Note (optional)</span><input type="text" id="sur-s-note" maxlength="200" autocomplete="off" placeholder="e.g. ad lookups the DNS blocklist already stops"></label>
      </div>
      <p class="muted dev-small">Suricata stops raising this alert everywhere (this table, device monitoring, Tripwire). TuxWall tests the change with <span class="mono">suricata -T</span>, writes it to its own block in threshold.config and reloads the rules (about a minute on a full ruleset); if Suricata does not take it, the previous file is restored. Undo it any time under <b>Suppressed rules</b>.</p>
      <div class="login-error dev-q-err" id="sur-s-err" hidden></div>
      <div class="vlan-modal-actions dev-q-actions">
        <button class="btn btn-primary" type="button" id="sur-s-go">Suppress</button>
        <button class="btn" type="button" id="sur-s-cancel">Cancel</button>
      </div>`;
    m.hidden = false;
    $("sur-s-cancel").addEventListener("click", close);
    $("sur-s-go").addEventListener("click", submit);
  }

  function close() {
    const m = $("sur-s-modal");
    if (m) m.hidden = true;
  }

  async function submit() {
    const a = pending;
    if (!a) return;
    const err = $("sur-s-err");
    err.hidden = true;
    const scope = (document.querySelector('input[name="sur-s-scope"]:checked') || {}).value || "network";
    const body = { action: "add", sid: Number(a.sid), scope, sig: a.sig || "", category: a.category || "", note: $("sur-s-note").value };
    if (scope === "device") {
      if (a.device) body.device = a.device;
      else body.ip = a.ip;
    }
    const go = $("sur-s-go");
    go.disabled = true;
    const r = await post(body);
    go.disabled = false;
    if (!r.ok) {
      err.textContent = r.data.error || `Not saved (HTTP ${r.status})`;
      err.hidden = false;
      return;
    }
    close();
    say(`Suppressing SID ${a.sid}: testing and reloading Suricata…`);
    poll(0);
  }

  // ── Suppressed rules card ────────────────────────────────────────────────
  function say(msg) {
    const el = $("sur-sup-job");
    if (el) el.textContent = msg || "";
  }

  function scopeText(e) {
    if (e.scope !== "device") return "Network-wide";
    return `Device: ${esc(e.device_name || e.device || "?")}<br><span class="muted mono">${(e.addrs || []).map(esc).join(", ")}</span>`;
  }

  function render() {
    const body = $("sur-sup-body");
    const badge = $("sur-sup-badge");
    if (!body || !data) return;
    if (data.error && !data.entries) {
      body.innerHTML = `<p class="login-error">${esc(data.error)}</p>`;
      return;
    }
    const list = data.entries || [];
    if (badge) {
      badge.textContent = list.length ? `${num(list.length)} rule${list.length === 1 ? "" : "s"}` : "none";
      badge.className = "badge " + (list.length ? "badge-static" : "");
    }
    const job = data.job || {};
    const busy = !!job.running;
    const rows = list.map((e) => `<tr>
        <td><b>${esc(e.sig || "—")}</b>${e.risky ? ` <span class="badge sev-MEDIUM" title="Not an INFO/POLICY rule">not INFO</span>` : ""}${e.category ? `<br><span class="muted">${esc(e.category)}</span>` : ""}</td>
        <td class="mono">${esc(e.sid)}</td>
        <td>${scopeText(e)}</td>
        <td>${esc(e.note || "")}</td>
        <td title="${esc(when(e.at))}">${esc(e.at ? new Date(e.at * 1000).toLocaleDateString() : "—")}${e.by ? ` · ${esc(e.by)}` : ""}</td>
        <td>${num(e.hits_24h)}</td>
        <td class="td-right"><button class="btn btn-sm btn-ghost" type="button" data-sur-unsup="${esc(e.key)}"${busy ? " disabled" : ""}>Unsuppress</button></td></tr>`).join("");
    const hand = data.hand || [];
    body.innerHTML = (data.error ? `<p class="login-error">${esc(data.error)}</p>` : "") +
      (list.length
        ? `<div class="table-wrap"><table class="dev-table" id="sur-sup-table"><thead><tr><th>Signature</th><th>SID</th><th>Scope</th><th>Note</th><th>Suppressed</th><th title="Alerts of this rule in the 24 hours before it was suppressed">Hits / 24 h before</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
        : `<p class="muted sur-sup-empty">No rules suppressed from the dashboard.</p>`) +
      (hand.length ? `<p class="muted sur-sup-hand">Also in threshold.config, written by hand (not managed here): ${num(hand.length)} suppress line${hand.length === 1 ? "" : "s"} (SID ${hand.slice(0, 12).map((h) => esc(h.sid)).join(", ")}${hand.length > 12 ? ", …" : ""}).</p>` : "");
    if (busy) say(`${job.action === "remove" ? "Unsuppressing" : "Suppressing"} SID ${job.sid}: testing and reloading Suricata…`);
    else if (job.finished) say(job.ok ? `SID ${job.sid}: ${job.message}` : `SID ${job.sid} not changed: ${job.message}`);
  }

  async function load() {
    if (!isAdmin || !$("sur-sup-card")) return null;
    try {
      data = await getJSON(API);
    } catch (e) {
      data = { error: e.message };
    }
    render();
    return data;
  }

  function poll(n) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(async () => {
      const d = await load();
      if (d && d.job && d.job.running && n < 100) poll(n + 1);
      else {
        if (typeof window.twRefreshSuricata === "function") window.twRefreshSuricata();
        document.dispatchEvent(new CustomEvent("tw:suricata-suppress", { detail: d }));
      }
    }, n ? 3000 : 800);
  }

  async function unsuppress(btn) {
    if (!(await confirmDlg("Unsuppress this rule? Suricata raises its alerts again after the reload."))) return;
    btn.disabled = true;
    const r = await post({ action: "remove", key: btn.dataset.surUnsup });
    if (!r.ok) {
      btn.disabled = false;
      say(r.data.error || `Failed (HTTP ${r.status})`);
      return;
    }
    say("Unsuppressing: testing and reloading Suricata…");
    poll(0);
  }

  function sensorsVisible() {
    const p = document.querySelector('#view-security .fw-pane[data-sec-pane="sensors"]');
    return !!p && !p.hidden && !document.getElementById("view-security").hidden;
  }

  function setRole(admin) {
    isAdmin = !!admin;
    const card = $("sur-sup-card");
    if (card) card.hidden = !isAdmin;
    if (!isAdmin) close();
    else if (sensorsVisible()) load();
  }

  function init() {
    const m = $("sur-s-modal");
    if (m) {
      $("sur-s-close").addEventListener("click", close);
      m.addEventListener("click", (e) => { if (e.target === m) close(); });
    }
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && m && !m.hidden) close(); });
    document.addEventListener("click", (e) => {
      const u = e.target.closest && e.target.closest("[data-sur-unsup]");
      if (u) unsuppress(u);
      const t = e.target.closest && e.target.closest('#sec-subtabs [data-sec-pane="sensors"]');
      if (t && isAdmin) setTimeout(load, 0);
    });
  }

  document.addEventListener("tw:role", (e) => setRole(e.detail && e.detail.admin));
  document.addEventListener("tw:view", (e) => {
    if (e.detail && e.detail.view === "security" && isAdmin) setTimeout(() => { if (sensorsVisible()) load(); }, 0);
  });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();

  window.twSuricataSuppress = { open, refresh: load, risky };
})();
