/* Device monitoring UI (3.3.7): the device panel and quarantine dialog on
   Clients (rows of the device table open it - dashboard.js merges the
   inventory into the lease table and calls twDevices.open), the "Device
   threats" card on Security, the "Flagged devices" figure on the Overview
   Security monitor, and Settings > Threat: monitoring sources and their
   warnings (Suricata without a LAN interface, Zeek without MACs / with bad
   checksums), threat intelligence (feeds, abuse.ch Auth-Key, local
   indicators); Settings > Alerts > Device alerts. The same source warnings
   show on Clients and on the Security card, with a link to Settings > Threat
   (links: [data-tw-settings="<pane>"] -> window.twSettings.open).
   Data: GET /api/devices/summary, /feeds (everyone), /api/devices/<id>,
   /indicators, /alerts, /findings/recent (admin); POST /api/devices/<id>/{quarantine,
   unquarantine,rename,expected,new-ack}, /api/devices/feeds/{update,key},
   /api/devices/indicators, /api/devices/alerts (admin + same Origin).
   The per-device outbound profile ("LAN Device Activity", formerly a
   Security card) comes from GET /api/security/zeek. Markup: index.html
   (#dev-modal, #dev-q-modal, #dev-threat-card, #dev-threat-table, #dev-src-card, #dev-src-hint,
   #ti-card, #ti-viewer-card, #dev-alerts-card, #ov-dev-flagged); shared classes only (card, modal, badge, dot, btn,
   vl-info, alerts-grid, ov-kv, chart-legend, bw-canvas). */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
  const confirmDlg = (msg) => (window.twConfirm || ((m) => Promise.resolve(window.confirm(m))))(msg);
  const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  const SEV_CLASS = { critical: "badge-err", high: "sev-HIGH", medium: "sev-MEDIUM", low: "badge-static", info: "badge-static" };
  const HEALTH = {
    critical: ["Critical", "badge-err", "dot-err"], warning: ["Warning", "sev-MEDIUM", "dot-warn"],
    new: ["New", "", "dot-new"], normal: ["Normal", "badge-ok", "dot-ok"],
  };
  const KIND_LABEL = {
    c2_connection: "Botnet C2 connection", intel_connection: "Malware host connection",
    intel_attempt: "Blocked/failed connection attempt", intel_inbound: "Inbound from a listed host",
    dns_lookup: "Malware domain lookup", dns_blocked: "Blocked malware domain lookup", ids_alert: "IDS alert",
  };
  const EXPIRY_LABEL = { none: "No expiry", "1h": "1 hour", "24h": "24 hours", "7d": "7 days" };
  const POLL_MS = 30000;

  let isAdmin = false;
  let roleKnown = false;
  let activeView = "";
  let pollTimer = null;
  let current = null;           // {id, detail, zeek}
  let tiData = null;
  let recent = [];              // newest not-expected findings (admin), for the Security card + popup

  // ── helpers ──────────────────────────────────────────────────────────────
  async function getJSON(url) {
    const res = await fetch(url, { cache: "no-store", credentials: "same-origin" });
    let d = null;
    try { d = await res.json(); } catch (_) { d = null; }
    if (!res.ok) throw Object.assign(new Error((d && d.error) || `HTTP ${res.status}`), { status: res.status, data: d });
    return d || {};
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
      cache: "no-store", body: JSON.stringify(body || {}),
    });
    let d = null;
    try { d = await res.json(); } catch (_) { d = null; }
    return { status: res.status, ok: res.ok && d && d.ok !== false, data: d || {} };
  }

  function bytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
    return `${(n / 1073741824).toFixed(2)} GB`;
  }
  const num = (n) => (Number(n) || 0).toLocaleString();
  function ago(ts) {
    if (!ts) return "—";
    const d = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (d < 60) return "just now";
    if (d < 3600) return `${Math.floor(d / 60)} min ago`;
    if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
    return `${Math.floor(d / 86400)} d ago`;
  }
  const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "—");
  const sevBadge = (sev) => `<span class="badge ${SEV_CLASS[sev] || ""}">${esc(SEV_LABEL[sev] || sev || "?")}</span>`;
  function healthBadge(h) {
    const x = HEALTH[h] || HEALTH.normal;
    return `<span class="badge ${x[1]}">${x[0]}</span>`;
  }
  function cssVar(name, fb) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fb;
  }
  function kv(label, value, raw) {
    return `<div class="ov-kv-row"><span class="ov-kv-label">${esc(label)}</span><span class="ov-kv-value">${raw ? value : esc(value)}</span></div>`;
  }

  // ── Security card + Overview figure ─────────────────────────────────────
  async function loadSummary() {
    let s;
    try {
      s = await getJSON("/api/devices/summary");
    } catch (_) {
      return;
    }
    const ov = $("ov-dev-flagged");
    if (ov) {
      ov.textContent = s.available ? num(s.flagged) : "—";
      ov.title = s.available
        ? `${num(s.flagged)} flagged · ${num(s.quarantined)} quarantined · ${num(s.devices)} devices`
        : "Device monitoring has no data yet";
    }
    renderThreatCard(s);
    renderSourceHint(s.warnings || []);
  }

  const settingsLink = (pane, text) => `<a href="#settings/${pane}" data-tw-settings="${pane}">${esc(text)}</a>`;

  function warningLines(list) {
    return list.map((w) => `<p>${esc(w.text)}.</p>`).join("");
  }

  // Clients page: why some detections are missing (DW-2 / DW-12)
  function renderSourceHint(list) {
    const el = $("dev-src-hint");
    if (!el) return;
    el.hidden = !list.length;
    el.innerHTML = list.length ? `${warningLines(list)}<p>How to fix it: ${settingsLink("threat", "Settings → Threat")}.</p>` : "";
  }

  function renderThreatCard(s) {
    const card = $("dev-threat-card");
    const body = $("dev-threat-body");
    if (!card || !body) return;
    card.hidden = !roleKnown;
    const hint = $("dev-threat-hint");
    if (!s.available) {
      if (hint) hint.textContent = "not running";
      body.innerHTML = `<p class="vl-info">Device monitoring has no data yet — tuxwall-devicewatch.service is not running or has not finished its first pass.</p>`;
      return;
    }
    if (hint) hint.textContent = s.running ? `${num(s.devices)} devices · ${num(s.online)} online` : "engine stalled — data may be old";
    const w = s.worst;
    const worst = w
      ? `<div class="dev-threat-worst">${sevBadge(w.severity)} <span>${esc(w.reason)}</span>
           <span class="muted">— ${esc(w.device_name || "device")}, ${esc(ago(w.last))}</span></div>`
      : `<div class="dev-threat-worst muted">No device flagged. ${s.feeds_total ? (s.feeds_ok < s.feeds_total
          ? settingsLink("threat", `${num(s.feeds_ok)} of ${num(s.feeds_total)} threat feeds current`) + "."
          : `${num(s.feeds_ok)} of ${num(s.feeds_total)} threat feeds current.`) : ""}</div>`;
    const warn = (s.warnings || []).length
      ? `<div class="vl-info">${warningLines(s.warnings)}<p>How to fix it: ${settingsLink("threat", "Settings → Threat")}.</p></div>` : "";
    body.innerHTML = `
      <div class="dev-threat-stats">
        <div class="dev-threat-stat${s.flagged ? " is-bad" : ""}"><b>${num(s.flagged)}</b><small>flagged</small></div>
        <div class="dev-threat-stat${s.quarantined ? " is-bad" : ""}"><b>${num(s.quarantined)}</b><small>quarantined</small></div>
        <div class="dev-threat-stat"><b>${num(s.new_24h)}</b><small>new (24 h)</small></div>
        ${worst}
        <button class="btn btn-sm" type="button" id="dev-threat-review">Review devices</button>
        ${isAdmin ? `<button class="btn btn-sm btn-ghost" type="button" data-tw-settings="threat">Threat settings</button>` : ""}
      </div>${warn}
      ${isAdmin ? "" : `<p class="muted dev-threat-recent">Details are for administrators</p>`}`;
    const rec = $("dev-threat-recent");
    if (rec) rec.hidden = !isAdmin;
    $("dev-threat-review").addEventListener("click", () => {
      if (window.twClients) window.twClients.showFlagged(!!(s.flagged || s.quarantined));
    });
    if (isAdmin) {
      renderRecent();
      loadRecent();
    }
  }

  // ── recent threats: Security ▸ Local table (25 rows, then "Show all") ───
  // The table is static markup (#dev-threat-table) so dashboard.js's shared
  // row-cap helper can attach to it at page load.
  async function loadRecent() {
    try {
      const d = await getJSON("/api/devices/findings/recent?limit=50");
      recent = Array.isArray(d.findings) ? d.findings : [];
    } catch (_) {
      return;
    }
    renderRecent();
  }

  const ACTION_LABEL = { blocked: "blocked", attempted: "attempted, no answer", lookup: "looked up", contacted: "contacted" };

  function recentRows(list) {
    return list.map((x) => {
      // a new device (Inventory): no host involved, dismissed instead of marked expected
      const isNew = x.kind === "new_device";
      const host = isNew
        ? `—${x.detail ? `<br><span class="muted">${esc(x.detail)}</span>` : ""}`
        : `<span class="mono">${esc(x.indicator || "—")}</span><br><span class="muted">${esc(ACTION_LABEL[x.action] || x.action)}</span>`;
      const act = isNew
        ? `<button class="btn btn-sm btn-ghost" type="button" data-dev-new-ack="${esc(x.device)}" title="Dismiss: removes this new-device row">Dismiss</button>`
        : `<button class="btn btn-sm btn-ghost" type="button" data-dev-thr-exp="${esc(x.id)}" data-dev="${esc(x.device)}" title="Mark as expected: stops counting toward health and stops its alerts">Mark expected</button>`;
      return `<tr>
        <td>${sevBadge(x.severity)}</td>
        <td>${esc(x.feed)}</td>
        <td>${host}</td>
        <td><a href="#clients" data-dev-goto="${esc(x.device)}">${esc(x.device_name || x.device)}</a></td>
        <td title="${esc(when(x.ts))}">${esc(ago(x.ts))}</td>
        <td class="td-right">${act}</td>
      </tr>`;
    }).join("");
  }

  function renderRecent() {
    const table = $("dev-threat-table");
    if (!table) return;
    const wrap = table.closest(".table-wrap");
    const empty = $("dev-threat-empty");
    table.tBodies[0].innerHTML = recentRows(recent);
    if (wrap) wrap.hidden = !recent.length;
    if (empty) empty.hidden = !!recent.length;
  }

  async function markExpected(btn) {
    if (!(await confirmDlg("Mark this finding as expected? It stops counting toward the device's health and stops its alerts. Unmark it any time from the device panel."))) return;
    btn.disabled = true;
    const r = await post(`/api/devices/${btn.dataset.dev}/expected`, { finding: btn.dataset.devThrExp, expected: true });
    if (!r.ok) {
      btn.disabled = false;
      const msg = $("dev-thr-msg");
      if (msg) msg.textContent = r.data.error || "Failed";
      return;
    }
    await loadRecent();
    loadSummary();
    if (window.twClients) window.twClients.refresh();
  }

  async function dismissNew(btn) {
    btn.disabled = true;
    const r = await post(`/api/devices/${btn.dataset.devNewAck}/new-ack`, {});
    if (!r.ok) {
      btn.disabled = false;
      const msg = $("dev-thr-msg");
      if (msg) msg.textContent = r.data.error || "Failed";
      return;
    }
    await loadRecent();
  }

  function localPaneVisible() {
    const p = document.querySelector('#view-security .fw-pane[data-sec-pane="local"]');
    return !!p && !p.hidden;
  }

  function schedulePoll() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    if (activeView === "overview" || activeView === "clients" || (activeView === "security" && localPaneVisible())) {
      loadSummary();
      pollTimer = setInterval(() => { if (!document.hidden) loadSummary(); }, POLL_MS);
    }
  }

  // ── device panel ─────────────────────────────────────────────────────────
  function modal() { return $("dev-modal"); }

  function closePanel() {
    const m = modal();
    if (m) m.hidden = true;
    current = null;
  }

  async function open(id) {
    const m = modal();
    if (!m || !isAdmin) return;
    current = { id, detail: null, zeek: null };
    $("dev-body").innerHTML = `<p class="muted">Loading…</p>`;
    m.hidden = false;
    await reload();
  }

  async function reload() {
    if (!current) return;
    const id = current.id;
    const [detail, zeek] = await Promise.allSettled([getJSON("/api/devices/" + id), getJSON("/api/security/zeek")]);
    if (!current || current.id !== id) return;
    if (detail.status !== "fulfilled") {
      $("dev-body").innerHTML = `<p class="login-error">${esc(detail.reason.message || "Could not load the device")}</p>`;
      return;
    }
    current.detail = detail.value;
    current.zeek = zeek.status === "fulfilled" ? zeek.value : null;
    renderPanel();
  }

  function leaseFor(dev) {
    const v4 = [...(dev.current_ips || []), ...(dev.ips || [])].find((ip) => !ip.includes(":") && !ip.includes("/"));
    return dev.mac && v4 ? { ip: v4, mac: dev.mac } : null;
  }

  function renderPanel() {
    const { device: d, findings, quarantine: q } = current.detail;
    const f = findings || [];
    const name = d.name || d.mac || d.id;
    // current addresses first; the others were seen in the last 24 h (DW-5)
    const cur = new Set(d.current_ips || []);
    const addrs = [...new Set([...(d.current_ips || []).filter((a) => !a.includes("/")), ...(d.ips || []), ...(d.ipv6 || [])])];
    const zone = [d.zone_name || d.zone, d.vlan != null ? `VLAN ${d.vlan}` : "", d.iface].filter(Boolean).join(" · ");
    const qBox = q && q.active ? `
      <div class="vl-info dev-q-status">
        <p><b>Quarantined</b> — ${q.mode === "isolate" ? "isolated: nothing is forwarded to or from this device; of the router it reaches only DNS, DHCP and ping" : "internet blocked: the device keeps the LAN and the router, nothing reaches the WAN"}.</p>
        <p class="muted">Since ${esc(when(q.since))} by ${esc(q.by || "?")} · ${q.expires ? `expires ${esc(when(q.expires))}` : "no expiry"}
          · matches ${esc([q.mac, ...(q.ips || []), ...(q.ipv6 || []), ...(q.nets || [])].filter(Boolean).join(", ") || "—")}</p>
      </div>` : "";
    const banNote = q && (q.lease_banned || []).length ? `<p class="vl-info">The Access column also bans ${esc(q.lease_banned.join(", "))} (UFW + DNS). Quarantine and ban are separate — lift each where it was set.</p>` : "";
    const ident = [
      kv("Vendor", d.vendor || "unknown"),
      kv("Type (guess)", (d.type && d.type !== "unknown" ? d.type : "unknown") + (d.type_reason ? ` — from ${d.type_reason}` : "")),
      kv("MAC", d.mac ? esc(d.mac) + (d.private_mac ? ` <span class="badge badge-static" title="A randomised (locally administered) address: the phone or laptop may show a different one on another network or after a reset">private MAC</span>` : "") : "— (VPN peer)", true),
      kv("Addresses", addrs.length ? addrs.map((a) => `<span class="mono">${esc(a)}</span>${cur.size && !cur.has(a) ? ` <span class="muted" title="Used by this device in the last 24 hours, not now">(earlier)</span>` : ""}`).join("<br>") : "—", true),
      kv("Network", zone || "—"),
      kv("First seen", when(d.first_seen)),
      kv("Last seen", `${when(d.last_seen)}${d.online ? " · online" : ""}`),
    ];
    const hostnames = Object.entries(d.hostnames || {}).map(([k, v]) => `${v} (${k})`).join(", ");
    if (hostnames) ident.push(kv("Names seen", hostnames));
    const fRows = f.map((x) => {
      const det = x.details || {};
      const why = [x.indicator ? `<span class="mono">${esc(x.indicator)}</span>` : "",
        det.malware ? esc(det.malware) : "", det.threat ? esc(det.threat) : "",
        det.query && det.query !== x.indicator ? `query <span class="mono">${esc(det.query)}</span>` : "",
        det.category ? esc(det.category) : "", det.listed_status ? esc(det.listed_status) : "",
        det.note ? esc(det.note) : ""].filter(Boolean).join(" · ");
      return `<tr class="${x.expected ? "dev-f-expected" : ""}">
        <td title="first ${esc(when(x.first))}">${esc(ago(x.last))}${x.count > 1 ? `<br><span class="muted">×${num(x.count)}</span>` : ""}</td>
        <td>${sevBadge(x.severity)}</td>
        <td>${esc(x.title || KIND_LABEL[x.kind] || x.kind)}<br><span class="muted">${esc(KIND_LABEL[x.kind] || x.kind)}</span></td>
        <td>${why || "—"}</td>
        <td class="td-right"><button class="btn btn-sm btn-ghost" type="button" data-dev-exp="${esc(x.id)}" data-on="${x.expected ? 0 : 1}" title="${x.expected ? "Count this finding again" : "Mark as expected: stops counting toward health and stops its alerts"}">${x.expected ? "Unmark" : "Expected"}</button></td>
      </tr>`;
    }).join("");
    const tops = (d.top_destinations || []).map((t) => `<tr>
        <td><span class="mono">${esc(t.ip)}</span>${t.name ? `<br><span class="muted">${esc(t.name)}</span>` : ""}</td>
        <td>${esc(t.country || "—")}</td><td>${esc(bytes(t.bytes))}</td><td>${num(t.conns)}</td></tr>`).join("");
    const countries = (d.top_countries || []).map((c) => `<span class="badge badge-static" title="${esc(bytes(c.bytes))} · ${num(c.conns)} connections">${esc(c.iso || c.country || "??")} ${esc(bytes(c.bytes))}</span>`).join(" ");
    const a = d.activity || {};
    const lanAct = lanActivity(d);
    const lease = leaseFor(d);
    const acts = (q && q.actions || []).slice().reverse().map((x) => `<li>${esc(when(x.ts))} — ${esc(x.action)}${x.mode ? ` (${esc(x.mode)})` : ""}${x.code ? ` [${esc(x.code)}]` : ""} by ${esc(x.by || "?")}</li>`).join("");
    $("dev-body").innerHTML = `
      <div class="dev-head">
        <h3 id="dev-title">${esc(name)}</h3>
        ${healthBadge(d.health)} ${q && q.active ? `<span class="badge badge-err">Quarantined</span>` : ""}
        ${d.reason ? `<span class="muted dev-head-reason">${esc(d.reason)}</span>` : ""}
      </div>
      ${qBox}${banNote}
      <div class="dev-actions">
        ${q && q.supported ? (q.active
          ? `<button class="btn btn-sm btn-primary" type="button" data-dev-act="release">Release</button>
             <button class="btn btn-sm" type="button" data-dev-act="quarantine">Change quarantine</button>`
          : `<button class="btn btn-sm btn-danger" type="button" data-dev-act="quarantine">Quarantine…</button>`) : ""}
        <button class="btn btn-sm" type="button" data-dev-act="rename">Rename</button>
        ${lease ? `<button class="btn btn-sm btn-ghost" type="button" data-dev-act="reserve">Reserve IP</button>` : ""}
        <span class="muted" id="dev-msg" role="status" aria-live="polite"></span>
      </div>
      <form class="dev-rename" id="dev-rename" hidden data-nosubmit>
        <input type="text" id="dev-rename-in" maxlength="64" value="${esc(d.name_source === "user" ? d.name : "")}" placeholder="${esc(d.name || "Name")}" autocomplete="off" spellcheck="false">
        <button class="btn btn-sm btn-primary" type="submit">Save name</button>
        <span class="muted">Empty = back to the name the device reports.</span>
      </form>
      <div class="dev-grid">
        <section class="dev-sec">
          <h4>Identity</h4>
          <div class="ov-kv">${ident.join("")}</div>
        </section>
        <section class="dev-sec">
          <h4>Traffic, last 24 h</h4>
          <div class="chart-legend">
            <span class="lg-item"><i style="--lg:var(--accent)"></i>Received today<b>${esc(bytes(a.bytes_in))}</b></span>
            <span class="lg-item"><i style="--lg:var(--amber)"></i>Sent today<b>${esc(bytes(a.bytes_out))}</b></span>
            <span class="lg-item">Today<b>${num(a.conns)} conns · ${num(a.destinations)} destinations</b></span>
          </div>
          <div class="bw-canvas-wrap"><canvas id="dev-chart" class="bw-canvas"></canvas></div>
        </section>
      </div>
      <section class="dev-sec">
        <h4>Findings <span class="muted">(${num((d.findings || {}).active)} active, ${num((d.findings || {}).expected)} expected)</span></h4>
        ${f.length ? `<div class="table-wrap"><table class="dev-table"><thead><tr><th>When</th><th>Severity</th><th>What</th><th>Why (indicator, feed)</th><th></th></tr></thead><tbody>${fRows}</tbody></table></div>`
          : `<p class="muted">No findings — nothing this device did matched a threat feed, a local indicator or an IDS signature (feeds, indicators and monitoring sources: ${settingsLink("threat", "Settings → Threat")}).</p>`}
      </section>
      <div class="dev-grid">
        <section class="dev-sec">
          <h4>Top destinations, 24 h</h4>
          ${tops ? `<div class="table-wrap"><table class="dev-table"><thead><tr><th>Destination</th><th>Country</th><th>Traffic</th><th>Conns</th></tr></thead><tbody>${tops}</tbody></table></div>` : `<p class="muted">No traffic to the internet in the last 24 hours.</p>`}
          ${countries ? `<p class="dev-countries">${countries}</p>` : ""}
        </section>
        <section class="dev-sec">
          <h4>LAN Device Activity <span class="muted">(Zeek, last hour)</span></h4>
          ${lanAct}
          ${acts ? `<h4>Quarantine log</h4><ul class="dev-log">${acts}</ul>` : ""}
        </section>
      </div>`;
    bindPanel(d, lease);
    requestAnimationFrame(() => drawChart($("dev-chart"), d.hourly || []));
  }

  function lanActivity(d) {
    const z = current.zeek;
    if (!z || !z.ok) return `<p class="muted">Zeek data unavailable.</p>`;
    if (!z.enabled) return `<p class="muted">${esc(z.hint || "Zeek is not running.")}</p>`;
    const mine = new Set([...(d.ips || []), ...(d.ipv6 || [])]);
    const rows = (z.devices || []).filter((v) => mine.has(v.device));
    if (!rows.length) return `<p class="muted">No connections to external hosts in the last hour.</p>`;
    return `<div class="ov-kv">${rows.map((v) => [
      kv("Address", v.device),
      kv("External connections", num(v.conns)),
      kv("Distinct peers", num(v.peer_count)),
      kv("Top peer", `${v.top_peer || "—"}${v.top_peer_hits ? ` ×${num(v.top_peer_hits)}` : ""}`),
      kv("Last seen", ago(v.last_ts)),
    ].join("")).join("")}</div>
      <p class="muted dev-small">Many unknown external hosts, or the same host at a fixed interval, is the classic malware check-in pattern.</p>`;
  }

  function say(msg) {
    const el = $("dev-msg");
    if (el) el.textContent = msg || "";
  }

  function bindPanel(d, lease) {
    const body = $("dev-body");
    body.querySelectorAll("[data-dev-act]").forEach((b) => b.addEventListener("click", async () => {
      const act = b.dataset.devAct;
      if (act === "quarantine") openQuarantine(d);
      else if (act === "release") release(d);
      else if (act === "rename") {
        const f = $("dev-rename");
        f.hidden = !f.hidden;
        if (!f.hidden) $("dev-rename-in").focus();
      } else if (act === "reserve" && lease && window.twClients) {
        closePanel();
        window.twClients.reserveFill(lease.ip, lease.mac);
      }
    }));
    $("dev-rename").addEventListener("submit", async (e) => {
      e.preventDefault();
      const r = await post(`/api/devices/${d.id}/rename`, { name: $("dev-rename-in").value });
      if (!r.ok) { say(r.data.error || "Rename failed"); return; }
      await reload();
      say("Renamed.");
      if (window.twClients) window.twClients.refresh();
    });
    body.querySelectorAll("[data-dev-exp]").forEach((b) => b.addEventListener("click", async () => {
      const on = b.dataset.on === "1";
      if (on && !(await confirmDlg("Mark this finding as expected? It stops counting toward the device's health and stops its alerts. Unmark it any time."))) return;
      b.disabled = true;
      const r = await post(`/api/devices/${d.id}/expected`, { finding: b.dataset.devExp, expected: on });
      if (!r.ok) { b.disabled = false; say(r.data.error || "Failed"); return; }
      await reload();
      if (window.twClients) window.twClients.refresh();
    }));
  }

  async function release(d) {
    if (!(await confirmDlg(`Release ${d.name || d.id}? Its network access is restored at once.`))) return;
    const r = await post(`/api/devices/${d.id}/unquarantine`, {});
    if (!r.ok) { say(r.data.error || "Release failed"); return; }
    await reload();
    say("Released.");
    if (window.twClients) window.twClients.refresh();
    loadSummary();
  }

  // hourly traffic: bars (received / sent) in the dashboard's chart style
  function drawChart(canvas, hourly) {
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width, h = rect.height;
    ctx.clearRect(0, 0, w, h);
    const padT = 10, padB = 16, padL = 4, padR = 4;
    const pw = w - padL - padR, ph = h - padT - padB;
    const muted = cssVar("--muted", "#8b949e");
    const n = hourly.length;
    const max = Math.max(1, ...hourly.map((x) => Math.max(x.in || 0, x.out || 0)));
    if (!n || hourly.every((x) => !x.in && !x.out)) {
      ctx.fillStyle = muted;
      ctx.font = "11px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("No traffic in the last 24 hours", w / 2, h / 2);
      return;
    }
    ctx.font = "10px sans-serif";
    for (let i = 0; i <= 4; i++) {
      const y = padT + (ph * i) / 4;
      ctx.globalAlpha = 0.12;
      ctx.strokeStyle = cssVar("--text", "#e6edf3");
      ctx.setLineDash([3, 4]);
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + pw, y); ctx.stroke();
      ctx.setLineDash([]);
      ctx.globalAlpha = 0.8;
      ctx.fillStyle = muted;
      ctx.textAlign = "left";
      if (i < 4) ctx.fillText(bytes(max * (1 - i / 4)), padL + 2, y + 10);
      ctx.globalAlpha = 1;
    }
    const slot = pw / n;
    const bw = Math.max(1, slot / 2 - 1.5);
    const cIn = cssVar("--accent", "#4f8cff"), cOut = cssVar("--amber", "#d29922");
    hourly.forEach((x, i) => {
      const x0 = padL + i * slot + 1;
      const hi = ph * ((x.in || 0) / max), ho = ph * ((x.out || 0) / max);
      ctx.fillStyle = cIn;
      ctx.fillRect(x0, padT + ph - hi, bw, hi);
      ctx.fillStyle = cOut;
      ctx.fillRect(x0 + bw + 1, padT + ph - ho, bw, ho);
    });
    ctx.fillStyle = muted;
    [[0, "left", padL], [Math.floor(n / 2), "center", null], [n - 1, "right", padL + pw]].forEach(([i, align, x]) => {
      const t = new Date((hourly[i].t || 0) * 1000);
      ctx.textAlign = align;
      ctx.fillText(`${String(t.getHours()).padStart(2, "0")}:00`, x == null ? padL + i * slot + slot / 2 : x, padT + ph + 12);
    });
  }

  // ── quarantine dialog ────────────────────────────────────────────────────
  function openQuarantine(d) {
    const m = $("dev-q-modal");
    const q = (current && current.detail && current.detail.quarantine) || {};
    const mode = q.active ? q.mode : "internet";
    const opts = (q.expires_options || Object.keys(EXPIRY_LABEL)).map((k) =>
      `<option value="${esc(k)}"${k === "24h" && !q.active ? " selected" : ""}>${esc(EXPIRY_LABEL[k] || k)}</option>`).join("");
    $("dev-q-body").innerHTML = `
      <h3 id="dev-q-title">Quarantine ${esc(d.name || d.id)}</h3>
      <div class="dev-q-modes">
        <label class="dev-q-mode"><input type="radio" name="dev-q-mode" value="internet"${mode === "internet" ? " checked" : ""}>
          <span><b>Block internet</b><br><span class="muted">The device keeps the LAN and the router (printing, casting, this dashboard); nothing it sends reaches the internet.</span></span></label>
        <label class="dev-q-mode"><input type="radio" name="dev-q-mode" value="isolate"${mode === "isolate" ? " checked" : ""}>
          <span><b>Isolate</b><br><span class="muted">Nothing is forwarded to or from the device — no internet, no other networks or VLANs, no VPN. Of the router it can only reach DNS, DHCP and ping, so it stays diagnosable and can be released.</span></span></label>
      </div>
      <div class="alerts-grid dev-q-grid">
        <label class="fw-field"><span>Ends</span><select id="dev-q-exp">${opts}</select></label>
        <label class="fw-field"><span>Note (optional)</span><input type="text" id="dev-q-note" maxlength="200" autocomplete="off"></label>
      </div>
      <p class="vl-info">Matched by ${d.mac ? `its MAC address (<span class="mono">${esc(d.mac)}</span>) and ` : ""}its current addresses; the router keeps them up to date as they change. It survives reboots${d.private_mac ? ". This device uses a <b>private MAC</b>: if it picks a new one, only its current addresses stay blocked" : ""}.${d.kind === "wg" ? "" : " Devices on the same switch or Wi-Fi network still reach it directly."}</p>
      <div class="login-error dev-q-err" id="dev-q-err" hidden></div>
      <div class="vlan-modal-actions dev-q-actions">
        <button class="btn btn-danger" type="button" id="dev-q-go">Quarantine</button>
        <button class="btn" type="button" id="dev-q-cancel">Cancel</button>
      </div>`;
    m.hidden = false;
    $("dev-q-cancel").addEventListener("click", () => { m.hidden = true; });
    $("dev-q-go").addEventListener("click", () => submitQuarantine(d, false));
  }

  async function submitQuarantine(d, confirmSelf) {
    const mode = (document.querySelector('input[name="dev-q-mode"]:checked') || {}).value;
    const err = $("dev-q-err");
    const go = $("dev-q-go");
    err.hidden = true;
    go.disabled = true;
    const r = await post(`/api/devices/${d.id}/quarantine`, {
      mode, expires: $("dev-q-exp").value, note: $("dev-q-note").value, confirm_self: !!confirmSelf,
    });
    go.disabled = false;
    if (r.status === 409 && r.data.code === "self") {
      err.innerHTML = `<b>This is the device you are using right now.</b> ${esc(r.data.error || "")}
        ${mode === "isolate" ? " You will lose the dashboard on this device; release it from another device." : ""}
        <div class="dev-q-actions"><button class="btn btn-danger btn-sm" type="button" id="dev-q-self">Quarantine my own device</button></div>`;
      err.hidden = false;
      $("dev-q-self").addEventListener("click", () => submitQuarantine(d, true));
      return;
    }
    if (!r.ok) {
      err.textContent = r.data.error || `Not quarantined (HTTP ${r.status})`;
      err.hidden = false;
      return;
    }
    $("dev-q-modal").hidden = true;
    await reload();
    say((r.data.warnings || []).length ? `Quarantined. ${r.data.warnings.join(" ")}` : "Quarantined.");
    if (window.twClients) window.twClients.refresh();
    loadSummary();
  }

  // ── Settings > Threat: monitoring sources + threat intelligence ────────
  const FEED_STATUS = {
    ok: ["Current", "badge-ok"], needs_key: ["Needs Auth-Key", "badge-static"], disabled: ["Off", "badge-static"],
    pending: ["Waiting", ""], error: ["Failed", "badge-err"], stale: ["Old", "sev-MEDIUM"],
  };

  async function loadFeeds() {
    if (!$("dev-src-card") || !roleKnown) return;
    try {
      const [feeds, ind] = await Promise.all([getJSON("/api/devices/feeds"),
        isAdmin ? getJSON("/api/devices/indicators") : Promise.resolve(null)]);
      tiData = { feeds, ind };
    } catch (err) {
      tiData = { error: err.message };
    }
    renderSources();
    if (isAdmin) renderFeeds();
  }

  function renderSources() {
    const body = $("dev-src-body");
    const badge = $("dev-src-badge");
    if (!body || !tiData) return;
    if (tiData.error) {
      body.innerHTML = `<p class="login-error">${esc(tiData.error)}</p>`;
      return;
    }
    const src = tiData.feeds.sources;
    const warns = tiData.feeds.warnings || [];
    if (!src) {
      if (badge) { badge.textContent = "no data"; badge.className = "badge"; }
      body.innerHTML = `<p class="vl-info">Device monitoring has no data yet — tuxwall-devicewatch.service is not running or has not finished its first pass.</p>`;
      return;
    }
    if (badge) {
      badge.textContent = !src.engine_running ? "engine stalled" : warns.length ? `${warns.length} to fix` : "sources OK";
      badge.className = "badge " + (!src.engine_running ? "badge-err" : warns.length ? "sev-MEDIUM" : "badge-ok");
    }
    const z = src.zeek || {};
    const su = src.suricata || {};
    const cap = (su.capture || []).join(", ");
    const rows = [
      kv("Analysis engine", src.engine_running ? "running" : "not running or stalled — data may be old"),
      kv("Zeek connections", z.lines ? `${num(z.lines)} in the last hour · MAC addresses ${z.mac_logging ? "logged" : "not logged"}`
        : (z.conn_ok ? "no connections seen yet" : "no Zeek connection log")),
      kv("Suricata capture", cap ? `${cap}${su.lan_capture === false ? " — no LAN interface" : su.lan_capture ? ` — LAN: ${(su.captured_lan || []).join(", ")}` : ""}` : "unknown"),
      kv("DNS block log", src.unbound_journal ? "read" : "not readable"),
      kv("DHCP leases", src.kea ? "read" : "not readable"),
      kv("Unmatched addresses", `${num(src.unattributed_addresses_1h)} in the last hour`),
    ];
    const wl = warns.map((w) => `<div class="vl-info">
        <p><span class="badge sev-MEDIUM">Fix</span> ${esc(w.text)}.</p>
        ${w.hint ? `<p>On the router: <span class="mono dev-src-cmd">${esc(w.hint)}</span></p>` : ""}
      </div>`).join("");
    body.innerHTML = `${wl}<div class="ov-kv">${rows.join("")}</div>
      <p class="muted dev-small">Unmatched addresses: LAN addresses seen in traffic that could not be tied to a device (typically IPv6 privacy addresses when Zeek logs no MAC addresses).</p>`;
  }

  function renderFeeds(msg) {
    const body = $("ti-body");
    if (!body || !tiData) return;
    const badge = $("ti-badge");
    if (tiData.error) {
      body.innerHTML = `<p class="login-error">${esc(tiData.error)}</p>`;
      return;
    }
    const { feeds, ind } = tiData;
    const rows = feeds.feeds || [];
    const ok = rows.filter((f) => f.status === "ok").length;
    if (badge) {
      badge.textContent = `${ok} of ${rows.length} feeds`;
      badge.className = "badge " + (ok ? "badge-ok" : "");
    }
    const feedRows = rows.map((f) => {
      const st = FEED_STATUS[f.status] || [f.status, ""];
      const c = f.count || {};
      return `<tr>
        <td><a href="${esc(f.homepage)}" target="_blank" rel="noopener">${esc(f.title)}</a>${f.error ? `<br><span class="muted">${esc(f.error)}</span>` : ""}</td>
        <td><span class="badge ${st[1]}">${esc(st[0])}</span></td>
        <td title="${esc(when(f.last_attempt))}">${esc(f.last_ok ? ago(f.last_ok) : "never")}</td>
        <td>${num(c.ip)} IPs · ${num(c.domain)} domains</td>
        <td>${esc(f.licence)}${f.attribution ? `<br><span class="muted">${esc(f.attribution)}</span>` : ""}</td></tr>`;
    }).join("");
    const items = ind.indicators || [];
    const indRows = items.map((x) => `<tr>
        <td class="mono">${esc(x.value)}</td><td>${esc(x.type)}</td><td>${sevBadge(x.severity)}</td>
        <td>${esc(x.note || "")}</td><td>${esc(x.added ? ago(x.added) : "")}${x.added_by ? ` · ${esc(x.added_by)}` : ""}</td>
        <td class="td-right"><button class="btn btn-sm btn-ghost" type="button" data-ti-rm="${esc(x.value)}">Remove</button></td></tr>`).join("");
    body.innerHTML = `
      <div class="table-wrap"><table class="dev-table"><thead><tr><th>Feed</th><th>Status</th><th>Updated</th><th>Entries</th><th>Licence</th></tr></thead>
        <tbody>${feedRows}</tbody></table></div>
      <div class="card-toolbar">
        <button class="btn btn-sm" type="button" id="ti-update">Update now</button>
        <span class="muted">${esc(feeds.note || "")}</span>
      </div>
      <form class="card-toolbar ti-key" id="ti-key" data-nosubmit>
        <label class="fw-field ti-key-field"><span>abuse.ch Auth-Key</span>
          <input type="password" id="ti-key-in" autocomplete="off" spellcheck="false" placeholder="${feeds.key_set ? "Key set — paste a new one to replace it" : "Paste your Auth-Key"}"></label>
        <button class="btn btn-sm btn-primary" type="submit">Save key</button>
        ${feeds.key_set ? `<button class="btn btn-sm btn-ghost" type="button" id="ti-key-clear">Remove key</button>` : ""}
        <span class="badge ${feeds.key_set ? "badge-ok" : "badge-static"}">${feeds.key_set ? "key set" : "no key"}</span>
      </form>
      <h4 class="ti-sub">Local indicators <span class="muted">(${num(items.length)} of ${num(ind.max)})</span></h4>
      <p class="vl-info">Your own list of addresses, networks and domains to watch for — for example from a security advisory. Examples: <span class="mono">192.0.2.10</span>, <span class="mono">198.51.100.0/24</span>, <span class="mono">2001:db8::/48</span>, <span class="mono">bad.example</span>, <span class="mono">*.bad.example</span> (every subdomain). A device that connects to or looks up one of them is flagged with the severity you choose.</p>
      ${items.length ? `<div class="table-wrap"><table class="dev-table"><thead><tr><th>Indicator</th><th>Type</th><th>Severity</th><th>Note</th><th>Added</th><th></th></tr></thead><tbody>${indRows}</tbody></table></div>` : ""}
      <form class="card-toolbar ti-add" id="ti-add" data-nosubmit>
        <input type="text" id="ti-add-val" placeholder="IP, CIDR or domain" autocomplete="off" spellcheck="false">
        <select id="ti-add-sev" aria-label="Severity">
          <option value="high" selected>High</option><option value="critical">Critical</option>
          <option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <input type="text" id="ti-add-note" placeholder="Note (optional)" maxlength="200" autocomplete="off">
        <button class="btn btn-sm btn-primary" type="submit">Add</button>
      </form>
      <p class="muted ti-msg" id="ti-msg" role="status" aria-live="polite">${esc(msg || "")}</p>`;
    $("ti-update").addEventListener("click", async () => {
      const r = await post("/api/devices/feeds/update", {});
      renderFeeds(r.ok ? "Update started — the list refreshes in a minute (abuse.ch is never polled more than every 5 minutes)." : (r.data.error || "Failed"));
      if (r.ok) setTimeout(loadFeeds, 60000);
    });
    $("ti-key").addEventListener("submit", async (e) => {
      e.preventDefault();
      const key = $("ti-key-in").value.trim();
      if (!key) { tiSay("Paste the key first."); return; }
      const r = await post("/api/devices/feeds/key", { key });
      $("ti-key-in").value = "";
      if (!r.ok) { tiSay(r.data.error || "Not saved"); return; }
      await loadFeeds();
      tiSay("Key saved; the keyed feeds download in the background.");
    });
    const clr = $("ti-key-clear");
    if (clr) clr.addEventListener("click", async () => {
      if (!(await confirmDlg("Remove the abuse.ch Auth-Key? URLhaus and ThreatFox stop updating (their last lists stay in use)."))) return;
      const r = await post("/api/devices/feeds/key", { key: "" });
      await loadFeeds();
      tiSay(r.ok ? "Key removed." : (r.data.error || "Failed"));
    });
    $("ti-add").addEventListener("submit", async (e) => {
      e.preventDefault();
      const r = await post("/api/devices/indicators", {
        action: "add",
        indicator: { value: $("ti-add-val").value.trim(), severity: $("ti-add-sev").value, note: $("ti-add-note").value },
      });
      if (!r.ok) { tiSay(r.data.error || "Not added"); return; }
      tiData.ind.indicators = r.data.indicators || [];
      renderFeeds("Added — the engine picks it up within a minute.");
    });
    body.querySelectorAll("[data-ti-rm]").forEach((b) => b.addEventListener("click", async () => {
      const r = await post("/api/devices/indicators", { action: "remove", value: b.dataset.tiRm });
      if (!r.ok) { tiSay(r.data.error || "Failed"); return; }
      tiData.ind.indicators = r.data.indicators || [];
      renderFeeds("Removed.");
    }));
  }

  function tiSay(msg) {
    const el = $("ti-msg");
    if (el) el.textContent = msg || "";
  }

  // ── Settings > Alerts > Device alerts ───────────────────────────────────
  async function loadAlerts() {
    if (!$("dev-alerts-card") || !isAdmin) return;
    try {
      const d = await getJSON("/api/devices/alerts");
      const c = d.config || {};
      $("dev-al-new").value = c.new_device || "lan";
      $("dev-al-sev").value = c.min_severity || "medium";
      $("dev-al-findings").checked = c.findings !== false;
      $("dev-al-quar").checked = c.quarantine !== false;
      $("dev-al-msg").textContent = "";
    } catch (err) {
      $("dev-al-msg").textContent = err.message;
    }
  }

  async function saveAlerts() {
    const btn = $("dev-al-save");
    btn.disabled = true;
    const r = await post("/api/devices/alerts", {
      new_device: $("dev-al-new").value, min_severity: $("dev-al-sev").value,
      findings: $("dev-al-findings").checked, quarantine: $("dev-al-quar").checked,
    });
    btn.disabled = false;
    $("dev-al-msg").textContent = r.ok ? "Saved." : (r.data.error || "Not saved");
  }

  // ── wiring ───────────────────────────────────────────────────────────────
  function setRole(admin) {
    isAdmin = !!admin;
    roleKnown = true;
    const ti = $("ti-card");
    if (ti) ti.hidden = !isAdmin;
    const tv = $("ti-viewer-card");
    if (tv) tv.hidden = isAdmin;
    const al = $("dev-alerts-card");
    if (al) al.hidden = !isAdmin;
    const card = $("dev-threat-card");
    if (card) card.hidden = false;
    if (!isAdmin) { closePanel(); recent = []; renderRecent(); }
    loadSummary();
  }

  function init() {
    const m = modal();
    if (m) {
      $("dev-modal-close").addEventListener("click", closePanel);
      m.addEventListener("click", (e) => { if (e.target === m) closePanel(); });
    }
    document.addEventListener("click", (e) => {
      const g = e.target.closest && e.target.closest("[data-dev-goto]");
      if (g) {
        e.preventDefault();
        if (window.twClients) window.twClients.openDevice(g.dataset.devGoto);
        return;
      }
      const x = e.target.closest && e.target.closest("[data-dev-thr-exp]");
      if (x) markExpected(x);
      const n = e.target.closest && e.target.closest("[data-dev-new-ack]");
      if (n) dismissNew(n);
    });
    const qm = $("dev-q-modal");
    if (qm) {
      $("dev-q-close").addEventListener("click", () => { qm.hidden = true; });
      qm.addEventListener("click", (e) => { if (e.target === qm) qm.hidden = true; });
    }
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if (qm && !qm.hidden) qm.hidden = true;
      else if (m && !m.hidden) closePanel();
    });
    const save = $("dev-al-save");
    if (save) save.addEventListener("click", saveAlerts);
    window.addEventListener("resize", () => {
      if (current && current.detail && m && !m.hidden) drawChart($("dev-chart"), current.detail.device.hourly || []);
    });
  }

  document.addEventListener("tw:role", (e) => setRole(e.detail && e.detail.admin));
  document.addEventListener("tw:view", (e) => {
    activeView = (e.detail && e.detail.view) || "";
    schedulePoll();
    if (activeView === "settings") {
      loadFeeds();
      if (isAdmin) loadAlerts();
    }
  });
  document.addEventListener("click", (e) => {
    const t = e.target.closest && e.target.closest("#settings-subtabs [data-settings-pane]");
    if (!t) return;
    if (t.dataset.settingsPane === "threat") loadFeeds();
    if (t.dataset.settingsPane === "alerts" && isAdmin) loadAlerts();
  });
  // The Security card lives in the "Local" sub-tab: fetch only while it is shown
  document.addEventListener("click", (e) => {
    if (e.target.closest && e.target.closest('#sec-subtabs [data-sec-pane]')) schedulePoll();
  });
  // "Settings → Threat" links (Clients hint, Security card, the device panel)
  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest("[data-tw-settings]");
    if (!a || !window.twSettings) return;
    e.preventDefault();
    closePanel();
    window.twSettings.open(a.dataset.twSettings);
  });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();

  window.twDevices = { open, refreshSummary: loadSummary, reloadFeeds: loadFeeds, close: closePanel };
})();
