/* Community settings: one module, mounted on Security ▸ Deception ▸
   Community (CrowdSec ▸ Community Bans shows their state with a link since
   3.3.7). Renders the two switches into every mounted container and keeps
   them in sync:
     - "Report catches to the community"  -> reporting.json "enabled"
     - "Use community bans" (auto-ban)     -> community-auto.json "enabled"
   Data: GET/POST /api/community/settings (admin; the POST is audited
   server-side with the dashboard user). Never downloads the ban list.
   Every render also refreshes the localStorage auto-ban cache
   (tuxwall-cban-auto) and fires a "tw:community-settings" event on document
   so the CrowdSec page can update its manual ban controls. */
(() => {
  "use strict";

  const API = "/api/community/settings";
  const AUTO_KEY = "tuxwall-cban-auto";
  const mounts = [];
  let data = null;
  let error = "";
  let forbidden = false;
  let busy = false;
  let inflight = null;
  let recheckTimer = null;
  let rechecks = 0;
  let loadedAt = 0;

  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
  const num = (n) => new Intl.NumberFormat().format(Math.round(n || 0));
  function ago(ts) {
    if (!ts) return "never";
    const d = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (d < 60) return "just now";
    if (d < 3600) return `${Math.floor(d / 60)} min ago`;
    if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
    return `${Math.floor(d / 86400)} d ago`;
  }
  const confirmDlg = (msg) => (window.twConfirm || ((m) => Promise.resolve(window.confirm(m))))(msg);

  function readAutoCache() {
    try {
      const v = JSON.parse(localStorage.getItem(AUTO_KEY) || "null");
      if (v && typeof v.enabled === "boolean") return v;
    } catch (_) { /* ignore */ }
    return null;
  }
  function writeAutoCache(a) {
    try {
      localStorage.setItem(AUTO_KEY, JSON.stringify({
        enabled: !!a.enabled,
        last_sync: a.last_sync || 0,
        added_total: a.added_total || 0,
        pending: a.pending || 0,
        ts: Date.now(),
      }));
    } catch (_) { /* ignore */ }
  }

  // ---- state -> words --------------------------------------------------------
  function reportState(r) {
    if (!r) return { badge: "unknown", label: "…", line: "Loading…" };
    if (!r.enabled) {
      const held = (r.queue && r.queue.pending) || 0;
      return {
        badge: "off", label: "Off",
        line: "Off — catches stay on this router (still banned locally)." +
          (held ? ` ${num(held)} queued report${held === 1 ? " is" : "s are"} held until reporting is back on.` : ""),
      };
    }
    let key;
    let badge;
    let label;
    if (r.status === "approved") {
      badge = "on"; label = "Approved";
      key = "Approved by tuxwall.org — your catches count fully";
    } else if (r.status === "pending") {
      badge = "warn"; label = "Pending";
      key = "Key pending approval — reports count at low weight until the tuxwall.org admin approves this install";
    } else if (r.status === "revoked") {
      badge = "bad"; label = "Revoked";
      key = "Key revoked — tuxwall.org refuses this install's reports";
    } else if (!r.key_present) {
      badge = "unknown"; label = "New";
      key = "No key yet — the first catch creates and registers one (pending approval)";
    } else if (r.status_checking && !r.status_checked_at) {
      badge = "unknown"; label = "Checking";
      key = "Checking the key status with tuxwall.org…";
    } else if (r.status_checked_at && !r.registered) {
      badge = "warn"; label = "Not registered";
      key = "Not registered yet — the next report registers this install (pending approval)";
    } else {
      badge = "unknown"; label = "Unknown";
      key = "Key status unavailable (tuxwall.org unreachable) — reports keep queueing and retry";
    }
    const q = r.queue || {};
    const parts = [`last report ${ago(r.last_report)}`, `${num(r.reported_24h)} in 24 h`];
    if (q.pending) parts.push(`${num(q.pending)} queued${q.retrying ? ` (${num(q.retrying)} retrying)` : ""}`);
    else parts.push("queue empty");
    if (q.paused) parts.push("sending paused for maintenance");
    return { badge, label, line: `${key}. On — ${parts.join(" · ")}.` };
  }

  function autoState(a) {
    if (!a) return { badge: "unknown", label: "…", line: "Loading…" };
    if (!a.enabled) {
      return { badge: "off", label: "Off", line: "Off — community IPs are not banned automatically (manual bans from the list still work)." };
    }
    const parts = [`last sync ${ago(a.last_sync)}`, `${num(a.added_total)} bans added in total`];
    if (a.pending) parts.push(`${num(a.pending)} waiting for the next pass`);
    return { badge: "on", label: "On", line: `On — ${parts.join(" · ")}.` };
  }

  function lastErrorLine(r) {
    if (!r || !r.enabled || !r.last_error) return "";
    const at = r.last_error_at || 0;
    if (at && Date.now() / 1000 - at > 86400) return "";      // older than a day: noise
    return `Last error ${ago(at)}: ${r.last_error}`;
  }

  // ---- render -------------------------------------------------------------------
  function skeleton(m) {
    const p = m.prefix;
    m.el.classList.add("cs-set");
    m.el.innerHTML = `
      <div class="cs-set-row" data-kind="report">
        <div class="cs-set-copy">
          <span class="cs-set-title" id="${p}-report-t">Report catches to the community</span>
          <span class="cs-set-desc" id="${p}-report-d">Sends the attacker IP and decoy evidence of each honeypot / canary catch to tuxwall.org under this install's anonymous key. Nothing else leaves the router.</span>
          <span class="cs-set-status" id="${p}-report-s" data-role="report-line">Loading…</span>
          <span class="cs-set-err" data-role="report-err" hidden></span>
        </div>
        <div class="cs-set-ctl">
          <span class="cs-badge" data-role="report-badge" data-state="unknown">…</span>
          <label class="fw-switch cs-switch">
            <input type="checkbox" role="switch" data-role="report" aria-labelledby="${p}-report-t" aria-describedby="${p}-report-d ${p}-report-s" disabled>
            <span class="fw-switch-slider"></span>
          </label>
        </div>
      </div>
      <div class="cs-set-row" data-kind="auto">
        <div class="cs-set-copy">
          <span class="cs-set-title" id="${p}-auto-t">Use community bans</span>
          <span class="cs-set-desc" id="${p}-auto-d">Bans every medium-or-higher IP on the tuxwall.org list locally in CrowdSec (90 days, synced every 10 min, never reported back). Protected infrastructure and the addresses this router depends on are skipped.</span>
          <span class="cs-set-status" id="${p}-auto-s" data-role="auto-line">Loading…</span>
        </div>
        <div class="cs-set-ctl">
          <span class="cs-badge" data-role="auto-badge" data-state="unknown">…</span>
          <label class="fw-switch cs-switch">
            <input type="checkbox" role="switch" data-role="auto" aria-labelledby="${p}-auto-t" aria-describedby="${p}-auto-d ${p}-auto-s" disabled>
            <span class="fw-switch-slider"></span>
          </label>
        </div>
      </div>
      <p class="cs-set-msg" data-role="msg" role="status" aria-live="polite"></p>`;
    m.el.querySelector('[data-role="report"]').addEventListener("change", (e) => onToggle("reporting_enabled", e.target));
    m.el.querySelector('[data-role="auto"]').addEventListener("change", (e) => onToggle("auto_ban", e.target));
  }

  function setBadge(el, st) {
    if (!el) return;
    el.dataset.state = st.badge;
    el.textContent = st.label;
  }

  function renderOne(m) {
    const q = (sel) => m.el.querySelector(sel);
    const r = data && data.reporting;
    let a = data && data.auto_ban;
    if (!a && !data) {
      const c = readAutoCache();
      if (c) a = c;
    }
    const rs = forbidden
      ? { badge: "unknown", label: "Admin only", line: "Only administrators can see or change the community settings." }
      : (error && !data ? { badge: "unknown", label: "Unavailable", line: `Settings unavailable: ${error}` } : reportState(r));
    const as = forbidden
      ? { badge: "unknown", label: "Admin only", line: "Only administrators can see or change the community settings." }
      : (error && !data && !a ? { badge: "unknown", label: "Unavailable", line: `Settings unavailable: ${error}` } : autoState(a));
    setBadge(q('[data-role="report-badge"]'), rs);
    setBadge(q('[data-role="auto-badge"]'), as);
    q('[data-role="report-line"]').textContent = rs.line;
    q('[data-role="auto-line"]').textContent = as.line;
    const errEl = q('[data-role="report-err"]');
    const errTxt = lastErrorLine(r);
    errEl.textContent = errTxt;
    errEl.hidden = !errTxt;
    const rep = q('[data-role="report"]');
    const auto = q('[data-role="auto"]');
    rep.checked = !!(r && r.enabled);
    auto.checked = !!(a && a.enabled);
    rep.disabled = busy || forbidden || !r;
    auto.disabled = busy || forbidden || !(data && data.auto_ban);
    m.el.dataset.report = r ? (r.enabled ? r.status : "off") : "unknown";
    m.el.dataset.auto = a ? (a.enabled ? "on" : "off") : "unknown";
  }

  function renderAll() {
    mounts.forEach(renderOne);
  }

  function say(text) {
    mounts.forEach((m) => {
      const el = m.el.querySelector('[data-role="msg"]');
      if (el) el.textContent = text || "";
    });
  }

  function publish() {
    if (data && data.auto_ban) writeAutoCache(data.auto_ban);
    try {
      document.dispatchEvent(new CustomEvent("tw:community-settings", { detail: data }));
    } catch (_) { /* old browsers */ }
  }

  // ---- data ---------------------------------------------------------------------
  async function load(opts = {}) {
    if (inflight && !opts.force) return inflight;
    const url = API + (opts.recheck ? "?refresh=1" : "");
    inflight = (async () => {
      try {
        const res = await fetch(url, { cache: "no-store", credentials: "same-origin" });
        if (res.status === 403) {
          forbidden = true;
          error = "";
          renderAll();
          return null;
        }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        if (!d || !d.ok) throw new Error((d && d.error) || "unavailable");
        forbidden = false;
        error = "";
        data = d;
        loadedAt = Date.now();
        renderAll();
        publish();
        scheduleRecheck();
        return d;
      } catch (err) {
        error = err.message || String(err);
        renderAll();
        return null;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  // The key status is looked up in the background server-side; while it is
  // still unknown, ask again a few times so the line settles by itself.
  function scheduleRecheck() {
    const r = data && data.reporting;
    clearTimeout(recheckTimer);
    if (r && r.enabled && r.status_checking && rechecks < 4) {
      rechecks += 1;
      recheckTimer = setTimeout(() => load(), 2500);
    } else if (!(r && r.status_checking)) {
      rechecks = 0;
    }
  }

  async function onToggle(field, input) {
    const want = !!input.checked;
    input.checked = !want;            // stay truthful until the server agrees
    if (busy) return;
    if (field === "reporting_enabled" && !want) {
      const ok = await confirmDlg("Stop reporting catches to the community? New honeypot and canary catches stay on this router only (they are still banned locally if auto-ban is on). Reports already queued are held and sent only if you turn reporting back on. Your evidence no longer helps other TuxWall installs while this is off.");
      if (!ok) { say("Reporting left on."); return; }
    }
    if (field === "auto_ban" && want) {
      const ok = await confirmDlg("Use community bans? Every medium-or-higher IP on the tuxwall.org community list is added to CrowdSec as a local 90-day ban, kept in sync every 10 minutes and never reported back. Protected infrastructure and the addresses this router depends on (DNS, NTP, gateway, mirrors) are never banned.");
      if (!ok) { say("Community bans left off."); return; }
    }
    busy = true;
    renderAll();
    say("Saving…");
    try {
      const res = await fetch(API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        cache: "no-store",
        body: JSON.stringify({ [field]: want }),
      });
      let d = null;
      try { d = await res.json(); } catch (_) { d = null; }
      if (!res.ok || !d || !d.ok) throw new Error((d && d.error) || `HTTP ${res.status}`);
      data = d;
      loadedAt = Date.now();
      error = "";
      const what = field === "reporting_enabled" ? "Community reporting" : "Community bans";
      say(`${what} ${want ? "on" : "off"}.`);
      publish();
    } catch (err) {
      say(`Couldn't save: ${err.message || err}`);
    } finally {
      busy = false;
      renderAll();
    }
  }

  // ---- public API ---------------------------------------------------------------
  function mount(el, prefix) {
    if (!el || mounts.some((m) => m.el === el)) return;
    const m = { el, prefix: prefix || ("cs" + mounts.length) };
    skeleton(m);
    mounts.push(m);
    renderOne(m);
  }

  window.twCommunitySettings = {
    mount,
    /** Fetch (at most every `maxAgeMs`, default 10 s) and render everywhere. */
    refresh(maxAgeMs = 10000) {
      if (busy) return Promise.resolve(data);
      if (data && Date.now() - loadedAt < maxAgeMs) {
        renderAll();
        return Promise.resolve(data);
      }
      return load();
    },
    recheck() { return load({ force: true, recheck: true }); },
    get data() { return data; },
  };

  function autoMount() {
    document.querySelectorAll("[data-community-settings]").forEach((el) =>
      mount(el, el.getAttribute("data-community-settings")));
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", autoMount);
  else autoMount();
})();
