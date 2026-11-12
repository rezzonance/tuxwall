/* ============================================================================
   TuxWall — dashboard enhancements (Phase B)
   Grouped sidebar + icon rail, live nav badges and router health, "updated
   Ns ago" indicator, hash deep links, command palette (Ctrl+K), compact page
   headers, overview service summary, firewall rule comments, themed alert /
   confirm, skeleton placeholders.
   Works purely through the DOM, read-only GET /api/* calls and clicks on
   existing nav / sub-tab elements. Never performs state changes itself.
   ========================================================================= */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  function lsGet(k, d) { try { var v = localStorage.getItem(k); return v === null ? d : v; } catch (_) { return d; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (_) { } }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  }
  function authed() {
    var gate = document.getElementById("login-gate");
    return !gate || gate.hidden;
  }
  function apiGet(url) {
    return fetch(url, { cache: "no-store", credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); });
  }
  var ICON = function (body, cls) {
    return '<svg class="' + (cls || "tw-ic") + '" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + body + "</svg>";
  };
  var CHEV = ICON('<path d="m6 9 6 6 6-6"/>', "tw-chev");

  // Track the last successful API response (for "Updated Ns ago")
  var lastOk = Date.now();
  var _fetch = window.fetch;
  window.fetch = function (input) {
    var p = _fetch.apply(this, arguments);
    try {
      var url = typeof input === "string" ? input : (input && input.url) || "";
      if (url.indexOf("/api/") !== -1) {
        p.then(function (r) { if (r && r.ok) lastOk = Date.now(); }, function () { });
      }
    } catch (_) { }
    return p;
  };

  /* ==========================================================================
     Toast + themed alert / confirm
     ======================================================================= */
  var toastBox = null;
  function toast(msg, kind, ms) {
    if (!toastBox) {
      toastBox = el("div", "tw-toasts");
      toastBox.setAttribute("aria-live", "polite");
      toastBox.setAttribute("role", "status");
      document.body.appendChild(toastBox);
    }
    var t = el("div", "tw-toast tw-toast-" + (kind || "info"));
    t.innerHTML = '<span class="tw-toast-msg"></span><button type="button" class="tw-toast-x" aria-label="Dismiss">&times;</button>';
    t.querySelector(".tw-toast-msg").textContent = String(msg == null ? "" : msg);
    var close = function () {
      t.classList.add("out");
      setTimeout(function () { t.remove(); }, 220);
    };
    t.querySelector(".tw-toast-x").addEventListener("click", close);
    toastBox.appendChild(t);
    setTimeout(close, ms || Math.min(12000, 4000 + String(msg || "").length * 40));
    return t;
  }
  window.twToast = toast;
  window.alert = function (msg) {
    var s = String(msg == null ? "" : msg);
    toast(s, /fail|error|invalid|denied|could not|cannot|unable/i.test(s) ? "error" : "info");
  };

  window.twConfirm = function (msg) {
    return new Promise(function (resolve) {
      var prev = document.activeElement;
      var wrap = el("div", "tw-dialog-backdrop");
      wrap.innerHTML =
        '<div class="tw-dialog" role="alertdialog" aria-modal="true" aria-labelledby="tw-dlg-title" aria-describedby="tw-dlg-msg">' +
        '<div class="tw-dialog-head"><span class="tw-dialog-ico">' + ICON('<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>') + '</span>' +
        '<h3 id="tw-dlg-title">Please confirm</h3></div>' +
        '<p class="tw-dialog-msg" id="tw-dlg-msg"></p>' +
        '<div class="tw-dialog-actions"><button type="button" class="btn tw-dlg-cancel">Cancel</button>' +
        '<button type="button" class="btn btn-primary tw-dlg-ok">OK</button></div></div>';
      wrap.querySelector(".tw-dialog-msg").textContent = String(msg == null ? "" : msg);
      if (/\b(delete|remove|revoke|disable|reboot|reset|stop|unban|wipe|purge|uninstall|erase|destroy|overwrite|permanently)\b/i.test(String(msg)))
        wrap.querySelector(".tw-dlg-ok").classList.replace("btn-primary", "btn-danger");
      var done = function (v) {
        document.removeEventListener("keydown", onKey, true);
        wrap.classList.add("out");
        setTimeout(function () { wrap.remove(); }, 160);
        if (prev && prev.focus) { try { prev.focus(); } catch (_) { } }
        resolve(v);
      };
      var ok = wrap.querySelector(".tw-dlg-ok"), cancel = wrap.querySelector(".tw-dlg-cancel");
      var onKey = function (e) {
        if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); done(false); }
        else if (e.key === "Tab") {
          e.preventDefault();
          (document.activeElement === ok ? cancel : ok).focus();
        }
      };
      ok.addEventListener("click", function () { done(true); });
      cancel.addEventListener("click", function () { done(false); });
      wrap.addEventListener("mousedown", function (e) { if (e.target === wrap) done(false); });
      document.addEventListener("keydown", onKey, true);
      document.body.appendChild(wrap);
      ok.focus();
    });
  };

  /* ==========================================================================
     B1. Grouped sidebar
     ======================================================================= */
  var GROUPS = [
    { id: "monitor", label: "Monitor", views: ["overview", "bandwidth", "security", "logs"] },
    { id: "network", label: "Network", views: ["clients", "dns", "domains", "blocklists", "vlans", "wireguard"] },
    { id: "protect", label: "Protect", views: ["firewall", "crowdsec"] },
    { id: "system", label: "System", views: ["system", "backups", "ai", "settings"] }
  ];
  var nav = document.getElementById("main-nav");
  var groupBox = {};
  var collapsed = {};
  try { collapsed = JSON.parse(lsGet("tw.navGroups", "{}")) || {}; } catch (_) { collapsed = {}; }

  function navLabel(item) {
    var s = item.querySelector("span:not(.tw-badge)");
    return s ? s.textContent.trim() : item.textContent.trim();
  }

  function buildGroups() {
    if (!nav || nav.dataset.twGrouped) return;
    nav.dataset.twGrouped = "1";
    GROUPS.forEach(function (g) {
      var wrap = el("div", "tw-nav-group");
      wrap.dataset.group = g.id;
      var head = el("button", "tw-nav-group-head",
        '<span class="tw-nav-group-label">' + g.label + "</span>" + CHEV);
      head.type = "button";
      head.id = "tw-ng-" + g.id;
      var items = el("div", "tw-nav-group-items");
      items.id = "tw-ngi-" + g.id;
      items.setAttribute("role", "group");
      items.setAttribute("aria-labelledby", head.id);
      head.setAttribute("aria-controls", items.id);
      head.addEventListener("click", function () {
        collapsed[g.id] = !collapsed[g.id];
        lsSet("tw.navGroups", JSON.stringify(collapsed));
        paintGroup(g.id);
      });
      wrap.appendChild(head);
      wrap.appendChild(items);
      nav.appendChild(wrap);
      groupBox[g.id] = { wrap: wrap, head: head, items: items };
      g.views.forEach(function (v) {
        var it = nav.querySelector('.nav-item[data-view="' + v + '"]');
        if (it) items.appendChild(it);
      });
      paintGroup(g.id);
    });
    // anything left over (unknown items) goes to Network
    $$(":scope > .nav-item", nav).forEach(function (it) { groupBox.network.items.appendChild(it); });
    placePluginItems();
    $$(".nav-item", nav).forEach(function (it) { it.title = navLabel(it); });
    new MutationObserver(function () { placePluginItems(); }).observe(nav, { childList: true, subtree: true });
  }
  function paintGroup(id) {
    var g = groupBox[id];
    if (!g) return;
    var c = !!collapsed[id];
    g.wrap.classList.toggle("collapsed", c);
    g.head.setAttribute("aria-expanded", c ? "false" : "true");
  }
  function placePluginItems() {
    if (!groupBox.network) return;
    var dest = groupBox.network.items;
    $$('.nav-item[data-plugin-nav], .nav-item.plugin-nav', nav).forEach(function (it) {
      if (it.parentNode !== dest) dest.appendChild(it);
      if (!it.title) it.title = navLabel(it);
    });
    $$(":scope > .nav-item", nav).forEach(function (it) { dest.appendChild(it); });
  }

  /* ==========================================================================
     B2. Badges, router health, "Updated Ns ago"
     ======================================================================= */
  function setBadge(view, text, kind, title) {
    var item = nav && nav.querySelector('.nav-item[data-view="' + view + '"]');
    if (!item) return;
    var b = item.querySelector(".tw-badge");
    if (!text) { if (b) b.remove(); return; }
    if (!b) { b = el("span", "tw-badge"); item.appendChild(b); }
    b.textContent = text;
    b.dataset.kind = kind || "info";
    b.title = title || "";
    b.setAttribute("aria-label", title || text);
  }
  function compact(n) {
    if (n > 999) return Math.floor(n / 1000) + "k";
    return String(n);
  }
  var health = { reach: null, level: "", reason: "" };
  function paintHealth() {
    var dot = document.getElementById("brand-status-dot");
    var txt = document.getElementById("brand-status-text");
    var box = document.getElementById("brand-status");
    if (!dot || !txt || !health.level) return;
    var map = { ok: ["online", "Healthy"], warn: ["warn", "Degraded"], bad: ["offline", "Router unreachable"] };
    var m = map[health.level];
    dot.dataset.status = m[0];
    txt.textContent = m[1];
    if (box) {
      box.dataset.health = health.level;
      box.title = health.reason || m[1];
    }
  }
  var origReach = window._tuxwallSetReachable;
  if (typeof origReach === "function") {
    window._tuxwallSetReachable = function (ok) {
      origReach(ok);
      if (!ok) { health.level = "bad"; health.reason = "The router API is not answering"; }
      setTimeout(paintHealth, 0);
    };
  }

  var tickCount = 0, lastTick = 0, ticking = false;
  var POLL_MS = 60000;
  function settle(p) { return p.then(function (v) { return v; }, function () { return null; }); }

  function tick() {
    if (ticking || !authed() || document.hidden) return;
    ticking = true;
    lastTick = Date.now();
    var withCs = tickCount % 5 === 0;
    tickCount++;
    Promise.all([
      settle(apiGet("/api/system")),
      settle(apiGet("/api/system/services")),
      settle(apiGet("/api/incidents")),
      settle(apiGet("/api/system/updates")),
      settle(apiGet("/api/backups/system")),
      settle(apiGet("/api/security")),
      withCs ? settle(apiGet("/api/crowdsec")) : Promise.resolve(undefined)
    ]).then(function (r) {
      ticking = false;
      var sys = r[0], svc = r[1], inc = r[2], upd = r[3], bk = r[4], sec = r[5], cs = r[6];
      // --- router health
      var reasons = [], level = "ok";
      var failed = [];
      if (svc && svc.services) {
        failed = svc.services.filter(function (s) { return s.active === "failed"; });
        if (failed.length) reasons.push(failed.length + " failed service" + (failed.length > 1 ? "s" : ""));
        paintDefenseDots(svc.services);
      }
      if (!sys) { level = "bad"; reasons.push("The router API is not answering"); }
      else {
        if (sys.wan && sys.wan.state && String(sys.wan.state).toUpperCase() !== "UP") reasons.push("WAN link is " + sys.wan.state);
        if (sys.latency && sys.latency.loss_1h_pct > 5) reasons.push("Packet loss " + sys.latency.loss_1h_pct.toFixed(1) + "% (1h)");
        if (sys.usage && sys.usage.disk_pct > 92) reasons.push("Disk " + Math.round(sys.usage.disk_pct) + "% full");
      }
      if (inc && inc.active) reasons.push(inc.active + " active incident" + (inc.active > 1 ? "s" : ""));
      if (level !== "bad" && reasons.length) level = "warn";
      if (level !== "bad" && inc && inc.critical) level = "warn";
      health.level = level;
      health.reason = reasons.length ? reasons.join(" · ") : "All checks passing";
      paintHealth();

      // --- System: failed services, else updates
      var updates = upd && typeof upd.upgradable === "number" ? upd.upgradable : 0;
      if (failed.length) setBadge("system", String(failed.length), "bad", failed.length + " failed service(s): " + failed.map(function (s) { return s.unit; }).join(", "));
      else if (updates) setBadge("system", String(updates), "warn", updates + " update" + (updates > 1 ? "s" : "") + " available");
      else setBadge("system", "");

      // --- Backups older than 7 days
      if (bk && bk.backups) {
        var newest = bk.backups.reduce(function (m, b) { return Math.max(m, b.time || 0); }, 0);
        var age = newest ? (Date.now() / 1000 - newest) / 86400 : Infinity;
        if (age > 7) setBadge("backups", "!", "warn", newest ? "Last backup " + Math.floor(age) + " days ago" : "No system backup yet");
        else setBadge("backups", "");
      }

      // --- Security: new attack hits since the last visit
      if (sec && sec.stats) {
        var key = "tw.seen.security", hits = sec.stats.hits || 0;
        var seen = JSON.parse(lsGet(key, "null") || "null");
        if (!seen || seen.started !== sec.started || seen.hits > hits || isActive("security")) {
          seen = { started: sec.started, hits: hits };
          lsSet(key, JSON.stringify(seen));
        }
        var nNew = hits - seen.hits;
        setBadge("security", nNew > 0 ? compact(nNew) : "", "info", nNew + " new blocked probe(s) since you last opened Security");
      }
      // --- CrowdSec: alerts newer than the last visit
      if (cs && cs.alerts) {
        var ck = "tw.seen.crowdsec";
        var since = parseFloat(lsGet(ck, "0")) || 0;
        if (!since || isActive("crowdsec")) { since = Date.now(); lsSet(ck, String(since)); }
        var nA = cs.alerts.filter(function (a) { return Date.parse(a.created_at) > since; }).length;
        setBadge("crowdsec", nA > 0 ? (nA >= cs.alerts.length ? nA + "+" : String(nA)) : "", "bad", nA + " new CrowdSec alert(s) since your last visit");
      }
    });
  }
  function isActive(view) {
    var a = nav && nav.querySelector(".nav-item.active");
    return !!(a && a.dataset.view === view);
  }
  function clearSeen(view) {
    if (view === "security" || view === "crowdsec") {
      setBadge(view, "");
      if (view === "crowdsec") lsSet("tw.seen.crowdsec", String(Date.now()));
      else lsSet("tw.seen.security", "null"); // re-baselined on the next poll
    }
  }
  setInterval(function () { if (Date.now() - lastTick >= POLL_MS - 500) tick(); }, 5000);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden && Date.now() - lastTick >= POLL_MS) tick();
  });

  // Defense Layers card (dashboard.js only paints it every 30s, and its very
  // first call happens before login, so the dots stay grey for up to 30s).
  function paintDefenseDots(services) {
    var by = {};
    services.forEach(function (s) { by[s.unit] = s; });
    var on = function (u) { return (by[u] || {}).active === "active"; };
    var set = function (id, ok) {
      var d = document.getElementById(id);
      if (d) d.className = "dot " + (ok ? "dot-ok" : "dot-err");
    };
    set("dl-ufw-dot", on("ufw.service"));
    set("dl-crowdsec-dot", on("crowdsec.service") && on("crowdsec-firewall-bouncer.service"));
    set("dl-suricata-dot", on("suricata.service"));
    set("dl-wireguard-dot", on("wg-quick@wg0.service"));
  }

  // "Updated Ns ago" + Pause / Resume (drives the existing auto-refresh toggle)
  function buildLive() {
    var actions = $(".topbar-actions");
    var auto = document.getElementById("auto-refresh");
    if (!actions || $(".tw-live", actions)) return;
    var live = el("div", "tw-live",
      '<span class="tw-live-dot" aria-hidden="true"></span>' +
      '<span class="tw-live-text" aria-live="off">Updated just now</span>' +
      '<button type="button" class="tw-live-btn" aria-pressed="false"></button>');
    actions.insertBefore(live, actions.firstChild);
    var txt = $(".tw-live-text", live), btn = $(".tw-live-btn", live);
    var paint = function () {
      var paused = auto && !auto.checked;
      live.classList.toggle("paused", !!paused);
      btn.innerHTML = paused
        ? ICON('<path d="M8 5v14l11-7z"/>') + "<span>Resume</span>"
        : ICON('<rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/>') + "<span>Pause</span>";
      btn.title = paused ? "Resume auto-refresh" : "Pause auto-refresh";
      btn.setAttribute("aria-pressed", paused ? "true" : "false");
      var s = Math.max(0, Math.round((Date.now() - lastOk) / 1000));
      var ago = s < 5 ? "just now" : s < 60 ? s + "s ago" : Math.floor(s / 60) + "m ago";
      txt.textContent = paused ? "Paused · updated " + ago : "Updated " + ago;
      live.classList.toggle("stale", !paused && s > 90);
    };
    btn.addEventListener("click", function () {
      if (!auto) return;
      auto.checked = !auto.checked;
      auto.dispatchEvent(new Event("change", { bubbles: true }));
      paint();
    });
    if (auto) auto.addEventListener("change", paint);
    setInterval(function () { if (!document.hidden) paint(); }, 1000);
    paint();
  }

  /* ==========================================================================
     B3. Deep links: #view or #view/subtab, real Back/Forward history
     ======================================================================= */
  function paneOf(tab) {
    if (!tab) return "";
    for (var i = 0; i < tab.attributes.length; i++) {
      var a = tab.attributes[i];
      if (/^data-.*-pane$/.test(a.name) && a.value) return a.value;
    }
    return "";
  }
  function activeView() {
    var a = nav && nav.querySelector(".nav-item.active");
    return a ? a.dataset.view : "";
  }
  function viewEl(view) {
    if (!view) return null;
    if (view.indexOf("plugin:") === 0) return document.getElementById("view-plugin-" + view.slice(7));
    return document.getElementById("view-" + view);
  }
  function mainStrip(view) {
    var v = viewEl(view);
    return v ? v.querySelector(".fw-subtabs") : null;
  }
  function currentHash() {
    var v = activeView();
    if (!v) return location.hash;
    var strip = mainStrip(v);
    var pane = strip ? paneOf(strip.querySelector(".fw-subtab.active")) : "";
    return "#" + v + (pane ? "/" + pane : "");
  }
  function parseHash(h) {
    var s = decodeURIComponent((h || "").replace(/^#/, ""));
    var i = s.indexOf("/");
    return i === -1 ? { view: s, sub: "" } : { view: s.slice(0, i), sub: s.slice(i + 1) };
  }
  function selectSub(view, sub) {
    var strip = mainStrip(view);
    if (!strip || !sub) return false;
    var tab = $$(".fw-subtab", strip).filter(function (t) { return paneOf(t) === sub; })[0];
    if (tab && !tab.classList.contains("active")) tab.click();
    return !!tab;
  }
  var applying = false;
  function go(view, sub, opts) {
    opts = opts || {};
    var item = nav && nav.querySelector('.nav-item[data-view="' + (window.CSS && CSS.escape ? CSS.escape(view) : view) + '"]');
    if (!item) return false;
    var before = location.hash;
    applying = true;
    if (!item.classList.contains("active")) item.click();
    clearSeen(view);
    return new Promise(function (resolve) {
      setTimeout(function () {
        if (sub) selectSub(view, sub);
        setTimeout(function () {
          applying = false;
          var h = currentHash();
          if (opts.push && h !== before) {
            history.replaceState(null, "", before || "#");
            history.pushState(null, "", h);
          } else if (h !== location.hash) {
            history.replaceState(null, "", h);
          }
          resolve(viewEl(view));
        }, 40);
      }, 60);
    });
  }
  window.twGo = go;
  function applyHash() {
    var p = parseHash(location.hash);
    if (!p.view) return;
    if (p.view === activeView()) {
      var strip = mainStrip(p.view);
      var cur = strip ? paneOf(strip.querySelector(".fw-subtab.active")) : "";
      if (!p.sub || cur === p.sub) return;
    }
    go(p.view, p.sub);
  }

  // Trusted clicks on nav / sub-tabs create history entries.
  var pendingFrom = null, syncTimer = 0;
  document.addEventListener("click", function (e) {
    if (!e.isTrusted || applying) return;
    var t = e.target.closest && e.target.closest(".nav-item[data-view], .fw-subtab, .ov-post-link[data-view], .ov-issue[data-view]");
    if (!t) return;
    if (t.classList.contains("fw-subtab")) {
      var strip = t.closest(".fw-subtabs");
      var v = viewEl(activeView());
      if (!strip || !v || v.querySelector(".fw-subtabs") !== strip) return;
    }
    if (t.dataset.view) clearSeen(t.dataset.view);
    if (pendingFrom === null) pendingFrom = location.hash;
    clearTimeout(syncTimer);
    syncTimer = setTimeout(function () {
      var from = pendingFrom; pendingFrom = null;
      var h = currentHash();
      if (h === from) { if (location.hash !== h) history.replaceState(null, "", h); return; }
      history.replaceState(null, "", from || location.pathname);
      history.pushState(null, "", h);
    }, 90);
  }, true);
  window.addEventListener("popstate", applyHash);
  window.addEventListener("hashchange", applyHash);

  /* ==========================================================================
     B4. Command palette
     ======================================================================= */
  var GO_KEYS = {
    o: "overview", d: "clients", n: "dns", m: "domains", x: "blocklists", f: "firewall",
    v: "vlans", s: "security", w: "wireguard", c: "crowdsec", b: "bandwidth",
    y: "system", k: "backups", l: "logs", a: "ai", ",": "settings"
  };
  var pal = null, palInput, palList, palItems = [], palSel = 0, palResults = [];
  var dataCache = { at: 0, leases: [], rules: [], peers: [], themes: [] };

  function staticItems() {
    var out = [];
    $$(".nav-item[data-view]", nav).forEach(function (it) {
      if (it.hidden || it.offsetParent === null && !it.closest(".tw-nav-group.collapsed") && getComputedStyle(it).display === "none") return;
      var view = it.dataset.view, label = navLabel(it);
      var g = it.closest(".tw-nav-group");
      var key = Object.keys(GO_KEYS).filter(function (k) { return GO_KEYS[k] === view; })[0];
      out.push({ kind: "Page", label: label, hint: g ? g.dataset.group : "", keys: key ? "g " + key : "",
        icon: it.querySelector("svg") ? it.querySelector("svg").outerHTML : "", run: function () { go(view, "", { push: true }); } });
      var v = viewEl(view);
      var strip = v && v.querySelector(".fw-subtabs");
      if (strip) {
        $$(".fw-subtab", strip).forEach(function (t) {
          var pane = paneOf(t);
          if (!pane || t.hidden) return;
          out.push({ kind: "Tab", label: label + " › " + t.textContent.trim(), hint: "#" + view + "/" + pane,
            run: function () { go(view, pane, { push: true }); } });
        });
      }
    });
    out.push({ kind: "Action", label: "Add firewall rule…", hint: "opens the rule form",
      run: function () { go("firewall", "rules", { push: true }).then(function () { var b = $("#fw-add-open"); if (b) b.click(); }); } });
    out.push({ kind: "Action", label: "Add WireGuard client…", hint: "jumps to WireGuard",
      run: function () { go("wireguard", "", { push: true }).then(function () { focusFlash($("#wg-add-peer")); }); } });
    out.push({ kind: "Action", label: "Static DHCP reservation…", hint: "opens DHCP › Static",
      run: function () { go("clients", "static", { push: true }).then(function () { var i = $("#res-mac"); if (i) i.focus(); }); } });
    var auto = document.getElementById("auto-refresh");
    out.push({ kind: "Action", label: (auto && !auto.checked ? "Resume" : "Pause") + " auto-refresh",
      run: function () { var b = $(".tw-live-btn"); if (b) b.click(); } });
    out.push({ kind: "Action", label: (document.documentElement.classList.contains("tw-mascots") ? "Hide" : "Show") + " mascot art",
      run: function () { setMascots(!document.documentElement.classList.contains("tw-mascots")); } });
    out.push({ kind: "Action", label: "Keyboard shortcuts", keys: "?", run: function () { openSheet(); } });
    return out;
  }
  function dataItems() {
    var out = [];
    dataCache.leases.forEach(function (l) {
      var name = l.hostname || "(no hostname)";
      out.push({ kind: "Device", label: name, hint: l.ip + "  " + (l.mac || ""), dot: l.online ? "ok" : "",
        extra: (l.vendor || "") + " " + (l.mac || ""),
        run: function () {
          go("clients", "dynamic", { push: true }).then(function () { fillSearch($("#search"), l.ip); });
        } });
      if (!l.static && l.mac) {
        out.push({ kind: "Action", label: "Reserve " + l.ip + " for " + name + "…", hint: "prefills DHCP › Static (not saved)",
          run: function () {
            go("clients", "static", { push: true }).then(function () {
              var m = $("#res-mac"), i = $("#res-ip"), h = $("#res-hostname");
              if (m) m.value = l.mac; if (i) i.value = l.ip; if (h && l.hostname) h.value = l.hostname;
              focusFlash($("#res-add-btn"));
            });
          } });
      }
    });
    dataCache.rules.forEach(function (r) {
      var src = String(r.src || r.from || "");
      var ci = src.indexOf("#");
      var note = ci >= 0 ? src.slice(ci + 1).trim() : "";
      var from = (ci >= 0 ? src.slice(0, ci) : src).trim();
      out.push({ kind: "Rule", label: "#" + r.number + " " + (r.action || "") + " " + (r.to || r.port || "") + (note ? " — " + note : ""),
        hint: "from " + from, run: function () {
          go("firewall", "rules", { push: true }).then(function () {
            fillSearch($("#fw-search"), "");
            setTimeout(function () {
              var row = $$("#fw-rules-table tbody tr").filter(function (tr) {
                var td = tr.querySelector("td"); return td && td.textContent.trim() === String(r.number);
              })[0];
              flashRow(row);
            }, 120);
          });
        } });
    });
    dataCache.peers.forEach(function (p) {
      out.push({ kind: "Peer", label: p.name || p.address, hint: "WireGuard " + (p.address || ""),
        run: function () {
          go("wireguard", "", { push: true }).then(function () {
            var v = viewEl("wireguard");
            var row = v && $$("tr, .wg-peer, li", v).filter(function (n) { return n.textContent.indexOf(p.name || p.address) !== -1 && n.children.length; }).pop();
            flashRow(row);
          });
        } });
    });
    dataCache.themes.forEach(function (t) {
      out.push({ kind: "Theme", label: "Theme: " + t.name, hint: t.id === document.documentElement.dataset.theme ? "active" : "apply",
        run: function () {
          go("settings", "appearance", { push: true }).then(function () {
            setTimeout(function () {
              var c = document.querySelector('.theme-card[data-id="' + t.id + '"]');
              if (c) { c.click(); c.scrollIntoView({ block: "nearest" }); }
            }, 250);
          });
        } });
    });
    return out;
  }
  function loadData() {
    if (Date.now() - dataCache.at < 60000) return Promise.resolve();
    dataCache.at = Date.now();
    return Promise.all([
      settle(apiGet("/api/leases")), settle(apiGet("/api/firewall")),
      settle(apiGet("/api/wireguard")), settle(apiGet("/api/themes"))
    ]).then(function (r) {
      if (r[0]) dataCache.leases = r[0].leases || [];
      if (r[1]) dataCache.rules = r[1].rules || [];
      if (r[2]) dataCache.peers = r[2].peers || [];
      if (r[3]) dataCache.themes = r[3].themes || [];
    });
  }
  function fillSearch(input, value) {
    if (!input) return;
    input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("keyup", { bubbles: true }));
    if (value) input.focus();
  }
  function flashRow(row) {
    if (!row) return;
    row.scrollIntoView({ block: "center", behavior: "smooth" });
    row.classList.remove("tw-flash");
    void row.offsetWidth;
    row.classList.add("tw-flash");
    setTimeout(function () { row.classList.remove("tw-flash"); }, 2600);
  }
  function focusFlash(b) {
    if (!b) return;
    flashRow(b);
    try { b.focus({ preventScroll: true }); } catch (_) { b.focus(); }
  }

  function score(q, text) {
    if (!q) return 1;
    text = text.toLowerCase();
    var idx = text.indexOf(q);
    if (idx !== -1) return 1000 - idx + (idx === 0 || /[\s›#.:\-/]/.test(text[idx - 1]) ? 200 : 0) - text.length * 0.1;
    // fuzzy subsequence
    var ti = 0, s = 0, run = 0;
    for (var i = 0; i < q.length; i++) {
      var c = q[i];
      if (c === " ") continue;
      var f = text.indexOf(c, ti);
      if (f === -1) return 0;
      run = f === ti ? run + 1 : 0;
      s += 10 + run * 5 + (f === 0 || /[\s›#.:\-/]/.test(text[f - 1]) ? 8 : 0) - Math.min(f - ti, 10);
      ti = f + 1;
    }
    return s;
  }
  var KIND_ORDER = { Page: 0, Tab: 1, Action: 2, Device: 3, Rule: 4, Peer: 5, Theme: 6 };
  function renderPalette() {
    var q = palInput.value.trim().toLowerCase();
    var all = palItems;
    var res = all.map(function (it) {
      var hay = it.label + " " + (it.kind === "Page" ? "" : (it.hint || "")) + " " + (it.extra || "");
      return { it: it, s: score(q, hay) };
    }).filter(function (x) { return x.s > 0 && (x.s >= 500 || x.s >= q.replace(/ /g, "").length * 12); });
    if (q) res.sort(function (a, b) { return b.s - a.s; });
    else res = res.filter(function (x) { return x.it.kind === "Page" || x.it.kind === "Action"; });
    palResults = res.slice(0, 60).map(function (x) { return x.it; });
    if (!q) palResults.sort(function (a, b) { return KIND_ORDER[a.kind] - KIND_ORDER[b.kind]; });
    palSel = 0;
    var html = "", lastKind = "";
    palResults.forEach(function (it, i) {
      if (!q && it.kind !== lastKind) { html += '<li class="tw-pal-sec" role="presentation">' + (it.kind === "Page" ? "Go to" : "Actions") + "</li>"; lastKind = it.kind; }
      html += '<li class="tw-pal-opt" role="option" id="tw-pal-o' + i + '" data-i="' + i + '" aria-selected="false">' +
        '<span class="tw-pal-kind" data-kind="' + it.kind + '">' + (it.icon || esc(it.kind)) + "</span>" +
        '<span class="tw-pal-label">' + (it.dot ? '<i class="tw-pal-dot ' + it.dot + '"></i>' : "") + esc(it.label) + "</span>" +
        (it.hint ? '<span class="tw-pal-hint">' + esc(it.hint) + "</span>" : "") +
        (it.keys ? '<kbd class="tw-kbd">' + esc(it.keys) + "</kbd>" : "") + "</li>";
    });
    if (!palResults.length) html = '<li class="tw-pal-empty" role="presentation">No matches for “' + esc(palInput.value) + "”</li>";
    palList.innerHTML = html;
    markSel();
  }
  function markSel() {
    $$(".tw-pal-opt", palList).forEach(function (o) {
      var on = +o.dataset.i === palSel;
      o.setAttribute("aria-selected", on ? "true" : "false");
      o.classList.toggle("sel", on);
      if (on) o.scrollIntoView({ block: "nearest" });
    });
    palInput.setAttribute("aria-activedescendant", palResults.length ? "tw-pal-o" + palSel : "");
  }
  function runSel(i) {
    var it = palResults[i];
    if (!it) return;
    closePalette();
    setTimeout(function () { it.run(); }, 10);
  }
  var palPrevFocus = null;
  function buildPalette() {
    pal = el("div", "tw-pal-backdrop");
    pal.hidden = true;
    pal.innerHTML =
      '<div class="tw-pal" role="dialog" aria-modal="true" aria-label="Command palette">' +
      '<div class="tw-pal-search">' + ICON('<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>') +
      '<input type="text" class="tw-pal-input" role="combobox" aria-expanded="true" aria-controls="tw-pal-list" aria-autocomplete="list" ' +
      'placeholder="Search pages, tabs, devices, rules, peers, themes…" spellcheck="false" autocomplete="off">' +
      '<kbd class="tw-kbd">Esc</kbd></div>' +
      '<ul class="tw-pal-list" id="tw-pal-list" role="listbox" aria-label="Results"></ul>' +
      '<div class="tw-pal-foot"><span><kbd class="tw-kbd">↑</kbd><kbd class="tw-kbd">↓</kbd> move</span><span><kbd class="tw-kbd">↵</kbd> open</span>' +
      '<span><kbd class="tw-kbd">?</kbd> shortcuts</span><span class="tw-pal-note">Actions only navigate — nothing is changed without your click.</span></div></div>';
    document.body.appendChild(pal);
    palInput = $(".tw-pal-input", pal);
    palList = $(".tw-pal-list", pal);
    palInput.addEventListener("input", renderPalette);
    palInput.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); palSel = Math.min(palResults.length - 1, palSel + 1); markSel(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); palSel = Math.max(0, palSel - 1); markSel(); }
      else if (e.key === "Home" && e.ctrlKey) { palSel = 0; markSel(); }
      else if (e.key === "Enter") { e.preventDefault(); runSel(palSel); }
      else if (e.key === "Escape") { e.preventDefault(); closePalette(); }
      else if (e.key === "Tab") { e.preventDefault(); }
    });
    palList.addEventListener("mousemove", function (e) {
      var o = e.target.closest(".tw-pal-opt");
      if (o && +o.dataset.i !== palSel) { palSel = +o.dataset.i; markSel(); }
    });
    palList.addEventListener("click", function (e) {
      var o = e.target.closest(".tw-pal-opt");
      if (o) runSel(+o.dataset.i);
    });
    pal.addEventListener("mousedown", function (e) { if (e.target === pal) closePalette(); });
  }
  function openPalette(prefill) {
    if (!authed()) return;
    if (!pal) buildPalette();
    closeSheet();
    palPrevFocus = document.activeElement;
    pal.hidden = false;
    palItems = staticItems().concat(dataItems());
    palInput.value = prefill || "";
    renderPalette();
    palInput.focus();
    loadData().then(function () {
      if (pal.hidden) return;
      palItems = staticItems().concat(dataItems());
      renderPalette();
    });
  }
  function closePalette() {
    if (!pal || pal.hidden) return;
    pal.hidden = true;
    if (palPrevFocus && palPrevFocus.focus && document.contains(palPrevFocus)) { try { palPrevFocus.focus(); } catch (_) { } }
  }
  window.twPalette = { open: openPalette, close: closePalette };

  // Shortcut cheat-sheet
  var sheet = null;
  function openSheet() {
    if (!sheet) {
      sheet = el("div", "tw-pal-backdrop tw-sheet-backdrop");
      var rows = Object.keys(GO_KEYS).map(function (k) {
        var it = nav.querySelector('.nav-item[data-view="' + GO_KEYS[k] + '"]');
        return it ? "<li><span>" + esc(navLabel(it)) + '</span><span><kbd class="tw-kbd">g</kbd> <kbd class="tw-kbd">' + esc(k) + "</kbd></span></li>" : "";
      }).join("");
      sheet.innerHTML =
        '<div class="tw-pal tw-sheet" role="dialog" aria-modal="true" aria-labelledby="tw-sheet-t">' +
        '<div class="tw-sheet-head"><h3 id="tw-sheet-t">Keyboard shortcuts</h3><button type="button" class="tw-sheet-x" aria-label="Close">&times;</button></div>' +
        '<div class="tw-sheet-cols"><div><h4>General</h4><ul>' +
        '<li><span>Command palette</span><span><kbd class="tw-kbd">Ctrl</kbd> <kbd class="tw-kbd">K</kbd> or <kbd class="tw-kbd">/</kbd></span></li>' +
        '<li><span>This cheat-sheet</span><span><kbd class="tw-kbd">?</kbd></span></li>' +
        '<li><span>Close dialogs</span><span><kbd class="tw-kbd">Esc</kbd></span></li>' +
        '<li><span>Back / forward</span><span><kbd class="tw-kbd">Alt</kbd> <kbd class="tw-kbd">←</kbd> / <kbd class="tw-kbd">→</kbd></span></li>' +
        '<li><span>Switch sub-tab</span><span><kbd class="tw-kbd">←</kbd> <kbd class="tw-kbd">→</kbd> on a tab</span></li>' +
        '</ul></div><div><h4>Go to</h4><ul>' + rows + "</ul></div></div></div>";
      document.body.appendChild(sheet);
      $(".tw-sheet-x", sheet).addEventListener("click", closeSheet);
      sheet.addEventListener("mousedown", function (e) { if (e.target === sheet) closeSheet(); });
    }
    sheet.hidden = false;
    $(".tw-sheet-x", sheet).focus();
  }
  function closeSheet() { if (sheet) sheet.hidden = true; }

  function typing(t) {
    if (!t) return false;
    var tag = t.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || t.isContentEditable;
  }
  var gPending = 0;
  document.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === "k" || e.key === "K")) {
      if (!authed()) return;
      e.preventDefault();
      if (pal && !pal.hidden) closePalette(); else openPalette();
      return;
    }
    if (e.key === "Escape") {
      if (sheet && !sheet.hidden) { closeSheet(); e.preventDefault(); return; }
    }
    if (e.ctrlKey || e.metaKey || e.altKey || typing(e.target) || !authed()) return;
    if ((pal && !pal.hidden) || document.querySelector(".tw-dialog-backdrop")) return;
    if (e.key === "/") { e.preventDefault(); openPalette(); return; }
    if (e.key === "?") { e.preventDefault(); if (sheet && !sheet.hidden) closeSheet(); else openSheet(); return; }
    if (gPending && Date.now() - gPending < 1200) {
      gPending = 0;
      var v = GO_KEYS[e.key.toLowerCase()];
      if (v) { e.preventDefault(); closeSheet(); go(v, "", { push: true }); }
      return;
    }
    if (e.key === "g") { gPending = Date.now(); }
  });

  function buildSearchButton() {
    var actions = $(".topbar-actions");
    if (!actions || $(".tw-search-btn", actions)) return;
    var b = el("button", "tw-search-btn",
      ICON('<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>') + '<span class="tw-search-ph">Search…</span><kbd class="tw-kbd">Ctrl K</kbd>');
    b.type = "button";
    b.title = "Command palette (Ctrl+K)";
    b.setAttribute("aria-label", "Open command palette");
    b.addEventListener("click", function () { openPalette(); });
    var live = $(".tw-live", actions);
    actions.insertBefore(b, live ? live.nextSibling : actions.firstChild);
  }

  /* ==========================================================================
     B5. Compact page headers + "Show mascot art"
     ======================================================================= */
  function setMascots(on) {
    document.documentElement.classList.toggle("tw-mascots", !!on);
    lsSet("tw.mascots", on ? "1" : "0");
    var cb = document.getElementById("tw-mascot-toggle");
    if (cb) cb.checked = !!on;
  }
  setMascots(lsGet("tw.mascots", "0") === "1");
  function buildMascotSetting() {
    var pane = $('#view-settings .fw-pane[data-settings-pane="appearance"]');
    if (!pane || $("#tw-mascot-toggle")) return;
    var card = el("div", "card tw-pref-card",
      '<div class="card-head"><h2>Page headers</h2><span class="muted">Stored in this browser</span></div>' +
      '<label class="tw-switch-row"><span class="tw-switch-copy"><b>Show mascot art</b>' +
      '<span class="muted">Large illustrated banners at the top of each page. Off = slim headers with more room for data.</span></span>' +
      '<span class="tw-switch"><input type="checkbox" id="tw-mascot-toggle"><span class="tw-switch-track" aria-hidden="true"></span></span></label>');
    var first = pane.querySelector(".card");
    pane.insertBefore(card, first ? first.nextSibling : null);
    var cb = $("#tw-mascot-toggle");
    cb.checked = document.documentElement.classList.contains("tw-mascots");
    cb.addEventListener("change", function () { setMascots(cb.checked); });
  }

  /* ==========================================================================
     B6. Overview services: "N/N healthy ✓", expandable; failures always shown
     ======================================================================= */
  function initSvcSummary() {
    var grid = document.getElementById("ov-svc-grid");
    var card = grid && grid.closest(".ov-svc-card, .card");
    if (!grid || !card) return;
    var head = card.querySelector(".card-head");
    var btn = el("button", "tw-svc-sum");
    btn.type = "button";
    btn.setAttribute("aria-controls", "ov-svc-grid");
    if (head) head.appendChild(btn);
    var open = lsGet("tw.svcOpen", "0") === "1";
    var paint = function () {
      var chips = $$(".ov-svc-chip", grid);
      var bad = chips.filter(function (c) { return !c.classList.contains("ok"); }).length;
      var total = chips.length;
      card.classList.add("tw-svc");
      card.classList.toggle("tw-svc-open", open);
      card.classList.toggle("tw-svc-allok", total > 0 && bad === 0);
      card.classList.toggle("tw-svc-empty", !total);
      btn.hidden = !total;
      btn.dataset.state = bad ? "bad" : "ok";
      btn.innerHTML = (bad
        ? '<span class="tw-svc-sum-txt">' + (total - bad) + "/" + total + " healthy · " + bad + " need attention</span>"
        : '<span class="tw-svc-sum-txt">' + total + "/" + total + " healthy</span>" + ICON('<path d="m5 12.5 4.5 4.5L19 7.5"/>', "tw-ic tw-ok-ic")) +
        '<span class="tw-svc-sum-more">' + (open ? "Hide" : "Show all") + "</span>" + CHEV;
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    };
    btn.addEventListener("click", function () { open = !open; lsSet("tw.svcOpen", open ? "1" : "0"); paint(); });
    new MutationObserver(paint).observe(grid, { childList: true });
    paint();
  }

  /* ==========================================================================
     B7. Firewall rule comments out of Source (display only)
     ======================================================================= */
  function splitComments(tbody) {
    $$("tr", tbody).forEach(function (tr) {
      var tds = tr.children;
      [4, 5].forEach(function (i) {
        var td = tds[i];
        if (!td || td.dataset.twSplit) return;
        var t = td.textContent;
        var ci = t.indexOf("#");
        td.dataset.twSplit = "1";
        if (ci < 0 || td.children.length) return;
        var main = t.slice(0, ci).trim(), note = t.slice(ci + 1).trim();
        if (!note) return;
        td.innerHTML = '<span class="tw-rule-src"></span><span class="tw-rule-note"></span>';
        td.firstChild.textContent = main || "any";
        td.lastChild.textContent = note;
        td.title = note;
      });
    });
  }
  function initRuleComments() {
    var tbody = $("#fw-rules-table tbody");
    if (!tbody) return;
    splitComments(tbody);
    new MutationObserver(function () { splitComments(tbody); }).observe(tbody, { childList: true });
  }

  /* ==========================================================================
     B7. Skeleton shimmer for "Loading…" / "—" placeholders
     ======================================================================= */
  var PLACEHOLDER = /^(—|-|–|Loading(…|\.\.\.)?|Loading .*(…|\.\.\.)|Gathering .*…)$/;
  var skelUntil = 0, skelTimer = 0;
  function skelScan() {
    var v = viewEl(activeView());
    $$(".tw-skel").forEach(function (n) {
      if (Date.now() > skelUntil || !PLACEHOLDER.test(n.textContent.trim())) n.classList.remove("tw-skel", "tw-skel-line");
    });
    if (!v || Date.now() > skelUntil) { clearInterval(skelTimer); skelTimer = 0; return; }
    $$("[id], p.muted, .ov-post-chip, .fw-num, .sys-card-chip", v).forEach(function (n) {
      if (n.childElementCount || /^(INPUT|SELECT|TEXTAREA|TD|TH|TR|TABLE|TBODY|OPTION|CANVAS|svg|BUTTON|LABEL)$/.test(n.tagName)) return;
      if (n.offsetParent === null || n.closest("td, button, select, .tw-nav-group, .page-hero")) return;
      var t = n.textContent.trim();
      if (!PLACEHOLDER.test(t)) return;
      n.classList.add("tw-skel");
      if (t.length > 2) n.classList.add("tw-skel-line");
    });
  }
  function startSkeleton() {
    skelUntil = Date.now() + 8000;
    skelScan();
    if (!skelTimer) skelTimer = setInterval(skelScan, 250);
  }

  /* ==========================================================================
     Boot
     ======================================================================= */
  var lastView = "";
  function onViewMaybeChanged() {
    var v = activeView();
    if (v && v !== lastView) {
      lastView = v;
      document.documentElement.dataset.twView = v;
      startSkeleton();
      if (v === "settings") setTimeout(buildMascotSetting, 50);
    }
  }
  function boot() {
    buildGroups();
    buildLive();
    buildSearchButton();
    buildMascotSetting();
    initSvcSummary();
    initRuleComments();
    if (nav) new MutationObserver(onViewMaybeChanged).observe(nav, { attributes: true, attributeFilter: ["class"], subtree: true });
    onViewMaybeChanged();
    // Deep link on load (dashboard.js only understands bare view names)
    var initial = location.hash;
    var p = parseHash(initial);
    var restore = function () {
      if (p.view) go(p.view, p.sub);
      else history.replaceState(null, "", currentHash());
    };
    setTimeout(restore, 150);
    var gate = document.getElementById("login-gate");
    if (gate) {
      var wasHidden = gate.hidden;
      new MutationObserver(function () {
        if (gate.hidden && !wasHidden) {
          setTimeout(function () { if (p.view) go(p.view, p.sub); tick(); }, 400);
        }
        wasHidden = gate.hidden;
      }).observe(gate, { attributes: true, attributeFilter: ["hidden"] });
    }
    setTimeout(tick, 1500);
  }
  // Password fields sit in <form data-nosubmit> wrappers (browser password
  // handling); their buttons are JS-driven, so never let them submit/reload.
  document.addEventListener("submit", function (ev) {
    if (ev.target && ev.target.matches && ev.target.matches("form[data-nosubmit]")) ev.preventDefault();
  }, true);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
