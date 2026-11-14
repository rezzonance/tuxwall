/* TuxWall — Firewall safety UI.
   Rules tab: lock + owner chip on managed rules (delete/move disabled), a
   Managed / Policy / Yours filter. Settings tab: snapshot history (snapshot
   now, diff, guarded restore with preview + 60 s confirm, download, upload,
   delete) and the legacy raw baseline (import only, restore disabled).
   Data: /api/firewall rows (owner fields), /api/firewall/snapshots*. */
(function () {
  "use strict";
  var view = document.getElementById("view-firewall");
  var table = document.getElementById("fw-rules-table");
  if (!view || !table) return;
  var tbody = table.querySelector("tbody");

  var state = { group: "", list: null, loading: false, detail: null, pending: null, timer: 0 };

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function req(method, url, body) {
    return fetch(url, {
      method: method, credentials: "same-origin", cache: "no-store",
      headers: body ? { "Content-Type": "application/json", Accept: "application/json" } : { Accept: "application/json" },
      body: body ? JSON.stringify(body) : undefined
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        j = j || {};
        j._status = r.status;
        if (!r.ok || j.ok === false) {
          var e = new Error(j.error || ("HTTP " + r.status));
          e.data = j;
          throw e;
        }
        return j;
      });
    });
  }
  function confirmBox(msg) {
    return Promise.resolve((window.twConfirm || window.confirm)(msg));
  }

  // ── Rules tab: owner chips, locks, group filter ─────────────────────────
  var SHORT = { honeypot: "Honeypot", canary: "Canary", policy: "Policy", wireguard: "WireGuard",
    nat: "NAT", mdns: "mDNS", portforward: "Port forward", dmz: "DMZ", management: "Router access",
    crowdsec: "CrowdSec", tripwire: "Tripwire", "canary-egress": "Canary egress",
    "forum-egress": "Forum egress" };
  var LOCK = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>';

  var groups = document.createElement("div");
  groups.className = "fw-chip-row fwp-groups";
  groups.setAttribute("role", "tablist");
  groups.setAttribute("aria-label", "Filter rules by owner");
  var ifChips = document.getElementById("fw-iface-chips");
  if (ifChips && ifChips.parentNode) ifChips.parentNode.insertBefore(groups, ifChips.nextSibling);

  function renderGroups(counts) {
    var defs = [["", "All rules"], ["managed", "Managed"], ["policy", "Policy"], ["yours", "Yours"]];
    groups.innerHTML = '<span class="fwp-groups-label muted">Owner</span>' + defs.map(function (d) {
      var n = d[0] ? counts[d[0]] || 0 : counts.all;
      return '<button type="button" role="tab" class="fw-chip' + (state.group === d[0] ? " active" : "") +
        '" aria-selected="' + (state.group === d[0]) + '" data-fwp-group="' + d[0] + '">' + esc(d[1]) +
        ' <span class="fw-chip-n">' + n + "</span></button>";
    }).join("");
  }

  function decorate() {
    var rows = tbody.querySelectorAll("tr[data-num]");
    var counts = { all: 0, managed: 0, policy: 0, yours: 0 };
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var g = row.dataset.group || "yours";
      counts.all++;
      counts[g] = (counts[g] || 0) + 1;
      if (!state.group || g === state.group) shown++;
      if (row.dataset.fwpDone) continue;
      row.dataset.fwpDone = "1";
      var owner = row.dataset.owner;
      if (!owner || owner === "user") continue;
      var label = row.dataset.ownerLabel || owner;
      var reason = row.dataset.ownerReason || "";
      var managed = row.dataset.managed === "1";
      var cell = row.cells[row.cells.length - 1];
      var chip = document.createElement("span");
      chip.className = "fwp-owner fwp-o-" + owner + (managed ? "" : " fwp-soft");
      chip.title = (managed ? "Managed by " : "") + label + (reason ? " — " + reason : "");
      chip.innerHTML = (managed ? LOCK : "") + esc(SHORT[owner] || owner);
      if (cell) cell.insertBefore(chip, cell.firstChild);
      if (managed) {
        row.classList.add("fwp-managed");
        var btns = row.querySelectorAll(".fw-move, .fw-remove");
        for (var b = 0; b < btns.length; b++) {
          btns[b].disabled = true;
          btns[b].setAttribute("aria-disabled", "true");
          btns[b].title = "Managed by " + label + " — change it there";
          btns[b].setAttribute("aria-label", btns[b].title);
        }
      }
    }
    renderGroups(counts);
    // one attribute on the tbody (CSS hides the rest): a single style
    // invalidation instead of one per row
    if (state.group) tbody.setAttribute("data-fwp-group", state.group);
    else tbody.removeAttribute("data-fwp-group");
    var empty = tbody.querySelector("tr.fwp-empty");
    if (rows.length && !shown) {
      if (!empty) {
        empty = document.createElement("tr");
        empty.className = "fwp-empty";
        empty.innerHTML = '<td colspan="9" class="muted" style="text-align:center;padding:1.2rem">No rules in this group.</td>';
        tbody.appendChild(empty);
      }
    } else if (empty) {
      empty.remove();
    }
  }
  new MutationObserver(function (muts) {
    for (var i = 0; i < muts.length; i++) {
      for (var j = 0; j < muts[i].addedNodes.length; j++) {
        var n = muts[i].addedNodes[j];
        if (n.nodeType === 1 && !n.classList.contains("fwp-empty")) { decorate(); return; }
      }
    }
  }).observe(tbody, { childList: true });
  groups.addEventListener("click", function (e) {
    var b = e.target.closest("[data-fwp-group]");
    if (!b) return;
    state.group = b.getAttribute("data-fwp-group");
    decorate();
  });
  if (tbody.querySelector("tr[data-num]")) decorate();

  // ── Settings tab: snapshot history ──────────────────────────────────────
  var pane = view.querySelector('.fw-pane[data-fw-pane="settings"]');
  var card = document.createElement("div");
  card.className = "card fwp-snaps";
  card.id = "fw-snapshots";
  card.innerHTML =
    '<div class="card-head"><h2>Snapshots</h2><span class="muted">Restore points for the ufw configuration. ' +
    "Managed rules (honeypot, canary, policy, WireGuard, NAT) are always kept from the current state.</span></div>" +
    '<div class="card-toolbar bl-toolbar fwp-snap-bar">' +
    '<input type="text" id="fwp-note" maxlength="200" placeholder="Note for a new snapshot (optional)" autocomplete="off">' +
    '<button type="button" class="btn btn-primary" id="fwp-snap-now">Snapshot now</button>' +
    '<span class="toolbar-spacer"></span>' +
    '<label class="btn fwp-upload" title="Upload a snapshot .tar.gz downloaded from TuxWall">Upload' +
    '<input type="file" id="fwp-upload" accept=".gz,.tgz,application/gzip" hidden></label>' +
    '<button type="button" class="btn" id="fwp-refresh">Refresh</button></div>' +
    '<div class="fwp-pending" id="fwp-pending" hidden></div>' +
    '<div class="table-wrap"><table class="fw-table fwp-table"><thead><tr>' +
    "<th>Time</th><th>Note</th><th>Type</th><th>Rules</th><th style=\"width:300px\"></th></tr></thead>" +
    '<tbody id="fwp-list"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody></table></div>' +
    '<div class="fwp-detail" id="fwp-detail" hidden></div>' +
    '<p class="muted fwp-hint" id="fwp-hint" aria-live="polite"></p>';
  if (pane) pane.appendChild(card);
  var $ = function (s) { return card.querySelector(s); };

  function hint(t, bad) {
    var h = $("#fwp-hint");
    h.textContent = t || "";
    h.classList.toggle("fwp-bad", !!bad);
  }
  function kindChip(m) {
    var k = m.kind || "manual";
    var t = { auto: "auto", manual: "manual", upload: "uploaded", legacy: "legacy" }[k] || k;
    return '<span class="fwp-kind fwp-k-' + esc(k) + '">' + esc(t) + "</span>";
  }
  function counts(m) {
    var c = m.counts || {};
    if (m.kind === "legacy") return '<span class="muted">' + (c.raw_v4 || 0) + " raw v4 / " + (c.raw_v6 || 0) + " v6</span>";
    return (c.ufw_v4 || 0) + " v4 · " + (c.ufw_v6 || 0) + " v6" +
      '<div class="muted fwp-sub">' + (c.managed || 0) + " managed · " + (c.yours || 0) + " yours</div>";
  }
  function rowBtns(m) {
    var id = esc(m.id);
    var restore = m.restorable === false
      ? '<button type="button" class="btn btn-sm" disabled title="The legacy raw baseline predates the managed rules; restore is disabled">Restore</button>'
      : '<button type="button" class="btn btn-sm" data-fwp-act="plan" data-id="' + id + '" title="Preview the restore (guard check, changes) before anything is applied">Restore</button>';
    return '<button type="button" class="btn btn-sm" data-fwp-act="diff" data-id="' + id + '">Diff</button>' + restore +
      '<a class="btn btn-sm" href="/api/firewall/snapshots/' + id + '/download" download>Download</a>' +
      '<button type="button" class="btn btn-sm" data-fwp-act="delete" data-id="' + id + '">Delete</button>';
  }
  function renderList() {
    var d = state.list;
    var body = $("#fwp-list");
    if (!d) return;
    var rows = (d.snapshots || []).map(function (m) {
      return '<tr data-id="' + esc(m.id) + '"' + (state.detail && state.detail.id === m.id ? ' class="fwp-sel"' : "") + ">" +
        '<td class="mono">' + esc(m.time || "") + (m.who ? '<div class="muted fwp-sub">' + esc(m.who) + "</div>" : "") + "</td>" +
        "<td>" + esc(m.note || m.reason || "") + (m.note && m.reason ? '<div class="muted fwp-sub">' + esc(m.reason) + "</div>" : "") + "</td>" +
        "<td>" + kindChip(m) + "</td><td>" + counts(m) + '</td><td class="fwp-actions">' + rowBtns(m) + "</td></tr>";
    });
    var lg = d.legacy || {};
    if (lg.present && !lg.imported_as) {
      rows.push('<tr class="fwp-legacy"><td class="mono">' + esc(lg.time) + "</td><td>" + esc(lg.label) +
        '<div class="muted fwp-sub">' + esc(lg.path) + " (kept untouched)</div></td><td>" + kindChip({ kind: "legacy" }) +
        '</td><td class="muted">raw iptables</td><td class="fwp-actions">' +
        '<button type="button" class="btn btn-sm" data-fwp-act="import">Import into history</button>' +
        '<button type="button" class="btn btn-sm" disabled title="Restore of the legacy raw baseline is disabled">Restore</button></td></tr>');
    }
    body.innerHTML = rows.length ? rows.join("") :
      '<tr><td colspan="5" class="muted" style="text-align:center;padding:1rem">No snapshots yet. Use “Snapshot now”.</td></tr>';
  }
  function load() {
    if (state.loading) return;
    state.loading = true;
    req("GET", "/api/firewall/snapshots").then(function (d) {
      state.list = d;
      renderList();
    }).catch(function (e) {
      $("#fwp-list").innerHTML = '<tr><td colspan="5" class="muted">Snapshots unavailable: ' + esc(e.message) + "</td></tr>";
    }).then(function () { state.loading = false; });
  }

  function guardHtml(g) {
    if (!g) return "";
    var items = [];
    (g.blocking || []).forEach(function (v) { items.push(["blocking", v]); });
    (g.new || []).forEach(function (v) { if ((g.blocking || []).indexOf(v) < 0 && !(g.blocking || []).some(function (b) { return b.id === v.id; })) items.push(["new", v]); });
    (g.existing || []).forEach(function (v) { items.push(["existing", v]); });
    var head = g.ok ? '<div class="fwp-guard fwp-ok">Firewall guard: passed</div>'
      : '<div class="fwp-guard fwp-refused">Firewall guard: refused</div>';
    if (!items.length) return head;
    return head + '<ul class="fwp-vlist">' + items.map(function (x) {
      var v = x[1];
      return '<li class="fwp-sev-' + esc(v.severity) + '"><span class="fwp-sev">' + esc(v.severity) + "</span> " +
        esc(v.title) + (x[0] === "existing" ? ' <span class="muted">(already the case today)</span>' : "") +
        (v.detail ? '<div class="muted fwp-sub">' + esc(v.detail) + "</div>" : "") + "</li>";
    }).join("") + "</ul>";
  }
  function unifiedHtml(u) {
    var keys = Object.keys(u || {});
    if (!keys.length) return "";
    return keys.map(function (k) {
      var lines = String(u[k]).split("\n").map(function (l) {
        var c = l.charAt(0) === "+" && l.indexOf("+++") !== 0 ? "fwp-add" : (l.charAt(0) === "-" && l.indexOf("---") !== 0 ? "fwp-del" : "");
        return '<span class="' + c + '">' + esc(l) + "</span>";
      }).join("\n");
      return '<details class="fwp-udiff"><summary>' + esc(k) + "</summary><pre>" + lines + "</pre></details>";
    }).join("");
  }
  function showDetail(html, id) {
    var el = $("#fwp-detail");
    el.innerHTML = html;
    el.hidden = false;
    state.detail = { id: id };
    renderList();
    el.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
  function closeBtn() {
    return '<button type="button" class="btn btn-sm fwp-close" data-fwp-act="close">Close</button>';
  }

  function doDiff(id) {
    hint("Comparing…");
    req("GET", "/api/firewall/snapshots/" + encodeURIComponent(id) + "/diff").then(function (d) {
      hint("");
      var m = d.meta || {};
      var ch = (d.changes || []).map(function (c) {
        return '<li class="fwp-ch fwp-ch-' + esc(c.kind) + (c.managed ? " fwp-ch-managed" : "") + '">' + esc(c.text) + "</li>";
      }).join("");
      showDetail('<div class="fwp-detail-head"><h3>Diff: ' + esc(m.time || id) + " → now</h3>" + closeBtn() + "</div>" +
        '<ul class="fwp-changes">' + ch + "</ul>" + unifiedHtml(d.unified), id);
    }).catch(function (e) { hint("Diff failed: " + e.message, true); });
  }

  function doPlan(id) {
    hint("Preparing restore preview…");
    req("POST", "/api/firewall/snapshots/" + encodeURIComponent(id) + "/restore", { dry_run: true }).then(function (p) {
      hint("");
      var m = p.meta || {};
      var g = p.guard || {};
      var list = function (title, arr, cls) {
        if (!arr || !arr.length) return "";
        return '<div class="fwp-plan-sec"><b>' + esc(title) + " (" + arr.length + ')</b><ul class="' + cls + '">' +
          arr.slice(0, 40).map(function (t) { return "<li>" + esc(t) + "</li>"; }).join("") +
          (arr.length > 40 ? '<li class="muted">… ' + (arr.length - 40) + " more</li>" : "") + "</ul></div>";
      };
      var can = g.ok && !p.no_changes;
      showDetail('<div class="fwp-detail-head"><h3>Restore preview: ' + esc(m.time || id) + "</h3>" + closeBtn() + "</div>" +
        guardHtml(g) +
        '<div class="fwp-lockout">' + esc(p.lockout_warning || "") + "</div>" +
        (p.no_changes ? '<p class="muted">Nothing to restore: the firewall files already match this snapshot (managed rules kept).</p>' : "") +
        list("Your rules that come back", p.rules_added, "fwp-add-list") +
        list("Rules that will be removed", p.rules_removed, "fwp-del-list") +
        '<p class="muted">' + (p.managed_kept || 0) + " managed rules are kept from the current firewall. " +
        esc((p.notes || []).join(" · ")) + "</p>" +
        list("Steps", p.actions, "fwp-steps") +
        '<div class="fwp-plan-foot">' + (can
          ? '<button type="button" class="btn btn-danger" data-fwp-act="restore" data-id="' + esc(id) + '">Restore now (60 s to confirm)</button>'
          : '<button type="button" class="btn" disabled>Restore now</button>') + "</div>", id);
    }).catch(function (e) {
      hint("", false);
      var d = e.data || {};
      showDetail('<div class="fwp-detail-head"><h3>Restore preview</h3>' + closeBtn() + "</div>" +
        '<div class="fwp-guard fwp-refused">' + esc(e.message) + "</div>" + guardHtml(d.guard), id);
    });
  }

  function doRestore(id) {
    confirmBox("Restore this snapshot now?\n\nThe ufw files are replaced (managed rules kept), ufw reloads, and " +
      "you have 60 seconds to confirm. Without confirmation the previous firewall comes back automatically.").then(function (ok) {
      if (!ok) return;
      hint("Restoring…");
      req("POST", "/api/firewall/snapshots/" + encodeURIComponent(id) + "/restore", { dry_run: false }).then(function (r) {
        if (r.no_changes) { hint(r.message || "No changes."); return; }
        startPending(r.needs_confirmation, r.confirm_within_s || 60, id);
        hint(r.message || "Restored.");
        load();
      }).catch(function (e) {
        hint("Restore refused: " + e.message, true);
        if (e.data && e.data.guard) showDetail('<div class="fwp-detail-head"><h3>Restore refused</h3>' + closeBtn() + "</div>" + guardHtml(e.data.guard), id);
      });
    });
  }

  function startPending(cid, secs, id) {
    state.pending = { id: cid, until: Date.now() + secs * 1000, snap: id };
    var el = $("#fwp-pending");
    el.hidden = false;
    clearInterval(state.timer);
    var tick = function () {
      var p = state.pending;
      if (!p) return;
      var left = Math.max(0, Math.round((p.until - Date.now()) / 1000));
      if (!left) {
        clearInterval(state.timer);
        el.innerHTML = "<b>Not confirmed.</b> The previous firewall was restored automatically.";
        state.pending = null;
        setTimeout(load, 1500);
        return;
      }
      el.innerHTML = "<b>Snapshot restored.</b> Keep it? Reverting in <span class=\"mono\">" + left + " s</span>. " +
        '<button type="button" class="btn btn-primary btn-sm" data-fwp-act="confirm">Keep these rules</button>';
    };
    tick();
    state.timer = setInterval(tick, 1000);
  }

  card.addEventListener("click", function (e) {
    var b = e.target.closest("[data-fwp-act]");
    if (!b) return;
    var act = b.getAttribute("data-fwp-act");
    var id = b.getAttribute("data-id");
    if (act === "diff") doDiff(id);
    else if (act === "plan") doPlan(id);
    else if (act === "restore") doRestore(id);
    else if (act === "close") { $("#fwp-detail").hidden = true; state.detail = null; renderList(); }
    else if (act === "confirm") {
      var p = state.pending;
      if (!p) return;
      req("POST", "/api/firewall/confirm", { id: p.id }).then(function () {
        clearInterval(state.timer);
        state.pending = null;
        $("#fwp-pending").innerHTML = "Restore confirmed.";
        setTimeout(function () { $("#fwp-pending").hidden = true; }, 4000);
      }).catch(function (err) { hint("Confirm failed: " + err.message, true); });
    } else if (act === "delete") {
      confirmBox("Delete this snapshot?").then(function (ok) {
        if (!ok) return;
        req("POST", "/api/firewall/snapshots/" + encodeURIComponent(id) + "/delete", {}).then(function () {
          hint("Snapshot deleted.");
          load();
        }).catch(function (err) { hint("Delete failed: " + err.message, true); });
      });
    } else if (act === "import") {
      req("POST", "/api/firewall/snapshots/import-legacy", {}).then(function () {
        hint("Legacy baseline imported into the history (diff only; restore stays disabled).");
        load();
      }).catch(function (err) { hint("Import failed: " + err.message, true); });
    }
  });

  function snapNow(note) {
    hint("Saving snapshot…");
    return req("POST", "/api/firewall/snapshots", { note: note || "" }).then(function (r) {
      hint("Snapshot saved (" + (r.snapshot && r.snapshot.id) + ").");
      $("#fwp-note").value = "";
      load();
      return r;
    }).catch(function (e) { hint("Snapshot failed: " + e.message, true); });
  }
  $("#fwp-snap-now").addEventListener("click", function () { snapNow($("#fwp-note").value.trim()); });
  $("#fwp-note").addEventListener("keydown", function (e) { if (e.key === "Enter") snapNow($("#fwp-note").value.trim()); });
  $("#fwp-refresh").addEventListener("click", load);
  $("#fwp-upload").addEventListener("change", function () {
    var f = this.files && this.files[0];
    this.value = "";
    if (!f) return;
    if (f.size > 2 * 1024 * 1024) { hint("That file is larger than 2 MB.", true); return; }
    var rd = new FileReader();
    rd.onload = function () {
      var data = String(rd.result || "").split(",")[1] || "";
      req("POST", "/api/firewall/snapshots/upload", { data: data, note: "Uploaded " + f.name }).then(function () {
        hint("Snapshot uploaded and validated. Use Restore… to preview it.");
        load();
      }).catch(function (e) { hint("Upload refused: " + e.message, true); });
    };
    rd.readAsDataURL(f);
  });

  function openSnapshots() {
    var tab = document.querySelector('#fw-subtabs .fw-subtab[data-fw-pane="settings"]');
    if (tab) tab.click();
    load();
    setTimeout(function () { card.scrollIntoView({ block: "start", behavior: "smooth" }); }, 50);
  }
  window.twFwSnapshots = openSnapshots;

  // The Rules-tab "Restore baseline" / "Save baseline" buttons now lead into
  // the snapshot history (the legacy raw restore is gone).
  document.addEventListener("click", function (e) {
    var b = e.target.closest("#fw-reset, #fw-baseline");
    if (!b) return;
    e.preventDefault();
    e.stopPropagation();
    if (b.id === "fw-baseline") snapNow("Saved from the Rules tab");
    openSnapshots();
  }, true);

  var subtabs = document.getElementById("fw-subtabs");
  if (subtabs) subtabs.addEventListener("click", function (e) {
    var t = e.target.closest('.fw-subtab[data-fw-pane="settings"]');
    if (t && !state.list) load();
  });
  if (pane && !pane.hidden && !view.hidden) load();

  // ══ Session 2: findings, suggestions, edit / enable-disable, hit counters ══
  var SVG = {
    edit: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L9 17l-4 1 1-4Z"/></svg>',
    power: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2v10"/><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/></svg>',
    explain: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/><path d="M11 8v3l2 1"/></svg>',
    tab: '<path d="M12 3 2 20h20Z"/><path d="M12 10v4"/><path d="M12 17h.01"/>'
  };
  var SEV = ["critical", "high", "medium", "low", "info"];
  var s2 = { findings: null, sugg: null, sev: "", hits: null, hitsAt: 0, byNum: {}, pend: null, ptimer: 0, ed: null };

  // navigation helpers (dashboard.js is an IIFE: go through the DOM)
  function go(href) {
    var parts = String(href || "").replace(/^#/, "").split("/");
    var nav = document.querySelector('.nav-item[data-view="' + parts[0] + '"]');
    if (nav) nav.click();
    if (parts[1]) setTimeout(function () {
      var v = document.getElementById("view-" + parts[0]);
      var t = v && v.querySelector('.fw-subtab[data-fw-pane="' + parts[1] + '"], .fw-subtab[data-sec-pane="' + parts[1] + '"]');
      if (t) t.click();
      if (parts[0] === "interfaces") {
        var m = document.getElementById("if-matrix");
        if (m) m.scrollIntoView({ block: "center", behavior: "smooth" });
      }
    }, 60);
  }
  function explain(target) {
    go("#security/traffic");
    setTimeout(function () {
      var inp = document.getElementById("diag-target");
      if (!inp) return;
      inp.value = target || "";
      inp.scrollIntoView({ block: "center", behavior: "smooth" });
      inp.focus();
      if (target) { var b = document.getElementById("diag-btn"); if (b) b.click(); }
    }, 160);
  }
  window.twFwExplain = explain;
  function showRule(num) {
    var tab = document.querySelector('#fw-subtabs .fw-subtab[data-fw-pane="rules"]');
    if (tab) tab.click();
    state.group = "";
    decorate();
    var fi = document.querySelector('#fw-iface-chips [data-fw-iface=""]');
    if (fi && !fi.classList.contains("active")) fi.click();
    var srch = document.getElementById("fw-search");
    if (srch && srch.value) { srch.value = ""; srch.dispatchEvent(new Event("input", { bubbles: true })); }
    setTimeout(function () {
      var row = tbody.querySelector('tr[data-num="' + num + '"]');
      if (!row) return;
      var old = tbody.querySelectorAll("tr.fwp-flash");
      for (var i = 0; i < old.length; i++) old[i].classList.remove("fwp-flash");
      row.classList.add("fwp-flash");
      row.scrollIntoView({ block: "center", behavior: "smooth" });
    }, 80);
  }
  function refreshRules() {
    s2.hitsAt = 0;
    var nav = document.querySelector('.nav-item[data-view="firewall"]');
    if (nav) nav.click();
  }

  // ── plan preview + apply + confirm (shared by Fix…, suggestions, edit, toggle) ──
  function qs(o) {
    return Object.keys(o).filter(function (k) { return o[k] != null && o[k] !== ""; }).map(function (k) {
      return encodeURIComponent(k) + "=" + encodeURIComponent(o[k]);
    }).join("&");
  }
  function planHtml(p, params) {
    var g = p.guard || {};
    var ch = (p.changes || []).map(function (c) {
      return '<li class="fwp-pc fwp-pc-' + esc(c.kind) + '"><b>' + (c.kind === "add" ? "+" : c.kind === "remove" ? "−" : "↕") +
        "</b> " + esc(c.plain) + '<div class="mono muted fwp-sub">' + esc(c.text) + "</div></li>";
    }).join("");
    var can = g.ok && !p.no_changes;
    return guardHtml(g) + '<div class="fwp-lockout">' + esc(p.lockout_warning || "") + "</div>" +
      (ch ? '<ul class="fwp-plan-changes">' + ch + "</ul>" : "") +
      ((p.actions || []).length ? '<div class="muted fwp-sub">Steps: ' + esc(p.actions.join(" → ")) + "</div>" : "") +
      '<div class="fwp-plan-foot">' + (can
        ? '<button type="button" class="btn btn-danger btn-sm" data-s2="apply" data-params="' + esc(JSON.stringify(params)) +
          '">Apply (60 s to confirm)</button>'
        : '<button type="button" class="btn btn-sm" disabled>Apply</button>') +
      ' <button type="button" class="btn btn-sm" data-s2="close-plan">Cancel</button></div>';
  }
  function openPlan(host, params) {
    host.hidden = false;
    host.innerHTML = '<div class="muted">Preparing preview…</div>';
    return req("GET", "/api/firewall/plan?" + qs(params)).then(function (p) {
      host.innerHTML = planHtml(p, params);
    }).catch(function (e) {
      var d = e.data || {};
      host.innerHTML = '<div class="fwp-guard fwp-refused">' + esc(e.message) + "</div>" + guardHtml(d.guard) +
        ' <button type="button" class="btn btn-sm" data-s2="close-plan">Close</button>';
    });
  }
  function applyPlan(btn) {
    var params = {};
    try { params = JSON.parse(btn.getAttribute("data-params") || "{}"); } catch (_) { return; }
    var host = btn.closest(".fwp-plan");
    confirmBox("Apply this firewall change now?\n\nAn automatic snapshot is taken first. You then have 60 seconds " +
      "to confirm; without confirmation the previous rules come back automatically.").then(function (ok) {
      if (!ok) return;
      btn.disabled = true;
      req("POST", "/api/firewall/apply", params).then(function (r) {
        if (host) host.innerHTML = '<div class="fwp-guard fwp-ok">' + esc(r.message || "Applied.") + "</div>";
        if (r.needs_confirmation) startConfirm(r.needs_confirmation, r.confirm_within_s || 60);
        s2.findings = s2.sugg = null;
        refreshRules();
      }).catch(function (e) {
        btn.disabled = false;
        if (host) host.innerHTML = '<div class="fwp-guard fwp-refused">' + esc(e.message) + "</div>" +
          guardHtml((e.data || {}).guard) + ' <button type="button" class="btn btn-sm" data-s2="close-plan">Close</button>';
      });
    });
  }
  var bar = document.createElement("div");
  bar.className = "fwp-confirm";
  bar.hidden = true;
  bar.setAttribute("role", "status");
  view.appendChild(bar);
  function startConfirm(cid, secs) {
    s2.pend = { id: cid, until: Date.now() + secs * 1000 };
    bar.hidden = false;
    clearInterval(s2.ptimer);
    var tick = function () {
      var p = s2.pend;
      if (!p) return;
      var left = Math.max(0, Math.round((p.until - Date.now()) / 1000));
      if (!left) {
        clearInterval(s2.ptimer);
        s2.pend = null;
        bar.innerHTML = "<b>Not confirmed.</b> The previous rules were restored automatically.";
        setTimeout(function () { bar.hidden = true; refreshRules(); }, 2500);
        return;
      }
      bar.innerHTML = "<b>Firewall changed.</b> Keep it? Reverting in <span class=\"mono\">" + left + " s</span> " +
        '<button type="button" class="btn btn-primary btn-sm" data-s2="keep">Keep the change</button>';
    };
    tick();
    s2.ptimer = setInterval(tick, 1000);
  }
  bar.addEventListener("click", function (e) {
    if (!e.target.closest('[data-s2="keep"]') || !s2.pend) return;
    req("POST", "/api/firewall/confirm", { id: s2.pend.id }).then(function () {
      clearInterval(s2.ptimer);
      s2.pend = null;
      bar.innerHTML = "Change kept.";
      setTimeout(function () { bar.hidden = true; }, 3000);
    }).catch(function (err) { bar.innerHTML = "Confirm failed: " + esc(err.message); });
  });

  // ── Findings pane ─────────────────────────────────────────────────────────
  var fpane = view.querySelector('.fw-pane[data-fw-pane="findings"]');
  var ftab = document.querySelector('#fw-subtabs .fw-subtab[data-fw-pane="findings"]');
  if (ftab && !ftab.querySelector(".tab-ic")) {
    var ic = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    ic.setAttribute("class", "tab-ic");
    ic.setAttribute("viewBox", "0 0 24 24");
    ic.setAttribute("aria-hidden", "true");
    ic.setAttribute("fill", "none");
    ic.setAttribute("stroke", "currentColor");
    ic.innerHTML = SVG.tab;
    ftab.insertBefore(ic, ftab.firstChild);
  }
  if (fpane) {
    fpane.innerHTML =
      '<div class="card fwp-findings" id="fw-findings"><div class="card-head"><h2>Findings</h2>' +
      '<span class="muted">What the ruleset actually does that you may not intend. Nothing is changed until you apply a previewed fix.</span></div>' +
      '<div class="fw-chip-row fwp-sevs" role="tablist" aria-label="Filter findings by severity"></div>' +
      '<div class="fwp-flist" id="fwp-flist"><div class="muted fwp-pad">Loading…</div></div></div>' +
      '<div class="card fwp-sugg" id="fw-suggestions"><div class="card-head"><h2>Suggestions</h2>' +
      '<span class="muted">Plans built from listening services, blocked traffic and templates. Preview first; nothing applies automatically.</span></div>' +
      '<div class="fwp-flist" id="fwp-slist"><div class="muted fwp-pad">Loading…</div></div></div>';
  }
  function refChips(rules) {
    return (rules || []).filter(function (r) { return r.number; }).map(function (r) {
      return '<button type="button" class="fwp-ref mono" data-s2="ref" data-num="' + r.number + '" title="' + esc(r.text) +
        '">#' + r.number + (r.family === "v6" ? " v6" : "") + "</button>";
    }).join("");
  }
  function fixBtn(f, idx, list) {
    var x = f.fix;
    var ex = f.explain ? '<button type="button" class="btn btn-sm" data-s2="explain" data-target="' + esc(f.explain) + '">Explain</button>' : "";
    if (!x) return ex;
    if (x.kind === "link") return '<button type="button" class="btn btn-sm" data-s2="link" data-href="' + esc(x.href) + '">' + esc(x.label || "Open") + "</button>" + ex;
    return '<button type="button" class="btn btn-sm btn-primary" data-s2="fix" data-list="' + list + '" data-idx="' + idx + '">Fix…</button>' + ex;
  }
  function findingHtml(f, i) {
    var long = (f.detail || "").length > 220 || (f.raw || []).length;
    return '<div class="fwp-f fwp-sev-' + esc(f.severity) + '" data-id="' + esc(f.id) + '">' +
      '<div class="fwp-f-head"><span class="fwp-sev">' + esc(f.severity) + '</span><span class="fwp-f-title">' + esc(f.title) + "</span></div>" +
      (f.detail ? (long ? '<details class="fwp-f-more"><summary>' + esc(f.detail.split("\n")[0].slice(0, 160)) + "</summary>" +
        '<div class="fwp-f-detail">' + esc(f.detail) + "</div>" +
        ((f.raw || []).length ? '<pre class="fwp-raw">' + esc(f.raw.join("\n")) + "</pre>" : "") + "</details>"
        : '<div class="fwp-f-detail">' + esc(f.detail) + "</div>") : "") +
      '<div class="fwp-f-foot">' + refChips(f.rules) + '<span class="fwp-sp"></span>' + fixBtn(f, i, "f") + "</div>" +
      '<div class="fwp-plan" hidden></div></div>';
  }
  function renderFindings() {
    var d = s2.findings;
    var box = document.getElementById("fwp-flist");
    if (!d || !box) return;
    var c = d.counts || {};
    var sevs = fpane.querySelector(".fwp-sevs");
    sevs.innerHTML = '<button type="button" role="tab" class="fw-chip' + (!s2.sev ? " active" : "") + '" aria-selected="' + !s2.sev +
      '" data-s2="sev" data-sev="">All <span class="fw-chip-n">' + (d.findings || []).length + "</span></button>" +
      SEV.filter(function (s) { return c[s]; }).map(function (s) {
        return '<button type="button" role="tab" class="fw-chip fwp-chip-' + s + (s2.sev === s ? " active" : "") + '" aria-selected="' +
          (s2.sev === s) + '" data-s2="sev" data-sev="' + s + '">' + s + ' <span class="fw-chip-n">' + c[s] + "</span></button>";
      }).join("");
    var list = (d.findings || []).map(function (f, i) { return [f, i]; }).filter(function (x) { return !s2.sev || x[0].severity === s2.sev; });
    box.innerHTML = list.length ? list.map(function (x) { return findingHtml(x[0], x[1]); }).join("")
      : '<div class="muted fwp-pad">' + ((d.findings || []).length ? "No findings at this severity." : "No findings — the ruleset does what it says.") + "</div>";
    if (ftab) {
      var top = (c.critical || 0) + (c.high || 0);
      var badge = ftab.querySelector(".fwp-tabn");
      if (!badge) { badge = document.createElement("span"); badge.className = "fwp-tabn"; ftab.appendChild(badge); }
      badge.textContent = top ? String(top) : "";
      badge.hidden = !top;
    }
  }
  function suggHtml(s, i) {
    var plan = s.plan || {};
    var st = s.status ? '<span class="fwp-st fwp-st-' + esc(s.status) + '">' + esc(s.status === "ok" ? "in place" : s.status) + "</span>" : "";
    var btns = "";
    if (plan.op && plan.op !== "template") btns += '<button type="button" class="btn btn-sm btn-primary" data-s2="fix" data-list="s" data-idx="' + i + '">Preview…</button>';
    if (plan.op === "template") btns += '<button type="button" class="btn btn-sm" data-s2="tpl" data-idx="' + i + '">Show rules</button>';
    if (s.href) btns += '<button type="button" class="btn btn-sm" data-s2="link" data-href="' + esc(s.href) + '">' + (s.href === "#interfaces" ? "Policy matrix" : "Open") + "</button>";
    if (s.explain) btns += '<button type="button" class="btn btn-sm" data-s2="explain" data-target="' + esc(s.explain) + '">Explain</button>';
    return '<div class="fwp-f fwp-s fwp-k-' + esc(s.kind) + '"><div class="fwp-f-head"><span class="fwp-kind">' + esc(s.kind) + "</span>" +
      '<span class="fwp-f-title">' + esc(s.title) + "</span>" + st + "</div>" +
      (s.detail ? '<div class="fwp-f-detail">' + esc(s.detail) + "</div>" : "") +
      '<div class="fwp-f-foot">' + refChips(s.rules) + '<span class="fwp-sp"></span>' + btns + "</div>" +
      '<div class="fwp-plan" hidden></div></div>';
  }
  function renderSugg() {
    var box = document.getElementById("fwp-slist");
    if (!s2.sugg || !box) return;
    var l = s2.sugg.suggestions || [];
    box.innerHTML = l.length ? l.map(suggHtml).join("") : '<div class="muted fwp-pad">No suggestions right now.</div>';
  }
  function loadFindings(force) {
    if (!fpane) return;
    if (force || !s2.findings) {
      req("GET", "/api/firewall/findings").then(function (d) { s2.findings = d; renderFindings(); })
        .catch(function (e) { document.getElementById("fwp-flist").innerHTML = '<div class="muted fwp-pad">Findings unavailable: ' + esc(e.message) + "</div>"; });
    } else renderFindings();
    if (force || !s2.sugg) {
      req("GET", "/api/firewall/suggestions").then(function (d) { s2.sugg = d; renderSugg(); })
        .catch(function (e) { document.getElementById("fwp-slist").innerHTML = '<div class="muted fwp-pad">Suggestions unavailable: ' + esc(e.message) + "</div>"; });
    } else renderSugg();
  }
  function fixParams(x) {
    var p = { op: x.op };
    ["number", "to", "expect", "rule", "before", "id", "port"].forEach(function (k) { if (x[k] != null) p[k] = x[k]; });
    return p;
  }
  function manualHtml(x) {
    return '<div class="fwp-guard">Preview only — this file is not edited from the dashboard.</div>' +
      ((x.steps || []).length ? '<ol class="fwp-steps">' + x.steps.map(function (s) { return "<li>" + esc(s) + "</li>"; }).join("") + "</ol>" : "") +
      (x.diff ? '<pre class="fwp-raw">' + x.diff.split("\n").map(function (l) {
        var c = l.charAt(0) === "+" && l.indexOf("+++") ? "fwp-add" : (l.charAt(0) === "-" && l.indexOf("---") ? "fwp-del" : "");
        return '<span class="' + c + '">' + esc(l) + "</span>";
      }).join("\n") + "</pre>" : "") + '<button type="button" class="btn btn-sm" data-s2="close-plan">Close</button>';
  }

  view.addEventListener("click", function (e) {
    var b = e.target.closest("[data-s2]");
    if (!b || !view.contains(b)) return;
    var act = b.getAttribute("data-s2");
    var item = b.closest(".fwp-f");
    if (act === "ref") showRule(b.getAttribute("data-num"));
    else if (act === "sev") { s2.sev = b.getAttribute("data-sev"); renderFindings(); }
    else if (act === "link") go(b.getAttribute("data-href"));
    else if (act === "explain") explain(b.getAttribute("data-target"));
    else if (act === "close-plan") { var h = b.closest(".fwp-plan"); if (h) { h.hidden = true; h.innerHTML = ""; } }
    else if (act === "apply") applyPlan(b);
    else if (act === "tpl" && item) {
      var s = (s2.sugg.suggestions || [])[+b.getAttribute("data-idx")];
      var host = item.querySelector(".fwp-plan");
      host.hidden = false;
      host.innerHTML = '<div class="muted fwp-sub">Equivalent ufw rules (for reference; the policy matrix writes managed versions):</div><pre class="fwp-raw">' +
        esc((s.plan.rules || []).join("\n")) + '</pre><button type="button" class="btn btn-sm" data-s2="close-plan">Close</button>';
    } else if (act === "fix" && item) {
      var src = b.getAttribute("data-list") === "s" ? (s2.sugg.suggestions || []) : (s2.findings.findings || []);
      var f = src[+b.getAttribute("data-idx")];
      var x = f.fix || f.plan;
      var host2 = item.querySelector(".fwp-plan");
      if (!x || !host2) return;
      if (x.kind === "manual") { host2.hidden = false; host2.innerHTML = manualHtml(x); }
      else if (x.kind === "edit") { showRule(x.number); setTimeout(function () { openEditor(x.number); }, 150); }
      else openPlan(host2, fixParams(x));
    }
  });
  if (ftab) ftab.addEventListener("click", function () { loadFindings(false); });
  if (fpane && !fpane.hidden && !view.hidden) loadFindings(false);

  // ── Rules tab: hit counters, Edit / Disable / Explain per row ─────────────
  function ago(t) {
    if (!t) return "never";
    var s = Math.max(0, Date.now() / 1000 - t);
    return s < 90 ? "just now" : s < 5400 ? Math.round(s / 60) + " min ago" : s < 129600 ? Math.round(s / 3600) + " h ago" : Math.round(s / 86400) + " d ago";
  }
  function fmtN(n) { return n == null ? "–" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e4 ? Math.round(n / 1e3) + "k" : String(n); }
  function spark(a) {
    var max = Math.max.apply(null, a.concat([1]));
    var pts = a.map(function (v, i) { return (i * 40 / (a.length - 1)).toFixed(1) + "," + (11 - v / max * 10).toFixed(1); }).join(" ");
    return '<svg class="fwp-spark" viewBox="0 0 40 12" aria-hidden="true"><polyline points="' + pts + '"/></svg>';
  }
  function hitsHtml(h) {
    if (!h || h.hits == null) return "";
    var tip = "Matched " + (h.hits || 0) + " packets since the last firewall reload" +
      (h.total != null ? "; " + h.total + " since " + new Date((h.first || 0) * 1000).toLocaleDateString() : "") +
      ". Last hit: " + ago(h.last_hit) + ". Sparkline: last 24 h.";
    return '<span class="fwp-hits' + (h.hits ? "" : " fwp-zero") + '" title="' + esc(tip) + '">' + spark(h.spark || [0, 0]) +
      '<span class="mono">' + fmtN(h.hits) + "</span> hits" + (h.last_hit ? " · " + ago(h.last_hit) : "") + "</span>";
  }
  function rowTarget(row) {
    var c = [(row.dataset.from || "").split(" ")[0], (row.dataset.to || "").split(" ")[0]];
    for (var i = 0; i < c.length; i++) if (/^\d{1,3}(\.\d{1,3}){3}$/.test(c[i])) return c[i];
    return "";
  }
  function decorateS2() {
    var rows = tbody.querySelectorAll("tr[data-num]");
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i], num = row.dataset.num;
      if (!num || row.dataset.fwpS2 === String(s2.hitsAt)) continue;
      row.dataset.fwpS2 = String(s2.hitsAt);
      var cell = row.cells[row.cells.length - 1], src = row.cells[4];
      if (!cell || !src) continue;
      var meta = src.querySelector(".fwp-meta");
      if (!meta) {
        var tgt = rowTarget(row);
        meta = document.createElement("div");
        meta.className = "fwp-meta";
        meta.innerHTML = '<span class="fwp-hslot"></span><button type="button" class="fwp-link" data-s2r="explain" data-target="' + esc(tgt) +
          '" title="Open Security → Traffic → Diagnose' + (tgt ? " for " + esc(tgt) : "") + '">Explain</button>';
        src.appendChild(meta);
        if (row.dataset.managed !== "1") {
          var span = document.createElement("span");
          span.className = "fwp-rowx";
          span.innerHTML = '<button type="button" class="act-btn fwp-act" data-s2r="edit" title="Edit this rule (preview, guard, 60 s confirm)" aria-label="Edit rule ' + esc(num) + '">' + SVG.edit + "</button>" +
            '<button type="button" class="act-btn fwp-act" data-s2r="disable" title="Disable (removed from ufw, kept under Disabled rules)" aria-label="Disable rule ' + esc(num) + '">' + SVG.power + "</button>";
          cell.appendChild(span);
        }
      }
      var h = s2.byNum[num];
      if (h) meta.firstChild.innerHTML = hitsHtml(h);
    }
    // an open editor survives the periodic re-render of the table
    if (s2.ed && !s2.ed.node.isConnected) {
      var r = tbody.querySelector('tr[data-num="' + s2.ed.num + '"]');
      if (r) r.parentNode.insertBefore(s2.ed.node, r.nextSibling);
      else s2.ed = null;
    }
  }
  function loadHits() {
    if (Date.now() - s2.hitsAt < 60000 && s2.hits) { decorateS2(); return; }
    req("GET", "/api/firewall/hits").then(function (d) {
      s2.hits = d;
      s2.hitsAt = Date.now();
      s2.byNum = {};
      (d.rules || []).forEach(function (r) { s2.byNum[r.number] = r; });
      decorateS2();
    }).catch(function () { /* counters optional */ });
  }
  new MutationObserver(function () {
    if (tbody.querySelector("tr[data-num]:not([data-fwp-s2])")) {
      decorateS2();
      loadHits();
    }
  }).observe(tbody, { childList: true });
  if (tbody.querySelector("tr[data-num]")) loadHits();

  function editorRow(row) {
    var n = row.nextElementSibling;
    if (n && n.classList.contains("fwp-edrow")) return n;
    if (s2.ed && s2.ed.node.isConnected) s2.ed.node.remove();
    n = document.createElement("tr");
    n.className = "fwp-edrow";
    n.innerHTML = '<td colspan="9"><div class="fwp-ed"></div></td>';
    row.parentNode.insertBefore(n, row.nextSibling);
    s2.ed = { num: row.dataset.num, node: n };
    return n;
  }
  function openEditor(num) {
    var row = tbody.querySelector('tr[data-num="' + num + '"]');
    var h = s2.byNum[num];
    if (!row || !h) return;
    var tr = editorRow(row);
    var box = tr.querySelector(".fwp-ed");
    var text = h.text || "";
    var m = text.match(/^(.*?)(?: comment '(.*)')?$/);
    box.innerHTML = '<div class="fwp-ed-grid"><label>Rule <input type="text" class="mono fwp-ed-rule" value="' + esc(m ? m[1] : text) + '" spellcheck="false" autocomplete="off"></label>' +
      '<label>Comment <input type="text" class="fwp-ed-com" maxlength="120" value="' + esc(m && m[2] ? m[2] : "") + '" placeholder="why this rule exists"></label></div>' +
      '<div class="muted fwp-sub">Now: ' + esc(h.plain || "") + "</div>" +
      '<div class="fwp-ed-btns"><button type="button" class="btn btn-sm btn-primary" data-s2e="preview" data-num="' + num + '">Preview</button>' +
      ' <button type="button" class="btn btn-sm" data-s2e="cancel">Cancel</button></div><div class="fwp-plan" hidden></div>';
    box.querySelector(".fwp-ed-rule").focus();
  }
  tbody.addEventListener("click", function (e) {
    var b = e.target.closest("[data-s2r], [data-s2e]");
    if (!b) return;
    var row = b.closest("tr[data-num]");
    var act = b.getAttribute("data-s2r") || b.getAttribute("data-s2e");
    if (act === "explain") { explain(b.getAttribute("data-target")); return; }
    if (act === "cancel") { var er = b.closest("tr.fwp-edrow"); if (er) er.remove(); s2.ed = null; return; }
    if (act === "edit" && row) { openEditor(row.dataset.num); return; }
    var hh = row ? s2.byNum[row.dataset.num] : null;
    if (act === "disable" && row) {
      var tr = editorRow(row);
      var host = tr.querySelector(".fwp-ed");
      host.innerHTML = '<div class="fwp-plan"></div>';
      openPlan(host.querySelector(".fwp-plan"), { op: "disable", number: row.dataset.num, expect: hh ? hh.key : "" });
      return;
    }
    if (act === "preview") {
      var ed = b.closest(".fwp-ed");
      var rule = ed.querySelector(".fwp-ed-rule").value.trim();
      var com = ed.querySelector(".fwp-ed-com").value.trim();
      var num = b.getAttribute("data-num");
      var h2 = s2.byNum[num];
      openPlan(ed.querySelector(".fwp-plan"), { op: "edit", number: num, expect: h2 ? h2.key : "",
        rule: rule + (com ? " comment '" + com.replace(/'/g, "") + "'" : "") });
    }
  });

  // disabled rules (stored in /etc/tuxwall/fw-disabled.json)
  var rulesCard = table.closest(".card");
  var dis = document.createElement("details");
  dis.className = "fwp-disabled";
  dis.hidden = true;
  if (rulesCard) rulesCard.appendChild(dis);
  function loadDisabled() {
    req("GET", "/api/firewall/disabled").then(function (d) {
      var l = d.rules || [];
      dis.hidden = !l.length;
      if (!l.length) { dis.innerHTML = ""; return; }
      dis.innerHTML = "<summary>Disabled rules (" + l.length + ")</summary><ul>" + l.map(function (r) {
        return '<li><div><span class="mono">' + esc(r.text) + '</span><div class="muted fwp-sub">' + esc(r.plain) +
          " · disabled " + esc(ago(r.disabled_at)) + (r.who ? " by " + esc(r.who) : "") + "</div></div>" +
          '<button type="button" class="btn btn-sm" data-s2d="' + esc(r.id) + '">Enable…</button><div class="fwp-plan" hidden></div></li>';
      }).join("") + "</ul>";
    }).catch(function () { dis.hidden = true; });
  }
  dis.addEventListener("click", function (e) {
    var b = e.target.closest("[data-s2d]");
    if (!b) return;
    openPlan(b.parentNode.querySelector(".fwp-plan"), { op: "enable", id: b.getAttribute("data-s2d") });
  });
  if (rulesCard) rulesCard.addEventListener("click", function (e) {
    var b = e.target.closest('[data-s2="apply"], [data-s2="close-plan"]');
    if (!b || b.closest("#fw-findings, #fw-suggestions")) return;
    if (b.getAttribute("data-s2") === "close-plan") { var er = b.closest("tr.fwp-edrow"); if (er) { er.remove(); s2.ed = null; } }
  });
  new MutationObserver(function (m) {
    for (var i = 0; i < m.length; i++) if (m[i].addedNodes.length) { loadDisabled(); return; }
  }).observe(tbody, { childList: true });

  // Explain per blocked event (Firewall → Traffic → recent events)
  var evBody = document.querySelector("#fw-events tbody");
  if (evBody) new MutationObserver(function () {
    var btns = evBody.querySelectorAll(".fw-block-src[data-ip]:not([data-fwp-x])");
    for (var i = 0; i < btns.length; i++) {
      btns[i].setAttribute("data-fwp-x", "1");
      var x = document.createElement("button");
      x.type = "button";
      x.className = "act-btn fwp-act";
      x.setAttribute("data-s2", "explain");
      x.setAttribute("data-target", btns[i].getAttribute("data-ip"));
      x.title = "Explain: why was this blocked? (Security → Traffic → Diagnose)";
      x.setAttribute("aria-label", x.title);
      x.innerHTML = SVG.explain;
      btns[i].parentNode.appendChild(x);
    }
  }).observe(evBody, { childList: true });
})();
