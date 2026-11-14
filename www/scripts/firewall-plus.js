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
})();
