/* TuxWall — Interfaces page (read-only): NIC inventory, role assignments,
   services bound to each network and the effective policy matrix.
   Data: GET /api/interfaces, GET /api/interfaces/policy. */
(function () {
  "use strict";
  var view = document.getElementById("view-interfaces");
  if (!view) return;

  var state = { data: null, policy: null, at: 0, loading: false, sel: null,
    draft: null, pedits: {}, presets: {}, plan: null, planning: false, pmEdit: false, pending: null, tick: 0,
    vlans: null, vlAt: 0, vlLoading: false, vlPolls: 0, vlTimer: 0, focusOpt: null };
  var $ = function (s, r) { return (r || view).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || view).querySelectorAll(s)); };

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function getJSON(url) {
    return fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (!r.ok || j.ok === false) throw new Error(j.error || ("HTTP " + r.status));
          return j;
        });
      });
  }

  var ROLE_LABEL = { wan: "WAN", lan: "LAN", opt: "OPT", vpn: "VPN" };
  function roleClass(role) {
    if (!role) return "if-role-none";
    if (role === "wan" || role === "lan" || role === "vpn") return "if-role-" + role;
    return "if-role-opt";
  }
  function roleChip(role, label) {
    var txt = label || (role ? (ROLE_LABEL[role] || role.toUpperCase()) : "unassigned");
    return '<span class="if-chip ' + roleClass(role) + '">' + esc(txt) + "</span>";
  }
  function yesno(b, on, off) {
    return '<span class="if-flag ' + (b ? "on" : "off") + '">' + esc(b ? (on || "on") : (off || "off")) + "</span>";
  }
  function fmtSpeed(m) {
    if (!m) return "—";
    return m >= 1000 ? (m / 1000).toFixed(m % 1000 ? 1 : 0) + " Gb/s" : m + " Mb/s";
  }

  /* ------------------------------------------------------------ render */
  function networksById() {
    var map = {};
    (state.data.networks || []).forEach(function (n) { map[n.id] = n; });
    return map;
  }
  function roleNameFor(dev) {
    var t = state.data.topology || {};
    if ((t.wan || {}).device === dev) return { role: "wan", label: "WAN" };
    if ((t.lan || {}).device === dev) return { role: "lan", label: "LAN" };
    var hit = null;
    (t.opt || []).forEach(function (o) {
      if (o.device !== dev) return;
      var id = (o.id || "opt").toUpperCase();
      hit = { role: o.id, label: id + (o.name && o.name !== id ? " · " + o.name : "") };
    });
    (t.vpn || []).forEach(function (v) { if (v.device === dev) hit = { role: "vpn", label: "VPN" }; });
    return hit || { role: "", label: "" };
  }

  function renderStats() {
    var d = state.data, t = d.topology || {};
    var inv = d.inventory || [];
    var wanDev = (t.wan || {}).device || "—";
    var wanInv = inv.filter(function (i) { return i.device === wanDev; })[0];
    var wanIp = wanInv ? (wanInv.addresses.filter(function (a) { return a.family === "inet"; })[0] || {}).cidr : "";
    var phys = inv.filter(function (i) { return i.kind === "ethernet"; });
    $("#if-stat-wan").textContent = wanDev;
    $("#if-stat-wan-sub").textContent = (t.wan || {}).mode === "static" ? "static " + (wanIp || "") : "DHCP " + (wanIp || "(no address)");
    $("#if-stat-lan").textContent = ((t.lan || {}).address || "—");
    $("#if-stat-lan-sub").textContent = (t.lan || {}).device || "";
    $("#if-stat-opt").textContent = String((t.opt || []).length);
    $("#if-stat-nics").textContent = phys.filter(function (i) { return i.carrier; }).length + " / " + phys.length;
    var src = $("#if-source");
    src.innerHTML = (d.source === "file"
      ? "Roles from <code>" + esc(d.path) + "</code>"
      : "Roles detected live (no <code>" + esc(d.path) + "</code> yet)") +
      ' · <span class="if-lock">' + (d.apply_locked ? "Plan only · Apply is locked on this router" : "Apply is unlocked on this router") + "</span>";
    var v = d.validation || {};
    var msgs = (v.errors || []).map(function (m) { return '<li class="err">' + esc(m) + "</li>"; })
      .concat((v.warnings || []).map(function (m) { return '<li class="warn">' + esc(m) + "</li>"; }));
    var vb = $("#if-validation");
    vb.hidden = !msgs.length;
    vb.innerHTML = msgs.length ? "<ul>" + msgs.join("") + "</ul>" : "";
  }

  function renderNics() {
    var rows = (state.data.inventory || []).filter(function (i) { return i.kind !== "ifb"; })
      .sort(function (a, b) {
        var ra = roleNameFor(a.device).role ? 0 : 1, rb = roleNameFor(b.device).role ? 0 : 1;
        return ra - rb || a.device.localeCompare(b.device);
      });
    $("#if-nic-table tbody").innerHTML = rows.map(function (i) {
      var r = roleNameFor(i.device);
      var addrs = i.addresses.filter(function (a) { return a.scope !== "link"; })
        .map(function (a) { return '<span class="if-addr' + (a.family === "inet6" ? " v6" : "") + '">' + esc(a.cidr) + "</span>"; }).join("");
      var kind = i.kind === "vlan" ? "VLAN " + esc(i.vlan) + " on " + esc(i.parent) : esc(i.kind);
      var link = i.carrier ? '<span class="if-link up">up</span>' : '<span class="if-link down">' + esc(i.operstate === "up" ? "no carrier" : (i.operstate || "down")) + "</span>";
      return "<tr>" +
        '<td data-label="Device"><strong class="if-dev">' + esc(i.device) + '</strong><div class="if-sub">' + kind + "</div></td>" +
        '<td data-label="Role">' + roleChip(r.role, r.label) + "</td>" +
        '<td data-label="MAC" class="if-mono">' + esc(i.mac || "—") + "</td>" +
        '<td data-label="Driver">' + esc(i.driver || "—") + "</td>" +
        '<td data-label="Speed">' + fmtSpeed(i.speed_mbit) + "</td>" +
        '<td data-label="Link">' + link + "</td>" +
        '<td data-label="Addresses">' + (addrs || '<span class="muted">—</span>') + "</td>" +
        "</tr>";
    }).join("") || '<tr><td colspan="7" class="muted">No interfaces found.</td></tr>';
  }

  function renderRoles() {
    var t = state.data.topology || {};
    var nets = state.data.networks || [];
    var cards = [];
    var w = t.wan || {};
    cards.push('<div class="if-role-card">' + roleChip("wan", "WAN") +
      '<div class="if-role-dev">' + esc(w.device || "unassigned") + "</div>" +
      '<div class="if-role-meta">' + esc(w.mode === "static" ? "Static " + (w.address || "") : "DHCP client") + "</div></div>");
    nets.forEach(function (n) {
      var lab = n.role === "lan" ? "LAN" : n.role === "vpn" ? "VPN" : (n.id || "opt").toUpperCase();
      var meta = [];
      if (n.address) meta.push(esc(n.address));
      if (n.vlan) meta.push("VLAN " + esc(n.vlan) + " on " + esc(n.parent));
      cards.push('<div class="if-role-card">' + roleChip(n.role === "opt" ? n.id : n.role, lab) +
        (n.name && n.name !== lab ? ' <span class="if-role-name">' + esc(n.name) + "</span>" : "") +
        '<div class="if-role-dev">' + esc(n.device) + "</div>" +
        '<div class="if-role-meta">' + meta.join(" · ") + "</div>" +
        (n.role !== "vpn" ? '<div class="if-role-flags">DHCP ' + yesno(n.dhcp) + " IPv6 RA " + yesno(n.ra) + "</div>" : "") +
        "</div>");
    });
    $("#if-roles").innerHTML = cards.join("");
  }

  function list(items) {
    if (!items.length) return '<span class="muted">none</span>';
    var li = function (a) { return a.map(function (x) { return "<li>" + x + "</li>"; }).join(""); };
    if (items.length <= 6) return '<ul class="if-list">' + li(items) + "</ul>";
    return '<ul class="if-list">' + li(items.slice(0, 5)) + '</ul><details class="if-more"><summary>' +
      (items.length - 5) + ' more</summary><ul class="if-list">' + li(items.slice(5)) + "</ul></details>";
  }
  function svcRow(name, ok, body) {
    return '<div class="if-svc"><div class="if-svc-name"><span class="if-dot ' + (ok ? "on" : "off") + '"></span>' + esc(name) + '</div><div class="if-svc-body">' + body + "</div></div>";
  }

  function renderServices() {
    var b = state.data.bindings || {};
    var nets = (state.data.networks || []).slice();
    nets.unshift({ id: "wan", role: "wan", name: "WAN / Internet", device: (state.data.topology.wan || {}).device });
    $("#if-services").innerHTML = nets.map(function (n) {
      var x = b[n.id] || {};
      var rows = [];
      var kea = x.kea || {};
      if (n.role !== "wan" || (kea.subnets || []).length) {
        rows.push(svcRow("DHCP (Kea)", kea.listening && (kea.subnets || []).length,
          (kea.subnets || []).length ? list(kea.subnets.map(function (s) {
            return "<code>" + esc(s.subnet) + "</code> pool " + esc((s.pools || []).join(", ") || "—") + " · " + esc(s.reservations) + " reservations" + (kea.listening ? "" : ' <span class="if-warn">not listening</span>');
          })) : '<span class="muted">no subnet</span>'));
      }
      if (n.role !== "wan" && n.role !== "vpn") {
        var ra = x.radvd || {};
        rows.push(svcRow("IPv6 RA (radvd)", ra.enabled, ra.enabled ? list(ra.prefixes.map(function (p) { return "<code>" + esc(p) + "</code>"; })) : '<span class="muted">off</span>'));
      }
      if (n.role !== "wan") {
        var ub = x.unbound || {};
        var acl = (ub.access || []).map(function (a) { return "<code>" + esc(a.net) + "</code> " + esc(a.action) + ' <span class="if-sub">' + esc(a.file) + "</span>"; });
        var ifs = (ub.interfaces || []).map(function (a) { return "listens on <code>" + esc(a.addr) + "</code>"; });
        rows.push(svcRow("DNS (Unbound)", acl.length > 0, list(ifs.concat(acl))));
      }
      rows.push(svcRow("Firewall (ufw)", (x.ufw || []).length > 0, list((x.ufw || []).map(function (r) { return "<code>" + esc(r) + "</code>"; }))));
      if ((x.nat || []).length || n.role === "wan") rows.push(svcRow("NAT", (x.nat || []).length > 0, list((x.nat || []).map(function (r) { return "<code>" + esc(r) + "</code>"; }))));
      var su = x.suricata || {};
      rows.push(svcRow("Suricata", su.af_packet || (su.home_net || []).length, (su.af_packet ? "captures (af-packet)" : '<span class="muted">not captured</span>') + ((su.home_net || []).length ? " · in HOME_NET" : "")));
      if (x.avahi) rows.push(svcRow("mDNS (Avahi)", x.avahi === "allowed", esc(x.avahi)));
      if (n.role === "wan") {
        var sq = x.sqm || {};
        rows.push(svcRow("SQM (CAKE)", sq.matches, sq.wan ? "sqm.conf WAN=<code>" + esc(sq.wan) + "</code>" + (sq.matches ? "" : ' <span class="if-warn">differs from the WAN role</span>') : '<span class="muted">not configured</span>'));
        var hp = x.honeypot || {};
        rows.push(svcRow("Honeypot / canary", hp.enabled || x.canary_rules > 0,
          (hp.enabled ? "honeypot on ports " + esc((hp.ports || []).join(", ")) : "honeypot off") + " · " + esc(x.canary_rules || 0) + " canary rules"));
        if (x.nat_dropin) rows.push(svcRow("NAT override", true, "TUXWALL_WAN_IFACE=<code>" + esc(x.nat_dropin) + "</code>"));
      }
      if (n.role === "vpn" && x.wireguard) {
        rows.push(svcRow("WireGuard", true, "Address <code>" + esc(x.wireguard.address || "—") + "</code> · port " + esc(x.wireguard.listenport || "—")));
      }
      var lab = n.role === "wan" ? "WAN" : n.role === "lan" ? "LAN" : n.role === "vpn" ? "VPN" : (n.id || "").toUpperCase();
      return '<div class="card if-svc-card"><div class="card-head"><h2>' + roleChip(n.role === "opt" ? n.id : n.role, lab) + " " + esc(n.name || "") +
        ' <span class="if-sub">' + esc(n.device || "") + (n.subnet ? " · " + esc(n.subnet) : "") + "</span></h2></div>" +
        '<div class="if-svc-grid">' + rows.join("") + "</div></div>";
    }).join("");
  }

  var STATE_LABEL = { allow: "Allow", block: "Block", established: "Return only", dns_dhcp: "DNS + DHCP", custom: "Some ports", self: "—" };
  function renderPolicy() {
    var p = state.policy;
    if (!p) return;
    var cols = p.columns || [], rows = p.rows || [];
    var head = '<tr><th class="if-mx-corner">From ↓ / To →</th>' + cols.map(function (c) {
      return '<th scope="col"><span class="if-mx-col">' + esc(c.id === "gw" ? "Gateway" : c.name) + '</span><span class="if-sub">' + esc(c.device || (c.id === "gw" ? "router" : "")) + "</span></th>";
    }).join("") + "</tr>";
    var body = rows.map(function (r) {
      return '<tr><th scope="row"><span class="if-mx-col">' + esc(r.name) + '</span><span class="if-sub">' + esc(r.device) + "</span></th>" +
        cols.map(function (c) {
          var cell = (p.cells[r.id] || {})[c.id] || {};
          var ed = (state.pedits[r.id] || {})[c.id];
          var st = ed || cell.state || "block";
          var extra = (cell.exceptions || []).length ? ' <span class="if-mx-exc" title="exceptions">+' + cell.exceptions.length + "</span>" : "";
          var v6 = cell.v6 ? '<span class="if-mx-v6">v6: ' + esc(STATE_LABEL[cell.v6] || cell.v6) + "</span>" : "";
          var ports = st === "custom" && cell.ports ? '<span class="if-mx-ports">' + esc(cell.ports.slice(0, 4).join(" ")) + (cell.ports.length > 4 ? " …" : "") + "</span>" : "";
          if (st === "self") return '<td role="gridcell" class="if-mx-self" aria-label="same network">—</td>';
          if (ed) { extra = ' <span class="if-mx-exc" title="was: ' + esc(STATE_LABEL[cell.state] || cell.state) + '">edited</span>'; ports = ""; v6 = ""; }
          return '<td role="gridcell" tabindex="0" aria-selected="false" class="if-mx-cell st-' + esc(st) + (ed ? " edited" : "") + (cell.source === "iptables" ? " raw" : "") + '" data-r="' + esc(r.id) + '" data-c="' + esc(c.id) + '">' +
            '<span class="if-mx-label">' + esc(STATE_LABEL[st] || st) + extra + "</span>" + ports + v6 + "</td>";
        }).join("") + "</tr>";
    }).join("");
    $("#if-matrix").innerHTML = "<table class=\"if-mx\" role=\"grid\" aria-label=\"Traffic policy between networks\"><thead>" + head + "</thead><tbody>" + body + "</tbody></table>";
    $("#if-mx-notes").innerHTML = (p.notes || []).map(function (n) { return "<li>" + esc(n) + "</li>"; }).join("") +
      "<li>Default policies: input " + esc((p.defaults || {}).input || "?") + ", forward " + esc((p.defaults || {}).forward || "?") + ". Replies to allowed connections always pass.</li>";
    showCell(state.sel);
  }
  function showCell(sel) {
    var box = $("#if-mx-detail");
    if (!sel || !state.policy) { box.innerHTML = '<span class="muted">Select a cell to see the rules that decide it.</span>'; return; }
    var p = state.policy, cell = (p.cells[sel.r] || {})[sel.c];
    if (!cell) return;
    var rn = (p.rows.filter(function (x) { return x.id === sel.r; })[0] || {}).name;
    var cn = (p.columns.filter(function (x) { return x.id === sel.c; })[0] || {}).name;
    $$(".if-mx-cell").forEach(function (b) {
      var on = b.dataset.r === sel.r && b.dataset.c === sel.c;
      b.classList.toggle("sel", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });
    var code = function (a) { return a.map(function (x) { return "<li><code>" + esc(x) + "</code></li>"; }).join(""); };
    box.innerHTML = "<h3>" + esc(rn) + " → " + esc(cn) + ': <span class="if-mx-state st-' + esc(cell.state) + '">' + esc(STATE_LABEL[cell.state] || cell.state) + "</span></h3>" +
      "<div class=\"if-sub\">Decided by" + (cell.default ? " the default policy" : "") + ":</div><ul class=\"if-list\">" + code(cell.rules || []) + "</ul>" +
      ((cell.exceptions || []).length ? '<div class="if-sub">Narrower rules (checked first):</div><ul class="if-list">' + code(cell.exceptions) + "</ul>" : "") +
      (cell.v6 ? '<div class="if-sub">IPv6: ' + esc(STATE_LABEL[cell.v6] || cell.v6) + "</div><ul class=\"if-list\">" + code(cell.v6_rules || []) + "</ul>" : "") +
      ((cell.legacy || []).length ? '<div class="if-sub">Created on the old VLANs page (source: <code>/etc/tuxwall/vlans.json</code>):</div><ul class="if-list">' +
        cell.legacy.map(function (lp) { return "<li>policy <code>" + esc(lp.id) + "</code> " + esc(lp.policy) + " · <code>" + esc(lp.rule) + "</code></li>"; }).join("") + "</ul>" : "") +
      (state.pmEdit ? cellEditor(sel, cell, rn, cn) : "");
  }

  function render() {
    if (!state.data) return;
    renderStats(); renderNics(); renderRoles(); renderServices(); renderPolicy();
    ensureEditUI(); renderPolicyBar(); renderEdit(); renderPending();
    lockNav(state.data.apply_locked !== false);
  }

  /* ------------------------------------------------------------ editor (phase 3) */
  var LOCK_TEXT = "Plan only — Apply is locked on this router. Test in a VM, then set apply_locked=false in /etc/tuxwall/interfaces.json.";
  var PRESETS = { trusted: "Trusted LAN", internet: "Internet only (IoT)", guest: "Isolated guest", management: "Management" };
  var PRESET_DEF = {
    trusted: { wan: "allow", gw: "allow", out: "allow", "in": "block", in_lan: "allow" },
    internet: { wan: "allow", gw: "dns_dhcp", out: "block", "in": "block", in_lan: "allow" },
    guest: { wan: "allow", gw: "dns_dhcp", out: "block", "in": "block", in_lan: "block" },
    management: { wan: "block", gw: "allow", out: "allow", "in": "block", in_lan: "block" }
  };
  var STEP_ICON = { netplan: "1", kea: "2", radvd: "3", unbound: "4", ufw: "5", nat: "6", avahi: "7", suricata: "8", sqm: "9", honeypot: "10", record: "11" };

  function postJSON(url, body) {
    return fetch(url, { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { j.__status = r.status; return j; }); });
  }
  function clone(o) { return JSON.parse(JSON.stringify(o == null ? null : o)); }
  function locked() { return !state.data || state.data.apply_locked !== false; }

  // Sub-tab glyphs in the shared 24px / 1.8 stroke style (dashboard.js
  // SUBTAB_ICONS covers the other views; these tabs are partly built here).
  var TAB_ICONS = {
    ports: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7.5 15.5v-4h2v-2h5v2h2v4z"/>',
    vlans: '<path d="M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L3 13.2V3h10.2l7.4 7.6a2 2 0 0 1 0 2.8z"/><circle cx="7.6" cy="7.6" r="1.4"/>',
    services: '<path d="M9 2v5M15 2v5M6 7h12v4a6 6 0 0 1-12 0zM12 17v5"/>',
    policy: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M3 15h18M9 3v18M15 3v18"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4z"/>'
  };
  function tabIcons() {
    var strip = $("#if-subtabs");
    if (!strip) return;
    var added = false;
    $$(".fw-subtab[data-if-pane]", strip).forEach(function (t) {
      var body = TAB_ICONS[t.getAttribute("data-if-pane")];
      if (!body || t.querySelector(".tab-ic")) return;
      var i = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      i.setAttribute("class", "tab-ic"); i.setAttribute("viewBox", "0 0 24 24"); i.setAttribute("aria-hidden", "true");
      i.setAttribute("fill", "none"); i.setAttribute("stroke", "currentColor");
      i.innerHTML = body;
      t.insertBefore(i, t.firstChild);
      added = true;
    });
    // tabs got wider: let the shared strip re-measure its sliding pill
    if (added) strip.dispatchEvent(new Event("scroll"));
  }

  function ensureEditUI() {
    ensureVlanUI();
    tabIcons();
    if ($("#if-edit-tab")) return;
    var tabs = $("#if-subtabs");
    var b = document.createElement("button");
    b.className = "fw-subtab"; b.type = "button"; b.id = "if-edit-tab";
    b.setAttribute("data-if-pane", "edit"); b.setAttribute("role", "tab"); b.setAttribute("aria-selected", "false");
    b.textContent = "Edit & plan";
    tabs.appendChild(b);
    $$(".fw-subtab[data-if-pane]").forEach(function (t) { t.setAttribute("role", "tab"); });
    tabIcons();
    var body = document.createElement("div");
    body.setAttribute("data-if-body", "edit"); body.hidden = true;
    body.innerHTML = '<div class="if-lockbar" id="if-lockbar" hidden></div>' +
      '<div class="if-pending" id="if-pending" hidden></div>' +
      '<div class="card"><div class="card-head"><h2>Assignments</h2></div>' +
      '<p class="if-sub if-ed-intro">Change roles, addresses and services, then review the plan: every affected file is rendered, checked with its own tool and shown as a diff. Nothing changes until Apply.</p>' +
      '<div class="if-ed" id="if-ed"></div>' +
      '<div class="if-ed-actions"><button type="button" class="btn btn-sm" id="if-add-opt">Add network on a port</button>' +
      '<button type="button" class="btn btn-sm" id="if-add-vlan">Add VLAN</button>' +
      '<span class="toolbar-spacer"></span><button type="button" class="btn btn-sm" id="if-reset">Reset edits</button>' +
      '<button type="button" class="btn btn-primary btn-sm" id="if-review">Review plan</button></div></div>' +
      '<div class="if-plan" id="if-plan" aria-live="polite"></div>';
    var pol = $('[data-if-body="policy"]');
    pol.parentNode.insertBefore(body, pol.nextSibling);
    var bar = document.createElement("div");
    bar.className = "if-pm-bar"; bar.id = "if-pm-bar";
    var mx = $("#if-matrix");
    mx.parentNode.insertBefore(bar, mx);
    var pp = document.createElement("div");
    pp.className = "if-plan"; pp.id = "if-plan-pm";
    $("#if-mx-notes").parentNode.appendChild(pp);
  }

  function draft() {
    if (!state.draft) {
      var t = clone(state.data.topology || {});
      var b = state.data.bindings || {};
      var pool = function (id) { var k = (b[id] || {}).kea || {}; return (((k.subnets || [])[0] || {}).pools || [])[0] || ""; };
      if (t.lan && t.lan.dhcp && !t.lan.pool) t.lan.pool = pool("lan");
      (t.opt || []).forEach(function (o) { if (o.dhcp && !o.pool) o.pool = pool(o.id); });
      state.draft = { wan: t.wan || {}, lan: t.lan || {}, opt: t.opt || [], vpn: t.vpn || [] };
      state.draftBase = JSON.stringify(state.draft);
    }
    return state.draft;
  }
  function draftDirty() { return state.draft && JSON.stringify(state.draft) !== state.draftBase; }
  function peditCount() { var n = 0; Object.keys(state.pedits).forEach(function (s) { n += Object.keys(state.pedits[s]).length; }); return n; }

  function nicOptions(sel, allowNone) {
    var inv = (state.data.inventory || []).filter(function (i) { return i.kind === "ethernet"; });
    var html = allowNone ? '<option value="">— unassigned —</option>' : "";
    var seen = false;
    inv.forEach(function (i) {
      if (i.device === sel) seen = true;
      html += '<option value="' + esc(i.device) + '"' + (i.device === sel ? " selected" : "") + ">" + esc(i.device) +
        " · " + (i.carrier ? "link up" : "no link") + (i.speed_mbit ? " · " + fmtSpeed(i.speed_mbit) : "") + "</option>";
    });
    if (sel && !seen) html += '<option value="' + esc(sel) + '" selected>' + esc(sel) + "</option>";
    return html;
  }
  function field(label, inner, cls) { return '<label class="if-f' + (cls ? " " + cls : "") + '"><span>' + esc(label) + "</span>" + inner + "</label>"; }
  function inp(k, v, ph, extra) { return '<input type="text" class="if-in" data-k="' + k + '" value="' + esc(v || "") + '" placeholder="' + esc(ph || "") + '" spellcheck="false" autocomplete="off"' + (extra || "") + ">"; }
  function chk(k, v, label) { return '<label class="if-chk"><input type="checkbox" data-k="' + k + '"' + (v ? " checked" : "") + "> " + esc(label) + "</label>"; }

  function netFields(prefix, n, kind) {
    var h = "";
    if (kind !== "lan") h += field("Name", inp(prefix + ".name", n.name, "e.g. IoT"));
    if (n.vlan != null && kind === "opt") {
      h += field("Parent port", '<select class="if-in" data-k="' + prefix + '.parent">' + nicOptions(n.parent, false) + "</select>");
      h += field("VLAN id", inp(prefix + ".vlan", n.vlan, "1-4094", ' inputmode="numeric"'));
    } else {
      h += field("Port", '<select class="if-in" data-k="' + prefix + '.device">' + nicOptions(n.device, kind !== "lan") + "</select>");
    }
    h += field("Address / prefix", inp(prefix + ".address", n.address, "192.168.20.1/24"));
    h += '<div class="if-f if-f-row">' + chk(prefix + ".dhcp", n.dhcp, "DHCP server") + chk(prefix + ".ra", n.ra, "IPv6 RA") + "</div>";
    if (n.dhcp) h += field("DHCP pool", inp(prefix + ".pool", n.pool, "first-last (blank = automatic)"));
    return h;
  }

  function renderEdit() {
    var box = $("#if-ed");
    if (!box || !state.data) return;
    var lb = $("#if-lockbar");
    lb.hidden = !locked();
    lb.innerHTML = '<strong>Plan only.</strong> ' + esc(LOCK_TEXT.replace(/^Plan only — /, ""));
    var d = draft();
    var cards = [];
    var w = d.wan || {};
    cards.push('<div class="if-ed-card"><div class="if-ed-head">' + roleChip("wan", "WAN") + ' <span class="if-sub">internet uplink</span></div>' +
      field("Port", '<select class="if-in" data-k="wan.device">' + nicOptions(w.device, false) + "</select>") +
      field("Mode", '<select class="if-in" data-k="wan.mode" data-rerender="1"><option value="dhcp"' + (w.mode !== "static" ? " selected" : "") + '>DHCP client</option><option value="static"' + (w.mode === "static" ? " selected" : "") + ">Static address</option></select>") +
      (w.mode === "static" ? field("Address / prefix", inp("wan.address", w.address, "203.0.113.2/24")) + field("Gateway", inp("wan.gateway", w.gateway, "203.0.113.1")) : "") +
      "</div>");
    cards.push('<div class="if-ed-card">' + '<div class="if-ed-head">' + roleChip("lan", "LAN") + ' <span class="if-sub">main network</span></div>' + netFields("lan", d.lan || {}, "lan") + "</div>");
    (d.opt || []).forEach(function (o, k) {
      var isNew = !o.id || !(state.data.topology.opt || []).some(function (x) { return x.id === o.id; });
      cards.push('<div class="if-ed-card' + (isNew ? " is-new" : "") + (state.focusOpt === o ? " if-focus" : "") + '" data-opt-card="' + k + '"><div class="if-ed-head">' + roleChip("opt", (o.id || "new").toUpperCase()) +
        (o.vlan != null ? ' <span class="if-sub">VLAN</span>' : "") + (isNew ? ' <span class="if-new">new</span>' : "") +
        '<span class="toolbar-spacer"></span><button type="button" class="btn btn-sm" data-rm-opt="' + k + '">Remove</button></div>' +
        netFields("opt." + k, o, "opt") +
        field("Policy preset", '<select class="if-in" data-preset-new="' + k + '"><option value="">' + (isNew ? "Internet only (IoT) — default" : "keep current rules") + "</option>" +
          Object.keys(PRESETS).map(function (p) { return '<option value="' + p + '"' + (o.__preset === p ? " selected" : "") + ">" + esc(PRESETS[p]) + "</option>"; }).join("") + "</select>") +
        "</div>");
    });
    (d.vpn || []).forEach(function (v) {
      cards.push('<div class="if-ed-card is-ro"><div class="if-ed-head">' + roleChip("vpn", "VPN") + ' <span class="if-sub">' + esc(v.device) + " · managed on the WireGuard page</span></div>" +
        '<div class="if-role-meta">' + esc(v.name || "") + " " + esc(v.address || "") + "</div></div>");
    });
    box.innerHTML = cards.join("");
  }

  function setPath(k, val) {
    var d = draft(), parts = k.split("."), o = d;
    for (var i = 0; i < parts.length - 1; i++) { o = o[/^\d+$/.test(parts[i]) ? +parts[i] : parts[i]]; if (!o) return; }
    var last = parts[parts.length - 1];
    if (last === "vlan") { val = val === "" ? "" : (/^\d+$/.test(val) ? +val : val); }
    o[last] = val;
    if (last === "parent" || last === "vlan") { if (o.parent && o.vlan) o.device = o.parent + "." + o.vlan; }
  }

  function ip4(s) {
    var m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(String(s || "").trim());
    return m ? ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4] : null;
  }
  function dropStalePool(prefix) {
    var parts = prefix.split("."), n = draft()[parts[0]];
    if (parts.length > 1) n = n[+parts[1]];
    if (!n || !n.pool) return false;
    var a = String(n.address || "").split("/"), base = ip4(a[0]), len = +a[1];
    var pr = String(n.pool).split("-"), lo = ip4(pr[0]), hi = ip4(pr[1]);
    if (base == null || !(len >= 0 && len <= 32) || lo == null || hi == null) return false;
    var mask = len ? (0xffffffff << (32 - len)) >>> 0 : 0;
    var net = (base & mask) >>> 0;
    if (((lo & mask) >>> 0) === net && ((hi & mask) >>> 0) === net) return false;
    n.pool = "";
    return true;
  }

  function planBody() {
    var body = {};
    if (draftDirty()) {
      var d = clone(state.draft);
      var presets = {};
      (d.opt || []).forEach(function (o, k) {
        if (o.__preset) { if (!o.id) o.id = nextOptId(d, k); presets[o.id] = o.__preset; }
        delete o.__preset;
        if (o.vlan === "" || o.vlan == null) { delete o.vlan; delete o.parent; }
        if (!o.dhcp) delete o.pool;
      });
      if (d.lan && !d.lan.dhcp) delete d.lan.pool;
      body.topology = d;
      body.presets = presets;
    } else if (state.draft) {
      body.presets = {};
      (state.draft.opt || []).forEach(function (o) { if (o.__preset && o.id) body.presets[o.id] = o.__preset; });
    }
    if (peditCount()) body.policy = clone(state.pedits);
    return body;
  }
  function nextOptId(d, k) {
    var used = {}; (d.opt || []).forEach(function (o) { if (o.id) used[o.id] = 1; });
    var n = 1; while (used["opt" + n]) n++;
    return "opt" + n;
  }

  function review(target) {
    if (state.planning) return;
    state.planning = true;
    var box = $(target || "#if-plan");
    box.innerHTML = '<div class="card if-plan-card"><span class="muted">Rendering and validating every affected file…</span></div>';
    postJSON("/api/interfaces/plan", planBody()).then(function (p) {
      state.plan = p; state.planTarget = target || "#if-plan";
      renderPlan();
    }).catch(function (e) {
      box.innerHTML = '<div class="card if-plan-card"><p class="if-err">Plan failed: ' + esc(e.message) + "</p></div>";
    }).then(function () { state.planning = false; });
  }

  function renderPlan() {
    var p = state.plan;
    ["#if-plan", "#if-plan-pm"].forEach(function (s) { if (s !== state.planTarget && $(s)) $(s).innerHTML = ""; });
    var box = $(state.planTarget || "#if-plan");
    if (!p || !box) return;
    var h = ['<div class="card if-plan-card"><div class="card-head"><h2>Plan</h2><span class="if-plan-sum">' + esc(p.summary || "") + "</span></div>"];
    if (p.apply_locked) h.push('<div class="if-lockbar"><strong>Plan only.</strong> ' + esc(LOCK_TEXT.replace(/^Plan only — /, "")) + "</div>");
    if (p.ok === false) {
      h.push('<div class="if-plan-errs"><h3>Fix these first</h3><ul>' + (p.errors || [p.error]).map(function (e) { return "<li>" + esc(e) + "</li>"; }).join("") + "</ul></div>");
      box.innerHTML = h.join("") + "</div>";
      return;
    }
    if (!(p.changes || []).length) {
      h.push('<p class="if-plan-none">No changes — the requested setup matches what is running.</p>');
      box.innerHTML = h.join("") + "</div>";
      return;
    }
    if ((p.warnings || []).length) {
      h.push('<div class="if-plan-warn"><h3>Warnings</h3><ul>' + p.warnings.map(function (w) {
        var hot = /you are connected|lose the dashboard|bypass ufw/i.test(w);
        return '<li class="' + (hot ? "hot" : "") + '">' + esc(w) + "</li>";
      }).join("") + "</ul></div>");
    }
    h.push('<ol class="if-steps">' + p.changes.map(function (g) {
      return '<li class="if-step"><div class="if-step-head"><span class="if-step-n">' + esc(STEP_ICON[g.step] || "") + "</span><strong>" + esc(g.title) + "</strong></div>" +
        '<ul class="if-list">' + g.items.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul>" +
        ((g.files || []).length ? '<div class="if-sub">Files: ' + g.files.map(function (f) { return "<code>" + esc(f) + "</code>"; }).join(" ") + "</div>" : "") +
        ((g.actions || []).length ? '<div class="if-sub">Then: ' + g.actions.map(function (a) { return "<code>" + esc(a) + "</code>"; }).join(" ") + "</div>" : "") + "</li>";
    }).join("") + "</ol>");
    var vals = p.validators || [];
    if (vals.length) {
      h.push('<div class="if-vals"><h3>Checks on the rendered files</h3><ul>' + vals.map(function (v) {
        var st = v.skipped ? "skip" : v.ok ? "ok" : "bad";
        return '<li class="if-val ' + st + '"><span class="if-val-st">' + (st === "ok" ? "passed" : st === "bad" ? "FAILED" : "skipped") + "</span> <code>" + esc(v.tool) + "</code>" +
          (v.output && st !== "ok" ? '<pre class="if-val-out">' + esc(v.output) + "</pre>" : (v.output && /stand-in/.test(v.output) ? ' <span class="if-sub">' + esc(v.output.split("\n")[0]) + "</span>" : "")) + "</li>";
      }).join("") + "</ul></div>");
    }
    h.push('<div class="if-diffs"><h3>File changes in apply order</h3>' + (p.files || []).map(function (f, k) {
      return '<details class="if-diff" data-diff="' + k + '"><summary><code>' + esc(f.path) + '</code> <span class="if-sub">' + esc(f.action) + "</span>" +
        ' <span class="if-add">+' + f.added + '</span> <span class="if-del">−' + f.removed + "</span></summary><div class=\"if-diff-body\"></div></details>";
    }).join("") + "</div>");
    h.push(applyBox(p));
    box.innerHTML = h.join("") + "</div>";
  }

  function applyBox(p) {
    if (p.apply_locked) {
      return '<div class="if-apply"><button type="button" class="btn btn-sm" disabled aria-disabled="true" title="Apply is locked on this router">Apply (locked)</button>' +
        '<span class="if-sub">Unlock only by editing <code>/etc/tuxwall/interfaces.json</code> as root on a test machine.</span></div>';
    }
    return '<div class="if-apply">' + (p.lockout ? '<label class="if-chk hot"><input type="checkbox" id="if-ack"> I understand I may lose this session; it rolls back after 60 s unless confirmed.</label>' : "") +
      '<label class="if-chk"><input type="checkbox" id="if-after-reboot"> Write files only; take effect after a reboot</label>' +
      '<button type="button" class="btn btn-primary btn-sm" id="if-apply">Apply plan</button></div>';
  }

  function diffHTML(text) {
    return '<pre class="if-diff-pre">' + String(text || "").split("\n").map(function (l) {
      var c = l.slice(0, 3) === "+++" || l.slice(0, 3) === "---" ? "f" : l[0] === "+" ? "a" : l[0] === "-" ? "d" : l.slice(0, 2) === "@@" ? "h" : "";
      return c ? '<span class="dl-' + c + '">' + esc(l) + "</span>" : esc(l);
    }).join("\n") + "</pre>";
  }

  function doApply() {
    var p = state.plan;
    if (!p || p.apply_locked) return;
    var body = planBody();
    body.plan_hash = p.plan_hash;
    body.ack_lockout = !!($("#if-ack") && $("#if-ack").checked);
    body.after_reboot = !!($("#if-after-reboot") && $("#if-after-reboot").checked);
    if (p.lockout && !body.ack_lockout) { setStatus("Tick the session warning first.", true); return; }
    var btn = $("#if-apply"); if (btn) { btn.disabled = true; btn.textContent = "Applying…"; }
    postJSON("/api/interfaces/apply", body).then(function (r) {
      if (r.__status === 423) { state.data.apply_locked = true; setStatus(r.error || LOCK_TEXT, true); renderPlan(); return; }
      if (!r.ok) { setStatus("Apply failed: " + (r.error || r.__status), true); if (btn) { btn.disabled = false; btn.textContent = "Apply plan"; } return; }
      state.pending = { id: r.id, after_reboot: r.after_reboot, until: r.confirm_within_s ? Date.now() + r.confirm_within_s * 1000 : 0 };
      state.plan = null; state.draft = null; state.pedits = {};
      renderPending(); renderPlan();
      setStatus(r.message || "Applied.");
    });
  }

  function renderPending() {
    var box = $("#if-pending");
    if (!box) return;
    if (!state.pending && state.data && (state.data.pending || []).length) {
      var x = state.data.pending[0];
      state.pending = { id: x.id, after_reboot: x.after_reboot, until: x.expires_in ? Date.now() + x.expires_in * 1000 : 0 };
    }
    var pd = state.pending;
    box.hidden = !pd;
    if (!pd) return;
    var left = pd.until ? Math.max(0, Math.round((pd.until - Date.now()) / 1000)) : null;
    box.innerHTML = "<strong>" + (pd.after_reboot ? "Written for the next reboot." : "Applied — confirm to keep it.") + "</strong> " +
      (left != null ? '<span class="if-count">' + left + " s left before automatic roll back.</span> " : "") +
      (pd.after_reboot ? "" : '<button type="button" class="btn btn-primary btn-sm" id="if-confirm">Confirm (keep)</button> ') +
      '<button type="button" class="btn btn-sm" id="if-rollback">Roll back now</button>';
    if (left != null && !state.tick) {
      state.tick = setInterval(function () {
        var c = $(".if-count", box);
        var l = Math.max(0, Math.round((state.pending ? state.pending.until - Date.now() : 0) / 1000));
        if (c) c.textContent = l + " s left before automatic roll back.";
        if (!state.pending || l <= 0) { clearInterval(state.tick); state.tick = 0; if (state.pending) { state.pending = null; load(true); } }
      }, 1000);
    }
  }

  function pendingAction(kind) {
    var pd = state.pending; if (!pd) return;
    postJSON("/api/interfaces/" + kind, { id: pd.id }).then(function (r) {
      setStatus(r.ok ? (kind === "confirm" ? "Change kept." : "Rolled back.") : (r.error || "Failed"), !r.ok);
      state.pending = null; if (state.tick) { clearInterval(state.tick); state.tick = 0; }
      load(true);
    });
  }

  /* ------------------------------------------------------------ policy editing (phase 4) */
  var CELL_CHOICES = { fwd: ["allow", "block", "established"], gw: ["allow", "dns_dhcp", "block"] };
  function cellEditor(sel, cell, rn, cn) {
    if (sel.r === "wan") return '<p class="if-sub if-pm-ro">Traffic from the internet is managed on the Firewall and Port forwarding pages.</p>';
    var kind = sel.c === "gw" ? "gw" : "fwd";
    var cur = (state.pedits[sel.r] || {})[sel.c] || cell.state;
    var h = '<div class="if-pm-edit"><label class="if-f"><span>Set ' + esc(rn) + " → " + esc(cn) + "</span>" +
      '<select class="if-in" id="if-cell-sel">' + CELL_CHOICES[kind].map(function (s) {
        return '<option value="' + s + '"' + (s === cur ? " selected" : "") + ">" + esc(STATE_LABEL[s]) + "</option>";
      }).join("") + (CELL_CHOICES[kind].indexOf(cur) < 0 ? '<option value="" selected>' + esc(STATE_LABEL[cur] || cur) + " (current)</option>" : "") + "</select></label>";
    if ((state.pedits[sel.r] || {})[sel.c]) h += '<button type="button" class="btn btn-sm" id="if-cell-undo">Undo this cell</button>';
    h += "</div>";
    if (cell.source === "iptables") {
      h += '<p class="if-warnline">This cell is opened by a raw iptables rule (<code>FORWARD -i/-o wg0 ACCEPT</code>) that bypasses ufw. ' +
        "Changing it makes the plan replace those raw rules with tagged ufw rules; existing ufw deny rules for the VPN then take effect. Nothing changes until Apply.</p>";
    }
    if (kind === "fwd") h += '<p class="if-sub">“Return only” blocks new connections in this direction; replies to connections opened from the other side still pass (same as Block for ufw).</p>';
    return h;
  }

  function renderPolicyBar() {
    var bar = $("#if-pm-bar");
    if (!bar || !state.policy) return;
    var n = peditCount();
    var nets = (state.policy.rows || []).filter(function (r) { return r.id !== "wan"; });
    bar.innerHTML = '<button type="button" class="btn btn-sm" id="if-pm-toggle" aria-pressed="' + state.pmEdit + '">' + (state.pmEdit ? "Done editing" : "Edit policy") + "</button>" +
      (state.pmEdit ? '<span class="if-pm-preset"><select class="if-in" id="if-pm-net" aria-label="Network">' + nets.map(function (r) { return '<option value="' + esc(r.id) + '">' + esc(r.name) + "</option>"; }).join("") +
        '</select><select class="if-in" id="if-pm-preset" aria-label="Preset">' + Object.keys(PRESETS).map(function (p) { return '<option value="' + p + '">' + esc(PRESETS[p]) + "</option>"; }).join("") +
        '</select><button type="button" class="btn btn-sm" id="if-pm-apply-preset">Use preset</button></span>' : "") +
      '<span class="toolbar-spacer"></span>' + (n ? '<span class="if-sub">' + n + " edited cell" + (n > 1 ? "s" : "") + '</span><button type="button" class="btn btn-sm" id="if-pm-discard">Discard edits</button>' : "") +
      '<button type="button" class="btn btn-primary btn-sm" id="if-pm-review">Review plan</button>';
    $("#if-matrix").classList.toggle("editing", state.pmEdit);
  }

  function setCell(r, c, st) {
    var cur = (((state.policy.cells || {})[r] || {})[c] || {}).state;
    state.pedits[r] = state.pedits[r] || {};
    if (!st || st === cur) delete state.pedits[r][c]; else state.pedits[r][c] = st;
    if (!Object.keys(state.pedits[r]).length) delete state.pedits[r];
  }
  function usePreset(zid, preset) {
    var p = PRESET_DEF[preset]; if (!p) return;
    (state.policy.rows || []).forEach(function (z) {
      if (z.id === zid) return;
      if (z.id === "wan") { setCell(zid, "wan", p.wan); return; }
      setCell(zid, z.id, p.out);
      setCell(z.id, zid, z.role === "lan" ? p.in_lan : p["in"]);
    });
    setCell(zid, "gw", p.gw);
  }



  /* ------------------------------------------------------------ VLANs tab */
  function ensureVlanUI() {
    if ($("#if-vlan-tab")) return;
    var first = $('.fw-subtab[data-if-pane="ports"]');
    if (!first) return;
    var b = document.createElement("button");
    b.className = "fw-subtab"; b.type = "button"; b.id = "if-vlan-tab";
    b.setAttribute("data-if-pane", "vlans"); b.setAttribute("role", "tab"); b.setAttribute("aria-selected", "false");
    b.textContent = "VLANs";
    first.parentNode.insertBefore(b, first.nextSibling);
    var body = document.createElement("div");
    body.setAttribute("data-if-body", "vlans"); body.hidden = true;
    body.innerHTML = '<div class="card card-mt if-vl-card"><div class="card-head"><h2>VLANs</h2><span class="toolbar-spacer"></span>' +
      '<button type="button" class="btn btn-sm" id="if-vl-aps">Re-check access points</button>' +
      '<button type="button" class="btn btn-primary btn-sm" id="if-vl-add">Add VLAN</button></div>' +
      '<p class="if-sub if-vl-intro">VLAN networks are part of the interface record (<code>/etc/tuxwall/interfaces.json</code>). Add, Edit and Remove open the Edit &amp; plan editor, so every change goes through the same plan review.</p>' +
      '<div class="if-vl-apstat" id="if-vl-apstat" aria-live="polite"></div>' +
      '<div class="if-vl-list" id="if-vl-list"><span class="muted">Loading VLANs…</span></div>' +
      '<div class="if-vl-legacy" id="if-vl-legacy"></div></div>';
    var ports = $('[data-if-body="ports"]');
    ports.parentNode.insertBefore(body, ports.nextSibling);
  }

  function loadVlans(force, refreshAps) {
    if (state.vlLoading) return;
    if (!force && state.vlans && Date.now() - state.vlAt < 30000) return;
    state.vlLoading = true;
    getJSON("/api/interfaces/vlans" + (refreshAps ? "?refresh=1" : "")).then(function (d) {
      state.vlans = d; state.vlAt = Date.now();
      renderVlans();
      var st = (d.aps || {}).status;
      clearTimeout(state.vlTimer);
      if ((st === "pending" || (d.aps || {}).refreshing) && state.vlPolls < 6) {
        state.vlPolls++;
        state.vlTimer = setTimeout(function () { loadVlans(true); }, 4000);
      } else { state.vlPolls = 0; }
    }).catch(function (e) {
      var l = $("#if-vl-list"); if (l) l.innerHTML = '<p class="if-err">Could not load VLANs: ' + esc(e.message) + "</p>";
    }).then(function () { state.vlLoading = false; });
  }

  function apStatus(d) {
    var a = d.aps || {};
    var when = a.at ? " · checked " + new Date(a.at * 1000).toLocaleTimeString() : "";
    switch (a.status) {
      case "ok":
        return "WiFi: " + a.count + " access point" + (a.count === 1 ? "" : "s") + " via the OpenWrt plugin" + when +
          (a.vlan_list ? "" : " · SSIDs are matched by their OpenWrt network name (the APs report no switch VLANs)") +
          (a.error ? ' · <span class="if-warn">' + esc(a.error) + "</span>" : "") +
          ((d.lan_ssids || []).length ? " · untagged on the LAN: " + d.lan_ssids.map(function (c) { return "<strong>" + esc(c.ssid) + "</strong>"; }).join(", ") : "");
      case "pending": return '<span class="muted">Checking the access points…</span>';
      case "absent": return '<span class="muted">OpenWrt plugin not installed: SSIDs per VLAN are not shown.</span>';
      case "disabled": return '<span class="muted">OpenWrt plugin is disabled: SSIDs per VLAN are not shown.</span>';
      case "unconfigured": return '<span class="muted">OpenWrt plugin has no access points configured.</span>';
      default: return '<span class="if-warn">Access points could not be checked' + (a.error ? ": " + esc(a.error) : "") + "</span>" + when;
    }
  }

  var PSHORT = { allow: "allow", block: "block", established: "return only", dns_dhcp: "DNS + DHCP", custom: "some ports" };
  function vlanCard(v) {
    var link = v.link || {};
    var lk = !link.present ? '<span class="if-link down">missing</span>' : link.carrier ? '<span class="if-link up">up</span>' : '<span class="if-link down">' + esc(link.state || "down") + "</span>";
    var rows = [];
    var row = function (k, val) { rows.push('<div class="if-vl-k">' + esc(k) + '</div><div class="if-vl-v">' + val + "</div>"); };
    row("Interface", "<code>" + esc(v.device) + "</code> on <code>" + esc(v.parent || "?") + "</code> · " + lk);
    row("Subnet", v.subnet ? "<code>" + esc(v.subnet) + "</code> · gateway <code>" + esc(v.gateway) + "</code>" : '<span class="muted">no IPv4 address</span>');
    row("DHCP", v.dhcp ? yesno(true) + " pool <code>" + esc((v.pools || []).join(", ") || "—") + "</code> · <strong>" + esc(v.leases) + "</strong> active lease" + (v.leases === 1 ? "" : "s") +
      (v.reservations ? " · " + esc(v.reservations) + " reserved" : "") + (v.dhcp_listening === false ? ' <span class="if-warn">Kea not listening</span>' : "") : yesno(false));
    row("IPv6 RA", v.ra ? yesno(true) + " " + (v.ra_prefixes || []).map(function (p) { return "<code>" + esc(p) + "</code>"; }).join(" ") : yesno(false));
    var p = v.policy;
    if (p) {
      var chips = p.out.map(function (c) {
        return '<span class="if-vl-pc st-' + esc(c.state) + '" title="' + esc(v.name + " → " + c.name + ": " + (STATE_LABEL[c.state] || c.state) + (c.source === "iptables" ? " (raw iptables rule)" : "") + (c.exceptions && c.dst !== "gw" ? "; " + c.exceptions + " narrower rule(s) checked first" : "")) + '">→ ' +
          esc(c.dst === "gw" ? "Gateway" : c.dst === "wan" ? "Internet" : c.name) + " " + esc(PSHORT[c.state] || c.state) + (c.exceptions && c.dst !== "gw" ? " +" + c.exceptions : "") + "</span>";
      }).concat(p["in"].filter(function (c) { return c.src !== "wan"; }).map(function (c) {
        return '<span class="if-vl-pc in st-' + esc(c.state) + '" title="' + esc(c.name + " → " + v.name + ": " + (STATE_LABEL[c.state] || c.state)) + '">← ' + esc(c.name) + " " + esc(PSHORT[c.state] || c.state) + "</span>";
      }));
      row("Policy", '<div><strong>' + esc(p.preset.label) + '</strong> <button type="button" class="btn btn-sm if-vl-mx" data-vl-mx="' + esc(v.id) + '">Matrix</button></div><div class="if-vl-pcs">' + chips.join("") + "</div>" +
        ((p.legacy || []).length ? '<div class="if-sub">' + p.legacy.length + " polic" + (p.legacy.length === 1 ? "y" : "ies") + " from the old VLANs page (shown in the matrix cells)</div>" : ""));
    } else {
      row("Policy", '<span class="muted">not in the policy matrix (not in the interface record)</span>');
    }
    var aps = v.aps || [];
    var ast = ((state.vlans || {}).aps || {}).status;
    row("WiFi", aps.length ? aps.map(function (c) {
      return '<span class="if-vl-ssid"><strong>' + esc(c.ssid) + "</strong> on " + esc(c.aps.join(", ")) + ' <span class="if-sub">' + esc(c.clients) + " client" + (c.clients === 1 ? "" : "s") + " · network " + esc(c.network) + (c.match === "name" ? " (matched by name)" : "") + "</span></span>";
    }).join("") : '<span class="muted">' + (ast === "ok" ? "no SSID carries this VLAN" : ast === "pending" ? "checking…" : "unknown") + "</span>");
    var acts = v.managed
      ? '<button type="button" class="btn btn-sm" data-vl-edit="' + esc(v.id) + '">Edit</button><button type="button" class="btn btn-sm btn-danger" data-vl-rm="' + esc(v.id) + '">Remove</button>'
      : '<button type="button" class="btn btn-sm" data-vl-adopt="' + esc(v.device) + '">Add to record</button>';
    return '<div class="if-vl-item' + (v.managed ? "" : " unmanaged") + '" data-vl="' + esc(v.device) + '"><div class="if-vl-head">' +
      '<span class="if-chip if-role-opt">VLAN ' + esc(v.vlan) + '</span> <strong class="if-vl-name">' + esc(v.name) + "</strong>" +
      (v.id ? ' <span class="if-sub">' + esc(String(v.id).toUpperCase()) + "</span>" : ' <span class="if-warn">not in interfaces.json</span>') +
      '<span class="toolbar-spacer"></span>' + acts + '</div><div class="if-vl-grid">' + rows.join("") + "</div></div>";
  }

  function renderVlans() {
    var d = state.vlans, list = $("#if-vl-list");
    if (!d || !list) return;
    $("#if-vl-apstat").innerHTML = apStatus(d);
    list.innerHTML = (d.vlans || []).length ? d.vlans.map(vlanCard).join("") :
      '<p class="muted">No VLANs yet. Use Add VLAN to tag a new network on a port.</p>';
    var lp = d.legacy_policies || [];
    $("#if-vl-legacy").innerHTML = '<p class="if-sub">' + (lp.length
      ? "Policies from the old VLANs page: " + lp.map(function (x) {
          return "<code>" + esc(x.rule || x.src + " → " + x.dst) + "</code>" + (x.cell ? " → matrix cell " + esc(x.cell[0]) + "→" + esc(x.cell[1]) : ' <span class="if-warn">(no matching networks)</span>');
        }).join("; ")
      : "No inter-VLAN policies were created on the old VLANs page; the matrix on the Policy tab shows the effective rules.") + "</p>";
  }

  function showPane(pane) {
    var tab = $('.fw-subtab[data-if-pane="' + pane + '"]');
    if (tab && !tab.classList.contains("active")) tab.click();
    try { if (location.hash.indexOf("#interfaces") === 0) history.replaceState(null, "", "#interfaces/" + pane); } catch (_) { }
  }
  function withData(fn) {
    if (state.data) { fn(); return; }
    setStatus("Loading…");
    var n = 0, t = setInterval(function () { if (state.data) { clearInterval(t); fn(); } else if (++n > 200) clearInterval(t); }, 150);
    load(true);
  }
  function focusOptCard(k, field) {
    var card = $('[data-opt-card="' + k + '"]');
    if (!card) return;
    card.scrollIntoView({ block: "center", behavior: "smooth" });
    var el = $('[data-k="opt.' + k + "." + (field || "name") + '"]', card) || $("input, select", card);
    if (el) el.focus({ preventScroll: true });
  }
  function optIndex(id) {
    var opts = draft().opt || [];
    for (var k = 0; k < opts.length; k++) if (opts[k].id === id) return k;
    return -1;
  }
  function vlanAdd(meta) {
    withData(function () {
      var d = draft();
      var o = meta || { name: "", vlan: "", parent: (d.lan || {}).device || "", address: "", dhcp: true, ra: false };
      d.opt.push(o);
      state.focusOpt = o;
      showPane("edit"); renderEdit();
      focusOptCard(d.opt.length - 1, meta ? "name" : "vlan");
    });
  }
  function vlanEdit(id) {
    withData(function () {
      var k = optIndex(id);
      if (k < 0) { setStatus("That VLAN is not in the editor's record; refresh the page.", true); return; }
      state.focusOpt = draft().opt[k];
      showPane("edit"); renderEdit(); focusOptCard(k, "name");
    });
  }
  function vlanRemove(id) {
    withData(function () {
      var k = optIndex(id);
      if (k < 0) return;
      var o = draft().opt.splice(k, 1)[0];
      state.focusOpt = null;
      showPane("edit"); renderEdit();
      setStatus("Removed " + (o.name || o.id) + " (VLAN " + o.vlan + ") from the draft. Review the plan below; nothing changes until Apply.");
      review("#if-plan");
      var pl = $("#if-plan"); if (pl) pl.scrollIntoView({ block: "start", behavior: "smooth" });
    });
  }
  function vlanAdopt(dev) {
    var v = ((state.vlans || {}).vlans || []).filter(function (x) { return x.device === dev; })[0];
    if (!v) return;
    vlanAdd({ name: v.name !== dev ? v.name : "", vlan: +v.vlan || v.vlan, parent: v.parent, device: dev, address: v.address, dhcp: false, ra: false });
  }

  /* Old VLANs page: while Apply is locked it is the live path; once unlocked it
     redirects here and leaves the sidebar. */
  var navLocked = null;
  function lockNav(isLocked) {
    navLocked = isLocked;
    var ni = document.querySelector(".nav-item.ni-vlans");
    if (ni) ni.hidden = !isLocked;
    var old = document.getElementById("view-vlans");
    if (!isLocked && old && !old.hidden && window.twGo) window.twGo("interfaces", "vlans");
  }
  (function watchOldPage() {
    var old = document.getElementById("view-vlans");
    var check = function () {
      if (navLocked !== null) { lockNav(navLocked); return; }
      getJSON("/api/interfaces/lock").then(function (j) { lockNav(j.apply_locked !== false); }).catch(function () { });
    };
    if (old) new MutationObserver(function () { if (!old.hidden) check(); }).observe(old, { attributes: true, attributeFilter: ["hidden"] });
    if (/^#vlans(\/|$)/.test(location.hash) || !document.getElementById("login-gate") || document.getElementById("login-gate").hidden) check();
  })();
  window.twIfVlanAdd = function () { if (window.twGo) window.twGo("interfaces", "vlans").then(function () { vlanAdd(); }); };

  function setStatus(msg, err) {
    var s = $("#if-status");
    s.textContent = msg || "";
    s.classList.toggle("err", !!err);
  }

  function load(force) {
    if (state.loading) return;
    if (!force && state.data && Date.now() - state.at < 30000) return;
    state.loading = true;
    setStatus("Loading…");
    Promise.all([getJSON("/api/interfaces"), getJSON("/api/interfaces/policy")])
      .then(function (res) {
        state.data = res[0]; state.policy = res[1]; state.at = Date.now();
        render();
        setStatus("Updated " + new Date().toLocaleTimeString());
      })
      .catch(function (e) { setStatus("Could not load interfaces: " + e.message, true); })
      .then(function () { state.loading = false; });
  }

  /* ------------------------------------------------------------ events */
  view.addEventListener("click", function (e) {
    var tab = e.target.closest(".fw-subtab[data-if-pane]");
    if (tab) {
      $$(".fw-subtab[data-if-pane]").forEach(function (t) {
        var on = t === tab;
        t.classList.toggle("active", on);
        t.setAttribute("aria-selected", on ? "true" : "false");
      });
      $$("[data-if-body]").forEach(function (p) { p.hidden = p.dataset.ifBody !== tab.dataset.ifPane; });
      if (tab.dataset.ifPane === "vlans") loadVlans(false);
      return;
    }
    var cell = e.target.closest(".if-mx-cell");
    if (cell) { state.sel = { r: cell.dataset.r, c: cell.dataset.c }; showCell(state.sel); return; }
    if (e.target.closest("#if-refresh")) { state.draft = null; load(true); if (state.vlans) loadVlans(true); return; }
    var t = e.target.closest("button");
    if (!t) return;
    var d, inv, used, free;
    switch (t.id) {
      case "if-add-opt":
        d = draft(); used = {};
        [d.wan, d.lan].concat(d.opt).forEach(function (n) { if (n && n.device) used[n.device] = 1; });
        inv = (state.data.inventory || []).filter(function (i) { return i.kind === "ethernet" && !used[i.device]; });
        free = inv[0] ? inv[0].device : "";
        d.opt.push({ name: "", device: free, address: "", dhcp: true, ra: false });
        renderEdit(); return;
      case "if-add-vlan":
        d = draft();
        d.opt.push({ name: "", vlan: "", parent: (d.lan || {}).device || "", address: "", dhcp: true, ra: false });
        renderEdit(); return;
      case "if-vl-add": vlanAdd(); return;
      case "if-vl-aps": state.vlPolls = 0; loadVlans(true, true); return;
      case "if-reset": state.draft = null; state.plan = null; state.focusOpt = null; renderEdit(); renderPlan(); $("#if-plan").innerHTML = ""; return;
      case "if-review": review("#if-plan"); return;
      case "if-apply": doApply(); return;
      case "if-confirm": pendingAction("confirm"); return;
      case "if-rollback": pendingAction("rollback"); return;
      case "if-pm-toggle": state.pmEdit = !state.pmEdit; renderPolicyBar(); showCell(state.sel); return;
      case "if-pm-apply-preset": usePreset($("#if-pm-net").value, $("#if-pm-preset").value); renderPolicy(); renderPolicyBar(); return;
      case "if-pm-discard": state.pedits = {}; renderPolicy(); renderPolicyBar(); return;
      case "if-pm-review": review("#if-plan-pm"); return;
      case "if-cell-undo": if (state.sel) { setCell(state.sel.r, state.sel.c, ""); renderPolicy(); renderPolicyBar(); } return;
    }
    if (t.hasAttribute("data-rm-opt")) { draft().opt.splice(+t.getAttribute("data-rm-opt"), 1); renderEdit(); return; }
    if (t.hasAttribute("data-vl-edit")) { vlanEdit(t.getAttribute("data-vl-edit")); return; }
    if (t.hasAttribute("data-vl-rm")) { vlanRemove(t.getAttribute("data-vl-rm")); return; }
    if (t.hasAttribute("data-vl-adopt")) { vlanAdopt(t.getAttribute("data-vl-adopt")); return; }
    if (t.hasAttribute("data-vl-mx")) {
      var zid = t.getAttribute("data-vl-mx");
      showPane("policy"); state.sel = { r: zid, c: "wan" }; showCell(state.sel);
      var c0 = $('.if-mx-cell[data-r="' + zid + '"]'); if (c0) c0.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  });

  function onField(e) {
    var el = e.target;
    if (el.id === "if-cell-sel" && state.sel) {
      setCell(state.sel.r, state.sel.c, el.value); renderPolicy(); renderPolicyBar(); return;
    }
    if (el.hasAttribute && el.hasAttribute("data-preset-new")) {
      draft().opt[+el.getAttribute("data-preset-new")].__preset = el.value || undefined; return;
    }
    var k = el.getAttribute && el.getAttribute("data-k");
    if (!k) return;
    setPath(k, el.type === "checkbox" ? el.checked : el.value.trim());
    if (e.type === "change" && /\.address$/.test(k) && dropStalePool(k.replace(/\.address$/, ""))) { renderEdit(); return; }
    if (e.type === "change" && (el.type === "checkbox" || el.tagName === "SELECT")) renderEdit();
  }
  view.addEventListener("input", function (e) { if (e.target.type !== "checkbox" && e.target.tagName !== "SELECT") onField(e); });
  view.addEventListener("change", onField);
  view.addEventListener("toggle", function (e) {
    var det = e.target;
    if (!det.classList || !det.classList.contains("if-diff") || !det.open || !state.plan) return;
    var f = (state.plan.files || [])[+det.getAttribute("data-diff")];
    var b = det.querySelector(".if-diff-body");
    if (f && b && !b.firstChild) b.innerHTML = diffHTML((state.plan.diffs || {})[f.path]);
  }, true);

  view.addEventListener("keydown", function (e) {
    var cell = e.target.closest && e.target.closest(".if-mx-cell");
    if (!cell || (e.key !== "Enter" && e.key !== " ")) return;
    e.preventDefault();
    state.sel = { r: cell.dataset.r, c: cell.dataset.c }; showCell(state.sel);
  });

  function onShow() {
    load(false);
    var vb = $('[data-if-body="vlans"]');
    if (vb && !vb.hidden) loadVlans(false);
  }
  ensureEditUI();
  new MutationObserver(function () { if (!view.hidden) onShow(); })
    .observe(view, { attributes: true, attributeFilter: ["hidden"] });
  if (!view.hidden) onShow();
})();
