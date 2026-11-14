/* TuxWall — Interfaces page (read-only): NIC inventory, role assignments,
   services bound to each network and the effective policy matrix.
   Data: GET /api/interfaces, GET /api/interfaces/policy. */
(function () {
  "use strict";
  var view = document.getElementById("view-interfaces");
  if (!view) return;

  var state = { data: null, policy: null, at: 0, loading: false, sel: null };
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
    (t.opt || []).forEach(function (o) { if (o.device === dev) var id = (o.id || "opt").toUpperCase(); hit = { role: o.id, label: id + (o.name && o.name !== id ? " · " + o.name : "") }; });
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
      ' · <span class="if-lock">' + (d.apply_locked ? "Read-only · Apply is locked on this router" : "Read-only view") + "</span>";
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
          var st = cell.state || "block";
          var extra = (cell.exceptions || []).length ? ' <span class="if-mx-exc" title="exceptions">+' + cell.exceptions.length + "</span>" : "";
          var v6 = cell.v6 ? '<span class="if-mx-v6">v6: ' + esc(STATE_LABEL[cell.v6] || cell.v6) + "</span>" : "";
          var ports = st === "custom" && cell.ports ? '<span class="if-mx-ports">' + esc(cell.ports.slice(0, 4).join(" ")) + (cell.ports.length > 4 ? " …" : "") + "</span>" : "";
          if (st === "self") return '<td role="gridcell" class="if-mx-self" aria-label="same network">—</td>';
          return '<td role="gridcell" tabindex="0" aria-selected="false" class="if-mx-cell st-' + esc(st) + '" data-r="' + esc(r.id) + '" data-c="' + esc(c.id) + '">' +
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
      (cell.v6 ? '<div class="if-sub">IPv6: ' + esc(STATE_LABEL[cell.v6] || cell.v6) + "</div><ul class=\"if-list\">" + code(cell.v6_rules || []) + "</ul>" : "");
  }

  function render() {
    if (!state.data) return;
    renderStats(); renderNics(); renderRoles(); renderServices(); renderPolicy();
  }

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
      return;
    }
    var cell = e.target.closest(".if-mx-cell");
    if (cell) { state.sel = { r: cell.dataset.r, c: cell.dataset.c }; showCell(state.sel); return; }
    if (e.target.closest("#if-refresh")) load(true);
  });

  view.addEventListener("keydown", function (e) {
    var cell = e.target.closest && e.target.closest(".if-mx-cell");
    if (!cell || (e.key !== "Enter" && e.key !== " ")) return;
    e.preventDefault();
    state.sel = { r: cell.dataset.r, c: cell.dataset.c }; showCell(state.sel);
  });

  new MutationObserver(function () { if (!view.hidden) load(false); })
    .observe(view, { attributes: true, attributeFilter: ["hidden"] });
  if (!view.hidden) load(false);
})();
