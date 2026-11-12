/* ============================================================================
   TuxWall — live network map (Overview) + unified threat timeline (Security)
   Phase D. Read-only: passively observes the /api/* responses dashboard.js
   already fetches (fetch wrapper + clone) and only issues its own GETs when
   that data is stale. Never performs state changes.
   ========================================================================= */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var SVGNS = "http://www.w3.org/2000/svg";
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function authed() {
    var gate = document.getElementById("login-gate");
    return !gate || gate.hidden;
  }
  var reduceMotion = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };
  function go(view, sub) {
    if (window.twGo) window.twGo(view, sub, { push: true });
    else { var n = $('.nav-item[data-view="' + view + '"]'); if (n) n.click(); }
  }

  /* ==========================================================================
     Shared API cache (fed by observing dashboard.js fetches)
     ======================================================================= */
  var cache = {};       // path -> { at, data }
  var inflight = {};
  var listeners = [];
  var WATCH = {
    "/api/system": 1, "/api/bandwidth": 1, "/api/security": 1, "/api/leases": 1,
    "/api/wireguard": 1, "/api/vlans": 1, "/api/dmz": 1, "/api/security/suricata": 1,
    "/api/security/honeypot": 1, "/api/security/canary": 1, "/api/security/tripwire": 1,
    "/api/incidents": 1, "/api/crowdsec": 1, "/api/dns": 1, "/api/firewall": 1
  };
  function pathOf(url) {
    try { return new URL(url, location.href).pathname.replace(/\/+$/, ""); } catch (_) { return ""; }
  }
  function slim(path, d) {
    // The CrowdSec payload is ~1.8 MB; keep only what the timeline needs.
    if (path === "/api/crowdsec" && d) {
      var banned = {};
      (d.decisions || []).forEach(function (x) { if (x && x.ip) banned[x.ip] = 1; });
      return { alerts: d.alerts || [], banned: banned, bans: d.bans_count || 0 };
    }
    return d;
  }
  function store(path, d) {
    if (!d || d.ok === false) return;
    cache[path] = { at: Date.now(), data: slim(path, d) };
    listeners.forEach(function (fn) { try { fn(path); } catch (_) { } });
  }
  var _fetch = window.fetch;
  window.fetch = function (input, init) {
    var p = _fetch.apply(this, arguments);
    try {
      var method = (init && init.method) || (input && input.method) || "GET";
      var path = String(method).toUpperCase() === "GET" ? pathOf(typeof input === "string" ? input : (input && input.url) || "") : "";
      if (path && WATCH[path]) {
        // Skip re-parsing the big CrowdSec payload unless ours is getting old.
        if (path !== "/api/crowdsec" || !cache[path] || Date.now() - cache[path].at > 240000) {
          p.then(function (r) {
            if (r && r.ok) r.clone().json().then(function (d) { store(path, d); }, function () { });
          }, function () { });
        }
      }
    } catch (_) { }
    return p;
  };
  function get(path, maxAge) {
    var c = cache[path];
    if (c && Date.now() - c.at < maxAge) return Promise.resolve(c.data);
    if (inflight[path]) return inflight[path];
    inflight[path] = _fetch(path, { cache: "no-store", credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (d) { store(path, d); return cache[path] ? cache[path].data : d; })
      .catch(function () { return c ? c.data : null; })
      .then(function (v) { delete inflight[path]; return v; });
    return inflight[path];
  }
  function data(path) { return cache[path] ? cache[path].data : null; }
  // Shared with insights.js so it observes the same responses (no extra polls).
  window.twApi = { data: data, get: get, on: function (fn) { listeners.push(fn); } };

  /* ==========================================================================
     Helpers
     ======================================================================= */
  function ip2n(ip) {
    var p = String(ip).split(".");
    if (p.length !== 4) return null;
    return (((+p[0]) << 24) >>> 0) + ((+p[1]) << 16) + ((+p[2]) << 8) + (+p[3]);
  }
  function inNet(ip, net) {
    var n = ip2n(ip);
    if (n === null || !net) return false;
    var m = net.bits ? (0xffffffff << (32 - net.bits)) >>> 0 : 0;
    return ((n & m) >>> 0) === ((net.base & m) >>> 0);
  }
  function parseCidr(s) {
    var m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(String(s || "").trim());
    if (!m) return null;
    var bits = +m[2], n = ip2n(m[1]);
    var mask = bits ? (0xffffffff << (32 - bits)) >>> 0 : 0;
    var base = (n & mask) >>> 0;
    return { base: base, bits: bits, text: [base >>> 24, (base >> 16) & 255, (base >> 8) & 255, base & 255].join(".") + "/" + bits };
  }
  function isPrivate(ip) {
    return /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|fd|fc|::1$)/i.test(String(ip || ""));
  }
  function fmtMbps(bps) {
    var m = (bps || 0) / 1e6;
    if (m >= 100) return m.toFixed(0);
    if (m >= 10) return m.toFixed(1);
    if (m >= 0.01) return m.toFixed(2);
    return "0";
  }
  function rel(ts) {
    if (!ts) return "—";
    var s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 45) return "just now";
    if (s < 3600) return Math.round(s / 60) + "m ago";
    if (s < 86400) return Math.round(s / 3600) + "h ago";
    return Math.round(s / 86400) + "d ago";
  }
  function absTime(ts) {
    try { return new Date(ts * 1000).toLocaleString(); } catch (_) { return ""; }
  }
  function flag(iso) {
    iso = String(iso || "").toUpperCase();
    if (!/^[A-Z]{2}$/.test(iso)) return "";
    return String.fromCodePoint(0x1f1e6 + iso.charCodeAt(0) - 65, 0x1f1e6 + iso.charCodeAt(1) - 65);
  }
  function svg(tag, attrs, parent) {
    var e = document.createElementNS(SVGNS, tag);
    if (attrs) for (var k in attrs) if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  /* ==========================================================================
     D1. Live network map
     ======================================================================= */
  var ICONS = {
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    core: '<path d="M12 3 4 6v6c0 4.5 3.4 8.2 8 9 4.6-.8 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
    lan: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    vlan: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="8.5" y="14" width="7" height="7" rx="1.5"/><path d="M6.5 10v2h11v-2M12 12v2"/>',
    wg: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    dmz: '<path d="M12 3 3 8v8l9 5 9-5V8z"/><path d="M3 8l9 5 9-5M12 13v8"/>'
  };
  var map = {
    card: null, svgEl: null, nodes: {}, links: [], layoutKey: "", width: 0,
    raf: 0, last: 0, prevHits: null, prevHoney: null, prevSur: null, pulseUntil: 0,
    timer: 0, built: false
  };

  function ovVisible() {
    var v = document.getElementById("view-overview");
    return !!v && !v.hidden && !document.hidden && authed();
  }

  function topology() {
    var sys = data("/api/system") || {};
    var vl = data("/api/vlans") || {};
    var wg = data("/api/wireguard") || {};
    var dmz = data("/api/dmz") || {};
    var wanIf = (sys.wan && sys.wan.ifname) || "";
    var router = sys.dhcp && sys.dhcp.router;
    var lan = null;
    (sys.interfaces || []).forEach(function (i) {
      if (lan || !i || i.name === wanIf || /^(lo|wg|ifb|docker|veth|br-|virbr)/.test(i.name) || i.name.indexOf(".") !== -1) return;
      (i.addrs || []).forEach(function (a) {
        if (lan || a.family !== "inet") return;
        if (!router || a.addr === router || isPrivate(a.addr)) lan = { ifname: i.name, net: parseCidr(a.addr + "/" + a.mask) };
      });
    });
    var nodes = [{ id: "wan", kind: "globe", title: "Internet", view: "security" },
                 { id: "core", kind: "core", title: "TuxWall", view: "system" }];
    var kids = [];
    kids.push({ id: "lan", kind: "lan", title: "LAN", view: "clients", ifname: lan ? lan.ifname : "", net: lan && lan.net });
    (vl.vlans || []).forEach(function (v) {
      var net = null;
      (v.addresses || []).forEach(function (a) { if (!net) net = parseCidr(a); });
      kids.push({ id: "vlan-" + v.vlan_id, kind: "vlan", title: (v.label || "VLAN") + " · " + v.vlan_id, view: "vlans", ifname: v.iface, net: net, state: v.state });
    });
    if (wg.configured || (wg.interface && wg.interface.name)) {
      kids.push({ id: "wg", kind: "wg", title: "WireGuard", view: "wireguard", ifname: (wg.interface && wg.interface.name) || "wg0" });
    }
    if ((dmz.dmz_count || 0) > 0) kids.push({ id: "dmz", kind: "dmz", title: "DMZ", view: "firewall", sub: "nat" });
    return { wanIf: wanIf, nodes: nodes, kids: kids };
  }

  function buildCard() {
    if (map.card) return map.card;
    var grid = $("#view-overview .ov-mon-grid");
    if (!grid) return null;
    var card = document.createElement("section");
    card.className = "card tw-netmap";
    card.setAttribute("aria-label", "Live network map");
    card.innerHTML =
      '<div class="tw-netmap-head">' +
        '<div class="tw-netmap-title"><span class="tw-netmap-live" aria-hidden="true"></span>Live network map</div>' +
        '<div class="tw-netmap-meta"><span class="tw-netmap-legend"><i class="dn"></i>download</span>' +
        '<span class="tw-netmap-legend"><i class="up"></i>upload</span>' +
        '<span class="tw-netmap-legend"><i class="atk"></i>blocked attack</span>' +
        '<span class="tw-netmap-total" aria-live="off"></span></div>' +
      '</div>' +
      '<div class="tw-netmap-stage"><svg class="tw-netmap-svg" role="img" aria-label="Network topology with live throughput"></svg></div>';
    grid.parentNode.insertBefore(card, grid);
    map.card = card;
    map.svgEl = card.querySelector("svg");
    map.svgEl.addEventListener("click", function (e) {
      var g = e.target.closest && e.target.closest("[data-nav]");
      if (g) go(g.getAttribute("data-nav"), g.getAttribute("data-sub") || "");
    });
    map.svgEl.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" && e.key !== " ") return;
      var g = e.target.closest && e.target.closest("[data-nav]");
      if (g) { e.preventDefault(); go(g.getAttribute("data-nav"), g.getAttribute("data-sub") || ""); }
    });
    return card;
  }

  function layout(topo) {
    var stage = map.card.querySelector(".tw-netmap-stage");
    // Measure the stage only when it has resized (ResizeObserver flags it);
    // reading clientWidth on every update forced a synchronous reflow.
    if (!map.stageW || map.measure) {
      var cw = stage.clientWidth;
      if (cw > 0) { map.stageW = cw; map.measure = false; }
      if (!map.ro && window.ResizeObserver) {
        map.ro = new ResizeObserver(function () { map.measure = true; });
        map.ro.observe(stage);
      }
    }
    var W = Math.max(300, Math.round(map.stageW || 900));
    var kids = topo.kids;
    var narrow = W < 720;
    var key = W + "|" + narrow + "|" + kids.map(function (k) { return k.id; }).join(",");
    if (key === map.layoutKey) return false;
    map.layoutKey = key;
    map.width = W;
    var s = map.svgEl;
    while (s.firstChild) s.removeChild(s.firstChild);
    map.nodes = {}; map.links = [];

    var defs = svg("defs", null, s);
    var gl = svg("filter", { id: "twnm-glow", x: "-50%", y: "-50%", width: "200%", height: "200%" }, defs);
    svg("feGaussianBlur", { stdDeviation: "3", result: "b" }, gl);
    var mg = svg("feMerge", null, gl);
    svg("feMergeNode", { "in": "b" }, mg); svg("feMergeNode", { "in": "SourceGraphic" }, mg);

    var pos = {}, H, nw, nh;
    if (!narrow) {
      nw = Math.min(196, Math.max(150, W * 0.17)); nh = 62;
      var rowH = 74;
      H = Math.max(230, kids.length * rowH + 40);
      var cy = H / 2;
      pos.wan = { x: Math.max(nw / 2 + 12, W * 0.12), y: cy };
      pos.core = { x: W * 0.45, y: cy };
      var kx = W - nw / 2 - 14;
      kids.forEach(function (k, i) { pos[k.id] = { x: kx, y: cy + (i - (kids.length - 1) / 2) * rowH }; });
    } else {
      var cols = 2, gap = 10;
      nw = Math.min(170, (W - 24 - gap) / cols); nh = 58;
      pos.wan = { x: W / 2, y: 40 };
      pos.core = { x: W / 2, y: 150 };
      var rows = Math.ceil(kids.length / cols);
      kids.forEach(function (k, i) {
        var r = Math.floor(i / cols), c = i % cols;
        var inRow = Math.min(cols, kids.length - r * cols);
        var span = inRow * nw + (inRow - 1) * gap;
        pos[k.id] = { x: (W - span) / 2 + nw / 2 + c * (nw + gap), y: 270 + r * (nh + 34) };
      });
      H = 270 + (rows - 1) * (nh + 34) + nh / 2 + 14;
    }
    s.setAttribute("viewBox", "0 0 " + W + " " + H);
    s.setAttribute("height", H);
    s.classList.toggle("narrow", narrow);

    var linkLayer = svg("g", { "class": "nm-links" }, s);
    var labelLayer = svg("g", { "class": "nm-labels" }, s);
    var nodeLayer = svg("g", { "class": "nm-nodes" }, s);

    function pathD(a, b, vertical) {
      if (vertical) {
        var y1 = a.y + nh / 2, y2 = b.y - nh / 2, my = (y1 + y2) / 2;
        return "M" + a.x + "," + y1 + " C" + a.x + "," + my + " " + b.x + "," + my + " " + b.x + "," + y2;
      }
      var x1 = a.x + nw / 2, x2 = b.x - nw / 2, mx = (x1 + x2) / 2;
      return "M" + x1 + "," + a.y + " C" + mx + "," + a.y + " " + mx + "," + b.y + " " + x2 + "," + b.y;
    }
    function addLink(id, from, to, cls) {
      var d = pathD(pos[from], pos[to], narrow);
      var g = svg("g", { "class": "nm-link " + (cls || ""), "data-link": id, "data-nav": "bandwidth" }, linkLayer);
      var track = svg("path", { d: d, "class": "nm-track" }, g);
      var dn = svg("path", { d: d, "class": "nm-flow nm-dn" }, g);
      var up = svg("path", { d: d, "class": "nm-flow nm-up" }, g);
      var atk = id === "wan" ? svg("path", { d: d, "class": "nm-atk" }, g) : null;
      var len = track.getTotalLength ? track.getTotalLength() : 200;
      var mid = narrow && id !== "wan" ? { x: pos[to].x, y: pos[to].y - nh / 2 - 15 }
        : track.getPointAtLength ? track.getPointAtLength(len / 2) : { x: 0, y: 0 };
      var lab = svg("g", { "class": "nm-label", "data-nav": "bandwidth", transform: "translate(" + mid.x.toFixed(1) + "," + mid.y.toFixed(1) + ")" }, labelLayer);
      var bg = svg("rect", { "class": "nm-label-bg", x: -44, y: -11, width: 88, height: 22, rx: 11 }, lab);
      var tx = svg("text", { "class": "nm-label-text", "text-anchor": "middle", y: 4 }, lab);
      if (atk) atk.style.strokeDasharray = "28 " + Math.max(60, len);
      map.links.push({ id: id, g: g, dn: dn, up: up, atk: atk, len: len, lab: lab, bg: bg, tx: tx, offDn: 0, offUp: 0, vDn: 0, vUp: 0 });
    }
    addLink("wan", "wan", "core", "is-wan");
    kids.forEach(function (k) { addLink(k.id, "core", k.id); });

    function addNode(n) {
      var p = pos[n.id];
      var g = svg("g", {
        "class": "nm-node nm-" + n.kind, "data-node": n.id, "data-nav": n.view, "data-sub": n.sub || null,
        tabindex: "0", role: "link", transform: "translate(" + (p.x - nw / 2).toFixed(1) + "," + (p.y - nh / 2).toFixed(1) + ")"
      }, nodeLayer);
      svg("title", null, g).textContent = "Open " + n.title;
      svg("rect", { "class": "nm-box", width: nw, height: nh, rx: 12 }, g);
      var ic = svg("g", { "class": "nm-ic", transform: "translate(10," + (nh / 2 - 15) + ")" }, g);
      svg("rect", { "class": "nm-ic-bg", width: 30, height: 30, rx: 9 }, ic);
      var icon = svg("g", { transform: "translate(5,5) scale(0.833)", fill: "none", stroke: "currentColor", "stroke-width": "1.9", "stroke-linecap": "round", "stroke-linejoin": "round" }, ic);
      icon.innerHTML = ICONS[n.kind] || ICONS.lan;
      var t1 = svg("text", { "class": "nm-t1", x: 48, y: nh / 2 - 9 }, g);
      var t2 = svg("text", { "class": "nm-t2", x: 48, y: nh / 2 + 7 }, g);
      var t3 = svg("text", { "class": "nm-t3", x: 48, y: nh / 2 + 21 }, g);
      t1.textContent = n.title;
      var dot = svg("circle", { "class": "nm-dot", cx: nw - 12, cy: 12, r: 3.5 }, g);
      map.nodes[n.id] = { g: g, t1: t1, t2: t2, t3: t3, dot: dot, def: n, maxW: nw - 56 };
    }
    topo.nodes.concat(kids).forEach(addNode);
    return true;
  }

  function fitText(t, s, maxW) {
    // Skip unchanged text: measuring forces a layout on every update.
    if (t._twSrc === s && t._twW === maxW) return;
    t._twSrc = s; t._twW = maxW;
    t.textContent = s;
    try {
      if (t.getComputedTextLength && t.getComputedTextLength() > maxW) {
        while (s.length > 3 && t.getComputedTextLength() > maxW) { s = s.slice(0, -1); t.textContent = s + "…"; }
      }
    } catch (_) { }
  }

  function updateMap() {
    if (!map.card || !authed()) return;
    var topo = topology();
    layout(topo);
    var sys = data("/api/system") || {};
    var bw = data("/api/bandwidth") || {};
    var sec = data("/api/security") || {};
    var leases = (data("/api/leases") || {}).leases || [];
    var wg = data("/api/wireguard") || {};
    var dmz = data("/api/dmz") || {};
    var ifs = {};
    (bw.interfaces || []).forEach(function (i) { ifs[i.name] = i; });
    var online = leases.filter(function (l) { return l.online; });
    var setN = function (id, t2, t3, state) {
      var n = map.nodes[id];
      if (!n) return;
      fitText(n.t2, t2, n.maxW);
      fitText(n.t3, t3 || "", n.maxW);
      n.g.setAttribute("data-state", state || "ok");
    };
    var lat = sys.latency || {};
    var st = sec.stats || {};
    var narrow = map.svgEl.classList.contains("narrow");
    setN("wan", (sys.wan && sys.wan.ipv4) || "—",
      (lat.current_ms != null ? Math.round(lat.current_ms) + " ms" : "—") + (st.hits_10m != null ? " · " + st.hits_10m + (narrow ? " blocked" : " blocked/10m") : ""),
      sys.wan && sys.wan.state && sys.wan.state !== "UP" ? "bad" : (lat.current_ms > 150 ? "warn" : "ok"));
    var cpu = sys.usage && sys.usage.cpu_pct;
    var hs = $("#ov-health-score");
    var health = hs ? hs.textContent.trim() : "";
    setN("core", (sys.hostname || "router"),
      "CPU " + (cpu != null ? Math.round(cpu) + "%" : "—") + (/^\d+$/.test(health) ? " · Health " + health : ""),
      /^\d+$/.test(health) && +health < 60 ? "bad" : (/^\d+$/.test(health) && +health < 85) || cpu > 85 ? "warn" : "ok");

    var rates = {};
    var wanI = ifs[topo.wanIf] || {};
    rates.wan = { dn: wanI.rx_bps || 0, up: wanI.tx_bps || 0 };
    topo.kids.forEach(function (k) {
      var cnt;
      if (k.kind === "lan" || k.kind === "vlan") {
        var i = ifs[k.ifname] || {};
        rates[k.id] = { dn: i.tx_bps || 0, up: i.rx_bps || 0 };
        cnt = k.net ? online.filter(function (l) { return inNet(l.ip, k.net); }).length : (k.kind === "lan" ? online.length : 0);
        setN(k.id, cnt + " online", k.net ? k.net.text : (k.ifname || ""), k.state && k.state !== "UP" ? "bad" : "ok");
      } else if (k.kind === "wg") {
        var w = ifs[k.ifname] || {};
        rates[k.id] = { dn: w.tx_bps || 0, up: w.rx_bps || 0 };
        var peers = wg.peers || [], now = Date.now() / 1000;
        var on = peers.filter(function (p) { return p.last_handshake && now - p.last_handshake < 180; }).length;
        var up = wg.interface && wg.interface.up;
        setN("wg", on + "/" + peers.length + (narrow ? " peers" : " peers online"), (wg.interface && wg.interface.listen_port) ? "udp/" + wg.interface.listen_port : "", up === false ? "bad" : (on ? "ok" : "idle"));
      } else if (k.kind === "dmz") {
        var ips = {};
        (dmz.clients || []).forEach(function (c) { if (c.dmz_enabled) ips[c.ip] = 1; });
        var r = { dn: 0, up: 0 };
        (bw.clients || []).forEach(function (c) { if (ips[c.ip]) { r.dn += (c.rx_bytes_per_s || 0) * 8; r.up += (c.tx_bytes_per_s || 0) * 8; } });
        rates.dmz = r;
        setN("dmz", (dmz.dmz_count || 0) + " exposed host" + (dmz.dmz_count === 1 ? "" : "s"), "isolated", "warn");
      }
    });

    map.links.forEach(function (L) {
      var r = rates[L.id] || { dn: 0, up: 0 };
      var mDn = r.dn / 1e6, mUp = r.up / 1e6;
      var wDn = Math.min(7, 1.6 + 1.9 * Math.log10(1 + mDn)), wUp = Math.min(6, 1.4 + 1.7 * Math.log10(1 + mUp));
      L.dn.style.strokeWidth = wDn.toFixed(2);
      L.up.style.strokeWidth = wUp.toFixed(2);
      L.vDn = mDn < 0.005 ? 0 : 18 + 34 * Math.log10(1 + mDn * 4);
      L.vUp = mUp < 0.005 ? 0 : 14 + 30 * Math.log10(1 + mUp * 4);
      L.dn.classList.toggle("idle", !L.vDn);
      L.up.classList.toggle("idle", !L.vUp);
      L.g.classList.toggle("busy", mDn + mUp > 25);
      var label = "↓" + fmtMbps(r.dn) + "  ↑" + fmtMbps(r.up) + " Mbps";
      if (L.tx._twSrc !== label) {   // measure only when the label changes
        L.tx._twSrc = label;
        L.tx.textContent = label;
        var tw = 92;
        try { tw = L.tx.getComputedTextLength() + 18; } catch (_) { }
        L.bg.setAttribute("x", (-tw / 2).toFixed(1));
        L.bg.setAttribute("width", tw.toFixed(1));
      }
      L.g.querySelector("title") || (svg("title", null, L.g).textContent = "Open Bandwidth");
    });
    var tot = map.card.querySelector(".tw-netmap-total");
    if (tot) tot.textContent = "WAN ↓" + fmtMbps(rates.wan.dn) + " ↑" + fmtMbps(rates.wan.up) + " Mbps";

    // Attack pulse when the blocked-hit counters grow
    var hits = st.hits, honey = ((data("/api/security/honeypot") || {}).state || {}).stats, sur = data("/api/security/suricata");
    var honeyN = honey ? honey.total : null, surN = sur ? sur.count_24h : null;
    var grew = 0;
    if (hits != null && map.prevHits != null && hits > map.prevHits) grew += hits - map.prevHits;
    if (honeyN != null && map.prevHoney != null && honeyN > map.prevHoney) grew += honeyN - map.prevHoney;
    if (surN != null && map.prevSur != null && surN > map.prevSur) grew += surN - map.prevSur;
    if (hits != null) map.prevHits = hits;
    if (honeyN != null) map.prevHoney = honeyN;
    if (surN != null) map.prevSur = surN;
    if (grew > 0) pulse(grew);
    if (!map.raf && !reduceMotion.matches && ovVisible()) map.raf = requestAnimationFrame(frame);
  }

  function pulse(n) {
    var L = map.links[0], wan = map.nodes.wan;
    if (!L || !wan) return;
    map.pulseUntil = performance.now() + 1600;
    L.g.classList.remove("attack"); void L.g.getBoundingClientRect(); L.g.classList.add("attack");
    wan.g.classList.remove("hit"); void wan.g.getBoundingClientRect(); wan.g.classList.add("hit");
    var badge = svg("text", { "class": "nm-hitbadge", x: 48, y: -6 }, wan.g);
    badge.textContent = "+" + n + " blocked";
    setTimeout(function () { badge.remove(); L.g.classList.remove("attack"); wan.g.classList.remove("hit"); }, 1800);
  }

  function frame(t) {
    map.raf = 0;
    if (!ovVisible() || reduceMotion.matches) { map.last = 0; return; }
    var dt = map.last ? Math.min(0.1, (t - map.last) / 1000) : 0;
    map.last = t;
    map.links.forEach(function (L) {
      if (L.vDn) { L.offDn = (L.offDn - L.vDn * dt) % 1000; L.dn.style.strokeDashoffset = L.offDn.toFixed(1); }
      if (L.vUp) { L.offUp = (L.offUp + L.vUp * dt) % 1000; L.up.style.strokeDashoffset = L.offUp.toFixed(1); }
      if (L.atk) {
        var k = Math.max(0, map.pulseUntil - t) / 1600;
        L.atk.style.strokeDashoffset = (L.len * k - 28 * (1 - k)).toFixed(1);
        L.atk.style.opacity = k > 0 ? Math.min(1, k * 2.5).toFixed(2) : "0";
      }
    });
    map.raf = requestAnimationFrame(frame);
  }

  function mapTick() {
    if (!ovVisible()) return;
    if (!buildCard()) return;
    // dashboard.js polls system/bandwidth/security every 5 s on Overview; only
    // fetch ourselves if that data has gone stale.
    Promise.all([
      get("/api/system", 9000), get("/api/bandwidth", 9000), get("/api/security", 9000),
      get("/api/leases", 40000), get("/api/wireguard", 40000),
      get("/api/vlans", 120000), get("/api/dmz", 120000)
    ]).then(updateMap);
  }

  listeners.push(function (path) {
    if (map.card && ovVisible() && /^\/api\/(system|bandwidth|security|leases|wireguard|vlans|dmz|security\/honeypot|security\/suricata)$/.test(path)) {
      clearTimeout(map.upd);
      map.upd = setTimeout(updateMap, 60);
    }
  });

  /* ==========================================================================
     D2. Unified threat timeline (Security → Timeline)
     ======================================================================= */
  var SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  var SOURCES = [
    { id: "suricata", label: "Suricata" }, { id: "crowdsec", label: "CrowdSec" },
    { id: "honeypot", label: "Honeypot" }, { id: "canary", label: "Canary" },
    { id: "tripwire", label: "Tripwire" }, { id: "firewall", label: "Firewall" },
    { id: "incident", label: "Incidents" }
  ];
  var tl = {
    root: null, sev: {}, src: {}, group: true, open: {}, limit: 60, timer: 0, events: [],
    loading: false, loadedAt: 0
  };
  try {
    var saved = JSON.parse(localStorage.getItem("tw.timeline") || "{}");
    // Default to medium+ so low-severity firewall noise doesn't bury real events
    tl.sev = saved.sev || { critical: true, high: true, medium: true }; tl.src = saved.src || {}; tl.group = saved.group !== false;
  } catch (_) { }
  function saveTl() {
    try { localStorage.setItem("tw.timeline", JSON.stringify({ sev: tl.sev, src: tl.src, group: tl.group })); } catch (_) { }
  }

  function collect() {
    var ev = [];
    var cutoff = Date.now() / 1000 - 86400;
    var geo = {};
    var sec = data("/api/security") || {};
    (sec.by_ip || []).forEach(function (r) { geo[r.ip] = r; });
    (sec.events || []).forEach(function (e) {
      if (e.src && !geo[e.src]) geo[e.src] = { iso: e.iso, country: e.country, city: e.city };
      ev.push({ ts: e.ts, src: "firewall", sev: "low", ip: e.src, title: "Blocked inbound " + (e.port || e.proto || ""), detail: "" });
    });
    var sur = data("/api/security/suricata") || {};
    (sur.alerts || []).forEach(function (a) {
      var s = String(a.severity || "").toLowerCase();
      var ip = a.src && isPrivate(a.src) && a.dst && !isPrivate(a.dst) ? a.src : a.src;
      ev.push({ ts: a.ts, src: "suricata", sev: s === "high" ? "high" : s === "medium" ? "medium" : "low", ip: ip, title: a.sig || "Suricata alert",
        detail: (a.category || "") + " · " + (a.src || "") + (a.sport ? ":" + a.sport : "") + " → " + (a.dst || "") + (a.dport ? ":" + a.dport : "") + " " + (a.proto || "") });
    });
    var cs = data("/api/crowdsec") || {};
    (cs.alerts || []).forEach(function (a) {
      var ts = Date.parse(a.created_at || a.start_at || "") / 1000;
      if (!ts) return;
      var ip = (a.source && (a.source.ip || a.source.value)) || "";
      var dec = (a.decisions || [])[0] || {};
      ev.push({ ts: ts, src: "crowdsec", sev: /local-ban|honeypot|canary/.test(a.scenario || "") ? "high" : "medium", ip: ip,
        title: (dec.type || "ban") + " · " + (a.scenario || a.message || "alert"),
        detail: (dec.duration ? "for " + dec.duration.replace(/(\d+)h\d+m[\d.]+s$/, "$1h") : "") + (a.events_count ? " · " + a.events_count + " event" + (a.events_count === 1 ? "" : "s") : "") + (a.source && a.source.cn ? " · " + a.source.cn : "") });
      if (ip && a.source && a.source.cn && !geo[ip]) geo[ip] = { iso: a.source.cn };
    });
    var hp = ((data("/api/security/honeypot") || {}).state) || {};
    (hp.traps || []).forEach(function (t) {
      ev.push({ ts: t.connected_at, src: "honeypot", sev: "medium", ip: t.ip, title: "Tarpit trapped port " + t.port,
        detail: "held " + Math.round(t.duration || 0) + "s" + (t.sent ? " · " + t.sent + " bytes sent" : "") });
    });
    var cn = data("/api/security/canary") || {};
    (cn.events || []).forEach(function (e) {
      var creds = /creds|login|password|auth/i.test((e.service || "") + " " + (e.detail || ""));
      ev.push({ ts: e.ts, src: "canary", sev: creds ? "high" : "medium", ip: e.src, title: "Canary " + (e.service || "event") + (e.dst_port ? " (:" + e.dst_port + ")" : ""), detail: e.detail || "" });
    });
    var tw = data("/api/security/tripwire") || {};
    if (tw.since && tw.src_ip) {
      ev.push({ ts: tw.since, src: "tripwire", sev: tw.tripped ? "critical" : "high", ip: tw.src_ip, title: "Tripwire " + (tw.tripped ? "TRIPPED" : "trip") + " · " + (tw.signature || tw.reason || ""),
        detail: (tw.class || "") + (tw.mode ? " · mode " + tw.mode : "") + (tw.trips ? " · " + tw.trips + " trip" + (tw.trips === 1 ? "" : "s") : "") });
    }
    var inc = data("/api/incidents") || {};
    (inc.incidents || []).forEach(function (i) {
      var s = String(i.severity || "").toLowerCase();
      ev.push({ ts: i.last_seen || i.first_seen, first: i.first_seen, src: "incident", sev: s === "critical" ? "critical" : s === "warning" ? "medium" : "low", ip: "",
        title: i.title || "Incident", detail: (i.detail || "") + (i.status ? " · " + i.status : "") });
    });
    tl.geo = geo;
    tl.banned = cs.banned || {};
    tl.events = ev.filter(function (e) { return e.ts && e.ts >= cutoff; }).sort(function (a, b) { return b.ts - a.ts; });
  }

  function filtered() {
    var anySev = Object.keys(tl.sev).some(function (k) { return tl.sev[k]; });
    var anySrc = Object.keys(tl.src).some(function (k) { return tl.src[k]; });
    return tl.events.filter(function (e) {
      return (!anySev || tl.sev[e.sev]) && (!anySrc || tl.src[e.src]);
    });
  }

  function stories(list) {
    if (!tl.group) return list.map(function (e) { return { key: "", events: [e], last: e.ts, first: e.first || e.ts, sev: e.sev, ip: e.ip }; });
    var by = {}, out = [];
    list.forEach(function (e) {
      var k = e.ip ? "ip:" + e.ip : "";
      if (!k) { out.push({ key: "", events: [e], last: e.ts, first: e.first || e.ts, sev: e.sev, ip: "" }); return; }
      var s = by[k];
      if (!s) { s = by[k] = { key: k, events: [], last: e.ts, first: e.ts, sev: e.sev, ip: e.ip }; out.push(s); }
      s.events.push(e);
      if (e.ts > s.last) s.last = e.ts;
      if (e.ts < s.first) s.first = e.ts;
      if (SEV_ORDER[e.sev] > SEV_ORDER[s.sev]) s.sev = e.sev;
    });
    return out.sort(function (a, b) { return b.last - a.last; });
  }

  function chip(kind, id, label, count, on) {
    return '<button type="button" class="tl-chip' + (on ? " on" : "") + '" data-' + kind + '="' + id + '" aria-pressed="' + (on ? "true" : "false") + '">' +
      (kind === "sev" ? '<i class="tl-sev-dot sev-' + id + '"></i>' : '<i class="tl-src-dot src-' + id + '"></i>') +
      esc(label) + '<span class="tl-chip-n">' + count + "</span></button>";
  }

  function ipBtn(ip) {
    var g = tl.geo[ip] || {};
    return '<button type="button" class="tl-ip" data-ip="' + esc(ip) + '" title="Search ' + esc(ip) + ' in the command palette">' +
      (g.iso ? '<span class="tl-flag" aria-hidden="true">' + flag(g.iso) + "</span>" : "") +
      '<span class="mono">' + esc(ip) + "</span></button>";
  }

  function srcBadge(id) {
    var s = SOURCES.filter(function (x) { return x.id === id; })[0];
    return '<span class="tl-src src-' + id + '">' + esc(s ? s.label : id) + "</span>";
  }

  function renderTl() {
    if (!tl.root) return;
    var all = tl.events;
    var sevCount = {}, srcCount = {};
    all.forEach(function (e) { sevCount[e.sev] = (sevCount[e.sev] || 0) + 1; srcCount[e.src] = (srcCount[e.src] || 0) + 1; });
    var bar = tl.root.querySelector(".tl-filters");
    bar.innerHTML =
      '<div class="tl-chiprow" role="group" aria-label="Severity">' +
        ["critical", "high", "medium", "low"].map(function (s) { return chip("sev", s, SEV_LABEL[s], sevCount[s] || 0, tl.sev[s]); }).join("") +
      "</div>" +
      '<div class="tl-chiprow" role="group" aria-label="Source">' +
        SOURCES.map(function (s) { return chip("src", s.id, s.label, srcCount[s.id] || 0, tl.src[s.id]); }).join("") +
      "</div>" +
      '<label class="tl-group-toggle"><input type="checkbox"' + (tl.group ? " checked" : "") + '> Group by attacker</label>';

    var list = stories(filtered());
    var box = tl.root.querySelector(".tl-list");
    var sum = tl.root.querySelector(".tl-summary");
    var ips = {};
    all.forEach(function (e) { if (e.ip) ips[e.ip] = 1; });
    sum.innerHTML = "<b>" + all.length + "</b> events · <b>" + Object.keys(ips).length + "</b> sources · last 24 h" +
      (tl.loadedAt ? ' · <span class="muted">updated ' + rel(tl.loadedAt / 1000) + "</span>" : "");
    if (!list.length) {
      box.innerHTML = '<div class="tl-empty">' + (tl.loading ? "Loading security events…" : "No events match these filters.") + "</div>";
      return;
    }
    var html = list.slice(0, tl.limit).map(function (s) {
      var e0 = s.events[0];
      var multi = s.events.length > 1;
      var open = multi && tl.open[s.key];
      var srcs = {};
      s.events.forEach(function (e) { srcs[e.src] = (srcs[e.src] || 0) + 1; });
      var g = s.ip ? tl.geo[s.ip] || {} : {};
      var head =
        '<div class="tl-row sev-' + s.sev + (multi ? " is-story" : "") + (open ? " open" : "") + '"' +
          (multi ? ' data-story="' + esc(s.key) + '" role="button" tabindex="0" aria-expanded="' + (open ? "true" : "false") + '"' : "") + ">" +
          '<span class="tl-when" title="' + esc(absTime(s.last)) + '">' + rel(s.last) + "</span>" +
          '<span class="tl-sev sev-' + s.sev + '">' + SEV_LABEL[s.sev] + "</span>" +
          '<span class="tl-main">' +
            '<span class="tl-title">' + (s.ip ? ipBtn(s.ip) : "") +
              '<span class="tl-text">' + esc(multi ? (e0.title) : e0.title) + "</span></span>" +
            '<span class="tl-sub">' +
              Object.keys(srcs).map(function (k) { return srcBadge(k) + (multi && srcs[k] > 1 ? '<span class="tl-x">×' + srcs[k] + "</span>" : ""); }).join("") +
              (multi ? '<span class="tl-meta">first ' + rel(s.first) + "</span>" : '<span class="tl-meta">' + esc(e0.detail || "") + "</span>") +
              (g.country && (multi || String(e0.detail || "").indexOf(g.country) === -1) ? '<span class="tl-meta">' + esc([g.city, g.country].filter(Boolean).join(", ")) + "</span>" : "") +
              (s.ip && tl.banned[s.ip] ? '<span class="tl-banned">banned</span>' : "") +
            "</span>" +
          "</span>" +
          (multi ? '<span class="tl-count">' + s.events.length + '<small>events</small></span><span class="tl-chev" aria-hidden="true"></span>' : "") +
        "</div>";
      if (!open) return head;
      var g2 = tl.geo[s.ip] || {};
      var info = (g2.isp || g2.asn || g2.city) ? '<div class="tl-story-info">' +
        [g2.city && g2.country ? g2.city + ", " + g2.country : g2.country, g2.isp, g2.asn ? "AS" + g2.asn : "", g2.count ? g2.count + " firewall hits" : ""].filter(Boolean).map(esc).join(" · ") + "</div>" : "";
      return head + '<div class="tl-story">' + info + s.events.slice(0, 40).map(function (e) {
        return '<div class="tl-ev sev-' + e.sev + '"><span class="tl-when" title="' + esc(absTime(e.ts)) + '">' + rel(e.ts) + "</span>" + srcBadge(e.src) +
          '<span class="tl-ev-text">' + esc(e.title) + (e.detail ? ' <span class="muted">' + esc(e.detail) + "</span>" : "") + "</span></div>";
      }).join("") + (s.events.length > 40 ? '<div class="tl-ev muted">+' + (s.events.length - 40) + " more</div>" : "") + "</div>";
    }).join("");
    if (list.length > tl.limit) html += '<button type="button" class="btn tl-more">Show ' + Math.min(60, list.length - tl.limit) + " more (" + (list.length - tl.limit) + " hidden)</button>";
    box.innerHTML = html;
  }

  function tlVisible() {
    var v = document.getElementById("view-security");
    return !!(tl.root && v && !v.hidden && !tl.root.closest(".fw-pane").hidden && !document.hidden && authed());
  }

  function loadTl() {
    if (tl.loading) return;
    tl.loading = true;
    if (!tl.events.length) renderTl();
    Promise.all([
      get("/api/security", 20000), get("/api/security/suricata", 20000), get("/api/security/honeypot", 20000),
      get("/api/security/canary", 30000), get("/api/security/tripwire", 30000), get("/api/incidents", 30000),
      get("/api/crowdsec", 300000)
    ]).then(function () {
      tl.loading = false;
      tl.loadedAt = Date.now();
      collect();
      renderTl();
    });
  }

  function buildTimeline() {
    var pane = $('#view-security .fw-pane[data-sec-pane="timeline"]');
    if (!pane || tl.root) return;
    pane.innerHTML =
      '<div class="card tw-timeline">' +
        '<div class="tl-head"><div><h2>Threat timeline</h2>' +
        '<p class="muted tl-desc">Suricata, CrowdSec, honeypot, canary, tripwire, firewall blocks and incidents in one stream — repeat offenders grouped into stories.</p></div>' +
        '<div class="tl-summary"></div></div>' +
        '<div class="tl-filters"></div>' +
        '<div class="tl-list" aria-live="polite"></div>' +
      "</div>";
    tl.root = pane.querySelector(".tw-timeline");
    tl.root.addEventListener("click", function (e) {
      var t = e.target;
      var ip = t.closest(".tl-ip");
      if (ip) {
        e.stopPropagation();
        if (window.twPalette) window.twPalette.open(ip.getAttribute("data-ip"));
        return;
      }
      var c = t.closest(".tl-chip");
      if (c) {
        var kind = c.hasAttribute("data-sev") ? "sev" : "src";
        var id = c.getAttribute("data-" + kind);
        tl[kind][id] = !tl[kind][id];
        tl.limit = 60; saveTl(); renderTl();
        return;
      }
      if (t.closest(".tl-more")) { tl.limit += 60; renderTl(); return; }
      var row = t.closest("[data-story]");
      if (row) { var k = row.getAttribute("data-story"); tl.open[k] = !tl.open[k]; renderTl(); }
    });
    tl.root.addEventListener("keydown", function (e) {
      if ((e.key === "Enter" || e.key === " ") && e.target.matches && e.target.matches("[data-story]")) {
        e.preventDefault();
        var k = e.target.getAttribute("data-story");
        tl.open[k] = !tl.open[k]; renderTl();
        var again = tl.root.querySelector('[data-story="' + (window.CSS && CSS.escape ? CSS.escape(k) : k) + '"]');
        if (again) again.focus();
      }
    });
    tl.root.addEventListener("change", function (e) {
      if (e.target.closest(".tl-group-toggle")) { tl.group = e.target.checked; saveTl(); renderTl(); }
    });
  }

  /* ==========================================================================
     Scheduler
     ======================================================================= */
  var tlLastLoad = 0;
  function tick() {
    if (document.hidden || !authed()) return;
    mapTick();
    buildTimeline();
    if (tlVisible() && Date.now() - tlLastLoad > 20000) { tlLastLoad = Date.now(); loadTl(); }
    else if (tlVisible() && tl.events.length) renderTl();
  }
  function kick() { setTimeout(tick, 80); }
  var TAB_ICONS = {
    timeline: '<path d="M12 7v5l3 2"/><circle cx="12" cy="12" r="9"/>',
    tripwire: '<path d="M3 17h4l3-10 4 14 3-8h4"/>'
  };
  function tabIcons() {
    Object.keys(TAB_ICONS).forEach(function (k) {
      var t = $('#sec-subtabs [data-sec-pane="' + k + '"]');
      if (!t || t.querySelector(".tab-ic")) return;
      var i = document.createElementNS(SVGNS, "svg");
      i.setAttribute("class", "tab-ic"); i.setAttribute("viewBox", "0 0 24 24"); i.setAttribute("aria-hidden", "true");
      i.setAttribute("fill", "none"); i.setAttribute("stroke", "currentColor");
      i.innerHTML = TAB_ICONS[k];
      t.insertBefore(i, t.firstChild);
    });
  }
  function boot() {
    tabIcons();
    setInterval(tick, 5000);
    var nav = document.getElementById("main-nav");
    if (nav) new MutationObserver(function () {
      kick();
      if (!ovVisible() && map.raf) { cancelAnimationFrame(map.raf); map.raf = 0; map.last = 0; }
    }).observe(nav, { attributes: true, attributeFilter: ["class"], subtree: true });
    document.addEventListener("click", function (e) {
      if (e.target.closest && e.target.closest('#sec-subtabs [data-sec-pane="timeline"]')) { tlLastLoad = 0; kick(); }
    });
    document.addEventListener("visibilitychange", kick);
    var gate = document.getElementById("login-gate");
    if (gate) new MutationObserver(kick).observe(gate, { attributes: true, attributeFilter: ["hidden"] });
    var rt = 0;
    window.addEventListener("resize", function () {
      clearTimeout(rt);
      rt = setTimeout(function () { if (map.card && ovVisible()) updateMap(); }, 150);
    });
    if (reduceMotion.addEventListener) reduceMotion.addEventListener("change", function () { if (map.card) updateMap(); });
    // Re-render on theme change so text measurement / colours stay right
    new MutationObserver(function () { map.layoutKey = ""; if (map.card && ovVisible()) updateMap(); })
      .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    kick();
    setTimeout(tick, 1500);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
