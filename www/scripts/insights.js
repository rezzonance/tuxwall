/* ============================================================================
   TuxWall — Router Insights (Overview). One tabbed early-warning panel that
   replaced the ratio donuts. Read-only: observes the /api/* responses the
   Overview already polls (via window.twApi from netmap.js) and keeps a small
   client-side history (1-min buckets, 24h, localStorage). Hand-written SVG.
   ========================================================================= */
(function () {
  "use strict";

  const root = document.getElementById("ov-insights");
  if (!root) return;

  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const reduceMotion = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };
  const MIN = 60000;

  /* ---------- formatting ---------- */
  const fmtPct = (v) => (v == null ? "—" : (v >= 10 || v === 0 ? Math.round(v) : v.toFixed(1)) + "%");
  const fmtNum = (n) => (n == null ? "—" : Math.round(n).toLocaleString());
  function fmtBytes(n) {
    n = n || 0;
    if (n < 1024) return Math.round(n) + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
    if (n < 1099511627776) return (n / 1073741824).toFixed(2) + " GB";
    return (n / 1099511627776).toFixed(2) + " TB";
  }
  // /api/bandwidth rx_bps / tx_bps are bits per second
  function fmtRate(b) {
    if (b == null) return "—";
    if (b >= 1e9) return (b / 1e9).toFixed(2) + " Gbps";
    if (b >= 1e6) return (b / 1e6).toFixed(1) + " Mbps";
    if (b >= 1e3) return (b / 1e3).toFixed(1) + " kbps";
    return Math.round(b) + " bps";
  }
  function fmtShort(v) {
    const t = (x, u) => (x >= 10 || x === Math.round(x) ? Math.round(x) : x.toFixed(1)) + u;
    return v >= 1e9 ? t(v / 1e9, "G") : v >= 1e6 ? t(v / 1e6, "M") : v >= 1e3 ? t(v / 1e3, "k") : t(v, "");
  }
  const fmtTime = (t) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  function fmtAgo(sec) {
    if (sec == null) return "—";
    if (sec < 60) return Math.round(sec) + "s ago";
    if (sec < 3600) return Math.round(sec / 60) + "m ago";
    if (sec < 86400) return Math.round(sec / 3600) + "h ago";
    return Math.round(sec / 86400) + "d ago";
  }
  function fmtUptime(s) {
    if (!s) return "—";
    const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
  }
  function flag(iso) {
    if (!iso || !/^[A-Za-z]{2}$/.test(iso)) return "🏳";
    return String.fromCodePoint(...iso.toUpperCase().split("").map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
  }

  /* ---------- metrics & thresholds ---------- */
  // load is stored as % of CPU cores (load1 / cores * 100)
  const TH = {
    cpu:  { w: 80, c: 95, max: 100, label: "CPU", color: "--h-blue", fmt: fmtPct },
    mem:  { w: 85, c: 95, max: 100, label: "Memory", color: "--h-violet", fmt: fmtPct },
    temp: { w: 75, c: 85, max: 105, label: "Temp", color: "--h-orange", fmt: (v) => (v == null ? "—" : Math.round(v) + "°C") },
    load: { w: 100, c: 200, max: 400, label: "Load", color: "--h-teal", fmt: (v) => (v == null ? "—" : Math.round(v) + "% of cores") },
    disk: { w: 85, c: 95, max: 100, label: "Disk", color: "--h-pink", fmt: fmtPct },
    swap: { w: 50, c: 80, max: 100, label: "Swap", color: "--h-slate", fmt: fmtPct },
  };
  const SYS_KEYS = ["cpu", "mem", "temp", "load", "disk", "swap"];
  const KEYS = ["cpu", "mem", "temp", "load", "disk", "swap", "rx", "tx", "atk", "qpm", "blk", "hit", "sf", "v6", "fwa", "fwb"];
  const level = (v, th) => (v == null ? 0 : v >= th.c ? 2 : v >= th.w ? 1 : 0);
  // Piecewise "headroom" scale: warn -> 70, crit -> 90, max -> 100.
  function norm(v, th) {
    if (v == null) return null;
    if (v <= th.w) return Math.max(0, v / th.w * 70);
    if (v <= th.c) return 70 + (v - th.w) / (th.c - th.w) * 20;
    return Math.min(100, 90 + (v - th.c) / Math.max(1, th.max - th.c) * 10);
  }

  /* ---------- history: in-memory fine samples + persisted minute buckets ---------- */
  const LS_HIST = "tw.insights.hist.v1";
  const FINE_KEEP = 65 * MIN, DAY = 24 * 60 * MIN, COMPACT_AFTER = 6 * 60 * MIN;
  const fine = {};               // key -> [[t, v], ...]
  const acc = {};                // key -> { m, sum, n }
  let rows = [];                 // [{ t, s (minutes), v: {key: val} }] sorted by t
  const bmap = new Map();        // t -> row
  let dirtyStore = false;

  (function load() {
    try {
      const j = JSON.parse(localStorage.getItem(LS_HIST) || "null");
      if (!j || j.v !== 1 || !Array.isArray(j.r)) return;
      const cutoff = Date.now() - DAY;
      j.r.forEach((r) => {
        const t = r[0] * MIN;
        if (t < cutoff) return;
        const row = { t, s: r[1] || 1, v: {} };
        j.k.forEach((k, i) => { if (r[i + 2] != null) row.v[k] = r[i + 2]; });
        rows.push(row); bmap.set(t, row);
      });
      rows.sort((a, b) => a.t - b.t);
    } catch (_) { }
  })();

  function saveHist() {
    if (!dirtyStore) return;
    dirtyStore = false;
    const now = Date.now();
    // Older than 6h: merge 1-minute rows into 5-minute rows; drop beyond 24h.
    const out = [], groups = new Map();
    rows.forEach((r) => {
      if (r.t < now - DAY) return;
      if (r.s === 1 && r.t < now - COMPACT_AFTER) {
        const g5 = Math.floor(r.t / (5 * MIN)) * 5 * MIN;
        let g = groups.get(g5);
        if (!g) { g = { t: g5, s: 5, sums: {}, ns: {} }; groups.set(g5, g); out.push(g); }
        KEYS.forEach((k) => { if (r.v[k] != null) { g.sums[k] = (g.sums[k] || 0) + r.v[k]; g.ns[k] = (g.ns[k] || 0) + 1; } });
      } else out.push(r);
    });
    rows = out.map((r) => {
      if (!r.sums) return r;
      const v = {};
      Object.keys(r.sums).forEach((k) => { v[k] = round1(r.sums[k] / r.ns[k]); });
      return { t: r.t, s: 5, v };
    }).sort((a, b) => a.t - b.t);
    // two partial 5-min groups for the same slot can appear only across a
    // compaction boundary; keep the first
    bmap.clear();
    rows = rows.filter((r) => (bmap.has(r.t) ? false : (bmap.set(r.t, r), true)));
    try {
      localStorage.setItem(LS_HIST, JSON.stringify({
        v: 1, k: KEYS,
        r: rows.map((r) => [r.t / MIN, r.s].concat(KEYS.map((k) => (r.v[k] == null ? null : r.v[k])))),
      }));
    } catch (_) { }
  }
  const round1 = (v) => Math.round(v * 10) / 10;

  function finalize(key) {
    const a = acc[key];
    if (!a || !a.n) return;
    let row = bmap.get(a.m);
    if (!row) {
      row = { t: a.m, s: 1, v: {} };
      bmap.set(a.m, row);
      if (rows.length && rows[rows.length - 1].t > a.m) { rows.push(row); rows.sort((x, y) => x.t - y.t); }
      else rows.push(row);
    }
    if (row.s === 1) row.v[key] = round1(a.sum / a.n);
    dirtyStore = true;
  }

  function add(key, t, v) {
    if (v == null || !isFinite(v)) return;
    const f = fine[key] || (fine[key] = []);
    if (f.length && t <= f[f.length - 1][0]) return;
    f.push([t, v]);
    if (f.length > 40 && f[0][0] < t - FINE_KEEP) {
      let i = 0; while (i < f.length && f[i][0] < t - FINE_KEEP) i++;
      f.splice(0, i);
    }
    const m = Math.floor(t / MIN) * MIN;
    const a = acc[key];
    if (!a || a.m !== m) { finalize(key); acc[key] = { m, sum: v, n: 1 }; }
    else { a.sum += v; a.n++; }
  }

  function seriesOf(key, range) {
    const now = Date.now(), t0 = now - range;
    const f = fine[key] || [];
    const out = [];
    const fStart = f.length ? f[0][0] : Infinity;
    let fineFrom;
    if (range <= 60 * MIN) fineFrom = Math.max(t0, Math.min(fStart, now));
    else {
      const a = acc[key];
      fineFrom = a ? a.m : now;
    }
    for (const r of rows) {
      const mid = r.t + r.s * MIN / 2;
      if (r.t + r.s * MIN < t0 || mid >= fineFrom) continue;
      const v = r.v[key];
      if (v != null) out.push([mid, v, r.s * MIN]);
    }
    for (const p of f) if (p[0] >= fineFrom && p[0] >= t0) out.push([p[0], p[1], 15000]);
    return out;
  }
  function oldest(keys) {
    let o = Infinity;
    keys.forEach((k) => {
      const f = fine[k]; if (f && f.length) o = Math.min(o, f[0][0]);
    });
    for (const r of rows) { if (keys.some((k) => r.v[k] != null)) { o = Math.min(o, r.t); break; } }
    return o;
  }
  function recentAvg(key, ms) {
    const f = fine[key] || [];
    const t0 = Date.now() - ms;
    let s = 0, n = 0;
    for (let i = f.length - 1; i >= 0 && f[i][0] >= t0; i--) { s += f[i][1]; n++; }
    return n ? s / n : null;
  }
  const last = (key) => { const f = fine[key]; return f && f.length ? f[f.length - 1][1] : null; };

  /* ---------- ingest observed API responses ---------- */
  const cur = { sys: null, bw: null, sec: null, dns: null, fw: null, tm: null, sur: null, surAt: 0 };
  let prevDns = null, prevFw = null, seeded = {};

  function wanName() {
    const w = cur.sys && cur.sys.wan && cur.sys.wan.ifname;
    if (w) return w;
    const ifs = (cur.bw && cur.bw.interfaces) || [];
    const best = ifs.filter((i) => !/^ifb/.test(i.name)).sort((a, b) => (b.rx_total || 0) - (a.rx_total || 0))[0];
    return best ? best.name : null;
  }

  function ingest(path) {
    const api = window.twApi;
    const d = api && api.data(path);
    if (!d) return;
    const now = Date.now();
    if (path === "/api/system") {
      cur.sys = d;
      if (!seeded.sys && Array.isArray(d.history)) {
        seeded.sys = 1;
        d.history.forEach((h) => { add("cpu", h[0] * 1000, h[1]); add("mem", h[0] * 1000, h[2]); });
      }
      const u = d.usage || {}, cores = (d.cpu || {}).cores || 1;
      add("cpu", now, u.cpu_pct);
      add("mem", now, u.mem_pct);
      add("temp", now, (d.cpu || {}).temp);
      add("load", now, d.load && d.load[0] != null ? d.load[0] / cores * 100 : null);
      add("disk", now, u.disk_pct);
      add("swap", now, u.swap_pct);
    } else if (path === "/api/bandwidth") {
      cur.bw = d;
      const wan = ((d.interfaces || []).filter((i) => i.name === wanName()))[0];
      if (wan) {
        if (!seeded.bw && Array.isArray(wan.history)) {
          seeded.bw = 1;
          wan.history.forEach((h, i) => { if (i % 3 === 0) { add("rx", h[0] * 1000, h[1]); add("tx", h[0] * 1000, h[2]); } });
        }
        add("rx", now, wan.rx_bps);
        add("tx", now, wan.tx_bps);
      }
    } else if (path === "/api/security") {
      cur.sec = d;
      const ser = d.series || [];
      if (!seeded.sec && ser.length > 6) {
        seeded.sec = 1;
        for (let i = 5; i < ser.length - 1; i++) {
          let s = 0; for (let j = i - 5; j <= i; j++) s += ser[j][1] || 0;
          add("atk", ser[i][0] * 1000 + 10000, s);
        }
      }
      add("atk", now, (d.stats || {}).hits_1m);
    } else if (path === "/api/dns") {
      if (!d.totals) return;
      cur.dns = d;
      const tot = d.totals;
      const sf = ((d.rcodes || []).filter((r) => r.label === "SERVFAIL")[0] || {}).count || 0;
      const snap = { t: now, q: tot.queries || 0, nx: tot.nxdomain || 0, h: tot.cachehits || 0, m: tot.cachemiss || 0, v6: tot.ipv6 || 0, sf };
      if (prevDns && snap.t - prevDns.t > 4000) {
        const dq = snap.q - prevDns.q;
        if (dq >= 0 && snap.nx >= prevDns.nx) {
          const dt = (snap.t - prevDns.t) / MIN;
          add("qpm", now, dq / dt);
          if (dq > 0) {
            add("blk", now, (snap.nx - prevDns.nx) / dq * 100);
            add("sf", now, Math.max(0, snap.sf - prevDns.sf) / dq * 100);
            add("v6", now, Math.max(0, snap.v6 - prevDns.v6) / dq * 100);
          }
          const dh = snap.h - prevDns.h, dm = snap.m - prevDns.m;
          if (dh + dm > 0) add("hit", now, dh / (dh + dm) * 100);
        }
      }
      if (!prevDns || snap.t - prevDns.t > 4000) prevDns = snap;
    } else if (path === SUR) {
      if (cur.sur === d) return;
      cur.sur = d; cur.surAt = Date.now();
    } else if (path === "/api/firewall") {
      cur.fw = d;
      // lifetime inbound counters (server-cached 10 s) -> per-minute rates
      const c = d.counters;
      if (c && c.ok !== false && c.at) {
        const snap = { at: c.at, a: c.allowed_packets || 0, b: c.blocked_packets || 0 };
        if (prevFw && snap.at > prevFw.at) {
          const da = snap.a - prevFw.a, db = snap.b - prevFw.b;
          if (da >= 0 && db >= 0) {
            const dt = (snap.at - prevFw.at) / 60;
            add("fwa", now, da / dt);
            add("fwb", now, db / dt);
          }
        }
        // counters went backwards (ufw reload / reboot): restart from here
        if (!prevFw || snap.at > prevFw.at) prevFw = snap;
      }
    } else return;
    schedule();
  }

  /* ---------- /api/traffic-monitor: not polled on the Overview; fetched
     only while the DNS tab is rendered, at most once a minute ---------- */
  let tmAt = 0;
  function ensureTm() {
    if (Date.now() - tmAt < MIN) return;
    tmAt = Date.now();
    const api = window.twApi;
    const p = api && api.get ? api.get("/api/traffic-monitor", MIN)
      : fetch("/api/traffic-monitor", { cache: "no-store", credentials: "same-origin" }).then((r) => (r.ok ? r.json() : null));
    p.then((d) => { if (d && Array.isArray(d.entries)) { cur.tm = d; if (st.tab === "dns") schedule(); } }, () => { });
  }
  function hostOf(ip) {
    const api = window.twApi;
    const l = api && api.data("/api/leases");
    const m = l && (l.leases || []).filter((x) => x.ip === ip)[0];
    return m && m.hostname && m.hostname !== "*" ? m.hostname : "";
  }

  /* ---------- /api/security/suricata: the Overview already polls it; the IDS
     tab tops it up through the shared cache at most once a minute ---------- */
  let surAt = 0;
  const SUR = "/api/security/suricata";
  function ensureSur() {
    if (Date.now() - surAt < MIN) return;
    surAt = Date.now();
    const api = window.twApi;
    const p = api && api.get ? api.get(SUR, MIN)
      : fetch(SUR, { cache: "no-store", credentials: "same-origin" }).then((r) => (r.ok ? r.json() : null));
    p.then((d) => { if (d && d.ok !== false) { if (cur.sur !== d) { cur.sur = d; cur.surAt = Date.now(); } if (st.tab === "ids") schedule(); } }, () => { });
  }
  const isPriv = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|f[cd][0-9a-f]{2}:|fe80:)/i.test(ip || "");
  // the router's own addresses (WAN + every interface) -> interface name
  function routerAddrs() {
    const s = cur.sys || {}, m = new Map(), w = s.wan || {};
    (s.interfaces || []).forEach((i) => (i.addrs || []).forEach((a) => { if (a.addr) m.set(a.addr, i.name); }));
    if (w.ipv4) m.set(w.ipv4, w.ifname || "WAN");
    (w.ipv6 || []).forEach((a) => m.set(a, w.ifname || "WAN"));
    return m;
  }
  function surStats(d) {
    const now = Date.now() / 1000, al = d.alerts || [], hr = d.hourly || [];
    const recent = al.filter((a) => a.ts >= now - 3600);
    let lh = recent.length, approx = false;
    // alerts holds the newest 30 only; if all of them fall inside the hour, estimate from the hourly buckets
    if (al.length >= 30 && recent.length === al.length && hr.length) {
      const c = hr[hr.length - 1], p = hr[hr.length - 2] || { count: 0 };
      const f = Math.min(1, Math.max(0, (now - c.t) / 3600));
      lh = Math.max(lh, Math.round(c.count + p.count * (1 - f))); approx = true;
    }
    const avg = (d.count_24h || 0) / 24;
    const alHigh = al.filter((a) => a.severity === "HIGH");
    const high = Math.max(alHigh.length,
      (d.top || []).filter((t) => t.severity === "HIGH").reduce((n, t) => n + t.count, 0),
      ...(d.talkers || []).map((t) => t.high || 0));
    const highHour = alHigh.some((a) => a.ts >= now - 3600) || (d.top || []).some((t) => t.severity === "HIGH" && t.last_ts >= now - 3600);
    const lanSrc = new Set(alHigh.filter((a) => isPriv(a.src)).map((a) => a.src));
    (d.talkers || []).forEach((t) => { if (t.local && t.high > 0 && !t.as_dst) lanSrc.add(t.ip); });
    return { lh, approx, avg, high, highHour, lanSrc: Array.from(lanSrc) };
  }

  /* ---------- status (tab dots + header summary) ---------- */
  function computeIssues() {
    const I = { system: [], dns: [], threats: [], ids: [], traffic: [] };
    if (cur.sur && cur.sur.enabled !== false) {
      const s = surStats(cur.sur);
      if (s.highHour) I.ids.push({ lv: 2, msg: "IDS: high-severity alert in the last hour" });
      if (s.lanSrc.length) I.ids.push({ lv: 2, msg: `IDS: LAN host ${hostOf(s.lanSrc[0]) || s.lanSrc[0]} raised a high-severity alert` + (s.lanSrc.length > 1 ? ` (+${s.lanSrc.length - 1})` : "") });
      if (s.lh >= Math.max(10, s.avg * 3)) I.ids.push({ lv: 1, msg: `IDS alert burst: ${fmtNum(s.lh)} in the last hour (${(s.lh / Math.max(s.avg, 0.1)).toFixed(1)}× the 24 h average)` });
      if (s.high && !s.highHour && !s.lanSrc.length) I.ids.push({ lv: 1, msg: `IDS: ${fmtNum(s.high)} high-severity alert${s.high === 1 ? "" : "s"} in 24 h` });
    }
    if (cur.sys) {
      SYS_KEYS.forEach((k) => {
        const th = TH[k];
        // CPU flaps on single samples; judge it on the last minute
        const v = k === "cpu" ? (recentAvg("cpu", MIN) != null ? recentAvg("cpu", MIN) : last("cpu")) : last(k);
        const lv = level(v, th);
        if (lv) I.system.push({ lv, msg: `${th.label} at ${th.fmt(v)} — ${lv === 2 ? "critical" : "warning"}` });
      });
    }
    if (cur.dns) {
      if (cur.dns.ok === false) I.dns.push({ lv: 2, msg: "DNS resolver not responding" });
      const sf = recentAvg("sf", 5 * MIN), q = recentAvg("qpm", 5 * MIN);
      if (sf != null && q > 5 && sf >= 5) I.dns.push({ lv: sf >= 15 ? 2 : 1, msg: `DNS SERVFAIL at ${fmtPct(sf)} of queries` });
    }
    if (cur.sec) {
      const st = cur.sec.stats || {};
      const now1 = st.hits_1m || 0, avg = (st.hits_10m || 0) / 10;
      if (now1 >= Math.max(120, avg * 8)) I.threats.push({ lv: 2, msg: `Attack burst: ${now1}/min` });
      else if (now1 >= Math.max(30, avg * 4)) I.threats.push({ lv: 1, msg: `Attack rate up: ${now1}/min` });
    }
    if (cur.sys) {
      const wan = cur.sys.wan || {}, lat = cur.sys.latency || {};
      if (wan.ifname && wan.state && wan.state !== "UP") I.traffic.push({ lv: 2, msg: `WAN ${wan.ifname} is ${wan.state}` });
      if (!wan.ifname) I.traffic.push({ lv: 2, msg: "No default route (WAN down?)" });
      if (lat.loss_1h_pct >= 2) I.traffic.push({ lv: lat.loss_1h_pct >= 10 ? 2 : 1, msg: `WAN packet loss ${lat.loss_1h_pct}% (1h)` });
      if (lat.baseline_ms > 0 && lat.current_ms > Math.max(lat.baseline_ms * 3, lat.baseline_ms + 30))
        I.traffic.push({ lv: 1, msg: `WAN latency ${Math.round(lat.current_ms)} ms (${(lat.current_ms / lat.baseline_ms).toFixed(1)}× baseline)` });
    }
    Object.keys(I).forEach((k) => I[k].sort((a, b) => b.lv - a.lv));
    return I;
  }

  /* ---------- UI shell ---------- */
  const TABS = [
    { id: "dns", label: "DNS", icon: '<path d="M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>' },
    { id: "threats", label: "Threats", icon: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9c-4.6-.7-8-4.5-8-9V6z"/><path d="M12 8v5M12 16v.01"/>' },
    { id: "ids", label: "IDS · Suricata", icon: '<circle cx="11" cy="11" r="6.5"/><path d="M20.5 20.5l-4.9-4.9M8.5 11h1.2l1-2l1.6 4l1-2h1.2"/>' },
    { id: "system", label: "System health", icon: '<path d="M3 12h4l2-5l4 10l2-5h6"/>' },
    { id: "traffic", label: "Traffic & Firewall", icon: '<path d="M7 4v16M7 20l-3-3M7 20l3-3M17 20V4M17 4l-3 3M17 4l3 3"/>' },
  ];
  const RANGES = [["15m", 15 * MIN], ["1h", 60 * MIN], ["6h", 360 * MIN], ["24h", 1440 * MIN]];
  const ls = (k, d) => { try { return localStorage.getItem(k) || d; } catch (_) { return d; } };
  const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch (_) { } };
  const st = {
    tab: TABS.some((t) => t.id === ls("tw.insights.tab")) ? ls("tw.insights.tab") : "system",
    range: RANGES.some((r) => r[0] === ls("tw.insights.range")) ? ls("tw.insights.range") : "1h",
    off: new Set(ls("tw.insights.off", "").split(",").filter(Boolean)),
    built: null, dirty: true, inView: true, timer: 0,
  };
  const rangeMs = () => RANGES.filter((r) => r[0] === st.range)[0][1];

  const body = $(".ins-body", root);
  const summary = $("#ins-summary", root);
  body.innerHTML = `
    <div class="ins-toolbar">
      <div class="ins-tabs" role="tablist" aria-label="Router insights">
        ${TABS.map((t) => `<button type="button" class="ins-tab" role="tab" id="ins-tab-${t.id}" data-tab="${t.id}"
            aria-controls="ins-panel" aria-selected="false" tabindex="-1"><span class="ins-dot" data-lv="0"></span><svg viewBox="0 0 24 24" aria-hidden="true">${t.icon}</svg><span>${t.label}</span></button>`).join("")}
      </div>
      <div class="ins-tools">
        <span class="ins-note" aria-live="polite"></span>
        <div class="seg-btns ins-range" role="radiogroup" aria-label="Time range">
          ${RANGES.map((r) => `<button type="button" class="seg-btn" role="radio" data-range="${r[0]}" aria-checked="false">${r[0]}</button>`).join("")}
        </div>
      </div>
    </div>
    <div class="ins-panel" id="ins-panel" role="tabpanel" tabindex="0"></div>
    <div class="ins-tip" role="tooltip" hidden></div>`;
  const panel = $(".ins-panel", root);
  const note = $(".ins-note", root);
  const tip = $(".ins-tip", root);

  function syncChrome() {
    $$(".ins-tab", root).forEach((b) => {
      const on = b.dataset.tab === st.tab;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    });
    panel.setAttribute("aria-labelledby", "ins-tab-" + st.tab);
    $(".ins-range", root).hidden = !!VIEWS[st.tab].noHist;
    $$(".ins-range .seg-btn", root).forEach((b) => {
      const on = b.dataset.range === st.range;
      b.classList.toggle("active", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
  }
  function selectTab(id, focus) {
    if (id === st.tab && st.built === id) return;
    st.tab = id; lsSet("tw.insights.tab", id);
    syncChrome();
    if (focus) { const b = $("#ins-tab-" + id, root); if (b) { b.focus(); b.scrollIntoView({ block: "nearest", inline: "nearest" }); } }
    st.dirty = true; render(true);
  }
  $(".ins-tabs", root).addEventListener("click", (e) => {
    const b = e.target.closest(".ins-tab"); if (b) selectTab(b.dataset.tab);
  });
  $(".ins-tabs", root).addEventListener("keydown", (e) => {
    const ids = TABS.map((t) => t.id);
    const ft = e.target.closest(".ins-tab");
    let i = ids.indexOf(ft ? ft.dataset.tab : st.tab);
    if (e.key === "ArrowRight" || e.key === "ArrowDown") i = (i + 1) % ids.length;
    else if (e.key === "ArrowLeft" || e.key === "ArrowUp") i = (i - 1 + ids.length) % ids.length;
    else if (e.key === "Home") i = 0;
    else if (e.key === "End") i = ids.length - 1;
    else return;
    e.preventDefault(); selectTab(ids[i], true);
  });
  $(".ins-range", root).addEventListener("click", (e) => {
    const b = e.target.closest(".seg-btn"); if (!b || b.dataset.range === st.range) return;
    st.range = b.dataset.range; lsSet("tw.insights.range", st.range);
    syncChrome(); st.dirty = true; render(true);
  });
  $(".ins-range", root).addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const ids = RANGES.map((r) => r[0]);
    let i = ids.indexOf(st.range) + (e.key === "ArrowRight" ? 1 : -1);
    i = (i + ids.length) % ids.length;
    e.preventDefault();
    const b = $(`.seg-btn[data-range="${ids[i]}"]`, root); b.click(); b.focus();
  });
  // legend toggles + clickable bar rows (delegated)
  panel.addEventListener("click", (e) => {
    const lg = e.target.closest(".ins-lg");
    if (lg) {
      const k = lg.dataset.key;
      if (st.off.has(k)) st.off.delete(k); else st.off.add(k);
      lsSet("tw.insights.off", Array.from(st.off).join(","));
      st.dirty = true; render(false);
      return;
    }
    const tk = e.target.closest(".ids-row[data-ip]");
    if (tk) { openSensors(tk.dataset.ip, tk.dataset.sev); return; }
    const go = e.target.closest("[data-go]");
    if (go) {
      const [v, s] = go.dataset.go.split("/");
      if (window.twGo) window.twGo(v, s, { push: true });
      else { const n = $(`.nav-item[data-view="${v}"]`); if (n) n.click(); }
    }
  });
  // Security → Sensors, switch its severity filter (client-side) and highlight the host's rows
  function openSensors(ip, sev) {
    const p = window.twGo ? window.twGo("security", "sensors", { push: true }) : null;
    if (!p) { const n = $('.nav-item[data-view="security"]'); if (n) n.click(); const t = $('.fw-subtab[data-sec-pane="sensors"]'); if (t) t.click(); }
    let n = 0, switched = false;
    const step = () => {
      const tb = document.getElementById("sec-suricata-body");
      if (!tb || !tb.children.length) { if (++n < 20) setTimeout(step, 250); return; }
      const b = sev && $(`#sec-suricata-tabs .seg-btn[data-sev="${sev}"]`);
      if (!switched && b && !b.classList.contains("active")) { switched = true; b.click(); setTimeout(step, 120); return; }
      const hits = $$("tr", tb).filter((tr) => $$("td", tr).some((td) => td.textContent.split(/[\s:]+/).indexOf(ip) >= 0));
      hits.forEach((tr) => tr.classList.add("ids-hit"));
      if (hits[0]) hits[0].scrollIntoView({ block: "center", behavior: reduceMotion.matches ? "auto" : "smooth" });
      setTimeout(() => hits.forEach((tr) => tr.classList.remove("ids-hit")), 8000);
    };
    setTimeout(step, 300);
  }
  // talker tooltips (hover + keyboard focus)
  let tipRow = null;
  function showRowTip(row) {
    const d = cur.sur, t = d && (d.talkers || []).filter((x) => x.ip === row.dataset.ip)[0];
    if (!t) return;
    tipRow = row;
    const name = $(".ids-nm b", row).textContent, kind = $(".ids-tag", row).textContent;
    const sevs = [["High", t.high, "var(--ins-crit)"], ["Medium", t.medium, "var(--ins-warn)"], ["Low", t.low, "var(--ids-low)"]].filter((x) => x[1]);
    tip.innerHTML = `<div class="ins-tip-t">${esc(name)}${name !== t.ip ? ` <em>${esc(t.ip)}</em>` : ""}</div>
      <div class="ids-tip-k" data-kind="${row.dataset.kind}">${esc(kind)} · ${fmtNum(t.count)} alerts · ${fmtNum(t.peers)} peer${t.peers === 1 ? "" : "s"}</div>
      ${(t.sigs || []).map((g) => `<div class="ids-tip-sig"><span>${esc(g.sig)}</span><b>${fmtNum(g.count)}</b></div>`).join("")}
      <div class="ids-tip-sep"></div>
      <div class="ins-tip-r" style="--c:var(--h-violet)"><i></i>As source ↑<b>${fmtNum(t.as_src)}</b></div>
      <div class="ins-tip-r" style="--c:var(--h-teal)"><i></i>As destination ↓<b>${fmtNum(t.as_dst)}</b></div>
      ${sevs.map((x) => `<div class="ins-tip-r" style="--c:${x[2]}"><i></i>${x[0]}<b>${fmtNum(x[1])}</b></div>`).join("")}
      <div class="ids-tip-f">${row.dataset.kind === "lan" && t.as_src >= t.as_dst ? "Alerts originate from this device — check it for malware or noisy apps. " : ""}Click for Security › Sensors</div>`;
    tip.classList.add("ids-tip");
    tip.hidden = false;
    const rb = root.getBoundingClientRect(), b = row.getBoundingClientRect();
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    const left = Math.max(8, Math.min(b.left - rb.left + Math.min(60, b.width / 4), rb.width - tw - 8));
    let top = b.bottom - rb.top + 6;
    if (top + th > rb.height - 4) top = b.top - rb.top - th - 6;
    tip.style.transform = `translate(${Math.round(left)}px, ${Math.round(Math.max(4, top))}px)`;
  }
  function hideRowTip() { if (!tipRow) return; tipRow = null; tip.hidden = true; tip.classList.remove("ids-tip"); }
  panel.addEventListener("pointerover", (e) => {
    const r = e.target.closest(".ids-row");
    if (r && r !== tipRow && e.pointerType !== "touch") showRowTip(r);
  });
  panel.addEventListener("pointerout", (e) => {
    if (tipRow && !(e.relatedTarget && tipRow.contains(e.relatedTarget))) hideRowTip();
  });
  panel.addEventListener("focusin", (e) => { const r = e.target.closest(".ids-row"); if (r) showRowTip(r); });
  panel.addEventListener("focusout", (e) => { if (e.target.closest(".ids-row")) hideRowTip(); });
  panel.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && tipRow) { hideRowTip(); return; }
    const go = e.target.closest("[data-go]");
    if (go && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); go.click(); }
  });

  /* ---------- building blocks ---------- */
  const col = (v) => `var(${v})`;
  function kpi(id, label) {
    return `<div class="ins-kpi" data-kpi="${id}"><div class="ins-kpi-label">${label}</div><div class="ins-kpi-val">—</div><div class="ins-kpi-sub"></div></div>`;
  }
  function setKpi(id, val, sub, lv, extra) {
    const el = $(`[data-kpi="${id}"]`, panel); if (!el) return;
    el.dataset.lv = lv || 0;
    const v = $(".ins-kpi-val", el), s = $(".ins-kpi-sub", el);
    if (v.textContent !== val) v.textContent = val;
    if (extra != null) s.innerHTML = extra; else if (s.textContent !== (sub || "")) s.textContent = sub || "";
  }
  // gauge-line: zone track + needle
  // inv: low values are bad (e.g. cache hit rate) — zones run red→amber→green
  function gauge(v, th, inv) {
    const p = (x) => Math.max(0, Math.min(100, x / th.max * 100));
    const lv = inv ? (v == null ? 0 : v <= th.c ? 2 : v <= th.w ? 1 : 0) : level(v, th);
    return `<div class="ins-gauge${inv ? " inv" : ""}" style="--w:${p(th.w)}%;--c:${p(th.c)}%"><i style="left:${p(v || 0)}%" data-lv="${lv}"></i></div>`;
  }
  // 100% stacked bar
  function stack(parts, fmt) {
    const tot = parts.reduce((n, p) => n + (p.v || 0), 0) || 1;
    return `<div class="ins-stack">${parts.map((p) => `<span style="flex-basis:${(p.v || 0) / tot * 100}%;--c:${p.c}" title="${esc(p.l)}: ${esc(fmt(p.v))} (${fmtPct((p.v || 0) / tot * 100)})"></span>`).join("")}</div>
      <div class="ins-stack-lg">${parts.map((p) => `<span style="--c:${p.c}"><i></i>${esc(p.l)} <b>${fmtPct((p.v || 0) / tot * 100)}</b> <em>${esc(fmt(p.v))}</em></span>`).join("")}</div>`;
  }
  // ranked horizontal bars; patches in place so widths animate
  function bars(el, items, opts) {
    if (!el) return;
    opts = opts || {};
    const max = Math.max(1, ...items.map((i) => i.v || 0));
    const tot = opts.total || items.reduce((n, i) => n + (i.v || 0), 0) || 1;
    const sig = items.map((i) => i.k).join("|");
    if (!items.length) { el.innerHTML = `<div class="ins-empty">${esc(opts.empty || "No data yet")}</div>`; el.dataset.sig = ""; return; }
    if (el.dataset.sig !== sig) {
      el.dataset.sig = sig;
      el.innerHTML = items.map((i) => `<div class="ins-bar${i.go ? " is-link" : ""}"${i.go ? ` data-go="${i.go}" role="link" tabindex="0"` : ""} title="${esc(i.title || "")}">
          <span class="ins-bar-l">${i.pre ? `<span class="ins-flag" aria-hidden="true">${i.pre}</span>` : ""}<span class="ins-bar-name">${esc(i.l)}</span></span>
          <span class="ins-bar-t"><span class="ins-bar-f" style="width:0;--c:${i.c || "var(--pc)"}"></span></span>
          <span class="ins-bar-v"></span><span class="ins-bar-p"></span></div>`).join("");
      el.offsetWidth; // commit 0 widths so the fill animates in
    }
    const rowsEl = el.children;
    items.forEach((i, n) => {
      const r = rowsEl[n];
      r.title = i.title || "";
      r.querySelector(".ins-bar-f").style.width = ((i.v || 0) / max * 100).toFixed(2) + "%";
      const vt = opts.fmt ? opts.fmt(i.v) : fmtNum(i.v);
      const v = r.querySelector(".ins-bar-v"); if (v.textContent !== vt) v.textContent = vt;
      const pt = opts.noPct ? "" : fmtPct((i.v || 0) / tot * 100);
      const p = r.querySelector(".ins-bar-p"); if (p.textContent !== pt) p.textContent = pt;
    });
  }

  /* ---------- SVG line chart with crosshair tooltip ---------- */
  let uid = 0;
  const widths = new WeakMap();
  const ro = window.ResizeObserver ? new ResizeObserver((ents) => {
    let changed = false;
    ents.forEach((e) => {
      const w = Math.round(e.contentRect.width);
      if (w && widths.get(e.target) !== w) { widths.set(e.target, w); changed = true; }
    });
    if (changed) { st.dirty = true; schedule(); }
  }) : null;

  function niceMax(v) {
    if (!(v > 0)) return 4;
    const p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
  }
  function thin(pts, maxN) {
    if (pts.length <= maxN) return pts;
    const k = Math.ceil(pts.length / maxN), out = [];
    for (let i = 0; i < pts.length; i += k) {
      let t = 0, v = 0, raw = 0, hasRaw = false, step = 0, n = 0;
      for (let j = i; j < Math.min(pts.length, i + k); j++) {
        t += pts[j][0]; v += pts[j][1]; step = Math.max(step, pts[j][2] || 0); n++;
        if (pts[j][3] != null) { raw += pts[j][3]; hasRaw = true; }
      }
      out.push([t / n, v / n, step * k, hasRaw ? raw / n : undefined]);
    }
    return out;
  }

  // cfg: { series:[{k,label,color,fmt,pts:[[t,v,step,raw]]}], h, yMax?, yFmt, bands?, area?, yLabels? }
  function chart(slot, cfg) {
    if (!slot) return;
    if (!slot.__ro && ro) { slot.__ro = 1; widths.set(slot, slot.clientWidth); ro.observe(slot); }
    const W = widths.get(slot) || slot.clientWidth || 600;
    const H = cfg.h || 180, R = 12, T = 10, B = 22;
    const vis = cfg.series.filter((s) => !st.off.has(s.k));
    vis.forEach((s) => { s.draw = thin(s.pts, Math.max(40, Math.floor((W - 60) / 2))); });
    const dataMax = Math.max(0, ...vis.map((s) => Math.max(0, ...s.draw.map((p) => p[1]))));
    const yMax = cfg.yMax || niceMax(dataMax * 1.12);
    const yFmt = cfg.yFmt || fmtShort;
    const ticks = cfg.yLabels || [0, 1, 2, 3, 4].map((i) => [yMax * i / 4, yFmt(yMax * i / 4)]);
    const L = Math.round(14 + Math.max(...ticks.map((t) => String(t[1]).length)) * 6.4);
    const pw = Math.max(10, W - L - R), ph = H - T - B;
    const t1 = Date.now(), t0 = t1 - rangeMs();
    const X = (t) => L + (t - t0) / (t1 - t0) * pw;
    const Y = (v) => T + ph - Math.max(0, Math.min(1, v / yMax)) * ph;
    const id = slot.__id || (slot.__id = "insc" + (++uid));
    let svg = `<svg class="ins-svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${esc(cfg.aria || "")}"><defs>`;
    vis.forEach((s, i) => {
      svg += `<linearGradient id="${id}g${i}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" style="stop-color:${s.color};stop-opacity:.32"/><stop offset="1" style="stop-color:${s.color};stop-opacity:0"/></linearGradient>`;
    });
    svg += `</defs>`;
    (cfg.bands || []).forEach((b) => {
      svg += `<rect class="ins-band ins-band-${b.cls}" x="${L}" y="${Y(b.y1)}" width="${pw}" height="${Math.max(0, Y(b.y0) - Y(b.y1))}"/>`;
      svg += `<line class="ins-band-line ins-band-${b.cls}" x1="${L}" x2="${L + pw}" y1="${Y(b.y0)}" y2="${Y(b.y0)}"/>`;
      svg += `<text class="ins-band-tx ins-band-${b.cls}" x="${L + pw - 4}" y="${Y(b.y0) - 4}" text-anchor="end">${b.label}</text>`;
    });
    ticks.forEach((tk) => {
      const y = Y(tk[0]);
      if (!cfg.yLabels || !tk[0]) svg += `<line class="ins-gridl" x1="${L}" x2="${L + pw}" y1="${y}" y2="${y}"/>`;
      svg += `<text class="ins-ax" x="${L - 6}" y="${y + 3}" text-anchor="end">${esc(tk[1])}</text>`;
    });
    const nT = Math.max(2, Math.min(6, Math.floor(pw / 110)));
    for (let i = 0; i <= nT; i++) {
      const t = t0 + (t1 - t0) * i / nT;
      svg += `<text class="ins-ax" x="${X(t)}" y="${H - 6}" text-anchor="${i === 0 ? "start" : i === nT ? "end" : "middle"}">${fmtTime(t)}</text>`;
    }
    vis.forEach((s, i) => {
      let d = "", a = "", seg = [];
      const flush = () => {
        if (!seg.length) return;
        d += seg.map((p, j) => (j ? "L" : "M") + X(p[0]).toFixed(1) + " " + Y(p[1]).toFixed(1)).join("");
        if (cfg.area && seg.length > 1) a += "M" + X(seg[0][0]).toFixed(1) + " " + Y(0) + seg.map((p) => "L" + X(p[0]).toFixed(1) + " " + Y(p[1]).toFixed(1)).join("") + "L" + X(seg[seg.length - 1][0]).toFixed(1) + " " + Y(0) + "Z";
        seg = [];
      };
      s.draw.forEach((p, j) => {
        const prev = s.draw[j - 1];
        if (prev && p[0] - prev[0] > 3.5 * Math.max(p[2] || 0, prev[2] || 0, 15000)) flush();
        seg.push(p);
      });
      flush();
      if (a) svg += `<path class="ins-area" d="${a}" fill="url(#${id}g${i})"/>`;
      if (d) svg += `<path class="ins-line" pathLength="1" d="${d}" style="stroke:${s.color}"/>`;
      const lp = s.draw[s.draw.length - 1];
      if (lp && t1 - lp[0] < 3 * MIN) svg += `<circle class="ins-last" cx="${X(lp[0]).toFixed(1)}" cy="${Y(lp[1]).toFixed(1)}" r="3" style="fill:${s.color}"/>`;
    });
    if (!vis.some((s) => s.draw.length)) svg += `<text class="ins-ax ins-nodata" x="${L + pw / 2}" y="${T + ph / 2}" text-anchor="middle">${cfg.series.length && !vis.length ? "All series hidden — use the legend" : "Collecting samples…"}</text>`;
    svg += `<g class="ins-cross" style="display:none"><line class="ins-cross-l" y1="${T}" y2="${T + ph}"/>${vis.map((s) => `<circle r="4" style="fill:${s.color}"/>`).join("")}</g></svg>`;
    slot.innerHTML = svg;
    slot.__c = { vis, X, Y, t0, t1, L, pw, cfg };
    if (!slot.__hover) bindHover(slot);
    else if (slot.__ht != null) slot.__show(slot.__ht); // keep the tooltip through live updates
  }
  function legend(el, series) {
    if (!el) return;
    const html = series.map((s) => `<button type="button" class="ins-lg" role="switch" data-key="${s.k}" aria-checked="${!st.off.has(s.k)}" style="--c:${s.color}"><i></i>${esc(s.label)}${s.now != null ? ` <b>${esc(s.now)}</b>` : ""}</button>`).join("");
    if (el.__h !== html) { el.__h = html; el.innerHTML = html; }
  }
  // 24 hourly bars (oldest → newest) with an average line and hover/keyboard tooltip
  function hourChart(slot, hourly, avg) {
    if (!slot) return;
    if (!slot.__ro && ro) { slot.__ro = 1; widths.set(slot, slot.clientWidth); ro.observe(slot); }
    const W = widths.get(slot) || slot.clientWidth || 400, H = W < 500 ? 150 : 200, T = 10, B = 22;
    const key = W + "|" + hourly.map((h) => h.t + ":" + h.count).join(",");
    if (slot.__key === key) return;
    slot.__key = key;
    const mx = niceMax(Math.max(1, ...hourly.map((h) => h.count)) * 1.1);
    const L = Math.round(14 + fmtShort(mx).length * 6.4), R = 6, pw = Math.max(10, W - L - R), ph = H - T - B;
    const n = Math.max(1, hourly.length), bw = pw / n, Y = (v) => T + ph - Math.min(1, v / mx) * ph;
    const burst = Math.max(10, avg * 3);
    let svg = `<svg class="ins-svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Suricata alerts per hour, last 24 hours">`;
    [0, mx / 2, mx].forEach((v) => { svg += `<line class="ins-gridl" x1="${L}" x2="${L + pw}" y1="${Y(v)}" y2="${Y(v)}"/><text class="ins-ax" x="${L - 6}" y="${Y(v) + 3}" text-anchor="end">${fmtShort(v)}</text>`; });
    hourly.forEach((h, i) => {
      const y = Y(h.count), x = L + i * bw + Math.min(2, bw * 0.15);
      svg += `<rect class="ids-hbar${h.count >= burst ? " burst" : ""}${i === n - 1 ? " cur" : ""}" data-i="${i}" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${Math.max(1, bw - 2 * Math.min(2, bw * 0.15)).toFixed(1)}" height="${Math.max(h.count ? 1.5 : 0, T + ph - y).toFixed(1)}" rx="2"/>`;
      if (i % 6 === 0 || i === n - 1) svg += `<text class="ins-ax" x="${(L + i * bw + bw / 2).toFixed(1)}" y="${H - 6}" text-anchor="${i === n - 1 ? "end" : i === 0 ? "start" : "middle"}">${i === n - 1 ? "now" : fmtTime(h.t * 1000)}</text>`;
    });
    if (avg > 0) svg += `<line class="ids-avg" x1="${L}" x2="${L + pw}" y1="${Y(avg).toFixed(1)}" y2="${Y(avg).toFixed(1)}"/><text class="ins-ax ids-avg-tx" x="${L + 4}" y="${(Y(avg) - 4).toFixed(1)}">avg ${avg >= 10 ? Math.round(avg) : avg.toFixed(1)}</text>`;
    if (!hourly.length) svg += `<text class="ins-ax ins-nodata" x="${L + pw / 2}" y="${T + ph / 2}" text-anchor="middle">No data</text>`;
    slot.innerHTML = svg + "</svg>";
    slot.__hc = { hourly, avg, L, bw, n };
    if (!slot.__hover) {
      slot.__hover = 1; slot.tabIndex = 0;
      let cur = null;
      const show = (i) => {
        const c = slot.__hc; if (!c || !c.hourly.length) return;
        i = Math.max(0, Math.min(c.n - 1, i)); cur = i;
        const h = c.hourly[i];
        $$(".ids-hbar", slot).forEach((r) => r.classList.toggle("hot", +r.dataset.i === i));
        const d0 = new Date(h.t * 1000);
        tip.classList.remove("ids-tip");
        tip.innerHTML = `<div class="ins-tip-t">${d0.toLocaleDateString([], { month: "short", day: "numeric" })} · ${fmtTime(h.t * 1000)}–${fmtTime(h.t * 1000 + 3600000)}${i === c.n - 1 ? " <em>so far</em>" : ""}</div>
          <div class="ins-tip-r" style="--c:var(--accent)"><i></i>Alerts<b>${fmtNum(h.count)}</b></div>
          ${c.avg > 0 ? `<div class="ins-tip-r" style="--c:var(--muted)"><i></i>vs 24 h avg<b>${(h.count / c.avg).toFixed(1)}×</b></div>` : ""}`;
        tip.hidden = false;
        const rb = root.getBoundingClientRect(), sb = slot.getBoundingClientRect();
        const sc = sb.width / (widths.get(slot) || sb.width);
        const x = sb.left - rb.left + (c.L + (i + 0.5) * c.bw) * sc;
        const tw = tip.offsetWidth;
        let left = x + 12; if (left + tw > rb.width - 8) left = x - tw - 12;
        tip.style.transform = `translate(${Math.round(Math.max(8, left))}px, ${Math.round(sb.top - rb.top + 8)}px)`;
      };
      const hide = () => { cur = null; tip.hidden = true; $$(".ids-hbar.hot", slot).forEach((r) => r.classList.remove("hot")); };
      slot.addEventListener("pointermove", (e) => {
        const c = slot.__hc; if (!c) return;
        const sb = slot.getBoundingClientRect();
        const x = (e.clientX - sb.left) * ((widths.get(slot) || sb.width) / sb.width);
        if (x < c.L || x > c.L + c.n * c.bw) return hide();
        const i = Math.floor((x - c.L) / c.bw); if (i !== cur) show(i);
      });
      slot.addEventListener("pointerleave", hide);
      slot.addEventListener("blur", hide);
      slot.addEventListener("keydown", (e) => {
        const c = slot.__hc; if (!c) return;
        if (e.key === "Escape") return hide();
        if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
        e.preventDefault();
        show(cur == null ? c.n - 1 : cur + (e.key === "ArrowRight" ? 1 : -1));
      });
    }
  }
  function nearest(pts, t) {
    let lo = 0, hi = pts.length - 1;
    if (hi < 0) return null;
    while (hi - lo > 1) { const m = (lo + hi) >> 1; if (pts[m][0] < t) lo = m; else hi = m; }
    return Math.abs(pts[lo][0] - t) <= Math.abs(pts[hi][0] - t) ? pts[lo] : pts[hi];
  }
  function bindHover(slot) {
    slot.__hover = 1;
    slot.tabIndex = 0;
    let kt = null;
    const show = (t) => {
      const c = slot.__c; if (!c || !c.vis.length) return hide();
      const g = slot.querySelector(".ins-cross"); if (!g) return;
      const tolerance = (c.t1 - c.t0) / 25;
      const hits = c.vis.map((s) => { const p = nearest(s.draw, t); return p && Math.abs(p[0] - t) <= Math.max(tolerance, (p[2] || 0)) ? p : null; });
      const ref = hits.filter(Boolean)[0];
      if (!ref) return hide();
      const x = c.X(ref[0]);
      g.style.display = "";
      const ln = g.querySelector("line"); ln.setAttribute("x1", x); ln.setAttribute("x2", x);
      g.querySelectorAll("circle").forEach((ci, i) => {
        const p = hits[i];
        if (p) { ci.setAttribute("cx", c.X(p[0])); ci.setAttribute("cy", c.Y(p[1])); ci.style.display = ""; }
        else ci.style.display = "none";
      });
      const span = ref[2] > 20000 ? ` <em>${Math.round(ref[2] / MIN)}-min avg</em>` : "";
      tip.innerHTML = `<div class="ins-tip-t">${new Date(ref[0]).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: ref[2] > 20000 ? undefined : "2-digit" })}${span}</div>` +
        c.vis.map((s, i) => hits[i] ? `<div class="ins-tip-r" style="--c:${s.color}"><i></i>${esc(s.label)}<b>${esc(s.fmt(hits[i][3] != null ? hits[i][3] : hits[i][1]))}</b></div>` : "").join("");
      tip.hidden = false;
      const rb = root.getBoundingClientRect(), sb = slot.getBoundingClientRect();
      const tw = tip.offsetWidth, th = tip.offsetHeight;
      let left = sb.left - rb.left + x + 14;
      if (left + tw > rb.width - 8) left = sb.left - rb.left + x - tw - 14;
      const top = Math.max(4, sb.top - rb.top + 8);
      tip.style.transform = `translate(${Math.round(Math.max(8, left))}px, ${Math.round(top + (th > 120 ? 0 : 6))}px)`;
      kt = ref[0];
      slot.__ht = t;
    };
    const hide = () => { tip.hidden = true; const g = slot.querySelector(".ins-cross"); if (g) g.style.display = "none"; kt = null; slot.__ht = null; };
    slot.addEventListener("pointermove", (e) => {
      const c = slot.__c; if (!c) return;
      const sb = slot.getBoundingClientRect();
      const x = (e.clientX - sb.left) * ((widths.get(slot) || sb.width) / sb.width);
      if (x < c.L - 4 || x > c.L + c.pw + 4) return hide();
      show(c.t0 + (x - c.L) / c.pw * (c.t1 - c.t0));
    });
    slot.addEventListener("pointerleave", hide);
    slot.addEventListener("blur", hide);
    slot.addEventListener("keydown", (e) => {
      const c = slot.__c; if (!c || !c.vis.length) return;
      const pts = c.vis[0].draw; if (!pts.length) return;
      if (e.key === "Escape") return hide();
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      e.preventDefault();
      let i = kt == null ? pts.length - 1 : pts.indexOf(nearest(pts, kt)) + (e.key === "ArrowRight" ? 1 : -1);
      i = Math.max(0, Math.min(pts.length - 1, i));
      show(pts[i][0]);
    });
    slot.__show = show;
  }

  /* ---------- tabs ---------- */
  const S = (k, label, color, fmt, pts) => ({ k, label, color: col(color), fmt, pts });

  const VIEWS = {
    system: {
      keys: SYS_KEYS,
      build: () => `
        <div class="ins-kpis">${SYS_KEYS.map((k) => kpi(k, TH[k].label)).join("")}</div>
        <div class="ins-grid">
          <section class="ins-box ins-span-8">
            <header><h3>Headroom</h3><span>each metric against its own warning / critical limit</span></header>
            <div class="ins-legend" data-lg="head"></div>
            <div class="ins-chart" data-chart="head"></div>
          </section>
          <section class="ins-box ins-span-4">
            <header><h3>Memory &amp; storage</h3><span data-slot="memsub"></span></header>
            <div class="ins-sub">RAM</div><div data-slot="mem"></div>
            <div class="ins-sub">Swap</div><div data-slot="swap"></div>
            <div class="ins-sub">Disk <span data-slot="mount"></span></div><div data-slot="disk"></div>
            <div class="ins-facts" data-slot="facts"></div>
          </section>
        </div>`,
      update() {
        const sys = cur.sys || {};
        const u = sys.usage || {}, cores = (sys.cpu || {}).cores || 1;
        SYS_KEYS.forEach((k) => {
          const th = TH[k], v = k === "cpu" ? (recentAvg("cpu", MIN) != null ? recentAvg("cpu", MIN) : last(k)) : last(k);
          let sub = `warn ${th.w}${k === "temp" ? "°" : "%"} · crit ${th.c}${k === "temp" ? "°" : "%"}`;
          let val = th.fmt(v);
          if (k === "load") { val = sys.load ? sys.load[0].toFixed(2) : "—"; sub = `${Math.round(v || 0)}% of ${cores} cores · 5m ${sys.load ? sys.load[1].toFixed(2) : "—"}`; }
          if (k === "cpu") sub = `1m avg · ${sub.replace(/%/g, "")}`;
          setKpi(k, val, null, level(v, th), `${gauge(k === "load" ? Math.min(v || 0, th.max) : v, th)}<span>${esc(sub)}</span>`);
        });
        const range = rangeMs();
        const ser = SYS_KEYS.map((k) => {
          const s = S(k, TH[k].label, TH[k].color, TH[k].fmt, seriesOf(k, range).map((p) => [p[0], norm(p[1], TH[k]), p[2], p[1]]));
          s.now = TH[k].fmt(last(k)).replace(" of cores", "");
          return s;
        });
        legend($('[data-lg="head"]', panel), ser);
        chart($('[data-chart="head"]', panel), {
          series: ser, h: 230, yMax: 100, aria: "System headroom trend",
          yLabels: [[0, "0"], [35, "OK"], [70, "WARN"], [90, "CRIT"]],
          bands: [{ y0: 70, y1: 90, cls: "warn", label: "WARNING" }, { y0: 90, y1: 100, cls: "crit", label: "CRITICAL" }],
        });
        const mem = sys.mem || {}, sw = sys.swap || {}, dk = sys.disk || {};
        const avail = mem.available != null ? mem.available : Math.max(0, (mem.total || 0) - (mem.used || 0));
        const used = Math.max(0, (mem.total || 0) - avail);
        let memParts, memHint = "";
        if (mem.apps != null) {
          memParts = [
            { l: "Apps", v: mem.apps, c: col("--h-violet") },
            { l: "Cache", v: mem.cache || 0, c: col("--h-sky") },
            { l: "Buffers", v: mem.buffers || 0, c: col("--h-teal") },
            { l: "Free", v: mem.memfree || 0, c: "color-mix(in srgb, var(--green) 70%, transparent)" }];
          memHint = `<div class="ins-hint">Cache &amp; buffers are reclaimable. In use (total − available): <b>${fmtBytes(used)}</b> · <b>${fmtPct(used / mem.total * 100)}</b> — the Memory thresholds use this.</div>`;
        } else {
          const other = Math.max(0, (mem.total || 0) - (mem.used || 0) - avail);
          memParts = [{ l: "Used", v: mem.used || 0, c: col("--h-violet") }];
          if (other > (mem.total || 0) * 0.005) memParts.push({ l: "Other", v: other, c: col("--h-amber") });
          memParts.push({ l: "Available", v: avail, c: "color-mix(in srgb, var(--green) 70%, transparent)" });
        }
        const set = (slot, html) => { const el = $(`[data-slot="${slot}"]`, panel); if (el && el.__h !== html) { el.__h = html; el.innerHTML = html; } };
        set("memsub", mem.total ? `${fmtBytes(mem.total)} total` : "");
        set("mem", mem.total ? stack(memParts, fmtBytes) + memHint : `<div class="ins-empty">Waiting for /api/system…</div>`);
        set("swap", sw.total ? stack([{ l: "Used", v: sw.used || 0, c: col("--h-slate") }, { l: "Free", v: sw.free != null ? sw.free : sw.total - (sw.used || 0), c: "color-mix(in srgb, var(--green) 55%, transparent)" }], fmtBytes) : `<div class="ins-empty">No swap</div>`);
        set("mount", dk.mount ? `<em>${esc(dk.mount)} · ${esc(dk.fs || "")}</em>` : "");
        set("disk", dk.total ? stack([{ l: "Used", v: dk.used || 0, c: col("--h-pink") }, { l: "Free", v: dk.avail != null ? dk.avail : dk.total - (dk.used || 0), c: "color-mix(in srgb, var(--green) 55%, transparent)" }], fmtBytes) : "");
        set("facts", `<span>Uptime <b>${fmtUptime(sys.uptime)}</b></span><span>Cores <b>${cores}</b></span><span>Temp <b>${TH.temp.fmt((sys.cpu || {}).temp)}</b></span>`);
      },
    },

    dns: {
      keys: ["qpm", "blk", "hit", "sf"],
      build: () => `
        <div class="ins-kpis">${kpi("qpm", "Queries / min")}${kpi("blk", "Blocked (NXDOMAIN)")}${kpi("hit", "Cache hit rate")}${kpi("sf", "SERVFAIL")}${kpi("v6", "Queries over IPv6")}</div>
        <div class="ins-grid">
          <section class="ins-box ins-span-7">
            <header><h3>Filtering</h3><span data-slot="since"></span></header>
            <div data-slot="sink"></div>
            <div class="ins-legend" data-lg="pct"></div>
            <div class="ins-chart" data-chart="pct"></div>
            <div class="ins-sub">Query rate</div>
            <div class="ins-chart" data-chart="qpm"></div>
          </section>
          <section class="ins-box ins-span-5">
            <header><h3>Query mix</h3><span data-slot="qtot"></span></header>
            <div class="ins-bars" data-bars="qtypes"></div>
            <div class="ins-sub">IPv4 / IPv6</div><div data-slot="ipv"></div>
            <div class="ins-sub">Response codes</div>
            <div class="ins-bars" data-bars="rcodes"></div>
          </section>
          <section class="ins-box ins-span-7">
            <header><h3>Top blocked domains</h3><span data-slot="tmwin"></span></header>
            <div class="ins-bars" data-bars="bdom"></div>
          </section>
          <section class="ins-box ins-span-5">
            <header><h3>Top blocked clients</h3><span>hover for IP and top domains</span></header>
            <div class="ins-bars" data-bars="bcli"></div>
          </section>
        </div>`,
      update() {
        const d = cur.dns;
        const tot = (d && d.totals) || {};
        const range = rangeMs();
        const q = recentAvg("qpm", 2 * MIN), b = recentAvg("blk", 5 * MIN), h = recentAvg("hit", 5 * MIN), sf = recentAvg("sf", 5 * MIN), v6 = recentAvg("v6", 5 * MIN);
        const lifeB = tot.queries ? (tot.nxdomain || 0) / tot.queries * 100 : null;
        const lifeH = tot.hitrate != null ? tot.hitrate * 100 : null;
        const sfLife = d ? ((((d.rcodes || []).filter((r) => r.label === "SERVFAIL")[0] || {}).count || 0) / Math.max(1, tot.queries) * 100) : null;
        setKpi("qpm", q != null ? fmtNum(q) : "—", q != null ? `${fmtNum(tot.queries)} since resolver start` : "measuring (needs two samples)…");
        setKpi("blk", fmtPct(b != null ? b : lifeB), b != null ? `5-min · lifetime ${fmtPct(lifeB)}` : "lifetime");
        const hv = h != null ? h : lifeH;
        setKpi("hit", fmtPct(hv), null, 0,
          `${gauge(hv, { w: 40, c: 20, max: 100 }, true)}<span>${h != null ? "5-min · lifetime " + fmtPct(lifeH) : "lifetime"}</span>`);
        const sfv = sf != null ? sf : sfLife;
        setKpi("sf", fmtPct(sfv), sf != null ? "of queries · 5-min · warn ≥ 5%" : "of queries · lifetime", sfv >= 15 ? 2 : sfv >= 5 ? 1 : 0);
        const v6Life = tot.queries ? (tot.ipv6 || 0) / tot.queries * 100 : null;
        setKpi("v6", fmtPct(v6 != null ? v6 : v6Life), v6 != null ? `5-min · lifetime ${fmtPct(v6Life)}` : "lifetime");
        const set = (slot, html) => { const el = $(`[data-slot="${slot}"]`, panel); if (el && el.__h !== html) { el.__h = html; el.innerHTML = html; } };
        set("since", d && d.uptime ? `since resolver start · ${fmtUptime(d.uptime)} ago` : "");
        set("sink", tot.queries ? stack([
          { l: "Allowed", v: Math.max(0, tot.queries - (tot.nxdomain || 0)), c: "var(--green)" },
          { l: "Blocked", v: tot.nxdomain || 0, c: "var(--red)" }], fmtNum) : `<div class="ins-empty">Waiting for /api/dns…</div>`);
        const pct = [
          S("blk", "Blocked %", "--red", fmtPct, seriesOf("blk", range)),
          S("hit", "Cache hit %", "--green", fmtPct, seriesOf("hit", range)),
          S("sf", "SERVFAIL %", "--h-amber", fmtPct, seriesOf("sf", range)),
        ];
        legend($('[data-lg="pct"]', panel), pct);
        chart($('[data-chart="pct"]', panel), { series: pct, h: 190, yMax: 100, yFmt: (v) => Math.round(v) + "%", aria: "DNS blocked and cache hit percentage" });
        chart($('[data-chart="qpm"]', panel), { series: [S("qpm", "Queries/min", "--accent", (v) => fmtNum(v) + "/min", seriesOf("qpm", range))], h: 140, area: true, aria: "DNS queries per minute" });
        const qt = (d && d.qtypes) || [];
        const qsum = qt.reduce((n, x) => n + (x.count || 0), 0);
        set("qtot", qsum ? `${fmtNum(qsum)} queries` : "");
        const top = qt.slice().sort((a, b2) => b2.count - a.count);
        const shown = top.slice(0, 7).map((x, i) => ({ k: x.label, l: x.label, v: x.count, c: col(["--h-blue", "--h-teal", "--h-violet", "--h-amber", "--h-green", "--h-pink", "--h-sky"][i]) }));
        const rest = top.slice(7).reduce((n, x) => n + x.count, 0);
        if (rest) shown.push({ k: "_o", l: "Other", v: rest, c: col("--h-slate") });
        bars($('[data-bars="qtypes"]', panel), shown.filter((x) => x.v > 0), { total: qsum, empty: "Waiting for /api/dns…" });
        set("ipv", tot.queries ? stack([
          { l: "IPv4", v: Math.max(0, tot.queries - (tot.ipv6 || 0)), c: col("--h-blue") },
          { l: "IPv6", v: tot.ipv6 || 0, c: col("--h-violet") }], fmtNum) : "");
        const RC = { NOERROR: "--green", NXDOMAIN: "--red", SERVFAIL: "--amber", REFUSED: "--h-orange", nodata: "--h-sky" };
        bars($('[data-bars="rcodes"]', panel), ((d && d.rcodes) || []).filter((r) => r.count > 0).sort((a, b2) => b2.count - a.count)
          .map((r) => ({ k: r.label, l: r.label, v: r.count, c: col(RC[r.label] || "--h-slate"), title: r.label === "NXDOMAIN" ? "Includes sinkholed (blocked) names" : r.label === "SERVFAIL" ? "Upstream / DNSSEC failures — a rising share is an early warning" : "" })),
        { total: tot.queries });
        ensureTm();
        const blk = ((cur.tm && cur.tm.entries) || []).filter((e) => e.type === "dns-block" && e.dst);
        const doms = new Map(), clis = new Map();
        let t0 = Infinity;
        const bump = (m, k, sub) => {
          let o = m.get(k); if (!o) m.set(k, o = { n: 0, by: new Map() });
          o.n++; o.by.set(sub, (o.by.get(sub) || 0) + 1);
        };
        blk.forEach((e) => {
          bump(doms, e.dst, e.src || "?"); bump(clis, e.src || "?", e.dst);
          const t = Date.parse(e.ts); if (t < t0) t0 = t;
        });
        const name = (ip) => { const h = hostOf(ip); return h ? `${h} (${ip})` : ip; };
        const topBy = (o, f) => Array.from(o.by).sort((a, b2) => b2[1] - a[1]).slice(0, 4).map((x) => `${f(x[0])} ×${x[1]}`).join("\n");
        set("tmwin", blk.length ? `last ${fmtNum(blk.length)} blocks since ${fmtTime(t0)}` : "");
        const wait = cur.tm ? "No DNS blocks in the recent log" : "Loading recent blocks…";
        bars($('[data-bars="bdom"]', panel), Array.from(doms).sort((a, b2) => b2[1].n - a[1].n).slice(0, 8).map(([k, o]) => ({
          k, l: k, v: o.n, c: "linear-gradient(90deg, color-mix(in srgb, var(--red) 50%, transparent), var(--red))",
          title: `${k}: ${o.n} blocked quer${o.n === 1 ? "y" : "ies"}\nBlocked for:\n${topBy(o, name)}`,
        })), { total: blk.length, empty: wait });
        bars($('[data-bars="bcli"]', panel), Array.from(clis).sort((a, b2) => b2[1].n - a[1].n).slice(0, 8).map(([k, o]) => ({
          k, l: hostOf(k) || k, v: o.n, c: col("--h-orange"), go: "clients",
          title: `${name(k)}: ${o.n} blocked quer${o.n === 1 ? "y" : "ies"}\nTop domains:\n${topBy(o, (x) => x)}`,
        })), { total: blk.length, empty: wait });
      },
    },

    threats: {
      keys: ["atk"],
      build: () => `
        <div class="ins-kpis">${kpi("a1", "Attacks / min")}${kpi("a10", "10-min average")}${kpi("src", "Unique sources")}${kpi("cty", "Countries")}${kpi("lastev", "Last event")}</div>
        <div class="ins-grid">
          <section class="ins-box ins-span-6">
            <header><h3>Attacks by country</h3><span>click a row for Security → Attacks</span></header>
            <div class="ins-bars ins-bars-cty" data-bars="cty"></div>
          </section>
          <section class="ins-box ins-span-6">
            <header><h3>Attack rate</h3><span>logged inbound blocks per minute</span></header>
            <div class="ins-chart" data-chart="atk"></div>
            <div class="ins-sub">Most targeted ports</div>
            <div class="ins-bars" data-bars="ports"></div>
          </section>
        </div>`,
      update() {
        const sec = cur.sec || {}, s = sec.stats || {};
        const avg = s.hits_10m != null ? s.hits_10m / 10 : null;
        const iss = computeIssues().threats[0];
        setKpi("a1", s.hits_1m != null ? fmtNum(s.hits_1m) : "—", avg != null && s.hits_1m != null ? (s.hits_1m > avg * 1.8 && s.hits_1m > 2 ? `▲ ${(s.hits_1m / Math.max(avg, 0.1)).toFixed(1)}× the 10-min avg` : "within normal range") : "", iss ? iss.lv : 0);
        setKpi("a10", avg != null ? avg.toFixed(1) : "—", s.hits_10m != null ? `${fmtNum(s.hits_10m)} in 10 min` : "");
        setKpi("src", fmtNum(s.unique_ips), s.hits != null ? `${fmtNum(s.hits)} hits total` : "");
        setKpi("cty", fmtNum(s.countries), "");
        setKpi("lastev", s.last_event ? fmtAgo(Date.now() / 1000 - s.last_event) : "—", s.last_event ? fmtTime(s.last_event * 1000) : "");
        const ips = sec.by_ip || [];
        const cs = (sec.countries || []).slice(0, 10);
        const tot = (sec.countries || []).reduce((n, c) => n + (c.count || 0), 0);
        bars($('[data-bars="cty"]', panel), cs.map((c) => {
          const name = !c.name || c.name === "??" ? "Unknown" : c.name;
          const top = ips.filter((i) => i.iso === c.iso).sort((a, b) => b.count - a.count)[0];
          return {
            k: c.iso || name, l: name, pre: flag(c.iso), v: c.count, go: "security/attacks",
            c: "linear-gradient(90deg, color-mix(in srgb, var(--red) 55%, transparent), var(--red))",
            title: `${name}: ${fmtNum(c.count)} hits (${fmtPct(c.count / Math.max(1, tot) * 100)})` + (top ? `\nTop source ${top.ip}${top.isp ? " · " + top.isp : ""} (${top.count})` : ""),
          };
        }), { total: tot, empty: "No attacks recorded" });
        chart($('[data-chart="atk"]', panel), { series: [S("atk", "Attacks/min", "--red", (v) => fmtNum(v) + "/min", seriesOf("atk", rangeMs()))], h: 170, area: true, aria: "Attack rate per minute" });
        const ports = (((cur.fw || {}).traffic || {}).top_ports || []).slice(0, 6);
        bars($('[data-bars="ports"]', panel), ports.map((p) => ({ k: p.port, l: p.port, v: p.count, c: col("--h-orange") })),
          { empty: "Waiting for /api/firewall…" });
      },
    },

    ids: {
      keys: [], noHist: true,
      note: () => (cur.sur && cur.sur.enabled !== false ? `24 h window · updated ${fmtAgo((Date.now() - (cur.surAt || Date.now())) / 1000)}` : ""),
      build: () => {
        st.idsOff = false;
        return `
        <div class="ins-kpis">${kpi("ia", "Alerts (24 h)")}${kpi("ih", "Hosts involved")}${kpi("ihi", "High severity")}${kpi("isig", "Top signature")}${kpi("i1h", "Last hour")}</div>
        <div class="ins-grid">
          <section class="ins-box ins-span-7">
            <header><h3>Top talkers</h3><span data-slot="tsub">hosts by alert count · hover for signatures, click for Sensors</span></header>
            <div class="ids-key" aria-hidden="true"><span class="ids-k-sev h"><i></i>High</span><span class="ids-k-sev m"><i></i>Medium</span><span class="ids-k-sev l"><i></i>Low</span>
              <span class="ids-k-sp"></span><span class="ids-tag" data-kind="lan">LAN device</span><span class="ids-tag" data-kind="ext">External</span><span class="ids-tag" data-kind="rtr">This router</span></div>
            <div class="ids-talkers" data-slot="talkers" role="list" aria-label="Top talkers"></div>
          </section>
          <section class="ins-box ins-span-5">
            <header><h3>Alerts per hour</h3><span data-slot="hsub"></span></header>
            <div class="ins-chart ids-hours" data-chart="hours"></div>
            <div class="ins-sub">Top destination ports</div>
            <div class="ins-bars" data-bars="dports"></div>
          </section>
          <section class="ins-box ins-span-12">
            <header><h3>Top signatures</h3><span>24 h · hover for category &amp; SID</span></header>
            <div class="ins-bars ins-bars-sig" data-bars="sigs"></div>
          </section>
        </div>`;
      },
      update() {
        ensureSur();
        const d = cur.sur;
        if (d && d.enabled === false) {
          if (!st.idsOff) {
            st.idsOff = true;
            panel.innerHTML = `<div class="ids-off"><svg viewBox="0 0 24 24" aria-hidden="true">${TABS.filter((t) => t.id === "ids")[0].icon}</svg>
              <div><h3>Suricata isn't running on this router</h3><p>Install and enable <b>Suricata</b> on the LAN/WAN interfaces to see intrusion-detection alerts, top talkers and signatures here. It runs as a passive IDS and never slows the connection.</p>
              <button type="button" class="ids-off-go" data-go="security/sensors">Open Security › Sensors</button></div></div>`;
          }
          return;
        }
        if (st.idsOff) { st.idsOff = false; panel.innerHTML = VIEWS.ids.build(); }
        const set = (slot, html) => { const el = $(`[data-slot="${slot}"]`, panel); if (el && el.__h !== html) { el.__h = html; el.innerHTML = html; } };
        if (!d) {
          set("talkers", `<div class="ins-empty">Loading Suricata alerts…</div>`);
          return;
        }
        const s = surStats(d), I = computeIssues().ids;
        const talkers = d.talkers || [], top = d.top || [];
        const nLan = talkers.filter((t) => t.local).length;
        setKpi("ia", fmtNum(d.count_24h), `≈ ${s.avg >= 10 ? fmtNum(s.avg) : s.avg.toFixed(1)} per hour`);
        setKpi("ih", fmtNum(d.talker_hosts != null ? d.talker_hosts : talkers.length), talkers.length ? `top ${talkers.length}: ${nLan} LAN · ${talkers.length - nLan} external` : "");
        setKpi("ihi", fmtNum(s.high), s.highHour ? "latest within the hour" : s.high ? "in the last 24 h" : "none in 24 h", s.highHour || s.lanSrc.length ? 2 : s.high ? 1 : 0);
        const t0 = top[0];
        setKpi("isig", t0 ? t0.sig.replace(/^(ET|GPL|SURICATA) /, "") : "—", t0 ? `${fmtNum(t0.count)}× · ${t0.severity.toLowerCase()} · ${t0.category || ""}` : "no signatures");
        const ks = $('[data-kpi="isig"]', panel);
        if (ks) ks.title = t0 ? `${t0.sig}\n${t0.category || ""} · ${t0.severity} · SID ${t0.sid}\n${fmtNum(t0.count)} alerts in 24 h` : "";
        const burst = s.lh >= Math.max(10, s.avg * 3);
        setKpi("i1h", (s.approx ? "≈ " : "") + fmtNum(s.lh), s.avg ? `${(s.lh / s.avg).toFixed(1)}× the hourly avg${burst ? " — burst" : ""}` : "", burst ? 1 : 0);
        // talkers
        const ra = routerAddrs(), wanIf = ((cur.sys || {}).wan || {}).ifname;
        const sec = window.twApi && window.twApi.data("/api/security");
        const geo = new Map(((sec && sec.by_ip) || []).map((g) => [g.ip, g]));
        const max = Math.max(1, ...talkers.map((t) => t.count));
        const now = Date.now() / 1000;
        const ICON = {
          rtr: '<svg viewBox="0 0 24 24"><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M8 9.5a5.5 5.5 0 0 1 8 0M5.5 7a9 9 0 0 1 13 0"/></svg>',
          lan: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
          ext: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/></svg>',
        };
        const rowsData = talkers.map((t) => {
          let kind, name, sub, tag, ico;
          if (ra.has(t.ip)) {
            const ifn = ra.get(t.ip);
            kind = "rtr"; name = (cur.sys && cur.sys.hostname) || "Router"; tag = "This router";
            sub = `${t.ip} · ${ifn === wanIf ? "WAN" : "LAN"} ${ifn}`;
          } else if (t.local || isPriv(t.ip)) {
            const h = hostOf(t.ip);
            kind = "lan"; name = h || t.ip; sub = h ? t.ip : "unnamed device"; tag = t.as_src >= t.as_dst ? "LAN · source" : "LAN device";
          } else {
            const g = geo.get(t.ip);
            kind = "ext"; name = t.ip; tag = "External";
            sub = g ? [g.city, g.country].filter(Boolean).join(", ") + (g.isp ? " · " + g.isp : "") : "external host";
            if (g && g.iso) ico = `<span class="ins-flag">${flag(g.iso)}</span>`;
          }
          const sev = t.high ? "HIGH" : t.medium >= t.low ? "MEDIUM" : "LOW";
          return { t, kind, name, sub, tag, ico: ico || ICON[kind], sev };
        });
        const tl = $('[data-slot="talkers"]', panel);
        const sig = rowsData.map((r) => [r.t.ip, r.t.count, r.t.high, r.t.medium, r.t.as_src, r.t.peers, r.name, r.sub].join(",")).join("|");
        if (tl && !talkers.length) set("talkers", `<div class="ins-empty">No alerts in the last 24 h</div>`);
        else if (tl && tl.dataset.sig !== sig) {
          const fo = document.activeElement && document.activeElement.closest && document.activeElement.closest(".ids-row");
          const foIp = fo && tl.contains(fo) ? fo.dataset.ip : null;
          tl.dataset.sig = sig; tl.__h = "";
          tl.innerHTML = rowsData.map((r, i) => {
            const t = r.t, tot = Math.max(1, t.high + t.medium + t.low);
            return `<div class="ids-row" role="listitem" tabindex="0" data-go="security/sensors" data-ip="${esc(t.ip)}" data-kind="${r.kind}" data-sev="${r.sev}"
                aria-label="${esc(`${r.name}${r.name !== t.ip ? " (" + t.ip + ")" : ""}, ${r.tag}, ${t.count} alerts, ${t.as_src} as source, ${t.as_dst} as destination, ${t.peers} peers`)}">
              <span class="ids-rank">${i + 1}</span>
              <span class="ids-who"><span class="ids-ico" aria-hidden="true">${r.ico}</span><span class="ids-nm"><b>${esc(r.name)}</b><em>${esc(r.sub)}</em></span><span class="ids-tag" data-kind="${r.kind}">${esc(r.tag)}</span></span>
              <span class="ids-sev" aria-hidden="true"><span class="ids-sev-t" style="width:${(t.count / max * 100).toFixed(1)}%">${[["h", t.high], ["m", t.medium], ["l", t.low]].filter((x) => x[1]).map((x) => `<i class="${x[0]}" style="flex-grow:${x[1] / tot}"></i>`).join("")}</span></span>
              <span class="ids-cnt">${fmtNum(t.count)}</span>
              <span class="ids-dir"><span title="as source">↑ ${fmtShort(t.as_src)}</span><span title="as destination">↓ ${fmtShort(t.as_dst)}</span></span>
              <span class="ids-peers">${fmtNum(t.peers)} peer${t.peers === 1 ? "" : "s"}</span>
              <span class="ids-ago" data-ts="${t.last_ts}"></span></div>`;
          }).join("");
          if (foIp) { const r = tl.querySelector(`.ids-row[data-ip="${CSS.escape(foIp)}"]`); if (r) r.focus(); }
          if (tipRow && !tl.contains(tipRow)) hideRowTip();
        }
        if (tl) $$(".ids-ago", tl).forEach((a) => {
          const txt = fmtAgo(Math.max(0, now - +a.dataset.ts));
          if (a.textContent !== txt) { a.textContent = txt; a.title = new Date(a.dataset.ts * 1000).toLocaleString(); }
        });
        // hourly chart
        set("hsub", I.length ? esc(I[0].msg.replace(/^IDS:? ?/, "")) : `peak ${fmtNum(Math.max(0, ...(d.hourly || []).map((h) => h.count)))} / h`);
        hourChart($('[data-chart="hours"]', panel), d.hourly || [], s.avg);
        const SEVC = { HIGH: "var(--ins-crit)", MEDIUM: "var(--ins-warn)", LOW: "var(--ids-low)" };
        bars($('[data-bars="dports"]', panel), (d.top_ports || []).slice(0, 10).map((p) => ({ k: p.port, l: p.port, v: p.count, c: col("--h-orange"), title: `${p.port}: ${fmtNum(p.count)} alerts` })),
          { total: d.count_24h, empty: "No alerts in the last 24 h" });
        bars($('[data-bars="sigs"]', panel), top.map((g) => ({
          k: g.sid + g.sig, l: g.sig, v: g.count, c: SEVC[g.severity] || SEVC.LOW, go: "security/sensors",
          pre: `<i class="ids-sevdot" style="--c:${SEVC[g.severity] || SEVC.LOW}"></i>`,
          title: `${g.sig}\n${g.category || "Uncategorised"} · ${g.severity} · SID ${g.sid}\nLast seen ${fmtAgo(now - g.last_ts)}`,
        })), { total: d.count_24h, empty: "No signatures fired in the last 24 h" });
      },
    },

    traffic: {
      keys: ["rx", "tx", "fwa", "fwb"],
      build: () => `
        <div class="ins-kpis">${kpi("dn", "WAN download")}${kpi("up", "WAN upload")}${kpi("tdn", "Downloaded")}${kpi("tup", "Uploaded")}${kpi("lat", "WAN latency")}</div>
        <div class="ins-grid">
          <section class="ins-box ins-span-7">
            <header><h3>WAN throughput</h3><span data-slot="wan"></span></header>
            <div class="ins-legend" data-lg="wan"></div>
            <div class="ins-chart" data-chart="wan"></div>
            <div class="ins-sub">Per interface <em>(live, last 10 min sparkline)</em></div>
            <div class="ins-ifs" data-slot="ifs"></div>
          </section>
          <section class="ins-box ins-span-5">
            <header><h3>Firewall</h3><span>new inbound connections</span></header>
            <div class="ins-sub">Allowed vs blocked <em>(packets, lifetime counters)</em></div><div data-slot="fwr"></div>
            <div class="ins-sub">Allowed / blocked per minute</div>
            <div class="ins-legend" data-lg="fwc"></div>
            <div class="ins-chart" data-chart="blk"></div>
            <div class="ins-sub">Top blocked sources <em>(recent log window)</em></div>
            <div class="ins-bars" data-bars="srcs"></div>
          </section>
        </div>`,
      update() {
        const bw = cur.bw || {}, sys = cur.sys || {};
        const ifs = bw.interfaces || [];
        const wn = wanName();
        const wan = ifs.filter((i) => i.name === wn)[0] || {};
        const lat = sys.latency || {};
        setKpi("dn", fmtRate(wan.rx_bps), wn ? `on ${wn}` : "");
        setKpi("up", fmtRate(wan.tx_bps), wn ? `on ${wn}` : "");
        setKpi("tdn", wan.rx_total != null ? fmtBytes(wan.rx_total) : "—", "since interface up");
        setKpi("tup", wan.tx_total != null ? fmtBytes(wan.tx_total) : "—", "since interface up");
        const iss = computeIssues().traffic[0];
        setKpi("lat", lat.current_ms != null ? Math.round(lat.current_ms) + " ms" : "—",
          lat.current_ms != null ? `baseline ${Math.round(lat.baseline_ms || 0)} ms · loss ${lat.loss_1h_pct ?? "—"}%` : "", iss ? iss.lv : 0);
        const set = (slot, html) => { const el = $(`[data-slot="${slot}"]`, panel); if (el && el.__h !== html) { el.__h = html; el.innerHTML = html; } };
        set("wan", wn ? `${esc(wn)}${(sys.wan || {}).ipv4 ? " · " + esc(sys.wan.ipv4) : ""}` : "");
        const range = rangeMs();
        const ws = [S("rx", "Download", "--accent", fmtRate, seriesOf("rx", range)), S("tx", "Upload", "--h-violet", fmtRate, seriesOf("tx", range))];
        ws[0].now = fmtRate(wan.rx_bps); ws[1].now = fmtRate(wan.tx_bps);
        legend($('[data-lg="wan"]', panel), ws);
        chart($('[data-chart="wan"]', panel), { series: ws, h: 190, area: true, aria: "WAN throughput (bits per second)" });
        // per-interface rows
        const list = ifs.filter((i) => !/^ifb/.test(i.name));
        const sysIf = {}; (sys.interfaces || []).forEach((i) => { sysIf[i.name] = i; });
        const mx = Math.max(1, ...list.map((i) => Math.max(i.rx_bps || 0, i.tx_bps || 0)));
        const spark = (h, idx) => {
          if (!h || h.length < 2) return "";
          const step = Math.max(1, Math.floor(h.length / 60)), pts = [];
          for (let i = 0; i < h.length; i += step) pts.push(h[i][idx] || 0);
          const m = Math.max(1, ...pts);
          return pts.map((v, i) => (i ? "L" : "M") + (i / (pts.length - 1) * 100).toFixed(1) + " " + (19 - v / m * 17).toFixed(1)).join("");
        };
        const el = $('[data-slot="ifs"]', panel);
        if (el) {
          const sig = list.map((i) => i.name).join("|");
          if (el.dataset.sig !== sig) {
            el.dataset.sig = sig;
            el.innerHTML = list.map((i) => `<div class="ins-if" data-if="${esc(i.name)}"><span class="ins-if-n"><i class="ins-if-st"></i>${esc(i.name)}</span>
              <span class="ins-if-b"><span class="ins-if-f dn"></span><span class="ins-if-f up"></span></span>
              <span class="ins-if-v"></span><svg class="ins-if-sp" viewBox="0 0 100 20" preserveAspectRatio="none" aria-hidden="true"><path class="dn"/><path class="up"/></svg></div>`).join("");
          }
          list.forEach((i) => {
            const r = el.querySelector(`[data-if="${CSS.escape(i.name)}"]`); if (!r) return;
            const state = (sysIf[i.name] || {}).state || "";
            r.dataset.state = state === "UP" ? "up" : state ? "down" : "";
            r.querySelector(".ins-if-st").title = state || "unknown";
            r.title = `${i.name}${i.name === wn ? " (WAN)" : ""} · ${state || "?"}\n↓ ${fmtRate(i.rx_bps)}  ↑ ${fmtRate(i.tx_bps)}\nTotal ↓ ${fmtBytes(i.rx_total)}  ↑ ${fmtBytes(i.tx_total)}`;
            r.querySelector(".ins-if-f.dn").style.width = ((i.rx_bps || 0) / mx * 100).toFixed(1) + "%";
            r.querySelector(".ins-if-f.up").style.width = ((i.tx_bps || 0) / mx * 100).toFixed(1) + "%";
            r.querySelector(".ins-if-v").innerHTML = `<b>↓ ${fmtRate(i.rx_bps)}</b><b>↑ ${fmtRate(i.tx_bps)}</b>`;
            r.querySelector("path.dn").setAttribute("d", spark(i.history, 1));
            r.querySelector("path.up").setAttribute("d", spark(i.history, 2));
          });
        }
        const tr = (cur.fw || {}).traffic || {};
        const fc = (cur.fw || {}).counters;
        set("fwr", fc && fc.ok !== false ? stack([{ l: "Allowed", v: fc.allowed_packets || 0, c: "var(--green)" }, { l: "Blocked", v: fc.blocked_packets || 0, c: "var(--red)" }], fmtNum) +
          `<div class="ins-hint">Accepted by explicit rules vs dropped (default deny + drop rules) · <b>${fmtBytes(fc.allowed_bytes)}</b> / <b>${fmtBytes(fc.blocked_bytes)}</b></div>`
          : `<div class="ins-empty">${cur.fw ? "Firewall counters unavailable" : "Waiting for /api/firewall…"}</div>`);
        const fmtPm = (v) => fmtNum(v) + "/min";
        const fs = [S("fwa", "Allowed/min", "--green", fmtPm, seriesOf("fwa", range)), S("fwb", "Blocked/min", "--red", fmtPm, seriesOf("fwb", range))];
        fs[0].now = last("fwa") != null ? fmtPm(last("fwa")) : null; fs[1].now = last("fwb") != null ? fmtPm(last("fwb")) : null;
        legend($('[data-lg="fwc"]', panel), fs);
        chart($('[data-chart="blk"]', panel), { series: fs, h: 130, aria: "Allowed and blocked inbound connections per minute" });
        bars($('[data-bars="srcs"]', panel), (tr.top_sources || []).slice(0, 5).map((s) => ({ k: s.ip, l: s.ip, v: s.count, c: col("--h-red"), go: "security/attacks" })),
          { noPct: true, empty: "No blocks in the log window" });
      },
    },
  };

  /* ---------- render loop (only the active tab, only when visible) ---------- */
  function ovVisible() {
    const v = document.getElementById("view-overview");
    const gate = document.getElementById("login-gate");
    return !!v && !v.hidden && !document.hidden && (!gate || gate.hidden);
  }
  function schedule() {
    st.dirty = true;
    if (st.timer) return;
    st.timer = setTimeout(() => { st.timer = 0; render(false); }, 120);
  }
  let lastIssuesKey = "";
  function updateStatus() {
    const I = computeIssues();
    TABS.forEach((t) => {
      const lv = I[t.id].length ? I[t.id][0].lv : 0;
      const dot = $(`#ins-tab-${t.id} .ins-dot`, root);
      if (dot) {
        dot.dataset.lv = lv;
        dot.title = I[t.id].length ? I[t.id].map((x) => x.msg).join("\n") : "Normal";
      }
    });
    const all = [].concat(I.system, I.dns, I.threats, I.ids, I.traffic).sort((a, b) => b.lv - a.lv);
    const has = cur.sys || cur.dns || cur.sec || cur.sur;
    const text = !has ? "Collecting data…" : all.length ? all[0].msg + (all.length > 1 ? `  (+${all.length - 1} more)` : "") : "All metrics normal";
    const key = (all[0] ? all[0].lv : 0) + text;
    if (key !== lastIssuesKey) {
      lastIssuesKey = key;
      summary.innerHTML = `<i class="ins-dot" data-lv="${all[0] ? all[0].lv : 0}"></i>${esc(text)}`;
      summary.title = all.map((x) => x.msg).join("\n");
      root.dataset.lv = all[0] ? all[0].lv : 0;
    }
  }
  function render(entering) {
    if (!ovVisible() || !st.inView) return;
    updateStatus();
    if (!st.dirty && !entering) return;
    st.dirty = false;
    const v = VIEWS[st.tab];
    if (st.built !== st.tab) {
      panel.innerHTML = v.build();
      st.built = st.tab;
      entering = true;
    }
    if (entering && !reduceMotion.matches) {
      panel.classList.remove("ins-enter"); panel.offsetWidth; panel.classList.add("ins-enter");
      clearTimeout(st.enterT); st.enterT = setTimeout(() => panel.classList.remove("ins-enter"), 900);
    }
    if (entering) tip.hidden = true;
    v.update();
    if (v.noHist) { note.textContent = v.note(); return; }
    const o = oldest(v.keys);
    const r = rangeMs();
    note.textContent = !isFinite(o) ? "Collecting samples…" : o > Date.now() - r + 2 * MIN ? `Collecting history since ${fmtTime(o)}` : "";
  }

  if (window.IntersectionObserver) {
    new IntersectionObserver((ents) => {
      st.inView = ents[ents.length - 1].isIntersecting;
      if (st.inView) render(false);
    }, { rootMargin: "200px" }).observe(root);
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden) render(false); });
  // re-render when the user returns to the Overview
  const ovEl = document.getElementById("view-overview");
  if (ovEl && window.MutationObserver) {
    new MutationObserver(() => { if (!ovEl.hidden) { st.dirty = true; render(false); } }).observe(ovEl, { attributes: true, attributeFilter: ["hidden"] });
  }
  // theme switches change CSS-variable colours only; SVG uses var() so no redraw needed.

  setInterval(() => { Object.keys(acc).forEach((k) => { if (acc[k] && acc[k].m < Date.now() - 2 * MIN) { finalize(k); acc[k] = null; } }); saveHist(); }, MIN);
  window.addEventListener("pagehide", () => { Object.keys(acc).forEach(finalize); dirtyStore = true; saveHist(); });

  syncChrome();
  function attach() {
    const api = window.twApi;
    if (!api) return false;
    api.on(ingest);
    ["/api/system", "/api/bandwidth", "/api/security", "/api/dns", "/api/firewall", SUR].forEach((p) => { if (api.data(p)) ingest(p); });
    return true;
  }
  if (!attach()) {
    // netmap.js not loaded: fall back to observing fetch ourselves
    const cache = {}, fns = [];
    window.twApi = { data: (p) => cache[p] || null, on: (fn) => fns.push(fn) };
    const W = /^\/api\/(system|bandwidth|security|dns|firewall|security\/suricata)$/;
    const _f = window.fetch;
    window.fetch = function (input, init) {
      const p = _f.apply(this, arguments);
      try {
        const m = ((init && init.method) || "GET").toUpperCase();
        const path = new URL(typeof input === "string" ? input : input.url, location.href).pathname.replace(/\/+$/, "");
        if (m === "GET" && W.test(path)) p.then((r) => r && r.ok && r.clone().json().then((d) => { if (d && d.ok !== false) { cache[path] = d; fns.forEach((fn) => fn(path)); } }, () => { }), () => { });
      } catch (_) { }
      return p;
    };
    attach();
  }
  render(true);
})();
