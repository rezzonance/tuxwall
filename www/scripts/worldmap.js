/* TuxWall world basemap for the attack maps (#ov-map, #sec-map).
   Replaces the old CARTO/OSM raster tiles with locally served Natural Earth
   country outlines (public domain, /data/world-*.geojson) drawn on a canvas
   in the active theme's colours, shaded by attack count.
   dashboard.js calls TuxWorldMap.attach(map) once per map and
   ctrl.setData(countries, byIp) on every /api/security poll. */
(function () {
  "use strict";
  if (typeof L === "undefined") return;

  const DATA_V = "20261111234908";
  const HI_ZOOM = 4;                       // 1:50m outlines from this zoom up
  const cache = {};
  function load(res) {
    if (!cache[res]) {
      cache[res] = fetch(`/data/world-${res}.geojson?v=${DATA_V}`, { credentials: "same-origin" })
        .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
        .catch((e) => { delete cache[res]; throw e; });
    }
    return cache[res];
  }

  // ── colour helpers (theme vars are plain #rrggbb / rgb()) ──────────────
  function parse(c) {
    c = (c || "").trim();
    if (c[0] === "#") {
      let h = c.slice(1);
      if (h.length === 3 || h.length === 4) h = h.split("").map((x) => x + x).join("");
      const n = parseInt(h.slice(0, 6), 16);
      return isNaN(n) ? null : [(n >> 16) & 255, (n >> 8) & 255, n & 255];
    }
    const m = c.match(/rgba?\(([^)]+)\)/);
    if (m) {
      const p = m[1].split(/[\s,/]+/).filter(Boolean).map(parseFloat);
      if (p.length >= 3 && p.slice(0, 3).every(isFinite)) return p.slice(0, 3);
    }
    return null;
  }
  const mix = (a, b, t) => [0, 1, 2].map((i) => Math.round(a[i] * (1 - t) + b[i] * t));
  const rgb = (c, a) => (a == null ? `rgb(${c.join(",")})` : `rgba(${c.join(",")},${a})`);
  const lum = (c) => (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255;
  const BLACK = [0, 0, 0];

  function readTheme(el) {
    const cs = getComputedStyle(el);
    const g = (n, d) => parse(cs.getPropertyValue(n)) || parse(d);
    const T = {
      bg: g("--bg", "#0f1419"), card: g("--card", "#1c2333"), text: g("--text", "#e6edf3"),
      accent: g("--accent", "#4f8cff"), red: g("--red", "#f85149"), fx: g("--map-accent", "#ff3b5c"),
    };
    const light = document.body.classList.contains("light-theme") || lum(T.bg) > 0.55;
    let ocean, land, line, label;
    if (light) {
      // Light themes keep the dark ops-map (all overlays are built for it),
      // but drawn in the theme's own ink with paper-coloured coastlines.
      ocean = mix(T.text, BLACK, 0.3);
      land = mix(ocean, T.card, 0.14);
      line = mix(land, T.card, 0.3);
      label = mix(ocean, T.card, 0.6);
    } else {
      ocean = mix(T.bg, BLACK, 0.42);
      land = mix(mix(T.card, T.bg, 0.35), T.text, 0.05);
      line = mix(land, T.text, 0.2);
      label = mix(land, T.text, 0.48);
    }
    land = mix(land, T.fx, 0.03);
    return {
      light, ocean, land, line, label, accent: T.accent, red: T.red, fx: T.fx, paper: light ? T.card : T.text,
      oceanHi: mix(mix(ocean, T.accent, 0.07), T.text, 0.03), oceanLo: mix(ocean, BLACK, 0.45),
    };
  }

  function rankLimit(z) { return z < 3 ? 0 : z < 4 ? 2 : z < 5 ? 3 : z < 6 ? 4 : 6; }

  function attach(map) {
    const el = map.getContainer();
    el.classList.add("wm");
    map.options.zoomSnap = 0.25;
    map.setMaxZoom(6);
    map.setMaxBounds([[-72, -180], [86, 180]]);
    map.options.maxBoundsViscosity = 0.85;
    map.attributionControl && map.attributionControl.setPrefix(false);
    map.attributionControl && map.attributionControl.addAttribution("Natural Earth");

    const renderer = L.canvas({ padding: 0.5, tolerance: 0 });
    if (!map.getPane("wmLabels")) {
      const p = map.createPane("wmLabels");
      p.style.zIndex = 450;
      p.style.pointerEvents = "none";
    }
    const tip = document.createElement("div");
    tip.className = "wm-tip";
    tip.hidden = true;
    el.appendChild(tip);

    const st = {
      theme: readTheme(el), layers: {}, res: null, counts: {}, sources: {}, names: {}, max: 0, sig: "",
      labels: {}, labelOn: new Set(), labelKey: "", hover: null,
    };
    const labelGroup = L.layerGroup().addTo(map);

    function fillFor(iso) {
      const t = st.theme, c = st.counts[iso] || 0;
      if (!c) return { fill: t.land, line: t.line };
      const k = st.max > 0 ? Math.log1p(c) / Math.log1p(st.max) : 0;
      const ramp = mix(t.accent, t.red, Math.pow(k, 0.8));
      return { fill: mix(t.land, ramp, 0.14 + 0.44 * k), line: mix(t.line, ramp, 0.45) };
    }
    function styleFor(f, hover) {
      const iso = f.properties.iso, s = fillFor(iso), t = st.theme;
      return {
        renderer, stroke: true, weight: hover ? 1.4 : 0.6, opacity: 1, fillOpacity: 1,
        color: rgb(hover ? mix(t.fx, t.paper, 0.25) : s.line),
        fillColor: rgb(hover ? mix(s.fill, t.paper, t.light ? 0.12 : 0.1) : s.fill),
      };
    }

    function tipHtml(p) {
      const n = st.counts[p.iso] || 0, s = st.sources[p.iso] || 0;
      const esc = (x) => String(x).replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]));
      const name = esc(st.names[p.iso] || p.name);
      if (!n) return `<b>${name}</b><span class="wm-tip-none">no attacks</span>`;
      return `<b>${name}</b><span><i>${n.toLocaleString()}</i> attack${n === 1 ? "" : "s"}</span>` +
        (s ? `<span><i>${s}</i> source${s === 1 ? "" : "s"}</span>` : "");
    }
    function showTip(e) {
      const p = e.layer && e.layer.feature && e.layer.feature.properties;
      if (!p || map._wmMoving) { tip.hidden = true; return; }
      tip.innerHTML = tipHtml(p);
      tip.hidden = false;
      const w = el.clientWidth, x = e.containerPoint.x, y = e.containerPoint.y;
      const tw = tip.offsetWidth || 160;
      tip.style.transform = `translate(${Math.round(x + 14 + tw > w ? x - tw - 14 : x + 14)}px,${Math.round(Math.max(4, y - 38))}px)`;
    }
    function setHover(layer) {
      if (st.hover === layer) return;
      if (st.hover) st.hover.setStyle(styleFor(st.hover.feature, false));
      st.hover = layer;
      if (layer) { layer.setStyle(styleFor(layer.feature, true)); layer.bringToFront(); }
    }

    // Built in small slices so the 1:50m set never blocks the main thread.
    function build(res, data) {
      if (st.layers[res]) return Promise.resolve(st.layers[res]);
      if (st.building && st.building[res]) return st.building[res];
      const layer = L.geoJSON(null, { style: (f) => styleFor(f, false), renderer, interactive: true });
      const feats = data.features;
      // Swapping resolutions: put it on the map empty so each slice also
      // pays its own projection cost, drawn over the coarse outlines.
      if (st.res) layer.addTo(map);
      st.building = st.building || {};
      return (st.building[res] = new Promise((done) => {
        let i = 0;
        (function step() {
          const t0 = performance.now();
          while (i < feats.length && performance.now() - t0 < 12) layer.addData(feats[i++]);
          if (i < feats.length) { setTimeout(step, 0); return; }
          delete st.building[res];
          done(finish(res, layer, data));
        })();
      }));
    }
    function finish(res, layer, data) {
      layer.on("mouseover mousemove", (e) => { setHover(e.layer); showTip(e); });
      layer.on("mouseout", () => { setHover(null); tip.hidden = true; });
      layer.on("click", (e) => { setHover(e.layer); showTip(e); });
      st.layers[res] = layer;
      // label points
      data.features.forEach((f) => {
        const p = f.properties;
        if (!st.labels[p.iso] || res === "50m") st.labels[p.iso] = { p, marker: st.labels[p.iso] && st.labels[p.iso].marker };
      });
      return layer;
    }

    function restyle(layer) {
      if (!layer) return;
      layer.eachLayer((l) => l.setStyle(styleFor(l.feature, l === st.hover)));
    }

    function show(res) {
      if (st.res === res || !st.layers[res]) return;
      const prev = st.layers[st.res];
      setHover(null);
      restyle(st.layers[res]);
      if (!map.hasLayer(st.layers[res])) st.layers[res].addTo(map);
      if (prev) map.removeLayer(prev);
      st.res = res;
    }

    function wantRes() { return map.getZoom() >= HI_ZOOM ? "50m" : "110m"; }
    function sync() {
      const res = wantRes();
      if (st.layers[res]) show(res);
      else load(res).then((d) => build(res, d)).then((l) => { if (wantRes() === res || !st.res) show(res); else map.removeLayer(l); updateLabels(); }).catch(() => {});
      updateLabels();
    }

    // Greedy, rank-ordered label placement; collisions only change with zoom.
    function updateLabels() {
      const z = map.getZoom(), lim = rankLimit(z);
      const key = Math.round(z * 4) + ":" + Object.keys(st.labels).length + ":" + st.sig;
      if (key === st.labelKey) return;
      st.labelKey = key;
      const want = new Set();
      if (lim) {
        const cands = Object.values(st.labels).filter((r) => r.p.lr <= lim && r.p.name)
          .sort((a, b) => (a.p.lr - b.p.lr) || ((st.counts[b.p.iso] || 0) - (st.counts[a.p.iso] || 0)));
        const boxes = [];
        for (const r of cands) {
          const pt = map.project([r.p.ly, r.p.lx], z);
          const w = r.p.name.length * 6.4 + 10, h = 15;
          const b = [pt.x - w / 2, pt.y - h / 2, pt.x + w / 2, pt.y + h / 2];
          if (boxes.some((o) => b[0] < o[2] && b[2] > o[0] && b[1] < o[3] && b[3] > o[1])) continue;
          boxes.push(b);
          want.add(r.p.iso);
        }
      }
      for (const iso of st.labelOn) if (!want.has(iso)) { labelGroup.removeLayer(st.labels[iso].marker); st.labelOn.delete(iso); }
      for (const iso of want) {
        const r = st.labels[iso];
        if (!r.marker) {
          r.marker = L.marker([r.p.ly, r.p.lx], {
            pane: "wmLabels", interactive: false, keyboard: false,
            icon: L.divIcon({ className: "wm-label", html: `<span>${r.p.name.replace(/[&<>]/g, "")}</span>`, iconSize: null }),
          });
        }
        if (!st.labelOn.has(iso)) { labelGroup.addLayer(r.marker); st.labelOn.add(iso); }
        const node = r.marker.getElement();
        if (node) node.classList.toggle("wm-hot", !!st.counts[iso]);
      }
    }

    function applyTheme() {
      st.theme = readTheme(el);
      const t = st.theme;
      el.style.setProperty("--wm-ocean", rgb(t.ocean));
      el.style.setProperty("--wm-ocean-hi", rgb(t.oceanHi));
      el.style.setProperty("--wm-ocean-lo", rgb(t.oceanLo));
      el.style.setProperty("--wm-label", rgb(t.label));
      el.style.setProperty("--wm-label-hot", rgb(mix(t.label, t.red, 0.55)));
      el.style.setProperty("--wm-halo", rgb(t.ocean, 0.85));
      Object.values(st.layers).forEach((l) => { if (map.hasLayer(l)) restyle(l); });
    }

    let themeTimer = 0;
    const mo = new MutationObserver(() => {
      clearTimeout(themeTimer);
      themeTimer = setTimeout(applyTheme, 30);
    });
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-theme-style", "style"] });
    mo.observe(document.body, { attributes: true, attributeFilter: ["class"] });
    mo.observe(el, { attributes: true, attributeFilter: ["data-palette"] });

    function fitMinZoom() {
      const w = el.clientWidth;
      if (!w) return;
      const z = Math.max(1, Math.min(3, Math.ceil(Math.log2(w / 256) * 4) / 4));
      if (z !== map.getMinZoom()) map.setMinZoom(z);
    }

    map.on("movestart zoomstart", () => { map._wmMoving = true; tip.hidden = true; });
    map.on("moveend zoomend", () => { map._wmMoving = false; });
    map.on("zoomend", sync);
    map.on("resize", fitMinZoom);
    fitMinZoom();
    applyTheme();
    sync();

    return {
      setData(countries, byIp) {
        const counts = {}, sources = {}, names = {};
        if (countries && countries.length) {
          for (const c of countries) {
            if (!c || !c.iso || c.iso.length !== 2 || c.iso === "??") continue;
            counts[c.iso] = (counts[c.iso] || 0) + (Number(c.count) || 0);
            if (c.name) names[c.iso] = c.name;
          }
        }
        for (const i of byIp || []) {
          if (!i || !i.iso) continue;
          sources[i.iso] = (sources[i.iso] || 0) + 1;
          if (!countries || !countries.length) counts[i.iso] = (counts[i.iso] || 0) + (Number(i.count) || 0);
          if (i.country && !names[i.iso]) names[i.iso] = i.country;
        }
        const sig = JSON.stringify([counts, sources]);
        st.names = names;
        if (sig === st.sig) return;
        st.sig = sig;
        st.counts = counts;
        st.sources = sources;
        st.max = Object.values(counts).reduce((a, b) => Math.max(a, b), 0);
        restyle(st.layers[st.res]);
        st.labelKey = "";
        updateLabels();
      },
      applyTheme,
    };
  }

  window.TuxWorldMap = { attach, load };
})();
