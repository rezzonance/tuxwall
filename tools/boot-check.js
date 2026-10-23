// Minimal DOM harness: execute dashboard.js outside a browser to find the
// boot-time crash. Element stubs answer every query; the first real error
// with a stack trace wins.
"use strict";
const fs = require("fs");

const handler = {
  get(target, prop) {
    if (prop in target) return target[prop];
    return makeEl(String(prop));
  },
  set(target, prop, v) { target[prop] = v; return true; },
};
function makeEl(tag) {
  const el = {
    tagName: String(tag || "div").toUpperCase(),
    children: [], style: {}, dataset: {}, _class: new Set(),
    classList: { add: (...c) => c.forEach(x => el._class.add(x)),
                 remove: (...c) => c.forEach(x => el._class.delete(x)),
                 toggle: (c, on) => { if (on === undefined) { el._class.has(c) ? el._class.delete(c) : el._class.add(c); } else if (on) el._class.add(c); else el._class.delete(c); },
                 contains: c => el._class.has(c) },
    addEventListener() {}, removeEventListener() {},
    appendChild(c) { el.children.push(c); return c; },
    removeChild() {}, insertBefore() { return null; },
    querySelector() { return makeEl("div"); },
    querySelectorAll() { return []; },
    closest() { return null; },
    getAttribute() { return null; }, setAttribute() {}, removeAttribute() {},
    getBoundingClientRect() { return { width: 0, height: 0, top: 0, left: 0 }; },
    focus() {}, click() {}, blur() {},
    getContext() { return new Proxy({}, { get: () => () => {} }); },
    value: "", hidden: false, disabled: false, checked: false,
    textContent: "", innerHTML: "", rows: [], map: () => [],
  };
  return new Proxy(el, {
    get(t, p) {
      if (p in t) return t[p];
      // unknown property read -> harmless element-ish value
      return undefined;
    },
    set(t, p, v) { t[p] = v; return true; },
  });
}

const elements = new Map();
// Faithful mode: only IDs that really exist in the served index.html exist.
// Parse-order simulation: at script-load time the browser has only parsed
// markup ABOVE the <script src=dashboard.js> tag - anything below it is
// invisible to the els map (this exact trap broke the live dashboard).
const stage = process.env.TW_STAGE || "/var/www/html";
const htmlSrc = fs.readFileSync(stage + "/index.html", "utf8");
const scriptPos = htmlSrc.search(/<script src="\/scripts\/dashboard\.js/);
const visibleHtml = scriptPos > 0 ? htmlSrc.slice(0, scriptPos) : htmlSrc;
const realIds = new Set();
for (const m of visibleHtml.matchAll(/\bid="([^"]+)"/g)) realIds.add(m[1]);
console.log("harness: IDs visible at script-load:", realIds.size,
            "| cs-ban-confirm visible:", realIds.has("cs-ban-confirm"));
function byId(id) {
  if (!realIds.has(id)) {
    // exact browser behavior: getElementById/querySelector miss -> null
    return null;
  }
  if (!elements.has(id)) elements.set(id, makeEl("div"));
  return elements.get(id);
}
const nullEl = null;
function querySel(sel) {
  // support "#id" and "#id tbody" / "#id child" selectors
  const m = /^#([A-Za-z0-9_-]+)(\s+.+)?$/.exec(sel || "");
  if (!m) return makeEl("div");
  const base = byId(m[1]);
  if (base === null) return null;
  return m[2] ? makeEl(m[2].trim()) : base;
}

const domReady = [];
global.document = new Proxy({
  getElementById: (id) => byId(id),
  querySelector: (sel) => querySel(sel),
  querySelectorAll: () => [],
  createElement: (t) => makeEl(t),
  createTextNode: () => makeEl("#text"),
  addEventListener: (ev, cb) => { if (ev === "DOMContentLoaded") domReady.push(cb); },
  removeEventListener() {},
  body: makeEl("body"),
  documentElement: makeEl("html"),
  head: makeEl("head"),
  hidden: false,
}, handler);

global.window = new Proxy({
  addEventListener() {}, removeEventListener() {},
  matchMedia: () => ({ matches: false, addEventListener() {}, addListener() {} }),
  location: { href: "https://router.housenetwork.site/", hash: "", host: "router.housenetwork.site", hostname: "router.housenetwork.site", protocol: "https:", origin: "https://router.housenetwork.site", search: "" },
  innerWidth: 1920, innerHeight: 1080, devicePixelRatio: 1,
  requestAnimationFrame: (cb) => setTimeout(cb, 0),
  cancelAnimationFrame: (id) => clearTimeout(id),
  setInterval: () => 0, clearInterval: () => {}, setTimeout: () => 0, clearTimeout: () => {},
  crypto: { getRandomValues: (a) => a, randomUUID: () => "x" },
  navigator: { userAgent: "node-harness", clipboard: { writeText: async () => {} } },
  URL: URL, URLSearchParams: URLSearchParams,
}, handler);

global.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
global.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
global.fetch = async () => ({
  ok: false, status: 401,
  json: async () => ({ ok: false, error: "Authentication required" }),
  text: async () => "",
});
global.matchMedia = global.window.matchMedia;
global.requestAnimationFrame = global.window.requestAnimationFrame;
// Real (but bounded) timers so the full boot chain actually executes.
const pending = new Set();
const nativeSetTimeout = setTimeout.bind(global);
const nativeClearTimeout = clearTimeout.bind(global);
const nativeSetInterval = setInterval.bind(global);
const nativeClearInterval = clearInterval.bind(global);
global.setTimeout = (cb, ms) => { const id = nativeSetTimeout(() => { pending.delete(id); try { cb(); } catch (e) { fail(e); } }, Math.min(ms || 0, 5)); pending.add(id); return id; };
global.clearTimeout = (id) => { nativeClearTimeout(id); pending.delete(id); };
global.setInterval = (cb, ms) => { const id = nativeSetInterval(() => { try { cb(); } catch (e) { fail(e); } }, Math.max(ms || 1, 5)); pending.add(id); return id; };
global.clearInterval = (id) => { nativeClearInterval(id); pending.delete(id); };
let crashed = false;
function fail(e) {
  if (crashed) return; crashed = true;
  console.log("DEFERRED CRASH:", e && e.message);
  const stack = (e && e.stack) || "";
  const lines = stack.split("\n").filter(l => /dashboard\.js|Function/i.test(l));
  console.log(lines.slice(0, 6).join("\n") || stack.split("\n").slice(0, 8).join("\n"));
  process.exit(1);
}
global.window.setTimeout = global.setTimeout;
global.window.setInterval = global.setInterval;
global.window.clearTimeout = global.clearTimeout;
global.window.clearInterval = global.clearInterval;
global.window.requestAnimationFrame = (cb) => global.setTimeout(cb, 0);
try { global.navigator = global.window.navigator; } catch (e) {}
global.alert = () => {}; global.confirm = () => false;
global.MutationObserver = class { observe() {} disconnect() {} };
global.IntersectionObserver = class { observe() {} disconnect() {} };
global.ResizeObserver = class { observe() {} disconnect() {} };
global.history = { pushState() {}, replaceState() {} };
global.location = global.window.location;
global.Image = class {};
global.CustomEvent = class { constructor(n, o) { Object.assign(this, o); } };
global.Event = global.CustomEvent;
global.dispatchEvent = () => {};
global.getComputedStyle = () => ({ getPropertyValue: () => "" });

const src = fs.readFileSync(process.env.TW_JS || ((process.env.TW_STAGE || "/var/www/html") + "/scripts/dashboard.js"), "utf8");
try {
  new Function(src)();
  console.log("SCRIPT COMPLETED WITHOUT TOP-LEVEL ERROR");
} catch (err) {
  fail(err);
  process.exit(1);
}
// Fire DOMContentLoaded (the real init chain) once parsing is "complete".
global.setTimeout(() => {
  for (const cb of domReady) {
    try { cb({}); } catch (e) { fail(e); }
  }
  console.log("DOMContentLoaded INIT CHAIN COMPLETED CLEAN");
  // Hard exit: the app registers polling intervals that would otherwise
  // keep this process (and any pipeline it feeds) alive until killed.
  process.exit(0);
}, 5);
// Let deferred boot work (timers/microtasks) run to completion.
let waited = 0;
const wait = () => {
  if (crashed) return;
  if (pending.size === 0 && waited > 300) { console.log("BOOT CHAIN FINISHED CLEAN"); process.exit(0); }
  waited += 50;
  setTimeout(wait, 50);
};
setTimeout(wait, 50);
