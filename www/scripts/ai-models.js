/* TuxWall AI assistant: "Models & providers" dialog (phase E).
   Connect AI providers (API key or device-code sign-in), replace/remove
   keys, add a local / OpenAI-compatible server and pick the default model.
   Talks to /api/agent/providers* and /api/agent/models* (admin only); the
   server never returns a full key (masked "••••1234" at most).
   Opened from the AI page sidebar, the model selects ("Connect a provider…")
   and /models. Public: window.twModels.open({ tab, provider }). */
(function () {
  "use strict";

  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function api(method, url, body) {
    const opt = { method, cache: "no-store", headers: {} };
    if (body !== undefined) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    const res = await fetch(url, opt);
    let d = {};
    try { d = await res.json(); } catch (_) { }
    if (res.status === 401) throw new Error("Your session expired. Sign in again.");
    if (res.status === 403) throw new Error("Administrator role required.");
    if (!res.ok || d.ok === false) throw new Error(d.error || ("Request failed (HTTP " + res.status + ")"));
    return d;
  }

  const TABS = [
    ["connected", "Connected"],
    ["connect", "Add provider"],
    ["local", "Local server"],
    ["default", "Default model"],
  ];
  const PRESETS = [
    ["Ollama", "ollama-lan", "http://192.168.1.x:11434/v1"],
    ["LM Studio", "lmstudio-pc", "http://192.168.1.x:1234/v1"],
    ["vLLM", "vllm-server", "http://192.168.1.x:8000/v1"],
    ["llama.cpp", "llamacpp", "http://192.168.1.x:8080/v1"],
    ["LiteLLM", "litellm", "http://192.168.1.x:4000/v1"],
  ];
  const EYE = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
  const EYE_OFF = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 5.1A10.8 10.8 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6A17 17 0 0 0 2 12s3.6 7 10 7a10 10 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>';

  const S = {
    open: false, tab: "connected", data: null, models: null, loading: false,
    sel: null, replace: null, query: "", oauth: null, pollT: 0, editing: null,
    detected: null, opener: null, busy: false,
  };

  // ── DOM ────────────────────────────────────────────────────────────────
  const root = document.createElement("div");
  root.className = "modal aim";
  root.hidden = true;
  root.innerHTML =
    '<div class="modal-box modal-box-wide aim-box" role="dialog" aria-modal="true" aria-labelledby="aim-title" aria-describedby="aim-sub">' +
      '<button type="button" class="modal-close" aria-label="Close" title="Close (Esc)">&times;</button>' +
      '<h3 id="aim-title">Models &amp; providers</h3>' +
      '<p class="aim-sub" id="aim-sub">Connect AI providers, add a local server and choose the default model. Keys stay on the router and are never shown again.</p>' +
      '<div class="aim-tabs" role="tablist" aria-label="Models and providers sections">' +
        TABS.map(([id, label]) =>
          '<button type="button" role="tab" class="aim-tab" id="aim-tab-' + id + '" data-tab="' + id +
          '" aria-controls="aim-pane" aria-selected="false" tabindex="-1">' + label + "</button>").join("") +
      "</div>" +
      '<div class="aim-msg" role="status" aria-live="polite" hidden></div>' +
      '<div class="aim-pane" id="aim-pane" role="tabpanel" tabindex="-1"></div>' +
    "</div>";
  document.body.appendChild(root);
  const box = root.querySelector(".aim-box");
  const pane = root.querySelector(".aim-pane");
  const msgEl = root.querySelector(".aim-msg");

  function say(text, kind) {
    if (!text) { msgEl.hidden = true; msgEl.textContent = ""; return; }
    msgEl.className = "aim-msg aim-msg-" + (kind || "info");
    msgEl.textContent = text;
    msgEl.hidden = false;
  }

  // ── data ───────────────────────────────────────────────────────────────
  async function load(force) {
    S.loading = true;
    try {
      const [p, m] = await Promise.all([
        api("GET", "/api/agent/providers" + (force ? "?refresh=1" : "")),
        api("GET", "/api/agent/models"),
      ]);
      S.data = p;
      S.models = m;
    } finally {
      S.loading = false;
    }
  }
  function modelsChanged() {
    const a = window.twAgent;
    if (a && a.loadModels) a.loadModels(true).catch(() => { });
  }

  // ── rendering ──────────────────────────────────────────────────────────
  function setTab(tab, focusTab) {
    S.tab = tab;
    root.querySelectorAll(".aim-tab").forEach((b) => {
      const on = b.dataset.tab === tab;
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
      b.classList.toggle("is-active", on);
      if (on && focusTab) b.focus();
    });
    pane.setAttribute("aria-labelledby", "aim-tab-" + tab);
    render();
  }

  function render() {
    if (!S.data) {
      pane.innerHTML = '<p class="aim-empty">' + (S.loading ? "Loading…" : "Not loaded.") + "</p>";
      return;
    }
    if (S.tab === "connected") renderConnected();
    else if (S.tab === "connect") renderConnect();
    else if (S.tab === "local") renderLocal();
    else renderDefault();
  }

  function chip(text, kind, title) {
    return '<span class="aim-chip' + (kind ? " aim-chip-" + kind : "") + '"' +
      (title ? ' title="' + esc(title) + '"' : "") + ">" + esc(text) + "</span>";
  }

  function modelCount(pid) {
    return ((S.models && S.models.models) || []).filter((m) => m.provider === pid).length;
  }

  function renderConnected() {
    const d = S.data;
    const rows = [];
    (d.credentials || []).forEach((c) => {
      const multi = (d.credentials || []).filter((x) => x.integrationID === c.integrationID).length > 1;
      rows.push(
        '<li class="aim-row" data-cred="' + esc(c.id) + '" data-int="' + esc(c.integrationID) + '">' +
          '<div class="aim-row-main">' +
            '<div class="aim-row-title">' + esc(c.integrationName || c.integrationID) +
              (c.label ? ' <span class="aim-muted">· ' + esc(c.label) + "</span>" : "") + "</div>" +
            '<div class="aim-row-meta">' +
              (c.type === "key" ? '<code class="aim-key" title="Only the last characters are shown">' + esc(c.masked) + "</code>" : chip(c.masked || c.type, "ok")) +
              (multi ? (c.active ? chip("active", "ok") : chip("inactive")) : "") +
              chip(modelCount(c.integrationID) + " models") +
            "</div>" +
          "</div>" +
          '<div class="aim-row-acts">' +
            '<button type="button" class="btn btn-sm" data-act="test" data-provider="' + esc(c.integrationID) + '">Test</button>' +
            (c.type === "key" ? '<button type="button" class="btn btn-sm" data-act="replace">Change key</button>' : "") +
            (multi && !c.active ? '<button type="button" class="btn btn-sm" data-act="activate">Use this key</button>' : "") +
            '<button type="button" class="btn btn-sm" data-act="remove">Remove</button>' +
          "</div>" +
          '<div class="aim-row-note" hidden></div>' +
        "</li>");
    });
    (d.custom || []).forEach((c) => {
      rows.push(
        '<li class="aim-row" data-custom="' + esc(c.id) + '">' +
          '<div class="aim-row-main">' +
            '<div class="aim-row-title">' + esc(c.name) + ' <span class="aim-muted">· ' + esc(c.id) + "</span></div>" +
            '<div class="aim-row-meta">' + chip("local server", "local") +
              '<code class="aim-url">' + esc(c.baseURL) + "</code>" +
              (c.hasKey ? chip(c.keyInFile ? "key stored" : "key in config", c.keyInFile ? "" : "warn",
                c.keyInFile ? "Stored outside the config file" : "Plain-text key in opencode.json: save once to move it") : "") +
              chip(modelCount(c.id) + " models") +
            "</div>" +
          "</div>" +
          '<div class="aim-row-acts">' +
            '<button type="button" class="btn btn-sm" data-act="test" data-provider="' + esc(c.id) + '">Test</button>' +
            '<button type="button" class="btn btn-sm" data-act="edit">Edit</button>' +
            '<button type="button" class="btn btn-sm" data-act="remove-custom">Remove</button>' +
          "</div>" +
          '<div class="aim-row-note" hidden></div>' +
        "</li>");
    });
    const customIds = new Set((d.custom || []).map((c) => c.id));
    const credInts = new Set((d.credentials || []).map((c) => c.integrationID));
    const builtin = (d.providers || []).filter((p) => !customIds.has(p.id) && !credInts.has(p.id));
    const info = builtin.map((p) =>
      '<li class="aim-row aim-row-quiet">' +
        '<div class="aim-row-main"><div class="aim-row-title">' + esc(p.name) + "</div>" +
        '<div class="aim-row-meta">' +
          (p.id === "opencode" ? chip("built in · free models", "ok") : p.local ? chip("local", "local") : chip("enabled")) +
          (p.baseURL ? '<code class="aim-url">' + esc(p.baseURL) + "</code>" : "") +
          chip(modelCount(p.id) + " models") +
        "</div></div></li>").join("");
    const env = (d.env || []).map((e) =>
      '<li class="aim-row aim-row-quiet"><div class="aim-row-main"><div class="aim-row-title">' + esc(e.integrationName) +
      '</div><div class="aim-row-meta">' + chip("from environment " + e.name) + "</div></div></li>").join("");
    pane.innerHTML =
      (rows.length
        ? '<ul class="aim-list">' + rows.join("") + "</ul>"
        : '<div class="aim-empty"><p>No API keys or servers added yet. The free OpenCode models work without a key.</p></div>') +
      '<div class="aim-actions">' +
        '<button type="button" class="btn btn-sm" data-go="connect">Add provider</button>' +
        '<button type="button" class="btn btn-sm" data-go="local">Add local server</button>' +
      "</div>" +
      (info || env ? '<h4 class="aim-h4">Also available</h4><ul class="aim-list">' + info + env + "</ul>" : "");
  }

  function integration(id) {
    return ((S.data && S.data.integrations) || []).find((i) => i.id === id) || null;
  }

  function renderConnect() {
    if (S.sel) return renderProvider();
    const q = S.query.trim().toLowerCase();
    const list = (S.data.integrations || []).filter((i) =>
      !q || i.name.toLowerCase().includes(q) || i.id.includes(q));
    const row = (i) => {
      const kinds = [];
      if (i.methods.some((m) => m.type === "key")) kinds.push("API key");
      if (i.methods.some((m) => m.type === "oauth" && m.usable)) kinds.push("sign-in");
      const n = (S.data.credentials || []).filter((c) => c.integrationID === i.id).length;
      return '<li><button type="button" class="aim-prov aip-raw" data-int="' + esc(i.id) + '">' +
        '<span class="aim-prov-name">' + esc(i.name) + "</span>" +
        '<span class="aim-prov-meta">' + (n ? chip("connected", "ok") : "") + esc(kinds.join(" · ")) + "</span>" +
        "</button></li>";
    };
    const pop = list.filter((i) => i.popular);
    const rest = list.filter((i) => !i.popular);
    pane.innerHTML =
      '<label class="fw-field aim-search"><span>Search providers</span>' +
        '<input type="text" class="aim-q" role="searchbox" placeholder="Anthropic, OpenAI, OpenRouter…" autocomplete="off" spellcheck="false" value="' + esc(S.query) + '"></label>' +
      (pop.length ? '<h4 class="aim-h4">Popular</h4><ul class="aim-provs">' + pop.map(row).join("") + "</ul>" : "") +
      (rest.length ? '<h4 class="aim-h4">' + (q ? "Other matches" : "All providers") + " (" + rest.length + ')</h4><ul class="aim-provs">' + rest.map(row).join("") + "</ul>" : "") +
      (!list.length ? '<p class="aim-empty">No provider matches “' + esc(S.query) + '”. For a server on your network use <button type="button" class="aim-link aip-raw" data-go="local">Local server</button>.</p>' : "");
  }

  function formFields(form, prefix) {
    return (form || []).filter((f) => !f.hidden).map((f) => {
      const id = "aim-f-" + prefix + "-" + f.key;
      const when = (f.when || []).map((w) => esc(w.key) + "=" + esc(w.value)).join(",");
      const req = f.required ? " required" : "";
      let input;
      if (f.options && f.options.length) {
        input = '<select id="' + id + '" data-key="' + esc(f.key) + '"' + req + ">" +
          f.options.map((o) => '<option value="' + esc(o.value) + '"' + (o.value === f.default ? " selected" : "") + ">" +
            esc(o.label) + (o.description ? " — " + esc(o.description) : "") + "</option>").join("") + "</select>";
      } else {
        input = '<input type="text" id="' + id + '" data-key="' + esc(f.key) + '" autocomplete="off" spellcheck="false"' + req +
          ' placeholder="' + esc(f.placeholder || "") + '" value="' + esc(f.default || "") + '">';
      }
      return '<label class="fw-field" for="' + id + '"' + (when ? ' data-when="' + when + '"' : "") + "><span>" +
        esc(f.title || f.key) + (f.required ? "" : " (optional)") + "</span>" + input +
        (f.description ? '<small class="aim-hint">' + esc(f.description) + "</small>" : "") + "</label>";
    }).join("");
  }
  function applyWhen(scope) {
    scope.querySelectorAll("[data-when]").forEach((el) => {
      const ok = el.dataset.when.split(",").every((cond) => {
        const [k, v] = cond.split("=");
        const src = scope.querySelector('[data-key="' + k + '"]');
        return src && src.value === v;
      });
      el.hidden = !ok;
    });
  }
  function collect(scope) {
    const out = {};
    scope.querySelectorAll("[data-key]").forEach((el) => {
      const lab = el.closest("[data-when]");
      if (lab && lab.hidden) return;
      if (el.value.trim()) out[el.dataset.key] = el.value.trim();
    });
    return out;
  }

  function secretField(id, label, placeholder, hint) {
    return '<div class="fw-field aim-secret"><span><label for="' + id + '">' + esc(label) + "</label></span>" +
      '<div class="aim-secret-wrap">' +
        '<input type="password" id="' + id + '" autocomplete="new-password" spellcheck="false" autocapitalize="off" placeholder="' + esc(placeholder || "") + '">' +
        '<button type="button" class="aim-eye aip-raw" data-eye="' + id + '" aria-label="Show key" aria-pressed="false" title="Show key">' + EYE + "</button>" +
      "</div>" + (hint ? '<small class="aim-hint">' + hint + "</small>" : "") + "</div>";
  }

  function renderProvider() {
    const i = integration(S.sel);
    if (!i) { S.sel = null; return renderConnect(); }
    const key = i.methods.find((m) => m.type === "key");
    const oauth = i.methods.filter((m) => m.type === "oauth" && m.usable);
    const env = i.methods.find((m) => m.type === "env");
    const rep = S.replace ? (S.data.credentials || []).find((c) => c.id === S.replace) : null;
    let html = '<button type="button" class="aim-back aim-link aip-raw" data-back="1">← All providers</button>' +
      '<h4 class="aim-h4 aim-prov-head">' + esc(i.name) + "</h4>";
    if (rep) html += '<p class="aim-note">Replacing key <code class="aim-key">' + esc(rep.masked) + "</code>" +
      (rep.label ? " (" + esc(rep.label) + ")" : "") + ". The old key is removed after the new one is saved.</p>";
    if (S.oauth) {
      const o = S.oauth;
      html += '<div class="aim-oauth" aria-live="polite">' +
        '<p class="aim-oauth-step">1. Open this page on your phone or computer:</p>' +
        '<p><a class="aim-oauth-url" href="' + esc(o.url) + '" target="_blank" rel="noopener noreferrer">' + esc(o.url) + "</a></p>" +
        (o.code ? '<p class="aim-oauth-step">2. Enter this code:</p><p class="aim-oauth-code"><code>' + esc(o.code) + '</code> <button type="button" class="btn btn-sm" data-act="copy-code">Copy code</button></p>'
          : '<p class="aim-oauth-step">' + esc(o.instructions) + "</p>") +
        '<p class="aim-oauth-status">' + esc(o.status === "pending" ? "Waiting for you to finish signing in…" : o.status) + "</p>" +
        '<div class="aim-actions"><button type="button" class="btn btn-sm" data-act="oauth-cancel">Cancel</button></div></div>';
      pane.innerHTML = html;
      return;
    }
    if (key) {
      html += '<form class="aim-form" data-form="key" novalidate>' +
        secretField("aim-key", key.label && key.label !== "API key" ? key.label : "API key", "Paste the key",
          "Stored by the agent on the router. Only the last 4 characters are ever shown again.") +
        formFields(key.form, "k") +
        '<label class="fw-field" for="aim-label"><span>Label (optional)</span>' +
          '<input type="text" id="aim-label" maxlength="60" autocomplete="off" placeholder="e.g. personal, work" value="' + esc(rep ? rep.label : "") + '"></label>' +
        '<div class="aim-actions"><button type="submit" class="btn btn-sm btn-primary">' + (rep ? "Save new key" : "Add key") + "</button>" +
        (rep ? '<button type="button" class="btn btn-sm" data-back="1">Cancel</button>' : "") + "</div>" +
        "</form>";
    }
    if (oauth.length && !rep) {
      html += '<h4 class="aim-h4">' + (key ? "Or sign in with an account" : "Sign in with an account") + "</h4>" +
        oauth.map((m) =>
          '<form class="aim-form aim-form-oauth" data-form="oauth" data-method="' + esc(m.id) + '" novalidate>' +
            formFields(m.form, "o-" + m.id) +
            '<div class="aim-actions"><button type="submit" class="btn btn-sm">' + esc(/^sign in|^log ?in/i.test(m.label) ? m.label : "Sign in: " + m.label) + "</button></div>" +
          "</form>").join("") +
        '<p class="aim-hint">You get a link and a short code to enter on any device; this page finishes the connection by itself.</p>';
    }
    if (env && env.names && env.names.length) {
      html += '<p class="aim-hint">Also read from the agent\'s environment: ' + env.names.map((n) => "<code>" + esc(n) + "</code>").join(", ") + ".</p>";
    }
    pane.innerHTML = html;
    pane.querySelectorAll(".aim-form").forEach(applyWhen);
    const k = pane.querySelector("#aim-key");
    if (k) setTimeout(() => k.focus(), 30);
  }

  function renderLocal() {
    const c = S.editing ? (S.data.custom || []).find((x) => x.id === S.editing) : null;
    const models = S.detected || (c ? c.models : []);
    pane.innerHTML =
      '<p class="aim-note">Any OpenAI-compatible server: Ollama, LM Studio, vLLM, llama.cpp, LiteLLM… The URL usually ends in <code>/v1</code>.</p>' +
      (c ? "" : '<div class="aim-presets" role="group" aria-label="Presets">' + PRESETS.map((p, n) =>
        '<button type="button" class="aim-preset aip-raw" data-preset="' + n + '">' + esc(p[0]) + "</button>").join("") + "</div>") +
      '<form class="aim-form" data-form="local" novalidate>' +
        '<div class="aim-grid">' +
          '<label class="fw-field" for="aim-l-name"><span>Name</span><input type="text" id="aim-l-name" maxlength="60" autocomplete="off" placeholder="e.g. LM Studio PC" value="' + esc(c ? c.name : "") + '"></label>' +
          '<label class="fw-field" for="aim-l-id"><span>ID (used in model names)</span><input type="text" id="aim-l-id" maxlength="40" autocomplete="off" spellcheck="false" placeholder="lmstudio-pc" value="' + esc(c ? c.id : "") + '"' + (c ? " readonly" : "") + "></label>" +
        "</div>" +
        '<label class="fw-field" for="aim-l-url"><span>Server URL</span><input type="text" inputmode="url" id="aim-l-url" autocomplete="off" spellcheck="false" placeholder="http://192.168.1.20:1234/v1" value="' + esc(c ? c.baseURL : "") + '"></label>' +
        secretField("aim-l-key", "API key (optional)", c && c.hasKey ? "Stored: leave empty to keep it" : "Only if the server needs one",
          "Saved in " + esc(S.data.keysDir || "/etc/tuxwall/agent/keys") + ", not in the config file.") +
        (c && c.hasKey ? '<label class="fw-field aim-check"><input type="checkbox" id="aim-l-clear"> <span>Remove the stored key</span></label>' : "") +
        '<label class="fw-field" for="aim-l-models"><span>Model IDs (one per line)</span>' +
          '<textarea id="aim-l-models" rows="4" spellcheck="false" placeholder="qwen3:8b">' + esc(models.join("\n")) + "</textarea></label>" +
        '<div class="aim-actions">' +
          '<button type="button" class="btn btn-sm" data-act="detect">Detect models</button>' +
          '<button type="submit" class="btn btn-sm btn-primary">' + (c ? "Save server" : "Save server") + "</button>" +
          (c ? '<button type="button" class="btn btn-sm" data-act="cancel-edit">Cancel</button>' : "") +
        "</div>" +
      "</form>";
  }

  function priceHint(m) {
    if (m.local) return "local";
    if (m.free) return "free";
    if (m.cost && (m.cost.input || m.cost.output)) return "$" + fmt(m.cost.input) + "/$" + fmt(m.cost.output) + " per 1M";
    return "";
  }
  function fmt(n) {
    n = Number(n) || 0;
    return n >= 10 ? String(Math.round(n)) : String(Math.round(n * 100) / 100);
  }

  function renderDefault() {
    const m = S.models || {};
    const list = m.models || [];
    const groups = m.groups || [];
    const conf = m.configured || "";
    const eff = m.default || "";
    const effName = (list.find((x) => x.id === eff) || {}).name || m.effective_name || eff;
    let warn = "";
    if (conf && !m.configured_ok) {
      warn = '<p class="aim-warn">The configured default <code>' + esc(conf) + "</code> is not available, so opencode is using <b>" +
        esc(effName || "its own pick") + "</b>. Pick a default below to fix this.</p>";
    }
    const selVal = conf ? (m.configured_ok ? conf : eff) : "";
    const opts = groups.map((g) =>
      '<optgroup label="' + esc(g.name) + (g.local ? " (local)" : "") + '">' +
      list.filter((x) => x.provider === g.id).map((x) => {
        const h = priceHint(x);
        return '<option value="' + esc(x.id) + '"' + (x.id === selVal ? " selected" : "") + ">" +
          esc(x.name) + (h && !(h === "free" && /free/i.test(x.name)) ? " · " + esc(h) : "") + "</option>";
      }).join("") + "</optgroup>").join("");
    pane.innerHTML =
      '<p class="aim-note">Used for new conversations and whenever no model is picked. The model picker in the chat switches the current conversation only.</p>' +
      warn +
      '<dl class="aim-facts"><dt>In use now</dt><dd>' + esc(effName) + ' <code>' + esc(eff) + "</code></dd>" +
      "<dt>Configured</dt><dd>" + (conf ? "<code>" + esc(conf) + "</code>" : "automatic (opencode picks)") + "</dd></dl>" +
      '<form class="aim-form" data-form="default" novalidate>' +
        '<label class="fw-field" for="aim-def"><span>Default model</span><select id="aim-def">' +
          '<option value="">Automatic (opencode picks)</option>' + opts + "</select></label>" +
        '<div class="aim-actions"><button type="submit" class="btn btn-sm btn-primary">Save default</button></div>' +
      "</form>";
  }

  // ── actions ────────────────────────────────────────────────────────────
  function setBusy(btn, on, label) {
    if (!btn) return;
    if (on) { btn.dataset.label = btn.textContent; btn.textContent = label || "Working…"; btn.disabled = true; }
    else { btn.textContent = btn.dataset.label || btn.textContent; btn.disabled = false; }
  }

  async function refreshAll(msg, kind) {
    await load(true);
    render();
    if (msg) say(msg, kind);
    modelsChanged();
  }

  async function submitKey(form, btn) {
    const keyEl = form.querySelector("#aim-key");
    const key = keyEl.value.trim();
    if (!key) { say("Paste the API key first.", "error"); keyEl.focus(); return; }
    const i = integration(S.sel);
    const body = { integrationID: S.sel, key, label: (form.querySelector("#aim-label") || {}).value || "" };
    const ans = collect(form);
    if (Object.keys(ans).length) body.answer = ans;
    if (S.replace) body.replaceCredentialID = S.replace;
    keyEl.value = "";
    setBusy(btn, true, "Saving…");
    try {
      const r = await api("POST", "/api/agent/providers/connect", body);
      body.key = "";
      S.replace = null;
      S.sel = null;
      S.tab = "connected";
      setTab("connected");
      await refreshAll((r.message || (i ? i.name : "Provider") + " connected") +
        ". Keys are checked on first use: press Test to try it now.", "ok");
    } catch (err) {
      body.key = "";
      say(err.message, "error");
      setBusy(btn, false);
      keyEl.focus();
    }
  }

  function stopPoll() { if (S.pollT) { clearTimeout(S.pollT); S.pollT = 0; } }
  async function cancelOAuth(silent) {
    stopPoll();
    const o = S.oauth;
    S.oauth = null;
    if (o) {
      try { await api("POST", "/api/agent/providers/oauth/cancel", { integrationID: o.integrationID, attemptID: o.attemptID }); } catch (_) { }
    }
    if (!silent && S.open) { render(); say("Sign-in cancelled.", "info"); }
  }
  async function startOAuth(form, btn) {
    const body = { integrationID: S.sel, methodID: form.dataset.method };
    const ans = collect(form);
    if (Object.keys(ans).length) body.answer = ans;
    setBusy(btn, true, "Starting…");
    try {
      const r = await api("POST", "/api/agent/providers/oauth/start", body);
      S.oauth = { integrationID: S.sel, attemptID: r.attemptID, url: r.url, code: r.code,
        instructions: r.instructions, status: "pending" };
      say("", "");
      render();
      poll();
    } catch (err) {
      say(err.message, "error");
      setBusy(btn, false);
    }
  }
  function poll() {
    stopPoll();
    S.pollT = setTimeout(async () => {
      const o = S.oauth;
      if (!o || !S.open) return;
      try {
        const r = await api("GET", "/api/agent/providers/oauth/status?integrationID=" +
          encodeURIComponent(o.integrationID) + "&attemptID=" + encodeURIComponent(o.attemptID));
        if (S.oauth !== o) return;
        if (r.status === "complete") {
          S.oauth = null; S.sel = null;
          setTab("connected");
          await refreshAll("Signed in. The provider's models are now in the model list.", "ok");
          return;
        }
        if (r.status === "failed" || r.status === "expired") {
          S.oauth = null;
          render();
          say(r.status === "expired" ? "The sign-in code expired. Start again." : ("Sign-in failed: " + (r.message || "unknown error")), "error");
          return;
        }
      } catch (err) {
        say(err.message, "error");
      }
      poll();
    }, 3000);
  }

  async function saveLocal(form, btn) {
    const val = (id) => ((form.querySelector(id) || {}).value || "").trim();
    const keyEl = form.querySelector("#aim-l-key");
    const body = {
      id: val("#aim-l-id"), name: val("#aim-l-name"), baseURL: val("#aim-l-url"),
      models: val("#aim-l-models").split(/[\s,]+/).filter(Boolean),
    };
    if (!body.id && body.name) body.id = slug(body.name);
    if (keyEl && keyEl.value.trim()) body.apiKey = keyEl.value.trim();
    const clr = form.querySelector("#aim-l-clear");
    if (clr && clr.checked) body.clearKey = true;
    if (keyEl) keyEl.value = "";
    setBusy(btn, true, "Saving…");
    say("Saving; the agent reloads its configuration (a few seconds)…", "info");
    try {
      const r = await api("POST", "/api/agent/providers/custom", body);
      body.apiKey = "";
      S.editing = null; S.detected = null;
      setTab("connected");
      await refreshAll((body.name || r.id) + ": " + (r.message || "saved"), r.loaded ? "ok" : "warn");
    } catch (err) {
      body.apiKey = "";
      say(err.message, "error");
      setBusy(btn, false);
    }
  }
  async function detect(btn) {
    const form = pane.querySelector('[data-form="local"]');
    const url = form.querySelector("#aim-l-url").value.trim();
    const keyEl = form.querySelector("#aim-l-key");
    if (!url) { say("Enter the server URL first.", "error"); form.querySelector("#aim-l-url").focus(); return; }
    const body = { baseURL: url, id: form.querySelector("#aim-l-id").value.trim() };
    if (keyEl.value.trim()) body.apiKey = keyEl.value.trim();
    setBusy(btn, true, "Detecting…");
    try {
      const r = await api("POST", "/api/agent/providers/custom/detect", body);
      body.apiKey = "";
      const ta = form.querySelector("#aim-l-models");
      ta.value = (r.models || []).join("\n");
      say(r.models.length ? "Found " + r.models.length + " model(s). Remove any you don't want, then save." : "The server answered but listed no models; enter the IDs by hand.", r.models.length ? "ok" : "warn");
    } catch (err) {
      body.apiKey = "";
      say(err.message, "error");
    } finally {
      setBusy(btn, false);
    }
  }
  function slug(s) {
    return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
  }

  async function test(btn, provider, note) {
    setBusy(btn, true, "Testing…");
    note.hidden = false;
    note.className = "aim-row-note";
    note.textContent = "Sending a one-line test prompt…";
    try {
      const r = await api("POST", "/api/agent/providers/test", { provider });
      note.className = "aim-row-note " + (r.passed ? "is-ok" : "is-err");
      note.textContent = (r.passed ? "Works: " : "Failed: ") + r.message + " (" + r.model + ")";
    } catch (err) {
      note.className = "aim-row-note is-err";
      note.textContent = err.message;
    } finally {
      setBusy(btn, false);
    }
  }

  async function confirmBox(text) {
    if (window.twConfirm) return window.twConfirm(text);
    return window.confirm(text);
  }

  pane.addEventListener("click", async (e) => {
    const go = e.target.closest("[data-go]");
    if (go) { S.sel = null; S.replace = null; S.editing = null; S.detected = null; setTab(go.dataset.go); return; }
    const back = e.target.closest("[data-back]");
    if (back) { await cancelOAuth(true); S.sel = null; S.replace = null; say(""); render(); return; }
    const prov = e.target.closest(".aim-prov");
    if (prov) { S.sel = prov.dataset.int; S.replace = null; say(""); render(); return; }
    const preset = e.target.closest("[data-preset]");
    if (preset) {
      const p = PRESETS[+preset.dataset.preset];
      const f = pane.querySelector('[data-form="local"]');
      f.querySelector("#aim-l-name").value = p[0];
      f.querySelector("#aim-l-id").value = p[1];
      const u = f.querySelector("#aim-l-url");
      u.value = p[2];
      u.focus();
      const at = p[2].indexOf("1.x");
      try { u.setSelectionRange(at + 2, at + 3); } catch (_) { }
      return;
    }
    const eye = e.target.closest("[data-eye]");
    if (eye) {
      const inp = pane.querySelector("#" + eye.dataset.eye);
      const show = inp.type === "password";
      inp.type = show ? "text" : "password";
      eye.innerHTML = show ? EYE_OFF : EYE;
      eye.setAttribute("aria-pressed", show ? "true" : "false");
      eye.setAttribute("aria-label", show ? "Hide key" : "Show key");
      eye.title = show ? "Hide key" : "Show key";
      inp.focus();
      return;
    }
    const btn = e.target.closest("[data-act]");
    if (!btn) return;
    const act = btn.dataset.act;
    const row = btn.closest(".aim-row");
    if (act === "test") return test(btn, btn.dataset.provider, row.querySelector(".aim-row-note"));
    if (act === "replace") {
      S.sel = row.dataset.int; S.replace = row.dataset.cred; say("");
      setTab("connect");
      return;
    }
    if (act === "activate" || act === "remove") {
      const cid = row.dataset.cred;
      const c = (S.data.credentials || []).find((x) => x.id === cid) || {};
      if (act === "remove" && !(await confirmBox("Remove the " + (c.integrationName || "") + " key " + (c.masked || "") +
        "? Its models disappear from the list until you add a key again."))) return;
      setBusy(btn, true, act === "remove" ? "Removing…" : "Saving…");
      try {
        await api("POST", "/api/agent/providers/" + act, { credentialID: cid });
        await refreshAll(act === "remove" ? "Key removed." : "Key activated.", "ok");
      } catch (err) { say(err.message, "error"); setBusy(btn, false); }
      return;
    }
    if (act === "edit") { S.editing = row.dataset.custom; S.detected = null; setTab("local"); return; }
    if (act === "cancel-edit") { S.editing = null; S.detected = null; setTab("connected"); return; }
    if (act === "remove-custom") {
      const id = row.dataset.custom;
      if (!(await confirmBox("Remove the local server '" + id + "' and its stored key? Its models disappear from the list."))) return;
      setBusy(btn, true, "Removing…");
      say("Removing; the agent reloads its configuration…", "info");
      try {
        await api("POST", "/api/agent/providers/custom/remove", { id });
        await refreshAll("Server removed.", "ok");
      } catch (err) { say(err.message, "error"); setBusy(btn, false); }
      return;
    }
    if (act === "detect") return detect(btn);
    if (act === "oauth-cancel") return cancelOAuth(false);
    if (act === "copy-code") {
      try { await navigator.clipboard.writeText(S.oauth.code); say("Code copied.", "ok"); }
      catch (_) { say("Copy failed; type the code shown.", "warn"); }
    }
  });

  pane.addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const btn = form.querySelector('[type="submit"]');
    if (form.dataset.form === "key") return submitKey(form, btn);
    if (form.dataset.form === "oauth") return startOAuth(form, btn);
    if (form.dataset.form === "local") return saveLocal(form, btn);
    if (form.dataset.form === "default") {
      const model = form.querySelector("#aim-def").value;
      setBusy(btn, true, "Saving…");
      try {
        const r = await api("POST", "/api/agent/models/default", { model });
        await refreshAll(r.applied ? "Default model saved." : "Saved; the agent has not picked it up yet.", r.applied ? "ok" : "warn");
      } catch (err) { say(err.message, "error"); setBusy(btn, false); }
    }
  });

  pane.addEventListener("input", (e) => {
    if (e.target.classList.contains("aim-q")) {
      S.query = e.target.value;
      const pos = e.target.selectionStart;
      renderConnect();
      const q = pane.querySelector(".aim-q");
      q.focus();
      try { q.setSelectionRange(pos, pos); } catch (_) { }
    } else if (e.target.id === "aim-l-name" && !S.editing) {
      const idEl = pane.querySelector("#aim-l-id");
      if (idEl && (!idEl.value || idEl.dataset.auto === "1")) { idEl.value = slug(e.target.value); idEl.dataset.auto = "1"; }
    } else if (e.target.id === "aim-l-id") {
      e.target.dataset.auto = "0";
    }
  });
  pane.addEventListener("change", (e) => {
    const f = e.target.closest(".aim-form");
    if (f && e.target.dataset.key) applyWhen(f);
  });

  root.querySelector(".aim-tabs").addEventListener("click", (e) => {
    const t = e.target.closest(".aim-tab");
    if (!t) return;
    cancelOAuth(true);
    S.sel = null; S.replace = null; S.editing = null; S.detected = null;
    say("");
    setTab(t.dataset.tab);
  });
  root.querySelector(".aim-tabs").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft" && e.key !== "Home" && e.key !== "End") return;
    e.preventDefault();
    const ids = TABS.map((t) => t[0]);
    let n = ids.indexOf(S.tab);
    n = e.key === "Home" ? 0 : e.key === "End" ? ids.length - 1 : (n + (e.key === "ArrowRight" ? 1 : -1) + ids.length) % ids.length;
    cancelOAuth(true);
    S.sel = null; S.replace = null; S.editing = null;
    say("");
    setTab(ids[n], true);
  });
  root.querySelector(".modal-close").addEventListener("click", () => close());
  root.addEventListener("mousedown", (e) => { if (e.target === root) close(); });
  document.addEventListener("keydown", (e) => {
    if (!S.open) return;
    if (e.key === "Escape") {
      if (document.querySelector(".tw-dialog-backdrop")) return;   // confirm dialog on top
      e.preventDefault();
      e.stopPropagation();
      close();
    } else if (e.key === "Tab") {
      const f = [...box.querySelectorAll('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex="0"]')]
        .filter((x) => x.offsetParent !== null);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }, true);

  async function open(opts) {
    opts = opts || {};
    const a = window.twAgent;
    if (a && a.isAdmin && !a.isAdmin()) return;
    S.opener = document.activeElement;
    S.sel = opts.provider || null;
    S.replace = null; S.editing = null; S.detected = null; S.query = "";
    S.tab = opts.tab || (opts.provider ? "connect" : "connected");
    S.open = true;
    root.hidden = false;
    document.documentElement.classList.add("aim-open");
    say("");
    setTab(S.tab);
    root.querySelector(".aim-tab.is-active").focus();
    try {
      await load(false);
      if (!S.open) return;
      setTab(S.tab);
    } catch (err) {
      pane.innerHTML = "";
      say(err.message, "error");
    }
  }
  function close() {
    if (!S.open) return;
    cancelOAuth(true);
    S.open = false;
    root.hidden = true;
    document.documentElement.classList.remove("aim-open");
    pane.innerHTML = "";
    say("");
    const o = S.opener;
    S.opener = null;
    if (o && o.focus && document.contains(o)) setTimeout(() => o.focus(), 0);
  }

  window.twModels = { open, close, priceHint };
})();
