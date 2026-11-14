/* TuxWall header assistant: a right-side slide-over chat with the opencode
   agent. Shares the current session with the AI Assistant page (#ai) and
   the page's SSE stream through window.twAgent (dashboard.js).
   window.twAsk({ text, context }) opens the panel with a question pre-filled
   (never auto-sent). */
(function () {
  "use strict";

  const btn = document.getElementById("ai-panel-btn");
  if (!btn) return;

  const SHORTCUT = "Ctrl+/";
  const WATCHDOG_MS = 180000;
  const PRETTY = {
    bash: "Bash", shell: "Shell", read: "Read", edit: "Edit", write: "Write", glob: "Glob",
    grep: "Grep", list: "List", webfetch: "Web fetch", websearch: "Web search",
    todowrite: "Todo", "todo-write": "Todo", "todo-read": "Todo", task: "Task",
    multiedit: "Multi edit", question: "Question", skill: "Skill", patch: "Patch",
  };

  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const svg = (body) => '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + body + "</svg>";
  const IC = {
    spark: svg('<path d="m12 3 1.7 5.3L19 10l-5.3 1.7L12 17l-1.7-5.3L5 10l5.3-1.7L12 3Z"/><path d="m18.5 15 .8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2Z"/>'),
    plus: svg('<path d="M12 5v14M5 12h14"/>'),
    expand: svg('<path d="M14 4h6v6"/><path d="m20 4-7 7"/><path d="M10 20H4v-6"/><path d="m4 20 7-7"/>'),
    close: svg('<path d="M6 6l12 12M18 6 6 18"/>'),
    send: svg('<path d="M12 19V5"/><path d="m5 12 7-7 7 7"/>'),
    stop: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="7" y="7" width="10" height="10" rx="2" fill="currentColor"/></svg>',
    page: svg('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 4v5"/>'),
    x: svg('<path d="M7 7l10 10M17 7 7 17"/>'),
    alert: svg('<path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4M12 17h.01"/>'),
    lock: svg('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
    help: svg('<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .9-1 1.7M12 17h.01"/>'),
  };

  // ── markdown (escape first, then a small safe subset) ───────────────
  const LIST_RE = /^(\s*)([-*+]|\d{1,3}[.)])\s+(.*)$/;
  const FENCE_RE = /^\s{0,3}(```+|~~~+)\s*([\w+#.-]*)\s*$/;
  const HR_RE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/;
  const TSEP_RE = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
  const indentOf = (l) => (/^\s*/.exec(l)[0].replace(/\t/g, "    ").length);

  function inline(src) {
    const codes = [];
    let s = String(src).replace(/`([^`\n]+)`/g, (_, c) => { codes.push(c); return "\u0000" + (codes.length - 1) + "\u0000"; });
    s = esc(s);
    s = s.replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, t, u) =>
      '<a href="' + u + '" target="_blank" rel="noopener noreferrer">' + t + "</a>");
    s = s.replace(/(^|[\s(])(https?:\/\/[^\s<)]+[^\s<).,;:!?'"])/g, (_, p, u) =>
      p + '<a href="' + u + '" target="_blank" rel="noopener noreferrer">' + u + "</a>");
    s = s.replace(/\*\*(?=\S)([^*]*?\S)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^\w])__(?=\S)([^_]*?\S)__(?!\w)/g, "$1<strong>$2</strong>");
    s = s.replace(/(^|[^*\w])\*(?=[^\s*])([^*\n]*?[^\s*])\*(?!\*)/g, "$1<em>$2</em>");
    s = s.replace(/(^|[^\w])_(?=[^\s_])([^_\n]*?[^\s_])_(?!\w)/g, "$1<em>$2</em>");
    s = s.replace(/~~(?=\S)([^~]*?\S)~~/g, "<del>$1</del>");
    s = s.replace(/\u0000(\d+)\u0000/g, (_, i) => "<code>" + esc(codes[+i]) + "</code>");
    return s.replace(/\n/g, "<br>");
  }

  function isBlockStart(l) {
    return FENCE_RE.test(l) || /^\s{0,3}#{1,6}\s/.test(l) || LIST_RE.test(l) ||
      /^\s{0,3}>/.test(l) || HR_RE.test(l);
  }

  function md(src) {
    const lines = String(src || "").replace(/\r\n?/g, "\n").split("\n");
    let html = "";
    let i = 0;
    while (i < lines.length) {
      const ln = lines[i];
      if (!ln.trim()) { i++; continue; }
      let m = FENCE_RE.exec(ln);
      if (m) {
        const fence = m[1];
        const buf = [];
        i++;
        while (i < lines.length && !lines[i].trim().startsWith(fence)) buf.push(lines[i++]);
        i++;
        html += '<pre class="aip-code"><code>' + esc(buf.join("\n")) + "</code></pre>";
        continue;
      }
      m = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/.exec(ln);
      if (m) { html += '<p class="aip-h aip-h' + m[1].length + '">' + inline(m[2]) + "</p>"; i++; continue; }
      if (HR_RE.test(ln) && !LIST_RE.test(ln.replace(/^(\s*[-*+])\s+[-*+].*$/, ""))) { html += "<hr>"; i++; continue; }
      if (ln.indexOf("|") !== -1 && i + 1 < lines.length && TSEP_RE.test(lines[i + 1])) {
        const cells = (l) => l.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
        const head = cells(ln);
        i += 2;
        const rows = [];
        while (i < lines.length && lines[i].indexOf("|") !== -1 && lines[i].trim()) rows.push(cells(lines[i++]));
        html += '<div class="aip-table"><table><thead><tr>' + head.map((c) => "<th>" + inline(c) + "</th>").join("") +
          "</tr></thead><tbody>" + rows.map((r) => "<tr>" + head.map((_, k) => "<td>" + inline(r[k] || "") + "</td>").join("") + "</tr>").join("") +
          "</tbody></table></div>";
        continue;
      }
      if (/^\s{0,3}>/.test(ln)) {
        const buf = [];
        while (i < lines.length && /^\s{0,3}>/.test(lines[i])) buf.push(lines[i++].replace(/^\s{0,3}>\s?/, ""));
        html += "<blockquote>" + md(buf.join("\n")) + "</blockquote>";
        continue;
      }
      m = LIST_RE.exec(ln);
      if (m) {
        const base = indentOf(m[1]);
        const ordered = /\d/.test(m[2]);
        const items = [];
        while (i < lines.length) {
          const l = lines[i];
          const mm = LIST_RE.exec(l);
          if (mm && indentOf(mm[1]) <= base + 1 && /\d/.test(mm[2]) === ordered) {
            items.push({ n: parseInt(mm[2], 10), lines: [mm[3]], off: mm[1].length + mm[2].length + 1 });
            i++; continue;
          }
          if (mm && indentOf(mm[1]) <= base + 1) break;
          const last = items[items.length - 1];
          if (!l.trim()) {
            let j = i + 1;
            while (j < lines.length && !lines[j].trim()) j++;
            if (j < lines.length && indentOf(lines[j]) > base) { last.lines.push(""); i++; continue; }
            break;
          }
          if (indentOf(l) > base) { last.lines.push(l.replace(new RegExp("^\\s{0," + last.off + "}"), "")); i++; continue; }
          if (!isBlockStart(l) && last.lines[last.lines.length - 1] !== "") { last.lines.push(l); i++; continue; }
          break;
        }
        const tag = ordered ? "ol" : "ul";
        const start = ordered && items[0].n > 1 ? ' start="' + items[0].n + '"' : "";
        html += "<" + tag + start + ">" + items.map((it) => {
          let inner = md(it.lines.join("\n"));
          const one = /^<p>([\s\S]*)<\/p>$/.exec(inner);
          if (one && one[1].indexOf("<p>") === -1) inner = one[1];
          return "<li>" + inner + "</li>";
        }).join("") + "</" + tag + ">";
        continue;
      }
      const buf = [];
      while (i < lines.length && lines[i].trim() && !(buf.length && isBlockStart(lines[i])) &&
             !(lines[i].indexOf("|") !== -1 && i + 1 < lines.length && TSEP_RE.test(lines[i + 1]))) {
        buf.push(lines[i++]);
      }
      if (!buf.length) buf.push(lines[i++]);
      html += "<p>" + inline(buf.join("\n")) + "</p>";
    }
    return html;
  }

  // ── DOM ──────────────────────────────────────────────────────────────
  const panel = document.createElement("aside");
  panel.id = "ai-panel";
  panel.className = "aip";
  panel.hidden = true;
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-modal", "false");
  panel.setAttribute("aria-label", "Assistant");
  panel.innerHTML =
    '<div class="aip-head">' +
      '<span class="aip-logo" aria-hidden="true">' + IC.spark + "</span>" +
      '<h2 class="aip-title" id="aip-title">Assistant</h2>' +
      '<label class="aip-sr" for="aip-model">Model</label>' +
      '<select class="aip-model" id="aip-model" title="Model (shared with the AI Assistant page)"><option value="">Loading…</option></select>' +
      '<button type="button" class="aip-icon-btn" data-aip="new" aria-label="New chat" title="New chat">' + IC.plus + "</button>" +
      '<button type="button" class="aip-icon-btn" data-aip="full" aria-label="Open full view" title="Open full view (AI Assistant page)">' + IC.expand + "</button>" +
      '<button type="button" class="aip-icon-btn" data-aip="close" aria-label="Close assistant" title="Close (Esc)">' + IC.close + "</button>" +
    "</div>" +
    '<div class="aip-log" role="log" aria-live="polite" aria-relevant="additions text" aria-label="Conversation" tabindex="-1"></div>' +
    '<div class="aip-foot">' +
      '<div class="aip-ctx-row"></div>' +
      '<div class="aip-compose">' +
        '<textarea class="aip-input" rows="1" placeholder="Ask about your network…" aria-label="Message the assistant" spellcheck="true"></textarea>' +
        '<button type="button" class="aip-send" aria-label="Send">' + IC.send + "</button>" +
      "</div>" +
      '<div class="aip-hint"><span><kbd>Enter</kbd> send · <kbd>Shift</kbd>+<kbd>Enter</kbd> new line</span><span class="aip-hint-r">Same chat as the AI Assistant page</span></div>' +
    "</div>";
  document.body.appendChild(panel);

  const $ = (sel) => panel.querySelector(sel);
  const elLog = $(".aip-log");
  const elInput = $(".aip-input");
  const elSend = $(".aip-send");
  const elModel = $(".aip-model");
  const elCtxRow = $(".aip-ctx-row");
  btn.setAttribute("aria-controls", "ai-panel");

  // ── state ────────────────────────────────────────────────────────────
  const S = {
    open: false,
    sid: null,
    busy: false,          // a turn is running for the current session
    own: false,           // ...and this panel started it
    turnSid: null,
    turn: null,           // live render state
    lastPrompt: "",
    unsub: null,
    watchdog: null,
    ctxOff: false,
    ctxKey: "",
    ctxOverride: null,
    permTimer: null,
    loadSeq: 0,
    stick: true,
  };
  const api = () => window.twAgent;

  // ── context chip ─────────────────────────────────────────────────────
  const clean = (s) => String(s || "").replace(/[\]\[\n\r]+/g, " ").replace(/\s+/g, " ").trim();
  const shortText = (el) => {
    const c = el.cloneNode(true);
    c.querySelectorAll(".fw-chip-n, .fwp-dot, .badge, .tab-badge, svg, [aria-hidden='true']").forEach((x) => x.remove());
    return clean(c.textContent);
  };
  function pageContext() {
    const nav = document.querySelector(".nav-item.active[data-view]");
    const view = nav && nav.dataset.view;
    if (!view || view === "ai") return null;
    const viewEl = document.getElementById(view.indexOf("plugin:") === 0 ? "view-plugin-" + view.slice(7) : "view-" + view);
    const label = nav.querySelector("span") ? clean(nav.querySelector("span").textContent) : clean((document.getElementById("page-title") || {}).textContent);
    let sub = "";
    let scope = viewEl;
    const strip = viewEl && viewEl.querySelector(".fw-subtabs");
    const tab = strip && strip.querySelector(".fw-subtab.active");
    if (tab) {
      sub = shortText(tab);
      const key = Object.keys(tab.dataset).find((k) => /Pane$/.test(k));
      if (key) {
        const attr = "data-" + key.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase());
        const pane = [...viewEl.querySelectorAll(".fw-pane[" + attr + "]")].find((p) => p.getAttribute(attr) === tab.dataset[key] && !p.hidden);
        if (pane) scope = pane;
      }
    }
    const details = [];
    if (scope) {
      scope.querySelectorAll('input[type="search"]').forEach((inp) => {
        const v = clean(inp.value);
        if (v && inp.offsetParent !== null) details.push('filter "' + v.slice(0, 60) + '"');
      });
      scope.querySelectorAll(".fw-chip-row").forEach((row) => {
        if (row.offsetParent === null) return;
        const on = row.querySelector(".fw-chip.active");
        if (!on) return;
        const t = shortText(on);
        if (!t || /^all$/i.test(t)) return;
        const lbId = row.getAttribute("aria-labelledby");
        const lb = lbId && document.getElementById(lbId);
        details.push((lb ? clean(lb.textContent) + ": " : "") + t);
      });
    }
    const where = label + (sub ? " › " + sub : "");
    return { key: view + "/" + sub, where, details: details.slice(0, 4).join(", ") };
  }
  function currentContext() {
    if (S.ctxOverride) return { key: "override", where: clean(S.ctxOverride), details: "" };
    return pageContext();
  }
  function contextLine(ctx) {
    return ctx.where + (ctx.details ? "; " + ctx.details : "");
  }
  function renderCtx() {
    const ctx = currentContext();
    if (ctx && ctx.key !== S.ctxKey) { S.ctxKey = ctx.key; if (!S.ctxOverride) S.ctxOff = false; }
    elCtxRow.innerHTML = "";
    if (!ctx) { elCtxRow.hidden = true; return; }
    elCtxRow.hidden = false;
    if (S.ctxOff) {
      const add = document.createElement("button");
      add.type = "button";
      add.className = "aip-ctx-add aip-raw";
      add.innerHTML = IC.page + "<span>Add page context</span>";
      add.addEventListener("click", () => { S.ctxOff = false; renderCtx(); elInput.focus(); });
      elCtxRow.appendChild(add);
      return;
    }
    const chip = document.createElement("span");
    chip.className = "aip-ctx";
    chip.title = "Sent with your question: " + contextLine(ctx);
    chip.innerHTML = IC.page + '<span class="aip-ctx-t"></span>';
    chip.querySelector(".aip-ctx-t").textContent = ctx.where + (ctx.details ? " · " + ctx.details : "");
    const x = document.createElement("button");
    x.type = "button";
    x.className = "aip-ctx-x aip-raw";
    x.setAttribute("aria-label", "Remove page context");
    x.title = "Don't send page context";
    x.innerHTML = IC.x;
    x.addEventListener("click", () => { S.ctxOff = true; S.ctxOverride = null; renderCtx(); elInput.focus(); });
    chip.appendChild(x);
    elCtxRow.appendChild(chip);
  }

  // ── rendering helpers ───────────────────────────────────────────────
  function atBottom() { return elLog.scrollHeight - elLog.scrollTop - elLog.clientHeight < 60; }
  function scrollEnd(force) { if (force || S.stick) elLog.scrollTop = elLog.scrollHeight; }
  elLog.addEventListener("scroll", () => { S.stick = atBottom(); }, { passive: true });

  function ctxChip(text) {
    const c = document.createElement("span");
    c.className = "tw-ctx-chip";
    c.title = "Page context sent with this question";
    c.textContent = text;
    return c;
  }
  function userMsg(text) {
    const parsed = api() ? api().parseContext(text) : { context: "", text };
    const el = document.createElement("div");
    el.className = "aip-msg aip-user";
    const bub = document.createElement("div");
    bub.className = "aip-bubble";
    if (parsed.context) bub.appendChild(ctxChip(parsed.context));
    const t = document.createElement("div");
    t.className = "aip-utext";
    t.textContent = parsed.text;
    bub.appendChild(t);
    el.appendChild(bub);
    elLog.appendChild(el);
    return el;
  }
  function turnEl() {
    const el = document.createElement("div");
    el.className = "aip-msg aip-asst";
    elLog.appendChild(el);
    return el;
  }
  function toolInfo(part) {
    const name = part.tool || part.name || "tool";
    const st = part.state || {};
    let input = st.input || part.input || {};
    if (typeof input === "string") { try { input = JSON.parse(input); } catch (_) { input = { command: input }; } }
    const detail = input.command || input.filePath || input.path || input.pattern || input.query ||
      input.url || input.name || input.description || st.title || "";
    const pretty = PRETTY[String(name).toLowerCase()] || (String(name).charAt(0).toUpperCase() + String(name).slice(1));
    let status = String(st.status || "pending").toLowerCase();
    if (status === "completed") status = "done";
    if (status === "streaming") status = "running";
    const out = st.error ? String(st.error) : (st.output != null && typeof st.output !== "object" ? String(st.output) : "");
    return { pretty, detail: String(detail), status, out, isErr: !!st.error };
  }
  const STATUS_TXT = { running: "running", pending: "pending", done: "done", error: "error" };
  function toolLine(part, el) {
    const info = toolInfo(part);
    if (!el) {
      el = document.createElement("details");
      el.className = "aip-tool";
      el.innerHTML = '<summary><span class="aip-tool-dot" aria-hidden="true"></span><span class="aip-tool-name"></span>' +
        '<span class="aip-tool-detail"></span><span class="aip-tool-st"></span></summary><pre class="aip-tool-out"></pre>';
    }
    el.dataset.status = info.status;
    el.querySelector(".aip-tool-name").textContent = info.pretty;
    el.querySelector(".aip-tool-detail").textContent = info.detail.replace(/\s+/g, " ").slice(0, 90);
    el.querySelector(".aip-tool-detail").title = info.detail.slice(0, 400);
    el.querySelector(".aip-tool-st").textContent = STATUS_TXT[info.status] || info.status;
    const out = el.querySelector(".aip-tool-out");
    out.textContent = info.out ? info.out.slice(0, 6000) + (info.out.length > 6000 ? "\n…" : "") : "(no output yet)";
    return el;
  }
  function toolsBox(parent) {
    const box = document.createElement("div");
    box.className = "aip-tools";
    parent.appendChild(box);
    return box;
  }
  function groupTools(box) {
    const n = box.children.length;
    if (n <= 3) return;
    const names = {};
    [...box.children].forEach((d) => { const k = d.querySelector(".aip-tool-name").textContent; names[k] = (names[k] || 0) + 1; });
    const g = document.createElement("details");
    g.className = "aip-tools-group";
    const sum = document.createElement("summary");
    sum.textContent = n + " tool calls · " + Object.keys(names).map((k) => names[k] > 1 ? k + " ×" + names[k] : k).join(", ");
    g.appendChild(sum);
    while (box.firstChild) g.appendChild(box.firstChild);
    box.appendChild(g);
  }
  function errorBox(parent, message, canRetry) {
    const el = document.createElement("div");
    el.className = "aip-error";
    el.setAttribute("role", "alert");
    el.innerHTML = IC.alert + '<div class="aip-error-b"><b></b><span>Try again, or pick another model above.</span></div>';
    el.querySelector("b").textContent = String(message || "Something went wrong").slice(0, 400);
    if (canRetry && S.lastPrompt) {
      const r = document.createElement("button");
      r.type = "button";
      r.className = "btn btn-sm";
      r.textContent = "Retry";
      r.addEventListener("click", () => { if (!S.busy) send(S.lastPrompt, { raw: true }); });
      el.appendChild(r);
    }
    parent.appendChild(el);
    return el;
  }
  function errText(er) {
    if (!er) return "";
    if (typeof er === "string") return er;
    return er.message || (er.data && er.data.message) || er.name || er.type || "Agent error";
  }

  function emptyState() {
    const el = document.createElement("div");
    el.className = "aip-empty";
    const ctx = pageContext();
    const where = ctx ? ctx.where : "";
    el.innerHTML = '<span class="aip-empty-ico" aria-hidden="true">' + IC.spark + "</span>" +
      "<b>Ask about your router</b><p>Answers come from the opencode agent on this gateway. " +
      "It can run commands here; requests that need your approval appear as cards.</p>";
    const sugg = where
      ? ["Explain what I'm looking at on " + where.split(" › ")[0], "Is anything here wrong or risky?", "What should I check first?"]
      : ["Is anything on my network unhealthy right now?", "Summarise today's security events", "Which interface is my WAN?"];
    const list = document.createElement("div");
    list.className = "aip-sugg";
    sugg.forEach((q) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "aip-sugg-btn aip-raw";
      b.textContent = q;
      b.addEventListener("click", () => { elInput.value = q; autosize(); elInput.focus(); });
      list.appendChild(b);
    });
    el.appendChild(list);
    elLog.appendChild(el);
  }

  function renderHistory(msgs) {
    elLog.innerHTML = "";
    if (!msgs.length) { emptyState(); return; }
    let turn = null, box = null, lastUser = "";
    msgs.forEach((m) => {
      const info = m.info || {};
      if (info.role === "user") {
        lastUser = (m.parts || []).filter((p) => p.type === "text").map((p) => p.text).join("\n");
        if (lastUser) userMsg(lastUser);
        turn = null; box = null;
        return;
      }
      if (info.role !== "assistant") return;
      if (!turn) turn = turnEl();
      (m.parts || []).forEach((p) => {
        const t = p.type || "";
        if (t === "text" && p.text && p.text.trim()) {
          if (box) { groupTools(box); box = null; }
          const d = document.createElement("div");
          d.className = "aip-md";
          d.innerHTML = md(p.text);
          turn.appendChild(d);
        } else if (t === "tool" || t.indexOf("tool") === 0) {
          if (!box) box = toolsBox(turn);
          box.appendChild(toolLine(p));
        }
      });
      if (info.error) {
        if (box) { groupTools(box); box = null; }
        S.lastPrompt = lastUser;
        errorBox(turn, errText(info.error), m === msgs[msgs.length - 1]);
      }
    });
    if (box) groupTools(box);
    S.lastPrompt = lastUser || S.lastPrompt;
    [...elLog.querySelectorAll(".aip-asst")].forEach((t) => { if (!t.childNodes.length) t.remove(); });
  }

  async function loadHistory() {
    const seq = ++S.loadSeq;
    const sid = S.sid;
    if (!sid) { elLog.innerHTML = ""; emptyState(); return; }
    if (!elLog.childNodes.length) elLog.innerHTML = '<div class="aip-loading">Loading conversation…</div>';
    try {
      const msgs = await api().messages(sid);
      if (seq !== S.loadSeq || sid !== S.sid) return;
      if (S.busy && S.turn) return;      // a live turn owns the log now
      renderHistory(msgs);
      if (S.busy) busyRow();
      scrollEnd(true);
    } catch (err) {
      if (seq !== S.loadSeq) return;
      if (err.notFound) { api().setSession(null); S.sid = null; elLog.innerHTML = ""; emptyState(); return; }
      elLog.innerHTML = "";
      errorBox(elLog, "Could not load the conversation: " + err.message, false);
    }
  }

  // ── busy state + live turn ──────────────────────────────────────────
  function busyRow(label) {
    let el = elLog.querySelector(".aip-busy");
    if (!el) {
      el = document.createElement("div");
      el.className = "aip-busy";
      el.innerHTML = '<span class="aip-dots" aria-hidden="true"><i></i><i></i><i></i></span><span class="aip-busy-t"></span>';
    }
    el.querySelector(".aip-busy-t").textContent = label || S.busyLabel || "Working…";
    elLog.appendChild(el);
    return el;
  }
  function setBusyLabel(label) {
    S.busyLabel = label;
    const el = elLog.querySelector(".aip-busy .aip-busy-t");
    if (el) el.textContent = label;
  }
  function setBusy(on, own) {
    S.busy = !!on;
    S.own = !!(on && own);
    panel.classList.toggle("is-busy", S.busy);
    btn.classList.toggle("is-busy", S.busy);
    elLog.setAttribute("aria-busy", S.busy ? "true" : "false");
    elSend.innerHTML = S.busy ? IC.stop : IC.send;
    elSend.setAttribute("aria-label", S.busy ? "Stop" : "Send");
    elSend.title = S.busy ? "Stop the running reply" : "Send (Enter)";
    elSend.classList.toggle("is-stop", S.busy);
    $('[data-aip="new"]').disabled = S.busy;
    if (!S.busy) {
      const b = elLog.querySelector(".aip-busy");
      if (b) b.remove();
      S.busyLabel = "";
      clearTimeout(S.watchdog);
      if (!S.open) unsubscribe();
    }
    updateSend();
  }
  function updateSend() {
    elSend.disabled = !S.busy && !elInput.value.trim();
  }

  function startTurn(sid) {
    S.turnSid = sid;
    S.turn = { el: turnEl(), blocks: new Map(), tools: new Map(), box: null, raf: 0 };
    S.stick = true;
    busyRow("Thinking…");
    scrollEnd(true);
  }
  function turnBlock(mid) {
    const t = S.turn;
    const key = mid || "_";
    let b = t.blocks.get(key);
    if (!b) {
      if (t.box) t.box = null;
      const el = document.createElement("div");
      el.className = "aip-md";
      t.el.appendChild(el);
      b = { el, text: "" };
      t.blocks.set(key, b);
    }
    return b;
  }
  function paint(b) {
    const t = S.turn;
    if (!t) return;
    b.dirty = true;
    if (t.raf) return;
    t.raf = requestAnimationFrame(() => {
      t.raf = 0;
      t.blocks.forEach((x) => { if (x.dirty) { x.dirty = false; x.el.innerHTML = md(x.text); } });
      busyRow();
      scrollEnd();
    });
  }
  function bumpWatchdog() {
    clearTimeout(S.watchdog);
    if (!S.busy) return;
    if (!S.own) {
      // following a turn started elsewhere: give up quietly if it goes silent
      S.watchdog = setTimeout(() => { if (S.busy && !S.own) endTurn(); }, 90000);
      return;
    }
    S.watchdog = setTimeout(async () => {
      if (!S.busy) return;
      if (panel.querySelector(".aip-card:not(.is-done)")) { bumpWatchdog(); return; }
      try {
        const d = await api().get("/api/agent/permission");
        if ((Array.isArray(d) ? d : (d.requests || [])).length) { bumpWatchdog(); return; }
      } catch (_) { /* fall through */ }
      endTurn("No response from the agent for 3 minutes. Is tuxwall-agent.service healthy?");
    }, WATCHDOG_MS);
  }
  function endTurn(error) {
    const t = S.turn;
    if (t && t.raf) cancelAnimationFrame(t.raf);
    if (error && t) errorBox(t.el, error, true);
    S.turn = null;
    const wasOwn = S.own;
    if (wasOwn) api().setExternalBusy(false);
    setBusy(false);
    if (!error) loadHistory();
    else scrollEnd(true);
  }

  // ── SSE events (shared stream) ──────────────────────────────────────
  function onEvent(d) {
    if (!d || !d.type) return;
    const p = d.properties || {};
    const type = d.type;
    if (type === "tw.permission.resolved") { resolveCard("perm", p.requestID, p.note); return; }
    if (type === "tw.question.resolved") { resolveCard("q", p.requestID, p.note); return; }
    if (type === "permission.asked") {
      if (S.busy || p.sessionID === S.sid) { permCard(p); bumpWatchdog(); }
      return;
    }
    if (type === "question.asked" || type === "question.v2.asked") {
      if ((p.sessionID || "") === (S.turnSid || S.sid) || S.busy) { questionCard(p); bumpWatchdog(); }
      return;
    }
    if (type === "question.replied" || type === "question.v2.replied") { resolveCard("q", p.requestID, "answered"); return; }
    if (type === "question.rejected" || type === "question.v2.rejected") { resolveCard("q", p.requestID, "skipped"); return; }
    const sid = S.turnSid || S.sid;
    if (!sid || p.sessionID !== sid) return;
    if (type === "session.idle") {
      if (S.busy) endTurn();
      else if (S.open) loadHistory();
      return;
    }
    if (!S.busy) {
      // a turn started elsewhere (AI page): follow it live
      if (!S.open || (type !== "message.part.delta" && type !== "message.part.updated")) return;
      setBusy(true, false);
      startTurn(sid);
    }
    bumpWatchdog();
    if (type === "message.updated") {
      const info = p.info || {};
      if (info.error) {
        const t = S.turn;
        if (t && !t.errored) { t.errored = true; errorBox(t.el, errText(info.error), true); scrollEnd(); }
      }
    } else if (type === "message.part.delta") {
      if (p.field && p.field !== "text") return;
      const b = turnBlock(p.messageID);
      b.text += p.delta || "";
      setBusyLabel("Writing…");
      paint(b);
    } else if (type === "message.part.updated") {
      const part = p.part || {};
      const pt = part.type || "";
      if (pt === "text") {
        const b = turnBlock(part.messageID);
        if (part.text != null && part.text.length >= b.text.length) b.text = part.text;
        paint(b);
      } else if (pt === "reasoning") {
        setBusyLabel("Thinking…");
      } else if (pt === "tool" || pt.indexOf("tool") === 0) {
        const t = S.turn;
        const key = part.id || (part.name || part.tool || "tool") + ":" + t.tools.size;
        let el = t.tools.get(key);
        if (!el) {
          if (!t.box) t.box = toolsBox(t.el);
          el = toolLine(part);
          t.box.appendChild(el);
          t.tools.set(key, el);
        } else {
          toolLine(part, el);
        }
        const info = toolInfo(part);
        setBusyLabel(info.status === "running" || info.status === "pending" ? "Running " + info.pretty + "…" : "Thinking…");
        busyRow();
        scrollEnd();
      }
    }
  }
  function subscribe() {
    if (S.unsub || !api()) return;
    S.unsub = api().subscribe(onEvent);
  }
  function unsubscribe() {
    if (!S.unsub || S.busy || S.open) return;
    const u = S.unsub;
    S.unsub = null;
    u();
  }

  // ── permission + question cards ─────────────────────────────────────
  function cardFor(kind, rid) {
    return [...elLog.querySelectorAll(".aip-card")].find((c) => c.dataset.kind === kind && c.dataset.rid === rid) || null;
  }
  function resolveCard(kind, rid, note) {
    const c = rid && cardFor(kind, rid);
    if (!c || c.classList.contains("is-done")) return;
    c.classList.add("is-done");
    const title = c.querySelector(".aip-card-title");
    c.innerHTML = "";
    const line = document.createElement("div");
    line.className = "aip-card-done";
    line.textContent = (title ? title.textContent : "Request") + " — " + (note || "answered");
    c.appendChild(line);
    if (S.busy) setBusyLabel("Working…");
    stopPermPollIfIdle();
  }
  function cardShell(kind, rid, icon, title) {
    const c = document.createElement("div");
    c.className = "aip-card aip-card-" + kind;
    c.dataset.kind = kind;
    c.dataset.rid = rid;
    c.setAttribute("role", "group");
    c.innerHTML = '<div class="aip-card-head">' + icon + '<span class="aip-card-title"></span></div><div class="aip-card-body"></div>';
    c.querySelector(".aip-card-title").textContent = title;
    c.setAttribute("aria-label", title);
    return c;
  }
  function placeCard(c) {
    const parent = (S.turn && S.turn.el) || elLog;
    parent.appendChild(c);
    if (S.busy) { setBusyLabel("Waiting for your answer…"); busyRow(); }
    scrollEnd(true);
    startPermPoll();
  }
  function permCard(r) {
    const rid = r.id || r.requestID;
    if (!rid || cardFor("perm", rid)) return;
    const meta = r.metadata || {};
    const kind = r.permission || r.tool || "tool";
    const c = cardShell("perm", rid, IC.lock, "Permission needed · " + kind);
    const body = c.querySelector(".aip-card-body");
    if (meta.description) {
      const p = document.createElement("p");
      p.textContent = meta.description;
      body.appendChild(p);
    }
    const what = (r.patterns && r.patterns.length ? r.patterns.join("\n") : "") || meta.title || "";
    if (meta.diff || what) {
      const pre = document.createElement("pre");
      pre.className = "aip-card-cmd";
      pre.textContent = String(meta.diff || what).slice(0, 4000);
      body.appendChild(pre);
    }
    const row = document.createElement("div");
    row.className = "aip-card-btns";
    [["once", "Allow once", ""], ["always", "Always allow", "oc-yes"], ["reject", "Deny", ""]].forEach(([resp, label, cls]) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = ("btn btn-sm " + cls).trim();
      b.textContent = label;
      b.addEventListener("click", async () => {
        row.querySelectorAll("button").forEach((x) => { x.disabled = true; });
        const note = resp === "reject" ? "denied" : resp === "always" ? "always allowed" : "allowed once";
        try {
          await api().post("/api/agent/permission/reply", { requestID: rid, response: resp });
          resolveCard("perm", rid, note);
          api().emitLocal({ type: "tw.permission.resolved", properties: { requestID: rid, note: resp === "reject" ? "denied" : "approved" } });
        } catch (err) {
          if (/not found|already/i.test(err.message || "")) { resolveCard("perm", rid, "already answered"); return; }
          row.querySelectorAll("button").forEach((x) => { x.disabled = false; });
          showCardErr(c, "Reply failed: " + err.message);
        }
      });
      row.appendChild(b);
    });
    body.appendChild(row);
    placeCard(c);
    const first = row.querySelector("button");
    if (first && S.open && panel.contains(document.activeElement) && document.activeElement !== elInput) first.focus();
  }
  function showCardErr(c, msg) {
    let e = c.querySelector(".aip-card-err");
    if (!e) { e = document.createElement("div"); e.className = "aip-card-err"; c.appendChild(e); }
    e.textContent = msg;
  }
  function questionCard(r) {
    const rid = r.id || r.requestID;
    const qs = r.questions || [];
    if (!rid || !qs.length || cardFor("q", rid)) return;
    const c = cardShell("q", rid, IC.help, "The agent has a question");
    const body = c.querySelector(".aip-card-body");
    const answers = qs.map(() => []);
    let sent = false;
    const submit = async () => {
      if (sent || !answers.every((a) => a.length)) return;
      sent = true;
      try {
        await api().post("/api/agent/question/reply", { requestID: rid, answers });
        resolveCard("q", rid, "answered");
        api().emitLocal({ type: "tw.question.resolved", properties: { requestID: rid, note: "answered" } });
      } catch (err) { sent = false; showCardErr(c, "Reply failed: " + err.message); }
    };
    qs.forEach((q, qi) => {
      const blk = document.createElement("div");
      blk.className = "aip-q";
      if (qs.length > 1 && q.header) {
        const h = document.createElement("div");
        h.className = "aip-q-h";
        h.textContent = q.header;
        blk.appendChild(h);
      }
      const p = document.createElement("p");
      p.textContent = q.question || q.header || "";
      blk.appendChild(p);
      const multi = !!(q.multiple || q.multi);
      const opts = document.createElement("div");
      opts.className = "aip-q-opts";
      (q.options || []).forEach((o) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "aip-q-opt aip-raw";
        b.setAttribute("aria-pressed", "false");
        b.innerHTML = "<b></b>" + (o.description ? "<span></span>" : "");
        b.querySelector("b").textContent = o.label;
        if (o.description) b.querySelector("span").textContent = o.description;
        b.addEventListener("click", () => {
          if (multi) {
            const on = answers[qi].indexOf(o.label) === -1;
            answers[qi] = on ? answers[qi].concat([o.label]) : answers[qi].filter((l) => l !== o.label);
            b.setAttribute("aria-pressed", String(on));
          } else {
            opts.querySelectorAll(".aip-q-opt").forEach((x) => x.setAttribute("aria-pressed", "false"));
            answers[qi] = [o.label];
            b.setAttribute("aria-pressed", "true");
            if (qs.length === 1 && q.custom === false) submit();
          }
        });
        opts.appendChild(b);
      });
      blk.appendChild(opts);
      if (q.custom !== false) {
        const inp = document.createElement("input");
        inp.type = "text";
        inp.className = "aip-q-custom";
        inp.placeholder = "Or type your own answer…";
        inp.setAttribute("aria-label", "Your own answer");
        inp.addEventListener("input", () => {
          const v = inp.value.trim();
          if (v) { answers[qi] = [v]; opts.querySelectorAll(".aip-q-opt").forEach((x) => x.setAttribute("aria-pressed", "false")); }
        });
        inp.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } });
        blk.appendChild(inp);
      }
      body.appendChild(blk);
    });
    const row = document.createElement("div");
    row.className = "aip-card-btns";
    const ok = document.createElement("button");
    ok.type = "button";
    ok.className = "btn btn-sm btn-primary";
    ok.textContent = "Answer";
    ok.addEventListener("click", submit);
    const skip = document.createElement("button");
    skip.type = "button";
    skip.className = "btn btn-sm";
    skip.textContent = "Skip";
    skip.addEventListener("click", async () => {
      if (sent) return;
      sent = true;
      try {
        await api().post("/api/agent/question/reject", { requestID: rid });
        resolveCard("q", rid, "skipped");
        api().emitLocal({ type: "tw.question.resolved", properties: { requestID: rid, note: "skipped" } });
      } catch (err) { sent = false; showCardErr(c, "Skip failed: " + err.message); }
    });
    row.appendChild(ok);
    row.appendChild(skip);
    body.appendChild(row);
    placeCard(c);
  }
  // pending cards answered elsewhere (AI page, another browser) settle here
  async function pollPending(renderNew) {
    try {
      const [pd, qd] = await Promise.all([
        api().get("/api/agent/permission").catch(() => null),
        api().get("/api/agent/question").catch(() => null),
      ]);
      const perms = pd ? (Array.isArray(pd) ? pd : (pd.requests || [])) : null;
      const ques = qd ? (Array.isArray(qd) ? qd : (qd.requests || [])) : null;
      if (perms) {
        const ids = new Set(perms.map((r) => r.id || r.requestID));
        elLog.querySelectorAll('.aip-card[data-kind="perm"]:not(.is-done)').forEach((c) => {
          if (!ids.has(c.dataset.rid)) resolveCard("perm", c.dataset.rid, "answered elsewhere");
        });
        if (renderNew) perms.forEach((r) => { if (S.busy || r.sessionID === S.sid) permCard(r); });
      }
      if (ques) {
        const ids = new Set(ques.map((r) => r.id || r.requestID));
        elLog.querySelectorAll('.aip-card[data-kind="q"]:not(.is-done)').forEach((c) => {
          if (!ids.has(c.dataset.rid)) resolveCard("q", c.dataset.rid, "answered elsewhere");
        });
        if (renderNew) ques.forEach((r) => { if ((r.sessionID || "") === S.sid) questionCard(r); });
      }
    } catch (_) { /* agent may be restarting */ }
  }
  function startPermPoll() {
    if (S.permTimer) return;
    S.permTimer = setInterval(() => {
      if (!elLog.querySelector(".aip-card:not(.is-done)")) { stopPermPollIfIdle(); return; }
      pollPending(false);
    }, 3000);
  }
  function stopPermPollIfIdle() {
    if (S.permTimer && !elLog.querySelector(".aip-card:not(.is-done)")) { clearInterval(S.permTimer); S.permTimer = null; }
  }

  // ── send / stop ─────────────────────────────────────────────────────
  async function send(text, opts) {
    opts = opts || {};
    const a = api();
    text = String(text || "").trim();
    if (!text || S.busy || !a) return;
    if (a.pageBusy()) { errorBox(elLog, "The AI Assistant page is still running a task. Wait for it or stop it there.", false); scrollEnd(true); return; }
    let full = text;
    if (!opts.raw) {
      const ctx = !S.ctxOff && currentContext();
      if (ctx) full = "[TuxWall context: " + contextLine(ctx) + "]\n\n" + text;
    }
    S.lastPrompt = full;
    elInput.value = "";
    autosize();
    S.ctxOverride = null;
    renderCtx();
    const empty = elLog.querySelector(".aip-empty");
    if (empty) empty.remove();
    elLog.querySelectorAll(".aip-error").forEach((e) => { const r = e.querySelector("button"); if (r) r.remove(); });
    userMsg(full);
    a.setExternalBusy(true);
    setBusy(true, true);
    subscribe();
    let sid = null;
    try {
      await a.ready(4000);
      sid = await a.ensureSession();
      S.sid = sid;
      startTurn(sid);
      bumpWatchdog();
      const d = await a.post("/api/agent/message", { sessionID: sid, text: full, model: a.model() });
      if (d && d.async === false) endTurn();
    } catch (err) {
      if (!S.turn) startTurn(sid);
      endTurn((err && err.message) || "Request failed");
    }
  }
  async function stop() {
    const sid = S.turnSid || S.sid;
    if (!sid) return;
    elSend.disabled = true;
    try {
      await api().post("/api/agent/session/abort", { sessionID: sid });
    } catch (err) {
      errorBox((S.turn && S.turn.el) || elLog, "Stop failed: " + err.message, false);
    }
    elLog.querySelectorAll(".aip-card:not(.is-done)").forEach((c) => {
      if (c.dataset.kind === "q") api().post("/api/agent/question/reject", { requestID: c.dataset.rid }).catch(() => {});
      resolveCard(c.dataset.kind, c.dataset.rid, "cancelled");
    });
    if (S.busy) {
      const t = S.turn;
      if (t) { const n = document.createElement("div"); n.className = "aip-note"; n.textContent = "Stopped."; t.el.appendChild(n); }
      S.turn = null;
      if (S.own) api().setExternalBusy(false);
      setBusy(false);
      setTimeout(() => { if (!S.busy) loadHistory(); }, 1200);
    }
  }

  // ── open / close ────────────────────────────────────────────────────
  function placeBelowTopbar() {
    const tb = document.querySelector(".topbar");
    const top = tb ? Math.max(0, Math.round(tb.getBoundingClientRect().bottom)) : 0;
    panel.style.setProperty("--aip-top", top + "px");
  }
  let scrollRaf = 0;
  function onScroll() {
    if (!S.open || scrollRaf) return;
    scrollRaf = requestAnimationFrame(() => { scrollRaf = 0; placeBelowTopbar(); });
  }

  async function syncModels() {
    const a = api();
    if (!a) return;
    try {
      const src = await a.loadModels();
      if (src && src.dataset.loaded === "1") {
        elModel.innerHTML = src.innerHTML;
        elModel.value = a.model();
      } else if (src) {
        elModel.innerHTML = src.innerHTML;
      }
    } catch (_) { /* keep placeholder */ }
  }

  function open(opts) {
    opts = opts || {};
    const a = api();
    if (!a || btn.hidden) return;
    if (!S.open) {
      S.open = true;
      placeBelowTopbar();
      panel.hidden = false;
      document.documentElement.classList.add("aip-open");
      requestAnimationFrame(() => panel.classList.add("is-open"));
      btn.setAttribute("aria-expanded", "true");
      btn.classList.add("is-active");
      subscribe();
      syncModels();
      if (!S.busy) {
        S.sid = a.session();
        elLog.innerHTML = "";
        loadHistory().then(() => {
          if (a.pageBusy() && S.sid && !S.busy) { setBusy(true, false); startTurn(S.sid); bumpWatchdog(); }
          pollPending(S.busy);
        });
      }
      S.stick = true;
    }
    renderCtx();
    if (opts.text != null) {
      elInput.value = String(opts.text);
      autosize();
    }
    setTimeout(() => {
      elInput.focus({ preventScroll: true });
      const n = elInput.value.length;
      try { elInput.setSelectionRange(n, n); } catch (_) { }
    }, 30);
  }
  function close(restoreFocus) {
    if (!S.open) return;
    S.open = false;
    panel.classList.remove("is-open");
    document.documentElement.classList.remove("aip-open");
    btn.setAttribute("aria-expanded", "false");
    btn.classList.remove("is-active");
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    setTimeout(() => { if (!S.open) panel.hidden = true; }, reduce ? 0 : 240);
    unsubscribe();
    if (restoreFocus !== false && !btn.hidden) btn.focus({ preventScroll: true });
  }
  function toggle() { if (S.open) close(); else open(); }

  function autosize() {
    elInput.style.height = "auto";
    elInput.style.height = Math.min(elInput.scrollHeight, 160) + "px";
    updateSend();
  }

  // ── wiring ──────────────────────────────────────────────────────────
  btn.title = "Assistant (" + SHORTCUT + ")";
  btn.setAttribute("aria-keyshortcuts", "Control+/");
  btn.addEventListener("click", toggle);
  panel.addEventListener("click", (e) => {
    const b = e.target.closest("[data-aip]");
    if (!b) return;
    const act = b.dataset.aip;
    if (act === "close") close();
    else if (act === "new") {
      if (S.busy) return;
      if (!api().newSession()) { errorBox(elLog, "The AI Assistant page is busy — try again when it finishes.", false); return; }
      S.sid = null;
      S.lastPrompt = "";
      elLog.innerHTML = "";
      emptyState();
      elInput.focus();
    } else if (act === "full") {
      const nav = document.querySelector('.nav-item[data-view="ai"]');
      close(false);
      if (nav) nav.click();
    }
  });
  elModel.addEventListener("change", () => { api().setModel(elModel.value); });
  elSend.addEventListener("click", () => { if (S.busy) stop(); else send(elInput.value); });
  elInput.addEventListener("input", autosize);
  elInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      if (!S.busy) send(elInput.value);
    }
  });

  function otherDialogOpen() {
    return !!document.querySelector(".tw-pal-backdrop:not([hidden]), .tw-dialog-backdrop, .modal:not([hidden]), .oc-overlay:not([hidden])");
  }
  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey && !e.altKey && !e.metaKey && e.key === "/") {
      if (btn.hidden || otherDialogOpen()) return;
      e.preventDefault();
      if (S.open && !panel.contains(document.activeElement)) { elInput.focus(); return; }
      toggle();
      return;
    }
    if (e.key === "Escape" && S.open && !e.defaultPrevented) {
      if (otherDialogOpen() && !panel.contains(document.activeElement)) return;
      e.preventDefault();
      close();
    }
  });
  // outside clicks close the panel, but never while a reply is running or
  // a permission/question is waiting
  document.addEventListener("pointerdown", (e) => {
    if (!S.open || S.busy || panel.contains(e.target) || btn.contains(e.target)) return;
    if (e.target.closest && e.target.closest(".tw-ask")) return;
    if (window.matchMedia("(max-width: 640px)").matches) return;
    if (elLog.querySelector(".aip-card:not(.is-done)")) return;
    if (e.target.closest(".modal, .tw-pal-backdrop, .tw-dialog-backdrop, .tw-toasts, .topbar")) return;
    close(false);
  }, true);
  window.addEventListener("resize", () => { if (S.open) placeBelowTopbar(); }, { passive: true });
  document.addEventListener("scroll", onScroll, { passive: true, capture: true });
  window.addEventListener("hashchange", () => { if (S.open) setTimeout(renderCtx, 60); });
  document.addEventListener("click", (e) => {
    if (S.open && !panel.contains(e.target) && e.target.closest && e.target.closest(".nav-item, .fw-subtab, .fw-chip")) setTimeout(renderCtx, 60);
  });
  document.addEventListener("input", (e) => {
    if (S.open && e.target && e.target.type === "search" && !panel.contains(e.target)) {
      clearTimeout(S.ctxT);
      S.ctxT = setTimeout(renderCtx, 300);
    }
  });
  document.addEventListener("tw:role", (e) => { if (!(e.detail && e.detail.admin)) close(false); });
  const gate = document.getElementById("login-gate");
  if (gate && window.MutationObserver) {
    new MutationObserver(() => { if (!gate.hidden) close(false); }).observe(gate, { attributes: true, attributeFilter: ["hidden"] });
  }

  function bindApi() {
    const a = api();
    if (!a || bindApi.done) return;
    bindApi.done = true;
    a.onSession((sid) => {
      if (sid === S.sid) return;
      if (S.busy && S.own) return;      // our turn keeps its session
      S.sid = sid;
      if (S.busy) { S.turn = null; setBusy(false); }
      if (S.open) { elLog.innerHTML = ""; loadHistory(); }
    });
    a.onModel((id) => { if (elModel.querySelector('option[value="' + (window.CSS && CSS.escape ? CSS.escape(id) : id) + '"]')) elModel.value = id; });
  }
  bindApi();
  if (!bindApi.done) document.addEventListener("DOMContentLoaded", bindApi);

  window.twAsk = function (opts) {
    opts = opts || {};
    if (opts.context != null && String(opts.context).trim()) { S.ctxOverride = String(opts.context); S.ctxOff = false; }
    open({ text: opts.text != null ? opts.text : "" });
  };

  // ── "Ask AI" shortcuts (one control for every page) ─────────────────
  // window.twAskButton({ text, context, title, iconOnly, className, onAsk })
  // returns a button (null for non-admins) that pre-fills the panel.
  // text/context may be functions, read at click time so counters are fresh.
  const askGate = () => document.documentElement.classList.toggle("tw-ask-on", !btn.hidden);
  askGate();
  document.addEventListener("tw:role", askGate);
  window.twAskAllowed = () => !!api() && !btn.hidden;
  window.twAskButton = function (o) {
    o = o || {};
    if (!window.twAskAllowed()) return null;
    const val = (v) => (typeof v === "function" ? v() : v);
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tw-ask aip-raw" + (o.iconOnly ? " tw-ask-icon" : "") + (o.className ? " " + o.className : "");
    const label = o.title || "Ask AI";
    b.setAttribute("aria-label", label);
    b.title = label + " — opens the assistant with the question filled in";
    b.innerHTML = IC.spark + (o.iconOnly ? "" : '<span class="tw-ask-t">Ask AI</span>');
    b.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (o.onAsk) o.onAsk();
      window.twAsk({ text: val(o.text) || "", context: val(o.context) || "" });
    });
    // keep Enter/Space on the button from reaching row handlers (role=button rows)
    b.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") e.stopPropagation(); });
    return b;
  };
})();
