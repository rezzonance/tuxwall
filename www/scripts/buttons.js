/* TuxWall buttons: every button gets the same design (css/buttons.css) and a
   colour tone; .btn buttons also get a leading icon from their label. Only
   data-* attributes are set, so code that rewrites a label with textContent
   keeps working; a MutationObserver re-reads the label when it changes.
     data-btn-tone  danger | primary | success | warning | info | neutral
     data-btn-icon  icon name (absent when the button has its own <svg>)
     data-btn-busy  label ends with "…" (Saving…, Applying…) -> spinner
     data-btn-only  icon-only button (svg or ✕) -> square
   Tabs, filter chips, toggles, sidebar items and clickable rows/cards are
   left alone (SKIP). */
(function () {
  "use strict";

  const CAND = 'button, input[type="submit"], input[type="button"], input[type="reset"], .btn';
  const SKIP = [
    ".nav-item", ".tw-nav-group-head", ".fw-subtab", ".seg-btn", ".svc-tab",
    ".fw-chip", ".tl-chip", ".ai-prompt-chip", ".ov-post-chip", ".theme-card",
    ".sec-feed-row", ".oc-tools-head", ".oc-perm-diff-toggle", ".oc-q-opt",
    ".tl-ip", ".tw-svc-sum", ".tw-pal-item", '[role="tab"]', '[role="switch"]',
    '[role="option"]', '[role="menuitemradio"]', ".leaflet-container *",
  ].join(",");

  const ICON_RULES = [
    [/^(sign ?in|log ?in)\b/, "login"],
    [/password|passphrase/, "key"],
    [/^(unban|allow|whitelist|trust)\b/, "allow"],
    [/^(ban|block)\b/, "ban"],
    [/^(delete|remove|revoke|purge|clear|wipe)\b/, "trash"],
    [/^(cancel|close|dismiss)\b/, "x"],
    [/\bapply\b|^(confirm|ok|done|resolve|accept|acknowledge)\b/, "check"],
    [/^(save|store)\b/, "save"],
    [/^(edit|rename|modify)\b/, "edit"],
    [/^(add|new|create)\b/, "plus"],
    [/^(refresh|reload|check|reboot|restart|reset|retry|re-?run|force|update now|sync)\b/, "rotate"],
    [/^(download|export|install|update|get)\b/, "download"],
    [/^(upload|import|restore)\b/, "upload"],
    [/^send\b/, "send"],
    [/^(test|run|speedtest|start|scan)\b/, "play"],
    [/^copy\b/, "copy"],
    [/^enable\b/, "power"],
    [/^(disable|stop)\b/, "power-off"],
    [/^(search|browse|find|look ?up|lookup)\b/, "search"],
    [/^(settings|configure|config|set ?up|use suggested|advanced|alert settings)\b/, "sliders"],
    [/\bqr\b/, "qr"],
    [/^(show|load|more)\b/, "chevron"],
    [/^raw\b/, "code"],
    [/^select all\b/, "check-square"],
    [/^select none\b/, "square"],
    [/^open\b/, "external"],
  ];

  /* Label -> tone, first match wins (destructive checked first). */
  const TONE_RULES = [
    [/^(delete|remove|disable|unban|unblock|revoke|reboot|reset|stop|update system|purge|wipe|clear|uninstall|deny|reject|flush|kick|disconnect|terminate|kill|erase)\b/, "danger"],
    [/^(cancel|close|dismiss|pause|resume|back|skip|no|hide|collapse|less|sign ?out|log ?out|prev|previous|next|first|last)\b|^[✕×✖x]$/, "neutral"],
    [/^(enable|start|allow|confirm|resolve|whitelist|trust|acknowledge|accept|approve|restore|yes)\b/, "success"],
    [/^(restart|reload|update|re-?run|rerun|retry|speed ?test|run|force|re-?apply|rebuild|renew|regenerate|rotate)\b/, "warning"],
    [/^(save|apply|add|create|new|sign ?in|log ?in|upload|import|bulk import|ban|block|set ?up|install|submit|send|generate|ok|done)\b|\bapply\b/, "primary"],
    [/^(refresh|check|test|download|export|copy|browse|view|show|edit|search|find|look ?up|lookup|details|open|load|more|raw|scan|preview|select|configure|config|settings|alert settings|advanced|use suggested|rename|modify|change|qr)\b|\bqr\b/, "info"],
  ];

  /* Row action buttons from actBtn(): tone from the act-<kind> class. */
  const ACT_TONES = {
    up: "neutral", down: "neutral", edit: "info", delete: "danger", active: "danger",
    ban: "primary", config: "info", download: "info", export: "info", import: "primary",
    backup: "success", restart: "warning", reload: "warning", start: "success", stop: "danger",
  };
  const ACTION_TONES = { restart: "warning", reload: "warning", start: "success", stop: "danger", enable: "success", disable: "danger" };
  const CLOSE_ONLY = /^[✕×✖x]$/;
  const GLYPH_ICON = { "▶": "send", "►": "send" };

  function setAttr(el, name, value) {
    if (value == null) {
      if (el.hasAttribute(name)) el.removeAttribute(name);
    } else if (el.getAttribute(name) !== value) {
      el.setAttribute(name, value);
    }
  }

  /* textContent without hidden parts (e.g. the bell's hidden "0" badge). */
  function visibleText(btn) {
    if (!btn.querySelector("[hidden]")) return btn.textContent;
    let out = "";
    const walk = (n) => {
      for (let c = n.firstChild; c; c = c.nextSibling) {
        if (c.nodeType === 3) out += c.nodeValue;
        else if (c.nodeType === 1 && !c.hasAttribute("hidden")) walk(c);
      }
    };
    walk(btn);
    return out;
  }

  function classTone(btn, cl, label) {
    if (cl.contains("btn-danger") || cl.contains("icon-btn-danger")) return "danger";
    if (cl.contains("btn-primary") || cl.contains("login-btn")) return "primary";
    if (cl.contains("btn-ghost")) return TONE_RULES[0][0].test(label) ? "danger" : "neutral";
    if (cl.contains("act-btn")) {
      for (const c of cl) {
        if (!c.startsWith("act-") || c === "act-btn" || c === "act-danger") continue;
        const k = c.slice(4);
        if (k === "power") return cl.contains("act-danger") ? "danger" : "success";
        if (ACT_TONES[k]) return ACT_TONES[k];
      }
      return cl.contains("act-danger") ? "danger" : null;
    }
    const act = btn.getAttribute("data-action");
    if (act && ACTION_TONES[act]) return ACTION_TONES[act];
    if (cl.contains("theme-del") || cl.contains("oc-sess-act")) return "danger";
    if (cl.contains("oc-yes")) return "success";
    if (cl.contains("oc-no") || cl.contains("modal-close") || cl.contains("oc-modal-x") ||
        cl.contains("tw-toast-x") || cl.contains("tw-sheet-x") || cl.contains("host-cancel") ||
        cl.contains("incident-bell") || cl.contains("user-menu-btn") || cl.contains("nav-toggle") ||
        cl.contains("tw-search-btn") || cl.contains("tw-live-btn")) return "neutral";
    if (cl.contains("host-save") || cl.contains("oc-send") || cl.contains("oc-q-send")) return "primary";
    if (cl.contains("ip-copy-btn") || cl.contains("card-edit") || cl.contains("host-edit")) return "info";
    if (cl.contains("plugin-power")) return cl.contains("is-on") ? "danger" : "success";
    return null;
  }

  function decorate(btn) {
    if (btn.matches(SKIP)) {
      setAttr(btn, "data-btn-tone", null);
      return;
    }
    const isInput = btn.tagName === "INPUT";
    const text = ((isInput ? btn.value : visibleText(btn)) || "").replace(/\s+/g, " ").trim();
    const named = text || btn.getAttribute("aria-label") || btn.getAttribute("title") || "";
    const label = named.toLowerCase();
    const hasSvg = !!btn.querySelector("svg");
    const isBtn = btn.classList.contains("btn");
    let icon = null;
    let only = null;
    if (CLOSE_ONLY.test(text)) {
      icon = "x";
      only = "";
      if (!btn.hasAttribute("aria-label")) btn.setAttribute("aria-label", "Close");
    } else if (GLYPH_ICON[text]) {
      icon = GLYPH_ICON[text];
      only = "";
    } else if (!text && (hasSvg || btn.children.length)) {
      only = "";
    } else if (!hasSvg && !isInput && /^[a-z0-9]/.test(label) &&
               (isBtn || !btn.children.length)) {
      for (const [re, name] of ICON_RULES) {
        if (re.test(label)) { icon = name; break; }
      }
    }
    if (btn.classList.contains("act-btn") || btn.classList.contains("icon-btn") ||
        btn.classList.contains("ov-svc-act") || btn.classList.contains("user-menu-btn") ||
        btn.classList.contains("incident-bell")) only = "";
    setAttr(btn, "data-btn-icon", isInput ? null : icon);
    setAttr(btn, "data-btn-only", only);
    setAttr(btn, "data-btn-busy", /(…|\.\.\.)$/.test(text) ? "" : null);

    let tone = classTone(btn, btn.classList, label);
    if (!tone) {
      for (const [re, t] of TONE_RULES) {
        if (re.test(label)) { tone = t; break; }
      }
    }
    setAttr(btn, "data-btn-tone", tone || "neutral");
  }

  function scan(root) {
    if (root.matches && root.matches(CAND)) decorate(root);
    if (root.querySelectorAll) root.querySelectorAll(CAND).forEach(decorate);
  }

  scan(document.body);

  const obs = new MutationObserver((records) => {
    const seen = new Set();
    for (const r of records) {
      let t = r.target;
      if (t.nodeType !== 1) t = t.parentElement;
      const b = t && t.closest ? t.closest(CAND) : null;
      if (b && !seen.has(b)) { seen.add(b); decorate(b); }
      if (r.type === "childList") {
        r.addedNodes.forEach((n) => {
          if (n.nodeType === 1 && (n.matches(CAND) || n.firstElementChild)) scan(n);
        });
      }
    }
  });
  obs.observe(document.body, {
    childList: true, subtree: true, characterData: true,
    attributes: true, attributeFilter: ["class", "aria-label", "title", "data-action", "value"],
  });
})();
