/* TuxWall UniFi plugin — read-only controller view. */
(function () {
  "use strict";
  const state = { el: null, api: null, cfg: null, secret: {}, busy: false, tab: "overview", data: null, clientFilter: "", traffic: null, trafficHidden: {}, trafficResizeBound: false, connectivity: null };

  function escEl(id) { return state.el.querySelector(id); }
  function setMsg(text, bad) {
    const el = escEl("#wifi-msg");
    if (!el) return;
    el.textContent = text || "";
    el.className = "wifi-msg" + (bad ? " is-bad" : "");
  }
  function fmtNum(n) { return (n == null || isNaN(n)) ? "—" : Number(n).toLocaleString(); }
  function fmtBytes(n) {
    n = Number(n || 0);
    if (n >= 1e9) return (n / 1e9).toFixed(1) + " GB";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + " MB";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB";
    return n + " B";
  }

  function wifiIcon(name) {
    const icons = {
      ap: '<path d="M3 14a9 9 0 0 1 18 0"/><path d="M6.5 14a5.5 5.5 0 0 1 11 0"/><circle cx="12" cy="17" r="1.5"/>',
      clients: '<circle cx="9" cy="8" r="3.2"/><path d="M2.6 20a6.4 6.4 0 0 1 12.8 0M15.6 5.3a3.2 3.2 0 0 1 0 5.4M18.9 20a6.4 6.4 0 0 0-2.8-5.3"/>',
      wireless: '<path d="M2.5 8.5a15 15 0 0 1 19 0M5.5 12a10 10 0 0 1 13 0M8.8 15.5a5 5 0 0 1 6.4 0"/><circle cx="12" cy="19" r="1"/>',
      wired: '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 17v4M11 17v4M15 17v4M19 17v4"/>',
      controller: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 6.5h6M12 17.5h6"/>',
      events: '<path d="M3 12h4l2.5-6 5 12 2.5-6h4"/>',
      inventory: '<path d="M8 6h13M8 12h13M8 18h13M3.6 6h.01M3.6 12h.01M3.6 18h.01"/>',
      topology: '<circle cx="18" cy="5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="19" r="2.5"/><path d="m8.3 10.8 7.4-4.4M8.3 13.2l7.4 4.4"/>',
      vlan: '<path d="M4 7h16M4 12h16M4 17h16"/><circle cx="7" cy="7" r="1" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="17" cy="17" r="1" fill="currentColor" stroke="none"/>',
      weak: '<path d="M2.5 8.5a15 15 0 0 1 19 0M5.5 12a10 10 0 0 1 13 0M8.8 15.5a5 5 0 0 1 6.4 0"/><circle cx="12" cy="19" r="1"/>',
      traffic: '<path d="M3 17l4.5-6.5 4 3.5L17 6l4 5"/><path d="M3 21h18"/><circle cx="17" cy="6" r="1.2" fill="currentColor" stroke="none"/>',
      connectivity: '<path d="M4 17.5a11 11 0 0 1 16 0"/><path d="M7.5 14a6 6 0 0 1 9 0"/><circle cx="12" cy="19" r="1.2"/><path d="M12 3v3M5 6l2 2M19 6l-2 2"/>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${icons[name] || icons.ap}</svg>`;
  }

  function enhanceWifiHeads() {
    if (!state.el) return;
    state.el.querySelectorAll(".wifi-head:not(.has-ico)").forEach((head) => {
      const h2 = head.querySelector("h2");
      if (!h2) return;
      const title = h2.textContent.trim().toLowerCase();
      let key = "wireless";
      if (title.includes("integration")) key = "controller";
      else if (title.includes("event")) key = "events";
      else if (title.includes("client") && !title.includes("ssid") && !title.includes("vlan")) key = "clients";
      else if (title.includes("inventory")) key = "inventory";
      else if (title.includes("topology")) key = "topology";
      else if (title.includes("ssid")) key = "wireless";
      else if (title.includes("vlan")) key = "vlan";
      else if (title.includes("weak")) key = "weak";
      const ico = document.createElement("span");
      ico.className = "wifi-head-ico";
      ico.setAttribute("aria-hidden", "true");
      ico.innerHTML = wifiIcon(key);
      head.insertBefore(ico, head.firstChild);
      head.classList.add("has-ico");
    });
  }

  function skeleton() {
    state.el.innerHTML = `
      <div class="wifi-page">
        <div class="fw-subtabs" id="wifi-subtabs">
          <button class="fw-subtab active" type="button" data-wifi-pane="overview">Overview</button>
          <button class="fw-subtab" type="button" data-wifi-pane="events">Events</button>
          <button class="fw-subtab" type="button" data-wifi-pane="inventory">Inventory</button>
          <span class="fw-subtabs-fill"></span>
        </div>
        <div class="wifi-pane" data-wifi-pane="overview">
        <div class="wifi-bento">
          <article class="wifi-card wifi-hero" data-accent="blue">
            <div class="wifi-hero-plate">
              <div class="wifi-hero-art"><img src="/api/plugins/unifi/asset/images/fierce-penguin-wi-fi.webp" alt=""></div>
              <div class="wifi-hero-head">
                <span class="wifi-hero-logo"><img class="logo-dark" src="/api/plugins/unifi/asset/images/unifi-network-white.svg" alt="UniFi Network"><img class="logo-light" src="/api/plugins/unifi/asset/images/unifi-network-black.svg" alt="UniFi Network"></span>
                <span class="wifi-hero-chip" id="wifi-hero-chip">Not connected</span>
              </div>
              <div class="wifi-hero-bottom">
                <div class="wifi-hero-value">
                  <img class="wifi-hero-orb" id="wifi-hero-orb" src="/api/plugins/unifi/asset/images/wifi-off.webp" alt="">
                  <span id="wifi-hero-status">Not connected</span>
                </div>
                <div class="wifi-hero-sub" id="wifi-hero-sub">Configure the controller to load access points.</div>
              </div>
            </div>
          </article>
          <article class="wifi-card wifi-kpi" data-accent="red"><span class="wifi-kicker">Access points</span><div class="wifi-num" id="wifi-kpi-aps">—</div><div class="wifi-sub">adopted APs</div></article>
          <article class="wifi-card wifi-kpi" data-accent="purple"><span class="wifi-kicker">Clients</span><div class="wifi-num" id="wifi-kpi-clients">—</div><div class="wifi-sub">associated clients</div></article>
          <article class="wifi-card wifi-kpi" data-accent="blue"><span class="wifi-kicker">Wireless</span><div class="wifi-num" id="wifi-kpi-wireless">—</div><div class="wifi-sub">over the air</div></article>
          <article class="wifi-card wifi-kpi" data-accent="green"><span class="wifi-kicker">Wired</span><div class="wifi-num" id="wifi-kpi-wired">—</div><div class="wifi-sub">on Ethernet</div></article>
          <article class="wifi-card wifi-controller" data-accent="purple">
            <div class="wifi-controller-art"><img src="/api/plugins/unifi/asset/images/neon-penguin-server-guardian.webp" alt=""></div>
            <span class="wifi-kicker">Controller</span>
            <div class="wifi-controller-name" id="wifi-controller-name">Not configured</div>
            <div class="wifi-controller-sub" id="wifi-controller-sub">Add your UniFi controller below.</div>
            <div class="wifi-controller-tags" id="wifi-controller-tags"></div>
          </article>
        </div>
        <div class="card wifi-config">
          <div class="wifi-head">
            <div class="wifi-head-copy">
              <h2>UniFi Integration</h2>
              <p class="muted" id="wifi-config-sub">Read-only access to your UniFi controller. Credentials stay on the router.</p>
            </div>
            <div class="wifi-head-actions">
              <button class="btn btn-sm" id="wifi-config-toggle" type="button">Configure</button>
              <button class="btn btn-sm" id="wifi-refresh" type="button">Refresh</button>
            </div>
          </div>
          <div class="wifi-form">
            <label class="wifi-field wifi-wide"><span>Controller URL</span><input id="wifi-url" type="url" placeholder="https://192.168.1.1:8443" autocomplete="off"></label>
            <label class="wifi-field"><span>Controller type</span><select id="wifi-ctype">
              <option value="classic">Classic Network Application</option>
              <option value="unifi_os">UniFi OS (UDM / Cloud Gateway / Cloud Key)</option>
            </select></label>
            <label class="wifi-field"><span>Authentication</span><select id="wifi-auth">
              <option value="local">Local username + password</option>
              <option value="api_key">API key (UniFi OS only)</option>
            </select></label>
            <label class="wifi-field wifi-local"><span>Username</span><input id="wifi-user" type="text" placeholder="dedicated UniFi account" autocomplete="off"></label>
            <label class="wifi-field wifi-local"><span>Password</span><input id="wifi-pass" type="password" placeholder="UniFi password" autocomplete="off"></label>
            <label class="wifi-field wifi-key"><span>API key</span><input id="wifi-key" type="password" placeholder="UniFi OS API key" autocomplete="off"></label>
            <label class="wifi-field"><span>Site</span><input id="wifi-site" type="text" placeholder="default" autocomplete="off"></label>
            <label class="wifi-check"><input id="wifi-verify" type="checkbox" checked> Verify TLS certificate</label>
          </div>
          <p class="wifi-hint muted">Classic controllers use the local account login; API keys are only available on UniFi OS.</p>
          <div class="wifi-actions">
            <button class="btn btn-primary" id="wifi-save" type="button">Save</button>
            <button class="btn" id="wifi-test" type="button">Test connection</button>
            <span class="wifi-msg" id="wifi-msg" role="status" aria-live="polite"></span>
          </div>
        </div>
        <div id="wifi-data"></div>
        </div>
        <div class="wifi-pane" data-wifi-pane="inventory" hidden>
          <div id="wifi-inventory"></div>
        </div>
        <div class="wifi-pane" data-wifi-pane="events" hidden>
          <div class="card wifi-events-card">
            <div class="wifi-head">
              <div>
                <h2>WiFi Events</h2>
                <p class="muted" id="wifi-events-sub">Connects, disconnects and roams · last 7 days</p>
              </div>
              <button class="btn btn-sm" id="wifi-events-refresh" type="button">Refresh events</button>
            </div>
            <div class="wifi-events" id="wifi-events-list"></div>
          </div>
        </div>
        <div class="wifi-drawer" id="wifi-drawer" hidden>
          <div class="wifi-drawer-backdrop" data-drawer-close></div>
          <aside class="wifi-drawer-panel" role="dialog" aria-modal="true" aria-labelledby="wifi-drawer-title">
            <div class="wifi-drawer-head">
              <div class="wifi-drawer-head-copy">
                <span class="wifi-kicker" id="wifi-drawer-kicker"></span>
                <h2 id="wifi-drawer-title"></h2>
                <p class="muted" id="wifi-drawer-sub"></p>
              </div>
              <button class="wifi-drawer-close" id="wifi-drawer-close" type="button" aria-label="Close details">&times;</button>
            </div>
            <div class="wifi-drawer-body" id="wifi-drawer-body"></div>
          </aside>
        </div>
      </div>`;
    escEl("#wifi-refresh").addEventListener("click", refreshData);
    escEl("#wifi-config-toggle").addEventListener("click", () => setCollapsed(!state.collapsed));
    escEl("#wifi-save").addEventListener("click", saveConfig);
    escEl("#wifi-test").addEventListener("click", testConnection);
    escEl("#wifi-auth").addEventListener("change", syncAuthFields);
    escEl("#wifi-events-refresh").addEventListener("click", refreshEvents);
    escEl("#wifi-drawer-close").addEventListener("click", closeDrawer);
    state.el.querySelectorAll("[data-drawer-close]").forEach((el) => el.addEventListener("click", closeDrawer));
    state.el.addEventListener("click", (ev) => {
      const ap = ev.target.closest(".wifi-ap[data-ap-mac]");
      if (ap && state.data) {
        const item = (state.data.aps || []).find((x) => x.mac === ap.dataset.apMac);
        if (item) openDrawer("ap", item);
        return;
      }
      const invAp = ev.target.closest("tr[data-ap-mac]");
      if (invAp && state.data) {
        const item = (state.data.aps || []).find((x) => x.mac === invAp.dataset.apMac);
        if (item) openDrawer("ap", item);
        return;
      }
      const row = ev.target.closest("tr[data-client-mac]");
      if (row && state.data) {
        const item = (state.data.clients || []).find((x) => x.mac === row.dataset.clientMac);
        if (item) openDrawer("client", item);
      }
    });
    state.el.addEventListener("keydown", (ev) => {
      const ap = ev.target.closest(".wifi-ap[data-ap-mac]");
      if (ap && (ev.key === "Enter" || ev.key === " ")) {
        ev.preventDefault();
        ap.click();
      }
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") closeDrawer();
    });
    state.el.querySelectorAll("#wifi-subtabs .fw-subtab").forEach((btn) => {
      btn.addEventListener("click", () => setWifiTab(btn.dataset.wifiPane));
    });
    enhanceWifiHeads();
  }

  function drawerRow(label, value) {
    if (value == null || value === "") value = "—";
    return `<div class="wifi-drawer-row"><span>${state.api.esc(label)}</span><b>${state.api.esc(value)}</b></div>`;
  }

  function openDrawer(kind, item) {
    const drawer = escEl("#wifi-drawer");
    if (!drawer) return;
    const kicker = escEl("#wifi-drawer-kicker");
    const title = escEl("#wifi-drawer-title");
    const sub = escEl("#wifi-drawer-sub");
    const body = escEl("#wifi-drawer-body");
    let html = "";
    if (kind === "ap") {
      const online = item.state === 1;
      kicker.textContent = "Access point";
      title.textContent = item.name || item.mac || "UniFi AP";
      sub.textContent = `${item.model || "UniFi AP"}${item.serial ? " · " + item.serial : ""}`;
      html += `<div class="wifi-drawer-section"><h3>Connection</h3>
        ${drawerRow("Status", online ? "Online" : "Offline")}
        ${drawerRow("IP address", item.ip)}
        ${drawerRow("MAC", item.mac)}
        ${drawerRow("Uptime", item.uptime)}
        ${drawerRow("Firmware", item.version)}
        ${drawerRow("Clients", item.clients)}
      </div>`;
      const up = item.uplink || {};
      if (up.type || up.speed || up.mac) {
        html += `<div class="wifi-drawer-section"><h3>Uplink</h3>
          ${drawerRow("Type", up.type)}
          ${drawerRow("Speed", up.speed ? up.speed + " Mbps" : "")}
          ${drawerRow("Port", up.port)}
          ${drawerRow("Uplink MAC", up.mac)}
        </div>`;
      }
      if ((item.radios || []).length) {
        html += `<div class="wifi-drawer-section"><h3>Radios</h3>`;
        item.radios.forEach((r) => {
          html += `<div class="wifi-radio-card">
            <div class="wifi-radio-head"><b>${state.api.esc(r.radio || r.name || "Radio")}</b><span>${state.api.esc(r.channel || "—")}</span></div>
            <div class="wifi-radio-grid">
              <span>Width</span><b>${state.api.esc(r.width || "—")}</b>
              <span>Tx power</span><b>${state.api.esc(r.tx_power != null ? r.tx_power : "—")}</b>
              <span>Utilization</span><b>${r.utilization != null ? state.api.esc(r.utilization) + "%" : "—"}</b>
              <span>Clients</span><b>${state.api.esc(r.clients != null ? r.clients : "—")}</b>
              <span>Tx retries</span><b>${state.api.esc(r.retries != null ? r.retries : "—")}</b>
            </div>
          </div>`;
        });
        html += `</div>`;
      }
      if ((item.vaps || []).length) {
        html += `<div class="wifi-drawer-section"><h3>SSIDs</h3>`;
        item.vaps.forEach((v) => {
          html += `<div class="wifi-drawer-row"><span>${state.api.esc(v.ssid || "Hidden")}</span><b>${v.up === false ? "down" : (v.clients != null ? v.clients + " clients" : "up")}</b></div>`;
        });
        html += `</div>`;
      }
      if (item.cpu != null || item.mem != null || (item.temperatures || []).length) {
        html += `<div class="wifi-drawer-section"><h3>System</h3>
          ${drawerRow("CPU", item.cpu != null ? item.cpu + "%" : "")}
          ${drawerRow("Memory", item.mem != null ? item.mem + "%" : "")}
          ${(item.temperatures || []).map((t) => drawerRow(t.name || "Temperature", t.temp != null ? t.temp + "°C" : "")).join("")}
        </div>`;
      }
    } else {
      kicker.textContent = item.wired ? "Wired client" : "WiFi client";
      title.textContent = item.name || item.hostname || item.mac || "Client";
      sub.textContent = [item.ip, item.mac].filter(Boolean).join(" · ");
      html += `<div class="wifi-drawer-section"><h3>Connection</h3>
        ${drawerRow("IP address", item.ip)}
        ${drawerRow("MAC", item.mac)}
        ${drawerRow("Network", item.wired ? "Wired" : (item.ssid || "WiFi"))}
        ${drawerRow("Access point", item.ap)}
        ${drawerRow("VLAN", item.vlan)}
        ${drawerRow("Uptime", item.uptime)}
      </div>`;
      if (!item.wired) {
        html += `<div class="wifi-drawer-section"><h3>Radio</h3>
          ${drawerRow("Signal", item.signal != null ? item.signal + " dBm" : "")}
          ${drawerRow("Noise", item.noise != null ? item.noise + " dBm" : "")}
          ${drawerRow("Channel", item.channel)}
          ${drawerRow("Band", item.radio)}
          ${drawerRow("Rx rate", item.rx_rate != null ? item.rx_rate + " Mbps" : "")}
          ${drawerRow("Tx rate", item.tx_rate != null ? item.tx_rate + " Mbps" : "")}
          ${drawerRow("Tx retries", item.tx_retries)}
          ${drawerRow("Satisfaction", item.satisfaction != null ? item.satisfaction + "%" : "")}
        </div>`;
      }
      html += `<div class="wifi-drawer-section"><h3>Traffic</h3>
        ${drawerRow("Received", item.rx_bytes != null ? fmtBytes(item.rx_bytes) : "")}
        ${drawerRow("Sent", item.tx_bytes != null ? fmtBytes(item.tx_bytes) : "")}
      </div>`;
    }
    body.innerHTML = html;
    drawer.hidden = false;
  }

  function closeDrawer() {
    const drawer = escEl("#wifi-drawer");
    if (drawer) drawer.hidden = true;
  }

  function setWifiTab(pane) {
    state.tab = pane;
    state.el.querySelectorAll("#wifi-subtabs .fw-subtab").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.wifiPane === pane);
    });
    state.el.querySelectorAll(".wifi-pane[data-wifi-pane]").forEach((p) => {
      p.hidden = p.dataset.wifiPane !== pane;
    });
    if (pane === "events") refreshEvents();
    if (pane === "inventory") {
      if (state.data) renderInventory();
      else refreshData();
    }
  }

  async function refreshEvents() {
    const list = escEl("#wifi-events-list");
    if (!list) return;
    if (!state.cfg || !state.cfg.url || !ready()) {
      list.innerHTML = '<div class="wifi-events-empty muted">Configure the controller first on the Overview tab.</div>';
      return;
    }
    list.innerHTML = '<div class="wifi-events-empty muted">Loading events…</div>';
    try {
      const d = await state.api.api("events", { limit: 100 });
      if (!d.ok) throw new Error(d.error || "Could not load events");
      renderEvents(d);
    } catch (err) {
      list.innerHTML = `<div class="wifi-events-empty is-bad">${state.api.esc(friendlyError(err.message))}</div>`;
    }
  }

  function renderEvents(d) {
    const list = escEl("#wifi-events-list");
    const sub = escEl("#wifi-events-sub");
    const events = d.events || [];
    if (sub) sub.textContent = `${events.length} recent event${events.length === 1 ? "" : "s"}`;
    if (!events.length) {
      list.innerHTML = '<div class="wifi-events-empty muted">No WiFi events reported.</div>';
      return;
    }
    list.innerHTML = events.map((e) => {
      const bits = [];
      if (e.client) bits.push(state.api.esc(e.client));
      if (e.mac) bits.push(state.api.esc(e.mac));
      if (e.hostname && e.hostname !== e.client) bits.push(state.api.esc(e.hostname));
      if (e.ssid) bits.push("SSID " + state.api.esc(e.ssid));
      if (e.ap) bits.push("AP " + state.api.esc(e.ap));
      if (e.channel) bits.push("ch " + state.api.esc(e.channel));
      if (e.radio) bits.push(state.api.esc(e.radio));
      return `<div class="wifi-event" data-sev="${state.api.esc(e.severity || "info")}">
        <span class="wifi-event-dot" aria-hidden="true"></span>
        <div class="wifi-event-copy">
          <div class="wifi-event-title">${state.api.esc(e.title || e.key || "WiFi event")}</div>
          ${bits.length ? `<div class="wifi-event-detail">${bits.join(" · ")}</div>` : ""}
          ${e.message && e.message !== e.title ? `<div class="wifi-event-message">${state.api.esc(e.message)}</div>` : ""}
        </div>
        <span class="wifi-event-time">${state.api.formatRelative(e.time)}</span>
      </div>`;
    }).join("");
  }

  function setCollapsed(collapsed) {
    state.collapsed = !!collapsed;
    const card = state.el.querySelector(".wifi-config");
    if (!card) return;
    card.classList.toggle("is-collapsed", state.collapsed);
    [".wifi-form", ".wifi-actions", ".wifi-hint"].forEach((sel) => {
      const node = state.el.querySelector(sel);
      if (node) node.hidden = state.collapsed;
    });
    const toggle = escEl("#wifi-config-toggle");
    if (toggle) toggle.textContent = state.collapsed ? "Configure" : "Hide settings";
    const sub = escEl("#wifi-config-sub");
    if (!sub) return;
    if (state.collapsed && state.cfg && state.cfg.url) {
      const ctype = state.cfg.controller_type === "unifi_os" ? "UniFi OS" : "Classic";
      const auth = state.cfg.auth_mode === "api_key" ? "API key" : "local login";
      sub.textContent = `${state.cfg.url} · ${ctype} · ${auth}`;
    } else {
      sub.textContent = "Read-only access to your UniFi controller. Credentials stay on the router.";
    }
  }

  function ready() {
    if (!state.cfg) return false;
    return state.cfg.auth_mode === "api_key"
      ? !!state.secret.api_key
      : !!(state.cfg.username && state.secret.password);
  }

  function syncAuthFields() {
    const mode = escEl("#wifi-auth").value;
    state.el.querySelectorAll(".wifi-local").forEach((el) => { el.hidden = mode !== "local"; });
    state.el.querySelectorAll(".wifi-key").forEach((el) => { el.hidden = mode !== "api_key"; });
  }

  async function loadConfig(autoRefresh = true, collapseOnReady = false) {
    try {
      const d = await state.api.getConfig();
      state.cfg = (d && d.config) || {};
      state.secret = (d && d.secret_configured) || {};
      escEl("#wifi-url").value = state.cfg.url || "";
      escEl("#wifi-ctype").value = state.cfg.controller_type || "classic";
      escEl("#wifi-auth").value = state.cfg.auth_mode || "local";
      escEl("#wifi-user").value = state.cfg.username || "";
      escEl("#wifi-site").value = state.cfg.site || "default";
      escEl("#wifi-verify").checked = state.cfg.verify_tls !== false;
      const key = escEl("#wifi-key");
      const pass = escEl("#wifi-pass");
      key.value = "";
      pass.value = "";
      key.placeholder = state.secret.api_key ? "API key configured — leave blank to keep" : "UniFi OS API key";
      pass.placeholder = state.secret.password ? "Password configured — leave blank to keep" : "UniFi password";
      syncAuthFields();
      if (autoRefresh && state.cfg.url && ready()) refreshData();
      else renderBento([], [], "");
      if (collapseOnReady && ready()) setCollapsed(true);
    } catch (err) {
      setMsg(err.message, true);
    }
  }

  function collectConfig() {
    return {
      url: escEl("#wifi-url").value.trim(),
      controller_type: escEl("#wifi-ctype").value,
      auth_mode: escEl("#wifi-auth").value,
      username: escEl("#wifi-user").value.trim(),
      password: escEl("#wifi-pass").value,
      api_key: escEl("#wifi-key").value.trim(),
      site: escEl("#wifi-site").value.trim() || "default",
      verify_tls: !!escEl("#wifi-verify").checked,
    };
  }

  async function persistConfig() {
    const d = await state.api.saveConfig(collectConfig());
    if (!d.ok) throw new Error(d.error || "Save failed");
    escEl("#wifi-key").value = "";
    escEl("#wifi-pass").value = "";
    await loadConfig(false);
    return d;
  }

  async function saveConfig() {
    setMsg("Saving…", false);
    try {
      await persistConfig();
      setCollapsed(true);
      setMsg("Saved.", false);
    } catch (err) {
      setMsg(err.message, true);
    }
  }

  function friendlyError(msg) {
    const text = String(msg || "");
    if (/CERTIFICATE_VERIFY_FAILED|certificate verify failed/i.test(text)) {
      return text + " — if this is the controller's self-signed certificate, uncheck Verify TLS certificate and save again.";
    }
    return text;
  }

  async function testConnection() {
    setMsg("Saving and testing…", false);
    try {
      await persistConfig();
      const d = await state.api.api("test", {});
      if (d.ok) setCollapsed(true);
      setMsg(d.ok ? "Connection OK." : friendlyError(d.error || "Connection failed."), !d.ok);
    } catch (err) {
      setMsg(friendlyError(err.message), true);
    }
  }

  async function refreshData() {
    if (state.busy) return;
    if (!state.cfg || !state.cfg.url || !ready()) {
      renderData(null);
      return;
    }
    state.busy = true;
    const btn = escEl("#wifi-refresh");
    if (btn) btn.disabled = true;
    try {
      const d = await state.api.api("overview", {});
      if (!d.ok) throw new Error(d.error || "Controller request failed");
      renderData(d);
      refreshTraffic();
      refreshConnectivity();
      if (state.tab === "inventory") renderInventory();
      setMsg("Updated " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), false);
    } catch (err) {
      renderData(null, friendlyError(err.message));
      setMsg(friendlyError(err.message), true);
    } finally {
      state.busy = false;
      if (btn) btn.disabled = false;
    }
  }

  function renderBento(aps, clients, error) {
    const n = (id, value) => {
      const el = escEl(id);
      if (el) el.textContent = value;
    };
    const wireless = clients.filter((c) => !c.wired).length;
    const connected = !error && !!(state.cfg && state.cfg.url && ready());
    n("#wifi-kpi-aps", connected ? aps.length : "—");
    n("#wifi-kpi-clients", connected ? clients.length : "—");
    n("#wifi-kpi-wireless", connected ? wireless : "—");
    n("#wifi-kpi-wired", connected ? clients.length - wireless : "—");
    const status = escEl("#wifi-hero-status");
    const orb = escEl("#wifi-hero-orb");
    const chip = escEl("#wifi-hero-chip");
    const sub = escEl("#wifi-hero-sub");
    if (error) {
      if (status) status.textContent = "Offline";
      if (orb) orb.src = "/api/plugins/unifi/asset/images/wifi-off.webp";
      if (chip) { chip.textContent = "error"; chip.className = "wifi-hero-chip is-bad"; }
      if (sub) sub.textContent = error;
    } else if (!connected) {
      if (status) status.textContent = "Not connected";
      if (orb) orb.src = "/api/plugins/unifi/asset/images/wifi-off.webp";
      if (chip) { chip.textContent = "setup"; chip.className = "wifi-hero-chip"; }
      if (sub) sub.textContent = "Configure the controller to load access points.";
    } else {
      if (status) status.textContent = "Online";
      if (orb) orb.src = "/api/plugins/unifi/asset/images/wifi_on.webp";
      if (chip) { chip.textContent = aps.length + " AP" + (aps.length === 1 ? "" : "s"); chip.className = "wifi-hero-chip is-up"; }
      if (sub) sub.textContent = `${aps.length} access points · ${clients.length} clients · ${wireless} wireless`;
    }
    const cname = escEl("#wifi-controller-name");
    const csub = escEl("#wifi-controller-sub");
    const ctags = escEl("#wifi-controller-tags");
    if (!cname) return;
    if (state.cfg && state.cfg.url) {
      const ctype = state.cfg.controller_type === "unifi_os" ? "UniFi OS" : "Classic";
      const auth = state.cfg.auth_mode === "api_key" ? "API key" : "Local auth";
      cname.textContent = state.cfg.url;
      csub.textContent = `${ctype} · site ${state.cfg.site || "default"}`;
      ctags.innerHTML = `<span>${state.api.esc(auth)}</span><span>${state.cfg.verify_tls === false ? "TLS verify off" : "TLS verify on"}</span>`;
    } else {
      cname.textContent = "Not configured";
      csub.textContent = "Add your UniFi controller below.";
      ctags.innerHTML = "";
    }
  }

  function apCard(ap) {
    const online = ap.state === 1;
    return `<div class="wifi-ap" data-state="${online ? "up" : "down"}" data-ap-mac="${state.api.esc(ap.mac)}" tabindex="0" role="button" title="Open access point details">
      <div class="wifi-ap-top">
        <span class="wifi-ap-ico" aria-hidden="true">${wifiIcon("ap")}</span>
        <div class="wifi-ap-title">
          <b>${state.api.esc(ap.name)}</b>
          <span class="wifi-ap-model">${state.api.esc(ap.model || "UniFi AP")}</span>
        </div>
        <span class="wifi-ap-status${online ? " is-up" : ""}">${online ? "online" : "offline"}</span>
      </div>
      <div class="wifi-ap-meta"><span class="mono">${state.api.esc(ap.ip || ap.mac)}</span></div>
      <div class="wifi-ap-stats">
        <span><b>${state.api.esc(ap.clients)}</b> clients</span>
        <span><b>${state.api.esc(ap.uptime)}</b> uptime</span>
        <span>${state.api.esc(ap.version)}</span>
      </div>
    </div>`;
  }

  function renderInventory() {
    const box = escEl("#wifi-inventory");
    if (!box) return;
    if (!state.data) {
      box.innerHTML = '<div class="card wifi-inventory-empty"><p class="muted">Open Overview or refresh the controller to load inventory.</p></div>';
      return;
    }
    const aps = state.data.aps || [];
    const clients = state.data.clients || [];
    const ssids = new Map();
    const vlans = new Map();
    clients.forEach((c) => {
      if (!c.wired) {
        const key = c.ssid || "Hidden SSID";
        ssids.set(key, (ssids.get(key) || 0) + 1);
      }
      const v = (c.vlan == null || c.vlan === "") ? "Unspecified" : String(c.vlan);
      vlans.set(v, (vlans.get(v) || 0) + 1);
    });
    const weak = clients.filter((c) => {
      const n = Number(c.signal);
      return !c.wired && !isNaN(n) && n <= -75;
    });
    const listHtml = (map) => [...map.entries()].sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `<div class="wifi-inv-list-row"><span>${state.api.esc(name)}</span><b>${count}</b></div>`).join("") ||
      '<div class="wifi-inv-list-row muted">No clients</div>';
    const apRows = aps.map((ap) => {
      const up = ap.uplink || {};
      return `<tr data-ap-mac="${state.api.esc(ap.mac)}" title="Open access point details">
        <td><b>${state.api.esc(ap.name)}</b><span class="wifi-inv-model">${state.api.esc(ap.model)}</span></td>
        <td><span class="wifi-ap-status${ap.state === 1 ? " is-up" : ""}">${ap.state === 1 ? "online" : "offline"}</span></td>
        <td class="mono">${state.api.esc(ap.ip || ap.mac)}</td>
        <td>${state.api.esc(up.type || "—")}</td>
        <td>${state.api.esc(up.port || "—")}</td>
        <td>${up.speed ? state.api.esc(up.speed) + " Mbps" : "—"}</td>
        <td>${state.api.esc(ap.clients)}</td>
        <td>${state.api.esc(ap.version || "—")}</td>
      </tr>`;
    }).join("");
    const topology = aps.map((ap) => {
      const up = ap.uplink || {};
      return `<div class="wifi-top-ap${ap.state === 1 ? "" : " is-off"}">
        <span class="wifi-top-dot"></span>
        <div><b>${state.api.esc(ap.name)}</b><small>${up.speed ? state.api.esc(up.speed) + " Mbps" : "uplink —"}${up.port ? " · port " + state.api.esc(up.port) : ""}</small></div>
      </div>`;
    }).join("") || '<div class="muted">No access points.</div>';

    box.innerHTML = `
      <div class="wifi-inv-grid">
        <div class="card wifi-inv-card">
          <div class="wifi-head">
            <div><h2>Access Point Inventory</h2><p class="muted">${aps.length} AP${aps.length === 1 ? "" : "s"} · ${clients.length} clients</p></div>
            <button class="btn btn-sm" id="wifi-inv-refresh" type="button">Refresh</button>
          </div>
          <div class="table-wrap">
            <table class="wifi-inv-table">
              <thead><tr><th>Access point</th><th>Status</th><th>IP</th><th>Uplink</th><th>Port</th><th>Speed</th><th>Clients</th><th>Firmware</th></tr></thead>
              <tbody>${apRows || '<tr><td colspan="8" class="muted">No APs reported.</td></tr>'}</tbody>
            </table>
          </div>
        </div>
        <div class="card wifi-top-card">
          <div class="wifi-head"><div><h2>Topology</h2><p class="muted">Controller → access points</p></div></div>
          <div class="wifi-topology">
            <div class="wifi-top-controller"><span class="wifi-kicker">Controller</span><b>${state.api.esc(state.cfg.url || "—")}</b><small>site ${state.api.esc(state.cfg.site || "default")}</small></div>
            <div class="wifi-top-branches">${topology}</div>
          </div>
        </div>
      </div>
      <div class="wifi-inv-grid wifi-inv-lists">
        <div class="card wifi-inv-list-card"><div class="wifi-head"><div><h2>Clients by SSID</h2></div></div><div class="wifi-inv-list">${listHtml(ssids)}</div></div>
        <div class="card wifi-inv-list-card"><div class="wifi-head"><div><h2>Clients by VLAN</h2></div></div><div class="wifi-inv-list">${listHtml(vlans)}</div></div>
        <div class="card wifi-inv-list-card"><div class="wifi-head"><div><h2>Weak clients</h2><p class="muted">≤ −75 dBm</p></div></div><div class="wifi-inv-list">${weak.length ? weak.map((c) => `<div class="wifi-inv-list-row"><span>${state.api.esc(c.name || c.mac)}<small>${state.api.esc(c.ap || "")}</small></span><b>${state.api.esc(c.signal)} dBm</b></div>`).join("") : '<div class="wifi-inv-list-row muted">None</div>'}</div></div>
      </div>`;
    escEl("#wifi-inv-refresh").addEventListener("click", refreshData);
    enhanceWifiHeads();
  }

  function signalBadge(signal) {
    if (signal == null || signal === "") return '<span class="muted">—</span>';
    const n = Number(signal);
    const q = isNaN(n) ? "unknown" : (n >= -65 ? "good" : n >= -75 ? "fair" : "weak");
    return `<span class="wifi-signal ${q}">${state.api.esc(signal)} dBm</span>`;
  }

  function filterClients() {
    const input = escEl("#wifi-client-search");
    const body = escEl("#wifi-client-body");
    const count = escEl("#wifi-client-count");
    if (!body) return;
    const q = (input ? input.value : state.clientFilter || "").trim().toLowerCase();
    let shown = 0;
    body.querySelectorAll("tr[data-client-mac]").forEach((row) => {
      const hit = !q || row.innerText.toLowerCase().includes(q);
      row.hidden = !hit;
      if (hit) shown++;
    });
    const total = body.querySelectorAll("tr[data-client-mac]").length;
    if (count) count.textContent = q ? `${shown} of ${total} clients` : `${total} clients`;
  }

  function exportClientsCsv() {
    if (!state.data) return;
    const rows = [["Client","Hostname","IP","MAC","SSID","AP","Signal dBm","Rx Mbps","Tx Mbps","Uptime","VLAN","Wired"]];
    (state.data.clients || []).forEach((c) => {
      rows.push([c.name || "", c.hostname || "", c.ip || "", c.mac || "", c.ssid || "",
        c.ap || "", c.signal != null ? c.signal : "", c.rx_rate != null ? c.rx_rate : "",
        c.tx_rate != null ? c.tx_rate : "", c.uptime || "", c.vlan != null ? c.vlan : "",
        c.wired ? "yes" : "no"]);
    });
    const csv = rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "tuxwall-wifi-clients-" + new Date().toISOString().slice(0, 10) + ".csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function fmtMbps(v) {
    if (v == null || isNaN(Number(v))) return "—";
    const n = Number(v);
    return n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2);
  }

  function niceMax(v) {
    const n = Number(v) || 0;
    if (n <= 0) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(n)));
    const step = p / 2;
    return Math.ceil((n * 1.15) / step) * step;
  }

  function trafficLegend(d) {
    const sm = d.summary || {};
    const hidden = state.trafficHidden || {};
    const series = [
      { key: "down", label: "Avg Download", value: fmtMbps(sm.down), unit: "Mbps" },
      { key: "up", label: "Avg Upload", value: fmtMbps(sm.up), unit: "Mbps" },
      { key: "retry", label: "TX Retries", value: sm.retry != null ? Number(sm.retry).toFixed(1) : "—", unit: "%" },
      { key: "clients", label: "Clients", value: sm.clients != null ? sm.clients : "—", unit: "" }
    ];
    return series.map((s) => `<button class="wifi-traffic-legend-item${hidden[s.key] ? " is-off" : ""}" type="button" data-series="${s.key}" aria-pressed="${hidden[s.key] ? "false" : "true"}">
      <span class="wifi-traffic-swatch" data-key="${s.key}"></span>
      <span class="wifi-traffic-legend-copy"><small>${s.label}</small><b>${s.value}${s.unit ? ` <em>${s.unit}</em>` : ""}</b></span>
    </button>`).join("");
  }

  function renderTraffic(d, error) {
    const box = escEl("#wifi-traffic");
    if (!box) return;
    state.traffic = d || null;
    if (!d || d.configured === false || error) {
      box.innerHTML = `<div class="card wifi-traffic-card">
        <div class="wifi-traffic-head">
          <div class="wifi-traffic-brand">
            <div><h2>Network Traffic</h2><p class="muted">Last 12 hours</p></div>
          </div>
        </div>
        <div class="wifi-traffic-empty muted">${state.api.esc(error || "Configure the controller to load 12-hour traffic.")}</div>
      </div>`;
      return;
    }
    const buckets = d.buckets || [];
    if (!buckets.length) {
      box.innerHTML = `<div class="card wifi-traffic-card">
        <div class="wifi-traffic-head">
          <div class="wifi-traffic-brand">
            <div><h2>Network Traffic</h2><p class="muted">Last 12 hours</p></div>
          </div>
        </div>
        <div class="wifi-traffic-empty muted">No 5-minute traffic reports yet. Data appears after the controller has collected history.</div>
      </div>`;
      return;
    }

    const hidden = state.trafficHidden || {};
    const W = Math.max(300, Math.round(box.clientWidth || 920));
    const H = W < 560 ? 208 : 252;
    const L = W < 560 ? 38 : 50;
    const R = W < 560 ? 38 : 52;
    const T = 18;
    const B = 30;
    const pw = W - L - R;
    const ph = H - T - B;
    const n = buckets.length;
    const x = (i) => L + (n === 1 ? pw / 2 : (i / (n - 1)) * pw);
    const vals = (key) => buckets.map((b) => (b[key] == null ? null : Number(b[key])));
    let leftMax = 1;
    vals("down").concat(vals("up")).forEach((v) => { if (v != null) leftMax = Math.max(leftMax, v); });
    leftMax = niceMax(leftMax);
    let rightMax = 5;
    vals("retry").concat(vals("clients")).forEach((v) => { if (v != null) rightMax = Math.max(rightMax, v); });
    rightMax = niceMax(rightMax);
    const yL = (v) => T + ph - (Math.max(0, Math.min(v, leftMax)) / leftMax) * ph;
    const yR = (v) => T + ph - (Math.max(0, Math.min(v, rightMax)) / rightMax) * ph;

    const segments = (key, yFn) => {
      const out = [];
      let cur = [];
      buckets.forEach((b, i) => {
        const v = b[key];
        if (v == null) {
          if (cur.length) out.push(cur);
          cur = [];
        } else {
          cur.push([x(i), yFn(Number(v)), i]);
        }
      });
      if (cur.length) out.push(cur);
      return out;
    };
    const smooth = (pts) => {
      if (!pts.length) return "";
      if (pts.length === 1) return `M${pts[0][0]},${pts[0][1]}`;
      let path = `M${pts[0][0]},${pts[0][1]}`;
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[i - 1] || pts[i];
        const p1 = pts[i];
        const p2 = pts[i + 1];
        const p3 = pts[i + 2] || p2;
        const c1x = p1[0] + (p2[0] - p0[0]) / 6;
        const c1y = p1[1] + (p2[1] - p0[1]) / 6;
        const c2x = p2[0] - (p3[0] - p1[0]) / 6;
        const c2y = p2[1] - (p3[1] - p1[1]) / 6;
        path += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
      }
      return path;
    };
    const area = (pts, base) => {
      if (!pts.length) return "";
      const line = smooth(pts);
      const last = pts[pts.length - 1];
      const first = pts[0];
      return `${line} L${last[0].toFixed(1)},${base} L${first[0].toFixed(1)},${base} Z`;
    };

    const grid = [];
    const gridN = W < 560 ? 3 : 4;
    for (let i = 0; i <= gridN; i++) {
      const gy = T + (i / gridN) * ph;
      const lv = leftMax * (1 - i / gridN);
      const rv = rightMax * (1 - i / gridN);
      grid.push(`<line class="wifi-chart-grid" x1="${L}" y1="${gy.toFixed(1)}" x2="${W - R}" y2="${gy.toFixed(1)}"/>`);
      grid.push(`<text class="wifi-chart-axis" x="${L - 8}" y="${(gy + 3.5).toFixed(1)}" text-anchor="end">${lv >= 10 ? lv.toFixed(0) : lv.toFixed(1)}</text>`);
      grid.push(`<text class="wifi-chart-axis" x="${W - R + 8}" y="${(gy + 3.5).toFixed(1)}">${rv >= 10 ? rv.toFixed(0) : rv.toFixed(0)}</text>`);
    }

    const ticks = W < 560 ? 4 : 6;
    const timeLabels = [];
    for (let i = 0; i < ticks; i++) {
      const idx = Math.round((i / (ticks - 1)) * (n - 1));
      const b = buckets[idx];
      const label = new Date(b.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      timeLabels.push(`<text class="wifi-chart-time" x="${x(idx).toFixed(1)}" y="${H - 8}" text-anchor="${i === 0 ? "start" : i === ticks - 1 ? "end" : "middle"}">${label}</text>`);
    }

    const defs = `<defs>
      <linearGradient id="wifiGradDown" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--wifi-chart-down)" stop-opacity=".42"/>
        <stop offset="100%" stop-color="var(--wifi-chart-down)" stop-opacity="0"/>
      </linearGradient>
      <linearGradient id="wifiGradUp" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--wifi-chart-up)" stop-opacity=".30"/>
        <stop offset="100%" stop-color="var(--wifi-chart-up)" stop-opacity="0"/>
      </linearGradient>
      <linearGradient id="wifiGradRetry" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--wifi-chart-retry)" stop-opacity=".16"/>
        <stop offset="100%" stop-color="var(--wifi-chart-retry)" stop-opacity="0"/>
      </linearGradient>
    </defs>`;

    const downSegs = segments("down", yL);
    const upSegs = segments("up", yL);
    const retrySegs = segments("retry", yR);
    const clientSegs = segments("clients", yR);
    const base = T + ph;
    let paths = "";
    if (!hidden.down) {
      downSegs.forEach((pts) => { paths += `<path class="wifi-chart-area" d="${area(pts, base)}" fill="url(#wifiGradDown)"/>`; });
      downSegs.forEach((pts) => { paths += `<path class="wifi-chart-line is-down" d="${smooth(pts)}"/>`; });
    }
    if (!hidden.up) {
      upSegs.forEach((pts) => { paths += `<path class="wifi-chart-area" d="${area(pts, base)}" fill="url(#wifiGradUp)"/>`; });
      upSegs.forEach((pts) => { paths += `<path class="wifi-chart-line is-up" d="${smooth(pts)}"/>`; });
    }
    if (!hidden.retry) {
      retrySegs.forEach((pts) => { paths += `<path class="wifi-chart-line is-retry" d="${smooth(pts)}"/>`; });
    }
    if (!hidden.clients) {
      clientSegs.forEach((pts) => { paths += `<path class="wifi-chart-line is-clients" d="${smooth(pts)}"/>`; });
    }

    const svg = `<svg class="wifi-traffic-svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="UniFi network traffic over the last 12 hours">
      ${defs}
      <text class="wifi-chart-unit" x="${L}" y="10">Mbps</text>
      <text class="wifi-chart-unit" x="${W - R}" y="10" text-anchor="end">clients / retry %</text>
      <g class="wifi-chart-grid-g">${grid.join("")}</g>
      <g class="wifi-chart-series">${paths}</g>
      <g class="wifi-chart-times">${timeLabels.join("")}</g>
      <g class="wifi-chart-cursor" hidden>
        <line class="wifi-chart-cursor-line" x1="0" y1="${T}" x2="0" y2="${base}"/>
        <circle class="wifi-chart-dot is-down" r="4" hidden/>
        <circle class="wifi-chart-dot is-up" r="4" hidden/>
        <circle class="wifi-chart-dot is-retry" r="3" hidden/>
        <circle class="wifi-chart-dot is-clients" r="3" hidden/>
      </g>
      <rect class="wifi-chart-hit" x="${L}" y="${T}" width="${pw}" height="${ph}" fill="transparent"/>
    </svg>`;

    box.innerHTML = `<div class="card wifi-traffic-card">
      <div class="wifi-traffic-head">
        <div class="wifi-traffic-brand">
          <span class="wifi-head-ico" aria-hidden="true">${wifiIcon("traffic")}</span>
          <div class="wifi-traffic-title"><h2>Network Traffic</h2><p class="muted">Access point throughput · last 12 hours</p></div>
        </div>
        <span class="wifi-traffic-live"><i></i>Live · 5 min</span>
      </div>
      <div class="wifi-traffic-legend">${trafficLegend(d)}</div>
      <div class="wifi-traffic-chart" id="wifi-traffic-chart">
        ${svg}
        <div class="wifi-traffic-tip" hidden></div>
      </div>
      <div class="wifi-traffic-foot"><span>${d.summary && d.summary.aps ? d.summary.aps : 0} access point${d.summary && d.summary.aps === 1 ? "" : "s"}</span><span>Peak ↓ ${fmtMbps(d.summary && d.summary.peak_down)} Mbps · Peak ↑ ${fmtMbps(d.summary && d.summary.peak_up)} Mbps</span></div>
    </div>`;

    box.querySelectorAll(".wifi-traffic-legend-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        const key = btn.dataset.series;
        state.trafficHidden = { ...(state.trafficHidden || {}) };
        state.trafficHidden[key] = !state.trafficHidden[key];
        renderTraffic(state.traffic);
      });
    });

    const wrap = escEl("#wifi-traffic-chart");
    const tip = wrap && wrap.querySelector(".wifi-traffic-tip");
    const cursor = wrap && wrap.querySelector(".wifi-chart-cursor");
    const hit = wrap && wrap.querySelector(".wifi-chart-hit");
    const cursorLine = wrap && wrap.querySelector(".wifi-chart-cursor-line");
    if (!wrap || !tip || !cursor || !hit) return;
    const dots = {
      down: wrap.querySelector(".wifi-chart-dot.is-down"),
      up: wrap.querySelector(".wifi-chart-dot.is-up"),
      retry: wrap.querySelector(".wifi-chart-dot.is-retry"),
      clients: wrap.querySelector(".wifi-chart-dot.is-clients")
    };
    const setSvgHidden = (node, on) => {
      if (!node) return;
      if (on) node.setAttribute("hidden", "");
      else node.removeAttribute("hidden");
    };
    const hideDots = () => Object.values(dots).forEach((dot) => setSvgHidden(dot, true));
    const move = (ev) => {
      const rect = wrap.getBoundingClientRect();
      const px = ((ev.clientX - rect.left) / rect.width) * W;
      let idx = Math.round(((px - L) / pw) * (n - 1));
      idx = Math.max(0, Math.min(n - 1, idx));
      const b = buckets[idx];
      setSvgHidden(cursor, false);
      cursorLine.setAttribute("x1", x(idx));
      cursorLine.setAttribute("x2", x(idx));
      const place = (dot, key, yFn) => {
        if (!dot) return;
        if (hidden[key] || b[key] == null) { setSvgHidden(dot, true); return; }
        setSvgHidden(dot, false);
        dot.setAttribute("cx", x(idx));
        dot.setAttribute("cy", yFn(Number(b[key])));
      };
      place(dots.down, "down", yL);
      place(dots.up, "up", yL);
      place(dots.retry, "retry", yR);
      place(dots.clients, "clients", yR);
      const time = new Date(b.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const row = (key, label, val) => hidden[key] ? "" : `<div class="wifi-traffic-tip-row" data-key="${key}"><span>${label}</span><b>${val}</b></div>`;
      tip.innerHTML = `<div class="wifi-traffic-tip-time">${time}</div>
        ${row("down", "Download", `${fmtMbps(b.down)} Mbps`)}
        ${row("up", "Upload", `${fmtMbps(b.up)} Mbps`)}
        ${row("retry", "TX Retries", `${b.retry == null ? "—" : Number(b.retry).toFixed(1)}%`)}
        ${row("clients", "Clients", b.clients == null ? "—" : b.clients)}`;
      tip.hidden = false;
      const leftPct = (x(idx) / W) * 100;
      tip.style.left = `${leftPct}%`;
      tip.classList.toggle("is-flip", leftPct > 66);
    };
    wrap.addEventListener("mousemove", move);
    wrap.addEventListener("mouseleave", () => {
      setSvgHidden(cursor, true);
      tip.hidden = true;
      hideDots();
    });
    if (!state.trafficResizeBound) {
      state.trafficResizeBound = true;
      let t = 0;
      window.addEventListener("resize", () => {
        clearTimeout(t);
        t = setTimeout(() => {
          if (state.traffic && state.el && state.el.querySelector("#wifi-traffic")) renderTraffic(state.traffic);
        }, 180);
      });
    }
  }

  async function refreshTraffic() {
    const box = escEl("#wifi-traffic");
    if (!box) return;
    if (!state.cfg || !state.cfg.url || !ready()) {
      renderTraffic(null);
      return;
    }
    box.innerHTML = `<div class="card wifi-traffic-card"><div class="wifi-traffic-loading"><span class="wifi-traffic-spinner"></span>Loading 12-hour traffic…</div></div>`;
    try {
      const d = await state.api.api("traffic", {});
      if (!d.ok) throw new Error(d.error || "Could not load traffic history");
      renderTraffic(d);
    } catch (err) {
      renderTraffic(null, friendlyError(err.message));
    }
  }

  function connLatency(ms) {
    const n = Number(ms) || 0;
    if (!n) return "—";
    return n >= 1000 ? `${(n / 1000).toFixed(1)} s` : `${n} ms`;
  }

  function renderConnectivity(d, error) {
    const box = escEl("#wifi-connectivity");
    if (!box) return;
    state.connectivity = d || null;
    const head = (sub) => `<div class="wifi-head has-ico">
      <span class="wifi-head-ico" aria-hidden="true">${wifiIcon("connectivity")}</span>
      <div><h2>WiFi Connectivity</h2><p class="muted">${sub}</p></div>
    </div>`;
    if (!d || d.configured === false || !d.available || error) {
      const msg = error || (d && d.message) || "Configure the controller to load WiFi connectivity.";
      box.innerHTML = `<div class="card wifi-conn-card">
        ${head("Last 12 hours · connection success")}
        <div class="wifi-conn-empty muted">${state.api.esc(msg)}</div>
      </div>`;
      return;
    }
    const a = d.attempts || {};
    const success = Number(a.success) || 0;
    const tone = success >= 90 ? "is-good" : success >= 75 ? "is-watch" : "is-bad";
    const toneVar = success >= 90 ? "var(--green)" : success >= 75 ? "var(--amber)" : "var(--red)";
    const label = success >= 90 ? "Healthy" : success >= 75 ? "Watch" : "Needs attention";
    const bars = [
      { key: "association", label: "Association", value: Number(a.association) || 0, color: "var(--wifi-chart-down)" },
      { key: "authentication", label: "Authentication", value: Number(a.authentication) || 0, color: "var(--wifi-chart-up)" },
      { key: "dhcp", label: "DHCP", value: Number(a.dhcp) || 0, color: "#bc8cff" },
      { key: "dns", label: "DNS", value: Number(a.dns) || 0, color: "var(--wifi-chart-retry)" },
    ];
    const failureRank = Object.entries(d.failures || {})
      .filter(([k, v]) => k !== "other" && Number(v) > 0)
      .sort((x, y) => Number(y[1]) - Number(x[1]));
    let failureNote = "No failed handshakes in this window";
    if (failureRank.length) {
      failureNote = `Most failures: ${state.api.esc(failureRank[0][0])} (${failureRank[0][1]})`;
    }
    const lat = d.latency || {};
    const total = Number(a.total) || 0;
    const failed = Number(a.failed) || 0;
    const sub = `Last ${d.hours || 12} hours · ${total} connection attempt${total === 1 ? "" : "s"} · ${d.clients || 0} client${d.clients === 1 ? "" : "s"}`;
    const barHtml = bars.map((bar) => `<div class="wifi-conn-bar" data-stage="${bar.key}" style="--bar:${bar.color};--pct:${bar.value}%">
      <div class="wifi-conn-bar-head"><span>${bar.label}</span><b>${bar.value.toFixed(1)}%</b></div>
      <div class="wifi-conn-track"><span class="wifi-conn-fill"></span></div>
    </div>`).join("");

    box.innerHTML = `<div class="card wifi-conn-card">
      <div class="wifi-head has-ico">
        <span class="wifi-head-ico" aria-hidden="true">${wifiIcon("connectivity")}</span>
        <div><h2>WiFi Connectivity</h2><p class="muted">${state.api.esc(sub)}</p></div>
        <span class="wifi-conn-badge ${tone}">${label}</span>
      </div>
      <div class="wifi-conn-body">
        <div class="wifi-conn-gauge-wrap">
          <div class="wifi-conn-gauge" style="--pct:${success};--tone:${toneVar}" role="img" aria-label="Overall connection success ${success.toFixed(1)} percent">
            <div class="wifi-conn-gauge-inner"><b>${success.toFixed(0)}<em>%</em></b><span>Success</span></div>
          </div>
          <div class="wifi-conn-caption">${failed ? `${failed} failed connection${failed === 1 ? "" : "s"}` : "All connection attempts succeeded"}</div>
        </div>
        <div class="wifi-conn-bars">${barHtml}</div>
      </div>
      <div class="wifi-conn-foot">
        <span class="wifi-conn-failures">${failureNote}</span>
        <span>Latency · assoc ${connLatency(lat.association)} · auth ${connLatency(lat.authentication)} · DHCP ${connLatency(lat.dhcp)} · total ${connLatency(lat.total)}</span>
      </div>
    </div>`;
  }

  async function refreshConnectivity() {
    const box = escEl("#wifi-connectivity");
    if (!box) return;
    if (!state.cfg || !state.cfg.url || !ready()) {
      renderConnectivity(null);
      return;
    }
    box.innerHTML = `<div class="card wifi-conn-card"><div class="wifi-traffic-loading"><span class="wifi-traffic-spinner"></span>Loading WiFi connectivity…</div></div>`;
    try {
      const d = await state.api.api("connectivity", { hours: 12 });
      if (!d.ok) throw new Error(d.error || "Could not load WiFi connectivity");
      renderConnectivity(d);
    } catch (err) {
      renderConnectivity(null, friendlyError(err.message));
    }
  }

  function renderData(d, error) {
    const box = escEl("#wifi-data");
    if (!box) return;
    state.data = d || null;
    if (!d) {
      renderBento([], [], error || "");
      box.innerHTML = `<div class="card wifi-empty"><p class="muted">${error ? state.api.esc(error) : "Configure the controller URL and credentials, then save."}</p></div>`;
      return;
    }
    const aps = d.aps || [];
    const clients = d.clients || [];
    const wireless = clients.filter((c) => !c.wired).length;
    renderBento(aps, clients, "");
    box.innerHTML = `
      <div class="wifi-aps">${aps.map(apCard).join("") || '<div class="wifi-empty muted">No access points reported.</div>'}</div>
      <div id="wifi-traffic" class="wifi-traffic"></div>
      <div id="wifi-connectivity" class="wifi-connectivity"></div>
      <div class="card wifi-clients">
        <div class="wifi-head"><div><h2>WiFi Clients</h2><p class="muted">${clients.length} associated clients</p></div></div>
        <div class="wifi-client-tools">
          <input type="search" id="wifi-client-search" placeholder="Filter by name, IP, SSID or AP…" autocomplete="off" value="${state.api.esc(state.clientFilter || "")}">
          <span class="muted" id="wifi-client-count"></span>
          <span class="toolbar-spacer"></span>
          <button class="btn btn-sm" id="wifi-csv" type="button">Export CSV</button>
        </div>
        <div class="table-wrap"><table>
          <thead><tr><th>Client</th><th>IP</th><th>SSID</th><th>AP</th><th>Signal</th><th>Rx / Tx (Mbps)</th><th>Uptime</th><th>VLAN</th></tr></thead>
          <tbody id="wifi-client-body">${clients.map((c) => `<tr data-client-mac="${state.api.esc(c.mac)}" title="Open client details">
            <td><b>${state.api.esc(c.name)}</b>${c.hostname && c.hostname !== c.name ? `<span class="muted"> · ${state.api.esc(c.hostname)}</span>` : ""}</td>
            <td class="mono">${state.api.esc(c.ip || c.mac)}</td>
            <td>${c.wired ? '<span class="badge">wired</span>' : state.api.esc(c.ssid || "—")}</td>
            <td>${state.api.esc(c.ap || "—")}</td>
            <td>${signalBadge(c.signal)}</td>
            <td class="mono">${c.rx_rate != null ? state.api.esc(c.rx_rate) : "—"} / ${c.tx_rate != null ? state.api.esc(c.tx_rate) : "—"}</td>
            <td>${state.api.esc(c.uptime || "—")}</td>
            <td>${c.vlan != null ? state.api.esc(c.vlan) : "—"}</td>
          </tr>`).join("") || '<tr><td colspan="8" class="muted">No clients reported.</td></tr>'}</tbody>
        </table></div>
      </div>`;
    const search = escEl("#wifi-client-search");
    if (search) {
      search.addEventListener("input", () => {
        state.clientFilter = search.value;
        filterClients();
      });
    }
    const csv = escEl("#wifi-csv");
    if (csv) csv.addEventListener("click", exportClientsCsv);
    filterClients();
    enhanceWifiHeads();
  }

  function mount(el, api) {
    state.el = el;
    state.api = api;
    skeleton();
    loadConfig(true, true);
  }

  function refresh() {
    if (!state.el) return;
    if (state.tab === "events") refreshEvents();
    else if (state.tab === "inventory") renderInventory();
    else loadConfig();
  }

  window.TuxWallPlugins.register("unifi", { mount, refresh });
})();
