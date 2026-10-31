/* TuxWall OpenWrt plugin — dumb-AP monitoring and management over SSH. */
(function () {
  "use strict";
  const state = {
    el: null, api: null, cfg: null, secret: {}, busy: false,
    tab: "overview", data: null, clientFilter: "", editing: null, updated: 0
  };

  const ICONS = {
    wifi: '<path d="M2.5 8.5a15 15 0 0 1 19 0M5.5 12a10 10 0 0 1 13 0M8.8 15.5a5 5 0 0 1 6.4 0"/><circle cx="12" cy="19" r="1"/>',
    wifiOff: '<path d="M2.5 8.5a15 15 0 0 1 6.2-3.3M15 5.4a15 15 0 0 1 6.5 3.1M5.5 12a10 10 0 0 1 3.3-2.4M15.6 9.5a10 10 0 0 1 2.9 2.5M8.8 15.5a5 5 0 0 1 4-1.1M14.6 16.1a5 5 0 0 1 .6.6"/><circle cx="12" cy="19" r="1"/><path d="M3 3l18 18"/>',
    plug: '<path d="M9 3v3M15 3v3M7 6h10a2 2 0 0 1 2 2v4a7 7 0 0 1-14 0V8a2 2 0 0 1 2-2Z"/><path d="M12 18v3"/>',
    users: '<circle cx="9" cy="8" r="3.2"/><path d="M2.6 20a6.4 6.4 0 0 1 12.8 0M15.6 5.3a3.2 3.2 0 0 1 0 5.4M18.9 20a6.4 6.4 0 0 0-2.8-5.3"/>',
    activity: '<path d="M3 12h4l2.5-6 5 12 2.5-6h4"/>',
    server: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 6.5h6M12 17.5h6"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3.6 6h.01M3.6 12h.01M3.6 18h.01"/>',
    refresh: '<path d="M20 11a8 8 0 0 0-14-5L4 8"/><path d="M4 3v5h5"/><path d="M4 13a8 8 0 0 0 14 5l2-2"/><path d="M20 21v-5h-5"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    rf: '<path d="M4 20v-2M9 20v-6M14 20v-10M19 20v-14"/><path d="M3 6l18 12" opacity="0.35"/>',
    net: '<circle cx="12" cy="12" r="2.5"/><path d="M7.5 7.5a6.4 6.4 0 0 0 0 9M16.5 7.5a6.4 6.4 0 0 1 0 9M4.9 4.9a10 10 0 0 0 0 14.2M19.1 4.9a10 10 0 0 1 0 14.2"/>',
    vlan: '<path d="M4 7h16M4 12h16M4 17h16"/><circle cx="7" cy="7" r="1.1" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.1" fill="currentColor" stroke="none"/><circle cx="17" cy="17" r="1.1" fill="currentColor" stroke="none"/>'
  };

  function svg(name) {
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;
  }
  function headIcon(name) {
    return `<span class="wifi-head-ico">${svg(name)}</span>`;
  }
  function tabIcon(name) {
    return `<svg class="tab-ic" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;
  }
  function escEl(id) { return state.el.querySelector(id); }
  function setMsg(text, bad) {
    const el = escEl("#wifi-msg");
    if (!el) return;
    el.textContent = text || "";
    el.className = "wifi-msg" + (bad ? " is-bad" : "");
    if (text && state.tab !== "overview") showToast(text, bad);
  }

  let toastTimer = null;
  function showToast(text, bad) {
    const el = escEl("#wifi-toast");
    if (!el) return;
    el.textContent = text || "";
    el.className = "wifi-toast" + (bad ? " is-bad" : "");
    el.hidden = !text;
    if (toastTimer) clearTimeout(toastTimer);
    if (text) toastTimer = setTimeout(() => { el.hidden = true; }, bad ? 7000 : 4000);
  }
  function fmtNum(n) { return (n == null || isNaN(n)) ? "—" : Number(n).toLocaleString(); }
  function ago(ts) {
    if (!ts) return "";
    const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 5) return "just now";
    if (s < 60) return s + "s ago";
    const m = Math.round(s / 60);
    if (m < 60) return m + "m ago";
    return Math.round(m / 60) + "h ago";
  }
  function hostList() {
    return String((state.cfg && state.cfg.hosts) || "").split(/[\s,;]+/).filter(Boolean);
  }
  function ready() { return hostList().length > 0; }
  function keyReady() { return !!(state.secret.ssh_key || state.secret.password); }

  function bandInfo(radio) {
    const r = String(radio || "").toLowerCase();
    if (r.startsWith("6")) return { key: "6g", short: "6 GHz" };
    if (r.startsWith("5")) return { key: "5g", short: "5 GHz" };
    if (r.startsWith("2")) return { key: "2g", short: "2.4 GHz" };
    return { key: "other", short: radio ? String(radio) : "radio" };
  }

  function signalCell(sig) {
    if (sig == null || isNaN(sig)) {
      return '<span class="wifi-sig is-unknown"><span class="wifi-sig-bars"><i></i><i></i><i></i><i></i></span><b>—</b></span>';
    }
    const s = Number(sig);
    let tone = "is-good", bars = 4;
    if (s <= -75) { tone = "is-weak"; bars = 1; }
    else if (s <= -67) { tone = "is-fair"; bars = 2; }
    else if (s <= -58) { bars = 3; }
    const meter = [0, 1, 2, 3].map((i) => `<i class="${i < bars ? "is-on" : ""}"></i>`).join("");
    return `<span class="wifi-sig ${tone}" title="${s} dBm">
      <span class="wifi-sig-bars">${meter}</span><b>${s}</b><em>dBm</em></span>`;
  }

  function skeleton() {
    state.el.innerHTML = `
      <div class="wifi-page">
        <div class="wifi-toast" id="wifi-toast" role="status" aria-live="polite" hidden></div>
        <section class="wifi-bento">
          <article class="wifi-card wifi-hero" data-accent="blue">
            <div class="wifi-hero-plate">
              <div class="wifi-hero-art"><img src="/api/plugins/openwrt/asset/images/fierce-penguin-wi-fi.webp" alt="" decoding="async"></div>
              <div class="wifi-hero-head">
                <span class="wifi-brand" role="img" aria-label="OpenWrt">
                  <img class="brand-dark" src="/api/plugins/openwrt/asset/images/openwrt-logo-dark.svg" alt="" decoding="async">
                  <img class="brand-light" src="/api/plugins/openwrt/asset/images/openwrt-logo.svg" alt="" decoding="async">
                </span>
                <span class="wifi-chip" id="wifi-hero-chip">Not configured</span>
              </div>
              <div class="wifi-hero-copy">
                <div class="wifi-hero-value"><span class="wifi-hero-dot" id="wifi-hero-dot"></span><span id="wifi-hero-state">Not configured</span></div>
                <p class="wifi-hero-sub" id="wifi-hero-sub">Add your access points to start monitoring.</p>
              </div>
            </div>
          </article>

          <article class="wifi-card wifi-kpi" data-accent="green">
            <span class="wifi-kicker">Access points</span>
            <div class="wifi-kpi-row"><div class="wifi-num" id="wifi-kpi-aps">—</div></div>
            <div class="wifi-kpi-sub" id="wifi-kpi-aps-sub">not polled yet</div>
          </article>
          <article class="wifi-card wifi-kpi" data-accent="blue">
            <span class="wifi-kicker">Clients</span>
            <div class="wifi-kpi-row"><div class="wifi-num" id="wifi-kpi-clients">—</div></div>
            <div class="wifi-kpi-sub" id="wifi-kpi-clients-sub">associated</div>
          </article>
          <article class="wifi-card wifi-kpi" data-accent="purple">
            <span class="wifi-kicker">Radios up</span>
            <div class="wifi-kpi-row"><div class="wifi-num" id="wifi-kpi-radios">—</div></div>
            <div class="wifi-kpi-sub" id="wifi-kpi-radios-sub">wireless interfaces</div>
          </article>
          <article class="wifi-card wifi-kpi" data-accent="amber">
            <span class="wifi-kicker">Weak signal</span>
            <div class="wifi-kpi-row"><div class="wifi-num" id="wifi-kpi-weak">—</div></div>
            <div class="wifi-kpi-sub">at or below &minus;75 dBm</div>
          </article>

          <article class="wifi-card wifi-config" id="wifi-config-card">
            <div class="wifi-config-head">
              ${headIcon("plug")}
              <div class="wifi-config-copy">
                <h2>AP Connection</h2>
                <p class="muted" id="wifi-config-summary">Not configured</p>
              </div>
              <div class="wifi-config-actions">
                <span class="wifi-msg" id="wifi-msg"></span>
                <button class="btn btn-sm" id="wifi-test" type="button">Test</button>
                <button class="btn btn-sm btn-ghost" id="wifi-config-toggle" type="button">Edit</button>
              </div>
            </div>
            <div class="wifi-config-body" id="wifi-config-body">
              <div class="wifi-config-inner">
              <div class="wifi-form">
                <div class="wifi-field wifi-wide">
                  <label for="wifi-hosts">Access points</label>
                  <input id="wifi-hosts" type="text" placeholder="192.168.1.43, 192.168.1.73" autocomplete="off">
                  <small class="wifi-hint">Comma, space or newline separated.</small>
                </div>
                <div class="wifi-field">
                  <label for="wifi-user">SSH username</label>
                  <input id="wifi-user" type="text" value="root" autocomplete="off">
                </div>
                <div class="wifi-field">
                  <label for="wifi-port">SSH port</label>
                  <input id="wifi-port" type="text" value="22" inputmode="numeric" autocomplete="off">
                </div>
                <div class="wifi-field wifi-wide">
                  <label for="wifi-auth">Authentication</label>
                  <select id="wifi-auth">
                    <option value="key">SSH private key (recommended)</option>
                    <option value="password">Password (needs sshpass on the firewall)</option>
                  </select>
                </div>
                <div class="wifi-field wifi-wide" data-auth="key">
                  <label for="wifi-key">SSH private key</label>
                  <textarea id="wifi-key" rows="3" class="mono" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellcheck="false"></textarea>
                </div>
                <div class="wifi-field wifi-wide" data-auth="password">
                  <label for="wifi-pass">SSH password</label>
                  <input id="wifi-pass" type="password" autocomplete="new-password">
                </div>
                <div class="wifi-field wifi-wide wifi-manage-row">
                  <label for="wifi-manage" class="wifi-check-label">
                    <input id="wifi-manage" type="checkbox">
                    <span><b>Enable AP management</b> (write access)<br>
                    <small class="muted">Allows creating and editing SSIDs and VLANs from this dashboard. Keep off if you only want monitoring.</small></span>
                  </label>
                </div>
                <div class="wifi-actions wifi-wide">
                  <button class="btn btn-sm btn-primary" id="wifi-save" type="button">Save settings</button>
                  <span class="wifi-msg muted">Changes are used on the next collection.</span>
                </div>
              </div>
              <aside class="wifi-config-note">
                <span class="wifi-note-kicker">How it connects</span>
                <ul>
                  <li id="wifi-note-write">Read-only over SSH — no changes are written to the APs.</li>
                  <li>One SSH round-trip per AP, run in parallel.</li>
                  <li>Credentials stay on the firewall; the key is only used for these hosts.</li>
                </ul>
              </aside>
              </div>
            </div>
          </article>
        </section>

        <div class="fw-subtabs" id="wifi-subtabs">
          <button class="fw-subtab active" type="button" data-wifi-pane="overview">${tabIcon("wifi")}Overview</button>
          <button class="fw-subtab" type="button" data-wifi-pane="events">${tabIcon("activity")}Events</button>
          <button class="fw-subtab" type="button" data-wifi-pane="inventory">${tabIcon("server")}Inventory</button>
          <button class="fw-subtab" type="button" data-wifi-pane="rf">${tabIcon("rf")}RF</button>
          <button class="fw-subtab" type="button" data-wifi-pane="networks">${tabIcon("net")}Networks</button>
          <span class="fw-subtabs-fill"></span>
        </div>

        <div class="wifi-pane" data-wifi-pane="overview">
          <div class="wifi-section-head">
            <div>
              <h2>Access points</h2>
              <p class="muted" id="wifi-ap-hint">Radios, channels and SSID load</p>
            </div>
            <div class="wifi-section-actions">
              <span class="wifi-updated" id="wifi-updated"></span>
              <button class="btn btn-sm btn-ghost" id="wifi-refresh" type="button">Refresh</button>
            </div>
          </div>
          <div class="wifi-aps" id="wifi-ap-grid"></div>
          <div id="wifi-overview-body"></div>
        </div>

        <div class="wifi-pane" data-wifi-pane="events" hidden>
          <div class="wifi-card wifi-events">
            <div class="wifi-head">
              ${headIcon("activity")}
              <div class="wifi-head-copy">
                <h2>WiFi Events</h2>
                <p class="muted">Connect / disconnect timeline from hostapd</p>
              </div>
              <span class="wifi-count" id="wifi-event-count"></span>
            </div>
            <div id="wifi-event-list" class="wifi-event-list"></div>
          </div>
        </div>

        <div class="wifi-pane" data-wifi-pane="inventory" hidden>
          <div class="wifi-card wifi-inventory">
            <div class="wifi-head">
              ${headIcon("server")}
              <div class="wifi-head-copy">
                <h2>AP Inventory</h2>
                <p class="muted">Hardware and firmware per access point</p>
              </div>
              <span class="wifi-count" id="wifi-inv-count"></span>
            </div>
            <div id="wifi-inventory-body"></div>
          </div>
        </div>

        <div class="wifi-pane" data-wifi-pane="rf" hidden>
          <div class="wifi-card wifi-rf">
            <div class="wifi-head">
              ${headIcon("rf")}
              <div class="wifi-head-copy">
                <h2>RF Environment</h2>
                <p class="muted">Neighbour networks, channel load and recommendations — scanned from the APs</p>
              </div>
              <div class="wifi-section-actions">
                <span class="wifi-updated" id="wifi-rf-updated"></span>
                <button class="btn btn-sm btn-primary" id="wifi-rf-scan" type="button">Scan now</button>
              </div>
            </div>
            <p class="wifi-hint">Scanning takes each radio off-channel for a couple of seconds — expect a brief blip for connected clients.</p>
            <div id="wifi-rf-body">
              <div class="wifi-empty"><b>No scan yet</b>Run a scan to see neighbouring networks, channel load and a recommended channel for each radio.</div>
            </div>
          </div>
        </div>

        <div class="wifi-pane" data-wifi-pane="networks" hidden>
          <div class="wifi-card wifi-networks">
            <div class="wifi-head">
              ${headIcon("net")}
              <div class="wifi-head-copy">
                <h2>Wireless Networks</h2>
                <p class="muted" id="wifi-net-sub">SSID management across all access points</p>
              </div>
              <div class="wifi-section-actions">
                <button class="btn btn-sm btn-primary" id="wifi-net-add" type="button">Add network</button>
              </div>
            </div>
            <div id="wifi-net-note"></div>
            <div id="wifi-net-form" hidden></div>
            <div id="wifi-net-body"></div>
          </div>
          <div class="wifi-card wifi-vlans">
            <div class="wifi-head">
              ${headIcon("vlan")}
              <div class="wifi-head-copy">
                <h2>VLANs</h2>
                <p class="muted" id="wifi-vlan-sub">Switch VLANs, bridges and interfaces across all APs</p>
              </div>
              <div class="wifi-section-actions">
                <button class="btn btn-sm btn-primary" id="wifi-vlan-add" type="button">Add VLAN</button>
              </div>
            </div>
            <div id="wifi-vlan-note"></div>
            <div id="wifi-vlan-form" hidden></div>
            <div id="wifi-vlan-body"></div>
          </div>
        </div>
      </div>`;

    escEl("#wifi-subtabs").addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-wifi-pane]");
      if (!btn) return;
      state.tab = btn.dataset.wifiPane;
      state.el.querySelectorAll(".fw-subtab").forEach((b) => b.classList.toggle("active", b === btn));
      state.el.querySelectorAll(".wifi-pane").forEach((p) => {
        p.hidden = p.dataset.wifiPane !== state.tab;
      });
      refresh();
    });
    escEl("#wifi-auth").addEventListener("change", syncAuthFields);
    escEl("#wifi-save").addEventListener("click", saveConfig);
    escEl("#wifi-test").addEventListener("click", testConnection);
    escEl("#wifi-config-toggle").addEventListener("click", () => setConfigMode(!state.editing));
    escEl("#wifi-refresh").addEventListener("click", () => {
      if (ready() && keyReady()) refreshData();
      else setMsg("Add access points and credentials first.", true);
    });
    escEl("#wifi-rf-scan").addEventListener("click", () => {
      if (ready() && keyReady()) runRfScan();
      else setMsg("Add access points and credentials first.", true);
    });
    escEl("#wifi-net-add").addEventListener("click", () => showNetForm(null));
    escEl("#wifi-vlan-add").addEventListener("click", () => showVlanForm(null));
  }

  function syncAuthFields() {
    const mode = escEl("#wifi-auth").value;
    state.el.querySelectorAll("[data-auth]").forEach((f) => {
      f.hidden = f.dataset.auth !== mode;
    });
  }

  function setConfigMode(editing) {
    state.editing = !!editing;
    const card = escEl("#wifi-config-card");
    if (!card) return;
    card.classList.toggle("is-collapsed", !state.editing);
    const btn = escEl("#wifi-config-toggle");
    if (btn) btn.textContent = state.editing ? "Done" : "Edit";
  }

  function configSummary() {
    const hosts = hostList();
    if (!hosts.length) return "No access points configured";
    const auth = (state.cfg && state.cfg.auth_mode) === "password" ? "password auth" : "key auth";
    const who = (state.cfg && state.cfg.username) || "root";
    if (!keyReady()) return `${who} · ${hosts.length} AP${hosts.length === 1 ? "" : "s"} · credentials missing`;
    return `${who}@${hosts.join(", ")} · ${auth}`;
  }

  function setHero(mode, text, sub) {
    const chip = escEl("#wifi-hero-chip");
    const dot = escEl("#wifi-hero-dot");
    const label = escEl("#wifi-hero-state");
    const subEl = escEl("#wifi-hero-sub");
    if (chip) {
      chip.textContent = mode === "live" ? "Live" : mode === "degraded" ? "Degraded"
        : mode === "down" ? "Offline" : mode === "pending" ? "Pending" : "Not configured";
      chip.className = "wifi-chip" + (mode === "live" ? " is-up"
        : mode === "degraded" ? " is-warn" : mode === "down" ? " is-bad" : "");
    }
    if (dot) dot.className = "wifi-hero-dot is-" + (mode === "live" ? "up"
      : mode === "degraded" ? "warn" : mode === "down" ? "down" : "idle");
    if (label) label.textContent = text;
    if (subEl) subEl.textContent = sub;
  }

  function resetKpis() {
    ["aps", "clients", "radios", "weak"].forEach((k) => {
      const el = escEl("#wifi-kpi-" + k);
      if (el) el.textContent = "—";
    });
    const apsSub = escEl("#wifi-kpi-aps-sub");
    if (apsSub) apsSub.textContent = "not polled yet";
    const rSub = escEl("#wifi-kpi-radios-sub");
    if (rSub) rSub.textContent = "wireless interfaces";
  }

  async function loadConfig(autoRefresh = true) {
    try {
      const d = await state.api.getConfig();
      state.cfg = (d && d.config) || {};
      state.secret = (d && d.secret_configured) || {};
      escEl("#wifi-hosts").value = state.cfg.hosts || "";
      escEl("#wifi-user").value = state.cfg.username || "root";
      escEl("#wifi-port").value = state.cfg.port || "22";
      escEl("#wifi-auth").value = state.cfg.auth_mode || "key";
      const manage = escEl("#wifi-manage");
      if (manage) manage.checked = !!state.cfg.manage_enabled;
      const note = escEl("#wifi-note-write");
      if (note) note.textContent = state.cfg.manage_enabled
        ? "Management enabled — SSID, VLAN and channel changes are written to every AP."
        : "Read-only over SSH — no changes are written to the APs.";
      const key = escEl("#wifi-key");
      key.value = "";
      key.placeholder = state.secret.ssh_key ? "SSH key configured — leave blank to keep" : "-----BEGIN OPENSSH PRIVATE KEY-----";
      escEl("#wifi-pass").value = "";
      escEl("#wifi-pass").placeholder = state.secret.password ? "Password configured — leave blank to keep" : "SSH password";
      syncAuthFields();
      const summary = escEl("#wifi-config-summary");
      if (summary) summary.textContent = configSummary();
      if (!ready() || !keyReady()) state.editing = true;
      else if (state.editing == null) state.editing = false;
      setConfigMode(state.editing);
      if (autoRefresh && ready() && keyReady()) refreshData();
      else {
        setHero(ready() ? "pending" : "idle",
          ready() ? "Waiting for credentials" : "Not configured",
          ready() ? "Add the SSH key or password, then save." : "Add your access points to start monitoring.");
        resetKpis();
        renderEmpty();
      }
    } catch (err) {
      setMsg(err.message, true);
    }
  }

  async function saveConfig() {
    if (state.busy) return;
    state.busy = true;
    setMsg("Saving…");
    try {
      const config = {
        hosts: escEl("#wifi-hosts").value.trim(),
        username: escEl("#wifi-user").value.trim() || "root",
        port: escEl("#wifi-port").value.trim() || "22",
        auth_mode: escEl("#wifi-auth").value,
        manage_enabled: !!(escEl("#wifi-manage") && escEl("#wifi-manage").checked),
      };
      const key = escEl("#wifi-key").value.trim();
      const pass = escEl("#wifi-pass").value;
      if (key) config.ssh_key = key;
      if (pass) config.password = pass;
      const d = await state.api.saveConfig(config);
      if (!d || !d.ok) throw new Error((d && d.error) || "Could not save settings");
      setMsg("Saved.");
      state.editing = false;
      await loadConfig(true);
    } catch (err) {
      setMsg(err.message, true);
    } finally {
      state.busy = false;
    }
  }

  async function testConnection() {
    if (state.busy) return;
    state.busy = true;
    setMsg("Testing…");
    try {
      const d = await state.api.api("test", {});
      if (d && d.ok) setMsg(d.message || "Connected.");
      else {
        const failed = ((d && d.results) || []).filter((r) => !r.ok)
          .map((r) => `${r.host}: ${r.error}`).join(" · ");
        setMsg(failed || (d && d.error) || "Test failed", true);
      }
    } catch (err) {
      setMsg(err.message, true);
    } finally {
      state.busy = false;
    }
  }

  function renderEmpty() {
    const grid = escEl("#wifi-ap-grid");
    if (grid) grid.innerHTML = "";
    escEl("#wifi-overview-body").innerHTML = `
      <div class="wifi-card wifi-empty-state">
        <span class="wifi-empty-ico">${svg("wifiOff")}</span>
        <b>No access points yet</b>
        <p class="muted">Add your OpenWrt AP addresses and SSH credentials in <strong>AP Connection</strong> above, then save.</p>
        <button class="btn btn-sm" type="button" data-wifi-open-config>Open settings</button>
      </div>`;
    const btn = state.el.querySelector("[data-wifi-open-config]");
    if (btn) btn.addEventListener("click", () => {
      setConfigMode(true);
      const card = escEl("#wifi-config-card");
      if (card && card.scrollIntoView) card.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  }

  function apCard(ap) {
    const radios = ap.radios || [];
    const radioDown = radios.some((r) => r.up === false);
    const radioHtml = radios.map((r) => {
      const band = bandInfo(r.radio);
      const bits = [`ch ${r.channel || "—"}`, r.width || ""].filter(Boolean).join(" · ");
      return `<div class="wifi-radio${r.up === false ? " is-down" : ""}">
        <span class="wifi-band" data-band="${state.api.esc(band.key)}">${state.api.esc(band.short)}</span>
        <span class="wifi-radio-meta">${state.api.esc(bits)}${r.tx_power ? " · " + state.api.esc(r.tx_power) + " dBm" : ""}</span>
        <span class="wifi-radio-count"><b>${fmtNum(r.clients)}</b><i>clients</i></span>
      </div>`;
    }).join("") || '<div class="wifi-radio-none muted">No radios reported</div>';

    const ssids = (ap.vaps || []).map((v) => `
      <span class="wifi-ssid${v.up === false ? " is-off" : ""}" title="${state.api.esc(v.ifname || "")}">
        <i></i>${state.api.esc(v.ssid || v.ifname)}<b>${fmtNum(v.clients)}</b>
      </span>`).join("") || '<span class="wifi-radio-none muted">No SSIDs reported</span>';

    return `
      <article class="wifi-card wifi-ap" data-state="${radioDown ? "warn" : "up"}">
        <div class="wifi-ap-top">
          <span class="wifi-ap-ico">${svg("wifi")}</span>
          <div class="wifi-ap-title">
            <b>${state.api.esc(ap.name)}</b>
            <small>${state.api.esc(ap.model || "OpenWrt device")}${ap.version ? " · " + state.api.esc(ap.version) : ""}</small>
          </div>
          <span class="wifi-pill ${radioDown ? "is-warn" : "is-up"}">${radioDown ? "Radio down" : "Online"}</span>
        </div>
        <div class="wifi-ap-meta">
          <span class="mono">${state.api.esc(ap.ip || "")}</span>
          <span>up ${state.api.esc(ap.uptime || "—")}</span>
        </div>
        <div class="wifi-radios">${radioHtml}</div>
        <div class="wifi-ssids">${ssids}</div>
        <div class="wifi-ap-foot">
          <span><b>${fmtNum(ap.clients)}</b> clients</span>
          <span class="mono">${state.api.esc(ap.mac || "")}</span>
        </div>
      </article>`;
  }

  function apErrorCard(err) {
    return `
      <article class="wifi-card wifi-ap is-down" data-state="down">
        <div class="wifi-ap-top">
          <span class="wifi-ap-ico">${svg("wifiOff")}</span>
          <div class="wifi-ap-title">
            <b>${state.api.esc(err.host)}</b>
            <small>Unreachable access point</small>
          </div>
          <span class="wifi-pill is-bad">Offline</span>
        </div>
        <p class="wifi-ap-error">${state.api.esc(err.error || "No response")}</p>
        <p class="wifi-ap-hint">Check that the AP is powered, on the LAN, and that the firewall's SSH key is authorised on it.</p>
        <div class="wifi-ap-foot">
          <span class="mono">${state.api.esc(err.host)}</span>
          <span>SSH failed</span>
        </div>
      </article>`;
  }

  function setText(id, text) {
    const el = escEl(id);
    if (el) el.textContent = text;
  }

  /* ---- Overview charts (inline SVG / CSS, no libraries) ------------------ */

  const SIG_BANDS = [
    { key: "excellent", label: "Excellent", max: -50, hint: "at or above −50 dBm" },
    { key: "good", label: "Good", max: -58, hint: "−50 to −58 dBm" },
    { key: "fair", label: "Fair", max: -67, hint: "−58 to −67 dBm" },
    { key: "weak", label: "Weak", max: -75, hint: "−67 to −75 dBm" },
    { key: "poor", label: "Poor", max: -Infinity, hint: "at or below −75 dBm" },
  ];

  function signalTone(sig) {
    if (sig <= -75) return "poor";
    if (sig <= -67) return "weak";
    if (sig <= -58) return "fair";
    if (sig <= -50) return "good";
    return "excellent";
  }

  function signalHistogram(clients) {
    const counts = SIG_BANDS.map(() => 0);
    clients.forEach((c) => {
      if (c.signal == null || isNaN(Number(c.signal))) return;
      const i = SIG_BANDS.findIndex((b) => Number(c.signal) > b.max);
      counts[i < 0 ? SIG_BANDS.length - 1 : i]++;
    });
    return { counts, total: counts.reduce((a, b) => a + b, 0) };
  }

  function renderSignalChart(clients) {
    const { counts, total } = signalHistogram(clients);
    if (!total) {
      return `<article class="wifi-card wifi-chart" data-accent="teal">
        <div class="wifi-chart-head"><span class="wifi-kicker">Signal quality</span></div>
        <div class="wifi-empty">No signal data reported by the access points.</div>
      </article>`;
    }
    const max = Math.max(1, ...counts);
    const healthy = counts[0] + counts[1] + counts[2];
    const W = 336, H = 174;
    const padL = 30, padR = 18, padT = 24, base = 124;
    const step = (W - padL - padR) / (SIG_BANDS.length - 1);
    const px = (i) => padL + step * i;
    const py = (n) => base - (n / max) * (base - padT);
    const pts = counts.map((n, i) => [px(i), py(n), n]);
    const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
    const area = `${line} L${px(counts.length - 1).toFixed(1)} ${base} L${padL} ${base} Z`;
    const tickVals = max >= 2 ? [0, Math.round(max / 2), max] : [0, max];
    const grid = [...new Set(tickVals)].map((n) => {
      const y = py(n);
      return `<line class="wifi-grid-line" x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}"/>` +
        `<text class="wifi-axis" x="${padL - 6}" y="${(y + 3).toFixed(1)}" text-anchor="end">${n}</text>`;
    }).join("");
    const labels = SIG_BANDS.map((b, i) =>
      `<text class="wifi-sig-lbl" x="${px(i).toFixed(1)}" y="${base + 17}" text-anchor="middle">${b.label}</text>`).join("");
    const countsText = pts.map(([x, y, n]) =>
      n ? `<text class="wifi-sig-count" x="${x.toFixed(1)}" y="${(y - 9).toFixed(1)}" text-anchor="middle">${n}</text>` : "").join("");
    const dots = pts.map(([x, y, n], i) =>
      `<circle class="wifi-line-dot tone-${SIG_BANDS[i].key}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.8">` +
      `<title>${SIG_BANDS[i].label} (${SIG_BANDS[i].hint}): ${n} client${n === 1 ? "" : "s"}</title></circle>`).join("");
    return `<article class="wifi-card wifi-chart" data-accent="teal">
      <div class="wifi-chart-head">
        <span class="wifi-kicker">Signal quality</span>
        <span class="wifi-chart-note"><b>${healthy}</b> of ${total} good or better</span>
      </div>
      <svg class="wifi-line-chart" viewBox="0 0 ${W} ${H}" role="img"
        aria-label="Signal quality curve for ${total} clients, from excellent to poor">
        ${grid}
        <path class="wifi-line-area" d="${area}"/>
        <path class="wifi-line" d="${line}"/>
        ${labels}${countsText}${dots}
      </svg>
    </article>`;
  }

  function renderApChart(aps, clients) {
    const rows = aps.map((ap) => ({
      name: ap.name || ap.ip || "AP",
      n: clients.filter((c) => c.ap === ap.name).length,
    })).filter((r) => r.n > 0).sort((a, b) => b.n - a.n);
    const mapped = rows.reduce((s, r) => s + r.n, 0);
    if (clients.length > mapped) rows.push({ name: "Unassigned", n: clients.length - mapped });
    const total = rows.reduce((s, r) => s + r.n, 0);
    if (!total) {
      return `<article class="wifi-card wifi-chart" data-accent="blue">
        <div class="wifi-chart-head"><span class="wifi-kicker">Clients by access point</span></div>
        <div class="wifi-empty">No clients associated yet.</div>
      </article>`;
    }
    const circ = 2 * Math.PI * 46;
    let acc = 0;
    const segs = rows.map((r, i) => {
      const span = (r.n / total) * circ;
      const len = Math.max(0, span - 2.2);
      const seg = `<circle class="wifi-donut-seg tone-${i % 6}" cx="60" cy="60" r="46"
        stroke-dasharray="${len.toFixed(2)} ${(circ - len).toFixed(2)}"
        stroke-dashoffset="${(-acc).toFixed(2)}"><title>${state.api.esc(r.name)}: ${r.n} client${r.n === 1 ? "" : "s"}</title></circle>`;
      acc += span;
      return seg;
    }).join("");
    const top = rows[0];
    const pct = Math.round((top.n / total) * 100);
    const foot = rows.length > 1
      ? `${state.api.esc(top.name)} carries <b>${pct}%</b> of clients`
      : `All clients on ${state.api.esc(top.name)}`;
    return `<article class="wifi-card wifi-chart" data-accent="blue">
      <div class="wifi-chart-head">
        <span class="wifi-kicker">Clients by access point</span>
        <span class="wifi-chart-note">${total} total</span>
      </div>
      <div class="wifi-donut-body">
        <div class="wifi-donut-wrap">
          <svg class="wifi-donut" viewBox="0 0 120 120" role="img"
            aria-label="Client distribution across ${rows.length} access points">
            <circle class="wifi-donut-track" cx="60" cy="60" r="46"/>
            ${segs}
          </svg>
          <div class="wifi-donut-total"><b>${total}</b><span>clients</span></div>
        </div>
        <div class="wifi-donut-legend">
          ${rows.map((r, i) => `<span class="wifi-donut-key" title="${state.api.esc(r.name)} — ${r.n} of ${total}">
            <i class="tone-${i % 6}"></i>${state.api.esc(r.name)}<b>${r.n}</b>
          </span>`).join("")}
        </div>
      </div>
      <div class="wifi-donut-foot">${foot}</div>
    </article>`;
  }

  function renderScatter(clients) {
    const pts = clients.filter((c) =>
      c.signal != null && !isNaN(Number(c.signal)) &&
      c.rx_rate != null && !isNaN(Number(c.rx_rate)));
    const W = 336, H = 186, padL = 38, padR = 12, padT = 14, padB = 30;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    if (!pts.length) {
      return `<article class="wifi-card wifi-chart" data-accent="amber">
        <div class="wifi-chart-head"><span class="wifi-kicker">Signal vs link rate</span></div>
        <div class="wifi-empty">Needs both signal and rate from at least one client.</div>
      </article>`;
    }
    const sigMin = -90, sigMax = -30;
    let rateMax = Math.max(100, ...pts.map((c) => Number(c.rx_rate)));
    rateMax = Math.ceil(rateMax / 100) * 100;
    const px = (s) => padL + ((Math.min(sigMax, Math.max(sigMin, s)) - sigMin) / (sigMax - sigMin)) * plotW;
    const py = (r) => padT + plotH - (Math.max(0, Math.min(rateMax, r)) / rateMax) * plotH;
    const hgrid = [0, 0.25, 0.5, 0.75, 1].map((f) => {
      const yy = padT + plotH * (1 - f);
      return `<line class="wifi-grid-line" x1="${padL}" y1="${yy.toFixed(1)}" x2="${W - padR}" y2="${yy.toFixed(1)}"/>` +
        (f > 0 && f < 1 ? `<text class="wifi-axis" x="${padL - 6}" y="${(yy + 3).toFixed(1)}" text-anchor="end">${Math.round(rateMax * f)}</text>` : "");
    }).join("");
    const vgrid = [0, 0.5, 1].map((f) => {
      const xx = padL + plotW * f;
      const dbm = Math.round(sigMin + (sigMax - sigMin) * f);
      return `<line class="wifi-grid-line" x1="${xx.toFixed(1)}" y1="${padT}" x2="${xx.toFixed(1)}" y2="${padT + plotH}"/>` +
        `<text class="wifi-axis" x="${xx.toFixed(1)}" y="${H - 8}" text-anchor="${f === 0 ? "start" : f === 1 ? "end" : "middle"}">${dbm}</text>`;
    }).join("");
    const dots = pts.map((c) => {
      const s = Number(c.signal), r = Number(c.rx_rate);
      return `<circle class="wifi-dot tone-${signalTone(s)}" cx="${px(s).toFixed(1)}" cy="${py(r).toFixed(1)}" r="4.2">` +
        `<title>${state.api.esc(c.hostname || c.name || c.mac || "Client")} · ${s} dBm · ${r} Mbps</title></circle>`;
    }).join("");
    return `<article class="wifi-card wifi-chart" data-accent="amber">
      <div class="wifi-chart-head">
        <span class="wifi-kicker">Signal vs link rate</span>
        <span class="wifi-chart-note">${pts.length} client${pts.length === 1 ? "" : "s"}</span>
      </div>
      <svg class="wifi-scatter" viewBox="0 0 ${W} ${H}" role="img"
        aria-label="Client signal strength against negotiated receive rate">
        <text class="wifi-axis-unit" x="${padL - 6}" y="${padT - 3}" text-anchor="end">Mbps</text>
        ${hgrid}${vgrid}${dots}
        <text class="wifi-axis-unit" x="${W - padR}" y="${padT - 3}" text-anchor="end">dBm</text>
      </svg>
    </article>`;
  }

  function renderCharts(d) {
    const aps = d.aps || [], clients = d.clients || [];
    if (!aps.length && !clients.length) return "";
    return `<div class="wifi-viz">
      ${renderSignalChart(clients)}
      ${renderApChart(aps, clients)}
      ${renderScatter(clients)}
    </div>`;
  }

  function renderOverview(d) {
    const aps = d.aps || [];
    const clients = d.clients || [];
    const errors = d.errors || [];
    const flaps = d.flaps || [];
    const weak = clients.filter((c) => c.signal != null && c.signal <= -75).length;
    const radiosTotal = aps.reduce((n, a) => n + (a.radios || []).length, 0);
    const radiosUp = aps.reduce((n, a) => n + (a.radios || []).filter((r) => r.up !== false).length, 0);

    setText("#wifi-kpi-aps", fmtNum(aps.length));
    setText("#wifi-kpi-aps-sub", errors.length ? `${errors.length} unreachable` : "all online");
    setText("#wifi-kpi-clients", fmtNum(clients.length));
    setText("#wifi-kpi-clients-sub", clients.length === 1 ? "device associated" : "devices associated");
    setText("#wifi-kpi-radios", fmtNum(radiosUp));
    setText("#wifi-kpi-radios-sub", radiosTotal ? `of ${radiosTotal} interfaces` : "wireless interfaces");
    setText("#wifi-kpi-weak", fmtNum(weak));

    const mode = !aps.length && errors.length ? "down" : errors.length ? "degraded" : "live";
    setHero(
      mode,
      mode === "live" ? "All online" : mode === "degraded" ? "Partial coverage" : "Offline",
      `${aps.length} AP${aps.length === 1 ? "" : "s"} · ${radiosUp}/${radiosTotal} radios · ${clients.length} client${clients.length === 1 ? "" : "s"}`
    );

    state.updated = Date.now();
    setText("#wifi-updated", "updated " + ago(state.updated));
    setText("#wifi-ap-hint", `${aps.length} reachable${errors.length ? ` · ${errors.length} unreachable` : ""}`);
    escEl("#wifi-ap-grid").innerHTML = aps.map(apCard).join("") + errors.map(apErrorCard).join("");

    escEl("#wifi-overview-body").innerHTML = `
      ${renderCharts(d)}
      ${renderHealth(d)}
      <div class="wifi-card wifi-clients">
        <div class="wifi-head">
          ${headIcon("users")}
          <div class="wifi-head-copy">
            <h2>WiFi Clients</h2>
            <p class="muted">${clients.length} associated client${clients.length === 1 ? "" : "s"} across ${aps.length} AP${aps.length === 1 ? "" : "s"}</p>
          </div>
        </div>
        <div class="wifi-tools">
          <input type="search" id="wifi-client-search" placeholder="Filter by name, IP, SSID or AP…" autocomplete="off" value="${state.api.esc(state.clientFilter || "")}">
          <span class="wifi-count" id="wifi-client-count"></span>
        </div>
        <div class="table-wrap"><table class="wifi-table wifi-client-table">
          <thead><tr><th>Client</th><th>IP</th><th>SSID</th><th>AP</th><th>Signal</th><th>Rx / Tx</th><th>Uptime</th></tr></thead>
          <tbody id="wifi-client-body">${clients.map((c) => {
            const flapping = flaps.some((f) => f.mac === c.mac);
            return `
            <tr data-client-mac="${state.api.esc(c.mac || "")}">
              <td class="wifi-client-name">
                <b>${state.api.esc(c.hostname || c.name || "Unknown device")}</b>
                ${flapping ? '<span class="wifi-pill is-warn">flapping</span>' : ""}
                <small class="mono">${state.api.esc(c.mac || "")}</small>
              </td>
              <td class="mono">${state.api.esc(c.ip || "—")}</td>
              <td>${c.ssid ? `<span class="wifi-ssid-sm">${state.api.esc(c.ssid)}</span>` : '<span class="muted">—</span>'}</td>
              <td>${state.api.esc(c.ap || "—")}</td>
              <td>${signalCell(c.signal)}</td>
              <td class="wifi-rate"><b>${c.rx_rate != null ? state.api.esc(c.rx_rate) : "—"}</b><i>/</i><b>${c.tx_rate != null ? state.api.esc(c.tx_rate) : "—"}</b><em>Mbps</em></td>
              <td>${state.api.esc(c.uptime || "—")}</td>
            </tr>`;
          }).join("") || '<tr><td colspan="7" class="muted">No clients reported.</td></tr>'}
            <tr class="wifi-client-none" id="wifi-client-none" hidden><td colspan="7" class="muted">No clients match this filter.</td></tr>
          </tbody>
        </table></div>
      </div>`;
    const search = escEl("#wifi-client-search");
    if (search) search.addEventListener("input", () => { state.clientFilter = search.value; filterClients(); });
    filterClients();
  }

  function filterClients() {
    const q = (state.clientFilter || "").toLowerCase();
    const rows = state.el.querySelectorAll("#wifi-client-body tr[data-client-mac]");
    let shown = 0;
    rows.forEach((tr) => {
      const hit = !q || tr.textContent.toLowerCase().includes(q);
      tr.hidden = !hit;
      if (hit) shown++;
    });
    const none = escEl("#wifi-client-none");
    if (none) none.hidden = !q || shown > 0;
    const count = escEl("#wifi-client-count");
    if (count) count.textContent = q ? `${shown} shown` : "";
  }

  async function runRfScan() {
    const body = escEl("#wifi-rf-body");
    const btn = escEl("#wifi-rf-scan");
    if (!body || state.busy) return;
    state.busy = true;
    if (btn) { btn.disabled = true; btn.textContent = "Scanning…"; }
    body.innerHTML = '<div class="wifi-empty"><span class="wifi-spinner"></span>Scanning both bands on every access point…</div>';
    try {
      const d = await state.api.api("rf", {});
      if (!d.ok) throw new Error(d.error || "Scan failed");
      renderRf(d);
      setText("#wifi-rf-updated", "updated " + ago(Date.now()));
    } catch (err) {
      body.innerHTML = `<div class="wifi-empty is-bad">${state.api.esc(err.message)}</div>`;
    } finally {
      state.busy = false;
      if (btn) { btn.disabled = false; btn.textContent = "Scan now"; }
    }
  }

  function rfScore(score) {
    if (score == null) return "—";
    const s = Number(score);
    let tone = "is-up";
    if (s >= 40) tone = "is-bad";
    else if (s >= 15) tone = "is-warn";
    return `<span class="wifi-pill ${tone}">${s.toFixed ? s.toFixed(1) : s}</span>`;
  }

  function renderRf(d) {
    const body = escEl("#wifi-rf-body");
    const aps = d.aps || [];
    if (!aps.length) {
      body.innerHTML = '<div class="wifi-empty"><b>Nothing to show</b>No access points responded to the scan.</div>';
      return;
    }
    body.innerHTML = aps.map((ap) => {
      const errs = (ap.scan_errors || []).map((e) => {
        const band = e.band ? bandInfo(e.band).short + " scan failed" : "Scan failed";
        return `<div class="wifi-rf-fail">${svg("wifiOff")}<b>${state.api.esc(band)}</b><span class="muted">${state.api.esc(e.error || "")}</span></div>`;
      }).join("");
      const bands = (ap.bands || []).map((b) => {
        const rec = b.recommendation || {};
        const manage = !!(state.cfg && state.cfg.manage_enabled);
        const recHtml = rec.channel != null ? `
          <div class="wifi-rf-rec">
            <span class="wifi-rf-rec-label">Recommended</span>
            <b>ch ${state.api.esc(rec.channel)}</b>${rec.dfs ? ' <span class="wifi-pill is-warn">DFS</span>' : ""}
            <span class="muted">load ${rec.score != null ? rec.score : "—"}${rec.note ? " · " + state.api.esc(rec.note) : ""}</span>
            ${manage ? `<button class="btn btn-sm" data-rf-apply data-ap="${state.api.esc(ap.ap)}" data-band="${state.api.esc(b.band)}" data-ch="${state.api.esc(rec.channel)}" data-dfs="${rec.dfs ? 1 : 0}">Apply</button>` : ""}
          </div>` : '<div class="wifi-rf-rec"><span class="muted">No free candidate channels in this band.</span></div>';
        const rows = (b.channels || []).filter((c) => c.ours || c.score > 0).map((c) => {
          const nets = (c.networks || []).map((n) =>
            `<span class="wifi-rf-net">${state.api.esc(n.ssid || "hidden")}<em>${n.signal != null ? n.signal + " dBm" : ""}</em>${n.width > 20 ? `<i>${n.width} MHz</i>` : ""}</span>`
          ).join("");
          return `<tr class="${c.ours ? "is-ours" : ""}">
            <td class="mono"><b>${c.channel}</b>${c.ours ? '<span class="wifi-pill is-up">yours</span>' : ""}</td>
            <td>${rfScore(c.score)}</td>
            <td>${nets || '<span class="muted">—</span>'}</td>
          </tr>`;
        }).join("");
        const info = bandInfo(b.band);
        return `
          <div class="wifi-rf-band">
            <div class="wifi-rf-band-head">
              <span class="wifi-band" data-band="${state.api.esc(info.key)}">${state.api.esc(info.short)}</span>
              <span class="muted">${(b.cells || []).length} networks visible · via ${state.api.esc(b.ifname || "")}</span>
            </div>
            ${recHtml}
            <div class="table-wrap"><table class="wifi-table wifi-rf-table">
              <thead><tr><th>Channel</th><th>Load</th><th>Strongest networks on / overlapping this channel</th></tr></thead>
              <tbody>${rows || '<tr><td colspan="3" class="muted">No significant interference measured.</td></tr>'}</tbody>
            </table></div>
          </div>`;
      }).join("");
      return `<div class="wifi-rf-ap">
        <div class="wifi-rf-ap-head"><b>${state.api.esc(ap.ap)}</b></div>
        ${errs}
        ${bands || ((ap.scan_errors || []).length ? "" : '<div class="wifi-empty muted">No scan data for this access point.</div>')}
      </div>`;
    }).join("");
    body.querySelectorAll("[data-rf-apply]").forEach((b) => b.addEventListener("click", () => {
      applyChannel(b.dataset.ap, b.dataset.band, b.dataset.ch, b.dataset.dfs === "1");
    }));
  }

  function netSecurity(enc) {
    const map = { "psk2": "WPA2", "sae": "WPA3", "sae-mixed": "WPA2/WPA3", "psk-mixed": "WPA2/WPA3", "none": "Open" };
    return map[enc] || enc || "—";
  }

  async function loadNetworks() {
    const body = escEl("#wifi-net-body");
    if (!body) return;
    body.innerHTML = '<div class="wifi-empty"><span class="wifi-spinner"></span>Loading networks…</div>';
    const vbody = escEl("#wifi-vlan-body");
    if (vbody) vbody.innerHTML = '<div class="wifi-empty"><span class="wifi-spinner"></span>Loading VLANs…</div>';
    try {
      const [d, v] = await Promise.all([
        state.api.api("wlan-list", {}),
        state.api.api("vlan-list", {}),
      ]);
      if (!d.ok) throw new Error(d.error || "Could not load networks");
      state.networks = d;
      renderNetworks(d);
      if (v.ok) { state.vlans = v; renderVlans(v); }
    } catch (err) {
      body.innerHTML = `<div class="wifi-empty is-bad">${state.api.esc(err.message)}</div>`;
    }
  }

  function portSummary(ports) {
    return (ports || []).map((p) =>
      `<span class="wifi-port${p.endsWith("t") ? " is-tagged" : ""}">${state.api.esc(p)}</span>`).join(" ");
  }

  function renderVlans(v) {
    const body = escEl("#wifi-vlan-body");
    const note = escEl("#wifi-vlan-note");
    const manage = !!v.manage_enabled;
    const vlans = v.vlans || [];
    note.innerHTML = manage
      ? '<p class="wifi-hint">Creating or editing a VLAN restarts each AP\'s network stack (~15s, brief WiFi blip). Deleting is blocked while any SSID is bound to the VLAN\'s interface.</p>'
      : '<div class="wifi-empty"><b>Management is disabled</b>Enable "AP management" in the plugin settings. Viewing is always available.</div>';
    const addBtn = escEl("#wifi-vlan-add");
    if (addBtn) addBtn.disabled = !manage;
    body.innerHTML = `
      <div class="table-wrap"><table class="wifi-table wifi-vlan-table">
        <thead><tr><th>VLAN</th><th>Description</th><th>Ports</th><th>Bridge</th><th>Interface</th><th>DHCP guard</th><th>APs</th><th class="td-right">Actions</th></tr></thead>
        <tbody>${vlans.map((n) => `
          <tr data-vlan="${state.api.esc(n.vlan)}">
            <td data-label="VLAN"><b>${state.api.esc(n.vlan)}</b>${n.protected ? ' <span class="wifi-pill is-warn">mgmt</span>' : ""}${n.consistent ? "" : ' <span class="wifi-pill is-bad">drift</span>'}</td>
            <td data-label="Description">${state.api.esc(n.description || "—")}</td>
            <td data-label="Ports" class="mono">${portSummary(n.ports)}</td>
            <td data-label="Bridge" class="mono">${state.api.esc(n.bridge || "—")}</td>
            <td data-label="Interface">${n.interface ? `<span class="wifi-ssid-sm">${state.api.esc(n.interface)}</span> <span class="muted">(${state.api.esc(n.proto || "?")})</span>` : "—"}</td>
            <td data-label="DHCP guard">${n.dhcp_guard ? '<span class="wifi-pill is-up">on</span>' : '<span class="wifi-pill is-warn">off</span>'}</td>
            <td data-label="APs">${n.aps.length}/${(v.aps || []).length}</td>
            <td class="td-right wifi-net-actions" data-label="Actions">
              <button class="btn btn-sm" data-vlan-edit ${manage && !n.protected ? "" : "disabled"}>Edit</button>
              <button class="btn btn-sm btn-ghost" data-vlan-delete ${manage && !n.protected ? "" : "disabled"}>Delete</button>
            </td>
          </tr>`).join("") || '<tr><td colspan="8" class="muted">No VLANs reported.</td></tr>'}
        </tbody>
      </table></div>`;
    body.querySelectorAll("[data-vlan-edit]").forEach((b) => b.addEventListener("click", (ev) => {
      const tr = ev.target.closest("tr");
      const n = (state.vlans.vlans || []).find((x) => String(x.vlan) === tr.dataset.vlan);
      showVlanForm(n);
    }));
    body.querySelectorAll("[data-vlan-delete]").forEach((b) => b.addEventListener("click", (ev) => {
      const tr = ev.target.closest("tr");
      const n = (state.vlans.vlans || []).find((x) => String(x.vlan) === tr.dataset.vlan);
      deleteVlan(n);
    }));
  }

  function showVlanForm(n) {
    const form = escEl("#wifi-vlan-form");
    if (!form) return;
    if (!n && !(state.networks || {}).manage_enabled) {
      setMsg("Enable AP management in the plugin settings first.", true);
      return;
    }
    state.vlanEdit = n;
    const editing = !!n;
    const vl = state.vlans || {};
    form.hidden = false;
    form.innerHTML = `
      <div class="wifi-net-form">
        <h3>${editing ? "Edit VLAN " + state.api.esc(n.vlan) : "Add VLAN"}</h3>
        <div class="wifi-form">
          <div class="wifi-field"><label>VLAN ID</label>
            <input id="wifi-vlan-id" type="text" inputmode="numeric" value="${editing ? state.api.esc(n.vlan) : ""}" placeholder="20" ${editing ? "disabled" : ""}></div>
          <div class="wifi-field"><label>Interface name</label>
            <input id="wifi-vlan-name" type="text" value="${editing ? state.api.esc(n.interface || "") : ""}" placeholder="iot, guest, …" ${editing ? "disabled" : ""}></div>
          <div class="wifi-field"><label>Description</label>
            <input id="wifi-vlan-desc" type="text" value="${editing ? state.api.esc(n.description || "") : ""}" placeholder="IoT"></div>
          <div class="wifi-field wifi-wide"><label>Ports</label>
            <input id="wifi-vlan-ports" type="text" class="mono" value="${editing ? state.api.esc((n.ports || []).join(" ")) : ((vl.cpu_port || "0t") + " " + (vl.physical_ports || ["2", "3"]).map((p) => p + "t").join(" "))}">
            <small class="wifi-hint">CPU ${state.api.esc(vl.cpu_port || "0t")} must stay tagged; physical ports ${state.api.esc((vl.physical_ports || []).join(", "))} — append "t" for tagged, plain number for untagged.</small></div>
        </div>
        <p class="wifi-hint">Applied to <b>every</b> access point; each AP restarts its network stack (~15s).</p>
        <div class="wifi-actions">
          <button class="btn btn-sm btn-primary" id="wifi-vlan-save" type="button">${editing ? "Save changes" : "Create VLAN"}</button>
          <button class="btn btn-sm btn-ghost" id="wifi-vlan-cancel" type="button">Cancel</button>
          <span class="wifi-msg" id="wifi-vlan-msg"></span>
        </div>
      </div>`;
    escEl("#wifi-vlan-cancel").addEventListener("click", () => { form.hidden = true; form.innerHTML = ""; });
    escEl("#wifi-vlan-save").addEventListener("click", saveVlanForm);
    if (form.scrollIntoView) form.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  async function saveVlanForm() {
    const editing = !!state.vlanEdit;
    const msg = escEl("#wifi-vlan-msg");
    const vlan = escEl("#wifi-vlan-id").value.trim();
    const name = escEl("#wifi-vlan-name").value.trim().toLowerCase();
    const desc = escEl("#wifi-vlan-desc").value.trim();
    const ports = escEl("#wifi-vlan-ports").value.trim().replace(/,/g, " ").replace(/\s+/g, " ");
    if (!vlan) { msg.textContent = "VLAN ID is required."; msg.className = "wifi-msg is-bad"; return; }
    if (!editing && !name) { msg.textContent = "Interface name is required."; msg.className = "wifi-msg is-bad"; return; }
    if (!window.confirm("Apply to ALL access points?\n\nEach AP restarts its network stack (~15s, brief WiFi blip). Continue?")) return;
    msg.textContent = "Applying…"; msg.className = "wifi-msg";
    try {
      const payload = editing
        ? { vlan: parseInt(state.vlanEdit.vlan, 10), description: desc, ports, confirm: true }
        : { vlan: parseInt(vlan, 10), name, description: desc, ports, confirm: true };
      const d = await state.api.api(editing ? "vlan-save" : "vlan-add", payload);
      if (!d.ok) throw new Error(Object.values(d.results || {}).map((r) => r.error).filter(Boolean).join(" · ")
        || d.error || "Change failed");
      msg.textContent = "Applied — waiting for APs to settle…"; msg.className = "wifi-msg";
      showToast(editing ? "VLAN updated on every access point." : "VLAN created on every access point.");
      escEl("#wifi-vlan-form").hidden = true;
      escEl("#wifi-vlan-form").innerHTML = "";
      setTimeout(loadNetworks, 20000);
    } catch (err) {
      msg.textContent = err.message; msg.className = "wifi-msg is-bad";
    }
  }

  async function deleteVlan(n) {
    if (!n) return;
    if (!window.confirm(`Delete VLAN ${n.vlan} (${n.description || n.interface || ""}) from ALL access points?\n\nThis removes its switch VLAN, bridge and interface. Continue?`)) return;
    setMsg("Deleting VLAN…");
    try {
      const d = await state.api.api("vlan-delete", { vlan: parseInt(n.vlan, 10), confirm: true });
      if (!d.ok) throw new Error(Object.values(d.results || {}).map((r) => r.error).filter(Boolean).join(" · ")
        || d.error || "Delete failed");
      setMsg("VLAN deleted — waiting for APs to settle…");
      setTimeout(loadNetworks, 20000);
    } catch (err) {
      setMsg(err.message, true);
    }
  }

  function renderNetworks(d) {
    const body = escEl("#wifi-net-body");
    const note = escEl("#wifi-net-note");
    const manage = !!d.manage_enabled;
    const nets = d.networks || [];
    note.innerHTML = manage
      ? (nets.length ? "" : '<div class="wifi-empty muted">No SSIDs found on the access points.</div>')
      : '<div class="wifi-empty"><b>Management is disabled</b>Enable "AP management" in the plugin settings to create or edit networks. Viewing is always available.</div>';
    const addBtn = escEl("#wifi-net-add");
    if (addBtn) addBtn.disabled = !manage;
    body.innerHTML = `
      <div class="table-wrap"><table class="wifi-table wifi-net-table">
        <thead><tr><th>SSID</th><th>Band</th><th>Security</th><th>Network</th><th>APs</th><th>Key</th><th>State</th><th class="td-right">Actions</th></tr></thead>
        <tbody>${nets.map((n) => `
          <tr data-ssid="${state.api.esc(n.ssid)}" data-band="${state.api.esc(n.band)}">
            <td data-label="SSID"><b>${state.api.esc(n.ssid)}</b></td>
            <td data-label="Band">${n.band === "5g" ? "5 GHz" : "2.4 GHz"}</td>
            <td data-label="Security"><span class="wifi-sec${n.encryption === "none" ? " is-open" : ""}">${netSecurity(n.encryption)}</span></td>
            <td data-label="Network"><span class="wifi-ssid-sm">${state.api.esc(n.network || "—")}</span></td>
            <td data-label="APs">${n.aps.length}/${(d.aps || []).length}</td>
            <td data-label="Key">${n.encryption === "none" ? '<span class="muted">open</span>'
              : (n.keys_match ? '<span class="wifi-pill is-up">match</span>' : '<span class="wifi-pill is-bad">differ</span>')}</td>
            <td data-label="State">${n.disabled ? '<span class="wifi-pill is-warn">disabled</span>' : '<span class="wifi-pill is-up">active</span>'}</td>
            <td class="td-right wifi-net-actions" data-label="Actions">
              <button class="btn btn-sm" data-net-edit ${manage ? "" : "disabled"}>Edit</button>
              <button class="btn btn-sm btn-ghost" data-net-toggle ${manage ? "" : "disabled"}>${n.disabled ? "Enable" : "Disable"}</button>
              <button class="btn btn-sm btn-ghost" data-net-delete ${manage ? "" : "disabled"}>Delete</button>
            </td>
          </tr>`).join("") || '<tr><td colspan="8" class="muted">No networks reported.</td></tr>'}
        </tbody>
      </table></div>`;
    body.querySelectorAll("[data-net-edit]").forEach((b) => b.addEventListener("click", (ev) => {
      showNetForm(rowNet(ev.target.closest("tr")));
    }));
    body.querySelectorAll("[data-net-toggle]").forEach((b) => b.addEventListener("click", (ev) => {
      const n = rowNet(ev.target.closest("tr"));
      toggleNet(n);
    }));
    body.querySelectorAll("[data-net-delete]").forEach((b) => b.addEventListener("click", (ev) => {
      deleteNet(rowNet(ev.target.closest("tr")));
    }));
  }

  function rowNet(tr) {
    if (!tr) return null;
    const ssid = tr.dataset.ssid, band = tr.dataset.band;
    return ((state.networks && state.networks.networks) || [])
      .find((n) => n.ssid === ssid && n.band === band);
  }

  function showNetForm(n) {
    const form = escEl("#wifi-net-form");
    if (!form) return;
    if (!n && !(state.networks || {}).manage_enabled) {
      setMsg("Enable AP management in the plugin settings first.", true);
      return;
    }
    state.netEdit = n;
    const editing = !!n;
    form.hidden = false;
    form.innerHTML = `
      <div class="wifi-net-form">
        <h3>${editing ? "Edit network" : "Add network"} ${editing ? state.api.esc(n.ssid) : ""}</h3>
        <div class="wifi-form">
          <div class="wifi-field"><label>SSID</label>
            <input id="wifi-net-ssid" type="text" maxlength="32" value="${editing ? state.api.esc(n.ssid) : ""}" placeholder="MyNetwork"></div>
          <div class="wifi-field"><label>Band</label>
            <select id="wifi-net-band" ${editing ? "disabled" : ""}>
              <option value="2g" ${editing && n.band === "2g" ? "selected" : ""}>2.4 GHz</option>
              <option value="5g" ${editing && n.band === "5g" ? "selected" : ""}>5 GHz</option>
            </select></div>
          <div class="wifi-field"><label>Security</label>
            <select id="wifi-net-enc">
              <option value="psk2" ${editing && n.encryption === "psk2" ? "selected" : ""}>WPA2-PSK</option>
              <option value="sae-mixed" ${editing && n.encryption === "sae-mixed" ? "selected" : ""}>WPA2/WPA3 mixed</option>
              <option value="sae" ${editing && n.encryption === "sae" ? "selected" : ""}>WPA3 only</option>
              <option value="none" ${editing && n.encryption === "none" ? "selected" : ""}>Open (no password)</option>
            </select></div>
          <div class="wifi-field"><label>Network</label>
            <input id="wifi-net-network" type="text" value="${editing ? state.api.esc(n.network || "lan") : "lan"}" placeholder="lan or iot"></div>
          <div class="wifi-field wifi-wide"><label>Password ${editing ? "(leave blank to keep current)" : ""}</label>
            <input id="wifi-net-key" type="password" autocomplete="new-password" placeholder="${editing ? "unchanged" : "8-63 characters"}"></div>
        </div>
        <p class="wifi-hint">Changes are applied to <b>every</b> access point at once. Renaming an SSID or changing its password disconnects clients until they are re-provisioned.</p>
        <div class="wifi-actions">
          <button class="btn btn-sm btn-primary" id="wifi-net-save" type="button">${editing ? "Save changes" : "Create network"}</button>
          <button class="btn btn-sm btn-ghost" id="wifi-net-cancel" type="button">Cancel</button>
          <span class="wifi-msg" id="wifi-net-msg"></span>
        </div>
      </div>`;
    escEl("#wifi-net-cancel").addEventListener("click", () => { form.hidden = true; form.innerHTML = ""; });
    escEl("#wifi-net-save").addEventListener("click", saveNetForm);
    if (form.scrollIntoView) form.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  async function saveNetForm() {
    const editing = !!state.netEdit;
    const msg = escEl("#wifi-net-msg");
    const ssid = escEl("#wifi-net-ssid").value.trim();
    const band = escEl("#wifi-net-band").value;
    const enc = escEl("#wifi-net-enc").value;
    const network = escEl("#wifi-net-network").value.trim();
    const key = escEl("#wifi-net-key").value;
    if (!ssid) { msg.textContent = "SSID is required."; msg.className = "wifi-msg is-bad"; return; }
    if (enc !== "none" && !editing && key.length < 8) {
      msg.textContent = "Password must be at least 8 characters."; msg.className = "wifi-msg is-bad"; return;
    }
    const impact = [];
    if (editing && ssid !== state.netEdit.ssid) impact.push("renaming disconnects every client on this network");
    if (key) impact.push("all clients must re-enter the new password");
    if (!editing) impact.push("the new network starts broadcasting on all APs");
    if (impact.length && !window.confirm(`Apply to ALL access points?\n\n· ${impact.join("\n· ")}\n\nContinue?`)) return;

    msg.textContent = "Applying…"; msg.className = "wifi-msg";
    try {
      const payload = editing
        ? { band: state.netEdit.band, ssid: state.netEdit.ssid, new_ssid: ssid,
            encryption: enc, network, key, confirm: true }
        : { band, ssid, encryption: enc, network, key, confirm: true };
      const d = await state.api.api(editing ? "wlan-save" : "wlan-add", payload);
      if (!d.ok) throw new Error(Object.values(d.results || {}).map((r) => r.error).filter(Boolean).join(" · ")
        || d.error || "Change failed");
      msg.textContent = "Applied."; msg.className = "wifi-msg";
      showToast(editing ? "Network updated on every access point." : "Network created on every access point.");
      escEl("#wifi-net-form").hidden = true;
      escEl("#wifi-net-form").innerHTML = "";
      setTimeout(loadNetworks, 2500);
    } catch (err) {
      msg.textContent = err.message; msg.className = "wifi-msg is-bad";
    }
  }

  async function toggleNet(n) {
    if (!n) return;
    const verb = n.disabled ? "Enable" : "Disable";
    if (!window.confirm(`${verb} "${n.ssid}" on all access points?` +
      (n.disabled ? "" : "\n\nClients on it will be disconnected."))) return;
    try {
      const d = await state.api.api("wlan-save", {
        band: n.band, ssid: n.ssid, new_ssid: n.ssid, encryption: n.encryption,
        network: n.network, disabled: !n.disabled, confirm: true,
      });
      if (!d.ok) throw new Error(d.error || "Toggle failed");
      showToast(`"${n.ssid}" ${n.disabled ? "enabled" : "disabled"} on every access point — waiting for the APs to settle…`);
      setTimeout(loadNetworks, 2500);
    } catch (err) {
      setMsg(err.message, true);
    }
  }

  async function deleteNet(n) {
    if (!n) return;
    if (!window.confirm(`Delete "${n.ssid}" from ALL access points?\n\nEvery client on it will lose this network. This cannot be undone from the dashboard.`)) return;
    try {
      const d = await state.api.api("wlan-delete", { band: n.band, ssid: n.ssid, confirm: true });
      if (!d.ok) throw new Error(d.error || "Delete failed");
      showToast(`"${n.ssid}" deleted from every access point — waiting for the APs to settle…`);
      setTimeout(loadNetworks, 2500);
    } catch (err) {
      setMsg(err.message, true);
    }
  }

  async function applyChannel(ap, band, channel, dfs) {
    const warn = dfs ? "\n\nThis is a DFS channel — the radio pauses 1-10 min for a radar check after switching." : "";
    if (!window.confirm(`Set ${band === "5g" ? "5 GHz" : "2.4 GHz"} channel ${channel} on ${ap}?` +
      "\n\nClients on that radio will blip for a few seconds." + warn)) return;
    setMsg("Applying channel…");
    try {
      const d = await state.api.api("radio-channel", { ap, band, channel: String(channel), confirm: true });
      if (!d.ok) throw new Error(d.error || "Channel change failed");
      setMsg("Channel applied — rescan to see the new environment.");
      setTimeout(runRfScan, 4000);
    } catch (err) {
      setMsg(err.message, true);
    }
  }

  function renderHealth(d) {
    const parity = d.parity;
    const flaps = d.flaps || [];
    let html = "";
    if (parity && (parity.compared || 0) >= 2) {
      html += `
        <div class="wifi-card wifi-health" data-state="${parity.match ? "ok" : "warn"}">
          <div class="wifi-head">
            ${headIcon("list")}
            <div class="wifi-head-copy">
              <h2>Config parity</h2>
              <p class="muted">Wireless settings compared across ${parity.compared} access points</p>
            </div>
            <span class="wifi-pill ${parity.match ? "is-up" : "is-warn"}">${parity.match ? "Match" : "Drift detected"}</span>
          </div>
          ${parity.match ? `<p class="wifi-health-lede">SSIDs, keys, network bindings and channel widths match on every access point.</p>` : `<ul class="wifi-parity-list">${(parity.mismatches || []).map((m) =>
            `<li>${state.api.esc(m)}</li>`).join("")}</ul>`}
        </div>`;
    }
    if (flaps.length) {
      html += `
        <div class="wifi-card wifi-health" data-state="warn">
          <div class="wifi-head">
            ${headIcon("activity")}
            <div class="wifi-head-copy">
              <h2>Flapping clients</h2>
              <p class="muted">Repeated disconnect / reconnect cycles in the log window</p>
            </div>
            <span class="wifi-pill is-warn">${flaps.length} flapping</span>
          </div>
          <div class="table-wrap"><table class="wifi-table wifi-flap-table">
            <thead><tr><th>Client</th><th>AP</th><th>Disconnects</th><th>Connects</th></tr></thead>
            <tbody>${flaps.map((f) => `<tr>
              <td class="mono" data-label="Client"><b>${state.api.esc(f.mac)}</b></td>
              <td data-label="AP">${state.api.esc(f.ap)}</td>
              <td data-label="Disconnects"><b>${fmtNum(f.disconnects)}</b></td>
              <td data-label="Connects">${fmtNum(f.connects)}</td>
            </tr>`).join("")}</tbody>
          </table></div>
        </div>`;
    }
    return html ? `<div class="wifi-health-row">${html}</div>` : "";
  }

  async function refreshData() {
    if (state.busy) return;
    state.busy = true;
    setMsg("Refreshing…");
    try {
      const d = await state.api.api("overview", {});
      state.data = d;
      if (!d.ok && !d.aps) throw new Error(d.error || "Could not collect AP data");
      renderOverview(d);
      setMsg("");
    } catch (err) {
      setMsg(err.message, true);
    } finally {
      state.busy = false;
    }
  }

  async function refreshEvents() {
    const list = escEl("#wifi-event-list");
    if (!list) return;
    list.innerHTML = '<div class="wifi-empty"><span class="wifi-spinner"></span>Loading events…</div>';
    try {
      const d = await state.api.api("events", { limit: 100 });
      if (!d.ok) throw new Error(d.error || "Could not load events");
      const events = d.events || [];
      const count = escEl("#wifi-event-count");
      if (count) count.textContent = events.length ? `${events.length} events` : "";
      const rows = events.map((e) => {
        const connected = e.severity !== "warning";
        const bits = [e.ap, e.ssid, e.auth].filter(Boolean).join(" · ");
        return `
          <div class="wifi-event" data-sev="${connected ? "info" : "warning"}">
            <span class="wifi-event-dot"></span>
            <div class="wifi-event-copy">
              <div class="wifi-event-title">${state.api.esc(e.title)}<span class="mono">${state.api.esc(e.client || e.mac || "")}</span></div>
              <div class="wifi-event-detail">${state.api.esc(bits || "—")}</div>
            </div>
            <span class="wifi-event-time" title="${state.api.esc(new Date(e.time * 1000).toLocaleString())}">${state.api.formatRelative(e.time)}</span>
          </div>`;
      }).join("");
      list.innerHTML = rows || '<div class="wifi-empty"><b>No hostapd events</b>Nothing has connected or disconnected in the current log window.</div>';
    } catch (err) {
      const count = escEl("#wifi-event-count");
      if (count) count.textContent = "";
      list.innerHTML = `<div class="wifi-empty is-bad">${state.api.esc(err.message)}</div>`;
    }
  }

  function renderInventory() {
    const body = escEl("#wifi-inventory-body");
    const d = state.data;
    const aps = (d && d.aps) || [];
    const count = escEl("#wifi-inv-count");
    if (count) count.textContent = aps.length ? `${aps.length} AP${aps.length === 1 ? "" : "s"}` : "";
    if (!aps.length) {
      body.innerHTML = '<div class="wifi-empty"><b>Nothing to show yet</b>Open the Overview tab to collect inventory from your access points.</div>';
      return;
    }
    body.innerHTML = `
      <div class="table-wrap"><table class="wifi-table wifi-inv-table">
        <thead><tr><th>Name</th><th>Model</th><th>Firmware</th><th>IP</th><th>MAC</th><th>Radios</th><th>Uptime</th><th class="td-right">Clients</th></tr></thead>
        <tbody>${aps.map((ap) => `
          <tr>
            <td><b>${state.api.esc(ap.name)}</b></td>
            <td>${state.api.esc(ap.model || "—")}</td>
            <td><span class="wifi-fw">${state.api.esc(ap.version || "—")}</span></td>
            <td class="mono">${state.api.esc(ap.ip || "—")}</td>
            <td class="mono">${state.api.esc(ap.mac || "—")}</td>
            <td>${(ap.radios || []).map((r) => {
              const band = bandInfo(r.radio);
              return `<span class="wifi-radio-tag${r.up === false ? " is-down" : ""}">${state.api.esc(band.short)}</span>`;
            }).join("") || "—"}</td>
            <td>${state.api.esc(ap.uptime || "—")}</td>
            <td class="td-right"><b>${fmtNum(ap.clients)}</b></td>
          </tr>`).join("")}</tbody>
      </table></div>`;
  }

  function mount(el, api) {
    state.el = el;
    state.api = api;
    skeleton();
    loadConfig(true);
  }

  function refresh() {
    if (!state.el) return;
    if (state.tab === "events") refreshEvents();
    else if (state.tab === "inventory") renderInventory();
    else if (state.tab === "rf") { /* manual scan only — keep last results */ }
    else if (state.tab === "networks") loadNetworks();
    else loadConfig();
  }

  window.TuxWallPlugins.register("openwrt", { mount, refresh });
})();
