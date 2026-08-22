(() => {
  "use strict";

  const REFRESH_MS = 30000;
  const BANDWIDTH_POLL_MS = 5000;
  const SECURITY_POLL_MS = 5000;
  const WG_POLL_MS = 5000;
  const OV_POLL_MS = 5000;
  const SYSTEM_WINDOW = 600;

  const state = {
    leases: [],
    sortKey: "ip",
    sortDir: 1,
    filter: "",
    lastUpdate: null,
    timer: null,
    svcTab: "active",
    svcData: null,
    activeView: null,
    bwData: null,
    wgData: null,
    secCrowdsecUp: null,
    secBannedIps: new Set(),
    domains: [],
    domEditId: null,
    domEditSource: null,
    ovData: null,
    suricataSev: "HIGH",
    sysHostname: "",
    editingHost: false,
    cfgTarget: null,
    updTimer: null,
    logTimer: null,
    allThemes: [],
    activeTheme: "dark",
    authed: false,
    username: "",
    role: "viewer",
    isOwner: false,
    themeBootstrapped: false,
  };

  const els = {
    body: document.getElementById("leases-body"),
    count: document.getElementById("result-count"),
    search: document.getElementById("search"),
    total: document.getElementById("stat-total"),
    dynamic: document.getElementById("stat-dynamic"),
    reserved: document.getElementById("stat-reserved"),
    statStatic: document.getElementById("stat-static"),
    updated: document.getElementById("last-updated"),
    banner: document.getElementById("banner"),
    refresh: document.getElementById("refresh-btn"),
    auto: document.getElementById("auto-refresh"),
    empty: document.getElementById("empty-state"),
    soon: document.getElementById("soon-card"),
    title: document.getElementById("page-title"),
    dnsQueries: document.getElementById("dns-queries"),
    dnsHitrate: document.getElementById("dns-hitrate"),
    dnsMisses: document.getElementById("dns-misses"),
    dnsRecur: document.getElementById("dns-recur"),
    dnsTcp: document.getElementById("dns-tcp"),
    dnsUdp: document.getElementById("dns-udp"),
    dnsUnwanted: document.getElementById("dns-unwanted"),
    dnsUptime: document.getElementById("dns-uptime"),
    dnsVersion: document.getElementById("dns-version"),
    dnsQtypesBody: document.querySelector("#dns-qtypes tbody"),
    dnsRcodesBody: document.querySelector("#dns-rcodes tbody"),
    dnsRrsetCount: document.getElementById("dns-rrset-count"),
    dnsRrsetSize: document.getElementById("dns-rrset-size"),
    dnsMsgCount: document.getElementById("dns-msg-count"),
    dnsMsgSize: document.getElementById("dns-msg-size"),
    dnsKeyCount: document.getElementById("dns-key-count"),
    fwStatus: document.getElementById("fw-status"),
    fwIncoming: document.getElementById("fw-incoming"),
    fwOutgoing: document.getElementById("fw-outgoing"),
    fwRules: document.getElementById("fw-rules"),
    fwBlocks: document.getElementById("fw-blocks"),
    fwAllows: document.getElementById("fw-allows"),
    fwLogging: document.getElementById("fw-logging"),
    fwRulesBody: document.querySelector("#fw-rules-table tbody"),
    fwRule: document.getElementById("fw-rule"),
    fwAdd: document.getElementById("fw-add"),
    fwAddCustom: document.getElementById("fw-add-custom"),
    fwBaseline: document.getElementById("fw-baseline"),
    fwReset: document.getElementById("fw-reset"),
    fwHint: document.getElementById("fw-hint"),
    fwAction: document.getElementById("fw-action"),
    fwDirection: document.getElementById("fw-direction"),
    fwIface: document.getElementById("fw-iface"),
    fwFamily: document.getElementById("fw-family"),
    fwFrom: document.getElementById("fw-from"),
    fwProto: document.getElementById("fw-proto"),
    fwPort: document.getElementById("fw-port"),
    fwSourcesBody: document.querySelector("#fw-sources tbody"),
    fwPortsBody: document.querySelector("#fw-ports tbody"),
    fwEventsBody: document.querySelector("#fw-events tbody"),
    csActive: document.getElementById("cs-active"),
    csBans: document.getElementById("cs-bans"),
    csBouncers: document.getElementById("cs-bouncers"),
    csExpiring: document.getElementById("cs-expiring"),
    csDecisionsBody: document.querySelector("#cs-decisions-table tbody"),
    csBouncersBody: document.querySelector("#cs-bouncers-table tbody"),
    csAlertsBody: document.querySelector("#cs-alerts-table tbody"),
    cblInput: document.getElementById("cbl-input"),
    cblAdd: document.getElementById("cbl-add"),
    cblStatus: document.getElementById("cbl-status"),
    cblFile: document.getElementById("cbl-file"),
    cblBody: document.querySelector("#cbl-body"),
    cblEmpty: document.getElementById("cbl-empty"),
    bwDown: document.getElementById("bw-down"),
    bwUp: document.getElementById("bw-up"),
    bwWindow: document.getElementById("bw-window"),
    bwSamples: document.getElementById("bw-samples"),
    bwCharts: document.getElementById("bw-charts"),
    bwClientsBody: document.querySelector("#bw-clients-body"),
    bwClientsEmpty: document.getElementById("bw-clients-empty"),
    secHits: document.getElementById("sec-hits"),
    secIps: document.getElementById("sec-ips"),
    secCountries: document.getElementById("sec-countries"),
    secRate: document.getElementById("sec-rate"),
    secGeoHint: document.getElementById("sec-geo-hint"),
    secCountriesBody: document.querySelector("#sec-countries-body"),
    secIpsBody: document.querySelector("#sec-ips-body"),
    secBanAll: document.getElementById("sec-ban-all"),
    secBanStatus: document.getElementById("sec-ban-status"),
    secEventsBody: document.querySelector("#sec-events-body"),
    secEventCount: document.getElementById("sec-event-count"),
    secSuricataBody: document.querySelector("#sec-suricata-body"),
    secSuricataHint: document.getElementById("sec-suricata-hint"),
    secSuricataTabs: document.getElementById("sec-suricata-tabs"),
    secChart: document.getElementById("sec-chart"),

    aiCfgModal: document.getElementById("ai-cfg-modal"),
    aiCfgModalClose: document.getElementById("ai-cfg-modal-close"),
    aiCfgBaseUrl: document.getElementById("ai-cfg-base-url"),
    aiCfgApiKey: document.getElementById("ai-cfg-api-key"),
    aiCfgModel: document.getElementById("ai-cfg-model"),
    aiCfgHint: document.getElementById("ai-cfg-hint"),
    aiCfgSave: document.getElementById("ai-cfg-modal-save"),
    aiCfgCancel: document.getElementById("ai-cfg-modal-cancel"),
    dmDomain: document.getElementById("dm-domain"),
    dmIp: document.getElementById("dm-ip"),
    dmPort: document.getElementById("dm-port"),
    dmNote: document.getElementById("dm-note"),
    dmAdd: document.getElementById("dm-add"),
    dmCancel: document.getElementById("dm-cancel"),
    dmHint: document.getElementById("dm-hint"),
    dmBody: document.querySelector("#dm-body"),
    dmCount: document.getElementById("dm-count"),
    dmPorts: document.getElementById("dm-ports"),
    dmStatus: document.getElementById("dm-status"),
    dmImportAll: document.getElementById("dm-import-all"),
    wgUnconfigured: document.getElementById("wg-unconfigured"),
    wgConfigured: document.getElementById("wg-configured"),
    wgSetupForm: document.getElementById("wg-setup-form"),
    wgSetupBtn: document.getElementById("wg-setup-btn"),
    wgSetupError: document.getElementById("wg-setup-error"),
    wgSetupAddress: document.getElementById("wg-setup-address"),
    wgSetupPort: document.getElementById("wg-setup-port"),
    wgSetupDns: document.getElementById("wg-setup-dns"),
    wgSetupAllowed: document.getElementById("wg-setup-allowed"),
    wgSetupEndpoint: document.getElementById("wg-setup-endpoint"),
    wgSetupKeepalive: document.getElementById("wg-setup-keepalive"),
    wgState: document.getElementById("wg-state"),
    wgEndpoint: document.getElementById("wg-endpoint"),
    wgPeers: document.getElementById("wg-peers"),
    wgTransfer: document.getElementById("wg-transfer"),
    wgHint: document.getElementById("wg-hint"),
    wgAddPeer: document.getElementById("wg-add-peer"),
    wgPeersBody: document.querySelector("#wg-peers-body"),
    wgPeerNote: document.getElementById("wg-peer-note"),
    wgModal: document.getElementById("wg-modal"),
    wgModalTitle: document.getElementById("wg-modal-title"),
    wgQr: document.getElementById("wg-qr"),
    wgModalText: document.getElementById("wg-modal-text"),
    wgModalDownload: document.getElementById("wg-modal-download"),
    wgModalCopy: document.getElementById("wg-modal-copy"),
    wgModalClose: document.getElementById("wg-modal-close"),
    wgModalClose2: document.getElementById("wg-modal-close2"),
    blDomains: document.getElementById("bl-domains"),
    blSources: document.getElementById("bl-sources"),
    blStatus: document.getElementById("bl-status"),
    blUpdated: document.getElementById("bl-updated"),
    blQueries: document.getElementById("bl-queries"),
    blBlocked: document.getElementById("bl-blocked"),
    blUrl: document.getElementById("bl-url"),
    blAdd: document.getElementById("bl-add"),
    blUpdate: document.getElementById("bl-update"),
    blBody: document.getElementById("bl-body"),
    blEmpty: document.getElementById("bl-empty"),
    blLog: document.getElementById("bl-log"),
    blHint: document.getElementById("bl-hint"),
    wlDomain: document.getElementById("wl-domain"),
    wlAdd: document.getElementById("wl-add"),
    wlBody: document.getElementById("wl-body"),
    wlEmpty: document.getElementById("wl-empty"),
    sysHost: document.getElementById("sys-host"),
    sysHostEdit: document.getElementById("sys-host-edit"),
    sysEditKea: document.getElementById("sys-edit-kea"),
    sysEditUnbound: document.getElementById("sys-edit-unbound"),
    cfgModal: document.getElementById("cfg-modal"),
    cfgModalTitle: document.getElementById("cfg-modal-title"),
    cfgModalText: document.getElementById("cfg-modal-text"),
    cfgModalHint: document.getElementById("cfg-modal-hint"),
    cfgModalSave: document.getElementById("cfg-modal-save"),
    cfgModalClose: document.getElementById("cfg-modal-close"),
    cfgModalCancel: document.getElementById("cfg-modal-cancel"),
    sysUpdDistro: document.getElementById("sys-upd-distro"),
    sysUpdKernel: document.getElementById("sys-upd-kernel"),
    sysUpdChecked: document.getElementById("sys-upd-checked"),
    sysUpdLast: document.getElementById("sys-upd-last"),
    sysUpdCount: document.getElementById("sys-upd-count"),
    sysUpdCheck: document.getElementById("sys-upd-check"),
    sysUpdApply: document.getElementById("sys-upd-apply"),
    sysUpdProgress: document.getElementById("sys-upd-progress"),
    sysUpdBar: document.getElementById("sys-upd-bar"),
    sysUpdStatus: document.getElementById("sys-upd-status"),
    sysUpdLog: document.getElementById("sys-upd-log"),
    sysReboot: document.getElementById("sys-reboot"),
    logSource: document.getElementById("log-source"),
    logPriority: document.getElementById("log-priority"),
    logLines: document.getElementById("log-lines"),
    logRefresh: document.getElementById("log-refresh"),
    logFollow: document.getElementById("log-follow"),
    logView: document.getElementById("log-view"),
    logMeta: document.getElementById("log-meta"),
    bkBody: document.getElementById("bk-body"),
    bkCreate: document.getElementById("bk-create"),
    bkRestore: document.getElementById("bk-restore"),
    bkFile: document.getElementById("bk-file"),
    bkMsg: document.getElementById("bk-msg"),
    bkSysCreate: document.getElementById("bk-sys-create"),
    bkSysBody: document.getElementById("bk-sys-body"),
    bkSysMsg: document.getElementById("bk-sys-msg"),
    bkSysProgress: document.getElementById("bk-sys-progress"),
    bkSysBar: document.getElementById("bk-sys-bar"),
    bkSysStatus: document.getElementById("bk-sys-status"),
    sysCpu: document.getElementById("sys-cpu"),
    sysMem: document.getElementById("sys-mem"),
    sysUptime: document.getElementById("sys-uptime"),
    sysLoad: document.getElementById("sys-load"),
    sysDisk: document.getElementById("sys-disk"),
    sysSwap: document.getElementById("sys-swap"),
    sysOs: document.getElementById("sys-os"),
    sysInterfacesBody: document.querySelector("#sys-interfaces tbody"),
    sysServicesBody: document.querySelector("#sys-services tbody"),
    sysSvcRefresh: document.getElementById("sys-svc-refresh"),
    svcTabs: document.getElementById("svc-tabs"),
    sysDhcpSubnet: document.getElementById("sys-dhcp-subnet"),
    sysDhcpRange: document.getElementById("sys-dhcp-range"),
    sysDhcpRouter: document.getElementById("sys-dhcp-router"),
    sysDhcpDns: document.getElementById("sys-dhcp-dns"),
    sysDhcpDomain: document.getElementById("sys-dhcp-domain"),
    sysDnsIface: document.getElementById("sys-dns-iface"),
    sysDnsPort: document.getElementById("sys-dns-port"),
    sysCpuModel: document.getElementById("sys-cpu-model"),
    sysCpuCores: document.getElementById("sys-cpu-cores"),
    sysMemDetail: document.getElementById("sys-mem-detail"),
    sysSwapDetail: document.getElementById("sys-swap-detail"),
    sysKernel: document.getElementById("sys-kernel"),
    sysArch: document.getElementById("sys-arch"),
    ovCpu: document.getElementById("ov-cpu"),
    ovMem: document.getElementById("ov-mem"),
    ovDisk: document.getElementById("ov-disk"),
    ovUptime: document.getElementById("ov-uptime"),
    ovClients: document.getElementById("ov-clients"),
    ovDnsBlocked: document.getElementById("ov-dns-blocked"),
    ovFwBlocks: document.getElementById("ov-fw-blocks"),
    ovAttacks: document.getElementById("ov-attacks"),
    ovLatNow: document.getElementById("ov-lat-now"),
    ovLatPeak: document.getElementById("ov-lat-peak"),
    ovLatLoss: document.getElementById("ov-lat-loss"),
    ovLatJitter: document.getElementById("ov-lat-jitter"),
    ovResHint: document.getElementById("ov-res-hint"),
    ovBwHint: document.getElementById("ov-bw-hint"),
    ovLatHint: document.getElementById("ov-lat-hint"),
    ovJitHint: document.getElementById("ov-jit-hint"),
    ovJitChart: document.getElementById("ov-jit-chart"),
    ovResChart: document.getElementById("ov-res-chart"),
    ovBwChart: document.getElementById("ov-bw-chart"),
    ovLatChart: document.getElementById("ov-lat-chart"),
    ovPieSinkhole: document.getElementById("ov-pie-sinkhole"),
    ovPieQtypes: document.getElementById("ov-pie-qtypes"),
    ovPieIpv: document.getElementById("ov-pie-ipv"),
    ovPieMem: document.getElementById("ov-pie-mem"),
    ovPieFw: document.getElementById("ov-pie-fw"),
    ovPieCountries: document.getElementById("ov-pie-countries"),
    ovPieBw: document.getElementById("ov-pie-bw"),
    ovPieCache: document.getElementById("ov-pie-cache"),
    ovGeoHint: document.getElementById("ov-geo-hint"),
    ovTalkersBody: document.querySelector("#ov-talkers-body"),
    ovSuricataBody: document.querySelector("#ov-suricata-body"),
    ovSuricataHint: document.getElementById("ov-suricata-hint"),
    themeGrid: document.getElementById("theme-grid"),
    themeActiveHint: document.getElementById("theme-active-hint"),
    themeFile: document.getElementById("theme-file"),
    themeUploadBtn: document.getElementById("theme-upload-btn"),
    themeUploadMsg: document.getElementById("theme-upload-msg"),
    themeFormatSample: document.getElementById("theme-format-sample"),
    loginGate: document.getElementById("login-gate"),
    loginForm: document.getElementById("login-form"),
    loginUser: document.getElementById("login-user"),
    loginPass: document.getElementById("login-pass"),
    loginError: document.getElementById("login-error"),
    loginBtn: document.getElementById("login-btn"),
    loginHeading: document.getElementById("login-heading"),
    loginSub: document.getElementById("login-sub"),
    logoutBtn: document.getElementById("logout-btn"),
    sideUser: document.getElementById("side-user"),
    sideRole: document.getElementById("side-role"),
    acctHint: document.getElementById("acct-hint"),
    pwCurrent: document.getElementById("pw-current"),
    pwNew: document.getElementById("pw-new"),
    pwConfirm: document.getElementById("pw-confirm"),
    pwSave: document.getElementById("pw-save"),
    pwMsg: document.getElementById("pw-msg"),
    usersCard: document.getElementById("users-card"),
    usersTbody: document.getElementById("users-tbody"),
    nuName: document.getElementById("nu-name"),
    nuPass: document.getElementById("nu-pass"),
    nuRole: document.getElementById("nu-role"),
    nuAdd: document.getElementById("nu-add"),
    usersMsg: document.getElementById("users-msg"),
  };

  const TYPE_LABEL = { 0: "Dynamic", 1: "Reserved", 2: "Reserved-Declined" };
  const OS_ICONS = {
    windows: {
      label: "Windows",
      svg: `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.9-1.801" fill="currentColor"/>
      </svg>`,
      color: "#0078d4",
    },
    mac: {
      label: "macOS",
      svg: `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor">
        <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11"/>
      </svg>`,
      color: "#aaaaaa",
    },
    apple: {
      label: "iOS / iPadOS",
      svg: `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor">
        <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11"/>
      </svg>`,
      color: "#6e6e73",
    },
    android: {
      label: "Android",
      svg: `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor">
        <path d="M6 18c0 .55.45 1 1 1h1v3.5c0 .83.67 1.5 1.5 1.5S11 23.33 11 22.5V19h2v3.5c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5V19h1c.55 0 1-.45 1-1V8H6v10zm-2.5-2C2.67 16 2 15.33 2 14.5v-5C2 8.67 2.67 8 3.5 8S5 8.67 5 9.5v5c0 .83-.67 1.5-1.5 1.5zm17 0c-.83 0-1.5-.67-1.5-1.5v-5c0-.83.67-1.5 1.5-1.5s1.5.67 1.5 1.5v5c0 .83-.67 1.5-1.5 1.5zM15.53 2.16l1.3-1.3c.2-.2.2-.51 0-.71-.2-.2-.51-.2-.71 0l-1.48 1.48A5.84 5.84 0 0 0 12 1c-.96 0-1.86.23-2.66.63L7.85.15c-.2-.2-.51-.2-.71 0-.2.2-.2.51 0 .71l1.31 1.31C7.14 3.45 6 5.17 6 7h12c0-1.83-1.14-3.55-2.47-4.84zM10 5H9V4h1v1zm5 0h-1V4h1v1z"/>
      </svg>`,
      color: "#3ddc84",
    },
    chromebook: {
      label: "ChromeOS",
      svg: `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="3.5" fill="#4285f4"/>
        <path d="M12 2a10 10 0 0 1 8.66 5H12a5 5 0 0 0-4.33 2.5L5.1 5.68A9.97 9.97 0 0 1 12 2z" fill="#ea4335"/>
        <path d="M2 12a10 10 0 0 1 3.1-7.32l3.57 6.18A5 5 0 0 0 12 17v5A10 10 0 0 1 2 12z" fill="#34a853"/>
        <path d="M12 17a5 5 0 0 0 4.33-2.5l3.57 6.18A10 10 0 0 1 12 22v-5z" fill="#fbbc05"/>
        <path d="M12 22v-5a5 5 0 0 0 4.33-2.5l3.57-6.18C21.27 9.8 22 10.85 22 12A10 10 0 0 1 12 22z" fill="#fbbc05"/>
      </svg>`,
      color: "#4285f4",
    },
    linux: {
      label: "Linux",
      svg: `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor">
        <path d="M20.581 19.049c-.55-.446-.76-1.22-.809-1.843-.053-.69.009-1.304-.5-1.966-.35-.451-.648-.655-.74-1.278-.08-.54.04-1.104.055-1.644.022-.726-.317-1.273-.861-1.67-.88-.635-.843-1.044-.843-1.044S17.482 2.831 12 2.831 6.118 9.604 6.118 9.604s.037.409-.843 1.044c-.544.397-.883.944-.861 1.67.015.54.135 1.104.055 1.644-.092.623-.39.827-.74 1.278-.509.662-.447 1.276-.5 1.966-.049.623-.259 1.397-.809 1.843-.55.446-.717 1.268.034 1.49.751.222 1.893.151 2.451-.518.557-.669.469-1.492.469-1.492.304.085.711.152 1.255.152.544 0 .951-.067 1.255-.152 0 0-.088.823.469 1.492.558.669 1.7.74 2.451.518.751-.222.584-1.044.034-1.49zM12 4.062c.737 0 .992.459.992.459L12 5.5l-.992-.979s.255-.459.992-.459zm-2.5 7.438c-.552 0-1-.675-1-1.5s.448-1.5 1-1.5 1 .675 1 1.5-.448 1.5-1 1.5zm5 0c-.552 0-1-.675-1-1.5s.448-1.5 1-1.5 1 .675 1 1.5-.448 1.5-1 1.5z"/>
      </svg>`,
      color: "#f5a623",
    },
    other: {
      label: "Network Device",
      svg: `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor">
        <path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3a4.237 4.237 0 0 0-6 0zm-4-4 2 2a7.074 7.074 0 0 1 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/>
      </svg>`,
      color: "#8b949e",
    },
  };
  const VIEW_TITLES = {
    overview: "Overview",
    clients: "DHCP Clients",
    dns: "DNS (Unbound)",
    domains: "Local Domains",
    blocklists: "Blocklists",
    firewall: "Firewall (UFW)",
    security: "Security",
    wireguard: "WireGuard",
    crowdsec: "CrowdSec",
    bandwidth: "Bandwidth",
    system: "System",
    backups: "Backups",
    logs: "Logs",
    settings: "Settings",
    ai: "AI Assistant",
  };

  const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));

  function formatDuration(sec) {
    if (sec === null || sec === undefined || isNaN(sec)) return "—";
    sec = Math.floor(sec);
    if (sec <= 0) return "Expired";
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m`;
    return `${sec}s`;
  }

  function formatRelative(ts) {
    if (!ts) return "—";
    const diff = Math.floor(Date.now() / 1000 - ts);
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  function formatDateTime(ts) {
    if (!ts) return "";
    return new Date(ts * 1000).toLocaleString();
  }

  function formatTime(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toLocaleTimeString();
  }

  function flagEmoji(iso) {
    if (!iso || iso.length !== 2 || iso === "??") return "🌐";
    return String.fromCodePoint(
      ...iso.toUpperCase().split("").map((c) => 0x1f1a5 + c.charCodeAt(0))
    );
  }

  function formatNumber(n) {
    return new Intl.NumberFormat().format(Math.round(n || 0));
  }

  function formatBytes(n) {
    n = n || 0;
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
    if (n < 1099511627776) return `${(n / 1073741824).toFixed(2)} GB`;
    return `${(n / 1099511627776).toFixed(2)} TB`;
  }

  function formatBits(bps) {
    if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " Gbps";
    if (bps >= 1e6) return (bps / 1e6).toFixed(2) + " Mbps";
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " kbps";
    return Math.round(bps) + " bps";
  }

  function formatMBs(bytesPerSec) {
    const b = bytesPerSec || 0;
    if (b >= 1048576) return (b / 1048576).toFixed(2) + " MB/s";
    if (b >= 1024) return (b / 1024).toFixed(1) + " KB/s";
    return b.toFixed(1) + " B/s";
  }

  function formatUptime(sec) {
    sec = Math.floor(sec || 0);
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m`;
    return `${sec}s`;
  }

  function compareIp(a, b) {
    const pa = (a || "").split(".").map(Number);
    const pb = (b || "").split(".").map(Number);
    for (let i = 0; i < 4; i++) {
      const x = pa[i] || 0, y = pb[i] || 0;
      if (x !== y) return x - y;
    }
    return 0;
  }

  function sortLeases(leases) {
    const { sortKey: key, sortDir: dir } = state;
    const sorted = [...leases];
    sorted.sort((x, y) => {
      if (key === "ip") return compareIp(x.ip, y.ip) * dir;
      if (key === "remaining") return ((x.remaining ?? -1) - (y.remaining ?? -1)) * dir;
      const a = String(x[key] ?? "").toLowerCase();
      const b = String(y[key] ?? "").toLowerCase();
      return a.localeCompare(b) * dir;
    });
    return sorted;
  }

  function filterLeases(leases) {
    const q = state.filter.trim().toLowerCase();
    if (!q) return leases;
    return leases.filter((l) =>
      [l.hostname, l.ip, l.mac, l.vendor].some((v) => String(v).toLowerCase().includes(q))
    );
  }

  function render() {
    const active = state.leases.filter((l) => (l.state || 0) !== 2);
    const rows = filterLeases(sortLeases(active));

    els.total.textContent = active.length;
    els.dynamic.textContent = active.filter((l) => (l.type || 0) === 0 && !l.static).length;
    els.reserved.textContent = active.filter((l) => (l.type || 0) === 1).length;
    els.statStatic.textContent = active.filter((l) => l.static).length;
    els.count.textContent = rows.length ? `${rows.length} of ${active.length} shown` : "";

    els.body.innerHTML = rows.map((l) => {
      const dotClass = l.static && l.online === false
        ? "dot-off"
        : (l.state || 0) === 1 ? "dot-warn" : "dot-ok";
      const osInfo = OS_ICONS[l.os];
      const osIcon = osInfo
        ? `<span class="os-badge os-badge-${esc(l.os)}" title="${esc([osInfo.label, l.os_detail, l.vendor].filter(Boolean).join(" · "))}" style="--os-color:${esc(osInfo.color)}">${osInfo.svg}</span>`
        : `<span class="os-badge os-badge-unknown" style="--os-color:#8b949e">${OS_ICONS.other.svg}</span>`;
      const vendor = l.vendor ? `<div class="client-vendor">${esc(l.vendor)}</div>` : "";
      const typeBadge = l.static
        ? `<span class="badge badge-static">Static</span>`
        : `<span class="badge">${esc(TYPE_LABEL[l.type] || "Unknown")}</span>`;
      let actions;
      if (l.static) {
        actions = `<span class="badge badge-static">${l.online === false ? "Offline" : "Static"}</span>`;
      } else if (state.role !== "admin") {
        actions = `<span class="badge ${l.banned ? "badge-err" : "badge-ok"}">${l.banned ? "Banned" : "Active"}</span>`;
      } else {
        actions = `<span class="badge ${l.banned ? "badge-err" : "badge-ok"}">${l.banned ? "Banned" : "Active"}</span>
           <button class="btn btn-sm ${l.banned ? "unban-btn" : "ban-btn btn-danger"}" data-ip="${esc(l.ip)}" data-hostname="${esc(l.hostname || "")}" data-mac="${esc(l.mac || "")}" type="button">${l.banned ? "Unban" : "Ban"}</button>`;
      }
      return `<tr class="client-row${l.banned ? " client-banned" : ""}${l.online === false && l.static ? " client-offline" : ""}">
        <td>
          <div class="client-host-cell">
            <span class="dot ${dotClass}"></span>
            ${osIcon}
            <div class="client-host-info">
              <span class="client-hostname">${esc(l.hostname || "(no hostname)")}</span>
              ${vendor}
            </div>
          </div>
        </td>
        <td class="mono">${esc(l.ip)}</td>
        <td class="mono">${esc(l.mac || "—")}</td>
        <td>${typeBadge}</td>
        <td title="${l.static ? "Static reservation" : esc(formatDateTime(l.expires))}">${l.static ? "Static" : formatDuration(l.remaining)}</td>
        <td title="${l.static && l.online === false ? "No current lease" : esc(formatDateTime(l.last_seen))}">${l.static && l.online === false ? "Offline" : formatRelative(l.last_seen)}</td>
        <td>${actions}</td>
      </tr>`;
    }).join("");

    els.empty.hidden = rows.length > 0;
    updateSortIndicators();
  }

  function updateSortIndicators() {
    document.querySelectorAll("th.sortable").forEach((th) => {
      th.classList.remove("sorting-asc", "sorting-desc");
      if (th.dataset.sort === state.sortKey) {
        th.classList.add(state.sortDir === 1 ? "sorting-asc" : "sorting-desc");
      }
    });
  }

  async function fetchJSON(url) {
    const res = await fetch(url, { cache: "no-store" });
    if (res.status === 401) handleSessionExpired();
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  function showBanner(show, msg) {
    els.banner.hidden = !show;
    if (show) {
      els.banner.textContent = "Dashboard API error: " + (msg || "unknown error");
    }
  }

  async function refresh() {
    try {
      const data = await fetchJSON("/api/leases");
      if (!data.ok) throw new Error(data.error || "Kea returned an error");
      state.leases = data.leases || [];
      state.lastUpdate = new Date();
      showBanner(false);
    } catch (err) {
      showBanner(true, err.message);
    }
    render();
    els.updated.textContent = state.lastUpdate
      ? `Updated ${state.lastUpdate.toLocaleTimeString()}`
      : "";
  }

  function renderDns(d) {
    if (!d.ok) {
      showBanner(true, d.error || "DNS stats unavailable");
      return;
    }
    const t = d.totals || {};
    els.dnsQueries.textContent = formatNumber(t.queries);
    els.dnsHitrate.textContent = ((t.hitrate || 0) * 100).toFixed(1) + "%";
    els.dnsMisses.textContent = formatNumber(t.cachemiss);
    els.dnsRecur.textContent = (t.avg_recursion_ms || 0) + " ms";
    els.dnsTcp.textContent = formatNumber(t.tcp);
    els.dnsUdp.textContent = formatNumber(t.udp);
    els.dnsUnwanted.textContent = formatNumber(t.unwanted);
    els.dnsUptime.textContent = formatUptime(d.uptime);
    els.dnsVersion.textContent = d.version ? "Unbound " + d.version : "";

    const maxQ = (d.qtypes && d.qtypes[0]) ? d.qtypes[0].count : 1;
    els.dnsQtypesBody.innerHTML = (d.qtypes || []).map((q) => `
      <tr>
        <td><b>${esc(q.label)}</b></td>
        <td>${formatNumber(q.count)}</td>
        <td><div class="bar"><div class="bar-fill" style="width:${Math.round(q.count / maxQ * 100)}%"></div></div></td>
      </tr>`).join("");

    const maxR = (d.rcodes && d.rcodes[0]) ? d.rcodes[0].count : 1;
    els.dnsRcodesBody.innerHTML = (d.rcodes || []).map((r) => `
      <tr>
        <td>${esc(r.label)}</td>
        <td>${formatNumber(r.count)}</td>
        <td><div class="bar"><div class="bar-fill" style="width:${Math.round(r.count / maxR * 100)}%"></div></div></td>
      </tr>`).join("");

    const c = d.caches || {};
    els.dnsRrsetCount.textContent = formatNumber(c.rrset_count);
    els.dnsRrsetSize.textContent = formatBytes(c.rrset_size);
    els.dnsMsgCount.textContent = formatNumber(c.msg_count);
    els.dnsMsgSize.textContent = formatBytes(c.msg_size);
    els.dnsKeyCount.textContent = formatNumber(c.key_count);
  }

  async function refreshDns() {
    try {
      const data = await fetchJSON("/api/dns");
      renderDns(data);
    } catch (err) {
      showBanner(true, "DNS stats error: " + err.message);
    }
  }

  function resetDomainForm() {
    state.domEditId = null;
    state.domEditSource = null;
    els.dmDomain.value = "";
    els.dmIp.value = "192.168.1.12";
    els.dmPort.value = "";
    els.dmNote.value = "";
    els.dmAdd.textContent = "Add Domain";
    els.dmCancel.hidden = true;
    els.dmHint.textContent = "";
  }

  function renderDomains(d) {
    if (!d.ok) {
      showBanner(true, d.error || "Domains data unavailable");
      return;
    }
    const domains = d.domains || [];
    state.domains = domains;
    els.dmCount.textContent = formatNumber(domains.length);
    els.dmPorts.textContent = formatNumber(domains.filter((x) => x.port).length);
    els.dmStatus.textContent = "OK";

    els.dmBody.innerHTML = domains.map((x) => {
      const target = "http://" + x.domain + (x.port ? ":" + x.port : "");
      const managed = x.managed !== false;
      const srcName = (x.source_file || "").split("/").pop();
      const actions = managed
        ? `<a class="btn btn-sm" href="${esc(target)}" target="_blank" rel="noopener">Open</a>
           <button class="btn btn-sm dm-edit" data-id="${esc(x.id)}" type="button">Edit</button>
           <button class="btn btn-sm btn-danger dm-delete" data-id="${esc(x.id)}" data-domain="${esc(x.domain)}" data-managed="1" type="button">Delete</button>`
        : `<span class="badge" title="${esc(x.source_file || "")}">${esc(srcName)}</span>
           <button class="btn btn-sm dm-import" data-id="${esc(x.id)}" type="button">Import</button>
           <button class="btn btn-sm btn-danger dm-delete" data-id="${esc(x.id)}" data-domain="${esc(x.domain)}" data-managed="0" type="button">Delete</button>`;
      return `
      <tr>
        <td><b>${esc(x.domain)}</b></td>
        <td class="mono">${esc(x.ip)}</td>
        <td class="mono">${x.port ? esc(x.port) : "—"}</td>
        <td class="muted">${esc(x.note || "")}</td>
        <td><div class="wg-actions">${actions}</div></td>
      </tr>`;
    }).join("") || '<tr><td colspan="5" class="empty">No local domains yet. Add one above.</td></tr>';

    els.dmImportAll.hidden = !domains.some((x) => x.managed === false);
  }

  async function refreshDomains() {
    try {
      const data = await fetchJSON("/api/domains");
      renderDomains(data);
    } catch (err) {
      showBanner(true, "Domains error: " + err.message);
    }
  }

  function bindDomainActions() {
    els.dmAdd.addEventListener("click", async () => {
      const importing = !!state.domEditSource;
      const payload = {
        domain: els.dmDomain.value.trim(),
        ip: els.dmIp.value.trim(),
        port: els.dmPort.value.trim(),
        note: els.dmNote.value.trim(),
      };
      if (state.domEditId && !importing) payload.id = state.domEditId;
      if (!payload.domain || !payload.ip) {
        els.dmHint.textContent = "Enter a domain and an IP address.";
        return;
      }
      els.dmAdd.disabled = true;
      try {
        const data = await postJSON(
          importing ? "/api/domains/import"
            : (state.domEditId ? "/api/domains/update" : "/api/domains/add"),
          payload
        );
        resetDomainForm();
        renderDomains(data);
      } catch (err) {
        els.dmHint.textContent = "Error: " + err.message;
      } finally {
        els.dmAdd.disabled = false;
      }
    });

    [els.dmDomain, els.dmIp, els.dmPort, els.dmNote].forEach((input) => {
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") els.dmAdd.click();
      });
    });

    els.dmCancel.addEventListener("click", resetDomainForm);

    els.dmImportAll.addEventListener("click", async () => {
      if (!window.confirm("Import all existing records into the tuxwall-managed list?")) return;
      els.dmImportAll.disabled = true;
      try {
        const data = await postJSON("/api/domains/import-all", {});
        renderDomains(data);
      } catch (err) {
        showBanner(true, "Import all: " + err.message);
      } finally {
        els.dmImportAll.disabled = false;
      }
    });

    els.dmBody.addEventListener("click", async (e) => {
      const edit = e.target.closest(".dm-edit");
      const imp = e.target.closest(".dm-import");
      const del = e.target.closest(".dm-delete");
      if (edit) {
        const entry = state.domains.find((x) => x.id === edit.dataset.id);
        if (!entry) return;
        state.domEditId = entry.id;
        state.domEditSource = null;
        els.dmDomain.value = entry.domain;
        els.dmIp.value = entry.ip;
        els.dmPort.value = entry.port || "";
        els.dmNote.value = entry.note || "";
        els.dmAdd.textContent = "Save Changes";
        els.dmCancel.hidden = false;
        els.dmHint.textContent = "";
        els.dmDomain.focus();
        return;
      }
      if (imp) {
        const entry = state.domains.find((x) => x.id === imp.dataset.id);
        if (!entry) return;
        state.domEditSource = entry;
        state.domEditId = null;
        els.dmDomain.value = entry.domain;
        els.dmIp.value = entry.ip;
        els.dmPort.value = entry.port || "";
        els.dmNote.value = entry.note || "";
        els.dmAdd.textContent = "Import Domain";
        els.dmCancel.hidden = false;
        els.dmHint.textContent = "This record will move into the tuxwall-managed list so you can edit it later.";
        els.dmDomain.focus();
        return;
      }
      if (del) {
        const managed = del.dataset.managed === "1";
        const msg = managed
          ? `Delete local domain "${del.dataset.domain}"? It will stop resolving on your LAN.`
          : `Delete local domain "${del.dataset.domain}"? It will be removed from your unbound config file.`;
        if (!window.confirm(msg)) return;
        del.disabled = true;
        try {
          const data = await postJSON("/api/domains/delete", { id: del.dataset.id });
          if (state.domEditId === del.dataset.id || (state.domEditSource && state.domEditSource.id === del.dataset.id)) resetDomainForm();
          renderDomains(data);
        } catch (err) {
          showBanner(true, "Delete domain: " + err.message);
        }
      }
    });
  }

  function renderFirewall(d) {
    if (!d.ok) {
      showBanner(true, d.error || "Firewall stats unavailable");
      return;
    }
    els.fwStatus.textContent = d.status ? d.status[0].toUpperCase() + d.status.slice(1) : "—";
    els.fwIncoming.textContent = d.defaults.incoming || "—";
    els.fwOutgoing.textContent = d.defaults.outgoing || "—";
    els.fwRules.textContent = formatNumber(d.rules.length);
    els.fwBlocks.textContent = formatNumber(d.traffic.block);
    els.fwAllows.textContent = formatNumber(d.traffic.allow);
    els.fwLogging.textContent = (d.logging || "").replace(/^on\s*/i, "") || "—";

    els.fwRulesBody.innerHTML = (d.rules || []).map((r) => `
      <tr>
        <td class="mono">${esc(r.to)}</td>
        <td><span class="badge ${r.action.startsWith("ALLOW") ? "badge-ok" : "badge-err"}">${esc(r.action)}</span></td>
        <td>${esc(r.from)}</td>
        <td>${r.number ? `<button class="btn btn-sm btn-danger fw-remove" type="button" data-num="${r.number}">Remove</button>` : ""}</td>
      </tr>`).join("");

    const srcMax = (d.traffic.top_sources && d.traffic.top_sources[0])
      ? d.traffic.top_sources[0].count : 1;
    els.fwSourcesBody.innerHTML = (d.traffic.top_sources || []).map((s) => `
      <tr>
        <td class="mono">${esc(s.ip)}</td>
        <td>${formatNumber(s.count)}</td>
        <td><div class="bar"><div class="bar-fill bar-fill-err" style="width:${Math.round(s.count / srcMax * 100)}%"></div></div></td>
      </tr>`).join("");

    const portMax = (d.traffic.top_ports && d.traffic.top_ports[0])
      ? d.traffic.top_ports[0].count : 1;
    els.fwPortsBody.innerHTML = (d.traffic.top_ports || []).map((p) => `
      <tr>
        <td class="mono">${esc(p.port)}</td>
        <td>${formatNumber(p.count)}</td>
        <td><div class="bar"><div class="bar-fill bar-fill-err" style="width:${Math.round(p.count / portMax * 100)}%"></div></div></td>
      </tr>`).join("");

    els.fwEventsBody.innerHTML = (d.traffic.recent || []).map((e) => `
      <tr>
        <td class="mono">${esc(e.ts.split("T")[1]?.slice(0, 8) || e.ts)}</td>
        <td><span class="badge ${e.action === "BLOCK" ? "badge-err" : "badge-ok"}">${esc(e.action)}</span></td>
        <td class="mono">${esc(e.in || e.out || "—")}</td>
        <td class="mono">${esc(e.src)}</td>
        <td class="mono">${esc(e.dst)}</td>
        <td class="mono">${esc(e.dpt ? e.dpt + "/" + e.proto : e.proto || "—")}</td>
      </tr>`).join("");
  }

  async function refreshFirewall() {
    try {
      const data = await fetchJSON("/api/firewall");
      renderFirewall(data);
    } catch (err) {
      showBanner(true, "Firewall stats error: " + err.message);
    }
  }

  function bindFirewallActions() {
    async function refreshInterfaces() {
      try {
        const data = await fetchJSON("/api/firewall/interfaces");
        if (!data.ok) return;
        const sel = els.fwIface;
        const current = sel.value;
        sel.innerHTML = '<option value="">any interface</option>' + (data.interfaces || []).map((i) =>
          `<option value="${esc(i.name)}">${esc(i.name)}${i.up ? "" : " (down)"}</option>`
        ).join("");
        if (current) sel.value = current;
      } catch (err) {
        /* leave the empty option */
      }
    }
    function buildRuleFromForm() {
      const action = els.fwAction.value;
      const direction = els.fwDirection.value;
      const iface = els.fwIface.value;
      const from = els.fwFrom.value.trim();
      const family = els.fwFamily.value;
      const proto = els.fwProto.value;
      const port = els.fwPort.value.trim();

      const parts = [action, direction];
      if (iface) parts.push("on", iface);
      let source = from;
      if (!source) {
        if (family === "v4") source = "0.0.0.0/0";
        else if (family === "v6") source = "::/0";
        else source = "any";
      }
      parts.push("from", source);
      if (port) {
        parts.push("to", "any", "port", port);
        if (proto === "tcp" || proto === "udp") parts.push("proto", proto);
      } else if (!iface && !from) {
        throw new Error("Enter an interface, source, or port");
      }
      return parts.join(" ");
    }

    async function addRule(rule) {
      els.fwHint.textContent = "";
      try {
        await postJSON("/api/firewall/allow", { rule });
        els.fwHint.textContent = "Rule added: " + rule;
        await refreshFirewall();
      } catch (err) {
        els.fwHint.textContent = "Error: " + err.message;
        throw err;
      }
    }

    els.fwAdd.addEventListener("click", async () => {
      let rule;
      try {
        rule = buildRuleFromForm();
      } catch (err) {
        els.fwHint.textContent = err.message;
        return;
      }
      els.fwAdd.disabled = true;
      try {
        await addRule(rule);
      } finally {
        els.fwAdd.disabled = false;
      }
    });

    els.fwPort.addEventListener("keydown", (e) => {
      if (e.key === "Enter") els.fwAdd.click();
    });

    els.fwAddCustom.addEventListener("click", async () => {
      const rule = els.fwRule.value.trim();
      if (!rule) return;
      els.fwAddCustom.disabled = true;
      try {
        await addRule(rule);
        els.fwRule.value = "";
      } finally {
        els.fwAddCustom.disabled = false;
      }
    });

    els.fwRule.addEventListener("keydown", (e) => {
      if (e.key === "Enter") els.fwAddCustom.click();
    });

    els.fwRulesBody.addEventListener("click", async (e) => {
      const btn = e.target.closest(".fw-remove");
      if (!btn) return;
      if (!window.confirm("Remove this firewall rule?")) return;
      btn.disabled = true;
      try {
        await postJSON("/api/firewall/delete", { number: btn.dataset.num });
        els.fwHint.textContent = "Rule removed.";
        await refreshFirewall();
      } catch (err) {
        els.fwHint.textContent = "Error: " + err.message;
        btn.disabled = false;
      }
    });

    async function firewallOp(payload) {
      els.fwHint.textContent = "Working…";
      const res = await postJSON("/api/firewall/reset", payload);
      if (!res.ok) throw new Error(res.error || "request failed");
      els.fwHint.textContent = (res.cleared ? "All rules flushed, " : "") +
        "baseline restored" +
        (res.baseline_created ? " (baseline captured from current settings)" : "") +
        (res.verified ? "" : " — live rules differ from baseline, verify manually");
      await refreshFirewall();
      return res;
    }

    els.fwBaseline.addEventListener("click", async () => {
      if (!window.confirm("Save the current live ruleset as the restore baseline?")) return;
      els.fwBaseline.disabled = true;
      try {
        const res = await postJSON("/api/firewall/reset", { action: "save" });
        if (!res.ok) throw new Error(res.error || "request failed");
        els.fwHint.textContent = "Baseline saved.";
      } catch (err) {
        els.fwHint.textContent = "Error: " + err.message;
      } finally {
        els.fwBaseline.disabled = false;
      }
    });

    els.fwReset.addEventListener("click", async () => {
      if (!window.confirm(
        "Reset the firewall?\n\nThis flushes ALL iptables/ip6tables rules " +
        "(IPv4 + IPv6, filter/nat/mangle/raw) and restores the saved baseline. " +
        "A snapshot of the current rules is kept as a backup first. " +
        "Your SSH session and internet should survive, but use the LAN connection to be safe."
      )) return;
      els.fwReset.disabled = true;
      try {
        await firewallOp({ action: "reset", clear: true });
      } catch (err) {
        els.fwHint.textContent = "Error: " + err.message;
      } finally {
        els.fwReset.disabled = false;
      }
    });

    refreshInterfaces();
  }

  let secMap = null;
  let ovMap = null;
  const SVG_NS = "http://www.w3.org/2000/svg";
  const SEC_TARGET = { lat: 39.9526, lon: -75.1652 }; // Philadelphia - your router location
  const SEC_ARC_MAX = 40;

  // Arc colour tiers by hit count
  function arcTier(count) {
    if (count >= 100) return { stroke: "#ff3333", glow: "#ff0000", core: "#ffaaaa" };
    if (count >= 20)  return { stroke: "#ff7700", glow: "#ff5500", core: "#ffcc88" };
    if (count >= 5)   return { stroke: "#ffcc00", glow: "#ffaa00", core: "#fff0aa" };
    return                  { stroke: "#4488ff", glow: "#2266dd", core: "#aaccff" };
  }

  function createAttackMap(el, target) {
    if (!el || typeof L === "undefined") return null;
    const m = {
      map: L.map(el, { worldCopyJump: true, zoomControl: false }).setView([25, 0], 2),
      target,
      markers: null,
      svg: null,
      lastByIp: null,
      statsEl: null,
    };

    // Zoom control bottom-right
    L.control.zoom({ position: "bottomright" }).addTo(m.map);

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      maxZoom: 18,
      subdomains: "abcd",
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
    }).addTo(m.map);

    // Target marker — multi-ring shield
    L.marker([target.lat, target.lon], {
      icon: L.divIcon({
        className: "sec-target-wrap",
        html: `<div class="sec-target">
          <span class="sec-target-ring sec-target-ring-3"></span>
          <span class="sec-target-ring sec-target-ring-2"></span>
          <span class="sec-target-ring sec-target-ring-1"></span>
          <span class="sec-target-core"></span>
        </div>`,
        iconSize: [48, 48],
        iconAnchor: [24, 24],
      }),
      interactive: false,
      keyboard: false,
      zIndexOffset: 1000,
    }).addTo(m.map);

    // SVG arc layer
    m.svg = L.DomUtil.create("svg", "sec-arcs", el);

    // Vignette overlay
    const vig = document.createElement("div");
    vig.className = "sec-map-vignette";
    el.appendChild(vig);

    // Scanline overlay
    const scan = document.createElement("div");
    scan.className = "sec-map-scanlines";
    el.appendChild(scan);

    // HUD stats overlay
    m.statsEl = document.createElement("div");
    m.statsEl.className = "sec-map-hud";
    m.statsEl.innerHTML = `
      <div class="sec-hud-row"><span class="sec-hud-dot"></span><span class="sec-hud-label">THREAT MONITOR</span></div>
      <div class="sec-hud-stat"><span class="sec-hud-val" id="${el.id}-hud-attacks">—</span><span class="sec-hud-key">ATTACKS</span></div>
      <div class="sec-hud-stat"><span class="sec-hud-val" id="${el.id}-hud-sources">—</span><span class="sec-hud-key">SOURCES</span></div>
      <div class="sec-hud-stat"><span class="sec-hud-val" id="${el.id}-hud-top">—</span><span class="sec-hud-key">TOP COUNTRY</span></div>
    `;
    el.appendChild(m.statsEl);

    m.map.on("move zoom resize", () => drawAttackArcs(m));
    return m;
  }

  function arcControlPoint(a, b) {
    const dx = b.x - a.x, dy = b.y - a.y;
    const dist = Math.hypot(dx, dy) || 1;
    const k = Math.min(90, dist * 0.22);
    return { x: (a.x + b.x) / 2 - (dy / dist) * k, y: (a.y + b.y) / 2 + (dx / dist) * k };
  }

  function arcPathD(a, b) {
    const c = arcControlPoint(a, b);
    return `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} Q ${c.x.toFixed(1)} ${c.y.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
  }

  function bezierLength(a, b) {
    const c = arcControlPoint(a, b);
    const steps = 20;
    let len = 0, px = a.x, py = a.y;
    for (let i = 1; i <= steps; i++) {
      const t = i / steps, mt = 1 - t;
      const x = mt * mt * a.x + 2 * mt * t * c.x + t * t * b.x;
      const y = mt * mt * a.y + 2 * mt * t * c.y + t * t * b.y;
      len += Math.hypot(x - px, y - py);
      px = x; py = y;
    }
    return Math.max(1, len);
  }

  function buildAttackPulses(m, byIp) {
    if (!m) return;
    if (!m.markers) m.markers = L.layerGroup().addTo(m.map);
    m.markers.clearLayers();
    for (const ip of byIp) {
      if (ip.lat == null || ip.lon == null) continue;
      const tier = arcTier(ip.count);
      const size = Math.min(32, 12 + 8 * Math.log10(Math.max(1, ip.count)));
      const marker = L.marker([ip.lat, ip.lon], {
        icon: L.divIcon({
          className: "sec-pulse-wrap",
          html: `<span class="sec-pulse" style="width:${size}px;height:${size}px;--pulse-color:${tier.glow}"></span>`,
          iconSize: [size, size],
          iconAnchor: [size / 2, size / 2],
        }),
        keyboard: false,
      });
      marker.bindPopup(
        `<div class="sec-popup">` +
        `<div class="sec-popup-ip">${esc(ip.ip)}</div>` +
        `<div class="sec-popup-loc">${esc(ip.country || "Unknown")}${ip.city ? " · " + esc(ip.city) : ""}</div>` +
        `<div class="sec-popup-hits"><b>${formatNumber(ip.count)}</b> hits · port <span class="mono">${esc(ip.port || "?")}</span></div>` +
        `<div class="sec-popup-time">Last seen ${formatRelative(ip.last)}</div>` +
        `</div>`
      );
      marker.addTo(m.markers);
    }
  }

  function drawAttackArcs(m) {
    if (!m || !m.map || !m.svg || !m.lastByIp) return;
    const el = m.map.getContainer();
    const w = el.clientWidth, h = el.clientHeight;
    m.svg.setAttribute("width", w);
    m.svg.setAttribute("height", h);
    m.svg.innerHTML = "";
    if (w < 10 || h < 10) return;

    const tgt = m.map.latLngToContainerPoint([m.target.lat, m.target.lon]);
    const recent = m.lastByIp
      .filter((i) => i.lat != null && i.lon != null)
      .slice(0, SEC_ARC_MAX);

    // SVG defs for gradients
    const defs = document.createElementNS(SVG_NS, "defs");
    m.svg.appendChild(defs);

    recent.forEach((ip, idx) => {
      const src = m.map.latLngToContainerPoint([ip.lat, ip.lon]);
      const d = arcPathD(src, tgt);
      const len = bezierLength(src, tgt);
      if (len < 20) return;
      const tier = arcTier(ip.count);
      const gid = `arc-grad-${idx}`;

      // Gradient: source colour → bright white-ish at target
      const grad = document.createElementNS(SVG_NS, "linearGradient");
      grad.setAttribute("id", gid);
      grad.setAttribute("gradientUnits", "userSpaceOnUse");
      grad.setAttribute("x1", src.x); grad.setAttribute("y1", src.y);
      grad.setAttribute("x2", tgt.x); grad.setAttribute("y2", tgt.y);
      const s1 = document.createElementNS(SVG_NS, "stop");
      s1.setAttribute("offset", "0%"); s1.setAttribute("stop-color", tier.stroke); s1.setAttribute("stop-opacity", "0.15");
      const s2 = document.createElementNS(SVG_NS, "stop");
      s2.setAttribute("offset", "60%"); s2.setAttribute("stop-color", tier.stroke); s2.setAttribute("stop-opacity", "0.7");
      const s3 = document.createElementNS(SVG_NS, "stop");
      s3.setAttribute("offset", "100%"); s3.setAttribute("stop-color", tier.core); s3.setAttribute("stop-opacity", "0.95");
      grad.appendChild(s1); grad.appendChild(s2); grad.appendChild(s3);
      defs.appendChild(grad);

      const baseW = Math.min(5, 1.5 + Math.log10(Math.max(1, ip.count)));

      // Layer 1: wide outer glow
      const outerGlow = document.createElementNS(SVG_NS, "path");
      outerGlow.setAttribute("d", d);
      outerGlow.setAttribute("fill", "none");
      outerGlow.setAttribute("stroke", tier.glow);
      outerGlow.setAttribute("stroke-width", baseW * 4);
      outerGlow.setAttribute("stroke-opacity", "0.08");
      outerGlow.setAttribute("stroke-linecap", "round");
      m.svg.appendChild(outerGlow);

      // Layer 2: mid glow
      const midGlow = document.createElementNS(SVG_NS, "path");
      midGlow.setAttribute("d", d);
      midGlow.setAttribute("fill", "none");
      midGlow.setAttribute("stroke", `url(#${gid})`);
      midGlow.setAttribute("stroke-width", baseW * 1.8);
      midGlow.setAttribute("stroke-opacity", "0.4");
      midGlow.setAttribute("stroke-linecap", "round");
      m.svg.appendChild(midGlow);

      // Layer 3: animated bright head
      const head = document.createElementNS(SVG_NS, "path");
      head.setAttribute("d", d);
      head.setAttribute("fill", "none");
      head.setAttribute("stroke", `url(#${gid})`);
      head.setAttribute("stroke-width", baseW);
      head.setAttribute("stroke-linecap", "round");
      const dash = Math.min(18, 5 + Math.log2(Math.max(1, ip.count)));
      head.style.strokeDasharray = `${dash} ${Math.max(1, len - dash)}`;
      head.style.setProperty("--len", `-${len.toFixed(1)}`);
      head.style.animationName = "sec-arc-fly";
      head.style.animationTimingFunction = "linear";
      head.style.animationIterationCount = "infinite";
      head.style.animationDuration = `${Math.max(300, Math.min(1200, len / 55)).toFixed(0)}ms`;
      head.style.animationDelay = `${(Math.random() * 1500).toFixed(0)}ms`;
      m.svg.appendChild(head);
    });

    // Update HUD stats
    if (m.statsEl) {
      const totalHits = m.lastByIp.reduce((s, i) => s + (i.count || 0), 0);
      const sources = m.lastByIp.filter((i) => i.lat != null).length;
      const topCountry = m.lastByIp[0]?.country || "—";
      const hudId = el.id;
      const hA = document.getElementById(`${hudId}-hud-attacks`);
      const hS = document.getElementById(`${hudId}-hud-sources`);
      const hT = document.getElementById(`${hudId}-hud-top`);
      if (hA) hA.textContent = formatNumber(totalHits);
      if (hS) hS.textContent = sources;
      if (hT) hT.textContent = topCountry;
    }
  }

  function renderAttackMap(m, byIp) {
    if (!m) return;
    m.lastByIp = byIp || [];
    buildAttackPulses(m, m.lastByIp);
    drawAttackArcs(m);
  }

  function initSecurityMap() {
    const el = document.getElementById("sec-map");
    if (!el || secMap) return;
    secMap = createAttackMap(el, SEC_TARGET);
  }

  function initOverviewMap() {
    const el = document.getElementById("ov-map");
    if (!el || ovMap) return;
    ovMap = createAttackMap(el, SEC_TARGET);
  }

  function drawSecurityChart(canvas, series) {
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width, h = rect.height;
    ctx.clearRect(0, 0, w, h);
    const padT = 8, padB = 16;
    const ph = h - padT - padB;
    const n = series.length;
    if (n < 2) {
      ctx.fillStyle = cssVar("--muted", "#8b949e");
      ctx.font = "11px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("Collecting samples…", w / 2, h / 2);
      return;
    }
    const max = Math.max(1, ...series.map((s) => s[1]));
    const bw = Math.max(1, w / n - 1);
    const hmRed = cssVar("--red", "#f85149");
    const hmBlue = cssVar("--accent", "#4f8cff");
    const hmZero = hexToRgba(cssVar("--muted", "#8b949e"), 0.15);
    for (let i = 0; i < n; i++) {
      const x = (w * i) / n;
      const val = series[i][1];
      const bh = val > 0 ? Math.max(1, Math.round((val / max) * ph)) : 0;
      ctx.fillStyle = val ? (i === n - 1 ? hexToRgba(hmRed, 0.9) : hexToRgba(hmBlue, 0.7)) : hmZero;
      ctx.fillRect(x, padT + ph - bh, bw, bh);
    }
    ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.9);
    ctx.font = "10px sans-serif";
    ctx.textAlign = "center";
    const steps = Math.min(6, n);
    for (let i = 0; i < steps; i++) {
      const idx = Math.round((i * (n - 1)) / (steps - 1));
      const t = new Date(series[idx][0] * 1000);
      const label = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}:${String(t.getSeconds()).padStart(2, "0")}`;
      ctx.fillText(label, (w * idx) / (n - 1) + bw / 2, padT + ph + 12);
    }
  }

  function renderSecurity(d) {
    if (!d.ok) {
      showBanner(true, d.error || "Security stats unavailable");
      return;
    }
    const st = d.stats || {};
    els.secHits.textContent = formatNumber(st.hits);
    els.secIps.textContent = formatNumber(st.unique_ips);
    els.secCountries.textContent = formatNumber(st.countries);
    els.secRate.textContent = st.hits_1m != null ? `${formatNumber(st.hits_1m)} / min` : "—";
    els.secGeoHint.textContent = d.geo_db.hint || `${formatNumber(st.unique_ips)} sources · last hit ${formatRelative(st.last_event)}`;

    renderAttackMap(secMap, d.by_ip || []);

    const countries = d.countries || [];
    const cMax = countries[0] ? countries[0].count : 1;
    const buildCountryRow = (c) => `
      <tr>
        <td>${flagEmoji(c.iso)} ${esc(c.name)}</td>
        <td>${formatNumber(c.count)}</td>
        <td><div class="bar"><div class="bar-fill bar-fill-err" style="width:${Math.round(c.count / cMax * 100)}%"></div></div></td>
      </tr>`;
    els.secCountriesBody.innerHTML = countries.slice(0, 25).map(buildCountryRow).join("");
    const cMoreWrap = document.getElementById("sec-countries-more-wrap");
    cMoreWrap.hidden = countries.length <= 25;
    if (!cMoreWrap.hidden) {
      document.getElementById("sec-countries-more").onclick = () => {
        document.getElementById("sec-countries-full-body").innerHTML = countries.map(buildCountryRow).join("");
        document.getElementById("sec-countries-modal").hidden = false;
      };
    }

    const byIp = d.by_ip || [];
    const ipMax = byIp[0] ? byIp[0].count : 1;
    const csUp = state.secCrowdsecUp;
    const buildIpRow = (i) => `
      <tr>
        <td class="mono"><a href="https://www.abuseipdb.com/check/${esc(i.ip)}" target="_blank" rel="noopener">${esc(i.ip)}</a></td>
        <td>${esc(i.country || "Unknown")}${i.city ? ` <span class="muted">· ${esc(i.city)}</span>` : ""}</td>
        <td>${formatNumber(i.count)}</td>
        <td><div class="bar"><div class="bar-fill bar-fill-err" style="width:${Math.round(i.count / ipMax * 100)}%"></div></div></td>
        <td>${csUp ? (state.secBannedIps.has(i.ip)
          ? `<button type="button" class="btn btn-sm sec-unban" data-ip="${esc(i.ip)}">Unban</button>`
          : `<button type="button" class="btn btn-sm btn-danger sec-ban" data-ip="${esc(i.ip)}">Ban</button>`)
          : ""}</td>
      </tr>`;
    els.secIpsBody.innerHTML = byIp.slice(0, 25).map(buildIpRow).join("");
    const ipMoreWrap = document.getElementById("sec-ips-more-wrap");
    ipMoreWrap.hidden = byIp.length <= 25;
    if (!ipMoreWrap.hidden) {
      document.getElementById("sec-ips-more").onclick = () => {
        document.getElementById("sec-ips-full-body").innerHTML = byIp.map(buildIpRow).join("");
        document.getElementById("sec-ips-modal").hidden = false;
      };
    }

    els.secEventsBody.innerHTML = (d.events || []).map((e) => `
      <tr>
        <td class="mono">${formatTime(e.ts)}</td>
        <td class="mono">${esc(e.src)}</td>
        <td>${flagEmoji(e.iso)} ${esc(e.country || "Unknown")}</td>
        <td class="mono">${esc(e.dst)}</td>
        <td class="mono">${esc(e.port)}</td>
      </tr>`).join("");
    els.secEventCount.textContent = `${(d.events || []).length} shown`;

    requestAnimationFrame(() => {
      drawSecurityChart(els.secChart, d.series || []);
    });
  }

  async function refreshSecurity() {
    try {
      const data = await fetchJSON("/api/security");
      renderSecurity(data);
    } catch (err) {
      showBanner(true, "Security stats error: " + err.message);
    }
  }

  function renderSuricata(d) {
    if (!d.ok) {
      showBanner(true, d.error || "Suricata data unavailable");
      return;
    }
    if (!d.enabled) {
      els.secSuricataHint.textContent = "not running";
      els.secSuricataBody.innerHTML =
        `<tr><td colspan="5" class="empty">${esc(d.hint || "Suricata not available.")}</td></tr>`;
      return;
    }
    const alerts = d.alerts || [];
    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    alerts.forEach((a) => { if (counts[a.severity] != null) counts[a.severity]++; });
    const sev = counts[state.suricataSev] != null ? state.suricataSev : "HIGH";
    state.suricataSev = sev;
    els.secSuricataTabs.querySelectorAll(".seg-btn").forEach((b) => {
      const key = (b.dataset.sev || "").toLowerCase();
      b.classList.toggle("active", b.dataset.sev === sev);
      const c = b.querySelector(".seg-count");
      if (c && counts[b.dataset.sev] != null) c.textContent = formatNumber(counts[b.dataset.sev]);
    });
    els.secSuricataHint.textContent = `${formatNumber(d.count_24h)} alerts in last 24h`;
    const shown = alerts.filter((a) => a.severity === sev);
    els.secSuricataBody.innerHTML = shown.map((a) => `
      <tr>
        <td class="mono">${formatTime(a.ts)}</td>
        <td><b>${esc(a.sig)}</b></td>
        <td><span class="badge sev-${esc(a.severity)}">${esc(a.severity)}</span></td>
        <td class="mono">${esc(a.src)}${a.sport ? ":" + esc(a.sport) : ""}</td>
        <td class="mono">${esc(a.dst)}${a.dport ? ":" + esc(a.dport) : ""}</td>
      </tr>`).join("")
      || `<tr><td colspan="5" class="empty">No ${esc(sev)} alerts in the last 24h.</td></tr>`;
  }

  async function refreshSuricata() {
    try {
      const data = await fetchJSON("/api/security/suricata");
      renderSuricata(data);
    } catch (err) {
      showBanner(true, "Suricata error: " + err.message);
    }
  }

  function renderAiSummary(d) {
    if (!d.ok) {
      if (d.error === "not_configured") {
        els.secAiSummary.innerHTML = `<span class="muted">${esc(d.hint || "AI summaries not configured.")}</span>`;
      } else {
        els.secAiSummary.innerHTML = `<span class="text-err">Error: ${esc(d.error)}${d.detail ? " \u2014 " + esc(d.detail) : ""}</span>`;
      }
      return;
    }
    const lines = (d.summary || "").trim().split("\n");
    let html = "";
    let inCmd = false;
    lines.forEach((l) => {
      let t = l.trim().replace(/\*\*/g, "").replace(/^#{1,3}\s*/, "").replace(/`/g, "").replace(/^\*\s*/, "").trim();
      if (!t) return;
      if (/^(bash|sh|shell|zsh)$/i.test(t)) return;
      if (/^```|^~~~/.test(t)) {
        inCmd = !inCmd;
        if (inCmd) html += '<pre class="ai-cmd">';
        else html += "</pre>";
        return;
      }
      const isCmd = /^(ufw |sudo |nft |iptables |cscli |systemctl )/.test(t);
      if (/^commands:?$/i.test(t)) {
        html += '<div class="ai-cmd-label">Commands:</div>';
        return;
      }
      if (isCmd) {
        if (!inCmd) { html += '<pre class="ai-cmd">'; inCmd = true; }
        html += esc(t) + "\n";
        return;
      }
      if (inCmd) { html += "</pre>"; inCmd = false; }
      if (/^\d+[.)]/.test(t)) {
        t = t.replace(/^\d+[.)]\s*/, "");
        html += `<div class="ai-li">${esc(t)}</div>`;
      } else if (/^[-*\u2022]/.test(t)) {
        html += `<div class="ai-li">${esc(t.replace(/^[-*\u2022]\s*/, ""))}</div>`;
      } else if (/^top action:/i.test(t)) {
        html += `<div class="ai-top">${esc(t)}</div>`;
      } else {
        html += `<div>${esc(t)}</div>`;
      }
    });
    if (inCmd) html += "</pre>";
    const cmds = d.commands || [];
    if (cmds.length) {
      html += '<div class="ai-cmd-label">Commands:</div><pre class="ai-cmd">'
        + cmds.map((c) => esc(c)).join("\n")
        + "</pre>";
    }
    els.secAiSummary.innerHTML = html;
    els.secAiStatus.textContent = (d.model || "") + " \u00b7 Generated " + formatRelative(d.generated_at);
  }

  function populateAiModelSelect(models, configured) {
    const sel = els.secAiModel;
    sel.innerHTML = "";
    const list = models.slice();
    if (configured && list.indexOf(configured) === -1) list.unshift(configured);
    if (!list.length) {
      const o = document.createElement("option");
      o.value = "";
      o.textContent = configured || "no models";
      sel.appendChild(o);
      return;
    }
    list.forEach((m) => {
      const o = document.createElement("option");
      o.value = m;
      o.textContent = m;
      if (m === configured) o.selected = true;
      sel.appendChild(o);
    });
  }



  function openAiCfgModal() {
    els.aiCfgHint.textContent = "";
    els.aiCfgHint.className = "muted cfg-hint";
    els.aiCfgApiKey.value = "";
    els.aiCfgModal.hidden = false;
    els.aiCfgSave.disabled = false;
    fetchJSON("/api/security/ai-config").then((data) => {
      if (!data.ok) throw new Error(data.error || "load failed");
      els.aiCfgBaseUrl.value = data.base_url || "";
      els.aiCfgModel.value = data.model || "";
      els.aiCfgApiKey.placeholder = data.api_key_masked || "sk-...";
      // Auto-highlight the matching preset
      const url = (data.base_url || "").toLowerCase();
      let matched = null;
      if (url.includes("anthropic.com")) matched = "claude";
      else if (url.includes("openai.com")) matched = "openai";
      else if (url.includes("localhost") || url.includes("127.0.0.1")) matched = "ollama";
      else if (url) matched = "custom";
      if (matched) applyAiPreset(matched);
      // Restore actual values after preset fill
      els.aiCfgBaseUrl.value = data.base_url || "";
      els.aiCfgModel.value = data.model || "";
    }).catch((err) => {
      els.aiCfgHint.className = "muted cfg-hint cfg-hint-err";
      els.aiCfgHint.textContent = err.message;
    });
  }

  function closeAiCfgModal() {
    els.aiCfgModal.hidden = true;
  }

  async function saveAiCfg() {
    const base_url = els.aiCfgBaseUrl.value.trim();
    const model = els.aiCfgModel.value.trim();
    const api_key = els.aiCfgApiKey.value;
    if (!base_url) { els.aiCfgHint.className = "muted cfg-hint cfg-hint-err"; els.aiCfgHint.textContent = "Base URL is required."; return; }
    if (!model) { els.aiCfgHint.className = "muted cfg-hint cfg-hint-err"; els.aiCfgHint.textContent = "Model is required."; return; }
    els.aiCfgSave.disabled = true;
    try {
      const body = { base_url, model };
      if (api_key) body.api_key = api_key;
      const data = await postJSON("/api/security/ai-config", body);
      els.aiCfgHint.className = "muted cfg-hint cfg-hint-ok";
      els.aiCfgHint.textContent = "Saved." + (data.backup ? " Backup: " + data.backup : "");
      refreshAiModels();
      // Also reload the AI page model selector
      const aiSel = document.getElementById("ai-model-select");
      if (aiSel) { delete aiSel.dataset.loaded; }
      loadAiPageConfig();
      setTimeout(closeAiCfgModal, 900);
    } catch (err) {
      els.aiCfgSave.disabled = false;
      els.aiCfgHint.className = "muted cfg-hint cfg-hint-err";
      els.aiCfgHint.textContent = err.message;
    }
  }

  function loadAiPageConfig() {
    const sel     = document.getElementById("ai-model-select");
    const notCfg  = document.getElementById("ai-not-configured");
    if (!sel) return;
    fetchJSON("/api/security/ai-config").then((d) => {
      if (!d.ok) { if (notCfg) notCfg.hidden = false; return; }
      const hasKey  = !!(d.api_key_masked && d.api_key_masked !== "");
      const isLocal = /localhost|127\.0\.0\.1/.test(d.base_url || "");
      if (!hasKey && !isLocal) { if (notCfg) notCfg.hidden = false; return; }
      if (notCfg) notCfg.hidden = true;
      // Build model list from preset matching the base_url
      const url = (d.base_url || "").toLowerCase();
      let preset = null;
      if (url.includes("anthropic.com")) preset = "claude";
      else if (url.includes("openai.com")) preset = "openai";
      else if (isLocal) preset = "ollama";
      const presetModels = preset && AI_PRESETS[preset] ? AI_PRESETS[preset].models : [];
      // Always include the currently configured model
      const configured = d.model || "";
      const modelList = configured && !presetModels.includes(configured)
        ? [configured, ...presetModels]
        : (presetModels.length ? presetModels : [configured]);
      sel.innerHTML = modelList.filter(Boolean).map((m) =>
        `<option value="${esc(m)}"${m === configured ? " selected" : ""}>${esc(m)}</option>`
      ).join("") || `<option value="${esc(configured)}">${esc(configured) || "unknown"}</option>`;
    }).catch(() => { if (notCfg) notCfg.hidden = false; });
  }

  const AI_PRESETS = {
    claude: {
      base_url: "https://api.anthropic.com/v1",
      models: ["claude-opus-4-5", "claude-sonnet-4-5", "claude-haiku-3-5"],
      default_model: "claude-sonnet-4-5",
      hint: "Get your API key at console.anthropic.com → API Keys",
      key_placeholder: "sk-ant-api03-…",
    },
    openai: {
      base_url: "https://api.openai.com/v1",
      models: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
      default_model: "gpt-4o",
      hint: "Get your API key at platform.openai.com → API Keys",
      key_placeholder: "sk-…",
    },
    ollama: {
      base_url: "http://localhost:11434/v1",
      models: [],
      default_model: "",
      hint: "Ollama runs locally — no API key needed. Make sure Ollama is running and you have a model pulled (e.g. ollama pull llama3).",
      key_placeholder: "Not required for local Ollama",
    },
    custom: {
      base_url: "",
      models: [],
      default_model: "",
      hint: "Enter the base URL of any OpenAI-compatible API endpoint.",
      key_placeholder: "API key (if required)",
    },
  };

  function applyAiPreset(preset) {
    const p = AI_PRESETS[preset];
    if (!p) return;
    els.aiCfgBaseUrl.value = p.base_url;
    if (p.default_model) els.aiCfgModel.value = p.default_model;
    els.aiCfgApiKey.placeholder = p.key_placeholder;
    const hintEl = document.getElementById("ai-preset-hint");
    if (hintEl) hintEl.textContent = p.hint;
    // Render model suggestion chips
    const chips = document.getElementById("ai-model-suggestions");
    if (chips) {
      chips.innerHTML = p.models.map((m) =>
        `<button type="button" class="ai-model-chip" data-model="${esc(m)}">${esc(m)}</button>`
      ).join("");
      chips.querySelectorAll(".ai-model-chip").forEach((btn) => {
        btn.addEventListener("click", () => {
          els.aiCfgModel.value = btn.dataset.model;
          chips.querySelectorAll(".ai-model-chip").forEach((b) => b.classList.remove("active"));
          btn.classList.add("active");
        });
      });
      // Mark default as active
      const def = chips.querySelector(`[data-model="${esc(p.default_model)}"]`);
      if (def) def.classList.add("active");
    }
    // Highlight active preset button
    document.querySelectorAll(".ai-preset-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.preset === preset);
    });
  }

  function bindAiSummary() {
    // AI configure buttons (AI page sidebar + not-configured banner)
    const aiConfigureBtn = document.getElementById("ai-configure-btn");
    if (aiConfigureBtn) aiConfigureBtn.addEventListener("click", openAiCfgModal);
    const aiNotCfgBtn = document.getElementById("ai-not-cfg-btn");
    if (aiNotCfgBtn) aiNotCfgBtn.addEventListener("click", openAiCfgModal);
    // Config modal controls
    els.aiCfgModalClose.addEventListener("click", closeAiCfgModal);
    els.aiCfgCancel.addEventListener("click", closeAiCfgModal);
    els.aiCfgSave.addEventListener("click", saveAiCfg);
    els.aiCfgModal.addEventListener("click", (e) => {
      if (e.target === els.aiCfgModal) closeAiCfgModal();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !els.aiCfgModal.hidden) closeAiCfgModal();
    });
    // Preset buttons
    document.querySelectorAll(".ai-preset-btn").forEach((btn) => {
      btn.addEventListener("click", () => applyAiPreset(btn.dataset.preset));
    });
  }

  function setSecBanStatus(text) {
    els.secBanStatus.textContent = text || "";
  }

  async function banCrowdsec(ip) {
    const data = await postJSON("/api/crowdsec/blocklist/add", { entry: ip });
    if (!data.ok) throw new Error(data.error || "Ban failed");
    return data;
  }

  async function unbanCrowdsec(ip) {
    const data = await postJSON("/api/crowdsec/blocklist/remove", { entry: ip });
    if (!data.ok) throw new Error(data.error || "Unban failed");
    return data;
  }

  async function updateSecBanAvailability() {
    try {
      const data = await fetchJSON("/api/crowdsec");
      state.secCrowdsecUp = !!data.ok;
    } catch (err) {
      state.secCrowdsecUp = false;
    }
    try {
      const bl = await fetchJSON("/api/crowdsec/blocklist");
      state.secBannedIps = new Set((bl.entries || []).map((e) => e.value));
    } catch (err) {
      state.secBannedIps = new Set();
    }
    const up = state.secCrowdsecUp;
    els.secBanAll.disabled = !up;
    if (!up) setSecBanStatus("CrowdSec unavailable");
    if (els.secIpsBody.rows.length) refreshSecurity();
  }

  function bindSecurityBans() {
    els.secIpsBody.addEventListener("click", async (e) => {
      const banBtn = e.target.closest(".sec-ban");
      const unbanBtn = e.target.closest(".sec-unban");
      const btn = banBtn || unbanBtn;
      if (!btn) return;
      const ip = btn.dataset.ip;
      btn.disabled = true;
      try {
        if (unbanBtn) {
          await unbanCrowdsec(ip);
          setSecBanStatus(`Removed ${ip} from the custom blocklist.`);
        } else {
          await banCrowdsec(ip);
          setSecBanStatus(`Added ${ip} to the custom blocklist (1y ban).`);
        }
        await updateSecBanAvailability();
      } catch (err) {
        setSecBanStatus(`Failed: ${err.message}`);
      } finally {
        btn.disabled = false;
      }
    });

    els.secBanAll.addEventListener("click", async () => {
      const rows = els.secIpsBody.querySelectorAll(".sec-ban");
      if (!rows.length) return;
      els.secBanAll.disabled = true;
      let ok = 0;
      let failed = 0;
      const total = rows.length;
      for (const btn of rows) {
        const ip = btn.dataset.ip;
        try {
          await banCrowdsec(ip);
          ok++;
          setSecBanStatus(`Added ${ok}/${total} (${ip}).`);
        } catch (err) {
          failed++;
        }
        btn.disabled = true;
      }
      await updateSecBanAvailability();
      els.secBanAll.disabled = false;
      setSecBanStatus(`Added ${ok} of ${total} top attackers to the custom blocklist${failed ? ` (${failed} failed)` : ""}.`);
    });

    updateSecBanAvailability();

    // Modal close buttons
    document.getElementById("sec-countries-modal-close").onclick = () => {
      document.getElementById("sec-countries-modal").hidden = true;
    };
    document.getElementById("sec-ips-modal-close").onclick = () => {
      document.getElementById("sec-ips-modal").hidden = true;
    };
    // Close on backdrop click
    document.getElementById("sec-countries-modal").addEventListener("click", (e) => {
      if (e.target === e.currentTarget) e.currentTarget.hidden = true;
    });
    document.getElementById("sec-ips-modal").addEventListener("click", (e) => {
      if (e.target === e.currentTarget) e.currentTarget.hidden = true;
    });
  }

  function formatHandshake(ts) {
    if (!ts) return "never";
    return formatRelative(ts);
  }

  function renderWireguard(d) {
    if (!d.ok) {
      showBanner(true, d.error || "WireGuard stats unavailable");
      return;
    }
    state.wgData = d;
    els.wgUnconfigured.hidden = !!d.configured;
    els.wgConfigured.hidden = !d.configured;
    if (!d.configured) return;

    const iface = d.interface || {};
    els.wgState.textContent = iface.up ? "Connected" : "Stopped";
    els.wgState.style.color = iface.up ? "var(--green)" : "var(--red)";
    els.wgEndpoint.textContent = d.endpoint || "—";
    els.wgEndpoint.title = d.wan_ip ? `WAN IP ${d.wan_ip}` : "";
    els.wgPeers.textContent = formatNumber((d.peers || []).length);
    const totalTx = (d.peers || []).reduce((n, p) => n + (p.tx || 0), 0);
    const totalRx = (d.peers || []).reduce((n, p) => n + (p.rx || 0), 0);
    els.wgTransfer.textContent = `${formatBytes(totalRx)} ↓ / ${formatBytes(totalTx)} ↑`;

    const peers = d.peers || [];
    els.wgHint.textContent = iface.up
      ? `wg0 · ${iface.address || ""} · listening on UDP ${iface.listen_port || ""}`
      : "interface is stopped";
    els.wgPeersBody.innerHTML = peers.length
      ? peers.map((p) => {
          const last = p.last_handshake ? `<span class="peer-up">${formatHandshake(p.last_handshake)}</span>` : `never`;
          const rk = esc(p.public_key).slice(0, 10) + "…" + esc(p.public_key).slice(-8);
          return `
          <tr data-pk="${esc(p.public_key)}">
            <td><b>${esc(p.name)}</b><br><span class="mono muted">${rk}</span></td>
            <td class="mono">${esc(p.address || "—")}</td>
            <td class="mono">${esc(p.endpoint || "—")}</td>
            <td>${last}</td>
            <td class="mono">${formatBytes(p.rx || 0)} / ${formatBytes(p.tx || 0)}</td>
            <td><div class="wg-actions">
              <button type="button" class="btn btn-sm wg-config-btn" data-pk="${esc(p.public_key)}">Config</button>
              <button type="button" class="btn btn-sm wg-rename-btn" data-pk="${esc(p.public_key)}">Rename</button>
              <button type="button" class="btn btn-sm btn-danger wg-remove-btn" data-pk="${esc(p.public_key)}" data-name="${esc(p.name)}">Remove</button>
            </div></td>
          </tr>`;
        }).join("")
      : `<tr><td colspan="6" class="empty">No clients yet. Click “Add Client” to create one.</td></tr>`;
    els.wgPeerNote.hidden = peers.length === 0;
  }

  async function refreshWireguard() {
    try {
      const data = await fetchJSON("/api/wireguard");
      renderWireguard(data);
    } catch (err) {
      showBanner(true, "WireGuard error: " + err.message);
    }
  }

  function wgShowModal(title, config) {
    els.wgModalTitle.textContent = title;
    els.wgModalText.value = config;
    els.wgModal.dataset.config = config;
    const qr = (typeof qrcode !== "undefined") && qrcode(0, "M");
    if (qr) {
      qr.addData(config);
      qr.make();
      els.wgQr.width = 240;
      els.wgQr.height = 240;
      const ctx = els.wgQr.getContext("2d");
      const img = qr.createDataURL(8, 4);
      const im = new Image();
      im.onload = () => {
        ctx.clearRect(0, 0, 240, 240);
        ctx.fillStyle = "#fff";
        ctx.fillRect(0, 0, 240, 240);
        ctx.drawImage(im, 0, 0, 240, 240);
      };
      im.src = img;
    } else {
      els.wgQr.width = 0;
      els.wgQr.height = 0;
    }
    els.wgModal.hidden = false;
  }

  function wgCloseModal() {
    els.wgModal.hidden = true;
  }

  async function wgAddClient() {
    const name = window.prompt("Name for this client (e.g. Jeff Phone):", "phone");
    if (name === null) return;
    try {
      const data = await postJSON("/api/wireguard/peer/add", { name });
      await refreshWireguard();
      wgShowModal(`Config for ${data.name || "client"}`, data.config);
    } catch (err) {
      showBanner(true, "Add client: " + err.message);
    }
  }

  async function wgShowConfig(pk) {
    try {
      const data = await postJSON("/api/wireguard/peer/config", { public_key: pk });
      wgShowModal(`Config for ${data.name || "client"}`, data.config);
    } catch (err) {
      showBanner(true, "Config: " + err.message);
    }
  }

  async function wgRename(pk) {
    const row = els.wgPeersBody.querySelector(`tr[data-pk="${CSS.escape(pk)}"]`);
    const current = row ? row.querySelector("b").textContent : "client";
    const name = window.prompt("New name:", current);
    if (name === null) return;
    try {
      await postJSON("/api/wireguard/peer/rename", { public_key: pk, name });
      await refreshWireguard();
    } catch (err) {
      showBanner(true, "Rename: " + err.message);
    }
  }

  async function wgRemove(pk, name) {
    if (!window.confirm(`Remove client “${name}”? This immediately revokes its access.`)) return;
    try {
      await postJSON("/api/wireguard/peer/remove", { public_key: pk });
      await refreshWireguard();
    } catch (err) {
      showBanner(true, "Remove client: " + err.message);
    }
  }

  function bindWireguardActions() {
    els.wgSetupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = els.wgSetupBtn;
      btn.disabled = true;
      els.wgSetupError.textContent = "";
      try {
        const body = {
          address: els.wgSetupAddress.value.trim(),
          listen_port: parseInt(els.wgSetupPort.value, 10),
          dns: els.wgSetupDns.value.trim(),
          allowed_ips: els.wgSetupAllowed.value.trim(),
          endpoint: els.wgSetupEndpoint.value.trim(),
          keepalive: parseInt(els.wgSetupKeepalive.value, 10),
        };
        const data = await postJSON("/api/wireguard/setup", body);
        await refreshWireguard();
        if (data.public_key) {
          els.wgSetupError.textContent = "";
          alert(`WireGuard is set up. Server public key: ${data.public_key.slice(0, 12)}…\nAdd a client to generate a config to scan.`);
        }
      } catch (err) {
        els.wgSetupError.textContent = "Setup failed: " + err.message;
      } finally {
        btn.disabled = false;
      }
    });

    els.wgAddPeer.addEventListener("click", wgAddClient);

    els.wgPeersBody.addEventListener("click", (e) => {
      const btn = e.target.closest(".wg-config-btn, .wg-rename-btn, .wg-remove-btn");
      if (!btn) return;
      const pk = btn.dataset.pk;
      if (btn.classList.contains("wg-config-btn")) wgShowConfig(pk);
      else if (btn.classList.contains("wg-rename-btn")) wgRename(pk);
      else wgRemove(pk, btn.dataset.name);
    });

    els.wgModalClose.addEventListener("click", wgCloseModal);
    els.wgModalClose2.addEventListener("click", wgCloseModal);
    els.wgModal.addEventListener("click", (e) => {
      if (e.target === els.wgModal) wgCloseModal();
    });

    els.wgModalCopy.addEventListener("click", () => {
      const copied = () => {
        els.wgModalCopy.textContent = "Copied";
        setTimeout(() => { els.wgModalCopy.textContent = "Copy"; }, 1500);
      };
      els.wgModalText.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { /* ignore */ }
      if (!ok && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(els.wgModalText.value).then(copied);
        return;
      }
      copied();
    });

    els.wgModalDownload.addEventListener("click", () => {
      const blob = new Blob([els.wgModalText.value], { type: "text/plain" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `wireguard-${els.wgModalTitle.textContent.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.conf`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    });
  }

  function renderCrowdsec(d) {
    if (!d.ok) {
      showBanner(true, d.error || "CrowdSec stats unavailable");
      return;
    }
    const decisions = d.decisions || [];
    const bouncers = d.bouncers || [];
    const alerts = d.alerts || [];

    const activeBouncers = bouncers.filter((b) => !b.revoked).length;

    els.csActive.textContent = formatNumber(d.active_count != null ? d.active_count : decisions.length);
    els.csBans.textContent = formatNumber(d.bans_count != null ? d.bans_count : decisions.filter((x) => x.type === "ban").length);
    els.csBouncers.textContent = `${activeBouncers} / ${bouncers.length}`;
    els.csExpiring.textContent = formatNumber(decisions.filter((x) => x.expiring).length);

    els.csDecisionsBody.innerHTML = decisions.map((x) => `
      <tr>
        <td class="mono">${esc(x.ip || "—")}</td>
        <td class="mono">${esc(x.scenario || "—")}</td>
        <td><span class="badge ${x.type === "ban" ? "badge-err" : "badge-ok"}">${esc(x.type || "—")}</span></td>
        <td>${esc(x.origin || "—")}</td>
        <td class="mono">${esc(x.until || "—")}</td>
      </tr>`).join("") || '<tr><td colspan="5" class="empty">No active decisions</td></tr>';

    els.csBouncersBody.innerHTML = bouncers.map((b) => `
      <tr>
        <td><b>${esc(b.name || "—")}</b></td>
        <td>${esc(b.type || "—")}</td>
        <td class="mono">${esc(b.version || "—")}</td>
        <td class="mono">${b.last_pull ? esc(b.last_pull) : "—"}</td>
        <td><span class="badge ${b.revoked ? "badge" : "badge-ok"}">${b.revoked ? "Revoked" : "Active"}</span></td>
      </tr>`).join("") || '<tr><td colspan="5" class="empty">No bouncers registered</td></tr>';

    els.csAlertsBody.innerHTML = alerts.map((a) => {
      const types = (a.decisions || []).map((x) => x.type).filter(Boolean);
      return `
      <tr>
        <td class="mono">${esc(a.created_at || "—")}</td>
        <td class="mono">${esc((a.scenario || "").replace(/^crowdsecurity\//, "") || "—")}</td>
        <td class="mono">${esc((a.source && a.source.value) || "—")}</td>
        <td>${formatNumber(a.events_count != null ? a.events_count : (a.events || []).length)}</td>
        <td>${types.length
          ? types.map((t) => `<span class="badge ${t === "ban" ? "badge-err" : "badge-ok"}">${esc(t)}</span>`).join(" ")
          : "—"}</td>
      </tr>`;
    }).join("") || '<tr><td colspan="5" class="empty">No alerts yet</td></tr>';
  }

  async function refreshCrowdsec() {
    try {
      const data = await fetchJSON("/api/crowdsec");
      renderCrowdsec(data);
    } catch (err) {
      showBanner(true, "CrowdSec stats error: " + err.message);
    }
  }

  function renderCustomBlocklist(d) {
    if (!d.ok) {
      if (els.cblStatus) els.cblStatus.textContent = d.error || "Blocklist unavailable";
      return;
    }
    if (els.cblFile) els.cblFile.textContent = d.file || "";
    const entries = d.entries || [];
    els.cblEmpty.hidden = entries.length > 0;
    els.cblBody.innerHTML = entries.map((e) => `
      <tr>
        <td class="mono">${esc(e.value)}</td>
        <td>${e.banned
          ? `<span class="badge badge-err">Banned${e.simulated ? " (simulated)" : ""}</span>`
          : '<span class="badge">Not active</span>'}</td>
        <td class="mono">${e.banned ? (e.until_ts ? esc(formatRelative(e.until_ts)) : "1y") : "—"}</td>
        <td style="text-align:right">
          <button type="button" class="btn btn-sm cbl-remove" data-entry="${esc(e.value)}">Remove</button>
        </td>
      </tr>`).join("");
    if (els.cblStatus) els.cblStatus.textContent = "";
  }

  async function refreshCustomBlocklist() {
    try {
      const data = await fetchJSON("/api/crowdsec/blocklist");
      renderCustomBlocklist(data);
    } catch (err) {
      if (els.cblStatus) els.cblStatus.textContent = "Error: " + err.message;
    }
  }

  function bindCustomBlocklist() {
    els.cblAdd.addEventListener("click", async () => {
      const value = els.cblInput.value.trim();
      if (!value) return;
      els.cblAdd.disabled = true;
      els.cblStatus.textContent = "Adding…";
      try {
        const data = await postJSON("/api/crowdsec/blocklist/add", { entry: value });
        els.cblInput.value = "";
        els.cblStatus.textContent = data.warning
          ? data.message + " (" + data.warning + ")"
          : (data.message || "Added.");
        await refreshCustomBlocklist();
      } catch (err) {
        els.cblStatus.textContent = err.message;
      } finally {
        els.cblAdd.disabled = false;
      }
    });

    els.cblInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") els.cblAdd.click();
    });

    els.cblBody.addEventListener("click", async (e) => {
      const btn = e.target.closest(".cbl-remove");
      if (!btn) return;
      const entry = btn.dataset.entry;
      if (!window.confirm(`Remove ${entry} from the blocklist and lift its ban?`)) return;
      btn.disabled = true;
      els.cblStatus.textContent = "Removing…";
      try {
        const data = await postJSON("/api/crowdsec/blocklist/remove", { entry });
        els.cblStatus.textContent = data.warning
          ? data.message + " (" + data.warning + ")"
          : (data.message || "Removed.");
        await refreshCustomBlocklist();
      } catch (err) {
        els.cblStatus.textContent = err.message;
        btn.disabled = false;
      }
    });
  }

  let blPollTimer = null;

  function blocklistStatusLabel(status) {
    switch (status) {
      case "idle": return "Ready";
      case "updating": return "Updating…";
      case "ok": return "OK";
      case "error": return "Error";
      default: return String(status || "—").toUpperCase();
    }
  }

  function blocklistStatusBadge(s) {
    if (s.last_status === "ok") return '<span class="badge badge-ok">OK</span>';
    if (s.last_status === "error") {
      return `<span class="badge badge-err" title="${esc(s.last_error || "")}">Error</span>`;
    }
    return '<span class="badge">Never</span>';
  }

  function renderBlocklists(d) {
    if (!d.ok) {
      showBanner(true, d.error || "Blocklist data unavailable");
      return;
    }
    const st = d.state || {};
    const sources = d.sources || [];
    const enabledCount = sources.filter((s) => s.enabled).length;

    els.blDomains.textContent = formatNumber(st.total_domains || 0);
    els.blSources.textContent = `${enabledCount} / ${sources.length}`;
    els.blStatus.textContent = blocklistStatusLabel(st.status);
    els.blStatus.title = st.last_error || "";
    els.blUpdated.textContent = st.last_update ? formatRelative(st.last_update) : "Never";

    const stats = d.stats || {};
    els.blQueries.textContent = stats.queries != null ? formatNumber(stats.queries) : "—";
    els.blBlocked.textContent = stats.blocked != null ? formatNumber(stats.blocked) : "—";

    els.blEmpty.hidden = sources.length > 0;
    els.blBody.innerHTML = sources.map((s) => `
      <tr>
        <td>
          <label class="toggle" title="Enable/disable this source">
            <input type="checkbox" class="bl-toggle" data-url="${esc(s.url)}" ${s.enabled ? "checked" : ""}>
            <span class="toggle-track"></span>
          </label>
        </td>
        <td class="mono">${esc(s.url)}</td>
        <td>${s.last_status === "ok" ? formatNumber(s.domains) : "—"}</td>
        <td class="muted">${s.last_updated ? formatRelative(s.last_updated) : "—"}</td>
        <td>${blocklistStatusBadge(s)}</td>
        <td>
          <button class="btn btn-sm btn-danger bl-remove" data-url="${esc(s.url)}" type="button">Remove</button>
        </td>
      </tr>`).join("");

    const whitelist = d.whitelist || [];
    els.wlEmpty.hidden = whitelist.length > 0;
    els.wlBody.innerHTML = whitelist.map((d) => `
      <tr>
        <td class="mono">${esc(d)}</td>
        <td>
          <button class="btn btn-sm btn-danger wl-remove" data-domain="${esc(d)}" type="button">Remove</button>
        </td>
      </tr>`).join("");

    els.blLog.textContent = (st.log || []).join("\n") || "(no update has run yet)";
    els.blLog.scrollTop = els.blLog.scrollHeight;

    els.blUpdate.disabled = st.status === "updating";
    els.blHint.textContent = st.status === "updating" ? "Downloading lists and reloading Unbound…" : "";
  }

  async function postJSON(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
      cache: "no-store",
    });
    if (res.status === 401 && url !== "/api/auth/login") handleSessionExpired();
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  async function refreshBlocklists() {
    try {
      const data = await fetchJSON("/api/blocklists");
      renderBlocklists(data);
      const status = (data.state || {}).status;
      if (status === "updating") {
        if (!blPollTimer) blPollTimer = setInterval(refreshBlocklists, 3000);
      } else if (blPollTimer) {
        clearInterval(blPollTimer);
        blPollTimer = null;
      }
    } catch (err) {
      showBanner(true, "Blocklist error: " + err.message);
    }
  }

  function bindBlocklistActions() {
    els.blAdd.addEventListener("click", async () => {
      const url = els.blUrl.value.trim();
      if (!url) return;
      els.blAdd.disabled = true;
      try {
        await postJSON("/api/blocklists/add", { url });
        els.blUrl.value = "";
        await refreshBlocklists();
      } catch (err) {
        showBanner(true, "Add list: " + err.message);
      } finally {
        els.blAdd.disabled = false;
      }
    });

    els.blUrl.addEventListener("keydown", (e) => {
      if (e.key === "Enter") els.blAdd.click();
    });

    els.blUpdate.addEventListener("click", async () => {
      try {
        await postJSON("/api/blocklists/update", {});
      } catch (err) {
        showBanner(true, "Update: " + err.message);
      }
      await refreshBlocklists();
    });

    els.blBody.addEventListener("click", async (e) => {
      const btn = e.target.closest(".bl-remove");
      if (!btn) return;
      if (!window.confirm("Remove this blocklist source?")) return;
      try {
        await postJSON("/api/blocklists/remove", { url: btn.dataset.url });
        await refreshBlocklists();
      } catch (err) {
        showBanner(true, "Remove: " + err.message);
      }
    });

    els.blBody.addEventListener("change", async (e) => {
      const toggle = e.target.closest(".bl-toggle");
      if (!toggle) return;
      try {
        await postJSON("/api/blocklists/toggle", { url: toggle.dataset.url });
      } catch (err) {
        showBanner(true, "Toggle: " + err.message);
      }
      await refreshBlocklists();
    });

    els.wlAdd.addEventListener("click", async () => {
      const domain = els.wlDomain.value.trim();
      if (!domain) return;
      els.wlAdd.disabled = true;
      try {
        await postJSON("/api/blocklists/whitelist/add", { domain });
        els.wlDomain.value = "";
        await refreshBlocklists();
      } catch (err) {
        showBanner(true, "Whitelist: " + err.message);
      } finally {
        els.wlAdd.disabled = false;
      }
    });

    els.wlDomain.addEventListener("keydown", (e) => {
      if (e.key === "Enter") els.wlAdd.click();
    });

    els.wlBody.addEventListener("click", async (e) => {
      const btn = e.target.closest(".wl-remove");
      if (!btn) return;
      if (!window.confirm(`Remove "${btn.dataset.domain}" from the whitelist?`)) return;
      try {
        await postJSON("/api/blocklists/whitelist/remove", { domain: btn.dataset.domain });
        await refreshBlocklists();
      } catch (err) {
        showBanner(true, "Whitelist remove: " + err.message);
      }
    });
  }

  function pct(part, total) {
    if (!total) return "";
    return ` (${Math.round((part / total) * 100)}%)`;
  }

  function renderSystem(d) {
    if (!d.ok) {
      showBanner(true, d.error || "System info unavailable");
      return;
    }
    const cpu = d.cpu || {};
    const mem = d.mem || {};
    const swap = d.swap || {};
    const disk = d.disk || {};

    els.sysHost.textContent = d.hostname || "—";
    state.sysHostname = d.hostname || "";
    if (!state.editingHost) {
      els.sysHost.textContent = state.sysHostname || "—";
    }
    els.sysCpu.textContent = cpu.cores ? `${cpu.cores} cores` + (cpu.temp != null ? ` · ${cpu.temp}°C` : "") : "—";
    els.sysMem.textContent = mem.total ? `${formatBytes(mem.used)} / ${formatBytes(mem.total)}${pct(mem.used, mem.total)}` : "—";
    els.sysUptime.textContent = formatUptime(d.uptime);
    els.sysLoad.textContent = (d.load || []).map((x) => x.toFixed(2)).join(" / ");
    els.sysDisk.textContent = disk.total ? `${formatBytes(disk.used)} / ${formatBytes(disk.total)}${pct(disk.used, disk.total)}` : "—";
    els.sysSwap.textContent = swap.total ? `${formatBytes(swap.used)} / ${formatBytes(swap.total)}` : "—";
    els.sysOs.textContent = d.os ? `${d.os}` : "—";

    els.sysInterfacesBody.innerHTML = (d.interfaces || []).map((i) => `
      <tr>
        <td><b class="mono">${esc(i.name)}</b></td>
        <td><span class="badge ${i.state === "UP" ? "badge-ok" : "badge-err"}">${esc(i.state || "—")}</span></td>
        <td class="mono">${esc(i.mac || "—")}</td>
        <td class="mono">${(i.addrs || []).map((a) => `${esc(a.addr)}/${a.mask}`).join("<br>") || "—"}</td>
      </tr>`).join("");

    els.sysDhcpSubnet.textContent = d.dhcp.subnet || "—";
    els.sysDhcpRange.textContent = (d.dhcp.pools || []).join(", ") || "—";
    els.sysDhcpRouter.textContent = d.dhcp.router || "—";
    els.sysDhcpDns.textContent = d.dhcp.dns || "—";
    els.sysDhcpDomain.textContent = d.dhcp.domain || "—";

    els.sysDnsIface.textContent = (d.dns.interfaces || []).join(", ") || "—";
    els.sysDnsPort.textContent = d.dns.port != null ? d.dns.port : "—";

    els.sysCpuModel.textContent = cpu.model || "—";
    els.sysCpuCores.textContent = cpu.cores ? cpu.cores + (cpu.temp != null ? ` · ${cpu.temp}°C` : "") : "—";
    els.sysMemDetail.textContent = mem.total ? `${formatBytes(mem.used)} / ${formatBytes(mem.total)}${pct(mem.used, mem.total)}` : "—";
    els.sysSwapDetail.textContent = swap.total ? `${formatBytes(swap.used)} / ${formatBytes(swap.total)}` : "—";
    els.sysKernel.textContent = d.kernel || "—";
    els.sysArch.textContent = d.arch || "—";
  }

  async function refreshSystem() {
    try {
      const data = await fetchJSON("/api/system");
      renderSystem(data);
    } catch (err) {
      showBanner(true, "System info error: " + err.message);
    }
  }

  function bindHostEdit() {
    els.sysHostEdit.addEventListener("click", () => {
      if (state.editingHost) return;
      state.editingHost = true;
      els.sysHost.innerHTML = `
        <span class="host-editor">
          <input type="text" id="host-input" value="${esc(state.sysHostname)}" maxlength="63" autocomplete="off" spellcheck="false">
          <button class="host-save" type="button">Save</button>
          <button class="host-cancel" type="button">Cancel</button>
        </span>`;
      const input = document.getElementById("host-input");
      input.focus();
      input.select();
      const close = (save) => {
        state.editingHost = false;
        if (save) {
          const val = input.value.trim();
          if (val) {
            els.sysHost.textContent = val;
            postJSON("/api/system/hostname", { hostname: val })
              .then(() => refreshSystem())
              .catch((err) => showBanner(true, "Hostname: " + err.message));
            return;
          }
        }
        els.sysHost.textContent = state.sysHostname || "—";
      };
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") close(true);
        else if (e.key === "Escape") close(false);
      });
      els.sysHost.querySelector(".host-save").addEventListener("click", () => close(true));
      els.sysHost.querySelector(".host-cancel").addEventListener("click", () => close(false));
    });
  }

  function bindConfigEdit() {
    const openCfg = async (kind, title) => {
      state.cfgTarget = kind;
      els.cfgModalTitle.textContent = title;
      els.cfgModalHint.textContent = "";
      els.cfgModalText.value = "Loading…";
      els.cfgModal.hidden = false;
      els.cfgModalSave.disabled = false;
      try {
        const data = await fetchJSON(`/api/system/${kind}-config`);
        if (!data.ok) throw new Error(data.error || "load failed");
        els.cfgModalText.value = data.content;
        els.cfgModalHint.className = "muted cfg-hint";
        els.cfgModalHint.textContent = data.path;
      } catch (err) {
        els.cfgModalHint.className = "muted cfg-hint cfg-hint-err";
        els.cfgModalHint.textContent = err.message;
      }
    };
    const closeCfg = () => {
      els.cfgModal.hidden = true;
      state.cfgTarget = null;
      els.cfgModalSave.disabled = false;
    };

    els.sysEditKea.addEventListener("click", () => openCfg("kea", "Edit Kea DHCP config"));
    els.sysEditUnbound.addEventListener("click", () => openCfg("unbound", "Edit Unbound config"));
    els.cfgModalClose.addEventListener("click", closeCfg);
    els.cfgModalCancel.addEventListener("click", closeCfg);
    els.cfgModal.addEventListener("click", (e) => {
      if (e.target === els.cfgModal) closeCfg();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !els.cfgModal.hidden) closeCfg();
    });

    els.cfgModalSave.addEventListener("click", async () => {
      const kind = state.cfgTarget;
      if (!kind) return;
      if (!window.confirm("Save changes and restart the service? A backup of the current file is made first.")) return;
      els.cfgModalSave.disabled = true;
      try {
        const data = await postJSON(`/api/system/${kind}-config`, { content: els.cfgModalText.value });
        els.cfgModalSave.disabled = false;
        els.cfgModalHint.className = "muted cfg-hint cfg-hint-ok";
        els.cfgModalHint.textContent = "Saved. Backup: " + data.backup;
        setTimeout(closeCfg, 900);
        refreshSystem();
      } catch (err) {
        els.cfgModalSave.disabled = false;
        els.cfgModalHint.className = "muted cfg-hint cfg-hint-err";
        els.cfgModalHint.textContent = err.message;
      }
    });
  }

  function setBkMsg(msg, err) {
    els.bkMsg.textContent = msg || "";
    els.bkMsg.className = "muted" + (err ? " bk-msg-err" : msg ? " bk-msg-ok" : "");
  }

  function renderBackups(d) {
    els.bkBody.innerHTML = (d.backups || []).map((b) => `
      <tr>
        <td class="mono">${esc(b.name)}</td>
        <td>${formatBytes(b.size)}</td>
        <td>${new Date(b.time * 1000).toLocaleString()}</td>
        <td class="td-right">
          <button class="btn btn-sm bk-dl" data-name="${esc(b.name)}" type="button">Download</button>
          <button class="btn btn-sm btn-danger bk-res" data-name="${esc(b.name)}" type="button">Restore</button>
          <button class="btn btn-sm bk-del" data-name="${esc(b.name)}" type="button" title="Delete this backup">Delete</button>
        </td>
      </tr>`).join("") || `<tr><td colspan="4" class="muted">No backups yet.</td></tr>`;
  }

  async function refreshBackups() {
    try {
      const data = await fetchJSON("/api/backups");
      renderBackups(data);
    } catch (err) {
      showBanner(true, "Backups: " + err.message);
    }
  }

  async function downloadBackup(name) {
    const res = await fetch("/api/backups/download?name=" + encodeURIComponent(name), { cache: "no-store" });
    if (!res.ok) throw new Error("Download failed");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  async function uploadRestore(name, buf) {
    const res = await fetch("/api/backups/restore?name=" + encodeURIComponent(name), {
      method: "POST",
      headers: { "Content-Type": "application/gzip" },
      body: buf,
      cache: "no-store",
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  function restoreMsg(data) {
    const n = data.restored ? data.restored.length : 0;
    return `Restored ${n} file(s).` + (data.restart_required ? " API server changed — run: sudo systemctl restart tuxwall" : "");
  }

  function setBkSysMsg(msg, err) {
    els.bkSysMsg.textContent = msg || "";
    els.bkSysMsg.className = "muted" + (err ? " bk-msg-err" : msg ? " bk-msg-ok" : "");
  }

  function renderSystemBackups(d) {
    els.bkSysBody.innerHTML = (d.backups || []).map((b) => `
      <tr>
        <td class="mono">${esc(b.name)}</td>
        <td>${formatBytes(b.size)}</td>
        <td>${new Date(b.time * 1000).toLocaleString()}</td>
        <td class="td-right">
          <button class="btn btn-sm bk-sys-dl" data-name="${esc(b.name)}" type="button">Download</button>
          <button class="btn btn-sm bk-sys-del" data-name="${esc(b.name)}" type="button" title="Delete this backup">Delete</button>
        </td>
      </tr>`).join("") || `<tr><td colspan="4" class="muted">No system backups yet.</td></tr>`;
  }

  async function refreshSystemBackups() {
    try {
      const data = await fetchJSON("/api/backups/system");
      renderSystemBackups(data);
      return data;
    } catch (err) {
      setBkSysMsg("System backups: " + err.message, true);
      return null;
    }
  }

  let bkSysPollTimer = null;

  async function pollSystemBackup() {
    try {
      const data = await refreshSystemBackups();
      if (!data) return;
      if (data.running) {
        els.bkSysProgress.hidden = false;
        els.bkSysBar.style.width = (data.pct || 0) + "%";
        els.bkSysStatus.textContent = `${data.pct || 0}% — ${data.step || "Running..."}`;
        els.bkSysCreate.disabled = true;
        bkSysPollTimer = setTimeout(pollSystemBackup, 600);
      } else {
        els.bkSysProgress.hidden = true;
        els.bkSysCreate.disabled = false;
        if (bkSysPollTimer) { clearTimeout(bkSysPollTimer); bkSysPollTimer = null; }
        if (data.error) setBkSysMsg("Backup failed: " + data.error, true);
        else if (data.result) setBkSysMsg(`Backup created: ${data.result}. Download and store it off this machine.`, false);
      }
    } catch (err) {
      els.bkSysProgress.hidden = true;
      els.bkSysCreate.disabled = false;
      setBkSysMsg("Backup status: " + err.message, true);
    }
  }

  async function downloadSystemBackup(name) {
    const res = await fetch("/api/backups/system/download?name=" + encodeURIComponent(name), { cache: "no-store" });
    if (!res.ok) throw new Error("Download failed");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  function bindBackups() {
    els.bkCreate.addEventListener("click", async () => {
      try {
        await postJSON("/api/backups/create", {});
        setBkMsg("Backup created.", false);
        await refreshBackups();
      } catch (err) {
        setBkMsg(err.message, true);
      }
    });

    els.bkRestore.addEventListener("click", async () => {
      const file = els.bkFile.files && els.bkFile.files[0];
      if (!file) {
        setBkMsg("Choose a .tar.gz backup file first.", true);
        return;
      }
      if (!window.confirm(`Restore dashboard from "${file.name}"? Current files will be overwritten.`)) return;
      try {
        const buf = await file.arrayBuffer();
        const data = await uploadRestore(file.name, buf);
        setBkMsg(restoreMsg(data), false);
        els.bkFile.value = "";
        await refreshBackups();
      } catch (err) {
        setBkMsg(err.message, true);
      }
    });

    els.bkBody.addEventListener("click", async (e) => {
      const dl = e.target.closest(".bk-dl");
      if (dl) {
        try {
          await downloadBackup(dl.dataset.name);
        } catch (err) {
          setBkMsg(err.message, true);
        }
        return;
      }
      const res = e.target.closest(".bk-res");
      if (res) {
        if (!window.confirm(`Restore dashboard from "${res.dataset.name}"? Current files will be overwritten.`)) return;
        try {
          const data = await postJSON("/api/backups/restore", { name: res.dataset.name });
          setBkMsg(restoreMsg(data), false);
          await refreshBackups();
        } catch (err) {
          setBkMsg(err.message, true);
        }
        return;
      }
      const del = e.target.closest(".bk-del");
      if (del) {
        if (!window.confirm(`Delete backup "${del.dataset.name}"?`)) return;
        try {
          await postJSON("/api/backups/delete", { name: del.dataset.name });
          setBkMsg("Backup deleted.", false);
          await refreshBackups();
        } catch (err) {
          setBkMsg(err.message, true);
        }
      }
    });
  }

  function bindSystemBackups() {
    els.bkSysCreate.addEventListener("click", async () => {
      try {
        await postJSON("/api/backups/system/create", {});
        setBkSysMsg("Starting system backup...", false);
        await pollSystemBackup();
      } catch (err) {
        setBkSysMsg(err.message, true);
      }
    });

    els.bkSysBody.addEventListener("click", async (e) => {
      const dl = e.target.closest(".bk-sys-dl");
      if (dl) {
        try {
          await downloadSystemBackup(dl.dataset.name);
        } catch (err) {
          setBkSysMsg(err.message, true);
        }
        return;
      }
      const del = e.target.closest(".bk-sys-del");
      if (del) {
        if (!window.confirm(`Delete system backup "${del.dataset.name}"?`)) return;
        try {
          await postJSON("/api/backups/system/delete", { name: del.dataset.name });
          setBkSysMsg("System backup deleted.", false);
          await refreshSystemBackups();
        } catch (err) {
          setBkSysMsg(err.message, true);
        }
      }
    });
  }

  function renderUpdates(d) {
    els.sysUpdDistro.textContent = d.distro || "—";
    els.sysUpdKernel.textContent = d.kernel || "—";
    els.sysUpdChecked.textContent = d.last_check ? new Date(d.last_check * 1000).toLocaleString() : "Never";
    els.sysUpdLast.textContent = d.last_upgrade ? new Date(d.last_upgrade * 1000).toLocaleString() : "Never";
    els.sysUpdCount.textContent = d.upgradable >= 0 ? formatNumber(d.upgradable) : "—";
    const running = !!d.running;
    els.sysUpdProgress.hidden = !running;
    els.sysUpdCheck.disabled = running;
    els.sysUpdApply.disabled = running;
    if (running) {
      const pct = d.percent != null ? Math.max(0, Math.min(100, d.percent)) : 0;
      els.sysUpdBar.style.width = pct + "%";
      els.sysUpdStatus.textContent = `${d.phase || "Working"} — ${pct}%`;
      els.sysUpdLog.textContent = (d.log || []).join("\n");
      els.sysUpdLog.scrollTop = els.sysUpdLog.scrollHeight;
    } else if (d.exit_code != null) {
      els.sysUpdStatus.textContent = d.exit_code === 0
        ? (d.last_upgrade ? "System update complete." : "Check complete.")
        : `Failed (exit ${d.exit_code}). See the log below or run 'Check for updates' for details.`;
      els.sysUpdLog.textContent = (d.log || []).join("\n");
    } else {
      els.sysUpdStatus.textContent = "";
      els.sysUpdLog.textContent = "";
    }
  }

  function stopUpdPoll() {
    if (state.updTimer) {
      clearInterval(state.updTimer);
      state.updTimer = null;
    }
  }

  function startUpdPoll() {
    if (state.updTimer) return;
    state.updTimer = setInterval(async () => {
      try {
        const d = await fetchJSON("/api/system/updates");
        renderUpdates(d);
        if (!d.running) stopUpdPoll();
      } catch (err) {
        showBanner(true, "Updates: " + err.message);
        stopUpdPoll();
      }
    }, 1000);
  }

  async function refreshUpdates() {
    try {
      const d = await fetchJSON("/api/system/updates");
      renderUpdates(d);
      if (d.running) startUpdPoll();
    } catch (err) {
      showBanner(true, "Updates: " + err.message);
    }
  }

  function bindUpdates() {
    els.sysUpdCheck.addEventListener("click", async () => {
      try {
        await postJSON("/api/system/updates/check", {});
        startUpdPoll();
        refreshUpdates();
      } catch (err) {
        showBanner(true, "Updates: " + err.message);
      }
    });
    els.sysUpdApply.addEventListener("click", async () => {
      if (!window.confirm("Install all available system updates now? This can take several minutes. A reboot may be recommended afterwards.")) return;
      try {
        await postJSON("/api/system/updates/apply", {});
        startUpdPoll();
        refreshUpdates();
      } catch (err) {
        showBanner(true, "Updates: " + err.message);
      }
    });
    els.sysReboot.addEventListener("click", async () => {
      if (!window.confirm("Reboot the router now? The dashboard and network go offline for about a minute.")) return;
      if (!window.confirm("Are you sure? All connections through this router will drop.")) return;
      try {
        await postJSON("/api/system/reboot", {});
        els.sysReboot.textContent = "Rebooting…";
        els.sysReboot.disabled = true;
      } catch (err) {
        showBanner(true, "Reboot: " + err.message);
      }
    });

    els.sysSvcRefresh.addEventListener("click", () => refreshServices());

    els.svcTabs.addEventListener("click", (ev) => {
      const t = ev.target.closest(".svc-tab");
      if (!t || t.classList.contains("active")) return;
      state.svcTab = t.dataset.tab;
      els.svcTabs.querySelectorAll(".svc-tab").forEach((x) => x.classList.toggle("active", x === t));
      renderServices();
    });

    els.sysServicesBody.addEventListener("click", async (ev) => {
      const btn = ev.target.closest("button[data-action]");
      if (!btn || btn.disabled) return;
      const unit = btn.dataset.unit;
      const action = btn.dataset.action;
      const warn = {
        stop: `Stop ${unit}? It will stay stopped until started again.`,
        restart: `Restart ${unit}? Active connections through it may drop.`,
        reload: `Reload ${unit}?`,
        start: `Start ${unit}?`,
      }[action];
      if (!window.confirm(warn)) return;
      btn.disabled = true;
      try {
        await postJSON("/api/system/services/action", { unit, action });
        showBanner(false);
        await refreshServices();
      } catch (err) {
        showBanner(true, `${unit} ${action}: ` + err.message);
        await refreshServices();
      }
    });
  }

  const BW_RX_FALLBACK = "#4f8cff";
  const BW_TX_FALLBACK = "#d29922";

  function logQuery() {
    return `source=${encodeURIComponent(els.logSource.value)}&lines=${els.logLines.value}&priority=${encodeURIComponent(els.logPriority.value)}`;
  }

  async function refreshLog() {
    try {
      const d = await fetchJSON(`/api/logs/tail?${logQuery()}`);
      const atBottom = els.logView.scrollHeight - els.logView.scrollTop - els.logView.clientHeight < 40;
      els.logView.textContent = d.content || "(no log entries)";
      els.logMeta.textContent = `${d.lines} line(s) · ${els.logSource.options[els.logSource.selectedIndex].text}`;
      if (els.logFollow.checked || atBottom) els.logView.scrollTop = els.logView.scrollHeight;
    } catch (err) {
      els.logMeta.textContent = err.message;
    }
  }

  async function loadLogSources() {
    try {
      const d = await fetchJSON("/api/logs/services");
      const cur = els.logSource.value;
      els.logSource.innerHTML = (d.sources || []).map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join("");
      if (cur && Array.from(els.logSource.options).some((o) => o.value === cur)) els.logSource.value = cur;
      refreshLog();
    } catch (err) {
      els.logMeta.textContent = err.message;
    }
  }

  function startLogTimer() {
    if (state.logTimer) return;
    state.logTimer = setInterval(() => {
      if (els.logFollow.checked) refreshLog();
    }, 5000);
  }

  function stopLogTimer() {
    if (state.logTimer) {
      clearInterval(state.logTimer);
      state.logTimer = null;
    }
  }

  function bindLogs() {
    els.logRefresh.addEventListener("click", refreshLog);
    els.logSource.addEventListener("change", refreshLog);
    els.logPriority.addEventListener("change", refreshLog);
    els.logLines.addEventListener("change", refreshLog);
  }

  function hexToRgba(hex, alpha) {
    const h = hex.replace("#", "");
    return `rgba(${parseInt(h.slice(0, 2), 16)},${parseInt(h.slice(2, 4), 16)},${parseInt(h.slice(4, 6), 16)},${alpha})`;
  }

  function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    if (!v) return fallback;
    if (/^#[0-9a-fA-F]{6}$/.test(v)) return v;
    return fallback;
  }

  // Smooth curve helper using Catmull-Rom → cubic bezier conversion
  function smoothCurvePath(ctx, pts) {
    if (pts.length < 2) return;
    ctx.moveTo(pts[0][0], pts[0][1]);
    if (pts.length === 2) { ctx.lineTo(pts[1][0], pts[1][1]); return; }
    const tension = 0.4;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[Math.max(i - 1, 0)];
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const p3 = pts[Math.min(i + 2, pts.length - 1)];
      const cp1x = p1[0] + (p2[0] - p0[0]) * tension;
      const cp1y = p1[1] + (p2[1] - p0[1]) * tension;
      const cp2x = p2[0] - (p3[0] - p1[0]) * tension;
      const cp2y = p2[1] - (p3[1] - p1[1]) * tension;
      ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2[0], p2[1]);
    }
  }

  function drawBandwidth(canvas, history, maxBps) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width, h = rect.height;
    ctx.clearRect(0, 0, w, h);

    const padT = 10, padB = 16, padL = 4, padR = 4;
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const n = history.length;
    if (n < 2) {
      ctx.fillStyle = cssVar("--muted", "#8b949e");
      ctx.font = "11px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("Collecting samples…", w / 2, h / 2);
      return;
    }

    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    const ticks = 4;
    for (let i = 0; i <= ticks; i++) {
      const y = padT + (ph * i) / ticks;
      ctx.strokeStyle = hexToRgba(cssVar("--text", "#e6edf3"), 0.06);
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 4]);
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + pw, y);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.8);
      ctx.fillText(formatBits(maxBps * (1 - i / ticks)), padL + 2, y - 3);
    }

    ctx.textAlign = "center";
    const steps = Math.min(5, n);
    for (let i = 0; i < steps; i++) {
      const idx = Math.round((i * (n - 1)) / (steps - 1));
      const t = new Date(history[idx][0] * 1000);
      const label = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}:${String(t.getSeconds()).padStart(2, "0")}`;
      ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.8);
      ctx.fillText(label, padL + (pw * idx) / (n - 1), padT + ph + 11);
    }

    function drawSeries(series, color) {
      const pts = [];
      for (let i = 0; i < n; i++) {
        const x = padL + (pw * i) / (n - 1);
        const y = padT + ph * Math.max(0, 1 - series[i] / maxBps);
        pts.push([x, y]);
      }
      // Gradient fill
      const grad = ctx.createLinearGradient(0, padT, 0, padT + ph);
      grad.addColorStop(0, hexToRgba(color, 0.28));
      grad.addColorStop(1, hexToRgba(color, 0.02));
      ctx.beginPath();
      smoothCurvePath(ctx, pts);
      ctx.lineTo(padL + pw, padT + ph);
      ctx.lineTo(padL, padT + ph);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      // Smooth line
      ctx.beginPath();
      smoothCurvePath(ctx, pts);
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      ctx.stroke();
    }

    drawSeries(history.map((s) => s[2]), cssVar("--amber", BW_TX_FALLBACK));
    drawSeries(history.map((s) => s[1]), cssVar("--accent", BW_RX_FALLBACK));
  }

  function renderBandwidth(d) {
    if (!d.ok) {
      showBanner(true, d.error || "Bandwidth stats unavailable");
      return;
    }
    state.bwData = d;
    const ifaces = d.interfaces || [];
    const totDown = ifaces.reduce((n, i) => n + (i.rx_bps || 0), 0);
    const totUp = ifaces.reduce((n, i) => n + (i.tx_bps || 0), 0);
    els.bwDown.textContent = formatBits(totDown);
    els.bwUp.textContent = formatBits(totUp);
    els.bwWindow.textContent = formatDuration(d.max_samples * d.interval);
    els.bwSamples.textContent = formatNumber(d.max_samples);

    const maxBps = ifaces.reduce((m, i) => {
      for (const s of i.history) {
        if (s[1] > m) m = s[1];
        if (s[2] > m) m = s[2];
      }
      return m;
    }, 1);

    els.bwCharts.innerHTML = ifaces.map((i) => `
      <div class="card bw-card">
        <div class="bw-head">
          <h2 class="mono">${esc(i.name)}</h2>
          <div class="bw-rates">
            <div class="bw-dn"><span>Down</span><b>${formatBits(i.rx_bps)}</b></div>
            <div class="bw-up"><span>Up</span><b>${formatBits(i.tx_bps)}</b></div>
          </div>
        </div>
        <div class="bw-canvas-wrap"><canvas class="bw-canvas" data-iface="${esc(i.name)}"></canvas></div>
      </div>`).join("");

    requestAnimationFrame(() => {
      ifaces.forEach((i) => {
        const cv = els.bwCharts.querySelector(`canvas[data-iface="${CSS.escape(i.name)}"]`);
        if (cv) drawBandwidth(cv, i.history, maxBps);
      });
    });

    const clients = d.clients || [];
    els.bwClientsEmpty.hidden = clients.length > 0;
    if (d.clients_error) {
      els.bwClientsEmpty.hidden = false;
      els.bwClientsEmpty.textContent = d.clients_error;
      els.bwClientsBody.innerHTML = "";
      return;
    }
    els.bwClientsBody.innerHTML = clients.map((c) => `
      <tr>
        <td><span class="mono">${esc(c.ip)}</span>${c.hostname ? `<span class="muted"> · ${esc(c.hostname)}</span>` : ""}</td>
        <td class="mono">${esc(c.mac || "—")}</td>
        <td>${formatMBs(c.rx_bytes_per_s)}</td>
        <td>${formatMBs(c.tx_bytes_per_s)}</td>
        <td>${formatBytes(c.rx_bytes)}</td>
        <td>${formatBytes(c.tx_bytes)}</td>
      </tr>`).join("");
  }

  async function refreshBandwidth() {
    try {
      const data = await fetchJSON("/api/bandwidth");
      renderBandwidth(data);
    } catch (err) {
      showBanner(true, "Bandwidth stats error: " + err.message);
    }
  }

  const CHART_COLORS = [
    "#4f8cff", "#3fb950", "#d29922", "#f85149", "#bc8cff",
    "#39c5cf", "#db61a2", "#ffa657", "#7ee787", "#a5d6ff",
    "#ff7b72", "#8b949e",
  ];

  function drawResourceChart(canvas, history) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width, h = rect.height;
    ctx.clearRect(0, 0, w, h);

    const padT = 10, padB = 16, padL = 4, padR = 4;
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const n = history.length;
    if (n < 2) {
      ctx.fillStyle = cssVar("--muted", "#8b949e");
      ctx.font = "11px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("Collecting samples…", w / 2, h / 2);
      return;
    }

    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    for (let i = 0; i <= 4; i++) {
      const y = padT + (ph * i) / 4;
      ctx.strokeStyle = hexToRgba(cssVar("--text", "#e6edf3"), 0.06);
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 4]);
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + pw, y);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.8);
      ctx.fillText(String(Math.round(100 - i * 25)) + "%", padL + 2, y - 3);
    }

    ctx.textAlign = "center";
    const steps = Math.min(5, n);
    for (let i = 0; i < steps; i++) {
      const idx = Math.round((i * (n - 1)) / (steps - 1));
      const t = new Date(history[idx][0] * 1000);
      const label = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}:${String(t.getSeconds()).padStart(2, "0")}`;
      ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.9);
      ctx.fillText(label, padL + (pw * idx) / (n - 1), padT + ph + 11);
    }

    function drawSeries(series, color) {
      const pts = [];
      for (let i = 0; i < n; i++) {
        const x = padL + (pw * i) / (n - 1);
        const y = padT + ph * Math.max(0, Math.min(1, 1 - series[i] / 100));
        pts.push([x, y]);
      }
      const grad = ctx.createLinearGradient(0, padT, 0, padT + ph);
      grad.addColorStop(0, hexToRgba(color, 0.28));
      grad.addColorStop(1, hexToRgba(color, 0.02));
      ctx.beginPath();
      smoothCurvePath(ctx, pts);
      ctx.lineTo(padL + pw, padT + ph);
      ctx.lineTo(padL, padT + ph);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.beginPath();
      smoothCurvePath(ctx, pts);
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      ctx.stroke();
    }

    const resCpu = cssVar("--amber", "#d29922");
    const resMem = cssVar("--accent", "#4f8cff");
    drawSeries(history.map((s) => s[1]), resCpu);
    drawSeries(history.map((s) => s[2]), resMem);

    ctx.fillStyle = resCpu;
    ctx.fillRect(padL + 2, padT - 2, 9, 9);
    ctx.fillStyle = resMem;
    ctx.fillRect(padL + 60, padT - 2, 9, 9);
    ctx.fillStyle = cssVar("--text", "#e6edf3");
    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    ctx.fillText("CPU", padL + 14, padT + 5);
    ctx.fillText("Mem", padL + 72, padT + 5);
  }

  function drawLatencyChart(canvas, history, baselineMs) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width, h = rect.height;
    ctx.clearRect(0, 0, w, h);

    const padT = 10, padB = 16, padL = 4, padR = 4;
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const n = history.length;
    if (n < 2) {
      ctx.fillStyle = cssVar("--muted", "#8b949e");
      ctx.font = "11px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("Collecting samples…", w / 2, h / 2);
      return;
    }

    let maxMs = 1;
    for (const s of history) {
      if (s[2] > maxMs) maxMs = s[2];
    }
    maxMs *= 1.15;
    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    for (let i = 0; i <= 3; i++) {
      const y = padT + (ph * i) / 3;
      ctx.strokeStyle = hexToRgba(cssVar("--text", "#e6edf3"), 0.06);
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 4]);
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + pw, y);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.8);
      const v = maxMs * (1 - i / 3);
      ctx.fillText(v >= 100 ? Math.round(v) + "ms" : v.toFixed(1), padL + 2, y - 3);
    }

    ctx.textAlign = "center";
    const steps = Math.min(5, n);
    for (let i = 0; i < steps; i++) {

      const idx = Math.round((i * (n - 1)) / (steps - 1));
      const t = new Date(history[idx][0] * 1000);
      const label = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`;
      ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.8);
      ctx.fillText(label, padL + (pw * idx) / (n - 1), padT + ph + 11);
    }

    function yFor(ms) {
      return padT + ph * Math.max(0, Math.min(1, 1 - ms / maxMs));
    }

    function drawSeries(col, color, filled) {
      const pts = [];
      for (let i = 0; i < n; i++) {
        pts.push([padL + (pw * i) / (n - 1), yFor(history[i][col])]);
      }
      if (filled) {
        const grad = ctx.createLinearGradient(0, padT, 0, padT + ph);
        grad.addColorStop(0, hexToRgba(color, 0.2));
        grad.addColorStop(1, hexToRgba(color, 0.01));
        ctx.beginPath();
        smoothCurvePath(ctx, pts);
        ctx.lineTo(padL + pw, padT + ph);
        ctx.lineTo(padL, padT + ph);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();
      }
      ctx.beginPath();
      smoothCurvePath(ctx, pts);
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      ctx.stroke();
    }

    const latMax = cssVar("--red", "#f85149");
    const latAvg = cssVar("--accent", "#4f8cff");
    drawSeries(2, hexToRgba(latMax, 0.6), false);
    drawSeries(1, latAvg, true);

    if (baselineMs > 0 && baselineMs < maxMs) {
      const by = yFor(baselineMs);
      ctx.save();
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = hexToRgba(cssVar("--green", "#3fb950"), 0.7);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, by);
      ctx.lineTo(padL + pw, by);
      ctx.stroke();
      ctx.restore();
    }

    ctx.fillStyle = latAvg;
    ctx.fillRect(padL + 2, padT - 2, 9, 9);
    ctx.fillStyle = hexToRgba(latMax, 0.75);
    ctx.fillRect(padL + 60, padT - 2, 9, 9);
    ctx.fillStyle = cssVar("--text", "#e6edf3");
    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    ctx.fillText("avg", padL + 14, padT + 5);
    ctx.fillText("max", padL + 72, padT + 5);
  }

  function drawJitterChart(canvas, history) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width, h = rect.height;
    ctx.clearRect(0, 0, w, h);

    const padT = 10, padB = 16, padL = 4, padR = 4;
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const pts = history.filter((s) => s.length > 3 && s[3] > 0);
    const n = pts.length;
    if (n < 2) {
      ctx.fillStyle = cssVar("--muted", "#8b949e");
      ctx.font = "11px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("Collecting samples…", w / 2, h / 2);
      return;
    }

    let maxMs = 0.5;
    for (const s of pts) {
      if (s[3] > maxMs) maxMs = s[3];
    }
    maxMs *= 1.15;

    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    for (let i = 0; i <= 3; i++) {
      const y = padT + (ph * i) / 3;
      ctx.strokeStyle = hexToRgba(cssVar("--text", "#e6edf3"), 0.06);
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 4]);
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + pw, y);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.8);
      const v = maxMs * (1 - i / 3);
      ctx.fillText(v >= 100 ? Math.round(v) + "ms" : v.toFixed(1), padL + 2, y - 3);
    }

    ctx.textAlign = "center";
    const steps = Math.min(5, n);
    for (let i = 0; i < steps; i++) {
      const idx = Math.round((i * (n - 1)) / (steps - 1));
      const t = new Date(pts[idx][0] * 1000);
      const label = `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`;
      ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.8);
      ctx.fillText(label, padL + (pw * idx) / (n - 1), padT + ph + 11);
    }

    const jitColor = cssVar("--amber", "#d29922");
    const curvePts = pts.map((s, i) => [
      padL + (pw * i) / (n - 1),
      padT + ph * Math.max(0, Math.min(1, 1 - s[3] / maxMs)),
    ]);
    const grad = ctx.createLinearGradient(0, padT, 0, padT + ph);
    grad.addColorStop(0, hexToRgba(jitColor, 0.28));
    grad.addColorStop(1, hexToRgba(jitColor, 0.02));
    ctx.beginPath();
    smoothCurvePath(ctx, curvePts);
    ctx.lineTo(padL + pw, padT + ph);
    ctx.lineTo(padL, padT + ph);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.beginPath();
    smoothCurvePath(ctx, curvePts);
    ctx.strokeStyle = jitColor;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.stroke();

    ctx.fillStyle = jitColor;
    ctx.fillRect(padL + 2, padT - 2, 9, 9);
    ctx.fillStyle = cssVar("--text", "#e6edf3");
    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    ctx.fillText("mdev", padL + 14, padT + 5);
  }

  const PIE_SPACING = 0.035;
  const PIE_EASE = 7;
  const PIE_SPIN_RATE = 8;
  const donutStates = new WeakMap();
  let pieTip = null;

  function pieTipEl() {
    if (!pieTip) {
      pieTip = document.createElement("div");
      pieTip.className = "pie-tip";
      document.body.appendChild(pieTip);
    }
    return pieTip;
  }
  function showPieTip(e, slice, total, bytes) {
    const tip = pieTipEl();
    const pct = total ? Math.round((slice.value / total) * 100) : 0;
    const val = bytes ? formatBytes(slice.value) : formatNumber(slice.value);
    tip.innerHTML = `<span class="pie-tip-dot" style="background:${slice.color};box-shadow:0 0 8px ${slice.color}"></span><b>${esc(slice.label)}</b><span class="pie-tip-val">${val} · ${pct}%</span>`;
    tip.style.display = "block";
    tip.style.left = (e.clientX + 16) + "px";
    tip.style.top = (e.clientY + 16) + "px";
    tip.style.setProperty("--tip-accent", slice.color);
  }
  function hidePieTip() {
    if (pieTip) pieTip.style.display = "none";
  }

  function shadeColor(hex, amt) {
    const n = parseInt(hex.slice(1), 16);
    const r = Math.min(255, Math.max(0, (n >> 16) + amt));
    const g = Math.min(255, Math.max(0, ((n >> 8) & 0xff) + amt));
    const b = Math.min(255, Math.max(0, (n & 0xff) + amt));
    return `rgb(${r},${g},${b})`;
  }

  function donutGeometry(rect, shownCount) {
    const w = rect.width, h = rect.height;
    const legendBlock = shownCount * 12;
    const cx = w / 2;
    const cy = (h - legendBlock) / 2;
    const donutR = Math.max(16, Math.min(w / 2 - 10, cy - 8, 62));
    const innerR = Math.max(8, donutR * 0.6);
    const thickness = donutR - innerR;
    return { cx, cy, donutR, innerR, thickness, midR: innerR + thickness / 2 };
  }

  function donutState(canvas) {
    let st = donutStates.get(canvas);
    if (!st) {
      st = {
        shown: [],
        total: 0,
        center: "",
        totalLabel: "",
        target: [],
        current: [],
        spin: 0,
        raf: 0,
        last: 0,
        hover: -1,
        wasVisible: false,
      };
      canvas.addEventListener("mousemove", (e) => donutHoverMove(canvas, st, e));
      canvas.addEventListener("mouseleave", () => {
        st.hover = -1;
        hidePieTip();
        if (st.total > 0) donutDraw(canvas, st);
      });
      donutStates.set(canvas, st);
    }
    return st;
  }

  function donutDraw(canvas, st) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, rect.width, rect.height);

    if (!st.total) {
      ctx.fillStyle = cssVar("--muted", "#8b949e");
      ctx.font = "11px sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText("No data yet", rect.width / 2, rect.height / 2);
      return;
    }

    const g = donutGeometry(rect, st.shown.length);
    const spacing = st.shown.length > 1 ? PIE_SPACING : 0;
    let acc = 0;
    const arcs = st.shown.map((s, i) => {
      const a = st.current[i] != null ? st.current[i] : 0;
      const half = Math.min(spacing / 2, a * 0.25);
      const arc = { from: acc + half, to: acc + a - half, s };
      acc += a;
      return arc;
    });

    const start = -Math.PI / 2 + st.spin;

    // --- Track ring (dark background) ---
    ctx.beginPath();
    ctx.arc(g.cx, g.cy, g.midR, 0, Math.PI * 2);
    ctx.strokeStyle = hexToRgba(cssVar("--border", "#2d333b"), 0.9);
    ctx.lineWidth = g.thickness;
    ctx.lineCap = "butt";
    ctx.stroke();

    // --- Main segment arcs ---
    ctx.lineCap = "round";
    arcs.forEach((arc, i) => {
      const hot = st.hover === i;
      if (arc.to <= arc.from) return;
      ctx.beginPath();
      ctx.arc(g.cx, g.cy, g.midR, start + arc.from, start + arc.to);
      ctx.strokeStyle = hot ? shadeColor(arc.s.color, 30) : arc.s.color;
      ctx.lineWidth = hot ? g.thickness + 6 : g.thickness;
      ctx.stroke();

      // Inner highlight — bright thin arc near inner edge
      ctx.save();
      ctx.globalAlpha = hot ? 0.55 : 0.22;
      ctx.beginPath();
      ctx.arc(g.cx, g.cy, g.innerR + 2, start + arc.from + 0.04, start + arc.to - 0.04);
      ctx.strokeStyle = shadeColor(arc.s.color, 60);
      ctx.lineWidth = 1.5;
      ctx.lineCap = "round";
      ctx.stroke();
      ctx.restore();
    });

    // --- Center gradient circle ---
    const cGrad = ctx.createRadialGradient(g.cx, g.cy - 4, 2, g.cx, g.cy, g.innerR - 2);
    const topColor = st.shown[st.hover >= 0 ? st.hover : 0]?.color || cssVar("--accent", "#4f8cff");
    cGrad.addColorStop(0, hexToRgba(topColor, 0.12));
    cGrad.addColorStop(1, hexToRgba(topColor, 0.02));
    ctx.beginPath();
    ctx.arc(g.cx, g.cy, g.innerR - 2, 0, Math.PI * 2);
    ctx.fillStyle = cGrad;
    ctx.fill();

    // --- Center text ---
    const numSize  = Math.round(g.innerR * 0.52);
    const lblSize  = Math.round(g.innerR * 0.27);
    const numY     = g.cy - lblSize * 0.6;
    const lblY     = g.cy + numSize * 0.55;

    // Big number — bold, coloured
    ctx.fillStyle = topColor;
    ctx.font = `800 ${numSize}px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(st.center, g.cx, numY);

    // Divider line
    ctx.save();
    ctx.globalAlpha = 0.18;
    ctx.beginPath();
    ctx.moveTo(g.cx - g.innerR * 0.45, g.cy + 1);
    ctx.lineTo(g.cx + g.innerR * 0.45, g.cy + 1);
    ctx.strokeStyle = cssVar("--muted", "#8b949e");
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.restore();

    // Sub-label — small caps feel, muted
    ctx.fillStyle = hexToRgba(cssVar("--muted", "#8b949e"), 0.75);
    ctx.font = `600 ${lblSize}px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText((st.totalLabel || formatNumber(st.total)).toUpperCase(), g.cx, lblY);

    // --- Legend ---
    const ly0 = rect.height - st.shown.length * 13 + 9;
    ctx.font = "11px sans-serif";
    const legDim = hexToRgba(cssVar("--muted", "#8b949e"), 0.35);
    st.shown.forEach((s, i) => {
      const ly = ly0 + i * 13;
      const dim = st.hover !== -1 && st.hover !== i;
      const dotAlpha = dim ? 0.3 : 1;
      // Rounded dot
      ctx.save();
      ctx.shadowBlur = dim ? 0 : 8;
      ctx.shadowColor = s.color;
      ctx.beginPath();
      ctx.arc(rect.width / 2 - 99, ly - 3, 4, 0, Math.PI * 2);
      ctx.fillStyle = hexToRgba(s.color, dotAlpha);
      ctx.fill();
      ctx.restore();
      // Label
      ctx.fillStyle = dim ? hexToRgba(cssVar("--text", "#e6edf3"), 0.35) : cssVar("--text", "#e6edf3");
      ctx.textAlign = "left";
      const label = s.label.length > 16 ? s.label.slice(0, 14) + "…" : s.label;
      ctx.fillText(label, rect.width / 2 - 90, ly);
      // Percentage
      ctx.fillStyle = dim ? hexToRgba(cssVar("--muted", "#8b949e"), 0.35) : hexToRgba(s.color, 0.9);
      ctx.textAlign = "right";
      ctx.font = "bold 11px sans-serif";
      ctx.fillText(Math.round((s.value / st.total) * 100) + "%", rect.width / 2 + 100, ly);
      ctx.font = "11px sans-serif";
    });
  }

  function donutTick(canvas, st, t) {
    st.raf = 0;
    const dt = st.last ? Math.min((t - st.last) / 1000, 0.1) : 0.016;
    st.last = t;
    if (st.spin > 0) st.spin = Math.max(0, st.spin - dt * PIE_SPIN_RATE);
    let animating = st.spin > 0;
    for (let i = 0; i < st.target.length; i++) {
      const cur = st.current[i] != null ? st.current[i] : 0;
      const tgt = st.target[i];
      if (Math.abs(tgt - cur) > 0.0006) {
        st.current[i] = cur + (tgt - cur) * Math.min(1, dt * PIE_EASE);
        animating = true;
      } else {
        st.current[i] = tgt;
      }
    }
    st.current.length = st.target.length;
    donutDraw(canvas, st);
    if (animating) st.raf = requestAnimationFrame((tt) => donutTick(canvas, st, tt));
  }

  function donutHoverMove(canvas, st, e) {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    let idx = -1;
    if (st.total > 0 && rect.width >= 10) {
      const g = donutGeometry(rect, st.shown.length);
      const dist = Math.hypot(x - g.cx, y - g.cy);
      if (dist >= g.innerR - 2 && dist <= g.donutR + 8) {
        const a = (Math.atan2(y - g.cy, x - g.cx) + Math.PI * 2) % (Math.PI * 2);
        const start = ((-Math.PI / 2 + st.spin) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2);
        const rel = (a - start + Math.PI * 2) % (Math.PI * 2);
        const spacing = st.shown.length > 1 ? PIE_SPACING : 0;
        let acc = 0;
        for (let i = 0; i < st.shown.length; i++) {
          const len = st.current[i] || 0;
          const half = Math.min(spacing / 2, len * 0.25);
          if (rel >= acc + half && rel <= acc + len - half) { idx = i; break; }
          acc += len;
        }
      }
    }
    if (idx !== st.hover) {
      st.hover = idx;
      if (st.total > 0) donutDraw(canvas, st);
    }
    if (idx >= 0) {
      showPieTip(e, st.shown[idx], st.total, !!st.totalLabel);
    } else {
      hidePieTip();
    }
  }

  function drawDonut(canvas, slices, centerLabel, totalLabel) {
    const rect = canvas.getBoundingClientRect();
    const visNow = rect.width >= 10 && rect.height >= 10;

    const items = (slices || []).filter((s) => s && s.value > 0);
    const total = items.reduce((n, s) => n + s.value, 0);
    let shown = [];
    if (total > 0) {
      const MAX_LEGEND = 5;
      shown = items.slice(0, MAX_LEGEND);
      const rest = items.slice(MAX_LEGEND);
      if (rest.length) {
        shown.push({
          label: "Other",
          value: rest.reduce((n, s) => n + s.value, 0),
          color: cssVar("--muted", "#8b949e"),
        });
      }
    }

    const st = donutState(canvas);
    st.shown = shown;
    st.total = total;
    st.center = centerLabel || "";
    st.totalLabel = totalLabel || "";
    st.target = shown.map((s) => (s.value / total) * Math.PI * 2);

    if (visNow && !st.wasVisible) {
      st.wasVisible = true;
      st.current = st.target.map(() => 0);
      st.spin = Math.PI * 2;
    }
    st.wasVisible = visNow;

    if (!st.total) {
      if (st.raf) { cancelAnimationFrame(st.raf); st.raf = 0; }
      donutDraw(canvas, st);
      return;
    }
    if (!st.raf) {
      st.last = performance.now();
      st.raf = requestAnimationFrame((t) => donutTick(canvas, st, t));
    }
  }

  function mergeInterfaceHistory(interfaces) {
    const byTs = new Map();
    for (const iface of interfaces || []) {
      for (const s of iface.history || []) {
        const cur = byTs.get(s[0]);
        if (cur) {
          cur[1] += s[1];
          cur[2] += s[2];
        } else {
          byTs.set(s[0], [s[0], s[1], s[2]]);
        }
      }
    }
    return [...byTs.values()].sort((a, b) => a[0] - b[0]);
  }

  function ovPie(canvas, slices, centerLabel, totalLabel) {
    requestAnimationFrame(() => drawDonut(canvas, slices, centerLabel, totalLabel));
  }

  function renderOverview(d) {
    state.ovData = d;
    const sys = d.sys || {};
    const usage = sys.usage || {};
    const mem = sys.mem || {};
    const disk = sys.disk || {};
    const bw = d.bw || {};
    const dns = d.dns || {};
    const sec = d.sec || {};
    const fw = d.fw || {};

    els.ovCpu.textContent = (usage.cpu_pct != null ? Math.round(usage.cpu_pct) : "—") + "%";
    els.ovCpu.title = "Load: " + ((sys.load || []).map((x) => x.toFixed(2)).join(" / ") || "—");
    els.ovMem.textContent = usage.mem_pct != null
      ? Math.round(usage.mem_pct) + "%"
      : (mem.total ? Math.round(mem.used / mem.total * 100) + "%" : "—");
    els.ovMem.title = mem.total ? `${formatBytes(mem.used)} / ${formatBytes(mem.total)}` : "";
    els.ovDisk.textContent = usage.disk_pct != null
      ? Math.round(usage.disk_pct) + "%"
      : (disk.total ? Math.round(disk.used / disk.total * 100) + "%" : "—");
    els.ovDisk.title = disk.total ? `${formatBytes(disk.used)} / ${formatBytes(disk.total)}` : "";
    els.ovUptime.textContent = formatUptime(sys.uptime);
    els.ovClients.textContent = formatNumber((d.leases || []).length);
    els.ovFwBlocks.textContent = formatNumber((fw.traffic || {}).block || 0);
    els.ovAttacks.textContent = (sec.stats || {}).hits_1m != null
      ? `${formatNumber((sec.stats || {}).hits_1m)} / min`
      : "—";

    const lat = sys.latency || {};
    const fmtMs = (v) => (v == null ? "—" : v >= 100 ? Math.round(v) + " ms" : v.toFixed(1) + " ms");
    els.ovLatNow.textContent = fmtMs(lat.current_ms);
    els.ovLatNow.title = lat.target
      ? `Ping to ${lat.target} | batch max: ${fmtMs(lat.current_max_ms)} | 24h baseline: ${fmtMs(lat.baseline_ms)}`
      : "";
    const peak = lat.peak_1h_ms || 0;
    const base = lat.baseline_ms || 0;
    els.ovLatPeak.textContent = fmtMs(peak > 0 ? peak : null);
    els.ovLatPeak.title =
      base > 0 && peak > base * 2
        ? `Spike detected: ${Math.round((peak / base - 1) * 100)}% above 24h baseline`
        : "Highest single ping in the last hour";
    els.ovLatPeak.style.color = base > 0 && peak > base * 2 ? cssVar("--red", "#f85149") : "";
    els.ovLatLoss.textContent = lat.loss_1h_pct != null ? lat.loss_1h_pct + "%" : "—";
    els.ovLatLoss.title = "Average packet loss over the last hour";
    els.ovLatJitter.textContent = fmtMs(lat.jitter_ms);
    els.ovLatJitter.title = "Mean deviation of recent ping batches (last 10 min)";

    const dnsT = dns.totals || {};
    const dnsOk = !!(dns.ok && dnsT.queries);
    const blocked = dnsT.nxdomain || 0;
    const allowed = Math.max(0, (dnsT.queries || 0) - blocked);
    els.ovDnsBlocked.textContent = dnsOk && dnsT.nxdomain != null
      ? Math.round(blocked / Math.max(1, dnsT.queries) * 100) + "%"
      : (dnsT.queries ? formatNumber(dnsT.queries) : "—");
    els.ovDnsBlocked.title = dnsOk && dnsT.nxdomain != null
      ? `${formatNumber(blocked)} blocked (NXDOMAIN) of ${formatNumber(dnsT.queries)} queries`
      : "Total queries";

    const pieGreen = cssVar("--green", "#3fb950");
    const pieRed = cssVar("--red", "#f85149");
    const pieBlue = cssVar("--accent", "#4f8cff");
    const pieAmber = cssVar("--amber", "#d29922");
    const memSlices = [
      { label: "Used", value: mem.used || 0, color: pieRed },
      { label: "Free", value: (mem.available || mem.total || 0), color: pieGreen },
    ];
    const fwSlices = [
      { label: "Allow", value: (fw.traffic || {}).allow || 0, color: pieGreen },
      { label: "Block", value: (fw.traffic || {}).block || 0, color: pieRed },
    ];
    const sinkholeSlices = [
      { label: "Allowed", value: allowed, color: pieGreen },
      { label: "Blocked", value: blocked, color: pieRed },
    ];
    const ipvSlices = [
      { label: "IPv4", value: Math.max(0, (dnsT.queries || 0) - (dnsT.ipv6 || 0)), color: pieBlue },
      { label: "IPv6", value: dnsT.ipv6 || 0, color: "#39c5cf" },
    ];
    const cacheSlices = [
      { label: "Cache hit", value: dnsT.cachehits || 0, color: pieGreen },
      { label: "Cache miss", value: dnsT.cachemiss || 0, color: pieAmber },
    ];

    const qtypeSlices = (dns.qtypes || []).map((q, i) => ({
      label: q.label, value: q.count, color: CHART_COLORS[i % CHART_COLORS.length],
    }));
    const countrySlices = (sec.countries || []).map((c, i) => ({
      label: c.name, value: c.count, color: CHART_COLORS[i % CHART_COLORS.length],
    }));

    const ifaces = bw.interfaces || [];
    const totDown = ifaces.reduce((n, i) => n + (i.rx_total || 0), 0);
    const totUp = ifaces.reduce((n, i) => n + (i.tx_total || 0), 0);
    const bwSlices = [
      { label: "Down", value: totDown, color: pieBlue },
      { label: "Up", value: totUp, color: pieAmber },
    ];

    ovPie(els.ovPieSinkhole, sinkholeSlices, blocked && allowed ? Math.round(blocked / (blocked + allowed) * 100) + "% blocked" : "");
    ovPie(els.ovPieQtypes, qtypeSlices, formatNumber(dnsT.queries));
    ovPie(els.ovPieIpv, ipvSlices, dnsT.ipv6 ? Math.round((dnsT.ipv6 / Math.max(1, dnsT.queries)) * 100) + "% v6" : "");
    ovPie(els.ovPieMem, memSlices, mem.total ? Math.round((mem.used || 0) / mem.total * 100) + "% used" : "");
    ovPie(els.ovPieFw, fwSlices, "");
    ovPie(els.ovPieCountries, countrySlices, formatNumber((sec.stats || {}).unique_ips || 0));
    ovPie(els.ovPieBw, bwSlices, "", formatBytes(totDown + totUp));
    ovPie(els.ovPieCache, cacheSlices, dnsT.hitrate != null ? Math.round(dnsT.hitrate * 100) + "% hit" : "");

    els.ovResHint.textContent = sys.uptime != null
      ? `Last ${Math.round(SYSTEM_WINDOW / 60)} minutes · 5s samples` : "";
    requestAnimationFrame(() => {
      drawResourceChart(els.ovResChart, (sys.history || []).map((s) => s));
    });

    els.ovBwHint.textContent = ifaces.length
      ? `${ifaces.map((i) => i.name).join(", ")} · ${Math.round(bw.max_samples * bw.interval / 60)} min window`
      : "Collecting samples…";
    const merged = mergeInterfaceHistory(ifaces);
    let maxBps = 1;
    for (const s of merged) {
      if (s[1] > maxBps) maxBps = s[1];
      if (s[2] > maxBps) maxBps = s[2];
    }
    requestAnimationFrame(() => {
      drawBandwidth(els.ovBwChart, merged, maxBps);
    });

    els.ovLatHint.textContent = (d.latHistory || []).length
      ? `ping ${((sys.latency || {}).target || "")} · 24h window`
      : "Collecting samples…";
    requestAnimationFrame(() => {
      drawLatencyChart(els.ovLatChart, d.latHistory || [], base);
    });

    els.ovJitHint.textContent = (d.latHistory || []).length
      ? `ping ${((sys.latency || {}).target || "")} · 24h window`
      : "Collecting samples…";
    requestAnimationFrame(() => {
      drawJitterChart(els.ovJitChart, d.latHistory || []);
    });

    renderAttackMap(ovMap, sec.by_ip || []);
    els.ovGeoHint.textContent = (sec.geo_db && sec.geo_db.hint) || `${formatNumber((sec.stats || {}).unique_ips || 0)} attack sources`;

    const clients = (bw.clients || []).slice(0, 6).sort((a, b) => (b.rx_bytes_per_s || 0) - (a.rx_bytes_per_s || 0));
    els.ovTalkersBody.innerHTML = clients.length
      ? clients.map((c) => `
        <tr>
          <td><span class="mono">${esc(c.ip)}</span>${c.hostname ? `<span class="muted"> · ${esc(c.hostname)}</span>` : ""}</td>
          <td>${formatMBs(c.rx_bytes_per_s)}</td>
          <td>${formatMBs(c.tx_bytes_per_s)}</td>
        </tr>`).join("")
      : `<tr><td colspan="3" class="empty">No client traffic yet.</td></tr>`;

    const sur = d.sur || {};
    els.ovSuricataHint.textContent = sur.enabled ? `${formatNumber(sur.count_24h)} alerts in last 24h` : "not running";
    els.ovSuricataBody.innerHTML = sur.enabled && (sur.top || []).length
      ? (sur.top || []).slice(0, 6).map((a) => `
        <tr>
          <td><b>${esc(a.sig)}</b></td>
          <td><span class="badge sev-${esc(a.severity)}">${esc(a.severity)}</span></td>
          <td>${formatNumber(a.count)}</td>
        </tr>`).join("")
      : `<tr><td colspan="3" class="empty">${esc(sur.hint || "No Suricata alerts.")}</td></tr>`;
  }

  async function refreshOverview() {
    try {
      const [sys, bw, dns, sec, fw, sur, leaseResp, latHist] = await Promise.all([
        fetchJSON("/api/system"),
        fetchJSON("/api/bandwidth"),
        fetchJSON("/api/dns"),
        fetchJSON("/api/security"),
        fetchJSON("/api/firewall"),
        fetchJSON("/api/security/suricata"),
        fetchJSON("/api/leases"),
        fetchJSON("/api/latency/history?hours=24").catch(() => ({ series: [] })),
      ]);
      renderOverview({ sys, bw, dns, sec, fw, sur, leases: leaseResp.leases || [], latHistory: latHist.series || [] });
    } catch (err) {
      showBanner(true, "Overview error: " + err.message);
    }
  }

  function svcStatusBadge(s) {
    if (s.active === "active") return `<span class="badge badge-ok">${esc(s.active)} · ${esc(s.sub)}</span>`;
    if (s.active === "failed") return `<span class="badge badge-err">${esc(s.active)}</span>`;
    return `<span class="muted">${esc(s.active || "—")}</span>`;
  }

  const SVC_TAB_LABELS = { active: "Active", failed: "Failed / Stopped" };

  const SVC_ACTION_ICONS = {
    start: '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>',
    stop: '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path d="M6 6h12v12H6z"/></svg>',
    restart: '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path d="M13 3h-2v10h2V3zm4.83 2.17l-1.42 1.42A6.99 6.99 0 0 1 19 12c0 3.87-3.13 7-7 7s-7-3.13-7-7c0-1.93.78-3.68 2.05-4.95L5.64 5.63A8.95 8.95 0 0 0 3 12c0 4.97 4.03 9 9 9s9-4.03 9-9c0-2.62-1.12-4.98-2.91-6.63z"/></svg>',
    reload: '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path d="M12 6v3l4-4-4-4v3c-4.42 0-8 3.58-8 8 0 1.57.46 3.03 1.24 4.26L6.7 14.8A5.87 5.87 0 0 1 6 12c0-3.31 2.69-6 6-6zm6.76 1.74L17.3 9.2c.44.84.7 1.79.7 2.8 0 3.31-2.69 6-6 6v-3l-4 4 4 4v-3c4.42 0 8-3.58 8-8 0-1.57-.46-3.03-1.24-4.26z"/></svg>',
  };

  function svcTabCounts(rows) {
    const counts = { active: 0, failed: 0 };
    for (const s of rows) {
      if (s.active === "active") counts.active++;
      else counts.failed++;
    }
    return counts;
  }

  function svcMatchesTab(s) {
    if (state.svcTab === "active") return s.active === "active";
    return s.active !== "active";
  }

  function renderServices() {
    const rows = ((state.svcData || {}).services || []);
    const isAdmin = state.role === "admin";
    document.querySelectorAll("#svc-tabs .svc-tab").forEach((t) => {
      const n = svcTabCounts(rows)[t.dataset.tab] || 0;
      t.textContent = `${SVC_TAB_LABELS[t.dataset.tab] || t.dataset.tab} (${n})`;
    });
    const visible = rows.filter(svcMatchesTab);
    els.sysServicesBody.innerHTML = visible.length
      ? visible.map((s) => {
          let actions = "";
          if (isAdmin) {
            actions = s.active === "active"
              ? `<button class="btn btn-sm icon-btn" data-action="restart" data-unit="${esc(s.unit)}" type="button" title="Restart ${esc(s.unit)}" aria-label="Restart ${esc(s.unit)}">${SVC_ACTION_ICONS.restart}</button>
                 <button class="btn btn-sm icon-btn" data-action="reload" data-unit="${esc(s.unit)}" type="button" title="Reload ${esc(s.unit)}" aria-label="Reload ${esc(s.unit)}">${SVC_ACTION_ICONS.reload}</button>
                 <button class="btn btn-sm btn-danger icon-btn" data-action="stop" data-unit="${esc(s.unit)}" type="button" title="Stop ${esc(s.unit)}" aria-label="Stop ${esc(s.unit)}">${SVC_ACTION_ICONS.stop}</button>`
              : `<button class="btn btn-sm icon-btn" data-action="start" data-unit="${esc(s.unit)}" type="button" title="Start ${esc(s.unit)}" aria-label="Start ${esc(s.unit)}">${SVC_ACTION_ICONS.start}</button>`;
          }
          return `
        <tr>
          <td><b class="mono">${esc(s.unit)}</b></td>
          <td>${svcStatusBadge(s)}</td>
          <td>${esc(s.desc || "—")}</td>
          <td><div class="svc-actions">${actions}</div></td>
        </tr>`;
        }).join("")
      : `<tr><td colspan="4" class="empty">No services match this filter.</td></tr>`;
  }

  async function refreshServices() {
    try {
      state.svcData = await fetchJSON("/api/system/services");
      renderServices();
    } catch (err) {
      /* best-effort; system view may not be visible */
    }
  }

  function schedule() {
    if (state.timer) clearInterval(state.timer);
    state.timer = setInterval(() => {
      if (!document.hidden) {
        refresh();
        refreshDns();
        refreshDomains();
        refreshFirewall();
        refreshCrowdsec();
        refreshCustomBlocklist();
        refreshBlocklists();
        refreshSystem();
        refreshServices();
      }
    }, REFRESH_MS);
    if (state.bwTimer) clearInterval(state.bwTimer);
    state.bwTimer = setInterval(() => {
      if (!document.hidden && state.activeView === "bandwidth") {
        refreshBandwidth();
      }
    }, BANDWIDTH_POLL_MS);
    if (state.secTimer) clearInterval(state.secTimer);
    state.secTimer = setInterval(() => {
      if (!document.hidden && state.activeView === "security") {
        refreshSecurity();
        refreshSuricata();
      }
    }, SECURITY_POLL_MS);
    if (state.wgTimer) clearInterval(state.wgTimer);
    state.wgTimer = setInterval(() => {
      if (!document.hidden && state.activeView === "wireguard") {
        refreshWireguard();
      }
    }, WG_POLL_MS);
    if (state.ovTimer) clearInterval(state.ovTimer);
    state.ovTimer = setInterval(() => {
      if (!document.hidden && state.activeView === "overview") {
        refreshOverview();
      }
    }, OV_POLL_MS);
  }

  const THEME_STORAGE_KEY = "tuxwall-theme";
  const THEME_COLOR_KEYS = ["bg", "bg-elev", "card", "border", "text", "muted", "accent", "green", "red", "amber"];
  const THEME_SWATCH_KEYS = ["bg", "card", "border", "accent", "green", "amber", "red"];
  const BUILTIN_THEMES = [
    {
      id: "dark", name: "Dark", builtin: true, dark: true,
      colors: {
        bg: "#0f1419", "bg-elev": "#161b22", card: "#1c2333",
        border: "#2d333b", text: "#e6edf3", muted: "#8b949e",
        accent: "#4f8cff", green: "#3fb950", red: "#f85149",
        amber: "#d29922",
      },
    },
    {
      id: "light", name: "Light", builtin: true, dark: false,
      colors: {
        bg: "#f6f8fa", "bg-elev": "#ffffff", card: "#ffffff",
        border: "#d0d7de", text: "#1f2328", muted: "#59636e",
        accent: "#0969da", green: "#1a7f37", red: "#cf222e",
        amber: "#9a6700",
      },
    },
    {
      id: "nord", name: "Nord", builtin: true, dark: true,
      colors: {
        bg: "#2e3440", "bg-elev": "#3b4252", card: "#3b4252",
        border: "#4c566a", text: "#eceff4", muted: "#a7b1c2",
        accent: "#88c0d0", green: "#a3be8c", red: "#bf616a",
        amber: "#ebcb8b",
      },
    },
    {
      id: "dracula", name: "Dracula", builtin: true, dark: true,
      colors: {
        bg: "#282a36", "bg-elev": "#21222c", card: "#2f3141",
        border: "#44475a", text: "#f8f8f2", muted: "#a4a8bc",
        accent: "#bd93f9", green: "#50fa7b", red: "#ff5555",
        amber: "#ffb86c",
      },
    },
    {
      id: "gruvbox", name: "Gruvbox Dark", builtin: true, dark: true,
      colors: {
        bg: "#282828", "bg-elev": "#1d2021", card: "#32302f",
        border: "#504945", text: "#ebdbb2", muted: "#a89984",
        accent: "#fe8019", green: "#b8bb26", red: "#fb4934",
        amber: "#fabd2f",
      },
    },
    {
      id: "solarized-light", name: "Solarized Light", builtin: true, dark: false,
      colors: {
        bg: "#eee8d5", "bg-elev": "#fdf6e3", card: "#fdf6e3",
        border: "#dcd4ba", text: "#073642", muted: "#657b83",
        accent: "#268bd2", green: "#859900", red: "#dc322f",
        amber: "#b58900",
      },
    },
    {
      id: "tokyo-night", name: "Tokyo Night", builtin: true, dark: true,
      colors: {
        bg: "#1a1b2e", "bg-elev": "#16213e", card: "#1f2b47",
        border: "#2a3a5c", text: "#c0caf5", muted: "#565f89",
        accent: "#7aa2f7", green: "#9ece6a", red: "#f7768e",
        amber: "#e0af68",
      },
    },
    {
      id: "catppuccin", name: "Catppuccin Mocha", builtin: true, dark: true,
      colors: {
        bg: "#1e1e2e", "bg-elev": "#181825", card: "#313244",
        border: "#45475a", text: "#cdd6f4", muted: "#6c7086",
        accent: "#89b4fa", green: "#a6e3a1", red: "#f38ba8",
        amber: "#fab387",
      },
    },
    {
      id: "cyberpunk", name: "Cyberpunk", builtin: true, dark: true,
      colors: {
        bg: "#0d0d1a", "bg-elev": "#12122b", card: "#1a1a3e",
        border: "#2a2a60", text: "#e8e8ff", muted: "#7a7aaa",
        accent: "#00f5ff", green: "#39ff14", red: "#ff0055",
        amber: "#ffcc00",
      },
    },
    {
      id: "emerald", name: "Emerald Dark", builtin: true, dark: true,
      colors: {
        bg: "#0d1a14", "bg-elev": "#121f19", card: "#1a2e22",
        border: "#274031", text: "#d4f0dc", muted: "#6a9e7a",
        accent: "#34d475", green: "#22c55e", red: "#f56565",
        amber: "#f6ad55",
      },
    },
    {
      id: "rose-pine", name: "Rosé Pine", builtin: true, dark: true,
      colors: {
        bg: "#191724", "bg-elev": "#1f1d2e", card: "#26233a",
        border: "#393552", text: "#e0def4", muted: "#6e6a86",
        accent: "#c4a7e7", green: "#9ccfd8", red: "#eb6f92",
        amber: "#f6c177",
      },
    },
    {
      id: "midnight", name: "Midnight Glass", builtin: true, dark: true,
      colors: {
        bg: "#080c14", "bg-elev": "#0e1521", card: "#111c2e",
        border: "#1e2d47", text: "#dce8f8", muted: "#5a7499",
        accent: "#60a5fa", green: "#34d399", red: "#f87171",
        amber: "#fbbf24",
      },
    },
  ];

  function findTheme(id) {
    return state.allThemes.find((t) => t.id === id)
      || BUILTIN_THEMES.find((t) => t.id === id)
      || null;
  }

  function applyThemeColors(theme) {
    const root = document.documentElement;
    THEME_COLOR_KEYS.forEach((k) => {
      root.style.setProperty(`--${k}`, theme.colors[k] || "");
    });
    document.body.classList.toggle("light-theme", theme.dark === false);
  }

  function cacheTheme(theme) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, JSON.stringify({ id: theme.id, theme }));
    } catch (err) { }
  }

  function repaintCharts() {
    if (!state.activeView || document.hidden) return;
    if (state.activeView === "overview" && state.ovData) renderOverview(state.ovData);
    else if (state.activeView === "bandwidth" && state.bwData) renderBandwidth(state.bwData);
    else if (state.activeView === "security") {
      refreshSecurity();
      refreshSuricata();
    } else if (state.activeView === "crowdsec") {
      refreshCrowdsec();
    }
  }

  async function applyTheme(id, opts) {
    const options = opts || {};
    const theme = findTheme(id);
    if (!theme) return false;
    state.activeTheme = theme.id;
    applyThemeColors(theme);
    cacheTheme(theme);
    if (options.persist !== false) {
      postJSON("/api/themes/active", { id: theme.id }).catch(() => {});
    }
    if (options.repaint !== false) repaintCharts();
    if (els.themeGrid) renderThemePicker();
    return true;
  }

  function renderThemePicker() {
    const themes = [...BUILTIN_THEMES, ...state.allThemes.filter((t) => !t.builtin)];
    els.themeGrid.innerHTML = themes.map((t) => `
      <div class="theme-card${t.id === state.activeTheme ? " active" : ""}" data-id="${esc(t.id)}" role="button" tabindex="0">
        <div class="theme-swatches">
          ${THEME_SWATCH_KEYS.map((k) => `<span class="theme-swatch" style="background:${esc(t.colors[k] || "#777777")}"></span>`).join("")}
        </div>
        <div class="theme-name">${esc(t.name)}${t.id === state.activeTheme ? ' <span class="theme-check">&#10003;</span>' : ""}</div>
        <div class="theme-meta">${t.builtin ? "Built-in" : "Custom"} &middot; ${t.dark === false ? "Light" : "Dark"}</div>
        ${t.builtin ? "" : `<button type="button" class="theme-del" data-del="${esc(t.id)}" title="Delete theme">&times;</button>`}
      </div>`).join("");
    const cur = findTheme(state.activeTheme);
    els.themeActiveHint.textContent = cur ? `${cur.name} (${cur.dark === false ? "light" : "dark"})` : "";
  }

  async function loadThemes() {
    try {
      const d = await fetchJSON("/api/themes");
      state.allThemes = d.themes || [];
      if (state.themeBootstrapped) {
        // Theme was already restored from localStorage — keep it and sync it
        // back to the server so the two stay in agreement.
        if (state.activeTheme && state.activeTheme !== d.active) {
          postJSON("/api/themes/active", { id: state.activeTheme }).catch(() => {});
        }
        renderThemePicker();
        return;
      }
      if (d.active && findTheme(d.active)) {
        await applyTheme(d.active, { persist: false });
        return;
      }
      renderThemePicker();
    } catch (err) {
      if (els.themeUploadMsg) els.themeUploadMsg.textContent = "Could not load themes: " + err.message;
    }
  }

  function bindSettings() {
    els.themeFormatSample.textContent = JSON.stringify({
      name: "My Theme",
      dark: false,
      colors: {
        bg: "#f6f8fa", "bg-elev": "#ffffff", card: "#ffffff",
        border: "#d0d7de", text: "#1f2328", muted: "#59636e",
        accent: "#0969da", green: "#1a7f37", red: "#cf222e",
        amber: "#9a6700",
      },
    }, null, 2);

    els.themeGrid.addEventListener("click", async (e) => {
      const del = e.target.closest(".theme-del");
      if (del) {
        e.stopPropagation();
        const id = del.dataset.del;
        const t = findTheme(id);
        if (!window.confirm(`Delete custom theme "${t ? t.name : id}"?`)) return;
        del.disabled = true;
        try {
          await postJSON("/api/themes/delete", { id });
          if (state.activeTheme === id) await applyTheme("dark", { persist: false });
          await loadThemes();
          els.themeUploadMsg.textContent = "";
        } catch (err) {
          els.themeUploadMsg.textContent = "Delete failed: " + err.message;
          del.disabled = false;
        }
        return;
      }
      const card = e.target.closest(".theme-card");
      if (card && card.dataset.id !== state.activeTheme) {
        applyTheme(card.dataset.id);
      }
    });

    els.themeGrid.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      const card = e.target.closest(".theme-card");
      if (card && !e.target.closest(".theme-del")) {
        e.preventDefault();
        applyTheme(card.dataset.id);
      }
    });

    els.themeUploadBtn.addEventListener("click", async () => {
      const file = els.themeFile.files && els.themeFile.files[0];
      if (!file) {
        els.themeUploadMsg.textContent = "Choose a .json theme file first.";
        return;
      }
      let parsed;
      try {
        parsed = JSON.parse(await file.text());
      } catch (err) {
        els.themeUploadMsg.textContent = "Not valid JSON: " + err.message;
        return;
      }
      els.themeUploadBtn.disabled = true;
      try {
        const d = await postJSON("/api/themes/upload", parsed);
        els.themeUploadMsg.textContent = `Installed "${d.theme.name}". Click its card above to apply it.`;
        els.themeFile.value = "";
        await loadThemes();
      } catch (err) {
        els.themeUploadMsg.textContent = "Upload failed: " + err.message;
      } finally {
        els.themeUploadBtn.disabled = false;
      }
    });
  }

  function switchView(view) {
    document.querySelectorAll(".nav-item").forEach((i) => {
      i.classList.toggle("active", i.dataset.view === view);
    });
    els.title.textContent = VIEW_TITLES[view] || "Dashboard";
    state.activeView = view;
    const implemented = view === "overview" || view === "clients" || view === "dns" || view === "domains" || view === "firewall" || view === "security" || view === "wireguard" || view === "crowdsec" || view === "bandwidth" || view === "blocklists" || view === "system" || view === "backups" || view === "logs" || view === "settings" || view === "ai";
    document.querySelectorAll(".view").forEach((v) => { v.hidden = true; });
    document.querySelectorAll(".pie-canvas").forEach((c) => {
      const st = donutStates.get(c);
      if (st) st.wasVisible = false;
    });
    hidePieTip();
    if (implemented) {
      document.getElementById("view-" + view).hidden = false;
      if (view === "overview") {
        initOverviewMap();
        refreshOverview();
        setTimeout(() => { if (ovMap) ovMap.map.invalidateSize(); }, 60);
      }
      if (view === "firewall") refreshFirewall();
      if (view === "domains") refreshDomains();
      if (view === "security") {
        initSecurityMap();
        refreshSecurity();
        refreshSuricata();
        setTimeout(() => { if (secMap) secMap.map.invalidateSize(); }, 60);
      }
      if (view === "crowdsec") {
        refreshCrowdsec();
        refreshCustomBlocklist();
      }
      if (view === "bandwidth") refreshBandwidth();
      if (view === "blocklists") refreshBlocklists();
      if (view === "system") {
        refreshSystem();
        refreshUpdates();
      }
      if (view === "logs") {
        loadLogSources();
        startLogTimer();
      } else {
        stopLogTimer();
      }
      if (view === "wireguard") refreshWireguard();
      if (view === "backups") {
        refreshBackups();
        refreshSystemBackups();
      }
      if (view === "settings") {
        loadThemes();
        if (state.isOwner) loadUsers();
      }
      els.soon.hidden = true;
      if (view === "ai") {
        const sel = document.getElementById("ai-model-select");
        if (sel && !sel.dataset.loaded) {
          sel.dataset.loaded = "1";
          loadAiPageConfig();
        }
      }
    } else {
      els.soon.hidden = false;
    }
  }

  // ================================================================
  // AI ASSISTANT
  // ================================================================
  (function aiChat() {
    const aiState = { messages: [], busy: false, inputTokens: 0, outputTokens: 0 };

    // Pricing per million tokens — covers common models
    const MODEL_PRICING = {
      "claude-opus-4-5":       { input: 15.00,  output: 75.00  },
      "claude-sonnet-4-5":     { input: 3.00,   output: 15.00  },
      "claude-haiku-3-5":      { input: 0.80,   output: 4.00   },
      "claude-3-5-sonnet-20241022": { input: 3.00, output: 15.00 },
      "claude-3-5-haiku-20241022":  { input: 0.80, output: 4.00  },
      "claude-3-opus-20240229":     { input: 15.00, output: 75.00 },
      "gpt-4o":                { input: 2.50,   output: 10.00  },
      "gpt-4o-mini":           { input: 0.15,   output: 0.60   },
      "gpt-4-turbo":           { input: 10.00,  output: 30.00  },
      "gpt-3.5-turbo":         { input: 0.50,   output: 1.50   },
    };

    function calcCost(model, inputTok, outputTok) {
      const key = Object.keys(MODEL_PRICING).find((k) => model && model.toLowerCase().includes(k.toLowerCase())) || null;
      if (!key) return null;
      const p = MODEL_PRICING[key];
      return (inputTok / 1e6) * p.input + (outputTok / 1e6) * p.output;
    }

    function formatCost(usd) {
      if (usd === null) return null;
      if (usd < 0.0001) return "<$0.0001";
      if (usd < 0.01)   return "$" + usd.toFixed(4);
      return "$" + usd.toFixed(4);
    }

    const elMessages  = document.getElementById("ai-messages");
    const elInput     = document.getElementById("ai-input");
    const elSendBtn   = document.getElementById("ai-send-btn");
    const elClearBtn  = document.getElementById("ai-clear-btn");
    const elModelSel  = document.getElementById("ai-model-select");
    const elStatus    = document.getElementById("ai-status-text");
    const elNotCfg    = document.getElementById("ai-not-configured");

    if (!elMessages) return; // view not in DOM yet

    // --- model list ---
    async function loadModels() {
      try {
        const d = await fetchJSON("/api/ai/chat/models");
        if (!d.ok || !d.models || !d.models.length) {
          if (elNotCfg) elNotCfg.hidden = false;
          return;
        }
        elModelSel.innerHTML = d.models.map((m) =>
          `<option value="${esc(m)}"${m === d.configured ? " selected" : ""}>${esc(m)}</option>`
        ).join("");
        if (elNotCfg) elNotCfg.hidden = true;
      } catch (_) {
        if (elNotCfg) elNotCfg.hidden = false;
      }
    }

    // --- markdown-lite renderer (bold, inline code, fenced code, bullets) ---
    function renderMarkdown(text) {
      let html = "";
      const lines = text.split("\n");
      let inCode = false, codeLang = "", codeBuf = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!inCode && line.startsWith("```")) {
          inCode = true; codeLang = line.slice(3).trim(); codeBuf = []; continue;
        }
        if (inCode) {
          if (line === "```") {
            html += `<pre class="ai-code-block"><code>${esc(codeBuf.join("\n"))}</code></pre>`;
            inCode = false; codeBuf = []; continue;
          }
          codeBuf.push(line); continue;
        }
        let l = esc(line);
        l = l.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
        l = l.replace(/`([^`]+)`/g, "<code class='ai-inline-code'>$1</code>");
        if (/^#{1,3}\s/.test(line)) {
          const lvl = line.match(/^(#+)/)[1].length;
          l = `<h${lvl} class="ai-resp-h">${l.replace(/^#+\s*/, "")}</h${lvl}>`;
        } else if (/^[-*]\s/.test(line)) {
          l = `<li>${l.slice(2)}</li>`;
        } else if (l.trim() === "") {
          l = "<br>";
        } else {
          l = `<p>${l}</p>`;
        }
        html += l;
      }
      if (inCode) html += `<pre class="ai-code-block"><code>${esc(codeBuf.join("\n"))}</code></pre>`;
      return html;
    }

    // --- parse <tuxwall-action> blocks out of AI response ---
    function parseActions(text) {
      const actions = [];
      const re = /<tuxwall-action>([\s\S]*?)<\/tuxwall-action>/g;
      let m;
      while ((m = re.exec(text)) !== null) {
        try { actions.push(JSON.parse(m[1].trim())); } catch (_) {}
      }
      return actions;
    }

    function stripActions(text) {
      return text.replace(/<tuxwall-action>[\s\S]*?<\/tuxwall-action>/g, "").trim();
    }

    // --- render a single action card ---
    function actionLabel(a) {
      switch (a.action) {
        case "block_ip":             return `🚫 Block IP <code>${esc(a.ip)}</code>`;
        case "unblock_ip":           return `✅ Unblock IP <code>${esc(a.ip)}</code>`;
        case "block_domain":         return `🚫 Block domain <code>${esc(a.domain)}</code>`;
        case "unblock_domain":       return `✅ Unblock domain <code>${esc(a.domain)}</code>`;
        case "restart_service":      return `🔄 Restart service <code>${esc(a.service)}</code>`;
        case "add_firewall_rule":    return `➕ Add UFW rule: <code>${esc(a.rule)}</code>`;
        case "delete_firewall_rule": return `🗑️ Delete UFW rule #<code>${esc(String(a.number))}</code>`;
        default: return `⚙️ <code>${esc(a.action)}</code>`;
      }
    }

    async function applyAction(a, btn) {
      btn.disabled = true;
      btn.textContent = "Applying…";
      try {
        let result = { ok: false, error: "Unknown action type" };

        if (a.action === "block_ip") {
          result = await postJSON("/api/security/ban", { ip: a.ip });

        } else if (a.action === "unblock_ip") {
          result = await postJSON("/api/security/unban", { ip: a.ip });

        } else if (a.action === "block_domain") {
          result = await postJSON("/api/domains/add", { name: a.domain, kind: "block" });

        } else if (a.action === "unblock_domain") {
          result = await postJSON("/api/domains/delete", { name: a.domain });

        } else if (a.action === "add_firewall_rule") {
          result = await postJSON("/api/firewall/allow", { rule: a.rule });

        } else if (a.action === "delete_firewall_rule") {
          result = await postJSON("/api/firewall/delete", { number: a.number });

        } else if (a.action === "restart_service") {
          result = await postJSON("/api/system/services/action", { unit: a.service, action: "restart" });
        }

        if (result.ok) {
          btn.textContent = "Applied ✓";
          btn.className = "ai-action-apply ai-action-done";
        } else {
          btn.textContent = "Failed: " + (result.error || "unknown");
          btn.disabled = false;
          btn.className = "ai-action-apply ai-action-err";
        }
      } catch (err) {
        btn.textContent = "Error: " + err.message;
        btn.disabled = false;
        btn.className = "ai-action-apply ai-action-err";
      }
    }

    // --- append a message bubble ---
    function appendMessage(role, text, actions) {
      // Remove welcome screen on first real message
      const welcome = elMessages.querySelector(".ai-welcome");
      if (welcome) welcome.remove();

      const wrap = document.createElement("div");
      wrap.className = `ai-msg ai-msg-${role}`;

      if (role === "assistant") {
        const clean = stripActions(text);
        const avatar = document.createElement("div");
        avatar.className = "ai-avatar";
        avatar.innerHTML = `<svg viewBox="0 0 24 24"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.38-1 1.73V7h2a7 7 0 0 1 7 7v1a3 3 0 0 1-2 2.83V19a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-2.17A3 3 0 0 1 2 14v-1a7 7 0 0 1 7-7h2V5.73A2 2 0 0 1 10 4a2 2 0 0 1 2-2zm-3 9a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zm6 0a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z"/></svg>`;
        const bubble = document.createElement("div");
        bubble.className = "ai-bubble";
        bubble.innerHTML = renderMarkdown(clean);

        // Action cards
        if (actions && actions.length) {
          const actDiv = document.createElement("div");
          actDiv.className = "ai-actions-wrap";
          actDiv.innerHTML = `<div class="ai-actions-label">Proposed changes</div>`;
          actions.forEach((a) => {
            const card = document.createElement("div");
            card.className = "ai-action-card";
            const lbl = document.createElement("span");
            lbl.className = "ai-action-lbl";
            lbl.innerHTML = actionLabel(a);
            if (a.comment) {
              const hint = document.createElement("span");
              hint.className = "ai-action-hint";
              hint.textContent = a.comment;
              card.appendChild(lbl);
              card.appendChild(hint);
            } else {
              card.appendChild(lbl);
            }
            const applyBtn = document.createElement("button");
            applyBtn.type = "button";
            applyBtn.className = "ai-action-apply";
            applyBtn.textContent = "Apply";
            applyBtn.addEventListener("click", () => applyAction(a, applyBtn));
            card.appendChild(applyBtn);
            actDiv.appendChild(card);
          });
          bubble.appendChild(actDiv);
        }
        wrap.appendChild(avatar);
        wrap.appendChild(bubble);
      } else {
        const bubble = document.createElement("div");
        bubble.className = "ai-bubble";
        bubble.textContent = text;
        wrap.appendChild(bubble);
      }

      elMessages.appendChild(wrap);
      elMessages.scrollTop = elMessages.scrollHeight;
      return wrap;
    }

    function setStatus(msg) {
      if (elStatus) elStatus.textContent = msg;
    }

    function setBusy(busy) {
      aiState.busy = busy;
      if (elSendBtn) elSendBtn.disabled = busy;
      if (elInput)   elInput.disabled   = busy;
      setStatus(busy ? "Thinking…" : "");
    }

    // --- typing indicator ---
    function showTyping() {
      const wrap = document.createElement("div");
      wrap.className = "ai-msg ai-msg-assistant ai-typing-wrap";
      wrap.innerHTML = `<div class="ai-avatar"><svg viewBox="0 0 24 24"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.38-1 1.73V7h2a7 7 0 0 1 7 7v1a3 3 0 0 1-2 2.83V19a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-2.17A3 3 0 0 1 2 14v-1a7 7 0 0 1 7-7h2V5.73A2 2 0 0 1 10 4a2 2 0 0 1 2-2zm-3 9a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zm6 0a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z"/></svg></div><div class="ai-bubble ai-typing"><span></span><span></span><span></span></div>`;
      elMessages.appendChild(wrap);
      elMessages.scrollTop = elMessages.scrollHeight;
      return wrap;
    }

    function updateUsageBar(lastIn, lastOut, model) {
      const bar = document.getElementById("ai-usage-bar");
      if (!bar) return;
      const totalIn  = aiState.inputTokens;
      const totalOut = aiState.outputTokens;
      const totalTok = totalIn + totalOut;
      const sessionCost = calcCost(model, totalIn, totalOut);
      const lastCost    = calcCost(model, lastIn, lastOut);
      const tokStr  = totalTok.toLocaleString() + " tokens";
      const costStr = sessionCost !== null ? " · " + formatCost(sessionCost) + " this session" : "";
      const lastStr = lastCost   !== null ? "Last reply: " + formatCost(lastCost) + " · " : "";
      bar.innerHTML =
        `<span class="ai-usage-last">${lastStr}${(lastIn + lastOut).toLocaleString()} tokens</span>` +
        `<span class="ai-usage-session">Session total: ${tokStr}${costStr}</span>`;
    }

    // --- send a message ---
    async function sendMessage(text) {
      text = text.trim();
      if (!text || aiState.busy) return;
      aiState.messages.push({ role: "user", content: text });
      appendMessage("user", text);
      if (elInput) { elInput.value = ""; elInput.style.height = "auto"; }
      setBusy(true);
      const typing = showTyping();
      try {
        const model = elModelSel ? elModelSel.value : "";
        const body = { messages: aiState.messages };
        if (model) body.model = model;
        const d = await postJSON("/api/ai/chat", body);
        typing.remove();
        if (!d.ok) {
          if (d.error === "not_configured" && elNotCfg) elNotCfg.hidden = false;
          appendMessage("assistant", "Sorry, I couldn't reach the AI: " + (d.error || "unknown error") + (d.hint ? "\n\n" + d.hint : ""), []);
        } else {
          const actions = parseActions(d.content);
          aiState.messages.push({ role: "assistant", content: d.content });
          appendMessage("assistant", d.content, actions);
          // Track usage
          const u = d.usage || {};
          const lastIn  = u.input_tokens  || 0;
          const lastOut = u.output_tokens || 0;
          aiState.inputTokens  += lastIn;
          aiState.outputTokens += lastOut;
          updateUsageBar(lastIn, lastOut, d.model || model);
        }
      } catch (err) {
        typing.remove();
        appendMessage("assistant", "Request failed: " + err.message, []);
      } finally {
        setBusy(false);
      }
    }

    // --- event bindings ---
    if (elSendBtn) {
      elSendBtn.addEventListener("click", () => sendMessage(elInput.value));
    }
    if (elInput) {
      elInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          sendMessage(elInput.value);
        }
      });
      elInput.addEventListener("input", () => {
        elInput.style.height = "auto";
        elInput.style.height = Math.min(elInput.scrollHeight, 180) + "px";
      });
    }
    if (elClearBtn) {
      elClearBtn.addEventListener("click", () => {
        aiState.messages = [];
        aiState.inputTokens = 0;
        aiState.outputTokens = 0;
        const bar = document.getElementById("ai-usage-bar");
        if (bar) bar.innerHTML = "";
        elMessages.innerHTML = "";
        const welcome = document.createElement("div");
        welcome.className = "ai-welcome";
        welcome.innerHTML = elMessages.closest("#view-ai").querySelector(".ai-welcome") ? "" :
          `<div class="ai-welcome-icon"><svg viewBox="0 0 24 24"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.38-1 1.73V7h2a7 7 0 0 1 7 7v1a3 3 0 0 1-2 2.83V19a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-2.17A3 3 0 0 1 2 14v-1a7 7 0 0 1 7-7h2V5.73A2 2 0 0 1 10 4a2 2 0 0 1 2-2zm-3 9a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zm6 0a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z"/></svg></div><h2>TuxWall AI Assistant</h2><p>Chat cleared. Ask me anything.</p>`;
        elMessages.appendChild(welcome);
      });
    }

    // Suggestion chips
    elMessages.addEventListener("click", (e) => {
      const s = e.target.closest(".ai-suggestion");
      if (s) sendMessage(s.textContent);
    });

    // Model loading is now handled in switchView() when view === "ai"
  })();

  function init() {
    els.search.addEventListener("input", (e) => {
      state.filter = e.target.value;
      render();
    });

    els.secSuricataTabs.addEventListener("click", (e) => {
      const btn = e.target.closest(".seg-btn");
      if (!btn || !btn.dataset.sev) return;
      if (btn.dataset.sev === state.suricataSev) return;
      state.suricataSev = btn.dataset.sev;
      els.secSuricataTabs.querySelectorAll(".seg-btn").forEach((b) =>
        b.classList.toggle("active", b.dataset.sev === state.suricataSev));
      refreshSuricata();
    });

    els.refresh.addEventListener("click", () => {
      refresh();
      refreshDns();
      refreshDomains();
      refreshFirewall();
      refreshSecurity();
      refreshSuricata();
      refreshCrowdsec();
      refreshCustomBlocklist();
      refreshBandwidth();
      refreshBlocklists();
      refreshSystem();
      refreshWireguard();
      refreshOverview();
    });

    els.auto.addEventListener("change", (e) => {
      if (e.target.checked) schedule();
      else if (state.timer) clearInterval(state.timer);
    });

    document.querySelectorAll("th.sortable").forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.dataset.sort;
        if (state.sortKey === key) {
          state.sortDir *= -1;
        } else {
          state.sortKey = key;
          state.sortDir = 1;
        }
        render();
      });
    });

    els.body.addEventListener("click", async (e) => {
      const btn = e.target.closest(".ban-btn, .unban-btn");
      if (!btn) return;
      const banning = btn.classList.contains("ban-btn");
      const label = btn.dataset.hostname || btn.dataset.ip;
      if (!window.confirm(
        banning
          ? `Ban ${label}? This blocks all internet access (firewall + DNS).`
          : `Unban ${label}?`
      )) return;
      btn.disabled = true;
      try {
        await postJSON(banning ? "/api/leases/ban" : "/api/leases/unban", {
          ip: btn.dataset.ip,
          hostname: btn.dataset.hostname,
          mac: btn.dataset.mac,
        });
        await refresh();
      } catch (err) {
        showBanner(true, (banning ? "Ban: " : "Unban: ") + err.message);
        btn.disabled = false;
      }
    });

    document.querySelectorAll(".nav-item").forEach((item) => {
      item.addEventListener("click", (e) => {
        e.preventDefault();
        switchView(item.dataset.view);
        if (history.replaceState) history.replaceState(null, "", "#" + item.dataset.view);
      });
    });

    window.addEventListener("resize", () => {
      if (state.activeView === "bandwidth" && state.bwData) {
        renderBandwidth(state.bwData);
      }
      if (state.activeView === "overview") {
        if (state.ovData) renderOverview(state.ovData);
        if (ovMap) ovMap.map.invalidateSize();
      }
      if (state.activeView === "security" && secMap) {
        secMap.map.invalidateSize();
      }
    });

    const initial = (location.hash || "#overview").replace("#", "");
    switchView(VIEW_TITLES[initial] ? initial : "overview");

    bindBlocklistActions();
    bindDomainActions();
    bindHostEdit();
    bindConfigEdit();
    bindUpdates();
    bindLogs();
    bindBackups();
    bindSystemBackups();
    bindWireguardActions();
    bindFirewallActions();
    bindAiSummary();
    bindSecurityBans();
    bindCustomBlocklist();
    bindSettings();

    let cachedTheme = null;
    try {
      cachedTheme = JSON.parse(localStorage.getItem(THEME_STORAGE_KEY) || "null");
    } catch (err) {
      cachedTheme = null;
    }
    if (cachedTheme && cachedTheme.theme && cachedTheme.theme.colors) {
      state.allThemes = [Object.assign({ builtin: false }, cachedTheme.theme)];
      applyTheme(cachedTheme.id, { persist: false, repaint: false });
      state.themeBootstrapped = true;
    }

    bindAuthActions();
    bindUsersActions();
    bootstrapAuth();

    // Online / Offline status indicator
    const brandStatusText = document.getElementById("brand-status-text");
    const brandStatusDot  = document.getElementById("brand-status-dot");
    function updateNetStatus() {
      const online = navigator.onLine;
      if (brandStatusText) brandStatusText.textContent = online ? "Online" : "Offline";
      if (brandStatusDot)  brandStatusDot.dataset.status = online ? "online" : "offline";
    }
    updateNetStatus();
    window.addEventListener("online",  updateNetStatus);
    window.addEventListener("offline", updateNetStatus);
  }

  function setLoginError(msg) {
    els.loginError.hidden = !msg;
    els.loginError.textContent = msg || "";
  }

  function showLoginGate(setupMode, errmsg) {
    els.loginHeading.textContent = setupMode ? "Welcome to TuxWall" : "TuxWall";
    els.loginSub.textContent = setupMode
      ? "Create the administrator account to secure this dashboard."
      : "Enter your credentials to manage this network";
    els.loginBtn.textContent = setupMode ? "Create & sign in" : "Sign in";
    setLoginError(errmsg || "");
    document.body.classList.add("locked");
    els.loginGate.hidden = false;
    setTimeout(() => {
      try { (setupMode ? els.loginUser : els.loginPass).focus(); } catch (err) { }
    }, 60);
  }

  function hideLoginGate() {
    els.loginGate.hidden = true;
    document.body.classList.remove("locked");
  }

  function applyDefaultPasswordWarning(flag) {
    if (!flag) return;
    els.pwMsg.textContent = "You are signed in with the default password (admin / tuxwall) - change it below.";
  }

  function roleLabel() {
    if (state.isOwner) return "primary admin";
    return state.role === "admin" ? "admin" : "read-only";
  }

  function applyRoleUI() {
    const isAdmin = state.role === "admin";
    document.querySelectorAll('.nav-item[data-view="settings"]').forEach((el) => {
      el.hidden = !isAdmin;
    });
    els.usersCard.hidden = !state.isOwner;
    els.sideUser.textContent = state.username || "";
    els.sideRole.textContent = roleLabel();
    if (!isAdmin && state.activeView === "settings") {
      switchView("overview");
    }
    if (state.data) render();
    if (state.svcData) renderServices();
  }

  async function loadUsers() {
    if (!state.isOwner) return;
    try {
      const d = await fetchJSON("/api/auth/users");
      renderUsers(d.users || []);
      els.usersMsg.textContent = "";
    } catch (err) {
      els.usersMsg.textContent = err.message;
    }
  }

  function renderUsers(users) {
    const me = state.username;
    els.usersTbody.innerHTML = users.map((u) => {
      const badge = u.owner
        ? `<span class="badge badge-static">Primary admin</span>`
        : u.role === "admin"
          ? `<span class="badge badge-ok">Admin</span>`
          : `<span class="badge">Viewer</span>`;
      const actions = u.owner ? `<span class="muted">—</span>` : `
        <button class="btn btn-sm" data-reset="${esc(u.username)}" type="button">Reset password</button>
        <button class="btn btn-sm btn-danger" data-del="${esc(u.username)}" type="button">Remove</button>`;
      return `
        <tr>
          <td><b>${esc(u.username)}</b>${u.username === me ? ` <span class="muted">(you)</span>` : ""}</td>
          <td>${badge}</td>
          <td>${actions}</td>
        </tr>`;
    }).join("");
  }

  function bindUsersActions() {
    els.nuAdd.addEventListener("click", async () => {
      const username = els.nuName.value.trim();
      const password = els.nuPass.value;
      if (!username || !password) {
        els.usersMsg.textContent = "Enter a username and password.";
        return;
      }
      els.nuAdd.disabled = true;
      try {
        await postJSON("/api/auth/users/add", { username, password, role: els.nuRole.value });
        els.usersMsg.textContent = `Added ${username}.`;
        els.nuName.value = "";
        els.nuPass.value = "";
        await loadUsers();
      } catch (err) {
        els.usersMsg.textContent = err.message;
      } finally {
        els.nuAdd.disabled = false;
      }
    });

    els.usersTbody.addEventListener("click", async (e) => {
      const del = e.target.closest("[data-del]");
      const rst = e.target.closest("[data-reset]");
      if (!del && !rst) return;
      const username = del ? del.dataset.del : rst.dataset.reset;
      try {
        if (del) {
          if (!window.confirm(`Remove user "${username}"? Their session ends immediately.`)) return;
          await postJSON("/api/auth/users/delete", { username });
          els.usersMsg.textContent = `Removed ${username}.`;
        } else {
          const pw = window.prompt(`New password for ${username} (min 8 characters):`);
          if (!pw) return;
          await postJSON("/api/auth/users/password", { username, password: pw });
          els.usersMsg.textContent = `Password updated for ${username}.`;
        }
        await loadUsers();
      } catch (err) {
        els.usersMsg.textContent = err.message;
      }
    });
  }

  function handleSessionExpired() {
    if (!state.authed) return;
    state.authed = false;
    state.role = "viewer";
    state.isOwner = false;
    els.logoutBtn.hidden = true;
    els.sideUser.textContent = "";
    els.sideRole.textContent = "";
    els.loginPass.value = "";
    showLoginGate(false, "Session expired. Sign in again.");
  }

  function bindAuthActions() {
    els.loginForm.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const username = els.loginUser.value.trim();
      const password = els.loginPass.value;
      if (!username || !password) {
        setLoginError("Enter a username and password.");
        return;
      }
      els.loginBtn.disabled = true;
      setLoginError("");
      try {
        const d = await postJSON("/api/auth/login", { username, password });
        els.loginPass.value = "";
        state.authed = true;
        state.role = d.role || "viewer";
        state.isOwner = !!d.is_owner;
        els.logoutBtn.hidden = false;
        state.username = d.username || username;
        els.acctHint.textContent = `Signed in as ${d.username || username} (${roleLabel()})`;
        applyDefaultPasswordWarning(d.default_password);
        applyRoleUI();
        hideLoginGate();
        startDashboard();
      } catch (err) {
        setLoginError(err.message);
      } finally {
        els.loginBtn.disabled = false;
      }
    });

    els.logoutBtn.addEventListener("click", async () => {
      try {
        await postJSON("/api/auth/logout", {});
      } catch (err) { }
      location.reload();
    });

    els.pwSave.addEventListener("click", async () => {
      const current = els.pwCurrent.value;
      const next = els.pwNew.value;
      if (!current || !next) {
        els.pwMsg.textContent = "Fill in both fields.";
        return;
      }
      if (next !== els.pwConfirm.value) {
        els.pwMsg.textContent = "New passwords do not match.";
        return;
      }
      els.pwSave.disabled = true;
      try {
        await postJSON("/api/auth/password", { current, new: next });
        els.pwMsg.textContent = "Password updated.";
        els.pwCurrent.value = els.pwNew.value = els.pwConfirm.value = "";
      } catch (err) {
        els.pwMsg.textContent = err.message;
      } finally {
        els.pwSave.disabled = false;
      }
    });
  }

  async function bootstrapAuth() {
    let d;
    try {
      d = await fetchJSON("/api/auth/session");
    } catch (err) {
      showLoginGate(false, "Cannot reach the dashboard API (" + err.message + ").");
      return;
    }
    if (!state.themeBootstrapped && d.active_theme && d.active_theme.colors) {
      state.allThemes = [Object.assign({ builtin: true }, d.active_theme)];
      applyTheme(d.active_theme.id, { persist: false, repaint: false });
    }
    if (!d.authenticated) {
      showLoginGate(!!d.setup_required);
      return;
    }
    state.authed = true;
    state.role = d.role || "viewer";
    state.isOwner = !!d.is_owner;
    els.logoutBtn.hidden = false;
    if (d.username) {
      state.username = d.username;
      els.acctHint.textContent = `Signed in as ${d.username} (${roleLabel()})`;
    }
    applyDefaultPasswordWarning(d.default_password);
    applyRoleUI();
    startDashboard();
  }

  function startDashboard() {
    schedule();
    refresh();
    refreshDns();
    refreshDomains();
    refreshFirewall();
    refreshSecurity();
    refreshSuricata();
    refreshCrowdsec();
    refreshCustomBlocklist();
    refreshBandwidth();
    refreshBlocklists();
    refreshSystem();
    refreshWireguard();
    refreshOverview();
    loadThemes();
    setInterval(refreshSystem, 60000);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
