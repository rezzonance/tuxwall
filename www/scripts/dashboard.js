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
    canManageUsers: false,
    users: [],
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
    fwLogging: document.getElementById("fw-logging-state"),
    fwSearch: document.getElementById("fw-search"),
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
    secEventsBody: null,
    secEventCount: null,
    secSuricataBody: document.querySelector("#sec-suricata-body"),
    secSuricataHint: document.getElementById("sec-suricata-hint"),
    secSuricataTabs: document.getElementById("sec-suricata-tabs"),
    secChart: document.getElementById("sec-chart"),
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
    bkSysCreate: document.getElementById("bk-sys-create"),
    bkSysBody: document.getElementById("bk-sys-body"),
    bkSysMsg: document.getElementById("bk-sys-msg"),
    bkSysProgress: document.getElementById("bk-sys-progress"),
    bkSysBar: document.getElementById("bk-sys-bar"),
    bkSysStatus: document.getElementById("bk-sys-status"),
    bkSysItems: document.getElementById("bk-sys-items"),
    bkSysAll: document.getElementById("bk-sys-all"),
    bkSysNone: document.getElementById("bk-sys-none"),
    bkSysContents: document.getElementById("bk-sys-contents"),
    bkSysFile: document.getElementById("bk-sys-file"),
    bkSysUpload: document.getElementById("bk-sys-upload"),
    bkSysContentsTitle: document.getElementById("bk-sys-contents-title"),
    bkSysFiles: document.getElementById("bk-sys-files"),
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
    ovWanIp: document.getElementById("ov-wan-ip"),
    ovWgPeers: document.getElementById("ov-wg-peers"),
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
    loginTotpLabel: document.getElementById("login-totp-label"),
    loginTotp: document.getElementById("login-totp"),
    logoutBtn: document.getElementById("logout-btn"),
    sideUser: document.getElementById("side-user"),
    sideRole: document.getElementById("side-role"),
    acctHint: document.getElementById("acct-hint"),
    pwOpen: document.getElementById("pw-open"),
    umCurrent: document.getElementById("um-current"),
    umCurrentField: document.getElementById("um-current-field"),
    usersCard: document.getElementById("users-card"),
    usersAdmin: document.getElementById("users-admin"),
    usersSearch: document.getElementById("users-search"),
    usersCount: document.getElementById("users-count"),
    usersTbody: document.getElementById("users-tbody"),
    nuOpen: document.getElementById("nu-open"),
    usersMsg: document.getElementById("users-msg"),
    totpCard: document.getElementById("totp-card"),
    totpBadge: document.getElementById("totp-badge"),
    totpStartBtn: document.getElementById("totp-start-btn"),
    totpEnroll: document.getElementById("totp-enroll"),
    totpQr: document.getElementById("totp-qr"),
    totpSecret: document.getElementById("totp-secret"),
    totpCode: document.getElementById("totp-code"),
    totpConfirmBtn: document.getElementById("totp-confirm-btn"),
    totpCancelBtn: document.getElementById("totp-cancel-btn"),
    totpDisableRow: document.getElementById("totp-disable-row"),
    totpDisablePass: document.getElementById("totp-disable-pass"),
    totpDisableCode: document.getElementById("totp-disable-code"),
    totpDisableBtn: document.getElementById("totp-disable-btn"),
    totpMsg: document.getElementById("totp-msg"),
    userModal: document.getElementById("user-modal"),
    userModalTitle: document.getElementById("user-modal-title"),
    userModalClose: document.getElementById("user-modal-close"),
    umName: document.getElementById("um-name"),
    umFullname: document.getElementById("um-fullname"),
    umPass: document.getElementById("um-pass"),
    umPass2: document.getElementById("um-pass2"),
    umPassField: document.getElementById("um-pass-field"),
    umPass2Field: document.getElementById("um-pass2-field"),
    umPassLabel: document.getElementById("um-pass-label"),
    umRole: document.getElementById("um-role"),
    umRoleField: document.getElementById("um-role-field"),
    umEnabled: document.getElementById("um-enabled"),
    umEnabledField: document.getElementById("um-enabled-field"),
    umMsg: document.getElementById("um-msg"),
    umSave: document.getElementById("um-save"),
    umCancel: document.getElementById("um-cancel"),
    routerLat: document.getElementById("router-lat"),
    routerLon: document.getElementById("router-lon"),
    routerLocSave: document.getElementById("router-loc-save"),
    routerLocMsg: document.getElementById("router-loc-msg"),
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
    vlans: "VLANs",
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

  async function fetchJSON(url, opts = {}) {
    const res = await fetch(url, { cache: "no-store", ...opts });
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
    // Also refresh reservations table if it's visible
    if (document.getElementById("reservations-card") &&
        !document.getElementById("reservations-card").closest(".view[hidden]")) {
      refreshReservations();
    }
  }

  // ── DHCP Reservations module ───────────────────────────────────────────────

  async function refreshReservations() {
    try {
      const data = await fetchJSON("/api/reservations");
      if (!data.ok) throw new Error(data.error);
      renderReservations(data.reservations || []);
    } catch (err) {
      document.getElementById("res-body").innerHTML =
        `<tr><td colspan="6" class="muted" style="text-align:center;padding:1.5rem">Error: ${esc(err.message)}</td></tr>`;
    }
  }

  function renderReservations(reservations) {
    const tbody = document.getElementById("res-body");
    if (!reservations.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="muted" style="text-align:center;padding:1.5rem">No static reservations configured</td></tr>`;
      return;
    }

    // Sort by IP numerically
    reservations.sort((a, b) => {
      const toNum = ip => ip.split(".").reduce((acc, o) => (acc << 8) + parseInt(o), 0);
      return toNum(a.ip) - toNum(b.ip);
    });

    tbody.innerHTML = reservations.map(r => {
      const onlineDot = r.online
        ? `<span class="dmz-dot dmz-dot-green" title="Online"></span>`
        : `<span class="dmz-dot dmz-dot-grey"  title="Offline / no ARP"></span>`;
      return `<tr>
        <td>${r.hostname ? `<span class="client-hostname">${esc(r.hostname)}</span>` : '<span class="muted">—</span>'}</td>
        <td class="mono">${esc(r.ip)}</td>
        <td class="mono">${esc(r.mac)}</td>
        <td class="muted" style="font-size:0.8rem">${esc(r.subnet)}</td>
        <td style="text-align:center">${onlineDot}</td>
        <td>
          <button class="btn btn-sm res-edit-btn"
            data-id="${esc(r.id)}" data-ip="${esc(r.ip)}"
            data-mac="${esc(r.mac)}" data-hostname="${esc(r.hostname)}">Edit</button>
          <button class="btn btn-sm btn-danger res-del-btn"
            data-id="${esc(r.id)}" data-ip="${esc(r.ip)}">Del</button>
        </td>
      </tr>`;
    }).join("");

    // Edit buttons
    document.querySelectorAll(".res-edit-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.getElementById("res-edit-id").value       = btn.dataset.id;
        document.getElementById("res-edit-ip").value       = btn.dataset.ip;
        document.getElementById("res-edit-mac").value      = btn.dataset.mac;
        document.getElementById("res-edit-hostname").value = btn.dataset.hostname;
        document.getElementById("res-edit-title").textContent = `Edit — ${btn.dataset.ip}`;
        document.getElementById("res-edit-hint").textContent  = "";
        document.getElementById("res-edit-modal").hidden = false;
      });
    });

    // Delete buttons
    document.querySelectorAll(".res-del-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        if (!confirm(`Delete reservation for ${btn.dataset.ip}?\nThe device will fall back to a dynamic lease.`)) return;
        btn.disabled = true;
        try {
          const r = await fetchJSON("/api/reservations/delete", {
            method: "POST", body: JSON.stringify({ id: btn.dataset.id })
          });
          if (!r.ok) throw new Error(r.error || "Failed");
          renderReservations(r.reservations || []);
        } catch (err) {
          alert("Error: " + err.message);
          btn.disabled = false;
        }
      });
    });
  }

  // Add reservation
  document.getElementById("res-add-btn").addEventListener("click", async () => {
    const btn      = document.getElementById("res-add-btn");
    const hint     = document.getElementById("res-hint");
    const mac      = document.getElementById("res-mac").value.trim();
    const ip       = document.getElementById("res-ip").value.trim();
    const hostname = document.getElementById("res-hostname").value.trim();

    hint.textContent = "";
    if (!mac || !ip) { hint.textContent = "MAC and IP are required."; return; }

    btn.disabled = true;
    hint.textContent = "Adding…";
    try {
      const r = await fetchJSON("/api/reservations/add", {
        method: "POST", body: JSON.stringify({ mac, ip, hostname })
      });
      if (!r.ok) throw new Error(r.error || "Failed");
      document.getElementById("res-mac").value      = "";
      document.getElementById("res-ip").value       = "";
      document.getElementById("res-hostname").value = "";
      hint.textContent = `✓ Reserved ${ip}`;
      renderReservations(r.reservations || []);
      render(); // refresh leases table to reflect static badge
    } catch (err) {
      hint.textContent = "Error: " + err.message;
    } finally {
      btn.disabled = false;
    }
  });

  // Edit modal save / close
  document.getElementById("res-edit-save").addEventListener("click", async () => {
    const btn      = document.getElementById("res-edit-save");
    const hint     = document.getElementById("res-edit-hint");
    const id       = document.getElementById("res-edit-id").value;
    const mac      = document.getElementById("res-edit-mac").value.trim();
    const hostname = document.getElementById("res-edit-hostname").value.trim();

    hint.textContent = "";
    btn.disabled = true;
    hint.textContent = "Saving…";
    try {
      const r = await fetchJSON("/api/reservations/edit", {
        method: "POST", body: JSON.stringify({ id, mac, hostname })
      });
      if (!r.ok) throw new Error(r.error || "Failed");
      document.getElementById("res-edit-modal").hidden = true;
      renderReservations(r.reservations || []);
    } catch (err) {
      hint.textContent = "Error: " + err.message;
      btn.disabled = false;
    }
  });

  ["res-edit-close", "res-edit-cancel"].forEach(id => {
    document.getElementById(id).addEventListener("click", () => {
      document.getElementById("res-edit-modal").hidden = true;
    });
  });

  // Auto-fill MAC from leases table when a client row is clicked
  document.getElementById("leases-body").addEventListener("click", e => {
    const row = e.target.closest("tr.client-row");
    if (!row) return;
    const ip  = row.querySelector("td:nth-child(2)")?.textContent?.trim() || "";
    const mac = row.querySelector("td:nth-child(3)")?.textContent?.trim() || "";
    if (!ip || !mac || mac === "—") return;
    const macIn = document.getElementById("res-mac");
    const ipIn  = document.getElementById("res-ip");
    // Only fill if fields are empty
    if (!macIn.value && !ipIn.value) {
      macIn.value = mac;
      ipIn.value  = ip;
      document.getElementById("reservations-card").scrollIntoView({ behavior: "smooth", block: "start" });
      macIn.focus();
    }
  });

  // Load reservations when clients view is first shown
  refreshReservations();

  // ── end DHCP Reservations module ───────────────────────────────────────────

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

  let _fwData = null;
  let _fwFilterText = "";
  let _fwFilterIface = "";   // "" = all, "__none__" = rules without iface

  function fwActionMeta(verb) {
    switch ((verb || "").toUpperCase()) {
      case "ALLOW":  return { cls: "fw-act-pass",   label: "Pass" };
      case "DENY":   return { cls: "fw-act-block",  label: "Block" };
      case "REJECT": return { cls: "fw-act-reject", label: "Reject" };
      case "LIMIT":  return { cls: "fw-act-limit",  label: "Limit" };
      default:       return { cls: "fw-act-pass",   label: verb || "?" };
    }
  }

  function fwRuleDirection(r) {
    if (r.direction) return r.direction;
    return (r.action || "").includes("OUT") ? "OUT" : "IN";
  }

  function renderFwRules() {
    if (!_fwData) return;
    const rules = _fwData.rules || [];
    const q = _fwFilterText.trim().toLowerCase();
    const rows = rules.filter((r) => {
      if (_fwFilterIface === "__none__" && r.iface) return false;
      if (_fwFilterIface && _fwFilterIface !== "__none__" && (r.iface || "") !== _fwFilterIface) return false;
      if (!q) return true;
      const hay = [r.number, r.to, r.from, r.action, r.iface, r.proto,
                   r.port, r.src, r.dst].join(" ").toLowerCase();
      return hay.includes(q);
    });
    if (!rows.length) {
      els.fwRulesBody.innerHTML = `<tr><td colspan="9" class="muted" style="text-align:center;padding:1.5rem">${rules.length ? "No rules match the current filter." : "No firewall rules configured."}</td></tr>`;
      return;
    }
    els.fwRulesBody.innerHTML = rows.map((r) => {
      const a = fwActionMeta(r.verb || (r.action || "").split(" ")[0]);
      const dir = fwRuleDirection(r);
      return `
      <tr>
        <td class="mono muted">${r.number != null ? r.number : "—"}</td>
        <td><span class="fw-act ${a.cls}">${a.label}</span></td>
        <td><span class="fw-dir fw-dir-${dir.toLowerCase()}">${dir}</span></td>
        <td>${r.iface ? `<span class="fw-iface mono">${esc(r.iface)}</span>` : `<span class="muted">any</span>`}</td>
        <td class="mono">${esc(r.src || r.from || "")}</td>
        <td class="mono">${esc(r.dst || r.to || "")}</td>
        <td class="mono">${r.port ? esc(r.port) : `<span class="muted">any</span>`}</td>
        <td>${r.proto ? `<span class="fw-proto-badge">${esc(r.proto)}</span>` : `<span class="muted">any</span>`}${r.v6 ? `<span class="fw-v6-badge">v6</span>` : ""}</td>
        <td>${r.number ? `<button class="btn btn-sm btn-danger fw-remove" type="button" data-num="${r.number}" title="Remove rule">✕</button>` : ""}</td>
      </tr>`;
    }).join("");
  }

  function renderFwIfaceChips() {
    if (!_fwData) return;
    const counts = {};
    let anyCount = 0;
    (_fwData.rules || []).forEach((r) => {
      if (r.iface) counts[r.iface] = (counts[r.iface] || 0) + 1;
      else anyCount++;
    });
    const ifaces = Object.keys(counts).sort();
    const box = document.getElementById("fw-iface-chips");
    const chipColors = { "": "var(--accent)", "__none__": "#a371f7" };
    const chipColor = (i) => chipColors[i] || ({ enp5s0: "var(--green)", enp6s0: "var(--amber)", wg0: "#39c5cf" }[i] || "#39c5cf");
    const chip = (label, val, count) =>
      `<button class="fw-chip${_fwFilterIface === val ? " active" : ""}" type="button" style="--fw-color:${chipColor(val)}" data-fw-iface="${esc(val)}">${esc(label)}${count ? ` <span class="fw-chip-n">${count}</span>` : ""}</button>`;
    box.innerHTML = chip("All", "", "") + chip("any iface", "__none__", anyCount) +
      ifaces.map((i) => chip(i, i, counts[i])).join("");
  }

  function fwLogLevel(d) {
    const lm = (d.logging || "").match(/\((low|medium|high|full)\)/i);
    if (lm) return lm[1].toLowerCase();
    return (d.logging || "").toLowerCase().startsWith("on") ? "low" : "off";
  }

  function renderFwSettings(d) {
    document.getElementById("fw-enabled-toggle").checked =
      (d.status || "").toLowerCase() === "active";
    document.getElementById("fw-def-incoming").value =
      (d.defaults.incoming || "deny").toLowerCase();
    document.getElementById("fw-def-outgoing").value =
      (d.defaults.outgoing || "allow").toLowerCase();
    document.getElementById("fw-log-level").value = fwLogLevel(d);
  }

  function renderFwTraffic(d) {
    const srcMax = (d.traffic.top_sources && d.traffic.top_sources[0])
      ? d.traffic.top_sources[0].count : 1;
    els.fwSourcesBody.innerHTML = (d.traffic.top_sources || []).map((s) => `
      <tr>
        <td class="mono">${esc(s.ip)}</td>
        <td>${formatNumber(s.count)}</td>
        <td><div class="bar"><div class="bar-fill bar-fill-err" style="width:${Math.round(s.count / srcMax * 100)}%"></div></div></td>
        <td><button class="btn btn-sm fw-block-src" type="button" data-ip="${esc(s.ip)}" title="Add a deny rule for this source">Block</button></td>
      </tr>`).join("") || `<tr><td colspan="4" class="muted" style="text-align:center;padding:1.5rem">No blocked sources in the recent log window</td></tr>`;

    const portMax = (d.traffic.top_ports && d.traffic.top_ports[0])
      ? d.traffic.top_ports[0].count : 1;
    els.fwPortsBody.innerHTML = (d.traffic.top_ports || []).map((p) => `
      <tr>
        <td class="mono">${esc(p.port)}</td>
        <td>${formatNumber(p.count)}</td>
        <td><div class="bar"><div class="bar-fill bar-fill-err" style="width:${Math.round(p.count / portMax * 100)}%"></div></div></td>
      </tr>`).join("") || `<tr><td colspan="3" class="muted" style="text-align:center;padding:1.5rem">No blocked ports in the recent log window</td></tr>`;

    els.fwEventsBody.innerHTML = (d.traffic.recent || []).map((e) => `
      <tr>
        <td class="mono">${esc(e.ts.split("T")[1]?.slice(0, 8) || e.ts)}</td>
        <td><span class="badge ${e.action === "BLOCK" ? "badge-err" : "badge-ok"}">${esc(e.action)}</span></td>
        <td class="mono">${esc(e.in || e.out || "—")}</td>
        <td class="mono">${esc(e.src)}</td>
        <td class="mono">${esc(e.dst)}</td>
        <td class="mono">${esc(e.dpt ? e.dpt + "/" + e.proto : e.proto || "—")}</td>
        <td>${e.action === "BLOCK" && e.src ? `<button class="btn btn-sm fw-block-src" type="button" data-ip="${esc(e.src)}" title="Add a deny rule for this source">Block</button>` : ""}</td>
      </tr>`).join("") || `<tr><td colspan="7" class="muted" style="text-align:center;padding:1.5rem">No recent events</td></tr>`;
  }

  function renderFirewall(d) {
    if (!d.ok) {
      showBanner(true, d.error || "Firewall stats unavailable");
      return;
    }
    _fwData = d;
    els.fwStatus.textContent = d.status ? d.status[0].toUpperCase() + d.status.slice(1) : "—";
    els.fwIncoming.textContent = d.defaults.incoming || "—";
    els.fwOutgoing.textContent = d.defaults.outgoing || "—";
    els.fwRules.textContent = formatNumber(d.rules.length);
    els.fwBlocks.textContent = formatNumber(d.traffic.block);
    els.fwAllows.textContent = formatNumber(d.traffic.allow);
    els.fwLogging.textContent = "Logging: " + fwLogLevel(d);
    renderFwRules();
    renderFwIfaceChips();
    renderFwTraffic(d);
    renderFwSettings(d);
  }

  // ── VLAN module ────────────────────────────────────────────────────────────

  let _vlanData = { vlans: [], parents: [], policies: [] };

  async function refreshVlans() {
    try {
      const data = await fetchJSON("/api/vlans");
      _vlanData = data;

      // Stat cards
      const up = data.vlans.filter(v => v.state === "UP").length;
      const parentSet = new Set(data.vlans.map(v => v.parent).filter(Boolean));
      document.getElementById("vlan-count").textContent    = data.vlans.length;
      document.getElementById("vlan-parents").textContent  = parentSet.size;
      document.getElementById("vlan-policies").textContent = data.policies.length;
      document.getElementById("vlan-up").textContent       = up;

      // Populate parent selects
      const parentSel = document.getElementById("vlan-parent-sel");
      const polSrc    = document.getElementById("pol-src");
      const polDst    = document.getElementById("pol-dst");
      parentSel.innerHTML = data.parents.map(p => `<option value="${esc(p)}">${esc(p)}</option>`).join("");

      const vlanIfaceOpts = `<option value="">Source interface</option>` +
        data.vlans.map(v => `<option value="${esc(v.iface)}">${esc(v.iface)} (VLAN ${esc(v.vlan_id)})</option>`).join("");
      polSrc.innerHTML = vlanIfaceOpts.replace("Source interface", "Source interface");
      polDst.innerHTML = vlanIfaceOpts.replace("Source interface", "Destination interface");

      // VLAN table
      const vtbody = document.querySelector("#vlan-table tbody");
      if (!data.vlans.length) {
        vtbody.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:1.5rem">No VLAN interfaces configured</td></tr>`;
      } else {
        vtbody.innerHTML = data.vlans.map(v => {
          const stateClass = v.state === "UP" ? "badge-green" : "badge-red";
          const addrs = v.addresses.length ? esc(v.addresses.join(", ")) : `<span class="muted">—</span>`;
          return `<tr data-iface="${esc(v.iface)}">
            <td class="mono">${esc(v.iface)}</td>
            <td><span class="vlan-vid-badge">${esc(v.vlan_id)}</span></td>
            <td class="mono">${esc(v.parent)}</td>
            <td class="mono">${addrs}</td>
            <td>${v.label ? esc(v.label) : `<span class="muted">—</span>`}</td>
            <td><span class="vlan-state ${stateClass}">${esc(v.state)}</span></td>
            <td class="muted">${esc(v.mtu)}</td>
            <td>
              <button class="btn btn-sm vlan-edit-btn" data-iface="${esc(v.iface)}"
                data-addr="${esc((v.addresses[0] || ""))}" data-label="${esc(v.label)}">Edit</button>
              <button class="btn btn-sm btn-danger vlan-del-btn" data-iface="${esc(v.iface)}">Del</button>
            </td>
          </tr>`;
        }).join("");
      }

      // Policy table
      const ptbody = document.querySelector("#pol-table tbody");
      if (!data.policies.length) {
        ptbody.innerHTML = `<tr><td colspan="7" class="muted" style="text-align:center;padding:1.5rem">No inter-VLAN policies configured</td></tr>`;
      } else {
        ptbody.innerHTML = data.policies.map(p => {
          const pClass = p.policy === "allow" ? "badge-green" : "badge-red";
          return `<tr>
            <td class="mono">${esc(p.src)}</td>
            <td class="mono">${esc(p.dst)}</td>
            <td><span class="vlan-state ${pClass}">${esc(p.policy.toUpperCase())}</span></td>
            <td class="muted">${esc(p.proto)}</td>
            <td class="muted">${p.port || "—"}</td>
            <td class="mono muted" style="font-size:0.75rem">${esc(p.rule)}</td>
            <td><button class="btn btn-sm btn-danger pol-del-btn" data-id="${esc(p.id)}">Del</button></td>
          </tr>`;
        }).join("");
      }

      _bindVlanEvents();
    } catch (err) {
      console.error("VLAN refresh error:", err);
    }
  }

  function _bindVlanEvents() {
    // Edit buttons
    document.querySelectorAll(".vlan-edit-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const iface = btn.dataset.iface;
        document.getElementById("vlan-edit-iface").value  = iface;
        document.getElementById("vlan-edit-addr").value   = btn.dataset.addr || "";
        document.getElementById("vlan-edit-label").value  = btn.dataset.label || "";
        document.getElementById("vlan-edit-title").textContent = `Edit ${iface}`;
        document.getElementById("vlan-edit-hint").textContent  = "";
        document.getElementById("vlan-edit-modal").hidden = false;
      });
    });

    // Delete VLAN buttons
    document.querySelectorAll(".vlan-del-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        const iface = btn.dataset.iface;
        if (!confirm(`Delete VLAN interface ${iface}? The interface will be removed immediately.`)) return;
        btn.disabled = true;
        try {
          const r = await fetchJSON("/api/vlans/delete", { method: "POST", body: JSON.stringify({ iface }) });
          if (!r.ok) throw new Error(r.error || "Failed");
          refreshVlans();
        } catch (err) {
          alert("Error: " + err.message);
          btn.disabled = false;
        }
      });
    });

    // Delete policy buttons
    document.querySelectorAll(".pol-del-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        if (!confirm("Remove this routing policy?")) return;
        btn.disabled = true;
        try {
          const r = await fetchJSON("/api/vlans/policy/delete", { method: "POST", body: JSON.stringify({ id: btn.dataset.id }) });
          if (!r.ok) throw new Error(r.error || "Failed");
          refreshVlans();
        } catch (err) {
          alert("Error: " + err.message);
          btn.disabled = false;
        }
      });
    });
  }

  // Add VLAN
  document.getElementById("vlan-add-btn").addEventListener("click", async () => {
    const btn     = document.getElementById("vlan-add-btn");
    const hint    = document.getElementById("vlan-add-hint");
    const parent  = document.getElementById("vlan-parent-sel").value.trim();
    const vid     = document.getElementById("vlan-vid-in").value.trim();
    const address = document.getElementById("vlan-addr-in").value.trim();
    const label   = document.getElementById("vlan-label-in").value.trim();

    hint.textContent = "";
    if (!parent || !vid) { hint.textContent = "Parent interface and VLAN ID are required."; return; }

    btn.disabled = true;
    hint.textContent = "Adding…";
    try {
      const r = await fetchJSON("/api/vlans/add", {
        method: "POST",
        body: JSON.stringify({ parent, vlan_id: Number(vid), address, label })
      });
      if (!r.ok) throw new Error(r.error || "Failed");
      document.getElementById("vlan-vid-in").value   = "";
      document.getElementById("vlan-addr-in").value  = "";
      document.getElementById("vlan-label-in").value = "";
      hint.textContent = `✓ ${r.iface} created`;
      refreshVlans();
    } catch (err) {
      hint.textContent = "Error: " + err.message;
    } finally {
      btn.disabled = false;
    }
  });

  // Edit modal save / cancel / close
  document.getElementById("vlan-edit-save").addEventListener("click", async () => {
    const btn   = document.getElementById("vlan-edit-save");
    const hint  = document.getElementById("vlan-edit-hint");
    const iface = document.getElementById("vlan-edit-iface").value;
    const addr  = document.getElementById("vlan-edit-addr").value.trim();
    const label = document.getElementById("vlan-edit-label").value.trim();

    hint.textContent = "";
    btn.disabled = true;
    hint.textContent = "Saving…";
    try {
      const r = await fetchJSON("/api/vlans/edit", {
        method: "POST",
        body: JSON.stringify({ iface, address: addr, label })
      });
      if (!r.ok) throw new Error(r.error || "Failed");
      document.getElementById("vlan-edit-modal").hidden = true;
      refreshVlans();
    } catch (err) {
      hint.textContent = "Error: " + err.message;
      btn.disabled = false;
    }
  });

  ["vlan-edit-close", "vlan-edit-cancel"].forEach(id => {
    document.getElementById(id).addEventListener("click", () => {
      document.getElementById("vlan-edit-modal").hidden = true;
    });
  });

  // Add routing policy
  document.getElementById("pol-add-btn").addEventListener("click", async () => {
    const btn   = document.getElementById("pol-add-btn");
    const hint  = document.getElementById("pol-hint");
    const src   = document.getElementById("pol-src").value;
    const dst   = document.getElementById("pol-dst").value;
    const policy = document.getElementById("pol-policy").value;
    const proto  = document.getElementById("pol-proto").value;
    const port   = document.getElementById("pol-port").value.trim();

    hint.textContent = "";
    if (!src || !dst) { hint.textContent = "Select source and destination interfaces."; return; }
    if (src === dst)  { hint.textContent = "Source and destination must differ."; return; }

    btn.disabled = true;
    hint.textContent = "Adding…";
    try {
      const r = await fetchJSON("/api/vlans/policy/add", {
        method: "POST",
        body: JSON.stringify({ src, dst, policy, proto, port })
      });
      if (!r.ok) throw new Error(r.error || "Failed");
      document.getElementById("pol-port").value = "";
      hint.textContent = "✓ Policy added";
      refreshVlans();
    } catch (err) {
      hint.textContent = "Error: " + err.message;
    } finally {
      btn.disabled = false;
    }
  });

  // ── end VLAN module ────────────────────────────────────────────────────────

  // ── Port Forwarding module ─────────────────────────────────────────────────

  async function refreshPortForward() {
    try {
      const [pfData, leaseData] = await Promise.all([
        fetchJSON("/api/portforward"),
        fetchJSON("/api/leases"),
      ]);

      // Populate internal IP dropdown with known hosts
      const ipSel = document.getElementById("pf-int-ip");
      const leases = (leaseData.leases || []).slice()
        .sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
      ipSel.innerHTML = leases.map(l => {
        const label = l.hostname ? `${esc(l.ip)} — ${esc(l.hostname)}` : esc(l.ip);
        return `<option value="${esc(l.ip)}">${label}</option>`;
      }).join("");

      // Render table
      const tbody = document.querySelector("#pf-table tbody");
      const rules = pfData.rules || [];
      if (!rules.length) {
        tbody.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:1.5rem">No port forwarding rules configured</td></tr>`;
        return;
      }
      tbody.innerHTML = rules.map(r => {
        const statusClass = r.active ? "pf-status-active" : "pf-status-inactive";
        const statusText  = r.active ? "Active" : "Inactive";
        const toggleLabel = r.enabled ? "Disable" : "Enable";
        const protoLabel  = r.proto === "both" ? "TCP+UDP" : r.proto.toUpperCase();
        return `<tr>
          <td>${r.label ? esc(r.label) : '<span class="muted">—</span>'}</td>
          <td><span class="pf-proto-badge">${esc(protoLabel)}</span></td>
          <td class="mono">${esc(r.ext_port)}</td>
          <td class="muted" style="font-size:1.1rem;text-align:center">→</td>
          <td class="mono">${esc(r.int_ip)}</td>
          <td class="mono">${esc(r.int_port)}</td>
          <td><span class="pf-status ${statusClass}">${statusText}</span></td>
          <td>
            <button class="btn btn-sm pf-toggle-btn" data-id="${esc(r.id)}" data-enabled="${r.enabled}">${toggleLabel}</button>
            <button class="btn btn-sm btn-danger pf-del-btn" data-id="${esc(r.id)}">Del</button>
          </td>
        </tr>`;
      }).join("");

      // Bind table buttons
      document.querySelectorAll(".pf-toggle-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
          btn.disabled = true;
          try {
            const r = await fetchJSON("/api/portforward/toggle", {
              method: "POST", body: JSON.stringify({ id: btn.dataset.id })
            });
            if (!r.ok) throw new Error(r.error || "Failed");
            refreshPortForward();
          } catch (err) { alert("Error: " + err.message); btn.disabled = false; }
        });
      });

      document.querySelectorAll(".pf-del-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
          if (!confirm("Delete this port forward rule?")) return;
          btn.disabled = true;
          try {
            const r = await fetchJSON("/api/portforward/delete", {
              method: "POST", body: JSON.stringify({ id: btn.dataset.id })
            });
            if (!r.ok) throw new Error(r.error || "Failed");
            refreshPortForward();
          } catch (err) { alert("Error: " + err.message); btn.disabled = false; }
        });
      });

    } catch (err) {
      console.error("Port forward refresh error:", err);
    }
  }

  document.getElementById("pf-add-btn").addEventListener("click", async () => {
    const btn     = document.getElementById("pf-add-btn");
    const hint    = document.getElementById("pf-hint");
    const extPort = document.getElementById("pf-ext-port").value.trim();
    const proto   = document.getElementById("pf-proto").value;
    const intIp   = document.getElementById("pf-int-ip").value;
    const intPort = document.getElementById("pf-int-port").value.trim() || extPort;
    const label   = document.getElementById("pf-label").value.trim();

    hint.textContent = "";
    if (!extPort || !intIp) { hint.textContent = "External port and internal host are required."; return; }

    btn.disabled = true;
    hint.textContent = "Adding…";
    try {
      const r = await fetchJSON("/api/portforward/add", {
        method: "POST",
        body: JSON.stringify({ ext_port: Number(extPort), proto, int_ip: intIp, int_port: Number(intPort), label })
      });
      if (!r.ok) throw new Error(r.error || "Failed");
      document.getElementById("pf-ext-port").value = "";
      document.getElementById("pf-int-port").value = "";
      document.getElementById("pf-label").value    = "";
      hint.textContent = "✓ Rule added";
      refreshPortForward();
    } catch (err) {
      hint.textContent = "Error: " + err.message;
    } finally {
      btn.disabled = false;
    }
  });

  // ── DMZ module ─────────────────────────────────────────────────────────────

  async function refreshDmz() {
    try {
      const data = await fetchJSON("/api/dmz");
      const clients = data.clients || [];
      const tbody = document.querySelector("#dmz-table tbody");

      if (!clients.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="muted" style="text-align:center;padding:1.5rem">No DHCP clients found</td></tr>`;
        return;
      }

      tbody.innerHTML = clients.map(c => {
        const onlineDot = c.online
          ? `<span class="dmz-dot dmz-dot-green" title="Online"></span>`
          : `<span class="dmz-dot dmz-dot-grey" title="Offline"></span>`;

        const staticBadge = c.has_reservation
          ? `<span class="dmz-badge dmz-badge-green">Static</span>`
          : `<span class="dmz-badge dmz-badge-amber" title="Add a DHCP reservation for reliable port forwarding">Dynamic</span>`;

        const dmzBadge = c.dmz_enabled
          ? `<span class="dmz-badge dmz-badge-red">DMZ ON</span>`
          : `<span class="dmz-badge dmz-badge-grey">Off</span>`;

        const btnClass = c.dmz_enabled ? "btn-danger" : "btn";
        const btnLabel = c.dmz_enabled ? "Disable DMZ" : "Enable DMZ";
        const btnTitle = c.dmz_enabled
          ? "Remove iptables isolation rules for this client"
          : c.has_reservation
            ? "Apply iptables FORWARD DROP rules — blocks this client from reaching other LAN hosts"
            : "⚠ No static reservation — enable anyway (IP may change on lease renewal)";

        return `<tr class="${c.dmz_enabled ? "dmz-row-active" : ""}">
          <td>${c.hostname ? esc(c.hostname) : '<span class="muted">—</span>'}</td>
          <td class="mono">${esc(c.ip)}</td>
          <td class="mono muted" style="font-size:0.78rem">${esc(c.mac)}</td>
          <td style="text-align:center">${onlineDot}</td>
          <td>${staticBadge}</td>
          <td>${dmzBadge}</td>
          <td>
            <button class="btn btn-sm ${btnClass} dmz-toggle-btn"
              data-ip="${esc(c.ip)}"
              data-enabled="${c.dmz_enabled}"
              title="${esc(btnTitle)}">${btnLabel}</button>
          </td>
        </tr>`;
      }).join("");

      // Bind toggle buttons
      document.querySelectorAll(".dmz-toggle-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
          const ip      = btn.dataset.ip;
          const enabled = btn.dataset.enabled === "true";
          const action  = enabled ? "disable" : "enable";

          if (!enabled) {
            const confirmed = confirm(
              `Enable DMZ isolation for ${ip}?\n\n` +
              `This will:\n` +
              `  • Block ${ip} from reaching other LAN hosts\n` +
              `  • Allow ${ip} to reach the gateway and internet\n` +
              `  • Allow inbound connections from the internet (via port forwards)\n\n` +
              `The rest of your network will NOT be able to initiate connections to ${ip}.`
            );
            if (!confirmed) return;
          } else {
            if (!confirm(`Disable DMZ isolation for ${ip}? The client will regain full LAN access.`)) return;
          }

          btn.disabled = true;
          try {
            const r = await fetchJSON(`/api/dmz/${action}`, {
              method: "POST", body: JSON.stringify({ ip })
            });
            if (!r.ok) throw new Error(r.error || "Failed");
            refreshDmz();
          } catch (err) {
            alert("Error: " + err.message);
            btn.disabled = false;
          }
        });
      });

    } catch (err) {
      console.error("DMZ refresh error:", err);
    }
  }

  // ── end Port Forwarding / DMZ module ──────────────────────────────────────

  async function refreshFirewall() {
    try {
      const data = await fetchJSON("/api/firewall");
      renderFirewall(data);
    } catch (err) {
      showBanner(true, "Firewall stats error: " + err.message);
    }
  }

  function bindFirewallActions() {
    // ── OPNsense-style sub-tabs ─────────────────────────────────────────
    document.querySelectorAll("#fw-subtabs .fw-subtab").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("#fw-subtabs .fw-subtab").forEach((b) =>
          b.classList.toggle("active", b === btn));
        document.querySelectorAll("#view-firewall .fw-pane").forEach((p) => {
          p.hidden = p.dataset.fwPane !== btn.dataset.fwPane;
        });
      });
    });

    // ── Add-rule modal ──────────────────────────────────────────────────
    const fwModal = document.getElementById("fw-add-modal");
    const fwModalHint = document.getElementById("fw-hint-modal");
    const fwCloseModal = () => { fwModal.hidden = true; };
    document.getElementById("fw-add-open").addEventListener("click", () => {
      fwModalHint.textContent = "";
      fwModal.hidden = false;
      els.fwPort.focus();
    });
    document.getElementById("fw-add-modal-close").addEventListener("click", fwCloseModal);
    document.getElementById("fw-add-cancel").addEventListener("click", fwCloseModal);
    fwModal.addEventListener("click", (e) => { if (e.target === fwModal) fwCloseModal(); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !fwModal.hidden) fwCloseModal();
    });

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
      fwModalHint.textContent = "";
      try {
        await postJSON("/api/firewall/allow", { rule });
        els.fwHint.textContent = "Rule added: " + rule;
        els.fwPort.value = "";
        els.fwFrom.value = "";
        fwModalHint.textContent = "";
        fwCloseModal();
        await refreshFirewall();
      } catch (err) {
        fwModalHint.textContent = "Error: " + err.message;
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
      els.fwHint.textContent = "baseline restored" +
        (res.verified ? "" : " — live rules differ from baseline, verify manually");
      await refreshFirewall();
      return res;
    }

    // ── Rules filtering: search + interface chips ───────────────────────
    els.fwSearch.addEventListener("input", () => {
      _fwFilterText = els.fwSearch.value;
      renderFwRules();
    });
    document.getElementById("fw-iface-chips").addEventListener("click", (e) => {
      const chip = e.target.closest(".fw-chip");
      if (!chip) return;
      _fwFilterIface = chip.dataset.fwIface || "";
      renderFwIfaceChips();
      renderFwRules();
    });

    // ── One-click block on traffic views ────────────────────────────────
    async function blockSource(ip) {
      if (!window.confirm(`Add a firewall rule blocking all traffic from ${ip}?`)) return;
      try {
        await postJSON("/api/firewall/allow", { rule: `deny from ${ip}` });
        els.fwHint.textContent = "Blocked source: " + ip;
        await refreshFirewall();
      } catch (err) {
        els.fwHint.textContent = "Error: " + err.message;
      }
    }
    [els.fwSourcesBody, els.fwEventsBody].forEach((tbody) => {
      if (!tbody) return;
      tbody.addEventListener("click", (e) => {
        const btn = e.target.closest(".fw-block-src");
        if (btn) blockSource(btn.dataset.ip);
      });
    });

    // ── Live view auto-refresh ──────────────────────────────────────────
    setInterval(() => {
      if (state.activeView !== "firewall") return;
      const active = document.querySelector("#fw-subtabs .fw-subtab.active");
      const live = document.getElementById("fw-live-toggle");
      if (active && active.dataset.fwPane === "traffic" && live && live.checked) {
        refreshFirewall();
      }
    }, 5000);

    // ── Settings pane ───────────────────────────────────────────────────
    document.getElementById("fw-settings-apply").addEventListener("click", async () => {
      const btn = document.getElementById("fw-settings-apply");
      const hint = document.getElementById("fw-settings-hint");
      if (!_fwData) return;
      const wantEnabled = document.getElementById("fw-enabled-toggle").checked;
      const wasEnabled = (_fwData.status || "").toLowerCase() === "active";
      const di = document.getElementById("fw-def-incoming").value;
      const dot = document.getElementById("fw-def-outgoing").value;
      const lv = document.getElementById("fw-log-level").value;
      hint.textContent = "";
      if (!wantEnabled && wasEnabled &&
          !window.confirm("Disable the firewall?\n\nThis turns off ALL packet filtering until re-enabled.")) {
        return;
      }
      btn.disabled = true;
      hint.textContent = "Applying…";
      try {
        if (wantEnabled !== wasEnabled) {
          await postJSON("/api/firewall/enable", { enabled: wantEnabled });
        }
        if (di !== (_fwData.defaults.incoming || "").toLowerCase()) {
          await postJSON("/api/firewall/default", { direction: "incoming", policy: di });
        }
        if (dot !== (_fwData.defaults.outgoing || "").toLowerCase()) {
          await postJSON("/api/firewall/default", { direction: "outgoing", policy: dot });
        }
        if (lv !== fwLogLevel(_fwData)) {
          await postJSON("/api/firewall/logging", { level: lv });
        }
        hint.textContent = "Settings applied.";
        await refreshFirewall();
      } catch (err) {
        hint.textContent = "Error: " + err.message;
      } finally {
        btn.disabled = false;
      }
    });

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
        "Restore the saved baseline?\n\n" +
        "This atomically replaces all IPv4/IPv6 tables " +
        "(filter/nat/mangle/raw) with the saved baseline rules. " +
        "Any rules added since the baseline was saved will be lost. " +
        "Your SSH session and internet should survive, but use the LAN connection to be safe."
      )) return;
      els.fwReset.disabled = true;
      try {
        await firewallOp({ action: "restore" });
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
  const DEFAULT_TARGET = { lat: 39.9526, lon: -75.1652 }; // Philadelphia - fallback if no location set
  function routerTarget() {
    if (state.routerLat != null && state.routerLon != null) {
      return { lat: Number(state.routerLat), lon: Number(state.routerLon) };
    }
    return DEFAULT_TARGET;
  }
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
      targetMarker: null,
      markers: null,
      svg: null,
      lastByIp: null,
      statsEl: null,
    };

    // Zoom control bottom-right
    L.control.zoom({ position: "bottomright" }).addTo(m.map);

    // CARTO dark basemap with registered API key (keyless tiles are watermarked)
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png?key=cb1_2tvx_1_e55a010f34e5e3603b0ff643", {
      maxZoom: 18,
      subdomains: "abcd",
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
    }).addTo(m.map);

    // Target marker — multi-ring shield
    m.targetMarker = L.marker([target.lat, target.lon], {
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
    secMap = createAttackMap(el, routerTarget());
  }

  function initOverviewMap() {
    const el = document.getElementById("ov-map");
    if (!el || ovMap) return;
    ovMap = createAttackMap(el, routerTarget());
  }

  function updateMapTarget(m, target) {
    if (!m) return;
    m.target = target;
    if (m.targetMarker) m.targetMarker.setLatLng([target.lat, target.lon]);
    drawAttackArcs(m);
  }

  function applyRouterTarget() {
    const t = routerTarget();
    updateMapTarget(secMap, t);
    updateMapTarget(ovMap, t);
  }

  // ── Security hits-over-time chart ─────────────────────────────────────────
  let _secChartSeries  = [];
  let _secChartHover   = null;
  let _secChartRaf     = null;
  let _secChartProgress = 0;   // 0→1 draw-in animation

  function _secChartAttachHover(canvas) {
    canvas._secHoverBound = canvas._secHoverBound || ((e) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const n  = _secChartSeries.length;
      if (!n) { _secChartHover = null; return; }
      const padL = 42, padR = 12;
      const pw = rect.width - padL - padR;
      const idx = Math.round(((mx - padL) / pw) * (n - 1));
      _secChartHover = Math.max(0, Math.min(n - 1, idx));
      _drawSecChart(canvas);
    });
    canvas._secLeaveBound = canvas._secLeaveBound || ((() => {
      _secChartHover = null;
      _drawSecChart(canvas);
    }));
    canvas.removeEventListener("mousemove", canvas._secHoverBound);
    canvas.removeEventListener("mouseleave", canvas._secLeaveBound);
    canvas.addEventListener("mousemove", canvas._secHoverBound);
    canvas.addEventListener("mouseleave", canvas._secLeaveBound);
  }

  function _drawSecChart(canvas, progress = 1) {
    if (!canvas) return;
    const dpr  = window.devicePixelRatio || 1;
    const rect  = canvas.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    canvas.width  = Math.round(rect.width  * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width, h = rect.height;
    ctx.clearRect(0, 0, w, h);

    const series = _secChartSeries;
    const n = series.length;

    if (n < 2) {
      ctx.fillStyle = cssVar("--muted", "#8b949e");
      ctx.font = `12px ${cssVar("--font","sans-serif")}`;
      ctx.textAlign = "center";
      ctx.fillText("Collecting samples…", w / 2, h / 2);
      return;
    }

    // Layout
    const padT = 18, padB = 28, padL = 42, padR = 12;
    const pw = w - padL - padR;
    const ph = h - padT - padB;

    const vals = series.map(s => s[1]);
    const max  = Math.max(1, ...vals);

    // Colour tokens
    const red    = cssVar("--red",    "#f85149");
    const accent = cssVar("--accent", "#4f8cff");
    const muted  = cssVar("--muted",  "#8b949e");
    const border = cssVar("--border", "#2d333b");

    // X/Y helpers
    const xOf = i => padL + (pw * i) / (n - 1);
    const yOf = v => padT + ph - (ph * Math.min(v, max) / max);

    // ── Grid lines + Y labels ──────────────────────────────────────────────
    const gridSteps = 4;
    ctx.save();
    ctx.strokeStyle = hexToRgba(border, 0.7);
    ctx.lineWidth   = 1;
    ctx.setLineDash([3, 4]);
    for (let g = 0; g <= gridSteps; g++) {
      const gy = padT + (ph / gridSteps) * g;
      ctx.beginPath();
      ctx.moveTo(padL, gy);
      ctx.lineTo(w - padR, gy);
      ctx.stroke();
      const val = Math.round(max - (max / gridSteps) * g);
      ctx.fillStyle = hexToRgba(muted, 0.7);
      ctx.font = "10px monospace";
      ctx.textAlign = "right";
      ctx.fillText(val, padL - 6, gy + 3.5);
    }
    ctx.restore();

    // ── Clipping mask for animated draw-in ────────────────────────────────
    const drawUpTo = padL + pw * Math.min(progress, 1);
    ctx.save();
    ctx.beginPath();
    ctx.rect(padL, 0, drawUpTo - padL, h);
    ctx.clip();

    // ── Gradient fill under line ───────────────────────────────────────────
    const grad = ctx.createLinearGradient(0, padT, 0, padT + ph);
    grad.addColorStop(0,   hexToRgba(accent, 0.45));
    grad.addColorStop(0.5, hexToRgba(accent, 0.15));
    grad.addColorStop(1,   hexToRgba(accent, 0.0));

    ctx.beginPath();
    ctx.moveTo(xOf(0), yOf(vals[0]));
    for (let i = 1; i < n; i++) {
      const cx = (xOf(i - 1) + xOf(i)) / 2;
      ctx.bezierCurveTo(cx, yOf(vals[i - 1]), cx, yOf(vals[i]), xOf(i), yOf(vals[i]));
    }
    ctx.lineTo(xOf(n - 1), padT + ph);
    ctx.lineTo(xOf(0),     padT + ph);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // ── Main line ─────────────────────────────────────────────────────────
    ctx.beginPath();
    ctx.moveTo(xOf(0), yOf(vals[0]));
    for (let i = 1; i < n; i++) {
      const cx = (xOf(i - 1) + xOf(i)) / 2;
      ctx.bezierCurveTo(cx, yOf(vals[i - 1]), cx, yOf(vals[i]), xOf(i), yOf(vals[i]));
    }
    ctx.strokeStyle = accent;
    ctx.lineWidth   = 2;
    ctx.setLineDash([]);
    ctx.stroke();

    // ── Peak glow dots ────────────────────────────────────────────────────
    const peakIdx = vals.indexOf(max);
    for (let i = 0; i < n; i++) {
      if (vals[i] === 0) continue;
      const isPeak = i === peakIdx;
      const isLast = i === n - 1;
      if (!isPeak && !isLast && vals[i] < max * 0.6) continue;
      const px = xOf(i), py = yOf(vals[i]);
      const col = isPeak ? red : accent;

      if (isPeak) {
        // Outer glow ring
        const glow = ctx.createRadialGradient(px, py, 0, px, py, 14);
        glow.addColorStop(0,   hexToRgba(col, 0.35));
        glow.addColorStop(1,   hexToRgba(col, 0.0));
        ctx.beginPath();
        ctx.arc(px, py, 14, 0, Math.PI * 2);
        ctx.fillStyle = glow;
        ctx.fill();
      }

      // Dot
      ctx.beginPath();
      ctx.arc(px, py, isPeak ? 5 : 3.5, 0, Math.PI * 2);
      ctx.fillStyle = isPeak ? red : hexToRgba(accent, 0.9);
      ctx.fill();
      ctx.strokeStyle = cssVar("--card", "#1c2333");
      ctx.lineWidth = isPeak ? 2 : 1.5;
      ctx.stroke();
    }

    ctx.restore();  // end clip

    // ── X axis time labels ─────────────────────────────────────────────────
    ctx.fillStyle = hexToRgba(muted, 0.8);
    ctx.font = "10px monospace";
    ctx.textAlign = "center";
    const steps = Math.min(6, n);
    for (let i = 0; i < steps; i++) {
      const idx = Math.round((i * (n - 1)) / (steps - 1));
      const t   = new Date(series[idx][0] * 1000);
      const lbl = `${String(t.getHours()).padStart(2,"0")}:${String(t.getMinutes()).padStart(2,"0")}:${String(t.getSeconds()).padStart(2,"0")}`;
      ctx.fillText(lbl, xOf(idx), padT + ph + 18);
    }

    // ── Hover crosshair + tooltip ──────────────────────────────────────────
    if (_secChartHover !== null && _secChartHover < n) {
      const hi  = _secChartHover;
      const hx  = xOf(hi);
      const hv  = vals[hi];
      const hy  = yOf(hv);

      // Vertical crosshair
      ctx.save();
      ctx.strokeStyle = hexToRgba(muted, 0.5);
      ctx.lineWidth   = 1;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(hx, padT);
      ctx.lineTo(hx, padT + ph);
      ctx.stroke();
      ctx.restore();

      // Highlight dot
      ctx.beginPath();
      ctx.arc(hx, hy, 6, 0, Math.PI * 2);
      ctx.fillStyle = hexToRgba(accent, 0.25);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(hx, hy, 4, 0, Math.PI * 2);
      ctx.fillStyle = accent;
      ctx.fill();

      // Tooltip bubble
      const t   = new Date(series[hi][0] * 1000);
      const tLbl = `${String(t.getHours()).padStart(2,"0")}:${String(t.getMinutes()).padStart(2,"0")}:${String(t.getSeconds()).padStart(2,"0")}`;
      const tip = `${hv} hit${hv !== 1 ? "s" : ""}  ${tLbl}`;
      ctx.font = "bold 11px monospace";
      const tipW = ctx.measureText(tip).width + 16;
      const tipH = 22;
      let tx = hx + 10;
      if (tx + tipW > w - padR) tx = hx - tipW - 10;
      const ty = Math.max(padT, hy - tipH / 2);

      ctx.fillStyle   = cssVar("--card", "#1c2333");
      ctx.strokeStyle = hexToRgba(accent, 0.6);
      ctx.lineWidth   = 1;
      ctx.setLineDash([]);
      ctx.beginPath();
      ctx.roundRect(tx, ty, tipW, tipH, 5);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle  = cssVar("--text", "#e6edf3");
      ctx.textAlign  = "left";
      ctx.fillText(tip, tx + 8, ty + 14.5);
    }
  }

  function drawSecurityChart(canvas, series) {
    if (!canvas) return;
    _secChartSeries = series || [];
    _secChartAttachHover(canvas);

    // Animate draw-in
    if (_secChartRaf) cancelAnimationFrame(_secChartRaf);
    _secChartProgress = 0;
    const start = performance.now();
    const dur   = 600;

    function tick(now) {
      _secChartProgress = Math.min((now - start) / dur, 1);
      // Ease out cubic
      const p = 1 - Math.pow(1 - _secChartProgress, 3);
      _drawSecChart(canvas, p);
      if (_secChartProgress < 1) _secChartRaf = requestAnimationFrame(tick);
    }
    _secChartRaf = requestAnimationFrame(tick);
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
    const cTotal = countries.reduce((s, c) => s + c.count, 0) || 1;
    const cMax   = countries[0] ? countries[0].count : 1;

    // Colour ramp for rank: top 3 get distinct colours, rest fade through amber→muted
    const RANK_COLORS = ["#f85149", "#ffa657", "#d29922"];
    function rankColor(idx) {
      if (idx < 3) return RANK_COLORS[idx];
      const t = Math.min((idx - 3) / 12, 1);
      // fade from amber to muted
      return `color-mix(in srgb, var(--amber) ${Math.round((1-t)*60)}%, var(--muted))`;
    }

    const buildCountryRow = (c, idx) => {
      const pct     = Math.round(c.count / cMax * 100);
      const sharePct = ((c.count / cTotal) * 100).toFixed(1);
      const color   = rankColor(idx);
      const iso     = (c.iso && c.iso !== "??") ? c.iso.toUpperCase() : "—";
      return `
      <tr class="country-row">
        <td>
          <div class="country-cell">
            <span class="country-rank" style="color:${color}">#${idx + 1}</span>
            <span class="country-iso-badge" style="--cc:${color}">${esc(iso)}</span>
            <span class="country-name">${esc(c.name || "Unknown")}</span>
          </div>
        </td>
        <td>
          <div class="country-bar-wrap">
            <div class="country-bar-fill" style="width:${pct}%;background:${color}"></div>
          </div>
        </td>
        <td class="country-hits">${formatNumber(c.count)}</td>
        <td class="country-share">${sharePct}%</td>
      </tr>`;
    };

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

    // Threat level derived from hit-count percentile
    function threatLevel(count) {
      const pct = count / ipMax;
      if (pct >= 0.5) return "HIGH";
      if (pct >= 0.15) return "MED";
      return "LOW";
    }
    function threatBadge(count, banned) {
      if (banned) return '<span class="ip-threat ip-threat-banned">BANNED</span>';
      const lvl = threatLevel(count);
      return `<span class="ip-threat ip-threat-${lvl.toLowerCase()}">${lvl}</span>`;
    }
    function ipPill(ip, count, banned) {
      const lvl = banned ? "banned" : threatLevel(count).toLowerCase();
      return `<span class="ip-pill ip-pill-${lvl}" data-ip="${esc(ip)}">
        <span class="ip-pill-addr">${esc(ip)}</span>
        <button class="ip-copy-btn" title="Copy IP" data-copy="${esc(ip)}">⎘</button>
      </span>`;
    }

    // Build a full <tr> string for a given IP entry
    function buildIpRow(i) {
      const banned    = state.secBannedIps.has(i.ip);
      const pct       = Math.round(i.count / ipMax * 100);
      const firstSeen = i.first ? new Date(i.first * 1000).toLocaleDateString() : "—";
      const lastSeen  = i.last  ? new Date(i.last  * 1000).toLocaleString()     : "—";
      const location  = [i.city, i.country].filter(Boolean).join(", ") || "Unknown";
      const banBtn    = csUp
        ? (banned
            ? `<button type="button" class="btn btn-sm sec-unban" data-ip="${esc(i.ip)}" title="Remove CrowdSec ban">Unban</button>`
            : `<button type="button" class="btn btn-sm btn-danger sec-ban" data-ip="${esc(i.ip)}" title="Add to CrowdSec blocklist">Ban</button>`)
        : "";
      const abuseBtn = `<a class="btn btn-sm btn-ghost ip-lookup-btn" href="https://www.abuseipdb.com/check/${esc(i.ip)}" target="_blank" rel="noopener" title="Check AbuseIPDB">🔍</a>`;
      return `<tr class="ip-row" data-ip="${esc(i.ip)}"
          data-location="${esc(location)}"
          data-port="${esc(i.port || "—")}"
          data-first="${esc(firstSeen)}"
          data-last="${esc(lastSeen)}"
          data-count="${i.count}"
          data-pct="${pct}"
          data-banned="${banned}">
        <td>${ipPill(i.ip, i.count, banned)}</td>
        <td>${threatBadge(i.count, banned)}</td>
        <td>${flagEmoji(i.iso)} <span class="ip-location">${esc(location)}</span>
            <span class="ip-isp muted" id="isp-${esc(i.ip).replace(/\./g,'-')}"></span></td>
        <td>${formatNumber(i.count)}</td>
        <td><div class="bar"><div class="bar-fill bar-fill-err" style="width:${pct}%"></div></div></td>
        <td><div class="svc-actions">${banBtn}${abuseBtn}</div></td>
      </tr>`;
    }

    // Keyed diff update — only touch rows that changed, never flash the whole table
    function diffIpTable(tbody, entries, limit) {
      const slice      = entries.slice(0, limit);
      const newIps     = slice.map(i => i.ip);
      const newMap     = Object.fromEntries(slice.map(i => [i.ip, i]));
      const existingRows = Array.from(tbody.querySelectorAll("tr[data-ip]"));
      const existingIps  = existingRows.map(r => r.dataset.ip);

      // Remove rows no longer in the list
      existingRows.forEach(r => {
        if (!newMap[r.dataset.ip]) r.remove();
      });

      // Insert / update rows in order
      newIps.forEach((ip, idx) => {
        const entry      = newMap[ip];
        const banned     = state.secBannedIps.has(ip);
        const pct        = Math.round(entry.count / ipMax * 100);
        let   row        = tbody.querySelector(`tr[data-ip="${CSS.escape(ip)}"]`);
        const isNew      = !row;

        if (isNew) {
          // Brand-new IP — insert a fresh row
          const tmp = document.createElement("tbody");
          tmp.innerHTML = buildIpRow(entry);
          row = tmp.firstElementChild;
          row.classList.add("ip-row-new");
          setTimeout(() => row.classList.remove("ip-row-new"), 600);
        } else {
          // Existing row — update only the cells that change frequently
          // (threat badge, hit count, bar, ban button — NOT the ISP span)
          const cells      = row.cells;
          const curBanned  = row.dataset.banned === "true";
          const countChanged = row.dataset.count !== String(entry.count);
          const bannedChanged = curBanned !== banned;

          // Update cells that change on each refresh
          if (countChanged || bannedChanged) {
            // IP pill threat class
            const pill = row.querySelector(".ip-pill");
            if (pill) {
              const lvl = banned ? "banned" : threatLevel(entry.count).toLowerCase();
              pill.className = `ip-pill ip-pill-${lvl}`;
            }
            // Threat badge
            if (cells[1]) cells[1].innerHTML = threatBadge(entry.count, banned);
            // Hit count
            if (cells[3]) cells[3].textContent = formatNumber(entry.count);
            // Bar
            if (cells[4]) cells[4].innerHTML =
              `<div class="bar"><div class="bar-fill bar-fill-err" style="width:${pct}%"></div></div>`;
            // Update data attrs
            row.dataset.count  = entry.count;
            row.dataset.pct    = pct;
            row.dataset.banned = banned;
          }
          // Always rebuild the actions cell — csUp may have changed since first render,
          // and this is just buttons so there's no flicker risk
          if (cells[5]) {
            const abuseBtn = `<a class="btn btn-sm btn-ghost ip-lookup-btn" href="https://www.abuseipdb.com/check/${esc(entry.ip)}" target="_blank" rel="noopener" title="Check AbuseIPDB">🔍</a>`;
            const banBtn = csUp
              ? (banned
                  ? `<button type="button" class="btn btn-sm sec-unban" data-ip="${esc(entry.ip)}" title="Remove CrowdSec ban">Unban</button>`
                  : `<button type="button" class="btn btn-sm btn-danger sec-ban" data-ip="${esc(entry.ip)}" title="Add to CrowdSec blocklist">Ban</button>`)
              : "";
            cells[5].innerHTML = `<div class="svc-actions">${banBtn}${abuseBtn}</div>`;
          }
        }

        // Ensure correct DOM order
        const sibling = tbody.children[idx];
        if (sibling !== row) tbody.insertBefore(row, sibling || null);

        // Wire up copy button if new row
        if (isNew) {
          const copyBtn = row.querySelector(".ip-copy-btn");
          if (copyBtn) {
            copyBtn.addEventListener("click", (e) => {
              e.stopPropagation();
              navigator.clipboard.writeText(copyBtn.dataset.copy).then(() => {
                copyBtn.textContent = "✓";
                setTimeout(() => { copyBtn.textContent = "⎘"; }, 1200);
              });
            });
          }
          attachIpRowHover(row);
        }
      });

      // If table was empty placeholder, clear it
      const placeholder = tbody.querySelector("td[colspan]");
      if (placeholder && newIps.length) placeholder.closest("tr")?.remove();
    }

    // Attach hover card to a single row (called once per row, on insert)
    function attachIpRowHover(row) {
      const hoverCard = document.getElementById("ip-hover-card");
      row.addEventListener("mouseenter", (e) => {
        const ispEl = document.getElementById("isp-" + row.dataset.ip.replace(/\./g, "-"));
        const isp   = ispEl ? ispEl.textContent.replace(/^·\s*/, "").trim() : "";
        hoverCard.innerHTML = `
          <div class="iph-ip mono">${esc(row.dataset.ip)}</div>
          <div class="iph-row"><span class="iph-label">Location</span><span>${esc(row.dataset.location)}</span></div>
          ${isp ? `<div class="iph-row"><span class="iph-label">ISP</span><span>${esc(isp)}</span></div>` : ""}
          <div class="iph-row"><span class="iph-label">Top Port</span><span class="mono">${esc(row.dataset.port)}</span></div>
          <div class="iph-row"><span class="iph-label">Hits</span><span>${esc(row.dataset.count)} <span class="muted">(${esc(row.dataset.pct)}% of max)</span></span></div>
          <div class="iph-row"><span class="iph-label">First seen</span><span>${esc(row.dataset.first)}</span></div>
          <div class="iph-row"><span class="iph-label">Last seen</span><span>${esc(row.dataset.last)}</span></div>
          <div class="iph-row"><span class="iph-label">CrowdSec</span>
            <span style="color:${row.dataset.banned==='true'?'var(--red)':'var(--green)'}">
              ${row.dataset.banned === "true" ? "Banned ✓" : "Not banned"}
            </span></div>`;
        hoverCard.hidden = false;
        positionHoverCard(e);
      });
      row.addEventListener("mousemove", positionHoverCard);
      row.addEventListener("mouseleave", () => { hoverCard.hidden = true; });
    }

    // Run the diff update
    const newIps = byIp.map(i => i.ip);
    const prevIps = Array.from(els.secIpsBody.querySelectorAll("tr[data-ip]")).map(r => r.dataset.ip);
    diffIpTable(els.secIpsBody, byIp, 25);

    // Only fetch ISP info for IPs that are new to the table
    const brandNewIps = byIp.slice(0, 25).filter(i => !prevIps.includes(i.ip));
    if (brandNewIps.length) fetchIspInfo(brandNewIps, "sec-ips");

    const ipMoreWrap = document.getElementById("sec-ips-more-wrap");
    ipMoreWrap.hidden = byIp.length <= 25;
    if (!ipMoreWrap.hidden) {
      document.getElementById("sec-ips-more").onclick = () => {
        document.getElementById("sec-ips-full-body").innerHTML = byIp.map(buildIpRow).join("");
        document.getElementById("sec-ips-modal").hidden = false;
        fetchIspInfo(byIp, "sec-ips-full");
      };
    }

    // (Recent Hits table replaced by Traffic Monitor)

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

  // ===================== TRAFFIC MONITOR =====================
  const TM_LIMIT = 100;
  let tmPaused = false;
  let tmFilter = "all";
  let tmEntries = [];
  let tmInterval = null;

  function tmBadge(type) {
    switch (type) {
      case "fw-block":  return '<span class="tm-badge tm-badge-block">FW Block</span>';
      case "fw-allow":  return '<span class="tm-badge tm-badge-allow">FW Allow</span>';
      case "dns-block": return '<span class="tm-badge tm-badge-dns">DNS Block</span>';
      default:          return '<span class="tm-badge">' + esc(type) + '</span>';
    }
  }

  function tmRowClass(type) {
    if (type === "fw-block")  return "tm-row-block";
    if (type === "dns-block") return "tm-row-dns";
    if (type === "fw-allow")  return "tm-row-allow";
    return "";
  }

  function tmDirection(dir) {
    return dir === "in"
      ? '<span class="tm-dir tm-dir-in">↓ IN</span>'
      : '<span class="tm-dir tm-dir-out">↑ OUT</span>';
  }

  function renderTrafficMonitor() {
    const body = document.getElementById("tm-body");
    if (!body) return;
    const visible = tmFilter === "all"
      ? tmEntries
      : tmEntries.filter(e => e.type === tmFilter);
    if (!visible.length) {
      body.innerHTML = '<tr><td colspan="6" class="empty">No events yet — traffic will appear as connections are made or blocked.</td></tr>';
      document.getElementById("tm-count").textContent = "";
      return;
    }
    body.innerHTML = visible.slice(0, TM_LIMIT).map(e => {
      const ts = e.ts ? e.ts.replace("T", " ").substring(0, 19).replace("+", " +") : "—";
      const src = e.src ? `<span class="mono">${esc(e.src)}</span>` : '<span class="muted">—</span>';
      const dst = e.dst
        ? (e.proto === "DNS" ? `<span class="mono tm-domain">${esc(e.dst)}</span>` : `<span class="mono">${esc(e.dst)}</span>`)
        : '<span class="muted">—</span>';
      const proto = e.port
        ? `<span class="mono">${esc(e.proto)}/${esc(e.port)}</span>`
        : (e.proto ? `<span class="mono">${esc(e.proto)}</span>` : '<span class="muted">—</span>');
      return `<tr class="${tmRowClass(e.type)}">
        <td class="mono tm-ts">${esc(ts)}</td>
        <td>${tmBadge(e.type)}</td>
        <td>${tmDirection(e.direction || "in")}</td>
        <td>${src}</td>
        <td>${dst}</td>
        <td>${proto}</td>
      </tr>`;
    }).join("");
    document.getElementById("tm-count").textContent = `${visible.length} events`;
  }

  async function refreshTrafficMonitor() {
    if (tmPaused) return;
    try {
      const d = await fetchJSON("/api/traffic-monitor");
      if (!d.ok) return;
      tmEntries = d.entries || [];
      renderTrafficMonitor();
      document.getElementById("tm-status").textContent =
        `Last updated ${new Date().toLocaleTimeString()} · auto-refresh every 5s`;
    } catch (e) {
      document.getElementById("tm-status").textContent = "Error fetching traffic data: " + e.message;
    }
  }

  function initTrafficMonitor() {
    // Filter buttons
    document.getElementById("tm-filter-btns").addEventListener("click", (e) => {
      const btn = e.target.closest("[data-tm-filter]");
      if (!btn) return;
      tmFilter = btn.dataset.tmFilter;
      document.querySelectorAll("[data-tm-filter]").forEach(b =>
        b.classList.toggle("active", b === btn));
      renderTrafficMonitor();
    });

    // Pause/resume
    document.getElementById("tm-pause-btn").addEventListener("click", () => {
      tmPaused = !tmPaused;
      document.getElementById("tm-pause-btn").textContent = tmPaused ? "▶ Resume" : "⏸ Pause";
      document.getElementById("tm-status").textContent = tmPaused
        ? "Paused — click Resume to continue"
        : "Resuming…";
      if (!tmPaused) refreshTrafficMonitor();
    });

    refreshTrafficMonitor();
    if (tmInterval) clearInterval(tmInterval);
    tmInterval = setInterval(refreshTrafficMonitor, 5000);
  }

  // ===================== DIAGNOSE TOOL =====================
  async function runDiagnose() {
    const target = (document.getElementById("diag-target").value || "").trim();
    if (!target) return;
    const btn = document.getElementById("diag-btn");
    const out = document.getElementById("diag-results");
    btn.disabled = true;
    btn.textContent = "Checking…";
    out.hidden = false;
    out.innerHTML = '<div class="diag-loading">Checking ' + esc(target) + '…</div>';
    try {
      const d = await postJSON("/api/diagnose", { target });
      if (!d.ok) {
        out.innerHTML = `<div class="diag-error">${esc(d.error || "Unknown error")}</div>`;
        return;
      }
      const overallClass = d.blocked ? "diag-overall-blocked" : "diag-overall-ok";
      const overallText = d.blocked ? "⚠ Something is blocking " + esc(d.target) : "✓ No blocks found for " + esc(d.target);
      out.innerHTML = `
        <div class="diag-overall ${overallClass}">${overallText}</div>
        <div class="diag-checks">
          ${(d.results || []).map(r => {
            const cls = r.blocked === true ? "diag-check-blocked"
                      : r.blocked === false ? "diag-check-ok"
                      : "diag-check-unknown";
            const icon = r.blocked === true ? "🔴" : r.blocked === false ? "🟢" : "⚪";
            return `<div class="diag-check ${cls}">
              <div class="diag-check-head">
                <span class="diag-check-icon">${icon}</span>
                <span class="diag-check-name">${esc(r.check)}</span>
              </div>
              <div class="diag-check-detail">${esc(r.detail)}</div>
              ${r.action ? `<div class="diag-check-action">→ ${esc(r.action)}</div>` : ""}
            </div>`;
          }).join("")}
        </div>`;
    } catch (e) {
      out.innerHTML = `<div class="diag-error">Request failed: ${esc(e.message)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Check";
    }
  }

  // ---- IP hover card positioning ----
  function positionHoverCard(e) {
    const card = document.getElementById("ip-hover-card");
    if (!card || card.hidden) return;
    const vw = window.innerWidth, vh = window.innerHeight;
    const cw = card.offsetWidth || 260, ch = card.offsetHeight || 180;
    let x = e.clientX + 14, y = e.clientY + 14;
    if (x + cw > vw - 10) x = e.clientX - cw - 10;
    if (y + ch > vh - 10) y = e.clientY - ch - 10;
    card.style.left = x + "px";
    card.style.top  = y + "px";
  }

  // ---- ISP batch lookup via ip-api.com (free, no key) ----
  async function fetchIspInfo(ipList, tablePrefix) {
    if (!ipList || !ipList.length) return;
    const ips = ipList.slice(0, 50).map(i => ({ query: i.ip, fields: "query,org,hosting" }));
    try {
      const resp = await fetch("http://ip-api.com/batch?fields=query,org,hosting", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ips),
      });
      if (!resp.ok) return;
      const data = await resp.json();
      data.forEach(r => {
        const id = `isp-${(r.query || "").replace(/\./g, "-")}`;
        const el = document.getElementById(id);
        if (!el) return;
        const hosting = r.hosting ? " · <span class='ip-hosting-badge'>Hosting</span>" : "";
        el.innerHTML = r.org ? `· ${esc(r.org)}${hosting}` : "";
      });
    } catch (_) { /* ip-api unreachable, skip silently */ }
  }

  function initDiagnose() {
    document.getElementById("diag-btn").addEventListener("click", runDiagnose);
    document.getElementById("diag-target").addEventListener("keydown", (e) => {
      if (e.key === "Enter") runDiagnose();
    });
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
    const brandVersion = document.getElementById("brand-version");
    if (brandVersion && d.tuxwall_version) brandVersion.textContent = "v" + d.tuxwall_version;
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

  async function uploadSystemBackupExamine(buf) {
    const res = await fetch("/api/backups/system/upload", {
      method: "POST",
      headers: { "Content-Type": "application/gzip" },
      body: buf,
      cache: "no-store",
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
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
          <button class="btn btn-sm bk-sys-browse" data-name="${esc(b.name)}" type="button">Browse</button>
          <button class="btn btn-sm bk-sys-san" data-name="${esc(b.name)}" type="button" title="Create a sanitized copy with secrets (WireGuard keys, credentials, API keys) removed — safe to share as a setup template">Export sanitized</button>
          <button class="btn btn-sm bk-sys-del" data-name="${esc(b.name)}" type="button" title="Delete this backup">Delete</button>
        </td>
      </tr>`).join("") || `<tr><td colspan="4" class="muted">No system backups yet.</td></tr>`;
  }

  let bkSysItemsCache = [];

  function renderSystemBackupItems(items) {
    bkSysItemsCache = items || [];
    els.bkSysItems.innerHTML = (items || []).map((it) => `
      <label class="bk-item">
        <input type="checkbox" class="bk-item-chk" data-arc="${esc(it.arc)}" ${it.exists ? "checked" : " disabled"} />
        <span class="bk-item-label">${esc(it.label)} <span class="muted mono">${esc(it.arc)}</span></span>
        <span class="muted">${it.exists ? formatBytes(it.size) : "not present"}</span>
      </label>`).join("") ||
      `<p class="muted">No config items available.</p>`;
  }

  function selectedSystemBackupItems() {
    return Array.from(els.bkSysItems.querySelectorAll(".bk-item-chk:checked"))
      .map((c) => c.dataset.arc);
  }

  async function refreshSystemBackupItems() {
    try {
      const data = await fetchJSON("/api/backups/system/items");
      renderSystemBackupItems(data.items);
    } catch (err) {
      els.bkSysItems.innerHTML = `<p class="muted bk-msg-err">Could not load config items: ${esc(err.message)}</p>`;
    }
  }

  function renderSystemBackupContents(data) {
    els.bkSysContentsTitle.textContent = "Contents of " + data.backup;
    els.bkSysFiles.innerHTML = (data.files || []).map((f) => `
      <tr>
        <td class="mono">${esc(f.name)}</td>
        <td>${formatBytes(f.size)}</td>
        <td class="muted">${esc(f.service || "—")}</td>
        <td class="td-right">
          <button class="btn btn-sm bk-file-dl" data-name="${esc(data.backup)}" data-file="${esc(f.name)}" type="button">Download</button>
          <button class="btn btn-sm bk-file-restore" data-name="${esc(data.backup)}" data-file="${esc(f.name)}" data-service="${esc(f.service || "")}" type="button">Restore</button>
        </td>
      </tr>`).join("") || `<tr><td colspan="4" class="muted">No files.</td></tr>`;
    els.bkSysContents.hidden = false;
  }

  async function browseSystemBackup(name) {
    try {
      const data = await fetchJSON("/api/backups/system/contents?name=" + encodeURIComponent(name));
      renderSystemBackupContents(data);
      setBkSysMsg("");
    } catch (err) {
      setBkSysMsg("Browse: " + err.message, true);
    }
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

  function bindSystemBackups() {
    els.bkSysAll.addEventListener("click", () => {
      els.bkSysItems.querySelectorAll(".bk-item-chk:not(:disabled)").forEach((c) => { c.checked = true; });
    });
    els.bkSysNone.addEventListener("click", () => {
      els.bkSysItems.querySelectorAll(".bk-item-chk").forEach((c) => { c.checked = false; });
    });

    els.bkSysCreate.addEventListener("click", async () => {
      const include = selectedSystemBackupItems();
      if (!include.length) {
        setBkSysMsg("Select at least one config item to back up.", true);
        return;
      }
      try {
        await postJSON("/api/backups/system/create", { include });
        setBkSysMsg("Starting system backup...", false);
        await pollSystemBackup();
      } catch (err) {
        setBkSysMsg(err.message, true);
      }
    });

    els.bkSysUpload.addEventListener("click", async () => {
      const file = els.bkSysFile.files && els.bkSysFile.files[0];
      if (!file) {
        setBkSysMsg("Choose a .tar.gz system backup file first.", true);
        return;
      }
      try {
        setBkSysMsg("Uploading and examining " + file.name + "…", false);
        const buf = await file.arrayBuffer();
        const data = await uploadSystemBackupExamine(buf);
        els.bkSysFile.value = "";
        renderSystemBackupContents({ backup: data.name, files: data.files });
        setBkSysMsg(
          `Examined "${data.name}" — ${(data.files || []).length} restorable file(s) listed below. ` +
          "Choose which to restore; current files get a timestamped .bak.", false);
      } catch (err) {
        setBkSysMsg("Upload: " + err.message, true);
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
      const browse = e.target.closest(".bk-sys-browse");
      if (browse) {
        await browseSystemBackup(browse.dataset.name);
        return;
      }
      const san = e.target.closest(".bk-sys-san");
      if (san) {
        if (!window.confirm(
          `Create a sanitized export of "${san.dataset.name}"?\n\n` +
          "Secrets (WireGuard keys, CrowdSec/cloudflared credentials, tuxwall auth) are removed or redacted. " +
          "The export downloads automatically and a copy stays on this server."
        )) return;
        try {
          const res = await postJSON("/api/backups/system/sanitize", { name: san.dataset.name });
          if (!res.ok || !res.name) throw new Error(res.error || "sanitize failed");
          await downloadSystemBackup(res.name);
          setBkSysMsg(
            `Sanitized export ${res.name} downloaded — ` +
            `${(res.dropped || []).length} secret file(s) dropped, ${res.redacted || 0} key(s) redacted. ` +
            "Verify SANITIZED.txt inside before sharing.", false);
        } catch (err) {
          setBkSysMsg("Sanitize: " + err.message, true);
        }
        return;
      }
      const del = e.target.closest(".bk-sys-del");
      if (del) {
        if (!window.confirm(`Delete system backup "${del.dataset.name}"?`)) return;
        try {
          await postJSON("/api/backups/system/delete", { name: del.dataset.name });
          setBkSysMsg("System backup deleted.", false);
          els.bkSysContents.hidden = true;
          await refreshSystemBackups();
        } catch (err) {
          setBkSysMsg(err.message, true);
        }
      }
    });

    els.bkSysFiles.addEventListener("click", async (e) => {
      const dl = e.target.closest(".bk-file-dl");
      if (dl) {
        const url = "/api/backups/system/file?name=" + encodeURIComponent(dl.dataset.name) +
          "&file=" + encodeURIComponent(dl.dataset.file);
        window.location.href = url;
        return;
      }
      const rst = e.target.closest(".bk-file-restore");
      if (rst) {
        const svc = rst.dataset.service;
        const isFw = rst.dataset.file === "iptables-save.txt" || rst.dataset.file === "ip6tables-save.txt";
        if (!window.confirm(
          `Restore "${rst.dataset.file}" from this backup?\n\n` +
          (isFw
            ? "This atomically replaces the ENTIRE live ruleset (IPv4 or IPv6) with the rules from the backup. Do this from a LAN connection."
            : "The current file is kept as a timestamped .bak alongside it." +
              (svc ? `\nAfterwards, apply it with: sudo systemctl restart ${svc}` : ""))
        )) return;
        try {
          const res = await postJSON("/api/backups/system/restore-file", {
            name: rst.dataset.name, file: rst.dataset.file,
          });
          if (!res.ok) throw new Error(res.error || "restore failed");
          setBkSysMsg(
            `Restored ${res.restored}.` +
            (res.restart_required ? ` To apply, run: sudo systemctl restart ${res.restart_required}` : "") +
            (res.note ? ` (${res.note})` : ""), false);
        } catch (err) {
          setBkSysMsg("Restore: " + err.message, true);
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

    const wan = sys.wan || {};
    els.ovWanIp.textContent = wan.ipv4 || "—";
    els.ovWanIp.title = wan.ifname
      ? `${wan.ifname}${(wan.ipv6 || [])[0] ? " · v6: " + wan.ipv6[0] : ""}`
      : "no default route";

    const wgPeers = ((d.wg || {}).peers || []);
    const nowSec = Math.floor(Date.now() / 1000);
    const wgOnline = wgPeers.filter((p) => (p.last_handshake || 0) > nowSec - 180).length;
    els.ovWgPeers.textContent = wgPeers.length ? `${wgOnline}/${wgPeers.length}` : "—";
    els.ovWgPeers.title = "WireGuard peers with a handshake in the last 3 minutes";

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

    renderWanCard(sys);
    renderWgCard(d.wg || {});
  }

  function renderWanCard(sys) {
    const body = document.getElementById("ov-wan-body");
    const hint = document.getElementById("ov-wan-hint");
    const wan = sys.wan || {};
    if (!body) return;
    if (!wan.ifname) {
      hint.textContent = "no default route";
      body.innerHTML = `<p class="muted">No WAN interface detected.</p>`;
      return;
    }
    const up = (wan.state || "").toUpperCase() === "UP";
    hint.textContent = wan.ifname;
    const rows = [];
    const row = (label, value, cls) => `
      <div class="ov-kv-row">
        <span class="ov-kv-label">${esc(label)}</span>
        <span class="ov-kv-value ${cls || ""}">${esc(value || "—")}</span>
      </div>`;
    rows.push(row("Link", `${wan.ifname} · ${(wan.state || "—").toUpperCase()}`, up ? "ok" : "down"));
    rows.push(row("IPv4", wan.ipv4));
    for (const a of (wan.ipv6 || []).slice(0, 3)) rows.push(row("IPv6", a));
    if ((wan.ipv6 || []).length > 3) rows.push(row("", `+${wan.ipv6.length - 3} more global v6 addrs`));
    rows.push(row("Gateway v4", wan.gateway4));
    rows.push(row("Gateway v6", wan.gateway6));
    body.innerHTML = rows.join("");
  }

  function renderWgCard(wg) {
    const body = document.getElementById("ov-wg-body");
    const hint = document.getElementById("ov-wg-hint");
    if (!body) return;
    if (!wg || !wg.configured) {
      hint.textContent = "not configured";
      body.innerHTML = `<p class="muted">WireGuard is not configured.</p>`;
      return;
    }
    const iface = wg.interface || {};
    const peers = wg.peers || [];
    const now = Math.floor(Date.now() / 1000);
    const ONLINE_WINDOW = 180;
    const online = peers.filter((p) => (p.last_handshake || 0) > now - ONLINE_WINDOW);
    hint.textContent = iface.up
      ? `up · ${online.length}/${peers.length} peers online`
      : "interface down";
    const rows = [];
    const row = (label, value, cls) => `
      <div class="ov-kv-row">
        <span class="ov-kv-label">${esc(label)}</span>
        <span class="ov-kv-value ${cls || ""}">${esc(value || "—")}</span>
      </div>`;
    rows.push(row("Interface", `${iface.name || "wg0"} · port ${iface.listen_port || "—"}`, iface.up ? "ok" : "down"));
    rows.push(row("Peers online", `${online.length} of ${peers.length}`, online.length ? "ok" : ""));
    rows.push(row("Transfer", `↓ ${formatBytes(iface.rx || 0)} · ↑ ${formatBytes(iface.tx || 0)}`));
    const peerRows = peers.slice(0, 5).map((p) => {
      const age = (p.last_handshake || 0) > 0 ? formatUptime(now - p.last_handshake) : "never";
      const isOn = (p.last_handshake || 0) > now - ONLINE_WINDOW;
      return `
        <div class="ov-wg-peer">
          <span>${esc(p.name || p.address)}${isOn ? ' <span class="badge badge-ok">on</span>' : ""}</span>
          <span class="muted">hs ${esc(age)} · ↓${formatBytes(p.rx || 0)} ↑${formatBytes(p.tx || 0)}</span>
        </div>`;
    }).join("");
    body.innerHTML = rows.join("") + (peers.length
      ? `<div class="ov-wg-peers" style="margin-top:6px">${peerRows}</div>`
      : `<p class="muted" style="margin-top:6px">No peers configured.</p>`);
  }

  async function refreshOverview() {
    try {
      const [sys, bw, dns, sec, fw, sur, leaseResp, latHist, wg] = await Promise.all([
        fetchJSON("/api/system"),
        fetchJSON("/api/bandwidth"),
        fetchJSON("/api/dns"),
        fetchJSON("/api/security"),
        fetchJSON("/api/firewall"),
        fetchJSON("/api/security/suricata"),
        fetchJSON("/api/leases"),
        fetchJSON("/api/latency/history?hours=24").catch(() => ({ series: [] })),
        fetchJSON("/api/wireguard").catch(() => ({})),
      ]);
      renderOverview({ sys, bw, dns, sec, fw, sur, leases: leaseResp.leases || [], latHistory: latHist.series || [], wg });
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

  function populateRouterLocation() {
    if (state.routerLat != null && els.routerLat) els.routerLat.value = state.routerLat;
    if (state.routerLon != null && els.routerLon) els.routerLon.value = state.routerLon;
    if (els.routerLocMsg) els.routerLocMsg.textContent = "";
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

    els.routerLocSave.addEventListener("click", async () => {
      const lat = (els.routerLat.value || "").trim();
      const lon = (els.routerLon.value || "").trim();
      if (!lat || !lon) {
        els.routerLocMsg.textContent = "Enter both latitude and longitude.";
        return;
      }
      els.routerLocSave.disabled = true;
      try {
        const d = await postJSON("/api/ui/router-location", { lat, lon });
        state.routerLat = Number(d.lat);
        state.routerLon = Number(d.lon);
        applyRouterTarget();
        els.routerLocMsg.textContent = "Location saved.";
      } catch (err) {
        els.routerLocMsg.textContent = err.message;
      } finally {
        els.routerLocSave.disabled = false;
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
    const implemented = view === "overview" || view === "clients" || view === "dns" || view === "domains" || view === "firewall" || view === "vlans" || view === "security" || view === "wireguard" || view === "crowdsec" || view === "bandwidth" || view === "blocklists" || view === "system" || view === "backups" || view === "logs" || view === "settings" || view === "ai";
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
      if (view === "firewall") { refreshFirewall(); refreshPortForward(); refreshDmz(); }
      if (view === "vlans") refreshVlans();
      if (view === "domains") refreshDomains();
      if (view === "security") {
        initSecurityMap();
        refreshSecurity();
        refreshSuricata();
        initTrafficMonitor();
        initDiagnose();
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
        refreshSystemBackups();
        refreshSystemBackupItems();
      }
      if (view === "settings") {
        loadThemes();
        populateRouterLocation();
        if (state.canManageUsers) loadUsers();
      }
      els.soon.hidden = true;
      if (view === "ai" && window.__tuxwallAgentEnable) {
        window.__tuxwallAgentEnable();
      }
    } else {
      els.soon.hidden = false;
    }
  }

  // ================================================================
  // AI ASSISTANT
  // ================================================================
  (function aiChat() {
    // ── Agent mode (opencode terminal) ────────────────────────────────
    const agent = {
      enabled: false, sessionID: null, busy: false, pollTimer: null,
      tokens: 0, cost: 0, msgs: 0, model: "", booted: false,
      version: "", directory: "", vcs: null, placeholderTimer: null,
    };
    const elAgentSide = document.getElementById("ai-agent-side");
    const elAgentModel   = document.getElementById("agent-model-select");
    const elAgentNewSess = document.getElementById("agent-new-session");
    const elAgentStatus  = document.getElementById("agent-status");
    const elAgentSessBtn = document.getElementById("agent-sessions-btn");
    const elTerminal  = document.getElementById("oc-terminal");
    const elOcScreen  = document.getElementById("oc-screen");
    const elOcInput   = document.getElementById("oc-input");
    const elOcSend    = document.getElementById("oc-send");
    const elOcPopup   = document.getElementById("oc-popup");
    const elOcOverlay = document.getElementById("oc-overlay");
    const elOcModal   = document.getElementById("oc-modal");
    const elOcStatus  = document.getElementById("oc-statusbar");
    const elOcState   = document.getElementById("oc-agent-state");
    const elOcVer     = document.getElementById("oc-term-ver");
    const elOcVerSide = document.getElementById("oc-agent-version");
    const elOcMark    = document.getElementById("oc-prompt-mark");
    const elOcNote    = document.getElementById("oc-mode-note");

    // Authentic opencode TUI logo (packages/tui/src/logo.ts)
    const OC_LOGO = {
      left:  ["                   ", "█▀▀█ █▀▀█ █▀▀█ █▀▀▄", "█__█ █__█ █^^^ █__█", "▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀~~▀"],
      right: ["             ▄     ", "█▀▀▀ █▀▀█ █▀▀█ █▀▀█", "█___ █__█ █__█ █^^^", "▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀"],
    };
    const OC_PLACEHOLDERS = [
      "What is the tech stack of this project?",
      "Audit my firewall rules for misconfigurations",
      "Explain @includes/api_server.py",
      "Fix broken tests",
    ];
    const OC_COMMANDS = [
      { cmd: "/new",      desc: "start a new session",                       alias: "/clear" },
      { cmd: "/sessions", desc: "list and switch sessions",                  alias: "/resume" },
      { cmd: "/undo",     desc: "undo last message and file changes" },
      { cmd: "/redo",     desc: "redo previously undone changes" },
      { cmd: "/compact",  desc: "compact the session context",               alias: "/summarize" },
      { cmd: "/share",    desc: "share session, get a link" },
      { cmd: "/unshare",  desc: "stop sharing the session" },
      { cmd: "/init",     desc: "analyze project and create AGENTS.md" },
      { cmd: "/abort",    desc: "abort the running task" },
      { cmd: "/clear",    desc: "start a new session (alias of /new)" },
      { cmd: "/models",   desc: "change the agent model" },
      { cmd: "/help",     desc: "show all commands" },
      { cmd: "/exit",     desc: "no-op — opencode is the only assistant",       alias: "/quit /q" },
    ];

    function agentUpdateStats() {
      const t = document.getElementById("agent-tokens");
      const c = document.getElementById("agent-cost");
      const m = document.getElementById("agent-msgs");
      if (t) t.textContent = agent.tokens.toLocaleString();
      if (c) c.textContent = agent.cost ? "$" + agent.cost.toFixed(4) : "$0.00";
      if (m) m.textContent = String(agent.msgs);
      ocRenderStatus();
    }

    async function agentLoadModels() {
      if (!elAgentModel || elAgentModel.dataset.loaded === "1") return;
      try {
        const d = await fetchJSON("/api/agent/models");
        if (!d.ok || !d.models || !d.models.length) {
          elAgentModel.innerHTML = `<option value="">no models available</option>`;
          return;
        }
        const groups = {};
        d.models.forEach((m) => { (groups[m.provider] = groups[m.provider] || []).push(m); });
        elAgentModel.innerHTML = Object.keys(groups).sort().map((prov) =>
          `<optgroup label="${esc(prov)}">` + groups[prov].map((m) =>
            `<option value="${esc(m.id)}">${esc(m.name)}</option>`).join("") +
          "</optgroup>").join("");
        // preselect: last-used model (localStorage), else server default
        const lastModel = localStorage.getItem("tuxwall.agent.model") || "";
        if (lastModel && d.models.some((m) => m.id === lastModel)) {
          elAgentModel.value = lastModel;
        } else {
          const defModel = (d.configured || "");
          if (defModel && d.models.some((m) => m.id === defModel)) {
            elAgentModel.value = defModel;
          }
        }
        elAgentModel.dataset.loaded = "1";
      } catch (_) {
        elAgentModel.innerHTML = `<option value="">failed to load models</option>`;
      }
    }

    async function agentLoadBootInfo() {
      try {
        const d = await fetchJSON("/api/agent/config");
        if (d && d.ok !== false) {
          agent.version = d.version || "";
          agent.directory = d.directory || "";
          agent.vcs = d.vcs || null;
          const vt = agent.version ? "v" + agent.version.replace(/^v/, "") : "opencode";
          if (elOcVer) elOcVer.textContent = agent.version ? "v" + agent.version.replace(/^v/, "") : "";
          if (elOcVerSide) elOcVerSide.textContent = vt + " · tuxwall";
          // refresh the boot screen if it is still on screen
          const bv = document.getElementById("oc-boot-ver");
          const bd = document.getElementById("oc-boot-dir");
          if (bv) bv.textContent = vt;
          if (bd) bd.textContent = agent.directory || "/";
          ocRenderStatus();
        }
      } catch (_) { /* offline is shown by health check */ }
    }

    function agentSetEnabled() {
      // opencode is the only AI assistant — always enabled
      agent.enabled = true;
      if (elAgentSide) elAgentSide.hidden = false;
      if (elTerminal) elTerminal.hidden = false;
      agentCheckHealth();
      agentLoadModels();
      agentUpdateStats();
      if (!agent.booted) { agent.booted = true; ocBootScreen(); agentLoadBootInfo(); }
      if (elOcInput) setTimeout(() => elOcInput.focus(), 50);
    }

    async function agentCheckHealth() {
      if (!elAgentStatus) return;
      try {
        const d = await fetchJSON("/api/agent/status");
        elAgentStatus.textContent = d.ok ? "● agent online" : "● agent offline: " + (d.error || "") + (d.status ? " (HTTP " + d.status + ")" : "");
        elAgentStatus.title = d.detail || d.hint || "";
        elAgentStatus.className = "agent-status" + (d.ok ? " agent-on" : " agent-off");
      } catch (err) {
        elAgentStatus.textContent = "● agent offline";
        elAgentStatus.className = "agent-status agent-off";
      }
    }


    // ── terminal render helpers ─────────────────────────────────────
    function ocScroll() { if (elOcScreen) elOcScreen.scrollTop = elOcScreen.scrollHeight; }

    function ocLine(text, cls) {
      const el = document.createElement("div");
      el.className = "oc-line" + (cls ? " " + cls : "");
      el.textContent = text == null ? "" : String(text);
      if (elOcScreen) elOcScreen.appendChild(el);
      ocScroll();
      return el;
    }

    function ocBlock(text, cls) {
      const el = document.createElement("div");
      el.className = "oc-tool-out" + (cls ? " " + cls : "");
      el.textContent = text == null ? "" : String(text);
      if (elOcScreen) elOcScreen.appendChild(el);
      ocScroll();
      return el;
    }

    function ocDiffBlock(diffText) {
      const el = document.createElement("div");
      el.className = "oc-tool-out oc-diff";
      (String(diffText || "").split("\n")).forEach((ln) => {
        const span = document.createElement("span");
        if (/^\+/.test(ln) && !/^\+\+\+/.test(ln)) span.className = "oc-add";
        else if (/^-/.test(ln) && !(/^---/.test(ln))) span.className = "oc-del";
        else if (/^@@/.test(ln)) span.className = "oc-hunk";
        span.textContent = ln || " ";
        el.appendChild(span);
      });
      if (elOcScreen) elOcScreen.appendChild(el);
      ocScroll();
      return el;
    }

    function ocTime() {
      const d = new Date();
      return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
    }

    function ocLogoHTML() {
      // faithful to the TUI: "open" muted, "code" bright+bold,
      // _ ^ ~ , rendered as their block equivalents
      const fix = (s) => s.replace(/_/g, " ").replace(/\^/g, "▀").replace(/~/g, "▀").replace(/,/g, "▄");
      let html = "";
      for (let i = 0; i < OC_LOGO.left.length; i++) {
        html += `<span class="oc-l">${esc(fix(OC_LOGO.left[i]))}</span><span class="oc-r">${esc(fix(OC_LOGO.right[i]))}</span>\n`;
      }
      return html;
    }

    function ocBootScreen(keepSession) {
      if (!elOcScreen) return;
      if (!keepSession) { agent.sessionID = null; agent.tokens = 0; agent.cost = 0; agent.msgs = 0; }
      elOcScreen.innerHTML = "";
      const boot = document.createElement("div");
      boot.className = "oc-boot";
      const vcsBit = agent.vcs && agent.vcs.branch ? ` <b>${esc(agent.vcs.branch)}</b>` : "";
      boot.innerHTML = `
        <div class="oc-logo">${ocLogoHTML()}</div>
        <div class="oc-boot-meta">
          <span class="oc-bootline">version   <b id="oc-boot-ver">${esc(agent.version ? "v" + agent.version.replace(/^v/, "") : "…")}</b></span>
          <span class="oc-bootline">directory <b id="oc-boot-dir">${esc(agent.directory || "/")}</b>${vcsBit}</span>
          <span class="oc-bootline">host      <b>tuxwall gateway</b> · agent mode · build</span>
        </div>
        <div class="oc-boot-tips">
          <span class="oc-tip">type <b>/</b> for commands — <b>!</b> runs shell — <b>@</b> mentions files</span><br>
          <span class="oc-tip"><b>/help</b> lists everything the terminal can do</span>
        </div>`;
      elOcScreen.appendChild(boot);
      if (elOcState) { elOcState.textContent = "idle"; elOcState.className = "oc-term-badge"; }
      agentUpdateStats();
      ocStartPlaceholders();
    }

    function ocStartPlaceholders() {
      if (agent.placeholderTimer) clearInterval(agent.placeholderTimer);
      let idx = 0;
      if (!elOcInput) return;
      elOcInput.placeholder = OC_PLACEHOLDERS[0];
      agent.placeholderTimer = setInterval(() => {
        if (!agent.enabled || !elOcInput || document.activeElement === elOcInput) return;
        idx = (idx + 1) % OC_PLACEHOLDERS.length;
        elOcInput.placeholder = OC_PLACEHOLDERS[idx];
      }, 4000);
    }

    function ocSetState(st) {
      if (!elOcState) return;
      elOcState.textContent = st;
      elOcState.className = "oc-term-badge" + (st === "busy" ? " oc-busy" : st === "error" ? " oc-error" : "");
      ocRenderStatus();
    }

    function ocRenderStatus() {
      if (!elOcStatus) return;
      const perms = document.querySelectorAll(".oc-perm:not(.oc-question):not(.oc-approved):not(.oc-denied)").length;
      const dir = agent.directory || "/";
      const git = agent.vcs && agent.vcs.branch ? " · git(" + agent.vcs.branch + ")" : "";
      const model = (elAgentModel && elAgentModel.value) ? elAgentModel.value : agent.model || "";
      elOcStatus.innerHTML =
        `<span class="oc-sb-dir">${esc(dir)}${esc(git)}</span>` +
        `<span class="oc-sb-right">` +
        (perms ? `<span class="oc-sb-perms">${perms} Permission${perms > 1 ? "s" : ""}</span>` : "") +
        (model ? `<span class="oc-sb-model">${esc(model)}</span>` : "") +
        `<span class="oc-sb-tokens">${agent.tokens.toLocaleString()} tokens</span>` +
        `<span class="oc-sb-ok">${agent.msgs} msg</span>` +
        `</span>`;
    }

    function ocUserMsg(text) {
      const el = document.createElement("div");
      el.className = "oc-msg oc-msg-user";
      el.innerHTML = `
        <div class="oc-msg-head">
          <span class="oc-msg-role">user</span>
          <span class="oc-msg-time">${ocTime()}</span>
        </div>
        <div class="oc-msg-body"></div>`;
      el.querySelector(".oc-msg-body").textContent = text;
      if (elOcScreen) elOcScreen.appendChild(el);
      ocScroll();
      return el;
    }

    function ocAgentMsg(model) {
      const el = document.createElement("div");
      el.className = "oc-msg oc-msg-agent";
      el.innerHTML = `
        <div class="oc-msg-head">
          <span class="oc-msg-role">opencode</span>
          <span class="oc-msg-meta">${esc(model || "")}</span>
          <span class="oc-msg-time">${ocTime()}</span>
          <span class="oc-msg-tokens oc-msg-tok-v"></span>
        </div>
        <div class="oc-msg-body"></div>`;
      if (elOcScreen) elOcScreen.appendChild(el);
      ocScroll();
      return el;
    }

    function ocToolInfo(part) {
      const name = part.tool || (part.type || "").replace(/^tool\./, "") || "tool";
      const st = part.state || {};
      const input = st.input || part.input || {};
      let detail = "";
      if (input.command) detail = input.command;
      else if (input.filePath) detail = input.filePath;
      else if (input.path) detail = input.path;
      else if (input.pattern) detail = input.pattern;
      else if (input.query) detail = input.query;
      else if (input.url) detail = input.url;
      if (!detail && st.title) detail = st.title;
      const pretty = {
        bash: "Bash", read: "Read", edit: "Edit", write: "Write", glob: "Glob",
        grep: "Grep", list: "List", webfetch: "Web Fetch", websearch: "Web Search",
        todowrite: "Todo", "todo-write": "Todo", "todo-read": "Todo", task: "Task",
        ask: "Ask", multiedit: "Multi Edit", question: "Question",
      }[String(name).toLowerCase()] || name.charAt(0).toUpperCase() + name.slice(1);
      return { name, pretty, detail, st };
    }

    // live tool rows keyed by part id — like the TUI's └─ tool lines
    const ocToolEls = new Map();

    function ocToolRow(part, afterEl, beforeEl) {
      const key = part.id || (part.type + ":" + JSON.stringify(part.input || {}).slice(0, 60));
      let entry = ocToolEls.get(key);
      if (!entry) {
        const info = ocToolInfo(part);
        const wrap = document.createElement("div");
        wrap.className = "oc-tool";
        const row = document.createElement("div");
        row.className = "oc-tool-row";
        row.innerHTML = `<span class="oc-tool-name"></span><span class="oc-tool-detail"></span><span class="oc-tool-state"></span>`;
        const out = document.createElement("div");
        out.className = "oc-tool-out";
        out.hidden = true;
        row.addEventListener("click", () => { out.hidden = !out.hidden; ocScroll(); });
        wrap.appendChild(row);
        wrap.appendChild(out);
        if (elOcScreen) {
          // beforeEl: keep tool rows ABOVE the assistant message so the
          // summary always renders last (bottom), like the opencode TUI
          if (beforeEl && beforeEl.parentNode === elOcScreen) elOcScreen.insertBefore(wrap, beforeEl);
          else if (afterEl && afterEl.parentNode === elOcScreen) elOcScreen.insertBefore(wrap, afterEl.nextSibling);
          else elOcScreen.appendChild(wrap);
        }
        entry = { wrap, row, out, key };
        ocToolEls.set(key, entry);
      }
      ocToolUpdate(entry, part);
      ocScroll();
      return entry;
    }

    function ocToolUpdate(entry, part) {
      const info = ocToolInfo(part);
      const nameEl = entry.row.querySelector(".oc-tool-name");
      const detailEl = entry.row.querySelector(".oc-tool-detail");
      const stateEl = entry.row.querySelector(".oc-tool-state");
      nameEl.textContent = info.pretty;
      detailEl.textContent = info.detail ? info.detail.slice(0, 120) : "";
      const status = (info.st.status || "pending").toLowerCase();
      if (status === "running") {
        stateEl.className = "oc-tool-state oc-running";
        stateEl.innerHTML = `<span class="oc-spinner">⠋</span> running`;
      } else if (status === "completed" || status === "done") {
        stateEl.className = "oc-tool-state oc-done";
        stateEl.textContent = "done";
      } else if (status === "error") {
        stateEl.className = "oc-tool-state oc-error";
        stateEl.textContent = "error";
      } else {
        stateEl.className = "oc-tool-state oc-pending";
        stateEl.textContent = "pending";
      }
      const diff = (info.st.meta && info.st.meta.diff) || info.st.diff ||
        (info.st.output && info.st.output.diff);
      const output = info.st.output != null && typeof info.st.output !== "object" ? info.st.output : "";
      const err = info.st.error || "";
      if (diff) {
        entry.out.classList.add("oc-diff");
        entry.out.innerHTML = "";
        String(diff).split("\n").forEach((ln) => {
          const span = document.createElement("span");
          if (/^\+/.test(ln) && !/^\+\+\+/.test(ln)) span.className = "oc-add";
          else if (/^-/.test(ln) && !/^---/.test(ln)) span.className = "oc-del";
          else if (/^@@/.test(ln)) span.className = "oc-hunk";
          span.textContent = ln || " ";
          entry.out.appendChild(span);
        });
        entry.out.hidden = false;
      } else if (err) {
        entry.out.classList.remove("oc-diff");
        entry.out.textContent = err;
        entry.out.hidden = false;
      } else if (output) {
        entry.out.classList.remove("oc-diff");
        entry.out.textContent = String(output).slice(0, 8000);
        entry.out.hidden = false;
      }
    }

    // ── permission cards (TUI style: y / a / n) ─────────────────────
    async function agentReply(requestID, response, btn) {
      btn.disabled = true;
      try {
        await postJSON("/api/agent/permission/reply", { requestID, response });
        const card = btn.closest(".oc-perm");
        if (card) ocPermResolve(card, response === "reject" ? "denied" : "approved");
      } catch (err) {
        btn.disabled = false;
        btn.textContent = "Error: " + err.message;
      }
    }

    // collapse a resolved permission card to a one-line note, then remove it
    // so resolved cards don't pile up and bury the agent's response
    function ocPermResolve(card, note) {
      if (!card || card.dataset.resolved) return;
      card.dataset.resolved = "1";
      card.classList.add(note === "denied" || note === "cancelled" ? "oc-denied" : "oc-approved");
      const head = card.querySelector(".oc-perm-head");
      if (head) card.innerHTML = `<div class="oc-perm-head oc-perm-done">${head.textContent} — ${esc(note)}</div>`;
      card.classList.add("oc-perm-collapse");
      ocRenderStatus();
      setTimeout(() => { card.remove(); ocRenderStatus(); }, 1500);
    }

    function ocPermCard(r) {
      const rid = r.id || r.requestID;
      const permType = r.permission || r.tool || "tool";
      const patterns = (r.patterns && r.patterns.length) ? r.patterns : [];
      const meta = r.metadata || {};
      const body = patterns.join("\n") || meta.title || "";
      const card = document.createElement("div");
      card.className = "oc-perm";
      card.dataset.permId = rid;
      card.innerHTML = `
        <div class="oc-perm-head">△ ${esc(permType)} permission</div>
        <div class="oc-perm-body">
          ${meta.description ? `<p class="oc-perm-desc">${esc(meta.description)}</p>` : ""}
        </div>`;
      const bodyBox = card.querySelector(".oc-perm-body");
      if (meta.diff) {
        bodyBox.appendChild(ocDiffBlock(meta.diff));
        bodyBox.lastChild.classList.add("oc-diff");
      } else if (body) {
        const pre = document.createElement("div");
        pre.className = "oc-tool-out";
        pre.textContent = body;
        bodyBox.appendChild(pre);
      }
      const btns = document.createElement("div");
      btns.className = "oc-perm-btns";
      [["once", "y", "allow once", "oc-yes"], ["always", "a", "always this session", "oc-yes"], ["reject", "n", "reject", "oc-no"]].forEach(([resp, key, label, cls]) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "oc-perm-btn " + cls;
        b.innerHTML = `<b>${key})</b>${esc(label)}`;
        b.addEventListener("click", () => agentReply(rid, resp, b));
        btns.appendChild(b);
      });
      bodyBox.appendChild(btns);
      if (elOcScreen) elOcScreen.appendChild(card);
      ocScroll();
      ocRenderStatus();
      return card;
    }

    async function agentPollPermissions() {
      if (!agent.enabled || !agent.sessionID) return;
      try {
        const d = await fetchJSON("/api/agent/permission");
        const reqs = Array.isArray(d) ? d : (d.requests || []);
        // include subagent sessions — their permission requests belong to
        // this turn too and must be approvable from here
        reqs.forEach((r) => {
          const rid = r.id || r.requestID;
          if (!rid || document.querySelector(`.oc-perm[data-perm-id="${rid}"]`)) return;
          ocPermCard(r);
        });
      } catch (_) { /* agent server may be mid-restart */ }
    }

    // ── agent question cards (opencode question tool) ───────────────
    function ocQuestionCard(r) {
      const rid = r.id || r.requestID;
      if (!rid || document.querySelector(`.oc-question[data-qid="${rid}"]`)) return null;
      const questions = r.questions || [];
      if (!questions.length) return null;
      const card = document.createElement("div");
      card.className = "oc-perm oc-question";
      card.dataset.qid = rid;
      card.innerHTML = `<div class="oc-perm-head">? agent question</div>`;
      const box = document.createElement("div");
      box.className = "oc-perm-body";
      const answers = questions.map(() => []);
      const blocks = [];
      let sent = false;

      const allAnswered = () => answers.every((a) => a.length > 0);

      const submit = async () => {
        if (sent || !allAnswered()) return;
        sent = true;
        try {
          await postJSON("/api/agent/question/reply", { requestID: rid, answers });
          ocPermResolve(card, "answered");
        } catch (err) {
          sent = false;
          const errEl = card.querySelector(".oc-q-err");
          if (errEl) errEl.textContent = "reply failed: " + err.message;
        }
      };

      questions.forEach((q, qi) => {
        const blk = document.createElement("div");
        blk.className = "oc-q-block";
        const head = questions.length > 1 ? `<div class="oc-q-head">${esc(q.header || "Question " + (qi + 1))}</div>` : "";
        blk.innerHTML = `${head}<p class="oc-q-text">${esc(q.question || "")}</p>`;
        const opts = q.options || [];
        opts.forEach((o) => {
          const b = document.createElement("button");
          b.type = "button";
          b.className = "oc-q-opt";
          b.innerHTML = `<b>${esc(o.label)}</b>${o.description ? `<span class="oc-q-desc">${esc(o.description)}</span>` : ""}`;
          b.addEventListener("click", () => {
            blk.querySelectorAll(".oc-q-opt.oc-sel").forEach((x) => x.classList.remove("oc-sel"));
            if (!q.multiple && answers[qi][0] === o.label) { answers[qi] = []; return; }
            if (q.multiple && answers[qi].includes(o.label)) {
              answers[qi] = answers[qi].filter((l) => l !== o.label);
              b.classList.remove("oc-sel");
            } else {
              answers[qi] = q.multiple ? answers[qi].concat([o.label]) : [o.label];
              b.classList.add("oc-sel");
            }
            if (!q.multiple && q.custom === false) submit();
          });
          blk.appendChild(b);
        });
        if (q.custom !== false) {
          const row = document.createElement("div");
          row.className = "oc-q-custom";
          const inp = document.createElement("input");
          inp.type = "text";
          inp.placeholder = "type your own answer…";
          inp.autocomplete = "off";
          const go = () => {
            const v = inp.value.trim();
            if (!v) return;
            blk.querySelectorAll(".oc-q-opt.oc-sel").forEach((x) => x.classList.remove("oc-sel"));
            answers[qi] = [v];
            submit();
          };
          inp.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } });
          const b = document.createElement("button");
          b.type = "button";
          b.className = "oc-q-send";
          b.textContent = "send";
          b.addEventListener("click", go);
          row.appendChild(inp);
          row.appendChild(b);
          blk.appendChild(row);
        }
        box.appendChild(blk);
        blocks.push(blk);
      });

      const btns = document.createElement("div");
      btns.className = "oc-perm-btns";
      const answerBtn = document.createElement("button");
      answerBtn.type = "button";
      answerBtn.className = "oc-perm-btn oc-yes";
      answerBtn.innerHTML = "<b>↵)</b>answer";
      answerBtn.addEventListener("click", submit);
      const skipBtn = document.createElement("button");
      skipBtn.type = "button";
      skipBtn.className = "oc-perm-btn oc-no";
      skipBtn.innerHTML = "<b>x)</b>skip question";
      skipBtn.addEventListener("click", async () => {
        if (sent) return;
        sent = true;
        try {
          await postJSON("/api/agent/question/reject", { requestID: rid });
          ocPermResolve(card, "skipped");
        } catch (err) {
          sent = false;
          const errEl = card.querySelector(".oc-q-err");
          if (errEl) errEl.textContent = "reject failed: " + err.message;
        }
      });
      btns.appendChild(answerBtn);
      btns.appendChild(skipBtn);
      box.appendChild(btns);
      const errEl = document.createElement("div");
      errEl.className = "oc-q-err";
      box.appendChild(errEl);
      card.appendChild(box);
      if (elOcScreen) elOcScreen.appendChild(card);
      ocScroll();
      ocRenderStatus();
      return card;
    }

    async function ocPollQuestions() {
      if (!agent.enabled || !agent.sessionID) return;
      try {
        const d = await fetchJSON("/api/agent/question");
        const reqs = Array.isArray(d) ? d : (d.requests || []);
        // only surface questions for the ACTIVE session — stale questions
        // from old sessions stay on the agent server, untouched
        reqs.forEach((r) => {
          if ((r.sessionID || "") !== agent.sessionID) return;
          ocQuestionCard(r);
        });
      } catch (_) { /* agent server may be mid-restart */ }
    }

    async function agentEnsureSession() {
      if (agent.sessionID) return agent.sessionID;
      const d = await postJSON("/api/agent/session/new", {});
      const sid = d.id;
      if (!sid) throw new Error(d.error || "could not create agent session");
      agent.sessionID = sid;
      // start permission polling while a session is active
      if (!agent.pollTimer) {
          agent.pollTimer = setInterval(() => {
            if (agent.busy) { agentPollPermissions(); ocPollQuestions(); }
          }, 2000);
        }
      return sid;
    }

    // ── live event stream (SSE) from opencode ──────────────────────
    agent.es = null;
    agent.onEvent = null;

    function agentEvents() {
      if (agent.es) return agent.es;
      try {
        const es = new EventSource("/api/agent/events");
        es.onmessage = (ev) => {
          if (!agent.onEvent) return;
          let d = null;
          try { d = JSON.parse(ev.data); } catch (_) { return; }
          agent.onEvent(d);
        };
        es.onerror = () => { /* EventSource auto-reconnects */ };
        agent.es = es;
      } catch (_) { agent.es = null; }
      return agent.es;
    }

    // ── agent prompt pipeline (terminal) ────────────────────────────
    function ocClearInput() {
      if (elOcInput) { elOcInput.value = ""; elOcInput.style.height = "auto"; }
      ocUpdateModeNote("");
      ocPopupHide();
    }

    function ocUpdateModeNote(val) {
      const v = (val != null ? val : (elOcInput ? elOcInput.value : "")).trim();
      if (!elOcNote || !elOcMark) return;
      if (v.startsWith("/")) { elOcNote.textContent = "command"; elOcNote.className = "oc-mode-note"; elOcMark.textContent = "/"; }
      else if (v.startsWith("!")) { elOcNote.textContent = "shell"; elOcNote.className = "oc-mode-note oc-shell"; elOcMark.textContent = "!"; }
      else { elOcNote.textContent = "build"; elOcNote.className = "oc-mode-note"; elOcMark.textContent = "❯"; }
    }

    async function ocShell(command) {
      if (!command) return;
      if (agent.busy) { ocLine("a task is already running — press esc to abort", "oc-muted"); return; }
      ocLine(command, "oc-echo");
      try {
        const sid = await agentEnsureSession();
        agent.busy = true;
        ocSetState("busy");
        const d = await postJSON("/api/agent/shell", { sessionID: sid, command });
        const res = d.result || {};
        const parts = res.parts || [];
        let out = "";
        parts.forEach((p) => {
          const t = p.type || "";
          if (t === "tool" || t.startsWith("tool")) {
            const st = p.state || {};
            if (st.output != null && typeof st.output !== "object") out += st.output;
            if (st.error) out += (out ? "\n" : "") + st.error;
          } else if (t === "text" && p.text) {
            out += (out ? "\n" : "") + p.text;
          }
        });
        if (String(out).trim()) ocBlock(out);
        else ocLine("(no output)", "oc-muted");
      } catch (err) {
        ocLine("shell error: " + err.message, "oc-error");
        ocSetState("error");
      } finally {
        agent.busy = false;
        if (!document.querySelector(".oc-perm:not(.oc-approved):not(.oc-denied)")) ocSetState("idle");
        ocRenderStatus();
      }
    }

    async function ocAbort() {
      if (!agent.sessionID) { ocLine("no active session", "oc-muted"); return; }
      if (!agent.busy) { ocLine("nothing running", "oc-muted"); return; }
      // detach the live event handlers immediately so the UI stops waiting
      agent.onEvent = null;
      try {
        await postJSON("/api/agent/session/abort", { sessionID: agent.sessionID });
        ocLine("aborted", "oc-warn");
      } catch (err) {
        ocLine("abort failed: " + err.message, "oc-error");
      }
      // force-finish the pending turn locally even if the server is slow
      // to confirm: clear any open permission cards and reset the state
      document.querySelectorAll(".oc-perm:not(.oc-approved):not(.oc-denied)").forEach((el) => {
        if (el.classList.contains("oc-question") && el.dataset.qid) {
          postJSON("/api/agent/question/reject", { requestID: el.dataset.qid }).catch(() => {});
        }
        ocPermResolve(el, "cancelled");
      });
      agent.busy = false;
      ocSetState("idle");
      agentUpdateStats();
    }

    async function ocRunCommand(raw) {
      const trimmed = raw.trim();
      const sp = trimmed.indexOf(" ");
      const cmd = (sp === -1 ? trimmed : trimmed.slice(0, sp)).toLowerCase();
      ocLine(trimmed, "oc-echo");
      const model = elAgentModel ? elAgentModel.value : "";
      const need = () => agent.sessionID || agentEnsureSession();
      try {
        switch (cmd) {
          case "/help":
            ocHelpModal();
            break;
          case "/new":
          case "/clear":
            ocToolEls.clear();
            ocBootScreen(false);
            ocLine("new session — type a prompt to begin", "oc-info");
            break;
          case "/sessions":
          case "/resume":
          case "/continue":
            ocSessionsModal();
            break;
          case "/undo": {
            const d = await postJSON("/api/agent/session/revert", { sessionID: await need() });
            ocLine("undid last message — file changes reverted (git)", "oc-ok");
            break;
          }
          case "/redo": {
            await postJSON("/api/agent/session/unrevert", { sessionID: await need() });
            ocLine("redone", "oc-ok");
            break;
          }
          case "/compact":
          case "/summarize": {
            ocLine("compacting session context…", "oc-info");
            await postJSON("/api/agent/session/summarize", { sessionID: await need(), model });
            ocLine("session compacted", "oc-ok");
            break;
          }
          case "/share": {
            const d = await postJSON("/api/agent/session/share", { sessionID: await need() });
            const s = d.session || {};
            const url = s.share || (s.share && s.share.url) || "";
            ocLine("shared: " + (url || "(no url returned — is sharing configured?)"), "oc-ok");
            break;
          }
          case "/unshare": {
            await postJSON("/api/agent/session/unshare", { sessionID: await need() });
            ocLine("session unshared", "oc-ok");
            break;
          }
          case "/init": {
            ocLine("analyzing project, writing AGENTS.md…", "oc-info");
            await postJSON("/api/agent/session/init", { sessionID: await need(), model });
            ocLine("AGENTS.md created", "oc-ok");
            break;
          }
          case "/abort":
            await ocAbort();
            break;
          case "/models":
            if (elAgentModel) {
              elAgentModel.focus();
              ocLine("model picker focused in the side panel — it applies to the next message", "oc-info");
            }
            break;
          case "/exit":
          case "/quit":
          case "/q":
            ocLine("opencode is the only assistant — nothing to exit to", "oc-muted");
            break;
          default:
            ocLine("unknown command: " + cmd + " — try /help", "oc-error");
        }
      } catch (err) {
        ocLine("error: " + err.message, "oc-error");
      }
    }

    // ── modals (sessions, help) ─────────────────────────────────────
    function ocModalOpen(title, bodyEl) {
      if (!elOcOverlay || !elOcModal) return;
      elOcModal.innerHTML = "";
      const head = document.createElement("div");
      head.className = "oc-modal-head";
      head.innerHTML = `<span>${esc(title)}</span><button class="oc-modal-x" type="button">✕</button>`;
      head.querySelector(".oc-modal-x").addEventListener("click", ocModalClose);
      const body = document.createElement("div");
      body.className = "oc-modal-body";
      if (bodyEl) body.appendChild(bodyEl);
      elOcModal.appendChild(head);
      elOcModal.appendChild(body);
      elOcOverlay.hidden = false;
    }

    function ocModalClose() { if (elOcOverlay) elOcOverlay.hidden = true; }

    function ocHelpModal() {
      const wrap = document.createElement("div");
      wrap.style.padding = "6px 4px";
      const head = document.createElement("div");
      head.className = "oc-help-cmd";
      head.innerHTML = `<b>command</b><span>what it does</span>`;
      head.style.opacity = "0.5";
      wrap.appendChild(head);
      OC_COMMANDS.forEach((c) => {
        const row = document.createElement("div");
        row.className = "oc-help-cmd";
        row.innerHTML = `<b>${esc(c.cmd)}${c.alias ? ` <i style="color:var(--oc-muted)">${esc(c.alias)}</i>` : ""}</b><span>${esc(c.desc)}</span>`;
        wrap.appendChild(row);
      });
      const extra = document.createElement("div");
      extra.className = "oc-help-cmd";
      extra.style.marginTop = "10px";
      extra.innerHTML = `<b>@file</b><span>fuzzy-search files and attach to the prompt</span>`;
      wrap.appendChild(extra);
      const extra2 = document.createElement("div");
      extra2.className = "oc-help-cmd";
      extra2.innerHTML = `<b>!command</b><span>run a shell command on the gateway</span>`;
      wrap.appendChild(extra2);
      ocModalOpen("opencode — help", wrap);
    }

    async function ocSessionsModal() {
      const wrap = document.createElement("div");
      wrap.innerHTML = `<div class="oc-modal-empty">loading sessions…</div>`;
      ocModalOpen("sessions — click to continue one", wrap);
      try {
        const d = await fetchJSON("/api/agent/session");
        const sessions = Array.isArray(d) ? d : (d.sessions || []);
        wrap.innerHTML = "";
        if (!sessions.length) {
          wrap.innerHTML = `<div class="oc-modal-empty">no sessions yet — send a prompt first</div>`;
          return;
        }
        sessions.sort((a, b) => {
          const at = (a.time && (a.time.updated || a.time.created)) || 0;
          const bt = (b.time && (b.time.updated || b.time.created)) || 0;
          return bt - at;
        });
        sessions.forEach((s) => {
          const row = document.createElement("div");
          row.className = "oc-sess" + (s.id === agent.sessionID ? " oc-sel" : "");
          const raw = (s.time && (s.time.updated || s.time.created)) || null;
          let when = "";
          if (raw) {
            const ms = typeof raw === "number" && String(raw).length === 10 ? raw * 1000 : raw;
            when = new Date(typeof ms === "number" ? ms : Date.parse(ms)).toLocaleString();
          }
          const title = s.title || s.id;
          row.innerHTML = `
            <span class="oc-sess-title">${s.id === agent.sessionID ? "<b>● </b>" : ""}${esc(String(title).slice(0, 70))}</span>
            <span class="oc-sess-time">${esc(when)}</span>`;
          const del = document.createElement("button");
          del.type = "button";
          del.className = "oc-sess-act";
          del.textContent = "delete";
          del.addEventListener("click", async (e) => {
            e.stopPropagation();
            if (!window.confirm("Delete this agent session?")) return;
            try {
              await postJSON("/api/agent/session/delete", { sessionID: s.id });
              row.remove();
              if (s.id === agent.sessionID) agent.sessionID = null;
            } catch (err) { ocLine("delete failed: " + err.message, "oc-error"); }
          });
          row.appendChild(del);
          row.addEventListener("click", () => { ocModalClose(); ocLoadSession(s.id); });
          wrap.appendChild(row);
        });
      } catch (err) {
        wrap.innerHTML = `<div class="oc-modal-empty">${esc(err.message || "failed to load sessions")}</div>`;
      }
    }

    async function ocLoadSession(sid) {
      ocToolEls.clear();
      if (elOcScreen) elOcScreen.innerHTML = "";
      agent.sessionID = sid;
      try {
        const d = await fetchJSON("/api/agent/session/messages?id=" + encodeURIComponent(sid));
        const msgs = d.messages || [];
        if (elOcScreen) elOcScreen.innerHTML = "";
        if (!msgs.length) { ocLine("(empty session)", "oc-muted"); return; }
        msgs.forEach((m) => ocRenderHistoryMsg(m.info, m.parts));
        ocLine("— session restored · " + msgs.length + " messages —", "oc-muted");
        ocScroll();
      } catch (err) {
        ocLine("failed to load session: " + err.message, "oc-error");
      }
    }

    function ocRenderHistoryMsg(info, parts) {
      const role = info && info.role;
      if (role === "user") {
        const text = (parts || []).filter((p) => p.type === "text").map((p) => p.text).join("\n");
        if (text) ocUserMsg(text);
        return;
      }
      if (role !== "assistant") return;
      const modelLabel = (info && (info.modelID || (info.model && info.model.modelID))) || "";
      const el = ocAgentMsg(modelLabel);
      const body = el.querySelector(".oc-msg-body");
      let anchor = el;
      (parts || []).forEach((p) => {
        const t = p.type || "";
        if (t === "text" && p.text) {
          body.appendChild(document.createTextNode(p.text));
        } else if (t === "reasoning") {
          const rtext = (p.state && p.state.text) || p.text || "";
          if (rtext) {
            const th = document.createElement("div");
            th.className = "oc-thinking";
            th.textContent = rtext;
            body.appendChild(th);
          }
        } else if (t === "tool" || t.startsWith("tool")) {
          const entry = ocToolRow(p, null, el);
          anchor = entry.wrap;
        }
      });
      const tok = (info && info.tokens) || {};
      const totalTok = (tok.input || 0) + (tok.output || 0) + (tok.reasoning || 0);
      const tokEl = el.querySelector(".oc-msg-tok-v");
      if (tokEl && totalTok) tokEl.textContent = totalTok.toLocaleString() + " tokens";
      if (!body.childNodes.length && anchor === el) el.remove();
      ocScroll();
    }

    // ── autocomplete popup (/ commands · @ files) ────────────────────
    let ocPopupItems = [];
    let ocPopupSel = 0;
    let ocPopupKind = null; // "cmd" | "file"
    let ocPopupToken = "";

    function ocPopupShow(kind, items, token) {
      if (!elOcPopup || !items.length) { ocPopupHide(); return; }
      ocPopupItems = items;
      ocPopupKind = kind;
      ocPopupToken = token || "";
      ocPopupSel = 0;
      ocPopupRender();
      elOcPopup.hidden = false;
    }

    function ocPopupRender() {
      if (!elOcPopup) return;
      elOcPopup.innerHTML = "";
      ocPopupItems.forEach((it, i) => {
        const row = document.createElement("div");
        row.className = "oc-popup-item" + (i === ocPopupSel ? " oc-sel" : "");
        if (ocPopupKind === "cmd") {
          row.innerHTML = `<span class="oc-pop-cmd">${esc(it.cmd)}</span><span class="oc-pop-desc">${esc(it.desc)}</span>` +
            (it.alias ? `<span class="oc-pop-hint">${esc(it.alias)}</span>` : "");
        } else {
          row.innerHTML = `<span class="oc-pop-desc" style="color:var(--oc-text)">${esc(it)}</span>`;
        }
        row.addEventListener("mousedown", (e) => { e.preventDefault(); ocPopupPick(i); });
        elOcPopup.appendChild(row);
      });
    }

    function ocPopupHide() {
      if (!elOcPopup) return;
      elOcPopup.hidden = true;
      ocPopupItems = [];
      ocPopupKind = null;
      ocPopupToken = "";
    }

    function ocPopupPick(i) {
      const it = ocPopupItems[i != null ? i : ocPopupSel];
      if (!it || !elOcInput) { ocPopupHide(); return; }
      const val = elOcInput.value;
      if (ocPopupKind === "cmd") {
        elOcInput.value = it.cmd + " ";
      } else {
        // replace the @token with @path
        const atIdx = val.lastIndexOf("@");
        if (atIdx >= 0) elOcInput.value = val.slice(0, atIdx) + "@" + it + " " + val.slice(atIdx + 1 + ocPopupToken.length);
      }
      ocPopupHide();
      elOcInput.focus();
      ocUpdateModeNote();
    }

    async function ocMaybePopup() {
      if (!elOcInput) return;
      const val = elOcInput.value;
      if (val.startsWith("/")) {
        const word = val.split(" ")[0].toLowerCase();
        const matches = OC_COMMANDS.filter((c) => c.cmd.startsWith(word));
        ocPopupShow("cmd", matches, word);
        return;
      }
      const atIdx = val.lastIndexOf("@");
      if (atIdx >= 0) {
        const after = val.slice(atIdx + 1);
        if (!after.includes(" ") && after.length <= 60) {
          if (!after) { ocPopupShow("file", [], ""); return; }
          try {
            const d = await fetchJSON("/api/agent/find/file?q=" + encodeURIComponent(after));
            if (d && d.ok !== false) ocPopupShow("file", d.files || [], after);
          } catch (_) { ocPopupHide(); }
          return;
        }
      }
      ocPopupHide();
    }

    // ── submit ──────────────────────────────────────────────────────
    function ocSubmit() {
      if (!elOcInput) return;
      const text = elOcInput.value.trim();
      if (!text) return;
      if (!elOcPopup.hidden) {
        if (ocPopupKind === "cmd" && OC_COMMANDS.some((c) => c.cmd === text)) {
          ocPopupHide(); // exact match — run it right away
        } else {
          ocPopupPick();
          return;
        }
      }
      ocClearInput();
      sendAgentMessage(text);
    }

    async function sendAgentMessage(text) {
      text = (text || "").trim();
      if (!text) return;
      if (text.startsWith("/")) return ocRunCommand(text);
      if (text.startsWith("!")) return ocShell(text.slice(1).trim());
      if (agent.busy) { ocLine("a task is already running — press esc to abort", "oc-muted"); return; }

      ocUserMsg(text);
      agent.busy = true;
      ocSetState("busy");
      const model = elAgentModel ? elAgentModel.value : "";

      let msgEl = null, bodyEl = null, cursorEl = null, fullText = "", lastInfo = null;
      let watchdog = null;
      let assistantMsgID = null;
      let sid = null;

      const ensureMsg = () => {
        if (msgEl) return;
        msgEl = ocAgentMsg(model);
        bodyEl = msgEl.querySelector(".oc-msg-body");
        cursorEl = document.createElement("span");
        cursorEl.className = "oc-cursor";
        bodyEl.appendChild(cursorEl);
      };
      const setText = (t) => {
        ensureMsg();
        fullText = t || "";
        while (bodyEl.firstChild && bodyEl.firstChild !== cursorEl) bodyEl.removeChild(bodyEl.firstChild);
        bodyEl.insertBefore(document.createTextNode(fullText), cursorEl);
        ocScroll();
      };
      const finish = (err) => {
        agent.onEvent = null;
        clearTimeout(watchdog);
        if (cursorEl) cursorEl.remove();
        if (err) {
          if (msgEl && !fullText) msgEl.remove();
          ocLine(String(err), "oc-error");
          ocSetState("error");
        } else {
          if (msgEl && lastInfo) {
            const tok = lastInfo.tokens || {};
            const total = (tok.input || 0) + (tok.output || 0) + (tok.reasoning || 0);
            const tokEl = msgEl.querySelector(".oc-msg-tok-v");
            if (tokEl && total) tokEl.textContent = total.toLocaleString() + " tokens";
          }
          if (!msgEl && ocToolEls.size === 0) ocLine("(agent finished)", "oc-muted");
          ocSetState("idle");
          agent.msgs += 1;
          // authoritative usage: opencode tracks cumulative session totals
          if (sid) {
            fetchJSON("/api/agent/session?id=" + encodeURIComponent(sid)).then((s) => {
              const t = s.tokens || {};
              agent.tokens = (t.input || 0) + (t.output || 0) + (t.reasoning || 0)
                + (t.cache && (t.cache.read || 0) || 0) + (t.cache && (t.cache.write || 0) || 0);
              agent.cost = s.cost || 0;
              agentUpdateStats();
            }).catch(() => {
              // fallback: accumulate from the last event we saw
              const tok = (lastInfo && lastInfo.tokens) || {};
              agent.tokens += (tok.input || 0) + (tok.output || 0) + (tok.reasoning || 0);
              agent.cost += (lastInfo && lastInfo.cost) || 0;
              agentUpdateStats();
            });
          } else {
            const tok = (lastInfo && lastInfo.tokens) || {};
            agent.tokens += (tok.input || 0) + (tok.output || 0) + (tok.reasoning || 0);
            agent.cost += (lastInfo && lastInfo.cost) || 0;
            agentUpdateStats();
          }
        }
        agent.busy = false;
        agentUpdateStats();
      };

      bumpWatchdog();
      function bumpWatchdog() {
        clearTimeout(watchdog);
        watchdog = setTimeout(async () => {
          if (!agent.busy) return;
          // a pending permission request means the agent is waiting on the
          // user, not stuck — keep waiting as long as approvals are pending
          // (any session: subagent requests count too)
          try {
            // recover any permission card lost to an SSE gap: re-render
            // pending requests that have no card in the terminal yet
            await agentPollPermissions();
            const d = await fetchJSON("/api/agent/permission");
            const pending = (Array.isArray(d) ? d : (d.requests || []))
              .filter((r) => !document.querySelector(`.oc-perm[data-perm-id="${r.id}"].oc-denied, .oc-perm[data-perm-id="${r.id}"].oc-approved`));
            if (pending.length) { bumpWatchdog(); return; }
          } catch (_) { /* proceed to timeout */ }
          // an unanswered question card also means the agent is waiting
          // on the user, not stuck — keep waiting while it is on screen
          try {
            await ocPollQuestions();
            if (document.querySelector(".oc-question:not(.oc-approved):not(.oc-denied)")) { bumpWatchdog(); return; }
          } catch (_) { /* proceed to timeout */ }
          finish("Timed out waiting for agent events (is tuxwall-agent.service healthy?). Check: journalctl -u tuxwall.service -t -n 50 | grep agent");
        }, 180000);
      }

      try {
        sid = await agentEnsureSession();
        agentEvents();
        agent.onEvent = (ev) => {
          if (!agent.busy) return; // aborted — ignore stale events
          const props = ev.properties || {};
          const type = ev.type;
          if (type === "permission.asked") {
            // permission requests always render, even from subagent
            // sessions (they carry their own sessionID) — filtering on
            // sessionID here made prompts invisible and hung the turn
            bumpWatchdog();
            const r = props;
            const rid = r.id || r.requestID;
            if (rid && !document.querySelector(`.oc-perm[data-perm-id="${rid}"]`)) ocPermCard(r);
            return;
          }
          if (type === "question.asked" || type === "question.v2.asked") {
            bumpWatchdog();
            ocQuestionCard(props);
            return;
          }
          if (type === "question.replied" || type === "question.v2.replied") {
            const qc = document.querySelector(`.oc-question[data-qid="${props.requestID}"]`);
            if (qc) ocPermResolve(qc, "answered");
            return;
          }
          if (type === "question.rejected" || type === "question.v2.rejected") {
            const qc = document.querySelector(`.oc-question[data-qid="${props.requestID}"]`);
            if (qc) ocPermResolve(qc, "skipped");
            return;
          }
          if (props.sessionID !== sid) return;
          if (type === "message.updated") {
            const info = props.info || {};
            if (info.role === "assistant") { lastInfo = info; assistantMsgID = info.id; }
            if (info.error) finish("Agent error: " + (info.error.message || JSON.stringify(info.error)));
          } else if (type === "message.part.updated") {
            const part = props.part || {};
            if (part.messageID && assistantMsgID && part.messageID !== assistantMsgID) return;
            const pt = part.type || "";
            if (pt === "text") {
              bumpWatchdog();
              setText(part.text || "");
            } else if (pt === "reasoning") {
              bumpWatchdog();
            } else if (pt === "tool" || pt.startsWith("tool")) {
              bumpWatchdog();
              ocToolRow(part, null, msgEl);
            }
          } else if (type === "message.part.delta") {
            if (props.messageID && assistantMsgID && props.messageID !== assistantMsgID) return;
            bumpWatchdog();
            if (props.field === "text" && props.delta) setText(fullText + props.delta);
          } else if (type === "session.idle") {
            finish();
          }
        };

        const d = await postJSON("/api/agent/message", { sessionID: sid, text, model });
        if (!d.async) {
          // server fell back to blocking mode: response is the final message
          agent.onEvent = null;
          clearTimeout(watchdog);
          if (msgEl) msgEl.remove();
          const parts = d.parts || [];
          const el = ocAgentMsg(model);
          const body = el.querySelector(".oc-msg-body");
          let anchor = el;
          parts.forEach((p) => {
            const pt = p.type || "";
            if (pt === "text" && p.text) body.appendChild(document.createTextNode(p.text));
            else if (pt === "tool" || pt.startsWith("tool")) anchor = ocToolRow(p, null, el).wrap;
          });
          const tok = d.tokens || {};
          const total = (tok.input || 0) + (tok.output || 0) + (tok.reasoning || 0);
          const tokEl = el.querySelector(".oc-msg-tok-v");
          if (tokEl && total) tokEl.textContent = total.toLocaleString() + " tokens";
          agent.tokens += total;
          agent.cost += d.cost || 0;
          agent.msgs += 1;
          agent.busy = false;
          ocSetState("idle");
          agentUpdateStats();
        }
      } catch (err) {
        finish(err.message + (err.detail ? "\n" + err.detail : ""));
      }
    }

    // ── terminal event bindings ─────────────────────────────────────
    if (elAgentNewSess) {
      elAgentNewSess.addEventListener("click", () => {
        ocToolEls.clear();
        ocBootScreen(false);
        ocLine("new session — type a prompt to begin", "oc-info");
        if (elOcInput) elOcInput.focus();
      });
    }
    if (elAgentSessBtn) elAgentSessBtn.addEventListener("click", () => ocSessionsModal());
    if (elOcSend) elOcSend.addEventListener("click", ocSubmit);
    if (elOcOverlay) elOcOverlay.addEventListener("click", (e) => { if (e.target === elOcOverlay) ocModalClose(); });
    if (elAgentModel) {
      elAgentModel.addEventListener("change", () => {
        agent.model = elAgentModel.value;
        try { localStorage.setItem("tuxwall.agent.model", elAgentModel.value); } catch (_) {}
        ocLine("model → " + (elAgentModel.value || "default"), "oc-muted");
        ocRenderStatus();
      });
    }
    if (elOcInput) {
      elOcInput.addEventListener("keydown", (e) => {
        if (!elOcPopup || !elOcPopup.hidden) {
          if (e.key === "ArrowDown") { e.preventDefault(); ocPopupSel = Math.min(ocPopupSel + 1, ocPopupItems.length - 1); ocPopupRender(); return; }
          if (e.key === "ArrowUp") { e.preventDefault(); ocPopupSel = Math.max(ocPopupSel - 1, 0); ocPopupRender(); return; }
          if (e.key === "Tab") { e.preventDefault(); ocPopupPick(); return; }
          if (e.key === "Escape") { e.preventDefault(); ocPopupHide(); return; }
        }
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          ocSubmit();
          return;
        }
        if (e.key === "Escape") {
          e.preventDefault();
          if (!elOcOverlay || elOcOverlay.hidden) {
            if (agent.busy) ocAbort();
          } else {
            ocModalClose();
          }
          return;
        }
        if (e.key === "c" && e.ctrlKey) { e.preventDefault(); ocPopupHide(); return; }
      });
      elOcInput.addEventListener("input", () => {
        elOcInput.style.height = "auto";
        elOcInput.style.height = Math.min(elOcInput.scrollHeight, 180) + "px";
        ocUpdateModeNote();
        ocMaybePopup();
      });
    }

    // opencode is the only AI assistant — expose enable hook for switchView()
    window.__tuxwallAgentEnable = agentSetEnabled;
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
    bindSystemBackups();
    bindWireguardActions();
    bindFirewallActions();
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
    bindTotpActions();
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

    // Sidebar version badge (shown on login-independent init too)
    const brandVersion = document.getElementById("brand-version");
    if (brandVersion && !brandVersion.textContent) {
      fetchJSON("/api/system")
        .then((d) => {
          if (d && d.tuxwall_version) brandVersion.textContent = "v" + d.tuxwall_version;
        })
        .catch(() => {});
    }
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
    els.loginTotpLabel.hidden = true;
    els.loginTotp.hidden = true;
    els.loginTotp.value = "";
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
    els.usersMsg.textContent = "You are signed in with the default password (admin / tuxwall) - change it with the Change password button.";
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
    els.usersCard.hidden = false;
    updateTotpCard();
    els.usersAdmin.hidden = !state.canManageUsers;
    els.sideUser.textContent = state.username || "";
    els.sideRole.textContent = roleLabel();
    if (!isAdmin && state.activeView === "settings") {
      switchView("overview");
    }
    if (state.data) render();
    if (state.svcData) renderServices();
  }

  async function loadUsers() {
    if (!state.canManageUsers) return;
    try {
      const d = await fetchJSON("/api/auth/users");
      state.users = d.users || [];
      renderUsers();
      els.usersMsg.textContent = "";
    } catch (err) {
      els.usersMsg.textContent = err.message;
    }
  }

  const ICONS = {
    edit: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.8 2.8 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>`,
    power: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/></svg>`,
    trash: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>`,
  };

  function iconBtn(icon, title, attrs) {
    return `<button class="icon-btn" type="button" title="${title}" ${attrs}>${ICONS[icon]}</button>`;
  }

  function renderUsers() {
    const me = state.username;
    const q = (els.usersSearch.value || "").trim().toLowerCase();
    const users = (state.users || []).filter((u) =>
      !q || u.username.toLowerCase().includes(q) || (u.fullname || "").toLowerCase().includes(q)
    );
    els.usersCount.textContent = `${users.length} of ${(state.users || []).length} users`;
    els.usersTbody.innerHTML = users.map((u) => {
      const badge = u.owner
        ? `<span class="badge badge-static">Primary admin</span>`
        : u.role === "admin"
          ? `<span class="badge badge-ok">Admin</span>`
          : `<span class="badge">Viewer</span>`;
      const status = u.disabled
        ? `<span class="badge badge-err">Disabled</span>`
        : `<span class="badge badge-ok">Enabled</span>`;
      const actions = u.owner
        ? (
          iconBtn("edit", "Edit", `data-edit="${esc(u.username)}"`) +
          iconBtn("power", u.disabled ? "Enable" : "Disable", `data-toggle="${esc(u.username)}" data-enabled="${u.disabled ? "0" : "1"}"`)
        )
        : (
          iconBtn("edit", "Edit", `data-edit="${esc(u.username)}"`) +
          iconBtn("power", u.disabled ? "Enable" : "Disable", `data-toggle="${esc(u.username)}" data-enabled="${u.disabled ? "0" : "1"}"`) +
          iconBtn("trash", "Remove", `data-del="${esc(u.username)}" class="icon-btn icon-btn-danger"`)
        );
      return `
        <tr>
          <td><b>${esc(u.username)}</b>${u.username === me ? ` <span class="muted">(you)</span>` : ""}</td>
          <td>${u.fullname ? esc(u.fullname) : '<span class="muted">—</span>'}</td>
          <td>${badge}</td>
          <td>${status}</td>
          <td class="wg-actions">${actions}</td>
        </tr>`;
    }).join("");
  }

  function closeUserModal() {
    els.userModal.hidden = true;
    els.umMsg.textContent = "";
  }

  function openUserModal(user) {
    els.umMsg.textContent = "";
    els.umSave.disabled = false;
    els.umName.readOnly = !!user;
    els.umName.value = user ? user.username : "";
    els.umFullname.value = user ? (user.fullname || "") : "";
    els.umCurrent.value = "";
    els.umPass.value = "";
    els.umPass2.value = "";
    const isSelf = !!(user && user.username === state.username);
    const canEditProfile = !user || state.canManageUsers;
    els.umCurrentField.hidden = !isSelf;
    els.umPassField.hidden = false;
    els.umPass2Field.hidden = false;
    els.umPassLabel.textContent = user ? "New password (blank = keep current)" : "Password (min 8)";
    els.umPass.placeholder = user ? "leave blank to keep current" : "min 8 characters";
    els.umFullname.parentElement.hidden = !canEditProfile;
    els.umRoleField.hidden = isSelf || !!(user && user.owner);
    els.umEnabledField.hidden = isSelf || !!(user && user.owner);
    if (user) {
      els.umRole.value = user.role || "viewer";
      els.umEnabled.checked = !user.disabled;
    } else {
      els.umRole.value = "viewer";
      els.umEnabled.checked = true;
    }
    els.userModalTitle.textContent = isSelf
      ? "Change your password"
      : user ? `Edit user — ${user.username}` : "Add user";
    els.userModal.hidden = false;
    setTimeout(() => {
      try { (isSelf ? els.umCurrent : (user ? els.umFullname : els.umName)).focus(); } catch (err) { }
    }, 60);
  }

  function bindUsersActions() {
    els.nuOpen.addEventListener("click", () => openUserModal(null));
    els.userModalClose.addEventListener("click", closeUserModal);
    els.umCancel.addEventListener("click", closeUserModal);
    els.userModal.addEventListener("click", (e) => {
      if (e.target === els.userModal) closeUserModal();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !els.userModal.hidden) closeUserModal();
    });
    els.usersSearch.addEventListener("input", renderUsers);

    els.umSave.addEventListener("click", async () => {
      const editing = els.umName.readOnly;
      const isSelf = els.umCurrentField.hidden === false;
      const username = els.umName.value.trim();
      const fullname = els.umFullname.value.trim();
      const current = els.umCurrent.value;
      const password = els.umPass.value;
      els.umMsg.textContent = "";
      if (!username) {
        els.umMsg.textContent = "Enter a username.";
        return;
      }
      if (!editing && !password) {
        els.umMsg.textContent = "Enter a password (min 8 characters).";
        return;
      }
      if (password && password !== els.umPass2.value) {
        els.umMsg.textContent = "Passwords do not match.";
        return;
      }
      if (isSelf && password && !current) {
        els.umMsg.textContent = "Enter your current password.";
        return;
      }
      if (isSelf && !password) {
        els.umMsg.textContent = "Enter a new password.";
        return;
      }
      els.umSave.disabled = true;
      try {
        if (isSelf) {
          if (!els.umFullname.parentElement.hidden) {
            await postJSON("/api/auth/users/update", { username, fullname });
          }
          await postJSON("/api/auth/password", { current, new: password });
          els.usersMsg.textContent = "Your password has been updated.";
        } else if (editing) {
          const body = { username, fullname };
          if (password) body.password = password;
          if (!els.umRoleField.hidden) body.role = els.umRole.value;
          if (!els.umEnabledField.hidden) body.enabled = els.umEnabled.checked;
          await postJSON("/api/auth/users/update", body);
          els.usersMsg.textContent = `Updated ${username}.`;
        } else {
          await postJSON("/api/auth/users/add", {
            username, password, fullname,
            role: els.umRole.value,
            enabled: els.umEnabled.checked,
          });
          els.usersMsg.textContent = `Added ${username}.`;
        }
        closeUserModal();
        await loadUsers();
      } catch (err) {
        els.umMsg.textContent = err.message;
      } finally {
        els.umSave.disabled = false;
      }
    });

    els.usersTbody.addEventListener("click", async (e) => {
      const del = e.target.closest("[data-del]");
      const tog = e.target.closest("[data-toggle]");
      const edt = e.target.closest("[data-edit]");
      if (!del && !tog && !edt) return;
      try {
        if (del) {
          const username = del.dataset.del;
          if (!window.confirm(`Remove user "${username}"? Their session ends immediately.`)) return;
          await postJSON("/api/auth/users/delete", { username });
          els.usersMsg.textContent = `Removed ${username}.`;
          await loadUsers();
        } else if (tog) {
          const username = tog.dataset.toggle;
          const enabled = tog.dataset.enabled === "1";
          if (enabled) {
            const self = username === state.username;
            const msg = self
              ? `Disable user "${username}"? This is YOUR account - your session ends immediately and you must sign in as another admin.`
              : `Disable user "${username}"? Their session ends immediately.`;
            if (!window.confirm(msg)) return;
          }
          await postJSON("/api/auth/users/enabled", { username, enabled: !enabled });
          els.usersMsg.textContent = `${username} ${enabled ? "disabled" : "enabled"}.`;
          await loadUsers();
        } else if (edt) {
          const user = (state.users || []).find((u) => u.username === edt.dataset.edit);
          if (user) openUserModal(user);
        }
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
    state.canManageUsers = false;
    els.logoutBtn.hidden = true;
    els.sideUser.textContent = "";
    els.sideRole.textContent = "";
    els.loginPass.value = "";
    showLoginGate(false, "Session expired. Sign in again.");
    updateTotpCard();
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
        const payload = { username, password };
        if (!els.loginTotp.hidden) payload.totp_code = els.loginTotp.value.trim();
        const d = await postJSON("/api/auth/login", payload);
        if (d.totp_required) {
          els.loginTotpLabel.hidden = false;
          els.loginTotp.hidden = false;
          els.loginBtn.textContent = "Verify & sign in";
          setLoginError("Enter the 6-digit code from your authenticator app.");
          try { els.loginTotp.focus(); } catch (err) { }
          return;
        }
        els.loginTotpLabel.hidden = true;
        els.loginTotp.hidden = true;
        els.loginTotp.value = "";
        els.loginBtn.textContent = "Sign in";
        els.loginPass.value = "";
        state.authed = true;
        state.role = d.role || "viewer";
        state.isOwner = !!d.is_owner;
        state.canManageUsers = !!d.can_manage_users;
        state.totpEnabled = !!d.totp_enabled;
        els.logoutBtn.hidden = false;
        state.username = d.username || username;
        els.acctHint.textContent = `Signed in as ${d.username || username} (${roleLabel()})`;
        applyDefaultPasswordWarning(d.default_password);
        applyRoleUI();
        if (state.canManageUsers && state.activeView === "settings") loadUsers();
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

    els.pwOpen.addEventListener("click", () => {
      const me = (state.users || []).find((u) => u.username === state.username);
      openUserModal(me || { username: state.username, owner: state.isOwner });
    });
  }

  function totpMsg(msg) {
    els.totpMsg.hidden = !msg;
    els.totpMsg.textContent = msg || "";
  }

  function updateTotpCard() {
    if (!els.totpCard) return;
    els.totpCard.hidden = !state.authed;
    const on = !!state.totpEnabled;
    els.totpBadge.textContent = on ? "2FA enabled" : "Not enabled";
    els.totpBadge.className = "badge" + (on ? " badge-ok" : "");
    els.totpStartBtn.hidden = on;
    els.totpEnroll.hidden = true;
    els.totpDisableRow.hidden = !on;
    els.totpCode.value = "";
    els.totpDisablePass.value = "";
    els.totpDisableCode.value = "";
    totpMsg("");
  }

  function renderTotpQr(uri) {
    const qr = (typeof qrcode !== "undefined") && qrcode(0, "M");
    if (!qr) return;
    qr.addData(uri);
    qr.make();
    els.totpQr.width = 240;
    els.totpQr.height = 240;
    const ctx = els.totpQr.getContext("2d");
    const img = qr.createDataURL(8, 4);
    const im = new Image();
    im.onload = () => {
      ctx.clearRect(0, 0, 240, 240);
      ctx.fillStyle = "#fff";
      ctx.fillRect(0, 0, 240, 240);
      ctx.drawImage(im, 0, 0, 240, 240);
    };
    im.src = img;
  }

  function bindTotpActions() {
    els.totpStartBtn.addEventListener("click", async () => {
      totpMsg("");
      els.totpStartBtn.disabled = true;
      try {
        const d = await postJSON("/api/auth/totp/setup", {});
        els.totpSecret.textContent = d.secret;
        renderTotpQr(d.uri);
        els.totpEnroll.hidden = false;
        try { els.totpCode.focus(); } catch (err) { }
      } catch (err) {
        totpMsg(err.message);
      } finally {
        els.totpStartBtn.disabled = false;
      }
    });

    els.totpCancelBtn.addEventListener("click", () => {
      els.totpEnroll.hidden = true;
      els.totpCode.value = "";
      totpMsg("");
    });

    els.totpConfirmBtn.addEventListener("click", async () => {
      const code = els.totpCode.value.trim();
      if (!/^\d{6}$/.test(code)) { totpMsg("Enter the 6-digit code from your app."); return; }
      els.totpConfirmBtn.disabled = true;
      totpMsg("");
      try {
        await postJSON("/api/auth/totp/confirm", { code });
        state.totpEnabled = true;
        updateTotpCard();
        if (state.canManageUsers) loadUsers();
      } catch (err) {
        totpMsg(err.message);
      } finally {
        els.totpConfirmBtn.disabled = false;
      }
    });

    els.totpDisableBtn.addEventListener("click", async () => {
      const current = els.totpDisablePass.value;
      const code = els.totpDisableCode.value.trim();
      if (!current) { totpMsg("Enter your current password."); return; }
      if (!/^\d{6}$/.test(code)) { totpMsg("Enter a 6-digit code."); return; }
      els.totpDisableBtn.disabled = true;
      totpMsg("");
      try {
        await postJSON("/api/auth/totp/disable", { current, code });
        state.totpEnabled = false;
        updateTotpCard();
        if (state.canManageUsers) loadUsers();
      } catch (err) {
        totpMsg(err.message);
      } finally {
        els.totpDisableBtn.disabled = false;
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
    state.canManageUsers = !!d.can_manage_users;
    state.totpEnabled = !!d.totp_enabled;
    state.routerLat = (d.router_lat != null) ? Number(d.router_lat) : null;
    state.routerLon = (d.router_lon != null) ? Number(d.router_lon) : null;
    els.logoutBtn.hidden = false;
    if (d.username) {
      state.username = d.username;
      els.acctHint.textContent = `Signed in as ${d.username} (${roleLabel()})`;
    }
    applyDefaultPasswordWarning(d.default_password);
    applyRoleUI();
    if (state.isOwner && state.activeView === "settings") loadUsers();
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
    // On a fresh login (no persisted session bootstrap) the router location is
    // not yet on state; fetch it so the attack map centers on the saved location.
    if (state.routerLat == null) {
      fetchJSON("/api/auth/session")
        .then((d) => {
          if (d.router_lat != null && d.router_lon != null) {
            state.routerLat = Number(d.router_lat);
            state.routerLon = Number(d.router_lon);
            if (els.routerLat) els.routerLat.value = state.routerLat;
            if (els.routerLon) els.routerLon.value = state.routerLon;
            applyRouterTarget();
          }
        })
        .catch(() => {});
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
