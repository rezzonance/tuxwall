#!/usr/bin/env python3
"""Dashboard structure after the 3.3.7 UI tidy-up (static: index.html + scripts).

Security > Local (device monitoring):
- the status cards (#dev-stats) use the shared stats-row / stat-card stat-c
  tiles of Tripwire and Deception, five in a fixed order and colour
  (Flagged red, Quarantined amber, New 24 h blue, Active clients green,
  Threat feeds teal), each clickable (data-dev-st, role=button, tabindex);
  the old .dev-threat-stats counters are gone everywhere;
- the device threats card, the Silenced card and the cards that used to be
  Settings > Threat (#dev-src-card with the Zeek "Ignore checksums" switch,
  #ti-card, #ti-viewer-card) live in the Local pane, in that order;
- the silence dialog (#dev-s-modal) is global (opened from Security and from
  the Clients device panel, so it must not sit inside one view).
Settings:
- no "Threat" sub-tab or pane any more; Device alerts stay in Settings > Alerts;
- old deep links (#settings/threat, data-tw-settings="threat") land on
  Security > Local (dashboard.js openSettingsPane -> openSecurityPane), and
  #security/<pane> works as a deep link.
Scripts: no "Settings → Threat" link left; button labels never end in "…"
(buttons.js shows such a button as busy); every POST URL devices.js uses is
routed by api_server.py; changed assets carry a ?v= cache-buster.
Session 2 (A4/A5/A8/B):
- DHCP Pools: a third sub-tab "Pools" on the DHCP page (after Devices,
  Static; icon key `pools`) with the pools card (#sys-pools, Add pool, raw
  Kea edit) in its pane; gone from System (no data-sys-pane="dhcp");
  setDhcpTab refreshes the pools; #clients/<pane> and the old #system/dhcp
  deep links land on it;
- CrowdSec > Community Bans: no community switches (no data-community-
  settings mount, no switch explanation) but the ban list, a state line and
  a link to Security > Deception > Community; the Deception card no longer
  says "the same switches as CrowdSec";
- Suricata suppression: "Suppress rule" on Sensors alert rows and on IDS
  findings in the device panel, the global #sur-s-modal, the Suppressed
  rules card (#sur-sup-card) on the Sensors pane, the API route;
- "What to do": guidance rows in the device panel and the Security > Local
  table (shared chevron button + detail row the row cap keeps with its row).

    python3 tools/ui_structure_check.py
"""
import os
import re
import sys
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "www", "index.html")
DASH = os.path.join(ROOT, "www", "scripts", "dashboard.js")
DEVJS = os.path.join(ROOT, "www", "scripts", "devices.js")
API = os.path.join(ROOT, "www", "includes", "api_server.py")
CSS_DIR = os.path.join(ROOT, "www", "css")

PASS = FAIL = 0
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


class Node:
    __slots__ = ("tag", "attrs", "parent", "children", "order")

    def __init__(self, tag, attrs, parent, order):
        self.tag, self.attrs, self.parent, self.children, self.order = tag, attrs, parent, [], order

    def cls(self):
        return (self.attrs.get("class") or "").split()

    def ancestors(self):
        n = self.parent
        while n is not None:
            yield n
            n = n.parent

    def walk(self):
        for c in self.children:
            yield c
            yield from c.walk()


class Tree(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", {}, None, 0)
        self.cur = self.root
        self.n = 0
        self.ids = {}
        self.dup = []

    def handle_starttag(self, tag, attrs):
        self.n += 1
        node = Node(tag, {k: (v or "") for k, v in attrs}, self.cur, self.n)
        self.cur.children.append(node)
        i = node.attrs.get("id")
        if i:
            if i in self.ids:
                self.dup.append(i)
            self.ids[i] = node
        if tag not in VOID:
            self.cur = node

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.cur = self.cur.parent

    def handle_endtag(self, tag):
        n = self.cur
        while n is not None and n.tag != tag:
            n = n.parent
        if n is not None and n.parent is not None:
            self.cur = n.parent


def main():
    html = read(INDEX)
    t = Tree()
    t.feed(html)
    ids = t.ids
    check(not t.dup, "index.html: duplicate ids %r" % t.dup[:10])
    local = [n for n in t.root.walk() if n.attrs.get("data-sec-pane") == "local" and "fw-pane" in n.cls()]
    check(len(local) == 1, "one Security > Local pane")
    local = local[0] if local else Node("x", {}, None, 0)
    inside = lambda i: i in ids and local in ids[i].ancestors()  # noqa: E731

    # status cards
    stats = ids.get("dev-stats")
    check(stats is not None and inside("dev-stats") and {"stats-row", "dev-stats"} <= set(stats.cls()),
          "#dev-stats: a stats-row inside the Local pane")
    cards = [c for c in (stats.children if stats else []) if "stat-card" in c.cls()]
    want = [("dev-st-flagged-card", "stat-c-red", "flagged", "Flagged"),
            ("dev-st-quar-card", "stat-c-amber", "quarantined", "Quarantined"),
            ("dev-st-new-card", "stat-c-blue", "new", "New (24 h)"),
            ("dev-st-active-card", "stat-c-green", "active", "Active clients"),
            ("dev-st-feeds-card", "stat-c-teal", "feeds", "Threat feeds")]
    check([c.attrs.get("id") for c in cards] == [w[0] for w in want],
          "Local status cards in order: %r" % [c.attrs.get("id") for c in cards])
    for c, (cid, colour, key, label) in zip(cards, want):
        check({"stat-card", "stat-c", colour} <= set(c.cls()), "%s: shared tile classes + %s" % (cid, colour))
        check(c.attrs.get("data-dev-st") == key and c.attrs.get("role") == "button" and c.attrs.get("tabindex") == "0",
              "%s: clickable (data-dev-st=%s, role=button, tabindex=0)" % (cid, key))
        base = cid[:-len("-card")]
        sub = [n for n in c.walk() if n.attrs.get("id") in (base, base + "-sub")]
        check(len(sub) == 2, "%s: value + sub-text (#%s, #%s-sub)" % (cid, base, base))
        m = re.search(r'id="%s".*?<div class="stat-label">([^<]+)<' % re.escape(cid), html, re.S)
        check(bool(m) and m.group(1).strip() == label, "%s label %r" % (cid, label))
    for name, src in [("index.html", html), ("devices.js", read(DEVJS)), ("dashboard.js", read(DASH))] + \
            [(n, read(os.path.join(CSS_DIR, n))) for n in sorted(os.listdir(CSS_DIR)) if n.endswith(".css")]:
        check("dev-threat-stat" not in src, "%s: the old .dev-threat-stats counters are gone" % name)

    # cards of the Local pane and their order
    order = ["dev-stats", "dev-threat-card", "dev-threat-table", "dev-silence-card", "dev-tune-card", "dev-src-card",
             "ti-card", "ti-viewer-card"]
    for i in order:
        check(inside(i), "#%s is inside Security > Local" % i)
    seq = [ids[i].order for i in order if i in ids]
    check(seq == sorted(seq) and len(seq) == len(order), "Local pane order: %s" % " < ".join(order))
    check(inside("dev-zeek-ck") and ids["dev-src-card"] in ids["dev-zeek-ck"].ancestors(),
          "Zeek checksum switch inside the Monitoring sources card")
    zin = ids.get("dev-zeek-ck-in")
    check(zin is not None and zin.attrs.get("type") == "checkbox" and "fw-switch" in zin.parent.cls(),
          "Zeek switch: shared fw-switch checkbox")
    check(ids.get("dev-thr-silenced") is not None and ids["dev-threat-card"] in ids["dev-thr-silenced"].ancestors(),
          "Show silenced toggle on the device threats card")
    sm = ids.get("dev-s-modal")
    check(sm is not None and "modal" in sm.cls() and not any("view" in a.cls() for a in sm.ancestors()),
          "#dev-s-modal: a global modal (outside every .view)")

    # Settings: no Threat tab/pane; Device alerts stay in Alerts
    check(not [n for n in t.root.walk() if n.attrs.get("data-settings-pane") == "threat"],
          "Settings: no Threat sub-tab or pane")
    alerts = [n for n in t.root.walk() if n.attrs.get("data-settings-pane") == "alerts" and "fw-pane" in n.cls()]
    check(bool(alerts) and "dev-alerts-card" in ids and alerts[0] in ids["dev-alerts-card"].ancestors(),
          "Device alerts stay in Settings > Alerts")
    check('href="#settings/threat"' not in html and 'data-tw-settings="threat"' not in html,
          "index.html: no link to Settings > Threat")

    # redirects + deep links (dashboard.js)
    dash = read(DASH)
    m = re.search(r"function openSettingsPane\(pane\) \{(.*?)\n  \}", dash, re.S)
    check(bool(m) and re.search(r'pane === "threat"\)\s*\{\s*openSecurityPane\("local", "dev-src-card"\);\s*return;', m.group(1)),
          "dashboard.js: openSettingsPane('threat') -> Security > Local (Monitoring sources)")
    check("window.twSecurity = { open: openSecurityPane }" in dash and "function openSecurityPane(pane, cardId)" in dash,
          "dashboard.js: window.twSecurity.open(pane, card)")
    check(re.search(r"/\^security\\/\(\[a-z\]\+\)\$/\.exec\(initial\)", dash) and "openSecurityPane(securityPane[1])" in dash,
          "dashboard.js: #security/<pane> deep link")
    check("showNewest()" in dash and 'key === "first_seen"' in dash, "dashboard.js: Clients newest-first for the New card")

    # devices.js
    dev = read(DEVJS)
    check('settingsLink("threat"' not in dev and 'data-tw-settings="threat"' not in dev and "Settings → Threat" not in dev,
          "devices.js: no Settings → Threat link left")
    check("data-tw-local" in dev and "window.twSecurity.open(" in dev, "devices.js: links to Security > Local cards")
    for lab in re.findall(r"<button[^>]*>([^<${}]*)</button>", dev) + re.findall(r"<button[^>]*>([^<${}]*)</button>", html):
        check(not lab.strip().endswith("…"), "button label %r ends in … (buttons.js shows it as busy)" % lab.strip())
    api = read(API)
    for url in sorted(set(re.findall(r'post\(\s*"(/api/devices/[a-z/-]+)"', dev))):
        check('"%s"' % url in api, "devices.js POST %s is routed by api_server.py" % url)
    check('"/api/devices/silence"' in api and '"/api/devices/zeek-checksums"' in api, "API routes for silence + Zeek switch")

    # A4: DHCP Pools on the DHCP page
    strip = ids.get("dhcp-subtabs")
    tabs = [c.attrs.get("data-dhcp-pane") for c in (strip.children if strip else []) if "fw-subtab" in c.cls()]
    check(tabs == ["dynamic", "static", "pools"], "DHCP sub-tabs: Devices, Static, Pools (%r)" % tabs)
    ptab = [c for c in (strip.children if strip else []) if c.attrs.get("data-dhcp-pane") == "pools"]
    check(bool(re.search(r'data-dhcp-pane="pools">Pools</button>', html)), "DHCP: the tab reads 'Pools'")
    pane = [n for n in t.root.walk() if n.attrs.get("data-dhcp-pane") == "pools" and "fw-pane" in n.cls()]
    clients = ids.get("view-clients")
    check(len(pane) == 1 and clients in pane[0].ancestors() and "hidden" in pane[0].attrs, "Pools pane inside #view-clients, hidden by default")
    for i in ("sys-pools", "sys-pools-note", "sys-pool-add", "sys-edit-kea"):
        check(i in ids and pane and pane[0] in ids[i].ancestors(), "#%s lives in the DHCP Pools pane" % i)
    check(not [n for n in t.root.walk() if n.attrs.get("data-sys-pane") == "dhcp"]
          and "DHCP Pools</button>" not in html, "System: the DHCP Pools sub-tab and pane are gone")
    system = ids.get("view-system")
    check(system is not None and not any(system in ids[i].ancestors() for i in ("sys-pools", "sys-pool-add") if i in ids),
          "System: no pools elements left")
    cfg = ids.get("cfg-modal")
    check(cfg is not None and not any("view" in a.cls() for a in cfg.ancestors()) and "dhcp-f-iface" in ids,
          "the pool form (#cfg-modal) stays global, so it opens from the DHCP page")
    m = re.search(r"const SUBTAB_ICONS = \{(.*?)\n  \};", dash, re.S)
    check(bool(m) and re.search(r"\n    pools: '", m.group(1)) and not re.search(r"\n    dhcp: '", m.group(1)),
          "SUBTAB_ICONS: icon key 'pools' (no stale 'dhcp')")
    m = re.search(r"function setDhcpTab\(pane\) \{(.*?)\n  \}", dash, re.S)
    check(bool(m) and 'if (pane === "pools") refreshPools();' in m.group(1), "setDhcpTab refreshes the pools when opened")
    check("function openClientsPane(pane)" in dash and 'initial === "system/dhcp" ? [initial, "pools"]' in dash
          and "openClientsPane(clientsPane[1])" in dash and "/^clients\\/([a-z]+)$/.exec(initial)" in dash,
          "deep links: #clients/<pane>, #system/dhcp -> DHCP > Pools")
    enh = read(os.path.join(ROOT, "www", "scripts", "enhance.js"))
    check('"system/dhcp": "clients/pools"' in enh and "s = MOVED[s] || s;" in enh,
          "enhance.js: #system/dhcp (load and in-page hash change) -> #clients/pools")
    m = re.search(r"async function refreshSystem\(\) \{(.*?)\n  \}", dash, re.S)
    check(bool(m) and "refreshPools" not in m.group(1), "refreshSystem no longer loads the pools")
    check(len(ptab) == 1, "one Pools tab")

    # A5: CrowdSec > Community Bans without the switches
    cpane = [n for n in t.root.walk() if n.attrs.get("data-cs-pane") == "community" and "fw-pane" in n.cls()]
    check(len(cpane) == 1, "one CrowdSec Community Bans pane")
    cp = cpane[0] if cpane else Node("x", {}, None, 0)
    check(not [n for n in cp.walk() if "data-community-settings" in n.attrs], "Community Bans: no community switches mounted")
    cps = html[html.find('data-cs-pane="community" hidden'):html.find('<section id="view-bandwidth"')]
    check("Use community bans</b> &mdash;" not in cps and "Report catches to the community</b> &mdash;" not in cps
          and "The same two switches" not in cps, "Community Bans: the switch explanation is gone")
    for i in ("cban-table", "cban-body", "cban-ban-all", "cban-generated", "cban-settings-line", "cban-settings-state"):
        check(i in ids and cp in ids[i].ancestors(), "Community Bans keeps #%s" % i)
    link = [n for n in cp.walk() if "data-tw-community-settings" in n.attrs]
    check(len(link) == 1 and link[0].tag == "a" and link[0].attrs.get("href") == "#security/deception"
          and "Security &rsaquo; Deception &rsaquo; Community" in cps, "Community Bans: link to Security > Deception > Community")
    check('openSecurityPane("deception", "dec-community-card")' in dash and "renderCbanSettingsLine" in dash,
          "dashboard.js: the link opens the Deception Community card; the state line is rendered")
    dec = [n for n in t.root.walk() if n.attrs.get("data-community-settings") == "dec-cs"]
    check(len(dec) == 1 and ids.get("dec-community-card") in dec[0].ancestors(), "Deception keeps the shared switches")
    check("the same switches as CrowdSec" not in html and "(or on CrowdSec &rsaquo; Community Bans)" not in html,
          "Deception texts no longer point at switches on CrowdSec")

    # A8: Suricata rule suppression
    supjs = read(os.path.join(ROOT, "www", "scripts", "suricata-suppress.js"))
    smod = ids.get("sur-s-modal")
    check(smod is not None and "modal" in smod.cls() and not any("view" in a.cls() for a in smod.ancestors()),
          "#sur-s-modal: a global modal")
    sens = [n for n in t.root.walk() if n.attrs.get("data-sec-pane") == "sensors" and "fw-pane" in n.cls()]
    check(len(sens) == 1 and "sur-sup-card" in ids and sens[0] in ids["sur-sup-card"].ancestors()
          and ids["sur-sup-card"].order > ids["sec-suricata-table"].order and "hidden" in ids["sur-sup-card"].attrs,
          "Suppressed rules card on the Sensors pane, after the alerts table, hidden until the role is known")
    check(re.search(r'<thead><tr><th>Time</th><th>Signature</th><th>Severity</th><th>Source</th><th>Destination</th><th></th></tr></thead>', html),
          "Sensors table: an action column")
    check("data-sur-suppress" in dash and "window.twSuricataSuppress.open(" in dash and "Suppress rule</button>" in dash,
          "Sensors rows: Suppress rule button")
    check("data-dev-suppress" in dev and "window.twSuricataSuppress.open(" in dev and 'x.kind === "ids_alert"' in dev,
          "device panel: Suppress rule on IDS findings")
    check('/api/security/suricata/suppress' in supjs and '"/api/security/suricata/suppress"' in api
          and '"/api/security/suricata/suppress",' in api, "API route (GET admin prefix + POST) for suppression")
    check("Addresses change" in supjs and "not an INFO or POLICY rule" in supjs and 'opt("network", true' in supjs,
          "suppress dialog: network-wide default, address warning, non-INFO warning")
    check("Hits / 24 h before" in supjs and "Unsuppress" in supjs and "data-sur-unsup" in supjs,
          "Suppressed rules list: hits before + Unsuppress")
    for lab in re.findall(r"<button[^>]*>([^<${}]*)</button>", supjs) + re.findall(r"<button[^>]*>([^<${}]*)</button>", dash):
        check(not lab.strip().endswith("…"), "button label %r ends in …" % lab.strip())

    # B: "What to do"
    check("data-dev-guide" in dev and "dev-guide-row tw-detail-row" in dev and "guideRow(gid, x.guidance, 6)" in dev
          and "guideRow(gid, x.guidance, 5)" in dev, "devices.js: guidance rows in the Local table (6 cols) and panel (5 cols)")
    check('!r.classList.contains("tw-detail-row")' in dash and "function capRow(r, on)" in dash,
          "row cap: detail rows follow their parent row, never counted")

    # Phase 2 (3.3.8): Detector tuning card (behaviour detectors, shadow mode)
    tune = ids.get("dev-tune-card")
    check(tune is not None and "card" in tune.cls() and "hidden" in tune.attrs,
          "#dev-tune-card: a card, hidden until an admin role is known")
    for i in ("dev-tune-badge", "dev-tune-set", "dev-tune-msg", "dev-tune-rows", "dev-tune-table", "dev-tune-empty"):
        check(i in ids and tune in ids[i].ancestors(), "#%s inside the Detector tuning card" % i)
    check(ids.get("dev-tune-set") is not None and "cs-set" in ids["dev-tune-set"].cls()
          and "dev-table" in (ids.get("dev-tune-table") or Node("x", {}, None, 0)).cls(),
          "Detector tuning: shared cs-set rows + dev-table")
    check(re.search(r'<thead><tr><th>Severity</th><th>Detector</th><th>Would report</th><th>Client</th><th>Seen</th><th></th></tr></thead>', html),
          "Detector tuning table columns")
    check("Shadow</b> mode" in html and "no push or Home Assistant alert" in html, "Detector tuning: shadow mode explained")
    check('class="seg-btns" role="group"' in dev and "data-dev-tune-mode" in dev and 'getJSON("/api/devices/detectors")' in dev
          and 'post("/api/devices/detectors"' in dev, "devices.js: modes as shared seg-btns, GET/POST /api/devices/detectors")
    check("data-dev-tune-exp" in dev and "data-dev-tune-silence" in dev and "guideRow(gid, r.guidance, 6)" in dev
          and "openSilence(tuneRows[" in dev, "devices.js: tuning rows with What to do, Silence, Mark expected / Unmark")
    check('const tc = $("dev-tune-card");' in dev and "if (tc) tc.hidden = !isAdmin;" in dev,
          "devices.js: the tuning card is admin-only")
    check('"dev-tune-table",' in dash, "row cap: the tuning table gets the shared Show all bar")
    check('"/api/devices/detectors"' in api and '"/api/devices/detectors",' in api,
          "API: /api/devices/detectors routed (GET admin prefix + POST)")
    for k in ("beaconing", "dns_bypass", "internal_scan"):
        check(re.search(r"\b%s: \"" % k, dev), "devices.js: label for %s" % k)

    # cache-busters
    for asset in ("/scripts/devices.js", "/scripts/dashboard.js", "/css/polish.css", "/scripts/suricata-suppress.js",
                  "/scripts/community-settings.js", "/scripts/enhance.js"):
        check(re.search(re.escape(asset) + r"\?v=\d{12}\"", html), "index.html: %s has a ?v= cache-buster" % asset)

    print("ui_structure_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
