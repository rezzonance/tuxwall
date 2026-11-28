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
    order = ["dev-stats", "dev-threat-card", "dev-threat-table", "dev-silence-card", "dev-src-card", "ti-card",
             "ti-viewer-card"]
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

    # cache-busters
    for asset in ("/scripts/devices.js", "/scripts/dashboard.js", "/css/polish.css"):
        check(re.search(re.escape(asset) + r"\?v=\d{12}\"", html), "index.html: %s has a ?v= cache-buster" % asset)

    print("ui_structure_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
