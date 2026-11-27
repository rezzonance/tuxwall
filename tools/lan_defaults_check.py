#!/usr/bin/env python3
"""LAN-agnostic defaults: nothing assumes a 192.168.1.0/24 LAN for NEW config.

The netinstaller and the VM image set up any LAN (e.g. 172.31.250.0/24), so:
- the dashboard must not pre-fill a hard-coded 192.168.1.x VALUE (WireGuard
  client DNS, local-domain IP, Pi-hole IP): values come from the router's
  real LAN address (/api/system, /api/wireguard); 192.168.1.x may only appear
  as a static placeholder fallback
- the WireGuard backend default DNS is derived (_wg_default_dns), never the
  empty WG_DEFAULT_DNS cache
- port forwarding + DMZ take the LAN/WAN interface, LAN subnet and gateway
  from /etc/tuxwall/interfaces.json first (legacy 192.168.1 detection only
  without it), so the installer's old "Port forwarding and DMZ ... still
  assume a 192.168.1.0/24 LAN" warning must not come back

    python3 tools/lan_defaults_check.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "www", "index.html")
JS_DIR = os.path.join(ROOT, "www", "scripts")
API = os.path.join(ROOT, "www", "includes", "api_server.py")
INSTALLER = os.path.join(ROOT, "tuxwall-install.sh")

PASS = FAIL = 0


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


def func(src, name):
    m = re.search(r"\ndef %s\(.*?(?=\ndef |\Z)" % re.escape(name), src, re.S)
    return m.group(0) if m else ""


# value="192.168.1.x" (HTML), .value = "192.168.1.x" / value: '192.168.1.x' (JS)
VALUE_RE = re.compile(r"""\bvalue\s*[=:]\s*["'`]\s*192\.168\.1\.\d""")


def check_dashboard():
    html = read(INDEX)
    for m in VALUE_RE.finditer(html):
        line = html.count("\n", 0, m.start()) + 1
        check(False, "www/index.html:%d pre-fills a hard-coded 192.168.1.x value" % line)
    check(VALUE_RE.search(html) is None, "index.html: no hard-coded 192.168.1.x input value")
    for name in sorted(os.listdir(JS_DIR)):
        if not name.endswith(".js"):
            continue
        src = read(os.path.join(JS_DIR, name))
        bad = [src.count("\n", 0, m.start()) + 1 for m in VALUE_RE.finditer(src)]
        check(not bad, "www/scripts/%s: no hard-coded 192.168.1.x value (lines %s)" % (name, bad))

    def tag(id_):
        m = re.search(r'<(?:input|textarea)\b[^>]*\bid="%s"[^>]*>' % re.escape(id_), html)
        return m.group(0) if m else ""

    wg = tag("wg-setup-dns")
    check(wg and 'value=""' in wg, "WireGuard setup DNS starts empty (filled from /api/wireguard interface.dns)")
    check('data-lan-value="{lan3}.' in tag("dm-ip"), "local-domain IP pre-fill follows the router's LAN")
    for id_ in ("res-ip", "dns-up-pihole", "rpz-target", "fw-from", "dhcp-f-subnet", "dhcp-f-start",
                "dhcp-f-end", "dhcp-f-router", "dhcp-f-dns"):
        check("data-lan-placeholder=" in tag(id_), "%s: placeholder follows the router's LAN" % id_)
    js = read(os.path.join(JS_DIR, "dashboard.js"))
    check(re.search(r"function renderSystem\(d\) \{.*?applyLanHints\(d\);", js, re.S) is not None,
          "dashboard.js: /api/system (dhcp.router + interfaces) feeds the LAN hints")
    check(re.search(r"if \(!d\.configured\) \{[^}]*d\.interface && d\.interface\.dns", js, re.S) is not None,
          "dashboard.js: the WireGuard setup form takes its DNS from /api/wireguard interface.dns")
    for k in ("{lan_ip}", "{lan_cidr}", "{lan3}"):
        check(k.strip("{}") in js and "\\%s\\}" % k[:-1] in js, "dashboard.js: lanHintText handles %s" % k)


def check_backend():
    src = read(API)
    check(re.search(r"\bor WG_DEFAULT_DNS\b", src) is None, "api_server: WireGuard DNS default is _wg_default_dns(), "
          "not the empty WG_DEFAULT_DNS cache")
    check(src.count("or _wg_default_dns()") >= 4, "api_server: setup, client configs and status use _wg_default_dns()")
    wgd = func(src, "_wg_default_dns")
    check('_topo("lan_address")' in wgd, "_wg_default_dns: the interfaces.json LAN address first")
    for name, need in (("_lan_iface", '_topo("lan_device")'), ("_lan_subnet", '_topo("lan_address")'),
                       ("_gateway_ip", '_topo("lan_address")'), ("_wan_iface", '_topo("wan_device")')):
        body = func(src, name)
        check(need in body and body.index(need) < body.find("subprocess.run("),
              "%s: interfaces.json first, legacy 192.168.1 detection only as a fallback" % name)
    for name in ("_apply_pf_rule", "_remove_pf_rule"):
        body = func(src, name)
        check("_wan_iface()" in body and "_lan_iface()" in body and "192.168" not in body,
              "%s: WAN/LAN interfaces from the topology, no LAN literal" % name)
    for name in ("_apply_dmz_isolation", "_remove_dmz_isolation"):
        body = func(src, name)
        check(all(f in body for f in ("_lan_subnet()", "_gateway_ip()", "_lan_iface()", "_wan_iface()"))
              and "192.168" not in body, "%s: subnet/gateway/interfaces from the topology" % name)
    for name in ("build_portforward", "add_portforward", "build_dmz", "enable_dmz", "disable_dmz"):
        check("192.168" not in func(src, name), "%s: no LAN literal" % name)


def check_installer():
    inst = read(INSTALLER)
    check("still assume a 192.168.1.0/24" not in inst and not re.search(r"Port forwarding and DMZ[^\n]*192\.168", inst),
          "tuxwall-install.sh: no stale 'port forwarding/DMZ assume 192.168.1.0/24' warning")


def main():
    check_dashboard()
    check_backend()
    check_installer()
    print("lan_defaults_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
