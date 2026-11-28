#!/usr/bin/env python3
"""Dashboard HTTPS (www/includes/https_tls.py, tuxwall-tls, postinst), sandboxed:

  python3 tools/https_check.py

- certificates (real openssl, scratch dirs): CA + server certificate from
  interface fixtures (documentation/private addresses): SANs = LAN/VPN/VLAN
  IPv4 + ULA, host name, .local, domain, unbound names pointing at the
  router; never the WAN, global IPv6 or link-local; keys 0600, certificates
  0644, directory 0755; server validity <= 398 days, CA ~10 years; two
  routers get different CAs (name + key); the CA is name-constrained (a leaf
  for another site signed by it does not verify; a public LAN address is
  left out and reported); idempotent; re-issued on SAN change, near expiry,
  CA change, --force-cert; --new-ca replaces the CA.
- nginx snippet render: 443 listeners (default_server) on exactly the listen
  include's addresses, TLS settings, CA download location, redirect with
  /.well-known/ + CA path exceptions, escape hatch (marker / setting), HSTS
  on / max-age=0 after off, http2 syntax by nginx version, comment-only when
  inactive.
- ownership decision matrix (owner-managed / active / disabled): local copy
  of sites-enabled/tuxwall, symlink elsewhere, edited package site, missing
  site, other servers on 443 (address, wildcard, [::], conf.d), unrelated
  443/8443 listeners, markers; refresh in owner-managed mode writes
  certificates only - no snippet, no nginx -t, no reload.
- refresh transaction: nginx -t failure puts the previous snippet AND
  certificate back; settings rollback on a failed apply; custom certificate
  validation (path rules, key mismatch, expired).
- real nginx (skipped when not installed): `nginx -t` in a scratch prefix
  accepts the package site + active snippet (redirect, escape hatch, HSTS,
  custom cert), rejects an active snippet next to another default_server on
  the same address:port (what the detection prevents) and accepts the
  owner-managed render next to a replica of a hand-made HTTPS setup.
- postinst https_setup / https_fw_allow (bash, fake helper + fake ufw): 443
  opened on LAN/VPN interfaces only and only when HTTPS goes active, an
  existing 443 rule is kept, owner-managed prints the note and touches no
  firewall, failures are warnings; package wiring (site include, timer,
  conffiles, Depends: openssl).
- fw_guard: with the redirect on, the admin's session needs 443.
- security headers: no location in the package site / nginx templates /
  rendered snippet drops the server-level add_header set (nginx
  inheritance); a real nginx on loopback serves them on /, /index.html,
  static files, 404 and the CA download over http + https (HSTS https
  only); the 3.3.5 `add_header Cache-Control` location fails both.
- upgrade notice: postinst https_announce (marker only when an upgrade
  turned TuxWall HTTPS on), announce_info / dismiss_announce, API route
  and dashboard banner wiring.
"""
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(ROOT, "www", "includes"))
import https_tls as H  # noqa: E402
import fw_guard as G   # noqa: E402

LISTEN = os.path.join(ROOT, "pkg", "usr", "local", "sbin", "tuxwall-nginx-listen")
SITE = os.path.join(ROOT, "pkg", "etc", "nginx", "sites-available", "tuxwall")
LIMITS = os.path.join(ROOT, "pkg", "etc", "nginx", "conf.d", "tuxwall-limits.conf")
POSTINST = os.path.join(ROOT, "pkg", "DEBIAN", "postinst")
OPENSSL = shutil.which("openssl")
NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if os.path.exists("/usr/sbin/nginx") else None)

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def link(name, *addrs):
    info = []
    for a in addrs:
        local, _, plen = a.partition("/")
        info.append({"family": "inet6" if ":" in local else "inet", "local": local,
                     "prefixlen": int(plen or 24), "scope": "link" if local.startswith("fe80") else "global"})
    return {"ifname": name, "addr_info": info}


IP = [
    link("lo", "127.0.0.1/8", "::1/128"),
    link("enp1s0", "203.0.113.9/24", "2001:db8:ffff::9/128", "fe80::1/64"),
    link("enp2s0", "192.168.1.1/24", "2001:db8:1:2::1/64", "fd00:1::1/64", "fe80::2/64"),
    link("enp2s0.10", "192.168.10.1/24", "fe80::3/64"),
    link("wg0", "10.0.0.1/24", "fd00:2::1/64"),
]
ROLES = {"version": 1, "wan": {"device": "enp1s0"},
         "lan": {"device": "enp2s0", "address": "192.168.1.1/24"},
         "opt": [{"id": "opt1", "device": "enp2s0.10", "address": "192.168.10.1/24"}],
         "vpn": [{"id": "wg0", "device": "wg0", "address": "10.0.0.1/24"}]}
LISTEN_ADDRS = ["192.168.1.1", "10.0.0.1", "fd00:1::1"]


class Box:
    """A scratch router: /etc-like tree + Env pointing into it."""

    def __init__(self, ip=None, roles=None, site="package", nginx_test=None, hostname="gw", domain="example.com"):
        self.d = tempfile.mkdtemp(prefix="https-check-")
        d = self.d
        self.calls = os.path.join(d, "calls")
        fake = os.path.join(d, "bin")
        os.makedirs(fake)
        for name in ("nginxt", "reload", "active", "timer", "restart"):
            write(os.path.join(fake, name), '#!/bin/sh\necho "%s $*" >> "%s"\nexit ${RC_%s:-0}\n'
                  % (name, self.calls, name.upper()), 0o755)
        self.ss_out = os.path.join(d, "ss-out")
        write(os.path.join(fake, "ss"), '#!/bin/sh\necho "ss $*" >> "%s"\ncat "%s" 2>/dev/null\nexit 0\n'
              % (self.calls, self.ss_out), 0o755)
        self.fake = fake
        self.ufw_added = os.path.join(d, "ufw-added")
        write(os.path.join(fake, "ufw"), '#!/bin/sh\necho "ufw $*" >> "%s"\n'
              '[ "$1" = show ] && cat "%s" 2>/dev/null\nexit 0\n' % (self.calls, self.ufw_added), 0o755)
        write(d + "/etc/tuxwall/interfaces.json", json.dumps(roles if roles is not None else ROLES))
        write(d + "/etc/nginx/sites-available/tuxwall", open(SITE).read())
        os.makedirs(d + "/etc/nginx/sites-enabled")
        os.makedirs(d + "/etc/nginx/conf.d")
        os.makedirs(d + "/etc/unbound/unbound.conf.d")
        if site == "package":
            os.symlink(d + "/etc/nginx/sites-available/tuxwall", d + "/etc/nginx/sites-enabled/tuxwall")
        self.env = H.Env(
            tls_dir=d + "/etc/tuxwall/tls", settings=d + "/etc/tuxwall/https.json",
            no_redirect=d + "/etc/tuxwall/no-https-redirect", no_https=d + "/etc/tuxwall/no-https",
            interfaces_json=d + "/etc/tuxwall/interfaces.json", kea_conf=d + "/etc/kea/kea-dhcp4.conf",
            unbound_dir=d + "/etc/unbound/unbound.conf.d",
            snippet=d + "/etc/nginx/snippets/tuxwall-tls.conf", sites_enabled=d + "/etc/nginx/sites-enabled",
            site_available=d + "/etc/nginx/sites-available/tuxwall", conf_d=d + "/etc/nginx/conf.d",
            listen_script=LISTEN, wrapper=d + "/usr/local/sbin/tuxwall-tls", state=d + "/var/lib/tls-state.json",
            log=d + "/var/log/tls.log", openssl=OPENSSL or "openssl",
            nginx_test=nginx_test or [fake + "/nginxt"], nginx_version="1.28.0",
            reload_cmd=[fake + "/reload"], active_cmd=[fake + "/active"], timer_cmd=[fake + "/timer"],
            restart_cmd=[fake + "/restart"],
            ufw=[fake + "/ufw"], ss_cmd=None,
            ip_json=ip if ip is not None else IP, hostname=hostname, domain=domain, reload_settle=0, listen_render=False)

    def called(self):
        try:
            return open(self.calls).read().splitlines() if os.path.exists(self.calls) else []
        finally:
            try:
                os.unlink(self.calls)
            except OSError:
                pass

    def site(self, name, text):
        write(os.path.join(self.env.sites_enabled, name), text)

    def close(self):
        shutil.rmtree(self.d, ignore_errors=True)


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def x509(path, *args):
    return subprocess.run([OPENSSL, "x509", "-in", path, "-noout"] + list(args), capture_output=True,
                          text=True).stdout


def validity_days(path):
    out = x509(path, "-startdate", "-enddate")
    nb = H._parse_date(re.search(r"notBefore=(.*)", out).group(1))
    na = H._parse_date(re.search(r"notAfter=(.*)", out).group(1))
    return (na - nb) / 86400


# ── certificates ─────────────────────────────────────────────────────────────

def t_certs():
    if not OPENSSL:
        print("SKIP: openssl not installed - certificate cases")
        return
    b = Box()
    try:
        write(b.env.unbound_dir + "/97-tuxwall-gateway.conf",
              'server:\n    local-data: "gateway.home.arpa. IN A 192.168.1.1"\n'
              '    local-data: "gateway.home.arpa. IN AAAA fd00:1::1"\n'
              '    local-data: "nas.home.arpa. IN A 192.168.1.20"\n')
        r = H.refresh(b.env, reload=True)
        check(r["ok"] and r["mode"] == "active", "fresh box: refresh ok, mode active (%s)" % r.get("message"))
        ufw = [c for c in b.called() if c.startswith("ufw allow")]
        check(ufw == ["ufw allow in on enp2s0 to any port 443 proto tcp comment TuxWall dashboard HTTPS (LAN)",
                      "ufw allow in on wg0 to any port 443 proto tcp comment TuxWall dashboard HTTPS (VPN)"],
              "going active: 443 opened on the LAN + VPN interfaces only, before the redirect (%s)" % ufw)
        check(r["ca_created"] and r["cert_issued"], "fresh box: CA created + certificate issued")
        tls = b.env.tls_dir
        check(mode(tls) == 0o755, "tls dir 0755 (CA readable for the nginx download location)")
        check(mode(tls + "/ca.key") == 0o600 and mode(tls + "/server.key") == 0o600, "private keys 0600")
        check(mode(tls + "/ca.crt") == 0o644 and mode(tls + "/server.crt") == 0o644, "certificates 0644")
        check(not [f for f in os.listdir(tls) if f.startswith(".work-") or f.endswith(".prev")],
              "no work dirs or .prev backups left behind")
        info = H.cert_info(b.env, tls + "/server.crt")
        want_ip = {"192.168.1.1", "10.0.0.1", "fd00:1::1", "fd00:2::1", "192.168.10.1"}
        check(set(info["ip"]) == want_ip, "SAN IPs = LAN/VPN/VLAN v4 + ULA: %s" % sorted(info["ip"]))
        check(not {"203.0.113.9", "2001:db8:1:2::1", "2001:db8:ffff::9", "127.0.0.1"} & set(info["ip"]),
              "no WAN, global IPv6 or loopback in the SANs")
        check(set(info["dns"]) == {"gw", "gw.local", "gw.example.com", "gateway.home.arpa"},
              "SAN names: host, host.local, host.domain, unbound name for the router (not the NAS): %s"
              % info["dns"])
        check(validity_days(tls + "/server.crt") <= 398, "server certificate <= 398 days (%.1f)"
              % validity_days(tls + "/server.crt"))
        check(3640 <= validity_days(tls + "/ca.crt") <= 3660, "CA ~10 years")
        ca = H.cert_info(b.env, tls + "/ca.crt")
        check(ca["constrained"] and ca["self_issued"], "CA is self-signed and name-constrained")
        check("gw" in ca["subject"] and re.search(r"gw [0-9a-f]{6}", ca["subject"]),
              "CA name carries the host name + a random suffix (%s)" % ca["subject"])
        txt = x509(tls + "/server.crt", "-text")
        check("CA:FALSE" in txt and "TLS Web Server Authentication" in txt and "prime256v1" in txt,
              "leaf: CA:FALSE, serverAuth, EC P-256")
        rc = subprocess.run([OPENSSL, "verify", "-CAfile", tls + "/ca.crt", tls + "/server.crt"],
                            capture_output=True).returncode
        check(rc == 0, "leaf verifies against the CA")
        # a rogue leaf for another site signed by the same CA must not verify
        work = tempfile.mkdtemp(dir=b.d)
        cfg = os.path.join(work, "r.cnf")
        write(cfg, "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=bank\n[v]\nsubjectAltName=DNS:bank.example.org,"
                   "IP:198.51.100.7\nextendedKeyUsage=serverAuth\n")
        subprocess.run([OPENSSL, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", work + "/r.key", "-config", cfg, "-out", work + "/r.csr"], capture_output=True)
        subprocess.run([OPENSSL, "x509", "-req", "-in", work + "/r.csr", "-CA", tls + "/ca.crt", "-CAkey",
                        tls + "/ca.key", "-set_serial", "7", "-days", "30", "-extfile", cfg, "-extensions", "v",
                        "-out", work + "/r.crt"], capture_output=True)
        v = subprocess.run([OPENSSL, "verify", "-CAfile", tls + "/ca.crt", work + "/r.crt"], capture_output=True,
                           text=True)
        check(os.path.exists(work + "/r.crt") and v.returncode != 0
              and "subtree" in (v.stdout + v.stderr).lower(),
              "name constraints: a leaf for another website signed by the CA is rejected (%s)"
              % (v.stdout + v.stderr).strip()[-80:])
        fp1 = ca["fingerprint_sha256"]
        # retire + re-activate with a 443 rule present: no new rule
        H.apply_settings(b.env, {"enabled": False})
        write(b.ufw_added, "Added user rules (see 'ufw status' for running firewall):\n"
                           "ufw allow in on enp2s0 to any port 443 proto tcp\n")
        b.called()
        H.apply_settings(b.env, {"enabled": True})
        check(not [c for c in b.called() if c.startswith("ufw allow")], "existing 443 rule: firewall left as is")
        # idempotent
        b.called()
        r2 = H.refresh(b.env, reload=True)
        check(r2["ok"] and not r2["cert_issued"] and not r2["snippet_changed"] and not r2["reloaded"],
              "second refresh: nothing re-issued, nothing reloaded")
        check(not [c for c in b.called() if c.startswith(("reload", "nginxt"))], "second refresh: no nginx -t/reload")
        # SAN change: a new VPN address -> re-issued by the same CA, reloaded
        ip2 = json.loads(json.dumps(IP))
        ip2[4]["addr_info"].append({"family": "inet", "local": "10.0.1.1", "prefixlen": 24, "scope": "global"})
        b.env.ip_json = ip2
        r3 = H.refresh(b.env, reload=True)
        calls = b.called()
        check(r3["cert_issued"] and not r3["ca_created"] and r3["why"] == "names/addresses changed",
              "new address: certificate re-issued, same CA (%s)" % r3.get("why"))
        check("10.0.1.1" in H.cert_info(b.env, tls + "/server.crt")["ip"], "new address is in the SANs")
        check(any(c.startswith("nginxt") for c in calls) and any(c.startswith("reload") for c in calls),
              "new address: nginx -t then reload")
        check("10.0.1.1" in open(b.env.snippet).read(), "new VPN address gets a 443 listener too")
        check(H.cert_info(b.env, tls + "/ca.crt")["fingerprint_sha256"] == fp1, "CA unchanged")
        # near expiry
        b.env.now = H.cert_info(b.env, tls + "/server.crt")["not_after"] - 10 * 86400
        r4 = H.refresh(b.env)
        check(r4["cert_issued"] and r4["why"].startswith("expires in"), "10 days before expiry: renewed (%s)"
              % r4.get("why"))
        b.env.now = None
        check(H.refresh(b.env, force_cert=True)["why"] == "regenerate requested", "--force-cert re-issues")
        r5 = H.refresh(b.env, new_ca=True)
        check(r5["ca_created"] and H.cert_info(b.env, tls + "/ca.crt")["fingerprint_sha256"] != fp1,
              "--new-ca: new CA, leaf re-issued by it")
        d = H.refresh(b.env, dry_run=True)
        check(d["ok"] and d["dry_run"] and not d["cert_issued"], "dry run: nothing issued")
        # two routers never share a CA
        b2 = Box()
        try:
            H.refresh(b2.env)
            c1, c2 = (H.cert_info(x.env, x.env.p("ca.crt")) for x in (b, b2))
            check(c1["fingerprint_sha256"] != c2["fingerprint_sha256"] and c1["subject"] != c2["subject"],
                  "CA uniqueness: different key and name per router")
            check(open(b.env.p("ca.key")).read() != open(b2.env.p("ca.key")).read(), "CA keys differ")
        finally:
            b2.close()
    finally:
        b.close()
    # a LAN with a public address: left out of the leaf (the CA cannot vouch for it)
    ip3 = json.loads(json.dumps(IP))
    ip3[2]["addr_info"].append({"family": "inet", "local": "198.51.100.1", "prefixlen": 29, "scope": "global"})
    roles3 = json.loads(json.dumps(ROLES))
    b = Box(ip=ip3, roles=roles3)
    try:
        r = H.refresh(b.env)
        st = H.status(b.env)
        check(r["ok"] and "198.51.100.1" not in H.cert_info(b.env, b.env.p("server.crt"))["ip"],
              "public LAN address: not in the certificate")
        check("198.51.100.1" not in st["listen"] and st["sans_current"], "public address: no listener, SANs current")
    finally:
        b.close()
    # no interfaces.json: detection (first private non-WAN interface + wg0)
    b = Box(roles={})
    os.unlink(b.env.interfaces_json)
    b.env.wan = "enp1s0"
    try:
        a = H.addresses(b.env)
        check([str(x) for x in a["listen"]] == LISTEN_ADDRS, "no roles file: detected %s" % a["listen"])
    finally:
        b.close()


# ── snippet render ───────────────────────────────────────────────────────────

def dec(**kw):
    d = {"mode": "active", "reasons": [], "listen": list(LISTEN_ADDRS), "redirect": True,
         "redirect_marker": False, "hsts": False, "site": {}}
    d.update(kw)
    return d


def t_render():
    env = H.Env(tls_dir="/etc/tuxwall/tls", nginx_version="1.28.0")
    s = H.render_snippet(env, dec(), dict(H.SETTINGS_DEFAULT))
    for a in ("192.168.1.1:443", "10.0.0.1:443", "[fd00:1::1]:443"):
        check("listen %s ssl default_server;" % a in s, "render: listener %s" % a)
    check(len(re.findall(r"(?m)^listen \S+:443 ssl default_server;", s)) == 3,
          "render: default_server only on the listen include's addresses")
    check("listen 443 ssl;\nlisten [::]:443 ssl;\n" in s,
          "render: wildcard 443 sockets (a missing address never blocks nginx start)")
    check("http2 on;" in s and "ssl http2" not in s, "render: nginx >= 1.25.1 uses `http2 on`")
    check("ssl_certificate /etc/tuxwall/tls/server.crt;" in s and "ssl_certificate_key /etc/tuxwall/tls/server.key;"
          in s, "render: TuxWall certificate")
    check("ssl_protocols TLSv1.2 TLSv1.3;" in s and "ssl_session_tickets off;" in s, "render: modern TLS")
    check("location = /tuxwall-ca.crt" in s and "alias /etc/tuxwall/tls/ca.crt;" in s, "render: CA download")
    check(re.search(r'\^http \(192\\\.168\\\.1\\\.1\|10\\\.0\\\.0\\\.1\|fd00:1::1\)\$', s),
          "render: redirect only on the TLS addresses (regex)")
    check("return 301 https://$host$request_uri;" in s, "render: 301 to https")
    check('if ($uri ~ "^/(\\.well-known/|tuxwall-ca\\.crt$)")' in s, "render: /.well-known/ + CA path exempt")
    check("Strict-Transport-Security" not in s, "render: no HSTS by default")
    s = H.render_snippet(env, dec(redirect=False), dict(H.SETTINGS_DEFAULT))
    check("return 301" not in s and "listen 192.168.1.1:443" in s, "render: escape hatch -> https kept, no redirect")
    s = H.render_snippet(env, dec(), dict(H.SETTINGS_DEFAULT, hsts=True, hsts_ever=True))
    check('set $tuxwall_hsts "max-age=31536000"' in s and "if ($scheme = https)" in s, "render: HSTS on (https only)")
    s = H.render_snippet(env, dec(), dict(H.SETTINGS_DEFAULT, hsts=False, hsts_ever=True))
    check('"max-age=0"' in s, "render: HSTS switched off -> max-age=0 clears it")
    s = H.render_snippet(H.Env(nginx_version="1.24.0"), dec(), dict(H.SETTINGS_DEFAULT))
    check("listen 192.168.1.1:443 ssl http2 default_server;" in s and "http2 on" not in s
          and "listen 443 ssl http2;" in s,
          "render: nginx 1.24 uses `listen ... ssl http2`")
    s = H.render_snippet(env, dec(), dict(H.SETTINGS_DEFAULT, custom_cert="/etc/ssl/r.pem", custom_key="/etc/ssl/r.key"))
    check("ssl_certificate /etc/ssl/r.pem;" in s and "ssl_certificate_key /etc/ssl/r.key;" in s,
          "render: own certificate")
    for m in ("owner-managed", "disabled", "no-addresses"):
        s = H.render_snippet(env, dec(mode=m, reasons=["x"]), dict(H.SETTINGS_DEFAULT))
        check(not [l for l in s.splitlines() if l.strip() and not l.startswith("#")],
              "render: %s -> comments only" % m)


# ── decision matrix ──────────────────────────────────────────────────────────

def t_decide():
    def run(setup, want, label, reason=None):
        b = Box(site="none")
        try:
            os.symlink(b.env.site_available, os.path.join(b.env.sites_enabled, "tuxwall"))
            setup(b)
            d = H.decide(b.env)
            ok = d["mode"] == want and (reason is None or any(reason in r for r in d["reasons"]))
            check(ok, "decide: %s -> %s (got %s: %s)" % (label, want, d["mode"], d["reasons"]))
            return d
        finally:
            b.close()

    run(lambda b: None, "active", "package symlink + include, nothing else on 443")

    def copy(b):
        os.unlink(os.path.join(b.env.sites_enabled, "tuxwall"))
        shutil.copy(b.env.site_available, os.path.join(b.env.sites_enabled, "tuxwall"))
    run(copy, "owner-managed", "sites-enabled/tuxwall is a regular file", "local copy")

    def elsewhere(b):
        os.unlink(os.path.join(b.env.sites_enabled, "tuxwall"))
        write(b.d + "/etc/nginx/sites-available/mine", open(SITE).read())
        os.symlink(b.d + "/etc/nginx/sites-available/mine", os.path.join(b.env.sites_enabled, "tuxwall"))
    run(elsewhere, "owner-managed", "symlink to another file", "local copy")

    def edited(b):
        t = open(b.env.site_available).read().replace("    include /etc/nginx/snippets/tuxwall-tls[.]conf;\n", "")
        write(b.env.site_available, t)
    run(edited, "owner-managed", "package site without the include (edited, kept by dpkg)", "edited")
    run(lambda b: os.unlink(os.path.join(b.env.sites_enabled, "tuxwall")), "owner-managed", "site not enabled",
        "not enabled")
    run(lambda b: b.site("mine-https", "server {\n  listen 192.168.1.1:443 ssl;\n  server_name router.example.com;\n"
                                      "  root /var/www/html;\n  ssl_certificate /etc/ssl/x.pem;\n}\n"),
        "owner-managed", "another site on LAN:443", "mine-https already listens on 192.168.1.1:443")
    run(lambda b: b.site("public", "server {\n listen 443 ssl; # public site\n server_name www.example.com;\n}\n"),
        "owner-managed", "another site on a 443 wildcard", "public already listens on *:443")
    run(lambda b: b.site("v6", "server {\n listen [::]:443 ssl ipv6only=on;\n}\n"), "owner-managed",
        "another site on [::]:443")
    run(lambda b: b.site("vpn6", "server { listen [fd00:1::1]:443 ssl; }"), "owner-managed",
        "another site on the LAN ULA:443", "[fd00:1::1]:443")
    run(lambda b: write(b.env.conf_d + "/x.conf", "server { listen 10.0.0.1:443 ssl; }\n"), "owner-managed",
        "conf.d server on VPN:443", "x.conf")
    run(lambda b: b.site("other", "server { listen 192.168.50.1:443 ssl; listen 192.168.1.1:8443 ssl; "
                                  "listen 192.168.1.1:80; }\n"), "active",
        "443 on a foreign address, 8443 and :80 on ours do not count")
    run(lambda b: b.site("commented", "server {\n # listen 192.168.1.1:443 ssl;\n listen 8080;\n}\n"), "active",
        "commented-out listen is ignored")
    run(lambda b: write(b.env.no_https, ""), "disabled", "/etc/tuxwall/no-https marker", "no-https")
    run(lambda b: H.save_settings(b.env, dict(H.SETTINGS_DEFAULT, enabled=False)), "disabled",
        "switched off in settings")
    d = run(lambda b: write(b.env.no_redirect, ""), "active", "redirect marker keeps HTTPS on")
    check(d["redirect"] is False and d["redirect_marker"], "decide: redirect marker -> no redirect")
    b = Box(ip=[link("lo", "127.0.0.1/8"), link("enp1s0", "203.0.113.9/24")], roles={"wan": {"device": "enp1s0"}})
    try:
        check(H.decide(b.env)["mode"] == "no-addresses", "decide: no LAN/VPN address -> no-addresses")
    finally:
        b.close()


def replica_sites(b, port_map=None):
    """A hand-made HTTPS setup like the maintainer's router, with example.com
    names and scratch certificate paths: the dashboard site is a local copy
    with hard-coded default_server :80 lines, a separate HTTPS dashboard site
    on the LAN/VPN addresses, a 443 wildcard public site and a Certbot-style
    site on the LAN addresses."""
    def a(addr, port):
        if port_map:
            return port_map(addr, port)
        return "[%s]:%d" % (addr, port) if ":" in addr else "%s:%d" % (addr, port)
    cert = b.d + "/certs/c.pem"
    key = b.d + "/certs/c.key"
    own = open(SITE).read().replace(
        "    include /etc/nginx/snippets/tuxwall-listen[.]conf;\n",
        "".join("    listen %s default_server;\n" % a(x, 80) for x in LISTEN_ADDRS))
    own = own.replace("    include /etc/nginx/snippets/tuxwall-tls[.]conf;\n", "")
    own = own.replace("server_name _;", "server_name router.example.com;")
    if port_map:
        own = own.replace("listen 80 default_server;", "listen %s default_server;" % port_map("*", 80))
        own = own.replace("listen [::]:80 default_server;", "listen %s default_server;" % port_map("::", 80))
    b.site("tuxwall", own)
    https = ("server {\n" + "".join("    listen %s ssl;\n" % a(x, 443) for x in LISTEN_ADDRS) +
             "    server_name router.example.com;\n    root /var/www/html;\n"
             "    ssl_certificate %s;\n    ssl_certificate_key %s;\n"
             "    location /api/ { proxy_pass http://127.0.0.1:8008; }\n}\n"
             "server {\n" + "".join("    listen %s;\n" % a(x, 80) for x in LISTEN_ADDRS) +
             "    server_name router.example.com;\n    return 301 https://$host$request_uri;\n}\n") % (cert, key)
    b.site("tuxwall-https", https)
    pub = ("server {\n    listen %s ssl;\n    server_name www.example.com;\n    ssl_certificate %s;\n"
           "    ssl_certificate_key %s;\n    return 200;\n}\n") % (a("*", 443), cert, key)
    b.site("public-site", pub)
    ha = ("server {\n    server_name ha.example.com;\n" + "".join("    listen %s ssl;\n" % a(x, 443)
                                                                  for x in LISTEN_ADDRS) +
          "    ssl_certificate %s;\n    ssl_certificate_key %s;\n    location / { proxy_pass http://127.0.0.1:8123; }\n}\n"
          % (cert, key))
    b.site("homeassistant", ha)
    return cert, key


def t_owner_managed_refresh():
    if not OPENSSL:
        return
    b = Box(site="none")
    try:
        replica_sites(b)
        b.called()
        r = H.refresh(b.env, reload=True)
        calls = b.called()
        check(r["ok"] and r["mode"] == "owner-managed", "replica: owner-managed (%s)" % r.get("message"))
        check(os.path.exists(b.env.p("server.crt")) and os.path.exists(b.env.p("ca.crt")),
              "replica: certificates generated anyway")
        check(not os.path.exists(b.env.snippet), "replica: no HTTPS snippet written")
        check(not [c for c in calls if c.startswith(("nginxt", "reload", "ufw"))],
              "replica: no nginx -t, no reload, no firewall change")
        check("existing HTTPS setup detected" in r["message"] and "Settings -> HTTPS" in r["message"],
              "replica: the note for the postinst output")
        st = H.status(b.env)
        files = {c["file"] for c in st["conflicts"]}
        check({"tuxwall-https", "public-site", "homeassistant"} <= files, "replica: conflicts listed (%s)" % files)
        check([s["file"] for s in st["owner_sites"]] == ["tuxwall-https"],
              "replica: the custom site serving the dashboard is identified (%s)" % st["owner_sites"])
        check(st["in_use"] == "none" and st["urls"] == [], "replica: TuxWall certificate not in use, no URLs")
        # an owner switch-on attempt changes nothing in nginx
        ok, res = H.apply_settings(b.env, {"enabled": True})
        check(not os.path.exists(b.env.snippet) and not [c for c in b.called() if c.startswith("reload")],
              "replica: enabling still leaves nginx alone")
        # a TuxWall snippet that was active before the owner added a conflicting site is retired
        b2 = Box()
        try:
            H.refresh(b2.env)
            check("listen 192.168.1.1:443" in open(b2.env.snippet).read(), "active snippet before the conflict")
            b2.site("mine", "server { listen 192.168.1.1:443 ssl default_server; }\n")
            b2.called()
            r = H.refresh(b2.env, reload=True)
            calls = b2.called()
            check(r["mode"] == "owner-managed" and "listen" not in re.sub(r"(?m)^#.*$", "", open(b2.env.snippet).read()),
                  "conflict appears later: TuxWall's listeners are retired (comment-only snippet)")
            check(any(c.startswith("nginxt") for c in calls) and any(c.startswith("reload") for c in calls),
                  "retiring the listeners: nginx -t + reload")
        finally:
            b2.close()
    finally:
        b.close()


def t_transactions():
    if not OPENSSL:
        return
    b = Box()
    try:
        H.refresh(b.env)
        snip = open(b.env.snippet).read()
        crt = open(b.env.p("server.crt")).read()
        os.environ["RC_NGINXT"] = "1"
        try:
            r = H.refresh(b.env, force_cert=True, reload=True)
            check(not r["ok"] and "previous" in r["message"], "nginx -t failure on a new certificate: refused")
            check(open(b.env.p("server.crt")).read() == crt, "nginx -t failure: previous certificate back")
            ok, res = H.apply_settings(b.env, {"redirect": False})
            check(not ok and open(b.env.snippet).read() == snip, "nginx -t failure on a settings change: snippet back")
            check(H.load_settings(b.env)["redirect"] is True, "failed settings change: settings rolled back")
            check(not os.path.exists(b.env.snippet + ".tuxwall-prev") and
                  not [f for f in os.listdir(b.env.tls_dir) if f.endswith(".prev")], "no backups left after rollback")
        finally:
            del os.environ["RC_NGINXT"]
        check(H.status(b.env)["applied"] is True, "status: applied after refresh")
        H.save_settings(b.env, dict(H.load_settings(b.env), redirect=False))
        check(H.status(b.env)["applied"] is False, "status: settings changed without refresh -> not applied")
        H.save_settings(b.env, dict(H.load_settings(b.env), redirect=True))
        ok, res = H.apply_settings(b.env, {"redirect": False})
        check(ok and "return 301" not in open(b.env.snippet).read(), "redirect off via settings")
        ok, res = H.apply_settings(b.env, {"hsts": True})
        check(ok and "max-age=31536000" in open(b.env.snippet).read() and H.load_settings(b.env)["hsts_ever"],
              "HSTS on via settings")
        # own certificate validation
        own = b.d + "/etc/ssl"
        os.makedirs(own)
        subprocess.run([OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", own + "/a.key", "-out", own + "/a.pem", "-days", "30", "-subj", "/CN=router"],
                       capture_output=True)
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out",
                        own + "/other.key"], capture_output=True)
        check("absolute paths" in H.validate_custom(b.env, "rel.pem", "rel.key"), "own cert: relative paths refused")
        check("absolute paths" in H.validate_custom(b.env, own + "/a.pem", own + "/a.key"),
              "own cert: outside /etc refused (scratch path)")
        old_ok = H._path_ok
        H._path_ok = lambda p: isinstance(p, str) and p.startswith("/")
        try:
            check(H.validate_custom(b.env, own + "/a.pem", own + "/a.key") == "", "own cert: matching pair accepted")
            check("does not belong" in H.validate_custom(b.env, own + "/a.pem", own + "/other.key"),
                  "own cert: key mismatch refused")
            check("not found" in H.validate_custom(b.env, own + "/missing.pem", own + "/a.key"), "own cert: missing file")
            ok, res = H.apply_settings(b.env, {"custom_cert": own + "/a.pem", "custom_key": own + "/a.key"})
            s = open(b.env.snippet).read()
            check(ok and ("ssl_certificate %s/a.pem;" % own) in s, "own cert in use after apply")
            check(H.status(b.env)["in_use"] == "custom", "status: own certificate in use")
            ok, res = H.apply_settings(b.env, {"custom_cert": "", "custom_key": ""})
            check(ok and "ssl_certificate %s;" % b.env.p("server.crt") in open(b.env.snippet).read(),
                  "back to the TuxWall certificate")
        finally:
            H._path_ok = old_ok
        check(not H._path_ok("/etc/../root/x") and H._path_ok("/etc/ssl/x.pem") is True, "path rule: under /etc only")
    finally:
        b.close()


def t_sockets():
    """Port 443 already taken by another program -> owner-managed; a reload
    that kept address-bound 443 sockets -> one nginx restart."""
    if not OPENSSL:
        return
    b = Box()
    try:
        b.env.ss_cmd = [b.fake + "/ss"]
        write(b.ss_out, 'LISTEN 0 4096 192.168.1.1:443 0.0.0.0:* users:(("docker-proxy",pid=7,fd=4))\n')
        d = H.decide(b.env)
        check(d["mode"] == "owner-managed" and any("docker-proxy (192.168.1.1:443)" in r for r in d["reasons"]),
              "another program on 443 -> owner-managed (%s)" % d["reasons"])
        write(b.ss_out, 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=9,fd=7))\n')
        b.called()
        H.refresh(b.env, reload=True)
        check(not [c for c in b.called() if c.startswith("restart")], "443 was free -> reload only, no restart")
        # the running nginx kept address-bound sockets after the reload
        write(b.ss_out, 'LISTEN 0 511 192.168.1.1:443 0.0.0.0:* users:(("nginx",pid=9,fd=7),("nginx",pid=8,fd=7))\n')
        r = H.refresh(b.env, reload=True, force_cert=True)
        calls = b.called()
        check(r["ok"] and r.get("restarted") and calls.index([c for c in calls if c.startswith("reload")][0])
              < calls.index([c for c in calls if c.startswith("restart")][0]),
              "reload kept address-bound 443 sockets -> nginx restarted once (%s)" % r.get("message"))
        write(b.ss_out, 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=9,fd=7))\n'
                        'LISTEN 0 511 [::]:443 [::]:* users:(("nginx",pid=9,fd=8))\n')
        H.refresh(b.env, reload=True, force_cert=True)
        check(not [c for c in b.called() if c.startswith("restart")], "wildcard sockets in place -> no restart")
    finally:
        b.close()


# ── real nginx -t ────────────────────────────────────────────────────────────

def t_real_nginx():
    if not NGINX or not OPENSSL:
        print("SKIP: nginx/openssl not installed - real nginx -t cases")
        return
    if not os.path.exists("/etc/nginx/mime.types"):
        print("SKIP: /etc/nginx/mime.types missing - real nginx -t cases")
        return
    # `nginx -t` binds the listen addresses (only EADDRINUSE is tolerated), so
    # the fixture addresses get loopback stand-ins and high ports: the snippet
    # refresh() writes is copied through the same mapping before every test.
    port = 18100 + os.getpid() % 500
    sub = [("192.168.1.1", "127.0.0.2"), ("10.0.0.1", "127.0.0.3"), ("[fd00:1::1]", "[::1]"),
           ("192.0.2.77", "192.0.2.77")]     # an address this machine does not have

    def pm(addr, p):
        q = port + (443 if p == 443 else 0) if p in (80, 443) else p
        h = dict((k.strip("[]"), v.strip("[]")) for k, v in sub).get(addr, addr)
        if h in ("*", "::"):
            return "[::]:%d" % q if h == "::" else str(q)
        return "[%s]:%d" % (h, q) if ":" in h else "%s:%d" % (h, q)

    def localize(text):
        text = re.sub(r"(?m)^listen 443 ", "listen %d " % (port + 443), text)
        text = re.sub(r"(?m)^listen \[::\]:443 ", "listen [::]:%d " % (port + 443), text)
        text = text.replace("listen 80 default_server;", "listen %d default_server;" % port)
        text = text.replace("listen [::]:80 default_server;", "listen [::]:%d default_server;" % port)
        for k, v in sub:
            text = text.replace("%s:443" % k, "%s:%d" % (v, port + 443)).replace("%s:80" % k, "%s:%d" % (v, port))
        return text

    b = Box()
    d = b.d
    loc = d + "/loc"
    os.makedirs(loc)
    nginx_conf = os.path.join(d, "nginx.conf")
    try:
        write(nginx_conf, "pid %s/nginx.pid;\nerror_log stderr;\nevents {}\nhttp {\n  access_log off;\n"
                          "  include /etc/nginx/mime.types;\n  include %s;\n  include %s/etc/nginx/sites-enabled/*;\n}\n"
              % (d, LIMITS, d))
        real = [NGINX, "-e", "stderr", "-p", d + "/", "-c", nginx_conf, "-t"]
        mapper = d + "/map.py"
        write(mapper, "import sys\nsrc, dst = sys.argv[1:3]\nt = open(src).read()\n" +
              "import re\nt = re.sub(r'(?m)^listen 443 ', 'listen %d ', t)\n" % (port + 443) +
              "t = re.sub(r'(?m)^listen \\[::\\]:443 ', 'listen [::]:%d ', t)\n" % (port + 443) +
              "".join("t = t.replace(%r, %r).replace(%r, %r)\n" % ("%s:443" % k, "%s:%d" % (v, port + 443),
                                                                   "%s:80" % k, "%s:%d" % (v, port)) for k, v in sub) +
              "open(dst, 'w').write(t)\n")
        write(d + "/nt.sh", '#!/bin/sh\nif [ -f "%s" ]; then %s %s "%s" "%s/tuxwall-tls.conf"; else rm -f "%s/tuxwall-tls.conf"; fi\n'
                            'exec %s\n' % (b.env.snippet, sys.executable, mapper, b.env.snippet, loc, loc,
                                            " ".join('"%s"' % x for x in real)), 0o755)
        b.env.nginx_test = [d + "/nt.sh"]
        b.env.nginx_version = None
        # the enabled package site: includes the stand-in copies of both snippets
        site = localize(open(SITE).read()).replace("/etc/nginx/snippets/tuxwall-listen[.]conf",
                                                   loc + "/tuxwall-listen[.]conf")
        site = site.replace("/etc/nginx/snippets/tuxwall-tls[.]conf", loc + "/tuxwall-tls[.]conf")
        write(b.env.site_available, site)
        write(loc + "/tuxwall-listen.conf", "".join("listen %s default_server;\n" % pm(a, 80) for a in LISTEN_ADDRS))

        def nt():
            p = subprocess.run(b.env.nginx_test, capture_output=True, text=True, timeout=30)
            return p.returncode, p.stderr.strip()

        rc, err = nt()
        check(rc == 0, "nginx -t: package site + listen include, no TLS snippet yet (%s)" % err[-200:])
        r = H.refresh(b.env)
        check(r["ok"] and r["mode"] == "active" and r["snippet_changed"],
              "refresh with real nginx -t: active snippet accepted (%s)" % r.get("message"))
        raw = open(b.env.snippet).read()

        def put(text):
            write(b.env.snippet, text)
            return nt()
        for label, settings, dd in (
                ("escape hatch", dict(H.SETTINGS_DEFAULT), dec(redirect=False)),
                ("HSTS on", dict(H.SETTINGS_DEFAULT, hsts=True, hsts_ever=True), dec()),
                ("HSTS off after on", dict(H.SETTINGS_DEFAULT, hsts_ever=True), dec()),
                ("own certificate", dict(H.SETTINGS_DEFAULT, custom_cert=b.env.p("server.crt"),
                                         custom_key=b.env.p("server.key")), dec())):
            rc, err = put(H.render_snippet(b.env, dd, settings))
            check(rc == 0, "nginx -t: %s (%s)" % (label, err[-200:]))
        v = H._nginx_version(b.env)
        rc, err = put(H.render_snippet(H.Env(tls_dir=b.env.tls_dir, nginx_version="1.24.0"), dec(),
                                       dict(H.SETTINGS_DEFAULT)))
        check(rc == 0, "nginx -t: legacy `listen ... ssl http2` syntax accepted by %s (%s)" % (v, err[-120:]))
        # an address that is gone (WireGuard down, IPv6 DAD at boot): fine thanks to the wildcard sockets ...
        gone = H.render_snippet(b.env, dec(listen=LISTEN_ADDRS + ["192.0.2.77"]), dict(H.SETTINGS_DEFAULT))
        rc, err = put(gone)
        check(rc == 0, "nginx -t: a listed address missing on the box does not break nginx (%s)" % err[-160:])
        # ... without them nginx would have to bind it and fail
        rc, err = put(re.sub(r"(?m)^listen (443|\[::\]:443) ssl;\n", "", gone))
        check(rc != 0 and "bind()" in err, "nginx -t: same without the wildcard sockets fails (%s)" % err[-100:])
        rc, err = put(raw)
        check(rc == 0, "nginx -t: back to the refresh() render")
        # what the detection prevents: a second default_server on the same
        # address:443. The stand-in address hides it from decide(), so this is
        # also refresh()'s rollback with a real failing nginx -t.
        crt = open(b.env.p("server.crt")).read()
        b.site("zz-other", "server {\n    listen %s ssl default_server;\n    ssl_certificate %s;\n"
                           "    ssl_certificate_key %s;\n}\n" % (pm("192.168.1.1", 443), b.env.p("server.crt"),
                                                                 b.env.p("server.key")))
        rc, err = nt()
        check(rc != 0 and "duplicate default server" in err,
              "nginx -t: active snippet + another default_server on LAN:443 = fatal (%s)" % err[-100:])
        r = H.refresh(b.env, force_cert=True)
        check(not r["ok"] and open(b.env.p("server.crt")).read() == crt and open(b.env.snippet).read() == raw,
              "refresh with a failing real nginx -t: previous certificate + snippet kept (%s)" % r.get("message")[:90])
        os.unlink(os.path.join(b.env.sites_enabled, "zz-other"))
        # the same site at the real address is seen by the detection -> owner-managed, nginx -t passes
        b.site("zz-other", "server {\n    listen 192.168.1.1:443 ssl default_server;\n}\n")
        check(H.decide(b.env)["mode"] == "owner-managed", "detection: another default_server on LAN:443")
        os.unlink(os.path.join(b.env.sites_enabled, "zz-other"))
        # owner-managed replica (stand-in addresses) + TuxWall's inactive snippet
        shutil.rmtree(b.env.sites_enabled)
        os.makedirs(b.env.sites_enabled)
        os.makedirs(d + "/certs", exist_ok=True)
        cert, key = replica_sites(b, port_map=pm)
        subprocess.run([OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "30", "-subj", "/CN=scratch"], capture_output=True)
        os.unlink(b.env.snippet)
        rc, err = nt()
        check(rc == 0, "nginx -t: replica of a hand-made HTTPS setup (%s)" % err[-200:])
        rc, err = put(H.render_snippet(b.env, dec(mode="owner-managed", reasons=["x"]), dict(H.SETTINGS_DEFAULT)))
        check(rc == 0, "nginx -t: replica + inactive snippet (%s)" % err[-200:])
        b2 = Box(site="none")
        try:
            replica_sites(b2)
            check(H.decide(b2.env)["mode"] == "owner-managed", "replica (real addresses): owner-managed")
        finally:
            b2.close()
    finally:
        b.close()


# ── security headers (nginx add_header inheritance) ──────────────────────────

SEC_HEADERS = {"x-frame-options", "x-content-type-options", "referrer-policy"}
TEMPLATES = [os.path.join(ROOT, "nginx", n) for n in ("tuxwall.conf", "tuxwall.conf.in", "tuxwall-https.conf",
                                                      "tuxwall-https.conf.in")]
TLS_INCLUDE = "include /etc/nginx/snippets/tuxwall-tls[.]conf;"


def header_blocks(text):
    """[(block, add_header names)] per server/location block; add_header
    outside any block (the TLS snippet) counts as server level."""
    text = re.sub(r"#[^\n]*", "", text)
    out, stack, top = [], [], set()
    for m in re.finditer(r"([^;{}]*)\{|\}|([^;{}]*);", text):
        if m.group(1) is not None:
            stack.append([" ".join(m.group(1).split()), set()])
        elif m.group(0) == "}":
            out.append(tuple(stack.pop()))
        else:
            words = m.group(2).split()
            if len(words) > 1 and words[0] == "add_header":
                (stack[-1][1] if stack else top).add(words[1].lower())
    return out, top


def header_gaps(text):
    """Locations that set their own add_header but miss a server-level one
    (nginx then sends none of the server's headers there)."""
    blocks, top = header_blocks(text)
    server = set(top)
    for name, hs in blocks:
        if name.startswith("server"):
            server |= hs
    return ["%s: %s" % (name, ", ".join(sorted(server - hs))) for name, hs in blocks
            if name.startswith("location") and hs and not server <= hs]


def t_headers_static():
    site = open(SITE).read()
    snippets = {"default": dict(H.SETTINGS_DEFAULT), "HSTS on": dict(H.SETTINGS_DEFAULT, hsts=True, hsts_ever=True),
                "escape hatch": dict(H.SETTINGS_DEFAULT, redirect=False)}
    blocks, _top = header_blocks(site)
    srv = [hs for n, hs in blocks if n.startswith("server")]
    check(srv and SEC_HEADERS <= srv[0], "package site: server-level security headers declared")
    check(not header_gaps(site), "package site: no location drops the security headers (%s)" % header_gaps(site))
    for label, settings in snippets.items():
        snip = H.render_snippet(H.Env(tls_dir="/etc/tuxwall/tls", nginx_version="1.28.0"), dec(), settings)
        both = site.replace(TLS_INCLUDE, snip)
        check(not header_gaps(both), "package site + TLS snippet (%s): no location drops a header (%s)"
              % (label, header_gaps(both)))
    hsts = H.render_snippet(H.Env(tls_dir="/etc/tuxwall/tls", nginx_version="1.28.0"), dec(), snippets["HSTS on"])
    check("strict-transport-security" in header_blocks(hsts)[1], "TLS snippet: HSTS at server level")
    for p in TEMPLATES:
        text = open(p).read()
        check(not header_gaps(text), "%s: no location drops the security headers (%s)"
              % (os.path.relpath(p, ROOT), header_gaps(text)))
    # self-test: the 3.3.5 site (add_header Cache-Control in `location /`) is caught
    old = site.replace("        expires epoch;\n", '        add_header Cache-Control "no-cache" always;\n')
    check(old != site and any(g.startswith("location /:") for g in header_gaps(old)),
          "header check catches a location add_header that drops the server headers")


def t_headers_served():
    """Serve the package site + TLS snippet from a real nginx on loopback and
    read the headers of /, /index.html, the CA download (http + https)."""
    if not NGINX or not OPENSSL or not os.path.exists("/etc/nginx/mime.types"):
        print("SKIP: nginx/openssl/mime.types missing - served header cases")
        return
    import http.client
    import ssl
    import time
    port = 18700 + os.getpid() % 500
    d = tempfile.mkdtemp(prefix="https-headers-")
    os.chmod(d, 0o755)
    procs = []
    try:
        write(d + "/www/index.html", "<html>TuxWall</html>\n")
        write(d + "/www/app.js", "1;\n")
        tls = d + "/tls"
        os.makedirs(tls)
        p = subprocess.run([OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                            "-keyout", tls + "/server.key", "-out", tls + "/server.crt", "-days", "2",
                            "-subj", "/CN=scratch"], capture_output=True)
        check(p.returncode == 0, "served headers: scratch certificate")
        shutil.copy(tls + "/server.crt", tls + "/ca.crt")
        os.chmod(tls + "/server.key", 0o644)
        snip = H.render_snippet(H.Env(tls_dir=tls, nginx_version=H._nginx_version(H.Env()) or "1.24.0"),
                                dec(), dict(H.SETTINGS_DEFAULT, hsts=True, hsts_ever=True))
        snip = re.sub(r"(?m)^listen \S+:443 ssl( http2)? default_server;\n", "", snip)
        snip = re.sub(r"(?m)^listen 443 ", "listen 127.0.0.1:%d " % (port + 443), snip)
        snip = re.sub(r"(?m)^listen \[::\]:443 .*\n", "", snip)

        def site_text(src):
            t = src.replace("listen 80 default_server;", "listen 127.0.0.1:%d default_server;" % port)
            t = t.replace("listen [::]:80 default_server;", "")
            t = t.replace("include /etc/nginx/snippets/tuxwall-listen[.]conf;", "")
            t = t.replace(TLS_INCLUDE, snip).replace("root /var/www/html;", "root %s/www;" % d)
            return t

        def serve(name, src):
            base = os.path.join(d, name)
            os.makedirs(base)
            temps = "".join("  %s_temp_path %s/%s;\n" % (k, base, k) for k in ("client_body", "proxy", "fastcgi",
                                                                               "uwsgi", "scgi"))
            write(base + "/site", site_text(src))
            write(base + "/nginx.conf", "pid %s/nginx.pid;\nerror_log %s/error.log;\nevents {}\nhttp {\n"
                                        "  access_log off;\n%s  include /etc/nginx/mime.types;\n  include %s;\n"
                                        "  include %s/site;\n}\n" % (base, base, temps, LIMITS, base))
            proc = subprocess.Popen([NGINX, "-p", base + "/", "-c", base + "/nginx.conf", "-g", "daemon off;"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(proc)
            for _ in range(50):
                try:
                    http.client.HTTPConnection("127.0.0.1", port, timeout=1).request("HEAD", "/nope")
                    return proc
                except OSError:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
            err = open(base + "/error.log").read() if os.path.exists(base + "/error.log") else ""
            check(False, "served headers: nginx started (%s)" % err[-200:])
            return None

        def stop(proc):
            proc.terminate()
            proc.wait(timeout=10)

        def get(path, tls_=False):
            if tls_:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                c = http.client.HTTPSConnection("127.0.0.1", port + 443, timeout=5, context=ctx)
            else:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", path)
            r = c.getresponse()
            r.read()
            c.close()
            return r.status, {k.lower(): v for k, v in r.getheaders()}

        proc = serve("current", open(SITE).read())
        if proc is None:
            return
        for path in ("/", "/index.html", "/app.js", "/tuxwall-ca.crt"):
            for over_tls in (False, True):
                st, h = get(path, over_tls)
                label = "%s %s" % ("https" if over_tls else "http", path)
                check(st == 200 and SEC_HEADERS <= set(h), "served %s: 200 + %s (got %s %s)"
                      % (label, "/".join(sorted(SEC_HEADERS)), st, sorted(h)))
                check(h.get("cache-control") == "no-cache", "served %s: Cache-Control no-cache" % label)
                check(("strict-transport-security" in h) == over_tls, "served %s: HSTS %s"
                      % (label, "sent" if over_tls else "not sent over http"))
        st, h = get("/nope")
        check(st == 404 and SEC_HEADERS <= set(h), "served http 404: security headers too")
        stop(proc)
        # the 3.3.5 location (add_header Cache-Control) really loses them
        old = open(SITE).read().replace("        expires epoch;\n", '        add_header Cache-Control "no-cache" always;\n')
        proc = serve("old", old)
        if proc is not None:
            st, h = get("/index.html")
            check(st == 200 and not (SEC_HEADERS & set(h)) and h.get("cache-control") == "no-cache",
                  "served: the 3.3.5 location drops the headers (test is sensitive)")
            stop(proc)
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
        shutil.rmtree(d, ignore_errors=True)


# ── postinst ─────────────────────────────────────────────────────────────────

SRC = open(POSTINST).read()


def func(name):
    m = re.search(r"^%s\(\) \{.*?^\}\n" % re.escape(name), SRC, re.M | re.S)
    return m.group(0) if m else ""


def t_postinst():
    fns = "".join(func(n) for n in ("fw_lan_ifaces", "fw_has_port_rule", "fw_fresh_allow", "https_fw_allow",
                                    "https_setup"))
    check(all(func(n) for n in ("https_fw_allow", "https_setup")), "postinst defines https_fw_allow + https_setup")
    step7 = SRC[SRC.index('step 7 "'):SRC.index('step 8 "')]
    check("https_setup" in step7 and step7.index("nginx_listen_render") < step7.index("https_setup")
          < step7.index("if nginx -t"), "postinst: listen include, then HTTPS, then nginx -t + reload")
    check("systemctl enable --now tuxwall-tls-renew.timer" in SRC, "postinst enables the renewal timer")
    d = tempfile.mkdtemp(prefix="https-postinst-")
    try:
        os.makedirs(d + "/fbin")
        write(d + "/fbin/ufw", '#!/bin/sh\necho "ufw $*" >> "$FAKE_LOG"\n'
                               'if [ "$1" = show ]; then cat "$UFW_ADDED" 2>/dev/null; fi\nexit 0\n', 0o755)
        write(d + "/fbin/openssl", "#!/bin/sh\nexit 0\n", 0o755)
        write(d + "/fbin/ip", "#!/bin/sh\nexit 1\n", 0o755)
        write(d + "/roles.json", json.dumps(ROLES))

        def helper(mode_, rc=0, msg="certificate issued (new CA); HTTPS on 192.168.1.1"):
            write(d + "/helper", '#!/bin/sh\necho "helper $*" >> "$FAKE_LOG"\n'
                                 'case "$1" in decide) echo %s ;; refresh) echo "tuxwall-tls: %s"; exit %d ;; esac\n'
                  % (mode_, msg, rc), 0o755)

        def run(script, added=""):
            write(d + "/added", added)
            env = dict(os.environ, PATH=d + "/fbin:" + os.environ.get("PATH", ""), FAKE_LOG=d + "/calls",
                       UFW_ADDED=d + "/added")
            if os.path.exists(d + "/calls"):
                os.unlink(d + "/calls")
            p = subprocess.run(["bash", "-c", "set -euo pipefail\n" + fns + script], env=env, capture_output=True,
                               text=True, timeout=60)
            calls = open(d + "/calls").read().splitlines() if os.path.exists(d + "/calls") else []
            return p.returncode, calls, p.stdout, p.stderr

        roles = d + "/roles.json"
        # fw_lan_ifaces reads interfaces.json / wg0.conf from fixed defaults: point them at the scratch dir
        call = 'https_setup enp1s0 enp2s0 "%s/helper"\n' % d
        fns_r = fns.replace("roles=${3:-/etc/tuxwall/interfaces.json}", "roles=${3:-%s}" % roles)
        fns_r = fns_r.replace("wgconf=${4:-/etc/wireguard/wg0.conf}", "wgconf=${4:-%s/none}" % d)

        def run_r(script, added=""):
            nonlocal fns
            saved, fns = fns, fns_r
            try:
                return run(script, added)
            finally:
                fns = saved
        helper("active")
        rc, calls, out, err = run_r(call)
        ufw = [c for c in calls if c.startswith("ufw allow")]
        check(rc == 0 and ufw == ["ufw allow in on enp2s0 to any port 443 proto tcp comment TuxWall dashboard HTTPS (LAN)",
                                  "ufw allow in on wg0 to any port 443 proto tcp comment TuxWall dashboard HTTPS (VPN)"],
              "postinst active: 443 on LAN + VPN only (%s)" % ufw)
        check(calls.index(ufw[-1]) < calls.index("helper refresh --reload"), "postinst: 443 opened before the redirect goes live")
        check("https: certificate issued" in out and "enp1s0" not in " ".join(ufw), "postinst: status line, never the WAN")
        rc, calls, out, err = run_r(call, added="ufw allow 443/tcp\n")
        check(rc == 0 and not [c for c in calls if c.startswith("ufw allow")] and "already has a firewall rule" in out,
              "postinst: an existing 443 rule is left as is")
        helper("owner-managed", msg="certificate issued (new CA); existing HTTPS setup detected (x) - nginx left alone;"
                                    " TuxWall's certificate is in /etc/tuxwall/tls (CA: ca.crt); enable from Settings"
                                    " -> HTTPS if wanted")
        rc, calls, out, err = run_r(call)
        check(rc == 0 and not [c for c in calls if c.startswith("ufw")] and "existing HTTPS setup detected" in out,
              "postinst owner-managed: no firewall change, note printed")
        helper("active", rc=1, msg="nginx -t failed with the new HTTPS snippet - previous files kept")
        rc, calls, out, err = run_r(call)
        check(rc == 0 and "WARNING nginx -t failed" in out and "tuxwall-tls refresh --reload" in out,
              "postinst: helper failure is a warning with the re-run command, never fails")
        rc, calls, out, err = run_r('https_setup enp1s0 enp2s0 "%s/missing"\n' % d)
        check(rc == 0 and "missing" in out and not calls, "postinst: missing helper -> note, nothing run")
        # no LAN known: private-network sources only
        write(roles, "{}")
        helper("active")
        rc, calls, out, err = run_r('https_setup enp1s0 "" "%s/helper"\n' % d)
        ufw = [c for c in calls if c.startswith("ufw allow")]
        check(rc == 0 and len(ufw) == 4 and all("from" in c and "port 443" in c for c in ufw),
              "postinst: no LAN interface -> 443 from RFC1918/ULA sources only (%d rules)" % len(ufw))
    finally:
        shutil.rmtree(d)


def t_announce():
    """Upgrade notice: postinst https_announce decides, https_tls reads/dismisses."""
    fns = func("https_serving") + func("https_announce")
    check(func("https_serving") and func("https_announce"), "postinst defines https_serving + https_announce")
    step7 = SRC[SRC.index('step 7 "'):SRC.index('step 8 "')]
    check(re.search(r"_https_was=no\n\s*https_serving && _https_was=yes\n\s*https_setup [^\n]*\n"
                    r"\s*_https_msg=\"\$\(https_announce \"\$\{2:-\}\" \"\$_https_was\"\)\"", step7),
          "postinst step 7: serving state read before https_setup, https_announce right after (prev version)")
    d = tempfile.mkdtemp(prefix="https-announce-")
    try:
        active = H.render_snippet(H.Env(tls_dir="/etc/tuxwall/tls", nginx_version="1.28.0"), dec(),
                                  dict(H.SETTINGS_DEFAULT))
        hatch = H.render_snippet(H.Env(tls_dir="/etc/tuxwall/tls", nginx_version="1.28.0"), dec(redirect=False),
                                 dict(H.SETTINGS_DEFAULT))
        owner = H.render_snippet(H.Env(), dec(mode="owner-managed", reasons=["local copy of sites-enabled/tuxwall"]),
                                 dict(H.SETTINGS_DEFAULT))
        snip, marker = d + "/tuxwall-tls.conf", d + "/lib/https-announce"

        def run(prev, was, text):
            if os.path.exists(marker):
                os.unlink(marker)
            if text is None:
                if os.path.exists(snip):
                    os.unlink(snip)
            else:
                write(snip, text)
            p = subprocess.run(["bash", "-c", "set -euo pipefail\n" + fns + 'https_announce "$1" "$2" "$3" "$4"',
                                "x", prev, was, snip, marker], capture_output=True, text=True, timeout=30)
            meta = json.load(open(marker)) if os.path.exists(marker) else None
            return p.returncode, meta, p.stdout

        def serving(text):
            if text is None:
                if os.path.exists(snip):
                    os.unlink(snip)
            else:
                write(snip, text)
            return subprocess.run(["bash", "-c", fns + 'https_serving "$1"', "x", snip]).returncode == 0
        check(serving(active) and serving(hatch) and not serving(owner) and not serving(None),
              "https_serving: active/escape-hatch snippet yes; owner-managed note / no snippet no")
        rc, meta, out = run("3.3.5", "no", active)
        check(rc == 0 and meta and meta["from"] == "3.3.5" and meta["redirect"] is True
              and isinstance(meta["since"], int) and "one-time notice" in out,
              "upgrade 3.3.5 -> HTTPS on: marker written (from, since, redirect) + status line (%s)" % meta)
        check(mode(marker) == 0o644, "marker 0644")
        rc, meta, out = run("", "no", active)
        check(rc == 0 and meta is None and out == "", "fresh install: no marker")
        rc, meta, _ = run("3.3.6", "yes", active)
        check(rc == 0 and meta is None, "upgrade with HTTPS already served: no marker")
        rc, meta, _ = run("3.3.5", "no", owner)
        check(rc == 0 and meta is None, "upgrade, owner-managed (no listeners): no marker")
        rc, meta, _ = run("3.3.5", "no", None)
        check(rc == 0 and meta is None, "upgrade, HTTPS off / no snippet: no marker")
        rc, meta, _ = run("3.3.5", "no", hatch)
        check(rc == 0 and meta and meta["redirect"] is False, "upgrade with the escape hatch: marker, redirect false")
        rc, meta, _ = run('3.3.5"; rm -rf /', "no", active)
        check(rc == 0 and meta and meta["from"] == "3.3.5rm-rf", "version string sanitised in the JSON (%s)" % meta)
        write(d + "/file", "x")
        p = subprocess.run(["bash", "-c", "set -euo pipefail\n" + fns + 'https_announce 3.3.5 no "$1" "$2"; echo done',
                            "x", snip, d + "/file/sub/marker"], capture_output=True, text=True, timeout=30)
        check(p.returncode == 0 and p.stdout.strip() == "done", "unwritable marker path: no failure, no message")

        # the API side (https_tls): shown only while the marker exists AND HTTPS is served
        env = H.Env(snippet=snip, announce=marker)
        run("3.3.5", "no", active)
        a = H.announce_info(env)
        check(a and a["from"] == "3.3.5" and a["redirect"] is True and a["since"], "announce_info: marker + serving (%s)" % a)
        write(snip, hatch)
        check(H.announce_info(env)["redirect"] is False, "announce_info: redirect read from the live snippet")
        write(snip, owner)
        check(H.announce_info(env) is None, "announce_info: hidden while TuxWall HTTPS is not served")
        write(snip, active)
        write(marker, "not json")
        a = H.announce_info(env)
        check(a and a["since"] is None and a["from"] == "", "announce_info: unreadable marker still announces")
        r = H.dismiss_announce(env)
        check(r["ok"] and not os.path.exists(marker) and H.announce_info(env) is None, "dismiss removes the marker")
        check(H.dismiss_announce(env)["ok"], "dismiss is idempotent")
        check(H.Env().announce == "/var/lib/tuxwall/https-announce", "default marker path")
    finally:
        shutil.rmtree(d)
    api = open(os.path.join(ROOT, "www", "includes", "api_server.py")).read()
    check('"/api/https/dismiss-announce"' in api and 'action == "dismiss-announce"' in api,
          "API: POST /api/https/dismiss-announce (admin prefix /api/https, CSRF like every POST)")
    check('"announce": announce_info(env)' in open(os.path.join(ROOT, "www", "includes", "https_tls.py")).read(),
          "status() reports the notice")
    js = open(os.path.join(ROOT, "www", "scripts", "https-settings.js")).read()
    check("/dismiss-announce" in js and "https-banner" in js and "no-https-redirect" in js,
          "dashboard: banner + dismiss + escape hatch mentioned")
    check('id="https-banner"' in open(os.path.join(ROOT, "www", "index.html")).read(), "index.html: banner element")


def t_package():
    site = open(SITE).read()
    check("include /etc/nginx/snippets/tuxwall-tls[.]conf;" in site, "package site includes the TLS snippet (glob)")
    check(site.index("tuxwall-listen[.]conf") < site.index("tuxwall-tls[.]conf"), "TLS include after the listen include")
    check(not re.search(r"(?m)^\s*listen\s+\S*443", site), "package site itself has no 443 listener")
    conff = open(os.path.join(ROOT, "pkg", "DEBIAN", "conffiles")).read().split()
    check("/etc/systemd/system/tuxwall-tls-renew.timer" in conff and
          "/etc/systemd/system/tuxwall-tls-renew.service" in conff, "renewal units are conffiles")
    check("/etc/nginx/snippets/tuxwall-tls.conf" not in conff, "generated snippet is not a conffile")
    ctl = open(os.path.join(ROOT, "pkg", "DEBIAN", "control")).read()
    check(re.search(r"(?m)^Depends:.*\bopenssl\b", ctl), "Depends: openssl")
    w = os.path.join(ROOT, "pkg", "usr", "local", "sbin", "tuxwall-tls")
    check(os.access(w, os.X_OK) and "/var/www/html/includes/https_tls.py" in open(w).read(),
          "tuxwall-tls wrapper: executable, runs the shared module")
    svc = open(os.path.join(ROOT, "pkg", "etc", "systemd", "system", "tuxwall-tls-renew.service")).read()
    tmr = open(os.path.join(ROOT, "pkg", "etc", "systemd", "system", "tuxwall-tls-renew.timer")).read()
    check("ExecStart=/usr/local/sbin/tuxwall-tls refresh --reload" in svc and "Type=oneshot" in svc,
          "renewal service: refresh --reload")
    check("OnCalendar=daily" in tmr and "Persistent=true" in tmr and "OnBootSec=" in tmr, "renewal timer: daily + boot")
    postrm = open(os.path.join(ROOT, "pkg", "DEBIAN", "postrm")).read()
    check("rm -f /etc/nginx/snippets/tuxwall-tls.conf" in postrm, "purge removes the generated snippet")
    inst = open(os.path.join(ROOT, "tuxwall-install.sh")).read()
    check("port 443 proto tcp comment 'TuxWall dashboard HTTPS (LAN)'" in inst, "installer opens 443 on the LAN")
    check(inst.index("tuxwall-nginx-listen ||") < inst.index("tuxwall-tls refresh ||"),
          "installer: HTTPS refresh after the network is up (step_services)")


def t_fw_guard():
    d = tempfile.mkdtemp(prefix="https-guard-")
    try:
        ctx = G.Ctx(root=d, client_ip="192.168.1.50", client_iface="enp2s0", client_dst="192.168.1.1")
        check(ctx.dashboard_ports() == G.DASHBOARD_PORTS, "guard: no snippet -> 80 or 443")
        write(d + "/etc/nginx/snippets/tuxwall-tls.conf",
              H.render_snippet(H.Env(nginx_version="1.28.0"), dec(), dict(H.SETTINGS_DEFAULT)))
        check(G.Ctx(root=d, client_ip="192.168.1.50", client_iface="enp2s0",
                    client_dst="192.168.1.1").dashboard_ports() == (443,), "guard: redirect on LAN address -> 443")
        check(G.Ctx(root=d, client_ip="fd00:1::50", client_iface="enp2s0",
                    client_dst="fd00:1::1").dashboard_ports() == (443,), "guard: redirect on the ULA -> 443")
        check(G.Ctx(root=d, client_ip="192.168.10.50", client_iface="enp2s0.10",
                    client_dst="192.168.10.1").dashboard_ports() == G.DASHBOARD_PORTS,
              "guard: VLAN address without redirect -> 80 or 443")
        write(d + "/etc/nginx/snippets/tuxwall-tls.conf",
              H.render_snippet(H.Env(nginx_version="1.28.0"), dec(redirect=False), dict(H.SETTINGS_DEFAULT)))
        check(G.Ctx(root=d, client_ip="192.168.1.50", client_iface="enp2s0",
                    client_dst="192.168.1.1").dashboard_ports() == G.DASHBOARD_PORTS, "guard: escape hatch -> 80 or 443")
    finally:
        shutil.rmtree(d)


def t_misc():
    p = H.parse_listen
    check(p(["443", "ssl"])[:2] == ("*", 443) and p(["[::]:443"])[:2] == ("*", 443)
          and p(["0.0.0.0:443"])[:2] == ("*", 443), "listen parse: wildcards")
    check(p(["[FD00:1::1]:443", "ssl"])[:2] == ("fd00:1::1", 443) and p(["192.168.1.1"])[:2] == ("192.168.1.1", 80),
          "listen parse: v6 literal normalised, default port 80")
    check(p(["unix:/run/x.sock"]) is None, "listen parse: unix socket ignored")
    t = H.servers('# c { x\nserver { listen 1.2.3.4:443 "ssl"; location / { root "/var/www/html"; } }\n'
                  'http { server { listen 80; } }')
    check(len(t) == 2 and H._server_info(t[0])["dashboard"], "nginx parser: comments, quotes, nested servers")
    check(H.name_permitted("gw.lan", {"dns": ["lan"], "ip": []}) and not H.name_permitted("evil.com",
                                                                                          {"dns": ["lan"], "ip": []}),
          "name constraints: DNS subtree match")
    check(H.name_permitted("fd00:2::1", {"dns": [], "ip": ["fc00::/7"]})
          and not H.name_permitted("2001:db8::1", {"dns": [], "ip": ["fc00::/7"]}), "name constraints: IPv6 match")
    d = tempfile.mkdtemp(prefix="https-kea-")
    try:
        write(d + "/kea.conf", '// c\n{ "Dhcp4": { "option-data": [ { "name": "domain-name-servers", "data": "x" },\n'
                               '  { "code": 15, "name": "domain-name", "data": "home.arpa" } ] } }\n')
        check(H._kea_domain(H.Env(kea_conf=d + "/kea.conf")) == "home.arpa", "Kea domain-name read")
        s = H.load_settings(H.Env(settings=d + "/none.json"))
        check(s["enabled"] is True and s["redirect"] is True and s["hsts"] is False, "defaults: on, redirect, no HSTS")
        write(d + "/s.json", json.dumps({"enabled": "yes", "hsts": True, "extra_names": ["ok.lan", "bad name"]}))
        s = H.load_settings(H.Env(settings=d + "/s.json"))
        check(s["enabled"] is True and s["hsts"] is True and s["extra_names"] == ["ok.lan"],
              "settings: wrong types ignored, invalid names dropped")
    finally:
        shutil.rmtree(d)
    ipaddress.ip_address("192.0.2.1")


t_misc()
t_render()
t_decide()
t_certs()
t_owner_managed_refresh()
t_transactions()
t_sockets()
t_real_nginx()
t_headers_static()
t_headers_served()
t_postinst()
t_announce()
t_package()
t_fw_guard()
print("https: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
