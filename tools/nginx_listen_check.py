#!/usr/bin/env python3
"""Host-neutral nginx site + generated listen include (sandboxed):

  python3 tools/nginx_listen_check.py

- pkg/etc/nginx/sites-available/tuxwall carries no host addresses and
  includes /etc/nginx/snippets/tuxwall-listen[.]conf (a glob: no error
  while the file does not exist), and keeps the 101m body limit on
  /api/backups/system/upload (backup uploads, like nginx/tuxwall.conf).
- pkg/usr/local/sbin/tuxwall-nginx-listen renders default_server listen
  lines from interfaces.json roles (or detection) and `ip -j addr` fixtures:
  LAN IPv4 + VPN IPv4 + LAN ULA IPv6, only addresses that exist, never the
  WAN, no VLAN/OPT, link-local or global IPv6; the maintainer's router
  renders exactly the 3.3.2 listen lines; addresses an enabled site that
  includes the file already names are not repeated (duplicate listen).
- install: atomic write, nginx -t (fake binary), previous file put back /
  new file removed when the test fails, unchanged content is a no-op.
- real nginx (skipped when not installed): `nginx -t` in a scratch prefix
  (high port, loopback addresses) accepts the neutral site with and
  without the include file, rejects the 3.3.2 hard-coded lines plus the
  include (the duplicate the guard prevents) and accepts the guarded render.
"""
import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "pkg", "etc", "nginx", "sites-available", "tuxwall")
LIMITS = os.path.join(ROOT, "pkg", "etc", "nginx", "conf.d", "tuxwall-limits.conf")
SCRIPT = os.path.join(ROOT, "pkg", "usr", "local", "sbin", "tuxwall-nginx-listen")
sys.dont_write_bytecode = True

loader = importlib.machinery.SourceFileLoader("tuxwall_nginx_listen", SCRIPT)
spec = importlib.util.spec_from_loader("tuxwall_nginx_listen", loader)
nl = importlib.util.module_from_spec(spec)
loader.exec_module(nl)

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


def link(name, *addrs):
    info = []
    for a in addrs:
        local, _, plen = a.partition("/")
        scope = "link" if local.startswith("fe80") else "global"
        info.append({"family": "inet6" if ":" in local else "inet", "local": local,
                     "prefixlen": int(plen or 24), "scope": scope})
    return {"ifname": name, "addr_info": info}


# the maintainer's router (3.3.2 shipped exactly these listen lines)
ROUTER_IP = [
    link("lo", "127.0.0.1/8", "::1/128"),
    link("enp5s0", "203.0.113.209/24", "2001:db8:ffff::1/128", "fe80::1/64"),
    link("eno1"),
    link("enp6s0", "192.168.1.1/24", "2001:db8:1:2534::1/64", "fd00:1::1/64", "fe80::2/64"),
    link("enp6s0.10", "192.168.10.1/24", "fe80::2/64"),
    link("ifb4wan", "fe80::3/64"),
    link("wg0", "10.0.0.1/24", "fd00:2::1/64"),
]
ROUTER_ROLES = {"version": 1, "wan": {"device": "enp5s0"},
                "lan": {"device": "enp6s0", "address": "192.168.1.1/24"},
                "opt": [{"id": "opt1", "device": "enp6s0.10", "address": "192.168.10.1/24"},
                        {"id": "opt2", "device": "eno1", "address": "192.168.2.1/24"}],
                "vpn": [{"id": "wg0", "device": "wg0", "address": "10.0.0.1/24"}]}
LIVE_332 = ["listen 192.168.1.1:80 default_server;", "listen 10.0.0.1:80 default_server;",
            "listen [fd00:1::1]:80 default_server;"]


def t_site_neutral():
    text = open(SITE).read()
    lit = re.findall(r"(?m)^\s*listen\s+(\d+\.\d+\.\d+\.\d+|\[[0-9a-fA-F:]*[0-9a-fA-F][0-9a-fA-F:]*\]):\d+", text)
    check(not lit, "packaged site has no host-specific listen lines (%r)" % lit)
    check("include /etc/nginx/snippets/tuxwall-listen[.]conf;" in text, "packaged site includes the listen file")
    check(re.search(r"(?m)^\s*listen 80 default_server;", text) and
          re.search(r"(?m)^\s*listen \[::\]:80 default_server;", text), "wildcard listeners kept")
    check(re.search(r"location = /api/backups/system/upload \{[^}]*client_max_body_size 101m;", text),
          "packaged site lifts the body limit for backup uploads (101m)")
    conffiles = open(os.path.join(ROOT, "pkg", "DEBIAN", "conffiles")).read().split()
    check("/etc/nginx/snippets/tuxwall-listen.conf" not in conffiles, "generated include is not a conffile")
    check(not os.path.exists(os.path.join(ROOT, "pkg", "etc", "nginx", "snippets")), "include not shipped in pkg/")


def t_render():
    body, lines = nl.render(ROUTER_ROLES, ROUTER_IP, "", set())
    check(lines == LIVE_332, "maintainer's router renders the 3.3.2 lines (%r)" % lines)
    body, lines = nl.render(None, ROUTER_IP, "enp5s0", set())
    check(lines == LIVE_332, "same result by detection without interfaces.json (%r)" % lines)
    check(not any("192.168.10.1" in l or "2001:db8:" in l or "fe80" in l or "203.0.113" in l or "fd00:2::" in l
                  for l in lines), "no VLAN/OPT, global v6, link-local, WAN or VPN v6 address")
    ip = [l for l in ROUTER_IP if l["ifname"] != "wg0"]
    body, lines = nl.render(ROUTER_ROLES, ip, "", set())
    check(lines == [LIVE_332[0], LIVE_332[2]], "VPN address absent -> not rendered (%r)" % lines)
    other = [link("lo", "127.0.0.1/8"), link("ens3", "203.0.113.5/24"), link("ens4", "10.20.0.1/24", "fd12:3::1/64")]
    roles = {"wan": {"device": "ens3"}, "lan": {"device": "ens4"}}
    body, lines = nl.render(roles, other, "", set())
    check(lines == ["listen 10.20.0.1:80 default_server;", "listen [fd12:3::1]:80 default_server;"],
          "another host renders its own addresses (%r)" % lines)
    body, lines = nl.render({"wan": {"device": "ens4"}, "lan": {"device": "ens4"}}, other, "", set())
    check(not lines, "LAN == WAN -> nothing (never a WAN listener)")
    body, lines = nl.render(None, [link("lo", "127.0.0.1/8"), link("ens3", "203.0.113.5/24")], "ens3", set())
    check(not lines and "no LAN/VPN address found" in body, "no LAN -> empty include, wildcard serves")
    body, lines = nl.render(ROUTER_ROLES, ROUTER_IP, "", {"192.168.1.1:80"})
    check(lines == LIVE_332[1:] and "(not repeated): 192.168.1.1:80" in body, "already-named address not repeated")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def fake_nginx(d, rc):
    p = os.path.join(d, "nginx-%d" % rc)
    write(p, "#!/bin/sh\necho 'nginx: [emerg] fake result' >&2\nexit %d\n" % rc)
    os.chmod(p, 0o755)
    return p


def t_install_and_cli():
    d = tempfile.mkdtemp(prefix="nginx-listen-")
    try:
        out = os.path.join(d, "snippets", "tuxwall-listen.conf")
        ipj = os.path.join(d, "ip.json")
        rolej = os.path.join(d, "interfaces.json")
        write(ipj, json.dumps(ROUTER_IP))
        write(rolej, json.dumps(ROUTER_ROLES))
        sites = os.path.join(d, "sites-enabled")
        os.makedirs(sites)
        args = ["--out", out, "--ip-json", ipj, "--interfaces-json", rolej, "--sites-dir", sites]
        rc = nl.main(args + ["--nginx", fake_nginx(d, 1)])
        check(rc == 1 and not os.path.exists(out), "nginx -t fails on a new file -> removed, rc 1")
        rc = nl.main(args + ["--nginx", fake_nginx(d, 0)])
        check(rc == 0 and [l for l in open(out).read().splitlines() if l.startswith("listen")] == LIVE_332,
              "written when nginx -t passes")
        check(oct(os.stat(out).st_mode & 0o777) == "0o644", "include is 0644")
        first = open(out).read()
        write(ipj, json.dumps([l for l in ROUTER_IP if l["ifname"] != "wg0"]))
        rc = nl.main(args + ["--nginx", fake_nginx(d, 1)])
        check(rc == 1 and open(out).read() == first, "nginx -t fails on a change -> previous file restored")
        check(not [f for f in os.listdir(os.path.dirname(out)) if f != "tuxwall-listen.conf"],
              "no temp/backup file left")
        write(ipj, json.dumps(ROUTER_IP))
        rc = nl.main(args + ["--nginx", "/nonexistent/nginx"])
        check(rc == 0 and open(out).read() == first, "unchanged content: no write, no nginx -t needed")
        # an enabled site that includes the file and still hard-codes an address
        write(os.path.join(sites, "tuxwall"), "server {\n    listen 80 default_server;\n"
              "    listen 10.0.0.1:80 default_server;\n    include /etc/nginx/snippets/tuxwall-listen[.]conf;\n}\n")
        rc = nl.main(args + ["--nginx", fake_nginx(d, 0)])
        got = [l for l in open(out).read().splitlines() if l.startswith("listen")]
        check(rc == 0 and got == [LIVE_332[0], LIVE_332[2]], "guard: site's own 10.0.0.1 line not repeated (%r)" % got)
        p = subprocess.run([sys.executable, SCRIPT, "--print", "--ip-json", ipj, "--interfaces-json", rolej,
                            "--sites-dir", os.path.join(d, "none")], capture_output=True, text=True)
        check(p.returncode == 0 and [l for l in p.stdout.splitlines() if l.startswith("listen")] == LIVE_332,
              "CLI --print")
    finally:
        shutil.rmtree(d)


def t_real_nginx():
    nginx = shutil.which("nginx") or ("/usr/sbin/nginx" if os.path.exists("/usr/sbin/nginx") else None)
    if not nginx:
        print("SKIP: nginx not installed - real nginx -t cases")
        return
    d = tempfile.mkdtemp(prefix="nginx-scratch-")
    try:
        port = 18000 + os.getpid() % 1000
        snippet = os.path.join(d, "tuxwall-listen.conf")

        def site(text):
            text = text.replace("/etc/nginx/snippets/tuxwall-listen[.]conf", os.path.join(d, "tuxwall-listen[.]conf"))
            return text.replace("listen 80 ", "listen %d " % port).replace("listen [::]:80 ", "listen [::]:%d " % port)

        def local(lines):
            # loopback stand-ins (bindable anywhere), same structure
            m = {"192.168.1.1": "127.0.0.2", "10.0.0.1": "127.0.0.3", "[fd00:1::1]": "[::1]"}
            out = []
            for l in lines:
                for k, v in m.items():
                    l = l.replace(k + ":80", "%s:%d" % (v, port))
                out.append(l)
            return out

        def run(site_text):
            write(os.path.join(d, "site.conf"), site_text)
            write(os.path.join(d, "nginx.conf"),
                  "pid %s/nginx.pid;\nerror_log stderr;\nevents {}\nhttp {\n  access_log off;\n"
                  "  include /etc/nginx/mime.types;\n  include %s;\n  include %s/site.conf;\n}\n" % (d, LIMITS, d))
            p = subprocess.run([nginx, "-e", "stderr", "-p", d + "/", "-c", d + "/nginx.conf", "-t"],
                               capture_output=True, text=True, timeout=30)
            return p.returncode, p.stderr

        neutral = open(SITE).read()
        if not os.path.exists("/etc/nginx/mime.types"):
            print("SKIP: /etc/nginx/mime.types missing - real nginx -t cases")
            return
        rc, err = run(site(neutral))
        check(rc == 0, "nginx -t: neutral site, no include file yet (%s)" % err.strip()[-200:])
        write(snippet, "\n".join(local(LIVE_332)) + "\n")
        rc, err = run(site(neutral))
        check(rc == 0, "nginx -t: neutral site + rendered include (%s)" % err.strip()[-200:])
        old = neutral.replace("    include /etc/nginx/snippets/tuxwall-listen[.]conf;\n",
                              "".join("    %s\n" % l for l in LIVE_332) +
                              "    include /etc/nginx/snippets/tuxwall-listen[.]conf;\n")
        rc, err = run(site(old).replace("192.168.1.1:80", "127.0.0.2:%d" % port)
                      .replace("10.0.0.1:80", "127.0.0.3:%d" % port).replace("[fd00:1::1]:80", "[::1]:%d" % port))
        check(rc != 0 and "duplicate" in err, "nginx -t: 3.3.2 lines + include = duplicate listen (%s)"
              % err.strip()[-120:])
        taken = {"127.0.0.2:%d" % port, "127.0.0.3:%d" % port, "[::1]:%d" % port}
        guarded = [l for l in local(LIVE_332) if l.split()[1] not in taken]
        write(snippet, "\n".join(guarded) + "\n")
        rc, err = run(site(old).replace("192.168.1.1:80", "127.0.0.2:%d" % port)
                      .replace("10.0.0.1:80", "127.0.0.3:%d" % port).replace("[fd00:1::1]:80", "[::1]:%d" % port))
        check(rc == 0, "nginx -t: guarded render next to hard-coded lines (%s)" % err.strip()[-200:])
    finally:
        shutil.rmtree(d)


t_site_neutral()
t_render()
t_install_and_cli()
t_real_nginx()
print("nginx listen: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
