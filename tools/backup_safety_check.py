#!/usr/bin/env python3
"""Backup safety checks for www/includes/backups.py: catalog vs the backup
script, item sizes, retention, persisted job state + failure incident,
sanitized export (a synthetic archive containing every known leak type),
archive limits, uploads, and the hardened single-file restore - all in a
temp root.

  python3 tools/backup_safety_check.py          pure tests (CI)
  sudo python3 tools/backup_safety_check.py --live
        also sanitizes the newest real system backup IN MEMORY (nothing is
        written) and asserts that no secret value from it survives. Prints
        counts and file names only, never values. --archive PATH picks the
        archive instead of the newest one.
"""
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(REPO, "www", "includes"))
sys.dont_write_bytecode = True

import backups as B  # noqa: E402

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


def raises(fn, exc=Exception):
    try:
        fn()
    except exc as e:
        return e
    return None


def mktar(path_or_buf, members):
    """members: list of (name, bytes | None for dir | ('sym', target) | ('dev',))."""
    kw = {"fileobj": path_or_buf} if hasattr(path_or_buf, "write") else {"name": path_or_buf}
    with tarfile.open(mode="w:gz", **kw) as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.mtime = int(time.time())
            if data is None:
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                t.addfile(ti)
            elif isinstance(data, tuple) and data[0] == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = data[1]
                t.addfile(ti)
            elif isinstance(data, tuple) and data[0] == "dev":
                ti.type = tarfile.CHRTYPE
                t.addfile(ti)
            else:
                ti.size = len(data)
                ti.mode = 0o755 if name.lstrip("./").startswith("usr/local/") else 0o644
                t.addfile(ti, io.BytesIO(data))


# ── 1. catalog vs system-backup.sh ──────────────────────────────────────────
def t_catalog():
    script = open(os.path.join(REPO, "pkg", "usr", "local", "sbin", "system-backup.sh")).read()
    arcs = set(re.findall(r'^\s*"[^"|]+\|([^"]+)"\s*$', script, re.M))
    for item in B.ITEMS:
        check(item["arc"] in arcs, "catalog item %s is captured by system-backup.sh" % item["arc"])
        check(item["path"] == "/" + item["arc"], "catalog path matches arc for %s" % item["arc"])
    check(len({i["arc"] for i in B.ITEMS}) == len(B.ITEMS), "catalog arcs are unique")

    def arr(name):
        m = re.search(r"^%s=\(([^)]*)\)" % name, script, re.M)
        return tuple(re.findall(r'"([^"]+)"', m.group(1))) if m else None
    check(arr("WWW_EXCLUDE") == B.WWW_EXCLUDE, "script WWW_EXCLUDE matches backups.WWW_EXCLUDE")
    check(arr("CROWDSEC_EXCLUDE") == B.CROWDSEC_EXCLUDE, "script CROWDSEC_EXCLUDE matches")
    check(arr("TUXWALL_STATE_ONLY") == B.TUXWALL_STATE_ONLY, "script TUXWALL_STATE_ONLY matches")
    check("-name __pycache__ -exec rm -rf" in script, "script prunes __pycache__ everywhere")
    check("chmod 600" in script and "umask 077" in script, "script keeps archives private")
    check("refusing unsafe output directory" in script, "script keeps the output-dir safety check")


# ── 2. item sizes ───────────────────────────────────────────────────────────
def t_sizes(root):
    www = os.path.join(root, "var/www/html")
    os.makedirs(os.path.join(www, "includes/__pycache__"))
    os.makedirs(os.path.join(www, "logs"))
    open(os.path.join(www, "index.html"), "wb").write(b"x" * 100)
    open(os.path.join(www, "includes/__pycache__/a.pyc"), "wb").write(b"x" * 5000)
    open(os.path.join(www, "logs/server.log"), "wb").write(b"x" * 7000)
    open(os.path.join(www, "index.html.bak-1"), "wb").write(b"x" * 9000)
    big = os.path.join(root, "bigbinary")
    open(big, "wb").write(b"x" * 50000)
    os.makedirs(os.path.join(root, "usr/local/bin"))
    os.symlink(big, os.path.join(root, "usr/local/bin/tool"))
    open(os.path.join(root, "usr/local/bin/script"), "wb").write(b"y" * 10)
    os.makedirs(os.path.join(root, "usr/local/bin/__pycache__"))
    open(os.path.join(root, "usr/local/bin/__pycache__/x.pyc"), "wb").write(b"y" * 999)
    st = os.path.join(root, "var/lib/tuxwall")
    os.makedirs(os.path.join(st, "fw-snapshots/x"))
    open(os.path.join(st, "fw-snapshots/x/a"), "wb").write(b"z" * 30)
    open(os.path.join(st, "dbip-city-lite.mmdb"), "wb").write(b"z" * 90000)
    open(os.path.join(st, "wireguard.json"), "wb").write(b"{}")
    sizes = {i["arc"]: i for i in B.items_listing(root)}
    check(sizes["var/www/html"]["size"] == 100, "www size excludes pycache/logs/.bak (%d)" % sizes["var/www/html"]["size"])
    check(sizes["usr/local/bin"]["size"] == 10, "symlinks are not followed in size estimates")
    check(sizes["var/lib/tuxwall"]["size"] == 32, "state size counts only the captured files")
    check(sizes["etc/kea"]["exists"] is False, "missing item reported as not present")


# ── 3. retention ────────────────────────────────────────────────────────────
def name_at(ts):
    return "system-backup-%s.tar.gz" % time.strftime("%Y%m%d-%H%M%S", time.localtime(ts))


def t_retention(root):
    now = time.mktime((2026, 11, 18, 3, 30, 0, 0, 0, -1))
    daily = [name_at(now - d * 86400) for d in range(0, 200)]
    plan = B.retention_plan(daily)
    keep = plan["keep"]
    check(daily[0] in keep and "newest" in keep[daily[0]], "newest kept")
    days = [n for n, r in keep.items() if "daily" in r]
    weeks = [n for n, r in keep.items() if "weekly" in r]
    months = [n for n, r in keep.items() if "monthly" in r]
    check(len(days) == 7 and len(weeks) == 4 and len(months) == 3, "7 daily / 4 weekly / 3 monthly")
    check(len(keep) <= 14 and len(keep) + len(plan["delete"]) == 200, "everything else deleted (%d kept)" % len(keep))
    two = [name_at(now - 400 * 86400), name_at(now - 800 * 86400)]
    check(not B.retention_plan(two)["delete"], "old sparse backups are not deleted by age alone")
    check(not B.retention_plan([daily[150]])["delete"], "a single backup is never deleted")
    p = B.retention_plan(daily, pinned=[daily[199]])
    check(daily[199] in p["keep"] and daily[199] not in p["delete"], "pinned backup kept")
    same_day = [name_at(now - h * 3600) for h in range(0, 3)]
    sp = B.retention_plan(same_day)
    check(same_day[0] in sp["keep"] and len(sp["delete"]) == 2, "several on one day: newest of the day kept")
    check(not B.retention_plan(daily, policy={"daily": 0, "weekly": 0, "monthly": 0})["delete"].count(daily[0]),
          "newest kept even with an empty policy")
    # prune on disk
    d = os.path.join(root, B.SYSTEM_DIR.lstrip("/"))
    os.makedirs(d, exist_ok=True)
    for n in daily[:30]:
        open(os.path.join(d, n), "wb").write(b"x")
    open(os.path.join(d, "sanitized-20260101-000000.tar.gz"), "wb").write(b"x")
    B.set_pinned(root, daily[29], True)
    removed = B.prune_system(root)
    left = sorted(n for n in os.listdir(d) if B.SYSTEM_RE.match(n))
    check(daily[29] in left and daily[0] in left, "prune keeps pinned + newest")
    check(len(removed) == 30 - len(left) and len(left) <= 12, "prune removes the rest (%d left)" % len(left))
    check(os.path.exists(os.path.join(d, "sanitized-20260101-000000.tar.gz")), "prune leaves other archive kinds")
    for n in os.listdir(d):
        os.remove(os.path.join(d, n))
    for i in range(5):
        open(os.path.join(d, "sanitized-2026010%d-000000.tar.gz" % (i + 1)), "wb").write(b"x")
    B.prune_simple(root, B.SANITIZED_RE, B.SANITIZED_KEEP)
    check(len(os.listdir(d)) == B.SANITIZED_KEEP, "sanitized exports keep their own limit")
    for n in os.listdir(d):
        os.remove(os.path.join(d, n))


# ── 4. sanitizer: synthetic archive with every leak type ────────────────────
SECRETS = {}


def sv(tag):
    v = "SeCrEt%s%s" % (tag, "Q7x9Zk2Lm4Np8Rt")
    SECRETS[tag] = v
    return v


def pem_block(kind="OPENSSH "):
    body = sv("pem" + kind.strip().lower() or "pem")
    return ("-----BEGIN %sPRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB%s\n"
            "AAAAMwAAAAtzc2gtZWQyNTUxOQAAACD\n-----END %sPRIVATE KEY-----\n" % (kind, body, kind))


def synthetic_members():
    plugin_manifest = json.dumps({"id": "openwrt", "config": [
        {"key": "hosts", "type": "text"}, {"key": "ssh_key", "type": "password", "secret": True},
        {"key": "password", "type": "password", "secret": True},
        {"key": "apcode", "type": "text", "secret": True}]}).encode()
    plugin_cfg = json.dumps({"hosts": "192.168.1.43", "username": "root", "auth_mode": "key",
                             "ssh_key": pem_block(), "password": sv("plugpw"),
                             "apcode": sv("plugcustom"), "enabled": True}).encode()
    return [
        ("./etc/tuxwall/", None),
        ("./etc/tuxwall/internal-token", sv("internal").encode()),
        ("./etc/tuxwall/agent-token", sv("agenttok").encode()),
        ("./etc/tuxwall/auth.json", json.dumps({"users": [{"name": "a", "hash": sv("authhash")}]}).encode()),
        ("./etc/tuxwall/llm.json", json.dumps({"api_key": sv("llm")}).encode()),
        ("./etc/tuxwall/agent/api.token", sv("apitoken").encode()),
        ("./etc/tuxwall/agent/keys/unsloth.key", sv("unsloth").encode()),
        ("./etc/tuxwall/opencode.json", json.dumps({"providers": {"x": {"settings": {
            "apiKey": sv("opencodekey"), "baseURL": "http://192.168.1.5:8000/v1"}},
            "y": {"settings": {"apiKey": "{file:/etc/tuxwall/agent/keys/y.key}"}}}}).encode()),
        ("./etc/tuxwall/opencode.json.bak", json.dumps({"apiKey": sv("opencodebak")}).encode()),
        ("./etc/tuxwall/alerts.json", json.dumps({"enabled": True, "ntfy_url": "https://ntfy.sh/" + sv("ntfy"),
                                                  "webhook_url": "https://hooks.example/" + sv("hook"),
                                                  "min_severity": "warning"}).encode()),
        ("./etc/tuxwall/reporting.json", json.dumps({"enabled": True, "url": "https://r.example",
                                                     "key": sv("reportkey")}).encode()),
        ("./etc/tuxwall/plugins/openwrt/plugin.json", plugin_manifest),
        ("./etc/tuxwall/plugins/openwrt/config.json", plugin_cfg),
        ("./etc/tuxwall/plugins/broken/config.json", ('{"token": "%s", ' % sv("brokenjson")).encode()),
        ("./etc/tuxwall/sqm.conf", b"WAN=enp5s0\nUP_RATE=285mbit\n"),
        ("./etc/cloudflared/token", sv("cftoken").encode()),
        ("./etc/cloudflared/cert.pem", pem_block("").encode()),
        ("./etc/cloudflared/abc.json", json.dumps({"TunnelSecret": sv("cfjson")}).encode()),
        ("./etc/cloudflared/config.yml", ("tunnel: x\ncredentials-file: /etc/cloudflared/abc.json\n"
                                          "token: %s\n" % sv("cfyml")).encode()),
        ("./etc/crowdsec/local_api_credentials.yaml", ("url: http://127.0.0.1:8080\nlogin: x\npassword: %s\n"
                                                       % sv("lapi")).encode()),
        ("./etc/crowdsec/notifications/email.yaml", (
            "type: email\nsmtp_host: smtp.example\n"
            "smtp_password: %s\n"
            "smtp_username: me # and   smtp_password: %s\n"
            "# smtp_password: # Replace with your actual password\n"
            "inline: {user: a, password: %s}\n" % (sv("smtp"), sv("smtpmid"), sv("smtpflow"))).encode()),
        ("./etc/crowdsec/config.yaml", ("api:\n  server:\n    online_client:\n      credentials_path: "
                                        "/etc/crowdsec/online_api_credentials.yaml\n").encode()),
        ("./etc/wireguard/wg0.conf", ("[Interface]\nAddress = 10.8.0.1/24\nPrivateKey = %s\nListenPort = 51820\n\n"
                                      "[Peer]\nPublicKey = pubkeyAAAA=\nPresharedKey=%s\nAllowedIPs = 10.8.0.2/32\n"
                                      % (sv("wgpriv"), sv("wgpsk"))).encode()),
        ("./etc/wireguard/privatekey", sv("wgfile").encode()),
        ("./etc/kea/kea-dhcp4.conf", ('// comment\n{"Dhcp4": {"control-socket": {"secret": "%s"}, '
                                      '"valid-lifetime": 4000}}\n' % sv("kea")).encode()),
        ("./etc/systemd/system/foo.service", ("[Service]\nEnvironment=FOO_TOKEN=%s\n"
                                              "Environment=\"BAR_API_KEY=%s\" \"PLAIN=1\"\n"
                                              "ExecStart=/usr/bin/foo --no-x --token %s --password=%s "
                                              "--token-file /etc/foo/token\n"
                                              % (sv("envtok"), sv("envkey"), sv("flagtok"), sv("flagpw"))).encode()),
        ("./etc/nginx/ssl/site.pem", ("-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n"
                                      + pem_block("RSA ")).encode()),
        ("./etc/nginx/conf.d/up.conf", ("upstream x { server 1.2.3.4; }\n# mid-line: foo=1 password=%s bar=2\n"
                                        "proxy_pass https://user:%s@backend.example/;\n"
                                        % (sv("midline"), sv("urlcred"))).encode()),
        ("./etc/ssh/ssh_host_ed25519_key", pem_block().replace("OPENSSH", "OPENSSH").encode()),
        ("./etc/ssh/ssh_host_ed25519_key.pub", b"ssh-ed25519 AAAAC3Nza host\n"),
        ("./etc/ssh/sshd_config", b"PasswordAuthentication no\nPort 22\n"),
        ("./etc/letsencrypt/accounts/acme/x/private_key.json", json.dumps({"n": "abc", "d": sv("jwkd")}).encode()),
        ("./etc/letsencrypt/cloudflare.ini", ("dns_cloudflare_api_token = %s\n" % sv("lecf")).encode()),
        ("./etc/letsencrypt/live/site/privkey.pem", pem_block("EC ").encode()),
        ("./etc/letsencrypt/renewal/site.conf", b"account = abc\nauthenticator = dns-cloudflare\n"),
        ("./etc/other/random.json", json.dumps({"note": "x", "blob": pem_block("")}).encode()),
        ("./usr/local/sbin/tuxwall-thing", ("#!/bin/bash\nAPI_TOKEN=%s\nTOKEN_FILE=/etc/tuxwall/agent-token\n"
                                            "PASS=$1\nPASSWORD=\"%s\"\n" % (sv("shtok"), sv("shpw"))).encode()),
        ("./usr/local/bin/helper.py", ("#!/usr/bin/env python3\npassword = body.get('password')\n"
                                       "API_KEY = \"%s\"\n" % sv("pylit")).encode()),
        ("./usr/local/bin/blob", b"\x7fELF\x00\x00" + pem_block().encode() + b"\x00"),
        ("./usr/local/bin/cloudflared", ("sym", "/usr/bin/cloudflared")),
        ("./var/lib/tuxwall/wireguard.json", json.dumps({"server": {"private_key": sv("wgjson"), "public_key": "pub="},
                                                         "peers": [{"name": "p", "private_key": sv("wgpeer"),
                                                                    "public_key": "pp="}]}).encode()),
        ("./var/lib/tuxwall/canary-token", sv("canary").encode()),
        ("./var/lib/tuxwall/whitelist.json", b'["1.2.3.4"]'),
        ("./var/lib/kea/kea-leases4.csv", b"address,hwaddr\n192.168.1.9,aa:bb\n"),
        ("./var/www/html/includes/api_server.py", b"token = secrets.token_hex(16)\n"),
        ("./iptables-save.txt", b"*filter\n:INPUT DROP [0:0]\n-A INPUT -m comment --comment \"x\" -j ACCEPT\nCOMMIT\n"),
        ("./manifest.txt", b"TuxWall system backup\n"),
        # false-positive guards: these must come through unchanged
        ("./etc/sudoers.d/agent", b"agent ALL=(root) NOPASSWD: /usr/bin/systemctl status *\n"),
        ("./etc/sysctl.d/99-x.conf", b"net.ipv4.tcp_syncookies = 1\n"),
        ("./etc/tuxwall/incidents.json", b'{"items": [{"key": "backup:never", "title": "x"}]}'),
        ("./usr/local/sbin/fp.sh", b"#!/bin/bash\n# Archives hold secrets: nothing is world readable\nset -e\n"),
        ("./etc/letsencrypt/renewal/x.conf", b"dns_cloudflare_credentials = /etc/letsencrypt/cloudflare.ini\n"),
        ("./../escape.txt", sv("traversal").encode()),
    ]


def t_sanitizer(root):
    src = os.path.join(root, "synthetic.tar.gz")
    mktar(src, synthetic_members())
    out = io.BytesIO()
    summary = B.sanitize_archive(src, out, "synthetic.tar.gz")
    data = out.getvalue()
    out.seek(0)
    bad = B.verify_export(io.BytesIO(data))
    check(not bad, "sanitized export passes its own verification (%s)" % bad[:3])
    blob = b""
    names = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for m in t:
            names.append(m.name)
            if m.isreg():
                blob += t.extractfile(m).read() + b"\n"
    for tag, val in SECRETS.items():
        check(val.encode() not in blob, "secret %r does not survive the export" % tag)
    check(b"PRIVATE KEY-----\nb3Bl" not in blob and not B.PEM_BODY_BYTES_RE.search(blob), "no PEM private key body survives")
    keep = {"etc/tuxwall/sqm.conf", "etc/wireguard/wg0.conf", "etc/kea/kea-dhcp4.conf",
            "etc/crowdsec/notifications/email.yaml", "etc/tuxwall/plugins/openwrt/config.json",
            "etc/systemd/system/foo.service", "etc/ssh/sshd_config", "etc/ssh/ssh_host_ed25519_key.pub",
            "var/lib/tuxwall/wireguard.json", "iptables-save.txt", "SANITIZED.txt",
            "etc/letsencrypt/renewal/site.conf", "usr/local/bin/cloudflared", "etc/tuxwall/opencode.json"}
    for k in keep:
        check(k in names, "non-secret config kept: %s" % k)
    for gone in ("var/www/html/includes/api_server.py", "var/lib/kea/kea-leases4.csv", "usr/local/bin/blob",
                 "etc/tuxwall/internal-token", "etc/tuxwall/agent-token", "etc/cloudflared/token",
                 "etc/ssh/ssh_host_ed25519_key", "etc/letsencrypt/accounts/acme/x/private_key.json"):
        check(gone not in names, "not in export: %s" % gone)
    check(not any(".." in n for n in names), "traversal member never exported")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        wg = t.extractfile("etc/wireguard/wg0.conf").read().decode()
        email = t.extractfile("etc/crowdsec/notifications/email.yaml").read().decode()
        oc = json.loads(t.extractfile("etc/tuxwall/opencode.json").read())
        sh = t.extractfile("usr/local/sbin/tuxwall-thing").read().decode()
        py = t.extractfile("usr/local/bin/helper.py").read().decode()
        svc = t.extractfile("etc/systemd/system/foo.service").read().decode()
        man = json.loads(t.extractfile("etc/tuxwall/plugins/openwrt/plugin.json").read())
    check("PublicKey = pubkeyAAAA=" in wg and "PrivateKey = <REDACTED>" in wg, "wg0.conf: private redacted, public kept")
    check("# smtp_password: # Replace with your actual password" in email, "placeholder comment line untouched")
    check(oc["providers"]["y"]["settings"]["apiKey"].startswith("{file:"), "{file:...} key references kept")
    check([f["key"] for f in man["config"]] == ["hosts", "ssh_key", "password", "apcode"],
          "plugin manifest field names are kept (schema 'key' is not a credential)")
    check("PASS=$1" in sh and "TOKEN_FILE=/etc/tuxwall/agent-token" in sh, "shell expressions / *_FILE paths kept")
    check("password = body.get('password')" in py, "code expressions are not mangled")
    check("--token-file /etc/foo/token" in svc and '"PLAIN=1"' in svc, "non-secret flags and env kept")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        same = {n: t.extractfile(n).read() for n in ("etc/sudoers.d/agent", "etc/sysctl.d/99-x.conf",
                                                       "usr/local/sbin/fp.sh", "etc/letsencrypt/renewal/x.conf")}
        inc = json.loads(t.extractfile("etc/tuxwall/incidents.json").read())
    src_map = dict((n.lstrip("./"), d) for n, d in synthetic_members() if isinstance(d, bytes))
    for n, d in same.items():
        check(d == src_map[n], "no false-positive redaction in %s" % n)
    check(inc["items"][0]["key"] == "backup:never", "plain 'key' fields that are not credentials are kept")
    check(summary["redacted"] > 10 and len(summary["dropped"]) >= 10,
          "summary counts (%d redacted, %d dropped)" % (summary["redacted"], len(summary["dropped"])))
    # verify_export must flag an unsanitized archive (the fail-closed check works)
    check(len(B.verify_export(src)) >= 10, "verify_export flags a raw archive")
    # sanitize_to_dir writes 0600, verified, pruned, audited
    d = os.path.join(root, B.SYSTEM_DIR.lstrip("/"))
    os.makedirs(d, exist_ok=True)
    res = B.sanitize_to_dir(root, src, "synthetic.tar.gz", who="tester")
    p = os.path.join(d, res["name"])
    check(os.path.isfile(p) and stat.S_IMODE(os.stat(p).st_mode) == 0o600, "export file is 0600")
    check(not [n for n in os.listdir(d) if n.endswith(".partial")], "no partial export left behind")
    os.remove(p)


def t_sanitizer_failclosed(root):
    # a member the redactor cannot clean must be dropped, never exported
    weird = "-----BEGIN PRIVATE KEY-----\n" + "A" * 64 + "\n(no end marker)\n"
    res = B.sanitize_member("etc/x/weird.conf", weird.encode())
    check(res[0] == "drop", "unterminated private key block -> file dropped")
    res = B.sanitize_member("etc/x/ok.conf", b"a = 1\n")
    check(res[0] == "keep" and res[2] == 0, "clean file kept unchanged")


# ── 5. archive limits + uploads ─────────────────────────────────────────────
def t_limits(root):
    p = os.path.join(root, "many.tar.gz")
    mktar(p, [("etc/x%d" % i, b"a") for i in range(50)])
    check(raises(lambda: B.check_archive(p, max_members=10), ValueError), "member-count limit")
    p2 = os.path.join(root, "big.tar.gz")
    mktar(p2, [("etc/big", b"\0" * 300000)])
    check(raises(lambda: B.check_archive(p2, max_total=100000), ValueError), "decompressed-size limit")
    check(raises(lambda: B.check_archive(p2, max_member=1000), ValueError), "member-size limit")
    p3 = os.path.join(root, "trav.tar.gz")
    mktar(p3, [("../../etc/passwd", b"x")])
    check(raises(lambda: B.check_archive(p3, strict=True), ValueError), "upload with traversal rejected")
    p4 = os.path.join(root, "dev.tar.gz")
    mktar(p4, [("etc/x", b"x"), ("etc/dev", ("dev",))])
    check(raises(lambda: B.check_archive(p4, strict=True), ValueError), "upload with a device member rejected")
    check(B.check_archive(p)["members"] == 50, "normal archive passes")
    check(raises(lambda: B.store_upload(root, b"not a gzip" * 20), ValueError), "non-gzip upload rejected")
    buf = io.BytesIO()
    mktar(buf, [("etc/hosts", b"127.0.0.1 localhost\n")])
    d = os.path.join(root, B.SYSTEM_DIR.lstrip("/"))
    names = []
    for i in range(3):
        r = B.store_upload(root, buf.getvalue(), who="tester")
        names.append(r["name"])
        time.sleep(1.05)
    ups = sorted(n for n in os.listdir(d) if B.UPLOADED_RE.match(n))
    check(len(ups) == B.UPLOADED_KEEP and ups[-1] == names[-1], "uploads keep their own limit")
    check(stat.S_IMODE(os.stat(os.path.join(d, ups[-1])).st_mode) == 0o600, "upload stored 0600")
    for n in ups:
        os.remove(os.path.join(d, n))
    fd, tp = B.mkstemp_private(root, prefix="t-")
    os.close(fd)
    check(stat.S_IMODE(os.stat(os.path.dirname(tp)).st_mode) == 0o700 and
          stat.S_IMODE(os.stat(tp).st_mode) == 0o600, "mkstemp_private: 0700 dir, 0600 file")
    check(re.search(r"t-[0-9a-f]{16}$", tp) is not None, "temp names are unpredictable")
    os.remove(tp)


# ── 6. restore ──────────────────────────────────────────────────────────────
def t_restore(root):
    live = os.path.join(root, "live")
    os.makedirs(os.path.join(live, "etc/tuxwall"))
    os.makedirs(os.path.join(live, "etc/kea"))
    os.makedirs(os.path.join(live, "usr/local/bin"))
    os.makedirs(os.path.join(live, "real"))
    os.symlink(os.path.join(live, "real"), os.path.join(live, "etc/linked"))
    open(os.path.join(live, "real/target"), "w").write("keep me\n")
    os.symlink(os.path.join(live, "real/target"), os.path.join(live, "etc/kea/link.conf"))
    kea = os.path.join(live, "etc/kea/kea-dhcp4.conf")
    open(kea, "w").write("line1\nold\n")
    os.chmod(kea, 0o640)
    arch = os.path.join(root, "rs.tar.gz")
    marker = "CONTENTMARKER-7781"
    mktar(arch, [("./etc/tuxwall/.bk-test", ("hello %s\n" % marker).encode()),
                 ("./etc/kea/kea-dhcp4.conf", b"line1\nnew\n"),
                 ("./etc/kea/link.conf", b"evil\n"),
                 ("./etc/linked/x.conf", b"evil\n"),
                 ("./etc/new/dir/file.conf", b"x\n"),
                 ("./usr/local/bin/tool", b"#!/bin/sh\necho hi\n"),
                 ("./iptables-save.txt", b"*filter\nCOMMIT\n"),
                 ("./etc/ufw/user.rules", b"*filter\n### RULES ###\nCOMMIT\n"),
                 ("./manifest.txt", b"m\n")])
    pv = B.restore_preview(live, arch, "rs.tar.gz", "etc/tuxwall/.bk-test")
    check(pv["kind"] == "new" and pv["perms"]["mode"] == "0600", "new file under etc/tuxwall -> 0600")
    check(pv["old_sha256"] == "absent" and "+hello" in pv["diff"], "new-file preview shows content")
    e = raises(lambda: B.restore_apply(live, arch, "rs.tar.gz", "etc/tuxwall/.bk-test", who="t"), B.Refused)
    check(e is not None and "Preview" in e.payload["error"], "apply without preview hashes refused")
    r = B.restore_apply(live, arch, "rs.tar.gz", "etc/tuxwall/.bk-test", who="tester", client="1.2.3.4",
                        expect_new=pv["new_sha256"], expect_old=pv["old_sha256"])
    tp = os.path.join(live, "etc/tuxwall/.bk-test")
    check(open(tp).read() == "hello %s\n" % marker and stat.S_IMODE(os.stat(tp).st_mode) == 0o600,
          "new file written with 0600")
    check(r["pre_restore"] is None and r["created"], "no pre-restore copy for a new file")
    pv = B.restore_preview(live, arch, "rs.tar.gz", "etc/kea/kea-dhcp4.conf")
    check(pv["kind"] == "modified" and "-old" in pv["diff"] and "+new" in pv["diff"], "modified file diff")
    check(pv["perms"]["mode"] == "0640", "live mode is kept")
    open(kea, "a").write("changed\n")
    e = raises(lambda: B.restore_apply(live, arch, "rs.tar.gz", "etc/kea/kea-dhcp4.conf",
                                       expect_new=pv["new_sha256"], expect_old=pv["old_sha256"]), B.Refused)
    check(e is not None and "changed since" in e.payload["error"], "live changed since preview -> refused")
    pv = B.restore_preview(live, arch, "rs.tar.gz", "etc/kea/kea-dhcp4.conf")
    r = B.restore_apply(live, arch, "rs.tar.gz", "etc/kea/kea-dhcp4.conf", who="tester",
                        expect_new=pv["new_sha256"], expect_old=pv["old_sha256"])
    check(open(kea).read() == "line1\nnew\n" and stat.S_IMODE(os.stat(kea).st_mode) == 0o640, "restored atomically, mode kept")
    pre = os.path.join(live, r["pre_restore"].lstrip("/"))
    check(os.path.isfile(pre) and open(pre).read() == "line1\nold\nchanged\n", "pre-restore copy holds the old file")
    check("/var/lib/tuxwall/backups/pre-restore/" in r["pre_restore"], "pre-restore copy is not next to the live file")
    check(not [n for n in os.listdir(os.path.join(live, "etc/kea")) if "bak" in n or "tuxwall-restore" in n],
          "no .bak / temp files left in the live dir")
    e = raises(lambda: B.restore_preview(live, arch, "rs.tar.gz", "etc/kea/link.conf"), B.Refused)
    check(e is not None and "symlink" in e.payload["error"], "symlinked target refused")
    check(open(os.path.join(live, "real/target")).read() == "keep me\n", "symlink target untouched")
    e = raises(lambda: B.restore_preview(live, arch, "rs.tar.gz", "etc/linked/x.conf"), B.Refused)
    check(e is not None and "symlink" in e.payload["error"], "symlinked parent directory refused")
    pv = B.restore_preview(live, arch, "rs.tar.gz", "etc/new/dir/file.conf")
    check(pv["kind"] == "new" and pv.get("creates_dirs"), "missing directories reported")
    B.restore_apply(live, arch, "rs.tar.gz", "etc/new/dir/file.conf", expect_new=pv["new_sha256"],
                    expect_old="absent")
    check(os.path.isfile(os.path.join(live, "etc/new/dir/file.conf")), "missing directories created")
    pv = B.restore_preview(live, arch, "rs.tar.gz", "usr/local/bin/tool")
    check(pv["strict"] and pv["perms"]["mode"] == "0755", "usr/local is strict; exec bit kept for new scripts")
    e = raises(lambda: B.restore_apply(live, arch, "rs.tar.gz", "usr/local/bin/tool",
                                       expect_new=pv["new_sha256"], expect_old="absent"), B.Refused)
    check(e is not None and e.payload.get("strict"), "strict path needs the second confirm")
    B.restore_apply(live, arch, "rs.tar.gz", "usr/local/bin/tool", confirm_strict=True,
                    expect_new=pv["new_sha256"], expect_old="absent")
    check(os.access(os.path.join(live, "usr/local/bin/tool"), os.X_OK), "strict restore with confirm works")
    for fw in ("iptables-save.txt", "etc/ufw/user.rules"):
        pv = B.restore_preview(live, arch, "rs.tar.gz", fw)
        check(pv["firewall"] and not pv["restorable"], "%s previewed as firewall (no raw restore)" % fw)
        e = raises(lambda: B.restore_apply(live, arch, "rs.tar.gz", fw, confirm_strict=True,
                                           expect_new=pv["new_sha256"], expect_old="absent"), B.Refused)
        check(e is not None and e.payload.get("firewall"), "%s raw restore refused" % fw)
    e = raises(lambda: B.restore_apply(live, arch, "rs.tar.gz", "manifest.txt"), B.Refused)
    check(e is not None, "info files cannot be restored")
    check(raises(lambda: B.restore_preview(live, arch, "rs.tar.gz", "../etc/passwd"), ValueError),
          "traversal member name rejected")
    audit = open(os.path.join(live, B.AUDIT_FILE.lstrip("/"))).read()
    check(marker not in audit and "line1" not in audit, "audit log never contains file contents")
    entries = B.audit_tail(live, 100)
    oks = [x for x in entries if x["action"] == "restore-file" and x.get("ok")]
    check(len(oks) == 4 and all(x.get("who") is not None and x.get("time") for x in oks), "audit: who/what/when per restore")
    check(any(x["action"] == "restore-file" and x.get("ok") is False for x in entries), "audit: refusals recorded")
    check(stat.S_IMODE(os.stat(os.path.join(live, B.AUDIT_FILE.lstrip("/"))).st_mode) == 0o600, "audit log 0600")
    # firewall dumps become an fw snapshot input
    arch2 = os.path.join(root, "fw.tar.gz")
    ufw = {"user.rules": "*filter\n:ufw-user-input - [0:0]\n### RULES ###\n### END RULES ###\nCOMMIT\n",
           "user6.rules": "*filter\n:ufw6-user-input - [0:0]\n### RULES ###\n### END RULES ###\nCOMMIT\n",
           "before.rules": "*filter\n:ufw-before-input - [0:0]\nCOMMIT\n"}
    mktar(arch2, [("./etc/ufw/%s" % k, v.encode()) for k, v in ufw.items()] +
          [("./iptables-save.txt", b"*filter\nCOMMIT\n")])
    os.makedirs(os.path.join(live, "etc/default"), exist_ok=True)
    open(os.path.join(live, "etc/default/ufw"), "w").write('IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\n')
    files, raw, notes = B.firewall_snapshot_files(live, arch2)
    check(files["user.rules"] == ufw["user.rules"] and raw.get("iptables.save"), "fw snapshot files from backup")
    check(files["ufw.default"].startswith("IPV6") and notes, "missing ufw.default taken from the live box (noted)")
    try:
        import fw_snap as S
        check(not S.validate_files({k: v for k, v in files.items() if k in S.UFW_FILES}),
              "converted files pass fw_snap.validate_files")
    except ImportError:
        pass
    e = raises(lambda: B.firewall_snapshot_files(live, arch), B.Refused)
    check(e is not None, "backup without ufw rule files cannot become a snapshot")


# ── 7. job state + failure incident ─────────────────────────────────────────
def t_jobs(root):
    jr = os.path.join(root, "jobs")
    os.makedirs(jr)
    ok_script = os.path.join(root, "ok.sh")
    open(ok_script, "w").write("#!/bin/sh\nwhile getopts o:i: o; do case $o in o) OUT=$OPTARG;; i) I=$OPTARG;; esac; done\n"
                               "echo 'PROGRESS 10 Working'\necho 'WARN: could not fully read /x' >&2\n"
                               "N=system-backup-$(date +%Y%m%d-%H%M%S).tar.gz\n"
                               "mkdir -p \"$OUT\"; tmpd=$(mktemp -d); echo hi > \"$tmpd/manifest.txt\"\n"
                               "tar -C \"$tmpd\" -czf \"$OUT/$N\" manifest.txt; rm -rf \"$tmpd\"\n"
                               "test -f \"$I\" || exit 9\necho \"RESULT $N\"\n")
    bad_script = os.path.join(root, "bad.sh")
    open(bad_script, "w").write("#!/bin/sh\necho 'PROGRESS 5 Start'\necho 'ERROR: disk on fire' >&2\nexit 3\n")
    for s in (ok_script, bad_script):
        os.chmod(s, 0o755)
    prog = []
    run = B.run_job(jr, include=["etc/hosts"], who="tester", on_progress=lambda p, s: prog.append(p),
                    script=ok_script)
    st = B.load_state(jr)
    check(run["ok"] and st["last_success"]["result"] == run["result"], "successful run recorded")
    check(prog == [10] and "WARN" in run["stderr_tail"], "progress parsed, stderr kept")
    check(stat.S_IMODE(os.stat(os.path.join(jr, B.STATE_FILE.lstrip("/"))).st_mode) == 0o600, "state file 0600")
    check(B.failure_incident(jr) is None, "no incident after success")
    check(not os.listdir(os.path.join(jr, B.WORK_DIR.lstrip("/"))), "include list temp file removed")
    time.sleep(1.1)
    run = B.run_job(jr, who="tester", script=bad_script)
    check(not run["ok"] and "disk on fire" in run["error"] and "status 3" in run["error"], "failure: stderr tail in error")
    inc = B.failure_incident(jr)
    check(inc and "failed" in inc[0].lower(), "failure raises the backup:failed incident")
    time.sleep(1.1)
    B.run_job(jr, include=["etc/hosts"], script=ok_script)
    check(B.failure_incident(jr) is None, "next success clears the incident")
    lk = B.JobLock(jr)
    check(lk.acquire(), "lock acquired")
    e = raises(lambda: B.run_job(jr, script=ok_script), B.Refused)
    check(e is not None and e.status == 409, "concurrent run refused")
    lk.release()
    B.update_state(jr, lambda s: s.update(last_run={"running": True, "started": 1, "trigger": "manual"}))
    B.reconcile_interrupted(jr)
    st = B.load_state(jr)
    check(not st["last_run"]["running"] and "interrupted" in st["last_failure"]["error"], "interrupted run -> failure")
    run = B.run_job(jr, script=os.path.join(root, "missing.sh"))
    check(not run["ok"] and "missing" in run["error"], "missing script is a recorded failure")


# ── --live: the real newest archive, in memory ──────────────────────────────
def live_check():
    d = B.SYSTEM_DIR
    names = sorted(n for n in os.listdir(d) if B.SYSTEM_RE.match(n))
    if not names:
        print("live: no system backup found")
        return
    src = os.path.join(d, names[-1])
    if "--archive" in sys.argv:
        src = sys.argv[sys.argv.index("--archive") + 1]
        names = [os.path.basename(src)]
    values = set()
    public = b""   # OpenSSH private keys embed their public key: that part is not secret
    with tarfile.open(src, "r:gz") as t:
        for m in t:
            n = B.member_safe(m.name)
            if not n or not m.isreg() or m.size > 4 * 1024 * 1024:
                continue
            data = t.extractfile(m).read()
            if n.endswith(".pub"):
                public += data.replace(b"\n", b"") + b"\n"
            if B.is_binary(data):
                continue
            text = data.decode("utf-8")
            if B.secret_file(n) and m.size < 8192:
                for tok in re.findall(r"[A-Za-z0-9+/=_\-.:]{16,}", text):
                    values.add(tok)
            for mm in re.finditer(r"(?i)(?:private|preshared)key\s*=\s*(\S{20,})", text):
                values.add(mm.group(1))
            for mm in B.PEM_RE.finditer(text):
                for line in mm.group(0).replace("\\n", "\n").splitlines()[1:-1]:
                    if len(line) >= 24:
                        values.add(line.strip())
            if n.endswith(".json"):
                try:
                    obj = json.loads(text)
                except ValueError:
                    obj = None

                def walk(o, sec=False):
                    if isinstance(o, dict):
                        schema = "label" in o or "type" in o  # {"key": "<field name>", "label": ...}
                        for k, v in o.items():
                            walk(v, sec or (B.is_secret_key(k) and not (schema and k == "key")))
                    elif isinstance(o, list):
                        for v in o:
                            walk(v, sec)
                    elif sec and isinstance(o, str) and len(o) >= 12 and not B._placeholder(o):
                        values.add(o)
                        if "://" in o:
                            values.add(o.rsplit("/", 1)[-1])
                walk(obj)
    values = {v for v in values if len(v) >= 12 and not v.startswith(("/", "{file:", "http://127."))
              and v.encode() not in public}
    out = io.BytesIO()
    summary = B.sanitize_archive(src, out, names[-1])
    blob = b""
    with tarfile.open(fileobj=io.BytesIO(out.getvalue()), mode="r:gz") as t:
        for m in t:
            if m.isreg():
                blob += t.extractfile(m).read() + b"\n"
    leaked = [v for v in values if v.encode() in blob]
    bad = B.verify_export(io.BytesIO(out.getvalue()))
    check(not bad, "live: export passes verification (%s)" % [b[0] for b in bad[:5]])
    check(not leaked, "live: none of %d secret values from the real archive survives (%d leaked)"
          % (len(values), len(leaked)))
    print("live: %s -> kept %d, dropped %d secret file(s), redacted %d value(s); %d secret values checked"
          % (names[-1], summary["kept"], len(summary["dropped"]), summary["redacted"], len(values)))


def main():
    root = tempfile.mkdtemp(prefix="tw-bk-check-")
    try:
        t_catalog()
        for fn in (t_sizes, t_retention, t_sanitizer, t_sanitizer_failclosed, t_limits, t_restore, t_jobs):
            sub = os.path.join(root, fn.__name__)
            os.makedirs(sub)
            try:
                fn(sub)
            except Exception as exc:
                import traceback
                traceback.print_exc()
                check(False, "%s crashed: %r" % (fn.__name__, exc))
        if "--live" in sys.argv:
            live_check()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("backup safety: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
