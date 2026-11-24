#!/usr/bin/env python3
"""TuxWall dashboard HTTPS: per-router CA + server certificate, nginx snippet, status.

Certificates (/etc/tuxwall/tls, directory 0755, keys 0600 root):
  ca.key / ca.crt   a small local CA, EC P-256, 10 years, its name carries the
                    host name and a random suffix (two routers never share a
                    CA). Name-constrained to private addresses (RFC 1918,
                    100.64/10, ULA) and local names (the host name, .local,
                    .lan, .home.arpa, .internal, .localdomain, the configured
                    domain): trusting it cannot let anyone impersonate other
                    sites. ca.json records the constraints.
  server.key / server.crt (leaf + CA)
                    397 days (browsers refuse > 398), SANs: the LAN/VLAN/VPN
                    IPv4 + ULA addresses, host name, host name.local, the
                    router's domain. Re-issued 30 days before expiry, when
                    the SANs change and when the CA changed.

nginx: /etc/nginx/snippets/tuxwall-tls.conf (included by the package site
with a glob, like tuxwall-listen.conf) adds `listen <addr>:443 ssl
default_server` on the addresses tuxwall-nginx-listen serves on :80 (plus
wildcard 443 sockets, so nginx never has to bind an address that is
missing at the moment), TLS settings, the CA download
(/tuxwall-ca.crt, also over http) and the http -> https redirect for those
addresses (not /.well-known/ or the CA download). HSTS only when switched on.
Every write is followed by `nginx -t`; on failure the previous files are put
back and http keeps working.

The listeners are only added when TuxWall owns the dashboard site:
sites-enabled/tuxwall is the package symlink, the package site includes the
snippet, and no other enabled server listens on 443 on those addresses (or on
a 443 wildcard). Otherwise the HTTPS setup is the owner's ("owner-managed"):
certificates are still generated, nginx is not touched.

Settings: /etc/tuxwall/https.json (enabled, redirect, hsts, custom_cert,
custom_key, extra_names). Escape hatches: /etc/tuxwall/no-https-redirect
(port 80 keeps serving the dashboard, for http integrations) and
/etc/tuxwall/no-https (no TuxWall listeners at all).

CLI (wrapper /usr/local/sbin/tuxwall-tls; tuxwall-tls-renew.timer runs
`refresh --reload` daily):
  status [--json]
  refresh [--reload] [--dry-run] [--force-cert] [--new-ca]
  set [--enabled on|off] [--redirect on|off] [--hsts on|off]
  custom-cert --cert FILE --key FILE | --clear
Exit: 0 ok, 1 refused / nginx -t failed (previous state kept), 2 error.
"""
import datetime
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

CA_DAYS = 3650
CERT_DAYS = 397
RENEW_DAYS = 30
HSTS_MAX_AGE = 31536000
SNIPPET_INCLUDE_RE = re.compile(r"(?m)^[ \t]*include[ \t]+\S*/tuxwall-tls(\[\.\]|\.)conf[ \t]*;")
PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]
LOCAL_SUFFIXES = ("local", "lan", "home.arpa", "internal", "localdomain")
LAN_ALLOW = ("127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8")
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")
SETTINGS_DEFAULT = {"enabled": True, "redirect": True, "hsts": False, "hsts_ever": False,
                    "custom_cert": "", "custom_key": "", "extra_names": []}
NAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


class Env:
    """Every path and command, overridable for tests (tools/https_check.py)."""

    def __init__(self, **kw):
        self.tls_dir = "/etc/tuxwall/tls"
        self.settings = "/etc/tuxwall/https.json"
        self.no_redirect = "/etc/tuxwall/no-https-redirect"
        self.no_https = "/etc/tuxwall/no-https"
        self.interfaces_json = "/etc/tuxwall/interfaces.json"
        self.kea_conf = "/etc/kea/kea-dhcp4.conf"
        self.unbound_dir = "/etc/unbound/unbound.conf.d"
        self.snippet = "/etc/nginx/snippets/tuxwall-tls.conf"
        self.sites_enabled = "/etc/nginx/sites-enabled"
        self.site_available = "/etc/nginx/sites-available/tuxwall"
        self.conf_d = "/etc/nginx/conf.d"
        self.listen_script = "/usr/local/sbin/tuxwall-nginx-listen"
        self.wrapper = "/usr/local/sbin/tuxwall-tls"
        self.state = "/var/lib/tuxwall/tls-state.json"
        self.log = "/var/log/tuxwall/tls.log"
        self.openssl = "openssl"
        self.nginx_test = ["nginx", "-t"]
        self.nginx_version = None          # "1.28.0"; None = ask `nginx -v`
        self.reload_cmd = ["systemctl", "reload", "nginx"]
        self.active_cmd = ["systemctl", "is-active", "--quiet", "nginx"]
        self.timer_cmd = ["systemctl", "is-active", "--quiet", "tuxwall-tls-renew.timer"]
        self.reload_settle = 1.5
        self.listen_render = True          # re-run tuxwall-nginx-listen (the :80 include) when active
        self.ufw = ["ufw"]                 # None: never touch the firewall (tests)
        self.ss_cmd = ["ss", "-Hltnp"]     # None: no socket checks (tests)
        self.restart_cmd = ["systemctl", "restart", "nginx"]
        self.ip_json = None                # fixture instead of `ip -j addr`
        self.wan = None                    # fixture instead of the default route
        self.hostname = None               # fixture instead of socket.gethostname()
        self.domain = None                 # fixture instead of `hostname -d` + Kea
        self.now = None                    # fixture clock (epoch seconds)
        for k, v in kw.items():
            if not hasattr(self, k):
                raise TypeError("unknown Env field %s" % k)
            setattr(self, k, v)

    def p(self, name):
        return os.path.join(self.tls_dir, name)

    def time(self):
        return self.now if self.now is not None else time.time()


# ── small helpers ────────────────────────────────────────────────────────────

def _read(path, default=None):
    try:
        with open(path) as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return default


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _write_atomic(path, data, mode=0o644):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + ".", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w" if isinstance(data, str) else "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _run(cmd, inp=None, timeout=60):
    try:
        p = subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def _log(env, msg):
    try:
        os.makedirs(os.path.dirname(env.log), exist_ok=True)
        with open(env.log, "a") as f:
            f.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except OSError:
        pass


def load_settings(env):
    s = dict(SETTINGS_DEFAULT)
    raw = _read_json(env.settings)
    if isinstance(raw, dict):
        for k, v in raw.items():
            if k in SETTINGS_DEFAULT and type(v) is type(SETTINGS_DEFAULT[k]):
                s[k] = v
    s["extra_names"] = [n for n in s["extra_names"] if isinstance(n, str) and NAME_RE.match(n.lower())]
    return s


def save_settings(env, s):
    out = {k: s.get(k, v) for k, v in SETTINGS_DEFAULT.items()}
    _write_atomic(env.settings, json.dumps(out, indent=2) + "\n", 0o644)


# ── addresses and names ──────────────────────────────────────────────────────

_NL = None


def _listen_mod(env):
    """tuxwall-nginx-listen (3.3.3) - the :80 address selection, reused so
    the TLS listeners and SANs follow exactly the same rules."""
    global _NL
    if _NL is not None and getattr(_NL, "__file__", None) == env.listen_script:
        return _NL
    if not os.path.isfile(env.listen_script):
        return None
    loader = importlib.machinery.SourceFileLoader("tuxwall_nginx_listen_for_tls", env.listen_script)
    spec = importlib.util.spec_from_loader("tuxwall_nginx_listen_for_tls", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    _NL = mod
    return mod


def _ip_data(env, nl):
    if env.ip_json is not None:
        return env.ip_json if not isinstance(env.ip_json, str) else _read_json(env.ip_json)
    return nl.load_ip(None)


def addresses(env):
    """{"listen": [ip...] (TLS listeners = the :80 include's addresses),
        "sans": [ip...] (listen + VLAN/OPT + VPN ULA), "lan": [...], "vpn": [...]}"""
    nl = _listen_mod(env)
    if nl is None:
        return {"listen": [], "sans": [], "lan": [], "vpn": [], "error": "tuxwall-nginx-listen not installed"}
    roles = _read_json(env.interfaces_json)
    wan = env.wan
    if wan is None:
        wan = ""
        if isinstance(roles, dict) and isinstance(roles.get("wan"), dict):
            wan = roles["wan"].get("device") or ""
        if not wan and env.ip_json is None:
            wan = nl.default_route_dev()
    by_dev = nl.addrs_by_dev(_ip_data(env, nl))
    lan, vpn = nl.pick_devices(roles, by_dev, wan)
    listen = []
    for dev in lan + vpn:
        listen += [ip for ip in by_dev.get(dev, []) if ip.version == 4 and nl.is_private_v4(ip)]
    for dev in lan:
        listen += [ip for ip in by_dev.get(dev, []) if nl.is_ula(ip)]
    opt = []
    if isinstance(roles, dict):
        opt = [o.get("device") for o in roles.get("opt") or [] if isinstance(o, dict) and o.get("device")]
    else:
        opt = [d for d in by_dev if d not in lan + vpn + [wan, "lo"] and not (wan and d.startswith(wan + "."))
               and not d.startswith(("docker", "veth", "br-", "virbr", "lxc"))]
    sans = list(listen)
    for dev in lan + vpn + opt:
        if not dev or dev == wan:
            continue
        for ip in by_dev.get(dev, []):
            if (ip.version == 4 and nl.is_private_v4(ip)) or nl.is_ula(ip):
                sans.append(ip)
    dedup = lambda xs: list(dict.fromkeys(xs))  # noqa: E731
    return {"listen": dedup(listen), "sans": dedup(sans), "lan": lan, "vpn": vpn}


def _kea_domain(env):
    """The DHCP domain-name option (first one), e.g. "lan"."""
    for m in re.finditer(r"\{[^{}]*\}", _read(env.kea_conf, "") or ""):
        block = m.group(0)
        if re.search(r'"name"\s*:\s*"domain-name"', block):
            d = re.search(r'"data"\s*:\s*"([^"]+)"', block)
            d = d.group(1).strip().lower().rstrip(".") if d else ""
            if NAME_RE.match(d):
                return d
    return ""


LOCAL_DATA_RE = re.compile(r'^\s*local-data:\s*"([A-Za-z0-9.-]+?)\.?\s+(?:\d+\s+)?IN\s+(A|AAAA)\s+([0-9A-Fa-f:.]+)\s*"',
                           re.M)


def unbound_names(env, ips):
    """Local DNS names (unbound local-data) that point at this router, e.g.
    the installer's gateway.<domain>."""
    want = {str(i) for i in ips}
    out = []
    try:
        files = sorted(f for f in os.listdir(env.unbound_dir) if f.endswith(".conf"))
    except OSError:
        return out
    for f in files:
        for m in LOCAL_DATA_RE.finditer(_read(os.path.join(env.unbound_dir, f), "") or ""):
            try:
                ip = str(ipaddress.ip_address(m.group(3)))
            except ValueError:
                continue
            name = m.group(1).lower()
            if ip in want and NAME_RE.match(name) and name not in out:
                out.append(name)
    return out


def host_names(env, settings, ips=()):
    host = (env.hostname if env.hostname is not None else socket.gethostname()).split(".")[0].lower()
    domains = []
    if env.domain is not None:
        domains = [env.domain] if env.domain else []
    else:
        try:
            fq = socket.getfqdn()
            if "." in fq:
                domains.append(fq.split(".", 1)[1].lower())
        except OSError:
            pass
        kd = _kea_domain(env)
        if kd:
            domains.append(kd)
    names = []
    if host and NAME_RE.match(host):
        names += [host, host + ".local"]
        names += ["%s.%s" % (host, d) for d in domains if d and NAME_RE.match(d) and d != "local"]
    names += unbound_names(env, ips)
    names += [n.lower() for n in settings.get("extra_names") or []]
    return list(dict.fromkeys(n for n in names if NAME_RE.match(n))), host, [d for d in domains if d]


def desired_sans(env, settings, addrs=None):
    addrs = addrs if addrs is not None else addresses(env)
    names, _, _ = host_names(env, settings, addrs["sans"])
    return {"dns": names, "ip": [str(ip) for ip in addrs["sans"]]}


# ── nginx configuration reading ──────────────────────────────────────────────

def _tokens(text):
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "{};":
            yield c
            i += 1
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            yield text[i + 1:j]
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};":
                j += 1
            yield text[i:j]
            i = j


def parse_nginx(text):
    """[(name, [args], children|None)] - enough for server/listen/ssl_* reads."""
    stack, cur, words = [], [], []
    for t in _tokens(text or ""):
        if t == ";":
            if words:
                cur.append((words[0], words[1:], None))
            words = []
        elif t == "{":
            node = (words[0] if words else "", words[1:], [])
            cur.append(node)
            stack.append(cur)
            cur, words = node[2], []
        elif t == "}":
            words = []
            if stack:
                cur = stack.pop()
        else:
            words.append(t)
    return cur if not stack else stack[0]


def _walk(nodes):
    for n in nodes or []:
        yield n
        if n[2] is not None:
            yield from _walk(n[2])


def servers(text):
    return [n for n in _walk(parse_nginx(text)) if n[0] == "server" and n[2] is not None]


def parse_listen(args):
    """('*'|host, port, {params}, "addr:port" as written) or None (unix sockets)."""
    if not args:
        return None
    spec, params = args[0], set(args[1:])
    if spec.startswith("unix:"):
        return None
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 80
    elif spec.isdigit():
        host, port = "*", int(spec)
    elif spec.count(":") == 1:
        host, p = spec.split(":")
        port = int(p) if p.isdigit() else 80
    else:
        host, port = spec, 80
    label = spec if not spec.isdigit() else "*:%s" % spec
    if host in ("*", "0.0.0.0", "::", ""):
        host = "*"
    else:
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            host = host.lower()
    return host, port, params, label


def _server_info(node):
    kids = node[2]
    listens = [parse_listen(a) for n, a, _c in kids if n == "listen"]
    names = [x for n, a, _c in kids if n == "server_name" for x in a]
    cert = next((a[0] for n, a, _c in kids if n == "ssl_certificate" and a), "")
    roots = [a[0] for n, a, _c in _walk(kids) if n == "root" and a]
    proxies = [a[0] for n, a, _c in _walk(kids) if n == "proxy_pass" and a]
    dash = any(r.rstrip("/") == "/var/www/html" for r in roots) or any(
        re.match(r"https?://(127\.0\.0\.1|localhost|\[::1\]):8008\b", p) for p in proxies)
    return {"listens": [x for x in listens if x], "names": names, "cert": cert, "dashboard": dash}


def site_state(env, tls_addrs):
    """Who owns HTTPS for the dashboard addresses. Returns
    {"site": "package"|"custom"|"missing"|"edited", "conflicts": [...], "custom_https": [...]}"""
    enabled = os.path.join(env.sites_enabled, "tuxwall")
    if os.path.islink(enabled):
        target = os.path.realpath(enabled)
        site = "package" if target == os.path.realpath(env.site_available) else "custom"
    elif os.path.exists(enabled):
        site = "custom"
    else:
        site = "missing"
    if site == "package" and not SNIPPET_INCLUDE_RE.search(_read(env.site_available, "") or ""):
        site = "edited"
    want = {str(a) for a in tls_addrs}
    conflicts, custom = [], []
    files = []
    try:
        files += [os.path.join(env.sites_enabled, f) for f in sorted(os.listdir(env.sites_enabled))]
    except OSError:
        pass
    try:
        files += [os.path.join(env.conf_d, f) for f in sorted(os.listdir(env.conf_d)) if f.endswith(".conf")]
    except OSError:
        pass
    for path in files:
        if os.path.abspath(path) == os.path.abspath(enabled) or os.path.isdir(path):
            continue
        text = _read(path)
        if text is None:
            continue
        name = os.path.basename(path)
        for srv in servers(text):
            info = _server_info(srv)
            hits = [spec for h, p, _, spec in info["listens"] if p == 443 and (h == "*" or h in want)]
            if not hits:
                continue
            prev = next((c for c in conflicts if c["file"] == name), None)
            if prev is None:
                conflicts.append({"file": name, "listen": [], "server_name": []})
                prev = conflicts[-1]
            prev["listen"] += [x for x in hits if x not in prev["listen"]]
            prev["server_name"] += [x for x in info["names"] if x not in prev["server_name"]][:4]
            if info["dashboard"]:
                custom.append({"file": name, "listen": hits, "cert_path": info["cert"]})
    return {"site": site, "conflicts": conflicts, "custom_https": custom}


def port443_listeners(env):
    """[(addr:port, program)] of TCP listeners on port 443 (ss -ltnp)."""
    if not env.ss_cmd:
        return None
    rc, out, _err = _run(env.ss_cmd + ["sport = :443"], timeout=15)
    if rc != 0:
        return None
    res = []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 4 or not f[3].endswith(":443"):
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        res.append((f[3], m.group(1) if m else ""))
    return res


def foreign_443(env):
    """Programs other than nginx holding port 443 (a wildcard nginx socket
    would collide with them)."""
    return sorted({"%s (%s)" % (p, a) for a, p in (port443_listeners(env) or []) if p and p != "nginx"})


def decide(env, settings=None, addrs=None):
    """mode: active | owner-managed | disabled | no-addresses, with reasons."""
    settings = settings or load_settings(env)
    addrs = addrs if addrs is not None else addresses(env)
    st = site_state(env, addrs["listen"])
    reasons = []
    if st["site"] == "custom":
        reasons.append("sites-enabled/tuxwall is a local copy, not the package site")
    elif st["site"] == "missing":
        reasons.append("the TuxWall nginx site is not enabled (sites-enabled/tuxwall)")
    elif st["site"] == "edited":
        reasons.append("the package site was edited and does not include the HTTPS snippet")
    for c in st["conflicts"]:
        reasons.append("%s already listens on %s" % (c["file"], ", ".join(c["listen"])))
    for prog in foreign_443(env):
        reasons.append("another program holds port 443: %s" % prog)
    if reasons:
        mode = "owner-managed"
    elif os.path.exists(env.no_https) or not settings.get("enabled", True):
        mode = "disabled"
        reasons.append("/etc/tuxwall/no-https is present" if os.path.exists(env.no_https)
                       else "switched off in Settings -> HTTPS")
    elif not addrs["listen"]:
        mode = "no-addresses"
        reasons.append(addrs.get("error") or "no LAN/VPN address found yet")
    else:
        mode = "active"
    redirect = bool(settings.get("redirect", True)) and not os.path.exists(env.no_redirect)
    return {"mode": mode, "reasons": reasons, "site": st, "listen": [str(a) for a in addrs["listen"]],
            "redirect": redirect, "redirect_marker": os.path.exists(env.no_redirect),
            "hsts": bool(settings.get("hsts"))}


# ── certificates ─────────────────────────────────────────────────────────────

def _parse_date(s):
    s = " ".join(s.split())
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S %Y %Z"):
        try:
            return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def cert_info(env, path):
    """Public facts of the first certificate in path (never the key)."""
    if not path or not os.path.isfile(path):
        return None
    rc, out, err = _run([env.openssl, "x509", "-in", path, "-noout", "-subject", "-issuer", "-startdate",
                         "-enddate", "-fingerprint", "-sha256", "-ext", "subjectAltName,nameConstraints",
                         "-nameopt", "RFC2253"])
    if rc != 0:
        return {"path": path, "error": (err.strip().splitlines() or ["unreadable"])[-1][:200]}
    info = {"path": path, "dns": [], "ip": [], "constrained": False}
    lines = out.splitlines()
    for i, line in enumerate(lines):
        k, _, v = line.partition("=")
        if k == "subject":
            info["subject"] = v.strip()
        elif k == "issuer":
            info["issuer"] = v.strip()
        elif k == "notBefore":
            info["not_before"] = _parse_date(v)
        elif k == "notAfter":
            info["not_after"] = _parse_date(v)
        elif k.lower().startswith("sha256 fingerprint"):
            info["fingerprint_sha256"] = v.strip().upper()
        elif "Subject Alternative Name" in line and i + 1 < len(lines):
            for part in lines[i + 1].split(","):
                part = part.strip()
                if part.startswith("DNS:"):
                    info["dns"].append(part[4:].lower())
                elif part.startswith("IP Address:"):
                    try:
                        info["ip"].append(str(ipaddress.ip_address(part[11:].strip())))
                    except ValueError:
                        pass
        elif "Name Constraints" in line:
            info["constrained"] = True
    na = info.get("not_after")
    info["days_left"] = int((na - env.time()) // 86400) if na else None
    info["self_issued"] = info.get("subject") == info.get("issuer")
    return info


def _pubkey(env, args):
    rc, out, _ = _run([env.openssl] + args)
    return hashlib.sha256(out.encode()).hexdigest() if rc == 0 and "PUBLIC KEY" in out else None


def key_matches(env, cert, key):
    a = _pubkey(env, ["x509", "-in", cert, "-noout", "-pubkey"])
    b = _pubkey(env, ["pkey", "-in", key, "-pubout", "-passin", "pass:"])
    return bool(a) and a == b


def _genkey(env, path):
    rc, out, err = _run([env.openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])
    if rc != 0 or "PRIVATE KEY" not in out:
        raise RuntimeError("openssl genpkey failed: %s" % (err.strip()[-200:] or rc))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(out)


def _ca_constraints(host, domains):
    dns = []
    for d in [host] + list(LOCAL_SUFFIXES) + list(domains):
        d = (d or "").lower().strip(".")
        if d and NAME_RE.match(d) and d not in dns:
            dns.append(d)
    return {"dns": dns, "ip": [str(n) for n in PRIVATE_NETS]}


def name_permitted(name, constraints):
    """RFC 5280 subtree match the way browsers apply the CA's constraints."""
    if constraints is None:
        return True
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        ip = None
    if ip is not None:
        return any(ip in ipaddress.ip_network(n) for n in constraints.get("ip", []) if
                   ipaddress.ip_network(n).version == ip.version)
    name = name.lower()
    return any(name == d or name.endswith("." + d) for d in constraints.get("dns", []))


def _subj_safe(s):
    return re.sub(r"[^A-Za-z0-9 ._()-]", "", s)[:48]


def create_ca(env, work, host, domains):
    cons = _ca_constraints(host, domains)
    suffix = secrets.token_hex(3)
    cn = "TuxWall Local CA %s %s" % (_subj_safe(host) or "router", suffix)
    nc = ",".join(["permitted;DNS:%s" % d for d in cons["dns"]] +
                  ["permitted;IP:%s/%s" % (n.network_address, n.netmask) for n in map(ipaddress.ip_network,
                                                                                         cons["ip"])])
    cfg = os.path.join(work, "ca.cnf")
    with open(cfg, "w") as f:
        f.write("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nO=TuxWall\nCN=%s\n"
                "[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                "subjectKeyIdentifier=hash\nnameConstraints=critical,%s\n" % (cn, nc))
    key, crt = os.path.join(work, "ca.key"), os.path.join(work, "ca.crt")
    _genkey(env, key)
    rc, _out, err = _run([env.openssl, "req", "-x509", "-new", "-key", key, "-sha256", "-days", str(CA_DAYS),
                          "-config", cfg, "-extensions", "v3_ca", "-set_serial", "0x" + secrets.token_hex(16),
                          "-out", crt])
    if rc != 0:
        raise RuntimeError("openssl req (CA) failed: %s" % err.strip()[-300:])
    os.chmod(crt, 0o644)
    meta = {"name": cn, "created": int(env.time()), "constraints": cons}
    with open(os.path.join(work, "ca.json"), "w") as f:
        json.dump(meta, f, indent=2)
    os.chmod(os.path.join(work, "ca.json"), 0o644)
    return meta


def issue_server(env, work, ca_key, ca_crt, sans, constraints):
    """Leaf for sans ({"dns","ip"}) minus names the CA may not certify.
    Returns (dropped names)."""
    dns = [d for d in sans["dns"] if name_permitted(d, constraints)]
    ips = [i for i in sans["ip"] if name_permitted(i, constraints)]
    dropped = [d for d in sans["dns"] if d not in dns] + [i for i in sans["ip"] if i not in ips]
    alt = ["DNS.%d=%s" % (n + 1, d) for n, d in enumerate(dns)] + \
          ["IP.%d=%s" % (n + 1, i) for n, i in enumerate(ips)]
    if not alt:
        raise RuntimeError("no usable name or address for the certificate")
    cfg = os.path.join(work, "srv.cnf")
    with open(cfg, "w") as f:
        f.write("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nO=TuxWall\nCN=TuxWall dashboard\n"
                "[v3_srv]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
                "subjectAltName=@alt\n[alt]\n%s\n" % "\n".join(alt))
    key, csr, leaf = (os.path.join(work, x) for x in ("server.key", "server.csr", "leaf.crt"))
    _genkey(env, key)
    rc, _o, err = _run([env.openssl, "req", "-new", "-key", key, "-config", cfg, "-out", csr])
    if rc != 0:
        raise RuntimeError("openssl req (server) failed: %s" % err.strip()[-300:])
    rc, _o, err = _run([env.openssl, "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
                        "-set_serial", "0x" + secrets.token_hex(16), "-days", str(CERT_DAYS), "-sha256",
                        "-extfile", cfg, "-extensions", "v3_srv", "-out", leaf])
    if rc != 0:
        raise RuntimeError("openssl x509 (sign) failed: %s" % err.strip()[-300:])
    rc, out, err = _run([env.openssl, "verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", ca_crt, leaf])
    if rc != 0:
        raise RuntimeError("new certificate does not verify against the CA: %s" % (out + err).strip()[-300:])
    with open(leaf) as a, open(ca_crt) as b, open(os.path.join(work, "server.crt"), "w") as f:
        f.write(a.read() + b.read())
    os.chmod(os.path.join(work, "server.crt"), 0o644)
    return dropped


def cert_needs(env, sans, constraints):
    """Why the server certificate must be (re)issued, or "" when it is fine."""
    crt, key = env.p("server.crt"), env.p("server.key")
    if not (os.path.isfile(crt) and os.path.isfile(key)):
        return "no certificate yet"
    info = cert_info(env, crt)
    if not info or info.get("error"):
        return "certificate unreadable"
    if info["days_left"] is None or info["days_left"] < RENEW_DAYS:
        return "expires in %s days" % info["days_left"]
    want_dns = sorted(d for d in sans["dns"] if name_permitted(d, constraints))
    want_ip = sorted(i for i in sans["ip"] if name_permitted(i, constraints))
    if sorted(info["dns"]) != want_dns or sorted(info["ip"]) != want_ip:
        return "names/addresses changed"
    rc, _o, _e = _run([env.openssl, "verify", "-CAfile", env.p("ca.crt"), crt])
    if rc != 0:
        return "not issued by the current CA"
    if not key_matches(env, crt, key):
        return "key does not match"
    return ""


def ensure_certs(env, settings, addrs, force=False, new_ca=False, dry_run=False):
    """CA + server certificate. Returns {"ca_created", "cert_issued", "why",
    "dropped", "prev": [(final, backup)...]} - backups let the caller undo."""
    names, host, domains = host_names(env, settings, addrs["sans"])
    sans = {"dns": names, "ip": [str(i) for i in addrs["sans"]]}
    res = {"ca_created": False, "cert_issued": False, "why": "", "dropped": [], "prev": []}
    have_ca = os.path.isfile(env.p("ca.crt")) and os.path.isfile(env.p("ca.key"))
    ca = cert_info(env, env.p("ca.crt")) if have_ca else None
    if have_ca and (not ca or ca.get("error") or (ca.get("days_left") or 0) < 1):
        have_ca = False
    make_ca = new_ca or not have_ca
    meta = None if make_ca else (_read_json(env.p("ca.json")) or {})
    cons = None if make_ca else meta.get("constraints")
    why = "new CA" if make_ca else ("regenerate requested" if force else cert_needs(env, sans, cons))
    res["why"] = why
    if dry_run or not why:
        return res
    os.makedirs(env.tls_dir, mode=0o755, exist_ok=True)
    os.chmod(env.tls_dir, 0o755)
    work = tempfile.mkdtemp(prefix=".work-", dir=env.tls_dir)
    try:
        if make_ca:
            meta = create_ca(env, work, host, domains)
            cons = meta["constraints"]
            ca_key, ca_crt = os.path.join(work, "ca.key"), os.path.join(work, "ca.crt")
        else:
            ca_key, ca_crt = env.p("ca.key"), env.p("ca.crt")
        res["dropped"] = issue_server(env, work, ca_key, ca_crt, sans, cons)
        moves = (["ca.key", "ca.crt", "ca.json"] if make_ca else []) + ["server.key", "server.crt"]
        for name in moves:
            final = env.p(name)
            if os.path.exists(final):
                bak = final + ".prev"
                shutil.copy2(final, bak)
                res["prev"].append((final, bak))
            else:
                res["prev"].append((final, None))
            os.replace(os.path.join(work, name), final)
        res["ca_created"] = make_ca
        res["cert_issued"] = True
        _log(env, "certificate issued (%s)%s" % (why, "; new CA " + meta["name"] if make_ca else ""))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return res


def _undo(prev):
    for final, bak in prev:
        try:
            if bak:
                os.replace(bak, final)
            elif os.path.exists(final):
                os.unlink(final)
        except OSError:
            pass


def _drop_backups(prev):
    for _final, bak in prev:
        if bak:
            try:
                os.unlink(bak)
            except OSError:
                pass


# ── nginx snippet ────────────────────────────────────────────────────────────

def _nginx_version(env):
    if env.nginx_version is not None:
        return env.nginx_version
    rc, out, err = _run([env.nginx_test[0], "-v"], timeout=10)
    m = re.search(r"nginx/(\d+\.\d+\.\d+)", out + err)
    return m.group(1) if m else ""


def _ver_ge(v, want):
    try:
        return tuple(int(x) for x in v.split(".")) >= want
    except ValueError:
        return False


def render_snippet(env, dec, settings):
    """The include for the package site; comments only unless mode is active."""
    head = ("# Generated by tuxwall-tls - do not edit. Settings: dashboard Settings -> Security -> HTTPS\n"
            "# (/etc/tuxwall/https.json). Included by the tuxwall nginx site.\n"
            "# Re-render: sudo tuxwall-tls refresh --reload\n")
    if dec["mode"] != "active":
        return head + "# TuxWall HTTPS inactive (%s): %s\n" % (dec["mode"], "; ".join(dec["reasons"]))
    v = _nginx_version(env)
    h2_on = _ver_ge(v, (1, 25, 1))
    h2_listen = (not h2_on) and _ver_ge(v, (1, 9, 5))
    if settings.get("custom_cert"):
        cert, key = settings["custom_cert"], settings.get("custom_key") or ""
    else:
        cert, key = env.p("server.crt"), env.p("server.key")
    out = [head]
    # Wildcard sockets first: with them nginx binds no single address, so a
    # LAN/VPN address that is missing (WireGuard down, IPv6 DAD at boot) can
    # never stop nginx from starting. The per-address lines below pick this
    # server (default_server) and drive the redirect; the firewall allows 443
    # on the LAN/VPN interfaces only and the location allow-lists apply.
    out.append("listen 443 ssl%s;\nlisten [::]:443 ssl%s;\n" % ((" http2",) * 2 if h2_listen else ("", "")))
    for a in dec["listen"]:
        hp = "[%s]:443" % a if ":" in a else "%s:443" % a
        out.append("listen %s ssl%s default_server;\n" % (hp, " http2" if h2_listen else ""))
    if h2_on:
        out.append("http2 on;\n")
    out.append("ssl_certificate %s;\nssl_certificate_key %s;\n" % (cert, key))
    out.append("ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers %s;\nssl_prefer_server_ciphers off;\n"
               "ssl_session_cache shared:TuxwallDashTLS:10m;\nssl_session_timeout 1d;\nssl_session_tickets off;\n"
               % CIPHERS)
    out.append("\n# The CA certificate, also over plain http (fetch it before trusting it).\n"
               "location = /tuxwall-ca.crt {\n")
    out += ["    allow %s;\n" % a for a in LAN_ALLOW]
    out.append("    deny all;\n    alias %s;\n    add_header Cache-Control \"no-cache\" always;\n}\n" % env.p("ca.crt"))
    if dec["redirect"]:
        alts = "|".join(re.escape(a) for a in dec["listen"])
        out.append("\n# http -> https on the addresses above, except ACME and the CA download.\n"
                   "# Escape hatch: /etc/tuxwall/no-https-redirect (or Settings) keeps :80 serving the dashboard.\n"
                   "set $tuxwall_https_redirect \"$scheme $server_addr\";\n"
                   "if ($uri ~ \"^/(\\.well-known/|tuxwall-ca\\.crt$)\") {\n"
                   "    set $tuxwall_https_redirect \"\";\n}\n"
                   "if ($tuxwall_https_redirect ~ \"^http (%s)$\") {\n"
                   "    return 301 https://$host$request_uri;\n}\n" % alts)
    if settings.get("hsts") or settings.get("hsts_ever"):
        age = HSTS_MAX_AGE if settings.get("hsts") else 0
        out.append("\n# HSTS (%s; sent over https only).\n"
                   "set $tuxwall_hsts \"\";\nif ($scheme = https) {\n    set $tuxwall_hsts \"max-age=%d\";\n}\n"
                   "add_header Strict-Transport-Security $tuxwall_hsts always;\n"
                   % ("on" if settings.get("hsts") else "switched off: max-age=0 clears it in browsers", age))
    return "".join(out)


def ensure_firewall(env, addrs):
    """Before the redirect goes live: TCP 443 must be open where 80 is, i.e.
    on the LAN/VPN interfaces (never the WAN). Adds the rules only when no
    ufw rule names port 443 yet (like the postinst on fresh installs); a box
    without ufw is left alone. Returns a status line or ""."""
    if not env.ufw or not shutil.which(env.ufw[0]) and not os.path.isabs(env.ufw[0]):
        return ""
    rc, out, _err = _run(env.ufw + ["show", "added"], timeout=30)
    if rc != 0:
        return ""
    rules = [l for l in out.splitlines() if re.match(r"ufw (route )?(allow|limit)", l)]
    if any(re.search(r"(^|\s)443(/tcp)?(\s|$)|port 443(\s|$)", l) for l in rules):
        return ""
    added = []
    for dev in list(dict.fromkeys(addrs.get("lan", []) + addrs.get("vpn", []))):
        what = "VPN" if dev in addrs.get("vpn", []) else "LAN"
        rc, _o, _e = _run(env.ufw + ["allow", "in", "on", dev, "to", "any", "port", "443", "proto", "tcp",
                                     "comment", "TuxWall dashboard HTTPS (%s)" % what], timeout=30)
        if rc == 0:
            added.append(dev)
    if added:
        _log(env, "firewall: port 443 allowed on %s" % ", ".join(added))
        return "port 443 allowed on %s" % ", ".join(added)
    return ""


def nginx_test(env):
    rc, out, err = _run(env.nginx_test, timeout=60)
    return rc == 0, (err or out or "").strip()


# ── refresh: certificates + snippet + nginx -t + reload ─────────────────────

def _save_state(env, st):
    try:
        _write_atomic(env.state, json.dumps(st, indent=2) + "\n", 0o644)
    except OSError:
        pass


class _Lock:
    def __init__(self, env):
        self.path = os.path.join(env.tls_dir, ".lock")
        self.f = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), mode=0o755, exist_ok=True)
        self.f = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        try:
            fcntl.flock(self.f, fcntl.LOCK_UN)
        finally:
            self.f.close()


def refresh(env=None, reload=False, dry_run=False, force_cert=False, new_ca=False, settings=None):
    """Bring certificates and the snippet up to date. Returns a dict with
    ok, mode, message, cert/snippet changes; never raises."""
    env = env or Env()
    if dry_run:
        return _refresh(env, reload, True, force_cert, new_ca, settings)
    try:
        with _Lock(env):
            return _refresh(env, reload, False, force_cert, new_ca, settings)
    except OSError as exc:
        return {"ok": False, "mode": "error", "message": "TLS directory not writable: %s" % exc}


def _refresh(env, reload, dry_run, force_cert, new_ca, settings):
    settings = settings or load_settings(env)
    res = {"ok": True, "dry_run": dry_run, "cert_issued": False, "ca_created": False, "snippet_changed": False,
           "reloaded": False, "at": int(env.time())}
    try:
        addrs = addresses(env)
        dec = decide(env, settings, addrs)
        res.update(mode=dec["mode"], reasons=dec["reasons"], listen=dec["listen"], redirect=dec["redirect"])
        certs = ensure_certs(env, settings, addrs, force=force_cert, new_ca=new_ca, dry_run=dry_run)
    except Exception as exc:
        res.update(ok=False, mode=res.get("mode", "error"), message="certificate step failed: %s" % exc)
        _log(env, res["message"])
        if not dry_run:
            _save_state(env, res)
        return res
    res.update(cert_issued=certs["cert_issued"], ca_created=certs["ca_created"], why=certs["why"],
               dropped=certs["dropped"])
    content = render_snippet(env, dec, settings)
    old = _read(env.snippet)
    write = content != old and (dec["mode"] == "active" or old is not None)
    if dec["mode"] == "active" and settings.get("custom_cert"):
        if not (os.path.isfile(settings["custom_cert"]) and os.path.isfile(settings.get("custom_key") or "")):
            write = False
            res.update(ok=False, message="your own certificate/key file is missing - snippet left as it was")
    if dry_run:
        res["snippet_changed"] = write
        res["message"] = res.get("message") or _summary(dec, certs, write, dry=True)
        return res
    # our certificate only matters to nginx while the active snippet points at it
    used = dec["mode"] == "active" and not settings.get("custom_cert")
    if write and dec["mode"] == "active":
        fw = ensure_firewall(env, addrs)
        if fw:
            res["firewall"] = fw
    if write:
        bak = None
        if old is not None:
            bak = env.snippet + ".tuxwall-prev"
            shutil.copy2(env.snippet, bak)
        _write_atomic(env.snippet, content, 0o644)
        ok, msg = nginx_test(env)
        if not ok:
            if bak:
                os.replace(bak, env.snippet)
            else:
                os.unlink(env.snippet)
            _undo(certs["prev"])
            ok_before, _m = nginx_test(env)
            res.update(ok=False, message="nginx -t failed with the new HTTPS snippet - previous files kept%s (%s)"
                       % ("" if ok_before else "; nginx -t fails without it too",
                          " | ".join(msg.splitlines()[-2:])))
            _log(env, res["message"])
            _save_state(env, res)
            return res
        if bak:
            os.unlink(bak)
        res["snippet_changed"] = True
    elif certs["cert_issued"] and used:
        ok, msg = nginx_test(env)
        if not ok:
            _undo(certs["prev"])
            res.update(ok=False, message="nginx -t failed with the new certificate - previous one kept (%s)"
                       % " | ".join(msg.splitlines()[-2:]))
            _log(env, res["message"])
            _save_state(env, res)
            return res
    _drop_backups(certs["prev"])
    # the :80 include follows the same addresses (interface Apply, timer) -
    # after the 443 listeners: nginx -t binds those (no wildcard on 443), so a
    # removed address must leave the TLS snippet first. Only while TuxWall
    # owns the site; an owner-managed nginx is never touched.
    if dec["mode"] == "active" and env.listen_render and os.path.isfile(env.listen_script):
        rc, out, _err = _run([sys.executable, "-B", env.listen_script], timeout=90)
        if rc == 0 and "include written" in out:
            res["listen_changed"] = True
    if reload and (res["snippet_changed"] or res.get("listen_changed") or (certs["cert_issued"] and used)):
        if _run(env.active_cmd, timeout=15)[0] == 0:
            rc, _o, err = _run(env.reload_cmd, timeout=60)
            res["reloaded"] = rc == 0
            if rc != 0:
                res.update(ok=False, message="nginx reload failed: %s" % err.strip()[-200:])
            elif env.reload_settle:
                time.sleep(env.reload_settle)   # the reload signal returns before new workers serve
            if rc == 0 and dec["mode"] == "active":
                _ensure_wildcard(env, res)
    res["message"] = res.get("message") or _summary(dec, certs, res["snippet_changed"])
    _log(env, "refresh: %s" % res["message"])
    _save_state(env, res)
    return res


def _ensure_wildcard(env, res):
    """A reload cannot swap address-bound 443 sockets (an earlier HTTPS
    site, owner-managed before) for the wildcard ones: the running nginx
    keeps its old configuration (`nginx -t` does not see it, EADDRINUSE is
    ignored there). Detected from the sockets; then nginx is restarted once
    - nginx -t passed and no other program holds 443."""
    before = port443_listeners(env)
    if before is None or any(a in ("0.0.0.0:443", "*:443") for a, _p in before):
        return
    foreign = foreign_443(env)
    if foreign:
        res.update(ok=False, message="nginx kept its old port 443 setup and another program holds 443 (%s) - "
                                     "not restarting nginx" % ", ".join(foreign))
        return
    rc, _o, err = _run(env.restart_cmd, timeout=90)
    res["restarted"] = rc == 0
    if rc != 0:
        res.update(ok=False, message="nginx restart failed: %s" % err.strip()[-200:])
    elif env.reload_settle:
        time.sleep(env.reload_settle)
    _log(env, "nginx restarted to take over port 443 (a reload cannot replace address-bound sockets)")


def _summary(dec, certs, snippet_changed, dry=False):
    parts = []
    if certs["cert_issued"] or (dry and certs["why"]):
        parts.append("certificate %s (%s)" % ("would be issued" if dry else "issued", certs["why"]))
    else:
        parts.append("certificate current")
    if dec["mode"] == "active":
        parts.append("HTTPS on %s%s" % (", ".join(dec["listen"]),
                                        "; http redirects to https" if dec["redirect"] else
                                        "; http not redirected (escape hatch)"))
    elif dec["mode"] == "owner-managed":
        parts.append("existing HTTPS setup detected (%s) - nginx left alone; TuxWall's certificate is in "
                     "/etc/tuxwall/tls (CA: ca.crt); enable from Settings -> HTTPS if wanted"
                     % "; ".join(dec["reasons"]))
    else:
        parts.append("TuxWall HTTPS %s (%s)" % (dec["mode"], "; ".join(dec["reasons"])))
    if snippet_changed:
        parts.append("nginx snippet %s" % ("would change" if dry else "updated"))
    return "; ".join(parts)


# ── status (dashboard card) ──────────────────────────────────────────────────

def status(env=None):
    env = env or Env()
    settings = load_settings(env)
    try:
        addrs = addresses(env)
        dec = decide(env, settings, addrs)
        sans = desired_sans(env, settings, addrs)
    except Exception as exc:
        return {"ok": False, "error": "status unavailable: %s" % exc}
    ca = cert_info(env, env.p("ca.crt"))
    srv = cert_info(env, env.p("server.crt"))
    meta = _read_json(env.p("ca.json")) or {}
    custom = None
    if settings.get("custom_cert"):
        custom = cert_info(env, settings["custom_cert"]) or {"path": settings["custom_cert"], "error": "missing"}
        custom["key_path"] = settings.get("custom_key", "")
    in_use = "none" if dec["mode"] != "active" else ("custom" if custom else ("tuxwall" if srv else "none"))
    owner_sites = []
    for c in dec["site"]["custom_https"]:
        info = cert_info(env, c["cert_path"]) if c.get("cert_path") else None
        owner_sites.append({"file": c["file"], "listen": c["listen"], "cert": info})
    timer = _run(env.timer_cmd, timeout=10)[0] == 0 if env.timer_cmd else False
    cons = meta.get("constraints")
    want_dns = [d for d in sans["dns"] if name_permitted(d, cons)]
    want_ip = [i for i in sans["ip"] if name_permitted(i, cons)]
    sans_current = bool(srv and not srv.get("error") and sorted(srv["dns"]) == sorted(want_dns)
                        and sorted(srv["ip"]) == sorted(want_ip))
    urls = ["https://%s/" % ("[%s]" % a if ":" in a else a) for a in dec["listen"]] if dec["mode"] == "active" else []
    ca_http = ["http://%s/tuxwall-ca.crt" % ("[%s]" % a if ":" in a else a) for a in dec["listen"][:1]] \
        if dec["mode"] == "active" else []
    return {
        "ok": True,
        "installed": os.path.exists(env.wrapper),
        "mode": dec["mode"],
        "reasons": dec["reasons"],
        "site": dec["site"]["site"],
        "conflicts": dec["site"]["conflicts"],
        "owner_sites": owner_sites,
        "listen": dec["listen"],
        "redirect": dec["redirect"],
        "redirect_setting": bool(settings.get("redirect", True)),
        "redirect_marker": dec["redirect_marker"],
        "no_https_marker": os.path.exists(env.no_https),
        "enabled_setting": bool(settings.get("enabled", True)),
        "hsts": bool(settings.get("hsts")),
        "ca": ca and dict(ca, name=meta.get("name", ""), constraints=cons),
        "cert": srv,
        "custom": custom,
        "in_use": in_use,
        "wanted_sans": {"dns": want_dns, "ip": want_ip},
        "not_coverable": [x for x in sans["dns"] + sans["ip"] if x not in want_dns + want_ip],
        "sans_current": sans_current,
        "urls": urls,
        "ca_http": ca_http,
        "timer_active": timer,
        "snippet_present": os.path.exists(env.snippet),
        # nginx runs what the settings/addresses say (else: refresh pending)
        "applied": (_read(env.snippet) == render_snippet(env, dec, settings)) if dec["mode"] == "active"
        else not ("\nlisten " in "\n" + (_read(env.snippet) or "")),
        "last": _read_json(env.state),
    }


# ── settings / custom certificate (CLI + API) ────────────────────────────────

def _path_ok(path):
    return (isinstance(path, str) and path.startswith("/") and ".." not in path.split("/")
            and len(path) < 512 and os.path.realpath(path).startswith("/etc/"))


def validate_custom(env, cert, key):
    """Error text, or "" when the pair is usable."""
    if not (_path_ok(cert) and _path_ok(key)):
        return "use absolute paths of files under /etc (e.g. /etc/ssl/private/router.key)"
    if not os.path.isfile(cert) or not os.path.isfile(key):
        return "certificate or key file not found"
    info = cert_info(env, cert)
    if not info or info.get("error"):
        return "not a readable PEM certificate (%s)" % ((info or {}).get("error") or "?")
    if info.get("days_left") is not None and info["days_left"] < 0:
        return "the certificate has expired"
    if not key_matches(env, cert, key):
        return "the key does not belong to the certificate (or it is encrypted - nginx needs it unencrypted)"
    return ""


def apply_settings(env, changes, reload=True):
    """changes: enabled/redirect/hsts (bool), custom_cert/custom_key (str, ""
    clears). Saves, refreshes; on a failed refresh the previous settings are
    put back. Returns (ok, refresh result)."""
    env = env or Env()
    old = load_settings(env)
    new = dict(old)
    for k in ("enabled", "redirect", "hsts"):
        if k in changes:
            new[k] = bool(changes[k])
    if new["hsts"]:
        new["hsts_ever"] = True
    if "custom_cert" in changes or "custom_key" in changes:
        c, k = changes.get("custom_cert", ""), changes.get("custom_key", "")
        if c or k:
            err = validate_custom(env, c, k)
            if err:
                return False, {"ok": False, "message": err}
        new["custom_cert"], new["custom_key"] = c, k
    existed = os.path.exists(env.settings)
    save_settings(env, new)
    res = refresh(env, reload=reload, settings=new)
    if not res.get("ok"):
        if existed:
            save_settings(env, old)
        else:
            try:
                os.unlink(env.settings)
            except OSError:
                pass
        refresh(env, reload=reload, settings=old)
    return bool(res.get("ok")), res


# ── CLI ──────────────────────────────────────────────────────────────────────

def _onoff(v):
    if v in ("on", "1", "true", "yes"):
        return True
    if v in ("off", "0", "false", "no"):
        return False
    raise SystemExit("expected on|off, got %r" % v)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="tuxwall-tls", description="TuxWall dashboard HTTPS certificate + nginx")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status")
    s.add_argument("--json", action="store_true")
    r = sub.add_parser("refresh", aliases=["renew"])
    r.add_argument("--reload", action="store_true", help="reload nginx when something changed")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--force-cert", action="store_true", help="issue a new server certificate")
    r.add_argument("--new-ca", action="store_true", help="new CA (every device must trust it again)")
    r.add_argument("--json", action="store_true")
    st = sub.add_parser("set")
    st.add_argument("--enabled")
    st.add_argument("--redirect")
    st.add_argument("--hsts")
    cc = sub.add_parser("custom-cert")
    cc.add_argument("--cert", default="")
    cc.add_argument("--key", default="")
    cc.add_argument("--clear", action="store_true")
    sub.add_parser("decide")
    a = ap.parse_args(argv)
    env = Env()
    try:
        if a.cmd == "status":
            st_ = status(env)
            if a.json:
                print(json.dumps(st_, indent=2))
            else:
                print("mode: %s%s" % (st_.get("mode"), (" (%s)" % "; ".join(st_.get("reasons") or []))
                                      if st_.get("reasons") else ""))
                for k in ("ca", "cert", "custom"):
                    c = st_.get(k)
                    if c and not c.get("error"):
                        print("%s: %s, expires in %s days, SHA-256 %s%s" % (
                            k, c.get("subject", ""), c.get("days_left"), c.get("fingerprint_sha256", ""),
                            ("; names " + ", ".join(c["dns"] + c["ip"])) if k != "ca" else ""))
                print("redirect: %s; HSTS: %s; renewal timer: %s" % (
                    "on" if st_.get("redirect") else "off", "on" if st_.get("hsts") else "off",
                    "active" if st_.get("timer_active") else "inactive"))
            return 0
        if a.cmd == "decide":
            d = decide(env)
            print(d["mode"])
            return 0
        if a.cmd in ("refresh", "renew"):
            res = refresh(env, reload=a.reload, dry_run=a.dry_run, force_cert=a.force_cert, new_ca=a.new_ca)
            print(json.dumps(res, indent=2) if a.json else "tuxwall-tls: %s" % res.get("message"))
            return 0 if res.get("ok") else 1
        if a.cmd == "set":
            ch = {k: _onoff(getattr(a, k)) for k in ("enabled", "redirect", "hsts") if getattr(a, k) is not None}
            ok, res = apply_settings(env, ch)
            print("tuxwall-tls: %s" % res.get("message"))
            return 0 if ok else 1
        if a.cmd == "custom-cert":
            ch = {"custom_cert": "", "custom_key": ""} if a.clear else {"custom_cert": a.cert, "custom_key": a.key}
            ok, res = apply_settings(env, ch)
            print("tuxwall-tls: %s" % res.get("message"))
            return 0 if ok else 1
    except Exception as exc:
        print("tuxwall-tls: %s" % exc, file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
