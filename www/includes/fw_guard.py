"""TuxWall firewall guard: rule ownership (classification) and safety invariants.

Pure module: everything it reads goes through ``Ctx`` (a file root and a command
runner), so tests can point it at a temp copy of /etc/ufw and a mocked runner.

- ``load_ruleset(ctx)``       ufw user tuples (v4/v6, file order) + defaults +
                              before.rules + optional raw iptables-save dumps.
- ``classify(rs, ctx)``       owner/managed/reason for every ufw tuple and raw rule.
- ``invariants(rs, ctx)``     violations {id, severity, title, detail, repair}.
- ``check(cur, prop, ctx)``   guard decision: new critical/high violations block.
- ``proposed_*``              build a proposed ruleset for add/delete/move/default.

Existing live rules are never rewritten to add tags: untagged honeypot rules are
recognised by matching the honeypot config (ports + WAN interface).
"""
import ipaddress
import json
import os
import re
import subprocess

try:
    import canary_egress as _CE
except ImportError:  # pragma: no cover
    try:
        from . import canary_egress as _CE
    except ImportError:
        _CE = None

HONEYPOT_TAG = "tuxwall-honeypot"
CANARY_PORTS = (22, 5900, 1433, 6379)
CANARY_SNMP_PORT = 161
MGMT_PORTS = (22, 80, 443, 8008, 4096, 8744, 53, 67)
DASHBOARD_PORTS = (80, 443)
SEVERITIES = ("critical", "high", "medium", "low", "info")
BLOCKING = ("critical", "high")

OWNERS = {
    "honeypot": ("Deception → Honeypot", "#deception"),
    "canary": ("Deception → Canary", "#deception"),
    "canary-egress": ("Deception → Canary egress containment (before.rules)", "#deception"),
    "forum-egress": ("Forum egress containment (before.rules)", ""),
    "tripwire": ("Security → Tripwire", "#security"),
    "crowdsec": ("CrowdSec firewall bouncer", "#crowdsec"),
    "nat": ("NAT / LAN → WAN forwarding (tuxwall-nat, installer)", "#firewall/nat"),
    "portforward": ("Firewall → NAT / Port Forward", "#firewall/nat"),
    "dmz": ("Firewall → NAT / DMZ", "#firewall/nat"),
    "wireguard": ("VPN → WireGuard", "#wireguard"),
    "policy": ("Interfaces → Policy matrix", "#interfaces/policy"),
    "mdns": ("mDNS reflector (Avahi)", ""),
    "management": ("Router access (installer rule)", ""),
    "user": ("", ""),
}
UNMANAGED = ("user", "management")


def owner_label(owner):
    return OWNERS.get(owner, ("", ""))[0]


# ── context ──────────────────────────────────────────────────────────────────

def _default_runner(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or ""
    except Exception as exc:
        return 127, str(exc)


def _default_runner_in(cmd, text, timeout=60):
    try:
        p = subprocess.run(cmd, input=text, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return 127, str(exc)


class Ctx:
    """Everything the guard reads. ``root`` prefixes every file path; ``run``
    executes read-only commands (iptables-save, ss, systemctl is-active, ip)."""

    def __init__(self, root="", run=None, wan=None, client_ip="", client_iface=None,
                 client_dst="", listeners=None, canary_active=None, opencanary_user=None,
                 opencanary_uid=None, raw=True, run_in=None):
        self.root = root or ""
        self.run = run or _default_runner
        self.run_in = run_in or _default_runner_in
        self._wan = wan
        self.client_ip = client_ip or ""
        self._client_iface = client_iface
        self._client_dst = client_dst
        self._listeners = listeners
        self._canary_active = canary_active
        self._ocu = opencanary_user
        self._ocuid = opencanary_uid
        self.want_raw = raw
        self._cache = {}

    def path(self, p):
        return self.root + p

    def read(self, p, default=""):
        try:
            with open(self.path(p), "r", errors="replace") as f:
                return f.read()
        except OSError:
            return default

    def json(self, p, default=None):
        try:
            return json.loads(self.read(p, "")) if self.read(p, "") else default
        except ValueError:
            return default

    # topology
    @property
    def topo(self):
        if "topo" not in self._cache:
            self._cache["topo"] = self.json("/etc/tuxwall/interfaces.json", {}) or {}
        return self._cache["topo"]

    @property
    def wan(self):
        if self._wan:
            return self._wan
        dev = ((self.topo.get("wan") or {}).get("device")) or ""
        if not dev:
            rc, out = self.run(["ip", "route", "show", "default"])
            m = re.search(r" dev (\S+)", out or "")
            dev = m.group(1) if m else ""
        self._wan = dev
        return dev

    @property
    def lan(self):
        return ((self.topo.get("lan") or {}).get("device")) or ""

    @property
    def wg(self):
        if "wg" not in self._cache:
            conf = self.read("/etc/wireguard/wg0.conf")
            port = re.search(r"(?im)^\s*ListenPort\s*=\s*(\d+)", conf)
            nets = []
            for m in re.finditer(r"(?im)^\s*Address\s*=\s*(.+)$", conf):
                for a in m.group(1).split(","):
                    try:
                        nets.append(str(ipaddress.ip_interface(a.strip()).network))
                    except ValueError:
                        pass
            for v in (self.topo.get("vpn") or []):
                try:
                    n = str(ipaddress.ip_interface(v.get("address") or "").network)
                    if n not in nets:
                        nets.append(n)
                except ValueError:
                    pass
            self._cache["wg"] = {"iface": "wg0", "port": int(port.group(1)) if port else 51820,
                                 "nets": nets}
        return self._cache["wg"]

    @property
    def honeypot(self):
        c = self.json("/var/lib/tuxwall/honeypot.json", {}) or {}
        ports = []
        for p in (c.get("ports") or [23, 2323, 3389, 445, 5555]):
            try:
                if 1 <= int(p) <= 65535:
                    ports.append(int(p))
            except (TypeError, ValueError):
                pass
        return {"enabled": bool(c.get("enabled")), "ports": sorted(set(ports))}

    @property
    def canary_installed(self):
        return os.path.exists(self.path("/etc/systemd/system/opencanary.service"))

    @property
    def canary_active(self):
        if self._canary_active is None:
            rc, out = self.run(["systemctl", "is-active", "opencanary"])
            self._canary_active = out.strip() == "active"
        return self._canary_active

    @property
    def opencanary_user(self):
        if self._ocu is None:
            self._ocu, self._ocuid = False, None
            for line in self.read("/etc/passwd").splitlines():
                f = line.split(":")
                if f and f[0] == "opencanary":
                    self._ocu = True
                    self._ocuid = f[2] if len(f) > 2 else None
        return self._ocu

    @property
    def opencanary_uid(self):
        self.opencanary_user
        return self._ocuid

    def uid_of(self, name):
        for line in self.read("/etc/passwd").splitlines():
            f = line.split(":")
            if f and f[0] == name and len(f) > 2:
                return f[2]
        return None

    @property
    def tripwire(self):
        conf = self.json("/etc/tuxwall/tripwire.json", {}) or {}
        st = self.json("/etc/tuxwall/tripwire-state.json", {}) or {}
        return {"mode": str(conf.get("mode") or "disabled"), "tripped": bool(st.get("tripped")),
                "trip_mode": st.get("mode") or "medium"}

    @property
    def crowdsec_chains(self):
        txt = self.read("/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml")
        if not txt:
            return []
        chains, inside = [], False
        for line in txt.splitlines():
            if re.match(r"^iptables_chains\s*:", line):
                inside = True
                continue
            if not inside:
                continue
            m = re.match(r"^\s+-\s*([A-Za-z0-9_-]+)", line)
            if m:
                chains.append(m.group(1))
            elif line.strip() and not line.lstrip().startswith("#"):
                break
        return chains or ["INPUT"]

    @property
    def portforwards(self):
        d = self.json("/etc/tuxwall/portforward.json", [])
        if isinstance(d, dict):
            d = d.get("rules") or []
        return [r for r in (d or []) if isinstance(r, dict)]

    @property
    def dmz(self):
        d = self.json("/etc/tuxwall/dmz.json", {}) or {}
        ips = []
        for k in (d if isinstance(d, dict) else {}):
            try:
                ips.append(str(ipaddress.ip_address(k)))
            except ValueError:
                pass
        return {"ips": ips}

    @property
    def listeners(self):
        if self._listeners is None:
            rc, out = self.run(["ss", "-lntupH"])
            ls = []
            for line in (out or "").splitlines():
                f = line.split()
                if len(f) < 5:
                    continue
                local = f[4]
                addr, _, port = local.rpartition(":")
                addr = addr.strip("[]").split("%")[0]
                proc = ""
                m = re.search(r'\(\("([^"]+)"', line)
                if m:
                    proc = m.group(1)
                try:
                    ls.append({"proto": f[0], "addr": addr, "port": int(port), "proc": proc})
                except ValueError:
                    pass
            self._listeners = ls
        return self._listeners

    @property
    def client_iface(self):
        if self._client_iface is None:
            self._client_iface, self._client_dst = "", ""
            if self.client_ip:
                rc, out = self.run(["ip", "-o", "route", "get", self.client_ip])
                m = re.search(r" dev (\S+)", out or "")
                s = re.search(r" src (\S+)", out or "")
                self._client_iface = m.group(1) if m else ""
                self._client_dst = s.group(1) if s else ""
                if out.startswith("local ") or self._client_iface == "lo":
                    self._client_iface = "lo"
        return self._client_iface

    @property
    def client_dst(self):
        self.client_iface
        return self._client_dst


# ── parsing ──────────────────────────────────────────────────────────────────

UFW_FILES = ("user.rules", "user6.rules", "before.rules", "before6.rules",
             "after.rules", "after6.rules")


def parse_user_rules(text, family):
    """Split a user.rules/user6.rules text into (head, blocks, tail).
    Each block: {tuple: str, body: [lines], rule: parsed tuple}."""
    lines = text.splitlines()
    try:
        i0 = next(i for i, l in enumerate(lines) if l.strip() == "### RULES ###")
        i1 = next(i for i, l in enumerate(lines) if l.strip() == "### END RULES ###")
    except StopIteration:
        return lines, [], []
    head, mid, tail = lines[:i0 + 1], lines[i0 + 1:i1], lines[i1:]
    blocks, cur = [], None
    for l in mid:
        if l.startswith("### tuple ### "):
            cur = {"tuple": l, "body": []}
            blocks.append(cur)
        elif cur is not None and l.strip():
            cur["body"].append(l)
    for i, b in enumerate(blocks):
        b["rule"] = parse_tuple(b["tuple"], family, i)
    return head, blocks, tail


def render_user_rules(head, blocks, tail):
    out = list(head) + [""]
    for b in blocks:
        out.append(b["tuple"])
        out.extend(b["body"])
        out.append("")
    out.extend(tail)
    return "\n".join(out) + "\n"


def parse_tuple(line, family, index=0):
    parts = line[len("### tuple ### "):].split()
    comment = ""
    for p in list(parts):
        if p.startswith("comment="):
            try:
                comment = bytes.fromhex(p[8:]).decode("utf-8", "replace")
            except ValueError:
                comment = p[8:]
            parts.remove(p)
    while len(parts) < 6:
        parts.append("any")
    app = len(parts) >= 9
    rest = parts[8:] if app else parts[6:]
    action = parts[0]
    route = action.startswith("route:")
    action = action.split(":", 1)[-1].split("_")[0]
    direction = rest[0] if rest else "in"
    iin = iout = ""
    for seg in direction.split("!"):
        if seg.startswith("in_"):
            iin = seg[3:]
        elif seg.startswith("out_"):
            iout = seg[4:]
    d = "out" if direction.startswith("out") else "in"
    r = {"family": family, "index": index, "route": route, "action": action,
         "proto": parts[1], "dport": parts[2], "dst": parts[3], "sport": parts[4],
         "src": parts[5], "in": iin, "out": iout, "dir": d, "comment": comment,
         "app": app}
    r["key"] = rule_key(r)
    r["text"] = rule_text(r)
    return r


def rule_key(r):
    return "|".join(str(r.get(k, "")) for k in
                    ("family", "route", "action", "proto", "dport", "dst", "sport", "src",
                     "in", "out", "dir"))


def _any(a):
    return a in ("", "any", "0.0.0.0/0", "::/0")


def rule_text(r):
    s = ("route " if r["route"] else "") + r["action"]
    if r["dir"] == "out" and not r["route"]:
        s += " out" + (" on " + r["out"] if r["out"] else "")
    else:
        if r["in"]:
            s += " in on " + r["in"]
        if r["out"]:
            s += " out on " + r["out"]
    s += " from " + ("any" if _any(r["src"]) else r["src"])
    if r["sport"] != "any":
        s += " port " + r["sport"]
    s += " to " + ("any" if _any(r["dst"]) else r["dst"])
    if r["dport"] != "any":
        s += " port " + r["dport"]
    if r["proto"] != "any":
        s += " proto " + r["proto"]
    if r["comment"]:
        s += " comment '%s'" % r["comment"]
    return s


def parse_defaults(text):
    d = {"input": "DROP", "output": "ACCEPT", "forward": "DROP"}
    for k, key in (("input", "DEFAULT_INPUT_POLICY"), ("output", "DEFAULT_OUTPUT_POLICY"),
                   ("forward", "DEFAULT_FORWARD_POLICY")):
        m = re.search(r'(?m)^%s="?(\w+)"?' % key, text or "")
        if m:
            d[k] = m.group(1).upper()
    return d


def load_ruleset(ctx, files=None, raw=None):
    """files: optional {name: text} overriding /etc/ufw/<name> and 'default'
    (= /etc/default/ufw). raw: optional {"v4": text, "v6": text}."""
    files = dict(files or {})
    def get(name, path):
        return files[name] if name in files else ctx.read(path)
    texts = {n: get(n, "/etc/ufw/" + n) for n in UFW_FILES}
    texts["default"] = get("default", "/etc/default/ufw")
    h4, b4, t4 = parse_user_rules(texts["user.rules"], "v4")
    h6, b6, t6 = parse_user_rules(texts["user6.rules"], "v6")
    rs = {"texts": texts, "blocks": {"v4": b4, "v6": b6},
          "parts": {"v4": (h4, t4), "v6": (h6, t6)},
          "v4": [b["rule"] for b in b4], "v6": [b["rule"] for b in b6],
          "defaults": parse_defaults(texts["default"]), "raw": raw}
    if rs["raw"] is None and ctx.want_raw:
        rs["raw"] = {}
        for fam, tool in (("v4", "iptables-save"), ("v6", "ip6tables-save")):
            rc, out = ctx.run([tool])
            rs["raw"][fam] = out if rc == 0 else ""
    return rs


def rebuild(rs, blocks4=None, blocks6=None, defaults=None, files=None):
    """A new ruleset from an existing one with replaced blocks/defaults/files."""
    texts = dict(rs["texts"])
    texts.update(files or {})
    b4 = rs["blocks"]["v4"] if blocks4 is None else blocks4
    b6 = rs["blocks"]["v6"] if blocks6 is None else blocks6
    for fam, bl in (("v4", b4), ("v6", b6)):
        for i, b in enumerate(bl):
            b["rule"] = parse_tuple(b["tuple"], fam, i)
    texts["user.rules"] = render_user_rules(rs["parts"]["v4"][0], b4, rs["parts"]["v4"][1])
    texts["user6.rules"] = render_user_rules(rs["parts"]["v6"][0], b6, rs["parts"]["v6"][1])
    defs = dict(rs["defaults"])
    defs.update(defaults or {})
    if defaults:
        t = texts["default"]
        for k, key in (("input", "DEFAULT_INPUT_POLICY"), ("output", "DEFAULT_OUTPUT_POLICY"),
                       ("forward", "DEFAULT_FORWARD_POLICY")):
            if k in defaults:
                t = re.sub(r'(?m)^%s=.*$' % key, '%s="%s"' % (key, defaults[k].upper()), t)
        texts["default"] = t
    return {"texts": texts, "blocks": {"v4": b4, "v6": b6}, "parts": rs["parts"],
            "v4": [b["rule"] for b in b4], "v6": [b["rule"] for b in b6],
            "defaults": defs, "raw": rs.get("raw")}


def numbered(rs):
    """Rules in `ufw status numbered` order (v4 list then v6 list)."""
    return rs["v4"] + rs["v6"]


# ── classification ───────────────────────────────────────────────────────────

def _ports(spec):
    """'80' / '80,443' / '8000:8100' / 'any' -> set of ints or None (=any)."""
    if spec in ("any", "", None):
        return None
    out = set()
    for part in str(spec).split(","):
        if ":" in part:
            a, b = part.split(":", 1)
            try:
                a, b = int(a), int(b)
            except ValueError:
                continue
            if b - a > 70000:
                return None
            out.update(range(a, b + 1))
        else:
            try:
                out.add(int(part))
            except ValueError:
                pass
    return out


def _single_port(spec):
    p = _ports(spec)
    return next(iter(p)) if p and len(p) == 1 else None


def _in_nets(addr, nets):
    try:
        n = ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return False
    for x in nets:
        try:
            if n.version == ipaddress.ip_network(x).version and n.subnet_of(ipaddress.ip_network(x)):
                return True
        except ValueError:
            pass
    return False


def _mk(owner, reason, **extra):
    d = {"owner": owner, "managed": owner not in UNMANAGED, "reason": reason,
         "label": owner_label(owner),
         "group": "policy" if owner == "policy" else ("yours" if owner in UNMANAGED else "managed")}
    d.update(extra)
    return d


def classify_rule(r, ctx):
    c = (r.get("comment") or "").strip()
    wan = ctx.wan
    hp = ctx.honeypot
    port = _single_port(r["dport"])
    if c == HONEYPOT_TAG or c.startswith(HONEYPOT_TAG + ":"):
        return _mk("honeypot", "Tagged %s" % HONEYPOT_TAG)
    if c.startswith("tuxwall-canary"):
        return _mk("canary", "Tagged %s" % c)
    if c.startswith("tuxwall-policy:"):
        return _mk("policy", "Interfaces policy cell %s" % c.split(":", 1)[1])
    if c.startswith("tuxwall: ") or c.startswith("tuxwall:"):
        return _mk("nat", "Installer forwarding rule (%s)" % c)
    if (not r["route"] and r["dir"] == "in" and r["action"] == "allow" and r["proto"] == "tcp"
            and wan and r["in"] == wan and _any(r["src"]) and _any(r["dst"])
            and port in hp["ports"]):
        why = "Honeypot port %d on the WAN (%s), matched by the honeypot config" % (port, wan)
        if not hp["enabled"]:
            why += " — the honeypot is disabled, so this is a leftover"
        return _mk("honeypot", why, matched_by="config")
    wg = ctx.wg
    if (not r["route"] and r["dir"] == "in" and wan and r["in"] == wan
            and r["proto"] in ("udp", "any") and port == wg["port"]):
        return _mk("wireguard", "WireGuard listen port %d on the WAN" % wg["port"])
    if (not r["route"] and r["in"] == wg["iface"] and port == 53
            and (_in_nets(r["src"], wg["nets"]))):
        return _mk("wireguard", "DNS for VPN clients (ensure_wg_routing)")
    if port == 5353 and r["proto"] in ("udp", "any") and not r["route"]:
        return _mk("mdns", "mDNS reflector port 5353")
    if "dhcpv6" in c.lower() or (r["family"] == "v6" and r["proto"] == "udp"
                                 and port in (546, 547) and str(r["dst"]).startswith("fe80")):
        return _mk("management", "DHCPv6 (router addressing)")
    if (not r["route"] and r["action"] == "allow" and r["dir"] == "in" and r["in"]
            and r["in"] == ctx.lan and r["proto"] == "any" and r["dport"] == "any"
            and _any(r["src"])):
        return _mk("management", "Allows the LAN to reach the router (dashboard, SSH, DNS)")
    return _mk("user", "")


def classify(rs, ctx):
    """{"ufw": [classification per numbered rule], "raw": [...], "before": [...]}"""
    out = {"ufw": [], "raw": [], "before": []}
    for n, r in enumerate(numbered(rs), 1):
        c = classify_rule(r, ctx)
        c.update({"number": n, "text": r["text"], "family": r["family"], "key": r["key"]})
        out["ufw"].append(c)
    for fam in ("v4", "v6"):
        for item in raw_rules((rs.get("raw") or {}).get(fam) or "", fam):
            item.update(classify_raw(item, ctx))
            out["raw"].append(item)
        bname = "before.rules" if fam == "v4" else "before6.rules"
        for ln in rs["texts"].get(bname, "").splitlines():
            if ln.startswith("-A ") and "--uid-owner" in ln:
                item = {"family": fam, "table": "filter", "chain": ln.split()[1], "line": ln}
                item.update(classify_raw(item, ctx))
                out["before"].append(item)
    return out


def raw_rules(text, family):
    """Non-ufw rules of an iptables-save dump (plus ufw-before-output owner rules)."""
    table, out = "", []
    pre = "ufw-" if family == "v4" else "ufw6-"
    for ln in (text or "").splitlines():
        if ln.startswith("*"):
            table = ln[1:].strip()
        elif ln.startswith("-A "):
            f = ln.split()
            chain = f[1]
            target = f[f.index("-j") + 1] if "-j" in f else ""
            if chain.startswith(pre) and "--uid-owner" not in ln:
                continue
            if target.startswith(pre) and chain in ("INPUT", "FORWARD", "OUTPUT"):
                continue
            out.append({"family": family, "table": table, "chain": chain, "line": ln,
                        "target": target})
    return out


def classify_raw(item, ctx):
    ln = item["line"]
    chain = item["chain"]
    wan, lan = ctx.wan, ctx.lan
    wg = ctx.wg["iface"]
    if "CROWDSEC" in ln:
        return _mk("crowdsec", "CrowdSec bouncer chain/hook (managed by the bouncer)")
    if "TUXWALL-TRIPWIRE" in ln:
        return _mk("tripwire", "Tripwire lockdown rule")
    m = re.search(r"--uid-owner (\S+)", ln)
    if m:
        who = m.group(1)
        if who in ("opencanary", ctx.opencanary_uid or "-"):
            return _mk("canary-egress", "Canary egress containment (before.rules)")
        if who in ("forumrun", ctx.uid_of("forumrun") or "-"):
            return _mk("forum-egress", "Forum php-fpm egress containment (before.rules)")
    if item["table"] == "nat":
        if "MASQUERADE" in ln:
            if any(("-s " + n) in ln for n in ctx.wg["nets"]):
                return _mk("wireguard", "VPN client masquerade (ensure_wg_routing)")
            return _mk("nat", "LAN → WAN masquerade (tuxwall-nat)")
        if "DNAT" in ln:
            return _mk("portforward", "Port forward DNAT")
    if chain in ("FORWARD", "INPUT") and re.search(r"(-i|-o) %s\b" % re.escape(wg), ln):
        return _mk("wireguard", "Raw WireGuard accept (ensure_wg_routing) — bypasses ufw")
    if chain == "FORWARD":
        for dmz in ctx.dmz["ips"]:
            if " %s/32 " % dmz in ln + " " or " %s " % dmz in ln + " ":
                return _mk("dmz", "DMZ isolation for %s" % dmz)
        if wan and lan and ("-i %s -o %s" % (wan, lan)) in ln and "ACCEPT" in ln:
            return _mk("portforward", "Port forward accept")
    return _mk("user", "Raw iptables rule outside ufw")


# ── invariants ───────────────────────────────────────────────────────────────

def _v(vid, severity, title, detail="", repair=None, owner=""):
    return {"id": vid, "severity": severity, "title": title, "detail": detail,
            "repair": repair, "owner": owner}


def _has_allow(rules, iface, proto, port):
    for r in rules:
        if (not r["route"] and r["dir"] == "in" and r["action"] in ("allow", "limit")
                and r["in"] == iface and r["proto"] in (proto, "any")):
            p = _ports(r["dport"])
            if p is None or port in p:
                return True
    return False


def evaluate_input(rules, defaults, pkt):
    """First-match evaluation of ufw input rules for pkt {iface, src, dst, proto, dport}.
    Returns (allowed: bool, rule|None)."""
    try:
        src = ipaddress.ip_address(pkt["src"])
    except ValueError:
        return True, None
    dst = None
    try:
        dst = ipaddress.ip_address(pkt.get("dst") or "")
    except ValueError:
        pass
    for r in rules:
        if r["route"] or r["dir"] != "in" or r.get("app"):
            continue
        if r["in"] and r["in"] != pkt["iface"]:
            continue
        if r["proto"] not in ("any", pkt["proto"]):
            continue
        p = _ports(r["dport"])
        if p is not None and pkt["dport"] not in p:
            continue
        if r["sport"] != "any":
            continue
        try:
            if not _any(r["src"]) and src not in ipaddress.ip_network(r["src"], strict=False):
                continue
            if not _any(r["dst"]) and (dst is None or dst not in ipaddress.ip_network(r["dst"], strict=False)):
                continue
        except (ValueError, TypeError):
            continue
        return r["action"] in ("allow", "limit"), r
    return defaults.get("input", "DROP") == "ACCEPT", None


def deception_ports(rs, ctx):
    """{port/proto: owner} for enabled honeypot ports and canary ports present now."""
    out = {}
    hp = ctx.honeypot
    if hp["enabled"]:
        for p in hp["ports"]:
            out["%d/tcp" % p] = "honeypot"
    for r in rs["v4"] + rs["v6"]:
        if (r["comment"] or "").startswith("tuxwall-canary"):
            p = _single_port(r["dport"])
            if p:
                out["%d/%s" % (p, r["proto"])] = "canary"
    return out


def canary_egress_repair(text, fam):
    """Repair hint for missing canary containment: the exact insertion the
    installer/postinst make (preview only; applied via canary_egress.py)."""
    rep = {"kind": "before-rules-insert", "owner": "canary-egress", "family": fam,
           "file": "/etc/ufw/before.rules" if fam == "v4" else "/etc/ufw/before6.rules",
           "cmd": ["python3", "/var/www/html/includes/canary_egress.py", "--apply"]}
    if _CE is not None:
        new, changed = _CE.insert(text or "", fam)
        rep["lines"] = _CE.LINES[fam]
        rep["anchor"] = _CE.ANCHORS[fam]
        rep["applicable"] = changed
        if changed:
            import difflib
            rep["diff"] = "".join(difflib.unified_diff(
                (text or "").splitlines(True), new.splitlines(True), rep["file"], rep["file"], n=2))
    return rep


def invariants(rs, ctx, cur=None):
    """Violations of the safety invariants for ruleset rs. ``cur`` (the live
    ruleset) supplies the canary ports that must stay open."""
    v = []
    wan = ctx.wan
    fams = [f for f in ("v4", "v6") if rs[f] or f == "v4"]
    cls = {r["key"]: classify_rule(r, ctx) for r in rs["v4"] + rs["v6"]}

    # 1. honeypot ports present (WAN-only) while enabled
    hp = ctx.honeypot
    if hp["enabled"] and wan:
        for p in hp["ports"]:
            for fam in fams:
                if not _has_allow(rs[fam], wan, "tcp", p):
                    v.append(_v("honeypot-missing:%d:%s" % (p, fam), "high",
                                "Honeypot port %d/tcp is not open on the WAN (%s)" % (p, fam),
                                "The honeypot is enabled; without this rule it catches nothing.",
                                {"kind": "ufw-add", "family": fam,
                                 "rule": "allow in on %s to any port %d proto tcp comment %s"
                                         % (wan, p, HONEYPOT_TAG)}, "honeypot"))
    # 2. canary ports present while the canary runs
    if ctx.canary_installed and ctx.canary_active and cur is not None:
        want = {(r["family"], r["dport"], r["proto"], r["comment"]) for r in cur["v4"] + cur["v6"]
                if (r["comment"] or "").startswith("tuxwall-canary")}
        have = {(r["family"], r["dport"], r["proto"], r["comment"]) for r in rs["v4"] + rs["v6"]
                if (r["comment"] or "").startswith("tuxwall-canary")}
        for fam, port, proto, com in sorted(want - have):
            v.append(_v("canary-missing:%s:%s:%s" % (port, proto, fam), "high",
                        "Canary port %s/%s would be closed (%s)" % (port, proto, fam),
                        "The canary is running; its decoy port must stay open on the WAN.",
                        {"kind": "ufw-add", "family": fam,
                         "rule": "allow in on %s to any port %s proto %s comment %s"
                                 % (wan, port, proto, com)}, "canary"))
    # deception rules must be WAN-only
    dports = deception_ports(rs, ctx)
    for r in rs["v4"] + rs["v6"]:
        c = cls[r["key"]]
        p = _ports(r["dport"])
        if r["route"] or r["dir"] != "in" or r["action"] not in ("allow", "limit"):
            continue
        if c["owner"] in ("honeypot", "canary") and r["in"] != wan:
            v.append(_v("deception-not-wan:%s" % r["key"], "high",
                        "Deception rule is not limited to the WAN: %s" % r["text"],
                        "Honeypot/canary ports must only be opened on %s." % (wan or "the WAN"),
                        {"kind": "refuse"}, c["owner"]))
        elif c["owner"] not in ("honeypot", "canary") and p is not None and not r["in"]:
            hit = sorted(x for x in dports if int(x.split("/")[0]) in p
                         and r["proto"] in (x.split("/")[1], "any"))
            if hit:
                v.append(_v("deception-everywhere:%s" % r["key"], "high",
                            "Rule opens deception port %s on every interface" % ", ".join(hit),
                            r["text"], {"kind": "refuse"}, "honeypot"))
    # 3. canary egress containment (files, both families)
    if ctx.opencanary_user:
        uid = ctx.opencanary_uid
        for fam, name, vid in (("v4", "before.rules", "canary-egress-missing"),
                               ("v6", "before6.rules", "canary-egress-missing-v6")):
            b = rs["texts"].get(name, "")
            if fam == "v6" and not b:
                continue
            if _CE is not None:
                ok = _CE.present(b, fam, uid)
            else:
                ok = any(("--uid-owner opencanary" in l or "--uid-owner %s " % uid in l + " ")
                         and "-j REJECT" in l for l in b.splitlines() if l.startswith("-A "))
            if not ok:
                v.append(_v(vid, "critical",
                            "Canary egress containment is missing from %s" % name,
                            "The opencanary user exists; without the owner-match REJECT in "
                            "%s a compromised canary can reach the LAN and the internet (%s)."
                            % ("ufw-before-output" if fam == "v4" else "ufw6-before-output", fam),
                            canary_egress_repair(b, fam), "canary-egress"))
        # loaded in the kernel? (files right but `ufw reload` never ran)
        save = (rs.get("raw") or {}).get("v4") or ""
        if uid and ":ufw-before-output" in save and _CE is not None and _CE.present(rs["texts"].get("before.rules", ""), "v4", uid):
            if not _CE.present(save, "v4", uid):
                v.append(_v("canary-egress-not-loaded", "high",
                            "Canary egress containment is in before.rules but not active",
                            "iptables has no owner-match REJECT for uid %s in ufw-before-output; "
                            "`ufw reload` loads it." % uid,
                            {"kind": "run", "cmd": ["ufw", "reload"]}, "canary-egress"))
    # 4. tripwire
    tw = ctx.tripwire
    raw = rs.get("raw") or {}
    # keyed on the TRIP (its own mode), not the configured mode: switching
    # to logonly/disabled while tripped leaves the lockdown in force
    if tw["tripped"] and raw.get("v4"):
        if not re.search(r'--comment "?TUXWALL-TRIPWIRE"? -j DROP', raw.get("v4", "")):
            v.append(_v("tripwire-hook-missing", "critical",
                        "Tripwire is tripped but its lockdown rule is missing",
                        "Tripped in %s mode; run `tuxwall-tripwire enforce` (the service "
                        "re-applies it every 15 s)." % str(tw.get("trip_mode") or "medium").upper(),
                        {"kind": "run", "cmd": ["/usr/local/sbin/tuxwall-tripwire", "enforce"]},
                        "tripwire"))
    # 5. CrowdSec hook first
    for fam in ("v4", "v6"):
        txt = raw.get(fam) or ""
        if not txt or ":CROWDSEC_CHAIN" not in txt:
            continue
        for chain in ctx.crowdsec_chains:
            first = next((l for l in txt.splitlines() if l.startswith("-A %s " % chain)), "")
            if "-j CROWDSEC_CHAIN" not in first:
                v.append(_v("crowdsec-not-first:%s:%s" % (chain, fam), "high",
                            "CrowdSec hook is not the first rule in %s (%s)" % (chain, fam),
                            "First rule is: %s" % (first or "(none)"),
                            {"kind": "bouncer-restart"}, "crowdsec"))
    # 6. deception port collisions
    for key, owner in sorted(dports.items()):
        port, proto = int(key.split("/")[0]), key.split("/")[1]
        for l in ctx.listeners:
            if l["port"] == port and l["proto"].startswith(proto) and l["addr"] in ("0.0.0.0", "::", "*"):
                v.append(_v("deception-collision:%s:%s" % (key, l["proc"]), "high",
                            "Deception port %s collides with a real service (%s on %s)"
                            % (key, l["proc"] or "?", l["addr"]),
                            "The WAN allow for the decoy also exposes the real service.",
                            {"kind": "refuse"}, owner))
        for pf in ctx.portforwards:
            if str(pf.get("ext_port")) == str(port) and pf.get("enabled", True):
                v.append(_v("deception-pf-collision:%s" % key, "high",
                            "Deception port %s is also a port forward" % key, "",
                            {"kind": "refuse"}, owner))
    # 7. default policies
    if rs["defaults"].get("input") == "ACCEPT":
        v.append(_v("default-input", "critical", "Default incoming policy is allow",
                    "Everything not explicitly denied reaches the router.",
                    {"kind": "default", "direction": "incoming", "policy": "deny"}))
    if rs["defaults"].get("forward") == "ACCEPT":
        v.append(_v("default-routed", "critical", "Default routed (forward) policy is allow",
                    "Traffic between all networks and the internet is forwarded unless denied.",
                    {"kind": "default", "direction": "routed", "policy": "deny"}))
    # 8. management ports on the WAN
    for r in rs["v4"] + rs["v6"]:
        if r["route"] or r["dir"] != "in" or r["action"] not in ("allow", "limit"):
            continue
        if r["in"] and r["in"] != wan:
            continue
        c = cls[r["key"]]
        if c["owner"] in ("honeypot", "canary", "wireguard"):
            continue
        p = _ports(r["dport"])
        hit = sorted(set(MGMT_PORTS) if p is None else set(MGMT_PORTS) & p)
        if not hit:
            continue
        if r["family"] == "v6" and str(r["dst"]).startswith("fe80"):
            continue
        sev = "high" if _any(r["src"]) else "medium"
        if p is None and _any(r["src"]):
            sev = "critical"
        v.append(_v("mgmt-wan:%s" % r["key"], sev,
                    "Management port%s %s allowed from the WAN" % (
                        "s" if len(hit) > 1 else "", ",".join(map(str, hit))),
                    "%s%s" % (r["text"], "" if r["in"] else " (no interface: applies to the WAN too)"),
                    {"kind": "refuse"}, c["owner"]))
    # 9. lockout: the admin's own path to the dashboard
    if ctx.client_ip and ctx.client_iface and ctx.client_iface != "lo":
        try:
            fam = "v6" if ipaddress.ip_address(ctx.client_ip).version == 6 else "v4"
        except ValueError:
            fam = None
        if fam:
            raw_ok = False
            for l in (raw.get(fam) or "").splitlines():
                if (l.startswith("-A INPUT ") and "-j ACCEPT" in l and "-i %s " % ctx.client_iface in l
                        and "--dport" not in l and "-s " not in l):
                    raw_ok = True
            res = [evaluate_input(rs[fam], rs["defaults"],
                                  {"iface": ctx.client_iface, "src": ctx.client_ip,
                                   "dst": ctx.client_dst, "proto": "tcp", "dport": p})
                   for p in DASHBOARD_PORTS]
            if not raw_ok and not any(a for a, _ in res):
                by = next((r for _, r in res if r), None)
                v.append(_v("lockout", "critical",
                            "This change would lock you out of the dashboard",
                            "Your session (%s via %s) could no longer reach ports 80/443%s."
                            % (ctx.client_ip, ctx.client_iface,
                               (" — blocked by: " + by["text"]) if by else " — no rule allows it"),
                            {"kind": "refuse"}, "management"))
    return v


def check(cur, prop, ctx):
    """Guard decision for a proposed ruleset: new critical/high violations
    block; violations that already exist are reported but do not block."""
    before = {x["id"]: x for x in invariants(cur, ctx, cur)}
    after = invariants(prop, ctx, cur)
    new = [x for x in after if x["id"] not in before]
    fixed = [x for x in before.values() if x["id"] not in {a["id"] for a in after}]
    blocking = [x for x in new if x["severity"] in BLOCKING]
    return {"ok": not blocking, "blocking": blocking, "new": new,
            "existing": [x for x in after if x["id"] in before], "fixed": fixed,
            "summary": ("Guard passed" if not blocking else
                        "Refused by the firewall guard: " + "; ".join(x["title"] for x in blocking))}


# ── proposals ────────────────────────────────────────────────────────────────

def _ufw_parse(argv):
    import gettext
    import ufw.common
    import ufw.frontend
    gettext.install(ufw.common.programName)
    return ufw.frontend.parse_command(["ufw"] + list(argv))


def tuples_from_rule_text(argv):
    """Parse a ufw rule (argv list) with ufw's own parser (no I/O) into tuple
    lines for each family it applies to: {"v4": line|None, "v6": line|None}."""
    pr = _ufw_parse(argv)
    r = pr.data.get("rule")
    if r is None:
        raise ValueError("not a rule")
    iptype = pr.data.get("iptype", "both")
    out = {"v4": None, "v6": None}
    for fam in ("v4", "v6"):
        if iptype not in ("both", fam):
            continue
        src, dst = r.src, r.dst
        if fam == "v6" and iptype == "both":
            src = "::/0" if src == "0.0.0.0/0" else src
            dst = "::/0" if dst == "0.0.0.0/0" else dst
        act = ("route:" if r.forward else "") + r.action
        if r.direction == "out":
            d = "out" + ("_" + r.interface_out if r.interface_out else "")
        elif r.interface_in or r.interface_out:
            segs = []
            if r.interface_in:
                segs.append("in_" + r.interface_in)
            if r.interface_out:
                segs.append("out_" + r.interface_out)
            d = "!".join(segs)
        else:
            d = "in"
        line = "### tuple ### %s %s %s %s %s %s %s" % (act, r.protocol, r.dport, dst, r.sport, src, d)
        if r.comment:
            line += " comment=" + r.comment
        out[fam] = line
    return out


def proposed_add(rs, argv):
    t = tuples_from_rule_text(argv)
    b4 = list(rs["blocks"]["v4"])
    b6 = list(rs["blocks"]["v6"])
    keys = {r["key"] for r in rs["v4"] + rs["v6"]}
    for fam, bl in (("v4", b4), ("v6", b6)):
        if t[fam]:
            nb = {"tuple": t[fam], "body": []}
            if parse_tuple(t[fam], fam)["key"] not in keys:
                bl.append(nb)
    return rebuild(rs, b4, b6), t


def proposed_delete(rs, number):
    n = int(number)
    b4, b6 = list(rs["blocks"]["v4"]), list(rs["blocks"]["v6"])
    if n <= len(b4):
        del b4[n - 1]
    else:
        del b6[n - 1 - len(b4)]
    return rebuild(rs, b4, b6)


def proposed_move(rs, number, direction):
    n = int(number)
    b4, b6 = list(rs["blocks"]["v4"]), list(rs["blocks"]["v6"])
    bl, i = (b4, n - 1) if n <= len(b4) else (b6, n - 1 - len(b4))
    j = i - 1 if direction == "up" else i + 1
    if 0 <= j < len(bl):
        bl[i], bl[j] = bl[j], bl[i]
    return rebuild(rs, b4, b6)


def proposed_default(rs, direction, policy):
    key = {"incoming": "input", "outgoing": "output", "routed": "forward"}[direction]
    val = {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT"}[policy]
    return rebuild(rs, defaults={key: val})


def rule_by_number(rs, number):
    rules = numbered(rs)
    try:
        n = int(number)
    except (TypeError, ValueError):
        return None
    return rules[n - 1] if 1 <= n <= len(rules) else None


def managed_refusal(c, verb="deleted"):
    where = c.get("label") or "TuxWall"
    return ("This rule is managed by %s and can't be %s from the Rules tab. "
            "Change it where it is managed%s." % (
                where, verb, (" (%s)" % c["reason"]) if c.get("reason") else ""))


def summary(rs, ctx):
    """Counts + current violations, for GET /api/firewall/managed."""
    cl = classify(rs, ctx)
    groups = {"managed": 0, "policy": 0, "yours": 0}
    owners = {}
    for c in cl["ufw"]:
        groups[c["group"]] += 1
        owners[c["owner"]] = owners.get(c["owner"], 0) + 1
    return {"ok": True, "rules": cl["ufw"], "raw": cl["raw"], "before": cl["before"],
            "groups": groups, "owners": owners,
            "owner_labels": {k: v[0] for k, v in OWNERS.items()},
            "invariants": invariants(rs, ctx, rs),
            "context": {"wan": ctx.wan, "lan": ctx.lan, "honeypot": ctx.honeypot,
                        "wireguard": ctx.wg, "canary_active": ctx.canary_active,
                        "tripwire": ctx.tripwire, "crowdsec_chains": ctx.crowdsec_chains}}
