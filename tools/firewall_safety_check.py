#!/usr/bin/env python3
"""Firewall safety checks: fw_guard classification + invariants, fw_snap
snapshots (create/list/diff/restore/upload/legacy) in a temp root with a
mocked command runner.

  python3 tools/firewall_safety_check.py            pure tests (CI)
  sudo python3 tools/firewall_safety_check.py --live
        also copies the live /etc/ufw files + iptables-save (read only) into a
        temp root and checks classification of the real ruleset
  sudo python3 tools/firewall_safety_check.py --netns
        also runs a snapshot restore whose `ufw reload` loads the result into a
        scratch network namespace (twfwtest) with iptables-restore; the host
        ruleset is compared before/after and the namespace is deleted.

Nothing here ever runs ufw or writes iptables on the host.
"""
import base64
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "www", "includes"))
sys.dont_write_bytecode = True

import fw_guard as G  # noqa: E402
import fw_snap as S  # noqa: E402
import fw_lint as L  # noqa: E402
import fw_edit as E  # noqa: E402
import fw_hits as H  # noqa: E402

try:
    import ufw.frontend  # noqa: F401  (ufw's own rule parser, used by proposed_add)
    HAVE_UFW = True
except ImportError:
    sys.path.append("/usr/lib/python3/dist-packages")
    try:
        import ufw.frontend  # noqa: F401,F811
        HAVE_UFW = True
    except ImportError:
        HAVE_UFW = False

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


# ── fixtures ────────────────────────────────────────────────────────────────
WAN, LAN = "eth0", "eth1"
HEX = lambda s: s.encode().hex()  # noqa: E731


def rule_lines(t, fam):
    """(tuple line, iptables lines) for a compact rule spec dict."""
    pre = "ufw" if fam == "v4" else "ufw6"
    anyn = "0.0.0.0/0" if fam == "v4" else "::/0"
    route = t.get("route", False)
    act = t.get("action", "allow")
    proto, dport = t.get("proto", "any"), str(t.get("dport", "any"))
    src, dst = t.get("src", anyn), t.get("dst", anyn)
    iin, iout = t.get("in", ""), t.get("out", "")
    d = "!".join(([("in_" + iin)] if iin else []) + ([("out_" + iout)] if iout else [])) or "in"
    if t.get("dir") == "out":
        d = "out" + ("_" + iout if iout else "")
    tl = "### tuple ### %s%s %s %s %s any %s %s" % ("route:" if route else "", act, proto, dport, dst, src, d)
    if t.get("comment"):
        tl += " comment=" + HEX(t["comment"])
    chain = "%s-user-%s" % (pre, "forward" if route else ("output" if t.get("dir") == "out" else "input"))
    tgt = {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT", "limit": "ACCEPT"}[act]
    a = ["-A", chain]
    if iin:
        a += ["-i", iin]
    if iout:
        a += ["-o", iout]
    if proto != "any":
        a += ["-p", proto]
    if dst != anyn:
        a += ["-d", dst]
    if dport != "any":
        a += ["--dport", dport]
    if src != anyn:
        a += ["-s", src]
    a += ["-j", tgt]
    return tl, [" ".join(a)]


HEAD = """*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
:ufw-user-limit - [0:0]
:ufw-user-limit-accept - [0:0]
### RULES ###
"""
TAIL = """### END RULES ###

### LOGGING ###
### END LOGGING ###

### RATE LIMITING ###
-A ufw-user-limit -j REJECT
-A ufw-user-limit-accept -j ACCEPT
### END RATE LIMITING ###
COMMIT
"""


def user_rules(specs, fam):
    head = HEAD if fam == "v4" else HEAD.replace("ufw-", "ufw6-")
    tail = TAIL if fam == "v4" else TAIL.replace("ufw-", "ufw6-")
    out = head + "\n"
    for t in specs:
        if t.get("fam", "both") not in ("both", fam):
            continue
        tl, body = rule_lines(t, fam)
        out += tl + "\n" + "\n".join(body) + "\n\n"
    return out + tail


BASE_SPECS = [
    {"in": WAN, "proto": "udp", "dport": 51820, "comment": "WireGuard VPN"},
    {"in": "wg0", "proto": "udp", "dport": 53, "src": "10.0.0.0/24", "fam": "v4"},
    {"in": LAN, "comment": "Allow all LAN traffic"},
    {"route": True, "in": LAN, "out": WAN, "comment": "tuxwall: LAN -> WAN"},
    {"in": "wg0", "proto": "tcp", "dport": 22, "src": "10.0.0.0/24", "comment": "SSH over WireGuard", "fam": "v4"},
    {"in": "wg0", "proto": "udp", "dport": 5353, "comment": "mDNS reflector"},
    {"route": True, "in": "eth1.10", "out": WAN, "comment": "tuxwall-policy:opt1->wan"},
    {"in": WAN, "proto": "tcp", "dport": 23},
    {"in": WAN, "proto": "tcp", "dport": 445},
    # the canary binds the WAN IPv4 only: IPv4-only rule (SNMP retired)
    {"in": WAN, "proto": "tcp", "dport": 6379, "comment": "tuxwall-canary", "fam": "v4"},
]

BEFORE = """# fixture before.rules
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT
# --- Tuxwall canary (opencanary) egress containment ---
-A ufw-before-output -m owner --uid-owner opencanary -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A ufw-before-output -m owner --uid-owner opencanary -j REJECT
# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
"""
BEFORE_OLD = """# fixture before.rules (old, no containment)
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT
# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
"""
BEFORE6 = BEFORE.replace("ufw-", "ufw6-")
DEFAULT = 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="DROP"\nDEFAULT_APPLICATION_POLICY="SKIP"\nMANAGE_BUILTINS=no\nIPT_SYSCTL=/etc/ufw/sysctl.conf\nIPT_MODULES=""\n'
IPT_SAVE = """# Generated by iptables-save
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:CROWDSEC_CHAIN - [0:0]
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-user-input - [0:0]
-A INPUT -j CROWDSEC_CHAIN
-A INPUT -j ufw-before-input
-A FORWARD -i wg0 -j ACCEPT
-A FORWARD -o wg0 -j ACCEPT
-A FORWARD -m comment --comment TUXWALL-TRIPWIRE -j DROP
-A OUTPUT -j ufw-before-output
-A CROWDSEC_CHAIN -m comment --comment "CrowdSec: cscli" -j DROP
-A ufw-before-output -m owner --uid-owner 995 -j REJECT --reject-with icmp-port-unreachable
-A ufw-user-input -i eth0 -p tcp --dport 23 -j ACCEPT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -i eth0 -p tcp --dport 8443 -j DNAT --to-destination 192.168.1.20:443
-A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT
"""
SS = """tcp LISTEN 0 4096 203.0.113.5:23 0.0.0.0:* users:(("python3",pid=1,fd=3))
tcp LISTEN 0 50 203.0.113.5:6379 0.0.0.0:* users:(("twistd",pid=4,fd=7))
tcp LISTEN 0 4096 192.168.1.1:22 0.0.0.0:* users:(("sshd",pid=2,fd=3))
tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=3,fd=3))
"""


class Runner:
    def __init__(self, ipt=IPT_SAVE, ss=SS, ip6t=""):
        self.calls = []
        self.ipt, self.ip6t, self.ss = ipt, ip6t, ss
        self.reload_rc = 0

    def __call__(self, cmd, timeout=15):
        self.calls.append(list(cmd))
        c = " ".join(cmd)
        if cmd[0] == "iptables-save":
            return 0, (self.ipt_c if "-c" in cmd and getattr(self, "ipt_c", None) is not None else self.ipt)
        if cmd[0] == "ip6tables-save":
            return 0, (self.ip6t_c if "-c" in cmd and getattr(self, "ip6t_c", None) is not None else self.ip6t)
        if cmd[:4] == ["ip", "-o", "link", "show"]:
            return 0, "".join("%d: %s: <UP> mtu 1500\n" % (i, n) for i, n in
                              enumerate(["lo", WAN, LAN, "eth2", "eth1.10@eth1", "wg0"], 1))
        if cmd[:2] == ["ss", "-lntupH"]:
            return 0, self.ss
        if cmd[:2] == ["systemctl", "is-active"]:
            return 0, "active\n"
        if c.startswith("ip -o route get"):
            ip = cmd[-1]
            dev = "wg0" if ip.startswith("10.0.0.") else LAN
            return 0, "%s dev %s src 192.168.1.1 uid 0\n" % (ip, dev)
        if cmd[:2] == ["ufw", "reload"]:
            return self.reload_rc, "Firewall reloaded\n"
        if cmd[:2] == ["nft", "-j"] and "list" in cmd and "-f" not in cmd:
            nft = getattr(self, "nft", {}) or {}
            if cmd[-1] == "tables":
                return 0, json.dumps({"nftables": [{"metainfo": {}}] + [
                    {"table": {"family": f, "name": n}} for f, n in nft]})
            key = (cmd[-2], cmd[-1])
            return (0, nft[key]) if key in nft else (1, "")
        if cmd[0] in ("ufw", "iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "nft"):
            raise AssertionError("unexpected mutating command in test: %s" % c)
        return 1, ""

    def run_in(self, cmd, text):
        self.calls.append(list(cmd) + ["<stdin>"])
        return 0, ""

    def mutations(self):
        return [c for c in self.calls if c[0] in ("ufw",) or c[-1] == "<stdin>"]


def make_root(specs=None, before=BEFORE, honeypot=True, legacy=True):
    root = tempfile.mkdtemp(prefix="twfw-")
    def w(p, text, mode=0o644):
        full = root + p
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(text)
        os.chmod(full, mode)
    specs = BASE_SPECS if specs is None else specs
    w("/etc/ufw/user.rules", user_rules(specs, "v4"), 0o640)
    w("/etc/ufw/user6.rules", user_rules(specs, "v6"), 0o640)
    w("/etc/ufw/before.rules", before, 0o640)
    w("/etc/ufw/before6.rules", before.replace("ufw-", "ufw6-"), 0o640)
    w("/etc/ufw/after.rules", "*filter\nCOMMIT\n", 0o640)
    w("/etc/ufw/after6.rules", "*filter\nCOMMIT\n", 0o640)
    w("/etc/ufw/sysctl.conf", "net/ipv4/ip_forward=1\n")
    w("/etc/default/ufw", DEFAULT)
    w("/etc/tuxwall/interfaces.json", json.dumps({"version": 1, "wan": {"device": WAN},
                                                  "lan": {"device": LAN, "address": "192.168.1.1/24"},
                                                  "vpn": [{"device": "wg0", "address": "10.0.0.1/24"}]}))
    w("/var/lib/tuxwall/honeypot.json", json.dumps({"enabled": honeypot, "ports": [23, 445]}))
    w("/etc/passwd", "root:x:0:0::/root:/bin/bash\nopencanary:x:995:980::/var/lib/opencanary:/usr/sbin/nologin\n")
    w("/etc/wireguard/wg0.conf", "[Interface]\nAddress = 10.0.0.1/24, fd00:2::1/64\nListenPort = 51820\n")
    w("/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml",
      "mode: iptables\niptables_chains:\n  - INPUT\n#  - FORWARD\nother: 1\n")
    w("/etc/systemd/system/opencanary.service", "[Unit]\n")
    w("/etc/tuxwall/tripwire.json", json.dumps({"mode": "logonly"}))
    if legacy:
        w("/etc/tuxwall/fw-baseline/iptables.rules", IPT_SAVE.replace(
            "-A ufw-before-output -m owner --uid-owner 995 -j REJECT --reject-with icmp-port-unreachable\n", ""), 0o644)
        w("/etc/tuxwall/fw-baseline/ip6tables.rules", "", 0o644)
        w("/etc/tuxwall/fw-baseline/ufw-status.txt", "Status: active\n", 0o644)
    return root


def mkctx(root, run=None, client="192.168.1.50", **kw):
    run = run or Runner()
    return G.Ctx(root=root, run=run, run_in=run.run_in, client_ip=client, **kw), run


# ── tests ────────────────────────────────────────────────────────────────────

def t_classify():
    root = make_root()
    ctx, run = mkctx(root)
    rs = G.load_ruleset(ctx)
    cl = G.classify(rs, ctx)
    by = {(c["text"].split(" comment")[0], c["family"]): c for c in cl["ufw"]}
    own = lambda txt, fam="v4": by[(txt, fam)]["owner"]  # noqa: E731
    check(own("allow in on eth0 from any to any port 23 proto tcp") == "honeypot", "honeypot untagged by config")
    check(by[("allow in on eth0 from any to any port 23 proto tcp", "v4")].get("matched_by") == "config",
          "honeypot matched_by config")
    check(own("allow in on eth0 from any to any port 23 proto tcp", "v6") == "honeypot", "honeypot v6")
    check(own("allow in on eth0 from any to any port 6379 proto tcp") == "canary", "canary tag")
    check(("allow in on eth0 from any to any port 6379 proto tcp", "v6") not in by,
          "canary rule is IPv4-only (SNMP retired)")
    check(own("route allow in on eth1.10 out on eth0 from any to any") == "policy", "policy tag")
    check(by[("route allow in on eth1.10 out on eth0 from any to any", "v4")]["group"] == "policy", "policy group")
    check(own("route allow in on eth1 out on eth0 from any to any") == "nat", "installer LAN->WAN")
    check(own("allow in on eth0 from any to any port 51820 proto udp") == "wireguard", "wg port")
    check(own("allow in on wg0 from 10.0.0.0/24 to any port 53 proto udp") == "wireguard", "wg dns")
    check(own("allow in on wg0 from any to any port 5353 proto udp") == "mdns", "mdns")
    check(own("allow in on eth1 from any to any") == "management", "LAN allow-all = management")
    check(not by[("allow in on eth1 from any to any", "v4")]["managed"], "management not locked")
    check(own("allow in on wg0 from 10.0.0.0/24 to any port 22 proto tcp") == "user", "user rule")
    check(by[("allow in on wg0 from 10.0.0.0/24 to any port 22 proto tcp", "v4")]["group"] == "yours", "yours group")
    check([c["number"] for c in cl["ufw"]] == list(range(1, len(cl["ufw"]) + 1)), "numbering")
    raw = {c["line"]: c["owner"] for c in cl["raw"]}
    check(raw.get("-A INPUT -j CROWDSEC_CHAIN") == "crowdsec", "raw crowdsec hook")
    check(raw.get("-A FORWARD -i wg0 -j ACCEPT") == "wireguard", "raw wg forward")
    check(raw.get("-A FORWARD -m comment --comment TUXWALL-TRIPWIRE -j DROP") == "tripwire", "raw tripwire")
    check(raw.get("-A POSTROUTING -o eth0 -j MASQUERADE") == "nat", "raw nat")
    check(raw.get("-A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE") == "wireguard", "raw wg masq")
    check(any(o == "portforward" for l, o in raw.items() if "DNAT" in l), "raw dnat")
    check(any(o == "canary-egress" for l, o in raw.items() if "--uid-owner 995" in l), "raw canary egress uid")
    check(all(c["owner"] == "canary-egress" for c in cl["before"] if "opencanary" in c["line"]) and cl["before"],
          "before.rules canary egress")
    check(not any(l.startswith("-A ufw-user-input") for l in raw), "ufw user chains not raw")
    # honeypot disabled -> leftover still managed
    root2 = make_root(honeypot=False)
    ctx2, _ = mkctx(root2)
    c2 = G.classify_rule(G.load_ruleset(ctx2)["v4"][7], ctx2)
    check(c2["owner"] == "honeypot" and "leftover" in c2["reason"], "disabled honeypot leftover")
    # a 23/tcp rule on the LAN is not honeypot
    r = G.parse_tuple("### tuple ### allow tcp 23 0.0.0.0/0 any 0.0.0.0/0 in_eth1", "v4")
    check(G.classify_rule(r, ctx)["owner"] == "user", "port 23 on LAN is user")
    # new tagged honeypot rule
    r = G.parse_tuple("### tuple ### allow tcp 2323 0.0.0.0/0 any 0.0.0.0/0 in_eth0 comment=" +
                      HEX("tuxwall-honeypot"), "v4")
    check(G.classify_rule(r, ctx)["owner"] == "honeypot", "honeypot tag")
    check("Deception" in G.managed_refusal(G.classify_rule(r, ctx)), "refusal names the owner")
    shutil.rmtree(root)
    shutil.rmtree(root2)


def ids(vs):
    return {v["id"].split(":")[0] for v in vs}


def t_invariants():
    root = make_root()
    ctx, run = mkctx(root)
    cur = G.load_ruleset(ctx)
    base = G.invariants(cur, ctx, cur)
    check(not [v for v in base if v["severity"] in G.BLOCKING], "clean fixture: no blocking violations %s" %
          [v["id"] for v in base])
    # remove honeypot port
    prop = G.proposed_delete(cur, 8)  # v4 23/tcp
    check("honeypot-missing" in ids(G.invariants(prop, ctx, cur)), "honeypot missing detected")
    # canary egress gone
    p2 = G.rebuild(cur, files={"before.rules": BEFORE_OLD})
    check("canary-egress-missing" in ids(G.invariants(p2, ctx, cur)), "canary egress missing")
    # default incoming allow
    p3 = G.proposed_default(cur, "incoming", "allow")
    check("default-input" in ids(G.invariants(p3, ctx, cur)), "default input allow")
    p3b = G.proposed_default(cur, "routed", "allow")
    check("default-routed" in ids(G.invariants(p3b, ctx, cur)), "default routed allow")
    # management port on WAN
    p4, _ = G.proposed_add(cur, ["allow", "22/tcp"])
    v4 = G.invariants(p4, ctx, cur)
    check("mgmt-wan" in ids(v4), "22 without iface flagged")
    p5, _ = G.proposed_add(cur, ["allow", "in", "on", WAN, "to", "any", "port", "8008", "proto", "tcp"])
    check("mgmt-wan" in ids(G.invariants(p5, ctx, cur)), "8008 on WAN flagged")
    p5b, _ = G.proposed_add(cur, ["allow", "in", "on", LAN, "to", "any", "port", "8008", "proto", "tcp"])
    check("mgmt-wan" not in ids(G.invariants(p5b, ctx, cur)), "8008 on LAN fine")
    # canary decoy 22 on WAN is not a management violation
    p6, _ = G.proposed_add(cur, ["allow", "in", "on", WAN, "to", "any", "port", "22", "proto", "tcp",
                                 "comment", "tuxwall-canary"])
    check("mgmt-wan" not in ids(G.invariants(p6, ctx, cur)), "canary 22 exempt")
    # deception port opened everywhere
    p7, _ = G.proposed_add(cur, ["allow", "23/tcp"])
    check("deception-everywhere" in ids(G.invariants(p7, ctx, cur)), "deception port on all ifaces")
    # lockout: delete the LAN allow-all (only rule that allows 80/443 from the LAN)
    n = next(i for i, r in enumerate(G.numbered(cur), 1) if r["text"].startswith("allow in on eth1 from any to any"))
    p8 = G.proposed_delete(cur, n)
    g8 = G.check(cur, p8, ctx)
    check(not g8["ok"] and "lockout" in ids(g8["blocking"]), "lockout blocks deleting LAN allow")
    # deny inserted above LAN allow -> lockout via move
    p9, _ = G.proposed_add(cur, ["deny", "in", "on", LAN, "to", "any", "port", "80,443", "proto", "tcp"])
    nd = len(p9["v4"])
    for _ in range(nd - 1):
        p9 = G.proposed_move(p9, nd, "up")
        nd -= 1
    check("lockout" in ids(G.invariants(p9, ctx, cur)), "deny moved to top locks out")
    # a VPN client keeps access only via its own rules
    ctxw, _ = mkctx(root, client="10.0.0.2")
    check("lockout" in ids(G.invariants(cur, ctxw, cur)), "wg client w/o 80/443 rule = lockout (fixture)")
    # collision
    ctxc, _ = mkctx(root, run=Runner(ss=SS + 'tcp LISTEN 0 1 0.0.0.0:445 0.0.0.0:* users:(("smbd",pid=9,fd=3))\n'))
    check("deception-collision" in ids(G.invariants(cur, ctxc, cur)), "collision with real listener")
    # crowdsec not first
    bad = IPT_SAVE.replace("-A INPUT -j CROWDSEC_CHAIN\n-A INPUT -j ufw-before-input\n",
                           "-A INPUT -i eth1 -j ACCEPT\n-A INPUT -j CROWDSEC_CHAIN\n")
    rsb = G.load_ruleset(ctx, raw={"v4": bad, "v6": ""})
    check("crowdsec-not-first" in ids(G.invariants(rsb, ctx, rsb)), "crowdsec order")
    # tripwire tripped but hook missing
    with open(root + "/etc/tuxwall/tripwire.json", "w") as f:
        json.dump({"mode": "high"}, f)
    with open(root + "/etc/tuxwall/tripwire-state.json", "w") as f:
        json.dump({"tripped": True}, f)
    rst = G.load_ruleset(ctx, raw={"v4": IPT_SAVE.replace("TUXWALL-TRIPWIRE", "X"), "v6": ""})
    check("tripwire-hook-missing" in ids(G.invariants(rst, ctx, rst)), "tripwire hook")
    # mode switched to logonly/disabled while tripped: the trip still counts
    for m in ("logonly", "disabled"):
        with open(root + "/etc/tuxwall/tripwire.json", "w") as f:
            json.dump({"mode": m}, f)
        with open(root + "/etc/tuxwall/tripwire-state.json", "w") as f:
            json.dump({"tripped": True, "mode": "high"}, f)
        check("tripwire-hook-missing" in ids(G.invariants(rst, ctx, rst)), "tripwire hook (mode %s)" % m)
    # an ALLOW rule alone is not the lockdown
    rsa = G.load_ruleset(ctx, raw={"v4": IPT_SAVE.replace(
        "-A FORWARD -m comment --comment TUXWALL-TRIPWIRE -j DROP",
        "-A INPUT -i eth0 -p udp --sport 67 --dport 68 -m comment --comment TUXWALL-TRIPWIRE-ALLOW -j ACCEPT"), "v6": ""})
    check("tripwire-hook-missing" in ids(G.invariants(rsa, ctx, rsa)), "tripwire allow-only is not a lockdown")
    rok = G.load_ruleset(ctx, raw={"v4": IPT_SAVE, "v6": ""})
    check("tripwire-hook-missing" not in ids(G.invariants(rok, ctx, rok)), "tripwire hook present")
    with open(root + "/etc/tuxwall/tripwire-state.json", "w") as f:
        json.dump({"tripped": False, "mode": "high"}, f)
    check("tripwire-hook-missing" not in ids(G.invariants(rst, ctx, rst)), "not tripped: no hook needed")
    # schema v2 (per-check actions) without the derived legacy "mode" field
    for conf, want in (({"version": 2, "enabled": True, "strength": "high",
                         "checks": {"canary.egress": {"action": "block"}}}, "high"),
                       ({"version": 2, "enabled": True, "checks": {"a": {"action": "log"}}},
                        "logonly"),
                       ({"version": 2, "enabled": False, "checks": {"a": {"action": "block"}}},
                        "disabled")):
        with open(root + "/etc/tuxwall/tripwire.json", "w") as f:
            json.dump(conf, f)
        check(ctx.tripwire["mode"] == want, "tripwire v2 config -> mode %s" % want)
    with open(root + "/etc/tuxwall/tripwire.json", "w") as f:
        json.dump({"mode": "high"}, f)
    with open(root + "/etc/tuxwall/tripwire-state.json", "w") as f:
        json.dump({"tripped": True}, f)
    # guard: harmless add passes; pre-existing issues don't block
    pa, _ = G.proposed_add(cur, ["allow", "in", "on", LAN, "to", "any", "port", "8080", "proto", "tcp"])
    check(G.check(cur, pa, ctx)["ok"], "harmless add passes")
    check(not G.check(cur, p4, ctx)["ok"], "guard refuses 22 on WAN")
    check(not G.check(cur, p3, ctx)["ok"], "guard refuses default allow")
    check(G.check(p4, p4, ctx)["ok"], "existing violation does not block an unrelated change")
    # parser tuples
    t = G.tuples_from_rule_text(["allow", "in", "on", WAN, "to", "any", "port", "23", "proto", "tcp",
                                 "comment", "tuxwall-honeypot"])
    r = G.parse_tuple(t["v4"], "v4")
    check(r["comment"] == "tuxwall-honeypot" and r["in"] == WAN and t["v6"], "ufw parser -> tuple")
    t2 = G.tuples_from_rule_text(["route", "allow", "in", "on", LAN, "out", "on", WAN])
    check(G.parse_tuple(t2["v4"], "v4")["route"], "route parse")
    t3 = G.tuples_from_rule_text(["deny", "from", "1.2.3.4"])
    check(t3["v4"] and not t3["v6"], "v4-only rule")
    shutil.rmtree(root)


def _cs_table(family, table, chain, prio=-10, policy="accept", nsets=1):
    sel = "ip" if family == "ip" else "ip6"
    pre = "crowdsec-blacklists" if family == "ip" else "crowdsec6-blacklists"
    objs = [{"metainfo": {}}, {"table": {"family": family, "name": table}},
            {"chain": {"family": family, "table": table, "name": chain, "type": "filter", "hook": "input",
                       "prio": prio, "policy": policy}}]
    for i in range(nsets):
        name = "%s-origin%d" % (pre, i)
        objs.append({"set": {"family": family, "table": table, "name": name, "type": "%s_addr" % (
            "ipv4" if family == "ip" else "ipv6"), "flags": ["timeout"]}})
        objs.append({"rule": {"family": family, "table": table, "chain": chain, "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": sel, "field": "saddr"}}, "right": "@" + name}},
            {"counter": name}, {"drop": None}]}})
    return json.dumps({"nftables": objs})


NFT_BOUNCER_YAML = ("mode: nftables\ndeny_action: DROP\niptables_chains:\n  - INPUT\nnftables:\n  ipv4:\n"
                    "    enabled: true\n    table: crowdsec\n    chain: crowdsec-chain\n    priority: -10\n"
                    "  ipv6:\n    enabled: true\n    table: crowdsec6\n    chain: crowdsec6-chain\n"
                    "    priority: -10\nnftables_hooks:\n  - input\n")


def t_crowdsec_nft():
    """Bouncer in nftables mode: invariants read its tables, not CROWDSEC_CHAIN."""
    root = make_root()
    with open(root + "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml", "w") as f:
        f.write(NFT_BOUNCER_YAML)
    nft_ok = {("ip", "crowdsec"): _cs_table("ip", "crowdsec", "crowdsec-chain-input"),
              ("ip6", "crowdsec6"): _cs_table("ip6", "crowdsec6", "crowdsec6-chain-input"),
              ("inet", "tuxwall_traffic"): "{}", ("ip", "filter"): "{}", ("inet", "tuxwall_crowdsec_ranges"): "{}",
              ("inet", "mystuff"): "{}"}
    no_cs = IPT_SAVE.replace(":CROWDSEC_CHAIN - [0:0]\n", "").replace("-A INPUT -j CROWDSEC_CHAIN\n", "").replace(
        '-A CROWDSEC_CHAIN -m comment --comment "CrowdSec: cscli" -j DROP\n', "")

    def ctx_with(nft, ipt=no_cs):
        run = Runner(ipt=ipt)
        run.nft = nft
        return mkctx(root, run=run)[0]
    ctx = ctx_with(nft_ok)
    check(ctx.crowdsec["mode"] == "nftables" and ctx.crowdsec["hooks"] == ["input"], "nft mode detected")
    rs = G.load_ruleset(ctx)
    inv = G.invariants(rs, ctx, rs)
    check(not [v for v in inv if v["owner"] == "crowdsec"], "healthy nft bouncer: no crowdsec violations %r" %
          [v["id"] for v in inv if v["owner"] == "crowdsec"])
    check(not [v for v in inv if v["severity"] in G.BLOCKING], "healthy nft fixture: nothing blocking")
    # no CROWDSEC_CHAIN in iptables is fine in nft mode (no "not first"), a leftover one is low
    ctx2 = ctx_with(nft_ok, ipt=IPT_SAVE.replace("-A INPUT -j CROWDSEC_CHAIN\n", ""))
    rs2 = G.load_ruleset(ctx2)
    inv2 = G.invariants(rs2, ctx2, rs2)
    check("crowdsec-not-first" not in ids(inv2) and
          [v["severity"] for v in inv2 if v["id"].startswith("crowdsec-stale-iptables")] == ["low"],
          "nft mode: leftover CROWDSEC_CHAIN is low, no ordering check %r" % ids(inv2))
    miss = dict(nft_ok)
    del miss[("ip6", "crowdsec6")]
    ctx3 = ctx_with(miss)
    rs3 = G.load_ruleset(ctx3)
    v3 = {v["id"]: v for v in G.invariants(rs3, ctx3, rs3)}
    check(v3.get("crowdsec-nft-missing:v6", {}).get("severity") == "high"
          and v3["crowdsec-nft-missing:v6"]["repair"] == {"kind": "bouncer-restart"}, "missing v6 table = high")
    bad = dict(nft_ok)
    bad[("ip", "crowdsec")] = _cs_table("ip", "crowdsec", "crowdsec-chain-input", prio=0)
    ctx4 = ctx_with(bad)
    rs4 = G.load_ruleset(ctx4)
    check([v["severity"] for v in G.invariants(rs4, ctx4, rs4) if v["id"].startswith("crowdsec-nft-priority")]
          == ["medium"], "priority not before ufw = medium")
    hk = dict(nft_ok)
    hk[("ip", "crowdsec")] = _cs_table("ip", "crowdsec", "crowdsec-chain-forward")
    ctx5 = ctx_with(hk)
    rs5 = G.load_ruleset(ctx5)
    check("crowdsec-nft-hook-missing:v4:input" in {v["id"] for v in G.invariants(rs5, ctx5, rs5)},
          "input hook missing = flagged")
    # findings carry the bouncer-restart fix
    fs = L.findings(rs3, ctx3)
    f6 = [f for f in fs if f["id"] == "guard:crowdsec-nft-missing:v6"]
    check(f6 and f6[0]["fix"]["kind"] == "manual" and "restart crowdsec-firewall-bouncer" in f6[0]["fix"]["steps"][0],
          "finding with restart fix")
    # nft table ownership
    own = {(c["family"], c["table"]): c["owner"] for c in G.classify_nft(ctx)}
    check(own == {("ip", "crowdsec"): "crowdsec", ("ip6", "crowdsec6"): "crowdsec",
                  ("inet", "tuxwall_crowdsec_ranges"): "crowdsec", ("inet", "tuxwall_traffic"): "traffic",
                  ("ip", "filter"): "iptables-nft", ("inet", "mystuff"): "user"}, "nft table owners %r" % own)
    s = G.summary(rs, ctx)
    check(s["context"]["crowdsec"]["mode"] == "nftables" and s["nft"] and
          s["context"]["crowdsec"]["families"]["v4"]["priority"] == -10, "summary context")
    # iptables mode: the bouncer table name is a leftover, ordering check still active
    with open(root + "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml", "w") as f:
        f.write("mode: iptables\niptables_chains:\n  - INPUT\n")
    ctx6 = ctx_with(nft_ok, ipt=IPT_SAVE)
    own6 = {(c["family"], c["table"]): c for c in G.classify_nft(ctx6)}
    check("left from nftables mode" in own6[("ip", "crowdsec")]["reason"], "iptables mode: leftover nft table")
    bad6 = IPT_SAVE.replace("-A INPUT -j CROWDSEC_CHAIN\n-A INPUT -j ufw-before-input\n",
                            "-A INPUT -i eth1 -j ACCEPT\n-A INPUT -j CROWDSEC_CHAIN\n")
    rs6 = G.load_ruleset(ctx6, raw={"v4": bad6, "v6": ""})
    i6 = ids(G.invariants(rs6, ctx6, rs6))
    check("crowdsec-not-first" in i6 and "crowdsec-nft-missing" not in i6, "iptables mode keeps the ordering check")
    check(not any(c[0] == "nft" for c in ctx6.run.calls if "table" in c), "iptables mode: bouncer tables not read")
    shutil.rmtree(root)


def _snap_files(root, sid):
    return S.load_files(G.Ctx(root=root, run=Runner()), sid)[1]


def t_snapshots():
    old_specs = [s for s in BASE_SPECS if "canary" not in s.get("comment", "")
                 and s.get("dport") != 445 and "policy" not in s.get("comment", "")] + [
        {"in": LAN, "proto": "tcp", "dport": 8080, "comment": "old user rule"}]
    root = make_root(specs=old_specs, before=BEFORE_OLD)
    ctx, run = mkctx(root)
    m_old = S.create(ctx, note="old", kind="manual", who="t", version="test")
    check(m_old["kind"] == "manual" and m_old["counts"]["ufw_v4"] > 0, "create manual")
    st = os.stat(root + S.SNAP_DIR + "/" + m_old["id"] + "/user.rules")
    check(oct(st.st_mode & 0o777) == "0o600", "snapshot files 600")
    check(oct(os.stat(root + S.SNAP_DIR).st_mode & 0o777) == "0o700", "snapshot dir 700")
    m_dup = S.create(ctx, kind="auto", dedupe=True)
    check(m_dup.get("deduplicated") and m_dup["id"] == m_old["id"], "auto dedupe")
    # move to the "current" state: canary rules, policy tag, containment, a new user rule
    cur_root = make_root(specs=BASE_SPECS + [{"in": LAN, "proto": "tcp", "dport": 9000, "comment": "new"}])
    for n in ("user.rules", "user6.rules", "before.rules", "before6.rules"):
        shutil.copy(cur_root + "/etc/ufw/" + n, root + "/etc/ufw/" + n)
    shutil.rmtree(cur_root)
    d = S.diff(ctx, m_old["id"])
    texts = " | ".join(c["text"] for c in d["changes"])
    check("Only in the snapshot: allow in on eth1 from any to any port 8080 proto tcp" in texts, "diff only-snapshot")
    check("Added since the snapshot" in texts and "(managed; kept on restore)" in texts, "diff managed kept")
    check("user.rules" in d["unified"] and d["unified"]["user.rules"].startswith("--- snapshot/"), "unified diff")
    lst = S.listing(ctx)
    check(len(lst["snapshots"]) == 1 and lst["legacy"]["present"] and not lst["legacy"]["restorable"],
          "listing + legacy entry")
    # restore plan: owned rules come from the current state
    plan = S.plan_restore(ctx, m_old["id"])
    check(plan["guard"]["ok"], "restore plan passes guard: %s" % plan["guard"]["summary"])
    nu = plan["files"]["user.rules"]
    check(HEX("tuxwall-canary") in nu and HEX("tuxwall-policy:opt1->wan") in nu, "canary/policy kept")
    check("--dport 445" in nu, "honeypot 445 kept")
    check("--dport 8080" in nu and "--dport 9000" not in nu, "user rules from snapshot")
    check("--uid-owner opencanary -j REJECT" in plan["files"]["before.rules"], "containment kept in before.rules")
    check(any("9000" in r for r in plan["rules_removed"]), "plan lists removed user rule")
    # relative order: policy rule stays before honeypot rules
    check(nu.index(HEX("tuxwall-policy:opt1->wan")) < nu.index("--dport 23 "), "managed order kept")
    # real restore with mocked runner
    sched = {}
    def schedule(cid, desc, fn, ttl):
        sched[cid] = fn
    before_cur = {k: open(root + p).read() for k, p in S.UFW_FILES.items()}
    res = S.restore(ctx, m_old["id"], who="t", reapply=[("noop", lambda: None)], schedule=schedule)
    check(res["ok"] and res["needs_confirmation"] in sched, "restore scheduled confirm")
    check(["ufw", "reload"] in run.calls, "ufw reload via runner")
    after = open(root + "/etc/ufw/user.rules").read()
    check(after == nu, "user.rules written")
    check(oct(os.stat(root + "/etc/ufw/user.rules").st_mode & 0o777) == "0o640", "mode preserved")
    try:
        S.restore(ctx, m_old["id"], schedule=schedule)
        check(False, "second restore refused while pending")
    except S.Refused as e:
        check(e.status == 409, "second restore refused while pending")
    sched[res["needs_confirmation"]]()   # timeout -> revert
    now = {k: open(root + p).read() for k, p in S.UFW_FILES.items()}
    check(now == before_cur, "revert restores the previous files")
    # reload failure -> immediate rollback
    run.reload_rc = 1
    try:
        S.restore(ctx, m_old["id"], schedule=schedule)
        check(False, "reload failure raises")
    except S.Refused as e:
        check(e.status == 500, "reload failure raises")
    run.reload_rc = 0
    now2 = {k: open(root + p).read() for k, p in S.UFW_FILES.items()}
    check(now2 == before_cur, "reload failure rolled back")
    # guard refusal: a snapshot that would drop the LAN allow -> lockout
    lock_specs = [s for s in BASE_SPECS if s.get("comment") != "Allow all LAN traffic"]
    lr = make_root(specs=lock_specs)
    lctx, _ = mkctx(lr)
    ml = S.create(lctx, note="no lan")
    for n in ("user.rules", "user6.rules"):
        shutil.copy(root + "/etc/ufw/" + n, lr + "/etc/ufw/" + n)
    try:
        S.restore(lctx, ml["id"], schedule=schedule)
        check(False, "lockout restore refused")
    except S.Refused as e:
        check(e.status == 409 and "lock you out" in e.payload["error"], "lockout restore refused")
    shutil.rmtree(lr)
    # retention
    for i in range(25):
        S.create(ctx, kind="auto", note=str(i))
    autos = [m for m in S.list_snaps(ctx) if m["kind"] == "auto"]
    check(len(autos) == S.KEEP_AUTO, "retention keeps 20 auto (%d)" % len(autos))
    check(any(m["id"] == m_old["id"] for m in S.list_snaps(ctx)), "manual kept")
    # download / upload
    data, name = S.download(ctx, m_old["id"])
    check(name.endswith(".tar.gz") and len(data) > 100, "download")
    up = S.upload(ctx, base64.b64encode(data).decode(), note="up")
    check(up["ok"] and up["snapshot"]["kind"] == "upload", "upload roundtrip")
    check(_snap_files(root, up["id"])["user.rules"] == _snap_files(root, m_old["id"])["user.rules"], "upload content")
    def tgz(files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for n, t in files.items():
                b = t.encode()
                ti = tarfile.TarInfo(n)
                ti.size = len(b)
                tar.addfile(ti, io.BytesIO(b))
        return base64.b64encode(buf.getvalue()).decode()
    good = {k: v for k, v in _snap_files(root, m_old["id"]).items() if k in S.UFW_FILES}
    for label, files in (
            ("shell in ufw.default", dict(good, **{"ufw.default": good["ufw.default"] + 'IPT_MODULES="$(reboot)"\n'})),
            ("unknown key", dict(good, **{"ufw.default": good["ufw.default"] + "EVIL=1\n"})),
            ("bad rules line", dict(good, **{"before.rules": good["before.rules"] + "rm -rf /\n"})),
            ("missing file", {k: v for k, v in good.items() if k != "user.rules"})):
        try:
            S.upload(ctx, tgz(files))
            check(False, "upload rejects " + label)
        except S.Refused as e:
            check(e.status == 400, "upload rejects " + label)
    try:
        S.upload(ctx, tgz({"../user.rules": "x"}))
        check(False, "upload rejects traversal")
    except S.Refused as e:
        check(e.status == 400, "upload rejects traversal")
    try:
        S.upload(ctx, base64.b64encode(b"x" * (S.UPLOAD_MAX + 1)).decode())
        check(False, "upload size cap")
    except S.Refused as e:
        check(e.status == 413, "upload size cap")
    # legacy baseline
    lp = S.legacy_restore_plan(ctx)
    check(not lp["ok"] and any(x["owner"] == "canary-egress" for x in lp["lost"]), "legacy refused (canary egress)")
    try:
        S.legacy_restore(ctx)
        check(False, "legacy restore refused")
    except S.Refused as e:
        check(e.status == 409, "legacy restore refused")
    check(not [c for c in run.calls if c[-1] == "<stdin>"], "no iptables-restore on refusal")
    imp = S.import_legacy(ctx, who="t")
    check(imp["ok"] and imp["snapshot"]["kind"] == "legacy", "import legacy")
    check(S.import_legacy(ctx)["already"], "import legacy idempotent")
    try:
        S.plan_restore(ctx, imp["id"])
        check(False, "legacy snapshot not restorable")
    except S.Refused as e:
        check(e.status == 409, "legacy snapshot not restorable")
    dl = S.diff(ctx, imp["id"])
    check(any(c["kind"] == "owned-lost" for c in dl["changes"]), "legacy diff lists owned rules lost")
    check(os.path.exists(root + "/etc/tuxwall/fw-baseline/iptables.rules"), "legacy dir untouched")
    check(S.delete(ctx, up["id"])["ok"] and not S._read_meta(ctx, up["id"]), "delete")
    check(not S._valid_id("../etc") and not S._valid_id("x"), "id validation")
    # user chains only (legacy)
    uc = S.user_chains_only(IPT_SAVE, "v4")
    check(":ufw-user-input" in uc and "CROWDSEC" not in uc and "uid-owner" not in uc, "legacy user chains only")
    # live-format validation accepts our own files
    check(not S.validate_files(good), "validate accepts snapshot files")
    shutil.rmtree(root)


def t_live():
    """Read-only copy of the live ufw files + iptables-save into a temp root."""
    root = tempfile.mkdtemp(prefix="twfw-live-")
    for p in list(S.UFW_FILES.values()) + ["/etc/tuxwall/interfaces.json", "/var/lib/tuxwall/honeypot.json",
                                            "/etc/passwd", "/etc/wireguard/wg0.conf",
                                            "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml",
                                            "/etc/tuxwall/tripwire.json", "/etc/tuxwall/tripwire-state.json",
                                            "/etc/systemd/system/opencanary.service"]:
        if os.path.exists(p):
            os.makedirs(os.path.dirname(root + p), exist_ok=True)
            shutil.copy(p, root + p)
    live_run = G._default_runner
    def ro(cmd, timeout=15):
        if cmd[0] in ("iptables-save", "ip6tables-save", "ss", "systemctl", "ip"):
            if cmd[0] == "systemctl" and cmd[1] != "is-active":
                raise AssertionError(cmd)
            if cmd[0] == "ip" and cmd[1:3] not in (["route", "show"], ["-o", "route"]):
                raise AssertionError(cmd)
            return live_run(cmd, timeout)
        if cmd[:2] == ["nft", "-j"] and "list" in cmd and "-f" not in cmd:
            return live_run(cmd, timeout)
        raise AssertionError("not read-only: %s" % cmd)
    ctx = G.Ctx(root=root, run=ro, client_ip="192.168.1.50")
    rs = G.load_ruleset(ctx)
    cl = G.classify(rs, ctx)
    ufw_n = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True).stdout
    rows = [l for l in ufw_n.splitlines() if re.match(r"^\[\s*\d+\]", l)]
    check(len(rows) == len(cl["ufw"]), "live: numbered rows = tuples (%d/%d)" % (len(rows), len(cl["ufw"])))
    hp = ctx.honeypot
    for c, row in zip(cl["ufw"], rows):
        m = re.match(r"^\[\s*\d+\]\s+(\d+)/tcp(?: \(v6\))? on (\S+)\s+ALLOW IN\s+Anywhere(?: \(v6\))?\s*$", row)
        if m and int(m.group(1)) in hp["ports"] and m.group(2) == ctx.wan:
            check(c["owner"] == "honeypot", "live honeypot row %s" % row.strip())
        if "tuxwall-canary" in row:
            check(c["owner"] == "canary", "live canary row")
    check(sum(1 for c in cl["ufw"] if c["owner"] == "honeypot") == 2 * len(hp["ports"]),
          "live: 2 x honeypot ports classified")
    if ctx.crowdsec.get("mode") == "nftables":
        own = {(c["family"], c["table"]): c["owner"] for c in G.classify_nft(ctx)}
        check(all(own.get((f["family"], f["table"])) == "crowdsec"
                  for f in ctx.crowdsec["nft"].values() if f["enabled"]), "live crowdsec (nft tables) %r" % own)
    else:
        check(any(c["owner"] == "crowdsec" for c in cl["raw"]), "live crowdsec")
    check(any(c["owner"] == "canary-egress" for c in cl["before"]), "live canary egress")
    inv = G.invariants(rs, ctx, rs)
    check(not [v for v in inv if v["severity"] == "critical"], "live: no critical violations %s" %
          [v["id"] for v in inv if v["severity"] == "critical"])
    check(not S.validate_files({k: open(p).read() for k, p in S.UFW_FILES.items()}), "live files validate")
    print("live invariants:", [(v["severity"], v["id"]) for v in inv])
    # session 2: findings on the real ruleset (read only)
    for p in ("/etc/ufw/ufw.conf", "/etc/kea/kea-dhcp4.conf", "/var/lib/kea/kea-leases4.csv",
              "/etc/tuxwall/portforward.json", "/etc/tuxwall/dmz.json"):
        if os.path.exists(p):
            os.makedirs(os.path.dirname(root + p), exist_ok=True)
            shutil.copy(p, root + p)
    def ro2(cmd, timeout=15):
        if cmd[:3] == ["ip", "-o", "link"]:
            return live_run(cmd, timeout)
        return ro(cmd, timeout)
    ctx2 = G.Ctx(root=root, run=ro2, client_ip="192.168.1.50")
    rs2 = G.load_ruleset(ctx2)
    fs = L.findings(rs2, ctx2)
    print("live findings:", [(f["severity"], f["id"].split("|")[0][:40]) for f in fs])
    check(not [f for f in fs if f["severity"] == "critical"], "live: no critical findings")
    if ctx2.wg["iface"] and "-A FORWARD -i wg0 -j ACCEPT" in (rs2["raw"] or {}).get("v4", ""):
        check(any(f["id"] == "raw-wg-forward" and f["severity"] == "high" for f in fs), "live: raw wg0 FORWARD finding")
    eno = [r for r in rs2["v4"] if r["action"] == "deny" and r["in"] == "eno1" and r["proto"] == "any"]
    if eno:
        check(any(f["id"].startswith("deny-before-allow:v4") and f["rules"][0]["key"] == eno[0]["key"] for f in fs),
              "live: eno1 deny before the worknet allows")
    check(any(f["id"] == "honeypot-untagged" and f["severity"] == "info" for f in fs), "live: untagged honeypot = info")
    cls = {r["key"]: G.classify_rule(r, ctx2) for r in rs2["v4"] + rs2["v6"]}
    fp = [f["id"] for f in fs if f["category"] in ("order", "exposure", "stale", "asymmetry")
          and not f["id"].startswith(("deny-before", "allow-before"))
          and f["rules"] and cls[f["rules"][0]["key"]]["managed"]]
    check(not fp, "live: no findings about managed/deception rules %s" % fp)
    sg = L.suggestions(rs2, ctx2, "")
    check({"tpl-ssh", "tpl-guest", "tpl-iot"} <= {s["id"] for s in sg}, "live: suggestion templates")
    if HAVE_UFW:
        bad = [b["rule"]["text"] for fam in ("v4", "v6") for b in rs2["blocks"][fam]
               if E.blocks_from_text(b["rule"]["text"])[fam] != {"tuple": b["tuple"], "body": b["body"]}]
        check(not bad, "live: every rule regenerates byte-identically %s" % bad[:3])
    saves = {f: live_run([t, "-c"])[1] for f, t in (("v4", "iptables-save"), ("v6", "ip6tables-save"))}
    m = H.map_hits(rs2, saves)
    check(m["v4"] is not None and m["v6"] is not None, "live: hit counters map (%s)" % m["errors"])
    shutil.rmtree(root)


def t_netns():
    """Snapshot restore whose `ufw reload` loads the rules into a scratch netns."""
    NS = "twfwtest"
    def host_save():
        out = ""
        for tool in ("iptables-save", "ip6tables-save"):
            out += S._norm_save(subprocess.run([tool], capture_output=True, text=True).stdout)
        return out
    host_before = host_save()
    subprocess.run(["ip", "netns", "add", NS], check=True)
    try:
        def ns(cmd, text=None):
            p = subprocess.run(["ip", "netns", "exec", NS] + cmd, input=text, capture_output=True, text=True)
            return p.returncode, p.stdout + p.stderr
        # base: live iptables-save minus ipset matches (sets don't exist in the namespace)
        live = subprocess.run(["iptables-save"], capture_output=True, text=True).stdout
        base = "\n".join(l for l in live.splitlines() if "--match-set" not in l) + "\n"
        rc, out = ns(["iptables-restore"], base)
        check(rc == 0, "netns: base ruleset loads (%s)" % out[:200])
        old_specs = [s for s in BASE_SPECS if "canary" not in s.get("comment", "")] + [
            {"in": LAN, "proto": "tcp", "dport": 8080, "comment": "old"}]
        root = make_root(specs=old_specs, before=BEFORE_OLD)
        runner = Runner()
        def ufw_reload_in_ns():
            # simulate ufw-init: user chains <- user.rules, before-output <- before.rules owner lines
            u = open(root + "/etc/ufw/user.rules").read()
            b = open(root + "/etc/ufw/before.rules").read()
            rc0, cur = ns(["iptables-save"])
            keep = [l for l in cur.splitlines() if l.startswith("-A ufw-before-output") and "--uid-owner" not in l]
            lines = ["*filter", ":ufw-user-input - [0:0]", ":ufw-user-forward - [0:0]",
                     ":ufw-user-output - [0:0]", ":ufw-before-output - [0:0]"] + keep
            lines += [l for l in u.splitlines() if l.startswith("-A ufw-user-")]
            lines += [l for l in b.splitlines() if l.startswith("-A ufw-before-output") and "--uid-owner" in l]
            lines.append("COMMIT")
            return ns(["iptables-restore", "--noflush"], "\n".join(lines) + "\n")
        def run(cmd, timeout=15):
            if cmd[:2] == ["ufw", "reload"]:
                runner.calls.append(cmd)
                return ufw_reload_in_ns()
            if cmd[0] in ("iptables-save", "ip6tables-save"):
                runner.calls.append(cmd)
                return ns(cmd)
            return runner(cmd, timeout)
        ctx = G.Ctx(root=root, run=run, run_in=lambda c, t: ns(c, t), client_ip="192.168.1.50")
        m = S.create(ctx, note="old")
        cur_root = make_root()
        for n in ("user.rules", "user6.rules", "before.rules", "before6.rules"):
            shutil.copy(cur_root + "/etc/ufw/" + n, root + "/etc/ufw/" + n)
        shutil.rmtree(cur_root)
        sched = {}
        res = S.restore(ctx, m["id"], schedule=lambda cid, d, fn, ttl: sched.setdefault(cid, fn))
        check(res["ok"], "netns: restore ok")
        rc, after = ns(["iptables-save"])
        check("-A ufw-user-input -i eth1 -p tcp -m tcp --dport 8080 -j ACCEPT" in after, "netns: user rule restored")
        check("-A ufw-user-input -i eth0 -p tcp -m tcp --dport 6379 -j ACCEPT" in after, "netns: canary rule kept")
        check("-m owner --uid-owner 995 -j REJECT" in after, "netns: canary containment kept")
        sched[res["needs_confirmation"]]()
        rc, reverted = ns(["iptables-save"])
        check("--dport 8080 -j ACCEPT" not in reverted, "netns: revert removed the restored rule")
        if HAVE_UFW:
            # session 2: edit-in-place + disable through apply_files, loaded into the netns
            S._PENDING.clear()
            rs = G.load_ruleset(ctx, raw={})
            num = next(i for i, r in enumerate(G.numbered(rs), 1)
                       if r["text"].startswith("allow in on wg0 from 10.0.0.0/24 to any port 22"))
            prop, info = E.propose_edit(rs, ctx, num, "limit in on wg0 from 10.0.0.0/24 to any port 2222 proto tcp")
            sched = {}
            res = S.apply_files(ctx, rs, prop, "edit", schedule=lambda c, d, fn, t: sched.setdefault(c, fn))
            rc, after = ns(["iptables-save"])
            check(res["ok"] and "--dport 2222" in after and "-j ufw-user-limit-accept" in after
                  and "-s 10.0.0.0/24 -i wg0 -p tcp -m tcp --dport 22 -j ACCEPT" not in after,
                  "netns: edited rule loaded (limit 2222 replaces 22)")
            sched[res["needs_confirmation"]]()
            rc, rev = ns(["iptables-save"])
            check("--dport 2222" not in rev and "--dport 22 -j ACCEPT" in rev, "netns: edit reverted")
            rs = G.load_ruleset(ctx, raw={})
            prop, info = E.propose_disable(rs, ctx, num)
            res = S.apply_files(ctx, rs, prop, "disable", schedule=lambda c, d, fn, t: sched.setdefault(c, fn),
                                side={E.DISABLED_FILE: E.disabled_text(info["records"])})
            rc, dis = ns(["iptables-save"])
            check("-s 10.0.0.0/24 -i wg0 -p tcp -m tcp --dport 22 -j ACCEPT" not in dis, "netns: disabled rule unloaded")
            S.confirmed(res["needs_confirmation"])
            rs = G.load_ruleset(ctx, raw={})
            prop, info = E.propose_enable(rs, ctx, E.load_disabled(ctx)[0]["id"])
            res = S.apply_files(ctx, rs, prop, "enable", schedule=lambda c, d, fn, t: sched.setdefault(c, fn),
                                side={E.DISABLED_FILE: E.disabled_text(info["remaining"])})
            rc, en = ns(["iptables-save"])
            check("-s 10.0.0.0/24 -i wg0 -p tcp -m tcp --dport 22 -j ACCEPT" in en, "netns: re-enabled rule loaded")
            S.confirmed(res["needs_confirmation"])
        shutil.rmtree(root)
    finally:
        subprocess.run(["ip", "netns", "del", NS])
    check(host_save() == host_before, "netns: host iptables/ip6tables unchanged")
    check(NS not in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout,
          "netns deleted")


# ── session 2: canary containment, findings, editing, hit counters ──────────

REPO = os.path.join(HERE, "..")
CANARY_DUP = BEFORE.replace("# don't delete", "# --- Tuxwall canary (opencanary) egress containment ---\n"
                            "-A ufw-before-output -m owner --uid-owner opencanary -j REJECT\n# don't delete")
LINT_SPECS = BASE_SPECS + [
    {"in": "eth2", "proto": "tcp", "dport": 53, "comment": "work DNS tcp"},
    {"in": "eth2", "action": "deny", "comment": "work: block router"},
    {"in": "eth2", "proto": "udp", "dport": 53, "comment": "work DNS udp"},
    {"in": "eth2", "proto": "udp", "dport": 67},
    {"in": "eth2", "proto": "udp", "dport": 5353, "comment": "mDNS reflector"},
    {"in": LAN, "proto": "tcp", "dport": 22, "fam": "v6", "comment": "SSH LAN only"},
    {"in": "wg0", "proto": "tcp", "dport": 8080},
    {"in": "wg0", "proto": "tcp", "dport": 8080},
]
TOPO = {"version": 1, "wan": {"device": WAN}, "lan": {"device": LAN, "address": "192.168.1.1/24"},
        "opt": [{"id": "opt1", "name": "IoT", "device": "eth1.10", "address": "192.168.10.1/24"},
                {"id": "opt2", "name": "Work", "device": "eth2", "address": "192.168.2.1/24"}],
        "vpn": [{"id": "wg0", "name": "WireGuard", "device": "wg0", "address": "10.0.0.1/24"}]}


def lint_root(specs=LINT_SPECS, before=BEFORE):
    root = make_root(specs=specs, before=before)
    with open(root + "/etc/tuxwall/interfaces.json", "w") as f:
        json.dump(TOPO, f)
    with open(root + "/etc/ufw/ufw.conf", "w") as f:
        f.write("ENABLED=yes\nLOGLEVEL=low\n")
    return root


def fids(fs):
    return {f["id"].split(":")[0] for f in fs}


def t_canary():
    import canary_egress as CE
    # missing (v4 + v6) -> critical, with the exact insertion as repair preview
    root = make_root(before=BEFORE_OLD)
    ctx, _ = mkctx(root)
    rs = G.load_ruleset(ctx)
    inv = {v["id"]: v for v in G.invariants(rs, ctx, rs)}
    check(inv.get("canary-egress-missing", {}).get("severity") == "critical", "canary: v4 missing = critical")
    check(inv.get("canary-egress-missing-v6", {}).get("severity") == "critical", "canary: v6 missing = critical")
    rep = inv["canary-egress-missing"]["repair"]
    check(rep["kind"] == "before-rules-insert" and rep["applicable"] and
          "+-A ufw-before-output -m owner --uid-owner opencanary -j REJECT" in rep["diff"], "canary: repair diff")
    fx = [f for f in L.findings(rs, ctx) if f["id"] == "guard:canary-egress-missing"]
    check(fx and fx[0]["fix"]["kind"] == "manual" and "canary_egress.py --apply" in fx[0]["fix"]["steps"][0],
          "canary: finding offers the insertion")
    # apply in the temp root (never ufw): idempotent, anchor kept, then no violation
    changed = CE.apply(root, reload=False, log=lambda *a: None)
    check(changed == ["v4", "v6"], "canary: apply inserts both families")
    t1 = open(root + "/etc/ufw/before.rules").read()
    check(CE.apply(root, reload=False, log=lambda *a: None) == [] and open(root + "/etc/ufw/before.rules").read() == t1,
          "canary: apply is idempotent")
    check(t1.index("--uid-owner opencanary -j REJECT") < t1.index("-A ufw-before-output -o lo -j ACCEPT"),
          "canary: inserted before the lo-ACCEPT anchor")
    check(CE.copies(t1, "v4") == 1 and CE.has_log(t1, "v4"), "canary: one copy, with the tripwire log line")
    rs2 = G.load_ruleset(ctx)
    check(not [v for v in G.invariants(rs2, ctx, rs2) if v["id"].startswith("canary-egress")],
          "canary: present -> no violation")
    check(CE.main(["--check", "--root", root]) == 0, "canary: --check after apply")
    # fixture with containment -> none; numeric uid in a save counts too
    ctxb, _ = mkctx(make_root())
    rsb = G.load_ruleset(ctxb)
    check(not [v for v in G.invariants(rsb, ctxb, rsb) if v["id"].startswith("canary-egress")],
          "canary: fixture with containment -> none")
    check(CE.present("-A ufw-before-output -m owner --uid-owner 995 -j REJECT --reject-with icmp-port-unreachable",
                     "v4", "995"), "canary: numeric uid (iptables-save form)")
    check(not CE.present("-A ufw-before-output -m owner --uid-owner opencanary -d 10.0.0.0/8 -j REJECT", "v4"),
          "canary: a partial REJECT is not containment")
    # kernel state: files fine, iptables has no REJECT for the uid -> not loaded
    ctxk, _ = mkctx(make_root(), run=Runner(ipt=IPT_SAVE.replace(
        "-A ufw-before-output -m owner --uid-owner 995 -j REJECT --reject-with icmp-port-unreachable\n", "")))
    rsk = G.load_ruleset(ctxk)
    check("canary-egress-not-loaded" in ids(G.invariants(rsk, ctxk, rsk)), "canary: not loaded in the kernel")
    # no opencanary user -> nothing required, apply is a no-op
    rootn = make_root(before=BEFORE_OLD)
    with open(rootn + "/etc/passwd", "w") as f:
        f.write("root:x:0:0::/root:/bin/bash\n")
    ctxn, _ = mkctx(rootn)
    rsn = G.load_ruleset(ctxn)
    check(not [v for v in G.invariants(rsn, ctxn, rsn) if v["id"].startswith("canary-egress")] and
          CE.apply(rootn, reload=False, log=lambda *a: None) == [], "canary: no user -> nothing")
    # duplicated block -> low hygiene finding with a dedupe preview
    ctxd, _ = mkctx(make_root(before=CANARY_DUP))
    fd = [f for f in L.findings(G.load_ruleset(ctxd), ctxd) if f["id"] == "before-dup:v4"]
    check(fd and fd[0]["severity"] == "low" and fd[0]["fix"] and "-# --- Tuxwall canary" in fd[0]["fix"]["diff"],
          "canary: duplicate block finding + preview")
    new, n = L.dedupe_containment(CANARY_DUP, "v4")
    check(n == 2 and CE.copies(new, "v4") == 1, "canary: dedupe keeps the first copy")
    # regression (3.3.1): the installer's marker never matched its own comment
    check("Tuxwall canary egress" not in CE.MARK, "canary: old marker string is not in the comment")
    for rel in ("tuxwall-install.sh", "pkg/DEBIAN/postinst", "scripts/opencanary/deploy-opencanary.sh"):
        txt = open(os.path.join(REPO, rel)).read()
        check("canary_egress.py" in txt and 'grep -q "Tuxwall canary egress"' not in txt,
              "canary: %s uses canary_egress.py" % rel)
    for r in (root, rootn):
        shutil.rmtree(r)


def t_canary_rules():
    """Canary rules no wider than the canary (deception phase 1): IPv4-only,
    leftovers flagged, removing an IPv6/SNMP leftover never refused."""
    legacy = [sp for sp in BASE_SPECS if "canary" not in sp.get("comment", "")] + [
        {"in": WAN, "proto": "tcp", "dport": 6379, "comment": "tuxwall-canary"},     # v4 + v6
        {"in": WAN, "proto": "udp", "dport": 161, "comment": "tuxwall-canary-snmp"}]  # v4 + v6
    root = make_root(specs=legacy)
    try:
        ctx, _ = mkctx(root, canary_active=True)
        cur = G.load_ruleset(ctx)
        vs = {v["id"]: v for v in G.invariants(cur, ctx, cur)}
        nl = sorted(k.split(":", 1)[1] for k in vs if k.startswith("canary-no-listener:"))
        check(len(nl) == 3 and all(vs["canary-no-listener:" + k]["severity"] == "medium" for k in nl),
              "canary: v6 6379 + v4/v6 SNMP without a listener flagged medium (%s)" % nl)
        check(not any(k.startswith("canary-no-listener:v4|False|allow|tcp|6379") for k in vs),
              "canary: v4 6379 with twistd listening is fine")
        check(not [v for v in vs.values() if v["severity"] in G.BLOCKING],
              "canary: leftovers never block")
        fx = vs["canary-no-listener:" + nl[0]]["repair"]
        check(fx["kind"] == "run" and fx["cmd"][:3] == ["ufw", "delete", "allow"], "canary: repair command")
        v6 = next(i for i, r in enumerate(G.numbered(cur), 1)
                  if r["family"] == "v6" and r["dport"] == "6379")
        g = G.check(cur, G.proposed_delete(cur, v6), ctx)
        check(g["ok"], "canary: deleting the IPv6 leftover is not refused")
        v4 = next(i for i, r in enumerate(G.numbered(cur), 1)
                  if r["family"] == "v4" and r["dport"] == "6379")
        g = G.check(cur, G.proposed_delete(cur, v4), ctx)
        check(not g["ok"] and any(v["id"].startswith("canary-missing:6379:tcp:v4")
                                  for v in g["new"]), "canary: deleting the live IPv4 rule is refused")
        ctx2, _ = mkctx(root, canary_active=False)
        vs2 = [v["id"] for v in G.invariants(cur, ctx2, cur)]
        check(len([x for x in vs2 if x.startswith("canary-leftover:")]) == 4,
              "canary not running: every canary rule is a leftover")
        check(not [x for x in vs2 if x.startswith("canary-missing")], "canary not running: nothing missing")
        fs = [f for f in L.findings(cur, ctx) if f["id"].startswith("guard:canary-no-listener")]
        check(len(fs) == 3 and fs[0]["fix"]["kind"] == "manual" and fs[0]["rules"],
              "canary: lint findings with the rule + a manual fix")
    finally:
        shutil.rmtree(root)


def t_lint():
    root = lint_root()
    ctx, run = mkctx(root)
    rs = G.load_ruleset(ctx)
    fs = L.findings(rs, ctx)
    by = {f["id"].split(":")[0] + ":" + f["id"].split("|")[0].split(":")[-1]: f for f in fs}
    dba = [f for f in fs if f["id"].startswith("deny-before-allow")]
    check(len(dba) == 2 and all(f["severity"] == "medium" for f in dba), "lint: eno1-style deny before allows (v4+v6)")
    d4 = next(f for f in dba if f["rules"][0]["family"] == "v4")
    check(len(d4["rules"]) == 4 and d4["fix"]["op"] == "move", "lint: 3 shadowed allows + move fix")
    check("managed" in d4["detail"], "lint: shadowed managed mDNS rule named as managed")
    wg = [f for f in fs if f["id"] == "raw-wg-forward"]
    check(wg and wg[0]["severity"] == "high" and "IoT (eth1.10) → WireGuard (wg0)" in wg[0]["detail"]
          and wg[0]["fix"]["href"] == "#interfaces", "lint: raw wg0 FORWARD bypass (high) + policy link")
    hu = [f for f in fs if f["id"] == "honeypot-untagged"]
    check(hu and hu[0]["severity"] == "info" and len(hu[0]["rules"]) == 4, "lint: untagged honeypot = info")
    check(any(f["id"].startswith("redundant:v6") for f in fs), "lint: v6 SSH rule redundant after LAN allow-all")
    check(any(f["id"].startswith("duplicate:") for f in fs), "lint: duplicate rule")
    check(not [f for f in fs if f["id"].startswith("guard:")], "lint: fixture has no guard violations")
    # no false positives on managed / deception rules
    cls = {r["key"]: G.classify_rule(r, ctx) for r in rs["v4"] + rs["v6"]}
    fp = [f["id"] for f in fs if f["category"] in ("order", "exposure", "stale", "asymmetry")
          and not f["id"].startswith(("deny-before", "allow-before"))
          and f["rules"] and cls[f["rules"][0]["key"]]["managed"]]
    check(not fp, "lint: no ordering/exposure findings on managed rules %s" % fp)
    check(not [f for f in fs if f["severity"] in ("critical",)], "lint: nothing critical in the fixture")
    # applying the suggested move removes the finding (and the guard passes)
    prop, info = E.propose_move_to(rs, ctx, d4["fix"]["number"], d4["fix"]["to"], d4["fix"]["expect"])
    check(G.check(rs, prop, ctx)["ok"], "lint: move fix passes the guard")
    check(not [f for f in L.findings(prop, ctx) if f["id"].startswith("deny-before-allow:v4")],
          "lint: move fix resolves the v4 finding")
    # allow without interface, stale host, missing interface, risky port forward
    root2 = lint_root(specs=BASE_SPECS + [{"proto": "tcp", "dport": 8443},
                                          {"route": True, "in": LAN, "out": "eth9", "comment": "gone"},
                                          {"route": True, "in": "eth1.10", "out": LAN, "dst": "192.168.1.99", "fam": "v4"}])
    with open(root2 + "/etc/tuxwall/portforward.json", "w") as f:
        json.dump([{"id": "p1", "ext_port": 3389, "int_ip": "192.168.1.50", "int_port": 3389, "proto": "tcp",
                    "enabled": True}], f)
    ctx2, _ = mkctx(root2)
    f2 = fids(L.findings(G.load_ruleset(ctx2), ctx2))
    for k in ("no-iface", "no-iface-dev", "stale-host", "pf-risky", "pf-noreserve"):
        check(k in f2, "lint: %s" % k)
    # zero-hit: needs history
    rs2 = G.load_ruleset(ctx2)
    user = next(r for r in rs2["v4"] if G.classify_rule(r, ctx2)["owner"] == "user")
    zh = L.findings(rs2, ctx2, hits={user["key"]: {"first": time.time() - 8 * 86400, "total": 0}})
    check("zero-hit" in fids(zh), "lint: zero-hit after 7 days")
    zh2 = L.findings(rs2, ctx2, hits={user["key"]: {"first": time.time() - 86400, "total": 0}})
    check("zero-hit" not in fids(zh2), "lint: no zero-hit with < 7 days of data")
    # logging off
    with open(root2 + "/etc/ufw/ufw.conf", "w") as f:
        f.write("ENABLED=yes\nLOGLEVEL=off\n")
    check("logging-off" in fids(L.findings(rs2, ctx2)), "lint: logging off")
    # suggestions: scanners -> honeypot port, LAN device blocked, templates
    log = []
    for i in range(12):
        log.append("2026-11-14T04:00:%02d host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=x SRC=198.51.100.%d "
                   "DST=203.0.113.5 LEN=44 PROTO=TCP SPT=4000 DPT=8081 WINDOW=1 SYN URGP=0" % (i, i + 1))
        log.append("2026-11-14T04:01:%02d host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=x SRC=198.51.100.%d "
                   "DST=203.0.113.5 LEN=44 PROTO=TCP SPT=4000 DPT=23 WINDOW=1 SYN URGP=0" % (i, i + 1))
    for i in range(6):
        log.append("2026-11-14T04:02:%02d host kernel: [UFW BLOCK] IN=eth2 OUT= MAC=x SRC=192.168.2.77 "
                   "DST=192.168.2.1 LEN=44 PROTO=TCP SPT=4000 DPT=9100 WINDOW=1 SYN URGP=0" % i)
    sg = L.suggestions(rs, ctx, "\n".join(log))
    hp = [s for s in sg if s["kind"] == "honeypot"]
    check(len(hp) == 1 and hp[0]["plan"]["port"] == 8081, "suggest: scanned WAN port -> honeypot (not 23)")
    lb = [s for s in sg if s["kind"] == "blocked"]
    check(lb and lb[0]["plan"]["op"] == "insert" and "from 192.168.2.77" in lb[0]["plan"]["rule"]
          and lb[0]["plan"]["before"], "suggest: LAN device blocked -> scoped allow before the deny")
    check({"tpl-ssh", "tpl-guest", "tpl-iot"} <= {s["id"] for s in sg}, "suggest: templates")
    check(next(s for s in sg if s["id"] == "tpl-iot")["href"] == "#interfaces", "suggest: template links the policy matrix")
    if HAVE_UFW:
        pl = E.blocks_from_text(lb[0]["plan"]["rule"])
        check(pl["v4"] and not pl["v6"], "suggest: plan rule parses (v4 only)")
    for r in (root, root2):
        shutil.rmtree(r)


def t_edit():
    root = lint_root()
    run = Runner()
    ctx, _ = mkctx(root, run=run)
    rs = G.load_ruleset(ctx)
    orig = {n: open(root + "/etc/ufw/" + n).read() for n in ("user.rules", "user6.rules")}
    num = next(i for i, r in enumerate(G.numbered(rs), 1) if r["text"].startswith("allow in on wg0 from 10.0.0.0/24 to any port 22"))
    key = G.numbered(rs)[num - 1]["key"]
    # every block regenerates byte-identically with ufw's formatter
    same = all(E.blocks_from_text(b["rule"]["text"])[fam] == {"tuple": b["tuple"], "body": b["body"]}
               for fam in ("v4", "v6") for b in rs["blocks"][fam] if b["rule"]["text"].startswith(("allow", "deny", "route")))
    check(same, "edit: blocks regenerate identically")
    prop, info = E.propose_edit(rs, ctx, num, "allow in on wg0 from 10.0.0.0/24 to any port 2222 proto tcp "
                                "comment 'SSH over WireGuard'", expect=key)
    d = E.describe(rs, prop, info, ctx)
    check(d["guard"]["ok"] and d["writes"] == ["user.rules"], "edit: plan ok, writes user.rules only")
    check(any(c["kind"] == "add" and "Allow TCP port 2222 from 10.0.0.0/24 arriving on WireGuard (wg0) to this router"
              in c["plain"] for c in d["changes"]), "edit: plain-language preview %s" % [c["plain"] for c in d["changes"]])
    check(G.numbered(prop)[num - 1]["dport"] == "2222", "edit: same position")
    sched = {}
    res = S.apply_files(ctx, rs, prop, "edit %d" % num, who="t", schedule=lambda c, de, fn, t: sched.setdefault(c, fn))
    check(res["ok"] and res["needs_confirmation"] in sched, "edit: applied with confirm window")
    check("--dport 2222" in open(root + "/etc/ufw/user.rules").read(), "edit: file written")
    check(["ufw", "reload"] in run.calls, "edit: mocked ufw reload")
    try:
        S.apply_files(ctx, G.load_ruleset(ctx), prop, "second", schedule=lambda *a: None)
        check(False, "edit: second change while pending refused")
    except S.Refused as exc:
        check(exc.status == 409, "edit: second change while pending refused")
    sched[res["needs_confirmation"]]()
    check(all(open(root + "/etc/ufw/" + n).read() == t for n, t in orig.items()), "edit: revert restores the files")
    # stale / managed / lockout
    for bad, code in (((num, "allow 1/tcp", "nope"), 409),):
        try:
            E.propose_edit(rs, ctx, *bad)
            check(False, "edit: stale refused")
        except E.EditError as exc:
            check(exc.status == code, "edit: stale expect -> 409")
    hp = next(i for i, r in enumerate(G.numbered(rs), 1) if G.classify_rule(r, ctx)["owner"] == "honeypot")
    try:
        E.propose_edit(rs, ctx, hp, "allow in on eth0 to any port 2323 proto tcp")
        check(False, "edit: managed refused")
    except E.EditError as exc:
        check(exc.status == 403 and exc.payload.get("managed"), "edit: managed rule refused (403)")
    lan = next(i for i, r in enumerate(G.numbered(rs), 1) if r["text"].startswith("allow in on eth1 from any to any"))
    p2, i2 = E.propose_edit(rs, ctx, lan, "deny in on eth1 comment 'Allow all LAN traffic'")
    check(not E.describe(rs, p2, i2, ctx)["guard"]["ok"], "edit: lockout edit refused by the guard")
    try:
        S.apply_files(ctx, rs, p2, "lockout", schedule=lambda *a: None)
        check(False, "edit: apply refuses lockout")
    except S.Refused as exc:
        check(exc.status == 409 and exc.payload["guard"]["blocking"], "edit: apply refuses lockout (409)")
    # disable (with v6 twin) -> enable restores the exact files
    S._PENDING.clear()
    rs = G.load_ruleset(ctx)
    mnum = next(i for i, r in enumerate(G.numbered(rs), 1) if r["text"].startswith("allow in on wg0 from any to any port 5353"))
    # mdns is managed: refused
    try:
        E.propose_disable(rs, ctx, mnum)
        check(False, "disable: managed refused")
    except E.EditError as exc:
        check(exc.status == 403, "disable: managed refused")
    dnum = next(i for i, r in enumerate(G.numbered(rs), 1) if r["text"].startswith("allow in on eth2 from any to any port 53 proto udp"))
    prop, info = E.propose_disable(rs, ctx, dnum, who="t")
    check(len(info["records"]) == 2 and len(prop["v4"]) == len(rs["v4"]) - 1 and len(prop["v6"]) == len(rs["v6"]) - 1,
          "disable: rule and its v6 twin removed")
    side = {E.DISABLED_FILE: E.disabled_text(E.load_disabled(ctx) + info["records"])}
    sched = {}
    res = S.apply_files(ctx, rs, prop, "disable", schedule=lambda c, de, fn, t: sched.setdefault(c, fn), side=side)
    check(res["ok"] and len(E.load_disabled(ctx)) == 2, "disable: stored in fw-disabled.json")
    S.confirmed(res["needs_confirmation"])
    rs_d = G.load_ruleset(ctx)
    prop, info = E.propose_enable(rs_d, ctx, E.load_disabled(ctx)[0]["id"])
    check(prop["texts"]["user.rules"] == orig["user.rules"] and prop["texts"]["user6.rules"] == orig["user6.rules"],
          "enable: re-inserted at the same positions (files identical)")
    res = S.apply_files(ctx, rs_d, prop, "enable", schedule=lambda c, de, fn, t: sched.setdefault(c, fn),
                        side={E.DISABLED_FILE: E.disabled_text(info["remaining"])})
    check(not E.load_disabled(ctx), "enable: removed from fw-disabled.json")
    sched[res["needs_confirmation"]]()
    check(len(E.load_disabled(ctx)) == 2, "enable revert: disabled list restored too")
    S._PENDING.clear()
    # insert before / move_to
    rs = G.load_ruleset(ctx)
    p3, i3 = E.propose_insert(rs, ctx, "allow in on eth2 to any port 123 proto udp comment 'NTP'", before=dnum - 1)
    check(G.numbered(p3)[dnum - 2]["dport"] == "123", "insert: at the requested position")
    check(E.plain(G.parse_tuple("### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth1!out_eth0", "v4"), ctx)
          .startswith("Allow forwarded all traffic from anywhere arriving on the LAN (eth1)"), "plain: route rule")
    try:
        E.parse_argv("allow 22/tcp; reboot")
        check(False, "edit: shell chars refused")
    except E.EditError:
        check(True, "edit: shell chars refused")
    check(E.parse_argv("allow 22/tcp comment 'a -> b'")[-1] == "a -> b", "edit: comment kept")
    shutil.rmtree(root)


def _save_with_counters(rs, fam, mult=1, drop=False):
    pre = "ufw" if fam == "v4" else "ufw6"
    out = ["*filter"]
    n = 0
    for b in rs["blocks"][fam]:
        for l in b["body"]:
            if l.split()[1] in ("%s-user-input" % pre, "%s-user-forward" % pre, "%s-user-output" % pre):
                n += 1
                if drop and n == 2:
                    continue
                out.append("[%d:%d] %s" % (n * mult, n * mult * 60, l))
    out.append("[9:9] -A %s-user-limit -j REJECT" % pre)
    out.append("COMMIT")
    return "\n".join(out) + "\n"


def t_hits():
    root = lint_root()
    ctx, run = mkctx(root)
    rs = G.load_ruleset(ctx, raw={})
    saves = {f: _save_with_counters(rs, f) for f in ("v4", "v6")}
    m = H.map_hits(rs, saves)
    check(m["v4"] and len(m["v4"]) == len(rs["v4"]) and m["v4"][0]["pkts"] == 1, "hits: v4 mapped in order")
    lim = sum(len([l for l in b["body"] if l.startswith("-A ufw-user-")]) for b in rs["blocks"]["v4"])
    check(m["v4"][-1]["pkts"] == lim, "hits: last block gets the last counter line")
    bad = H.map_hits(rs, {"v4": _save_with_counters(rs, "v4", drop=True), "v6": saves["v6"]})
    check(bad["v4"] is None and "v4" in bad["errors"] and bad["v6"], "hits: mismatch -> unmapped, not guessed")
    # sampler: deltas, reset detection, sparkline, zero-hit state
    run.ipt_c, run.ip6t_c = saves["v4"], saves["v6"]
    t0 = 1_800_000_000
    rec, _ = H.sample(ctx, rs, now=t0)
    H.record(ctx, rec)
    run.ipt_c = _save_with_counters(rs, "v4", mult=3)
    rec2, _ = H.sample(ctx, rs, now=t0 + 300)
    st = H.record(ctx, rec2)
    h0 = H.hkey(rs["v4"][0]["key"])
    check(st["rules"][h0]["total"] == 2 and st["rules"][h0]["last_hit"] == t0 + 300, "hits: delta folded")
    run.ipt_c = _save_with_counters(rs, "v4", mult=1)   # counters reset (ufw reload)
    rec3, _ = H.sample(ctx, rs, now=t0 + 600)
    st = H.record(ctx, rec3)
    check(st["rules"][h0]["total"] == 3, "hits: reset detected (delta = new value)")
    v = H.view(ctx, rs, now=t0 + 650)
    r0 = v["rules"][0]
    check(r0["number"] == 1 and r0["total"] == 3 and sum(r0["spark"]) == 3 and r0["hits"] == 1, "hits: view + sparkline")
    check(v["mapped"] == {"v4": True, "v6": True}, "hits: both families mapped")
    sk = H.state_by_key(ctx, rs)
    check(sk[rs["v4"][0]["key"]]["total"] == 3, "hits: state by rule key for findings")
    check(len(open(root + H.HITS_FILE).read().splitlines()) == 3, "hits: jsonl appended")
    shutil.rmtree(root)


def t_api():
    """api_server glue in-process: temp root, mocked runner, no host commands."""
    import importlib
    api = importlib.import_module("api_server")
    root = lint_root()
    run = Runner()
    real_sub = subprocess.run

    def guarded(cmd, *a, **k):
        c = cmd if isinstance(cmd, list) else [cmd]
        if c and c[0] in ("ufw", "iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "nft"):
            raise AssertionError("host firewall command in API test: %s" % c)
        return real_sub(cmd, *a, **k)
    api.subprocess.run = guarded
    api._fw_ctx = lambda client_ip="", raw=True: G.Ctx(root=root, run=run, run_in=run.run_in,
                                                       client_ip=client_ip or "192.168.1.50", raw=raw)
    api._fw_reapply_owned = lambda: []
    sched = {}
    api._fw_snap_schedule = lambda cid, d, fn, ttl: sched.setdefault(cid, fn)
    api._fw_ufw_log_tail = lambda limit=0: ""
    try:
        code, f = api.fw_findings_view("findings", "192.168.1.50")
        check(code == 200 and f["counts"]["high"] >= 1, "api: findings")
        code, s = api.fw_findings_view("suggestions", "192.168.1.50")
        check(code == 200 and s["suggestions"], "api: suggestions")
        rs = G.load_ruleset(api._fw_ctx())
        num = next(i for i, r in enumerate(G.numbered(rs), 1) if r["text"].startswith("allow in on eth2 from any to any port 53 proto udp"))
        code, p = api.fw_plan_view({"op": "disable", "number": str(num)}, "192.168.1.50")
        check(code == 200 and p["dry_run"] and p["guard"]["ok"] and len(p["changes"]) == 2, "api: plan (dry run)")
        check(not run.mutations(), "api: plan ran no ufw")
        code, r = api.fw_apply({"op": "disable", "number": num}, {"username": "t"}, "192.168.1.50")
        check(code == 200 and r["needs_confirmation"] in sched and ["ufw", "reload"] in run.calls, "api: apply disable")
        code, dl = api.fw_disabled_view()
        check(code == 200 and len(dl["rules"]) == 2 and dl["rules"][0]["plain"], "api: disabled list")
        sched[r["needs_confirmation"]]()
        api._fw_snap.confirmed(r["needs_confirmation"])
        code, dl = api.fw_disabled_view()
        check(not dl["rules"], "api: revert empties the disabled list")
        hp = next(i for i, r in enumerate(G.numbered(rs), 1) if G.classify_rule(r, api._fw_ctx())["owner"] == "honeypot")
        code, r = api.fw_apply({"op": "disable", "number": hp}, {"username": "t"}, "192.168.1.50")
        check(code == 403 and r.get("managed"), "api: managed rule -> 403")
        code, r = api.fw_plan_view({"op": "honeypot-add", "port": "8008"}, "192.168.1.50")
        check(code == 200 and not r["guard"]["ok"], "api: honeypot port 8008 refused by guard")
        code, h = api.fw_hits_view()
        check(code == 200 and "rules" in h, "api: hits view")
    finally:
        api.subprocess.run = real_sub
        shutil.rmtree(root)


def main():
    t_canary()
    if HAVE_UFW:
        t_canary_rules()
    t_lint()
    if HAVE_UFW:
        t_edit()
        t_api()
    else:
        print("SKIP t_edit/t_api: python3 ufw module not installed")
    t_hits()
    t_classify()
    if HAVE_UFW:
        t_invariants()
        t_crowdsec_nft()
    else:
        print("SKIP t_invariants/t_crowdsec_nft: python3 ufw module not installed")
    t_snapshots()
    if "--live" in sys.argv:
        t_live()
    if "--netns" in sys.argv:
        t_netns()
    print("firewall_safety_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
