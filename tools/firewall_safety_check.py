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

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "www", "includes"))
sys.dont_write_bytecode = True

import fw_guard as G  # noqa: E402
import fw_snap as S  # noqa: E402

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
    {"in": WAN, "proto": "tcp", "dport": 6379, "comment": "tuxwall-canary"},
    {"in": WAN, "proto": "udp", "dport": 161, "comment": "tuxwall-canary-snmp"},
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
            return 0, self.ipt
        if cmd[0] == "ip6tables-save":
            return 0, self.ip6t
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
    check(own("allow in on eth0 from any to any port 161 proto udp") == "canary", "canary snmp tag")
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
    check(any(c["owner"] == "crowdsec" for c in cl["raw"]), "live crowdsec")
    check(any(c["owner"] == "canary-egress" for c in cl["before"]), "live canary egress")
    inv = G.invariants(rs, ctx, rs)
    check(not [v for v in inv if v["severity"] == "critical"], "live: no critical violations %s" %
          [v["id"] for v in inv if v["severity"] == "critical"])
    check(not S.validate_files({k: open(p).read() for k, p in S.UFW_FILES.items()}), "live files validate")
    print("live invariants:", [(v["severity"], v["id"]) for v in inv])
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
        shutil.rmtree(root)
    finally:
        subprocess.run(["ip", "netns", "del", NS])
    check(host_save() == host_before, "netns: host iptables/ip6tables unchanged")
    check(NS not in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout,
          "netns deleted")


def main():
    t_classify()
    if HAVE_UFW:
        t_invariants()
    else:
        print("SKIP t_invariants: python3 ufw module not installed")
    t_snapshots()
    if "--live" in sys.argv:
        t_live()
    if "--netns" in sys.argv:
        t_netns()
    print("firewall_safety_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
