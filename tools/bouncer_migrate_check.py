#!/usr/bin/env python3
"""CrowdSec bouncer iptables -> nftables upgrade migration checks
(pkg/usr/local/sbin/tuxwall-bouncer-nft-migrate).

  python3 tools/bouncer_migrate_check.py          pure tests (CI): config
        rendering (same layout as tuxwall-install.sh configure_bouncer, the
        deny action kept), ipset/probe parsing, the readiness rule, and the
        whole flow against a simulated host (systemctl/nft/iptables/ipset
        answered from an in-memory model under a temp root): skip cases
        (not installed, opt-out flag, already nftables, .local override,
        earlier failure, owner rolled back, bouncer stopped, nft unusable,
        short kernel timeouts), the zero-gap switch (old iptables rules
        enforce until the nft sets are populated, then removed), rollback
        on empty sets / forward hook / priority 0 / failed restart, owner +
        mode of the config kept, backups 0600 in a 0700 dir, idempotency.
  sudo python3 tools/bouncer_migrate_check.py --netns
        also, in a scratch network namespace (twbmig): the 365-day timeout
        probe with real nft, readiness against a real bouncer-like table, and
        removal of a real CROWDSEC_CHAIN jump/chain + ipsets. The namespace
        is deleted afterwards; the host ruleset is compared before/after.
"""
import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT_DIR, "www", "includes"))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True

import crowdsec_fw as C  # noqa: E402
from crowdsec_fw_check import CFG_IPT, bouncer_table  # noqa: E402

SCRIPT = os.path.join(ROOT_DIR, "pkg", "usr", "local", "sbin", "tuxwall-bouncer-nft-migrate")
_loader = importlib.machinery.SourceFileLoader("tw_bouncer_migrate", SCRIPT)
_spec = importlib.util.spec_from_loader("tw_bouncer_migrate", _loader)
M = importlib.util.module_from_spec(_spec)
_loader.exec_module(M)

PASS = FAIL = 0
DAY = 86400


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


# ── pure helpers ─────────────────────────────────────────────────────────────

def t_render():
    stock = CFG_IPT.replace("deny_action: DROP", "deny_action: REJECT").replace("    priority: -10\n", "")
    new = M.render_nft_config(stock)
    cfg = C.bouncer_config(new)
    check(cfg["mode"] == "nftables" and cfg["hooks"] == ["input"], "render: nftables + input hook only")
    check(cfg["nft"]["v4"]["priority"] == -10 and cfg["nft"]["v6"]["priority"] == -10, "render: priority -10")
    check(cfg["deny_action"] == "REJECT", "render: deny action kept")
    check("api_key: not-a-real-key" in new and "iptables_chains:\n  - INPUT" in new, "render: rest untouched")
    check(M.render_nft_config(new) == new, "render: idempotent")
    # same transform as the installer's configure_bouncer (except deny_action)
    src = open(os.path.join(ROOT_DIR, "tuxwall-install.sh")).read()
    py = re.search(r"configure_bouncer\(\) \{.*?<<'PY'\n(.*?)\nPY\n", src, re.S).group(1)
    d = tempfile.mkdtemp(prefix="bmig-render-")
    try:
        p = os.path.join(d, "b.yaml")
        with open(p, "w") as f:
            f.write(stock)
        subprocess.run([sys.executable, "-c", py, p, "nftables"], check=True, timeout=30)
        inst = open(p).read()
    finally:
        shutil.rmtree(d)
    check(inst.replace("deny_action: DROP", "deny_action: REJECT") == new,
          "render == installer configure_bouncer output (deny action aside)")
    check(M.local_override("mode: iptables\n") == ["mode"] and M.local_override("api_key: x\n") == [],
          ".local override detection")
    ipl = ("Name: crowdsec-blacklists-0\nType: hash:net\nNumber of entries: 12400\n\n"
           "Name: crowdsec6-blacklists-1\nNumber of entries: 84\n\nName: other\nNumber of entries: 9\n"
           "Name: crowdsec-blacklists-x\nNumber of entries: 5\n")
    check(M.ipset_counts(ipl, ["crowdsec-blacklists", "crowdsec6-blacklists"]) ==
          {"crowdsec-blacklists-0": 12400, "crowdsec6-blacklists-1": 84}, "ipset_counts")
    probe = json.dumps({"nftables": [{"set": {"family": "inet", "name": "p", "table": M.PROBE_TABLE,
                                              "type": "ipv4_addr", "flags": ["timeout"],
                                              "elem": [{"elem": {"val": "192.0.2.1", "timeout": 365 * DAY,
                                                                 "expires": 365 * DAY - 2}}]}}]})
    check(M.probe_ok(C, probe), "probe: 365 d kept")
    check(not M.probe_ok(C, probe.replace(str(365 * DAY - 2), str(49 * DAY))), "probe: capped timeout refused")
    check(not M.probe_ok(C, ""), "probe: no output refused")
    cmds = M.iptables_cleanup_cmds(["INPUT", "FORWARD"])
    check([k for k, _ in cmds] == ["jump", "jump", "flush", "chain"] * 2 and cmds[4][1][0] == "ip6tables",
          "cleanup: jumps first, then flush/delete, v4 + v6")


# ── simulated host ───────────────────────────────────────────────────────────

class Host:
    """In-memory bouncer/firewall. scenario: ok | empty | forward | prio0 |
    restart_fail | few. Records the time line of enforcement."""

    def __init__(self, root, scenario="ok", installed=True, active=True, nft_ok=True, probe_days=365,
                 ipsets=None, v6=True):
        self.root, self.scenario, self.installed, self.active = root, scenario, installed, active
        self.nft_ok, self.probe_days = nft_ok, probe_days
        self.ipsets = dict(ipsets if ipsets is not None else
                           {"crowdsec-blacklists-0": 900, "crowdsec-blacklists-1": 100, "crowdsec6-blacklists-0": 20})
        self.jumps = {"iptables": ["INPUT"], "ip6tables": ["INPUT"] if v6 else []}
        self.chain = {"iptables": True, "ip6tables": v6}
        self.nft = {}           # (family, table) -> json
        self.probe = False
        self.calls = []
        self.gaps = 0           # polls with neither iptables nor nft enforcement
        self.restarts = 0
        self.clock = 1000.0
        self.process = "iptables" if active else None

    def cfg_mode(self):
        p = self.root + "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
        return C.bouncer_config(open(p).read())["mode"]

    def enforcing(self):
        return bool(self.jumps["iptables"] and self.chain["iptables"]) or bool(self.nft)

    def start(self):
        mode = self.cfg_mode()
        self.restarts += 1
        if mode == "iptables":     # Init deletes and re-creates chain + ipsets
            self.chain = {"iptables": True, "ip6tables": True}
            self.jumps = {"iptables": ["INPUT"], "ip6tables": ["INPUT"]}
            self.ipsets = {"crowdsec-blacklists-0": 500, "crowdsec6-blacklists-0": 10}
            self.process = "iptables"
            return 0
        if self.scenario == "restart_fail":
            return 1
        n = {"ok": 990, "few": 10, "empty": 0, "forward": 990, "prio0": 990}[self.scenario]
        v4 = {"crowdsec-blacklists-CAPI": {"198.51.%d.%d" % (i // 250, i % 250): 300 * DAY for i in range(n)}}
        v6 = {"crowdsec6-blacklists-CAPI": {"2001:db8::%x" % (i + 1): 300 * DAY for i in range(20 if n else 0)}}
        prio = 0 if self.scenario == "prio0" else -10
        t4 = json.loads(bouncer_table(sets=v4, prio=prio))
        t6 = json.loads(bouncer_table("ip6", "crowdsec6", "crowdsec6-chain-input", prio=prio, sets=v6))
        if self.scenario == "forward":
            for t, fam, tab, ch in ((t4, "ip", "crowdsec", "crowdsec-chain-forward"),
                                    (t6, "ip6", "crowdsec6", "crowdsec6-chain-forward")):
                t["nftables"].append({"chain": {"family": fam, "table": tab, "name": ch, "type": "filter",
                                                "hook": "forward", "prio": -10, "policy": "accept"}})
        self.nft[("ip", "crowdsec")] = json.dumps(t4)
        self.nft[("ip6", "crowdsec6")] = json.dumps(t6)
        self.process = "nftables"
        return 0

    def run(self, cmd, input=None, timeout=60):
        self.calls.append(list(cmd))
        c = cmd[0]
        if c == "systemctl":
            sub = cmd[1]
            if sub == "cat":
                return (0, "[Unit]") if self.installed else (1, "No files found")
            if sub == "is-active":
                return (0, "active\n") if self.active else (3, "inactive\n")
            if sub == "kill":
                assert cmd[2:4] == ["-s", "KILL"], cmd   # never a graceful stop
                self.process = None
                return 0, ""
            if sub == "restart":
                assert self.process is None, "restart without SIGKILL first"
                return self.start(), ""
            raise AssertionError(cmd)
        if c == "nft":
            if not self.nft_ok:
                return 1, "Error: Could not process rule: Operation not supported"
            if cmd[1:] == ["list", "tables"]:
                return 0, "".join("table %s %s\n" % k for k in self.nft)
            if cmd[1:3] == ["-f", "-"]:
                assert M.PROBE_TABLE in input
                self.probe = True
                return 0, ""
            if cmd[1:3] == ["delete", "table"]:
                if cmd[4] == M.PROBE_TABLE:
                    ok, self.probe = self.probe, False
                    return (0, "") if ok else (1, "No such file")
                return (0, "") if self.nft.pop((cmd[3], cmd[4]), None) else (1, "No such file")
            if cmd[1:4] == ["-j", "list", "set"]:
                exp = self.probe_days * DAY - 2
                return 0, json.dumps({"nftables": [{"set": {"family": "inet", "name": "p", "table": cmd[5],
                                                            "type": "ipv4_addr", "flags": ["timeout"],
                                                            "elem": [{"elem": {"val": "192.0.2.1",
                                                                               "timeout": self.probe_days * DAY,
                                                                               "expires": exp}}]}}]})
            if cmd[1] == "-j" and "list" in cmd and "table" in cmd:
                self.clock += 0.5
                if not self.enforcing():
                    self.gaps += 1
                t = self.nft.get((cmd[-2], cmd[-1]))
                return (0, t) if t else (1, "No such file")
            if cmd[1:] == ["list", "ruleset"]:
                return 0, "table ip filter {}\n"
            raise AssertionError(cmd)
        if c in ("iptables", "ip6tables"):
            op = cmd[2]
            if op == "-C":
                return (0, "") if cmd[3] in self.jumps[c] and self.chain[c] else (1, "")
            if op == "-D":
                if cmd[3] in self.jumps[c]:
                    self.jumps[c].remove(cmd[3])
                    return 0, ""
                return 1, "Bad rule"
            if op == "-F":
                return (0, "") if self.chain[c] else (1, "No chain")
            if op == "-X":
                if self.chain[c] and not self.jumps[c]:
                    self.chain[c] = False
                    return 0, ""
                return 1, "No chain/target/match by that name"
            if op == "-S":
                return (0, "-N CROWDSEC_CHAIN") if self.chain[c] else (1, "")
            raise AssertionError(cmd)
        if c in ("iptables-save", "ip6tables-save"):
            return 0, "*filter\n-A INPUT -j CROWDSEC_CHAIN\nCOMMIT\n"
        if c == "ipset":
            if cmd[1:] == ["list", "-t"]:
                return 0, "".join("Name: %s\nNumber of entries: %d\n\n" % kv for kv in self.ipsets.items())
            if cmd[1] == "save":
                return 0, "create crowdsec-blacklists-0 hash:net\n"
            if cmd[1] == "destroy":
                ch = "ip6tables" if cmd[2].startswith("crowdsec6") else "iptables"
                if self.chain[ch]:
                    return 1, "Set cannot be destroyed: it is in use by a kernel component"
                return (0, "") if self.ipsets.pop(cmd[2], None) is not None else (1, "does not exist")
            raise AssertionError(cmd)
        raise AssertionError(cmd)


class TEnv(M.Env):
    def __init__(self, root, host):
        super().__init__(root)
        self.host = host
        self.quiet = True
        self.lines = []

    def run(self, cmd, input=None, timeout=60):
        return self.host.run(cmd, input=input, timeout=timeout)

    def sleep(self, s):
        self.host.clock += s

    def now(self):
        return self.host.clock

    def log(self, msg):
        self.lines.append(msg)
        super().log(msg)


def world(scenario="ok", cfg=CFG_IPT, local=None, **kw):
    root = tempfile.mkdtemp(prefix="bmig-")
    os.makedirs(root + "/etc/crowdsec/bouncers")
    os.makedirs(root + "/etc/tuxwall")
    p = root + "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    with open(p, "w") as f:
        f.write(cfg)
    os.chmod(p, 0o600)
    if local is not None:
        with open(p + ".local", "w") as f:
            f.write(local)
    h = Host(root, scenario, **kw)
    return root, h, TEnv(root, h)


def cfg_text(root):
    return open(root + "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml").read()


def state(root):
    try:
        return json.load(open(root + "/var/lib/tuxwall/bouncer-nft-migration.json"))
    except OSError:
        return {}


def t_skips():
    cases = [
        ("not installed", dict(installed=False), None, None, "not installed"),
        ("opt-out", {}, None, "optout", "opt-out flag"),
        ("already nftables", {}, CFG_IPT.replace("mode: iptables", "mode: nftables"), None, "already in nftables"),
        ("ipset mode", {}, CFG_IPT.replace("mode: iptables", "mode: ipset"), None, "not managed"),
        (".local override", {}, None, "local", "owner override"),
        ("bouncer stopped", dict(active=False), None, None, "not running"),
        ("nft unusable", dict(nft_ok=False), None, None, "nft does not work"),
        ("short timeouts", dict(probe_days=49), None, None, "365-day set timeout"),
    ]
    for name, kw, cfg, extra, want in cases:
        root, h, env = world(cfg=cfg or CFG_IPT, local="mode: iptables\n" if extra == "local" else None, **kw)
        try:
            if extra == "optout":
                open(root + "/etc/tuxwall/no-bouncer-migration", "w").close()
            before = cfg_text(root)
            rc = M.migrate(env, C)
            changed = [c for c in h.calls if c[:2] in (["systemctl", "kill"], ["systemctl", "restart"])
                       or c[0] in ("iptables", "ip6tables") and c[2] in ("-D", "-X", "-F")
                       or c[:2] == ["ipset", "destroy"]]
            act, why, _q = M.plan(env, C)
            check(rc == 0 and cfg_text(root) == before and not changed and act == "skip" and want in why,
                  "skip (%s): rc=%s why=%r changed=%s" % (name, rc, why, changed))
            check(not h.probe, "skip (%s): probe table never left behind" % name)
            check(not os.path.isdir(root + "/var/backups"), "skip (%s): no backup taken" % name)
            quiet = name in ("not installed", "already nftables")
            check(bool(env.lines) != quiet, "skip (%s): logged=%s" % (name, env.lines))
        finally:
            shutil.rmtree(root)


def t_migrate_ok():
    root, h, env = world("ok")
    try:
        st0 = os.stat(root + "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml")
        rc = M.migrate(env, C)
        cfg = C.bouncer_config(cfg_text(root))
        st1 = os.stat(root + "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml")
        check(rc == 0 and cfg["mode"] == "nftables" and cfg["hooks"] == ["input"]
              and cfg["deny_action"] == "DROP", "ok: config switched %r" % env.lines)
        check(stat.S_IMODE(st1.st_mode) == 0o600 and st1.st_uid == st0.st_uid, "ok: config owner/mode kept")
        kill = h.calls.index(["systemctl", "kill", "-s", "KILL", "crowdsec-firewall-bouncer"])
        first_del = min(i for i, c in enumerate(h.calls) if c[0] in ("iptables", "ip6tables") and c[2] == "-D")
        lists = [i for i, c in enumerate(h.calls) if c[:2] == ["nft", "-j"] and "table" in c]
        check(kill < min(lists) < first_del, "ok: SIGKILL -> nft populated -> old rules removed (in order)")
        check(h.gaps == 0, "ok: no enforcement gap (%d)" % h.gaps)
        check(not h.jumps["iptables"] and not h.chain["iptables"] and not h.chain["ip6tables"]
              and not h.ipsets, "ok: CROWDSEC_CHAIN + ipsets removed: %r %r" % (h.chain, h.ipsets))
        check(not h.probe and h.restarts == 1, "ok: probe table removed, one restart")
        s = state(root)
        check(s.get("result") == "migrated" and s.get("ipset_entries") == 1020 and s.get("elements") == 1010,
              "ok: state %r" % s)
        b = s.get("backup", "")
        check(os.path.isdir(b) and stat.S_IMODE(os.stat(b).st_mode) == 0o700, "ok: backup dir 0700")
        files = sorted(os.listdir(b))
        check(files == ["crowdsec-firewall-bouncer.yaml.pre-nft", "ip6tables.save", "ipset.save",
                        "iptables.save", "nft-ruleset.txt"], "ok: backup files %s" % files)
        check(all(stat.S_IMODE(os.stat(os.path.join(b, f)).st_mode) == 0o600 for f in files), "ok: backups 0600")
        check(open(os.path.join(b, "crowdsec-firewall-bouncer.yaml.pre-nft")).read() == CFG_IPT,
              "ok: original config backed up")
        log = open(root + "/var/log/tuxwall/bouncer-migration.log").read()
        check("done: bouncer in nftables mode" in log and "not-a-real-key" not in log, "ok: logged, no API key")
        n = len(h.calls)
        rc = M.migrate(env, C)
        check(rc == 0 and all(c[:2] != ["systemctl", "kill"] for c in h.calls[n:]), "ok: second run is a no-op")
    finally:
        shutil.rmtree(root)


def t_rollbacks():
    for scen, want in (("empty", "too few elements"), ("few", "too few elements"),
                       ("forward", "crowdsec-nft-hooks"), ("prio0", "crowdsec-nft-priority"),
                       ("restart_fail", "did not start")):
        root, h, env = world(scen)
        try:
            rc = M.migrate(env, C)
            s = state(root)
            check(rc == 1 and cfg_text(root) == CFG_IPT, "rollback (%s): config restored" % scen)
            check(h.process == "iptables" and h.jumps["iptables"] == ["INPUT"] and h.chain["iptables"]
                  and h.ipsets, "rollback (%s): iptables bouncer enforcing again" % scen)
            check(not h.nft, "rollback (%s): nft tables removed: %s" % (scen, list(h.nft)))
            check(s.get("result") == "failed" and want in s.get("reason", "") and s.get("rolled_back") is True,
                  "rollback (%s): state %r" % (scen, s))
            n = len(h.calls)
            check(M.migrate(env, C) == 0 and len(h.calls) - n <= 3, "rollback (%s): not retried" % scen)
            h.scenario = "ok"
            check(M.migrate(env, C, force=True) == 0 and state(root).get("result") == "migrated",
                  "rollback (%s): --force retries" % scen)
        finally:
            shutil.rmtree(root)


def t_owner_rollback():
    root, h, env = world("ok")
    try:
        M.migrate(env, C)
        p = root + "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
        with open(p, "w") as f:
            f.write(CFG_IPT)
        h.calls.clear()
        rc = M.migrate(env, C)
        check(rc == 0 and cfg_text(root) == CFG_IPT and not any(c[:2] == ["systemctl", "kill"] for c in h.calls),
              "owner switched back to iptables: kept")
    finally:
        shutil.rmtree(root)


def t_check_only():
    root, h, env = world("ok")
    try:
        rc = M.migrate(env, C, check_only=True)
        check(rc == 0 and cfg_text(root) == CFG_IPT and h.process == "iptables"
              and any("would migrate" in x for x in env.lines), "--check changes nothing")
    finally:
        shutil.rmtree(root)


def t_ready():
    cfg = C.bouncer_config(M.render_nft_config(CFG_IPT))
    t4 = C.parse_table(C.nft_objects(bouncer_table()))
    t6 = C.parse_table(C.nft_objects(bouncer_table("ip6", "crowdsec6", "crowdsec6-chain-input",
                                                   sets={"crowdsec6-blacklists-CAPI": {"2001:db8::1": DAY}})))
    ok, probs, n = M.nft_ready(C, cfg, {"v4": t4, "v6": t6}, 3)
    check(ok and not probs and n == 3, "ready: hooks + 3/3 elements")
    ok, probs, n = M.nft_ready(C, cfg, {"v4": t4, "v6": t6}, 4)
    check(ok, "ready: 3 of 4 (>= 90%% of int) %r" % probs)
    ok, probs, n = M.nft_ready(C, cfg, {"v4": t4, "v6": t6}, 10)
    check(not ok and not probs, "not ready: too few elements")
    ok, probs, n = M.nft_ready(C, cfg, {"v4": t4, "v6": None}, 0)
    check(not ok and "crowdsec-nft-missing:v6" in probs, "not ready: v6 table missing")
    v6off = C.bouncer_config(M.render_nft_config(CFG_IPT.replace("  ipv6:\n    enabled: true", "  ipv6:\n    enabled: false")))
    ok, probs, n = M.nft_ready(C, v6off, {"v4": t4, "v6": None}, 0)
    check(ok, "ready: IPv6 disabled needs no v6 table %r" % probs)


# ── --netns: real nft/iptables/ipset in a scratch namespace ─────────────────

def t_netns():
    NS = "twbmig"
    host = lambda: (subprocess.run(["nft", "list", "tables"], capture_output=True, text=True).stdout,  # noqa: E731
                    subprocess.run(["ipset", "list", "-n"], capture_output=True, text=True).stdout,
                    subprocess.run(["iptables", "-w", "-S"], capture_output=True, text=True).stdout)
    before = host()
    subprocess.run(["ip", "netns", "add", NS], check=True)
    try:
        class NEnv(M.Env):
            def run(self, cmd, input=None, timeout=60):
                return super().run(["ip", "netns", "exec", NS] + cmd, input=input, timeout=timeout)
        root = tempfile.mkdtemp(prefix="bmig-ns-")
        env = NEnv(root)
        env.quiet = True
        try:
            ok, why = M.nft_usable(env, C)
            check(ok, "netns: real kernel keeps a 365-day set timeout (%s)" % why)
            check(M.PROBE_TABLE not in env.run(["nft", "list", "tables"])[1], "netns: probe table removed")
            rc, out = env.run(["nft", "-f", "-"], input="""table ip crowdsec {
  set crowdsec-blacklists-CAPI { type ipv4_addr; flags timeout;
    elements = { 198.51.100.1 timeout 365d, 198.51.100.2 timeout 90d }
  }
  chain crowdsec-chain-input { type filter hook input priority -10; policy accept;
    ip saddr @crowdsec-blacklists-CAPI counter drop
  }
}
""")
            check(rc == 0, "netns: bouncer-like table loads (%s)" % out[:200])
            cfg = C.bouncer_config(M.render_nft_config(CFG_IPT.replace("  ipv6:\n    enabled: true", "  ipv6:\n    enabled: false")))
            ok, probs, n = M.nft_ready(C, cfg, M.bouncer_tables(env, C, cfg), 2)
            check(ok and n == 2, "netns: real table is ready %r %d" % (probs, n))
            have_ipset = env.run(["ipset", "list", "-n"])[0] == 0
            for c in (["ipset", "create", "crowdsec-blacklists-0", "hash:net", "timeout", "300"],
                      ["ipset", "add", "crowdsec-blacklists-0", "198.51.100.9", "timeout", "200"],
                      ["iptables", "-w", "-N", "CROWDSEC_CHAIN"],
                      ["iptables", "-w", "-A", "CROWDSEC_CHAIN", "-m", "set", "--match-set",
                       "crowdsec-blacklists-0", "src", "-j", "DROP"],
                      ["iptables", "-w", "-I", "INPUT", "1", "-j", "CROWDSEC_CHAIN"],
                      ["iptables", "-w", "-I", "INPUT", "2", "-j", "CROWDSEC_CHAIN"]):
                if c[0] == "ipset" and not have_ipset:
                    continue
                rc, out = env.run(c)
                check(rc == 0, "netns: setup %s (%s)" % (" ".join(c[:4]), out.strip()[:120]))
            cnt = M.ipset_counts(env.run(["ipset", "list", "-t"])[1], ["crowdsec-blacklists"]) if have_ipset else {}
            check(not have_ipset or cnt == {"crowdsec-blacklists-0": 1}, "netns: ipset_counts on real ipset %r" % cnt)
            ctx = {"cfg": C.bouncer_config(CFG_IPT), "ipsets": cnt}
            check(M._iptables_back(env, ctx), "netns: _iptables_back sees the real jump + ipset")
            for kind, cmd in M.iptables_cleanup_cmds(["INPUT"], ["v4"]):
                if kind == "jump":
                    while env.run(cmd)[0] == 0:
                        pass
                else:
                    env.run(cmd)
            for name in cnt:
                env.run(["ipset", "destroy", name])
            rc, out = env.run(["iptables", "-w", "-S"])
            check("CROWDSEC_CHAIN" not in out, "netns: both jumps + chain removed")
            check(not have_ipset or "crowdsec" not in env.run(["ipset", "list", "-n"])[1], "netns: ipset destroyed")
        finally:
            shutil.rmtree(root)
    finally:
        subprocess.run(["ip", "netns", "del", NS])
    check(host() == before, "netns: host nft tables, ipsets, iptables rules unchanged")


def main():
    t_render()
    t_ready()
    t_skips()
    t_migrate_ok()
    t_rollbacks()
    t_owner_rollback()
    t_check_only()
    if "--netns" in sys.argv:
        t_netns()
    print("bouncer_migrate_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
