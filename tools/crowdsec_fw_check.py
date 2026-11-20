#!/usr/bin/env python3
"""CrowdSec bouncer enforcement checks (www/includes/crowdsec_fw.py).

  python3 tools/crowdsec_fw_check.py            pure tests (CI): bouncer config
        parsing (PyYAML and the fallback parser), synthetic `nft -j` tables,
        family state/problems, decisions from a temp SQLite store, the
        re-time / lapsed / Range plans, rendered nft scripts and reconcile()
        with a fake runner (no host commands).
  sudo python3 tools/crowdsec_fw_check.py --netns
        also builds a bouncer-like table in a scratch network namespace
        (twcsfw) and runs reconcile() against real nft there: elements that a
        longer ban did not extend are re-timed, a vanished element is not
        resurrected, Range bans land in the TuxWall table. The namespace is
        deleted afterwards; the host ruleset is compared before/after.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "www", "includes"))
sys.dont_write_bytecode = True

import crowdsec_fw as C  # noqa: E402

PASS = FAIL = 0
DAY = 86400


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


CFG_IPT = """mode: iptables
update_frequency: 10s
api_url: http://127.0.0.1:8088/
api_key: not-a-real-key
disable_ipv6: false
deny_action: DROP
blacklists_ipv4: crowdsec-blacklists
blacklists_ipv6: crowdsec6-blacklists
ipset_type: nethash
iptables_chains:
  - INPUT
#  - FORWARD
iptables_add_rule_comments: true

## nftables
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: crowdsec
    chain: crowdsec-chain
    priority: -10
  ipv6:
    enabled: true
    set-only: false
    table: crowdsec6
    chain: crowdsec6-chain
    priority: -10

nftables_hooks:
  - input
  - forward

prometheus:
  enabled: false
"""
CFG_NFT = CFG_IPT.replace("mode: iptables", "mode: nftables").replace(
    "nftables_hooks:\n  - input\n  - forward\n", "nftables_hooks:\n  - input\n")


def nft_doc(objs):
    return json.dumps({"nftables": [{"metainfo": {"version": "1.1.6", "json_schema_version": 1}}] + objs})


def bouncer_table(family="ip", table="crowdsec", chain="crowdsec-chain-input", prio=-10, policy="accept",
                  sets=None, hook="input", terse=False):
    """`nft -j list table` of a bouncer table: sets {name: {ip: expires}}."""
    sets = sets if sets is not None else {"crowdsec-blacklists-CAPI": {"198.51.100.1": 5 * DAY},
                                          "crowdsec-blacklists-cscli": {"198.51.100.2": 300 * DAY}}
    sel = "ip" if family == "ip" else "ip6"
    typ = "ipv4_addr" if family == "ip" else "ipv6_addr"
    objs = [{"table": {"family": family, "name": table, "handle": 9}},
            {"chain": {"family": family, "table": table, "name": chain, "handle": 1, "type": "filter",
                       "hook": hook, "prio": prio, "policy": policy}},
            {"counter": {"family": family, "name": "processed", "table": table, "packets": 1000, "bytes": 9}}]
    for name, els in sets.items():
        body = {"family": family, "name": name, "table": table, "type": typ, "flags": ["timeout"]}
        if not terse and els:
            body["elem"] = [{"elem": {"val": ip, "timeout": exp + 10, "expires": exp}} if exp is not None
                            else ip for ip, exp in els.items()]
        objs.append({"set": body})
        objs.append({"counter": {"family": family, "name": name, "table": table, "packets": 7, "bytes": 420}})
    objs.append({"rule": {"family": family, "table": table, "chain": chain, "handle": 3,
                          "expr": [{"counter": "processed"}]}})
    for name in sets:
        objs.append({"rule": {"family": family, "table": table, "chain": chain, "handle": 4,
                              "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": sel,
                                                                                    "field": "saddr"}},
                                                  "right": "@" + name}},
                                       {"counter": name}, {"drop": None}]}})
    return nft_doc(objs)


def make_db(rows):
    """rows: (value, scope, until_epoch, origin, type, simulated)"""
    fd, path = tempfile.mkstemp(prefix="csfw-", suffix=".db")
    os.close(fd)
    db = sqlite3.connect(path)
    db.execute("create table decisions (id integer primary key, created_at text, until text, scenario text, "
               "type text, scope text, value text, origin text, simulated integer)")
    for i, (value, scope, until, origin, typ, sim) in enumerate(rows, 1):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(until))
        if i % 3 == 0:
            stamp += ".145867117"
        db.execute("insert into decisions (created_at, until, scenario, type, scope, value, origin, simulated) "
                   "values (?, ?, 'x', ?, ?, ?, ?, ?)", (stamp, stamp + "+00:00", typ, scope, value, origin, sim))
    db.commit()
    db.close()
    return path


class FakeNft:
    def __init__(self, tables=None, fail_scripts=()):
        self.tables = dict(tables or {})     # (family, name) -> json text (full)
        self.calls, self.scripts = [], []
        self.fail_scripts = fail_scripts

    def run(self, cmd, timeout=30):
        self.calls.append(list(cmd))
        assert cmd[:2] == ["nft", "-j"] and "list" in cmd, cmd
        fam, name = cmd[-2], cmd[-1]
        if (fam, name) not in self.tables:
            return 1, ""
        return 0, self.tables[(fam, name)]

    def run_in(self, cmd, text, timeout=60):
        assert cmd == ["nft", "-f", "-"], cmd
        self.scripts.append(text)
        if any(s in text for s in self.fail_scripts):
            return 1, "Error: Could not process rule: No such file or directory"
        return 0, ""


# ── tests ────────────────────────────────────────────────────────────────────

def t_config():
    c = C.bouncer_config(CFG_IPT)
    check(c["mode"] == "iptables" and c["iptables_chains"] == ["INPUT"], "iptables mode + chains")
    check(c["nft"]["v4"] == {"enabled": True, "set_only": False, "family": "ip", "table": "crowdsec",
                             "chain": "crowdsec-chain", "priority": -10, "blacklist": "crowdsec-blacklists"},
          "v4 nft settings: %r" % c["nft"]["v4"])
    check(c["nft"]["v6"]["family"] == "ip6" and c["nft"]["v6"]["blacklist"] == "crowdsec6-blacklists",
          "v6 nft settings")
    check(c["hooks"] == ["input", "forward"], "hooks parsed")
    n = C.bouncer_config(CFG_NFT)
    check(n["mode"] == "nftables" and n["hooks"] == ["input"] and n["deny_action"] == "DROP", "nft mode config")
    check(C._mini_yaml(CFG_NFT).get("nftables") == __import__("yaml").safe_load(CFG_NFT)["nftables"]
          if _have_yaml() else True, "fallback parser matches PyYAML (nftables section)")
    mini = C._mini_yaml(CFG_NFT)
    check(mini["mode"] == "nftables" and mini["nftables_hooks"] == ["input"]
          and mini["nftables"]["ipv6"]["priority"] == -10 and mini["iptables_chains"] == ["INPUT"],
          "fallback parser: %r" % {k: mini.get(k) for k in ("mode", "nftables_hooks")})
    d = C.bouncer_config("mode: nftables\n")
    check(d["nft"]["v4"]["table"] == "crowdsec" and d["nft"]["v6"]["chain"] == "crowdsec6-chain"
          and d["nft"]["v4"]["priority"] == 0 and d["hooks"] == ["input"], "bouncer defaults")
    d6 = C.bouncer_config("mode: nftables\ndisable_ipv6: true\n")
    check(not d6["nft"]["v6"]["enabled"] and d6["nft"]["v4"]["enabled"], "disable_ipv6 -> v6 disabled")
    loc = C.bouncer_config(CFG_IPT, "mode: nftables\nnftables:\n  ipv4:\n    priority: -20\n")
    check(loc["mode"] == "nftables" and loc["nft"]["v4"]["priority"] == -20
          and loc["nft"]["v4"]["table"] == "crowdsec", ".local override merges")
    check(C.bouncer_config("")["mode"] == "" and not C.bouncer_config("")["present"], "absent config")


def _have_yaml():
    try:
        import yaml  # noqa: F401
        return True
    except ImportError:
        return False


def t_state():
    cfg = C.bouncer_config(CFG_NFT)
    tbl = C.parse_table(C.nft_objects(bouncer_table()))
    check(set(tbl["sets"]) == {"crowdsec-blacklists-CAPI", "crowdsec-blacklists-cscli"}, "sets parsed")
    check(tbl["sets"]["crowdsec-blacklists-cscli"]["elements"] == {"198.51.100.2": 300 * DAY}, "elements + expiry")
    st = C.nft_family_state(cfg, "v4", tbl)
    check(st["problems"] == [], "healthy table: no problems %r" % st["problems"])
    check(st["sets"] == {"crowdsec-blacklists-CAPI": 1, "crowdsec-blacklists-cscli": 1} and st["rules"] == 2
          and st["dropped"] == 14 and st["processed"] == 1000, "counts: %r" % st)
    check(st["hooks"] == [{"chain": "crowdsec-chain-input", "hook": "input", "prio": -10, "policy": "accept"}],
          "hook reported")
    terse = C.parse_table(C.nft_objects(bouncer_table(terse=True)))
    check(C.nft_family_state(cfg, "v4", terse)["problems"] == [], "terse listing is enough for the invariants")
    ids = lambda s: [p["id"] for p in s["problems"]]  # noqa: E731
    check(ids(C.nft_family_state(cfg, "v4", None)) == ["crowdsec-nft-missing:v4"], "missing table")
    bad = C.parse_table(C.nft_objects(bouncer_table(chain="other")))
    check(ids(C.nft_family_state(cfg, "v4", bad)) == ["crowdsec-nft-hook-missing:v4:input"], "hook missing")
    fwd = C.parse_table(C.nft_objects(bouncer_table(chain="crowdsec-chain-input", hook="forward")))
    check(ids(C.nft_family_state(cfg, "v4", fwd)) == ["crowdsec-nft-hook-missing:v4:input"],
          "chain on the wrong hook = missing")
    p0 = C.parse_table(C.nft_objects(bouncer_table(prio=0)))
    s0 = C.nft_family_state(cfg, "v4", p0)
    check(ids(s0) == ["crowdsec-nft-priority:v4:input"] and s0["problems"][0]["severity"] == "medium",
          "priority 0 (not before ufw) flagged medium")
    pd = C.parse_table(C.nft_objects(bouncer_table(policy="drop")))
    check("crowdsec-nft-policy:v4:input" in ids(C.nft_family_state(cfg, "v4", pd)), "policy drop flagged")
    six = C.parse_table(C.nft_objects(bouncer_table("ip6", "crowdsec6", "crowdsec6-chain-input",
                                                     sets={"crowdsec6-blacklists-cscli": {"2001:db8::1": DAY}})))
    s6 = C.nft_family_state(cfg, "v6", six)
    check(s6["problems"] == [] and s6["sets"] == {"crowdsec6-blacklists-cscli": 1}, "v6 table")
    cfg6off = C.bouncer_config(CFG_NFT.replace("disable_ipv6: false", "disable_ipv6: true").replace(
        "  ipv6:\n    enabled: true", "  ipv6:\n    enabled: false"))
    check(C.nft_family_state(cfg6off, "v6", None)["problems"] == [], "disabled family: no problems")
    run = FakeNft({("ip", "crowdsec"): bouncer_table()})
    stx = C.status(run.run, cfg)
    check(stx["families"]["v4"]["present"] and not stx["families"]["v6"]["present"]
          and run.calls[0] == ["nft", "-j", "-t", "list", "table", "ip", "crowdsec"], "status() reads terse")
    check(stx["families"]["v4"]["sets"] == {"crowdsec-blacklists-CAPI": None, "crowdsec-blacklists-cscli": None},
          "terse status: set sizes unknown, not 0")
    full = C.status(FakeNft({("ip", "crowdsec"): bouncer_table()}).run, cfg, terse=False)
    check(full["families"]["v4"]["sets"] == {"crowdsec-blacklists-CAPI": 1, "crowdsec-blacklists-cscli": 1},
          "full status counts elements")
    check(C.status(run.run, C.bouncer_config(CFG_IPT))["families"] == {}, "iptables mode: no nft reads")
    # interval elements / plain elements
    s = {"set": {"name": "r", "elem": [{"elem": {"val": {"prefix": {"addr": "216.180.246.0", "len": 24}},
                                                  "timeout": 99, "expires": 90}}, "2001:DB8::5",
                                       {"elem": {"val": {"range": ["192.0.2.1", "192.0.2.9"]}, "expires": 5}}]}}
    check(C.set_elements(s["set"]) == {"216.180.246.0/24": 90, "2001:db8::5": None, "192.0.2.1-192.0.2.9": 5},
          "element keys: prefix/plain/range")


def t_db():
    now = time.time()
    path = make_db([
        ("198.51.100.1", "Ip", now + 5 * DAY, "CAPI", "ban", 0),
        ("198.51.100.1", "Ip", now + 365 * DAY, "cscli", "ban", 0),     # longer, later
        ("198.51.100.2", "Ip", now + 300 * DAY, "cscli", "ban", 0),
        ("198.51.100.3", "Ip", now - 60, "cscli", "ban", 0),            # expired
        ("198.51.100.4", "Ip", now + DAY, "cscli", "captcha", 0),       # not a ban
        ("198.51.100.5", "Ip", now + DAY, "crowdsec", "ban", 1),        # simulated
        ("2001:0db8:0000::0001", "Ip", now + 90 * DAY, "cscli", "ban", 0),
        ("216.180.246.0/24", "Range", now + 364 * DAY, "cscli-import", "ban", 0),
    ])
    try:
        b = C.active_bans(path, now)
        check(set(b["ip"]) == {"198.51.100.1", "198.51.100.2", "2001:db8::1"}, "active ip bans: %r" % b["ip"])
        check(abs(b["ip"]["198.51.100.1"][0] - (now + 365 * DAY)) <= 1 and b["ip"]["198.51.100.1"][1] == "cscli",
              "longest ban per value wins (+origin)")
        check(set(b["range"]) == {"216.180.246.0/24"}, "range bans")
        only = C.active_bans(path, now, values=["198.51.100.2", "198.51.100.3"])
        check(set(only["ip"]) == {"198.51.100.2"}, "values filter")
        check(C.db_path(lambda p: "db_config:\n  type: sqlite\n  db_path: /x/cs.db\n") == "/x/cs.db", "db_path")
        check(C.db_path(lambda p: "db_config:\n  type: mysql\n") is None, "non-sqlite -> None")
    finally:
        os.unlink(path)


def t_plans():
    now = 1_800_000_000.0
    bans = {"198.51.100.1": (now + 365 * DAY, "cscli"), "198.51.100.2": (now + 300 * DAY, "cscli"),
            "198.51.100.9": (now + 30 * DAY, "cscli")}
    sets = {"v4": {"crowdsec-blacklists-CAPI": {"198.51.100.1": 5 * DAY, "216.180.246.0": 300 * DAY,
                                                "198.51.100.7": DAY},
                   "crowdsec-blacklists-cscli": {"198.51.100.2": 300 * DAY - 600, "198.51.100.9": None}}}
    plan = C.refresh_plan(sets, bans, now)
    check(plan == [("v4", "crowdsec-blacklists-CAPI", "198.51.100.1", 365 * DAY)],
          "only the unextended element is re-timed: %r" % plan)
    prev = {("v4", "crowdsec-blacklists-CAPI", "198.51.100.9"): now - 10,     # expired, ban active
            ("v4", "crowdsec-blacklists-CAPI", "198.51.100.2"): now + 50 * DAY,  # deleted early (bouncer)
            ("v4", "crowdsec-blacklists-CAPI", "198.51.100.8"): now - 10,     # expired, no ban
            ("v4", "crowdsec-blacklists-cscli", "198.51.100.2"): now + 300 * DAY}
    cur = {("v4", "crowdsec-blacklists-cscli", "198.51.100.2"): 1}
    lap = C.lapsed_plan(prev, cur, bans, now)
    check(lap == [("v4", "crowdsec-blacklists-CAPI", "198.51.100.9", 30 * DAY)],
          "only a naturally expired element with an active ban is re-added: %r" % lap)
    s = C.render_refresh("ip", "crowdsec", "crowdsec-blacklists-CAPI", [("198.51.100.1", 99), ("198.51.100.3", 5)])
    check(s == "delete element ip crowdsec crowdsec-blacklists-CAPI { 198.51.100.1, 198.51.100.3 }\n"
               "add element ip crowdsec crowdsec-blacklists-CAPI { 198.51.100.1 timeout 99s, "
               "198.51.100.3 timeout 5s }\n", "refresh script is one delete+add transaction")
    rp = C.range_plan({"10.1.0.0/16": (now + 10 * DAY, "a"), "10.1.2.0/24": (now + 5 * DAY, "a"),
                       "10.1.3.0/24": (now + 50 * DAY, "a"), "203.0.113.0/24": (now + DAY, "a"),
                       "2001:db8::/48": (now + DAY, "a"), "192.0.2.0/24": (now - 5, "a")}, now)
    check(rp["v4"] == [("10.1.0.0/16", 10 * DAY), ("203.0.113.0/24", DAY)] and rp["v6"] == [("2001:db8::/48", DAY)],
          "range plan: contained/overlapping dropped, expired skipped: %r" % rp)
    check(C.range_plan({"2001:db8::/48": (now + DAY, "a")}, now, ("v4",)) == {"v4": []}, "disabled family skipped")
    txt = C.render_range_table(-10, "DROP", rp)
    check("add chain inet tuxwall_crowdsec_ranges input { type filter hook input priority -10; policy accept; }"
          in txt and "flush set inet tuxwall_crowdsec_ranges ranges4" in txt
          and "ip saddr @ranges4 counter drop" in txt and "ip6 saddr @ranges6 counter drop" in txt
          and "{ 10.1.0.0/16 timeout 864000s, 203.0.113.0/24 timeout 86400s }" in txt, "range table script")
    check("reject with icmpx admin-prohibited" in C.render_range_table(-10, "REJECT", rp), "REJECT deny_action")
    live = {"present": True, "chains": {"input": {"hook": "input", "prio": -10, "policy": "accept"}},
            "rules": [{"sets": ["ranges4"]}, {"sets": ["ranges6"]}],
            "sets": {"ranges4": {"elements": {"10.1.0.0/16": 10 * DAY - 30, "203.0.113.0/24": DAY - 30}},
                     "ranges6": {"elements": {"2001:db8::/48": DAY}}}}
    check(C.range_table_matches(live, -10, rp), "matching range table is left alone")
    live["sets"]["ranges4"]["elements"]["10.1.0.0/16"] = DAY
    check(not C.range_table_matches(live, -10, rp), "short range element -> rewrite")
    check(not C.range_table_matches(None, -10, rp), "absent range table -> write")


def t_reconcile():
    now = time.time()
    path = make_db([("198.51.100.1", "Ip", now + 365 * DAY, "cscli", "ban", 0),
                    ("198.51.100.2", "Ip", now + 300 * DAY, "cscli", "ban", 0),
                    ("2001:db8::1", "Ip", now + 90 * DAY, "cscli", "ban", 0),
                    ("216.180.246.0/24", "Range", now + 364 * DAY, "cscli-import", "ban", 0)])
    try:
        cfg = C.bouncer_config(CFG_NFT)
        v4 = bouncer_table(sets={"crowdsec-blacklists-CAPI": {"198.51.100.1": 5 * DAY},
                                 "crowdsec-blacklists-cscli": {"198.51.100.2": 300 * DAY - 100,
                                                               "216.180.246.0": 364 * DAY}})
        v6 = bouncer_table("ip6", "crowdsec6", "crowdsec6-chain-input",
                           sets={"crowdsec6-blacklists-cscli": {"2001:db8::1": 2 * DAY}})
        fake = FakeNft({("ip", "crowdsec"): v4, ("ip6", "crowdsec6"): v6})
        st = {}
        res = C.reconcile(st, fake.run, fake.run_in, cfg, path, now, dry_run=True)
        check(res["refresh_planned"] == 2 and fake.scripts == [] and res["range_table"] == "would-write",
              "dry run plans, writes nothing: %r" % res)
        res = C.reconcile(st, fake.run, fake.run_in, cfg, path, now)
        check(res["refreshed"] == 2 and res["refresh_failed"] == 0 and res["ranges"] == 1
              and res["range_table"] == "written" and res["missing"] == 0 and not res["errors"],
              "reconcile: %r" % res)
        check(any("delete element ip crowdsec crowdsec-blacklists-CAPI { 198.51.100.1 }" in s for s in fake.scripts)
              and any("delete element ip6 crowdsec6 crowdsec6-blacklists-cscli { 2001:db8::1 }" in s
                      for s in fake.scripts), "v4 + v6 re-time scripts")
        check(any("216.180.246.0/24 timeout" in s for s in fake.scripts), "Range ban written to the TuxWall table")
        check(res["families"]["v4"]["sets"] == {"crowdsec-blacklists-CAPI": 1, "crowdsec-blacklists-cscli": 2},
              "family summary")
        # a vanished element makes its batch fail -> per element retry, counted
        fake2 = FakeNft({("ip", "crowdsec"): v4}, fail_scripts=("198.51.100.1",))
        cfg4 = C.bouncer_config(CFG_NFT.replace("  ipv6:\n    enabled: true", "  ipv6:\n    enabled: false"))
        r2 = C.reconcile({}, fake2.run, fake2.run_in, cfg4, path, now)
        check(r2["refresh_failed"] == 1 and r2["refreshed"] == 0, "vanished element: not resurrected %r" % r2)
        # iptables mode: leftover range table removed, bouncer tables untouched
        fake3 = FakeNft({("inet", C.RANGE_TABLE): nft_doc([{"table": {"family": "inet", "name": C.RANGE_TABLE}}])})
        r3 = C.reconcile({"prev": {1: 2}}, fake3.run, fake3.run_in, C.bouncer_config(CFG_IPT), path, now)
        check(r3["range_table"] == "removed" and fake3.scripts == ["delete table inet tuxwall_crowdsec_ranges\n"],
              "iptables mode removes the leftover range table")
        fake4 = FakeNft({})
        r4 = C.reconcile({}, fake4.run, fake4.run_in, C.bouncer_config(CFG_IPT), path, now)
        check(fake4.scripts == [] and r4["range_table"] == "absent", "iptables mode, nothing to do: no writes")
        r5 = C.reconcile({}, fake4.run, fake4.run_in, cfg, "/nonexistent/cs.db", now)
        check(r5["errors"] and fake4.scripts == [], "no database -> error, no writes")
    finally:
        os.unlink(path)


# ── --netns: real nft in a scratch namespace ─────────────────────────────────

def t_netns():
    NS = "twcsfw"
    host = lambda: subprocess.run(["nft", "list", "tables"], capture_output=True, text=True).stdout  # noqa: E731
    before = host()
    subprocess.run(["ip", "netns", "add", NS], check=True)
    now = time.time()
    path = make_db([("198.51.100.1", "Ip", now + 365 * DAY, "cscli", "ban", 0),
                    ("198.51.100.2", "Ip", now + 300 * DAY, "cscli", "ban", 0),
                    ("216.180.246.0/24", "Range", now + 364 * DAY, "cscli-import", "ban", 0)])
    try:
        def run(cmd, timeout=30):
            p = subprocess.run(["ip", "netns", "exec", NS] + cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout

        def run_in(cmd, text, timeout=60):
            p = subprocess.run(["ip", "netns", "exec", NS] + cmd, input=text, capture_output=True, text=True,
                               timeout=timeout)
            return p.returncode, p.stdout + p.stderr
        rc, out = run_in(["nft", "-f", "-"], """table ip crowdsec {
  counter processed { }
  counter crowdsec-blacklists-CAPI { }
  set crowdsec-blacklists-CAPI { type ipv4_addr; flags timeout;
    elements = { 198.51.100.1 timeout 5d, 198.51.100.2 timeout 1d }
  }
  chain crowdsec-chain-input { type filter hook input priority -10; policy accept;
    counter name "processed"
    ip saddr @crowdsec-blacklists-CAPI counter name "crowdsec-blacklists-CAPI" drop
  }
}
""")
        check(rc == 0, "netns: bouncer-like table loads (%s)" % out[:200])
        cfg = C.bouncer_config(CFG_NFT.replace("  ipv6:\n    enabled: true", "  ipv6:\n    enabled: false"))
        st = C.status(run, cfg)
        check(st["families"]["v4"]["problems"] == [] and st["families"]["v4"]["rules"] == 1,
              "netns: real table passes the invariants %r" % st["families"]["v4"]["problems"])
        res = C.reconcile({}, run, run_in, cfg, path, now)
        check(res["refreshed"] == 2 and res["range_table"] == "written" and not res["errors"],
              "netns: reconcile %r" % res)
        tbl = C.list_table(run, "ip", "crowdsec", terse=False)
        els = tbl["sets"]["crowdsec-blacklists-CAPI"]["elements"]
        check(els["198.51.100.1"] > 364 * DAY and 299 * DAY < els["198.51.100.2"] < 301 * DAY,
              "netns: elements re-timed to the longest ban: %r" % els)
        rt = C.list_table(run, "inet", C.RANGE_TABLE, terse=False)
        check(rt and rt["sets"]["ranges4"]["elements"].get("216.180.246.0/24", 0) > 363 * DAY,
              "netns: Range ban in the TuxWall table")
        res2 = C.reconcile({}, run, run_in, cfg, path, now)
        check(res2["refreshed"] == 0 and res2["range_table"] == "ok", "netns: second pass is a no-op %r" % res2)
        # vanished element (bouncer lifted it meanwhile) is never resurrected
        gone = C.render_refresh("ip", "crowdsec", "crowdsec-blacklists-CAPI", [("198.51.100.1", 99),
                                                                               ("198.51.100.77", 99)])
        rc, out = run_in(["nft", "-f", "-"], gone)
        tbl = C.list_table(run, "ip", "crowdsec", terse=False)
        els = tbl["sets"]["crowdsec-blacklists-CAPI"]["elements"]
        check(rc != 0 and "198.51.100.77" not in els and els["198.51.100.1"] > 364 * DAY,
              "netns: batch with a vanished element aborts atomically")
        # back to iptables mode: range table removed
        r3 = C.reconcile({}, run, run_in, C.bouncer_config(CFG_IPT), path, now)
        check(r3["range_table"] == "removed" and C.list_table(run, "inet", C.RANGE_TABLE) is None,
              "netns: iptables mode removes the range table")
    finally:
        subprocess.run(["ip", "netns", "del", NS])
        os.unlink(path)
    check(host() == before, "netns: host nft tables unchanged")


def main():
    t_config()
    t_state()
    t_db()
    t_plans()
    t_reconcile()
    if "--netns" in sys.argv:
        t_netns()
    print("crowdsec_fw_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
