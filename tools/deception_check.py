#!/usr/bin/env python3
"""Deception layer checks (www/includes/api_server.py), all sandboxed:

  python3 tools/deception_check.py          pure tests + a loopback tarpit load test (CI)

Every file path the code touches is remapped into a temp dir, subprocess.run
is replaced by a fake (cscli/ufw/ss/systemctl/ip are recorded or answered
from fixtures, anything else fails the test), the collector transport
(_report_http_post) is a stub and urllib.request.urlopen raises - nothing
here bans, opens a firewall rule or sends a report. Global addresses used
below only ever reach the stubs.

Covers: BoundedTTLMap; tarpit slot accounting (per-IP / total caps reserved
before a thread exists, release, thread-start failure, generation stop) and
the >= threshold with a once-per-source flag (also for connections dropped
over capacity); accept() errors never kill a listener; the LAN guard
(LAN/VLAN/WG + the delegated global IPv6 prefix, loopback, ULA); the
never-ban guard on every ban/report path (honeypot catch, canary webhook,
the cscli helper, _spawn_report) incl. own/recent WAN, Cloudflare/protected,
collector-published ranges and infrastructure IPs; a spared source judged
afresh after an allowlist add/remove (through the API), a never-ban change,
an unban or the recheck age while real catches stay deduplicated (honeypot
and canary, campaign 3 C3-1); cscli return codes; the
retired SNMP/UDP evidence; reporting "enabled" (absent = on; off holds the
queue, on resumes it) and the persistent queue (no key on disk, 0600 atomic
writes, retry/backoff on network/429/5xx, refusal on 4xx, survives a
restart); the community settings view/update (strict input, audit, cached
key status, no-op re-saves), a delivery clearing a transient last error, and
the 24 h deception-ban count; report categories with port/service (multi-word
Redis commands); the canary firewall plan (IPv4 only, grace before closing,
leftovers removed), the canary WAN IPv4 picked exactly like
opencanary-render-conf on multi-address fixtures (documentation ranges
treated as public inside the test) and the cached tail read of opencanary.log.
The load test binds a sandboxed listener on 127.0.0.2 (never the WAN) and
shows one client can no longer exceed the per-IP cap and fds stay bounded.
"""
import importlib.util
import json
import os
import shutil
import socket
import stat
import sys
import tempfile
import threading
import time

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT_DIR, "www", "includes", "api_server.py")
sys.dont_write_bytecode = True

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


spec = importlib.util.spec_from_file_location("api_server_deception", TARGET)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)

TMP = tempfile.mkdtemp(prefix="deception-check-")
A.REPORTING_CONF_FILE = os.path.join(TMP, "etc", "reporting.json")
A.REPORT_QUEUE_FILE = os.path.join(TMP, "lib", "report-queue.json")
A.REPORT_PAUSE_FILE = os.path.join(TMP, "lib", "report-queue.pause")
A.RECENT_WAN_FILE = os.path.join(TMP, "lib", "recent-wan-ips.json")
A.HONEY_CONF_FILE = os.path.join(TMP, "lib", "honeypot.json")
A.CANARY_CONF = os.path.join(TMP, "opencanaryd", "opencanary.conf")
A.CANARY_LOG = os.path.join(TMP, "opencanary", "opencanary.log")
A.COMMUNITY_AUTO_STATE = os.path.join(TMP, "etc", "community-auto.json")
A.COMMUNITY_AUDIT_LOG = os.path.join(TMP, "log", "community-settings-audit.log")
for d in ("etc", "lib", "opencanaryd", "opencanary"):
    os.makedirs(os.path.join(TMP, d), exist_ok=True)
for name in ("REPORTING_CONF_FILE", "REPORT_QUEUE_FILE", "REPORT_PAUSE_FILE", "RECENT_WAN_FILE",
             "HONEY_CONF_FILE",
             "CANARY_CONF", "CANARY_LOG", "COMMUNITY_AUTO_STATE", "COMMUNITY_AUDIT_LOG"):
    assert getattr(A, name).startswith(TMP), name

# ── fixtures: the router (documentation / private ranges) ───────────────────
WAN4 = "198.51.100.1"            # stands in for the WAN IPv4
WAN6 = "2001:470:ffff:9::2"      # WAN IPv6 (global, so the guard must name it)
DELEGATED = "2001:470:ffff:1::"  # delegated global /64 on the LAN
ATTACKER = "45.95.147.10"        # global sources: only ever reach the stubs
ATTACKER2 = "185.220.101.77"
ATTACKER6 = "2a0e:97c0:3e3::77"
CF = "104.16.0.1"                # Cloudflare edge (protected)
NTP = "162.159.200.1"            # stands in for an NTP server (never-ban set)
IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo
1: lo    inet6 ::1/128 scope host
2: wan0    inet %s/24 brd 198.51.100.255 scope global wan0
2: wan0    inet6 %s/128 scope global
3: lan0    inet 192.168.1.1/24 brd 192.168.1.255 scope global lan0
3: lan0    inet6 %s1/64 scope global
3: lan0    inet6 fd00:1::1/64 scope global
3: lan0    inet6 fe80::1/64 scope link
4: lan0.10    inet 192.168.10.1/24 scope global lan0.10
5: opt0    inet 192.168.2.1/24 scope global opt0
6: wg0    inet 10.0.0.1/24 scope global wg0
6: wg0    inet6 fd00:2::1/64 scope global
""" % (WAN4, WAN6, DELEGATED)


class Proc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class FakeRun:
    """subprocess.run replacement: records everything, answers fixtures."""

    def __init__(self):
        self.calls = []
        self.cscli_rc = 0
        self.ss = ""
        self.active = "active"
        self.ip4 = "[]"            # `ip -j -4 addr show <wan>` answer
        self.allow = {}            # allowlist name -> [values] (cscli allowlists ...)

    def __call__(self, cmd, *a, **kw):
        cmd = list(cmd)
        self.calls.append(cmd)
        exe = os.path.basename(cmd[0])
        if exe == "cscli" and cmd[1:2] == ["allowlists"]:
            if cmd[2] == "list":
                return Proc(0, json.dumps([
                    {"name": n, "items": [{"value": v, "expiration": "0001-01-01T00:00:00Z"} for v in vals]}
                    for n, vals in self.allow.items()]))
            if cmd[2] == "add":
                self.allow.setdefault(cmd[3], []).append(cmd[4])
            elif cmd[2] == "remove":
                self.allow[cmd[3]] = [v for v in self.allow.get(cmd[3], []) if v != cmd[4]]
            return Proc(0, "", "")
        if exe == "cscli":
            return Proc(self.cscli_rc, "" if not self.cscli_rc else "",
                        "" if not self.cscli_rc else "level=fatal msg=\"boom\"")
        if cmd[:4] == ["ip", "-j", "-4", "addr"]:
            return Proc(0, self.ip4)
        if cmd[:3] == ["ip", "-o", "addr"]:
            return Proc(0, IP_ADDR)
        if cmd[:2] == ["ss", "-Htlnp"]:
            return Proc(0, self.ss)
        if cmd[:2] == ["systemctl", "is-active"]:
            return Proc(0 if self.active == "active" else 3, self.active + "\n")
        if exe == "ufw":
            return Proc(0, "Rule updated\n")
        if cmd[:2] == ["ip", "-j"]:
            return Proc(0, "[]")
        if exe == "getent":
            return Proc(2, "")
        raise AssertionError("unexpected command in test: %s" % cmd)

    def cscli(self):
        return [c for c in self.calls if os.path.basename(c[0]) == "cscli"]

    def ufw(self):
        return [c for c in self.calls if os.path.basename(c[0]) == "ufw"]


RUN = FakeRun()
A.subprocess.run = RUN
# CrowdSec allowlists: none here (tools/allowlist_check.py covers them); a
# never-stale empty cache keeps cscli out of the guard paths counted below.
A._ALLOWLIST_CACHE.update(ts=time.time() + 10 ** 9, nets=(), ok=True)


def _no_network(*a, **kw):
    raise AssertionError("network access attempted in a test")


A.urllib.request.urlopen = _no_network
SENT = []
TRANSPORT = {"mode": "ok"}


def fake_post(url, body, headers, timeout):
    data = json.loads(body.decode())
    SENT.append({"url": url, "body": data, "headers": headers})
    m = TRANSPORT["mode"]
    if m == "ok":
        return 200, {"ok": True, "accepted": True}
    if m == "network":
        raise OSError("connection refused")
    if m == "503":
        return 503, {"ok": False, "error": "busy"}
    if m == "429":
        return 429, {"ok": False, "error": "Rate limit exceeded"}
    if m == "400":
        return 400, {"ok": False, "error": "Refusing protected infrastructure IP"}
    if m == "rotate":
        # the old key is revoked and the key file changes mid-pass
        if data.get("key") == ROTATE["old"]:
            write_reporting({"url": "https://collector.invalid/report", "key": ROTATE["new"]})
            return 403, {"ok": False, "error": "Reporter key revoked"}
        return 200, {"ok": True, "accepted": True}
    if m == "register":
        if data.get("action") == "status":
            return 200, {"ok": True, "found": True, "status": "pending", "approved": False,
                         "created": 1.0, "trusted_after": None}
        return 200, {"ok": True, "status": "pending", "approved": False, "created": 1.0,
                     "trusted_after": None}
    raise AssertionError(m)


ROTATE = {"old": "old-key-" + "a" * 24, "new": "new-key-" + "b" * 24}


A._report_http_post = fake_post
A._honey_wan_ip = lambda: WAN4
A._honey_wan6 = lambda: WAN6
A._honey_wan_iface = lambda: "wan0"
A._lan_subnets = lambda: [A.ipaddress.ip_network(n) for n in
                          ("192.168.1.0/24", "192.168.10.0/24", "192.168.2.0/24", "10.0.0.0/24",
                           "127.0.0.0/8")]
A._community_never_ban_ips = lambda: {NTP, "192.168.1.1", WAN4}
A.suricata_evidence_for_ip = lambda ip: ("", "")
A.suricata_alerts_for_ip = lambda ip: []
A.ufw_evidence_for_ip = lambda ip: None
A.ufw_evidence_phrase = lambda ev: ""
A.get_security_monitor = lambda: type("M", (), {"by_ip": {}})()
A._invalidate_crowdsec_decisions_cache = lambda: None
# interfaces.json is read from the real path by the LAN guard; harmless (read
# only) but keep the fixture authoritative
A._HONEY_LAN.update(ts=0.0, nets=None)
_real_open = open


def write_reporting(data):
    with open(A.REPORTING_CONF_FILE, "w") as f:
        json.dump(data, f)


def reset_queue():
    A.REPORT_Q.update(loaded=False, items=[], stats={})
    for p in (A.REPORT_QUEUE_FILE,):
        if os.path.exists(p):
            os.unlink(p)
    SENT.clear()


def reset_honey():
    with A.HONEY_APPLY_LOCK:
        A.HONEY_STATE["active"].clear()
        A.HONEY_STATE["per_ip"].clear()
        A.HONEY_STATE["hits"].clear()
        for k in A.HONEY_STATE["stats"]:
            A.HONEY_STATE["stats"][k] = 0
        A.HONEY_STATE["log"] = []


# the queue worker must not run on its own during the tests: process by hand
A._report_worker_ensure = lambda: None


# ── tests ────────────────────────────────────────────────────────────────────

def t_ttl_map():
    m = A.BoundedTTLMap(3, 10)
    for i, k in enumerate("abcd"):
        m.set(k, i, now=100 + i)
    check(len(m) == 3 and m.get("a", now=104) is None and m.get("d", now=104) == 3, "LRU cap")
    check(m.get("b", now=111) is None and m.get("d", now=112) == 3, "TTL from the last write")
    m.set("d", 9, now=120)
    check(m.get("d", now=129) == 9 and m.get("d", now=131) is None, "rewrite refreshes the TTL")
    check(len(m.items(now=200)) == 0, "items() expires")
    big = A.BoundedTTLMap(1000, 3600)
    for i in range(50000):
        big.set("10.%d.%d.%d" % (i >> 16, (i >> 8) & 255, i & 255), i, now=1000)
    check(len(big) == 1000 and big.evicted == 49000, "never grows with the internet")
    check(isinstance(A.CANARY_RECENT, A.BoundedTTLMap)
          and isinstance(A.HONEY_STATE["hits"], A.BoundedTTLMap), "canary + honeypot maps bounded")


def t_slots():
    reset_honey()
    sids = [A._honey_admit(ATTACKER, 23) for _ in range(A.HONEY_MAX_PER_IP + 5)]
    ok = [s for s in sids if s is not None]
    check(len(ok) == A.HONEY_MAX_PER_IP, "per-IP cap fires (%d)" % len(ok))
    check(A.HONEY_STATE["per_ip"][ATTACKER] == A.HONEY_MAX_PER_IP, "per-IP counter")
    ok2 = [A._honey_admit(ATTACKER, p) for p in (445, 3389, 5555)]
    check(ok2 == [None, None, None], "per-IP cap spans every port (was keyed (ip, port))")
    check(A.HONEY_STATE["stats"]["dropped"] == 8, "drops counted")
    A._honey_release(ok[0])
    check(A._honey_admit(ATTACKER, 445) is not None, "released slot is reusable")
    reset_honey()
    n = 0
    for i in range(A.HONEY_MAX_TOTAL + 20):
        if A._honey_admit("45.95.%d.%d" % (i // 200, i % 200), 23) is not None:
            n += 1
    check(n == A.HONEY_MAX_TOTAL and len(A.HONEY_STATE["active"]) == A.HONEY_MAX_TOTAL,
          "total cap holds")
    for sid in list(A.HONEY_STATE["active"]):
        A._honey_release(sid)
    check(not A.HONEY_STATE["active"] and not A.HONEY_STATE["per_ip"], "all released")
    check(A._honey_release(999999) is None, "double release is harmless")


def t_threshold():
    reset_honey()
    acts = [A._honey_count_hit(ATTACKER, 3)[1] for _ in range(6)]
    check(acts == [False, False, True, False, False, False], "threshold 3: acts once at 3")
    acts = [A._honey_count_hit(ATTACKER2, 1)[1] for _ in range(3)]
    check(acts == [True, False, False], "threshold 1: first hit")
    reset_honey()
    for _ in range(4):
        A._honey_count_hit(ATTACKER, 5)
    check(A._honey_count_hit(ATTACKER, 2)[1] is True, "lowered threshold: >= fires (== never would)")
    reset_honey()
    A._honey_count_hit(ATTACKER, 1)
    A._honey_unaction(ATTACKER)
    check(A._honey_count_hit(ATTACKER, 1)[1] is True, "failed catch start retried")
    check(A.HONEY_STATE["stats"]["unique"] == 1 and A.HONEY_STATE["stats"]["total"] == 2,
          "stats total/unique")


class FakeListenSock:
    """accept() script: errors, connections, then the socket closes."""

    def __init__(self, script):
        self.script = list(script)
        self.closed = False

    def accept(self):
        if not self.script:
            self.closed = True
            raise OSError(9, "Bad file descriptor")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def fileno(self):
        return -1 if self.closed else 3

    def close(self):
        self.closed = True


class FakeConn:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def t_listener():
    reset_honey()
    A._HONEY_CONF_CACHE.update(ts=time.time() + 3600,
                               conf={"enabled": True, "ports": [23], "auto_ban": True,
                                     "ban_threshold": 2, "max_hold": 10})
    catches, tarpits = [], []
    real_catch, real_tarpit, real_sleep = A._honey_catch, A._honey_tarpit, A.time.sleep
    A._honey_catch = lambda ip, port, auto: catches.append((ip, port, auto))
    A._honey_tarpit = lambda conn, ip, port, sid=None, gen=None: (tarpits.append(sid),
                                                                  A._honey_release(sid))
    A.time.sleep = lambda s: None
    A.HONEY_ACCEPT_BACKOFF = 0
    try:
        conns = [FakeConn() for _ in range(5)]
        lan = FakeConn()
        script = [OSError(24, "Too many open files"), (conns[0], (ATTACKER, 1)),
                  OSError(23, "File table overflow"), (conns[1], (ATTACKER, 2)),
                  (lan, ("192.168.1.50", 3)), (conns[2], (ATTACKER, 4)),
                  OSError(103, "Software caused connection abort"), (conns[3], (ATTACKER2, 5))]
        sock = FakeListenSock(script)
        A._honey_listener(sock, 23)
        check(sock.closed and not sock.script, "listener survives EMFILE/ENFILE/ECONNABORTED")
        check(A.HONEY_STATE["stats"]["accept_errors"] == 3, "accept errors counted")
        check(lan.closed and A.HONEY_STATE["stats"]["lan_guard"] == 1, "LAN source closed + counted")
        check(len(tarpits) == 4, "four sources trapped")
        check(catches == [(ATTACKER, 23, True)], "threshold 2 -> exactly one catch")
        # thread start failure: slot released, connection closed
        real_thread = A.threading.Thread

        class Boom(real_thread):
            def start(self):
                raise RuntimeError("can't start new thread")
        A.threading.Thread = Boom
        try:
            c = FakeConn()
            reset_honey()
            A._honey_listener(FakeListenSock([(c, (ATTACKER, 9))]), 23)
        finally:
            A.threading.Thread = real_thread
        check(c.closed and not A.HONEY_STATE["active"] and not A.HONEY_STATE["per_ip"],
              "thread-start failure: slot released, connection closed")
        check(A.HONEY_STATE["stats"]["thread_errors"] == 1, "thread error counted")
        # over capacity still counts toward the threshold (never skipped)
        reset_honey()
        A._HONEY_CONF_CACHE["conf"]["ban_threshold"] = 3
        for _ in range(A.HONEY_MAX_PER_IP):
            A._honey_admit(ATTACKER, 23)
        catches.clear()
        drops = [FakeConn() for _ in range(3)]
        A._honey_listener(FakeListenSock([(x, (ATTACKER, 1)) for x in drops]), 23)
        check(all(x.closed for x in drops) and A.HONEY_STATE["stats"]["dropped"] == 3,
              "over the per-IP cap: dropped")
        check(catches == [(ATTACKER, 23, True)], "dropped connections still reach the threshold")
    finally:
        A._honey_catch, A._honey_tarpit, A.time.sleep = real_catch, real_tarpit, real_sleep
        A.HONEY_ACCEPT_BACKOFF = 1.0
        reset_honey()


def t_lan_guard():
    A._HONEY_LAN.update(ts=0.0, nets=None)
    lan = ["192.168.1.50", "192.168.10.20", "192.168.2.9", "10.0.0.5", "127.0.0.1",
           DELEGATED + "1234", DELEGATED + "abcd:1", "fd00:1::99", "fd00:2::3", "fe80::1", "::1",
           "::ffff:192.168.1.50", "not-an-ip"]
    for ip in lan:
        check(A._honey_is_lan(ip), "LAN guard: %s" % ip)
    for ip in (ATTACKER, ATTACKER6, "2001:470:ffff:2::1", WAN6, WAN4):
        check(not A._honey_is_lan(ip), "not LAN: %s" % ip)
    nets = [str(n) for n in A._honey_lan_nets()]
    check(DELEGATED + "/64" in nets, "delegated global /64 is a LAN network")
    check(not any(n.startswith("198.51.100.") for n in nets) and WAN6 + "/128" not in nets,
          "the WAN is never a LAN network")


def t_guard_paths():
    reset_queue()
    write_reporting({"enabled": True, "url": "https://collector.invalid/report", "key": "k" * 32})
    with A.COMMUNITY_BANS_LOCK:
        A.COMMUNITY_BANS_CACHE["data"] = {"protected": ["203.0.113.0/24", "93.184.0.0/16"]}
    A._NEVER_BAN.update(ts=0.0, ips=None, refreshing=False)
    blocked = {
        "192.168.1.50": "LAN", DELEGATED + "77": "LAN", "fd00:1::5": "non-global",
        WAN4: "own", WAN6: "own", CF: "protected", "2606:4700::1": "protected",
        "93.184.215.14": "published", NTP: "infrastructure", "198.51.100.77": "non-global",
        "::ffff:" + CF: "protected",
    }
    with open(A.RECENT_WAN_FILE, "w") as f:
        json.dump(["71.1.2.3"], f)
    blocked["71.1.2.3"] = "recent WAN"
    for ip, what in blocked.items():
        check(A._deception_guard(ip) is not None, "guard refuses %s (%s)" % (ip, what))
    check(A._deception_guard(ATTACKER) is None and A._deception_guard(ATTACKER6) is None,
          "guard passes real attackers")
    RUN.calls.clear()
    reset_honey()
    for ip in blocked:
        ok, err = A._deception_cscli_ban(ip, "8760h", "test")
        check(not ok and "never-ban" in err, "cscli helper refuses %s" % ip)
        A._honey_catch(ip, 23, True)
        r = A._spawn_report(ip, "x", "honeypot", "scan")
        check(isinstance(r, dict) and not r.get("ok"), "_spawn_report refuses %s" % ip)
    check(not RUN.cscli(), "no cscli call for any protected/own/LAN source")
    check(not A.REPORT_Q["items"], "nothing queued for them")
    check(A.HONEY_STATE["stats"]["guarded"] == len(blocked), "honeypot guard counted")
    # canary webhook path
    A.CANARY_RECENT.clear()
    for ip in [x for x in blocked if ":" not in x or x.startswith("2")]:
        res = A.handle_canary_hit(canary_body(ip, 4002, 22))
        check(res.get("ok") and not res.get("banned"), "canary refuses %s (%s)" % (ip, res.get("message")))
    check(not RUN.cscli() and not A.REPORT_Q["items"], "canary: no ban, no report for them")
    # and the real attacker passes every path (stubs only)
    A.CANARY_RECENT.clear()
    res = A.handle_canary_hit(canary_body(ATTACKER, 4002, 22))
    check(res.get("banned") is True and len(RUN.cscli()) == 1, "canary bans a real attacker (stub)")
    check(RUN.cscli()[0][RUN.cscli()[0].index("--reason") + 1] == "canary/ssh-login-attempt",
          "canary decision reason")
    q = A.REPORT_Q["items"]
    check(len(q) == 1 and q[0]["payload"]["category"] == "ssh"
          and "SSH 22/tcp" in q[0]["payload"]["reason"], "canary report: ssh + port/service")
    res = A.handle_canary_hit(canary_body(ATTACKER, 4002, 22))
    check(res.get("message") == "recently handled" and len(RUN.cscli()) == 1, "canary dedupe")
    # cscli failure: reported, but not counted as banned
    RUN.cscli_rc = 1
    A.CANARY_RECENT.clear()
    res = A.handle_canary_hit(canary_body(ATTACKER2, 9001, 1433))
    check(res.get("banned") is False and "rc=1" in (res.get("ban_error") or ""), "cscli rc checked")
    check(A.REPORT_Q["items"][-1]["payload"]["category"] == "bruteforce", "mssql login -> bruteforce")
    reset_honey()
    A._honey_ban(ATTACKER2)
    check(A.HONEY_STATE["stats"]["ban_failed"] == 1 and A.HONEY_STATE["stats"]["banned"] == 0,
          "honeypot ban failure not counted as banned")
    RUN.cscli_rc = 0
    # SNMP / UDP evidence: never banned or reported
    before = len(RUN.cscli())
    A.CANARY_RECENT.clear()
    res = A.handle_canary_hit(canary_body("45.95.147.99", 13001, 161))
    check(res.get("ignored") and len(RUN.cscli()) == before, "UDP (SNMP) evidence never banned")
    check(not any(i["payload"]["ip"] == "45.95.147.99" for i in A.REPORT_Q["items"]),
          "UDP evidence never reported")
    # honeypot catch for a real attacker: ban (stub) + report with the service
    reset_queue()
    A._honey_catch(ATTACKER6, 3389, True)
    q = A.REPORT_Q["items"]
    check(len(q) == 1 and q[0]["payload"]["category"] == "rdp"
          and q[0]["payload"]["reason"].startswith("honeypot: RDP probe on 3389/tcp"),
          "honeypot report: rdp + port/service")
    check(A.HONEY_STATE["stats"]["banned"] == 1 and A.HONEY_STATE["stats"]["reported"] == 1,
          "honeypot catch: banned + reported")
    A._honey_catch(ATTACKER, 23, False)
    check(len(RUN.cscli()) == before + 1, "auto_ban off: no local ban")
    check(A.REPORT_Q["items"][-1]["payload"]["category"] == "scan"
          and "telnet probe on 23/tcp" in A.REPORT_Q["items"][-1]["payload"]["reason"],
          "auto_ban off: still reported (telnet -> scan)")
    with A.COMMUNITY_BANS_LOCK:
        A.COMMUNITY_BANS_CACHE["data"] = None


def canary_body(ip, logtype, port, logdata=None):
    fields = [{"title": "src_host", "value": ip}, {"title": "logtype", "value": logtype},
              {"title": "dst_port", "value": port},
              {"title": "logdata", "value": json.dumps(logdata or {"USERNAME": "root"})}]
    return {"attachments": [{"fields": fields}]}


def hp_hit(ip, port=445, auto_ban=True, now=None):
    """One honeypot connection as the accept loop handles it (catch inline)."""
    _, act = A._honey_count_hit(ip, 1, now)
    if act:
        A._honey_catch(ip, port, auto_ban)
    return act


def bans_of(ip):
    return len([c for c in RUN.cscli() if c[1:3] == ["decisions", "add"] and ip in c])


def queued(ip):
    return len([i for i in A.REPORT_Q["items"] if i["payload"]["ip"] == ip])


def t_guard_recheck():
    """C3-1: a spared source is judged afresh after the allowlist / never-ban
    set changes and after an unban; real catches stay deduplicated."""
    reset_queue()
    reset_honey()
    write_reporting({"enabled": True, "url": "https://collector.invalid/report", "key": "k" * 32})
    A._NEVER_BAN.update(ts=0.0, ips=None, refreshing=False)
    A.CANARY_RECENT.clear()
    RUN.calls.clear()
    RUN.allow = {"lab": []}
    real = (A._csfw, A._allowlist_lockout_live, A._community_never_ban_ips)
    A._csfw = None
    A._allowlist_lockout_live = lambda net, client_ip: []
    with A._ALLOWLIST_CACHE_LOCK:
        A._ALLOWLIST_CACHE.update(ts=time.time(), nets=(), refreshing=False, ok=True)
    X, Y, Z, W = "45.95.147.20", "45.95.147.21", "45.95.147.22", "45.95.147.23"
    admin = {"username": "boss", "role": "admin"}

    def allow(ip, add=True):
        st, res = (A.allowlist_add if add else A.allowlist_remove)({"list": "lab", "value": ip}, admin)
        return st == 200 and res.get("ok")

    try:
        # honeypot: allowlisted -> spared; removed -> caught on the next hit
        check(allow(X), "allowlist add (API)")
        g0 = A.HONEY_STATE["stats"]["guarded"]
        check(hp_hit(X) and bans_of(X) == 0 and not queued(X), "honeypot: allowlisted source spared")
        check("allowlist lab" in A.HONEY_STATE["log"][-1], "honeypot: guard reason logged")
        check(not hp_hit(X) and not hp_hit(X) and A.HONEY_STATE["stats"]["guarded"] == g0 + 1,
              "honeypot: spared source not re-judged on every hit (guard memo)")
        gen = A._deception_guard_gen()
        check(allow(X, add=False) and A._deception_guard_gen() > gen,
              "allowlist remove (API) bumps the guard generation")
        check(hp_hit(X) and bans_of(X) == 1 and queued(X) == 1,
              "honeypot: caught (ban + report) on the first hit after the removal")
        check(not any(hp_hit(X) for _ in range(5)) and bans_of(X) == 1,
              "honeypot: a real catch stays deduplicated (no re-ban per hit)")
        # admin unban -> the next hit counts again
        check(A.unban_crowdsec_ip(X)["ok"], "unban")
        check(hp_hit(X) and bans_of(X) == 2, "honeypot: unban -> next hit caught again")
        # caught, then allowlisted (ban lifted), then removed again -> caught again
        check(allow(X) and hp_hit(X) and bans_of(X) == 2, "allowlist add after a catch: spared")
        check(allow(X, add=False) and hp_hit(X) and bans_of(X) == 3,
              "honeypot: removed again -> caught again")

        # canary: same sequence
        check(allow(Y), "allowlist add Y")
        r = A.handle_canary_hit(canary_body(Y, 17001, 6379, {"CMD": "INFO"}))
        check(r.get("guard") == "CrowdSec allowlist lab" and not r.get("banned") and bans_of(Y) == 0,
              "canary: allowlisted source spared")
        r = A.handle_canary_hit(canary_body(Y, 17001, 6379, {"CMD": "INFO"}))
        check(r.get("guard") == "CrowdSec allowlist lab" and bans_of(Y) == 0,
              "canary: still spared (memo answers with the reason)")
        check(allow(Y, add=False), "allowlist remove Y")
        r = A.handle_canary_hit(canary_body(Y, 17001, 6379, {"CMD": "CONFIG SET"}))
        check(r.get("banned") is True and bans_of(Y) == 1 and queued(Y) == 1,
              "canary: caught on the first hit after the removal (not 'recently handled')")
        check(A.REPORT_Q["items"][-1]["payload"]["category"] == "malware",
              "canary: CONFIG SET reported as malware (C3-2)")
        r = A.handle_canary_hit(canary_body(Y, 17001, 6379))
        check(r.get("message") == "recently handled" and bans_of(Y) == 1, "canary: catch deduplicated")
        check(A.unban_crowdsec_ip(Y)["ok"], "unban Y")
        r = A.handle_canary_hit(canary_body(Y, 4002, 22))
        check(r.get("banned") is True and bans_of(Y) == 2, "canary: unban -> next hit caught again")

        # the never-ban set changes (e.g. an old NTP/DNS address goes away)
        A._community_never_ban_ips = lambda: {NTP, "192.168.1.1", WAN4, Z}
        A._NEVER_BAN.update(ts=0.0, ips=None, refreshing=False)
        check(hp_hit(Z) and bans_of(Z) == 0, "honeypot: never-ban source spared")
        r = A.handle_canary_hit(canary_body(Z, 4002, 22))
        check(r.get("guard") and bans_of(Z) == 0, "canary: never-ban source spared")
        A._community_never_ban_ips = lambda: {NTP, "192.168.1.1", WAN4}
        gen = A._deception_guard_gen()
        A._never_ban_refresh()
        check(A._deception_guard_gen() > gen, "never-ban change bumps the guard generation")
        check(hp_hit(Z) and bans_of(Z) == 1, "honeypot: caught once it left the never-ban set")
        r = A.handle_canary_hit(canary_body(Z, 4002, 22))
        check(r.get("banned") is True and bans_of(Z) == 2, "canary: caught once it left the never-ban set")
        gen = A._deception_guard_gen()
        A._never_ban_refresh()
        check(A._deception_guard_gen() == gen, "unchanged never-ban set: no bump")

        # memo expiry without a generation change (LAN/WAN/protected inputs)
        A._community_never_ban_ips = lambda: {NTP, "192.168.1.1", WAN4, W}
        A._NEVER_BAN.update(ts=0.0, ips=None, refreshing=False)
        check(hp_hit(W) and bans_of(W) == 0, "spared W")
        check(not hp_hit(W, now=time.time() + 5), "memo fresh within the recheck window")
        A._community_never_ban_ips = lambda: {NTP, "192.168.1.1", WAN4}
        gen = A._deception_guard_gen()
        # swapped in without a refresh: no bump, only the memo's age expires it
        A._NEVER_BAN.update(ts=time.time(), ips=frozenset({NTP, "192.168.1.1", WAN4}))
        check(not hp_hit(W, now=time.time() + 10) and A._deception_guard_gen() == gen,
              "same generation, fresh memo: still spared")
        check(hp_hit(W, now=time.time() + A.DECEPTION_GUARD_RECHECK + 1) and bans_of(W) == 1,
              "stale memo re-judged after DECEPTION_GUARD_RECHECK")
        check(A._deception_forget("bogus") == 0 and A._deception_forget("45.95.147.0/24") >= 1,
              "_deception_forget: invalid ignored, network form works")
    finally:
        A._csfw, A._allowlist_lockout_live, A._community_never_ban_ips = real
        A._NEVER_BAN.update(ts=0.0, ips=None, refreshing=False)
        with A._ALLOWLIST_CACHE_LOCK:
            A._ALLOWLIST_CACHE.update(ts=time.time() + 10 ** 9, nets=(), refreshing=False, ok=True)
        RUN.allow = {}
        A.CANARY_RECENT.clear()
        reset_honey()
        reset_queue()


def t_categories():
    dc = A.deception_category
    check(dc("honeypot", 3389) == "rdp" and dc("honeypot", 22) == "ssh", "honeypot rdp/ssh")
    check(dc("honeypot", 23) == "scan" and dc("honeypot", 445) == "scan"
          and dc("honeypot", 5555) == "scan", "honeypot telnet/smb/adb -> scan")
    check(dc("honeypot", 8080) == "web" and dc("honeypot", 25) == "spam", "honeypot web/mail")
    check(dc("canary", 22, 4000) == "ssh" and dc("canary", 22, 4002) == "ssh", "canary ssh")
    check(dc("canary", 1433, 9001) == "bruteforce" and dc("canary", 5900, 12001) == "bruteforce",
          "canary mssql/vnc logins")
    check(dc("canary", 6379, 17001, {"CMD": "CONFIG"}) == "malware"
          and dc("canary", 6379, 17001, {"CMD": "INFO"}) == "scan", "canary redis")
    # C3-2: OpenCanary logs multi-word commands ("CONFIG GET"); the verb decides
    for cmd in ("CONFIG GET", "CONFIG SET", "config set dir", " SLAVEOF 192.0.2.9 6379",
                "replicaof no one", "MODULE LOAD /tmp/x.so", "Eval", "FLUSHALL", "SCRIPT LOAD"):
        check(dc("canary", 6379, 17001, {"CMD": cmd}) == "malware", "redis %r -> malware" % cmd)
    for cmd in ("INFO server", "PING", "", "   ", "CONFIGX GET", "GET config", None, 7):
        check(dc("canary", 6379, 17001, {"CMD": cmd}) == "scan", "redis %r -> scan" % (cmd,))
    check(dc("canary", 6379, 17001, None) == "scan", "redis without logdata -> scan")
    check(all(dc("honeypot", p) in A.REPORT_CATEGORIES for p in range(1, 70000, 97)),
          "always a collector category")
    check(A.deception_service(445) == "SMB" and A.deception_service(4444) == "port 4444",
          "service names")
    # a specific category survives the UFW refinement; a generic one is refined
    reset_queue()
    write_reporting({"enabled": True, "key": "k" * 32})
    A.ufw_evidence_for_ip = lambda ip: {"packets": 7}
    A.ufw_evidence_phrase = lambda ev: "port scan of 12 ports"
    try:
        A._spawn_report(ATTACKER, "honeypot: RDP probe on 3389/tcp", "honeypot", "rdp")
        A._spawn_report(ATTACKER2, "canary: redis command (Redis 6379/tcp)", "canary", "other")
    finally:
        A.ufw_evidence_for_ip = lambda ip: None
        A.ufw_evidence_phrase = lambda ev: ""
    cats = {i["payload"]["ip"]: i["payload"] for i in A.REPORT_Q["items"]}
    check(cats[ATTACKER]["category"] == "rdp" and cats[ATTACKER2]["category"] == "scan",
          "specific kept, generic refined")
    check(cats[ATTACKER]["hits"] == 7 and len(cats[ATTACKER]["reason"]) <= 96, "evidence attached")


def t_reporting():
    reset_queue()
    os.path.exists(A.REPORTING_CONF_FILE) and os.unlink(A.REPORTING_CONF_FILE)
    check(A.load_reporting_conf()["enabled"] is True, "no file: reporting on (historical default)")
    write_reporting({"url": "https://collector.invalid/report", "key": "s3cr3tkey" * 4})
    check(A.load_reporting_conf()["enabled"] is True, "enabled absent: on")
    write_reporting({"enabled": False, "url": "https://collector.invalid/report", "key": "s3cr3tkey" * 4})
    r = A.report_ban_to_org(ATTACKER, 3, "honeypot: x", "honeypot", "scan")
    check(not r["ok"] and "off" in r["reason"] and not A.REPORT_Q["items"], "switched off: nothing queued")
    r = A._spawn_report(ATTACKER, "x", "honeypot", "scan")
    check(not A.REPORT_Q["items"], "switched off: _spawn_report queues nothing")
    # turning it off HOLDS what was queued (not sent, not discarded) ...
    write_reporting({"enabled": True, "url": "https://collector.invalid/report", "key": "s3cr3tkey" * 4})
    TRANSPORT["mode"] = "ok"
    A.report_ban_to_org(ATTACKER, 1, "a", "canary", "ssh")
    st = A.set_reporting_enabled(False)
    check(st["enabled"] is False and st["queue_length"] == 1 and st["dropped_total"] == 0
          and st["held"] is True, "set_reporting_enabled(False) holds the queue")
    out = A._report_q_process()
    check(out["held"] and out["sent"] == 0 and out["left"] == 1 and not SENT,
          "switched off: queued reports are not sent")
    check(not A.report_ban_to_org(ATTACKER2, 1, "b", "honeypot", "scan")["ok"]
          and len(A.REPORT_Q["items"]) == 1, "switched off: new catches stay local")
    mode = stat.S_IMODE(os.stat(A.REPORTING_CONF_FILE).st_mode)
    check(mode == 0o600, "reporting.json written 0600 (%o)" % mode)
    check(not [f for f in os.listdir(os.path.dirname(A.REPORTING_CONF_FILE)) if f.startswith(".")],
          "atomic write leaves no temp file")
    # ... and switching back on resumes it
    st = A.set_reporting_enabled(True)
    check(st["enabled"] and st["queue_length"] == 1 and not st["held"], "switched on: queue kept")
    out = A._report_q_process()
    check(out["sent"] == 1 and not A.REPORT_Q["items"] and SENT[-1]["body"]["ip"] == ATTACKER,
          "switched on: the held report is delivered")
    check(A.load_reporting_conf()["key"] == "s3cr3tkey" * 4, "key preserved across settings writes")
    # held reports still age out (stale evidence is never sent late)
    reset_queue()
    A.report_ban_to_org(ATTACKER, 1, "a", "canary", "ssh")
    A.set_reporting_enabled(False)
    A.REPORT_Q["items"][0]["created"] = time.time() - A.REPORT_QUEUE_MAX_AGE - 5
    out = A._report_q_process()
    check(out["discarded"] == 1 and not A.REPORT_Q["items"]
          and A.reporting_status()["dropped_total"] == 1, "held reports expire after the max age")
    A.set_reporting_enabled(True)
    reset_queue()
    # queue: send ok
    reset_queue()
    TRANSPORT["mode"] = "ok"
    A.report_ban_to_org(ATTACKER, 2, "honeypot: telnet probe on 23/tcp", "honeypot", "scan",
                        [{"sig": "ET SCAN x", "count": 3, "sid": 1}])
    A.report_ban_to_org(ATTACKER, 9, "honeypot: telnet probe on 23/tcp", "honeypot", "scan")
    check(len(A.REPORT_Q["items"]) == 1 and A.REPORT_Q["items"][0]["payload"]["hits"] == 9,
          "same ip+source merged")
    raw = _real_open(A.REPORT_QUEUE_FILE).read()
    check("s3cr3tkey" not in raw, "the key is never written to the queue file")
    check(stat.S_IMODE(os.stat(A.REPORT_QUEUE_FILE).st_mode) == 0o600, "queue file 0600")
    out = A._report_q_process()
    check(out["sent"] == 1 and not A.REPORT_Q["items"], "sent + removed")
    b = SENT[-1]["body"]
    check(b["key"] == "s3cr3tkey" * 4 and b["ip"] == ATTACKER and b["category"] == "scan"
          and b["suricata"][0]["sid"] == 1, "payload + key at send time")
    check(SENT[-1]["headers"]["X-Tuxwall-Version"] == A.TUXWALL_VERSION
          and SENT[-1]["url"] == "https://collector.invalid/report", "headers + URL")
    st = A.reporting_status()
    check(st["sent_24h"] == 1 and st["last_report"] and st["queue_length"] == 0
          and st["key_present"] and "key" not in st, "status after a send (no key)")
    # transient failures retry with backoff, persist across a restart
    reset_queue()
    TRANSPORT["mode"] = "network"
    A.report_ban_to_org(ATTACKER2, 1, "canary: ssh login attempt (SSH 22/tcp)", "canary", "ssh")
    t0 = time.time()
    out = A._report_q_process(now=t0)
    it = A.REPORT_Q["items"][0]
    check(out["retry"] == 1 and it["attempts"] == 1 and it["next_try"] >= t0 + A.REPORT_RETRY_BASE,
          "network error -> retry later")
    check(A._report_q_process(now=t0 + 1)["sent"] == 0 and len(SENT) == 1, "not before next_try")
    A.REPORT_Q.update(loaded=False, items=[], stats={})   # "restart"
    check(A.reporting_status()["queue_length"] == 1, "queue survives a restart")
    TRANSPORT["mode"] = "503"
    A._report_q_process(now=t0 + 4000)
    TRANSPORT["mode"] = "429"
    A._report_q_process(now=t0 + 9000)
    it = A.REPORT_Q["items"][0]
    check(it["attempts"] == 3, "503 / 429 retried")
    check(A._report_backoff(1) >= 30 and A._report_backoff(20) <= A.REPORT_RETRY_MAX * 1.25,
          "backoff doubles, capped")
    check("will retry" in (A.reporting_status()["last_error"] or ""), "outage shown as last error")
    TRANSPORT["mode"] = "ok"
    out = A._report_q_process(now=t0 + 20000)
    check(out["sent"] == 1 and not A.REPORT_Q["items"], "delivered after the outage")
    st = A.reporting_status()
    check(st["last_error"] is None and st["last_error_at"] is None,
          "C3-5: the delivery clears the transient 'will retry' error")
    # refusals are final
    reset_queue()
    TRANSPORT["mode"] = "400"
    A.report_ban_to_org(ATTACKER, 1, "x", "canary", "ssh")
    out = A._report_q_process()
    check(out["refused"] == 1 and not A.REPORT_Q["items"]
          and "not retried" in A.reporting_status()["last_error"], "4xx refusal dropped")
    TRANSPORT["mode"] = "ok"
    A.report_ban_to_org(ATTACKER2, 1, "x", "canary", "ssh")
    A._report_q_process()
    check("not retried" in (A.reporting_status()["last_error"] or ""),
          "a later delivery does not hide a refusal (that report was lost)")
    # caps + age
    reset_queue()
    old_max = A.REPORT_QUEUE_MAX
    A.REPORT_QUEUE_MAX = 5
    try:
        for i in range(8):
            A.report_ban_to_org("45.95.148.%d" % i, 1, "x", "honeypot", "scan")
        check(len(A.REPORT_Q["items"]) == 5 and A.REPORT_Q["items"][0]["payload"]["ip"] == "45.95.148.3",
              "queue capped (oldest dropped)")
        A.REPORT_Q["items"][0]["created"] = time.time() - A.REPORT_QUEUE_MAX_AGE - 5
        A.report_ban_to_org("45.95.149.1", 1, "x", "honeypot", "scan")
        check(all(i["payload"]["ip"] != "45.95.148.3" for i in A.REPORT_Q["items"]), "stale evidence dropped")
    finally:
        A.REPORT_QUEUE_MAX = old_max
    check(A.report_ban_to_org("10.1.2.3", 1, "x", "honeypot")["ok"] is False, "non-global never queued")
    # maintenance pause (key rotation): nothing sent, nothing lost
    reset_queue()
    write_reporting({"url": "https://collector.invalid/report", "key": ROTATE["old"]})
    TRANSPORT["mode"] = "rotate"
    A.report_ban_to_org(ATTACKER, 1, "x", "canary", "ssh")
    A.report_ban_to_org(ATTACKER2, 1, "x", "honeypot", "scan")
    open(A.REPORT_PAUSE_FILE, "w").close()
    out = A._report_q_process()
    check(out["paused"] and out["sent"] == 0 and not SENT and out["left"] == 2,
          "paused: nothing sent, queue kept")
    check(A.reporting_status()["paused"] is True, "status shows the pause")
    old_t = time.time() - A.REPORT_PAUSE_MAX_AGE - 5
    os.utime(A.REPORT_PAUSE_FILE, (old_t, old_t))
    check(not A._report_q_paused(), "a forgotten pause file expires")
    os.unlink(A.REPORT_PAUSE_FILE)
    # key rotated mid-pass: the old key's 403 is retried with the new key
    out = A._report_q_process()
    check(out["refused"] == 0 and out["retry"] >= 1, "403 after a key change -> retry, not drop")
    for it in A.REPORT_Q["items"]:
        it["next_try"] = 0
    out = A._report_q_process()
    check(not A.REPORT_Q["items"] and SENT[-1]["body"]["key"] == ROTATE["new"],
          "every queued report delivered with the new key")
    check(A.reporting_status()["refused_total"] == 0, "nothing lost during the rotation")
    # registration / status: POST with the key in the body, never in a URL
    SENT.clear()
    TRANSPORT["mode"] = "register"
    st = A.community_reporting_status()
    r = A.community_reporting_register()
    check(st["registered"] and st["status"] == "pending" and st["approved"] is False
          and r["ok"] and r["status"] == "pending", "status + register parse the collector reply")
    check(len(SENT) == 2 and all(x["url"] == "https://collector.invalid/register"
                                 and "?" not in x["url"] for x in SENT)
          and SENT[0]["body"] == {"key": ROTATE["new"], "action": "status"}
          and SENT[1]["body"]["key"] == ROTATE["new"],
          "register/status POST the key in the body (no query string)")
    TRANSPORT["mode"] = "ok"
    reset_queue()


def t_community_settings():
    reset_queue()
    write_reporting({"enabled": True, "url": "https://collector.invalid/report", "key": ROTATE["new"]})
    with open(A.COMMUNITY_AUTO_STATE, "w") as f:
        json.dump({"enabled": False, "last_sync": 0, "added_total": 7}, f)
    A.COMMUNITY_REG.update(data=None, fp=None, ts=0.0, ok=False, running=False, error=None)
    SENT.clear()
    TRANSPORT["mode"] = "register"
    v = A.community_settings_view()
    r, a = v["reporting"], v["auto_ban"]
    check(v["ok"] and r["enabled"] is True and a["enabled"] is False and a["added_total"] == 7,
          "settings view: both switches")
    check(set(r["queue"]) >= {"pending", "sent", "failed"} and ROTATE["new"] not in json.dumps(v),
          "settings view: queue counters, never the key")
    check(r["status"] == "unknown" and r["status_checking"] is True, "first view: lookup started in the background")
    for _ in range(100):
        if not A.COMMUNITY_REG["running"]:
            break
        time.sleep(0.02)
    r = A.community_settings_view()["reporting"]
    check(r["registered"] and r["status"] == "pending" and r["approved"] is False
          and r["status_checked_at"], "cached status: pending (from the collector reply)")
    n = len(SENT)
    A.community_settings_view()
    check(len(SENT) == n, "cached: no second lookup within the TTL")
    check(all(x["body"] == {"key": ROTATE["new"], "action": "status"} for x in SENT),
          "status lookups only (nothing registered or reported)")
    # key rotation drops the cached status
    write_reporting({"enabled": True, "url": "https://collector.invalid/report", "key": ROTATE["old"]})
    r = A.community_settings_view()["reporting"]
    check(r["status"] == "unknown", "rotated key: old status forgotten")
    for _ in range(100):
        if not A.COMMUNITY_REG["running"]:
            break
        time.sleep(0.02)
    # no key: no lookup at all
    write_reporting({"enabled": True, "url": "https://collector.invalid/report"})
    n = len(SENT)
    r = A.community_settings_view()["reporting"]
    check(r["key_present"] is False and r["status"] == "unknown" and len(SENT) == n,
          "no key yet: nothing looked up")
    write_reporting({"enabled": True, "url": "https://collector.invalid/report", "key": ROTATE["new"]})
    TRANSPORT["mode"] = "ok"
    # updates: strict input, audited with the user, unchanged values not rewritten
    who = {"username": "tester", "role": "admin"}
    for bad in ({}, {"reporting_enabled": "false"}, {"auto_ban": 1}, {"enabled": True}, None):
        try:
            A.community_settings_update(bad, who, "192.0.2.9")
            check(False, "bad input refused: %r" % (bad,))
        except ValueError:
            check(True, "bad input refused")
    before = os.stat(A.COMMUNITY_AUTO_STATE).st_mtime_ns
    out = A.community_settings_update({"auto_ban": False}, who, "192.0.2.9")
    check(out["ok"] and out["changed"] == [] and os.stat(A.COMMUNITY_AUTO_STATE).st_mtime_ns == before,
          "re-saving the current auto-ban value is a no-op")
    A.report_ban_to_org(ATTACKER, 1, "a", "canary", "ssh")
    out = A.community_settings_update({"reporting_enabled": False}, who, "192.0.2.9")
    check(out["changed"] == ["reporting_enabled"] and out["reporting"]["enabled"] is False
          and out["reporting"]["queue"]["pending"] == 1 and out["reporting"]["queue"]["held"],
          "reporting off via settings: queue held")
    out = A.community_settings_update({"reporting_enabled": True, "auto_ban": True}, who, "192.0.2.9")
    check(out["reporting"]["enabled"] and out["auto_ban"]["enabled"]
          and sorted(out["changed"]) == ["auto_ban", "reporting_enabled"]
          and out["reporting"]["queue"]["pending"] == 1, "both switched on; queue resumes")
    check(A._load_community_auto()["enabled"] is True and A._load_community_auto()["added_total"] == 7,
          "auto-ban state kept its counters")
    lines = [json.loads(x) for x in _real_open(A.COMMUNITY_AUDIT_LOG).read().splitlines()]
    check(len(lines) == 3 and all(x["user"] == "tester" and x["client"] == "192.0.2.9" for x in lines)
          and lines[1]["changes"]["reporting_enabled"] == {"from": True, "to": False},
          "every settings request audited with the dashboard user")
    check(stat.S_IMODE(os.stat(A.COMMUNITY_AUDIT_LOG).st_mode) & 0o007 == 0, "audit log not world-readable")
    check(any("/api/community/settings".startswith(p) for p in A.ADMIN_GET_PREFIXES),
          "GET /api/community/settings is admin-only")
    # deception bans in the last 24 h (cscli raw output)
    raw = ("id,source,ip,reason,action,country,as,events_count,expiration,simulated,alert_id\n"
           "1,cscli,Ip:45.95.147.10,honeypot/tuxwall,ban,,,1,8759h,false,1\n"
           "2,cscli,Ip:185.220.101.77,canary/ssh-connection,ban,,\"AS1, Inc\",1,8759h,false,2\n"
           "3,cscli,Ip:185.220.101.78,custom/local-ban,ban,,,1,89d,false,3\n"
           "4,cscli,Ip:185.220.101.79,canary/vnc-connection,captcha,,,1,4h,false,4\n")
    check(A._deception_bans_count(raw) == (1, 1), "bans 24 h: honeypot + canary bans counted")
    A._DECEPTION_BANS.update(ts=0.0, data=None)
    d = A.deception_bans_24h()
    call = [c for c in RUN.calls if c[:3] == [A.CROWDSEC_BIN, "decisions", "list"]
            or (os.path.basename(c[0]) == "cscli" and "--since" in c)][-1]
    check(d["ok"] and "--since" in call and call[call.index("--since") + 1] == "24h"
          and "add" not in call, "bans 24 h: one read-only cscli list --since 24h")
    reset_queue()
    with open(A.COMMUNITY_AUTO_STATE, "w") as f:
        json.dump({"enabled": False}, f)


def t_community_pages():
    rows = [{"ip": "45.95.150.%d" % i, "severity": "medium"} for i in range(12)]
    calls = []
    state = {"gen": "g1", "flip": False}

    def fake_page(offset):
        calls.append(offset)
        gen = state["gen"]
        if state["flip"] and offset > 0:
            gen, state["flip"] = "g2", False
        page = rows[offset:offset + 5]
        nxt = offset + len(page)
        return {"ok": True, "generated": gen, "bans": list(page),
                "next_offset": nxt if nxt < len(rows) else None}

    real = A._fetch_community_bans_page
    A._fetch_community_bans_page = fake_page
    try:
        first, bans = A._fetch_community_bans_pages()
        check([b["ip"] for b in bans] == [r["ip"] for r in rows] and calls == [0, 5, 10],
              "community list paged with next_offset (3 pages, all rows once)")
        calls.clear()
        state["flip"] = True
        first, bans = A._fetch_community_bans_pages()
        check(len(bans) == 12 and calls == [0, 5, 0, 5, 10],
              "snapshot change mid-paging -> start over once")
        old = {"ok": True, "generated": "x", "bans": rows[:3]}   # pre-paging collector
        A._fetch_community_bans_page = lambda off: dict(old)
        first, bans = A._fetch_community_bans_pages()
        check(len(bans) == 3, "old collector without next_offset: one page")
    finally:
        A._fetch_community_bans_page = real


class doc_global:
    """Treat the documentation ranges as public IPv4 inside the block, so
    the "global WAN IPv4" rule can be exercised with documentation fixtures
    (both api_server and opencanary-render-conf use the ipaddress module)."""
    DOC = [A.ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

    def __enter__(self):
        cls = A.ipaddress.IPv4Address
        self.g, self.p = cls.is_global, cls.is_private
        doc = self.DOC
        g, p = self.g, self.p
        cls.is_global = property(lambda s: any(s in n for n in doc) or g.fget(s))
        cls.is_private = property(lambda s: not any(s in n for n in doc) and p.fget(s))
        return self

    def __exit__(self, *exc):
        A.ipaddress.IPv4Address.is_global = self.g
        A.ipaddress.IPv4Address.is_private = self.p


def ip4_json(*addrs, ifname="wan0"):
    return json.dumps([{"ifindex": 2, "ifname": ifname, "addr_info": [
        {"family": "inet6" if ":" in a else "inet", "local": a, "prefixlen": 24, "scope": "global"}
        for a in addrs]}])


def load_render_conf():
    from importlib.machinery import SourceFileLoader
    path = os.path.join(ROOT_DIR, "scripts", "opencanary", "opencanary-render-conf")
    loader = SourceFileLoader("opencanary_render_conf", path)
    spec_r = importlib.util.spec_from_loader("opencanary_render_conf", loader)
    mod = importlib.util.module_from_spec(spec_r)
    loader.exec_module(mod)
    mod.WAN_IFACE = "wan0"
    return mod


def t_canary_wan():
    """C3-4: the firewall watchdog and opencanary-render-conf pick the same
    WAN IPv4 (several IPv4s on the WAN: static block + DHCP, an alias)."""
    R = load_render_conf()
    fixtures = [
        ("192.168.1.43", "203.0.113.43", "198.51.100.9"),     # private primary + aliases
        ("198.51.100.9", "203.0.113.43"),                      # two public
        ("203.0.113.43", "198.51.100.9", "192.0.2.77"),
        ("100.64.3.4", "10.0.0.2"),                            # CGNAT / private only
        ("2001:db8::5", "203.0.113.43"),                       # v6 entries ignored
        (),
    ]
    with doc_global():
        for fx in fixtures:
            RUN.ip4 = ip4_json(*fx)
            mine, theirs = A._canary_wan_ip("wan0"), R.wan_ip()
            want = next((a for a in fx if ":" not in a and not a.startswith(("192.168.", "10.", "100.64."))), None)
            check(mine == theirs == want, "same WAN IPv4 as render-conf for %s (%r / %r)" % (fx, mine, theirs))
        for bad in ("", "not json", "{}", "[1, 2]", '[{"addr_info": [{"local": 5}]}]'):
            RUN.ip4 = bad
            check(A._canary_wan_ip("wan0") is None, "malformed ip output -> None (%r)" % bad)
        check(A._canary_wan_ip_pick(ip4_json("192.168.1.43", "203.0.113.43")) == "203.0.113.43",
              "pure picker")
    # reconcile with several IPv4s: the default-route source differs from the
    # canary's address; rules stay, no restart
    CAN, SRC = "203.0.113.43", "198.51.100.9"
    ss = ("LISTEN 0 50 %s:6379 0.0.0.0:* users:((\"twistd\",pid=9,fd=5))\n"
          "LISTEN 0 50 %s:22 0.0.0.0:* users:((\"twistd\",pid=9,fd=6))\n" % (CAN, CAN))
    with open(A.CANARY_CONF, "w") as f:
        json.dump({"device.listen_addr": CAN, "ssh.enabled": True, "ssh.port": 22,
                   "redis.enabled": True, "redis.port": 6379}, f)
    current = {("v4", 22, "tcp"), ("v4", 6379, "tcp")}
    real = (A._canary_fw_rules, A._canary_can_manage, A._fw_guard, A._honey_wan_ip)
    A._canary_fw_rules = lambda wan: set(current)
    A._canary_can_manage = lambda: True
    A._fw_guard = A._fw_guard or object()
    A._honey_wan_ip = lambda: SRC
    RUN.ss, RUN.active = ss, "active"
    A.CANARY_FW_STATE.update(pending=None, restart_at=0.0)
    try:
        with doc_global():
            RUN.ip4 = ip4_json("192.168.1.43", CAN, SRC)
            RUN.calls.clear()
            rs = [A._canary_fw_reconcile() for _ in range(3)]
        check(all(r["ok"] and not r["removed"] and not r["pending"] and not r["added"] for r in rs),
              "multi-address WAN: canary rules kept (%r)" % (rs[-1],))
        check(not RUN.ufw() and not any(c[:2] == ["systemctl", "restart"] for c in RUN.calls),
              "multi-address WAN: no ufw change, no canary restart")
        check(rs[-1]["open_ports"] == [22, 6379], "open ports reported")
    finally:
        A._canary_fw_rules, A._canary_can_manage, A._fw_guard, A._honey_wan_ip = real
        RUN.ip4, RUN.ss = "[]", ""


def t_canary_fw():
    plan = A._canary_fw_plan
    conf = {(22, "tcp"), (5900, "tcp"), (1433, "tcp"), (6379, "tcp")}
    rules = {("v4", 22, "tcp"), ("v6", 22, "tcp"), ("v4", 161, "udp"), ("v6", 161, "udp"),
             ("v4", 6379, "tcp"), ("v6", 6379, "tcp")}
    add, rem = plan(True, {22, 5900, 1433, 6379}, conf, rules)
    check(add == [("v4", 1433, "tcp"), ("v4", 5900, "tcp")], "plan: open missing IPv4 rules")
    check(sorted(rem) == sorted([("v6", 22, "tcp"), ("v4", 161, "udp"), ("v6", 161, "udp"),
                                 ("v6", 6379, "tcp")]), "plan: IPv6 + SNMP leftovers removed")
    add, rem = plan(False, set(), conf, rules)
    check(not add and len(rem) == len(rules), "plan: canary down -> everything closes")
    add, rem = plan(True, {22}, {(22, "tcp")}, {("v4", 22, "tcp")})
    check(not add and not rem, "plan: steady state")
    add, rem = plan(True, {22, 8080}, {(22, "tcp")}, set())
    check(add == [("v4", 22, "tcp")], "plan: only configured ports, never a real service")
    ss = ("LISTEN 0 50 %s:22 0.0.0.0:* users:((\"twistd\",pid=9,fd=5))\n"
          "LISTEN 0 50 %s:5900 0.0.0.0:* users:((\"twistd\",pid=9,fd=6))\n"
          "LISTEN 0 128 192.168.1.1:22 0.0.0.0:* users:((\"sshd\",pid=3,fd=3))\n"
          "LISTEN 0 128 %s:8443 0.0.0.0:* users:((\"nginx\",pid=4,fd=3))\n" % (WAN4, WAN4, WAN4))
    check(A._canary_bound_tcp(WAN4, ss) == {22, 5900}, "twistd ports on the WAN IPv4 only")
    # reconcile with stubs: grace before closing, opens at once
    with open(A.CANARY_CONF, "w") as f:
        json.dump({"device.listen_addr": WAN4, "ssh.enabled": True, "ssh.port": 22,
                   "vnc.enabled": True, "vnc.port": 5900, "snmp.enabled": False}, f)
    check(A._canary_conf_ports() == {(22, "tcp"), (5900, "tcp")}, "config ports (SNMP off)")
    current = {("v4", 22, "tcp"), ("v6", 22, "tcp")}
    real_rules, real_manage, real_guard = A._canary_fw_rules, A._canary_can_manage, A._fw_guard
    A._canary_fw_rules = lambda wan: set(current)
    A._canary_can_manage = lambda: True
    A._fw_guard = A._fw_guard or object()
    RUN.ss, RUN.active = ss, "active"
    RUN.ip4 = ip4_json(WAN4)
    A.CANARY_FW_STATE.update(pending=None, restart_at=time.time())
    dg = doc_global().__enter__()
    try:
        RUN.calls.clear()
        r1 = A._canary_fw_reconcile()
        u1 = RUN.ufw()
        check(r1["ok"] and r1["added"] == [("v4", 5900, "tcp")] and not r1["removed"]
              and r1["pending"] == [("v6", 22, "tcp")], "pass 1: open 5900, v6 22 pending")
        check(u1 == [["ufw", "allow", "in", "on", "wan0", "to", "0.0.0.0/0", "port", "5900",
                      "proto", "tcp", "comment", "tuxwall-canary"]], "IPv4-only add command")
        current.add(("v4", 5900, "tcp"))
        RUN.calls.clear()
        r2 = A._canary_fw_reconcile()
        check(r2["removed"] == [("v6", 22, "tcp")] and RUN.ufw() == [
            ["ufw", "delete", "allow", "in", "on", "wan0", "to", "::/0", "port", "22", "proto", "tcp"]],
            "pass 2: IPv6 leftover deleted (family-specific spec)")
        current.discard(("v6", 22, "tcp"))
        RUN.active = "inactive"
        RUN.calls.clear()
        r3 = A._canary_fw_reconcile()
        check(not r3["removed"] and len(r3["pending"]) == 2 and not RUN.ufw(),
              "canary down: one grace pass (a restart never flaps the firewall)")
        RUN.active = "active"
        r4 = A._canary_fw_reconcile()
        check(not r4["removed"] and not r4["pending"], "back up within the grace: nothing closed")
        RUN.active = "inactive"
        A._canary_fw_reconcile()
        RUN.calls.clear()
        r5 = A._canary_fw_reconcile()
        check(sorted(r5["removed"]) == [("v4", 22, "tcp"), ("v4", 5900, "tcp")],
              "still down on the next pass: rules closed")
        RUN.calls.clear()
        current.clear()
        RUN.active = "active"
        RUN.ss = ""
        r6 = A._canary_fw_reconcile()
        check(not r6["added"] and not RUN.ufw(), "nothing bound: nothing opened (bind-first)")
        RUN.ss = ss
        r7 = A._canary_fw_reconcile()
        check(sorted(r7["added"]) == [("v4", 22, "tcp"), ("v4", 5900, "tcp")], "reopened when back")
    finally:
        dg.__exit__()
        A._canary_fw_rules, A._canary_can_manage, A._fw_guard = real_rules, real_manage, real_guard
        RUN.active = "active"
        RUN.ip4 = "[]"


def t_canary_log():
    lines = []
    for i in range(5000):
        e = {"src_host": "45.95.%d.%d" % (i // 250, i % 250), "logtype": 4002,
             "local_time_adjusted": time.strftime("%Y-%m-%d %H:%M:%S"),
             "dst_port": 22, "logdata": {"USERNAME": "root", "PASSWORD": "x" * (i % 40)}}
        lines.append(json.dumps(e))
    with open(A.CANARY_LOG, "w") as f:
        f.write("\n".join(lines) + "\n")
    got = A._canary_tail_lines(A.CANARY_LOG, 64 * 1024, 300)
    check(len(got) == 300 and got[-1] == lines[-1] and all(g in lines for g in got),
          "tail: last complete lines only")
    small = A._canary_tail_lines(A.CANARY_LOG, 2000, 300)
    check(small and all(g in lines for g in small), "tail: partial first line dropped")
    A._canary_ban_snapshot = lambda: (3, ATTACKER)
    A._CANARY_VIEW.update(ts=0.0, data=None)
    v1 = A.build_canary()
    check(v1["ok"] and v1["events_24h"] == 300 and len(v1["events"]) == 25, "build_canary from the tail")
    with open(A.CANARY_LOG, "a") as f:
        f.write(json.dumps(dict(json.loads(lines[0]), src_host="45.95.200.1")) + "\n")
    check(A.build_canary() is v1, "cached within the TTL")
    A._CANARY_VIEW["ts"] = 0.0
    v2 = A.build_canary()
    check(v2 is not v1 and v2["sources_24h"] == 300, "refreshed after the TTL (tail of 300)")


def t_load():
    """Sandboxed tarpit on 127.0.0.2 (never the WAN listeners): one client
    opens 60 connections; the per-IP cap holds and fds stay bounded."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.2", 0))
    except OSError as exc:
        print("SKIP t_load: cannot bind 127.0.0.2 (%s)" % exc)
        return
    srv.listen(64)
    srv.settimeout(0.5)
    port = srv.getsockname()[1]
    reset_honey()
    A._HONEY_CONF_CACHE.update(ts=time.time() + 3600,
                               conf={"enabled": True, "ports": [port], "auto_ban": True,
                                     "ban_threshold": 1, "max_hold": 30})
    catches = []
    real = (A._honey_is_lan, A._honey_is_self, A._honey_catch, A.HONEY_TICK)
    A._honey_is_lan = lambda ip: False          # loopback stands in for an internet source
    A._honey_is_self = lambda ip: False
    A._honey_catch = lambda ip, p, auto: catches.append(ip)   # no ban, no report
    A.HONEY_TICK = 0.2
    fd_dir = "/proc/self/fd"
    fds0 = len(os.listdir(fd_dir)) if os.path.isdir(fd_dir) else None
    t = threading.Thread(target=A._honey_listener, args=(srv, port), daemon=True)
    t.start()
    clients = []
    try:
        for _ in range(60):
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.settimeout(2)
            c.connect(("127.0.0.2", port))
            clients.append(c)
        deadline = time.time() + 5
        while time.time() < deadline and A.HONEY_STATE["stats"]["total"] < 60:
            time.sleep(0.05)
        time.sleep(0.3)
        with A.HONEY_APPLY_LOCK:
            active = len(A.HONEY_STATE["active"])
            per_ip = dict(A.HONEY_STATE["per_ip"])
            st = dict(A.HONEY_STATE["stats"])
        check(st["total"] == 60, "load: 60 connections accepted (%d)" % st["total"])
        check(active == A.HONEY_MAX_PER_IP and per_ip.get("127.0.0.1") == A.HONEY_MAX_PER_IP,
              "load: one client held to the per-IP cap (%d)" % active)
        check(st["dropped"] == 60 - A.HONEY_MAX_PER_IP, "load: the rest dropped (%d)" % st["dropped"])
        check(catches == ["127.0.0.1"], "load: one catch per source")
        tarpits = [x for x in threading.enumerate() if x.name == "honey-tarpit"]
        check(len(tarpits) == A.HONEY_MAX_PER_IP, "load: tarpit threads bounded (%d)" % len(tarpits))
        if fds0 is not None:
            fds = len(os.listdir(fd_dir))
            # 60 client sockets are ours; the server side may only add its 8 held fds
            check(fds - fds0 <= 60 + A.HONEY_MAX_PER_IP + 4,
                  "load: server-side fds bounded (+%d)" % (fds - fds0 - 60))
        held = [c for c in clients if _peer_alive(c)]
        check(len(held) <= A.HONEY_MAX_PER_IP + 1, "load: dropped clients see a close (%d held)" % len(held))
    finally:
        for c in clients:
            c.close()
        with A.HONEY_APPLY_LOCK:
            A.HONEY_STATE["gen"] += 1
        t.join(timeout=5)
        deadline = time.time() + 5
        while time.time() < deadline and A.HONEY_STATE["active"]:
            time.sleep(0.05)
        check(not A.HONEY_STATE["active"] and not A.HONEY_STATE["per_ip"],
              "load: every slot released after stop")
        check(not t.is_alive(), "load: listener exited on the generation bump")
        A._honey_is_lan, A._honey_is_self, A._honey_catch, A.HONEY_TICK = real
        reset_honey()


def _peer_alive(c):
    """False when the server closed our connection (EOF or reset)."""
    c.setblocking(False)
    try:
        data = c.recv(64)
        return bool(data)           # tarpit dribbles NUL bytes
    except BlockingIOError:
        return True
    except OSError:
        return False
    finally:
        c.setblocking(True)


def main():
    try:
        for t in (t_ttl_map, t_slots, t_threshold, t_listener, t_lan_guard, t_guard_paths,
                  t_guard_recheck, t_categories, t_reporting, t_community_settings, t_community_pages,
                  t_canary_fw, t_canary_wan, t_canary_log, t_load):
            t()
        bad = [c for c in RUN.calls if os.path.basename(c[0]) == "cscli"
               and any(x in c for x in ("192.168.1.50", WAN4, WAN6, CF, NTP))]
        check(not bad, "no cscli call ever named a LAN/own/protected address")
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("deception_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
