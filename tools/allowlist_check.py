#!/usr/bin/env python3
"""CrowdSec allowlist management (www/includes/api_server.py), sandboxed:

  python3 tools/allowlist_check.py

subprocess.run is a fake CrowdSec (cscli allowlists list/add/remove/create
and decisions delete answered from in-memory lists, fixture values are
documentation addresses only); the decision scan and the router's own
addresses are stubbed. Nothing touches the host.

Covers: value / comment / expiry / list-name validation (IPv4-mapped and
NAT64 notation, host bits dropped, days sent to cscli as hours), the
0.0.0.0/0 and ::/0 refusal, broad ranges needing confirm_broad, duplicates
and unknown lists, the argv cscli gets (no shell, --flag=value), lifting
covered bans with `decisions delete --range X --contained` and reporting
broader range bans it leaves alone, the lock-out detection on removal
(browser address, LAN/VLAN/VPN networks, router addresses, recent WAN,
infrastructure, protected ranges) and confirm_lockout, list creation, the
cached network set (first load synchronous, stale refreshed in the
background, invalidated after a change, expired entries ignored), the
deception guard and manual bans honouring it, and queued reports for a
newly allowlisted IP being dropped.
"""
import importlib.util
import ipaddress
import json
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "www", "includes", "api_server.py")
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("api_server_allowlist", TARGET)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


class Proc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


ZERO = "0001-01-01T00:00:00.000Z"


def item(value, desc="", exp=ZERO):
    return {"value": value, "description": desc, "expiration": exp,
            "created_at": "2026-11-01T10:00:00.000Z"}


class FakeCscli:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.lists = {
            "home": {"name": "home", "description": "home WAN + delegated prefix",
                     "created_at": "2026-09-26T20:51:39.934Z", "updated_at": "2026-11-19T23:26:36.275Z",
                     "items": [item("203.0.113.7"), item("2001:db8:aa::/64", "prefix"),
                               item("192.168.1.0/24", "LAN")]},
            "cloudflare": {"name": "cloudflare", "description": "edge",
                           "created_at": "2026-09-01T05:16:11.180Z", "updated_at": "2026-09-01T05:16:11.222Z",
                           "items": [item("198.51.100.0/24", "edge range")]},
        }
        self.deleted = []

    def __call__(self, cmd, *a, **kw):
        cmd = list(cmd)
        self.calls.append(cmd)
        assert not kw.get("shell"), "shell=True used"
        assert kw.get("timeout"), "cscli without a timeout"
        if os.path.basename(cmd[0]) != "cscli":
            raise AssertionError("unexpected command %r" % cmd)
        args = cmd[1:]
        if self.fail and args[:2] == self.fail:
            return Proc(1, "", 'level=fatal msg="boom"')
        if args == ["allowlists", "list", "-o", "json"]:
            return Proc(0, json.dumps(list(self.lists.values())))
        if args[:2] == ["allowlists", "add"]:
            name, value = args[2], args[3]
            flags = dict(f[2:].split("=", 1) for f in args[4:])
            exp = ZERO
            if "expiration" in flags:
                exp = "2026-12-01T00:00:00.000Z"
            self.lists[name]["items"].append(item(value, flags.get("comment", ""), exp))
            return Proc(0, "", 'level=info msg="added 1 values to allowlist %s"' % name)
        if args[:2] == ["allowlists", "remove"]:
            name, value = args[2], args[3]
            self.lists[name]["items"] = [i for i in self.lists[name]["items"] if i["value"] != value]
            return Proc(0, "", 'level=info msg="removed 1 values from allowlist %s"' % name)
        if args[:2] == ["allowlists", "create"]:
            desc = args[3].split("=", 1)[1]
            self.lists[args[2]] = {"name": args[2], "description": desc, "items": [],
                                   "created_at": "2026-11-22T00:00:00Z", "updated_at": "2026-11-22T00:00:00Z"}
            return Proc(0, "", "")
        if args[:2] == ["decisions", "delete"]:
            self.deleted.append(args[2:])
            return Proc(0, "", 'level=info msg="2 decision(s) deleted"')
        raise AssertionError("unexpected cscli call %r" % args)

    def writes(self):
        return [c[1:] for c in self.calls if c[1:3] != ["allowlists", "list"]]


FAKE = FakeCscli()
A.CROWDSEC_BIN = "/fake/cscli"
A.subprocess.run = FAKE
FW_SYNCS = []
A._crowdsec_fw_sync_async = lambda delay=0: FW_SYNCS.append(delay)
A._invalidate_crowdsec_decisions_cache = lambda: None


class FakeCsfw:
    bans = {"ip": {}, "range": {}}

    @staticmethod
    def db_path():
        return __file__          # exists; never opened by the stub

    @classmethod
    def active_bans(cls, path):
        return cls.bans


A._csfw = FakeCsfw
# the router's own addresses for the lock-out check (documentation values)
LIVE = {"lan": [ipaddress.ip_network(n) for n in ("192.168.1.0/24", "2001:db8:aa::/64", "127.0.0.0/8")],
        "own": {"192.168.1.1", "2001:db8:aa::1", "203.0.113.7", "127.0.0.1"},
        "infra": frozenset({"192.0.2.53", "203.0.113.7"}), "wan": ["203.0.113.7"]}
A._honey_lan_nets = lambda: LIVE["lan"]
A._recent_wan_ips = lambda: list(LIVE["wan"])
A._honey_wan_ip = lambda: LIVE["wan"][0]
A._honey_wan6 = lambda: None
A._deception_never_ban_ips = lambda: LIVE["infra"]
_real_lockout_live = A._allowlist_lockout_live


def lockout_live(net, client_ip):
    return A._allowlist_lockout_reasons(net, client_ip, LIVE["lan"], LIVE["own"], LIVE["infra"],
                                        LIVE["wan"], A.PROTECTED_NETS)


A._allowlist_lockout_live = lockout_live
ADMIN = {"username": "boss", "role": "admin"}


def t_validation():
    v = A._allowlist_clean_value
    for raw, want in (("192.0.2.9", "192.0.2.9/32"), (" 192.0.2.77/24 ", "192.0.2.0/24"),
                      ("2001:db8::1", "2001:db8::1/128"), ("2001:db8:1::5/48", "2001:db8:1::/48"),
                      ("::ffff:192.0.2.1", "192.0.2.1/32"), ("64:ff9b::c000:201", "192.0.2.1/32")):
        net, err = v(raw)
        check(err is None and str(net) == want, "value %r -> %s (got %s, %s)" % (raw, want, net, err))
    for raw in ("", "abc", "192.0.2.1; rm -rf /", "192.0.2.1 192.0.2.2", "192.0.2.256", "192.0.2.0/33",
                "::ffff:0:0/100", "64:ff9b::/120", "-e", "1" * 65, None, 5, ["192.0.2.1"]):
        check(v(raw)[1] is not None, "value %r refused" % (raw,))
    check(A._allowlist_value_str(ipaddress.ip_network("192.0.2.9/32")) == "192.0.2.9", "single v4 plain")
    check(A._allowlist_value_str(ipaddress.ip_network("2001:db8::/32")) == "2001:db8::/32", "range as CIDR")

    e = A._allowlist_clean_expiry
    for raw, want in (("never", None), ("", None), (None, None), ("NEVER", None), ("1h", "1h"),
                      ("24h", "24h"), ("7d", "168h"), ("30d", "720h"), ("90m", "90m"), ("365d", "8760h")):
        check(e(raw) == (want, None), "expiry %r -> %r (got %r)" % (raw, want, e(raw)))
    for raw in ("366d", "1w", "0h", "-1h", "1.5h", "1h30m", "10", "h", 7, "9999999h"):
        check(e(raw)[1] is not None, "expiry %r refused" % (raw,))

    c = A._allowlist_clean_comment
    check(c("x" * 200) == ("x" * 200, None) and c(None) == ("", None) and c("  hi ") == ("hi", None),
          "comment up to 200 printable chars, trimmed")
    for raw in ("x" * 201, "a\nb", "tab\there", "nul\x00", 5):
        check(c(raw)[1] is not None, "comment %r refused" % (raw[:12] if isinstance(raw, str) else raw,))

    for name in ("home", "a", "x_y-z", "tuxwall-internal", "a" * 64):
        check(A.ALLOWLIST_NAME_RE.match(name), "list name %r valid" % name)
    for name in ("Home", "-x", "_x", "a" * 65, "a b", "../x", "x/y", ""):
        check(not A.ALLOWLIST_NAME_RE.match(name), "list name %r invalid" % name)


def t_add():
    FAKE.calls.clear()
    for bad in ("0.0.0.0/0", "::/0", "1.2.3.4/0"):
        st, d = A.allowlist_add({"list": "home", "value": bad, "confirm_broad": True}, ADMIN)
        check(st == 400 and "whole internet" in d["error"], "%s always refused (%s)" % (bad, st))
    st, d = A.allowlist_add({"list": "home", "value": "10.0.0.0/8"}, ADMIN)
    check(st == 409 and d.get("needs_confirm") == "broad" and "broad" in d["warning"],
          "v4 broader than /16 needs confirm_broad")
    st, d = A.allowlist_add({"list": "home", "value": "2001:db8::/24"}, ADMIN)
    check(st == 409 and d.get("needs_confirm") == "broad", "v6 broader than /32 needs confirm_broad")
    st, d = A.allowlist_add({"list": "home", "value": "10.0.0.0/8", "confirm_broad": "true"}, ADMIN)
    check(st == 409, "confirm_broad must be a real boolean")
    check(not FAKE.writes(), "nothing written for refused adds")
    st, d = A.allowlist_add({"list": "nope", "value": "192.0.2.5"}, ADMIN)
    check(st == 404, "unknown list -> 404")
    st, d = A.allowlist_add({"list": "../etc", "value": "192.0.2.5"}, ADMIN)
    check(st == 400, "bad list name -> 400")
    st, d = A.allowlist_add({"list": "home", "value": "203.0.113.7"}, ADMIN)
    check(st == 409 and "already" in d["error"], "duplicate -> 409")
    st, d = A.allowlist_add({"list": "home", "value": "192.0.2.5", "comment": "a\x07"}, ADMIN)
    check(st == 400, "control character in comment -> 400")

    FakeCsfw.bans = {"ip": {"192.0.2.5": (0, "cscli"), "192.0.2.200": (0, "cscli")},
                     "range": {"192.0.2.0/24": (0, "cscli"), "198.51.100.0/24": (0, "x")}}
    FAKE.calls.clear()
    FW_SYNCS.clear()
    st, d = A.allowlist_add({"list": "home", "value": "192.0.2.5", "comment": "tuxwall whitelist test",
                             "expiration": "7d"}, ADMIN)
    check(st == 200 and d["ok"] and d["value"] == "192.0.2.5", "add -> 200 (%s %s)" % (st, d.get("error")))
    w = FAKE.writes()
    check(["allowlists", "add", "home", "192.0.2.5", "--expiration=168h",
           "--comment=tuxwall whitelist test"] in w, "cscli argv: one value, --flag=value (%r)" % w)
    check(["decisions", "delete", "--range", "192.0.2.5/32", "--contained"] in w,
          "covered bans lifted with --range X --contained")
    check(d["lifted"] == ["192.0.2.5"] and d["lifted_count"] == 1, "lifted reported (%r)" % d.get("lifted"))
    check(d["still_banned_by_ranges"] == ["192.0.2.0/24"], "broader range ban reported, not lifted")
    check("192.0.2.0/24" in d["message"], "message names the broader range ban")
    check(d.get("decisions_deleted") == 2 and FW_SYNCS == [0], "range table re-synced after a lift")
    check(any(e["value"] == "192.0.2.5" for e in d["entries"]), "entries returned")
    check(A._allowlist_match("192.0.2.5") == "home", "cache invalidated right after the add")

    FAKE.calls.clear()
    st, d = A.allowlist_add({"list": "home", "value": "192.0.2.192/26"}, ADMIN)
    check(st == 200 and d["lifted"] == ["192.0.2.200"], "range entry lifts the IP bans inside it")
    check(not any("--expiration" in " ".join(c) or "--comment" in " ".join(c) for c in FAKE.writes()),
          "never / empty comment -> no flags")
    st, d = A.allowlist_add({"list": "cloudflare", "value": "10.0.0.0/8", "confirm_broad": True}, ADMIN)
    check(st == 200 and d["value"] == "10.0.0.0/8", "confirmed broad range added")

    FAKE.fail = ["allowlists", "add"]
    st, d = A.allowlist_add({"list": "home", "value": "192.0.2.99"}, ADMIN)
    check(st == 502 and "boom" in d["error"], "cscli failure surfaced")
    FAKE.fail = None


def t_lockout():
    r = A._allowlist_lockout_reasons
    lan = LIVE["lan"]
    n = ipaddress.ip_network
    check(r(n("192.0.2.0/24"), "192.168.1.50", lan, LIVE["own"], LIVE["infra"], LIVE["wan"],
            A.PROTECTED_NETS) == ["infrastructure this router depends on (DNS/NTP/gateway/resolver/APT): "
                                  "192.0.2.53"], "infrastructure covered")
    got = r(n("192.168.1.0/24"), "192.168.1.50", lan, LIVE["own"], (), (), ())
    check(any("your own address 192.168.1.50" in x for x in got)
          and any("LAN/VLAN/VPN network 192.168.1.0/24" in x for x in got)
          and any("own address: 192.168.1.1" in x for x in got), "LAN entry: browser + LAN + router (%r)" % got)
    got = r(n("2001:db8:aa::/48"), None, lan, LIVE["own"], (), (), ())
    check(any("2001:db8:aa::/64" in x for x in got), "delegated v6 prefix overlap detected")
    got = r(n("203.0.113.7/32"), None, lan, LIVE["own"], LIVE["infra"], LIVE["wan"], ())
    check(len(got) == 1 and "own address: 203.0.113.7" in got[0], "WAN address reported once (%r)" % got)
    check(r(n("198.18.0.0/15"), "192.168.1.50", lan, LIVE["own"], LIVE["infra"], LIVE["wan"],
            A.PROTECTED_NETS) == [], "unrelated range: no warning")
    check(r(n("127.0.0.0/8"), "127.0.0.1", lan, LIVE["own"], (), (), ()) == [], "loopback ignored")
    check(r(n("104.16.0.0/12"), None, (), (), (), (), A.PROTECTED_NETS)[0].startswith("protected"),
          "protected (Cloudflare) overlap detected")
    check(r(n("192.0.2.9/32"), "::ffff:192.0.2.9", (), (), (), (), ()) and True,
          "IPv4-mapped browser address normalised")

    FAKE.calls.clear()
    st, d = A.allowlist_remove({"list": "home", "value": "192.168.1.0/24"}, ADMIN, "192.168.1.50")
    check(st == 409 and d["needs_confirm"] == "lockout" and "192.168.1.50" in d["warning"],
          "LAN entry removal needs confirm_lockout")
    check(not FAKE.writes(), "nothing removed without the confirmation")
    st, d = A.allowlist_remove({"list": "home", "value": "192.168.1.0/24", "confirm_lockout": 1},
                               ADMIN, "192.168.1.50")
    check(st == 409, "confirm_lockout must be a real boolean")
    st, d = A.allowlist_remove({"list": "home", "value": "192.0.2.77"}, ADMIN, "192.168.1.50")
    check(st == 404, "entry not in list -> 404")
    before = json.dumps(FAKE.lists["home"]["items"], sort_keys=True)
    st, d = A.allowlist_remove({"list": "home", "value": "192.0.2.5"}, ADMIN, "192.168.1.50")
    check(st == 200 and ["allowlists", "remove", "home", "192.0.2.5"] in FAKE.writes(), "remove -> 200")
    check(A._allowlist_match("192.0.2.5") is None, "cache invalidated right after the remove")
    check(json.dumps(FAKE.lists["home"]["items"], sort_keys=True) != before, "list changed")
    st, d = A.allowlist_remove({"list": "home", "value": "2001:db8:aa::/64", "confirm_lockout": True},
                               ADMIN, "192.168.1.50")
    check(st == 200, "confirmed lock-out removal goes through")


def t_create_and_list():
    st, d = A.allowlist_create({"name": "Bad Name"}, ADMIN)
    check(st == 400, "create: bad name -> 400")
    st, d = A.allowlist_create({"name": "home"}, ADMIN)
    check(st == 409, "create: existing -> 409")
    st, d = A.allowlist_create({"name": "partners", "description": "partner offices"}, ADMIN)
    check(st == 200 and "partners" in FAKE.lists, "create -> 200")
    check(["allowlists", "create", "partners", "--description=partner offices"] in FAKE.writes(),
          "create argv")
    st, d = A.build_allowlists()
    names = [x["name"] for x in d["lists"]]
    check(st == 200 and names == sorted(names) and "partners" in names, "list: all lists, sorted")
    home = next(x for x in d["lists"] if x["name"] == "home")
    check(home["count"] == len(home["entries"]) and home["managed_by"] is None, "count + managed_by")
    e = home["entries"][0]
    check(e["expiration"] is None and e["expires_ts"] is None and e["created_ts"], "never-expiring entry")
    FAKE.fail = ["allowlists", "list"]
    st, d = A.build_allowlists()
    check(st == 502 and not d["ok"], "cscli down -> 502")
    FAKE.fail = None


def t_cache_and_guard():
    nets = A._allowlist_nets_from(A._allowlist_parse([
        {"name": "testlist", "items": [item("203.0.113.0/24"), item("2001:db8:1::/48"),
                                       item("198.51.100.9", exp="2020-01-01T00:00:00Z")]}]))
    check(A._allowlist_match("203.0.113.9", nets) == "testlist", "v4 range matched")
    check(A._allowlist_match("::ffff:203.0.113.9", nets) == "testlist", "IPv4-mapped matched")
    check(A._allowlist_match("2001:db8:1:2::3", nets) == "testlist", "v6 range matched")
    check(A._allowlist_match("198.51.100.9", nets) is None, "expired entry ignored")
    check(A._allowlist_match("bogus", nets) is None, "invalid ip -> None")

    with A._ALLOWLIST_CACHE_LOCK:
        A._ALLOWLIST_CACHE.update(ts=time.time(), nets=nets, refreshing=False, ok=True)
    FAKE.calls.clear()
    check(A._deception_guard("203.0.113.9") == "CrowdSec allowlist testlist", "guard: allowlist reason")
    check(A._deception_guard("2001:db8:1::77") == "CrowdSec allowlist testlist", "guard: v6 allowlist")
    check(A._deception_guard("198.51.100.9") == "non-global address", "guard: expired entry not used")
    check(not FAKE.calls, "fresh cache: no cscli call on the hot path")
    ok, err = A._deception_cscli_ban("203.0.113.9", "8760h", "test")
    check(not ok and "allowlist testlist" in err and not FAKE.calls, "deception ban refused, no cscli")
    r = A._spawn_report("203.0.113.9", "x", "honeypot", "scan")
    check(isinstance(r, dict) and not r.get("ok") and "allowlist" in r.get("reason", ""),
          "report refused for an allowlisted IP")

    # stale: the old set answers at once, one background refresh starts
    started = []
    real_thread = A.threading.Thread

    class T(real_thread):
        def start(self):
            started.append(self.name)
            super().start()
    A.threading.Thread = T
    try:
        with A._ALLOWLIST_CACHE_LOCK:
            A._ALLOWLIST_CACHE.update(ts=time.time() - A.ALLOWLIST_CACHE_TTL - 1, refreshing=False)
        t0 = time.time()
        check(A._allowlist_match("203.0.113.9") == "testlist", "stale set still answers")
        check(time.time() - t0 < 0.5 and started == ["allowlist"], "stale -> one background refresh")
        A._allowlist_match("203.0.113.9")
        check(started == ["allowlist"], "no second refresh while one runs")
    finally:
        A.threading.Thread = real_thread
    for th in threading.enumerate():
        if th.name == "allowlist":
            th.join(5)
    check(A._allowlist_match("203.0.113.9") is None and A._allowlist_match("192.168.1.9") == "home",
          "background refresh replaced the set with the live lists")

    # first use loads synchronously; a cscli failure keeps the old set
    with A._ALLOWLIST_CACHE_LOCK:
        A._ALLOWLIST_CACHE.update(ts=0.0, nets=None, refreshing=False, ok=False)
    check(A._allowlist_match("192.168.1.9") == "home", "first call loads synchronously")
    FAKE.fail = ["allowlists", "list"]
    A._allowlist_refresh()
    check(A._allowlist_match("192.168.1.9") == "home", "failed refresh keeps the last good set")
    FAKE.fail = None

    # manual ban: clear message instead of a cscli call
    FAKE.calls.clear()
    real = A._allowlist_match
    A._allowlist_match = lambda ip, nets=None, now=None: "home" if ip == "45.95.147.99" else None
    try:
        res = A.ban_crowdsec_ip("45.95.147.99", "24h")
        check(not res["ok"] and res.get("allowlisted") == "home" and "allowlisted in home" in res["error"],
              "manual ban of an allowlisted IP: clear error")
        check(not FAKE.calls, "no cscli decisions add for it")
        # queued report for an IP allowlisted afterwards is dropped
        saved = []
        A._report_q_save = lambda: saved.append(1)
        with A.REPORT_Q_LOCK:
            A.REPORT_Q["items"] = [{"id": "a", "payload": {"ip": "45.95.147.99"}},
                                   {"id": "b", "payload": {"ip": "45.95.147.100"}}]
            A.REPORT_Q["stats"] = {}
        check(A._report_q_drop_allowlisted() == 1 and [i["id"] for i in A.REPORT_Q["items"]] == ["b"]
              and A.REPORT_Q["stats"]["dropped_total"] == 1 and saved, "queued report dropped")
    finally:
        A._allowlist_match = real


def t_live_inputs():
    # the live gatherer combines the helpers (ip -j addr answered here)
    real_run = A.subprocess.run

    def run(cmd, *a, **kw):
        if cmd[:2] == ["ip", "-j"]:
            return Proc(0, json.dumps([{"addr_info": [{"local": "192.168.1.1"}, {"local": "198.51.100.1"}]}]))
        return real_run(cmd, *a, **kw)
    A.subprocess.run = run
    try:
        got = _real_lockout_live(ipaddress.ip_network("198.51.100.0/24"), "192.168.1.50")
        check(any("198.51.100.1" in x for x in got), "live gatherer reads the router's addresses (%r)" % got)
    finally:
        A.subprocess.run = real_run


for t in (t_validation, t_add, t_lockout, t_create_and_list, t_cache_and_guard, t_live_inputs):
    try:
        t()
    except Exception as exc:
        import traceback
        traceback.print_exc()
        check(False, "%s raised %r" % (t.__name__, exc))

print("allowlist_check: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
