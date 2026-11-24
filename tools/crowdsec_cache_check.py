#!/usr/bin/env python3
"""CrowdSec panel caches, /api/crowdsec/summary and client aborts
(www/includes/api_server.py), over the loopback harness (tools/api_harness.py,
fail-closed sandbox: no subprocess, no writes outside a temp dir, no network):

  python3 tools/crowdsec_cache_check.py

The cscli-backed builders are stubbed with in-memory decisions
(documentation addresses only).

Covers: _SwrCache (fresh/stale/cold, one background refresh at a time,
concurrent cold callers share one build, a failed refresh keeps the last
value, mark_stale during a refresh reruns it, drop discards it); the panel
and ban-state payloads keeping separate timestamps (they once shared one, so
building either made the other's old value look fresh); automatic
(soft) invalidation keeps serving while an interactive one empties the
cache; GET /api/crowdsec/summary shape, size, order and auth (viewer, agent
token); /api/crowdsec unchanged; a client that disconnects mid-response
logs one short line per path (rate-limited) and no traceback, while a real
handler exception still reaches handle_error; the Home Assistant
integration reading either payload shape.
"""
import importlib.util
import json
import os
import socket
import struct
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.dont_write_bytecode = True
import api_harness  # noqa: E402

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


def wait_for(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.01)
    return pred()


H = api_harness.Harness(name="api_server_crowdsec_cache")
A = H.mod
LOG = []
A.print = lambda *a, **k: LOG.append(" ".join(str(x) for x in a))


def decisions(n, base=0):
    return [{"ip": "203.0.113.%d" % ((base + i) % 250 + 1) if i % 2 else "2001:db8::%x" % (base + i + 1),
             "scope": "Ip", "scenario": "tuxwall/honeypot", "type": "ban" if i % 7 else "captcha",
             "origin": "cscli", "created": "", "until": "", "until_ts": 1.0e9 + i,
             "simulated": False, "expiring": False} for i in range(n)]


class FakeCrowdsec:
    """Stands in for the three cscli calls behind the panel."""

    def __init__(self, n=300):
        self.n = n
        self.fetches = 0
        self.gate = None          # threading.Event: fetch blocks until set
        self.fail = False

    def fetch(self):
        self.fetches += 1
        if self.gate is not None:
            self.gate.wait(10)
        if self.fail:
            return {"ok": False, "error": "cscli down"}
        return {"ok": True, "decisions": decisions(self.n)}


FAKE = FakeCrowdsec()
A._fetch_crowdsec_active_decisions = FAKE.fetch
A._cscli = lambda args, default=None: [{"name": "fw-bouncer"}] if args[:1] == ["bouncers"] else []
A.crowdsec_enforcement = lambda: {"mode": "nftables", "at": 1}
A._read_custom_blocklist = lambda: ["198.51.100.9"]


def reset_caches():
    for c in (A._CROWDSEC_DEC_CACHE, A._CROWDSEC_PANEL_CACHE, A._CROWDSEC_BAN_STATE_CACHE):
        assert wait_for(lambda c=c: not c.refreshing), "refresh still running"
        c.drop()
    FAKE.gate, FAKE.fail, FAKE.fetches = None, False, 0


def t_swr_cache():
    calls = []
    gate = threading.Event()
    gate.set()

    def build():
        calls.append(1)
        gate.wait(10)
        return {"ok": True, "n": len(calls)}

    c = A._SwrCache("t", 30.0, build)
    v, stale = c.read()
    check(v == {"ok": True, "n": 1} and not stale and len(calls) == 1, "cold read builds synchronously")
    check(c.get()["n"] == 1 and len(calls) == 1, "fresh read is served from the cache")

    # stale: served at once, one background refresh however many readers
    c.at -= 31
    gate.clear()
    outs = [c.read() for _ in range(20)]
    check(all(o == ({"ok": True, "n": 1}, True) for o in outs), "stale value served immediately, flagged stale")
    check(wait_for(lambda: len(calls) == 2) and c.refreshing, "background refresh started")
    time.sleep(0.05)
    check(len(calls) == 2, "only one refresh in flight (single-flight, %d builds)" % len(calls))
    gate.set()
    check(wait_for(lambda: not c.refreshing) and c.get()["n"] == 2, "refresh result stored, value fresh again")

    # failed refresh keeps the last good value
    broken = []
    calls.clear()
    c2 = A._SwrCache("t2", 30.0, lambda: {"ok": False, "error": "x"} if broken else build())
    c2.get()
    broken.append(1)
    c2.at -= 31
    c2.get()
    check(wait_for(lambda: not c2.refreshing) and c2.get()["n"] == 1, "failed refresh keeps the last good value")
    c3 = A._SwrCache("t3", 30.0, lambda: {"ok": False, "error": "down"})
    check(c3.get() == {"ok": False, "error": "down"} and c3.peek()[0] is None,
          "failed cold build: error returned, nothing stored")

    # soft invalidation while a cold build runs: stored, but stale
    gate.clear()
    c4 = A._SwrCache("t4", 30.0, build)
    th = threading.Thread(target=c4.get)
    th.start()
    time.sleep(0.05)
    c4.mark_stale()
    gate.set()
    th.join(5)
    check(c4.peek()[0] is not None and c4.peek()[1] == 0.0, "mark_stale during a cold build: value kept as stale")
    gate.set()

    # concurrent cold callers share one build
    calls.clear()
    gate.clear()
    c3 = A._SwrCache("t3", 30.0, build)
    got = []
    ths = [threading.Thread(target=lambda: got.append(c3.get())) for _ in range(8)]
    for th in ths:
        th.start()
    time.sleep(0.1)
    gate.set()
    for th in ths:
        th.join(5)
    check(len(calls) == 1 and len(got) == 8 and all(g is got[0] for g in got),
          "8 concurrent cold readers -> 1 build (%d)" % len(calls))

    # mark_stale during a refresh: that result is discarded and it runs again
    calls.clear()
    gate.clear()
    c3.at -= 31
    c3.get()
    wait_for(lambda: len(calls) == 1)
    c3.mark_stale()
    gate.set()
    check(wait_for(lambda: not c3.refreshing) and len(calls) == 2, "mark_stale during a refresh reruns it")
    v, stale = c3.read()
    check(not stale and v["n"] == 2, "the rerun's value is stored as fresh")

    # drop during a refresh: the refresh's value is discarded, next read is cold
    calls.clear()
    gate.clear()
    c3.at -= 31
    c3.get()
    wait_for(lambda: len(calls) == 1)
    c3.drop()
    gate.set()
    check(wait_for(lambda: not c3.refreshing) and c3.peek()[0] is None, "drop discards an overlapping refresh")

    # mark_stale(kick=True) refreshes right away without a reader
    calls.clear()
    c3.get()
    c3.mark_stale(kick=True)
    check(wait_for(lambda: len(calls) == 2 and not c3.refreshing) and not c3.read()[1],
          "mark_stale(kick=True) refreshes in the background")


def t_separate_timestamps():
    reset_caches()
    check(A._CROWDSEC_PANEL_CACHE is not A._CROWDSEC_BAN_STATE_CACHE, "panel and ban-state are separate caches")
    bs = A.build_crowdsec_ban_state()
    check(bs.get("ok") and "198.51.100.9" in bs["ips"], "ban-state built (banlist + decisions)")
    A._CROWDSEC_BAN_STATE_CACHE.at -= A._CROWDSEC_PANEL_TTL + 1     # ban-state ages out
    cs = A.build_crowdsec()                                        # panel built now
    check(cs.get("ok") and cs["active_count"] == FAKE.n, "panel built")
    _, stale = A._CROWDSEC_BAN_STATE_CACHE.read()
    check(stale, "building the panel does not make an old ban-state look fresh")
    wait_for(lambda: not A._CROWDSEC_BAN_STATE_CACHE.refreshing)
    A._CROWDSEC_PANEL_CACHE.at -= A._CROWDSEC_PANEL_TTL + 1
    A.build_crowdsec_ban_state()
    _, stale = A._CROWDSEC_PANEL_CACHE.read()
    check(stale, "building ban-state does not make an old panel look fresh")


def t_panel_background_and_invalidation():
    reset_caches()
    A.build_crowdsec()
    check(FAKE.fetches == 1, "cold panel: one decisions fetch")
    # automatic ban (deception/community-auto): soft - still served, refresh now
    FAKE.gate = threading.Event()
    A._invalidate_crowdsec_decisions_cache(soft=True)
    check(A._CROWDSEC_DEC_CACHE.peek()[0] is not None and A._CROWDSEC_PANEL_CACHE.peek()[0] is not None,
          "soft invalidation keeps the snapshots")
    t0 = time.time()
    outs = [A.build_crowdsec() for _ in range(10)]
    dt = time.time() - t0
    check(wait_for(lambda: FAKE.fetches == 2), "the next read starts a decisions refresh")
    check(all(o.get("ok") and o["active_count"] == FAKE.n for o in outs) and dt < 1.0,
          "panel served from the stale snapshot while the refresh runs (%.2fs)" % dt)
    check(FAKE.fetches == 2, "one decisions refresh in flight (%d)" % FAKE.fetches)
    FAKE.n = 320
    FAKE.gate.set()
    check(wait_for(lambda: not A._CROWDSEC_DEC_CACHE.refreshing), "decisions refresh finished")
    check(A._CROWDSEC_PANEL_CACHE.read()[1], "new decisions mark the panel stale")
    check(wait_for(lambda: A.build_crowdsec()["active_count"] == 320), "panel picks up the new decisions")

    # interactive ban: hard - the next read waits for fresh data
    FAKE.gate = None
    A._invalidate_crowdsec_decisions_cache()
    check(A._CROWDSEC_PANEL_CACHE.peek()[0] is None and A._CROWDSEC_DEC_CACHE.peek()[0] is None,
          "interactive invalidation empties the caches")
    FAKE.n = 321
    check(A.build_crowdsec()["active_count"] == 321, "next read after an interactive ban is fresh")

    # failure: a stale panel keeps being served
    reset_caches()
    A.build_crowdsec()
    FAKE.fail = True
    A._CROWDSEC_PANEL_CACHE.at -= A._CROWDSEC_PANEL_TTL + 1
    A._CROWDSEC_DEC_CACHE.at = 0.0
    for _ in range(3):
        check(A.build_crowdsec().get("ok"), "CrowdSec failing: last good panel still served")
    wait_for(lambda: not A._CROWDSEC_DEC_CACHE.refreshing)
    FAKE.fail = False


def t_summary_http():
    reset_caches()
    FAKE.n = 300
    r = H.request("GET", "/api/crowdsec/summary", role="viewer")
    j = r.json or {}
    check(r.status == 200 and j.get("ok"), "summary: viewer gets 200 (%s %s)" % (r.status, r.error))
    check(set(j) == {"ok", "active_count", "bans_count", "recent", "enforcement", "updated_at", "stale"},
          "summary keys (%s)" % sorted(j))
    full = A.build_crowdsec()
    check(j.get("active_count") == 300 and j.get("bans_count") == full["bans_count"], "summary counts")
    check(j.get("recent") == [d["ip"] for d in full["decisions"][:25]],
          "summary.recent = first 25 IPs of /api/crowdsec's decision list, same order")
    check(j.get("enforcement") == {"mode": "nftables", "at": 1}, "summary carries the enforcement summary")
    check(isinstance(j.get("updated_at"), int) and abs(j["updated_at"] - time.time()) < 60, "summary updated_at")
    check(len(r.body) < 8192, "summary is small (%d bytes)" % len(r.body))
    rf = H.request("GET", "/api/crowdsec", role="viewer")
    check(rf.status == 200 and len((rf.json or {}).get("decisions") or []) == 300
          and set(rf.json) >= {"decisions", "active_count", "bans_count", "bouncers", "alerts", "enforcement"},
          "/api/crowdsec still carries the full payload")
    r = H.request("GET", "/api/crowdsec/summary")
    check(r.status == 401, "summary without a session -> 401 (%s)" % r.status)
    r = H.request("GET", "/api/crowdsec/summary", headers={A.AGENT_API_TOKEN_HEADER: api_harness.AGENT_TOKEN})
    check(r.status == 200 and (r.json or {}).get("ok"), "summary readable with the agent read token (%s)" % r.status)
    check("/api/crowdsec/summary" in A.AGENT_API_READ_PATHS, "summary in AGENT_API_READ_PATHS")
    FAKE.fail = True
    reset_caches()
    FAKE.fail = True
    r = H.request("GET", "/api/crowdsec/summary", role="viewer")
    check(r.status == 200 and (r.json or {}).get("ok") is False and r.json.get("error"),
          "summary with CrowdSec down: ok false + error")
    FAKE.fail = False


def abort_request(path):
    """GET path, then reset the connection before the answer is written."""
    tag = "abort-%d" % len(LOG)
    s = socket.create_connection(("127.0.0.1", H.port))
    req = ("GET %s HTTP/1.1\r\nHost: x\r\nCookie: %s=%s\r\n%s: %s\r\n\r\n"
           % (path, A.SESSION_COOKIE, H.session("viewer"), api_harness.REQ_HEADER, tag))
    s.sendall(req.encode())
    time.sleep(0.1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    return tag


def t_client_abort():
    released = threading.Event()
    served = []
    real = A.build_crowdsec

    def slow_big():
        released.wait(10)
        served.append(1)
        return {"ok": True, "decisions": ["x" * 200] * 40000}    # ~8 MB

    A.build_crowdsec = slow_big
    try:
        LOG.clear()
        tag = abort_request("/api/crowdsec?x=1")
        time.sleep(0.1)
        released.set()
        check(wait_for(lambda: any("client closed" in x for x in LOG)), "client abort logged (%r)" % LOG[-3:])
        notes = [x for x in LOG if "client closed" in x]
        check(len(notes) == 1 and "GET /api/crowdsec " in notes[0] and "?" not in notes[0]
              and "Traceback" not in "".join(LOG), "one short line with the path (%r)" % notes)
        time.sleep(0.2)
        check(tag not in H._traces, "no traceback for a client abort")
        released.clear()
        tag2 = abort_request("/api/crowdsec")
        time.sleep(0.1)
        released.set()
        wait_for(lambda: len(served) == 2)
        time.sleep(0.3)
        check(len([x for x in LOG if "client closed" in x]) == 1, "second abort on the same path muted")
        check(tag2 not in H._traces, "no traceback for the second abort")
        ent = A._CLIENT_ABORT_LOG.get("/api/crowdsec")
        check(ent and ent[1] == 1, "muted aborts counted for the next note (%r)" % (ent,))
        # an abort while idle on keep-alive (no request read) is silent
        LOG.clear()
        s = socket.create_connection(("127.0.0.1", H.port))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()
        time.sleep(0.2)
        check(not LOG, "idle connection reset: nothing logged")

        # a real handler error still produces its traceback
        def boom():
            raise RuntimeError("real bug")
        A.build_crowdsec = boom
        r = H.request("GET", "/api/crowdsec", role="viewer")
        wait_for(lambda: r.tag in H._traces)
        check("RuntimeError: real bug" in H._traces.get(r.tag, ""), "real exceptions keep their traceback")
    finally:
        released.set()
        A.build_crowdsec = real
    # the log note itself: rate limit per path, interval honoured
    A._CLIENT_ABORT_LOG.clear()
    LOG.clear()
    e = BrokenPipeError()
    check(A._note_client_abort("GET", "/a", e) and not A._note_client_abort("GET", "/a", e)
          and A._note_client_abort("GET", "/b", e), "one note per path per interval")
    A._CLIENT_ABORT_LOG["/a"][0] -= A.CLIENT_ABORT_LOG_INTERVAL + 1
    check(A._note_client_abort("GET", "/a", e) and "2 times" in LOG[-1], "next note after the interval counts muted ones")


def t_home_assistant_shapes():
    path = os.path.join(ROOT, "integrations", "home-assistant", "tuxwall", "crowdsec_data.py")
    spec = importlib.util.spec_from_file_location("tuxwall_ha_crowdsec_data", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    full = A._build_crowdsec_panel()
    summary = {"ok": True, "active_count": full["active_count"], "bans_count": full["bans_count"],
               "recent": [d["ip"] for d in full["decisions"][:25]]}
    check(m.crowdsec_active_count(full) == m.crowdsec_active_count(summary) == full["active_count"],
          "HA: same count from either shape")
    check(m.crowdsec_ips(full) == m.crowdsec_ips(summary) == summary["recent"], "HA: same IPs from either shape")
    check(m.crowdsec_active_count({}) == 0 and m.crowdsec_ips({}) == [], "HA: unavailable reads as 0 / []")
    check(m.crowdsec_active_count({"decisions": [{"value": "x"}]}) == 1
          and m.crowdsec_ips({"decisions": [{"value": "x"}]}) == ["x"], "HA: old 'value' field still read")
    manifest = json.load(open(os.path.join(os.path.dirname(path), "manifest.json")))
    check(manifest.get("version") not in (None, "1.0.0"), "HA manifest version bumped")
    coord = open(os.path.join(os.path.dirname(path), "coordinator.py")).read()
    check('"/api/crowdsec/summary"' in coord and "TuxwallNotFound" in coord, "HA coordinator uses the summary with a 404 fallback")


for t in (t_swr_cache, t_separate_timestamps, t_panel_background_and_invalidation, t_summary_http,
          t_client_abort, t_home_assistant_shapes):
    try:
        t()
    except Exception as exc:
        import traceback
        traceback.print_exc()
        check(False, "%s raised %r" % (t.__name__, exc))

H.close()
print("crowdsec_cache_check: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
