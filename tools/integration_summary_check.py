#!/usr/bin/env python3
"""GET /api/integration/summary (www/includes/api_server.py) - the one
payload the Home Assistant integration polls - over the loopback harness
(tools/api_harness.py, fail-closed sandbox: no subprocess, no writes outside
a temp dir, no network):

  python3 tools/integration_summary_check.py

The sources behind each section are stubbed (documentation addresses only).

Covers: _SwrCache.kick()/wait() (background-only builds, bounded waits,
error kept); the summary's shape (every section with ok/stale, a few KB),
auth (401 without a session, viewer ok, admin ok, no agent token: some parts
are not agent-readable) and the route policy entry; section failure
isolation (a raising, refusing or hanging source flags only its own section,
the response stays within INTEGRATION_WAIT, a stale value is served while a
slow refresh runs and the next poll does not wait for it); the derived
fields (community status, certificate expiry per HTTPS mode, tripwire
level, WAN connectivity from the latency monitor, apt candidate version);
the /api/firewall traffic block unchanged by the _ufw_log_traffic()
extraction; INTEGRATION_CORE_UNITS == the integration's CORE_SERVICES; and
the Home Assistant parser (summary_data.py) reading the real payload.
"""
import importlib
import json
import os
import sys
import tempfile
import threading
import time
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.dont_write_bytecode = True
import api_harness  # noqa: E402
import route_policy  # noqa: E402

HA_DIR = os.path.join(ROOT, "integrations", "home-assistant", "tuxwall")
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


def ha_module(name):
    """A module of the HA integration without running its __init__ (which
    imports Home Assistant)."""
    if "twha" not in sys.modules:
        pkg = types.ModuleType("twha")
        pkg.__path__ = [HA_DIR]
        sys.modules["twha"] = pkg
    return importlib.import_module("twha." + name)


H = api_harness.Harness(name="api_server_integration_summary")
A = H.mod
LOG = []
A.print = lambda *a, **k: LOG.append(" ".join(str(x) for x in a))
NOW = time.time()


class FakeLatency:
    sample = None

    def latest(self):
        return self.sample


class FakeSecurity:
    def snapshot(self):
        return {"ok": True, "stats": {"hits": 900, "unique_ips": 700, "countries": 30, "hits_1m": 4,
                                      "hits_10m": 31, "last_event": NOW}}

    def top_countries(self, since, limit=3):
        return [{"iso": "NL", "name": "Netherlands", "hits": 300, "sources": 12},
                {"iso": "DE", "name": "Germany", "hits": 120, "sources": 9}][:limit]


LAT = FakeLatency()
LAT.sample = {"ts": NOW, "avg_ms": 12.5, "max_ms": 20.0, "loss_pct": 0.0, "jitter_ms": 1.5}
BK_STATE = {"last_success": {"finished": int(NOW) - 3600}, "last_failure": {"finished": int(NOW) - 86400 * 3},
            "last_run": {"running": False}}
HTTPS = {"value": {"ok": True, "mode": "owner-managed", "in_use": "none",
                   "owner_sites": [{"file": "site-a", "listen": ["443"],
                                    "cert": {"not_after": NOW + 86400 * 50, "days_left": 50}},
                                   {"file": "site-b", "listen": ["8443"],
                                    "cert": {"not_after": NOW + 86400 * 20, "days_left": 20}}],
                   "cert": {"not_after": NOW + 86400 * 300, "days_left": 300},
                   "ca": {"not_after": NOW + 86400 * 3000}}}
APT_DIR = tempfile.mkdtemp(prefix="apt-lists-", dir=H.scratch)
with open(os.path.join(APT_DIR, "example.org_tuxwall_dists_stable_main_binary-all_Packages"), "w") as f:
    f.write("Package: tuxwall\nVersion: 3.3.6\nArchitecture: all\n\n"
            "Package: tuxwall-extra\nVersion: 9.9.9\n\n"
            "Package: tuxwall\nVersion: 3.3.10\nArchitecture: all\n\n"
            "Package: tuxwall\nVersion: 3.3.9\n")
with open(os.path.join(APT_DIR, "example.org_ubuntu_dists_main_binary-amd64_Packages"), "w") as f:
    f.write("Package: tuxwall\nVersion: 99.0\n")          # not a TuxWall index: ignored
UFW_FIXTURE = os.path.join(H.scratch, "ufw.log")
with open(UFW_FIXTURE, "w") as f:
    for i in range(40):
        act = "BLOCK" if i % 4 else "ALLOW"
        f.write("2026-11-24T10:00:%02d.000000-05:00 gw kernel: [UFW %s] IN=wan0 OUT= MAC=00 "
                "SRC=203.0.113.%d DST=192.0.2.1 LEN=40 TOS=0x00 PREC=0x00 TTL=50 ID=1 PROTO=TCP "
                "SPT=4000 DPT=%d WINDOW=1 RES=0x00 SYN URGP=0\n" % (i, act, i % 7 + 1, 22 + i % 3))

SERVICES = [{"unit": u, "load": "loaded", "active": "active", "sub": "running", "desc": "unit " + u}
            for u in A.INTEGRATION_CORE_UNITS if u != "radvd.service"]
SERVICES.append({"unit": "other.service", "load": "loaded", "active": "failed", "sub": "failed", "desc": "x"})

REAL_OPEN = open


def fake_open(path, *a, **k):
    return REAL_OPEN(UFW_FIXTURE if path == "/var/log/ufw.log" else path, *a, **k)


A.open = fake_open
A.list_system_services = lambda: {"ok": True, "services": [dict(s) for s in SERVICES], "conflicts": []}
A.get_security_monitor = lambda: FakeSecurity()
A.get_latency_monitor = lambda: LAT
A.build_crowdsec_summary = lambda: {"ok": True, "active_count": 1234, "bans_count": 1200,
                                    "recent": ["203.0.113.%d" % i for i in range(1, 26)],
                                    "enforcement": {"mode": "nftables"}, "updated_at": int(NOW), "stale": False}
A.build_dns = lambda: {"ok": True, "extended": True,
                       "totals": {"queries": 1000, "nxdomain": 250, "hitrate": 0.8125}}
A.count_blocked_domains = lambda: 123456
A.last_blocklist_update = lambda: NOW - 7200
A.build_system = lambda: {
    "ok": True, "hostname": "gw", "tuxwall_version": "3.3.6", "kernel": "6.0", "uptime": 5000.0,
    "cpu": {"temp": 48.5}, "usage": {"cpu_pct": 3.2, "mem_pct": 41.0, "disk_pct": 12.3, "swap_pct": 0.0,
                                     "load": [0.1, 0.2, 0.3]},
    "wan": {"ifname": "wan0", "state": "UP", "ipv4": "192.0.2.1", "ipv6": ["2001:db8::1", "2001:db8::2",
                                                                         "2001:db8::3"],
            "gateway4": "192.0.2.254", "gateway6": "fe80::1"},
    "interfaces": [{"name": "lan0"}] * 10, "history": [[1, 2]] * 100}
A.build_honeypot = lambda: {"ok": True, "conf": {"enabled": True},
                            "state": {"listening": True, "active_count": 3, "sources_24h": 17,
                                      "stats": {"total": 99, "unique": 40, "banned": 12},
                                      "log": ["[10:00:%02d] line %d" % (i, i) for i in range(20)],
                                      "started_at": NOW - 999}}
A.build_canary = lambda: {"ok": True, "active": True, "events_24h": 55, "sources_24h": 21, "creds_24h": 4,
                          "bans_active": 300, "events": [{"src": "203.0.113.9"}] * 25}
TRIP = {"value": {"ok": True, "mode": "medium", "enabled": True, "tripped": False, "trip_mode": "high",
                  "since": NOW - 86400 * 10, "reason": "old trip", "phase": "normal", "strength": "medium",
                  "trips": 2, "resolved_at": NOW - 86400 * 9}}
A.tripwire_status = lambda: dict(TRIP["value"])
REPORT = {"value": {"enabled": True, "last_report": NOW - 60, "last_error": None, "last_error_at": None,
                    "queue_length": 0, "sent_24h": 40, "paused": False, "held": False}}
A.reporting_status = lambda: dict(REPORT["value"])
A.build_wireguard = lambda: {"ok": True, "configured": True, "interface": {"up": True},
                             "peers": [{"last_handshake": NOW - 30}, {"last_handshake": NOW - 4000},
                                       {"last_handshake": 0}]}
A.build_leases = lambda: {"ok": True, "leases": [
    {"ip": "192.0.2.10", "expires": NOW + 100, "online": True, "static": False},
    {"ip": "192.0.2.11", "expires": NOW + 100, "online": False, "static": True},
    {"ip": "192.0.2.12", "expires": None, "online": True, "static": True}]}


class FakeBk:
    @staticmethod
    def load_state():
        return json.loads(json.dumps(BK_STATE))

    @staticmethod
    def load_settings():
        return {"stale_days": 8}


A._bk = FakeBk
A.https_status = lambda: json.loads(json.dumps(HTTPS["value"]))
A._dpkg_version = lambda pkg: "3.3.6"
A.APT_LISTS_DIR = APT_DIR
A._boot_time = lambda: int(NOW) - 5000
A.build_devices_summary = lambda: {
    "ok": True, "available": True, "running": True, "generated_at": int(NOW), "devices": 12, "online": 9,
    "new_24h": 1, "flagged": 2, "critical": 1, "warning": 1, "quarantined": 0, "findings_active": 3,
    "worst": {"severity": "critical", "reason": "Connected to a known botnet C2 server (Feodo Tracker)",
              "device": "m020000000001", "device_name": "Example laptop", "last": int(NOW) - 60},
    "feeds_ok": 1, "feeds_total": 3}
A._integ_devices_recent = lambda: (
    [{"id": "f" * 16, "severity": "critical", "reason": "Connected to a known botnet C2 server (Feodo Tracker)",
      "device": "m020000000001", "device_name": "Example laptop", "first": int(NOW) - 120, "last": int(NOW) - 60}],
    [{"id": "m020000000002", "name": "Example plug", "zone": "IoT", "vendor": "", "first_seen": int(NOW) - 300}])


def reset():
    for c in A._INTEG_CACHES.values():
        assert wait_for(lambda c=c: not c.refreshing), "refresh still running: " + c.name
        c.drop()
        c.error = None


def summary(role="viewer"):
    r = H.request("GET", "/api/integration/summary", role=role)
    return r, (r.json or {})


SECTIONS = ("services", "security", "firewall", "crowdsec", "dns", "blocklist", "system", "wan", "tarpit",
            "canary", "tripwire", "community", "wireguard", "dhcp", "backup", "https", "update", "devices")
# server sections the Home Assistant integration does not read (none since HA 1.3.0)
NOT_IN_HA_YET = set()


def t_swr_kick_wait():
    gate = threading.Event()
    calls = []

    def build():
        calls.append(threading.current_thread().name)
        gate.wait(10)
        return {"ok": True, "n": len(calls)}

    c = A._SwrCache("kw", 30.0, build)
    check(c.kick() is True and c.kick() is False, "kick starts one refresh; a second kick does not")
    check(wait_for(lambda: len(calls) == 1) and calls[0] == "kw", "cold kick builds in a background thread")
    t0 = time.time()
    v, stale = c.wait(time.time() + 0.2)
    check(v is None and stale and 0.15 < time.time() - t0 < 1.0, "wait() gives up at the deadline (cold: None)")
    gate.set()
    v, stale = c.wait(time.time() + 5)
    check(v == {"ok": True, "n": 1} and not stale, "wait() returns the finished build")
    check(c.kick() is False, "fresh: no refresh")
    c.at -= 31
    gate.clear()
    check(c.kick() is True, "stale: kick refreshes")
    v, stale = c.wait(time.time() + 0.05)
    check(v["n"] == 1 and stale, "slow refresh: last value, flagged stale")
    v, stale = c.wait(0, ref=c.at + 1)
    check(not stale, "staleness judged at ref")
    gate.set()
    wait_for(lambda: not c.refreshing)
    bad = A._SwrCache("kw-bad", 30.0, lambda: {"ok": False, "error": "source down"})
    bad.kick()
    v, _ = bad.wait(time.time() + 2)
    check(v is None and bad.error == "source down", "failed build: nothing stored, error kept (%r)" % bad.error)

    def boom():
        raise RuntimeError("kaput")
    bad2 = A._SwrCache("kw-boom", 30.0, boom)
    bad2.kick()
    bad2.wait(time.time() + 2)
    check(bad2.error == "kaput" and not bad2.refreshing, "raising build: error kept, refresh ended")


def t_shape_and_auth():
    reset()
    r, j = summary()
    check(r.status == 200 and j.get("ok") is True, "viewer: 200 (%s %s)" % (r.status, r.error))
    check(j.get("schema") == 1 and isinstance(j.get("generated_at"), int), "schema + generated_at")
    check(all(isinstance(j.get(s), dict) and j[s].get("ok") is True and j[s].get("stale") is False
              for s in SECTIONS), "every section ok and fresh (%s)"
          % [s for s in SECTIONS if not (j.get(s) or {}).get("ok")])
    check(set(j) == set(SECTIONS) | {"ok", "schema", "generated_at", "tuxwall_version"},
          "no unexpected top-level keys (%s)" % sorted(set(j) - set(SECTIONS)))
    check(len(r.body) < 6144, "a few KB (%d bytes)" % len(r.body))
    check(not r.effects, "no side effects (%r)" % r.effects[:3])
    body = r.body.decode()
    for leak in ("history", "interfaces", "path", "key", "password", "token", "events"):
        check('"%s"' % leak not in body, "no %r field in the summary" % leak)
    check(r.headers.get("content-type", "").startswith("application/json"), "JSON content type")
    r2 = H.request("GET", "/api/integration/summary")
    check(r2.status == 401, "no session -> 401 (%s)" % r2.status)
    r3, j3 = summary("admin")
    check(r3.status == 200 and j3.get("ok"), "admin -> 200")
    r4 = H.request("GET", "/api/integration/summary",
                   headers={A.AGENT_API_TOKEN_HEADER: api_harness.AGENT_TOKEN})
    check(r4.status in (401, 403), "agent read token is not accepted (%s)" % r4.status)
    check("/api/integration/summary" not in A.AGENT_API_READ_PATHS, "not in AGENT_API_READ_PATHS")
    check("GET /api/integration/summary" in route_policy.VIEWER_OK
          and "GET /api/integration/summary" not in route_policy.AGENT_TOKEN_OK, "route policy: viewer, no agent")
    return j


def t_values(j):
    s = j["services"]
    check([u["unit"] for u in s["units"]] == [u for u in A.INTEGRATION_CORE_UNITS if u != "radvd.service"],
          "services: core units only, in order, absent unit left out")
    check(s["failed"] == 1 and set(s["units"][0]) == {"unit", "active", "sub", "desc"}, "services: failed count")
    check(j["security"]["hits_1m"] == 4 and j["security"]["top_countries_24h"][0]["iso"] == "NL", "security")
    check(j["firewall"] == {"block": 30, "allow": 10, "ok": True, "stale": False}, "firewall counts (%r)"
          % j["firewall"])
    check(j["crowdsec"]["active_count"] == 1234 and len(j["crowdsec"]["recent"]) == 25, "crowdsec")
    check(j["dns"]["queries"] == 1000 and j["dns"]["hitrate"] == 0.8125, "dns")
    check(j["blocklist"]["domains"] == 123456, "blocklist")
    sy = j["system"]
    check(sy["cpu_pct"] == 3.2 and sy["mem_pct"] == 41.0 and sy["disk_pct"] == 12.3 and sy["temp_c"] == 48.5
          and sy["boot_time"] == int(NOW) - 5000 and "wan" not in sy, "system")
    w = j["wan"]
    check(w["online"] is True and w["ipv6_ready"] is True and w["latency_ms"] == 12.5 and w["ipv4"] == "192.0.2.1"
          and len(w["ipv6"]) == 2 and w["ok"], "wan (%r)" % w)
    check(j["tarpit"]["active"] == 3 and j["tarpit"]["total"] == 99 and len(j["tarpit"]["log"]) == 5, "tarpit")
    check(j["canary"]["events_24h"] == 55 and "events" not in j["canary"], "canary")
    t = j["tripwire"]
    check(t["tripped"] is False and t["level"] == "medium" and t["reason"] is None and t["since"] is None,
          "tripwire not tripped: level = strength, no reason/since")
    check(j["community"]["status"] == "ok" and j["community"]["sent_24h"] == 40, "community ok")
    check(j["wireguard"]["peers"] == 3 and j["wireguard"]["online"] == 1, "wireguard")
    check(j["dhcp"] == {"leases": 2, "online": 1, "reserved": 2, "ok": True, "stale": False},
          "dhcp: online counts leased clients only (%r)" % j["dhcp"])
    b = j["backup"]
    check(b["last_success"] == int(NOW) - 3600 and b["failed"] is False, "backup")
    h = j["https"]
    check(h["source"] == "owner" and abs(h["expires"] - (NOW + 86400 * 20)) < 1 and h["days_left"] == 20,
          "https owner-managed: earliest owner certificate")
    u = j["update"]
    check(u["installed"] == "3.3.6" and u["latest"] == "3.3.10" and u["source"] == "apt"
          and isinstance(u["checked_at"], int), "update: newest TuxWall in the TuxWall apt index (%r)" % u)
    check(j["tuxwall_version"] == "3.3.6", "tuxwall_version")
    d = j["devices"]
    check(d["flagged"] == 2 and d["quarantined"] == 0 and d["worst"]["severity"] == "critical"
          and set(d["worst"]) == {"severity", "reason", "device_name", "last"}
          and set(d["findings"][0]) == {"id", "severity", "reason", "device", "device_name", "first", "last"}
          and set(d["new_devices"][0]) == {"id", "name", "zone", "vendor", "first_seen"},
          "devices: counts, worst, newest findings/new devices - generic reasons, no indicator or address (%r)" % d)


def t_derived():
    # tripwire tripped
    TRIP["value"] = dict(TRIP["value"], tripped=True, reason="Suricata priority-1 alert", since=NOW - 5)
    out = A._integ_tripwire()
    check(out["tripped"] and out["level"] == "high" and out["reason"] and out["since"], "tripwire tripped")
    TRIP["value"] = dict(TRIP["value"], tripped=False)
    # community states
    base = dict(REPORT["value"])
    cases = [({"enabled": False}, "off"),
             ({"last_error_at": NOW, "last_report": NOW - 100}, "error"),
             ({"last_error_at": NOW - 100, "last_report": NOW}, "ok"),
             ({"last_report": None, "last_error_at": NOW}, "error"),
             ({"queue_length": 4}, "queued")]
    for patch, want in cases:
        REPORT["value"] = dict(base, **patch)
        check(A._integ_community()["status"] == want, "community %r -> %s" % (patch, want))
    REPORT["value"] = base
    # https per mode
    keep = HTTPS["value"]
    for value, want in (
            (dict(keep, mode="active", in_use="tuxwall"), ("tuxwall", 300)),
            (dict(keep, mode="active", in_use="custom", custom={"not_after": NOW + 86400 * 9, "days_left": 9}),
             ("custom", 9)),
            (dict(keep, mode="active", in_use="custom", custom={"path": "/etc/x", "error": "missing"}),
             (None, None)),
            (dict(keep, mode="disabled"), (None, None)),
            (dict(keep, owner_sites=[{"cert": {"error": "unreadable"}}]), (None, None))):
        HTTPS["value"] = value
        out = A._integ_https()
        check((out["source"], out["days_left"]) == want, "https %s/%s -> %r (%r)"
              % (value["mode"], value.get("in_use"), want, (out["source"], out["days_left"])))
    HTTPS["value"] = {"ok": False, "error": "module missing"}
    check(A._integ_https() == {"ok": False, "error": "module missing"}, "https unavailable -> section error")
    HTTPS["value"] = keep
    # WAN connectivity from the latency monitor
    sysd = {"wan": {"ifname": "wan0", "ipv6": [], "gateway6": False}}
    for sample, want in ((dict(LAT.sample, ts=time.time()), True),
                         (dict(LAT.sample, ts=time.time(), loss_pct=100.0), False),
                         (dict(LAT.sample, ts=time.time() - 600), False),
                         (None, None)):
        keep_s, LAT.sample = LAT.sample, sample
        w = A._integ_wan(sysd, False)
        check(w["online"] is want and w["ipv6_ready"] is False, "wan online %r -> %r (%r)" % (
            sample and (sample["loss_pct"], int(time.time() - sample["ts"])), want, w["online"]))
        LAT.sample = keep_s
    check(A._integ_wan({"wan": {"ifname": ""}}, False)["online"] is False, "no default route -> offline")
    w = A._integ_wan(None, False)
    check(w["ok"] is True and w["ipv4"] is None and w["online"] is True,
          "system section missing: connectivity still reported (%r)" % w)
    keep_s, LAT.sample = LAT.sample, None
    check(A._integ_wan(None, False)["ok"] is False, "no system, no samples: wan not ok")
    LAT.sample = keep_s
    # apt candidate
    check(A._apt_candidate(lists_dir=os.path.join(H.scratch, "nope")) == (None, None), "no apt index -> None")
    real_dpkg = A._dpkg_version
    A._dpkg_version = lambda pkg: "3.4.0"
    try:
        u = A._integ_update()
        check(u["installed"] == "3.4.0" and u["latest"] == "3.4.0", "installed newer than the repo: latest = installed")
    finally:
        A._dpkg_version = real_dpkg
    # crowdsec: the panel's 30 s staleness is not the summary's
    real_cs = A.build_crowdsec_summary
    try:
        A.build_crowdsec_summary = lambda: {"ok": True, "active_count": 1, "stale": True, "updated_at": int(time.time())}
        check(A._integ_crowdsec()["stale"] is False, "crowdsec: recently built panel is not stale")
        A.build_crowdsec_summary = lambda: {"ok": True, "active_count": 1, "stale": True,
                                            "updated_at": int(time.time()) - 3600}
        check(A._integ_crowdsec()["stale"] is True, "crowdsec: an hour-old panel is stale")
        A.build_crowdsec_summary = lambda: {"ok": False, "error": "cscli down"}
        check(A._integ_crowdsec() == {"ok": False, "error": "cscli down"}, "crowdsec down: error passed on")
    finally:
        A.build_crowdsec_summary = real_cs


def t_isolation():
    reset()
    real = {n: getattr(A, n) for n in ("_integ_canary", "_integ_dns", "_integ_https", "_integ_dhcp")}
    gate = threading.Event()

    def hang():
        gate.wait(20)
        return {"ok": True, "events_24h": 1}

    def boom():
        raise RuntimeError("unbound-control exploded")

    A._integ_canary = hang
    A._integ_dns = boom
    A._integ_https = lambda: {"ok": False, "error": "HTTPS status unavailable"}
    A._integ_dhcp = lambda: None
    try:
        t0 = time.time()
        r, j = summary()
        dt = time.time() - t0
        check(r.status == 200 and j.get("ok"), "a failing source does not fail the response")
        check(dt < A.INTEGRATION_WAIT + 1.0, "hanging source: response within the wait (%.2fs)" % dt)
        check(j["canary"] == {"ok": False, "stale": True, "error": "not ready yet"}, "hanging cold section: pending")
        check(j["dns"]["ok"] is False and "exploded" in j["dns"]["error"], "raising source: its error (%r)" % j["dns"])
        check(j["https"]["ok"] is False and j["https"]["error"] == "HTTPS status unavailable", "refusing source")
        check(j["dhcp"]["ok"] is False, "builder returning nothing: section not ok")
        others = [s for s in SECTIONS if s not in ("canary", "dns", "https", "dhcp")]
        check(all(j[s]["ok"] and not j[s]["stale"] for s in others),
              "other sections unaffected (%s)" % [s for s in others if not j[s]["ok"]])
        check(any("exploded" in x for x in LOG), "a raising builder is logged once")
        # the next poll does not wait for the refresh still hanging
        t0 = time.time()
        r, j = summary()
        check(time.time() - t0 < A.INTEGRATION_WAIT + 1.0 and j["canary"]["ok"] is False,
              "still cold: waits at most INTEGRATION_WAIT again")
        gate.set()
        check(wait_for(lambda: not A._INTEG_CACHES["canary"].refreshing), "hanging refresh finished")
        r, j = summary()
        check(j["canary"]["ok"] and not j["canary"]["stale"] and j["canary"]["events_24h"] == 1, "recovered")
        # warm + slow refresh: stale value at once, next poll does not wait at all
        gate.clear()
        A._INTEG_CACHES["canary"].at -= 3600
        t0 = time.time()
        r, j = summary()
        dt1 = time.time() - t0
        check(j["canary"]["ok"] and j["canary"]["stale"] and j["canary"]["events_24h"] == 1,
              "slow refresh: last value served, stale")
        t0 = time.time()
        r, j = summary()
        dt2 = time.time() - t0
        check(dt2 < 0.5 and j["canary"]["stale"], "refresh from an earlier poll still running: no wait (%.2fs)"
              % dt2)
        check(dt1 < A.INTEGRATION_WAIT + 1.0, "first stale poll bounded (%.2fs)" % dt1)
        gate.set()
        wait_for(lambda: not A._INTEG_CACHES["canary"].refreshing)
    finally:
        gate.set()
        for n, f in real.items():
            setattr(A, n, f)
    reset()


def t_firewall_unchanged():
    t = A._ufw_log_traffic()
    check(t["block"] == 30 and t["allow"] == 10 and len(t["recent"]) == 25
          and t["top_sources"][0]["count"] >= t["top_sources"][-1]["count"]
          and {p["port"] for p in t["top_ports"]} == {"22/TCP", "23/TCP", "24/TCP"},
          "_ufw_log_traffic parses the log as build_firewall did (%r)" % {k: t[k] for k in ("block", "allow")})
    src = open(api_harness.TARGET).read()
    body = src[src.index("def build_firewall():"):src.index("_FW_COUNTER_CACHE")]
    check("traffic = _ufw_log_traffic()" in body and '"traffic": traffic,' in body,
          "build_firewall still returns the traffic block")


def t_core_units_match_ha():
    const = ha_module("const")
    check(list(A.INTEGRATION_CORE_UNITS) == list(const.CORE_SERVICES),
          "INTEGRATION_CORE_UNITS == CORE_SERVICES of the HA integration")


def t_ha_reads_payload():
    reset()
    _r, j = summary()
    sd = ha_module("summary_data")
    data = sd.normalize_summary(j)
    check(data["mode"] == "summary" and all(data["sections"][s] is not None for s in sd.SECTIONS),
          "HA: every section read")
    check(set(sd.SECTIONS) == set(SECTIONS) - NOT_IN_HA_YET, "HA section list == server sections")
    missing = [k for k in sd.VALUES if sd.value(data, k) is None]
    check(not missing, "HA: every entity has a value from the real payload (missing %s)" % missing)
    check(sd.value(data, "crowdsec_bans") == 1234 and sd.value(data, "dns_blocked_pct") == 25.0
          and sd.value(data, "internet_latency") == 12.5 and sd.value(data, "tripwire") is False
          and sd.value(data, "certificate_expiry") == j["https"]["expires"], "HA: values")
    check(sd.installed_version(data) == "3.3.6" and sd.router_latest(data) == "3.3.10", "HA: versions")


for t in (t_swr_kick_wait, t_shape_and_auth, t_derived, t_isolation, t_firewall_unchanged,
          t_core_units_match_ha, t_ha_reads_payload):
    try:
        if t is t_shape_and_auth:
            t_values(t())
        else:
            t()
    except Exception as exc:
        import traceback
        traceback.print_exc()
        check(False, "%s raised %r" % (t.__name__, exc))

H.close()
print("integration_summary_check: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
