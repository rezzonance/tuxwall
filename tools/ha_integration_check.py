#!/usr/bin/env python3
"""Home Assistant integration (integrations/home-assistant/tuxwall) without a
Home Assistant install:

  python3 tools/ha_integration_check.py

Runs the HA-free parsing module (summary_data.py, crowdsec_data.py) on stub
payloads of both API shapes - GET /api/integration/summary and the per-page
endpoints older routers serve (/api/system, /api/security, ...) - and checks
the integration's metadata: every file compiles, manifest keys/version,
strings.json == translations/en.json, every translation_key has a name and an
icon, the 1.0 entity keys/names are unchanged (unique_ids derive from them),
enum options are translated.
"""
import ast
import importlib
import json
import os
import py_compile
import re
import sys
import tempfile
import time
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HA_DIR = os.path.join(ROOT, "integrations", "home-assistant", "tuxwall")
sys.dont_write_bytecode = True
PASS = FAIL = 0
NOW = time.time()


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


def ha_module(name):
    if "twha" not in sys.modules:
        pkg = types.ModuleType("twha")
        pkg.__path__ = [HA_DIR]
        sys.modules["twha"] = pkg
    return importlib.import_module("twha." + name)


sd = ha_module("summary_data")

SUMMARY = {
    "ok": True, "schema": 1, "generated_at": int(NOW), "tuxwall_version": "3.3.6",
    "services": {"ok": True, "stale": False, "failed": 0, "units": [
        {"unit": "unbound.service", "active": "active", "sub": "running", "desc": "Unbound"},
        {"unit": "nginx.service", "active": "failed", "sub": "failed", "desc": "nginx"}]},
    "security": {"ok": True, "stale": False, "hits_1m": 5, "hits_10m": 40, "unique_ips": 300,
                 "top_countries_24h": [{"iso": "NL", "name": "Netherlands", "hits": 90, "sources": 4},
                                       {"iso": "DE", "name": "Germany", "hits": 10, "sources": 2}]},
    "firewall": {"ok": True, "stale": False, "block": 77, "allow": 3},
    "crowdsec": {"ok": True, "stale": True, "active_count": 12, "recent": ["203.0.113.1", "203.0.113.2"]},
    "dns": {"ok": True, "stale": False, "queries": 200, "nxdomain": 50, "hitrate": 0.5},
    "blocklist": {"ok": True, "stale": False, "domains": 1000, "updated_at": NOW - 60},
    "system": {"ok": True, "stale": False, "cpu_pct": 7.5, "mem_pct": 30.1, "disk_pct": 9.9, "temp_c": 51.0,
               "boot_time": int(NOW) - 1000, "uptime": 1000.0},
    "wan": {"ok": True, "stale": False, "ifname": "wan0", "ipv4": "192.0.2.1", "ipv6": ["2001:db8::1"],
            "online": True, "ipv6_ready": True, "latency_ms": 15.2, "loss_pct": 0.0, "jitter_ms": 1.1,
            "target": "192.0.2.53", "sample_at": int(NOW)},
    "tarpit": {"ok": True, "stale": False, "enabled": True, "active": 2, "total": 50, "log": []},
    "canary": {"ok": True, "stale": False, "active": True, "events_24h": 9, "sources_24h": 3, "creds_24h": 1,
               "bans_active": 5},
    "tripwire": {"ok": True, "stale": False, "tripped": True, "level": "high", "reason": "test", "since": NOW - 9,
                 "mode": "high", "phase": "tripped", "trips": 1},
    "community": {"ok": True, "stale": False, "status": "queued", "queue": 3, "last_report": NOW - 600},
    "wireguard": {"ok": True, "stale": False, "peers": 2, "online": 1, "up": True},
    "dhcp": {"ok": True, "stale": False, "leases": 14, "online": 12, "reserved": 3},
    "backup": {"ok": True, "stale": False, "last_success": int(NOW) - 7200, "failed": False},
    "https": {"ok": False, "stale": True, "error": "HTTPS status unavailable"},
    "update": {"ok": True, "stale": False, "installed": "3.3.6", "latest": "3.3.7", "checked_at": int(NOW)},
    "devices": {"ok": True, "stale": False, "running": True, "devices": 12, "online": 9, "new_24h": 1, "flagged": 2,
                "critical": 1, "warning": 1, "quarantined": 1,
                "worst": {"severity": "critical", "reason": "Connected to a known botnet C2 server (Feodo Tracker)",
                          "device_name": "Example laptop", "last": int(NOW) - 60},
                "findings": [{"id": "f2", "severity": "critical", "reason": "r2", "device": "m020000000001",
                              "device_name": "Example laptop", "first": int(NOW) - 60, "last": int(NOW) - 60},
                             {"id": "f1", "severity": "medium", "reason": "r1", "device": "m020000000002",
                              "device_name": "Example tv", "first": int(NOW) - 900, "last": int(NOW) - 600}],
                "new_devices": [{"id": "m020000000003", "name": "Example plug", "zone": "IoT", "vendor": "",
                                 "first_seen": int(NOW) - 300}]},
}

LEGACY = {
    "services": {"ok": True, "services": [
        {"unit": "unbound.service", "load": "loaded", "active": "active", "sub": "running", "desc": "Unbound"},
        {"unit": "nginx.service", "load": "loaded", "active": "failed", "sub": "failed", "desc": "nginx"},
        {"unit": "cron.service", "load": "loaded", "active": "active", "sub": "running", "desc": "cron"}]},
    "security": {"ok": True, "stats": {"hits_1m": 5, "hits_10m": 40, "unique_ips": 300},
                 "by_ip": [{"ip": "203.0.113.1", "count": 60, "iso": "NL", "country": "Netherlands", "last": NOW},
                           {"ip": "203.0.113.2", "count": 30, "iso": "NL", "country": "Netherlands", "last": NOW},
                           {"ip": "203.0.113.3", "count": 500, "iso": "FR", "country": "France",
                            "last": NOW - 90000},
                           {"ip": "203.0.113.4", "count": 10, "iso": "DE", "country": "Germany", "last": NOW}]},
    "firewall": {"ok": True, "traffic": {"block": 77, "allow": 3}},
    "crowdsec": {"ok": True, "decisions": [{"ip": "203.0.113.1"}, {"value": "203.0.113.2"}] + [{"ip": "x"}] * 10},
    "dns": {"ok": True, "totals": {"queries": 200, "nxdomain": 50, "hitrate": 0.5}},
    "system": {"ok": True, "tuxwall_version": "3.3.5", "uptime": 1000.0, "cpu": {"temp": 51.0},
               "usage": {"cpu_pct": 7.5, "mem_pct": 30.1, "disk_pct": 9.9},
               "wan": {"ifname": "wan0", "ipv4": "192.0.2.1", "ipv6": ["2001:db8::1", "2001:db8::2", "x"],
                       "gateway6": "fe80::1"},
               "latency": {"current_ms": 15.2, "loss_1h_pct": 0.0, "jitter_ms": 1.1, "target": "192.0.2.53"}},
    "honeypot": {"ok": True, "conf": {"enabled": True},
                 "state": {"active_count": 2, "stats": {"total": 50}, "log": ["a", "b"]}},
    "wireguard": {"ok": True, "configured": True, "interface": {"up": True},
                  "peers": [{"last_handshake": NOW - 10}, {"last_handshake": NOW - 999}]},
}

SHARED = ("attacks_per_min", "fw_blocks", "crowdsec_bans", "dns_queries", "dns_blocked_pct",
          "dns_cache_hitrate", "wan_ip", "vpn_peers_online", "honeypot_trapped", "tarpit_active",
          "top_attack_country", "internet_latency", "cpu_usage", "memory_usage", "disk_usage", "temperature",
          "wan_connectivity", "ipv6_connectivity")


def t_summary_shape():
    d = sd.normalize_summary(SUMMARY)
    check(d["mode"] == "summary" and [s["unit"] for s in d["services"]] == ["unbound.service", "nginx.service"],
          "summary: services list")
    check(d["sections"]["https"] is None, "summary: a section with ok false is missing")
    check(not sd.available(d, "certificate_expiry") and sd.value(d, "certificate_expiry") is None,
          "missing section -> entity unavailable, value None")
    want = {"attacks_per_min": 5, "fw_blocks": 77, "crowdsec_bans": 12, "dns_queries": 200,
            "dns_blocked_pct": 25.0, "dns_cache_hitrate": 50.0, "wan_ip": "192.0.2.1", "vpn_peers_online": 1,
            "honeypot_trapped": 50, "tarpit_active": 2, "canary_hits_24h": 9, "top_attack_country": "Netherlands",
            "community_reporting": "queued", "internet_latency": 15.2, "dhcp_clients": 14,
            "blocked_domains": 1000, "cpu_usage": 7.5, "memory_usage": 30.1, "disk_usage": 9.9,
            "temperature": 51.0, "last_boot": int(NOW) - 1000, "tuxwall_version": "3.3.6",
            "last_backup": int(NOW) - 7200, "tripwire": True, "wan_connectivity": True, "ipv6_connectivity": True,
            "flagged_devices": 2, "device_threat": True}
    for k, v in want.items():
        check(sd.value(d, k) == v, "summary %s = %r (%r)" % (k, v, sd.value(d, k)))
    check(set(want) | {"certificate_expiry"} == set(sd.VALUES), "every entity key covered by the test")
    check(sd.attributes(d, "crowdsec_bans") == {"ips": ["203.0.113.1", "203.0.113.2"], "stale": True},
          "stale section flagged in the attributes")
    check(sd.attributes(d, "tripwire")["level"] == "high" and sd.attributes(d, "tripwire")["reason"] == "test",
          "tripwire attributes")
    check(sd.attributes(d, "top_attack_country") == {"iso": "NL", "hits": 90, "sources": 4,
                                                     "runners_up": ["Germany"]}, "top country attributes")
    check(sd.installed_version(d) == "3.3.6" and sd.router_latest(d) == "3.3.7", "versions")
    da = sd.attributes(d, "flagged_devices")
    check(da["quarantined"] == 1 and da["worst_finding"].startswith("Connected to a known botnet")
          and da["worst_device"] == "Example laptop" and da["worst_severity"] == "critical"
          and sd.attributes(d, "device_threat") == da, "device attributes (quarantined, worst finding)")
    calm = sd.normalize_summary(dict(SUMMARY, devices=dict(SUMMARY["devices"], flagged=0, worst=None)))
    check(sd.value(calm, "device_threat") is False and sd.value(calm, "flagged_devices") == 0
          and sd.attributes(calm, "flagged_devices")["worst_finding"] is None, "no flagged device -> threat off")
    old_router = sd.normalize_summary({k: v for k, v in SUMMARY.items() if k != "devices"})
    check(not sd.available(old_router, "flagged_devices") and not sd.available(old_router, "device_threat"),
          "router without device monitoring -> unavailable")
    # unknown community state is not passed through an enum sensor
    d2 = sd.normalize_summary(dict(SUMMARY, community={"ok": True, "status": "weird"}))
    check(sd.value(d2, "community_reporting") is None, "unknown enum state -> None")
    # garbage in, no exceptions out
    for junk in (None, [], "x", {"ok": True, "security": "x", "system": {"ok": True, "cpu_pct": "high"}},
                 {"dns": {"ok": True, "queries": 0, "nxdomain": 5}}):
        d3 = sd.normalize_summary(junk)
        vals = {k: sd.value(d3, k) for k in sd.VALUES}
        attrs = {k: sd.attributes(d3, k) for k in sd.VALUES}
        check(isinstance(vals, dict) and isinstance(attrs, dict), "junk payload %r tolerated" % (junk,))
    check(sd.value(sd.normalize_summary({"dns": {"ok": True, "queries": 0, "nxdomain": 5}}),
                   "dns_blocked_pct") is None, "0 queries -> blocked % unknown")


def t_legacy_shape():
    d = sd.normalize_legacy(LEGACY, now=NOW)
    s = sd.normalize_summary(SUMMARY)
    check(d["mode"] == "legacy" and len(d["services"]) == 3, "legacy: every unit kept (CORE_SERVICES filter later)")
    for k in SHARED:
        check(sd.value(d, k) == sd.value(s, k), "legacy %s == summary (%r vs %r)" % (k, sd.value(d, k),
                                                                                    sd.value(s, k)))
    check(sd.value(d, "tuxwall_version") == "3.3.5" and sd.installed_version(d) == "3.3.5"
          and sd.router_latest(d) is None, "legacy: installed version from /api/system, latest unknown")
    check(abs(sd.value(d, "last_boot") - (NOW - 1000)) <= 30 and sd.value(d, "last_boot") % 60 == 0,
          "legacy: boot time from uptime, minute-rounded")
    for k in ("canary_hits_24h", "community_reporting", "dhcp_clients", "blocked_domains", "last_backup",
              "certificate_expiry", "tripwire", "flagged_devices", "device_threat"):
        check(not sd.available(d, k), "legacy: %s unavailable (not in the old payloads)" % k)
    check(sd.attributes(d, "crowdsec_bans")["ips"][:2] == ["203.0.113.1", "203.0.113.2"], "legacy crowdsec ips")
    check(sd.attributes(d, "wan_ip")["ipv6"] == ["2001:db8::1", "2001:db8::2"], "legacy wan ipv6 trimmed")
    # 1.1.0 crowdsec summary shape inside a legacy poll
    d2 = sd.normalize_legacy(dict(LEGACY, crowdsec={"ok": True, "active_count": 9, "recent": ["a"]}), now=NOW)
    check(sd.value(d2, "crowdsec_bans") == 9, "legacy with /api/crowdsec/summary")
    # failing endpoints: their sections missing, the rest still read
    d3 = sd.normalize_legacy({"system": LEGACY["system"]}, now=NOW)
    check(sd.available(d3, "cpu_usage") and not sd.available(d3, "fw_blocks")
          and not sd.available(d3, "crowdsec_bans") and d3["services"] == [], "legacy: partial payloads")
    d4 = sd.normalize_legacy({}, now=NOW)
    check(not any(sd.available(d4, k) for k in sd.VALUES), "legacy: nothing -> everything unavailable")
    hp_off = dict(LEGACY, honeypot={"ok": True, "conf": {"enabled": False}, "state": {"stats": {"total": 5}}})
    check(sd.value(sd.normalize_legacy(hp_off, now=NOW), "honeypot_trapped") == 0, "tarpit off -> 0")
    zero = dict(LEGACY, system=dict(LEGACY["system"], latency={"current_ms": 0.0}))
    check(sd.value(sd.normalize_legacy(zero, now=NOW), "wan_connectivity") is False, "every ping lost -> offline")


def t_device_events():
    d = sd.normalize_summary(SUMMARY)
    ev, seen = sd.device_events(d, None)
    check(ev == [] and set(seen["f"]) == {"f1", "f2"} and seen["n"] == ["m020000000003"],
          "events: first poll only records (no replay after a restart)")
    ev2, seen2 = sd.device_events(d, seen)
    check(ev2 == [] and seen2 == seen, "events: same payload -> nothing fired")
    nxt = dict(SUMMARY, devices=dict(SUMMARY["devices"], findings=[
        {"id": "f3", "severity": "high", "reason": "r3", "device": "m020000000002", "device_name": "Example tv",
         "first": int(NOW), "last": int(NOW)}] + SUMMARY["devices"]["findings"], new_devices=[
        {"id": "m020000000004", "name": "Example cam", "zone": "LAN", "vendor": "Example", "first_seen": int(NOW)}]
        + SUMMARY["devices"]["new_devices"]))
    ev3, seen3 = sd.device_events(sd.normalize_summary(nxt), seen2)
    check([e[0] for e in ev3] == ["tuxwall_device_finding", "tuxwall_new_device"]
          and ev3[0][1] == {"id": "f3", "severity": "high", "reason": "r3", "device_id": "m020000000002",
                            "device": "Example tv", "first": int(NOW), "last": int(NOW)}
          and ev3[1][1]["device"] == "Example cam" and ev3[1][1]["zone"] == "LAN", "events: one per new id (%r)" % ev3)
    ev4, _s = sd.device_events(sd.normalize_summary(nxt), seen3)
    check(ev4 == [], "events: deduped by id")
    old = sd.normalize_summary({k: v for k, v in SUMMARY.items() if k != "devices"})
    check(sd.device_events(old, None) == ([], {}), "events: router without the section -> none")
    big = {"f": ["x%d" % i for i in range(600)], "n": []}
    _e, s5 = sd.device_events(d, big)
    check(len(s5["f"]) == sd.SEEN_MAX, "events: seen list bounded")
    coord = open(os.path.join(HA_DIR, "coordinator.py")).read()
    const = ha_module("const")
    check("device_events(data, self._device_seen)" in coord and const.EVENT_DEVICE_FINDING == "tuxwall_device_finding"
          and const.EVENT_NEW_DEVICE == "tuxwall_new_device", "coordinator fires the device events")


def t_packages():
    text = ("Package: tuxwall\nVersion: 3.3.6\nArchitecture: all\nDescription: x\n continued\n\n"
            "Package: tuxwall-doc\nVersion: 9.0\n\n"
            "Package: tuxwall\nVersion: 3.3.10\n\nPackage: tuxwall\nVersion: 3.3.9\n")
    check(sd.packages_latest(text) == "3.3.10", "Packages index: newest tuxwall (numeric compare)")
    check(sd.packages_latest("") is None and sd.packages_latest("Package: other\nVersion: 1\n") is None,
          "Packages index without tuxwall -> None")


def t_metadata():
    files = sorted(f for f in os.listdir(HA_DIR) if f.endswith(".py"))
    with tempfile.TemporaryDirectory() as tmp:
        for f in files:
            try:
                py_compile.compile(os.path.join(HA_DIR, f), cfile=os.path.join(tmp, f + "c"), doraise=True)
                ok = True
            except py_compile.PyCompileError as exc:
                print(exc)
                ok = False
            check(ok, "compiles: %s" % f)
    man = json.load(open(os.path.join(HA_DIR, "manifest.json")))
    allowed = {"domain", "name", "codeowners", "config_flow", "dependencies", "after_dependencies",
               "documentation", "integration_type", "iot_class", "issue_tracker", "loggers", "requirements",
               "version", "quality_scale", "single_config_entry"}
    check(set(man) <= allowed, "manifest keys known (%s)" % sorted(set(man) - allowed))
    check(man["domain"] == "tuxwall" and man["version"] == "1.3.0" and man["iot_class"] == "local_polling"
          and re.fullmatch(r"\d+\.\d+\.\d+", man["version"]), "manifest domain/version/iot_class")
    for name, size in (("icon.png", 256), ("icon@2x.png", 512)):
        path = os.path.join(HA_DIR, "brand", name)
        try:
            with open(path, "rb") as f:
                head = f.read(26)
            w, h = int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")
            ok = head[:8] == b"\x89PNG\r\n\x1a\n" and (w, h) == (size, size) and head[25] == 6
        except OSError:
            ok = False
        check(ok, "brand/%s is a %dx%d RGBA PNG" % (name, size, size))
    strings = json.load(open(os.path.join(HA_DIR, "strings.json")))
    en = json.load(open(os.path.join(HA_DIR, "translations", "en.json")))
    check(strings == en, "strings.json == translations/en.json")
    icons = json.load(open(os.path.join(HA_DIR, "icons.json")))
    for platform in ("sensor", "binary_sensor"):
        src = open(os.path.join(HA_DIR, platform + ".py")).read()
        keys = re.findall(r'translation_key="([a-z0-9_]+)"', src)
        check(keys, "%s: translated entities found" % platform)
        for k in keys:
            check(k in strings["entity"][platform] and strings["entity"][platform][k].get("name"),
                  "%s.%s has a translated name" % (platform, k))
            check(k in sd.VALUES, "%s.%s has a value function" % (platform, k))
            if not (platform == "sensor" and k == "temperature"):     # device class icon
                check(k in icons["entity"][platform], "%s.%s has an icon" % (platform, k))
        check(set(strings["entity"][platform]) == set(keys), "%s: no stale translations" % platform)
    states = strings["entity"]["sensor"]["community_reporting"]["state"]
    check(set(states) == set(sd.COMMUNITY_STATES), "community_reporting enum states translated")
    # 1.0 entities: keys and names unchanged (unique_id = <entry>_<key>)
    tree = ast.parse(open(os.path.join(HA_DIR, "sensor.py")).read())
    old = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "SensorEntityDescription":
            kw = {k.arg: getattr(k.value, "value", None) for k in node.keywords}
            if kw.get("name"):
                old[kw["key"]] = kw["name"]
    check(old == {"attacks_per_min": "Attacks per minute", "fw_blocks": "Firewall blocks",
                  "crowdsec_bans": "CrowdSec active bans", "dns_queries": "DNS queries (since restart)",
                  "dns_blocked_pct": "DNS blocked", "dns_cache_hitrate": "DNS cache hit rate", "wan_ip": "WAN IP",
                  "vpn_peers_online": "VPN peers online", "honeypot_trapped": "Tarpit trapped connections"},
          "1.0 sensor keys/names unchanged (%r)" % old)
    bsrc = open(os.path.join(HA_DIR, "binary_sensor.py")).read()
    check('f"{entry.entry_id}_svc_{unit.replace(\'@\', \'_\')}"' in bsrc
          and 'f"{entry.entry_id}_core_healthy"' in bsrc and '"TuxWall core services healthy"' in bsrc,
          "service binary sensor unique_ids/names unchanged")
    coord = open(os.path.join(HA_DIR, "coordinator.py")).read()
    check("INTEGRATION_SUMMARY_PATH" in coord and "TuxwallNotFound" in coord and "_legacy" in coord,
          "coordinator: summary with a 404 fallback to the per-page endpoints")
    const = ha_module("const")
    check(const.INTEGRATION_SUMMARY_PATH == "/api/integration/summary" and const.APT_CHECK_SECONDS >= 6 * 3600,
          "summary path; apt index fetched at most every 6 h")
    for f in files:
        src = open(os.path.join(HA_DIR, f)).read()
        check(not re.search(r"\b(requests|urllib\.request|time\.sleep)\b", src),
              "%s: no blocking I/O helpers" % f)


for t in (t_summary_shape, t_legacy_shape, t_device_events, t_packages, t_metadata):
    try:
        t()
    except Exception as exc:
        import traceback
        traceback.print_exc()
        check(False, "%s raised %r" % (t.__name__, exc))

print("ha_integration_check: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
