"""Turn TuxWall API payloads into the integration's data (no Home Assistant
imports, so tools/ha_integration_check.py can run it without HA).

TuxWall after 3.3.6 answers GET /api/integration/summary: one compact payload
(a few KB) with a section per source, each flagged ``ok`` / ``stale``.
Older routers answer 404 there; the coordinator then polls the per-page
endpoints as 1.1.0 did (``legacy_parts``) and normalize_legacy() maps what
they carry onto the same sections. A section that is missing (older router,
or the source failed) is None and its entities read as unavailable.

normalize_*() return::

    {"mode": "summary" | "legacy",
     "services": [{"unit", "active", "sub", "desc"}, ...],
     "sections": {name: dict | None, ...}}
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from .crowdsec_data import crowdsec_active_count, crowdsec_ips

SECTIONS = (
    "services", "security", "firewall", "crowdsec", "dns", "blocklist", "system",
    "wan", "tarpit", "canary", "tripwire", "community", "wireguard", "dhcp",
    "backup", "https", "update", "devices",
)
PEER_ONLINE_SECONDS = 180
COMMUNITY_STATES = ["ok", "queued", "error", "off"]


def _d(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def _num(x: Any) -> float | int | None:
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def _top_country(rows: Any) -> list[dict]:
    return [r for r in (rows if isinstance(rows, list) else []) if isinstance(r, dict) and r.get("iso")]


def normalize_summary(payload: Any) -> dict[str, Any]:
    p = _d(payload)
    sections: dict[str, Any] = {}
    for name in SECTIONS:
        sec = p.get(name)
        sections[name] = dict(sec) if isinstance(sec, dict) and sec.get("ok") else None
    if sections["system"] is not None and p.get("tuxwall_version"):
        sections["system"].setdefault("version", p.get("tuxwall_version"))
    services = (sections["services"] or {}).get("units")
    return {
        "mode": "summary",
        "services": [s for s in services if isinstance(s, dict)] if isinstance(services, list) else [],
        "sections": sections,
    }


def legacy_top_countries(by_ip: Any, now: float, window: float = 86400) -> list[dict]:
    """Top countries from /api/security's by_ip (top 50 sources only)."""
    agg: dict[str, dict] = {}
    for e in by_ip if isinstance(by_ip, list) else []:
        if not isinstance(e, dict) or not e.get("iso") or e.get("iso") == "??":
            continue
        if (_num(e.get("last")) or 0) < now - window:
            continue
        a = agg.setdefault(e["iso"], {"iso": e["iso"], "name": e.get("country") or e["iso"],
                                      "hits": 0, "sources": 0})
        a["hits"] += int(_num(e.get("count")) or 0)
        a["sources"] += 1
    return sorted(agg.values(), key=lambda a: (-a["hits"], a["iso"]))[:3]


def normalize_legacy(parts: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """parts: the per-endpoint payloads 1.1.0 fetched ({} where a call
    failed): services, security, firewall, crowdsec, dns, system, honeypot,
    wireguard."""
    now = time.time() if now is None else now
    sections: dict[str, Any] = {name: None for name in SECTIONS}

    services = _d(parts.get("services")).get("services")
    services = [s for s in services if isinstance(s, dict)] if isinstance(services, list) else []
    if services:
        sections["services"] = {"units": services, "stale": False}

    sec = _d(parts.get("security"))
    if sec.get("stats"):
        st = _d(sec.get("stats"))
        sections["security"] = {
            "hits_1m": st.get("hits_1m"), "hits_10m": st.get("hits_10m"),
            "unique_ips": st.get("unique_ips"),
            "top_countries_24h": legacy_top_countries(sec.get("by_ip"), now),
        }

    traffic = _d(_d(parts.get("firewall")).get("traffic"))
    if "block" in traffic:
        sections["firewall"] = {"block": traffic.get("block")}

    cs = parts.get("crowdsec")
    if isinstance(cs, dict) and cs and cs.get("ok", True):
        sections["crowdsec"] = {"active_count": crowdsec_active_count(cs), "recent": crowdsec_ips(cs)}

    dns = _d(parts.get("dns"))
    if dns.get("ok") and isinstance(dns.get("totals"), dict):
        t = dns["totals"]
        sections["dns"] = {"queries": t.get("queries"), "nxdomain": t.get("nxdomain"),
                           "hitrate": t.get("hitrate")}

    system = _d(parts.get("system"))
    if system.get("ok"):
        usage = _d(system.get("usage"))
        uptime = _num(system.get("uptime"))
        sections["system"] = {
            "cpu_pct": usage.get("cpu_pct"), "mem_pct": usage.get("mem_pct"),
            "disk_pct": usage.get("disk_pct"), "temp_c": _d(system.get("cpu")).get("temp"),
            "uptime": uptime,
            # rounded to the minute: uptime is read a moment after boot time
            "boot_time": int(round((now - uptime) / 60.0) * 60) if uptime else None,
            "version": system.get("tuxwall_version") or None,
            "hostname": system.get("hostname"),
        }
        wan = _d(system.get("wan"))
        lat = _d(system.get("latency"))
        cur = _num(lat.get("current_ms"))
        sections["wan"] = {
            "ifname": wan.get("ifname"), "state": wan.get("state"), "ipv4": wan.get("ipv4"),
            "ipv6": (wan.get("ipv6") or [])[:2] if isinstance(wan.get("ipv6"), list) else [],
            # the latency monitor's newest batch: 0 ms = every ping lost
            "online": (cur > 0) if cur is not None else None,
            "ipv6_ready": bool(wan.get("ipv6")) and bool(wan.get("gateway6")),
            "latency_ms": cur if cur else None,
            "loss_pct": lat.get("loss_1h_pct"), "jitter_ms": lat.get("jitter_ms"),
            "target": lat.get("target"),
        }
        if system.get("tuxwall_version"):
            sections["update"] = {"installed": system.get("tuxwall_version"), "latest": None}

    hp = _d(parts.get("honeypot"))
    if hp.get("ok"):
        conf, st = _d(hp.get("conf")), _d(hp.get("state"))
        stats = _d(st.get("stats"))
        sections["tarpit"] = {
            "enabled": bool(conf.get("enabled")), "listening": bool(st.get("listening")),
            "active": int(_num(st.get("active_count")) or 0), "total": int(_num(stats.get("total")) or 0),
            "sources_24h": st.get("sources_24h"),
            "log": [str(x) for x in (st.get("log") or [])[-5:]] if isinstance(st.get("log"), list) else [],
        }

    wg = _d(parts.get("wireguard"))
    peers = wg.get("peers")
    if isinstance(peers, list):
        sections["wireguard"] = {
            "configured": bool(wg.get("configured")), "up": bool(_d(wg.get("interface")).get("up")),
            "peers": len(peers),
            "online": sum(1 for p in peers if isinstance(p, dict)
                          and (_num(p.get("last_handshake")) or 0) > now - PEER_ONLINE_SECONDS),
        }

    return {"mode": "legacy", "services": services, "sections": sections}


# ── entity values ───────────────────────────────────────────────────────────
# key -> (section, value(section dict), attributes(section dict) or None).
# A value function may return None (unknown); the entity is unavailable only
# when the whole section is missing.

def _pct(n: Any, d: Any) -> float | None:
    if not _num(d):
        return None
    return round(100.0 * (_num(n) or 0) / d, 1)


def _top(s: dict) -> dict:
    rows = _top_country(s.get("top_countries_24h"))
    return rows[0] if rows else {}


def _community_status(s: dict) -> str | None:
    v = s.get("status")
    return v if v in COMMUNITY_STATES else None


def _cert_expiry(s: dict) -> Any:
    return s.get("expires")


def _worst(s: dict) -> dict | None:
    w = s.get("worst")
    if not isinstance(w, dict):
        return None
    return {"severity": w.get("severity"), "reason": w.get("reason"), "device": w.get("device_name"),
            "last": w.get("last")}


def _device_attrs(s: dict) -> dict:
    w = _worst(s) or {}
    return {"quarantined": s.get("quarantined"), "critical": s.get("critical"), "warning": s.get("warning"),
            "devices": s.get("devices"), "online": s.get("online"), "new_24h": s.get("new_24h"),
            "worst_severity": w.get("severity"), "worst_finding": w.get("reason"), "worst_device": w.get("device"),
            "worst_last": w.get("last")}


VALUES: dict[str, tuple[str, Callable[[dict], Any], Callable[[dict], dict] | None]] = {
    # 1.0 sensors (unique_ids/names unchanged)
    "attacks_per_min": ("security", lambda s: s.get("hits_1m"),
                        lambda s: {"unique_ips": s.get("unique_ips"), "hits_10m": s.get("hits_10m")}),
    "fw_blocks": ("firewall", lambda s: s.get("block"), None),
    "crowdsec_bans": ("crowdsec", lambda s: crowdsec_active_count(s),
                      lambda s: {"ips": crowdsec_ips(s)}),
    "dns_queries": ("dns", lambda s: s.get("queries"), None),
    "dns_blocked_pct": ("dns", lambda s: _pct(s.get("nxdomain"), s.get("queries")), None),
    "dns_cache_hitrate": ("dns", lambda s: round(100.0 * s["hitrate"], 1)
                          if _num(s.get("hitrate")) is not None else None, None),
    "wan_ip": ("wan", lambda s: s.get("ipv4") or None,
               lambda s: {"ifname": s.get("ifname"), "ipv6": (s.get("ipv6") or [])[:2]}),
    "vpn_peers_online": ("wireguard", lambda s: s.get("online"),
                         lambda s: {"peers": s.get("peers"), "interface_up": s.get("up")}),
    "honeypot_trapped": ("tarpit", lambda s: s.get("total") if s.get("enabled") else 0,
                         lambda s: {"enabled": s.get("enabled"), "listening": s.get("listening"),
                                    "sources_24h": s.get("sources_24h")}),
    # 1.2 sensors
    "tarpit_active": ("tarpit", lambda s: s.get("active") if s.get("enabled") else 0, None),
    "canary_hits_24h": ("canary", lambda s: s.get("events_24h"),
                        lambda s: {"sources_24h": s.get("sources_24h"), "credentials_24h": s.get("creds_24h"),
                                   "bans_active": s.get("bans_active"), "service_active": s.get("active")}),
    "top_attack_country": ("security", lambda s: _top(s).get("name"),
                           lambda s: {"iso": _top(s).get("iso"), "hits": _top(s).get("hits"),
                                      "sources": _top(s).get("sources"),
                                      "runners_up": [r.get("name") for r in
                                                     _top_country(s.get("top_countries_24h"))[1:]]}),
    "community_reporting": ("community", _community_status,
                            lambda s: {"last_delivery": s.get("last_report"), "last_error_at": s.get("last_error_at"),
                                       "queued": s.get("queue"), "sent_24h": s.get("sent_24h"),
                                       "paused": s.get("paused")}),
    "internet_latency": ("wan", lambda s: s.get("latency_ms"),
                         lambda s: {"packet_loss_pct": s.get("loss_pct"), "jitter_ms": s.get("jitter_ms"),
                                    "target": s.get("target")}),
    "dhcp_clients": ("dhcp", lambda s: s.get("leases"),
                     lambda s: {"online": s.get("online"), "reserved": s.get("reserved")}),
    "blocked_domains": ("blocklist", lambda s: s.get("domains"),
                        lambda s: {"updated_at": s.get("updated_at")}),
    "cpu_usage": ("system", lambda s: s.get("cpu_pct"), None),
    "memory_usage": ("system", lambda s: s.get("mem_pct"), None),
    "disk_usage": ("system", lambda s: s.get("disk_pct"), None),
    "temperature": ("system", lambda s: s.get("temp_c"), None),
    "last_boot": ("system", lambda s: s.get("boot_time"), None),
    "tuxwall_version": ("system", lambda s: s.get("version"), None),
    "last_backup": ("backup", lambda s: s.get("last_success"),
                    lambda s: {"last_failure": s.get("last_failure"), "failed": s.get("failed"),
                               "stale_days": s.get("stale_days")}),
    "certificate_expiry": ("https", _cert_expiry,
                           lambda s: {"days_left": s.get("days_left"), "source": s.get("source"),
                                      "mode": s.get("mode")}),
    # binary sensors
    "tripwire": ("tripwire", lambda s: bool(s.get("tripped")),
                 lambda s: {"level": s.get("level"), "reason": s.get("reason"), "since": s.get("since"),
                            "mode": s.get("mode"), "phase": s.get("phase"), "trips": s.get("trips")}),
    "wan_connectivity": ("wan", lambda s: s.get("online"),
                         lambda s: {"interface": s.get("ifname"), "checked_at": s.get("sample_at")}),
    "ipv6_connectivity": ("wan", lambda s: s.get("ipv6_ready"),
                          lambda s: {"basis": "global WAN address + IPv6 default route"}),
    # 1.3: device monitoring (TuxWall 3.3.7+; older routers: unavailable)
    "flagged_devices": ("devices", lambda s: s.get("flagged"), _device_attrs),
    "device_threat": ("devices", lambda s: (_num(s.get("flagged")) or 0) > 0 if _num(s.get("flagged")) is not None
                      else None, _device_attrs),
}

# attributes holding epoch seconds (shown as ISO 8601)
TIMESTAMP_ATTRS = {"last_delivery", "last_error_at", "updated_at", "last_failure", "since", "checked_at",
                   "worst_last"}


def section(data: Any, name: str) -> dict | None:
    sec = _d(_d(data).get("sections")).get(name)
    return sec if isinstance(sec, dict) else None


def value(data: Any, key: str) -> Any:
    name, fn, _attrs = VALUES[key]
    sec = section(data, name)
    if sec is None:
        return None
    try:
        return fn(sec)
    except (TypeError, ValueError, KeyError, AttributeError):
        return None


def attributes(data: Any, key: str) -> dict[str, Any]:
    name, _fn, fn = VALUES[key]
    sec = section(data, name)
    if sec is None or fn is None:
        return {}
    try:
        out = dict(fn(sec))
    except (TypeError, ValueError, KeyError, AttributeError):
        return {}
    if sec.get("stale"):
        out["stale"] = True
    return out


def available(data: Any, key: str) -> bool:
    return section(data, VALUES[key][0]) is not None


# ── TuxWall version / apt index ─────────────────────────────────────────────

def version_key(v: Any) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or "")))


def packages_latest(text: str, package: str = "tuxwall") -> str | None:
    """Newest Version of package in an apt Packages index."""
    best = None
    for stanza in (text or "").split("\n\n"):
        fields = dict(re.findall(r"^([A-Za-z-]+):[ \t]*(.*)$", stanza, re.M))
        if fields.get("Package") != package or not fields.get("Version"):
            continue
        v = fields["Version"].strip()
        if best is None or version_key(v) > version_key(best):
            best = v
    return best


def installed_version(data: Any) -> str | None:
    upd = section(data, "update") or {}
    sysv = (section(data, "system") or {}).get("version")
    return upd.get("installed") or sysv or None


def router_latest(data: Any) -> str | None:
    return (section(data, "update") or {}).get("latest") or None


# ── device events (1.3) ─────────────────────────────────────────────────────
# The router lists its newest active findings and new devices (the "devices"
# section, at most 10 each, generic reasons only). The coordinator fires one
# event per id it has not seen before; the first poll after a start only
# records what is there (no replay after a Home Assistant restart).
SEEN_MAX = 500


def device_events(data: Any, seen: dict | None) -> tuple[list[tuple[str, dict]], dict]:
    """-> ([(event type, payload), ...], new seen state)."""
    sec = section(data, "devices")
    if sec is None:
        return [], seen or {}
    findings = [f for f in (sec.get("findings") or []) if isinstance(f, dict) and f.get("id")]
    new = [d for d in (sec.get("new_devices") or []) if isinstance(d, dict) and d.get("id")]
    first = seen is None
    seen = {"f": list((seen or {}).get("f") or []), "n": list((seen or {}).get("n") or [])}
    events: list[tuple[str, dict]] = []
    for f in reversed(findings):
        if f["id"] in seen["f"]:
            continue
        seen["f"].append(f["id"])
        if not first:
            events.append(("tuxwall_device_finding", {
                "id": f["id"], "severity": f.get("severity"), "reason": f.get("reason"),
                "device_id": f.get("device"), "device": f.get("device_name"),
                "first": f.get("first"), "last": f.get("last")}))
    for d in reversed(new):
        if d["id"] in seen["n"]:
            continue
        seen["n"].append(d["id"])
        if not first:
            events.append(("tuxwall_new_device", {
                "device_id": d["id"], "device": d.get("name"), "zone": d.get("zone"), "vendor": d.get("vendor"),
                "first_seen": d.get("first_seen")}))
    seen["f"], seen["n"] = seen["f"][-SEEN_MAX:], seen["n"][-SEEN_MAX:]
    return events, seen
