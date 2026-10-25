"""Read-only UniFi Network plugin for TuxWall.

Supports:
  - classic self-hosted controller: /api/login + /api/s/<site>/...
  - UniFi OS: /api/auth/login + /proxy/network/api/s/<site>/...
  - UniFi OS API key: X-API-KEY + /proxy/network/api/s/<site>/...
"""
import http.cookiejar
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


def _cfg(req):
    cfg = req.get("config") or {}
    return {
        "url": str(cfg.get("url") or "").strip().rstrip("/"),
        "mode": str(cfg.get("auth_mode") or "local").strip(),
        "controller": str(cfg.get("controller_type") or "classic").strip(),
        "username": str(cfg.get("username") or "").strip(),
        "password": str(cfg.get("password") or ""),
        "key": str(cfg.get("api_key") or "").strip(),
        "site": str(cfg.get("site") or "default").strip() or "default",
        "verify": bool(cfg.get("verify_tls", True)),
    }


def _context(cfg):
    ctx = ssl.create_default_context()
    if not cfg["verify"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _login(cfg):
    """Build an urllib opener and return (opener, headers)."""
    if not cfg["url"]:
        raise RuntimeError("Controller URL is not configured")
    ctx = _context(cfg)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )
    headers = {
        "Accept": "application/json",
        "User-Agent": "tuxwall-unifi-plugin/0.1",
    }
    if cfg["mode"] == "api_key":
        if not cfg["key"]:
            raise RuntimeError("UniFi API key is not configured")
        headers["X-API-KEY"] = cfg["key"]
        return opener, headers
    if not cfg["username"] or not cfg["password"]:
        raise RuntimeError("UniFi username and password are not configured")
    login_path = "/api/auth/login" if cfg["controller"] == "unifi_os" else "/api/login"
    payload = json.dumps({
        "username": cfg["username"],
        "password": cfg["password"],
        "remember": True,
    }).encode("utf-8")
    login_req = urllib.request.Request(
        cfg["url"] + login_path,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": "tuxwall-unifi-plugin/0.1"},
        method="POST",
    )
    with opener.open(login_req, timeout=15) as resp:
        resp.read()
    csrf = ""
    for cookie in jar:
        if cookie.name == "csrf_token":
            csrf = cookie.value
            break
    if csrf:
        headers["X-CSRF-Token"] = csrf
    return opener, headers


def _api_prefix(cfg):
    if cfg["mode"] == "local" and cfg["controller"] == "classic":
        return "/api"
    return "/proxy/network/api"


def _get(cfg, opener, headers, path):
    req = urllib.request.Request(cfg["url"] + path, headers=headers, method="GET")
    with opener.open(req, timeout=15) as resp:
        body = resp.read().decode("utf-8", "replace")
    try:
        data = json.loads(body)
    except ValueError:
        raise RuntimeError("Controller returned non-JSON data")
    return data.get("data") if isinstance(data, dict) else data


def _post(cfg, opener, headers, path, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        cfg["url"] + path,
        data=body,
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    with opener.open(req, timeout=15) as resp:
        raw = resp.read().decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except ValueError:
        raise RuntimeError("Controller returned non-JSON data")
    return data.get("data") if isinstance(data, dict) else data


def _uptime(seconds):
    try:
        s = int(seconds or 0)
    except (TypeError, ValueError):
        return "—"
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"



def _session_duration(seconds):
    try:
        s = int(seconds or 0)
    except (TypeError, ValueError):
        return "—"
    if s >= 3600:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{max(0, s) // 60}m"


def _events(cfg, limit=100):
    """Build a WiFi activity timeline from controller session history.

    Current Network Application versions no longer expose /stat/event, but
    the client-session history endpoint still contains association periods.
    We derive connect/disconnect/roam events from consecutive sessions.
    """
    opener, headers = _login(cfg)
    site = urllib.parse.quote(cfg["site"], safe="")
    base = _api_prefix(cfg) + f"/s/{site}/stat"
    now = int(time.time())
    window = 7 * 86400
    sessions = _post(cfg, opener, headers, base + "/session", {
        "type": "all", "start": now - window, "end": now,
    }) or []
    devices = _get(cfg, opener, headers, base + "/device") or []
    ap_names = {}
    for d in devices:
        if isinstance(d, dict) and d.get("mac"):
            ap_names[d["mac"]] = d.get("name") or d.get("hostname") or d["mac"]

    by_mac = {}
    for s in sessions:
        if not isinstance(s, dict) or s.get("is_wired"):
            continue
        mac = s.get("mac") or ""
        start = int(s.get("assoc_time") or 0)
        duration = int(s.get("duration") or 0)
        if not start or duration <= 0:
            continue
        ap_mac = s.get("ap_mac") or ""
        by_mac.setdefault(mac, []).append({
            "mac": mac,
            "client": s.get("hostname") or s.get("name") or mac,
            "hostname": s.get("hostname") or "",
            "ip": s.get("ip") or "",
            "ap": ap_names.get(ap_mac, ap_mac),
            "ap_mac": ap_mac,
            "start": start,
            "end": start + duration,
            "duration": duration,
            "satisfaction": s.get("satisfaction"),
        })

    out = []
    for mac, rows in by_mac.items():
        rows.sort(key=lambda r: r["start"])
        for idx, row in enumerate(rows):
            prev = rows[idx - 1] if idx > 0 else None
            nxt = rows[idx + 1] if idx + 1 < len(rows) else None
            prev_roam = bool(prev and prev["ap_mac"] != row["ap_mac"] and
                             row["start"] - prev["end"] <= 300)
            next_roam = bool(nxt and nxt["ap_mac"] != row["ap_mac"] and
                             nxt["start"] - row["end"] <= 300)
            common = {
                "client": row["client"],
                "hostname": row["hostname"] if row["hostname"] != row["client"] else "",
                "mac": row["mac"],
                "ap": row["ap"],
                "wired": False,
            }
            if not prev_roam:
                out.append({
                    **common, "time": row["start"],
                    "title": "Client connected", "severity": "info",
                    "message": "",
                })
            if not next_roam and row["end"] < now - 60:
                out.append({
                    **common, "time": row["end"],
                    "title": "Client disconnected", "severity": "warning",
                    "message": "Session lasted " + _session_duration(row["duration"]),
                })
            if next_roam:
                out.append({
                    **common, "time": nxt["start"],
                    "title": "Client roamed", "severity": "info",
                    "ap": nxt["ap"], "from_ap": row["ap"],
                    "message": f"{row['ap']} → {nxt['ap']}",
                })

    out.sort(key=lambda e: e["time"], reverse=True)
    try:
        limit = max(1, min(int(limit), 300))
    except (TypeError, ValueError):
        limit = 100
    return {"ok": True, "events": out[:limit], "source": "session-history",
            "window_days": 7, "controller": cfg["url"], "site": cfg["site"]}


def _mbps(value):
    try:
        if value is None:
            return None
        return round(float(value) / 1000.0, 1)
    except (TypeError, ValueError):
        return value



def _incidents(cfg):
    if not cfg["url"]:
        return {"ok": True, "incidents": []}
    if cfg["mode"] == "api_key" and not cfg["key"]:
        return {"ok": True, "incidents": []}
    if cfg["mode"] == "local" and (not cfg["username"] or not cfg["password"]):
        return {"ok": True, "incidents": []}
    data = _overview(cfg)
    incidents = []
    for ap in data.get("aps") or []:
        if ap.get("state") != 1:
            incidents.append({
                "key": "ap-offline:" + (ap.get("mac") or ap.get("name") or "unknown"),
                "severity": "warning",
                "title": "Access point offline: " + (ap.get("name") or "UniFi AP"),
                "detail": "Model %s · IP %s" % (ap.get("model") or "unknown", ap.get("ip") or "unknown"),
            })
        for radio in ap.get("radios") or []:
            try:
                util = float(radio.get("utilization"))
            except (TypeError, ValueError):
                continue
            if util >= 85:
                incidents.append({
                    "key": "ap-util:%s:%s" % (ap.get("mac") or ap.get("name"), radio.get("name") or radio.get("radio")),
                    "severity": "warning",
                    "title": "High channel utilization on %s" % (ap.get("name") or "AP"),
                    "detail": "%s radio is %.0f%% utilized." % (radio.get("radio") or radio.get("name") or "radio", util),
                })
    weak = []
    for c in data.get("clients") or []:
        if c.get("wired"):
            continue
        try:
            sig = float(c.get("signal"))
        except (TypeError, ValueError):
            continue
        if sig <= -75:
            weak.append(c.get("name") or c.get("mac") or "client")
    if weak:
        incidents.append({
            "key": "weak-wifi-clients",
            "severity": "warning",
            "title": "%d WiFi client%s with weak signal" % (len(weak), "" if len(weak) == 1 else "s"),
            "detail": "Signal ≤ -75 dBm: " + ", ".join(weak[:8]) + ("…" if len(weak) > 8 else ""),
        })
    try:
        conn = _connectivity(cfg, 12)
    except Exception:
        conn = {}
    if conn.get("available"):
        attempts = conn.get("attempts") or {}
        try:
            total = int(attempts.get("total") or 0)
        except (TypeError, ValueError):
            total = 0
        if total >= 3:
            success = float(attempts.get("success") or 0)
            stages = [
                ("Association", float(attempts.get("association") or 0)),
                ("Authentication", float(attempts.get("authentication") or 0)),
                ("DHCP", float(attempts.get("dhcp") or 0)),
                ("DNS", float(attempts.get("dns") or 0)),
            ]
            low = sorted([(name, value) for name, value in stages if value < 85],
                         key=lambda item: item[1])
            if success < 90 or low:
                failed = int(attempts.get("failed") or 0)
                stage_text = " · ".join("%s %.0f%%" % (name, value) for name, value in stages)
                detail = "Last 12h · %d connection attempt%s · %d failed · %s." % (
                    total, "" if total == 1 else "s", failed, stage_text)
                if low:
                    detail += " Lowest stage: %s at %.0f%%." % (low[0][0], low[0][1])
                failures = conn.get("failures") or {}
                ranked = sorted(((str(k), int(v)) for k, v in failures.items()
                                 if k != "other" and v), key=lambda item: -item[1])
                if ranked:
                    detail += " Most failures: %s (%d)." % (ranked[0][0], ranked[0][1])
                incidents.append({
                    "key": "wifi-connectivity",
                    "severity": "warning",
                    "title": "WiFi connectivity at %.0f%% success" % success,
                    "detail": detail,
                })
    return {"ok": True, "incidents": incidents}


def _overview(cfg):
    opener, headers = _login(cfg)
    site = urllib.parse.quote(cfg["site"], safe="")
    site_base = _api_prefix(cfg) + f"/s/{site}"
    base = site_base + "/stat"
    devices = _get(cfg, opener, headers, base + "/device") or []
    clients = _get(cfg, opener, headers, base + "/sta") or []
    try:
        wlans = _get(cfg, opener, headers, site_base + "/rest/wlanconf") or []
    except Exception:
        wlans = []
    wlan_names = {
        w.get("_id"): w.get("name") or ""
        for w in wlans if isinstance(w, dict) and w.get("_id")
    }
    aps = []
    for d in devices:
        if not isinstance(d, dict) or d.get("type") != "uap":
            continue
        radios = []
        stats = {}
        for r in (d.get("radio_table_stats") or []):
            if isinstance(r, dict):
                stats[r.get("name") or r.get("radio")] = r
        for r in (d.get("radio_table") or []):
            if not isinstance(r, dict):
                continue
            key = r.get("name") or r.get("radio") or ""
            st = stats.get(key) or {}
            radios.append({
                "name": key,
                "radio": r.get("radio") or st.get("radio") or "",
                "channel": st.get("channel") or r.get("channel"),
                "width": r.get("ht") or st.get("ht"),
                "tx_power": r.get("tx_power") or st.get("tx_power"),
                "clients": st.get("num_sta"),
                "utilization": st.get("cu_total"),
                "retries": st.get("tx_retries"),
                "tx_packets": st.get("tx_packets"),
            })
        vaps = []
        for v in (d.get("vap_table") or []):
            if not isinstance(v, dict):
                continue
            vaps.append({
                "ssid": wlan_names.get(v.get("wlanconf_id"), v.get("ssid") or ""),
                "radio": v.get("radio") or "",
                "wlanconf_id": v.get("wlanconf_id") or "",
                "clients": v.get("num_sta"),
                "up": v.get("up"),
                "bssid": v.get("bssid") or "",
            })
        uplink = d.get("uplink") if isinstance(d.get("uplink"), dict) else {}
        sys_stats = d.get("system-stats") if isinstance(d.get("system-stats"), dict) else {}
        temps = []
        for t in (d.get("temperatures") or []):
            if isinstance(t, dict):
                temps.append({"name": t.get("name") or "", "temp": t.get("temp")})
        aps.append({
            "name": d.get("name") or d.get("hostname") or d.get("mac") or "AP",
            "model": d.get("model") or "",
            "ip": d.get("ip") or "",
            "mac": d.get("mac") or "",
            "serial": d.get("serial") or "",
            "adopted": d.get("adopted"),
            "state": int(d.get("state") or 0),
            "uptime": _uptime(d.get("uptime")),
            "clients": int(d.get("num_sta") or 0),
            "tx_bytes": int(d.get("tx_bytes") or 0),
            "rx_bytes": int(d.get("rx_bytes") or 0),
            "version": d.get("version") or "",
            "radios": radios,
            "vaps": vaps,
            "uplink": {
                "type": uplink.get("type") or "",
                "mac": uplink.get("uplink_mac") or uplink.get("mac") or "",
                "port": uplink.get("port_idx") or uplink.get("port") or "",
                "speed": uplink.get("speed") or "",
                "full_duplex": uplink.get("full_duplex"),
                "up": uplink.get("up"),
            },
            "cpu": sys_stats.get("cpu"),
            "mem": sys_stats.get("mem"),
            "temperatures": temps,
        })
    ap_names = {a["mac"]: a["name"] for a in aps}
    out_clients = []
    for c in clients:
        if not isinstance(c, dict):
            continue
        ap_mac = c.get("ap_mac") or ""
        out_clients.append({
            "name": c.get("name") or c.get("hostname") or c.get("mac") or "client",
            "hostname": c.get("hostname") or "",
            "ip": c.get("ip") or "",
            "mac": c.get("mac") or "",
            "ssid": c.get("essid") or "",
            "ap": ap_names.get(ap_mac, ap_mac),
            "ap_mac": ap_mac,
            "signal": c.get("signal"),
            "noise": c.get("noise"),
            "rx_rate": _mbps(c.get("rx_rate")),
            "tx_rate": _mbps(c.get("tx_rate")),
            "tx_retries": c.get("tx_retries") or c.get("wifi_tx_retries"),
            "uptime": _uptime(c.get("uptime")),
            "assoc_time": c.get("assoc_time"),
            "latest_assoc_time": c.get("latest_assoc_time"),
            "satisfaction": c.get("satisfaction"),
            "wired": bool(c.get("is_wired")),
            "vlan": c.get("vlan"),
            "network": c.get("network") or "",
            "channel": c.get("channel"),
            "radio": c.get("radio") or "",
            "rx_bytes": c.get("rx_bytes"),
            "tx_bytes": c.get("tx_bytes"),
        })
    out_clients.sort(key=lambda x: (x["name"] or "").lower())
    return {"ok": True, "aps": aps, "clients": out_clients,
            "controller": cfg["url"], "site": cfg["site"]}




TRAFFIC_STEP_MS = 5 * 60 * 1000
TRAFFIC_BUCKETS = 12 * 60 // 5


def _traffic(cfg):
    """Aggregate per-AP 5-minute report rows into 12 hours of traffic history."""
    if not cfg["url"]:
        return {"ok": True, "buckets": [], "summary": {}, "configured": False}
    if cfg["mode"] == "api_key" and not cfg["key"]:
        return {"ok": True, "buckets": [], "summary": {}, "configured": False}
    if cfg["mode"] == "local" and (not cfg["username"] or not cfg["password"]):
        return {"ok": True, "buckets": [], "summary": {}, "configured": False}

    opener, headers = _login(cfg)
    site = urllib.parse.quote(cfg["site"], safe="")
    now = int(time.time() * 1000)
    attrs = ["time", "rx_bytes", "tx_bytes", "tx_retries",
             "wifi_tx_attempts", "wifi_tx_dropped", "num_sta"]
    rows = _post(cfg, opener, headers,
                 _api_prefix(cfg) + f"/s/{site}/stat/report/5minutes.ap",
                 {"attrs": attrs, "start": now - TRAFFIC_BUCKETS * TRAFFIC_STEP_MS,
                  "end": now}) or []

    merged = {}
    aps = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            t = int(row.get("time") or 0)
        except (TypeError, ValueError):
            continue
        if not t:
            continue
        bucket = (t // TRAFFIC_STEP_MS) * TRAFFIC_STEP_MS
        item = merged.setdefault(bucket, {
            "rx": 0.0, "tx": 0.0, "retries": 0.0,
            "attempts": 0.0, "clients": 0.0,
        })
        for src, dst in (("rx_bytes", "rx"), ("tx_bytes", "tx"),
                         ("tx_retries", "retries"),
                         ("wifi_tx_attempts", "attempts"),
                         ("num_sta", "clients")):
            try:
                item[dst] += float(row.get(src) or 0)
            except (TypeError, ValueError):
                pass
        ap = row.get("ap") or row.get("oid")
        if ap:
            aps.add(str(ap))

    aligned_start = ((now - TRAFFIC_BUCKETS * TRAFFIC_STEP_MS) // TRAFFIC_STEP_MS) * TRAFFIC_STEP_MS
    buckets = []
    peak_down = peak_up = 0.0
    down_sum = up_sum = 0.0
    down_n = up_n = 0
    retry_weighted = 0.0
    attempts_total = 0.0
    last_clients = None
    for i in range(TRAFFIC_BUCKETS + 1):
        t = aligned_start + i * TRAFFIC_STEP_MS
        item = merged.get(t)
        if item is None:
            buckets.append({"t": t, "down": None, "up": None,
                            "retry": None, "clients": None})
            continue
        down = item["rx"] * 8 / (TRAFFIC_STEP_MS / 1000.0) / 1_000_000
        up = item["tx"] * 8 / (TRAFFIC_STEP_MS / 1000.0) / 1_000_000
        retry = (item["retries"] / item["attempts"] * 100.0) if item["attempts"] > 0 else 0.0
        clients = int(round(item["clients"]))
        down = round(down, 3)
        up = round(up, 3)
        retry = round(min(retry, 100.0), 1)
        peak_down = max(peak_down, down)
        peak_up = max(peak_up, up)
        down_sum += down
        up_sum += up
        down_n += 1
        up_n += 1
        retry_weighted += item["retries"]
        attempts_total += item["attempts"]
        last_clients = clients
        buckets.append({"t": t, "down": down, "up": up,
                        "retry": retry, "clients": clients})

    summary = {
        "down": round(down_sum / down_n, 2) if down_n else 0.0,
        "up": round(up_sum / up_n, 2) if up_n else 0.0,
        "retry": round(retry_weighted / attempts_total * 100.0, 1) if attempts_total else 0.0,
        "clients": last_clients if last_clients is not None else 0,
        "peak_down": round(peak_down, 2),
        "peak_up": round(peak_up, 2),
        "points": down_n,
        "aps": len(aps),
    }
    return {"ok": True, "configured": True, "buckets": buckets,
            "summary": summary, "start": aligned_start, "end": now,
            "interval": TRAFFIC_STEP_MS}


def _v2_prefix(cfg):
    if cfg["mode"] == "local" and cfg["controller"] == "classic":
        return "/v2/api"
    return "/proxy/network/v2/api"


def _connectivity(cfg, hours=12):
    """Return UniFi's WiFi connectivity success breakdown for the time window."""
    if not cfg["url"]:
        return {"ok": True, "configured": False, "available": False}
    if cfg["mode"] == "api_key" and not cfg["key"]:
        return {"ok": True, "configured": False, "available": False}
    if cfg["mode"] == "local" and (not cfg["username"] or not cfg["password"]):
        return {"ok": True, "configured": False, "available": False}

    opener, headers = _login(cfg)
    site = urllib.parse.quote(cfg["site"], safe="")
    now = int(time.time() * 1000)
    query = urllib.parse.urlencode({
        "start": now - int(hours) * 3600 * 1000,
        "end": now,
        "apMac": "all",
        "clientMac": "all",
        "radioBand": "all",
    })
    path = f"{_v2_prefix(cfg)}/site/{site}/wifi-connectivity?{query}"
    try:
        req = urllib.request.Request(cfg["url"] + path, headers=headers, method="GET")
        with opener.open(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 404, 405):
            return {"ok": True, "configured": True, "available": False,
                    "message": "WiFi Connectivity is not available on this controller version."}
        raise
    try:
        data = json.loads(raw)
    except ValueError:
        return {"ok": True, "configured": True, "available": False,
                "message": "Controller returned an unexpected connectivity response."}
    if not isinstance(data, dict):
        return {"ok": True, "configured": True, "available": False,
                "message": "Controller returned no connectivity data."}

    attempts = data.get("attempts") or {}
    groups = data.get("event_groups") or []
    failures = {"association": 0, "authentication": 0, "dhcp": 0, "dns": 0, "other": 0}
    for group in groups:
        if not isinstance(group, dict):
            continue
        for event in group.get("events") or []:
            if not isinstance(event, dict):
                continue
            reason = str(event.get("failure_reason") or "").upper()
            stage = str(event.get("failure_stage") or "").upper()
            if reason == "SUCCESS" or stage == "SUCCESS":
                continue
            if "ASSOC" in reason or "ASSOC" in stage:
                failures["association"] += 1
            elif "AUTH" in reason or "AUTH" in stage:
                failures["authentication"] += 1
            elif "DHCP" in reason or "DHCP" in stage:
                failures["dhcp"] += 1
            elif "DNS" in reason or "DNS" in stage:
                failures["dns"] += 1
            else:
                failures["other"] += 1

    def ratio(key):
        try:
            return round(max(0.0, min(100.0, float(attempts.get(key) or 0))), 1)
        except (TypeError, ValueError):
            return 0.0

    latencies = data.get("latencies") or {}

    def latency_ms(key):
        try:
            return int(round(float(latencies.get(key) or 0) / 1000.0))
        except (TypeError, ValueError):
            return 0

    try:
        total_attempts = int(attempts.get("total_attempts") or 0)
    except (TypeError, ValueError):
        total_attempts = 0
    try:
        total_clients = int(data.get("total_clients") or 0)
    except (TypeError, ValueError):
        total_clients = 0

    return {
        "ok": True,
        "configured": True,
        "available": True,
        "hours": int(hours),
        "attempts": {
            "success": ratio("success_ratio"),
            "association": ratio("association_ratio"),
            "authentication": ratio("authentication_ratio"),
            "dhcp": ratio("dhcp_ratio"),
            "dns": ratio("dns_ratio"),
            "total": total_attempts,
            "failed": int(attempts.get("failed_client_connections") or 0),
        },
        "clients": total_clients,
        "event_clients": len(groups),
        "failures": failures,
        "latency": {
            "association": latency_ms("association_latency"),
            "authentication": latency_ms("authentication_latency"),
            "dhcp": latency_ms("dhcp_latency"),
            "traffic": latency_ms("traffic_latency"),
            "total": latency_ms("total_latency"),
        },
    }


def handle(req):
    cfg = _cfg(req)
    action = req.get("action") or ""
    try:
        if action == "connectivity":
            return _connectivity(cfg, int((req.get("payload") or {}).get("hours") or 12))
        if action == "traffic":
            return _traffic(cfg)
        if action == "incidents":
            return _incidents(cfg)
        if action == "test":
            opener, headers = _login(cfg)
            site = urllib.parse.quote(cfg["site"], safe="")
            _get(cfg, opener, headers, _api_prefix(cfg) + f"/s/{site}/stat/device")
            return {"ok": True, "message": "Connected to the UniFi controller."}
        if action in ("overview", "refresh"):
            return _overview(cfg)
        if action == "events":
            return _events(cfg, (req.get("payload") or {}).get("limit") or 100)
        return {"ok": False, "error": f"Unknown action: {action}"}
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:400]
        except Exception:
            pass
        return {"ok": False, "error": f"Controller HTTP {exc.code}: {detail or exc.reason}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
