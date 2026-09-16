#!/usr/bin/env python3
"""tuxwall collector - community ban reporting service for tuxwall.org.

Receives ban reports from TuxWall firewall installs, aggregates them in
SQLite, enriches them with geo/ASN data, and serves:

  POST /report                   - ingest {key, ip, hits, reason, source}
  GET  /healthz                  - liveness probe
  GET  /api/public/bans          - JSON list of aggregated bans
  GET  /api/admin/bans           - loopback-only admin listing (X-Admin-Key)
  DELETE /api/admin/bans/<ip>    - loopback-only admin removal (X-Admin-Key)
  GET  /bans                     - public HTML page
  GET  /ip/<addr>                - AbuseIPDB-style per-IP report card
  GET  /lists/community-bans.txt - plain-text IPs (severity-filterable)

Reporter identity is never stored: the per-install report key is hashed
with SHA-256 and only the hash is kept, giving the distinct-reporter count
without leaking who reported what.

Data (c) DB-IP.com, licensed under CC BY 4.0 (https://db-ip.com/db/lite.php)
"""
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("TUXWALL_COLLECTOR_PORT") or "8009")

DB_PATH = os.environ.get("TUXWALL_COLLECTOR_DB") or "/var/lib/tuxwall-collector/reports.db"
DATA_DIR = "/var/lib/tuxwall"
GEO_CITY_DB = os.path.join(DATA_DIR, "dbip-city-lite.mmdb")
GEO_ASN_DB = os.path.join(DATA_DIR, "dbip-asn-lite.mmdb")

RETENTION_DAYS = 90
RATE_LIMIT_PER_HOUR = 120
DEDUPE_SECONDS = 300       # ignore a report for (ip, reporter) seen this recently
PRUNE_EVERY = 200          # run retention cleanup every N ingests
SOURCE_MAX = 24
REASON_MAX = 96
MAX_HITS = 1000000

# Admin endpoints (/api/admin/**) are NEVER proxied by nginx — they answer on
# the loopback listener only. The key gates them against local misuse and is
# compared in constant time. Key file is created by deploy-collector.sh
# (0600/0640 root:adm); absent key = admin endpoints disabled outright.
ADMIN_KEY_PATH = os.environ.get(
    "TUXWALL_COLLECTOR_ADMIN_KEY") or "/etc/tuxwall-collector/admin.key"

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
SEVERITY_ORDER = [SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]


def severity_for(hits, reporters):
    """Severity driven by how much of the community has been hit and how hard."""
    if reporters >= 10 or hits >= 5000:
        return SEVERITY_CRITICAL
    if reporters >= 5 or hits >= 500:
        return SEVERITY_HIGH
    if reporters >= 2 or hits >= 50:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def severity_rank(sev):
    return SEVERITY_ORDER.index(sev)


CATEGORIES = ["ssh", "rdp", "bruteforce", "scan", "web", "spam", "dos",
              "malware", "manual", "blocklist", "other"]
CATEGORY_LABELS = {
    "ssh": "SSH Attack", "rdp": "RDP Attack", "bruteforce": "Brute Force",
    "scan": "Port Scan", "web": "Web App Attack", "spam": "Spam",
    "dos": "DoS / DDoS", "malware": "Malware / Botnet",
    "manual": "Manual Ban", "blocklist": "Manual Blocklist", "other": "Other",
}


def category_for(reason, source):
    """Best-effort AbuseIPDB-style category from the reporter's reason/source.

    Reporters may also send a structured `category` in the report payload;
    this only kicks in when they don't.
    """
    r = (reason or "").lower()
    s = (source or "").lower()
    if "rdp" in r:
        return "rdp"
    if "ssh" in r or "sshd" in r:
        return "ssh"
    if any(k in r for k in ("brute", "credential", "login", "dictionary",
                            "password", "hydra")):
        return "bruteforce"
    if any(k in r for k in ("scan", "probe", "port ", "sniff", "nmap")):
        return "scan"
    if any(k in r for k in ("http", "web", "iis", "apache", "nginx", "sql",
                            "php", "api", "cve", "exploit", "shell", "admin",
                            "xmlrpc", "wp-", "joomla")):
        return "web"
    if any(k in r for k in ("spam", "smtp", "mail", "phish", "spoof", "pxe",
                            "jabber", "sip")):
        return "spam"
    if any(k in r for k in ("dos", "ddos", "flood", "syn")):
        return "dos"
    if any(k in r for k in ("malware", "botnet", "c2 ", "c&c", "cnc", "mirai",
                            "cobalt", "ddg", "xzfl")):
        return "malware"
    if "blocklist" in r or s == "blocklist":
        return "blocklist"
    if "manual" in r or s == "manual":
        return "manual"
    return "other"


# --- Geo/ASN enrichment (both DB-IP MMDBs, reused from the LAN dashboard) ---
class GeoEnricher:
    def __init__(self):
        self._lock = threading.Lock()
        self._city = None
        self._asn = None

    def _open(self, path):
        try:
            import maxminddb  # python3-maxminddb / pip maxminddb
            return maxminddb.open_database(path)
        except Exception:
            return None

    def enrich(self, ip):
        info = {"country": "", "iso": "", "city": "", "isp": "", "asn": ""}
        with self._lock:
            if self._city is None:
                self._city = self._open(GEO_CITY_DB)
            if self._asn is None:
                self._asn = self._open(GEO_ASN_DB)
            city, asn = self._city, self._asn
        if city is not None:
            try:
                rec = city.get(ip)
                if isinstance(rec, dict):
                    c = rec.get("country") or {}
                    info["iso"] = (c.get("iso_code") or "").upper()
                    info["country"] = (c.get("names") or {}).get("en", "") or info["iso"]
                    cit = rec.get("city") or {}
                    info["city"] = (cit.get("names") or {}).get("en", "") or ""
            except Exception:
                pass
        if asn is not None:
            try:
                rec = asn.get(ip)
                if isinstance(rec, dict):
                    info["asn"] = str(rec.get("autonomous_system_number") or "")
                    info["isp"] = str(rec.get("autonomous_system_organization") or "")
            except Exception:
                pass
        if not info["iso"]:
            info["iso"] = "??"
        return info


GEO = GeoEnricher()


# --- Storage ---------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    ip TEXT PRIMARY KEY,
    hits INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    country TEXT NOT NULL DEFAULT '',
    iso TEXT NOT NULL DEFAULT '',
    city TEXT NOT NULL DEFAULT '',
    isp TEXT NOT NULL DEFAULT '',
    asn TEXT NOT NULL DEFAULT '',
    last_reason TEXT NOT NULL DEFAULT '',
    last_source TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS report_reports (
    ip TEXT NOT NULL,
    reporter TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL,
    PRIMARY KEY (ip, reporter)
);
CREATE INDEX IF NOT EXISTS idx_reports_last_seen ON reports(last_seen);
CREATE TABLE IF NOT EXISTS report_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reporter TEXT NOT NULL,
    ts REAL NOT NULL,
    category TEXT NOT NULL DEFAULT 'other',
    source TEXT NOT NULL DEFAULT '',
    hits INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_report_events_ip_ts ON report_events(ip, ts);
"""


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self._conn = None
        self._init_db()

    def _connect(self):
        # One shared connection guarded by self.lock; sqlite3 objects are not
        # thread-safe by default, and the HTTP workers run in other threads.
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._conn = self._connect()
        with self.lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def ingest(self, reporter, ip, hits, reason, source, category, now):
        """Record a report. Returns "ok", "duplicate", or "error"."""
        geo = GEO.enrich(ip)
        with self.lock:
            cur = self._conn.execute(
                "SELECT last_seen FROM report_reports WHERE ip=? AND reporter=?",
                (ip, reporter))
            row = cur.fetchone()
            if row is not None and now - row[0] < DEDUPE_SECONDS:
                return "duplicate"
            # Delta semantics: clients send the cumulative event count seen from
            # this IP. Only the increase over what this reporter already
            # contributed is added, so re-reporting the same IP (after the dedupe
            # window) can never double-count its hits.
            cur = self._conn.execute(
                "SELECT hits FROM report_reports WHERE ip=? AND reporter=?",
                (ip, reporter))
            reported_row = cur.fetchone()
            base = reported_row[0] if reported_row is not None else 0
            delta = hits - base
            geo = GEO.enrich(ip)
            if reported_row is not None and delta <= 0:
                # Same or lower cumulative count → idempotent re-report. Refresh
                # timestamps and metadata only; no hit or event added.
                self._conn.execute(
                    "UPDATE report_reports SET last_seen=? WHERE ip=? AND reporter=?",
                    (now, ip, reporter))
                self._conn.execute(
                    "UPDATE reports SET last_seen=?, country=?, iso=?, city=?,"
                    " isp=?, asn=?, last_reason=?, last_source=? WHERE ip=?",
                    (now, geo["country"], geo["iso"], geo["city"],
                     geo["isp"], geo["asn"], reason, source, ip))
                self._conn.commit()
                return "duplicate"
            cur = self._conn.execute(
                "SELECT hits FROM reports WHERE ip=?",
                (ip,))
            existing = cur.fetchone()
            add_hits = delta if delta > 0 else hits
            if existing is None:
                self._conn.execute(
                    "INSERT INTO reports (ip, hits, first_seen, last_seen, country, iso,"
                    " city, isp, asn, last_reason, last_source)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (ip, add_hits, now, now, geo["country"], geo["iso"], geo["city"],
                     geo["isp"], geo["asn"], reason, source))
            else:
                self._conn.execute(
                    "UPDATE reports SET hits=?, last_seen=?, country=?, iso=?, city=?,"
                    " isp=?, asn=?, last_reason=?, last_source=? WHERE ip=?",
                    (existing[0] + add_hits, now, geo["country"], geo["iso"],
                     geo["city"], geo["isp"], geo["asn"], reason, source, ip))
            self._conn.execute(
                "INSERT INTO report_reports (ip, reporter, hits, last_seen)"
                " VALUES (?,?,?,?)"
                " ON CONFLICT(ip, reporter) DO UPDATE SET"
                " hits = excluded.hits,"
                " last_seen = excluded.last_seen",
                (ip, reporter, base + add_hits, now))
            self._conn.execute(
                "INSERT INTO report_events (ip, reporter, ts, category, source, hits)"
                " VALUES (?,?,?,?,?,?)",
                (ip, reporter, now, category, source, add_hits))
            self._conn.commit()
        return "ok"

    def prune(self, now):
        cutoff = now - RETENTION_DAYS * 86400
        with self.lock:
            self._conn.execute("DELETE FROM reports WHERE last_seen < ?", (cutoff,))
            self._conn.execute(
                "DELETE FROM report_reports WHERE last_seen < ?", (cutoff,))
            self._conn.commit()

    def remove_ip(self, ip):
        """Admin removal: purge an IP from every table. Returns deleted row
        counts per table so the caller can tell a hit from a no-op."""
        with self.lock:
            counts = {}
            for table in ("reports", "report_reports", "report_events"):
                cur = self._conn.execute(f"DELETE FROM {table} WHERE ip=?", (ip,))
                counts[table] = cur.rowcount if cur.rowcount >= 0 else 0
            self._conn.commit()
        return counts

    def top_bans(self, min_severity=0, tier=None, limit=500):
        """Aggregate ban rows ordered by hit count.

        min_severity: keep rows at rank >= this (a "at least this bad" filter).
        tier:         keep only rows whose severity is EXACTLY this tier.
        """
        tier_constraints = {
            SEVERITY_LOW: "(r.hits < 50 AND c.reporters < 2)",
            SEVERITY_MEDIUM: ("(r.hits >= 50 OR c.reporters >= 2)"
                              " AND r.hits < 500 AND c.reporters < 5"),
            SEVERITY_HIGH: ("(r.hits >= 500 OR c.reporters >= 5)"
                            " AND r.hits < 5000 AND c.reporters < 10"),
            SEVERITY_CRITICAL: "(r.hits >= 5000 OR c.reporters >= 10)",
        }
        where = ["r.last_seen > ?"]
        args = [time.time() - RETENTION_DAYS * 86400]
        if tier in tier_constraints:
            where.append(tier_constraints[tier])
        with self.lock:
            cur = self._conn.execute(
                "WITH counts AS (SELECT ip, COUNT(*) AS reporters"
                "   FROM report_reports GROUP BY ip)"
                " SELECT r.ip, r.hits, r.first_seen, r.last_seen, r.country, r.iso,"
                " r.city, r.isp, r.asn, COALESCE(c.reporters, 0) AS reporters"
                " FROM reports r LEFT JOIN counts c ON c.ip = r.ip"
                " WHERE " + " AND ".join(where)
                + " ORDER BY r.hits DESC LIMIT ?",
                tuple(args) + (limit,))
            rows = cur.fetchall()
        bans = []
        for (ip, hits, first_seen, last_seen, country, iso, city, isp, asn,
             reporters) in rows:
            sev = severity_for(hits, reporters)
            if severity_rank(sev) < min_severity:
                continue
            bans.append({
                "ip": ip,
                "hits": hits,
                "reporters": reporters,
                "country": country,
                "iso": iso,
                "city": city,
                "isp": isp,
                "asn": asn,
                "severity": sev,
                "details_url": "/ip/" + ip,
                "first_seen": first_seen,
                "last_seen": last_seen,
            })
        return bans

    def get_ip_report(self, ip):
        """Per-IP detail: aggregate row + category/source breakdown + event log."""
        with self.lock:
            cur = self._conn.execute(
                "SELECT ip, hits, first_seen, last_seen, country, iso, city, isp,"
                " asn, last_reason, last_source FROM reports WHERE ip=?",
                (ip,))
            row = cur.fetchone()
            if row is None:
                return None
            reporters = self._conn.execute(
                "SELECT COUNT(*) FROM report_reports WHERE ip=?", (ip,)).fetchone()[0]
            cats = self._conn.execute(
                "SELECT category, SUM(hits), COUNT(*) FROM report_events"
                " WHERE ip=? GROUP BY category ORDER BY SUM(hits) DESC",
                (ip,)).fetchall()
            srcs = self._conn.execute(
                "SELECT source, COUNT(*) FROM report_events"
                " WHERE ip=? GROUP BY source ORDER BY COUNT(*) DESC",
                (ip,)).fetchall()
            events = self._conn.execute(
                "SELECT reporter, ts, category, source, hits FROM report_events"
                " WHERE ip=? ORDER BY ts DESC LIMIT 50",
                (ip,)).fetchall()
        (ip, hits, first_seen, last_seen, country, iso, city, isp, asn,
         last_reason, last_source) = row
        return {
            "ip": ip,
            "hits": hits,
            "reporters": reporters,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "country": country,
            "iso": iso,
            "city": city,
            "isp": isp,
            "asn": asn,
            "severity": severity_for(hits, reporters),
            "last_reason": last_reason,
            "last_source": last_source,
            "categories": {c: {"hits": h, "reports": n} for c, h, n in cats},
            "sources": {s: n for s, n in srcs},
            "events": [{
                "reporter": r, "ts": t, "category": c, "source": s, "hits": h,
            } for r, t, c, s, h in events],
        }

    def stats(self):
        with self.lock:
            cur = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(hits),0) FROM reports")
            ips, hits = cur.fetchone()
            cur = self._conn.execute(
                "SELECT COUNT(DISTINCT reporter) FROM report_reports")
            reporters = cur.fetchone()[0]
        return {"ips": ips, "hits": hits, "reporters": reporters}


# --- Per-key rate limiting (in-memory, resets on restart) ------------------
class RateLimiter:
    def __init__(self, limit):
        self.limit = limit
        self._lock = threading.Lock()
        self._hits = defaultdict(deque)

    def allow(self, key, now):
        with self._lock:
            d = self._hits[key]
            window = now - 3600
            while d and d[0] < window:
                d.popleft()
            if len(d) >= self.limit:
                return False
            d.append(now)
            return True


RATE = RateLimiter(RATE_LIMIT_PER_HOUR)


# --- HTTP handler ----------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "tuxwall-collector/1.0"

    def log_message(self, fmt, *args):
        sys_log = _log()
        try:
            sys_log.put(json.dumps({
                "ts": time.time(),
                "client": self.client_address[0] if self.client_address else "",
                "path": self.path,
                "msg": fmt % args,
            }))
        except Exception:
            pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code, text, ctype="text/plain; charset=utf-8"):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _ok_json(self, **kw):
        self._json(200, {"ok": True, **kw})

    # --- Admin auth (loopback-only endpoints, never proxied by nginx) ------
    def _admin_key(self):
        try:
            with open(ADMIN_KEY_PATH, "rb") as f:
                return f.read().strip()
        except OSError:
            return b""

    def _admin_authorized(self):
        supplied = (self.headers.get("X-Admin-Key") or "").strip().encode("utf-8")
        return bool(supplied) and hmac.compare_digest(supplied, self._admin_key())

    def do_GET(self):
        path = self.path.split("?")[0]
        import urllib.parse
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if path == "/healthz":
            self._ok_json(service="tuxwall-collector",
                          stats=_store().stats())
            return
        if path == "/api/public/bans":
            try:
                min_sev = params.get("severity") or ["all"]
                sev = min_sev[0] or "all"
            except Exception:
                sev = "all"
            rank = 0 if sev == "all" else max(0, severity_rank(sev))
            try:
                limit = max(1, min(1000, int((params.get("limit") or ["500"])[0])))
            except (TypeError, ValueError):
                limit = 500
            bans = _store().top_bans(min_severity=rank, limit=limit)
            self._json(200, {
                "ok": True,
                "generated": datetime.now(timezone.utc).isoformat(),
                "severity_filter": sev,
                "total": len(bans),
                "bans": bans,
            })
            return
        if path.startswith("/api/public/bans/"):
            # Per-IP lookup used by dashboard browsers and third-party tools.
            try:
                addr = ipaddress.ip_address(path[len("/api/public/bans/"):])
            except ValueError:
                self._json(400, {"ok": False, "error": "Invalid IP"})
                return
            data = _store().get_ip_report(str(addr))
            if data is None:
                self._json(200, {"ok": True, "ip": str(addr), "reported": False})
                return
            data = dict(data)
            data.pop("events", None)
            self._json(200, {"ok": True, "ip": str(addr), "reported": True,
                             "report": data})
            return
        if path == "/bans":
            try:
                sev = (params.get("severity") or ["all"])[0] or "all"
            except Exception:
                sev = "all"
            self._text(200, render_bans_page(sev), "text/html; charset=utf-8")
            return
        if path.startswith("/ip/"):
            try:
                addr = ipaddress.ip_address(path[len("/ip/"):])
            except ValueError:
                self._json(400, {"ok": False, "error": "Invalid IP"})
                return
            self._text(200, render_ip_page(str(addr)), "text/html; charset=utf-8")
            return
        if path == "/lists/community-bans.txt":
            try:
                sev = (params.get("severity") or ["all"])[0] or "all"
            except Exception:
                sev = "all"
            rank = 0 if sev == "all" else max(0, severity_rank(sev))
            bans = _store().top_bans(min_severity=rank, limit=20000)
            lines = [b["ip"] for b in bans]
            self._text(200, "\n".join(lines) + ("\n" if lines else ""))
            return
        if path == "/api/admin/bans":
            if not self._admin_authorized():
                self._json(401, {"ok": False, "error": "Admin key required"})
                return
            bans = _store().top_bans(min_severity=0, limit=20000)
            self._json(200, {
                "ok": True,
                "generated": datetime.now(timezone.utc).isoformat(),
                "total": len(bans),
                "bans": bans,
            })
            return
        if path.startswith("/api/admin/bans/"):
            if not self._admin_authorized():
                self._json(401, {"ok": False, "error": "Admin key required"})
                return
            try:
                addr = ipaddress.ip_address(path[len("/api/admin/bans/"):])
            except ValueError:
                self._json(400, {"ok": False, "error": "Invalid IP"})
                return
            self._json(405, {
                "ok": False,
                "error": "Admin ban lookups use DELETE",
                "usage": "curl -X DELETE -H \"X-Admin-Key: <key>\""
                         " http://127.0.0.1:8009/api/admin/bans/<ip>",
            })
            return
        if path == "/report":
            # /report only accepts POST — return a hint instead of a bare 404
            # so a browser/GET curl doesn't look like a broken endpoint.
            self._json(405, {
                "ok": False,
                "error": "/report accepts POST only",
                "usage": "POST JSON: {\"key\":\"<install key>\", \"ip\":\"1.2.3.4\","
                         "\"hits\":12, \"reason\":\"ssh bruteforce\", \"source\":\"crowdsec\"}",
            })
            return
        self._json(404, {"ok": False, "error": "Not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/report":
            self._json(404, {"ok": False, "error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        if length <= 0 or length > 65536:
            self._json(413, {"ok": False, "error": "Payload too large or empty"})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            body = {}
        if not isinstance(body, dict):
            body = {}

        key = str(body.get("key") or "").strip()
        if len(key) < 16:
            self._json(400, {"ok": False, "error": "Missing or invalid report key"})
            return

        ip_raw = str(body.get("ip") or "").strip()
        try:
            addr = ipaddress.ip_address(ip_raw)
        except ValueError:
            self._json(400, {"ok": False, "error": "Invalid IP"})
            return
        if not addr.is_global:
            self._json(400, {"ok": False, "error": "Refusing private/reserved IP"})
            return
        ip = str(addr)

        try:
            hits = int(body.get("hits") or 1)
        except (TypeError, ValueError):
            hits = 1
        hits = max(0, min(MAX_HITS, hits))

        reason = str(body.get("reason") or "")[:REASON_MAX]
        source = str(body.get("source") or "")[:SOURCE_MAX]
        raw_cat = str(body.get("category") or "").strip().lower()
        category = raw_cat if raw_cat in CATEGORIES else category_for(reason, source)

        reporter = hashlib.sha256(key.encode("utf-8")).hexdigest()
        now = time.time()
        if not RATE.allow(reporter, now):
            self._json(429, {"ok": False, "error": "Rate limit exceeded"})
            return

        result = _store().ingest(reporter, ip, hits, reason, source, category, now)

        global _ingest_count
        _ingest_count += 1
        if _ingest_count % PRUNE_EVERY == 0:
            _store().prune(now)

        if result == "error":
            self._json(500, {"ok": False, "error": "Storage failure"})
            return
        self._ok_json(accepted=(result == "ok"), duplicate=(result == "duplicate"))

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if not path.startswith("/api/admin/bans/"):
            self._json(404, {"ok": False, "error": "Not found"})
            return
        if not self._admin_authorized():
            self._json(401, {"ok": False, "error": "Admin key required"})
            return
        try:
            addr = ipaddress.ip_address(path[len("/api/admin/bans/"):])
        except ValueError:
            self._json(400, {"ok": False, "error": "Invalid IP"})
            return
        ip = str(addr)
        counts = _store().remove_ip(ip)
        if counts.get("reports", 0) == 0:
            self._json(404, {"ok": False, "error": "IP not found", "ip": ip})
            return
        _log().put(json.dumps({
            "ts": time.time(),
            "client": self.client_address[0] if self.client_address else "",
            "path": path,
            "msg": "admin delete: removed %s (reports=%d report_reports=%d"
                   " report_events=%d)" % (ip, counts.get("reports", 0),
                                           counts.get("report_reports", 0),
                                           counts.get("report_events", 0)),
        }))
        self._json(200, {"ok": True, "ip": ip, "removed": counts})


def _store():
    return STORE


def _log():
    return LOG


def render_severity_badge(sev):
    key = sev if sev in SEVERITY_ORDER else SEVERITY_LOW
    return '<span class="sev sev-%s">%s</span>' % (key, (sev or "—").upper())


def _filter_badge(value, label, active):
    cls = "badge cur" if active else "badge"
    href = "/bans" if value == "all" else "/bans?severity=" + value
    return '<a class="%s" href="%s">%s</a>' % (cls, href, label)


def render_bans_page(sev="all"):
    if sev == "all":
        bans = _store().top_bans(min_severity=0, limit=100)
    else:
        try:
            severity_rank(sev)
        except ValueError:
            sev = "all"
            bans = _store().top_bans(min_severity=0, limit=100)
        else:
            bans = _store().top_bans(tier=sev, limit=100)
    stats = _store().stats()
    rows = []
    for b in bans:
        flag = b["iso"]
        if len(flag) == 2:
            flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in flag)
        else:
            flag = "\u2753"
        loc = " • ".join(x for x in (b["city"], b["country"]) if x) or "Unknown"
        rows.append(
            "<tr>"
            f"<td class='mono'><a class='ip-link' href='/ip/{_esc(b['ip'])}'>{_esc(b['ip'])}</a></td>"
            f"<td>{render_severity_badge(b['severity'])}</td>"
            f"<td>{fmt_num(b['hits'])}</td>"
            f"<td>{fmt_num(b['reporters'])}</td>"
            f"<td>{flag} {_esc(loc)}</td>"
            f"<td class='muted'>{_esc(b['isp']) or '—'}</td>"
            f"<td class='mono muted'>{fmt_date(b['last_seen'])}</td>"
            "</tr>"
        )
    body = "".join(rows) or (
        "<tr><td colspan='7' class='empty'>No community bans yet — "
        "installations that opt in to ban reporting will appear here.</td></tr>")
    filters = "".join(
        _filter_badge(s, s.title() if s != "all" else "All", s == sev)
        for s in ["all"] + SEVERITY_ORDER)
    return (HTML_TEMPLATE
            .replace("__TOTAL__", fmt_num(stats["ips"]))
            .replace("__HITS__", fmt_num(stats["hits"]))
            .replace("__REPORTERS__", fmt_num(stats["reporters"]))
            .replace("__FILTERS__", filters)
            .replace("__ROWS__", body)
            .replace("__GENERATED__",
                     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
            .replace("__PAGE_CSS__", PAGE_CSS))


def _flag_emoji(iso):
    if len(iso or "") == 2:
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso)
    return "\u2753"


def render_ip_page(ip):
    """AbuseIPDB-style per-IP report card using the site's own design."""
    d = _store().get_ip_report(ip)
    if d is None:
        return (IP_DETAIL_TEMPLATE
                .replace("__IP__", _esc(ip))
                .replace("__BADGE__", "")
                .replace("__FLAG__", "")
                .replace("__BODY__", (
                    "<p class='verdict'>No community reports for this IP yet."
                    " It is not currently on the TuxWall ban list. "
                    "<a href='/bans' class='ip-link'>Back to the ban list.</a></p>"))
                .replace("__PAGE_CSS__", PAGE_CSS))

    flag = _flag_emoji(d["iso"])
    loc = " • ".join(x for x in (d["city"], d["country"]) if x) or "Unknown"
    sev = d["severity"]

    verdict = "Reported by <strong>%d</strong> independent firewall installs" % (
        d["reporters"])
    if d["reporters"] > 1:
        verdict += (" — high community confidence this source is malicious, based on "
                    "multiple TuxWall installs independently blocking it.")
    else:
        verdict += (" — no other TuxWall install has encountered it yet, so this "
                    "reflects one network's experience.")

    cats = d["categories"]
    max_hits = max([v["hits"] for v in cats.values()] or [1])
    cat_rows = "".join(
        "<div class='cat-row'>"
        "<span class='k'>%s</span>"
        "<div class='bar'><i style='width:%.0f%%'></i></div>"
        "<span class='n'>%s / %d</span></div>"
        % (_esc(CATEGORY_LABELS.get(c, c.title())),
           v["hits"] * 100.0 / max_hits, fmt_num(v["hits"]), v["reports"])
        for c, v in sorted(cats.items(), key=lambda kv: -kv[1]["hits"]))
    if not cat_rows:
        cat_rows = "<div class='kv'><span class='k'>Reported as</span>" \
                   "<span class='v'>%s</span></div>" % (
                       _esc(CATEGORY_LABELS.get(
                           category_for(d["last_reason"], d["last_source"]),
                           "Other")))

    srcs = "".join(
        "<div class='kv'><span class='k'>%s</span><span class='v'>%d reports</span></div>"
        % (_esc(s or "tuxwall"), n)
        for s, n in sorted(d["sources"].items(), key=lambda kv: -kv[1])) or \
        "<div class='kv'><span class='k'>Source</span><span class='v'>%s</span></div>" % (
            _esc(d["last_source"] or "tuxwall"))

    rows = []
    for e in d["events"]:
        when = datetime.fromtimestamp(e["ts"], timezone.utc).strftime("%Y-%m-%d %H:%M")
        rows.append(
            "<tr>"
            f"<td class='mono muted'>{_esc(when)}</td>"
            f"<td class='mono'>{_esc(e['reporter'][:8])}</td>"
            f"<td>{render_severity_badge(severity_for(e['hits'], 1))}</td>"
            f"<td>{_esc(CATEGORY_LABELS.get(e['category'], e['category'].title()))}</td>"
            f"<td class='mono'>{fmt_num(e['hits'])}</td>"
            "</tr>")
    events = "".join(rows) or (
        "<tr><td colspan='5' class='empty'>No detailed report history yet.</td></tr>")

    body = (
        "<div class='stats'>"
        "<div class='stat-card'><div class='num'>__TOTAL__</div><div class='lbl'>Total hits</div></div>"
        "<div class='stat-card'><div class='num'>__REPORTERS__</div><div class='lbl'>Reporting installs</div></div>"
        "<div class='stat-card'><div class='num'>__FIRST_SEEN__</div><div class='lbl'>First seen</div></div>"
        "<div class='stat-card'><div class='num'>__LAST_SEEN__</div><div class='lbl'>Last seen</div></div>"
        "</div>"
        "<p class='verdict'>__VERDICT__</p>"
        "<div class='detail-grid'>"
        "<div class='detail-card'><h3>Source / Network</h3>"
        "<div class='kv'><span class='k'>Location</span><span class='v'>__IP_LOCATION__</span></div>"
        "<div class='kv'><span class='k'>ISP</span><span class='v'>__ISP__</span></div>"
        "<div class='kv'><span class='k'>ASN</span><span class='v'>__ASN__</span></div>"
        "<div class='kv'><span class='k'>Last reason</span><span class='v'>__LAST_REASON__</span></div>"
        "</div>"
        "<div class='detail-card'><h3>Reported categories</h3>__CATS__</div>"
        "</div>"
        "<div class='detail-card' style='margin-bottom:2rem;'>"
        "<h3>Reporting sources</h3>__SOURCES__</div>"
        "<div class='table-wrap'><table class='deps-table'>"
        "<thead><tr><th>Time (UTC)</th><th>Install</th><th>Severity</th>"
        "<th>Category</th><th>Hits</th></tr></thead>"
        "<tbody>__ROWS__</tbody></table></div>")

    return (IP_DETAIL_TEMPLATE
            .replace("__IP__", _esc(d["ip"]))
            .replace("__BADGE__", render_severity_badge(sev))
            .replace("__FLAG__", flag)
            .replace("__BODY__", body)
            .replace("__IP_LOCATION__", _esc(loc))
            .replace("__ISP__", _esc(d["isp"]) or "—")
            .replace("__ASN__", _esc(d["asn"]) or "—")
            .replace("__LAST_REASON__", _esc(d["last_reason"]) or "—")
            .replace("__TOTAL__", fmt_num(d["hits"]))
            .replace("__REPORTERS__", fmt_num(d["reporters"]))
            .replace("__FIRST_SEEN__", fmt_date(d["first_seen"]))
            .replace("__LAST_SEEN__", fmt_date(d["last_seen"]))
            .replace("__VERDICT__", verdict)
            .replace("__CATS__", cat_rows)
            .replace("__SOURCES__", srcs)
            .replace("__ROWS__", events)
            .replace("__PAGE_CSS__", PAGE_CSS))


def _esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def fmt_num(n):
    return format(int(n or 0), ",d")


def fmt_date(ts):
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return "—"


PAGE_CSS = """\
.page-main { max-width: 1100px; margin: 0 auto; padding: 6rem 2rem 0; }
    .filters { display: flex; gap: 0.6rem; flex-wrap: wrap; align-items: center;
               margin: 0 0 1.5rem; }
    .filters .fl { font-size: 0.7rem; letter-spacing: 0.2em; text-transform: uppercase;
                   color: var(--muted); margin-right: 0.25rem; }
    .filters .badge { text-decoration: none; cursor: pointer; }
    .filters .badge.cur { background: var(--green); color: #000;
                          border-color: var(--green); font-weight: bold; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
             gap: 1.2rem; margin: 0 0 2rem; }
    .stat-card { background: var(--card); border: 1px solid var(--border);
                 border-radius: 4px; padding: 1.2rem 1.4rem; }
    .stat-card .num { font-size: 1.6rem; color: var(--green); font-weight: bold; }
    .stat-card .lbl { font-size: 0.72rem; letter-spacing: 0.1em; text-transform: uppercase;
                      color: var(--muted); margin-top: 2px; }
    .table-wrap { overflow-x: auto; background: var(--card); border: 1px solid var(--border);
                  border-radius: 4px; }
    .table-wrap .deps-table { margin-top: 0; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.75rem; }
    .muted { color: var(--muted); }
    .sev { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 2px;
           font-size: 0.65rem; letter-spacing: 0.1em; text-transform: uppercase;
           border: 1px solid transparent; }
    .sev-low      { color: #39ff14; border-color: #1a7a00; }
    .sev-medium   { color: #f0a500; border-color: #b8860b; }
    .sev-high     { color: #f97316; border-color: #ea580c; }
    .sev-critical { color: #ef4444; border-color: #b91c1c; }
    .empty { text-align: center; color: var(--muted); padding: 2rem 1rem; }
    .nav-links a.active { color: var(--green); }
    .ip-link { color: var(--green); text-decoration: none; }
    .ip-link:hover { text-decoration: underline; }
    .ip-head { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
    .ip-head .section-title { margin-bottom: 0; }
    .ip-flag { font-size: 1.4rem; line-height: 1; }
    .verdict { color: var(--muted); font-size: 0.9rem; }
    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.2rem;
                   margin: 0 0 2rem; }
    @media (max-width: 700px) { .detail-grid { grid-template-columns: 1fr; } }
    .detail-card { background: var(--card); border: 1px solid var(--border);
                   border-radius: 4px; padding: 1.2rem 1.4rem; }
    .detail-card h3 { color: var(--white); font-size: 0.85rem; margin: 0 0 0.9rem;
                      letter-spacing: 0.05em; }
    .kv { display: flex; justify-content: space-between; gap: 1rem; padding: 0.3rem 0;
          border-bottom: 1px solid var(--border); }
    .kv:last-child { border-bottom: none; }
    .kv .k { color: var(--muted); text-transform: uppercase; font-size: 0.65rem;
             letter-spacing: 0.1em; }
    .kv .v { color: var(--text); text-align: right; }
    .cat-row { display: grid; grid-template-columns: 130px 1fr 110px; align-items: center;
               gap: 0.6rem; padding: 0.3rem 0; }
    .cat-row .k { color: var(--muted); font-size: 0.72rem; }
    .cat-row .bar { height: 8px; background: #0a0a0a; border: 1px solid var(--border);
                    border-radius: 2px; overflow: hidden; }
    .cat-row .bar i { display: block; height: 100%; background: var(--dimgreen); }
    .cat-row .n { text-align: right; color: var(--muted); font-size: 0.7rem; }"""


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Community Bans — TuxWall</title>
  <meta name="description" content="IPs reported as banned by participating TuxWall firewall installs, with hit counts, severity, and geolocation. Powered by the TuxWall community ban network." />
  <meta name="robots" content="index, follow" />
  <link rel="canonical" href="https://tuxwall.org/bans" />
  <meta name="theme-color" content="#0d0d0d" />
  <link rel="icon" href="/favicon.ico?v=2" sizes="16x16 32x32 48x48 64x64" />
  <link rel="icon" type="image/png" sizes="60x60" href="/images/tux-logo60.png?v=2" />
  <link rel="stylesheet" href="/css/style.css?v=20260830b" />
  <style>
    __PAGE_CSS__
  </style>
</head>
<body>

  <nav>
    <a class="nav-brand" href="https://tuxwall.org/">
      <img src="/images/tuxwall-small-white.png" alt="Tux" />
    </a>
    <ul class="nav-links" id="navLinks">
      <li><a href="https://tuxwall.org/">Home</a></li>
      <li><a class="active" href="/bans">Bans</a></li>
      <li><a href="/api/public/bans">JSON API</a></li>
      <li><a href="/lists/community-bans.txt">Ban List</a></li>
      <li><a class="nav-forum" href="https://github.com/rezzonance/tuxwall" target="_blank" rel="noopener">GitHub</a></li>
    </ul>
    <button class="nav-toggle" id="navToggle" aria-label="Toggle menu" aria-expanded="false" aria-controls="navLinks">
      <span></span><span></span><span></span>
    </button>
  </nav>

  <div class="page-main">
    <section class="section" style="padding-top:0;">
      <p class="section-label">// community ban list</p>
      <h2 class="section-title">Banned by TuxWall.</h2>
      <p class="section-desc">IPs reported as banned by participating TuxWall firewall installs.
         Severity reflects cumulative hit counts and how many independent installs reported the source.</p>

      <div class="filters">
        <span class="fl">Severity:</span>
        __FILTERS__
      </div>

      <div class="stats">
        <div class="stat-card"><div class="num">__TOTAL__</div><div class="lbl">Unique IPs</div></div>
        <div class="stat-card"><div class="num">__HITS__</div><div class="lbl">Reported hits</div></div>
        <div class="stat-card"><div class="num">__REPORTERS__</div><div class="lbl">Reporting installs</div></div>
      </div>

      <div class="table-wrap">
        <table class="deps-table">
          <thead><tr><th>IP</th><th>Severity</th><th>Hits</th><th>Reporters</th>
            <th>Location</th><th>ISP / AS</th><th>Last seen</th></tr></thead>
          <tbody>__ROWS__</tbody>
        </table>
      </div>
    </section>
  </div>

  <footer>
    Data generated __GENERATED__ · Geo data (c) DB-IP.com, CC BY 4.0.
    <a href="/api/public/bans">JSON API</a> ·
    <a href="/lists/community-bans.txt">Plain-text IP list</a>
    (<a href="/lists/community-bans.txt?severity=high">high severity only</a>) —
    add it to your firewall via the TuxWall custom blocklist.
    Built for dedicated Linux gateways.
  </footer>

  <script>
    const navToggle = document.getElementById('navToggle');
    const navLinks = document.getElementById('navLinks');
    function closeNav() {
      document.body.classList.remove('nav-open');
      navToggle.setAttribute('aria-expanded', 'false');
    }
    navToggle.addEventListener('click', () => {
      const open = document.body.classList.toggle('nav-open');
      navToggle.setAttribute('aria-expanded', open);
    });
    navLinks.addEventListener('click', e => {
      if (e.target.tagName === 'A') closeNav();
    });
    window.matchMedia('(min-width: 821px)').addEventListener('change', e => {
      if (e.matches) closeNav();
    });
  </script>

</body>
</html>
"""


IP_DETAIL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>IP __IP__ — Community Bans — TuxWall</title>
  <meta name="description" content="Community abuse report for __IP__: severity, hit counts, reports from independent TuxWall firewall installs, categories, and geolocation." />
  <meta name="robots" content="index, follow" />
  <link rel="canonical" href="https://tuxwall.org/ip/__IP__" />
  <meta name="theme-color" content="#0d0d0d" />
  <link rel="icon" href="/favicon.ico?v=2" sizes="16x16 32x32 48x48 64x64" />
  <link rel="icon" type="image/png" sizes="60x60" href="/images/tux-logo60.png?v=2" />
  <link rel="stylesheet" href="/css/style.css?v=20260830b" />
  <style>
    __PAGE_CSS__
  </style>
</head>
<body>

  <nav>
    <a class="nav-brand" href="https://tuxwall.org/">
      <img src="/images/tuxwall-small-white.png" alt="Tux" />
    </a>
    <ul class="nav-links" id="navLinks">
      <li><a href="https://tuxwall.org/">Home</a></li>
      <li><a class="active" href="/bans">Bans</a></li>
      <li><a href="/api/public/bans">JSON API</a></li>
      <li><a href="/lists/community-bans.txt">Ban List</a></li>
      <li><a class="nav-forum" href="https://github.com/rezzonance/tuxwall" target="_blank" rel="noopener">GitHub</a></li>
    </ul>
    <button class="nav-toggle" id="navToggle" aria-label="Toggle menu" aria-expanded="false" aria-controls="navLinks">
      <span></span><span></span><span></span>
    </button>
  </nav>

  <div class="page-main">
    <section class="section" style="padding-top:0;">
      <p class="section-label">// ip report</p>
      <div class="ip-head">
        <h2 class="section-title">__IP__</h2>
        __BADGE__
        <span class="ip-flag">__FLAG__</span>
      </div>
      <p class="section-desc"><a class="ip-link" href="/bans">« back to ban list</a><br>
         Community abuse report compiled from reports sent by participating TuxWall firewall installs.</p>
      __BODY__
    </section>
  </div>

  <footer>
    Verdicts and categories are self-reported by participating TuxWall installs and are not a guarantee.
    Geo data (c) DB-IP.com, CC BY 4.0.
    <a href="/api/public/bans">JSON API</a> · <a href="/bans">Ban list</a>.
    Built for dedicated Linux gateways.
  </footer>

  <script>
    const navToggle = document.getElementById('navToggle');
    const navLinks = document.getElementById('navLinks');
    function closeNav() {
      document.body.classList.remove('nav-open');
      navToggle.setAttribute('aria-expanded', 'false');
    }
    navToggle.addEventListener('click', () => {
      const open = document.body.classList.toggle('nav-open');
      navToggle.setAttribute('aria-expanded', open);
    });
    navLinks.addEventListener('click', e => {
      if (e.target.tagName === 'A') closeNav();
    });
    window.matchMedia('(min-width: 821px)').addEventListener('change', e => {
      if (e.matches) closeNav();
    });
  </script>

</body>
</html>
"""


def main():
    global STORE, LOG, _ingest_count
    STORE = Store(DB_PATH)
    LOG = queue.Queue(maxsize=500)
    _ingest_count = 0
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.socket.settimeout(5.0)
    print("tuxwall-collector listening on {}:{} db={}".format(
        LISTEN_HOST, LISTEN_PORT, DB_PATH), flush=True)

    def logger():
        while True:
            item = LOG.get()
            if item is None:
                break
            print(item, flush=True)

    threading.Thread(target=logger, daemon=True).start()

    def sweep():
        while True:
            time.sleep(6 * 3600)
            try:
                STORE.prune(time.time())
            except Exception as exc:
                print("prune failed: %r" % (exc,), flush=True)

    threading.Thread(target=sweep, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()