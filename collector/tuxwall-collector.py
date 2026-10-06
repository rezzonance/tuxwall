#!/usr/bin/env python3
"""tuxwall collector - community ban reporting service for tuxwall.org.

Receives ban reports from TuxWall firewall installs, aggregates them in
SQLite, enriches them with geo/ASN data, and serves:

  POST /report                   - ingest {key, ip, hits, reason, source,
                                   category?, suricata?: [{sig, count, sid}]}
  GET  /healthz                  - liveness probe
  GET  /api/public/bans          - JSON list of aggregated bans
  GET  /api/public/stats         - uncapped totals (ips, hits, countries, ...)
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


def severity_for(hits, reporters, deception=False):
    """Severity driven by how much of the community has been hit and how hard.

    Deception-source reports (canary/honeypot) are definitionally hostile -
    nothing legitimate connects to services that do not exist, so they carry
    zero false-positive potential. A single confirmed canary touch is a
    deliberate intrusion attempt (e.g. an SSH login with sprayed
    credentials), not recon noise - so deception evidence floors the entry
    at medium rather than letting volume alone speak.
    """
    if reporters >= 10 or hits >= 5000:
        return SEVERITY_CRITICAL
    if reporters >= 5 or hits >= 500:
        return SEVERITY_HIGH
    if reporters >= 2 or hits >= 50 or deception:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW

DECEPTION_SOURCES = ("canary", "honeypot")


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
CREATE TABLE IF NOT EXISTS suricata_evidence (
    ip TEXT NOT NULL,
    sig TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    last_ts REAL NOT NULL,
    PRIMARY KEY (ip, sig)
);
CREATE INDEX IF NOT EXISTS idx_suricata_evidence_ip ON suricata_evidence(ip);
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

    def ingest(self, reporter, ip, hits, reason, source, category, now,
               suricata=None):
        """Record a report. Returns "ok", "duplicate", or "error".

        suricata: optional list of {sig, count, sid} — meaningful Suricata
        alerts the reporter observed from this IP. Upserted per signature;
        count keeps the max so re-reports can't inflate it.
        """
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
            for item in (suricata or []):
                sig = str(item.get("sig") or "").strip()[:120]
                if not sig:
                    continue
                try:
                    cnt = max(1, min(MAX_HITS, int(item.get("count") or 1)))
                except (TypeError, ValueError):
                    cnt = 1
                self._conn.execute(
                    "INSERT INTO suricata_evidence (ip, sig, count, last_ts)"
                    " VALUES (?,?,?,?)"
                    " ON CONFLICT(ip, sig) DO UPDATE SET"
                    " count = MAX(count, excluded.count),"
                    " last_ts = excluded.last_ts",
                    (ip, sig, cnt, now))
            self._conn.commit()
        return "ok"

    def prune(self, now):
        cutoff = now - RETENTION_DAYS * 86400
        with self.lock:
            self._conn.execute("DELETE FROM reports WHERE last_seen < ?", (cutoff,))
            self._conn.execute(
                "DELETE FROM report_reports WHERE last_seen < ?", (cutoff,))
            self._conn.execute(
                "DELETE FROM suricata_evidence WHERE last_ts < ?", (cutoff,))
            self._conn.commit()
            # Long-running service: checkpoint the WAL so it never grows
            # unbounded between restarts.
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass

    def remove_ip(self, ip):
        """Admin removal: purge an IP from every table. Returns deleted row
        counts per table so the caller can tell a hit from a no-op."""
        with self.lock:
            counts = {}
            for table in ("reports", "report_reports", "report_events",
                          "suricata_evidence"):
                cur = self._conn.execute(f"DELETE FROM {table} WHERE ip=?", (ip,))
                counts[table] = cur.rowcount if cur.rowcount >= 0 else 0
            self._conn.commit()
        return counts

    def top_bans(self, min_severity=0, tier=None, limit=500, before=None,
                 order="hits"):
        """Aggregate ban rows ordered by hit count (default) or newest first.

        min_severity: keep rows at rank >= this (a "at least this bad" filter).
        tier:         keep only rows whose severity is EXACTLY this tier.
        before:       keyset cursor (last_seen, ip) - return only rows older
                      than it. Stable under inserts: browsing page 2 never
                      re-shows or skips rows when new bans arrive mid-browse.
        order:        "hits" (default) or "recent" (last_seen DESC, ip DESC).
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
        if before is not None:
            where.append("(r.last_seen, r.ip) < (?, ?)")
            args += [before[0], before[1]]
        with self.lock:
            cur = self._conn.execute(
                "WITH counts AS (SELECT ip, COUNT(*) AS reporters"
                "   FROM report_reports GROUP BY ip)"
                " SELECT r.ip, r.hits, r.first_seen, r.last_seen, r.country, r.iso,"
                " r.city, r.isp, r.asn, r.last_source,"
                " COALESCE(c.reporters, 0) AS reporters"
                " FROM reports r LEFT JOIN counts c ON c.ip = r.ip"
                " WHERE " + " AND ".join(where)
                + (" ORDER BY r.last_seen DESC, r.ip DESC LIMIT ?"
                   if order == "recent" else
                   " ORDER BY r.hits DESC LIMIT ?"),
                tuple(args) + (limit,))
            rows = cur.fetchall()
        bans = []
        for (ip, hits, first_seen, last_seen, country, iso, city, isp, asn,
             last_source, reporters) in rows:
            sev = severity_for(hits, reporters,
                              deception=last_source in DECEPTION_SOURCES)
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
            "last_reason": last_reason,
            "last_source": last_source,
            "severity": severity_for(
                hits, reporters,
                deception=any(s in DECEPTION_SOURCES for s, _ in srcs)),
            "categories": {c: {"hits": h, "reports": n} for c, h, n in cats},
            "sources": {s: n for s, n in srcs},
            "suricata": [
                {"sig": sg, "count": c, "last_ts": t}
                for sg, c, t in self._conn.execute(
                    "SELECT sig, count, last_ts FROM suricata_evidence"
                    " WHERE ip=? ORDER BY count DESC, last_ts DESC LIMIT 10",
                    (ip,)).fetchall()],
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

    def public_stats(self):
        """Uncapped aggregate counts over the active (in-retention) ban set,
        for /api/public/stats. Reporter identities are never exposed, only
        the distinct count."""
        cutoff = time.time() - RETENTION_DAYS * 86400
        with self.lock:
            ips, hits, countries, last_seen = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(hits),0),"
                " COUNT(DISTINCT NULLIF(iso,'')), MAX(last_seen)"
                " FROM reports WHERE last_seen > ?", (cutoff,)).fetchone()
            reporters = self._conn.execute(
                "SELECT COUNT(DISTINCT rr.reporter) FROM report_reports rr"
                " JOIN reports r ON r.ip = rr.ip WHERE r.last_seen > ?",
                (cutoff,)).fetchone()[0]
        return {"ips": ips, "hits": hits, "countries": countries,
                "reporters": reporters, "last_seen": last_seen,
                "retention_days": RETENTION_DAYS}


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
        # Defense-in-depth: admin is loopback-only by design. nginx always
        # sets X-Real-IP / X-Forwarded-For when proxying, so any request
        # carrying them arrived via a proxy rather than from the local
        # host - refuse regardless of key, so no future nginx change can
        # ever expose the admin endpoints behind the key gate alone.
        if (self.headers.get("X-Real-IP")
                or self.headers.get("X-Forwarded-For")):
            return False
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
        if path == "/api/public/bans/more":
            # Load-more fragment for the /bans table: keyset pagination.
            # Public like the table it feeds; the /api/public/ nginx
            # location's rate limit applies. Requires a valid cursor.
            try:
                before = float((params.get("before") or ["0"])[0])
            except (TypeError, ValueError):
                before = 0.0
            cursor_ip = ((params.get("ip") or [""])[0] or "").strip()
            try:
                if cursor_ip and ipaddress.ip_address(cursor_ip).version not in (4, 6):
                    cursor_ip = ""
            except ValueError:
                cursor_ip = ""
            if not before or not cursor_ip:
                self._json(400, {"ok": False,
                                 "error": "Valid before+ip cursor required"})
                return
            try:
                sev = (params.get("severity") or ["all"])[0] or "all"
                if sev != "all":
                    severity_rank(sev)
            except Exception:
                sev = "all"
            rank = 0 if sev == "all" else max(0, severity_rank(sev))
            tier = sev if sev != "all" else None
            PAGE = 2000
            bans = _store().top_bans(min_severity=rank, tier=tier, limit=PAGE + 1,
                                     order="recent", before=(before, cursor_ip))
            more = len(bans) > PAGE
            bans = bans[:PAGE]
            # hit-bar scaling: consistent with the page, use the global max
            top1 = _store().top_bans(limit=1)
            max_hits = (top1[0]["hits"] if top1 else 1) or 1
            now = time.time()
            rows = "".join(_bans_row_html(b, max_hits, now) for b in bans)
            out = {"ok": True, "count": len(bans), "more": more,
                   "rows": rows}
            if more and bans:
                # exact float repr - %.6f can round UP, which would make
                # the cursor row itself compare as "older" and duplicate
                out["next_before"] = str(bans[-1]["last_seen"] or 0)
                out["next_ip"] = bans[-1]["ip"]
            self._json(200, out)
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
        if path == "/api/public/stats":
            self._json(200, dict(_store().public_stats(), ok=True,
                                 generated=datetime.now(timezone.utc).isoformat()))
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

        # Optional Suricata evidence from the reporter's IDS: top signatures
        # observed from this IP. Bounded — anything malformed is dropped.
        suricata = []
        raw_sur = body.get("suricata")
        if isinstance(raw_sur, list):
            for item in raw_sur[:5]:
                if not isinstance(item, dict):
                    continue
                sig = str(item.get("sig") or "").strip()[:120]
                if not sig:
                    continue
                try:
                    cnt = max(1, min(MAX_HITS, int(item.get("count") or 1)))
                except (TypeError, ValueError):
                    cnt = 1
                try:
                    sid = int(item.get("sid") or 0)
                except (TypeError, ValueError):
                    sid = 0
                suricata.append({"sig": sig, "count": cnt, "sid": sid})

        reporter = hashlib.sha256(key.encode("utf-8")).hexdigest()
        now = time.time()
        if not RATE.allow(reporter, now):
            self._json(429, {"ok": False, "error": "Rate limit exceeded"})
            return

        result = _store().ingest(reporter, ip, hits, reason, source, category,
                                 now, suricata)

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


def fmt_ago(ts, now=None):
    """Compact relative time ("4m ago", "3h ago", "2d ago")."""
    try:
        delta = max(0, int((now or time.time()) - float(ts)))
    except (TypeError, ValueError):
        return "—"
    if delta < 60:
        return "just now"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if delta >= size:
            return "%d%s ago" % (delta // size, unit)
    return "just now"


def _fmt_utc(ts):
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ""


def _top_counts(items, n):
    counts = defaultdict(int)
    for k in items:
        if k:
            counts[k] += 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def _bar_list(pairs, label_fn):
    if not pairs:
        return "<p class='muted empty-sm'>Not enough data yet.</p>"
    top = pairs[0][1] or 1
    return "".join(
        "<div class='rank-row'><span class='rank-k'>%s</span>"
        "<span class='rank-bar'><i style='width:%.0f%%'></i></span>"
        "<span class='rank-n'>%s</span></div>"
        % (label_fn(k), v * 100.0 / top, fmt_num(v))
        for k, v in pairs)


def _bans_row_html(b, max_hits, now):
    """One <tr> of the /bans table. Shared by the page render and the
    load-more fragment endpoint so appended rows match exactly."""
    loc = " • ".join(x for x in (b["city"], b["country"]) if x) or "Unknown"
    isp = _esc(b["isp"] or "")
    search = " ".join(x for x in (b["ip"], b["city"], b["country"], b["iso"],
                                  b["isp"], b["asn"], b["severity"]) if x).lower()
    try:
        a = ipaddress.ip_address(b["ip"])
        ip_key = "%d-%s" % (a.version, a.packed.hex().zfill(32))
    except ValueError:
        ip_key = b["ip"]
    try:
        sev_key = severity_rank(b["severity"])
    except ValueError:
        sev_key = 0
    return (
        f"<tr data-search='{_esc(search)}'>"
        f"<td class='mono' data-v='{ip_key}'><a class='ip-link' href='/ip/{_esc(b['ip'])}'>{_esc(b['ip'])}</a></td>"
        f"<td data-v='{sev_key}'>{render_severity_badge(b['severity'])}</td>"
        f"<td class='hits-cell' data-v='{int(b['hits'] or 0)}'><span class='hits-n'>{fmt_num(b['hits'])}</span>"
        f"<span class='hits-bar'><i style='width:{b['hits'] * 100.0 / max_hits:.0f}%'></i></span></td>"
        f"<td class='num-cell' data-v='{int(b['reporters'] or 0)}'>{fmt_num(b['reporters'])}</td>"
        f"<td data-v='{_esc(loc.lower())}'><span class='flag'>{_flag_emoji(b['iso'])}</span> {_esc(loc)}</td>"
        f"<td class='muted isp-cell' title='{isp}' data-v='{isp.lower()}'>{isp or '—'}"
        + (f" <span class='asn'>AS{_esc(b['asn'])}</span>" if b.get('asn') else "")
        + "</td>"
        f"<td class='mono muted' title='{_fmt_utc(b['last_seen'])}' data-v='{float(b['last_seen'] or 0):.0f}'>{fmt_ago(b['last_seen'], now)}</td>"
        "</tr>"
    )


def render_bans_page(sev="all"):
    # Every active ban, used for the page-wide aggregates (distribution,
    # countries, networks). The table itself shows the top 100 for the
    # selected tier.
    all_bans = _store().top_bans(min_severity=0, limit=5000)
    if sev != "all":
        try:
            severity_rank(sev)
        except ValueError:
            sev = "all"
    # Table rows: newest reports first so freshly reported bans are
    # immediately visible (the client-side sort re-orders on demand).
    # Capped at 500 rows for page weight; the aggregates above still use
    # the full set. Was: top 100 by hits, which hid new single-hit bans
    # below the cut even though the txt list and JSON API carried them.
    rows_all = sorted(all_bans,
                     key=lambda b: (b.get("last_seen") or 0), reverse=True)
    if sev != "all":
        rows_all = [b for b in rows_all if b["severity"] == sev]
    bans = rows_all[:2000]
    stats = _store().stats()
    now = time.time()

    # Severity distribution bar
    dist = {k: 0 for k in SEVERITY_ORDER}
    for b in all_bans:
        dist[b["severity"] if b["severity"] in dist else SEVERITY_LOW] += 1
    total_active = len(all_bans) or 1
    dist_bar = "".join(
        "<a class='dist-seg dist-%s' href='/bans?severity=%s' style='flex-grow:%d'"
        " title='%s: %s IPs'></a>" % (k, k, dist[k], k.title(), fmt_num(dist[k]))
        for k in reversed(SEVERITY_ORDER) if dist[k])
    dist_legend = "".join(
        "<span class='dist-key'><i class='dist-%s'></i>%s <b>%s</b> <em>%.0f%%</em></span>"
        % (k, k.title(), fmt_num(dist[k]), dist[k] * 100.0 / total_active)
        for k in reversed(SEVERITY_ORDER))

    iso_name = {}
    for b in all_bans:
        if b["iso"] and b["country"]:
            iso_name.setdefault(b["iso"], b["country"])
    countries = _top_counts((b["iso"] for b in all_bans), 6)
    networks = _top_counts((b["isp"] for b in all_bans), 6)
    n_countries = len({b["iso"] for b in all_bans if b["iso"]})
    last_ts = max((b["last_seen"] or 0 for b in all_bans), default=0)

    max_hits = max((b["hits"] for b in bans), default=1) or 1
    body = "".join(_bans_row_html(b, max_hits, now) for b in bans) or (
        "<tr><td colspan='7' class='empty'>No community bans yet. "
        "Installations that opt in to ban reporting will appear here.</td></tr>")
    # Keyset pagination: the rendered slice ends at (last_seen, ip) of its
    # last row; older rows load on demand. Aggregates above stay full-set.
    loadmore = ""
    if len(rows_all) > len(bans) and bans:
        last = bans[-1]
        remaining = len(rows_all) - len(bans)
        loadmore = (
            "<div class='load-more' id='loadMoreWrap' "
            "style='text-align:center;padding:18px 0 8px;'>"
            "<button type='button' id='loadMoreBtn' "
            "class='filter-badge' "
            f"data-before='{last['last_seen'] or 0}' "
            f"data-ip='{_esc(last['ip'])}' data-sev='{_esc(sev)}'>"
            f"Load more ({fmt_num(remaining)} older)</button></div>")
    filters = "".join(
        _filter_badge(s, (s.title() if s != "all" else "All")
                      + " <span class='cnt'>%s</span>" % fmt_num(
                          len(all_bans) if s == "all" else dist[s]),
                      s == sev)
        for s in ["all"] + SEVERITY_ORDER)
    showing = "Top %d of %s" % (len(bans), fmt_num(
        len(all_bans) if sev == "all" else dist.get(sev, 0)))
    return (HTML_TEMPLATE
            .replace("__TOTAL__", str(int(stats["ips"] or 0)))
            .replace("__HITS__", str(int(stats["hits"] or 0)))
            .replace("__REPORTERS__", str(int(stats["reporters"] or 0)))
            .replace("__COUNTRIES__", str(n_countries))
            .replace("__LAST_ACTIVITY__", fmt_ago(last_ts, now) if last_ts else "—")
            .replace("__DIST_BAR__", dist_bar)
            .replace("__DIST_LEGEND__", dist_legend)
            .replace("__TOP_COUNTRIES__", _bar_list(
                countries, lambda k: "%s %s" % (_flag_emoji(k), _esc(iso_name.get(k, k)))))
            .replace("__TOP_NETWORKS__", _bar_list(networks, _esc))
            .replace("__SHOWING__", showing)
            .replace("__FILTERS__", filters)
            .replace("__ROWS__", body)
            .replace("__LOADMORE__", loadmore)
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

    # Suricata signatures reported by participating installs (their IDS
    # alerts observed from this IP). Absent when no install had evidence.
    sur_rows = "".join(
        "<div class='kv'><span class='k mono'>%s</span>"
        "<span class='v'>%s alert%s</span></div>"
        % (_esc(s["sig"]), fmt_num(s["count"]), "s" if s["count"] != 1 else "")
        for s in (d.get("suricata") or []))
    sur_card = ""
    if sur_rows:
        sur_card = ("<div class='detail-card' style='margin-bottom:2rem;'>"
                    "<h3>Suricata signatures observed</h3>%s"
                    "<p class='muted' style='font-size:0.72rem;margin:0.6rem 0 0;'>"
                    "IDS signatures seen by reporting TuxWall installs."
                    "</p></div>" % sur_rows)

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
        "<div class='stat-card'><div class='num' data-count='__TOTAL_RAW__'>__TOTAL__</div><div class='lbl'>Total hits</div></div>"
        "<div class='stat-card'><div class='num'>__REPORTERS__</div><div class='lbl'>Reporting installs</div></div>"
        "<div class='stat-card'><div class='num'>__FIRST_SEEN__</div><div class='lbl'>First seen</div></div>"
        "<div class='stat-card'><div class='num' title='__LAST_SEEN_UTC__'>__LAST_SEEN__</div><div class='lbl'>Last seen</div></div>"
        "</div>"
        "<p class='verdict__VERDICT_CLS__'>__VERDICT__</p>"
        "<div class='lookups'><span>Look up elsewhere:</span>"
        "<a href='https://www.abuseipdb.com/check/__IP__' target='_blank' rel='noopener nofollow'>AbuseIPDB</a>"
        "<a href='https://www.shodan.io/host/__IP__' target='_blank' rel='noopener nofollow'>Shodan</a>"
        "<a href='https://bgp.he.net/ip/__IP__' target='_blank' rel='noopener nofollow'>bgp.he.net</a>"
        "<a href='https://ipinfo.io/__IP__' target='_blank' rel='noopener nofollow'>ipinfo</a>"
        "<a href='/api/public/bans/__IP__'>JSON</a>"
        "</div>"
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
        "__SURICATA__"
        "<div class='table-wrap'><table class='deps-table'>"
        "<thead><tr><th>Time (UTC)</th><th>Install</th><th>Severity</th>"
        "<th>Category</th><th>Hits</th></tr></thead>"
        "<tbody>__ROWS__</tbody></table></div>")

    return (IP_DETAIL_TEMPLATE
            .replace("__BODY__", body)
            .replace("__IP__", _esc(d["ip"]))
            .replace("__BADGE__", render_severity_badge(sev))
            .replace("__FLAG__", flag)
            .replace("__IP_LOCATION__", _esc(loc))
            .replace("__ISP__", _esc(d["isp"]) or "—")
            .replace("__ASN__", _esc(d["asn"]) or "—")
            .replace("__LAST_REASON__", _esc(d["last_reason"]) or "—")
            .replace("__TOTAL__", fmt_num(d["hits"]))
            .replace("__REPORTERS__", fmt_num(d["reporters"]))
            .replace("__FIRST_SEEN__", fmt_date(d["first_seen"]))
            .replace("__LAST_SEEN_UTC__", _fmt_utc(d["last_seen"]))
            .replace("__LAST_SEEN__", fmt_ago(d["last_seen"]))
            .replace("__TOTAL_RAW__", str(int(d["hits"] or 0)))
            .replace("__VERDICT_CLS__", "" if d["reporters"] > 1 else " solo")
            .replace("__VERDICT__", verdict)
            .replace("__CATS__", cat_rows)
            .replace("__SOURCES__", srcs)
            .replace("__SURICATA__", sur_card)
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
    .page-main .section { padding-left: 0; padding-right: 0; }
    .nav-links a.active { color: var(--green); }

    /* header */
    .live-pill { display: inline-flex; align-items: center; gap: 0.5rem;
                 font-family: var(--mono, monospace); font-size: 0.7rem;
                 letter-spacing: 0.15em; text-transform: uppercase; color: #ff7b72;
                 border: 1px solid rgba(255,95,87,0.35); background: rgba(255,60,60,0.06);
                 border-radius: 999px; padding: 0.25rem 0.8rem; margin-bottom: 1rem; }
    .live-dot { width: 8px; height: 8px; border-radius: 50%; background: #ff5f57;
                animation: live-ping 1.8s ease-out infinite; }
    @keyframes live-ping { 0% { box-shadow: 0 0 0 0 rgba(255,95,87,0.6); }
                           100% { box-shadow: 0 0 0 10px rgba(255,95,87,0); } }
    .page-title { font-size: clamp(2rem, 5vw, 3rem); line-height: 1.1; margin-bottom: 0.75rem; }
    .page-title span { color: var(--green); }

    /* stat cards */
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
             gap: 1rem; margin: 2rem 0; }
    .stat-card { background: var(--card); border: 1px solid var(--border);
                 border-radius: 6px; padding: 1.1rem 1.3rem; position: relative; overflow: hidden; }
    .stat-card::before { content: ''; position: absolute; left: 0; top: 0; right: 0; height: 2px;
                         background: linear-gradient(90deg, var(--green), transparent); }
    .stat-card.red::before { background: linear-gradient(90deg, #ff5f57, transparent); }
    .stat-card .num { font-family: var(--mono, monospace); font-size: 1.7rem; color: var(--green);
                      font-weight: bold; font-variant-numeric: tabular-nums; line-height: 1.2; }
    .stat-card.red .num { color: #ff7b72; }
    .stat-card .lbl { font-size: 0.72rem; letter-spacing: 0.1em; text-transform: uppercase;
                      color: var(--muted); margin-top: 4px; }

    /* severity distribution */
    .dist { margin: 0 0 2rem; }
    .dist-bar { display: flex; height: 12px; border-radius: 6px; overflow: hidden;
                background: #0a0a0a; border: 1px solid var(--border); gap: 2px; }
    .dist-seg { display: block; min-width: 6px; transition: filter 0.2s; }
    .dist-seg:hover { filter: brightness(1.3); }
    .dist-legend { display: flex; flex-wrap: wrap; gap: 0.4rem 1.4rem; margin-top: 0.7rem;
                   font-size: 0.85rem; color: var(--muted); }
    .dist-key { display: inline-flex; align-items: center; gap: 0.4rem; }
    .dist-key i { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
    .dist-key b { color: var(--text); font-weight: 600; }
    .dist-key em { font-style: normal; opacity: 0.7; }
    .dist-low { background: #39ff14; } .dist-medium { background: #f0a500; }
    .dist-high { background: #f97316; } .dist-critical { background: #ef4444; }

    /* insight panels */
    .insights { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(300px, 100%), 1fr));
                gap: 1rem; margin: 0 0 2.5rem; }
    .panel { background: var(--card); border: 1px solid var(--border); border-radius: 6px;
             padding: 1.2rem 1.4rem; }
    .panel h3 { font-family: var(--mono, monospace); color: var(--white); font-size: 0.8rem;
                letter-spacing: 0.12em; text-transform: uppercase; margin: 0 0 0.9rem; }
    .rank-row { display: grid; grid-template-columns: minmax(0, 11rem) 1fr 3rem; gap: 0.7rem;
                align-items: center; padding: 0.28rem 0; font-size: 0.88rem; }
    .rank-k { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text); }
    .rank-bar { height: 6px; background: #0a0a0a; border-radius: 3px; overflow: hidden; }
    .rank-bar i { display: block; height: 100%; border-radius: 3px;
                  background: linear-gradient(90deg, var(--dimgreen), var(--green)); }
    .rank-n { text-align: right; color: var(--muted); font-variant-numeric: tabular-nums; }
    .empty-sm { font-size: 0.85rem; }

    /* use-this-list callout */
    .use-list { display: grid; grid-template-columns: 1fr auto; gap: 1rem 2rem; align-items: center;
                border: 1px solid var(--dimgreen); border-radius: 6px; padding: 1.3rem 1.5rem;
                margin: 0 0 2.5rem;
                background: linear-gradient(135deg, rgba(57,255,20,0.07), rgba(57,255,20,0.01)); }
    .use-list h3 { color: var(--white); font-size: 1.05rem; margin-bottom: 0.3rem; }
    .use-list p { color: var(--muted); font-size: 0.92rem; margin: 0; }
    .use-list .cmd { grid-column: 1 / -1; display: flex; align-items: center; gap: 0.75rem;
                     background: rgba(0,0,0,0.5); border: 1px solid var(--border); border-radius: 4px;
                     padding: 0.5rem 0.5rem 0.5rem 0.9rem; font-family: var(--mono, monospace);
                     font-size: 0.82rem; }
    .use-list .cmd code { flex: 1; overflow-x: auto; white-space: nowrap; background: none;
                          padding: 0; color: var(--text); }
    .use-list .actions { display: flex; gap: 0.6rem; flex-wrap: wrap; }
    @media (max-width: 700px) { .use-list { grid-template-columns: 1fr; } }
    .copy-btn { flex-shrink: 0; font-family: var(--mono, monospace); font-size: 0.72rem;
                letter-spacing: 0.08em; text-transform: uppercase; color: var(--green);
                background: rgba(57,255,20,0.08); border: 1px solid var(--dimgreen);
                border-radius: 4px; padding: 0.35rem 0.7rem; cursor: pointer; }
    .copy-btn:hover, .copy-btn.copied { background: var(--green); color: #000; }

    /* table toolbar */
    .toolbar { display: flex; flex-wrap: wrap; gap: 0.8rem 1.2rem; align-items: center;
               justify-content: space-between; margin: 0 0 1rem; }
    .filters { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
    .filters .fl { font-size: 0.7rem; letter-spacing: 0.2em; text-transform: uppercase;
                   color: var(--muted); margin-right: 0.25rem; }
    .filters .badge { text-decoration: none; cursor: pointer; }
    .filters .badge .cnt { opacity: 0.65; margin-left: 0.2rem; }
    .filters .badge.cur { background: var(--green); color: #000;
                          border-color: var(--green); font-weight: bold; }
    .search { flex: 0 1 300px; display: flex; align-items: center; gap: 0.5rem;
              background: var(--card); border: 1px solid var(--border); border-radius: 4px;
              padding: 0 0.75rem; }
    .search:focus-within { border-color: var(--dimgreen); }
    .search svg { flex-shrink: 0; opacity: 0.6; }
    .search input { flex: 1; min-width: 0; background: none; border: none; outline: none;
                    color: var(--text); font: inherit; font-size: 0.9rem; padding: 0.5rem 0; }
    .table-meta { font-size: 0.8rem; color: var(--muted); margin: 0 0 0.6rem; }

    /* table */
    .table-wrap { overflow-x: auto; background: var(--card); border: 1px solid var(--border);
                  border-radius: 6px; }
    .table-wrap .deps-table { margin-top: 0; }
    .deps-table thead th { position: sticky; top: 0; background: #121212; }
    .deps-table td { vertical-align: middle; }
    .deps-table th[data-sort] button { all: unset; cursor: pointer; display: inline-flex;
                                       align-items: center; gap: 0.35rem; color: inherit;
                                       font: inherit; letter-spacing: inherit; text-transform: inherit; }
    .deps-table th[data-sort] button::after { content: '↕'; opacity: 0.35; font-size: 0.85em; }
    .deps-table th[aria-sort="ascending"] button::after { content: '↑'; opacity: 1; }
    .deps-table th[aria-sort="descending"] button::after { content: '↓'; opacity: 1; }
    .deps-table th[data-sort] button:hover { color: var(--white); }
    .deps-table th[data-sort] button:focus-visible { outline: 2px solid var(--green); outline-offset: 2px; }
    .deps-table tbody tr { transition: background 0.15s; }
    .deps-table tbody tr:hover td { background: rgba(57,255,20,0.04); }
    .hits-cell { min-width: 110px; }
    .hits-n { font-variant-numeric: tabular-nums; }
    .hits-bar { display: block; height: 3px; margin-top: 4px; background: #0a0a0a;
                border-radius: 2px; overflow: hidden; }
    .hits-bar i { display: block; height: 100%; background: var(--dimgreen); }
    .num-cell { font-variant-numeric: tabular-nums; text-align: center; }
    .isp-cell { max-width: 240px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .asn { font-family: var(--mono, monospace); font-size: 0.7rem; opacity: 0.7; }
    .flag { font-size: 1.05rem; }
    .no-match { display: none; }
    .no-match.show { display: table-row; }

    .mono { font-family: var(--mono, ui-monospace, monospace); font-size: 0.8rem; }
    .muted { color: var(--muted); }
    .sev { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 3px;
           font-family: var(--mono, monospace); font-size: 0.66rem; letter-spacing: 0.1em;
           text-transform: uppercase; border: 1px solid transparent; font-weight: 600; }
    .sev-low      { color: #39ff14; border-color: #1a7a00; background: rgba(57,255,20,0.06); }
    .sev-medium   { color: #f0a500; border-color: #b8860b; background: rgba(240,165,0,0.07); }
    .sev-high     { color: #fb923c; border-color: #ea580c; background: rgba(249,115,22,0.08); }
    .sev-critical { color: #f87171; border-color: #b91c1c; background: rgba(239,68,68,0.1); }
    .empty { text-align: center; color: var(--muted); padding: 2rem 1rem; }
    .ip-link { color: var(--green); text-decoration: none; }
    .ip-link:hover { text-decoration: underline; }

    /* ip report page */
    .ip-head { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
    .ip-head .section-title { margin-bottom: 0; font-size: clamp(1.6rem, 4vw, 2.4rem); }
    .ip-flag { font-size: 1.6rem; line-height: 1; }
    .verdict { color: var(--text); font-size: 1rem; border-left: 3px solid var(--green);
               padding: 0.6rem 1rem; background: rgba(57,255,20,0.04); margin: 0 0 1.5rem; }
    .verdict.solo { border-left-color: #f0a500; background: rgba(240,165,0,0.05); }
    .lookups { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center;
               margin: 0 0 2rem; font-size: 0.85rem; color: var(--muted); }
    .lookups a { color: var(--text); text-decoration: none; border: 1px solid var(--border);
                 border-radius: 4px; padding: 0.25rem 0.7rem; transition: border-color 0.2s; }
    .lookups a:hover { border-color: var(--green); color: var(--green); }
    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 0 0 2rem; }
    @media (max-width: 700px) { .detail-grid { grid-template-columns: 1fr; } }
    .detail-card { background: var(--card); border: 1px solid var(--border);
                   border-radius: 6px; padding: 1.2rem 1.4rem; }
    .detail-card h3 { font-family: var(--mono, monospace); color: var(--white); font-size: 0.8rem;
                      letter-spacing: 0.12em; text-transform: uppercase; margin: 0 0 0.9rem; }
    .kv { display: flex; justify-content: space-between; gap: 1rem; padding: 0.4rem 0;
          border-bottom: 1px solid var(--border); font-size: 0.92rem; }
    .kv:last-child { border-bottom: none; }
    .kv .k { color: var(--muted); text-transform: uppercase; font-size: 0.7rem;
             letter-spacing: 0.1em; padding-top: 0.15rem; }
    .kv .v { color: var(--text); text-align: right; word-break: break-word; }
    .cat-row { display: grid; grid-template-columns: 130px 1fr 110px; align-items: center;
               gap: 0.6rem; padding: 0.3rem 0; }
    .cat-row .k { color: var(--text); font-size: 0.85rem; }
    .cat-row .bar { height: 6px; background: #0a0a0a; border-radius: 3px; overflow: hidden; }
    .cat-row .bar i { display: block; height: 100%; border-radius: 3px;
                      background: linear-gradient(90deg, var(--dimgreen), var(--green)); }
    .cat-row .n { text-align: right; color: var(--muted); font-size: 0.78rem; }

    @media (max-width: 600px) {
      .page-main { padding: 5rem 1.25rem 0; }
      .search { flex: 1 1 100%; }
    }
    @media (prefers-reduced-motion: reduce) { .live-dot { animation: none; } }"""


NAV_HTML = """<nav>
    <a class="nav-brand" href="https://tuxwall.org/">
      <img src="/images/tuxwall-nav.png" alt="TuxWall" width="114" height="38"
           onerror="this.onerror=null;this.src='/images/tuxwall-small-white.png'" />
    </a>
    <ul class="nav-links" id="navLinks">
      <li><a href="https://tuxwall.org/">Home</a></li>
      <li><a href="https://tuxwall.org/#features">Features</a></li>
      <li><a href="https://tuxwall.org/#install">Install</a></li>
      <li><a href="https://tuxwall.org/configs.html">Configs</a></li>
      <li class="has-dropdown">
        <a class="dropdown-toggle active" href="/bans" aria-haspopup="true">Community Bans ▾</a>
        <ul class="dropdown">
          <li><a href="/api/public/bans">JSON</a></li>
          <li><a href="/lists/community-bans.txt">Ban List</a></li>
        </ul>
      </li>
      <li><a class="nav-forum" href="https://forum.tuxwall.org">Forum</a></li>
    </ul>
    <button class="nav-toggle" id="navToggle" aria-label="Toggle menu" aria-expanded="false" aria-controls="navLinks">
      <span></span><span></span><span></span>
    </button>
  </nav>"""


NAV_JS = """
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

    // Copy buttons: <button class="copy-btn" data-copy="text">
    document.querySelectorAll('.copy-btn[data-copy]').forEach(btn => {
      btn.addEventListener('click', () => {
        const text = btn.dataset.copy;
        const done = msg => { const o = btn.textContent; btn.textContent = msg;
          btn.classList.add('copied');
          setTimeout(() => { btn.textContent = o; btn.classList.remove('copied'); }, 1500); };
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(text).then(() => done('Copied!'), () => done('Failed'));
        } else {
          const ta = document.createElement('textarea'); ta.value = text;
          document.body.appendChild(ta); ta.select();
          try { document.execCommand('copy'); done('Copied!'); } catch (e) { done('Failed'); }
          ta.remove();
        }
      });
    });

    // Count-up for stat numbers: <div class="num" data-count="1234">
    (function () {
      const els = document.querySelectorAll('[data-count]');
      const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      els.forEach(el => {
        const target = parseInt(el.dataset.count, 10) || 0;
        if (reduce || target < 10) { el.textContent = target.toLocaleString(); return; }
        const start = performance.now(), dur = 1200;
        (function tick(now) {
          const t = Math.min((now - start) / dur, 1);
          el.textContent = Math.round(target * (1 - Math.pow(1 - t, 3))).toLocaleString();
          if (t < 1) requestAnimationFrame(tick);
        })(start);
      });
    })();
"""


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Community Bans — TuxWall</title>
  <meta name="description" content="IPs reported as banned by participating TuxWall firewall installs, with hit counts, severity, and geolocation. Powered by the TuxWall community ban network." />
  <meta name="robots" content="index, follow" />
  <link rel="canonical" href="https://tuxwall.org/bans" />
  <meta property="og:type" content="website" />
  <meta property="og:title" content="TuxWall Community Bans" />
  <meta property="og:description" content="A live, free blocklist of attacker IPs reported by TuxWall firewalls around the world." />
  <meta property="og:url" content="https://tuxwall.org/bans" />
  <meta property="og:image" content="https://tuxwall.org/images/og-image.jpg" />
  <meta name="theme-color" content="#0d0d0d" />
  <link rel="icon" href="/favicon.ico?v=2" sizes="16x16 32x32 48x48 64x64" />
  <link rel="icon" type="image/png" sizes="60x60" href="/images/tux-logo60.png?v=2" />
  <link rel="stylesheet" href="/css/style.css?v=20261004-2" />
  <style>
    __PAGE_CSS__
  </style>
</head>
<body>

  __NAV__

  <main class="page-main">
    <section class="section" style="padding-top:0;">
      <span class="live-pill"><span class="live-dot"></span> Live · last report __LAST_ACTIVITY__</span>
      <h1 class="page-title section-title">Community <span>Bans</span></h1>
      <p class="section-desc">Attackers caught by TuxWall firewalls around the world, aggregated into one free blocklist.
         Severity grows with the number of hits and how many independent installs reported the same source.</p>

      <div class="stats">
        <div class="stat-card red"><div class="num" data-count="__TOTAL__">__TOTAL__</div><div class="lbl">Unique attacker IPs</div></div>
        <div class="stat-card red"><div class="num" data-count="__HITS__">__HITS__</div><div class="lbl">Reported hits</div></div>
        <div class="stat-card"><div class="num" data-count="__COUNTRIES__">__COUNTRIES__</div><div class="lbl">Countries of origin</div></div>
        <div class="stat-card"><div class="num" data-count="__REPORTERS__">__REPORTERS__</div><div class="lbl">Reporting installs</div></div>
      </div>

      <div class="dist">
        <div class="dist-bar">__DIST_BAR__</div>
        <div class="dist-legend">__DIST_LEGEND__</div>
      </div>

      <div class="insights">
        <div class="panel"><h3>Top countries</h3>__TOP_COUNTRIES__</div>
        <div class="panel"><h3>Top networks</h3>__TOP_NETWORKS__</div>
      </div>

      <div class="use-list">
        <div>
          <h3>Block them on your own firewall</h3>
          <p>Add the plain-text list to the TuxWall custom blocklist, or to any firewall that accepts an IP list URL. It updates continuously.</p>
        </div>
        <div class="actions">
          <a class="btn btn-outline" href="/lists/community-bans.txt">All IPs</a>
          <a class="btn btn-outline" href="/lists/community-bans.txt?severity=high">High+ only</a>
          <a class="btn btn-outline" href="/api/public/bans">JSON</a>
        </div>
        <div class="cmd">
          <code>https://tuxwall.org/lists/community-bans.txt</code>
          <button class="copy-btn" data-copy="https://tuxwall.org/lists/community-bans.txt">Copy URL</button>
        </div>
      </div>

      <div class="toolbar">
        <div class="filters">
          <span class="fl">Severity:</span>
          __FILTERS__
        </div>
        <label class="search">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
          <input id="banSearch" type="search" placeholder="Filter by IP, country, ISP…" aria-label="Filter bans" autocomplete="off" />
        </label>
      </div>
      <p class="table-meta"><span id="tableCount">__SHOWING__</span> · <span id="sortLabel">sorted by hits ↓</span> · click a column to sort · hover a time for the exact UTC timestamp</p>

      <div class="table-wrap">
        <table class="deps-table" id="banTable">
          <thead><tr>
            <th data-sort="ip" aria-sort="none"><button type="button">IP</button></th>
            <th data-sort="num" data-first="desc" aria-sort="none"><button type="button">Severity</button></th>
            <th data-sort="num" data-first="desc" aria-sort="descending"><button type="button">Hits</button></th>
            <th data-sort="num" data-first="desc" aria-sort="none"><button type="button">Reporters</button></th>
            <th data-sort="text" aria-sort="none"><button type="button">Location</button></th>
            <th data-sort="text" aria-sort="none"><button type="button">ISP / AS</button></th>
            <th data-sort="num" data-first="desc" aria-sort="none"><button type="button">Last seen</button></th>
          </tr></thead>
          <tbody>__ROWS__
            <tr class="no-match"><td colspan="7" class="empty">No bans match that filter.</td></tr>
          </tbody>
        </table>
      </div>
      __LOADMORE__
    </section>
  </main>

  <footer>
    Data generated __GENERATED__ · Geo data © DB-IP.com, CC BY 4.0 ·
    <a href="/api/public/bans">JSON API</a> ·
    <a href="/lists/community-bans.txt">Plain-text IP list</a>
    (<a href="/lists/community-bans.txt?severity=high">high severity only</a>)
    <br /><br />
    <span style="color:#777;">Built for dedicated Linux gateways.</span>
  </footer>

  <script>
    __NAV_JS__

    // Instant client-side table filter
    (function () {
      const input = document.getElementById('banSearch');
      const none = document.querySelector('#banTable .no-match');
      const count = document.getElementById('tableCount');
      const initial = count ? count.textContent : '';
      if (!input) return;
      input.addEventListener('input', () => {
        const q = input.value.trim().toLowerCase();
        let shown = 0;
        // re-query on every input so load-more appended rows filter too
        const rows = Array.from(document.querySelectorAll('#banTable tbody tr[data-search]'));
        rows.forEach(r => {
          const hit = !q || r.dataset.search.includes(q);
          r.style.display = hit ? '' : 'none';
          if (hit) shown++;
        });
        none.classList.toggle('show', shown === 0);
        count.textContent = q ? shown + ' matching' : initial;
      });
      document.addEventListener('keydown', e => {
        if (e.key === '/' && document.activeElement !== input) { e.preventDefault(); input.focus(); }
      });
    })();

    // Column sorting (client-side over the rendered rows)
    (function () {
      const table = document.getElementById('banTable');
      const tbody = table.tBodies[0];
      const heads = Array.from(table.tHead.rows[0].cells);
      const label = document.getElementById('sortLabel');
      const noMatch = tbody.querySelector('.no-match');
      heads.forEach((th, col) => {
        th.querySelector('button').addEventListener('click', () => {
          const cur = th.getAttribute('aria-sort');
          const dir = cur === 'none'
            ? (th.dataset.first === 'desc' ? 'descending' : 'ascending')
            : (cur === 'ascending' ? 'descending' : 'ascending');
          heads.forEach(h => h.setAttribute('aria-sort', 'none'));
          th.setAttribute('aria-sort', dir);
          const sign = dir === 'ascending' ? 1 : -1;
          const type = th.dataset.sort;
          const rows = Array.from(tbody.querySelectorAll('tr[data-search]'));
          const key = r => r.cells[col].dataset.v || '';
          rows.sort((a, b) => {
            const x = key(a), y = key(b);
            let d = (type === 'num' ? (parseFloat(x) || 0) - (parseFloat(y) || 0)
                                    : x.localeCompare(y)) * sign;
            if (d === 0) d = (parseFloat(b.cells[2].dataset.v) || 0) - (parseFloat(a.cells[2].dataset.v) || 0);
            return d;
          });
          rows.forEach(r => tbody.insertBefore(r, noMatch));
          label.textContent = 'sorted by ' + th.textContent.trim().toLowerCase() +
                              (dir === 'ascending' ? ' ↑' : ' ↓');
        });
      });
    })();
    // Load older rows on demand (keyset pagination - stable under inserts)
    (function () {
      const btn = document.getElementById('loadMoreBtn');
      const wrap = document.getElementById('loadMoreWrap');
      if (!btn || !wrap) return;
      const tbody = document.getElementById('banTable').tBodies[0];
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        const label = btn.textContent;
        btn.textContent = 'Loading…';
        try {
          const u = '/api/public/bans/more?before=' + encodeURIComponent(btn.dataset.before)
                  + '&ip=' + encodeURIComponent(btn.dataset.ip)
                  + '&severity=' + encodeURIComponent(btn.dataset.sev);
          const r = await fetch(u);
          const d = await r.json();
          if (!d.ok) throw new Error(d.error || 'failed');
          if (d.rows) tbody.insertAdjacentHTML('beforeend', d.rows);
          if (d.more && d.next_before != null) {
            btn.dataset.before = d.next_before;
            btn.dataset.ip = d.next_ip;
            btn.disabled = false;
            btn.textContent = 'Load more';
          } else {
            wrap.parentNode.removeChild(wrap);
          }
        } catch (e) {
          btn.disabled = false;
          btn.textContent = label + ' (retry)';
        }
      });
    })();
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
  <link rel="stylesheet" href="/css/style.css?v=20261004-2" />
  <style>
    __PAGE_CSS__
  </style>
</head>
<body>

  __NAV__

  <main class="page-main">
    <section class="section" style="padding-top:0;">
      <p class="section-desc" style="margin-bottom:1rem;"><a class="ip-link" href="/bans">← Back to Community Bans</a></p>
      <p class="section-label">// ip report</p>
      <div class="ip-head">
        <h1 class="section-title mono-ip">__IP__</h1>
        <button class="copy-btn" data-copy="__IP__">Copy</button>
        __BADGE__
        <span class="ip-flag">__FLAG__</span>
      </div>
      <p class="section-desc" style="margin-top:0.75rem;">Community abuse report compiled from reports sent by participating TuxWall firewall installs.</p>
      __BODY__
    </section>
  </main>

  <footer>
    Verdicts and categories are self-reported by participating TuxWall installs and are not a guarantee.
    Geo data © DB-IP.com, CC BY 4.0 ·
    <a href="/api/public/bans">JSON API</a> · <a href="/bans">Ban list</a>
    <br /><br />
    <span style="color:#777;">Built for dedicated Linux gateways.</span>
  </footer>

  <script>
    __NAV_JS__
  </script>

</body>
</html>
"""

HTML_TEMPLATE = HTML_TEMPLATE.replace("__NAV__", NAV_HTML).replace("__NAV_JS__", NAV_JS)
IP_DETAIL_TEMPLATE = (IP_DETAIL_TEMPLATE.replace("__NAV__", NAV_HTML)
                      .replace("__NAV_JS__", NAV_JS))


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