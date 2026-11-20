#!/usr/bin/env python3
"""Severity / trust-model / hardening check for collector/tuxwall-collector.py.

Usage:
    python3 tools/collector_severity_check.py            # scratch database
    python3 tools/collector_severity_check.py COPY.db    # also audit a copy
                                                         # of a real database

Builds throwaway databases, feeds them reports through Store.ingest() and
asserts the rules installs rely on (Automatic mode enforces medium+):

- admin approval: a pending key can never push an IP above low, whatever it
  claims (canary source, huge hit counts, many keys, age); an approved key
  with deception evidence reaches medium; pending hits/evidence never lift
  an approved report; revoking drops the weight, revoke + transfer (key
  rotation) keeps it; legacy 'active' keys migrate idempotently;
- top_bans(tier=...) returns exactly the rows severity_for() puts in that
  tier, so the public tier filters agree with the feed;
- abuse limits: per-client identity (X-Real-IP from loopback only, IPv6 per
  /64), per-IP and per-key limits, global daily new-key cap;
- retention: prune() removes old report_events / whitelist_hits but keeps
  the newest deception event per (ip, reporter), so severities don't move;
- an in-process HTTP server on an ephemeral loopback port (scratch DB,
  never the live collector): POST/GET /register, query strings never
  logged, /ip/ global-only, report cards without reporter hashes, quote
  escaping, cached + paginated /api/public/bans (public cap vs loopback),
  CDN cache headers, /bans/more, admin key scopes, admin approve/revoke.

With a database path, the tier-consistency audit runs against a copy of
real data (pass a copy, never the live file) and prints the severity
distribution. Nothing is sent anywhere.
"""
import hashlib
import http.client
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "collector", "tuxwall-collector.py")

spec = importlib.util.spec_from_file_location("collector", TARGET)
col = importlib.util.module_from_spec(spec)
spec.loader.exec_module(col)

LOW, MED, HIGH, CRIT = (col.SEVERITY_LOW, col.SEVERITY_MEDIUM,
                        col.SEVERITY_HIGH, col.SEVERITY_CRITICAL)
WEEK = col.TRUST_SECONDS
failures = []


def check(cond, msg):
    print(("  ok    " if cond else "  FAIL  ") + msg)
    if not cond:
        failures.append(msg)


def tier_audit(store, label):
    everything = {b["ip"]: b["severity"] for b in store.top_bans(limit=100000)}
    seen = {}
    for tier in (LOW, MED, HIGH, CRIT):
        for b in store.top_bans(tier=tier, limit=100000):
            seen[b["ip"]] = tier
            if b["severity"] != tier:
                failures.append("%s: %s in tier %s but severity %s"
                                % (label, b["ip"], tier, b["severity"]))
    check(seen == everything,
          "%s: tier filters partition the feed exactly (%d rows)" % (label, len(everything)))
    return everything


print("severity_for() truth table")
cases = [
    # (hits, reporters, deception, trusted) -> expected
    ((1, 1, True, 0), LOW),        # pending key claiming canary
    ((10**6, 1, True, 0), LOW),    # pending key, absurd hit count
    ((10, 25, True, 0), LOW),      # 25 pending keys (sybil burst)
    ((1, 1, True, 1), MED),        # real catch from an approved install
    ((50, 1, False, 1), MED),      # approved, volume only
    ((1, 2, False, 1), MED),       # approved + a second reporter
    ((1, 1, False, 1), LOW),       # approved, no supporting evidence
    ((500, 1, True, 1), HIGH),
    ((1, 2, True, 2), HIGH),
    ((1, 5, True, 5), CRIT),
]
for args, want in cases:
    got = col.severity_for(args[0], args[1], deception=args[2], trusted=args[3])
    check(got == want, "hits=%s reporters=%s deception=%s trusted=%s -> %s"
          % (args + (got,)))

tmp = tempfile.mkdtemp(prefix="tw-collector-check-")
store = col.Store(os.path.join(tmp, "reports.db"))
now = time.time()


def sev_of(ip, st=None):
    for b in (st or store).top_bans(limit=100000):
        if b["ip"] == ip:
            return b["severity"]
    return None


def age_key(key, seconds, st=None):
    st = st or store
    with st.lock:
        st._conn.execute("UPDATE reporter_keys SET created=? WHERE key=?",
                         (now - seconds, key))
        st._conn.commit()


def status_of(key, st=None):
    row = (st or store).key_status(key)
    return row and row["status"]


print("Trust model: admin approval (scratch database)")
store.ingest("new-key-aaaaaaaaaaaaaa", "203.0.113.10", 1, "ssh login", "canary", "ssh", now)
check(status_of("new-key-aaaaaaaaaaaaaa") == "pending", "unknown key auto-registers as pending")
check(sev_of("203.0.113.10") == LOW, "pending key + canary claim -> low (not enforced)")
check(all(b["ip"] != "203.0.113.10" for b in store.top_bans(min_severity=1, limit=100000)),
      "pending key's IP absent from the medium+ feed installs enforce")
for i in range(10):
    store.ingest("sybil-key-%02d-xxxxxxxx" % i, "203.0.113.20", 5000, "spray", "canary", "ssh", now)
check(sev_of("203.0.113.20") == LOW, "10 pending keys, 5000 hits each -> still low")
age_key("new-key-aaaaaaaaaaaaaa", 30 * 86400)
check(sev_of("203.0.113.10") == LOW, "a month of history alone no longer trusts a key")
store.approve_key("new-key-aaaaaaaaaaaaaa", now)
check(status_of("new-key-aaaaaaaaaaaaaa") == "approved", "approve_key: pending -> approved")
check(sev_of("203.0.113.10") == MED, "approved key + deception -> medium (full weight at once)")
store.ingest("old-key-bbbbbbbbbbbbbbb", "203.0.113.10", 1, "ssh login", "canary", "ssh", now)
check(sev_of("203.0.113.10") == MED, "second reporter still pending -> stays medium")
store.approve_key("old-key-bbbbbbbbbbbbbbb", now)
check(sev_of("203.0.113.10") == HIGH, "two approved reporters -> high")
store.ingest("old-key-bbbbbbbbbbbbbbb", "203.0.113.30", 80, "manual", "manual", "manual", now)
check(sev_of("203.0.113.30") is None, "manual-only report never published")
# pending evidence never lifts an approved report
store.ingest("new-key-aaaaaaaaaaaaaa", "203.0.113.40", 1, "probe", "honeypot", "scan", now)
store.ingest("sybil-key-00-xxxxxxxx", "203.0.113.40", 100000, "spray", "canary", "ssh", now)
check(sev_of("203.0.113.40") == MED, "pending key's 100000 hits don't lift approved medium to high")
store.ingest("new-key-aaaaaaaaaaaaaa", "203.0.113.41", 1, "manual", "manual", "manual", now)
store.ingest("sybil-key-01-xxxxxxxx", "203.0.113.41", 1, "spray", "canary", "ssh", now)
check(sev_of("203.0.113.41") == LOW,
      "approved manual report + pending canary claim -> low (deception must come from an approved key)")
store.revoke_key("old-key-bbbbbbbbbbbbbbb", now)
check(sev_of("203.0.113.10") == MED, "revoking one of two approved keys -> back to medium")
check(store.approve_key("old-key-bbbbbbbbbbbbbbb", now)["status"] == "revoked",
      "a revoked key cannot be re-approved")
check(store.ingest("old-key-bbbbbbbbbbbbbbb", "203.0.113.50", 1, "x", "canary", "ssh", now)
      == "revoked", "revoked key refused at ingest")
tier_audit(store, "scratch")

print("Key rotation: revoke + transfer keeps the install's weight")
rot = col.Store(os.path.join(tmp, "rotate.db"))
for i in range(5):
    rot.ingest("rotate-old-key-000000", "198.51.100.%d" % (10 + i), 1 + i * 300, "x", "honeypot", "scan", now)
rot.ingest("rotate-old-key-000000", "198.51.100.30", 3, "x", "canary", "ssh", now - 400)
rot.approve_key("rotate-old-key-000000", now)
before = {b["ip"]: b["severity"] for b in rot.top_bans(limit=1000)}
rot.register_key("rotate-new-key-111111", now)
rot.approve_key("rotate-new-key-111111", now)
rot.ingest("rotate-new-key-111111", "198.51.100.30", 9, "x", "canary", "ssh", now)  # overlap
rot.revoke_key("rotate-old-key-000000", now)
moved = rot.transfer_evidence("rotate-old-key-000000", "rotate-new-key-111111")
after = {b["ip"]: b["severity"] for b in rot.top_bans(limit=1000)}
check(before == after and len(after) == 6, "severities identical after rotation (%d IPs)" % len(after))
check(moved["report_reports"] == 6 and moved["report_events"] == 6, "old key's rows moved: %s" % moved)
with rot.lock:
    rr = rot._conn.execute("SELECT hits FROM report_reports WHERE ip='198.51.100.30'").fetchall()
check(rr == [(9,)], "overlapping (ip, reporter) rows merge (max hits)")
rot2 = col.Store(os.path.join(tmp, "rotate2.db"))
rot2.ingest("plain-old-key-0000000", "198.51.100.40", 1, "x", "honeypot", "scan", now)
rot2.approve_key("plain-old-key-0000000", now)
rot2.revoke_key("plain-old-key-0000000", now)
check(sev_of("198.51.100.40", rot2) == LOW, "revoke WITHOUT transfer drops the evidence to low")

print("Key ids: resolve by hash prefix")
ka, kb = "ab" * 32, "ab" * 4 + "cd" * 28
for k in (ka, kb):
    rot.register_key(k, now)
check(rot.resolve_key(ka[:8]) == (None, "ambiguous"), "ambiguous prefix refused")
check(rot.resolve_key(ka[:6]) == (None, "invalid"), "prefix shorter than 8 refused")
check(rot.resolve_key("abababab" + "ab" * 4)[0] == ka, "unique prefix resolves")
check(rot.resolve_key("ffffffff") == (None, "not found"), "unknown prefix -> not found")
check(rot.resolve_key("abab'; --") == (None, "invalid"), "non-hex id refused")

print("Migration from the pre-approval schema (idempotent)")
legacy = os.path.join(tmp, "legacy.db")
c = sqlite3.connect(legacy)
c.executescript("""
CREATE TABLE reporter_keys (key TEXT PRIMARY KEY, created REAL NOT NULL,
  last_seen REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active');
CREATE TABLE report_reports (ip TEXT NOT NULL, reporter TEXT NOT NULL,
  hits INTEGER NOT NULL DEFAULT 0, last_seen REAL NOT NULL, PRIMARY KEY (ip, reporter));
""")
c.executemany("INSERT INTO reporter_keys VALUES (?,?,?,?)", [
    ("legacy-trusted-key-1", now - 60 * 86400, now, "active"),
    ("legacy-young-key-222", now - 86400, now, "active"),
    ("legacy-revoked-key-3", now - 60 * 86400, now, "revoked")])
c.execute("INSERT INTO report_reports VALUES ('203.0.113.9','legacy-orphan-key-44',1,?)", (now,))
c.commit()
c.close()
mig = col.Store(legacy)
check(status_of("legacy-trusted-key-1", mig) == "approved", "week-old active key -> approved (keeps weight)")
check(status_of("legacy-young-key-222", mig) == "pending", "young active key -> pending")
check(status_of("legacy-revoked-key-3", mig) == "revoked", "revoked key stays revoked")
check(status_of("legacy-orphan-key-44", mig) == "pending", "reporter without a key row -> pending")
check(len(mig.migration_notes) == 4, "migration notes: %s" % "; ".join(mig.migration_notes))
check(all("legacy-trusted-key-1" not in n for n in mig.migration_notes),
      "notes show hash prefixes only")
mig2 = col.Store(legacy)
check(mig2.migration_notes == [] and status_of("legacy-trusted-key-1", mig2) == "approved",
      "second start: no changes (idempotent)")

print("Daily new-key cap")
cap = col.Store(os.path.join(tmp, "cap.db"))
saved = col.NEW_KEYS_PER_DAY
col.NEW_KEYS_PER_DAY = 3
try:
    res = [cap.register_key("cap-key-%02d-xxxxxxxxxx" % i, now) for i in range(4)]
    check(res == ["ok", "ok", "ok", "cap"], "4th new key in 24 h refused: %s" % res)
    check(cap.register_key("cap-key-00-xxxxxxxxxx", now) == "ok", "existing key unaffected by the cap")
    check(cap.ingest("cap-key-99-xxxxxxxxxx", "203.0.113.77", 1, "x", "canary", "ssh", now) == "cap",
          "auto-registration on /report obeys the cap")
    check(cap.ingest("cap-key-01-xxxxxxxxxx", "203.0.113.77", 1, "x", "canary", "ssh", now) == "ok",
          "known keys keep reporting while the cap is reached")
finally:
    col.NEW_KEYS_PER_DAY = saved

print("Retention: prune()")
pr = col.Store(os.path.join(tmp, "prune.db"))
old = now - (col.RETENTION_DAYS + 5) * 86400
pr.ingest("prune-key-approved-00", "203.0.113.60", 1, "x", "canary", "ssh", old)
pr.ingest("prune-key-approved-00", "203.0.113.60", 5, "x", "manual", "manual", old + 400)
pr.ingest("prune-key-approved-00", "203.0.113.60", 9, "x", "manual", "manual", now)
pr.approve_key("prune-key-approved-00", now)
pr.ingest("prune-key-approved-00", "203.0.113.61", 1, "x", "canary", "ssh", old)  # stale IP
pr.record_whitelist_hit("prune-key-approved-00", "1.1.1.1", "built-in", old)
pr.record_whitelist_hit("prune-key-approved-00", "1.1.1.1", "built-in", now)
sev_before = sev_of("203.0.113.60", pr)
out = pr.prune(now)
with pr.lock:
    ev = pr._conn.execute("SELECT ip, source FROM report_events ORDER BY id").fetchall()
    wh = pr._conn.execute("SELECT COUNT(*) FROM whitelist_hits").fetchone()[0]
check(("203.0.113.60", "canary") in ev, "newest deception event per (ip, reporter) kept")
check(("203.0.113.60", "manual") in ev and len([e for e in ev if e[1] == "manual"]) == 1,
      "old non-deception events pruned, recent kept")
check(all(e[0] != "203.0.113.61" for e in ev), "events of retention-pruned IPs removed")
check(sev_of("203.0.113.60", pr) == sev_before == MED, "still listed with the same severity")
check(wh == 1 and out["whitelist_hits"] == 1, "old whitelist_hits pruned: %s" % out)

print("Client identity for the per-IP limits")


class FakeReq:
    """Just enough of a request for Handler._rate_client()."""
    def __init__(self, peer, real=None):
        self.client_address = (peer, 40000)
        self.headers = {"X-Real-IP": real} if real else {}


rc = col.Handler._rate_client
check(rc(FakeReq("127.0.0.1", "198.51.100.7")) == "198.51.100.7",
      "proxied request -> keyed by the real client (X-Real-IP)")
check(rc(FakeReq("127.0.0.1", "198.51.100.7")) != rc(FakeReq("127.0.0.1", "198.51.100.8")),
      "two installs behind the proxy get separate buckets")
check(rc(FakeReq("127.0.0.1", "2001:db8:1:2::a")) == rc(FakeReq("127.0.0.1", "2001:db8:1:2:ffff::9")),
      "IPv6 clients share one bucket per /64")
check(rc(FakeReq("127.0.0.1", "::ffff:198.51.100.7")) == "198.51.100.7",
      "IPv4-mapped X-Real-IP normalised")
check(rc(FakeReq("203.0.113.5", "198.51.100.7")) == "203.0.113.5",
      "X-Real-IP ignored unless the peer is loopback (no spoofing)")
check(rc(FakeReq("127.0.0.1", "not-an-ip")) == "127.0.0.1",
      "garbage X-Real-IP falls back to the peer")
check(rc(FakeReq("127.0.0.1")) == "127.0.0.1",
      "local request without X-Real-IP keyed by the peer")

lim = col.RateLimiter(2)
t0 = time.time()
check(lim.allow("a", t0) and lim.allow("a", t0) and not lim.allow("a", t0),
      "limiter refuses the third request in the hour")
check(lim.allow("b", t0), "another client is unaffected")
for i in range(20005):
    lim.allow("idle-%d" % i, t0 - 7200)
lim.allow("c", t0)
check(len(lim._hits) < 100, "idle clients pruned (table bounded)")

print("Escaping")
check(col._esc("a'b\"<c>&") == "a&#x27;b&quot;&lt;c&gt;&amp;", "_esc escapes both quote styles")
check(col._esc(None) == "", "_esc(None) -> ''")
check(col._public_ip_or_none("fe80::1%25eth0") is None, "/ip/: scoped address refused")
check(col._public_ip_or_none("10.0.0.1") is None, "/ip/: private address refused")
check(col._public_ip_or_none("::ffff:8.8.8.8") is not None
      and str(col._public_ip_or_none("::ffff:8.8.8.8")) == "8.8.8.8", "/ip/: mapped -> plain v4")

print("HTTP endpoints (in-process server, ephemeral loopback port, scratch DB)")
http_dir = tempfile.mkdtemp(prefix="tw-collector-http-")
admin_file = os.path.join(http_dir, "admin.key")
bans_file = os.path.join(http_dir, "admin-api.key")
with open(admin_file, "w") as f:
    f.write("A" * 64 + "\n")
with open(bans_file, "w") as f:
    f.write("B" * 64 + "\n")
col.ADMIN_KEY_PATH, col.BANS_KEY_PATH = admin_file, bans_file
col.STORE = col.Store(os.path.join(http_dir, "reports.db"))
col.LOG = __import__("queue").Queue(maxsize=5000)
col._ingest_count = 0
col.PUBLIC_CACHE.clear()
srv = col.ThreadingHTTPServer(("127.0.0.1", 0), col.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
PORT = srv.server_address[1]
VER = {"X-Tuxwall-Version": "3.3.1"}
PROXY = {"X-Real-IP": "198.51.100.200"}


def req(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    data = None if body is None else json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    conn.request(method, path, body=data, headers=h)
    r = conn.getresponse()
    raw = r.read()
    conn.close()
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except ValueError:
        parsed = raw.decode("utf-8", "replace")
    return r.status, dict(r.getheaders()), parsed


def logs():
    out = []
    while not col.LOG.empty():
        out.append(col.LOG.get_nowait())
    return "\n".join(out)


RAW = "raw-secret-key-0123456789abcdef"
KID = hashlib.sha256(RAW.encode()).hexdigest()
logs()
st, _, d = req("POST", "/register", {"key": RAW}, dict(VER, **PROXY))
check(st == 200 and d.get("status") == "pending" and d.get("approved") is False
      and d.get("trusted_after") is None, "POST /register -> pending, not approved")
st, _, d = req("POST", "/register", {"key": RAW, "action": "status"}, PROXY)
check(st == 200 and d.get("found") and d.get("status") == "pending", "POST /register status lookup")
st, _, d = req("POST", "/register", {"key": "unknown-key-000000000000", "action": "status"}, PROXY)
check(st == 200 and d.get("found") is False, "status lookup never registers")
st, _, d = req("GET", "/register?key=" + RAW, None, PROXY)
check(st == 200 and d.get("status") == "pending", "legacy GET /register?key= still answers")
req("GET", "/nope?key=" + RAW + "&x=1", None, PROXY)
lg = logs()
check(RAW not in lg and "key=" not in lg and '"/register"' in lg,
      "collector log has paths only - raw key / query never logged")
st, _, d = req("POST", "/register", {"key": RAW}, {"X-Real-IP": "198.51.100.200"})
check(st == 426, "registration without a version header refused (426)")

st, _, d = req("POST", "/report", {"key": RAW, "ip": "45.83.64.99", "hits": 3,
                                   "source": "canary", "category": "ssh"}, dict(VER, **PROXY))
check(st == 200 and d.get("accepted"), "/report from a pending key accepted (%s %s)" % (st, d))
st, h, d = req("GET", "/api/public/bans/45.83.64.99")
check(d["report"]["severity"] == LOW, "pending key's report published at low")

# admin scopes
st, _, d = req("GET", "/api/admin/keys", None, {"X-Admin-Key": "B" * 64})
check(st == 401, "scoped ban-admin key cannot manage reporter keys")
st, _, d = req("GET", "/api/admin/bans", None, {"X-Admin-Key": "B" * 64})
check(st == 200 and d.get("ok"), "scoped ban-admin key can list bans")
st, _, d = req("GET", "/api/admin/keys", None, {"X-Admin-Key": "A" * 64, "X-Real-IP": "127.0.0.1"})
check(st == 401, "admin refused when proxy headers are present")
st, _, d = req("GET", "/api/admin/keys?status=pending", None, {"X-Admin-Key": "A" * 64})
check(st == 200 and [k["key"] for k in d["keys"]] == [KID] and d.get("new_keys_cap"),
      "admin lists pending keys")
st, _, d = req("POST", "/api/admin/keys/%s/approve" % KID[:10], None, {"X-Admin-Key": "A" * 64})
check(st == 200 and d.get("status") == "approved", "admin approves by hash prefix")
col.PUBLIC_CACHE.clear()
st, _, d = req("GET", "/api/public/bans/45.83.64.99")
check(d["report"]["severity"] == MED, "approved -> the same report now medium")
st, _, d = req("POST", "/register", {"key": RAW, "action": "status"}, PROXY)
check(d.get("approved") is True and d.get("trusted_after"), "status shows approved")

# report card: no reporter hash, escaping
with col.STORE.lock:
    col.STORE._conn.execute("UPDATE reports SET isp=? WHERE ip='45.83.64.99'",
                            ("Evil' onmouseover='x\"<b>",))
    col.STORE._conn.commit()
col.PUBLIC_CACHE.clear()
st, _, page = req("GET", "/ip/45.83.64.99", None, PROXY)
check(st == 200 and KID[:8] not in page and "Approved install" in page,
      "report card shows approval state, not the reporter hash")
check("onmouseover='x" not in page and "Evil&#x27; onmouseover=&#x27;x&quot;&lt;b&gt;" in page,
      "ISP rendered with quotes escaped")
st, _, _d = req("GET", "/ip/10.1.2.3", None, PROXY)
check(st == 400, "/ip/<private> refused")
st, _, _d = req("GET", "/ip/fe80::1%25eth0", None, PROXY)
check(st == 400, "/ip/<scoped v6> refused")

# lists, caching, pagination
for i in range(30):
    col.STORE.ingest(KID, "45.83.65.%d" % (i + 1), i + 1, "x", "honeypot", "scan", time.time() - i)
col.PUBLIC_CACHE.clear()
saved_max = col.PUBLIC_BANS_MAX
col.PUBLIC_BANS_MAX = 10
try:
    st, h, d = req("GET", "/api/public/bans?limit=20000", None, PROXY)
    check(st == 200 and d["total"] == 10 and d["next_offset"] == 10 and d["total_available"] == 31,
          "public caller capped (limit 20000 -> 10 rows, next_offset 10, 31 available)")
    check(h.get("Cache-Control") == "public, max-age=60", "public list is CDN-cacheable (max-age 60)")
    check(h.get("Access-Control-Allow-Origin") == "*", "CORS header on the public JSON")
    seen, off, gens = [], 0, set()
    while off is not None:
        st, h, d = req("GET", "/api/public/bans?limit=20000&offset=%d" % off, None, PROXY)
        seen += [b["ip"] for b in d["bans"]]
        gens.add(d["generated"])
        off = d["next_offset"]
    check(len(seen) == len(set(seen)) == 31 and len(gens) == 1,
          "offset pagination returns every row once from one snapshot")
    st, h, d = req("GET", "/api/public/bans?limit=20000")
    check(d["total"] == 31 and d["next_offset"] is None, "direct loopback caller gets the whole list")
finally:
    col.PUBLIC_BANS_MAX = saved_max
calls = []
orig_top = col.Store.top_bans


def counting(self, *a, **kw):
    calls.append(kw)
    return orig_top(self, *a, **kw)


col.Store.top_bans = counting
try:
    col.PUBLIC_CACHE.clear()
    for _ in range(5):
        req("GET", "/api/public/bans?limit=10", None, PROXY)
        req("GET", "/lists/community-bans.txt", None, PROXY)
    check(len(calls) == 1, "5x JSON + 5x txt within the TTL -> one DB query (%d)" % len(calls))
    calls.clear()
    first = req("GET", "/api/public/bans?order=recent&limit=3", None, PROXY)[2]["bans"]
    last = first[-1]
    calls.clear()
    st, h, d = req("GET", "/api/public/bans/more?before=%s&ip=%s" % (last["last_seen"], last["ip"]),
                   None, PROXY)
    check(st == 200 and d["count"] == 28 and "45.83.65." in d["rows"],
          "/bans/more returns the older rows (%s)" % d.get("count"))
    check(len(calls) <= 1, "/bans/more: at most one (cached) top query, was two")
finally:
    col.Store.top_bans = orig_top
st, h, txt = req("GET", "/lists/community-bans.txt", None, PROXY)
check(st == 200 and len(txt.split()) == 31 and h.get("Cache-Control") == "public, max-age=60",
      "/lists/community-bans.txt served from cache with max-age 60")

# abuse limits through HTTP
saved = (col.REGISTER_IP_RATE, col.REPORT_IP_RATE)
col.REGISTER_IP_RATE, col.REPORT_IP_RATE = col.RateLimiter(2), col.RateLimiter(3)
try:
    r6 = [req("POST", "/register", {"key": "limit-key-%02d-xxxxxxxxxx" % i}, dict(
        VER, **{"X-Real-IP": "2001:db8:aa:bb::%x" % (i + 1)}))[0] for i in range(3)]
    check(r6 == [200, 200, 429], "/register limited per client /64 (%s)" % r6)
    other = req("POST", "/register", {"key": "limit-key-99-xxxxxxxxxx"},
                dict(VER, **{"X-Real-IP": "2001:db8:aa:cc::1"}))[0]
    check(other == 200, "another /64 unaffected")
    rr = [req("POST", "/report", {"key": RAW, "ip": "45.83.64.%d" % (120 + i), "source": "canary"},
              dict(VER, **{"X-Real-IP": "198.51.100.250"}))[0] for i in range(4)]
    check(rr == [200, 200, 200, 429], "/report limited per client IP (%s)" % rr)
finally:
    col.REGISTER_IP_RATE, col.REPORT_IP_RATE = saved

# revoke with transfer through HTTP
RAW2 = "raw-secret-key-new-fedcba9876543210"
KID2 = hashlib.sha256(RAW2.encode()).hexdigest()
req("POST", "/register", {"key": RAW2}, dict(VER, **{"X-Real-IP": "198.51.100.201"}))
st, _, d = req("POST", "/api/admin/keys/%s/revoke" % KID[:12], {"transfer_to": KID2[:12]},
               {"X-Admin-Key": "A" * 64})
check(st == 409, "transfer to a pending key refused")
req("POST", "/api/admin/keys/%s/approve" % KID2[:12], None, {"X-Admin-Key": "A" * 64})
st, _, d = req("POST", "/api/admin/keys/%s/revoke" % KID[:12], {"transfer_to": KID2[:12]},
               {"X-Admin-Key": "A" * 64})
check(st == 200 and d["transferred"]["report_reports"] >= 31, "revoke + transfer via the admin API")
st, _, d = req("GET", "/api/public/bans/45.83.64.99")
check(d["report"]["severity"] == MED, "rotated install keeps medium")
st, _, d = req("POST", "/report", {"key": RAW, "ip": "45.83.64.130", "source": "canary"},
               dict(VER, **PROXY))
check(st == 403, "old key refused after revocation")
st, _, d = req("POST", "/report", {"key": RAW2, "ip": "45.83.64.130", "source": "canary"},
               dict(VER, **PROXY))
check(st == 200 and d.get("accepted"), "new key accepted")
lg = logs()
check(RAW not in lg and RAW2 not in lg, "no raw key anywhere in the collector log")
srv.shutdown()

if len(sys.argv) > 1:
    print("Audit of %s" % sys.argv[1])
    real = col.Store(sys.argv[1])
    for note in real.migration_notes:
        print("  migration:", note)
    dist = {}
    for sev in tier_audit(real, "copy").values():
        dist[sev] = dist.get(sev, 0) + 1
    print("  severity distribution:", dist)

print()
if failures:
    print("%d check(s) failed" % len(failures))
    sys.exit(1)
print("all checks passed")
