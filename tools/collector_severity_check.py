#!/usr/bin/env python3
"""Severity / trust-floor check for collector/tuxwall-collector.py.

Usage:
    python3 tools/collector_severity_check.py            # scratch database
    python3 tools/collector_severity_check.py COPY.db    # also audit a copy
                                                         # of a real database

Builds a throwaway database, feeds it reports through Store.ingest() and
asserts the rules installs rely on (Automatic mode enforces medium+):

- a brand-new key can never push an IP to medium, whatever it claims
  (canary source, huge hit counts, several fresh keys at once);
- a key with a week of history plus deception evidence reaches medium;
- top_bans(tier=...) returns exactly the rows severity_for() puts in that
  tier, so the public tier filters agree with the feed.

With a database path, the same tier-consistency audit runs against a
copy of real data (pass a copy, never the live file) and prints the
severity distribution. Nothing is sent anywhere; the collector's HTTP
server is never started.
"""
import importlib.util
import os
import sys
import tempfile
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
    ((1, 1, True, 0), LOW),        # fresh key claiming canary
    ((10**6, 1, True, 0), LOW),    # fresh key, absurd hit count
    ((10, 25, True, 0), LOW),      # 25 fresh keys (sybil burst)
    ((1, 1, True, 1), MED),        # real catch from an established install
    ((50, 1, False, 1), MED),      # trusted, volume only
    ((1, 2, False, 1), MED),       # trusted + a second reporter
    ((1, 1, False, 1), LOW),       # trusted, no supporting evidence
    ((500, 1, True, 1), HIGH),
    ((1, 2, True, 2), HIGH),
    ((1, 5, True, 5), CRIT),
]
for args, want in cases:
    got = col.severity_for(args[0], args[1], deception=args[2], trusted=args[3])
    check(got == want, "hits=%s reporters=%s deception=%s trusted=%s -> %s"
          % (args + (got,)))

print("Store scenarios (scratch database)")
tmp = tempfile.mkdtemp(prefix="tw-collector-check-")
store = col.Store(os.path.join(tmp, "reports.db"))
now = time.time()


def sev_of(ip):
    for b in store.top_bans(limit=100000):
        if b["ip"] == ip:
            return b["severity"]
    return None


def age_key(key, seconds):
    with store.lock:
        store._conn.execute("UPDATE reporter_keys SET created=? WHERE key=?",
                            (now - seconds, key))
        store._conn.commit()


store.ingest("fresh-key-aaaaaaaaaaaa", "203.0.113.10", 1, "ssh login", "canary", "ssh", now)
check(sev_of("203.0.113.10") == LOW, "fresh key + canary claim -> low (not enforced)")
check(all(b["ip"] != "203.0.113.10" for b in store.top_bans(min_severity=1, limit=100000)),
      "fresh key's IP absent from the medium+ feed installs enforce")

for i in range(10):
    store.ingest("sybil-key-%02d-xxxxxxxx" % i, "203.0.113.20", 5000, "spray", "canary", "ssh", now)
check(sev_of("203.0.113.20") == LOW, "10 fresh keys, 5000 hits each -> still low")

age_key("fresh-key-aaaaaaaaaaaa", WEEK + 60)
check(sev_of("203.0.113.10") == MED, "same key after a week of history -> medium")

store.ingest("old-key-bbbbbbbbbbbbb", "203.0.113.10", 1, "ssh login", "canary", "ssh", now)
age_key("old-key-bbbbbbbbbbbbb", WEEK + 60)
check(sev_of("203.0.113.10") == HIGH, "two trusted reporters -> high")

store.ingest("old-key-bbbbbbbbbbbbb", "203.0.113.30", 80, "manual", "manual", "manual", now)
check(sev_of("203.0.113.30") is None, "manual-only report never published")

tier_audit(store, "scratch")

if len(sys.argv) > 1:
    print("Audit of %s" % sys.argv[1])
    real = col.Store(sys.argv[1])
    dist = {}
    for sev in tier_audit(real, "copy").values():
        dist[sev] = dist.get(sev, 0) + 1
    print("  severity distribution:", dist)

print()
if failures:
    print("%d check(s) failed" % len(failures))
    sys.exit(1)
print("all checks passed")
