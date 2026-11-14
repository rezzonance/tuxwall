# Collector trust floor for medium severity (draft)

Status: **draft on branch `draft/collector-trust-floor`, not deployed.**

## Problem

Installs in Automatic mode (`CommunityAutoWorker`) enforce every feed entry
at **medium or above** as a 90-day local ban. In 3.3.0 the collector rates an
IP medium when *any* of these is true: two reporters, 50+ hits, or
canary/honeypot evidence. All three are cheap to fake:

- reporter keys are free and auto-registered on the first report;
- `source` ("canary") and `hits` are self-reported by the sender;
- two keys are as easy to make as one.

So one request from a key created seconds earlier could put any IP outside
the protected ranges on every subscribed install's blocklist for 90 days.

The router-side comment in `CommunityAutoWorker._pass` already assumed the
opposite ("a forged report must clear the multi-reporter trust floor"); the
collector didn't enforce it.

## Change

`severity_for()` now requires at least one **trusted** reporter (a key with
`TRUST_SECONDS` = 7 days of registration history) for medium:

| Severity | Rule |
|---|---|
| critical | 5+ trusted reporters |
| high | 2+ trusted reporters, or 1 trusted reporter with 500+ hits |
| medium | 1+ trusted reporter **and** canary/honeypot evidence, 50+ hits, or a second reporter |
| low | everything else |

Reports from new keys still land in the database and on the public list at
**low**. They are visible on report cards but never auto-enforced, until the
key has a week of history or a trusted install sees the same IP.

`top_bans()` exact-tier filters (`tier=`) are rewritten to match
`severity_for()`. They previously used hit/reporter thresholds that no longer
matched the trust-based rules, so a tier page could list an IP under a
different tier than the feed gave it.

## Impact (measured on a copy of the live database, 2026-11-12)

- 9,213 published IPs: all medium before, all medium after. **No change today**:
  both active reporter keys are older than a week.
- Effect is on future reports only: a new install's catches publish at low
  for its first 7 days unless a trusted install corroborates them. The
  dashboard's "register up front" button starts that clock at install time.

## Residual risk

A "sleeper" key that registers, waits a week, then lies is trusted, so one
of its canary claims reaches medium. The remaining guards are the
protected ranges (built-in plus the admin-managed list), each install's own
never-ban list (DNS, NTP, gateway, own addresses, APT mirrors; added
2026-11-12), per-key rate limits, and key revocation through
`/api/admin/keys`. Requiring two independent trusted reporters for medium
would close it, at the cost of single-install catches never being enforced
by others.

## Registration rate limit (same branch)

`/register` rate-limited by `client_address`, which behind nginx is always
`127.0.0.1`. Every install shared one bucket of `RATE_LIMIT_PER_HOUR` (120)
registrations per hour, so a burst of new installs, or one abuser sending
120 requests, made "register up front" fail for everyone for an hour.
Reports still auto-register, but those installs' 7-day trust clock started
late.

`Handler._rate_client()` now keys the limiter on the real client from
nginx's `X-Real-IP` (already set on `/register`; upstream `real_ip_header
CF-Connecting-IP`). The header is trusted only when the peer is loopback;
IPv6 clients are bucketed per /64; IPv4-mapped forms are normalised. The
value is used only for the in-memory limiter, never logged or stored, so
reporters stay anonymous. `RateLimiter` prunes idle entries once it tracks
more than 20,000 clients. No nginx change is needed.

## Verification

`python3 tools/collector_severity_check.py [copy-of-reports.db]`, also added
to CI. It covers the severity rules, the tier filters and the registration
rate-limit identity; it fails on the 3.3.0 collector and passes on this
branch.

## Rollout

1. Merge, then install `collector/tuxwall-collector.py` to
   `/opt/tuxwall-collector/` and `systemctl restart tuxwall-collector`.
   No database migration; severity is computed per request.
2. No client change is needed. Installs already enforce medium+.
3. Optional: add one sentence to the Deception notice in `www/index.html`:
   "New installs' catches are enforced by other installs once their key is
   7 days old."
