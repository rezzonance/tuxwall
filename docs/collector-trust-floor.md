# Collector trust model: admin approval

Status: **deployed 2026-11-19 (deception phase 2; key scope "keys" for the ban page added the same day).** Replaces the 7-day
"trusted after a week of history" floor (2026-11-12, kept below as history).

## Why

Installs in Automatic mode (`CommunityAutoWorker`) enforce every feed entry at
**medium or above** as a 90-day local ban. Reporter keys are free, and
`source` ("canary") and `hits` are self-reported. Under the 7-day rule a
"sleeper" key only had to wait a week before its claims reached every
subscriber, and a farm of keys registered in advance could poison the feed.

## Rule

A reporter key is one of:

| Status | Meaning |
|---|---|
| `pending` | New key (from `POST /register` or its first report). Reports are stored and published, at **low** only. Never counts toward medium+. |
| `approved` | An admin vouched for it (`tuxwall-collector-admin approve`). Full weight at once. |
| `revoked` | Refused at ingest; never counts. Final (cannot be re-approved). |

Severity is computed from **approved evidence only**:

- `trusted` = distinct approved reporters for the IP
- `hits` = hits reported by approved keys
- `deception` = an approved key has canary/honeypot evidence for the IP

| Severity | Rule (unchanged thresholds) |
|---|---|
| critical | 5+ trusted reporters |
| high | 2+ trusted reporters, or 1 trusted reporter with 500+ hits |
| medium | 1+ trusted reporter **and** canary/honeypot evidence, 50+ hits, or a second trusted reporter |
| low | everything else |

The thresholds and the deception-only publication gate are the same as
before; what changed is who counts as trusted, and that a pending key's hits
or evidence can no longer lift an approved report (e.g. an approved
1-hit canary report stays medium even if a pending key claims 100000 hits).

`top_bans(tier=...)` uses the same rule in SQL (`_severity_rank_sql`), so the
public tier filters always agree with the feed (checked by
`tools/collector_severity_check.py`, also against a copy of the live DB).

## Migration (idempotent, on first start)

- `reporter_keys` gains `approved_at` / `revoked_at`.
- Legacy `active` keys that were already trusted under the 7-day rule become
  `approved` (so no published severity changes at migration); younger ones
  become `pending`. On 2026-11-19: the router key (9d0a84c8…) -> approved; the
  only other key (e1101414…) was already revoked. Distribution before/after
  on a copy of the live DB: 12,487 medium -> 12,487 medium, identical.

## Admin

Loopback-only admin API (`X-Admin-Key`, refused when proxy headers are
present), driven by the root CLI:

```
sudo tuxwall-collector-admin pending            # keys waiting for approval
sudo tuxwall-collector-admin list [--status approved|pending|revoked] [--json]
sudo tuxwall-collector-admin approve <id>       # id = key hash or 8+ hex prefix
sudo tuxwall-collector-admin revoke <id> [--transfer-to <id>]
echo '<raw key>' | tuxwall-collector-admin hash # id of a raw key
```

`revoke --transfer-to` is for key rotation of the same install: the old key's
`report_reports` / `report_events` / `whitelist_hits` rows are re-attributed
to the (already approved) new key in one transaction, so the install's
history keeps its weight. A plain revoke drops the key's evidence to low.

Endpoints: `GET /api/admin/keys[?status=]`, `POST /api/admin/keys/<id>/approve`,
`POST /api/admin/keys/<id>/revoke` (`{"transfer_to": "<id>"}`), legacy
`DELETE /api/admin/keys/<id>`.

### Admin key scopes

| Key file (root-owned, via `LoadCredential=`) | Scope | Reaches |
|---|---|---|
| `/etc/tuxwall-collector/admin.key` (root:adm 0640) | `full` | everything (CLI) |
| `/etc/tuxwall-collector/admin-api.key` (root:tuxwall-banadmin 0640) | `bans` | `/api/admin/bans*` only |
| `/etc/tuxwall-collector/admin-keys.key` (root:tuxwall-banadmin 0640) | `keys` | `/api/admin/keys*` only (list, approve, revoke, revoke + transfer) |

The two scoped keys belong to the LAN Ban Management page (php-fpm pool
`tuxwall-admin`, user tuxwall-banadmin); neither reaches the other scope or
the whitelist. A scoped key that equals another configured key is ignored
(fail closed). Answers to the `keys` scope identify keys by `id` (the
16-hex hash prefix the CLI shows) and never carry the full hash; only the
`full` key also gets `key`. `GET /api/admin/keys` lists per key: status,
created, last_seen, approved_at, revoked_at, `reported_ips`, `events_24h`,
`events_7d`, `events_total` (retained report events, 90 days) and
`categories` (category -> retained events).

Audit: approve / revoke (incl. the transfer target and moved row counts) and
ban removals are logged to the collector journal with the target's 8-hex
prefix, `scope=` and `actor=` - the dashboard user the page sends in
`X-Admin-Actor` (sanitized, informational). No key material is logged.

The page itself: listing for every signed-in dashboard user (read-only for
viewers); approve / revoke / revoke + transfer need the dashboard admin role
(checked server-side), a POST and a CSRF token bound to the dashboard
session (HMAC of the session cookie under a page-private secret). Revoking
this router's own key - identified by matching the dashboard's community
settings approval time against the key list - needs a second explicit
confirmation (also enforced server-side; required for every revoke while the
router's key cannot be identified). History transfer is offered only from an
approved key to another approved key.

## Abuse limits

- per client IP (real client from nginx `X-Real-IP` = `CF-Connecting-IP`,
  trusted from loopback only; IPv6 grouped per /64): `/report` 600/h,
  `/register` 20 registrations/h, 240 status lookups/h;
- per reporter key: `/report` 120/h (unchanged);
- global: at most 100 new keys per 24 h (registration and auto-registration
  on `/report` answer 429 "paused for today" beyond it);
- nginx `tuxwall_report` zone (30 r/m per client) stays in front.

## Registration API

`POST /register {"key"}` registers (pending) and returns
`{status, approved, created, approved_at, trusted_after}` (`trusted_after` =
approval time, `null` while pending - kept for older dashboards).
`POST /register {"key", "action": "status"}` is a pure lookup. The legacy
`GET /register?key=` still answers, but neither the collector log nor the
nginx access log records query strings that carry a key.

## Residual risk

An approved install that turns hostile can still put single-reporter
mediums on the feed until it is revoked; the protected ranges, each
install's own never-ban list and per-key limits remain the backstop.

## History: 7-day floor (2026-11-12)

Medium required one key with 7 days of registration history. Superseded by
admin approval because key age is free to accumulate.
