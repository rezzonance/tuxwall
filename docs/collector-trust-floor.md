# Collector trust model: admin approval

Status: **deployed 2026-11-19 (deception phase 2).** Replaces the 7-day
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
`DELETE /api/admin/keys/<id>`. The scoped ban-admin key
(`/etc/tuxwall-collector/admin-api.key`) only reaches `/api/admin/bans*`.

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
