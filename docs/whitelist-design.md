# Community feed infrastructure whitelist — 3.2.4 design

Status: IMPLEMENTED (collector + client). The 3.2.3 hardcoded
`PROTECTED_NETS` floor (Cloudflare ranges + Anthropic's 160.79.104.0/24)
remains as the non-removable base layer; everything below is built on top:

- `whitelist_ranges` / `whitelist_hits` tables (schema auto-migrates)
- GET/POST `/api/admin/whitelist`, GET `/api/admin/whitelist/hits`,
  DELETE `/api/admin/whitelist/<id>` (loopback + X-Admin-Key, like /keys)
- ingest refuses floor+managed matches and records every attempt
- adding a managed range retroactively scrubs reports / report_reports /
  report_events / suricata_evidence in one transaction
- `GET /api/public/whitelist` + `protected` field in `/api/public/bans`
- client CommunityAutoWorker skips both the hardcoded floor and the
  published list (old collectors omit the field -> empty list, floor
  still applies)

## Problem

`community-auto` enforces **every** IP on the public feed regardless of
severity tier. The severity floors only limit *how high* an IP ranks — a
single reporter (register key, wait 7 days, report) can land any IP on the
feed at low severity. Therefore any IP the ecosystem depends on must never
enter the feed at all, and the protected list must be maintainable without
shipping a client release.

## Design

Two layers in the collector:

1. **Built-in floor** (code constants, not removable): current
   `PROTECTED_NETS`. Cannot be edited away via the admin API.
2. **Admin-managed list** (DB table `whitelist_ranges`), maintained via
   new loopback-only, admin-key-gated endpoints (same pattern as
   `/api/admin/keys`):
   - `GET  /api/admin/whitelist` — effective list (floor + managed), with
     source attribution per entry
   - `POST /api/admin/whitelist` — add range (validated via
     `ipaddress.ip_network`; reject anything overlapping the floor as
     redundant)
   - `DELETE /api/admin/whitelist/<id>` — remove managed entry

### Ingest behavior

Parse reported IP → if it matches the effective whitelist → reject (400,
"Refusing protected infrastructure IP") **and record the attempt** in a
`whitelist_hits` table: reporter key hash, attempted IP, timestamp. This
is the abuse-intel payoff: poisoning attempts become visible instead of
silently vanishing. Expose a summary (attempts over time, top reporters)
via `/api/admin/whitelist/hits`.

### Retroactive scrub

On whitelist change, delete matching rows from `reports` /
`report_reports` / `report_events` / `suricata_evidence` in one
transaction. Refusing future reports is not enough — anything that slipped
in before a range was protected keeps poisoning consumers forever.

### Publication

Include the effective whitelist in the public API so consumers can skip
the ranges client-side regardless of their version:

- `GET /api/public/whitelist` → `{"ranges": [...], "generated": ...}`
- also embed `"protected": [...]` in `/api/public/bans` responses so a
  single fetch serves both

Client side (3.2.4+): `CommunityAutoWorker._pass` consults the published
list (cached, 10-min TTL like the bans themselves) in addition to the
local hardcoded floor. Hardcoded floor stays as fallback when the
collector is unreachable.

## Sizing

Collector-only for everything except the client consumption change:
admin endpoints + DB table + scrub + audit + publication ≈ a focused day.
Client change is small (merge published list into the skip check).
