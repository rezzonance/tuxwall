# TuxWall integration for Home Assistant

Exposes the TuxWall gateway's security state as Home Assistant entities and
events, and closes the two blind spots neither side can see alone:

- **East-west LAN traffic never touches the router**, so the router cannot
  see attacks on Home Assistant itself. This integration watches HA's own
  failed-login alerts and fires events for them.
- **HAOS knows its own auth state** (failed logins, session abuse) but has
  no gateway context. This integration brings the router's core-service
  health, attack rate, bans and tarpit catches in as entities/events so one
  automation pipeline covers both.

## Entities

All entities belong to one device, **TuxWall Gateway**. An entity whose
data the router does not provide (older TuxWall, or that source failing
right now) is *unavailable* rather than wrong; a value the router could not
refresh in time keeps its last reading and gets a `stale: true` attribute.

**Sensors (since 1.0, names and entity IDs unchanged)** — Attacks per minute
(attributes `unique_ips`, `hits_10m`), Firewall blocks, CrowdSec active bans
(`ips`: the first 25), DNS queries (since restart), DNS blocked (%), DNS cache
hit rate (%), WAN IP (`ifname`, `ipv6`), VPN peers online (`peers`,
`interface_up`), Tarpit trapped connections (total since the tarpit started;
0 while it is off).

**Security (1.2)**

| Entity | What |
|---|---|
| Tripwire (binary, problem) | on = tripped; `level`, `reason`, `since`, `mode`, `phase`, `trips` |
| Tarpit active connections | connections held in the tarpit right now |
| Canary hits (24 h) | canary (OpenCanary) events; `sources_24h`, `credentials_24h`, `bans_active` |
| Top attacking country (24 h) | country of the sources seen in the last 24 h with the most blocked hits (hits counted since the dashboard API started); `iso`, `hits`, `sources`, `runners_up` |
| Community reporting | `ok` / `queued` / `error` / `off`; `last_delivery`, `last_error_at`, `queued`, `sent_24h` |

**Network (1.2)**

| Entity | What |
|---|---|
| WAN connectivity (binary) | the router's ping monitor (1.1.1.1, every ~15 s) got answers within the last 90 s |
| IPv6 connectivity (binary) | the WAN has a global IPv6 address and an IPv6 default route (no IPv6 probe) |
| Internet latency (ms) | newest ping batch average; `packet_loss_pct`, `jitter_ms` |
| DHCP clients | active Kea leases; `online` (answering ARP), `reserved` |
| Blocked domains | size of the DNS blocklist; `updated_at` |

**Device monitoring (1.3, TuxWall 3.3.7+)**

| Entity | What |
|---|---|
| Flagged devices | LAN devices with health *warning* or *critical* (threat-intel match, IDS alert); `quarantined`, `critical`, `warning`, `devices`, `online`, `new_24h`, `worst_severity`, `worst_finding` (a generic reason such as "Connected to a known botnet C2 server (Feodo Tracker)" — never the address or domain), `worst_device`, `worst_last` |
| Device threat (binary, problem) | on = at least one device is flagged; same attributes |

Routers without device monitoring show both as unavailable.

**System and maintenance (1.2, diagnostic)** — CPU usage (%), Memory usage
(%), CPU temperature (°C, when the board reports one), Root disk usage (%),
Last boot (timestamp), TuxWall version, Last successful backup (timestamp;
`failed` when a newer run failed), Certificate expiry (timestamp of the
dashboard's HTTPS certificate — TuxWall's own, your custom one, or the
earliest one of an nginx site you manage; `days_left`, `source`).

**Update** — `update.tuxwall`: installed vs latest TuxWall. The latest
version comes from the router's apt index (what `apt policy tuxwall` shows
after the daily apt update); older routers: Home Assistant reads the TuxWall
apt repository's index itself, at most every 6 hours. The release notes link
opens the GitHub release. Installing stays on the router (dashboard **System
→ Updates**, or `sudo apt update && sudo apt upgrade`).

**Binary sensors (since 1.0)** — one per core gateway service (Unbound, Kea,
radvd, nginx, Suricata, CrowdSec + bouncer, WireGuard, tuxwall,
tuxwall-agent, tuxwall-collector, tuxwall-nat, tuxwall-sqm) plus an aggregate
"TuxWall core services healthy" with a `down_services` attribute.

**Services** — `tuxwall.ban_device` / `tuxwall.unban_device` (UFW deny +
Unbound DNS block; requires an **admin** tuxwall user).

**Events** — fired as `tuxwall_event` with a `type`:

| type | when |
|---|---|
| `service_down` / `service_up` | a core gateway service transitions |
| `wan_ip_change` | the WAN address changed (dynamic WAN) |
| `tarpit_catch` | the honeypot trapped/auto-banned a source |
| `ha_login_failure` | HA's own failed-login alert (east-west blind spot) |

Device monitoring (1.3, TuxWall 3.3.7+) fires two more event types, once per
finding / device id (the router lists its 10 newest; the first poll after a
Home Assistant start only records them, so a restart never replays old ones):

| event type | data |
|---|---|
| `tuxwall_device_finding` | `id`, `severity` (low/medium/high/critical), `reason` (generic), `device`, `device_id`, `first`, `last` |
| `tuxwall_new_device` | `device`, `device_id`, `zone`, `vendor`, `first_seen` |

## Install (HAOS)

1. Create a **dedicated tuxwall user** (dashboard → Settings → User
   Manager). Read-only (`viewer`) is enough for sensors/events; create an
   admin user only if you want the ban/unban services.
2. Copy this folder to the HAOS host as
   `/config/custom_components/tuxwall/` (SFTP via the File editor add-on or
   the SSH add-on).
3. Restart Home Assistant, then **Settings → Devices & Services → Add
   Integration → TuxWall**. Enter the base URL (e.g.
   `https://192.168.1.1`), username and password; add the TOTP code only if
   that account has 2FA.
   - **HTTPS (TuxWall 3.3.6+):** the dashboard redirects http to https with
     a certificate from the router's own CA. Download the CA
     (dashboard **Settings → Security → HTTPS → Download CA certificate**),
     copy it into the HA config folder (e.g. `/config/tuxwall-ca.crt`) and
     enter that path as *Router CA certificate file*. Unticking *Verify the
     HTTPS certificate* also works but is not recommended.
   - An existing entry that uses `http://` stops at login with "redirects to
     https" after the router upgrade: remove and re-add it with `https://`,
     or keep http with `sudo touch /etc/tuxwall/no-https-redirect && sudo
     tuxwall-tls refresh --reload` on the router.
4. Poll interval (10–3600s) is adjustable under the integration's
   *Configure* options.

### Updating

1. Copy the new folder over `/config/custom_components/tuxwall/`, replacing
   every file and adding the new ones (1.2.0 adds `entity.py`,
   `summary_data.py`, `update.py`, `icons.json`; 1.2.1 `brand/`). With the
   *Terminal & SSH* add-on:
   `rm -rf /config/custom_components/tuxwall && tar -xzf tuxwall-ha-1.3.1.tar.gz -C /config`
   (the archive holds `custom_components/tuxwall/`). Over the *Samba share*
   add-on: replace the `config/custom_components/tuxwall` folder.
2. Restart Home Assistant (**Settings → System → Restart**). The config
   entry, the existing entities and their history are kept; the new
   entities appear on the TuxWall Gateway device.
3. Optional: the router side (`GET /api/integration/summary`) arrives with
   the next TuxWall release. Until the router has it, the integration polls
   the older per-page endpoints and the entities those do not cover show as
   unavailable.

## Changelog

- **1.3.1** — "What to do": `tuxwall_device_finding` and `tuxwall_new_device`
  events carry `guidance` (the first recommended step, one plain sentence)
  and the *Flagged devices* sensor a `worst_guidance` attribute (TuxWall
  3.3.7 routers; older routers: `null`). Nothing else changed.
- **1.3.0** — Device monitoring (TuxWall 3.3.7): *Flagged devices* sensor
  (attributes: quarantined count, worst finding as a generic reason, critical
  / warning counts) and *Device threat* binary sensor (problem), read from
  the `devices` section of `/api/integration/summary` (routers without it:
  unavailable). Events `tuxwall_device_finding` and `tuxwall_new_device`,
  fired from the difference between polls and deduplicated by id.
- **1.2.1** — Integration icon: `brand/icon.png` and `brand/icon@2x.png` (the
  TuxWall logo), shown by Home Assistant 2026.3 and later.
- **1.2.0** — One request per poll: `GET /api/integration/summary` (about
  5 KB, every section flagged `ok`/`stale`; a slow or failing source on the
  router no longer delays or fails the poll) instead of eight endpoints
  (~100 KB per poll with 1.1.0, ~3.6 MB with 1.0.0). Routers without it
  answer 404 and get the 1.1.0 per-endpoint polling (the summary is retried
  hourly). New entities: Tripwire, WAN and IPv6 connectivity, internet
  latency, tarpit active connections, canary hits, top attacking country,
  community reporting, DHCP clients, blocked domains, CPU / memory / disk /
  temperature, last boot, TuxWall version, last backup, certificate expiry
  and the `update.tuxwall` entity. Entities follow the coordinator (no
  per-entity polling), and a failed poll marks them unavailable instead of
  showing empty values. Fixed: *Tarpit trapped connections* always read 0
  and the `tarpit_catch` event never fired (the honeypot payload nests its
  counters under `state`). The *Attacks per minute* attribute `hits_1h`
  (always empty — the router keeps no hourly count) is replaced by
  `hits_10m`.
- **1.1.0** — CrowdSec numbers come from `GET /api/crowdsec/summary` (a few
  KB) instead of the full decision list (`/api/crowdsec`, several MB on a
  router with thousands of bans, fetched every poll; it could exceed the
  15 s request timeout). Routers without the endpoint answer 404 and the
  integration falls back to `/api/crowdsec` (retrying the summary hourly).
  The *CrowdSec active bans* sensor and its `ips` attribute (the first 25
  addresses, soonest expiry first) are unchanged.
- **1.0.0** — first release.

## Example automations

Notify when a core gateway service drops (the "no internet" first check):

```yaml
alias: Gateway service down
trigger:
  - platform: event
    event_type: tuxwall_event
    event_data:
      type: service_down
action:
  - service: notify.mobile_app
    data:
      message: "TuxWall: {{ trigger.event.data.service }} stopped"
```

Notify on failed logins against HA itself (router cannot see these):

```yaml
alias: HA login failure
trigger:
  - platform: event
    event_type: tuxwall_event
    event_data:
      type: ha_login_failure
action:
  - service: notify.mobile_app
    data:
      message: "{{ trigger.event.data.message }}"
```

Presence-hardening example — everyone away, ban the guest device:

```yaml
alias: Lockdown when away
trigger:
  - platform: zone
    entity_id: person.jane
    zone: zone.home
    event: leave
action:
  - service: tuxwall.ban_device
    data:
      ip: 192.168.1.99
```

## Security notes

- Store the tuxwall credentials only in HA (config entry); keep the
  dedicated user at the lowest role that covers what you use.
- The API is LAN/VPN-restricted by the router's nginx, so the integration
  works only from inside the network (or via the router's WireGuard).
- `ban_device` affects the whole LAN: double-check the IP before calling.
