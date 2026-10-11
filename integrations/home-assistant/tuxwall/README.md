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

**Sensors** — attacks/min, firewall blocks, CrowdSec active bans, DNS
queries / blocked % / cache hit rate, WAN IP (attributes: interface,
IPv6), VPN peers online, tarpit trapped connections.

**Binary sensors** — one per core gateway service (Unbound, Kea, radvd,
nginx, Suricata, CrowdSec + bouncer, WireGuard, tuxwall, tuxwall-agent,
tuxwall-collector, tuxwall-nat, tuxwall-sqm) plus an aggregate
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

## Install (HAOS)

1. Create a **dedicated tuxwall user** (dashboard → Settings → User
   Manager). Read-only (`viewer`) is enough for sensors/events; create an
   admin user only if you want the ban/unban services.
2. Copy this folder to the HAOS host as
   `/config/custom_components/tuxwall/` (SFTP via the File editor add-on or
   the SSH add-on).
3. Restart Home Assistant, then **Settings → Devices & Services → Add
   Integration → TuxWall**. Enter the base URL (e.g.
   `http://192.168.1.1`), username and password; add the TOTP code only if
   that account has 2FA.
4. Poll interval (10–3600s) is adjustable under the integration's
   *Configure* options.

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
    entity_id: person.jeff
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
