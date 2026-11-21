---
name: TuxWall deception layer
description: Use for anything touching the honeypot tarpit, OpenCanary canary, canary egress containment, the tripwire, or CrowdSec bans and the firewall bouncer - including false-positive bans, decoy ports, port conflicts and Findings about deception rules. Protection must never be lost.
---

# Deception layer and CrowdSec on TuxWall

Ground rule: the deception layer must never lose protection. Do not stop, disable, remove, reorder or "temporarily"
open around any of it. Fix the specific thing (one IP, one port, one rule) instead. Ask the owner before any change.

## Components (current state: facts file "Firewall" and "Services" sections)
Live state without shell: `tuxwall_crowdsec_decisions` (pass `ip` to check one address), `tuxwall_security_events`,
`tuxwall_firewall_rules` with `owner` honeypot / canary.
- Honeypot tarpit (inside the tuxwall API): config `/var/lib/tuxwall/honeypot.json` {enabled, ports, auto_ban, ban_threshold};
  listens on WAN decoy ports (v4 + v6) opened by ufw rules commented `tuxwall-honeypot`. Caps: 8 held connections per source,
  256 total, 4 h max. Hits >= threshold -> CrowdSec ban (long) -> community report, once per source.
- OpenCanary (`opencanary.service`, user `opencanary`): fake SSH/VNC/MSSQL/Redis on the WAN IPv4 only, opened by IPv4 ufw
  rules commented `tuxwall-canary` (the SNMP decoy was retired 2026-11-19). The API's canary watchdog closes those rules when
  the canary is down and reopens them when it is back; a Finding "Canary rule ... not running / without a listener" is a
  leftover it will remove. Log `/var/log/opencanary/opencanary.log` (logrotate weekly); alerts reach the dashboard webhook.
- Never-ban guard: no deception path bans or reports LAN/VLAN/VPN addresses (incl. the delegated global IPv6 prefix), the
  router's own or recent WAN addresses, protected infrastructure (Cloudflare, model APIs, collector-published ranges) or
  infrastructure the router depends on (DNS forwarders, NTP, gateways, resolvers, APT mirrors).
- Community reporting: `/etc/tuxwall/reporting.json` (root 0600, holds the install key - never print it) `enabled` is the
  off switch; reports go through the persistent retry queue `/var/lib/tuxwall/report-queue.json` (no key inside); while
  off, queued reports are held (not sent, aged out after 7 days) and resume when switched back on. The owner changes it -
  and community auto-ban (`/etc/tuxwall/community-auto.json`) - in the dashboard (Security > Deception or CrowdSec >
  Community Bans; `GET/POST /api/community/settings`, audited in `/var/log/tuxwall/community-settings-audit.log`).
  Never toggle either switch yourself.
- Canary egress containment: owner-match rules in `/etc/ufw/before.rules` and `/etc/ufw/before6.rules` (ufw-before-output) let the
  opencanary user reach only the dashboard webhook (127.0.0.1:8008) and local DNS; everything else is logged
  `[TUXWALL-CANARY-EGRESS]` and rejected. A similar block contains the forum user. Never delete or duplicate these blocks.
  Check: `sudo python3 /var/www/html/includes/canary_egress.py --check` (exit 0 = present in both files); `--plan` shows a repair diff.
- Tripwire (`tuxwall-tripwire.service`, config `/etc/tuxwall/tripwire.json` schema v2: master `enabled`, block `strength`
  medium|high, `notify`, per-check `checks` {action off|log|block, threshold, exclusions}; derived legacy `mode`; state
  `/etc/tuxwall/tripwire-state.json`, history `/var/lib/tuxwall/tripwire-events.jsonl`): checks are Suricata priority-1
  exploit classes and canary egress. Block strength: medium = internet only (FORWARD -i/-o <wan> DROP; VPN->LAN, LAN<->VLAN
  keep working), high = all forwarding + new WAN input closed (WAN DHCP/ND/replies allowed). Both restrict the router's OWN WAN
  egress while tripped (OUTPUT `TUXWALL-TRIPWIRE-EGRESS[-ALLOW]`, REJECT last): DNS only from uid unbound, NTP from the chrony
  uid, WAN DHCP/ND, replies, HTTPS to the alerts.json push targets (ipsets `tw-egress4/6`); unbound still answers all names.
  So while tripped, internet tools on the router (apt, curl, model providers) fail by design. Router-originated/loopback
  traffic is always ignored. Read-only: `sudo tuxwall-tripwire config`, `history --check C`, `test CHECK` (dry run, no side
  effects). No auto-restore: a trip is resolved deliberately by the owner in the dashboard (Security). Never change settings
  on your own. Recovery mode (`sudo tuxwall-tripwire recovery-status`): a timed window while tripped that widens the router's
  egress to the AI/push allowlist (one `TUXWALL-TRIPWIRE-RECOVERY-ALLOW` rule per family above the egress REJECT, ipsets
  `tw-recovery4/6`, DNS limited to those names via unbound runtime zones); end/expiry returns to the tripped egress policy.
  If you were started with an incident brief, investigate read-only and never start/extend/end recovery,
  restore or open the firewall yourself - that is the owner's call.
- CrowdSec (`crowdsec`, `crowdsec-firewall-bouncer`): decisions block attackers; permanent bans in `/etc/tuxwall/custom-blocklist.txt`.

## Common tasks
- A legitimate host is blocked: `sudo cscli decisions list -i <ip>` (or `| grep <ip>`), check `custom-blocklist.txt` and DNS client bans.
  Remove only that decision (`sudo cscli decisions delete --ip <ip>`, ask first); recurring -> whitelist it (dashboard CrowdSec page).
- Want a service/port forward on a WAN port: first check it is not a honeypot or canary port (facts lists them). If it is,
  pick another external port - the dashboard guard refuses it anyway. Never move a decoy to make room without the owner's decision.
- Incident "port X held by <process>": the deception layer needs that port; identify the process (`sudo ss -tlnp | grep :X`) and ask
  the owner how to move the other service. Do not stop the canary.
- Findings like honeypot-missing / canary-missing / canary-egress-missing: repair through Firewall > Findings (guarded fix),
  or with owner approval `sudo python3 /var/www/html/includes/canary_egress.py --apply` for containment. Snapshot first
  (load `tuxwall-firewall-change`).
- Adding a honeypot port: Firewall suggestions / Deception page (op honeypot-add runs the guard + auto snapshot).

## Never
- `systemctl stop|disable` crowdsec, crowdsec-firewall-bouncer, opencanary, tuxwall-tripwire, suricata.
- Deleting or editing `tuxwall-honeypot` / `tuxwall-canary*` ufw rules or the containment blocks; `ufw reset`; restoring old
  before.rules copies by hand (they may duplicate or drop the containment).
- Unbanning ranges wholesale or flushing all decisions.

## Verify
`systemctl is-active crowdsec crowdsec-firewall-bouncer opencanary tuxwall-tripwire`; `sudo ufw status | grep -c tuxwall-honeypot`
and `grep -c tuxwall-canary` unchanged from before; `canary_egress.py --check` exit 0; facts "Deception" line unchanged;
Firewall > Findings shows no new deception finding.
