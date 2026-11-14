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
  listens on WAN decoy ports opened by ufw rules commented `tuxwall-honeypot`. Hits -> CrowdSec ban (long) -> community report.
- OpenCanary (`opencanary.service`, user `opencanary`): fake services on WAN ports opened by ufw rules commented
  `tuxwall-canary` / `tuxwall-canary-snmp`. Log `/var/log/opencanary/opencanary.log`; alerts reach the dashboard webhook.
- Canary egress containment: owner-match rules in `/etc/ufw/before.rules` and `/etc/ufw/before6.rules` (ufw-before-output) let the
  opencanary user reach only the dashboard webhook (127.0.0.1:8008) and local DNS; everything else is logged
  `[TUXWALL-CANARY-EGRESS]` and rejected. A similar block contains the forum user. Never delete or duplicate these blocks.
  Check: `sudo python3 /var/www/html/includes/canary_egress.py --check` (exit 0 = present in both files); `--plan` shows a repair diff.
- Tripwire (`tuxwall-tripwire.service`, config `/etc/tuxwall/tripwire.json` mode disabled|logonly|medium|high, state
  `/etc/tuxwall/tripwire-state.json`): trips on real exploit-class Suricata alerts or canary egress; medium/high cut WAN forwarding.
  No auto-restore: a trip is resolved deliberately by the owner in the dashboard (Security). Never change the mode on your own.
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
