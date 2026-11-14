---
name: TuxWall firewall change
description: Use before adding, editing, moving, disabling or deleting any firewall rule (ufw, iptables, nftables, port forwards, DMZ, zone policy) or restoring a firewall snapshot on this TuxWall router. Snapshot first, guard preview, 60 s confirm-or-rollback.
---

# Changing the TuxWall firewall safely

This is a live router. A bad rule cuts the household's internet or the owner's own session.
Read the "Firewall", "NAT" and "Zone policy" sections of the facts file first.

## Hard rules
- Never cut LAN IPv4/IPv6 access, the WAN uplink, or the admin's current session (dashboard 80/443, API 8008, SSH 22 from the LAN).
- Never touch rules owned by TuxWall components: honeypot (`tuxwall-honeypot`), canary (`tuxwall-canary*`),
  canary/forum egress containment in `/etc/ufw/before*.rules`, tripwire, CrowdSec bouncer chains,
  NAT (tuxwall-nat), WireGuard, mDNS, policy-matrix rules. Their owners re-create them; the guard refuses edits.
- Never run `ufw disable`, `ufw reset`, `iptables -F`, `nft flush ruleset`, or `iptables-restore` of an old file.
  The legacy `/etc/tuxwall/fw-baseline` is superseded by snapshots - do not restore it by hand.
- Every new ufw rule gets a purpose comment: `... comment 'IoT: printer to LAN'`.
- Do not add raw `iptables -A/-I ... -j ACCEPT` outside ufw (wg0.conf PostUp, scripts): Findings flags them and
  they bypass the zone policy. With `policy.wg_raw_forward=false` VPN forwarding is ufw route rules only.
- Ask the owner before any change; say exactly what will change and how it is undone.

## 1. Collect (read-only)
- `sudo ufw status numbered` and `sudo ufw status verbose` (defaults, logging)
- `sudo iptables-save` (raw chains, NAT) - look, do not edit
- Facts file: findings count, latest snapshot id, NAT rule present, deception state
- What exactly must be allowed/blocked: source zone/subnet, destination, port/proto, direction (in vs route/forward)

## 2. Decide
- Is it already covered? Check for an existing allow/deny that matches (rule order matters: first match wins).
- Is it a zone-to-zone question (LAN/IoT/OPT/VPN/WAN)? Prefer the Interfaces > Policy matrix wording and a
  `ufw route allow in on <a> out on <b> ...` rule over host rules.
- WAN-facing? Never open a decoy port (honeypot/canary ports in the facts) or a management port (22, 80, 443, 8008, 4096, 8744, 53, 67) on the WAN.
- Port forward / DMZ: use Firewall > NAT in the dashboard (it runs the guard).

## 3. Apply through the dashboard flow (preferred)
The dashboard API needs an admin session; you have no API credentials, so guide the owner (or, when they
supply a session, use the API with header `Origin: http://127.0.0.1:8008`):
1. Snapshot: Firewall > Settings > Snapshots > Create (API `POST /api/firewall/snapshots {"note": "before <change>"}`).
2. Preview: Firewall > Rules edit dialog shows the guard verdict (API `GET /api/firewall/plan?op=insert&rule=<ufw rule>`,
   ops: insert|edit|move|disable|enable, with `number`/`to`/`before`). A guard refusal is final - change the plan.
3. Apply: `POST /api/firewall/apply` (same fields) takes an auto snapshot and arms a 60 s confirm-or-rollback.
   The owner confirms from their browser (`POST /api/firewall/confirm {"id": ...}`); no confirm = automatic revert.
4. Restore instead of edit: Snapshots > Restore shows a preview (`POST /api/firewall/snapshots/<id>/restore {"dry_run": true}`),
   then restores with the same 60 s confirm. Managed rules (deception, NAT) are kept on restore.

## 4. Shell fallback (dashboard down, owner explicitly approved)
1. Back up: `sudo cp -a /etc/ufw /root/ufw.bak.$(date +%Y%m%d-%H%M%S)` and `sudo iptables-save > /root/iptables.bak.<ts>`.
2. Arm a revert before changing anything, e.g. `sudo systemd-run --on-active=120 --unit=tw-fw-revert sh -c 'cp -a /root/ufw.bak.<ts>/. /etc/ufw/ && ufw reload'`.
3. Make ONE change with `sudo ufw ... comment '...'`.
4. Owner confirms LAN internet, dashboard and SSH still work -> `sudo systemctl stop tw-fw-revert.timer`.

## 5. Verify
- `sudo ufw status numbered`: the rule is there, commented, in the intended position.
- NAT: `sudo iptables -t nat -S POSTROUTING` still has `-o <wan> -j MASQUERADE`.
- Deception rules unchanged (count `tuxwall-honeypot` / `tuxwall-canary` lines before and after).
- Firewall > Findings: no new critical/high/medium (the facts file refreshes within 5 min).
- Ask the owner to test from an affected client; resolved only when they confirm.
