---
name: TuxWall connectivity
description: Use when the LAN or a network segment has no internet, DNS names fail, devices get no IP address (DHCP), IPv6 breaks, WireGuard clients cannot connect, or everything is slow - including the "no IPv4 after a reboot" NAT race. Collect, decide, smallest safe fix, verify.
---

# Connectivity triage on TuxWall

Detect, don't assume: take interface names, subnets and roles from the facts file or
`/etc/tuxwall/interfaces.json` (`wan.device`, `lan`, `opt[]`, `vpn[]`), then confirm live.
Diagnose read-only first, change one thing at a time, re-verify after every fix.
Restarting unbound, kea, systemd-networkd, wg-quick or suricata blips the whole LAN: ask first.
Never stop crowdsec/bouncer/suricata/unbound/ufw to "test".

## 0. Collect bundle (read-only)
```
ip -br addr; ip route show default; ip -6 route show default
sudo iptables -t nat -S POSTROUTING
systemctl --failed
systemctl is-active systemd-networkd tuxwall-nat kea-dhcp4-server unbound radvd wg-quick@wg0
journalctl -u systemd-networkd -u unbound -u kea-dhcp4-server --since -30min --no-pager | tail -60
```
Severity order: no-internet > dns-dead > dhcp-fail > dashboard-down > slow > wireguard > ipv6.

## No internet for the LAN (router itself may be fine)
1. Router out? `ping -c3 1.1.1.1`. No: WAN problem - `networkctl status <wan>`; no address -> `sudo networkctl renew <wan>`;
   still nothing -> ISP/cable/modem (MAC binding on a new router: ask before cloning a MAC).
2. Exactly one IPv4 default route via the WAN? Strays from an interface event: ask before `ip route del`.
3. Router pings out, LAN does not -> NAT. `sudo iptables -t nat -S POSTROUTING` MUST contain `-A POSTROUTING -o <wan> -j MASQUERADE`.
   - Known boot race (IPv4 outage on this product): tuxwall-nat ran before the WAN had a DHCP lease and set no NAT.
     Check `journalctl -u tuxwall-nat -b` and `systemctl cat tuxwall-nat` (drop-in `TUXWALL_WAN_IFACE` must equal the WAN role).
   - Fix: `sudo systemctl restart tuxwall-nat` (oneshot with RemainAfterExit - `start` is a no-op once "active").
     The script prints nothing and exits 0 even on failure: verify by effect (rule present, a LAN client browses).
   - LAN NAT is owned by tuxwall-nat (`/usr/local/sbin/tuxwall-nat-ensure`), not by ufw before.rules: never add NAT stanzas there (ufw reload duplicates them).
4. WAN IP just changed and some flows hang: `sudo conntrack -D -s <old-wan-ip>` (ask). Never `conntrack -F` without explicit consent.
5. Only one segment (IoT/OPT/VPN) affected: check its forward rule to the WAN in the zone policy (facts) and `sudo ufw status | grep <dev>`.

## DNS dead (ping 1.1.1.1 works, names fail)
- `systemctl status unbound`, `unbound-control status`, `dig @127.0.0.1 example.com`, `journalctl -u unbound -n 50`, `ss -ulnp | grep :53`.
- Crash loop while `unbound-checkconf` is clean = an `interface:` line binds an address that is down (a single-client NIC such as a
  work-PC port without link). Fix: bind only always-present interfaces (loopback, LAN, VLANs); reach the transient subnet with
  `access-control:` only. Ask before restarting unbound.
- `validation failure` -> clock: `chronyc tracking` before touching DNS.
- 53 must never listen on the WAN address.
- One client/site only: `cscli decisions list | grep <ip>`, `grep -r <domain> /var/lib/unbound/`, client bans; whitelist on the Blocklists page.

## DHCP fail (no leases)
- `systemctl status kea-dhcp4-server`, `kea-dhcp4 -t -c /etc/kea/kea-dhcp4.conf`, `tail -50 /var/log/kea/kea-dhcp4.log`.
- "failed to select subnet" = pool/subnet drift: each subnet4 `interface` must hold an address inside its `subnet`.
- "exhausted" = pool full. VLAN clients only: the tagged sub-interface must be UP and the switch port tagged.
- Prefer dashboard DHCP edits (they back up and hot-reload). Hand edit: `cp -a` backup, `kea-dhcp4 -t`, then `sudo systemctl reload-or-restart kea-dhcp4-server`.
- A segment with "no link" in the facts (e.g. a dedicated work-PC port) simply has no clients right now - not a fault.

## IPv6
- `ip -6 route show default` (finite expiry), `journalctl -u sync-ipv6-pd -u radvd -n 30`. Prefix rotated -> `sudo systemctl start sync-ipv6-pd`.

## WireGuard
- `sudo wg show`: handshake < 3 min = connected. No handshake: UDP 51820 allowed on the WAN? WAN IP changed (client endpoint stale)?
  Handshake but no traffic: AllowedIPs or MTU (1280 on the client). Never paste peer configs or keys into chat or web files.

## Slow / bufferbloat
- `tc qdisc show` (cake on the ifb device), `journalctl -u tuxwall-sqm -n 20`; qdisc lost -> `sudo systemctl restart tuxwall-sqm`.
  Suricata is passive (af-packet) and not a cause of slowness.

## Done
On box: one default route per family, NAT rule present, services active, no new errors in the journal.
Client side: ask the owner to confirm a device on the affected segment browses again.
