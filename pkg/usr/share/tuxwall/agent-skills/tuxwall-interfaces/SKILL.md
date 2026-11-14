---
name: TuxWall interfaces
description: Use for questions or changes about interface roles (WAN, LAN, OPT networks, VLANs, VPN), adding or moving a network or a dedicated device port (worknet), the zone policy matrix, or Interface Assignments. Assignments Apply is locked - plan only.
---

# Interfaces, roles and zones on TuxWall

## Where the truth lives
- Role record: `/etc/tuxwall/interfaces.json` - `wan {device, mode}`, `lan {device, address, dhcp, ra}`,
  `opt[] {id, name, device, address, dhcp, ra, vlan?, parent?}`, `vpn[] {id, device, address}`,
  `policy {wg_raw_forward}`, `apply_locked`. The facts file shows the current values plus link state.
- Live: `ip -br link`, `ip -br addr`, `networkctl status`, `ip route show default` (WAN = default-route device).
- Legacy VLAN list: `/etc/tuxwall/vlans.json` (kept in sync by the dashboard).
- Dashboard: Interfaces page (Assignments, Policy matrix, VLANs). Read API (admin session):
  `GET /api/interfaces`, `/api/interfaces/policy`, `/api/interfaces/vlans`, `/api/interfaces/lock`.

## Apply is locked
`apply_locked: true` means Interface Assignments may only produce a plan: `POST /api/interfaces/plan` (dry run) or the
Assignments tab preview. `/api/interfaces/apply` returns 423. Never set `apply_locked` to false, never edit
interfaces.json, netplan or networkd files to "apply" a plan yourself. Present the plan and let the owner decide.

## What one network touches (check all when explaining or planning)
- Address: netplan/networkd (`/etc/netplan/*.yaml`); VLANs are `<parent>.<id>` sub-interfaces.
- DHCP: a Kea `subnet4` with `interface`, `subnet`, pool inside the subnet (`/etc/kea/kea-dhcp4.conf`).
- DNS: unbound `access-control:` for the subnet; an `interface:` bind only if the interface is always present.
  A single-client port (e.g. a work PC on its own NIC) must NOT be bound - its address vanishes when the
  PC is off and unbound then crash-loops (precedent: `/etc/unbound/unbound.conf.d/89-worknet-dns.conf` uses access-control only).
- IPv6: radvd only where `ra: true`; sync-ipv6-pd for the LAN GUA prefix.
- Firewall zones: ufw rules on the device (`in on <dev>`, `route ... in on <a> out on <b>`) with comments; NAT is the single
  `-o <wan> -j MASQUERADE` from tuxwall-nat (covers every internal subnet). mDNS reflector (avahi), Suricata HOME_NET, SQM WAN.
- `policy.wg_raw_forward=false`: VPN forwarding is ufw route rules only - no raw FORWARD ACCEPTs in wg0.conf PostUp.

## Zone policy matrix
States: allow, block, established (return traffic only), dns_dhcp (only DNS/DHCP to the router), custom (specific ports), self.
Typical safe defaults: LAN -> everything allowed; IoT/OPT -> internet + router DNS/DHCP only, blocked from LAN and each other
(narrow exceptions as commented rules); VPN -> LAN + internet; WAN -> established only (new WAN connections dropped in before.rules,
port forwards via DNAT). Changing a cell = a firewall change: load the `tuxwall-firewall-change` skill.

## Decision steps for "add/move a network or port"
1. Read the role record and live state; identify the free NIC or VLAN id; confirm the subnet does not overlap any existing one.
2. Write a plan listing every item above (address, Kea, unbound, radvd, ufw zone rules, avahi, suricata) and its undo.
3. Mark anything that can cut the LAN or the admin session (changing the LAN device/address, the WAN device, the parent of VLANs).
4. Ask the owner. Execution happens by the owner (or by you step by step with explicit approval, backups `cp -a f f.bak.$(date +%Y%m%d-%H%M%S)`,
   and the firewall skill for the ufw part).

## Verify
`ip -br addr` shows the address; `kea-dhcp4 -t -c /etc/kea/kea-dhcp4.conf` passes; `unbound-checkconf` passes; ufw rules commented;
a client on the segment gets a lease (`/var/log/kea/kea-dhcp4.log` DHCPACK) and reaches what the policy allows and nothing else.
"No link" on an OPT port whose device is off is normal.
