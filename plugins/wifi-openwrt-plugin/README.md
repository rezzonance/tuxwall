# OpenWrt Access Points plugin for TuxWall

Read-only WiFi dashboard for OpenWrt **dumb APs** — no controller required.
Companion to the UniFi plugin (same view model, different hardware): install
whichever matches your access points, or both for mixed environments.

## What it does

- **Overview** — per-AP cards (model, firmware, uptime, radios with channel /
  width / tx-power, SSIDs with client counts) plus a live client table with
  IP, SSID, AP, signal, rx/tx rates and connection time. Includes **config
  parity** (wireless settings compared across APs — drift raises an incident)
  and **flapping-client detection** from the hostapd log.
- **Networks & VLANs** *(opt-in management)* — create, edit, rename, disable or
  delete SSIDs across **all APs in one pass**: security (WPA2 / WPA3 / mixed /
  open), passwords, and network binding (lan / iot / …). VLAN management
  creates the full dumb-AP recipe (switch VLAN + bridge + DHCP-client
  interface + DHCP/RA guards) on every AP at once, edits tagged/untagged
  ports, and deletes safely — refusing while any SSID is still bound to the
  VLAN's interface, and never touching VLAN 1 (management). Changes apply
  via `uci commit` + a detached network reload, so SSH sessions confirm
  before the stack restarts. Requires the "AP management" setting.
- **RF Environment** — on-demand channel scan from the APs: neighbour
  networks with signal and width, per-channel interference load, and a
  recommended channel per radio (DFS-aware, excludes channels your own APs
  occupy). One click applies the recommendation to that AP. Scanning blips
  clients briefly, so it never runs automatically.
- **Events** — connect / disconnect timeline parsed from hostapd logs
  (`logread`), including the auth algorithm used.
- **Incidents** — unreachable APs, radios that are down, weak-signal clients
  (≤ -75 dBm), config drift between APs, and flapping clients.
- **Inventory** — hardware / firmware table across all APs.

## How it talks to the APs

One SSH round-trip per AP (parallel), running a read-only POSIX shell script
via stdin:

```
ubus call system board / system info / network.wireless status
iwinfo <iface> info + assoclist for every wireless interface
ubus call hostapd.<iface> get_clients (when available)
ip neigh show        → MAC → IP mapping for associated clients
logread | grep AP-STA-…  → event timeline
```

Client hostnames are resolved locally through unbound and mDNS on the firewall.
Read-only collection never writes to the APs; management actions (opt-in via
the "AP management" setting) write wireless config only, and always through
`uci commit wireless` + `wifi reload`.

## Setup

1. Create a dedicated key pair on the firewall:
   `ssh-keygen -t ed25519 -f ~/tuxwall-openwrt-key -N "" -C tuxwall-openwrt`
2. Add the public half to each AP:
   `echo "<contents of ~/tuxwall-openwrt-key.pub>" >> /etc/dropbear/authorized_keys`
3. Install the plugin, open **System → Plugins → OpenWrt Access Points**,
   paste the AP IPs and the private key, save, then **Test connection**.

Password auth is supported if `sshpass` is installed on the firewall, but
key auth is recommended.

## Client hostnames

Names are resolved best-first from:

1. **Kea DHCP leases** — authoritative, covers every DHCP client (phones,
   TVs, laptops). The lease file is root-only, so enable the optional
   one-time mirror (below) to activate this source.
2. **mDNS** (avahi-browse on the firewall) — works with zero setup; covers
   IoT that announces itself (Shelly, ESPHome, HomeKit, printers). Cached
   for ~60 s so refreshes stay fast.
3. **Reverse DNS** via unbound — usually empty on stock setups.

### Optional: mirror the Kea lease file (2 minutes, root)

```ini
# /etc/systemd/system/tuxwall-kea-mirror.service
[Unit]
Description=Mirror Kea lease file for the TuxWall OpenWrt plugin
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'cp /var/lib/kea/kea-leases4.csv /var/lib/tuxwall/kea-leases.csv && chmod 644 /var/lib/tuxwall/kea-leases.csv'
```

```ini
# /etc/systemd/system/tuxwall-kea-mirror.timer
[Unit]
Description=Refresh Kea lease mirror every 2 minutes
[Timer]
OnBootSec=1min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tuxwall-kea-mirror.timer
```

The mirror contains hostnames, MACs and IPs (no credentials) and is what
the plugin reads at `/var/lib/tuxwall/kea-leases.csv`.

## Hardening options

- The plugin worker runs unprivileged (`tuxwall-plugin` / `nobody`) with a
  20-second timeout and a private /tmp; the private key is written to a
  0600 temp file only for the duration of each collection.
- For stricter AP-side control, deploy a read-only status script on each AP
  and restrict the authorized key with `command="/bin/sh /root/status.sh"`,
  then have the plugin use that (the collector sends its script via stdin,
  so a forced-command wrapper is a drop-in change).
