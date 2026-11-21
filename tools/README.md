# Dev tools

Static checks that catch the two bug classes that each took the live
dashboard down during 3.0.6 development. Run both before any deploy of the
dashboard files — the deploy script on the maintainer's router runs them
automatically before restarting services.

## boot-check.js — browser boot simulation

```bash
TW_STAGE=/var/www/html TW_JS=/var/www/html/scripts/dashboard.js node tools/boot-check.js
```

Executes the real `dashboard.js` against the real `index.html` with a
stub DOM that models the browser faithfully in two ways that matter:

1. **Parse order** — at script-load time only markup *above* the
   `<script src="dashboard.js">` tag exists. Element IDs placed after the
   script resolve to `null` (this shipped once and killed the login gate,
   logout, and the whole init chain).
2. **DOMContentLoaded** — the real `init()` chain runs to completion; a
   null `addEventListener` or missing element crashes here instead of in
   every user's browser.

Passes when it prints `DOMContentLoaded INIT CHAIN COMPLETED CLEAN`.

## py-name-check.py — module-level name-order check

```bash
python3 tools/py-name-check.py includes/api_server.py collector/tuxwall-collector.py
```

Flags module-level statements that reference names defined later in the
file (`NameError` at import → systemd crash loop; `py_compile` cannot
catch these). Exit 1 on any violation.

## The third check

`python3 -m py_compile` / `node --check` still matter (syntax). The three
together: syntax, import-time names, boot-time DOM — each one catches what
the others can't.

## backup_safety_check.py — backups module (CI)

```bash
python3 tools/backup_safety_check.py                 # pure tests in a temp root
sudo python3 tools/backup_safety_check.py --live     # + sanitize the newest real backup in memory
```

Checks `www/includes/backups.py`: catalog vs `system-backup.sh`, item size
estimates, retention (7 daily / 4 weekly / 3 monthly, newest + pinned kept),
persisted job state and the `backup:failed` incident, the sanitized export
against a synthetic archive containing every known leak type (and, with
`--live`, every secret value of the real archive), upload limits, and the
single-file restore (preview, atomic write, permissions, pre-restore copy,
symlink refusal, strict second confirm, firewall routing, audit log).

## tripwire_check.py — tripwire engine (CI)

```bash
python3 tools/tripwire_check.py
```

Loads `pkg/usr/local/sbin/tuxwall-tripwire` with `TUXWALL_TRIPWIRE_ROOT`
pointing at a temp dir: every path is remapped, the firewall is stubbed
(rules are only recorded) and pushes go to a file. Checks the eve.json
pre-filter and event normalisation, `evaluate()` per mode and deception-port
absorption, config schema v2 (v1 migration to Log only - never Block -,
validation, confirm gate for arming Block, block strength frozen while
tripped, audit), per-check actions, exclusions (router/loopback, the two
real false positives, WAN-only, CIDRs, signature ids), thresholds, the Test
path (no side effects), the event history (hook, filters, 90-day / size
retention, one-time import of tripwire.log), the lockdown rule plan (high mode keeps WAN DHCP, IPv6 ND and
replies to router-opened connections above the DROP), enforce/lift
idempotence, push dedupe + summary, push-before-enforce, the state lock
(threads + processes), set-mode/resolve audit and the "still tripped"
warning, eve rotation (rename, copytruncate, oversized lines), the kernel
follower, watcher death, and a short daemon run (heartbeats, disabled mode
stops the watchers, re-enforcement, CLI resolve). Real iptables rules are
validated separately inside a throwaway `ip netns` (never on a live
firewall): run the engine with `TUXWALL_TRIPWIRE_ROOT=<tmp>` plus
`TUXWALL_TRIPWIRE_NETNS=<ns>`.

Recovery mode (phase 4) in the same sandbox: allowlist building from the
opencode config / model catalog / alerts.json (LAN servers = local models,
plain HTTP never allowlisted, no key material), the OUTPUT rule plan (v4+v6,
REJECT last, DNS only from the resolver uid, ipset match), the state machine
(start only while tripped, durations, extend cap, re-apply after a flush,
refresh, expiry back to the full block, end, a new blocking event closes the
window, restart persistence via `enforce` and the daemon), the unbound
runtime-zone handling (fake control channel: owner zones never overridden, a
pre-existing root zone left alone), the stub DNS client (CNAME + compression),
the incident brief (trip details, no secrets) and the restore checklist.

## tripwire_netns_check.py — recovery firewall + DNS in namespaces (root, manual)

```bash
sudo python3 tools/tripwire_netns_check.py
```

Not in CI. Builds three throwaway namespaces (router / WAN / LAN, veths
created inside them), a WAN DNS stub, TLS endpoints, a LAN "local model" and
an unconfined copy of unbound as the router's resolver
(`tripwire_netns_helpers.py`), then runs the real engine inside the router
namespace for MEDIUM and HIGH: trip, recovery (allowed endpoints reachable
over v4+v6, denied names refused, denied IPs blocked, direct DNS blocked, LAN
still blocked, WAN->router closed in high), extend, expiry, end, daemon
re-apply after a flush + simulated unbound restart, daemon expiry, and
resolve (everything removed). Snapshots of the live iptables/ip6tables/ipset/
unbound zones before and after must match; the namespaces are always deleted.

## deception_check.py — deception layer (CI)

```bash
python3 tools/deception_check.py
```

Imports `www/includes/api_server.py` with every path remapped into a temp
dir, `subprocess.run` faked (cscli/ufw/ss/systemctl answered from fixtures)
and the collector transport stubbed — nothing is banned, opened or sent.
Covers the tarpit slot accounting (per-IP / total caps reserved before a
thread exists, thread-start failure, accept() errors), the `>=` threshold
with its once-per-source flag, bounded TTL maps, the LAN guard incl. the
delegated global IPv6 prefix, the never-ban guard on every ban/report path
(own/recent WAN, protected ranges, infrastructure IPs), cscli return codes,
retired SNMP/UDP evidence, the reporting switch + persistent retry queue
(no key on disk, 0600 atomic writes, backoff, restart), report categories,
the canary firewall plan (IPv4 only, grace before closing) and the cached
tail read of `opencanary.log`. A loopback load test (127.0.0.2, never the
WAN) proves one client cannot exceed the per-IP cap and fds stay bounded.

## custom_blocklist_check.py — custom banlist sync (CI)

```bash
python3 tools/custom_blocklist_check.py
```

Imports `www/includes/api_server.py` with the banlist file in a temp dir and
`subprocess.run` replaced by a fake CrowdSec (an in-memory decision table
answering `cscli decisions list/import/delete/add`). Covers file parsing
(comments, invalid/non-global lines, duplicates, unreadable file), reading
the live bans (longest per value; expired, other-scenario and non-ban
decisions ignored), the pure diff (add, refresh after 20 days, remove,
protected CDN ranges, IPv6 notation), the mass-removal guard, dry-run (no
writes), one import for all adds, exact-value deletes, a second sync being a
no-op, re-adding an active entry not duplicating its ban, and the remove
flow's re-sync. A sync that changes bans triggers one CrowdSec enforcement
pass (stubbed here).

## crowdsec_fw_check.py — CrowdSec bouncer enforcement (CI + root netns)

```bash
python3 tools/crowdsec_fw_check.py              # pure (CI)
sudo python3 tools/crowdsec_fw_check.py --netns # + real nft in a scratch namespace
```

`www/includes/crowdsec_fw.py`: bouncer config parsing (PyYAML and the
fallback parser, defaults, `.local` merge), synthetic `nft -j` tables (hook,
priority before ufw, policy, sets, counters, terse listings), decisions from a
temp SQLite store (longest ban per value, expired/simulated/non-ban skipped),
the re-time plan (elements a longer ban did not extend), the lapsed-element
plan, the Range-ban table (containment, overlaps, REJECT) and `reconcile()`
with a fake runner (dry run, per-element retry when an element vanished,
iptables mode removing a leftover range table, no DB = no writes). `--netns`
loads a bouncer-like table into namespace `twcsfw`, reconciles against real
nft (re-timed elements, atomic abort when an element vanished, Range table
written then removed) and checks the host's tables are unchanged.
firewall_safety_check.py covers the guard side (nft-mode invariants, nft
table ownership).

## bouncer_migrate_check.py — CrowdSec bouncer iptables → nftables upgrade (CI + root netns)

```bash
python3 tools/bouncer_migrate_check.py              # pure (CI)
sudo python3 tools/bouncer_migrate_check.py --netns # + real nft/iptables/ipset in a scratch namespace
```

`pkg/usr/local/sbin/tuxwall-bouncer-nft-migrate` (run by postinst on
upgrades): the config rendering is byte-identical to the installer's
`configure_bouncer` except that the deny action is kept; `.local`
overrides, `ipset list -t` counts, the 365-day timeout probe and the
readiness rule (configured hooks only, priority before ufw, >= 90 % of the old
ipset entries). The whole flow runs against a simulated host (systemctl, nft,
iptables, ipset answered from an in-memory model under a temp root): every
skip case (not installed, opt-out flag, already nftables, other modes, `.local`
override, bouncer stopped, nft unusable, capped timeouts, earlier failure,
owner switched back) changes nothing; the switch SIGKILLs the old bouncer,
never polls with neither backend enforcing, then removes CROWDSEC_CHAIN and
the ipsets; empty/short sets, a forward hook, priority 0 or a failed restart
restore the iptables config and remove the nft tables; config owner/mode,
0700/0600 backups, no API key in the log, a second run is a no-op, `--force`
retries. `--netns` (namespace `twbmig`) runs the probe and the readiness check
against real nft and removes a real CROWDSEC_CHAIN (two jumps) and ipset; the
host's nft tables, ipsets and iptables rules are compared before/after.

## kea_conf_check.py — Kea config with comments (CI)

```bash
python3 tools/kea_conf_check.py
```

`www/includes/kea_conf.py` and its users. Kea allows `//` and `#` line or
trailing comments and `/* */` blocks; the installer writes a `// Generated
by ...` header that strict `json.load` rejected (DHCP reservations returned
500 on fresh installs). Covers stripping only outside strings (URLs with
`//`, `#` in names, `/* */` and escaped quotes inside strings), the installer's
real `kea_json` output, header split and the one-time "Edited from the TuxWall
dashboard" mark (the installer keeps such a file on re-runs:
`kea_is_replaceable` is run in bash), the atomic write (owner/mode kept, no
temp file, idempotent, failed write leaves the file untouched), the API's
reservation add/edit/delete on a commented file (Kea reload stubbed, nothing
under /etc/kea opened), `topology._read_kea`, `assign_plan.r_kea` (header
kept, body-comment warning) and `fw_lint.kea_reservations`.

## pkg_scripts_check.py — maintainer-script decisions (CI)

```bash
python3 tools/pkg_scripts_check.py
```

Cuts the decision functions out of `pkg/DEBIAN/postinst` and runs them with
bash against a fake `systemctl`: the tripwire unit is enabled once by the
package (marker `/var/lib/tuxwall/.tripwire-enabled-once`) even when a legacy
v1 `tripwire.json` exists, an enabled unit is only marked, a unit the owner
disabled after the marker is never re-enabled, a failed enable leaves no
marker; the bouncer migration runs on upgrades only and never fails the
postinst; `prerm remove` forgets the marker only when it disables an enabled
unit. Also `bash -n` on postinst/prerm/postrm and STEP_TOTAL vs the steps.

## port_owner_check.py — port-ownership incidents (CI)

```bash
python3 tools/port_owner_check.py
```

Synthetic `ss -tlnp`/`ss -ulnp` and `systemctl list-sockets` output through
the listener attribution and the `portowner:*` / `sshd:wan` rules:
socket-activated sshd on LAN/VPN addresses (held by systemd, pid 1, until
the first connection) raises nothing; a socket on 0.0.0.0, `*` or the WAN
address, a real stranger, pid 1 without a matching socket unit and a
socket-activated stranger service all still alert.
