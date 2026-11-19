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
