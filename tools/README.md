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
absorption, the lockdown rule plan (high mode keeps WAN DHCP, IPv6 ND and
replies to router-opened connections above the DROP), enforce/lift
idempotence, push dedupe + summary, push-before-enforce, the state lock
(threads + processes), set-mode/resolve audit and the "still tripped"
warning, eve rotation (rename, copytruncate, oversized lines), the kernel
follower, watcher death, and a short daemon run (heartbeats, disabled mode
stops the watchers, re-enforcement, CLI resolve). Real iptables rules are
validated separately inside a throwaway `ip netns` (never on a live
firewall): run the engine with `TUXWALL_TRIPWIRE_ROOT=<tmp>` plus
`TUXWALL_TRIPWIRE_NETNS=<ns>`.
