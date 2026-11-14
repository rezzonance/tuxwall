---
name: TuxWall dashboard development
description: Use when changing the TuxWall dashboard itself - HTML, JavaScript, CSS or the Python API (api_server.py and its sibling modules) - or debugging a dashboard page, API endpoint or the dashboard service. File map, backups, cache-busting, safe reload and rollback.
---

# Working on the TuxWall dashboard

## File map (live install)
- `/var/www/html/index.html` - all page markup, cards, modals; script/style tags carry `?v=<timestamp>` cache-busters.
- `/var/www/html/scripts/dashboard.js` - main frontend logic; feature modules beside it
  (`interfaces.js`, `firewall-plus.js`, `insights.js`, `netmap.js`, `enhance.js`, `buttons.js`, `worldmap.js`).
- `/var/www/html/css/*.css` - `style.css` base, `themes.css` theme tokens, one file per feature (`interfaces.css`, `firewall-plus.css`, ...).
- `/var/www/html/includes/api_server.py` - the root-run API (`tuxwall.service`, 127.0.0.1:8008, behind nginx).
  Sibling modules in the same directory: `topology.py` (interface roles/policy), `fw_guard.py` (managed-rule guard),
  `fw_snap.py` (snapshots, confirm-or-rollback), `fw_lint.py` (Findings), `fw_edit.py`, `fw_hits.py`, `canary_egress.py`,
  `assign_plan.py`/`assign_apply.py` (Interface Assignments). No `__pycache__` in the web root (`sys.dont_write_bytecode`).
- State/config: `/etc/tuxwall/*.json`, `/var/lib/tuxwall/`. Agent facts: `/var/lib/tuxwall/agent/facts.md` (written by the API).
- nginx site: `/etc/nginx/sites-available/tuxwall`.

## Rules
- Never change the dashboard theme: no `POST /api/themes/active`, no edits to `active_theme` in `/etc/tuxwall/ui.json`,
  no changes to theme token values in `themes.css`. New UI uses the existing CSS variables (theme tokens) only.
- Read the target file and match its patterns before editing; smallest change that works; ask before large rewrites.
- Back up before every edit: `cp -a <file> <file>.bak.$(date +%Y%m%d-%H%M%S)` (the owner may also keep copies in a backup directory - ask).
- Do not echo public IPs, keys, tokens or peer configs into anything under `/var/www/html`.
- Admin-only data stays behind the API's auth; POSTs need a same-origin `Origin` header (CSRF check).

## Frontend change
1. Back up, edit the JS/CSS/HTML.
2. Bump the `?v=` value of every changed JS/CSS file in `index.html` (e.g. `date +%Y%m%d%H%M%S`) so browsers reload it.
3. Syntax check JS: `node --check <file>` if node is available.
4. Ask the owner to hard-reload and check the page; check the browser console for errors.

## API change
1. Back up `api_server.py` (and any module you touch).
2. Edit; `python3 -m py_compile` on a copy outside the web root (avoid creating `__pycache__` there), e.g. compile with `cfile=/tmp/x.pyc`.
3. Reload: `sudo systemctl reload tuxwall` (SIGUSR1 re-exec, ~2 s; every dashboard user is logged out). Restarting tuxwall,
   nginx or tuxwall-agent is dashboard-only and safe for the network.
4. Check it came back: `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8008/api/auth/session` (expect 200) and
   `journalctl -u tuxwall -n 30` for tracebacks. If it does not come up within ~20 s: restore the backup, reload again.
5. Background threads must never die on exceptions and must stay cheap (the API also serves the live network pages).

## Debugging a page
- `journalctl -u tuxwall --since -10min` (tracebacks, `[fw]`, `[incidents]` lines), `journalctl -u nginx`, `/var/log/nginx/error.log`.
- Endpoints are dispatched in `Handler.do_GET` / `do_POST` of api_server.py: `grep -n '"/api/<name>' /var/www/html/includes/api_server.py`.
- Dashboard down but network fine = control plane only: restart `tuxwall` / `nginx`, roll back the newest backup if an edit caused it.
