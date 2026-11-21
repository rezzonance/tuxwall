# CrowdSec and the custom banlist

The dashboard's **Custom Banlist** (`/etc/tuxwall/custom-blocklist.txt`, one
IP or CIDR per line) is applied to CrowdSec by the TuxWall API itself
(`sync_custom_blocklist` in `api_server.py`). The CrowdSec engine does **not**
read the file any more.

## How bans are applied (since Nov 2026)

- **Dashboard add**: the entry is appended to the file and banned at once
  (`cscli decisions add --reason custom/custom-blocklist --duration 8760h`).
- **Dashboard remove**: the entry is dropped from the file and its decisions
  are deleted; a re-sync then re-applies anything still listed (for example a
  listed range that contained the removed IP).
- **Sync** (90 s after the API starts, then every 6 hours, retried every
  10 minutes while CrowdSec is down): compares the file with the live
  `custom/custom-blocklist` decisions and changes only the difference:
  - listed but not banned -> banned (one `cscli decisions import` for all);
  - newest ban older than 20 days -> re-issued: in iptables mode the
    firewall bouncer caps ipset timeouts at ~24.8 days and only re-adds an
    IP when it sees a new decision; `crowdsec-dedupe` then removes the
    superseded decision. In nftables mode (the default for new installs)
    set elements keep the full year and the API's CrowdSec enforcement
    pass (`crowdsec_fw.py`) re-times any element a newer, longer ban did
    not extend, so the refresh is redundant there but harmless;
  - listed ranges (CIDR): nftables mode keeps them in TuxWall's own
    `inet tuxwall_crowdsec_ranges` table (the bouncer's nft sets hold single
    addresses only); in iptables mode the bouncer's hash:net ipsets hold them;
  - banned as `custom/custom-blocklist` but no longer listed -> lifted
    (exact value and scenario only). Held back if the file cannot be read or
    the diff would lift most of the list at once (a truncated file must
    never mass-unban);
  - entries inside protected CDN/infrastructure ranges (Cloudflare,
    api.anthropic.com - `PROTECTED_NETS`) are never banned automatically,
    matching what the engine's `crowdsecurity/cdn-whitelist` did before.

Hand edits to the file are picked up by the next sync; to apply sooner,
reload the dashboard API (`sudo systemctl reload tuxwall`; the sync runs
90 s later) or re-add the entry from the dashboard.

Every listed entry has one active ban (briefly two after a refresh, until
crowdsec-dedupe runs); restarting or reloading CrowdSec no longer touches
them.

## Why the engine chain was removed

Until 3.3.1 three files made the engine re-read the whole file on every
start and reload: `acquis.d/custom-blocklist.yaml` (`mode: cat`),
`parsers/s01-parse/custom-blocklist.yaml` and
`scenarios/custom-blocklist.yaml`. Each pass poured ~320 new alerts and
1-year decisions for IPs that were already banned - duplicates that grew
the store (21 MB + 21 MB WAL, ~16k alerts on the reference install), cost
crowdsec minutes of CPU at every boot, and needed `crowdsec-dedupe` to
clean up after them. The package no longer ships those files; upgrades
remove them.

The `custom_blocklist_remediation` profile in `/etc/crowdsec/profiles.yaml`
(merged by hand on older installs) only matched the engine's own alerts for
that scenario and is now inert; it can stay or be removed.

## crowdsec-dedupe

`crowdsec-dedupe.timer` runs `/usr/local/sbin/crowdsec_dedupe.py` every
6 hours: it collapses duplicate active decisions (keeping the longest expiry
per value + scenario + type + origin; custom-blocklist bans collapse across
origins) and prunes decision-less alerts older than 7 days.

## Firewall bouncer: nftables mode (upgrades migrate)

In iptables mode the bouncer keeps bans in ipsets, whose timeouts are capped
at ~24.8 days: 90-day and 1-year bans silently drop out of the kernel. New
installs therefore use nftables mode (input hook only, priority -10 so bans
drop before ufw, no forward hook). Package upgrades move an existing
iptables-mode bouncer over with `/usr/local/sbin/tuxwall-bouncer-nft-migrate`
(run by the postinst; `--check` shows what it would do):

- only when the bouncer is installed, active and in iptables mode, nft works
  and the kernel keeps a 365-day set timeout (scratch table, removed again);
  the deny action is kept; a `.local` override of `mode`/`nftables*` is
  respected (skipped);
- zero gap: the old bouncer is killed with SIGKILL so its CROWDSEC_CHAIN and
  ipsets keep enforcing, the new one starts, and only once its nft sets hold
  the bans (>= 90 % of the old ipset entries, input hook, priority before
  ufw) are the old chain/jumps and ipsets removed;
- otherwise (timeout 90 s, wrong hook/priority, failed start) the iptables
  config is restored and the bouncer restarted - the box is left as it was,
  and the migration is not retried automatically (`--force` retries);
- once migrated, a bouncer the owner switches back to iptables stays so.

Opt out: `sudo touch /etc/tuxwall/no-bouncer-migration`. Log:
`/var/log/tuxwall/bouncer-migration.log`; state:
`/var/lib/tuxwall/bouncer-nft-migration.json`; backups (config, iptables /
ip6tables / ipset saves, nft ruleset): `/var/backups/tuxwall-bouncer-nft-<time>/`.
Manual rollback: install the backed-up `crowdsec-firewall-bouncer.yaml.pre-nft`
as `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml` (root, 0600) and
`sudo systemctl restart crowdsec-firewall-bouncer`.
