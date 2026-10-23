# CrowdSec custom-blocklist chain

These three files are the engine side of the dashboard's **Custom Banlist**
(`/etc/tuxwall/custom-blocklist.txt`): they make the CrowdSec daemon itself
re-apply every file entry as a 1-year ban on each restart/reload, so the
permanent banlist survives anything without the API server's involvement.

| File (package path) | Installs to |
|---|---|
| `acquis.d/custom-blocklist.yaml` | `/etc/crowdsec/acquis.d/custom-blocklist.yaml` |
| `parsers/s01-parse/custom-blocklist.yaml` | `/etc/crowdsec/parsers/s01-parse/custom-blocklist.yaml` |
| `scenarios/custom-blocklist.yaml` | `/etc/crowdsec/scenarios/custom-blocklist.yaml` |

**Historical bug fixed in 3.0.6:** the acquis previously pointed at
`/etc/netdash/custom-blocklist.txt` — a path from before the rename — so the
whole re-apply chain silently never ran and older dashboard entries showed
"not active" forever. It now reads `/etc/tuxwall/custom-blocklist.txt`.

**Important:** the parser's pattern is anchored (`^IP-or-CIDR$`). Lines with
inline comments or trailing text are silently skipped — one entry per line,
nothing else. The dashboard only writes clean lines, but hand edits have
broken this before.

## One manual step on fresh installs: the remediation profile

CrowdSec has no `profiles.d`, so the profile that gives these alerts their
1-year duration must be merged into `/etc/crowdsec/profiles.yaml` (prepended
above the default profiles, so it wins via `on_success: break`):

```yaml
name: custom_blocklist_remediation
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.Scenario == "custom/custom-blocklist"
decisions:
 - type: ban
   duration: 8760h
on_success: break
```

Then `sudo systemctl reload crowdsec`.
