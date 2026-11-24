#!/bin/bash
###############################################################################
#  TuxWall - OpenCanary deployment (deception services)
#  ----------------------------------------------------
#  Deploys the OpenCanary deception honeypot for tuxwall: WAN-IPv4-only
#  emulators (SSH 22, VNC 5900, MSSQL 1433, Redis 6379; the SNMP 161/udp
#  decoy was retired on 2026-11-19 - UDP evidence is spoofable) running as a
#  sandboxed system user, with its Slack-style webhook wired into the
#  tuxwall dashboard (any event with a global source IP that passes the
#  never-ban guard -> CrowdSec 1y ban + tuxwall.org community report, same
#  pipeline as the tarpit).
#
#  DEPENDENCIES (all installed by this script):
#    apt:  python3-venv        - the canary runs from a venv at /opt/opencanary
#    pip:  opencanary          - NOT in the Ubuntu archives (PyPI only)
#    pip:  scapy               - only needed by the (retired) SNMP module;
#                                kept so re-enabling it needs no new install
#
#  Hardening baked in (each learned the hard way - see git history):
#    - twistd runs as a dedicated opencanary system user, never root
#    - CAP_NET_BIND_SERVICE only (ports 22/161), ProtectSystem=strict,
#      ProtectHome, PrivateTmp, NoNewPrivileges
#    - AF_NETLINK allowed in RestrictAddressFamilies (scapy route lookups)
#    - config is root:opencanary 0640 (canary must read it; it embeds the
#      webhook token, so never world-readable), re-rendered from the
#      template at every start with the CURRENT WAN IPv4 (no hardcoding)
#    - device.listen_addr = WAN IPv4 only - the emulators are unreachable
#      from the LAN/WireGuard; sshd keeps 192.168.1.1/10.0.0.1:22
#    - firewall rules open ONLY for ports the canary actually bound
#      (bind-first, same invariant as the tarpit), IPv4 only (the canary
#      binds the WAN IPv4); the dashboard's canary watchdog closes them when
#      the canary stops and reopens them when it is back
#    - webhook handler with a timeout (tuxwall_canary_handler.py; the stock
#      SlackHandler posts without one, from the reactor thread)
#    - /etc/logrotate.d/opencanary (weekly / 20M, copytruncate)
#
#  Usage: sudo bash scripts/opencanary/deploy-opencanary.sh
###############################################################################
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_WWW=/var/www/html
TS=$(date +%Y%m%d-%H%M%S)

echo "== 1/6 system user + directories =="
getent group opencanary >/dev/null || groupadd --system opencanary
getent passwd opencanary >/dev/null || useradd --system --gid opencanary \
    --home-dir /var/lib/opencanary --shell /usr/sbin/nologin opencanary
mkdir -p /etc/opencanaryd

echo "== 2/6 venv + opencanary + scapy (from PyPI) =="
apt-get install -y --no-install-recommends python3-venv
if [ ! -x /opt/opencanary/bin/twistd ]; then
    python3 -m venv /opt/opencanary
    /opt/opencanary/bin/pip install --quiet opencanary scapy
else
    /opt/opencanary/bin/pip install --quiet scapy
fi

echo "== 3/6 config template + renderer + systemd unit =="
install -o root -g root -m 0644 "$HERE/opencanary.conf.tmpl" /etc/opencanaryd/opencanary.conf.tmpl
install -o root -g root -m 0755 "$HERE/opencanary-render-conf" /usr/local/sbin/opencanary-render-conf
install -o root -g root -m 0644 "$HERE/opencanary.service" /etc/systemd/system/opencanary.service
SITE=$(/opt/opencanary/bin/python3 -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
install -o root -g root -m 0644 "$HERE/tuxwall_canary_handler.py" "$SITE/tuxwall_canary_handler.py"
install -o root -g root -m 0644 "$HERE/opencanary.logrotate" /etc/logrotate.d/opencanary

echo "== preflight: public WAN IPv4 + free decoy ports =="
WANIF=$(python3 -c 'import json;print((json.load(open("/etc/tuxwall/interfaces.json")).get("wan") or {}).get("device") or "enp5s0")' 2>/dev/null || echo enp5s0)
# the renderer's own rule decides the address (first global IPv4 on the WAN)
if ! /usr/local/sbin/opencanary-render-conf >/dev/null; then
    echo "ERROR: no public (global) IPv4 on the WAN interface $WANIF." >&2
    echo "       The canary binds the WAN IPv4 only; behind CGNAT / double NAT (a private" >&2
    echo "       100.64.x / 10.x / 172.16-31.x / 192.168.x WAN address) it cannot run." >&2
    echo "       Nothing was started and no firewall rule was opened." >&2
    exit 1
fi
WANIP=$(python3 -c 'import json;print(json.load(open("/etc/opencanaryd/opencanary.conf"))["device.listen_addr"])')
PORTS=$(python3 -c '
import json
c = json.load(open("/etc/opencanaryd/opencanary.conf"))
print(" ".join(str(c[k[:-8] + ".port"]) for k in sorted(c)
               if k.endswith(".enabled") and c[k] is True and k[:-8] + ".port" in c and k != "snmp.enabled"))')
CONFLICT=""
for P in $PORTS; do
    # anything but the canary itself on 0.0.0.0 / [::] / * / the WAN IPv4 blocks its bind
    WHO=$(ss -Htlnp | awk -v ip="$WANIP" -v p="$P" '
        { n = split($4, a, ":"); if (a[n] != p) next
          addr = substr($4, 1, length($4) - length(p) - 1)
          if ((addr == "0.0.0.0" || addr == "[::]" || addr == "*" || addr == ip) && $0 !~ /twistd/) {
              match($0, /\(\("[^"]+"/); print (RSTART ? substr($0, RSTART + 3, RLENGTH - 4) : "a service") ; exit } }')
    [ -n "$WHO" ] && CONFLICT="$CONFLICT
       port $P/tcp: $WHO listens on every address (or on $WANIP)"
done
if [ -n "$CONFLICT" ]; then
    echo "ERROR: the canary cannot bind its decoy ports on $WANIP:$CONFLICT" >&2
    echo "       A fresh install's sshd listens on 0.0.0.0:22 (LAN-only through ufw). Bind it to" >&2
    echo "       the LAN address(es) instead (ListenAddress in /etc/ssh/sshd_config.d/, then" >&2
    echo "       'systemctl restart ssh'), or set \"ssh.enabled\": false in" >&2
    echo "       $HERE/opencanary.conf.tmpl, then re-run. Nothing was started." >&2
    exit 1
fi

echo "== 4/6 dashboard receiver (canary hits -> CrowdSec ban + community report) =="
# The canary webhook route (/api/canary/hit) ships with tuxwall v2.9.x.
systemctl is-active --quiet tuxwall.service || {
    echo "WARNING: tuxwall is not running - webhook events will 403 until it is."
}

echo "== 5/6 start the canary =="
# The log holds captured attack credentials - root/group readable only
[ -f /var/log/opencanary/opencanary.log ] && \
    chmod 0640 /var/log/opencanary/opencanary.log

systemctl daemon-reload
systemctl enable --now opencanary.service
sleep 5
if ! systemctl is-active --quiet opencanary.service; then
    echo "ERROR: opencanary.service did not stay up ($(systemctl is-active opencanary.service))." >&2
    echo "       Last log lines:" >&2
    journalctl -u opencanary.service -n 15 --no-pager >&2 || true
    echo "       The unit restarts itself (Restart=always); stop it with" >&2
    echo "       'systemctl disable --now opencanary.service' until the cause is fixed." >&2
    echo "       No firewall rule was opened." >&2
    exit 1
fi
echo "active"

echo "== 6/6 firewall: open WAN IPv4 rules ONLY for ports the canary actually bound =="
# the address twistd was given (the renderer's choice), not the first one on the WAN
WANIP=$(python3 -c 'import json;print(json.load(open("/etc/opencanaryd/opencanary.conf"))["device.listen_addr"])')
for P in $(ss -Htlnp | awk -v ip="$WANIP" '$4 ~ "^"ip":" && /twistd/ {split($4,a,":"); print a[length(a)]}' | sort -u); do
    case "$P" in
        22|5900|1433|6379)  # canary ports only - the tarpit owns its own rules
            ufw allow in on "$WANIF" to 0.0.0.0/0 port $P proto tcp comment tuxwall-canary >/dev/null
            echo "   tcp/$P allowed on IPv4 (canary bound it)"
            ;;
    esac
done

echo "== egress containment: the canary user may only reach the webhook + local DNS =="
# Same definition as the installer/postinst (owner-match REJECT in
# ufw-before-output, before the lo-ACCEPT anchor). Idempotent; best-effort.
CE=""
for cand in "$HERE/../../www/includes/canary_egress.py" "$API_WWW/includes/canary_egress.py"; do
    [ -f "$cand" ] && { CE="$cand"; break; }
done
if [ -n "$CE" ]; then
    PYTHONDONTWRITEBYTECODE=1 python3 "$CE" --apply || true
    PYTHONDONTWRITEBYTECODE=1 python3 "$CE" --check >/dev/null 2>&1 \
        && echo "   containment present (before.rules + before6.rules)" \
        || echo "   WARNING: containment not confirmed - check /etc/ufw/before*.rules"
else
    echo "   WARNING: canary_egress.py not found - containment not checked"
fi

echo
echo "DONE. Canary emulators live on the WAN address only."
echo "Events: /var/log/opencanary/opencanary.log - every global source is"
echo "auto-banned via CrowdSec and reported to tuxwall.org."
