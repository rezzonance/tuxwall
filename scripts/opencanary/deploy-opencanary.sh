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
systemctl is-active opencanary.service
/usr/local/sbin/opencanary-render-conf

echo "== 6/6 firewall: open WAN IPv4 rules ONLY for ports the canary actually bound =="
WANIF=$(python3 -c 'import json;print((json.load(open("/etc/tuxwall/interfaces.json")).get("wan") or {}).get("device") or "enp5s0")' 2>/dev/null || echo enp5s0)
WANIP=$(ip -j -4 addr show "$WANIF" | python3 -c 'import sys,json;print(next(a["local"] for i in json.load(sys.stdin) for a in i["addr_info"]))')
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
