#!/bin/bash
###############################################################################
#  TuxWall - OpenCanary deployment (deception services)
#  ----------------------------------------------------
#  Deploys the OpenCanary deception honeypot for tuxwall: WAN-only emulators
#  (SSH 22, VNC 5900, MSSQL 1433, Redis 6379, SNMP 161/udp) running as a
#  sandboxed system user, with its Slack-style webhook wired into the
#  tuxwall dashboard (any event with a global source IP -> CrowdSec 1y ban
#  + tuxwall.org community report, same pipeline as the tarpit).
#
#  DEPENDENCIES (all installed by this script):
#    apt:  python3-venv        - the canary runs from a venv at /opt/opencanary
#    pip:  opencanary          - NOT in the Ubuntu archives (PyPI only)
#    pip:  scapy               - required by the SNMP canary module; NOT a
#                                default dependency of the opencanary package
#                                and must be installed explicitly
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
#      (bind-first, same invariant as the tarpit)
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

echo "== 4/6 dashboard receiver (canary hits -> CrowdSec ban + community report) =="
# The canary webhook route (/api/canary/hit) ships with tuxwall v2.9.x.
systemctl is-active --quiet tuxwall.service || {
    echo "WARNING: tuxwall is not running - webhook events will 403 until it is."
}

echo "== 5/6 start the canary =="
systemctl daemon-reload
systemctl enable --now opencanary.service
sleep 5
systemctl is-active opencanary.service
/usr/local/sbin/opencanary-render-conf

echo "== 6/6 firewall: open WAN ports ONLY for ports the canary actually bound =="
WANIP=$(ip -j -4 addr show enp5s0 | python3 -c 'import sys,json;print(next(a["local"] for i in json.load(sys.stdin) for a in i["addr_info"]))')
for P in $(ss -tln | awk -v ip="$WANIP" '$4 ~ ip":" {split($4,a,":"); print a[length(a)]}' | sort -u); do
    case "$P" in
        22|5900|1433|6379)  # canary ports only - the tarpit owns its own rules
            ufw allow in on enp5s0 to any port $P proto tcp comment "tuxwall canary" >/dev/null
            echo "   tcp/$P allowed (canary bound it)"
            ;;
    esac
done
if ss -uln | grep -q ":161 "; then
    ufw allow in on enp5s0 to any port 161 proto udp comment "tuxwall canary snmp" >/dev/null
    echo "   udp/161 allowed (snmp canary bound)"
fi

echo
echo "DONE. Canary emulators live on the WAN address only."
echo "Events: /var/log/opencanary/opencanary.log - every global source is"
echo "auto-banned via CrowdSec and reported to tuxwall.org."
