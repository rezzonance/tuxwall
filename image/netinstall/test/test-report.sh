#!/bin/sh
# TEST ONLY: installed into the netinstall test VM. Waits for the unattended
# tuxwall-setup run, prints a machine-readable report on the serial console
# and powers the VM off.
out=/dev/ttyS0
[ -w "$out" ] || out=/dev/console
say() { echo "$*" >"$out"; }
i=0
while [ $i -lt 3600 ]; do
    [ -e /etc/tuxwall/setup-done ] && break
    # the wizard runs as "bash tuxwall-setup": ask systemd, not pgrep
    if [ $i -gt 120 ] && [ -e /etc/tuxwall/setup-pending ] \
       && ! systemctl -q is-active tuxwall-setup@ttyS0.service tuxwall-setup@tty1.service; then
        break
    fi
    sleep 2; i=$((i + 2))
done
sleep 5
check() {   # check NAME cmd...
    n=$1; shift
    if "$@" >/dev/null 2>&1; then say "TUXWALL-TEST-CHECK $n PASS"; else say "TUXWALL-TEST-CHECK $n FAIL"; fi
}
say "TUXWALL-TEST-REPORT-BEGIN"
check setup-done test -e /etc/tuxwall/setup-done
check pending-cleared test ! -e /etc/tuxwall/setup-pending
check firstboot-units-disabled sh -c '! ls /etc/systemd/system/multi-user.target.wants/tuxwall-setup@* 2>/dev/null'
for s in nginx tuxwall unbound kea-dhcp4-server radvd ssh; do
    check "active-$s" systemctl is-active --quiet "$s"
done
# LAN = 172.31.250.1/24 (setup-answers.test). curl binds to that address, so
# nothing leaves the VM through QEMU's NAT when the LAN is not configured.
LANIP=172.31.250.1
check lan-address sh -c "ip -4 -o addr show | grep -q ' $LANIP/24'"
check dashboard-https-lan sh -c "curl -sk --interface $LANIP -o /dev/null -w '%{http_code}' https://$LANIP/ | grep -q '^200\$'"
check api-admin-created sh -c "curl -sk --interface $LANIP https://$LANIP/api/auth/session | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get(\"setup_required\") is False else 1)'"
check ssh-listening sh -c 'ss -Hltn "( sport = :22 )" | grep -q .'
check ufw-active sh -c 'ufw status | grep -q "Status: active"'
check internet-dns getent hosts archive.ubuntu.com
check tuxwall-apt-list grep -q rezzonance.github.io/tuxwall /etc/apt/sources.list.d/tuxwall.list
say "TUXWALL-TEST-INFO tuxwall=$(dpkg-query -W -f='${Version}' tuxwall 2>/dev/null) kernel=$(uname -r)"
say "TUXWALL-TEST-INFO secureboot=$(mokutil --sb-state 2>/dev/null | head -n1 || echo n/a) $(dmesg 2>/dev/null | grep -m1 -i 'secure boot' || true)"
say "TUXWALL-TEST-INFO ca=$(/usr/local/sbin/tuxwall-tls status 2>/dev/null | grep -m1 '^ca:' || true)"
ip -br addr | sed 's/^/TUXWALL-TEST-INFO ip /' >"$out"
tail -n 25 /var/log/tuxwall-setup.log 2>/dev/null | sed 's/^/TUXWALL-TEST-LOG setup /' >"$out"
tail -n 40 /var/log/tuxwall-install.log 2>/dev/null | sed 's/^/TUXWALL-TEST-LOG install /' >"$out"
say "TUXWALL-TEST-REPORT-END"
sleep 3
systemctl poweroff --check-inhibitors=no
