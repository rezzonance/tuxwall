#!/bin/sh
# TEST ONLY: installed into the netinstall test VM. Waits for the unattended
# tuxwall-setup run, prints a machine-readable report on the serial console
# (+ /var/log/tuxwall-test-report.log) and powers the VM off - unless a QEMU
# guest agent channel exists (Proxmox lab: the report is read through the
# agent, the VM stays up for more checks).
out=/dev/ttyS0
[ -w "$out" ] || out=/dev/console
LOG=/var/log/tuxwall-test-report.log
: >"$LOG"
say() { echo "$*" | tee -a "$LOG" >"$out"; }
emit() { tee -a "$LOG" >"$out"; }
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
check lan-isolated test -e /run/tuxwall-test/lan-isolated
sed 's/^/TUXWALL-TEST-LOG /' /var/log/tuxwall-test-lan-gate.log 2>/dev/null | emit
check setup-done test -e /etc/tuxwall/setup-done
check pending-cleared test ! -e /etc/tuxwall/setup-pending
check firstboot-units-disabled sh -c '! ls /etc/systemd/system/multi-user.target.wants/tuxwall-setup@* 2>/dev/null'
for s in nginx tuxwall unbound kea-dhcp4-server radvd ssh crowdsec crowdsec-firewall-bouncer; do
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
check login-summary grep -q '^TuxWall dashboard: https://' /etc/issue.d/zz-tuxwall.issue
if [ -e /etc/tuxwall/vm-image ]; then
    # VM image (image/vm/test/make-test-seed.sh): cloud-init + the auto answers path
    check vm-cloud-init-done sh -c 'cloud-init status 2>/dev/null | grep -q "^status: done"'
    # shellcheck disable=SC2016  # expanded by the inner sh
    check vm-rootfs-grown sh -c '[ "$(df -B1G --output=size / | tail -n1 | tr -d " ")" -ge 10 ]'
    check vm-password-file-removed test ! -e /etc/tuxwall/test-admin-password
    say "TUXWALL-TEST-INFO vm-image $(tr '\n' ' ' </etc/tuxwall/vm-image)"
fi
say "TUXWALL-TEST-INFO tuxwall=$(dpkg-query -W -f='${Version}' tuxwall 2>/dev/null) kernel=$(uname -r)"
say "TUXWALL-TEST-INFO secureboot=$(mokutil --sb-state 2>/dev/null | head -n1 || echo n/a) $(dmesg 2>/dev/null | grep -m1 -i 'secure boot' || true)"
say "TUXWALL-TEST-INFO ca=$(/usr/local/sbin/tuxwall-tls status 2>/dev/null | grep -m1 '^ca:' || true)"
ip -br addr | sed 's/^/TUXWALL-TEST-INFO ip /' | emit
tail -n 25 /var/log/tuxwall-setup.log 2>/dev/null | sed 's/^/TUXWALL-TEST-LOG setup /' | emit
tail -n 40 /var/log/tuxwall-install.log 2>/dev/null | sed 's/^/TUXWALL-TEST-LOG install /' | emit
say "TUXWALL-TEST-REPORT-END"
[ -e /dev/virtio-ports/org.qemu.guest_agent.0 ] && exit 0
sleep 3
systemctl poweroff --check-inhibitors=no
