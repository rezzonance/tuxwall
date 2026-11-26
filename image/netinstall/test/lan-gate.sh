#!/bin/sh
# TEST ONLY (Proxmox lab safety gate, installed by the test seed): the test
# VM's LAN NIC sits on a lab bridge whose physical port must be unplugged -
# the wizard starts Kea + radvd there. Before it may run, the LAN NIC (LAN_MAC
# of the answers file) must have no address from elsewhere and receive no
# frame at all for 30 s (an attached LAN shows ARP/mDNS/DHCP broadcasts within
# seconds). Fail-closed:
#   PASS -> /run/tuxwall-test/lan-isolated (tuxwall-setup@ requires it)
#   FAIL -> LAN NIC down, wizard blocked, VM powers off in 10 minutes
set -u
WATCH=${TUXWALL_LAN_GATE_SECONDS:-30}
ANS=/etc/tuxwall/setup-answers
LOG=/var/log/tuxwall-test-lan-gate.log
RUN=/run/tuxwall-test
con=/dev/ttyS0
[ -w "$con" ] || con=/dev/console
mkdir -p "$RUN"
rm -f "$RUN/lan-isolated"
dev=""
say() { echo "TUXWALL-TEST-GATE $*" | tee -a "$LOG" >"$con" 2>/dev/null || true; }
fail() {
    say "lan-isolated FAIL: $*"
    [ -n "$dev" ] && ip link set dev "$dev" down
    shutdown -P +10 "TuxWall test: LAN not isolated" 2>/dev/null || true
    exit 1
}
mac="$(sed -n 's/^LAN_MAC=//p' "$ANS" 2>/dev/null | tr 'A-F' 'a-f')"
[ -n "$mac" ] || fail "no LAN_MAC in $ANS"
for d in /sys/class/net/*; do
    [ "$(cat "$d/address" 2>/dev/null)" = "$mac" ] && dev=${d##*/}
done
[ -n "$dev" ] || fail "no NIC with MAC $mac"
glob="$(ip -o addr show dev "$dev" scope global | awk '{print $4}' | tr '\n' ' ')"
[ -z "$glob" ] || fail "$dev already has an address from elsewhere: $glob"
# Quiet: no IPv6 (RS/NS) and no IPv4 address of our own while listening.
echo 1 >"/proc/sys/net/ipv6/conf/$dev/disable_ipv6" 2>/dev/null || true
ip -4 addr flush dev "$dev"
ip link set dev "$dev" up || fail "cannot bring $dev up"
sleep 3
say "watching $dev ($mac) for ${WATCH}s, carrier=$(cat "/sys/class/net/$dev/carrier" 2>/dev/null)"
rx0="$(cat "/sys/class/net/$dev/statistics/rx_packets")"
cap="$(python3 - "$dev" "$WATCH" <<'PY'
import socket, sys, time
dev, secs = sys.argv[1], float(sys.argv[2])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))  # ETH_P_ALL
s.bind((dev, 0))
end, seen = time.time() + secs, []
while True:
    left = end - time.time()
    if left <= 0:
        break
    s.settimeout(left)
    try:
        data, addr = s.recvfrom(65535)
    except socket.timeout:
        break
    if addr[2] == socket.PACKET_OUTGOING:
        continue
    seen.append("%s > %s type=0x%s len=%d" % (data[6:12].hex(":"), data[0:6].hex(":"), data[12:14].hex(), len(data)))
print("frames=%d" % len(seen))
for line in seen[:10]:
    print("frame " + line)
PY
)" || fail "capture failed on $dev"
rx1="$(cat "/sys/class/net/$dev/statistics/rx_packets")"
printf '%s\n' "$cap" | while IFS= read -r l; do say "$l"; done
n="$(printf '%s\n' "$cap" | sed -n '1s/^frames=//p')"
[ "$n" = 0 ] || fail "foreign frames on $dev: ${n:-?} (rx_packets $rx0 -> $rx1)"
[ "$rx0" = "$rx1" ] || fail "rx_packets on $dev moved $rx0 -> $rx1"
echo 0 >"/proc/sys/net/ipv6/conf/$dev/disable_ipv6" 2>/dev/null || true
date -u '+%Y-%m-%dT%H:%M:%SZ' >"$RUN/lan-isolated"
say "lan-isolated PASS: $dev received nothing in ${WATCH}s (rx_packets $rx0 -> $rx1)"
