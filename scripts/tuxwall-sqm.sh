#!/bin/bash
# TuxWall SQM - CAKE qdisc on the WAN port.
# Phase 1: egress (upload) shaping + per-LAN-host fairness
# Phase 2: ingress (download) shaping via IFB + per-LAN-host fairness
set -u

# Set WAN to your actual WAN-facing network interface (e.g. eth0, enp3s0, ppp0)
WAN="eth0"
IFB="ifb4wan"

# Set to ~95% of your provisioned upload speed to avoid ISP queue buildup
UP_RATE="95mbit"
# Set to ~92% of your provisioned download speed
DOWN_RATE="920mbit"

# Wait up to 30s for the WAN port (reboot ordering)
n=0
while ! ip link show "$WAN" >/dev/null 2>&1; do
    n=$((n + 1))
    [ "$n" -ge 30 ] && echo "WAN $WAN not found, aborting" && exit 1
    sleep 1
done

# Clean slate (idempotent re-runs)
tc qdisc del dev "$WAN" root 2>/dev/null || true
tc qdisc del dev "$WAN" ingress 2>/dev/null || true
ip link del "$IFB" 2>/dev/null || true

# --- Phase 1: upload ---
# dual-srchost = fair split between LAN hosts while contending
# ack-filter   = reclaim upload wasted on TCP ACK floods (asymmetric links)
# nat          = see through NAT so fairness applies per real host
# overhead/mpu = DOCSIS framing compensation
tc qdisc replace dev "$WAN" root cake \
    bandwidth "$UP_RATE" diffserv3 nat dual-srchost ack-filter \
    overhead 18 mpu 64

# --- Phase 2: download ---
# Can't queue what already arrived, so redirect ingress to a virtual IFB
# and shape there. dual-dsthost = fair split toward LAN hosts.
modprobe ifb 2>/dev/null || true
ip link add name "$IFB" type ifb || { echo "failed to create $IFB"; exit 1; }
ip link set "$IFB" up
tc qdisc add dev "$WAN" handle ffff: ingress
tc filter add dev "$WAN" parent ffff: matchall action mirred egress redirect dev "$IFB"
tc qdisc replace dev "$IFB" root cake \
    bandwidth "$DOWN_RATE" diffserv3 nat dual-dsthost \
    overhead 18 mpu 64

echo "SQM active: up=$UP_RATE down=$DOWN_RATE on $WAN (+$IFB)"
