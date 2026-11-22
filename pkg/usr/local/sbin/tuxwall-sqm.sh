#!/bin/bash
# TuxWall SQM - CAKE qdisc on the WAN port.
# Phase 1: egress (upload) shaping + per-LAN-host fairness
# Phase 2: ingress (download) shaping via IFB + per-LAN-host fairness
#
# Shipped in the package since 3.3.5 (before: tuxwall-install.sh only, so
# apt installs had no script and the dashboard said "SQM script missing").
# Every per-box value comes from config, never from this file:
#   /etc/tuxwall/sqm.conf        WAN=, UP_RATE=, DOWN_RATE= (System > Traffic Shaping)
#   /etc/tuxwall/interfaces.json the WAN role, when sqm.conf names no WAN
#
# Usage: tuxwall-sqm.sh [--dry-run]
#   --dry-run  print the tc/ip/modprobe commands instead of running them
set -u

DRY_RUN=0
case "${1:-}" in
    "") ;;
    --dry-run|-n) DRY_RUN=1 ;;
    *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

run() {
    if [ "$DRY_RUN" = 1 ]; then
        echo "+ $*"
    else
        "$@"
    fi
}

# Set WAN to your actual WAN-facing network interface (e.g. eth0, enp3s0, ppp0)
WAN="eth0"
IFB="ifb4wan"

# Set to ~95% of your provisioned upload speed to avoid ISP queue buildup
UP_RATE="95mbit"
# Set to ~92% of your provisioned download speed
DOWN_RATE="920mbit"

# The WAN role recorded in /etc/tuxwall/interfaces.json replaces the default.
if [ -r /etc/tuxwall/interfaces.json ]; then
    _w="$(python3 -c 'import json; print((json.load(open("/etc/tuxwall/interfaces.json")).get("wan") or {}).get("device") or "")' 2>/dev/null)"
    [ -n "$_w" ] && WAN="$_w"
fi

# Dashboard-managed override: System > Traffic Shaping writes /etc/tuxwall/sqm.conf
# (WAN=, UP_RATE=, DOWN_RATE=). Values there win over the defaults above.
SQM_CONF="/etc/tuxwall/sqm.conf"
if [ -r "$SQM_CONF" ]; then
    # shellcheck disable=SC1090
    . "$SQM_CONF"
fi

# Wait up to 30s for the WAN port (reboot ordering)
n=0
while ! ip link show "$WAN" >/dev/null 2>&1; do
    if [ "$DRY_RUN" = 1 ]; then
        echo "# WAN $WAN not found (a real run waits 30 s, then aborts)"
        break
    fi
    n=$((n + 1))
    [ "$n" -ge 30 ] && echo "WAN $WAN not found, aborting" && exit 1
    sleep 1
done

# Clean slate (idempotent re-runs)
run tc qdisc del dev "$WAN" root 2>/dev/null || true
run tc qdisc del dev "$WAN" ingress 2>/dev/null || true
run ip link del "$IFB" 2>/dev/null || true

# --- Phase 1: upload ---
# dual-srchost = fair split between LAN hosts while contending
# ack-filter   = reclaim upload wasted on TCP ACK floods (asymmetric links)
# nat          = see through NAT so fairness applies per real host
# overhead/mpu = DOCSIS framing compensation
run tc qdisc replace dev "$WAN" root cake \
    bandwidth "$UP_RATE" diffserv3 nat dual-srchost ack-filter \
    overhead 18 mpu 64

# --- Phase 2: download ---
# Can't queue what already arrived, so redirect ingress to a virtual IFB
# and shape there. dual-dsthost = fair split toward LAN hosts.
run modprobe ifb 2>/dev/null || true
run ip link add name "$IFB" type ifb || { echo "failed to create $IFB"; exit 1; }
run ip link set "$IFB" up
run tc qdisc add dev "$WAN" handle ffff: ingress
run tc filter add dev "$WAN" parent ffff: matchall action mirred egress redirect dev "$IFB"
run tc qdisc replace dev "$IFB" root cake \
    bandwidth "$DOWN_RATE" diffserv3 nat dual-dsthost \
    overhead 18 mpu 64

if [ "$DRY_RUN" = 1 ]; then
    echo "SQM dry run: up=$UP_RATE down=$DOWN_RATE on $WAN (+$IFB) - nothing changed"
else
    echo "SQM active: up=$UP_RATE down=$DOWN_RATE on $WAN (+$IFB)"
fi
