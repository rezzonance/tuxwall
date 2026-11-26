#!/usr/bin/env bash
###############################################################################
#  run-qemu-test.sh - end-to-end QEMU test of the netinstall ISO (TEST variant)
#  ---------------------------------------------------------------------------
#    image/netinstall/build.sh --test
#    image/netinstall/test/run-qemu-test.sh --iso out/tuxwall-netinstall-X-amd64-TEST.iso \
#        --ubuntu-iso ~/.cache/tuxwall-netinstall/ubuntu-26.04.1/ubuntu-26.04.1-live-server-amd64.iso \
#        --mode uefi|bios [--work DIR] [--mem MB] [--phase2-only]
#
#  Phase 1 boots the TEST ISO: unattended install onto a blank 20 GB disk,
#  the Ubuntu ISO file is found on a second (FAT) disk by iso-scan - the
#  shipped "low RAM" path - so the VM fits in 4 GB. Phase 2 boots the
#  installed disk: the first-boot units run tuxwall-setup with the test
#  answers (tuxwall-install.sh --source apt), a report unit prints checks on
#  the serial console and powers off. Exit 0 = every check passed.
#  Phase 2 runs on a qcow2 overlay of the installed disk (phase1.qcow2 in the
#  work dir): --phase2-only repeats the first boot on a fresh overlay without
#  reinstalling (same ISO payload: rebuild + full run after payload changes).
#
#  Networking is QEMU user-mode only: NIC 1 = "WAN" (QEMU NAT to the
#  internet), NIC 2 = "LAN" (a unix datagram socket with no peer: isolated).
#  Nothing on the host's network changes; no bridges, no taps.
#
#  Needs: qemu-system-x86_64, qemu-img, OVMF (UEFI) / SeaBIOS (BIOS),
#  mkfs.vfat + mcopy (dosfstools, mtools), read/write access to /dev/kvm.
#  Overrides: QEMU, QEMU_IMG, QEMU_DATADIRS (colon list for -L), OVMF_CODE,
#  OVMF_VARS, SEABIOS.
###############################################################################
set -Eeuo pipefail

ISO="" UISO="" MODE=uefi WORK="" MEM=4096 TIMEOUT1=5400 TIMEOUT2=5400 PHASE2_ONLY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --iso) ISO=$(readlink -f "$2"); shift 2 ;;
        --ubuntu-iso) UISO=$(readlink -f "$2"); shift 2 ;;
        --mode) MODE=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        --mem) MEM=$2; shift 2 ;;
        --phase2-only) PHASE2_ONLY=1; shift ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^#  \{0,1\}//'; exit 0 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
[[ -f $ISO && -f $UISO ]] || { echo "--iso and --ubuntu-iso are required" >&2; exit 2; }
[[ $ISO == *-TEST.iso ]] || { echo "refusing: --iso must be a *-TEST.iso (build.sh --test)" >&2; exit 2; }
[[ $MODE == uefi || $MODE == bios ]] || { echo "--mode uefi|bios" >&2; exit 2; }
(( MEM <= 4096 )) || { echo "--mem is capped at 4096 MB" >&2; exit 2; }
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo "no access to /dev/kvm (run as a member of group kvm)" >&2; exit 2; }

QEMU=${QEMU:-qemu-system-x86_64}
QEMU_IMG=${QEMU_IMG:-qemu-img}
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.ms.fd}
SEABIOS=${SEABIOS:-/usr/share/seabios/bios-256k.bin}
WORK=${WORK:-$(dirname "$ISO")/qemu-test-$MODE}
mkdir -p "$WORK"
WORK=$(readlink -f "$WORK")
LOGP1="$WORK/phase1-install.serial.log" LOGP2="$WORK/phase2-firstboot.serial.log"
echo "work dir: $WORK"

# The Ubuntu ISO as a file on a FAT32 disk (what a user copies to a stick).
UDISK="$WORK/ubuntu-iso-disk.img"
if [[ ! -s $UDISK ]]; then
    size_kb=$(( $(stat -c %s "$UISO") / 1024 + 262144 ))
    mkfs.vfat -C -F 32 -n UBUNTUISO "$UDISK" "$size_kb" >/dev/null
    mcopy -i "$UDISK" "$UISO" "::/$(basename "$UISO")"
fi
BASE="$WORK/phase1.qcow2" VARS1="$WORK/vars-phase1.fd"
if (( PHASE2_ONLY )); then
    [[ -s $BASE && ( $MODE == bios || -s $VARS1 ) ]] || { echo "--phase2-only: no phase-1 disk in $WORK" >&2; exit 2; }
else
    rm -f "$WORK/disk.qcow2" "$WORK/vars.fd" "$BASE" "$VARS1"
    "$QEMU_IMG" create -f qcow2 "$WORK/disk.qcow2" 20G >/dev/null
fi

datadirs=()
IFS=: read -r -a _dd <<<"${QEMU_DATADIRS:-}"
for d in "${_dd[@]}"; do [[ -n $d ]] && datadirs+=(-L "$d"); done
fw=()
if [[ $MODE == uefi ]]; then
    (( PHASE2_ONLY )) || cp "$OVMF_VARS" "$WORK/vars.fd"
    fw=(-machine "q35,smm=on,accel=kvm" -global "driver=cfi.pflash01,property=secure,value=on"
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE"
        -drive "if=pflash,format=raw,unit=1,file=$WORK/vars.fd")
else
    fw=(-machine "pc,accel=kvm" -bios "$SEABIOS")
fi

run_vm() {   # run_vm LOG TIMEOUT extra-args...
    local log=$1 tmo=$2; shift 2
    rm -f "$log" "$WORK/qemu.pid" "$WORK/lan.sock" "$WORK/lan-nopeer.sock"
    nice -n 10 "$QEMU" "${datadirs[@]}" "${fw[@]}" -cpu host -smp 2 -m "$MEM" -display none -no-reboot \
        -drive "file=$WORK/disk.qcow2,if=virtio,format=qcow2" \
        -netdev user,id=wan -device virtio-net-pci,netdev=wan,mac=52:54:00:12:34:01 \
        -netdev "dgram,id=lan,local.type=unix,local.path=$WORK/lan.sock,remote.type=unix,remote.path=$WORK/lan-nopeer.sock" -device virtio-net-pci,netdev=lan,mac=52:54:00:12:34:02 \
        -serial "file:$log" -pidfile "$WORK/qemu.pid" "$@" &
    local qpid=$! t=0
    while kill -0 "$qpid" 2>/dev/null; do
        if (( t >= tmo )); then
            echo "timeout after ${tmo}s; stopping the VM (pid $qpid)"
            kill "$qpid" 2>/dev/null || true
            wait "$qpid" 2>/dev/null || true
            return 1
        fi
        sleep 10; t=$((t + 10))
    done
    local rc=0
    wait "$qpid" || rc=$?
    echo "VM stopped after ${t}s (qemu exit $rc)"
    return "$rc"
}

if (( ! PHASE2_ONLY )); then
    echo "== phase 1: unattended install ($MODE, ${MEM} MB)"
    run_vm "$LOGP1" "$TIMEOUT1" \
        -drive "file=$ISO,media=cdrom,readonly=on,if=none,id=cd0" -device ide-cd,drive=cd0,bootindex=0 \
        -drive "file=$UDISK,format=raw,if=virtio,readonly=on" || { echo "FAIL: phase 1 did not finish"; exit 1; }
    for stage in early late; do
        if ! grep -a -q "TUXWALL-TEST: $stage-commands ok" "$LOGP1"; then
            echo "FAIL: $stage-commands did not report"; exit 1
        fi
        echo "$stage-commands ok"
    done
    mv "$WORK/disk.qcow2" "$BASE"
    [[ $MODE == bios ]] || cp "$WORK/vars.fd" "$VARS1"
fi
# phase 2 on a throw-away overlay: the installed disk stays reusable
rm -f "$WORK/disk.qcow2"
"$QEMU_IMG" create -f qcow2 -b "$BASE" -F qcow2 "$WORK/disk.qcow2" >/dev/null
[[ $MODE == bios ]] || cp "$VARS1" "$WORK/vars.fd"

echo "== phase 2: first boot, tuxwall-setup (answers file) + report"
run_vm "$LOGP2" "$TIMEOUT2" || { echo "FAIL: phase 2 did not finish"; exit 1; }
report="$(tr -d '\r' <"$LOGP2" | sed -n '/TUXWALL-TEST-REPORT-BEGIN/,/TUXWALL-TEST-REPORT-END/p')"
[[ -n $report ]] || { echo "FAIL: no report on the serial console"; exit 1; }
printf '%s\n' "$report" | grep -a 'TUXWALL-TEST-CHECK\|TUXWALL-TEST-INFO'
fails=$(printf '%s\n' "$report" | grep -ac 'TUXWALL-TEST-CHECK .* FAIL' || true)
passes=$(printf '%s\n' "$report" | grep -ac 'TUXWALL-TEST-CHECK .* PASS' || true)
echo "checks: $passes passed, $fails failed"
(( fails == 0 && passes > 0 ))
