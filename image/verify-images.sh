#!/usr/bin/env bash
# image/verify-images.sh DIR VERSION - check the built install images before
# they are published (.github/workflows/apt.yml, job "images"):
#   tuxwall-netinstall-VERSION-amd64.iso    SHA-256 file, ISO 9660 volume
#       CIDATA, El Torito boot images for BIOS and UEFI, Ubuntu's signed
#       shim + GRUB + kernel, the seed and the TuxWall payload
#   tuxwall-vm-VERSION-amd64.qcow2          SHA-256 file, qemu-img check,
#       qcow2 format
#   every file under GitHub's 2 GiB release-asset limit; no TEST variant.
set -euo pipefail
dir=${1:?usage: verify-images.sh DIR VERSION}
ver=${2:?usage: verify-images.sh DIR VERSION}
QEMU_IMG="${QEMU_IMG:-qemu-img}"
MAX_BYTES=$((2 * 1024 * 1024 * 1024 - 1))
fail() { echo "::error::$*" >&2; exit 1; }

iso="tuxwall-netinstall-$ver-amd64.iso"
vm="tuxwall-vm-$ver-amd64.qcow2"
cd "$dir"
ls ./*-TEST* >/dev/null 2>&1 && fail "a TEST image is in $dir - never publish it"
for f in "$iso" "$vm"; do
    [[ -f $f && -f $f.sha256 ]] || fail "$f or $f.sha256 missing"
    sha256sum -c --quiet "$f.sha256" || fail "$f does not match $f.sha256"
    bytes="$(stat -L -c %s "$f")"
    (( bytes <= MAX_BYTES )) || fail "$f is $bytes bytes: over GitHub's 2 GiB asset limit"
    printf '%-40s %5d MiB  sha256 %s\n' "$f" "$((bytes / 1048576))" "$(cut -d' ' -f1 "$f.sha256")"
done

rep="$(xorriso -indev "$iso" -report_el_torito plain 2>/dev/null)"
xorriso -indev "$iso" -pvd_info 2>/dev/null | grep -Eq '^Volume Id +: CIDATA$' || fail "$iso: volume id is not CIDATA"
grep -Eq '^El Torito boot img : +1 +BIOS ' <<<"$rep" || fail "$iso: no BIOS El Torito boot image"
grep -Eq '^El Torito boot img : +[0-9]+ +UEFI ' <<<"$rep" || fail "$iso: no UEFI El Torito boot image"
files="$(xorriso -indev "$iso" -find / -type f 2>/dev/null)"
for f in /EFI/boot/bootx64.efi /EFI/boot/grubx64.efi /casper/vmlinuz /casper/initrd /boot/grub/grub.cfg \
         /user-data /meta-data /tuxwall/SHA256SUMS /tuxwall/tuxwall-setup /tuxwall/install-firstboot.sh; do
    grep -q "'$f'" <<<"$files" || fail "$iso: $f missing"
done
grep -q "squashfs'" <<<"$files" && fail "$iso: a squashfs is in the ISO"
grep -q "setup-answers" <<<"$files" && fail "$iso: test answers in the ISO"
echo "$iso: BIOS + UEFI El Torito, volume CIDATA, payload present"

"$QEMU_IMG" check -q "$vm" || fail "$vm: qemu-img check failed"
"$QEMU_IMG" info --output=json "$vm" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["format"] == "qcow2", d["format"]
print("%s: qcow2, virtual size %d GiB" % (sys.argv[1], d["virtual-size"] >> 30))' "$vm" || fail "$vm is not a qcow2"
