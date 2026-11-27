#!/usr/bin/env bash
###############################################################################
#  image/netinstall/build.sh - build the TuxWall netinstall ISO
#  ---------------------------------------------------------------------------
#  A ~140 MB BIOS + UEFI (Secure Boot) ISO made of Ubuntu's own, verified boot
#  chain - signed shim, signed GRUB, signed kernel and the casper initrd of
#  the pinned live-server ISO (image/netinstall/ubuntu-release.env) - plus an
#  autoinstall seed (volume label CIDATA) and the TuxWall first-boot payload.
#  At install time casper downloads that same live-server ISO over HTTPS
#  (iso-url=) or finds it on another disk (iso-scan/filename=); the
#  autoinstall early-commands check its SHA-256 before anything is installed.
#
#    image/netinstall/build.sh                 -> out/tuxwall-netinstall-<ver>-amd64.iso + .sha256
#    image/netinstall/build.sh --out DIR --cache DIR
#    image/netinstall/build.sh --test          QEMU test variant (unattended,
#                                              *-TEST.iso, never publish it)
#
#  Unprivileged: needs curl, gpg, gpgv, xorriso, sha256sum, python3 and the
#  Ubuntu archive keyring (ubuntu-keyring). Every download is verified: the
#  SHA256SUMS signature (pinned cdimage key fingerprint) and the pinned ISO
#  SHA-256; the TuxWall APT key's fingerprint is checked too.
###############################################################################
set -Eeuo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/tuxwall-netinstall"
KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg
TEST=0
WAN_MAC="" LAN_MAC=""
MAX_BYTES=$((2 * 1024 * 1024 * 1024 - 1))
TARGET_BYTES=$((300 * 1024 * 1024))

die()  { printf 'build.sh: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

usage() { sed -n '2,24p' "$0" | sed 's/^#  \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)     OUT="${2:?}"; shift 2 ;;
        --cache)   CACHE="${2:?}"; shift 2 ;;
        --keyring) KEYRING="${2:?}"; shift 2 ;;
        --wan-mac) WAN_MAC="${2:?}"; shift 2 ;;
        --lan-mac) LAN_MAC="${2:?}"; shift 2 ;;
        --test)    TEST=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

# ── Pins (KEY=VALUE, whitelisted, never sourced) ────────────────────────────
declare -A PIN=()
while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    [[ $line =~ ^([A-Z0-9_]+)=([A-Za-z0-9._:/+-]+)$ ]] || die "ubuntu-release.env: bad line: $line"
    PIN[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
done <"$HERE/ubuntu-release.env"
for k in UBUNTU_VERSION UBUNTU_ISO UBUNTU_BASE_URL UBUNTU_OLD_BASE_URL UBUNTU_ISO_SHA256 UBUNTU_ISO_SIZE \
         UBUNTU_CASPER_UUID UBUNTU_CDIMAGE_KEY_FPR TUXWALL_APT_KEY_FPR; do
    [[ -n ${PIN[$k]:-} ]] || die "ubuntu-release.env: $k missing"
done
[[ ${PIN[UBUNTU_BASE_URL]} == https://* && ${PIN[UBUNTU_OLD_BASE_URL]} == https://* ]] || die "Ubuntu URLs must be https"

VERSION="$(sed -n 's/^Version: //p' "$REPO/pkg/DEBIAN/control" | head -n1)"
[[ -n $VERSION ]] || die "no Version in pkg/DEBIAN/control"
NAME="tuxwall-netinstall-$VERSION-amd64"
(( TEST )) && NAME+="-TEST"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || date +%s)}"

for t in curl gpg gpgv xorriso sha256sum python3; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
[[ -r $KEYRING ]] || die "Ubuntu archive keyring not found: $KEYRING (package ubuntu-keyring)"

mkdir -p "$OUT" "$CACHE"
LOGFILE="$OUT/$NAME.build.log"
exec > >(tee "$LOGFILE") 2>&1
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tuxwall-netinstall.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
printf 'TuxWall netinstall build: %s (Ubuntu %s, SOURCE_DATE_EPOCH=%s%s)\n' \
    "$NAME" "${PIN[UBUNTU_VERSION]}" "$SOURCE_DATE_EPOCH" "$( (( TEST )) && echo ', TEST variant')"

# ── 1. Ubuntu's signed checksum list ────────────────────────────────────────
step "Ubuntu SHA256SUMS (signature by ${PIN[UBUNTU_CDIMAGE_KEY_FPR]})"
CDIR="$CACHE/ubuntu-${PIN[UBUNTU_VERSION]}"
mkdir -p "$CDIR"
fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"; }
fetch "${PIN[UBUNTU_BASE_URL]}/SHA256SUMS" "$WORK/SHA256SUMS" \
    || fetch "${PIN[UBUNTU_OLD_BASE_URL]}/SHA256SUMS" "$WORK/SHA256SUMS" || die "cannot download SHA256SUMS"
fetch "${PIN[UBUNTU_BASE_URL]}/SHA256SUMS.gpg" "$WORK/SHA256SUMS.gpg" \
    || fetch "${PIN[UBUNTU_OLD_BASE_URL]}/SHA256SUMS.gpg" "$WORK/SHA256SUMS.gpg" || die "cannot download SHA256SUMS.gpg"
status="$(gpgv --status-fd 1 --keyring "$KEYRING" "$WORK/SHA256SUMS.gpg" "$WORK/SHA256SUMS" 2>/dev/null || true)"
grep -Eq "^\[GNUPG:\] VALIDSIG ([0-9A-F]+ ){9}${PIN[UBUNTU_CDIMAGE_KEY_FPR]}$|^\[GNUPG:\] VALIDSIG ${PIN[UBUNTU_CDIMAGE_KEY_FPR]} " <<<"$status" \
    || die "SHA256SUMS: no valid signature by ${PIN[UBUNTU_CDIMAGE_KEY_FPR]}"
listed="$(awk -v f="*${PIN[UBUNTU_ISO]}" '$2 == f || $2 == substr(f, 2) {print $1}' "$WORK/SHA256SUMS")"
[[ $listed == "${PIN[UBUNTU_ISO_SHA256]}" ]] || die "SHA256SUMS lists ${listed:-nothing} for ${PIN[UBUNTU_ISO]}, pinned ${PIN[UBUNTU_ISO_SHA256]}"
echo "signature good, ${PIN[UBUNTU_ISO]} = ${PIN[UBUNTU_ISO_SHA256]}"

# ── 2. The live-server ISO (cached; always re-hashed) ──────────────────────
step "Ubuntu ISO ${PIN[UBUNTU_ISO]}"
UISO="$CDIR/${PIN[UBUNTU_ISO]}"
iso_ok() { [[ -f $UISO && $(stat -c %s "$UISO") == "${PIN[UBUNTU_ISO_SIZE]}" ]] && [[ "$(sha256sum "$UISO" | cut -d' ' -f1)" == "${PIN[UBUNTU_ISO_SHA256]}" ]]; }
if ! iso_ok; then
    rm -f "$UISO"
    fetch "${PIN[UBUNTU_BASE_URL]}/${PIN[UBUNTU_ISO]}" "$UISO.part" \
        || fetch "${PIN[UBUNTU_OLD_BASE_URL]}/${PIN[UBUNTU_ISO]}" "$UISO.part" || die "ISO download failed"
    mv "$UISO.part" "$UISO"
    iso_ok || { rm -f "$UISO"; die "downloaded ISO does not match the pinned size/SHA-256"; }
fi
echo "verified: $UISO"
xorriso -osirrox on -indev "$UISO" -extract /.disk/casper-uuid-generic "$WORK/casper-uuid" >/dev/null 2>&1 \
    || die "ISO has no /.disk/casper-uuid-generic"
[[ "$(tr -d '\n' <"$WORK/casper-uuid")" == "${PIN[UBUNTU_CASPER_UUID]}" ]] || die "casper UUID differs from the pin"

# ── 3. TuxWall APT key ──────────────────────────────────────────────────────
step "TuxWall APT key"
export GNUPGHOME="$WORK/gnupg"; mkdir -m 700 "$GNUPGHOME"
fpr="$(gpg --batch --show-keys --with-colons "$REPO/apt-public.asc" 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"
[[ $fpr == "${PIN[TUXWALL_APT_KEY_FPR]}" ]] || die "apt-public.asc fingerprint ${fpr:-none} != ${PIN[TUXWALL_APT_KEY_FPR]}"
echo "apt-public.asc = $fpr"

# ── 4. Payload + seed ───────────────────────────────────────────────────────
step "Payload and autoinstall seed"
OV="$WORK/overlay"
P="$OV/tuxwall"
mkdir -p "$P" "$OV/boot/grub"
install -m 0755 "$REPO/pkg/usr/local/sbin/tuxwall-setup" "$P/tuxwall-setup"
install -m 0644 "$REPO/pkg/etc/systemd/system/tuxwall-setup@.service" "$P/tuxwall-setup@.service"
install -m 0755 "$REPO/tuxwall-install.sh" "$P/tuxwall-install.sh"
install -m 0644 "$REPO/apt-public.asc" "$P/apt-public.asc"
gpg --batch --yes --dearmor -o "$P/tuxwall-archive-keyring.gpg" "$REPO/apt-public.asc"
install -m 0755 "$REPO/image/common/install-firstboot.sh" "$P/install-firstboot.sh"
install -m 0755 "$HERE/verify-ubuntu-iso.sh" "$P/verify-ubuntu-iso.sh"
if (( TEST )); then
    MAC_RE='^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$'
    [[ $WAN_MAC =~ $MAC_RE && $LAN_MAC =~ $MAC_RE ]] || die "--test needs --wan-mac/--lan-mac (the lab VM's unique MACs, e.g. BC:24:11:00:68:01)"
    install -m 0600 "$HERE/test/setup-answers.test" "$P/setup-answers.test"
    sed -i "s/@WAN_MAC@/$WAN_MAC/g; s/@LAN_MAC@/$LAN_MAC/g" "$P/setup-answers.test"
    grep -q '@[A-Z0-9_]*@' "$P/setup-answers.test" && die "unrendered placeholder in setup-answers.test" || true
    install -m 0755 "$HERE/test/test-report.sh" "$P/test-report.sh"
    install -m 0755 "$HERE/test/lan-gate.sh" "$P/lan-gate.sh"
    install -m 0644 "$HERE/test/lan-gate.service" "$P/lan-gate.service"
fi
printf 'TuxWall %s netinstall payload (Ubuntu %s)\n' "$VERSION" "${PIN[UBUNTU_VERSION]}" >"$P/VERSION"
(cd "$P" && find . -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort | xargs sha256sum >"$WORK/payload.sums" && mv "$WORK/payload.sums" SHA256SUMS)
PAYLOAD_SHA256="$(sha256sum "$P/SHA256SUMS" | cut -d' ' -f1)"

render() {   # render TEMPLATE OUT
    python3 - "$1" "$2" <<PY
import sys
s = open(sys.argv[1]).read()
for k, v in {
    "@TUXWALL_VERSION@": "$VERSION",
    "@UBUNTU_VERSION@": "${PIN[UBUNTU_VERSION]}",
    "@UBUNTU_ISO@": "${PIN[UBUNTU_ISO]}",
    "@UBUNTU_ISO_SHA256@": "${PIN[UBUNTU_ISO_SHA256]}",
    "@UBUNTU_ISO_SIZE@": "${PIN[UBUNTU_ISO_SIZE]}",
    "@ISO_URL@": "${PIN[UBUNTU_BASE_URL]}/${PIN[UBUNTU_ISO]}",
    "@ISO_URL_OLD@": "${PIN[UBUNTU_OLD_BASE_URL]}/${PIN[UBUNTU_ISO]}",
    "@PAYLOAD_SHA256@": "$PAYLOAD_SHA256",
    "@TUXWALL_APT_KEY_FPR@": "${PIN[TUXWALL_APT_KEY_FPR]}",
}.items():
    s = s.replace(k, v)
import re
left = sorted(set(re.findall(r"@[A-Z0-9_]+@", s)))
if left:
    sys.exit("unrendered placeholders: %s" % left)
open(sys.argv[2], "w").write(s)
PY
}
if (( TEST )); then
    render "$HERE/test/user-data-test.in" "$OV/user-data"
    render "$HERE/test/grub-test.cfg.in" "$OV/boot/grub/grub.cfg"
else
    render "$HERE/user-data.in" "$OV/user-data"
    render "$HERE/grub.cfg.in" "$OV/boot/grub/grub.cfg"
fi
python3 - "$OV/user-data" <<'PY' || die "user-data is not valid YAML with an autoinstall section"
import sys
try:
    import yaml
except ImportError:
    print("(PyYAML missing: YAML syntax not checked)"); sys.exit(0)
d = yaml.safe_load(open(sys.argv[1]))
assert isinstance(d, dict) and d["autoinstall"]["version"] == 1
PY
printf 'instance-id: tuxwall-netinstall-%s\n' "$VERSION" >"$OV/meta-data"
cat >"$OV/README.txt" <<EOF
TuxWall $VERSION netinstall for Ubuntu ${PIN[UBUNTU_VERSION]} LTS (amd64, BIOS + UEFI/Secure Boot).

Boot this stick, pick the disk and your account in Ubuntu's installer; after
the reboot the TuxWall setup asks for the WAN/LAN ports on the console.
The installer downloads ${PIN[UBUNTU_ISO]} (SHA-256 ${PIN[UBUNTU_ISO_SHA256]})
from ${PIN[UBUNTU_BASE_URL]}/ into RAM (6 GB+ RAM), or uses that ISO written
to a second USB stick / that file on another disk ("low RAM" menu entries).
https://github.com/rezzonance/tuxwall
EOF
find "$OV" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(cd "$OV" && find . -type f | LC_ALL=C sort | sed 's/^/  /')

# ── 5. ISO: Ubuntu's boot setup replayed, live system + package pool dropped
step "ISO"
ISO="$OUT/$NAME.iso"
rm -f "$ISO" "$ISO.sha256"
xorriso -report_about WARNING \
    -indev "$UISO" -outdev "$ISO" \
    -boot_image any replay \
    -volid CIDATA \
    -volume_date all_file_dates set_to_mtime \
    -find /casper -type f -not -name vmlinuz -not -name initrd -exec rm -- \
    -rm_r /pool /dists /md5sum.txt /boot/grub/loopback.cfg /ubuntu -- \
    -map "$OV/boot/grub/grub.cfg" /boot/grub/grub.cfg \
    -map "$OV/user-data" /user-data \
    -map "$OV/meta-data" /meta-data \
    -map "$OV/README.txt" /README.txt \
    -map "$OV/tuxwall" /tuxwall \
    -commit
bytes="$(stat -c %s "$ISO")"
(( bytes < MAX_BYTES )) || die "ISO is $bytes bytes: over the 2 GiB release-asset limit"
(( bytes <= TARGET_BYTES )) || echo "WARNING: ISO is $((bytes / 1048576)) MiB, over the 300 MiB target"

# ── 6. Self-check of the result ─────────────────────────────────────────────
step "Check"
listing="$(xorriso -indev "$ISO" -find / -type f 2>/dev/null)"
for f in /casper/vmlinuz /casper/initrd /EFI/boot/bootx64.efi /EFI/boot/grubx64.efi /boot/grub/i386-pc/eltorito.img \
         /boot/grub/grub.cfg /user-data /meta-data /.disk/info /tuxwall/SHA256SUMS /tuxwall/tuxwall-setup; do
    grep -q "'$f'" <<<"$listing" || die "missing in the ISO: $f"
done
grep -q "squashfs'" <<<"$listing" && die "a squashfs is still in the ISO"
xorriso -indev "$ISO" -report_el_torito plain 2>/dev/null | grep -E 'El Torito boot img|Volume id' || true
(cd "$OUT" && sha256sum "$NAME.iso" >"$NAME.iso.sha256")
printf '\nBuilt %s (%s MiB)\n%s\n' "$ISO" "$((bytes / 1048576))" "$(cat "$ISO.sha256")"
