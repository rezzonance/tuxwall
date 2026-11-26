#!/usr/bin/env bash
###############################################################################
#  image/vm/build.sh - build the TuxWall VM image (qcow2)
#  ---------------------------------------------------------------------------
#  The official Ubuntu 26.04 LTS cloud image (signature-verified, unchanged)
#  plus the TuxWall first-boot payload: tuxwall-setup, tuxwall-install.sh, the
#  signed TuxWall APT source and the first-boot units (tty1 + ttyS0), the
#  same files the netinstall ISO puts on a fresh install
#  (image/common/install-firstboot.sh). TuxWall itself is installed by the
#  wizard at first boot from the APT repository - always the current release,
#  and the image stays the size of Ubuntu's.
#
#    image/vm/build.sh                    -> out/tuxwall-vm-<ver>-amd64.qcow2 + .sha256
#    image/vm/build.sh --out DIR --cache DIR
#    image/vm/build.sh --latest           newest Ubuntu cloud image release
#                                         instead of the pinned serial
#
#  Unprivileged and no VM: needs curl, gpg, gpgv, qemu-img (qemu-utils),
#  debugfs + e2fsck (e2fsprogs), sfdisk, python3 and the Ubuntu cloud image
#  keyring (ubuntu-cloudimage-keyring). The files are written into the
#  image's ext4 root with debugfs and read back; e2fsck and qemu-img check +
#  compare the result.
###############################################################################
set -Eeuo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/tuxwall-vm"
KEYRING=/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
QEMU_IMG="${QEMU_IMG:-qemu-img}"
LATEST=0
MAX_BYTES=$((2 * 1024 * 1024 * 1024 - 1))

die()  { printf 'build.sh: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

usage() { sed -n '2,23p' "$0" | sed 's/^#  \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)      OUT="${2:?}"; shift 2 ;;
        --cache)    CACHE="${2:?}"; shift 2 ;;
        --keyring)  KEYRING="${2:?}"; shift 2 ;;
        --qemu-img) QEMU_IMG="${2:?}"; shift 2 ;;
        --latest)   LATEST=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

# ── Pins (KEY=VALUE, whitelisted, never sourced) ────────────────────────────
declare -A PIN=()
while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    [[ $line =~ ^([A-Z0-9_]+)=([A-Za-z0-9._:/+-]+)$ ]] || die "ubuntu-cloud.env: bad line: $line"
    PIN[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
done <"$HERE/ubuntu-cloud.env"
for k in UBUNTU_CLOUD_VERSION UBUNTU_CLOUD_BASE_URL UBUNTU_CLOUD_SERIAL UBUNTU_CLOUD_IMAGE UBUNTU_CLOUD_SHA256 \
         UBUNTU_CLOUD_KEY_FPR TUXWALL_APT_KEY_FPR VM_DISK_SIZE; do
    [[ -n ${PIN[$k]:-} ]] || die "ubuntu-cloud.env: $k missing"
done
[[ ${PIN[UBUNTU_CLOUD_BASE_URL]} == https://* ]] || die "Ubuntu URL must be https"
[[ ${PIN[VM_DISK_SIZE]} =~ ^[0-9]+G$ ]] || die "VM_DISK_SIZE must look like 16G"

VERSION="$(sed -n 's/^Version: //p' "$REPO/pkg/DEBIAN/control" | head -n1)"
[[ -n $VERSION ]] || die "no Version in pkg/DEBIAN/control"
NAME="tuxwall-vm-$VERSION-amd64"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || date +%s)}"

for t in curl gpg gpgv debugfs e2fsck sfdisk sha256sum python3 truncate; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
command -v "$QEMU_IMG" >/dev/null 2>&1 || die "missing tool: qemu-img (package qemu-utils, or --qemu-img PATH)"
[[ -r $KEYRING ]] || die "Ubuntu cloud image keyring not found: $KEYRING (package ubuntu-cloudimage-keyring)"

mkdir -p "$OUT" "$CACHE"
LOGFILE="$OUT/$NAME.build.log"
exec > >(tee "$LOGFILE") 2>&1
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tuxwall-vm.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"; }

# ── 1. Which Ubuntu cloud image ─────────────────────────────────────────────
SERIAL=${PIN[UBUNTU_CLOUD_SERIAL]}
if (( LATEST )); then
    step "Newest Ubuntu ${PIN[UBUNTU_CLOUD_VERSION]} cloud image release"
    fetch "${PIN[UBUNTU_CLOUD_BASE_URL]}/" "$WORK/index.html" || die "cannot list ${PIN[UBUNTU_CLOUD_BASE_URL]}/"
    SERIAL="$(grep -o 'href="release-[0-9]\{8\}\(\.[0-9]\+\)\?/"' "$WORK/index.html" | sed 's/^href="release-//; s/\/"$//' \
              | sort -V | tail -n1)"
    [[ -n $SERIAL ]] || die "no release-YYYYMMDD directory in ${PIN[UBUNTU_CLOUD_BASE_URL]}/"
fi
BASE="${PIN[UBUNTU_CLOUD_BASE_URL]}/release-$SERIAL"
printf 'TuxWall VM image build: %s (Ubuntu %s cloud image, serial %s%s, SOURCE_DATE_EPOCH=%s)\n' \
    "$NAME" "${PIN[UBUNTU_CLOUD_VERSION]}" "$SERIAL" "$( (( LATEST )) && echo ', --latest')" "$SOURCE_DATE_EPOCH"

# ── 2. Ubuntu's signed checksum list ────────────────────────────────────────
step "Ubuntu SHA256SUMS (signature by ${PIN[UBUNTU_CLOUD_KEY_FPR]})"
fetch "$BASE/SHA256SUMS" "$WORK/SHA256SUMS" || die "cannot download $BASE/SHA256SUMS (pinned release gone? try --latest)"
fetch "$BASE/SHA256SUMS.gpg" "$WORK/SHA256SUMS.gpg" || die "cannot download $BASE/SHA256SUMS.gpg"
status="$(gpgv --status-fd 1 --keyring "$KEYRING" "$WORK/SHA256SUMS.gpg" "$WORK/SHA256SUMS" 2>/dev/null || true)"
grep -Eq "^\[GNUPG:\] VALIDSIG ([0-9A-F]+ ){9}${PIN[UBUNTU_CLOUD_KEY_FPR]}$|^\[GNUPG:\] VALIDSIG ${PIN[UBUNTU_CLOUD_KEY_FPR]} " <<<"$status" \
    || die "SHA256SUMS: no valid signature by ${PIN[UBUNTU_CLOUD_KEY_FPR]}"
IMG_SHA="$(awk -v f="*${PIN[UBUNTU_CLOUD_IMAGE]}" '$2 == f || $2 == substr(f, 2) {print $1}' "$WORK/SHA256SUMS")"
[[ $IMG_SHA =~ ^[0-9a-f]{64}$ ]] || die "SHA256SUMS does not list ${PIN[UBUNTU_CLOUD_IMAGE]}"
if (( ! LATEST )) && [[ $IMG_SHA != "${PIN[UBUNTU_CLOUD_SHA256]}" ]]; then
    die "SHA256SUMS lists $IMG_SHA for ${PIN[UBUNTU_CLOUD_IMAGE]}, pinned ${PIN[UBUNTU_CLOUD_SHA256]}"
fi
echo "signature good, ${PIN[UBUNTU_CLOUD_IMAGE]} = $IMG_SHA"

# ── 3. The cloud image (cached; always re-hashed) ──────────────────────────
step "Ubuntu cloud image"
CDIR="$CACHE/cloud-${PIN[UBUNTU_CLOUD_VERSION]}-$SERIAL"
mkdir -p "$CDIR"
SRC="$CDIR/${PIN[UBUNTU_CLOUD_IMAGE]}"
img_ok() { [[ -f $SRC ]] && [[ "$(sha256sum "$SRC" | cut -d' ' -f1)" == "$IMG_SHA" ]]; }
if ! img_ok; then
    rm -f "$SRC"
    fetch "$BASE/${PIN[UBUNTU_CLOUD_IMAGE]}" "$SRC.part" || die "image download failed"
    mv "$SRC.part" "$SRC"
    img_ok || { rm -f "$SRC"; die "downloaded image does not match the signed SHA-256"; }
fi
echo "verified: $SRC"
"$QEMU_IMG" info --output=json "$SRC" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["format"] == "qcow2", d["format"]' \
    || die "the cloud image is not a qcow2"

# ── 4. TuxWall APT key ──────────────────────────────────────────────────────
step "TuxWall APT key"
export GNUPGHOME="$WORK/gnupg"; mkdir -m 700 "$GNUPGHOME"
fpr="$(gpg --batch --show-keys --with-colons "$REPO/apt-public.asc" 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"
[[ $fpr == "${PIN[TUXWALL_APT_KEY_FPR]}" ]] || die "apt-public.asc fingerprint ${fpr:-none} != ${PIN[TUXWALL_APT_KEY_FPR]}"
echo "apt-public.asc = $fpr"

# ── 5. Files to add (a staging root, made by the shared first-boot script) ──
step "First-boot payload"
P="$WORK/payload"
STAGE="$WORK/stage"
mkdir -p "$P" "$STAGE/etc"
install -m 0755 "$REPO/pkg/usr/local/sbin/tuxwall-setup" "$P/tuxwall-setup"
install -m 0644 "$REPO/pkg/etc/systemd/system/tuxwall-setup@.service" "$P/tuxwall-setup@.service"
install -m 0755 "$REPO/tuxwall-install.sh" "$P/tuxwall-install.sh"
install -m 0644 "$REPO/apt-public.asc" "$P/apt-public.asc"
gpg --batch --yes --dearmor -o "$P/tuxwall-archive-keyring.gpg" "$REPO/apt-public.asc"
# The cloud image boots with console=tty1 console=ttyS0: the wizard waits on both.
sh "$REPO/image/common/install-firstboot.sh" --payload "$P" --origin vm-image --console ttyS0 "$STAGE"
printf 'tuxwall_version=%s\nubuntu=%s\nubuntu_cloud_image=%s\nubuntu_cloud_serial=%s\nubuntu_cloud_sha256=%s\n' \
    "$VERSION" "${PIN[UBUNTU_CLOUD_VERSION]}" "${PIN[UBUNTU_CLOUD_IMAGE]}" "$SERIAL" "$IMG_SHA" >"$STAGE/etc/tuxwall/vm-image"
rmdir "$STAGE/etc/systemd/system/tuxwall-setup@.service.d" 2>/dev/null || true
[[ ! -e $STAGE/etc/tuxwall/setup-answers ]] || die "answers file in the image payload"
(cd "$STAGE" && find . -mindepth 1 | LC_ALL=C sort | sed 's/^\./  /')

# ── 6. Raw copy of the image, grown to VM_DISK_SIZE ────────────────────────
step "Disk (${PIN[VM_DISK_SIZE]})"
RAW="$WORK/disk.raw"
"$QEMU_IMG" convert -f qcow2 -O raw "$SRC" "$RAW"
truncate -s "${PIN[VM_DISK_SIZE]}" "$RAW"
sfdisk --relocate gpt-bak-std "$RAW" >/dev/null 2>&1 || die "cannot move the backup GPT to the end of the disk"
read -r ROOT_START SECTOR < <(sfdisk -J "$RAW" | python3 -c '
import json, sys
t = json.load(sys.stdin)["partitiontable"]
r = [p for p in t["partitions"] if p.get("name") == "cloudimg-rootfs"]
assert len(r) == 1, "no single cloudimg-rootfs partition"
print(r[0]["start"], t.get("sectorsize", 512))') || die "root partition not found"
FS="$RAW?offset=$((ROOT_START * SECTOR))"
label="$(debugfs -R stats "$FS" 2>/dev/null | sed -n 's/^Filesystem volume name: *//p')"
[[ $label == cloudimg-rootfs ]] || die "root file system label is '${label:-?}', expected cloudimg-rootfs"
echo "root file system: partition at sector $ROOT_START, label $label"

# ── 7. Write the staging tree into the ext4 root (debugfs), read it back ────
step "Install the payload into the root file system"
python3 - "$STAGE" "$FS" "$WORK" <<'PY'
import hashlib, os, re, stat, subprocess, sys
stage, fs, work = sys.argv[1:]

def debugfs(cmds, write=False):
    path = os.path.join(work, "debugfs.cmds")
    with open(path, "w") as f:
        f.write("\n".join(cmds) + "\n")
    args = ["debugfs"] + (["-w"] if write else []) + ["-f", path, fs]
    return subprocess.run(args, capture_output=True, text=True)

def dstat(path):   # -> stat text, or None when the path does not exist
    r = subprocess.run(["debugfs", "-R", "stat " + path, fs], capture_output=True, text=True)
    return None if "File not found" in r.stderr or "Inode:" not in r.stdout else r.stdout

items = []
for dp, dns, fns in os.walk(stage):
    dns.sort()
    for n in sorted(dns) + sorted(fns):
        p = os.path.join(dp, n)
        items.append(("/" + os.path.relpath(p, stage), p))
items.sort(key=lambda x: (x[0].count("/"), x[0]))
for path, _ in items:
    if not re.fullmatch(r"/[A-Za-z0-9_./@-]+", path):
        sys.exit("unsafe path for debugfs: %r" % path)

exists = {p: dstat(p) is not None for p, _ in items}

cmds = []
for path, src in items:
    st = os.lstat(src)
    parent, name = os.path.split(path)
    if stat.S_ISDIR(st.st_mode):
        if not exists[path]:
            cmds += ["mkdir " + path, "sif %s mode 0%o" % (path, 0o40000 | (st.st_mode & 0o7777)),
                     "sif %s uid 0" % path, "sif %s gid 0" % path]
        continue
    if exists[path]:
        cmds.append("rm " + path)
    if stat.S_ISLNK(st.st_mode):
        cmds.append("symlink %s %s" % (path, os.readlink(src)))
    elif stat.S_ISREG(st.st_mode):
        cmds += ["cd " + (parent or "/"), "write %s %s" % (src, name), "cd /",
                 "sif %s mode 0%o" % (path, 0o100000 | (st.st_mode & 0o7777))]
    else:
        sys.exit("unsupported file type: " + path)
    cmds += ["sif %s uid 0" % path, "sif %s gid 0" % path]
r = debugfs(cmds, write=True)
errs = [l for l in r.stderr.splitlines() if l.strip() and not l.startswith("debugfs ")]
if errs:
    print("\n".join(errs))

# read back: every file's content, mode, owner; every link's target
bad = 0
for path, src in items:
    st = os.lstat(src)
    text = dstat(path) or ""
    m = re.search(r"Mode:\s+0?(\d+)", text)
    u = re.search(r"User:\s+(\d+)\s+Group:\s+(\d+)", text)
    want = st.st_mode & 0o7777
    if not m or int(m.group(1), 8) & 0o7777 != want or not u or u.groups() != ("0", "0"):
        if not (stat.S_ISDIR(st.st_mode) and exists[path]):   # existing directories keep their mode
            print("MISMATCH mode/owner:", path, m and m.group(1), u and u.groups()); bad += 1
    if stat.S_ISLNK(st.st_mode):
        if 'Fast link dest: "%s"' % os.readlink(src) not in text:
            print("MISMATCH link:", path); bad += 1
for path, src in items:
    if os.path.isfile(src) and not os.path.islink(src):
        dst = os.path.join(work, "readback")
        subprocess.run(["debugfs", "-R", "dump %s %s" % (path, dst), fs], capture_output=True)
        a = hashlib.sha256(open(src, "rb").read()).hexdigest()
        b = hashlib.sha256(open(dst, "rb").read()).hexdigest() if os.path.exists(dst) else "missing"
        if a != b:
            print("MISMATCH content:", path); bad += 1
        else:
            print("  ok %s  %s" % (a[:16], path))
        if os.path.exists(dst):
            os.unlink(dst)
sys.exit(1 if bad else 0)
PY
e2fsck -fn "$FS" >"$WORK/e2fsck.log" 2>&1 || { cat "$WORK/e2fsck.log"; die "e2fsck found problems in the root file system"; }
tail -n 1 "$WORK/e2fsck.log"

# ── 8. qcow2 (compressed), checks ──────────────────────────────────────────
step "qcow2"
QCOW="$OUT/$NAME.qcow2"
rm -f "$QCOW" "$QCOW.sha256"
"$QEMU_IMG" convert -f raw -O qcow2 -c -o compat=1.1 "$RAW" "$QCOW"
"$QEMU_IMG" check "$QCOW"
"$QEMU_IMG" compare -f raw -F qcow2 "$RAW" "$QCOW" || die "qcow2 content differs from the raw disk"
"$QEMU_IMG" info --output=json "$QCOW" | python3 -c '
import json, sys
d = json.load(sys.stdin)
want = int(sys.argv[1][:-1]) << 30
assert d["format"] == "qcow2" and d["virtual-size"] == want, (d["format"], d["virtual-size"], want)
print("qcow2, virtual size %d GiB" % (d["virtual-size"] >> 30))' "${PIN[VM_DISK_SIZE]}" || die "unexpected qcow2 format/size"
bytes="$(stat -c %s "$QCOW")"
(( bytes < MAX_BYTES )) || die "image is $bytes bytes: over the 2 GiB release-asset limit"
(cd "$OUT" && sha256sum "$NAME.qcow2" >"$NAME.qcow2.sha256")
printf '\nBuilt %s (%s MiB, Ubuntu cloud image serial %s)\n%s\n' "$QCOW" "$((bytes / 1048576))" "$SERIAL" "$(cat "$QCOW.sha256")"
