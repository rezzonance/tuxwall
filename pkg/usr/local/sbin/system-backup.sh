#!/usr/bin/env bash
# TuxWall system backup: captures critical system config + apt package state
# into a single self-contained archive with a restore.sh inside.
#
# Usage:
#   sudo system-backup.sh [-o OUTDIR] [-i INCLUDE_FILE]
#
# Emits progress lines on stdout:   PROGRESS <pct> <message>
# Emits final archive name:        RESULT <filename>
#
# INCLUDE_FILE (optional): one arcname per line; only matching CONFIG_PATHS
# entries are captured. Empty or missing file = include everything.
set -euo pipefail

OUTDIR="/home/jeff/backups/system"
INCLUDE_FILE=""
while getopts "o:i:" opt; do
  case "$opt" in
    o) OUTDIR="$OPTARG" ;;
    i) INCLUDE_FILE="$OPTARG" ;;
    *) exit 2 ;;
  esac
done

TS="$(date +%Y%m%d-%H%M%S)"
NAME="system-backup-${TS}.tar.gz"
STAGE="$(mktemp -d /tmp/sysbackup.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT

progress() { echo "PROGRESS $1 $2"; }

# Source (path or dir) -> destination arcname
CONFIG_PATHS=(
  "/etc/netplan|etc/netplan"
  "/etc/systemd/network|etc/systemd/network"
  "/etc/kea|etc/kea"
  "/etc/unbound|etc/unbound"
  "/etc/ufw|etc/ufw"
  "/etc/nginx|etc/nginx"
  "/etc/systemd/system|etc/systemd/system"
  "/etc/sysctl.d|etc/sysctl.d"
  "/etc/radvd.conf|etc/radvd.conf"
  "/etc/wireguard|etc/wireguard"
  "/etc/cloudflared|etc/cloudflared"
  "/etc/tuxwall|etc/tuxwall"
  "/etc/crowdsec|etc/crowdsec"
  "/etc/apt/sources.list|etc/apt/sources.list"
  "/etc/apt/sources.list.d|etc/apt/sources.list.d"
  "/etc/hosts|etc/hosts"
  "/etc/hostname|etc/hostname"
  "/etc/fstab|etc/fstab"
  "/etc/hosts.allow|etc/hosts.allow"
  "/etc/hosts.deny|etc/hosts.deny"
  "/usr/local/bin|usr/local/bin"
  "/usr/local/sbin|usr/local/sbin"
)

# Subdirs to skip inside /etc/crowdsec (regenerable / downloadable)
CROWDSEC_EXCLUDE=("hub" "patterns" "lists")

# Optional include filter: keep only CONFIG_PATHS entries whose arcname
# appears in INCLUDE_FILE. No file / empty file = include everything.
if [ -n "$INCLUDE_FILE" ] && [ -s "$INCLUDE_FILE" ]; then
  FILTERED=()
  for entry in "${CONFIG_PATHS[@]}"; do
    arc="${entry#*|}"
    if grep -qx -- "$arc" "$INCLUDE_FILE"; then
      FILTERED+=("$entry")
    fi
  done
  if [ "${#FILTERED[@]}" -eq 0 ]; then
    echo "ERROR: include filter matched no known config entries" >&2
    exit 3
  fi
  CONFIG_PATHS=("${FILTERED[@]}")
fi

progress 5 "Preparing staging area"

for entry in "${CONFIG_PATHS[@]}"; do
  src="${entry%%|*}"
  arc="${entry#*|}"
  if [ ! -e "$src" ]; then
    continue
  fi
  mkdir -p "$STAGE/$(dirname "$arc")"
  if [ -d "$src" ]; then
    mkdir -p "$STAGE/$arc"
    if [ "$src" = "/etc/crowdsec" ]; then
      args=(-a)
      for sub in "${CROWDSEC_EXCLUDE[@]}"; do
        args+=(--exclude "$sub")
      done
      rsync "${args[@]}" "$src"/ "$STAGE/$arc/" 2>/dev/null || echo "WARN: could not fully read $src" >&2
    else
      cp -a "$src"/. "$STAGE/$arc/" 2>/dev/null || echo "WARN: could not fully read $src" >&2
    fi
  else
    cp -a "$src" "$STAGE/$arc" 2>/dev/null || echo "WARN: could not read $src" >&2
  fi
done
progress 30 "Configuration files collected"

# package state (requires root)
progress 35 "Capturing installed package state"
dpkg --get-selections > "$STAGE/dpkg-selections.txt" 2>/dev/null || true
apt-mark showmanual > "$STAGE/apt-manual.txt" 2>/dev/null || true
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > "$STAGE/package-versions.txt" 2>/dev/null || true
cp -a /etc/apt/sources.list "$STAGE/etc/apt/sources.list" 2>/dev/null || true

progress 50 "Capturing live firewall rules"
iptables-save > "$STAGE/iptables-save.txt" 2>/dev/null || true
ip6tables-save > "$STAGE/ip6tables-save.txt" 2>/dev/null || true

# write restore.sh
progress 60 "Embedding restore script"
cat > "$STAGE/restore.sh" <<'RESTORE_EOF'
#!/usr/bin/env bash
# TuxWall system backup restore — run with sudo from the extracted backup directory:
#   tar xzf system-backup-*.tar.gz
#   sudo bash restore.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

echo "==> Restoring system configuration (etc/, usr/local/)"
[ -d etc ] && cp -a etc/. /etc/
[ -d usr/local ] && cp -a usr/local/. /usr/local/

echo "==> Reloading systemd unit definitions"
systemctl daemon-reload || true

echo "==> Applying kernel settings"
sysctl --system || true

echo "==> Restoring installed packages"
if [ -f dpkg-selections.txt ]; then
  dpkg --set-selections < dpkg-selections.txt
  apt-get dselect-upgrade -y || true
fi
if [ -f apt-manual.txt ]; then
  xargs apt-mark manual < apt-manual.txt || true
fi

echo "==> Enabling and restarting key services"
for svc in kea-dhcp4-server unbound nginx radvd cloudflared crowdsec tuxwall; do
  systemctl enable "$svc" 2>/dev/null || true
  systemctl restart "$svc" 2>/dev/null || true
done
systemctl restart systemd-networkd 2>/dev/null || true
systemctl restart ufw 2>/dev/null || true

echo "==> Done. Manual follow-ups if needed:"
echo "    sudo netplan apply"
echo "    sudo wg-quick up wg0"
echo "    sudo ufw status"
RESTORE_EOF
chmod +x "$STAGE/restore.sh"

# manifest
progress 70 "Writing manifest"
{
  echo "TuxWall system backup"
  echo "Created:      $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
  echo "Hostname:     $(hostname)"
  echo "Kernel:       $(uname -r)"
  echo "Restore:      tar xzf ${NAME} && sudo bash restore.sh"
  echo ""
  echo "Included config:"
  for entry in "${CONFIG_PATHS[@]}"; do
    [ -e "${entry%%|*}" ] && echo "  ${entry%%|*}"
  done
  echo ""
  echo "Also included: dpkg-selections.txt, apt-manual.txt, package-versions.txt, iptables-save.txt, ip6tables-save.txt"
} > "$STAGE/manifest.txt"

progress 85 "Compressing archive"
mkdir -p "$OUTDIR"
tar -C "$STAGE" -czf "$OUTDIR/$NAME" .
chmod 600 "$OUTDIR/$NAME"
st="$OUTDIR/$NAME"
progress 95 "Archive written: $st"

echo "RESULT $NAME"
progress 100 "Done"
echo "System backup: $st" >&2
