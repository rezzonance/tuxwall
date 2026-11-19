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

OUTDIR="/var/lib/tuxwall/backups/system"
INCLUDE_FILE=""
while getopts "o:i:" opt; do
  case "$opt" in
    o) OUTDIR="$OPTARG" ;;
    i) INCLUDE_FILE="$OPTARG" ;;
    *) exit 2 ;;
  esac
done

# 2026-11-03 audit: this archive contains WireGuard private keys, tuxwall
# auth.json and the cloudflared tunnel secret. The output directory must be
# an operator-storage path - never web-served, user-writable or /tmp.
case "$OUTDIR" in
  /var/lib/tuxwall/backups/*|/var/backups/*|/root/*|/mnt/*|/media/*|/opt/backups/*) ;;
  *)
    echo "ERROR: refusing unsafe output directory: $OUTDIR" >&2
    echo "       (use /var/lib/tuxwall/backups, /var/backups, /root, /mnt or /media)" >&2
    exit 2 ;;
esac

# Archives hold secrets: nothing this script creates is ever group/world readable.
umask 077

TS="$(date +%Y%m%d-%H%M%S)"
NAME="system-backup-${TS}.tar.gz"
STAGE="$(mktemp -d /tmp/sysbackup.XXXXXX)"
PARTIAL=""
trap 'rm -rf "$STAGE"; [ -n "$PARTIAL" ] && rm -f "$PARTIAL"' EXIT

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
  "/var/www/html|var/www/html"
  "/etc/default/ufw|etc/default/ufw"
  "/etc/nftables.conf|etc/nftables.conf"
  "/etc/ssh|etc/ssh"
  "/etc/letsencrypt|etc/letsencrypt"
  "/etc/suricata|etc/suricata"
  "/etc/opencanaryd|etc/opencanaryd"
  "/etc/chrony|etc/chrony"
  "/etc/systemd/resolved.conf|etc/systemd/resolved.conf"
  "/etc/sudoers.d|etc/sudoers.d"
  "/etc/cron.d|etc/cron.d"
  "/etc/networkd-dispatcher|etc/networkd-dispatcher"
  "/etc/modules-load.d|etc/modules-load.d"
  "/var/lib/tuxwall|var/lib/tuxwall"
  "/var/lib/kea|var/lib/kea"
)

# Keep these three lists in sync with www/includes/backups.py (checked by
# tools/backup_safety_check.py).
# Subdirs to skip inside /etc/crowdsec (regenerable / downloadable)
CROWDSEC_EXCLUDE=("hub" "patterns" "lists")
# Dashboard: skip bytecode, logs, editor/deploy leftovers
WWW_EXCLUDE=("__pycache__" "logs" "backups" ".git" "*.pyc" "*.bak-*" "*.orig" "*.pre-*" "*.tmp" "index.nginx-debian.html")
# /var/lib/tuxwall: only state needed to rebuild (no GeoIP DBs, caches,
# histories, hit logs or the backups themselves)
TUXWALL_STATE_ONLY=("fw-snapshots" "firewall-backups" "wireguard.json" "canary-token" "whitelist.json" "rpz.json" "rpz-feeds.json" "blocklists.json" "honeypot.json" "reported-decisions.json")

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
    if [ "$src" = "/etc/crowdsec" ] || [ "$src" = "/var/www/html" ]; then
      args=(-a)
      if [ "$src" = "/etc/crowdsec" ]; then excl=("${CROWDSEC_EXCLUDE[@]}"); else excl=("${WWW_EXCLUDE[@]}"); fi
      for sub in "${excl[@]}"; do
        args+=(--exclude "$sub")
      done
      rsync "${args[@]}" "$src"/ "$STAGE/$arc/" 2>/dev/null || echo "WARN: could not fully read $src" >&2
    elif [ "$src" = "/var/lib/tuxwall" ]; then
      for sub in "${TUXWALL_STATE_ONLY[@]}"; do
        [ -e "$src/$sub" ] || continue
        cp -a "$src/$sub" "$STAGE/$arc/" 2>/dev/null || echo "WARN: could not read $src/$sub" >&2
      done
    else
      cp -a "$src"/. "$STAGE/$arc/" 2>/dev/null || echo "WARN: could not fully read $src" >&2
    fi
  else
    cp -a "$src" "$STAGE/$arc" 2>/dev/null || echo "WARN: could not read $src" >&2
  fi
done
# Bytecode caches are regenerated; never back them up (GLOBAL_EXCLUDE).
find "$STAGE" -depth -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
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

echo "==> Restoring system configuration (etc/, usr/local/, var/)"
[ -d etc ] && cp -a etc/. /etc/
[ -d usr/local ] && cp -a usr/local/. /usr/local/
[ -d var/lib/tuxwall ] && mkdir -p /var/lib/tuxwall && cp -a var/lib/tuxwall/. /var/lib/tuxwall/
[ -d var/lib/kea ] && mkdir -p /var/lib/kea && cp -a var/lib/kea/. /var/lib/kea/
[ -d var/www/html ] && mkdir -p /var/www/html && cp -a var/www/html/. /var/www/html/
# NOTE: iptables-save.txt / ip6tables-save.txt are a reference only; the
# firewall comes back from etc/ufw (+ ufw reload below).

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
for svc in kea-dhcp4-server unbound nginx radvd crowdsec tuxwall; do
  systemctl enable "$svc" 2>/dev/null || true
  systemctl restart "$svc" 2>/dev/null || true
done
# NOTE: ufw is not a systemd unit — reload its rules instead of restarting.
ufw reload 2>/dev/null || true
# NOTE: systemd-networkd restart can sever SSH on a live gateway; the
# restored netplan is applied on next reboot (or manually).
echo "    NOTE: network config restored but NOT applied - reboot (or netplan apply) to activate."

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
  echo "Not included: databases (CrowdSec/reports/MariaDB: see the USB backup), GeoIP databases,"
  echo "              caches, logs, histories, home directories (incl. the opencode credential store)"
} > "$STAGE/manifest.txt"

progress 85 "Compressing archive"
mkdir -p "$OUTDIR"
# Write under a temporary name and rename only after the archive verifies,
# so a failed or interrupted run never leaves a valid-looking backup.
PARTIAL="$OUTDIR/.${NAME}.partial"
tar -C "$STAGE" -czf "$PARTIAL" .
chmod 600 "$PARTIAL"
progress 92 "Verifying archive"
if ! tar -tzf "$PARTIAL" >/dev/null 2>&1; then
  echo "ERROR: archive verification failed (tar -tzf)" >&2
  exit 4
fi
mv -f "$PARTIAL" "$OUTDIR/$NAME"
PARTIAL=""
st="$OUTDIR/$NAME"
progress 95 "Archive written: $st"

echo "RESULT $NAME"
progress 100 "Done"
echo "System backup: $st" >&2
