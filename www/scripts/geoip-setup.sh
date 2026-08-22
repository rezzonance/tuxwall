#!/usr/bin/env bash
# Installs the free DB-IP "IP to City Lite" database (MMDB) + the maxminddb
# Python package so the tuxwall Security page can map blocked attacker IPs
# to countries/cities. No account or license key required.
#
# Usage:  sudo bash geoip-setup.sh
#
# Data (c) DB-IP.com, licensed under CC BY 4.0 - attribution required in the UI:
#   https://db-ip.com/db/lite.php
set -euo pipefail

DEST=/var/lib/tuxwall/dbip-city-lite.mmdb

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run with sudo:  sudo bash $0" >&2
  exit 1
fi

echo "[1/3] Installing the maxminddb Python package..."
if ! python3 -c "import maxminddb" 2>/dev/null; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y python3-maxminddb >/dev/null 2>&1 || true
  fi
fi
if ! python3 -c "import maxminddb" 2>/dev/null; then
  python3 -m pip install --break-system-packages maxminddb
fi
python3 -c "import maxminddb" || { echo "ERROR: could not import maxminddb" >&2; exit 1; }

echo "[2/3] Downloading db-ip City Lite (MMDB)..."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

DB_URL=""
for MONTH_OFFSET in 0 1 2 3; do
  STAMP="$(date -u -d "-${MONTH_OFFSET} month" +%Y-%m 2>/dev/null || date -u +%Y-%m)"
  URL="https://download.db-ip.com/free/dbip-city-lite-${STAMP}.mmdb.gz"
  if curl -fsSL -o "$TMP/dbip.mmdb.gz" "$URL" 2>/dev/null; then
    DB_URL="$URL"
    break
  fi
done
if [[ -z "$DB_URL" ]]; then
  echo "ERROR: could not download db-ip City Lite (server unreachable?)" >&2
  exit 1
fi
echo "   fetched $DB_URL"

gzip -d -f "$TMP/dbip.mmdb.gz"
DB="$TMP/dbip.mmdb"
mkdir -p /var/lib/tuxwall
install -m 0644 "$DB" "$DEST"
echo "Installed $DEST"

echo "[3/3] Restarting the dashboard API..."
systemctl restart tuxwall

echo
echo "Done. The Security page will now show attacker locations on the map."
echo "Verify with:  curl -s http://127.0.0.1:8008/api/security | python3 -m json.tool"
