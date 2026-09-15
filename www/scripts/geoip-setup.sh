#!/usr/bin/env bash
# Installs the free DB-IP "IP to City Lite" + "IP to ASN Lite" databases (MMDB)
# and the maxminddb Python package so the tuxwall Security page can map
# blocked attacker IPs to countries/cities and ISP/ASN. No account or
# license key required.
#
# Usage:  sudo bash geoip-setup.sh
#
# Data (c) DB-IP.com, licensed under CC BY 4.0 - attribution required in the UI:
#   https://db-ip.com/db/lite.php
set -euo pipefail

DEST=/var/lib/tuxwall/dbip-city-lite.mmdb
ASN_DEST=/var/lib/tuxwall/dbip-asn-lite.mmdb

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run with sudo:  sudo bash $0" >&2
  exit 1
fi

echo "[1/4] Installing the maxminddb Python package..."
if ! python3 -c "import maxminddb" 2>/dev/null; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y python3-maxminddb >/dev/null 2>&1 || true
  fi
fi
if ! python3 -c "import maxminddb" 2>/dev/null; then
  python3 -m pip install --break-system-packages maxminddb
fi
python3 -c "import maxminddb" || { echo "ERROR: could not import maxminddb" >&2; exit 1; }

echo "[2/4] Downloading db-ip City Lite (MMDB)..."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch_one() {
  # $1 = destination, $2 = short name (e.g. "dbip-city-lite", "dbip-asn-lite")
  local dest="$1" name="$2" url="" stamp
  for MONTH_OFFSET in 0 1 2 3; do
    STAMP="$(date -u -d "-${MONTH_OFFSET} month" +%Y-%m 2>/dev/null || date -u +%Y-%m)"
    URL="https://download.db-ip.com/free/${name}-${STAMP}.mmdb.gz"
    if curl -fsSL -o "$TMP/file.mmdb.gz" "$URL" 2>/dev/null; then
      url="$URL"
      break
    fi
  done
  if [[ -z "$url" ]]; then
    echo "ERROR: could not download ${name} (server unreachable?)" >&2
    return 1
  fi
  echo "   fetched $url"
  gzip -d -f "$TMP/file.mmdb.gz"
  install -m 0644 "$TMP/file.mmdb" "$dest"
  echo "Installed $dest"
}

mkdir -p /var/lib/tuxwall
fetch_one "$DEST" dbip-city-lite || exit 1
fetch_one "$ASN_DEST" dbip-asn-lite || exit 1

echo "[3/4] Restarting the dashboard API..."
systemctl try-restart tuxwall 2>/dev/null || systemctl start tuxwall 2>/dev/null || true
echo "[4/4] Restarting the tuxwall-collector service (if present)..."
systemctl try-restart tuxwall-collector 2>/dev/null || true

echo
echo "Done. The Security page will now show attacker locations and ISP/ASN on the map."
echo "Verify with:  curl -s http://127.0.0.1:8008/api/security | python3 -m json.tool"