#!/usr/bin/env bash
# Deploys the tuxwall.org community ban collector + updated dashboard on the
# tuxwall.org server (this host). Root required.
#
#   sudo bash scripts/deploy-collector.sh
#
# Installs:
#   - collector -> /opt/tuxwall-collector/  + tuxwall-collector.service
#   - nginx: conf.d/tuxwall-limits.conf (new tuxwall_report zone) and the
#     tuxwall-org vhost with /report /bans /api/public and /lists proxying
#   - dashboard client changes (api_server.py, index.html, dashboard.js,
#     geoip-setup.sh) into /var/www/html with a cache-bust bump
#   - best-effort db-ip ASN database via geoip-setup.sh (ISP column)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITE="${SITE:-/etc/nginx/sites-available/tuxwall-org}"

[[ $EUID -eq 0 ]] || { echo "Run with sudo:" >&2; exit 1; }

echo "[1/6] Installing collector service..."
install -d -m 0755 /opt/tuxwall-collector /var/lib/tuxwall-collector
install -m 0755 "$REPO_DIR/collector/tuxwall-collector.py" /opt/tuxwall-collector/tuxwall-collector.py
install -m 0644 "$REPO_DIR/systemd/tuxwall-collector.service" /etc/systemd/system/tuxwall-collector.service
systemctl daemon-reload
systemctl enable --now tuxwall-collector
systemctl restart tuxwall-collector
sleep 1
curl -fsS http://127.0.0.1:8009/healthz && echo

echo "[2/6] Installing nginx rate-limit zone..."
install -m 0644 "$REPO_DIR/nginx/tuxwall-limits.conf" /etc/nginx/conf.d/tuxwall-limits.conf

echo "[3/6] Installing tuxwall-org vhost ($SITE)..."
install -m 0644 "$REPO_DIR/nginx/tuxwall-org.conf" "$SITE"
ln -sfn "$SITE" /etc/nginx/sites-enabled/$(basename "$SITE")
nginx -t
systemctl reload nginx

echo "[4/6] Updating dashboard files in /var/www/html..."
install -d /var/www/html
cp -f "$REPO_DIR/www/includes/api_server.py" /var/www/html/includes/api_server.py
cp -f "$REPO_DIR/www/index.html" /var/www/html/index.html
cp -f "$REPO_DIR/www/scripts/dashboard.js" /var/www/html/scripts/dashboard.js
cp -f "$REPO_DIR/www/scripts/geoip-setup.sh" /var/www/html/scripts/geoip-setup.sh
cp -rf "$REPO_DIR/www/css/." /var/www/html/css/
chmod 755 /var/www/html/scripts/geoip-setup.sh
chmod 755 /var/www/html/includes/api_server.py
ASSET_V="$(date +%Y%m%d%H%M)"
sed -i -E "s/\.(js|css)\?v=[A-Za-z0-9]+/.\1?v=${ASSET_V}/g" /var/www/html/index.html
echo "   asset version set to $ASSET_V"

echo "[5/6] Restarting dashboard API..."
systemctl restart tuxwall
sleep 1
curl -fsS http://127.0.0.1:8008/api/auth/session | python3 -c \
  'import sys,json; d=json.load(sys.stdin); print("api ok, authenticated:", d.get("authenticated"))'

echo "[6/6] Installing db-ip ASN database (ISP column, best effort)..."
if [[ -f /var/lib/tuxwall/dbip-asn-lite.mmdb ]]; then
  echo "   dbip-asn-lite.mmdb already present"
else
  bash "$REPO_DIR/www/scripts/geoip-setup.sh" \
    || echo "   (geoip-setup failed/skipped — run later: sudo bash /var/www/html/scripts/geoip-setup.sh)"
fi

echo
echo "Done. Collector:       curl http://127.0.0.1:8009/healthz"
echo "      Public page:     https://tuxwall.org/bans"
echo "      Ban list:        https://tuxwall.org/lists/community-bans.txt"