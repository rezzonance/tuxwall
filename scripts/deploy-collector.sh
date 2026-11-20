#!/usr/bin/env bash
# Deploys the tuxwall.org community ban collector + updated dashboard on the
# tuxwall.org server (this host). Root required.
#
#   sudo bash scripts/deploy-collector.sh
#
# Installs:
#   - collector -> /opt/tuxwall-collector/  + tuxwall-collector.service
#   - nginx: conf.d/tuxwall-limits.conf (new tuxwall_report zone),
#     conf.d/tuxwall-org-log.conf (key-safe access log format) and the
#     tuxwall-org vhost with /report /bans /api/public and /lists proxying
#   - tuxwall-collector-admin -> /usr/local/sbin (reporter key approval)
#   - dashboard client changes (api_server.py, index.html, dashboard.js,
#     geoip-setup.sh) into /var/www/html with a cache-bust bump
#   - best-effort db-ip ASN database via geoip-setup.sh (ISP column)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITE="${SITE:-/etc/nginx/sites-available/tuxwall-org}"

[[ $EUID -eq 0 ]] || { echo "Run with sudo:" >&2; exit 1; }

echo "[1/6] Installing collector service..."
# Dedicated unprivileged service user; the DB lives in the unit's
# StateDirectory (/var/lib/tuxwall-collector, owned by that user, 0700).
getent passwd tuxwall-collector >/dev/null || useradd --system --user-group \
  --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tuxwall-collector
install -d -m 0755 /opt/tuxwall-collector
install -m 0755 "$REPO_DIR/collector/tuxwall-collector.py" /opt/tuxwall-collector/tuxwall-collector.py
install -m 0755 "$REPO_DIR/scripts/tuxwall-collector-admin" /usr/local/sbin/tuxwall-collector-admin

# Admin keys for the loopback-only /api/admin endpoints. Never proxied by
# nginx. Created once, never overwritten; the service gets private copies
# through systemd LoadCredential=, so the files stay root-owned.
#   admin.key      full admin (reporter keys, whitelist, bans): root:adm 0640,
#                  used by tuxwall-collector-admin (run as root)
#   admin-api.key  scoped ban listing/removal key for the LAN Ban Management
#                  page: root:tuxwall-banadmin 0640 (php-fpm pool
#                  tuxwall-admin) - never readable by www-data / public PHP
install -d -m 0751 -g adm /etc/tuxwall-collector
getent group tuxwall-banadmin >/dev/null || useradd --system --user-group \
  --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tuxwall-banadmin
for kf in admin.key:adm admin-api.key:tuxwall-banadmin; do
  f="/etc/tuxwall-collector/${kf%%:*}"; grp="${kf##*:}"
  if [[ ! -s "$f" ]]; then
    ( umask 077; openssl rand -hex 32 > "$f" )
    echo "   created $f"
  fi
  chown "root:$grp" "$f"; chmod 0640 "$f"
done

install -m 0644 "$REPO_DIR/systemd/tuxwall-collector.service" /etc/systemd/system/tuxwall-collector.service
systemctl daemon-reload
systemctl enable tuxwall-collector
systemctl restart tuxwall-collector   # ExecStartPre fixes DB ownership
sleep 2
curl -fsS http://127.0.0.1:8009/healthz && echo
echo "   pending reporter keys (approve with: tuxwall-collector-admin approve <id>):"
/usr/local/sbin/tuxwall-collector-admin pending || true

echo "[2/6] Installing nginx rate-limit zone..."
install -m 0644 "$REPO_DIR/nginx/tuxwall-limits.conf" /etc/nginx/conf.d/tuxwall-limits.conf
# access-log format that never records key-bearing query strings
install -m 0644 "$REPO_DIR/nginx/tuxwall-org-log.conf" /etc/nginx/conf.d/tuxwall-org-log.conf
# /bans page cache (bans.php) - private to the php-fpm user, not /tmp
install -d -m 0700 -o www-data -g www-data /var/cache/tuxwall-org

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
# 3.3.1 UI modules and the world-map data (index.html references them;
# deploying a 3.3.1 index.html without these breaks the dashboard)
cp -rf "$REPO_DIR/www/scripts/." /var/www/html/scripts/
cp -rf "$REPO_DIR/www/data" /var/www/html/
cp -f "$REPO_DIR/www/scripts/geoip-setup.sh" /var/www/html/scripts/geoip-setup.sh
cp -rf "$REPO_DIR/www/css/." /var/www/html/css/
chmod 755 /var/www/html/scripts/geoip-setup.sh
chmod 755 /var/www/html/includes/api_server.py
ASSET_V="$(date +%Y%m%d%H%M)"
sed -i -E "s/\.(js|css)\?v=[A-Za-z0-9]+/.\1?v=${ASSET_V}/g" /var/www/html/index.html
echo "   asset version set to $ASSET_V"

echo "[5/6] Restarting dashboard API..."
systemctl restart tuxwall
# The API binds after a few seconds (module load + geoip init) - retry the
# health check for up to 30s instead of a fixed 1s sleep (which failed
# cosmetically on every deploy).
probe=""
for _ in $(seq 1 30); do
  sleep 1
  if probe=$(curl -fsS -m 2 http://127.0.0.1:8008/api/auth/session 2>/dev/null); then
    break
  fi
done
if [[ -z "$probe" ]]; then
  echo "dashboard API did not come up within 30s - check: journalctl -u tuxwall" >&2
  exit 1
fi
python3 -c 'import sys,json; d=json.load(sys.stdin); print("api ok, authenticated:", d.get("authenticated"))' <<< "$probe"

echo "[6/6] Installing db-ip ASN database (ISP column, best effort)..."
if [[ -f /var/lib/tuxwall/dbip-asn-lite.mmdb ]]; then
  echo "   dbip-asn-lite.mmdb already present"
else
  bash "$REPO_DIR/www/scripts/geoip-setup.sh" \
    || echo "   (geoip-setup failed/skipped — run later: sudo bash /var/www/html/scripts/geoip-setup.sh)"
fi

echo
echo "Done. Collector:       curl http://127.0.0.1:8009/healthz"
echo "      Reporter keys:   sudo tuxwall-collector-admin pending | approve <id> | revoke <id>"
echo "      Public page:     https://tuxwall.org/bans"
echo "      Ban list:        https://tuxwall.org/lists/community-bans.txt"