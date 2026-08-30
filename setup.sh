#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# TuxWall Automated Installer
# Tested on: Ubuntu 24.04 / 25.04
# Run as root: sudo bash setup.sh
# ============================================================================

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Colours ---------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[ OK ]${NC}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
fail()  { printf "${RED}[FAIL]${NC}  %s\n" "$*" >&2; exit 1; }

# --- Pre-flight checks ----------------------------------------------------
[[ $EUID -eq 0 ]] || fail "Run this script as root: sudo bash $0"

command -v apt-get >/dev/null 2>&1 || fail "apt-get not found — this installer targets Debian/Ubuntu."

info "TuxWall installer starting from: $REPO_DIR"
echo

# ============================================================================
# 1. SYSTEM PACKAGES
# ============================================================================
info "Installing system dependencies..."

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq

apt-get install -y --no-install-recommends \
    ufw iptables nftables iproute2 \
    kea-dhcp4-server kea-common \
    unbound unbound-anchor \
    radvd \
    wireguard wireguard-tools \
    suricata suricata-update \
    crowdsec crowdsec-firewall-bouncer-iptables \
    nginx \
    python3 curl jq gzip ieee-data \
    || fail "apt install failed"

# Optional but nice to have
apt-get install -y --no-install-recommends python3-maxminddb python3-netifaces 2>/dev/null || true

ok "System packages installed"

# ============================================================================
# 2. DISABLE systemd-resolved (conflicts with unbound on port 53)
# ============================================================================
info "Disabling systemd-resolved..."

systemctl disable --now systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved-varlink.socket systemd-resolved-monitor.socket 2>/dev/null || true

rm -f /etc/resolv.conf

# Point DNS to unbound (localhost)
cat > /etc/resolv.conf <<'EOF'
nameserver 127.0.0.1
nameserver ::1
search home.arpa
EOF

ok "systemd-resolved disabled, /etc/resolv.conf set to unbound"

# ============================================================================
# 3. ENABLE IP FORWARDING
# ============================================================================
info "Enabling IPv4/IPv6 forwarding..."

sed -i 's/^#\s*net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/'           /etc/sysctl.conf 2>/dev/null || true
sed -i 's/^#\s*net.ipv6.conf.all.forwarding.*/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf 2>/dev/null || true

grep -q '^net.ipv4.ip_forward=1'           /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1'           >> /etc/sysctl.conf
grep -q '^net.ipv6.conf.all.forwarding=1'  /etc/sysctl.conf 2>/dev/null || echo 'net.ipv6.conf.all.forwarding=1'  >> /etc/sysctl.conf

sysctl -w net.ipv4.ip_forward=1          >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1

ok "IP forwarding enabled"

# ============================================================================
# 4. DIRECTORY STRUCTURE
# ============================================================================
info "Creating directory structure..."

mkdir -p /etc/tuxwall
mkdir -p /var/lib/tuxwall
mkdir -p /var/lib/unbound
mkdir -p /etc/unbound/unbound.conf.d

ok "Directories created"

# ============================================================================
# 5. WEB ROOT — /var/www/html
# ============================================================================
info "Installing web files to /var/www/html..."

# Preserve default nginx page if present
[[ -f /var/www/html/index.nginx-debian.html ]] && mv /var/www/html/index.nginx-debian.html /var/www/html/index.nginx-debian.html.bak 2>/dev/null || true

# Remove stale www files (but keep api_server data dirs intact)
rm -f  /var/www/html/index.html
rm -rf /var/www/html/css /var/www/html/scripts /var/www/html/includes /var/www/html/images /var/www/html/themes

# Copy fresh
cp -r "$REPO_DIR/www/index.html"      /var/www/html/index.html
cp -r "$REPO_DIR/www/css"             /var/www/html/css
cp -r "$REPO_DIR/www/scripts"         /var/www/html/scripts
cp -r "$REPO_DIR/www/includes"        /var/www/html/includes
cp -r "$REPO_DIR/www/images"          /var/www/html/images

# Ensure api_server.py is executable
chmod 755 /var/www/html/includes/api_server.py

ok "Web files installed"

# ============================================================================
# 6. CONFIG FILES — /etc/tuxwall
# ============================================================================
info "Installing config files to /etc/tuxwall/..."

cp "$REPO_DIR/config/ui.json"              /etc/tuxwall/ui.json
cp "$REPO_DIR/config/llm.json.example"     /etc/tuxwall/llm.json
cp "$REPO_DIR/config/custom-blocklist.txt" /etc/tuxwall/custom-blocklist.txt

# Auth is generated at first run by api_server.py; ensure dir is writable
chmod 755 /etc/tuxwall

ok "Config files installed"

# ============================================================================
# 7. SCRIPTS
# ============================================================================
info "Installing scripts..."

# SQM script
cp "$REPO_DIR/scripts/tuxwall-sqm.sh" /usr/local/sbin/tuxwall-sqm.sh
chmod 755 /usr/local/sbin/tuxwall-sqm.sh

# System backup script (if present in repo)
[[ -f "$REPO_DIR/scripts/system-backup.sh" ]] && {
    cp "$REPO_DIR/scripts/system-backup.sh" /usr/local/sbin/system-backup.sh
    chmod 755 /usr/local/sbin/system-backup.sh
    ok "system-backup.sh installed"
}

# GeoIP setup (can be run later)
chmod 755 "$REPO_DIR/www/scripts/geoip-setup.sh" 2>/dev/null || true

ok "Scripts installed"

# ============================================================================
# 8. NGINX CONFIGURATION
# ============================================================================
info "Installing nginx site config..."

# Remove default site if enabled
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

cp "$REPO_DIR/nginx/tuxwall.conf" /etc/nginx/sites-available/tuxwall

# Create symlink if not present
ln -sf /etc/nginx/sites-available/tuxwall /etc/nginx/sites-enabled/tuxwall

# Validate
nginx -t 2>/dev/null && ok "nginx config validated" || warn "nginx -t failed — check config manually"

# ============================================================================
# 9. SYSTEMD SERVICE FILES
# ============================================================================
info "Installing systemd units..."

cp "$REPO_DIR/systemd/tuxwall.service"                    /etc/systemd/system/tuxwall.service
cp "$REPO_DIR/systemd/tuxwall-blocklist-update.service"   /etc/systemd/system/tuxwall-blocklist-update.service
cp "$REPO_DIR/systemd/tuxwall-blocklist-update.timer"     /etc/systemd/system/tuxwall-blocklist-update.timer

# SQM service (optional — installed but not enabled by default)
cp "$REPO_DIR/systemd/tuxwall-sqm.service"               /etc/systemd/system/tuxwall-sqm.service

systemctl daemon-reload

ok "Systemd units installed"

# ============================================================================
# 9B. OPENCODE AI AGENT (opencode)
# ============================================================================
info "Setting up the opencode AI agent (dashboard AI assistant)..."

if bash "$REPO_DIR/scripts/setup-opencode-agent.sh" \
        "$REPO_DIR/config/opencode.json" \
        "$REPO_DIR/systemd/tuxwall-agent.service"; then
    ok "opencode agent installed (tuxwall-agent.service on 127.0.0.1:4096)"
else
    warn "opencode agent setup failed — the dashboard works without it;"
    warn "re-run later: sudo bash $REPO_DIR/scripts/setup-opencode-agent.sh"
fi


# ============================================================================
# 10. UNBOUND — ensure includes directory exists
# ============================================================================
info "Setting up unbound..."

# Ensure unbound.d conf.d directory exists
mkdir -p /etc/unbound/unbound.conf.d

# Create the local-domains include if it doesn't exist
DOMAINS_CONF="/etc/unbound/unbound.conf.d/98-local-domains.conf"
if [[ ! -f "$DOMAINS_CONF" ]]; then
    cat > "$DOMAINS_CONF" <<'UNBOUND_EOF'
server:
    local-zone: "home.arpa" static
    local-data: "gateway.home.arpa. IN A 192.168.1.1"
    local-data-ptr: "192.168.1.1 gateway.home.arpa"
UNBOUND_EOF
    ok "Created $DOMAINS_CONF"
fi

ok "Unbound configured"

# ============================================================================
# 11. UFW — allow web interface and WireGuard
# ============================================================================
info "Configuring UFW rules..."

# Allow HTTP (dashboard)
ufw allow 80/tcp comment "TuxWall dashboard" 2>/dev/null || true

# Allow WireGuard default port
ufw allow 51820/udp comment "WireGuard" 2>/dev/null || true

ok "UFW rules added"

# ============================================================================
# 12. ENABLE AND START SERVICES
# ============================================================================
info "Enabling services..."

# Core services
for svc in \
    kea-dhcp4-server \
    unbound \
    radvd \
    suricata \
    crowdsec \
    nginx \
    tuxwall \
    tuxwall-agent \
    tuxwall-blocklist-update.timer \
; do
    systemctl enable "$svc" 2>/dev/null || warn "Could not enable $svc"
    systemctl start  "$svc" 2>/dev/null || warn "Could not start $svc — may need manual config"
done

ok "Services enabled and started"

# ============================================================================
# 13. FIX HARDCODED PATHS IN api_server.py
# ============================================================================
info "Patching hardcoded paths in api_server.py..."

API_SERVER="/var/www/html/includes/api_server.py"

if [[ -f "$API_SERVER" ]]; then
    # Fix BACKUP_DIR
    sed -i 's|BACKUP_DIR = "/home/jeff/backups"|BACKUP_DIR = "/var/backups/tuxwall"|g' "$API_SERVER"

    # Fix SOURCE_DIR
    sed -i 's|SOURCE_DIR = "/home/jeff/tuxwall-blocklist"|SOURCE_DIR = "/var/lib/tuxwall"|g' "$API_SERVER"

    # Create the backup dir
    mkdir -p /var/backups/tuxwall

    ok "Hardcoded paths patched"
else
    warn "api_server.py not found at $API_SERVER — skipping path patch"
fi

# ============================================================================
# 14. PERMISSIONS
# ============================================================================
info "Setting permissions..."

# Unbound must be able to read blocklist/bans conf
chmod 644 /var/lib/unbound/blocklist.conf     2>/dev/null || true
chmod 644 /var/lib/unbound/client-bans.conf   2>/dev/null || true

# Data directory writable by tuxwall service (runs as root by default)
chmod 755 /var/lib/tuxwall

ok "Permissions set"

# ============================================================================
# DONE
# ============================================================================
echo
echo "=========================================="
echo -e "${GREEN}  TuxWall installation complete!${NC}"
echo "=========================================="
echo
echo "  Dashboard : http://localhost (or gateway LAN IP)"
echo "  Default   : admin / tuxwall"
echo
echo "  Services  :"
echo "    systemctl status tuxwall"
echo "    systemctl status tuxwall-agent   (opencode AI assistant)"
echo "    systemctl status unbound"
echo "    systemctl status kea-dhcp4-server"
echo "    systemctl status crowdsec"
echo "    systemctl status suricata"
echo "    systemctl status nginx"
echo
echo "  Logs      :"
echo "    journalctl -u tuxwall -f"
echo
echo "  Optional  :"
echo "    sudo bash $REPO_DIR/www/scripts/geoip-setup.sh   # Enable GeoIP map"
echo "    sudo /usr/local/sbin/tuxwall-sqm.sh              # Enable SQM (edit WAN/speeds first)"
echo
