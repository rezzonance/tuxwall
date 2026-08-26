#!/usr/bin/env bash
###############################################################################
#  TuxWall Installer
#  Installs and configures TuxWall on a fresh Ubuntu system.
#  Run as root:  sudo bash install.sh
###############################################################################
set -euo pipefail

# ── Resolve script directory ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colours ──────────────────────────────────────────────────────────────────
R='\033[0;31m'  G='\033[0;32m'  Y='\033[0;33m'  C='\033[0;36m'
B='\033[1m'     DIM='\033[2m'   NC='\033[0m'

log()  { echo -e "${G}[+]${NC} $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; }
err()  { echo -e "${R}[✗]${NC} $*" >&2; }
hr()   { echo -e "${DIM}$(printf '%.0s─' {1..60})${NC}"; }

# ── Pre-flight checks ───────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root.  sudo bash $0"
    exit 1
fi

if ! grep -qi 'ubuntu' /etc/os-release 2>/dev/null; then
    warn "This script is designed for Ubuntu. Proceed with caution on other distros."
fi

TUXWALL_DEB_URL="https://github.com/rezzonance/tuxwall/raw/refs/heads/main/tuxwall_2.2.1_all.deb"
TUXWALL_DEB="/tmp/tuxwall_2.2.1_all.deb"

# ── ASCII Banner ─────────────────────────────────────────────────────────────
clear
echo -e "${C}"
cat << 'BANNER'

  TTTTTTT  U   U  X   X  W     W    A     L     L
     T     U   U  X  X   W     W   A A    L     L
     T     U   U  X X    W     W  A   A   L     L
     T      UUU   XX     W  W  W  AAAAA   L     L
     T       U    X X    W W W W  A   A   L     L
     T       U    X  X   WW   WW  A   A   L     L
     T       U    X   X  W     W  A   A   LLLLLLL

BANNER
echo -e "${NC}"
echo -e "  ${B}Linux Network Dashboard Installer${NC}"
echo -e "  ${DIM}https://github.com/rezzonance/tuxwall${NC}"
hr
echo

# ── Step 1: System packages ─────────────────────────────────────────────────
log "Installing system packages..."
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq

apt-get install -y -qq \
    ufw iptables nftables iproute2 \
    kea-dhcp4-server kea-common \
    unbound unbound-anchor \
    radvd \
    wireguard wireguard-tools \
    suricata suricata-update \
    crowdsec crowdsec-firewall-bouncer-iptables \
    nginx \
    python3 python3-pip \
    curl jq gzip ca-certificates \
    ieee-data

log "System packages installed."

# ── Step 2: Disable systemd-resolved ────────────────────────────────────────
log "Disabling systemd-resolved (conflicts with unbound on port 53)..."

systemctl disable --now systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved-varlink.socket systemd-resolved-monitor.socket 2>/dev/null || true

# Replace symlink with static resolv.conf
if [[ -L /etc/resolv.conf ]]; then
    rm -f /etc/resolv.conf
fi

cat > /etc/resolv.conf << 'RESOLV'
nameserver 127.0.0.1
nameserver ::1
search localdomain
RESOLV

log "systemd-resolved disabled. /etc/resolv.conf points to local unbound."

# ── Step 3: Check for DHCPv6 port 546 conflicts ─────────────────────────────
log "Checking for DHCPv6 port 546 conflicts..."

PORT546_PROCS=$(ss -ulnp | grep ':546 ' | grep -v '^UNCONN.*\[::\]:546' || true)
if [[ -n "$PORT546_PROCS" ]]; then
    warn "Processes found on UDP port 546 (DHCPv6 client):"
    echo "$PORT546_PROCS"
    echo
    warn "systemd-networkd and standalone DHCPv6 clients conflict on this port."
    warn "This causes intermittent IPv6 drops. Disabling known DHCPv6 clients..."

    for svc in wide-dhcpv6-client dibbler-client isc-dhcp6-client kea-dhcp6-server; do
        if systemctl is-enabled "$svc" 2>/dev/null | grep -q enabled; then
            systemctl disable --now "$svc" 2>/dev/null || true
            log "  Disabled $svc"
        fi
    done
else
    log "No DHCPv6 port 546 conflicts detected."
fi

# ── Step 4: Enable IP forwarding ────────────────────────────────────────────
log "Enabling IPv4 and IPv6 forwarding..."

SYSCTL_CONF="/etc/sysctl.d/99-tuxwall-forwarding.conf"
cat > "$SYSCTL_CONF" << 'SYSCTL'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
SYSCTL
sysctl --system -q 2>/dev/null

log "IP forwarding enabled."

# ── Step 5: Install TuxWall ─────────────────────────────────────────────────
log "Downloading TuxWall package..."

if [[ ! -f "$TUXWALL_DEB" ]]; then
    curl -fsSL -o "$TUXWALL_DEB" "$TUXWALL_DEB_URL"
fi

log "Installing TuxWall..."
dpkg -i "$TUXWALL_DEB" 2>/dev/null || apt-get install -f -y -qq

log "TuxWall package installed."

# ── Step 6: Create directories ──────────────────────────────────────────────
log "Creating required directories..."

mkdir -p /etc/tuxwall
mkdir -p /var/lib/tuxwall
mkdir -p /var/lib/unbound
mkdir -p /var/log/suricata
mkdir -p /run/kea

# ── Step 7: Config files ────────────────────────────────────────────────────
log "Installing configuration files..."

# Copy config files if not already present
for f in llm.json.example custom-blocklist.txt ui.json; do
    src="$SCRIPT_DIR/config/$f"
    dst="/etc/tuxwall/$f"
    if [[ -f "$src" && ! -f "$dst" ]]; then
        cp "$src" "$dst"
        log "  Installed /etc/tuxwall/$f"
    elif [[ -f "$dst" ]]; then
        warn "  /etc/tuxwall/$f already exists, skipping."
    fi
done

# Create llm.json from example if missing
if [[ ! -f /etc/tuxwall/llm.json ]]; then
    cp /etc/tuxwall/llm.json.example /etc/tuxwall/llm.json
    log "  Created /etc/tuxwall/llm.json from example"
fi

# ── Step 8: Unbound local domains config ────────────────────────────────────
log "Configuring Unbound..."

UNBOUND_DOM="/etc/unbound/unbound.conf.d/98-local-domains.conf"
if [[ ! -f "$UNBOUND_DOM" ]]; then
    cat > "$UNBOUND_DOM" << 'UNBOUND'
# Managed by TuxWall installer - local domain resolution
server:
    local-zone: "localdomain." static
    local-data: "localhost. IN A 127.0.0.1"
    local-data: "localhost. IN AAAA ::1"
    local-data-ptr: "127.0.0.1 localhost."
    local-data-ptr: "::1 localhost."
UNBOUND
    log "  Created $UNBOUND_DOM"
fi

# Ensure unbound directories exist for blocklists
mkdir -p /var/lib/unbound
touch /var/lib/unbound/blocklist.conf
touch /var/lib/unbound/client-bans.conf

# ── Step 9: Nginx configuration ─────────────────────────────────────────────
log "Configuring Nginx..."

# Remove default site if present
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# Install tuxwall nginx config
cp "$SCRIPT_DIR/nginx/tuxwall.conf" /etc/nginx/sites-available/tuxwall
ln -sf /etc/nginx/sites-available/tuxwall /etc/nginx/sites-enabled/tuxwall

if nginx -t 2>/dev/null; then
    log "  Nginx config validated."
else
    warn "  Nginx config test failed — check /etc/nginx/sites-available/tuxwall"
fi

# ── Step 10: Systemd services ───────────────────────────────────────────────
log "Installing systemd service files..."

for unit in tuxwall.service tuxwall-blocklist-update.service tuxwall-blocklist-update.timer; do
    src="$SCRIPT_DIR/systemd/$unit"
    dst="/etc/systemd/system/$unit"
    if [[ -f "$src" ]]; then
        cp "$src" "$dst"
        log "  Installed $unit"
    fi
done

systemctl daemon-reload

# ── Step 11: SQM script ─────────────────────────────────────────────────────
log "Installing SQM script..."

cp "$SCRIPT_DIR/scripts/tuxwall-sqm.sh" /usr/local/sbin/tuxwall-sqm.sh
chmod +x /usr/local/sbin/tuxwall-sqm.sh

# Install SQM systemd service
cp "$SCRIPT_DIR/systemd/tuxwall-sqm.service" /etc/systemd/system/tuxwall-sqm.service
systemctl daemon-reload

warn "SQM is installed but NOT enabled. Edit /usr/local/sbin/tuxwall-sqm.sh first:"
warn "  - Set WAN to your WAN interface name"
warn "  - Set UP_RATE to ~95% of your upload speed"
warn "  - Set DOWN_RATE to ~92% of your download speed"
warn "Then run:  sudo systemctl enable --now tuxwall-sqm"

# ── Step 12: UFW rules ─────────────────────────────────────────────────────
log "Configuring UFW rules..."

if command -v ufw &>/dev/null; then
    # Allow HTTP for dashboard (if not behind VPN)
    ufw allow 80/tcp 2>/dev/null || true
    # Allow WireGuard
    ufw allow 51820/udp 2>/dev/null || true
    log "  UFW rules added (HTTP, WireGuard)"
fi

# ── Step 13: Fix hardcoded paths in api_server.py ───────────────────────────
log "Fixing hardcoded paths in api_server.py..."

API_SERVER="/var/www/html/includes/api_server.py"
if [[ -f "$API_SERVER" ]]; then
    # Fix BACKUP_DIR
    sed -i 's|^BACKUP_DIR = "/home/jeff/backups"|BACKUP_DIR = "/var/lib/tuxwall/backups"|' "$API_SERVER"
    # Fix SOURCE_DIR
    sed -i 's|^SOURCE_DIR = "/home/jeff/tuxwall-blocklist"|SOURCE_DIR = "/var/www/html"|' "$API_SERVER"
    log "  Fixed BACKUP_DIR and SOURCE_DIR paths"
fi

# Create backup directory
mkdir -p /var/lib/tuxwall/backups

# ── Step 14: Enable and start services ──────────────────────────────────────
log "Enabling and starting services..."

for svc in \
    kea-dhcp4-server \
    unbound \
    radvd \
    nginx \
    tuxwall \
    tuxwall-blocklist-update.timer; do
    systemctl enable --now "$svc" 2>/dev/null && log "  $svc started" || warn "  Failed to start $svc"
done

# Suricata and CrowdSec may need additional config
for svc in suricata crowdsec; do
    systemctl enable --now "$svc" 2>/dev/null && log "  $svc started" || warn "  $svc failed (may need manual config)"
done

# ── Step 15: Verify ─────────────────────────────────────────────────────────
echo
hr
echo -e "  ${B}${G}TuxWall Installation Complete!${NC}"
hr
echo

# Check port 53
UNBOUND_53=$(ss -ulnp | grep ':53 ' | grep -c 'unbound' || true)
if [[ "$UNBOUND_53" -gt 0 ]]; then
    echo -e "  ${G}✓${NC} Unbound listening on port 53"
else
    echo -e "  ${Y}?${NC} Unbound port 53 status unknown — check: ss -ulnp | grep ':53 '"
fi

# Check tuxwall service
if systemctl is-active --quiet tuxwall 2>/dev/null; then
    echo -e "  ${G}✓${NC} TuxWall API running on http://127.0.0.1:8008"
else
    echo -e "  ${R}✗${NC} TuxWall API not running — check: journalctl -u tuxwall -n 20"
fi

# Check nginx
if systemctl is-active --quiet nginx 2>/dev/null; then
    echo -e "  ${G}✓${NC} Nginx running on port 80"
else
    echo -e "  ${R}✗${NC} Nginx not running — check: systemctl status nginx"
fi

# Check resolved
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo -e "  ${R}✗${NC} systemd-resolved is still running (may conflict!)"
else
    echo -e "  ${G}✓${NC} systemd-resolved disabled"
fi

echo
echo -e "  ${B}Dashboard:${NC} http://$(hostname -I | awk '{print $1}')/"
echo
echo -e "  ${DIM}Next steps:${NC}"
echo -e "  ${DIM}  1. Configure Kea DHCP:  sudo nano /etc/kea/kea-dhcp4.conf${NC}"
echo -e "  ${DIM}  2. Configure Unbound:   sudo nano /etc/unbound/unbound.conf${NC}"
echo -e "  ${DIM}  3. Configure radvd:     sudo nano /etc/radvd.conf${NC}"
echo -e "  ${DIM}  4. (Optional) Setup GeoIP:  sudo bash /var/www/html/scripts/geoip-setup.sh${NC}"
echo -e "  ${DIM}  5. (Optional) Edit SQM:     sudo nano /usr/local/sbin/tuxwall-sqm.sh${NC}"
echo
