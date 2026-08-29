#!/usr/bin/env bash
###############################################################################
#  TuxWall Appliance - Installer (stock Ubuntu path)
#  ---------------------------------------------------------------------------
#  Run this ONCE on a freshly-installed stock Ubuntu (server) machine to turn
#  it into a TuxWall gateway. It:
#    1. Installs the appliance runtime to /opt/tuxwall-appliance.
#    2. Installs the first-boot AUTOLOGIN mechanism so the WAN/LAN wizard runs
#       interactively on your next login (ttyst alone - no custom ISO needed).
#    3. Applies optional multipathd hardening (guarded, best-effort).
#
#  Usage:
#    sudo bash install-appliance.sh [--deb /path/to/tuxwall.deb]
#
#  After it finishes: log out (or reboot). On the next login you'll be dropped
#  into the one-time WAN/LAN setup wizard, then a normal login is restored.
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root: sudo bash $0"
    exit 1
fi

# ── 1. Stage the appliance payload + autologin mechanism ────────────────────
echo
echo "[+] Installing TuxWall appliance payload + first-boot autologin..."
bash "$SCRIPT_DIR/stage.sh" "$@"

# ── 2. Multipathd hardening (guarded, best-effort) ──────────────────────────
# On some Ubuntu installs the kernel can bind to the isolated device-mapper
# multipath module even when no SAN is present, causing a FATAL
# "bad settings in read-only bindings file" at first boot (LP#2120444).
# Harmless to apply when the issue isn't present; guarded against missing tools.
echo
echo "[+] Applying optional multipathd hardening (best-effort)..."
if command -v multipathd >/dev/null 2>&1; then
    mkdir -p /etc/multipath
    printf 'defaults {\n    user_friendly_names no\n}\n' > /etc/multipath.conf 2>/dev/null || true
    touch /etc/multipath/bindings 2>/dev/null || true
    printf 'blacklist dm_multipath\n' > /etc/modprobe.d/blacklist-multipath.conf 2>/dev/null || true
    systemctl disable --now multipathd.service 2>/dev/null || true
    echo "[+] multipathd configured to NOT manage the gateway disk."
else
    echo "[-] multipathd not present - nothing to harden."
fi

# ── 3. Next steps ───────────────────────────────────────────────────────────
echo
echo "==============================================================="
echo "  TuxWall appliance installed successfully."
echo
echo "  Next: log out (or reboot). On the next login the first-boot"
echo "  WAN/LAN wizard will run once, then normal login is restored."
echo "==============================================================="
