#!/usr/bin/env bash
###############################################################################
#  TuxWall first-boot wizard entry point (run from the root autologin on tty1
#  or the serial console). Called via /root/.bash_profile.
#
#  Architecture: the appliance autologins to root on FIRST boot only, so the
#  interactive WAN/LAN wizard runs in a real login session (reliable prompts -
#  no systemd oneshot / tty grabs). When the wizard completes it removes the
#  autologin override, so later boots show a NORMAL login prompt.
#
#  Only the tty that matches the boot console (detected from /proc/cmdline)
#  actually runs the wizard; other ttys just show a shell, preventing a
#  local+serial double-run on a single boot.
###############################################################################
set -euo pipefail

WIZARD="/opt/tuxwall-appliance/tuxwall-firstboot.sh"
MARK="/etc/tuxwall/.appliance-configured"
DROPIN_DIR="/etc/systemd/system/getty@tty1.service.d"
DROPIN_TTY1="$DROPIN_DIR/tuxwall-firstboot.conf"
DROPIN_SERIAL="/etc/systemd/system/getty@ttyS0.service.d/tuxwall-firstboot.conf"

CMDLINE="$(cat /proc/cmdline 2>/dev/null || true)"
BOOT_SERIAL=0
[[ "$CMDLINE" =~ console=(ttyS[0-9]+) ]] && BOOT_SERIAL=1

# What tty is this session on? (The first argument, or from tty.)
TTY_NAME="${1:-}"
if [[ -z "$TTY_NAME" ]]; then
    tty_path="$(tty 2>/dev/null || true)"
    TTY_NAME="${tty_path#/dev/}"
fi

# Decide if THIS tty is the one the system booted its console on.
ACTIVE=0
if [[ "$BOOT_SERIAL" -eq 1 && "$TTY_NAME" == ttyS* ]]; then
    ACTIVE=1
elif [[ "$BOOT_SERIAL" -eq 0 && "$TTY_NAME" == tty1 ]]; then
    ACTIVE=1
fi

# Not the active console (e.g. a second tty) - just present a normal shell.
if [[ "$ACTIVE" -eq 0 ]]; then
    echo "TuxWall first-boot is handled on the boot console (tty1/ttyS0)."
    return 0 2>/dev/null || exit 0
fi

# ── Already configured? Disable autologin and fall to normal login. ────────
if [[ -f "$MARK" ]]; then
    echo
    echo "==============================================================="
    echo "  TuxWall is already configured."
    echo "  First-boot autologin is disabled - a normal login will be used."
    echo "==============================================================="
    rm -f "$DROPIN_TTY1" "$DROPIN_SERIAL" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    exit 0
fi

echo
echo "Welcome to the TuxWall gateway first-time setup."
echo "Choose your WAN and LAN interfaces and confirm a few settings. Once only."
echo

# Run the wizard. On success, disable autologin for future boots.
if "$WIZARD"; then
    echo
    echo "TuxWall configuration complete."
    echo "Disabling first-boot autologin - a normal login will be used henceforth."
    rm -f "$DROPIN_TTY1" "$DROPIN_SERIAL" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    echo "Reboot to apply networking and start services."
    exit 0
else
    echo
    echo "Wizard did not complete cleanly - it will run again on the next boot."
    echo "Review the output above for what failed."
    exit 1
fi
