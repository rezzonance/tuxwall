#!/usr/bin/env bash
###############################################################################
#  TuxWall Appliance - Stage / Prepare
#  -------------------------------------------------------------
#  Populates /opt/tuxwall-appliance on the target gateway with:
#    - tuxwall-firstboot.sh        (the first-boot wizard)
#    - firstboot-autologin.sh      (autologin entry point that runs the wizard)
#    - getty-*.conf / bash-profile (first-boot autologin mechanism)
#    - tuxwall.deb                 (the tuxwall package)
#    - repo/                       (nginx, systemd, config, scripts)
#
#  Then installs the autologin mechanism so the wizard runs at first login.
#
#  Used two ways:
#    1. On a running machine:  sudo bash stage.sh
#    2. Inside an ISO/chroot build: the same thing at image-build time
#       (so the wizard fires automatically on the customer's first boot).
#
#  Usage:
#    bash stage.sh [--deb /path/to/tuxwall.deb] [--repo /path/to/github-tuxwall]
###############################################################################
set -euo pipefail

APP="${TUXWALL_APP_DIR:-/opt/tuxwall-appliance}"
DEB_SRC=""
REPO_SRC=""

# Locate defaults relative to this project if not given
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deb)  DEB_SRC="$2"; shift 2 ;;
        --repo) REPO_SRC="$2"; shift 2 ;;
        *)      echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Defaults based on known layout
[[ -z "$DEB_SRC"  && -f "$PROJECT_DIR/stage/tuxwall.deb" ]]  && DEB_SRC="$PROJECT_DIR/stage/tuxwall.deb"
# In the standalone GitHub layout the .deb sits at the repo root alongside
# install.sh (e.g. tuxwall_2.2.1_all.deb).
[[ -z "$DEB_SRC" && -f "$SCRIPT_DIR/install.sh" ]] && DEB_SRC="$(find "$SCRIPT_DIR" -maxdepth 1 -name 'tuxwall*.deb' | head -n1)"
[[ -z "$REPO_SRC" && -f "$SCRIPT_DIR/install.sh" ]] && REPO_SRC="$SCRIPT_DIR"

echo "[+] TuxWall appliance staging"
echo "    target: $APP"

# ── Create the runtime directory ────────────────────────────────────────────
install -d -m 755 "$APP"

# ── First-boot wizard script ────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/firstboot/tuxwall-firstboot.sh" ]]; then
    install -m 755 "$SCRIPT_DIR/firstboot/tuxwall-firstboot.sh" "$APP/tuxwall-firstboot.sh"
    echo "[+] wizard script -> $APP/tuxwall-firstboot.sh"
else
    echo "[-] wizard script not found at $SCRIPT_DIR/firstboot/tuxwall-firstboot.sh" >&2
fi

# ── Autologin first-boot mechanism ─────────────────────────────────────────
# The first-boot wizard now runs in a REAL login session on first boot
# (autologin to root on the boot console), then disables autologin so later
# boots show a normal login. This removes the fragile systemd-oneshot-on-tty
# approach that caused SIGHUP.
FIRSTBOOT_ENTRY=""
if [[ -f "$SCRIPT_DIR/firstboot/firstboot-autologin.sh" ]]; then
    install -m 755 "$SCRIPT_DIR/firstboot/firstboot-autologin.sh" "$APP/firstboot-autologin.sh"
    FIRSTBOOT_ENTRY="$APP/firstboot-autologin.sh"
    echo "[+] first-boot entry -> $APP/firstboot-autologin.sh"
fi

# Getty autologin drop-ins (tty1 local + ttyS0 serial) and the root shell hook.
for d in getty-tty1-autologin.conf getty-ttyS0-autologin.conf root-bash-profile; do
    if [[ -f "$SCRIPT_DIR/firstboot/$d" ]]; then
        install -m 644 "$SCRIPT_DIR/firstboot/$d" "$APP/$d"
        echo "[+] autologin file -> $APP/$d"
    fi
done

# Serial console helper (configures the OS for headless serial boots).
if [[ -f "$SCRIPT_DIR/firstboot/serial-console.sh" ]]; then
    install -m 755 "$SCRIPT_DIR/firstboot/serial-console.sh" "$APP/serial-console.sh"
    echo "[+] helper -> $APP/serial-console.sh"
fi

# ── TuxWall package ─────────────────────────────────────────────────────────
if [[ -n "$DEB_SRC" && -f "$DEB_SRC" ]]; then
    install -m 644 "$DEB_SRC" "$APP/tuxwall.deb"
    echo "[+] deb -> $APP/tuxwall.deb ($(du -h "$APP/tuxwall.deb" | cut -f1))"
else
    echo "[!] no tuxwall .deb to stage (use --deb)"
fi

# ── Repo configs (nginx, systemd, config, scripts) ─────────────────────────
if [[ -n "$REPO_SRC" && -d "$REPO_SRC" ]]; then
    install -d -m 755 "$APP/repo"
    for d in nginx systemd config scripts; do
        if [[ -d "$REPO_SRC/$d" ]]; then
            cp -r "$REPO_SRC/$d" "$APP/repo/"
            echo "[+] repo/$d -> $APP/repo/$d"
        fi
    done
else
    echo "[!] no repo source to stage (use --repo)"
fi

# ── Install autologin mechanism on a live target (root) ─────────────────────
# On a running machine run with sudo, actually install the autologin drop-ins
# and root shell hook so the wizard fires on the next login. This is the
# delivery path used by install-appliance.sh (stock-Ubuntu path).
if [[ $EUID -eq 0 && -f "$APP/firstboot-autologin.sh" ]]; then
    install -d -m 755 /etc/systemd/system/getty@tty1.service.d \
                     /etc/systemd/system/getty@ttyS0.service.d
    if [[ -f "$APP/getty-tty1-autologin.conf" ]]; then
        install -m 644 "$APP/getty-tty1-autologin.conf" \
            /etc/systemd/system/getty@tty1.service.d/tuxwall-firstboot.conf
    fi
    if [[ -f "$APP/getty-ttyS0-autologin.conf" ]]; then
        install -m 644 "$APP/getty-ttyS0-autologin.conf" \
            /etc/systemd/system/getty@ttyS0.service.d/tuxwall-firstboot.conf
    fi
    if [[ -f "$APP/root-bash-profile" ]]; then
        install -m 644 "$APP/root-bash-profile" /root/.bash_profile
    fi
    systemctl daemon-reload
    echo "[+] installed autologin mechanism (wizard will run on next boot)"
else
    echo "[!] not root - skipped installing autologin (run stage.sh with sudo on target)"
fi

echo
echo "[+] Staging complete."
echo "    On next boot the wizard will prompt to select WAN/LAN."
