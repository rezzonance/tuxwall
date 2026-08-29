#!/usr/bin/env bash
###############################################################################
#  Serial console setup for headless TuxWall gateways.
#  Run manually on a stock installed box when its console is HEADLESS/SERIAL
#  (e.g. serial-over-LAN / IPMI):
#      sudo /opt/tuxwall-appliance/serial-console.sh
#
#  It reads /proc/cmdline and only configures the installed system's serial
#  console when a serial console= is present on the boot command line (a
#  headless install). On a local/tty1 boot it does nothing and leaves the box
#  on the physical console. The wizard itself auto-selects tty1 vs ttyS0, so
#  this just makes the OS usable over serial after the fact.
###############################################################################
set -euo pipefail

CMDLINE="$(cat /proc/cmdline 2>/dev/null || true)"

# Find a console= argument. Prefer ttyS* (serial).
SERIAL_TTY=""
if [[ "$CMDLINE" =~ console=(ttyS[0-9]+),([0-9]+) ]]; then
    SERIAL_TTY="${BASH_REMATCH[1]}"
    BAUD="${BASH_REMATCH[2]}"
fi

if [[ -z "$SERIAL_TTY" ]]; then
    # GUI/local-console boot - nothing to do.
    echo "serial-console.sh: no serial console on cmdline - leaving tty1" >&2
    exit 0
fi

echo "serial-console.sh: configuring serial console $SERIAL_TTY @ $BAUD"

# ── GRUB: put console= on both the default and the linux cmdline ──────────
sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"console=$SERIAL_TTY,${BAUD}n8\"|" /etc/default/grub
sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"console=$SERIAL_TTY,${BAUD}n8\"|" /etc/default/grub
sed -i "s|^#GRUB_TERMINAL=.*|GRUB_TERMINAL=serial|" /etc/default/grub
if ! grep -q '^GRUB_SERIAL_COMMAND' /etc/default/grub; then
    printf 'GRUB_SERIAL_COMMAND="serial --speed=%s --unit=0 --word=8 --parity=no --stop=1"\n' "$BAUD" >> /etc/default/grub
fi
update-grub

# ── Enable a login getty on the serial port ────────────────────────────────
systemctl enable "serial-getty@$SERIAL_TTY.service" 2>/dev/null || true

exit 0
