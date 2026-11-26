#!/bin/sh
# install-firstboot.sh [options] ROOT
#
# Prepares a freshly installed Ubuntu root file system (the netinstaller's
# /target, or a VM image mounted somewhere) for the TuxWall first-boot
# wizard. Shared by the netinstall ISO (autoinstall late-commands) and the VM
# images. POSIX sh: runs in Ubuntu's live installer as well as on a build host.
#
#   --payload DIR            directory with tuxwall-setup, tuxwall-setup@.service,
#                            tuxwall-install.sh, apt-public.asc,
#                            tuxwall-archive-keyring.gpg (default: this script's dir)
#   --origin NAME            recorded in /etc/tuxwall/setup-pending (netinstall, vm-image)
#   --console TTY            run the wizard on this console too (repeatable; tty1 always)
#   --consoles-from-cmdline  add the serial consoles of /proc/cmdline (console=ttyS0,...)
#   --answers FILE           TESTS ONLY: run the wizard unattended with this answers file
#
# What it does to ROOT (nothing else, no services started):
#   /usr/local/sbin/tuxwall-setup, /usr/local/share/tuxwall/tuxwall-install.sh
#   (+ apt-public.asc next to it), /etc/systemd/system/tuxwall-setup@.service
#   enabled for tty1 (+ serial consoles), /usr/share/keyrings/tuxwall.gpg +
#   /etc/apt/sources.list.d/tuxwall.list, /etc/tuxwall/setup-pending and a
#   login hint in /etc/profile.d. TuxWall itself is installed by the wizard.
set -eu

payload="$(dirname "$0")"
origin=unknown
consoles="tty1"
answers=""
from_cmdline=0
while [ $# -gt 1 ]; do
    case "$1" in
        --payload) payload=$2; shift 2 ;;
        --origin) origin=$2; shift 2 ;;
        --console) consoles="$consoles $2"; shift 2 ;;
        --consoles-from-cmdline) from_cmdline=1; shift ;;
        --answers) answers=$2; shift 2 ;;
        *) echo "install-firstboot.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ $# -eq 1 ] || { echo "usage: install-firstboot.sh [options] ROOT" >&2; exit 2; }
root=${1%/}
[ -d "$root/etc" ] || { echo "install-firstboot.sh: $root does not look like a root file system" >&2; exit 1; }

if [ "$from_cmdline" = 1 ] && [ -r /proc/cmdline ]; then
    for c in $(tr ' ' '\n' </proc/cmdline | sed -n 's/^console=\(ttyS[0-9]*\|ttyAMA[0-9]*\|hvc[0-9]*\).*/\1/p'); do
        consoles="$consoles $c"
    done
fi

for f in tuxwall-setup tuxwall-setup@.service tuxwall-install.sh apt-public.asc tuxwall-archive-keyring.gpg; do
    [ -s "$payload/$f" ] || { echo "install-firstboot.sh: missing $payload/$f" >&2; exit 1; }
done

install -D -m 0755 "$payload/tuxwall-setup" "$root/usr/local/sbin/tuxwall-setup"
install -D -m 0755 "$payload/tuxwall-install.sh" "$root/usr/local/share/tuxwall/tuxwall-install.sh"
install -D -m 0644 "$payload/apt-public.asc" "$root/usr/local/share/tuxwall/apt-public.asc"
install -D -m 0644 "$payload/tuxwall-setup@.service" "$root/etc/systemd/system/tuxwall-setup@.service"

# Signed TuxWall APT repository (same entry as tuxwall-install.sh writes).
install -D -m 0644 "$payload/tuxwall-archive-keyring.gpg" "$root/usr/share/keyrings/tuxwall.gpg"
mkdir -p "$root/etc/apt/sources.list.d"
echo "deb [signed-by=/usr/share/keyrings/tuxwall.gpg] https://rezzonance.github.io/tuxwall stable main" \
    >"$root/etc/apt/sources.list.d/tuxwall.list"
chmod 0644 "$root/etc/apt/sources.list.d/tuxwall.list"

# First-boot units: one per console; the first console where Enter is
# pressed runs the wizard, the others give way (lock in tuxwall-setup).
wants="$root/etc/systemd/system/multi-user.target.wants"
mkdir -p "$wants"
seen=" "
for c in $consoles; do
    case "$seen" in *" $c "*) continue ;; esac
    seen="$seen$c "
    ln -sf /etc/systemd/system/tuxwall-setup@.service "$wants/tuxwall-setup@$c.service"
done

if [ -n "$answers" ]; then
    # Tests only: the wizard runs unattended on the first console.
    install -D -m 0600 "$answers" "$root/etc/tuxwall/setup-answers"
    mkdir -p "$root/etc/systemd/system/tuxwall-setup@.service.d"
    printf '[Service]\nExecStart=\nExecStart=/usr/local/sbin/tuxwall-setup --answers /etc/tuxwall/setup-answers\n' \
        >"$root/etc/systemd/system/tuxwall-setup@.service.d/50-test-answers.conf"
fi

mkdir -p "$root/etc/tuxwall"
printf 'origin=%s\ncreated=%s\n' "$origin" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$root/etc/tuxwall/setup-pending"

mkdir -p "$root/etc/profile.d"
cat >"$root/etc/profile.d/zz-tuxwall-setup-hint.sh" <<'HINT'
# TuxWall: shown until the first-boot setup has run (removed by tuxwall-setup).
if [ -f /etc/tuxwall/setup-pending ] && [ -n "${PS1:-}" ]; then
    printf '\n  TuxWall is not set up yet: run  sudo tuxwall-setup\n\n'
fi
HINT
chmod 0644 "$root/etc/profile.d/zz-tuxwall-setup-hint.sh"

echo "install-firstboot.sh: TuxWall first-boot setup prepared in $root (consoles:$seen)"
