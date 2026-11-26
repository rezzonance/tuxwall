#!/bin/sh
# verify-ubuntu-iso.sh SHA256 SIZE - run by the netinstall autoinstall
# early-commands inside Ubuntu's live installer. Checks the Ubuntu
# live-server ISO the installer is running from (downloaded by casper with
# iso-url=, or found with iso-scan/filename=) against the SHA-256 pinned at
# build time. casper itself only checks HTTPS + the ISO's casper UUID.
set -eu
want=$1
size=$2
src="$(findmnt -n -o SOURCE /cdrom 2>/dev/null || true)"
if [ -z "$src" ] || [ ! -b "$src" ]; then
    echo "TuxWall: cannot find the device behind /cdrom (got '${src:-nothing}')" >&2
    exit 1
fi
# The loop device of a downloaded ISO is backed by a file (deleted from the
# initramfs after switch_root, still readable through the loop device). Only
# the ISO's own length is hashed: a CD drive or a USB stick the ISO was
# written to can be larger.
got="$(head -c "$size" "$src" | sha256sum | cut -d' ' -f1)"
if [ "$got" != "$want" ]; then
    msg="TuxWall: the Ubuntu ISO behind /cdrom ($src) has SHA-256 $got, expected $want. Install stopped."
    echo "$msg" >&2
    echo "$msg" >/dev/console 2>/dev/null || true
    exit 1
fi
echo "TuxWall: Ubuntu ISO SHA-256 verified ($src)"
