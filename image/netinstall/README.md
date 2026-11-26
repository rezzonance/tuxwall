# TuxWall netinstall ISO

A small (~130 MB) USB/CD image that installs **stock Ubuntu 26.04 LTS server**
with Ubuntu's own installer (subiquity), then sets TuxWall up on the first boot.
No custom distribution: the boot chain is Ubuntu's signed shim, signed GRUB,
signed kernel and casper initrd, taken unchanged from the official
live-server ISO; TuxWall comes from its signed APT repository.

## How it works

1. **Boot** (BIOS or UEFI, Secure Boot on or off). GRUB menu:
   - *Install TuxWall (downloads Ubuntu …)* - casper downloads the pinned
     `ubuntu-26.04.1-live-server-amd64.iso` from releases.ubuntu.com over HTTPS
     (`iso-url=`) **into RAM**. Needs DHCP internet on one port and **6 GB+ RAM**
     (the 2.9 GB ISO stays in RAM during the install).
   - *Ubuntu ISO written to a second USB stick (low RAM)* - the same ISO written
     (dd/Rufus/Etcher) to another stick; casper's own device scan finds it (no
     `iso-url=`/`iso-scan`), normal installer RAM. When casper mounts the
     stick's ISO9660 partition, `verify-ubuntu-iso.sh` hashes the whole disk.
   - *Ubuntu ISO file on another USB stick / disk (low RAM)* - copy the same ISO
     file to the root of any other stick/partition (FAT32, exFAT, ext4); casper
     finds it (`iso-scan/filename=`) and the install needs no more RAM than a
     normal Ubuntu server install (~2 GB+; tested with 4 GB).
   - *Help* - prints which entry to use (RAM, "No space left on device" +
     BusyBox prompt = too little RAM for the download entry); Esc returns.
   - *download from old-releases.ubuntu.com* - when Ubuntu has published a newer
     point release, the pinned one moves there.
   - Serial-console variants (ttyS0, 115200 baud) for headless boxes.
2. **Verify**: before anything is installed the autoinstall early-commands check
   the TuxWall payload (SHA256SUMS whose hash is in the seed) and the Ubuntu ISO
   the installer runs from against the SHA-256 pinned in `ubuntu-release.env`
   (casper itself only checks HTTPS - busybox wget verifies the certificate via
   `openssl s_client -verify_return_error -verify_hostname` - and the ISO's casper UUID).
3. **Install Ubuntu** (interactive): language, keyboard, **disk** (Ubuntu's guided
   storage screen shows every disk with its size/model; the stick itself is hidden
   because the seed is mounted; nothing is written before the installer's
   *Confirm destructive action* dialog), **account** (user + password) and
   **SSH** (OpenSSH on, optional key import). Minimal server + whiptail/curl/gnupg.
4. **late-commands** (`image/common/install-firstboot.sh`): TuxWall APT repo +
   keyring (fingerprint `5D79B9082DCAEB9CCB731382F5D8235716BDBDD1`, checked at build
   time), `tuxwall-setup`, `tuxwall-install.sh`, the first-boot units, the
   `/etc/tuxwall/setup-pending` flag. TuxWall itself and its network config are
   *not* installed yet.
5. **First boot**: `tuxwall-setup` waits on tty1 (and the serial console when the
   installer used one) - press Enter: pick the WAN port (or *Detect*: plug the
   modem cable in), DHCP / static / keep, the LAN port and network (192.168.1.1/24
   unless that collides with the WAN), optionally the dashboard admin, review,
   then it runs `tuxwall-install.sh --source apt --role gateway --wan … --lan …
   --wan-mode … --subnet … -y` and shows the dashboard URL, the router CA's
   SHA-256 fingerprint and how to log in (also kept on the console login
   screen: `/etc/issue.d/zz-tuxwall.issue`). Re-run any time: `sudo tuxwall-setup`.
   Unattended: an answers file at `/etc/tuxwall/setup-answers` is run by the
   first-boot units without asking (see the main README, "Run as a VM").

## Build

```sh
image/netinstall/build.sh [--out DIR] [--cache DIR]
# -> out/tuxwall-netinstall-<version>-amd64.iso + .sha256 + .build.log
```

Unprivileged; needs `curl gpg gpgv xorriso python3` and `ubuntu-keyring`.
Downloads (cached) and verifies Ubuntu's `SHA256SUMS` (+ `.gpg`, signer
fingerprint pinned) and the 2.9 GB live-server ISO, then rebuilds the ISO with
`xorriso -boot_image any replay` (Ubuntu's El Torito + EFI partition layout kept,
live system and package pool dropped, volume label `CIDATA` for cloud-init's
NoCloud seed). Reproducible: the same commit gives the same ISO
(`SOURCE_DATE_EPOCH` = commit time).

Bumping Ubuntu: update every value in `ubuntu-release.env` together (the kernel
and initrd must come from the ISO the installer downloads).

## Test (QEMU, user-mode networking only)

```sh
image/netinstall/build.sh --test                 # *-TEST.iso: unattended seed, never publish it
image/netinstall/test/run-qemu-test.sh --iso out/…-TEST.iso --ubuntu-iso <cached ubuntu ISO> --mode uefi|bios
```

Phase 1 installs onto a blank 20 GB disk (Secure Boot OVMF with Microsoft keys
in UEFI mode, SeaBIOS otherwise; Ubuntu ISO file on a second FAT disk), phase 2
boots it: `tuxwall-setup --answers` (test/setup-answers.test) installs TuxWall,
`test/test-report.sh` prints PASS/FAIL checks on the serial console.
`tools/netinstall_check.py` is the static check run by CI.
