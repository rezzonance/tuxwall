# TuxWall VM image

`tuxwall-vm-<version>-amd64.qcow2`: the official **Ubuntu 26.04 LTS cloud
image**, signature-verified and unchanged, plus the TuxWall first-boot payload
- the same files the netinstall ISO puts on a fresh install
(`image/common/install-firstboot.sh`): `tuxwall-setup` + its first-boot units
(tty1 and ttyS0 - the cloud image boots with `console=tty1 console=ttyS0`),
`tuxwall-install.sh`, the signed TuxWall APT source and the
`/etc/tuxwall/setup-pending` flag, plus `/etc/tuxwall/vm-image` (which Ubuntu
image it came from).

**Design: TuxWall is installed at first boot, not pre-installed.** The image
stays the size of Ubuntu's (~820 MB), nothing in it ages between releases
except Ubuntu itself, and the install path is the one the netinstaller and
`tuxwall-install.sh` users run (signed APT repository, current release). The
cost is a few minutes and internet access at first boot - which the gateway
needs anyway.

Usage (Proxmox, libvirt, cloud-init, headless answers): main README,
"Run as a VM".

Only a qcow2 is published (a raw.xz of the 16 GiB disk would cost minutes of
xz per release for no gain); for a raw disk: `qemu-img convert -O raw
tuxwall-vm-<version>-amd64.qcow2 tuxwall-vm.raw`.

## Build

```sh
image/vm/build.sh [--out DIR] [--cache DIR] [--latest] [--qemu-img PATH]
# -> out/tuxwall-vm-<version>-amd64.qcow2 + .sha256 + .build.log
```

Unprivileged, starts no VM (no chroot, no mount, no virt-customize): needs
`curl gpg gpgv qemu-img (qemu-utils) debugfs e2fsck (e2fsprogs) sfdisk python3`
and `ubuntu-cloudimage-keyring`.

1. `SHA256SUMS` + `.gpg` of the pinned release directory
   (`ubuntu-cloud.env`), signature by the "UEC Image Automatic Signing Key"
   (fingerprint pinned); the image's hash must match it (and the pin, unless
   `--latest`).
2. `install-firstboot.sh --origin vm-image --console ttyS0` into a staging
   directory.
3. `qemu-img convert` to raw, grown to `VM_DISK_SIZE` (16G, sparse; backup
   GPT moved to the end; cloud-init grows the root file system at first
   boot), the staging tree written into the `cloudimg-rootfs` ext4 with
   `debugfs -w` (`file?offset=`), every file read back and compared,
   `e2fsck -fn`.
4. `qemu-img convert -c` to qcow2, `qemu-img check`, `qemu-img compare`
   against the raw disk, the 2 GiB release-asset limit.

Ubuntu removes dated cloud image directories after a few months: release
builds (`.github/workflows/apt.yml`, job "images") use `--latest` (newest
release directory, same signature check; serial + SHA-256 in the build log
and in `/etc/tuxwall/vm-image`). Bump `UBUNTU_CLOUD_SERIAL` +
`UBUNTU_CLOUD_SHA256` together for local, reproducible builds.

## Test (Proxmox lab)

`test/make-test-seed.sh --out DIR [--ssh-key FILE.pub]` makes a NoCloud seed
ISO (TEST ONLY): a test user, the QEMU guest agent, the netinstall test
answers (`image/netinstall/test/setup-answers.test`) as
`/etc/tuxwall/setup-answers`, the LAN isolation gate (run by cloud-init's
runcmd before the wizard may start; a drop-in makes the wizard refuse to run
without its marker) and the netinstall test report (`test-report.sh`, with
VM checks: cloud-init done, root file system grown, password file removed).
Attach it as a CD next to the imported qcow2; MACs as in the answers file
(WAN `52:54:00:12:34:01`, LAN `...:02`).
