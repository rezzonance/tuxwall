#!/usr/bin/env python3
"""Netinstall ISO + first-boot wizard static checks (no ISO build, no root).

    python3 tools/netinstall_check.py

- autoinstall seed: valid YAML, storage + identity interactive, no default
  disk layout / password in the shipped seed, Ubuntu ISO pinned and verified
  in early-commands, payload installed in late-commands without test answers
- GRUB menu: no 'autoinstall' (no confirmation-less wipe), every iso-url is
  the pinned https URL, cloud-init seed restricted to NoCloud
- pins: https URLs, fingerprints = tuxwall-install.sh + apt-public.asc
- image/common/install-firstboot.sh run against a temp root (fake payload)
- tuxwall-setup: NIC table and installer command lines built from fixture
  /sys/class/net trees and answers files (subnet maths from the real
  tuxwall-install.sh), refusals, every flag exists in tuxwall-install.sh
- unit not enabled by the package, shipped as a conffile; no secrets or
  owner data in image/; bash -n (+ shellcheck when installed)
- VM image (image/vm): pinned cloud image + signer, build.sh writes only the
  shared first-boot payload (no answers, no test seed), 2 GiB limit, checks;
  wizard: answers file picked up on the console units, login-screen summary,
  cloud-init netplan pinned to the current port names
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NI = os.path.join(ROOT, "image", "netinstall")
WIZ = os.path.join(ROOT, "pkg", "usr", "local", "sbin", "tuxwall-setup")
UNIT = os.path.join(ROOT, "pkg", "etc", "systemd", "system", "tuxwall-setup@.service")
FIRSTBOOT = os.path.join(ROOT, "image", "common", "install-firstboot.sh")
INSTALLER = os.path.join(ROOT, "tuxwall-install.sh")
VM = os.path.join(ROOT, "image", "vm")
SHELL_SCRIPTS = (WIZ, FIRSTBOOT, os.path.join(NI, "build.sh"), os.path.join(NI, "verify-ubuntu-iso.sh"),
                 os.path.join(NI, "test", "run-qemu-test.sh"), os.path.join(NI, "test", "test-report.sh"),
                 os.path.join(NI, "test", "lan-gate.sh"), os.path.join(VM, "build.sh"),
                 os.path.join(VM, "test", "make-test-seed.sh"), os.path.join(ROOT, "image", "verify-images.sh"))

PASS = FAIL = 0


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def read(p):
    with open(p) as f:
        return f.read()


def pins():
    out = {}
    for line in read(os.path.join(NI, "ubuntu-release.env")).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Z0-9_]+)=([A-Za-z0-9._:/+-]+)$", line)
        check(m is not None, "ubuntu-release.env line parses: " + line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def render(text, p):
    subs = {
        "@TUXWALL_VERSION@": "0.0.0", "@UBUNTU_VERSION@": p["UBUNTU_VERSION"], "@UBUNTU_ISO@": p["UBUNTU_ISO"],
        "@UBUNTU_ISO_SHA256@": p["UBUNTU_ISO_SHA256"], "@UBUNTU_ISO_SIZE@": p["UBUNTU_ISO_SIZE"],
        "@ISO_URL@": p["UBUNTU_BASE_URL"] + "/" + p["UBUNTU_ISO"],
        "@ISO_URL_OLD@": p["UBUNTU_OLD_BASE_URL"] + "/" + p["UBUNTU_ISO"],
        "@PAYLOAD_SHA256@": "0" * 64, "@TUXWALL_APT_KEY_FPR@": p["TUXWALL_APT_KEY_FPR"],
    }
    for k, v in subs.items():
        text = text.replace(k, v)
    check(not re.findall(r"@[A-Z0-9_]+@", text), "every placeholder is known to the checker")
    # same placeholder set as build.sh renders
    build = read(os.path.join(NI, "build.sh"))
    for k in subs:
        check('"%s"' % k in build, "build.sh renders " + k)
    return text


def load_yaml(text, name):
    try:
        import yaml
    except ImportError:
        print("note: PyYAML not installed, YAML structure checks skipped for", name)
        return None
    d = yaml.safe_load(text)
    check(isinstance(d, dict) and isinstance(d.get("autoinstall"), dict), name + ": has an autoinstall mapping")
    return d


def check_pins(p):
    for k in ("UBUNTU_VERSION", "UBUNTU_ISO", "UBUNTU_BASE_URL", "UBUNTU_OLD_BASE_URL", "UBUNTU_ISO_SHA256",
              "UBUNTU_ISO_SIZE", "UBUNTU_CASPER_UUID", "UBUNTU_CDIMAGE_KEY_FPR", "TUXWALL_APT_KEY_FPR"):
        check(k in p, "pin present: " + k)
    check(p["UBUNTU_BASE_URL"].startswith("https://releases.ubuntu.com/"), "ISO from releases.ubuntu.com over https")
    check(p["UBUNTU_OLD_BASE_URL"].startswith("https://old-releases.ubuntu.com/"), "fallback old-releases over https")
    check(p["UBUNTU_VERSION"] in p["UBUNTU_ISO"] and p["UBUNTU_ISO"].endswith("-live-server-amd64.iso"),
          "ISO name matches the version")
    check(p["UBUNTU_BASE_URL"].endswith("/" + p["UBUNTU_VERSION"]) and p["UBUNTU_OLD_BASE_URL"].endswith("/" + p["UBUNTU_VERSION"]),
          "URLs are point-release specific (kernel/initrd must match the ISO)")
    check(re.fullmatch(r"[0-9a-f]{64}", p["UBUNTU_ISO_SHA256"]) is not None, "ISO SHA-256 pinned")
    check(p["UBUNTU_ISO_SIZE"].isdigit() and int(p["UBUNTU_ISO_SIZE"]) % 2048 == 0, "ISO size pinned")
    for k in ("UBUNTU_CDIMAGE_KEY_FPR", "TUXWALL_APT_KEY_FPR"):
        check(re.fullmatch(r"[0-9A-F]{40}", p[k]) is not None, k + " is a full v4 fingerprint")
    check(p["TUXWALL_APT_KEY_FPR"] == "5D79B9082DCAEB9CCB731382F5D8235716BDBDD1", "TuxWall APT key fingerprint")
    m = re.search(r'^APT_KEY_FPR="([0-9A-F]+)"', read(INSTALLER), re.M)
    check(m and m.group(1) == p["TUXWALL_APT_KEY_FPR"], "same fingerprint as tuxwall-install.sh")
    if shutil.which("gpg"):
        with tempfile.TemporaryDirectory() as gh:
            out = subprocess.run(["gpg", "--batch", "--show-keys", "--with-colons", os.path.join(ROOT, "apt-public.asc")],
                                 capture_output=True, text=True, env=dict(os.environ, GNUPGHOME=gh)).stdout
        fprs = re.findall(r"^fpr:+([0-9A-F]{40}):", out, re.M)
        check(fprs[:1] == [p["TUXWALL_APT_KEY_FPR"]], "apt-public.asc primary key = the pinned fingerprint")
    else:
        print("note: gpg not installed, apt-public.asc fingerprint not checked")


def check_seed(p):
    text = render(read(os.path.join(NI, "user-data.in")), p)
    check(text.startswith("#cloud-config\n"), "user-data starts with #cloud-config")
    d = load_yaml(text, "user-data")
    if d:
        ai = d["autoinstall"]
        check(ai.get("version") == 1, "autoinstall version 1")
        inter = ai.get("interactive-sections") or []
        check("*" not in inter, "no '*' interactive section (explicit list)")
        for s in ("storage", "identity"):
            check(s in inter, "interactive section: " + s)
        check("storage" not in ai, "shipped seed has no storage layout (the user picks the disk)")
        check("identity" not in ai and "user-data" not in ai, "shipped seed has no account / password")
        check(ai.get("source", {}).get("id") == "ubuntu-server-minimal", "minimal server")
        check(ai.get("ssh", {}).get("install-server") is True, "OpenSSH installed")
        check("shutdown" not in ai, "shipped seed keeps the installer's own reboot prompt")
        early = "\n".join(ai.get("early-commands") or [])
        check("verify-ubuntu-iso.sh" in early and p["UBUNTU_ISO_SHA256"] in early and p["UBUNTU_ISO_SIZE"] in early,
              "early-commands verify the Ubuntu ISO against the pinned SHA-256 + size")
        check("sha256sum -c" in early and "0" * 64 in early, "early-commands verify the payload")
        check("LABEL=CIDATA" in early and "mount -o ro" in early, "seed mounted read-only (hides the stick from the disk list)")
        for k in ("early-commands", "late-commands"):
            check(all(isinstance(c, str) for c in ai.get(k) or []), "%s are strings (subiquity schema)" % k)
        late = ai.get("late-commands") or []
        late_s = "\n".join(c if isinstance(c, str) else " ".join(c) for c in late)
        check("install-firstboot.sh" in late_s and "/target" in late_s, "late-commands install the first-boot wizard")
        check("--answers" not in late_s and "test" not in late_s.lower(), "shipped seed has no test answers")
        check("tuxwall-install.sh" not in late_s and "apt-get install" not in late_s,
              "TuxWall itself is not installed during the Ubuntu install")
    check(not re.search(r"\$6\$|password:", text), "no password hash in the shipped seed")

    t = render(read(os.path.join(NI, "test", "user-data-test.in")), p)
    td = load_yaml(t, "test user-data")
    if td:
        ai = td["autoinstall"]
        check(not ai.get("interactive-sections"), "test seed is unattended")
        check("storage" in ai and "identity" in ai, "test seed answers storage + identity")
        for k in ("early-commands", "late-commands"):
            check(all(isinstance(c, str) for c in ai.get(k) or []), "test seed %s are strings (subiquity schema)" % k)
        check(any("--answers" in str(c) for c in ai.get("late-commands") or []), "test seed passes the answers file")
        late_t = "\n".join(str(c) for c in ai.get("late-commands") or [])
        check("lan-gate.sh /target/usr/local/sbin/tuxwall-test-lan-gate" in late_t
              and "multi-user.target.wants/tuxwall-test-lan-gate.service" in late_t,
              "test seed installs + enables the LAN isolation gate")
        dropin = re.search(r"printf \"(\[Unit\][^\"]*)\" >/target/etc/systemd/system/tuxwall-setup@\.service\.d/[^ ']+\.conf", late_t)
        check(dropin is not None and "Requires=tuxwall-test-lan-gate.service" in dropin.group(1)
              and "After=tuxwall-test-lan-gate.service" in dropin.group(1)
              and "ExecStartPre=/usr/bin/test -e /run/tuxwall-test/lan-isolated" in dropin.group(1),
              "test wizard requires the gate and its lan-isolated marker (fail-closed)")
    build = read(os.path.join(NI, "build.sh"))
    check(re.search(r'if \(\( TEST \)\); then\s+render "\$HERE/test/user-data-test.in"', build) is not None,
          "build.sh uses the test seed only with --test")
    m = re.search(r'if \(\( TEST \)\); then\n((?:    [^\n]*\n)+)fi', build)
    check(m is not None and "lan-gate.sh" in m.group(1) and "lan-gate.service" in m.group(1)
          and build.count("lan-gate") == m.group(1).count("lan-gate"), "build.sh adds the LAN gate to the TEST payload only")
    gate = read(os.path.join(NI, "test", "lan-gate.sh"))
    tail = gate.rsplit("\n", 4)
    check(gate.count('"$RUN/lan-isolated"') == 2 and 'rm -f "$RUN/lan-isolated"' in gate
          and '>"$RUN/lan-isolated"' in "".join(tail[-3:]),
          "LAN gate: stale marker removed first, marker written only as the last step")
    check('[ "$n" = 0 ] || fail' in gate and '[ "$rx0" = "$rx1" ] || fail' in gate and "|| fail \"capture failed" in gate,
          "LAN gate: any received frame, moving RX counter or a failed capture blocks the wizard")
    check("PACKET_OUTGOING" in gate and 'ip link set dev "$dev" down' in gate and "scope global" in gate,
          "LAN gate: ignores only its own frames, takes the NIC down on failure, refuses a pre-addressed NIC")
    unit = read(os.path.join(NI, "test", "lan-gate.service"))
    check("Type=oneshot" in unit and "RemainAfterExit=yes" in unit and "/usr/local/sbin/tuxwall-test-lan-gate" in unit,
          "LAN gate unit: oneshot, stays active for the wizard's Requires=")
    check('NAME+="-TEST"' in build, "test ISO is named *-TEST")
    check("-TEST.iso" in read(os.path.join(NI, "test", "run-qemu-test.sh")), "QEMU test refuses a non-TEST ISO")
    check("-volid CIDATA" in build and "-boot_image any replay" in build, "ISO: Ubuntu boot setup replayed, NoCloud label")
    check("--proto '=https'" in build and "VALIDSIG" in build, "build: https only + signature fingerprint check")


def check_grub(p):
    g = render(read(os.path.join(NI, "grub.cfg.in")), p)
    lines = [l.strip() for l in g.splitlines() if l.strip().startswith("linux")]
    check(len(lines) >= 4, "GRUB has the install entries")
    for l in lines:
        words = l.split()
        check("autoinstall" not in words, "shipped GRUB entry without 'autoinstall': " + l[:60])
        check("ds=nocloud" in words, "NoCloud only: " + l[:60])
        check(words[1] == "/casper/vmlinuz", "Ubuntu's signed kernel")
        for w in words:
            if w.startswith(("iso-url=", "url=")):
                check(w.split("=", 1)[1] in (p["UBUNTU_BASE_URL"] + "/" + p["UBUNTU_ISO"],
                                             p["UBUNTU_OLD_BASE_URL"] + "/" + p["UBUNTU_ISO"]),
                      "iso-url is the pinned https URL: " + w)
                check("initramfs_options=size=90%" in words, "download entries let the ISO use RAM")
            if w.startswith("iso-scan/filename="):
                check(w == "iso-scan/filename=/" + p["UBUNTU_ISO"], "iso-scan finds the pinned ISO file")
    check("url=http:" not in g, "no plain-http ISO URL")
    scan = [l for l in lines if not any(w.startswith(("iso-url=", "iso-scan/", "url=")) for w in l.split())]
    check(len(scan) >= 2, "shipped GRUB: 'Ubuntu ISO written to a second USB stick' entries (casper device scan)")
    m = re.search(r'menuentry "Help:[^"]*" \{(.*?)\n\}', g, re.S)
    check(m is not None and "No space left on device" in m.group(1) and "BusyBox" in m.group(1)
          and "sleep --interruptible" in m.group(1) and "linux" not in m.group(1),
          "GRUB help entry explains the RAM failure and the low-RAM entries (boots nothing)")
    check(re.search(r'menuentry "Install TuxWall \(downloads[^"]*6 GB\+ RAM\)"', g) is not None,
          "download entry title states the RAM need")
    head = g.split("menuentry", 1)[0]
    check(re.search(r"^set timeout=-1$", head, re.M) is not None and "timeout_style=menu" in head
          and re.search(r"^set default=0$", head, re.M) is not None,
          "shipped GRUB waits for a choice (no auto-boot into the 6 GB download entry), default highlight = entry 0")
    check(re.search(r"terminal_input console serial\s+terminal_output console serial", head) is not None,
          "shipped GRUB menu also on the serial console")
    ver = read(os.path.join(NI, "verify-ubuntu-iso.sh"))
    check("PKNAME" in ver and 'head -c "$size" "/dev/$parent"' in ver,
          "ISO check: an ISO9660 partition of a dd'ed stick is checked as its whole disk")
    tg = render(read(os.path.join(NI, "test", "grub-test.cfg.in")), p)
    entries = re.findall(r'^menuentry "([^"]*)"\s*\{\s*linux\s+([^\n]*)', tg, re.M)
    check(len(entries) == 3 and all("autoinstall" in l.split() for _, l in entries),
          "test GRUB: three unattended entries (test ISO only)")
    if len(entries) == 3:
        scan, dev, dl = (l.split() for _, l in entries)
        check("iso-scan/filename=/" + p["UBUNTU_ISO"] in scan, "test entry 0 = iso-scan (ISO file on a disk)")
        check(not any(w.startswith(("iso-scan", "iso-url", "url=")) for w in dev), "test entry 1 = casper device scan")
        check(any(w.startswith("iso-url=https://") for w in dl), "test entry 2 = download")
    check(re.search(r"set default=2\s+if search [^\n]*--file [^\n]*/%s; then\s+set default=0\s+"
                    r"elif search [^\n]*--file [^\n]*/casper/[^\n]*\.squashfs; then\s+set default=1\s+fi"
                    % re.escape(p["UBUNTU_ISO"]), tg) is not None,
          "test GRUB picks the entry from where the Ubuntu ISO is (file / CD / download)")
    rep = read(os.path.join(NI, "test", "test-report.sh"))
    check("check login-summary grep -q '^TuxWall dashboard: https://' /etc/issue.d/zz-tuxwall.issue" in rep,
          "test report: the login screen keeps the dashboard URL")
    check("vm-cloud-init-done" in rep and "vm-rootfs-grown" in rep and "vm-password-file-removed" in rep,
          "test report: VM image checks")
    check("check lan-isolated test -e /run/tuxwall-test/lan-isolated" in rep, "test report: LAN gate result")
    check(re.search(r"guest_agent\.0 \] && exit 0\s+sleep 3\s+systemctl poweroff", rep) is not None,
          "test report keeps the VM up when a guest agent reads it (Proxmox), powers off otherwise (QEMU driver)")


def check_firstboot():
    with tempfile.TemporaryDirectory() as td:
        pay, root = os.path.join(td, "payload"), os.path.join(td, "root")
        os.makedirs(pay)
        os.makedirs(os.path.join(root, "etc"))
        for f in ("tuxwall-setup", "tuxwall-setup@.service", "tuxwall-install.sh", "apt-public.asc",
                  "tuxwall-archive-keyring.gpg"):
            with open(os.path.join(pay, f), "w") as fh:
                fh.write("x\n")
        r = subprocess.run(["sh", FIRSTBOOT, "--payload", pay, "--origin", "check", "--console", "ttyS0",
                            "--console", "tty1", root], capture_output=True, text=True)
        check(r.returncode == 0, "install-firstboot.sh runs unprivileged on a temp root: " + r.stderr.strip())
        j = lambda *a: os.path.join(root, *a)
        check(os.access(j("usr/local/sbin/tuxwall-setup"), os.X_OK), "wizard installed executable")
        check(os.path.isfile(j("usr/local/share/tuxwall/tuxwall-install.sh")), "installer next to the wizard")
        check(os.path.isfile(j("usr/local/share/tuxwall/apt-public.asc")), "apt key next to the installer")
        check(os.path.isfile(j("etc/tuxwall/setup-pending")), "setup-pending flag")
        wants = sorted(os.listdir(j("etc/systemd/system/multi-user.target.wants")))
        check(wants == ["tuxwall-setup@tty1.service", "tuxwall-setup@ttyS0.service"], "units enabled once per console: %s" % wants)
        check(os.readlink(j("etc/systemd/system/multi-user.target.wants/tuxwall-setup@tty1.service"))
              == "/etc/systemd/system/tuxwall-setup@.service", "instance link targets the template")
        lst = read(j("etc/apt/sources.list.d/tuxwall.list")).strip()
        inst = read(INSTALLER)
        url = re.search(r'^APT_REPO_URL="([^"]+)"', inst, re.M).group(1)
        keyring = re.search(r'^APT_KEYRING=(\S+)', inst, re.M).group(1)
        check(lst == "deb [signed-by=%s] %s stable main" % (keyring, url), "apt entry identical to tuxwall-install.sh's")
        check(not os.path.exists(j("etc/systemd/system/tuxwall-setup@.service.d")), "no test drop-in without --answers")
        check("setup-pending" in read(j("etc/profile.d/zz-tuxwall-setup-hint.sh")), "login hint while pending")
        ans = os.path.join(td, "a")
        with open(ans, "w") as fh:
            fh.write("ROLE=dashboard\n")
        r = subprocess.run(["sh", FIRSTBOOT, "--payload", pay, "--answers", ans, root], capture_output=True, text=True)
        check(r.returncode == 0 and "--answers /etc/tuxwall/setup-answers" in
              read(j("etc/systemd/system/tuxwall-setup@.service.d/50-test-answers.conf")), "--answers adds the test drop-in")
        r = subprocess.run(["sh", FIRSTBOOT, "--payload", os.path.join(td, "nope"), root], capture_output=True, text=True)
        check(r.returncode != 0, "missing payload refused")


def vm_pins():
    out = {}
    for line in read(os.path.join(VM, "ubuntu-cloud.env")).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Z0-9_]+)=([A-Za-z0-9._:/+-]+)$", line)
        check(m is not None, "ubuntu-cloud.env line parses: " + line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def check_vm_image():
    p = vm_pins()
    for k in ("UBUNTU_CLOUD_VERSION", "UBUNTU_CLOUD_BASE_URL", "UBUNTU_CLOUD_SERIAL", "UBUNTU_CLOUD_IMAGE",
              "UBUNTU_CLOUD_SHA256", "UBUNTU_CLOUD_KEY_FPR", "TUXWALL_APT_KEY_FPR", "VM_DISK_SIZE"):
        check(k in p, "VM pin present: " + k)
    if len(p) < 8:
        return
    check(p["UBUNTU_CLOUD_BASE_URL"].startswith("https://cloud-images.ubuntu.com/releases/"),
          "cloud image from cloud-images.ubuntu.com over https")
    check(re.fullmatch(r"\d{8}(\.\d+)?", p["UBUNTU_CLOUD_SERIAL"]) is not None, "cloud image serial pinned")
    check(re.fullmatch(r"[0-9a-f]{64}", p["UBUNTU_CLOUD_SHA256"]) is not None, "cloud image SHA-256 pinned")
    check(p["UBUNTU_CLOUD_IMAGE"] == "ubuntu-%s-server-cloudimg-amd64.img" % p["UBUNTU_CLOUD_VERSION"],
          "cloud image name matches the version")
    check(p["UBUNTU_CLOUD_KEY_FPR"] == "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81",
          "signer = UEC Image Automatic Signing Key")
    check(p["TUXWALL_APT_KEY_FPR"] == pins()["TUXWALL_APT_KEY_FPR"], "same TuxWall APT key as the ISO pins")
    check(re.fullmatch(r"\d+G", p["VM_DISK_SIZE"]) is not None and 8 <= int(p["VM_DISK_SIZE"][:-1]) <= 64,
          "VM disk size 8-64 GiB")
    b = read(os.path.join(VM, "build.sh"))
    check("--proto '=https'" in b and "VALIDSIG" in b and "ubuntu-cloudimage-keyring.gpg" in b,
          "VM build: https only, signature fingerprint check, cloud image keyring")
    check('img_ok || { rm -f "$SRC"; die' in b and '[[ $IMG_SHA != "${PIN[UBUNTU_CLOUD_SHA256]}" ]]' in b,
          "VM build: image hash checked against the signed list (and the pin unless --latest)")
    check('image/common/install-firstboot.sh" --payload "$P" --origin vm-image --console ttyS0 "$STAGE"' in b,
          "VM build: the shared first-boot payload, wizard on tty1 + ttyS0")
    check("--answers" not in b and "test/" not in b and "setup-answers.test" not in b and "make-test-seed" not in b,
          "VM build: no test answers / seed in the shipped image")
    check('die "answers file in the image payload"' in b, "VM build refuses an answers file in the payload")
    check("MAX_BYTES=$((2 * 1024 * 1024 * 1024 - 1))" in b and "(( bytes < MAX_BYTES ))" in b,
          "VM build: fails over GitHub's 2 GiB asset limit")
    for t in ('"$QEMU_IMG" check "$QCOW"', '"$QEMU_IMG" compare', "e2fsck -fn", "MISMATCH content"):
        check(t in b, "VM build verifies its result: " + t)
    check("sudo" not in b and "mount " not in b and "chroot" not in b and "qemu-system" not in b
          and "virt-customize" not in b, "VM build: unprivileged, starts no VM")
    gi = os.path.join(VM, ".gitignore")
    check(os.path.isfile(gi) and "out/" in read(gi), "VM build output ignored by git")
    seed = read(os.path.join(VM, "test", "make-test-seed.sh"))
    check("TEST ONLY" in seed and "-TEST-seed.iso" in seed and "lan-gate.sh" in seed
          and "/usr/local/sbin/tuxwall-test-lan-gate || true" in seed
          and "ExecStartPre=/usr/bin/test -e /run/tuxwall-test/lan-isolated" in seed,
          "VM test seed: LAN gate in runcmd, wizard fail-closed on its marker")


def mk_nic(base, name, mac, driver=None, carrier=None, speed=None, ipv4=None, wireless=False, bridge=False, device=True):
    d = os.path.join(base, name)
    os.makedirs(d)
    with open(os.path.join(d, "address"), "w") as f:
        f.write(mac + "\n")
    if device:
        dev = os.path.join(base, "_devices", name)
        os.makedirs(dev)
        os.symlink(dev, os.path.join(d, "device"))
        if driver:
            drv = os.path.join(base, "_drivers", driver)
            os.makedirs(drv, exist_ok=True)
            os.symlink(drv, os.path.join(dev, "driver"))
    if carrier is not None:
        with open(os.path.join(d, "carrier"), "w") as f:
            f.write(str(carrier) + "\n")
    if speed is not None:
        with open(os.path.join(d, "speed"), "w") as f:
            f.write(str(speed) + "\n")
    if ipv4:
        with open(os.path.join(d, "tw_ipv4"), "w") as f:
            f.write(ipv4 + "\n")
    if wireless:
        os.makedirs(os.path.join(d, "wireless"))
    if bridge:
        os.makedirs(os.path.join(d, "bridge"))


def wizard(sysnet, *args):
    env = dict(os.environ, TUXWALL_SETUP_SYSNET=sysnet)
    return subprocess.run(["bash", WIZ, *args], capture_output=True, text=True, env=env, timeout=60)


def cmd_of(sysnet, answers_text, td):
    a = os.path.join(td, "answers-%d" % (abs(hash(answers_text)) % 10**8))
    with open(a, "w") as f:
        f.write(answers_text)
    r = wizard(sysnet, "--installer", INSTALLER, "--answers", a, "--print-command")
    return r, r.stdout.strip().split()


def check_wizard():
    with tempfile.TemporaryDirectory() as td:
        sn = os.path.join(td, "net")
        mk_nic(sn, "lo", "00:00:00:00:00:00", device=False)
        mk_nic(sn, "enp1s0", "52:54:00:00:00:01", "igc", 1, 2500, "198.51.100.23/24")
        mk_nic(sn, "enp2s0", "52:54:00:00:00:02", "igc", 0, -1)
        mk_nic(sn, "enp3s0", "52:54:00:00:00:03", "r8169")
        mk_nic(sn, "wlp4s0", "52:54:00:00:00:04", "iwlwifi", 0, wireless=True)
        mk_nic(sn, "br0", "52:54:00:00:00:09", bridge=True, device=False)
        mk_nic(sn, "veth0", "52:54:00:00:00:0a", device=False)
        with open(os.path.join(sn, "tw_default_route"), "w") as f:
            f.write("enp1s0\n")

        r = wizard(sn, "--list-nics")
        check(r.returncode == 0, "--list-nics runs: " + r.stderr.strip())
        rows = {l.split()[0]: l for l in r.stdout.splitlines()[1:] if l.strip()}
        check(sorted(rows) == ["enp1s0", "enp2s0", "enp3s0", "wlp4s0"], "physical ports only (no lo/bridge/veth): %s" % sorted(rows))
        check("2.5G" in rows.get("enp1s0", "") and "link up" in rows["enp1s0"] and "igc" in rows["enp1s0"]
              and "[internet]" in rows["enp1s0"] and "198.51.100.23/24" in rows["enp1s0"], "row: speed, link, driver, route, IPv4")
        check("no link" in rows.get("enp2s0", "") and " - " in rows["enp2s0"], "row: no link, unknown speed")
        check(" down " in rows.get("enp3s0", "") + " ", "row: admin-down port shows 'down'")
        check("[wireless]" in rows.get("wlp4s0", ""), "row: wireless tagged")

        base = "bash %s --source apt --role gateway" % INSTALLER
        r, c = cmd_of(sn, "WAN=enp1s0\nLAN=enp2s0\nLAN_SUBNET=192.168.1.1/24\n", td)
        check(r.returncode == 0 and " ".join(c) == base + " --wan enp1s0 --lan enp2s0 --wan-mode dhcp --subnet 192.168.1.1/24 -y",
              "DHCP gateway command: %s %s" % (" ".join(c), r.stderr.strip()))
        r, c = cmd_of(sn, "WAN_MAC=52:54:00:00:00:02\nLAN_MAC=52:54:00:00:00:03\n", td)
        check(r.returncode == 0 and "--wan enp2s0 --lan enp3s0" in " ".join(c), "ports by MAC: " + r.stderr.strip())
        check("--subnet 192.168.1.1/24" in " ".join(c), "default LAN 192.168.1.1/24")
        # WAN already in 192.168.1.0/24 (double NAT behind an ISP router): another default
        os.unlink(os.path.join(sn, "enp1s0", "tw_ipv4"))
        with open(os.path.join(sn, "enp1s0", "tw_ipv4"), "w") as f:
            f.write("192.168.1.57/24\n")
        r, c = cmd_of(sn, "WAN=enp1s0\nLAN=enp2s0\n", td)
        check(r.returncode == 0 and "--subnet 192.168.50.1/24" in " ".join(c), "collision with the WAN -> 192.168.50.1/24: %s" % " ".join(c))
        r, _ = cmd_of(sn, "WAN=enp1s0\nLAN=enp2s0\nLAN_SUBNET=192.168.1.1/24\n", td)
        check(r.returncode != 0 and "overlaps" in r.stderr, "LAN overlapping the WAN refused: " + r.stderr.strip())
        r, c = cmd_of(sn, "WAN=enp1s0\nWAN_MODE=static\nWAN_ADDRESS=203.0.113.10/24\nWAN_GATEWAY=203.0.113.1\n"
                          "WAN_DNS=9.9.9.9,1.1.1.1\nLAN=enp2s0\nLAN_SUBNET=10.20.30.1/24\n", td)
        check(r.returncode == 0 and "--wan-mode keep" in " ".join(c), "static WAN -> wizard writes netplan, installer keeps it")
        r, c = cmd_of(sn, "WAN=enp1s0\nWAN_MODE=keep\nLAN=enp2s0\nLAN_SUBNET=10.20.30.1/24\nEXTRA=--no-agent --no-geoip\n", td)
        check(r.returncode == 0 and " ".join(c).endswith("--no-agent --no-geoip -y"), "EXTRA flags passed through")
        r, c = cmd_of(sn, "ROLE=dashboard\n", td)
        check(r.returncode == 0 and " ".join(c) == "bash %s --source apt --role dashboard -y" % INSTALLER, "dashboard role command")
        for bad, why in (("WAN=enp1s0\nLAN=enp1s0\n", "same port"),
                         ("WAN=enp1s0\nLAN=wlp4s0\n", "wireless LAN"),
                         ("WAN=enp9s0\nLAN=enp2s0\n", "unknown port"),
                         ("WAN=enp1s0;reboot\nLAN=enp2s0\n", "shell metacharacters"),
                         ("WAN=$(touch /tmp/x)\n", "command substitution"),
                         ("FOO=1\n", "unknown key"),
                         ("WAN=enp1s0\nLAN=enp2s0\nEXTRA=--replace-configs\n", "EXTRA outside the allow-list"),
                         ("WAN=enp1s0\nLAN=enp2s0\nLAN_SUBNET=8.8.8.1/24\n", "public LAN range"),
                         ("WAN=enp1s0\nWAN_MODE=pppoe\nLAN=enp2s0\n", "PPPoE (unsupported by the installer)"),
                         ("WAN=enp1s0\nWAN_MODE=static\nWAN_ADDRESS=203.0.113.10\nLAN=enp2s0\n", "static without prefix"),
                         ("WAN_MAC=00:11:22:33:44:55\n", "unknown MAC"),
                         ("WAN=enp1s0\nLAN=enp2s0\nADMIN_USER=bad user\n", "invalid admin name")):
            r, _ = cmd_of(sn, bad, td)
            check(r.returncode != 0, "refused: " + why)
        # every flag the wizard can produce exists in tuxwall-install.sh
        flags = set(re.findall(r"^\s+(--[a-z-]+)\)", read(INSTALLER), re.M))
        wiz = read(WIZ)
        produced = set(re.findall(r"(--(?:source|deb|role|wan|lan|wan-mode|subnet|no-[a-z]+|ssh-wan))\b", wiz.split("build_install_cmd() {")[1].split("\n}")[0]))
        produced |= {"--no-crowdsec", "--no-agent", "--no-speedtest", "--no-geoip", "--ssh-wan"}
        check(produced and produced <= flags, "installer accepts every flag the wizard passes: %s" % sorted(produced - flags))
        r = wizard(sn, "--answers", "/dev/null")
        check(r.returncode != 0, "test hook refuses to change a real system")

        # The interactive steps with plain prompts, driven through stdin.
        drive = r'''
set -u
source "$WIZ"
INSTALLER="$INST"; UI=plain
detect_phys
step_wan <<<'2' && echo "WAN=$WAN"
step_wan_mode <<<$'2\n203.0.113.10/24\n203.0.113.1\n9.9.9.9, 1.1.1.1\n' && echo "MODE=$WAN_MODE $WAN_ADDRESS $WAN_GATEWAY $WAN_DNS"
step_lan <<<$'3\n\n1\n' && echo "LAN=$LAN"
step_subnet <<<$'8.8.8.1/24\n\n10.20.30.1/24\n' && echo "SUBNET=$LAN_SUBNET"
step_admin <<<$'n\n' && echo "ADMIN=[$ADMIN_USER]"
check_answers && echo CHECK=ok
build_install_cmd; echo "CMD=${INSTALL_CMD[*]}"
summary_text | sed 's/^/SUM /'
wan_netplan_yaml | sed 's/^/NP /'
step_wan <<<'b' || echo "BACK=$?"
'''
        env = dict(os.environ, TUXWALL_SETUP_SYSNET=sn, WIZ=WIZ, INST=INSTALLER)
        r = subprocess.run(["bash", "-c", drive], capture_output=True, text=True, env=env, timeout=60)
        out = r.stdout
        check("WAN=enp2s0" in out, "plain UI: WAN picked by number: " + r.stderr[-300:])
        check("MODE=static 203.0.113.10/24 203.0.113.1 9.9.9.9, 1.1.1.1" in out, "plain UI: static WAN asked")
        check("LAN=enp1s0" in out, "plain UI: wireless LAN refused, then a wired port")
        check("SUBNET=10.20.30.1/24" in out, "plain UI: public subnet refused, typed subnet accepted")
        check("ADMIN=[]" in out and "CHECK=ok" in out, "plain UI: admin later, answers valid")
        check("CMD=bash %s --source apt --role gateway --wan enp2s0 --lan enp1s0 --wan-mode keep --subnet 10.20.30.1/24 -y"
              % INSTALLER in out, "plain UI: installer command")
        check("SUM Dashboard:  https://10.20.30.1/" in out and "SUM SSH:" in out, "review shows the dashboard URL and SSH scope")
        np = "\n".join(l[3:] for l in out.splitlines() if l.startswith("NP "))
        try:
            import yaml
            y = yaml.safe_load(np)["network"]["ethernets"]["enp2s0"]
            check(y["addresses"] == ["203.0.113.10/24"] and y["routes"] == [{"to": "default", "via": "203.0.113.1"}]
                  and y["nameservers"]["addresses"] == ["9.9.9.9", "1.1.1.1"] and y["dhcp4"] is False,
                  "static WAN netplan: %s" % y)
        except ImportError:
            check("via: 203.0.113.1" in np, "static WAN netplan has the gateway")
        check("BACK=1" in out, "plain UI: 'b' goes back")


FIRSTBOOT_HARNESS = r'''
set -u
source "$WIZ"
PENDING=$TD/pending AUTO_ANSWERS=$TD/answers LOCK=$TD/lock LOG=$TD/log ISSUE=$TD/issue.d/zz-tuxwall.issue
CONSOLE_TTY=ttyS9
: >"$PENDING"; echo "ROLE=dashboard" >"$AUTO_ANSWERS"
exec 8>"$LOCK"
console_gate </dev/null >"$TD/gate1.out"; echo "GATE1 ANSWERS=$ANSWERS AUTO=$AUTO_RUN"
exec 8>&-
# a second console while the first holds the lock: waits, then gives way
( exec 9>"$LOCK"; flock 9; sleep 2; rm -f "$PENDING" ) &
sleep 0.5
( exec 8>"$LOCK"; ANSWERS="" AUTO_RUN=0; console_gate </dev/null >"$TD/gate2.out"; echo "GATE2 RETURNED" ); echo "GATE2 rc=$?"
wait
FIN_URL=https://192.168.1.1/ FIN_HOST=192.168.1.1 FIN_FPR='AB:CD\\ef'
write_issue; echo "ISSUE_RC=$?"
ADMIN_PASSWORD_FILE=$TD/pw; : >"$ADMIN_PASSWORD_FILE"; drop_password_file; [[ -e $TD/pw ]] && echo "PW_KEPT_OUTSIDE_ETC"
# cloud-init netplan: Proxmox names net0 eth0 (rename failed at first boot)
FIXTURE=0 SYS_NET=$TD/net CLOUD_NETPLAN=$TD/50-cloud-init.yaml CLOUD_NET_OFF=$TD/cloud.cfg.d/99-tuxwall-network.cfg
CLOUD_NETPLAN_ORIG=$TD/50.orig
pin_cloud_init_network; echo "PIN1_RC=$?"
pin_cloud_init_network; echo "PIN2_RC=$?"
'''


def check_wizard_firstboot_extras():
    """Answers file dropped in by cloud-init / an image: run unattended by one
    console unit, the other gives way; the summary stays on the login screen;
    cloud-init's netplan keeps the ports' current names."""
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "issue.d"))
        os.makedirs(os.path.join(td, "cloud.cfg.d"))
        for n, mac in (("ens18", "BC:24:11:00:00:01"), ("ens19", "BC:24:11:00:00:02")):
            os.makedirs(os.path.join(td, "net", n))
            with open(os.path.join(td, "net", n, "address"), "w") as f:
                f.write(mac + "\n")
        with open(os.path.join(td, "50-cloud-init.yaml"), "w") as f:
            f.write('network:\n  version: 2\n  ethernets:\n    eth0:\n      match:\n        macaddress: "BC:24:11:00:00:01"\n'
                    '      dhcp4: true\n      set-name: "eth0"\n    ens19:\n      match:\n        macaddress: "BC:24:11:00:00:02"\n'
                    '      set-name: "ens19"\n      dhcp4: false\n')
        r = subprocess.run(["bash", "-c", FIRSTBOOT_HARNESS], capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, WIZ=WIZ, TD=td))
        out = r.stdout
        check("GATE1 ANSWERS=%s/answers AUTO=1" % td in out, "answers file on a console unit: unattended run\n"
              + out + r.stderr[-600:])
        check("running unattended" in read(os.path.join(td, "gate1.out")), "console says it runs unattended")
        check("GATE2 rc=0" in out and "GATE2 RETURNED" not in out
              and "running unattended on another console" in read(os.path.join(td, "gate2.out")),
              "second console waits for the unattended run, then exits 0 (no failed unit)\n" + out)
        issue = read(os.path.join(td, "issue.d", "zz-tuxwall.issue")) if os.path.exists(
            os.path.join(td, "issue.d", "zz-tuxwall.issue")) else ""
        check(issue.startswith("TuxWall dashboard: https://192.168.1.1/\nRouter CA SHA-256: AB:CDef\n")
              and "\\" not in issue, "login-screen summary: URL + CA fingerprint, no agetty escapes\n" + issue)
        check("PW_KEPT_OUTSIDE_ETC" in out, "only a password file under /etc/tuxwall/ is removed")
        check("PIN1_RC=0" in out and "PIN2_RC=0" in out, "pin_cloud_init_network runs\n" + out + r.stderr[-600:])
        try:
            import yaml
            d = yaml.safe_load(read(os.path.join(td, "50-cloud-init.yaml")))["network"]["ethernets"]
            check(sorted(d) == ["ens18", "ens19"] and "set-name" not in d["ens18"]
                  and d["ens18"]["match"]["macaddress"] == "BC:24:11:00:00:01" and d["ens18"]["dhcp4"] is True
                  and d["ens19"].get("set-name") == "ens19",
                  "cloud-init netplan: pending rename dropped, entry keyed by the current name, matching rename kept: %s" % d)
            check(os.path.exists(os.path.join(td, "50.orig")) and "eth0" in read(os.path.join(td, "50.orig")),
                  "original cloud-init netplan kept")
        except ImportError:
            print("note: PyYAML missing, netplan pin result not parsed")
        off = os.path.join(td, "cloud.cfg.d", "99-tuxwall-network.cfg")
        check(os.path.exists(off) and "network: {config: disabled}" in read(off), "cloud-init network config disabled")
    wiz = read(WIZ)
    m = re.search(r"\nprepare_wan\(\) \{[^\n]*\n\s+pin_cloud_init_network\n", wiz)
    check(m is not None, "prepare_wan pins the cloud-init netplan before any netplan apply")
    inst = read(INSTALLER)
    rl = re.search(r"\nrun_long\(\) \{\n(.*?)\n\}\n", inst, re.S)
    body = rl.group(1) if rl else ""
    check("/dev/ttyS*" in body and "every=67" in body and "(( i % every == 0 ))" in body,
          "installer spinner redraws every ~10 s on a serial console (no flood)")
    check("frames='|/-\\'" in body and re.search(r'case "\$\{TERM:-dumb\}" in\s+linux\|vt\*\|dumb[^)]*\) ;;\s+\*\) frames=', body) is not None,
          "installer spinner: ASCII frames on the Linux console / vt* / dumb (braille shows as '0')")
    if shutil.which("script"):
        with tempfile.TemporaryDirectory() as td:
            h = os.path.join(td, "spin.sh")
            with open(h, "w") as f:
                f.write("LOG=/dev/null C_C= C_0= C_DIM=\n" + (rl.group(0) if rl else "") + "\nrun_long x sleep 0.5\n")
            seen = {}
            for t in ("linux", "vt220", "xterm-256color"):
                env = dict(os.environ, TERM=t, LANG="C.UTF-8", LC_ALL="C.UTF-8")
                r = subprocess.run(["script", "-qec", "bash " + h, "/dev/null"], capture_output=True, text=True,
                                   env=env, timeout=30, errors="replace")
                seen[t] = r.stdout
            check("\u280b" not in seen["linux"] and "|" in seen["linux"] and "\u280b" not in seen["vt220"]
                  and "\u280b" in seen["xterm-256color"],
                  "installer spinner run: ASCII on TERM=linux/vt220, braille only on a UTF-8 terminal emulator")
    else:
        print("note: script(1) missing, spinner run skipped")


def check_unit_and_package():
    u = read(UNIT)
    check("ConditionPathExists=/etc/tuxwall/setup-pending" not in u and "Environment=TUXWALL_SETUP_FIRSTBOOT=1" in u,
          "pending checked by the wizard, not as a unit condition (a skipped unit would keep its getty stopped)")
    check("Conflicts=getty@%i.service serial-getty@%i.service" in u and "After=getty@%i.service serial-getty@%i.service" in u,
          "unit takes the console from its getty via Conflicts= + After= (boot: getty start job dropped)")
    check("ExecStartPre" not in u, "no ExecStartPre stopping the getty (raced TTYVHangup: wizard SIGHUPed on Proxmox BIOS)")
    with tempfile.TemporaryDirectory() as td:
        env = dict(os.environ, TUXWALL_SETUP_FIRSTBOOT="1")
        if not os.path.exists("/etc/tuxwall/setup-pending"):
            r = subprocess.run(["bash", WIZ, "--console", "ttyS9"], capture_output=True, text=True, timeout=30, env=env, cwd=td)
            check(r.returncode == 0 and not r.stdout and not r.stderr,
                  "first-boot unit run with nothing pending: exits 0 at once\n" + r.stdout + r.stderr)
        env.pop("TUXWALL_SETUP_FIRSTBOOT")
        r = subprocess.run(["bash", WIZ, "--console", "ttyS9"], capture_output=True, text=True, timeout=30, env=env, cwd=td)
        check(os.geteuid() == 0 or (r.returncode != 0 and "root" in r.stderr + r.stdout),
              "without the unit flag the pending shortcut does not apply\n" + r.stdout + r.stderr)
    check("ExecStart=/usr/local/sbin/tuxwall-setup --console %I" in u, "unit runs the wizard on its console")
    check("DefaultDependencies=no" in u and "After=multi-user.target" in u,
          "unit starts after boot (no ordering cycle with getty/cloud-final)")
    check("ExecStopPost=" in u and "getty@" in u, "unit gives the console back to its getty")
    post = read(os.path.join(ROOT, "pkg", "DEBIAN", "postinst"))
    check("tuxwall-setup" not in post, "postinst never enables the first-boot wizard")
    check("/etc/systemd/system/tuxwall-setup@.service" in read(os.path.join(ROOT, "pkg", "DEBIAN", "conffiles")).split(),
          "unit is a conffile")
    check(os.access(WIZ, os.X_OK), "tuxwall-setup is executable in the tree")
    dc = read(os.path.join(ROOT, "tools", "deb_contents_check.py"))
    check("./usr/local/sbin/tuxwall-setup" in dc and "tuxwall-setup@.service" in dc, "deb_contents_check covers the wizard")
    wiz = read(WIZ)
    check('say "$(summary_text)"' in wiz and "summary_text | tr" not in wiz,
          "answers-file run prints the same aligned multi-line summary as the wizard (no ';'-joined line)")
    check("--answers" in wiz and "source \"$ANSWERS\"" not in wiz and ". \"$ANSWERS\"" not in wiz, "answers file is parsed, never sourced")
    check("/api/auth/setup" in wiz, "wizard can create the first admin through the API")
    check("tuxwall-tls status --json" in wiz, "wizard shows the CA fingerprint")


def check_secrets():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import privacy_check
    for dp, _dn, fns in os.walk(os.path.join(ROOT, "image")):
        if "/out" in dp:
            continue
        for fn in fns:
            p = os.path.join(dp, fn)
            t = read(p)
            rel = os.path.relpath(p, ROOT)
            check(not privacy_check.hits(t), "no owner data: " + rel)
            check("PRIVATE KEY" not in t, "no private key: " + rel)
            if "$6$" in t:
                check(rel in ("image/netinstall/test/user-data-test.in", "image/vm/test/make-test-seed.sh"),
                      "password hash only in the test seeds: " + rel)
    for f in (WIZ, UNIT):
        check(not privacy_check.hits(read(f)), "no owner data: " + os.path.relpath(f, ROOT))
    gi = os.path.join(ROOT, "image", "netinstall", ".gitignore")
    check(os.path.isfile(gi) and "out/" in read(gi), "build output ignored by git")


INSTALLER_HARNESS = r'''
set +Eeu; trap - ERR
LOG=$TD/install.log; : >"$LOG"
# run_long: maintainer scripts must not inherit the console's TERM
TERM=vt220 run_long "env" sh -c 'echo "ENV TERM=$TERM NO_COLOR=$NO_COLOR"'
# step_crowdsec: every install fails and leaves a half-configured bouncer
curl() { return 1; }
gpg() { cat >/dev/null; return 1; }
sleep() { :; }
bouncer_nft_usable() { return 1; }
configure_bouncer() { echo CONFIGURED >>"$TD/calls"; }
dpkg-query() {
    printf 'crowdsec ii \ncrowdsec-firewall-bouncer-iptables iF \ncrowdsec-firewall-bouncer-nftables un \n'
    printf 'crowdsec-firewall-bouncer rc \n'
}
apt-get() { echo "APT TERM=$TERM $*" >>"$TD/calls"; [[ $1 == purge ]]; }
PATH=$TD/bin
step_crowdsec
echo "RC $?" >>"$TD/calls"
'''


def check_installer_apt():
    """tuxwall-install.sh: apt runs with TERM=dumb (the bouncer postinst died
    on the serial console's TERM=vt220) and a failed CrowdSec attempt purges
    its half-configured packages instead of leaving dpkg broken."""
    with tempfile.TemporaryDirectory() as td:
        os.mkdir(os.path.join(td, "bin"))
        for tool in ("grep", "cat", "date", "sh", "dirname", "readlink", "basename"):
            src = shutil.which(tool)
            if src:
                os.symlink(src, os.path.join(td, "bin", tool))
        script = "source %s\n%s" % (shlex.quote(INSTALLER), INSTALLER_HARNESS)
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, TD=td))
        log = read(os.path.join(td, "install.log"))
        calls = read(os.path.join(td, "calls")) if os.path.exists(os.path.join(td, "calls")) else ""
        check("ENV TERM=dumb NO_COLOR=1" in log, "run_long: TERM=dumb NO_COLOR=1 for the command\n" + log[-800:])
        installs = [c for c in calls.splitlines() if c.startswith("APT ") and " install " in c]
        purges = [c for c in calls.splitlines() if c.startswith("APT ") and " purge " in c]
        check(installs and all(c.startswith("APT TERM=dumb ") for c in installs),
              "apt-get install runs with TERM=dumb\n" + calls)
        check(purges and all(c.endswith(" crowdsec-firewall-bouncer-iptables") for c in purges),
              "half-configured bouncer (only) purged\n" + calls)
        order = [("purge" if " purge " in c else "install") for c in calls.splitlines() if c.startswith("APT ")]
        check(order[:1] == ["install"] and order[-1] == "purge" and "purge" in order[1:-1]
              and any(c.endswith("install -y -q --no-install-recommends -o DPkg::Lock::Timeout=600 "
                                 "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "
                                 "crowdsec crowdsec-firewall-bouncer") for c in installs),
              "purge between attempts, Ubuntu archive fallback tried, dpkg left clean\n" + calls)
        check("CONFIGURED" not in calls and "RC 0" in calls, "CrowdSec failure is a warning (rc 0)\n" + calls
              + r.stderr[-800:])


BOUNCER_HARNESS = r'''
set +Eeu; trap - ERR
LOG=$TD/install.log; : >"$LOG"
ok() { echo "OK $*" >>"$TD/calls"; }
warn() { echo "WARN $*" >>"$TD/calls"; }
info() { :; }
bouncer_nft_usable() { return 0; }
# keyless bouncer (configured before CrowdSec), CrowdSec knows no bouncer
cscli() {
    echo "CSCLI $*" >>"$TD/calls"
    case "$1 $2" in
        "bouncers list") cat "$TD/list" ;;
        "bouncers add") echo "k3y-from-cscli" ;;
    esac
}
bouncer_ensure_key "$TD/a.yaml"
echo '[{"name":"cs-firewall-bouncer-1"}]' >"$TD/list"
bouncer_ensure_key "$TD/b.yaml"
'''


def check_installer_bouncer_key():
    """tuxwall-install.sh: a bouncer left without a LAPI key (its postinst ran
    before CrowdSec was configured - fresh netinstall on Proxmox) gets one
    from cscli; an existing registration is left alone."""
    with tempfile.TemporaryDirectory() as td:
        for n in ("a", "b"):
            with open(os.path.join(td, n + ".yaml"), "w") as f:
                f.write("mode: nftables\napi_url: http://127.0.0.1:8080/\napi_key: ${API_KEY}\nlog_mode: file\n")
        with open(os.path.join(td, "list"), "w") as f:
            f.write("[]\n")
        script = "source %s\n%s" % (shlex.quote(INSTALLER), BOUNCER_HARNESS)
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, TD=td))
        calls = read(os.path.join(td, "calls")) if os.path.exists(os.path.join(td, "calls")) else ""
        a, b = read(os.path.join(td, "a.yaml")), read(os.path.join(td, "b.yaml"))
        check("api_key: k3y-from-cscli\n" in a and a.count("api_key") == 1 and "log_mode: file" in a,
              "keyless bouncer gets a cscli key in its config\n" + a + calls + r.stderr[-500:])
        adds = [c for c in calls.splitlines() if c.startswith("CSCLI bouncers add ")]
        check(len(adds) == 1 and re.match(r"^CSCLI bouncers add cs-firewall-bouncer-\d+ -o raw$", adds[0]) is not None,
              "exactly one bouncer registered, upstream-style name\n" + calls)
        check("api_key: ${API_KEY}" in b, "existing bouncer registration left alone\n" + b)
        check("k3y" not in read(os.path.join(td, "install.log")), "bouncer key not written to the install log")
    inst = read(INSTALLER)
    m = re.search(r"\nconfigure_bouncer\(\) \{\n(.*?)\n\}\n", inst, re.S)
    body = m.group(1) if m else ""
    check(re.search(r'bouncer_ensure_key "\$cfg"\n\s*if systemctl restart crowdsec-firewall-bouncer', body) is not None,
          "configure_bouncer registers the key before restarting the bouncer")


def check_installer_wait_online():
    """tuxwall-install.sh: retiring systemd-resolved (for Unbound) leaves
    netplan's generated systemd-networkd-wait-online drop-in waiting with --dns
    (it pings io.systemd.Resolve.Monitor) - after the install that wait fails on
    every boot. The installer drops a wait-online override that re-runs the same
    wait without --dns."""
    inst = read(INSTALLER)
    m = re.search(r"\nstep_dns\(\) \{\n(.*?)\n\}\n", inst, re.S)
    body = m.group(1) if m else ""
    check("systemd-resolved.service" in body and "systemd-networkd-wait-online.service.d/tuxwall.conf" in body,
          "step_dns retires resolved and writes a wait-online override")
    check('ExecStart=/lib/systemd/systemd-networkd-wait-online --any -o routable -i %s' in body
          and '"$WAN"' in body and 'ExecStart=\\n' in body,
          "wait-online override re-runs without --dns, for the WAN interface\n" + body[:600])


def check_blocklist_save_race():
    """api_server.save_blocklists: the first-start seed and the installer's
    first-download request save at once - one writer at a time (the loser's
    os.replace found its .tmp moved away -> empty reply on a fresh install)."""
    import ast
    import threading
    src = read(os.path.join(ROOT, "www", "includes", "api_server.py"))
    tree = ast.parse(src)
    keep = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "save_blocklists":
            keep.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id.startswith("_BLOCKLIST")
                                                  for t in node.targets):
            keep.append(node)
    check(any(isinstance(n, ast.FunctionDef) for n in keep), "save_blocklists found")
    with tempfile.TemporaryDirectory() as td:
        ns = {"os": os, "json": __import__("json"), "threading": threading,
              "BLOCKLIST_DIR": td, "BLOCKLIST_CONFIG": os.path.join(td, "blocklists.json")}
        exec(compile(ast.Module(body=keep, type_ignores=[]), "save_blocklists", "exec"), ns)
        errors = []

        def worker():
            for _ in range(200):
                try:
                    ns["save_blocklists"]([{"url": "https://example.invalid/list", "domains": 0}])
                except OSError as e:
                    errors.append(e)
        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        check(not errors, "concurrent save_blocklists calls never fail (%d errors: %s)"
              % (len(errors), errors[:1]))


def check_shell():
    for s in SHELL_SCRIPTS:
        shell = "sh" if read(s).startswith("#!/bin/sh") else "bash"
        r = subprocess.run([shell, "-n", s], capture_output=True, text=True)
        check(r.returncode == 0, "%s -n %s %s" % (shell, os.path.relpath(s, ROOT), r.stderr.strip()))
    if shutil.which("shellcheck"):
        r = subprocess.run(["shellcheck", "-x", *SHELL_SCRIPTS], capture_output=True, text=True)
        check(r.returncode == 0, "shellcheck clean:\n" + r.stdout[:3000])
    else:
        print("note: shellcheck not installed, skipped")


def check_macs():
    """The lab MACs are never hard-coded. The QEMU default 52:54:00:12:34:xx once
    leased the Proxmox host's own static IP (192.168.1.86) from the live router
    and cut the host off; lab VMs get unique Proxmox-style BC:24:11:... MACs and
    the test answers / VM-image seed take those MACs as arguments."""
    bad = re.compile(r"(?:WAN_MAC|LAN_MAC|macaddress|\bmac)\s*[=:]\s*[\"']?52:54:00:12:34", re.I)
    for root, _dirs, fns in os.walk(ROOT):
        if "/.git/" in root + "/" or "/out/" in root + "/":
            continue
        for fn in fns:
            p = os.path.join(root, fn)
            try:
                with open(p, "rb") as f:
                    b = f.read(8192)
            except OSError:
                continue
            if b"\x00" in b:
                continue
            if bad.search(b.decode("utf-8", "replace")):
                check(False, "no hard-coded lab MAC (52:54:00:12:34): " + os.path.relpath(p, ROOT))
    sa = read(os.path.join(NI, "test", "setup-answers.test"))
    check("@WAN_MAC@" in sa and "@LAN_MAC@" in sa, "test answers take WAN/LAN MACs as placeholders")
    b = read(os.path.join(NI, "build.sh"))
    check("--wan-mac" in b and "--lan-mac" in b and "@WAN_MAC@" in b and "@LAN_MAC@" in b,
          "build.sh --test fills the MACs into the test answers")
    ms = read(os.path.join(VM, "test", "make-test-seed.sh"))
    check("--wan-mac" in ms and "--lan-mac" in ms and "@WAN_MAC@" in ms and "@LAN_MAC@" in ms,
          "VM-image test seed takes the MACs and fills them into the answers")
    rq = read(os.path.join(NI, "test", "run-qemu-test.sh"))
    check("--wan-mac" in rq and "--lan-mac" in rq and 'mac="$WAN_MAC"' in rq and 'mac="$LAN_MAC"' in rq,
          "QEMU test takes its NIC MACs as flags (never hard-coded)")


def main():
    p = pins()
    check_pins(p)
    check_seed(p)
    check_grub(p)
    check_firstboot()
    check_vm_image()
    check_wizard()
    check_wizard_firstboot_extras()
    check_unit_and_package()
    check_installer_apt()
    check_installer_bouncer_key()
    check_installer_wait_online()
    check_blocklist_save_race()
    check_secrets()
    check_macs()
    check_shell()
    print("netinstall_check: {} passed, {} failed".format(PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
