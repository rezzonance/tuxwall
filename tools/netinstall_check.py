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
SHELL_SCRIPTS = (WIZ, FIRSTBOOT, os.path.join(NI, "build.sh"), os.path.join(NI, "verify-ubuntu-iso.sh"),
                 os.path.join(NI, "test", "run-qemu-test.sh"), os.path.join(NI, "test", "test-report.sh"))

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
    build = read(os.path.join(NI, "build.sh"))
    check(re.search(r'if \(\( TEST \)\); then\s+render "\$HERE/test/user-data-test.in"', build) is not None,
          "build.sh uses the test seed only with --test")
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


def check_unit_and_package():
    u = read(UNIT)
    check("ConditionPathExists=/etc/tuxwall/setup-pending" in u, "unit only runs while setup is pending")
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
                check(rel == "image/netinstall/test/user-data-test.in", "password hash only in the test seed: " + rel)
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


def main():
    p = pins()
    check_pins(p)
    check_seed(p)
    check_grub(p)
    check_firstboot()
    check_wizard()
    check_unit_and_package()
    check_installer_apt()
    check_secrets()
    check_shell()
    print("netinstall_check: {} passed, {} failed".format(PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
