#!/usr/bin/env python3
"""SQM helper: packaged, generic, and --dry-run == what a real run does.

tuxwall-sqm.sh used to ship only through tuxwall-install.sh, so apt installs
showed "SQM script missing". Since 3.3.5 the package ships it at
/usr/local/sbin/tuxwall-sqm.sh. These tests run a copy of the shipped script
with its /etc/tuxwall paths pointed at a temp dir and tc/ip/modprobe/sleep
replaced by stubs that only record their arguments - nothing touches the
host's network.

    python3 tools/sqm_check.py
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "pkg/usr/local/sbin/tuxwall-sqm.sh")

PASS = FAIL = 0


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def expected(wan, up, down, ifb="ifb4wan"):
    """The command sequence of the 3.3.4-era script (live router reference)."""
    return [
        "tc qdisc del dev {} root".format(wan),
        "tc qdisc del dev {} ingress".format(wan),
        "ip link del {}".format(ifb),
        "tc qdisc replace dev {} root cake bandwidth {} diffserv3 nat dual-srchost ack-filter "
        "overhead 18 mpu 64".format(wan, up),
        "modprobe ifb",
        "ip link add name {} type ifb".format(ifb),
        "ip link set {} up".format(ifb),
        "tc qdisc add dev {} handle ffff: ingress".format(wan),
        "tc filter add dev {} parent ffff: matchall action mirred egress redirect dev {}".format(wan, ifb),
        "tc qdisc replace dev {} root cake bandwidth {} diffserv3 nat dual-dsthost "
        "overhead 18 mpu 64".format(ifb, down),
    ]


class Sandbox:
    def __init__(self, wan_exists=True):
        self.dir = tempfile.mkdtemp(prefix="sqm-check.")
        self.etc = os.path.join(self.dir, "etc")
        self.stub = os.path.join(self.dir, "stub")
        os.makedirs(self.etc)
        os.makedirs(self.stub)
        self.log = os.path.join(self.dir, "calls.log")
        with open(SCRIPT) as f:
            src = f.read()
        self.script = os.path.join(self.dir, "tuxwall-sqm.sh")
        with open(self.script, "w") as f:
            f.write(src.replace("/etc/tuxwall/", self.etc + "/"))
        for cmd in ("tc", "modprobe", "sleep"):
            self._stub(cmd, 'echo "{} $*" >> "$SQM_LOG"\n'.format(cmd))
        show = "exit 0" if wan_exists else "exit 1"
        self._stub("ip", 'if [ "$1 $2" = "link show" ]; then {}; fi\necho "ip $*" >> "$SQM_LOG"\n'.format(show))

    def _stub(self, name, body):
        p = os.path.join(self.stub, name)
        with open(p, "w") as f:
            f.write("#!/bin/sh\n" + body)
        os.chmod(p, 0o755)

    def write(self, name, text):
        with open(os.path.join(self.etc, name), "w") as f:
            f.write(text)

    def run(self, *args):
        open(self.log, "w").close()
        env = {"PATH": self.stub + ":/usr/bin:/bin", "SQM_LOG": self.log}
        p = subprocess.run(["bash", self.script, *args], capture_output=True, text=True, env=env, timeout=60)
        with open(self.log) as f:
            calls = [line.rstrip("\n") for line in f]
        return p.returncode, p.stdout, calls

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def dry_commands(out):
    return [line[2:] for line in out.splitlines() if line.startswith("+ ")]


def scenario(name, files, want):
    sb = Sandbox()
    try:
        for fname, text in files.items():
            sb.write(fname, text)
        rc, out, calls = sb.run()
        check(rc == 0, name + ": real run exits 0 (got {}: {})".format(rc, out.strip()[-200:]))
        check(calls == want, name + ": real run commands\n  got  {}\n  want {}".format(calls, want))
        rc, out, calls = sb.run("--dry-run")
        check(rc == 0, name + ": --dry-run exits 0")
        check(calls == [], name + ": --dry-run runs no tc/ip/modprobe (ran {})".format(calls))
        check(dry_commands(out) == want, name + ": --dry-run prints the same commands\n  got  {}".format(
            dry_commands(out)))
        check("nothing changed" in out, name + ": --dry-run says nothing changed")
    finally:
        sb.close()


def main():
    check(os.path.isfile(SCRIPT), "packaged script exists: pkg/usr/local/sbin/tuxwall-sqm.sh")
    check(os.stat(SCRIPT).st_mode & stat.S_IXUSR, "packaged script is executable")
    idx = subprocess.run(["git", "-C", ROOT, "ls-files", "-s", "pkg/usr/local/sbin/tuxwall-sqm.sh"],
                         capture_output=True, text=True).stdout
    check(idx.startswith("100755"), "git records the script as 0755 (the .deb installs it 0755)")
    check(not os.path.exists(os.path.join(ROOT, "scripts/tuxwall-sqm.sh")), "one script: scripts/ copy is gone")
    check(subprocess.run(["bash", "-n", SCRIPT]).returncode == 0, "bash -n")
    with open(os.path.join(ROOT, "tuxwall-install.sh")) as f:
        inst = f.read()
    check("scripts/tuxwall-sqm.sh" not in inst, "installer no longer uses scripts/tuxwall-sqm.sh")
    check("pkg/usr/local/sbin/tuxwall-sqm.sh" in inst, "installer falls back to the packaged copy")
    with open(os.path.join(ROOT, "pkg/etc/systemd/system/tuxwall-sqm.service")) as f:
        check("ExecStart=/usr/local/sbin/tuxwall-sqm.sh" in f.read(), "tuxwall-sqm.service runs the packaged path")
    with open(SCRIPT) as f:
        src = f.read()
    for needle in ("enp5s0", "275mbit", "2115mbit", "192.168."):
        check(needle not in src, "no box-specific value in the script: " + needle)

    # the live router's settings (sqm.conf names the WAN; interfaces.json agrees)
    scenario("dashboard sqm.conf",
             {"sqm.conf": "# TuxWall SQM rates (Mbit). Managed by dashboard System > Traffic Shaping.\n"
                          "WAN=enp5s0\nUP_RATE=275mbit\nDOWN_RATE=2115mbit\n",
              "interfaces.json": json.dumps({"wan": {"device": "enp5s0", "mode": "dhcp"}})},
             expected("enp5s0", "275mbit", "2115mbit"))
    scenario("sqm.conf wins over interfaces.json",
             {"sqm.conf": "WAN=eth1\nUP_RATE=40mbit\nDOWN_RATE=300mbit\n",
              "interfaces.json": json.dumps({"wan": {"device": "enp9s0"}})},
             expected("eth1", "40mbit", "300mbit"))
    scenario("no WAN in sqm.conf -> interfaces.json role",
             {"sqm.conf": "UP_RATE=40mbit\nDOWN_RATE=300mbit\n",
              "interfaces.json": json.dumps({"wan": {"device": "enp9s0"}})},
             expected("enp9s0", "40mbit", "300mbit"))
    scenario("no config -> generic defaults", {}, expected("eth0", "95mbit", "920mbit"))

    sb = Sandbox(wan_exists=False)
    try:
        sb.write("sqm.conf", "WAN=wan9\n")
        rc, out, calls = sb.run()
        check(rc == 1 and "not found, aborting" in out, "missing WAN: real run aborts (rc {})".format(rc))
        check(calls.count("sleep 1") == 29 and not [c for c in calls if c.startswith(("tc", "ip "))],
              "missing WAN: waits, changes nothing ({} calls)".format(len(calls)))
        rc, out, calls = sb.run("--dry-run")
        check(rc == 0 and "not found" in out and dry_commands(out) == expected("wan9", "95mbit", "920mbit"),
              "missing WAN: --dry-run notes it and still prints the plan")
        check(calls == [], "missing WAN: --dry-run does not wait or change anything")
        rc, out, calls = sb.run("--bogus")
        check(rc == 2 and calls == [], "unknown option: usage, rc 2, nothing run")
    finally:
        sb.close()

    print("sqm_check: {} passed, {} failed".format(PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
