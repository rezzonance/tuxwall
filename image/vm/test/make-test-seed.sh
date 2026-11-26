#!/usr/bin/env bash
# TEST ONLY - never publish the output. Builds a NoCloud seed ISO (volume
# label cidata) for the TuxWall VM image lab test: plain NoCloud (no
# network-config: cloud-init DHCPs the first NIC = WAN), a test user, the QEMU
# guest agent, and the unattended first boot the README documents - the
# answers file in /etc/tuxwall/setup-answers - with the same answers, LAN
# isolation gate and report as the netinstall TEST ISO (image/netinstall/test).
#
#   image/vm/test/make-test-seed.sh --out DIR [--ssh-key FILE.pub]
#   -> DIR/tuxwall-vm-TEST-seed.iso (attach as a CD next to the imported qcow2)
#
# The wizard is fail-closed behind the gate: cloud-init's runcmd runs it
# before cloud-final ends (the wizard units start after cloud-final), and a
# drop-in makes the wizard refuse to start without its lan-isolated marker.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
NT="$REPO/image/netinstall/test"
OUT="" KEY=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT="${2:?}"; shift 2 ;;
        --ssh-key) KEY="${2:?}"; shift 2 ;;
        *) echo "usage: $0 --out DIR [--ssh-key FILE.pub]" >&2; exit 2 ;;
    esac
done
[[ -n $OUT ]] || { echo "usage: $0 --out DIR [--ssh-key FILE.pub]" >&2; exit 2; }
command -v xorriso >/dev/null || { echo "xorriso missing" >&2; exit 1; }
[[ -z $KEY || $(head -c 4 "$KEY") == ssh- ]] || { echo "$KEY is not an SSH public key" >&2; exit 1; }
mkdir -p "$OUT"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

python3 - "$NT" "$KEY" "$W/user-data" <<'PY'
import json, os, sys
nt, key, out = sys.argv[1:]
rd = lambda n: open(os.path.join(nt, n)).read()
def wf(path, content, perm):
    return {"path": path, "permissions": perm, "owner": "root:root", "content": content}
user = {"name": "tester", "groups": ["sudo"], "shell": "/bin/bash", "sudo": "ALL=(ALL) NOPASSWD:ALL",
        "lock_passwd": False,
        # throwaway lab password "tuxwall-test-only" (same as the netinstall test seed)
        "passwd": "$6$tuxwalltest$ogxK7WQidgMnMPUdnX7z4/wT9iHCnU.PvSmhnUkCTABrB65gCv7ucCsb0tKjyjoef0mKINJnrUd8YDap8ltXh0"}
if key:
    user["ssh_authorized_keys"] = [open(key).read().strip()]
report_unit = ("[Unit]\nDescription=TuxWall VM image test report\nAfter=multi-user.target\nDefaultDependencies=no\n"
               "[Service]\nType=simple\nExecStart=/usr/local/sbin/tuxwall-test-report\n")
d = {
    "hostname": "tuxwall-vm-test",
    "users": [user],
    "ssh_pwauth": False,
    "packages": ["qemu-guest-agent"],
    "write_files": [
        # the documented headless path: answers file -> unattended first boot
        wf("/etc/tuxwall/setup-answers", rd("setup-answers.test"), "0600"),
        wf("/etc/tuxwall/test-admin-password", "tuxwall-test-only", "0600"),
        wf("/usr/local/sbin/tuxwall-test-lan-gate", rd("lan-gate.sh"), "0755"),
        wf("/usr/local/sbin/tuxwall-test-report", rd("test-report.sh"), "0755"),
        wf("/etc/systemd/system/tuxwall-test-report.service", report_unit, "0644"),
        wf("/etc/systemd/system/tuxwall-setup@.service.d/60-test-lan-gate.conf",
           "[Service]\nExecStartPre=/usr/bin/test -e /run/tuxwall-test/lan-isolated\n", "0644"),
    ],
    "runcmd": [
        "systemctl daemon-reload",
        "systemctl start qemu-guest-agent || true",
        "/usr/local/sbin/tuxwall-test-lan-gate || true",
        "systemctl start --no-block tuxwall-test-report.service",
    ],
}
with open(out, "w") as f:
    f.write("#cloud-config\n# TEST ONLY (image/vm/test/make-test-seed.sh) - never publish.\n")
    f.write(json.dumps(d, indent=1) + "\n")   # JSON is valid YAML
PY
printf 'instance-id: tuxwall-vm-test-%s\nlocal-hostname: tuxwall-vm-test\n' "$(date +%s)" >"$W/meta-data"
rm -f "$OUT/tuxwall-vm-TEST-seed.iso"
xorriso -as mkisofs -quiet -V cidata -J -r -o "$OUT/tuxwall-vm-TEST-seed.iso" "$W/user-data" "$W/meta-data"
echo "$OUT/tuxwall-vm-TEST-seed.iso"
