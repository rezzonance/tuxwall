#!/usr/bin/env python3
"""TuxWall Suricata provisioning (guarded, idempotent).

The stock suricata.yaml ships placeholder af-packet interface names that
fail to bind on a fresh install, so suricata.service can exit immediately.
If NONE of the configured af-packet interfaces exist on this system, this
script rebinds them to the detected WAN (default-route) and LAN (private
address) interfaces and sets HOME_NET to the LAN subnet.

Installs whose af-packet interfaces already exist -- hand-tuned boxes,
re-runs -- are left completely untouched (exit 1).

Usage: tune-suricata.py /etc/suricata/suricata.yaml [sysfs_dir]
       (sysfs_dir override exists only for testing)
Exit:  0 = config rewritten,  1 = left untouched,  2 = error
"""
import os
import re
import subprocess
import sys


def main():
    if len(sys.argv) < 2:
        return 2
    path = sys.argv[1]
    sysfs = sys.argv[2] if len(sys.argv) > 2 else "/sys/class/net"
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError:
        return 2

    # Locate af-packet interface lines within the top-level block.
    in_af = False
    iface_re = re.compile(r"^(\s{2}- interface:\s*)(\S+?)\s*$")
    iface_lines = []  # (line_index, prefix)
    for i, ln in enumerate(lines):
        if re.match(r"^af-packet:\s*$", ln):
            in_af = True
        elif in_af and re.match(r"^\S", ln):
            in_af = False
        if in_af:
            m = iface_re.match(ln)
            if m:
                iface_lines.append((i, m.group(1)))

    try:
        known = set(os.listdir(sysfs)) - {"lo"}
    except OSError:
        return 2
    if not iface_lines or any(
        lines[i].strip().startswith(p.strip()) and
        lines[i].strip()[len(p.strip()):].split()[0] in known
        for i, p in iface_lines
    ):
        return 1  # valid (or nothing to tune) -> untouched

    # Detect WAN (default-route device) and LAN (private-address device).
    wan = subprocess.run(
        ["bash", "-c", "ip route show default 2>/dev/null | awk '{print $5}' | head -n1"],
        capture_output=True, text=True,
    ).stdout.strip()
    if not wan or wan not in known:
        return 1  # cannot detect WAN safely -> untouched

    lan, lan_net = "", "192.168.0.0/16"
    out = subprocess.run(
        ["ip", "-o", "-4", "addr"], capture_output=True, text=True,
    ).stdout
    for row in out.splitlines():
        m = re.match(r"(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", row)
        if not m:
            continue
        ifc, ipaddr, plen = m.group(1), m.group(2), int(m.group(3))
        if ifc in (wan, "lo"):
            continue
        o1, o2 = ipaddr.split(".")[:2]
        private = (
            o1 == "10"
            or ipaddr.startswith("192.168.")
            or (o1 == "172" and 16 <= int(o2) <= 31)
        )
        if private:
            lan = ifc
            host = ipaddr.split(".")
            if o1 == "10":
                net = ipaddr
            elif ipaddr.startswith("192.168."):
                net = ".".join(host[:3] + ["0"])
            else:  # 172.16-31
                net = ".".join(host[:2] + ["0", "0"])
            lan_net = "%s/%d" % (net, plen)
            break

    bind = [wan] + ([lan] if lan else [])
    for k, (i, prefix) in enumerate(iface_lines[: len(bind)]):
        lines[i] = prefix + bind[k] + "\n"

    text = "".join(lines)
    text = re.sub(
        r'(?m)^HOME_NET:\s*"\[[^\]]*\]"',
        'HOME_NET: ["%s"]' % lan_net,
        text,
    )
    try:
        with open(path, "w") as f:
            f.write(text)
    except OSError:
        return 2
    print("tuned: af-packet -> %s%s  HOME_NET -> %s" % (wan, " + " + lan if lan else "", lan_net))
    return 0


if __name__ == "__main__":
    sys.exit(main())
