#!/usr/bin/env python3
"""TuxWall Suricata provisioning (guarded, idempotent).

The stock suricata.yaml ships placeholder af-packet interface names that
fail to bind on a fresh install, so suricata.service can exit immediately.
If NONE of the configured af-packet interfaces exist on this system, this
script rebinds them to the detected WAN (default-route) and LAN (private
address) interfaces and sets HOME_NET to the LAN subnet.

Installs whose af-packet interfaces already exist -- hand-tuned boxes,
re-runs -- are left completely untouched (exit 1).

--add-lan: if af-packet captures no LAN interface (the "lan" role of
/etc/tuxwall/interfaces.json, else the first non-WAN interface with a
private IPv4 address), add a capture block for it with a cluster-id of its
own, before the "default" template. Device monitoring needs it: on the WAN
side every IPv4 alert carries the router's NAT address, so it can never be
attributed to a device. Run by the installer on fresh installs and offered
by the dashboard (Security > Local) otherwise. Never touches an IPS
(copy-mode) setup, a LAN already captured (or its VLAN parent) or a file
without an af-packet section (exit 1). Restart Suricata afterwards.

Usage: tune-suricata.py [--add-lan] /etc/suricata/suricata.yaml [sysfs_dir]
       (sysfs_dir and $TUXWALL_INTERFACES_JSON overrides exist only for testing)
Exit:  0 = config rewritten,  1 = left untouched,  2 = error
"""
import ipaddress
import json
import os
import re
import subprocess
import sys

ROLES = os.environ.get("TUXWALL_INTERFACES_JSON") or "/etc/tuxwall/interfaces.json"


def _roles():
    try:
        with open(ROLES) as f:
            r = json.load(f)
        return r if isinstance(r, dict) else {}
    except Exception:
        return {}


def _dev(role):
    return str(role.get("device") or "") if isinstance(role, dict) else str(role or "")


def _default_dev():
    return subprocess.run(
        ["bash", "-c", "ip route show default 2>/dev/null | awk '{print $5}' | head -n1"],
        capture_output=True, text=True,
    ).stdout.strip()


def _private_lan(wan):
    out = subprocess.run(["ip", "-o", "-4", "addr"], capture_output=True, text=True).stdout
    for row in out.splitlines():
        m = re.match(r"(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", row)
        if m and m.group(1) not in (wan, "lo") and ipaddress.ip_address(m.group(2)).is_private:
            return m.group(1)
    return ""


def add_lan(path, sysfs):
    try:
        with open(path) as f:
            lines = f.readlines()
        known = set(os.listdir(sysfs)) - {"lo"}
    except OSError:
        return 2
    start = next((i for i, ln in enumerate(lines) if re.match(r"^af-packet:\s*$", ln)), None)
    if start is None:
        return 1
    end = next((i for i in range(start + 1, len(lines)) if re.match(r"^\S", lines[i])
                and not lines[i].startswith("#")), len(lines))
    section = "".join(lines[start:end])
    if re.search(r"^\s*copy-mode:\s*(ips|tap)\b", section, re.M):
        return 1                                 # an inline IPS/TAP pair: hands off
    ifaces = [m.group(1).strip("\"'") for m in re.finditer(r"^\s*-\s*interface:\s*(\S+)", section, re.M)]
    roles = _roles()
    wan = _dev(roles.get("wan")) or _default_dev()
    lan = _dev(roles.get("lan"))
    if not lan or lan not in known or lan == wan:
        lan = _private_lan(wan)
    if not lan or lan not in known or lan == wan:
        return 1                                 # no LAN to add (yet)
    if lan in ifaces or lan.split(".")[0] in ifaces:
        return 1                                 # already captured
    ids = {int(x) for x in re.findall(r"^\s*cluster-id:\s*(\d+)", section, re.M)}
    cid = next(i for i in range(97, 0, -1) if i not in ids | {99, 98})
    block = ["  # LAN capture added by TuxWall (tune-suricata.py --add-lan): device monitoring\n",
             "  # attributes IDS alerts to LAN devices by their address\n",
             "  - interface: %s\n" % lan, "    cluster-id: %d\n" % cid,
             "    cluster-type: cluster_flow\n", "    defrag: yes\n"]
    at = next((i for i in range(start + 1, end) if re.match(r"^\s*-\s*interface:\s*\"?default\"?\s*$", lines[i])), None)
    if at is not None:
        while at > start + 1 and re.match(r"^  #", lines[at - 1]):
            at -= 1                              # keep the template's own comment above it
    else:
        at = end
        while at > start + 1 and not lines[at - 1].strip():
            at -= 1
    lines[at:at] = block
    tmp = path + ".tuxwall-tmp"
    try:
        st = os.stat(path)
        with open(tmp, "w") as f:
            f.write("".join(lines))
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return 2
    print("added: af-packet %s (cluster-id %d)" % (lan, cid))
    return 0


def main():
    args = sys.argv[1:]
    if args[:1] == ["--add-lan"]:
        if len(args) < 2:
            return 2
        return add_lan(args[1], args[2] if len(args) > 2 else "/sys/class/net")
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

    # WAN/LAN roles from /etc/tuxwall/interfaces.json when present.
    roles = _roles()
    r_wan = _dev(roles.get("wan"))
    r_lan = _dev(roles.get("lan"))
    r_addr = str((roles.get("lan") or {}).get("address") or "") if isinstance(roles.get("lan"), dict) else ""

    # Detect WAN (default-route device) and LAN (private-address device).
    wan = r_wan or subprocess.run(
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

    if r_lan and r_lan in known and r_lan != wan and r_addr:
        try:
            lan, lan_net = r_lan, str(ipaddress.ip_interface(r_addr).network)
        except ValueError:
            pass

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
