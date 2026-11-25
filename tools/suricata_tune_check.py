#!/usr/bin/env python3
"""scripts/tune-suricata.py (both copies): the placeholder rewrite and
--add-lan (device monitoring needs Suricata on the LAN side: on the WAN every
IPv4 alert carries the router's NAT address). Temp files only; the LAN/WAN
roles come from a fixture interfaces.json, the interfaces from a fake sysfs.

    python3 tools/suricata_tune_check.py
"""
import filecmp
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "tune-suricata.py")
PKG_COPY = os.path.join(ROOT, "pkg", "usr", "local", "share", "tuxwall", "scripts", "tune-suricata.py")
sys.path.insert(0, os.path.join(ROOT, "www", "includes"))
import devicewatch as dw  # noqa: E402

PASS = FAIL = 0
TMP = tempfile.mkdtemp(prefix="suricata-tune-")

# the shape of the stock (Ubuntu 8.0) af-packet section
STOCK = """%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
af-packet:
  - interface: eth0
    # Number of receive threads. "auto" uses the number of cores
    #threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    #use-mmap: yes
  # Put default values here. These will be used for an interface that is not
  # in the list above.
  - interface: default
    #threads: auto
    #use-mmap: no

pcap:
  - interface: eth0
  - interface: default
"""


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def setup(name, yaml_text, ifaces=("wan0", "lan0"), roles=None):
    d = os.path.join(TMP, name)
    os.makedirs(os.path.join(d, "sys"))
    for i in ifaces:
        os.makedirs(os.path.join(d, "sys", i))
    with open(os.path.join(d, "suricata.yaml"), "w") as f:
        f.write(yaml_text)
    os.chmod(os.path.join(d, "suricata.yaml"), 0o640)
    with open(os.path.join(d, "interfaces.json"), "w") as f:
        json.dump(roles if roles is not None else {"wan": {"device": "wan0"}, "lan": {"device": "lan0",
                                                                                    "address": "192.0.2.1/24"}}, f)
    return d


def run(d, *args):
    env = dict(os.environ, TUXWALL_INTERFACES_JSON=os.path.join(d, "interfaces.json"))
    p = subprocess.run([sys.executable, "-B", SCRIPT] + list(args) + [os.path.join(d, "suricata.yaml"),
                                                                       os.path.join(d, "sys")],
                       capture_output=True, text=True, env=env, timeout=30)
    with open(os.path.join(d, "suricata.yaml")) as f:
        return p.returncode, f.read(), p.stdout


def main():
    check(filecmp.cmp(SCRIPT, PKG_COPY, shallow=False), "scripts/ and pkg/ copies identical")
    try:
        import yaml
    except ImportError:
        yaml = None

    # WAN only (an older install, or a fresh one whose LAN had no address yet)
    wan_only = STOCK.replace("interface: eth0\n    # Number", "interface: wan0\n    # Number", 1)
    d = setup("wanonly", wan_only)
    rc, text, out = run(d, "--add-lan")
    cap = dw.suricata_capture(os.path.join(d, "suricata.yaml"))
    check(rc == 0 and cap == ["wan0", "lan0"] and "added: af-packet lan0 (cluster-id 97)" in out,
          "--add-lan: LAN capture added (%r, %r)" % (rc, cap))
    i_lan, i_def = text.index("- interface: lan0"), text.index("- interface: default")
    i_note = text.index("  # Put default values here")
    check(i_lan < i_note < i_def and "cluster-id: 97" in text[i_lan:i_note],
          "--add-lan: before the default template and its comment, own cluster-id")
    check(oct(os.stat(os.path.join(d, "suricata.yaml")).st_mode & 0o777) == oct(0o640), "--add-lan: file mode kept")
    if yaml is not None:
        y = yaml.safe_load(text)
        names = [x.get("interface") for x in y["af-packet"]]
        check(names == ["wan0", "lan0", "default"] and y["af-packet"][1]["cluster-id"] == 97
              and y["af-packet"][1]["cluster-type"] == "cluster_flow", "--add-lan: valid YAML (%r)" % names)
    rc2, text2, _o = run(d, "--add-lan")
    check(rc2 == 1 and text2 == text, "--add-lan: idempotent (already captured -> untouched)")

    # the live router's shape: several interfaces with cluster-ids, LAN missing
    live = ("af-packet:\n  - interface: wan0\n    cluster-id: 98\n  - interface: opt0\n    cluster-id: 97\n"
            "  - interface: eno1\n    cluster-id: 96\n\n  - interface: default\nlogging:\n  x: 1\n")
    d = setup("live", live, ifaces=("wan0", "lan0", "opt0", "eno1"))
    rc, text, out = run(d, "--add-lan")
    check(rc == 0 and "cluster-id 95" in out and dw.suricata_capture(os.path.join(d, "suricata.yaml"))
          == ["wan0", "opt0", "eno1", "lan0"], "--add-lan: next free cluster-id (%r)" % out)

    # no "default" template: appended at the end of the section
    d = setup("nodefault", "af-packet:\n  - interface: wan0\n    cluster-id: 99\n\nlogging:\n  x: 1\n")
    rc, text, _o = run(d, "--add-lan")
    check(rc == 0 and text.index("lan0") < text.index("logging:") and text.endswith("logging:\n  x: 1\n"),
          "--add-lan: appended inside the af-packet section")

    # refusals: IPS pair, LAN unknown, LAN = WAN, VLAN parent already captured, no af-packet
    ips = "af-packet:\n  - interface: wan0\n    copy-mode: ips\n    copy-iface: lan0\n  - interface: lan0\n" \
          "    copy-mode: ips\n    copy-iface: wan0\n"
    d = setup("ips", ips.replace("interface: lan0", "interface: lan9"), ifaces=("wan0", "lan0", "lan9"))
    rc, text, _o = run(d, "--add-lan")
    check(rc == 1 and "TuxWall" not in text, "--add-lan: an IPS (copy-mode) setup is never touched")
    d = setup("nolan", wan_only, ifaces=("wan0",), roles={"wan": {"device": "wan0"}})
    rc, text, _o = run(d, "--add-lan")
    check(rc == 1 and "TuxWall" not in text,
          "--add-lan: no LAN interface on this system -> untouched")
    d = setup("vlan", wan_only.replace("interface: wan0", "interface: lan0", 1), ifaces=("wan0", "lan0", "lan0.10"),
              roles={"wan": "wan0", "lan": {"device": "lan0.10"}})
    rc, _t, _o = run(d, "--add-lan")
    check(rc == 1, "--add-lan: the VLAN's parent is captured already -> untouched (string 'wan' role accepted)")
    d = setup("noaf", "vars:\n  x: 1\n")
    check(run(d, "--add-lan")[0] == 1, "--add-lan: no af-packet section -> untouched")

    # the original placeholder rewrite still binds WAN + LAN
    d = setup("stock", STOCK)
    rc, text, out = run(d)
    check(rc == 0 and dw.suricata_capture(os.path.join(d, "suricata.yaml")) == ["wan0", "lan0"],
          "rewrite: placeholders -> WAN + LAN (%r)" % out)
    check(run(d)[0] == 1, "rewrite: existing interfaces -> untouched")

    # installers: fresh installs add the LAN capture
    post = open(os.path.join(ROOT, "pkg", "DEBIAN", "postinst")).read()
    inst = open(os.path.join(ROOT, "tuxwall-install.sh")).read()
    check("tune-suricata.py --add-lan" in post and 'FRESH_INSTALL' in post, "postinst: --add-lan on fresh installs")
    check("scripts/tune-suricata.py" in inst and '"$tune" --add-lan /etc/suricata/suricata.yaml' in inst,
          "tuxwall-install.sh: --add-lan once the LAN is configured")

    shutil.rmtree(TMP, ignore_errors=True)
    print("suricata_tune_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
