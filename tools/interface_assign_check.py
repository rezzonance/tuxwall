#!/usr/bin/env python3
"""Interface assignments: render, validation and sandboxed apply tests.

Every test builds a private sandbox tree (etc/netplan, etc/kea, etc/ufw,
...) for a sample topology and points the plan/apply engine at it with
root=<sandbox>. Service commands go to a mock runner. Nothing touches the
live configuration or runs a real reload.

  python3 tools/interface_assign_check.py           pure tests (CI)
  sudo python3 tools/interface_assign_check.py --tools
      also validates the rendered files with netplan generate, kea-dhcp4 -t
      (temp file under /etc/kea, deleted), radvd --configtest,
      iptables-restore --test and unbound-checkconf.
"""
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "www", "includes"))
import topology as T  # noqa: E402
import assign_plan as P  # noqa: E402
import assign_apply as A  # noqa: E402

FAILS = []
COUNT = [0]


def check(cond, msg):
    COUNT[0] += 1
    if not cond:
        FAILS.append(msg)
        print("FAIL", msg)


# ---------------------------------------------------------------- samples

UFW_HEAD = {"v4": "*filter\n:ufw-user-input - [0:0]\n:ufw-user-output - [0:0]\n:ufw-user-forward - [0:0]\n"
                  ":ufw-user-limit - [0:0]\n:ufw-user-limit-accept - [0:0]\n### RULES ###\n\n",
            "v6": "*filter\n:ufw6-user-input - [0:0]\n:ufw6-user-output - [0:0]\n:ufw6-user-forward - [0:0]\n"
                  ":ufw6-user-limit - [0:0]\n:ufw6-user-limit-accept - [0:0]\n### RULES ###\n\n"}
UFW_TAIL = {"v4": "### END RULES ###\n\n### RATE LIMITING ###\n-A ufw-user-limit -j REJECT\n"
                  "-A ufw-user-limit-accept -j ACCEPT\n### END RATE LIMITING ###\nCOMMIT\n",
            "v6": "### END RULES ###\n\n### RATE LIMITING ###\n-A ufw6-user-limit -j REJECT\n"
                  "-A ufw6-user-limit-accept -j ACCEPT\n### END RATE LIMITING ###\nCOMMIT\n"}


def sample(kind):
    """(record, files) for a sample box. kind: 2nic | 3nic | vlan."""
    rec = {"version": 1, "wan": {"device": "eth0", "mode": "dhcp"},
           "lan": {"device": "eth1", "address": "10.10.1.1/24", "dhcp": True, "ra": True},
           "opt": [], "vpn": [], "policy": None, "apply_locked": False}
    eth = {"eth0": {"dhcp4": True, "dhcp6": True, "accept-ra": True},
           "eth1": {"dhcp4": False, "addresses": ["10.10.1.1/24", "fd00:10::1/64"], "optional": True}}
    kea_subs = [{"id": 1, "subnet": "10.10.1.0/24", "interface": "eth1",
                 "pools": [{"pool": "10.10.1.100-10.10.1.200"}],
                 "option-data": [{"name": "routers", "data": "10.10.1.1"},
                                 {"name": "domain-name-servers", "data": "10.10.1.1"}],
                 "reservations": [{"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "10.10.1.50"}]}]
    ifaces = ["eth1"]
    rules = [("allow", False, "eth1", "", "any", "any", "LAN to router"),
             ("allow", True, "eth1", "eth0", "any", "any", "LAN -> WAN")]
    ub_if = ["10.10.1.1"]
    ub_acl = ["10.10.1.0/24"]
    vlans = {}
    home = ["10.10.1.0/24"]
    if kind in ("3nic", "vlan"):
        dev = "eth2" if kind == "3nic" else "eth1.20"
        o = {"id": "opt1", "name": "IoT", "device": dev, "address": "10.10.20.1/24", "dhcp": True, "ra": False}
        if kind == "vlan":
            o.update(vlan=20, parent="eth1")
            vlans[dev] = {"id": 20, "link": "eth1", "addresses": ["10.10.20.1/24"]}
        else:
            eth["eth2"] = {"addresses": ["10.10.20.1/24"], "optional": True}
        rec["opt"].append(o)
        kea_subs.append({"id": 2, "subnet": "10.10.20.0/24", "interface": dev,
                         "pools": [{"pool": "10.10.20.20-10.10.20.254"}],
                         "option-data": [{"name": "routers", "data": "10.10.20.1"}]})
        ifaces.append(dev)
        rules += [("allow", True, dev, "eth0", "any", "any", ""),
                  ("allow", False, dev, "", "any", "53", ""),
                  ("allow", False, dev, "", "udp", "67", ""),
                  ("deny", True, dev, "eth1", "any", "any", "")]
        ub_if.append("10.10.20.1")
        ub_acl.append("10.10.20.0/24")
        home.append("10.10.20.0/24")
    ufw = {}
    for fam in ("v4", "v6"):
        ufw[fam] = UFW_HEAD[fam] + "".join(
            P.ufw_block(fam, route, act, iin, iout, proto=proto, dport=port, comment=c)
            for act, route, iin, iout, proto, port, c in rules) + UFW_TAIL[fam]
    netplan = {"network": {"version": 2, "renderer": "networkd", "ethernets": eth}}
    files = {
        "/etc/netplan/50-cloud-init.yaml": P._yaml_dump(netplan),
        "/etc/kea/kea-dhcp4.conf": json.dumps({"Dhcp4": {
            "interfaces-config": {"interfaces": ifaces},
            "lease-database": {"type": "memfile", "persist": False},
            "valid-lifetime": 86400, "subnet4": kea_subs}}, indent=4),
        "/etc/radvd.conf": "interface eth1 {\n    AdvSendAdvert on;\n    prefix fd00:10::/64 {\n"
                           "        AdvOnLink on;\n        AdvAutonomous on;\n    };\n};\n",
        "/etc/unbound/unbound.conf": 'server:\n    chroot: ""\n    directory: "/etc/unbound"\n    username: ""\n'
                                     '    pidfile: ""\n    use-syslog: no\n'
                                     'include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"\n',
        "/etc/unbound/unbound.conf.d/router-dns.conf": "server:\n    interface: 127.0.0.1\n" +
            "".join("    interface: %s\n" % a for a in ub_if) +
            "    access-control: 127.0.0.0/8 allow\n" +
            "".join("    access-control: %s allow\n" % a for a in ub_acl) +
            "    access-control: 0.0.0.0/0 refuse\n"
            '    local-data: "router.home.arpa. IN A 10.10.1.1"\n',
        "/etc/ufw/user.rules": ufw["v4"],
        "/etc/ufw/user6.rules": ufw["v6"],
        "/etc/ufw/before.rules": "*filter\n:ufw-before-input - [0:0]\n:ufw-before-output - [0:0]\n"
                                 ":ufw-before-forward - [0:0]\n"
                                 "-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
                                 "-A ufw-before-forward -i eth0 -j DROP\nCOMMIT\n",
        "/etc/ufw/before6.rules": "*filter\n:ufw6-before-forward - [0:0]\n"
                                  "-A ufw6-before-forward -i eth0 -j DROP\nCOMMIT\n",
        "/etc/default/ufw": 'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_FORWARD_POLICY="DROP"\n',
        "/etc/avahi/avahi-daemon.conf": "[server]\nuse-ipv4=yes\ndeny-interfaces=eth0\n",
        "/etc/suricata/suricata.yaml": 'vars:\n  address-groups:\n    HOME_NET: "[%s]"\naf-packet:\n'
                                       '  - interface: eth0\n  - interface: eth1\n  - interface: default\n' % ",".join(home),
        "/etc/tuxwall/sqm.conf": "WAN=eth0\nUP_RATE=100mbit\n",
        "/etc/tuxwall/interfaces.json": json.dumps(rec, indent=2) + "\n",
    }
    if vlans:
        files["/etc/netplan/99-tuxwall-vlans.yaml"] = P._yaml_dump({"network": {"version": 2, "vlans": vlans}})
        files["/etc/tuxwall/vlans.json"] = json.dumps({"eth1.20": {"label": "IoT", "address": "10.10.20.1/24",
                                                                   "vlan_id": 20, "parent": "eth1"}}, indent=2)
    return rec, files


class Box(object):
    def __init__(self, kind, raw=None):
        self.kind = kind
        self.rec, files = sample(kind)
        self.root = tempfile.mkdtemp(prefix="tw-assign-test-")
        for p, t in files.items():
            full = self.root + p
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as f:
                f.write(t)
        os.makedirs(self.root + "/sys/class/net", exist_ok=True)
        for d in ("eth0", "eth1", "eth2", "eth3"):
            os.makedirs(self.root + "/sys/class/net/" + d, exist_ok=True)
        self.raw = raw or []

    def ctx(self, validate=False):
        return P.Ctx(root=self.root, raw=copy.deepcopy(self.raw), validate=validate)

    def plan(self, body, ip="", validate=False):
        T.SYS_NET = self.root + "/sys/class/net"
        return P.plan(body, session_ip=ip, ctx=self.ctx(validate))

    def read(self, p):
        with open(self.root + p) as f:
            return f.read()

    def digest(self):
        h = hashlib.sha256()
        for base, dirs, files in sorted(os.walk(self.root + "/etc")):
            dirs.sort()
            for n in sorted(files):
                fp = os.path.join(base, n)
                h.update(fp.encode())
                with open(fp, "rb") as f:
                    h.update(f.read())
        return h.hexdigest()

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


def topo(box):
    return copy.deepcopy(box.rec)


def matrix(box):
    """The derived matrix of the sandbox's current rules (as the editor would send it)."""
    ctx = box.ctx()
    texts = {"v4": ctx.read(T.UFW_USER[0]), "v6": ctx.read(T.UFW_USER[1])}
    rec = ctx.record()
    wan_drop = [l.split()[3] for l in ctx.read("/etc/ufw/before.rules").splitlines()
                if l.startswith("-A ufw-before-forward -i ") and l.endswith("-j DROP")]
    pol = T.current_policy(rec, rules=T._ufw_tuples(texts), raw=box.raw, wan_drop=wan_drop)
    return pol


def states(pol):
    return {s: {d: c["state"] for d, c in row.items()} for s, row in pol["cells"].items()}


class Runner(object):
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on

    def __call__(self, cmd):
        self.calls.append(" ".join(cmd))
        if self.fail_on and self.fail_on in " ".join(cmd):
            return 1, "mock failure"
        return 0, ""


# ---------------------------------------------------------------- tests

def t_no_changes():
    for kind in ("2nic", "3nic", "vlan"):
        b = Box(kind)
        r = b.plan({})
        check(r["ok"] and r["summary"] == "No changes" and not r["files"], "%s: empty plan has changes: %s" % (kind, r.get("summary")))
        r = b.plan({"topology": topo(b), "policy": states(matrix(b))})
        check(r["ok"] and r["summary"] == "No changes", "%s: echoed topology+matrix has changes: %s %s" % (kind, r.get("summary"), r.get("changes")))
        b.close()


def t_lan_readdress():
    b = Box("2nic")
    t = topo(b)
    t["lan"]["address"] = "10.20.0.1/16"
    r = b.plan({"topology": t}, ip="10.10.1.77")
    paths = [f["path"] for f in r["files"]]
    check(r["ok"], "readdress: plan failed %s" % r.get("error"))
    check(paths[0].startswith("/etc/netplan/"), "readdress: netplan is not first: %s" % paths)
    order = [P.STEP_INDEX[f["step"]] for f in r["files"]]
    check(order == sorted(order), "readdress: files not in apply order")
    kea = json.loads(P.build({"topology": t}, "", b.ctx()).files["/etc/kea/kea-dhcp4.conf"]["new"])
    s = kea["Dhcp4"]["subnet4"][0]
    check(s["subnet"] == "10.20.0.0/16", "readdress: kea subnet %s" % s["subnet"])
    check(s["option-data"][0]["data"] == "10.20.0.1", "readdress: kea routers %s" % s["option-data"])
    check(s["reservations"] == [], "readdress: out-of-subnet reservation kept")
    check(any("reservation" in w for w in r["warnings"]), "readdress: no reservation warning")
    check(r["lockout"] and any("10.10.1.77" in w for w in r["warnings"]), "readdress: no session warning")
    d = r["diffs"]
    check("+    interface: 10.20.0.1" in d.get("/etc/unbound/unbound.conf.d/router-dns.conf", ""), "readdress: unbound interface")
    check("+    access-control: 10.20.0.0/16 allow" in d.get("/etc/unbound/unbound.conf.d/router-dns.conf", ""), "readdress: unbound acl")
    check("IN A 10.20.0.1" in d.get("/etc/unbound/unbound.conf.d/router-dns.conf", ""), "readdress: local-data")
    check("10.20.0.1/16" in d.get("/etc/netplan/50-cloud-init.yaml", ""), "readdress: netplan address")
    check("10.20.0.0/16" in d.get("/etc/suricata/suricata.yaml", ""), "readdress: HOME_NET")
    b.close()


def t_add_opt():
    b = Box("2nic")
    t = topo(b)
    t["opt"].append({"name": "Guest", "device": "eth2", "address": "10.10.30.1/24", "dhcp": True, "ra": True,
                     "pool": "10.10.30.50-10.10.30.99"})
    r = b.plan({"topology": t, "presets": {"opt1": "guest"}})
    check(r["ok"], "add-opt: %s" % r.get("error"))
    res = P.build({"topology": t, "presets": {"opt1": "guest"}}, "", b.ctx())
    kea = json.loads(res.files["/etc/kea/kea-dhcp4.conf"]["new"])["Dhcp4"]
    check(kea["interfaces-config"]["interfaces"] == ["eth1", "eth2"], "add-opt: kea ifaces %s" % kea["interfaces-config"])
    check(kea["subnet4"][1]["id"] == 2 and kea["subnet4"][1]["pools"] == [{"pool": "10.10.30.50-10.10.30.99"}], "add-opt: kea subnet")
    check("interface eth2 {" in res.files["/etc/radvd.conf"]["new"], "add-opt: radvd block")
    ub = res.files["/etc/unbound/unbound.conf.d/router-dns.conf"]["new"]
    check("interface: 10.10.30.1" in ub and "access-control: 10.10.30.0/24 allow" in ub, "add-opt: unbound")
    m = r["matrix_after"]
    check(m["opt1"]["wan"] == "allow" and m["opt1"]["gw"] == "dns_dhcp" and m["opt1"]["lan"] == "block"
          and m["lan"]["opt1"] == "block", "add-opt: guest preset matrix %s" % m.get("opt1"))
    check("tuxwall-policy:opt1->wan".encode().hex() in res.files["/etc/ufw/user.rules"]["new"], "add-opt: tagged rule")
    np = res.files.get("/etc/netplan/90-tuxwall.yaml", {}).get("new", "") or res.files.get("/etc/netplan/50-cloud-init.yaml", {}).get("new", "")
    check("10.10.30.1/24" in np, "add-opt: netplan address")
    b.close()


def t_vlan():
    b = Box("2nic")
    t = topo(b)
    t["opt"].append({"name": "Cameras", "vlan": 30, "parent": "eth1", "address": "10.10.31.1/24", "dhcp": True, "ra": False})
    res = P.build({"topology": t}, "", b.ctx())
    check(res.validation["ok"], "vlan: invalid %s" % res.validation)
    np = res.files.get("/etc/netplan/99-tuxwall-vlans.yaml", {}).get("new", "")
    check("eth1.30:" in np and "id: 30" in np and "link: eth1" in np, "vlan: netplan vlan file %r" % np)
    vj = json.loads(res.files["/etc/tuxwall/vlans.json"]["new"])
    check(vj.get("eth1.30", {}).get("vlan_id") == 30, "vlan: vlans.json")
    t2 = topo(b)
    t2["opt"].append({"name": "Bad", "vlan": 5000, "parent": "eth1", "address": "10.10.32.1/24"})
    check(not P.build({"topology": t2}, "", b.ctx()).validation["ok"], "vlan: id 5000 accepted")
    t3 = topo(b)
    t3["opt"].append({"name": "Orphan", "vlan": 31, "parent": "eth9", "address": "10.10.33.1/24"})
    T.SYS_NET = b.root + "/sys/class/net"
    check(not P.build({"topology": t3}, "", b.ctx()).validation["ok"], "vlan: missing parent accepted")
    b.close()
    # removing a VLAN network
    b = Box("vlan")
    t = topo(b)
    t["opt"] = []
    res = P.build({"topology": t}, "", b.ctx())
    np = res.files.get("/etc/netplan/99-tuxwall-vlans.yaml", {}).get("new", "")
    check("eth1.20" not in np, "vlan-remove: still in netplan")
    k = json.loads(res.files["/etc/kea/kea-dhcp4.conf"]["new"])["Dhcp4"]
    check(k["interfaces-config"]["interfaces"] == ["eth1"] and len(k["subnet4"]) == 1, "vlan-remove: kea")
    check("eth1.20" not in res.files["/etc/ufw/user.rules"]["new"], "vlan-remove: ufw rules kept")
    check("10.10.20" not in res.files["/etc/unbound/unbound.conf.d/router-dns.conf"]["new"], "vlan-remove: unbound")
    b.close()


def t_swap():
    b = Box("3nic")
    t = topo(b)
    t["wan"]["device"], t["lan"]["device"] = "eth1", "eth0"
    res = P.build({"topology": t}, "", b.ctx())
    check(res.validation["ok"] and not res.errors, "swap: %s %s" % (res.validation, res.errors))
    u = res.files["/etc/ufw/user.rules"]["new"]
    check("in_eth0!out_eth1 comment=" in u and "-A ufw-user-forward -i eth0 -o eth1 -j ACCEPT" in u, "swap: LAN->WAN rule")
    check("in_eth2!out_eth1" in u and "-i eth2 -o eth0 -j DROP" in u, "swap: opt rules follow")
    check("-i eth1 -j DROP" in res.files["/etc/ufw/before.rules"]["new"], "swap: WAN drop follows")
    check(res.files["/etc/tuxwall/sqm.conf"]["new"].startswith("WAN=eth1"), "swap: sqm")
    check("deny-interfaces=eth1" in res.files["/etc/avahi/avahi-daemon.conf"]["new"], "swap: avahi")
    np = T._yaml_load(res.files["/etc/netplan/50-cloud-init.yaml"]["new"])["network"]["ethernets"]
    check(np["eth1"].get("dhcp4") is True and "addresses" not in np["eth1"], "swap: netplan WAN %s" % np["eth1"])
    check("10.10.1.1/24" in np["eth0"].get("addresses", []), "swap: netplan LAN %s" % np["eth0"])
    k = json.loads(res.files["/etc/kea/kea-dhcp4.conf"]["new"])["Dhcp4"]
    check(k["subnet4"][0]["interface"] == "eth0" and k["interfaces-config"]["interfaces"][0] == "eth0", "swap: kea")
    check("interface eth0 {" in res.files["/etc/radvd.conf"]["new"], "swap: radvd")
    check(any("WireGuard" in w for w in res.warnings), "swap: no endpoint warning")
    # LAN <-> OPT swap of devices (kea must not cross the subnets)
    t = topo(b)
    t["lan"]["device"], t["opt"][0]["device"] = "eth2", "eth1"
    k = json.loads(P.build({"topology": t}, "", b.ctx()).files["/etc/kea/kea-dhcp4.conf"]["new"])["Dhcp4"]
    check([(s["subnet"], s["interface"]) for s in k["subnet4"]] == [("10.10.1.0/24", "eth2"), ("10.10.20.0/24", "eth1")],
          "swap lan/opt: kea %s" % [(s["subnet"], s["interface"]) for s in k["subnet4"]])
    b.close()


def t_validation():
    b = Box("3nic")
    cases = [
        (lambda t: t["lan"].update(pool="10.10.1.1-10.10.1.50"), "gateway"),
        (lambda t: t["lan"].update(pool="10.10.2.10-10.10.2.50"), "not inside"),
        (lambda t: t["lan"].update(pool="10.10.1.90-10.10.1.80"), "start is after"),
        (lambda t: t["opt"][0].update(address="10.10.1.129/25"), "overlap"),
        (lambda t: t["opt"][0].update(device="eth1"), "assigned twice"),
        (lambda t: t["lan"].update(device=""), "No LAN"),
        (lambda t: t["lan"].update(address="127.0.0.2/8"), "reserved"),
        (lambda t: t["wan"].update(mode="static", address="nonsense"), "static WAN"),
    ]
    for fn, word in cases:
        t = topo(b)
        fn(t)
        r = b.plan({"topology": t})
        check(not r["ok"] and word.lower() in r.get("error", "").lower(), "validation '%s': %s" % (word, r.get("error")))
    r = b.plan({"policy": {"lan": {"opt1": "dns_dhcp"}}})
    check(not r["ok"] and "Gateway column" in r.get("error", ""), "validation: dns_dhcp in forward column")
    r = b.plan({"policy": {"wan": {"lan": "allow"}}})
    check(not r["ok"] and "Port forwarding" in r.get("error", ""), "validation: WAN allow")
    b.close()


def t_policy_edits():
    b = Box("3nic")
    before = states(matrix(b))
    check(before["opt1"]["lan"] == "block" and before["lan"]["opt1"] == "block", "policy: sample matrix %s" % before)
    body = {"policy": {"opt1": {"lan": "allow"}, "lan": {"gw": "dns_dhcp"}}}
    r = b.plan(body, ip="10.10.1.9")
    check(r["ok"] and r["matrix_after"]["opt1"]["lan"] == "allow" and r["matrix_after"]["lan"]["gw"] == "dns_dhcp",
          "policy: after %s" % r.get("matrix_after", {}).get("opt1"))
    check(r["lockout"], "policy: lan->gw restriction from the LAN is not flagged")
    u = r["diffs"]["/etc/ufw/user.rules"]
    # the tagged allow must land before the old deny (first match wins)
    nu = P.build(body, "", b.ctx()).files["/etc/ufw/user.rules"]["new"]
    i_tag = nu.find("tuxwall-policy:opt1->lan".encode().hex())
    i_old = nu.find("-A ufw-user-forward -i eth2 -o eth1 -j DROP")
    check(0 <= i_tag < i_old, "policy: tagged rule not before the old deny")
    check("+### tuple ### allow any 53 0.0.0.0/0 any 0.0.0.0/0 in_eth1" in u, "policy: dns rule text")
    check("-A ufw-user-input -i eth1 -p tcp --dport 53 -j ACCEPT" in nu and
          "-A ufw-user-input -i eth1 -p udp --dport 53 -j ACCEPT" in nu, "policy: dns tcp+udp")
    # apply in the sandbox, then the same edit is a no-op; a new edit replaces the tagged rule exactly
    code, out = A.apply(dict(body, plan_hash=r["plan_hash"], ack_lockout=True), "10.10.1.9", root=b.root,
                        runner=Runner(), schedule=lambda *a: None)
    check(code == 200, "policy: sandbox apply %s %s" % (code, out))
    A.confirm(out.get("id"))
    r2 = b.plan(body)
    check(r2["summary"] == "No changes", "policy: re-plan after apply is not empty: %s" % r2.get("changes"))
    r3 = b.plan({"policy": {"opt1": {"lan": "block"}}})
    nu3 = P.build({"policy": {"opt1": {"lan": "block"}}}, "", b.ctx()).files["/etc/ufw/user.rules"]["new"]
    check(nu3.count("tuxwall-policy:opt1->lan".encode().hex()) == 1, "policy: tagged rule not replaced exactly")
    check(r3["matrix_after"]["opt1"]["lan"] == "block", "policy: replace")
    rec = json.loads(b.read(T.CONF))
    check(rec["policy"]["cells"]["opt1"]["lan"] == "allow", "policy: record cells %s" % rec.get("policy"))
    b.close()


def t_raw_wg():
    raw = [{"family": "v4", "dir": "in", "dev": "wg0", "target": "ACCEPT", "text": "-A FORWARD -i wg0 -j ACCEPT"},
           {"family": "v4", "dir": "out", "dev": "wg0", "target": "ACCEPT", "text": "-A FORWARD -o wg0 -j ACCEPT"}]
    b = Box("3nic", raw=raw)
    rec = json.loads(b.read(T.CONF))
    rec["vpn"] = [{"id": "wg0", "name": "WireGuard", "device": "wg0", "address": "10.99.0.1/24"}]
    with open(b.root + T.CONF, "w") as f:
        json.dump(rec, f)
    b.rec = rec
    check(b.plan({})["summary"] == "No changes", "raw: empty plan")
    m = states(matrix(b))
    check(m["wg0"]["lan"] == "allow" and m["opt1"]["wg0"] == "allow", "raw: derived %s" % m["wg0"])
    t = topo(b)
    t["opt"].append({"name": "Guest", "device": "eth3", "address": "10.10.50.1/24", "dhcp": True, "ra": False})
    r = b.plan({"topology": t, "presets": {"opt2": "guest"}})
    check(r["ok"] and not r["raw_replaced"] and r["matrix_after"]["opt2"]["wg0"] == "allow",
          "raw: a preset on a new network must not replace the raw rules")
    r = b.plan({"policy": {"opt1": {"wg0": "block"}}})
    check(r["ok"] and r["raw_replaced"], "raw: not replaced %s" % r.get("error"))
    acts = [g["actions"] for g in r["changes"] if g["step"] == "ufw"][0]
    check("iptables -D FORWARD -i wg0 -j ACCEPT" in acts and "iptables -D FORWARD -o wg0 -j ACCEPT" in acts, "raw: actions %s" % acts)
    check(any("bypass ufw" in w for w in r["warnings"]), "raw: warning")
    ma = r["matrix_after"]
    check(ma["opt1"]["wg0"] == "block" and ma["wg0"]["lan"] == "allow" and ma["lan"]["wg0"] == "allow"
          and ma["wg0"]["opt1"] == "allow", "raw: preserved cells %s / %s" % (ma["wg0"], ma["lan"]))
    rec_new = json.loads(P.build({"policy": {"opt1": {"wg0": "block"}}}, "", b.ctx()).files[T.CONF]["new"])
    check(rec_new["policy"].get("wg_raw_forward") is False, "raw: record flag")
    # sandbox apply runs the raw deletion, rollback re-inserts it
    run = Runner()
    code, out = A.apply({"policy": {"opt1": {"wg0": "block"}}, "plan_hash": r["plan_hash"]}, root=b.root,
                        runner=run, schedule=lambda *a: None, raw=raw)
    check(code == 200 and "iptables -D FORWARD -i wg0 -j ACCEPT" in run.calls, "raw: apply %s %s" % (code, run.calls))
    A.rollback(out.get("id"))
    check("iptables -I FORWARD 1 -i wg0 -j ACCEPT" in run.calls, "raw: rollback re-insert %s" % run.calls[-6:])
    b.close()


def t_apply_sandbox():
    b = Box("3nic")
    t = topo(b)
    t["opt"][0]["address"] = "10.10.40.1/24"
    body = {"topology": t}
    r = b.plan(body)
    # locked: 423 and nothing written
    rec = json.loads(b.read(T.CONF))
    rec["apply_locked"] = True
    with open(b.root + T.CONF, "w") as f:
        json.dump(rec, f)
    h_locked = b.digest()
    run = Runner()
    code, out = A.apply(dict(body, plan_hash=r["plan_hash"]), root=b.root, runner=run)
    check(code == 423 and out.get("locked") and "apply_locked=false" in out["error"], "lock: %s %s" % (code, out))
    check(b.digest() == h_locked and not run.calls, "lock: something was touched")
    check(not os.path.exists(b.root + A.SNAP_DIR), "lock: snapshot written")
    rec2 = dict(rec)
    rec2.pop("apply_locked")
    with open(b.root + T.CONF, "w") as f:
        json.dump(rec2, f)
    check(A.apply(dict(body, plan_hash=r["plan_hash"]), root=b.root, runner=run)[0] == 423, "lock: missing flag must lock")
    rec["apply_locked"] = False
    with open(b.root + T.CONF, "w") as f:
        f.write(json.dumps(rec, indent=2) + "\n")
    r = b.plan(body)
    h0 = b.digest()
    # stale hash
    code, out = A.apply(dict(body, plan_hash="0000"), root=b.root, runner=run)
    check(code == 409 and b.digest() == h0, "hash: %s" % code)
    # apply -> rollback (manual)
    run = Runner()
    code, out = A.apply(dict(body, plan_hash=r["plan_hash"]), root=b.root, runner=run, schedule=lambda *a: None)
    check(code == 200 and b.digest() != h0, "apply: %s %s" % (code, out.get("error")))
    want = ["ufw status numbered", "iptables-save", "ip6tables-save", "netplan apply",
            "systemctl restart kea-dhcp4-server", "systemctl restart unbound", "ufw reload"]
    seq = [c for c in run.calls if c in want]
    check(seq == want, "apply: action order %s" % run.calls)
    check("10.10.40.0/24" in b.read("/etc/kea/kea-dhcp4.conf"), "apply: kea written")
    check(oct(os.stat(b.root + "/etc/netplan/50-cloud-init.yaml").st_mode & 0o777) == "0o600", "apply: netplan mode")
    check(A.apply(dict(body, plan_hash=r["plan_hash"]), root=b.root, runner=run)[0] == 409, "apply: second pending apply allowed")
    code, out2 = A.rollback(out["id"])
    check(code == 200 and b.digest() == h0, "rollback: files differ after manual rollback")
    hist = [json.loads(l)["event"] for l in open(b.root + A.HISTORY)]
    check(hist[-3:] == ["apply-start", "apply-done", "rolled-back"], "audit: %s" % hist)
    # timeout rollback
    code, out = A.apply(dict(body, plan_hash=r["plan_hash"]), root=b.root, runner=Runner(), ttl=0.3)
    time.sleep(0.8)
    check(code == 200 and b.digest() == h0 and not A.pending(), "timeout: not rolled back")
    # confirm keeps it
    code, out = A.apply(dict(body, plan_hash=r["plan_hash"]), root=b.root, runner=Runner(), ttl=0.3)
    check(code == 200, "confirm: apply %s %s" % (code, out))
    A.confirm(out.get("id"))
    time.sleep(0.6)
    check(b.digest() != h0 and "10.10.40.1/24" in b.read(T.CONF), "confirm: change not kept")
    b.close()
    # a failing service reload rolls back at once
    b = Box("3nic")
    r = b.plan(body)
    h0 = b.digest()
    run = Runner(fail_on="kea-dhcp4-server")
    code, out = A.apply(dict(body, plan_hash=r["plan_hash"]), root=b.root, runner=run)
    check(code == 500 and b.digest() == h0 and not A.pending(), "fail: not rolled back (%s)" % code)
    check(run.calls.count("netplan apply") == 2, "fail: services not reloaded after restore %s" % run.calls)
    # apply after reboot: files only
    run = Runner()
    code, out = A.apply(dict(body, plan_hash=r["plan_hash"], after_reboot=True), root=b.root, runner=run)
    check(code == 200 and out["after_reboot"] and not [c for c in run.calls if "restart" in c or "apply" in c],
          "after-reboot: services touched %s" % run.calls)
    A.rollback(out["id"])
    check(b.digest() == h0, "after-reboot: rollback")
    # lockout needs an explicit ack
    t2 = topo(b)
    t2["lan"]["address"] = "10.10.5.1/24"
    r = b.plan({"topology": t2}, ip="10.10.1.20")
    code, out = A.apply({"topology": t2, "plan_hash": r["plan_hash"]}, "10.10.1.20", root=b.root, runner=Runner())
    check(code == 409 and out.get("lockout") and b.digest() == h0, "lockout: no ack needed")
    b.close()


def t_tools():
    """Real validators on rendered sandbox configs (root, tools installed)."""
    for kind, edit in (("2nic", lambda t: t["lan"].update(address="10.30.0.1/24")),
                       ("3nic", lambda t: t.update(wan=dict(t["wan"], device="eth1"), lan=dict(t["lan"], device="eth0"))),
                       ("vlan", lambda t: t["opt"].append({"name": "Cam", "vlan": 40, "parent": "eth1",
                                                            "address": "10.10.41.1/24", "dhcp": True, "ra": True}))):
        b = Box(kind)
        t = topo(b)
        edit(t)
        r = b.plan({"topology": t, "policy": {"lan": {"wan": "allow"}}}, validate=True)
        check(r["ok"], "tools %s: %s" % (kind, r.get("error")))
        for v in r.get("validators", []):
            if v["skipped"]:
                print("  skip %-34s %s" % (v["tool"], v["output"][:60]))
                continue
            check(v["ok"], "tools %s: %s failed: %s" % (kind, v["tool"], v["output"][:300]))
            print("  %-4s %-40s %s" % ("ok" if v["ok"] else "FAIL", v["tool"], kind))
        b.close()
    check(not [n for n in os.listdir("/etc/kea") if n.startswith(".tuxwall-plan-")], "tools: kea temp file left")


def main():
    tests = [t_no_changes, t_lan_readdress, t_add_opt, t_vlan, t_swap, t_validation, t_policy_edits, t_raw_wg,
             t_apply_sandbox]
    if "--tools" in sys.argv:
        tests.append(t_tools)
    for fn in tests:
        n = len(FAILS)
        fn()
        print("%-18s %s" % (fn.__name__, "ok" if len(FAILS) == n else "FAILED"))
    print("%d checks, %d failed" % (COUNT[0], len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
