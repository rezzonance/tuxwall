"""TuxWall interface assignments: plan engine (read-only).

plan(body) compares a requested topology (and policy-matrix edits) with
the current one, renders every affected config file in apply order,
validates the rendered files with their own tools inside a temp dir and
returns plain-language changes, unified diffs and warnings.

Nothing here writes outside a private temp dir, except one short-lived
temp file under /etc/kea (AppArmor only lets kea-dhcp4 read there) that
is always deleted again. build() is shared with assign_apply.py.

ctx.root (default "") prefixes every path, so tests run against a
sandbox copy of /etc instead of the live files.
"""
import copy
import difflib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

import topology as T

NETPLAN_MANAGED = "/etc/netplan/90-tuxwall.yaml"
NETPLAN_VLANS = "/etc/netplan/99-tuxwall-vlans.yaml"
UNBOUND_MAIN = "/etc/unbound/unbound.conf"
UNBOUND_ROUTER = T.UNBOUND_DIR + "/router-dns.conf"
UFW_BEFORE = ("/etc/ufw/before.rules", "/etc/ufw/before6.rules")
KEA_LEASES = "/var/lib/kea/kea-leases4.csv"
TAG = "tuxwall-policy:"

STEPS = [
    ("netplan", "Network interfaces (netplan)"),
    ("kea", "DHCP server (Kea)"),
    ("radvd", "IPv6 router advertisements (radvd)"),
    ("unbound", "DNS resolver (Unbound)"),
    ("ufw", "Firewall (ufw) and policy matrix"),
    ("nat", "NAT (tuxwall-nat)"),
    ("avahi", "mDNS (Avahi)"),
    ("suricata", "IDS (Suricata)"),
    ("sqm", "Traffic shaping (SQM)"),
    ("honeypot", "Honeypot / canary"),
    ("record", "Interface record"),
]
STEP_TITLE = dict(STEPS)
STEP_INDEX = {s: i for i, (s, _) in enumerate(STEPS)}

# service actions run by assign_apply after the files are written
ACTIONS = {
    "netplan": [["netplan", "apply"]],
    "kea": [["systemctl", "restart", "kea-dhcp4-server"]],
    "radvd": [["systemctl", "restart", "radvd"]],
    "unbound": [["systemctl", "restart", "unbound"]],
    "ufw": [["ufw", "reload"]],
    "nat": [["systemctl", "daemon-reload"], ["systemctl", "restart", "tuxwall-nat"]],
    "avahi": [["systemctl", "restart", "avahi-daemon"]],
    "suricata": [["systemctl", "restart", "suricata"]],
    "sqm": [["systemctl", "restart", "tuxwall-sqm"]],
    "honeypot": [["systemctl", "restart", "opencanary"]],
    "record": [],
}

POLICY_STATES = ("allow", "block", "established", "dns_dhcp")
PRESETS = {
    # out: this network -> others; in: others -> this network
    "trusted": {"label": "Trusted LAN", "wan": "allow", "gw": "allow", "out": "allow", "in": "block", "in_lan": "allow"},
    "internet": {"label": "Internet only (IoT)", "wan": "allow", "gw": "dns_dhcp", "out": "block", "in": "block", "in_lan": "allow"},
    "guest": {"label": "Isolated guest", "wan": "allow", "gw": "dns_dhcp", "out": "block", "in": "block", "in_lan": "block"},
    "management": {"label": "Management", "wan": "block", "gw": "allow", "out": "allow", "in": "block", "in_lan": "block"},
}


class Ctx(object):
    """Where to read the current state. root="" is the live box."""

    def __init__(self, root="", raw=None, validate=True, now=None, aps=None):
        self.root = (root or "").rstrip("/")
        self._raw = raw
        self.validate = validate
        self.now = now or time.time()
        self._aps = aps  # None | dict | callable -> OpenWrt AP data (see ap_carriers)
        self._aps_done = False

    def aps(self):
        if not self._aps_done:
            self._aps_done = True
            if callable(self._aps):
                try:
                    self._aps = self._aps()
                except Exception:
                    self._aps = {"status": "error", "error": "access point lookup failed"}
        return self._aps if isinstance(self._aps, dict) else None

    def p(self, path):
        return self.root + path

    def read(self, path):
        return T._read(self.p(path))

    def exists(self, path):
        return os.path.exists(self.p(path))

    def listdir(self, d):
        try:
            return sorted(os.listdir(self.p(d)))
        except OSError:
            return []

    def record(self):
        if not self.root:
            return copy.deepcopy(T.load())
        d = T._read_json(self.p(T.CONF))
        return d if isinstance(d, dict) else {}

    def raw(self):
        if self._raw is None:
            self._raw = T._raw_forward() if not self.root else []
        return self._raw


# ---------------------------------------------------------------- model

def _iface(addr):
    try:
        if addr and "/" in str(addr):
            return ipaddress.ip_interface(str(addr))
    except ValueError:
        pass
    return None


def _nets(t):
    """id -> normalised network entry (wan, lan, opt*, vpn*)."""
    out = {}
    w = dict(t.get("wan") or {})
    if w.get("device"):
        w.update(id="wan", role="wan", ip=_iface(w.get("address")) if w.get("mode") == "static" else None)
        out["wan"] = w
    entries = []
    if (t.get("lan") or {}).get("device"):
        entries.append(("lan", "lan", t["lan"]))
    for o in t.get("opt") or []:
        entries.append((o.get("id") or o.get("device"), "opt", o))
    for v in t.get("vpn") or []:
        entries.append((v.get("id") or v.get("device"), "vpn", v))
    for nid, role, e in entries:
        n = dict(e)
        if n.get("vlan") and n.get("parent") and not n.get("device"):
            n["device"] = "%s.%s" % (n["parent"], n["vlan"])
        n.update(id=nid, role=role, ip=_iface(n.get("address")))
        n.setdefault("name", "LAN" if role == "lan" else nid.upper())
        out[nid] = n
    return out


class Model(object):
    """What changes between the current and the requested topology."""

    def __init__(self, cur, new):
        self.cur, self.new = cur, new
        self.old, self.nw = _nets(cur), _nets(new)
        self.dev_map, self.ip_map = {}, {}
        self.added = [i for i in self.nw if i not in self.old]
        self.removed = [i for i in self.old if i not in self.nw]
        self.kept = [i for i in self.nw if i in self.old]
        for i in self.kept:
            a, b = self.old[i], self.nw[i]
            if a["role"] == "vpn":
                continue
            if a.get("device") and b.get("device") and a["device"] != b["device"]:
                self.dev_map[a["device"]] = b["device"]
            if a["ip"] and b["ip"] and a["ip"] != b["ip"] and a["ip"].version == b["ip"].version:
                self.ip_map[a["ip"].with_prefixlen] = b["ip"].with_prefixlen
                self.ip_map[str(a["ip"].ip)] = str(b["ip"].ip)
                if a["ip"].network != b["ip"].network:
                    self.ip_map[str(a["ip"].network)] = str(b["ip"].network)
        self.removed_devs = {self.old[i]["device"] for i in self.removed if self.old[i].get("device")}

    def changed(self, i, *keys):
        a, b = self.old.get(i) or {}, self.nw.get(i) or {}
        return any(a.get(k) != b.get(k) for k in keys)

    @property
    def wan_changed(self):
        return self.changed("wan", "device", "mode", "address", "gateway")

    def subnet_moved(self, i):
        a, b = self.old.get(i), self.nw.get(i)
        return bool(a and b and a["ip"] and b["ip"] and a["ip"].network != b["ip"].network)

    def net_ids(self, role=None):
        return [i for i in self.nw if role is None or self.nw[i]["role"] == role]


_DEV_L = r"(?<![A-Za-z0-9.\-])"
_DEV_R = r"(?![A-Za-z0-9_\-]|\.[A-Za-z0-9])"


def _subst(text, dev_map=None, ip_map=None):
    """Replace device names and addresses as whole tokens, all at once
    (so a WAN/LAN swap does not chain)."""
    dev_map, ip_map = dev_map or {}, ip_map or {}
    pats = []
    if dev_map:
        pats.append(_DEV_L + "(?P<dev>%s)" % "|".join(re.escape(k) for k in sorted(dev_map, key=len, reverse=True)) + _DEV_R)
    if ip_map:
        pats.append(r"(?<![0-9.:])(?P<ip>%s)(?![0-9]|\.[0-9]|/[0-9])" % "|".join(
            re.escape(k) for k in sorted(ip_map, key=len, reverse=True)))
    if not pats or not text:
        return text
    return re.sub("|".join(pats), lambda x: dev_map[x.group("dev")] if x.groupdict().get("dev") else ip_map[x.group("ip")], text)


def _dev_re(dev):
    return re.compile(_DEV_L + re.escape(dev) + _DEV_R)


# ---------------------------------------------------------------- output

class Result(object):
    def __init__(self):
        self.files = {}      # path -> {step, old, new, mode, notes}
        self.changes = []    # {step, text}
        self.warnings = []
        self.errors = []
        self.extra_actions = []  # {step, cmd, undo}
        self.steps = set()
        self.lockout = False
        self.policy = None
        self.validators = []
        self.record = None
        self.lockout_cells = []

    def change(self, step, text):
        self.changes.append({"step": step, "text": text})
        self.steps.add(step)

    def file(self, step, path, old, new, mode=0o644):
        if old == new:
            return False
        self.files[path] = {"step": step, "old": old, "new": new, "mode": mode}
        self.steps.add(step)
        return True

    def warn(self, text):
        if text not in self.warnings:
            self.warnings.append(text)


# ---------------------------------------------------------------- netplan

ROLE_KEYS = ("addresses", "dhcp4", "dhcp6", "accept-ra", "nameservers", "dhcp4-overrides",
             "dhcp6-overrides", "routes", "gateway4", "gateway6", "routing-policy", "link-local",
             "ipv6-privacy")


def _yaml_dump(doc):
    import yaml

    class D(yaml.SafeDumper):
        def increase_indent(self, flow=False, indentless=False):
            return super(D, self).increase_indent(flow, False)
    return yaml.dump(doc, Dumper=D, sort_keys=False, default_flow_style=False)


def _keep_order(cfg, ref):
    order = list(ref or {})
    return dict(sorted(cfg.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else len(order)))


def r_netplan(ctx, m, res):
    if not (m.dev_map or m.ip_map or m.wan_changed or
            any(m.old[i]["role"] != "vpn" for i in m.removed) or
            any(m.nw[i]["role"] != "vpn" for i in m.added)):
        return
    names = [n for n in ctx.listdir(T.NETPLAN_DIR) if n.endswith(".yaml")]
    docs = {}
    for n in names:
        docs[n] = T._yaml_load(ctx.read(T.NETPLAN_DIR + "/" + n)) or {}
    new_docs = copy.deepcopy(docs)
    wan_new = m.nw.get("wan") or {}
    wan_old = m.old.get("wan") or {}
    removed_vlans = {m.old[i]["device"] for i in m.removed if m.old[i].get("vlan")}
    placed = set()
    for n in names:
        net = (new_docs[n] or {}).get("network")
        if not isinstance(net, dict):
            continue
        eth = net.get("ethernets")
        if isinstance(eth, dict):
            roles, out = {}, {}
            for dev, cfg in eth.items():
                cfg = cfg or {}
                out[dev] = {k: v for k, v in cfg.items() if k not in ROLE_KEYS}
                rp = {k: v for k, v in cfg.items() if k in ROLE_KEYS}
                if dev in m.removed_devs and dev not in m.dev_map:
                    rp = {}
                if rp:
                    roles[m.dev_map.get(dev, dev)] = rp
            for dev, rp in roles.items():
                rp = copy.deepcopy(rp)
                if isinstance(rp.get("addresses"), list):
                    rp["addresses"] = [m.ip_map.get(str(a), a) for a in rp["addresses"]]
                if dev == wan_new.get("device") and (m.wan_changed or dev in m.dev_map.values()):
                    _netplan_wan(rp, wan_old, wan_new)
                out.setdefault(dev, {}).update(rp)
                placed.add(dev)
            for dev in list(out):
                if not out[dev]:
                    out[dev] = {"optional": True}
                out[dev] = _keep_order(out[dev], eth.get(dev))
            net["ethernets"] = out
        vl = net.get("vlans")
        if isinstance(vl, dict):
            out = {}
            for dev, cfg in vl.items():
                if dev in removed_vlans and dev not in m.dev_map:
                    continue
                cfg = copy.deepcopy(cfg or {})
                nd = m.dev_map.get(dev, dev)
                ent = next((e for e in m.nw.values() if e.get("device") == nd), None)
                if ent and ent.get("vlan"):
                    cfg["id"], cfg["link"] = int(ent["vlan"]), ent.get("parent") or cfg.get("link")
                if isinstance(cfg.get("addresses"), list):
                    cfg["addresses"] = [m.ip_map.get(str(a), a) for a in cfg["addresses"]]
                out[nd] = cfg
                placed.add(nd)
            net["vlans"] = out
    # roles whose device has no netplan config yet
    for i in m.net_ids():
        e = m.nw[i]
        dev = e.get("device")
        if e["role"] == "vpn" or not dev or dev in placed:
            continue
        old = m.old.get(i) or {}
        if i in m.kept and old.get("device") == dev and not m.changed(i, "address", "mode"):
            continue  # unchanged and configured outside netplan
        if e.get("vlan"):
            n = os.path.basename(NETPLAN_VLANS)
            d = new_docs.setdefault(n, {"network": {"version": 2}})
            cfg = {"id": int(e["vlan"]), "link": e.get("parent")}
            if e["ip"]:
                cfg["addresses"] = [e["ip"].with_prefixlen]
            d["network"].setdefault("vlans", {})[dev] = cfg
            continue
        n = os.path.basename(NETPLAN_MANAGED)
        d = new_docs.setdefault(n, {"network": {"version": 2, "renderer": "networkd"}})
        cfg = {"optional": True}
        if i == "wan":
            _netplan_wan(cfg, {}, e)
        elif e["ip"]:
            cfg.update({"dhcp4": False, "addresses": [e["ip"].with_prefixlen]})
        d["network"].setdefault("ethernets", {})[dev] = cfg
    vn = os.path.basename(NETPLAN_VLANS)
    vd = (new_docs.get(vn) or {}).get("network")
    drop_vlans_file = False
    if isinstance(vd, dict) and new_docs.get(vn) != docs.get(vn):
        # like the old VLANs page: a VLAN parent must be defined somewhere
        defined = {d for doc in new_docs.values() for d in ((((doc or {}).get("network") or {}).get("ethernets")) or {})}
        for dev, cfg in (vd.get("vlans") or {}).items():
            lk = (cfg or {}).get("link")
            if lk and lk not in defined:
                vd.setdefault("ethernets", {})[lk] = {"optional": True}
                defined.add(lk)
        if not vd.get("vlans"):
            vd.pop("vlans", None)
        # parents keep their entry (e.g. optional: true); the file goes only when nothing is left
        drop_vlans_file = not vd.get("vlans") and not vd.get("ethernets") and set(vd) <= {"version", "renderer"}
    for n, doc in sorted(new_docs.items()):
        if doc == docs.get(n):
            continue
        path = T.NETPLAN_DIR + "/" + n
        old = ctx.read(path) if n in docs else None
        if n == vn and drop_vlans_file:
            if old is not None:
                res.file("netplan", path, old, None, 0o600)
            continue
        res.file("netplan", path, old, _yaml_dump(doc), 0o600)
        if old and "#" in old:
            res.warn("%s is rewritten from its parsed form: its comments are not kept "
                     "(the snapshot keeps the original)." % path)
    for i in m.kept:
        if m.dev_map.get((m.old[i] or {}).get("device")):
            res.change("netplan", "%s moves from %s to %s." % (m.nw[i]["name"] if i != "wan" else "WAN",
                                                              m.old[i]["device"], m.nw[i]["device"]))
        if m.old[i]["ip"] != m.nw[i]["ip"] and m.nw[i]["role"] != "wan" and m.nw[i]["ip"]:
            res.change("netplan", "%s address %s -> %s." % (m.nw[i]["name"], m.old[i].get("address") or "none",
                                                            m.nw[i]["ip"].with_prefixlen))
    if m.changed("wan", "mode", "address", "gateway"):
        res.change("netplan", "WAN becomes %s." % (
            "a DHCP client" if wan_new.get("mode") != "static" else "static %s" % wan_new.get("address")))
    for i in m.added:
        if m.nw[i]["role"] != "vpn":
            res.change("netplan", "New network %s on %s (%s)." % (m.nw[i]["name"], m.nw[i]["device"],
                                                                 m.nw[i].get("address") or "no address"))
    for i in m.removed:
        if m.old[i]["role"] != "vpn":
            res.change("netplan", "%s (%s) is unassigned; its addresses are removed." % (m.old[i]["name"], m.old[i]["device"]))


def _netplan_wan(cfg, old, new):
    if new.get("mode") == "static":
        cfg["dhcp4"] = False
        addrs = [a for a in cfg.get("addresses") or [] if ":" in str(a)]
        cfg["addresses"] = [new.get("address")] + addrs
        routes = [r for r in cfg.get("routes") or [] if r.get("to") not in ("default", "0.0.0.0/0")]
        if new.get("gateway"):
            routes.append({"to": "default", "via": new["gateway"]})
        if routes:
            cfg["routes"] = routes
        else:
            cfg.pop("routes", None)
    else:
        cfg["dhcp4"] = True
        addrs = [a for a in cfg.get("addresses") or [] if ":" in str(a)]
        if addrs:
            cfg["addresses"] = addrs
        else:
            cfg.pop("addresses", None)
        routes = [r for r in cfg.get("routes") or [] if r.get("to") not in ("default", "0.0.0.0/0")]
        if routes:
            cfg["routes"] = routes
        else:
            cfg.pop("routes", None)


# ---------------------------------------------------------------- kea

def default_pool(ipi):
    net = ipi.network
    hosts = net.num_addresses - 2
    lo = int(net.network_address) + (20 if hosts > 60 else 2)
    hi = int(net.broadcast_address) - 1
    gw = int(ipi.ip)
    if lo <= gw <= hi:
        if gw - lo > hi - gw:
            hi = gw - 1
        else:
            lo = gw + 1
    return "%s-%s" % (ipaddress.ip_address(lo), ipaddress.ip_address(hi))


def _pool_of(s):
    return [p.get("pool") for p in s.get("pools") or []]


def _lease_counts(ctx):
    """Active leases per Kea subnet id (last record per address wins)."""
    last = {}
    # memfile: lease-file cleanup leaves older records in .2 (and .1 while it runs)
    for path in (KEA_LEASES + ".2", KEA_LEASES + ".1", KEA_LEASES):
        for line in ctx.read(path).splitlines()[1:]:
            f = line.split(",")
            if len(f) < 10:
                continue
            last[f[0]] = f
    out = {}
    for f in last.values():
        try:
            if f[9] == "0" and float(f[4]) > ctx.now:
                out[f[5]] = out.get(f[5], 0) + 1
        except ValueError:
            pass
    return out


def r_kea(ctx, m, res):
    text = ctx.read(T.KEA_CONF)
    if not text:
        if any(m.nw[i].get("dhcp") for i in m.net_ids()):
            res.warn("Kea is not configured (%s missing); DHCP settings are not rendered." % T.KEA_CONF)
        return
    try:
        doc = T.kea_conf.loads(text)
    except ValueError:
        res.warn("%s is not valid JSON; DHCP changes are not rendered." % T.KEA_CONF)
        return
    new = copy.deepcopy(doc)
    d4 = new.get("Dhcp4") or {}
    ic = d4.setdefault("interfaces-config", {})
    ifaces = [str(x) for x in ic.get("interfaces") or []]
    subs = d4.setdefault("subnet4", [])
    leases = None

    def lease_n(s):
        nonlocal leases
        if leases is None:
            leases = _lease_counts(ctx)
        return leases.get(str(s.get("id")), 0)

    orig_if = {id(s): s.get("interface") for s in subs}
    if_map, if_add = {}, []

    def drop_iface(dev):
        if_map[dev] = None

    for i in list(m.old):
        o = m.old[i]
        if o["role"] in ("wan", "vpn") or not o.get("device"):
            continue
        n = m.nw.get(i)
        on = bool(n and n.get("dhcp") and n["ip"])
        mine = [s for s in subs if orig_if.get(id(s)) == o["device"]]
        if not on:
            if mine or o["device"] in [x.split("/")[0] for x in ifaces]:
                for s in mine:
                    subs.remove(s)
                    res.change("kea", "DHCP for %s stops: subnet %s (id %s) is removed." % (o["name"], s.get("subnet"), s.get("id")))
                    k = lease_n(s)
                    if k:
                        res.warn("%d active DHCP lease(s) in %s will be lost." % (k, s.get("subnet")))
                drop_iface(o["device"])
            continue
        nd = n["device"]
        if mine:
            s = mine[0]
            s["interface"] = nd
            net = n["ip"].network
            if str(net) != s.get("subnet"):
                res.change("kea", "DHCP subnet for %s moves %s -> %s." % (n["name"], s.get("subnet"), net))
                k = lease_n(s)
                res.warn("DHCP subnet %s moves to %s: clients get new addresses when they renew"
                         "%s." % (s.get("subnet"), net, (" (%d active lease(s) lost)" % k) if k else ""))
                s["subnet"] = str(net)
                keep = [r for r in s.get("reservations") or []
                        if r.get("ip-address") and ipaddress.ip_address(r["ip-address"]) in net]
                lost = len(s.get("reservations") or []) - len(keep)
                if "reservations" in s:
                    s["reservations"] = keep
                if lost:
                    res.warn("%d DHCP reservation(s) of %s fall outside %s and are dropped." % (lost, n["name"], net))
            pools = _pool_of(s)
            want = n.get("pool") or (pools[0] if pools and _pool_ok(pools[0], n["ip"]) else default_pool(n["ip"]))
            if pools != [want]:
                s["pools"] = [{"pool": want}]
                res.change("kea", "DHCP pool for %s: %s." % (n["name"], want))
            for od in s.get("option-data") or []:
                if od.get("name") in ("routers", "domain-name-servers") and o["ip"]:
                    vals = [v.strip() for v in str(od.get("data", "")).split(",")]
                    od["data"] = ", ".join(str(n["ip"].ip) if v == str(o["ip"].ip) else v for v in vals)
            if o["device"] != nd:
                res.change("kea", "DHCP for %s now listens on %s." % (n["name"], nd))
        else:
            sid = max([int(x.get("id") or 0) for x in subs] + [0]) + 1
            gw = str(n["ip"].ip)
            subs.append({"id": sid, "subnet": str(n["ip"].network), "interface": nd,
                         "pools": [{"pool": n.get("pool") or default_pool(n["ip"])}],
                         "option-data": [{"name": "routers", "data": gw},
                                         {"name": "domain-name-servers", "data": gw}]})
            res.change("kea", "DHCP starts on %s: subnet %s (id %d), pool %s." % (
                n["name"], n["ip"].network, sid, n.get("pool") or default_pool(n["ip"])))
        if o["device"] in [x.split("/")[0] for x in ifaces]:
            if o["device"] != nd:
                if_map[o["device"]] = nd
        else:
            if_add.append(nd)
    for i in m.added:
        n = m.nw[i]
        if n["role"] in ("wan", "vpn") or not (n.get("dhcp") and n["ip"]):
            continue
        sid = max([int(x.get("id") or 0) for x in subs] + [0]) + 1
        pool = n.get("pool") or default_pool(n["ip"])
        gw = str(n["ip"].ip)
        subs.append({"id": sid, "subnet": str(n["ip"].network), "interface": n["device"],
                     "pools": [{"pool": pool}],
                     "option-data": [{"name": "routers", "data": gw},
                                     {"name": "domain-name-servers", "data": gw}]})
        if_add.append(n["device"])
        res.change("kea", "DHCP on new network %s: subnet %s (id %d), pool %s." % (n["name"], n["ip"].network, sid, pool))
    out_if = []
    for x in ifaces:
        dev = x.split("/")[0]
        if dev in if_map:
            if if_map[dev]:
                out_if.append(if_map[dev])
        else:
            out_if.append(x)
    for d in if_add:
        if d not in [x.split("/")[0] for x in out_if]:
            out_if.append(d)
    ic["interfaces"] = out_if
    if new != doc:
        res.file("kea", T.KEA_CONF, text, T.kea_conf.dumps(new, T.kea_conf.split_header(text)[0]), 0o644)
        if T.kea_conf.body_has_comments(text):
            res.warn("%s is rewritten from its parsed form: comments inside the JSON are not kept "
                     "(the header comment and the snapshot are)." % T.KEA_CONF)


def _pool_ok(pool, ipi):
    try:
        a, b = [ipaddress.ip_address(x.strip()) for x in pool.split("-", 1)]
    except ValueError:
        return False
    return a in ipi.network and b in ipi.network and not (int(a) <= int(ipi.ip) <= int(b))


# ---------------------------------------------------------------- radvd

_RADVD_BLOCK = re.compile(r"^interface\s+(\S+)\s*\{.*?^\};[ \t]*\n?", re.M | re.S)


def r_radvd(ctx, m, res):
    text = ctx.read(T.RADVD_CONF)
    new = text
    have = set(re.findall(r"^\s*interface\s+(\S+)\s*\{", text, re.M))
    for i in m.old:
        o, n = m.old[i], m.nw.get(i)
        if o["role"] in ("wan", "vpn") or o.get("device") not in have:
            continue
        if not n or not n.get("ra"):
            new = _RADVD_BLOCK.sub(lambda mm: "" if mm.group(1) == o["device"] else mm.group(0), new)
            res.change("radvd", "IPv6 router advertisements stop on %s (%s)." % (o["name"], o["device"]))
    new = _subst(new, m.dev_map)
    have = set(re.findall(r"^\s*interface\s+(\S+)\s*\{", new, re.M))
    for i in m.net_ids():
        n = m.nw[i]
        if n["role"] in ("wan", "vpn") or not n.get("ra") or n.get("device") in have:
            continue
        new = new.rstrip("\n") + ("\n\n" if new.strip() else "") + (
            "interface %s {\n    AdvSendAdvert on;\n    MinRtrAdvInterval 30;\n    MaxRtrAdvInterval 100;\n"
            "    prefix ::/64 {\n        AdvOnLink on;\n        AdvAutonomous on;\n    };\n};\n" % n["device"])
        res.change("radvd", "IPv6 router advertisements start on %s (%s), advertising its own /64 prefixes." % (n["name"], n["device"]))
    if new != text:
        if text and m.dev_map and any(re.search(r"^\s*interface\s+%s\s*\{" % re.escape(k), text, re.M) for k in m.dev_map):
            res.change("radvd", "radvd blocks follow their networks to the new devices.")
        if not re.search(r"^\s*interface\s+\S+\s*\{", new, re.M):
            res.warn("No network advertises IPv6 any more; radvd will fail to start (stop it if that is intended).")
        res.file("radvd", T.RADVD_CONF, text or None, new)


# ---------------------------------------------------------------- unbound

def r_unbound(ctx, m, res):
    files = [n for n in ctx.listdir(T.UNBOUND_DIR) if n.endswith(".conf")]
    gone_ips, gone_nets = set(), set()
    for i in m.removed:
        o = m.old[i]
        if o["role"] != "vpn" and o["ip"]:
            gone_ips.add(str(o["ip"].ip)); gone_nets.add(str(o["ip"].network))
    for n in files:
        path = T.UNBOUND_DIR + "/" + n
        text = ctx.read(path)
        new = []
        for line in text.splitlines(True):
            s = line.split("#", 1)[0].strip()
            mi = re.match(r"^interface:\s*(\S+)$", s)
            ma = re.match(r"^access-control:\s*(\S+)\s+allow\S*$", s)
            if (mi and mi.group(1) in gone_ips) or (ma and ma.group(1) in gone_nets):
                continue
            new.append(line)
        new = "".join(_subst(l.split("#", 1)[0], None, m.ip_map) + (("#" + l.split("#", 1)[1]) if "#" in l else "")
                      for l in new)
        if new != text:
            res.file("unbound", path, text, new)
    adds_if, adds_acl = [], []
    for i in m.added:
        e = m.nw[i]
        if e["role"] in ("wan", "vpn") or not e["ip"]:
            continue
        adds_if.append(str(e["ip"].ip)); adds_acl.append(str(e["ip"].network))
    if adds_if:
        path = UNBOUND_ROUTER if UNBOUND_ROUTER.rsplit("/", 1)[1] in files else T.UNBOUND_DIR + "/92-tuxwall-networks.conf"
        cur = res.files[path]["new"] if path in res.files else ctx.read(path)
        lines = cur.splitlines(True) if cur else ["server:\n"]

        def last(rx):
            idx = -1
            for k, l in enumerate(lines):
                if re.match(rx, l.split("#", 1)[0].strip()):
                    idx = k
            return idx
        k = last(r"^interface:\s*\d")
        for a in reversed(adds_if):
            lines.insert(k + 1 if k >= 0 else 1, "    interface: %s\n" % a)
        k = last(r"^access-control:\s*\d\S*\s+allow")
        for a in reversed(adds_acl):
            lines.insert(k + 1 if k >= 0 else len(lines), "    access-control: %s allow\n" % a)
        res.file("unbound", path, cur or None, "".join(lines))
    for i in m.added:
        if m.nw[i]["role"] not in ("wan", "vpn") and m.nw[i]["ip"]:
            res.change("unbound", "DNS answers %s on %s." % (m.nw[i]["ip"].network, m.nw[i]["ip"].ip))
    for i in m.removed:
        if m.old[i]["role"] not in ("wan", "vpn") and m.old[i]["ip"]:
            res.change("unbound", "DNS stops listening/answering for %s." % m.old[i]["ip"].network)
    if any(":" not in k and "/" not in k for k in m.ip_map) and any(p.startswith(T.UNBOUND_DIR) for p in res.files):
        res.change("unbound", "Listen addresses, access-control and local records follow the new addresses.")


# ---------------------------------------------------------------- ufw

def _split_rules(text):
    """(head, [blocks], tail) of a ufw user rules file."""
    a = text.find("### RULES ###\n")
    b = text.find("### END RULES ###")
    if a < 0 or b < 0:
        return None
    a += len("### RULES ###\n")
    body = text[a:b]
    parts = re.split(r"(?m)^(?=### tuple ### )", body)
    lead = parts[0] if parts and not parts[0].startswith("### tuple") else ""
    blocks = [p for p in parts if p.startswith("### tuple ### ")]
    return text[:a] + lead, blocks, text[b:]


def _join_rules(head, blocks, tail):
    return head + "".join(blocks) + tail


def _block_tuple(block, fam):
    r = T._ufw_tuples({"v4": block, "v6": ""} if fam == "v4" else {"v4": "", "v6": block})
    return r[0] if r else None


def ufw_block(fam, route, action, iin="", iout="", proto="any", dport="any", comment=""):
    """The exact text ufw writes for an interface rule (tuple + iptables)."""
    anyaddr = "0.0.0.0/0" if fam == "v4" else "::/0"
    pre = "ufw-user-" if fam == "v4" else "ufw6-user-"
    chain = pre + ("forward" if route else "input")
    direction = "!".join([x for x in (("in_" + iin) if iin else "", ("out_" + iout) if iout else "") if x]) or "in"
    tup = "### tuple ### %s%s %s %s %s any %s %s" % ("route:" if route else "", action, proto, dport,
                                                      anyaddr, anyaddr, direction)
    if comment:
        tup += " comment=" + comment.encode("utf-8").hex()
    target = "ACCEPT" if action == "allow" else "DROP"
    base = "-A %s%s%s" % (chain, (" -i " + iin) if iin else "", (" -o " + iout) if iout else "")
    lines = []
    if dport != "any":
        for p in (["tcp", "udp"] if proto == "any" else [proto]):
            lines.append("%s -p %s --dport %s -j %s" % (base, p, dport, target))
    elif proto != "any":
        lines.append("%s -p %s -j %s" % (base, proto, target))
    else:
        lines.append("%s -j %s" % (base, target))
    return tup + "\n" + "\n".join(lines) + "\n\n"


def _zones(t):
    nets = T.networks(t)
    w = (t.get("wan") or {}).get("device", "")
    z = [{"id": n["id"], "role": n["role"], "name": n["name"], "device": n["device"],
          "subnet": n["subnet"], "subnets6": n["subnets6"]} for n in nets]
    z.append({"id": "wan", "role": "wan", "name": "WAN / Internet", "device": w, "subnet": "", "subnets6": []})
    return nets, z


def _zone_of(addr, zones):
    if T._any(addr):
        return None
    try:
        a = ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return None
    for z in zones:
        for s in [z["subnet"]] + z["subnets6"]:
            if s and a.version == ipaddress.ip_network(s).version and a.subnet_of(ipaddress.ip_network(s)):
                return z["id"]
    return None


def _decider(blocks, fam, s, d, zones):
    """Index of the first block that fully decides forward cell s->d
    (same matching as topology.current_policy)."""
    for k, b in enumerate(blocks):
        r = _block_tuple(b, fam)
        if not r or not r["route"]:
            continue
        if r["in"] or r["out"]:
            if (r["in"] and r["in"] != s["device"]) or (r["out"] and r["out"] != d["device"]):
                continue
            full = T._any(r["src"]) and T._any(r["dst"])
        else:
            if _zone_of(r["src"], zones) != s["id"] or _zone_of(r["dst"], zones) != d["id"]:
                continue
            full = True
        if full and r["proto"] == "any" and r["dport"] == "any":
            return k
    return None


def _first_input(blocks, fam, dev):
    for k, b in enumerate(blocks):
        r = _block_tuple(b, fam)
        if r and not r["route"] and r["in"] == dev:
            return k
    return None


def _cell_blocks(fam, s, d, state):
    tag = "%s%s->%s" % (TAG, s["id"], d["id"])
    if d["id"] == "gw":
        if state == "allow":
            return [ufw_block(fam, False, "allow", s["device"], comment=tag)]
        if state == "block":
            return [ufw_block(fam, False, "deny", s["device"], comment=tag)]
        dhcp = "67" if fam == "v4" else "547"
        return [ufw_block(fam, False, "allow", s["device"], dport="53", comment=tag),
                ufw_block(fam, False, "allow", s["device"], proto="udp", dport=dhcp, comment=tag),
                ufw_block(fam, False, "deny", s["device"], comment=tag)]
    return [ufw_block(fam, True, "allow" if state == "allow" else "deny", s["device"], d["device"], comment=tag)]


def _strip_tag(blocks, fam, tag):
    out = []
    for b in blocks:
        r = _block_tuple(b, fam)
        if r and r["comment"] == tag:
            continue
        out.append(b)
    return out


def preset_cells(zid, preset, zones):
    """Cells a preset sets: this network's row and its column."""
    p = PRESETS.get(preset)
    if not p:
        return {}
    cells = {zid: {}}
    for z in zones:
        if z["id"] == zid:
            continue
        if z["id"] == "wan":
            cells[zid]["wan"] = p["wan"]
            continue
        cells[zid][z["id"]] = p["out"]
        cells.setdefault(z["id"], {})[zid] = p["in_lan"] if z["role"] == "lan" else p["in"]
    cells[zid]["gw"] = p["gw"]
    return cells


def r_ufw(ctx, m, res, body):
    texts = {"v4": ctx.read(T.UFW_USER[0]), "v6": ctx.read(T.UFW_USER[1])}
    parsed = {f: _split_rules(texts[f]) for f in texts}
    if not parsed["v4"]:
        res.warn("ufw user rules not found; firewall changes are not rendered.")
        return
    gone_nets = {str(m.old[i]["ip"].network) for i in m.removed if m.old[i]["ip"]}
    blocks = {}
    removed_rules = 0
    for f in ("v4", "v6"):
        if not parsed[f]:
            blocks[f] = []
            continue
        keep = []
        for b in parsed[f][1]:
            r = _block_tuple(b, f)
            if r and ((r["in"] and r["in"] in m.removed_devs) or (r["out"] and r["out"] in m.removed_devs)
                      or r["src"] in gone_nets or r["dst"] in gone_nets):
                removed_rules += 1
                continue
            keep.append(_subst(b, m.dev_map, m.ip_map))
        blocks[f] = keep
    if removed_rules:
        res.change("ufw", "%d firewall rule(s) of unassigned networks are removed." % removed_rules)
    if m.dev_map or m.ip_map:
        res.change("ufw", "Firewall rules follow their networks (%s)." % ", ".join(
            "%s -> %s" % kv for kv in sorted(m.dev_map.items())) if m.dev_map else
            "Firewall rules follow the new addresses.")
    # before.rules: WAN drop / LAN->WAN accept follow the devices
    for path in UFW_BEFORE:
        t = ctx.read(path)
        nt = _subst(t, m.dev_map, None)
        if res.file("ufw", path, t, nt):
            res.change("ufw", "%s: interface names follow their roles." % os.path.basename(path))
    # stale host references
    all_nets = [n["ip"].network for n in m.nw.values() if n.get("ip")]
    for f in ("v4",):
        for b in blocks[f]:
            r = _block_tuple(b, f)
            for a in (r or {}).get("src"), (r or {}).get("dst"):
                if not a or T._any(a) or "/" in a:
                    continue
                try:
                    ip = ipaddress.ip_address(a)
                except ValueError:
                    continue
                if not any(ip in n for n in all_nets) and ip.is_private:
                    res.warn("Firewall rule '%s' refers to %s, which is in no network any more." % (T.ufw_rule_text(r), a))

    # ---- policy matrix
    t_new = m.new
    nets, zones = _zones(t_new)
    cols = zones + [{"id": "gw", "role": "gateway", "name": "Gateway (router)", "device": "", "subnet": "", "subnets6": []}]
    zmap = {z["id"]: z for z in cols}
    vpn_devs = {n["device"] for n in m.nw.values() if n["role"] == "vpn"}
    raw = ctx.raw()
    wan_drop = [m.dev_map.get(d, d) for d in re.findall(r"^-A ufw6?-before-forward -i (\S+) -j DROP\s*$",
                                                         ctx.read(UFW_BEFORE[0]), re.M)]

    def derive(bl, rw):
        txt = {f: "".join(bl[f]) for f in bl}
        return T.current_policy(t_new, rules=T._ufw_tuples(txt), raw=rw, wan_drop=wan_drop, nets=nets, legacy=[])

    before = derive(blocks, raw)
    want = {}
    for zid in [i for i in m.added if i in zmap]:
        pr = (body.get("presets") or {}).get(zid) or ("internet" if m.nw[zid]["role"] == "opt" else "")
        for s, row in preset_cells(zid, pr, zones).items():
            for d, st in row.items():
                want.setdefault(s, {})[d] = st
    for zid, pr in (body.get("presets") or {}).items():
        if zid in zmap and zid not in m.added:
            for s, row in preset_cells(zid, pr, zones).items():
                for d, st in row.items():
                    want.setdefault(s, {})[d] = st
    from_preset = {(a, b) for a in want for b in want[a]}
    pol = body.get("policy")
    if isinstance(pol, dict):
        cells = pol.get("cells") if isinstance(pol.get("cells"), dict) else pol
        for s, row in cells.items():
            if isinstance(row, dict):
                for d, st in row.items():
                    st = st.get("state") if isinstance(st, dict) else st
                    want.setdefault(s, {})[d] = st
                    from_preset.discard((s, d))
    edits = []
    for s, row in want.items():
        for d, st in row.items():
            if s not in zmap or d not in zmap or s == d or s == "gw":
                continue
            cur = (before["cells"].get(s) or {}).get(d) or {}
            if st not in POLICY_STATES or st == cur.get("state"):
                continue
            if (s, d) in from_preset and cur.get("source") == "iptables":
                res.change("ufw", "%s -> %s stays '%s': a raw iptables rule decides it; edit that cell in the matrix "
                           "to replace the raw rule." % (zmap[s]["name"], zmap[d]["name"], cur.get("state")))
                continue
            if d == "gw" and st == "established":
                res.errors.append("%s -> Gateway: 'established only' is not a gateway setting." % zmap[s]["name"])
                continue
            if d != "gw" and st == "dns_dhcp":
                res.errors.append("%s -> %s: 'DNS + DHCP only' applies to the Gateway column." % (zmap[s]["name"], zmap[d]["name"]))
                continue
            if s == "wan":
                if st == "allow":
                    res.errors.append("WAN -> %s: new connections from the internet are dropped before ufw; "
                                      "use Port forwarding instead." % zmap[d]["name"])
                    continue
                if d != "gw" and cur.get("state") in ("established", "block") and st in ("established", "block"):
                    continue
                if d == "gw":
                    res.errors.append("WAN -> Gateway is managed on the Firewall page (honeypot, WireGuard port).")
                    continue
            if cur.get("state") == "established" and st == "block":
                continue
            if not zmap[s]["device"] or (d != "gw" and not zmap[d]["device"]):
                res.errors.append("%s -> %s has no interface to write a rule for." % (zmap[s]["name"], zmap[d]["name"]))
                continue
            edits.append((s, d, st, cur))
    raw_used = [e for e in edits if (e[3] or {}).get("source") == "iptables"]
    raw_after = raw
    if raw_used:
        raw_after = [r for r in raw if not (r["target"] == "ACCEPT" and r["dev"] in vpn_devs)]
        mid = derive(blocks, raw_after)
        preserved = []
        for s in before["cells"]:
            for d, c in before["cells"][s].items():
                if c.get("source") != "iptables" or any(e[0] == s and e[1] == d for e in edits):
                    continue
                c2 = mid["cells"][s][d]
                if c2["state"] == "allow":
                    continue
                if c2.get("default") and s != "wan":
                    edits.append((s, d, "allow", c))
                    preserved.append("%s -> %s" % (zmap[s]["name"], zmap[d]["name"]))
                else:
                    res.change("ufw", "%s -> %s becomes '%s' once the raw rule is gone (decided by: %s)." % (
                        zmap[s]["name"], zmap[d]["name"], c2["state"], "; ".join(c2.get("rules") or [])))
        devs = sorted({r["dev"] for r in raw if r not in raw_after})
        for r in raw:
            if r in raw_after:
                continue
            tool = "iptables" if r["family"] == "v4" else "ip6tables"
            flag = "-i" if r["dir"] == "in" else "-o"
            res.extra_actions.append({"step": "ufw",
                                      "cmd": [tool, "-D", "FORWARD", flag, r["dev"], "-j", "ACCEPT"],
                                      "undo": [tool, "-I", "FORWARD", "1", flag, r["dev"], "-j", "ACCEPT"]})
        res.change("ufw", "Replace the raw iptables rules 'FORWARD -i/-o %s -j ACCEPT' (they bypass ufw) with "
                   "tagged ufw policy rules%s." % ("/".join(devs), (" (kept open: %s)" % ", ".join(preserved)) if preserved else ""))
        res.warn("Editing a VPN cell removes the raw 'FORWARD -i/-o %s ACCEPT' rules that WireGuard setup adds and "
                 "that bypass ufw. Existing ufw deny rules for %s then take effect, and WireGuard stops re-adding "
                 "them (policy.wg_raw_forward=false)." % ("/".join(devs), "/".join(devs)))
    for s, d, st, cur in edits:
        tag = "%s%s->%s" % (TAG, s, d)
        for f in ("v4", "v6"):
            if not parsed[f]:
                continue
            bl = _strip_tag(blocks[f], f, tag)
            if d == "gw":
                k = _first_input(bl, f, zmap[s]["device"])
            else:
                k = _decider(bl, f, zmap[s], zmap[d], zones)
            k = len(bl) if k is None else k
            bl[k:k] = _cell_blocks(f, zmap[s], zmap[d], st)
            blocks[f] = bl
        label = {"allow": "allow", "block": "block", "established": "return traffic only",
                 "dns_dhcp": "DNS + DHCP only"}[st]
        res.change("ufw", "Policy %s -> %s: %s -> %s (rule tagged %s)." % (
            zmap[s]["name"], zmap[d]["name"], cur.get("state", "?"), label, tag))
        if d == "gw" and st != "allow":
            res.lockout_cells.append(s)
    after = derive(blocks, raw_after)
    for s, d, st, cur in edits:
        got = after["cells"][s][d]["state"]
        ok = got == st or (st == "block" and got == "established") or (st == "established" and got == "block")
        if not ok:
            res.warn("%s -> %s will read '%s', not '%s': an earlier or narrower rule decides it (%s)." % (
                zmap[s]["name"], zmap[d]["name"], got, st, "; ".join(after["cells"][s][d].get("rules") or [])))
        if (after["cells"][s][d].get("exceptions") or []) and d != "gw":
            res.warn("%s -> %s keeps %d narrower rule(s) that are checked first." % (
                zmap[s]["name"], zmap[d]["name"], len(after["cells"][s][d]["exceptions"])))
    res.policy = {"before": before, "after": after, "edits": [{"src": s, "dst": d, "state": st} for s, d, st, _ in edits],
                  "raw_replaced": bool(raw_used)}
    for f, path in (("v4", T.UFW_USER[0]), ("v6", T.UFW_USER[1])):
        if parsed[f]:
            res.file("ufw", path, texts[f], _join_rules(parsed[f][0], blocks[f], parsed[f][2]), 0o640)


# ---------------------------------------------------------------- the rest

def r_nat(ctx, m, res):
    for n in ctx.listdir(T.NAT_DROPIN):
        path = T.NAT_DROPIN + "/" + n
        t = ctx.read(path)
        if "TUXWALL_WAN_IFACE" in t and res.file("nat", path, t, _subst(t, m.dev_map)):
            res.change("nat", "TUXWALL_WAN_IFACE override follows the WAN.")
    if m.changed("wan", "device") or m.dev_map or m.ip_map or m.added or m.removed:
        res.change("nat", "tuxwall-nat re-runs and masquerades out of the WAN (%s)." % (m.nw.get("wan") or {}).get("device"))
        res.steps.add("nat")


def _text_step(ctx, res, step, path, fn, msg):
    t = ctx.read(path)
    if not t:
        return
    nt = fn(t)
    if res.file(step, path, t, nt):
        res.change(step, msg)


def r_avahi(ctx, m, res):
    if m.dev_map:
        _text_step(ctx, res, "avahi", T.AVAHI_CONF,
                   lambda t: re.sub(r"(?m)^(\s*(?:allow|deny)-interfaces\s*=.*)$", lambda x: _subst(x.group(1), m.dev_map), t),
                   "mDNS allow/deny-interfaces follow their roles.")


def r_suricata(ctx, m, res):
    gone = {str(m.old[i]["ip"].network) for i in m.removed if m.old[i]["ip"]}
    add = [str(m.nw[i]["ip"].network) for i in m.added if m.nw[i]["ip"] and m.nw[i]["role"] != "wan"]

    def fn(t):
        def home(x):
            items = [s.strip() for s in x.group(2).split(",") if s.strip()]
            items = [m.ip_map.get(s, s) for s in items if s not in gone]
            items += [a for a in add if a not in items]
            return x.group(1) + ",".join(items) + x.group(3)
        t = re.sub(r'(?m)^(\s*HOME_NET:\s*"\[)([^\]"]*)(\]")', home, t, count=1)
        return re.sub(r"(?m)^(\s*-\s*interface:\s*)(\S+)", lambda x: x.group(1) + m.dev_map.get(x.group(2), x.group(2)), t)
    if m.dev_map or m.ip_map or gone or add:
        _text_step(ctx, res, "suricata", T.SURICATA_CONF, fn, "Suricata capture interfaces / HOME_NET follow the networks.")
        if "suricata" in res.steps:
            res.warn("suricata.yaml is not test-loaded by the plan (suricata -T takes minutes); Apply restarts it.")


def r_sqm(ctx, m, res):
    if m.dev_map:
        _text_step(ctx, res, "sqm", T.SQM_CONF,
                   lambda t: re.sub(r"(?m)^(WAN=)(\S+)", lambda x: x.group(1) + m.dev_map.get(x.group(2), x.group(2)), t),
                   "SQM shapes the new WAN.")


def r_honeypot(ctx, m, res):
    if m.wan_changed:
        res.change("honeypot", "Canary/honeypot rules follow the WAN; opencanary re-renders its listen address on restart.")
        res.steps.add("honeypot")


def r_record(ctx, m, res, cur, body):
    rec = copy.deepcopy(cur)
    for k in ("wan", "lan", "opt", "vpn"):
        if k in m.new:
            rec[k] = copy.deepcopy(m.new[k])
    pol = rec.get("policy") if isinstance(rec.get("policy"), dict) else {}
    if res.policy and res.policy["edits"]:
        cells = pol.setdefault("cells", {})
        for e in res.policy["edits"]:
            cells.setdefault(e["src"], {})[e["dst"]] = e["state"]
        pol["version"] = 1
        if res.policy["raw_replaced"]:
            pol["wg_raw_forward"] = False
        rec["policy"] = pol
    rec["apply_locked"] = cur.get("apply_locked", True)
    if json.dumps(rec, sort_keys=True) != json.dumps(cur, sort_keys=True):
        rec["generated"] = {"by": "assign_apply", "at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ctx.now))}
        old = ctx.read(T.CONF)
        res.file("record", T.CONF, old or None, json.dumps(rec, indent=2) + "\n")
        res.change("record", "%s records the new assignments (the source of truth)." % T.CONF)
        res.record = rec
    vf = T._read_json(ctx.p(T.VLAN_FILE))
    if isinstance(vf, dict) or any(n.get("vlan") for n in m.nw.values()):
        vf = vf if isinstance(vf, dict) else {}
        olddev = {m.old[i]["device"]: i for i in m.old if m.old[i].get("device")}
        # keep metadata keys and VLANs the record does not manage (e.g. made on the old VLANs page)
        nv = {k: copy.deepcopy(v) for k, v in vf.items() if k.startswith("__") or k not in olddev}
        pols = nv.get("__policies__")
        if isinstance(pols, list):
            keep = []
            for lp in pols:
                if not isinstance(lp, dict):
                    keep.append(lp)
                    continue
                if lp.get("src") in m.removed_devs or lp.get("dst") in m.removed_devs:
                    res.change("record", "VLANs-page policy %s (%s) is dropped with its network." % (
                        lp.get("id", "?"), lp.get("rule") or "%s -> %s" % (lp.get("src"), lp.get("dst"))))
                    continue
                for k in ("src", "dst"):
                    if lp.get(k) in m.dev_map:
                        lp[k] = m.dev_map[lp[k]]
                if lp.get("rule"):
                    lp["rule"] = _subst(lp["rule"], m.dev_map)
                keep.append(lp)
            nv["__policies__"] = keep
        for n in m.nw.values():
            if n.get("vlan") and n["role"] == "opt":
                prev = None
                for od, i in olddev.items():
                    if i == n["id"]:
                        prev = vf.get(od)
                e = dict(prev) if isinstance(prev, dict) else {}
                e.update({"label": n.get("name") or e.get("label"), "address": n.get("address"),
                          "vlan_id": int(n["vlan"]), "parent": n.get("parent")})
                nv[n["device"]] = e
        if nv != vf:
            old = ctx.read(T.VLAN_FILE)
            res.file("record", T.VLAN_FILE, old or None, json.dumps(nv, indent=2))
            res.change("record", "%s is kept in step as a mirror for the old VLANs page." % T.VLAN_FILE)


# ---------------------------------------------------------------- validators

def _run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return None, "%s is not installed" % cmd[0]
    except Exception as exc:
        return 1, str(exc)


def _trim(s, n=1500):
    s = s or ""
    return s if len(s) <= n else "...\n" + s[-n:]


def run_validators(ctx, res, tmp):
    out = []

    def add(step, tool, rc, txt):
        out.append({"step": step, "tool": tool, "ok": rc == 0 if rc is not None else None,
                    "skipped": rc is None, "output": _trim(txt)})

    def final(path):
        return res.files[path]["new"] if path in res.files else ctx.read(path)

    if "netplan" in res.steps:
        d = os.path.join(tmp, "netplan-root")
        os.makedirs(d + T.NETPLAN_DIR, mode=0o700)
        names = set(n for n in ctx.listdir(T.NETPLAN_DIR) if n.endswith(".yaml"))
        names |= {os.path.basename(p) for p in res.files if p.startswith(T.NETPLAN_DIR + "/")}
        for n in names:
            txt = final(T.NETPLAN_DIR + "/" + n)
            if txt is None:
                continue
            fp = d + T.NETPLAN_DIR + "/" + n
            with open(fp, "w") as f:
                f.write(txt)
            os.chmod(fp, 0o600)
        rc, txt = _run(["netplan", "generate", "--root-dir", d])
        add("netplan", "netplan generate --root-dir <tmp>", rc, txt)
    if T.KEA_CONF in res.files:
        fd, kp = tempfile.mkstemp(prefix=".tuxwall-plan-", suffix=".json", dir="/etc/kea") if os.path.isdir("/etc/kea") and os.access("/etc/kea", os.W_OK) else (None, None)
        if kp:
            try:
                body = res.files[T.KEA_CONF]["new"]
                with os.fdopen(fd, "w") as f:
                    f.write(body)
                rc, txt = _run(["kea-dhcp4", "-t", kp])
                standins = []
                wanted = {n.get("device") for n in getattr(res, "model").nw.values()}
                for _ in range(8):
                    mm = re.search(r"interface name (\S+) for subnet \S+ is not present in the system|"
                                   r"interface '([^']+)' doesn't exist in the system", txt or "")
                    if mm:
                        mm = re.match(r"(.*)", mm.group(1) or mm.group(2))
                    if rc == 0 or not mm or mm.group(1) not in wanted or mm.group(1) in standins:
                        break
                    # the device does not exist yet (new VLAN / NIC): test the rest with a stand-in
                    standins.append(mm.group(1))
                    kd = T.kea_conf.loads(body)
                    k4 = kd.get("Dhcp4") or {}
                    il = [x for x in (k4.get("interfaces-config") or {}).get("interfaces") or []
                          if x.split("/")[0] != mm.group(1)]
                    k4.setdefault("interfaces-config", {})["interfaces"] = il + ([] if "lo" in il else ["lo"])
                    for sb in k4.get("subnet4") or []:
                        if sb.get("interface") == mm.group(1):
                            sb["interface"] = "lo"
                    body = json.dumps(kd)
                    with open(kp, "w") as f:
                        f.write(body)
                    rc, txt = _run(["kea-dhcp4", "-t", kp])
                errs = [l for l in (txt or "").splitlines() if "rror" in l or " ERROR " in l]
                if rc and errs:
                    txt = "\n".join(errs[-3:])
                elif rc == 0:
                    txt = "configuration test passed"
                if standins:
                    txt = ("(%s not present yet; tested with 'lo' as a stand-in)\n" % ", ".join(standins)) + (txt or "")
            finally:
                os.unlink(kp)
        else:
            rc, txt = None, "/etc/kea is not writable (run as root to test-load the config)"
        add("kea", "kea-dhcp4 -t", rc, txt)
    if T.RADVD_CONF in res.files:
        fp = os.path.join(tmp, "radvd.conf")
        with open(fp, "w") as f:
            f.write(res.files[T.RADVD_CONF]["new"])
        rc, txt = _run(["radvd", "--configtest", "-C", fp])
        add("radvd", "radvd --configtest", rc, txt)
    if any(p.startswith(T.UNBOUND_DIR) for p in res.files):
        src = ctx.p("/etc/unbound")
        dst = os.path.join(tmp, "unbound")
        try:
            shutil.copytree(src, dst, symlinks=False, ignore=shutil.ignore_patterns("*.bak*"))
            for p, f in res.files.items():
                if p.startswith(T.UNBOUND_DIR):
                    with open(dst + p[len("/etc/unbound"):], "w") as fh:
                        fh.write(f["new"])
            for base, _, files in os.walk(dst):
                for n in files:
                    if n.endswith(".conf"):
                        fp = os.path.join(base, n)
                        with open(fp) as fh:
                            t = fh.read()
                        t2 = t.replace("/etc/unbound/", dst + "/")
                        if t2 != t:
                            with open(fp, "w") as fh:
                                fh.write(t2)
            rc, txt = _run(["unbound-checkconf", dst + "/unbound.conf"])
        except Exception as exc:
            rc, txt = 1, "could not stage unbound config: %s" % exc
        add("unbound", "unbound-checkconf", rc, txt)
    for path, tool in ((T.UFW_USER[0], "iptables-restore"), (T.UFW_USER[1], "ip6tables-restore"),
                       (UFW_BEFORE[0], "iptables-restore"), (UFW_BEFORE[1], "ip6tables-restore")):
        if path in res.files:
            fp = os.path.join(tmp, os.path.basename(path))
            with open(fp, "w") as f:
                f.write(res.files[path]["new"])
            # --test parses and builds the ruleset but never commits it
            rc, txt = _run([tool, "--test", "--noflush", fp])
            add("ufw", "%s --test %s" % (tool, os.path.basename(path)), rc, txt)
    if T.CONF in res.files:
        try:
            json.loads(res.files[T.CONF]["new"])
            add("record", "json", 0, "valid JSON")
        except ValueError as exc:
            add("record", "json", 1, str(exc))
    res.validators = out


# ---------------------------------------------------------------- VLANs

def ap_carriers(aps, vid, name=""):
    """SSIDs (and the APs broadcasting them) that put clients on VLAN vid.

    aps: {"status", "vlans": [openwrt vlan-list rows], "vaps": [{ap, ssid,
    network, clients, up}]}. An SSID carries the VLAN when its OpenWrt
    network is that VLAN's interface in vlan-list (swconfig APs) or, since
    DSA APs report no switch VLANs, when the network is named like the
    VLAN (its name, vlan<id>, br-vlan<id>): match "name"."""
    if not isinstance(aps, dict) or not aps.get("vaps") or vid in (None, ""):
        return []
    vid = str(vid)
    listed = {str(v.get("interface") or "") for v in aps.get("vlans") or []
              if str(v.get("vlan")) == vid} - {""}
    names = {x.lower() for x in (name or "", "vlan" + vid, "vlan_" + vid, "br-vlan" + vid) if x}
    out = {}
    for v in aps["vaps"]:
        net = str(v.get("network") or "")
        how = "vlan-list" if net in listed else ("name" if net.lower() in names else "")
        if not how:
            continue
        ssid = str(v.get("ssid") or "")
        e = out.setdefault(ssid, {"ssid": ssid, "network": net, "aps": [], "clients": 0, "match": how})
        if v.get("ap") and v["ap"] not in e["aps"]:
            e["aps"].append(v["ap"])
        try:
            e["clients"] += int(v.get("clients") or 0)
        except (TypeError, ValueError):
            pass
        if how == "vlan-list":
            e["match"] = how
    return sorted(out.values(), key=lambda e: e["ssid"].lower())


def _carrier_text(c):
    return "SSID '%s' on %s (network %s, %d client(s) now)" % (
        c["ssid"], ", ".join(c["aps"]) or "?", c["network"], c["clients"])


def guess_preset(zid, policy):
    """Which preset a network's current row/column matches. VPN cells are
    ignored (raw WireGuard accepts decide them, not the preset)."""
    zones = [z for z in policy.get("rows") or [] if z.get("role") != "vpn"]
    cells = policy.get("cells") or {}
    best = None
    for key in PRESETS:
        want = preset_cells(zid, key, zones)
        n = tot = 0
        for s_, row in want.items():
            for d_, st in row.items():
                tot += 1
                if ((cells.get(s_) or {}).get(d_) or {}).get("state") != st:
                    n += 1
        if best is None or n < best[1]:
            best = (key, n, tot)
    if not best:
        return {"preset": "", "label": "Custom", "exact": False, "differs": 0}
    key, n, _ = best
    return {"preset": key, "exact": n == 0, "differs": n,
            "label": PRESETS[key]["label"] if n == 0 else "Custom (closest: %s, %d cell%s differ%s)" % (
                PRESETS[key]["label"], n, "" if n == 1 else "s", "s" if n == 1 else "")}


def vlans(ctx=None, view=None, policy=None, aps=None):
    """Rows for the Interfaces -> VLANs tab: every VLAN in the record plus
    VLAN devices (or vlans.json entries) the record does not know yet."""
    ctx = ctx or Ctx()
    view = view if view is not None else T.interfaces_view()
    policy = policy if policy is not None else T.current_policy()
    aps = aps if isinstance(aps, dict) else ctx.aps()
    t = view.get("topology") or {}
    binds = view.get("bindings") or {}
    inv = {i["device"]: i for i in view.get("inventory") or []}
    vf = T._read_json(ctx.p(T.VLAN_FILE))
    vf = vf if isinstance(vf, dict) else {}
    leases = _lease_counts(ctx)
    cols = {c["id"]: c for c in policy.get("columns") or []}
    rows, seen = [], set()

    def link(dev):
        i = inv.get(dev)
        if not i:
            return {"present": False, "state": "missing", "carrier": False}
        return {"present": True, "state": i.get("operstate") or "", "carrier": bool(i.get("carrier"))}

    def pol(zid):
        row = (policy.get("cells") or {}).get(zid)
        if not row:
            return None
        out = []
        for cid, c in row.items():
            if c.get("state") == "self":
                continue
            out.append({"dst": cid, "name": (cols.get(cid) or {}).get("name", cid), "state": c.get("state"),
                        "source": c.get("source", ""), "exceptions": len(c.get("exceptions") or [])})
        inbound = []
        for sid, srow in (policy.get("cells") or {}).items():
            c = srow.get(zid) or {}
            if sid != zid and c.get("state"):
                inbound.append({"src": sid, "name": (cols.get(sid) or {}).get("name", sid), "state": c["state"]})
        legacy = [lp for lp in policy.get("legacy_policies") or [] if lp.get("cell") and zid in lp["cell"]]
        g = guess_preset(zid, policy)
        return {"preset": g, "out": out, "in": inbound, "legacy": legacy}

    for o in t.get("opt") or []:
        if not o.get("vlan"):
            continue
        dev = o.get("device") or "%s.%s" % (o.get("parent"), o.get("vlan"))
        seen.add(dev)
        ipi = _iface(o.get("address"))
        b = binds.get(o.get("id")) or {}
        kea = b.get("kea") or {}
        subs = kea.get("subnets") or []
        n_leases = sum(leases.get(str(x.get("id")), 0) for x in subs)
        legacy = vf.get(dev) if isinstance(vf.get(dev), dict) else None
        rows.append({
            "id": o.get("id"), "managed": True, "name": o.get("name") or o.get("id"),
            "vlan": o.get("vlan"), "parent": o.get("parent"), "device": dev,
            "address": o.get("address") or "", "gateway": str(ipi.ip) if ipi else "",
            "subnet": str(ipi.network) if ipi else "",
            "dhcp": bool(o.get("dhcp")), "dhcp_listening": bool(kea.get("listening")),
            "pools": [p for x in subs for p in (x.get("pools") or [])],
            "kea_subnets": [x.get("id") for x in subs],
            "reservations": sum(int(x.get("reservations") or 0) for x in subs),
            "leases": n_leases,
            "ra": bool(o.get("ra")), "ra_prefixes": (b.get("radvd") or {}).get("prefixes") or [],
            "link": link(dev),
            "mirror": {"vlans_json": bool(legacy), "label": (legacy or {}).get("label", "")},
            "policy": pol(o.get("id")),
            "aps": ap_carriers(aps, o.get("vlan"), o.get("name") or ""),
        })
    extra = {}
    for dev, i in inv.items():
        if i.get("kind") == "vlan" and dev not in seen:
            extra[dev] = {"vlan": i.get("vlan"), "parent": i.get("parent"),
                          "address": next((a["cidr"] for a in i.get("addresses") or [] if a.get("family") == "inet"), "")}
    for dev, e in vf.items():
        if dev.startswith("__") or dev in seen or not isinstance(e, dict):
            continue
        x = extra.setdefault(dev, {"vlan": e.get("vlan_id"), "parent": e.get("parent"), "address": e.get("address", "")})
        x["label"] = e.get("label", "")
    for dev, e in sorted(extra.items()):
        ipi = _iface(e.get("address"))
        rows.append({"id": "", "managed": False, "name": e.get("label") or dev, "vlan": e.get("vlan"),
                     "parent": e.get("parent"), "device": dev, "address": e.get("address") or "",
                     "gateway": str(ipi.ip) if ipi else "", "subnet": str(ipi.network) if ipi else "",
                     "dhcp": False, "pools": [], "kea_subnets": [], "reservations": 0, "leases": 0,
                     "ra": False, "ra_prefixes": [], "link": link(dev),
                     "mirror": {"vlans_json": dev in vf, "label": (vf.get(dev) or {}).get("label", "") if isinstance(vf.get(dev), dict) else ""},
                     "policy": None, "aps": ap_carriers(aps, e.get("vlan"), e.get("label") or "")})
    rows.sort(key=lambda r: (not r["managed"], int(r["vlan"]) if str(r["vlan"]).isdigit() else 0))
    a = aps if isinstance(aps, dict) else {}
    untagged = []
    if a.get("vaps"):
        tagged = {c["ssid"] for r in rows for c in r["aps"]}
        lan_name = (t.get("lan") or {}).get("name") or "lan"
        for c in ap_carriers({"vaps": a["vaps"]}, "lan", "lan" if lan_name.lower() == "lan" else lan_name):
            if c["ssid"] not in tagged:
                untagged.append(c)
    return {"ok": True, "vlans": rows, "parents": sorted(d for d, i in inv.items() if i.get("kind") == "ethernet"),
            "lan_ssids": untagged,
            "aps": {"status": a.get("status", "absent"), "error": a.get("error", ""), "at": a.get("at"),
                    "count": len({v.get("ap") for v in a.get("vaps") or [] if v.get("ap")}),
                    "vlan_list": bool(a.get("vlans"))},
            "legacy_policies": policy.get("legacy_policies") or [],
            "apply_locked": t.get("apply_locked", True) is not False}


# ---------------------------------------------------------------- build / plan

def _norm_topology(cur, want):
    """Fill what the editor may omit from the current record."""
    t = {k: copy.deepcopy(want.get(k, cur.get(k))) for k in ("wan", "lan", "opt", "vpn")}
    t["wan"] = t["wan"] or {}
    t["lan"] = t["lan"] or {}
    t["opt"] = [o for o in (t["opt"] or []) if isinstance(o, dict)]
    t["vpn"] = [v for v in (t["vpn"] or []) if isinstance(v, dict)]
    for k, o in enumerate(t["opt"]):
        if not o.get("id"):
            used = {x.get("id") for x in t["opt"]}
            n = 1
            while "opt%d" % n in used:
                n += 1
            o["id"] = "opt%d" % n
        if o.get("vlan") not in (None, ""):
            try:
                o["vlan"] = int(o["vlan"])
            except (TypeError, ValueError):
                pass
            if o.get("parent") and isinstance(o.get("vlan"), int):
                o["device"] = "%s.%d" % (o["parent"], o["vlan"])
        else:
            o.pop("vlan", None); o.pop("parent", None)
    for e in [t["lan"]] + t["opt"]:
        if e.get("pool") in ("", None):
            e.pop("pool", None)
    # keep the stored policy; edits arrive separately
    t["policy"] = copy.deepcopy(cur.get("policy"))
    return t


def build(body, session_ip="", ctx=None):
    ctx = ctx or Ctx()
    body = body if isinstance(body, dict) else {}
    cur = ctx.record()
    want = body.get("topology") if isinstance(body.get("topology"), dict) else {}
    new = _norm_topology(cur, want)
    res = Result()
    res.validation = T.validate(new)
    res.cur, res.new = cur, new
    m = Model(cur, new)
    res.model = m
    if not res.validation["ok"]:
        return res
    r_netplan(ctx, m, res)
    r_kea(ctx, m, res)
    r_radvd(ctx, m, res)
    r_unbound(ctx, m, res)
    r_ufw(ctx, m, res, body)
    r_nat(ctx, m, res)
    r_avahi(ctx, m, res)
    r_suricata(ctx, m, res)
    r_sqm(ctx, m, res)
    r_honeypot(ctx, m, res)
    r_vlan_notes(ctx, m, res)
    if not res.errors:
        r_record(ctx, m, res, cur, body)
    _warn_session(m, res, session_ip)
    if m.wan_changed:
        res.warn("The WAN changes: WireGuard clients use the public WAN address as their Endpoint; if it changes, "
                 "update every client config. WireGuard's own NAT rule stays on the old WAN until WireGuard is restarted.")
    if any(f.get("old") and f.get("new") is None for f in res.files.values()):
        res.warn("Some files are removed; the snapshot keeps them.")
    return res


def r_vlan_notes(ctx, m, res):
    """Consequences of removing or re-tagging a VLAN network: its policy
    cells go away, and access points may still put WiFi clients on it."""
    gone = [i for i in m.removed if m.old[i].get("vlan") and m.old[i]["role"] == "opt"]
    moved = [i for i in m.kept if m.old[i].get("vlan") and str(m.old[i].get("vlan")) != str(m.nw[i].get("vlan"))]
    if not gone and not moved:
        return
    zones = len(m.old) + (0 if "wan" in m.old else 1)
    for i in gone:
        o = m.old[i]
        res.change("ufw" if "ufw" in res.steps else "record",
                   "Policy matrix: the %s (VLAN %s) row and column are removed (%d cells)." % (o["name"], o["vlan"], 2 * zones - 1))
    aps = ctx.aps()
    if aps is None or aps.get("status") in ("absent", "disabled", "unconfigured"):
        return
    if aps.get("status") not in ("ok", None) and not aps.get("vaps"):
        res.warn("Could not check the access points for SSIDs on the changed VLAN(s) (OpenWrt plugin: %s)." % (
            aps.get("error") or aps.get("status")))
        return
    for i in gone:
        o = m.old[i]
        for c in ap_carriers(aps, o["vlan"], o.get("name")):
            res.warn("%s still tags VLAN %s (%s). Once the VLAN is removed those clients get no DHCP and no "
                     "gateway; move or remove the SSID on the WiFi page first." % (_carrier_text(c), o["vlan"], o["name"]))
    for i in moved:
        o, n = m.old[i], m.nw[i]
        for c in ap_carriers(aps, o["vlan"], o.get("name")):
            res.warn("%s tags VLAN %s; %s moves to VLAN %s, so re-tag the SSID's network on the access points too."
                     % (_carrier_text(c), o["vlan"], n["name"], n.get("vlan")))


def _warn_session(m, res, ip):
    if not ip:
        return
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return
    for i, o in m.old.items():
        if not o.get("ip") or a not in o["ip"].network:
            continue
        n = m.nw.get(i)
        moved = not n or n.get("device") != o.get("device") or n.get("ip") != o.get("ip")
        cut = i in res.lockout_cells
        if moved or cut:
            res.lockout = True
            res.warn("You are connected from %s through %s (%s). This plan %s; you may lose the dashboard. "
                     "Apply keeps a 60 s confirm window and rolls back on its own if you cannot confirm." % (
                         ip, o["name"], o["device"],
                         "changes that network" if moved else "limits that network's access to the router"))
        return


def _ordered(res):
    return sorted(res.files.items(), key=lambda kv: (STEP_INDEX[kv[1]["step"]], kv[0]))


def plan_hash(res):
    h = hashlib.sha256()
    for path, f in _ordered(res):
        txt = f["new"] or ""
        if path == T.CONF:  # its "generated" timestamp is not part of the plan
            txt = re.sub(r'"generated":\s*\{[^}]*\}', "", txt)
        h.update(path.encode() + b"\0" + txt.encode() + b"\0")
    for a in res.extra_actions:
        h.update(json.dumps(a["cmd"]).encode())
    return h.hexdigest()[:16]


def actions(res):
    """Ordered service actions for assign_apply (raw iptables first in ufw)."""
    out = []
    for step, _ in STEPS:
        if step not in res.steps:
            continue
        out += [{"step": step, "cmd": a["cmd"], "undo": a.get("undo")} for a in res.extra_actions if a["step"] == step]
        out += [{"step": step, "cmd": c} for c in ACTIONS[step]]
    return out


def _udiff(path, old, new):
    return "".join(difflib.unified_diff((old or "").splitlines(True), (new or "").splitlines(True),
                                        "a" + path if old is not None else "/dev/null",
                                        "b" + path if new is not None else "/dev/null", n=2))


def plan(body, session_ip="", ctx=None):
    ctx = ctx or Ctx()
    res = build(body, session_ip, ctx)
    cur = res.cur
    locked = cur.get("apply_locked", True) is not False
    base = {"apply_locked": locked, "validation": res.validation,
            "lock_message": LOCK_MESSAGE if locked else ""}
    if not res.validation["ok"] or res.errors:
        base.update(ok=False, error="; ".join(res.validation["errors"] + res.errors),
                    errors=res.validation["errors"] + res.errors, changes=[], files=[], diffs={},
                    warnings=res.warnings, summary="The requested setup is not valid")
        return base
    files, diffs = [], {}
    for path, f in _ordered(res):
        d = _udiff(path, f["old"], f["new"])
        diffs[path] = d
        files.append({"path": path, "step": f["step"], "title": STEP_TITLE[f["step"]],
                      "action": "create" if f["old"] is None else "delete" if f["new"] is None else "modify",
                      "mode": oct(f["mode"]), "added": sum(1 for l in d.splitlines() if l[:1] == "+" and l[:3] != "+++"),
                      "removed": sum(1 for l in d.splitlines() if l[:1] == "-" and l[:3] != "---")})
    if ctx.validate and res.files:
        tmp = tempfile.mkdtemp(prefix="tuxwall-plan-")
        try:
            run_validators(ctx, res, tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    groups = []
    for step, title in STEPS:
        items = [c["text"] for c in res.changes if c["step"] == step]
        if items or step in res.steps:
            groups.append({"step": step, "title": title, "items": items or ["Reloaded to pick up the changes."],
                           "files": [f["path"] for f in files if f["step"] == step],
                           "actions": [" ".join(a["cmd"]) for a in actions(res) if a["step"] == step]})
    if not files and not res.extra_actions:
        groups = []
    bad = [v for v in res.validators if v["ok"] is False]
    pol = res.policy or {}
    base.update(ok=True, changes=groups, files=files, diffs=diffs, warnings=res.warnings,
                validators=res.validators, validators_ok=not bad, lockout=res.lockout,
                summary="No changes" if not groups else "%d step(s), %d file(s)%s" % (
                    len(groups), len(files), "; %d validator(s) failed" % len(bad) if bad else ""),
                policy_edits=pol.get("edits", []), raw_replaced=pol.get("raw_replaced", False),
                matrix_after={s: {d: c["state"] for d, c in row.items()} for s, row in
                              ((pol.get("after") or {}).get("cells") or {}).items()},
                plan_hash=plan_hash(res) if groups else "", presets={k: v["label"] for k, v in PRESETS.items()})
    return base


LOCK_MESSAGE = ("Plan only - Apply is locked on this router. Test in a VM, then set "
                "apply_locked=false in /etc/tuxwall/interfaces.json.")
