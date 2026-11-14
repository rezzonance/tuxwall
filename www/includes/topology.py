"""TuxWall interface roles (WAN / LAN / OPTn / VPN) and what is bound to them.

/etc/tuxwall/interfaces.json is the record of which NIC plays which role.
When it is missing, the roles are detected from the live box (default route,
Kea subnets, VLAN file, WireGuard), so every caller gets the same answer the
old per-helper detection gave.

Read-only: nothing here changes the network. The only file this module ever
writes is interfaces.json itself (ensure()/write(), atomic, never overwrites).

Command line (root):
  python3 topology.py            print the effective topology
  python3 topology.py --write    create interfaces.json if missing
  python3 topology.py --policy   print the current effective policy matrix
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time

CONF = "/etc/tuxwall/interfaces.json"
PROFILE = "/etc/tuxwall/install-profile.json"
NETWORK_JSON = "/etc/tuxwall/network.json"
VLAN_FILE = "/etc/tuxwall/vlans.json"
KEA_CONF = "/etc/kea/kea-dhcp4.conf"
RADVD_CONF = "/etc/radvd.conf"
UNBOUND_DIR = "/etc/unbound/unbound.conf.d"
NETPLAN_DIR = "/etc/netplan"
SURICATA_CONF = "/etc/suricata/suricata.yaml"
SQM_CONF = "/etc/tuxwall/sqm.conf"
AVAHI_CONF = "/etc/avahi/avahi-daemon.conf"
UFW_DEFAULTS = "/etc/default/ufw"
UFW_BEFORE = "/etc/ufw/before.rules"
UFW_USER = ("/etc/ufw/user.rules", "/etc/ufw/user6.rules")
WG_DIR = "/etc/wireguard"
HONEYPOT_CONF = "/var/lib/tuxwall/honeypot.json"
NAT_DROPIN = "/etc/systemd/system/tuxwall-nat.service.d"
SYS_NET = "/sys/class/net"

VERSION = 1
_cache = {"key": None, "data": None}


# ---------------------------------------------------------------- helpers

def _run(args, timeout=5):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout).stdout
    except Exception:
        return ""


def _ip_json(*args):
    try:
        return json.loads(_run(["ip", "-j"] + list(args)) or "[]")
    except ValueError:
        return []


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _read_kea():
    text = _read(KEA_CONF)
    if not text:
        return {}
    try:
        return json.loads(text)
    except ValueError:
        pass
    # Kea accepts // # and /* */ comments; strip them outside strings
    out, i, n, q = [], 0, len(text), False
    while i < n:
        c = text[i]
        if q:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 1
            elif c == '"':
                q = False
        elif c == '"':
            q = True; out.append(c)
        elif c == "#" or text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    try:
        return json.loads("".join(out))
    except ValueError:
        return {}


def _default_route_dev():
    for r in _ip_json("route", "show", "default"):
        if r.get("dev"):
            return r["dev"]
    return ""


def _net(cidr):
    try:
        return ipaddress.ip_interface(cidr).network
    except ValueError:
        return None


def _yaml_load(text):
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except Exception:
        return {}


def _netplan():
    """Merged ethernets/vlans from /etc/netplan (later files win per key)."""
    eth, vlans = {}, {}
    try:
        names = sorted(f for f in os.listdir(NETPLAN_DIR) if f.endswith(".yaml"))
    except OSError:
        names = []
    for name in names:
        net = (_yaml_load(_read(os.path.join(NETPLAN_DIR, name))) or {}).get("network") or {}
        for k, v in (net.get("ethernets") or {}).items():
            eth.setdefault(k, {}).update(v or {})
        for k, v in (net.get("vlans") or {}).items():
            vlans.setdefault(k, {}).update(v or {})
    return eth, vlans


def _radvd_ifaces():
    return re.findall(r"^\s*interface\s+(\S+)\s*\{", _read(RADVD_CONF), re.M)


# ---------------------------------------------------------------- inventory

def _sys(dev, name):
    return _read("/sys/class/net/%s/%s" % (dev, name)).strip()


def inventory():
    """Every interface except lo: mac, kind, driver, speed, link, addresses."""
    links = _ip_json("-d", "link", "show")
    addrs = {a.get("ifname"): a.get("addr_info", []) for a in _ip_json("addr", "show")}
    out = []
    for l in links:
        dev = l.get("ifname", "")
        if not dev or dev == "lo":
            continue
        li = l.get("linkinfo") or {}
        kind = li.get("info_kind") or ""
        if not kind:
            kind = "ethernet" if os.path.exists("/sys/class/net/%s/device" % dev) else "virtual"
        drv = ""
        try:
            drv = os.path.basename(os.readlink("/sys/class/net/%s/device/driver" % dev))
        except OSError:
            pass
        speed = None
        try:
            s = int(_sys(dev, "speed"))
            speed = s if s > 0 else None
        except ValueError:
            pass
        carrier = _sys(dev, "carrier") == "1"
        out.append({
            "device": dev,
            "mac": l.get("address", "") if l.get("link_type") == "ether" else "",
            "kind": kind,
            "driver": drv,
            "speed_mbit": speed,
            "carrier": carrier,
            "operstate": (l.get("operstate") or "").lower(),
            "mtu": l.get("mtu"),
            "vlan": (li.get("info_data") or {}).get("id") if kind == "vlan" else None,
            "parent": l.get("link") if kind == "vlan" else None,
            "addresses": [
                {"family": "inet" if a.get("family") == "inet" else "inet6",
                 "cidr": "%s/%s" % (a.get("local"), a.get("prefixlen")),
                 "scope": a.get("scope", ""), "dynamic": bool(a.get("dynamic"))}
                for a in addrs.get(dev, []) if a.get("local")
            ],
        })
    return out


# ---------------------------------------------------------------- detection

def _first_v4_in(dev_addrs, net):
    for a in dev_addrs:
        if a.get("family") == "inet":
            ip = ipaddress.ip_interface("%s/%s" % (a["local"], a["prefixlen"]))
            if net is None or ip.ip in net:
                return str(ip)
    return ""


def detect():
    """Build the topology record from install-profile.json + the live box."""
    prof = _read_json(PROFILE) or {}
    netj = _read_json(NETWORK_JSON) or {}
    addrs = {a.get("ifname"): a.get("addr_info", []) for a in _ip_json("addr", "show")}
    links = {l.get("ifname"): l for l in _ip_json("-d", "link", "show")}
    eth_np, vlan_np = _netplan()
    kea4 = (_read_kea().get("Dhcp4") or {})
    kea_ifaces = [str(i).split("/")[0] for i in
                  ((kea4.get("interfaces-config") or {}).get("interfaces") or [])]
    ra = set(_radvd_ifaces())
    vfile = _read_json(VLAN_FILE) or {}

    def prof_dev(role):
        v = prof.get(role) or prof.get(role + "_iface") or prof.get(role + "_interface")
        if isinstance(v, dict):
            v = v.get("device") or v.get("iface")
        return str(v) if v else ""

    wan_dev = str(netj.get("wan_iface") or "") or prof_dev("wan") or _default_route_dev()
    wan_mode = "dhcp"
    if wan_dev:
        np = eth_np.get(wan_dev) or {}
        dyn = any(a.get("dynamic") for a in addrs.get(wan_dev, []) if a.get("family") == "inet")
        if not (np.get("dhcp4") or dyn) and (np.get("addresses") or addrs.get(wan_dev)):
            wan_mode = "static"
    if wan_dev and wan_dev == prof_dev("wan") and prof.get("wan_mode") in ("dhcp", "static"):
        wan_mode = prof["wan_mode"]
    wan = {"device": wan_dev, "mode": wan_mode}
    if wan_mode == "static":
        wan["address"] = _first_v4_in(addrs.get(wan_dev, []), None) or \
            next((a for a in (eth_np.get(wan_dev) or {}).get("addresses") or [] if ":" not in str(a)), "")

    def kind(dev):
        return ((links.get(dev) or {}).get("linkinfo") or {}).get("info_kind") or ""

    def configured_v4(dev, net):
        a = _first_v4_in(addrs.get(dev, []), net)
        if a:
            return a
        np = eth_np.get(dev) or vlan_np.get(dev) or {}
        for c in np.get("addresses") or []:
            c = str(c)
            if ":" not in c and (net is None or ipaddress.ip_interface(c).ip in net):
                return c
        return ""

    # one entry per Kea-served interface, in subnet order
    nets = []
    for s in kea4.get("subnet4") or []:
        dev = s.get("interface") or ""
        sub = _net(s.get("subnet", ""))
        if not dev or dev == wan_dev or sub is None or any(n["device"] == dev for n in nets):
            continue
        addr = configured_v4(dev, sub)
        if not addr:
            gw = next((o.get("data") for o in s.get("option-data") or []
                       if o.get("name") == "routers"), "")
            if gw:
                addr = "%s/%d" % (gw.split(",")[0].strip(), sub.prefixlen)
        nets.append({"device": dev, "address": addr, "dhcp": dev in kea_ifaces,
                     "ra": dev in ra, "kea_subnet_id": s.get("id")})
    # VLANs (vlans.json / netplan) not served by Kea
    for dev, meta in list(vfile.items()) + [(k, {}) for k in vlan_np]:
        if dev.startswith("__") or dev == wan_dev or any(n["device"] == dev for n in nets):
            continue
        meta = meta if isinstance(meta, dict) else {}
        nets.append({"device": dev, "address": meta.get("address") or configured_v4(dev, None),
                     "dhcp": False, "ra": dev in ra})

    lan_dev = prof_dev("lan")
    if lan_dev and lan_dev != wan_dev and not any(n["device"] == lan_dev for n in nets):
        pn, pg = _net(str(prof.get("lan_network") or "")), str(prof.get("lan_gateway") or "")
        nets.insert(0, {"device": lan_dev, "dhcp": lan_dev in kea_ifaces, "ra": lan_dev in ra,
                        "address": configured_v4(lan_dev, pn) or
                        ("%s/%d" % (pg, pn.prefixlen) if pn and pg else "")})
    if not lan_dev or lan_dev == wan_dev:
        lan_dev = ""
        for n in nets:  # first non-VLAN served network that is actually up
            if "." not in n["device"] and kind(n["device"]) != "vlan" and \
                    _first_v4_in(addrs.get(n["device"], []), None):
                lan_dev = n["device"]; break
        if not lan_dev and nets:
            lan_dev = nets[0]["device"]

    lan, opt = {}, []
    for n in nets:
        dev = n["device"]
        if dev == lan_dev:
            lan = {"device": dev, "address": n["address"], "dhcp": n["dhcp"], "ra": n["ra"]}
            continue
        o = {"id": "opt%d" % (len(opt) + 1), "name": "", "device": dev,
             "address": n["address"], "dhcp": n["dhcp"], "ra": n["ra"]}
        vl = links.get(dev) or {}
        vid = ((vl.get("linkinfo") or {}).get("info_data") or {}).get("id")
        vmeta = vfile.get(dev) if isinstance(vfile.get(dev), dict) else {}
        vnp = vlan_np.get(dev) or {}
        vid = vid or vmeta.get("vlan_id") or vnp.get("id")
        if vid:
            o["vlan"] = int(vid)
            o["parent"] = vl.get("link") or vmeta.get("parent") or vnp.get("link") or dev.split(".")[0]
        o["name"] = vmeta.get("label") or ("VLAN %s" % vid if vid else o["id"].upper())
        opt.append(o)

    vpn = []
    wg = sorted(set([d for d, l in links.items() if kind(d) == "wireguard"] +
                    [f[:-5] for f in (os.listdir(WG_DIR) if os.path.isdir(WG_DIR) else [])
                     if re.match(r"^[A-Za-z0-9_.-]+\.conf$", f)]))
    for dev in wg:
        v4 = _first_v4_in(addrs.get(dev, []), None)
        vpn.append({"id": dev, "name": "WireGuard" if len(wg) == 1 else "WireGuard %s" % dev,
                    "device": dev, "address": v4})

    return {"version": VERSION, "wan": wan, "lan": lan, "opt": opt, "vpn": vpn,
            "policy": None, "apply_locked": True,
            "generated": {"by": "topology.detect", "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                          "from": "install-profile+live" if prof else "live"}}


# ---------------------------------------------------------------- load

def _file_key():
    try:
        st = os.stat(CONF)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def has_file():
    return _file_key() is not None


def load():
    """The topology: interfaces.json when present, else detected live.

    File reads are cached by mtime; detection is never cached (it is the
    fallback the old helpers performed on every call)."""
    key = _file_key()
    if key is not None:
        if _cache["key"] == key:
            return _cache["data"]
        data = _read_json(CONF)
        if isinstance(data, dict) and isinstance(data.get("wan"), dict):
            data.setdefault("opt", []); data.setdefault("vpn", []); data.setdefault("lan", {})
            data.setdefault("apply_locked", True)
            _cache.update(key=key, data=data)
            return data
    return detect()


def write(data, path=CONF):
    """Atomic write (0644; the record holds no secrets)."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".interfaces.", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ensure():
    """Create interfaces.json from the live box if it does not exist yet.
    Returns True when a file was written. Never overwrites."""
    if has_file():
        return False
    data = detect()
    if not data["wan"].get("device") or not data["lan"].get("device"):
        return False  # not enough to go on (first boot before networking)
    write(data)
    return True


def sync_legacy_vlan(op, dev, meta, path=CONF):
    """Keep the record in step with the old VLANs page (add/edit/delete),
    which changes the live interface directly. Only touches an existing
    record; returns True when it was rewritten."""
    data = _read_json(path)
    if not isinstance(data, dict) or not dev:
        return False
    meta = meta or {}
    opts = [o for o in data.get("opt") or [] if isinstance(o, dict)]
    hit = next((o for o in opts if o.get("device") == dev), None)
    if op == "delete":
        if not hit:
            return False
        opts.remove(hit)
    elif op == "edit":
        if not hit:
            return False
        if meta.get("label"):
            hit["name"] = meta["label"]
        if meta.get("address"):
            hit["address"] = meta["address"]
        else:
            hit.pop("address", None)
    elif op == "add":
        if hit:
            return False
        used = {o.get("id") for o in opts}
        n = 1
        while "opt%d" % n in used:
            n += 1
        try:
            vid = int(meta.get("vlan_id"))
        except (TypeError, ValueError):
            return False
        o = {"id": "opt%d" % n, "name": meta.get("label") or "VLAN %d" % vid, "device": dev,
             "dhcp": False, "ra": False, "vlan": vid, "parent": meta.get("parent", "")}
        if meta.get("address"):
            o["address"] = meta["address"]
        opts.append(o)
    else:
        return False
    data["opt"] = opts
    write(data, path)
    return True


# ---------------------------------------------------------------- accessors

def wan():
    return load().get("wan") or {}


def wan_device():
    """WAN device from the record only ('' when there is no record, so the
    callers keep their own live fallback)."""
    if not has_file():
        return ""
    return str((load().get("wan") or {}).get("device") or "")


def lan():
    return load().get("lan") or {}


def lan_device():
    if not has_file():
        return ""
    return str((load().get("lan") or {}).get("device") or "")


def lan_address():
    """'192.168.1.1/24' style, from the record only."""
    if not has_file():
        return ""
    return str((load().get("lan") or {}).get("address") or "")


def networks(topo=None):
    """lan + opt + vpn, each with role, id, name, device and subnet."""
    t = topo or load()
    addrs = {a.get("ifname"): a.get("addr_info", []) for a in _ip_json("addr", "show")}
    out = []

    def add(role, nid, name, n):
        dev = n.get("device", "")
        addr = n.get("address") or _first_v4_in(addrs.get(dev, []), None)
        net = _net(addr) if addr else None
        v6 = []
        for a in addrs.get(dev, []):
            if a.get("family") == "inet6" and a.get("scope") == "global":
                s = str(ipaddress.ip_interface("%s/%s" % (a["local"], a["prefixlen"])).network)
                if s not in v6:
                    v6.append(s)
        item = dict(n)
        item.update({"role": role, "id": nid, "name": name, "device": dev,
                     "address": addr, "subnet": str(net) if net else "", "subnets6": v6})
        out.append(item)

    if (t.get("lan") or {}).get("device"):
        add("lan", "lan", t["lan"].get("name") or "LAN", t["lan"])
    for o in t.get("opt") or []:
        add("opt", o.get("id") or o.get("device"), o.get("name") or o.get("id"), o)
    for v in t.get("vpn") or []:
        add("vpn", v.get("id") or v.get("device"), v.get("name") or "VPN", v)
    return out


def role_of(dev, topo=None):
    t = topo or load()
    if not dev:
        return ""
    if (t.get("wan") or {}).get("device") == dev:
        return "wan"
    if (t.get("lan") or {}).get("device") == dev:
        return "lan"
    for o in t.get("opt") or []:
        if o.get("device") == dev:
            return o.get("id") or "opt"
    for v in t.get("vpn") or []:
        if v.get("device") == dev:
            return "vpn"
    return ""


def validate(topo=None):
    """Structural checks. Returns {"ok", "errors": [...], "warnings": [...]}."""
    t = topo or load()
    errors, warnings = [], []
    devs = {}
    entries = [("wan", t.get("wan") or {}), ("lan", t.get("lan") or {})] + \
        [(o.get("id") or "opt", o) for o in t.get("opt") or []] + \
        [(v.get("id") or "vpn", v) for v in t.get("vpn") or []]
    if not (t.get("wan") or {}).get("device"):
        errors.append("No WAN interface assigned.")
    if not (t.get("lan") or {}).get("device"):
        errors.append("No LAN interface assigned.")
    w = t.get("wan") or {}
    if w.get("mode") not in (None, "dhcp", "static"):
        errors.append("WAN mode must be dhcp or static.")
    if w.get("mode") == "static":
        try:
            ipaddress.ip_interface(str(w.get("address") or ""))
            if "/" not in str(w.get("address")):
                raise ValueError
        except ValueError:
            errors.append("WAN: a static WAN needs an address like 203.0.113.2/24.")
        if w.get("gateway"):
            try:
                ipaddress.ip_address(str(w["gateway"]))
            except ValueError:
                errors.append("WAN: bad gateway %s." % w["gateway"])
    present = set(os.listdir(SYS_NET)) if os.path.isdir(SYS_NET) else set()
    nets = []
    for rid, e in entries:
        dev = e.get("device")
        if not dev:
            continue
        if dev in devs:
            errors.append("%s is assigned twice (%s and %s)." % (dev, devs[dev], rid))
        devs[dev] = rid
        if present and dev not in present and not e.get("vlan"):
            warnings.append("%s (%s) does not exist on this machine." % (dev, rid))
        vid = e.get("vlan")
        if vid is not None:
            if not (isinstance(vid, int) and 1 <= vid <= 4094):
                errors.append("%s: VLAN id must be 1-4094." % rid)
            if present and e.get("parent") and e["parent"] not in present:
                errors.append("%s: parent %s does not exist." % (rid, e["parent"]))
        addr = e.get("address")
        if addr and rid != "wan":
            try:
                ipi = ipaddress.ip_interface(addr)
            except ValueError:
                errors.append("%s: bad address %s." % (rid, addr)); continue
            if ipi.ip == ipi.network.network_address or (
                    ipi.version == 4 and ipi.network.prefixlen < 31 and
                    ipi.ip == ipi.network.broadcast_address):
                errors.append("%s: %s is not a usable host address." % (rid, addr))
            if not ipi.ip.is_private:
                warnings.append("%s: %s is not a private address." % (rid, addr))
            if ipi.ip.is_loopback or ipi.ip.is_link_local or ipi.ip.is_multicast or \
                    ipi.ip.is_unspecified or (ipi.version == 4 and ipi.ip in ipaddress.ip_network("0.0.0.0/8")):
                errors.append("%s: %s is in a reserved range." % (rid, addr))
            elif ipi.version == 4 and ipi.ip in ipaddress.ip_network("100.64.0.0/10"):
                warnings.append("%s: %s is carrier-grade NAT space (100.64.0.0/10)." % (rid, addr))
            if ipi.version == 4 and ipi.network.prefixlen > 30 and e.get("dhcp"):
                errors.append("%s: /%d is too small for a DHCP pool." % (rid, ipi.network.prefixlen))
            pool = e.get("pool")
            if pool:
                try:
                    a, b = [ipaddress.ip_address(x.strip()) for x in str(pool).split("-", 1)]
                except ValueError:
                    errors.append("%s: DHCP pool must look like a.b.c.d-a.b.c.e." % rid); a = b = None
                if a is not None:
                    if a.version != ipi.version or a not in ipi.network or b not in ipi.network:
                        errors.append("%s: DHCP pool %s is not inside %s." % (rid, pool, ipi.network))
                    elif int(a) > int(b):
                        errors.append("%s: DHCP pool start is after its end." % rid)
                    elif int(a) <= int(ipi.ip) <= int(b):
                        errors.append("%s: the gateway %s is inside the DHCP pool %s." % (rid, ipi.ip, pool))
                    elif a == ipi.network.network_address or (
                            ipi.version == 4 and b == ipi.network.broadcast_address):
                        errors.append("%s: DHCP pool %s includes the network or broadcast address." % (rid, pool))
            nets.append((rid, ipi.network))
        if vid is not None and e.get("parent") and e.get("parent") == (t.get("wan") or {}).get("device"):
            warnings.append("%s: VLAN %s rides on the WAN interface %s." % (rid, vid, e["parent"]))
    for i, (a, na) in enumerate(nets):
        for b, nb in nets[i + 1:]:
            if na.overlaps(nb):
                errors.append("%s and %s overlap (%s / %s)." % (a, b, na, nb))
    return {"ok": not errors, "errors": errors, "warnings": warnings}


# ---------------------------------------------------------------- firewall

def _ufw_tuples(texts=None):
    """Parse '### tuple ###' lines of user.rules / user6.rules in file order.
    texts: optional {"v4": text, "v6": text} instead of the live files."""
    rules = []
    for fam, path in zip(("v4", "v6"), UFW_USER):
        for line in (texts[fam] if texts is not None else _read(path)).splitlines():
            if not line.startswith("### tuple ### "):
                continue
            parts = line[len("### tuple ### "):].split()
            if len(parts) < 6:
                continue
            comment = ""
            rest = parts[6:]
            for p in list(rest):
                if p.startswith("comment="):
                    try:
                        comment = bytes.fromhex(p[8:]).decode("utf-8", "replace")
                    except ValueError:
                        comment = p[8:]
                    rest.remove(p)
            action = parts[0]
            route = action.startswith("route:")
            action = action.split(":", 1)[-1]
            direction = rest[0] if rest else "in"
            iin = iout = ""
            for seg in direction.split("!"):
                if seg.startswith("in_"):
                    iin = seg[3:]
                elif seg.startswith("out_"):
                    iout = seg[4:]
            rules.append({
                "family": fam, "route": route, "action": action,
                "proto": parts[1], "dport": parts[2], "dst": parts[3],
                "sport": parts[4], "src": parts[5], "in": iin, "out": iout,
                "comment": comment,
            })
    return rules


def _any(addr):
    return addr in ("0.0.0.0/0", "::/0", "any")


def ufw_rule_text(r):
    s = ("route " if r["route"] else "") + r["action"]
    if r["in"]:
        s += " in on " + r["in"]
    if r["out"]:
        s += " out on " + r["out"]
    if not _any(r["src"]):
        s += " from " + r["src"]
    if not _any(r["dst"]) or r["dport"] != "any":
        s += " to " + (r["dst"] if not _any(r["dst"]) else "any")
    if r["dport"] != "any":
        s += " port " + r["dport"]
    if r["proto"] != "any":
        s += " proto " + r["proto"]
    if r["family"] == "v6":
        s += " (v6)"
    if r["comment"]:
        s += "  # " + r["comment"]
    return s


def _ufw_defaults():
    d = {}
    for m in re.finditer(r'^DEFAULT_(\w+)_POLICY="?(\w+)"?', _read(UFW_DEFAULTS), re.M):
        d[m.group(1).lower()] = m.group(2).upper()
    return d


def _raw_forward():
    """Direct FORWARD accepts outside ufw (e.g. ensure_wg_routing's
    '-i wg0 -j ACCEPT'), which take effect before every ufw rule."""
    out = []
    for fam, tool in (("v4", "iptables"), ("v6", "ip6tables")):
        for line in _run([tool, "-S", "FORWARD"]).splitlines():
            m = re.match(r"^-A FORWARD (-[io]) (\S+) -j (ACCEPT|DROP|REJECT)$", line.strip())
            if m:
                out.append({"family": fam, "dir": "in" if m.group(1) == "-i" else "out",
                            "dev": m.group(2), "target": m.group(3), "text": line.strip()})
    return out


def _before_forward_drops():
    return re.findall(r"^-A ufw6?-before-forward -i (\S+) -j DROP\s*$", _read(UFW_BEFORE), re.M)


_DNS_DHCP_PORTS = {"53", "67", "68", "546", "547", "5353"}


def current_policy(topo=None, rules=None, raw=None, wan_drop=None, nets=None, legacy=None):
    """The effective zone-to-zone matrix derived from today's rules.

    Cell states: allow | block | established (return traffic only) |
    dns_dhcp (gateway column) | custom (gateway column, other ports) | self.
    Each cell carries the rules that decided it, exceptions (narrower
    rules seen first) and the v6 state when it differs.
    rules/raw/wan_drop/nets override the live sources (the plan engine
    derives the matrix of a rendered, not yet applied, rule set)."""
    t = topo or load()
    nets = networks(t) if nets is None else nets
    w = (t.get("wan") or {}).get("device", "")
    zones = [{"id": n["id"], "role": n["role"], "name": n["name"], "device": n["device"],
              "subnet": n["subnet"], "subnets6": n["subnets6"]} for n in nets]
    zones.append({"id": "wan", "role": "wan", "name": "WAN / Internet", "device": w,
                  "subnet": "", "subnets6": []})
    cols = zones + [{"id": "gw", "role": "gateway", "name": "Gateway (router)",
                     "device": "", "subnet": "", "subnets6": []}]
    by_dev = {z["device"]: z["id"] for z in zones if z["device"]}

    def zone_of_net(addr):
        if _any(addr):
            return None
        try:
            a = ipaddress.ip_network(addr, strict=False)
        except ValueError:
            return None
        for z in zones:
            for s in [z["subnet"]] + z["subnets6"]:
                if s and a.version == ipaddress.ip_network(s).version and \
                        a.subnet_of(ipaddress.ip_network(s)):
                    return z["id"]
        return None

    rules = _ufw_tuples() if rules is None else rules
    defaults = _ufw_defaults()
    raw = _raw_forward() if raw is None else raw
    wan_drop = set(_before_forward_drops() if wan_drop is None else wan_drop)
    notes = []

    def fwd_cell(src, dst, fam):
        if src["id"] == dst["id"]:
            return {"state": "self", "rules": [], "exceptions": []}
        for r in raw:
            if r["family"] == fam and r["target"] == "ACCEPT" and (
                    (r["dir"] == "in" and r["dev"] == src["device"]) or
                    (r["dir"] == "out" and r["dev"] == dst["device"])):
                return {"state": "allow", "rules": [r["text"] + "  (iptables, before ufw)"],
                        "exceptions": [], "source": "iptables"}
        if src["device"] and src["device"] in wan_drop:
            return {"state": "established", "rules": ["-A ufw-before-forward -i %s -j DROP" % src["device"]],
                    "exceptions": [], "source": "before.rules"}
        exc = []
        for r in rules:
            if not r["route"] or r["family"] != fam:
                continue
            if r["in"] or r["out"]:
                if (r["in"] and r["in"] != src["device"]) or (r["out"] and r["out"] != dst["device"]):
                    continue
                full = _any(r["src"]) and _any(r["dst"])
            else:
                zs, zd = zone_of_net(r["src"]), zone_of_net(r["dst"])
                if zs != src["id"] or zd != dst["id"]:
                    continue
                full = True  # subnet-to-subnet rule covers the whole zone pair
            full = full and r["proto"] == "any" and r["dport"] == "any"
            if full:
                return {"state": "allow" if r["action"] == "allow" else "block",
                        "rules": [ufw_rule_text(r)], "exceptions": exc, "source": "ufw"}
            exc.append(ufw_rule_text(r))
        return {"state": "allow" if defaults.get("forward") == "ACCEPT" else "block",
                "rules": ["default forward policy %s" % defaults.get("forward", "?")],
                "exceptions": exc, "source": "default", "default": True}

    def gw_cell(src, fam):
        dev = src["device"]
        ports, deciding, exc = [], [], []
        for r in rules:
            if r["route"] or r["family"] != fam or (r["in"] and r["in"] != dev) or not r["in"]:
                continue
            if r["dport"] == "any" and r["proto"] == "any" and _any(r["src"]):
                deciding.append(ufw_rule_text(r))
                if r["action"] == "allow":
                    return {"state": "allow", "rules": deciding, "exceptions": [], "source": "ufw"}
                break
            if r["action"] == "allow":
                ports.append("%s/%s" % (r["dport"], r["proto"]) if r["proto"] != "any" else r["dport"])
                exc.append(ufw_rule_text(r))
        if not ports:
            st = "block"
        elif all(p.split("/")[0] in _DNS_DHCP_PORTS for p in ports):
            st = "dns_dhcp"
        else:
            st = "custom"
        return {"state": st, "ports": sorted(set(ports), key=lambda p: (len(p), p)),
                "rules": deciding or ["default input policy %s" % defaults.get("input", "?")],
                "exceptions": exc, "source": "ufw"}

    cells = {}
    for s in zones:
        row = {}
        for d in cols:
            if d["id"] == "gw":
                c4, c6 = gw_cell(s, "v4"), gw_cell(s, "v6")
            else:
                c4, c6 = fwd_cell(s, d, "v4"), fwd_cell(s, d, "v6")
            if c6["state"] != c4["state"]:
                c4["v6"] = c6["state"]
                c4["v6_rules"] = c6["rules"]
            row[d["id"]] = c4
        cells[s["id"]] = row

    # inter-VLAN policies created on the old VLANs page (vlans.json __policies__)
    if legacy is None:
        legacy = (_read_json(VLAN_FILE) or {}).get("__policies__") or []
    legacy_out = []
    for lp in legacy if isinstance(legacy, list) else []:
        if not isinstance(lp, dict):
            continue
        s, d = by_dev.get(lp.get("src") or ""), by_dev.get(lp.get("dst") or "")
        ent = {"id": lp.get("id", ""), "src": lp.get("src", ""), "dst": lp.get("dst", ""),
               "policy": lp.get("policy", ""), "proto": lp.get("proto", "any"),
               "port": lp.get("port", ""), "rule": lp.get("rule", ""),
               "cell": [s, d] if s and d and s != d else None}
        legacy_out.append(ent)
        if ent["cell"]:
            cells[s][d].setdefault("legacy", []).append(ent)
        else:
            notes.append("VLANs-page policy %s (%s) refers to an interface that is in no network."
                         % (ent["id"] or "?", ent["rule"] or "%s -> %s" % (ent["src"], ent["dst"])))

    shadow = [r for r in raw if r["target"] == "ACCEPT"]
    if shadow:
        notes.append("Raw FORWARD accepts (%s) run before ufw, so ufw deny rules for "
                     "those interfaces have no effect." % ", ".join(sorted({r["dev"] for r in shadow})))
    for d in wan_drop:
        notes.append("New connections from %s are dropped in before.rules; only return "
                     "traffic (and port forwards via DNAT) pass." % d)
    return {"ok": True, "source": "derived", "managed": bool(t.get("policy")),
            "rows": zones, "columns": cols, "cells": cells,
            "defaults": defaults, "notes": notes, "legacy_policies": legacy_out,
            "states": ["allow", "block", "established", "dns_dhcp", "custom", "self"]}


# ---------------------------------------------------------------- bindings

def _unbound():
    acl, ifs = [], []
    try:
        names = sorted(os.listdir(UNBOUND_DIR))
    except OSError:
        names = []
    for n in names:
        if not n.endswith(".conf"):
            continue
        for line in _read(os.path.join(UNBOUND_DIR, n)).splitlines():
            line = line.split("#", 1)[0].strip()
            m = re.match(r"^access-control:\s*(\S+)\s+(\S+)", line)
            if m:
                acl.append({"net": m.group(1), "action": m.group(2), "file": n})
            m = re.match(r"^interface:\s*(\S+)", line)
            if m:
                ifs.append({"addr": m.group(1), "file": n})
    return acl, ifs


def _suricata():
    text = _read(SURICATA_CONF)
    m = re.search(r"^af-packet:\s*\n(.*?)(?=^\S)", text, re.M | re.S)
    af = re.findall(r"^\s*-\s*interface:\s*(\S+)", m.group(1), re.M) if m else []
    hn = re.search(r'^\s*HOME_NET:\s*"?\[?([^"\]\n]*)', text, re.M)
    home = [x.strip() for x in hn.group(1).split(",") if x.strip()] if hn else []
    return [a for a in af if a != "default"], home


def _kv(path):
    d = {}
    for line in _read(path).splitlines():
        m = re.match(r"^\s*([A-Za-z_]+)\s*=\s*\"?([^\"#]*)\"?", line)
        if m:
            d[m.group(1)] = m.group(2).strip()
    return d


def _nat():
    out = []
    for fam, tool in (("v4", "iptables"), ("v6", "ip6tables")):
        for line in _run([tool, "-t", "nat", "-S", "POSTROUTING"]).splitlines():
            if "MASQUERADE" in line or "SNAT" in line:
                out.append({"family": fam, "text": line.strip(),
                            "out": (re.search(r"-o (\S+)", line) or [None, ""])[1],
                            "src": (re.search(r"-s (\S+)", line) or [None, ""])[1]})
    return out


def _nat_dropin():
    v = ""
    try:
        for n in sorted(os.listdir(NAT_DROPIN)):
            m = re.search(r"TUXWALL_WAN_IFACE=(\S+)", _read(os.path.join(NAT_DROPIN, n)))
            if m:
                v = m.group(1).strip("\"'")
    except OSError:
        pass
    return v


def _wg_conf(dev):
    d = {}
    for line in _read(os.path.join(WG_DIR, dev + ".conf")).splitlines():
        m = re.match(r"^\s*(Address|ListenPort)\s*=\s*(.+)$", line)
        if m:  # never the keys
            d[m.group(1).lower()] = m.group(2).strip()
    return d


def bindings(topo=None):
    """What each configured service binds to each role (read-only view)."""
    t = topo or load()
    nets = networks(t)
    kea4 = (_read_kea().get("Dhcp4") or {})
    kea_ifaces = [str(i).split("/")[0] for i in
                  ((kea4.get("interfaces-config") or {}).get("interfaces") or [])]
    radvd_text = _read(RADVD_CONF)
    radvd = {}
    for m in re.finditer(r"^\s*interface\s+(\S+)\s*\{(.*?)^\};", radvd_text, re.M | re.S):
        radvd[m.group(1)] = re.findall(r"^\s*prefix\s+(\S+)", m.group(2), re.M)
    acl, ub_ifs = _unbound()
    af, home = _suricata()
    sqm = _kv(SQM_CONF)
    avahi = _kv(AVAHI_CONF)
    nat = _nat()
    rules = _ufw_tuples()
    honey = _read_json(HONEYPOT_CONF) or {}
    w = (t.get("wan") or {}).get("device", "")

    def in_net(a, nets_):
        try:
            x = ipaddress.ip_network(a, strict=False)
        except ValueError:
            return False
        for s in nets_:
            try:
                y = ipaddress.ip_network(s)
            except ValueError:
                continue
            if x.version == y.version and (x.subnet_of(y) or y.subnet_of(x)) and x.prefixlen >= y.prefixlen:
                return True
        return False

    def avahi_state(dev):
        allow = [x.strip() for x in avahi.get("allow-interfaces", "").split(",") if x.strip()]
        deny = [x.strip() for x in avahi.get("deny-interfaces", "").split(",") if x.strip()]
        if dev in deny:
            return "denied"
        if allow:
            return "allowed" if dev in allow else "not listed"
        return "allowed"

    inv = {i["device"]: i for i in inventory()}
    out = {}
    all_nets = [dict(n) for n in nets] + [{"id": "wan", "role": "wan", "name": "WAN",
                                            "device": w, "subnet": "", "subnets6": []}]
    for n in all_nets:
        dev = n["device"]
        subs = [s for s in [n.get("subnet")] + list(n.get("subnets6") or []) if s]
        addrs = [str(ipaddress.ip_interface(a["cidr"]).ip)
                 for a in (inv.get(dev) or {}).get("addresses", [])]
        b = {}
        ks = [s for s in kea4.get("subnet4") or [] if s.get("interface") == dev]
        b["kea"] = {"listening": dev in kea_ifaces,
                    "subnets": [{"id": s.get("id"), "subnet": s.get("subnet"),
                                 "pools": [p.get("pool") for p in s.get("pools") or []],
                                 "reservations": len(s.get("reservations") or [])} for s in ks]}
        b["radvd"] = {"enabled": dev in radvd, "prefixes": radvd.get(dev, [])}
        b["unbound"] = {"access": [a for a in acl if a["action"] != "refuse" and in_net(a["net"], subs)],
                        "interfaces": [i for i in ub_ifs if i["addr"] in addrs]}
        b["ufw"] = [ufw_rule_text(r) for r in rules if dev and (r["in"] == dev or r["out"] == dev)
                    or (not r["in"] and not r["out"] and (in_net(r["src"], subs) or in_net(r["dst"], subs)))]
        b["nat"] = [x["text"] for x in nat if (dev and x["out"] == dev) or (x["src"] and in_net(x["src"], subs))]
        b["suricata"] = {"af_packet": dev in af,
                         "home_net": [h for h in home if in_net(h, subs)]}
        b["avahi"] = avahi_state(dev) if dev else ""
        if n["role"] == "wan":
            b["sqm"] = {"wan": sqm.get("WAN", ""), "matches": sqm.get("WAN", "") == dev}
            b["honeypot"] = {"enabled": bool(honey.get("enabled")), "ports": honey.get("ports") or [],
                             "iface": dev}
            b["canary_rules"] = sum(1 for r in rules if r["in"] == dev and r["comment"].startswith("tuxwall-canary"))
            b["nat_dropin"] = _nat_dropin()
        if n["role"] == "vpn":
            b["wireguard"] = _wg_conf(dev)
        out[n["id"]] = b
    return out


def interfaces_view():
    """Payload for GET /api/interfaces."""
    t = load()
    inv = inventory()
    for i in inv:
        i["role"] = role_of(i["device"], t)
    return {"ok": True, "source": "file" if has_file() else "detected", "path": CONF,
            "apply_locked": t.get("apply_locked", True) is not False,
            "topology": t, "networks": networks(t), "inventory": inv,
            "bindings": bindings(t), "validation": validate(t)}


def _norm(t):
    keep = ("wan", "lan", "opt", "vpn", "policy")
    return json.dumps({k: (t or {}).get(k) for k in keep}, sort_keys=True)


def plan(body, session_ip="", aps=None):
    """POST /api/interfaces/plan: render every affected config into a temp
    dir, validate it and return the ordered changes (assign_plan.py).
    aps: optional callable returning the cached OpenWrt AP/SSID data."""
    import assign_plan
    return assign_plan.plan(body if isinstance(body, dict) else {}, session_ip=session_ip,
                            ctx=assign_plan.Ctx(aps=aps))


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--write":
        wrote = ensure()
        print(("wrote %s" % CONF) if wrote else ("%s exists or detection incomplete; unchanged" % CONF))
    elif arg == "--detect":
        print(json.dumps(detect(), indent=2))
    elif arg == "--policy":
        print(json.dumps(current_policy(), indent=2))
    elif arg == "--view":
        print(json.dumps(interfaces_view(), indent=2))
    else:
        print(json.dumps(load(), indent=2))
