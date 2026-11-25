#!/usr/bin/env python3
"""Device quarantine for TuxWall device monitoring (3.3.7).

The dashboard API (root) quarantines a device from the Clients page; this
module holds everything that does not need the API: the persisted state,
the safety decision, the nftables rule plan, applying it, and the boot-time
restore (`quarantine.py restore`, run by tuxwall-quarantine.service before
the network comes up, so a quarantine survives a reboot even when the API is
down or slow to start).

Modes
  internet  the device keeps the LAN and the router, but nothing it sends is
            forwarded to the WAN (and nothing from the WAN reaches it).
  isolate   nothing is forwarded to or from the device at all (other LAN
            subnets, VLANs, VPN, WAN), and of the router itself it can only
            reach DNS (53), DHCP (67, DHCPv6 547) and ICMP/ICMPv6 (ping,
            neighbour discovery) - it stays diagnosable and can be released.
  Devices on the same switch / Wi-Fi segment talk to each other directly; the
  router cannot block traffic it does not route.

Matching: the device's MAC (`ether saddr`, every address it uses, including
new IPv6 privacy addresses) plus its current IPv4/IPv6 addresses (both
directions; the dashboard API refreshes them every minute from the device
inventory), WireGuard peers by their allowed IPs (host prefixes only).

nftables: own table `inet tuxwall_quarantine` (forward + input hooks at
priority -5, policy accept, drops only). ufw (iptables-nft), firewall
snapshots and their auto-revert, Tripwire and the CrowdSec bouncer only touch
their own tables, so the quarantine table survives all of them - like
`inet tuxwall_crowdsec_ranges`. The whole table is rewritten in one `nft -f`
transaction; with no quarantined device it has its sets and chains but no
rules.

State: /etc/tuxwall/devices/quarantine.json (root 0600)
    {"version": 1, "wan": [ifname, ...], "entries": [
        {"device", "kind" mac|wg|ip, "name", "mode", "mac", "ips", "ipv6",
         "nets" (WireGuard allowed IPs), "since", "expires" (epoch|null),
         "by", "note"}]}
"wan" is the WAN interface list seen at the last change, so the boot restore
needs no detection (the WAN may still be down). Expired entries are not
rendered at boot; the API drops, logs and notifies them on its next pass.
Every action is appended to /var/lib/tuxwall/device-actions.jsonl (root 0600,
rotated at 1 MB).

Safety (check_request): never the router's own MACs/addresses, never the
upstream gateway, never a WireGuard peer whose allowed IPs are wider than a
host prefix, and not the requesting admin's own device unless confirm_self.
plan() re-applies the router/gateway filter on every render, so an edited
state file cannot lock the router out either.

CLI (root): quarantine.py restore | status | release <device-id> | release-all
"""
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

TABLE = "tuxwall_quarantine"
FAMILY = "inet"
PRIORITY = -5
STATE_FILE = "/etc/tuxwall/devices/quarantine.json"
LOG_FILE = "/var/lib/tuxwall/device-actions.jsonl"
LOG_MAX_BYTES = 1 << 20
MODES = ("internet", "isolate")
EXPIRES = {"none": None, "1h": 3600, "24h": 86400, "7d": 7 * 86400}
MAX_ENTRIES = 256
MAX_ADDRS = 32                      # per device and family
ISOLATE_UDP = (53, 67, 547)
ISOLATE_TCP = (53,)
WG_MIN_PREFIX = {4: 24, 6: 64}      # a peer routing more than this is a site, not a device
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
DEVICE_ID_RE = re.compile(r"^[mwi][0-9a-f]{12,16}$")
IFNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}$")
SETS = {
    "internet": {"mac": "inet_mac", "v4": "inet_v4", "v6": "inet_v6"},
    "isolate": {"mac": "iso_mac", "v4": "iso_v4", "v6": "iso_v6"},
}
SET_TYPES = {"mac": "ether_addr", "v4": "ipv4_addr", "v6": "ipv6_addr"}
COMMENT = "tuxwall: device quarantine"


# ── environment (tests remap paths and stub commands) ─────────────────────────

def _default_run(cmd, text=None, timeout=20):
    try:
        p = subprocess.run(cmd, input=text, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "" if p.returncode else "")
    except Exception as exc:
        return 127, str(exc)


class Env:
    def __init__(self, state_file=STATE_FILE, log_file=LOG_FILE, run=None, clock=None, sys_net="/sys/class/net"):
        self.state_file = state_file
        self.log_file = log_file
        self.run = run or _default_run
        self.clock = clock or time.time
        self.sys_net = sys_net
        self.nft = shutil.which("nft") or "/usr/sbin/nft"
        self.ip = shutil.which("ip") or "/usr/sbin/ip"


# ── addresses ─────────────────────────────────────────────────────────────────

def norm_mac(value):
    v = str(value or "").strip().lower().replace("-", ":")
    return v if MAC_RE.match(v) and v != "00:00:00:00:00:00" else ""


def norm_ip(value):
    """Canonical host address (IPv4-mapped IPv6 unwrapped), or ''."""
    v = str(value or "").strip()
    if "%" in v:
        v = v.split("%", 1)[0]
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return ""
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a)


def _usable_host(ip):
    """An address a quarantine may name: unicast, not loopback/multicast/
    unspecified/link-local (fe80:: is the same on every link and a MAC rule
    already covers it)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_multicast or a.is_unspecified or a.is_link_local
                or (a.version == 4 and a == ipaddress.IPv4Address("255.255.255.255")))


def norm_net(value):
    try:
        n = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None
    return n


# ── state ─────────────────────────────────────────────────────────────────────

def _clean_entry(e):
    if not isinstance(e, dict) or not DEVICE_ID_RE.match(str(e.get("device") or "")):
        return None
    if e.get("mode") not in MODES:
        return None
    mac = norm_mac(e.get("mac"))
    addrs = sorted({norm_ip(x) for x in list(e.get("ips") or []) + list(e.get("ipv6") or [])
                    if isinstance(x, str)} - {""})
    v4 = [x for x in addrs if ":" not in x and _usable_host(x)][:MAX_ADDRS]
    v6 = [x for x in addrs if ":" in x and _usable_host(x)][:MAX_ADDRS]
    nets = []
    for x in e.get("nets") or []:
        n = norm_net(x)
        if n is not None and n.prefixlen >= WG_MIN_PREFIX[n.version] and str(n) not in nets:
            nets.append(str(n))
    if not (mac or v4 or v6 or nets):
        return None
    exp = e.get("expires")
    out = {
        "device": e["device"], "kind": e.get("kind") if e.get("kind") in ("mac", "wg", "ip") else "ip",
        "name": str(e.get("name") or "")[:64], "mode": e["mode"], "mac": mac,
        "ips": v4, "ipv6": v6, "nets": nets[:MAX_ADDRS],
        "since": int(e.get("since") or 0), "expires": int(exp) if isinstance(exp, (int, float)) and exp > 0 else None,
        "by": str(e.get("by") or "")[:64], "note": str(e.get("note") or "")[:200],
    }
    return out


def load_state(env):
    try:
        fd = os.open(env.state_file, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        raw = {}
    raw = raw if isinstance(raw, dict) else {}
    entries, seen = [], set()
    for e in raw.get("entries") or []:
        c = _clean_entry(e)
        if c and c["device"] not in seen:
            seen.add(c["device"])
            entries.append(c)
    wan = [w for w in (raw.get("wan") or []) if isinstance(w, str) and IFNAME_RE.match(w)]
    return {"version": 1, "wan": wan[:4], "entries": entries[:MAX_ENTRIES]}


def save_state(env, st):
    d = os.path.dirname(env.state_file)
    os.makedirs(d, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".quarantine-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "wan": st.get("wan") or [], "entries": st.get("entries") or []},
                      f, indent=1, sort_keys=True)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, env.state_file)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def log_action(env, ev):
    """Append one action ({"action", "device", ...}) to the action log."""
    ev = dict(ev, ts=int(env.clock()))
    try:
        d = os.path.dirname(env.log_file)
        os.makedirs(d, mode=0o755, exist_ok=True)
        try:
            if os.path.getsize(env.log_file) > LOG_MAX_BYTES:
                os.replace(env.log_file, env.log_file + ".1")
        except OSError:
            pass
        fd = os.open(env.log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, separators=(",", ":"), sort_keys=True) + "\n")
    except OSError:
        pass
    return ev


def read_actions(env, device=None, limit=50):
    out = []
    for path in (env.log_file + ".1", env.log_file):
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(ev, dict) and (device is None or ev.get("device") == device):
                        out.append(ev)
        except OSError:
            continue
    return out[-limit:]


# ── router context ────────────────────────────────────────────────────────────

def _json_cmd(env, args):
    rc, out = env.run(args, timeout=10)
    if rc != 0:
        return []
    try:
        data = json.loads(out or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def router_context(env, wan=None):
    """What a quarantine must never hit: the router's own MACs and
    addresses, the upstream gateway(s); plus the neighbour table (client IP
    -> MAC for the self check) and the WAN interface list."""
    macs, ips, gws, gw_macs, neigh = set(), set(), set(), set(), {}
    for link in _json_cmd(env, [env.ip, "-j", "link", "show"]):
        m = norm_mac(link.get("address"))
        if m:
            macs.add(m)
        m = norm_mac(link.get("permaddr"))
        if m:
            macs.add(m)
    try:
        for name in os.listdir(env.sys_net):
            try:
                with open(os.path.join(env.sys_net, name, "address")) as f:
                    m = norm_mac(f.read())
                if m:
                    macs.add(m)
            except OSError:
                continue
    except OSError:
        pass
    for link in _json_cmd(env, [env.ip, "-j", "addr", "show"]):
        for a in link.get("addr_info") or []:
            v = norm_ip(a.get("local"))
            if v:
                ips.add(v)
    for fam in ("-4", "-6"):
        for r in _json_cmd(env, [env.ip, fam, "-j", "route", "show", "default"]):
            g = norm_ip(r.get("gateway"))
            if g:
                gws.add(g)
            for nh in r.get("nexthops") or []:
                g = norm_ip((nh or {}).get("gateway"))
                if g:
                    gws.add(g)
    for n in _json_cmd(env, [env.ip, "-j", "neigh", "show"]):
        ip, mac = norm_ip(n.get("dst")), norm_mac(n.get("lladdr"))
        if ip and mac:
            neigh[ip] = mac
            if ip in gws:
                gw_macs.add(mac)
    wan_list = [w for w in (wan or []) if w and IFNAME_RE.match(w)]
    return {"macs": macs, "ips": ips, "gateways": gws, "gateway_macs": gw_macs, "neigh": neigh,
            "wan": wan_list}


# ── targets + decision ────────────────────────────────────────────────────────

def device_targets(device, devices=(), wg_peers=None):
    """{"kind", "mac", "ips", "ipv6", "nets"} for a device of the inventory.
    Addresses another device currently holds are left out (a DHCP address
    handed on must not stay quarantined); the MAC rule still catches the
    device itself on any address."""
    did = device.get("id") or ""
    kind = {"m": "mac", "w": "wg", "i": "ip"}.get(did[:1], "ip")
    others = set()
    for d in devices or ():
        if isinstance(d, dict) and d.get("id") != did:
            for k in ("current_ips", "ips", "ipv6"):
                others.update(norm_ip(x) for x in (d.get(k) or []) if isinstance(x, str))
    addrs = set()
    for k in ("current_ips", "ips", "ipv6"):
        for x in device.get(k) or []:
            if isinstance(x, str) and "/" not in x:
                v = norm_ip(x)
                if v and _usable_host(v) and v not in others:
                    addrs.add(v)
    nets = []
    if kind == "wg":
        allowed = []
        for p in (wg_peers or []):
            if isinstance(p, dict) and p.get("public_key") and p.get("public_key") == device.get("wg_public_key"):
                allowed = [x for x in (p.get("allowed_ips") or []) if isinstance(x, str)]
                break
        allowed += [x for x in (device.get("current_ips") or []) if isinstance(x, str) and "/" in x]
        for x in allowed:
            n = norm_net(x)
            if n is not None and str(n) not in nets:
                nets.append(str(n))
    return {"kind": kind, "mac": norm_mac(device.get("mac")) if kind == "mac" else "",
            "ips": sorted(a for a in addrs if ":" not in a)[:MAX_ADDRS],
            "ipv6": sorted(a for a in addrs if ":" in a)[:MAX_ADDRS], "nets": nets[:MAX_ADDRS]}


def _covers(nets, ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_self(targets, client_ip, ctx):
    """Is the requesting browser on this device? (client IP from the trusted
    proxy; its MAC from the neighbour table)."""
    c = norm_ip(client_ip)
    if not c or c in ctx.get("ips", ()) or c in ("127.0.0.1", "::1"):
        return False
    if c in targets.get("ips", ()) or c in targets.get("ipv6", ()):
        return True
    if targets.get("mac") and ctx.get("neigh", {}).get(c) == targets["mac"]:
        return True
    return _covers(targets.get("nets") or (), c)


def check_request(device, targets, mode, expires, ctx, client_ip="", confirm_self=False):
    """None when the quarantine may go ahead, else (http status, payload).
    Payload "code" tells the UI which warning to show."""
    if mode not in MODES:
        return 400, {"ok": False, "code": "mode", "error": "mode must be internet or isolate"}
    if expires not in EXPIRES:
        return 400, {"ok": False, "code": "expires", "error": "expires must be none, 1h, 24h or 7d"}
    mac = targets.get("mac")
    if not (mac or targets.get("ips") or targets.get("ipv6") or targets.get("nets")):
        return 409, {"ok": False, "code": "no_address",
                     "error": "No MAC or current address is known for this device - nothing to match"}
    if mac and mac in ctx.get("macs", ()):
        return 403, {"ok": False, "code": "router", "error": "This is the router itself - it cannot be quarantined"}
    own = [a for a in targets.get("ips", []) + targets.get("ipv6", []) if a in ctx.get("ips", ())]
    if own or any(_covers(targets.get("nets") or (), a) for a in ctx.get("ips", ())):
        return 403, {"ok": False, "code": "router",
                     "error": "This device uses one of the router's own addresses - refused"}
    gws = ctx.get("gateways", set())
    if (mac and mac in ctx.get("gateway_macs", ())) or any(a in gws for a in targets.get("ips", []) + targets.get("ipv6", [])) \
            or any(_covers(targets.get("nets") or (), g) for g in gws):
        return 403, {"ok": False, "code": "gateway",
                     "error": "This device is the router's upstream gateway - quarantining it would cut the internet"}
    for n in targets.get("nets") or []:
        net = ipaddress.ip_network(n, strict=False)
        if net.prefixlen < WG_MIN_PREFIX[net.version]:
            return 409, {"ok": False, "code": "wide_peer",
                         "error": "This VPN peer routes %s - more than one device; edit the peer instead" % n}
    if mode == "internet" and not ctx.get("wan"):
        return 409, {"ok": False, "code": "no_wan",
                     "error": "The WAN interface is unknown - use Isolate, or check Interfaces"}
    if not confirm_self and is_self(targets, client_ip, ctx):
        return 409, {"ok": False, "code": "self", "self": True,
                     "error": "This is the device you are using right now. Quarantining it "
                              + ("cuts its internet access" if mode == "internet"
                                 else "locks it out of the dashboard") + " - confirm to continue"}
    return None


def warnings_for(device, targets, mode):
    out = []
    if targets.get("mac") and device.get("private_mac"):
        out.append("This device uses a private (randomised) MAC address. If it picks a new one, the MAC rule "
                   "no longer matches; its current addresses stay blocked until they change.")
    if targets.get("kind") == "ip":
        out.append("No MAC address is known: only the listed addresses are blocked.")
    if mode == "isolate":
        out.append("Devices on the same switch or Wi-Fi network still reach it directly - the router only "
                   "controls traffic it forwards.")
    return out


def make_entry(device, targets, mode, expires, now, by="", note=""):
    secs = EXPIRES.get(expires)
    return _clean_entry({
        "device": device.get("id"), "kind": targets.get("kind"), "name": device.get("name") or "",
        "mode": mode, "mac": targets.get("mac"), "ips": targets.get("ips"), "ipv6": targets.get("ipv6"),
        "nets": targets.get("nets"), "since": int(now), "expires": int(now + secs) if secs else None,
        "by": by, "note": note})


# ── plan + render ─────────────────────────────────────────────────────────────

def plan(state, ctx, now):
    """Set contents per mode (expired entries and anything that names the
    router or its gateway are dropped here, whatever the state file says)."""
    out = {m: {"mac": set(), "v4": set(), "v6": set()} for m in MODES}
    skipped = []
    router_ips = set(ctx.get("ips") or ())
    blocked_macs = set(ctx.get("macs") or ()) | set(ctx.get("gateway_macs") or ())
    blocked_ips = router_ips | set(ctx.get("gateways") or ())
    for e in state.get("entries") or []:
        if e.get("expires") and e["expires"] <= now:
            skipped.append((e["device"], "expired"))
            continue
        sets = out[e["mode"]]
        if e.get("mac"):
            if e["mac"] in blocked_macs:
                skipped.append((e["device"], "router-mac"))
                continue
            sets["mac"].add(e["mac"])
        for ip in e.get("ips") or []:
            if ip not in blocked_ips:
                sets["v4"].add(ip)
        for ip in e.get("ipv6") or []:
            if ip not in blocked_ips:
                sets["v6"].add(ip)
        for n in e.get("nets") or []:
            net = norm_net(n)
            if net is None or any(_covers([str(net)], a) for a in blocked_ips):
                skipped.append((e["device"], "router-net"))
                continue
            sets["v4" if net.version == 4 else "v6"].add(str(net) if net.prefixlen < net.max_prefixlen
                                                          else str(net.network_address))
    wan = [w for w in (state.get("wan") or ctx.get("wan") or []) if IFNAME_RE.match(w)]
    return {"internet": {k: sorted(v) for k, v in out["internet"].items()},
            "isolate": {k: sorted(v) for k, v in out["isolate"].items()},
            "wan": wan, "skipped": skipped}


def plan_empty(p):
    return not any(p[m][k] for m in MODES for k in ("mac", "v4", "v6"))


def _q(name):
    return '"%s"' % name


def render(p):
    """The whole table in one transaction (idempotent)."""
    t = "%s %s" % (FAMILY, TABLE)
    # add + delete + add: one atomic swap that also replaces a table left by
    # an older layout (an existing set with other flags would fail "add set")
    lines = ["add table %s" % t, "delete table %s" % t, "add table %s" % t]
    for mode in MODES:
        for k, sname in SETS[mode].items():
            flags = "" if k == "mac" else " flags interval;"
            lines.append("add set %s %s { type %s;%s }" % (t, sname, SET_TYPES[k], flags))
    lines.append("add chain %s forward { type filter hook forward priority %d; policy accept; }" % (t, PRIORITY))
    lines.append("add chain %s input { type filter hook input priority %d; policy accept; }" % (t, PRIORITY))
    lines.append("add chain %s iso_in" % t)
    if not plan_empty(p):
        i, s = SETS["internet"], SETS["isolate"]
        wan = p.get("wan") or []
        if wan and any(p["internet"][k] for k in ("mac", "v4", "v6")):
            w = "{ %s }" % ", ".join(_q(x) for x in wan)
            c = 'counter drop comment "%s (internet)"' % COMMENT
            lines += [
                "add rule %s forward oifname %s ether saddr @%s %s" % (t, w, i["mac"], c),
                "add rule %s forward oifname %s ip saddr @%s %s" % (t, w, i["v4"], c),
                "add rule %s forward oifname %s ip6 saddr @%s %s" % (t, w, i["v6"], c),
                "add rule %s forward iifname %s ip daddr @%s %s" % (t, w, i["v4"], c),
                "add rule %s forward iifname %s ip6 daddr @%s %s" % (t, w, i["v6"], c),
            ]
        if any(p["isolate"][k] for k in ("mac", "v4", "v6")):
            c = 'counter drop comment "%s (isolate)"' % COMMENT
            lines += [
                "add rule %s forward ether saddr @%s %s" % (t, s["mac"], c),
                "add rule %s forward ip saddr @%s %s" % (t, s["v4"], c),
                "add rule %s forward ip6 saddr @%s %s" % (t, s["v6"], c),
                "add rule %s forward ip daddr @%s %s" % (t, s["v4"], c),
                "add rule %s forward ip6 daddr @%s %s" % (t, s["v6"], c),
                "add rule %s input ether saddr @%s jump iso_in" % (t, s["mac"]),
                "add rule %s input ip saddr @%s jump iso_in" % (t, s["v4"]),
                "add rule %s input ip6 saddr @%s jump iso_in" % (t, s["v6"]),
                "add rule %s iso_in meta l4proto { icmp, ipv6-icmp } return" % t,
                "add rule %s iso_in udp dport { %s } return" % (t, ", ".join(str(x) for x in ISOLATE_UDP)),
                "add rule %s iso_in tcp dport { %s } return" % (t, ", ".join(str(x) for x in ISOLATE_TCP)),
                'add rule %s iso_in counter drop comment "%s (isolate: router access)"' % (t, COMMENT),
            ]
        for mode in MODES:
            for k, sname in SETS[mode].items():
                items = p[mode][k]
                if items:
                    lines.append("add element %s %s { %s }" % (t, sname, ", ".join(items)))
    return "\n".join(lines) + "\n"


# ── live table ────────────────────────────────────────────────────────────────

def table_state(env):
    """{"sets": {name: [elements]}, "rules": n, "chains": {name: hook}} of
    the live table, or None when it does not exist."""
    rc, out = env.run([env.nft, "-j", "list", "table", FAMILY, TABLE], timeout=15)
    if rc != 0:
        return None
    try:
        items = json.loads(out).get("nftables") or []
    except (ValueError, AttributeError):
        return None
    st = {"sets": {}, "rules": 0, "chains": {}}
    for it in items:
        if "set" in it:
            s = it["set"]
            elems = []
            for e in s.get("elem") or []:
                if isinstance(e, dict) and "prefix" in e:
                    elems.append("%s/%s" % (e["prefix"].get("addr"), e["prefix"].get("len")))
                elif isinstance(e, dict) and "elem" in e:
                    v = e["elem"].get("val")
                    elems.append(str(v.get("prefix", {}).get("addr")) + "/" + str(v["prefix"]["len"])
                                 if isinstance(v, dict) and "prefix" in v else str(v))
                elif isinstance(e, dict) and "range" in e:
                    elems.append("-".join(str(x) for x in e["range"]))
                else:
                    elems.append(str(e))
            st["sets"][s.get("name")] = sorted(elems)
        elif "rule" in it:
            st["rules"] += 1
        elif "chain" in it:
            st["chains"][it["chain"].get("name")] = it["chain"].get("hook")
    return st


def _norm_elems(items):
    out = []
    for x in items:
        n = norm_net(x)
        if n is not None and n.prefixlen == n.max_prefixlen:
            out.append(str(n.network_address))
        elif n is not None:
            out.append(str(n))
        else:
            out.append(str(x).lower())
    return sorted(out)


def matches(live, p):
    """True when the live table already enforces plan p (no rewrite)."""
    if live is None:
        return False
    if live["chains"].get("forward") != "forward" or live["chains"].get("input") != "input":
        return False
    for mode in MODES:
        for k, sname in SETS[mode].items():
            if sname not in live["sets"]:
                return False
            if _norm_elems(live["sets"][sname]) != _norm_elems(p[mode][k]):
                return False
    want_rules = 0 if plan_empty(p) else len([ln for ln in render(p).splitlines() if ln.startswith("add rule")])
    return live["rules"] == want_rules


def apply(env, p, force=False):
    """Make the live table enforce p. -> (changed, error or "")."""
    if not force and matches(table_state(env), p):
        return False, ""
    rc, out = env.run([env.nft, "-f", "-"], text=render(p), timeout=30)
    if rc != 0:
        return False, (out or "nft failed").strip()[:300]
    return True, ""


def ensure_table(env, state, ctx, now):
    return apply(env, plan(state, ctx, now))


# ── periodic sync (the API calls this every minute) ───────────────────────────

def sync(state, devices, now, wan=None, wg_peers=None):
    """Refresh every entry's addresses from the inventory and split off the
    expired ones. -> (new state, expired entries, changed?)."""
    by_id = {d.get("id"): d for d in devices or () if isinstance(d, dict)}
    kept, expired, changed = [], [], False
    for e in state.get("entries") or []:
        if e.get("expires") and e["expires"] <= now:
            expired.append(e)
            changed = True
            continue
        dev = by_id.get(e["device"])
        if dev is not None:
            t = device_targets(dev, devices, wg_peers)
            new = dict(e, ips=t["ips"], ipv6=t["ipv6"])
            if e.get("kind") == "mac" and t["mac"]:
                new["mac"] = t["mac"]
            if e.get("kind") == "wg" and t["nets"]:
                new["nets"] = t["nets"]
            if dev.get("name"):
                new["name"] = str(dev["name"])[:64]
            new = _clean_entry(new) or e
            if new != e:
                changed = True
            kept.append(new)
        else:
            kept.append(e)
    wan_list = [w for w in (wan or []) if w and IFNAME_RE.match(w)]
    st = {"version": 1, "wan": wan_list or state.get("wan") or [], "entries": kept}
    if st["wan"] != (state.get("wan") or []):
        changed = True
    return st, expired, changed


def public_entry(e, now=None):
    if not e:
        return None
    now = time.time() if now is None else now
    return {"mode": e["mode"], "since": e.get("since"), "expires": e.get("expires"), "by": e.get("by"),
            "note": e.get("note") or "", "mac": e.get("mac") or "", "ips": e.get("ips") or [],
            "ipv6": e.get("ipv6") or [], "nets": e.get("nets") or [],
            "remaining": max(0, int(e["expires"] - now)) if e.get("expires") else None}


# ── CLI ───────────────────────────────────────────────────────────────────────

def restore(env):
    """Boot: render the persisted quarantine (without expired entries)."""
    st = load_state(env)
    ctx = router_context(env, st.get("wan"))
    p = plan(st, ctx, env.clock())
    changed, err = apply(env, p, force=True)
    n = sum(1 for e in st["entries"] if not (e.get("expires") and e["expires"] <= env.clock()))
    if err:
        print("tuxwall-quarantine: could not load the quarantine table: %s" % err, file=sys.stderr)
        return 1
    print("tuxwall-quarantine: table inet %s loaded, %d device(s) quarantined%s"
          % (TABLE, n, "" if not p["skipped"] else ", skipped %d" % len(p["skipped"])))
    return 0


def main(argv):
    env = Env()
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "restore":
        return restore(env)
    if cmd == "status":
        st = load_state(env)
        live = table_state(env)
        print(json.dumps({"entries": len(st["entries"]), "wan": st["wan"],
                          "table": None if live is None else {"rules": live["rules"],
                                                              "elements": sum(len(v) for v in live["sets"].values())}}))
        return 0
    if cmd in ("release", "release-all"):
        st = load_state(env)
        target = argv[2] if cmd == "release" and len(argv) > 2 else None
        if cmd == "release" and not target:
            print("usage: quarantine.py release <device-id>", file=sys.stderr)
            return 2
        gone = [e for e in st["entries"] if target is None or e["device"] == target]
        st["entries"] = [e for e in st["entries"] if e not in gone]
        save_state(env, st)
        ctx = router_context(env, st.get("wan"))
        _changed, err = apply(env, plan(st, ctx, env.clock()), force=True)
        for e in gone:
            log_action(env, {"action": "release", "device": e["device"], "mode": e["mode"], "by": "cli"})
        print("released %d device(s)%s" % (len(gone), "; nft: " + err if err else ""))
        return 1 if err else 0
    print(__doc__.split("\n\n")[0])
    print("usage: quarantine.py restore | status | release <device-id> | release-all", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
