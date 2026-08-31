#!/usr/bin/env python3
import base64
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime
from uuid import uuid4
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEA_SOCKET = "/run/kea/kea4-ctrl-socket"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8008
SOCKET_TIMEOUT = 5.0

BANDWIDTH_INTERVAL = 2.0
BANDWIDTH_WINDOW = 600

SYSTEM_POLL_INTERVAL = 5.0
SYSTEM_WINDOW = 600

CLIENT_TRAFFIC_INTERVAL = 2.0
NFT_TABLE = "tuxwall_traffic"
NFT_TX_SET = "clients_tx"
NFT_RX_SET = "clients_rx"
NFT_BIN = shutil.which("nft") or "/usr/sbin/nft"

BLOCKLIST_DIR = "/var/lib/tuxwall"
BLOCKLIST_CONFIG = os.path.join(BLOCKLIST_DIR, "blocklists.json")
BLOCKLIST_WHITELIST = os.path.join(BLOCKLIST_DIR, "whitelist.json")
CLIENT_BANS_FILE = os.path.join(BLOCKLIST_DIR, "bans.json")
CLIENT_BANS_CONF = "/var/lib/unbound/client-bans.conf"
BLOCKLIST_CONF = "/var/lib/unbound/blocklist.conf"
BLOCKLIST_BACKUP = BLOCKLIST_CONF + ".bak"
BLOCKLIST_MAX_BYTES = 50 * 1024 * 1024
BLOCKLIST_FETCH_TIMEOUT = 90
DEFAULT_BLOCKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

EVENT_RE = re.compile(
    r"^(?P<ts>\S+)\s+\S+\s+kernel:\s+\[UFW\s+(?P<action>ALLOW|BLOCK)\]"
    r"\s+IN=(?P<in>\S*)"
    r"\s+OUT=(?P<out>\S*)"
    r".*?SRC=(?P<src>\S+)"
    r"\s+DST=(?P<dst>\S+)"
    r".*?PROTO=(?P<proto>\S+)"
    r"(?:\s+SPT=(?P<spt>\S+))?"
    r"(?:\s+DPT=(?P<dpt>\S+))?"
)

STATE_ACTIVE = 0
STATE_DECLINED = 1
STATE_EXPIRED = 2

OUI_CSV = "/usr/share/ieee-data/oui.csv"
_OUI_DB = None

OS_HINTS = (
    ("APPLE", "apple"),
    ("GOOGLE", "android"),
    ("SAMSUNG", "android"),
    ("LG ELECTRONICS", "android"),
    ("HUAWEI", "android"),
    ("XIAOMI", "android"),
    ("MOTOROLA", "android"),
    ("NOKIA", "android"),
    ("SONY MOBILE", "android"),
    ("HTC", "android"),
    ("ONEPLUS", "android"),
    ("OPPO", "android"),
    ("VIVO", "android"),
    ("ZTE", "android"),
    ("ERICSSON", "android"),
    ("REALME", "android"),
    ("LENOVO MOBILE", "android"),
    ("MICROSOFT", "windows"),
    ("XBOX", "windows"),
    ("MICRO-STAR", "windows"),
    ("RASPBERRY", "linux"),
    ("REDHAT", "linux"),
    ("SYSTEM76", "linux"),
    ("LINARO", "linux"),
    ("NVIDIA", "linux"),
)


def _load_oui_db():
    db = {}
    try:
        with open(OUI_CSV, errors="replace") as f:
            for line in f:
                parts = line.split(",", 3)
                if len(parts) < 3 or parts[0] not in ("MA-L", "MA-M"):
                    continue
                db[parts[1].strip().upper()] = parts[2].strip().strip('"')
    except OSError:
        return {}
    return db


def oui_vendor(mac):
    global _OUI_DB
    if _OUI_DB is None:
        _OUI_DB = _load_oui_db()
    if not mac:
        return ""
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    if len(prefix) < 6:
        return ""
    return _OUI_DB.get(prefix, "")


def vendor_os(vendor, hostname=""):
    v = (vendor or "").upper()
    h = (hostname or "").lower().split(".")[0]

    if any(t in h for t in ("iphone", "ipad", "ipod", "apple-tv", "appletv")):
        return "apple"
    if any(t in h for t in ("macbook", "imac", "mac-mini", "macmini", "macpro", "mbp", "mba")):
        return "mac"
    if any(t in h for t in ("chromebook", "chronos", "pixelbook")) or h.startswith("cyan"):
        return "chromebook"
    if any(t in h for t in ("android", "galaxy", "pixel", "redmi", "xiaomi", "huawei",
                            "oneplus", "oppo", "vivo", "zte", "nokia", "samsung",
                            "motorola", "moto", "lenovo", "realme")):
        return "android"
    if any(t in h for t in ("ubuntu", "debian", "fedora", "archlinux", "manjaro", "kali",
                            "nixos", "alpine", "centos", "rocky", "pop_os", "pop-os",
                            "linux", "raspbian", "raspberrypi", "raspberry-pi")):
        return "linux"
    if (h.startswith(("desktop-", "laptop-", "win-")) or h in ("pc", "windows")
            or "windows" in h or "laptop" in h or " pc" in h or h.endswith("-pc")):
        return "windows"

    os_name = ""
    for fragment, name in OS_HINTS:
        if fragment in v:
            os_name = name
            break
    return os_name or "other"


def kea_command(command, arguments=None):
    payload = {"command": command, "service": ["dhcp4"]}
    if arguments is not None:
        payload["arguments"] = arguments
    body = json.dumps(payload).encode("utf-8")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        sock.connect(KEA_SOCKET)
        sock.sendall(body)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()
    raw = b"".join(chunks).strip()
    if not raw:
        raise RuntimeError("Empty response from Kea control socket")
    return json.loads(raw)


def service_active(name):
    try:
        out = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() == "active"
    except Exception:
        return False


_ROUTER_CACHE = {"ts": 0, "data": None}


def router_static():
    """Gateway (the server itself) as a static entry."""
    now = time.time()
    if _ROUTER_CACHE["data"] and now - _ROUTER_CACHE["ts"] < 300:
        return _ROUTER_CACHE["data"]
    ip = ""
    try:
        with open("/etc/kea/kea-dhcp4.conf", "r") as f:
            kea = json.load(f)
        d4 = kea.get("Dhcp4", {})
        for o in d4.get("option-data", []):
            if o.get("name") == "routers":
                ip = o.get("data", "")
        if not ip:
            for s in d4.get("subnet4", []):
                for o in s.get("option-data", []):
                    if o.get("name") == "routers":
                        ip = o.get("data", "")
                if not ip:
                    subnet = s.get("subnet", "")
                    if "/" in subnet:
                        ip = subnet.rsplit("/", 1)[0].rsplit(".", 1)[0] + ".1"
    except (OSError, ValueError):
        pass
    mac = ""
    if ip:
        try:
            proc = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=5)
            for iface in json.loads(proc.stdout):
                for a in iface.get("addr_info", []):
                    if a.get("family") == "inet" and a.get("local") == ip:
                        mac = iface.get("address", "")
                        break
        except Exception:
            pass
    hostname = "gateway"
    try:
        hostname = socket.gethostname()
    except Exception:
        pass
    data = {"ip": ip, "mac": mac, "hostname": hostname}
    _ROUTER_CACHE["ts"] = now
    _ROUTER_CACHE["data"] = data
    return data


# ─────────────────────────────────────────────────────────────────────────────
# DHCP Reservations (read/write kea-dhcp4.conf)
# ─────────────────────────────────────────────────────────────────────────────

KEA_CONF    = "/etc/kea/kea-dhcp4.conf"
_KEA_LOCK   = threading.Lock()


def _read_kea():
    with open(KEA_CONF) as f:
        return json.load(f)


def _write_kea(data):
    # Atomic write via temp file
    tmp = KEA_CONF + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=4)
    os.replace(tmp, KEA_CONF)


def _reload_kea():
    """Signal Kea to reload its config via the control socket."""
    try:
        kea_command("config-reload")
    except Exception:
        # Fallback: systemctl reload
        subprocess.run(
            ["systemctl", "reload-or-restart", "kea-dhcp4-server"],
            capture_output=True, text=True, timeout=15
        )


def _validate_reservation(ip, mac, hostname, existing_id=None):
    """Return error string or None."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return f"Invalid IP address: {ip}"

    # Normalise MAC
    mac_norm = mac.lower().strip()
    if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac_norm):
        return "Invalid MAC address — expected format aa:bb:cc:dd:ee:ff"

    if hostname and not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$", hostname):
        return "Invalid hostname — letters, numbers and hyphens only"

    return None


def build_reservations():
    """Return all reservations from kea-dhcp4.conf with live ARP status."""
    try:
        kea  = _read_kea()
    except Exception as exc:
        return {"ok": False, "error": str(exc), "reservations": []}

    out = []
    for subnet in kea.get("Dhcp4", {}).get("subnet4", []):
        subnet_id  = subnet.get("id", 1)
        subnet_str = subnet.get("subnet", "")
        for r in subnet.get("reservations", []):
            ip = r.get("ip-address", "")
            if not ip:
                continue
            out.append({
                "id":        f"{subnet_id}_{ip.replace('.','_')}",
                "subnet_id": subnet_id,
                "subnet":    subnet_str,
                "ip":        ip,
                "mac":       r.get("hw-address", "") or "",
                "hostname":  r.get("hostname", "") or "",
                "online":    arp_online(ip),
            })

    return {"ok": True, "reservations": out}


def add_reservation(body):
    ip       = (body.get("ip") or "").strip()
    mac      = (body.get("mac") or "").strip().lower()
    hostname = (body.get("hostname") or "").strip()

    err = _validate_reservation(ip, mac, hostname)
    if err:
        raise ValueError(err)

    with _KEA_LOCK:
        kea = _read_kea()
        subnets = kea.get("Dhcp4", {}).get("subnet4", [])
        if not subnets:
            raise ValueError("No subnet4 defined in Kea config")

        # Check for duplicates
        for s in subnets:
            for r in s.get("reservations", []):
                if r.get("ip-address") == ip:
                    raise ValueError(f"IP {ip} is already reserved")
                if r.get("hw-address", "").lower() == mac:
                    raise ValueError(f"MAC {mac} already has a reservation")

        # Add to the first subnet (or whichever contains the IP)
        target = subnets[0]
        for s in subnets:
            net = s.get("subnet", "")
            if net:
                try:
                    if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(net, strict=False):
                        target = s
                        break
                except ValueError:
                    pass

        entry = {"hw-address": mac, "ip-address": ip}
        if hostname:
            entry["hostname"] = hostname

        target.setdefault("reservations", []).append(entry)
        _write_kea(kea)
        _reload_kea()

    return build_reservations()


def edit_reservation(body):
    res_id   = (body.get("id") or "").strip()
    mac      = (body.get("mac") or "").strip().lower()
    hostname = (body.get("hostname") or "").strip()

    if not res_id:
        raise ValueError("id is required")

    # id format: {subnet_id}_{ip_with_underscores}
    parts = res_id.split("_", 1)
    try:
        subnet_id = int(parts[0])
    except (ValueError, IndexError):
        raise ValueError("Invalid reservation id")
    ip = parts[1].replace("_", ".") if len(parts) > 1 else ""

    err = _validate_reservation(ip, mac, hostname, existing_id=res_id)
    if err:
        raise ValueError(err)

    with _KEA_LOCK:
        kea = _read_kea()
        found = False
        for s in kea.get("Dhcp4", {}).get("subnet4", []):
            if s.get("id") != subnet_id:
                continue
            for r in s.get("reservations", []):
                if r.get("ip-address") == ip:
                    r["hw-address"] = mac
                    if hostname:
                        r["hostname"] = hostname
                    elif "hostname" in r:
                        del r["hostname"]
                    found = True
                    break
            if found:
                break

        if not found:
            raise ValueError(f"Reservation for {ip} not found")

        _write_kea(kea)
        _reload_kea()

    return build_reservations()


def delete_reservation(body):
    res_id = (body.get("id") or "").strip()
    if not res_id:
        raise ValueError("id is required")

    parts = res_id.split("_", 1)
    try:
        subnet_id = int(parts[0])
    except (ValueError, IndexError):
        raise ValueError("Invalid reservation id")
    ip = parts[1].replace("_", ".") if len(parts) > 1 else ""

    with _KEA_LOCK:
        kea = _read_kea()
        found = False
        for s in kea.get("Dhcp4", {}).get("subnet4", []):
            if s.get("id") != subnet_id:
                continue
            before = s.get("reservations", [])
            after  = [r for r in before if r.get("ip-address") != ip]
            if len(after) < len(before):
                s["reservations"] = after
                found = True
            break

        if not found:
            raise ValueError(f"Reservation for {ip} not found")

        _write_kea(kea)
        _reload_kea()

    return build_reservations()


def kea_reservations():
    """Static reservations defined in kea-dhcp4.conf."""
    try:
        with open("/etc/kea/kea-dhcp4.conf", "r") as f:
            kea = json.load(f)
    except (OSError, ValueError):
        return []
    out = []
    for s in kea.get("Dhcp4", {}).get("subnet4", []):
        for r in s.get("reservations", []):
            ip = r.get("ip-address", "")
            if not ip:
                continue
            out.append({
                "ip": ip,
                "hostname": r.get("hostname", "") or "",
                "mac": r.get("hw-address", "") or r.get("duid", ""),
            })
    return out


_ARP_CACHE = {}


def arp_online(ip):
    """Best-effort ARP reachability check for a static IP."""
    if not ip:
        return False
    now = time.time()
    cached = _ARP_CACHE.get(ip)
    if cached and now - cached[0] < 30:
        return cached[1]
    online = False
    try:
        proc = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
        for line in proc.stdout.splitlines():
            if not line.startswith(ip):
                continue
            online = "lladdr" in line and not any(
                s in line for s in ("FAILED", "INCOMPLETE", "noarp")
            )
            break
    except Exception:
        pass
    _ARP_CACHE[ip] = (now, online)
    return online


def build_leases():
    now = int(time.time())
    try:
        response = kea_command("lease4-get-all")
    except Exception as exc:
        return {"ok": False, "error": str(exc), "leases": []}

    entry = response[0] if isinstance(response, list) and response else response
    if not isinstance(entry, dict):
        return {"ok": True, "leases": []}

    result_code = entry.get("result", 0)
    text = entry.get("text", "")
    if result_code in (1, 2):
        return {"ok": False, "error": text or "Kea returned an error", "leases": []}

    arguments = entry.get("arguments")
    raw_leases = arguments.get("leases", []) if isinstance(arguments, dict) else []
    banned_ips = {b["ip"] for b in load_bans()}

    leases = []
    lease_map = {}
    for lease in raw_leases:
        state = int(lease.get("state", STATE_ACTIVE))
        if state == STATE_EXPIRED:
            continue
        valid = int(lease.get("valid-lft") or lease.get("valid-lifetime") or 0)
        cltt = int(lease.get("cltt") or 0)
        expires = cltt + valid
        mac = lease.get("hw-address", "") or ""
        vendor = oui_vendor(mac)
        item = {
            "ip": lease.get("ip-address", ""),
            "hostname": lease.get("hostname", "") or "",
            "mac": mac,
            "vendor": vendor,
            "os": vendor_os(vendor, lease.get("hostname", "") or ""),
            "state": state,
            "type": lease.get("type", 0),
            "expires": expires,
            "last_seen": cltt,
            "remaining": max(0, expires - now),
            "banned": lease.get("ip-address", "") in banned_ips,
            "static": False,
            "online": True,
        }
        leases.append(item)
        lease_map[item["ip"]] = item

    reserved_ips = set()
    for r in kea_reservations():
        reserved_ips.add(r["ip"])
        existing = lease_map.get(r["ip"])
        if existing:
            existing["static"] = True
            if not existing["hostname"] and r["hostname"]:
                existing["hostname"] = r["hostname"]
                existing["os"] = vendor_os(existing["vendor"], r["hostname"])
            continue
        vendor = oui_vendor(r["mac"])
        online = arp_online(r["ip"])
        leases.append({
            "ip": r["ip"],
            "hostname": r["hostname"],
            "mac": r["mac"],
            "vendor": vendor,
            "os": vendor_os(vendor, r["hostname"]),
            "state": STATE_ACTIVE,
            "type": 0,
            "expires": None,
            "last_seen": None,
            "remaining": None,
            "banned": r["ip"] in banned_ips,
            "static": True,
            "online": online,
        })

    router = router_static()
    if router["ip"] and router["ip"] not in reserved_ips:
        existing = lease_map.get(router["ip"])
        if existing:
            existing["static"] = True
            if not existing["hostname"]:
                existing["hostname"] = router["hostname"]
        else:
            vendor = oui_vendor(router["mac"])
            leases.append({
                "ip": router["ip"],
                "hostname": router["hostname"],
                "mac": router["mac"],
                "vendor": vendor,
                "os": vendor_os(vendor, router["hostname"]),
                "state": STATE_ACTIVE,
                "type": 0,
                "expires": None,
                "last_seen": None,
                "remaining": None,
                "banned": False,
                "static": True,
                "online": True,
            })

    return {"ok": True, "leases": leases}


# --- System services (systemd) --------------------------------------------

SERVICE_UNIT_RE = re.compile(r"^[A-Za-z0-9@._-]+\.service$")
PROTECTED_SERVICES = {"nginx.service"}
ALLOWED_SERVICE_ACTIONS = {"start", "stop", "restart", "reload"}


def list_system_services():
    proc = subprocess.run(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
        capture_output=True, text=True, timeout=20,
    )
    services = []
    for line in proc.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        unit, load, active, sub, desc = parts
        services.append({
            "unit": unit,
            "load": load,
            "active": active,
            "sub": sub,
            "desc": desc.strip(),
        })

    def sort_key(s):
        rank = 0 if s["active"] == "failed" else (1 if s["active"] == "active" else 2)
        return (rank, s["unit"])

    services.sort(key=sort_key)
    return {"ok": True, "services": services}


def service_action(unit, action):
    unit = (unit or "").strip()
    action = (action or "").strip()
    if action not in ALLOWED_SERVICE_ACTIONS:
        raise ValueError("Unsupported action: {}".format(action))
    if not SERVICE_UNIT_RE.match(unit):
        raise ValueError("Invalid unit name")
    if unit in PROTECTED_SERVICES and action in ("stop", "restart"):
        raise ValueError("{} is protected (it serves this dashboard)".format(unit))
    proc = subprocess.run(
        ["systemctl", action, unit],
        capture_output=True, text=True, timeout=45,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise ValueError(detail[-1] if detail else "systemctl {} failed".format(action))
    return {"ok": True}


def build_status():
    return {
        "ok": True,
        "hostname": os.uname().nodename,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "load": [round(x, 2) for x in os.getloadavg()],
        "services": {
            "kea-dhcp4": service_active("kea-dhcp4-server"),
            "unbound": service_active("unbound"),
            "ufw": service_active("ufw"),
            "crowdsec": service_active("crowdsec"),
            "wg-quick@wg0": service_active("wg-quick@wg0"),
            "netplan": service_active("systemd-networkd"),
        },
    }


def build_dns():
    def run_control(args):
        try:
            proc = subprocess.run(
                ["unbound-control"] + args,
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode != 0:
                raise RuntimeError((proc.stderr or "unbound-control failed").strip())
            return proc.stdout
        except Exception as exc:
            raise RuntimeError(str(exc))

    try:
        stdout = run_control(["stats_noreset"])
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    stats = {}
    for line in stdout.splitlines():
        key, _, value = line.partition("=")
        if key:
            stats[key] = value

    extended = any(k.startswith("num.answer.rcode.") for k in stats)

    def num(key, default=0):
        try:
            return float(stats.get(key, default))
        except (TypeError, ValueError):
            return default

    queries = num("total.num.queries")
    hits = num("total.num.cachehits")
    misses = num("total.num.cachemiss")
    hitrate = hits / (hits + misses) if (hits + misses) else 0.0

    def breakdown(prefix):
        items = []
        for key, value in stats.items():
            if key.startswith(prefix) and not key.endswith(".other"):
                label = key[len(prefix):]
                try:
                    items.append({"label": label, "count": int(value)})
                except (TypeError, ValueError):
                    pass
        items.sort(key=lambda x: x["count"], reverse=True)
        return items

    qtypes = breakdown("num.query.type.")[:12]
    rcodes = breakdown("num.answer.rcode.")

    status = {}
    try:
        for line in run_control(["status"]).splitlines():
            key, _, value = line.partition(": ")
            if key:
                status[key] = value
    except Exception:
        pass

    uptime = 0
    try:
        uptime = int(status.get("uptime", "0").split()[0])
    except (ValueError, IndexError):
        pass

    return {
        "ok": True,
        "version": status.get("version", ""),
        "threads": status.get("threads", ""),
        "uptime": uptime,
        "totals": {
            "queries": int(queries),
            "cachehits": int(hits),
            "cachemiss": int(misses),
            "hitrate": round(hitrate, 4),
            "prefetch": int(num("total.num.prefetch")),
            "recursivereplies": int(num("total.num.recursivereplies")),
            "avg_recursion_ms": round(num("total.recursion.time.avg"), 2),
            "tcp": int(num("num.query.tcp")),
            "udp": int(num("num.query.udp")),
            "ipv6": int(num("num.query.ipv6")),
            "unwanted": int(num("unwanted.queries")),
            "nxdomain": int(num("num.answer.rcode.NXDOMAIN")),
        },
        "extended": extended,
        "caches": {
            "rrset_count": int(num("rrset.cache.count")),
            "rrset_size": int(num("rrset.cache.size")),
            "msg_count": int(num("msg.cache.count")),
            "msg_size": int(num("msg.cache.size")),
            "key_count": int(num("key.cache.count")),
        },
        "qtypes": qtypes,
        "rcodes": rcodes,
    }


# --- Local domains (Unbound local-data) ------------------------------------
DOMAINS_CONF_PATH = "/etc/tuxwall/domains.json"
DOMAINS_UNBOUND_CONF = "/var/lib/unbound/local-domains.conf"
DOMAINS_INCLUDE = "/etc/unbound/unbound.conf.d/98-local-domains.conf"
DOMAIN_LOCK = threading.Lock()

DOMAIN_NAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)


def valid_domain_name(name):
    """Lowercase, strip trailing dot, require at least one label + TLD."""
    name = (name or "").strip().lower().rstrip(".")
    if not name or len(name) > 253:
        return None
    if not DOMAIN_NAME_RE.match(name):
        return None
    return name


def _valid_domain_port(port):
    port = str(port or "").strip()
    if not port:
        return None
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        return False
    return int(port)


def load_domains():
    try:
        with open(DOMAINS_CONF_PATH, "r") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_domains(domains):
    os.makedirs(os.path.dirname(DOMAINS_CONF_PATH), exist_ok=True)
    tmp = DOMAINS_CONF_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(domains, f, indent=2)
    os.replace(tmp, DOMAINS_CONF_PATH)


def write_domains_unbound_conf(domains):
    lines = [
        "# Generated by the tuxwall Local Domains page - DO NOT EDIT",
        "# {} local domains".format(len(domains)),
        "server:",
    ]
    for d in sorted(domains, key=lambda x: x["domain"]):
        rrtype = "AAAA" if d.get("v6") else "A"
        lines.append('    local-zone: "{}." static'.format(d["domain"]))
        lines.append('    local-data: "{}. IN {} {}"'.format(d["domain"], rrtype, d["ip"]))
    os.makedirs(os.path.dirname(DOMAINS_UNBOUND_CONF), exist_ok=True)
    tmp = DOMAINS_UNBOUND_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, DOMAINS_UNBOUND_CONF)

    # make sure unbound includes the generated file
    os.makedirs(os.path.dirname(DOMAINS_INCLUDE), exist_ok=True)
    body = 'include: "{}"\n'.format(DOMAINS_UNBOUND_CONF)
    try:
        with open(DOMAINS_INCLUDE, "r") as f:
            existing = f.read()
    except OSError:
        existing = ""
    if body not in existing:
        with open(DOMAINS_INCLUDE, "w") as f:
            f.write("# Managed by the tuxwall Local Domains page - DO NOT EDIT\n")
            f.write("server:\n")
            f.write(body)


def _read_conf():
    try:
        with open(DOMAINS_UNBOUND_CONF, "r") as f:
            return f.read()
    except OSError:
        return None


def _domains_reload_or_rollback(domains, prev_conf):
    """Apply the unbound conf and reload; restore the old conf on failure."""
    write_domains_unbound_conf(domains)
    try:
        reload_unbound()
    except Exception as exc:
        if prev_conf is not None:
            with open(DOMAINS_UNBOUND_CONF, "w") as f:
                f.write(prev_conf)
        raise RuntimeError(str(exc))


def _domain_entry_from_payload(body, existing=None):
    name = valid_domain_name(body.get("domain"))
    if not name:
        return None, "Invalid domain name (use e.g. plex.housenetwork.site)."
    ip = (body.get("ip") or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, "Invalid IP address."
    port = _valid_domain_port(body.get("port"))
    if port is False:
        return None, "Port must be a number from 1 to 65535."
    entry = {
        "id": (existing or {}).get("id") or uuid4().hex[:8],
        "domain": name,
        "ip": ip,
        "port": port,
        "note": (body.get("note") or "").strip(),
        "v6": addr.version == 6,
    }
    return entry, None


UNBOUND_SCAN_PATHS = ("/etc/unbound/unbound.conf.d", "/etc/unbound/unbound.conf")
UNBOUND_SCAN_EXCLUDE = {"local-domains.conf", "blocklist.conf", "client-bans.conf"}

LOCAL_DATA_RE = re.compile(r'local-data:\s*"([^"]+)"')
LOCAL_ZONE_RE = re.compile(r'local-zone:\s*"([^"]+)"\s+\S+')
DNS_RECORD_RE = re.compile(
    r"^(?P<name>\S+)\s+IN\s+(?P<rrtype>A|AAAA)\s+(?P<ip>\S+)$"
)


def unbound_conf_files():
    """Unbound config files that tuxwall does not manage."""
    files = []
    for base in UNBOUND_SCAN_PATHS:
        if os.path.isfile(base):
            files.append(base)
        elif os.path.isdir(base):
            try:
                for fn in sorted(os.listdir(base)):
                    if fn.endswith(".conf") and fn not in UNBOUND_SCAN_EXCLUDE:
                        files.append(os.path.join(base, fn))
            except OSError:
                pass
    return files


def discover_local_domains():
    """Parse local-data records from unbound config files that are not managed
    by tuxwall (everything outside /var/lib/unbound/local-domains.conf). Each
    entry carries enough info to remove it from its source file."""
    records = {}
    for path in unbound_conf_files():
        try:
            with open(path, "r") as f:
                lines = f.readlines()
        except OSError:
            continue
        for idx, raw in enumerate(lines):
            m = LOCAL_DATA_RE.search(raw)
            if not m:
                continue
            rec = DNS_RECORD_RE.match(m.group(1).strip())
            if not rec:
                continue
            domain = rec.group("name").rstrip(".").lower()
            if domain in records:
                continue
            records[domain] = {
                "id": "u_" + domain,
                "domain": domain,
                "ip": rec.group("ip"),
                "port": None,
                "note": "",
                "rrtype": rec.group("rrtype"),
                "v6": rec.group("rrtype") == "AAAA",
                "managed": False,
                "source_file": path,
                "line": idx,
            }
    return list(records.values())


def _zones_in_use(lines):
    """Set of zone names still referenced by local-data records in lines."""
    used = set()
    for raw in lines:
        m = LOCAL_DATA_RE.search(raw)
        if not m:
            continue
        rec = DNS_RECORD_RE.match(m.group(1).strip())
        if not rec:
            continue
        dom = rec.group("name").rstrip(".").lower()
        parts = dom.split(".")
        for i in range(len(parts)):
            used.add(".".join(parts[i:]))
    return used


def remove_unbound_local_data(path, domains_to_remove):
    """Remove local-data lines (and any local-zone left with no records) from
    an unbound config file. Returns the original file contents when changed so
    a caller can restore them, or None when nothing changed."""
    try:
        with open(path, "r") as f:
            original = f.read()
    except OSError:
        return None
    lines = original.splitlines(keepends=True)
    targets = set(domains_to_remove)
    new_lines = []
    for raw in lines:
        m = LOCAL_DATA_RE.search(raw)
        if m:
            rec = DNS_RECORD_RE.match(m.group(1).strip())
            if rec and rec.group("name").rstrip(".").lower() in targets:
                continue
        new_lines.append(raw)
    kept = _zones_in_use(new_lines)
    new_lines = [
        raw for raw in new_lines
        if not (LOCAL_ZONE_RE.search(raw)
                and LOCAL_ZONE_RE.search(raw).group(1).rstrip(".") not in kept)
    ]
    result = "".join(new_lines)
    if result == original:
        return None
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(result)
    os.replace(tmp, path)
    return original


def restore_unbound_local_data(path, original):
    if original is None:
        return
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(original)
    os.replace(tmp, path)


def build_domains():
    managed = load_domains()
    managed_names = {d["domain"] for d in managed}
    discovered = [
        d for d in discover_local_domains()
        if d["domain"] not in managed_names
    ]
    return {
        "ok": True,
        "domains": [dict(d, managed=True) for d in managed] + discovered,
    }


def add_domain(body):
    with DOMAIN_LOCK:
        entry, err = _domain_entry_from_payload(body)
        if err:
            return {"ok": False, "error": err}
        domains = load_domains()
        if any(d["domain"] == entry["domain"] for d in domains):
            return {"ok": False, "error": "Domain already exists."}
        prev = _read_conf()
        domains.append(entry)
        save_domains(domains)
        try:
            _domains_reload_or_rollback(domains, prev)
        except Exception as exc:
            save_domains([d for d in domains if d["id"] != entry["id"]])
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "domains": build_domains()["domains"]}


def update_domain(body):
    with DOMAIN_LOCK:
        did = (body.get("id") or "").strip()
        domains = load_domains()
        idx = next((i for i, d in enumerate(domains) if d["id"] == did), None)
        if idx is None:
            return {"ok": False, "error": "Domain not found."}
        entry, err = _domain_entry_from_payload(body, existing=domains[idx])
        if err:
            return {"ok": False, "error": err}
        if any(d["domain"] == entry["domain"] and d["id"] != did for d in domains):
            return {"ok": False, "error": "Domain already exists."}
        prev_domains = list(domains)
        prev_conf = _read_conf()
        domains[idx] = entry
        save_domains(domains)
        try:
            _domains_reload_or_rollback(domains, prev_conf)
        except Exception as exc:
            save_domains(prev_domains)
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "domains": build_domains()["domains"]}


def delete_domain(body):
    with DOMAIN_LOCK:
        did = (body.get("id") or "").strip()
        if did.startswith("u_"):
            name = did[2:]
            src = next((d for d in discover_local_domains() if d["id"] == did), None)
            if not src:
                return {"ok": False, "error": "Domain not found."}
            prev_src = remove_unbound_local_data(src["source_file"], [name])
            if prev_src is None:
                return {"ok": False, "error": "Domain not found in source file."}
            try:
                reload_unbound()
            except Exception as exc:
                restore_unbound_local_data(src["source_file"], prev_src)
                return {"ok": False, "error": str(exc)}
            return {"ok": True, "domains": build_domains()["domains"]}
        domains = load_domains()
        if not any(d["id"] == did for d in domains):
            return {"ok": False, "error": "Domain not found."}
        prev_domains = list(domains)
        prev_conf = _read_conf()
        domains = [d for d in domains if d["id"] != did]
        save_domains(domains)
        try:
            _domains_reload_or_rollback(domains, prev_conf)
        except Exception as exc:
            save_domains(prev_domains)
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "domains": build_domains()["domains"]}


def import_domain(body):
    """Adopt a discovered local-data record into the tuxwall-managed list."""
    with DOMAIN_LOCK:
        name = valid_domain_name(body.get("domain"))
        if not name:
            return {"ok": False, "error": "Invalid domain name (use e.g. plex.housenetwork.site)."}
        src = next(
            (d for d in discover_local_domains() if d["domain"] == name), None
        )
        if not src:
            return {"ok": False, "error": "Domain not found in unbound config files."}
        entry, err = _domain_entry_from_payload(body)
        if err:
            return {"ok": False, "error": err}
        domains = load_domains()
        if any(d["domain"] == entry["domain"] for d in domains):
            return {"ok": False, "error": "Domain already exists."}
        prev_domains = list(domains)
        prev_conf = _read_conf()
        prev_src = remove_unbound_local_data(src["source_file"], [name])
        domains.append(entry)
        save_domains(domains)
        try:
            _domains_reload_or_rollback(domains, prev_conf)
        except Exception as exc:
            save_domains(prev_domains)
            restore_unbound_local_data(src["source_file"], prev_src)
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "domains": build_domains()["domains"]}


def import_all_domains():
    """Adopt every discovered local-data record into the managed list."""
    with DOMAIN_LOCK:
        domains = load_domains()
        managed_names = {d["domain"] for d in domains}
        discovered = [
            d for d in discover_local_domains()
            if d["domain"] not in managed_names
        ]
        if not discovered:
            return {"ok": True, "domains": build_domains()["domains"], "imported": 0}
        prev_domains = list(domains)
        prev_conf = _read_conf()
        prev_sources = {}
        for d in discovered:
            path = d["source_file"]
            prev_sources[path] = remove_unbound_local_data(path, [d["domain"]])
        for d in discovered:
            domains.append({
                "id": uuid4().hex[:8],
                "domain": d["domain"],
                "ip": d["ip"],
                "port": None,
                "note": "",
                "v6": d["v6"],
            })
        save_domains(domains)
        try:
            _domains_reload_or_rollback(domains, prev_conf)
        except Exception as exc:
            save_domains(prev_domains)
            for path, original in prev_sources.items():
                restore_unbound_local_data(path, original)
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "domains": build_domains()["domains"], "imported": len(discovered)}


def build_interfaces():
    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        names = []
    interfaces = []
    for name in sorted(names):
        if name == "lo":
            continue
        state = ""
        try:
            with open(os.path.join("/sys/class/net", name, "operstate")) as f:
                state = f.read().strip()
        except OSError:
            pass
        interfaces.append({"name": name, "up": state == "up"})
    return {"ok": True, "interfaces": interfaces}


_FW_IFACE_RE = re.compile(r"\bon\s+(\S+)")
_FW_PORT_PROTO_RE = re.compile(r"(\d+(?:[:,-]\d+)*)\s*/\s*(tcp6|udp6|tcp|udp|tcp\|udp|ah|esp|gre|ipv6|igmp|sctp)\s*$", re.IGNORECASE)


def _parse_rule_side(text):
    """Parse one side of a ufw rule ('Anywhere on enp3s0', '10.0.0.0/24',
    '80,443/tcp') into structured fields for the advanced firewall UI."""
    text = (text or "").strip()
    iface = None
    m = _FW_IFACE_RE.search(text)
    if m:
        iface = m.group(1)
        text = (text[:m.start()] + " " + text[m.end():]).strip()
    v6 = "(v6)" in text
    text = text.replace(" (v6)", "").replace("(v6)", "").strip()
    port = None
    proto = None
    m = _FW_PORT_PROTO_RE.search(text)
    if m:
        port = m.group(1)
        proto = m.group(2).lower()
        text = text[:m.start()].strip()
    elif text and re.fullmatch(r"\d+([:,]\d+)*", text):
        # bare port list e.g. '53' or '80,443'
        port = text
        text = ""
    if text == "Anywhere":
        text = "any"
    # '10.0.0.5 53' style (destination host + port)
    m = re.match(r"^(\S+)\s+(\d+(?:[:,-]\d+)*)$", text)
    if m and m.group(1) != "any":
        text = m.group(1)
        if not port:
            port = m.group(2)
    return {"addr": text or "any", "iface": iface, "port": port,
            "proto": proto, "v6": v6}


def build_firewall():
    try:
        proc = subprocess.run(
            ["ufw", "status", "numbered"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or "ufw failed").strip()}

    # "Default:" and "Logging:" lines only appear in verbose output
    try:
        vproc = subprocess.run(
            ["ufw", "status", "verbose"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        vproc = None

    status = ""
    logging_state = ""
    defaults = {}
    rules = []
    for line in ((vproc.stdout if vproc and vproc.returncode == 0 else "")
                 + "\n" + proc.stdout).splitlines():
        ls = line.strip()
        if not ls:
            continue
        if ls.startswith("Status:"):
            status = ls.split(":", 1)[1].strip()
        elif ls.startswith("Logging:"):
            logging_state = ls.split(":", 1)[1].strip()
        elif ls.startswith("Default:"):
            for part in ls.split(":", 1)[1].split(","):
                m = re.match(r"\s*(\w+)\s*\((\w+)\)", part)
                if m:
                    defaults[m.group(2)] = m.group(1)
        else:
            parts = re.split(r"\s{2,}", ls)
            if len(parts) >= 3 and parts[1].split()[0].upper() in ("ALLOW", "DENY", "LIMIT", "REJECT"):
                num = None
                to = parts[0].strip()
                m = re.match(r"^\[\s*(\d+)\]\s+(.*)$", parts[0])
                if m:
                    num = int(m.group(1))
                    to = m.group(2).strip()
                action_words = parts[1].split()
                from_text = " ".join(parts[2:]).strip()
                src = _parse_rule_side(from_text)
                dst = _parse_rule_side(to)
                rules.append({
                    "number": num,
                    "to": to,
                    "action": " ".join(action_words),
                    "from": from_text,
                    # structured fields for the advanced UI
                    "verb": action_words[0].upper(),
                    "direction": (action_words[1].upper()
                                  if len(action_words) > 1 else None),
                    "iface": dst["iface"] or src["iface"],
                    "proto": dst["proto"] or src["proto"],
                    "port": dst["port"] or src["port"],
                    "src": src["addr"],
                    "dst": dst["addr"],
                    "v6": src["v6"] or dst["v6"],
                })

    traffic = {"allow": 0, "block": 0, "top_sources": [], "top_ports": [], "recent": []}
    sources = {}
    ports = {}
    events = []
    try:
        with open("/var/log/ufw.log", "r", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 524288))
            text = f.read()
    except Exception:
        text = ""

    for line in text.splitlines():
        m = EVENT_RE.match(line.strip())
        if not m:
            continue
        g = m.groupdict()
        action = g["action"]
        if action == "ALLOW":
            traffic["allow"] += 1
        else:
            traffic["block"] += 1
        if action == "BLOCK" and g["proto"] != "2":
            sources[g["src"]] = sources.get(g["src"], 0) + 1
            if g["dpt"]:
                port = g["dpt"] + "/" + (g["proto"] or "")
            elif g["proto"]:
                port = g["proto"]
            else:
                port = "?"
            ports[port] = ports.get(port, 0) + 1
        events.append({
            "ts": g["ts"], "action": action, "in": g["in"], "out": g["out"],
            "src": g["src"], "dst": g["dst"], "proto": g["proto"],
            "spt": g["spt"], "dpt": g["dpt"],
        })

    traffic["top_sources"] = [
        {"ip": k, "count": v}
        for k, v in sorted(sources.items(), key=lambda x: -x[1])[:10]
    ]
    traffic["top_ports"] = [
        {"port": k, "count": v}
        for k, v in sorted(ports.items(), key=lambda x: -x[1])[:10]
    ]
    traffic["recent"] = events[-25:]

    return {
        "ok": True,
        "status": status,
        "logging": logging_state,
        "defaults": defaults,
        "rules": rules,
        "traffic": traffic,
    }


def add_firewall_rule(rule_text):
    """Add a ufw rule, e.g. 'allow 8080/tcp' or
    'allow in on wg0 from 10.0.0.0/24 to any port 53 proto udp'."""
    args = (rule_text or "").split()
    if not args:
        raise RuntimeError("Rule is empty")
    _ufw(args)
    return build_firewall()


def delete_firewall_rule(number):
    """Delete a ufw rule by its number in `ufw status numbered`.

    `ufw delete <num>` prompts for confirmation and aborts when there is no
    stdin, so pass --force (same ruleset as 'ufw status numbered')."""
    try:
        num = int(number)
    except (TypeError, ValueError):
        raise RuntimeError("Invalid rule number")
    if num < 1:
        raise RuntimeError("Invalid rule number")
    _ufw(["--force", "delete", str(num)])
    return build_firewall()


_UFW_POLICIES = ("allow", "deny", "reject")
_UFW_LOG_LEVELS = ("off", "on", "low", "medium", "high", "full")


def set_firewall_enabled(enabled):
    """Enable or disable the ufw firewall."""
    _ufw(["--force", "enable" if enabled else "disable"])
    return build_firewall()


def set_firewall_default(direction, policy):
    """Set a default policy: `ufw default <policy> <direction>`."""
    direction = (direction or "").lower()
    policy = (policy or "").lower()
    if direction not in ("incoming", "outgoing", "routed"):
        raise RuntimeError("Invalid direction (incoming/outgoing/routed)")
    if policy not in _UFW_POLICIES:
        raise RuntimeError("Invalid policy (allow/deny/reject)")
    _ufw(["default", policy, direction])
    return build_firewall()


def set_firewall_logging(level):
    """Set ufw log level: off/on/low/medium/high/full."""
    level = (level or "").lower()
    if level not in _UFW_LOG_LEVELS:
        raise RuntimeError("Invalid logging level")
    _ufw(["logging", level])
    return build_firewall()


CROWDSEC_BIN = shutil.which("cscli") or "/usr/bin/cscli"
CROWDSEC_TIMEOUT = 15


def _cscli(args, default=None):
    """Run cscli and return parsed JSON output, or `default` on any failure."""
    try:
        proc = subprocess.run(
            [CROWDSEC_BIN] + args,
            capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "cscli failed").strip())
        out = proc.stdout.strip()
        if not out:
            return default
        parsed = json.loads(out)
        return parsed if isinstance(parsed, list) else default
    except Exception:
        return default


def _parse_iso(ts):
    if not ts:
        return None
    text = str(ts).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def build_crowdsec():
    try:
        proc = subprocess.run(
            [CROWDSEC_BIN, "decisions", "list", "-o", "json"],
            capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "cscli failed").strip())
        parsed = json.loads(proc.stdout.strip() or "[]")
        decisions_alerts = parsed if isinstance(parsed, list) else []
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    now = time.time()
    decisions = []
    for item in decisions_alerts:
        if isinstance(item, dict) and isinstance(item.get("decisions"), list):
            decisions.extend(item["decisions"])
        elif isinstance(item, dict):
            decisions.append(item)

    active = []
    for d in decisions:
        dtype = d.get("type") or ""
        if dtype == "unban":
            continue
        until_ts = _parse_iso(d.get("until"))
        if until_ts is not None and until_ts <= now:
            continue
        active.append({
            "ip": d.get("value") or "",
            "scope": d.get("scope") or "",
            "scenario": (d.get("scenario") or "").replace("crowdsecurity/", ""),
            "type": dtype,
            "origin": d.get("origin") or "",
            "created": d.get("created_at") or "",
            "until": d.get("until") or "",
            "until_ts": until_ts,
            "simulated": bool(d.get("simulated")),
            "expiring": until_ts is not None and until_ts - now <= 86400,
        })

    active.sort(key=lambda e: (e["until_ts"] or 0))

    return {
        "ok": True,
        "decisions": active,
        "active_count": len(active),
        "bans_count": len([d for d in active if d.get("type") == "ban"]),
        "bouncers": _cscli(["bouncers", "list", "-o", "json"], []) or [],
        "alerts": _cscli(["alerts", "list", "-o", "json"], []) or [],
    }


BAN_DURATION_RE = re.compile(r"^\d+[mhd]$")
BAN_DURATION_SECONDS = {"m": 60, "h": 3600, "d": 86400}


def ban_crowdsec_ip(ip, duration="24h"):
    """Ban a single IP via `cscli decisions add`. Rejects non-global
    (private/reserved) addresses and durations beyond 30 days."""
    ip = (ip or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "Invalid IP: %r" % ip}
    if not addr.is_global:
        return {"ok": False, "error": "Refusing to ban non-global IP %s (private/reserved)." % ip}
    duration = (duration or "").strip()
    if not BAN_DURATION_RE.match(duration):
        return {"ok": False, "error": "Duration must be like 24h, 7d, or 30d."}
    seconds = int(duration[:-1]) * BAN_DURATION_SECONDS[duration[-1]]
    if seconds > 30 * 86400:
        return {"ok": False, "error": "Duration too long (max 30d)."}
    try:
        proc = subprocess.run(
            [CROWDSEC_BIN, "decisions", "add", "--ip", ip, "--duration", duration],
            capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout or "cscli failed").strip()}
    return {
        "ok": True,
        "ip": ip,
        "duration": duration,
        "message": (proc.stdout or proc.stderr or "").strip(),
    }


def unban_crowdsec_ip(ip):
    """Remove any CrowdSec decisions for an IP (undo an accidental ban)."""
    ip = (ip or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "Invalid IP: %r" % ip}
    try:
        proc = subprocess.run(
            [CROWDSEC_BIN, "decisions", "delete", "-i", ip],
            capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout or "cscli failed").strip()}
    return {
        "ok": True,
        "ip": ip,
        "message": (proc.stdout or proc.stderr or "").strip(),
    }


# --- Custom blocklist ----------------------------------------------------
# A plain-text list of IPs/CIDRs that the dashboard keeps permanently banned
# through CrowdSec. Each entry is tagged with a stable `--reason` so the UI
# can tell these decisions apart from scenario-generated ones. The file lives
# in /etc/tuxwall (ReadWritePaths in the unit) so the UI can edit it without
# a reload; the CrowdSec trigger re-applies it on restarts.
CUSTOM_BLOCKLIST_FILE = "/etc/tuxwall/custom-blocklist.txt"
CUSTOM_BLOCKLIST_REASON = "custom/custom-blocklist"
CUSTOM_BLOCKLIST_DURATION = "8760h"  # 1 year


def _parse_blocklist_entry(value):
    """Validate/normalize a user-supplied blocklist entry (IP or CIDR).

    Returns (parsed, error) where parsed is a dict with 'type' ('ip'|'range')
    and 'value', or (None, message) on error."""
    value = (value or "").strip()
    if not value:
        return None, "Entry is empty."
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        try:
            net = ipaddress.ip_network(value, strict=True)
        except ValueError:
            return None, "Invalid entry. Expected an IP (1.2.3.4) or a CIDR network (1.2.3.0/24)."
        if not net.is_global:
            return None, "Refusing to block non-global range %s (private/reserved)." % net
        return {"type": "range", "value": str(net)}, None
    if not addr.is_global:
        return None, "Refusing to block non-global IP %s (private/reserved)." % addr
    return {"type": "ip", "value": str(addr)}, None


def _read_custom_blocklist():
    """Return the list of active entries in the custom blocklist file."""
    if not os.path.exists(CUSTOM_BLOCKLIST_FILE):
        return []
    try:
        with open(CUSTOM_BLOCKLIST_FILE, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def _ensure_custom_blocklist_file():
    if os.path.exists(CUSTOM_BLOCKLIST_FILE):
        return True
    try:
        os.makedirs(os.path.dirname(CUSTOM_BLOCKLIST_FILE), exist_ok=True)
        with open(CUSTOM_BLOCKLIST_FILE, "w", encoding="utf-8") as fh:
            fh.write("# Custom CrowdSec blocklist. One IP or CIDR per line.\n")
            fh.write("# Managed from the dashboard CrowdSec page; lines starting with '#' are ignored.\n")
        return True
    except OSError:
        return False


def _append_custom_blocklist_entry(entry):
    if not _ensure_custom_blocklist_file():
        return False
    try:
        with open(CUSTOM_BLOCKLIST_FILE, "a", encoding="utf-8") as fh:
            fh.write(entry + "\n")
        return True
    except OSError:
        return False


def _drop_custom_blocklist_entry(entry):
    """Rewrite the file dropping the given entry while keeping comments/order."""
    try:
        with open(CUSTOM_BLOCKLIST_FILE, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        lines = []
    out = [ln for ln in lines if ln.strip() != entry]
    if len(out) == len(lines):
        return False
    try:
        with open(CUSTOM_BLOCKLIST_FILE, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + ("\n" if out else ""))
        return True
    except OSError:
        return False


def build_custom_blocklist():
    """Status view: each file entry with whether a matching ban is active."""
    entries = _read_custom_blocklist()
    active = {}
    cs = build_crowdsec()
    if cs.get("ok"):
        for d in cs.get("decisions", []):
            if d.get("scenario") == CUSTOM_BLOCKLIST_REASON and d.get("ip"):
                active[d["ip"]] = d
    rows = []
    for e in entries:
        d = active.get(e)
        rows.append({
            "value": e,
            "banned": bool(d),
            "until": (d or {}).get("until") or "",
            "until_ts": (d or {}).get("until_ts"),
            "simulated": bool((d or {}).get("simulated")),
        })
    return {
        "ok": True,
        "file": CUSTOM_BLOCKLIST_FILE,
        "entries": rows,
        "active_count": len(active),
    }


def add_custom_blocklist_entry(value):
    """Add an entry to the list and create a matching long-lived CrowdSec ban."""
    parsed, err = _parse_blocklist_entry(value)
    if err:
        return {"ok": False, "error": err}
    entry = parsed["value"]
    if entry in _read_custom_blocklist():
        return {"ok": False, "error": "%s is already on the blocklist." % entry}
    if not _append_custom_blocklist_entry(entry):
        return {"ok": False, "error": "Could not write %s." % CUSTOM_BLOCKLIST_FILE}
    args = [CROWDSEC_BIN, "decisions", "add"]
    if parsed["type"] == "range":
        args += ["--range", entry]
    else:
        args += ["--ip", entry]
    args += ["--duration", CUSTOM_BLOCKLIST_DURATION, "--reason", CUSTOM_BLOCKLIST_REASON]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT)
    except Exception as exc:
        return {"ok": True, "warning": str(exc),
                "message": "Added %s to the list, but the CrowdSec ban failed." % entry}
    if proc.returncode != 0:
        return {"ok": True, "warning": (proc.stderr or proc.stdout or "").strip(),
                "message": "Added %s to the list, but the CrowdSec ban failed." % entry}
    return {"ok": True, "message": "Added %s to the blocklist (1y ban)." % entry}


def remove_custom_blocklist_entry(value):
    """Drop an entry from the list and delete its CrowdSec decisions."""
    value = (value or "").strip()
    if value not in _read_custom_blocklist():
        return {"ok": False, "error": "%s is not on the blocklist." % value}
    if not _drop_custom_blocklist_entry(value):
        return {"ok": False, "error": "Could not write %s." % CUSTOM_BLOCKLIST_FILE}
    parsed, _ = _parse_blocklist_entry(value)
    args = [CROWDSEC_BIN, "decisions", "delete"]
    if parsed and parsed["type"] == "range":
        args += ["--range", value]
    else:
        args += ["--ip", value]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT)
    except Exception as exc:
        return {"ok": True, "warning": str(exc),
                "message": "Removed %s from the list, but the CrowdSec ban cleanup failed." % value}
    if proc.returncode != 0:
        return {"ok": True, "warning": (proc.stderr or proc.stdout or "").strip(),
                "message": "Removed %s from the list, but the CrowdSec ban cleanup failed." % value}
    return {"ok": True, "message": "Removed %s from the blocklist." % value}


# --- Security / attack map -----------------------------------------------
GEO_DB_PATH = os.path.join(BLOCKLIST_DIR, "dbip-city-lite.mmdb")
GEO_CACHE_FILE = os.path.join(BLOCKLIST_DIR, "geo_cache.json")
UFW_LOG = "/var/log/ufw.log"
SECURITY_POLL_INTERVAL = 1.0
SECURITY_BUCKET_SECONDS = 10
SECURITY_BUCKETS = 60
SECURITY_MAX_EVENTS = 400

PRIVATE_SRC_RE = re.compile(
    r"^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|"
    r"224\.|239\.|255\.|0:|fe80:|fc|fd|::1)"
)


class SecurityMonitor:
    def __init__(self, interval=SECURITY_POLL_INTERVAL):
        self.interval = interval
        self.lock = threading.Lock()
        self.geo_lock = threading.Lock()
        self.events = deque(maxlen=SECURITY_MAX_EVENTS)
        self.by_ip = {}
        self.country_hits = {}
        self.country_names = {}
        self.buckets = deque(maxlen=SECURITY_BUCKETS)
        self.running = False
        self.thread = None
        self._reader = None
        self._db_checked = False
        self._cache = {}
        self._cache_dirty = False
        self._file = None
        self._ino = 0
        self._offset = 0
        self._started = time.time()

    def _ensure_reader(self):
        with self.geo_lock:
            if not self._db_checked:
                self._db_checked = True
                try:
                    import maxminddb
                    self._reader = maxminddb.open_database(GEO_DB_PATH)
                except Exception:
                    self._reader = None
            return self._reader

    def _load_cache(self):
        try:
            with open(GEO_CACHE_FILE, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._cache = data
        except (OSError, ValueError):
            self._cache = {}

    def _save_cache(self):
        try:
            os.makedirs(BLOCKLIST_DIR, exist_ok=True)
            tmp = GEO_CACHE_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._cache, f)
            os.replace(tmp, GEO_CACHE_FILE)
        except OSError:
            pass

    def geo_for(self, ip):
        cached = self._cache.get(ip)
        if cached is not None:
            return cached
        info = {"country": "", "iso": "", "city": "", "lat": None, "lon": None}
        reader = self._ensure_reader()
        if reader is not None:
            try:
                rec = reader.get(ip)
                if isinstance(rec, dict):
                    c = rec.get("country") or {}
                    info["iso"] = (c.get("iso_code") or "").upper()
                    info["country"] = (c.get("names") or {}).get("en", "") or info["iso"]
                    city = rec.get("city") or {}
                    info["city"] = (city.get("names") or {}).get("en", "") or ""
                    loc = rec.get("location") or {}
                    info["lat"] = loc.get("latitude")
                    info["lon"] = loc.get("longitude")
            except Exception:
                pass
        if not info["iso"]:
            info["iso"] = "??"
        with self.geo_lock:
            self._cache[ip] = info
            self._cache_dirty = True
        return info

    def _open_follow(self):
        try:
            st = os.stat(UFW_LOG)
            self._file = open(UFW_LOG, "rb")
            self._ino = st.st_ino
            self._offset = max(0, st.st_size - 262144)
        except OSError:
            self._file = None

    @staticmethod
    def _parse_ts(raw):
        try:
            return datetime.fromisoformat(raw).timestamp()
        except Exception:
            return None

    def _bump_bucket(self, ts):
        b = int(ts // SECURITY_BUCKET_SECONDS) * SECURITY_BUCKET_SECONDS
        if not self.buckets:
            self.buckets.append([b, 1])
            return
        cur = self.buckets[-1][0]
        if b < cur:
            return
        if b == cur:
            self.buckets[-1][1] += 1
            return
        while cur < b:
            cur += SECURITY_BUCKET_SECONDS
            self.buckets.append([cur, 0])
        self.buckets[-1][1] += 1

    def record(self, ts, src, dst, dpt, proto, geo):
        port = (dpt + "/" + proto) if dpt else (proto or "?")
        with self.lock:
            iso = geo["iso"]
            self.country_hits[iso] = self.country_hits.get(iso, 0) + 1
            self.country_names[iso] = geo["country"] or iso
            entry = self.by_ip.setdefault(src, {
                "ip": src,
                "count": 0,
                "first": ts,
                "last": ts,
                "country": geo["country"],
                "iso": geo["iso"],
                "city": geo["city"],
                "lat": geo["lat"],
                "lon": geo["lon"],
                "ports": {},
            })
            entry["count"] += 1
            entry["last"] = max(entry["last"], ts)
            entry["ports"][port] = entry["ports"].get(port, 0) + 1
            self.events.append({
                "ts": ts, "src": src, "dst": dst,
                "dpt": dpt, "proto": proto, "port": port,
                "iso": iso, "country": geo["country"], "city": geo["city"],
            })
            self._bump_bucket(ts)

    def _tick(self):
        try:
            if self._file is None:
                self._open_follow()
                if self._file is None:
                    return
            st = os.stat(UFW_LOG)
            if st.st_ino != self._ino or st.st_size < self._offset:
                self._file.close()
                self._open_follow()
                if self._file is None:
                    return
            self._file.seek(self._offset)
            chunk = self._file.read()
            self._offset = self._file.tell()
        except OSError:
            return

        now = time.time()
        for raw in chunk.splitlines():
            m = EVENT_RE.match(raw.decode("utf-8", "replace").strip())
            if not m:
                continue
            g = m.groupdict()
            if g["action"] != "BLOCK" or not g["in"]:
                continue
            src = g["src"]
            if not src or ":" in src or PRIVATE_SRC_RE.match(src):
                continue
            geo = self.geo_for(src)
            ts = self._parse_ts(g["ts"]) or now
            self.record(ts, src, g["dst"], g["dpt"] or "", g["proto"] or "", geo)

    def start(self):
        if self.running:
            return
        self.running = True
        self._load_cache()
        self._open_follow()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        tick = 0
        while self.running:
            time.sleep(self.interval)
            self._tick()
            tick += 1
            if tick % 60 == 0 and self._cache_dirty:
                with self.geo_lock:
                    self._save_cache()
                    self._cache_dirty = False

    def snapshot(self):
        with self.lock:
            now = time.time()
            hits = sum(e["count"] for e in self.by_ip.values())
            hits_1m = sum(1 for e in self.events if e["ts"] >= now - 60)
            hits_10m = sum(1 for e in self.events if e["ts"] >= now - 600)
            by_ip = []
            for e in self.by_ip.values():
                top_port = max(e["ports"].items(), key=lambda x: x[1])[0] if e["ports"] else "?"
                by_ip.append({
                    "ip": e["ip"], "count": e["count"],
                    "first": e["first"], "last": e["last"],
                    "country": e["country"], "iso": e["iso"], "city": e["city"],
                    "lat": e["lat"], "lon": e["lon"], "port": top_port,
                })
            by_ip.sort(key=lambda x: -x["count"])
            countries = [
                {"iso": iso, "name": self.country_names.get(iso, iso), "count": c}
                for iso, c in sorted(self.country_hits.items(), key=lambda x: -x[1])
            ]
            events = list(self.events)[-50:]
            events.reverse()
            series = [list(b) for b in self.buckets]
            geo_available = self._ensure_reader() is not None
        return {
            "ok": True,
            "started": self._started,
            "geo_db": {
                "available": geo_available,
                "path": GEO_DB_PATH if os.path.exists(GEO_DB_PATH) else "",
                "hint": (
                    "Geo-location unavailable - install the db-ip City Lite database "
                    "with scripts/geoip-setup.sh to map attacker locations."
                ) if not geo_available else "",
            },
            "stats": {
                "hits": hits,
                "unique_ips": len(by_ip),
                "countries": len(countries),
                "hits_1m": hits_1m,
                "hits_10m": hits_10m,
                "last_event": events[0]["ts"] if events else None,
            },
            "by_ip": by_ip[:50],
            "countries": countries,
            "events": events,
            "series": series,
        }


_SECURITY = None
_SECURITY_LOCK = threading.Lock()


def get_security_monitor():
    global _SECURITY
    with _SECURITY_LOCK:
        if _SECURITY is None:
            _SECURITY = SecurityMonitor()
            _SECURITY.start()
        return _SECURITY


# --- AI threat summary ------------------------------------------------------
LLM_CONF_PATH = "/etc/tuxwall/llm.json"
LLM_TIMEOUT = 45
LLM_MODELS_TIMEOUT = 15


def _llm_is_local(conf):
    base_host = conf["base_url"].split("/", 3)[2].split(":")[0] if "://" in conf["base_url"] else ""
    return base_host in ("localhost", "127.0.0.1", "::1")


def _llm_is_anthropic(conf):
    return "anthropic.com" in conf.get("base_url", "")


def _llm_headers(conf):
    headers = {"Content-Type": "application/json"}
    if conf["api_key"]:
        if _llm_is_anthropic(conf):
            headers["x-api-key"] = conf["api_key"]
            headers["anthropic-version"] = "2023-06-01"
        else:
            headers["Authorization"] = "Bearer " + conf["api_key"]
    return headers


def llm_model_list():
    conf = load_llm_conf()
    if not conf["api_key"] and not _llm_is_local(conf):
        return {"ok": False, "error": "not_configured"}
    try:
        req = urllib.request.Request(conf["base_url"] + "/models", method="GET")
        with urllib.request.urlopen(req, timeout=LLM_MODELS_TIMEOUT) as resp:
            parsed = json.loads(resp.read().decode("utf-8"))
        seen, models = set(), []
        for m in parsed.get("data") or []:
            mid = str(m.get("id") or "")
            if not mid:
                continue
            key = mid[:-7] if mid.endswith(":latest") else mid
            if key in seen:
                continue
            seen.add(key)
            models.append(key)
        models.sort()
        return {"ok": True, "models": models, "configured": conf["model"]}
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return {"ok": False, "error": "api_error", "detail": "HTTP {}: {}".format(exc.code, detail),
                "configured": conf["model"]}
    except Exception as exc:
        return {"ok": False, "error": "api_error", "detail": str(exc),
                "configured": conf["model"]}


def load_llm_conf():
    conf = {
        "api_key": (os.environ.get("TUXWALL_LLM_API_KEY")
                    or os.environ.get("OPENAI_API_KEY") or ""),
        "base_url": os.environ.get("TUXWALL_LLM_BASE_URL") or "https://api.openai.com/v1",
        "model": os.environ.get("TUXWALL_LLM_MODEL") or "qwen2.5:14b",
    }
    try:
        with open(LLM_CONF_PATH, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            conf["api_key"] = conf["api_key"] or str(data.get("api_key") or "")
            conf["base_url"] = str(data.get("base_url") or conf["base_url"])
            conf["model"] = str(data.get("model") or conf["model"])
    except (OSError, ValueError):
        pass
    conf["base_url"] = conf["base_url"].rstrip("/")
    return conf


def get_llm_conf():
    conf = load_llm_conf()
    key = conf["api_key"]
    masked = (key[:4] + "****" + key[-4:]) if len(key) > 8 else ("****" if key else "")
    return {"ok": True, "api_key_masked": masked, "base_url": conf["base_url"], "model": conf["model"]}


def save_llm_conf(body):
    base_url = (body.get("base_url") or "").strip().rstrip("/")
    api_key = (body.get("api_key") or "").strip()
    model = (body.get("model") or "").strip()
    if not base_url:
        raise ValueError("Base URL is required")
    if not model:
        raise ValueError("Model is required")
    data = {"base_url": base_url, "model": model}
    if api_key:
        data["api_key"] = api_key
    else:
        existing = load_llm_conf()
        data["api_key"] = existing["api_key"]
    bak = LLM_CONF_PATH + ".bak-" + time.strftime("%Y%m%d%H%M%S")
    try:
        if os.path.exists(LLM_CONF_PATH):
            shutil.copy2(LLM_CONF_PATH, bak)
    except OSError:
        pass
    os.makedirs(os.path.dirname(LLM_CONF_PATH), exist_ok=True)
    with open(LLM_CONF_PATH, "w") as f:
        json.dump(data, f, indent=2)
    return {"ok": True, "backup": bak if os.path.exists(bak) else None}


# --- Suricata IDS ----------------------------------------------------------
SURICATA_EVE_LOG = "/var/log/suricata/eve.json"
SURICATA_WINDOW = 86400
SURICATA_TAIL_BYTES = 4 * 1024 * 1024
SURICATA_SEVERITY = {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}


def _suricata_tail_lines():
    """Read complete JSON lines from the tail of eve.json (bounded memory)."""
    try:
        st = os.stat(SURICATA_EVE_LOG)
    except OSError:
        return None
    if st.st_size == 0:
        return []
    start = max(0, st.st_size - SURICATA_TAIL_BYTES)
    try:
        with open(SURICATA_EVE_LOG, "r", errors="replace") as f:
            f.seek(start)
            if start:
                f.readline()
            data = f.read()
    except OSError:
        return None
    lines = []
    for raw in data.splitlines():
        raw = raw.strip()
        if raw:
            lines.append(raw)
    return lines


def build_suricata():
    """Recent Suricata signature alerts read from eve.json (IDS mode).

    Suricata runs as a passive sensor: it inspects a copy of each packet via
    af-packet and never sits in the forwarding path, so there is no throughput
    impact on the router.
    """
    lines = _suricata_tail_lines()
    if lines is None:
        return {
            "ok": True, "enabled": False, "count_24h": 0, "alerts": [], "top": [],
            "hint": ("Suricata is not installed or not writing /var/log/suricata/eve.json. "
                     "Install it in passive IDS mode to add signature alerts to the AI "
                     "Threat Summary."),
        }
    now = time.time()
    alerts = []
    for raw in lines:
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(ev, dict) or ev.get("event_type") != "alert":
            continue
        alert = ev.get("alert") or {}
        sig = (alert.get("signature") or "").strip()
        if not sig:
            continue
        ts = _parse_iso(ev.get("timestamp")) or now
        if now - ts > SURICATA_WINDOW:
            continue
        alerts.append({
            "ts": ts,
            "sig": sig[:120],
            "sid": alert.get("signature_id"),
            "category": (alert.get("category") or "").strip(),
            "severity": SURICATA_SEVERITY.get(str(alert.get("severity")), "LOW"),
            "src": ev.get("src_ip") or "",
            "sport": ev.get("src_port") or "",
            "dst": ev.get("dest_ip") or "",
            "dport": ev.get("dest_port") or "",
            "proto": (ev.get("proto") or "").upper(),
        })
    alerts.sort(key=lambda a: a["ts"], reverse=True)

    top = {}
    for a in alerts:
        key = (a["sig"], a["sid"])
        if key not in top:
            top[key] = {
                "sig": a["sig"], "sid": a["sid"],
                "category": a["category"], "severity": a["severity"],
                "count": 0, "last_ts": a["ts"],
            }
        top[key]["count"] += 1
        if a["ts"] > top[key]["last_ts"]:
            top[key]["last_ts"] = a["ts"]
    top_list = sorted(top.values(), key=lambda t: (-t["count"], t["severity"]))

    return {
        "ok": True,
        "enabled": True,
        "count_24h": len(alerts),
        "alerts": alerts[:30],
        "top": top_list[:10],
    }


def _collect_security_facts():
    facts = {}
    try:
        snap = get_security_monitor().snapshot()
        facts["stats"] = snap.get("stats", {})
        facts["top_attackers"] = [
            {"ip": i["ip"], "hits": i["count"], "top_port": i.get("port"),
             "country": i.get("country"), "city": i.get("city")}
            for i in (snap.get("by_ip") or [])[:10]
        ]
        facts["recent_events"] = [
            {"src": e["src"], "port": e["port"], "country": e.get("country"),
             "ago_s": round(max(0, time.time() - e["ts"]))}
            for e in (snap.get("events") or [])[:15]
        ]
    except Exception:
        pass
    try:
        cs = build_crowdsec()
        if cs.get("ok"):
            facts["crowdsec"] = {
                "active_count": cs.get("active_count"),
                "bans_count": cs.get("bans_count"),
                "active_decisions": [
                    {"ip": d["ip"], "scenario": d["scenario"], "type": d["type"],
                     "until": d.get("until")}
                    for d in cs.get("decisions", [])[:10]
                ],
            }
    except Exception:
        pass
    try:
        bans = load_bans()
        facts["dashboard_bans"] = [
            {"ip": b["ip"], "hostname": b.get("hostname", ""),
             "added": time.strftime("%Y-%m-%d %H:%M", time.localtime(b["added_at"]))}
            for b in bans[:10]
        ]
    except Exception:
        pass
    try:
        sur = build_suricata()
        if sur.get("ok") and sur.get("enabled"):
            facts["suricata"] = {
                "alerts_24h": sur.get("count_24h"),
                "top_alerts": [
                    {"signature": t["sig"], "severity": t["severity"],
                     "category": t["category"], "count": t["count"]}
                    for t in (sur.get("top") or [])
                ],
            }
    except Exception:
        pass
    return facts


def _clean_ufw_command(cmd):
    cmd = re.sub(
        r"\bport (\d{1,5})/(tcp|udp)\b",
        lambda m: "port {} proto {}".format(m.group(1), m.group(2).lower()),
        cmd, flags=re.I,
    )
    cmd = re.sub(r"\b(\d{1,3}(?:\.\d{1,3}){3})/32\b", r"\1", cmd)
    return " ".join(cmd.split())


def _split_summary(content):
    """Extract runnable commands from the model output and keep the prose.

    The model is unreliable about placing commands in a 'Commands:' section,
    so any line that looks like a ufw/cscli/nft/iptables command is pulled out
    here, normalized to valid syntax, and deduplicated.
    """
    prose, commands = [], []
    for line in content.splitlines():
        t = line.strip()
        if not t:
            continue
        candidate = re.sub(r"^[\s\-*\u2022\d.)]+", "", t)
        if re.match(r"^(?:sudo\s+)?(?:ufw|cscli|nft|iptables)\b", candidate, re.I):
            cleaned = _clean_ufw_command(candidate)
            if not cleaned or re.search(r"\bdeny from any\b", cleaned, re.I):
                continue
            if cleaned not in commands:
                commands.append(cleaned)
            continue
        if re.fullmatch(r"[*_#\s]*commands?:?[*_#\s]*", t, re.I):
            continue
        prose.append(t)
    return "\n".join(prose).strip(), commands


def _llm_chat(conf, messages):
    body = {
        "model": conf["model"],
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 700,
    }
    req = urllib.request.Request(
        conf["base_url"] + "/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers=_llm_headers(conf),
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
        parsed = json.loads(resp.read().decode("utf-8"))
    content = (((parsed.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
    if not content:
        raise RuntimeError("empty model response")
    return content


def _limit_summary(prose):
    """Cap the number of finding bullets and keep the top action.

    Bullets are lines matching the '<attack type> | severity | <action>'
    format the model is told to use. Anything after the cap is dropped; the
    'Top action:' line is always kept.
    """
    lines = [l.strip() for l in prose.splitlines() if l.strip()]
    bullets, top, heading, seen_bullet = [], [], [], False
    for l in lines:
        if re.search(r"\|\s*(HIGH|MEDIUM|LOW)\s*\|", l, re.I):
            seen_bullet = True
            if len(bullets) < 5:
                if not re.match(r"^[-*\u2022]", l):
                    l = "- " + l
                bullets.append(l)
        elif re.match(r"^top action:", l, re.I):
            top.append(l)
        elif not seen_bullet:
            heading.append(l)
    if seen_bullet and len(bullets) == 5:
        bullets.append("- (further findings omitted \u2014 see map and top attackers)")
    return "\n".join(heading + bullets + top).strip()


def collect_ai_context():
    """Snapshot real system state to inject into the AI prompt."""
    sections = []

    # Firewall rules
    try:
        fw = build_firewall()
        if fw.get("ok"):
            rules = fw.get("rules") or []
            defaults = fw.get("defaults") or {}
            lines = ["=== FIREWALL (UFW) ===",
                     "Status: " + fw.get("status", "unknown"),
                     "Default incoming: " + defaults.get("incoming", "?"),
                     "Default outgoing: " + defaults.get("outgoing", "?"),
                     "Rules:"]
            for r in rules[:30]:
                lines.append(f"  [{r.get('num')}] {r.get('action','?')} {r.get('to','?')} from {r.get('from','any')}  # {r.get('comment','')}")
            sections.append("\n".join(lines))
    except Exception as e:
        sections.append(f"=== FIREWALL ===\nUnavailable: {e}")

    # DHCP leases
    try:
        leases = build_leases()
        active = [l for l in (leases.get("leases") or []) if l.get("state") != 2]
        lines = [f"=== DHCP CLIENTS ({len(active)} active) ==="]
        for l in active[:20]:
            lines.append(f"  {l.get('ip','?'):16} {(l.get('hostname') or '(no hostname)'):30} {l.get('mac',''):18} {l.get('vendor','')}")
        sections.append("\n".join(lines))
    except Exception as e:
        sections.append(f"=== DHCP CLIENTS ===\nUnavailable: {e}")

    # DNS settings
    try:
        dns = build_dns()
        if dns.get("ok"):
            lines = ["=== DNS (Unbound) ==="]
            upstreams = dns.get("upstreams") or []
            lines.append("Upstreams: " + (", ".join(upstreams) if upstreams else "none"))
            stats = dns.get("stats") or {}
            if stats:
                lines.append(f"Queries total: {stats.get('total',0)}  blocked: {stats.get('blocked',0)}  cache_hit: {stats.get('cache_hit',0)}")
            sections.append("\n".join(lines))
    except Exception as e:
        sections.append(f"=== DNS ===\nUnavailable: {e}")

    # System services
    try:
        svcs = list_system_services()
        lines = ["=== SERVICES ==="]
        for s in (svcs.get("services") or [])[:15]:
            lines.append(f"  {s.get('unit',''):30} {s.get('active','?'):10} {s.get('sub','')}")
        sections.append("\n".join(lines))
    except Exception as e:
        sections.append(f"=== SERVICES ===\nUnavailable: {e}")

    # System stats
    try:
        st = build_status()
        if st.get("ok"):
            lines = ["=== SYSTEM ===",
                     f"Hostname: {st.get('hostname','')}",
                     f"Uptime: {st.get('uptime_str','')}",
                     f"CPU: {st.get('cpu_percent',0):.1f}%  RAM: {st.get('mem_percent',0):.1f}%  Disk: {st.get('disk_percent',0):.1f}%",
                     f"Load: {st.get('load_1',0):.2f} / {st.get('load_5',0):.2f} / {st.get('load_15',0):.2f}"]
            sections.append("\n".join(lines))
    except Exception as e:
        sections.append(f"=== SYSTEM ===\nUnavailable: {e}")

    # Blocked domains count
    try:
        doms = build_domains()
        blocked = [d for d in (doms.get("domains") or []) if d.get("kind") == "block"]
        allowed = [d for d in (doms.get("domains") or []) if d.get("kind") == "allow"]
        sections.append(f"=== DNS DOMAINS ===\nBlocked: {len(blocked)}  Allowed overrides: {len(allowed)}")
        if blocked[:10]:
            sections[-1] += "\nRecent blocks: " + ", ".join(d.get("name","") for d in blocked[:10])
    except Exception as e:
        sections.append(f"=== DNS DOMAINS ===\nUnavailable: {e}")

    # Security / bans
    try:
        bans = load_bans()
        lines = [f"=== ACTIVE BANS ({len(bans)}) ==="]
        for b in bans[:10]:
            lines.append(f"  {b.get('ip',''):18} {b.get('hostname','')}")
        sections.append("\n".join(lines))
    except Exception as e:
        sections.append(f"=== ACTIVE BANS ===\nUnavailable: {e}")

    # Top attackers
    try:
        snap = get_security_monitor().snapshot()
        attackers = (snap.get("by_ip") or [])[:8]
        if attackers:
            lines = ["=== TOP ATTACKERS (last window) ==="]
            for a in attackers:
                lines.append(f"  {a.get('ip',''):18} hits={a.get('count',0):5}  port={a.get('port','')}  {a.get('country','')}")
            sections.append("\n".join(lines))
    except Exception:
        pass

    return "\n\n".join(sections)


AI_CHAT_SYSTEM_PROMPT = """You are TuxWall AI — an intelligent assistant embedded inside the TuxWall network firewall dashboard.
You have deep knowledge of Linux networking, iptables/nftables, DNS (Unbound), DHCP (dnsmasq), WireGuard VPN, Suricata IDS, and general network security.

You can answer questions, explain firewall concepts, help diagnose network issues, and propose configuration changes to TuxWall.

When you want to propose a change to TuxWall settings, output a JSON block inside <tuxwall-action> tags (one per action).
Each action must have an "action" field (the type) and the relevant fields below.

At the start of every conversation you will receive a LIVE SYSTEM SNAPSHOT showing the actual current state of the firewall — real UFW rules with their numbers, real DHCP clients with their IPs and hostnames, real DNS settings, real bans, services, and system stats. Use this data to answer questions accurately and to propose changes that reference the real rule numbers and real IPs.

Supported actions and their fields:

  Block an IP (adds UFW deny + DNS block):
    {"action":"block_ip","ip":"1.2.3.4","comment":"Reason"}

  Unblock an IP:
    {"action":"unblock_ip","ip":"1.2.3.4"}

  Add a UFW allow rule (e.g. "allow 22/tcp", "allow from 192.168.1.0/24"):
    {"action":"add_firewall_rule","rule":"allow 22/tcp","comment":"Allow SSH"}

  Delete a UFW rule by its number (from the snapshot):
    {"action":"delete_firewall_rule","number":5,"comment":"Remove old rule"}

  Block a domain in DNS (adds to Unbound blocklist):
    {"action":"block_domain","domain":"ads.example.com","comment":"Ad server"}

  Remove a blocked domain:
    {"action":"unblock_domain","domain":"ads.example.com"}

  Restart a system service (use the unit name from the snapshot):
    {"action":"restart_service","service":"unbound","comment":"Apply DNS changes"}

Rules:
- You have real system data — use it. Reference actual rule numbers, actual IPs, actual hostnames.
- Only propose actions the user explicitly asks for.
- Always explain what will change and why before outputting action blocks.
- Warn before any disruptive action (blocking services, deleting rules).
- Use markdown for code. Be concise.
- Never guess at IPs or domain names — use only what appears in the system snapshot.
"""

def ai_chat(messages, model=None):
    """Handle a multi-turn AI chat session with TuxWall context awareness."""
    conf = load_llm_conf()
    if not conf["api_key"] and not _llm_is_local(conf):
        return {
            "ok": False,
            "error": "not_configured",
            "hint": "Configure an AI provider in Settings → AI / Security, or add /etc/tuxwall/llm.json",
        }
    if model:
        conf["model"] = model

    # Collect live system state and prepend as context
    try:
        ctx = collect_ai_context()
        context_msg = {"role": "user", "content": "LIVE SYSTEM SNAPSHOT:\n\n" + ctx}
        context_ack = {"role": "assistant", "content": "I have reviewed the current system snapshot and am ready to assist."}
    except Exception as exc:
        context_msg = {"role": "user", "content": f"(System snapshot unavailable: {exc})"}
        context_ack = {"role": "assistant", "content": "I couldn't retrieve the system snapshot but will do my best."}

    # Build message list with system prompt + live context + conversation
    full_messages = (
        [{"role": "system", "content": AI_CHAT_SYSTEM_PROMPT}]
        + [context_msg, context_ack]
        + (messages or [])
    )

    try:
        body = {
            "model": conf["model"],
            "messages": full_messages,
            "temperature": 0.5,
            "max_tokens": 1800,
        }
        req = urllib.request.Request(
            conf["base_url"] + "/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers=_llm_headers(conf),
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
            parsed = json.loads(resp.read().decode("utf-8"))
        content = (((parsed.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
        if not content:
            raise RuntimeError("Empty response from model")
        usage = parsed.get("usage") or {}
        return {
            "ok": True,
            "content": content,
            "model": conf["model"],
            "usage": {
                "input_tokens":  int(usage.get("prompt_tokens")    or usage.get("input_tokens")  or 0),
                "output_tokens": int(usage.get("completion_tokens") or usage.get("output_tokens") or 0),
            },
        }
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:400]
        except Exception:
            pass
        return {"ok": False, "error": "API error HTTP {}: {}".format(exc.code, detail)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def ai_security_summary(model=None):
    conf = load_llm_conf()
    if not conf["api_key"] and not _llm_is_local(conf):
        return {
            "ok": False,
            "error": "not_configured",
            "hint": ('Create /etc/tuxwall/llm.json with {"api_key": "sk-..."} '
                     "or set the TUXWALL_LLM_API_KEY environment variable."),
        }
    if model:
        conf["model"] = model

    facts = _collect_security_facts()
    system_prompt = (
        "You are a decisive senior SOC analyst for a small home network. "
        "Given the firewall observations, produce a concise analysis. Rules:\n"
        "- Use at most 5 short bullets. If many IPs share the same attack "
        "type, group them in one bullet instead of listing each one.\n"
        "- Each bullet: '<attack type>' | severity <HIGH|MEDIUM|LOW> | <one "
        "concrete action the owner should take>. Severity must be exactly "
        "HIGH, MEDIUM, or LOW - never invent other values.\n"
        "- Be decisive: never write 'monitor', 'consider', 'may', or 'further "
        "investigation'.\n"
        "- Port 23 is telnet and port 22 is SSH; label attack types with the "
        "correct protocol.\n"
        "- Only reference data present in the observations; do not invent IPs, "
        "ports, CVEs, or scenarios.\n"
        "- If an attacker IP is in well-known public infrastructure ranges "
        "(e.g. 1.1.1.1, 8.8.8.8, 9.9.9.9), the address may be spoofed or "
        "shared, so recommend blocking the specific port rather than the "
        "entire IP.\n"
        "- CrowdSec bans are active security controls and are assumed valid. "
        "Never recommend lifting or removing them unless the observations show "
        "clear evidence of a false positive.\n"
        "- Suricata alerts are signature-based detections from a passive IDS. "
        "Treat HIGH-severity alerts as priority findings, but a single alert is "
        "a signal, not proof of a breach - correlate it with the firewall "
        "observations before recommending a block.\n"
        "- If observations are empty or minimal, output a single bullet saying "
        "so.\n"
        "- End with one short line: 'Top action: <the single most important "
        "step>'.\n"
        "- Finally, add a section headed exactly 'Commands:' with 1-3 "
        "concrete, copy-paste ready shell commands that implement the "
        "recommended actions, using the exact IPs, ports, and interfaces from "
        "the observations.\n"
        "- The 'Commands:' section must contain ONLY valid commands, one per "
        "line: no code fences, no backticks, no numbering, no markdown, no "
        "explanatory text. Use exactly these forms:\n"
        "    ufw deny from <IP> to any\n"
        "    ufw deny from <IP> to any port <PORT> proto <tcp|udp>\n"
        "    ufw allow in on <IFACE> from <SUBNET> to any port <PORT> proto <tcp|udp>\n"
        "    sudo cscli decisions add --ip <IP> --duration <24h|7d>\n"
        "- Never combine a bare IP with '/32' in a ufw rule, never put "
        "'from any' inside a deny command, and never emit a language tag or "
        "the word 'bash' before or inside the 'Commands:' section.\n"
        "- The 'Commands:' section must be the final output; nothing may "
        "follow it."
    )
    user_prompt = "Current firewall observations (JSON):\n" + json.dumps(facts, indent=2)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        content = _llm_chat(conf, messages)
        summary, commands = _split_summary(content)
        if not commands:
            try:
                repair = _llm_chat(conf, messages + [
                    {"role": "assistant", "content": content},
                    {"role": "user", "content": (
                        "Your analysis contained no 'Commands:' section. Reply now with "
                        "ONLY the Commands: section containing 1-3 valid commands that "
                        "implement your recommendations, using the exact forms from the "
                        "rules. Nothing else."
                    )},
                ])
                _, commands = _split_summary(repair)
            except Exception:
                commands = []
        summary = _limit_summary(summary)
        return {
            "ok": True,
            "summary": summary,
            "commands": commands,
            "model": conf["model"],
            "generated_at": time.time(),
        }
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return {"ok": False, "error": "api_error", "detail": "HTTP {}: {}".format(exc.code, detail)}
    except Exception as exc:
        return {"ok": False, "error": "api_error", "detail": str(exc)}


# --- WireGuard / VPN ------------------------------------------------------
WG_CONF = "/etc/wireguard/wg0.conf"
WG_STATE_FILE = os.path.join(BLOCKLIST_DIR, "wireguard.json")
WG_IFACE = "wg0"
WG_DEFAULT_ADDRESS = "10.0.0.1/24"
WG_V6_ADDRESS = "fd00:2::1/64"
WG_V6_SUBNET = "fd00:2::/64"
WG_DEFAULT_DNS = "192.168.1.1"
WG_DEFAULT_ALLOWED_IPS = "0.0.0.0/0, ::/0"
WG_DEFAULT_KEEPALIVE = 25
WG_DEFAULT_PORT = 51820
WG_NAME_RE = re.compile(r"[^\w .-]")
WG_WAN_IP = {"ip": ""}


def is_wg_key(value):
    """True if value looks like a WireGuard key (base64 of 32 bytes).

    `wg show ... private-key` prints "(none)" when the kernel has no key for
    the interface, so we must never treat that placeholder as a real key."""
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 44:
        return False
    try:
        return len(base64.b64decode(value + "=" * (-len(value) % 4))) == 32
    except Exception:
        return False


def _wg(args, input_text=None, timeout=15):
    proc = subprocess.run(
        ["wg"] + args, input=input_text,
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "wg failed").strip())
    return proc.stdout


def wg_genkey():
    return _wg(["genkey"]).strip()


def wg_pubkey(private_key):
    return _wg(["pubkey"], input_text=(private_key or "") + "\n").strip()


def wg_systemctl(args, timeout=60):
    proc = subprocess.run(
        ["systemctl"] + args, capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "systemctl failed").strip())


def get_wan_ip():
    if WG_WAN_IP["ip"]:
        return WG_WAN_IP["ip"]
    try:
        route = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        m = re.search(r"dev\s+(\S+)", route)
        dev = m.group(1) if m else ""
        addr = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        for line in addr.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet":
                iface = parts[1].rstrip(":")
                if dev and iface == dev:
                    WG_WAN_IP["ip"] = parts[3].split("/")[0]
                    return WG_WAN_IP["ip"]
        for line in addr.splitlines():
            parts = line.split()
            if (len(parts) >= 5 and parts[2] == "inet"
                    and parts[4] == "global"):
                WG_WAN_IP["ip"] = parts[3].split("/")[0]
                return WG_WAN_IP["ip"]
    except Exception:
        pass
    return ""


def get_wan_interface():
    """Name of the interface holding the default route (the WAN)."""
    try:
        route = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        m = re.search(r"dev\s+(\S+)", route)
        return m.group(1) if m else ""
    except Exception:
        return ""


def ensure_wg_routing():
    """Make sure VPN clients can reach the internet.

    Enables IPv4 forwarding and installs NAT masquerade + FORWARD accept rules
    for the WireGuard interface. Idempotent, so it is safe to call on every
    peer write without duplicating rules."""
    wan = get_wan_interface()
    if not wan:
        return
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                       capture_output=True, text=True, timeout=5)
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
                       capture_output=True, text=True, timeout=5)
        state = load_wg_state()
        subnet = wg_client_subnet(state)
        v6subnet = WG_V6_SUBNET
        adds = [
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet,
             "-o", wan, "-j", "MASQUERADE"],
            ["iptables", "-A", "FORWARD", "-i", WG_IFACE, "-j", "ACCEPT"],
            ["iptables", "-A", "FORWARD", "-o", WG_IFACE, "-j", "ACCEPT"],
            ["iptables", "-A", "INPUT", "-i", WG_IFACE, "-s", subnet,
             "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            ["iptables", "-A", "INPUT", "-i", WG_IFACE, "-s", subnet,
             "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
            ["ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", v6subnet,
             "-o", wan, "-j", "MASQUERADE"],
            ["ip6tables", "-A", "FORWARD", "-i", WG_IFACE, "-j", "ACCEPT"],
            ["ip6tables", "-A", "FORWARD", "-o", WG_IFACE, "-j", "ACCEPT"],
            ["ip6tables", "-A", "INPUT", "-i", WG_IFACE, "-s", v6subnet,
             "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            ["ip6tables", "-A", "INPUT", "-i", WG_IFACE, "-s", v6subnet,
             "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
        ]
        for add in adds:
            check = ["-C" if x == "-A" else x for x in add]
            if subprocess.run(check, capture_output=True, text=True,
                              timeout=10).returncode != 0:
                subprocess.run(add, capture_output=True, text=True, timeout=10)
        try:
            _ufw(["allow", "in on {} from {} to any port 53 proto udp".format(
                WG_IFACE, subnet)])
            _ufw(["allow", "in on {} from {} to any port 53 proto tcp".format(
                WG_IFACE, subnet)])
            _ufw(["allow", "in on {} from {} to any port 53 proto udp".format(
                WG_IFACE, v6subnet)])
            _ufw(["allow", "in on {} from {} to any port 53 proto tcp".format(
                WG_IFACE, v6subnet)])
        except Exception:
            pass
    except Exception:
        pass
    ensure_wg_dns()


def ensure_wg_dns():
    """Let WireGuard clients use the router's own DNS (unbound).

    Unbound refuses everything except the LAN by default, so we add an
    access-control allow for the VPN subnet. Unbound picks the most specific
    netblock, so the /24 allow overrides the 0.0.0.0/0 refuse."""
    try:
        state = load_wg_state()
        subnet = wg_client_subnet(state)
        path = "/etc/unbound/unbound.conf.d/90-wireguard-dns.conf"
        content = (
            "# Managed by the tuxwall WireGuard page - DO NOT EDIT\n"
            "server:\n"
            "    access-control: {} allow\n".format(subnet)
        )
        try:
            with open(path, "r") as f:
                current = f.read()
        except OSError:
            current = ""
        if current != content:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.write(content)
            os.replace(tmp, path)
            reload_unbound()
    except Exception:
        pass


def load_wg_state():
    try:
        with open(WG_STATE_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {"server": {}, "peers": []}


def save_wg_state(state):
    os.makedirs(BLOCKLIST_DIR, exist_ok=True)
    tmp = WG_STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, WG_STATE_FILE)
    try:
        os.chmod(WG_STATE_FILE, 0o600)
    except OSError:
        pass


def read_wg_conf_interface():
    address = WG_DEFAULT_ADDRESS
    listen_port = WG_DEFAULT_PORT
    private_key = ""
    try:
        with open(WG_CONF, "r") as f:
            for line in f:
                ls = line.strip()
                if ls.startswith("Address ="):
                    address = ls.split("=", 1)[1].strip()
                elif ls.startswith("ListenPort ="):
                    try:
                        listen_port = int(ls.split("=", 1)[1].strip())
                    except ValueError:
                        pass
                elif ls.startswith("PrivateKey ="):
                    private_key = ls.split("=", 1)[1].strip()
    except OSError:
        pass
    return address, listen_port, private_key


def _wg_running_private_key():
    try:
        key = _wg(["show", WG_IFACE, "private-key"]).strip()
    except Exception:
        return ""
    return key if is_wg_key(key) else ""


def _wg_server_private_key(state):
    """Server private key from the state file, then the on-disk config, then
    the live interface. Only real keys are returned; the kernel reports
    "(none)" when the interface has no key, which is never a usable key."""
    server = state.get("server") or {}
    priv = server.get("private_key") or ""
    if not is_wg_key(priv):
        priv = ""
    if not priv:
        _, _, priv = read_wg_conf_interface()
    if not is_wg_key(priv):
        priv = ""
    if not priv:
        priv = _wg_running_private_key()
    return priv


def _wg_recover_server_key(state):
    """Persist a recoverable server private key back into the state file so a
    later write never drops it from the config again."""
    server = state.get("server")
    if not isinstance(server, dict):
        server = {}
        state["server"] = server
    if not is_wg_key(server.get("private_key") or ""):
        priv = _wg_server_private_key(state)
        if is_wg_key(priv):
            server["private_key"] = priv
        else:
            server.pop("private_key", None)
        save_wg_state(state)
    return server


def write_wg_conf(state):
    server = state.get("server") or {}
    conf_addr, conf_port, conf_priv = read_wg_conf_interface()
    priv = server.get("private_key") or conf_priv or _wg_running_private_key()
    if not is_wg_key(priv):
        priv = ""
    subnet = wg_client_subnet(state)
    wan = get_wan_interface()
    lines = [
        "# Managed by the tuxwall WireGuard page - DO NOT EDIT",
        "[Interface]",
        "Address = {}, {}".format(
            (server.get("address") or conf_addr or WG_DEFAULT_ADDRESS).split(",")[0].strip(),
            WG_V6_ADDRESS),
        "ListenPort = {}".format(server.get("listen_port") or conf_port or WG_DEFAULT_PORT),
    ]
    if priv:
        lines.append("PrivateKey = {}".format(priv))
    if wan:
        lines.append(
            "PostUp = iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || "
            "iptables -A FORWARD -i %i -j ACCEPT; "
            "iptables -C FORWARD -o %i -j ACCEPT 2>/dev/null || "
            "iptables -A FORWARD -o %i -j ACCEPT; "
            "iptables -t nat -C POSTROUTING -s {} -o {} -j MASQUERADE 2>/dev/null || "
            "iptables -t nat -A POSTROUTING -s {} -o {} -j MASQUERADE; "
            "iptables -C INPUT -i %i -s {} -p udp --dport 53 -j ACCEPT 2>/dev/null || "
            "iptables -A INPUT -i %i -s {} -p udp --dport 53 -j ACCEPT; "
            "iptables -C INPUT -i %i -s {} -p tcp --dport 53 -j ACCEPT 2>/dev/null || "
            "iptables -A INPUT -i %i -s {} -p tcp --dport 53 -j ACCEPT; "
            "ip6tables -C FORWARD -i %i -j ACCEPT 2>/dev/null || "
            "ip6tables -A FORWARD -i %i -j ACCEPT; "
            "ip6tables -C FORWARD -o %i -j ACCEPT 2>/dev/null || "
            "ip6tables -A FORWARD -o %i -j ACCEPT; "
            "ip6tables -t nat -C POSTROUTING -s {} -o {} -j MASQUERADE 2>/dev/null || "
            "ip6tables -t nat -A POSTROUTING -s {} -o {} -j MASQUERADE; "
            "ip6tables -C INPUT -i %i -s {} -p udp --dport 53 -j ACCEPT 2>/dev/null || "
            "ip6tables -A INPUT -i %i -s {} -p udp --dport 53 -j ACCEPT; "
            "ip6tables -C INPUT -i %i -s {} -p tcp --dport 53 -j ACCEPT 2>/dev/null || "
            "ip6tables -A INPUT -i %i -s {} -p tcp --dport 53 -j ACCEPT; "
            "sysctl -w net.ipv4.ip_forward=1; "
            "sysctl -w net.ipv6.conf.all.forwarding=1".format(
                subnet, wan, subnet, wan, subnet, subnet, subnet, subnet,
                WG_V6_SUBNET, wan, WG_V6_SUBNET, wan,
                WG_V6_SUBNET, WG_V6_SUBNET, WG_V6_SUBNET, WG_V6_SUBNET))
        lines.append(
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null; "
            "iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null; "
            "iptables -t nat -D POSTROUTING -s {} -o {} -j MASQUERADE 2>/dev/null; "
            "iptables -D INPUT -i %i -s {} -p udp --dport 53 -j ACCEPT 2>/dev/null; "
            "iptables -D INPUT -i %i -s {} -p tcp --dport 53 -j ACCEPT 2>/dev/null; "
            "ip6tables -D FORWARD -i %i -j ACCEPT 2>/dev/null; "
            "ip6tables -D FORWARD -o %i -j ACCEPT 2>/dev/null; "
            "ip6tables -t nat -D POSTROUTING -s {} -o {} -j MASQUERADE 2>/dev/null; "
            "ip6tables -D INPUT -i %i -s {} -p udp --dport 53 -j ACCEPT 2>/dev/null; "
            "ip6tables -D INPUT -i %i -s {} -p tcp --dport 53 -j ACCEPT 2>/dev/null".format(
                subnet, wan, subnet, subnet,
                WG_V6_SUBNET, wan, WG_V6_SUBNET, WG_V6_SUBNET))
    for peer in state.get("peers", []):
        lines.append("")
        lines.append("# Peer: {}".format(peer.get("name") or "device"))
        lines.append("[Peer]")
        lines.append("PublicKey = {}".format(peer["public_key"]))
        addr = (peer.get("address") or "").split("/")[0]
        last = addr.split(".")[3] if "." in addr else ""
        v6 = wg_client_v6(last) if last else ""
        lines.append("AllowedIPs = {}/32, {}/128".format(addr, v6))
    lines.append("")
    os.makedirs(os.path.dirname(WG_CONF), exist_ok=True)
    tmp = WG_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines))
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, WG_CONF)


def apply_wg_config():
    try:
        subprocess.run(
            ["bash", "-c",
             "wg syncconf {} <(wg-quick strip {})".format(WG_IFACE, WG_IFACE)],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        pass
    ensure_wg_routing()


def parse_wg_dump(dump):
    lines = dump.splitlines()
    if not lines:
        return {"public_key": "", "listen_port": 0, "peers": []}
    iface = lines[0].split("\t")
    peers = []
    for line in lines[1:]:
        p = line.split("\t")
        if len(p) < 8:
            continue
        peers.append({
            "public_key": p[0],
            "preshared_key": "" if p[1] in ("", "(none)") else p[1],
            "endpoint": "" if p[2] in ("", "(none)") else p[2],
            "allowed_ips": "" if p[3] in ("", "(none)") else p[3],
            "last_handshake": int(p[4]) if p[4].isdigit() else 0,
            "rx": int(p[5]) if p[5].isdigit() else 0,
            "tx": int(p[6]) if p[6].isdigit() else 0,
            "keepalive": int(p[7]) if p[7].isdigit() else 0,
        })
    return {
        "public_key": iface[1] if len(iface) > 1 and is_wg_key(iface[1]) else "",
        "listen_port": int(iface[2]) if len(iface) > 2 and iface[2].isdigit() else 0,
        "peers": peers,
    }


def next_wg_client_ip(state):
    used = set()
    for p in state.get("peers", []):
        try:
            used.add(int(p["address"].split("/")[0].split(".")[3]))
        except (ValueError, IndexError):
            pass
    base = (state.get("server") or {}).get("address", WG_DEFAULT_ADDRESS)
    prefix = ".".join(base.split("/")[0].split(".")[:3])
    for i in range(2, 254):
        if i not in used:
            return "{}.{}".format(prefix, i)
    raise RuntimeError("No free client IP addresses in the /24")


def wg_client_subnet(state):
    base = (state.get("server") or {}).get("address", WG_DEFAULT_ADDRESS)
    return ".".join(base.split("/")[0].split(".")[:3]) + ".0/24"


def wg_client_v6(last_octet):
    return WG_V6_SUBNET.split("/")[0] + "{}".format(last_octet)


def build_client_conf(client_priv, server_pub, client_ip, endpoint,
                      allowed_ips, dns, keepalive):
    last = client_ip.split("/")[0].split(".")[3] if "." in client_ip else ""
    v6 = wg_client_v6(last) if last else ""
    return (
        "[Interface]\n"
        "PrivateKey = {}\n"
        "Address = {}/24, {}/64\n"
        "DNS = {}\n"
        "\n"
        "[Peer]\n"
        "PublicKey = {}\n"
        "AllowedIPs = {}\n"
        "Endpoint = {}\n"
        "PersistentKeepalive = {}\n"
    ).format(client_priv, client_ip, v6, dns, server_pub, allowed_ips,
             endpoint, keepalive)


def _wg_server_pub():
    state = load_wg_state()
    server_priv = _wg_server_private_key(state)
    return wg_pubkey(server_priv) if server_priv else ""


def _wg_endpoint(listen_port):
    wan = get_wan_ip()
    return "{}:{}".format(wan or "YOUR_WAN_IP", listen_port)


def setup_wireguard(body):
    if os.path.exists(WG_CONF):
        return {"ok": True, "already": True}
    address = (body.get("address") or WG_DEFAULT_ADDRESS).strip()
    try:
        listen_port = int(body.get("listen_port") or WG_DEFAULT_PORT)
    except (TypeError, ValueError):
        raise RuntimeError("Invalid listen port")
    if not (0 < listen_port < 65536):
        raise RuntimeError("Invalid listen port")
    dns = (body.get("dns") or WG_DEFAULT_DNS).strip()
    allowed_ips = (body.get("allowed_ips") or WG_DEFAULT_ALLOWED_IPS).strip()
    try:
        keepalive = int(body.get("keepalive") or WG_DEFAULT_KEEPALIVE)
    except (TypeError, ValueError):
        keepalive = WG_DEFAULT_KEEPALIVE
    endpoint = (body.get("endpoint") or "").strip()
    if not endpoint:
        endpoint = get_wan_ip()
    if not endpoint:
        raise RuntimeError("Could not detect the WAN IP - provide an endpoint")

    server_priv = wg_genkey()
    state = {
        "server": {
            "address": address,
            "listen_port": listen_port,
            "dns": dns,
            "allowed_ips": allowed_ips,
            "keepalive": keepalive,
            "endpoint": endpoint,
            "private_key": server_priv,
        },
        "peers": [],
    }
    save_wg_state(state)
    write_wg_conf(state)
    client_subnet = wg_client_subnet(state)
    _ufw(["allow", "{}/udp".format(listen_port)])
    _ufw(["allow", "in on {} from {} to any port 53 proto udp".format(WG_IFACE, client_subnet)])
    _ufw(["allow", "in on {} from {} to any port 53 proto tcp".format(WG_IFACE, client_subnet)])
    _ufw(["allow", "in on {} from {} to any port 53 proto udp".format(WG_IFACE, WG_V6_SUBNET)])
    _ufw(["allow", "in on {} from {} to any port 53 proto tcp".format(WG_IFACE, WG_V6_SUBNET)])
    wg_systemctl(["enable", "wg-quick@{}".format(WG_IFACE)])
    wg_systemctl(["restart", "wg-quick@{}".format(WG_IFACE)])
    ensure_wg_routing()
    return {
        "ok": True,
        "already": False,
        "public_key": wg_pubkey(server_priv),
        "endpoint": _wg_endpoint(listen_port),
    }


def add_wg_peer(name=""):
    state = load_wg_state()
    _wg_recover_server_key(state)
    server = state.get("server") or {}
    if not is_wg_key(server.get("private_key") or ""):
        if not os.path.exists(WG_CONF):
            raise RuntimeError("WireGuard is not configured yet")
        raise RuntimeError("WireGuard server private key is missing - regenerate it first")
    client_priv = wg_genkey()
    client_pub = wg_pubkey(client_priv)
    client_ip = next_wg_client_ip(state)
    clean_name = WG_NAME_RE.sub("", (name or "").strip())[:40] or "device"
    state["peers"].append({
        "name": clean_name,
        "public_key": client_pub,
        "private_key": client_priv,
        "address": "{}/24".format(client_ip),
        "added_at": time.time(),
    })
    save_wg_state(state)
    write_wg_conf(state)
    apply_wg_config()
    server_pub = wg_pubkey(server["private_key"]) if server.get("private_key") else ""
    allowed_ips = server.get("allowed_ips") or WG_DEFAULT_ALLOWED_IPS
    dns = server.get("dns") or WG_DEFAULT_DNS
    keepalive = server.get("keepalive") or WG_DEFAULT_KEEPALIVE
    port = server.get("listen_port") or WG_DEFAULT_PORT
    endpoint_host = server.get("endpoint") or get_wan_ip()
    if not endpoint_host or endpoint_host.startswith("YOUR_WAN_IP"):
        endpoint_host = get_wan_ip()
    endpoint = "{}:{}".format(endpoint_host, port)
    conf = build_client_conf(
        client_priv, server_pub, client_ip, endpoint,
        allowed_ips, dns, keepalive,
    )
    return {
        "ok": True,
        "name": clean_name,
        "public_key": client_pub,
        "address": client_ip,
        "endpoint": endpoint,
        "config": conf,
    }


def peer_config(public_key):
    state = load_wg_state()
    peer = next((p for p in state.get("peers", [])
                 if p.get("public_key") == public_key), None)
    if not peer or not peer.get("private_key"):
        raise RuntimeError("Client config unavailable for this peer")
    server = state.get("server") or {}
    server_priv = _wg_server_private_key(state)
    if not server_priv:
        raise RuntimeError("Server private key not found")
    server_pub = wg_pubkey(server_priv)
    client_ip = peer["address"].split("/")[0]
    port = server.get("listen_port") or WG_DEFAULT_PORT
    endpoint_host = server.get("endpoint") or get_wan_ip()
    if not endpoint_host or endpoint_host.startswith("YOUR_WAN_IP"):
        endpoint_host = get_wan_ip()
    endpoint = "{}:{}".format(endpoint_host, port)
    conf = build_client_conf(
        peer["private_key"], server_pub, client_ip, endpoint,
        server.get("allowed_ips") or WG_DEFAULT_ALLOWED_IPS,
        server.get("dns") or WG_DEFAULT_DNS,
        server.get("keepalive") or WG_DEFAULT_KEEPALIVE,
    )
    return {"ok": True, "name": peer.get("name"), "config": conf,
            "endpoint": endpoint}


def remove_wg_peer(public_key):
    state = load_wg_state()
    before = len(state.get("peers", []))
    state["peers"] = [p for p in state.get("peers", [])
                      if p.get("public_key") != public_key]
    if len(state["peers"]) == before:
        raise RuntimeError("Peer not found")
    _wg_recover_server_key(state)
    save_wg_state(state)
    write_wg_conf(state)
    apply_wg_config()
    return {"ok": True}


def rename_wg_peer(public_key, name):
    clean = WG_NAME_RE.sub("", (name or "").strip())[:40] or "device"
    state = load_wg_state()
    for peer in state.get("peers", []):
        if peer.get("public_key") == public_key:
            peer["name"] = clean
            _wg_recover_server_key(state)
            save_wg_state(state)
            write_wg_conf(state)
            return {"ok": True, "name": clean}
    raise RuntimeError("Peer not found")


def wg_interface_start():
    wg_systemctl(["start", "wg-quick@{}".format(WG_IFACE)])


def wg_interface_stop():
    wg_systemctl(["stop", "wg-quick@{}".format(WG_IFACE)])


def build_wireguard():
    configured = os.path.exists(WG_CONF)
    state = load_wg_state()
    conf_addr, conf_port, conf_priv = read_wg_conf_interface()
    server_priv = _wg_server_private_key(state)
    if configured and not is_wg_key(conf_priv) and server_priv:
        _wg_recover_server_key(state)
        write_wg_conf(state)
        _, _, conf_priv = read_wg_conf_interface()
    server_pub = wg_pubkey(server_priv) if server_priv else ""
    up = False
    live_peers = []
    live_pub = ""
    live_port = 0
    if configured:
        try:
            dump = _wg(["show", WG_IFACE, "dump"])
            parsed = parse_wg_dump(dump)
            up = True
            live_peers = parsed["peers"]
            live_pub = parsed["public_key"]
            live_port = parsed["listen_port"]
        except Exception:
            up = False

    state_peers = {p.get("public_key"): p for p in state.get("peers", [])}
    all_keys = set(live_peers and {p["public_key"] for p in live_peers}) | set(state_peers)
    live_map = {p["public_key"]: p for p in live_peers}
    peers = []
    for idx, pk in enumerate(sorted(all_keys), 1):
        lp = live_map.get(pk, {})
        sp = state_peers.get(pk, {})
        addr = (sp.get("address") or "").split("/")[0]
        if not addr:
            addr = (lp.get("allowed_ips") or "").split("/")[0]
        peers.append({
            "public_key": pk,
            "name": sp.get("name") or "Peer {}".format(idx),
            "address": addr,
            "allowed_ips": lp.get("allowed_ips", ""),
            "endpoint": lp.get("endpoint", ""),
            "last_handshake": lp.get("last_handshake", 0),
            "rx": lp.get("rx", 0),
            "tx": lp.get("tx", 0),
            "keepalive": lp.get("keepalive", 0),
            "has_config": bool(sp.get("private_key")),
            "added_at": sp.get("added_at"),
        })
    peers.sort(key=lambda p: (p["address"] or "z"))

    server = state.get("server") or {}
    listen_port = conf_port or live_port or server.get("listen_port") or WG_DEFAULT_PORT
    return {
        "ok": True,
        "configured": configured,
        "wan_ip": get_wan_ip(),
        "endpoint": _wg_endpoint(listen_port) if configured else "",
        "interface": {
            "name": WG_IFACE,
            "up": up,
            "public_key": (live_pub if is_wg_key(live_pub) else "") or server_pub,
            "listen_port": listen_port,
            "address": conf_addr,
            "dns": server.get("dns") or WG_DEFAULT_DNS,
            "allowed_ips": server.get("allowed_ips") or WG_DEFAULT_ALLOWED_IPS,
            "keepalive": server.get("keepalive") or WG_DEFAULT_KEEPALIVE,
            "rx": sum(p["rx"] for p in live_peers),
            "tx": sum(p["tx"] for p in live_peers),
            "service_active": service_active("wg-quick@{}".format(WG_IFACE)),
        },
        "peers": peers,
    }


# --- Blocklist / ad-blocking (Pi-hole style) -------------------------------
BLOCKLIST_UPDATE_LOCK = threading.Lock()

BLOCKLIST_STATE = {
    "status": "idle",
    "last_update": None,
    "last_ok": None,
    "last_error": None,
    "total_domains": 0,
    "log": [],
}

DOMAIN_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
SKIP_HOSTS = {
    "localhost", "localhost.localdomain", "broadcasthost", "local",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "home.arpa",
}


def blocklist_log(line):
    BLOCKLIST_STATE["log"].append(
        "[{}] {}".format(time.strftime("%H:%M:%S"), line)
    )
    del BLOCKLIST_STATE["log"][:-60]


def load_blocklists():
    try:
        with open(BLOCKLIST_CONFIG, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except (OSError, ValueError):
        pass
    return None


def save_blocklists(data):
    os.makedirs(BLOCKLIST_DIR, exist_ok=True)
    tmp = BLOCKLIST_CONFIG + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, BLOCKLIST_CONFIG)


def load_whitelist():
    try:
        with open(BLOCKLIST_WHITELIST, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, str)]
    except (OSError, ValueError):
        pass
    return []


def save_whitelist(domains):
    os.makedirs(BLOCKLIST_DIR, exist_ok=True)
    tmp = BLOCKLIST_WHITELIST + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(domains), f, indent=2)
    os.replace(tmp, BLOCKLIST_WHITELIST)


def normalize_domain(token):
    dom = token.strip().lower().rstrip(".")
    if dom.startswith("*."):
        dom = dom[2:]
    elif dom.startswith("."):
        dom = dom[1:]
    return dom


def valid_whitelist_domain(token):
    dom = normalize_domain(token)
    if (not dom or "/" in dom or _looks_like_ip(dom)
            or dom in SKIP_HOSTS or not DOMAIN_RE.match(dom)):
        return None
    return dom


def filter_whitelist(domains, whitelist):
    if not whitelist:
        return domains
    whitelist = set(whitelist)
    suffixes = tuple("." + w for w in whitelist)
    return {
        d for d in domains
        if d not in whitelist and not d.endswith(suffixes)
    }


# --- Client bans (firewall + DNS block, Pi-hole "block client" style) ----
BAN_LOCK = threading.Lock()


def load_bans():
    try:
        with open(CLIENT_BANS_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return [b for b in data if isinstance(b, dict) and b.get("ip")]
    except (OSError, ValueError):
        pass
    return []


def save_bans(bans):
    os.makedirs(BLOCKLIST_DIR, exist_ok=True)
    tmp = CLIENT_BANS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(bans, f, indent=2)
    os.replace(tmp, CLIENT_BANS_FILE)


def write_client_bans_conf(bans):
    lines = [
        "# Generated by the tuxwall DHCP Clients page - DO NOT EDIT",
        "server:",
    ]
    lines.extend(
        "    access-control: {} refuse".format(b["ip"])
        for b in sorted(bans, key=lambda x: x["ip"])
    )
    os.makedirs(os.path.dirname(CLIENT_BANS_CONF), exist_ok=True)
    tmp = CLIENT_BANS_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, CLIENT_BANS_CONF)


def reload_unbound():
    proc = subprocess.run(
        ["unbound-checkconf"], capture_output=True, text=True, timeout=30
    )
    if proc.returncode != 0:
        raise RuntimeError(
            (proc.stderr or proc.stdout or "unbound-checkconf failed").strip()
        )
    proc = subprocess.run(
        ["unbound-control", "reload"], capture_output=True, text=True, timeout=120
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "unbound-control reload failed").strip())


def _ufw(args):
    flat = []
    for arg in args:
        if " " in arg:
            flat.extend(arg.split())
        else:
            flat.append(arg)
    proc = subprocess.run(
        ["ufw"] + flat, capture_output=True, text=True, timeout=30
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "ufw failed").strip())


def ban_client(ip, hostname="", mac=""):
    with BAN_LOCK:
        bans = load_bans()
        if any(b["ip"] == ip for b in bans):
            return False
        _ufw(["insert", "1", "deny", "from", ip, "to", "any"])
        bans.insert(0, {
            "ip": ip,
            "hostname": hostname or "",
            "mac": mac or "",
            "added_at": time.time(),
        })
        save_bans(bans)
        write_client_bans_conf(bans)
        try:
            reload_unbound()
        except Exception as exc:
            subprocess.run(
                ["ufw", "delete", "deny", "from", ip, "to", "any"],
                capture_output=True, text=True, timeout=30,
            )
            save_bans([b for b in load_bans() if b["ip"] != ip])
            write_client_bans_conf(load_bans())
            raise RuntimeError(str(exc))
        return True


def unban_client(ip):
    with BAN_LOCK:
        bans = load_bans()
        if not any(b["ip"] == ip for b in bans):
            return False
        subprocess.run(
            ["ufw", "delete", "deny", "from", ip, "to", "any"],
            capture_output=True, text=True, timeout=30,
        )
        bans = [b for b in bans if b["ip"] != ip]
        save_bans(bans)
        write_client_bans_conf(bans)
        reload_unbound()
        return True


def ensure_blocklist_config():
    data = load_blocklists()
    if data is not None:
        return data
    seed = [{
        "url": DEFAULT_BLOCKLIST_URL,
        "enabled": True,
        "added_at": time.time(),
        "last_status": None,
        "last_error": None,
        "last_updated": None,
        "domains": 0,
    }]
    save_blocklists(seed)
    return seed


def valid_blocklist_url(url):
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def fetch_blocklist(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": "tuxwall-blocklist/1.0",
        "Accept-Encoding": "gzip",
    })
    with urllib.request.urlopen(req, timeout=BLOCKLIST_FETCH_TIMEOUT) as resp:
        data = resp.read(BLOCKLIST_MAX_BYTES + 1)
        if len(data) > BLOCKLIST_MAX_BYTES:
            raise RuntimeError(
                "List exceeds {} MB limit".format(BLOCKLIST_MAX_BYTES // (1024 * 1024))
            )
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
    return data.decode("utf-8", errors="replace")


def _looks_like_ip(token):
    return bool(IPV4_RE.match(token)) or ":" in token


def parse_blocklist(text):
    domains = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        if _looks_like_ip(tokens[0]):
            candidates = tokens[1:]
        else:
            candidates = tokens[:1]
        for cand in candidates:
            dom = cand.strip().lower().rstrip(".")
            if dom.startswith("*."):
                dom = dom[2:]
            elif dom.startswith("."):
                dom = dom[1:]
            if (not dom or "/" in dom or _looks_like_ip(dom)
                    or dom in SKIP_HOSTS or not DOMAIN_RE.match(dom)):
                continue
            domains.add(dom)
    return domains


def write_blocklist_conf(domains):
    lines = [
        "# Generated by the tuxwall blocklist page - DO NOT EDIT",
        "# last-update: {:.3f}".format(time.time()),
        "# {} domains".format(len(domains)),
        "server:",
    ]
    lines.extend(
        '    local-zone: "{}." always_nxdomain'.format(d)
        for d in sorted(domains)
    )
    os.makedirs(os.path.dirname(BLOCKLIST_CONF), exist_ok=True)
    tmp = BLOCKLIST_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, BLOCKLIST_CONF)


def count_blocked_domains():
    try:
        with open(BLOCKLIST_CONF, "r") as f:
            for _ in range(5):
                line = f.readline()
                m = re.search(r"#\s*(\d+)\s+domains", line)
                if m:
                    return int(m.group(1))
    except (OSError, ValueError):
        pass
    return BLOCKLIST_STATE["total_domains"]


def last_blocklist_update():
    if BLOCKLIST_STATE["last_update"]:
        return BLOCKLIST_STATE["last_update"]
    try:
        with open(BLOCKLIST_CONF, "r") as f:
            for _ in range(3):
                line = f.readline()
                m = re.search(r"last-update:\s*([0-9.]+)", line)
                if m:
                    return float(m.group(1))
    except (OSError, ValueError):
        pass
    return None


def run_blocklist_update():
    if not BLOCKLIST_UPDATE_LOCK.acquire(blocking=False):
        return
    try:
        sources = ensure_blocklist_config()
        enabled = [s for s in sources if s.get("enabled", True)]
        BLOCKLIST_STATE["status"] = "updating"
        BLOCKLIST_STATE["last_error"] = None
        blocklist_log(
            "Starting update ({}/{} sources enabled)".format(len(enabled), len(sources))
        )

        all_domains = set()
        for src in enabled:
            url = src.get("url", "")
            blocklist_log("Fetching {}".format(url))
            try:
                domains = parse_blocklist(fetch_blocklist(url))
            except Exception as exc:
                msg = str(exc)
                src["last_status"] = "error"
                src["last_error"] = msg
                src["last_updated"] = time.time()
                blocklist_log("  FAILED: {}".format(msg))
                continue
            src["last_status"] = "ok"
            src["last_error"] = None
            src["last_updated"] = time.time()
            src["domains"] = len(domains)
            all_domains |= domains
            blocklist_log("  {} domains".format(len(domains)))

        save_blocklists(sources)

        if enabled and not all_domains:
            BLOCKLIST_STATE["last_error"] = "No domains fetched from any enabled source"
            BLOCKLIST_STATE["status"] = "error"
            blocklist_log("No domains fetched - keeping existing blocklist")
            return

        whitelist = load_whitelist()
        if whitelist:
            excluded = len(all_domains) - len(filter_whitelist(all_domains, whitelist))
            all_domains = filter_whitelist(all_domains, whitelist)
            blocklist_log("Skipped {} domains via whitelist".format(excluded))

        BLOCKLIST_STATE["total_domains"] = len(all_domains)
        blocklist_log("Total unique domains: {}".format(len(all_domains)))

        if os.path.exists(BLOCKLIST_CONF):
            shutil.copy2(BLOCKLIST_CONF, BLOCKLIST_BACKUP)

        write_blocklist_conf(all_domains)

        proc = subprocess.run(
            ["unbound-checkconf"], capture_output=True, text=True, timeout=30
        )
        if proc.returncode != 0:
            raise RuntimeError(
                (proc.stderr or proc.stdout or "unbound-checkconf failed").strip()
            )

        proc = subprocess.run(
            ["unbound-control", "reload"], capture_output=True, text=True, timeout=120
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "unbound-control reload failed").strip())

        now = time.time()
        BLOCKLIST_STATE["status"] = "ok"
        BLOCKLIST_STATE["last_update"] = now
        BLOCKLIST_STATE["last_ok"] = now
        BLOCKLIST_STATE["last_error"] = None
        blocklist_log("Update complete - unbound reloaded")
    except Exception as exc:
        msg = str(exc)
        if os.path.exists(BLOCKLIST_BACKUP):
            shutil.copy2(BLOCKLIST_BACKUP, BLOCKLIST_CONF)
            blocklist_log("Restored previous blocklist after failure")
        BLOCKLIST_STATE["last_error"] = msg
        BLOCKLIST_STATE["status"] = "error"
        blocklist_log("FAILED: {}".format(msg))
    finally:
        BLOCKLIST_UPDATE_LOCK.release()


def build_blocklists():
    sources = ensure_blocklist_config()
    dns = build_dns()
    stats = None
    if dns.get("ok"):
        totals = dns.get("totals") or {}
        stats = {
            "queries": int(totals.get("queries") or 0),
            "blocked": int(totals.get("nxdomain") or 0) if dns.get("extended") else None,
        }
    return {
        "ok": True,
        "sources": sources,
        "whitelist": load_whitelist(),
        "stats": stats,
        "state": {
            "status": BLOCKLIST_STATE["status"],
            "last_update": last_blocklist_update(),
            "last_ok": BLOCKLIST_STATE["last_ok"],
            "last_error": BLOCKLIST_STATE["last_error"],
            "total_domains": count_blocked_domains(),
            "log": BLOCKLIST_STATE["log"],
        },
    }


class BandwidthMonitor:
    def __init__(self, interval=BANDWIDTH_INTERVAL, window=BANDWIDTH_WINDOW):
        self.interval = interval
        self.max_samples = max(10, int(window / interval))
        self.lock = threading.Lock()
        self.samples = {}
        self.totals = {}
        self.last = {}
        self.running = False
        self.thread = None

    @staticmethod
    def _read():
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.read().splitlines()
        except Exception:
            return {}
        result = {}
        for line in lines:
            if ":" not in line:
                continue
            iface, rest = line.split(":", 1)
            iface = iface.strip()
            if iface == "lo":
                continue
            parts = rest.split()
            if len(parts) < 9:
                continue
            try:
                result[iface] = {"rx": int(parts[0]), "tx": int(parts[8])}
            except ValueError:
                continue
        return result

    def _tick(self):
        now = time.time()
        current = self._read()
        with self.lock:
            for iface, counts in current.items():
                prev = self.last.get(iface)
                if prev is not None and now > prev["t"]:
                    dt = now - prev["t"]
                    rx, tx = counts["rx"], counts["tx"]
                    if rx >= prev["rx"] and tx >= prev["tx"]:
                        rx_bps = (rx - prev["rx"]) * 8 / dt
                        tx_bps = (tx - prev["tx"]) * 8 / dt
                        self.samples.setdefault(iface, deque(maxlen=self.max_samples)).append(
                            [now, rx_bps, tx_bps]
                        )
                        tot = self.totals.setdefault(iface, {"rx": 0, "tx": 0})
                        tot["rx"] += rx - prev["rx"]
                        tot["tx"] += tx - prev["tx"]
                self.last[iface] = {"t": now, "rx": counts["rx"], "tx": counts["tx"]}

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.running:
            time.sleep(self.interval)
            self._tick()

    def snapshot(self):
        with self.lock:
            return {
                iface: (list(dq), dict(self.totals.get(iface, {"rx": 0, "tx": 0})))
                for iface, dq in self.samples.items()
            }


_MONITOR = None
_MONITOR_LOCK = threading.Lock()


def get_monitor():
    global _MONITOR
    with _MONITOR_LOCK:
        if _MONITOR is None:
            _MONITOR = BandwidthMonitor()
            _MONITOR.start()
        return _MONITOR


def build_bandwidth():
    monitor = get_monitor()
    interfaces = []
    for iface, (history, totals) in monitor.snapshot().items():
        if not history:
            continue
        interfaces.append({
            "name": iface,
            "rx_bps": history[-1][1],
            "tx_bps": history[-1][2],
            "rx_total": totals["rx"],
            "tx_total": totals["tx"],
            "history": history,
        })
    interfaces.sort(key=lambda i: i["name"])

    clients = []
    clients_error = ""
    traffic = get_client_traffic()
    if traffic is not None:
        try:
            leases = build_leases().get("leases", [])
        except Exception:
            leases = []
        lease_map = {l["ip"]: l for l in leases if l.get("ip")}
        try:
            sync_client_traffic_clients(list(lease_map))
        except Exception as exc:
            clients_error = str(exc)
        for ip, snap in traffic.snapshot().items():
            lease = lease_map.get(ip, {})
            clients.append({
                "ip": ip,
                "hostname": lease.get("hostname", ""),
                "mac": lease.get("mac", ""),
                "rx_bytes_per_s": snap["rx_rate"],
                "tx_bytes_per_s": snap["tx_rate"],
                "rx_bytes": snap["rx_total"],
                "tx_bytes": snap["tx_total"],
            })
        clients.sort(key=lambda c: c["ip"])
    else:
        clients_error = _CLIENT_TRAFFIC_ERROR or "Per-client tracking unavailable."
    return {
        "ok": True,
        "interval": monitor.interval,
        "max_samples": monitor.max_samples,
        "interfaces": interfaces,
        "clients": clients,
        "clients_error": clients_error,
    }


_CLIENT_TRAFFIC = None
_CLIENT_TRAFFIC_ERROR = ""
_CLIENT_TRAFFIC_LOCK = threading.Lock()


def ensure_client_traffic_table():
    try:
        proc = subprocess.run(
            [NFT_BIN, "list", "table", "inet", NFT_TABLE],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as exc:
        return str(exc)
    if proc.returncode == 0:
        return ""
    spec = (
        "table inet %s {\n"
        "  set %s {\n"
        "    type ipv4_addr\n"
        "    counter\n"
        "  }\n"
        "  set %s {\n"
        "    type ipv4_addr\n"
        "    counter\n"
        "  }\n"
        "  chain prerouting {\n"
        "    type filter hook prerouting priority 0; policy accept;\n"
        "    ip saddr @%s counter\n"
        "    ip daddr @%s counter\n"
        "  }\n"
        "}\n"
    ) % (NFT_TABLE, NFT_TX_SET, NFT_RX_SET, NFT_TX_SET, NFT_RX_SET)
    try:
        proc = subprocess.run(
            [NFT_BIN, "-f", "-"], input=spec, text=True,
            capture_output=True, timeout=10,
        )
    except Exception as exc:
        return str(exc)
    if proc.returncode == 0:
        return ""
    return (proc.stderr or "nft create table failed").strip()


def sync_client_traffic_clients(ips):
    if not ips:
        return
    for set_name in (NFT_TX_SET, NFT_RX_SET):
        subprocess.run(
            [NFT_BIN, "add", "element", "inet", NFT_TABLE, set_name,
             "{%s}" % ", ".join(ips)],
            capture_output=True, text=True, timeout=10,
        )


class ClientTrafficMonitor:
    def __init__(self, interval=CLIENT_TRAFFIC_INTERVAL):
        self.interval = interval
        self.lock = threading.Lock()
        self.rates = {}
        self.totals = {}
        self.last = {}
        self.running = False
        self.thread = None

    @staticmethod
    def _read():
        result = {}
        for direction, set_name in (("rx", NFT_RX_SET), ("tx", NFT_TX_SET)):
            try:
                proc = subprocess.run(
                    [NFT_BIN, "list", "set", "inet", NFT_TABLE, set_name],
                    capture_output=True, text=True, timeout=10,
                )
            except Exception:
                continue
            if proc.returncode != 0:
                continue
            for match in re.finditer(
                r"(\d{1,3}(?:\.\d{1,3}){3}) counter packets \d+ bytes (\d+)",
                proc.stdout,
            ):
                result.setdefault(match.group(1), {})[direction] = int(match.group(2))
        return result

    def _tick(self):
        now = time.time()
        current = self._read()
        with self.lock:
            for ip, counts in current.items():
                prev = self.last.get(ip)
                rx, tx = counts.get("rx", 0), counts.get("tx", 0)
                if (prev is not None and now > prev["t"]
                        and rx >= prev["rx"] and tx >= prev["tx"]):
                    dt = now - prev["t"]
                    if dt > 0:
                        self.rates[ip] = {
                            "rx_rate": (rx - prev["rx"]) / dt,
                            "tx_rate": (tx - prev["tx"]) / dt,
                        }
                        tot = self.totals.setdefault(ip, {"rx": 0, "tx": 0})
                        tot["rx"] += rx - prev["rx"]
                        tot["tx"] += tx - prev["tx"]
                self.last[ip] = {"t": now, "rx": rx, "tx": tx}

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.running:
            time.sleep(self.interval)
            self._tick()

    def snapshot(self):
        with self.lock:
            return {
                ip: {
                    "rx_rate": r.get("rx_rate", 0.0),
                    "tx_rate": r.get("tx_rate", 0.0),
                    "rx_total": self.totals.get(ip, {}).get("rx", 0),
                    "tx_total": self.totals.get(ip, {}).get("tx", 0),
                }
                for ip, r in self.rates.items()
            }


def get_client_traffic():
    global _CLIENT_TRAFFIC, _CLIENT_TRAFFIC_ERROR
    with _CLIENT_TRAFFIC_LOCK:
        if _CLIENT_TRAFFIC is None:
            _CLIENT_TRAFFIC_ERROR = ensure_client_traffic_table()
            if _CLIENT_TRAFFIC_ERROR:
                return None
            monitor = ClientTrafficMonitor()
            monitor.start()
            _CLIENT_TRAFFIC = monitor
        return _CLIENT_TRAFFIC


class SystemMonitor:
    """Samples CPU% + memory% into a rolling history for the overview charts."""

    def __init__(self, interval=SYSTEM_POLL_INTERVAL, window=SYSTEM_WINDOW):
        self.interval = interval
        self.max_samples = max(10, int(window / interval))
        self.lock = threading.Lock()
        self.history = deque(maxlen=self.max_samples)
        self.last_cpu = None
        self.cpu_pct = 0.0
        self.running = False
        self.thread = None

    @staticmethod
    def _cpu_times():
        try:
            with open("/proc/stat", "r") as f:
                line = f.readline()
            if not line.startswith("cpu"):
                return None
            parts = list(map(int, line.split()[1:]))
            idle = parts[3] + parts[4] if len(parts) > 4 else 0
            return sum(parts), idle
        except Exception:
            return None

    @staticmethod
    def _mem_pct():
        try:
            mem = {}
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    parts = line.split()
                    if not parts:
                        continue
                    if parts[0] in ("MemTotal:", "MemAvailable:"):
                        mem[parts[0]] = int(parts[1]) * 1024
            total = mem.get("MemTotal:", 0)
            available = mem.get("MemAvailable:", total)
            if not total:
                return 0.0
            return round((total - available) * 100.0 / total, 1)
        except Exception:
            return 0.0

    def _tick(self):
        now = time.time()
        cpu = self._cpu_times()
        if cpu is not None:
            if self.last_cpu is not None:
                dt_total = cpu[0] - self.last_cpu[0]
                dt_idle = cpu[1] - self.last_cpu[1]
                if dt_total > 0:
                    self.cpu_pct = round(
                        max(0.0, min(100.0, (1 - dt_idle / dt_total) * 100.0)), 1
                    )
            self.last_cpu = cpu
        with self.lock:
            self.history.append([now, self.cpu_pct, self._mem_pct()])

    def start(self):
        if self.running:
            return
        self.running = True
        self._tick()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.running:
            time.sleep(self.interval)
            self._tick()

    def snapshot(self):
        with self.lock:
            return {
                "cpu_pct": self.cpu_pct,
                "history": [list(h) for h in self.history],
            }


_SYSTEM = None
_SYSTEM_LOCK = threading.Lock()


def get_system_monitor():
    global _SYSTEM
    with _SYSTEM_LOCK:
        if _SYSTEM is None:
            _SYSTEM = SystemMonitor()
            _SYSTEM.start()
        return _SYSTEM


LATENCY_TARGET = "75.75.75.75"
LATENCY_WINDOW = 48 * 3600
LATENCY_HISTORY_FILE = "/var/lib/tuxwall/latency_history.jsonl"

_LATENCY = None
_LATENCY_LOCK = threading.Lock()


class LatencyMonitor:
    """Continuously pings an external target to track WAN latency, loss and jitter."""

    def __init__(self, target=LATENCY_TARGET, window=LATENCY_WINDOW):
        self.target = target
        self.max_samples = max(60, int(window / 10))
        self.lock = threading.Lock()
        self.history = deque(maxlen=self.max_samples)
        self.running = False
        self.thread = None
        self._load_history()

    def _load_history(self):
        try:
            cutoff = time.time() - LATENCY_WINDOW
            with open(LATENCY_HISTORY_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("ts", 0) >= cutoff:
                        self.history.append(
                            (rec["ts"], rec["avg"], rec["max"], rec["loss"], rec.get("mdev", 0.0))
                        )
        except OSError:
            pass

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.running:
            sample = self._ping_batch()
            if sample:
                with self.lock:
                    self.history.append(sample)
                self._append_history(sample)
            time.sleep(5)

    def _ping_batch(self):
        try:
            proc = subprocess.run(
                ["ping", "-n", "-q", "-i", "0.5", "-c", "12", "-w", "9", self.target],
                capture_output=True, text=True, timeout=12,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        loss = None
        rtt = {}
        for line in proc.stdout.splitlines():
            ls = line.strip()
            m = re.search(r"([\d.]+)% packet loss", ls)
            if m:
                loss = float(m.group(1))
            m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", ls)
            if m:
                rtt = {
                    "min": float(m.group(1)),
                    "avg": float(m.group(2)),
                    "max": float(m.group(3)),
                    "mdev": float(m.group(4)),
                }
        if loss is None:
            return None
        if not rtt:
            return (time.time(), 0.0, 0.0, 100.0, 0.0)
        return (
            time.time(),
            round(rtt["avg"], 2),
            round(rtt["max"], 2),
            loss,
            round(rtt["mdev"], 2),
        )

    def _append_history(self, sample):
        try:
            os.makedirs(os.path.dirname(LATENCY_HISTORY_FILE), exist_ok=True)
            ts, avg, mx, loss, mdev = sample
            with open(LATENCY_HISTORY_FILE, "a") as f:
                f.write(
                    json.dumps({"ts": ts, "avg": avg, "max": mx, "loss": loss, "mdev": mdev}) + "\n"
                )
        except OSError:
            pass

    def stats(self):
        with self.lock:
            hist = list(self.history)
        now = time.time()
        recent_1h = [s for s in hist if s[0] >= now - 3600]
        recent_10m = [s for s in hist if s[0] >= now - 600]
        day_avgs = sorted(s[1] for s in hist if s[1] > 0)
        latest = hist[-1] if hist else None
        peak_1h = max((s[2] for s in recent_1h), default=0.0)
        loss_vals = [s[3] for s in recent_1h]
        jitter_vals = [s[4] for s in recent_10m if s[4] > 0]
        baseline = None
        if day_avgs:
            mid = len(day_avgs) // 2
            baseline = (
                day_avgs[mid]
                if len(day_avgs) % 2
                else round((day_avgs[mid - 1] + day_avgs[mid]) / 2, 2)
            )
        return {
            "target": self.target,
            "current_ms": latest[1] if latest else None,
            "current_max_ms": latest[2] if latest else None,
            "peak_1h_ms": peak_1h,
            "loss_1h_pct": round(sum(loss_vals) / len(loss_vals), 2) if loss_vals else None,
            "jitter_ms": round(sum(jitter_vals) / len(jitter_vals), 2) if jitter_vals else None,
            "baseline_ms": baseline,
            "samples": len(hist),
        }

    def history_series(self, hours=24, max_points=720):
        """Return [ts, avg_ms, max_ms, jitter_mdev] points for a chart window."""
        with self.lock:
            hist = list(self.history)
        cutoff = time.time() - hours * 3600
        pts = [s for s in hist if s[0] >= cutoff]
        if len(pts) <= max_points:
            return [[s[0], s[1], s[2], s[4]] for s in pts]
        step = len(pts) / max_points
        out = []
        i = 0.0
        while i < len(pts):
            chunk = pts[int(i) : int(i + step)] or [pts[int(i)]]
            mvals = [c[4] for c in chunk if c[4] > 0]
            out.append([
                chunk[-1][0],
                chunk[-1][1],
                max(c[2] for c in chunk),
                round(sum(mvals) / len(mvals), 2) if mvals else 0.0,
            ])
            i += step
        return out


def get_latency_monitor():
    global _LATENCY
    with _LATENCY_LOCK:
        if _LATENCY is None:
            _LATENCY = LatencyMonitor()
            _LATENCY.start()
        return _LATENCY


UI_CONF_FILE = "/etc/tuxwall/ui.json"
THEMES_DIR = "/var/www/html/themes"

# ---- Web authentication ----
AUTH_FILE = "/etc/tuxwall/auth.json"
SESSION_COOKIE = "tuxwall_session"
SESSION_TTL = 12 * 3600
PBKDF2_ITERATIONS = 200000
MIN_PASSWORD_LEN = 8
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "tuxwall"

_sessions = {}
_sessions_lock = threading.Lock()
_login_fails = {}


USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")
FULLNAME_RE = re.compile(r"^[^\x00-\x1f<>\"'/\\{}$]{0,64}$")


def _hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS
    ).hex()


def _migrate_legacy_record(data):
    """Convert single-user auth.json (pre-multi-user) to the users-list format."""
    if not (isinstance(data, dict) and data.get("salt") and data.get("hash") and data.get("username")):
        return False
    legacy = {
        "username": data["username"],
        "salt": data["salt"],
        "hash": data["hash"],
        "created": data.get("created", int(time.time())),
        "role": "admin",
        "owner": True,
    }
    if data.get("default_password"):
        legacy["default_password"] = True
    _save_users([legacy])
    return True


def _load_users():
    try:
        with open(AUTH_FILE, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    if isinstance(data, dict) and isinstance(data.get("users"), list):
        return [u for u in data["users"] if isinstance(u, dict) and u.get("username") and u.get("hash")]
    if _migrate_legacy_record(data):
        return _load_users()
    return []


def _save_users(users):
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"users": users}, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_FILE)


def _new_user(username, password, role, owner=False, is_default=False, fullname=""):
    record = {
        "username": username,
        "salt": secrets.token_bytes(32).hex(),
        "created": int(time.time()),
        "role": role,
        "owner": bool(owner),
        "fullname": fullname or "",
    }
    if is_default:
        record["default_password"] = True
    record["hash"] = _hash_password(password, record["salt"])
    return record


def _find_user(users, username):
    for u in users:
        if u["username"] == username:
            return u
    return None


def _ensure_default_auth():
    if _load_users():
        return
    try:
        _save_users([
            _new_user(DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASSWORD, "admin", owner=True, is_default=True)
        ])
    except OSError:
        pass


def _create_session(username, role):
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _sessions_lock:
        for t in [t for t, s in _sessions.items() if s["exp"] < now]:
            del _sessions[t]
        _sessions[token] = {"exp": now + SESSION_TTL, "username": username, "role": role}
    return token


def _revoke_user_sessions(username):
    with _sessions_lock:
        for t in [t for t, s in _sessions.items() if s.get("username") == username]:
            del _sessions[t]


def _cookie_token(headers):
    raw = headers.get("Cookie") or ""
    for part in raw.split(";"):
        name, _, value = part.strip().partition("=")
        if name == SESSION_COOKIE:
            return value.strip()
    return None


def _session_identity(headers):
    """Return {username, role, owner} for a live session, else None.

    Re-checks the user list on every call so deleted users and changed
    roles take effect immediately without waiting for session expiry.
    """
    token = _cookie_token(headers)
    if not token:
        return None
    now = time.time()
    with _sessions_lock:
        sess = _sessions.get(token)
        if sess is None or sess["exp"] < now:
            _sessions.pop(token, None)
            return None
        username = sess["username"]
        sess["exp"] = now + SESSION_TTL
    users = _load_users()
    user = _find_user(users, username)
    if user is None or user.get("disabled"):
        with _sessions_lock:
            _sessions.pop(token, None)
        return None
    return {
        "username": user["username"],
        "role": user.get("role", "viewer"),
        "owner": bool(user.get("owner")),
    }


def _valid_session(headers):
    return _session_identity(headers) is not None


def _drop_session(headers):
    token = _cookie_token(headers)
    if token:
        with _sessions_lock:
            _sessions.pop(token, None)


def _client_key(handler):
    real = handler.headers.get("X-Real-IP")
    return real.strip() if real else handler.client_address[0]


def _login_lock_remaining(ip):
    entry = _login_fails.get(ip)
    if not entry:
        return 0
    _, locked_until = entry
    if locked_until <= time.time():
        return 0
    return int(locked_until - time.time()) + 1


def _record_login_failure(ip):
    count, _ = _login_fails.get(ip, (0, 0.0))
    count += 1
    lockout = min(30 * (2 ** max(0, count - 5)), 900) if count >= 5 else 0
    _login_fails[ip] = (count, time.time() + lockout)


def _clear_login_failures(ip):
    _login_fails.pop(ip, None)


# ---- TOTP two-factor authentication ----
TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1


def _totp_code(secret_b32, step):
    """RFC 6238 code (SHA-1, 6 digits) for a given 30s timestep."""
    key = base64.b32decode(secret_b32, casefold=True)
    digest = hmac.new(key, step.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0xF
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def _totp_match(secret_b32, code, last_step=None):
    """Return the timestep matching a valid 6-digit code, else None.

    Accepts the previous/current/next step (authenticator clock skew) but
    never a step at or before `last_step`, so a used code cannot be replayed.
    """
    if not secret_b32 or not re.fullmatch(r"\d{6}", str(code or "")):
        return None
    now_step = int(time.time()) // TOTP_STEP
    for step in (now_step, now_step - TOTP_WINDOW, now_step + TOTP_WINDOW):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(_totp_code(secret_b32, step), code):
            return step
    return None


def _totp_uri(username, secret_b32):
    label = urllib.parse.quote("TuxWall:" + username)
    return "otpauth://totp/{}?secret={}&issuer=TuxWall&algorithm=SHA1&digits={}&period={}".format(
        label, secret_b32, TOTP_DIGITS, TOTP_STEP
    )


def validate_password_strength(password):
    password = str(password or "")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError("Password must be at least {} characters".format(MIN_PASSWORD_LEN))
    if len(password) > 256:
        raise ValueError("Password too long")
    return password


def _can_manage_users(users, me):
    if me is None or me.get("disabled"):
        return False
    if me.get("owner"):
        return True
    if me.get("role") != "admin":
        return False
    return not any(u.get("owner") and not u.get("disabled") for u in users)


def auth_session_state(identity=None):
    _ensure_default_auth()
    users = _load_users()
    me = _find_user(users, identity["username"]) if identity else None
    state = {
        "ok": True,
        "authenticated": me is not None,
        "username": me["username"] if me else "",
        "role": (me.get("role", "viewer") if me else ""),
        "is_owner": bool(me and me.get("owner")),
        "can_manage_users": _can_manage_users(users, me),
        "setup_required": not users,
        "default_password": bool(me and me.get("default_password")),
        "totp_enabled": bool(me and me.get("totp_secret")),
    }
    active = load_ui_conf().get("active_theme", "dark")
    theme = None
    for t in list_themes()["themes"]:
        if t["id"] == active:
            theme = {"id": t["id"], "name": t["name"], "dark": t["dark"], "colors": t["colors"]}
            break
    state["active_theme"] = theme or {
        "id": "dark", "name": "Dark", "dark": True,
        "colors": {k: v for k, v in BUILTIN_THEMES[0]["colors"].items()},
    }
    _uc = load_ui_conf()
    state["router_lat"] = _uc.get("router_lat")
    state["router_lon"] = _uc.get("router_lon")
    return state


def attempt_login(body, ip):
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")

    _ensure_default_auth()

    remaining = _login_lock_remaining(ip)
    if remaining > 0:
        raise PermissionError("Too many failed attempts. Try again in {}s".format(remaining))

    users = _load_users()
    user = _find_user(users, username)
    if user is None or not hmac.compare_digest(
        _hash_password(password, user["salt"]), user["hash"]
    ):
        _record_login_failure(ip)
        remaining = _login_lock_remaining(ip)
        hint = " Invalid credentials."
        if remaining:
            hint += " Locked for {}s.".format(remaining)
        raise PermissionError(hint.strip())
    if user.get("disabled"):
        raise PermissionError("This account is disabled")

    secret = user.get("totp_secret")
    if secret:
        matched = _totp_match(secret, body.get("totp_code"), user.get("totp_last_step"))
        if matched is None:
            if not str(body.get("totp_code") or "").strip():
                # Password is correct: ask the client for the second factor.
                return {"ok": True, "totp_required": True}
            _record_login_failure(ip)
            remaining = _login_lock_remaining(ip)
            hint = " Invalid verification code."
            if remaining:
                hint += " Locked for {}s.".format(remaining)
            raise PermissionError(hint.strip())
        user["totp_last_step"] = matched
        try:
            _save_users(users)  # persist replay guard
        except OSError:
            pass  # best-effort; do not block login on a failed write

    _clear_login_failures(ip)
    return {
        "ok": True,
        "username": user["username"],
        "role": user.get("role", "viewer"),
        "is_owner": bool(user.get("owner")),
        "can_manage_users": _can_manage_users(_load_users(), user),
        "default_password": bool(user.get("default_password")),
        "totp_enabled": bool(user.get("totp_secret")),
    }


def change_password(body, identity):
    if not identity:
        raise PermissionError("Authentication required")
    users = _load_users()
    user = _find_user(users, identity["username"])
    if user is None:
        raise PermissionError("Account no longer exists")
    current = str(body.get("current") or "")
    new = validate_password_strength(body.get("new"))
    if not hmac.compare_digest(_hash_password(current, user["salt"]), user["hash"]):
        raise PermissionError("Current password is incorrect")
    user["salt"] = secrets.token_bytes(32).hex()
    user["hash"] = _hash_password(new, user["salt"])
    user.pop("default_password", None)
    _save_users(users)
    return {"ok": True}


def totp_setup(identity):
    """Start enrollment: store a pending secret, return it with an otpauth URI."""
    if not identity:
        raise PermissionError("Authentication required")
    users = _load_users()
    user = _find_user(users, identity["username"])
    if user is None:
        raise PermissionError("Account no longer exists")
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    user["totp_pending_secret"] = secret
    try:
        _save_users(users)
    except OSError as exc:
        raise PermissionError("Could not write auth config: %s" % exc.strerror)
    return {"ok": True, "secret": secret, "uri": _totp_uri(user["username"], secret)}


def totp_confirm(body, identity):
    """Finish enrollment: verify a code against the pending secret and activate."""
    if not identity:
        raise PermissionError("Authentication required")
    users = _load_users()
    user = _find_user(users, identity["username"])
    if user is None:
        raise PermissionError("Account no longer exists")
    pending = user.get("totp_pending_secret")
    if not pending:
        raise PermissionError("No enrollment in progress - start setup again")
    matched = _totp_match(pending, body.get("code"))
    if matched is None:
        raise PermissionError("Invalid verification code")
    user["totp_secret"] = user.pop("totp_pending_secret")
    user["totp_last_step"] = matched
    try:
        _save_users(users)
    except OSError as exc:
        raise PermissionError("Could not save the 2FA secret: %s" % exc.strerror)
    return {"ok": True, "totp_enabled": True}


def totp_disable(body, identity):
    """Turn off 2FA: requires the current password, plus a code if enrolled."""
    if not identity:
        raise PermissionError("Authentication required")
    users = _load_users()
    user = _find_user(users, identity["username"])
    if user is None:
        raise PermissionError("Account no longer exists")
    current = str(body.get("current") or "")
    if not hmac.compare_digest(_hash_password(current, user["salt"]), user["hash"]):
        raise PermissionError("Current password is incorrect")
    if user.get("totp_secret") and \
            _totp_match(user["totp_secret"], body.get("code"), user.get("totp_last_step")) is None:
        raise PermissionError("Invalid verification code")
    user.pop("totp_secret", None)
    user.pop("totp_pending_secret", None)
    user.pop("totp_last_step", None)
    try:
        _save_users(users)
    except OSError as exc:
        raise PermissionError("Could not save: %s" % exc.strerror)
    return {"ok": True, "totp_enabled": False}


def _require_owner(identity):
    if not identity:
        raise PermissionError("Authentication required")
    users = _load_users()
    me = _find_user(users, identity["username"])
    if me is None:
        raise PermissionError("Account no longer exists")
    if not me.get("owner"):
        # Fail-open only when the primary admin is disabled or gone:
        # then any enabled admin can manage users (e.g. re-enable the owner).
        owner_active = any(u.get("owner") and not u.get("disabled") for u in users)
        if owner_active or me.get("role") != "admin":
            raise PermissionError("Only the primary administrator can manage users")
    return users


def list_users(identity):
    users = _require_owner(identity)
    return {
        "ok": True,
        "users": [
            {
                "username": u["username"],
                "role": u.get("role", "viewer"),
                "owner": bool(u.get("owner")),
                "disabled": bool(u.get("disabled")),
                "fullname": u.get("fullname", ""),
                "created": u.get("created"),
                "totp": bool(u.get("totp_secret")),
            }
            for u in users
        ],
    }


def _validate_fullname(fullname):
    fullname = str(fullname or "").strip()
    if not FULLNAME_RE.match(fullname):
        raise ValueError("Full name must be 0-64 characters (no angle brackets or quotes)")
    return fullname


def add_user(body, identity):
    users = _require_owner(identity)
    username = str(body.get("username") or "").strip()
    if not USERNAME_RE.match(username):
        raise ValueError("Username must be 1-32 characters: letters, digits, dot, dash, underscore")
    if _find_user(users, username):
        raise ValueError("That username already exists")
    password = validate_password_strength(body.get("password"))
    fullname = _validate_fullname(body.get("fullname"))
    role = body.get("role") or "viewer"
    if role not in ("admin", "viewer"):
        raise ValueError("Role must be admin or viewer")
    users.append(_new_user(username, password, role, fullname=fullname))
    if body.get("enabled") is False:
        users[-1]["disabled"] = True
    _save_users(users)
    return {"ok": True}


def update_user(body, identity):
    users = _require_owner(identity)
    username = str(body.get("username") or "")
    user = _find_user(users, username)
    if user is None:
        raise ValueError("No such user")
    changed = {}
    if "fullname" in body:
        user["fullname"] = changed["fullname"] = _validate_fullname(body.get("fullname"))
    if "password" in body and str(body.get("password") or ""):
        new = validate_password_strength(body.get("password"))
        user["salt"] = secrets.token_bytes(32).hex()
        user["hash"] = _hash_password(new, user["salt"])
        user.pop("default_password", None)
        changed["password"] = True
    if "role" in body:
        role = body.get("role")
        if role not in ("admin", "viewer"):
            raise ValueError("Role must be admin or viewer")
        if user.get("owner") and role != "admin":
            raise PermissionError("The primary administrator must keep the admin role")
        user["role"] = changed["role"] = role
    if "enabled" in body:
        enabled = bool(body.get("enabled"))
        if not enabled:
            _check_disable_allowed(users, user)
            user["disabled"] = True
        else:
            user.pop("disabled", None)
        changed["enabled"] = enabled
    if not changed:
        raise ValueError("Nothing to update")
    _save_users(users)
    if user.get("disabled"):
        _revoke_user_sessions(username)
    changed["ok"] = True
    changed["username"] = username
    return changed


def delete_user(body, identity):
    users = _require_owner(identity)
    username = str(body.get("username") or "")
    user = _find_user(users, username)
    if user is None:
        raise ValueError("No such user")
    if user.get("owner"):
        raise PermissionError("The primary administrator account cannot be removed")
    users.remove(user)
    _save_users(users)
    _revoke_user_sessions(username)
    return {"ok": True}


def _other_enabled_admins(users, username):
    return [
        u for u in users
        if u["username"] != username and not u.get("disabled") and u.get("role") == "admin"
    ]


def _check_disable_allowed(users, user):
    """Prevent disabling the last enabled administrator (would lock everyone out)."""
    if not user.get("disabled") and (user.get("owner") or user.get("role") == "admin"):
        if not _other_enabled_admins(users, user["username"]):
            raise PermissionError(
                "At least one other enabled admin account must exist before disabling this one"
            )


def set_user_enabled(body, identity):
    users = _require_owner(identity)
    username = str(body.get("username") or "")
    user = _find_user(users, username)
    if user is None:
        raise ValueError("No such user")
    enabled = bool(body.get("enabled"))
    if not enabled:
        _check_disable_allowed(users, user)
        user["disabled"] = True
    else:
        user.pop("disabled", None)
    _save_users(users)
    if not enabled:
        _revoke_user_sessions(username)
    return {"ok": True, "username": username, "enabled": enabled}


def reset_user_password(body, identity):
    users = _require_owner(identity)
    username = str(body.get("username") or "")
    user = _find_user(users, username)
    if user is None:
        raise ValueError("No such user")
    new = validate_password_strength(body.get("password"))
    user["salt"] = secrets.token_bytes(32).hex()
    user["hash"] = _hash_password(new, user["salt"])
    user.pop("default_password", None)
    _save_users(users)
    _revoke_user_sessions(username)
    return {"ok": True}

THEME_COLOR_KEYS = ("bg", "bg-elev", "card", "border", "text", "muted", "accent", "green", "red", "amber")
HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
THEME_NAME_RE = re.compile(r"^[^<>\"'/\\{}$]{1,40}$")

BUILTIN_THEMES = [
    {
        "id": "dark", "name": "Dark", "builtin": True, "dark": True,
        "colors": {
            "bg": "#0f1419", "bg-elev": "#161b22", "card": "#1c2333",
            "border": "#2d333b", "text": "#e6edf3", "muted": "#8b949e",
            "accent": "#4f8cff", "green": "#3fb950", "red": "#f85149",
            "amber": "#d29922",
        },
    },
    {
        "id": "light", "name": "Light", "builtin": True, "dark": False,
        "colors": {
            "bg": "#f6f8fa", "bg-elev": "#ffffff", "card": "#ffffff",
            "border": "#d0d7de", "text": "#1f2328", "muted": "#59636e",
            "accent": "#0969da", "green": "#1a7f37", "red": "#cf222e",
            "amber": "#9a6700",
        },
    },
    {
        "id": "nord", "name": "Nord", "builtin": True, "dark": True,
        "colors": {
            "bg": "#2e3440", "bg-elev": "#3b4252", "card": "#3b4252",
            "border": "#4c566a", "text": "#eceff4", "muted": "#a7b1c2",
            "accent": "#88c0d0", "green": "#a3be8c", "red": "#bf616a",
            "amber": "#ebcb8b",
        },
    },
    {
        "id": "dracula", "name": "Dracula", "builtin": True, "dark": True,
        "colors": {
            "bg": "#282a36", "bg-elev": "#21222c", "card": "#2f3141",
            "border": "#44475a", "text": "#f8f8f2", "muted": "#a4a8bc",
            "accent": "#bd93f9", "green": "#50fa7b", "red": "#ff5555",
            "amber": "#ffb86c",
        },
    },
    {
        "id": "gruvbox", "name": "Gruvbox Dark", "builtin": True, "dark": True,
        "colors": {
            "bg": "#282828", "bg-elev": "#1d2021", "card": "#32302f",
            "border": "#504945", "text": "#ebdbb2", "muted": "#a89984",
            "accent": "#fe8019", "green": "#b8bb26", "red": "#fb4934",
            "amber": "#fabd2f",
        },
    },
    {
        "id": "solarized-light", "name": "Solarized Light", "builtin": True, "dark": False,
        "colors": {
            "bg": "#eee8d5", "bg-elev": "#fdf6e3", "card": "#fdf6e3",
            "border": "#dcd4ba", "text": "#073642", "muted": "#657b83",
            "accent": "#268bd2", "green": "#859900", "red": "#dc322f",
            "amber": "#b58900",
        },
    },
    {
        "id": "tokyo-night", "name": "Tokyo Night", "builtin": True, "dark": True,
        "colors": {
            "bg": "#1a1b2e", "bg-elev": "#16213e", "card": "#1f2b47",
            "border": "#2a3a5c", "text": "#c0caf5", "muted": "#565f89",
            "accent": "#7aa2f7", "green": "#9ece6a", "red": "#f7768e",
            "amber": "#e0af68",
        },
    },
    {
        "id": "catppuccin", "name": "Catppuccin Mocha", "builtin": True, "dark": True,
        "colors": {
            "bg": "#1e1e2e", "bg-elev": "#181825", "card": "#313244",
            "border": "#45475a", "text": "#cdd6f4", "muted": "#6c7086",
            "accent": "#89b4fa", "green": "#a6e3a1", "red": "#f38ba8",
            "amber": "#fab387",
        },
    },
    {
        "id": "cyberpunk", "name": "Cyberpunk", "builtin": True, "dark": True,
        "colors": {
            "bg": "#0d0d1a", "bg-elev": "#12122b", "card": "#1a1a3e",
            "border": "#2a2a60", "text": "#e8e8ff", "muted": "#7a7aaa",
            "accent": "#00f5ff", "green": "#39ff14", "red": "#ff0055",
            "amber": "#ffcc00",
        },
    },
    {
        "id": "emerald", "name": "Emerald Dark", "builtin": True, "dark": True,
        "colors": {
            "bg": "#0d1a14", "bg-elev": "#121f19", "card": "#1a2e22",
            "border": "#274031", "text": "#d4f0dc", "muted": "#6a9e7a",
            "accent": "#34d475", "green": "#22c55e", "red": "#f56565",
            "amber": "#f6ad55",
        },
    },
    {
        "id": "rose-pine", "name": "Rosé Pine", "builtin": True, "dark": True,
        "colors": {
            "bg": "#191724", "bg-elev": "#1f1d2e", "card": "#26233a",
            "border": "#393552", "text": "#e0def4", "muted": "#6e6a86",
            "accent": "#c4a7e7", "green": "#9ccfd8", "red": "#eb6f92",
            "amber": "#f6c177",
        },
    },
    {
        "id": "midnight", "name": "Midnight Glass", "builtin": True, "dark": True,
        "colors": {
            "bg": "#080c14", "bg-elev": "#0e1521", "card": "#111c2e",
            "border": "#1e2d47", "text": "#dce8f8", "muted": "#5a7499",
            "accent": "#60a5fa", "green": "#34d399", "red": "#f87171",
            "amber": "#fbbf24",
        },
    },
]


def load_ui_conf():
    try:
        with open(UI_CONF_FILE, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_ui_conf(data):
    os.makedirs(os.path.dirname(UI_CONF_FILE), exist_ok=True)
    tmp = UI_CONF_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, UI_CONF_FILE)


def _custom_theme_files():
    try:
        names = os.listdir(THEMES_DIR)
    except OSError:
        return []
    out = []
    for name in names:
        if not name.endswith(".json"):
            continue
        base = name[:-5]
        if not re.match(r"^[a-z0-9][a-z0-9-]{0,47}$", base):
            continue
        try:
            with open(os.path.join(THEMES_DIR, name), "r") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        colors = data.get("colors")
        if not isinstance(colors, dict):
            continue
        entry = {
            "id": base,
            "name": str(data.get("name") or base)[:40],
            "builtin": False,
            "dark": bool(data.get("dark", True)),
            "colors": {k: str(colors.get(k, "")) for k in THEME_COLOR_KEYS},
        }
        out.append(entry)
    out.sort(key=lambda t: t["name"].lower())
    return out


def _find_builtin_theme(theme_id):
    for t in BUILTIN_THEMES:
        if t["id"] == theme_id:
            return dict(t)
    return None


def list_themes():
    themes = [_find_builtin_theme(t["id"]) for t in BUILTIN_THEMES]
    themes += _custom_theme_files()
    active = load_ui_conf().get("active_theme", "dark")
    if active != "dark" and not any(t["id"] == active for t in themes):
        active = "dark"
    return {"ok": True, "active": active, "themes": themes}


def validate_theme_payload(body):
    name = str(body.get("name") or "").strip()
    if not name:
        raise ValueError("Theme name is required")
    if not THEME_NAME_RE.match(name):
        raise ValueError("Theme name contains invalid characters")
    colors = body.get("colors")
    if not isinstance(colors, dict):
        raise ValueError("colors object is required")
    clean = {}
    for key in THEME_COLOR_KEYS:
        val = str(colors.get(key) or "").strip()
        if not HEX_COLOR_RE.match(val):
            raise ValueError("Invalid or missing color '{}' (use #rrggbb)".format(key))
        clean[key] = val.lower()
    dark = bool(body.get("dark", True))
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:32] or "custom"
    return {"name": name, "dark": dark, "colors": clean, "slug": slug}


def save_custom_theme(payload):
    if _find_builtin_theme(payload["slug"]):
        raise FileExistsError("'{}' is a built-in theme name".format(payload["name"]))
    os.makedirs(THEMES_DIR, exist_ok=True)
    path = os.path.join(THEMES_DIR, payload["slug"] + ".json")
    if os.path.exists(path):
        raise FileExistsError("A theme named '{}' already exists".format(payload["name"]))
    record = {"name": payload["name"], "dark": payload["dark"], "colors": payload["colors"]}
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(record, f, indent=2)
    os.replace(tmp, path)
    return {
        "id": payload["slug"],
        "name": payload["name"],
        "builtin": False,
        "dark": payload["dark"],
        "colors": payload["colors"],
    }


def delete_custom_theme(theme_id):
    base = str(theme_id or "")
    if not re.match(r"^[a-z0-9][a-z0-9-]{0,47}$", base):
        raise ValueError("Invalid theme id")
    path = os.path.join(THEMES_DIR, base + ".json")
    if not os.path.isfile(path):
        raise ValueError("Custom theme not found")
    os.remove(path)
    conf = load_ui_conf()
    if conf.get("active_theme") == base:
        conf["active_theme"] = "dark"
        save_ui_conf(conf)
    return {"ok": True, "deleted": base}


def set_active_theme(theme_id):
    theme_id = str(theme_id or "")
    known = _find_builtin_theme(theme_id) is not None
    if not known:
        known = os.path.isfile(os.path.join(THEMES_DIR, theme_id + ".json"))
    if not known:
        raise ValueError("Unknown theme '{}'".format(theme_id))
    conf = load_ui_conf()
    conf["active_theme"] = theme_id
    save_ui_conf(conf)
    return {"ok": True, "active": theme_id}


def set_router_location(lat, lon):
    """Persist the router (home/target) location used by the attack map."""
    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        raise ValueError("Latitude and longitude must be numbers.")
    if not -90.0 <= lat <= 90.0:
        raise ValueError("Latitude must be between -90 and 90.")
    if not -180.0 <= lon <= 180.0:
        raise ValueError("Longitude must be between -180 and 180.")
    conf = load_ui_conf()
    conf["router_lat"] = lat
    conf["router_lon"] = lon
    save_ui_conf(conf)
    return {"ok": True, "lat": lat, "lon": lon}


BASELINES_FILE = "/etc/tuxwall/baselines.json"

def load_baselines():
    try:
        with open(BASELINES_FILE, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

def save_baselines(data):
    allowed_keys = {"retransBaseline", "cakeDropsBaseline", "cakeOverlimitsBaseline"}
    filtered = {k: int(v) for k, v in data.items() if k in allowed_keys}
    with open(BASELINES_FILE, "w") as f:
        json.dump(filtered, f, indent=2)


def build_system():
    def read(path, default=""):
        try:
            with open(path, "r") as f:
                return f.read().strip()
        except OSError:
            return default

    os_info = {}
    for line in read("/etc/os-release").splitlines():
        key, _, value = line.partition("=")
        if key:
            os_info[key] = value.strip('"')

    uname = os.uname()

    uptime = 0.0
    try:
        uptime = float(read("/proc/uptime").split()[0])
    except (ValueError, IndexError):
        pass

    cpu_model = ""
    cpu_cores = 0
    for line in read("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
        elif line.startswith("processor"):
            cpu_cores += 1

    mem = {"total": 0, "available": 0, "used": 0}
    swap = {"total": 0, "free": 0, "used": 0}
    for line in read("/proc/meminfo").splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "MemTotal:":
            mem["total"] = int(parts[1]) * 1024
        elif parts[0] == "MemAvailable:":
            mem["available"] = int(parts[1]) * 1024
        elif parts[0] == "SwapTotal:":
            swap["total"] = int(parts[1]) * 1024
        elif parts[0] == "SwapFree:":
            swap["free"] = int(parts[1]) * 1024
    mem["used"] = mem["total"] - mem["available"]
    swap["used"] = swap["total"] - swap["free"]

    disk = {}
    try:
        proc = subprocess.run(["df", "-B1", "/"], capture_output=True, text=True, timeout=5)
        parts = proc.stdout.splitlines()[1].split()
        disk = {
            "fs": parts[0],
            "total": int(parts[1]),
            "used": int(parts[2]),
            "avail": int(parts[3]),
            "mount": parts[5],
        }
    except Exception:
        pass

    interfaces = []
    try:
        proc = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=5)
        for iface in json.loads(proc.stdout):
            if iface.get("ifname") == "lo":
                continue
            addrs = [
                {"family": a.get("family"), "addr": a.get("local"), "mask": a.get("prefixlen")}
                for a in iface.get("addr_info", [])
                if a.get("family") in ("inet", "inet6")
            ]
            addrs.sort(key=lambda x: x["family"] != "inet")
            flags = iface.get("flags", [])
            state = iface.get("operstate")
            if state == "UNKNOWN" and "UP" in flags:
                state = "UP"
            interfaces.append({
                "name": iface.get("ifname"),
                "state": state,
                "mac": iface.get("address", ""),
                "addrs": addrs,
            })
    except Exception:
        pass

    dhcp = {"subnet": "", "pools": [], "router": "", "dns": "", "domain": ""}
    try:
        with open("/etc/kea/kea-dhcp4.conf", "r") as f:
            kea = json.load(f)
        d4 = kea.get("Dhcp4", {})
        opts = {}
        for o in d4.get("option-data", []):
            opts[o.get("name")] = o.get("data")
        for subnet in d4.get("subnet4", []):
            dhcp["subnet"] = subnet.get("subnet", "")
            dhcp["pools"] = [p.get("pool", "") for p in subnet.get("pools", [])]
            for o in subnet.get("option-data", []):
                opts.setdefault(o.get("name"), o.get("data"))
        dhcp["router"] = opts.get("routers", "")
        dhcp["dns"] = opts.get("domain-name-servers", "")
        dhcp["domain"] = opts.get("domain-name", "")
    except (OSError, ValueError):
        pass

    dns = {"interfaces": [], "port": 53}
    for path in ("/etc/unbound/unbound.conf.d/router-dns.conf", "/etc/unbound/unbound.conf"):
        try:
            text = read(path)
        except Exception:
            continue
        for line in text.splitlines():
            ls = line.strip()
            if ls.startswith("interface:"):
                dns["interfaces"].append(ls.split(":", 1)[1].strip())
            elif ls.startswith("port:"):
                try:
                    dns["port"] = int(ls.split(":", 1)[1].strip())
                except ValueError:
                    pass

    cpu_temp = None
    try:
        for zone in sorted(os.listdir("/sys/class/thermal")):
            if not zone.startswith("thermal_zone"):
                continue
            base = "/sys/class/thermal/" + zone
            ztype = read(base + "/type")
            if "pkg" in ztype or "x86" in ztype or "cpu" in ztype:
                try:
                    cpu_temp = round(int(read(base + "/temp")) / 1000.0, 1)
                except (ValueError, TypeError):
                    pass
                break
    except OSError:
        pass

    try:
        mon = get_system_monitor().snapshot()
    except Exception:
        mon = {"cpu_pct": 0.0, "history": []}

    try:
        latency = get_latency_monitor().stats()
    except Exception:
        latency = {}

    return {
        "ok": True,
        "hostname": uname.nodename,
        "os": os_info.get("PRETTY_NAME", ""),
        "kernel": uname.release,
        "arch": uname.machine,
        "uptime": uptime,
        "load": [round(x, 2) for x in os.getloadavg()],
        "cpu": {"model": cpu_model, "cores": cpu_cores, "temp": cpu_temp},
        "mem": mem,
        "swap": swap,
        "disk": disk,
        "interfaces": interfaces,
        "dhcp": dhcp,
        "dns": dns,
        "latency": latency,
        "usage": {
            "cpu_pct": mon["cpu_pct"],
            "mem_pct": round(mem["used"] * 100.0 / mem["total"], 1) if mem["total"] else 0.0,
            "swap_pct": round(swap["used"] * 100.0 / swap["total"], 1) if swap["total"] else 0.0,
            "disk_pct": round(disk["used"] * 100.0 / disk["total"], 1) if disk.get("total") else 0.0,
            "load": [round(x, 2) for x in os.getloadavg()],
        },
        "history": mon["history"],
    }


HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def set_hostname(name):
    name = (name or "").strip().lower()
    if len(name) > 253 or not HOSTNAME_RE.match(name):
        raise ValueError("Hostname may only contain letters, digits, hyphens and dots")
    proc = subprocess.run(
        ["hostnamectl", "set-hostname", name],
        capture_output=True, text=True, timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "hostnamectl failed").strip())
    return socket.gethostname()


BACKUP_DIR = "/var/lib/tuxwall/backups"
WWW_DIR = "/var/www/html"
SOURCE_DIR = "/var/www/html"
BACKUP_RE = re.compile(r"^[A-Za-z0-9._-]+\.tar\.gz$")
BACKUP_TARGETS = ("index.html", "css", "scripts", "includes", "images")
SOURCE_SYNC = ("index.html", "css/style.css", "scripts/dashboard.js", "includes/api_server.py")


def list_backups():
    try:
        entries = []
        for name in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if not BACKUP_RE.match(name):
                continue
            path = os.path.join(BACKUP_DIR, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            entries.append({
                "name": name,
                "size": st.st_size,
                "time": int(st.st_mtime),
            })
        return {"ok": True, "backups": entries}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "backups": []}


def create_backup():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    name = "tuxwall-backup-" + time.strftime("%Y%m%d-%H%M%S") + ".tar.gz"
    dest = os.path.join(BACKUP_DIR, name)
    with tarfile.open(dest, "w:gz") as tar:
        for entry in BACKUP_TARGETS:
            path = os.path.join(WWW_DIR, entry)
            if os.path.exists(path):
                tar.add(path, arcname=entry)
    st = os.stat(dest)
    return {"ok": True, "backup": {"name": name, "size": st.st_size, "time": int(st.st_mtime)}}


def _tar_member_safe(member):
    if not member.isreg():
        return False
    name = member.name.replace("\\", "/")
    if name.startswith("/") or ".." in name.split("/"):
        return False
    return True


def restore_backup(filename, raw=None):
    if raw is None:
        base = os.path.basename(filename or "")
        if not BACKUP_RE.match(base):
            raise ValueError("Invalid backup name")
        path = os.path.join(BACKUP_DIR, base)
        if not os.path.isfile(path):
            raise ValueError("Backup not found")
    else:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        base = os.path.basename(filename or "") or "tuxwall-restore.tar.gz"
        if not base.endswith(".tar.gz"):
            base += ".tar.gz"
        path = os.path.join(BACKUP_DIR, base)
        with open(path, "wb") as f:
            f.write(raw)

    restored = []
    try:
        tar = tarfile.open(path, "r:gz")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ValueError("Not a valid .tar.gz backup")
    with tar:
        for member in tar.getmembers():
            if not _tar_member_safe(member):
                continue
            top = member.name.split("/", 1)[0]
            if top not in BACKUP_TARGETS:
                continue
            dest = os.path.join(WWW_DIR, member.name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with tar.extractfile(member) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
            restored.append(member.name)

    for rel in SOURCE_SYNC:
        src = os.path.join(WWW_DIR, rel)
        if os.path.isfile(src):
            dst = os.path.join(SOURCE_DIR, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)

    return {
        "restored": sorted(restored),
        "restart_required": "includes/api_server.py" in restored,
    }


def delete_backup(filename):
    base = os.path.basename(filename or "")
    if not BACKUP_RE.match(base):
        raise ValueError("Invalid backup name")
    path = os.path.join(BACKUP_DIR, base)
    if not os.path.isfile(path):
        raise ValueError("Backup not found")
    os.remove(path)
    return {"ok": True, "deleted": base}


SYSTEM_BACKUP_DIR = os.path.join(BACKUP_DIR, "system")
SYSTEM_BACKUP_RE = re.compile(r"^system-backup-\d{8}-\d{6}\.tar\.gz$")
SYSTEM_BACKUP_SCRIPT = "/usr/local/sbin/system-backup.sh"
_system_backup_job = {"running": False, "pct": 0, "step": "", "result": None, "error": None}
_system_backup_lock = threading.Lock()


def _system_backup_worker():
    global _system_backup_job
    try:
        os.makedirs(SYSTEM_BACKUP_DIR, exist_ok=True)
        script = SYSTEM_BACKUP_SCRIPT
        if not os.path.isfile(script):
            raise FileNotFoundError(
                "Backup script missing (%s). Install it: sudo bash ~/tuxwall-blocklist/deploy.sh" % script
            )
        proc = subprocess.Popen(
            [script, "-o", SYSTEM_BACKUP_DIR],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        result = None
        error = None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^PROGRESS\s+(\d+)\s*(.*)$", line)
            if m:
                with _system_backup_lock:
                    _system_backup_job["pct"] = int(m.group(1))
                    _system_backup_job["step"] = m.group(2)
                continue
            m = re.match(r"^RESULT\s+(\S+)$", line)
            if m:
                result = m.group(1)
                continue
        proc.wait()
        if proc.returncode != 0:
            error = "Backup script exited with status %d" % proc.returncode
        with _system_backup_lock:
            _system_backup_job["result"] = result if result and not error else None
            _system_backup_job["error"] = error
    except Exception as exc:
        with _system_backup_lock:
            _system_backup_job["error"] = str(exc)
    finally:
        with _system_backup_lock:
            _system_backup_job["running"] = False
            _system_backup_job["pct"] = 100 if _system_backup_job["error"] else _system_backup_job["pct"]


def create_system_backup():
    with _system_backup_lock:
        if _system_backup_job["running"]:
            raise ValueError("A system backup is already running")
        _system_backup_job.update({"pct": 0, "step": "Starting", "result": None, "error": None, "running": True})
    threading.Thread(target=_system_backup_worker, daemon=True).start()
    return {"ok": True, "running": True}


def system_backup_status():
    with _system_backup_lock:
        return {
            "ok": True,
            "running": _system_backup_job["running"],
            "pct": _system_backup_job["pct"],
            "step": _system_backup_job["step"],
            "result": _system_backup_job["result"],
            "error": _system_backup_job["error"],
            "backups": list_system_backups().get("backups", []),
        }


def list_system_backups():
    try:
        entries = []
        for name in sorted(os.listdir(SYSTEM_BACKUP_DIR), reverse=True):
            if not SYSTEM_BACKUP_RE.match(name):
                continue
            path = os.path.join(SYSTEM_BACKUP_DIR, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            entries.append({"name": name, "size": st.st_size, "time": int(st.st_mtime)})
        return {"ok": True, "backups": entries}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "backups": []}


def delete_system_backup(filename):
    base = os.path.basename(filename or "")
    if not SYSTEM_BACKUP_RE.match(base):
        raise ValueError("Invalid system backup name")
    path = os.path.join(SYSTEM_BACKUP_DIR, base)
    if not os.path.isfile(path):
        raise ValueError("System backup not found")
    os.remove(path)
    return {"ok": True, "deleted": base}


CONFIG_FILES = {
    "kea": {"path": "/etc/kea/kea-dhcp4.conf", "svc": "kea-dhcp4-server"},
    "unbound": {"path": "/etc/unbound/unbound.conf.d/router-dns.conf", "svc": "unbound"},
}


def read_config(kind):
    cfg = CONFIG_FILES.get(kind)
    if not cfg:
        raise ValueError("Unknown config")
    try:
        with open(cfg["path"], "r") as f:
            content = f.read()
    except OSError as exc:
        raise RuntimeError(str(exc))
    return {"path": cfg["path"], "service": cfg["svc"], "content": content}


def write_config(kind, content):
    cfg = CONFIG_FILES.get(kind)
    if not cfg:
        raise ValueError("Unknown config")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Config is empty")
    if len(content) > 262144:
        raise ValueError("Config too large")
    path = cfg["path"]
    bak = path + ".bak-" + time.strftime("%Y%m%d%H%M%S")
    shutil.copy2(path, bak)
    with open(path, "w") as f:
        f.write(content)
    proc = subprocess.run(
        ["systemctl", "restart", cfg["svc"]],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "Failed to restart {}".format(cfg["svc"])).strip())
    return {"path": path, "backup": bak, "service": cfg["svc"]}


# ---- System updates / reboot ----
UPDATE_STATE = {
    "running": False,
    "op": None,
    "percent": 0,
    "phase": "",
    "exit_code": None,
    "log": [],
    "last_check": None,
    "last_check_ok": None,
    "last_upgrade": None,
}
UPDATE_LOCK = threading.Lock()
_UPGRADABLE_CACHE = {"ts": 0, "count": -1}


def _upd_set(**kw):
    with UPDATE_LOCK:
        UPDATE_STATE.update(kw)


def _upd_append(line):
    with UPDATE_LOCK:
        UPDATE_STATE["log"].append(line)
        if len(UPDATE_STATE["log"]) > 300:
            del UPDATE_STATE["log"][:-300]


def _count_upgradable():
    now = time.time()
    if now - _UPGRADABLE_CACHE["ts"] < 30:
        return _UPGRADABLE_CACHE["count"]
    count = -1
    try:
        proc = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=25)
        count = sum(1 for l in proc.stdout.splitlines() if "upgradable" in l)
    except Exception:
        count = -1
    _UPGRADABLE_CACHE.update(ts=now, count=count)
    return count


def _apt_exec(args, pct_start, pct_end):
    env = dict(os.environ)
    env["DEBIAN_FRONTEND"] = "noninteractive"
    proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
        bufsize=1,
    )
    half = (pct_start + pct_end) / 2.0
    for line in proc.stdout:
        line = line.rstrip("\n")
        _upd_append(line)
        pct = None
        m = re.search(r"\((\d+)\s+of\s+(\d+)\)", line)
        if m:
            k, n = int(m.group(1)), int(m.group(2))
            if n > 0:
                pct = pct_start + (pct_end - pct_start) * (0.5 + 0.5 * (k / n))
        elif line.startswith("Get:") or "Preparing to unpack" in line:
            pct = half
        elif "Setting up " in line:
            pct = pct_end - 1
        if pct is not None:
            _upd_set(percent=max(pct_start, min(pct_end, round(pct))))
    code = proc.wait()
    return code


def _apt_worker(op):
    if op == "check":
        _upd_set(running=True, op="check", percent=0, phase="apt update", exit_code=None, log=[])
        code = _apt_exec(["apt-get", "update"], 0, 20)
        if code == 0:
            count = _count_upgradable()
            _upd_set(percent=100, phase="done", exit_code=0, last_check=time.time(), last_check_ok=True)
            _upd_append("Check complete: {} package(s) upgradable.".format(count if count >= 0 else "?"))
        else:
            _upd_set(percent=100, phase="failed", exit_code=code, last_check=time.time(), last_check_ok=False)
        _upd_set(running=False)
    else:
        _upd_set(running=True, op="apply", percent=0, phase="apt update", exit_code=None, log=[])
        code = _apt_exec(["apt-get", "update"], 0, 15)
        if code != 0:
            _upd_set(percent=100, phase="failed (apt update)", exit_code=code)
            _upd_set(running=False)
            return
        _upd_set(phase="apt upgrade")
        code = _apt_exec(
            ["apt-get", "dist-upgrade", "-y", "-o", "Dpkg::Options::=--force-confold"],
            15, 100,
        )
        if code == 0:
            _upd_set(phase="done", exit_code=0, percent=100, last_upgrade=time.time())
            _upd_append("System update complete.")
        else:
            _upd_set(phase="failed", exit_code=code)
        _upd_set(running=False)


def _distro_name():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                k, _, v = line.partition("=")
                if k == "PRETTY_NAME":
                    return v.strip().strip('"')
    except OSError:
        pass
    return "Ubuntu"


def updates_snapshot():
    with UPDATE_LOCK:
        return {
            "ok": True,
            "distro": _distro_name(),
            "running": UPDATE_STATE["running"],
            "op": UPDATE_STATE["op"],
            "percent": UPDATE_STATE["percent"],
            "phase": UPDATE_STATE["phase"],
            "exit_code": UPDATE_STATE["exit_code"],
            "log": list(UPDATE_STATE["log"])[-50:],
            "last_check": UPDATE_STATE["last_check"],
            "last_check_ok": UPDATE_STATE["last_check_ok"],
            "last_upgrade": UPDATE_STATE["last_upgrade"],
            "upgradable": _count_upgradable(),
            "kernel": os.uname().release,
        }


def start_update(op):
    with UPDATE_LOCK:
        if UPDATE_STATE["running"]:
            raise RuntimeError("An update is already in progress")
        UPDATE_STATE["log"] = []
    threading.Thread(target=_apt_worker, args=(op,), daemon=True).start()
    return {"ok": True, "started": op}


def system_reboot():
    subprocess.Popen(["systemctl", "reboot", "--no-block"])
    return {"ok": True, "rebooting": True}


# ---- Server logs ----
LOG_SOURCES = [
    {"id": "system", "name": "System (all journal)"},
    {"id": "tuxwall", "name": "TuxWall API"},
    {"id": "kea-dhcp4", "name": "Kea DHCP"},
    {"id": "unbound", "name": "Unbound DNS"},
    {"id": "nginx", "name": "Nginx"},
    {"id": "crowdsec", "name": "CrowdSec"},
    {"id": "wg0", "name": "WireGuard (wg0)"},
    {"id": "networkd", "name": "systemd-networkd"},
    {"id": "unattended", "name": "Unattended upgrades"},
    {"id": "syslog", "name": "System log (syslog)"},
    {"id": "dmesg", "name": "Kernel ring buffer"},
]

LOG_UNITS = {
    "tuxwall": "tuxwall",
    "kea-dhcp4": "kea-dhcp4-server",
    "unbound": "unbound",
    "nginx": "nginx",
    "crowdsec": "crowdsec",
    "wg0": "wg-quick@wg0",
    "networkd": "systemd-networkd",
    "unattended": "unattended-upgrades",
}

LOG_PRIORITIES = {"err", "warning", "notice", "info", "debug"}


def _tail_file(path, lines):
    try:
        proc = subprocess.run(["tail", "-n", str(lines), path], capture_output=True, text=True, timeout=10)
        return proc.stdout
    except Exception:
        return ""


def tail_log(source, lines, priority):
    if not isinstance(source, str) or not source:
        raise ValueError("Invalid log source")
    if not isinstance(lines, int) or lines < 1:
        lines = 200
    lines = min(lines, 5000)
    if priority and priority not in LOG_PRIORITIES:
        priority = ""

    if source == "syslog":
        path = "/var/log/syslog"
        if not os.path.exists(path):
            path = "/var/log/messages"
        out = _tail_file(path, lines)
    elif source == "dmesg":
        proc = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=10)
        out = "\n".join(proc.stdout.splitlines()[-lines:])
    else:
        args = ["journalctl", "--no-pager"]
        unit = LOG_UNITS.get(source)
        if unit:
            args += ["-u", unit]
        if priority:
            args += ["-p", priority]
        args += ["-n", str(lines)]
        proc = subprocess.run(args, capture_output=True, text=True, timeout=25)
        out = (proc.stdout or proc.stderr or "").strip()

    n = len(out.splitlines()) if out else 0
    return {"ok": True, "source": source, "lines": n, "content": out}


class AgentError(RuntimeError):
    """Error talking to the opencode agent server, with upstream detail."""

    def __init__(self, message, status=0, body=""):
        super().__init__(message)
        self.status = status
        self.body = body


class Handler(BaseHTTPRequestHandler):

    # ── opencode agent proxy ────────────────────────────────────────────
    AGENT_BASE = "http://127.0.0.1:4096"
    AGENT_PASSWORD = os.environ.get("TUXWALL_AGENT_PASSWORD", "")

    def _agent_ok(self):
        return True

    def _agent_log(self, msg):
        """Log an agent-proxy event to stderr -> journald (journalctl -u tuxwall.service)."""
        import sys as _sys
        print("[agent] {} {}".format(time.strftime("%Y-%m-%d %H:%M:%S"), msg), file=_sys.stderr, flush=True)

    def _agent_call(self, method, path, payload=None, timeout=30):
        """Forward a request to the local opencode server (HTTP basic auth).

        Returns parsed JSON. On failure raises AgentError carrying the
        upstream status code and response body so callers can log and
        display the real cause.
        """
        url = self.AGENT_BASE + path
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if self.AGENT_PASSWORD:
            import base64
            tok = base64.b64encode(
                ("opencode:" + self.AGENT_PASSWORD).encode()).decode()
            headers["Authorization"] = "Basic " + tok
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            self._agent_log("HTTP {} {} {} -> {} body={}".format(
                method, path, status, exc.reason, body[:2000]))
            detail = body.strip()
            if not detail:
                detail = str(exc.reason or "no response body")
            raise AgentError("opencode returned HTTP {}: {}".format(status, detail[:2000]),
                             status=status, body=detail[:2000])
        except urllib.error.URLError as exc:
            self._agent_log("HTTP {} {} -> unreachable: {}".format(method, path, exc.reason))
            raise AgentError(
                "opencode server unreachable at {} ({}). Is tuxwall-agent.service running?".format(
                    url, exc.reason),
                status=0, body=str(exc.reason))
        except socket.timeout:
            self._agent_log("HTTP {} {} -> timeout after {}s".format(method, path, timeout))
            raise AgentError(
                "opencode timed out after {}s on {} {}".format(timeout, method, path),
                status=0, body="timeout")
        self._agent_log("HTTP {} {} -> {} len={}".format(
            method, path, status, len(body or "")))
        try:
            return json.loads(body or "{}")
        except ValueError as exc:
            self._agent_log("HTTP {} {} -> non-JSON response: {}".format(
                method, path, body[:500]))
            raise AgentError("opencode returned invalid JSON ({}): {}".format(
                exc, body[:500]), status=status, body=body[:2000])

    def _agent_error(self, exc):
        """Build a structured error payload from an AgentError (or any exception)."""
        if isinstance(exc, AgentError):
            return {
                "ok": False,
                "error": str(exc),
                "status": exc.status,
                "detail": exc.body[:2000],
                "hint": "see: journalctl -u tuxwall.service -t -n 50 | grep agent",
            }
        return {
            "ok": False,
            "error": str(exc),
            "hint": "see: journalctl -u tuxwall.service -t -n 50 | grep agent",
        }

    def _agent_events_sse(self):
        """Proxy opencode's /event SSE stream to the browser, live."""
        import base64
        url = self.AGENT_BASE + "/event"
        headers = {"Accept": "text/event-stream"}
        if self.AGENT_PASSWORD:
            tok = base64.b64encode(
                ("opencode:" + self.AGENT_PASSWORD).encode()).decode()
            headers["Authorization"] = "Basic " + tok
        req = urllib.request.Request(url, headers=headers)
        try:
            upstream = urllib.request.urlopen(req, timeout=None)
        except Exception as exc:
            self._send(502, {"ok": False, "error": "agent event stream unavailable: %s" % exc})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            for raw in upstream:
                self.wfile.write(raw if isinstance(raw, bytes) else raw.encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # browser closed the stream
        finally:
            try:
                upstream.close()
            except Exception:
                pass
            self.close_connection = True

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, download_name):
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/gzip")
        self.send_header("Content-Disposition", 'attachment; filename="{}"'.format(download_name))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_auth(self, code, payload, cookie=None, clear_cookie=False):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if clear_cookie:
            self.send_header(
                "Set-Cookie",
                "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0".format(SESSION_COOKIE),
            )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/agent/events":
            identity = _session_identity(self.headers)
            if identity is None:
                self._send(401, {"ok": False, "error": "Authentication required"})
                return
            self._agent_events_sse()
            return
        if path == "/api/auth/session":
            self._send(200, auth_session_state(_session_identity(self.headers)))
            return
        identity = _session_identity(self.headers) if path.startswith("/api/") else None
        if path.startswith("/api/") and identity is None:
            self._send(401, {"ok": False, "error": "Authentication required"})
            return
        if path == "/api/auth/users":
            try:
                self._send(200, list_users(identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            return
        if path == "/api/leases":
            self._send(200, build_leases())
        elif path == "/api/status":
            self._send(200, build_status())
        elif path == "/api/dns":
            self._send(200, build_dns())
        elif path == "/api/domains":
            self._send(200, build_domains())
        elif path == "/api/firewall":
            self._send(200, build_firewall())
        elif path == "/api/firewall/interfaces":
            self._send(200, build_interfaces())
        elif path == "/api/security":
            self._send(200, get_security_monitor().snapshot())
        elif path == "/api/traffic-monitor":
            self._send(200, build_traffic_monitor())
        elif path == "/api/ai/chat/models":
            self._send(200, llm_model_list())
        elif path == "/api/security/ai-models":
            self._send(200, llm_model_list())
        elif path == "/api/security/ai-config":
            self._send(200, get_llm_conf())
        elif path == "/api/security/ai-summary":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            model = (qs.get("model") or [None])[0]
            self._send(200, ai_security_summary(model))
        elif path == "/api/security/suricata":
            self._send(200, build_suricata())
        elif path == "/api/agent/models":
            try:
                data = self._agent_call("GET", "/config/providers", timeout=10)
                models = []
                for p in (data.get("providers") or []):
                    pid = p.get("id")
                    for mid in (p.get("models") or {}):
                        models.append({
                            "id": pid + "/" + mid,
                            "provider": pid,
                            "model": mid,
                            "name": ((p.get("models") or {}).get(mid) or {}).get("name") or mid,
                        })
                configured = ""
                try:
                    conf = self._agent_call("GET", "/config", timeout=10)
                    configured = conf.get("model") or ""
                except Exception:
                    pass
                self._send(200, {"ok": True, "models": models,
                                 "default": data.get("default") or {},
                                 "configured": configured})
            except Exception as exc:
                self._send(500, self._agent_error(exc))
        elif path == "/api/agent/status":
            try:
                health = self._agent_call("GET", "/global/health", timeout=5)
                self._send(200, {"ok": True, "server": health})
            except Exception as exc:
                self._send(200, self._agent_error(exc))
        elif path == "/api/agent/session":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            session_id = (qs.get("id") or [None])[0]
            try:
                if session_id:
                    data = self._agent_call("GET", "/session/" + urllib.parse.quote(session_id))
                else:
                    data = self._agent_call("GET", "/session")
                self._send(200, data)
            except Exception as exc:
                self._send(500, self._agent_error(exc))
        elif path == "/api/agent/permission":
            try:
                data = self._agent_call("GET", "/permission")
                self._send(200, data)
            except Exception as exc:
                self._send(500, self._agent_error(exc))
        elif path == "/api/agent/config":
            # boot info for the terminal UI: version, cwd, vcs, config
            out = {"ok": True, "version": "", "directory": "",
                   "vcs": None, "config": {}, "error": ""}
            try:
                health = self._agent_call("GET", "/global/health", timeout=5)
                out["version"] = (health or {}).get("version") or ""
            except Exception as exc:
                out["error"] = str(exc)
            try:
                out["config"] = self._agent_call("GET", "/config", timeout=10) or {}
            except Exception:
                pass
            try:
                out["directory"] = (self._agent_call("GET", "/path", timeout=10) or {}).get("directory") or ""
            except Exception:
                pass
            try:
                out["vcs"] = self._agent_call("GET", "/vcs", timeout=10)
            except Exception:
                out["vcs"] = None
            self._send(200, out)
        elif path == "/api/agent/session/messages":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            session_id = (qs.get("id") or [None])[0]
            if not session_id:
                self._send(400, {"ok": False, "error": "id required"})
                return
            try:
                data = self._agent_call(
                    "GET", "/session/" + urllib.parse.quote(session_id) + "/message")
                self._send(200, {"ok": True, "messages": data if isinstance(data, list) else []})
            except Exception as exc:
                self._send(500, self._agent_error(exc))
        elif path == "/api/agent/find/file":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            query = (qs.get("q") or [""])[0]
            if not query:
                self._send(200, {"ok": True, "files": []})
                return
            try:
                data = self._agent_call(
                    "GET", "/find/file?" + urllib.parse.urlencode({"query": query, "limit": "12"}), timeout=10)
                files = data if isinstance(data, list) else []
                self._send(200, {"ok": True, "files": files[:12]})
            except Exception as exc:
                self._send(200, {"ok": False, "files": [], **self._agent_error(exc)})
        elif path == "/api/wireguard":
            self._send(200, build_wireguard())
        elif path == "/api/crowdsec":
            self._send(200, build_crowdsec())
        elif path == "/api/crowdsec/blocklist":
            self._send(200, build_custom_blocklist())
        elif path == "/api/bandwidth":
            self._send(200, build_bandwidth())
        elif path == "/api/blocklists":
            self._send(200, build_blocklists())
        elif path == "/api/system":
            self._send(200, build_system())
        elif path == "/api/system/services":
            try:
                self._send(200, list_system_services())
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
        elif path == "/api/latency/history":
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                hours = min(48.0, max(0.25, float(qs.get("hours", ["24"])[0])))
            except ValueError:
                hours = 24.0
            self._send(200, {"ok": True, "hours": hours, "series": get_latency_monitor().history_series(hours=hours)})
        elif path == "/api/baselines":
            self._send(200, load_baselines())

        elif path == "/api/backups":
            self._send(200, list_backups())

        elif path == "/api/backups/system":
            self._send(200, system_backup_status())

        elif path == "/api/backups/system/download":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            name = (qs.get("name") or [None])[0] or ""
            base = os.path.basename(name)
            if not SYSTEM_BACKUP_RE.match(base):
                self._send(400, {"ok": False, "error": "Invalid system backup name"})
                return
            fpath = os.path.join(SYSTEM_BACKUP_DIR, base)
            if not os.path.isfile(fpath):
                self._send(404, {"ok": False, "error": "System backup not found"})
                return
            self._send_file(fpath, base)

        elif path == "/api/reservations":
            self._send(200, build_reservations())

        elif path == "/api/portforward":
            self._send(200, build_portforward())

        elif path == "/api/dmz":
            self._send(200, build_dmz())

        elif path == "/api/vlans":
            self._send(200, build_vlans())

        elif path == "/api/system/updates":
            self._send(200, updates_snapshot())

        elif path == "/api/logs/services":
            self._send(200, {"ok": True, "sources": LOG_SOURCES})

        elif path == "/api/logs/tail":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            source = (query.get("source") or ["system"])[0]
            try:
                lines = int((query.get("lines") or ["200"])[0])
            except ValueError:
                lines = 200
            priority = (query.get("priority") or [""])[0]
            try:
                self._send(200, tail_log(source, lines, priority))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path in ("/api/system/kea-config", "/api/system/unbound-config"):
            kind = "kea" if path.endswith("kea-config") else "unbound"
            try:
                self._send(200, {"ok": True, **read_config(kind)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/download":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            name = (qs.get("name") or [None])[0] or ""
            base = os.path.basename(name)
            if not BACKUP_RE.match(base):
                self._send(400, {"ok": False, "error": "Invalid backup name"})
                return
            fpath = os.path.join(BACKUP_DIR, base)
            if not os.path.isfile(fpath):
                self._send(404, {"ok": False, "error": "Backup not found"})
                return
            self._send_file(fpath, base)

        elif path == "/api/system/hostname":
            name = (body.get("hostname") or "").strip()
            try:
                new_name = set_hostname(name)
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
            self._send(200, {"ok": True, "hostname": new_name})
        elif path == "/api/themes":
            self._send(200, list_themes())

        elif path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"ok": False, "error": "Not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        length = int(self.headers.get("Content-Length") or 0)
        raw = b""
        body = {}
        if length:
            maxlen = 104857600 if path == "/api/backups/restore" else 262144
            if length > maxlen:
                self._send(413, {"ok": False, "error": "Payload too large"})
                return
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                body = {}
        if not isinstance(body, dict):
            body = {}

        if path == "/api/auth/login":
            ip = _client_key(self)
            try:
                result = attempt_login(body, ip)
            except PermissionError as exc:
                self._send_auth(403, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self._send_auth(400, {"ok": False, "error": str(exc)})
                return
            except Exception:
                self._send_auth(500, {"ok": False, "error": "Login failed"})
                return
            if result.get("totp_required"):
                # Password accepted; no session until the second factor is given.
                self._send_auth(200, result)
                return
            cookie = "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}".format(
                SESSION_COOKIE,
                _create_session(result["username"], result.get("role", "viewer")),
                SESSION_TTL,
            )
            self._send_auth(200, result, cookie=cookie)
            return

        if path == "/api/auth/logout":
            _drop_session(self.headers)
            self._send_auth(200, {"ok": True}, clear_cookie=True)
            return

        # Internal self-restart: localhost only, no auth required
        if path == "/api/system/self-restart":
            if self.client_address[0] not in ("127.0.0.1", "::1"):
                self._send(403, {"ok": False, "error": "Forbidden"})
                return
            try:
                _ensure_unbound_local_actions()
                subprocess.Popen(["systemctl", "restart", "unbound.service"])
                subprocess.Popen(["systemctl", "restart", "tuxwall.service"])
                self._send(200, {"ok": True})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
            return

        identity = _session_identity(self.headers) if path.startswith("/api/") else None
        if path.startswith("/api/") and identity is None:
            # local-only exemption so the systemd timer can trigger updates
            # without a browser session (loopback callers only)
            if path == "/api/blocklists/update" and \
                    _client_key(self) in ("127.0.0.1", "::1"):
                identity = {"username": "system-timer", "role": "admin", "owner": False}
            else:
                self._send(401, {"ok": False, "error": "Authentication required"})
                return

        if path == "/api/auth/password":
            try:
                self._send(200, change_password(body, identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            return

        if path == "/api/auth/totp/setup":
            try:
                self._send(200, totp_setup(identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            return

        if path == "/api/auth/totp/confirm":
            try:
                self._send(200, totp_confirm(body, identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            return

        if path == "/api/auth/totp/disable":
            try:
                self._send(200, totp_disable(body, identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            return

        if path == "/api/auth/users/add":
            try:
                self._send(200, add_user(body, identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            return

        if path == "/api/auth/users/delete":
            try:
                self._send(200, delete_user(body, identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            return

        if path == "/api/auth/users/update":
            try:
                self._send(200, update_user(body, identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            return

        if path == "/api/auth/users/enabled":
            try:
                self._send(200, set_user_enabled(body, identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            return

        if path == "/api/auth/users/password":
            try:
                self._send(200, reset_user_password(body, identity))
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            return

        if identity.get("role") != "admin":
            self._send(403, {"ok": False, "error": "Administrator access required"})
            return

        if path == "/api/baselines":
            save_baselines(body)
            self._send(200, {"ok": True})
            return

        if path == "/api/blocklists/add":
            url = (body.get("url") or "").strip()
            if not valid_blocklist_url(url):
                self._send(400, {"ok": False, "error": "Invalid URL"})
                return
            sources = ensure_blocklist_config()
            if any(s.get("url") == url for s in sources):
                self._send(409, {"ok": False, "error": "List already added"})
                return
            sources.append({
                "url": url,
                "enabled": True,
                "added_at": time.time(),
                "last_status": None,
                "last_error": None,
                "last_updated": None,
                "domains": 0,
            })
            save_blocklists(sources)
            self._send(200, build_blocklists())

        elif path == "/api/blocklists/remove":
            url = (body.get("url") or "").strip()
            sources = ensure_blocklist_config()
            sources = [s for s in sources if s.get("url") != url]
            save_blocklists(sources)
            self._send(200, build_blocklists())

        elif path == "/api/blocklists/toggle":
            url = (body.get("url") or "").strip()
            sources = ensure_blocklist_config()
            for src in sources:
                if src.get("url") == url:
                    src["enabled"] = not src.get("enabled", True)
            save_blocklists(sources)
            self._send(200, build_blocklists())

        elif path == "/api/leases/ban":
            ip = (body.get("ip") or "").strip()
            if not IPV4_RE.match(ip):
                self._send(400, {"ok": False, "error": "Invalid IP address"})
                return
            try:
                changed = ban_client(ip, body.get("hostname") or "", body.get("mac") or "")
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
            self._send(200, {"ok": True, "banned": True, "changed": changed})

        elif path == "/api/leases/unban":
            ip = (body.get("ip") or "").strip()
            if not IPV4_RE.match(ip):
                self._send(400, {"ok": False, "error": "Invalid IP address"})
                return
            try:
                changed = unban_client(ip)
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
            self._send(200, {"ok": True, "banned": False, "changed": changed})

        elif path == "/api/blocklists/whitelist/add":
            dom = valid_whitelist_domain(body.get("domain") or "")
            if not dom:
                self._send(400, {"ok": False, "error": "Invalid domain"})
                return
            whitelist = set(load_whitelist())
            whitelist = {w for w in whitelist if not w.endswith("." + dom)}
            if dom not in whitelist and not any(dom.endswith("." + w) for w in whitelist):
                whitelist.add(dom)
            save_whitelist(whitelist)
            self._send(200, build_blocklists())

        elif path == "/api/blocklists/whitelist/remove":
            dom = normalize_domain(body.get("domain") or "")
            if not dom:
                self._send(400, {"ok": False, "error": "Invalid domain"})
                return
            whitelist = set(load_whitelist())
            whitelist.discard(dom)
            save_whitelist(whitelist)
            self._send(200, build_blocklists())

        elif path == "/api/diagnose":
            self._send(200, build_diagnose(body.get("target", "")))

        elif path == "/api/blocklists/update":
            if BLOCKLIST_STATE["status"] == "updating":
                self._send(200, build_blocklists())
                return
            threading.Thread(target=run_blocklist_update, daemon=True).start()
            self._send(202, build_blocklists())

        elif path == "/api/wireguard/setup":
            try:
                self._send(200, setup_wireguard(body))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/wireguard/peer/add":
            try:
                self._send(200, add_wg_peer(body.get("name") or ""))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/wireguard/peer/remove":
            pk = (body.get("public_key") or "").strip()
            if not pk:
                self._send(400, {"ok": False, "error": "Missing public key"})
                return
            try:
                self._send(200, remove_wg_peer(pk))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/wireguard/peer/rename":
            pk = (body.get("public_key") or "").strip()
            if not pk:
                self._send(400, {"ok": False, "error": "Missing public key"})
                return
            try:
                self._send(200, rename_wg_peer(pk, body.get("name") or ""))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/wireguard/peer/config":
            pk = (body.get("public_key") or "").strip()
            if not pk:
                self._send(400, {"ok": False, "error": "Missing public key"})
                return
            try:
                self._send(200, peer_config(pk))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/wireguard/start":
            try:
                wg_interface_start()
                self._send(200, {"ok": True})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/system/services/action":
            try:
                self._send(200, service_action(body.get("unit") or "", body.get("action") or ""))
            except Exception as exc:
                self._send(400, {"ok": False, "error": str(exc)})

        elif path == "/api/wireguard/stop":
            try:
                wg_interface_stop()
                self._send(200, {"ok": True})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/firewall/allow":
            try:
                self._send(200, add_firewall_rule(body.get("rule") or ""))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/firewall/delete":
            try:
                self._send(200, delete_firewall_rule(body.get("number")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/firewall/enable":
            try:
                self._send(200, set_firewall_enabled(bool(body.get("enabled"))))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/firewall/default":
            try:
                self._send(200, set_firewall_default(
                    body.get("direction"), body.get("policy")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/firewall/logging":
            try:
                self._send(200, set_firewall_logging(body.get("level")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/crowdsec/ban":
            try:
                self._send(200, ban_crowdsec_ip(body.get("ip"), body.get("duration")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/crowdsec/unban":
            try:
                self._send(200, unban_crowdsec_ip(body.get("ip")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/crowdsec/blocklist/add":
            try:
                self._send(200, add_custom_blocklist_entry(body.get("entry")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/crowdsec/blocklist/remove":
            try:
                self._send(200, remove_custom_blocklist_entry(body.get("entry")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/domains/add":
            try:
                self._send(200, add_domain(body))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/domains/update":
            try:
                self._send(200, update_domain(body))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/domains/delete":
            try:
                self._send(200, delete_domain(body))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/domains/import":
            try:
                self._send(200, import_domain(body))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/domains/import-all":
            try:
                self._send(200, import_all_domains())
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/create":
            try:
                self._send(200, create_backup())
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/system/create":
            try:
                self._send(200, create_system_backup())
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/system/delete":
            try:
                self._send(200, delete_system_backup(body.get("name")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/delete":
            filename = (body.get("name") or "").strip()
            try:
                self._send(200, delete_backup(filename))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path in ("/api/system/kea-config", "/api/system/unbound-config"):
            kind = "kea" if path.endswith("kea-config") else "unbound"
            try:
                self._send(200, {"ok": True, **write_config(kind, body.get("content") or "")})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/agent/status":
            try:
                health = self._agent_call("GET", "/global/health", timeout=5)
                self._send(200, {"ok": True, "server": health})
            except Exception as exc:
                self._send(200, self._agent_error(exc))

        elif path == "/api/agent/session":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            session_id = (qs.get("id") or [None])[0]
            try:
                if session_id:
                    data = self._agent_call("GET", "/session/" + urllib.parse.quote(session_id))
                else:
                    data = self._agent_call("GET", "/session")
                self._send(200, data)
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/models":
            try:
                data = self._agent_call("GET", "/config/providers", timeout=10)
                models = []
                for p in (data.get("providers") or []):
                    pid = p.get("id")
                    for mid in (p.get("models") or {}):
                        models.append({
                            "id": pid + "/" + mid,
                            "provider": pid,
                            "model": mid,
                            "name": ((p.get("models") or {}).get(mid) or {}).get("name") or mid,
                        })
                configured = ""
                try:
                    conf = self._agent_call("GET", "/config", timeout=10)
                    configured = conf.get("model") or ""
                except Exception:
                    pass
                self._send(200, {"ok": True, "models": models,
                                 "default": data.get("default") or {},
                                 "configured": configured})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/permission":
            try:
                data = self._agent_call("GET", "/permission")
                self._send(200, data)
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/question":
            try:
                data = self._agent_call("GET", "/question")
                self._send(200, data)
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/question/reply":
            request_id = (body.get("requestID") or "").strip()
            answers = body.get("answers")
            if not request_id or not isinstance(answers, list) or not answers:
                self._send(400, {"ok": False, "error": "requestID and answers required"})
                return
            try:
                data = self._agent_call(
                    "POST",
                    "/question/" + urllib.parse.quote(request_id) + "/reply",
                    {"answers": answers},
                )
                self._send(200, data if isinstance(data, dict) else {"ok": True})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/question/reject":
            request_id = (body.get("requestID") or "").strip()
            if not request_id:
                self._send(400, {"ok": False, "error": "requestID required"})
                return
            try:
                data = self._agent_call(
                    "POST",
                    "/question/" + urllib.parse.quote(request_id) + "/reject",
                )
                self._send(200, data if isinstance(data, dict) else {"ok": True})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/new":
            try:
                data = self._agent_call("POST", "/session", {})
                if isinstance(data, dict):
                    data = dict(data)
                    data.setdefault("ok", True)
                self._send(200, data)
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/permission/reply":
            request_id = (body.get("requestID") or "").strip()
            reply = (body.get("reply") or body.get("response") or "").strip()
            if not request_id or reply not in ("once", "always", "reject"):
                self._send(400, {"ok": False, "error": "requestID and reply (once/always/reject) required"})
                return
            try:
                data = self._agent_call(
                    "POST",
                    "/permission/" + urllib.parse.quote(request_id) + "/reply",
                    {"reply": reply},
                )
                self._send(200, data if isinstance(data, dict) else {"ok": True})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/message":
            session_id = (body.get("sessionID") or "").strip()
            text = (body.get("text") or "").strip()
            if not session_id or not text:
                self._send(400, {"ok": False, "error": "sessionID and text required"})
                return
            payload = {"parts": [{"type": "text", "text": text}]}
            model = (body.get("model") or "").strip()
            if model and "/" in model:
                provider_id, model_id = model.split("/", 1)
                payload["model"] = {"providerID": provider_id, "modelID": model_id}
            try:
                # async fire-and-forget: the browser follows progress via
                # /api/agent/events (SSE) instead of waiting for this call
                self._agent_call(
                    "POST",
                    "/session/" + urllib.parse.quote(session_id) + "/prompt_async",
                    payload,
                    timeout=30,
                )
                self._send(200, {"ok": True, "async": True})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/shell":
            # "!command" passthrough: run a shell command inside the session
            session_id = (body.get("sessionID") or "").strip()
            command = (body.get("command") or "").strip()
            if not session_id or not command:
                self._send(400, {"ok": False, "error": "sessionID and command required"})
                return
            payload = {"agent": "build", "command": command}
            try:
                data = self._agent_call(
                    "POST",
                    "/session/" + urllib.parse.quote(session_id) + "/shell",
                    payload, timeout=300)
                self._send(200, {"ok": True, "result": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/command":
            # execute an opencode slash command inside the session
            session_id = (body.get("sessionID") or "").strip()
            command = (body.get("command") or "").strip()
            if not session_id or not command:
                self._send(400, {"ok": False, "error": "sessionID and command required"})
                return
            payload = {"command": command}
            for key in ("arguments", "messageID", "agent"):
                if body.get(key):
                    payload[key] = body[key]
            model = (body.get("model") or "").strip()
            if model and "/" in model:
                provider_id, model_id = model.split("/", 1)
                payload["model"] = {"providerID": provider_id, "modelID": model_id}
            try:
                data = self._agent_call(
                    "POST",
                    "/session/" + urllib.parse.quote(session_id) + "/command",
                    payload, timeout=300)
                self._send(200, {"ok": True, "result": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/abort":
            session_id = (body.get("sessionID") or "").strip()
            if not session_id:
                self._send(400, {"ok": False, "error": "sessionID required"})
                return
            try:
                data = self._agent_call(
                    "POST",
                    "/session/" + urllib.parse.quote(session_id) + "/abort")
                self._send(200, {"ok": True, "result": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/revert":
            # /undo — revert the last (or given) message
            session_id = (body.get("sessionID") or "").strip()
            if not session_id:
                self._send(400, {"ok": False, "error": "sessionID required"})
                return
            payload = {}
            if body.get("messageID"):
                payload["messageID"] = body["messageID"]
            try:
                data = self._agent_call(
                    "POST",
                    "/session/" + urllib.parse.quote(session_id) + "/revert", payload)
                self._send(200, {"ok": True, "result": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/unrevert":
            # /redo — restore reverted messages
            session_id = (body.get("sessionID") or "").strip()
            if not session_id:
                self._send(400, {"ok": False, "error": "sessionID required"})
                return
            try:
                data = self._agent_call(
                    "POST",
                    "/session/" + urllib.parse.quote(session_id) + "/unrevert")
                self._send(200, {"ok": True, "result": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/summarize":
            # /compact
            session_id = (body.get("sessionID") or "").strip()
            if not session_id:
                self._send(400, {"ok": False, "error": "sessionID required"})
                return
            payload = {}
            model = (body.get("model") or "").strip()
            if model and "/" in model:
                provider_id, model_id = model.split("/", 1)
                payload = {"providerID": provider_id, "modelID": model_id}
            try:
                data = self._agent_call(
                    "POST",
                    "/session/" + urllib.parse.quote(session_id) + "/summarize", payload,
                    timeout=300)
                self._send(200, {"ok": True, "result": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/share":
            session_id = (body.get("sessionID") or "").strip()
            if not session_id:
                self._send(400, {"ok": False, "error": "sessionID required"})
                return
            try:
                data = self._agent_call(
                    "POST", "/session/" + urllib.parse.quote(session_id) + "/share")
                self._send(200, {"ok": True, "session": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/unshare":
            session_id = (body.get("sessionID") or "").strip()
            if not session_id:
                self._send(400, {"ok": False, "error": "sessionID required"})
                return
            try:
                data = self._agent_call(
                    "DELETE", "/session/" + urllib.parse.quote(session_id) + "/share")
                self._send(200, {"ok": True, "session": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/init":
            # /init — analyze the project and write AGENTS.md
            session_id = (body.get("sessionID") or "").strip()
            if not session_id:
                self._send(400, {"ok": False, "error": "sessionID required"})
                return
            payload = {}
            model = (body.get("model") or "").strip()
            if model and "/" in model:
                provider_id, model_id = model.split("/", 1)
                payload = {"providerID": provider_id, "modelID": model_id}
            try:
                data = self._agent_call(
                    "POST",
                    "/session/" + urllib.parse.quote(session_id) + "/init", payload,
                    timeout=300)
                self._send(200, {"ok": True, "result": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/delete":
            session_id = (body.get("sessionID") or "").strip()
            if not session_id:
                self._send(400, {"ok": False, "error": "sessionID required"})
                return
            try:
                data = self._agent_call(
                    "DELETE", "/session/" + urllib.parse.quote(session_id))
                self._send(200, {"ok": True, "result": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/agent/session/rename":
            session_id = (body.get("sessionID") or "").strip()
            title = (body.get("title") or "").strip()
            if not session_id or not title:
                self._send(400, {"ok": False, "error": "sessionID and title required"})
                return
            try:
                data = self._agent_call(
                    "PATCH", "/session/" + urllib.parse.quote(session_id),
                    {"title": title[:200]})
                self._send(200, {"ok": True, "session": data})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path == "/api/ai/chat":
            try:
                messages = body.get("messages") or []
                model = body.get("model") or None
                if not isinstance(messages, list):
                    raise ValueError("messages must be a list")
                self._send(200, ai_chat(messages, model))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/security/ai-config":
            try:
                self._send(200, save_llm_conf(body))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path in ("/api/system/updates/check", "/api/system/updates/apply"):
            op = "check" if path.endswith("check") else "apply"
            try:
                self._send(200, start_update(op))
            except Exception as exc:
                self._send(409 if "already" in str(exc) else 500, {"ok": False, "error": str(exc)})

        elif path == "/api/themes/active":
            try:
                self._send(200, set_active_theme(body.get("id")))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})

        elif path == "/api/themes/upload":
            try:
                payload = validate_theme_payload(body)
                theme = save_custom_theme(payload)
                self._send(200, {"ok": True, "theme": theme})
            except FileExistsError as exc:
                self._send(409, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})

        elif path == "/api/themes/delete":
            try:
                self._send(200, delete_custom_theme(body.get("id")))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})

        elif path == "/api/ui/router-location":
            try:
                self._send(200, set_router_location(body.get("lat"), body.get("lon")))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})

        elif path == "/api/system/self-restart":
            # Internal-use restart: writes unbound conf and restarts tuxwall service
            try:
                _ensure_unbound_local_actions()
                subprocess.Popen(["systemctl", "restart", "tuxwall.service", "--no-block"])
                self._send(200, {"ok": True})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/system/reboot":
            try:
                self._send(200, system_reboot())
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/restore":
            if body and body.get("name"):
                try:
                    result = restore_backup(body["name"])
                except Exception as exc:
                    self._send(500, {"ok": False, "error": str(exc)})
                    return
                self._send(200, {"ok": True, **result})
                return
            filename = (qs.get("name") or [None])[0] or self.headers.get("X-Filename") or "tuxwall-restore.tar.gz"
            if not raw:
                self._send(400, {"ok": False, "error": "No file uploaded"})
                return
            try:
                result = restore_backup(filename, raw=raw)
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
            self._send(200, {"ok": True, **result})

        elif path == "/api/reservations/add":
            try:
                self._send(200, add_reservation(body))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/reservations/edit":
            try:
                self._send(200, edit_reservation(body))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/reservations/delete":
            try:
                self._send(200, delete_reservation(body))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/portforward/add":
            try:
                self._send(200, add_portforward(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/portforward/delete":
            try:
                self._send(200, delete_portforward(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/portforward/toggle":
            try:
                self._send(200, toggle_portforward(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/dmz/enable":
            try:
                self._send(200, enable_dmz(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/dmz/disable":
            try:
                self._send(200, disable_dmz(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/vlans/add":
            try:
                self._send(200, add_vlan(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/vlans/edit":
            try:
                self._send(200, edit_vlan(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/vlans/delete":
            try:
                self._send(200, delete_vlan(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/vlans/policy/add":
            try:
                self._send(200, add_vlan_policy(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/vlans/policy/delete":
            try:
                self._send(200, delete_vlan_policy(body))
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        else:
            self._send(404, {"ok": False, "error": "Not found"})

    def log_message(self, fmt, *args):
        pass


UNBOUND_LOCAL_ACTIONS_CONF = "/etc/unbound/unbound.conf.d/log-local-actions.conf"
UNBOUND_LOCAL_ACTIONS_RE = re.compile(
    r"unbound\[\d+\].*?info:\s+\S+\s+always_nxdomain\s+(\d+\.\d+\.\d+\.\d+)@\d+\s+(\S+?\.?)\s+(\w+)\s+IN"
)
TRAFFIC_JOURNAL_RE = re.compile(
    r"^(\S+)\s+\S+\s+unbound\[\d+\]"
)

TUXWALL_SERVICE_FILE = "/etc/systemd/system/tuxwall.service"
TUXWALL_SERVICE_CONTENT = """\
[Unit]
Description=Network Dashboard API
After=network.target kea-dhcp4-server.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /var/www/html/includes/api_server.py
ExecReload=/bin/kill -USR1 $MAINPID
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/etc/wireguard /etc/ufw /etc/systemd/system /etc/tuxwall /etc/unbound

[Install]
WantedBy=multi-user.target
"""

def _ensure_service_reload():
    """Add ExecReload to tuxwall.service if missing, then daemon-reload."""
    try:
        current = open(TUXWALL_SERVICE_FILE).read()
        if "ExecReload" not in current:
            with open(TUXWALL_SERVICE_FILE, "w") as f:
                f.write(TUXWALL_SERVICE_CONTENT)
            subprocess.run(["systemctl", "daemon-reload"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        pass

def _ensure_unbound_local_actions():
    """Write log-local-actions conf if missing, reload unbound."""
    if os.path.exists(UNBOUND_LOCAL_ACTIONS_CONF):
        return
    try:
        with open(UNBOUND_LOCAL_ACTIONS_CONF, "w") as f:
            f.write("server:\n    log-local-actions: yes\n")
        subprocess.run(["unbound-control", "reload"],
                       capture_output=True, text=True, timeout=10)
    except Exception:
        pass

def build_traffic_monitor():
    """Return merged, time-sorted traffic events from UFW log + Unbound local-actions."""
    _ensure_unbound_local_actions()
    entries = []

    # --- UFW log (last 512 KB) ---
    try:
        with open(UFW_LOG, "r", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 524288))
            text = f.read()
    except Exception:
        text = ""

    for line in text.splitlines():
        m = EVENT_RE.match(line.strip())
        if not m:
            continue
        g = m.groupdict()
        action = g["action"]
        iface_in  = g.get("in", "") or ""
        iface_out = g.get("out", "") or ""
        direction = "in" if iface_in else "out"
        src = g.get("src", "") or ""
        dst = g.get("dst", "") or ""
        # Skip multicast/IGMP noise with no real src
        if action == "BLOCK" and src in ("0.0.0.0", ""):
            continue
        entries.append({
            "ts":        g["ts"],
            "type":      "fw-block" if action == "BLOCK" else "fw-allow",
            "source":    "Firewall",
            "direction": direction,
            "src":       src,
            "dst":       dst,
            "proto":     g.get("proto", "") or "",
            "port":      g.get("dpt", "") or g.get("spt", "") or "",
            "iface":     iface_in or iface_out,
            "detail":    "",
        })

    # --- Unbound local-actions (DNS blocklist hits) via journald ---
    try:
        proc = subprocess.run(
            ["journalctl", "-u", "unbound", "--no-pager", "-n", "300",
             "--output=short-iso", "--since", "1 hour ago"],
            capture_output=True, text=True, timeout=8
        )
        for line in proc.stdout.splitlines():
            m = UNBOUND_LOCAL_ACTIONS_RE.search(line)
            if not m:
                continue
            client_ip  = m.group(1)
            domain     = m.group(2).rstrip(".").lstrip("/")
            rec_type   = m.group(3)   # A, AAAA, MX, etc.
            if not domain or domain.startswith("_"):
                continue
            ts_raw = line.split()[0] if line else ""
            entries.append({
                "ts":        ts_raw,
                "type":      "dns-block",
                "source":    "DNS Blocklist",
                "direction": "out",
                "src":       client_ip,
                "dst":       domain,
                "proto":     "DNS",
                "port":      "53",
                "iface":     "",
                "detail":    f"{rec_type} blocked",
            })
    except Exception:
        pass

    # Sort newest first, cap at 150
    entries.sort(key=lambda x: x["ts"], reverse=True)
    entries = entries[:150]

    return {"ok": True, "entries": entries}


def build_diagnose(target):
    """Check whether a domain or IP is blocked by firewall, DNS blocklist, or CrowdSec."""
    target = (target or "").strip().lower().rstrip(".")
    if not target:
        return {"ok": False, "error": "No target provided"}

    results = []
    is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target))

    # --- 1. DNS blocklist check ---
    if not is_ip:
        blocked_by_dns = False
        try:
            with open(BLOCKLIST_CONF, "r", errors="replace") as f:
                content = f.read()
            # Unbound blocklist format: local-zone: "domain." always_nxdomain
            if f'"{target}."' in content or f'"{target}"' in content:
                blocked_by_dns = True
        except Exception:
            pass
        if not blocked_by_dns:
            # Also check custom blocklist file
            try:
                custom = open("/etc/tuxwall/custom-blocklist.txt").read()
                if target in custom:
                    blocked_by_dns = True
            except Exception:
                pass
        results.append({
            "check":   "DNS Blocklist",
            "blocked": blocked_by_dns,
            "detail":  f"{target} is in the Unbound blocklist — DNS queries will return NXDOMAIN" if blocked_by_dns
                       else f"{target} is not in the DNS blocklist",
            "action":  "Remove from blocklist in the DNS Blocklists page" if blocked_by_dns else "",
        })

        # --- 2. Live DNS resolution test ---
        try:
            proc = subprocess.run(
                ["dig", "+short", "+time=3", target],
                capture_output=True, text=True, timeout=6
            )
            answer = proc.stdout.strip()
            if not answer:
                dns_result = "No answer — domain may not exist, or DNS is blocking it"
                dns_ok = False
            else:
                dns_result = f"Resolves to: {answer.splitlines()[0]}"
                dns_ok = True
        except Exception as e:
            dns_result = f"DNS lookup failed: {e}"
            dns_ok = False
        results.append({
            "check":   "DNS Resolution",
            "blocked": not dns_ok,
            "detail":  dns_result,
            "action":  "Check Unbound logs or blocklist" if not dns_ok else "",
        })

    # --- 3. CrowdSec ban check ---
    try:
        proc = subprocess.run(
            ["cscli", "decisions", "list", "--ip", target, "--output", "json"],
            capture_output=True, text=True, timeout=8
        )
        decisions = json.loads(proc.stdout or "[]") or []
        cs_blocked = bool(decisions)
        results.append({
            "check":   "CrowdSec",
            "blocked": cs_blocked,
            "detail":  f"{target} has {len(decisions)} active CrowdSec decision(s)" if cs_blocked
                       else f"{target} is not banned by CrowdSec",
            "action":  f"Run: cscli decisions delete --ip {target}" if cs_blocked else "",
        })
    except Exception:
        results.append({
            "check":   "CrowdSec",
            "blocked": None,
            "detail":  "CrowdSec not available",
            "action":  "",
        })

    # --- 4. Custom IP blocklist check ---
    if is_ip:
        ip_blocked = False
        try:
            with open("/etc/tuxwall/custom-blocklist.txt") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line == target:
                        ip_blocked = True
                        break
        except Exception:
            pass
        results.append({
            "check":   "Custom IP Blocklist",
            "blocked": ip_blocked,
            "detail":  f"{target} is in the custom IP blocklist" if ip_blocked
                       else f"{target} is not in the custom IP blocklist",
            "action":  "Remove from /etc/tuxwall/custom-blocklist.txt" if ip_blocked else "",
        })

    # --- 5. UFW rules check ---
    try:
        proc = subprocess.run(
            ["ufw", "status", "verbose"],
            capture_output=True, text=True, timeout=8
        )
        ufw_out = proc.stdout
        # Look for explicit DENY/REJECT rules matching the target
        deny_match = any(
            target in line and ("DENY" in line or "REJECT" in line)
            for line in ufw_out.splitlines()
        )
        allow_match = any(
            target in line and "ALLOW" in line
            for line in ufw_out.splitlines()
        )
        if deny_match:
            detail = f"{target} matches an explicit UFW DENY/REJECT rule"
            action = "Check rules: ufw status numbered"
        elif allow_match:
            detail = f"{target} matches an explicit UFW ALLOW rule"
            action = ""
        else:
            detail = f"No explicit UFW rule for {target} — default policy applies"
            action = ""
        results.append({
            "check":   "UFW Firewall Rules",
            "blocked": deny_match,
            "detail":  detail,
            "action":  action,
        })
    except Exception:
        results.append({
            "check":   "UFW Firewall Rules",
            "blocked": None,
            "detail":  "UFW not available",
            "action":  "",
        })

    overall = any(r["blocked"] for r in results if r["blocked"] is not None)
    return {
        "ok":      True,
        "target":  target,
        "blocked": overall,
        "results": results,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Port Forwarding + DMZ
# ─────────────────────────────────────────────────────────────────────────────

PF_PERSIST   = "/etc/tuxwall/portforward.json"
DMZ_PERSIST  = "/etc/tuxwall/dmz.json"


def _wan_iface():
    """Return the WAN interface name from the default route."""
    try:
        r = subprocess.run(
            ["ip", "-j", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        routes = json.loads(r.stdout or "[]")
        if routes:
            return routes[0].get("dev", "enp5s0")
    except Exception:
        pass
    return "enp5s0"


def _lan_iface():
    """LAN interface — the one carrying 192.168.1.0/24."""
    try:
        r = subprocess.run(
            ["ip", "-j", "addr"], capture_output=True, text=True, timeout=5
        )
        for iface in json.loads(r.stdout or "[]"):
            for a in iface.get("addr_info", []):
                if a.get("family") == "inet" and a.get("local", "").startswith("192.168.1."):
                    return iface.get("ifname", "enp6s0")
    except Exception:
        pass
    return "enp6s0"


def _lan_subnet():
    """e.g. '192.168.1.0/24'"""
    try:
        r = subprocess.run(
            ["ip", "-j", "addr"], capture_output=True, text=True, timeout=5
        )
        for iface in json.loads(r.stdout or "[]"):
            for a in iface.get("addr_info", []):
                if a.get("family") == "inet" and a.get("local", "").startswith("192.168.1."):
                    net = ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network
                    return str(net)
    except Exception:
        pass
    return "192.168.1.0/24"


def _gateway_ip():
    """Gateway's own LAN IP."""
    try:
        r = subprocess.run(
            ["ip", "-j", "addr"], capture_output=True, text=True, timeout=5
        )
        for iface in json.loads(r.stdout or "[]"):
            for a in iface.get("addr_info", []):
                if a.get("family") == "inet" and a.get("local", "").startswith("192.168.1."):
                    return a["local"]
    except Exception:
        pass
    return "192.168.1.1"


def _ipt_backend():
    """
    Return the correct iptables binary for the active backend.
    UFW on this system uses iptables-nft; the 'iptables' alternative
    may point to iptables-legacy which is a different (empty) ruleset.
    We detect which backend actually has UFW chains loaded.
    """
    for binary in ("iptables-nft", "iptables-legacy", "iptables"):
        try:
            r = subprocess.run(
                [binary, "-t", "filter", "-L", "ufw-before-input", "-n"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                return binary
        except FileNotFoundError:
            continue
    return "iptables"


_IPT_BIN = None


def _get_ipt_bin():
    global _IPT_BIN
    if _IPT_BIN is None:
        _IPT_BIN = _ipt_backend()
    return _IPT_BIN


def _ipt(*args, table="filter", check=True):
    """Run iptables (correct backend) with the given args."""
    cmd = [_get_ipt_bin(), "-t", table] + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if check and r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "iptables failed").strip())
    return r.returncode == 0


def _ipt_rule_exists(table, chain, *rule_args):
    """True if the rule already exists (iptables -C)."""
    return _ipt("-C", chain, *rule_args, table=table, check=False)


# ── Port Forwarding ──────────────────────────────────────────────────────────

def _load_pf():
    try:
        with open(PF_PERSIST) as f:
            return json.load(f)
    except Exception:
        return []


def _save_pf(rules):
    os.makedirs("/etc/tuxwall", exist_ok=True)
    with open(PF_PERSIST, "w") as f:
        json.dump(rules, f, indent=2)


def _apply_pf_rule(rule):
    """Insert a single port forward into iptables (idempotent)."""
    wan  = _wan_iface()
    lan  = _lan_iface()
    ext  = str(rule["ext_port"])
    dst  = rule["int_ip"]
    dpt  = str(rule["int_port"])
    proto = rule["proto"]   # tcp | udp | both

    protos = ["tcp", "udp"] if proto == "both" else [proto]
    for p in protos:
        # PREROUTING DNAT
        dnat_args = ["-i", wan, "-p", p, "--dport", ext,
                     "-j", "DNAT", "--to-destination", f"{dst}:{dpt}"]
        if not _ipt_rule_exists("nat", "PREROUTING", *dnat_args):
            _ipt("-A", "PREROUTING", *dnat_args, table="nat")

        # FORWARD accept for the forwarded traffic
        fwd_args = ["-i", wan, "-o", lan, "-p", p,
                    "-d", dst, "--dport", dpt, "-m", "state",
                    "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"]
        if not _ipt_rule_exists("filter", "FORWARD", *fwd_args):
            _ipt("-A", "FORWARD", *fwd_args)


def _remove_pf_rule(rule):
    """Remove a single port forward from iptables."""
    wan  = _wan_iface()
    lan  = _lan_iface()
    ext  = str(rule["ext_port"])
    dst  = rule["int_ip"]
    dpt  = str(rule["int_port"])
    proto = rule["proto"]

    protos = ["tcp", "udp"] if proto == "both" else [proto]
    for p in protos:
        dnat_args = ["-i", wan, "-p", p, "--dport", ext,
                     "-j", "DNAT", "--to-destination", f"{dst}:{dpt}"]
        if _ipt_rule_exists("nat", "PREROUTING", *dnat_args):
            _ipt("-D", "PREROUTING", *dnat_args, table="nat")

        fwd_args = ["-i", wan, "-o", lan, "-p", p,
                    "-d", dst, "--dport", dpt, "-m", "state",
                    "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"]
        if _ipt_rule_exists("filter", "FORWARD", *fwd_args):
            _ipt("-D", "FORWARD", *fwd_args)


def build_portforward():
    rules = _load_pf()
    # Enrich with live iptables state
    for rule in rules:
        wan = _wan_iface()
        ext = str(rule["ext_port"])
        dst = rule["int_ip"]
        dpt = str(rule["int_port"])
        proto = rule["proto"]
        protos = ["tcp", "udp"] if proto == "both" else [proto]
        active = all(
            _ipt_rule_exists("nat", "PREROUTING",
                             "-i", wan, "-p", p, "--dport", ext,
                             "-j", "DNAT", "--to-destination", f"{dst}:{dpt}")
            for p in protos
        )
        rule["active"] = active
    return {"ok": True, "rules": rules}


def add_portforward(body):
    label    = (body.get("label") or "").strip()
    proto    = (body.get("proto") or "tcp").strip().lower()
    int_ip   = (body.get("int_ip") or "").strip()
    try:
        ext_port = int(body.get("ext_port", 0))
        int_port = int(body.get("int_port") or ext_port)
    except (TypeError, ValueError):
        raise ValueError("Ports must be integers")

    if proto not in ("tcp", "udp", "both"):
        raise ValueError("proto must be tcp, udp, or both")
    if not (1 <= ext_port <= 65535) or not (1 <= int_port <= 65535):
        raise ValueError("Port out of range 1–65535")
    if not int_ip:
        raise ValueError("Internal IP is required")
    ipaddress.ip_address(int_ip)   # validate

    rules = _load_pf()
    # Check for duplicate external port + proto
    for r in rules:
        if r["ext_port"] == ext_port and (r["proto"] == proto or proto == "both" or r["proto"] == "both"):
            raise ValueError(f"External port {ext_port} is already forwarded")

    rule = {
        "id":       str(uuid4())[:8],
        "label":    label,
        "proto":    proto,
        "ext_port": ext_port,
        "int_ip":   int_ip,
        "int_port": int_port,
        "enabled":  True,
    }
    _apply_pf_rule(rule)
    rules.append(rule)
    _save_pf(rules)
    return {"ok": True, "rule": rule}


def delete_portforward(body):
    rid = (body.get("id") or "").strip()
    if not rid:
        raise ValueError("id is required")
    rules = _load_pf()
    target = next((r for r in rules if r["id"] == rid), None)
    if not target:
        raise ValueError("Rule not found")
    _remove_pf_rule(target)
    _save_pf([r for r in rules if r["id"] != rid])
    return {"ok": True}


def toggle_portforward(body):
    rid = (body.get("id") or "").strip()
    if not rid:
        raise ValueError("id is required")
    rules = _load_pf()
    target = next((r for r in rules if r["id"] == rid), None)
    if not target:
        raise ValueError("Rule not found")
    if target["enabled"]:
        _remove_pf_rule(target)
        target["enabled"] = False
    else:
        _apply_pf_rule(target)
        target["enabled"] = True
    _save_pf(rules)
    return {"ok": True, "enabled": target["enabled"]}


# ── DMZ ──────────────────────────────────────────────────────────────────────

def _load_dmz():
    try:
        with open(DMZ_PERSIST) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_dmz(data):
    os.makedirs("/etc/tuxwall", exist_ok=True)
    with open(DMZ_PERSIST, "w") as f:
        json.dump(data, f, indent=2)


def _apply_dmz_isolation(ip):
    """
    Isolate a DMZ client from the rest of the LAN while allowing:
      - DMZ → gateway (DNS, DHCP, management)
      - DMZ → WAN (outbound internet)
      - WAN → DMZ (inbound, handled by port forwards)
      - established return traffic
    Blocks:
      - DMZ → any other LAN host
    """
    lan_subnet = _lan_subnet()
    gw         = _gateway_ip()
    wan        = _wan_iface()
    lan        = _lan_iface()

    # 1. Allow DMZ client to reach the gateway (DNS port 53, DHCP is broadcast, any)
    gw_args = ["-s", ip, "-d", gw, "-i", lan, "-j", "ACCEPT"]
    if not _ipt_rule_exists("filter", "FORWARD", *gw_args):
        _ipt("-I", "FORWARD", "1", *gw_args)

    # 2. Allow established/related return traffic back to DMZ client
    est_args = ["-d", ip, "-o", lan, "-m", "state",
                "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]
    if not _ipt_rule_exists("filter", "FORWARD", *est_args):
        _ipt("-I", "FORWARD", "2", *est_args)

    # 3. Allow DMZ client outbound to WAN
    wan_args = ["-s", ip, "-i", lan, "-o", wan, "-j", "ACCEPT"]
    if not _ipt_rule_exists("filter", "FORWARD", *wan_args):
        _ipt("-I", "FORWARD", "3", *wan_args)

    # 4. Block DMZ client from reaching any other LAN host (DROP, not REJECT,
    #    so port scanning the LAN from DMZ is silent)
    drop_args = ["-s", ip, "-d", lan_subnet, "-j", "DROP"]
    if not _ipt_rule_exists("filter", "FORWARD", *drop_args):
        _ipt("-A", "FORWARD", *drop_args)


def _remove_dmz_isolation(ip):
    """Remove DMZ isolation rules for a client."""
    lan_subnet = _lan_subnet()
    gw         = _gateway_ip()
    wan        = _wan_iface()
    lan        = _lan_iface()

    rules_to_remove = [
        ("filter", "FORWARD", ["-s", ip, "-d", gw, "-i", lan, "-j", "ACCEPT"]),
        ("filter", "FORWARD", ["-d", ip, "-o", lan, "-m", "state",
                               "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
        ("filter", "FORWARD", ["-s", ip, "-i", lan, "-o", wan, "-j", "ACCEPT"]),
        ("filter", "FORWARD", ["-s", ip, "-d", lan_subnet, "-j", "DROP"]),
    ]
    for table, chain, args in rules_to_remove:
        if _ipt_rule_exists(table, chain, *args):
            _ipt("-D", chain, *args, table=table, check=False)


def build_dmz():
    """Return DMZ-enabled clients merged with live lease data."""
    dmz = _load_dmz()

    # Get all known clients from leases
    leases_data = build_leases()
    clients = []
    for lease in leases_data.get("leases", []):
        ip = lease.get("ip", "")
        enabled = ip in dmz
        has_reservation = lease.get("static", False)
        clients.append({
            "ip":              ip,
            "hostname":        lease.get("hostname", ""),
            "mac":             lease.get("mac", ""),
            "online":          lease.get("online", False),
            "has_reservation": has_reservation,
            "dmz_enabled":     enabled,
            "dmz_note":        dmz.get(ip, {}).get("note", "") if enabled else "",
        })

    # Sort: DMZ-enabled first, then by IP
    clients.sort(key=lambda c: (not c["dmz_enabled"],
                                [int(x) for x in c["ip"].split(".")
                                 if x.isdigit()]))
    return {
        "ok":        True,
        "clients":   clients,
        "dmz_count": sum(1 for c in clients if c["dmz_enabled"]),
        "warning":   (
            "DMZ clients share the LAN subnet. Isolation is enforced via "
            "iptables FORWARD rules that drop DMZ→LAN traffic. The DMZ client "
            "can still reach the gateway and the internet."
        ),
    }


def enable_dmz(body):
    ip   = (body.get("ip") or "").strip()
    note = (body.get("note") or "").strip()
    if not ip:
        raise ValueError("IP is required")
    ipaddress.ip_address(ip)

    dmz = _load_dmz()
    if ip in dmz:
        return {"ok": True, "already_enabled": True}

    _apply_dmz_isolation(ip)
    dmz[ip] = {"note": note, "enabled_at": time.time()}
    _save_dmz(dmz)
    return {"ok": True}


def disable_dmz(body):
    ip = (body.get("ip") or "").strip()
    if not ip:
        raise ValueError("IP is required")

    dmz = _load_dmz()
    if ip not in dmz:
        return {"ok": True, "already_disabled": True}

    _remove_dmz_isolation(ip)
    dmz.pop(ip, None)
    _save_dmz(dmz)
    return {"ok": True}


def _restore_nat_on_boot():
    """Re-apply all stored port forward and DMZ rules on API startup."""
    # Port forwards
    for rule in _load_pf():
        if rule.get("enabled", True):
            try:
                _apply_pf_rule(rule)
            except Exception as exc:
                print(f"[boot] PF restore failed for {rule.get('id')}: {exc}", flush=True)

    # DMZ isolation
    dmz = _load_dmz()
    for ip in dmz:
        try:
            _apply_dmz_isolation(ip)
        except Exception as exc:
            print(f"[boot] DMZ restore failed for {ip}: {exc}", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# VLAN management
# ─────────────────────────────────────────────────────────────────────────────

VLAN_PERSIST_FILE = "/etc/tuxwall/vlans.json"


def _load_vlan_persist():
    """Load persisted VLAN metadata (name, policy notes)."""
    try:
        with open(VLAN_PERSIST_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_vlan_persist(data):
    os.makedirs("/etc/tuxwall", exist_ok=True)
    with open(VLAN_PERSIST_FILE, "w") as f:
        json.dump(data, f, indent=2)


def build_vlans():
    """Return all VLAN interfaces, their addresses, and inter-VLAN UFW policies."""

    # --- live interfaces via iproute2 ---
    try:
        r = subprocess.run(
            ["ip", "-j", "-d", "link", "show"],
            capture_output=True, text=True, timeout=5
        )
        links = json.loads(r.stdout or "[]")
    except Exception:
        links = []

    try:
        r = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        addrs_raw = json.loads(r.stdout or "[]")
    except Exception:
        addrs_raw = []

    addr_map = {}
    for iface in addrs_raw:
        name = iface.get("ifname", "")
        addr_map[name] = [
            f"{a['local']}/{a['prefixlen']}"
            for a in iface.get("addr_info", [])
            if a.get("family") in ("inet", "inet6")
        ]

    persist = _load_vlan_persist()

    vlans = []
    for link in links:
        li = link.get("linkinfo", {})
        if li.get("info_kind") != "vlan":
            continue
        name = link.get("ifname", "")
        vid = li.get("info_data", {}).get("id", "")
        parent = link.get("link", "")
        state = link.get("operstate", "UNKNOWN")
        mtu = link.get("mtu", "")
        addresses = addr_map.get(name, [])
        meta = persist.get(name, {})
        vlans.append({
            "iface":     name,
            "vlan_id":   vid,
            "parent":    parent,
            "state":     state,
            "mtu":       mtu,
            "addresses": addresses,
            "label":     meta.get("label", ""),
        })

    # --- physical interfaces (candidates for VLAN parent) ---
    parents = []
    for link in links:
        li = link.get("linkinfo", {})
        kind = li.get("info_kind") or ""
        if kind in ("vlan", "wireguard", "loopback", "bridge"):
            continue
        flags = link.get("flags", [])
        if "LOOPBACK" in flags:
            continue
        parents.append(link.get("ifname", ""))

    # --- inter-VLAN UFW policies stored in persist ---
    policies = persist.get("__policies__", [])

    return {"ok": True, "vlans": vlans, "parents": parents, "policies": policies}


def add_vlan(body):
    parent = (body.get("parent") or "").strip()
    try:
        vid = int(body.get("vlan_id", 0))
    except (TypeError, ValueError):
        raise ValueError("VLAN ID must be an integer")
    address = (body.get("address") or "").strip()
    label   = (body.get("label") or "").strip()

    if not parent or not vid:
        raise ValueError("parent interface and VLAN ID are required")
    if not (1 <= vid <= 4094):
        raise ValueError("VLAN ID must be 1–4094")
    if address:
        ipaddress.ip_interface(address)   # validate

    iface = f"{parent}.{vid}"

    # Create the VLAN interface
    subprocess.run(
        ["ip", "link", "add", "link", parent, "name", iface, "type", "vlan", "id", str(vid)],
        check=True, capture_output=True, text=True, timeout=10
    )
    if address:
        subprocess.run(
            ["ip", "addr", "add", address, "dev", iface],
            check=True, capture_output=True, text=True, timeout=10
        )
    subprocess.run(
        ["ip", "link", "set", iface, "up"],
        check=True, capture_output=True, text=True, timeout=10
    )

    # Persist metadata + netplan
    persist = _load_vlan_persist()
    persist[iface] = {"label": label, "address": address, "vlan_id": vid, "parent": parent}
    _save_vlan_persist(persist)
    _vlan_netplan_sync(persist)

    return {"ok": True, "iface": iface}


def edit_vlan(body):
    iface   = (body.get("iface") or "").strip()
    address = (body.get("address") or "").strip()
    label   = (body.get("label") or "").strip()

    if not iface:
        raise ValueError("iface is required")
    if address:
        ipaddress.ip_interface(address)

    persist = _load_vlan_persist()

    # Replace addresses on the interface
    try:
        r = subprocess.run(
            ["ip", "-j", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5
        )
        existing = json.loads(r.stdout or "[]")
        for entry in existing:
            for a in entry.get("addr_info", []):
                if a.get("family") == "inet":
                    subprocess.run(
                        ["ip", "addr", "del", f"{a['local']}/{a['prefixlen']}", "dev", iface],
                        capture_output=True, text=True, timeout=10
                    )
    except Exception:
        pass

    if address:
        subprocess.run(
            ["ip", "addr", "add", address, "dev", iface],
            check=True, capture_output=True, text=True, timeout=10
        )

    meta = persist.get(iface, {})
    meta["label"]   = label
    meta["address"] = address
    persist[iface]  = meta
    _save_vlan_persist(persist)
    _vlan_netplan_sync(persist)

    return {"ok": True}


def delete_vlan(body):
    iface = (body.get("iface") or "").strip()
    if not iface:
        raise ValueError("iface is required")

    subprocess.run(
        ["ip", "link", "set", iface, "down"],
        capture_output=True, text=True, timeout=10
    )
    subprocess.run(
        ["ip", "link", "delete", iface],
        check=True, capture_output=True, text=True, timeout=10
    )

    persist = _load_vlan_persist()
    persist.pop(iface, None)
    _save_vlan_persist(persist)
    _vlan_netplan_sync(persist)

    return {"ok": True}


def add_vlan_policy(body):
    src  = (body.get("src") or "").strip()
    dst  = (body.get("dst") or "").strip()
    policy = (body.get("policy") or "deny").strip().lower()
    proto  = (body.get("proto") or "any").strip()
    port   = (body.get("port") or "").strip()

    if not src or not dst:
        raise ValueError("src and dst interfaces are required")
    if policy not in ("allow", "deny"):
        raise ValueError("policy must be allow or deny")

    # Build UFW rule
    port_part  = f" port {port}" if port and port != "any" else ""
    proto_part = f" proto {proto}" if proto and proto != "any" else ""
    rule = f"{policy} in on {src} out on {dst}{port_part}{proto_part}"
    add_firewall_rule(rule)

    persist = _load_vlan_persist()
    policies = persist.get("__policies__", [])
    policies.append({
        "id":     str(uuid4())[:8],
        "src":    src,
        "dst":    dst,
        "policy": policy,
        "proto":  proto,
        "port":   port,
        "rule":   rule,
    })
    persist["__policies__"] = policies
    _save_vlan_persist(persist)

    return {"ok": True}


def delete_vlan_policy(body):
    pid = (body.get("id") or "").strip()
    if not pid:
        raise ValueError("policy id is required")

    persist = _load_vlan_persist()
    policies = persist.get("__policies__", [])
    target = next((p for p in policies if p["id"] == pid), None)
    if not target:
        raise ValueError("policy not found")

    # Remove from UFW by matching rule text
    try:
        r = subprocess.run(
            ["ufw", "status", "numbered"],
            capture_output=True, text=True, timeout=8
        )
        for line in reversed(r.stdout.splitlines()):
            m = re.match(r"\[\s*(\d+)\]", line)
            if m and target["src"] in line and target["dst"] in line:
                subprocess.run(
                    ["ufw", "--force", "delete", m.group(1)],
                    capture_output=True, text=True, timeout=10
                )
                break
    except Exception:
        pass

    persist["__policies__"] = [p for p in policies if p["id"] != pid]
    _save_vlan_persist(persist)
    return {"ok": True}


def _vlan_netplan_sync(persist):
    """Write a netplan yaml for all persisted VLANs so they survive reboot."""
    netplan_path = "/etc/netplan/99-tuxwall-vlans.yaml"
    vlans_cfg = {}
    ethernets = set()

    for iface, meta in persist.items():
        if iface.startswith("__"):
            continue
        parent  = meta.get("parent", "")
        vid     = meta.get("vlan_id", "")
        address = meta.get("address", "")
        if not parent or not vid:
            continue
        ethernets.add(parent)
        entry = {"id": int(vid), "link": parent}
        if address:
            entry["addresses"] = [address]
        vlans_cfg[iface] = entry

    if not vlans_cfg:
        # Remove the file if no VLANs left
        try:
            os.remove(netplan_path)
        except FileNotFoundError:
            pass
        return

    lines = ["network:", "  version: 2", "  ethernets:"]
    for eth in sorted(ethernets):
        lines.append(f"    {eth}: {{optional: true}}")
    lines.append("  vlans:")
    for name, cfg in vlans_cfg.items():
        lines.append(f"    {name}:")
        lines.append(f"      id: {cfg['id']}")
        lines.append(f"      link: {cfg['link']}")
        if cfg.get("addresses"):
            lines.append(f"      addresses: [{cfg['addresses'][0]}]")

    with open(netplan_path, "w") as f:
        f.write("\n".join(lines) + "\n")


def _self_restart(signum, frame):
    """SIGUSR1 handler: re-exec the API process in-place to pick up code changes."""
    print("tuxwall API self-restarting...", flush=True)
    os.execv(sys.executable, [sys.executable] + sys.argv)


def main():
    signal.signal(signal.SIGUSR1, _self_restart)
    _ensure_service_reload()
    _ensure_unbound_local_actions()
    _restore_nat_on_boot()
    get_security_monitor()
    get_system_monitor()
    get_latency_monitor()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.daemon_threads = True
    print(f"tuxwall API listening on http://{LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
