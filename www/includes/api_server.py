#!/usr/bin/env python3
import base64
import errno
import gzip
import hashlib
import hmac
import io
import ipaddress
import itertools
import json
import mimetypes
import os
import pwd
import glob
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import OrderedDict, deque
from datetime import datetime, timezone
from uuid import uuid4
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Sibling modules live under the web root: never leave __pycache__ there.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import topology as _topology
except Exception as _exc:  # the API must still start without it
    print("tuxwall: topology module unavailable: %r" % _exc, flush=True)
    _topology = None
try:
    import fw_guard as _fw_guard
    import fw_snap as _fw_snap
except Exception as _exc:
    print("tuxwall: firewall guard/snapshot modules unavailable: %r" % _exc, flush=True)
    _fw_guard = _fw_snap = None
try:
    import backups as _bk
except Exception as _exc:
    print("tuxwall: backups module unavailable: %r" % _exc, flush=True)
    _bk = None
try:
    import fw_lint as _fw_lint
    import fw_edit as _fw_edit
    import fw_hits as _fw_hits
except Exception as _exc:
    print("tuxwall: firewall findings/edit/hits modules unavailable: %r" % _exc, flush=True)
    _fw_lint = _fw_edit = _fw_hits = None
try:
    import crowdsec_fw as _csfw
except Exception as _exc:
    print("tuxwall: crowdsec_fw module unavailable: %r" % _exc, flush=True)
    _csfw = None
try:
    import kea_conf as _kea_conf
except Exception as _exc:  # strict JSON only (no Kea comments) without it
    print("tuxwall: kea_conf module unavailable: %r" % _exc, flush=True)
    _kea_conf = None


def _topo(fn, default=""):
    """Call a topology accessor; '' (or default) when unavailable."""
    if _topology is None:
        return default
    try:
        return getattr(_topology, fn)() or default
    except Exception:
        return default

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
        kea = _read_kea()
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
    """Parsed kea-dhcp4.conf; Kea's // # /* */ comments are allowed."""
    if _kea_conf is not None:
        return _kea_conf.read(KEA_CONF)
    with open(KEA_CONF) as f:
        return json.load(f)


def _write_kea(data):
    """Atomic rewrite keeping owner/mode and the leading comment header."""
    if _kea_conf is not None:
        _kea_conf.write(KEA_CONF, data)
        return
    tmp = KEA_CONF + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=4)
    os.replace(tmp, KEA_CONF)


def _kea_leases_healthy():
    """True if Kea's lease manager answers on the control socket.

    An in-process config-reload was observed leaving the daemon alive but
    with 'no current lease manager is available' - every DHCPDISCOVER then
    fails while the service still shows active. lease4-get-all is the same
    probe the dashboard leases view uses, so a broken lease manager is
    detected immediately instead of after clients start timing out.

    Healthy = result 0 (leases listed) or 3 (empty lease DB - every fresh
    install). 1 is an error, 2 'command not supported' (lease_cmds hook not
    loaded); a timeout or socket error means Kea did not answer at all."""
    try:
        resp = kea_command("lease4-get-all")
        result = (resp[0] if resp else {}) if isinstance(resp, list) else (resp or {})
        return isinstance(result, dict) and result.get("result") in (0, 3)
    except Exception:
        return False


class KeaConfigRejected(ValueError):
    """Kea answered config-reload with a non-zero result: it keeps running
    the previous config, so the change did not take effect."""


def _reload_kea():
    """Reload Kea's config via the control socket, then verify the lease
    manager survived; fall back to a full restart if it did not.

    A plain in-process reload can drop the lease manager (see
    _kea_leases_healthy). A restart re-reads the config and re-opens the
    lease file, and is the only reliable recovery - so it is used as the
    fallback whenever the post-reload health check fails.

    Raises KeaConfigRejected (Kea's text) when Kea refuses the new config."""
    try:
        resp = kea_command("config-reload")
    except Exception:
        # Fallback: systemctl reload
        subprocess.run(
            ["systemctl", "reload-or-restart", "kea-dhcp4-server"],
            capture_output=True, text=True, timeout=15
        )
    else:
        result = (resp[0] if resp else {}) if isinstance(resp, list) else (resp or {})
        if not isinstance(result, dict) or result.get("result") != 0:
            code = result.get("result") if isinstance(result, dict) else None
            text = (result.get("text") if isinstance(result, dict) else "") or "no reason given"
            raise KeaConfigRejected(
                "Kea rejected the new config (result %s): %s" % (code, text))
    if _kea_leases_healthy():
        return
    # Lease manager dropped (or reload never landed) - full restart
    subprocess.run(
        ["systemctl", "restart", "kea-dhcp4-server"],
        capture_output=True, text=True, timeout=45
    )
    # The control socket needs a moment after a restart
    import time as _time
    for _ in range(10):
        if _kea_leases_healthy():
            return
        _time.sleep(1)
    raise RuntimeError(
        "Kea reload left the lease manager broken (restart did not recover)")


def _restore_kea_text(text):
    """Put previous kea-dhcp4.conf content back (atomic, owner/mode kept)."""
    st = os.stat(KEA_CONF)
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(KEA_CONF) + ".", suffix=".tmp",
                               dir=os.path.dirname(KEA_CONF))
    try:
        os.fchmod(fd, st.st_mode & 0o7777)
        if (st.st_uid, st.st_gid) != (os.geteuid(), os.getegid()):
            os.fchown(fd, st.st_uid, st.st_gid)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, KEA_CONF)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write_reload_kea(data):
    """_write_kea + _reload_kea as one step: when Kea rejects the new config
    the previous file is restored and reloaded, and KeaConfigRejected
    (a ValueError carrying Kea's text) reaches the caller."""
    try:
        with open(KEA_CONF) as f:
            previous = f.read()
    except OSError:
        previous = None
    _write_kea(data)
    try:
        _reload_kea()
    except KeaConfigRejected as exc:
        if previous is None:
            raise
        _restore_kea_text(previous)
        try:
            _reload_kea()
        except Exception as again:
            raise KeaConfigRejected(
                "%s - previous config restored, but its reload failed: %s" % (exc, again))
        raise KeaConfigRejected("%s - previous config restored, nothing changed" % exc)


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
        _write_reload_kea(kea)

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

        _write_reload_kea(kea)

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

        _write_reload_kea(kea)

    return build_reservations()


def kea_reservations():
    """Static reservations defined in kea-dhcp4.conf."""
    try:
        kea = _read_kea()
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
        # 2026-11-08: Kea's memfile flips a lease to expired-reclaimed
        # (state 2) only lazily - a dead client's lease can sit at state 0
        # long past its expiry and show as a live client forever. Judge by
        # the lease's own clock: a lease past expiry is gone, whatever the
        # state byte says. (Live clients renew at T1, long before expiry.)
        if expires and expires <= now:
            continue
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
            # real ARP presence (cached 30s), not an assumption: a lease
            # says "holds an address", not "is on the network right now"
            "online": arp_online(lease.get("ip-address", "")),
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


# Services that conflict with Tuxwall's core stack and must NOT run on a
# gateway. The unified installer disables them on fresh installs, but an
# apt upgrade or
# a dependency package (libvirt pulls dnsmasq in, etc.) can quietly bring
# them back. This table drives the dashboard banner warning; the backend
# reports the live intersection so the client never hardcodes the list.
KNOWN_CONFLICT_SERVICES = {
    "systemd-resolved.service": (
        "systemd-resolved",
        "it binds ::1:53 and evicts unbound's IPv6 listener, breaking LAN "
        "IPv6 DNS. Disable it: sudo systemctl disable --now systemd-resolved"),
    "dnsmasq.service": (
        "dnsmasq",
        "it binds ports 53 and 67, conflicting with unbound (DNS) and kea "
        "(DHCP). Disable it: sudo systemctl disable --now dnsmasq"),
    "isc-dhcp-server.service": (
        "isc-dhcp-server",
        "it binds port 67, conflicting with kea (DHCP). Disable it: "
        "sudo systemctl disable --now isc-dhcp-server"),
}


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
    active_units = {s["unit"] for s in services if s["active"] == "active"}
    conflicts = [
        {"unit": unit, "label": label, "warning": msg}
        for unit, (label, msg) in KNOWN_CONFLICT_SERVICES.items()
        if unit in active_units
    ]
    return {"ok": True, "services": services, "conflicts": conflicts}


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

    # Verbose output carries the Status/Logging/Default header lines the
    # numbered output lacks, but it also repeats every rule line without a
    # number — parsing rules from both made each rule appear twice in the
    # table. Header lines come from verbose; rules come only from numbered.
    status = ""
    logging_state = ""
    defaults = {}
    for line in ((vproc.stdout if vproc and vproc.returncode == 0 else "")
                 .splitlines()):
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

    rules = []
    for line in proc.stdout.splitlines():
        ls = line.strip()
        if not ls:
            continue
        # Column-split on 2+ spaces breaks when a long "To" value leaves
        # only one space before the action word; pivot on the action
        # keyword instead so every line parses the same way.
        m = re.match(r"^(?P<to>.+?)\s+(?P<verb>ALLOW|DENY|LIMIT|REJECT)"
                     r"(?:\s+(?P<dir>IN|OUT|FWD))?\s+(?P<from>.+)$", ls)
        if not m:
            continue
        to = m.group("to").strip()
        num = None
        nm = re.match(r"^\[\s*(\d+)\]\s+(.*)$", to)
        if nm:
            num = int(nm.group(1))
            to = nm.group(2).strip()
        action_words = ([m.group("verb"), m.group("dir")]
                        if m.group("dir") else [m.group("verb")])
        from_text = m.group("from").strip()
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
    _fw_annotate_rules(rules)

    return {
        "ok": True,
        "status": status,
        "logging": logging_state,
        "defaults": defaults,
        "rules": rules,
        "traffic": traffic,
        "counters": _firewall_counters(),
    }


_FW_COUNTER_CACHE = {"at": 0.0, "data": None}
_FW_COUNTER_LOCK = threading.Lock()


def _firewall_counters():
    """Lifetime packet/byte counters for inbound traffic (IPv4 + IPv6):
    accepted by an explicit ufw rule vs dropped by the default-deny policy.
    UFW only logs blocks, so counters are the only source for allow vs block.
    Read-only (iptables -L -v -x); cached for 10 s."""
    now = time.time()
    with _FW_COUNTER_LOCK:
        if _FW_COUNTER_CACHE["data"] is not None and now - _FW_COUNTER_CACHE["at"] < 10:
            return _FW_COUNTER_CACHE["data"]
    out = {"allowed_packets": 0, "allowed_bytes": 0,
           "blocked_packets": 0, "blocked_bytes": 0, "at": int(now), "ok": False}
    for binary, prefix in (("iptables", "ufw"), ("ip6tables", "ufw6")):
        for chain, kind in (("%s-user-input" % prefix, "allowed"),
                            ("%s-before-input" % prefix, None),
                            ("INPUT", "policy")):
            try:
                proc = subprocess.run([binary, "-w", "2", "-L", chain, "-v", "-x", "-n"],
                                      capture_output=True, text=True, timeout=5)
            except Exception:
                continue
            if proc.returncode != 0:
                continue
            lines = proc.stdout.splitlines()
            if kind == "policy":
                # "Chain INPUT (policy DROP 123 4567 bytes)" - packets the
                # default policy dropped after every ufw chain declined them.
                m = re.search(r"policy \w+ (\d+) packets?, (\d+) bytes", lines[0] if lines else "")
                if not m:
                    m = re.search(r"policy DROP (\d+) (\d+)", lines[0] if lines else "")
                if m:
                    out["blocked_packets"] += int(m.group(1))
                    out["blocked_bytes"] += int(m.group(2))
                    out["ok"] = True
                continue
            if kind is None:
                # Explicit drops in ufw-before-input (invalid packets etc.).
                for ln in lines[2:]:
                    f = ln.split()
                    if len(f) >= 3 and f[2] in ("DROP", "REJECT") and f[0].isdigit():
                        out["blocked_packets"] += int(f[0])
                        out["blocked_bytes"] += int(f[1])
                continue
            for ln in lines[2:]:
                f = ln.split()
                if len(f) >= 3 and f[2] == "ACCEPT" and f[0].isdigit():
                    out["allowed_packets"] += int(f[0])
                    out["allowed_bytes"] += int(f[1])
                    out["ok"] = True
    with _FW_COUNTER_LOCK:
        _FW_COUNTER_CACHE["at"] = now
        _FW_COUNTER_CACHE["data"] = out
    return out


def add_firewall_rule(rule_text, client_ip=""):
    """Add a ufw rule, e.g. 'allow 8080/tcp' or
    'allow in on wg0 from 10.0.0.0/24 to any port 53 proto udp'."""
    args = (rule_text or "").split()
    if not args:
        raise RuntimeError("Rule is empty")
    # Whitelist: only single-rule verbs may pass through here. Destructive /
    # global subcommands (reset, disable, enable, default, logging,
    # delete, --force, ...) must go through their dedicated API functions.
    # A leading 'route' is permitted for forwarding rules (ufw requires it
    # for in-on/out-on rules: 'route allow in on eth1 out on eth2'); the
    # token after it still has to be one of the whitelisted verbs.
    if args[0].lower() == "route":
        if len(args) < 2:
            raise RuntimeError("Rule is empty after 'route'")
        verb = args[1].lower()
    else:
        verb = args[0].lower()
    if verb not in ("allow", "deny", "reject", "limit"):
        raise RuntimeError(
            "Unsupported rule verb %r (use allow/deny/reject/limit)" % args[0])
    for tok in args:
        if tok.startswith("-"):
            raise RuntimeError("Flag-style tokens are not allowed in firewall rules")
        if any(c in tok for c in ";|&$`!(){}<>\\\n\r"):
            raise RuntimeError("Invalid character in firewall rule")
    _fw_guard_run(lambda cur: _fw_guard.proposed_add(cur, args)[0], client_ip,
                  "add " + " ".join(args))
    _ufw(args)
    return build_firewall()


def delete_firewall_rule(spec, client_ip=""):
    """Delete a ufw rule by its CONTENT, not its number.

    2026-11-09 audit: numbers in 'ufw status numbered' shift whenever any
    other component (crowdsec bouncer, tuxwall-nat, timers) touches the
    ruleset between the dashboard rendering the list and the user clicking
    delete - deleting by a stale number removes the WRONG rule. The client
    sends the rule it saw (to/action/from + its number at render time);
    we re-resolve against the CURRENT ruleset under the change lock and
    delete the rule that matches the spec. A stale number is fine (it
    just means things shifted); a stale SPEC that matches nothing is a
    clean 'already deleted' error, never a wrong-rule deletion."""
    if not isinstance(spec, dict):
        raise RuntimeError("Rule spec is incomplete")
    to = str(spec.get("to") or "").strip()
    action = str(spec.get("action") or "").strip()
    frm = str(spec.get("from") or "").strip()
    if not to or not action or not frm:
        raise RuntimeError("Rule spec is incomplete")
    with _fw_move_lock:
        proc = subprocess.run(["ufw", "status", "numbered"],
                              capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            raise RuntimeError("ufw status failed")
        found = None
        for line in proc.stdout.splitlines():
            ls = line.strip()
            m = re.match(r"^\[\s*(\d+)\]\s+(.+)$", ls)
            if not m:
                continue
            num, rest = int(m.group(1)), m.group(2)
            rm = re.match(r"^(?P<to>.+?)\s+(?P<verb>ALLOW|DENY|LIMIT|REJECT)"
                          r"(?:\s+(?P<dir>IN|OUT|FWD))?\s+(?P<from>.+)$", rest)
            if not rm:
                continue
            if (rm.group("to").strip() == to and
                    " ".join(([rm.group("verb"), rm.group("dir")]
                               if rm.group("dir") else [rm.group("verb")])).strip() == action and
                    rm.group("from").strip() == frm):
                found = num
                break  # first match: ufw CLI semantics (one rule per delete)
        if found is None:
            raise RuntimeError(
                "Rule not found in the current ruleset - it may already "
                "have been deleted. Refresh the firewall page.")
        _fw_managed_check(found, "deleted")
        _fw_guard_run(lambda cur: _fw_guard.proposed_delete(cur, found), client_ip,
                      "delete rule %d" % found)
        _ufw(["--force", "delete", str(found)])
    return build_firewall()


# --- Firewall rule reordering (ufw backend API) ----------------------------
# ufw's CLI cannot move rules (insert always appends the IPv6 half), but its
# own backend can: get_rules() returns UFWRule objects in `ufw status
# numbered` order (IPv4 list then IPv6 list), and _write_rules() +
# _reload_user_rules() persist and apply a reordered list — the same code
# path the CLI uses for every rule change. Reordering swaps two rules
# within one family list (iptables and ip6tables evaluate independently);
# when both swapped rules are dual-stack, their twins in the other family
# list are swapped as well so both rulesets stay in step.
_fw_move_lock = threading.Lock()


def _ufw_backend():
    import gettext
    import ufw.common
    import ufw.backend_iptables
    # ufw's CLI installs gettext before using the backend; imported as a
    # library that setup never runs, and any _do_checks warning or error
    # path raises NameError on '_'. Install it exactly as /usr/sbin/ufw
    # does (bound into builtins) so those paths behave normally.
    gettext.install(ufw.common.programName)
    return ufw.backend_iptables.UFWBackendIptables(dryrun=False)


def _ufw_rule_key(r):
    return (r.action, r.direction, r.forward, r.protocol, r.dport, r.sport,
            r.src, r.dst, r.interface_in, r.interface_out, r.comment)


def move_firewall_rule(number, direction, expected_spec=None, client_ip=""):
    """Swap the numbered rule with the adjacent rule in its family
    (IPv4/IPv6) list. Numbering matches `ufw status numbered`."""
    if direction not in ("up", "down"):
        raise RuntimeError("Direction must be 'up' or 'down'")
    try:
        num = int(number)
    except (TypeError, ValueError):
        raise RuntimeError("Invalid rule number")
    if num < 1:
        raise RuntimeError("Invalid rule number")

    # staleness guard (2026-11-09 audit): if the client also sends the
    # rule it SAW at this number, verify against the CURRENT numbered
    # list - the ruleset may have shifted under the UI (bouncer/timers
    # add rules). A stale number must move the RIGHT rule or refuse.
    if expected_spec:
        exp = " ".join(str(expected_spec.get(k) or "").strip()
                       for k in ("to", "action", "from"))
        proc = subprocess.run(["ufw", "status", "numbered"],
                              capture_output=True, text=True, timeout=10)
        cur = None
        for line in proc.stdout.splitlines():
            m = re.match(r"^\[\s*(\d+)\]\s+(.+)$", line.strip())
            if m and int(m.group(1)) == num:
                cur = m.group(2).strip()
                break
        if cur is None or " ".join(cur.split()) != " ".join(exp.split()):
            raise RuntimeError(
                "Ruleset changed since the page was rendered (rule %d no "
                "longer matches what you saw). Refresh the firewall page "
                "and retry." % num)

    _fw_managed_check(num, "moved")
    _fw_guard_run(lambda cur: _fw_guard.proposed_move(cur, num, direction), client_ip,
                  "move rule %d %s" % (num, direction))
    with _fw_move_lock:
        b = _ufw_backend()
        rules = b.get_rules()
        # Replicate ufw's app-profile dedup so numbers match the numbered
        # list exactly (app rules expand to several entries).
        flat, seen = [], {}
        for r in rules:
            if r.dapp or r.sapp:
                tupl = r.get_app_tuple()
                if tupl in seen:
                    continue
                seen[tupl] = True
            flat.append(r)
        if num > len(flat):
            raise RuntimeError("Rule %d not found" % num)
        rule = flat[num - 1]
        if rule.dapp or rule.sapp:
            raise RuntimeError(
                "Application-profile rules cannot be reordered here")

        fam = b.rules6 if rule.v6 else b.rules
        i = next((k for k, r in enumerate(fam) if r is rule), None)
        if i is None:
            raise RuntimeError("Rule not found in its family list")
        j = i - 1 if direction == "up" else i + 1
        if j < 0:
            raise RuntimeError("Rule is already at the top of its list")
        if j >= len(fam):
            raise RuntimeError("Rule is already at the bottom of its list")
        other = fam[j]
        if other.dapp or other.sapp:
            raise RuntimeError(
                "Cannot swap with an application-profile rule")

        fam[i], fam[j] = other, rule

        # Keep dual-stack rules in step: if both rules also exist in the
        # other family list, swap their twins too (only when unambiguous).
        note = ""
        other_list = b.rules if rule.v6 else b.rules6

        def _twin(entry):
            key = _ufw_rule_key(entry)
            hits = [k for k, r in enumerate(other_list)
                    if _ufw_rule_key(r) == key]
            return hits[0] if len(hits) == 1 else None

        t1, t2 = _twin(rule), _twin(other)
        if t1 is not None and t2 is not None:
            other_list[t1], other_list[t2] = other_list[t2], other_list[t1]
            note = " (twins in the other family list swapped to match)"
        else:
            note = " (single-family rules: other family untouched)"

        b._write_rules(v6=False)
        b._write_rules(v6=True)
        b._reload_user_rules()

    result = build_firewall()
    result["move"] = {"ok": True, "rule": num, "direction": direction,
                      "note": note}
    return result


_UFW_POLICIES = ("allow", "deny", "reject")
_UFW_LOG_LEVELS = ("off", "on", "low", "medium", "high", "full")


def set_firewall_enabled(enabled):
    """Enable or disable the ufw firewall."""
    _ufw(["--force", "enable" if enabled else "disable"])
    return build_firewall()


# --- Confirm-or-rollback for dangerous changes (2026-11-09 audit #9) -----
# A dangerous change (default policy to allow, NAT change, reset) applies
# immediately but schedules an automatic revert in 60 seconds. The user
# confirms via /api/firewall/confirm — if they can still reach the
# dashboard, one click keeps the change; if the change locked them out,
# the revert restores the previous state automatically. The same pattern
# router firmware has used for decades.
_FW_CONFIRM_LOCK = threading.Lock()
_FW_PENDING = {}  # change_id -> {"revert": callable, "expires": ts, "desc": str}


def _fw_schedule_revert(change_id, desc, revert_fn, ttl=60):
    with _FW_CONFIRM_LOCK:
        # cancel any prior pending revert of the same kind
        for k in list(_FW_PENDING):
            if _FW_PENDING[k]["desc"] == desc:
                del _FW_PENDING[k]
        _FW_PENDING[change_id] = {"revert": revert_fn, "expires": time.time() + ttl,
                                  "desc": desc, "at": time.time()}
    threading.Timer(ttl, _fw_expire, args=(change_id,)).start()


def _fw_expire(change_id):
    fn = None
    desc = ""
    with _FW_CONFIRM_LOCK:
        pending = _FW_PENDING.pop(change_id, None)
        if pending:
            fn = pending["revert"]
            desc = pending["desc"]
    if fn:
        try:
            fn()
            print("[fw] FW-CONFIRM-EXPIRED: auto-reverted '%s' (no "
                  "confirmation within 60s - the change may have locked "
                  "the admin out)" % desc, flush=True)
        except Exception as exc:
            print("[fw] FW-CONFIRM-REVERT-FAILED: %s (%s)" % (desc, exc),
                  flush=True)


def confirm_fw_change(change_id):
    """Keep a pending dangerous change — cancels its auto-revert."""
    with _FW_CONFIRM_LOCK:
        pending = _FW_PENDING.pop(change_id, None)
    if not pending:
        raise RuntimeError("No pending change to confirm (it may have "
                           "already auto-reverted — check the firewall)")
    remaining = max(0, int(pending["expires"] - time.time()))
    return {"ok": True, "confirmed": pending["desc"], "was_remaining_s": remaining}


def set_firewall_default(direction, policy, client_ip=""):
    """Set a default policy: `ufw default <policy> <direction>`.

    Setting incoming/routed to allow/accept is the classic lockout-
    yourself move, so those go through the confirm window: applied now,
    auto-reverted in 60s unless confirmed."""
    direction = (direction or "").lower()
    policy = (policy or "").lower()
    if direction not in ("incoming", "outgoing", "routed"):
        raise RuntimeError("Invalid direction (incoming/outgoing/routed)")
    if policy not in _UFW_POLICIES:
        raise RuntimeError("Invalid policy (allow/deny/reject)")
    _fw_guard_run(lambda cur: _fw_guard.proposed_default(cur, direction, policy), client_ip,
                  "default %s %s" % (policy, direction))

    dangerous = direction in ("incoming", "routed") and policy in ("allow", "accept")
    if dangerous:
        prev = build_firewall().get("defaults", {}).get(direction, "deny")
        def revert():
            _ufw(["default", prev, direction])
        change_id = "fwdefault:%s:%s" % (direction, policy)
        _fw_schedule_revert(change_id, "default %s -> %s" % (direction, policy), revert)
    _ufw(["default", policy, direction])
    result = build_firewall()
    if dangerous:
        result["needs_confirmation"] = change_id
        result["confirm_within_s"] = 60
    return result


def set_firewall_logging(level):
    """Set ufw log level: off/on/low/medium/high/full."""
    level = (level or "").lower()
    if level not in _UFW_LOG_LEVELS:
        raise RuntimeError("Invalid logging level")
    _ufw(["logging", level])
    return build_firewall()


FW_BASELINE_DIR = "/etc/tuxwall/fw-baseline"


def save_firewall_baseline():
    """Snapshot the live iptables/ip6tables rulesets (filter/nat/mangle/raw)
    plus ufw status into /etc/tuxwall/fw-baseline/."""
    os.makedirs(FW_BASELINE_DIR, exist_ok=True)
    saved = {}
    for family, tool in (("iptables", "iptables-save"), ("ip6tables", "ip6tables-save")):
        proc = subprocess.run(
            [tool], capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"{tool} failed: {(proc.stderr or '').strip()}")
        path = os.path.join(FW_BASELINE_DIR, f"{family}.rules")
        with open(path, "w") as f:
            f.write(proc.stdout)
        saved[family] = path
    ufw_proc = subprocess.run(
        ["ufw", "status", "verbose"], capture_output=True, text=True, timeout=30,
    )
    with open(os.path.join(FW_BASELINE_DIR, "ufw-status.txt"), "w") as f:
        f.write(ufw_proc.stdout)
    return {"ok": True, "baseline": saved}


def _norm_ruleset(text):
    """Normalize a ruleset dump for comparison: drop comment lines and
    zero out packet/byte counters."""
    lines = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        lines.append(re.sub(r"\[\d+:\d+\]", "[0:0]", line))
    return lines


def restore_firewall_baseline():
    """Atomically restore all IPv4/IPv6 tables from the saved baseline
    using iptables-restore/ip6tables-restore, then verify the live ruleset
    matches the baseline."""
    paths = {
        "iptables": os.path.join(FW_BASELINE_DIR, "iptables.rules"),
        "ip6tables": os.path.join(FW_BASELINE_DIR, "ip6tables.rules"),
    }
    missing = [p for p in paths.values() if not os.path.isfile(p)]
    if missing:
        raise RuntimeError("Baseline not found — save a baseline first")
    for tool, path in (("iptables-restore", paths["iptables"]),
                       ("ip6tables-restore", paths["ip6tables"])):
        proc = subprocess.run(
            [tool, "--wait", "5", path],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"{tool} failed: {(proc.stderr or '').strip()}")
    verified = True
    for family, tool in (("iptables", "iptables-save"),
                         ("ip6tables", "ip6tables-save")):
        live = subprocess.run(
            [tool], capture_output=True, text=True, timeout=30,
        )
        with open(paths[family]) as f:
            if _norm_ruleset(live.stdout) != _norm_ruleset(f.read()):
                verified = False
    return {"ok": True, "restored": paths, "verified": verified}


# --- Firewall guard + snapshot history (fw_guard.py / fw_snap.py) ----------
# Every mutating firewall endpoint asks the guard first: managed rules
# (honeypot, canary, policy, WireGuard, NAT, ...) can't be deleted or moved
# from the Rules tab, and a change that adds a new critical/high invariant
# violation (lockout, WAN management port, default allow, missing deception
# or containment rules) is refused. An automatic snapshot is taken first.
class _FwRefused(Exception):
    def __init__(self, status, payload):
        Exception.__init__(self, payload.get("error", "refused"))
        self.status = status
        self.payload = payload


def _fw_ctx(client_ip="", raw=True):
    return _fw_guard.Ctx(client_ip=client_ip, raw=raw)


def _fw_guard_run(propose, client_ip, what):
    """Run the guard for a proposed change; raise _FwRefused when it blocks.
    A crash inside the guard is logged and does not block (fail-open) - the
    managed-rule lock is checked separately and fails closed."""
    if _fw_guard is None:
        return None
    try:
        ctx = _fw_ctx(client_ip)
        cur = _fw_guard.load_ruleset(ctx)
        prop = propose(cur)
        res = _fw_guard.check(cur, prop, ctx)
    except _FwRefused:
        raise
    except Exception as exc:
        print("[fw] guard error (%s): %r" % (what, exc), flush=True)
        return {"ok": True, "guard_error": str(exc)}
    if not res["ok"]:
        print("[fw] FW-GUARD-REFUSED %s: %s" % (what, res["summary"]), flush=True)
        raise _FwRefused(409, {"ok": False, "error": res["summary"], "guard": res})
    return res


def _fw_managed_check(number, verb):
    """403 when the numbered rule is managed by a TuxWall component."""
    if _fw_guard is None:
        return
    try:
        ctx = _fw_ctx(raw=False)
        rule = _fw_guard.rule_by_number(_fw_guard.load_ruleset(ctx), number)
    except Exception as exc:
        raise _FwRefused(503, {"ok": False, "error": "Firewall guard unavailable: %s" % exc})
    if rule is None:
        return
    c = _fw_guard.classify_rule(rule, ctx)
    if c["managed"]:
        raise _FwRefused(403, {"ok": False, "managed": True, "owner": c["owner"],
                               "owner_label": c["label"],
                               "error": _fw_guard.managed_refusal(c, verb)})


def _fw_annotate_rules(rules):
    """Attach owner/managed/group to the build_firewall() rows (by number)."""
    if _fw_guard is None:
        return
    try:
        ctx = _fw_ctx(raw=False)
        numbered = _fw_guard.numbered(_fw_guard.load_ruleset(ctx))
    except Exception as exc:
        print("[fw] classify failed: %r" % exc, flush=True)
        return
    for row in rules:
        n = row.get("number")
        if not n or n > len(numbered):
            continue
        r = numbered[n - 1]
        port = (row.get("port") or "").split("/")[0]
        if r["dport"] != "any" and port and port != r["dport"]:
            continue  # numbering drifted; leave the row unclassified
        c = _fw_guard.classify_rule(r, ctx)
        row.update({"owner": c["owner"], "managed": c["managed"], "owner_label": c["label"],
                    "owner_reason": c["reason"], "group": c["group"]})


def _fw_autosnap(reason, identity=None):
    if _fw_snap is None:
        return None
    try:
        return _fw_snap.create(_fw_ctx(raw=False), kind="auto", reason=reason,
                               who=(identity or {}).get("username", ""),
                               version=TUXWALL_VERSION, dedupe=True)
    except Exception as exc:
        print("[fw] auto snapshot failed (%s): %r" % (reason, exc), flush=True)
        return None


def _fw_reapply_owned():
    """Owned raw rules from their CURRENT configs, after a ufw reload. The
    CrowdSec chain is left to the bouncer; ufw-file rules (honeypot, canary,
    policy, ...) were merged into the restored files by fw_snap."""
    hooks = []
    if os.path.exists("/etc/wireguard/wg0.conf"):
        hooks.append(("WireGuard routing", ensure_wg_routing))
    hooks.append(("Port forwards / DMZ", _restore_nat_on_boot))
    if os.path.exists("/usr/local/sbin/tuxwall-nat-ensure"):
        hooks.append(("NAT (tuxwall-nat-ensure)", lambda: subprocess.run(
            ["/usr/local/sbin/tuxwall-nat-ensure"], capture_output=True, timeout=30)))
    try:
        with open(TRIPWIRE_STATE) as f:
            tripped = bool(json.load(f).get("tripped"))
    except Exception:
        tripped = False
    if tripped:
        hooks.append(("Tripwire lockdown", lambda: subprocess.run(
            ["/usr/local/sbin/tuxwall-tripwire", "enforce"], capture_output=True, timeout=30)))
    return hooks


def _fw_snap_schedule(change_id, desc, revert_fn, ttl):
    _fw_schedule_revert(change_id, desc, revert_fn, ttl)


def fw_snapshot_get(path, identity, client_ip=""):
    """GET /api/firewall/snapshots[/<id>/diff|/<id>/download|/<id>/plan]."""
    if _fw_snap is None:
        return 503, {"ok": False, "error": "Snapshot module unavailable"}
    ctx = _fw_ctx(client_ip)
    parts = path.rstrip("/").split("/")[4:]  # after /api/firewall/snapshots
    try:
        if not parts:
            return 200, _fw_snap.listing(ctx)
        if parts[0] == "legacy" and len(parts) == 2 and parts[1] == "plan":
            p = _fw_snap.legacy_restore_plan(ctx)
            p.pop("files", None)
            return 200, p
        if len(parts) == 2 and parts[1] == "diff":
            return 200, _fw_snap.diff(ctx, parts[0])
        if len(parts) == 2 and parts[1] == "plan":
            return 200, _fw_snap._public(_fw_snap.plan_restore(ctx, parts[0]))
        if len(parts) == 2 and parts[1] == "download":
            data, name = _fw_snap.download(ctx, parts[0])
            return 200, ("__bytes__", data, name)
        return 404, {"ok": False, "error": "Unknown snapshot endpoint"}
    except _fw_snap.Refused as exc:
        return exc.status, exc.payload


def fw_snapshot_post(path, body, identity, client_ip=""):
    """POST /api/firewall/snapshots (create), /upload, /import-legacy,
    /<id>/restore {dry_run}, /<id>/delete."""
    if _fw_snap is None:
        return 503, {"ok": False, "error": "Snapshot module unavailable"}
    who = (identity or {}).get("username", "")
    ctx = _fw_ctx(client_ip)
    parts = path.rstrip("/").split("/")[4:]
    try:
        if not parts:
            m = _fw_snap.create(ctx, note=str(body.get("note") or "")[:200], kind="manual",
                                who=who, version=TUXWALL_VERSION)
            return 200, {"ok": True, "snapshot": m}
        if parts == ["upload"]:
            return 200, _fw_snap.upload(ctx, body.get("data") or "", note=str(body.get("note") or "")[:200],
                                        who=who, version=TUXWALL_VERSION)
        if parts == ["import-legacy"]:
            return 200, _fw_snap.import_legacy(ctx, who=who, version=TUXWALL_VERSION)
        if len(parts) == 2 and parts[1] == "delete":
            return 200, _fw_snap.delete(ctx, parts[0])
        if len(parts) == 2 and parts[1] == "restore":
            if body.get("dry_run", True):
                return 200, dict(_fw_snap._public(_fw_snap.plan_restore(ctx, parts[0])), dry_run=True)
            with _fw_move_lock:
                res = _fw_snap.restore(ctx, parts[0], who=who, version=TUXWALL_VERSION,
                                       reapply=_fw_reapply_owned(), schedule=_fw_snap_schedule)
            print("[fw] FW-SNAPSHOT-RESTORE %s by %s (confirm id %s)" % (
                parts[0], who, res.get("needs_confirmation")), flush=True)
            return 200, res
        return 404, {"ok": False, "error": "Unknown snapshot endpoint"}
    except _fw_snap.Refused as exc:
        return exc.status, exc.payload


def fw_legacy_restore(identity, client_ip=""):
    """The old 'Restore baseline' button. Never a raw restore of all tables:
    with snapshot history present it points there; otherwise the legacy raw
    baseline is restored (user chains only, confirm-or-revert) only if the
    guard finds no managed rule it would roll back."""
    if _fw_snap is None:
        return 503, {"ok": False, "error": "Snapshot module unavailable"}
    ctx = _fw_ctx(client_ip)
    snaps = [m for m in _fw_snap.list_snaps(ctx) if m.get("restorable", True)]
    if snaps:
        return 409, {"ok": False, "use_snapshots": True, "latest": snaps[0],
                     "error": "Restores now go through Firewall → Settings → Snapshots (preview, guard, "
                              "60 s confirm). The legacy raw baseline is no longer restored directly."}
    try:
        return 200, _fw_snap.legacy_restore(ctx, who=(identity or {}).get("username", ""),
                                            version=TUXWALL_VERSION, schedule=_fw_snap_schedule)
    except _fw_snap.Refused as exc:
        return exc.status, exc.payload


def fw_managed_view(client_ip=""):
    if _fw_guard is None:
        return 503, {"ok": False, "error": "Guard module unavailable"}
    ctx = _fw_ctx(client_ip)
    return 200, _fw_guard.summary(_fw_guard.load_ruleset(ctx), ctx)


# --- Findings, suggestions, hit counters, guarded edit/toggle (fw_lint, fw_edit,
# fw_hits). Everything here is read-only except /api/firewall/apply, which goes
# through the guard, an auto snapshot and the 60 s confirm-or-revert window.
_FW_LINT_CACHE = {}
_FW_LINT_LOCK = threading.Lock()


def _fw_ufw_log_tail(limit=1048576):
    try:
        with open("/var/log/ufw.log", "r", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - limit))
            return f.read()
    except OSError:
        return ""


def fw_findings_view(kind, client_ip=""):
    """GET /api/firewall/findings | /api/firewall/suggestions (cached 15 s)."""
    if _fw_lint is None or _fw_guard is None:
        return 503, {"ok": False, "error": "Findings module unavailable"}
    key = (kind, client_ip)
    with _FW_LINT_LOCK:
        hit = _FW_LINT_CACHE.get(key)
        if hit and time.time() - hit[0] < 15:
            return 200, hit[1]
    ctx = _fw_ctx(client_ip)
    rs = _fw_guard.load_ruleset(ctx)
    if kind == "findings":
        hits = _fw_hits.state_by_key(ctx, rs) if _fw_hits else None
        items = _fw_lint.findings(rs, ctx, hits=hits)
        counts = {s: 0 for s in _fw_guard.SEVERITIES}
        for f in items:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        res = {"ok": True, "findings": items, "counts": counts, "generated": int(time.time())}
    else:
        res = {"ok": True, "suggestions": _fw_lint.suggestions(rs, ctx, _fw_ufw_log_tail()),
               "generated": int(time.time())}
    with _FW_LINT_LOCK:
        _FW_LINT_CACHE[key] = (time.time(), res)
    return 200, res


def fw_hits_view():
    if _fw_hits is None or _fw_guard is None:
        return 503, {"ok": False, "error": "Hit counters unavailable"}
    ctx = _fw_ctx(raw=False)
    rs = _fw_guard.load_ruleset(ctx, raw={})
    res = _fw_hits.view(ctx, rs)
    rules = _fw_guard.numbered(rs)
    for row in res["rules"]:
        r = rules[row["number"] - 1]
        row["text"] = r["text"]
        if _fw_edit is not None:
            row["plain"] = _fw_edit.plain(r, ctx)
    return 200, res


def fw_disabled_view():
    if _fw_edit is None:
        return 503, {"ok": False, "error": "Edit module unavailable"}
    ctx = _fw_ctx(raw=False)
    out = []
    for r in _fw_edit.load_disabled(ctx):
        p = _fw_guard.parse_tuple(r["tuple"], r["family"])
        out.append({"id": r["id"], "group": r.get("group"), "family": r["family"], "text": p["text"],
                    "plain": _fw_edit.plain(p, ctx), "comment": p["comment"],
                    "disabled_at": r.get("disabled_at"), "who": r.get("who", "")})
    return 200, {"ok": True, "rules": out}


def _fw_propose(ctx, rs, q, who=""):
    """(proposed ruleset, info, side files) for an edit-flow request."""
    op = str(q.get("op") or "")
    num = q.get("number")
    expect = q.get("expect") or None
    side = {}
    if op == "edit":
        prop, info = _fw_edit.propose_edit(rs, ctx, num, str(q.get("rule") or ""), expect)
    elif op == "insert":
        prop, info = _fw_edit.propose_insert(rs, ctx, str(q.get("rule") or ""), q.get("before") or None)
    elif op == "move":
        prop, info = _fw_edit.propose_move_to(rs, ctx, num, q.get("to"), expect)
    elif op == "disable":
        prop, info = _fw_edit.propose_disable(rs, ctx, num, expect, who=who)
        side[_fw_edit.DISABLED_FILE] = _fw_edit.disabled_text(_fw_edit.load_disabled(ctx) + info["records"])
    elif op == "enable":
        prop, info = _fw_edit.propose_enable(rs, ctx, str(q.get("id") or ""))
        side[_fw_edit.DISABLED_FILE] = _fw_edit.disabled_text(info["remaining"])
    else:
        raise _fw_edit.EditError(400, "Unknown operation %r" % op)
    return prop, info, side


def _fw_honeypot_plan(ctx, rs, port):
    """Guard view of adding a WAN honeypot port (preview for suggestions)."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise _fw_edit.EditError(400, "Invalid port")
    prop, info = _fw_edit.propose_insert(
        rs, ctx, "allow in on %s to any port %d proto tcp comment %s" % (ctx.wan, port, _fw_guard.HONEYPOT_TAG))
    d = _fw_edit.describe(rs, prop, info, ctx)
    probs = _fw_honeypot_port_problems(ctx, [port])
    if probs:
        d["guard"]["ok"] = False
        d["guard"]["summary"] = "Refused: " + "; ".join(probs)
    d["op"] = "honeypot-add"
    d["ports"] = sorted(set(ctx.honeypot["ports"]) | {port})
    d["actions"] = ["auto snapshot", "honeypot config: ports %s" % d["ports"],
                    "the honeypot binds %d on the WAN and opens it with a tagged ufw rule" % port]
    return d


def _fw_honeypot_port_problems(ctx, ports):
    out = []
    canary = set(_fw_guard.CANARY_PORTS)
    for p in ports:
        if p in _fw_guard.MGMT_PORTS:
            out.append("%d is a management port" % p)
        if p in canary:
            out.append("%d belongs to the canary" % p)
        for l in ctx.listeners:
            if l["port"] == p and l["proto"].startswith("tcp") and l["addr"] in ("0.0.0.0", "::", "*"):
                out.append("%s already listens on %d" % (l["proc"] or "a service", p))
        for pf in ctx.portforwards:
            if str(pf.get("ext_port")) == str(p) and pf.get("enabled", True):
                out.append("%d is a port forward" % p)
    return out


def fw_plan_view(q, client_ip=""):
    """GET /api/firewall/plan?op=edit|insert|move|disable|enable|honeypot-add (dry run)."""
    if _fw_edit is None or _fw_guard is None:
        return 503, {"ok": False, "error": "Edit module unavailable"}
    ctx = _fw_ctx(client_ip)
    rs = _fw_guard.load_ruleset(ctx)
    try:
        if q.get("op") == "honeypot-add":
            return 200, _fw_honeypot_plan(ctx, rs, q.get("port"))
        prop, info, _side = _fw_propose(ctx, rs, q)
        d = _fw_edit.describe(rs, prop, info, ctx)
        d["dry_run"] = True
        return 200, d
    except _fw_edit.EditError as exc:
        return exc.status, exc.payload


def fw_apply(body, identity, client_ip=""):
    """POST /api/firewall/apply: the guarded, confirm-or-revert edit flow."""
    if _fw_edit is None or _fw_guard is None or _fw_snap is None:
        return 503, {"ok": False, "error": "Edit module unavailable"}
    who = (identity or {}).get("username", "")
    ctx = _fw_ctx(client_ip)
    try:
        if body.get("op") == "honeypot-add":
            rs = _fw_guard.load_ruleset(ctx)
            plan = _fw_honeypot_plan(ctx, rs, body.get("port"))
            if not plan["guard"]["ok"]:
                return 409, {"ok": False, "error": plan["guard"]["summary"], "guard": plan["guard"]}
            _fw_autosnap("honeypot add port %s" % body.get("port"), identity)
            res = set_honeypot_conf({"ports": plan["ports"]})
            return (200 if res.get("ok") else 409), res
        with _fw_move_lock:
            rs = _fw_guard.load_ruleset(ctx)
            prop, info, side = _fw_propose(ctx, rs, body, who=who)
            desc = "%s %s" % (info["op"], body.get("number") or body.get("id") or body.get("rule") or "")
            res = _fw_snap.apply_files(ctx, rs, prop, desc.strip(), who=who, version=TUXWALL_VERSION,
                                       reapply=_fw_reapply_owned(), schedule=_fw_snap_schedule, side=side)
        with _FW_LINT_LOCK:
            _FW_LINT_CACHE.clear()
        print("[fw] FW-EDIT %s by %s (confirm id %s)" % (desc, who, res.get("needs_confirmation")), flush=True)
        res["plan"] = _fw_edit.describe(rs, prop, info, ctx)
        return 200, res
    except _fw_edit.EditError as exc:
        return exc.status, exc.payload
    except _fw_snap.Refused as exc:
        return exc.status, exc.payload


def _fw_hits_loop():
    time.sleep(90)
    warned = False
    while True:
        try:
            ctx = _fw_ctx(raw=False)
            rec, _mapped = _fw_hits.sample(ctx)
            _fw_hits.record(ctx, rec)
        except Exception as exc:
            if not warned:
                print("[fw] hit counter sample failed: %r" % exc, flush=True)
                warned = True
        time.sleep(_fw_hits.INTERVAL)


def _fw_nat_guard(what, body, identity):
    """Port forwards / DMZ: auto snapshot; a forward may not use a deception
    (honeypot/canary) or management port on the WAN."""
    if _fw_guard is None:
        return
    if what in ("portforward/add", "portforward/toggle"):
        port = body.get("ext_port")
        if what == "portforward/toggle":
            rid = str(body.get("id") or "")
            r = next((x for x in _load_pf() if x.get("id") == rid), None)
            port = r.get("ext_port") if r and not r.get("enabled") else None
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            port = None
        if port is not None:
            try:
                ctx = _fw_ctx(raw=False)
                dp = _fw_guard.deception_ports(_fw_guard.load_ruleset(ctx, raw={}), ctx)
            except Exception as exc:
                print("[fw] nat guard error: %r" % exc, flush=True)
                dp = {}
            hit = [k for k in dp if k.split("/")[0] == str(port)]
            if hit:
                raise _FwRefused(409, {"ok": False, "error": "Refused by the firewall guard: WAN port %d is a "
                                       "%s decoy port (%s). Pick another external port." % (
                                           port, dp[hit[0]], ", ".join(hit))})
            if port in (8008, 4096, 8744):
                raise _FwRefused(409, {"ok": False, "error": "Refused by the firewall guard: port %d is a "
                                       "TuxWall management port." % port})
    _fw_autosnap(what, identity)


def start_fw_hits_sampler():
    if _fw_hits is not None and _fw_guard is not None:
        threading.Thread(target=_fw_hits_loop, name="fw-hits", daemon=True).start()


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


_GO_DURATION_RE = re.compile(r"(-?\d+(?:\.\d+)?)(h|ms|m|s)")


def _go_duration_seconds(text):
    """'8759h54m34.5s' (cscli decision duration) -> seconds, or None."""
    parts = _GO_DURATION_RE.findall(str(text or ""))
    if not parts:
        return None
    mult = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}
    return sum(float(v) * mult[u] for v, u in parts)


def _parse_iso(ts):
    if not ts:
        return None
    text = str(ts).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


_CROWDSEC_DEC_CACHE = {"at": 0.0, "data": None, "refreshing": False}
_CROWDSEC_DEC_LOCK = threading.Lock()
# The full-list fetch is far heavier than the per-call cscli probes: with
# >10k active decisions `cscli decisions list --limit 0` needs 15-20s just
# to serialize, so a 20s cache with a 15s timeout meant every dashboard
# poll re-ran a query that could never finish - the CrowdSec panel hung
# on "Command timed out after 15 seconds" until the decision count was
# brought down. Instead: the list gets its own generous timeout, a
# refresh runs in the background when the cache ages out, and callers
# are served the last good snapshot (flagged stale) instead of an error.
_CROWDSEC_DEC_TTL = 300.0  # 2026-11-03 audit: was 60s; full-list refresh is the most expensive call
_CROWDSEC_LIST_TIMEOUT = 90  # full `decisions list --limit 0` only


_CROWDSEC_PANEL_TTL = 30.0  # 2026-11-03 audit: cache cscli-heavy panel payloads
_CROWDSEC_PANEL_LOCK = threading.Lock()
_CROWDSEC_PANEL_CACHE = {"crowdsec": None, "ban_state": None, "at": 0.0}


def _invalidate_crowdsec_panel_cache():
    with _CROWDSEC_PANEL_LOCK:
        _CROWDSEC_PANEL_CACHE["at"] = 0.0
        _CROWDSEC_PANEL_CACHE["crowdsec"] = None
        _CROWDSEC_PANEL_CACHE["ban_state"] = None


def _invalidate_crowdsec_decisions_cache():
    _invalidate_crowdsec_panel_cache()
    with _CROWDSEC_DEC_LOCK:
        _CROWDSEC_DEC_CACHE["at"] = 0.0
        _CROWDSEC_DEC_CACHE["data"] = None


def _fetch_crowdsec_active_decisions():
    """Fetch and normalise active decisions only.

    Deliberately skips the bouncer and alert listings that build_crowdsec()
    adds for the CrowdSec page. Top Attackers only needs the decision values
    to decide between Ban and Remove ban, and those extra cscli calls were
    the slow part of that probe.
    """
    try:
        proc = subprocess.run(
            # --limit 0 is essential: cscli defaults to 100 alerts, and with
            # thousands of live decisions (honeypot/canary/file bans) the
            # dashboard saw only the newest 100 - every older banlist entry
            # then wrongly showed as "not active".
            [CROWDSEC_BIN, "decisions", "list", "-o", "json", "--limit", "0"],
            capture_output=True, text=True, timeout=_CROWDSEC_LIST_TIMEOUT,
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
            # Decisions have no created_at/until of their own: inherit the
            # alert's creation time and derive expiry from the remaining
            # duration (cscli reports time left, e.g. "8759h54m34s").
            alert_created = item.get("created_at") or item.get("start_at") or ""
            for dec in item["decisions"]:
                if not isinstance(dec, dict):
                    continue
                dec = dict(dec)
                if not dec.get("created_at") and alert_created:
                    dec["created_at"] = alert_created
                if not dec.get("until"):
                    secs = _go_duration_seconds(dec.get("duration"))
                    if secs is not None:
                        dec["until"] = datetime.fromtimestamp(
                            now + secs, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                decisions.append(dec)
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
    return {"ok": True, "decisions": active}


def _start_crowdsec_dec_refresh():
    """Refresh the decision snapshot in a background thread (single-flight)."""
    with _CROWDSEC_DEC_LOCK:
        if _CROWDSEC_DEC_CACHE["refreshing"]:
            return
        _CROWDSEC_DEC_CACHE["refreshing"] = True

    def _run():
        try:
            result = _fetch_crowdsec_active_decisions()
            if result.get("ok"):
                with _CROWDSEC_DEC_LOCK:
                    _CROWDSEC_DEC_CACHE["data"] = result
                    _CROWDSEC_DEC_CACHE["at"] = time.time()
        finally:
            with _CROWDSEC_DEC_LOCK:
                _CROWDSEC_DEC_CACHE["refreshing"] = False

    threading.Thread(target=_run, daemon=True).start()


def _crowdsec_active_decisions():
    """Active decisions, cached; stale snapshots are served, never errors.

    Fresh: returned directly. Aged out but present: a background refresh
    is started and the last good snapshot is returned flagged stale - a
    slow or failing cscli must not blank the CrowdSec panel on every poll.
    Only a cold start (no snapshot yet, e.g. first call after boot) does a
    synchronous fetch, which may take a while on installs with many
    thousands of decisions.
    """
    now = time.time()
    with _CROWDSEC_DEC_LOCK:
        cached = _CROWDSEC_DEC_CACHE["data"]
        if cached is not None and now - _CROWDSEC_DEC_CACHE["at"] < _CROWDSEC_DEC_TTL:
            return cached
    if cached is None:
        result = _fetch_crowdsec_active_decisions()
        if result.get("ok"):
            with _CROWDSEC_DEC_LOCK:
                _CROWDSEC_DEC_CACHE["data"] = result
                _CROWDSEC_DEC_CACHE["at"] = time.time()
        return result
    _start_crowdsec_dec_refresh()
    out = dict(cached)
    out["stale"] = True
    return out


def build_crowdsec():
    # 2026-11-03 audit: cached - every cscli call costs a fresh LAPI login
    # (bcrypt hash) plus SQLite scans, and the dashboard polls ~every 10s.
    now = time.time()
    with _CROWDSEC_PANEL_LOCK:
        cached = _CROWDSEC_PANEL_CACHE["crowdsec"]
        if cached is not None and now - _CROWDSEC_PANEL_CACHE["at"] < _CROWDSEC_PANEL_TTL:
            return cached
    core = _crowdsec_active_decisions()
    if not core.get("ok"):
        return core
    active = core["decisions"]
    out = {
        "ok": True,
        "decisions": active,
        "active_count": len(active),
        "bans_count": len([d for d in active if d.get("type") == "ban"]),
        "bouncers": _cscli(["bouncers", "list", "-o", "json"], []) or [],
        "alerts": _cscli(["alerts", "list", "-o", "json"], []) or [],
        "enforcement": crowdsec_enforcement(),
    }
    with _CROWDSEC_PANEL_LOCK:
        _CROWDSEC_PANEL_CACHE["crowdsec"] = out
        _CROWDSEC_PANEL_CACHE["at"] = now
    return out


def build_crowdsec_ban_state():
    """Compact Ban/Unban state for Security ▸ Top Attackers.

    One decisions query plus the local permanent blocklist file, returned as
    a small list of IPs. This replaces fetching the full ~700 KB CrowdSec
    payload and the full blocklist just to label the action buttons.
    """
    now = time.time()
    with _CROWDSEC_PANEL_LOCK:
        cached = _CROWDSEC_PANEL_CACHE["ban_state"]
        if cached is not None and now - _CROWDSEC_PANEL_CACHE["at"] < _CROWDSEC_PANEL_TTL:
            return cached
    core = _crowdsec_active_decisions()
    if not core.get("ok"):
        return {"ok": False, "error": core.get("error") or "CrowdSec unavailable"}
    banned = set()
    try:
        banned.update(_read_custom_blocklist())
    except Exception:
        pass
    for d in core.get("decisions", []):
        if d.get("ip") and d.get("type") != "unban":
            banned.add(d["ip"])
    ips = sorted(banned)
    out = {"ok": True, "ips": ips, "count": len(ips)}
    with _CROWDSEC_PANEL_LOCK:
        _CROWDSEC_PANEL_CACHE["ban_state"] = out
        _CROWDSEC_PANEL_CACHE["at"] = now
    return out


BAN_DURATION_RE = re.compile(r"^\d+[mhd]$")
BAN_DURATION_SECONDS = {"m": 60, "h": 3600, "d": 86400}


def ban_crowdsec_ip(ip, duration="24h"):
    """Ban a single IP locally via `cscli decisions add` (timed local ban).

    Never reported to tuxwall.org - community data is deception-only
    (canary/honeypot), and manual bans carry contributor judgment (one bad
    ban must never reach every install pulling the community list). Rejects
    non-global (private/reserved) addresses and durations beyond 90 days."""
    ip = (ip or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "Invalid IP: %r" % ip}
    if not addr.is_global:
        return {"ok": False, "error": "Refusing to ban non-global IP %s (private/reserved)." % ip}
    duration = (duration or "").strip()
    if not BAN_DURATION_RE.match(duration):
        return {"ok": False, "error": "Duration must be like 24h, 7d, or 90d."}
    seconds = int(duration[:-1]) * BAN_DURATION_SECONDS[duration[-1]]
    if seconds > 90 * 86400:
        return {"ok": False, "error": "Duration too long (max 90d)."}
    try:
        proc = subprocess.run(
            [CROWDSEC_BIN, "decisions", "add", "--ip", ip, "--duration", duration,
             "--reason", CUSTOM_LOCAL_BAN_REASON],
            capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout or "cscli failed").strip()}
    _invalidate_crowdsec_decisions_cache()
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
    _invalidate_crowdsec_decisions_cache()
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
# a reload; sync_custom_blocklist() keeps the decisions in step with it.
CUSTOM_BLOCKLIST_FILE = "/etc/tuxwall/custom-blocklist.txt"
CUSTOM_BLOCKLIST_REASON = "custom/custom-blocklist"
CUSTOM_BLOCKLIST_DURATION = "8760h"  # 1 year
# Timed local bans (Top Attackers popup / community rows). Same tag scheme
# so the UI can tell them from scenario decisions; live only in the
# CrowdSec decision DB (no file entry, nothing reported to tuxwall.org).
CUSTOM_LOCAL_BAN_REASON = "custom/local-ban"


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
    """Status view: the custom banlist.

    Two kinds of rows, one view:
      - "permanent": file entries (1y bans kept applied and refreshed by
        sync_custom_blocklist), shown even if their decision has lapsed
        ("not active" until the next sync re-applies it).
      - "timed": custom/local-ban decisions made from Top Attackers or the
        community tab. They live only in the CrowdSec decision DB and
        expire on their own - once expired they are gone from this view.
    Nothing here is ever reported to tuxwall.org."""
    entries = _read_custom_blocklist()
    active = {}
    timed = {}
    cs = _crowdsec_active_decisions()
    if cs.get("ok"):
        for d in cs.get("decisions", []):
            if d.get("ip") and d.get("scenario") == CUSTOM_BLOCKLIST_REASON:
                active[d["ip"]] = d
            elif d.get("ip") and d.get("scenario") == CUSTOM_LOCAL_BAN_REASON:
                timed[d["ip"]] = d
    rows = []
    for e in entries:
        d = active.get(e)
        rows.append({
            "value": e,
            "kind": "permanent",
            "duration": "1y",
            "banned": bool(d),
            "until": (d or {}).get("until") or "",
            "until_ts": (d or {}).get("until_ts"),
            "simulated": bool((d or {}).get("simulated")),
        })
    # Timed local bans that are not also permanent file entries
    for ip, d in timed.items():
        if ip in entries:
            continue
        rows.append({
            "value": ip,
            "kind": "timed",
            "duration": "timed",
            "banned": True,
            "until": d.get("until") or "",
            "until_ts": d.get("until_ts"),
            "simulated": bool(d.get("simulated")),
        })
    return {
        "ok": True,
        "file": CUSTOM_BLOCKLIST_FILE,
        "entries": rows,
        "active_count": len(active) + len(timed),
    }


def _apply_blocklist_decision(parsed):
    """Create the long-lived CrowdSec decision for a banlist entry."""
    args = [CROWDSEC_BIN, "decisions", "add"]
    if parsed["type"] == "range":
        args += ["--range", parsed["value"]]
    else:
        args += ["--ip", parsed["value"]]
    args += ["--duration", CUSTOM_BLOCKLIST_DURATION, "--reason", CUSTOM_BLOCKLIST_REASON]
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                               timeout=CROWDSEC_TIMEOUT)
    except Exception as exc:
        return {"ok": False, "warning": str(exc)}
    if proc.returncode != 0:
        return {"ok": False, "warning": (proc.stderr or proc.stdout or "cscli failed").strip()}
    _invalidate_crowdsec_decisions_cache()
    return {"ok": True}


def add_custom_blocklist_entry(value):
    """Add an entry to the list and create a matching long-lived CrowdSec ban.

    Idempotent: re-adding an entry already in the file re-applies the 1y
    ban if it is not active instead of dead-ending (the old "already on
    the blocklist" error is what left stale "not active" rows with no way
    to revive them) - via the sync, so a live ban is never duplicated."""
    parsed, err = _parse_blocklist_entry(value)
    if err:
        return {"ok": False, "error": err}
    entry = parsed["value"]
    with _CUSTOM_BLOCKLIST_SYNC_LOCK:
        return _add_custom_blocklist_entry_locked(parsed, entry)


def _add_custom_blocklist_entry_locked(parsed, entry):
    if entry in _read_custom_blocklist():
        # Already listed - make sure the ban is actually alive.
        result = sync_custom_blocklist()
        if not result.get("ok") or result.get("failed"):
            return {"ok": True, "warning": result.get("error") or "; ".join(result.get("failed") or []),
                    "message": "%s is already on the banlist; the 1y ban re-apply failed "
                               "(the background sync retries it)." % entry}
        key = _custom_blocklist_key(entry)
        if key in [_custom_blocklist_key(v) for v in result.get("protected", [])]:
            return {"ok": True, "message": "%s is already on the banlist; it is inside a protected "
                                           "CDN/infrastructure range, so it is not re-applied "
                                           "automatically." % entry}
        if key in [_custom_blocklist_key(v) for v in result.get("add", [])]:
            return {"ok": True, "message": "%s is already on the banlist - 1y ban re-applied." % entry}
        return {"ok": True, "message": "%s is already on the banlist - its 1y ban is active." % entry}
    if not _append_custom_blocklist_entry(entry):
        return {"ok": False, "error": "Could not write %s." % CUSTOM_BLOCKLIST_FILE}
    result = _apply_blocklist_decision(parsed)
    if not result.get("ok"):
        return {"ok": True, "warning": result.get("warning"),
                "message": "Added %s to the list, but the CrowdSec ban failed." % entry}
    # Deliberately NOT reported to tuxwall.org: community data is
    # deception-only (canary/honeypot). Blocklist adds are user judgment
    # and could break services on every install if one leaked into the
    # community list.
    return {"ok": True, "message": "Added %s to the banlist (1y ban)." % entry}


def remove_custom_blocklist_entry(value):
    """Drop an entry from the banlist and delete its CrowdSec decisions.

    File entries follow the rewrite path; timed local bans (not in the
    file) fall back to plain decision deletion."""
    value = (value or "").strip()
    with _CUSTOM_BLOCKLIST_SYNC_LOCK:
        result = _remove_custom_blocklist_entry_locked(value)
    # `decisions delete --ip` also lifts a listed range containing the IP;
    # re-apply whatever is still on the list right away.
    if result.get("ok"):
        _custom_blocklist_sync_async()
    return result


def _remove_custom_blocklist_entry_locked(value):
    if value not in _read_custom_blocklist():
        # Not a file entry - a timed local ban. Lift the decision instead.
        data = unban_crowdsec_ip(value)
        if data.get("ok"):
            data["message"] = "Removed the timed ban for %s." % value
        return data
    if not _drop_custom_blocklist_entry(value):
        return {"ok": False, "error": "Could not write %s." % CUSTOM_BLOCKLIST_FILE}
    _invalidate_crowdsec_decisions_cache()
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


# Idempotent apply (Nov 2026). The file used to be re-read by a CrowdSec
# file acquisition (mode: cat) on every engine start/reload, which poured
# ~320 new alerts + 1y decisions each time - duplicates for IPs that were
# already banned, minutes of crowdsec CPU per boot and an ever-growing
# store. The engine no longer reads the file; this reconciles it with the
# live custom-blocklist decisions instead: only entries without an active
# ban are added, bans getting old are re-issued, and custom-blocklist bans
# whose entry left the file are lifted. Runs at API start, every
# CUSTOM_BLOCKLIST_SYNC_INTERVAL, and after dashboard removals.
CUSTOM_BLOCKLIST_DURATION_SECONDS = 8760 * 3600
# In iptables mode the firewall bouncer caps ipset timeouts at ~24.8 days
# (2147483 s) and only re-adds an IP when it sees a NEW decision, so every
# 1y ban is re-issued once it is 20 days old (the engine re-read used to do
# this as a side effect of restarts/reloads). crowdsec-dedupe collapses the
# superseded decision. In nftables mode elements carry the full duration
# and crowdsec_fw re-times elements a longer decision did not extend, so
# the refresh is redundant there but harmless.
CUSTOM_BLOCKLIST_REFRESH_AGE = 20 * 86400
CUSTOM_BLOCKLIST_SYNC_INTERVAL = 6 * 3600
CUSTOM_BLOCKLIST_SYNC_RETRY = 600
CUSTOM_BLOCKLIST_SYNC_START_DELAY = 90
CUSTOM_BLOCKLIST_IMPORT_TIMEOUT = 120
_CUSTOM_BLOCKLIST_SYNC_LOCK = threading.RLock()
_CUSTOM_BLOCKLIST_SYNC_STATE = {"last": None, "running": False}


def _custom_blocklist_key(value):
    """Canonical form for comparing file entries with decision values."""
    text = str(value or "").strip()
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _custom_blocklist_file_entries():
    """(entries, invalid, readable): parsed entries in file order (first
    occurrence wins), lines that are not a valid global IP/CIDR (reported,
    never applied), and whether the file could be read at all."""
    try:
        with open(CUSTOM_BLOCKLIST_FILE, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return [], [], False
    entries, invalid, seen = [], [], set()
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parsed, err = _parse_blocklist_entry(ln)
        if err:
            invalid.append(ln)
            continue
        key = _custom_blocklist_key(parsed["value"])
        if key not in seen:
            seen.add(key)
            entries.append(parsed)
    return entries, invalid, True


def _custom_blocklist_current_from(alerts):
    """`cscli decisions list -s custom/custom-blocklist -o json` payload ->
    {key: {"value", "scope", "id", "remaining"}}: the longest active
    custom-blocklist ban per value."""
    current = {}
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        for d in alert.get("decisions") or []:
            if not isinstance(d, dict) or d.get("scenario") != CUSTOM_BLOCKLIST_REASON \
                    or (d.get("type") or "ban") != "ban":
                continue
            duration = str(d.get("duration") or "").strip()
            remaining = _go_duration_seconds(duration)
            # a deleted/expired decision is listed with a negative duration
            if remaining is None or remaining <= 0 or duration.startswith("-"):
                continue
            key = _custom_blocklist_key(d.get("value"))
            prev = current.get(key)
            if prev is None or remaining > prev["remaining"]:
                current[key] = {"value": d.get("value") or "", "scope": d.get("scope") or "",
                                "id": d.get("id"), "remaining": remaining}
    return current


def _custom_blocklist_current():
    """Live custom-blocklist bans (see _custom_blocklist_current_from), or
    None when cscli/CrowdSec is unavailable - never an empty guess."""
    try:
        proc = subprocess.run(
            [CROWDSEC_BIN, "decisions", "list", "-s", CUSTOM_BLOCKLIST_REASON,
             "-o", "json", "--limit", "0"],
            capture_output=True, text=True, timeout=_CROWDSEC_LIST_TIMEOUT)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    try:
        parsed = json.loads(proc.stdout.strip() or "null")
    except ValueError:
        return None
    if parsed is not None and not isinstance(parsed, list):
        return None
    return _custom_blocklist_current_from(parsed)


def _custom_blocklist_protected(parsed):
    """Entry inside (or overlapping) PROTECTED_NETS - CDN/infrastructure
    ranges the engine's cdn-whitelist always refused to ban from the file,
    so the sync does not ban them either (an existing ban is left alone)."""
    try:
        net = ipaddress.ip_network(parsed["value"], strict=False)
    except (KeyError, ValueError):
        return False
    if net.num_addresses == 1:
        return _ip_in_protected(net.network_address)
    return any(net.version == p.version and net.overlaps(p) for p in PROTECTED_NETS)


def _custom_blocklist_plan(entries, current, refresh_age=CUSTOM_BLOCKLIST_REFRESH_AGE,
                           protected=_custom_blocklist_protected):
    """Pure diff. entries: parsed file entries; current: live bans by key.
    add = listed but not banned; refresh = banned, but the longest ban is
    older than refresh_age; remove = banned as custom-blocklist but no
    longer listed; protected = listed but never auto-(re)applied."""
    wanted = {}
    for parsed in entries:
        wanted.setdefault(_custom_blocklist_key(parsed["value"]), parsed)
    threshold = CUSTOM_BLOCKLIST_DURATION_SECONDS - refresh_age
    add, refresh, skipped = [], [], []
    for key, parsed in wanted.items():
        cur = current.get(key)
        if protected(parsed):
            skipped.append(parsed)
        elif cur is None:
            add.append(parsed)
        elif cur["remaining"] < threshold:
            refresh.append(parsed)
    remove = [current[k] for k in sorted(current) if k not in wanted]
    return {"add": add, "refresh": refresh, "remove": remove, "protected": skipped}


def _custom_blocklist_removal_guard(n_remove, n_current, readable):
    """None when removals may proceed, else the reason they are held back:
    an unreadable file, or a diff that would lift most of the list at once
    (a truncated/replaced file must never mass-unban)."""
    if not readable:
        return "blocklist file unreadable"
    if n_remove > 10 and n_remove * 2 > n_current:
        return "would lift %d of %d bans at once" % (n_remove, n_current)
    return None


def _custom_blocklist_import(parsed_list):
    """Ban many entries with ONE `cscli decisions import` (one alert, not
    one per entry). Returns an error string or None."""
    payload = [{
        "value": p["value"],
        "scope": "Range" if p["type"] == "range" else "Ip",
        "type": "ban",
        "duration": CUSTOM_BLOCKLIST_DURATION,
        "reason": CUSTOM_BLOCKLIST_REASON,
    } for p in parsed_list]
    try:
        proc = subprocess.run(
            [CROWDSEC_BIN, "decisions", "import", "-i", "-", "--format", "json"],
            input=json.dumps(payload), capture_output=True, text=True,
            timeout=CUSTOM_BLOCKLIST_IMPORT_TIMEOUT)
    except Exception as exc:
        return str(exc)
    if proc.returncode != 0:
        return (proc.stderr or proc.stdout or "cscli import failed").strip()
    return None


def _custom_blocklist_delete(cur):
    """Lift exactly one listed value's custom-blocklist bans (exact value +
    scenario: other scenarios' bans and containing ranges are untouched)."""
    try:
        proc = subprocess.run(
            [CROWDSEC_BIN, "decisions", "delete", "-v", cur["value"],
             "-s", CUSTOM_BLOCKLIST_REASON],
            capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT)
    except Exception as exc:
        return str(exc)
    if proc.returncode != 0:
        return (proc.stderr or proc.stdout or "cscli delete failed").strip()
    return None


def sync_custom_blocklist(dry_run=False):
    """Make the live custom-blocklist bans match the file (idempotent).

    dry_run only reports the diff. Adds and refreshes go through one
    `cscli decisions import`; removals are per value and held back by
    _custom_blocklist_removal_guard. After a refresh, crowdsec-dedupe is
    started so the superseded decisions are collapsed right away."""
    with _CUSTOM_BLOCKLIST_SYNC_LOCK:
        current = _custom_blocklist_current()
        if current is None:
            return {"ok": False, "error": "CrowdSec unavailable (cscli decisions list failed)"}
        entries, invalid, readable = _custom_blocklist_file_entries()
        plan = _custom_blocklist_plan(entries, current)
        held = _custom_blocklist_removal_guard(len(plan["remove"]), len(current), readable) \
            if plan["remove"] else None
        out = {
            "ok": True,
            "dry_run": bool(dry_run),
            "entries": len(entries),
            "active": len(current),
            "invalid": invalid,
            "add": [p["value"] for p in plan["add"]],
            "refresh": [p["value"] for p in plan["refresh"]],
            "remove": [c["value"] for c in plan["remove"]],
            "protected": [p["value"] for p in plan["protected"]],
            "remove_held": held,
            "failed": [],
        }
        if dry_run:
            return out
        to_ban = plan["add"] + plan["refresh"]
        if to_ban:
            err = _custom_blocklist_import(to_ban)
            if err:
                out["failed"].append("import: %s" % err)
        if plan["remove"] and not held:
            for cur in plan["remove"]:
                err = _custom_blocklist_delete(cur)
                if err:
                    out["failed"].append("delete %s: %s" % (cur["value"], err))
        if to_ban or (plan["remove"] and not held):
            _invalidate_crowdsec_decisions_cache()
            _crowdsec_fw_sync_async(delay=15)   # nftables mode: Range bans live in TuxWall's table
        if plan["refresh"] and not out["failed"]:
            try:
                subprocess.run(["systemctl", "start", "--no-block", "crowdsec-dedupe.service"],
                               capture_output=True, text=True, timeout=10)
            except Exception:
                pass
        out["at"] = time.time()
        _CUSTOM_BLOCKLIST_SYNC_STATE["last"] = {k: (len(v) if isinstance(v, list) else v)
                                                for k, v in out.items()}
        return out


def _custom_blocklist_sync_logged(origin):
    try:
        res = sync_custom_blocklist()
    except Exception as exc:
        print("[custom-blocklist] %s sync failed: %r" % (origin, exc), flush=True)
        return False
    if not res.get("ok"):
        print("[custom-blocklist] %s sync skipped: %s" % (origin, res.get("error")), flush=True)
        return False
    if res["add"] or res["refresh"] or res["remove"] or res["failed"]:
        print("[custom-blocklist] %s sync: %d entries, +%d added, %d refreshed, %d removed%s%s"
              % (origin, res["entries"], len(res["add"]), len(res["refresh"]),
                 0 if res["remove_held"] else len(res["remove"]),
                 " (removals held: %s)" % res["remove_held"] if res["remove_held"] else "",
                 "; failed: %s" % "; ".join(res["failed"]) if res["failed"] else ""),
              flush=True)
    return not res["failed"]


def _custom_blocklist_sync_async():
    def _run():
        _custom_blocklist_sync_logged("post-change")
    threading.Thread(target=_run, name="custom-blocklist-sync1", daemon=True).start()


def _custom_blocklist_sync_loop():
    time.sleep(CUSTOM_BLOCKLIST_SYNC_START_DELAY)
    origin = "startup"
    while True:
        if not os.path.exists(CROWDSEC_BIN):
            time.sleep(CUSTOM_BLOCKLIST_SYNC_INTERVAL)   # no CrowdSec on this install
            continue
        ok = _custom_blocklist_sync_logged(origin)
        origin = "periodic"
        time.sleep(CUSTOM_BLOCKLIST_SYNC_INTERVAL if ok else CUSTOM_BLOCKLIST_SYNC_RETRY)


def start_custom_blocklist_sync():
    if _CUSTOM_BLOCKLIST_SYNC_STATE["running"]:
        return
    _CUSTOM_BLOCKLIST_SYNC_STATE["running"] = True
    threading.Thread(target=_custom_blocklist_sync_loop, name="custom-blocklist-sync",
                     daemon=True).start()


# --- CrowdSec bouncer enforcement (nftables mode corrections) ---------------
# The nftables bouncer skips IPs already in a set, so a later, longer ban
# never extends the kernel element, and it truncates Range decisions to one
# address. crowdsec_fw.reconcile() re-times such elements (atomic
# delete+add, never resurrecting a lifted ban), re-adds elements that lapsed
# while their ban is still active, and keeps Range bans in TuxWall's own
# `inet tuxwall_crowdsec_ranges` table. In iptables mode it only removes
# that table if one is left over. Every 15 min, and shortly after
# custom-blocklist changes.
CROWDSEC_FW_SYNC_INTERVAL = 900
CROWDSEC_FW_SYNC_START_DELAY = 120
_CROWDSEC_FW_LOCK = threading.Lock()
_CROWDSEC_FW_STATE = {"running": False, "last": None, "mem": {}}


def crowdsec_fw_reconcile(origin="periodic"):
    if _csfw is None:
        return None
    try:
        with _CROWDSEC_FW_LOCK:
            res = _csfw.reconcile(_CROWDSEC_FW_STATE["mem"])
    except Exception as exc:
        print("[crowdsec-fw] %s pass failed: %r" % (origin, exc), flush=True)
        return None
    _CROWDSEC_FW_STATE["last"] = res
    if (origin == "startup" or res.get("refreshed") or res.get("refresh_failed") or res.get("readded")
            or res.get("errors") or res.get("range_table") not in ("ok", "absent")):
        print("[crowdsec-fw] %s: mode %s, re-timed %d (failed %d), re-added %d, ranges %d (table %s)%s"
              % (origin, res.get("mode") or "?", res.get("refreshed", 0), res.get("refresh_failed", 0),
                 res.get("readded", 0), res.get("ranges", 0), res.get("range_table"),
                 "; " + "; ".join(res["errors"]) if res.get("errors") else ""), flush=True)
    return res


def _crowdsec_fw_sync_async(delay=0):
    if _csfw is None:
        return
    def _run():
        if delay:
            time.sleep(delay)
        crowdsec_fw_reconcile("post-change")
    threading.Thread(target=_run, name="crowdsec-fw-sync1", daemon=True).start()


def _crowdsec_fw_loop():
    time.sleep(CROWDSEC_FW_SYNC_START_DELAY)
    origin = "startup"
    while True:
        crowdsec_fw_reconcile(origin)
        origin = "periodic"
        time.sleep(CROWDSEC_FW_SYNC_INTERVAL)


def start_crowdsec_fw_sync():
    if _csfw is None or _CROWDSEC_FW_STATE["running"]:
        return
    _CROWDSEC_FW_STATE["running"] = True
    threading.Thread(target=_crowdsec_fw_loop, name="crowdsec-fw-sync", daemon=True).start()


def crowdsec_enforcement():
    """Compact enforcement summary for the CrowdSec page (last reconcile
    pass; no firewall reads on the request path)."""
    last = _CROWDSEC_FW_STATE.get("last") or {}
    mode = last.get("mode")
    if not mode and _csfw is not None:
        mode = _csfw.read_bouncer_config().get("mode")
    out = {"mode": mode or "", "at": last.get("at")}
    if mode == "nftables":
        fams = {}
        for fam, st in (last.get("families") or {}).items():
            fams[fam] = {"table": "%s %s" % (st.get("family"), st.get("table")),
                         "present": bool(st.get("present")),
                         "elements": sum((st.get("sets") or {}).values()),
                         "sets": len(st.get("sets") or {}),
                         "hooks": [h.get("hook") for h in st.get("hooks") or []],
                         "dropped_packets": st.get("dropped", 0)}
        out.update({"families": fams, "ranges": last.get("ranges", 0),
                    "retimed": last.get("refreshed", 0), "readded": last.get("readded", 0),
                    "missing": last.get("missing", 0), "bans": last.get("bans")})
    return out


# --- Community bans (tuxwall.org) ------------------------------------------
# Server-side proxy of the public community ban list for the CrowdSec page.
# Cached so browsing the tab doesn't re-download 500+ rows on every view;
# the browser talks only to the local API. Deception-evidence only by
# policy (enforced collector-side) - see the collector's top_bans().
# Paged: the collector serves at most 5000 rows per public request and
# returns next_offset until the list is complete (all pages come from one
# 60 s server-side snapshot, checked via "generated"), so the dashboard tab
# and community-auto always see the ENTIRE published list (~12500 IPs in
# 2026-11). Older collectors without paging answer with one page and
# next_offset absent - that page is the whole list. Cached 10 minutes.
COMMUNITY_BANS_URL = "https://tuxwall.org/api/public/bans"
COMMUNITY_BANS_PAGE = 5000
COMMUNITY_BANS_MAX_PAGES = 10
COMMUNITY_BANS_TTL = 600  # seconds
COMMUNITY_BANS_MAX_BYTES = 4 * 1024 * 1024  # per page
COMMUNITY_BANS_CACHE = {"ts": 0.0, "data": None}
COMMUNITY_BANS_LOCK = threading.Lock()


def _community_stats_url():
    """Aggregate counters endpoint that sits beside the public ban list."""
    base = COMMUNITY_BANS_URL.split("?", 1)[0].rstrip("/")
    return base.rsplit("/", 1)[0] + "/stats"


def _community_reporters():
    """Distinct installs feeding the published list, or None if unknown.

    Display-only aggregate: a stats outage must never take the ban list (or
    the pane) down with it, so every failure degrades to "unknown".
    """
    try:
        req = urllib.request.Request(_community_stats_url(), headers={
            "User-Agent": "tuxwall-community-bans/1.0",
        })
        with urllib.request.urlopen(req, timeout=8) as resp:
            payload = json.loads(resp.read(65536).decode("utf-8", errors="replace"))
        count = int(payload.get("reporters"))
        return count if count >= 0 else None
    except Exception:
        return None


def _fetch_community_bans_page(offset):
    url = "%s?%s" % (COMMUNITY_BANS_URL, urllib.parse.urlencode(
        {"limit": COMMUNITY_BANS_PAGE, "offset": offset}))
    req = urllib.request.Request(url, headers={
        "User-Agent": "tuxwall-community-bans/1.0",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read(COMMUNITY_BANS_MAX_BYTES + 1)
    if len(body) > COMMUNITY_BANS_MAX_BYTES:
        raise RuntimeError("community ban list page too large")
    payload = json.loads(body.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict) or not payload.get("ok"):
        raise RuntimeError("bad payload from tuxwall.org")
    if not isinstance(payload.get("bans"), list):
        payload["bans"] = []
    return payload


def _fetch_community_bans_pages():
    """-> (first page payload, every ban row). Follows next_offset; if the
    collector's snapshot changes mid-way (new "generated"), starts over
    once so rows are never skipped or doubled."""
    for _attempt in range(2):
        first = _fetch_community_bans_page(0)
        bans = list(first["bans"])
        nxt = first.get("next_offset")
        pages = 1
        consistent = True
        while isinstance(nxt, int) and nxt > 0 and pages < COMMUNITY_BANS_MAX_PAGES:
            page = _fetch_community_bans_page(nxt)
            if page.get("generated") != first.get("generated"):
                consistent = False
                break
            bans.extend(page["bans"])
            nxt = page.get("next_offset")
            pages += 1
        if consistent:
            seen, unique = set(), []
            for b in bans:
                ip = b.get("ip") if isinstance(b, dict) else None
                if ip and ip not in seen:
                    seen.add(ip)
                    unique.append(b)
            return first, unique
    raise RuntimeError("community ban list changed while paging - retry later")


def build_community_bans():
    now = time.time()
    with COMMUNITY_BANS_LOCK:
        cached = COMMUNITY_BANS_CACHE["data"]
        if cached is not None and now - COMMUNITY_BANS_CACHE["ts"] < COMMUNITY_BANS_TTL:
            out = dict(cached)
            out["cached"] = True
            out["auto"] = _load_community_auto()
            return out
    try:
        payload, bans = _fetch_community_bans_pages()
        data = {
            "ok": True,
            "generated": payload.get("generated") or "",
            "total": len(bans),
            "reporters": _community_reporters(),
            # Collector-published protected-infrastructure ranges (3.2.4):
            # consulted by CommunityAutoWorker so adding protection upstream
            # never requires a client release. Old collectors omit it -> [].
            "protected": payload.get("protected") or [],
            "bans": bans,
        }
    except Exception as exc:
        # Serve stale cache if we have it, else surface the error
        with COMMUNITY_BANS_LOCK:
            stale = COMMUNITY_BANS_CACHE["data"]
        if stale is not None:
            out = dict(stale)
            out["cached"] = True
            out["stale"] = True
            out["auto"] = _load_community_auto()
            return out
        return {"ok": False, "error": "tuxwall.org unreachable: %s" % exc,
                "bans": []}
    with COMMUNITY_BANS_LOCK:
        COMMUNITY_BANS_CACHE["ts"] = now
        COMMUNITY_BANS_CACHE["data"] = data
    out = dict(data)
    out["cached"] = False
    out["auto"] = _load_community_auto()
    return out


# --- Community sharing registration (tuxwall.org) -------------------------
# Key-only registration so an install's deception evidence becomes
# "trusted" after TRUST_SECONDS (collector-side). These endpoints send
# ONLY the locally generated key - no IPs, no logs, nothing else.
# NOTE: the register URL is derived lazily (in _reporting_register_url)
# because REPORTING_DEFAULT_URL is defined further down in this file -
# computing it at module level caused a NameError crash loop.


def _reporting_register_url():
    """tuxwall.org /register endpoint, derived from the configured
    report URL so a custom reporting host carries over."""
    conf = load_reporting_conf()
    base = (conf.get("url") or REPORTING_DEFAULT_URL).rstrip("/")
    return base.rsplit("/", 1)[0] + "/register"


def _reporting_key():
    """The local install key, created on first use if needed."""
    conf = load_reporting_conf()
    if not conf["key"]:
        conf = ensure_reporting_key()
    return conf["key"]


def _register_post(body):
    """POST to tuxwall.org /register with the key in the JSON body (never
    in a URL - URLs end up in access logs). Goes through the reporting
    path's single send function. -> (http status, parsed dict)."""
    return _report_http_post(
        _reporting_register_url(), json.dumps(body).encode("utf-8"),
        {"Content-Type": "application/json", "User-Agent": "tuxwall-report/1.0",
         "X-Tuxwall-Version": TUXWALL_VERSION},
        REPORTING_TIMEOUT)


def _registration_fields(data):
    return {"status": data.get("status") or "unknown",
            "approved": bool(data.get("approved")),
            "created": data.get("created"),
            "approved_at": data.get("approved_at"),
            "trusted_after": data.get("trusted_after")}


def community_reporting_status():
    """Is this install's key registered, and approved by the tuxwall.org
    admin (pending keys report at low weight)? Pure lookup - nothing is
    reported or registered by this call."""
    key = _reporting_key()
    out = {"ok": True, "registered": False, "status": "unknown", "approved": False}
    try:
        code, data = _register_post({"key": key, "action": "status"})
        if code != 200 or not data.get("ok"):
            raise RuntimeError("HTTP %d: %s" % (code, data.get("error") or "lookup refused"))
        if data.get("found"):
            out["registered"] = True
            out.update(_registration_fields(data))
    except Exception as exc:
        out["warning"] = "tuxwall.org unreachable: %s" % exc
    _community_reg_store(out, key)
    return out


def community_reporting_register():
    """Register this install's key with tuxwall.org (it stays pending -
    low weight - until the tuxwall.org admin approves it). Sends ONLY the
    key and the version."""
    key = _reporting_key()
    try:
        code, data = _register_post({"key": key, "version": TUXWALL_VERSION})
        if not data.get("ok"):
            return {"ok": False, "error": data.get("error") or ("registration refused (HTTP %d)" % code)}
        _community_reg_store(dict(_registration_fields(data), ok=True, registered=True), key)
        return dict(_registration_fields(data), ok=True)
    except Exception as exc:
        return {"ok": False, "error": "tuxwall.org unreachable: %s" % exc}


# --- Community auto-ban (tuxwall.org intel -> local enforcement) ---------
# Optional mode for the Community Bans tab: when enabled, a background
# worker keeps EVERY listed community IP banned locally (90d decisions,
# tagged custom/local-ban, never reported). Diff-based: each pass only
# adds IPs that don't already have an active decision, and 90d expiry
# self-cleans IPs that fall off the community list.
COMMUNITY_AUTO_STATE = "/etc/tuxwall/community-auto.json"
COMMUNITY_AUTO_INTERVAL = 600   # seconds between sync passes
COMMUNITY_AUTO_BATCH = 800      # max cscli calls per pass (keeps passes short)
COMMUNITY_AUTO_LOCK = threading.Lock()


def _load_community_auto():
    state = {"enabled": False, "last_sync": 0, "last_pass_added": 0,
             "added_total": 0, "pending": 0}
    try:
        with open(COMMUNITY_AUTO_STATE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            for k in state:
                if k in data:
                    state[k] = data[k]
    except (OSError, ValueError):
        pass
    return state


def _save_community_auto(state):
    tmp = COMMUNITY_AUTO_STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, COMMUNITY_AUTO_STATE)


def set_community_auto(enabled):
    """Toggle automatic community banning. Takes effect immediately (the
    worker wakes within ~30s; enabling forces a pass on the next tick)."""
    with COMMUNITY_AUTO_LOCK:
        state = _load_community_auto()
        state["enabled"] = bool(enabled)
        if enabled and not state.get("last_sync"):
            state["last_sync"] = 0  # force an immediate first pass
        _save_community_auto(state)
    return {"ok": True, "auto": state}


# Protected infrastructure ranges (keep in sync with the collector and
# nginx/tuxwall-org.conf for the CF part). Never locally banned from
# COMMUNITY intel: community-auto bans every listed IP regardless of tier,
# so a poisoned feed entry here would cut this box off from tuxwall.org,
# every CF-fronted SaaS (opencode.ai included) or the model API. Locally
# OBSERVED attacks from these ranges are still handled by the normal
# canary/honeypot path - only remote feed enforcement skips them.
# 3.2.4: consumers also honor the collector-published list
# (docs/whitelist-design.md) - protection updates need no client release.
PROTECTED_NETS = tuple(ipaddress.ip_network(n) for n in (
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
    "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "160.79.104.0/24",     # Anthropic api.anthropic.com (not CF-fronted)
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
))


def _ip_in_published(value, networks):
    """True when `value` falls in a collector-published protected range."""
    try:
        addr = _plain_ip(ipaddress.ip_address(str(value)))
    except ValueError:
        return False
    return any(addr in net for net in networks)


def _ip_in_protected(value):
    try:
        addr = _plain_ip(ipaddress.ip_address(str(value)))
    except ValueError:
        return False
    return any(addr in net for net in PROTECTED_NETS)


def _plain_ip(addr):
    """IPv4 written as IPv6 (::ffff:a.b.c.d, NAT64 64:ff9b::a.b.c.d) -> IPv4,
    so range and set checks cannot be sidestepped by the notation."""
    if addr.version == 6:
        if addr.ipv4_mapped:
            return addr.ipv4_mapped
        if addr in _NAT64_NET:
            return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr


_NAT64_NET = ipaddress.ip_network("64:ff9b::/96")


def _community_never_ban_ips():
    """Addresses this router depends on, which remote community intel must
    never ban locally: its configured DNS forwarders and NTP servers (the
    canary exemption set), its own interface addresses, default gateways,
    resolv.conf nameservers and APT mirror hosts. Read live each pass."""
    ips = set(_infra_exempt_ips())
    try:
        out = subprocess.run(["ip", "-j", "addr"], capture_output=True,
                             text=True, timeout=5).stdout
        for iface in json.loads(out or "[]"):
            for a in iface.get("addr_info", []):
                if a.get("local"):
                    ips.add(a["local"])
    except Exception:
        pass
    for fam in ("-4", "-6"):
        try:
            out = subprocess.run(["ip", "-j", fam, "route", "show", "default"],
                                 capture_output=True, text=True, timeout=5).stdout
            for r in json.loads(out or "[]"):
                if r.get("gateway"):
                    ips.add(r["gateway"])
        except Exception:
            pass
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                m = re.match(r"\s*nameserver\s+([0-9a-fA-F:.]+)", line)
                if m:
                    ips.add(m.group(1))
    except OSError:
        pass
    hosts = set()
    for path in ["/etc/apt/sources.list"] + sorted(
            os.path.join("/etc/apt/sources.list.d", n)
            for n in (os.listdir("/etc/apt/sources.list.d")
                      if os.path.isdir("/etc/apt/sources.list.d") else [])):
        try:
            with open(path) as f:
                for line in f:
                    for m in re.finditer(r"https?://([A-Za-z0-9.-]+)", line):
                        hosts.add(m.group(1).lower())
        except OSError:
            continue
    for host in sorted(hosts)[:20]:
        try:
            out = subprocess.run(["getent", "ahosts", host], capture_output=True,
                                 text=True, timeout=3).stdout
            for ln in out.splitlines():
                ips.add(ln.split()[0])
        except Exception:
            continue
    clean = set()
    for ip in ips:
        try:
            clean.add(str(_plain_ip(ipaddress.ip_address(ip.split("%")[0]))))
        except ValueError:
            continue
    return clean


class CommunityAutoWorker(threading.Thread):
    """Keeps local 90d bans in sync with the community ban list."""

    def __init__(self):
        super().__init__(name="community-auto", daemon=True)

    def run(self):
        while True:
            try:
                state = _load_community_auto()
                if state["enabled"] and time.time() - state["last_sync"] >= COMMUNITY_AUTO_INTERVAL:
                    self._pass()
            except Exception:
                pass
            time.sleep(30)

    def _pass(self):
        data = build_community_bans()   # cached (10-min TTL) - shared with UI
        cs = build_crowdsec()
        if not data.get("ok") or not cs.get("ok"):
            return  # unreachable or crowdsec down: retry next tick
        banned = set()
        for d in cs.get("decisions", []):
            if d.get("ip") and d.get("type") != "unban":
                banned.add(d["ip"])
        published = []
        for r in data.get("protected") or []:
            try:
                published.append(ipaddress.ip_network(str(r)))
            except ValueError:
                continue
        missing = []
        skipped_cf = 0
        skipped_low = 0
        skipped_infra = 0
        try:
            never_ban = _community_never_ban_ips()
        except Exception:
            never_ban = set()
        for b in data.get("bans", []):
            if not (isinstance(b, dict) and b.get("ip")):
                continue
            try:
                b = dict(b, ip=str(_plain_ip(ipaddress.ip_address(str(b["ip"])))))
            except ValueError:
                continue
            # Never ban an address this router itself depends on (its DNS
            # forwarders, NTP, gateway, own IPs, APT mirrors) - the static
            # protected ranges only cover the big public providers.
            if b["ip"] in never_ban:
                skipped_infra += 1
                continue
            # 2026-11-09 audit: the feed publishes single-reporter LOW
            # entries (the deception gate trusts self-attested evidence
            # classes). Enforce medium+ only - a forged report must clear
            # the multi-reporter trust floor to reach installs via
            # community-auto.
            if str(b.get("severity") or "low").lower() in ("low", "info"):
                skipped_low += 1
                continue
            if _ip_in_protected(b["ip"]):
                skipped_cf += 1     # never ban protected infra from remote intel
                continue
            if published and _ip_in_published(b["ip"], published):
                skipped_cf += 1     # collector-published range (3.2.4)
                continue
            if b["ip"] not in banned:
                missing.append(b["ip"])
        added = 0
        for ip in missing[:COMMUNITY_AUTO_BATCH]:
            result = ban_crowdsec_ip(ip, "90d")
            if result.get("ok"):
                added += 1
        with COMMUNITY_AUTO_LOCK:
            state = _load_community_auto()
            state["last_sync"] = time.time()
            state["last_pass_added"] = added
            state["added_total"] = (state.get("added_total") or 0) + added
            state["skipped_cf"] = skipped_cf
            state["skipped_low"] = skipped_low
            state["skipped_infra"] = skipped_infra
            state["pending"] = max(0, len(missing) - added)
            _save_community_auto(state)


_COMMUNITY_AUTO = None
_COMMUNITY_AUTO_LOCK2 = threading.Lock()


def get_community_auto_worker():
    global _COMMUNITY_AUTO
    with _COMMUNITY_AUTO_LOCK2:
        if _COMMUNITY_AUTO is None:
            _COMMUNITY_AUTO = CommunityAutoWorker()
            _COMMUNITY_AUTO.start()
        return _COMMUNITY_AUTO


# --- Security / attack map -----------------------------------------------
GEO_DB_PATH = os.path.join(BLOCKLIST_DIR, "dbip-city-lite.mmdb")
GEO_ASN_DB_PATH = os.path.join(BLOCKLIST_DIR, "dbip-asn-lite.mmdb")
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
        self._asn_reader = None
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
                try:
                    import maxminddb
                    self._asn_reader = maxminddb.open_database(GEO_ASN_DB_PATH)
                except Exception:
                    self._asn_reader = None
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
        info = {"country": "", "iso": "", "city": "", "lat": None, "lon": None,
                "asn": "", "isp": ""}
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
        if self._asn_reader is not None:
            try:
                rec = self._asn_reader.get(ip)
                if isinstance(rec, dict):
                    info["asn"] = str(rec.get("autonomous_system_number") or "")
                    info["isp"] = str(rec.get("autonomous_system_organization") or "")
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
                "asn": geo.get("asn", ""),
                "isp": geo.get("isp", ""),
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
                    "lat": e["lat"], "lon": e["lon"],
                    "asn": e.get("asn", ""), "isp": e.get("isp", ""),
                    "port": top_port,
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
    # the file AND its backup hold the API key: never world-readable
    # (2026-11-09 audit: direct-write path created them 0644)
    os.chmod(LLM_CONF_PATH, 0o600)
    if os.path.exists(bak):
        os.chmod(bak, 0o600)
    return {"ok": True, "backup": bak if os.path.exists(bak) else None}


class BoundedTTLMap:
    """Thread-safe LRU map with a per-entry TTL (from the last write) and a
    hard size cap. The deception layer keys these by attacker address, so
    they must never grow with the internet (2026-11-19: the honeypot hit
    counter and the canary dedupe map were unbounded)."""

    def __init__(self, maxlen, ttl):
        self.maxlen = max(1, int(maxlen))
        self.ttl = float(ttl)
        self._d = OrderedDict()        # key -> (written_at, value), oldest first
        self._lock = threading.Lock()
        self.evicted = 0

    def _expire(self, now):
        d = self._d
        while d:
            k = next(iter(d))
            if now - d[k][0] < self.ttl:
                break
            del d[k]
            self.evicted += 1

    def get(self, key, now=None):
        now = time.time() if now is None else now
        with self._lock:
            hit = self._d.get(key)
            if hit is None:
                return None
            if now - hit[0] >= self.ttl:
                del self._d[key]
                return None
            return hit[1]

    def set(self, key, value, now=None):
        now = time.time() if now is None else now
        with self._lock:
            self._d.pop(key, None)
            self._d[key] = (now, value)
            self._expire(now)
            while len(self._d) > self.maxlen:
                self._d.popitem(last=False)
                self.evicted += 1

    def pop(self, key, default=None):
        with self._lock:
            hit = self._d.pop(key, None)
            return default if hit is None else hit[1]

    def items(self, now=None):
        now = time.time() if now is None else now
        with self._lock:
            self._expire(now)
            return [(k, v) for k, (_, v) in self._d.items()]

    def clear(self):
        with self._lock:
            self._d.clear()

    def __len__(self):
        with self._lock:
            return len(self._d)


# --- Community ban reporting (tuxwall.org) --------------------------------
# Deception catches (honeypot + canary) are reported to the tuxwall.org
# collector, which aggregates them into the public community ban list. The
# per-install key in /etc/tuxwall/reporting.json is what lets the collector
# count *distinct* reporting installs for severity; the key is only ever sent
# over HTTPS and hashed server-side (never stored in plaintext).
#
# 2026-11-19 (deception phase 1):
#   - reporting.json "enabled" is honoured (absent = on, the historical
#     behaviour); off means nothing is queued or sent.
#   - the file holds the key: written atomically, root 0600, and only when
#     the settings change (the per-report status lives in the queue state).
#   - every report goes through a persistent retry queue
#     (/var/lib/tuxwall/report-queue.json, no key inside): network errors,
#     429 and 5xx retry with exponential backoff; refusals (4xx) are dropped.
#   - reporting_status() is the one summary for the settings UI.
REPORTING_CONF_FILE = "/etc/tuxwall/reporting.json"
REPORTING_DEFAULT_URL = "https://tuxwall.org/report"
# Tuxwall version sent with every community report/registration. tuxwall.org
# refuses reports from below MIN_REPORTER_VERSION (3.2.4) - that release is
# the one that stops consumers from ever banning Cloudflare edge IPs.
# Keep in sync with pkg/DEBIAN/control.
TUXWALL_VERSION = "3.3.4"
REPORTING_TIMEOUT = 10
REPORT_QUEUE_FILE = os.path.join(BLOCKLIST_DIR, "report-queue.json")
REPORT_QUEUE_MAX = 2000              # queued reports kept at most (oldest dropped)
REPORT_QUEUE_MAX_AGE = 7 * 86400     # stale evidence is dropped, not sent late
REPORT_RETRY_BASE = 30               # seconds; doubles per attempt
REPORT_RETRY_MAX = 3600
REPORT_BATCH = 25                    # sends per worker pass
# Maintenance pause (key rotation): while this file exists - and is younger
# than REPORT_PAUSE_MAX_AGE, so a forgotten file can't silence reporting
# for good - the worker sends nothing; reports keep queueing.
REPORT_PAUSE_FILE = os.path.join(BLOCKLIST_DIR, "report-queue.pause")
REPORT_PAUSE_MAX_AGE = 1800
_report_status_lock = threading.Lock()


def load_reporting_conf():
    conf = {
        "enabled": True,
        "url": REPORTING_DEFAULT_URL,
        "key": "",
    }
    try:
        with open(REPORTING_CONF_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            conf["enabled"] = bool(data.get("enabled", True))
            url = str(data.get("url") or "").strip().rstrip("/")
            if url:
                conf["url"] = url
            conf["key"] = str(data.get("key") or "")
    except (OSError, ValueError):
        pass
    return conf


def _mask_key(key):
    if len(key) > 8:
        return key[:4] + "****" + key[-4:]
    return "****" if key else ""


def _write_private_json(path, data):
    """Atomic root-only write: temp file (mkstemp = 0600) in the same
    directory, fsync, rename. The reporting key never sits in a 0644 file
    or a half-written one."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _save_reporting_conf(conf):
    """Persist the reporting settings (enabled/url/key) atomically, 0600."""
    data = {"enabled": bool(conf.get("enabled", True)),
            "url": str(conf.get("url") or REPORTING_DEFAULT_URL),
            "key": str(conf.get("key") or "")}
    _write_private_json(REPORTING_CONF_FILE, data)
    return data


REPORT_CATEGORIES = ["ssh", "rdp", "bruteforce", "scan", "web", "spam", "dos",
                     "malware", "manual", "blocklist", "other"]


def report_category_for(reason, source):
    """Structured AbuseIPDB-style category sent with each ban report so the
    tuxwall.org report card can aggregate abuse types, not just free text."""
    r = (reason or "").lower()
    s = (source or "").lower()
    if "rdp" in r:
        return "rdp"
    if "ssh" in r or "sshd" in r:
        return "ssh"
    if any(k in r for k in ("brute", "credential", "login", "dictionary",
                            "password", "hydra")):
        return "bruteforce"
    if any(k in r for k in ("scan", "probe", "port ", "sniff", "nmap")):
        return "scan"
    if any(k in r for k in ("http", "web", "iis", "apache", "nginx", "sql",
                            "php", "api", "cve", "exploit", "shell", "admin",
                            "xmlrpc", "wp-", "joomla")):
        return "web"
    if any(k in r for k in ("spam", "smtp", "mail", "phish", "spoof", "pxe",
                            "jabber", "sip")):
        return "spam"
    if any(k in r for k in ("dos", "ddos", "flood", "syn")):
        return "dos"
    if any(k in r for k in ("malware", "botnet", "c2 ", "c&c", "cnc", "mirai",
                            "cobalt", "ddg", "xzfl")):
        return "malware"
    if "blocklist" in r or s == "blocklist":
        return "blocklist"
    if "manual" in r or s == "manual":
        return "manual"
    return "other"


# Deception categories: the decoy knows exactly which fake service was hit,
# so reports carry the port/service instead of falling back to "other".
DECEPTION_SERVICES = {
    21: "FTP", 22: "SSH", 23: "telnet", 25: "SMTP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    2323: "telnet", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5555: "ADB", 5900: "VNC", 6379: "Redis", 8080: "HTTP", 8443: "HTTPS",
    9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB",
}
_DECEPTION_PORT_CATEGORY = {22: "ssh", 3389: "rdp", 25: "spam", 80: "web",
                            443: "web", 8080: "web", 8443: "web"}
# Redis commands scanners use to plant cron jobs / rogue replicas
_REDIS_EXPLOIT_CMDS = ("config", "slaveof", "replicaof", "module", "eval",
                       "flushall", "script")


def deception_service(port):
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "unknown service"
    return DECEPTION_SERVICES.get(port, "port %d" % port)


def deception_category(source, port=None, logtype=None, logdata=None):
    """Report category for a deception catch from what was actually hit:
    honeypot = a bare connection to a fake service (scan, or the service's
    own class for SSH/RDP/web/mail ports); canary = what the emulator saw
    (SSH session, a login against MSSQL/VNC, a Redis exploit command)."""
    try:
        port = int(port) if port not in (None, "") else None
    except (TypeError, ValueError):
        port = None
    if source == "canary":
        lt = int(logtype or 0)
        if lt in (4000, 4001, 4002):
            return "ssh"
        if lt in (9001, 9002, 12001):
            return "bruteforce"
        if lt == 17001:
            cmd = str((logdata or {}).get("CMD") or "").strip().lower()
            return "malware" if cmd in _REDIS_EXPLOIT_CMDS else "scan"
    return _DECEPTION_PORT_CATEGORY.get(port, "scan")


def ensure_reporting_key():
    """Create the anonymous per-install reporting key on first use."""
    with _report_status_lock:
        conf = load_reporting_conf()
        if conf["key"]:
            return conf
        conf["key"] = secrets.token_hex(16)
        try:
            _save_reporting_conf(conf)
        except OSError as exc:
            print("[report] could not save the reporting key: %r" % (exc,), flush=True)
        return conf


def set_reporting_enabled(enabled):
    """The real off switch (dashboard: Deception / Community Bans settings).
    Off: new catches are not queued and nothing is sent; reports already
    queued are HELD (not sent, not discarded - they still age out after
    REPORT_QUEUE_MAX_AGE). On again: the held queue resumes at once."""
    with _report_status_lock:
        conf = load_reporting_conf()
        conf["enabled"] = bool(enabled)
        _save_reporting_conf(conf)
    if enabled:
        _report_q_load()
        with REPORT_Q_LOCK:
            pending = bool(REPORT_Q["items"])
        if pending:
            _report_worker_ensure()
            REPORT_Q_WAKE.set()
    return reporting_status()


# --- report queue -------------------------------------------------------------
REPORT_Q = {"loaded": False, "items": [], "stats": {}}
REPORT_Q_LOCK = threading.RLock()
REPORT_Q_WAKE = threading.Event()
_REPORT_WORKER = {"thread": None}


def _report_q_default_stats():
    return {"last_report": None, "last_error": None, "last_error_at": None,
            "sent_total": 0, "refused_total": 0, "dropped_total": 0,
            "retries_total": 0, "sent_recent": []}


def _report_q_load():
    with REPORT_Q_LOCK:
        if REPORT_Q["loaded"]:
            return
        items, stats = [], _report_q_default_stats()
        try:
            with open(REPORT_QUEUE_FILE) as f:
                data = json.load(f)
            if isinstance(data, dict):
                items = [i for i in (data.get("items") or [])
                         if isinstance(i, dict) and isinstance(i.get("payload"), dict)]
                if isinstance(data.get("stats"), dict):
                    stats.update(data["stats"])
        except (OSError, ValueError):
            pass
        # the legacy last-report fields lived in reporting.json
        if stats.get("last_report") is None:
            try:
                with open(REPORTING_CONF_FILE) as f:
                    old = json.load(f)
                if isinstance(old, dict):
                    stats["last_report"] = old.get("last_report")
                    stats["last_error"] = old.get("last_error")
            except (OSError, ValueError):
                pass
        REPORT_Q.update(loaded=True, items=items[-REPORT_QUEUE_MAX:], stats=stats)


def _report_q_save():
    """Persist the queue + counters (never the key). Caller holds the lock."""
    now = time.time()
    st = REPORT_Q["stats"]
    st["sent_recent"] = [t for t in (st.get("sent_recent") or [])
                         if isinstance(t, (int, float)) and now - t < 86400][-5000:]
    try:
        _write_private_json(REPORT_QUEUE_FILE, {"version": 1, "items": REPORT_Q["items"],
                                                "stats": st})
    except OSError as exc:
        print("[report] queue save failed: %r" % (exc,), flush=True)


def _report_q_prune_stale(now=None):
    """Drop queued reports older than REPORT_QUEUE_MAX_AGE (stale evidence
    is never sent late, e.g. after a long switch-off). -> count dropped."""
    now = now or time.time()
    cutoff = now - REPORT_QUEUE_MAX_AGE
    with REPORT_Q_LOCK:
        items = REPORT_Q["items"]
        keep = [i for i in items if float(i.get("created") or now) >= cutoff]
        n = len(items) - len(keep)
        if n:
            REPORT_Q["items"] = keep
            st = REPORT_Q["stats"]
            st["dropped_total"] = int(st.get("dropped_total") or 0) + n
            st["last_error"] = "%d queued report(s) older than %d days dropped" % (
                n, REPORT_QUEUE_MAX_AGE // 86400)
            st["last_error_at"] = now
            _report_q_save()
    return n


def _report_payload(ip, hits=0, reason="", source="", category="", suricata=None):
    """The report body WITHOUT the key (the key is added at send time, so
    the persisted queue never holds it). None for a non-global address."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    if not addr.is_global:
        return None
    payload = {
        "ip": str(addr),
        "hits": max(0, int(hits or 0)),
        "reason": (reason or "")[:96],
        "source": (source or "")[:24] or "tuxwall",
        "category": (category if category in REPORT_CATEGORIES
                     else report_category_for(reason, source)),
    }
    # Suricata signatures observed from this IP (top 5, sanitized) —
    # rendered on the tuxwall.org report card. Bounded so a hostile or
    # buggy caller can't inflate the ingest payload.
    if isinstance(suricata, list):
        clean = []
        for item in suricata[:5]:
            if not isinstance(item, dict):
                continue
            sig = str(item.get("sig") or "").strip()[:120]
            if not sig:
                continue
            try:
                count = max(1, min(1000000, int(item.get("count") or 1)))
            except (TypeError, ValueError):
                count = 1
            try:
                sid = int(item.get("sid") or 0)
            except (TypeError, ValueError):
                sid = 0
            clean.append({"sig": sig, "count": count, "sid": sid})
        if clean:
            payload["suricata"] = clean
    return payload


def _report_enqueue(payload, now=None):
    """Queue one report (persisted) and wake the sender. Returns a status
    dict; nothing is queued while reporting is switched off."""
    if not payload:
        return {"ok": False, "reason": "invalid or non-global ip"}
    if not load_reporting_conf()["enabled"]:
        return {"ok": False, "reason": "community reporting is switched off"}
    now = now or time.time()
    _report_q_load()
    with REPORT_Q_LOCK:
        items = REPORT_Q["items"]
        for it in items:
            p = it["payload"]
            if p.get("ip") == payload["ip"] and p.get("source") == payload["source"]:
                p["hits"] = max(int(p.get("hits") or 0), int(payload.get("hits") or 0))
                return {"ok": True, "queued": True, "merged": True, "id": it["id"]}
        item = {"id": secrets.token_hex(6), "payload": payload, "created": now,
                "attempts": 0, "next_try": now, "last_error": None}
        items.append(item)
        dropped = 0
        cutoff = now - REPORT_QUEUE_MAX_AGE
        keep = [i for i in items if float(i.get("created") or now) >= cutoff]
        dropped += len(items) - len(keep)
        if len(keep) > REPORT_QUEUE_MAX:
            dropped += len(keep) - REPORT_QUEUE_MAX
            keep = keep[-REPORT_QUEUE_MAX:]
        REPORT_Q["items"] = keep
        if dropped:
            REPORT_Q["stats"]["dropped_total"] = int(REPORT_Q["stats"].get("dropped_total") or 0) + dropped
        _report_q_save()
    _report_worker_ensure()
    REPORT_Q_WAKE.set()
    return {"ok": True, "queued": True, "id": item["id"]}


def _report_http_post(url, body, headers, timeout):
    """The only network call of the reporting path (tests replace it).
    Returns (http status, parsed JSON dict or {})."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(65536)
            code = resp.status
    except urllib.error.HTTPError as exc:
        code = exc.code
        try:
            raw = exc.read(65536)
        except Exception:
            raw = b""
    try:
        parsed = json.loads((raw or b"{}").decode("utf-8", "replace") or "{}")
    except ValueError:
        parsed = {}
    return code, parsed if isinstance(parsed, dict) else {}


def _report_send_one(item, conf):
    """-> ("sent" | "retry" | "refused", detail). Transient failures
    (network, timeouts, 429, 5xx) retry; a 4xx refusal (invalid, protected,
    revoked key, version) is final."""
    body = dict(item["payload"], key=conf["key"])
    try:
        code, parsed = _report_http_post(
            conf["url"], json.dumps(body).encode("utf-8"),
            {"Content-Type": "application/json", "User-Agent": "tuxwall-report/1.0",
             "X-Tuxwall-Version": TUXWALL_VERSION},
            REPORTING_TIMEOUT)
    except Exception as exc:
        return "retry", ("network: %s" % (exc,))[:200]
    err = str(parsed.get("error") or "")[:160]
    if 200 <= code < 300:
        if parsed.get("ok"):
            return "sent", ("duplicate" if parsed.get("duplicate") else "accepted")
        return "refused", ("HTTP %d: %s" % (code, err or "not ok"))[:200]
    if code == 429 or code >= 500:
        return "retry", ("HTTP %d: %s" % (code, err))[:200]
    return "refused", ("HTTP %d: %s" % (code, err))[:200]


def _report_backoff(attempts):
    delay = min(REPORT_RETRY_MAX, REPORT_RETRY_BASE * (2 ** max(0, attempts - 1)))
    return delay + secrets.randbelow(max(1, int(delay // 5) + 1))


def _report_q_paused(now=None):
    try:
        age = (now or time.time()) - os.stat(REPORT_PAUSE_FILE).st_mtime
    except OSError:
        return False
    return age < REPORT_PAUSE_MAX_AGE


def _report_q_process(now=None, limit=REPORT_BATCH):
    """Send every due item once (oldest first). Returns {sent, retry,
    refused, discarded, left, paused}. Never raises."""
    now = now or time.time()
    out = {"sent": 0, "retry": 0, "refused": 0, "discarded": 0, "left": 0,
           "paused": False, "held": False}
    _report_q_load()
    out["discarded"] = _report_q_prune_stale(now)
    conf = load_reporting_conf()
    if not conf["enabled"]:
        # switched off: hold what is queued (sent when switched back on)
        out["held"] = True
        with REPORT_Q_LOCK:
            out["left"] = len(REPORT_Q["items"])
        return out
    if _report_q_paused(now):
        out["paused"] = True
        with REPORT_Q_LOCK:
            out["left"] = len(REPORT_Q["items"])
        return out
    with REPORT_Q_LOCK:
        due = [dict(i) for i in REPORT_Q["items"]
               if float(i.get("next_try") or 0) <= now][:limit]
    if due and not conf["key"]:
        conf = ensure_reporting_key()
    for item in due:
        result, detail = _report_send_one(item, conf)
        if result == "refused" and load_reporting_conf()["key"] != conf["key"]:
            # the key was rotated while this pass ran (old key revoked):
            # resend with the new key instead of dropping the report
            result, detail = "retry", "reporting key rotated - resending with the new key"
        t = time.time()
        with REPORT_Q_LOCK:
            st = REPORT_Q["stats"]
            live = next((i for i in REPORT_Q["items"] if i["id"] == item["id"]), None)
            if result == "sent":
                out["sent"] += 1
                st["last_report"] = t
                st["sent_total"] = int(st.get("sent_total") or 0) + 1
                st.setdefault("sent_recent", []).append(t)
                if live is not None:
                    REPORT_Q["items"].remove(live)
            elif result == "refused":
                out["refused"] += 1
                st["refused_total"] = int(st.get("refused_total") or 0) + 1
                st["last_error"] = "%s (%s, not retried)" % (detail, item["payload"].get("ip"))
                st["last_error_at"] = t
                if live is not None:
                    REPORT_Q["items"].remove(live)
            else:
                out["retry"] += 1
                st["retries_total"] = int(st.get("retries_total") or 0) + 1
                st["last_error"] = "%s (will retry)" % detail
                st["last_error_at"] = t
                if live is not None:
                    live["attempts"] = int(live.get("attempts") or 0) + 1
                    live["last_error"] = detail
                    live["next_try"] = t + _report_backoff(live["attempts"])
            _report_q_save()
    with REPORT_Q_LOCK:
        out["left"] = len(REPORT_Q["items"])
    return out


def _report_q_next_due():
    with REPORT_Q_LOCK:
        if not REPORT_Q["items"]:
            return None
        return min(float(i.get("next_try") or 0) for i in REPORT_Q["items"])


def _report_worker_loop():
    _report_q_load()
    while True:
        try:
            _report_q_process()
        except Exception as exc:
            print("[report] worker pass failed: %r" % (exc,), flush=True)
        nxt = _report_q_next_due()
        wait = 300.0 if nxt is None else max(1.0, min(300.0, nxt - time.time()))
        if nxt is not None and _report_q_paused():
            wait = 10.0
        if nxt is not None and not load_reporting_conf()["enabled"]:
            wait = 300.0      # held while switched off; switching on wakes us
        REPORT_Q_WAKE.wait(wait)
        REPORT_Q_WAKE.clear()


def _report_worker_ensure():
    with REPORT_Q_LOCK:
        t = _REPORT_WORKER["thread"]
        if t is not None and t.is_alive():
            return t
        t = threading.Thread(target=_report_worker_loop, name="report-queue", daemon=True)
        t.start()
        _REPORT_WORKER["thread"] = t
    return t


def reporting_status():
    """Local reporting state in one place (phase 3: settings + queue UI):
    switch, key present (never the key), URL, last report / error, 24 h
    count, queue length and next retry."""
    conf = load_reporting_conf()
    _report_q_load()
    now = time.time()
    with REPORT_Q_LOCK:
        st = dict(REPORT_Q["stats"])
        items = list(REPORT_Q["items"])
    nxt = min((float(i.get("next_try") or 0) for i in items), default=None)
    return {
        "enabled": conf["enabled"],
        "key_present": bool(conf["key"]),
        "url": conf["url"],
        "last_report": st.get("last_report"),
        "last_error": st.get("last_error"),
        "last_error_at": st.get("last_error_at"),
        "sent_24h": len([t for t in (st.get("sent_recent") or [])
                         if isinstance(t, (int, float)) and now - t < 86400]),
        "sent_total": int(st.get("sent_total") or 0),
        "refused_total": int(st.get("refused_total") or 0),
        "dropped_total": int(st.get("dropped_total") or 0),
        "paused": _report_q_paused(now),
        "held": bool(items) and not conf["enabled"],
        "queue_length": len(items),
        "queue_retrying": len([i for i in items if int(i.get("attempts") or 0) > 0]),
        "next_retry": nxt,
        "worker_alive": bool(_REPORT_WORKER["thread"] and _REPORT_WORKER["thread"].is_alive()),
    }


def report_ban_to_org(ip, hits=0, reason="", source="", category="",
                      suricata=None):
    """Queue a ban report for tuxwall.org (sent by the report-queue worker,
    retried on failure). Never raises; returns a status dict."""
    try:
        if not load_reporting_conf()["enabled"]:
            return {"ok": False, "reason": "community reporting is switched off"}
        return _report_enqueue(_report_payload(ip, hits, reason, source, category, suricata))
    except Exception as exc:
        return {"ok": False, "reason": str(exc)}


# --- Community settings (Security > Deception + CrowdSec > Community Bans) ----
# One lightweight view of the two community switches, shared by both pages:
#   reporting - this install's deception catches -> tuxwall.org (reporting.json)
#   auto_ban  - the tuxwall.org list -> local CrowdSec bans (community-auto.json)
# Built from local state only: never downloads the ban list. The key's
# approval state (pending / approved / revoked) comes from a cached
# POST /register {"action": "status"} lookup refreshed in the background.
# Changes are audited with the dashboard user.
COMMUNITY_AUDIT_LOG = "/var/log/tuxwall/community-settings-audit.log"
COMMUNITY_REG_TTL = 600        # cached approval status after a good lookup (s)
COMMUNITY_REG_RETRY = 120      # ... after a failed one
COMMUNITY_REG_MIN_GAP = 20     # forced re-checks at most this often
COMMUNITY_REG = {"data": None, "fp": None, "ts": 0.0, "ok": False, "running": False,
                 "error": None}
COMMUNITY_REG_LOCK = threading.Lock()
COMMUNITY_SETTINGS_KEYS = ("reporting_enabled", "auto_ban")


def _reporting_key_fp(key):
    return hashlib.sha256((key or "").encode("utf-8")).hexdigest()[:16] if key else None


def _community_reg_store(out, key):
    """Remember a status lookup result (called by community_reporting_status)."""
    with COMMUNITY_REG_LOCK:
        if out.get("warning"):
            COMMUNITY_REG.update(ts=time.time(), ok=False, error=str(out["warning"])[:200])
        else:
            COMMUNITY_REG.update(data=dict(out), fp=_reporting_key_fp(key), ts=time.time(),
                                 ok=True, error=None)


def _community_reg_refresh():
    try:
        community_reporting_status()
    except Exception as exc:
        with COMMUNITY_REG_LOCK:
            COMMUNITY_REG.update(ts=time.time(), ok=False, error=str(exc)[:200])
    finally:
        with COMMUNITY_REG_LOCK:
            COMMUNITY_REG["running"] = False


def community_registration(force=False):
    """Cached approval state of this install's reporting key. A stale cache
    starts one background lookup and answers with what is known (checking
    = True meanwhile). No key yet: nothing is looked up (the first report
    creates and registers it)."""
    key = load_reporting_conf()["key"]
    if not key:
        return {"registered": False, "status": "unknown", "approved": False,
                "checked_at": None, "checking": False, "error": None, "key_present": False}
    fp = _reporting_key_fp(key)
    now = time.time()
    with COMMUNITY_REG_LOCK:
        if COMMUNITY_REG["fp"] not in (None, fp):        # key rotated: forget
            COMMUNITY_REG.update(data=None, fp=None, ts=0.0, ok=False, error=None)
        age = now - COMMUNITY_REG["ts"]
        ttl = COMMUNITY_REG_TTL if COMMUNITY_REG["ok"] else COMMUNITY_REG_RETRY
        stale = (COMMUNITY_REG["data"] is None and COMMUNITY_REG["ts"] == 0.0) or age >= ttl \
            or (force and age >= COMMUNITY_REG_MIN_GAP)
        start = stale and not COMMUNITY_REG["running"]
        if start:
            COMMUNITY_REG["running"] = True
        data = dict(COMMUNITY_REG["data"] or {})
        checked = COMMUNITY_REG["ts"] if COMMUNITY_REG["data"] is not None else None
        error = COMMUNITY_REG["error"]
        running = COMMUNITY_REG["running"]
    if start:
        try:
            threading.Thread(target=_community_reg_refresh, name="community-reg",
                             daemon=True).start()
        except RuntimeError:
            with COMMUNITY_REG_LOCK:
                COMMUNITY_REG["running"] = False
            running = False
    status = str(data.get("status") or "unknown")
    if status not in ("pending", "approved", "revoked"):
        status = "unknown"
    return {"registered": bool(data.get("registered")), "status": status,
            "approved": bool(data.get("approved")) and status == "approved",
            "approved_at": data.get("approved_at"), "created": data.get("created"),
            "checked_at": checked, "checking": running, "error": error, "key_present": True}


def community_settings_view(force_status=False):
    """GET /api/community/settings (admin): both switches + reporting status."""
    rs = reporting_status()
    reg = community_registration(force_status)
    auto = _load_community_auto()
    return {
        "ok": True,
        "reporting": {
            "enabled": bool(rs["enabled"]),
            "registered": reg["registered"],
            "status": reg["status"],
            "approved": reg["approved"],
            "approved_at": reg.get("approved_at"),
            "key_present": reg["key_present"],
            "status_checked_at": reg["checked_at"],
            "status_checking": reg["checking"],
            "status_error": reg["error"],
            "last_report": rs["last_report"],
            "last_error": rs["last_error"],
            "last_error_at": rs["last_error_at"],
            "reported_24h": rs["sent_24h"],
            "queue": {
                "pending": rs["queue_length"],
                "retrying": rs["queue_retrying"],
                "sent": rs["sent_total"],
                "failed": rs["refused_total"],
                "dropped": rs["dropped_total"],
                "next_retry": rs["next_retry"],
                "paused": rs["paused"],
                "held": rs["held"],
            },
        },
        "auto_ban": {
            "enabled": bool(auto.get("enabled")),
            "last_sync": auto.get("last_sync") or None,
            "added_total": int(auto.get("added_total") or 0),
            "last_pass_added": int(auto.get("last_pass_added") or 0),
            "pending": int(auto.get("pending") or 0),
        },
    }


def _community_audit(who, client, changes):
    entry = {"ts": round(time.time(), 3), "user": who or "?", "client": client or "",
             "changes": changes}
    print("[community] settings by %s: %s" % (entry["user"], json.dumps(changes)), flush=True)
    try:
        os.makedirs(os.path.dirname(COMMUNITY_AUDIT_LOG), exist_ok=True)
        fd = os.open(COMMUNITY_AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:
        print("[community] audit write failed: %r" % (exc,), flush=True)


def community_settings_update(body, identity, client=""):
    """POST /api/community/settings {reporting_enabled?, auto_ban?} (admin).
    Strict booleans, at least one known key; every request is audited with
    the dashboard user (old -> new per key, unchanged values included).
    Raises ValueError on bad input."""
    if not isinstance(body, dict) or not body:
        raise ValueError("send reporting_enabled and/or auto_ban (true/false)")
    unknown = sorted(k for k in body if k not in COMMUNITY_SETTINGS_KEYS)
    if unknown:
        raise ValueError("unknown setting: %s" % ", ".join(unknown)[:120])
    for k in body:
        if not isinstance(body[k], bool):
            raise ValueError("%s must be true or false" % k)
    changes = {}
    if "reporting_enabled" in body:
        old = bool(load_reporting_conf()["enabled"])
        new = body["reporting_enabled"]
        if new != old:
            set_reporting_enabled(new)
        changes["reporting_enabled"] = {"from": old, "to": new}
    if "auto_ban" in body:
        old = bool(_load_community_auto().get("enabled"))
        new = body["auto_ban"]
        if new != old:
            res = set_community_auto(new)
            if not res.get("ok"):
                raise RuntimeError("community auto-ban could not be saved")
        changes["auto_ban"] = {"from": old, "to": new}
    _community_audit((identity or {}).get("username"), client, changes)
    out = community_settings_view()
    out["changed"] = sorted(k for k, v in changes.items() if v["from"] != v["to"])
    return out


# Deception bans of the last 24 h (Deception status cards): one cheap
# `cscli decisions list --since 24h` (alerts of the last day only), cached.
DECEPTION_BANS_TTL = 120
DECEPTION_BANS_RETRY = 30
_DECEPTION_BANS = {"ts": 0.0, "data": None}
_DECEPTION_BANS_LOCK = threading.Lock()


def _deception_bans_count(raw):
    """Pure: (honeypot, canary) ban decisions in `cscli -o raw` output."""
    honey = canary = 0
    for line in (raw or "").splitlines()[1:]:
        parts = line.strip().split(",")
        if len(parts) < 5 or parts[4] != "ban":
            continue
        reason = parts[3]
        if reason.startswith("honeypot/"):
            honey += 1
        elif reason.startswith("canary/"):
            canary += 1
    return honey, canary


def deception_bans_24h():
    now = time.time()
    with _DECEPTION_BANS_LOCK:
        d = _DECEPTION_BANS["data"]
        if d is not None and now - _DECEPTION_BANS["ts"] < (
                DECEPTION_BANS_TTL if d.get("ok") else DECEPTION_BANS_RETRY):
            return dict(d)
        prev = dict(d) if d else None
    out = {"ok": False, "honeypot": 0, "canary": 0, "total": 0, "at": now}
    try:
        proc = subprocess.run([CROWDSEC_BIN, "decisions", "list", "-o", "raw",
                               "--limit", "0", "--since", "24h"],
                              capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT)
        if proc.returncode == 0:
            honey, canary = _deception_bans_count(proc.stdout)
            out.update(ok=True, honeypot=honey, canary=canary, total=honey + canary)
        else:
            out["error"] = (proc.stderr or "cscli failed").strip()[:160]
    except Exception as exc:
        out["error"] = str(exc)[:160]
    if not out["ok"] and prev and prev.get("ok"):
        out = dict(prev, stale=True, error=out.get("error"))   # last good numbers
    with _DECEPTION_BANS_LOCK:
        _DECEPTION_BANS.update(ts=time.time(), data=dict(out))
    return out


RECENT_WAN_FILE = os.path.join(BLOCKLIST_DIR, "recent-wan-ips.json")
RECENT_WAN_MAX = 5
RECENT_WAN_LOCK = threading.Lock()


def _recent_wan_ips():
    """The last few WAN addresses this router held (both families)."""
    try:
        with open(RECENT_WAN_FILE) as f:
            data = json.load(f)
        if isinstance(data, list):
            return [str(a) for a in data if isinstance(a, str)][:RECENT_WAN_MAX]
    except (OSError, ValueError):
        pass
    return []


def _record_recent_wan():
    """Track the last few WAN addresses (both families).

    The watcher's self-guard only knows the CURRENT address; on a dynamic
    WAN the engine can still self-capture the just-rotated-away address,
    and that stale self-report must not reach the community list either
    (observed live: an engine self-capture survived on the public list for
    five days after the purge). Current addresses go first, then whatever
    history the file holds, deduped, capped."""
    now = [a for a in (_honey_wan_ip(), _honey_wan6()) if a]
    try:
        with RECENT_WAN_LOCK:
            merged = []
            for a in now + _recent_wan_ips():
                if a and a not in merged:
                    merged.append(a)
            merged = merged[:RECENT_WAN_MAX]
            try:
                with open(RECENT_WAN_FILE, "w") as f:
                    json.dump(merged, f, indent=2)
            except OSError:
                pass  # best-effort; the in-memory guard still applies
    except Exception:
        pass


def _is_own_or_recent_wan(ip):
    """True for any WAN address this router currently holds - or recently
    held. Used by every report path so no self-capture (current or
    rotated-away) is ever reported to the community list."""
    return ip and ip in set(_recent_wan_ips()) | {_honey_wan_ip(), _honey_wan6()}


# --- Deception never-ban guard (every honeypot/canary ban + report path) -----
# 2026-11-19 (deception phase 1): the honeypot and canary used to ban and
# report any source with only a LAN/self check (and the IPv6 LAN guard
# missed the delegated global prefix). _deception_guard() is now consulted
# by _deception_cscli_ban() and _spawn_report(), i.e. by every path that
# bans or reports a deception catch.
_NEVER_BAN = {"ts": 0.0, "ips": None, "refreshing": False}
_NEVER_BAN_LOCK = threading.Lock()
_NEVER_BAN_TTL = 600


def _never_ban_refresh():
    try:
        ips = frozenset(_community_never_ban_ips())
    except Exception as exc:
        print("[deception] never-ban refresh failed: %r" % (exc,), flush=True)
        ips = None
    with _NEVER_BAN_LOCK:
        if ips is not None:
            _NEVER_BAN.update(ts=time.time(), ips=ips)
        _NEVER_BAN["refreshing"] = False
    return ips


def _deception_never_ban_ips():
    """Addresses this router depends on (DNS forwarders, NTP, gateways, own
    interface addresses, resolvers, APT mirrors), cached _NEVER_BAN_TTL. The
    first call loads synchronously; afterwards a stale set is refreshed in
    the background so a canary webhook never waits on DNS lookups."""
    with _NEVER_BAN_LOCK:
        ips, ts = _NEVER_BAN["ips"], _NEVER_BAN["ts"]
        stale = ips is None or time.time() - ts >= _NEVER_BAN_TTL
        start = stale and ips is not None and not _NEVER_BAN["refreshing"]
        if start:
            _NEVER_BAN["refreshing"] = True
    if ips is None:
        return _never_ban_refresh() or frozenset()
    if start:
        try:
            threading.Thread(target=_never_ban_refresh, name="never-ban", daemon=True).start()
        except RuntimeError:
            with _NEVER_BAN_LOCK:
                _NEVER_BAN["refreshing"] = False
    return ips


def _community_published_protected():
    """Collector-published protected ranges from the cached community list
    (no fetch here)."""
    with COMMUNITY_BANS_LOCK:
        data = COMMUNITY_BANS_CACHE.get("data") or {}
    nets = []
    for r in data.get("protected") or []:
        try:
            nets.append(ipaddress.ip_network(str(r)))
        except ValueError:
            continue
    return nets


def _deception_guard(ip):
    """Why `ip` must never be banned or reported by the deception layer,
    or None when it may be."""
    try:
        addr = _plain_ip(ipaddress.ip_address(str(ip or "").strip().split("%")[0]))
    except ValueError:
        return "invalid address"
    s = str(addr)
    if not addr.is_global:
        return "non-global address"
    if _honey_is_lan(s):
        return "LAN/VLAN/VPN address (incl. the delegated IPv6 prefix)"
    if _honey_is_self(s) or _is_own_or_recent_wan(s):
        return "this router's own (or recent) WAN address"
    if _ip_in_protected(s):
        return "protected infrastructure range"
    pub = _community_published_protected()
    if pub and _ip_in_published(s, pub):
        return "collector-published protected range"
    if s in _deception_never_ban_ips():
        return "infrastructure this router depends on (DNS/NTP/gateway/resolver/APT)"
    return None


def _deception_cscli_ban(ip, duration, reason):
    """The deception layer's only CrowdSec ban call: guard first, return
    code checked. -> (ok, error or None)."""
    why = _deception_guard(ip)
    if why:
        return False, "refused by the never-ban guard: " + why
    try:
        proc = subprocess.run(
            [CROWDSEC_BIN, "decisions", "add", "--ip", ip,
             "--duration", duration, "--reason", reason],
            capture_output=True, text=True, timeout=CROWDSEC_TIMEOUT,
        )
    except Exception as exc:
        return False, ("CrowdSec unavailable: %s" % (exc,))[:200]
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "cscli failed").strip().splitlines()
        return False, ("cscli rc=%d: %s" % (proc.returncode, msg[-1] if msg else ""))[:200]
    try:
        _invalidate_crowdsec_decisions_cache()
    except Exception:
        pass
    return True, None


def _spawn_report(ip, reason, source, category=""):
    """Queue a ban report (the report-queue worker sends and retries it).

    Guard: _deception_guard() - LAN/VPN (incl. the delegated global v6
    prefix), any WAN address this router holds or recently held (a
    self-capture of the rotated-away address is still a self-capture),
    protected infrastructure and the never-ban set - is never reported, on
    any path.

    Evidence is attached so the tuxwall.org report card reflects the observed
    abuse type instead of how the IP happened to be banned locally:
      1. Suricata first — its verdict replaces the category and the top
         matching signature is appended to the reason.
      2. Otherwise the UFW drop record — the pattern that actually reached
         the firewall (port scan, service probe) becomes the category and
         is appended to the reason.
    """
    why = _deception_guard(ip)
    if why:
        _honey_log("report skipped for {}: {}".format(ip, why))
        return {"ok": False, "reason": why}
    try:
        sur_cat, sur_sig = suricata_evidence_for_ip(ip)
    except Exception:
        sur_cat, sur_sig = ("", "")
    ev_cat, suffix, ufw_ev = "", "", None
    if sur_cat:
        if sur_sig:
            suffix = " — suricata: %s" % sur_sig[:60]
    else:
        # No signature evidence (typical: bare SYNs to closed ports match no
        # rule) — describe the drop pattern the firewall itself recorded.
        try:
            ufw_ev = ufw_evidence_for_ip(ip)
            phrase = ufw_evidence_phrase(ufw_ev)
            mapped = report_category_for(phrase, "") if phrase else ""
        except Exception:
            ufw_ev, phrase, mapped = None, "", ""
        if phrase:
            ev_cat = mapped if mapped and mapped != "other" else ""
            suffix = " — %s" % phrase
    if suffix:
        # Keep the evidence inside the collector's 96-char reason cap:
        # trim the suffix first, then the base reason.
        if len(reason) + len(suffix) > 96:
            reason = reason[:max(20, 96 - len(suffix))]
        reason = (reason + suffix)[:96]
    # A deception catch already knows the service it hit (ssh/rdp/web/...):
    # only a generic "scan"/"other" is refined by Suricata or the UFW record.
    if category not in REPORT_CATEGORIES or category in ("scan", "other"):
        if sur_cat:
            category = sur_cat
        elif ev_cat:
            category = ev_cat
    try:
        sur_alerts = suricata_alerts_for_ip(ip)
    except Exception:
        sur_alerts = []
    try:
        mon = get_security_monitor()
        hits = int((mon.by_ip.get(ip) or {}).get("count") or 0)
    except Exception:
        hits = 0
    if not hits and ufw_ev:
        # Monitor window missed the IP (e.g. log rotated) — the firewall's
        # own drop count is a fair stand-in.
        hits = ufw_ev["packets"]
    return report_ban_to_org(ip, hits, reason, source, category, sur_alerts)


# --- OpenCanary deception services (receiver, status, control) ---------------
# OpenCanary (systemd unit opencanary.service, /opt/opencanary) emulates
# services on the WAN address only. Its Slack-style webhook alerts this
# receiver; any event with a globally routable source IP is definitionally
# hostile (nothing legitimate connects to services that do not exist), so
# sources are auto-banned via CrowdSec and community-reported - the same
# pipeline and the same reasoning as the tarpit.
CANARY_TOKEN_FILE = os.path.join(BLOCKLIST_DIR, "canary-token")
CANARY_LOG = "/var/log/opencanary/opencanary.log"
CANARY_CONF = "/etc/opencanaryd/opencanary.conf"
CANARY_SERVICE = "opencanary.service"
CANARY_BAN_PREFIX = "canary/"
CANARY_PORTS = (22, 5900, 1433, 6379)    # TCP, WAN IPv4 only (SNMP 161/udp retired 2026-11-19)
CANARY_EVENT_WINDOW = 86400
CANARY_READ_LINES = 300
CANARY_LOGTYPES = {
    4000: "ssh connection",
    4001: "ssh version exchange",
    4002: "ssh login attempt",
    9001: "mssql login",
    9002: "mssql login",
    12001: "vnc connection",
    13001: "snmp command",
    17001: "redis command",
}
# Canary ban counts must not scan the whole decision table: with a few
# thousand decisions `cscli decisions list --limit 0` takes 10-15s, which
# blocked every dashboard poll (the card appeared stuck/disabled). Decisions
# carry a scenario (canary/<event>), so one cheap filtered query per known
# canary scenario is exact enough and returns in milliseconds. The result is
# display-only, so a short cache is fine.
CANARY_BAN_SCENARIOS = tuple(sorted({
    "canary/" + str(v).replace(" ", "-")
    for v in CANARY_LOGTYPES.values()
}))
CANARY_BAN_TTL = 60
CANARY_BAN_CACHE = {"ts": 0.0, "count": 0, "last_ip": None}
CANARY_BAN_LOCK = threading.Lock()


def _canary_ban_snapshot():
    """(active canary decisions, newest banned IP), cached for CANARY_BAN_TTL."""
    now = time.time()
    with CANARY_BAN_LOCK:
        if now - CANARY_BAN_CACHE["ts"] < CANARY_BAN_TTL:
            return CANARY_BAN_CACHE["count"], CANARY_BAN_CACHE["last_ip"]

    count, failed = 0, False
    newest, last_ip = -1, None
    for scenario in CANARY_BAN_SCENARIOS:
        try:
            proc = subprocess.run(
                [CROWDSEC_BIN, "decisions", "list", "-o", "raw",
                 "--limit", "0", "-s", scenario],
                capture_output=True, text=True,
                timeout=min(CROWDSEC_TIMEOUT, 5))
            if proc.returncode != 0:
                failed = True
                continue
        except Exception:
            failed = True
            continue
        for line in (proc.stdout or "").splitlines()[1:]:
            parts = line.strip().split(",")
            if len(parts) > 3 and parts[3] == scenario:
                count += 1
                try:
                    decision_id = int(parts[0])
                except (TypeError, ValueError):
                    decision_id = -1
                if decision_id > newest:
                    newest = decision_id
                    last_ip = parts[2].replace("Ip:", "") or last_ip

    with CANARY_BAN_LOCK:
        # A partial failure must not overwrite a good cached count with a low one.
        if not failed:
            CANARY_BAN_CACHE.update(ts=time.time(), count=count,
                                    last_ip=last_ip)
        return CANARY_BAN_CACHE["count"], CANARY_BAN_CACHE["last_ip"]


CANARY_RECENT_TTL = 3600
CANARY_RECENT_MAX = 8192
CANARY_RECENT = BoundedTTLMap(CANARY_RECENT_MAX, CANARY_RECENT_TTL)   # ip -> handled at
CANARY_LOCK = threading.Lock()
# OpenCanary modules whose evidence is UDP (spoofable source address).
# The SNMP decoy was retired on 2026-11-19 (owner decision); any UDP event
# that still arrives is logged and never banned or reported.
CANARY_UDP_LOGTYPES = (13001,)


def _canary_token():
    try:
        with open(CANARY_TOKEN_FILE, "r") as f:
            return f.read().strip()
    except OSError:
        return ""


def ensure_canary_token():
    """Create the shared webhook token on first use."""
    tok = _canary_token()
    if tok:
        return tok
    tok = secrets.token_hex(24)
    os.makedirs(os.path.dirname(CANARY_TOKEN_FILE), exist_ok=True)
    with open(CANARY_TOKEN_FILE, "w") as f:
        f.write(tok)
    try:
        os.chmod(CANARY_TOKEN_FILE, 0o600)
    except OSError:
        pass
    return tok


def _infra_exempt_ips():
    """IPs whose services the box depends on: unbound's forward-zone
    resolvers and chrony's NTP servers, read from their actual configs.
    Updated on each call (cheap: two small file reads)."""
    ips = set()
    # unbound forward-zone addresses
    try:
        for conf in sorted(os.listdir("/etc/unbound/unbound.conf.d")):
            if not conf.endswith(".conf"):
                continue
            with open(os.path.join("/etc/unbound/unbound.conf.d", conf)) as f:
                for line in f:
                    m = re.match(r"\s*forward-addr:\s*([0-9a-fA-F:.]+)", line)
                    if m:
                        try:
                            ips.add(str(ipaddress.ip_address(m.group(1))))
                        except ValueError:
                            pass
    except OSError:
        pass
    # chrony NTP servers: read every config surface (main conf,
    # sources.d/, conf.d/, and the sourcedir directives that pull them in)
    chrony_hosts = set()
    try:
        for conf_path in ["/etc/chrony/chrony.conf"]:
            # walk the sourcedir/confdir includes
            with open(conf_path) as f:
                for line in f:
                    m = re.match(r"\s*sourcedir\s+(\S+)", line)
                    if m:
                        import glob as _g
                        for src in sorted(_g.glob(m.group(1) + "/*")):
                            try:
                                with open(src) as sf:
                                    for sl in sf:
                                        hm = re.match(
                                            r"\s*(?:server|pool)\s+(\S+)", sl)
                                        if hm:
                                            chrony_hosts.add(
                                                hm.group(1).split()[0])
                            except OSError:
                                continue
                    m = re.match(r"\s*(?:server|pool)\s+(\S+)", line)
                    if m:
                        chrony_hosts.add(m.group(1).split()[0])
        # also scan sources.d and conf.d directly (some distros put
        # pools there without a sourcedir directive reaching them)
        for d in ("/etc/chrony/sources.d", "/etc/chrony/conf.d"):
            if os.path.isdir(d):
                for fn in os.listdir(d):
                    fp = os.path.join(d, fn)
                    try:
                        with open(fp) as f:
                            for line in f:
                                m = re.match(r"\s*(?:server|pool)\s+(\S+)", line)
                                if m:
                                    chrony_hosts.add(m.group(1).split()[0])
                    except OSError:
                        continue
    except OSError:
        pass
    # resolve every hostname to IPs
    for host in chrony_hosts:
        host = host.rstrip(".")
        try:
            ipaddress.ip_address(host)
            ips.add(host)
            continue
        except ValueError:
            pass
        try:
            answers = subprocess.run(
                ["getent", "ahostsv4", host],
                capture_output=True, text=True, timeout=3).stdout
            for ans in answers.splitlines():
                addr = ans.split()[0]
                try:
                    ipaddress.ip_address(addr)
                    ips.add(addr)
                except ValueError:
                    continue
        except Exception:
            continue
    return ips


def _is_infra_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return ip in _infra_exempt_ips()


def handle_canary_hit(body):
    """Parse an OpenCanary webhook alert; ban + report global sources that
    pass the never-ban guard (TCP evidence only)."""
    fields = {}
    atts = body.get("attachments") if isinstance(body, dict) else None
    if isinstance(atts, list) and atts and isinstance(atts[0], dict):
        for f in atts[0].get("fields", []) or []:
            if isinstance(f, dict) and f.get("title") is not None:
                fields[str(f["title"])] = f.get("value")
    if not fields:
        return {"ok": False, "error": "unrecognized payload"}
    try:
        logtype = int(fields.get("logtype") or 0)
    except (TypeError, ValueError):
        logtype = 0
    ip = str(fields.get("src_host") or "").strip()
    what = CANARY_LOGTYPES.get(logtype, "deception service event %s" % logtype)
    if not ip:
        return {"ok": True, "ignored": True, "message": "no source host"}
    try:
        if not ipaddress.ip_address(ip).is_global:
            return {"ok": True, "ignored": True, "message": "non-global source"}
    except ValueError:
        return {"ok": False, "error": "invalid source host"}
    if _honey_is_self(ip):
        return {"ok": True, "ignored": True, "message": "self"}
    # 2026-11-09 audit: UDP-source evidence (SNMP, logtype 13001) is
    # SPOOFABLE - one forged packet with a fake source would earn a ban.
    # The SNMP decoy is retired (2026-11-19); UDP evidence is never acted on.
    if logtype in CANARY_UDP_LOGTYPES:
        _honey_log("canary: ignored UDP event from {} ({}) - spoofable source, "
                   "never banned or reported".format(ip, what))
        return {"ok": True, "ignored": True, "ip": ip, "local_only": True,
                "message": "UDP evidence is spoofable - never banned"}
    try:
        port = int(fields.get("dst_port") or 0)
    except (TypeError, ValueError):
        port = 0
    with CANARY_LOCK:
        now = time.time()
        last = CANARY_RECENT.get(ip, now)
        if last and now - last < CANARY_RECENT_TTL:
            return {"ok": True, "ignored": True, "message": "recently handled"}
        CANARY_RECENT.set(ip, now, now)
    why = _deception_guard(ip)
    if why:
        with HONEY_APPLY_LOCK:
            HONEY_STATE["stats"]["guarded"] = HONEY_STATE["stats"].get("guarded", 0) + 1
        _honey_log("canary: {} NOT banned/reported ({}) - {}".format(ip, what, why))
        return {"ok": True, "ignored": True, "ip": ip, "guard": why,
                "message": "never banned: " + why}
    ok, err = _deception_cscli_ban(ip, CUSTOM_BLOCKLIST_DURATION,
                                   "canary/" + what.replace(" ", "-"))
    if ok:
        _honey_log("canary: auto-banned {} ({})".format(ip, what))
    else:
        _honey_log("canary: {} NOT banned locally ({}): {}".format(ip, what, err))
    logdata = fields.get("logdata")
    if isinstance(logdata, str):
        try:
            logdata = json.loads(logdata)
        except ValueError:
            logdata = {}
    svc = deception_service(port) if port else "canary"
    reason = "canary: %s (%s%s)" % (what, svc, " %d/tcp" % port if port else "")
    _spawn_report(ip, reason, "canary",
                  deception_category("canary", port, logtype,
                                     logdata if isinstance(logdata, dict) else {}))
    out = {"ok": True, "banned": ok, "ip": ip, "message": what}
    if not ok:
        out["ban_error"] = err
    return out


def _canary_event_detail(logtype, logdata):
    """Human one-liner per event, credentials included where captured."""
    d = logdata if isinstance(logdata, dict) else {}
    if logtype == 4002:
        return "creds {}/{} ({})".format(
            d.get("USERNAME", "?"), d.get("PASSWORD", "?"),
            str(d.get("REMOTEVERSION") or "?").split("-")[-1][:24])
    if logtype == 17001:
        return "CMD {} {}".format(d.get("CMD", "?"), str(d.get("ARGS", ""))[:40]).strip()
    if logtype == 4001:
        return str(d.get("REMOTEVERSION") or "?")[:48]
    parts = []
    for k in sorted(d):
        v = str(d[k])
        if len(v) > 40:
            v = v[:37] + "..."
        parts.append("{}={}".format(k, v))
        if len(parts) >= 3:
            break
    return " ".join(parts) if parts else "connection"


# --- Tripwire (WAN containment on confirmed intrusion) ---------------------
TRIPWIRE_CONF = "/etc/tuxwall/tripwire.json"
TRIPWIRE_STATE = "/etc/tuxwall/tripwire-state.json"
TRIPWIRE_HEALTH = "/run/tuxwall-tripwire/health.json"
TRIPWIRE_AUDIT = "/var/log/tuxwall/tripwire-audit.log"
TRIPWIRE_BIN = "/usr/local/sbin/tuxwall-tripwire"
TRIPWIRE_MODES = ("disabled", "logonly", "medium", "high")
TRIPWIRE_HEALTH_STALE = 60      # engine writes health every 5 s
TRIPWIRE_WATCHER_STALE = 90


def _tripwire_read(path, fb):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, type(fb)) else fb
    except Exception:
        return fb


def tripwire_health(mode=None, tripped=False):
    """Engine service + per-watcher heartbeat summary (shared by the status
    endpoint and the incident monitor)."""
    now = time.time()
    if mode is None:
        mode = str(_tripwire_read(TRIPWIRE_CONF, {}).get("mode") or "disabled")
    try:
        active = subprocess.run(["systemctl", "is-active", "tuxwall-tripwire"],
                                capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        active = "unknown"
    h = _tripwire_read(TRIPWIRE_HEALTH, {})
    age = (now - float(h.get("ts") or 0)) if h.get("ts") else None
    watchers = {}
    for name, w in (h.get("watchers") or {}).items():
        if not isinstance(w, dict):
            continue
        beat = float(w.get("beat") or 0)
        state = str(w.get("state") or "unknown")
        if state == "running" and beat and now - beat > TRIPWIRE_WATCHER_STALE:
            state = "stale"
        watchers[name] = {"state": state, "age": round(now - beat, 1) if beat else None,
                          "restarts": int(w.get("restarts") or 0),
                          "events": int(w.get("events") or 0),
                          "error": str(w.get("error") or "")[:200],
                          "note": str(w.get("note") or "")[:200]}
    # v2 engines report which watchers the per-check settings need (a
    # source whose checks are all Off runs no thread); older ones: all of
    # them unless the mode is disabled
    wanted = h.get("wanted") if isinstance(h.get("wanted"), dict) else None
    if wanted is None:
        wanted = {n: mode != "disabled" for n in ("suricata", "canary")}
    problems = []
    if active != "active":
        problems.append("engine service is %s" % (active or "not running"))
    elif age is None:
        problems.append("engine has not reported a heartbeat")
    elif age > TRIPWIRE_HEALTH_STALE:
        problems.append("engine heartbeat is %d s old" % int(age))
    else:
        for name in ("suricata", "canary"):
            if not wanted.get(name):
                continue
            w = watchers.get(name)
            if not w or w["state"] != "running":
                problems.append("%s watcher is %s%s" % (
                    name, (w or {}).get("state", "missing"),
                    (" (%s)" % w["error"]) if w and w.get("error") and w["state"] != "running" else ""))
    for name, w in watchers.items():
        w["wanted"] = bool(wanted.get(name))
    return {"active": active, "heartbeat_age": round(age, 1) if age is not None else None,
            "watchers": watchers, "problems": problems, "healthy": not problems,
            "wanted": {n: bool(wanted.get(n)) for n in ("suricata", "canary")},
            "needed": any(wanted.values()) or bool(tripped)}


def _tripwire_audit_tail(n=10):
    try:
        with open(TRIPWIRE_AUDIT) as f:
            lines = f.readlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if isinstance(e, dict):
            e.pop("client", None)
            out.append(e)
    return out


def _tripwire_ui_config():
    """Per-check view from the engine (it owns the schema, the v1 -> v2
    migration and the history counts); None when the engine can't answer."""
    try:
        proc = subprocess.run([TRIPWIRE_BIN, "config"], capture_output=True, text=True,
                              timeout=15)
        data = json.loads(proc.stdout) if proc.returncode == 0 else None
    except Exception:
        data = None
    return data if isinstance(data, dict) and data.get("ok") else None


def tripwire_status():
    conf = _tripwire_read(TRIPWIRE_CONF, {})
    st = _tripwire_read(TRIPWIRE_STATE, {})
    ui = _tripwire_ui_config()
    if ui and isinstance(ui.get("config"), dict):
        conf = ui["config"]
    mode = str(conf.get("mode") or "disabled")
    # which parts of the lockdown are in the kernel: the engine reports it
    # (medium = FORWARD -i/-o <wan>, high = all forwarding + WAN input, both
    # + the router's egress REJECT); fall back to scanning the chains
    parts = (ui or {}).get("rules") if isinstance((ui or {}).get("rules"), dict) else None
    if parts is None:
        parts = {}
        try:
            for key, chain, rx in (("forward", "FORWARD", r'--comment "?TUXWALL-TRIPWIRE"? -j DROP'),
                                   ("input", "INPUT", r'--comment "?TUXWALL-TRIPWIRE"? -j DROP'),
                                   ("egress", "OUTPUT",
                                    r'--comment "?TUXWALL-TRIPWIRE-EGRESS"? -j REJECT')):
                parts[key] = all(re.search(rx, subprocess.run(
                    [ipt, "-S", chain], capture_output=True, text=True, timeout=10).stdout or "")
                    for ipt in ("iptables", "ip6tables"))
        except Exception:
            pass
    rules = bool(parts.get("forward"))
    if st.get("tripped") and st.get("mode") == "high":
        rules = rules and bool(parts.get("input"))

    def rec(v):
        return v if isinstance(v, dict) else None
    return {"ok": True,
            "mode": mode,
            "tripped": bool(st.get("tripped")),
            "trip_mode": st.get("mode"), "since": st.get("since"),
            "reason": st.get("reason"), "class": st.get("class"),
            "check": st.get("check") or "",
            "signature": st.get("signature") or "",
            "src_ip": st.get("src_ip"), "dst": st.get("dst") or "",
            "trips": st.get("trips") or 0,
            "resolved_at": st.get("resolved_at"), "resolved_by": st.get("resolved_by") or "",
            "logonly_events": int(st.get("logonly_events") or 0),
            "last_logonly": rec(st.get("last_logonly")),
            "absorbed_events": int(st.get("absorbed_events") or 0),
            "last_absorbed": rec(st.get("last_absorbed")),
            "rules_present": rules,
            "rules": {k: bool(parts.get(k)) for k in ("forward", "forward_all", "input", "egress",
                                                      "recovery")},
            "wan": [str(w) for w in ((ui or {}).get("wan") or [])][:4],
            "egress": (ui or {}).get("egress") or {},
            "engine": tripwire_health(mode, bool(st.get("tripped"))),
            "audit": _tripwire_audit_tail(10),
            "enabled": bool(conf.get("enabled", mode != "disabled")),
            "strength": conf.get("strength") or (mode if mode in ("medium", "high") else "medium"),
            "notify": conf.get("notify") or {},
            "checks": (ui or {}).get("checks") or [],
            "coming_later": (ui or {}).get("coming_later") or [],
            "history_info": (ui or {}).get("history") or {},
            "config_available": ui is not None,
            # recovery mode: phase normal | tripped | recovery (+ details)
            "phase": ((ui or {}).get("recovery") or {}).get("phase") or (
                ("recovery" if (st.get("recovery") or {}).get("active") else "tripped")
                if st.get("tripped") else "normal"),
            "recovery": (ui or {}).get("recovery") or {}}


def _tripwire_cli(args, timeout=30):
    proc = subprocess.run([TRIPWIRE_BIN] + args, capture_output=True, text=True,
                          timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "tripwire command failed").strip()[-200:])
    return (proc.stdout or "").strip()


class TripwireConfirmRequired(ValueError):
    pass


def _tripwire_json_cli(args, payload=None, timeout=30):
    """Engine commands that answer one JSON line: exit 0 ok, 2 refused
    (ValueError), 3 confirmation required."""
    proc = subprocess.run([TRIPWIRE_BIN] + args, capture_output=True, text=True,
                          timeout=timeout,
                          input=json.dumps(payload) if payload is not None else "")
    try:
        res = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        res = None
    if not isinstance(res, dict):
        raise RuntimeError((proc.stderr or proc.stdout or "tripwire command failed").strip()[-200:])
    if proc.returncode == 3 or res.get("confirm_required"):
        raise TripwireConfirmRequired(res.get("error") or "confirmation required")
    if proc.returncode != 0 or not res.get("ok", True):
        raise ValueError(res.get("error") or "refused by the tripwire engine")
    return res


TRIPWIRE_SETTING_KEYS = ("enabled", "strength", "notify")


def tripwire_configure(body, identity=None, client_ip="", keys=TRIPWIRE_SETTING_KEYS):
    """Settings patch (master switch, block strength, notify policy, or the
    per-check map) applied by the engine: validation, atomic root-0600
    write, refusal of a strength change while tripped, confirm gate for
    anything that arms blocking, audit entry with the dashboard user."""
    patch = {k: body[k] for k in keys if k in body}
    unknown = [k for k in body if k not in keys and k != "confirm"]
    if unknown:
        raise ValueError("unknown setting %r" % unknown[0])
    if not patch:
        raise ValueError("nothing to change")
    who = (identity or {}).get("username", "") or "unknown"
    args = ["configure", "--by", who, "--via", "dashboard", "--client", client_ip or ""]
    if body.get("confirm") is True:
        args.append("--confirm")
    res = _tripwire_json_cli(args, patch)
    return {"ok": True, "changes": res.get("changes") or [], "mode": (res.get("config") or {}).get("mode"),
            "tripped": bool(res.get("tripped")), "warning": res.get("warning") or ""}


def tripwire_test(body):
    """Simulate one event through the engine's real evaluation path - no
    history entry, no push, no enforcement."""
    check = str(body.get("check") or "").strip()
    if not re.match(r"^[a-z]+\.[a-z-]+$", check):
        raise ValueError("unknown check")
    event = body.get("event") or {}
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    return _tripwire_json_cli(["test", check], event)


TRIPWIRE_HISTORY = "/var/lib/tuxwall/tripwire-events.jsonl"
TRIPWIRE_HISTORY_ACTIONS = ("absorb", "excluded", "counted", "log", "block")


def tripwire_history(qs):
    """Event history, newest first; filters check / action / since / until,
    paged by offset + limit (max 200)."""
    def q(name):
        return (qs.get(name) or [""])[0].strip()
    check, action = q("check"), q("action")
    if action and action not in TRIPWIRE_HISTORY_ACTIONS:
        raise ValueError("unknown action filter")
    try:
        since = float(q("since") or 0)
        until = float(q("until") or 0)
        offset = max(0, int(q("offset") or 0))
        limit = max(1, min(200, int(q("limit") or 50)))
    except ValueError:
        raise ValueError("since/until/offset/limit must be numbers")
    rows = []
    try:
        with open(TRIPWIRE_HISTORY) as f:
            lines = f.readlines()
    except OSError:
        lines = []
    for ln in reversed(lines):
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(r, dict):
            continue
        ts = float(r.get("ts") or 0)
        if (check and r.get("check") != check) or (action and r.get("action") != action):
            continue
        if (since and ts < since) or (until and ts > until):
            continue
        rows.append(r)
    return {"ok": True, "items": rows[offset:offset + limit], "total": len(rows),
            "offset": offset, "limit": limit}


def tripwire_set_mode(body, identity=None, client_ip=""):
    """Legacy (v1) mode change through the engine, kept for scripts: only
    disabled (master switch off) and logonly (every check Log only) are
    accepted; arming blocking goes through the per-check settings. Atomic
    config write + audit entry with the dashboard user. A trip in force is
    never lifted; changing settings while tripped returns a warning."""
    mode = str(body.get("mode") or "").strip().lower()
    if mode not in TRIPWIRE_MODES:
        raise ValueError("mode must be disabled, logonly, medium or high")
    who = (identity or {}).get("username", "") or "unknown"
    return _tripwire_json_cli(["set-mode", mode, "--by", who, "--via", "dashboard",
                               "--client", client_ip or ""])


def _tripwire_check_password(identity, password):
    if not identity:
        raise PermissionError("Authentication required")
    users = _load_users()
    user = _find_user(users, identity["username"])
    if user is None:
        raise PermissionError("Account no longer exists")
    if not hmac.compare_digest(_hash_password(str(password or ""), user["salt"]), user["hash"]):
        raise PermissionError("Password is incorrect")


def tripwire_resolve(body, identity, client_ip=""):
    """Lift the lockdown. Deliberate two-step: admin session PLUS the
    acting admin's password - a stolen dashboard session must never be
    enough to re-open the WAN during a trip - plus the restore checklist
    (findings reviewed, cause fixed/understood, confirm) and an optional
    note, validated and audited by the engine (`restore`), which ends a
    recovery window first."""
    _tripwire_check_password(identity, body.get("password"))
    res = _tripwire_json_cli(["restore", "--by", identity["username"], "--via", "dashboard",
                              "--client", client_ip or ""],
                             {"checklist": body.get("checklist"), "note": body.get("note") or ""},
                             timeout=90)
    return {"ok": True, "detail": str(res.get("detail") or "")[:200]}


def _tripwire_who(identity, client_ip):
    return ["--by", (identity or {}).get("username", "") or "unknown", "--via", "dashboard",
            "--client", client_ip or ""]


def tripwire_recovery_extend(body, identity, client_ip=""):
    minutes = body.get("minutes")
    if isinstance(minutes, bool) or not isinstance(minutes, (int, str)):
        raise ValueError("minutes must be a whole number")
    return _tripwire_json_cli(["recovery-extend", "--minutes", str(minutes)]
                              + _tripwire_who(identity, client_ip))


def tripwire_recovery_end(identity, client_ip=""):
    """Back to the full block (less access, so no password needed)."""
    return _tripwire_json_cli(["recovery-end"] + _tripwire_who(identity, client_ip), timeout=60)


CANARY_TAIL_BYTES = 512 * 1024
CANARY_VIEW_TTL = 10
_CANARY_VIEW = {"ts": 0.0, "data": None}
_CANARY_VIEW_LOCK = threading.Lock()


def _canary_tail_lines(path, max_bytes, max_lines):
    """The last max_lines complete lines of a file, reading at most
    max_bytes from its end (the log is never read whole)."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        start = max(0, size - max_bytes)
        f.seek(start)
        data = f.read(max_bytes)
    lines = data.decode("utf-8", "replace").splitlines()
    if start and lines:
        lines = lines[1:]          # first line is partial
    return lines[-max_lines:]


def build_canary():
    """Cached (CANARY_VIEW_TTL) view of _build_canary(): every Security poll
    used to re-read the whole opencanary.log."""
    now = time.time()
    with _CANARY_VIEW_LOCK:
        if _CANARY_VIEW["data"] is not None and now - _CANARY_VIEW["ts"] < CANARY_VIEW_TTL:
            return _CANARY_VIEW["data"]
    data = _build_canary()
    with _CANARY_VIEW_LOCK:
        _CANARY_VIEW.update(ts=time.time(), data=data)
    return data


def _build_canary():
    """Deception-services overview: emulated ports, events (with captured
    credentials), CrowdSec bans originated by the canary, and stat-card
    counters matching the honeypot card's grid."""
    active = False
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", CANARY_SERVICE],
            capture_output=True, text=True, timeout=5)
        active = (proc.stdout or "").strip() == "active"
    except Exception:
        pass

    modules, ports = [], []
    try:
        with open(CANARY_CONF, "r") as f:
            conf = json.load(f)
        for k, v in conf.items():
            if k.endswith(".enabled") and v:
                name = k.rsplit(".", 1)[0]
                modules.append({"name": name, "port": conf.get(name + ".port")})
    except (OSError, ValueError):
        pass
    modules.sort(key=lambda m: m["port"] or 0)

    events = []
    total_24h = sources_24h = creds_24h = 0
    seen = set()
    now = time.time()
    try:
        lines = _canary_tail_lines(CANARY_LOG, CANARY_TAIL_BYTES, CANARY_READ_LINES)
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if not isinstance(e, dict) or e.get("src_host") in ("", None):
                continue
            ts = e.get("local_time_adjusted") or e.get("utc_time") or ""
            try:
                epoch = time.mktime(time.strptime(ts.split(".")[0], "%Y-%m-%d %H:%M:%S"))
            except (ValueError, TypeError):
                epoch = now
            logtype = e.get("logtype")
            if logtype in (1000, 1001, 1002, 1003, 1004, 1005):
                continue    # service bookkeeping, not attacks
            if now - epoch <= CANARY_EVENT_WINDOW:
                total_24h += 1
                seen.add(e.get("src_host"))
                if logtype == 4002:
                    creds_24h += 1
            events.append({
                "ts": epoch,
                "src": e.get("src_host"),
                "dst_port": e.get("dst_port"),
                "service": CANARY_LOGTYPES.get(logtype, "event %s" % logtype),
                "detail": _canary_event_detail(
                    logtype, e.get("logdata") if isinstance(e.get("logdata"), dict) else {}),
            })
    except OSError:
        pass
    sources_24h = len(seen)
    events.sort(key=lambda e: -e["ts"])
    events = events[:25]

    ban_count, last_ban_ip = _canary_ban_snapshot()

    # WAN ports the watchdog last saw bound AND opened (every 60 s)
    with CANARY_FW_LOCK:
        fw_last = dict(CANARY_FW_STATE.get("last") or {})
    listening = sorted(int(p) for p in (fw_last.get("open_ports") or []))

    return {
        "ok": True,
        "active": active,
        "service": CANARY_SERVICE,
        "modules": modules,
        "listening_ports": (listening if fw_last.get("ok") and not fw_last.get("skipped")
                            else None),
        "listening_checked_at": fw_last.get("at"),
        "events_24h": total_24h,
        "sources_24h": sources_24h,
        "creds_24h": creds_24h,
        "bans_active": ban_count,
        "last_ban_ip": last_ban_ip,
        "events": events,
        "hint": None if active else
                "opencanary.service is not active - no emulators are listening",
    }


def _canary_can_manage():
    """True if this host runs the canary (unit + config present)."""
    return os.path.exists("/etc/systemd/system/opencanary.service")


def set_canary_enabled(enabled):
    """Enable or disable the canary service with matching firewall rules.

    Enable: start the service first, then open WAN rules only for the
    ports it actually bound (bind-first, the tarpit's invariant). Disable:
    stop the service and close exactly its rules - the tarpit's ports and
    every other rule stay untouched. Both go through _canary_fw_reconcile()
    (IPv4-only rules: the canary binds the WAN IPv4 only).
    """
    if not _canary_can_manage():
        return {"ok": False, "error": "opencanary is not installed on this host"}
    with _CANARY_VIEW_LOCK:
        _CANARY_VIEW.update(ts=0.0, data=None)
    if enabled:
        try:
            subprocess.run(["systemctl", "enable", "--now", CANARY_SERVICE],
                           capture_output=True, text=True, timeout=30)
            time.sleep(4)     # let the emulators bind before opening rules
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        res = _canary_fw_reconcile(force=True)
        opened = sorted(set(res.get("open_ports") or []))
        _honey_log("canary enabled (ports {})".format(opened))
        return {"ok": True, "enabled": True, "ports": opened}
    try:
        subprocess.run(["systemctl", "disable", "--now", CANARY_SERVICE],
                       capture_output=True, text=True, timeout=30)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    res = _canary_fw_reconcile(force=True)
    closed = sorted({r[1] for r in res.get("removed") or []})
    _honey_log("canary disabled (ports closed: {})".format(closed))
    return {"ok": True, "enabled": False, "ports": closed}


# --- Canary firewall watchdog ------------------------------------------------
# The canary's WAN allow rules must never be wider than its live listeners
# (same invariant as the tarpit watchdog): every CANARY_FW_INTERVAL the
# tuxwall-canary rules are reconciled with what twistd actually has bound on
# the WAN IPv4 - rules close when the canary is down (after a grace pass, so
# a Restart=always blip never flaps the firewall) and reopen when it is back.
# IPv4 only: the canary binds the WAN IPv4, an IPv6 rule would open a port
# with no listener. Old IPv6 / SNMP rules are removed by the same pass.
CANARY_FW_INTERVAL = 60
CANARY_UDP_MODULES = ("snmp", "ntp", "tftp", "sip")
CANARY_FW_STATE = {"pending": None, "last": None, "thread": None, "restart_at": 0.0}
CANARY_FW_LOCK = threading.Lock()
CANARY_RESTART_MIN_GAP = 900


def _canary_conf_data():
    try:
        with open(CANARY_CONF, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _canary_conf_ports(conf=None):
    """{(port, proto)} of the modules enabled in the live OpenCanary config."""
    conf = _canary_conf_data() if conf is None else conf
    out = set()
    for k, v in conf.items():
        if not (k.endswith(".enabled") and v is True):
            continue
        name = k[:-len(".enabled")]
        try:
            p = int(conf.get(name + ".port"))
        except (TypeError, ValueError):
            continue
        if 1 <= p <= 65535:
            out.add((p, "udp" if name in CANARY_UDP_MODULES else "tcp"))
    return out


def _canary_bound_tcp(wan_ip, ss_out):
    """TCP ports twistd listens on at the WAN IPv4 (from `ss -Htlnp`)."""
    ports = set()
    for line in (ss_out or "").splitlines():
        f = line.split()
        if len(f) < 4 or "twistd" not in line:
            continue
        addr, _, port = f[3].rpartition(":")
        if addr.strip("[]") != wan_ip:
            continue
        try:
            ports.add(int(port))
        except ValueError:
            continue
    return ports


def _canary_fw_plan(active, bound_tcp, conf_ports, rules):
    """Pure: (add, remove). `rules` = {(family, port, proto)} tuxwall-canary
    rules present now. Wanted = an IPv4 TCP rule per configured TCP port
    twistd has bound on the WAN IPv4 (nothing when the canary is down)."""
    want = set()
    if active:
        want = {("v4", p, "tcp") for p in bound_tcp if (p, "tcp") in conf_ports}
    add = sorted(want - set(rules))
    remove = sorted(set(rules) - want)
    return add, remove


def _canary_fw_rules(wan):
    rs = _fw_guard.load_ruleset(_fw_ctx(raw=False))
    out = set()
    for r in rs["v4"] + rs["v6"]:
        if not (r.get("comment") or "").startswith("tuxwall-canary"):
            continue
        if r.get("route") or r.get("dir") != "in" or r.get("in") != wan:
            continue
        if r.get("action") != "allow" or not (_fw_guard._any(r.get("src"))
                                              and _fw_guard._any(r.get("dst"))):
            continue        # hand-made variant: never touched automatically
        p = _fw_guard._single_port(r.get("dport"))
        if p:
            out.add((r["family"], int(p), r.get("proto") or "tcp"))
    return out


def _canary_fw_reconcile(force=False):
    """One reconcile pass. Removals need the same plan twice in a row
    (one CANARY_FW_INTERVAL apart) unless force=True; additions apply at
    once (bind-first: only ports twistd really holds). Never raises."""
    res = {"ok": True, "added": [], "removed": [], "pending": [], "open_ports": []}
    try:
        if _fw_guard is None or not _canary_can_manage():
            return {"ok": True, "skipped": "canary not managed here"}
        wan = _honey_wan_iface()
        wan_ip = _honey_wan_ip()
        try:
            active = subprocess.run(["systemctl", "is-active", CANARY_SERVICE],
                                    capture_output=True, text=True,
                                    timeout=10).stdout.strip() == "active"
            ss = subprocess.run(["ss", "-Htlnp"], capture_output=True, text=True, timeout=10)
        except Exception as exc:
            return {"ok": False, "error": "probe failed: %s" % (exc,)}
        if ss.returncode != 0 or not wan:
            return {"ok": False, "error": "ss failed or no WAN interface - nothing changed"}
        bound = _canary_bound_tcp(wan_ip, ss.stdout) if (active and wan_ip) else set()
        rules = _canary_fw_rules(wan)
        add, remove = _canary_fw_plan(active, bound, _canary_conf_ports(), rules)
        with CANARY_FW_LOCK:
            prev = CANARY_FW_STATE["pending"]
            CANARY_FW_STATE["pending"] = list(remove) if remove else None
        do_remove = list(remove) if force else [r for r in remove if prev and r in prev]
        res["pending"] = [r for r in remove if r not in do_remove]
        with _fw_move_lock:
            for fam, port, proto in do_remove:
                try:
                    _ufw(["delete", "allow", "in", "on", wan, "to",
                          "::/0" if fam == "v6" else "0.0.0.0/0",
                          "port", str(port), "proto", proto])
                    res["removed"].append((fam, port, proto))
                except Exception as exc:
                    res["ok"] = False
                    res.setdefault("errors", []).append("%s %d/%s: %s" % (fam, port, proto, exc))
            for fam, port, proto in add:
                try:
                    _ufw(["allow", "in", "on", wan, "to", "0.0.0.0/0", "port", str(port),
                          "proto", proto, "comment", "tuxwall-canary"])
                    res["added"].append((fam, port, proto))
                except Exception as exc:
                    res["ok"] = False
                    res.setdefault("errors", []).append("%s %d/%s: %s" % (fam, port, proto, exc))
        if res["removed"]:
            with CANARY_FW_LOCK:
                CANARY_FW_STATE["pending"] = None
            _honey_log("canary watchdog: closed {} ({})".format(
                ", ".join("%d/%s %s" % (p, pr, f) for f, p, pr in res["removed"]),
                "canary active" if active else "canary not running"))
        if res["added"]:
            _honey_log("canary watchdog: opened {} (twistd bound on {})".format(
                ", ".join("%d/%s v4" % (p, pr) for _, p, pr in res["added"]), wan_ip))
        res["open_ports"] = sorted({p for f, p, pr in (rules - set(res["removed"]))
                                    | set(res["added"]) if f == "v4"})
        res["active"] = active
        # The canary renders its config with the WAN IPv4 at start; after a
        # WAN change it listens on a dead address until restarted.
        listen = str(_canary_conf_data().get("device.listen_addr") or "")
        if active and wan_ip and listen and listen != wan_ip:
            with CANARY_FW_LOCK:
                due = time.time() - CANARY_FW_STATE["restart_at"] >= CANARY_RESTART_MIN_GAP
                if due:
                    CANARY_FW_STATE["restart_at"] = time.time()
            if due:
                _honey_log("canary watchdog: WAN IPv4 changed ({} -> {}) - restarting "
                           "the canary to rebind".format(listen, wan_ip))
                subprocess.run(["systemctl", "restart", CANARY_SERVICE],
                               capture_output=True, text=True, timeout=60)
                res["restarted"] = True
    except Exception as exc:
        res = {"ok": False, "error": repr(exc)}
    with CANARY_FW_LOCK:
        CANARY_FW_STATE["last"] = dict(res, at=time.time())
    return res


def _canary_fw_watchdog():
    while True:
        time.sleep(CANARY_FW_INTERVAL)
        r = _canary_fw_reconcile()
        if not r.get("ok"):
            print("[canary-fw] %s" % (r.get("error") or r.get("errors")), flush=True)


def start_canary_fw_watchdog():
    if not _canary_can_manage():
        return None
    with CANARY_FW_LOCK:
        t = CANARY_FW_STATE["thread"]
        if t is not None and t.is_alive():
            return t
        t = threading.Thread(target=_canary_fw_watchdog, name="canary-fw", daemon=True)
        CANARY_FW_STATE["thread"] = t
    t.start()
    return t


# --- Community reporting policy ---------------------------------------------
# tuxwall.org receives deception evidence ONLY: canary and honeypot catches
# (a completed handshake to a service that does not exist - zero
# false-positive potential). Manual actions - local timed bans, custom
# blocklist adds, CLI decisions - are NEVER reported: they carry user
# judgment, and one bad ban (someone blocking Netflix "thinking it was an
# attacker") must never be able to break services on every install
# pulling the community list. The states/helpers below remain for the
# (removed) engine/CLI decision watcher; kept so old state files and any
# future watcher skip-list stay consistent with that policy.
BAN_REPORT_STATE = os.path.join(BLOCKLIST_DIR, "reported-decisions.json")
BAN_REPORT_LOCK = threading.Lock()
BAN_REPORT_INTERVAL = 60
BAN_REPORT_SKIP_REASONS = ("honeypot/",          # reported at ban time
                           "custom/custom-blocklist",  # ditto (blocklist add)
                           "manual ban")         # ditto (dashboard manual ban)
BAN_REPORT_SOURCES = ("crowdsec", "cscli")  # cscli covers CLI-made bans;
                                           # "capi" excluded: those IPs came
                                           # FROM community lists (circular)


def _load_reported_ban_ids():
    try:
        with open(BAN_REPORT_STATE, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            ids = [int(i) for i in data if str(i).isdigit()]
            return set(ids[-20000:])
    except (OSError, ValueError):
        pass
    return set()


def _save_reported_ban_ids(ids):
    os.makedirs(os.path.dirname(BAN_REPORT_STATE), exist_ok=True)
    tmp = BAN_REPORT_STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(ids)[-20000:], f)
    os.replace(tmp, BAN_REPORT_STATE)


# NOTE: engine/CLI CrowdSec decisions are deliberately NOT reported.
# Manual and engine bans carry contributor judgment (only as good as the
# person banning; one bad ban pollutes every install pulling the list).
# Deception catches carry their own evidence - a completed handshake to a
# service that does not exist - so they are the only community data.
# The watcher that reported engine/CLI decisions was removed with this.

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
        **_suricata_talkers(alerts),
    }


def _suricata_talkers(alerts):
    """Aggregate the alert window for the Overview's Router Insights panel:
    the hosts involved in the most alerts (as source or destination), the
    most-targeted destination ports, and alerts per hour."""
    hosts = {}
    ports = {}
    hourly = {}
    now = time.time()
    for a in alerts:
        sev = a.get("severity") or "LOW"
        for role, ip, peer in (("src", a.get("src"), a.get("dst")),
                               ("dst", a.get("dst"), a.get("src"))):
            if not ip or (role == "dst" and ip == a.get("src")):
                continue
            h = hosts.get(ip)
            if h is None:
                try:
                    local = ipaddress.ip_address(ip).is_private
                except ValueError:
                    local = False
                h = hosts[ip] = {"ip": ip, "local": local, "count": 0, "as_src": 0,
                                 "as_dst": 0, "high": 0, "medium": 0, "low": 0,
                                 "last_ts": a.get("ts") or 0, "_sigs": {}, "_peers": set()}
            h["count"] += 1
            h["as_" + role] += 1
            h[sev.lower() if sev.lower() in ("high", "medium", "low") else "low"] += 1
            sig = a.get("sig") or "unknown"
            h["_sigs"][sig] = h["_sigs"].get(sig, 0) + 1
            if peer and len(h["_peers"]) < 500:
                h["_peers"].add(peer)
            if (a.get("ts") or 0) > h["last_ts"]:
                h["last_ts"] = a.get("ts") or 0
        dport = a.get("dport")
        if dport:
            key = "{}/{}".format(dport, a.get("proto") or "")
            ports[key] = ports.get(key, 0) + 1
        ts = a.get("ts")   # epoch seconds (build_suricata parses eve.json timestamps)
        if isinstance(ts, (int, float)) and now - ts < 86400:
            bucket = int(ts // 3600) * 3600
            hourly[bucket] = hourly.get(bucket, 0) + 1
    talkers = sorted(hosts.values(), key=lambda h: (-h["count"], -h["high"]))[:15]
    for h in talkers:
        sigs = sorted(h.pop("_sigs").items(), key=lambda kv: -kv[1])
        h["sigs"] = [{"sig": k, "count": v} for k, v in sigs[:3]]
        h["peers"] = len(h.pop("_peers"))
    first_hour = int(now // 3600) * 3600 - 23 * 3600
    return {
        "talkers": talkers,
        "talker_hosts": len(hosts),
        "top_ports": [{"port": k, "count": v} for k, v in
                      sorted(ports.items(), key=lambda kv: -kv[1])[:10]],
        "hourly": [{"t": first_hour + i * 3600, "count": hourly.get(first_hour + i * 3600, 0)}
                   for i in range(24)],
    }


# --- Zeek (passive network analysis) ----------------------------------------
# Zeek runs as a passive sensor on the LAN interface (enp6s0): it sniffs a
# copy of every packet but never sits in the forwarding path, so router
# throughput is unaffected. Two feeds back the Security tab panels:
#   notice.log — Zeek's Notice framework events (scan detection, SSL
#                certificate anomalies, DNS weirdness, protocol violations)
#   conn.log   — per-connection records used to build an outbound activity
#                profile per LAN device for malware/C2 hunting.

ZEEK_LOG_DIR = "/opt/zeek/logs/current"
ZEEK_NOTICE_LOG = os.path.join(ZEEK_LOG_DIR, "notice.log")
ZEEK_CONN_LOG = os.path.join(ZEEK_LOG_DIR, "conn.log")
ZEEK_WINDOW = 86400
ZEEK_TAIL_BYTES = 4 * 1024 * 1024
ZEEK_DEVICE_WINDOW = 3600


def _zeek_tail_lines(path):
    """Read complete JSON lines from the tail of a Zeek log (bounded memory)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if st.st_size == 0:
        return []
    start = max(0, st.st_size - ZEEK_TAIL_BYTES)
    try:
        with open(path, "r", errors="replace") as f:
            f.seek(start)
            if start:
                f.readline()
            data = f.read()
    except OSError:
        return None
    return [raw.strip() for raw in data.splitlines() if raw.strip()]


def _zeek_endpoint(ev, vec_key, addr_key):
    """Extract ("addr", "port") from a Zeek JSON record, tolerating both the
    flattened layout ("id.orig_h" / "id.orig_p") and the structured one
    ("src": [{"addr": ..., "port": ...}]) used by different Zeek writers."""
    val = ev.get(vec_key)
    if isinstance(val, dict):
        return str(val.get("addr") or ""), val.get("port")
    if isinstance(val, list) and val and isinstance(val[0], dict):
        return str(val[0].get("addr") or ""), val[0].get("port")
    return str(ev.get(addr_key) or ""), ev.get("id.orig_p" if addr_key == "id.orig_h" else "id.resp_p")


def _zeek_is_lan(ip):
    """True for addresses on this router's LAN/VPN side (private ranges)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# --- AIDE file integrity ------------------------------------------------------
AIDE_BINARY = "/usr/bin/aide"
AIDE_CONF = "/etc/aide/aide.conf"
AIDE_DB = "/var/lib/aide/aide.db"
AIDE_DB_NEW = "/var/lib/aide/aide.db.new"
AIDE_LOG = "/var/log/aide/aide.log"
AIDE_NIGHTLY = "/etc/cron.daily/dailyaidecheck"
AIDE_TIMEOUT = 3600  # init took ~26 min on this host; allow an hour

AIDE_STATE = {
    "running": False,
    "op": None,          # "check" | "update"
    "started_at": None,
    "finished_at": None,
    "summary": None,
    "changes": [],
    "raw_tail": [],
    "error": None,
}
AIDE_LOCK = threading.Lock()

AIDE_SUMMARY_RES = {
    "total": re.compile(r"number of entries:\s*(\d+)", re.IGNORECASE),
    "added": re.compile(r"Added entries:\s*(\d+)"),
    "removed": re.compile(r"Removed entries:\s*(\d+)"),
    "changed": re.compile(r"Changed entries:\s*(\d+)"),
}
# Real AIDE 0.19 output: section headers ("Added entries:") followed by
# entry lines like "f++++++++++++++++++: /path" (type char + attr deltas).
AIDE_SECTION_RE = re.compile(r"^(Added|Removed|Changed) entries:\s*$")
AIDE_ENTRY_RE = re.compile(r"^[a-zA-Z][\w.+-]*:\s+(/[^\s]+)")


def _aide_parse_report(text):
    """Extract summary counts and changed paths from an AIDE report."""
    summary = {}
    for key, rex in AIDE_SUMMARY_RES.items():
        m = rex.search(text)
        summary[key] = int(m.group(1)) if m else None
    changes = []
    section = None
    for line in text.splitlines():
        line = line.rstrip()
        if not line or set(line) == {"-"}:
            continue
        m = AIDE_SECTION_RE.match(line)
        if m:
            section = m.group(1).lower()
            continue
        if not section:
            continue
        m = AIDE_ENTRY_RE.match(line)
        if m:
            changes.append({"type": section, "path": m.group(1)[:160]})
            if len(changes) >= 100:
                break
    return summary, changes[:100]


def _aide_last_nightly():
    """Best-effort parse of the most recent run in /var/log/aide/aide.log."""
    try:
        with open(AIDE_LOG, "r") as f:
            text = f.read()
    except OSError:
        return None
    chunks = text.split("Start timestamp:")
    if not text.strip():
        return None
    last = chunks[-1]
    try:
        mtime = os.path.getmtime(AIDE_LOG)
    except OSError:
        mtime = None
    summary, changes = _aide_parse_report(last)
    m = re.search(r"Start timestamp:\s*([^\n]+)", last)
    return {
        "started": (m.group(1).strip() if m else None),
        "mtime": mtime,
        "summary": summary,
        "changes": changes[:50],
    }


def _aide_run(op):
    """Run aide --check/--update in the background and update AIDE_STATE."""
    cmd = [AIDE_BINARY, "--config=" + AIDE_CONF, "--" + op]
    started = time.time()
    AIDE_STATE.update({
        "running": True, "op": op, "started_at": started,
        "finished_at": None, "summary": None, "changes": [],
        "raw_tail": [], "error": None,
    })
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=AIDE_TIMEOUT,
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        summary, changes = _aide_parse_report(text)
        tail = [l for l in text.splitlines() if l.strip()][-40:]
        AIDE_STATE.update({
            "summary": summary,
            "changes": changes,
            "raw_tail": tail,
            # AIDE exit codes are a bitmask: 1=added 2=removed 4=changed.
            # Anything below 8 is a valid result (changes present), not an error.
            "error": None if 0 <= proc.returncode < 8 else
                     "aide --{} exited {}: {}".format(op, proc.returncode, (proc.stderr or "").strip()[:300]),
        })
        if op == "update" and 0 <= proc.returncode < 8:
            # promote aide.db.new to the baseline (preserve ownership/mode)
            try:
                st = os.stat(AIDE_DB)
                os.replace(AIDE_DB_NEW, AIDE_DB)
                os.chown(AIDE_DB, st.st_uid, st.st_gid)
                os.chmod(AIDE_DB, st.st_mode & 0o7777)
            except OSError as exc:
                AIDE_STATE["error"] = "baseline promotion failed: {}".format(exc)
    except subprocess.TimeoutExpired:
        AIDE_STATE["error"] = "aide --{} timed out after {}s".format(op, AIDE_TIMEOUT)
    except Exception as exc:
        AIDE_STATE["error"] = str(exc)
    finally:
        AIDE_STATE["running"] = False
        AIDE_STATE["finished_at"] = time.time()


def start_aide_run(op):
    if op not in ("check", "update"):
        return {"ok": False, "error": "Invalid operation"}
    if not os.path.exists(AIDE_BINARY):
        return {"ok": False, "error": "AIDE is not installed"}
    with AIDE_LOCK:
        if AIDE_STATE["running"]:
            return {"ok": True, "running": True, "message": "AIDE is already running"}
        threading.Thread(target=_aide_run, args=(op,), daemon=True).start()
    return {"ok": True, "running": True, "message": "AIDE {} started".format(op)}


def build_aide():
    """AIDE status: baseline db info, nightly cron, last run, live job state."""
    enabled = os.path.exists(AIDE_BINARY)
    db = None
    try:
        st = os.stat(AIDE_DB)
        db = {"mtime": st.st_mtime, "size": st.st_size}
    except OSError:
        pass
    version = None
    try:
        proc = subprocess.run([AIDE_BINARY, "--version"], capture_output=True,
                              text=True, timeout=10)
        m = re.search(r"AIDE\s+([\d.]+)", proc.stdout or proc.stderr or "")
        version = m.group(1) if m else None
    except Exception:
        pass
    state = {k: AIDE_STATE.get(k) for k in
             ("running", "op", "started_at", "finished_at", "summary",
              "changes", "error")}
    return {
        "ok": True,
        "enabled": enabled,
        "version": version,
        "db": db,
        "nightly": {
            "enabled": os.path.exists(AIDE_NIGHTLY),
            "last": _aide_last_nightly(),
        },
        "state": state,
        "hint": None if enabled else
                "AIDE is not installed (apt install aide && aideinit)",
    }


# --- Honeypot (WAN port-garden tarpit) -----------------------------------------
# Trap WAN port scanners: bind classic scan ports on the WAN address only,
# hold each connection open with a clamped TCP window (tarpit), and auto-ban
# the source via CrowdSec. Any connection to these ports is hostile by
# definition, so no reputation cross-checking is needed before a ban.
HONEY_CONF_FILE = os.path.join(BLOCKLIST_DIR, "honeypot.json")
# --- Network portability (2026-11-10 audit #10) ---------------------------
# /etc/tuxwall/network.json is the single source of truth for interface
# roles. The installer seeds it from the actual box; everything that
# used to hardcode one machine's names (enp5s0, enp6s0, 192.168.1.x)
# reads from here. Absent file = derive dynamically (first boot before
# the wizard runs), never a hardcoded guess.
NETWORK_CONF = "/etc/tuxwall/network.json"


def _net_conf():
    try:
        with open(NETWORK_CONF) as f:
            return json.load(f)
    except Exception:
        return {}


def _detect_wan_iface():
    """The interface holding the default route, or the config's answer."""
    conf = _net_conf()
    if conf.get("wan_iface"):
        return str(conf["wan_iface"])
    topo = _topo("wan_device")
    if topo:
        return topo
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        if " dev " in out:
            return out.split(" dev ")[1].split()[0]
    except Exception:
        pass
    return ""


def _lan_subnets():
    """Private subnets the router serves (LAN, VLANs, VPN) — never the
    WAN. Used by the honeypot LAN guard, the tarpit, and anywhere that
    used to hardcode 192.168.1.0/24."""
    conf = _net_conf()
    if conf.get("lan_subnets"):
        return [ipaddress.ip_network(str(n))
                for n in conf["lan_subnets"] if n]
    # dynamic: every private subnet on every non-WAN interface
    wan = _detect_wan_iface()
    nets = []
    try:
        out = subprocess.run(["ip", "-o", "addr", "show"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            if iface == "lo" or iface == wan or iface.startswith(wan + "."):
                continue
            cidr = parts[3]
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if net.is_private and not net.is_loopback and not net.is_link_local:
                    if net not in nets:
                        nets.append(net)
            except ValueError:
                continue
    except Exception:
        pass
    # loopback always counts as "ours"
    nets.append(ipaddress.ip_network("127.0.0.0/8"))
    return nets


def _honey_wan_iface():
    """The deception layer's WAN: network.json override, else the default
    route, re-read on every use (an import-time constant would freeze the
    answer from whenever the API happened to start - including a moment
    when the route was briefly down). enp5s0 is a last resort only."""
    return _detect_wan_iface() or "enp5s0"


HONEY_WAN_IFACE = _honey_wan_iface()  # legacy references during migration
HONEY_DEFAULT_PORTS = [23, 2323, 3389, 445, 5555]
HONEY_MAX_TOTAL = 256        # concurrent trapped sockets across all ports
HONEY_MAX_PER_IP = 8         # concurrent trapped sockets per source IP
HONEY_MAX_HOLD = 4 * 3600    # hold a single connection at most 4 hours
HONEY_TICK = 10              # poll interval / dribble period (seconds)
HONEY_REASON = "honeypot/tuxwall"

# 2026-11-19 (deception phase 1): the slot accounting is done with real
# per-IP / total counters reserved BEFORE a tarpit thread exists (the old
# map was keyed (ip, port), so the per-IP cap never fired and one source
# could hold unlimited threads/fds), and the hit counter is a bounded TTL map.
HONEY_HITS_MAX = 20000       # distinct sources remembered for the threshold
HONEY_HITS_TTL = 86400       # ... for a day after their last connection
HONEY_ACCEPT_BACKOFF = 1.0   # seconds to pause after an accept() error

HONEY_STATE = {
    "listening": False,
    "wan_ip": None,
    "wan_ip6": None,
    "ports": [],
    "threads": [],
    "active": {},            # slot id -> {"ip","port","connected_at"}
    "per_ip": {},            # ip -> live tarpit slots
    "gen": 0,                # bumped on stop: older tarpit threads exit
    "traps": [],              # closed connection history (bounded)
    "hits": BoundedTTLMap(HONEY_HITS_MAX, HONEY_HITS_TTL),  # ip -> {"hits","first","last","actioned"}
    "stats": {"total": 0, "unique": 0, "wasted": 0, "banned": 0, "lan_guard": 0,
              "dropped": 0, "guarded": 0, "ban_failed": 0, "reported": 0,
              "accept_errors": 0, "thread_errors": 0},
    "log": [],
    "started_at": None,
    "error": None,
    "sockets": {},      # port -> live bound trap socket
    "watchdog": None,
}
HONEY_STOP = threading.Event()
HONEY_APPLY_LOCK = threading.RLock()
HONEY_SLOT_IDS = itertools.count(1)
HONEY_LAN_TTL = 300
_HONEY_LAN = {"ts": 0.0, "nets": None}
_HONEY_ACCEPT_ERR_LOGGED = {}


def _deception_lan_nets():
    """Every network the router serves - LAN, VLANs, OPT ports, WireGuard -
    including GLOBAL IPv6 prefixes (the delegated /64 on the LAN is
    globally routable, so `not is_global` alone missed it). Read from the
    interfaces (never the WAN), plus interfaces.json/network.json and
    loopback."""
    nets = list(_lan_subnets())
    wan = _honey_wan_iface()
    try:
        out = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True,
                             text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[2] not in ("inet", "inet6"):
                continue
            iface = parts[1].split("@")[0]
            if iface == "lo" or not wan or iface == wan or iface.startswith(wan + "."):
                continue
            try:
                net = ipaddress.ip_interface(parts[3]).network
            except ValueError:
                continue
            if net.is_link_local:
                continue
            if net.version == 4 and not net.is_private:
                continue        # a public v4 on a LAN port is not ours to guard
            if net.version == 6 and net.prefixlen < 48:
                continue
            if net not in nets:
                nets.append(net)
    except Exception:
        pass
    topo = {}
    try:
        with open("/etc/tuxwall/interfaces.json") as f:
            topo = json.load(f) or {}
    except (OSError, ValueError):
        topo = {}
    for sect in [topo.get("lan") or {}] + list(topo.get("opt") or []) + list(topo.get("vpn") or []):
        if not isinstance(sect, dict):
            continue
        for key in ("address", "address6"):
            try:
                net = ipaddress.ip_interface(str(sect.get(key) or "")).network
            except ValueError:
                continue
            if net not in nets:
                nets.append(net)
    for extra in ("127.0.0.0/8", "::1/128"):
        n = ipaddress.ip_network(extra)
        if n not in nets:
            nets.append(n)
    return nets


def _honey_lan_nets():
    now = time.time()
    nets = _HONEY_LAN["nets"]
    if nets is None or now - _HONEY_LAN["ts"] >= HONEY_LAN_TTL:
        try:
            nets = _deception_lan_nets()
        except Exception:
            nets = nets or [ipaddress.ip_network("127.0.0.0/8")]
        _HONEY_LAN.update(ts=now, nets=nets)
    return nets


def _honey_is_lan(ip):
    """True for anything the deception layer must treat as ours: invalid,
    non-global IPv6 (ULA, link-local, loopback), or inside any LAN/VLAN/VPN
    network incl. the delegated global IPv6 prefix."""
    try:
        a = _plain_ip(ipaddress.ip_address(str(ip).split("%")[0]))
    except ValueError:
        return True
    if a.version == 6 and not a.is_global:
        return True
    return any(a.version == net.version and a in net for net in _honey_lan_nets())


def _honey_load_conf():
    conf = {
        "enabled": False,
        "ports": list(HONEY_DEFAULT_PORTS),
        "auto_ban": True,
        "ban_threshold": 1,
        "max_hold": HONEY_MAX_HOLD,
    }
    try:
        with open(HONEY_CONF_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            conf.update({k: data[k] for k in conf if k in data})
    except (OSError, ValueError):
        pass
    conf["ports"] = _honey_valid_ports(conf["ports"])
    return conf


def _honey_valid_ports(ports):
    try:
        vals = sorted({int(p) for p in (ports or [])})
    except (TypeError, ValueError):
        return []
    return [p for p in vals if 1 <= p <= 65535][:16]


def _honey_save_conf(conf):
    os.makedirs(os.path.dirname(HONEY_CONF_FILE), exist_ok=True)
    tmp = HONEY_CONF_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(conf, f, indent=2)
    os.replace(tmp, HONEY_CONF_FILE)
    _HONEY_CONF_CACHE["conf"] = None


def _honey_log(line):
    with HONEY_APPLY_LOCK:
        HONEY_STATE["log"].append("[{}] {}".format(time.strftime("%H:%M:%S"), line))
        del HONEY_STATE["log"][:-60]


def _honey_is_self(ip):
    """True for the router's own current WAN addresses (self-originated)."""
    if not ip:
        return False
    with HONEY_APPLY_LOCK:
        return ip in (HONEY_STATE.get("wan_ip"), HONEY_STATE.get("wan_ip6"))


def _honey_wan_ip():
    """Resolve the current WAN IPv4 without sending a packet (UDP connect)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 53))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None
    if _honey_is_lan(ip):
        return None
    return ip


def _honey_wan6():
    """Resolve the WAN interface's global IPv6 (None if none/ULA-only)."""
    try:
        r = subprocess.run(
            ["ip", "-j", "-6", "addr", "show", _honey_wan_iface()],
            capture_output=True, text=True, timeout=5,
        )
        for iface in json.loads(r.stdout or "[]"):
            for a in iface.get("addr_info", []):
                if a.get("scope") != "global":
                    continue
                try:
                    addr = ipaddress.ip_address(a.get("local", ""))
                except ValueError:
                    continue
                if addr.version == 6 and addr.is_global and not addr.is_private:
                    return str(addr)
    except Exception:
        pass
    return None


def _honey_ban(ip):
    """Best-effort local CrowdSec ban for a trapped scanner (guarded, rc
    checked).

    Deliberately does NOT report to tuxwall.org: community reporting for
    honeypot catches happens at the catch site (_honey_catch), so a
    missing or failing CrowdSec binary never silently drops a consented
    deception-layer report.
    """
    ok, err = _deception_cscli_ban(ip, CUSTOM_BLOCKLIST_DURATION, HONEY_REASON)
    with HONEY_APPLY_LOCK:
        HONEY_STATE["stats"]["banned" if ok else "ban_failed"] += 1
    if ok:
        _honey_log("auto-banned {} (CrowdSec 1y)".format(ip))
    else:
        _honey_log("caught {} - NOT banned locally: {}".format(ip, err))
    return ok


def _honey_catch(ip, port, auto_ban):
    """Threshold reached for `ip` (once per IP): guard, then the optional
    local ban and the community report (unconditional: enabling the
    deception layer IS the opt-in to share trap catches; reporting.json
    "enabled" is the off switch)."""
    why = _deception_guard(ip)
    if why:
        with HONEY_APPLY_LOCK:
            HONEY_STATE["stats"]["guarded"] += 1
        _honey_log("guard: {} not banned/reported ({})".format(ip, why))
        return
    if auto_ban:
        _honey_ban(ip)
    svc = deception_service(port)
    res = _spawn_report(ip, "honeypot: %s probe on %d/tcp" % (svc, port), "honeypot",
                        deception_category("honeypot", port))
    if isinstance(res, dict) and res.get("ok"):
        with HONEY_APPLY_LOCK:
            HONEY_STATE["stats"]["reported"] += 1


def _honey_count_hit(ip, threshold, now=None):
    """Count one connection from ip. -> (hits, act): act is True exactly
    once per remembered source, on the first connection with
    hits >= threshold (>=, not ==: a connection dropped over capacity still
    counts, so the threshold can never be skipped)."""
    now = time.time() if now is None else now
    with HONEY_APPLY_LOCK:
        cur = HONEY_STATE["hits"].get(ip, now)
        e = dict(cur) if cur else {"hits": 0, "first": now, "actioned": False}
        e["hits"] = int(e.get("hits") or 0) + 1
        e["last"] = now
        act = (not e.get("actioned")) and e["hits"] >= max(1, int(threshold or 1))
        if act:
            e["actioned"] = True
        HONEY_STATE["hits"].set(ip, e, now)
        HONEY_STATE["stats"]["total"] += 1
        if cur is None:
            HONEY_STATE["stats"]["unique"] += 1
    return e["hits"], act


def _honey_unaction(ip):
    """The catch could not be started: let the next connection retry."""
    with HONEY_APPLY_LOCK:
        cur = HONEY_STATE["hits"].get(ip)
        if cur:
            HONEY_STATE["hits"].set(ip, dict(cur, actioned=False))


def _honey_admit(ip, port, now=None):
    """Reserve a tarpit slot BEFORE any thread exists. None when the total
    or the per-IP cap is reached (the caller closes the connection)."""
    with HONEY_APPLY_LOCK:
        st = HONEY_STATE
        if (len(st["active"]) >= HONEY_MAX_TOTAL
                or st["per_ip"].get(ip, 0) >= HONEY_MAX_PER_IP):
            st["stats"]["dropped"] += 1
            return None
        sid = next(HONEY_SLOT_IDS)
        st["active"][sid] = {"ip": ip, "port": port,
                             "connected_at": time.time() if now is None else now}
        st["per_ip"][ip] = st["per_ip"].get(ip, 0) + 1
        return sid


def _honey_release(sid):
    with HONEY_APPLY_LOCK:
        st = HONEY_STATE
        a = st["active"].pop(sid, None)
        if a is None:
            return None
        n = st["per_ip"].get(a["ip"], 0) - 1
        if n > 0:
            st["per_ip"][a["ip"]] = n
        else:
            st["per_ip"].pop(a["ip"], None)
        return a


def _honey_tarpit(conn, ip, port, sid=None, gen=None):
    """Hold one scanner connection open, dribbling one byte per tick."""
    start = time.time()
    sent = 0
    try:
        conn.settimeout(HONEY_TICK)
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, 1)
        except (AttributeError, OSError):
            pass
        while (not HONEY_STOP.is_set()
               and (gen is None or HONEY_STATE["gen"] == gen)
               and time.time() - start < HONEY_MAX_HOLD):
            try:
                if not conn.recv(1024):
                    break  # remote closed
            except socket.timeout:
                pass
            except OSError:
                break
            try:
                conn.send(b"\x00")
                sent += 1
            except OSError:
                break
    finally:
        try:
            conn.close()
        except OSError:
            pass
        duration = time.time() - start
        if sid is not None:
            _honey_release(sid)
        with HONEY_APPLY_LOCK:
            HONEY_STATE["stats"]["wasted"] += duration
            HONEY_STATE["traps"].append({
                "ip": ip, "port": port, "connected_at": start,
                "duration": duration, "sent": sent,
            })
            HONEY_STATE["traps"] = HONEY_STATE["traps"][-400:]


def _honey_bind(port, family, addr):
    """Bind one honeypot port synchronously. Returns the socket or None.

    Binding BEFORE opening the firewall rule guarantees a failed bind
    (port in use by a real service) can never expose that service to WAN.
    IPv6 sockets are V6ONLY (never "::"), so only the WAN address binds.
    """
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((addr, port))
        sock.listen(16)
        sock.settimeout(2)
        return sock
    except OSError as exc:
        with HONEY_APPLY_LOCK:
            HONEY_STATE["error"] = (
                "port {}/{} not bound ({}) - no firewall rule added"
                .format(port, "v6" if family == socket.AF_INET6 else "v4",
                        getattr(exc, "strerror", exc)))
        _honey_log(HONEY_STATE["error"])
        return None


_HONEY_CONF_CACHE = {"ts": 0.0, "conf": None}
HONEY_CONF_TTL = 5


def _honey_conf_cached():
    """honeypot.json, re-read at most every HONEY_CONF_TTL seconds (the
    accept loop used to read the file for every connection)."""
    now = time.time()
    c = _HONEY_CONF_CACHE
    if c["conf"] is None or now - c["ts"] >= HONEY_CONF_TTL:
        c.update(ts=now, conf=_honey_load_conf())
    return c["conf"]


def _honey_accept_error(port, exc):
    """accept() failed with the socket still open (EMFILE/ENFILE/ENOBUFS/
    ENOMEM/ECONNABORTED...): count it, log at most once a minute per port,
    and keep the trap alive - an error must never kill the listener."""
    with HONEY_APPLY_LOCK:
        HONEY_STATE["stats"]["accept_errors"] += 1
        now = time.time()
        if now - _HONEY_ACCEPT_ERR_LOGGED.get(port, 0) < 60:
            return
        _HONEY_ACCEPT_ERR_LOGGED[port] = now
    _honey_log("port {}: accept() failed ({}) - trap kept, retrying".format(
        port, errno.errorcode.get(getattr(exc, "errno", 0) or 0, exc)))


def _honey_close(conn):
    try:
        conn.close()
    except OSError:
        pass


def _honey_listener(sock, port):
    """Accept loop for one bound honeypot socket."""
    with HONEY_APPLY_LOCK:
        gen = HONEY_STATE["gen"]
    try:
        while not HONEY_STOP.is_set() and HONEY_STATE["gen"] == gen:
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if HONEY_STOP.is_set() or sock.fileno() == -1 or HONEY_STATE["gen"] != gen:
                    return
                _honey_accept_error(port, exc)
                time.sleep(HONEY_ACCEPT_BACKOFF)
                continue
            ip = addr[0]
            if _honey_is_lan(ip) or _honey_is_self(ip):
                with HONEY_APPLY_LOCK:
                    HONEY_STATE["stats"]["lan_guard"] += 1
                _honey_close(conn)
                continue
            conf = _honey_conf_cached()
            _, act = _honey_count_hit(ip, conf.get("ban_threshold") or 1)
            if act:
                try:
                    threading.Thread(target=_honey_catch,
                                     args=(ip, port, bool(conf.get("auto_ban"))),
                                     name="honey-catch", daemon=True).start()
                except RuntimeError:
                    _honey_unaction(ip)
                    with HONEY_APPLY_LOCK:
                        HONEY_STATE["stats"]["thread_errors"] += 1
            sid = _honey_admit(ip, port)
            if sid is None:
                # over capacity: drop instead of trap so threads/fds stay bounded
                _honey_close(conn)
                continue
            try:
                threading.Thread(target=_honey_tarpit, args=(conn, ip, port, sid, gen),
                                 name="honey-tarpit", daemon=True).start()
            except RuntimeError:
                _honey_release(sid)
                _honey_close(conn)
                with HONEY_APPLY_LOCK:
                    HONEY_STATE["stats"]["thread_errors"] += 1
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _honey_watchdog():
    """Keep firewall rules no wider than the live trap sockets.

    Every 60s: any port whose trap socket has died immediately loses its
    UFW allow rule, so a service that later grabs that port can never
    inherit WAN exposure from a dead tarpit. Exits when the honeypot is
    no longer listening.
    """
    while True:
        time.sleep(60)
        with HONEY_APPLY_LOCK:
            if not HONEY_STATE["listening"]:
                return
            socks = dict(HONEY_STATE.get("sockets") or {})
        dead = [p for p, s in socks.items() if s.fileno() == -1]
        for port in dead:
            _honey_ufw_deny(port)
            with HONEY_APPLY_LOCK:
                HONEY_STATE["sockets"].pop(port, None)
                if port in HONEY_STATE["ports"]:
                    HONEY_STATE["ports"].remove(port)
            _honey_log("watchdog: trap on port {} died - firewall rule removed".format(port))
        if dead:
            with HONEY_APPLY_LOCK:
                if not HONEY_STATE["sockets"] and HONEY_STATE["listening"]:
                    HONEY_STATE["listening"] = False
                    HONEY_STATE["error"] = "all traps died - firewall rules removed"
                    _honey_log("all traps dead - honeypot stopped")

        # Rebind on WAN address changes. Dynamic WAN addresses (Xfinity
        # IPv4 and IPv6) can appear seconds after boot — a boot-time bind
        # then misses the v6 trap entirely — and can change mid-run, which
        # leaves traps bound to an address that no longer receives. Watch
        # both families and re-apply whenever the live address differs.
        with HONEY_APPLY_LOCK:
            cur4 = HONEY_STATE.get("wan_ip")
            cur6 = HONEY_STATE.get("wan_ip6")
            listening = HONEY_STATE["listening"]
        if listening:
            new4 = _honey_wan_ip()
            new6 = _honey_wan6()
            if (new4 and new4 != cur4) or (new6 and new6 != cur6):
                _honey_log(
                    "watchdog: WAN address change ({} -> {} | {} -> {}) - "
                    "rebinding traps".format(cur4, new4, cur6, new6))
                try:
                    apply_honeypot(_honey_load_conf(), touch_ufw=True)
                except Exception as exc:
                    HONEY_STATE["error"] = "rebind failed: %r" % (exc,)
                    _honey_log(HONEY_STATE["error"])

def _honey_rule_present(port):
    """True if a WAN allow for this port exists already (tagged or not).
    Existing untagged rules are left as they are: ufw would otherwise
    rewrite them just to add the comment."""
    if _fw_guard is None:
        return False
    try:
        rs = _fw_guard.load_ruleset(_fw_ctx(raw=False))
        return _fw_guard._has_allow(rs["v4"], _honey_wan_iface(), "tcp", int(port))
    except Exception:
        return False


def _honey_ufw_allow(port):
    if _honey_rule_present(port):
        return True
    try:
        # tagged so the firewall guard can tell honeypot rules apart
        _ufw(["allow", "in", "on", _honey_wan_iface(),
              "to", "any", "port", str(port), "proto", "tcp",
              "comment", _fw_guard.HONEYPOT_TAG if _fw_guard else "tuxwall-honeypot"])
    except Exception as exc:
        _honey_log("ufw allow port {}: {}".format(port, exc))
        return False
    return True


def _honey_ufw_deny(port):
    try:
        _ufw(["delete", "allow", "in", "on", _honey_wan_iface(),
              "to", "any", "port", str(port), "proto", "tcp"])
    except Exception:
        pass  # rule not present - fine


def _honey_stop_listeners():
    with HONEY_APPLY_LOCK:
        HONEY_STATE["gen"] += 1     # listeners + tarpits of this generation exit
    HONEY_STOP.set()
    for t in HONEY_STATE["threads"]:
        t.join(timeout=3)
    HONEY_STATE["threads"] = []
    HONEY_STOP.clear()
    with HONEY_APPLY_LOCK:
        HONEY_STATE["listening"] = False
        HONEY_STATE["ports"] = []
        HONEY_STATE["sockets"] = {}
        # live tarpit slots stay counted until their threads close them
        # (within one HONEY_TICK): resetting the map here let a WAN rebind
        # double the real number of held fds


def apply_honeypot(conf, touch_ufw=False):
    """(Re)start or stop the honeypot listeners per conf.

    touch_ufw=True adds/removes the WAN allow rules (used by the API
    endpoint; skipped at boot since UFW rules persist).
    """
    with HONEY_APPLY_LOCK:
        if HONEY_STATE["threads"]:
            busy = True
        else:
            busy = False
    if busy:
        _honey_stop_listeners()
    if not conf.get("enabled"):
        if touch_ufw:
            for p in _honey_valid_ports(conf.get("ports")):
                _honey_ufw_deny(p)
        _honey_log("honeypot disabled")
        return {"ok": True, "enabled": False}
    wan_ip = _honey_wan_ip()
    if not wan_ip:
        HONEY_STATE["error"] = "could not resolve a non-LAN WAN IPv4 address"
        _honey_log(HONEY_STATE["error"])
        return {"ok": False, "error": HONEY_STATE["error"]}
    ports = _honey_valid_ports(conf.get("ports"))
    if not ports:
        return {"ok": False, "error": "no valid ports configured"}
    wan_ip6 = _honey_wan6()
    # bind every port FIRST (both families); only bound ports get the
    # firewall allow rule (one UFW rule covers v4 and v6)
    bound = {}
    for p in ports:
        sock = _honey_bind(p, socket.AF_INET, wan_ip)
        if sock is not None:
            bound["v4:%d" % p] = sock
        if wan_ip6:
            sock6 = _honey_bind(p, socket.AF_INET6, wan_ip6)
            if sock6 is not None:
                bound["v6:%d" % p] = sock6
    if not bound:
        return {"ok": False, "error": "no ports could be bound on {}"
                .format(wan_ip)}
    bound_ports = sorted({int(k.split(":")[1]) for k in bound})
    if touch_ufw:
        for p in bound_ports:
            _honey_ufw_allow(p)
    for key, sock in bound.items():
        t = threading.Thread(
            target=_honey_listener, args=(sock, int(key.split(":")[1])),
            daemon=True)
        t.start()
        with HONEY_APPLY_LOCK:
            HONEY_STATE["threads"].append(t)
    with HONEY_APPLY_LOCK:
        HONEY_STATE["sockets"] = dict(bound)
        HONEY_STATE["listening"] = True
        HONEY_STATE["wan_ip"] = wan_ip
        HONEY_STATE["wan_ip6"] = wan_ip6
        HONEY_STATE["ports"] = bound_ports
        HONEY_STATE["started_at"] = time.time()
        if HONEY_STATE["error"] and HONEY_STATE["error"].startswith("port "):
            HONEY_STATE["error"] = None  # bind errors from this cycle are stale
    wd = HONEY_STATE.get("watchdog")
    if not wd or not wd.is_alive():
        wd = threading.Thread(target=_honey_watchdog, daemon=True)
        wd.start()
        with HONEY_APPLY_LOCK:
            HONEY_STATE["watchdog"] = wd
    _honey_log("honeypot active on {}{} ports {}{}".format(
        wan_ip, " / " + wan_ip6 if wan_ip6 else "", bound_ports,
        "" if len(bound_ports) == len(ports)
        else " (skipped {})".format(sorted(set(ports) - set(bound_ports)))))
    return {"ok": True, "enabled": True, "wan_ip": wan_ip, "wan_ip6": wan_ip6,
            "ports": bound_ports}


def start_honeypot_at_boot():
    conf = _honey_load_conf()
    if conf.get("enabled"):
        try:
            apply_honeypot(conf, touch_ufw=False)
        except Exception as exc:
            _honey_log("boot start failed: {}".format(exc))


def build_honeypot():
    with HONEY_APPLY_LOCK:
        active = sorted(
            HONEY_STATE["active"].values(),
            key=lambda a: a["connected_at"], reverse=True,
        )[:50]
        traps = list(reversed(HONEY_STATE["traps"][-30:]))
        hit_items = HONEY_STATE["hits"].items()     # sources seen in the last 24 h
        top = sorted(
            ((ip, int(e.get("hits") or 0)) for ip, e in hit_items),
            key=lambda kv: -kv[1])[:15]
        state = {
            "listening": HONEY_STATE["listening"],
            "wan_ip": HONEY_STATE["wan_ip"],
            "wan_ip6": HONEY_STATE["wan_ip6"],
            "ports": HONEY_STATE["ports"],
            "started_at": HONEY_STATE["started_at"],
            "error": HONEY_STATE["error"],
            "stats": dict(HONEY_STATE["stats"]),
            "active_count": len(HONEY_STATE["active"]),
            "limits": {"total": HONEY_MAX_TOTAL, "per_ip": HONEY_MAX_PER_IP,
                       "hold": HONEY_MAX_HOLD},
            "active": active,
            "traps": traps,
            "top": [{"ip": ip, "hits": n} for ip, n in top],
            "sources_24h": len(hit_items),
            "log": list(HONEY_STATE["log"][-20:]),
        }
        lan_nets = _HONEY_LAN["nets"]
    # LAN guard: the networks treated as ours (cached; refreshed on the
    # tarpit's own schedule) and what the guards held back since start
    state["lan_guard"] = {
        "nets": [str(n) for n in (lan_nets or [])
                 if not n.is_loopback][:24],
        "closed": int(state["stats"].get("lan_guard") or 0),
        "guarded": int(state["stats"].get("guarded") or 0),
        "dropped": int(state["stats"].get("dropped") or 0),
    }
    return {
        "ok": True,
        "conf": _honey_load_conf(),
        "state": state,
        "hint": ("Listening sockets bind the WAN address only; LAN/WG "
                 "sources are closed immediately and never counted."),
    }


def set_honeypot_conf(body):
    conf = _honey_load_conf()
    if "enabled" in body and bool(body.get("enabled")) != bool(conf.get("enabled")):
        _fw_autosnap("honeypot %s" % ("on" if body.get("enabled") else "off"), None)
    if "enabled" in body:
        conf["enabled"] = bool(body.get("enabled"))
    if body.get("ports") is not None:
        ports = _honey_valid_ports(body.get("ports"))
        if not ports:
            return {"ok": False, "error": "No valid ports (1-65535, max 16)"}
        if _fw_guard is not None:
            # firewall guard: a decoy port must never expose a real service,
            # a management port, the canary or a port forward on the WAN
            try:
                probs = _fw_honeypot_port_problems(_fw_ctx(raw=False),
                                                   [p for p in ports if p not in conf["ports"]])
            except Exception as exc:
                print("[fw] honeypot guard error: %r" % exc, flush=True)
                probs = []
            if probs:
                return {"ok": False, "error": "Refused by the firewall guard: " + "; ".join(probs)}
            _fw_autosnap("honeypot ports", None)
        old_ports = conf["ports"]
        conf["ports"] = ports
    else:
        old_ports = conf["ports"]
    if "auto_ban" in body:
        conf["auto_ban"] = bool(body.get("auto_ban"))
    if body.get("ban_threshold") is not None:
        try:
            conf["ban_threshold"] = max(1, min(10, int(body.get("ban_threshold"))))
        except (TypeError, ValueError):
            return {"ok": False, "error": "Invalid ban threshold"}
    _honey_save_conf(conf)
    # remove ufw rules for ports we dropped
    for p in old_ports:
        if p not in conf["ports"] or not conf["enabled"]:
            _honey_ufw_deny(p)
    result = apply_honeypot(conf, touch_ufw=True)
    if not result.get("ok"):
        # roll back to disabled so we never leave half-bound state
        conf["enabled"] = False
        _honey_save_conf(conf)
        apply_honeypot(conf, touch_ufw=True)
        return {"ok": False, "error": result.get("error")}
    return {"ok": True, "conf": conf, "message": (
        "Honeypot enabled on {}".format(result.get("ports")) if conf["enabled"]
        else "Honeypot disabled")}


def build_zeek():
    """Recent Zeek notices plus per-LAN-device outbound activity, read live
    from /opt/zeek/logs/current. Refreshed by the Security tab poll."""
    if not os.path.exists(ZEEK_NOTICE_LOG) and not os.path.exists(ZEEK_CONN_LOG):
        return {
            "ok": True, "enabled": False, "count_24h": 0, "notices": [],
            "devices": [],
            "hint": ("Zeek is not installed or not writing logs to "
                     "/opt/zeek/logs/current. Install Zeek (zeek.org), load "
                     "the JSON log scripts, and 'zeekctl deploy' on the LAN "
                     "interface to populate this panel."),
        }
    now = time.time()

    # --- Notices (24h) ---
    notices = []
    for raw in _zeek_tail_lines(ZEEK_NOTICE_LOG) or []:
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(ev, dict) or not ev.get("note"):
            continue
        try:
            ts = float(ev.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        if not ts or now - ts > ZEEK_WINDOW:
            continue
        src, sport = _zeek_endpoint(ev, "src", "id.orig_h")
        dst, dport = _zeek_endpoint(ev, "dst", "id.resp_h")
        notices.append({
            "ts": ts,
            "note": str(ev.get("note"))[:60],
            "msg": str(ev.get("msg") or "")[:160],
            "src": src, "sport": sport or "",
            "dst": dst, "dport": dport or "",
        })
    notices.sort(key=lambda n: n["ts"], reverse=True)

    # --- Per-device outbound profile (1h window) ---
    # A device talking to many unknown external hosts, or regularly beeping
    # at the same one, is the classic malware check-in pattern.
    devices = {}
    for raw in _zeek_tail_lines(ZEEK_CONN_LOG) or []:
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        try:
            ts = float(ev.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        if not ts or now - ts > ZEEK_DEVICE_WINDOW:
            continue
        orig = str(ev.get("id.orig_h") or "")
        resp = str(ev.get("id.resp_h") or "")
        if _zeek_is_lan(orig):
            dev, peer = orig, resp
        elif _zeek_is_lan(resp):
            dev, peer = resp, orig
        else:
            continue
        if not dev or not peer or _zeek_is_lan(peer):
            continue
        d = devices.setdefault(dev, {"device": dev, "conns": 0, "peers": {},
                                     "last_ts": ts})
        d["conns"] += 1
        d["peers"][peer] = d["peers"].get(peer, 0) + 1
        if ts > d["last_ts"]:
            d["last_ts"] = ts
    device_list = []
    for d in devices.values():
        top_peer, top_hits = max(d["peers"].items(), key=lambda kv: kv[1])
        device_list.append({
            "device": d["device"],
            "conns": d["conns"],
            "peer_count": len(d["peers"]),
            "top_peer": top_peer,
            "top_peer_hits": top_hits,
            "last_ts": d["last_ts"],
        })
    device_list.sort(key=lambda v: (-v["conns"], v["device"]))
    device_list = device_list[:50]

    return {
        "ok": True,
        "enabled": True,
        "count_24h": len(notices),
        "notices": notices[:100],
        "devices": device_list,
    }


# --- Zeek QUIC connections ----------------------------------------------------
# Every UDP/TLS (QUIC) flow from a LAN device to an external peer, read live
# from quic.log. Ordinary HTTP/3 carries a real SNI on port 443; an
# anonymous QUIC tunnel (proxy/VPN tooling) shows odd ports and no SNI.

ZEEK_QUIC_LOG = os.path.join(ZEEK_LOG_DIR, "quic.log")
ZEEK_QUIC_WINDOW = 3600


def build_zeek_quic():
    """Recent QUIC flows per LAN device (last hour), read from quic.log."""
    if not os.path.exists(ZEEK_QUIC_LOG):
        return {
            "ok": True, "enabled": False, "count_1h": 0, "flows": [],
            "hint": ("Zeek is not writing quic.log — no QUIC traffic seen yet "
                     "or the QUIC analyzer is disabled."),
        }
    now = time.time()
    flows = []
    for raw in _zeek_tail_lines(ZEEK_QUIC_LOG) or []:
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        try:
            ts = float(ev.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        if not ts or now - ts > ZEEK_QUIC_WINDOW:
            continue
        orig = str(ev.get("id.orig_h") or "")
        resp = str(ev.get("id.resp_h") or "")
        if _zeek_is_lan(orig):
            dev, peer = orig, resp
        elif _zeek_is_lan(resp):
            dev, peer = resp, orig
        else:
            continue
        if not peer or _zeek_is_lan(peer):
            continue
        flows.append({
            "ts": ts,
            "device": dev,
            "peer": peer,
            "port": ev.get("id.resp_p") or "",
            "version": str(ev.get("version") or "")[:40],
            "sni": str(ev.get("server_name") or ""),
        })
    flows.sort(key=lambda f: f["ts"], reverse=True)
    return {
        "ok": True,
        "enabled": True,
        "count_1h": len(flows),
        "flows": flows[:100],
    }


# --- Suricata evidence for ban reports -------------------------------------
# When a ban is reported to tuxwall.org, enrich the report with what Suricata
# actually saw from that IP so the community report card carries a real abuse
# type (bruteforce, scan, ssh, ...) instead of the generic "how it was banned
# locally" category. Informational/noisy signatures are ignored: they say
# nothing about the IP's intent and would mislabel benign traffic.

# Signature/category fragments that carry no abuse signal.
_SURICATA_NOISE = (
    "et info", "et policy", "suricata ethertype", "excessive header repetition",
    "misc activity", "generic protocol command decode", "unknown protocol",
    "applayer", "detect protocol", "tcp window", "reassembly",
    "microsoft connection test", "github cdn", "dns over https",
)

# Ordered rules: first keyword hit wins for a given alert. Specific abuse
# categories come first; "scan" precedes "ssh" so "ET SCAN Potential SSH
# Scan" is a scan, not an ssh attack, while "SSH Bruteforce" is caught by
# the earlier bruteforce rule.
_SURICATA_CAT_RULES = (
    ("malware", ("malware", "botnet", "trojan", "c&c", "cnc", "backdoor",
                 "ransomware", "mirai")),
    ("dos", ("ddos", "dos", "flood")),
    ("bruteforce", ("brute", "dictionary", "credential", "hydra",
                    "password guess", "multiple failed login", "bad-auth")),
    ("rdp", ("rdp", "vnc", "remote desktop")),
    ("scan", ("scan", "probe", "sweep", "nmap")),
    ("ssh", ("ssh",)),
    ("web", ("sql injection", "xss", "lfi", "rfi", "command injection",
             "web attack", "web-server", "web_server", "file upload",
             "cve-", "exploit", "shellcode")),
    ("spam", ("spam", "smtp", "phishing")),
)


def _suricata_alert_category(sig, cat):
    text = ("%s %s" % (sig, cat)).lower()
    for frag in _SURICATA_NOISE:
        if frag in text:
            return ""
    for cat_name, keys in _SURICATA_CAT_RULES:
        for k in keys:
            if k in text:
                return cat_name
    return ""


def suricata_evidence_for_ip(ip, window=SURICATA_WINDOW):
    """Best abuse category and top signature Suricata saw from this IP.

    Returns (category, signature). ("", "") when Suricata has no meaningful
    (non-informational) alert for the IP in the window — the caller then
    keeps the category it chose itself.
    """
    alerts = suricata_alerts_for_ip(ip, window)
    if not alerts:
        return ("", "")
    return (alerts[0]["category"], alerts[0]["sig"])


def suricata_alerts_for_ip(ip, window=SURICATA_WINDOW):
    """Meaningful Suricata alerts from this IP, aggregated by signature.

    Returns a list of {"sig", "sid", "count", "category", "ts"} sorted by
    alert count (ties: most recent), capped at 5 — the payload sent to
    tuxwall.org stays small and the report card shows the loudest
    signatures. Informational/noisy signatures are skipped just as in
    suricata_evidence_for_ip().
    """
    lines = _suricata_tail_lines()
    if not lines:
        return []
    now = time.time()
    agg = {}
    for raw in lines:
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(ev, dict) or ev.get("event_type") != "alert":
            continue
        if (ev.get("src_ip") or "") != ip:
            continue
        alert = ev.get("alert") or {}
        sig = (alert.get("signature") or "").strip()
        if not sig:
            continue
        ts = _parse_iso(ev.get("timestamp")) or now
        if now - ts > window:
            continue
        cat = _suricata_alert_category(sig, alert.get("category") or "")
        if not cat:
            continue
        key = (sig, alert.get("signature_id"))
        entry = agg.setdefault(key, {
            "sig": sig[:120], "sid": alert.get("signature_id"),
            "count": 0, "category": cat, "ts": 0.0,
        })
        entry["count"] += 1
        if ts > entry["ts"]:
            entry["ts"] = ts
    return sorted(agg.values(),
                  key=lambda e: (-e["count"], -e["ts"]))[:5]


# --- UFW evidence for ban reports -------------------------------------------
# Suricata only sees what a signature describes — a well-formed SYN to a closed
# port matches nothing, which is most of what a home firewall actually gets.
# The UFW drop log is the record that sees those attackers, so when there is no
# Suricata evidence the ban report falls back to it: the drop pattern is
# summarised into the reason ("port scan: 14 ports probed", "telnet probe: 26
# packets to port 23") and the category maps off that text.

UFW_EVIDENCE_WINDOW = 7 * 86400
_UFW_SRC_RE = re.compile(r"SRC=(\S+)")
_UFW_DPT_RE = re.compile(r"DPT=(\d+)")
_UFW_TS_RE = re.compile(r"^(\S+)")

# Well-known ports worth naming in the evidence phrase.
_UFW_PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
}


def ufw_evidence_for_ip(ip, window=UFW_EVIDENCE_WINDOW):
    """This IP's firewall-drop record from the live UFW log.

    Returns None when the log is unreadable, else a dict with the packet
    count, per-port counts (sorted busiest first) and first/last drop
    timestamps. Reads the current log file only — rotated files fall
    outside the evidence window anyway.
    """
    ports = {}
    total = 0
    first = None
    last = None
    cutoff = time.time() - window
    try:
        with open(UFW_LOG, "r", errors="replace") as f:
            for line in f:
                if ("SRC=%s " % ip) not in line:
                    continue
                m = _UFW_TS_RE.match(line)
                if m:
                    ts = _parse_iso(m.group(1))
                    if ts and ts >= cutoff:
                        if first is None or ts < first:
                            first = ts
                        if last is None or ts > last:
                            last = ts
                total += 1
                d = _UFW_DPT_RE.search(line)
                if d:
                    p = int(d.group(1))
                    ports[p] = ports.get(p, 0) + 1
    except OSError:
        return None
    if not total:
        return None
    return {
        "packets": total,
        "ports": sorted(ports.items(), key=lambda kv: (-kv[1], kv[0])),
        "first": first,
        "last": last,
    }


def ufw_evidence_phrase(ev):
    """Human phrase for the drop pattern: scan, service probe, or nothing."""
    if not ev:
        return ""
    ports = ev["ports"]
    if len(ports) >= 3:
        top = ", ".join(str(p) for p, _ in ports[:4])
        return "port scan: %d ports probed (top: %s)" % (len(ports), top)
    if len(ports) == 1:
        p, n = ports[0]
        name = _UFW_PORT_NAMES.get(p)
        what = "%s probe" % name if name else "probe"
        return "%s: %d packets to port %d" % (what, n, p)
    if len(ports) == 2:
        (p1, n1), (p2, n2) = ports
        return "probe: %d + %d packets to ports %d, %d" % (n1, n2, p1, p2)
    return "%d packets dropped (no TCP/UDP ports)" % ev["packets"]


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
    bullets, top, heading, seen_bullet, dropped = [], [], [], False, 0
    for l in lines:
        if re.search(r"\|\s*(HIGH|MEDIUM|LOW)\s*\|", l, re.I):
            seen_bullet = True
            if len(bullets) < 5:
                if not re.match(r"^[-*\u2022]", l):
                    l = "- " + l
                bullets.append(l)
            else:
                dropped += 1
        elif re.match(r"^top action:", l, re.I):
            top.append(l)
        elif not seen_bullet:
            heading.append(l)
    if dropped:
        bullets.append(f"- ({dropped} further finding(s) omitted \u2014 see map and top attackers)")
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
                lines.append(f"  [{r.get('number')}] {r.get('action','?')} {r.get('to','?')} from {r.get('from','any')}")
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
            totals = dns.get("totals") or {}
            lines.append(f"Queries: {totals.get('queries',0)}  NXDOMAIN(blocked): {totals.get('nxdomain',0)}  "
                         f"hit-rate: {totals.get('hitrate',0):.1%}  uptime: {dns.get('uptime',0)}s")
            qtypes = dns.get("qtypes") or []
            if qtypes:
                lines.append("Top qtypes: " + ", ".join(f"{q.get('label')}:{q.get('count')}" for q in qtypes[:5]))
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
            load = st.get("load") or [0, 0, 0]
            svc_states = st.get("services") or {}
            down = sorted(k for k, v in svc_states.items() if not v)
            lines = ["=== SYSTEM ===",
                     f"Hostname: {st.get('hostname','')}",
                     f"Time: {st.get('time','')}",
                     f"Load: {' / '.join(f'{x:.2f}' for x in load[:3])}",
                     "Services down: " + (", ".join(down) if down else "none")]
            sections.append("\n".join(lines))
    except Exception as e:
        sections.append(f"=== SYSTEM ===\nUnavailable: {e}")

    # Local DNS domains (managed overrides + discovered unbound records)
    try:
        doms = build_domains()
        all_doms = doms.get("domains") or []
        managed = [d for d in all_doms if d.get("managed")]
        discovered = [d for d in all_doms if not d.get("managed")]
        sections.append(f"=== DNS DOMAINS ===\nManaged: {len(managed)}  Discovered: {len(discovered)}")
        if managed[:10]:
            sections[-1] += "\nManaged: " + ", ".join(d.get("domain","") for d in managed[:10])
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
WG_DEFAULT_DNS = ""  # derived: the router's own primary LAN address


def _wg_default_dns():
    global WG_DEFAULT_DNS
    if WG_DEFAULT_DNS:
        return WG_DEFAULT_DNS
    conf = _net_conf()
    if conf.get("lan_address"):
        WG_DEFAULT_DNS = str(conf["lan_address"])
        return WG_DEFAULT_DNS
    addr = _topo("lan_address")
    if addr:
        try:
            WG_DEFAULT_DNS = str(ipaddress.ip_interface(addr).ip)
            return WG_DEFAULT_DNS
        except ValueError:
            pass
    # dynamic: first private v4 on the first non-WAN interface
    wan = _detect_wan_iface()
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[1] in ("lo", wan):
                continue
            ip = parts[3].split("/")[0]
            if ipaddress.ip_address(ip).is_private:
                WG_DEFAULT_DNS = ip
                return ip
    except Exception:
        pass
    return "192.168.1.1"  # last resort
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
    """The WAN interface: interfaces.json, else the default route's device."""
    topo = _topo("wan_device")
    if topo:
        return topo
    try:
        route = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        m = re.search(r"dev\s+(\S+)", route)
        return m.group(1) if m else ""
    except Exception:
        return ""


_WG_RAW_FWD_RE = re.compile(
    r"ip6?tables -C FORWARD -[io] %i -j ACCEPT 2>/dev/null \|\| "
    r"ip6?tables -A FORWARD -[io] %i -j ACCEPT; ")


_WG_RAW_DNS_RE = re.compile(
    r"ip6?tables -C INPUT -i %i -s \S+ -p (?:udp|tcp) --dport 53 -j ACCEPT 2>/dev/null \|\| "
    r"ip6?tables -A INPUT -i %i -s \S+ -p (?:udp|tcp) --dport 53 -j ACCEPT; ?")


def _wg_raw_forward_disabled():
    """True once an applied policy matrix took over WireGuard forwarding
    (interfaces.json policy.wg_raw_forward == false)."""
    if _topology is None or not _topology.has_file():
        return False
    try:
        pol = _topology.load().get("policy")
        return isinstance(pol, dict) and pol.get("wg_raw_forward") is False
    except Exception:
        return False


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
        if _wg_raw_forward_disabled():
            # the interface policy matrix replaced these with tagged ufw rules;
            # the DNS INPUT accepts only repeat the ufw allows added below
            adds = [a for a in adds if a[1:3] not in (["-A", "FORWARD"], ["-A", "INPUT"])]
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
        if _wg_raw_forward_disabled():
            # ufw route rules / the policy matrix own WireGuard forwarding:
            # raw FORWARD -i/-o wg0 ACCEPTs would bypass them. PostDown keeps
            # its (harmless) deletes so older rules are cleaned up on wg down.
            lines[-2] = _WG_RAW_DNS_RE.sub("", _WG_RAW_FWD_RE.sub("", lines[-2]))
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


WG_UFW_TAG = "tuxwall-wireguard"     # the listen port on the WAN (fw_guard owner "wireguard")
WG_SSH_UFW_TAG = "tuxwall-vpn-ssh"   # SSH from VPN clients (an ordinary, editable rule)


def _sshd_ports():
    """Ports sshd listens on (`sshd -T`); [22] when it cannot tell, [] without sshd."""
    try:
        out = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=10).stdout
    except FileNotFoundError:
        return []
    except Exception:
        out = ""
    ports = sorted({int(m) for m in re.findall(r"(?m)^port (\d+)$", out or "") if 0 < int(m) < 65536})
    return ports or [22]


def wg_ufw_open_rules(listen_port, wan, client_subnet, ssh_ports=()):
    """ufw argv lists for a new WireGuard server: the listen port on the WAN
    only (never on every interface), DNS + SSH from the VPN subnets."""
    if wan:
        rules = [["allow", "in", "on", wan, "to", "any", "port", str(listen_port), "proto", "udp",
                  "comment", WG_UFW_TAG]]
    else:  # no WAN known: reachable at all beats a VPN nobody can reach
        rules = [["allow", "{}/udp".format(listen_port), "comment", WG_UFW_TAG]]
    for net in (client_subnet, WG_V6_SUBNET):
        for proto in ("udp", "tcp"):
            rules.append(["allow", "in on {} from {} to any port 53 proto {}".format(WG_IFACE, net, proto)])
    for port in ssh_ports:
        for net in (client_subnet, WG_V6_SUBNET):
            rules.append(["allow", "in", "on", WG_IFACE, "from", net, "to", "any", "port", str(port),
                          "proto", "tcp", "comment", WG_SSH_UFW_TAG])
    return rules


def setup_wireguard(body):
    if os.path.exists(WG_CONF):
        return {"ok": True, "already": True}
    address = (body.get("address") or WG_DEFAULT_ADDRESS).strip()
    # 2026-11-03 audit: this value is written into wg0.conf, which wg-quick
    # executes (PostUp/PostDown run through a root shell) - a newline or
    # metacharacter here is directive injection. Anchor to IP/CIDR syntax.
    try:
        for part in address.split(","):
            ipaddress.ip_network(part.strip(), strict=False)
    except ValueError:
        raise RuntimeError("Invalid WireGuard address (IP or CIDR only)")
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
    for rule in wg_ufw_open_rules(listen_port, get_wan_interface(), client_subnet, _sshd_ports()):
        _ufw(rule)
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


# --- RPZ (response policy zones) -------------------------------------------
RPZ_ENTRIES_FILE = os.path.join(BLOCKLIST_DIR, "rpz.json")
RPZ_ZONEFILE = "/var/lib/unbound/rpz-block.rpz"
RPZ_BACKUP = RPZ_ZONEFILE + ".bak"
RPZ_INCLUDE = "/etc/unbound/unbound.conf.d/98-rpz.conf"
RPZ_ZONE_NAME = "rpz.local"
RPZ_ACTIONS = ("block", "drop", "redirect", "passthru")
RPZ_MATCHES = ("domain", "ip")

RPZ_INCLUDE_BODY = (
    "# Managed by the tuxwall Blocklists page (RPZ) - DO NOT EDIT\n"
    "server:\n"
    "    # respip module required for RPZ (default is \"validator iterator\")\n"
    "    module-config: \"respip validator iterator\"\n"
    "\n"
    "rpz:\n"
    "    name: \"" + RPZ_ZONE_NAME + "\"\n"
    "    zonefile: \"" + RPZ_ZONEFILE + "\"\n"
    "    # zonefile mtime is checked and reloaded automatically, no restart needed\n"
    "    # log which RPZ trigger fired (visible in journal / unbound-control)\n"
    "    rpz-log: yes\n"
    "    rpz-log-name: \"" + RPZ_ZONE_NAME + "\"\n"
)


def load_rpz_entries():
    try:
        with open(RPZ_ENTRIES_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return [
                    e for e in data
                    if isinstance(e, dict) and e.get("domain")
                    and e.get("action") in RPZ_ACTIONS
                ]
    except (OSError, ValueError):
        pass
    return []


def save_rpz_entries(entries):
    os.makedirs(os.path.dirname(RPZ_ENTRIES_FILE), exist_ok=True)
    tmp = RPZ_ENTRIES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(entries, f, indent=2)
    os.replace(tmp, RPZ_ENTRIES_FILE)


def valid_rpz_domain(token):
    dom = normalize_domain(token)
    if not dom or _looks_like_ip(dom) or not DOMAIN_RE.match(dom):
        return None
    return dom


def valid_rpz_cidr(token):
    """Normalize a CIDR (or bare IP) for answer-IP policies; None if invalid."""
    token = (token or "").strip()
    if not token or not IPV4_RE.match(token.split("/")[0]):
        return None
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    return str(net)


def valid_rpz_value(token):
    """Accept a domain or CIDR; returns (value, mode) or (None, None)."""
    if "/" in token or _looks_like_ip((token or "").strip()):
        cidr = valid_rpz_cidr(token)
        return (cidr, "ip") if cidr else (None, None)
    dom = valid_rpz_domain(token)
    return (dom, "domain") if dom else (None, None)


def _rpz_ip_owner(cidr):
    """Encode a CIDR as an RPZ response-IP owner label.

    Format (per RPZ spec): prefixlen.<network octets, reversed, truncated
    to the octets that carry network bits>.rpz-ip
    e.g. 192.0.2.0/24 -> 24.2.0.192.rpz-ip
    """
    net = ipaddress.ip_network(cidr)
    used = net.network_address.packed[: (net.prefixlen + 7) // 8]
    rev = ".".join(str(b) for b in used[::-1])
    return "{}.{}.rpz-ip".format(net.prefixlen, rev)


def _rpz_rdata(entry):
    action = entry.get("action")
    if action == "block":
        return "."
    if action == "drop":
        return "rpz-drop."
    if action == "passthru":
        return "rpz-passthru."
    if action == "redirect":
        target = (entry.get("target") or "").strip()
        if not IPV4_RE.match(target):
            raise ValueError("redirect requires a valid IPv4 target")
        return target + "."
    raise ValueError("invalid action (expected block/drop/redirect/passthru)")


def write_rpz_zone(entries):
    serial = time.strftime("%Y%m%d%H")
    lines = [
        "$TTL 300",
        "@ IN SOA {}. hostmaster.housenetwork.site. (".format(RPZ_ZONE_NAME),
        "        {} ; serial".format(serial),
        "        3600       ; refresh",
        "        600        ; retry",
        "        86400      ; expire",
        "        30 )       ; minimum",
        "@ IN NS localhost.",
        "",
        "; Generated by the tuxwall Blocklists page (RPZ) - DO NOT EDIT",
        "; owner names encode the target domain as <domain>.{}".format(RPZ_ZONE_NAME),
    ]
    for e in sorted(entries, key=lambda x: x["domain"]):
        rdata = _rpz_rdata(e)
        if e.get("match", "domain") == "ip":
            lines.append("{}.{}. CNAME {}".format(
                _rpz_ip_owner(e["domain"]), RPZ_ZONE_NAME, rdata))
            continue
        dom = e["domain"]
        lines.append("{}.{}. CNAME {}".format(dom, RPZ_ZONE_NAME, rdata))
        lines.append("*.{0}.{1}. CNAME {2}".format(dom, RPZ_ZONE_NAME, rdata))
    os.makedirs(os.path.dirname(RPZ_ZONEFILE), exist_ok=True)
    tmp = RPZ_ZONEFILE + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, RPZ_ZONEFILE)


def ensure_rpz_include():
    """Install the 98-rpz.conf include (server + rpz stanzas) if missing."""
    if os.path.exists(RPZ_INCLUDE):
        return False
    os.makedirs(os.path.dirname(RPZ_INCLUDE), exist_ok=True)
    tmp = RPZ_INCLUDE + ".tmp"
    with open(tmp, "w") as f:
        f.write(RPZ_INCLUDE_BODY)
    os.replace(tmp, RPZ_INCLUDE)
    return True


def apply_rpz():
    """Regenerate the RPZ zonefile from rpz.json and hot-reload unbound.

    Uses unbound-control reload (no downtime). On checkconf/reload failure
    the previous zonefile is restored and an error raised.
    """
    entries = load_rpz_entries()
    ensure_rpz_include()
    if os.path.exists(RPZ_ZONEFILE):
        shutil.copy2(RPZ_ZONEFILE, RPZ_BACKUP)
    write_rpz_zone(entries)
    try:
        reload_unbound()
    except Exception:
        if os.path.exists(RPZ_BACKUP):
            shutil.copy2(RPZ_BACKUP, RPZ_ZONEFILE)
        raise


def add_rpz_entry(value, action, target="", note="", match=None):
    val, mode = valid_rpz_value(value)
    if val is None:
        return {"ok": False, "error": "Invalid domain or CIDR"}
    if mode == "ip" and match == "domain":
        return {"ok": False, "error": "Value looks like an IP/CIDR; pick 'Answer IP' match"}
    if mode == "domain" and match == "ip":
        return {"ok": False, "error": "Value looks like a domain; pick 'Domain' match"}
    if action not in RPZ_ACTIONS:
        return {"ok": False, "error": "Invalid action (expected block/drop/redirect/passthru)"}
    entry = {
        "domain": val,
        "match": mode,
        "action": action,
        "target": (target or "").strip() if action == "redirect" else "",
        "note": (note or "").strip()[:200],
        "added_at": time.time(),
    }
    try:
        _rpz_rdata(entry)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    entries = load_rpz_entries()
    if any(e["domain"] == val for e in entries):
        return {"ok": False, "error": "{} already has an RPZ policy".format(val)}
    entries.append(entry)
    try:
        save_rpz_entries(entries)
        apply_rpz()
    except Exception as exc:
        save_rpz_entries([e for e in entries if e["domain"] != val])
        try:
            apply_rpz()
        except Exception:
            pass
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "message": "RPZ policy for {} applied".format(val)}


def remove_rpz_entry(value):
    val, _ = valid_rpz_value(value)
    if val is None:
        return {"ok": False, "error": "Invalid domain or CIDR"}
    entries = load_rpz_entries()
    if not any(e["domain"] == val for e in entries):
        return {"ok": False, "error": "{} has no RPZ policy".format(val)}
    entries = [e for e in entries if e["domain"] != val]
    try:
        save_rpz_entries(entries)
        apply_rpz()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "message": "RPZ policy for {} removed".format(val)}


def build_rpz():
    entries = load_rpz_entries()
    try:
        zone_mtime = os.path.getmtime(RPZ_ZONEFILE)
    except OSError:
        zone_mtime = None
    return {
        "ok": True,
        "entries": entries,
        "zone_name": RPZ_ZONE_NAME,
        "zonefile": RPZ_ZONEFILE,
        "include_installed": os.path.exists(RPZ_INCLUDE),
        "last_update": zone_mtime,
        "feeds": _rpz_feeds_status(load_rpz_feeds()),
        "stats": _rpz_stats(),
        "hits": _rpz_hits(100),
    }


# --- RPZ feeds (auto-updating threat feeds consumed by unbound directly) ---
RPZ_FEEDS_FILE = os.path.join(BLOCKLIST_DIR, "rpz-feeds.json")
RPZ_FEEDS_CONF = "/etc/unbound/unbound.conf.d/98-rpz-feeds.conf"
RPZ_FEEDS_BACKUP = RPZ_FEEDS_CONF + ".bak"


def _rpz_feed_zone_name(url):
    return "feed-{}.rpz.local".format(hashlib.sha256(url.encode()).hexdigest()[:8])


def _rpz_feed_zonefile(url):
    return os.path.join(
        os.path.dirname(RPZ_ZONEFILE),
        "rpz-feed-{}.rpz".format(hashlib.sha256(url.encode()).hexdigest()[:8]),
    )


def load_rpz_feeds():
    try:
        with open(RPZ_FEEDS_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return [
                    f for f in data
                    if isinstance(f, dict) and f.get("url")
                ]
    except (OSError, ValueError):
        pass
    return []


def save_rpz_feeds(feeds):
    os.makedirs(os.path.dirname(RPZ_FEEDS_FILE), exist_ok=True)
    tmp = RPZ_FEEDS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(feeds, f, indent=2)
    os.replace(tmp, RPZ_FEEDS_FILE)


def write_rpz_feeds_conf(feeds):
    enabled = [f for f in feeds if f.get("enabled", True)]
    lines = ["# Generated by the tuxwall Blocklists page (RPZ feeds) - DO NOT EDIT"]
    for f in enabled:
        url = f["url"]
        name = _rpz_feed_zone_name(url)
        zonefile = _rpz_feed_zonefile(url)
        lines.append("")
        lines.append("# {}".format(f.get("name") or url))
        lines.append("rpz:")
        lines.append('    name: "{}"'.format(name))
        lines.append('    url: "{}"'.format(url))
        lines.append('    zonefile: "{}"'.format(zonefile))
        lines.append("    # unbound re-checks the feed automatically and hot-reloads it")
        lines.append("    rpz-log: yes")
        lines.append('    rpz-log-name: "{}"'.format(name))
    lines.append("")
    os.makedirs(os.path.dirname(RPZ_FEEDS_CONF), exist_ok=True)
    tmp = RPZ_FEEDS_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines))
    os.replace(tmp, RPZ_FEEDS_CONF)


def _rpz_feed_entries(url):
    """Count CNAME policy entries in a feed's cached zonefile."""
    try:
        with open(_rpz_feed_zonefile(url), "r") as f:
            return sum(
                1 for line in f
                if " CNAME " in line and not line.startswith(("$", "@", ";"))
            )
    except OSError:
        return 0


def apply_rpz_feeds():
    """Regenerate the RPZ feeds include and hot-reload unbound."""
    feeds = load_rpz_feeds()
    if os.path.exists(RPZ_FEEDS_CONF):
        shutil.copy2(RPZ_FEEDS_CONF, RPZ_FEEDS_BACKUP)
    write_rpz_feeds_conf(feeds)
    try:
        reload_unbound()
    except Exception:
        if os.path.exists(RPZ_FEEDS_BACKUP):
            shutil.copy2(RPZ_FEEDS_BACKUP, RPZ_FEEDS_CONF)
        raise


def add_rpz_feed(url, name=""):
    url = (url or "").strip()
    if not valid_blocklist_url(url):
        return {"ok": False, "error": "Invalid feed URL (https and public host required)"}
    feeds = load_rpz_feeds()
    if any(f["url"] == url for f in feeds):
        return {"ok": False, "error": "Feed already added"}
    feeds.append({
        "url": url,
        "name": (name or "").strip()[:200],
        "enabled": True,
        "added_at": time.time(),
    })
    try:
        save_rpz_feeds(feeds)
        apply_rpz_feeds()
    except Exception as exc:
        save_rpz_feeds([f for f in feeds if f["url"] != url])
        apply_rpz_feeds()
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "message": "RPZ feed added and Unbound reloaded"}


def remove_rpz_feed(url):
    url = (url or "").strip()
    feeds = load_rpz_feeds()
    if not any(f["url"] == url for f in feeds):
        return {"ok": False, "error": "Feed not found"}
    removed = [f for f in feeds if f["url"] == url]
    feeds = [f for f in feeds if f["url"] != url]
    try:
        save_rpz_feeds(feeds)
        apply_rpz_feeds()
    except Exception as exc:
        save_rpz_feeds(feeds + removed)
        apply_rpz_feeds()
        return {"ok": False, "error": str(exc)}
    try:
        os.remove(_rpz_feed_zonefile(url))
    except OSError:
        pass
    return {"ok": True, "message": "RPZ feed removed and Unbound reloaded"}


def toggle_rpz_feed(url):
    url = (url or "").strip()
    feeds = load_rpz_feeds()
    for f in feeds:
        if f["url"] == url:
            f["enabled"] = not f.get("enabled", True)
    save_rpz_feeds(feeds)
    try:
        apply_rpz_feeds()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "message": "RPZ feed toggled and Unbound reloaded"}


def _rpz_feeds_status(feeds):
    """Annotate feeds with entry counts / zonefile mtimes (best effort)."""
    out = []
    for f in feeds:
        zonefile = _rpz_feed_zonefile(f["url"])
        try:
            mtime = os.path.getmtime(zonefile)
        except OSError:
            mtime = None
        g = dict(f)
        g["entries"] = _rpz_feed_entries(f["url"]) if mtime else 0
        g["last_updated"] = mtime
        g["last_status"] = "ok" if mtime else "pending"
        out.append(g)
    return out


# --- RPZ activity: hit log + action counters -------------------------------
RPZ_HIT_LINE_RE = re.compile(r"rpz:\s+applied\s+\[(?P<zone>[^\]]+)\]\s+(?P<qname>\S+)\s+"
                             r"(?P<action>rpz-[a-z-]+)\s+(?P<client>[\d.]+)@(?P<port>\d+)\s+"
                             r"(?P<query>\S+)")
RPZ_ACTIVITY_CACHE = {"at": 0.0, "hits": [], "lock": threading.Lock()}
RPZ_ACTIVITY_TTL = 10


def _rpz_journal_hits(limit):
    """Read recent RPZ 'applied' lines from the unbound journal."""
    try:
        proc = subprocess.run(
            ["journalctl", "-u", "unbound", "--since", "-24h", "--no-pager",
             "-o", "short-iso", "-n", "2000"],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0:
            return []
    except Exception:
        return []
    hits = []
    for line in proc.stdout.splitlines():
        if "rpz: applied" not in line:
            continue
        m = RPZ_HIT_LINE_RE.search(line)
        if not m:
            continue
        hits.append({
            "time": line.split(" ", 1)[0],
            "zone": m.group("zone"),
            "qname": m.group("qname"),
            "action": m.group("action"),
            "client": m.group("client"),
            "query": m.group("query"),
        })
    hits.reverse()
    return hits[:limit]


def _rpz_hits(limit=100):
    with RPZ_ACTIVITY_CACHE["lock"]:
        now = time.time()
        if now - RPZ_ACTIVITY_CACHE["at"] > RPZ_ACTIVITY_TTL:
            RPZ_ACTIVITY_CACHE["hits"] = _rpz_journal_hits(500)
            RPZ_ACTIVITY_CACHE["at"] = now
        return RPZ_ACTIVITY_CACHE["hits"][:limit]


def _rpz_stats():
    """Pull RPZ action counters from unbound-control stats (since restart).

    Uses stats_noreset - plain `unbound-control stats` RESETS every unbound
    statistics counter (queries, cache hits, qtypes, ...) on read. The
    dashboard's 30s blocklist/RPZ refresh polls this function, so a resetting
    read periodically zeroed the counters just before the overview's /api/dns
    read, blanking the DNS donut charts with "No data yet"."""
    stats = {}
    try:
        proc = subprocess.run(
            ["unbound-control", "stats_noreset"], capture_output=True, text=True,
            timeout=15
        )
        for line in proc.stdout.splitlines():
            if not line.startswith("num.rpz."):
                continue
            key, _, val = line.partition("=")
            try:
                stats[key] = int(val)
            except ValueError:
                pass
    except Exception:
        pass
    return stats


# --- RPZ bulk import --------------------------------------------------------
def rpz_import(text):
    """Import policies, one per line: <value> [action] [target].

    CIDR values are auto-detected (anything with a '/' or an IP) and become
    answer-IP policies. Returns a summary; invalid lines are reported.
    """
    added, skipped, errors = 0, 0, []
    pending = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        value = parts[0]
        action = parts[1] if len(parts) > 1 else "block"
        target = parts[2] if len(parts) > 2 else ""
        val, mode = valid_rpz_value(value)
        if val is None:
            errors.append("invalid value: {}".format(value))
            continue
        if action not in RPZ_ACTIONS:
            errors.append("invalid action for {}: {}".format(value, action))
            continue
        entry = {
            "domain": val,
            "match": mode,
            "action": action,
            "target": target.strip() if action == "redirect" else "",
            "note": "bulk import",
            "added_at": time.time(),
        }
        try:
            _rpz_rdata(entry)
        except ValueError as exc:
            errors.append("{}: {}".format(value, exc))
            continue
        pending.append(entry)

    entries = load_rpz_entries()
    known = {e["domain"] for e in entries}
    for entry in pending:
        if entry["domain"] in known:
            skipped += 1
            continue
        entries.append(entry)
        known.add(entry["domain"])
        added += 1

    if not added:
        return {"ok": True, "added": 0, "skipped": skipped, "errors": errors,
                "message": "Nothing imported (duplicates or invalid lines)"}
    try:
        save_rpz_entries(entries)
        apply_rpz()
    except Exception as exc:
        # revert to the pre-import state and re-apply
        save_rpz_entries(entries[:-added])
        try:
            apply_rpz()
        except Exception:
            pass
        return {"ok": False, "added": 0, "skipped": skipped,
                "errors": errors + [str(exc)], "message": "Import failed: " + str(exc)}
    return {"ok": True, "added": added, "skipped": skipped, "errors": errors,
            "message": "Imported {} policies{}".format(
                added, " ({} skipped as duplicates)".format(skipped) if skipped else "")}


def refresh_rpz_feeds():
    """Force Unbound to re-download feed zones.

    Unbound re-fetches a url: RPZ zone when its cached zonefile is absent,
    so remove the cache and hot-reload. If a feed is unreachable, Unbound
    logs an error and keeps serving DNS without that zone until its next
    successful check.
    """
    feeds = [f for f in load_rpz_feeds() if f.get("enabled", True)]
    removed = []
    for f in feeds:
        zonefile = _rpz_feed_zonefile(f["url"])
        try:
            os.remove(zonefile)
            removed.append(zonefile)
        except OSError:
            pass
    try:
        reload_unbound()
    except Exception:
        # restore caches so we don't leave feeds cold on a failed reload
        for zonefile in removed:
            open(zonefile, "a").close()
        try:
            reload_unbound()
        except Exception as exc:
            raise RuntimeError("Feed refresh failed: {}".format(exc))
    return {"ok": True, "message": "Forced re-download of {} feed(s)".format(len(removed))}


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


# --- Blocklist SSRF guard (live patch 2026-09-06) ---
class _SSRFRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects that point at non-public hosts."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        loc = headers.get("Location") or newurl
        try:
            host = urllib.parse.urlsplit(
                urllib.parse.urljoin(req.full_url, loc)).hostname or ""
        except ValueError:
            raise RuntimeError("Blocked redirect: malformed Location")
        if not _blocklist_host_is_public(host):
            raise RuntimeError(
                "Blocked redirect to non-public host %r" % host)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _blocklist_host_is_public(host):
    """Resolve host and require every address to be globally reachable."""
    host = (host or "").strip().rstrip(".")
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC,
                                   type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return False  # fail closed on unresolvable names
    addrs = {info[4][0] for info in infos}
    if not addrs:
        return False
    for raw in addrs:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False
    return True


def valid_blocklist_url(url):
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


BLOCKLIST_CATALOG_SOURCES_URL = "https://tuxwall.org/blocklist/sources.txt"
BLOCKLIST_CATALOG_RPZ_URL = "https://tuxwall.org/blocklist/rpz.txt"
BLOCKLIST_CATALOG_TTL = 600  # seconds to cache the catalog in memory
BLOCKLIST_CATALOG_MAX_BYTES = 1024 * 1024

BLOCKLIST_CATALOG_CACHE = {"ts": 0.0, "data": None}


def _parse_blocklist_catalog(text):
    """Parse 'URL | Name | Description' lines from a catalog file."""
    items = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        url = parts[0] if parts else ""
        if not valid_blocklist_url(url):
            continue
        items.append({
            "url": url,
            "name": (parts[1] if len(parts) > 1 and parts[1] else url),
            "description": parts[2] if len(parts) > 2 else "",
        })
    return items


def build_blocklist_catalog():
    now = time.time()
    cached = BLOCKLIST_CATALOG_CACHE["data"]
    if cached is not None and now - BLOCKLIST_CATALOG_CACHE["ts"] < BLOCKLIST_CATALOG_TTL:
        out = dict(cached)
        out["cached"] = True
        return out
    result = {"ok": True, "sources": [], "rpz": [], "errors": []}
    for key, url in (("sources", BLOCKLIST_CATALOG_SOURCES_URL),
                     ("rpz", BLOCKLIST_CATALOG_RPZ_URL)):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "tuxwall-catalog/1.0",
            })
            with urllib.request.urlopen(req, timeout=BLOCKLIST_FETCH_TIMEOUT) as resp:
                body = resp.read(BLOCKLIST_CATALOG_MAX_BYTES + 1)
                if len(body) > BLOCKLIST_CATALOG_MAX_BYTES:
                    raise RuntimeError("catalog file too large")
                result[key] = _parse_blocklist_catalog(
                    body.decode("utf-8", errors="replace"))
        except Exception as exc:
            result["errors"].append("%s: %s" % (key, exc))
    BLOCKLIST_CATALOG_CACHE["ts"] = now
    BLOCKLIST_CATALOG_CACHE["data"] = result
    out = dict(result)
    out["cached"] = False
    return out


def fetch_blocklist(url):
    try:
        parts = urllib.parse.urlsplit((url or "").strip())
    except ValueError:
        raise RuntimeError("Invalid blocklist URL")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise RuntimeError("Invalid blocklist URL (http/https only)")
    if not _blocklist_host_is_public(parts.hostname):
        raise RuntimeError(
            "Refusing to fetch from non-public host %r" % parts.hostname)
    req = urllib.request.Request(url, headers={
        "User-Agent": "tuxwall-blocklist/1.0",
        "Accept-Encoding": "gzip",
    })
    opener = urllib.request.build_opener(_SSRFRedirectHandler)
    with opener.open(req, timeout=BLOCKLIST_FETCH_TIMEOUT) as resp:
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
        # Only list clients that hold a lease AND answer on the LAN right now,
        # so dead/offline clients drop out of the sets and the page.
        active_map = {}
        for ip, lease in lease_map.items():
            try:
                online = arp_online(ip)
            except Exception:
                online = True
            if online:
                active_map[ip] = lease
        try:
            sync_client_traffic_clients(list(active_map))
        except Exception as exc:
            clients_error = str(exc)
        own_ips = _host_ipv4_addrs()
        for ip, snap in traffic.snapshot().items():
            lease = active_map.get(ip)
            if lease is None or ip in own_ips:
                continue
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


def _host_ipv4_addrs():
    """IPv4 addresses assigned to this router (excluded from client lists)."""
    try:
        proc = subprocess.run(
            ["ip", "-o", "-4", "addr"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return set()
    addrs = set()
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            addrs.add(parts[3].split("/")[0])
    return addrs


def sync_client_traffic_clients(ips):
    """Keep the nft per-IP sets in sync with the given client IPs.

    Adds elements for new clients and removes elements for clients that
    no longer have an active lease, so dead IPs stop being counted and
    listed. Removing an element resets its counter, which the monitor
    treats as a fresh baseline.
    """
    wanted = set(ips)
    for set_name in (NFT_TX_SET, NFT_RX_SET):
        try:
            proc = subprocess.run(
                [NFT_BIN, "list", "set", "inet", NFT_TABLE, set_name],
                capture_output=True, text=True, timeout=10,
            )
        except Exception:
            continue
        if proc.returncode != 0:
            continue
        current = set()
        for match in re.finditer(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+counter", proc.stdout,
        ):
            current.add(match.group(1))
        for ip in current - wanted:
            try:
                subprocess.run(
                    [NFT_BIN, "delete", "element", "inet", NFT_TABLE,
                     set_name, "{%s}" % ip],
                    capture_output=True, text=True, timeout=10,
                )
            except Exception:
                continue
        missing = wanted - current
        if missing:
            try:
                subprocess.run(
                    [NFT_BIN, "add", "element", "inet", NFT_TABLE,
                     set_name, "{%s}" % ", ".join(sorted(missing))],
                    capture_output=True, text=True, timeout=10,
                )
            except Exception:
                continue


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
                if prev is not None and now > prev["t"]:
                    dt = now - prev["t"]
                    if rx < prev["rx"] or tx < prev["tx"]:
                        # Counter was reset (element recreated) - new baseline.
                        self.rates[ip] = {"rx_rate": 0.0, "tx_rate": 0.0}
                    elif dt > 0:
                        self.rates[ip] = {
                            "rx_rate": (rx - prev["rx"]) / dt,
                            "tx_rate": (tx - prev["tx"]) / dt,
                        }
                        tot = self.totals.setdefault(ip, {"rx": 0, "tx": 0})
                        tot["rx"] += rx - prev["rx"]
                        tot["tx"] += tx - prev["tx"]
                self.last[ip] = {"t": now, "rx": rx, "tx": tx}
            for gone in set(self.rates) - set(current):
                self.rates.pop(gone, None)
                self.totals.pop(gone, None)
                self.last.pop(gone, None)

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


LATENCY_TARGET = "1.1.1.1"
LATENCY_WINDOW = 48 * 3600
LATENCY_HISTORY_FILE = "/var/lib/tuxwall/latency_history.jsonl"
LATENCY_HISTORY_KEEP = 7 * 86400
LATENCY_TRIM_EVERY = 3600

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
        self._last_trim = 0.0
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
        if time.time() - self._last_trim >= LATENCY_TRIM_EVERY:
            self._trim_history()

    def _trim_history(self):
        """Drop on-disk samples older than LATENCY_HISTORY_KEEP (the file
        used to grow forever: ~8 MB a month). Only rewrites when the oldest
        line is out of range; this thread is the only writer."""
        self._last_trim = time.time()
        cutoff = self._last_trim - LATENCY_HISTORY_KEEP
        tmp = LATENCY_HISTORY_FILE + ".tmp"
        try:
            with open(LATENCY_HISTORY_FILE, "r") as f:
                try:
                    if json.loads(f.readline()).get("ts", 0) >= cutoff:
                        return
                except (ValueError, AttributeError):
                    pass
                f.seek(0)
                with open(tmp, "w") as out:
                    for line in f:
                        try:
                            if json.loads(line).get("ts", 0) >= cutoff:
                                out.write(line)
                        except (ValueError, AttributeError):
                            continue
            os.replace(tmp, LATENCY_HISTORY_FILE)
        except OSError:
            try:
                os.unlink(tmp)
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


# ---- Router Insights history (Overview line charts) ----
# One row per minute, collected server-side so the charts have history no
# matter whether a browser was watching. Appended to a JSONL file (survives
# API reloads; compacted to 24 h) and served by GET /api/insights/history.
INSIGHTS_HISTORY_FILE = "/var/lib/tuxwall/insights-history.jsonl"
INSIGHTS_KEYS = ("cpu", "mem", "temp", "load", "disk", "swap", "rx", "tx", "atk",
                 "qpm", "blk", "hit", "sf", "v6", "fwa", "fwb")
INSIGHTS_KEEP = 1440            # 24 h of 1-minute rows
INSIGHTS_RANGES = {"15m": (900, 60), "1h": (3600, 60), "6h": (21600, 60), "24h": (86400, 300)}


class InsightsHistory:
    """Samples the Router Insights metrics once a minute (aligned to the
    minute). Rates are averages over the minute: CPU from /proc/stat, WAN
    from /proc/net/dev, DNS from unbound counters, firewall from the cached
    iptables counters. Counter resets (unbound/ufw restart) leave that
    minute empty instead of producing negative or huge values."""

    def __init__(self):
        self.lock = threading.Lock()
        self.rows = deque(maxlen=INSIGHTS_KEEP)
        self.prev = {}
        self.appended = 0
        self.tick_ms = None
        self.tick_cpu_ms = None
        self.running = False

    # -- persistence --
    def _load(self):
        cutoff = time.time() - 86400
        rows = {}
        try:
            with open(INSIGHTS_HISTORY_FILE, "r") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                        t = int(rec["t"])
                    except (ValueError, KeyError, TypeError):
                        continue
                    if t >= cutoff:
                        rows[t] = {k: rec[k] for k in INSIGHTS_KEYS
                                   if isinstance(rec.get(k), (int, float))}
        except OSError:
            pass
        with self.lock:
            for t in sorted(rows):
                self.rows.append((t, rows[t]))
        self._compact()

    def _compact(self):
        with self.lock:
            rows = list(self.rows)
        tmp = INSIGHTS_HISTORY_FILE + ".tmp"
        try:
            os.makedirs(os.path.dirname(INSIGHTS_HISTORY_FILE), exist_ok=True)
            with open(tmp, "w") as f:
                for t, v in rows:
                    f.write(json.dumps(dict(v, t=t), separators=(",", ":")) + "\n")
            os.replace(tmp, INSIGHTS_HISTORY_FILE)
        except OSError as exc:
            print("[insights] compact failed: %s" % exc, flush=True)
        self.appended = 0

    def _append(self, t, v):
        try:
            with open(INSIGHTS_HISTORY_FILE, "a") as f:
                f.write(json.dumps(dict(v, t=t), separators=(",", ":")) + "\n")
        except OSError:
            pass
        self.appended += 1
        if self.appended >= 120:
            self._compact()

    # -- sources --
    @staticmethod
    def _cpu_times():
        with open("/proc/stat", "r") as f:
            parts = [int(x) for x in f.readline().split()[1:]]
        return sum(parts), parts[3] + (parts[4] if len(parts) > 4 else 0)

    @staticmethod
    def _iface_bytes(iface):
        with open("/proc/net/dev", "r") as f:
            for line in f:
                name, _, rest = line.partition(":")
                if name.strip() == iface:
                    p = rest.split()
                    return int(p[0]), int(p[8])
        return None

    @staticmethod
    def _gauges():
        out = {}
        mem = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                p = line.split()
                if p and p[0] in ("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"):
                    mem[p[0]] = int(p[1])
        if mem.get("MemTotal:"):
            out["mem"] = round((mem["MemTotal:"] - mem.get("MemAvailable:", 0)) * 100.0 / mem["MemTotal:"], 1)
        out["swap"] = round((mem.get("SwapTotal:", 0) - mem.get("SwapFree:", 0)) * 100.0 / mem["SwapTotal:"], 1) \
            if mem.get("SwapTotal:") else 0.0
        st = os.statvfs("/")
        if st.f_blocks:
            out["disk"] = round((st.f_blocks - st.f_bfree) * 100.0 / st.f_blocks, 1)
        out["load"] = round(os.getloadavg()[0] * 100.0 / (os.cpu_count() or 1), 1)
        try:
            for zone in sorted(os.listdir("/sys/class/thermal")):
                if not zone.startswith("thermal_zone"):
                    continue
                base = "/sys/class/thermal/" + zone
                with open(base + "/type") as f:
                    ztype = f.read().strip()
                if "pkg" in ztype or "x86" in ztype or "cpu" in ztype:
                    with open(base + "/temp") as f:
                        out["temp"] = round(int(f.read().strip()) / 1000.0, 1)
                    break
        except (OSError, ValueError):
            pass
        return out

    @staticmethod
    def _dns_counters():
        proc = subprocess.run(["unbound-control", "stats_noreset"],
                              capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return None
        want = {"total.num.queries": "q", "num.answer.rcode.NXDOMAIN": "nx",
                "total.num.cachehits": "h", "total.num.cachemiss": "m",
                "num.query.ipv6": "v6", "num.answer.rcode.SERVFAIL": "sf"}
        out = {"q": 0, "nx": 0, "h": 0, "m": 0, "v6": 0, "sf": 0}
        for line in proc.stdout.splitlines():
            k, _, val = line.partition("=")
            if k in want:
                try:
                    out[want[k]] = float(val)
                except ValueError:
                    pass
        return out

    def _read_all(self):
        """Raw readings: counters and gauges at this instant."""
        now = time.time()
        r = {"t": now}
        for name, fn in (("cpu", self._cpu_times), ("gauges", self._gauges),
                         ("dns", self._dns_counters)):
            try:
                r[name] = fn()
            except Exception:
                r[name] = None
        try:
            wan = _detect_wan_iface()
            r["wan"] = wan
            r["net"] = self._iface_bytes(wan) if wan else None
        except Exception:
            r["net"] = None
        try:
            c = _firewall_counters()
            r["fw"] = (c["at"], c["allowed_packets"], c["blocked_packets"]) if c.get("ok") else None
        except Exception:
            r["fw"] = None
        return r

    def _sample(self):
        cur = self._read_all()
        prev, self.prev = self.prev, cur
        v = dict(cur.get("gauges") or {})
        if not prev:
            return v
        dt = cur["t"] - prev["t"]
        if dt <= 1:
            return v
        if cur.get("cpu") and prev.get("cpu"):
            tot = cur["cpu"][0] - prev["cpu"][0]
            idle = cur["cpu"][1] - prev["cpu"][1]
            if tot > 0:
                v["cpu"] = round(max(0.0, min(100.0, (1 - idle / tot) * 100.0)), 1)
        if cur.get("net") and prev.get("net") and cur.get("wan") == prev.get("wan"):
            drx = cur["net"][0] - prev["net"][0]
            dtx = cur["net"][1] - prev["net"][1]
            if drx >= 0 and dtx >= 0:
                v["rx"] = round(drx * 8 / dt)
                v["tx"] = round(dtx * 8 / dt)
        d, pd = cur.get("dns"), prev.get("dns")
        if d and pd and all(d[k] >= pd[k] for k in d):
            dq = d["q"] - pd["q"]
            v["qpm"] = round(dq * 60.0 / dt, 1)
            if dq > 0:
                v["blk"] = round((d["nx"] - pd["nx"]) * 100.0 / dq, 1)
                v["sf"] = round((d["sf"] - pd["sf"]) * 100.0 / dq, 2)
                v["v6"] = round((d["v6"] - pd["v6"]) * 100.0 / dq, 1)
            dh, dm = d["h"] - pd["h"], d["m"] - pd["m"]
            if dh + dm > 0:
                v["hit"] = round(dh * 100.0 / (dh + dm), 1)
        f, pf = cur.get("fw"), prev.get("fw")
        if f and pf and f[0] > pf[0] and f[1] >= pf[1] and f[2] >= pf[2]:
            fdt = (f[0] - pf[0]) / 60.0
            v["fwa"] = round((f[1] - pf[1]) / fdt, 1)
            v["fwb"] = round((f[2] - pf[2]) / fdt, 1)
        try:
            mon = get_security_monitor()
            with mon.lock:
                buckets = list(mon.buckets)
            end = int(cur["t"] // 60) * 60
            v["atk"] = sum(c for b, c in buckets if end - 60 <= b < end)
        except Exception:
            pass
        return v

    def _tick(self):
        t0, c0 = time.time(), time.thread_time()
        if self.prev and t0 - self.prev["t"] < 20:
            return
        v = self._sample()
        # the row covers the minute that just ended (labelled by its start)
        t = int(time.time() // 60) * 60 - 60
        if v:
            with self.lock:
                if not self.rows or self.rows[-1][0] < t:
                    self.rows.append((t, v))
                    added = True
                else:
                    added = False
            if added:
                self._append(t, v)
        self.tick_ms = round((time.time() - t0) * 1000, 1)
        self.tick_cpu_ms = round((time.thread_time() - c0) * 1000, 1)

    def _loop(self):
        self._load()
        self._sample()          # baseline for the first minute's deltas
        while self.running:
            time.sleep(60.5 - time.time() % 60)
            try:
                self._tick()
            except Exception as exc:
                print("[insights] sample failed: %s" % exc, flush=True)

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._loop, name="insights-history", daemon=True).start()

    def series(self, rng):
        span, step = INSIGHTS_RANGES.get(rng, INSIGHTS_RANGES["1h"])
        now = time.time()
        cutoff = now - span - 60
        with self.lock:
            rows = [r for r in self.rows if r[0] >= cutoff]
            oldest = self.rows[0][0] if self.rows else None
        if step > 60:
            groups = {}
            order = []
            for t, v in rows:
                g = int(t // step) * step
                if g not in groups:
                    groups[g] = {}
                    order.append(g)
                acc = groups[g]
                for k, x in v.items():
                    s = acc.setdefault(k, [0.0, 0])
                    s[0] += x
                    s[1] += 1
            rows = [(g, {k: round(s[0] / s[1], 2) for k, s in groups[g].items()}) for g in order]
        return {
            "ok": True,
            "range": rng if rng in INSIGHTS_RANGES else "1h",
            "step": step,
            "keys": list(INSIGHTS_KEYS),
            "oldest": oldest,
            "now": now,
            "tick_ms": self.tick_ms,
            "tick_cpu_ms": self.tick_cpu_ms,
            "points": [[t] + [v.get(k) for k in INSIGHTS_KEYS] for t, v in rows],
        }


_INSIGHTS = None
_INSIGHTS_LOCK = threading.Lock()


def get_insights_history():
    global _INSIGHTS
    with _INSIGHTS_LOCK:
        if _INSIGHTS is None:
            _INSIGHTS = InsightsHistory()
            _INSIGHTS.start()
        return _INSIGHTS


UI_CONF_FILE = "/etc/tuxwall/ui.json"
THEMES_DIR = "/var/www/html/themes"

# ---- Web authentication ----
AUTH_FILE = "/etc/tuxwall/auth.json"
SESSION_COOKIE = "tuxwall_session"


def _session_cookie_value(headers, token):
    """Build the session Set-Cookie value. Adds `; Secure` only when the
    request came in over HTTPS (X-Forwarded-Proto from nginx) — live
    patch 2026-09-06, dual-mode so HTTP logins keep working pre-TLS."""
    value = "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}".format(
        SESSION_COOKIE, token, SESSION_TTL)
    try:
        proto = (headers.get("X-Forwarded-Proto") or "").split(",")[0]
    except Exception:
        proto = ""
    if proto.strip().lower() == "https":
        value += "; Secure"
    return value
SESSION_TTL = 12 * 3600
SESSION_IDLE_TIMEOUT = 120 * 60  # raised 2026-09-11: dashboard polls pause when tab hidden
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
    # Live patch 2026-09-06: default credentials removed. This is now a
    # no-op kept for its call sites. No users -> setup_required (fail
    # closed); the first admin is created via POST /api/auth/setup.
    # DEFAULT_ADMIN_PASSWORD is no longer used anywhere.
    return


def _create_session(username, role):
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _sessions_lock:
        for t in [t for t, s in list(_sessions.items())
                 if s["exp"] < now or now - s.get("last", now) > SESSION_IDLE_TIMEOUT]:
            del _sessions[t]
        _sessions[token] = {"exp": now + SESSION_TTL, "last": now,
                            "username": username, "role": role}
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
        if now - sess.get("last", now) > SESSION_IDLE_TIMEOUT:
            _sessions.pop(token, None)
            return None
        username = sess["username"]
        sess["last"] = now
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


def _is_admin(identity):
    return bool(identity) and identity.get("role") == "admin"


# Role gating (2026-09-12). Previously any authenticated session could call
# every state-changing endpoint; the read-only "viewer" role was enforced
# only by hiding controls in the browser, so a viewer could reboot the
# router, rewrite firewall rules, read WireGuard peer configs or drive the
# AI agent (which holds sudo). Both tables below are default-deny: a newly
# added endpoint is admin-only until it is deliberately listed here.

# POSTs a viewer may make. These are self-service account actions, and each
# one additionally verifies inside its handler that the caller is operating
# on their own account. Login/logout/setup are handled before the gate.
VIEWER_POST_PATHS = frozenset({
    "/api/auth/password",
    "/api/auth/totp/setup",
    "/api/auth/totp/confirm",
    "/api/auth/totp/disable",
})

# GETs that disclose credentials or grant shell reach, so admin-only.
# /api/backups/** ships raw archives containing auth.json and WireGuard
# private keys; /api/agent/** reaches the opencode agent; /api/logs/**
# returns raw service journals (client IPs/hostnames, auth failures, URLs,
# tokens printed by services - 3.3.3).
ADMIN_GET_PREFIXES = (
    "/api/logs",
    "/api/firewall/snapshots",
    "/api/backups",
    "/api/agent",
    "/api/alerts",
    "/api/plugins",
    "/api/system/kea-config",
    "/api/system/unbound-config",
    "/api/system/dhcp-form",
    "/api/system/unbound-form",
    "/api/community",
)


def _drop_session(headers):
    token = _cookie_token(headers)
    if token:
        with _sessions_lock:
            _sessions.pop(token, None)


def _client_key(handler):
    # Only trust X-Real-IP when the connection itself came from the local
    # nginx proxy (loopback). Otherwise a LAN client could spoof the header
    # and rotate identities to bypass login rate limiting.
    try:
        direct = handler.client_address[0]
    except Exception:
        direct = ""
    if direct in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        real = handler.headers.get("X-Real-IP")
        if real and real.strip():
            return real.strip()
        fwd = handler.headers.get("X-Forwarded-For")
        if fwd and fwd.strip():
            return fwd.split(",")[0].strip()
        return direct
    return direct


# 2026-11-03 audit: loopback peer-IP trust was a hole - any local process
# (SSRF from the co-hosted public forum, malware) reached the loopback-exempt
# endpoints unauthenticated and could forge X-Real-IP to rotate login
# rate-limit buckets. Loopback exemptions now require a shared secret that
# lives in a root-only file, unreadable by other local users.
INTERNAL_TOKEN_FILE = "/etc/tuxwall/internal-token"
INTERNAL_TOKEN_HEADER = "X-Tuxwall-Token"


def _ensure_internal_token():
    """Root-only shared secret for loopback-exempt endpoints; created on
    first use. Returns "" when unavailable (exemptions then fail closed)."""
    try:
        with open(INTERNAL_TOKEN_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        tok = secrets.token_hex(32)
        try:
            with open(INTERNAL_TOKEN_FILE, "w") as f:
                f.write(tok)
            os.chmod(INTERNAL_TOKEN_FILE, 0o600)
            return tok
        except Exception:
            return ""
    except Exception:
        return ""


def _valid_internal_token(handler):
    tok = _ensure_internal_token()
    if not tok:
        return False
    supplied = handler.headers.get(INTERNAL_TOKEN_HEADER) or ""
    return hmac.compare_digest(supplied, tok)


def _is_trusted_local(handler):
    """Loopback peer AND the internal-token handshake. Only tuxwall's own
    units (which read the root-only token) qualify; a plain loopback
    connection - SSRF, local malware - does not."""
    try:
        direct = handler.client_address[0]
    except Exception:
        return False
    if direct not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        return False
    return _valid_internal_token(handler)


# AI assistant (2026-11-14): read-only token for the opencode agent's tuxwall
# MCP tool (/usr/local/lib/tuxwall/tuxwall_mcp.py). The token file is
# readable by the tuxwall-agent group only. A request carrying the header is
# served ONLY when it is a direct loopback connection (no proxy headers -
# nginx always adds them, so the header is useless from the LAN), a GET, the
# token matches, and the path is in the explicit allowlist below. The
# resulting identity (role "agent-ro") never passes an admin/write check.
AGENT_API_TOKEN_DIR = "/etc/tuxwall/agent"
AGENT_API_TOKEN_FILE = AGENT_API_TOKEN_DIR + "/api.token"
AGENT_API_TOKEN_HEADER = "X-TuxWall-Agent-Token"
AGENT_API_GROUP = "tuxwall-agent"
AGENT_API_READ_PATHS = frozenset({
    "/api/status",
    "/api/system",
    "/api/system/services",
    "/api/firewall",
    "/api/firewall/managed",
    "/api/firewall/findings",
    "/api/firewall/suggestions",
    "/api/firewall/hits",
    "/api/firewall/interfaces",
    "/api/interfaces",
    "/api/interfaces/policy",
    "/api/leases",
    "/api/dns",
    "/api/crowdsec",
    "/api/security",
    "/api/incidents",
    "/api/insights/history",
})
_AGENT_API_PROXY_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto",
                            "X-Forwarded-Host", "Forwarded")


def _ensure_agent_api_token():
    """Create (or repair perms of) the agent read token. Called at start."""
    import grp
    try:
        gid = grp.getgrnam(AGENT_API_GROUP).gr_gid
    except KeyError:
        gid = 0   # no agent user yet: root-only until the next start
    try:
        os.makedirs(AGENT_API_TOKEN_DIR, mode=0o750, exist_ok=True)
        os.chown(AGENT_API_TOKEN_DIR, 0, gid)
        os.chmod(AGENT_API_TOKEN_DIR, 0o750)
        try:
            with open(AGENT_API_TOKEN_FILE) as f:
                ok = len(f.read().strip()) >= 32
        except FileNotFoundError:
            ok = False
        if not ok:
            fd, tmp = tempfile.mkstemp(prefix=".api.token.", dir=AGENT_API_TOKEN_DIR)
            try:
                os.fchmod(fd, 0o640)
                os.fchown(fd, 0, gid)
                with os.fdopen(fd, "w") as f:
                    f.write(secrets.token_urlsafe(32) + "\n")
                os.replace(tmp, AGENT_API_TOKEN_FILE)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        os.chown(AGENT_API_TOKEN_FILE, 0, gid)
        os.chmod(AGENT_API_TOKEN_FILE, 0o640)
    except Exception as exc:
        print("[agent-api] read token unavailable: %s" % type(exc).__name__, flush=True)


def _agent_api_token():
    try:
        with open(AGENT_API_TOKEN_FILE) as f:
            tok = f.read().strip()
    except OSError:
        return ""
    return tok if len(tok) >= 32 else ""


def _agent_ro_identity(handler, path):
    """Validate a request that carries the agent token header (GET only).
    Returns the read-only identity, or None after sending the error."""
    try:
        direct = handler.client_address[0]
    except Exception:
        direct = ""
    if (direct not in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
            or any(handler.headers.get(h) is not None for h in _AGENT_API_PROXY_HEADERS)):
        handler._send(403, {"ok": False, "error": "Agent token accepted from local direct connections only"})
        return None
    tok = _agent_api_token()
    supplied = handler.headers.get(AGENT_API_TOKEN_HEADER) or ""
    if not tok or not hmac.compare_digest(supplied.encode(), tok.encode()):
        handler._send(401, {"ok": False, "error": "Invalid agent token"})
        return None
    if path not in AGENT_API_READ_PATHS:
        handler._send(403, {"ok": False, "error": "Endpoint not available to the agent read token"})
        return None
    return {"username": "agent", "role": "agent-ro", "owner": False}


# AI assistant phase E (2026-11-14): AI providers, API keys and models are
# managed from the dashboard (admin only, like every /api/agent route).
# - Catalog keys/OAuth go to opencode's own credential store via its API;
#   the browser only ever sees a masked tail ("••••abcd").
# - Custom OpenAI-compatible servers are written to /etc/tuxwall/opencode.json
#   (world-readable) in the V2 "providers" shape; their keys live in
#   /etc/tuxwall/agent/keys/<id>.key (0640 root:tuxwall-agent) referenced
#   as "{file:...}" so the config file itself never holds a secret.
# - Key material is never logged: credential calls use log_body=False and
#   upstream error text is scrubbed of the submitted key.
OPENCODE_CONF = "/etc/tuxwall/opencode.json"
AGENT_KEYS_DIR = AGENT_API_TOKEN_DIR + "/keys"
_OC_CONF_LOCK = threading.Lock()
AGENT_PROVIDER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
AGENT_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$")
AGENT_KEY_RE = re.compile(r"^[\x21-\x7e]{8,512}$")
AGENT_OBJ_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
AGENT_INTEG_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
AGENT_OPENAI_COMPAT_PKG = "@opencode/ai/providers/openai-compatible"
AGENT_POPULAR_INTEGRATIONS = (
    "anthropic", "openai", "openrouter", "google", "opencode", "opencode-go",
    "deepseek", "mistral", "groq", "xai", "togetherai", "fireworks-ai",
    "github-copilot",
)
# Catalog IDs a custom server may reuse: local runtimes whose built-in entry
# is only an endpoint (overriding it with a custom baseURL is the documented
# V2 pattern). Every other catalog ID is reserved.
AGENT_LOCAL_RUNTIME_IDS = ("lmstudio", "vllm", "unsloth")


def _agent_mask_secret(value):
    v = str(value or "")
    return "••••" + v[-4:] if len(v) >= 12 else "••••"


def _agent_scrub(text, secrets_list):
    out = str(text or "")
    for s in secrets_list or ():
        if s and len(s) >= 4:
            out = out.replace(s, "••••")
    return out


def _agent_redact(obj):
    """Copy of a config/provider structure with secret-looking values masked
    (opencode resolves {file:} references, so /api/config holds real keys)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if (isinstance(v, str) and v
                    and re.search(r"(?i)api.?key|token|secret|password|authorization", str(k))):
                out[k] = v if v.startswith(("{file:", "{env:")) else _agent_mask_secret(v)
            elif str(k).lower() == "headers" and isinstance(v, dict):
                out[k] = {hk: "••••" for hk in v}
            else:
                out[k] = _agent_redact(v)
        return out
    if isinstance(obj, list):
        return [_agent_redact(x) for x in obj]
    return obj


def _oc_conf_read():
    with open(OPENCODE_CONF) as f:
        conf = json.load(f)
    if not isinstance(conf, dict):
        raise ValueError("opencode.json is not a JSON object")
    return conf


def _oc_conf_write(conf):
    """Atomic rewrite of /etc/tuxwall/opencode.json keeping owner/mode; the
    previous version is kept as opencode.json.bak (0600). Caller holds
    _OC_CONF_LOCK."""
    st = os.stat(OPENCODE_CONF)
    data = json.dumps(conf, indent=2, ensure_ascii=False) + "\n"
    json.loads(data)
    d = os.path.dirname(OPENCODE_CONF)
    with open(OPENCODE_CONF, "rb") as f:
        prev = f.read()
    for target, payload, mode, uid, gid in (
            (OPENCODE_CONF + ".bak", prev, 0o600, 0, 0),
            (OPENCODE_CONF, data.encode("utf-8"), st.st_mode & 0o7777, st.st_uid, st.st_gid)):
        fd, tmp = tempfile.mkstemp(prefix=".opencode.json.", dir=d)
        try:
            os.fchmod(fd, mode)
            os.fchown(fd, uid, gid)
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def _agent_key_path(pid):
    return os.path.join(AGENT_KEYS_DIR, pid + ".key")


def _agent_key_write(pid, key):
    import grp
    gid = grp.getgrnam(AGENT_API_GROUP).gr_gid
    os.makedirs(AGENT_KEYS_DIR, mode=0o750, exist_ok=True)
    os.chown(AGENT_KEYS_DIR, 0, gid)
    os.chmod(AGENT_KEYS_DIR, 0o750)
    fd, tmp = tempfile.mkstemp(prefix=".key.", dir=AGENT_KEYS_DIR)
    try:
        os.fchmod(fd, 0o640)
        os.fchown(fd, 0, gid)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        os.replace(tmp, _agent_key_path(pid))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return _agent_key_path(pid)


def _agent_key_read(pid):
    try:
        with open(_agent_key_path(pid)) as f:
            return f.read().strip()
    except OSError:
        return ""


def _agent_key_remove(pid):
    try:
        os.unlink(_agent_key_path(pid))
    except FileNotFoundError:
        pass


def _agent_ip_blocked(ip):
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return False
    return (ip.is_link_local or ip.is_multicast or ip.is_unspecified
            or ip.is_reserved
            or ip in ipaddress.ip_network("169.254.0.0/16")
            or ip == ipaddress.ip_address("fd00:ec2::254"))


def _agent_check_url(url, resolve=False):
    """Validate a custom server base URL (http/https; no link-local or
    metadata addresses). Returns the normalized URL. resolve=True also
    rejects hostnames that resolve to blocked or no addresses."""
    url = str(url or "").strip().rstrip("/")
    if not url or len(url) > 300 or any(c.isspace() for c in url):
        raise ValueError("Enter the server URL, e.g. http://192.168.1.20:11434/v1")
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError("Invalid URL")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("URL must start with http:// or https:// and include a host")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("URL must not contain credentials, a query or a fragment")
    host = parts.hostname
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and _agent_ip_blocked(literal):
        raise ValueError("Link-local / metadata addresses are not allowed")
    if host.lower() in ("metadata", "metadata.google.internal"):
        raise ValueError("Metadata endpoints are not allowed")
    if literal is None:
        try:
            infos = socket.getaddrinfo(host, port or (443 if parts.scheme == "https" else 80),
                                       proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            infos = []
            if resolve:
                raise ValueError("Cannot resolve host '{}'".format(host))
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0].split("%")[0])
            except ValueError:
                continue
            if _agent_ip_blocked(ip):
                raise ValueError("Host resolves to a link-local / metadata address")
    return url


class _AgentNoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _agent_detect_models(base_url, key=""):
    """GET {baseURL}/models on an OpenAI-compatible server (5 s, no
    redirects, no proxy). Returns a list of model IDs."""
    base_url = _agent_check_url(base_url, resolve=True)
    headers = {"Accept": "application/json", "User-Agent": "TuxWall"}
    if key:
        headers["Authorization"] = "Bearer " + key
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _AgentNoRedirect)
    req = urllib.request.Request(base_url + "/models", headers=headers, method="GET")
    try:
        with opener.open(req, timeout=5) as resp:
            body = resp.read(2000001)
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308):
            raise ValueError("The server redirected (HTTP {}); enter the final URL".format(exc.code))
        if exc.code in (401, 403):
            raise ValueError("The server refused the request (HTTP {}): check the API key".format(exc.code))
        raise ValueError("The server answered HTTP {} for /models: is the URL right "
                         "(most servers need /v1 at the end)?".format(exc.code))
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise ValueError("Could not reach the server: {}".format(_agent_scrub(reason, [key])))
    if len(body) > 2000000:
        raise ValueError("Model list too large")
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        raise ValueError("The server did not return JSON for /models")
    items = data
    if isinstance(data, dict):
        items = data.get("data") or data.get("models") or []
    ids = []
    for it in items if isinstance(items, list) else []:
        mid = it if isinstance(it, str) else (
            (it.get("id") or it.get("name") or it.get("model")) if isinstance(it, dict) else None)
        mid = str(mid or "").strip()
        if AGENT_MODEL_ID_RE.match(mid) and mid not in ids:
            ids.append(mid)
    return ids[:200]


# 2026-11-03 audit: global failure cap. The per-source lockout was
# bypassable by rotating the source key - a DIRECT loopback connection
# (SSRF from the co-hosted public service, local malware) controls
# X-Real-IP, which _client_key honors for loopback peers, so every attempt
# got a fresh bucket. A global windowed cap makes rotation useless. Normal
# households never come near LOGIN_GLOBAL_MAX.
_LOGIN_FAIL_GLOBAL = []
LOGIN_GLOBAL_WINDOW = 600   # seconds
LOGIN_GLOBAL_MAX = 40       # failures across all sources within the window


def _login_lock_remaining(ip):
    now = time.time()
    while _LOGIN_FAIL_GLOBAL and now - _LOGIN_FAIL_GLOBAL[0] >= LOGIN_GLOBAL_WINDOW:
        _LOGIN_FAIL_GLOBAL.pop(0)
    if len(_LOGIN_FAIL_GLOBAL) >= LOGIN_GLOBAL_MAX:
        return int(_LOGIN_FAIL_GLOBAL[0] + LOGIN_GLOBAL_WINDOW - now) + 1
    entry = _login_fails.get(ip)
    if not entry:
        return 0
    _, locked_until = entry
    if locked_until <= now:
        return 0
    return int(locked_until - now) + 1


def _record_login_failure(ip):
    _LOGIN_FAIL_GLOBAL.append(time.time())
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
            if t.get("style"):
                theme["style"] = t["style"]
            break
    state["active_theme"] = theme or {
        "id": "dark", "name": "Dark", "dark": True,
        "colors": {k: v for k, v in BUILTIN_THEMES[0]["colors"].items()},
    }
    # The router's location only for signed-in users (attack map, settings):
    # this endpoint answers unauthenticated callers too (login page).
    if me is not None:
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


def setup_first_admin(body, ip):
    """Create the initial owner-admin when no users exist yet.

    Fail-closed: refuses (and counts against login rate limiting) when
    any user already exists. Returns a login-style result dict."""
    remaining = _login_lock_remaining(ip)
    if remaining > 0:
        raise PermissionError(
            "Too many failed attempts. Try again in {}s".format(remaining))
    if _load_users():
        _record_login_failure(ip)
        raise PermissionError("Setup already completed")
    username = str(body.get("username") or "").strip()
    if not USERNAME_RE.match(username):
        raise ValueError(
            "Invalid username (1-32 chars: letters, digits, _ . -)")
    password = validate_password_strength(body.get("password"))
    if _load_users():
        raise PermissionError("Setup already completed")
    user = _new_user(username, password, "admin", owner=True)
    _save_users([user])
    _clear_login_failures(ip)
    return {
        "ok": True,
        "username": user["username"],
        "role": "admin",
        "is_owner": True,
        "can_manage_users": True,
        "default_password": False,
        "totp_enabled": False,
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
        style = _clean_theme_style(data.get("style"))
        if style:
            entry["style"] = style
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


def _clean_theme_style(value):
    """Optional 'style' key of a custom theme: the id of a built-in theme
    whose look (surfaces, corners, fonts, effects) it inherits."""
    style = str(value or "").strip().lower()
    if style and any(t["id"] == style for t in BUILTIN_THEMES):
        return style
    return ""


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
    return {"name": name, "dark": dark, "colors": clean, "slug": slug,
            "style": _clean_theme_style(body.get("style"))}


def save_custom_theme(payload):
    if _find_builtin_theme(payload["slug"]):
        raise FileExistsError("'{}' is a built-in theme name".format(payload["name"]))
    os.makedirs(THEMES_DIR, exist_ok=True)
    path = os.path.join(THEMES_DIR, payload["slug"] + ".json")
    if os.path.exists(path):
        raise FileExistsError("A theme named '{}' already exists".format(payload["name"]))
    record = {"name": payload["name"], "dark": payload["dark"], "colors": payload["colors"]}
    if payload.get("style"):
        record["style"] = payload["style"]
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
        **({"style": payload["style"]} if payload.get("style") else {}),
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


def _dpkg_version(pkg):
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", pkg],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def _wan_info():
    """Current WAN state: default-route interface, its addresses, gateways."""
    wan = {"ifname": "", "state": "", "ipv4": "", "ipv6": [],
           "gateway4": "", "gateway6": ""}
    try:
        proc = subprocess.run(["ip", "-j", "route", "show", "default"],
                               capture_output=True, text=True, timeout=5)
        routes = json.loads(proc.stdout or "[]")
        if routes:
            wan["ifname"] = routes[0].get("dev", "")
            wan["gateway4"] = routes[0].get("gateway", "")
            wan["ipv4"] = routes[0].get("prefsrc", "")
    except Exception:
        pass
    try:
        proc = subprocess.run(["ip", "-j", "-6", "route", "show", "default"],
                               capture_output=True, text=True, timeout=5)
        routes = json.loads(proc.stdout or "[]")
        if routes:
            wan["gateway6"] = routes[0].get("gateway", "")
    except Exception:
        pass
    if wan["ifname"]:
        try:
            proc = subprocess.run(["ip", "-j", "addr", "show", "dev", wan["ifname"]],
                                  capture_output=True, text=True, timeout=5)
            ifaces = json.loads(proc.stdout or "[]")
            if ifaces:
                wan["state"] = ifaces[0].get("operstate", "")
                for a in ifaces[0].get("addr_info", []):
                    if a.get("family") == "inet6" and a.get("scope") == "global":
                        wan["ipv6"].append(a.get("local", ""))
        except Exception:
            pass
    return wan


_FASTFETCH_CACHE = {"ts": 0, "output": "", "html": ""}

FASTFETCH_BIN = shutil.which("fastfetch") or "/usr/bin/fastfetch"

_FF_SGR_RE = re.compile(r"\x1b\[([0-9;]*)m")
_FF_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# xterm palette for standard / bright foreground/background colors.
_FF_STD = {
    30: "#000000", 31: "#cd0000", 32: "#00cd00", 33: "#cdcd00",
    34: "#0000ee", 35: "#cd00cd", 36: "#00cdcd", 37: "#e5e5e5",
    90: "#7f7f7f", 91: "#ff0000", 92: "#00ff00", 93: "#ffff00",
    94: "#5c5cff", 95: "#ff00ff", 96: "#00ffff", 97: "#ffffff",
}


def _ff_256_color(n):
    """Map a 256-color palette index to a hex color."""
    n = n % 256
    if n < 8:
        return _FF_STD[30 + n]
    if n < 16:
        return _FF_STD[90 + (n - 8)]
    if 16 <= n <= 231:
        n -= 16
        r = (n // 36) % 6
        g = (n // 6) % 6
        b = n % 6
        conv = lambda v: 0 if v == 0 else 55 + v * 40
        return "#%02x%02x%02x" % (conv(r), conv(g), conv(b))
    v = 8 + (n - 232) * 10
    return "#%02x%02x%02x" % (v, v, v)


def _ff_html_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def ansi_to_html(text):
    """Convert terminal output with SGR color escapes to styled HTML.

    Only <span style="..."> tags are emitted; all text is HTML-escaped.
    Non-SGR escape sequences (cursor movement etc.) are stripped.
    """
    out = []
    fg = None
    bg = None
    bold = False
    open_span = False

    def close():
        nonlocal open_span
        if open_span:
            out.append("</span>")
            open_span = False

    def reopen():
        nonlocal open_span
        styles = []
        if fg:
            styles.append("color:" + fg)
        if bg:
            styles.append("background:" + bg)
        if bold:
            styles.append("font-weight:bold")
        if styles:
            out.append('<span style="' + ";".join(styles) + '">')
            open_span = True

    pos = 0
    for m in _FF_SGR_RE.finditer(text):
        if m.start() > pos:
            chunk = _FF_CSI_RE.sub("", text[pos:m.start()])
            out.append(_ff_html_escape(chunk))
        params = m.group(1)
        codes = [int(c) if c else 0 for c in params.split(";")] if params else [0]
        close()
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                fg, bg, bold = None, None, False
            elif c == 1:
                bold = True
            elif c == 22:
                bold = False
            elif c in _FF_STD and c < 50:
                fg = _FF_STD[c]
            elif 90 <= c <= 97:
                fg = _FF_STD[c]
            elif c == 39:
                fg = None
            elif 40 <= c <= 47:
                bg = _FF_STD.get(c - 10)
            elif 100 <= c <= 107:
                bg = _FF_STD.get(c - 10)
            elif c == 49:
                bg = None
            elif c in (38, 48):
                is_fg = c == 38
                if i + 1 < len(codes) and codes[i + 1] == 5 and i + 2 < len(codes):
                    col = _ff_256_color(codes[i + 2])
                    if is_fg:
                        fg = col
                    else:
                        bg = col
                    i += 2
                elif (i + 1 < len(codes) and codes[i + 1] == 2
                        and i + 4 < len(codes)):
                    col = "#%02x%02x%02x" % (
                        codes[i + 2] % 256, codes[i + 3] % 256, codes[i + 4] % 256)
                    if is_fg:
                        fg = col
                    else:
                        bg = col
                    i += 4
            i += 1
        reopen()
        pos = m.end()
    if pos < len(text):
        out.append(_ff_html_escape(_FF_CSI_RE.sub("", text[pos:])))
    close()
    return "".join(out)


def build_fastfetch():
    """Run fastfetch (distro logo on top, colors forced) and return its output.

    Returns both plain text ("output") and an ANSI-to-HTML conversion
    ("html") so the dashboard can render the logo in color like a terminal.
    Cached for a few seconds so the System page can poll without spawning
    a process on every request.
    """
    now = time.time()
    if _FASTFETCH_CACHE["output"] and now - _FASTFETCH_CACHE["ts"] < 10:
        return {"ok": True, "output": _FASTFETCH_CACHE["output"],
                "logo": _FASTFETCH_CACHE.get("logo", ""),
                "info": _FASTFETCH_CACHE.get("info", ""),
                "html": _FASTFETCH_CACHE["html"],
                "html_logo": _FASTFETCH_CACHE.get("html_logo", ""),
                "html_info": _FASTFETCH_CACHE.get("html_info", ""),
                "cached": True}
    if not FASTFETCH_BIN or not os.path.isfile(FASTFETCH_BIN):
        return {"ok": False, "error": "fastfetch is not installed"}
    try:
        proc = subprocess.run(
            [FASTFETCH_BIN, "--pipe", "false", "--logo-position", "top",
             "--separator", ": ", "-s",
             "Title:Separator:OS:Host:Kernel:Uptime:Packages:Shell:CPU:Memory:Swap:Disk:LocalIP:Locale"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or "fastfetch failed").strip()}
    raw = proc.stdout or ""
    # Split logo (everything before the first blank line) from the spec
    # block so the dashboard can lay them out side by side.
    logo_raw, info_raw = [], []
    seen_blank = False
    for line in raw.splitlines():
        if not _FF_CSI_RE.sub("", line).strip():
            seen_blank = True
            continue
        (info_raw if seen_blank else logo_raw).append(line.rstrip())
    # Plain-text variant: strip all escapes, drop the trailing color-palette
    # blocks (lines of only block characters).
    def _plain(lines):
        out = []
        for line in lines:
            s = _FF_CSI_RE.sub("", line).rstrip()
            if not s.strip():
                continue
            if re.fullmatch(r"[█▓▒░ ]+", s.strip()):
                continue
            out.append(s)
        return "\n".join(out).strip()

    # Colored variant: same filtering, then ANSI -> HTML per line so a
    # stray span can never leak across a dropped line.
    def _colored(lines):
        out = []
        for line in lines:
            if not _FF_CSI_RE.sub("", line).strip():
                continue
            if re.fullmatch(r"[█▓▒░ ]+",
                             _FF_CSI_RE.sub("", line).strip()):
                continue
            out.append(ansi_to_html(line.rstrip()))
        return "\n".join(out).strip()

    logo = _plain(logo_raw)
    info = _plain(info_raw)
    output = (logo + "\n\n" + info).strip()
    if not output:
        return {"ok": False, "error": "fastfetch produced no output"}
    html_logo = _colored(logo_raw)
    html_info = _colored(info_raw)
    _FASTFETCH_CACHE["ts"] = now
    _FASTFETCH_CACHE["output"] = output
    _FASTFETCH_CACHE["logo"] = logo
    _FASTFETCH_CACHE["info"] = info
    _FASTFETCH_CACHE["html"] = (html_logo + "\n\n" + html_info).strip()
    _FASTFETCH_CACHE["html_logo"] = html_logo
    _FASTFETCH_CACHE["html_info"] = html_info
    return {"ok": True, "output": output, "logo": logo, "info": info,
            "html": _FASTFETCH_CACHE["html"],
            "html_logo": html_logo, "html_info": html_info,
            "cached": False}


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
        elif parts[0] in ("MemFree:", "Buffers:", "Cached:", "SReclaimable:", "Shmem:"):
            mem[parts[0][:-1].lower()] = int(parts[1]) * 1024
    mem["used"] = mem["total"] - mem["available"]
    # Breakdown for the Overview: page cache (incl. reclaimable slab, minus
    # shared memory, as free(1) counts it), buffers, and the remainder that
    # applications actually hold.
    if "cached" in mem:
        cache = mem.get("cached", 0) + mem.get("sreclaimable", 0) - mem.get("shmem", 0)
        mem["cache"] = max(0, cache)
        mem["buffers"] = mem.get("buffers", 0)
        mem["apps"] = max(0, mem["total"] - mem.get("memfree", 0) - mem["buffers"] - mem["cache"])
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
        kea = _read_kea()
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
        "tuxwall_version": _dpkg_version("tuxwall"),
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
        "wan": _wan_info(),
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

# The dashboard-only backups (/api/backups, /create, /delete, /download,
# /restore) were never used by the UI and could overwrite /var/www/html from
# an uploaded archive. Removed in Backups phase 1 (2026-11-18): they answer
# 410 Gone. System backups live under /api/backups/system/*.
LEGACY_BACKUP_PATHS = frozenset({"/api/backups", "/api/backups/create", "/api/backups/delete",
                                 "/api/backups/download", "/api/backups/restore"})
LEGACY_BACKUP_GONE = {"ok": False, "gone": True,
                      "error": "The dashboard-only backup endpoints were removed; use the system "
                               "backups under System > Backups."}


SYSTEM_BACKUP_DIR = os.path.join(BACKUP_DIR, "system")
SYSTEM_BACKUP_RE = re.compile(r"^system-backup-\d{8}-\d{6}\.tar\.gz$")
SANITIZED_RE = re.compile(r"^sanitized-\d{8}-\d{6}\.tar\.gz$")
UPLOADED_RE = re.compile(r"^uploaded-\d{8}-\d{6}\.tar\.gz$")

# Catalog, retention, job state, sanitizer and restore live in
# includes/backups.py (tested by tools/backup_safety_check.py); this file
# keeps the in-memory progress of the dashboard-started run and the routes.
_system_backup_job = {"running": False, "pct": 0, "step": "", "result": None, "error": None}
_system_backup_lock = threading.Lock()


def _bk_required():
    if _bk is None:
        raise RuntimeError("Backup module unavailable (includes/backups.py failed to import)")


def system_backup_items():
    _bk_required()
    return {"ok": True, "items": _bk.items_listing()}


def _backup_incident_refresh():
    """Open/clear backup:failed right away instead of at the next tick."""
    def run():
        try:
            run_incident_check()
        except Exception as exc:
            print("[backup] incident refresh failed: %r" % exc, flush=True)
    threading.Thread(target=run, daemon=True).start()


def _system_backup_worker(include, who, trigger="manual"):
    """Run one backup (in this thread) with progress in _system_backup_job.
    Returns the finished run record, or None when another job held the lock."""
    def progress(pct, step):
        with _system_backup_lock:
            _system_backup_job["pct"] = pct
            _system_backup_job["step"] = step
    result = error = run = None
    try:
        run = _bk.run_job(include=include, who=who, trigger=trigger, on_progress=progress)
        if run.get("ok"):
            result = run.get("result")
        else:
            error = run.get("error") or "Backup failed"
    except _bk.Refused as exc:
        error = exc.payload.get("error") or str(exc)
    except Exception as exc:
        error = str(exc) or exc.__class__.__name__
        try:
            run = _bk.record_failure("", trigger, error, who=who)   # still raises backup:failed
        except Exception as rexc:
            print("[backup] could not record the failure: %r" % rexc, flush=True)
    with _system_backup_lock:
        _system_backup_job.update({"running": False, "result": result, "error": error,
                                   "pct": 100 if error else _system_backup_job["pct"]})
    print("[backup] %s system backup by %s: %s" % (trigger, who or "?", result or ("FAILED: %s" % error)), flush=True)
    _backup_incident_refresh()
    return run


def create_system_backup(include=None, who=""):
    _bk_required()
    if include is not None:
        if not isinstance(include, list) or not include:
            raise ValueError("Invalid include list")
        unknown = [a for a in include if a not in _bk.ITEM_BY_ARC]
        if unknown:
            raise ValueError("Unknown config item(s): %s" % ", ".join(str(a) for a in unknown[:3]))
    with _system_backup_lock:
        if _system_backup_job["running"] or _bk.job_is_locked():
            raise ValueError("A system backup is already running")
        _system_backup_job.update({"pct": 0, "step": "Starting", "result": None, "error": None, "running": True})
    threading.Thread(target=_system_backup_worker, args=(include, who), daemon=True).start()
    return {"ok": True, "running": True}


# --- Scheduled backups --------------------------------------------------------
# A thread in this API (not a systemd timer): the schedule is owner-edited
# here and takes effect at once, the run shares the job lock and the live
# progress with the "Create" button, and failures go through the same
# state file -> backup:failed incident -> ntfy path. Missed slots (router
# off at the scheduled time) run once soon after start; see backups.due_slot.
BACKUP_SCHED_START_DELAY = 90
BACKUP_SCHED_TICK = 30


def _backup_scheduled_run(slot):
    with _system_backup_lock:
        if _system_backup_job["running"] or _bk.job_is_locked():
            return False                       # a manual run or USB copy: retry next tick
        _system_backup_job.update({"pct": 0, "step": "Scheduled backup", "result": None, "error": None,
                                   "running": True})
    run = _system_backup_worker(None, "scheduler", trigger="scheduled")
    if run is None:
        with _system_backup_lock:
            _system_backup_job["error"] = None
        return False
    _bk.mark_slot("", slot, run)
    if run.get("ok") and _bk.load_settings()["usb_after"]:
        try:
            dev, err = _bk.usb_detect()
            if dev or err:
                res = _bk.usb_copy(who="scheduler", trigger="scheduled")
                print("[backup] scheduled USB copy: %s%s" % (res.get("file"), " (already there)" if res.get("skipped") else ""),
                      flush=True)
            else:
                print("[backup] scheduled USB copy skipped: no %s stick attached" % _bk.USB_LABEL, flush=True)
        except _bk.Refused as exc:
            print("[backup] scheduled USB copy FAILED: %s" % exc.payload.get("error"), flush=True)
        except Exception as exc:
            print("[backup] scheduled USB copy FAILED: %r" % exc, flush=True)
        _usb_status_cache["t"] = 0
        _backup_incident_refresh()
    return True


def _backup_scheduler_loop():
    time.sleep(BACKUP_SCHED_START_DELAY)
    try:
        err = _bk.usb_cleanup()
        if err:
            print("[backup] %s" % err, flush=True)
    except Exception as exc:
        print("[backup] USB cleanup failed: %r" % exc, flush=True)
    while True:
        try:
            slot = _bk.schedule_due("")
            if slot is not None:
                print("[backup] scheduled backup due (slot %s)" % time.strftime("%Y-%m-%d %H:%M", time.localtime(slot)),
                      flush=True)
                _backup_scheduled_run(slot)
        except Exception as exc:
            print("[backup] scheduler error: %r" % exc, flush=True)
        time.sleep(BACKUP_SCHED_TICK)


def start_backup_scheduler():
    if _bk is None:
        return
    threading.Thread(target=_backup_scheduler_loop, name="backup-scheduler", daemon=True).start()


_usb_status_cache = {"t": 0, "data": None}
_usb_status_lock = threading.Lock()


def _usb_status(force=False):
    with _usb_status_lock:
        if force or not _usb_status_cache["data"] or time.time() - _usb_status_cache["t"] > 10:
            try:
                _usb_status_cache["data"] = _bk.usb_status()
            except Exception as exc:
                _usb_status_cache["data"] = {"present": False, "error": "USB detection failed: %s" % exc,
                                             "label": _bk.USB_LABEL}
            _usb_status_cache["t"] = time.time()
        return dict(_usb_status_cache["data"])


def _public_run(run):
    if not run:
        return None
    keep = ("id", "started", "finished", "running", "ok", "trigger", "who", "result", "error",
            "stderr_tail", "size", "pruned", "integrity")
    out = {k: run.get(k) for k in keep if k in run}
    items = run.get("items")
    out["items"] = items if items == "all" else len(items or [])
    return out


def system_backup_status():
    with _system_backup_lock:
        job = dict(_system_backup_job)
    st = {}
    failed = None
    extra = {}
    if _bk is not None:
        try:
            st = _bk.load_state() if job["running"] else _bk.reconcile_interrupted()
            failed = _bk.failure_incident()
        except Exception as exc:
            print("[backup] state read failed: %r" % exc, flush=True)
        try:
            settings = _bk.load_settings()
            extra = {"stale_days": settings["stale_days"], "usb_after": settings["usb_after"],
                     "schedule": _bk.schedule_info(), "encryption": _bk.encryption_info(),
                     "usb": _usb_status()}
        except Exception as exc:
            print("[backup] settings read failed: %r" % exc, flush=True)
    out = {
        "ok": True,
        "running": job["running"],
        "pct": job["pct"],
        "step": job["step"],
        "result": job["result"],
        "error": job["error"],
        "backups": list_system_backups().get("backups", []),
        "others": list_other_archives(),
        "last_run": _public_run(st.get("last_run")),
        "last_success": _public_run(st.get("last_success")),
        "last_failure": _public_run(st.get("last_failure")),
        "failed": bool(failed),
        "pinned": st.get("pinned") or [],
        "retention": dict(_bk.RETENTION) if _bk else {},
        "stale_days": 8,
    }
    out.update(extra)
    return out


def list_system_backups():
    if _bk is None:
        return {"ok": False, "error": "Backup module unavailable", "backups": []}
    return {"ok": True, "backups": _bk.list_archives()}


def list_other_archives():
    """Sanitized exports and uploads, read-only, for the unified Backups list."""
    if _bk is None:
        return []
    try:
        return _bk.list_archives(regex=_bk.SANITIZED_RE) + _bk.list_archives(regex=_bk.UPLOADED_RE)
    except Exception as exc:
        print("[backup] listing exports/uploads failed: %r" % exc, flush=True)
        return []


def delete_system_backup(filename, who="", client=""):
    base = os.path.basename(filename or "")
    if not (SYSTEM_BACKUP_RE.match(base) or SANITIZED_RE.match(base) or UPLOADED_RE.match(base)):
        raise ValueError("Invalid system backup name")
    path = os.path.join(SYSTEM_BACKUP_DIR, base)
    if not os.path.isfile(path):
        raise FileNotFoundError("Backup not found")
    os.remove(path)
    if _bk is not None:
        try:
            _bk.forget_archive("", base)
            if base in (_bk.load_state().get("pinned") or []):
                _bk.set_pinned("", base, False, who=who)
            _bk.audit("", "delete", who=who, client=client, archive=base)
        except Exception:
            pass
    return {"ok": True, "deleted": base}


# --- SQM / traffic shaping (CAKE on WAN + IFB) -------------------------------
SQM_CONF = "/etc/tuxwall/sqm.conf"
SQM_SCRIPT = "/usr/local/sbin/tuxwall-sqm.sh"
SQM_DEFAULTS = {"wan": "", "ifb": "ifb4wan", "up_mbit": 285, "down_mbit": 1850}


def _sqm_wan():
    if not SQM_DEFAULTS["wan"]:
        SQM_DEFAULTS["wan"] = _detect_wan_iface() or "enp5s0"
    return SQM_DEFAULTS["wan"]
# Ookla speedtest is NOT in the Ubuntu archives, its packagecloud repo ends
# at jammy (404 on noble+), and the snap is an unofficial wrapper — so
# postinst auto-installs the official tarball. The guided test
# degrades to a clear error when it is absent.
SQM_SPEEDTEST_HINT = ("speedtest binary not found — install it for guided "
                      "tests: `sudo bash /var/www/html/scripts/install-speedtest.sh` "
                      "(official Ookla tarball; snap also works)")


def sqm_speedtest_available():
    return shutil.which("speedtest") is not None


def load_sqm_conf():
    conf = dict(SQM_DEFAULTS)
    try:
        with open(SQM_CONF, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip().lower(), v.strip().strip('"')
                if k in ("wan", "ifb"):
                    if re.match(r"^[a-zA-Z0-9_.-]{1,16}$", v):
                        conf[k] = v
                elif k in ("up_mbit", "down_mbit", "up_rate", "down_rate"):
                    m = re.match(r"^(\d+)", v)
                    if m:
                        key = "up_mbit" if k.startswith("up") else "down_mbit"
                        conf[key] = max(1, min(10000, int(m.group(1))))
    except OSError:
        pass
    return conf


def save_sqm_conf(conf):
    os.makedirs(os.path.dirname(SQM_CONF), exist_ok=True)
    tmp = SQM_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write("# TuxWall SQM rates (Mbit). Managed by dashboard System > Traffic Shaping.\n")
        f.write("WAN=%s\n" % conf.get("wan", SQM_DEFAULTS["wan"]))
        f.write("UP_RATE=%dmbit\n" % int(conf["up_mbit"]))
        f.write("DOWN_RATE=%dmbit\n" % int(conf["down_mbit"]))
    os.replace(tmp, SQM_CONF)
    os.chmod(SQM_CONF, 0o644)


def _tc_qdisc_show():
    try:
        proc = subprocess.run(["tc", "-s", "qdisc", "show"],
                              capture_output=True, text=True, timeout=10)
        return proc.stdout if proc.returncode == 0 else ""
    except Exception:
        return ""


def sqm_status():
    conf = load_sqm_conf()
    tc = _tc_qdisc_show()
    wan = conf["wan"]
    ifb = conf.get("ifb", SQM_DEFAULTS["ifb"])
    # Active if a cake root qdisc is present on WAN and IFB.
    wan_cake = bool(re.search(r"qdisc cake \S+: dev %s root" % re.escape(wan), tc))
    ifb_cake = bool(re.search(r"qdisc cake \S+: dev %s root" % re.escape(ifb), tc))
    drops = {"up_drops": None, "down_drops": None, "down_overlimits": None}
    m = re.search(r"qdisc cake \S+: dev %s root.*?Sent \S+ bytes \S+ pkt \(dropped (\d+)"
                  % re.escape(wan), tc, re.S)
    if m:
        drops["up_drops"] = int(m.group(1))
    m = re.search(r"qdisc cake \S+: dev %s root.*?Sent \S+ bytes \S+ pkt \(dropped (\d+), overlimits (\d+)"
                  % re.escape(ifb), tc, re.S)
    if m:
        drops["down_drops"] = int(m.group(1))
        drops["down_overlimits"] = int(m.group(2))
    return {"ok": True, "wan": wan, "ifb": ifb,
            "up_mbit": conf["up_mbit"], "down_mbit": conf["down_mbit"],
            "active": bool(wan_cake and ifb_cake),
            "wan_shaped": wan_cake, "ifb_shaped": ifb_cake,
            "speedtest_available": sqm_speedtest_available(),
            "speedtest_hint": "" if sqm_speedtest_available() else SQM_SPEEDTEST_HINT,
            **drops}


def sqm_apply(up_mbit, down_mbit, wan=None):
    try:
        up = int(up_mbit)
        down = int(down_mbit)
    except (TypeError, ValueError):
        raise ValueError("Rates must be numbers (Mbit)")
    if not 1 <= up <= 10000:
        raise ValueError("Upload rate must be between 1 and 10000 Mbit")
    if not 1 <= down <= 10000:
        raise ValueError("Download rate must be between 1 and 10000 Mbit")
    conf = load_sqm_conf()
    if wan:
        if not re.match(r"^[a-zA-Z0-9_.-]{1,16}$", wan):
            raise ValueError("Invalid WAN interface")
        conf["wan"] = wan
    conf["up_mbit"] = up
    conf["down_mbit"] = down
    save_sqm_conf(conf)
    if not os.path.isfile(SQM_SCRIPT):
        raise FileNotFoundError("SQM script missing (%s)" % SQM_SCRIPT)
    proc = subprocess.run(["bash", SQM_SCRIPT], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "SQM script failed").strip()[-500:])
    return {"ok": True, **sqm_status(), "applied_output": (proc.stdout or "").strip()[-500:]}


def sqm_suggest(measured_down, measured_up, cfg_down=None, cfg_up=None):
    """Suggested shaping rates (~93% of measured) + mismatch warnings."""
    out = {}
    for label, meas in (("down", measured_down), ("up", measured_up)):
        if meas and meas > 0:
            out[label + "_suggested"] = max(1, int(meas * 0.93))
        else:
            out[label + "_suggested"] = None
    warnings = []
    try:
        if measured_down and cfg_down:
            if measured_down < 0.7 * cfg_down:
                warnings.append(
                    "Measured download (%d Mbps) is far below the configured cap (%d Mbps) — "
                    "the ISP may have provisioned a slower tier (or the line is congested). "
                    "Consider shaping to ~%d Mbps."
                    % (int(measured_down), int(cfg_down), out["down_suggested"] or 0))
            elif measured_down > cfg_down * 1.05:
                warnings.append(
                    "Measured download (%d Mbps) exceeds the configured cap (%d Mbps) — "
                    "shaping is throttling you. Raise the cap to ~%d Mbps."
                    % (int(measured_down), int(cfg_down), out["down_suggested"] or 0))
        if measured_up and cfg_up:
            if measured_up < 0.7 * cfg_up:
                warnings.append(
                    "Measured upload (%d Mbps) is far below the configured cap (%d Mbps)."
                    % (int(measured_up), int(cfg_up)))
            elif measured_up > cfg_up * 1.05:
                warnings.append(
                    "Measured upload (%d Mbps) exceeds the configured cap (%d Mbps) — "
                    "raise it to ~%d Mbps."
                    % (int(measured_up), int(cfg_up), out["up_suggested"] or 0))
    except (TypeError, ValueError):
        pass
    out["warnings"] = warnings
    return out


_sqm_test_job = {"running": False, "stage": "", "result": None, "error": None}
_sqm_test_lock = threading.Lock()


def _sqm_test_worker():
    try:
        if not sqm_speedtest_available():
            raise RuntimeError(SQM_SPEEDTEST_HINT)
        conf = load_sqm_conf()
        wan, ifb = conf["wan"], conf.get("ifb", SQM_DEFAULTS["ifb"])
        with _sqm_test_lock:
            _sqm_test_job["stage"] = "Removing shaping for clean measurement"
        # Best-effort removal; ignore failures (already unshaped).
        subprocess.run(["tc", "qdisc", "del", "dev", wan, "root"],
                       capture_output=True, timeout=15)
        subprocess.run(["tc", "qdisc", "del", "dev", wan, "ingress"],
                       capture_output=True, timeout=15)
        subprocess.run(["tc", "qdisc", "del", "dev", ifb, "root"],
                       capture_output=True, timeout=15)
        with _sqm_test_lock:
            _sqm_test_job["stage"] = "Running speedtest (this takes ~30-60s)"
        # Ookla speedtest aborts with std::logic_error (basic_string null)
        # when HOME is unset, as under systemd — always provide one.
        _st_env = dict(os.environ)
        _st_env.setdefault("HOME", "/root")
        proc = subprocess.run(
            ["speedtest", "--accept-license", "--accept-gdpr", "-f", "json"],
            capture_output=True, text=True, timeout=180, env=_st_env)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or "speedtest failed").strip()[-300:])
        data = json.loads(proc.stdout or "{}")
        # Ookla CLI schema: top-level "download"/"upload" objects, each with
        # "bandwidth" in bytes/sec; "ping" has latency/jitter in ms.
        dl = (data.get("download") or {}).get("bandwidth")
        ul = (data.get("upload") or {}).get("bandwidth")
        down_mbps = round(dl * 8 / 1e6, 1) if dl else None
        up_mbps = round(ul * 8 / 1e6, 1) if ul else None
        ping = data.get("ping") or {}
        result = {
            "down_mbps": down_mbps, "up_mbps": up_mbps,
            "idle_ms": ping.get("latency"), "jitter_ms": ping.get("jitter"),
            "packet_loss": data.get("packetLoss"),
            "server": (data.get("server") or {}).get("name"),
            "isp": (data.get("isp") or {}),
            "result_url": (data.get("result") or {}).get("url"),
            "suggestion": sqm_suggest(down_mbps, up_mbps, conf["down_mbit"], conf["up_mbit"]),
            "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        with _sqm_test_lock:
            _sqm_test_job["stage"] = "Restoring shaping"
            _sqm_test_job["result"] = result
        proc = subprocess.run(["bash", SQM_SCRIPT], capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            with _sqm_test_lock:
                _sqm_test_job["error"] = "Speedtest OK, but shaping restore FAILED: %s. Re-run: sudo %s" % (
                    (proc.stderr or proc.stdout or "").strip()[-200:], SQM_SCRIPT)
    except Exception as exc:
        try:
            subprocess.run(["bash", SQM_SCRIPT], capture_output=True, timeout=60)
        except Exception:
            pass
        with _sqm_test_lock:
            _sqm_test_job["error"] = str(exc)
    finally:
        with _sqm_test_lock:
            _sqm_test_job["running"] = False
            if not _sqm_test_job["error"]:
                _sqm_test_job["stage"] = "Done"


def sqm_speedtest_start():
    with _sqm_test_lock:
        if _sqm_test_job["running"]:
            raise ValueError("A speedtest is already running")
        _sqm_test_job.update({"running": True, "stage": "Starting", "result": None, "error": None})
    threading.Thread(target=_sqm_test_worker, daemon=True).start()
    return {"ok": True, "running": True}


def sqm_speedtest_status():
    with _sqm_test_lock:
        return {"ok": True, "running": _sqm_test_job["running"],
                "stage": _sqm_test_job["stage"],
                "result": _sqm_test_job["result"],
                "error": _sqm_test_job["error"]}


def _system_backup_path(filename, sanitized=False):
    base = os.path.basename(filename or "")
    if not (SYSTEM_BACKUP_RE.match(base) or UPLOADED_RE.match(base) or
            (sanitized and SANITIZED_RE.match(base))):
        raise ValueError("Invalid system backup name")
    path = os.path.join(SYSTEM_BACKUP_DIR, base)
    if not os.path.isfile(path):
        raise ValueError("System backup not found")
    return base, path


def upload_system_backup(raw, who="", passphrase=None):
    """Validate (gzip, member-count and decompressed-size limits, no unsafe
    members, SHA256SUMS) and store an uploaded system backup (root-only).
    Encrypted (.gpg) uploads are decrypted with the given or stored passphrase."""
    _bk_required()
    res = _bk.store_upload("", raw, who=who, passphrase=passphrase or None)
    try:
        res["services"] = _bk.services_in(res.get("files") or [])
    except Exception:
        pass
    return res


def system_backup_contents(filename):
    _bk_required()
    base, path = _system_backup_path(filename)
    _bk.check_archive(path, strict=bool(UPLOADED_RE.match(base)))
    integ = _bk.check_integrity("", base, path)
    files = _bk.contents(path)
    return {"ok": True, "backup": base, "files": files, "services": _bk.services_in(files),
            "integrity": integ["status"], "integrity_summary": _bk.integrity_summary(integ)}


def download_system_backup_member(filename, member):
    """(member name, bytes) - read in memory with a size cap, no temp file."""
    _bk_required()
    base, path = _system_backup_path(filename)
    name, _m, data = _bk.read_member(path, member, limit=_bk.DOWNLOAD_MEMBER_MAX)
    return name, data


def preview_system_restore(filename, member):
    _bk_required()
    base, path = _system_backup_path(filename)
    _bk.check_archive(path, strict=bool(UPLOADED_RE.match(base)))
    _bk.require_intact("", base, path)
    return _bk.restore_preview("", path, base, member)


def restore_system_backup_member(filename, member, who="", client="", confirm_strict=False,
                                 expect_new=None, expect_old=None):
    """Single-file restore through backups.restore_apply: needs the preview
    hashes, a second confirm for strict paths, writes atomically with safe
    permissions, keeps a pre-restore copy and audits. Firewall files are
    refused here (import them as a firewall snapshot instead). Services are
    never restarted automatically."""
    _bk_required()
    base, path = _system_backup_path(filename)
    _bk.require_intact("", base, path)
    res = _bk.restore_apply("", path, base, member, who=who, client=client,
                            confirm_strict=confirm_strict, expect_new=expect_new, expect_old=expect_old)
    res["units"] = _bk.unit_plan([res.get("restart_required")])
    print("[backup] RESTORE-FILE /%s from %s by %s (pre-restore copy: %s)"
          % (res["restored"], base, who or "?", res.get("pre_restore") or "none, new file"), flush=True)
    return res


def preview_system_restore_many(filename, files=None, service=None):
    _bk_required()
    base, path = _system_backup_path(filename)
    _bk.check_archive(path, strict=bool(UPLOADED_RE.match(base)))
    _bk.require_intact("", base, path)
    if service is not None and not isinstance(service, str):
        raise ValueError("Invalid service")
    return _bk.restore_preview_many("", path, base, members=files, service=service or None)


def restore_system_backup_many(filename, files, who="", client="", confirm_strict=False):
    """Several files in one apply (see backups.restore_apply_many): all
    hashes checked first, one pre-restore folder, atomic per file, rollback
    of the written files if one fails. Never restarts anything."""
    _bk_required()
    base, path = _system_backup_path(filename)
    _bk.require_intact("", base, path)
    res = _bk.restore_apply_many("", path, base, files, who=who, client=client, confirm_strict=confirm_strict)
    print("[backup] RESTORE-FILES %d file(s) from %s by %s (pre-restore copies: %s)"
          % (len(res["restored"]), base, who or "?", res.get("pre_restore") or "none, new files"), flush=True)
    return res


def _defer_self_reload(cmd):
    def run():
        time.sleep(1.5)
        try:
            subprocess.run(cmd, capture_output=True, timeout=60)
        except Exception as exc:
            print("[backup] deferred %s failed: %r" % (" ".join(cmd), exc), flush=True)
    threading.Thread(target=run, daemon=True).start()


def backup_service_action(unit, confirm_critical=False, who="", client=""):
    _bk_required()
    res = _bk.run_unit_action("", unit, confirm_critical=confirm_critical, who=who, client=client,
                              defer=_defer_self_reload)
    print("[backup] SERVICE-ACTION %s %s by %s" % (res.get("action"), unit, who or "?"), flush=True)
    return res


def verify_system_backup(filename):
    _bk_required()
    base, path = _system_backup_path(filename, sanitized=True)
    res = _bk.check_integrity("", base, path, force=True)
    return {"ok": True, "name": base, "integrity": res["status"], "summary": _bk.integrity_summary(res),
            "sha256": res.get("sha256"), "files": res.get("files")}


def import_system_backup_firewall(filename, identity=None, client_ip=""):
    """Turn the firewall files of a system backup (etc/ufw rules, defaults,
    iptables dumps) into an uploaded firewall snapshot. Nothing is applied:
    restore happens in Firewall > Settings > Snapshots (preview, guard,
    automatic snapshot first, 60 s confirm-or-revert)."""
    _bk_required()
    if _fw_snap is None:
        raise RuntimeError("Firewall snapshot module unavailable")
    who = (identity or {}).get("username", "")
    base, path = _system_backup_path(filename)
    _bk.require_intact("", base, path)
    files, raw, notes = _bk.firewall_snapshot_files("", path)
    ufw = {k: files.get(k, "") for k in _fw_snap.UFW_FILES}
    errs = _fw_snap.validate_files({k: v for k, v in ufw.items() if v})
    if errs:
        raise _bk.Refused(409, {"ok": False, "error": "The firewall files in this backup failed validation: "
                                + "; ".join(errs[:3])})
    m = _fw_snap.create(_fw_ctx(client_ip), note="From system backup %s" % base, kind="upload", who=who,
                        version=TUXWALL_VERSION, files=ufw, raw=raw)
    _bk.audit("", "firewall-import", who=who, client=client_ip, archive=base, snapshot=m.get("id"))
    print("[backup] FW-IMPORT %s -> firewall snapshot %s by %s" % (base, m.get("id"), who or "?"), flush=True)
    return {"ok": True, "id": m.get("id"), "snapshot": m, "notes": notes,
            "message": "Imported as firewall snapshot %s. Preview and restore it in Firewall > Settings > "
                       "Snapshots (guard check, 60 s confirm-or-revert)." % m.get("id")}


def sanitize_system_backup(filename, who=""):
    """Shareable copy with secrets removed; refuses to write an export that
    fails its own secret re-scan."""
    _bk_required()
    base, path = _system_backup_path(filename)
    _bk.check_archive(path, strict=bool(UPLOADED_RE.match(base)))
    return dict(_bk.sanitize_to_dir("", path, base, who=who), ok=True)


def backup_settings_save(body, who=""):
    _bk_required()
    patch = {k: body[k] for k in ("schedule", "usb_after", "stale_days") if k in body}
    if not patch:
        raise ValueError("Nothing to save")
    _bk.save_settings("", patch, who=who)
    _backup_incident_refresh()
    st = system_backup_status()
    return {"ok": True, "schedule": st.get("schedule"), "usb_after": st.get("usb_after"),
            "stale_days": st.get("stale_days")}


def backup_encryption_save(body, who=""):
    _bk_required()
    action = body.get("action")
    if action == "set":
        info = _bk.set_passphrase("", body.get("passphrase"), who=who)
    elif action == "remove":
        info = _bk.clear_passphrase("", who=who)
    else:
        raise ValueError("Unknown action")
    print("[backup] encryption passphrase %s by %s" % ("set" if action == "set" else "removed", who or "?"),
          flush=True)
    return {"ok": True, "encryption": info}


def backup_usb_copy(body, who=""):
    _bk_required()
    name = body.get("name") or None
    if name is not None and not SYSTEM_BACKUP_RE.match(os.path.basename(name)):
        raise ValueError("Only system backups are copied to the stick")
    with _system_backup_lock:
        if _system_backup_job["running"]:
            raise _bk.Refused(409, {"ok": False, "error": "A system backup is running; copy when it has finished"})
    try:
        res = _bk.usb_copy(name=os.path.basename(name) if name else None, who=who, trigger="manual")
    finally:
        _usb_status_cache["t"] = 0
    print("[backup] USB-COPY %s by %s (%s)" % (res.get("file"), who or "?",
                                              "already there" if res.get("skipped") else "copied, verified"), flush=True)
    return res


def backup_usb_check():
    _bk_required()
    try:
        return _bk.usb_check()
    finally:
        _usb_status_cache["t"] = 0


UNBOUND_ROUTER_CONF = "/etc/unbound/unbound.conf.d/router-dns.conf"


def _kea_single_subnet():
    """Return (kea_data, d4, subnet); only single-subnet setups are
    form-editable — anything else must use the raw editor."""
    kea = _read_kea()
    d4 = kea.get("Dhcp4", {})
    subnets = d4.get("subnet4", [])
    if len(subnets) != 1:
        raise ValueError(
            "Form editing covers a single subnet (found %d) — "
            "use the raw file editor." % len(subnets))
    return kea, d4, subnets[0]


def _kea_opt(subnet, d4, name):
    for o in subnet.get("option-data", []):
        if o.get("name") == name:
            return o.get("data", "")
    for o in d4.get("option-data", []):
        if o.get("name") == name:
            return o.get("data", "")
    return ""


def _kea_set_opt(subnet, name, data):
    for o in subnet.setdefault("option-data", []):
        if o.get("name") == name:
            o["data"] = data
            return
    subnet["option-data"].append({"name": name, "data": data})


def get_dhcp_form():
    kea, d4, subnet = _kea_single_subnet()
    pools = subnet.get("pools", [])
    if len(pools) != 1 or "-" not in str(pools[0].get("pool", "")):
        raise ValueError(
            "Form editing covers a single START-END pool — "
            "use the raw file editor.")
    start, end = [p.strip() for p in
                  str(pools[0]["pool"]).split("-", 1)]
    lifetime = subnet.get("valid-lifetime", d4.get("valid-lifetime", ""))
    return {
        "ok": True,
        "subnet": subnet.get("subnet", ""),
        "pool_start": start,
        "pool_end": end,
        "router": _kea_opt(subnet, d4, "routers"),
        "dns": _kea_opt(subnet, d4, "domain-name-servers"),
        "domain": _kea_opt(subnet, d4, "domain-name"),
        "valid_lifetime": str(lifetime),
        "reservations": len(subnet.get("reservations", [])),
    }


def save_dhcp_form(body):
    kea, d4, subnet = _kea_single_subnet()
    pools = subnet.get("pools", [])
    if len(pools) != 1:
        raise ValueError("Expected a single pool — use the raw file editor.")

    try:
        net = ipaddress.IPv4Network((body.get("subnet") or "").strip(),
                                    strict=False)
    except ValueError:
        raise ValueError("Invalid subnet CIDR (e.g. 192.168.1.0/24)")
    try:
        start = ipaddress.IPv4Address((body.get("pool_start") or "").strip())
        end = ipaddress.IPv4Address((body.get("pool_end") or "").strip())
    except ValueError:
        raise ValueError("Pool start/end must be IPv4 addresses")
    if start not in net or end not in net:
        raise ValueError("Pool must lie inside the subnet")
    if int(start) > int(end):
        raise ValueError("Pool start must not exceed pool end")
    try:
        router = ipaddress.IPv4Address((body.get("router") or "").strip())
    except ValueError:
        raise ValueError("Invalid router IP address")
    if router not in net:
        raise ValueError("Router must lie inside the subnet")
    dns_list = [d.strip() for d in
                str(body.get("dns") or "").replace(",", " ").split()]
    if not dns_list:
        raise ValueError("At least one DNS server is required")
    for d in dns_list:
        try:
            ipaddress.ip_address(d)
        except ValueError:
            raise ValueError("Invalid DNS server address: %s" % d)
    domain = (body.get("domain") or "").strip()
    if domain and not HOSTNAME_RE.match(domain):
        raise ValueError("Invalid domain name")
    lifetime_raw = str(body.get("valid_lifetime") or "").strip()
    try:
        lifetime = int(lifetime_raw)
    except ValueError:
        raise ValueError("Lease time must be a number of seconds")
    if not 60 <= lifetime <= 31536000:
        raise ValueError("Lease time must be 60..31536000 seconds")

    subnet["subnet"] = str(net)
    pools[0]["pool"] = "%s-%s" % (start, end)
    _kea_set_opt(subnet, "routers", str(router))
    _kea_set_opt(subnet, "domain-name-servers", ", ".join(dns_list))
    if domain:
        _kea_set_opt(subnet, "domain-name", domain)
    else:
        subnet["option-data"] = [o for o in subnet.get("option-data", [])
                                 if o.get("name") != "domain-name"]
    if "valid-lifetime" in subnet:
        subnet["valid-lifetime"] = lifetime
    elif "valid-lifetime" in d4:
        d4["valid-lifetime"] = lifetime
    else:
        subnet["valid-lifetime"] = lifetime

    warnings = []
    for r in subnet.get("reservations", []):
        try:
            rip = ipaddress.IPv4Address(r.get("ip-address", ""))
        except ValueError:
            continue
        if rip not in net:
            warnings.append(
                "Reservation %s is outside the new subnet" % rip)

    bak = KEA_CONF + ".bak-" + time.strftime("%Y%m%d%H%M%S")
    shutil.copy2(KEA_CONF, bak)
    _write_kea(kea)
    try:
        _reload_kea()
    except Exception as exc:
        shutil.copy2(bak, KEA_CONF)
        try:
            _reload_kea()
        except Exception:
            pass
        raise RuntimeError("Kea rejected the config, restored backup: %s"
                           % exc)
    out = get_dhcp_form()
    out["backup"] = bak
    out["warnings"] = warnings
    return out


def _iface_ipv4_addrs():
    """Map interface name -> list of IPv4Network its addresses belong to."""
    out = {}
    try:
        proc = subprocess.run(["ip", "-j", "addr"], capture_output=True,
                              text=True, timeout=5)
        for iface in json.loads(proc.stdout or "[]"):
            name = iface.get("ifname", "")
            nets = []
            for a in iface.get("addr_info", []):
                if a.get("family") != "inet":
                    continue
                try:
                    nets.append(ipaddress.IPv4Interface(
                        "%s/%s" % (a.get("local"), a.get("prefixlen"))).network)
                except ValueError:
                    continue
            out[name] = nets
    except Exception:
        pass
    return out


def _wan_ifname():
    topo = _topo("wan_device")
    if topo:
        return topo
    try:
        proc = subprocess.run(["ip", "-j", "route", "show", "default"],
                              capture_output=True, text=True, timeout=5)
        routes = json.loads(proc.stdout or "[]")
        if routes:
            return routes[0].get("dev", "")
    except Exception:
        pass
    return ""


def list_dhcp_subnets():
    """All Kea subnet4 entries with pool/option summary + live interface match."""
    kea = _read_kea()
    d4 = kea.get("Dhcp4", {})
    ifaces = _iface_ipv4_addrs()
    wan = _wan_ifname()
    subnets = []
    for idx, subnet in enumerate(d4.get("subnet4", [])):
        try:
            net = ipaddress.IPv4Network(subnet.get("subnet", ""), strict=False)
            net_s = str(net)
        except ValueError:
            net, net_s = None, subnet.get("subnet", "")
        bound = subnet.get("interface", "")
        serving = [n for n, nets in ifaces.items()
                   if net and any(x == net for x in nets)]
        pools = []
        for p in subnet.get("pools", []):
            pools.append(p.get("pool", "") if isinstance(p, dict) else str(p))
        subnets.append({
            "key": idx,
            "id": subnet.get("id"),
            "subnet": net_s,
            "interface": bound,
            "serving_ifaces": serving,
            "pools": pools,
            "router": _kea_opt(subnet, d4, "routers"),
            "dns": _kea_opt(subnet, d4, "domain-name-servers"),
            "domain": _kea_opt(subnet, d4, "domain-name"),
            "lease_time": str(subnet.get("valid-lifetime",
                                         d4.get("valid-lifetime", ""))),
            "reservations": len(subnet.get("reservations", [])),
        })
    candidates = [{"name": n, "nets": [str(x) for x in nets],
                   "is_wan": n == wan}
                  for n, nets in sorted(ifaces.items())
                  if n != "lo" and nets]
    return {"ok": True, "subnets": subnets, "interfaces": candidates,
            "wan": wan}


def save_dhcp_subnet(body):
    """Create or update one Kea subnet4 bound to an interface.

    body: {key?, interface, subnet, pool_start, pool_end, router, dns,
           domain?, lease_time?}. Backup + reload with rollback on failure.
    """
    kea = _read_kea()
    d4 = kea.get("Dhcp4", {})
    subnets = d4.setdefault("subnet4", [])
    raw_key = body.get("key")
    if raw_key in (None, ""):
        target = None
    else:
        try:
            target = subnets[int(raw_key)]
        except (ValueError, IndexError):
            raise ValueError("Unknown subnet")
    iface = (body.get("interface") or "").strip()
    if not re.match(r"^[a-zA-Z0-9_.-]{1,16}$", iface):
        raise ValueError("Invalid interface name")
    ifaces = _iface_ipv4_addrs()
    if iface not in ifaces:
        raise ValueError("Interface %s not found" % iface)
    try:
        net = ipaddress.IPv4Network((body.get("subnet") or "").strip(),
                                    strict=False)
    except ValueError:
        raise ValueError("Invalid subnet CIDR (e.g. 192.168.10.0/24)")
    if not any(x == net for x in ifaces[iface]):
        raise ValueError(
            "Interface %s has no address in %s — assign it first" % (iface, net))
    try:
        start = ipaddress.IPv4Address((body.get("pool_start") or "").strip())
        end = ipaddress.IPv4Address((body.get("pool_end") or "").strip())
    except ValueError:
        raise ValueError("Pool start/end must be IPv4 addresses")
    if start not in net or end not in net:
        raise ValueError("Pool must lie inside the subnet")
    if int(start) > int(end):
        raise ValueError("Pool start must not exceed pool end")
    if int(start) == int(net.network_address) or \
            int(end) == int(net.broadcast_address):
        raise ValueError("Pool must not include network/broadcast address")
    try:
        router = ipaddress.IPv4Address((body.get("router") or "").strip())
    except ValueError:
        raise ValueError("Invalid router IP address")
    if router not in net:
        raise ValueError("Router must lie inside the subnet")
    dns_list = [d.strip() for d in
                str(body.get("dns") or "").replace(",", " ").split()]
    if not dns_list:
        raise ValueError("At least one DNS server is required")
    for d in dns_list:
        try:
            ipaddress.ip_address(d)
        except ValueError:
            raise ValueError("Invalid DNS server address: %s" % d)
    domain = (body.get("domain") or "").strip()
    if domain and not HOSTNAME_RE.match(domain):
        raise ValueError("Invalid domain name")
    lease_raw = str(body.get("lease_time") or body.get("valid_lifetime")
                    or "").strip()
    lease = None
    if lease_raw:
        try:
            lease = int(lease_raw)
        except ValueError:
            raise ValueError("Lease time must be a number of seconds")
        if not 60 <= lease <= 31536000:
            raise ValueError("Lease time must be 60..31536000 seconds")
    for idx, other in enumerate(subnets):
        if target is not None and other is target:
            continue
        try:
            onet = ipaddress.IPv4Network(other.get("subnet", ""), strict=False)
        except ValueError:
            continue
        if net.overlaps(onet):
            raise ValueError("Subnet overlaps %s" % onet)
        if (other.get("interface", "") or "") == iface and \
                str(other.get("subnet", "")) != str(net):
            raise ValueError("Interface %s already serves %s" %
                             (iface, other.get("subnet", "")))

    # Sync the subnet's interface into the top-level interfaces-config:
    # Kea only listens on listed interfaces, so a subnet bound to an
    # interface that is not listed (e.g. a newly created VLAN) would never
    # get DHCP service even though everything else looks correct.
    ifaces_cfg = d4.setdefault("interfaces-config", {})
    iface_list = ifaces_cfg.setdefault("interfaces", [])
    if iface not in iface_list:
        iface_list.append(iface)

    entry = target if target is not None else {}
    entry["subnet"] = str(net)
    entry["interface"] = iface
    if "id" not in entry:
        used = {s.get("id") for s in subnets if isinstance(s.get("id"), int)}
        nid = 1
        while nid in used:
            nid += 1
        entry["id"] = nid
    entry["pools"] = [{"pool": "%s-%s" % (start, end)}]
    _kea_set_opt(entry, "routers", str(router))
    _kea_set_opt(entry, "domain-name-servers", ", ".join(dns_list))
    if domain:
        _kea_set_opt(entry, "domain-name", domain)
    else:
        entry["option-data"] = [o for o in entry.get("option-data", [])
                                if o.get("name") != "domain-name"]
    if lease is not None:
        entry["valid-lifetime"] = lease
    if target is None:
        subnets.append(entry)

    warnings = []
    for r in entry.get("reservations", []):
        try:
            rip = ipaddress.IPv4Address(r.get("ip-address", ""))
        except ValueError:
            continue
        if rip not in net:
            warnings.append("Reservation %s is outside the subnet" % rip)
    bak = KEA_CONF + ".bak-" + time.strftime("%Y%m%d%H%M%S")
    shutil.copy2(KEA_CONF, bak)
    _write_kea(kea)
    try:
        _reload_kea()
    except Exception as exc:
        shutil.copy2(bak, KEA_CONF)
        try:
            _reload_kea()
        except Exception:
            pass
        raise RuntimeError("Kea rejected the config, restored backup: %s"
                           % exc)
    out = list_dhcp_subnets()
    out["backup"] = bak
    out["warnings"] = warnings
    return out


def _unbound_read_lines():
    try:
        with open(UNBOUND_ROUTER_CONF) as f:
            return f.read().splitlines()
    except OSError as exc:
        raise RuntimeError(str(exc))


def get_unbound_form():
    lines = _unbound_read_lines()
    interfaces, forwarders, fz_names = [], [], []
    port, do_ip4, do_ip6 = 53, True, True
    tls_upstream = False
    in_fz = False
    for raw in lines:
        ls = raw.strip()
        if not ls or ls.startswith("#"):
            if in_fz and not raw[:1].isspace():
                in_fz = False
            continue
        if ls.startswith("forward-zone:"):
            in_fz = True
            continue
        if in_fz:
            if ls.startswith("name:"):
                fz_names.append(ls.split(":", 1)[1].strip().strip('"'))
            elif ls.startswith("forward-addr:"):
                forwarders.append(ls.split(":", 1)[1].strip())
            elif ls.startswith("forward-tls-upstream:") and \
                    ls.split(":", 1)[1].strip().lower() == "yes":
                tls_upstream = True
            continue
        if ls.startswith("interface:"):
            interfaces.append(ls.split(":", 1)[1].strip())
        elif ls.startswith("port:"):
            try:
                port = int(ls.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif ls.startswith("do-ip4:"):
            do_ip4 = ls.split(":", 1)[1].strip().lower() == "yes"
        elif ls.startswith("do-ip6:"):
            do_ip6 = ls.split(":", 1)[1].strip().lower() == "yes"
    foreign = [n for n in fz_names if n not in ('"."', ".")]
    if foreign:
        raise ValueError(
            "Custom forward zones present (%s) — use the raw file editor."
            % ", ".join(foreign))
    return {
        "ok": True,
        "interfaces": interfaces,
        "port": port,
        "do_ip4": do_ip4,
        "do_ip6": do_ip6,
        "forwarders": forwarders,
        "tls_upstream": tls_upstream,
        "mode": "forward" if forwarders else "recursive",
    }


def save_unbound_form(body):
    ifaces = []
    for line in str(body.get("interfaces") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            raise ValueError("Invalid listen address: %s" % line)
        if line not in ifaces:
            ifaces.append(line)
    if not ifaces:
        raise ValueError("At least one listen address is required")
    try:
        port = int(str(body.get("port") or "").strip())
    except ValueError:
        raise ValueError("Port must be a number")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be 1..65535")
    do_ip4 = bool(body.get("do_ip4"))
    do_ip6 = bool(body.get("do_ip6"))
    if not (do_ip4 or do_ip6):
        raise ValueError("Enable at least one of IPv4 / IPv6")
    forwarders = []
    tls_used = False
    for line in str(body.get("forwarders") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # Accept the extended unbound forward-addr syntax:
        #   IP[@port][#tls-auth-name]   e.g. 1.1.1.1@853#cloudflare-dns.com
        # A #tls-auth-name turns on tls-upstream for the forward zone.
        addr = line
        auth = ""
        if "#" in addr:
            addr, auth = addr.split("#", 1)
            auth = auth.strip()
        fwd_port = None
        if "@" in addr:
            addr, p = addr.rsplit("@", 1)
            try:
                fwd_port = int(p.strip())
            except ValueError:
                raise ValueError("Invalid forwarder port in: %s" % line)
            if not 1 <= fwd_port <= 65535:
                raise ValueError("Invalid forwarder port in: %s" % line)
        try:
            ipaddress.ip_address(addr.strip())
        except ValueError:
            raise ValueError("Invalid forwarder address: %s" % line)
        if "#" in line and not auth:
            raise ValueError("Missing TLS auth name in: %s" % line)
        if auth:
            if not re.match(r"^[A-Za-z0-9._-]+$", auth):
                raise ValueError("Invalid TLS auth name in: %s" % line)
            tls_used = True
        if line not in forwarders:
            forwarders.append(line)

    lines = _unbound_read_lines()
    out, seen_iface, seen_port = [], False, False
    in_fz, skip_fz = False, False
    for raw in lines:
        ls = raw.strip()
        if ls.startswith("forward-zone:"):
            in_fz, skip_fz = True, True
            continue
        if in_fz:
            if raw[:1].isspace() or not ls or ls.startswith("#"):
                continue
            in_fz, skip_fz = False, False
        if skip_fz:
            continue
        if ls.startswith("interface:"):
            if not seen_iface:
                out.extend("    interface: %s" % i for i in ifaces)
                seen_iface = True
            continue
        if ls.startswith("port:") and not seen_port:
            out.append("    port: %d" % port)
            seen_port = True
            continue
        if ls.startswith("do-ip4:"):
            out.append("    do-ip4: %s" % ("yes" if do_ip4 else "no"))
            continue
        if ls.startswith("do-ip6:"):
            out.append("    do-ip6: %s" % ("yes" if do_ip6 else "no"))
            continue
        out.append(raw)
    if not seen_iface:
        out.append("server:")
        out.extend("    interface: %s" % i for i in ifaces)
    if not seen_port:
        out.append("    port: %d" % port)
    if forwarders:
        if tls_used:
            # tls-cert-bundle is a server: option; forward-tls-upstream
            # is the forward-zone option that enables DoT for it.
            out.append("")
            out.append("server:")
            out.append("    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt")
        out.append("")
        out.append('forward-zone:')
        out.append('    name: "."')
        if tls_used:
            out.append('    forward-tls-upstream: yes')
        out.extend("    forward-addr: %s" % f for f in forwarders)

    bak = UNBOUND_ROUTER_CONF + ".bak-" + time.strftime("%Y%m%d%H%M%S")
    shutil.copy2(UNBOUND_ROUTER_CONF, bak)
    tmp = UNBOUND_ROUTER_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(out) + "\n")
    os.replace(tmp, UNBOUND_ROUTER_CONF)
    try:
        reload_unbound()
    except Exception as exc:
        shutil.copy2(bak, UNBOUND_ROUTER_CONF)
        raise RuntimeError("Unbound rejected the config, restored backup: %s"
                           % exc)
    form = get_unbound_form()
    form["backup"] = bak
    return form


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
    # tuxwall.service sandboxes the API (ProtectSystem=full), and apt dies
    # with EROFS mid-transaction once a package writes outside the sandbox
    # - observed live: openssh's packaging stopped ssh.service first, the
    # upgrade then died half-installed and the gateway lost SSH until a
    # manual unsandboxed 'apt --fix-broken'. So run apt in a transient
    # systemd unit instead: outside the service sandbox, output streamed
    # back (--pipe), waited on (--wait), cleaned up on exit (--collect).
    # Fall back to in-process only when systemd-run is unavailable.
    if shutil.which("systemd-run"):
        args = ["systemd-run", "--pipe", "--wait", "--collect",
                "-p", "Environment=DEBIAN_FRONTEND=noninteractive"] + args
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
    # 3.3.4: without the opencode binary the agent is "not installed" (the
    # unit is skipped) - errors say so and carry the install command.
    AGENT_BIN = "/home/tuxwall-agent/.opencode/bin/opencode"
    AGENT_SETUP_CMD = "sudo bash /usr/local/share/tuxwall/scripts/setup-opencode-agent.sh"

    def _agent_ok(self):
        return True

    def _agent_installed(self):
        return os.access(self.AGENT_BIN, os.X_OK)

    def _agent_log(self, msg):
        """Log an agent-proxy event to stderr -> journald (journalctl -u tuxwall.service)."""
        import sys as _sys
        print("[agent] {} {}".format(time.strftime("%Y-%m-%d %H:%M:%S"), msg), file=_sys.stderr, flush=True)

    # --- opencode dual-protocol (V1 + V2) ------------------------------
    # The bundled opencode agent is 1.18.x (V1 server API: /session,
    # /event, ...) today and 2.x (V2 server API: /api/session, /api/event,
    # ...) after an agent upgrade. The dashboard speaks V1 exclusively;
    # this layer detects the agent generation once per service lifetime
    # and translates requests/responses/events so both work unchanged.
    _AGENT_V2 = None
    _AGENT_V2_LOCK = threading.Lock()
    _AGENT_V2_TOOL_META = {}   # tool id -> {name, input} (lifecycle row stability)

    def _agent_is_v2(self):
        """True when the agent speaks the V2 API. Probed once, cached;
        re-probed after connection-level failures so an agent upgrade
        mid-service-life is picked up."""
        with self._AGENT_V2_LOCK:
            if self._AGENT_V2 is not None:
                return self._AGENT_V2
            try:
                self._agent_call_raw("GET", "/api/info", timeout=5)
                self._AGENT_V2 = True
            except AgentError as exc:
                if exc.status == 404:
                    self._AGENT_V2 = False   # V1: no /api/* namespace
                elif exc.status in (401, 403):
                    self._AGENT_V2 = True    # auth differs, routing proves V2
                elif exc.status == 0:
                    raise                    # agent down: callers handle this
                else:
                    self._AGENT_V2 = False
            return self._AGENT_V2

    def _agent_call_raw(self, method, path, payload=None, timeout=30,
                        sse=False, log_body=True):
        """HTTP call to the agent, verbatim (no translation). Raises
        AgentError with upstream status/body on failure. log_body=False
        keeps upstream bodies out of the journal (credential calls)."""
        url = self.AGENT_BASE + path
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if not sse:
            headers["Accept"] = "application/json"
        else:
            headers = {"Accept": "text/event-stream"}
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
                method, path, status, exc.reason,
                body[:2000] if log_body else "<{} bytes, not logged>".format(len(body))))
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
        if sse:
            return body
        try:
            return json.loads(body or "{}")
        except ValueError as exc:
            self._agent_log("HTTP {} {} -> non-JSON response: {}".format(
                method, path, body[:500] if log_body else "<not logged>"))
            raise AgentError("opencode returned invalid JSON ({}): {}".format(
                exc, body[:500]), status=status, body=body[:2000])

    def _agent_v2_pending_permissions(self):
        """All pending permission requests across sessions.

        V2 keeps permission requests SESSION-scoped: the global
        /api/permission/request returns an empty list even while requests
        are pending (verified against a live 2.1.4 - the shell permission
        flow died on this). Returns [(sessionID, request), ...].

        Sessions are collected from BOTH the active list and the full
        session list: a session mid-turn can be absent from /api/session/
        active (observed live - its pending ask then became permanently
        unanswerable), so the union is required for correctness."""
        sids = []
        seen = set()
        try:
            active = self._agent_call_raw("GET", "/api/session/active", timeout=10)
            data = active.get("data") if isinstance(active, dict) else None
            if isinstance(data, dict):
                sids = [k for k in data.keys() if k.startswith("ses")]
            elif isinstance(data, list):
                sids = [s.get("id") for s in data
                        if isinstance(s, dict) and s.get("id")]
        except AgentError:
            pass
        for s in sids:
            seen.add(s)
        try:
            data = self._agent_call_raw("GET", "/api/session", timeout=10)
            for s in (data.get("data") or []):
                sid = s.get("id") if isinstance(s, dict) else None
                if sid and sid not in seen:
                    sids.append(sid)
                    seen.add(sid)
        except AgentError:
            pass
        out = []
        for sid in sids[:20]:
            try:
                data = self._agent_call_raw(
                    "GET",
                    "/api/session/" + urllib.parse.quote(sid) + "/permission",
                    timeout=10)
                for r in (data.get("data") or []):
                    out.append((sid, r))
            except AgentError:
                continue
        return out

    def _agent_v2_find_session_id(self, request_id):
        """Locate the session a pending permission request belongs to
        (V2 replies are session-scoped)."""
        for sid, r in self._agent_v2_pending_permissions():
            if r.get("id") == request_id:
                return sid
        return None

    def _agent_v2_last_message_id(self, session_id):
        """Latest message id in a session (V2 revert staging requires an
        explicit messageID; the V1 'revert last' semantics pick the most
        recent message)."""
        try:
            data = self._agent_call_raw(
                "GET", "/api/session/" + urllib.parse.quote(session_id) + "/message",
                timeout=15)
            items = data.get("data") or []
            if items:
                return items[-1].get("id")
        except AgentError:
            pass
        return None

    @staticmethod
    def _agent_v2_perm_to_v1(r):
        """V2 Permission.Request -> the V1 request shape the dashboard's
        permission cards read (id / permission / tool / patterns /
        metadata)."""
        if not isinstance(r, dict):
            return r
        meta = r.get("metadata") or {}
        out = dict(r)
        action = r.get("action") or "tool"
        out.setdefault("permission", action)
        out.setdefault("tool", action)
        out.setdefault("patterns", r.get("resources") or [])
        if r.get("message") and not meta.get("description"):
            meta = dict(meta)
            meta.setdefault("description", r.get("message"))
            out["metadata"] = meta
        return out

    @staticmethod
    def _agent_v2_form_questions(form):
        """V2 form fields -> V1 'questions' objects for the dashboard's
        question cards."""
        questions = []
        for f in (form.get("fields") or []):
            if not isinstance(f, dict):
                continue
            ftype = f.get("type") or ""
            opts = []
            for o in (f.get("options") or []):
                if isinstance(o, dict):
                    opts.append({"label": str(o.get("label") or o.get("value") or ""),
                                 "description": str(o.get("description") or "")})
                else:
                    opts.append({"label": str(o), "description": ""})
            questions.append({
                "header": f.get("header") or f.get("label") or "",
                "question": f.get("question") or f.get("label") or f.get("title")
                            or (form.get("title") if len(form.get("fields") or []) == 1 else ""),
                "options": opts,
                "multi": ftype == "multiselect" or bool(f.get("multi")),
            })
        return questions

    def _agent_v2_translate(self, method, path, payload):
        """Map a V1-style agent call onto the V2 API.

        Returns (method, v2_path, v2_payload, needs_post_processing).
        Post-processing (multi-step flows) is handled in _agent_v2_finish.
        """
        p = path
        q = ""
        if "?" in p:
            p, q = p.split("?", 1)
        sid = lambda s: urllib.parse.quote(s or "")
        if p == "/global/health":
            return ("GET", "/api/info", None)
        if p == "/config":
            return ("GET", "/api/config", None)
        if p == "/config/providers":
            # Merged in _agent_v2_finish (needs /api/provider + /api/model)
            return ("GET", "/api/provider", None)
        if p == "/session":
            if method == "POST":
                return ("POST", "/api/session", payload or {})
            return ("GET", "/api/session", None)
        if p == "/permission":
            return ("GET", "/api/permission/request", None)
        if p == "/question":
            return ("GET", "/api/form", None)
        if p == "/path":
            return ("GET", "/api/location", None)
        if p == "/vcs":
            return ("GET", "/api/vcs", None)
        if p == "/find/file":
            params = urllib.parse.parse_qs(q)
            v2q = (params.get("query") or [""])[0]
            return ("GET", "/api/fs/find?" + urllib.parse.urlencode(
                {"query": v2q}), None)
        if p.startswith("/session/"):
            rest = p[len("/session/"):]
            parts = rest.split("/")
            if len(parts) == 1:
                s = parts[0]
                if method == "DELETE":
                    return ("DELETE", "/api/session/" + sid(s), None)
                if method == "PATCH":
                    return ("PATCH", "/api/session/" + sid(s), payload or {})
                return ("GET", "/api/session/" + sid(s), None)
            s, action = parts[0], parts[1]
            base = "/api/session/" + sid(s)
            if action == "message":
                return ("GET", base + "/message", None)
            if action == "prompt_async":
                # V1 payload: {parts: [{type:"text", text}], model?}
                text = "\n".join((pp.get("text") or "") for pp in
                                 ((payload or {}).get("parts") or [])
                                 if isinstance(pp, dict) and pp.get("type") == "text")
                # V2 prompts carry no model: the session model is switched
                # beforehand (_agent_v2_apply_model).
                return ("POST", base + "/prompt", {"text": text})
            if action == "shell":
                v2p = {"command": (payload or {}).get("command") or ""}
                return ("POST", base + "/shell", v2p)
            if action == "command":
                pl = payload or {}
                v2p = {"name": pl.get("command") or ""}
                v2p["text"] = " ".join(str(a) for a in (pl.get("arguments") or []))
                return ("POST", base + "/command", v2p)
            if action == "abort":
                return ("POST", base + "/interrupt", None)
            if action == "summarize":
                return ("POST", base + "/compact", None)
            if action == "revert":
                return ("POST", base + "/revert/stage", None)  # messageID added in finish
            if action == "unrevert":
                raise AgentError(
                    "redo (unrevert) is not supported by the opencode v2 agent API",
                    status=501, body="unrevert has no V2 equivalent")
            if action in ("share",):
                raise AgentError(
                    "session sharing is not supported by the opencode v2 agent API",
                    status=501, body="share has no V2 equivalent")
            if action == "init":
                return ("POST", "/api/vcs/init", None)
        if p.startswith("/permission/") and p.endswith("/reply"):
            request_id = p[len("/permission/"):-len("/reply")]
            # session-scoped in V2; resolved in _agent_v2_finish
            return ("POST", "/api/permission/" + sid(request_id) + "/reply",
                    payload or {})
        if p.startswith("/question/"):
            request_id = parts_id = p[len("/question/"):].split("/")[0]
            tail = p[len("/question/"):][len(request_id):]
            if tail == "/reply":
                return ("POST", "/api/form/" + sid(request_id) + "/reply",
                        payload or {})
            if tail == "/reject":
                return ("DELETE", "/api/form/" + sid(request_id), None)
        # Unmapped path: surface clearly rather than silently 404ing.
        raise AgentError("opencode v2 mapping missing for {} {}".format(method, path),
                         status=501, body="dual-protocol translator gap")

    def _agent_v2_finish(self, v1_method, v1_path, v2_path, v2_payload, result):
        """Post-process a V2 response into the V1 shape the dashboard
        expects (unwrap {data}, merge multi-call flows, normalize)."""
        p = v1_path.split("?")[0]
        def d(x):
            return x.get("data") if isinstance(x, dict) and "data" in x else x

        if p == "/config/providers":
            # Build the V1 providers view from /api/model (models exist even
            # when /api/provider lists nothing - providers only appear
            # there once activated/credentialed). Provider names are
            # enriched from /api/provider when available.
            raw = d(result)
            prov_list = (raw.get("data") if isinstance(raw, dict) and "data" in raw else raw) or []
            names = {}
            for prov in (prov_list or []):
                if isinstance(prov, dict) and prov.get("id"):
                    names[prov["id"]] = prov.get("name") or prov["id"]
            providers = []
            seen = {}
            try:
                models = self._agent_call_raw("GET", "/api/model", timeout=10)
                mlist = (models.get("data") or []) if isinstance(models, dict) else []
            except AgentError:
                mlist = []
            for m in mlist:
                if not isinstance(m, dict):
                    continue
                pid = m.get("providerID") or "model"
                mid = m.get("modelID") or m.get("id") or "?"
                seen.setdefault(pid, {})[mid] = {"name": m.get("name") or mid}
            for pid in sorted(seen):
                providers.append({
                    "id": pid,
                    "name": names.get(pid, pid),
                    "models": seen[pid],
                })
            default = {}
            try:
                default = self._agent_call_raw("GET", "/api/model/default", timeout=5)
                default = d(default) or {}
                if isinstance(default, dict) and default.get("providerID"):
                    default = dict(default)
                    default.setdefault("model",
                                       default.get("modelID") or default.get("id") or "")
            except AgentError:
                pass
            return {"ok": True, "providers": providers, "default": default}
        if p == "/config":
            # V2 /api/config returns a list of layered entries; merge the
            # document entries' info into one object (V1 callers expect a
            # single config dict) and normalize the V2 model ref into the
            # V1 "provider/model" string.
            raw = d(result)
            merged = {}
            entries = raw if isinstance(raw, list) else [raw]
            for e in entries:
                if isinstance(e, dict) and isinstance(e.get("info"), dict):
                    merged.update(e["info"])
                elif isinstance(e, dict) and e.get("type") != "directory":
                    merged.update({k: v for k, v in e.items()
                                   if k not in ("type", "path")})
            model = merged.get("model")
            if isinstance(model, dict) and model.get("providerID"):
                merged["model"] = "{}/{}".format(
                    model.get("providerID"),
                    model.get("model") or model.get("modelID") or "")
            return merged
        if p == "/session" and v1_method == "POST":
            return d(result)
        if p == "/session":
            return d(result)
        if p.startswith("/session/") and p.endswith("/message"):
            return d(result)
        if p == "/permission":
            # V2: aggregate across active sessions (the global endpoint
            # lists nothing) and normalize each into the V1 card shape.
            requests = self._agent_v2_pending_permissions()
            return [self._agent_v2_perm_to_v1(r) for _sid, r in requests]
        if p == "/question":
            raw = d(result)
            forms = (raw.get("data") if isinstance(raw, dict) else raw) or []
            # The dashboard's question poll reads `d.requests` and renders
            # each entry as a question card: {requestID, sessionID,
            # questions}. Map V2 forms into that shape.
            requests = []
            for form in forms:
                if not isinstance(form, dict):
                    continue
                requests.append({
                    "requestID": form.get("id") or "",
                    "sessionID": form.get("sessionID") or "",
                    "questions": self._agent_v2_form_questions(form),
                })
            return {"ok": True, "requests": requests}
        if p == "/path":
            raw = d(result)
            return {"directory": (raw or {}).get("directory") or ""}
        if p == "/vcs":
            return d(result)
        if p == "/find/file":
            raw = d(result)
            return raw.get("data") if isinstance(raw, dict) else raw
        # Permission reply: resolve the session, then send the real reply.
        if p.startswith("/permission/") and p.endswith("/reply"):
            request_id = p[len("/permission/"):-len("/reply")]
            session_id = self._agent_v2_find_session_id(request_id)
            if not session_id:
                raise AgentError("pending permission {} not found".format(request_id),
                                 status=404, body="permission request missing")
            reply = (v2_payload or {}).get("reply") or "once"
            real = self._agent_call_raw(
                "POST",
                "/api/session/" + urllib.parse.quote(session_id) +
                "/permission/" + urllib.parse.quote(request_id) + "/reply",
                {"decision": reply}, timeout=15)
            return real
        # Question reply/reject: resolve the form's session, act on the form.
        if p.startswith("/question/"):
            request_id = p[len("/question/"):].split("/")[0]
            form = None
            try:
                data = self._agent_call_raw("GET", "/api/form", timeout=10)
                for f in (data.get("data") or []):
                    if f.get("id") == request_id:
                        form = f
                        break
            except AgentError:
                pass
            if not form or not form.get("sessionID"):
                raise AgentError("pending question {} not found".format(request_id),
                                 status=404, body="form missing")
            fbase = ("/api/session/" + urllib.parse.quote(form["sessionID"]) +
                     "/form/" + urllib.parse.quote(request_id))
            if p.endswith("/reply"):
                answers = (v2_payload or {}).get("answers") or []
                answer = answers[0] if len(answers) == 1 else answers
                return self._agent_call_raw("POST", fbase + "/reply",
                                            {"answer": answer}, timeout=15)
            return self._agent_call_raw("DELETE", fbase, timeout=15)
        # Revert: V2 is staged (messageID) then committed.
        if p.startswith("/session/") and p.endswith("/revert"):
            session_id = p[len("/session/"):].split("/")[0]
            message_id = self._agent_v2_last_message_id(session_id)
            if not message_id:
                raise AgentError("no messages to revert", status=400, body="empty session")
            base = "/api/session/" + urllib.parse.quote(session_id)
            self._agent_call_raw("POST", base + "/revert/stage",
                                 {"messageID": message_id}, timeout=30)
            return self._agent_call_raw("POST", base + "/revert/commit",
                                       None, timeout=60)
        # Shell: V2 runs the command through the session asynchronously.
        # Poll the message list until the shell message completes, then
        # build the V1 {parts:[...]} shape the dashboard's !-command flow
        # parses (tool part with state.output / state.error).
        if p.startswith("/session/") and p.endswith("/shell"):
            session_id = p[len("/session/"):].split("/")[0]
            command = (v2_payload or {}).get("command") or ""
            deadline = time.time() + 280
            base = "/api/session/" + urllib.parse.quote(session_id)
            while time.time() < deadline:
                time.sleep(0.6)
                try:
                    data = self._agent_call_raw("GET", base + "/message", timeout=15)
                except AgentError:
                    break
                shell_msgs = [m for m in (data.get("data") or [])
                              if isinstance(m, dict) and m.get("type") == "shell"]
                if not shell_msgs:
                    continue
                last = shell_msgs[-1]
                if last.get("command") != command:
                    continue
                status = last.get("status") or "running"
                if status == "running":
                    continue
                out = (last.get("output") or {}).get("output") or ""
                exit_code = last.get("exit")
                state = {"status": "completed" if status == "exited" else "error",
                         "output": out}
                if status != "exited" or (exit_code not in (None, 0)):
                    state["error"] = "exit {}".format(exit_code if exit_code is not None else status)
                return {"parts": [{"type": "tool", "name": "shell", "state": state}]}
            raise AgentError("shell command did not finish in time",
                             status=504, body="shell poll timeout")
        # Default: unwrap {data} envelopes so V1 callers see plain payloads.
        return d(result)

    def _agent_call(self, method, path, payload=None, timeout=30):
        """Forward a request to the local opencode server (HTTP basic auth).

        Speaks the V1 wire protocol to callers and translates to/from the
        V2 API automatically when the agent is opencode 2.x.

        Returns parsed JSON in the V1 shape. On failure raises AgentError
        carrying the upstream status code and response body so callers can
        log and display the real cause.
        """
        if self._agent_is_v2():
            m2, p2, payload2 = self._agent_v2_translate(method, path, payload)
            p1 = path.split("?")[0]
            # Multi-step flows (session-scoped replies, staged reverts,
            # cross-session permission aggregation) are fully orchestrated
            # inside _agent_v2_finish; the stub paths returned by the
            # translator must not be called directly.
            deferred = (
                p1 == "/permission"
                or (p1.startswith("/permission/") and p1.endswith("/reply"))
                or p1.startswith("/question/")
                or (p1.startswith("/session/") and p1.endswith("/revert"))
            )
            if deferred:
                result = self._agent_v2_finish(method, path, p2, payload2, None)
            else:
                result = self._agent_call_raw(m2, p2, payload2, timeout=timeout)
                result = self._agent_v2_finish(method, path, p2, payload2, result)
            # V2 success responses are frequently bare ({} on 200, or a
            # {data:...} envelope with no verdict field). The V1 routes the
            # dashboard posts to REQUIRE ok:true - a {} passthrough renders
            # as "HTTP 200" on the client. Errors raise AgentError before
            # this point, so a dict result here is always a success.
            if isinstance(result, dict) and "ok" not in result:
                result = dict(result)
                result["ok"] = True
            return result
        return self._agent_call_raw(method, path, payload, timeout=timeout)

    def _agent_error(self, exc):
        """Build a structured error payload from an AgentError (or any exception)."""
        if not self._agent_installed():
            return {
                "ok": False,
                "installed": False,
                "error": "AI assistant not installed",
                "hint": "Install it on the router: " + self.AGENT_SETUP_CMD,
                "fix": self.AGENT_SETUP_CMD,
            }
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

    # ── tripwire recovery mode (needs the agent for providers + session) ─
    def _tripwire_agent_providers(self):
        """Catalog providers with a stored credential: their endpoints join
        the recovery allowlist (ids only - never key material)."""
        try:
            if not self._agent_is_v2():
                return []
            return sorted({c["integrationID"] for c in self._agent_credentials()
                           if c.get("integrationID")})[:40]
        except Exception:
            return []

    def _tripwire_incident_session(self, title):
        """Create the incident's assistant session (titled, empty: the brief
        is pre-filled in the browser, never auto-sent). Returns (id, error)."""
        try:
            data = self._agent_call("POST", "/session",
                                    {"title": str(title or "Tripwire incident")[:120]})
        except Exception as exc:
            return "", str(exc)[:200]
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data["data"]
        sid = str((data or {}).get("id") or "") if isinstance(data, dict) else ""
        if not AGENT_OBJ_ID_RE.match(sid):
            return "", "the assistant did not return a session id"
        try:
            _tripwire_json_cli(["recovery-session", sid])
        except Exception:
            pass
        return sid, ""

    def _tripwire_recovery_preview(self, identity):
        providers = self._tripwire_agent_providers() if _is_admin(identity) else []
        return _tripwire_json_cli(["recovery-status", "--preview"], {"providers": providers},
                                  timeout=45)

    def _tripwire_recovery_start(self, body, identity, client_ip):
        _tripwire_check_password(identity, body.get("password"))
        minutes = body.get("minutes", 60)
        if isinstance(minutes, bool) or not isinstance(minutes, (int, str)):
            raise ValueError("minutes must be a whole number")
        res = _tripwire_json_cli(["recovery-start", "--minutes", str(minutes)]
                                 + _tripwire_who(identity, client_ip),
                                 {"providers": self._tripwire_agent_providers(),
                                  "local_only": body.get("local_only") is True}, timeout=120)
        out = dict(res)
        out.update(self._tripwire_brief(identity))
        return out

    def _tripwire_brief(self, identity):
        """Incident brief + the incident session (created once per recovery)."""
        b = _tripwire_json_cli(["recovery-brief"])
        sid, err = b.get("session_id") or "", ""
        if not sid and b.get("recovery_active") and _is_admin(identity):
            sid, err = self._tripwire_incident_session(b.get("title"))
        return {"brief": {"title": b.get("title") or "", "text": b.get("text") or ""},
                "session_id": sid, "session_error": err}

    # ── providers / API keys / models (phase E, see OPENCODE_CONF) ─────
    _AGENT_INTEG_CACHE = {"t": 0.0, "data": None}

    @staticmethod
    def _agent_d(x):
        return x.get("data") if isinstance(x, dict) and "data" in x else x

    def _agent_secret_call(self, method, path, payload=None, secrets_list=(), timeout=30):
        """Agent call whose request may carry a secret: bodies are not
        logged and upstream error text is scrubbed of the secret."""
        try:
            return self._agent_call_raw(method, path, payload, timeout=timeout, log_body=False)
        except AgentError as exc:
            raise AgentError(_agent_scrub(str(exc), secrets_list), status=exc.status,
                             body=_agent_scrub(exc.body, secrets_list))

    @staticmethod
    def _agent_err_text(exc):
        """Readable message from an opencode V2 error body."""
        body = getattr(exc, "body", "") or ""
        msg = ""
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                inner = data.get("data") if isinstance(data.get("data"), dict) else {}
                msg = (data.get("message") or inner.get("message") or data.get("error")
                       or data.get("name") or "")
                if isinstance(msg, dict):
                    msg = msg.get("message") or json.dumps(msg)[:300]
        except ValueError:
            msg = body
        msg = str(msg or exc).strip()
        return msg[:400] or "opencode request failed"

    @staticmethod
    def _agent_clean_text(value, limit=60):
        v = re.sub(r"[\x00-\x1f\x7f]", "", str(value or "")).strip()
        return v[:limit]

    @staticmethod
    def _agent_trim_form(form):
        out = []
        for f in form or []:
            if not isinstance(f, dict) or not f.get("key"):
                continue
            g = {k: f[k] for k in ("key", "title", "description", "required", "type",
                                   "placeholder", "default", "hidden", "pattern") if k in f}
            if isinstance(f.get("options"), list):
                g["options"] = [{"value": str(o.get("value", "")),
                                 "label": str(o.get("label") or o.get("value") or ""),
                                 "description": str(o.get("description") or "")}
                                for o in f["options"] if isinstance(o, dict)]
            if isinstance(f.get("when"), list):
                g["when"] = [w for w in f["when"] if isinstance(w, dict)]
            out.append(g)
        return out

    @staticmethod
    def _agent_form_answer(form, answer):
        """Keep only answers for the method's declared form fields."""
        if not form or not isinstance(answer, dict):
            return None
        keys = {f.get("key") for f in form}
        out = {}
        for k, v in answer.items():
            if k in keys and isinstance(v, (str, int, float, bool)) and v != "":
                out[k] = re.sub(r"[\x00-\x1f\x7f]", "", v)[:300] if isinstance(v, str) else v
        return out or None

    def _agent_integrations(self, force=False):
        c = self._AGENT_INTEG_CACHE
        if not force and c["data"] is not None and time.time() - c["t"] < 600:
            return c["data"]
        raw = self._agent_d(self._agent_call_raw("GET", "/api/integration", timeout=20,
                                                 log_body=False)) or []
        out = []
        for i in raw if isinstance(raw, list) else []:
            if not isinstance(i, dict) or not i.get("id"):
                continue
            methods = []
            for m in i.get("methods") or []:
                if not isinstance(m, dict):
                    continue
                t = m.get("type")
                if t == "key":
                    methods.append({"type": "key", "label": m.get("label") or "API key",
                                    "form": self._agent_trim_form(m.get("form"))})
                elif t == "oauth":
                    mid = str(m.get("id") or "")
                    methods.append({"type": "oauth", "id": mid,
                                    "label": m.get("label") or "Sign in",
                                    "form": self._agent_trim_form(m.get("form")),
                                    # device-code flows work from any device;
                                    # browser flows redirect to the router's
                                    # own localhost and cannot finish remotely
                                    "usable": "device" in mid or "headless" in mid})
                elif t == "env":
                    methods.append({"type": "env",
                                    "names": [str(n) for n in (m.get("names") or [])][:5]})
            conns = []
            for cn in i.get("connections") or []:
                if isinstance(cn, dict):
                    st = cn.get("status")
                    conns.append({"type": cn.get("type") or "", "id": cn.get("id") or "",
                                  "label": cn.get("label") or cn.get("name") or "",
                                  "method": cn.get("method") or "",
                                  "status": st.get("status") if isinstance(st, dict) else "",
                                  "message": (st.get("message") or "")[:200] if isinstance(st, dict) else ""})
            out.append({"id": i["id"], "name": i.get("name") or i["id"],
                        "methods": methods, "connections": conns})
        c["data"] = out
        c["t"] = time.time()
        return out

    def _agent_find_integration(self, iid):
        if not AGENT_INTEG_ID_RE.match(iid or ""):
            raise ValueError("Unknown provider")
        for i in self._agent_integrations():
            if i["id"] == iid:
                return i
        raise ValueError("Unknown provider '{}'".format(iid))

    @staticmethod
    def _agent_is_local(pid, base):
        if pid in ("ollama", "lmstudio", "vllm", "llamacpp", "llama.cpp"):
            return True
        host = ""
        try:
            host = urllib.parse.urlsplit(base or "").hostname or ""
        except ValueError:
            pass
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return host == "localhost" or host.endswith((".local", ".lan", ".home", ".internal")) or "." not in host

    def _agent_provider_list(self):
        raw = self._agent_d(self._agent_call_raw("GET", "/api/provider", timeout=10,
                                                 log_body=False)) or []
        out = []
        for p in raw if isinstance(raw, list) else []:
            if not isinstance(p, dict) or not p.get("id"):
                continue
            base = str((p.get("settings") or {}).get("baseURL") or "")
            local = self._agent_is_local(p["id"], base)
            out.append({"id": p["id"], "name": p.get("name") or p["id"],
                        "integrationID": p.get("integrationID") or "",
                        "activation": p.get("activation") or "",
                        "local": local, "baseURL": base if local else ""})
        return out

    def _agent_credentials(self):
        raw = self._agent_d(self._agent_call_raw("GET", "/api/credential", timeout=10,
                                                 log_body=False)) or []
        out = []
        for c in raw if isinstance(raw, list) else []:
            if not isinstance(c, dict) or not c.get("id"):
                continue
            v = c.get("value") if isinstance(c.get("value"), dict) else {}
            t = v.get("type") or ""
            out.append({"id": c["id"], "integrationID": c.get("integrationID") or "",
                        "label": c.get("label") or "", "active": bool(c.get("active")),
                        "type": t,
                        "masked": (_agent_mask_secret(v.get("key")) if t == "key"
                                   else "signed in" if t == "oauth" else t)})
        return out

    @staticmethod
    def _agent_custom_list():
        try:
            conf = _oc_conf_read()
        except Exception:
            return []
        out = []
        for block, legacy in (("providers", False), ("provider", True)):
            provs = conf.get(block)
            if not isinstance(provs, dict):
                continue
            for pid, p in provs.items():
                if not isinstance(p, dict):
                    continue
                st = p.get("settings") if not legacy else p.get("options")
                st = st if isinstance(st, dict) else {}
                key = st.get("apiKey")
                out.append({"id": pid, "name": p.get("name") or pid,
                            "baseURL": st.get("baseURL") or "",
                            "hasKey": bool(key),
                            "keyInFile": isinstance(key, str) and key.startswith("{file:"),
                            "models": list((p.get("models") or {}).keys())[:200],
                            "legacy": legacy})
        return out

    def _agent_default_info(self, model_ids=None):
        configured = ""
        try:
            m = _oc_conf_read().get("model")
            if isinstance(m, str):
                configured = m
            elif isinstance(m, dict) and m.get("providerID"):
                configured = "{}/{}".format(m.get("providerID"), m.get("model") or "")
        except Exception:
            pass
        effective, effective_name = "", ""
        try:
            dd = self._agent_d(self._agent_call_raw("GET", "/api/model/default", timeout=5,
                                                    log_body=False)) or {}
            if isinstance(dd, dict) and dd.get("providerID"):
                effective = dd["providerID"] + "/" + (dd.get("id") or dd.get("modelID") or "")
                effective_name = dd.get("name") or ""
        except AgentError:
            pass
        out = {"configured": configured, "effective": effective, "effective_name": effective_name}
        if model_ids is not None:
            out["configured_ok"] = (not configured) or configured in model_ids
        return out

    def _agent_models_view(self):
        raw = self._agent_d(self._agent_call_raw("GET", "/api/model", timeout=10,
                                                 log_body=False)) or []
        try:
            provs = {p["id"]: p for p in self._agent_provider_list()}
        except AgentError:
            provs = {}
        models, groups, seen = [], [], set()
        for m in raw if isinstance(raw, list) else []:
            if not isinstance(m, dict) or m.get("enabled") is False:
                continue
            pid = m.get("providerID") or ""
            mid = m.get("id") or m.get("modelID") or ""
            if not pid or not mid:
                continue
            pinfo = provs.get(pid) or {}
            local = bool(pinfo.get("local"))
            costs = m.get("cost") or []
            c0 = costs[0] if costs and isinstance(costs[0], dict) else None
            cin = c0.get("input") if c0 else None
            cout = c0.get("output") if c0 else None
            if pid not in seen:
                seen.add(pid)
                groups.append({"id": pid, "name": pinfo.get("name") or pid, "local": local})
            models.append({
                "id": pid + "/" + mid, "provider": pid, "model": mid,
                "name": m.get("name") or mid,
                "provider_name": pinfo.get("name") or pid,
                "free": bool(c0) and not local and not cin and not cout,
                "local": local,
                "cost": {"input": cin, "output": cout} if c0 else None,
                "context": (m.get("limit") or {}).get("context"),
                "tools": bool((m.get("capabilities") or {}).get("tools")),
                "status": m.get("status") or "",
            })
        info = self._agent_default_info({x["id"] for x in models})
        return {"ok": True, "models": models, "groups": groups,
                "default": info["effective"], "effective_name": info["effective_name"],
                "configured": info["configured"], "configured_ok": info["configured_ok"]}

    def _agent_wait_provider(self, pid, present=True, expect_models=None, timeout=15.0):
        """opencode hot-reloads its config a few seconds after a write; wait
        until the provider shows up with the expected models (or
        disappears). Returns (state_reached, model_count)."""
        deadline = time.time() + timeout
        count = 0
        while True:
            try:
                ids = {p["id"] for p in self._agent_provider_list()}
                ok = (pid in ids) == present
                if ok and present:
                    raw = self._agent_d(self._agent_call_raw("GET", "/api/model", timeout=10,
                                                             log_body=False)) or []
                    have = {m.get("id") for m in raw
                            if isinstance(m, dict) and m.get("providerID") == pid}
                    count = len(have)
                    if expect_models is not None and have != set(expect_models):
                        ok = False
                if ok:
                    return True, count
            except AgentError:
                pass
            if time.time() >= deadline:
                return False, count
            time.sleep(0.5)

    def _agent_v2_apply_model(self, session_id, model):
        """V2 prompts carry no model: switch the session's model first when
        the requested one differs from the session's current model.
        Returns True when switched."""
        model = (model or "").strip()
        if not session_id or "/" not in model:
            return False
        pid, mid = model.split("/", 1)
        cur = None
        try:
            s = self._agent_d(self._agent_call_raw(
                "GET", "/api/session/" + urllib.parse.quote(session_id), timeout=10)) or {}
            sm = s.get("model") if isinstance(s, dict) else None
            if isinstance(sm, dict) and sm.get("providerID"):
                cur = (sm.get("providerID"), sm.get("id") or "")
        except AgentError:
            pass
        if cur is None:
            # no explicit model yet: the session runs on the default
            eff = self._agent_default_info().get("effective") or ""
            if eff and eff == model:
                return False
        elif cur == (pid, mid):
            return False
        self._agent_call_raw("POST", "/api/session/" + urllib.parse.quote(session_id) + "/model",
                             {"model": {"id": mid, "providerID": pid}}, timeout=15)
        self._agent_log("session {} model -> {}".format(session_id, model))
        return True

    def _agent_providers_get(self, path):
        """GET /api/agent/providers[/oauth/status]. Returns (code, payload)."""
        if path == "/api/agent/providers":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            integ = self._agent_integrations(force=bool(qs.get("refresh")))
            by_id = {i["id"]: i for i in integ}
            popular = [p for p in AGENT_POPULAR_INTEGRATIONS if p in by_id]
            rank = {p: n for n, p in enumerate(popular)}
            ordered = sorted(integ, key=lambda i: (rank.get(i["id"], 999), i["name"].lower()))
            listed = []
            for i in ordered:
                methods = [m for m in i["methods"] if m["type"] in ("key", "oauth", "env")]
                if not any(m["type"] == "key" or (m["type"] == "oauth" and m["usable"]) for m in methods):
                    continue
                listed.append({"id": i["id"], "name": i["name"], "popular": i["id"] in rank,
                               "methods": methods})
            creds = self._agent_credentials()
            for c in creds:
                c["integrationName"] = (by_id.get(c["integrationID"]) or {}).get("name") or c["integrationID"]
            env_conns = []
            for i in integ:
                for cn in i["connections"]:
                    if cn["type"] == "env":
                        env_conns.append({"integrationID": i["id"], "integrationName": i["name"],
                                          "name": cn["label"]})
            try:
                providers = self._agent_provider_list()
            except AgentError:
                providers = []
            return 200, {"ok": True, "integrations": listed, "popular": popular,
                         "credentials": creds, "env": env_conns,
                         "providers": providers, "custom": self._agent_custom_list(),
                         "default": self._agent_default_info(),
                         "keysDir": AGENT_KEYS_DIR}
        if path == "/api/agent/providers/oauth/status":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            iid = (qs.get("integrationID") or [""])[0]
            aid = (qs.get("attemptID") or [""])[0]
            if not AGENT_INTEG_ID_RE.match(iid) or not AGENT_OBJ_ID_RE.match(aid):
                return 400, {"ok": False, "error": "integrationID and attemptID required"}
            try:
                res = self._agent_d(self._agent_secret_call(
                    "GET", "/api/integration/{}/connect/oauth/{}".format(
                        urllib.parse.quote(iid), urllib.parse.quote(aid)), timeout=15)) or {}
            except AgentError as exc:
                if exc.status != 404:
                    raise
                res = {"status": "expired", "message": "The sign-in attempt is no longer active"}
            st = res.get("status") or "pending"
            if st == "complete":
                self._AGENT_INTEG_CACHE["data"] = None
            return 200, {"ok": True, "status": st, "message": (res.get("message") or "")[:300],
                         "expires": (res.get("time") or {}).get("expires")}
        return 404, {"ok": False, "error": "Not found"}

    def _agent_providers_post(self, path, body):
        """POST /api/agent/providers/* and /api/agent/models/default.
        Returns (code, payload). Never echoes submitted keys."""
        q = urllib.parse.quote
        if path == "/api/agent/providers/connect":
            iid = str(body.get("integrationID") or "").strip()
            key = body.get("key")
            key = key.strip() if isinstance(key, str) else ""
            label = self._agent_clean_text(body.get("label"))
            integ = self._agent_find_integration(iid)
            km = next((m for m in integ["methods"] if m["type"] == "key"), None)
            if not km:
                raise ValueError("{} does not accept an API key".format(integ["name"]))
            if not AGENT_KEY_RE.match(key):
                raise ValueError("That does not look like an API key (8-512 printable characters, no spaces)")
            replace = str(body.get("replaceCredentialID") or "")
            before = self._agent_credentials()
            if replace and not any(c["id"] == replace and c["integrationID"] == iid for c in before):
                raise ValueError("The key to replace was not found")
            payload = {"key": key}
            if label:
                payload["label"] = label
            answer = self._agent_form_answer(km.get("form"), body.get("answer"))
            if answer:
                payload["answer"] = answer
            try:
                self._agent_secret_call("POST", "/api/integration/{}/connect/key".format(q(iid)),
                                        payload, [key], timeout=60)
            except AgentError as exc:
                return 400 if 400 <= exc.status < 500 else 502, {
                    "ok": False, "error": "{} rejected the key: {}".format(
                        integ["name"], _agent_scrub(self._agent_err_text(exc), [key]))}
            finally:
                key = payload["key"] = ""
            self._AGENT_INTEG_CACHE["data"] = None
            after = self._agent_credentials()
            old_ids = {c["id"] for c in before}
            new = [c for c in after if c["id"] not in old_ids]
            replaced = False
            if replace:
                try:
                    self._agent_secret_call("DELETE", "/api/credential/" + q(replace), timeout=15)
                    replaced = True
                except AgentError as exc:
                    self._agent_log("credential replace: removing old {} failed: {}".format(
                        replace, exc.status))
            self._agent_log("credential added for {} ({})".format(iid, "replace" if replace else "new"))
            return 200, {"ok": True, "credential": new[0] if new else None, "replaced": replaced,
                         "message": "{} connected".format(integ["name"])}
        if path in ("/api/agent/providers/remove", "/api/agent/providers/rename",
                    "/api/agent/providers/activate"):
            cid = str(body.get("credentialID") or "")
            if not AGENT_OBJ_ID_RE.match(cid):
                raise ValueError("credentialID required")
            cred = next((c for c in self._agent_credentials() if c["id"] == cid), None)
            if not cred:
                return 404, {"ok": False, "error": "Credential not found"}
            if path.endswith("/remove"):
                self._agent_secret_call("DELETE", "/api/credential/" + q(cid), timeout=15)
                self._agent_log("credential removed for {}".format(cred["integrationID"]))
            elif path.endswith("/rename"):
                label = self._agent_clean_text(body.get("label"))
                if not label:
                    raise ValueError("Label required")
                self._agent_secret_call("PATCH", "/api/credential/" + q(cid), {"label": label}, timeout=15)
            else:
                self._agent_secret_call("POST", "/api/credential/{}/activate".format(q(cid)), None, timeout=15)
            self._AGENT_INTEG_CACHE["data"] = None
            return 200, {"ok": True}
        if path == "/api/agent/providers/oauth/start":
            iid = str(body.get("integrationID") or "").strip()
            mid = str(body.get("methodID") or "").strip()
            integ = self._agent_find_integration(iid)
            m = next((x for x in integ["methods"] if x["type"] == "oauth" and x["id"] == mid), None)
            if not m:
                raise ValueError("Unknown sign-in method")
            if not m["usable"]:
                raise ValueError("This sign-in method needs a browser on the router itself; "
                                 "use an API key or a device-code sign-in instead")
            payload = {"methodID": mid}
            label = self._agent_clean_text(body.get("label"))
            if label:
                payload["label"] = label
            answer = self._agent_form_answer(m.get("form"), body.get("answer"))
            if answer:
                payload["answer"] = answer
            try:
                res = self._agent_d(self._agent_secret_call(
                    "POST", "/api/integration/{}/connect/oauth".format(q(iid)), payload, timeout=30)) or {}
            except AgentError as exc:
                return 502, {"ok": False, "error": self._agent_err_text(exc)}
            url = str(res.get("url") or "")
            aid = str(res.get("attemptID") or "")
            redir = (urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("redirect_uri") or [""])[0]
            if re.match(r"^https?://(localhost|127\.0\.0\.1|\[::1\])[:/]", redir):
                try:
                    self._agent_secret_call("DELETE", "/api/integration/{}/connect/oauth/{}".format(
                        q(iid), q(aid)), timeout=10)
                except AgentError:
                    pass
                raise ValueError("This sign-in redirects to the router's own browser and cannot be "
                                 "finished from here; use an API key instead")
            instr = str(res.get("instructions") or "")[:300]
            code = re.search(r"code:\s*([A-Za-z0-9-]{4,})", instr)
            return 200, {"ok": True, "attemptID": aid, "url": url, "instructions": instr,
                         "code": code.group(1) if code else "", "mode": res.get("mode") or "",
                         "expires": (res.get("time") or {}).get("expires")}
        if path in ("/api/agent/providers/oauth/complete", "/api/agent/providers/oauth/cancel"):
            iid = str(body.get("integrationID") or "").strip()
            aid = str(body.get("attemptID") or "").strip()
            if not AGENT_INTEG_ID_RE.match(iid) or not AGENT_OBJ_ID_RE.match(aid):
                raise ValueError("integrationID and attemptID required")
            base = "/api/integration/{}/connect/oauth/{}".format(q(iid), q(aid))
            if path.endswith("/cancel"):
                try:
                    self._agent_secret_call("DELETE", base, timeout=15)
                except AgentError as exc:
                    if exc.status != 404:
                        raise
                return 200, {"ok": True}
            code = self._agent_clean_text(body.get("code"), 500)
            try:
                self._agent_secret_call("POST", base + "/complete", {"code": code or None},
                                        [code], timeout=60)
            except AgentError as exc:
                return 400, {"ok": False, "error": _agent_scrub(self._agent_err_text(exc), [code])}
            self._AGENT_INTEG_CACHE["data"] = None
            return 200, {"ok": True}
        if path == "/api/agent/providers/custom/detect":
            key = body.get("apiKey")
            key = key.strip() if isinstance(key, str) else ""
            pid = str(body.get("id") or "").strip().lower()
            if not key and AGENT_PROVIDER_ID_RE.match(pid):
                key = _agent_key_read(pid)
            try:
                ids = _agent_detect_models(body.get("baseURL"), key)
            except ValueError as exc:
                return 400, {"ok": False, "error": _agent_scrub(str(exc), [key])}
            return 200, {"ok": True, "models": ids}
        if path == "/api/agent/providers/test":
            return self._agent_provider_test(body)
        if path == "/api/agent/providers/custom":
            return self._agent_custom_save(body)
        if path == "/api/agent/providers/custom/remove":
            pid = str(body.get("id") or "").strip()
            if not AGENT_PROVIDER_ID_RE.match(pid):
                raise ValueError("Provider id required")
            with _OC_CONF_LOCK:
                conf = _oc_conf_read()
                found = False
                for block in ("providers", "provider"):
                    provs = conf.get(block)
                    if isinstance(provs, dict) and pid in provs:
                        found = True
                if not found:
                    return 404, {"ok": False, "error": "Custom provider not found"}
                m = conf.get("model")
                cur = m if isinstance(m, str) else (m.get("providerID", "") + "/" if isinstance(m, dict) else "")
                if cur.startswith(pid + "/"):
                    return 409, {"ok": False, "error": "A model of this provider is the default; "
                                                       "choose another default model first"}
                for block in ("providers", "provider"):
                    provs = conf.get(block)
                    if isinstance(provs, dict) and pid in provs:
                        del provs[pid]
                        if not provs:
                            conf.pop(block)
                _oc_conf_write(conf)
                _agent_key_remove(pid)
            self._agent_log("custom provider {} removed".format(pid))
            gone, _n = self._agent_wait_provider(pid, present=False)
            return 200, {"ok": True, "unloaded": gone}
        if path == "/api/agent/models/default":
            model = str(body.get("model") or "").strip()
            if model:
                ids = {m["id"] for m in self._agent_models_view()["models"]}
                if model not in ids:
                    raise ValueError("Model '{}' is not available".format(model[:120]))
            with _OC_CONF_LOCK:
                conf = _oc_conf_read()
                if model:
                    conf["model"] = model
                else:
                    conf.pop("model", None)
                _oc_conf_write(conf)
            self._agent_log("default model -> {}".format(model or "(automatic)"))
            eff = ""
            deadline = time.time() + 15
            while True:
                eff = self._agent_default_info().get("effective") or ""
                if not model or eff == model or time.time() >= deadline:
                    break
                time.sleep(0.5)
            return 200, {"ok": True, "configured": model, "effective": eff,
                         "applied": (not model) or eff == model}
        return 404, {"ok": False, "error": "Not found"}

    def _agent_provider_test(self, body):
        """Send one tiny prompt ("Reply with OK") through a provider in a
        throwaway session and report the outcome; opencode stores keys
        without checking them, so this is how a bad key shows up."""
        pid = str(body.get("provider") or "").strip()
        model = str(body.get("model") or "").strip()
        if not AGENT_PROVIDER_ID_RE.match(pid) and not AGENT_INTEG_ID_RE.match(pid):
            raise ValueError("provider required")
        cands = [m for m in self._agent_models_view()["models"] if m["provider"] == pid]
        if model:
            cands = [m for m in cands if m["id"] == model]
        if not cands:
            return 404, {"ok": False, "error": "No models available for '{}'".format(pid)}
        def price(m):
            c = m.get("cost") or {}
            return (c.get("input") or 0) + (c.get("output") or 0)
        pick = sorted(cands, key=price)[0]
        sess = self._agent_d(self._agent_call_raw("POST", "/api/session", {}, timeout=15)) or {}
        sid = sess.get("id") if isinstance(sess, dict) else None
        if not sid:
            return 502, {"ok": False, "error": "Could not create a test session"}
        base = "/api/session/" + urllib.parse.quote(sid)
        result = {"ok": True, "model": pick["id"], "passed": False, "message": ""}
        try:
            mp, mm = pick["id"].split("/", 1)
            self._agent_call_raw("POST", base + "/model", {"model": {"id": mm, "providerID": mp}}, timeout=15)
            self._agent_call_raw("POST", base + "/prompt",
                                 {"text": "Connection test. Reply with just: OK"}, timeout=30)
            deadline = time.time() + 60
            while time.time() < deadline:
                time.sleep(1.0)
                msgs = self._agent_d(self._agent_call_raw("GET", base + "/message", timeout=15,
                                                          log_body=False)) or []
                idle = [m for m in msgs if isinstance(m, dict) and m.get("type") == "idle"]
                if not idle:
                    continue
                err = idle[0].get("error") if isinstance(idle[0].get("error"), dict) else None
                if idle[0].get("outcome") == "succeeded" or (not err and idle[0].get("outcome") != "failed"):
                    result.update(passed=True, message="{} answered".format(pick["name"]))
                else:
                    msg = (err or {}).get("message") or idle[0].get("outcome") or "failed"
                    st = (err or {}).get("status")
                    result["message"] = "{}{}".format(str(msg)[:300], " (HTTP {})".format(st) if st else "")
                break
            else:
                result["message"] = "No answer within 60 s"
        finally:
            try:
                self._agent_call_raw("POST", base + "/interrupt", None, timeout=10)
            except AgentError:
                pass
            try:
                self._agent_call_raw("DELETE", base, timeout=15)
            except AgentError:
                pass
        return 200, result

    def _agent_custom_save(self, body):
        pid = str(body.get("id") or "").strip().lower()
        if not AGENT_PROVIDER_ID_RE.match(pid):
            raise ValueError("ID: 1-40 lowercase letters, digits, - or _ (e.g. lmstudio-pc)")
        name = self._agent_clean_text(body.get("name")) or pid
        base = _agent_check_url(body.get("baseURL"))
        key = body.get("apiKey")
        key = key.strip() if isinstance(key, str) else ""
        clear = bool(body.get("clearKey"))
        if key and not re.match(r"^[\x21-\x7e]{1,512}$", key):
            raise ValueError("API key: printable characters only, no spaces")
        raw_models = body.get("models")
        if isinstance(raw_models, str):
            raw_models = re.split(r"[\s,]+", raw_models)
        models = []
        for mid in raw_models if isinstance(raw_models, list) else []:
            mid = str(mid or "").strip()
            if not mid:
                continue
            if not AGENT_MODEL_ID_RE.match(mid):
                raise ValueError("Invalid model ID '{}'".format(mid[:80]))
            if mid not in models:
                models.append(mid)
        if not models:
            raise ValueError("Add at least one model ID (or use Detect models)")
        if len(models) > 200:
            raise ValueError("Too many models (max 200)")
        with _OC_CONF_LOCK:
            conf = _oc_conf_read()
            provs = conf.get("providers") if isinstance(conf.get("providers"), dict) else {}
            legacy = conf.get("provider") if isinstance(conf.get("provider"), dict) else {}
            existing = pid in provs or pid in legacy
            if not existing:
                try:
                    integ_ids = {i["id"] for i in self._agent_integrations()}
                    prov_ids = {p["id"] for p in self._agent_provider_list()}
                except AgentError:
                    integ_ids, prov_ids = set(), set()
                if pid in prov_ids or (pid in integ_ids and pid not in AGENT_LOCAL_RUNTIME_IDS):
                    raise ValueError("'{}' is already used by a built-in provider; choose another ID".format(pid))
            prev = provs.get(pid) or legacy.get(pid) or {}
            prev_settings = prev.get("settings") if pid in provs else prev.get("options")
            prev_settings = prev_settings if isinstance(prev_settings, dict) else {}
            prev_models = prev.get("models") if isinstance(prev.get("models"), dict) else {}
            entry = {"name": name, "package": AGENT_OPENAI_COMPAT_PKG,
                     "settings": {"baseURL": base}, "models": {}}
            for mid in models:
                pm = prev_models.get(mid)
                entry["models"][mid] = pm if isinstance(pm, dict) and pm else {"name": mid}
            keyref = ""
            if key:
                keyref = "{file:" + _agent_key_write(pid, key) + "}"
            elif not clear:
                old = prev_settings.get("apiKey")
                if isinstance(old, str) and old.startswith("{file:"):
                    keyref = old
                elif isinstance(old, str) and old and not old.startswith("{env:"):
                    keyref = "{file:" + _agent_key_write(pid, old) + "}"   # migrate plaintext
                elif isinstance(old, str) and old:
                    keyref = old
            if keyref:
                entry["settings"]["apiKey"] = keyref
            key = ""
            provs[pid] = entry
            conf["providers"] = provs
            if pid in legacy:
                del legacy[pid]
                if not legacy:
                    conf.pop("provider", None)
            _oc_conf_write(conf)
            if clear:
                _agent_key_remove(pid)
        self._agent_log("custom provider {} saved ({} models)".format(pid, len(models)))
        loaded, count = self._agent_wait_provider(pid, present=True, expect_models=models)
        return 200, {"ok": True, "id": pid, "loaded": loaded, "models": count,
                     "message": ("Saved; {} model(s) available".format(count) if loaded
                                 else "Saved, but opencode has not loaded it yet")}

    def _agent_v2_event_to_v1(self, frame):
        """Translate one V2 /api/event frame into the V1 event objects the
        dashboard's SSE handler consumes (type + properties). Returns a
        list of V1 events (usually 0-2); unknown events are dropped.

        V2 wire format (verified against a live 2.1.4 server):
            data: {"id", "created"?, "type": <name>, "location"?,
                  "data": {...}, "durable"?}
        - the event name is the frame-level "type"
        - "data" is a plain JSON object (the spec's V2EventEncoded
          string form is also tolerated)
        - ": heartbeat" comment frames are skipped by the reader."""
        if not isinstance(frame, dict):
            return []
        ev_type = frame.get("type") or frame.get("event") or ""
        data = frame.get("data")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                data = {}
        if not isinstance(data, dict):
            data = {}
        sid = data.get("sessionID") or ""

        def emit(type_name, properties):
            return {"type": type_name, "properties": properties}

        def tool_output(data):
            content = data.get("content")
            if isinstance(content, list):
                chunks = []
                for c in content:
                    if isinstance(c, dict) and c.get("type") == "text":
                        chunks.append(c.get("text") or "")
                    elif isinstance(c, str):
                        chunks.append(c)
                if chunks:
                    return "".join(chunks)
            if isinstance(data.get("output"), str):
                return data["output"]
            return ""

        def tool_part(data, state):
            # Stable identity across the V2 tool lifecycle
            # (input.started -> called -> success/failed): every phase must
            # resolve to the SAME dashboard row key (part.id, else
            # type+name), or each phase renders as a new stacked row - the
            # "30 tool calls" pileup. Remember names and inputs seen in
            # earlier phases because success/failed only carry metadata.
            tid = data.get("callID") or data.get("id") or ""
            name = data.get("tool") or data.get("name") or ""
            meta = self._AGENT_V2_TOOL_META
            entry = meta.get(tid) or {}
            if tid and name:
                entry["name"] = name
            elif tid and entry.get("name"):
                name = entry["name"]
            incoming = data.get("input")
            if tid and incoming not in (None, ""):
                entry["input"] = incoming
            if tid:
                meta[tid] = entry
            cached_input = entry.get("input")
            part = {"messageID": data.get("assistantMessageID") or "",
                    "type": "tool", "id": tid, "name": name,
                    "tool": name}
            # V1 consumers read state.input for the command/path detail.
            if state.get("input") in (None, "") and cached_input not in (None, ""):
                state["input"] = cached_input
            md = data.get("metadata")
            if md:
                state["meta"] = md
                state["metadata"] = md
            part["state"] = state
            return emit("message.part.updated", {"sessionID": sid, "part": part})

        if ev_type == "permission.asked":
            req = self._agent_v2_perm_to_v1(data)
            return [emit("permission.asked", req)]
        if ev_type == "form.created":
            form = data.get("form") or data
            props = {
                "requestID": form.get("id") or "",
                "sessionID": form.get("sessionID") or "",
                "questions": self._agent_v2_form_questions(form),
            }
            return [emit("question.v2.asked", props)]
        if ev_type == "form.replied":
            return [emit("question.replied",
                         {"requestID": (data.get("form") or data).get("id") or ""})]
        if ev_type == "form.cancelled":
            return [emit("question.rejected",
                         {"requestID": (data.get("form") or data).get("id") or ""})]
        if ev_type == "session.text.delta":
            return [emit("message.part.delta", {
                "sessionID": sid,
                "messageID": data.get("assistantMessageID") or "",
                "field": "text", "delta": data.get("delta") or ""})]
        if ev_type == "session.text.ended":
            return [emit("message.part.updated", {
                "sessionID": sid,
                "part": {"messageID": data.get("assistantMessageID") or "",
                         "type": "text", "text": data.get("text") or ""}})]
        if ev_type in ("session.reasoning.delta", "session.reasoning.ended",
                       "session.text.started", "session.reasoning.started"):
            return [emit("message.part.updated", {
                "sessionID": sid,
                "part": {"messageID": data.get("assistantMessageID") or "",
                         "type": "reasoning", "text": data.get("text") or ""}})]
        if ev_type == "session.tool.input.started":
            return [tool_part(data, {"status": "streaming", "input": ""})]
        if ev_type == "session.tool.called":
            return [tool_part(data, {"status": "running",
                                     "input": data.get("input") or ""})]
        if ev_type == "session.tool.progress":
            state = {"status": "running", "output": tool_output(data)}
            return [tool_part(data, state)]
        if ev_type == "session.tool.success":
            state = {"status": "completed"}
            out = tool_output(data)
            if out:
                state["output"] = out
            md = data.get("metadata") or frame.get("metadata")
            if md:
                state["meta"] = md
            return [tool_part(data, state)]
        if ev_type == "session.tool.failed":
            err = data.get("error") or "tool failed"
            if isinstance(err, dict):
                err = err.get("message") or json.dumps(err)
            return [tool_part(data, {"status": "error", "error": str(err)})]
        if ev_type == "session.usage.updated":
            # info.id MUST be the assistant message id when present, else
            # omitted entirely: the dashboard stores it as assistantMsgID
            # and drops every part/delta whose messageID differs. A
            # fabricated id (e.g. the session id) suppresses the whole
            # response text - that exact bug shipped in the first pass.
            info = {"role": "assistant", "tokens": data.get("tokens") or {},
                    "cost": data.get("cost") or 0}
            if data.get("assistantMessageID"):
                info["id"] = data["assistantMessageID"]
            return [emit("message.updated", {"sessionID": sid, "info": info})]
        if ev_type == "session.execution.failed":
            err = data.get("error") or {}
            return [
                emit("message.updated", {
                    "sessionID": sid,
                    "info": {"role": "assistant",
                             "error": {"message": (err.get("message") if isinstance(err, dict)
                                                   else str(err)) or "execution failed"}}}),
                emit("session.idle", {"sessionID": sid}),
            ]
        if ev_type in ("session.execution.succeeded", "session.execution.interrupted"):
            return [emit("session.idle", {"sessionID": sid})]
        return []

    def _agent_events_sse(self):
        """Proxy opencode's SSE event stream to the browser, live.

        V1 agent: verbatim passthrough (the browser already speaks V1).
        V2 agent: frames are translated into the V1 event shapes the
        dashboard consumes, one SSE data line per emitted event."""
        import base64
        v2 = False
        try:
            v2 = self._agent_is_v2()
        except AgentError:
            pass
        url = self.AGENT_BASE + ("/api/event" if v2 else "/event")
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

        def emit_v1(obj):
            body = json.dumps(obj).encode()
            self.wfile.write(b"data: " + body + b"\n\n")
            self.wfile.flush()

        try:
            if not v2:
                for raw in upstream:
                    self.wfile.write(raw if isinstance(raw, bytes) else raw.encode())
                    self.wfile.flush()
            else:
                # Parse V2 SSE frames: "data: {json}" lines; each frame is
                # {"id"?, "event", "data"(<json string>)}.
                buf = b""
                while True:
                    chunk = upstream.readline()
                    if not chunk:
                        break
                    line = chunk.decode("utf-8", "replace").strip()
                    if not line.startswith("data:"):
                        continue
                    data_str = line[5:].strip()
                    try:
                        frame = json.loads(data_str)
                    except ValueError:
                        continue
                    if not isinstance(frame, dict):
                        continue
                    for ev in self._agent_v2_event_to_v1(frame):
                        emit_v1(ev)
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

    def _send_asset(self, path):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as exc:
            self._send(404, {"ok": False, "error": str(exc)})
            return
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path, download_name, content_type="application/gzip", extra_headers=None):
        # Streamed in 1 MB chunks: archives are not read into memory.
        with open(path, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format(download_name))
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra_headers or {}).items():
                if v:
                    self.send_header(k, v)
            self.end_headers()
            shutil.copyfileobj(f, self.wfile, 1048576)

    def _send_bytes(self, data, download_name, content_type="application/gzip"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
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

    def _backup_post(self, path, body, raw, identity):
        """POST /api/backups/system/{create,restore-file,restore-files,
        preview-many,service-action,import-firewall,sanitize,upload,delete,
        pin,verify,settings,encryption,usb-copy,usb-check} (admin-only via
        the default-deny gate). Passphrases are never logged or echoed."""
        who = (identity or {}).get("username", "")
        client = _client_key(self)
        try:
            if path == "/api/backups/system/create":
                res = create_system_backup(body.get("include"), who=who)
            elif path == "/api/backups/system/restore-file":
                res = restore_system_backup_member(
                    body.get("name"), body.get("file"), who=who, client=client,
                    confirm_strict=bool(body.get("confirm_strict") or body.get("confirm_code_replace")),
                    expect_new=body.get("expect_sha256"), expect_old=body.get("expect_live_sha256"))
            elif path == "/api/backups/system/import-firewall":
                res = import_system_backup_firewall(body.get("name"), identity, client)
            elif path == "/api/backups/system/sanitize":
                res = sanitize_system_backup(body.get("name"), who=who)
            elif path == "/api/backups/system/upload":
                pw = self.headers.get("X-Backup-Passphrase") or ""
                res = upload_system_backup(raw, who=who,
                                           passphrase=urllib.parse.unquote(pw, errors="strict") if pw else None)
            elif path == "/api/backups/system/preview-many":
                res = preview_system_restore_many(body.get("name"), body.get("files"), body.get("service"))
            elif path == "/api/backups/system/restore-files":
                res = restore_system_backup_many(body.get("name"), body.get("files"), who=who, client=client,
                                                 confirm_strict=bool(body.get("confirm_strict")))
            elif path == "/api/backups/system/service-action":
                res = backup_service_action(body.get("unit"), confirm_critical=bool(body.get("confirm_critical")),
                                            who=who, client=client)
            elif path == "/api/backups/system/verify":
                res = verify_system_backup(body.get("name"))
            elif path == "/api/backups/system/settings":
                res = backup_settings_save(body, who=who)
            elif path == "/api/backups/system/encryption":
                res = backup_encryption_save(body, who=who)
            elif path == "/api/backups/system/usb-copy":
                res = backup_usb_copy(body, who=who)
            elif path == "/api/backups/system/usb-check":
                res = backup_usb_check()
            elif path == "/api/backups/system/delete":
                res = delete_system_backup((body.get("name") or "").strip(), who=who, client=client)
            elif path == "/api/backups/system/pin":
                _bk_required()
                res = {"ok": True, "pinned": _bk.set_pinned("", body.get("name"), bool(body.get("pinned", True)),
                                                            who=who)}
            else:
                self._send(404, {"ok": False, "error": "Not found"})
                return
        except Exception as exc:
            if _bk is not None and isinstance(exc, _bk.Refused):
                self._send(exc.status, exc.payload)
            elif isinstance(exc, FileNotFoundError):
                self._send(404, {"ok": False, "error": str(exc)})
            elif isinstance(exc, ValueError):
                self._send(400, {"ok": False, "error": str(exc)})
            else:
                print("[backup] %s failed: %r" % (path, exc), flush=True)
                self._send(500, {"ok": False, "error": str(exc)})
            return
        self._send(200, res)

    def do_GET(self):
        path = self.path.split("?")[0]
        agent_ro = None
        if self.headers.get(AGENT_API_TOKEN_HEADER) is not None:
            agent_ro = _agent_ro_identity(self, path)
            if agent_ro is None:
                return
        if path == "/api/agent/events":
            identity = _session_identity(self.headers)
            if identity is None:
                self._send(401, {"ok": False, "error": "Authentication required"})
                return
            # Handled before the ADMIN_GET_PREFIXES gate below, so it needs
            # its own check: this stream carries the agent's command output.
            if not _is_admin(identity):
                self._send(403, {"ok": False, "error": "Administrator role required"})
                return
            self._agent_events_sse()
            return
        if path == "/api/auth/session":
            self._send(200, auth_session_state(_session_identity(self.headers)))
            return
        if agent_ro is not None:
            identity = agent_ro
        else:
            identity = _session_identity(self.headers) if path.startswith("/api/") else None
        if path.startswith("/api/") and identity is None:
            self._send(401, {"ok": False, "error": "Authentication required"})
            return
        if (path.startswith(ADMIN_GET_PREFIXES) and not _is_admin(identity)):
            self._send(403, {"ok": False, "error": "Administrator role required"})
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
        elif path == "/api/firewall/managed":
            code, res = fw_managed_view(_client_key(self))
            self._send(code, res)
        elif path in ("/api/firewall/findings", "/api/firewall/suggestions"):
            code, res = fw_findings_view(path.rsplit("/", 1)[-1], _client_key(self))
            self._send(code, res)
        elif path == "/api/firewall/hits":
            code, res = fw_hits_view()
            self._send(code, res)
        elif path == "/api/firewall/disabled":
            code, res = fw_disabled_view()
            self._send(code, res)
        elif path == "/api/firewall/plan":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            code, res = fw_plan_view({k: v[0] for k, v in qs.items()}, _client_key(self))
            self._send(code, res)
        elif path.startswith("/api/firewall/snapshots"):
            code, res = fw_snapshot_get(path, identity, _client_key(self))
            if isinstance(res, tuple) and res and res[0] == "__bytes__":
                self._send_bytes(res[1], res[2])
            else:
                self._send(code, res)
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
        elif path == "/api/security/zeek":
            self._send(200, build_zeek())
        elif path == "/api/security/zeek/quic":
            self._send(200, build_zeek_quic())
        elif path == "/api/security/aide":
            self._send(200, build_aide())
        elif path == "/api/security/honeypot":
            self._send(200, build_honeypot())
        elif path == "/api/security/deception":
            self._send(200, {"ok": True, "bans_24h": deception_bans_24h()})
        elif path == "/api/security/canary":
            self._send(200, build_canary())
        elif path == "/api/security/tripwire":
            self._send(200, tripwire_status())
        elif path == "/api/security/tripwire/history":
            try:
                self._send(200, tripwire_history(
                    urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
        elif path == "/api/security/tripwire/recovery":
            try:
                self._send(200, self._tripwire_recovery_preview(identity))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)[:200]})
        elif path == "/api/agent/models":
            try:
                if self._agent_is_v2():
                    self._send(200, self._agent_models_view())
                    return
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
                                 "default": _agent_redact(data.get("default") or {}),
                                 "configured": configured})
            except Exception as exc:
                self._send(500, self._agent_error(exc))
        elif path.startswith("/api/agent/providers"):
            try:
                if not self._agent_is_v2():
                    self._send(501, {"ok": False, "error": "Provider management needs the opencode 2.x agent"})
                    return
                code, res = self._agent_providers_get(path)
                self._send(code, res)
            except Exception as exc:
                self._send(502, {"ok": False, "error": str(exc)[:500]})
        elif path == "/api/agent/status":
            try:
                health = self._agent_call("GET", "/global/health", timeout=5)
                self._send(200, {"ok": True, "installed": True, "server": health})
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
        elif path == "/api/agent/question":
            # The dashboard POLLS this with GET (its only route lived in
            # do_POST, so the poll 404'd forever and question recovery
            # silently never worked - cards rendered from SSE alone).
            try:
                data = self._agent_call("GET", "/question")
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
                out["config"] = _agent_redact(self._agent_call("GET", "/config", timeout=10) or {})
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
        elif path == "/api/crowdsec/ban-state":
            self._send(200, build_crowdsec_ban_state())
        elif path == "/api/plugins":
            self._send(200, list_plugins())
        elif path == "/api/plugins/available":
            # NOTE: GET route (the dashboard fetches this); the twin
            # registration lives in do_POST next to install_plugin_from_github
            # - registering it there only made it 404 here (the generic
            # /api/plugins/ pattern swallowed it). Keep this one canonical.
            try:
                catalog = build_plugin_catalog()
                installed = {}
                for p in ((list_plugins() or {}).get("plugins") or []):
                    if p.get("id"):
                        installed[p["id"]] = str(p.get("version") or "")
                for entry in (catalog.get("plugins") or []):
                    pid = entry.get("id")
                    entry["installed"] = pid in installed
                    if entry["installed"] and installed[pid]:
                        # semver-ish: "Update" when the catalog version
                        # is newer than what's on the box
                        try:
                            def vt(v):
                                return [int(x) for x in str(v).split(".")]
                            entry["update"] = vt(entry.get("version") or "0") > vt(installed[pid])
                        except (ValueError, TypeError):
                            entry["update"] = str(entry.get("version") or "") != installed[pid]
                    else:
                        entry["update"] = False
                self._send(200, catalog)
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
        elif path.startswith("/api/plugins/"):
            rest = path[len("/api/plugins/"):]
            parts = rest.split("/")
            pid = parts[0]
            try:
                if len(parts) >= 3 and parts[1] == "asset":
                    rel = urllib.parse.unquote("/".join(parts[2:]))
                    self._send_asset(plugin_asset_path(pid, rel))
                elif len(parts) == 2 and parts[1] == "config":
                    self._send(200, _plugin_config_public(pid))
                else:
                    self._send(404, {"ok": False, "error": "plugin route not found"})
            except FileNotFoundError:
                self._send(404, {"ok": False, "error": "plugin asset not found"})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
        elif path == "/api/incidents":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            self._send(200, build_incidents((qs.get("limit") or ["120"])[0]))
        elif path == "/api/alerts/config":
            self._send(200, {"ok": True, "config": _load_alert_config()})
        elif path == "/api/crowdsec/community-bans":
            self._send(200, build_community_bans())
        elif path == "/api/crowdsec/reporting/status":
            self._send(200, community_reporting_status())
        elif path == "/api/community/settings":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                self._send(200, community_settings_view(
                    force_status=(qs.get("refresh") or [""])[0] == "1"))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)[:200]})
        elif path == "/api/bandwidth":
            self._send(200, build_bandwidth())
        elif path == "/api/blocklists":
            self._send(200, build_blocklists())
        elif path == "/api/blocklists/catalog":
            self._send(200, build_blocklist_catalog())
        elif path == "/api/rpz":
            self._send(200, build_rpz())
        elif path == "/api/system":
            self._send(200, build_system())
        elif path == "/api/system/fastfetch":
            self._send(200, build_fastfetch())
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
        elif path == "/api/insights/history":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            self._send(200, get_insights_history().series(qs.get("range", ["1h"])[0]))
        elif path == "/api/baselines":
            self._send(200, load_baselines())

        elif path == "/api/sqm":
            try:
                self._send(200, sqm_status())
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
        elif path == "/api/sqm/speedtest/status":
            self._send(200, sqm_speedtest_status())

        elif path == "/api/dhcp/subnets":
            try:
                self._send(200, list_dhcp_subnets())
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path in LEGACY_BACKUP_PATHS:
            self._send(410, LEGACY_BACKUP_GONE)

        elif path == "/api/backups/system":
            self._send(200, system_backup_status())

        elif path == "/api/backups/system/items":
            try:
                self._send(200, system_backup_items())
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/system/preview":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                self._send(200, preview_system_restore((qs.get("name") or [""])[0],
                                                       (qs.get("file") or [""])[0]))
            except Exception as exc:
                if _bk is not None and isinstance(exc, _bk.Refused):
                    self._send(exc.status, exc.payload)
                elif isinstance(exc, ValueError):
                    self._send(400, {"ok": False, "error": str(exc)})
                else:
                    self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/system/audit":
            self._send(200, {"ok": True, "entries": _bk.audit_tail("", 100) if _bk else []})

        elif path == "/api/backups/system/usb":
            if _bk is None:
                self._send(500, {"ok": False, "error": "Backup module unavailable"})
            else:
                self._send(200, dict(_usb_status(force=True), ok=True))

        elif path == "/api/backups/system/contents":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            name = (qs.get("name") or [None])[0] or ""
            try:
                self._send(200, system_backup_contents(name))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/system/file":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            name = (qs.get("name") or [None])[0] or ""
            member = (qs.get("file") or [None])[0] or ""
            try:
                mname, data = download_system_backup_member(name, member)
                fname = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(mname)) or "file"
                self._send_bytes(data, fname, "application/octet-stream")
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/backups/system/download":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            name = (qs.get("name") or [None])[0] or ""
            base = os.path.basename(name)
            if not (SYSTEM_BACKUP_RE.match(base) or SANITIZED_RE.match(base)
                    or UPLOADED_RE.match(base)):
                self._send(400, {"ok": False, "error": "Invalid system backup name"})
                return
            fpath = os.path.join(SYSTEM_BACKUP_DIR, base)
            if not os.path.isfile(fpath):
                self._send(404, {"ok": False, "error": "System backup not found"})
                return
            # Everything that leaves the box is encrypted once a passphrase is
            # set (sanitized exports are meant for sharing and stay plain).
            pw = _bk.read_passphrase() if (_bk is not None and not SANITIZED_RE.match(base)) else None
            if not pw:
                self._send_file(fpath, base)
                return
            tmp = None
            try:
                integ = _bk.check_integrity("", base, fpath)
                if integ["status"] == "damaged":
                    self._send(409, {"ok": False, "error": "This backup is damaged (%s); not downloaded"
                                                           % _bk.integrity_summary(integ)})
                    return
                tmp = _bk.encrypted_copy("", fpath, pw)
                _bk.audit("", "download", who=(identity or {}).get("username", ""), client=_client_key(self),
                          archive=base, encrypted=True)
                self._send_file(tmp, base + ".gpg", content_type="application/pgp-encrypted",
                                extra_headers={"X-Backup-SHA256": integ.get("sha256") or ""})
            except Exception as exc:
                print("[backup] encrypted download failed: %r" % exc, flush=True)
                self._send(500, {"ok": False, "error": "Encrypting the download failed: %s" % exc})
            finally:
                if tmp:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass

        elif path == "/api/reservations":
            self._send(200, build_reservations())

        elif path == "/api/portforward":
            self._send(200, build_portforward())

        elif path == "/api/dmz":
            self._send(200, build_dmz())

        elif path == "/api/vlans":
            self._send(200, build_vlans())

        elif path in ("/api/interfaces", "/api/interfaces/policy", "/api/interfaces/vlans", "/api/interfaces/lock"):
            self._send(*interfaces_get(path, self.path))

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

        elif path == "/api/system/dhcp-form":
            try:
                self._send(200, get_dhcp_form())
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/system/unbound-form":
            try:
                self._send(200, get_unbound_form())
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/themes":
            self._send(200, list_themes())

        elif path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"ok": False, "error": "Not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if self.headers.get(AGENT_API_TOKEN_HEADER) is not None:
            self._send(403, {"ok": False, "error": "The agent read token is GET-only"})
            return
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        # Lightweight CSRF check: when the browser sends Origin/Referer, its
        # host must match the Host we were reached on. Same-origin dashboard
        # traffic is unaffected; cross-site form posts are rejected.
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if origin and path.startswith("/api/"):
            try:
                o_host = urllib.parse.urlsplit(origin).hostname or ""
            except Exception:
                o_host = ""
            h_host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
            if o_host and o_host.lower() != h_host:
                self._send(403, {"ok": False, "error": "Cross-site request rejected"})
                return
        length = int(self.headers.get("Content-Length") or 0)
        raw = b""
        body = {}
        if length:
            maxlen = 104857600 if path == "/api/backups/system/upload" else 262144
            if path == "/api/firewall/snapshots/upload":
                maxlen = 4 * 1024 * 1024
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
            cookie = _session_cookie_value(
                self.headers,
                _create_session(result["username"], result.get("role", "viewer")),
            )
            self._send_auth(200, result, cookie=cookie)
            return

        if path == "/api/auth/logout":
            _drop_session(self.headers)
            self._send_auth(200, {"ok": True}, clear_cookie=True)
            return

        if path == "/api/auth/setup":
            ip = _client_key(self)
            try:
                result = setup_first_admin(body, ip)
            except PermissionError as exc:
                self._send_auth(403, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self._send_auth(400, {"ok": False, "error": str(exc)})
                return
            except Exception:
                self._send_auth(500, {"ok": False, "error": "Setup failed"})
                return
            cookie = _session_cookie_value(
                self.headers,
                _create_session(result["username"], "admin"),
            )
            self._send_auth(200, result, cookie=cookie)
            return

        # OpenCanary webhook: loopback-only, token-gated, no session auth.
        if path == "/api/canary/hit":
            if _client_key(self) not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                self._send(403, {"ok": False, "error": "Forbidden"})
                return
            if not hmac.compare_digest(qs.get("token", [""])[0] or "",
                                       ensure_canary_token()):
                self._send(403, {"ok": False, "error": "Forbidden"})
                return
            self._send(200, handle_canary_hit(body))
            return

        # Internal self-restart: trusted-local (loopback + internal token)
        # or an admin session. 2026-11-03 audit: the old check trusted the
        # peer IP alone, so any local process (SSRF from the co-hosted
        # public forum, malware) reached this unauthenticated.
        if path == "/api/system/self-restart":
            ident_sr = _session_identity(self.headers)
            if not _is_trusted_local(self) and not _is_admin(ident_sr):
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
            # without a browser session. 2026-11-03 audit: requires the
            # internal token, not just a loopback peer (SSRF defense).
            if path == "/api/blocklists/update" and _is_trusted_local(self):
                identity = {"username": "system-timer", "role": "admin", "owner": False}
            else:
                self._send(401, {"ok": False, "error": "Authentication required"})
                return

        # Default-deny role gate. Everything that changes state, reads
        # credentials, or reaches the AI agent requires an admin; viewers are
        # limited to the self-service account actions listed above.
        if path.startswith("/api/") and not _is_admin(identity):
            if path not in VIEWER_POST_PATHS:
                self._send(403, {"ok": False, "error": "Administrator role required"})
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

        if path == "/api/sqm":
            try:
                self._send(200, sqm_apply(body.get("up_mbit"), body.get("down_mbit"),
                                          (body.get("wan") or "").strip() or None))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
            return

        if path == "/api/sqm/speedtest/start":
            try:
                self._send(200, sqm_speedtest_start())
            except ValueError as exc:
                self._send(409, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
            return

        if path == "/api/dhcp/subnets":
            try:
                self._send(200, save_dhcp_subnet(body or {}))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
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
                if _fw_edit is not None and _fw_guard is not None:
                    _fw_guard_run(lambda cur: _fw_edit.propose_insert(
                        cur, None, "deny from %s to any" % ip, before=1)[0], _client_key(self), "ban %s" % ip)
                    _fw_autosnap("ban %s" % ip, identity)
                changed = ban_client(ip, body.get("hostname") or "", body.get("mac") or "")
            except _FwRefused as exc:
                self._send(exc.status, exc.payload)
                return
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

        elif path == "/api/rpz/add":
            result = add_rpz_entry(
                body.get("domain") or "",
                (body.get("action") or "").strip(),
                body.get("target") or "",
                body.get("note") or "",
                (body.get("match") or "").strip() or None,
            )
            self._send(200 if result.get("ok") else 400, result)

        elif path == "/api/rpz/import":
            self._send(200, rpz_import(body.get("text") or ""))

        elif path == "/api/rpz/remove":
            result = remove_rpz_entry(body.get("domain") or "")
            self._send(200 if result.get("ok") else 400, result)

        elif path == "/api/rpz/apply":
            try:
                apply_rpz()
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
            self._send(200, {"ok": True, "message": "RPZ zone applied and Unbound reloaded"})

        elif path == "/api/rpz/feed/add":
            result = add_rpz_feed(body.get("url") or "", body.get("name") or "")
            self._send(200 if result.get("ok") else 400, result)

        elif path == "/api/rpz/feed/refresh":
            try:
                result = refresh_rpz_feeds()
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
            self._send(200, result)

        elif path == "/api/rpz/feed/remove":
            result = remove_rpz_feed(body.get("url") or "")
            self._send(200 if result.get("ok") else 400, result)

        elif path == "/api/rpz/feed/toggle":
            result = toggle_rpz_feed(body.get("url") or "")
            self._send(200 if result.get("ok") else 400, result)

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

        elif path in ("/api/firewall/allow", "/api/firewall/delete", "/api/firewall/move",
                      "/api/firewall/enable", "/api/firewall/default", "/api/firewall/logging"):
            cip = _client_key(self)
            _fw_autosnap(path.rsplit("/", 1)[-1], identity)
            try:
                if path == "/api/firewall/allow":
                    res = add_firewall_rule(body.get("rule") or "", client_ip=cip)
                elif path == "/api/firewall/delete":
                    res = delete_firewall_rule(body, client_ip=cip)
                elif path == "/api/firewall/move":
                    spec = body if body.get("to") and body.get("action") and body.get("from") else None
                    res = move_firewall_rule(body.get("number"), body.get("direction"),
                                             expected_spec=spec, client_ip=cip)
                elif path == "/api/firewall/enable":
                    res = set_firewall_enabled(bool(body.get("enabled")))
                elif path == "/api/firewall/default":
                    res = set_firewall_default(body.get("direction"), body.get("policy"), client_ip=cip)
                else:
                    res = set_firewall_logging(body.get("level"))
                self._send(200, res)
            except _FwRefused as exc:
                self._send(exc.status, exc.payload)
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/firewall/apply":
            code, res = fw_apply(body, identity, _client_key(self))
            self._send(code, res)

        elif path == "/api/firewall/confirm":
            cid = str(body.get("id") or "")
            if _fw_snap is not None:
                _fw_snap.confirmed(cid)
            try:
                self._send(200, confirm_fw_change(cid))
            except Exception as exc:
                self._send(409, {"ok": False, "error": str(exc)})

        elif path == "/api/firewall/reset":
            # Legacy Save/Restore baseline buttons: "save" now records a manual
            # snapshot (the Sep 1 /etc/tuxwall/fw-baseline is kept untouched);
            # "restore" goes through the guarded snapshot flow.
            action = (body.get("action") or "").lower()
            if action == "save":
                code, res = fw_snapshot_post("/api/firewall/snapshots",
                                             {"note": "Saved with the Rules tab button"},
                                             identity, _client_key(self))
                self._send(code, res)
            elif action == "restore":
                _fw_autosnap("legacy restore", identity)
                code, res = fw_legacy_restore(identity, _client_key(self))
                self._send(code, res)
            else:
                self._send(400, {
                    "ok": False,
                    "error": "unknown action; use 'save' or 'restore'",
                })

        elif path.startswith("/api/firewall/snapshots"):
            code, res = fw_snapshot_post(path, body, identity, _client_key(self))
            self._send(code, res)

        elif path == "/api/crowdsec/ban":
            try:
                self._send(200, ban_crowdsec_ip(body.get("ip"), body.get("duration")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
        elif path == "/api/community/settings":
            # same-origin was checked above when Origin/Referer is present;
            # this switch also refuses a POST that carries neither
            if not (self.headers.get("Origin") or self.headers.get("Referer")):
                self._send(403, {"ok": False, "error": "Origin header required"})
                return
            try:
                self._send(200, community_settings_update(body, identity, _client_key(self)))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)[:200]})
        elif path == "/api/crowdsec/reporting/register":
            try:
                self._send(200, community_reporting_register())
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
        elif path == "/api/crowdsec/community-bans/auto":
            try:
                self._send(200, set_community_auto(bool(body.get("enabled"))))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/crowdsec/unban":
            try:
                self._send(200, unban_crowdsec_ip(body.get("ip")))
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/plugins/install":
            try:
                self._send(200, install_plugin_from_github(body, identity.get("username", "")))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
        elif path == "/api/plugins/available":
            try:
                catalog = build_plugin_catalog()
                installed = {}
                for p in ((list_plugins() or {}).get("plugins") or []):
                    if p.get("id"):
                        installed[p["id"]] = str(p.get("version") or "")
                for entry in (catalog.get("plugins") or []):
                    pid = entry.get("id")
                    entry["installed"] = pid in installed
                    if entry["installed"] and installed[pid]:
                        # semver-ish: "Update" when the catalog version
                        # is newer than what's on the box
                        try:
                            def vt(v):
                                return [int(x) for x in str(v).split(".")]
                            entry["update"] = vt(entry.get("version") or "0") > vt(installed[pid])
                        except (ValueError, TypeError):
                            entry["update"] = str(entry.get("version") or "") != installed[pid]
                    else:
                        entry["update"] = False
                self._send(200, catalog)
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path.startswith("/api/plugins/"):
            m = re.match(r"^/api/plugins/([a-z][a-z0-9-]{1,31})/(enable|config|action|uninstall|pin)$", path)
            if not m:
                self._send(404, {"ok": False, "error": "plugin route not found"})
                return
            pid, action = m.group(1), m.group(2)
            try:
                if action == "enable":
                    self._send(200, _plugin_save_config(pid, {"enabled": bool(body.get("enabled"))}))
                elif action == "config":
                    self._send(200, _plugin_save_config(pid, body))
                elif action == "uninstall":
                    self._send(200, uninstall_plugin(pid))
                elif action == "pin":
                    self._send(200, plugin_repin(pid, body, identity.get("username", "")))
                else:
                    result = plugin_action(pid, body.get("action") or "", body.get("payload") or {})
                    self._send(200, result)
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/incidents/ack":
            try:
                self._send(200, _ack_incident(body.get("id"), identity.get("username", "")))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})

        elif path == "/api/incidents/ack-all":
            self._send(200, _ack_incidents(all_active=True, user=identity.get("username", "")))

        elif path == "/api/incidents/dismiss":
            try:
                self._send(200, _dismiss_incident(body.get("id")))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})

        elif path == "/api/alerts/config":
            try:
                self._send(200, save_alert_config(body))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})

        elif path == "/api/alerts/test":
            self._send(200, test_alert_config())

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

        elif path == "/api/security/canary/config":
            result = set_canary_enabled(bool(body.get("enabled")))
            self._send(200 if result.get("ok") else 400, result)

        elif path in ("/api/security/tripwire/config", "/api/security/tripwire/resolve",
                      "/api/security/tripwire/checks", "/api/security/tripwire/test",
                      "/api/security/tripwire/recovery/start",
                      "/api/security/tripwire/recovery/extend",
                      "/api/security/tripwire/recovery/end",
                      "/api/security/tripwire/recovery/brief"):
            # errors used to escape the handler (dropped connection, so the
            # dashboard never showed "Password is incorrect")
            try:
                if path.endswith("/recovery/start"):
                    self._send(200, self._tripwire_recovery_start(body, identity,
                                                                  _client_key(self)))
                elif path.endswith("/recovery/extend"):
                    self._send(200, tripwire_recovery_extend(body, identity, _client_key(self)))
                elif path.endswith("/recovery/end"):
                    self._send(200, tripwire_recovery_end(identity, _client_key(self)))
                elif path.endswith("/recovery/brief"):
                    self._send(200, dict(self._tripwire_brief(identity), ok=True))
                elif path.endswith("/config") and "mode" in body:
                    self._send(200, tripwire_set_mode(body, identity, _client_key(self)))
                elif path.endswith("/config"):
                    self._send(200, tripwire_configure(body, identity, _client_key(self)))
                elif path.endswith("/checks"):
                    self._send(200, tripwire_configure(body, identity, _client_key(self),
                                                       keys=("checks",)))
                elif path.endswith("/test"):
                    self._send(200, tripwire_test(body))
                else:
                    self._send(200, tripwire_resolve(body, identity, _client_key(self)))
            except TripwireConfirmRequired as exc:
                self._send(409, {"ok": False, "confirm_required": True, "error": str(exc)})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except PermissionError as exc:
                self._send(403, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)[:200]})

        elif path == "/api/security/honeypot/config":
            self._send(200, set_honeypot_conf(body))

        elif path == "/api/security/aide/check":
            self._send(200, start_aide_run("check"))

        elif path == "/api/security/aide/update":
            self._send(200, start_aide_run("update"))


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

        elif path in LEGACY_BACKUP_PATHS:
            self._send(410, LEGACY_BACKUP_GONE)

        elif path.startswith("/api/backups/system/"):
            self._backup_post(path, body, raw, identity)

        elif path in ("/api/system/kea-config", "/api/system/unbound-config"):
            kind = "kea" if path.endswith("kea-config") else "unbound"
            try:
                self._send(200, {"ok": True, **write_config(kind, body.get("content") or "")})
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/system/dhcp-form":
            try:
                self._send(200, save_dhcp_form(body or {}))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/system/unbound-form":
            try:
                self._send(200, save_unbound_form(body or {}))
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/agent/status":
            try:
                health = self._agent_call("GET", "/global/health", timeout=5)
                self._send(200, {"ok": True, "installed": True, "server": health})
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
                                 "default": _agent_redact(data.get("default") or {}),
                                 "configured": configured})
            except Exception as exc:
                self._send(500, self._agent_error(exc))

        elif path.startswith("/api/agent/providers") or path == "/api/agent/models/default":
            # key/provider management: admin-only via the default-deny gate
            # above (same rule as every /api/agent route); never logs bodies
            try:
                if not self._agent_is_v2():
                    self._send(501, {"ok": False, "error": "Provider management needs the opencode 2.x agent"})
                    return
                code, res = self._agent_providers_post(path, body)
                self._send(code, res)
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)[:400]})
            except AgentError as exc:
                self._send(502, {"ok": False, "error": self._agent_err_text(exc)})
            except Exception as exc:
                self._agent_log("provider admin {} failed: {}".format(path, type(exc).__name__))
                self._send(500, {"ok": False, "error": "Internal error ({})".format(type(exc).__name__)})
            finally:
                body = None

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
                if model and self._agent_is_v2():
                    try:
                        self._agent_v2_apply_model(session_id, model)
                    except AgentError as exc:
                        self._send(400, {"ok": False,
                                         "error": "Could not switch to model {}: {}".format(
                                             model, self._agent_err_text(exc))})
                        return
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
                if model and self._agent_is_v2():
                    self._agent_v2_apply_model(session_id, model)
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

        elif path == "/api/system/hostname":
            try:
                new_name = set_hostname((body.get("hostname") or "").strip())
            except ValueError as exc:
                self._send(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})
                return
            self._send(200, {"ok": True, "hostname": new_name})

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
                _fw_nat_guard("portforward/add", body, identity)
                self._send(200, add_portforward(body))
            except _FwRefused as exc:
                self._send(exc.status, exc.payload)
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/portforward/delete":
            try:
                _fw_nat_guard("portforward/delete", body, identity)
                self._send(200, delete_portforward(body))
            except _FwRefused as exc:
                self._send(exc.status, exc.payload)
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/portforward/toggle":
            try:
                _fw_nat_guard("portforward/toggle", body, identity)
                self._send(200, toggle_portforward(body))
            except _FwRefused as exc:
                self._send(exc.status, exc.payload)
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/dmz/enable":
            try:
                _fw_nat_guard("dmz/enable", body, identity)
                self._send(200, enable_dmz(body))
            except _FwRefused as exc:
                self._send(exc.status, exc.payload)
            except (ValueError, subprocess.CalledProcessError) as exc:
                self._send(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send(500, {"ok": False, "error": str(exc)})

        elif path == "/api/dmz/disable":
            try:
                _fw_nat_guard("dmz/disable", body, identity)
                self._send(200, disable_dmz(body))
            except _FwRefused as exc:
                self._send(exc.status, exc.payload)
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

        elif path == "/api/interfaces/plan":
            self._send(*interfaces_plan(body, _client_key(self)))

        elif path in ("/api/interfaces/apply", "/api/interfaces/confirm", "/api/interfaces/rollback"):
            self._send(*interfaces_apply(path.rsplit("/", 1)[1], body, identity, _client_key(self)))

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

UNBOUND_RSYSLOG_RULE = "/etc/rsyslog.d/45-tuxwall-unbound.conf"
UNBOUND_RSYSLOG_CONTENT = (
    "# TuxWall 2026-11-03: unbound's always_nxdomain block notifications feed\n"
    "# the dashboard Traffic Monitor via JOURNALD (journalctl -u unbound), not\n"
    "# from this file. Duplicating them into /var/log/syslog wrote ~583k\n"
    "# lines/day of noise for nothing. Drop them here; journald is unaffected\n"
    "# (and rate/size-capped by systemd).\n"
    "if $programname == 'unbound' and $msg contains 'always_nxdomain' then stop\n"
)


def _ensure_unbound_local_actions():
    """Keep log-local-actions on (the Traffic Monitor reads block events from
    journald) while keeping the resulting syslog noise suppressed via an
    rsyslog drop rule. Idempotent: only writes/reloads what is missing."""
    wrote_conf = False
    if not os.path.exists(UNBOUND_LOCAL_ACTIONS_CONF):
        try:
            with open(UNBOUND_LOCAL_ACTIONS_CONF, "w") as f:
                f.write("server:\n    log-local-actions: yes\n")
            wrote_conf = True
        except Exception:
            pass
    if not os.path.exists(UNBOUND_RSYSLOG_RULE):
        try:
            os.makedirs(os.path.dirname(UNBOUND_RSYSLOG_RULE), exist_ok=True)
            with open(UNBOUND_RSYSLOG_RULE, "w") as f:
                f.write(UNBOUND_RSYSLOG_CONTENT)
            subprocess.run(["systemctl", "restart", "rsyslog"],
                           capture_output=True, text=True, timeout=10)
        except Exception:
            pass
    if wrote_conf:
        try:
            subprocess.run(["unbound-control", "reload"],
                           capture_output=True, text=True, timeout=10)
        except Exception:
            pass

_TRAFFIC_CACHE = {"ts": 0, "data": None}
_TRAFFIC_CACHE_TTL = 5  # seconds; one snapshot shared by all tabs/pollers
_TRAFFIC_CACHE_LOCK = threading.Lock()


def build_traffic_monitor():
    """Return merged, time-sorted traffic events from UFW log + Unbound local-actions."""
    now = time.time()
    with _TRAFFIC_CACHE_LOCK:
        if _TRAFFIC_CACHE["data"] is not None and now - _TRAFFIC_CACHE["ts"] < _TRAFFIC_CACHE_TTL:
            return _TRAFFIC_CACHE["data"]
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

    result = {"ok": True, "entries": entries}
    with _TRAFFIC_CACHE_LOCK:
        _TRAFFIC_CACHE["ts"] = time.time()
        _TRAFFIC_CACHE["data"] = result
    return result


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
            # Also check custom blocklist file (exact line match — a
            # substring test would false-positive, e.g. ample.com in
            # example.com, and match #-commented lines)
            try:
                with open("/etc/tuxwall/custom-blocklist.txt") as f:
                    entries = {ln.strip().lower() for ln in f
                               if ln.strip() and not ln.strip().startswith("#")}
                if target.lower() in entries:
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
    """Return the WAN interface name: interfaces.json, else the default route."""
    topo = _topo("wan_device")
    if topo:
        return topo
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
    """LAN interface: interfaces.json, else the one carrying 192.168.1.0/24."""
    topo = _topo("lan_device")
    if topo:
        return topo
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
    """e.g. '192.168.1.0/24' (interfaces.json LAN, else legacy detection)"""
    addr = _topo("lan_address")
    if addr:
        try:
            return str(ipaddress.ip_interface(addr).network)
        except ValueError:
            pass
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
    """Gateway's own LAN IP (interfaces.json LAN, else legacy detection)."""
    addr = _topo("lan_address")
    if addr:
        try:
            return str(ipaddress.ip_interface(addr).ip)
        except ValueError:
            pass
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


_IF_AP_CACHE = {"at": 0.0, "data": None, "busy": False}
_IF_AP_LOCK = threading.Lock()
_IF_AP_TTL = 300


def _if_ap_fetch():
    """Read-only OpenWrt plugin calls (vlan-list + overview SSH to the APs)."""
    data = None
    try:
        if not os.path.isfile(os.path.join(PLUGINS_DIR, "openwrt", "plugin.json")):
            data = {"status": "absent"}
        elif not _plugin_load_config("openwrt").get("enabled", True):
            data = {"status": "disabled"}
        else:
            vl = plugin_action("openwrt", "vlan-list", {})
            ov = plugin_action("openwrt", "overview", {})
            if ov.get("configured") is False or vl.get("configured") is False:
                data = {"status": "unconfigured", "error": ov.get("error") or vl.get("error") or ""}
            else:
                vaps = []
                for ap in ov.get("aps") or []:
                    for v in ap.get("vaps") or []:
                        vaps.append({"ap": ap.get("name") or ap.get("ip") or "", "ssid": v.get("ssid") or "",
                                     "network": v.get("network") or "", "clients": v.get("clients") or 0,
                                     "up": bool(v.get("up"))})
                errs = [str(e.get("host", "")) + ": " + str(e.get("error", "")) for e in ov.get("errors") or []
                        if isinstance(e, dict)]
                if ov.get("error"):
                    errs.append(str(ov["error"]))
                data = {"status": "ok" if (vaps or ov.get("ok")) else "error",
                        "error": "; ".join(errs)[:300],
                        "vlans": vl.get("vlans") or [] if vl.get("ok") else [], "vaps": vaps}
    except Exception as exc:
        data = {"status": "error", "error": str(exc)[:300]}
    data["at"] = int(time.time())
    with _IF_AP_LOCK:
        _IF_AP_CACHE.update(at=time.time(), data=data, busy=False)


def _if_ap_info(wait=0.0, refresh=False):
    """Cached AP/SSID data for the Interfaces -> VLANs tab and the plan.
    Never blocks longer than `wait`; a refresh runs in the background."""
    with _IF_AP_LOCK:
        d = _IF_AP_CACHE["data"]
        if d is not None and not refresh and time.time() - _IF_AP_CACHE["at"] < _IF_AP_TTL:
            return d
        if not _IF_AP_CACHE["busy"]:
            _IF_AP_CACHE["busy"] = True
            threading.Thread(target=_if_ap_fetch, name="if-ap-fetch", daemon=True).start()
    end = time.time() + wait
    while time.time() < end:
        time.sleep(0.2)
        with _IF_AP_LOCK:
            if not _IF_AP_CACHE["busy"]:
                return _IF_AP_CACHE["data"]
    with _IF_AP_LOCK:
        d = _IF_AP_CACHE["data"]
    return dict(d, refreshing=True) if d is not None else {"status": "pending"}


def interfaces_get(path, raw_path=""):
    """GET /api/interfaces, /api/interfaces/policy|vlans|lock (read-only)."""
    if _topology is None:
        return 503, {"ok": False, "error": "Interface topology module is not installed"}
    try:
        try:
            _topology.ensure()  # first use: record the live roles (never overwrites)
        except Exception:
            pass
        if path.endswith("/policy"):
            return 200, _topology.current_policy()
        if path.endswith("/lock"):
            return 200, {"ok": True, "apply_locked": _topology.load().get("apply_locked", True) is not False}
        if path.endswith("/vlans"):
            import assign_plan
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(raw_path or path).query)
            aps = _if_ap_info(wait=1.5, refresh=(q.get("refresh") or [""])[0] == "1")
            return 200, assign_plan.vlans(aps=aps)
        view = _topology.interfaces_view()
        try:
            import assign_apply
            view["pending"] = assign_apply.pending()
        except Exception:
            view["pending"] = []
        return 200, view
    except Exception as exc:
        return 500, {"ok": False, "error": str(exc)}


def interfaces_plan(body, session_ip=""):
    """POST /api/interfaces/plan (admin). Read-only: renders and validates
    in a temp dir, writes nothing to the live configuration."""
    if _topology is None:
        return 503, {"ok": False, "error": "Interface topology module is not installed"}
    try:
        res = _topology.plan(body if isinstance(body, dict) else {}, session_ip=session_ip,
                             aps=lambda: _if_ap_info(wait=12))
        return (200 if res.get("ok") else 400), res
    except Exception as exc:
        return 500, {"ok": False, "error": str(exc)}


def _assign_fw_guard(res, client_ip=""):
    """Firewall guard for an interface/policy plan: refuse (409) when the
    rendered ufw files add a critical/high invariant violation."""
    if _fw_guard is None:
        return None
    names = {"/etc/ufw/" + n: n for n in _fw_guard.UFW_FILES}
    names["/etc/default/ufw"] = "default"
    new = {names[p]: f.get("new") or "" for p, f in (res.files or {}).items() if p in names}
    if not new:
        return None
    try:
        ctx = _fw_ctx(client_ip)
        rec = (res.files or {}).get("/etc/tuxwall/interfaces.json")
        if rec and rec.get("new"):
            ctx._wan = ((json.loads(rec["new"]).get("wan") or {}).get("device")) or None
        cur = _fw_guard.load_ruleset(ctx)
        prop = _fw_guard.load_ruleset(ctx, files=new, raw=cur.get("raw"))
        g = _fw_guard.check(cur, prop, ctx)
    except Exception as exc:
        print("[fw] interfaces guard error: %r" % exc, flush=True)
        return None
    if g["ok"]:
        return None
    return 409, {"ok": False, "error": g["summary"], "guard": g}


def interfaces_apply(action, body, identity, session_ip=""):
    """POST /api/interfaces/apply|confirm|rollback (admin).

    423 while /etc/tuxwall/interfaces.json does not say apply_locked=false
    (only a root edit of that file unlocks it). The confirm window reuses
    the firewall confirm-or-rollback timer (_fw_schedule_revert)."""
    try:
        import assign_apply
    except Exception as exc:
        return 503, {"ok": False, "error": "Interface apply module is not installed: %s" % exc}
    body = body if isinstance(body, dict) else {}
    try:
        if assign_apply.is_locked() and not (action != "apply" and assign_apply.pending()):
            return assign_apply.locked_response()
        if action == "apply":
            def schedule(aid, ttl):
                _fw_schedule_revert("assign:" + aid, "interface assignment " + aid,
                                    lambda: assign_apply.rollback(aid, "timeout"), ttl)
            _fw_autosnap("interfaces apply", identity)
            return assign_apply.apply(body, session_ip=session_ip,
                                      user=(identity or {}).get("username", ""), schedule=schedule,
                                      guard=lambda res: _assign_fw_guard(res, session_ip))
        aid = str(body.get("id") or "")
        with _FW_CONFIRM_LOCK:
            _FW_PENDING.pop("assign:" + aid, None)
        if action == "confirm":
            return assign_apply.confirm(aid)
        return assign_apply.rollback(aid or None, "manual")
    except Exception as exc:
        return 500, {"ok": False, "error": str(exc)}


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
    _vlan_record_sync("add", iface, persist[iface])

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
    _vlan_record_sync("edit", iface, meta)

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
    _vlan_record_sync("delete", iface, {})

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
    # 'route' keyword is required for in-on/out-on forwarding rules
    rule = f"route {policy} in on {src} out on {dst}{port_part}{proto_part}"
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


def _vlan_record_sync(op, iface, meta):
    """interfaces.json is the source of truth for VLANs (Interfaces -> VLANs);
    this page changes the live interface directly, so keep the record in step."""
    if _topology is None:
        return
    try:
        _topology.sync_legacy_vlan(op, iface, meta)
    except Exception as exc:
        print("[vlans] interfaces.json sync failed for %s %s: %s" % (op, iface, exc), flush=True)


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


# ── Isolated plugin host ───────────────────────────────────────────────────
PLUGINS_DIR = "/etc/tuxwall/plugins"
PLUGIN_API = 1
PLUGIN_WORKER_CODE = r"""
import sys, json, os, importlib.util
pdir = sys.argv[1]
sys.path.insert(0, pdir)
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))   # no core dumps of config/credentials
except Exception:
    pass
try:
    spec = importlib.util.spec_from_file_location("tuxwall_plugin_main", os.path.join(pdir, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    req = json.load(sys.stdin)
    fn = getattr(mod, "handle", None)
    if not callable(fn):
        raise RuntimeError("plugin main.py does not define handle(request)")
    out = fn(req)
    if not isinstance(out, dict):
        out = {"ok": True, "data": out}
    json.dump(out, sys.stdout)
except Exception as exc:
    json.dump({"ok": False, "error": str(exc)}, sys.stdout)
"""


PLUGIN_MAX_BYTES = 50 * 1024 * 1024
_PLUGIN_INSTALL_LOCK = threading.Lock()


def _plugin_github_parts(url):
    from urllib.parse import urlsplit, unquote
    parsed = urlsplit((url or "").strip())
    if parsed.scheme not in ("http", "https") or parsed.netloc.lower() not in ("github.com", "www.github.com"):
        raise ValueError("Use a public https://github.com/... folder URL")
    parts = [unquote(p) for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner and repository")
    owner, repo = parts[0], parts[1]
    branch = ""
    subpath = ""
    if len(parts) > 2:
        if parts[2] != "tree" or len(parts) < 4:
            raise ValueError("Use the folder URL (github.com/owner/repo/tree/branch/folder)")
        branch = parts[3]
        subpath = "/".join(parts[4:])
    return owner, repo, branch, subpath


def _plugin_safe_extract(zip_file, dest):
    root = os.path.realpath(dest)
    total = 0
    for info in zip_file.infolist():
        total += int(info.file_size or 0)
        if total > 100 * 1024 * 1024:
            raise ValueError("Plugin archive expands to more than 100 MB")
        name = info.filename.replace("\\", "/")
        if not name or name.startswith("/") or ".." in name.split("/"):
            continue
        target = os.path.realpath(os.path.join(root, name))
        if target != root and not target.startswith(root + os.sep):
            continue
        if info.is_dir():
            os.makedirs(target, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zip_file.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)


# Plugin files: settings/credentials (config.json) and the pin
# (.provenance.json) are 0600 root - the demoted worker never reads them, it
# gets its config from the root parent over stdin (plugin_action). Code and
# web assets are 0644, directories 0755 (3.3.3: every file used to be 0644,
# so plugin secrets such as the OpenWrt SSH key were world-readable).
PLUGIN_CONFIG_FILE = "config.json"
PLUGIN_PIN_FILE = ".provenance.json"
PLUGIN_HASH_V = 2
# Written once the first API start with pinning has pinned the plugins that
# were installed before pins existed (trust on first use). After that, an
# unpinned plugin is refused until it is reinstalled or re-pinned by an admin.
PLUGIN_TOFU_MARKER = "/etc/tuxwall/plugin-pins-tofu.done"
_PLUGIN_CODE_EXTS = (".py", ".js", ".mjs", ".css", ".html", ".htm", ".md", ".svg")
_PLUGIN_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PLUGIN_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_PLUGIN_PIN_CACHE = {}
_PLUGIN_PIN_LOCK = threading.Lock()
_PLUGIN_PIN_LOGGED = set()


def _plugin_secret_name(name):
    """Files kept 0600 root: settings/credentials, the pin, *secret* data."""
    low = name.lower()
    if low in (PLUGIN_CONFIG_FILE, PLUGIN_PIN_FILE):
        return True
    if low.startswith(("." + PLUGIN_CONFIG_FILE + ".", "." + PLUGIN_PIN_FILE + ".")):
        return True     # atomic-write temp files
    return "secret" in low and not low.endswith(_PLUGIN_CODE_EXTS)


def _plugin_hash_skip(rel, version):
    parts = rel.split("/")
    name = parts[-1]
    if name.endswith(".pyc") or "__pycache__" in parts:
        return True
    if version == 1:
        return name in (PLUGIN_CONFIG_FILE, PLUGIN_PIN_FILE)
    if len(parts) == 1:
        if name in (PLUGIN_CONFIG_FILE, PLUGIN_PIN_FILE):
            return True
        if name.startswith(("." + PLUGIN_CONFIG_FILE + ".", "." + PLUGIN_PIN_FILE + ".")) and name.endswith(".tmp"):
            return True
    return False


def _plugin_content_hash(root, version=PLUGIN_HASH_V):
    """SHA-256 over every code file (main.py, web/, plugin.json, ...) - the
    content pin. The plugin's own config.json and pin file are excluded.
    v2 (3.3.3) frames each path and content with its length (v1 simply
    concatenated them, so bytes could move between a name and a file);
    v1 is kept to verify pins written by 3.3.0-3.3.2 installs."""
    h = hashlib.sha256()
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for fn in sorted(files):
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, root).replace(os.sep, "/")
            if _plugin_hash_skip(rel, version):
                continue
            try:
                with open(fp, "rb") as f:
                    data = f.read()
            except OSError:
                data = None
            if version == 1:
                h.update(rel.encode())
                if data is not None:
                    h.update(data)
                continue
            rb = rel.encode("utf-8", "surrogateescape")
            h.update(b"F" + len(rb).to_bytes(4, "big") + rb)
            if data is None:
                h.update(b"E")
            else:
                h.update(b"D" + len(data).to_bytes(8, "big") + data)
    return h.hexdigest()


def _plugin_tree_files(root):
    """rel path -> sha256 of every hashed file (update previews)."""
    out = {}
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for fn in files:
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, root).replace(os.sep, "/")
            if _plugin_hash_skip(rel, PLUGIN_HASH_V):
                continue
            try:
                with open(fp, "rb") as f:
                    out[rel] = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                out[rel] = ""
    return out


def _plugin_write_perms(root):
    """Directories 0755, code/assets 0644, secret files 0600. Symlinks are
    left alone (installs never create them; the pin check refuses them)."""
    for base, dirs, files in os.walk(root):
        try:
            os.chmod(base, 0o755)
        except OSError:
            pass
        for name in files:
            fp = os.path.join(base, name)
            if os.path.islink(fp):
                continue
            try:
                os.chmod(fp, 0o600 if _plugin_secret_name(name) else 0o644)
            except OSError:
                pass


def _plugin_write_private(path, data):
    """Atomic 0600 write (temp file in the same directory + rename)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    d, base = os.path.split(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + base + ".", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _plugin_read_pin(pdir):
    try:
        with open(os.path.join(pdir, PLUGIN_PIN_FILE), "r") as f:
            pin = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {"_invalid": True}
    return pin if isinstance(pin, dict) else {"_invalid": True}


def _plugin_write_pin(pdir, pin):
    _plugin_write_private(os.path.join(pdir, PLUGIN_PIN_FILE),
                          json.dumps({k: v for k, v in pin.items() if not k.startswith("_")}, indent=2) + "\n")


def _plugin_tree_problems(pdir):
    """(problem, signature): every entry must be owned by the API's uid
    (root), not group/world-writable and not a symlink - otherwise a pin
    next to the code proves nothing. The signature (lstat of every entry)
    keys the verification cache."""
    import stat as _stat
    me = os.geteuid()
    sig = []
    problem = ""

    def look(path):
        st = os.lstat(path)
        rel = os.path.relpath(path, pdir).replace(os.sep, "/")
        sig.append((rel, st.st_mode, st.st_uid, st.st_size, st.st_mtime_ns, st.st_ino))
        if _stat.S_ISLNK(st.st_mode):
            return "%s is a symlink" % rel
        if st.st_uid != me:
            return "%s is not owned by %s" % (rel, "root" if me == 0 else "uid %d" % me)
        if st.st_mode & 0o022:
            return "%s is writable by group/others" % rel
        return ""

    for base, dirs, files in os.walk(pdir):
        dirs.sort()
        problem = problem or look(base)
        for name in sorted(files):
            problem = problem or look(os.path.join(base, name))
        for name in dirs:
            if os.path.islink(os.path.join(base, name)):
                problem = problem or look(os.path.join(base, name))
    if not sig:
        raise FileNotFoundError(pdir)
    return problem, tuple(sig)


def _plugin_pin_status(pid):
    """Integrity of an installed plugin against its pin. state: ok |
    unpinned | mismatch | unsafe | invalid. Cached per file signature."""
    pdir = os.path.join(PLUGINS_DIR, pid)
    problem, sig = _plugin_tree_problems(pdir)
    with _PLUGIN_PIN_LOCK:
        cached = _PLUGIN_PIN_CACHE.get(pid)
        if cached and cached[0] == sig:
            return dict(cached[1])
    pin = _plugin_read_pin(pdir)
    info = {"commit": "", "pinned_sha256": "", "pinned_by": "", "actual_sha256": ""}
    if isinstance(pin, dict) and not pin.get("_invalid"):
        info.update(commit=str(pin.get("commit") or ""), pinned_sha256=str(pin.get("content_sha256") or ""),
                    pinned_by=str(pin.get("pinned_by") or ("install" if pin.get("content_sha256") else "")))
    fix = "chown -R root:root %s && chmod -R go-w %s" % (pdir, pdir)
    if problem:
        res = dict(info, state="unsafe", error="Plugin %s refused: %s. Fix it (%s), review the files, then "
                   "pin them again on System > Plugins." % (pid, problem, fix))
    elif pin is None or (not pin.get("_invalid") and not pin.get("content_sha256")):
        res = dict(info, state="unpinned", error="Plugin %s refused: it has no integrity pin. Reinstall it, "
                   "or review its files and pin them on System > Plugins." % pid)
    elif pin.get("_invalid"):
        res = dict(info, state="invalid", error="Plugin %s refused: its pin file %s is unreadable. Reinstall it, "
                   "or review its files and pin them again on System > Plugins." % (pid, PLUGIN_PIN_FILE))
    else:
        try:
            version = int(pin.get("hash_v") or 1)
        except (TypeError, ValueError):
            version = 0
        actual = _plugin_content_hash(pdir, version) if version in (1, 2) else ""
        res = dict(info, actual_sha256=actual)
        if actual and hmac.compare_digest(actual, str(pin.get("content_sha256"))):
            res.update(state="ok", error="")
        else:
            res.update(state="mismatch", error="Plugin %s refused: its code changed since it was pinned "
                       "(pinned %s, now %s). Update or reinstall it, or review the change and pin it again on "
                       "System > Plugins." % (pid, str(pin.get("content_sha256"))[:12], (actual or "?")[:12]))
    with _PLUGIN_PIN_LOCK:
        _PLUGIN_PIN_CACHE[pid] = (sig, dict(res))
    return res


def _plugin_pin_forget(pid):
    with _PLUGIN_PIN_LOCK:
        _PLUGIN_PIN_CACHE.pop(pid, None)
    # no _PLUGIN_INCIDENTS_LOCK: the incident monitor holds it while plugin
    # workers run (up to 20 s each); a single dict pop is atomic
    _PLUGIN_INCIDENTS_CACHE.pop(pid, None)


def _plugin_pin_log(pid, status):
    """Journal line, once per plugin/state/content (the incident monitor
    raises plugin:<id>:integrity from the same status)."""
    key = (pid, status.get("state"), status.get("actual_sha256"))
    with _PLUGIN_PIN_LOCK:
        if key in _PLUGIN_PIN_LOGGED:
            return
        _PLUGIN_PIN_LOGGED.add(key)
    print("[plugins] INTEGRITY %s: %s" % (pid, status.get("error") or status.get("state")), flush=True)


def _plugin_integrity_error(pid):
    """"" when the plugin may run, else the refusal message (logged)."""
    try:
        status = _plugin_pin_status(pid)
    except FileNotFoundError:
        return "plugin %s is not installed" % pid
    except OSError as exc:
        status = {"state": "unsafe", "error": "Plugin %s refused: cannot check its files (%s)" % (pid, exc)}
    if status.get("state") == "ok":
        return ""
    _plugin_pin_log(pid, status)
    return status.get("error") or "Plugin %s refused: integrity check failed" % pid


def _plugin_http_get(url, accept=None, limit=PLUGIN_MAX_BYTES, timeout=30):
    headers = {"User-Agent": "tuxwall-plugin-installer/1.1"}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(limit + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError("GitHub: repository, branch or commit not found")
        if exc.code in (403, 429):
            raise ValueError("GitHub refused the request (HTTP %s, rate limit?) - try again later" % exc.code)
        raise
    if len(data) > limit:
        raise ValueError("GitHub response is larger than %d MB" % (limit // (1024 * 1024)))
    return data


def _plugin_resolve_commit(owner, repo, branch):
    """Branch (default branch when empty) -> (branch, 40-hex commit SHA):
    installs download that exact commit, never a moving branch head."""
    base = "https://api.github.com/repos/%s/%s" % (urllib.parse.quote(owner, safe=""),
                                                   urllib.parse.quote(repo, safe=""))
    if not branch:
        info = json.loads(_plugin_http_get(base, "application/vnd.github+json", 1 << 20, 15)
                          .decode("utf-8", "replace"))
        branch = info.get("default_branch") or "main"
    sha = _plugin_http_get(base + "/commits/" + urllib.parse.quote(branch, safe="/"),
                           "application/vnd.github.sha", 4096, 15).decode("ascii", "replace").strip().lower()
    if not _PLUGIN_SHA_RE.match(sha):
        raise ValueError("GitHub did not resolve %r to a commit" % branch)
    return branch, sha


def _plugin_fetch_stage(url, commit=None):
    """Download the plugin at one exact commit and stage it (perms set,
    content hash computed) in a hidden directory under PLUGINS_DIR - same
    filesystem, so going live is a rename. The caller removes info["stage"]
    unless it renamed it into place."""
    owner, repo, branch, subpath = _plugin_github_parts(url)
    if commit:
        commit = str(commit).strip().lower()
        if not _PLUGIN_SHA_RE.match(commit):
            raise ValueError("commit must be a 40-character commit SHA")
    else:
        branch, commit = _plugin_resolve_commit(owner, repo, branch)
    archive_url = "https://codeload.github.com/%s/%s/zip/%s" % (
        urllib.parse.quote(owner, safe=""), urllib.parse.quote(repo, safe=""), commit)
    data = _plugin_http_get(archive_url, None, PLUGIN_MAX_BYTES, 30)
    with tempfile.TemporaryDirectory(prefix="tuxwall-plugin-") as tmp:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                _plugin_safe_extract(z, tmp)
        except zipfile.BadZipFile:
            raise ValueError("GitHub returned an invalid archive")
        candidates = []
        wanted = subpath.strip("/")
        for base, dirs, files in os.walk(tmp):
            if "plugin.json" not in files:
                continue
            rel = os.path.relpath(base, tmp).replace("\\", "/")
            if wanted:
                if rel == wanted or rel.endswith("/" + wanted):
                    candidates.append(base)
            else:
                candidates.append(base)
        if not candidates:
            raise ValueError("No plugin.json found at that GitHub folder")
        if len(candidates) > 1:
            raise ValueError("Multiple plugin.json files found; use a more specific folder URL")
        src = candidates[0]
        with open(os.path.join(src, "plugin.json"), "r") as f:
            manifest = json.load(f)
        if not isinstance(manifest, dict):
            raise ValueError("plugin.json must be an object")
        pid = str(manifest.get("id") or "").strip()
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", pid):
            raise ValueError("plugin.json has an invalid id")
        if manifest.get("api") != PLUGIN_API:
            raise ValueError("Plugin API %r is not supported" % manifest.get("api"))
        if not os.path.isfile(os.path.join(src, "main.py")):
            raise ValueError("Plugin package is missing main.py")
        rel_path = os.path.relpath(src, tmp).replace("\\", "/").split("/", 1)
        os.makedirs(PLUGINS_DIR, exist_ok=True)
        stage = tempfile.mkdtemp(prefix=".staging-", dir=PLUGINS_DIR)
        try:
            shutil.copytree(src, stage, dirs_exist_ok=True, ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "*.pyc", PLUGIN_CONFIG_FILE, PLUGIN_PIN_FILE))
            _plugin_write_perms(stage)
            return {
                "stage": stage, "pid": pid, "manifest": manifest,
                "repo": "%s/%s" % (owner, repo), "branch": branch, "commit": commit,
                "path": wanted or (rel_path[1] if len(rel_path) > 1 else ""),
                "content_sha256": _plugin_content_hash(stage),
                "files": _plugin_tree_files(stage),
            }
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise


def install_plugin_from_github(body, who=""):
    """Install or update a plugin from a GitHub folder URL, pinned.

    The branch is resolved to a commit SHA and that commit is downloaded;
    .provenance.json records repo, path, commit and the content hash, and
    every run of the plugin is checked against it (_plugin_integrity_error).
    Updating an installed plugin is two calls: without confirm_sha256 the
    answer is a preview (current vs new commit/hash, changed files) and
    nothing changes; repeating the call with the previewed "commit" and
    "confirm_sha256" installs exactly that content (refused if it differs)."""
    url = (body.get("url") or "").strip()
    _plugin_github_parts(url)
    with _PLUGIN_INSTALL_LOCK:
        info = _plugin_fetch_stage(url, body.get("commit") or None)
        stage = info["stage"]
        try:
            pid = info["pid"]
            manifest = info["manifest"]
            dest = os.path.join(PLUGINS_DIR, pid)
            updating = os.path.exists(dest)
            old_pin = (_plugin_read_pin(dest) or {}) if updating else {}
            if updating:
                confirm = str(body.get("confirm_sha256") or "").strip().lower()
                if not confirm:
                    try:
                        old_version = _plugin_load_manifest(pid).get("version") or ""
                    except Exception:
                        old_version = ""
                    old_files = _plugin_tree_files(dest)
                    new_files = info["files"]
                    added = sorted(set(new_files) - set(old_files))
                    removed = sorted(set(old_files) - set(new_files))
                    changed = sorted(f for f in set(new_files) & set(old_files) if new_files[f] != old_files[f])
                    return {
                        "ok": True, "confirm_required": True,
                        "plugin": {"id": pid, "name": manifest.get("name") or pid},
                        "current": {"version": old_version, "commit": str(old_pin.get("commit") or ""),
                                    "content_sha256": str(old_pin.get("content_sha256") or ""),
                                    "pinned_by": str(old_pin.get("pinned_by") or "")},
                        "new": {"version": manifest.get("version") or "", "commit": info["commit"],
                                "branch": info["branch"], "content_sha256": info["content_sha256"]},
                        "changes": {"added": added[:50], "removed": removed[:50], "changed": changed[:50],
                                    "counts": {"added": len(added), "removed": len(removed),
                                               "changed": len(changed)}},
                    }
                if not _PLUGIN_HEX64_RE.match(confirm) or not hmac.compare_digest(confirm, info["content_sha256"]):
                    raise ValueError("The downloaded update (content %s) is not the one you confirmed (%s); "
                                     "nothing was changed - review the update again"
                                     % (info["content_sha256"][:12], confirm[:12]))
                try:
                    with open(os.path.join(dest, PLUGIN_CONFIG_FILE), "rb") as f:
                        saved = f.read()
                except FileNotFoundError:
                    saved = None
                if saved is not None:
                    _plugin_write_private(os.path.join(stage, PLUGIN_CONFIG_FILE), saved)
            pin = {
                "installed_at": time.time(),
                "source_url": url,
                "repo": info["repo"],
                "path": info["path"],
                "source_branch": info["branch"],
                "commit": info["commit"],
                "version": manifest.get("version") or "",
                # THE PIN: checked before every run of the plugin and before
                # its web assets are served (2026-11-09 audit #5 / 3.3.3).
                "content_sha256": info["content_sha256"],
                "hash_v": PLUGIN_HASH_V,
                "pinned_by": "update" if updating else "install",
                "pinned_at": time.time(),
                "by": who or "",
            }
            if updating and old_pin.get("content_sha256"):
                pin["previous_content_sha256"] = str(old_pin.get("content_sha256"))
                pin["previous_commit"] = str(old_pin.get("commit") or "")
            _plugin_write_pin(stage, pin)
            os.chmod(stage, 0o755)
            if updating:
                old = tempfile.mkdtemp(prefix=".old-", dir=PLUGINS_DIR)
                os.rmdir(old)
                os.rename(dest, old)
                try:
                    os.rename(stage, dest)
                except BaseException:
                    os.rename(old, dest)
                    raise
                stage = None
                shutil.rmtree(old, ignore_errors=True)
            else:
                os.rename(stage, dest)
                stage = None
            _plugin_pin_forget(pid)
            print("[plugins] %s %s: %s@%s path=%s content_sha256=%s%s" % (
                "updated" if updating else "installed", pid, info["repo"], info["commit"], info["path"] or "/",
                info["content_sha256"], (" by " + who) if who else ""), flush=True)
            out = {"ok": True, "plugin": {
                "id": pid,
                "name": manifest.get("name") or pid,
                "version": manifest.get("version") or "",
                "commit": info["commit"],
                "content_sha256": info["content_sha256"],
                "pinned_sha": info["content_sha256"][:16],
            }}
            if updating:
                out["updated"] = True
            return out
        finally:
            if stage:
                shutil.rmtree(stage, ignore_errors=True)


def plugin_repin(pid, body, who=""):
    """Admin re-pin of the files on disk (local edits, or a plugin that
    predates pinning after the first-start TOFU). Without confirm_sha256 it
    only reports the current content hash; with it, the files must still
    hash to exactly that value. Never pins files owned by another user."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", pid or ""):
        raise ValueError("invalid plugin id")
    pdir = os.path.join(PLUGINS_DIR, pid)
    if not os.path.isdir(pdir):
        raise ValueError("plugin %s is not installed" % pid)
    with _PLUGIN_INSTALL_LOCK:
        problem, _sig = _plugin_tree_problems(pdir)
        if problem:
            raise ValueError("Cannot pin %s: %s (fix: chown -R root:root %s && chmod -R go-w %s)"
                             % (pid, problem, pdir, pdir))
        current = _plugin_content_hash(pdir)
        old = _plugin_read_pin(pdir) or {}
        if old.get("_invalid"):
            old = {}
        confirm = str(body.get("confirm_sha256") or "").strip().lower()
        if not confirm:
            return {"ok": True, "confirm_required": True, "plugin": pid, "content_sha256": current,
                    "pinned_sha256": str(old.get("content_sha256") or ""),
                    "commit": str(old.get("commit") or "")}
        if not hmac.compare_digest(confirm, current):
            raise ValueError("The files of %s changed while you were reviewing them (now %s); nothing was "
                             "pinned - review again" % (pid, current[:12]))
        pin = dict(old)
        if old.get("content_sha256") and old.get("content_sha256") != current:
            pin["previous_content_sha256"] = str(old.get("content_sha256"))
            pin["local_changes"] = True
        try:
            pin.setdefault("version", _plugin_load_manifest(pid).get("version") or "")
        except Exception:
            pass
        pin.update(content_sha256=current, hash_v=PLUGIN_HASH_V, pinned_by="admin", pinned_at=time.time(),
                   by=who or "")
        _plugin_write_pin(pdir, pin)
        _plugin_pin_forget(pid)
    print("[plugins] re-pinned %s: content_sha256=%s%s" % (pid, current, (" by " + who) if who else ""), flush=True)
    return {"ok": True, "plugin": pid, "content_sha256": current}


def _plugin_pins_startup():
    """At API start: secret files back to 0600 (3.3.2 and older wrote them
    0644), v1 pins re-recorded in the v2 framing when they still match, and
    - on the first start with pinning only - trust-on-first-use pins for
    plugins installed before pins existed (logged with their hash)."""
    tofu = not os.path.exists(PLUGIN_TOFU_MARKER)
    pinned = []
    for pid in _plugin_ids():
        pdir = os.path.join(PLUGINS_DIR, pid)
        try:
            for name in os.listdir(pdir):
                fp = os.path.join(pdir, name)
                if _plugin_secret_name(name) and os.path.isfile(fp) and not os.path.islink(fp):
                    if os.stat(fp).st_mode & 0o077:
                        os.chmod(fp, 0o600)
                        print("[plugins] %s: %s was readable by others - now 0600" % (pid, name), flush=True)
            problem, _sig = _plugin_tree_problems(pdir)
            if problem:
                print("[plugins] %s: not pinned/verified at start: %s" % (pid, problem), flush=True)
                continue
            pin = _plugin_read_pin(pdir)
            if pin is None and tofu:
                digest = _plugin_content_hash(pdir)
                try:
                    version = _plugin_load_manifest(pid).get("version") or ""
                except Exception:
                    version = ""
                _plugin_write_pin(pdir, {"content_sha256": digest, "hash_v": PLUGIN_HASH_V, "version": version,
                                         "pinned_by": "tofu", "pinned_at": time.time(), "commit": ""})
                pinned.append(pid)
                print("[plugins] %s: no pin found - trusted the files on disk at first start (TOFU), "
                      "content_sha256=%s" % (pid, digest), flush=True)
            elif (isinstance(pin, dict) and not pin.get("_invalid") and pin.get("content_sha256")
                  and str(pin.get("hash_v") or "1") == "1"):
                if hmac.compare_digest(_plugin_content_hash(pdir, 1), str(pin["content_sha256"])):
                    pin["content_sha256_v1"] = pin["content_sha256"]
                    pin["content_sha256"] = _plugin_content_hash(pdir)
                    pin["hash_v"] = PLUGIN_HASH_V
                    _plugin_write_pin(pdir, pin)
                    print("[plugins] %s: pin re-recorded in hash v2, content_sha256=%s"
                          % (pid, pin["content_sha256"]), flush=True)
            _plugin_pin_forget(pid)
            status = _plugin_pin_status(pid)
            if status.get("state") != "ok":
                _plugin_pin_log(pid, status)
        except Exception as exc:
            print("[plugins] %s: pin check at start failed: %r" % (pid, exc), flush=True)
    if tofu:
        try:
            os.makedirs(os.path.dirname(PLUGIN_TOFU_MARKER), exist_ok=True)
            with open(PLUGIN_TOFU_MARKER, "w") as f:
                f.write("%s TOFU pins: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), " ".join(pinned) or "(none)"))
        except OSError as exc:
            print("[plugins] cannot write %s: %r" % (PLUGIN_TOFU_MARKER, exc), flush=True)


def _plugin_ids():
    try:
        return sorted(d for d in os.listdir(PLUGINS_DIR)
                      if not d.startswith(".") and os.path.isdir(os.path.join(PLUGINS_DIR, d)))
    except OSError:
        return []


def _plugin_load_manifest(pid):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", pid or ""):
        raise ValueError("invalid plugin id")
    path = os.path.join(PLUGINS_DIR, pid, "plugin.json")
    with open(path, "r") as f:
        m = json.load(f)
    if not isinstance(m, dict):
        raise ValueError("plugin.json must be an object")
    if m.get("api") != PLUGIN_API:
        raise ValueError("plugin API %r is not supported (need %s)" % (m.get("api"), PLUGIN_API))
    if not m.get("name"):
        raise ValueError("plugin.json is missing name")
    if not os.path.isfile(os.path.join(PLUGINS_DIR, pid, "main.py")):
        raise ValueError("plugin has no main.py")
    return m


def _plugin_config_path(pid):
    return os.path.join(PLUGINS_DIR, pid, "config.json")


def _plugin_load_config(pid, manifest=None):
    cfg = {}
    try:
        with open(_plugin_config_path(pid), "r") as f:
            raw = json.load(f)
            if isinstance(raw, dict):
                cfg.update(raw)
    except Exception:
        pass
    manifest = manifest or _plugin_load_manifest(pid)
    settings = manifest.get("settings") or []
    for fld in settings:
        key = fld.get("key")
        if key and key not in cfg and "default" in fld:
            cfg[key] = fld["default"]
    if "enabled" not in cfg:
        cfg["enabled"] = bool(manifest.get("enabled", True))
    return cfg


def _plugin_config_public(pid, manifest=None):
    cfg = _plugin_load_config(pid, manifest)
    manifest = manifest or _plugin_load_manifest(pid)
    out = dict(cfg)
    configured = {}
    for fld in manifest.get("settings") or []:
        key = fld.get("key")
        if not key:
            continue
        if fld.get("secret"):
            configured[key] = bool(cfg.get(key))
            out[key] = ""
    return {"ok": True, "config": out, "secret_configured": configured}


def _plugin_save_config(pid, body):
    manifest = _plugin_load_manifest(pid)
    cfg = _plugin_load_config(pid, manifest)
    incoming = body.get("config") if isinstance(body.get("config"), dict) else body
    allowed = {f.get("key"): f for f in (manifest.get("settings") or []) if f.get("key")}
    for key, fld in allowed.items():
        if key not in incoming:
            continue
        value = incoming.get(key)
        if fld.get("secret"):
            if value in (None, ""):
                continue
            cfg[key] = str(value)
        elif fld.get("type") == "bool":
            cfg[key] = bool(value)
        else:
            cfg[key] = value
    if "enabled" in incoming:
        cfg["enabled"] = bool(incoming.get("enabled"))
    os.makedirs(os.path.dirname(_plugin_config_path(pid)), exist_ok=True)
    # 0600 root, atomically: credentials never sit world-readable, not even
    # for the instant between write and chmod
    _plugin_write_private(_plugin_config_path(pid), json.dumps(cfg, indent=2))
    _plugin_pin_forget(pid)
    return {"ok": True, "config": _plugin_config_public(pid, manifest)["config"]}


# --- Plugin catalog (browsable "available plugins") -----------------------
# Served from the gh-pages site, regenerated by CI whenever plugins/ on
# main changes. Dashboards browse this list; install-from-GitHub fetches
# the actual plugin source straight from github.com using the URLs in it
# (no plugin code is hosted on tuxwall.org or the gh-pages site).
PLUGIN_CATALOG_URL = "https://rezzonance.github.io/tuxwall/plugins/catalog.json"
PLUGIN_CATALOG_TTL = 600
PLUGIN_CATALOG_CACHE = {"ts": 0.0, "data": None}
PLUGIN_CATALOG_LOCK = threading.Lock()


def build_plugin_catalog():
    """Available plugins from the published catalog, cached 10 minutes.

    Entries are tagged with their local install state so the dashboard can
    show "install" vs "installed" without a second round-trip."""
    now = time.time()
    with PLUGIN_CATALOG_LOCK:
        cached = PLUGIN_CATALOG_CACHE["data"]
        if cached is not None and now - PLUGIN_CATALOG_CACHE["ts"] < PLUGIN_CATALOG_TTL:
            out = dict(cached)
            out["cached"] = True
            return out
    try:
        req = urllib.request.Request(PLUGIN_CATALOG_URL, headers={
            "User-Agent": "tuxwall-plugin-catalog/1.0",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(4 * 1024 * 1024 + 1)
        if len(body) > 4 * 1024 * 1024:
            raise RuntimeError("plugin catalog too large")
        data = json.loads(body.decode("utf-8", errors="replace"))
        if not isinstance(data, dict) or not isinstance(data.get("plugins"), list):
            raise RuntimeError("bad catalog payload")
    except Exception as exc:
        with PLUGIN_CATALOG_LOCK:
            stale = PLUGIN_CATALOG_CACHE["data"]
        if stale is not None:
            out = dict(stale)
            out["cached"] = True
            out["stale"] = True
            return out
        return {"ok": False, "error": "plugin catalog unreachable: %s" % exc,
                "plugins": []}
    with PLUGIN_CATALOG_LOCK:
        PLUGIN_CATALOG_CACHE["ts"] = now
        PLUGIN_CATALOG_CACHE["data"] = data
    out = dict(data)
    out["cached"] = False
    return out


def list_plugins(include_config=False):
    out = []
    for pid in _plugin_ids():
        try:
            manifest = _plugin_load_manifest(pid)
            cfg = _plugin_load_config(pid, manifest)
            try:
                pin = _plugin_pin_status(pid)
            except OSError as exc:
                pin = {"state": "unsafe", "error": "Plugin %s refused: cannot check its files (%s)" % (pid, exc)}
            entry = {
                "id": pid,
                "name": manifest.get("name") or pid,
                "version": manifest.get("version") or "",
                "description": manifest.get("description") or "",
                "api": manifest.get("api"),
                "nav": manifest.get("nav") or {},
                "settings": manifest.get("settings") or [],
                "enabled": bool(cfg.get("enabled", True)),
                "web": os.path.isdir(os.path.join(PLUGINS_DIR, pid, "web")),
                "error": "",
                "pin": {"state": pin.get("state"), "commit": pin.get("commit") or "",
                        "content_sha256": pin.get("pinned_sha256") or "",
                        "pinned_by": pin.get("pinned_by") or ""},
            }
            if pin.get("state") != "ok":
                # refused to run: no nav entry, no assets, toggle disabled
                _plugin_pin_log(pid, pin)
                entry["error"] = pin.get("error") or "integrity check failed"
                entry["enabled"] = False
            if include_config:
                entry["config"] = _plugin_config_public(pid, manifest)
            out.append(entry)
        except Exception as exc:
            out.append({"id": pid, "name": pid, "enabled": False, "error": str(exc)})
    return {"ok": True, "plugins": out}


def _plugin_lease_names():
    """MAC -> {ip, hostname} for plugins whose manifest declares
    "uses-leases": true. The plugin worker runs demoted (nobody) and
    cannot reach Kea's control socket - the root parent performs the
    read and hands the result over with the request, so no privilege
    is extended to plugin code (the worker only gets hostnames, never
    lease commands)."""
    try:
        response = kea_command("lease4-get-all")
        entry = response[0] if isinstance(response, list) and response else response
        leases = ((entry.get("arguments") or {}).get("leases")) or []
        out = {}
        for l in leases:
            mac = (l.get("hw-address") or "").strip().upper()
            hostname = (l.get("hostname") or "").strip()
            if mac and hostname:
                out[mac] = {"ip": l.get("ip-address") or "", "hostname": hostname}
        return out
    except Exception:
        return {}


def _plugin_worker_identity():
    for name in ("tuxwall-plugin", "nobody"):
        try:
            p = pwd.getpwnam(name)
            return p.pw_uid, p.pw_gid
        except KeyError:
            continue
    return 65534, 65534


def plugin_action(pid, action, payload):
    manifest = _plugin_load_manifest(pid)
    cfg = _plugin_load_config(pid, manifest)
    if not cfg.get("enabled", True):
        raise ValueError("plugin is disabled")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", pid or ""):
        raise ValueError("invalid plugin id")
    pdir = os.path.join(PLUGINS_DIR, pid)
    refused = _plugin_integrity_error(pid)
    if refused:
        return {"ok": False, "error": refused, "integrity": "refused"}
    req = {
        "action": action or "",
        "payload": payload if isinstance(payload, dict) else {},
        "config": cfg,
        "manifest": manifest,
        # lease names for plugins that declare "uses-leases" (the demoted
        # worker cannot query Kea itself; see _plugin_lease_names)
        "leases": _plugin_lease_names() if manifest.get("uses-leases") else None,
    }
    # Demotion by subprocess itself (no preexec_fn: Python code between
    # fork and exec is unsafe in this threaded server). A non-root parent
    # (tests) cannot drop privileges and runs the worker as itself.
    drop = {}
    if os.geteuid() == 0:
        uid, gid = _plugin_worker_identity()
        drop = {"user": uid, "group": gid, "extra_groups": []}
    try:
        proc = subprocess.run(
            [sys.executable, "-c", PLUGIN_WORKER_CODE, pdir],
            input=json.dumps(req), capture_output=True, text=True,
            timeout=20, cwd=pdir, umask=0o077,
            env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"},
            **drop,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "plugin action timed out"}
    except Exception as exc:
        return {"ok": False, "error": "plugin worker failed: %s" % exc}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or "plugin worker exited %s" % proc.returncode).strip()[:2000]}
    try:
        out = json.loads(proc.stdout or "{}")
    except ValueError:
        return {"ok": False, "error": "plugin returned invalid JSON", "detail": proc.stdout[:2000]}
    if not isinstance(out, dict):
        out = {"ok": True, "data": out}
    return out


def uninstall_plugin(pid):
    """Remove an installed plugin entirely.

    Deletes the plugin's directory - code, web assets, and its config.json
    (including any credentials the plugin stored). Plugin workers are
    spawned per request (nothing persistent to stop), so removal is
    immediate; the install lock prevents racing a concurrent install."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", pid or ""):
        raise ValueError("invalid plugin id")
    pdir = os.path.join(PLUGINS_DIR, pid)
    if not os.path.isdir(pdir):
        raise ValueError("plugin %s is not installed" % pid)
    with _PLUGIN_INSTALL_LOCK:
        shutil.rmtree(pdir)
    _plugin_pin_forget(pid)
    return {"ok": True, "removed": pid}


def plugin_asset_path(pid, rel):
    manifest = _plugin_load_manifest(pid)
    refused = _plugin_integrity_error(pid)
    if refused:
        # plugin web code runs with the admin's session: same pin as main.py
        raise ValueError(refused)
    web = os.path.realpath(os.path.join(PLUGINS_DIR, pid, "web"))
    target = os.path.realpath(os.path.join(web, rel))
    if target != web and not target.startswith(web + os.sep):
        raise ValueError("invalid asset path")
    if not os.path.isfile(target):
        raise FileNotFoundError(target)
    return target


# ── Incidents & alerting ───────────────────────────────────────────────────
INCIDENTS_FILE = "/etc/tuxwall/incidents.json"
ALERT_CONFIG_FILE = "/etc/tuxwall/alerts.json"
INCIDENT_MAX = 400
INCIDENT_CHECK_INTERVAL = 30
INCIDENT_SEVERITY_RANK = {"info": 1, "warning": 2, "critical": 3}
_INCIDENT_LOCK = threading.Lock()


def _incident_read_json(path, fallback):
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else fallback
    except Exception:
        return fallback


def _incident_write_json(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except Exception as exc:
        print("[incidents] write %s failed: %s" % (path, exc), flush=True)


def _load_incidents():
    data = _incident_read_json(INCIDENTS_FILE, {"items": []})
    items = data.get("items", [])
    return items if isinstance(items, list) else []


def _trim_incidents(items):
    active = [i for i in items if i.get("status") == "active"]
    resolved = [i for i in items if i.get("status") != "active"]
    active.sort(key=lambda i: i.get("last_seen", 0), reverse=True)
    resolved.sort(key=lambda i: i.get("last_seen", 0), reverse=True)
    keep = active + resolved[:max(0, INCIDENT_MAX - len(active))]
    keep.sort(key=lambda i: i.get("last_seen", 0), reverse=True)
    return keep


def build_incidents(limit=120):
    try:
        limit = max(1, min(500, int(limit)))
    except (TypeError, ValueError):
        limit = 120
    with _INCIDENT_LOCK:
        items = _load_incidents()
    items.sort(key=lambda i: i.get("last_seen", 0), reverse=True)
    active = [i for i in items if i.get("status") == "active"]
    unack = [i for i in active if not i.get("acknowledged")]
    return {
        "ok": True,
        "incidents": items[:limit],
        "active": len(active),
        "unacknowledged": len(unack),
        "critical": len([i for i in active if i.get("severity") == "critical"]),
        "warning": len([i for i in active if i.get("severity") == "warning"]),
        "checked_at": int(time.time()),
    }


def _ack_incidents(incident_id=None, user="", all_active=False):
    now = time.time()
    with _INCIDENT_LOCK:
        items = _load_incidents()
        changed = 0
        for inc in items:
            if inc.get("status") != "active" or inc.get("acknowledged"):
                continue
            if all_active or (incident_id and inc.get("id") == incident_id):
                inc["acknowledged"] = True
                inc["acknowledged_at"] = now
                inc["acknowledged_by"] = user or ""
                changed += 1
        if changed:
            _incident_write_json(INCIDENTS_FILE, {"items": _trim_incidents(items)})
    return {"ok": True, "acknowledged": changed}


def _ack_incident(incident_id, user=""):
    if not incident_id:
        raise ValueError("id is required")
    result = _ack_incidents(incident_id=incident_id, user=user)
    if not result["acknowledged"]:
        return {"ok": False, "error": "Incident not found or already acknowledged"}
    return result


def _dismiss_incident(incident_id):
    """Remove one resolved incident from the visible history."""
    if not incident_id:
        raise ValueError("id is required")
    with _INCIDENT_LOCK:
        items = _load_incidents()
        target = next((i for i in items if i.get("id") == incident_id), None)
        if target is None:
            return {"ok": False, "error": "Incident not found"}
        if target.get("status") == "active":
            return {"ok": False, "error": "Acknowledge active incidents instead"}
        kept = [i for i in items if i.get("id") != incident_id]
        _incident_write_json(INCIDENTS_FILE, {"items": _trim_incidents(kept)})
    return {"ok": True, "dismissed": 1}


def _alert_config_defaults():
    return {
        "enabled": True,
        "webhook_url": "",
        "ntfy_url": "",
        "min_severity": "warning",
        "notify_resolved": True,
    }


def _load_alert_config():
    cfg = _alert_config_defaults()
    raw = _incident_read_json(ALERT_CONFIG_FILE, {})
    for key in cfg:
        if key in raw:
            cfg[key] = raw[key]
    if cfg.get("min_severity") not in INCIDENT_SEVERITY_RANK:
        cfg["min_severity"] = "warning"
    cfg["enabled"] = bool(cfg.get("enabled", True))
    cfg["notify_resolved"] = bool(cfg.get("notify_resolved", True))
    return cfg


def _clean_alert_url(value, allow_bare_ntfy=False):
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) > 2048:
        raise ValueError("URL is too long")
    if allow_bare_ntfy and "://" not in value:
        value = "https://ntfy.sh/" + value.lstrip("/")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL must start with http:// or https://")
    return value


def save_alert_config(body):
    cfg = _load_alert_config()
    cfg["enabled"] = bool(body.get("enabled", cfg["enabled"]))
    cfg["notify_resolved"] = bool(body.get("notify_resolved", cfg["notify_resolved"]))
    cfg["webhook_url"] = _clean_alert_url(body.get("webhook_url", cfg["webhook_url"]))
    cfg["ntfy_url"] = _clean_alert_url(body.get("ntfy_url", cfg["ntfy_url"]), allow_bare_ntfy=True)
    sev = (body.get("min_severity") or cfg["min_severity"]).strip().lower()
    if sev not in INCIDENT_SEVERITY_RANK:
        raise ValueError("min_severity must be info, warning or critical")
    cfg["min_severity"] = sev
    _incident_write_json(ALERT_CONFIG_FILE, cfg)
    return {"ok": True, "config": cfg}


def _dispatch_alert(cfg, incident, transition):
    """Send one incident transition to the configured channels."""
    errors = []
    if not cfg.get("enabled"):
        return errors
    rank = INCIDENT_SEVERITY_RANK.get(incident.get("severity", "info"), 1)
    if rank < INCIDENT_SEVERITY_RANK.get(cfg.get("min_severity", "warning"), 2):
        return errors
    if transition == "resolved" and not cfg.get("notify_resolved", True):
        return errors

    title = ("[%s] %s" % (incident.get("severity", "info").upper(), incident.get("title", "TuxWall incident")))
    detail = incident.get("detail", "")
    text = "%s\n%s\n%s" % (title, detail, time.strftime("%Y-%m-%d %H:%M:%S"))

    ntfy_url = cfg.get("ntfy_url", "")
    if ntfy_url:
        try:
            headers = {
                "Title": title.encode("ascii", "ignore").decode("ascii") or "TuxWall incident",
                "Priority": "urgent" if incident.get("severity") == "critical" else "high",
                "Tags": "warning" if transition == "opened" else "white_check_mark",
                "Content-Type": "text/plain; charset=utf-8",
            }
            req = urllib.request.Request(ntfy_url, data=text.encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=8) as resp:
                resp.read(1024)
        except Exception as exc:
            errors.append("ntfy: %s" % exc)

    webhook_url = cfg.get("webhook_url", "")
    if webhook_url:
        try:
            payload = json.dumps({
                "type": "tuxwall.incident",
                "transition": transition,
                "incident": incident,
                "sent_at": int(time.time()),
            }).encode("utf-8")
            req = urllib.request.Request(
                webhook_url, data=payload, method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "tuxwall-alerts/1.0"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                resp.read(1024)
        except Exception as exc:
            errors.append("webhook: %s" % exc)
    return errors


def _notify_async(incident, transition):
    cfg = _load_alert_config()
    def run():
        try:
            errors = _dispatch_alert(cfg, incident, transition)
            if errors:
                print("[incidents] notify %s: %s" % (incident.get("id"), "; ".join(errors)), flush=True)
        except Exception as exc:
            print("[incidents] notify failed: %s" % exc, flush=True)
    threading.Thread(target=run, daemon=True).start()


def test_alert_config():
    cfg = _load_alert_config()
    fake = {
        "id": "test-" + uuid4().hex[:6],
        "severity": cfg.get("min_severity", "warning"),
        "title": "TuxWall test alert",
        "detail": "If you can read this, the notification channel is working.",
        "status": "active",
        "first_seen": int(time.time()),
        "last_seen": int(time.time()),
    }
    if not cfg.get("enabled"):
        return {"ok": False, "error": "External notifications are disabled"}
    if not cfg.get("ntfy_url") and not cfg.get("webhook_url"):
        return {"ok": False, "error": "No webhook or ntfy URL configured"}
    errors = _dispatch_alert(cfg, fake, "test")
    if errors:
        return {"ok": False, "error": "; ".join(errors)}
    return {"ok": True, "message": "Test notification sent"}


def _iface_operstate(name):
    try:
        with open("/sys/class/net/%s/operstate" % name) as f:
            return f.read().strip().lower()
    except OSError:
        return "missing"


def _default_route_iface():
    try:
        proc = subprocess.run(["ip", "route", "show", "default"], capture_output=True,
                              text=True, timeout=4)
        for line in proc.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                i = parts.index("dev")
                if i + 1 < len(parts):
                    return parts[i + 1]
    except Exception:
        pass
    return ""


def _incident_bytes(n):
    try:
        return "%.1f GB" % (n / (1024 ** 3))
    except Exception:
        return "?"


_PLUGIN_INCIDENTS_CACHE = {}
_PLUGIN_INCIDENTS_LOCK = threading.Lock()
_PLUGIN_INCIDENTS_TTL = 300


def _plugin_incident_conditions():
    """Collect optional incident checks contributed by enabled plugins."""
    now = time.time()
    out = {}
    with _PLUGIN_INCIDENTS_LOCK:
        for pid in _plugin_ids():
            try:
                pin = _plugin_pin_status(pid)
                if pin.get("state") != "ok":
                    _plugin_pin_log(pid, pin)
                    out["plugin:%s:integrity" % pid] = (
                        "warning" if pin.get("state") == "unpinned" else "critical",
                        "Plugin %s blocked: integrity check failed" % pid,
                        str(pin.get("error") or "")[:600])
                    continue
            except Exception:
                pass
            try:
                manifest = _plugin_load_manifest(pid)
                if not manifest.get("alerts"):
                    continue
                cfg = _plugin_load_config(pid, manifest)
                if not cfg.get("enabled", True):
                    continue
                cached = _PLUGIN_INCIDENTS_CACHE.get(pid)
                if cached and now - cached.get("at", 0) < _PLUGIN_INCIDENTS_TTL:
                    items = cached.get("items") or []
                else:
                    result = plugin_action(pid, "incidents", {})
                    items = []
                    if result.get("ok"):
                        for inc in result.get("incidents") or []:
                            if not isinstance(inc, dict) or not inc.get("key"):
                                continue
                            sev = str(inc.get("severity") or "warning").lower()
                            if sev not in INCIDENT_SEVERITY_RANK:
                                sev = "warning"
                            items.append({
                                "key": str(inc["key"])[:80],
                                "severity": sev,
                                "title": str(inc.get("title") or "Plugin incident")[:160],
                                "detail": str(inc.get("detail") or "")[:600],
                            })
                    else:
                        items.append({
                            "key": "check-error",
                            "severity": "warning",
                            "title": "%s check failed" % (manifest.get("name") or pid),
                            "detail": str(result.get("error") or "Plugin check failed")[:600],
                        })
                    _PLUGIN_INCIDENTS_CACHE[pid] = {"at": now, "items": items}
                for inc in items:
                    key = "plugin:%s:%s" % (pid, inc["key"])
                    out[key] = (inc["severity"], inc["title"], inc["detail"])
            except Exception:
                continue
    return out


# systemd socket activation: until the first connection, ss attributes a
# socket-activated listener (ssh.socket on Debian/Ubuntu) to systemd
# (pid 1) alone. Such a listener belongs to the service behind the socket
# unit, so it is attributed to that service's process name - never to
# "systemd". Keys are service names without ".service"/"@" instance parts.
SOCKET_SERVICE_COMMS = {"ssh": "sshd", "sshd": "sshd"}
# Expected owners of claimed ports by process name. sshd legitimately
# shares port 22 with the WAN-side canary SSH by design (real sshd: LAN/VPN
# addresses only; canary: WAN only); _port_owner_incidents catches the
# dangerous variant of that split.
PORT_EXPECTED_COMMS = frozenset({"unbound", "kea-dhcp4", "kea-ctrl-agent", "nginx",
                                 "twistd", "avahi-daemon", "chronyd", "dbus-daemon",
                                 "sshd"})
_SS_USER_RE = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+)')
_LIST_SOCKETS_RE = re.compile(
    r"^\s*(\S+)\s+(Stream|Datagram|SequentialPacket)\s+(\S+\.socket)\s*(.*?)\s*$")


def _listen_key_addr(addr):
    """Comparable form of a listen address from ss or list-sockets:
    interface suffixes dropped, ss's dual-stack "*" read as "[::]"."""
    addr = (addr or "").split("%", 1)[0]
    if addr in ("*", ""):
        return "[::]"
    return addr


def _systemd_socket_listeners(text):
    """`systemctl list-sockets --all --no-legend --show-types` ->
    {(proto, addr, port): (socket_unit, comm)} for IP listeners, where comm
    is the process name of the service the socket activates."""
    out = {}
    for line in (text or "").splitlines():
        m = _LIST_SOCKETS_RE.match(line)
        if not m:
            continue
        listen, stype, unit, activates = m.groups()
        addr, _, port_s = listen.rpartition(":")
        if not addr or not port_s.isdigit():
            continue
        service = (activates or "").split()[0].rstrip(",") if activates else ""
        if not service or service == "-":
            service = unit[:-len(".socket")]
        base = service.split("@", 1)[0]
        if base.endswith(".service"):
            base = base[:-len(".service")]
        comm = SOCKET_SERVICE_COMMS.get(base, base)
        proto = "tcp" if stype == "Stream" else "udp"
        out[(proto, _listen_key_addr(addr), int(port_s))] = (unit, comm)
    return out


def _proc_comm(pid):
    try:
        with open("/proc/%d/comm" % pid) as f:
            return f.read().strip()
    except OSError:
        return ""


def _parse_ss_listeners(proto, text, sockets, comm_of=_proc_comm):
    """`ss -tlnp` / `ss -ulnp` output -> [(proto, addr, port, pid, comm,
    socket_unit)]. A socket shared by several processes is attributed to
    the first one that is not systemd; a socket held by systemd (pid 1)
    alone is a socket-activated listener and is attributed to the service
    behind its unit (`sockets`, from _systemd_socket_listeners), with
    socket_unit set. pid 1 without a matching socket unit stays "systemd"
    (a stranger to every check)."""
    out = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        addr, _, port_s = parts[3].rpartition(":")
        if not port_s.isdigit():
            continue
        port = int(port_s)
        users = [(name, int(pid)) for name, pid in _SS_USER_RE.findall(line)]
        pid, comm, unit = 0, "", ""
        real = [u for u in users if u[1] != 1]
        if real:
            name, pid = real[0]
            comm = comm_of(pid) or name
        elif users:
            pid = 1
            sock = sockets.get((proto, _listen_key_addr(addr), port))
            if sock:
                unit, comm = sock
            else:
                comm = comm_of(1) or users[0][0] or "systemd"
        out.append((proto, addr, port, pid, comm, unit))
    return out


def _listener_who(pid, comm, unit):
    if unit:
        return "%s (via %s, systemd socket activation)" % (comm or "a service", unit)
    return "%s (pid %d)" % (comm or "an unknown process", pid)


def _port_owner_incidents(listeners, claimed, expected_pids, expected_comms, wan_ips):
    """Port-ownership incidents from the attributed listeners: a stranger
    on a port a Tuxwall service needs (portowner:<port>/<proto>), and real
    sshd - running or socket-activated - on a wildcard or WAN address
    (sshd:wan). Returns {key: (severity, title, detail)}."""
    out = {}
    holders = {}
    for proto, addr, port, pid, comm, unit in listeners:
        if (port, proto) in claimed and pid:
            holders.setdefault((port, proto), []).append((pid, comm, unit))
    for (port, proto), hl in holders.items():
        strangers = [h for h in hl
                     if h[0] not in expected_pids and h[1] not in expected_comms]
        if not strangers:
            continue
        owner = claimed[(port, proto)]
        expected_here = (len(hl) - len(strangers)) > 0
        spid, scomm, sunit = strangers[0]
        who = _listener_who(spid, scomm, sunit)
        fix = sunit or scomm or "it"
        if expected_here:
            out["portowner:%d/%s" % (port, proto)] = (
                "warning",
                "Port %d/%s is contested by %s" % (port, proto, who),
                "%s needs port %d/%s and is bound on one address, but %s "
                "holds another address on the same port - a partial "
                "conflict that will break one side. Stop or reconfigure "
                "%s, or move the Tuxwall service."
                % (owner, port, proto, who, fix))
        else:
            out["portowner:%d/%s" % (port, proto)] = (
                "critical",
                "Port %d/%s is held by %s" % (port, proto, who),
                "%s needs port %d/%s, but %s is bound there instead - "
                "the core service cannot use it. If %s is software you "
                "installed, stop or reconfigure it, or move the Tuxwall "
                "service." % (owner, port, proto, who, fix))

    # sshd shares port 22 with the canary by design, but only on LAN/VPN
    # addresses - the WAN address must belong to the canary alone. A
    # socket-activated sshd counts as soon as its socket listens there.
    for proto, addr, port, pid, comm, unit in listeners:
        if comm == "sshd" and port == 22 and (
                addr in ("0.0.0.0", "*", "[::]", "") or addr in wan_ips
                or addr.strip("[]") in wan_ips):
            if unit:
                where = ("ListenStream= in %s (systemctl edit %s)" % (unit, unit))
            else:
                where = "ListenAddress in /etc/ssh/sshd_config"
            out["sshd:wan"] = (
                "critical",
                "Real sshd is bound on the WAN address",
                "%s is listening on %s port 22 - the WAN "
                "should only expose the deception layer's fake SSH. "
                "Restrict sshd to the LAN/WireGuard addresses "
                "(%s)." % (_listener_who(pid, comm, unit), addr, where))
            break
    return out


def _incident_conditions():
    now = time.time()
    desired = {}

    def add(key, severity, title, detail):
        desired[key] = (severity, title, detail)

    wan = _default_route_iface()
    if not wan:
        add("wan:route", "critical", "WAN has no default route",
            "The router has no default route; all internet access is down.")
    elif _iface_operstate(wan) != "up":
        add("wan:link", "critical", "WAN link is down",
            "%s reports %s." % (wan, _iface_operstate(wan)))

    conf = _net_conf()
    lan_ifaces = conf.get("lan_ifaces") or []
    if not lan_ifaces:
        # derive: every UP non-WAN physical interface (skip VLAN subs,
        # the tarpit handles those separately)
        wan = _detect_wan_iface()
        try:
            out = subprocess.run(["ip", "-o", "link", "show"],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                iface = line.split(":")[1].strip().split("@")[0]
                if iface in ("lo", wan) or "." in iface:
                    continue
                # virtual interfaces (wireguard tunnels, ifb shaping
                # devices) are never a "LAN link" to monitor; they flap
                # by design. Only physical interfaces with a carrier.
                if iface.startswith(("wg", "ifb", "tun", "tap", "veth", "br-")):
                    continue
                if "UP" in line and "LOWER_UP" in line:
                    lan_ifaces.append(iface)
        except Exception:
            pass
    for name in lan_ifaces[:4]:  # cap at 4 to bound the check cost
        label = "LAN"
        state = _iface_operstate(name)
        if state == "missing":
            add("lan:%s" % name, "critical", "%s interface is missing" % label,
                "%s does not exist." % name)
        elif state != "up":
            add("lan:%s" % name, "warning", "%s link is down" % label,
                "%s reports %s." % (name, state))

    try:
        persist = _load_vlan_persist()
        for iface, meta in persist.items():
            if iface.startswith("__"):
                continue
            state = _iface_operstate(iface)
            label = (meta or {}).get("label") or iface
            if state == "missing":
                add("vlan:%s" % iface, "warning", "VLAN %s is missing" % label,
                    "%s does not exist." % iface)
            elif state != "up":
                add("vlan:%s" % iface, "warning", "VLAN %s link is down" % label,
                    "%s reports %s." % (iface, state))
    except Exception:
        pass

    services = (
        ("unbound.service", "Unbound DNS", "critical"),
        ("kea-dhcp4-server.service", "Kea DHCP", "critical"),
        ("crowdsec.service", "CrowdSec", "warning"),
        ("suricata.service", "Suricata IDS", "warning"),
        ("crowdsec-firewall-bouncer.service", "CrowdSec firewall bouncer", "warning"),
    )
    for unit, label, severity in services:
        try:
            proc = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                                  capture_output=True, timeout=5)
            if proc.returncode != 0:
                add("service:%s" % unit, severity, "%s is not running" % label,
                    "%s is not active. Check the service on System ▸ Maintenance." % unit)
        except Exception:
            pass

    # 2026-11-10: an in-place edit (sed -i) on eve.json rotates the file
    # out from under suricata - the engine keeps writing to the orphaned
    # inode while the dashboard and the tripwire watch a frozen file. This
    # box ran blind for 37 hours before anyone noticed. Detect it by
    # comparison: suricata writes every alert to BOTH fast.log and
    # eve.json, so fresh-fast.log + stale-eve.json means the eve output
    # is orphaned (never edit or rotate eve.json in place). A quiet
    # network makes both stale and correctly raises nothing.
    try:
        proc = subprocess.run(["systemctl", "is-active", "--quiet", "suricata"],
                              capture_output=True, timeout=5)
        if proc.returncode == 0:
            eve_age = time.time() - os.path.getmtime(SURICATA_EVE_LOG)
            fast_age = time.time() - os.path.getmtime("/var/log/suricata/fast.log")
            if fast_age < 600 and eve_age > fast_age + 300:
                add("ids:eve-stale", "critical", "IDS is blind: eve.json is frozen",
                    "Suricata is running and alerting (fast.log is fresh) but "
                    "/var/log/suricata/eve.json has not been written in %d "
                    "minutes - the engine is writing to an orphaned file, so "
                    "the dashboard and the tripwire see nothing. Restart "
                    "suricata, and never edit eve.json in place."
                    % int(eve_age / 60))
    except Exception:
        pass

    # Tripwire engine + watcher heartbeats (only when it is armed or a trip
    # is in force: a disabled tripwire runs no watchers by design).
    try:
        tw_conf = _tripwire_read(TRIPWIRE_CONF, {})
        tw_st = _tripwire_read(TRIPWIRE_STATE, {})
        tw_mode = str(tw_conf.get("mode") or "disabled")
        tw_tripped = bool(tw_st.get("tripped"))
        if tw_mode != "disabled" or tw_tripped:
            twh = tripwire_health(tw_mode, tw_tripped)
            if not twh["healthy"]:
                add("tripwire:engine", "critical" if tw_tripped else "warning",
                    "Tripwire is not watching",
                    "Mode %s: %s. Trip-class events may be missed%s. Check "
                    "Security > Tripwire and `systemctl status tuxwall-tripwire`."
                    % (tw_mode, "; ".join(twh["problems"]),
                       " and the lockdown is not being re-enforced" if tw_tripped
                       and twh["active"] != "active" else ""))
    except Exception:
        pass

    try:
        usage = shutil.disk_usage("/")
        pct = usage.used * 100.0 / usage.total if usage.total else 0
        if pct >= 92:
            add("disk:root", "critical", "Root filesystem is almost full",
                "%.1f%% used (%s free)." % (pct, _incident_bytes(usage.free)))
        elif pct >= 88:
            add("disk:root", "warning", "Root filesystem is filling up",
                "%.1f%% used (%s free)." % (pct, _incident_bytes(usage.free)))
    except Exception:
        pass

    try:
        mem_total = mem_avail = 0
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if parts and parts[0] == "MemTotal:":
                    mem_total = int(parts[1]) * 1024
                elif parts and parts[0] == "MemAvailable:":
                    mem_avail = int(parts[1]) * 1024
        if mem_total:
            pct = (mem_total - mem_avail) * 100.0 / mem_total
            if pct >= 97:
                add("memory:root", "critical", "Memory is critically low",
                    "%.1f%% used; the router is at risk of OOM." % pct)
            elif pct >= 92:
                add("memory:root", "warning", "Memory usage is high",
                    "%.1f%% used." % pct)
    except Exception:
        pass

    # Functional firewall check: the ufw systemd unit reports
    # "active/finished" even when its ruleset failed to load (observed
    # 2026-11-09: a failed boot left INPUT/FORWARD policy ACCEPT - the
    # box failing OPEN - for 7 minutes with the unit green, and a failed
    # reload can do the same live). Trust the packet filter's actual
    # state, not the unit file. A tripwire lockdown never changes chain
    # policies, so this cannot false-positive during containment.
    try:
        for ipt, fam in (("iptables", "IPv4"), ("ip6tables", "IPv6")):
            state = []
            enforcing = True
            for chain in ("INPUT", "FORWARD"):
                # iptables -S takes ONE chain; first line is "-P <chain> <pol>"
                out = subprocess.run([ipt, "-S", chain],
                                     capture_output=True, text=True, timeout=5).stdout
                first = out.splitlines()[0].split() if out.splitlines() else []
                pol = first[2] if len(first) >= 3 and first[0] == "-P" else "unknown"
                state.append("%s=%s" % (chain, pol))
                if pol != "DROP":
                    enforcing = False
            if not enforcing:
                add("fw:function-%s" % fam.lower(), "critical",
                    "Firewall is NOT enforcing (%s)" % fam,
                    "INPUT/FORWARD are not DROP (%s) - the packet filter is "
                    "failing OPEN. Usually a broken /etc/ufw/before.rules; "
                    "validate with: tuxwall-fw-reload (tests before applying)."
                    % ", ".join(state))
    except Exception:
        pass

    # Unbound functional probe: the service can be 'active' while
    # SERVFAILing everything (observed after a long WAN blackout - the
    # daemon never recovered its upstream state and liveness checks
    # missed it for hours). Compare a query THROUGH unbound with one
    # DIRECT to an upstream: fire only when the WAN path works but the
    # local resolver does not - during an intentional WAN containment
    # (tripwire) the direct query fails too and this stays silent.
    try:
        local = subprocess.run(
            ["dig", "+time=2", "+tries=1", "+short", "@127.0.0.1", "cloudflare.com"],
            capture_output=True, text=True, timeout=5)
        if not (local.stdout or "").strip():
            direct = subprocess.run(
                ["dig", "+time=2", "+tries=1", "+short", "@1.1.1.1", "cloudflare.com"],
                capture_output=True, text=True, timeout=5)
            if (direct.stdout or "").strip():
                add("service:unbound-function", "critical",
                    "Unbound is running but not resolving",
                    "The DNS service answers but returns no results while the "
                    "WAN path is working - queries from every LAN client are "
                    "failing. Restart it: sudo systemctl restart unbound")
    except Exception:
        pass

    try:
        for zone in sorted(os.listdir("/sys/class/thermal")):
            if not zone.startswith("thermal_zone"):
                continue
            base = "/sys/class/thermal/" + zone
            with open(base + "/type") as f:
                kind = f.read().strip()
            if kind not in ("x86_pkg_temp", "acpitz"):
                continue
            with open(base + "/temp") as f:
                temp = float(f.read().strip()) / 1000.0
            if temp >= 92:
                add("temp:cpu", "critical", "CPU temperature is critical",
                    "%s reports %.0f°C." % (kind, temp))
            elif temp >= 85:
                add("temp:cpu", "warning", "CPU temperature is high",
                    "%s reports %.0f°C." % (kind, temp))
            break
    except Exception:
        pass

    # --- Port ownership conflicts ------------------------------------------
    # Every port Tuxwall depends on - DNS, DHCP, the web vhosts, the
    # dashboard API, the agent, the deception layer - is claimed by a
    # known service. Any OTHER process sitting on a claimed port (dnsmasq
    # stealing 53/67 from unbound/kea, a stray daemon squatting on a
    # dashboard port, unforeseen software reserving a core port) means a
    # core service failed to bind or is about to. Detected with process
    # attribution every cycle.
    deception_ports = {}
    try:
        conf_ports = []
        try:
            conf_ports = [int(p) for p in (_honey_load_conf().get("ports") or [])]
        except Exception:
            pass
        with HONEY_APPLY_LOCK:
            live_ports = [int(p) for p in (HONEY_STATE.get("ports") or [])]
        for p in set(conf_ports) | set(live_ports):
            deception_ports[int(p)] = "the deception layer (tarpit)"
        for p in set(CANARY_PORTS) | {cp for cp, _ in _canary_conf_ports()}:
            deception_ports.setdefault(int(p), "the deception layer (canary)")
    except Exception:
        pass

    # claimed[(port, proto)] = the service that needs it
    claimed = {}
    for p, owner in deception_ports.items():
        claimed[(p, "tcp")] = owner
        claimed[(p, "udp")] = owner
    claimed[(53, "tcp")] = "Unbound DNS"
    claimed[(53, "udp")] = "Unbound DNS"
    claimed[(67, "udp")] = "Kea DHCP"
    claimed[(8008, "tcp")] = "the Tuxwall dashboard API"
    claimed[(4096, "tcp")] = "the Tuxwall AI agent"
    try:
        nproc = subprocess.run(["nginx", "-T"], capture_output=True,
                               text=True, timeout=10)
        for m in re.finditer(r"^\s*listen\s+(?:\[?[^\]\s]*\]?:)?(\d+)\s*;",
                             nproc.stdout, re.M):
            claimed.setdefault((int(m.group(1)), "tcp"), "nginx")
    except Exception:
        pass

    # expected owners: MainPIDs of the core units + well-known service names
    expected_pids = set()
    for unit in ("unbound.service", "kea-dhcp4-server.service", "nginx.service",
                 "opencanary.service", "tuxwall.service", "tuxwall-agent.service",
                 "tuxwall-collector.service"):
        try:
            proc = subprocess.run(
                ["systemctl", "show", unit, "--property=MainPID", "--value"],
                capture_output=True, text=True, timeout=5)
            pid = int((proc.stdout or "0").strip() or 0)
            if pid > 0:
                expected_pids.add(pid)
        except Exception:
            pass
    expected_comms = PORT_EXPECTED_COMMS

    # one ss pass with process attribution, shared by every check below
    listeners = []            # (proto, addr, port, pid, comm, socket_unit)
    try:
        sockets = _systemd_socket_listeners(subprocess.run(
            ["systemctl", "list-sockets", "--all", "--no-legend", "--show-types"],
            capture_output=True, text=True, timeout=10).stdout)
    except Exception:
        sockets = {}
    try:
        for proto, sscmd in (("tcp", ["ss", "-tlnp"]), ("udp", ["ss", "-ulnp"])):
            proc = subprocess.run(sscmd, capture_output=True, text=True,
                                  timeout=10)
            listeners.extend(_parse_ss_listeners(proto, proc.stdout, sockets))
    except Exception:
        pass

    # Conflict 1 (a stranger holds a port a Tuxwall service depends on) and
    # the sshd/canary split on port 22
    try:
        wan_ips = {ip for ip in (_honey_wan_ip(),
                                 (HONEY_STATE.get("wan_ip6") or None)) if ip}
        desired.update(_port_owner_incidents(listeners, claimed, expected_pids,
                                             expected_comms, wan_ips))
    except Exception:
        pass

    # Conflict 2: a user configuration points at a deception-layer port -
    # the honeypot owns the listener (or the forward DNATs past it), so the
    # user's service is silently dead or the canary is bypassed.
    try:
        conf_claims = []
        for r in (_load_pf() or []):
            try:
                conf_claims.append((int(r["ext_port"]),
                                    "port-forward to %s" % (r.get("int_ip") or "?")))
            except (KeyError, TypeError, ValueError):
                pass
        proc = subprocess.run(["ufw", "status"], capture_output=True,
                              text=True, timeout=10)
        wan_if = _wan_iface()
        for line in proc.stdout.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)(?: on (\S+))?\s+ALLOW IN\s", line)
            if not m:
                continue
            if wan_if and m.group(3) and m.group(3) != wan_if:
                continue          # not WAN-facing
            if "tuxwall" in line.lower() or "canary" in line.lower():
                continue          # the deception layer's own managed rules
            try:
                port = int(m.group(1))
            except ValueError:
                continue
            if port in deception_ports:
                conf_claims.append((port, "WAN firewall allow rule"))
        seen = set()
        for port, what in conf_claims:
            if port in deception_ports and port not in seen:
                seen.add(port)
                add("portconflict:%d" % port, "warning",
                    "Port %d conflicts with the deception layer" % port,
                    "%s also uses port %d (%s): traffic there goes to the "
                    "honeypot, not your service. Move the service to another "
                    "port, or adjust the deception ports under Security."
                    % (what, port, deception_ports[port]))
    except Exception:
        pass

    # --- Unexpected WAN-reachable listeners --------------------------------
    # Anything listening on 0.0.0.0/[::] (TCP: a deliberate act) or bound
    # to the WAN address itself that is not an expected service is one
    # fat-fingered firewall rule away from internet exposure. Expected:
    # public web (80/443), DHCP (67), mDNS reflector (5353), WireGuard
    # (51820) and the deception layer.
    try:
        approved = {80, 443, 67, 5353, 51820} | set(deception_ports)
        wan_ips = {ip for ip in (_honey_wan_ip(),
                                 (HONEY_STATE.get("wan_ip6") or None)) if ip}
        flagged = {}
        for proto, addr, port, pid, comm, _unit in listeners:
            if port in approved or addr.startswith("127.") or addr.startswith("[::1]"):
                continue
            if (proto == "tcp" and addr in ("0.0.0.0", "*", "[::]", "")) \
                    or addr in wan_ips:
                flagged.setdefault((port, proto), comm or "a service")
        for (port, proto), who in sorted(flagged.items()):
            add("listener:%d/%s" % (port, proto), "warning",
                "Unexpected service on port %d (%s)" % (port, proto),
                "%s is bound on every interface - including the WAN - on "
                "port %d/%s. If that is intentional, allow or forward it "
                "deliberately; otherwise stop the service or rebind it to "
                "the LAN address." % (who, port, proto))
    except Exception:
        pass

    # --- AIDE integrity check freshness -------------------------------------
    # The nightly AIDE run is the file-integrity tripwire; a silently
    # stopped timer means nobody is watching the filesystem.
    try:
        st = os.stat("/var/log/aide/aide.log")
        age_h = (now - st.st_mtime) / 3600.0
        if age_h > 30:
            add("aide:stale", "warning", "AIDE integrity check is stale",
                "Last AIDE run was %.0f hours ago (expected daily). Check: "
                "systemctl status dailyaidecheck.timer" % age_h)
    except FileNotFoundError:
        pass                       # AIDE not installed on this box
    except Exception:
        pass

    # --- System backup freshness ---------------------------------------------
    try:
        backups = glob.glob("/var/lib/tuxwall/backups/system/system-backup-*.tar.gz")
        latest = max((os.path.getmtime(b) for b in backups), default=0)
        if not latest:
            add("backup:never", "warning", "No system backup has been created",
                "A gateway without a config backup turns every mistake into "
                "a rebuild. Create one under System > Backups.")
        else:
            stale_days = _bk.load_settings()["stale_days"] if _bk is not None else 8
            if now - latest > stale_days * 86400:
                add("backup:stale", "warning", "System backup is stale",
                    "Last system backup is %.0f days old (threshold: %d days, set under System > "
                    "Backups)." % ((now - latest) / 86400, stale_days))
    except Exception:
        pass
    # A failed run (persisted in backups/state.json) stays an incident until
    # the next successful backup; an interrupted run counts as failed.
    try:
        if _bk is not None:
            _bk.reconcile_interrupted()
            failed = _bk.failure_incident()
            if failed:
                add("backup:failed", "warning", failed[0], failed[1])
            usb_failed = _bk.usb_failure_incident()
            if usb_failed:
                add("backup:usb-failed", "warning", usb_failed[0], usb_failed[1])
    except Exception:
        pass

    # --- Duplicate NAT masquerade rules ---------------------------------------
    # Hand-added NAT stanzas in /etc/ufw/before.rules survive as APPENDED
    # copies on every ufw reload (observed in the field). tuxwall-nat owns
    # the masquerade; duplicates are dead weight that grows over time.
    try:
        wan_if = _wan_iface()
        if wan_if:
            proc = subprocess.run(["iptables-save", "-t", "nat"],
                                  capture_output=True, text=True, timeout=10)
            n = proc.stdout.count(
                "-A POSTROUTING -o %s -j MASQUERADE" % wan_if)
            if n > 1:
                add("nat:duplicates", "warning",
                    "Duplicate NAT masquerade rules (%d)" % n,
                    "Only one LAN->WAN masquerade is needed; %d copies exist. "
                    "A legacy *nat stanza in /etc/ufw/before.rules is being "
                    "re-appended on every ufw reload - remove it (the "
                    "tuxwall-nat service owns NAT)." % n)
    except Exception:
        pass

    return desired


def _reconcile_incidents(desired):
    now = time.time()
    opened, resolved = [], []
    with _INCIDENT_LOCK:
        items = _load_incidents()
        active = {i.get("key"): i for i in items if i.get("status") == "active"}
        changed = False
        for key, (severity, title, detail) in desired.items():
            inc = active.get(key)
            if inc:
                if (inc.get("severity") != severity or inc.get("title") != title
                        or inc.get("detail") != detail or now - inc.get("last_seen", 0) > 300):
                    inc["severity"] = severity
                    inc["title"] = title
                    inc["detail"] = detail
                    inc["last_seen"] = now
                    changed = True
            else:
                inc = {
                    "id": uuid4().hex[:12],
                    "key": key,
                    "severity": severity,
                    "title": title,
                    "detail": detail,
                    "status": "active",
                    "first_seen": now,
                    "last_seen": now,
                    "acknowledged": False,
                }
                items.insert(0, inc)
                opened.append(dict(inc))
                changed = True
        for key, inc in active.items():
            if key not in desired:
                inc["status"] = "resolved"
                inc["resolved_at"] = now
                inc["last_seen"] = now
                resolved.append(dict(inc))
                changed = True
        if changed:
            _incident_write_json(INCIDENTS_FILE, {"items": _trim_incidents(items)})
    for inc in opened:
        _notify_async(inc, "opened")
    for inc in resolved:
        _notify_async(inc, "resolved")
    return opened, resolved


def run_incident_check():
    desired = _incident_conditions()
    return _reconcile_incidents(desired)


class IncidentMonitor(threading.Thread):
    def __init__(self):
        super().__init__(name="incident-monitor", daemon=True)
        self.running = True

    def run(self):
        time.sleep(4)
        while self.running:
            try:
                run_incident_check()
            except Exception as exc:
                print("[incidents] check failed: %s" % exc, flush=True)
            time.sleep(INCIDENT_CHECK_INTERVAL)


_INCIDENT_MONITOR = None
_INCIDENT_MONITOR_LOCK = threading.Lock()


def start_incident_monitor():
    global _INCIDENT_MONITOR
    with _INCIDENT_MONITOR_LOCK:
        if _INCIDENT_MONITOR is None:
            _INCIDENT_MONITOR = IncidentMonitor()
            _INCIDENT_MONITOR.start()
        return _INCIDENT_MONITOR


# --- Agent facts: a compact, live summary of this install for the dashboard's
# OpenCode agent (tuxwall-agent). Loaded as an "instructions" file from
# /etc/tuxwall/opencode.json so the agent knows the box before the first
# question. Checked every 5 min; the file is only rewritten when a value
# changes (every rewrite reaches open sessions as an instruction update).
# No secrets: no keys, tokens, passwords, peer configs or public addresses.
AGENT_FACTS_FILE = "/var/lib/tuxwall/agent/facts.md"
AGENT_FACTS_INTERVAL = 300
AGENT_FACTS_START_DELAY = 30
AGENT_FACTS_SERVICES = (
    "systemd-networkd", "tuxwall-nat", "ufw", "kea-dhcp4-server", "unbound", "radvd",
    "wg-quick@wg0", "crowdsec", "crowdsec-firewall-bouncer", "suricata", "opencanary",
    "tuxwall-tripwire", "tuxwall-sqm", "nginx", "tuxwall", "tuxwall-agent", "tuxwall-collector",
)
_AGENT_FACTS_HEADER_LINES = 4


def _af_run(args, timeout=8):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.stdout if p.returncode == 0 else ""
    except Exception:
        return ""


def _af_ago(ts, now=None):
    try:
        d = int((now or time.time()) - float(ts))
    except (TypeError, ValueError):
        return "?"
    if d < 3600:
        return "<1 h ago"
    if d < 86400:
        return "%d h ago" % (d // 3600)
    return "%d d ago" % (d // 86400)


def _af_clip(text, n):
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[:n - 3].rstrip() + "..."


def _af_round(n):
    return str(n) if n < 1000 else "~{:,}".format(int(round(n, -2)))


def _af_addrs():
    """{dev: {"v4": [cidr], "v6": [cidr], "state": str}} from `ip -j addr`."""
    out = {}
    try:
        data = json.loads(_af_run(["ip", "-j", "addr", "show"]) or "[]")
    except ValueError:
        data = []
    for l in data:
        dev = l.get("ifname", "")
        if not dev or dev == "lo":
            continue
        e = out.setdefault(dev, {"v4": [], "v6": [], "state": (l.get("operstate") or "").lower()})
        for a in l.get("addr_info") or []:
            if a.get("local") and a.get("scope") == "global":
                e["v4" if a.get("family") == "inet" else "v6"].append("%s/%s" % (a["local"], a.get("prefixlen")))
    return out


def _af_v6_text(cidrs):
    ula, gua = [], 0
    for c in cidrs:
        try:
            n = ipaddress.ip_interface(c).network
        except ValueError:
            continue
        if n.is_private:
            if str(n) not in ula:
                ula.append(str(n))
        else:
            gua += 1
    parts = ula + (["GUA from ISP prefix (not shown)"] if gua else [])
    return ", ".join(parts) or "none"


def _af_v4_text(cidrs):
    out = []
    for c in cidrs:
        try:
            ip = ipaddress.ip_interface(c).ip
        except ValueError:
            continue
        out.append(c if ip.is_private else ("public (not shown)" if ip.is_global else "CGNAT/shared address"))
    return ", ".join(out) or "none"


def _af_section_system():
    lines = ["## System"]
    boot = ""
    try:
        with open("/proc/uptime") as f:
            boot = time.strftime("%Y-%m-%d %H:%M", time.localtime(time.time() - float(f.read().split()[0])))
    except (OSError, ValueError, IndexError):
        pass
    lines.append("- Host `%s`, TuxWall %s, last boot %s" % (os.uname().nodename, TUXWALL_VERSION, boot or "?"))
    dr = _af_run(["ip", "route", "show", "default"]).split()
    dr6 = _af_run(["ip", "-6", "route", "show", "default"]).split()
    lines.append("- Default route: IPv4 via dev `%s`, IPv6 via dev `%s`" % (
        dr[dr.index("dev") + 1] if "dev" in dr[:-1] else "NONE",
        dr6[dr6.index("dev") + 1] if "dev" in dr6[:-1] else "none"))
    return lines


def _af_section_interfaces():
    topo_mod = globals().get("_topology")
    addrs = _af_addrs()
    lines = ["## Interfaces and networks"]
    if topo_mod is None or not topo_mod.has_file():
        lines.append("- No /etc/tuxwall/interfaces.json role record; live addresses:")
        for dev, e in sorted(addrs.items()):
            lines.append("  - `%s` %s: IPv4 %s; IPv6 %s" % (dev, e["state"], _af_v4_text(e["v4"]),
                                                            _af_v6_text(e["v6"])))
        return lines
    t = topo_mod.load()
    inv = {i["device"]: i for i in topo_mod.inventory()}

    def link(dev):
        i = inv.get(dev)
        if not i:
            return "MISSING"
        return "up" if i.get("carrier") else "no link (%s)" % (i.get("operstate") or "down")

    lines.append("Roles from /etc/tuxwall/interfaces.json (apply_locked=%s, policy=%s):" % (
        str(t.get("apply_locked", True) is not False).lower(), json.dumps(t.get("policy") or {})))
    w = t.get("wan") or {}
    wdev = w.get("device", "")
    lines.append("- WAN `%s` (%s): %s; IPv4 %s; IPv6 %s" % (
        wdev, w.get("mode", "?"), link(wdev), _af_v4_text((addrs.get(wdev) or {}).get("v4", [])).replace("none", "NONE"),
        _af_v6_text((addrs.get(wdev) or {}).get("v6", []))))
    for n in topo_mod.networks(t):
        dev = n.get("device", "")
        flags = []
        if n.get("vlan"):
            flags.append("VLAN %s on `%s`" % (n.get("vlan"), n.get("parent", "?")))
        if n.get("role") != "vpn":
            flags.append("DHCP %s" % ("on" if n.get("dhcp") else "off"))
            flags.append("RA %s" % ("on" if n.get("ra") else "off"))
        label = "LAN" if n.get("role") == "lan" else "%s %s \"%s\"" % (n.get("role", "").upper(), n.get("id"), n.get("name"))
        lines.append("- %s `%s`: %s; %s (subnet %s); IPv6 %s%s" % (
            label, dev, link(dev), n.get("address") or "no address", n.get("subnet") or "?",
            _af_v6_text(n.get("subnets6") or []), ("; " + ", ".join(flags)) if flags else ""))
    known = {wdev} | {n.get("device") for n in topo_mod.networks(t)}
    other = ["%s(%s)" % (d, "up" if i.get("carrier") else "down") for d, i in sorted(inv.items()) if d not in known]
    if other:
        lines.append("- Other devices (no role): %s" % ", ".join(other))
    return lines


def _af_section_policy():
    topo_mod = globals().get("_topology")
    if topo_mod is None or not hasattr(topo_mod, "current_policy"):
        return []
    p = topo_mod.current_policy()
    names = {c["id"]: c.get("name", c["id"]) for c in p.get("columns") or []}
    lines = ["## Zone policy (Interfaces > Policy matrix, derived from ufw)",
             "Defaults: " + ", ".join("%s %s" % (k, v) for k, v in (p.get("defaults") or {}).items())]
    for src, row in (p.get("cells") or {}).items():
        cells = []
        for dst, c in row.items():
            if c.get("state") == "self":
                continue
            s = c.get("state", "?")
            if c.get("exceptions"):
                s += "+%d exc" % len(c["exceptions"])
            cells.append("%s %s" % (names.get(dst, dst), s))
        lines.append("- from %s -> %s" % (names.get(src, src), ", ".join(cells)))
    for note in p.get("notes") or []:
        lines.append("- Note: %s" % note)
    return lines


def _af_section_services():
    try:  # one call; is-active exits 3 when any unit is down, stdout still lists every state
        states = subprocess.run(["systemctl", "is-active"] + list(AGENT_FACTS_SERVICES),
                                capture_output=True, text=True, timeout=10).stdout.split()
    except Exception:
        states = []
    if len(states) != len(AGENT_FACTS_SERVICES):
        states = ["active" if service_active(s) else "inactive" for s in AGENT_FACTS_SERVICES]
    up = [s for s, st in zip(AGENT_FACTS_SERVICES, states) if st == "active"]
    down = ["%s (%s)" % (s, st) for s, st in zip(AGENT_FACTS_SERVICES, states) if st != "active"]
    return ["## Services",
            "- active: %s" % (", ".join(up) or "none"),
            "- NOT active: %s" % (", ".join(down) or "none")]


def _af_section_firewall():
    lines = ["## Firewall (ufw)"]
    st = _af_run(["ufw", "status"], timeout=15)
    lines.append("- ufw: %s" % ("active" if "Status: active" in st else "INACTIVE or unknown"))
    guard = globals().get("_fw_guard")
    if guard is not None:
        ctx = _fw_ctx("")
        s = guard.summary(guard.load_ruleset(ctx), ctx)
        g = s.get("groups") or {}
        lines.append("- Rules: %d (managed %d, policy %d, owner's %d); by owner: %s" % (
            sum(g.values()), g.get("managed", 0), g.get("policy", 0), g.get("yours", 0),
            ", ".join("%s %d" % kv for kv in sorted((s.get("owners") or {}).items(), key=lambda kv: -kv[1]))))
        inv = s.get("invariants") or []
        lines.append("- Guard invariants violated: %s" % (
            "; ".join(str(i.get("title") or i.get("id") or i)[:100] for i in inv[:5]) if inv else "none"))
        c = s.get("context") or {}
        hp = c.get("honeypot") or {}
        tw = c.get("tripwire") or {}
        csx = c.get("crowdsec") or {}
        if csx.get("mode") == "nftables":
            cs_desc = "nftables mode, %s hook(s), priority %s" % (
                ", ".join(csx.get("hooks") or []) or "input",
                "/".join(str((f or {}).get("priority")) for f in (csx.get("families") or {}).values()) or "?")
        else:
            cs_desc = "%s mode, chains %s" % (csx.get("mode") or "iptables",
                                               ", ".join(c.get("crowdsec_chains") or []) or "none")
        lines.append("- Deception: honeypot %s (WAN ports %s); canary %s; tripwire mode %s%s; CrowdSec bouncer: %s" % (
            "enabled" if hp.get("enabled") else "DISABLED", ", ".join(str(x) for x in hp.get("ports") or []) or "none",
            "active" if c.get("canary_active") else "NOT active", tw.get("mode", "?"),
            " (TRIPPED)" if tw.get("tripped") else "", cs_desc))
    else:
        n = len([l for l in st.splitlines() if l[:1] == "["]) or len([l for l in st.splitlines() if " ALLOW" in l or " DENY" in l])
        lines.append("- Rules: %d (ufw status)" % n)
    try:
        import canary_egress as _ce
        ok = []
        for fam, path in (("v4", "/etc/ufw/before.rules"), ("v6", "/etc/ufw/before6.rules")):
            with open(path) as f:
                ok.append(_ce.present(f.read(), fam))
        lines.append("- Canary egress containment in before*.rules: %s" % ("present (v4+v6)" if all(ok) else "MISSING"))
    except Exception:
        pass
    view = globals().get("fw_findings_view")
    if view is not None:
        code, res = view("findings", "")
        if code == 200 and res.get("ok"):
            cnt = res.get("counts") or {}
            lines.append("- Findings (Firewall > Findings): %d open - %s" % (
                len(res.get("findings") or []), ", ".join("%s %d" % (k, v) for k, v in cnt.items())))
            for f in [f for f in res.get("findings") or [] if f.get("severity") in ("critical", "high", "medium")][:8]:
                lines.append("  - [%s] %s" % (f.get("severity"), _af_clip(f.get("title"), 140)))
    snap = globals().get("_fw_snap")
    if snap is not None:
        snaps = snap.list_snaps(_fw_ctx(raw=False))
        if snaps:
            m = snaps[0]
            lines.append("- Latest snapshot: `%s` (%s, %s%s); %d kept in %s" % (
                m.get("id"), m.get("time", "?"), m.get("kind", "?"),
                (": " + _af_clip(m.get("note"), 80)) if m.get("note") else "", len(snaps), snap.SNAP_DIR))
        else:
            lines.append("- Snapshots: none yet")
    return lines


def _af_section_nat():
    wan = (_topo("wan_device") if "_topo" in globals() else "") or get_wan_interface()
    rules = [l.strip() for l in _af_run(["iptables", "-t", "nat", "-S", "POSTROUTING"]).splitlines()
             if "MASQUERADE" in l or "SNAT" in l]
    want = "-A POSTROUTING -o %s -j MASQUERADE" % wan
    mine = [r for r in rules if r == want]
    txt = "present" if mine else "MISSING (LAN IPv4 has no internet - see the tuxwall-connectivity skill)"
    if len(mine) > 1:
        txt += " (%d copies)" % len(mine)
    other = [r.replace("-A POSTROUTING ", "") for r in rules if r != want]
    return ["## NAT",
            "- LAN IPv4 masquerade `%s`: %s; owned by tuxwall-nat.service "
            "(/usr/local/sbin/tuxwall-nat-ensure)" % (want, txt),
            "- Other POSTROUTING NAT rules: %s" % ("; ".join("`%s`" % r for r in other[:6]) or "none")]


def _af_section_crowdsec():
    res = _crowdsec_active_decisions()
    if not res.get("ok"):
        return ["## CrowdSec", "- decisions: unavailable (%s)" % str(res.get("error", ""))[:80]]
    decs = res.get("decisions") or []
    origins = {}
    for d in decs:
        origins[d.get("origin") or "?"] = origins.get(d.get("origin") or "?", 0) + 1
    top = sorted(origins.items(), key=lambda kv: -kv[1])[:4]
    return ["## CrowdSec",
            "- Active decisions: %s (bans %s); by origin: %s (counts rounded)" % (
                _af_round(len(decs)), _af_round(len([d for d in decs if d.get("type") == "ban"])),
                ", ".join("%s %s" % (k, _af_round(v)) for k, v in top) or "none")]


def _af_section_dhcp():
    try:
        kea = _read_kea()
    except (OSError, ValueError):
        kea = {}
    subnets = (kea.get("Dhcp4") or {}).get("subnet4") or []
    counts = {}
    resp = kea_command("lease4-get-all")
    entry = resp[0] if isinstance(resp, list) and resp else resp
    now = time.time()
    for l in ((entry or {}).get("arguments") or {}).get("leases") or []:
        if int(l.get("state", 0)) == STATE_EXPIRED:
            continue
        if int(l.get("cltt") or 0) + int(l.get("valid-lft") or 0) <= now:
            continue
        counts[l.get("subnet-id")] = counts.get(l.get("subnet-id"), 0) + 1
    lines = ["## DHCP (Kea)"]
    for s in subnets:
        pools = ", ".join(p.get("pool", "") for p in s.get("pools") or [])
        lines.append("- %s on `%s`: %d active leases, %d reservations, pool %s" % (
            s.get("subnet"), s.get("interface", "?"), counts.get(s.get("id"), 0),
            len(s.get("reservations") or []), pools or "none"))
    return lines


def _af_section_wireguard():
    dump = _wg(["show", "wg0", "dump"])
    peers = parse_wg_dump(dump)["peers"]
    now = time.time()
    hs = [p["last_handshake"] for p in peers if p.get("last_handshake")]
    active = len([h for h in hs if now - h < 180])
    day = len([h for h in hs if now - h < 86400])
    latest = ("active now" if active else _af_ago(max(hs), now)) if hs else "never"
    return ["## WireGuard",
            "- wg0 up; %d peers; handshake <3 min: %d, <24 h: %d; latest handshake: %s" % (
                len(peers), active, day, latest)]


def _af_section_incidents():
    with _INCIDENT_LOCK:
        items = _load_incidents()
    now = time.time()
    active = [i for i in items if i.get("status") == "active"]
    recent = [i for i in items if i.get("status") != "active" and now - (i.get("last_seen") or 0) < 86400]
    lines = ["## Incidents (dashboard bell)",
             "- Active: %d; resolved in the last 24 h: %d" % (len(active), len(recent))]
    for i in (active + sorted(recent, key=lambda x: -(x.get("last_seen") or 0)))[:8]:
        lines.append("  - [%s, %s] %s (%s)" % (i.get("severity", "?"), i.get("status", "?"),
                                              _af_clip(i.get("title"), 110), _af_ago(i.get("last_seen"), now)))
    return lines


def build_agent_facts():
    """Markdown body (without the header) - every section fails on its own."""
    out = []
    for fn in (_af_section_system, _af_section_interfaces, _af_section_policy, _af_section_nat,
               _af_section_firewall, _af_section_services, _af_section_dhcp, _af_section_wireguard,
               _af_section_crowdsec, _af_section_incidents):
        try:
            part = fn()
        except Exception as exc:
            part = ["## %s" % fn.__name__.replace("_af_section_", "").capitalize(),
                    "- unavailable (%s)" % type(exc).__name__]
        if part:
            out.extend(part + [""])
    out.append("Detail: load a tuxwall-* skill (firewall-change, connectivity, interfaces, deception, "
               "dashboard-dev); verify with live commands before acting.")
    return "\n".join(out).rstrip() + "\n"


def write_agent_facts(force=False):
    body = build_agent_facts()
    try:
        with open(AGENT_FACTS_FILE) as f:
            old = f.read().split("\n", _AGENT_FACTS_HEADER_LINES)
        if not force and len(old) > _AGENT_FACTS_HEADER_LINES and old[-1] == body:
            return False
    except OSError:
        pass
    header = [
        "# TuxWall live facts (auto-generated)",
        "Generated by the TuxWall API (api_server.py); checked every 5 minutes, rewritten only when a value",
        "changes. Values as of %s. If a live command disagrees, the live command wins." % time.strftime("%Y-%m-%d %H:%M %Z"),
        "",
    ]
    d = os.path.dirname(AGENT_FACTS_FILE)
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o755)
    fd, tmp = tempfile.mkstemp(prefix=".facts.", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(header) + "\n" + body)
        os.chmod(tmp, 0o644)
        os.replace(tmp, AGENT_FACTS_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def _agent_facts_loop():
    time.sleep(AGENT_FACTS_START_DELAY)
    while True:
        try:
            write_agent_facts()
        except Exception as exc:
            print("[agent-facts] write failed: %r" % exc, flush=True)
        time.sleep(AGENT_FACTS_INTERVAL)


def start_agent_facts_writer():
    threading.Thread(target=_agent_facts_loop, name="agent-facts", daemon=True).start()


def _self_restart(signum, frame):
    """SIGUSR1 handler: re-exec the API process in-place to pick up code changes."""
    print("tuxwall API self-restarting...", flush=True)
    os.execv(sys.executable, [sys.executable] + sys.argv)


def _inherited_children():
    """PIDs that are already children of this process at startup. The
    SIGUSR1 re-exec keeps the PID, so commands the previous image still
    had in flight (latency ping, systemctl, cscli, ss, unbound-control...)
    stay our children, but nothing in this image will ever wait() on them
    and they linger as zombies until the service is fully restarted."""
    me = os.getpid()
    pids = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % name, "rb") as f:
                stat = f.read()
        except OSError:
            continue
        fields = stat[stat.rfind(b")") + 2:].split()
        if len(fields) > 1 and fields[1] == str(me).encode():
            pids.append(int(name))
    return pids


def _reap_inherited(pids):
    pending = set(pids)
    while pending:
        for pid in list(pending):
            try:
                done, _status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                done = pid
            if done:
                pending.discard(pid)
        if pending:
            time.sleep(2)


def _start_inherited_reaper():
    """Reap (only) the children inherited across the re-exec. Must run
    before this image spawns anything, so every PID found belongs to the
    previous image; waiting on specific PIDs never touches subprocess's own
    children, unlike SIGCHLD=SIG_IGN or waitpid(-1)."""
    try:
        pids = _inherited_children()
    except OSError as exc:
        print("[startup] inherited child scan failed: %r" % (exc,), flush=True)
        return
    if pids:
        print("[startup] reaping %d child process(es) left by the previous image" % len(pids), flush=True)
        threading.Thread(target=_reap_inherited, args=(pids,), name="exec-reaper", daemon=True).start()


NOFILE_SOFT_TARGET = 8192


def _raise_nofile_limit():
    """Soft RLIMIT_NOFILE up to NOFILE_SOFT_TARGET (never above the hard
    limit): the unit inherits 1024, which the tarpit's 256 slots plus the
    API's own sockets and pipes came too close to. Survives the SIGUSR1
    re-exec."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = NOFILE_SOFT_TARGET if hard == resource.RLIM_INFINITY else min(hard, NOFILE_SOFT_TARGET)
        if soft != resource.RLIM_INFINITY and soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    except Exception as exc:
        print("[startup] RLIMIT_NOFILE unchanged: %r" % (exc,), flush=True)


def main():
    _start_inherited_reaper()
    signal.signal(signal.SIGUSR1, _self_restart)
    _raise_nofile_limit()
    _ensure_service_reload()
    _ensure_unbound_local_actions()
    _restore_nat_on_boot()
    start_honeypot_at_boot()
    start_canary_fw_watchdog()    # canary WAN rules follow its live listeners (IPv4, 60 s)
    _report_worker_ensure()       # sends reports queued before a restart (persistent queue)
    threading.Thread(target=_deception_never_ban_ips, name="never-ban", daemon=True).start()
    get_security_monitor()
    get_system_monitor()
    get_latency_monitor()
    get_insights_history()
    start_incident_monitor()
    start_backup_scheduler()      # scheduled system backups (+ optional USB copy)
    get_community_auto_worker()   # community auto-ban sync (no-op until enabled)
    start_custom_blocklist_sync() # custom banlist file -> 1y bans, idempotent (90 s, then 6 h)
    start_crowdsec_fw_sync()      # nftables bouncer: re-time unextended bans, Range table (2 min, then 15 min)
    start_fw_hits_sampler()       # read-only per-rule hit counters (5 min)
    start_agent_facts_writer()    # /var/lib/tuxwall/agent/facts.md for the AI agent (5 min)
    _ensure_agent_api_token()     # /etc/tuxwall/agent/api.token for the agent's read-only MCP tool
    _plugin_pins_startup()        # plugin secrets 0600, pins (TOFU once for pre-3.3.3 installs)
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.daemon_threads = True
    print(f"tuxwall API listening on http://{LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
