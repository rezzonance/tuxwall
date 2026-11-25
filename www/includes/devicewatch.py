#!/usr/bin/env python3
"""TuxWall device monitoring engine (tuxwall-devicewatch.service, 3.3.7).

Agentless, read-only analysis of what the router already sees. Runs as the
unprivileged user tuxwall-devicewatch in a sandbox (no capabilities, no
network: IPAddressDeny=any) and writes its results to
/var/lib/tuxwall/devices/, which the dashboard API reads.

    devicewatch.py run                      the service loop (one cycle per minute)
    devicewatch.py once                     one cycle, then exit (debugging)
    devicewatch.py feeds-update [--force] [--only NAME]
                                            threat-intel download (tuxwall-devicewatch-feeds.service)
    devicewatch.py status                   print status.json

Inputs (all read-only)
  /opt/zeek/logs/current/{conn,dns,dhcp,software,known_hosts}.log  (group zeek)
      incremental: inode + offset + first-line hash per log, rotated files
      are finished from the dated archive dir (conn.HH:MM:SS-HH:MM:SS.log.gz)
      or the spool, partial last lines wait for the next cycle, at most
      LOG_BUDGET_BYTES per log per cycle, archives older than
      CATCHUP_MAX_AGE after a long downtime are skipped (counted as gaps).
  /var/log/suricata/eve.json      alerts (same follower; copytruncate-aware)
  journalctl -u unbound           log-local-actions / RPZ block lines (group
                                  systemd-journal), cursor checkpoint
  /var/lib/kea/kea-leases{4,6}.csv*   active leases (group _kea; the Kea
                                  control socket stays inaccessible)
  /etc/kea/kea-dhcp4.conf         reservation host names
  ip -j neigh / ip -j addr        ARP/NDP neighbours, LAN prefixes (netlink)
  /etc/tuxwall/interfaces.json    interface roles (lan / opt (VLAN) / vpn / wan)
  /var/lib/tuxwall/wg-peers.json  WireGuard peers (public keys, allowed IPs,
                                  names) - written by the API, which runs as
                                  root; private keys never leave the API
  /usr/share/ieee-data/oui.txt    vendor names
  /var/lib/tuxwall/dbip-city-lite.mmdb  countries (python3-maxminddb, optional)
  /var/lib/tuxwall/devices/feeds/*.json  parsed threat-intel feeds
  /etc/tuxwall/devices/{names,expected,local-indicators,devicewatch}.json
                                  admin overlays written by the API

Outputs (/var/lib/tuxwall/devices/, 0640, schema 1)
  devices.json   {"schema", "generated_at", "devices": [device, ...]}
  findings.json  {"schema", "generated_at", "findings": [finding, ...]}
  summary.json   counts for the Security card / Overview / Home Assistant
  status.json    sources, feeds, cycle timing, CPU and memory
  events.jsonl   new_device / finding events (for alerts; rotated at 1 MB)
  engine.json    private state (checkpoints, inventory, aggregates)

Device ids: "m" + 12 hex (MAC), "w" + 16 hex (sha256 of a WireGuard public
key), "i" + 16 hex (sha256 of an address with no known MAC).

Severity (finding kinds)
  c2_connection      completed outbound connection to a C2 address      critical
  intel_connection   completed outbound connection to a malware host     high
  dns_lookup         answered DNS lookup of a malware domain              high
  intel_attempt      outbound attempt to a listed address, no answer     medium
  ids_alert          Suricata alert (malware/exploit classes only) on a
                     flow the device started: severity 1 high, 2 medium,
                     3 low. Attacks the device only received (it is the
                     server) are low - unless the device itself sent the
                     alerting packet of an attack-response / "Successful
                     ... Privilege Gain" signature (then as above)
  intel_inbound      a listed address connected to the device            low
  dns_blocked        lookup blocked by DNS (RPZ / blocklist) or failed    low
  A Feodo entry offline for more than 30 days counts as "old": at most
  medium (its address may have been reassigned). Local indicators carry
  their own severity (cap for the kind above).

Risk score 0-100 = min(100, sum over active findings of
  weight(severity) x recency(last seen)),
  weights critical 60, high 35, medium 15, low 4; recency 1.0 (< 24 h),
  0.5 (< 7 days), 0.2 (older, until the 30-day retention drops it).
  Findings marked "expected" do not count.
Health: critical = an active critical finding seen in the last 7 days or
  risk >= 80; warning = an active high/medium finding in the last 7 days or
  risk >= 30; new = first seen in the last 24 h (not for devices present
  when monitoring started); otherwise normal. Low findings alone only raise
  the score.

Type guess: first match of TYPE_RULES (host name, then vendor, then the
browser user agent from Zeek software.log); WireGuard peers are
"vpn-client". A locally administered MAC is shown as "Private MAC".

Phase 2 hook: Detector subclasses get on_conn / on_dns / on_alert /
on_cycle calls with normalised events and return finding specs; the
threat-intel and Suricata matching are themselves detectors.
"""
import csv
import glob
import gzip
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import zlib
from collections import OrderedDict
from datetime import datetime

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import devicewatch_feeds as feeds  # noqa: E402

try:
    import kea_conf as _kea_conf
except Exception:  # the engine works without reservation names
    _kea_conf = None

SCHEMA = 1
ENGINE_VERSION = "1.0"

CYCLE_SECONDS = 60
STATE_SAVE_SECONDS = 300
TOPOLOGY_SECONDS = 600
LOG_BUDGET_BYTES = 32 << 20
READ_CHUNK = 1 << 20
MAX_LINE = 1 << 20
INITIAL_BACKLOG = {"zeek": 64 << 20, "eve": 4 << 20}
CATCHUP_MAX_AGE = 3 * 3600
CATCHUP_MAX_BYTES = 512 << 20
JOURNAL_MAX_LINES = 200000
RETENTION_DAYS = 30
HOURS_KEPT = 24
DESTS_PER_HOUR = 64
TOP_N = 10
NEW_DEVICE_SECONDS = 86400
ONLINE_SECONDS = 600
WG_ONLINE_SECONDS = 180
IP_HISTORY_SECONDS = 7 * 86400
IP_HISTORY_MAX = 20000
IP_HISTORY_PER_IP = 4
MAX_FINDINGS = 10000
MAX_DEVICES = 2000
EVENTS_MAX_BYTES = 1 << 20
RDNS_MAX = 50000
DEDUPE_MAX = 50000
CLASSIFY_CACHE_MAX = 200000
DNS_HOT_SECONDS = 3600

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_NAMES = {v: k for k, v in SEV_RANK.items()}
RISK_WEIGHTS = {"critical": 60, "high": 35, "medium": 15, "low": 4, "info": 0}
RISK_RECENCY = ((86400, 1.0), (7 * 86400, 0.5))
RISK_RECENCY_OLD = 0.2
HEALTH_WINDOW = 7 * 86400
HEALTH_CRITICAL_SCORE = 80
HEALTH_WARNING_SCORE = 30

KIND_TEXT = {
    "c2_connection": "Connected to a known botnet C2 server",
    "intel_connection": "Connected to a known malware host",
    "dns_lookup": "Looked up a known malware domain",
    "intel_attempt": "Tried to reach a known malicious address (no answer)",
    "intel_inbound": "Contacted by a known malicious address",
    "dns_blocked": "Lookup of a known malware domain was blocked",
    "ids_alert": "Intrusion detection alert",
}
KIND_DEFAULT_SEV = {"c2_connection": "critical", "intel_connection": "high", "dns_lookup": "high",
                    "intel_attempt": "medium", "intel_inbound": "low", "dns_blocked": "low"}
SOURCE_TITLES = {"feodo": "Feodo Tracker", "urlhaus": "URLhaus", "threatfox": "ThreatFox",
                 "local": "local indicator list", "suricata": "Suricata"}

# Suricata: only alerts that point at malware/exploitation of the device.
# Decoder/stream events, INFO/POLICY/HUNTING/SCAN rules and IP-reputation
# lists (mostly inbound internet noise) never become device findings.
SURICATA_IGNORE_PREFIXES = (
    "SURICATA ", "ET INFO", "ET POLICY", "ET SCAN", "ET HUNTING", "ET DNS ", "ET GAMES", "ET CHAT",
    "ET P2P", "ET USER_AGENTS", "GPL ICMP", "ET DROP", "ET CINS", "ET DSHIELD", "ET COMPROMISED",
    "ET TOR", "ET 3CORESEC", "GPL SCAN", "GPL POLICY", "ET VOIP",
)
SURICATA_ALLOW_PREFIXES = (
    "ET MALWARE", "ET TROJAN", "ET CNC", "ET MOBILE_MALWARE", "ET CURRENT_EVENTS", "ET EXPLOIT_KIT",
    "ET EXPLOIT", "ET ATTACK_RESPONSE", "ET WORM", "ET COINMINING", "ET COINMINER", "ET PHISHING",
    "ET WEB_CLIENT", "GPL ATTACK_RESPONSE", "GPL TROJAN", "GPL EXPLOIT", "THREATFOX", "URLHAUS",
    "FEODO", "ABUSE.CH", "SSLBL",
)
SURICATA_ALLOW_CATEGORIES = frozenset((
    "A Network Trojan was Detected", "Malware Command and Control Activity Detected",
    "Domain Observed Used for C2 Detected", "Exploit Kit Activity Detected",
    "Successful Administrator Privilege Gain", "Successful User Privilege Gain",
    "Crypto Currency Mining Activity Detected", "Targeted Malicious Activity was Detected",
    "Executable code was detected",
))

# (field, regex, type) - first match wins; field: name | vendor | ua
TYPE_RULES = tuple((f, re.compile(rx, re.I), t) for f, rx, t in (
    ("name", r"iphone|android|galaxy|pixel-?\d|oneplus|redmi|xiaomi|moto-?g|phone", "phone"),
    ("name", r"ipad|tablet|kindle|fire-?hd|galaxy-?tab", "tablet"),
    ("name", r"apple-?tv|roku|chromecast|fire-?tv|firestick|shield-?tv|bravia|webos|lgwebos|"
             r"samsung-?tv|tizen|android-?tv|google-?tv|(^|[-_])tv([-_]|$)", "tv"),
    ("name", r"macbook|imac|mac-?mini|mac-?pro|laptop|desktop|(^|-)pc(-|$)|thinkpad|surface|"
             r"chromebook|workstation|ubuntu|debian|fedora|windows|^win-", "computer"),
    ("name", r"echo-?(dot|show)?|alexa|google-?home|nest-?(mini|audio|hub)|homepod|sonos|speaker", "speaker"),
    ("name", r"camera|(^|[-_])cam([-_]|\d|$)|doorbell|wyze|eufy|arlo|reolink|hikvision|dahua|ring-", "camera"),
    ("name", r"printer|epson|brother|canon|officejet|deskjet|laserjet|^npi[0-9a-f]", "printer"),
    ("name", r"xbox|playstation|^ps[45]|nintendo|steam-?deck", "console"),
    ("name", r"esp[-_]?[0-9a-f]{4,}|esp32|esp8266|tasmota|shelly|sonoff|tuya|wled|(^|-)hue|smartthings|"
             r"zigbee|(^|-)iot|smart-?plug|bulb|thermostat|ecobee|myq", "iot"),
    ("name", r"(^|-)nas(-|\d|$)|synology|diskstation|qnap|truenas|unraid", "nas"),
    ("name", r"unifi|^u6-|^uap|^usw|access-?point|^ap-|(^|-)deco(-|$)|orbi|eero|^switch-", "network"),
    ("name", r"raspberry|^pi\d?$|^rpi", "computer"),
    ("vendor", r"espressif|tuya|shelly|allterco|itead|signify|philips lighting|lifx|ecobee|chamberlain|"
               r"wyze|meross|govee|sonoff|nest labs", "iot"),
    ("vendor", r"roku|vizio|hisense|tcl king|lg electronics.*tv", "tv"),
    ("vendor", r"sonos|bose", "speaker"),
    ("vendor", r"synology|qnap", "nas"),
    ("vendor", r"ubiquiti|ruckus|aruba|meraki|mikrotik|netgear|eero|zyxel", "network"),
    ("vendor", r"nintendo|sony interactive", "console"),
    ("vendor", r"hewlett packard|hp inc|brother industries|seiko epson|canon inc|lexmark|xerox|kyocera", "printer"),
    ("vendor", r"raspberry pi", "computer"),
    ("vendor", r"intel corporate|dell inc|lenovo|asustek|micro-star|gigabyte|framework computer", "computer"),
    ("ua", r"iphone|android.*mobile", "phone"),
    ("ua", r"ipad|android(?!.*mobile)", "tablet"),
    ("ua", r"smart-?tv|tizen|web0s|bravia|\baft[a-z]\b|roku|crkey", "tv"),
    ("ua", r"windows nt|macintosh|x11; (linux|ubuntu|fedora)|cros", "computer"),
))

EXT, LAN, OWN, SKIP = 0, 1, 2, 3
SINKHOLES = frozenset(("0.0.0.0", "::", "127.0.0.1", "::1"))
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
BLOCK_ACTIONS = ("always_nxdomain", "always_refuse", "always_null", "refuse", "deny", "inform_deny",
                 "always_deny", "redirect")
UNBOUND_LOCAL_RE = re.compile(r"info:\s+\S+\s+(%s)\s+([0-9A-Fa-f:.]+)@\d+\s+(\S+)\s+\S+\s+IN"
                              % "|".join(BLOCK_ACTIONS))
UNBOUND_RPZ_RE = re.compile(r"rpz:\s+applied\s+\[[^\]]*\]\s+\S+\s+rpz-[a-z-]+\s+([0-9A-Fa-f:.]+)@\d+\s+(\S+)")


# ── small helpers ────────────────────────────────────────────────────────────

class Config:
    """Every path the engine touches; root= remaps them for tests
    (also TUXWALL_DEVICEWATCH_ROOT)."""

    def __init__(self, root=None):
        r = (os.environ.get("TUXWALL_DEVICEWATCH_ROOT", "") if root is None else root).rstrip("/")

        def p(x):
            return r + x if r else x
        self.root = r
        self.state_dir = p("/var/lib/tuxwall/devices")
        self.feeds_dir = os.path.join(self.state_dir, "feeds")
        self.conf_dir = p("/etc/tuxwall/devices")
        self.zeek_logs = p("/opt/zeek/logs")
        self.zeek_current = p("/opt/zeek/logs/current")
        self.eve = p("/var/log/suricata/eve.json")
        self.kea4 = [p("/var/lib/kea/kea-leases4.csv.2"), p("/var/lib/kea/kea-leases4.csv.1"),
                     p("/var/lib/kea/kea-leases4.csv")]
        self.kea6 = [p("/var/lib/kea/kea-leases6.csv.2"), p("/var/lib/kea/kea-leases6.csv.1"),
                     p("/var/lib/kea/kea-leases6.csv")]
        self.kea_conf = p("/etc/kea/kea-dhcp4.conf")
        self.interfaces = p("/etc/tuxwall/interfaces.json")
        self.oui = p("/usr/share/ieee-data/oui.txt")
        self.wg_snapshot = p("/var/lib/tuxwall/wg-peers.json")
        self.geo_db = p("/var/lib/tuxwall/dbip-city-lite.mmdb")

    def conf(self, name):
        return os.path.join(self.conf_dir, name)

    def state(self, name):
        return os.path.join(self.state_dir, name)


def atomic_write_json(path, obj, mode=0o640, indent=None):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, separators=(",", ":") if indent is None else None, indent=indent)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def data_ts(path):
    try:
        return int(os.stat(path).st_mtime)
    except OSError:
        return None


def read_json(path, default=None, max_bytes=64 << 20):
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes + 1)
        if len(data) > max_bytes:
            return default
        return json.loads(data.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return default


def norm_mac(value):
    m = str(value or "").strip().lower().replace("-", ":")
    if len(m) == 12 and ":" not in m:
        m = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    if not MAC_RE.match(m):
        return None
    first = int(m[:2], 16)
    if first & 1 or m in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None                     # multicast / broadcast / empty
    return m


def is_private_mac(mac):
    """Locally administered (randomised 'private Wi-Fi address')."""
    return bool(int(mac[:2], 16) & 2)


def mac_id(mac):
    return "m" + mac.replace(":", "")


def hash_id(prefix, value):
    return prefix + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def wg_id(pubkey):
    return hash_id("w", pubkey)


def ip_id(ip):
    return hash_id("i", ip)


DEVICE_ID_RE = re.compile(r"^(m[0-9a-f]{12}|[wi][0-9a-f]{16})$")


def mac_from_eui64(ip):
    """MAC embedded in a SLAAC EUI-64 interface id (…ff:fe…), else None."""
    try:
        a = ipaddress.IPv6Address(ip)
    except ValueError:
        return None
    iid = a.packed[8:]
    if iid[3:5] != b"\xff\xfe":
        return None
    b = bytes([iid[0] ^ 2]) + iid[1:3] + iid[5:8]
    return norm_mac(":".join("%02x" % x for x in b))


def parse_eve_ts(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except (TypeError, ValueError):
        try:
            return datetime.fromisoformat(str(value)).timestamp()
        except ValueError:
            return None


def worse(a, b):
    return a if SEV_RANK.get(a, 0) >= SEV_RANK.get(b, 0) else b


def lower_sev(sev):
    return SEV_NAMES[max(1, SEV_RANK.get(sev, 1) - 1)]


def cap_sev(sev, cap):
    return sev if SEV_RANK.get(sev, 0) <= SEV_RANK.get(cap, 0) else cap


class Distinct:
    """Distinct-count estimate (linear counting, 8192 bits = 1 KB): 'how many
    destinations today' without keeping the destinations."""
    BITS = 8192

    def __init__(self, hexstr=None):
        try:
            b = bytearray.fromhex(hexstr) if hexstr else None
        except ValueError:
            b = None
        self.b = b if b is not None and len(b) == self.BITS // 8 else bytearray(self.BITS // 8)

    def add(self, s):
        h = zlib.crc32(s.encode("utf-8")) % self.BITS
        self.b[h >> 3] |= 1 << (h & 7)

    def count(self):
        ones = int.from_bytes(self.b, "big").bit_count()
        zeros = self.BITS - ones
        if zeros == 0:
            return self.BITS * 8
        return int(round(-self.BITS * math.log(zeros / self.BITS)))

    def hex(self):
        return self.b.hex()


# ── vendor (IEEE OUI) and countries ─────────────────────────────────────────

class Oui:
    LINE_RE = re.compile(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$")

    def __init__(self, path):
        self.path = path
        self.db = None

    def _load(self):
        db = {}
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = self.LINE_RE.match(line)
                    if m:
                        db[(m.group(1) + m.group(2) + m.group(3)).lower()] = m.group(4)[:64]
        except OSError:
            pass
        self.db = db

    def vendor(self, mac):
        if not mac:
            return ""
        if is_private_mac(mac):
            return "Private MAC"
        if self.db is None:
            self._load()
        return self.db.get(mac.replace(":", "")[:6], "")


class Geo:
    def __init__(self, path):
        self.path = path
        self.reader = None
        self.checked = False
        self.cache = {}
        self.available = False

    def iso(self, ip):
        c = self.cache.get(ip)
        if c is not None:
            return c
        if not self.checked:
            self.checked = True
            try:
                import maxminddb
                self.reader = maxminddb.open_database(self.path, maxminddb.MODE_MMAP)
                self.available = True
            except Exception:
                self.reader = None
        iso = ""
        if self.reader is not None:
            try:
                rec = self.reader.get(ip)
                if isinstance(rec, dict):
                    iso = ((rec.get("country") or {}).get("iso_code") or "").upper()
            except Exception:
                iso = ""
        if len(self.cache) > 50000:
            self.cache.clear()
        self.cache[ip] = iso
        return iso


# ── incremental log follower ─────────────────────────────────────────────────

def _open_any(path):
    return gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb")


def _head_of(path, n):
    try:
        with _open_any(path) as f:
            data = f.read(n)
    except (OSError, EOFError, zlib.error):
        return None
    return hashlib.sha1(data).hexdigest() if len(data) == n else None


class Follower:
    """Reads complete new lines of an append-only log across restarts and
    rotation. Checkpoint: inode, device, offset, length + sha1 of the first
    line (<= 256 bytes) - the identity used to find the rotated copy."""

    def __init__(self, name, path, archives=None, initial_backlog=64 << 20, clock=time.time,
                 catchup_max_age=CATCHUP_MAX_AGE):
        self.name = name
        self.path = path
        self.archives = archives          # callable -> [(path, mtime)] oldest first
        self.initial_backlog = initial_backlog
        self.clock = clock
        self.catchup_max_age = catchup_max_age
        self.cp = {}
        self.stats = {"lines": 0, "bytes": 0, "oversized": 0, "rotations": 0, "gaps": 0,
                      "archives_read": 0, "lag_bytes": 0, "error": None, "last_line_at": None}

    def restore(self, cp):
        if isinstance(cp, dict) and isinstance(cp.get("ino"), int) and isinstance(cp.get("off"), int):
            self.cp = {k: cp.get(k) for k in ("ino", "dev", "off", "hl", "head", "skip")}

    @staticmethod
    def _head(f):
        f.seek(0)
        data = f.read(256)
        nl = data.find(b"\n")
        if nl < 0:
            if len(data) < 256:
                return 0, ""
            hl = 256
        else:
            hl = nl + 1
        return hl, hashlib.sha1(data[:hl]).hexdigest()

    def _new_cp(self, st, off=0):
        return {"ino": st.st_ino, "dev": st.st_dev, "off": off, "hl": 0, "head": "", "skip": False}

    def poll(self, handler, budget=LOG_BUDGET_BYTES):
        """Feed new complete lines (bytes, without newline) to handler.
        Returns the number of bytes consumed from the live file."""
        try:
            st = os.stat(self.path)
        except OSError:
            self.stats["error"] = "missing"
            return 0
        self.stats["error"] = None
        cp = self.cp
        try:
            if not cp.get("ino"):
                start = max(0, st.st_size - self.initial_backlog)
                self.cp = cp = self._new_cp(st, start)
                cp["skip"] = start > 0
            elif (st.st_ino, st.st_dev) != (cp["ino"], cp.get("dev")):
                self._finish_rotated(handler)
                self.cp = cp = self._new_cp(st)
            else:
                rotated = st.st_size < cp["off"]
                if not rotated and cp.get("hl"):
                    with open(self.path, "rb") as f:
                        f.seek(0)
                        data = f.read(cp["hl"])
                    rotated = len(data) < cp["hl"] or hashlib.sha1(data).hexdigest() != cp["head"]
                if rotated:                  # truncated / rewritten in place (copytruncate)
                    self._finish_rotated(handler)
                    self.cp = cp = self._new_cp(st)
            return self._read(st, handler, budget)
        except OSError as exc:
            self.stats["error"] = exc.__class__.__name__
            return 0

    def _read(self, st, handler, budget):
        cp = self.cp
        consumed = 0
        with open(self.path, "rb") as f:
            if not cp.get("hl"):
                cp["hl"], cp["head"] = self._head(f)
            off = cp["off"]
            f.seek(off)
            while consumed < budget:
                data = f.read(READ_CHUNK)
                if not data:
                    break
                if cp.get("skip"):          # resume inside a line: drop up to the next newline
                    nl = data.find(b"\n")
                    if nl < 0:
                        off += len(data)
                        consumed += len(data)
                        continue
                    data = data[nl + 1:]
                    off += nl + 1
                    consumed += nl + 1
                    cp["skip"] = False
                    if not data:
                        continue
                last = data.rfind(b"\n")
                if last < 0:
                    if len(data) >= MAX_LINE:   # one oversized line: skip it
                        self.stats["oversized"] += 1
                        off += len(data)
                        consumed += len(data)
                        cp["skip"] = True
                        f.seek(off)
                        continue
                    break                       # a partial last line: wait for the rest
                chunk = data[:last + 1]
                self._emit(chunk, handler)
                off += last + 1
                consumed += last + 1
                f.seek(off)
            cp["off"] = off
        self.stats["lag_bytes"] = max(0, st.st_size - cp["off"])
        self.stats["bytes"] += consumed
        return consumed

    def _emit(self, chunk, handler):
        n = 0
        for line in chunk.split(b"\n"):
            if not line:
                continue
            if len(line) > MAX_LINE:
                self.stats["oversized"] += 1
                continue
            n += 1
            handler(line)
        self.stats["lines"] += n
        if n:
            self.stats["last_line_at"] = self.clock()

    def _finish_rotated(self, handler):
        """Read the rest of the file we were following from its rotated copy
        (matched by first-line hash), then every later archive that is not
        older than the catch-up window."""
        cp = self.cp
        self.stats["rotations"] += 1
        if not self.archives or not cp.get("hl"):
            self.stats["gaps"] += 1 if cp.get("off") else 0
            return
        try:
            cands = self.archives() or []
        except OSError:
            cands = []
        same = [i for i in range(len(cands)) if _head_of(cands[i][0], cp["hl"]) == cp["head"]]
        if not same:
            self.stats["gaps"] += 1
            return
        # the spool copy is complete; a .gz of the same file may still be being written
        plain = [i for i in same if not cands[i][0].endswith(".gz")]
        idx = plain[-1] if plain else same[-1]
        now = self.clock()
        total = 0
        for j, (path, mtime) in enumerate(cands[idx:]):
            if j and idx + j in same:
                continue                     # another copy of the file just finished
            if j and mtime < now - self.catchup_max_age:
                self.stats["gaps"] += 1
                continue
            if total > CATCHUP_MAX_BYTES:
                self.stats["gaps"] += 1
                continue
            total += self._read_archive(path, cp["off"] if j == 0 else 0, handler)

    def _read_archive(self, path, start, handler):
        n = 0
        try:
            with _open_any(path) as f:
                skip = start
                while skip > 0:
                    got = f.read(min(skip, READ_CHUNK))
                    if not got:
                        return 0
                    skip -= len(got)
                tail = b""
                while True:
                    data = f.read(READ_CHUNK)
                    if not data:
                        break
                    n += len(data)
                    data = tail + data
                    last = data.rfind(b"\n")
                    if last < 0:
                        tail = data if len(data) < MAX_LINE else b""
                        continue
                    self._emit(data[:last + 1], handler)
                    tail = data[last + 1:]
                if tail.strip():
                    self._emit(tail, handler)
            self.stats["archives_read"] += 1
        except (OSError, EOFError, zlib.error):
            self.stats["gaps"] += 1
        return n


def zeek_archives(cfg, name, days=2):
    """Rotated copies of a Zeek log, oldest first: spool leftovers
    (conn.YYYY-MM-DD-HH-MM-SS.log) and the dated archive
    (logs/YYYY-MM-DD/conn.HH:MM:SS-HH:MM:SS.log.gz)."""
    def lister():
        out = []
        cur = os.path.realpath(cfg.zeek_current)
        for p in glob.glob(os.path.join(cur, name + ".*.log")):
            out.append(p)
        dirs = sorted(d for d in glob.glob(os.path.join(cfg.zeek_logs, "[12][0-9][0-9][0-9]-*"))
                      if os.path.isdir(d))[-days:]
        for d in dirs:
            out.extend(glob.glob(os.path.join(d, name + ".*.log.gz")))
            out.extend(glob.glob(os.path.join(d, name + ".*.log")))
        res = []
        for p in out:
            try:
                res.append((p, os.stat(p).st_mtime))
            except OSError:
                pass
        res.sort(key=lambda x: (x[1], x[0]))
        return res
    return lister


def eve_archives(path):
    def lister():
        res = []
        for p in glob.glob(path + ".[0-9]") + glob.glob(path + ".[0-9].gz"):
            try:
                res.append((p, os.stat(p).st_mtime))
            except OSError:
                pass
        res.sort(key=lambda x: (x[1], x[0]))
        return res
    return lister


# ── inventory sources ────────────────────────────────────────────────────────

def read_kea_leases(paths, now, v6=False):
    """Active leases from Kea memfile CSVs (files read in Kea's own order,
    later rows replace earlier ones for the same address)."""
    leases = {}
    for p in paths:
        try:
            f = open(p, newline="", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with f:
            rd = csv.reader(f)
            header = next(rd, None)
            if not header:
                continue
            idx = {h.strip(): i for i, h in enumerate(header)}
            if "address" not in idx or "expire" not in idx:
                continue

            def col(row, name):
                i = idx.get(name)
                return row[i] if i is not None and i < len(row) else ""
            for row in rd:
                addr = col(row, "address")
                try:
                    expire = int(col(row, "expire") or 0)
                    valid = int(col(row, "valid_lifetime") or 0)
                    state = int(col(row, "state") or 0)
                except ValueError:
                    continue
                leases[addr] = {"ip": addr, "mac": norm_mac(col(row, "hwaddr")),
                                "hostname": col(row, "hostname").replace("&#x2c", ",").rstrip(".")[:64],
                                "expire": expire, "cltt": expire - valid if valid < 0xffffffff else expire,
                                "state": state}
    out = []
    for le in leases.values():
        if le["state"] != 0 or le["expire"] <= now or not le["mac"]:
            continue
        if not feeds.norm_ip(le["ip"]):
            continue
        out.append(le)
    return out


def read_kea_reservations(path):
    if _kea_conf is None:
        return []
    try:
        data = _kea_conf.read(path)
    except Exception:
        return []
    d4 = data.get("Dhcp4") if isinstance(data, dict) else None
    if not isinstance(d4, dict):
        return []
    subnets = list(d4.get("subnet4") or [])
    for sn in d4.get("shared-networks") or []:
        if isinstance(sn, dict):
            subnets.extend(sn.get("subnet4") or [])
    res = list(d4.get("reservations") or [])
    for s in subnets:
        if isinstance(s, dict):
            res.extend(s.get("reservations") or [])
    out = []
    for r in res:
        if not isinstance(r, dict):
            continue
        mac = norm_mac(r.get("hw-address"))
        if mac:
            out.append({"mac": mac, "ip": r.get("ip-address") or "", "hostname": str(r.get("hostname") or "")[:64]})
    return out


def run_json_cmd(args, timeout=10):
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    try:
        return json.loads(p.stdout.decode("utf-8", "replace") or "null")
    except ValueError:
        return None


class Sources:
    """System inputs that need a command; tests replace these callables."""

    @staticmethod
    def neighbours():
        return run_json_cmd(["ip", "-j", "neigh", "show"])

    @staticmethod
    def addresses():
        return run_json_cmd(["ip", "-j", "addr", "show"])

    @staticmethod
    def default_route_devs():
        out = set()
        for fam in ("-4", "-6"):
            for r in run_json_cmd(["ip", "-j", fam, "route", "show", "default"]) or []:
                if isinstance(r, dict) and r.get("dev"):
                    out.add(r["dev"])
        return out

    @staticmethod
    def journal(cursor, since="-10min", max_lines=JOURNAL_MAX_LINES):
        """(lines [(ts, message)], new cursor, error or None) of unbound's journal."""
        args = ["journalctl", "-u", "unbound.service", "-o", "json", "--output-fields=MESSAGE",
                "--no-pager", "-q"]
        args += ["--after-cursor=" + cursor] if cursor else ["--since=" + since]
        try:
            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            return [], cursor, "journalctl unavailable (%s)" % exc.__class__.__name__
        out, last = [], cursor
        try:
            for raw in p.stdout:
                try:
                    j = json.loads(raw)
                except ValueError:
                    continue
                msg = j.get("MESSAGE")
                if isinstance(msg, list):
                    msg = bytes(x & 0xff for x in msg if isinstance(x, int)).decode("utf-8", "replace")
                try:
                    ts = int(j.get("__REALTIME_TIMESTAMP") or 0) / 1e6
                except ValueError:
                    ts = 0
                last = j.get("__CURSOR") or last
                if isinstance(msg, str):
                    out.append((ts, msg))
                if len(out) >= max_lines:
                    break
        finally:
            try:
                p.stdout.close()
            except OSError:
                pass
            if p.poll() is None:
                p.terminate()
            try:
                err = p.communicate(timeout=10)[1] or b""
            except (subprocess.SubprocessError, ValueError):
                err = b""
                p.kill()
        err = err.decode("utf-8", "replace")
        if cursor and p.returncode not in (0, None, -15) and not out:
            return [], None, "journal cursor rejected; restarting from the last 10 minutes"
        if "not seeing messages" in err or "No journal files were opened due to insufficient permissions" in err:
            return out, last, "no permission to read the system journal (systemd-journal group)"
        return out, last, None


# ── detectors (the Phase 2 plug-in point) ────────────────────────────────────

class ConnEvent:
    __slots__ = ("ts", "device", "dev_ip", "peer", "peer_port", "proto", "outbound", "state", "history",
                 "bytes_in", "bytes_out", "service", "established", "duration")


class DnsEvent:
    __slots__ = ("ts", "device", "dev_ip", "query", "qtype", "rcode", "answers", "answered", "blocked", "source")


class AlertEvent:
    __slots__ = ("ts", "device", "dev_ip", "peer", "outbound", "device_sent", "sid", "rev", "signature",
                 "category", "severity", "proto", "dest_port", "action")


class Detector:
    """Called by the engine for every attributed event. on_conn / on_dns /
    on_alert return an iterable of finding specs: {"kind", "indicator",
    "indicator_type", "severity", "title", "source", "details"} (the event's
    device gets them); on_cycle returns (spec, device id, ts) tuples. Phase 2
    detectors (beaconing, volume, scanning, DGA, ...) subclass this, keep
    their own bounded state and are added to Engine(detectors=...)."""
    name = "detector"

    def on_conn(self, eng, ev):
        return ()

    def on_dns(self, eng, ev):
        return ()

    def on_alert(self, eng, ev):
        return ()

    def on_cycle(self, eng, now):
        return ()


class IntelDetector(Detector):
    """Threat-intel matching: responder addresses of LAN devices' flows and
    DNS queries/answers against the feeds and the local indicator list."""
    name = "intel"

    def on_conn(self, eng, ev):
        hits = eng.intel.match_ip(ev.peer)
        hot = eng.dns_hot_lookup(ev.device, ev.peer, ev.ts) if not hits else None
        if not hits and not hot:
            return ()
        out = []
        if hits:
            for feed, meta in hits:
                out.append(self._conn_spec(ev, feed, meta, ev.peer, "ip"))
        else:
            feed, meta, domain = hot
            spec = self._conn_spec(ev, feed, meta, domain, "domain")
            spec["details"]["via_dns"] = True
            out.append(spec)
        return out

    @staticmethod
    def _conn_spec(ev, feed, meta, indicator, itype):
        c2 = meta.get("t") == "botnet_cc"
        old = meta.get("st") == "old"
        if not ev.outbound:
            kind = "intel_inbound"
        elif not ev.established:
            kind = "intel_attempt"
        else:
            kind = "c2_connection" if c2 else "intel_connection"
        sev = KIND_DEFAULT_SEV[kind]
        if meta.get("sev"):           # local indicator: its own level for a completed connection
            sev = meta["sev"] if kind in ("c2_connection", "intel_connection") else cap_sev(meta["sev"], sev)
        if old:
            sev = cap_sev(sev, "medium")
        details = {"peer": ev.peer, "port": ev.peer_port, "proto": ev.proto, "state": ev.state,
                   "direction": "outbound" if ev.outbound else "inbound"}
        if meta.get("m"):
            details["malware"] = meta["m"]
        if meta.get("t"):
            details["threat"] = meta["t"]
        if old:
            details["listed_status"] = "offline for 30+ days"
        if meta.get("note"):
            details["note"] = meta["note"]
        return {"kind": kind, "indicator": indicator, "indicator_type": itype, "severity": sev,
                "title": "%s (%s)" % (KIND_TEXT[kind], SOURCE_TITLES.get(feed, feed)), "source": feed,
                "details": details}

    def on_dns(self, eng, ev):
        hits = eng.intel.match_domain(ev.query)
        if not hits:
            return ()
        out = []
        for feed, meta, matched in hits:
            if ev.answered:
                kind = "dns_lookup"
                eng.dns_hot_add(ev.device, ev.answers, feed, meta, matched, ev.ts)
            else:
                # Zeek and the unbound journal both see a blocked lookup: count it once
                if eng._dup(("q", ev.dev_ip, ev.query), ev.ts, 3.0):
                    continue
                kind = "dns_blocked"
            sev = KIND_DEFAULT_SEV[kind]
            if meta.get("sev"):
                sev = cap_sev(meta["sev"], sev)
            details = {"qtype": ev.qtype, "rcode": ev.rcode, "via": ev.source}
            if meta.get("m"):
                details["malware"] = meta["m"]
            if meta.get("t"):
                details["threat"] = meta["t"]
            if meta.get("note"):
                details["note"] = meta["note"]
            if matched != ev.query:
                details["query"] = ev.query
            out.append({"kind": kind, "indicator": matched, "indicator_type": "domain", "severity": sev,
                        "title": "%s (%s)" % (KIND_TEXT[kind], SOURCE_TITLES.get(feed, feed)), "source": feed,
                        "details": details})
        return out


class SuricataDetector(Detector):
    name = "suricata"

    def on_alert(self, eng, ev):
        sev = {1: "high", 2: "medium"}.get(ev.severity, "low")
        compromise = ev.device_sent and (ev.signature.upper().startswith(("ET ATTACK_RESPONSE", "GPL ATTACK_RESPONSE"))
                                         or ev.category.startswith("Successful"))
        if not ev.outbound and not compromise:
            sev = "low"                 # an attack the device received (internet scanners on exposed services)
        return ({"kind": "ids_alert", "indicator": "sid:%s" % ev.sid, "indicator_type": "signature",
                 "severity": sev, "title": ev.signature[:160], "source": "suricata",
                 "details": {"category": ev.category[:80], "sid": ev.sid, "rev": ev.rev, "peer": ev.peer,
                             "port": ev.dest_port, "proto": ev.proto,
                             "direction": "outbound" if ev.outbound else "inbound",
                             "action": ev.action}},)


def suricata_relevant(signature, category):
    s = (signature or "").upper()
    if s.startswith(SURICATA_IGNORE_PREFIXES):
        return False
    return s.startswith(SURICATA_ALLOW_PREFIXES) or (category or "") in SURICATA_ALLOW_CATEGORIES


# ── indicators ───────────────────────────────────────────────────────────────

class Intel:
    """Feed files + local indicators, reloaded when they change."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.feeds = {}          # name -> {"ip": {}, "domain": {}, "mtime"}
        self.local_ip = {}
        self.local_domain = {}
        self.local_wild = {}
        self.local_nets = []
        self.local_mtime = None
        self.enabled = None

    def reload(self, config=None):
        changed = False
        on = set(feeds.enabled_feeds(config))
        if on != self.enabled:
            self.enabled = on
            changed = True
        for name in feeds.FEEDS:
            path = os.path.join(self.cfg.feeds_dir, name + ".json")
            try:
                mtime = os.stat(path).st_mtime if name in on else None
            except OSError:
                mtime = None
            cur = self.feeds.get(name)
            if mtime is None:
                if cur:
                    self.feeds.pop(name, None)
                    changed = True
                continue
            if cur and cur["mtime"] == mtime:
                continue
            data = read_json(path, None, 256 << 20)
            if isinstance(data, dict) and isinstance(data.get("ip"), dict) and isinstance(data.get("domain"), dict):
                ips, doms = feeds.expand(data)
                data = None
                self.feeds[name] = {"ip": ips, "domain": doms, "mtime": mtime, "fetched_at": data_ts(path)}
                changed = True
        path = self.cfg.conf("local-indicators.json")
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            mtime = None
        if mtime != self.local_mtime:
            self.local_mtime = mtime
            self.local_ip, self.local_domain, self.local_wild, self.local_nets = {}, {}, {}, []
            for it in feeds.load_local_indicators(path) if mtime else []:
                meta = {"t": "local", "sev": it["severity"], "note": it.get("note") or ""}
                if it["type"] == "ip":
                    self.local_ip[it["value"]] = meta
                elif it["type"] == "cidr":
                    self.local_nets.append((ipaddress.ip_network(it["value"]), meta))
                elif it["value"].startswith("*."):
                    self.local_wild[it["value"][2:]] = meta
                else:
                    self.local_domain[it["value"]] = meta
            changed = True
        return changed

    def counts(self):
        out = {n: {"ip": len(f["ip"]), "domain": len(f["domain"])} for n, f in self.feeds.items()}
        out["local"] = {"ip": len(self.local_ip) + len(self.local_nets),
                        "domain": len(self.local_domain) + len(self.local_wild)}
        return out

    def has_domains(self):
        return bool(self.local_domain or self.local_wild or any(f["domain"] for f in self.feeds.values()))

    def match_ip(self, ip):
        hits = []
        for name, f in self.feeds.items():
            m = f["ip"].get(ip)
            if m is not None:
                hits.append((name, m))
        m = self.local_ip.get(ip)
        if m is not None:
            hits.append(("local", m))
        if self.local_nets:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                a = None
            if a is not None:
                for net, meta in self.local_nets:
                    if a.version == net.version and a in net:
                        hits.append(("local", meta))
                        break
        return hits

    def match_domain(self, q):
        """[(feed, meta, matched name)] - exact names for the feeds, '*.'
        entries of the local list also match their subdomains."""
        hits = []
        for name, f in self.feeds.items():
            m = f["domain"].get(q)
            if m is not None:
                hits.append((name, m, q))
        m = self.local_domain.get(q)
        if m is not None:
            hits.append(("local", m, q))
        elif self.local_wild:
            parts = q.split(".")
            for i in range(len(parts) - 1):
                base = ".".join(parts[i:])
                m = self.local_wild.get(base)
                if m is not None:
                    hits.append(("local", m, "*." + base))
                    break
        return hits


# ── scoring (also used by the API for instant overlays) ──────────────────────

def score_device(device, findings, now, new_seconds=NEW_DEVICE_SECONDS):
    """(risk 0-100, health, reason, worst finding or None) - see the module
    docstring for the weights."""
    risk = 0.0
    worst = None
    recent_rank = 0
    for f in findings:
        if f.get("expected"):
            continue
        sev = f.get("severity") or "low"
        age = now - (f.get("last") or 0)
        rec = RISK_RECENCY_OLD
        for limit, factor in RISK_RECENCY:
            if age < limit:
                rec = factor
                break
        risk += RISK_WEIGHTS.get(sev, 0) * rec
        if age < HEALTH_WINDOW:
            recent_rank = max(recent_rank, SEV_RANK.get(sev, 0))
        if worst is None or (SEV_RANK.get(sev, 0), f.get("last") or 0) > \
                (SEV_RANK.get(worst.get("severity"), 0), worst.get("last") or 0):
            worst = f
    risk = int(min(100, round(risk)))
    if recent_rank >= SEV_RANK["critical"] or risk >= HEALTH_CRITICAL_SCORE:
        health = "critical"
    elif recent_rank >= SEV_RANK["medium"] or risk >= HEALTH_WARNING_SCORE:
        health = "warning"
    elif not device.get("baseline") and now - (device.get("first_seen") or 0) < new_seconds:
        health = "new"
    else:
        health = "normal"
    if health in ("critical", "warning") and worst is not None:
        reason = public_reason(worst)
    elif health == "new":
        reason = "New device (first seen %s ago)" % _ago(now - (device.get("first_seen") or now))
    else:
        reason = ""
    return risk, health, reason, worst


def public_reason(f):
    """Generic text for viewers: never the indicator, address or domain."""
    kind = f.get("kind")
    if kind == "ids_alert":
        cat = ((f.get("details") or {}).get("category") or "").strip()
        return "Intrusion detection alert" + (": " + cat if cat else "")
    text = KIND_TEXT.get(kind, "Suspicious activity")
    src = SOURCE_TITLES.get(f.get("source"), "")
    return "%s (%s)" % (text, src) if src else text


def _ago(sec):
    sec = max(0, int(sec))
    if sec < 3600:
        return "%d min" % max(1, sec // 60)
    if sec < 86400:
        return "%d h" % (sec // 3600)
    return "%d d" % (sec // 86400)


def guess_type(device, vendor, names, software):
    if device.get("kind") == "wg":
        return "vpn-client", "WireGuard peer"
    for field, rx, typ in TYPE_RULES:
        if field == "name":
            for src, n in names:
                if n and rx.search(n):
                    return typ, "%s name" % src
        elif field == "vendor":
            if vendor and rx.search(vendor):
                return typ, "vendor"
        elif field == "ua":
            for s in software:
                if s.get("type", "").endswith("BROWSER") and rx.search(s.get("version") or s.get("name") or ""):
                    return typ, "browser user agent"
    return "unknown", ""


# ── the engine ───────────────────────────────────────────────────────────────

class Engine:
    def __init__(self, cfg=None, sources=None, clock=time.time, detectors=None):
        self.cfg = cfg or Config()
        self.src = sources or Sources()
        self.clock = clock
        self.oui = Oui(self.cfg.oui)
        self.geo = Geo(self.cfg.geo_db)
        self.intel = Intel(self.cfg)
        self.detectors = list(detectors) if detectors is not None else [IntelDetector(), SuricataDetector()]
        self.devices = {}
        self.findings = {}
        self.ip_hist = {}
        self.agg = {}               # device id -> runtime aggregates
        self.rdns = OrderedDict()
        self.dns_hot = {}           # (device, ip) -> (feed, meta, domain, expires)
        self.dedupe = {}
        self.cls_cache = {}
        self.events = []
        self.bootstrapped = False
        self.journal_cursor = None
        self.journal_active = False
        self.journal_error = None
        self.neigh_state = {}       # mac -> state
        self.lease_ips = {}         # device -> set of current IPs
        self.wg_peers = {}
        self.wg_nets = []
        self.prefixes = []
        self.own_ips = set()
        self.own_macs = set()
        self.roles = {}
        self.wan_devs = set()
        self.topology_at = 0
        self.config = {}
        self.overlay = {"names": {}, "expected": []}
        self.overlay_mtimes = {}
        self.last_save = 0
        self.started = clock()
        self.stats = {"unattributed": 0, "dup_flows": 0, "suricata_ignored": 0, "suricata_used": 0,
                      "cycles": 0, "last_cycle_s": 0.0}
        self.source_status = {}
        self.day_cache = {}
        z = self.cfg.zeek_current
        self.followers = {
            name: Follower(name, os.path.join(z, name + ".log"), zeek_archives(self.cfg, name),
                           INITIAL_BACKLOG["zeek"], clock)
            for name in ("dhcp", "software", "known_hosts", "dns", "conn")
        }
        self.followers["eve"] = Follower("eve", self.cfg.eve, eve_archives(self.cfg.eve), INITIAL_BACKLOG["eve"], clock)

    # ---- persistence ----
    def load_state(self):
        st = read_json(self.cfg.state("engine.json"), None, 512 << 20)
        if not isinstance(st, dict) or st.get("schema") != SCHEMA:
            return False
        self.bootstrapped = bool(st.get("bootstrapped"))
        self.journal_cursor = st.get("journal_cursor") or None
        for name, cp in (st.get("followers") or {}).items():
            if name in self.followers:
                self.followers[name].restore(cp)
        devs = st.get("devices") or {}
        for did, d in devs.items():
            if DEVICE_ID_RE.match(did) and isinstance(d, dict):
                agg = d.pop("_agg", None)
                self.devices[did] = d
                if isinstance(agg, dict):
                    self.agg[did] = self._agg_from_json(agg)
        for fid, f in (st.get("findings") or {}).items():
            if isinstance(f, dict) and DEVICE_ID_RE.match(str(f.get("device") or "")):
                self.findings[fid] = f
        hist = st.get("ip_hist") or {}
        if isinstance(hist, dict):
            self.ip_hist = {k: v for k, v in hist.items() if isinstance(v, list)}
        return True

    def save_state(self):
        devs = {}
        for did, d in self.devices.items():
            dd = dict(d)
            a = self.agg.get(did)
            if a:
                dd["_agg"] = self._agg_to_json(a)
            devs[did] = dd
        st = {"schema": SCHEMA, "saved_at": int(self.clock()), "bootstrapped": self.bootstrapped,
              "journal_cursor": self.journal_cursor,
              "followers": {n: f.cp for n, f in self.followers.items()},
              "devices": devs, "findings": self.findings, "ip_hist": self.ip_hist}
        atomic_write_json(self.cfg.state("engine.json"), st, 0o600)
        self.last_save = self.clock()

    @staticmethod
    def _agg_from_json(a):
        hours = {}
        for k, v in (a.get("hours") or {}).items():
            try:
                hours[int(k)] = {"in": int(v.get("in") or 0), "out": int(v.get("out") or 0),
                                 "n": int(v.get("n") or 0), "d": dict(v.get("d") or {}), "c": dict(v.get("c") or {})}
            except (TypeError, ValueError, AttributeError):
                continue
        return {"day": a.get("day") or "", "in": int(a.get("in") or 0), "out": int(a.get("out") or 0),
                "n": int(a.get("n") or 0), "dl": Distinct(a.get("dl")), "hours": hours,
                "last_traffic": a.get("last_traffic")}

    @staticmethod
    def _agg_to_json(a):
        return {"day": a["day"], "in": a["in"], "out": a["out"], "n": a["n"], "dl": a["dl"].hex(),
                "hours": {str(k): v for k, v in a["hours"].items()}, "last_traffic": a.get("last_traffic")}

    # ---- overlays / config ----
    def _load_if_changed(self, name):
        path = self.cfg.conf(name)
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            mtime = None
        if self.overlay_mtimes.get(name, -1) == mtime:
            return None, False
        self.overlay_mtimes[name] = mtime
        return (read_json(path, {}, 4 << 20) if mtime else {}), True

    def load_overlays(self):
        cfg, ch = self._load_if_changed("devicewatch.json")
        if ch:
            self.config = cfg if isinstance(cfg, dict) else {}
        names, ch = self._load_if_changed("names.json")
        if ch:
            n = names.get("names") if isinstance(names, dict) else None
            self.overlay["names"] = {k: v for k, v in (n or {}).items()
                                     if DEVICE_ID_RE.match(k) and isinstance(v, str)}
        exp, ch = self._load_if_changed("expected.json")
        if ch:
            e = exp.get("entries") if isinstance(exp, dict) else None
            self.overlay["expected"] = [x for x in (e or []) if isinstance(x, dict) and x.get("indicator")]
            self._apply_expected()

    def _apply_expected(self):
        for f in self.findings.values():
            f["expected"] = is_expected(f, self.overlay["expected"])

    def retention_seconds(self):
        try:
            days = int(self.config.get("retention_days") or RETENTION_DAYS)
        except (TypeError, ValueError):
            days = RETENTION_DAYS
        return max(1, min(365, days)) * 86400

    # ---- topology ----
    def refresh_topology(self, force=False):
        now = self.clock()
        if not force and now - self.topology_at < TOPOLOGY_SECONDS and self.prefixes:
            return
        self.topology_at = now
        roles, wan = {}, set()
        conf = read_json(self.cfg.interfaces, {}) or {}
        if isinstance(conf, dict) and conf.get("lan"):
            w = (conf.get("wan") or {}).get("device")
            if w:
                wan.add(w)
            lan = conf.get("lan") or {}
            if lan.get("device"):
                roles[lan["device"]] = {"zone": "lan", "name": "LAN", "vlan": None}
            for o in conf.get("opt") or []:
                if isinstance(o, dict) and o.get("device"):
                    roles[o["device"]] = {"zone": o.get("id") or "opt", "name": o.get("name") or o["device"],
                                          "vlan": o.get("vlan")}
            for v in conf.get("vpn") or []:
                if isinstance(v, dict) and v.get("device"):
                    roles[v["device"]] = {"zone": "vpn", "name": v.get("name") or v["device"], "vlan": None}
        wan |= set(self.src.default_route_devs() or ())
        prefixes, own, own_macs = [], set(), set()
        fallback = not (isinstance(conf, dict) and conf.get("lan"))
        for ifc in self.src.addresses() or []:
            if not isinstance(ifc, dict):
                continue
            dev = ifc.get("ifname")
            m = norm_mac(ifc.get("address"))
            if m:
                own_macs.add(m)
            for a in ifc.get("addr_info") or []:
                local = a.get("local")
                ip = feeds.norm_ip(local) if local else None
                if not ip:
                    continue
                own.add(ip)
                if dev in wan or dev == "lo" or a.get("scope") == "link":
                    continue
                if fallback and dev not in roles:
                    try:
                        if not ipaddress.ip_address(ip).is_private:
                            continue
                    except ValueError:
                        continue
                    roles.setdefault(dev, {"zone": "lan", "name": dev, "vlan": None})
                if dev not in roles:
                    continue
                try:
                    net = ipaddress.ip_network("%s/%s" % (ip, a.get("prefixlen")), strict=False)
                except ValueError:
                    continue
                prefixes.append((net, dev))
        prefixes.sort(key=lambda x: -x[0].prefixlen)
        if prefixes != self.prefixes or own != self.own_ips:
            self.cls_cache.clear()
        self.prefixes, self.own_ips, self.roles, self.wan_devs = prefixes, own, roles, wan
        self.own_macs = own_macs

    def classify(self, ip):
        """(class, interface) of an address: EXT, LAN (a device), OWN (the
        router), SKIP (multicast/link-local/broadcast/garbage)."""
        c = self.cls_cache.get(ip)
        if c is not None:
            return c
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            c = (SKIP, None)
        else:
            if ip in self.own_ips:
                c = (OWN, None)
            elif a.is_multicast or a.is_unspecified or a.is_loopback or a.is_link_local:
                c = (SKIP, None)
            else:
                c = None
                for net, dev in self.prefixes:
                    if a.version == net.version and a in net:
                        if a.version == 4 and (a == net.broadcast_address or a == net.network_address) \
                                and net.prefixlen < 31:
                            c = (SKIP, None)
                        else:
                            c = (LAN, dev)
                        break
                if c is None:
                    for net, dev in self.wg_nets:
                        if a.version == net.version and a in net:
                            c = (LAN, dev)
                            break
                if c is None:
                    c = (EXT, None) if (a.is_global or a.is_private) else (SKIP, None)
        if len(self.cls_cache) > CLASSIFY_CACHE_MAX:
            self.cls_cache.clear()
        self.cls_cache[ip] = c
        return c

    # ---- inventory ----
    def ensure_device(self, did, kind, ts, **attrs):
        d = self.devices.get(did)
        if d is None:
            if len(self.devices) >= MAX_DEVICES:
                return None
            d = {"id": did, "kind": kind, "first_seen": ts, "last_seen": ts, "names": {}, "ips": {},
                 "seen_by": {}, "software": {}, "baseline": not self.bootstrapped}
            self.devices[did] = d
            if self.bootstrapped:
                self._event({"type": "new_device", "device": did, "kind": kind,
                             "private_mac": bool(attrs.get("mac") and is_private_mac(attrs["mac"]))}, ts)
        for k, v in attrs.items():
            if v is not None:
                d[k] = v
        if ts < (d.get("first_seen") or ts):
            d["first_seen"] = ts
        return d

    def touch(self, d, ts, source=None, ip=None):
        if ts > (d.get("last_seen") or 0):
            d["last_seen"] = ts
        if source:
            sb = d.setdefault("seen_by", {})
            if ts > (sb.get(source) or 0):
                sb[source] = ts
        if ip:
            ips = d.setdefault("ips", {})
            if ts > (ips.get(ip) or 0):
                ips[ip] = ts
                if len(ips) > 32:
                    for k in sorted(ips, key=ips.get)[:len(ips) - 32]:
                        del ips[k]

    def observe(self, ip, did, ts):
        h = self.ip_hist.get(ip)
        if h is None:
            if len(self.ip_hist) >= IP_HISTORY_MAX:
                self._prune_ip_hist(force=True)
            h = self.ip_hist[ip] = []
        if h and h[-1][0] == did:
            if ts > h[-1][2]:
                h[-1][2] = ts
            if ts < h[-1][1]:
                h[-1][1] = ts
            return
        for e in h:
            if e[0] == did and e[1] - 600 <= ts <= e[2] + 600:
                e[2] = max(e[2], ts)
                return
        h.append([did, ts, ts])
        h.sort(key=lambda e: e[2])
        del h[:-IP_HISTORY_PER_IP]

    def who(self, ip, ts):
        h = self.ip_hist.get(ip)
        if not h:
            return None
        if len(h) == 1:
            return h[0][0] if ts <= h[0][2] + IP_HISTORY_SECONDS else None
        for did, first, last in reversed(h):
            if first - 600 <= ts <= last + 3600:
                return did
        for did, first, last in reversed(h):
            if first <= ts:
                return did
        return h[0][0]

    def _prune_ip_hist(self, force=False):
        cut = self.clock() - IP_HISTORY_SECONDS
        for ip in [k for k, v in self.ip_hist.items() if not v or v[-1][2] < cut]:
            del self.ip_hist[ip]
        if force and len(self.ip_hist) >= IP_HISTORY_MAX:
            for ip in sorted(self.ip_hist, key=lambda k: self.ip_hist[k][-1][2])[:IP_HISTORY_MAX // 10]:
                del self.ip_hist[ip]

    def attribute(self, ip, ts, iface=None, create=True):
        did = self.who(ip, ts)
        if did:
            return did
        if ":" in ip:
            mac = mac_from_eui64(ip)
            if mac:
                d = self.ensure_device(mac_id(mac), "mac", ts, mac=mac)
                if d is not None:
                    self.observe(ip, d["id"], ts)
                    return d["id"]
            self.stats["unattributed"] += 1
            return None
        if not create:
            return None
        did = ip_id(ip)
        d = self.ensure_device(did, "ip", ts, address=ip)
        if d is None:
            return None
        self.observe(ip, did, ts)
        if iface:
            self._set_iface(d, iface)
        return did

    def _set_iface(self, d, iface):
        r = self.roles.get(iface) or {}
        d["iface"] = iface
        d["zone"] = r.get("zone") or ""
        d["zone_name"] = r.get("name") or iface
        d["vlan"] = r.get("vlan")

    def refresh_inventory(self):
        now = self.clock()
        # Kea leases (v4 + v6) and reservations
        cur_ips = {}
        for v6, paths in ((False, self.cfg.kea4), (True, self.cfg.kea6)):
            leases = read_kea_leases(paths, now, v6)
            if not v6:
                self.source_status["kea"] = {"ok": any(os.access(p, os.R_OK) for p in paths),
                                             "active_leases": len(leases)}
            for le in leases:
                mac = le["mac"]
                d = self.ensure_device(mac_id(mac), "mac", min(now, le["cltt"] or now), mac=mac)
                if d is None:
                    continue
                if le["hostname"]:
                    d["names"]["kea"] = le["hostname"]
                self.touch(d, min(now, le["cltt"] or now), "lease", le["ip"])
                self.observe(le["ip"], d["id"], now)
                cur_ips.setdefault(d["id"], set()).add(le["ip"])
                c, dev = self.classify(le["ip"])
                if dev:
                    self._set_iface(d, dev)
        for r in read_kea_reservations(self.cfg.kea_conf):
            d = self.devices.get(mac_id(r["mac"]))
            if d is not None and r["hostname"]:
                d["names"]["reservation"] = r["hostname"]
        # neighbours (ARP / NDP)
        neigh = self.src.neighbours()
        states = {}
        n_ok = 0
        for n in neigh or []:
            if not isinstance(n, dict):
                continue
            dev = n.get("dev")
            mac = norm_mac(n.get("lladdr"))
            ip = feeds.norm_ip(n.get("dst"))
            if not mac or not ip or dev in self.wan_devs or dev not in self.roles:
                continue
            st = (n.get("state") or ["?"])[0] if isinstance(n.get("state"), list) else str(n.get("state") or "?")
            if st in ("FAILED", "INCOMPLETE", "NOARP"):
                continue
            n_ok += 1
            c, _ = self.classify(ip)
            if c != LAN and not ip.startswith("fe80:"):
                continue
            d = self.ensure_device(mac_id(mac), "mac", now, mac=mac)
            if d is None:
                continue
            active = st in ("REACHABLE", "DELAY", "PROBE", "PERMANENT")
            if not ip.startswith("fe80:"):
                self.observe(ip, d["id"], now)
                self.touch(d, now if active else (d.get("last_seen") or now), "neighbour", ip)
                cur_ips.setdefault(d["id"], set()).add(ip)
            elif active:
                self.touch(d, now, "neighbour")
            self._set_iface(d, dev)
            prev = states.get(mac)
            if prev is None or (prev not in ("REACHABLE", "DELAY", "PROBE") and active):
                states[mac] = st
        self.neigh_state = states
        self.source_status["neighbours"] = {"ok": neigh is not None, "entries": n_ok}
        # WireGuard peers (snapshot written by the API)
        snap = read_json(self.cfg.wg_snapshot, None, 4 << 20)
        peers, nets = {}, []
        if isinstance(snap, dict):
            iface = snap.get("iface") or "wg0"
            for p in snap.get("peers") or []:
                pk = str((p or {}).get("public_key") or "")
                if not re.match(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$", pk):
                    continue
                did = wg_id(pk)
                hs = int(p.get("last_handshake") or 0)
                d = self.ensure_device(did, "wg", now, wg_public_key=pk)
                if d is None:
                    continue
                d["names"]["wg"] = str(p.get("name") or "")[:64]
                self._set_iface(d, iface)
                if hs:
                    self.touch(d, min(hs, now), "wireguard")
                peers[did] = hs
                for cidr in p.get("allowed_ips") or []:
                    try:
                        net = ipaddress.ip_network(str(cidr), strict=False)
                    except ValueError:
                        continue
                    if net.num_addresses == 1:
                        ip = net.network_address.compressed
                        self.observe(ip, did, now)
                        cur_ips.setdefault(did, set()).add(ip)
                    else:
                        nets.append((net, iface))
        if nets != self.wg_nets:
            self.cls_cache.clear()
        self.wg_peers, self.wg_nets = peers, nets
        self.source_status["wireguard"] = {"ok": isinstance(snap, dict), "peers": len(peers)}
        self.lease_ips = cur_ips

    # ---- log handlers ----
    def _loads(self, line):
        try:
            ev = json.loads(line)
        except ValueError:
            return None
        return ev if isinstance(ev, dict) else None

    def _ts(self, ev):
        try:
            return float(ev.get("ts") or 0)
        except (TypeError, ValueError):
            return 0.0

    def _dup(self, key, ts, window=1.0):
        prev = self.dedupe.get(key)
        if prev is not None and abs(prev - ts) < window:
            return True
        if len(self.dedupe) > DEDUPE_MAX:
            self.dedupe.clear()
        self.dedupe[key] = ts
        return False

    def on_dhcp(self, line):
        ev = self._loads(line)
        if not ev:
            return
        mac = norm_mac(ev.get("mac"))
        ip = feeds.norm_ip(ev.get("assigned_addr") or ev.get("client_addr") or "")
        ts = self._ts(ev)
        if not mac or not ts:
            return
        if ip:
            c, dev = self.classify(ip)
            if c != LAN:
                return
        d = self.ensure_device(mac_id(mac), "mac", ts, mac=mac)
        if d is None:
            return
        host = ev.get("host_name") or ev.get("client_fqdn") or ""
        if host:
            d["names"]["dhcp"] = str(host).rstrip(".")[:64]
        self.touch(d, ts, "dhcp", ip)
        if ip:
            self.observe(ip, d["id"], ts)
            if dev:
                self._set_iface(d, dev)

    def on_software(self, line):
        ev = self._loads(line)
        if not ev:
            return
        host = feeds.norm_ip(ev.get("host") or "")
        ts = self._ts(ev)
        if not host or self.classify(host)[0] != LAN:
            return
        did = self.who(host, ts)
        d = self.devices.get(did) if did else None
        if d is None:
            return
        name = str(ev.get("name") or "")[:48]
        if not name:
            return
        sw = d.setdefault("software", {})
        sw[name] = {"type": str(ev.get("software_type") or "")[:32],
                    "version": str(ev.get("unparsed_version") or "")[:120], "last": ts}
        if len(sw) > 8:
            for k in sorted(sw, key=lambda k: sw[k].get("last") or 0)[:len(sw) - 8]:
                del sw[k]

    def on_known_host(self, line):
        ev = self._loads(line)
        if not ev:
            return
        host = feeds.norm_ip(ev.get("host") or "")
        ts = self._ts(ev)
        if host and self.classify(host)[0] == LAN:
            did = self.who(host, ts)
            if did and did in self.devices:
                self.touch(self.devices[did], ts, "zeek")

    def on_dns(self, line):
        ev = self._loads(line)
        if not ev:
            return
        o = ev.get("id.orig_h") or ""
        c, iface = self.classify(o)
        if c != LAN:
            return
        q = ev.get("query")
        if not isinstance(q, str) or "." not in q:
            return
        ts = self._ts(ev)
        if self._dup(("d", o, ev.get("id.orig_p"), ev.get("trans_id"), q), ts, 2.0):
            self.stats["dup_flows"] += 1
            return
        q = q.lower().rstrip(".")
        answers = [a for a in (ev.get("answers") or []) if isinstance(a, str)]
        ips = []
        for a in answers:
            if a and (a[0].isdigit() or ":" in a) and feeds.norm_ip(a):
                ips.append(feeds.norm_ip(a))
                self.rdns[ips[-1]] = q
        while len(self.rdns) > RDNS_MAX:
            self.rdns.popitem(last=False)
        if not self.intel.has_domains():
            return
        did = self.attribute(o, ts, iface, create=False)
        rcode = ev.get("rcode_name") or ""
        real = [a for a in ips if a not in SINKHOLES]
        de = DnsEvent()
        de.ts, de.device, de.dev_ip, de.query = ts, did, o, q
        de.qtype, de.rcode, de.answers = ev.get("qtype_name") or "", rcode, real
        de.answered = rcode == "NOERROR" and bool(real or [a for a in answers if a and a not in SINKHOLES])
        de.blocked = not de.answered
        de.source = "zeek"
        self._run_detectors("on_dns", de, o, iface)

    def on_unbound(self, ts, msg):
        m = UNBOUND_LOCAL_RE.search(msg)
        if m:
            client, qname = m.group(2), m.group(3)
        else:
            m = UNBOUND_RPZ_RE.search(msg)
            if not m:
                return
            client, qname = m.group(1), m.group(2)
        ip = feeds.norm_ip(client)
        if not ip:
            return
        c, iface = self.classify(ip)
        if c != LAN:
            return
        q = qname.lower().rstrip(".")
        if not self.intel.match_domain(q):
            return
        de = DnsEvent()
        de.ts, de.device, de.dev_ip, de.query = ts, self.who(ip, ts), ip, q
        de.qtype, de.rcode, de.answers, de.answered, de.blocked, de.source = "", "BLOCKED", [], False, True, "unbound"
        self._run_detectors("on_dns", de, ip, iface)

    def on_conn(self, line):
        ev = self._loads(line)
        if not ev:
            return
        o = ev.get("id.orig_h") or ""
        r = ev.get("id.resp_h") or ""
        co, oif = self.classify(o)
        cr, rif = self.classify(r)
        if co == LAN and cr == EXT:
            dev_ip, peer, outbound, iface = o, r, True, oif
        elif cr == LAN and co == EXT:
            dev_ip, peer, outbound, iface = r, o, False, rif
        else:
            return
        ts = self._ts(ev)
        if not ts:
            return
        proto = ev.get("proto") or ""
        if self._dup(("c", o, ev.get("id.orig_p"), r, ev.get("id.resp_p"), proto), ts, 1.0):
            self.stats["dup_flows"] += 1
            return
        ob = ev.get("orig_ip_bytes") or ev.get("orig_bytes") or 0
        rb = ev.get("resp_ip_bytes") or ev.get("resp_bytes") or 0
        if not isinstance(ob, int):
            ob = 0
        if not isinstance(rb, int):
            rb = 0
        b_out, b_in = (ob, rb) if outbound else (rb, ob)
        # Zeek's optional mac-logging policy adds the link-layer addresses: the
        # LAN side's MAC settles addresses the neighbour table no longer holds
        l2 = norm_mac(ev.get("orig_l2_addr" if outbound else "resp_l2_addr"))
        if l2 and l2 not in self.own_macs and not self.who(dev_ip, ts):
            d = self.ensure_device(mac_id(l2), "mac", ts, mac=l2)
            if d is not None:
                self.observe(dev_ip, d["id"], ts)
                if iface:
                    self._set_iface(d, iface)
        did = self.attribute(dev_ip, ts, iface)
        if did:
            self._traffic(did, ts, peer, b_in, b_out)
        state = ev.get("conn_state") or ""
        hist = ev.get("history") or ""
        ce = ConnEvent()
        ce.ts, ce.device, ce.dev_ip, ce.peer = ts, did, dev_ip, peer
        ce.peer_port = ev.get("id.resp_p") if outbound else ev.get("id.orig_p")
        ce.proto, ce.outbound, ce.state, ce.history = proto, outbound, state, hist
        ce.bytes_in, ce.bytes_out, ce.service = b_in, b_out, ev.get("service") or ""
        ce.duration = ev.get("duration") or 0
        if proto == "tcp":
            ce.established = state in ("SF", "S1", "S2", "S3", "RSTO", "RSTR") or ("h" in hist.lower() and "d" in hist.lower())
        else:
            ce.established = (ev.get("resp_pkts") or 0) > 0 and (ev.get("orig_pkts") or 0) > 0
        self._run_detectors("on_conn", ce, dev_ip, iface)

    def on_eve(self, line):
        if b'"event_type":"alert"' not in line:
            return
        ev = self._loads(line)
        if not ev or ev.get("event_type") != "alert":
            return
        a = ev.get("alert") or {}
        sig = str(a.get("signature") or "")
        cat = str(a.get("category") or "")
        if not suricata_relevant(sig, cat):
            self.stats["suricata_ignored"] += 1
            return
        ts = parse_eve_ts(ev.get("timestamp"))
        if not ts:
            return
        src, dst = feeds.norm_ip(ev.get("src_ip") or ""), feeds.norm_ip(ev.get("dest_ip") or "")
        if not src or not dst:
            return
        client = dst if ev.get("direction") == "to_client" else src
        self.stats["suricata_used"] += 1
        for ip, other in ((src, dst), (dst, src)):
            c, iface = self.classify(ip)
            if c != LAN:
                continue
            ae = AlertEvent()
            ae.ts, ae.dev_ip, ae.peer, ae.outbound = ts, ip, other, ip == client
            ae.device_sent = ip == src
            ae.sid, ae.rev = a.get("signature_id"), a.get("rev")
            ae.signature, ae.category = sig, cat
            ae.severity = a.get("severity") if isinstance(a.get("severity"), int) else 3
            ae.proto = ev.get("proto") or ""
            ae.dest_port = ev.get("dest_port")
            ae.action = a.get("action") or ""
            ae.device = self.attribute(ip, ts, iface)
            self._run_detectors("on_alert", ae, ip, iface)

    def _run_detectors(self, method, ev, dev_ip, iface):
        for det in self.detectors:
            try:
                specs = getattr(det, method)(self, ev)
            except Exception as exc:  # a broken detector must not stop the engine
                self.source_status.setdefault("detectors", {})[det.name] = "error: %s" % exc.__class__.__name__
                continue
            for spec in specs or ():
                did = ev.device
                if not did:
                    # a threat on an address with no known MAC still needs a device
                    did = hash_id("i", dev_ip)
                    d = self.ensure_device(did, "ip", ev.ts, address=dev_ip)
                    if d is None:
                        continue
                    self.observe(dev_ip, did, ev.ts)
                    if iface:
                        self._set_iface(d, iface)
                    ev.device = did
                self.record_finding(did, spec, ev.ts)

    # ---- DNS -> connection correlation ----
    def dns_hot_add(self, did, ips, feed, meta, domain, ts):
        if not did:
            return
        for ip in ips[:16]:
            self.dns_hot[(did, ip)] = (feed, meta, domain, ts + DNS_HOT_SECONDS)
        if len(self.dns_hot) > 20000:
            now = self.clock()
            self.dns_hot = {k: v for k, v in self.dns_hot.items() if v[3] > now}

    def dns_hot_lookup(self, did, ip, ts):
        if not did or not self.dns_hot:
            return None
        v = self.dns_hot.get((did, ip))
        if v is None or ts > v[3]:
            return None
        return v[0], v[1], v[2]

    # ---- aggregates ----
    def _day(self, ts):
        hour = int(ts // 3600)
        d = self.day_cache.get(hour)
        if d is None:
            if len(self.day_cache) > 2000:
                self.day_cache.clear()
            d = self.day_cache[hour] = time.strftime("%Y-%m-%d", time.localtime(hour * 3600))
        return d

    def _agg(self, did):
        a = self.agg.get(did)
        if a is None:
            a = self.agg[did] = {"day": "", "in": 0, "out": 0, "n": 0, "dl": Distinct(), "hours": {},
                                 "last_traffic": None}
        return a

    def _traffic(self, did, ts, peer, b_in, b_out):
        a = self._agg(did)
        today = self._day(self.clock())
        if a["day"] != today:
            a.update(day=today, **{"in": 0, "out": 0, "n": 0})
            a["dl"] = Distinct()
        if self._day(ts) == today:
            a["in"] += b_in
            a["out"] += b_out
            a["n"] += 1
            a["dl"].add(peer)
        if ts > (a.get("last_traffic") or 0):
            a["last_traffic"] = ts
        d = self.devices.get(did)
        if d is not None:
            self.touch(d, ts, "traffic")
        hour = int(ts // 3600) * 3600
        if hour < self.clock() - HOURS_KEPT * 3600:
            return
        hb = a["hours"].get(hour)
        if hb is None:
            hb = a["hours"][hour] = {"in": 0, "out": 0, "n": 0, "d": {}, "c": {}}
        hb["in"] += b_in
        hb["out"] += b_out
        hb["n"] += 1
        b = b_in + b_out
        dd = hb["d"]
        e = dd.get(peer)
        if e is not None:
            e[0] += b
            e[1] += 1
        else:
            if len(dd) >= DESTS_PER_HOUR:
                victim = min(dd, key=lambda k: dd[k][0])
                if dd[victim][0] > b:
                    victim = None
                if victim is not None:
                    del dd[victim]
            if len(dd) < DESTS_PER_HOUR:
                dd[peer] = [b, 1, self.rdns.get(peer, "")]
        iso = self.geo.iso(peer) or "??"
        c = hb["c"].get(iso)
        if c is None:
            hb["c"][iso] = [b, 1]
        else:
            c[0] += b
            c[1] += 1

    # ---- findings ----
    def record_finding(self, did, spec, ts):
        now = self.clock()
        if ts < now - self.retention_seconds():
            return None
        key = "%s|%s|%s" % (did, spec["kind"], spec["indicator"])
        fid = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
        f = self.findings.get(fid)
        if f is None:
            if len(self.findings) >= MAX_FINDINGS:
                self._prune_findings(force=True)
            f = self.findings[fid] = {
                "id": fid, "device": did, "kind": spec["kind"], "indicator": str(spec["indicator"])[:255],
                "indicator_type": spec.get("indicator_type") or "", "severity": spec["severity"],
                "title": spec.get("title") or KIND_TEXT.get(spec["kind"], spec["kind"]),
                "source": spec.get("source") or "", "first": ts, "last": ts, "count": 1,
                "details": spec.get("details") or {}}
            f["expected"] = is_expected(f, self.overlay["expected"])
            if not f["expected"]:
                self._event({"type": "finding", "device": did, "finding": fid, "severity": f["severity"],
                             "kind": f["kind"], "source": f["source"]}, ts)
            return f
        f["count"] += 1
        if ts > f["last"]:
            f["last"] = ts
            f["details"] = spec.get("details") or f["details"]
        if ts < f["first"]:
            f["first"] = ts
        if SEV_RANK.get(spec["severity"], 0) > SEV_RANK.get(f["severity"], 0):
            f["severity"] = spec["severity"]
            f["title"] = spec.get("title") or f["title"]
            if not f.get("expected"):
                self._event({"type": "finding", "device": did, "finding": fid, "severity": f["severity"],
                             "kind": f["kind"], "source": f["source"], "escalated": True}, ts)
        return f

    def _prune_findings(self, force=False):
        cut = self.clock() - self.retention_seconds()
        for fid in [k for k, f in self.findings.items() if (f.get("last") or 0) < cut]:
            del self.findings[fid]
        if force and len(self.findings) >= MAX_FINDINGS:
            order = sorted(self.findings, key=lambda k: (SEV_RANK.get(self.findings[k]["severity"], 0),
                                                         self.findings[k]["last"]))
            for fid in order[:MAX_FINDINGS // 10]:
                del self.findings[fid]

    def _event(self, ev, ts):
        ev = dict(ev, ts=int(ts))
        self.events.append(ev)

    def flush_events(self):
        if not self.events:
            return
        path = self.cfg.state("events.jsonl")
        try:
            if os.path.exists(path) and os.path.getsize(path) > EVENTS_MAX_BYTES:
                os.replace(path, path + ".1")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                for ev in self.events:
                    f.write(json.dumps(ev, separators=(",", ":")) + "\n")
            self.events = []
        except OSError:
            self.events = self.events[-1000:]

    # ---- the cycle ----
    def poll_logs(self):
        handlers = {"dhcp": self.on_dhcp, "software": self.on_software, "known_hosts": self.on_known_host,
                    "dns": self.on_dns, "conn": self.on_conn}
        for name in ("dhcp", "software", "known_hosts", "dns", "conn"):
            self.followers[name].poll(handlers[name])
        if self.config.get("suricata", True):
            self.followers["eve"].poll(self.on_eve)
        if self.config.get("unbound_journal", True):
            lines, cursor, err = self.src.journal(self.journal_cursor)
            self.journal_error = err
            self.journal_active = err is None or bool(lines)
            if cursor is not None or err:
                self.journal_cursor = cursor
            if self.intel.has_domains():
                for ts, msg in lines:
                    if "always_" in msg or "rpz: applied" in msg or "deny" in msg or "refuse" in msg or \
                            "redirect" in msg:
                        self.on_unbound(ts, msg)
            self.source_status["unbound_journal"] = {"ok": err is None, "lines": len(lines), "error": err}
        else:
            self.journal_active = False

    def prune(self):
        now = self.clock()
        cut = now - HOURS_KEPT * 3600 - 3600
        for a in self.agg.values():
            for h in [h for h in a["hours"] if h < cut]:
                del a["hours"][h]
        self._prune_findings()
        self._prune_ip_hist()
        old = now - max(self.retention_seconds(), 90 * 86400)
        for did in [k for k, d in self.devices.items()
                    if (d.get("last_seen") or 0) < old and not any(f["device"] == k for f in self.findings.values())]:
            self.devices.pop(did, None)
            self.agg.pop(did, None)
        if self.dns_hot:
            self.dns_hot = {k: v for k, v in self.dns_hot.items() if v[3] > now}

    def cycle(self):
        t0 = time.monotonic()
        self.load_overlays()
        self.refresh_topology()
        if self.intel.reload(self.config):
            pass
        self.refresh_inventory()
        self.poll_logs()
        for det in self.detectors:
            try:
                for spec, did, ts in det.on_cycle(self, self.clock()) or ():
                    self.record_finding(did, spec, ts)
            except Exception:
                pass
        self.prune()
        self.bootstrapped = True
        self.stats["cycles"] += 1
        self.stats["last_cycle_s"] = round(time.monotonic() - t0, 3)
        self.write_outputs()
        self.flush_events()
        if self.clock() - self.last_save >= STATE_SAVE_SECONDS:
            self.save_state()

    # ---- outputs ----
    def device_name(self, d):
        did = d["id"]
        user = self.overlay["names"].get(did)
        if user:
            return user, "user"
        names = d.get("names") or {}
        for src in ("reservation", "kea", "dhcp", "wg"):
            if names.get(src):
                return names[src], src
        if d.get("kind") == "ip":
            return "Device %s" % (d.get("address") or ""), "address"
        vendor = d.get("vendor") or ""
        if vendor and vendor != "Private MAC":
            return "%s device" % vendor.split(",")[0][:32], "vendor"
        return (d.get("mac") or "Unknown device"), "mac"

    def build_device(self, d, flist, now):
        did = d["id"]
        mac = d.get("mac")
        vendor = self.oui.vendor(mac) if mac else ""
        d["vendor"] = vendor
        name, name_src = self.device_name(d)
        sw = sorted((dict(v, name=k) for k, v in (d.get("software") or {}).items()),
                    key=lambda s: -(s.get("last") or 0))
        names = [(k, v) for k, v in (("user", self.overlay["names"].get(did)),) if v]
        names += [(k, (d.get("names") or {}).get(k)) for k in ("reservation", "kea", "dhcp", "wg")]
        typ, why = guess_type(d, vendor, names, sw)
        if typ == "unknown" and mac and is_private_mac(mac):
            why = "private MAC"
        risk, health, reason, worst = score_device(d, flist, now)
        a = self.agg.get(did)
        today = self._day(now)
        cur = sorted(ip for ip, t in (d.get("ips") or {}).items() if t >= now - 86400)
        current = sorted(self.lease_ips.get(did, ()))
        online = False
        nstate = self.neigh_state.get(mac) if mac else None
        if nstate in ("REACHABLE", "DELAY", "PROBE", "PERMANENT"):
            online = True
        last_traffic = (a or {}).get("last_traffic") or 0
        if now - last_traffic < ONLINE_SECONDS:
            online = True
        if d.get("kind") == "wg":
            online = now - (self.wg_peers.get(did) or 0) < WG_ONLINE_SECONDS
        hourly, dests, countries = [], {}, {}
        base = int(now // 3600) * 3600 - (HOURS_KEPT - 1) * 3600
        hours = (a or {}).get("hours") or {}
        for i in range(HOURS_KEPT):
            h = base + i * 3600
            hb = hours.get(h)
            hourly.append({"t": h, "in": hb["in"] if hb else 0, "out": hb["out"] if hb else 0,
                           "conns": hb["n"] if hb else 0})
            if hb:
                for ip, e in hb["d"].items():
                    x = dests.get(ip)
                    if x is None:
                        dests[ip] = [e[0], e[1], e[2] if len(e) > 2 else ""]
                    else:
                        x[0] += e[0]
                        x[1] += e[1]
                        if not x[2] and len(e) > 2:
                            x[2] = e[2]
                for iso, e in hb["c"].items():
                    x = countries.setdefault(iso, [0, 0])
                    x[0] += e[0]
                    x[1] += e[1]

        def dest_rows(keyidx):
            rows = sorted(dests.items(), key=lambda kv: (-kv[1][keyidx], kv[0]))[:TOP_N]
            return [{"ip": ip, "name": e[2] or self.rdns.get(ip, ""), "country": self.geo.iso(ip),
                     "bytes": e[0], "conns": e[1]} for ip, e in rows]
        if a and a.get("day") == today:
            activity = {"day": today, "bytes_in": a["in"], "bytes_out": a["out"], "conns": a["n"],
                        "destinations": a["dl"].count()}
        else:
            activity = {"day": today, "bytes_in": 0, "bytes_out": 0, "conns": 0, "destinations": 0}
        active = [f for f in flist if not f.get("expected")]
        return {
            "id": did, "kind": d.get("kind"), "name": name, "name_source": name_src,
            "mac": mac, "private_mac": bool(mac and is_private_mac(mac)), "vendor": vendor,
            "type": typ, "type_reason": why,
            "ips": [ip for ip in cur if ":" not in ip], "ipv6": [ip for ip in cur if ":" in ip],
            "current_ips": current,
            "iface": d.get("iface") or "", "zone": d.get("zone") or "", "zone_name": d.get("zone_name") or "",
            "vlan": d.get("vlan"), "first_seen": int(d.get("first_seen") or 0), "last_seen": int(d.get("last_seen") or 0),
            "online": online, "neighbour_state": nstate, "baseline": bool(d.get("baseline")),
            "health": health, "risk": risk, "reason": reason,
            "worst_finding": worst["id"] if worst else None,
            "findings": {"total": len(flist), "active": len(active), "expected": len(flist) - len(active)},
            "activity": activity, "hourly": hourly,
            "top_destinations": dest_rows(0), "top_destinations_by_conns": dest_rows(1),
            "top_countries": [{"iso": iso, "bytes": e[0], "conns": e[1]}
                              for iso, e in sorted(countries.items(), key=lambda kv: -kv[1][0])[:TOP_N]],
            "hostnames": {k: v for k, v in (d.get("names") or {}).items() if v},
            "software": sw[:8], "seen_by": d.get("seen_by") or {},
            "wg_public_key": d.get("wg_public_key"),
        }

    def write_outputs(self):
        now = self.clock()
        by_dev = {}
        for f in self.findings.values():
            by_dev.setdefault(f["device"], []).append(f)
        devices = [self.build_device(d, by_dev.get(did, []), now) for did, d in self.devices.items()]
        rank = {"critical": 3, "warning": 2, "new": 1}
        devices.sort(key=lambda x: (-rank.get(x["health"], 0), -x["risk"], x["name"].lower()))
        findings = sorted(self.findings.values(), key=lambda f: (-SEV_RANK.get(f["severity"], 0), -f["last"]))
        atomic_write_json(self.cfg.state("devices.json"),
                          {"schema": SCHEMA, "generated_at": int(now), "devices": devices})
        atomic_write_json(self.cfg.state("findings.json"),
                          {"schema": SCHEMA, "generated_at": int(now), "findings": findings})
        atomic_write_json(self.cfg.state("summary.json"), summarize(devices, findings, now))
        atomic_write_json(self.cfg.state("status.json"), self.status(now))

    def status(self, now):
        try:
            import resource
            ru = resource.getrusage(resource.RUSAGE_SELF)
            cpu, rss = round(ru.ru_utime + ru.ru_stime, 2), ru.ru_maxrss
        except Exception:
            cpu, rss = None, None
        try:
            with open("/proc/self/statm") as f:
                rss_now = int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") // 1024
        except (OSError, ValueError, IndexError):
            rss_now = None
        logs = {}
        for n, f in self.followers.items():
            logs[n] = dict(f.stats)
        return {"schema": SCHEMA, "version": ENGINE_VERSION, "generated_at": int(now), "started_at": int(self.started),
                "cycle_seconds": CYCLE_SECONDS, "stats": dict(self.stats), "logs": logs,
                "sources": self.source_status, "indicators": self.intel.counts(),
                "geoip": self.geo.available, "devices": len(self.devices), "findings": len(self.findings),
                "cpu_seconds": cpu, "max_rss_kb": rss, "rss_kb": rss_now,
                "journal": {"active": self.journal_active, "error": self.journal_error},
                "lan_prefixes": len(self.prefixes)}


def is_expected(f, entries):
    for e in entries:
        if e.get("indicator") != f.get("indicator"):
            continue
        if e.get("device") not in ("*", f.get("device")):
            continue
        if e.get("kind") and e.get("kind") != f.get("kind"):
            continue
        return True
    return False


def summarize(devices, findings, now):
    flagged = [d for d in devices if d["health"] in ("warning", "critical")]
    active = [f for f in findings if not f.get("expected")]
    worst = None
    for f in active:
        if worst is None or (SEV_RANK.get(f["severity"], 0), f["last"]) > (SEV_RANK.get(worst["severity"], 0), worst["last"]):
            worst = f
    names = {d["id"]: d["name"] for d in devices}
    return {
        "schema": SCHEMA, "generated_at": int(now),
        "devices": len(devices), "online": sum(1 for d in devices if d["online"]),
        "new_24h": sum(1 for d in devices if d["health"] == "new"),
        "flagged": len(flagged), "critical": sum(1 for d in devices if d["health"] == "critical"),
        "warning": sum(1 for d in devices if d["health"] == "warning"),
        "findings_active": len(active),
        "worst": {"severity": worst["severity"], "reason": public_reason(worst), "device": worst["device"],
                  "device_name": names.get(worst["device"], ""), "last": int(worst["last"])} if worst else None,
    }


# ── CLI ──────────────────────────────────────────────────────────────────────

_STOP = False


def _stop(*_a):
    global _STOP
    _STOP = True


def run_service(cfg):
    eng = Engine(cfg)
    os.makedirs(cfg.state_dir, exist_ok=True)
    eng.load_state()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print("devicewatch: started (%d devices, %d findings known)" % (len(eng.devices), len(eng.findings)), flush=True)
    while not _STOP:
        t0 = time.monotonic()
        try:
            eng.cycle()
        except Exception as exc:  # keep running; the next cycle retries
            print("devicewatch: cycle failed: %r" % (exc,), flush=True)
        while not _STOP and time.monotonic() - t0 < CYCLE_SECONDS:
            time.sleep(1)
    try:
        eng.save_state()
    except OSError as exc:
        print("devicewatch: final state save failed: %r" % (exc,), flush=True)
    print("devicewatch: stopped", flush=True)


def main(argv):
    cfg = Config()
    cmd = argv[0] if argv else "status"
    if cmd == "run":
        run_service(cfg)
        return 0
    if cmd == "once":
        eng = Engine(cfg)
        eng.load_state()
        eng.cycle()
        eng.save_state()
        print(json.dumps(eng.status(time.time()), indent=1))
        return 0
    if cmd == "feeds-update":
        config = read_json(cfg.conf("devicewatch.json"), {}) or {}
        only = None
        if "--only" in argv:
            i = argv.index("--only")
            only = argv[i + 1:i + 2]
        force = "--force" in argv
        try:   # "Update now" in the dashboard: a request newer than the last run
            force = force or os.stat(cfg.conf("feeds-update.request")).st_mtime > \
                (feeds.load_state(cfg.feeds_dir).get("_updated") or 0)
        except OSError:
            pass
        feeds.update_feeds(cfg.feeds_dir, cfg.conf_dir, config, force=force, only=only)
        return 0
    if cmd == "status":
        print(json.dumps(read_json(cfg.state("status.json"), {}), indent=1))
        return 0
    print(__doc__.split("\n\n")[1])
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
