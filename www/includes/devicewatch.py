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
  /opt/zeek/logs/current/{conn,dns,dhcp,software,known_hosts,ssl}.log  (group zeek)
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
  /var/lib/tuxwall/shared/wg-peers.json  WireGuard peers (public keys,
                                  allowed IPs, names) - written by the API,
                                  which runs as root; private keys never
                                  leave the API
  /etc/suricata/suricata.yaml     capture interfaces (does Suricata see the
                                  LAN at all? - status warning otherwise)
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
  shadow.json    behaviour detectors' results in shadow mode / learning
                 period (admin "Detector tuning" card only; never findings)
  engine.json    private state (checkpoints, inventory, aggregates)
  baselines.json private per-device baselines (0600, aggregates only)
  detectors.json private behaviour-detector state (0600; beaconing's
                 check-in times per device + destination, last 24 h)

Device ids: "m" + 12 hex (MAC), "w" + 16 hex (sha256 of a WireGuard public
key), "i" + 16 hex (sha256 of an address with no known MAC).

Attribution (event -> device): the MAC seen with the event wins - Zeek's
mac-logging policy (conn.log orig_l2_addr / resp_l2_addr) or Suricata's
"ether" block; otherwise the address ownership history (per IP a few
[device, first, last] intervals from leases, neighbours, DHCP and those
MACs): the most recent holder whose interval contains the event time, else
the last holder before it (up to 1 h), else the next one. A holder never
extends its interval across another device's claim, and a lease does not
count while the neighbour table shows another MAC on the address. Findings
already recorded never move to another device.

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
  Findings marked "expected" do not count, nor do silenced ones.
Silence rules (/etc/tuxwall/devices/silence.json, written by the API):
  scope "indicator" (one indicator on every device, optionally one kind),
  "device_kind" (one device + one finding kind), "suffix" (a domain and
  its subdomains, optionally one kind), "kind" (a finding kind on every
  device); optional expiry. A silenced finding is still recorded (marked
  "silenced": rule id) but counts like an expected one: no risk, no
  health, no alert event. Critical findings (c2_connection, outbound IDS
  attack responses, anything of severity critical) are only silenced by
  a rule with include_critical. silence_match() takes any finding dict,
  so Phase 2 detector kinds work unchanged.
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

Behaviour detection (Phase 2, 3.3.8): BeaconDetector (beaconing),
DnsBypassDetector (dns_bypass), ScanDetector (internal_scan; it also gets
on_lan: device -> LAN host / router flows through the router). Mode per
detector in devicewatch.json {"detectors": {name: off|shadow|on}}, default
shadow. record_behaviour(): severity capped at medium unless the result
comes with a threat-intel hit; mode on + an established baseline -> a
normal finding; otherwise a shadow row in shadow.json (reason "shadow", or
"learning" in mode on) - no health, no alert event. Expected marks and
silence rules match detector keys (the finding's indicator: destination,
provider, scan pattern) like any other indicator. Baselines (C1): see
Baselines; a device is established after LEARN_DAYS with LEARN_MIN_HOURS
active hours.
"""
import bisect
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
from array import array
from collections import Counter, OrderedDict
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
NEIGH_ACTIVE = ("REACHABLE", "DELAY", "PROBE", "PERMANENT")
WG_ONLINE_SECONDS = 180
IP_HISTORY_SECONDS = 7 * 86400
IP_HISTORY_MAX = 20000
IP_HISTORY_PER_IP = 8
IP_MERGE_SECONDS = 3600         # an observation this close extends the holder's interval
IP_TAIL_SECONDS = 3600          # the last holder keeps an address this long after its last sighting
IP_LEAD_SECONDS = 600
ZEEK_WINDOW_CYCLES = 60         # source-health counters: about the last hour
ZEEK_MIN_LINES = 200
BAD_CHECKSUM_SHARE = 0.5
UNATTR_MAX = 10000
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
    "beaconing": "Regular check-ins to a rarely used server",
    "dns_bypass": "Uses encrypted DNS that bypasses the router",
    "internal_scan": "Scanned other devices or the router",
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

# ── behaviour detection (Phase 2, 3.3.8) ────────────────────────────────────
# Every behaviour detector has a mode in devicewatch.json "detectors":
# off | shadow | on (default shadow). Shadow results - and, in mode "on",
# results for devices still in their learning period - go to a separate
# store (shadow.json), never to findings.json or events.jsonl, so they can
# not reach health, Flagged, the threat table, alerts or Home Assistant.
BEHAVIOUR_DETECTORS = ("beaconing", "dns_bypass", "internal_scan")
DETECTOR_INFO = {
    "beaconing": ("Beaconing", "Regular check-ins all day to a server few or no other devices use"),
    "dns_bypass": ("DNS bypass", "Encrypted DNS (DoH, DoT, DoQ) to public resolvers instead of the router"),
    "internal_scan": ("Internal scanning", "One device probing many LAN hosts, or many ports on one host or the router"),
}
DETECTOR_MODES = ("off", "shadow", "on")
DETECTOR_DEFAULT_MODE = "shadow"
BEHAVIOUR_SEV_CAP = "medium"        # unless combined with a threat-intel hit
MAX_SHADOW = 5000
SHADOW_DAYS_KEPT = 8
LEARN_DAYS = 7                      # a baseline is "established" after 7 days ...
LEARN_MIN_HOURS = 24                # ... with at least this many active hours
BASELINE_DAYS = 30
BASELINE_PORTS_MAX = 128
BASELINE_COUNTRIES_MAX = 64
SNI_MAX = 50000

EXT, LAN, OWN, SKIP = 0, 1, 2, 3
SINKHOLES = frozenset(("0.0.0.0", "::", "127.0.0.1", "::1"))
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
BLOCK_ACTIONS = ("always_nxdomain", "always_refuse", "always_null", "refuse", "deny", "inform_deny",
                 "always_deny", "redirect")
UNBOUND_LOCAL_RE = re.compile(r"info:\s+\S+\s+(%s)\s+([0-9A-Fa-f:.]+)@\d+\s+(\S+)\s+\S+\s+IN"
                              % "|".join(BLOCK_ACTIONS))
# Zeek ssl.log (JSON): the two fields the engine needs, without a full parse
SSL_NAME_RE = re.compile(rb'"server_name":"([A-Za-z0-9._-]{1,253})"')
SSL_RESP_RE = re.compile(rb'"id\.resp_h":"([0-9A-Fa-f:.]{2,45})"')
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
        # in a directory: the unit maps the directory, so the API's atomic
        # rewrites (a new inode each time) stay visible to the running engine
        self.wg_snapshot = p("/var/lib/tuxwall/shared/wg-peers.json")
        self.wg_snapshot_legacy = p("/var/lib/tuxwall/wg-peers.json")
        self.geo_db = p("/var/lib/tuxwall/dbip-city-lite.mmdb")
        self.suricata_conf = p("/etc/suricata/suricata.yaml")

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


def stale_leases(leases, neigh_active, iface_of):
    """IPv4 addresses of leases that are not the MAC's address now (DW-13): a
    MAC with several active leases on one network (a new client id got a
    new address, the old lease runs out later) holds the one the neighbour
    table sees in use - or, with no neighbour entry, the newest lease."""
    groups = {}
    for le in leases:
        if not le.get("v6"):
            groups.setdefault((le["mac"], iface_of(le["ip"])), []).append(le)
    active_on = {}
    for mac, ip in neigh_active:
        if ":" not in ip:
            active_on.setdefault((mac, iface_of(ip)), set()).add(ip)
    out = set()
    for key, group in groups.items():
        if len(group) < 2:
            continue
        live = active_on.get(key) or set()
        if live:
            out.update(le["ip"] for le in group if le["ip"] not in live)
        else:
            best = max(group, key=lambda le: (le["cltt"] or 0, le["expire"] or 0, le["ip"]))
            out.update(le["ip"] for le in group if le is not best)
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


def suricata_capture(path):
    """Interfaces Suricata captures (the af-packet section of suricata.yaml
    - TuxWall's capture mode - without the "default" template), or None if
    unreadable."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read(8 << 20)
    except OSError:
        return None
    out = []
    for sec in ("af-packet",):
        m = re.search(r"^%s:[ \t]*\n(.*?)(?=^\S)" % sec, text + "\n~:\n", re.M | re.S)
        if m:
            for x in re.findall(r"^\s*-\s*interface:\s*(\S+)", m.group(1), re.M):
                x = x.strip("\"'")
                if x and x != "default" and x not in out:
                    out.append(x)
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
                 "bytes_in", "bytes_out", "service", "established", "duration", "to_router")


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
    their own bounded state and are added to Engine(detectors=...).
    Behaviour detectors (behaviour = True) also get on_lan (device -> LAN
    host / router flows that pass the router); their specs go through
    Engine.record_behaviour (mode, learning period, severity cap) and they
    may keep state across restarts (state_to_json / state_from_json)."""
    name = "detector"
    behaviour = False

    def on_conn(self, eng, ev):
        return ()

    def on_lan(self, eng, ev):
        return ()

    def stats(self):
        return {}

    def state_to_json(self, now):
        return None

    def state_from_json(self, data, now):
        pass

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
        if not (ev.answered or ev.blocked):
            return ()
        hits = eng.intel.match_domain(ev.query)
        if not hits:
            return ()
        out = []
        for feed, meta, matched in hits:
            if ev.answered:
                kind = "dns_lookup"
                eng.dns_hot_add(ev.device, ev.answers, feed, meta, matched, ev.ts)
            else:
                # Zeek and the unbound journal both see a blocked lookup (and a
                # client asks A + AAAA, often with a retry): count it once
                if eng._dup(("q", ev.dev_ip, ev.query), ev.ts, 10.0):
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


# ── behaviour detectors: curated lists ──────────────────────────────────────

def detector_modes(config):
    """{detector: off|shadow|on} from devicewatch.json (default shadow)."""
    raw = config.get("detectors") if isinstance(config, dict) else None
    raw = raw if isinstance(raw, dict) else {}
    return {n: raw[n] if raw.get(n) in DETECTOR_MODES else DETECTOR_DEFAULT_MODE for n in BEHAVIOUR_DETECTORS}


def name_in(name, suffixes):
    """True when host name `name` is one of `suffixes` or a subdomain of one."""
    d = str(name or "").lower().rstrip(".")
    while d:
        if d in suffixes:
            return True
        _, _, d = d.partition(".")
    return False


# Addresses that are never a beacon's target: private networks beyond the
# LAN prefixes (an ISP modem's status page, a site-to-site peer), CGNAT,
# link-local. Documentation ranges count as internet (tests and the lab).
_LOCALISH_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"))
_LOCALISH = {}


def localish_ip(ip):
    v = _LOCALISH.get(ip)
    if v is None:
        try:
            a = ipaddress.ip_address(ip)
            v = any(a.version == n.version and a in n for n in _LOCALISH_NETS)
        except ValueError:
            v = True
        if len(_LOCALISH) > 65536:
            _LOCALISH.clear()
        _LOCALISH[ip] = v
    return v


# Well-known periodic services (D1): time, OS updates and telemetry, push
# and connectivity checks, Home Assistant cloud, big media/messaging apps
# and common smart-home clouds. Each entry covers its subdomains; the
# shared platforms of devicewatch_feeds (google.com, apple.com, microsoft.com
# ...) are allowed as well. Deliberately NOT here: generic hosting/CDN
# names (amazonaws.com, cloudfront.net, azurewebsites.net, workers.dev) -
# malware C2 lives there too.
BEACON_ALLOW = frozenset((
    # time
    "ntp.org", "time.apple.com", "time.windows.com", "time.google.com", "time.cloudflare.com", "ntp.ubuntu.com",
    # Apple
    "push.apple.com", "mzstatic.com", "apple-dns.net", "aaplimg.com", "cdn-apple.com", "apple-cloudkit.com",
    "icloud-content.com", "itunes.apple.com",
    # Google / Android
    "gstatic.com", "googleapis.com", "1e100.net", "googleusercontent.com", "gvt1.com", "gvt2.com",
    "android.com", "googlesyndication.com", "doubleclick.net", "google-analytics.com", "app-measurement.com",
    "crashlytics.com", "firebaseio.com", "googletagmanager.com", "nest.com", "home.nest.com",
    # Microsoft / Windows / Xbox
    "windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "events.data.microsoft.com",
    "telemetry.microsoft.com", "msftconnecttest.com", "msftncsi.com", "wns.windows.com", "notify.windows.com",
    "windows.com", "msn.com", "bing.com", "skype.com", "office365.com", "office.net", "msedge.net",
    "azureedge.net", "trafficmanager.net", "xboxlive.com", "microsoftonline.com", "sharepoint.com",
    # Linux distributions, browsers
    "ubuntu.com", "canonical.com", "snapcraft.io", "launchpad.net", "debian.org", "fedoraproject.org",
    "gnome.org", "kde.org", "mozilla.com", "mozilla.net", "mozilla.org", "firefox.com", "brave.com",
    "opera.com", "duckduckgo.com",
    # Home Assistant
    "nabucasa.com", "nabu.casa", "home-assistant.io",
    # media, messaging, gaming
    "netflix.com", "nflxvideo.net", "nflxso.net", "spotify.com", "scdn.co", "spotifycdn.com", "whatsapp.net",
    "whatsapp.com", "signal.org", "zoom.us", "slack.com", "plex.tv", "plex.direct", "roku.com",
    "playstation.net", "playstation.com", "nintendo.net", "nintendo.com", "sonos.com", "twitch.tv",
    "disneyplus.com", "dssott.com", "hulu.com", "primevideo.com", "amazonvideo.com",
    # smart-home clouds
    "meethue.com", "tuyaus.com", "tuyaeu.com", "tuyacn.com", "tuya.com", "shelly.cloud", "coolkit.cc",
    "ring.com", "ecobee.com", "smartthings.com", "meross.com", "wyze.com", "tplinkcloud.com", "tp-link.com",
    "alexa.amazon.com", "amazonalexa.com", "a2z.com", "amazon-dss.com", "media-amazon.com",
    # security vendors / VPN keepalives
    "tailscale.com", "tailscale.io",
))
BEACON_SKIP_PORTS = frozenset((53, 67, 68, 123, 137, 138, 853, 1900, 5353))

# Public DoH / DoT / DoQ resolvers (D2), curated Nov 2026 - no refresh: a
# connection to one of these addresses on 443 (DoH) or anything on 853
# (DoT/DoQ), or to an address the DNS answered for one of the host names.
DOH_PROVIDERS = {
    "cloudflare": ("Cloudflare", (
        "cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com"), (
        "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", "162.159.36.1", "162.159.46.1",
        "104.16.248.249", "104.16.249.249", "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2606:4700:4700::1112", "2606:4700:4700::1002", "2606:4700:4700::1113", "2606:4700:4700::1003",
        "2606:4700::6810:f8f9", "2606:4700::6810:f9f9")),
    "google": ("Google Public DNS", ("dns.google", "dns.google.com", "dns64.dns.google", "8888.google"), (
        "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844", "2001:4860:4860::6464",
        "2001:4860:4860::64")),
    "quad9": ("Quad9", ("dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "dns12.quad9.net"), (
        "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11", "9.9.9.12",
        "149.112.112.12", "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11",
        "2620:fe::fe:11", "2620:fe::12", "2620:fe::fe:12")),
    "nextdns": ("NextDNS", ("dns.nextdns.io", "nextdns.io"), ("45.90.28.0/24", "45.90.30.0/24", "2a07:a8c0::/32",
                                                               "2a07:a8c1::/32")),
    "adguard": ("AdGuard DNS", ("dns.adguard-dns.com", "adguard-dns.com", "dns.adguard.com", "dns-family.adguard.com",
                                "dns-unfiltered.adguard.com"), (
        "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16", "94.140.14.140", "94.140.14.141",
        "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff", "2a10:50c0::1:ff",
        "2a10:50c0::2:ff")),
    "opendns": ("OpenDNS (Cisco)", ("doh.opendns.com", "doh.familyshield.opendns.com", "doh.umbrella.com"), (
        "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123", "2620:119:35::35",
        "2620:119:53::53", "2620:119:35::123", "2620:119:53::123")),
    "mullvad": ("Mullvad DNS", ("dns.mullvad.net",), ("194.242.2.0/24", "2a07:e340::/32")),
    "controld": ("Control D", ("controld.com", "freedns.controld.com"), ("76.76.2.0/24", "76.76.10.0/24",
                                                                         "2606:1a40::/32")),
    "cleanbrowsing": ("CleanBrowsing", ("doh.cleanbrowsing.org",), (
        "185.228.168.9", "185.228.169.9", "185.228.168.10", "185.228.169.11", "185.228.168.168",
        "185.228.169.168", "2a0d:2a00:1::", "2a0d:2a00:2::")),
    "dnssb": ("DNS.SB", ("doh.dns.sb", "doh.sb", "dot.sb"), ("185.222.222.222", "45.11.45.11", "2a09::", "2a11::")),
    "yandex": ("Yandex DNS", ("common.dot.dns.yandex.net", "dns.yandex.ru"), ("77.88.8.8", "77.88.8.1", "77.88.8.88",
                                                                           "77.88.8.2", "2a02:6b8::feed:0ff")),
    "alidns": ("AliDNS", ("dns.alidns.com",), ("223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1")),
    "comcast": ("Xfinity DoH", ("doh.xfinity.com",), ()),
}
PROVIDER_TITLES = {k: v[0] for k, v in DOH_PROVIDERS.items()}
PROVIDER_TITLES["unlisted"] = "an unlisted DoT/DoQ server"
_DOH_IP = {}
_DOH_NETS = []
_DOH_HOSTS = {}
for _pk, (_t, _hosts, _addrs) in DOH_PROVIDERS.items():
    for _h in _hosts:
        _DOH_HOSTS[_h] = _pk
    for _a in _addrs:
        if "/" in _a:
            _DOH_NETS.append((ipaddress.ip_network(_a), _pk))
        else:
            _DOH_IP[ipaddress.ip_address(_a).compressed] = _pk
# device types whose own DoH (a browser's "secure DNS", the system's private
# DNS) is informational only; IoT and unknown devices get medium
DNS_BYPASS_QUIET_TYPES = frozenset(("computer", "nas", "phone", "tablet", "vpn-client"))


_DOH_CACHE = {}


def doh_provider(ip, name=""):
    """Provider key of a public DoH/DoT resolver address (or of the host
    name the DNS answered for it), else None."""
    key = (ip, name)
    try:
        return _DOH_CACHE[key]
    except KeyError:
        pass
    p = _doh_provider(ip, name)
    if len(_DOH_CACHE) > 50000:
        _DOH_CACHE.clear()
    _DOH_CACHE[key] = p
    return p


def _doh_provider(ip, name):
    p = _DOH_IP.get(ip)
    if p:
        return p
    if _DOH_NETS:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            a = None
        if a is not None:
            for net, key in _DOH_NETS:
                if a.version == net.version and a in net:
                    return key
    d = str(name or "").lower().rstrip(".")
    while d:
        p = _DOH_HOSTS.get(d)
        if p:
            return p
        _, _, d = d.partition(".")
    return None


# The router's own services in normal use (D3 ignores device -> router flows
# to these): DNS, DHCP/DHCPv6, NTP, the dashboard (HTTP/HTTPS), DoT to the
# router, mDNS/SSDP.
ROUTER_SERVICES = frozenset((("udp", 53), ("tcp", 53), ("udp", 67), ("udp", 68), ("udp", 547), ("udp", 546),
                             ("udp", 123), ("tcp", 80), ("tcp", 443), ("udp", 443), ("tcp", 853), ("udp", 853),
                             ("udp", 5353), ("udp", 1900)))


def _median(xs):
    s = sorted(xs)
    n = len(s)
    if not n:
        return 0
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def _fmt_interval(sec):
    sec = int(round(sec))
    if sec < 120:
        return "%d s" % sec
    if sec < 7200:
        return "%d min" % round(sec / 60.0)
    return "%.1f h" % (sec / 3600.0)


class BeaconDetector(Detector):
    """D1: regular check-ins. Per device + destination (the TLS server name
    or DNS name the destination address was answered for, else the
    address) the start times of its connections over 24 h; check-ins closer
    than COLLAPSE seconds count once. Every EVAL seconds each pair with at
    least MIN_CHECKINS check-ins over at least MIN_SPAN is scored:
        0.45 x interval regularity (1 - MAD/median / 0.25, floored at 0)
      + 0.35 x share of intervals within 20 % of the median
      + 0.20 x request-size regularity (1 - MAD/median of bytes sent)
    minus 0.05 when a second device uses the destination. Destinations used
    by FLEET_COMMON devices or more, the curated BEACON_ALLOW list, the
    shared platforms, DNS/NTP/mDNS ports and private addresses never count.
    Severity low; medium for score >= 0.9 to a destination no other device
    uses; high when the destination is also on a threat list. A pair is
    reported at most every REPORT_EVERY seconds. Key: the destination."""
    name = "beaconing"
    behaviour = True
    WINDOW = 86400
    COLLAPSE = 10
    EVAL = 600
    MIN_CHECKINS = 24
    MIN_SPAN = 6 * 3600
    SCORE_MIN = 0.8
    MAX_PAIRS = 40000
    MAX_POINTS = 3000
    REPORT_EVERY = 6 * 3600
    PAIR_EVAL = 3600
    SAVE_MIN_POINTS = 6

    def __init__(self):
        self.pairs = {}         # (device, dest) -> [times array, sizes array, last peer, last port, proto, reported]
        self.allow = {}
        self.last_eval = 0
        self.last = {"candidates": 0, "scored": 0, "reported": 0}

    def allowed(self, dest):
        a = self.allow.get(dest)
        if a is None:
            a = name_in(dest, BEACON_ALLOW) or feeds.shared_platform(dest)
            if len(self.allow) > 50000:
                self.allow.clear()
            self.allow[dest] = a
        return a

    def on_conn(self, eng, ev):
        if not ev.outbound or not ev.device or ev.proto not in ("tcp", "udp") or ev.peer_port in BEACON_SKIP_PORTS:
            return ()
        if localish_ip(ev.peer):
            return ()
        name = eng.dest_name(ev.peer)
        dest = name or ev.peer
        if self.allowed(dest) or doh_provider(ev.peer, name):    # DNS over HTTPS is periodic by nature (D2)
            return ()
        t = int(ev.ts)
        size = min(max(0, int(ev.bytes_out or 0)), 0xffffffff)
        key = (ev.device, dest)
        p = self.pairs.get(key)
        if p is None:
            if len(self.pairs) >= self.MAX_PAIRS:
                self._shrink(t)
            self.pairs[key] = [array("I", [t]), array("I", [size]), ev.peer, ev.peer_port, ev.proto, 0, 0, 0]
            return ()
        times = p[0]
        if abs(t - times[-1]) < self.COLLAPSE:
            return ()
        if len(times) >= self.MAX_POINTS:
            self._trim(p, t - self.WINDOW)
            if len(times) >= self.MAX_POINTS:
                del p[0][:self.MAX_POINTS // 4]
                del p[1][:self.MAX_POINTS // 4]
        p[0].append(t)
        p[1].append(size)
        p[2], p[3], p[4] = ev.peer, ev.peer_port, ev.proto
        return ()

    @staticmethod
    def _trim(p, cut):
        if p[0] and min(p[0]) < cut:
            keep = [(t, s) for t, s in zip(p[0], p[1]) if t >= cut]
            p[0] = array("I", [t for t, _s in keep])
            p[1] = array("I", [s for _t, s in keep])

    def _shrink(self, now):
        cut = now - self.WINDOW
        for k in [k for k, p in self.pairs.items() if max(p[0]) < cut]:
            del self.pairs[k]
        if len(self.pairs) >= self.MAX_PAIRS:
            for k in sorted(self.pairs, key=lambda k: (len(self.pairs[k][0]), self.pairs[k][0][-1]))[:self.MAX_PAIRS // 5]:
                del self.pairs[k]

    def score(self, times, sizes, floor=0.0):
        """(score, details) of one pair's check-ins (sorted, collapsed; the
        sizes in any order), or None when there are too few, they span too
        little time or the timing alone cannot reach `floor`."""
        n = len(times)
        if n < self.MIN_CHECKINS or times[-1] - times[0] < self.MIN_SPAN:
            return None
        iv = sorted(b - a for a, b in zip(times, times[1:]))
        k = len(iv)
        m = iv[k // 2] if k % 2 else (iv[k // 2 - 1] + iv[k // 2]) / 2.0
        if m <= 0:
            return None
        tol = max(2.0, 0.2 * m)
        share = (bisect.bisect_right(iv, m + tol) - bisect.bisect_left(iv, m - tol)) / float(k)
        if 0.45 + 0.35 * share + 0.2 < floor:
            return None
        mad = _median([abs(x - m) for x in iv])
        jitter = mad / m
        s_jit = max(0.0, 1.0 - jitter / 0.25)
        timing = 0.45 * s_jit + 0.35 * share
        if timing + 0.2 < floor:
            return None
        sm = _median(sizes)
        s_size = 1.0 - min(1.0, _median([abs(s - sm) for s in sizes]) / sm) if sm else 0.5
        sc = timing + 0.2 * s_size
        return sc, {"interval_s": int(round(m)), "jitter": round(jitter, 3), "regular_share": round(share, 2),
                    "checkins": n, "span_h": round((times[-1] - times[0]) / 3600.0, 1), "score": round(sc, 2)}

    def on_cycle(self, eng, now):
        if now - self.last_eval < self.EVAL:
            return ()
        self.last_eval = now
        cut = now - self.WINDOW
        fleet, devs, cands = {}, set(), []
        for key in list(self.pairs):
            p = self.pairs[key]
            self._trim(p, cut)
            if not p[0]:
                del self.pairs[key]
                continue
            devs.add(key[0])
            if len(p[0]) >= 4:
                fleet[key[1]] = fleet.get(key[1], 0) + 1
            if len(p[0]) >= self.MIN_CHECKINS:
                cands.append(key)
        common = max(3, int(math.ceil(0.1 * len(devs))))
        out = []
        scored = 0
        for key in cands:
            did, dest = key
            users = fleet.get(dest, 1)
            if users >= common:
                continue
            p = self.pairs[key]
            # each pair at most every PAIR_EVAL seconds, and only with new check-ins
            if len(p[0]) == p[6] or now - p[7] < self.PAIR_EVAL or now - p[5] < self.REPORT_EVERY:
                continue
            p[6], p[7] = len(p[0]), now
            st = sorted(p[0])
            times = st[:1] + [b for a, b in zip(st, st[1:]) if b - a >= self.COLLAPSE]
            res = self.score(times, p[1], self.SCORE_MIN)
            if res is None:
                continue
            scored += 1
            sc, det = res
            if users > 1:
                sc -= 0.05
                det["score"] = round(sc, 2)
            if sc < self.SCORE_MIN:
                continue
            p[5] = now
            is_ip = dest == p[2]
            intel = bool(eng.intel.match_ip(p[2]) or (not is_ip and eng.intel.match_domain(dest)))
            sev = "high" if intel else ("medium" if sc >= 0.9 and users == 1 else "low")
            det.update(devices=users, peer=p[2], port=p[3], proto=p[4])
            if intel:
                det["intel"] = True
            out.append(({"kind": "beaconing", "indicator": dest, "indicator_type": "ip" if is_ip else "domain",
                         "severity": sev, "intel": intel,
                         "title": "Regular check-ins every %s to %s" % (_fmt_interval(det["interval_s"]), dest),
                         "source": "beaconing", "details": det}, did, times[-1]))
        self.last = {"candidates": len(cands), "scored": scored, "reported": len(out)}
        return out

    def stats(self):
        return dict(self.last, pairs=len(self.pairs), last_eval=int(self.last_eval))

    def state_to_json(self, now):
        cut = now - self.WINDOW
        rows = []
        for (did, dest), p in self.pairs.items():
            pts = [(t, s) for t, s in zip(p[0], p[1]) if t >= cut]
            if len(pts) < self.SAVE_MIN_POINTS:
                continue
            t0 = pts[0][0]
            rows.append([did, dest, t0, [t - t0 for t, _s in pts], [s for _t, s in pts], p[2], p[3], p[4], int(p[5])])
        return {"v": 1, "pairs": rows, "last_eval": int(self.last_eval)}

    def state_from_json(self, data, now):
        if not isinstance(data, dict) or data.get("v") != 1:
            return
        cut = now - self.WINDOW
        for row in data.get("pairs") or []:
            try:
                did, dest, t0, dts, sizes, peer, port, proto, rep = row
                pts = [(int(t0) + int(d), int(s)) for d, s in zip(dts, sizes) if int(t0) + int(d) >= cut]
            except (TypeError, ValueError):
                continue
            if not pts or not DEVICE_ID_RE.match(str(did)) or len(self.pairs) >= self.MAX_PAIRS:
                continue
            self.pairs[(did, str(dest)[:255])] = [array("I", [t for t, _s in pts]),
                                                  array("I", [min(max(0, s), 0xffffffff) for _t, s in pts]),
                                                  str(peer), port, str(proto), int(rep or 0), 0, 0]


class DnsBypassDetector(Detector):
    """D2: a device uses its own encrypted DNS - a completed connection to a
    public DoH resolver on 443 (TCP, or UDP = DoH over QUIC), or anything on
    853 (DoT over TCP, DoQ over UDP) - instead of the router's resolver.
    Severity info for computers, phones/tablets and VPN peers (a browser's
    secure DNS), medium for IoT and unknown devices. Key: the provider."""
    name = "dns_bypass"
    behaviour = True
    REPORT_EVERY = 600

    def __init__(self):
        self.last_seen = {}     # (device, provider, 10-min bucket) -> ts
        self.seen = 0

    def on_conn(self, eng, ev):
        port = ev.peer_port
        if port not in (443, 853) or not ev.outbound or not ev.device or not ev.established:
            return ()
        name = eng.dest_name(ev.peer)
        prov = doh_provider(ev.peer, name)
        if port == 853:
            proto = "DoQ" if ev.proto == "udp" else "DoT"
            prov = prov or "unlisted"
        elif prov:
            proto = "DoH over QUIC" if ev.proto == "udp" else "DoH"
        else:
            return ()
        key = (ev.device, prov, int(ev.ts // self.REPORT_EVERY))     # once per device, provider and 10 min
        if key in self.last_seen:
            return ()
        if len(self.last_seen) > 20000:
            self.last_seen.clear()
        self.last_seen[key] = ev.ts
        self.seen += 1
        typ = eng.device_type(ev.device)
        sev = "info" if typ in DNS_BYPASS_QUIET_TYPES else "medium"
        return ({"kind": "dns_bypass", "indicator": prov, "indicator_type": "provider", "severity": sev,
                 "title": "Encrypted DNS (%s) to %s, not the router's resolver" % (proto, PROVIDER_TITLES.get(prov, prov)),
                 "source": "dns_bypass",
                 "details": {"protocol": proto, "peer": ev.peer, "port": port, "server": name or "",
                             "device_type": typ}},)

    def stats(self):
        return {"uses": self.seen}


class ScanDetector(Detector):
    """D3: internal scanning. Device -> LAN host / router flows that pass the
    router (VLAN <-> LAN, VPN <-> LAN, device -> router ports; the router's
    own services in normal use are ignored before this detector sees them).
    Within WINDOW seconds, one device contacting >= HOSTS distinct hosts
    with mostly failed attempts (or >= HOSTS_ANY hosts at all), or >= PORTS
    distinct ports on one host with mostly failed attempts (or >= PORTS_ANY
    ports at all). Severity medium. Key: the pattern - "hosts:<proto>/<most
    tried port>" or "ports:<host>" ("ports:router" for the router)."""
    name = "internal_scan"
    behaviour = True
    WINDOW = 600
    HOSTS = 20
    HOSTS_ANY = 64
    PORTS = 15
    PORTS_ANY = 100
    FAILED_SHARE = 0.5
    MAX_EVENTS = 4096
    REPORT_EVERY = 3600

    def __init__(self):
        self.ev = {}            # device -> [(ts, host, port, proto, failed)]
        self.dirty = set()
        self.reported = {}
        self.flows = 0

    def on_lan(self, eng, ev):
        """Collects the device's flows; when the oldest one leaves the window
        (or the list is full) the window so far is evaluated and the older
        half dropped - consecutive windows overlap by WINDOW / 2, so a scan
        shorter than that is always seen whole, also in a log backlog."""
        if not ev.device:
            return ()
        lst = self.ev.get(ev.device)
        if lst is None:
            if len(self.ev) >= MAX_DEVICES:
                return ()
            lst = self.ev[ev.device] = []
        out = ()
        if lst and (ev.ts - lst[0][0] > self.WINDOW or len(lst) >= self.MAX_EVENTS):
            out = [spec for spec, _ts in self._report(ev.device, lst)]
            cut = ev.ts - self.WINDOW / 2
            lst[:] = [x for x in lst if x[0] >= cut][-(self.MAX_EVENTS // 2):]
        lst.append((ev.ts, "router" if ev.to_router else ev.peer, ev.peer_port, ev.proto, not ev.established))
        self.flows += 1
        self.dirty.add(ev.device)
        return out

    def _report(self, did, lst):
        """[(spec, ts)] for the scan patterns in lst not reported in the last
        REPORT_EVERY seconds (by log time)."""
        out = []
        if not lst:
            return out
        last = max(x[0] for x in lst)
        for key, det in self.evaluate(lst):
            rk = (did, key)
            prev = self.reported.get(rk)
            if prev is not None and abs(last - prev) < self.REPORT_EVERY:
                continue
            self.reported[rk] = last
            if det["pattern"] == "hosts":
                title = "Contacted %d devices in %d min (%s)" % (det["hosts"], det["window_min"], key[6:])
            else:
                title = "Tried %d ports on %s in %d min" % (
                    det["ports"], "the router" if det["target"] == "router" else det["target"], det["window_min"])
            out.append(({"kind": "internal_scan", "indicator": key, "indicator_type": "pattern",
                         "severity": "medium", "title": title, "source": "internal_scan", "details": det}, last))
        return out

    def evaluate(self, lst):
        """[(key, details)] of the scan patterns in one device's recent flows."""
        if not lst:
            return []
        end = max(x[0] for x in lst)
        cur = [x for x in lst if x[0] >= end - self.WINDOW]
        hosts, ports = {}, {}
        failed = 0
        for ts, host, port, proto, bad in cur:
            hosts.setdefault(host, [0, 0])
            hosts[host][0] += 1
            hosts[host][1] += bad
            failed += bad
            ports.setdefault(host, {})
            pk = "icmp" if proto == "icmp" else "%s/%s" % (proto, port)
            ports[host][pk] = ports[host].get(pk, 0) + 1
        out = []
        share = failed / float(len(cur))
        if (len(hosts) >= self.HOSTS and share >= self.FAILED_SHARE) or len(hosts) >= self.HOSTS_ANY:
            tried = {}
            for h in ports.values():
                for pk in h:
                    tried[pk] = tried.get(pk, 0) + 1
            top = sorted(tried.items(), key=lambda kv: (-kv[1], kv[0]))
            out.append(("hosts:" + top[0][0], {"pattern": "hosts", "hosts": len(hosts), "attempts": len(cur),
                                                 "failed_share": round(share, 2), "window_min": self.WINDOW // 60,
                                                 "top_ports": [k for k, _n in top[:5]]}))
        for host, pmap in ports.items():
            n, bad = hosts[host]
            fs = bad / float(n)
            if (len(pmap) >= self.PORTS and fs >= self.FAILED_SHARE) or len(pmap) >= self.PORTS_ANY:
                out.append(("ports:" + host, {"pattern": "ports", "target": host, "ports": len(pmap), "attempts": n,
                                              "failed_share": round(fs, 2), "window_min": self.WINDOW // 60,
                                              "sample_ports": sorted(pmap, key=lambda k: -pmap[k])[:8]}))
        return out

    def on_cycle(self, eng, now):
        out = []
        for did in self.dirty:
            for spec, ts in self._report(did, self.ev.get(did) or []):
                out.append((spec, did, ts))
        self.dirty.clear()
        if len(self.reported) > 20000:
            self.reported = {k: v for k, v in self.reported.items() if now - v < self.REPORT_EVERY}
        for did in [d for d, lst in self.ev.items() if not lst or max(x[0] for x in lst) < now - 4 * self.WINDOW]:
            del self.ev[did]
        return out

    def stats(self):
        return {"flows": self.flows, "devices": len(self.ev)}


def behaviour_detectors():
    return [BeaconDetector(), DnsBypassDetector(), ScanDetector()]


# ── per-device baselines (C1) ───────────────────────────────────────────────

_ENTROPY_CACHE = {}


def label_entropy(q):
    """Shannon entropy (bits per character) of the first label of a name."""
    lab = q.split(".", 1)[0]
    e = _ENTROPY_CACHE.get(lab)
    if e is None:
        n = float(len(lab))
        e = -sum(c / n * math.log2(c / n) for c in Counter(lab).values()) if lab else 0.0
        if len(_ENTROPY_CACHE) > 20000:
            _ENTROPY_CACHE.clear()
        _ENTROPY_CACHE[lab] = e
    return e


class Baselines:
    """Per-device behaviour baselines: aggregates only, never a destination.
    Per device: learning start, active hours (hours with at least one
    connection), established (>= LEARN_DAYS since start and >=
    LEARN_MIN_HOURS active hours), up to BASELINE_DAYS daily buckets
    {in, out, n (flows), h (active hours), dst (distinct destinations,
    estimated), pt / ct (distinct ports / countries), q / nx (DNS queries /
    NXDOMAIN), ent (first-label entropy histogram, 8 one-bit bins)} and the
    ports / countries ever used with the day last seen (bounded). Devices
    not seen for BASELINE_DAYS start learning again."""
    SKETCH_BITS = 2048

    def __init__(self):
        self.devs = {}
        self.cur = {}           # device -> [day, sketch bytearray, ports set, countries set]

    def _rec(self, did, ts):
        b = self.devs.get(did)
        if b is None:
            if len(self.devs) >= MAX_DEVICES:
                return None
            b = self.devs[did] = {"start": int(ts), "hours": 0, "lh": 0, "est": 0, "last": int(ts),
                                  "days": {}, "ports": {}, "cty": {}}
        return b

    @staticmethod
    def _bucket(b, day):
        rows = b["days"]
        r = rows.get(day)
        if r is None:
            r = rows[day] = {"in": 0, "out": 0, "n": 0, "h": 0, "dst": 0, "pt": 0, "ct": 0, "q": 0, "nx": 0,
                             "ent": [0] * 8}
            while len(rows) > BASELINE_DAYS + 1:
                del rows[min(rows)]
        return r

    def _cur(self, did, day):
        c = self.cur.get(did)
        if c is None or c[0] != day:
            if c is not None and c[0] > day:
                return None             # a late line of an earlier day: no distinct counts
            c = self.cur[did] = [day, bytearray(self.SKETCH_BITS // 8), set(), set()]
        return c

    def flow(self, did, ts, peer, b_in, b_out, iso, port):
        b = self._rec(did, ts)
        if b is None:
            return
        day = int(ts // 86400)
        r = self._bucket(b, day)
        r["in"] += b_in
        r["out"] += b_out
        r["n"] += 1
        h = int(ts // 3600)
        if h > b["lh"]:
            b["lh"] = h
            b["hours"] += 1
            r["h"] += 1
        if ts > b["last"]:
            b["last"] = int(ts)
        c = self._cur(did, day)
        if c is None:
            return
        x = zlib.crc32(peer.encode("utf-8")) % self.SKETCH_BITS
        c[1][x >> 3] |= 1 << (x & 7)
        if port and len(c[2]) < 256:
            c[2].add(port)
        if iso and len(c[3]) < 64:
            c[3].add(iso)
        if port:
            pm = b["ports"]
            k = str(port)
            if k not in pm and len(pm) >= BASELINE_PORTS_MAX:
                del pm[min(pm, key=pm.get)]
            pm[k] = day
        if iso and iso != "??":
            cm = b["cty"]
            if iso not in cm and len(cm) >= BASELINE_COUNTRIES_MAX:
                del cm[min(cm, key=cm.get)]
            cm[iso] = day

    def dns(self, did, ts, q, rcode):
        b = self._rec(did, ts)
        if b is None:
            return
        r = self._bucket(b, int(ts // 86400))
        r["q"] += 1
        if rcode == "NXDOMAIN":
            r["nx"] += 1
        r["ent"][min(7, int(label_entropy(q)))] += 1

    def fold(self):
        """Distinct counts of the current days into their buckets."""
        for did, (day, sk, pts, cts) in self.cur.items():
            b = self.devs.get(did)
            r = b["days"].get(day) if b else None
            if r is None:
                continue
            zeros = self.SKETCH_BITS - int.from_bytes(sk, "big").bit_count()
            r["dst"] = self.SKETCH_BITS * 4 if zeros == 0 else int(round(-self.SKETCH_BITS * math.log(zeros / float(self.SKETCH_BITS))))
            r["pt"], r["ct"] = len(pts), len(cts)

    def established(self, did, now):
        b = self.devs.get(did)
        if b is None:
            return False
        if b["est"]:
            return True
        if now - b["start"] >= LEARN_DAYS * 86400 and b["hours"] >= LEARN_MIN_HOURS:
            b["est"] = int(now)
            return True
        return False

    def prune(self, now):
        cut_day = int(now // 86400) - BASELINE_DAYS
        for did in [d for d, b in self.devs.items() if b["last"] < now - BASELINE_DAYS * 86400]:
            del self.devs[did]
            self.cur.pop(did, None)
        for b in self.devs.values():
            for d in [d for d in b["days"] if d < cut_day]:
                del b["days"][d]
            for m in (b["ports"], b["cty"]):
                for k in [k for k, v in m.items() if v < cut_day]:
                    del m[k]
        for did in [d for d, c in self.cur.items() if c[0] < cut_day or d not in self.devs]:
            del self.cur[did]

    def counts(self, now):
        est = sum(1 for d in self.devs if self.established(d, now))
        return {"devices": len(self.devs), "established": est, "learning": len(self.devs) - est,
                "learn_days": LEARN_DAYS, "learn_min_hours": LEARN_MIN_HOURS}

    def to_json(self):
        self.fold()
        devs = {}
        for did, b in self.devs.items():
            devs[did] = dict(b, days={str(k): v for k, v in b["days"].items()})
        cur = {did: [c[0], c[1].hex(), sorted(c[2]), sorted(c[3])] for did, c in self.cur.items()}
        return {"schema": 1, "devices": devs, "cur": cur}

    def from_json(self, data):
        if not isinstance(data, dict) or data.get("schema") != 1:
            return False
        for did, b in (data.get("devices") or {}).items():
            if not DEVICE_ID_RE.match(str(did)) or not isinstance(b, dict) or len(self.devs) >= MAX_DEVICES:
                continue
            try:
                days = {}
                for k, v in (b.get("days") or {}).items():
                    r = {f: int(v.get(f) or 0) for f in ("in", "out", "n", "h", "dst", "pt", "ct", "q", "nx")}
                    ent = [int(x) for x in (v.get("ent") or [])][:8]
                    r["ent"] = ent + [0] * (8 - len(ent))
                    days[int(k)] = r
                rec = {"start": int(b["start"]), "hours": int(b.get("hours") or 0), "lh": int(b.get("lh") or 0),
                       "est": int(b.get("est") or 0), "last": int(b.get("last") or b["start"]),
                       "days": dict(sorted(days.items())[-(BASELINE_DAYS + 1):]),
                       "ports": {str(k): int(v) for k, v in list((b.get("ports") or {}).items())[:BASELINE_PORTS_MAX]},
                       "cty": {str(k)[:4]: int(v) for k, v in list((b.get("cty") or {}).items())[:BASELINE_COUNTRIES_MAX]}}
            except (TypeError, ValueError, KeyError, AttributeError):
                continue
            self.devs[did] = rec
        for did, c in (data.get("cur") or {}).items():
            try:
                if did in self.devs:
                    sk = bytearray.fromhex(c[1])
                    if len(sk) == self.SKETCH_BITS // 8:
                        self.cur[did] = [int(c[0]), sk, set(int(x) for x in c[2][:256]), set(str(x) for x in c[3][:64])]
            except (TypeError, ValueError, IndexError):
                continue
        return True


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
        entries of the local list also match their subdomains. Feeds never
        match a shared platform (feeds.shared_platform) - also for feed files
        parsed before that filter existed."""
        hits = []
        if self.feeds and not feeds.shared_platform(q):
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
        if suppressed(f):
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
        self.detectors = list(detectors) if detectors is not None else \
            [IntelDetector(), SuricataDetector()] + behaviour_detectors()
        self.modes = detector_modes({})
        self._active_cache = {}
        self._active_modes = None
        self.baselines = Baselines()
        self.shadow = {}            # shadow / learning-period behaviour results (never findings)
        self.dev_types = {}         # device -> guessed type (last outputs)
        self.sni = OrderedDict()    # address -> TLS server name (Zeek ssl.log)
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
        self.lease_ips = {}         # device -> {current IP: (neighbour active, lease start)}
        self.wg_peers = {}
        self.wg_nets = []
        self.prefixes = []
        self.own_ips = set()
        self.own_macs = set()
        self.roles = {}
        self.wan_devs = set()
        self.topology_at = 0
        self.config = {}
        self.overlay = {"names": {}, "expected": [], "silence": []}
        self.silence_next_expiry = 0
        self.overlay_mtimes = {}
        self.last_save = 0
        self.started = clock()
        self.stats = {"unattributed": 0, "dup_flows": 0, "suricata_ignored": 0, "suricata_used": 0,
                      "l2_attributed": 0, "cycles": 0, "last_cycle_s": 0.0}
        self.source_status = {}
        self.suricata_ifaces = None     # capture interfaces from suricata.yaml (None: unknown)
        self.suricata_key = None
        self.role_parents = {}
        self.zeek_cyc = [0, 0, 0, 0]    # this cycle: conn lines, with MACs, TCP lines, TCP with bad checksums
        self.zeek_win = []              # per-cycle counters, about the last hour
        self.unattr = {}                # LAN address with no device -> last time (status: count per hour)
        self.day_cache = {}
        z = self.cfg.zeek_current
        self.followers = {
            name: Follower(name, os.path.join(z, name + ".log"), zeek_archives(self.cfg, name),
                           INITIAL_BACKLOG["zeek"], clock)
            for name in ("dhcp", "software", "known_hosts", "dns", "ssl", "conn")
        }
        self.followers["eve"] = Follower("eve", self.cfg.eve, eve_archives(self.cfg.eve), INITIAL_BACKLOG["eve"], clock)

    # ---- persistence ----
    def load_state(self):
        self.load_behaviour_state()
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
        for fid, f in (st.get("shadow") or {}).items():
            if isinstance(f, dict) and DEVICE_ID_RE.match(str(f.get("device") or "")) and f.get("kind"):
                self.shadow[fid] = f
        return True

    def load_behaviour_state(self):
        """Baselines and detector state (their own files: a damaged or
        missing one never costs the main engine state)."""
        now = self.clock()
        self.baselines.from_json(read_json(self.cfg.state("baselines.json"), None, 128 << 20))
        dstate = read_json(self.cfg.state("detectors.json"), None, 128 << 20)
        if isinstance(dstate, dict):
            for det in self.detectors:
                if det.behaviour and det.name in dstate:
                    try:
                        det.state_from_json(dstate[det.name], now)
                    except Exception:
                        pass

    def save_behaviour_state(self):
        now = self.clock()
        self.baselines.prune(now)
        atomic_write_json(self.cfg.state("baselines.json"), self.baselines.to_json(), 0o600)
        dstate = {}
        for det in self.detectors:
            if det.behaviour:
                try:
                    s = det.state_to_json(now)
                except Exception:
                    s = None
                if s is not None:
                    dstate[det.name] = s
        atomic_write_json(self.cfg.state("detectors.json"), {"schema": 1, "saved_at": int(now), **dstate}, 0o600)

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
              "devices": devs, "findings": self.findings, "ip_hist": self.ip_hist, "shadow": self.shadow}
        atomic_write_json(self.cfg.state("engine.json"), st, 0o600)
        self.save_behaviour_state()
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
            self.modes = detector_modes(self.config)
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
        sil, ch = self._load_if_changed("silence.json")
        now = self.clock()
        if ch:
            self.overlay["silence"] = silence_rules(sil)
        if ch or (self.silence_next_expiry and now >= self.silence_next_expiry):
            self._apply_silence(now)

    def _apply_expected(self):
        for f in self.findings.values():
            f["expected"] = is_expected(f, self.overlay["expected"])

    def _apply_silence(self, now=None):
        """Mark every finding with the silence rule that covers it (expired
        rules no longer count: re-applied when the next one expires)."""
        now = self.clock() if now is None else now
        rules = self.overlay["silence"]
        for f in self.findings.values():
            f["silenced"] = silence_match(f, rules, now)
        self.silence_next_expiry = min((r["expires"] for r in rules if r.get("expires") and r["expires"] > now),
                                       default=0)

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
            if self._file_key(self.cfg.suricata_conf) != self.suricata_key:
                self._read_suricata()           # a capture fix shows within a cycle (INFO-1)
            return
        self.topology_at = now
        roles, wan, parents = {}, set(), {}
        conf = read_json(self.cfg.interfaces, {}) or {}
        if isinstance(conf, dict) and conf.get("lan"):
            w = conf.get("wan")
            w = w.get("device") if isinstance(w, dict) else w
            if isinstance(w, str) and w:
                wan.add(w)
            lan = conf.get("lan") or {}
            if lan.get("device"):
                roles[lan["device"]] = {"zone": "lan", "name": "LAN", "vlan": None}
            for o in conf.get("opt") or []:
                if isinstance(o, dict) and o.get("device"):
                    roles[o["device"]] = {"zone": o.get("id") or "opt", "name": o.get("name") or o["device"],
                                          "vlan": o.get("vlan")}
                    if isinstance(o.get("parent"), str) and o["parent"]:
                        parents[o["device"]] = o["parent"]
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
        self.role_parents = parents
        self._read_suricata()

    @staticmethod
    def _file_key(path):
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_ino, st.st_mtime_ns, st.st_size)

    def _read_suricata(self):
        self.suricata_key = self._file_key(self.cfg.suricata_conf)
        self.suricata_ifaces = suricata_capture(self.cfg.suricata_conf)

    def suricata_status(self):
        """Does Suricata capture a LAN/VLAN interface? Alerts seen only on
        the WAN carry the router's own (NAT) address and can never be
        attributed to a device."""
        cap = self.suricata_ifaces
        lan = sorted(d for d, r in self.roles.items() if r.get("zone") != "vpn")
        if cap is None:
            return {"config": False, "capture": [], "lan_capture": None, "lan_ifaces": lan}

        def covered(dev):
            return dev in cap or self.role_parents.get(dev) in cap or dev.split(".")[0] in cap
        seen = [d for d in lan if covered(d)]
        return {"config": True, "capture": list(cap), "lan_capture": bool(seen) if lan else None,
                "lan_ifaces": lan, "captured_lan": seen,
                "wan_only": bool(cap) and all(c in self.wan_devs for c in cap)}

    def warnings(self, now):
        """Source problems that make detections incomplete: [{code, text,
        hint}] for status.json, Security > Local (Monitoring sources) and the Clients page."""
        out = []
        su = self.suricata_status()
        if su["lan_capture"] is False and self.config.get("suricata", True):
            lan = next((d for d, r in self.roles.items() if r.get("zone") == "lan"), "")
            out.append({
                "code": "suricata_no_lan",
                "text": "IDS alerts can't be attributed to devices — Suricata only watches the WAN"
                        if su.get("wan_only") else
                        "IDS alerts can't be attributed to devices — Suricata watches no LAN or VLAN interface",
                "hint": "Add the LAN interface%s to Suricata's capture: sudo python3 /usr/local/share/tuxwall/scripts/"
                        "tune-suricata.py --add-lan /etc/suricata/suricata.yaml && sudo systemctl restart suricata"
                        % (" (%s)" % lan if lan else "")})
        z = self.zeek_window(recent=True)
        if z["lines"] >= ZEEK_MIN_LINES and z["tcp"] and z["bad_checksum"] >= BAD_CHECKSUM_SHARE * z["tcp"]:
            out.append({
                "code": "zeek_bad_checksums",
                "text": "Zeek sees bad checksums on most connections (checksum offloading on a virtual network card?) "
                        "— completed connections count only as attempts",
                "hint": "sudo /usr/local/share/tuxwall/scripts/zeek-site-setup.sh --checksums on (or the Ignore checksums switch below)"})
        if z["lines"] >= ZEEK_MIN_LINES and not z["l2"]:
            out.append({
                "code": "zeek_no_mac",
                "text": "Zeek does not log MAC addresses — events on IPv6 privacy addresses and reused IPs are "
                        "attributed from the neighbour table only",
                "hint": "sudo /usr/local/share/tuxwall/scripts/zeek-site-setup.sh"})
        return out

    def zeek_window(self, recent=False):
        """Zeek counters of about the last hour; recent: only the newest
        cycles that reach ZEEK_MIN_LINES, so a fixed site policy clears its
        warning as soon as enough new lines arrive (INFO-1)."""
        lines = l2 = tcp = bad = 0
        for a, b, c, d in reversed(self.zeek_win):
            if recent and lines >= ZEEK_MIN_LINES:
                break
            lines += a
            l2 += b
            tcp += c
            bad += d
        return {"lines": lines, "l2": l2, "tcp": tcp, "bad_checksum": bad}

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
        """Record that device did held ip at time ts (observations arrive
        out of order: inventory at 'now', log lines from the past). An
        interval of the same device absorbs ts unless that would stretch it
        over another device's claim; otherwise a new interval starts."""
        h = self.ip_hist.get(ip)
        if h is None:
            if len(self.ip_hist) >= IP_HISTORY_MAX:
                self._prune_ip_hist(force=True)
            h = self.ip_hist[ip] = []
        grow = None
        for e in h:
            if e[0] != did:
                continue
            if e[1] <= ts <= e[2]:
                return
            if e[1] - IP_MERGE_SECONDS <= ts <= e[2] + IP_MERGE_SECONDS:
                lo, hi = (e[2], ts) if ts > e[2] else (ts, e[1])
                if not any(o[0] != did and o[1] < hi and o[2] > lo for o in h):
                    grow = e
                    break
        if grow is not None:
            grow[1] = min(grow[1], ts)
            grow[2] = max(grow[2], ts)
        else:
            h.append([did, ts, ts])
        h.sort(key=lambda e: e[2])
        del h[:-IP_HISTORY_PER_IP]

    def who(self, ip, ts):
        """The device that held ip at time ts (see the module docstring)."""
        h = self.ip_hist.get(ip)
        if not h:
            return None
        inside = before = after = None
        for e in h:
            if e[1] <= ts <= e[2]:
                if inside is None or e[1] > inside[1]:
                    inside = e
            elif e[2] < ts:
                if before is None or e[2] > before[2]:
                    before = e
            elif after is None or e[1] < after[1]:
                after = e
        if inside is not None:
            return inside[0]
        gap_b = ts - before[2] if before is not None else None
        gap_a = after[1] - ts if after is not None else None
        near_b = gap_b is not None and gap_b <= IP_TAIL_SECONDS
        near_a = gap_a is not None and gap_a <= IP_LEAD_SECONDS
        if near_b and near_a:
            return before[0] if gap_b <= gap_a else after[0]
        if near_b:
            return before[0]
        if near_a:
            return after[0]
        if before is not None:
            return before[0] if gap_b <= IP_HISTORY_SECONDS else None
        return after[0]        # older than every sighting (the first backlog after a start)

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
            if ip in self.unattr or len(self.unattr) < UNATTR_MAX:
                self.unattr[ip] = max(ts, self.unattr.get(ip) or 0)
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

    def attribute_mac(self, ip, mac, ts, iface=None):
        """Device of the MAC that carried an event (Zeek L2 / Suricata ether),
        recorded as a holder of ip at ts; None for the router's own MACs."""
        if not mac or mac in self.own_macs:
            return None
        d = self.ensure_device(mac_id(mac), "mac", ts, mac=mac)
        if d is None:
            return None
        self.observe(ip, d["id"], ts)
        if iface:
            self._set_iface(d, iface)
        self.stats["l2_attributed"] += 1
        return d["id"]

    def _set_iface(self, d, iface):
        r = self.roles.get(iface) or {}
        if not r and d.get("kind") == "wg":
            r = {"zone": "vpn", "name": "WireGuard (%s)" % iface}
        d["iface"] = iface
        d["zone"] = r.get("zone") or ""
        d["zone_name"] = r.get("name") or iface
        d["vlan"] = r.get("vlan")

    def refresh_inventory(self):
        now = self.clock()
        # neighbours first: who answers for an address right now
        neigh = self.src.neighbours()
        usable = []
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
            usable.append((dev, mac, ip, st))
        neigh_mac = {ip: mac for _dev, mac, ip, _st in usable}
        neigh_active = {(mac, ip) for _dev, mac, ip, st in usable if st in NEIGH_ACTIVE}
        # Kea leases (v4 + v6) and reservations
        cur_ips = {}                # device -> {ip: (neighbour active, lease start)}

        def held_now(did, ip, active, start):
            m = cur_ips.setdefault(did, {})
            a0, s0 = m.get(ip, (0, 0))
            m[ip] = (max(a0, active), max(s0, start))
        all_leases = []
        for v6, paths in ((False, self.cfg.kea4), (True, self.cfg.kea6)):
            leases = read_kea_leases(paths, now, v6)
            if not v6:
                self.source_status["kea"] = {"ok": any(os.access(p, os.R_OK) for p in paths),
                                             "active_leases": len(leases)}
            all_leases += [dict(le, v6=v6) for le in leases]
        earlier = stale_leases(all_leases, neigh_active, lambda ip: self.classify(ip)[1])
        kea_names = {}              # device -> (held, in use, start, hostname): the current lease names it
        for le in all_leases:
            mac = le["mac"]
            d = self.ensure_device(mac_id(mac), "mac", min(now, le["cltt"] or now), mac=mac)
            if d is None:
                continue
            # a lease the neighbour table contradicts (another MAC uses the
            # address now) is not evidence of who holds it; neither is a
            # second, older lease of the MAC on the same network (DW-13)
            held = neigh_mac.get(le["ip"]) in (None, mac) and le["ip"] not in earlier
            if le["hostname"]:
                rank = (held, (mac, le["ip"]) in neigh_active, not le.get("v6"), le["cltt"] or 0, le["hostname"])
                if rank > kea_names.get(d["id"], (False,)):
                    kea_names[d["id"]] = rank
            self.touch(d, min(now, le["cltt"] or now), "lease", le["ip"] if held else None)
            if held:
                self.observe(le["ip"], d["id"], now)
                held_now(d["id"], le["ip"], int((mac, le["ip"]) in neigh_active), le["cltt"] or 0)
            c, dev = self.classify(le["ip"])
            if dev:
                self._set_iface(d, dev)
        for did, rank in kea_names.items():
            self.devices[did]["names"]["kea"] = rank[-1]
        for r in read_kea_reservations(self.cfg.kea_conf):
            d = self.devices.get(mac_id(r["mac"]))
            if d is not None and r["hostname"]:
                d["names"]["reservation"] = r["hostname"]
        # neighbours (ARP / NDP)
        states = {}
        n_ok = 0
        for dev, mac, ip, st in usable:
            n_ok += 1
            c, _ = self.classify(ip)
            if c != LAN and not ip.startswith("fe80:"):
                continue
            d = self.ensure_device(mac_id(mac), "mac", now, mac=mac)
            if d is None:
                continue
            active = st in NEIGH_ACTIVE
            if not ip.startswith("fe80:"):
                self.observe(ip, d["id"], now)
                self.touch(d, now if active else (d.get("last_seen") or now), "neighbour", ip)
                held_now(d["id"], ip, int(active), 0)
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
        if snap is None and not os.path.exists(self.cfg.wg_snapshot):
            snap = read_json(self.cfg.wg_snapshot_legacy, None, 4 << 20)   # API older than the shared dir
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
                        held_now(did, ip, 0, 0)
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
        did = self.attribute(o, ts, iface, create=False)
        rcode = ev.get("rcode_name") or ""
        if did and ts:
            self.baselines.dns(did, ts, q, rcode)
        if not self.intel.has_domains():
            return
        real = [a for a in ips if a not in SINKHOLES]
        de = DnsEvent()
        de.ts, de.device, de.dev_ip, de.query = ts, did, o, q
        de.qtype, de.rcode, de.answers = ev.get("qtype_name") or "", rcode, real
        de.answered = rcode == "NOERROR" and bool(real or [a for a in answers if a and a not in SINKHOLES])
        # Blocked only when the answer is a sinkhole address. NOERROR without
        # records (an AAAA query for an IPv4-only name), NXDOMAIN, SERVFAIL or
        # no reply are neither; RPZ/local-zone blocks arrive via on_unbound().
        de.blocked = (not de.answered and rcode == "NOERROR"
                      and bool(answers) and all((not a) or a in SINKHOLES for a in answers))
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

    def on_ssl(self, line):
        """TLS server names (Zeek ssl.log) of internet addresses: the
        destination name of a connection when no DNS answer names it."""
        m = SSL_NAME_RE.search(line)
        h = SSL_RESP_RE.search(line) if m else None
        if not h:
            return
        r = h.group(1).decode("ascii", "replace")
        name = m.group(1).decode("ascii", "replace").lower().rstrip(".")
        if "." not in name or self.classify(r)[0] != EXT:
            return
        self.sni[r] = name[:253]
        self.sni.move_to_end(r)
        while len(self.sni) > SNI_MAX:
            self.sni.popitem(last=False)

    def dest_name(self, ip):
        return self.sni.get(ip) or self.rdns.get(ip) or ""

    def device_type(self, did):
        """Guessed type of a device (the last outputs' value; computed once
        right after a restart, before the first outputs)."""
        typ = self.dev_types.get(did)
        if typ is None:
            d = self.devices.get(did)
            if d is None:
                return "unknown"
            mac = d.get("mac")
            names = [(k, v) for k, v in (("user", self.overlay["names"].get(did)),) if v]
            names += [(k, (d.get("names") or {}).get(k)) for k in ("reservation", "kea", "dhcp", "wg")]
            sw = sorted((dict(v, name=k) for k, v in (d.get("software") or {}).items()),
                        key=lambda s: -(s.get("last") or 0))
            typ = guess_type(d, self.oui.vendor(mac) if mac else "", names, sw)[0]
            self.dev_types[did] = typ
        return typ

    def _lan_flow(self, ev, o, oif, r, cr, did):
        """Device -> LAN host / router flow (D3): the router's own services in
        normal use are dropped here, the rest goes to on_lan."""
        proto = ev.get("proto") or ""
        port = ev.get("id.resp_p")
        if cr == OWN and (proto == "icmp" or (proto, port) in ROUTER_SERVICES):
            return
        ts = self._ts(ev)
        if not ts:
            return
        if self._dup(("l", o, ev.get("id.orig_p"), r, port, proto), ts, 1.0):
            return
        if did is None:
            did = self.attribute(o, ts, oif)
        if not did:
            return
        state = ev.get("conn_state") or ""
        hist = ev.get("history") or ""
        ce = ConnEvent()
        ce.ts, ce.device, ce.dev_ip, ce.peer, ce.peer_port = ts, did, o, r, port
        ce.proto, ce.outbound, ce.state, ce.history, ce.to_router = proto, True, state, hist, cr == OWN
        ce.bytes_in = ev.get("resp_ip_bytes") or 0
        ce.bytes_out = ev.get("orig_ip_bytes") or 0
        ce.service, ce.duration = ev.get("service") or "", ev.get("duration") or 0
        if proto == "tcp":
            ce.established = state in ("SF", "S1", "S2", "S3", "RSTO") or ("h" in hist.lower() and "d" in hist.lower())
        else:
            ce.established = (ev.get("resp_pkts") or 0) > 0
        self._run_detectors("on_lan", ce, o, oif)

    def on_conn(self, line):
        ev = self._loads(line)
        if not ev:
            return
        zc = self.zeek_cyc
        zc[0] += 1
        if "orig_l2_addr" in ev or "resp_l2_addr" in ev:
            zc[1] += 1
        if ev.get("proto") == "tcp":
            zc[2] += 1
            if "c" in str(ev.get("history") or "").lower():     # Zeek: a packet with a bad checksum
                zc[3] += 1
        o = ev.get("id.orig_h") or ""
        r = ev.get("id.resp_h") or ""
        co, oif = self.classify(o)
        cr, rif = self.classify(r)
        if co == LAN and cr == EXT:
            dev_ip, peer, outbound, iface = o, r, True, oif
        elif cr == LAN and co == EXT:
            dev_ip, peer, outbound, iface = r, o, False, rif
        else:
            # device <-> router (DNS, DHCP, NTP) or routed LAN <-> VLAN: no
            # detection, but the MAC on the flow still says who holds the
            # address (an IPv6 privacy address used only for DNS lookups)
            orig_did = None
            if (co == LAN or cr == LAN) and ("orig_l2_addr" in ev or "resp_l2_addr" in ev):
                ts = self._ts(ev)
                for ip, cls, ifc, key in ((o, co, oif, "orig_l2_addr"), (r, cr, rif, "resp_l2_addr")):
                    mac = norm_mac(ev.get(key)) if cls == LAN and ts else None
                    if mac and mac not in self.own_macs:
                        did = self.attribute_mac(ip, mac, ts, ifc)
                        if ip == o:
                            orig_did = did
            # D3: a device contacting LAN hosts / router ports through the router
            if co == LAN and cr in (LAN, OWN) and self.modes.get("internal_scan") != "off":
                self._lan_flow(ev, o, oif, r, cr, orig_did)
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
        # Zeek's mac-logging policy adds the link-layer addresses: the LAN
        # side's MAC at the time of the flow decides (IP reuse, IPv6 privacy
        # addresses the neighbour table no longer holds)
        l2 = norm_mac(ev.get("orig_l2_addr" if outbound else "resp_l2_addr"))
        did = self.attribute_mac(dev_ip, l2, ts, iface) if l2 else None
        if did is None:
            did = self.attribute(dev_ip, ts, iface)
        peer_port = ev.get("id.resp_p") if outbound else ev.get("id.orig_p")
        if did:
            self._traffic(did, ts, peer, b_in, b_out, peer_port if outbound and proto in ("tcp", "udp") else None)
        state = ev.get("conn_state") or ""
        hist = ev.get("history") or ""
        ce = ConnEvent()
        ce.ts, ce.device, ce.dev_ip, ce.peer = ts, did, dev_ip, peer
        ce.peer_port, ce.to_router = peer_port, False
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
        # eve-log "ethernet: yes" adds the frame's MACs (useless on the WAN side)
        ether = ev.get("ether") if ev.get("in_iface") not in self.wan_devs else None
        ether = ether if isinstance(ether, dict) else {}
        for ip, other in ((src, dst), (dst, src)):
            c, iface = self.classify(ip)
            if c != LAN:
                continue
            mac = norm_mac(ether.get("src_mac" if ip == src else "dest_mac")) if ether else None
            ae = AlertEvent()
            ae.ts, ae.dev_ip, ae.peer, ae.outbound = ts, ip, other, ip == client
            ae.device_sent = ip == src
            ae.sid, ae.rev = a.get("signature_id"), a.get("rev")
            ae.signature, ae.category = sig, cat
            ae.severity = a.get("severity") if isinstance(a.get("severity"), int) else 3
            ae.proto = ev.get("proto") or ""
            ae.dest_port = ev.get("dest_port")
            ae.action = a.get("action") or ""
            ae.device = (self.attribute_mac(ip, mac, ts, iface) if mac else None) or self.attribute(ip, ts, iface)
            self._run_detectors("on_alert", ae, ip, iface)

    def _active(self, method):
        """[(detector, bound method)] that implement `method` and are not
        off (cached until self.modes is replaced)."""
        if self._active_modes is not self.modes:
            self._active_modes = self.modes
            self._active_cache = {}
        hit = self._active_cache.get(method)
        if hit is None:
            hit = self._active_cache[method] = [
                (d, getattr(d, method)) for d in self.detectors
                if getattr(type(d), method) is not getattr(Detector, method)
                and not (d.behaviour and self.modes.get(d.name, DETECTOR_DEFAULT_MODE) == "off")]
        return hit

    def _run_detectors(self, method, ev, dev_ip, iface):
        for det, fn in self._active(method):
            try:
                specs = fn(self, ev)
            except Exception as exc:  # a broken detector must not stop the engine
                self.source_status.setdefault("detectors", {})[det.name] = "error: %s" % exc.__class__.__name__
                continue
            for spec in specs or ():
                if det.behaviour:
                    if ev.device:
                        self.record_behaviour(det, ev.device, spec, ev.ts)
                    continue
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

    def _traffic(self, did, ts, peer, b_in, b_out, port=None):
        self.baselines.flow(did, ts, peer, b_in, b_out, self.geo.iso(peer), port)
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

    # ---- behaviour results (shadow mode, learning period) ----
    def record_behaviour(self, det, did, spec, ts):
        """A behaviour detector's result: severity capped at medium unless it
        comes with a threat-intel hit; mode "on" and an established baseline
        -> a normal finding (health, alerts); otherwise a shadow row (reason
        "shadow", or "learning" in mode on)."""
        spec = dict(spec)
        intel = bool(spec.pop("intel", False))
        if not intel:
            spec["severity"] = cap_sev(spec.get("severity") or "low", BEHAVIOUR_SEV_CAP)
        mode = self.modes.get(det.name, DETECTOR_DEFAULT_MODE)
        if mode == "off":
            return None
        if mode == "on" and self.baselines.established(did, self.clock()):
            return self.record_finding(did, spec, ts)
        return self.record_shadow(did, spec, ts, "learning" if mode == "on" else "shadow", det.name)

    def record_shadow(self, did, spec, ts, reason, detector):
        now = self.clock()
        if ts < now - self.retention_seconds() or did not in self.devices:
            return None
        key = "%s|%s|%s" % (did, spec["kind"], spec["indicator"])
        fid = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
        day = str(int(ts // 86400))
        f = self.shadow.get(fid)
        if f is None:
            if len(self.shadow) >= MAX_SHADOW:
                self._prune_shadow(force=True)
            f = self.shadow[fid] = {
                "id": fid, "device": did, "kind": spec["kind"], "indicator": str(spec["indicator"])[:255],
                "indicator_type": spec.get("indicator_type") or "", "severity": spec["severity"],
                "title": spec.get("title") or KIND_TEXT.get(spec["kind"], spec["kind"]),
                "source": spec.get("source") or detector, "first": ts, "last": ts, "count": 1,
                "details": spec.get("details") or {}, "shadow": True, "reason": reason, "detector": detector,
                "days": {day: 1}}
            return f
        f["count"] += 1
        days = f.setdefault("days", {})
        days[day] = days.get(day, 0) + 1
        while len(days) > SHADOW_DAYS_KEPT:
            del days[min(days, key=int)]
        if ts >= f["last"]:
            f["last"] = ts
            f["details"] = spec.get("details") or f["details"]
            f["title"] = spec.get("title") or f["title"]
            f["reason"] = reason
        if ts < f["first"]:
            f["first"] = ts
        if SEV_RANK.get(spec["severity"], 0) > SEV_RANK.get(f["severity"], 0):
            f["severity"] = spec["severity"]
        return f

    def _prune_shadow(self, force=False):
        cut = self.clock() - self.retention_seconds()
        for fid in [k for k, f in self.shadow.items() if (f.get("last") or 0) < cut]:
            del self.shadow[fid]
        if force and len(self.shadow) >= MAX_SHADOW:
            for fid in sorted(self.shadow, key=lambda k: self.shadow[k].get("last") or 0)[:MAX_SHADOW // 10]:
                del self.shadow[fid]

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
            f["silenced"] = silence_match(f, self.overlay["silence"], now)
            if not suppressed(f):
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
            # an escalation to critical may leave the rule's reach
            f["silenced"] = silence_match(f, self.overlay["silence"], now)
            if not suppressed(f):
                self._event({"type": "finding", "device": did, "finding": fid, "severity": f["severity"],
                             "kind": f["kind"], "source": f["source"], "escalated": True}, ts)
        return f

    INTEL_KINDS = ("c2_connection", "intel_connection", "intel_attempt", "intel_inbound",
                   "dns_lookup", "dns_blocked")

    def _retract_stale_intel(self):
        """Drop feed findings whose indicator the feed no longer lists (a feed
        correction, or a filter such as feeds.shared_platform). Only for feeds
        that are loaded right now - a feed that is missing or disabled keeps its
        findings - and never for the owner's local list or Suricata."""
        gone = []
        for fid, f in self.findings.items():
            src = f.get("source") or ""
            if f.get("kind") not in self.INTEL_KINDS or src not in self.intel.feeds:
                continue
            ind = f.get("indicator") or ""
            if f.get("indicator_type") == "domain":
                listed = any(name == src for name, _m, _q in self.intel.match_domain(ind))
            else:
                listed = any(name == src for name, _m in self.intel.match_ip(ind))
            if not listed:
                gone.append(fid)
        for fid in gone:
            f = self.findings.pop(fid)
            self._event({"type": "retracted", "device": f["device"], "finding": fid,
                         "kind": f["kind"], "source": f.get("source") or ""}, self.clock())
        if gone:
            self.stats["retracted"] = self.stats.get("retracted", 0) + len(gone)
        return len(gone)

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
                    "dns": self.on_dns, "ssl": self.on_ssl, "conn": self.on_conn}
        self.zeek_cyc = [0, 0, 0, 0]
        for name in ("dhcp", "software", "known_hosts", "dns", "ssl", "conn"):
            if name == "ssl" and self.modes.get("beaconing") == "off" and self.modes.get("dns_bypass") == "off":
                continue
            self.followers[name].poll(handlers[name])
        self.zeek_win.append(tuple(self.zeek_cyc))
        del self.zeek_win[:-ZEEK_WINDOW_CYCLES]
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
        self._prune_shadow()
        self._prune_ip_hist()
        old = now - max(self.retention_seconds(), 90 * 86400)
        for did in [k for k, d in self.devices.items()
                    if (d.get("last_seen") or 0) < old and not any(f["device"] == k for f in self.findings.values())]:
            self.devices.pop(did, None)
            self.agg.pop(did, None)
        if self.dns_hot:
            self.dns_hot = {k: v for k, v in self.dns_hot.items() if v[3] > now}
        if self.unattr:
            self.unattr = {k: v for k, v in self.unattr.items() if v > now - 3600 and not self.who(k, v)}

    def cycle(self):
        t0 = time.monotonic()
        self.load_overlays()
        self.refresh_topology()
        if self.intel.reload(self.config):
            self._retract_stale_intel()
        self.refresh_inventory()
        self.poll_logs()
        for det in self.detectors:
            if det.behaviour and self.modes.get(det.name, DETECTOR_DEFAULT_MODE) == "off":
                continue
            try:
                for spec, did, ts in det.on_cycle(self, self.clock()) or ():
                    if det.behaviour:
                        self.record_behaviour(det, did, spec, ts)
                    else:
                        self.record_finding(did, spec, ts)
            except Exception as exc:
                self.source_status.setdefault("detectors", {})[det.name] = "error: %s" % exc.__class__.__name__
        self.prune()
        self.baselines.fold()
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

    def build_device(self, d, flist, now, holders=None):
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
        self.dev_types[did] = typ
        risk, health, reason, worst = score_device(d, flist, now)
        a = self.agg.get(did)
        today = self._day(now)
        # current addresses: the one the neighbour table sees in use first,
        # then the newest lease (the Clients row, the viewer row and the
        # panel all take the first IPv4 one - DW-13)
        held = self.lease_ips.get(did) or {}
        current = sorted(held, key=lambda ip: (-held[ip][0], -held[ip][1], ip))
        # addresses of the last 24 h: current ones first, then the most
        # recent; never one that another device holds now (reused by DHCP)
        mine = {ip: i for i, ip in enumerate(current)}
        seen = d.get("ips") or {}
        cur = sorted({ip for ip, t in seen.items() if t >= now - 86400
                      and not ((holders or {}).get(ip, set()) - {did})} | {ip for ip in current if "/" not in ip},
                     key=lambda ip: (mine.get(ip, len(mine)), -(seen.get(ip) or 0), ip))
        online = False
        nstate = self.neigh_state.get(mac) if mac else None
        if nstate in NEIGH_ACTIVE:
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
        active = [f for f in flist if not suppressed(f)]
        silenced = sum(1 for f in flist if f.get("silenced") and not f.get("expected"))
        return {
            "id": did, "kind": d.get("kind"), "name": name, "name_source": name_src,
            "mac": mac, "private_mac": bool(mac and is_private_mac(mac)), "vendor": vendor,
            "type": typ, "type_reason": why,
            "ips": [ip for ip in cur if ":" not in ip], "ipv6": [ip for ip in cur if ":" in ip],
            "current_ips": current,
            # every address of the device with when it was last seen on it
            # (quarantine: recent addresses no other device owns - DW-14)
            "ip_seen": {ip: int(t) for ip, t in seen.items()},
            "iface": d.get("iface") or "", "zone": d.get("zone") or "", "zone_name": d.get("zone_name") or "",
            "vlan": d.get("vlan"), "first_seen": int(d.get("first_seen") or 0), "last_seen": int(d.get("last_seen") or 0),
            "online": online, "neighbour_state": nstate, "baseline": bool(d.get("baseline")),
            "health": health, "risk": risk, "reason": reason,
            "worst_finding": worst["id"] if worst else None,
            "findings": {"total": len(flist), "active": len(active), "expected": len(flist) - len(active) - silenced,
                         "silenced": silenced},
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
        holders = {}
        for did, ips in self.lease_ips.items():
            for ip in ips:
                holders.setdefault(ip, set()).add(did)
        devices = [self.build_device(d, by_dev.get(did, []), now, holders) for did, d in self.devices.items()]
        rank = {"critical": 3, "warning": 2, "new": 1}
        devices.sort(key=lambda x: (-rank.get(x["health"], 0), -x["risk"], x["name"].lower()))
        findings = sorted(self.findings.values(), key=lambda f: (-SEV_RANK.get(f["severity"], 0), -f["last"]))
        atomic_write_json(self.cfg.state("devices.json"),
                          {"schema": SCHEMA, "generated_at": int(now), "devices": devices})
        atomic_write_json(self.cfg.state("findings.json"),
                          {"schema": SCHEMA, "generated_at": int(now), "findings": findings})
        atomic_write_json(self.cfg.state("summary.json"), summarize(devices, findings, now))
        # behaviour results in shadow mode / learning period: admin "Detector
        # tuning" card only (never findings.json, so never health or alerts)
        atomic_write_json(self.cfg.state("shadow.json"),
                          {"schema": SCHEMA, "generated_at": int(now), "modes": dict(self.modes),
                           "findings": sorted(self.shadow.values(), key=lambda f: -(f.get("last") or 0))})
        if len(self.dev_types) > len(self.devices) + 100:
            self.dev_types = {k: v for k, v in self.dev_types.items() if k in self.devices}
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
        z = self.zeek_window()
        sources = dict(self.source_status)
        sources["suricata"] = self.suricata_status()
        sources["zeek"] = dict(z, mac_logging=bool(z["l2"]) if z["lines"] else None)
        return {"schema": SCHEMA, "version": ENGINE_VERSION, "generated_at": int(now), "started_at": int(self.started),
                "cycle_seconds": CYCLE_SECONDS, "stats": dict(self.stats), "logs": logs,
                "unattributed_addresses_1h": sum(1 for v in self.unattr.values() if v > now - 3600),
                "warnings": self.warnings(now),
                "sources": sources, "indicators": self.intel.counts(),
                "geoip": self.geo.available, "devices": len(self.devices), "findings": len(self.findings),
                "cpu_seconds": cpu, "max_rss_kb": rss, "rss_kb": rss_now,
                "journal": {"active": self.journal_active, "error": self.journal_error},
                "lan_prefixes": len(self.prefixes),
                "detectors": {d.name: dict(d.stats(), mode=self.modes.get(d.name, DETECTOR_DEFAULT_MODE))
                              for d in self.detectors if d.behaviour},
                "baselines": self.baselines.counts(now), "shadow": len(self.shadow)}


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


def suppressed(f):
    """Marked expected or covered by a silence rule: no risk, no health,
    no alert."""
    return bool(f.get("expected") or f.get("silenced"))


# ── silence rules (/etc/tuxwall/devices/silence.json) ───────────────────────

SILENCE_SCOPES = ("indicator", "device_kind", "suffix", "kind")
SILENCE_EXPIRY = {"7d": 7 * 86400, "30d": 30 * 86400, "forever": 0}
SILENCE_MAX = 200
SILENCE_ID_RE = re.compile(r"^s[0-9a-f]{12}$")
KIND_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
SUFFIX_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
CRITICAL_KINDS = frozenset(("c2_connection",))
NOT_SILENCEABLE = frozenset(("new_device",))


def is_critical_finding(f):
    """What a silence rule never covers without include_critical: a C2
    connection, an outbound IDS attack response / "Successful ..." alert
    the device sent, or any finding of severity critical."""
    if f.get("severity") == "critical" or f.get("kind") in CRITICAL_KINDS:
        return True
    if f.get("kind") == "ids_alert" and f.get("severity") not in ("low", "info", None):
        det = f.get("details") if isinstance(f.get("details"), dict) else {}
        title = str(f.get("title") or "").upper()
        return title.startswith(("ET ATTACK_RESPONSE", "GPL ATTACK_RESPONSE")) or \
            str(det.get("category") or "").startswith("Successful")
    return False


def _finding_domains(f):
    out = []
    for v in (f.get("indicator"), ((f.get("details") or {}) if isinstance(f.get("details"), dict) else {}).get("query")):
        v = str(v or "").strip().lower().rstrip(".")
        if v.startswith("*."):
            v = v[2:]
        if v and not v.startswith("sid:") and v not in out:
            out.append(v)
    return out


def silence_rule_covers(rule, f):
    """Scope match only (no expiry, no critical guard)."""
    scope = rule.get("scope")
    kind = rule.get("kind")
    if kind and kind != f.get("kind"):
        return False
    if scope == "indicator":
        return str(f.get("indicator") or "").lower() == rule.get("indicator")
    if scope == "device_kind":
        return f.get("device") == rule.get("device") and bool(kind)
    if scope == "suffix":
        sfx = rule.get("suffix") or ""
        return bool(sfx) and any(d == sfx or d.endswith("." + sfx) for d in _finding_domains(f))
    if scope == "kind":
        return bool(kind)
    return False


def silence_match(f, rules, now):
    """Id of the first live rule that silences finding f, else None."""
    if f.get("kind") in NOT_SILENCEABLE:
        return None
    crit = None
    for r in rules or ():
        exp = r.get("expires") or 0
        if exp and exp <= now:
            continue
        if not silence_rule_covers(r, f):
            continue
        if crit is None:
            crit = is_critical_finding(f)
        if crit and not r.get("include_critical"):
            continue
        return r.get("id")
    return None


def silence_rules(data):
    """The valid rules of a silence.json document (bad entries dropped)."""
    raw = data.get("rules") if isinstance(data, dict) else None
    out = []
    for r in raw if isinstance(raw, list) else []:
        if not isinstance(r, dict) or not SILENCE_ID_RE.match(str(r.get("id") or "")) \
                or r.get("scope") not in SILENCE_SCOPES:
            continue
        try:
            exp = int(r.get("expires") or 0)
        except (TypeError, ValueError):
            continue
        out.append(dict(r, expires=exp, include_critical=r.get("include_critical") is True))
        if len(out) >= SILENCE_MAX:
            break
    return out


def validate_silence_rule(body, now, rid=None):
    """A new rule from an admin request -> normalised dict, or ValueError
    with a message for the dashboard."""
    if not isinstance(body, dict):
        raise ValueError("rule must be an object")
    scope = body.get("scope")
    if scope not in SILENCE_SCOPES:
        raise ValueError("scope must be one of: " + ", ".join(SILENCE_SCOPES))
    kind = str(body.get("kind") or "").strip().lower()
    if kind and not KIND_RE.match(kind):
        raise ValueError("Unknown finding kind")
    if kind in NOT_SILENCEABLE:
        raise ValueError("New-device rows are dismissed, not silenced")
    rule = {"id": rid or "s" + hashlib.sha1(("%s|%r" % (now, sorted(body.items(), key=str))).encode()).hexdigest()[:12],
            "scope": scope}
    if scope == "indicator":
        ind = str(body.get("indicator") or "").strip().lower()
        if not ind or len(ind) > 255 or any(c.isspace() for c in ind):
            raise ValueError("An indicator is required")
        rule["indicator"] = ind
    elif scope == "device_kind":
        dev = str(body.get("device") or "")
        if not DEVICE_ID_RE.match(dev):
            raise ValueError("A device is required")
        if not kind:
            raise ValueError("A finding kind is required")
        rule["device"] = dev
    elif scope == "suffix":
        sfx = str(body.get("suffix") or "").strip().lower().rstrip(".")
        if sfx.startswith("*."):
            sfx = sfx[2:]
        if not SUFFIX_RE.match(sfx):
            raise ValueError("A domain suffix such as telemetry.example.com is required (at least two labels)")
        rule["suffix"] = sfx
    elif not kind:
        raise ValueError("A finding kind is required")
    if kind:
        rule["kind"] = kind
    exp = body.get("expires", "30d")
    if exp not in SILENCE_EXPIRY:
        raise ValueError("expires must be 7d, 30d or forever")
    rule["expires"] = int(now + SILENCE_EXPIRY[exp]) if SILENCE_EXPIRY[exp] else 0
    rule["include_critical"] = body.get("include_critical") is True
    rule["note"] = " ".join("".join(ch if ch.isprintable() else " " for ch in str(body.get("note") or "")).split())[:200]
    return rule


def summarize(devices, findings, now):
    flagged = [d for d in devices if d["health"] in ("warning", "critical")]
    active = [f for f in findings if not suppressed(f)]
    worst = None
    for f in active:
        if worst is None or (SEV_RANK.get(f["severity"], 0), f["last"]) > (SEV_RANK.get(worst["severity"], 0), worst["last"]):
            worst = f
    names = {d["id"]: d["name"] for d in devices}
    new = [d for d in devices if not d.get("baseline") and now - (d.get("first_seen") or 0) < NEW_DEVICE_SECONDS]
    zones = {}
    for d in new:
        z = str(d.get("zone_name") or d.get("zone") or "other")[:32]
        zones[z] = zones.get(z, 0) + 1
    return {
        "schema": SCHEMA, "generated_at": int(now),
        "devices": len(devices), "online": sum(1 for d in devices if d["online"]),
        # first seen in the last 24 h - whatever its health (a new device with
        # a finding is "warning", still new); not the devices of the first pass
        "new_24h": len(new),
        # per network of the new devices (Security > Local: "2 on IoT")
        "new_zones": dict(sorted(zones.items(), key=lambda kv: (-kv[1], kv[0]))[:3]),
        # active clients: seen in the last 10 minutes (neighbour table, traffic, WireGuard handshake)
        "active": sum(1 for d in devices if d.get("online") or now - (d.get("last_seen") or 0) < ONLINE_SECONDS),
        "flagged": len(flagged), "critical": sum(1 for d in devices if d["health"] == "critical"),
        "warning": sum(1 for d in devices if d["health"] == "warning"),
        "findings_active": len(active),
        "findings_silenced": sum(1 for f in findings if f.get("silenced") and not f.get("expected")),
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
