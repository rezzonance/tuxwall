#!/usr/bin/env python3
"""Threat-intel feeds and local indicators for TuxWall device monitoring.

Used by the engine (devicewatch.py: `feeds-update` runs as
tuxwall-devicewatch-feeds.service, the analysis service loads the parsed
files) and by the dashboard API (status, local indicator validation).

Feeds (all abuse.ch data is CC0; attribution requested):
  feodo      Feodo Tracker botnet C2 IP blocklist (JSON). No key needed.
  urlhaus    URLhaus malware-hosting host file. Since 2026-10-21 abuse.ch
             serves exports only with a free Auth-Key in the URL path.
  threatfox  ThreatFox IOC export (CSV in a ZIP: ip:port, domain and URL
             IOCs of the past 6 months). Auth-Key needed, as for URLhaus.
SSLBL is not used: its IP list is gone and certificate hashes need the TLS
handshake fingerprints of Phase 2.

The Auth-Key is optional: /etc/tuxwall/devices/abuse-ch.key (root 0600),
handed to the feed unit by systemd (LoadCredential=abusech-key). Without it
the two feeds report "needs_key" and are skipped. The key is never logged:
every message passes mask().

Downloads: HTTPS only (redirects to anything else refused), If-None-Match /
If-Modified-Since, a size cap per feed, a parse check, and the last good
file is kept when anything fails (no internet, Tripwire egress block, HTTP
error, garbage). Parsed feeds are written as feeds/<name>.json:
    {"schema": 1, "feed", "fetched_at", "meta": [meta, ...],
     "ip": {addr: meta index}, "domain": {name: meta index}}
meta: {"m": malware, "t": threat type, "p": port, "st": status, "c": confidence}
(shared metadata is stored once: a 200k-IOC export stays a few tens of MB
in the engine).
"""
import csv
import io
import ipaddress
import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

sys.dont_write_bytecode = True

SCHEMA = 1
USER_AGENT = "TuxWall-devicewatch/1 (+https://tuxwall.org)"
HTTP_TIMEOUT = 30
MIN_FORCED_INTERVAL = 300          # abuse.ch: exports change every 5 min, never fetch faster
RETRY_INTERVAL = 3600              # after a failure (the feed timer runs hourly)
FEED_OLD_C2_DAYS = 30              # Feodo: an offline C2 last online longer ago is "old"

FEEDS = {
    "feodo": {
        "title": "Feodo Tracker botnet C2 IP blocklist",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "homepage": "https://feodotracker.abuse.ch/blocklist/",
        "format": "feodo_json",
        "needs_key": False,
        "max_bytes": 8 << 20,
        "interval": 6 * 3600,
        "licence": "CC0 1.0",
        "attribution": "abuse.ch Feodo Tracker",
        "kind": "c2",
    },
    "urlhaus": {
        "title": "URLhaus malware-hosting hosts",
        "url": "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/hostfile.txt",
        "homepage": "https://urlhaus.abuse.ch/api/",
        "format": "hostfile",
        "needs_key": True,
        "max_bytes": 32 << 20,
        "interval": 6 * 3600,
        "licence": "CC0 1.0",
        "attribution": "abuse.ch URLhaus",
        "kind": "malware_host",
    },
    "threatfox": {
        "title": "ThreatFox IOCs (C2 and payload-delivery IPs/domains, past 6 months)",
        "url": "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip",
        "homepage": "https://threatfox.abuse.ch/export/",
        "format": "threatfox_csv_zip",
        "needs_key": True,
        "max_bytes": 64 << 20,
        "max_unzipped": 512 << 20,
        "interval": 6 * 3600,
        "licence": "CC0 1.0",
        "attribution": "abuse.ch ThreatFox",
        "kind": "ioc",
        "min_confidence": 50,
    },
}

KEY_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
SEVERITIES = ("critical", "high", "medium", "low")
LOCAL_TYPES = ("ip", "cidr", "domain")
LOCAL_MAX = 2000
LOCAL_NOTE_MAX = 200


class FeedError(Exception):
    pass


# ── validation helpers (shared with the API) ────────────────────────────────

def norm_ip(value):
    """Canonical text of an IP address (Zeek's format), or None."""
    try:
        return ipaddress.ip_address(str(value).strip().strip("[]")).compressed
    except ValueError:
        return None


def norm_domain(value):
    """Lower-case host name without trailing dot (IDNA for non-ASCII), or None."""
    d = str(value or "").strip().lower().rstrip(".")
    if not d or len(d) > 253:
        return None
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    labels = d.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(x) for x in labels):
        return None
    if labels[-1].isdigit():          # an IP address, not a name
        return None
    return d


# Documentation ranges (RFC 5737 / RFC 3849) are never routed, so listing them
# is harmless - and they are what tests and the lab use as "bad" addresses.
DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                   "2001:db8::/32"))


def public_ip(ip):
    """An address a feed may list: global unicast (or documentation) - never
    a private/LAN, loopback, link-local or multicast address."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global or any(a.version == n.version and a in n for n in DOC_NETS)


def _never_matched(a):
    """Addresses no LAN device's flow to the internet can have as its peer."""
    return a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local or \
        (a.version == 4 and a == ipaddress.IPv4Address("255.255.255.255"))


def validate_local_indicator(item, router_ips=(), lan_nets=()):
    """Normalise one admin-entered indicator; raises ValueError with a
    user-facing message. Returns {"type", "value", "severity", "note"}.
    router_ips / lan_nets (the API passes them when an admin adds one): the
    router's own addresses and its LAN/VLAN networks are refused - device
    monitoring only looks at traffic between a device and the outside, so
    such an entry could never match."""
    if not isinstance(item, dict):
        raise ValueError("indicator must be an object")
    raw = str(item.get("value") or "").strip()
    typ = str(item.get("type") or "").strip().lower()
    if not raw:
        raise ValueError("value required")
    if not typ:
        typ = "cidr" if "/" in raw else ("ip" if norm_ip(raw) else "domain")
    if typ not in LOCAL_TYPES:
        raise ValueError("type must be ip, cidr or domain")
    nets = []
    for n in lan_nets or ():
        try:
            nets.append(ipaddress.ip_network(str(n), strict=False))
        except ValueError:
            continue
    own = {norm_ip(x) for x in router_ips or ()} - {None}
    if typ == "ip":
        v = norm_ip(raw)
        if not v:
            raise ValueError("not an IP address")
        a = ipaddress.ip_address(v)
        if _never_matched(a):
            raise ValueError("%s is not an internet address (unspecified, loopback, multicast or link-local) "
                             "- it can never match" % v)
        if v in own:
            raise ValueError("%s is one of the router's own addresses - device monitoring only checks traffic "
                             "between a device and the outside, so it can never match" % v)
        lan = next((n for n in nets if n.version == a.version and a in n), None)
        if lan is not None:
            raise ValueError("%s is inside your own network %s - traffic between local devices is not checked, "
                             "so it can never match" % (v, lan))
    elif typ == "cidr":
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError("not a network (CIDR)")
        if net.prefixlen < (8 if net.version == 4 else 16):
            raise ValueError("network too broad (at least /8 for IPv4, /16 for IPv6)")
        v = net.compressed
        if _never_matched(net.network_address) or net.is_loopback or net.is_multicast or net.is_link_local:
            raise ValueError("%s is not an internet network (unspecified, loopback, multicast or link-local) "
                             "- it can never match" % v)
        if any(ipaddress.ip_address(x) in net for x in own if ipaddress.ip_address(x).version == net.version):
            raise ValueError("%s contains one of the router's own addresses - pick a narrower network" % v)
        lan = next((n for n in nets if n.version == net.version and n.overlaps(net)), None)
        if lan is not None:
            raise ValueError("%s overlaps your own network %s - traffic between local devices is not checked" % (v, lan))
    else:
        wild = raw.startswith("*.")
        d = norm_domain(raw[2:] if wild else raw)
        if not d:
            raise ValueError("not a domain name")
        v = ("*." + d) if wild else d
    sev = str(item.get("severity") or "high").strip().lower()
    if sev not in SEVERITIES:
        raise ValueError("severity must be critical, high, medium or low")
    note = str(item.get("note") or "").strip()
    note = "".join(ch for ch in note if ch.isprintable())[:LOCAL_NOTE_MAX]
    return {"type": typ, "value": v, "severity": sev, "note": note}


def load_local_indicators(path):
    """[{"type","value","severity","note",...}] from local-indicators.json;
    invalid entries are skipped (the API validates on write)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    items = data.get("indicators") if isinstance(data, dict) else None
    out = []
    for it in items if isinstance(items, list) else []:
        try:
            v = validate_local_indicator(it)
        except ValueError:
            continue
        v.update({k: it.get(k) for k in ("added", "added_by") if k in it})
        out.append(v)
        if len(out) >= LOCAL_MAX:
            break
    return out


def mask(text, key):
    text = str(text)
    if key:
        text = text.replace(key, "***")
    return re.sub(r"/v2/files/exports/[^/\s]+/", "/v2/files/exports/***/", text)


# ── parsers (bytes in -> {"ip": {}, "domain": {}}) ──────────────────────────

def parse_feodo_json(data, now=None):
    now = time.time() if now is None else now
    try:
        rows = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise FeedError("not JSON")
    if not isinstance(rows, list):
        raise FeedError("expected a JSON list")
    ips = {}
    for r in rows:
        if not isinstance(r, dict):
            raise FeedError("unexpected entry")
        ip = norm_ip(r.get("ip_address"))
        if not ip or not public_ip(ip):
            continue
        status = str(r.get("status") or "")[:16]
        last = _date_ts(r.get("last_online"))
        old = status != "online" and (last is None or last < now - FEED_OLD_C2_DAYS * 86400)
        port = r.get("port")
        ips[ip] = {"m": str(r.get("malware") or "")[:48], "t": "botnet_cc",
                   "p": port if isinstance(port, int) else None, "st": "old" if old else (status or "listed")}
    if rows and not ips:
        raise FeedError("no usable entries")
    return {"ip": ips, "domain": {}}


def parse_hostfile(data, now=None):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise FeedError("not UTF-8 text")
    if "<html" in text[:2048].lower():
        raise FeedError("got an HTML page, not a host file")
    ips, doms = {}, {}
    seen_lines = 0
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        seen_lines += 1
        parts = line.split()
        host = parts[1] if len(parts) >= 2 else parts[0]
        ip = norm_ip(host)
        if ip:
            if public_ip(ip):
                ips[ip] = {"t": "malware_host"}
            continue
        d = norm_domain(host)
        if d and d not in ("localhost", "localhost.localdomain"):
            doms[d] = {"t": "malware_host"}
    if seen_lines and not (ips or doms):
        raise FeedError("no usable entries")
    if not seen_lines:
        raise FeedError("empty file")
    return {"ip": ips, "domain": doms}


def parse_threatfox_csv(stream, min_confidence=50):
    """stream: text lines of ThreatFox's CSV export. Header is the last
    '# "first_seen_utc",...' comment line; values are quoted with ", "."""
    header = None
    ips, doms = {}, {}
    rows = 0
    for line in stream:
        if line.startswith("#"):
            h = line.lstrip("#").strip()
            if "ioc_value" in h and "ioc_type" in h:
                header = next(csv.reader([h], skipinitialspace=True))
            continue
        if not line.strip():
            continue
        if header is None:
            raise FeedError("CSV header not found")
        rec = next(csv.reader([line], skipinitialspace=True), None)
        if not rec:
            continue
        row = dict(zip(header, rec))
        rows += 1
        try:
            conf = int(row.get("confidence_level") or 0)
        except ValueError:
            conf = 0
        if conf < min_confidence:
            continue
        typ = row.get("ioc_type") or ""
        val = (row.get("ioc_value") or "").strip()
        meta = {"m": (row.get("malware_printable") or row.get("fk_malware") or "")[:48],
                "t": (row.get("threat_type") or "")[:24], "c": conf}
        if typ == "ip:port":
            host, _, port = val.rpartition(":")
            ip = norm_ip(host)
            if ip and public_ip(ip):
                meta["p"] = int(port) if port.isdigit() else None
                ips[ip] = meta
        elif typ == "domain":
            d = norm_domain(val)
            if d:
                doms[d] = meta
        elif typ == "url":
            m = re.match(r"^[a-z][a-z0-9+.-]*://\[?([^/\]:?#]+)", val, re.I)
            if m:
                ip = norm_ip(m.group(1))
                if ip:
                    if public_ip(ip):
                        ips.setdefault(ip, meta)
                else:
                    d = norm_domain(m.group(1))
                    if d:
                        doms.setdefault(d, meta)
    if header is None:
        raise FeedError("CSV header not found")
    if rows and not (ips or doms):
        raise FeedError("no usable entries above the confidence threshold")
    return {"ip": ips, "domain": doms}


def parse_threatfox_zip(data, now=None, max_unzipped=512 << 20, min_confidence=50):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise FeedError("not a ZIP file")
    names = [i for i in zf.infolist() if i.filename.lower().endswith(".csv")]
    if not names:
        raise FeedError("no CSV in the ZIP")
    info = names[0]
    if info.file_size > max_unzipped:
        raise FeedError("CSV too large (%d bytes)" % info.file_size)
    with zf.open(info) as raw:
        text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
        return parse_threatfox_csv(text, min_confidence=min_confidence)


def _date_ts(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(str(value)[:19], fmt))
        except ValueError:
            continue
    return None


PARSERS = {"feodo_json": parse_feodo_json, "hostfile": parse_hostfile}


def compact(parsed):
    """{"ip": {k: meta}, "domain": {k: meta}} -> the file layout with each
    distinct meta stored once."""
    metas, index = [], {}

    def ref(m):
        key = json.dumps(m, sort_keys=True)
        i = index.get(key)
        if i is None:
            i = index[key] = len(metas)
            metas.append(m)
        return i
    return {"meta": metas, "ip": {k: ref(v) for k, v in parsed["ip"].items()},
            "domain": {k: ref(v) for k, v in parsed["domain"].items()}}


def expand(data):
    """Loaded feed file -> (ip dict, domain dict) of meta dicts (shared)."""
    metas = data.get("meta") if isinstance(data.get("meta"), list) else []
    out = []
    for kind in ("ip", "domain"):
        src = data.get(kind) if isinstance(data.get(kind), dict) else {}
        d = {}
        for k, i in src.items():
            if isinstance(i, int) and 0 <= i < len(metas) and isinstance(metas[i], dict):
                d[k] = metas[i]
            elif isinstance(i, dict):
                d[k] = i
        out.append(d)
    return out[0], out[1]


def parse_feed(name, data, now=None):
    spec = FEEDS[name]
    if spec["format"] == "threatfox_csv_zip":
        return parse_threatfox_zip(data, now, spec.get("max_unzipped", 512 << 20),
                                   spec.get("min_confidence", 50))
    return PARSERS[spec["format"]](data, now)


# ── download ────────────────────────────────────────────────────────────────

class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not str(newurl).lower().startswith("https://"):
            raise FeedError("redirect to a non-HTTPS URL refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url, etag=None, last_modified=None, max_bytes=8 << 20, timeout=HTTP_TIMEOUT):
    """(status, body bytes or None, headers dict). 304 -> body None."""
    if not url.lower().startswith("https://"):
        raise FeedError("only HTTPS feed URLs are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if etag:
        req.add_header("If-None-Match", etag)
    if last_modified:
        req.add_header("If-Modified-Since", last_modified)
    opener = urllib.request.build_opener(_HttpsOnlyRedirect(),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, None, dict(exc.headers or {})
        raise
    with resp:
        length = resp.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > max_bytes:
            raise FeedError("download larger than the %d MB cap" % (max_bytes >> 20))
        chunks, total = [], 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise FeedError("download larger than the %d MB cap" % (max_bytes >> 20))
            chunks.append(chunk)
        return resp.status, b"".join(chunks), {k.lower(): v for k, v in resp.headers.items()}


def describe_error(exc):
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return "auth", "the abuse.ch Auth-Key was rejected (HTTP %d)" % exc.code
        if exc.code == 410:
            return "gone", "HTTP 410: abuse.ch retired this keyless URL (an Auth-Key is needed)"
        if exc.code == 429:
            return "error", "HTTP 429: rate limited by the feed server"
        return "error", "HTTP %d" % exc.code
    if isinstance(exc, urllib.error.URLError):
        return "unreachable", "feed server unreachable (no internet, DNS, or egress blocked by Tripwire): %s" \
            % getattr(exc, "reason", exc)
    if isinstance(exc, (TimeoutError, OSError)):
        return "unreachable", "feed server unreachable (%s)" % exc.__class__.__name__
    if isinstance(exc, FeedError):
        return "invalid", str(exc)
    return "error", "%s: %s" % (exc.__class__.__name__, exc)


def read_key(conf_dir, cred_dir=None):
    """The optional abuse.ch Auth-Key: systemd credential first, then the
    0600 file (manual root runs, tests). '' when absent/invalid."""
    cands = []
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY") if cred_dir is None else cred_dir
    if cred_dir:
        cands.append(os.path.join(cred_dir, "abusech-key"))
    cands.append(os.path.join(conf_dir, "abuse-ch.key"))
    for p in cands:
        try:
            with open(p, encoding="utf-8") as f:
                k = f.read(512).strip()
        except OSError:
            continue
        if KEY_RE.match(k):
            return k
    return ""


def _atomic_json(path, obj, mode=0o640):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, separators=(",", ":"), sort_keys=True)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_state(feeds_dir):
    try:
        with open(os.path.join(feeds_dir, "state.json"), encoding="utf-8") as f:
            st = json.load(f)
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def enabled_feeds(config):
    sel = (config or {}).get("feeds") if isinstance(config, dict) else None
    out = []
    for name in FEEDS:
        on = True
        if isinstance(sel, dict) and name in sel:
            on = bool(sel[name])
        if on:
            out.append(name)
    return out


def update_feeds(feeds_dir, conf_dir, config=None, force=False, now=None, fetch=None, only=None, log=None):
    """Fetch every enabled feed that is due. Returns the new state dict.
    fetch(url, etag, last_modified, max_bytes) -> (status, body, headers)
    is injectable for tests."""
    now = time.time() if now is None else now
    fetch = fetch or (lambda url, etag, lm, mx: http_get(url, etag, lm, mx))
    log = log or (lambda msg: print(msg, flush=True))
    key = read_key(conf_dir)
    state = load_state(feeds_dir)
    on = enabled_feeds(config)
    for name, spec in FEEDS.items():
        if only and name not in only:
            continue
        st = state.setdefault(name, {})
        st["enabled"] = name in on
        st["needs_key"] = spec["needs_key"]
        st["key_set"] = bool(key) if spec["needs_key"] else None
        if name not in on:
            st["status"] = "disabled"
            continue
        if spec["needs_key"] and not key:
            st.update(status="needs_key", error="free abuse.ch Auth-Key required (auth.abuse.ch); "
                                               "add it in the dashboard's threat-feed settings", last_attempt=now)
            continue
        last = st.get("last_attempt") or 0
        # a failed feed is retried hourly (the timer's pace), a good one per its interval
        interval = spec["interval"] if st.get("status") == "ok" else RETRY_INTERVAL
        due = now - last >= (MIN_FORCED_INTERVAL if force else interval - 300)
        if not due:
            continue
        url = spec["url"].replace("{key}", key)
        st["last_attempt"] = now
        have_file = os.path.exists(os.path.join(feeds_dir, name + ".json"))
        try:
            status, body, headers = fetch(url, st.get("etag") if have_file else None,
                                          st.get("last_modified") if have_file else None, spec["max_bytes"])
            if status == 304:
                st.update(status="ok", error=None, last_checked=now, last_ok=now)
                log("devicewatch feeds: %s not modified" % name)
                continue
            parsed = parse_feed(name, body, now)
            out = dict(compact(parsed), schema=SCHEMA, feed=name, fetched_at=int(now),
                       source_modified=headers.get("last-modified"))
            _atomic_json(os.path.join(feeds_dir, name + ".json"), out)
            st.update(status="ok", error=None, last_ok=now, last_checked=now, last_changed=now,
                      etag=headers.get("etag"), last_modified=headers.get("last-modified"),
                      count={"ip": len(parsed["ip"]), "domain": len(parsed["domain"])},
                      bytes=len(body))
            log("devicewatch feeds: %s ok (%d IPs, %d domains)" % (name, len(parsed["ip"]), len(parsed["domain"])))
        except Exception as exc:
            kind, msg = describe_error(exc)
            msg = mask(msg, key)[:300]
            st.update(status=kind, error=msg)
            log("devicewatch feeds: %s failed, keeping the last good copy: %s" % (name, msg))
    state["_updated"] = now
    _atomic_json(os.path.join(feeds_dir, "state.json"), state)
    return state


def feed_status(feeds_dir, conf_dir=None, config=None, key_set=None):
    """Public status rows for the API (no key, no key-bearing URL)."""
    state = load_state(feeds_dir)
    on = enabled_feeds(config)
    rows = []
    for name, spec in FEEDS.items():
        st = state.get(name) or {}
        status = st.get("status") or "pending"
        if name not in on:
            status = "disabled"
        elif spec["needs_key"] and key_set is False:
            status = "needs_key"
        rows.append({
            "name": name, "title": spec["title"], "homepage": spec["homepage"],
            "licence": spec["licence"], "attribution": spec["attribution"],
            "needs_key": spec["needs_key"], "enabled": name in on, "status": status,
            "error": st.get("error") if status not in ("ok", "disabled") else None,
            "last_ok": st.get("last_ok"), "last_attempt": st.get("last_attempt"),
            "last_changed": st.get("last_changed"), "count": st.get("count") or {"ip": 0, "domain": 0},
        })
    return rows
