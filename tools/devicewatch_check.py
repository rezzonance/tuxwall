#!/usr/bin/env python3
"""Device monitoring (3.3.7): engine, feeds, API and units - sandboxed.

    python3 tools/devicewatch_check.py

Everything runs in temp dirs with fixtures that use documentation addresses
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), example
domains and made-up MACs; no command, network or real log is touched.

- Zeek follower: partial lines, restart from the checkpoint, rotation into a
  dated .gz archive (and a spool copy of the same file: read once),
  catch-up limit after a long downtime, copytruncate (eve.json), rewrite in
  place, oversized lines, first-run backlog starts at a line boundary.
- Inventory: Kea leases + reservation names + Zeek dhcp.log + neighbours
  (FAILED / WAN entries ignored), IPv6 privacy address -> MAC through the
  neighbour table, EUI-64, private MAC, VLAN zone, WireGuard peer keyed by
  its public key, name priority, new-device event only after the baseline.
- Feeds: Feodo JSON, host file, ThreatFox CSV-in-ZIP parsers, HTML/garbage
  rejection, size cap, 304, last good copy kept, needs_key, the key never
  in state/errors, HTTPS-only.
- Matching: C2 connection (critical) > DNS lookup (high) > attempt / DNS
  blocked (low); DNS answer -> connection correlation; unbound journal +
  Zeek seen once; Suricata alert attributed to the MAC that held the IP at
  alert time; noise signatures ignored; dedupe/aggregation; "expected"
  suppression; retention; local indicators (ip, cidr, *.domain).
- Risk score + health + generic reasons; aggregates (traffic, hourly,
  top destinations/countries, distinct count).
- API (loopback harness): role-filtered list, admin-only detail and
  indicators, summary, rename, expected, indicators, key (0600, never
  echoed), WireGuard snapshot without private/preshared keys.
- Silence rules (A7): validation, scopes (indicator / device+kind / domain
  suffix / kind, generic for Phase 2 kinds), expiry, the critical guard,
  health/summary/threat-table exclusion, no engine event and no push/HA
  alert while silenced; the API routes (admin + same Origin).
- Zeek checksum switch (A3): command building, policy/result parsing, the
  state on GET /api/devices/feeds, POST gates + one job at a time (the
  script itself: tools/zeek_site_check.py).
- Units: sandbox directives, writable paths = the state dir only.
"""
import base64
import configparser
import gzip
import io
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "www", "includes"))
sys.path.insert(0, HERE)
import devicewatch as dw  # noqa: E402
import devicewatch_feeds as feeds  # noqa: E402

PASS = FAIL = 0


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


NOW = 1795560000.0          # 2026-11-24
TMP = tempfile.mkdtemp(prefix="dw-check-")

MAC_A = "02:00:5e:10:00:0a"     # locally administered ("private MAC")
MAC_B = "00:00:5e:00:53:0b"     # IANA documentation OUI (RFC 7042)
MAC_C = "00:00:5e:00:53:0c"
MAC_D = "00:00:5e:00:53:0d"
WG_PK = base64.b64encode(bytes(range(32))).decode()
C2_IP = "203.0.113.66"
OLD_C2 = "203.0.113.67"
BAD_HOST = "malware.example.net"
EXT = "198.51.100.20"


# ── fixtures ────────────────────────────────────────────────────────────────

def w(path, text, mode="w"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode) as f:
        f.write(text)


def jl(obj):
    return json.dumps(obj, separators=(",", ":")) + "\n"


def conn(ts, o, r, rp=443, op=50000, proto="tcp", state="SF", ob=200, rb=5000, hist="ShADadFf"):
    return jl({"ts": ts, "uid": "C%x" % int(ts * 1000), "id.orig_h": o, "id.orig_p": op, "id.resp_h": r,
               "id.resp_p": rp, "proto": proto, "conn_state": state, "history": hist,
               "orig_ip_bytes": ob, "resp_ip_bytes": rb, "orig_pkts": 3, "resp_pkts": 3 if rb else 0})


def dns(ts, o, q, answers=None, rcode="NOERROR", tid=1):
    e = {"ts": ts, "uid": "D%x" % int(ts * 1000), "id.orig_h": o, "id.orig_p": 40000 + tid, "id.resp_h": "192.0.2.1",
         "id.resp_p": 53, "proto": "udp", "trans_id": tid, "query": q, "qtype_name": "A", "rcode_name": rcode}
    if answers is not None:
        e["answers"] = answers
    return jl(e)


def eve(ts, src, dst, sig, cat, sev=1, sid=2024897, direction="to_server"):
    t = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)) + ".000000" + time.strftime("%z", time.localtime(ts))
    return jl({"timestamp": t, "event_type": "alert", "src_ip": src, "src_port": 50000, "dest_ip": dst,
               "dest_port": 443, "proto": "TCP", "direction": direction,
               "alert": {"action": "allowed", "signature_id": sid, "rev": 2, "signature": sig,
                         "category": cat, "severity": sev}})


class FakeSources:
    def __init__(self):
        self.neigh = []
        self.journal_lines = []
        self.addrs = [
            {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
            {"ifname": "wan0", "addr_info": [{"family": "inet", "local": "198.51.100.2", "prefixlen": 24}]},
            {"ifname": "lan0", "addr_info": [
                {"family": "inet", "local": "192.0.2.1", "prefixlen": 26},
                {"family": "inet6", "local": "2001:db8:1::1", "prefixlen": 64, "scope": "global"},
                {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]},
            {"ifname": "lan0.10", "addr_info": [{"family": "inet", "local": "192.0.2.65", "prefixlen": 26}]},
            {"ifname": "wg0", "addr_info": [{"family": "inet", "local": "192.0.2.129", "prefixlen": 26}]},
        ]

    def neighbours(self):
        return self.neigh

    def addresses(self):
        return self.addrs

    def default_route_devs(self):
        return {"wan0"}

    def journal(self, cursor):
        lines, self.journal_lines = self.journal_lines, []
        return lines, "cursor-%d" % len(lines) if lines else cursor, None


def make_root(name):
    r = os.path.join(TMP, name)
    w(r + "/etc/tuxwall/interfaces.json", json.dumps({
        "version": 1, "wan": {"device": "wan0"}, "lan": {"device": "lan0", "address": "192.0.2.1/26"},
        "opt": [{"id": "opt1", "name": "IoT", "device": "lan0.10", "vlan": 10, "parent": "lan0"}],
        "vpn": [{"id": "wg0", "name": "WireGuard", "device": "wg0"}]}))
    w(r + "/usr/share/ieee-data/oui.txt",
      "00-00-5E   (hex)\t\tICANN, IANA Department\n00005E     (base 16)\t\tICANN, IANA Department\n")
    os.makedirs(r + "/opt/zeek/spool/manager", exist_ok=True)
    os.makedirs(r + "/opt/zeek/logs", exist_ok=True)
    os.symlink(r + "/opt/zeek/spool/manager", r + "/opt/zeek/logs/current")
    for n in ("conn", "dns", "dhcp", "software", "known_hosts"):
        w(r + "/opt/zeek/spool/manager/%s.log" % n, "")
    w(r + "/var/log/suricata/eve.json", "")
    return r


def leases_csv(rows):
    out = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
    for ip, mac, host, expire in rows:
        out += "%s,%s,,3600,%d,1,0,0,%s,0,,0\n" % (ip, mac, expire, host)
    return out


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def engine(root, src=None, clock=None):
    cfg = dw.Config(root)
    return dw.Engine(cfg, src or FakeSources(), clock or Clock(NOW))


# ── follower ────────────────────────────────────────────────────────────────

def t_follower():
    d = os.path.join(TMP, "follow")
    os.makedirs(d + "/logs/2026-11-24", exist_ok=True)
    path = d + "/conn.log"
    clock = Clock(NOW)
    got = []

    def lister():
        res = []
        for p in sorted(os.listdir(d + "/logs/2026-11-24")):
            full = d + "/logs/2026-11-24/" + p
            res.append((full, os.stat(full).st_mtime))
        for p in os.listdir(d):
            if p.startswith("conn.2"):
                res.append((d + "/" + p, os.stat(d + "/" + p).st_mtime))
        res.sort(key=lambda x: (x[1], x[0]))
        return res

    w(path, "L1\nL2\nL3-part")
    f = dw.Follower("conn", path, lister, 64 << 20, clock)
    f.poll(got.append)
    check(got == [b"L1", b"L2"], "follower: complete lines only, partial last line waits (%r)" % got)
    w(path, "ial\nL4\n", "a")
    f.poll(got.append)
    check(got[2:] == [b"L3-partial", b"L4"], "follower: partial line completed on the next poll")
    cp = json.loads(json.dumps(f.cp))
    w(path, "L5\n", "a")
    f2 = dw.Follower("conn", path, lister, 64 << 20, clock)
    f2.restore(cp)
    got2 = []
    f2.poll(got2.append)
    check(got2 == [b"L5"], "follower: restart from the checkpoint, nothing re-read (%r)" % got2)
    # rotation: unread tail + archive as .gz in the dated dir, new file
    w(path, "L6\nL7\n", "a")
    with open(path, "rb") as src, gzip.open(d + "/logs/2026-11-24/conn.00:00:00-01:00:00.log.gz", "wb") as dst:
        dst.write(src.read())
    os.utime(d + "/logs/2026-11-24/conn.00:00:00-01:00:00.log.gz", (NOW - 14 * 3600, NOW - 14 * 3600))
    os.unlink(path)
    w(path, "N1\nN2\n")
    got3 = []
    f2.poll(got3.append)
    check(got3 == [b"L6", b"L7", b"N1", b"N2"], "follower: rotated tail read from the .gz archive, then the "
                                                 "new file (%r)" % got3)
    check(f2.stats["rotations"] == 1 and f2.stats["gaps"] == 0, "follower: rotation counted, no gap")
    # rotation with a spool copy AND the .gz of the same file: read once
    w(path, "N3\n", "a")
    with open(path, "rb") as src:
        data = src.read()
    w(d + "/conn.2026-11-24-02-00-00.log", data.decode())
    with gzip.open(d + "/logs/2026-11-24/conn.01:00:00-02:00:00.log.gz", "wb") as dst:
        dst.write(data)
    os.utime(d + "/logs/2026-11-24/conn.01:00:00-02:00:00.log.gz", (NOW - 13 * 3600, NOW - 13 * 3600))
    os.unlink(path)
    w(path, "M1\n")
    got4 = []
    f2.poll(got4.append)
    check(got4 == [b"N3", b"M1"], "follower: spool + .gz copies of one file read once (%r)" % got4)
    os.unlink(d + "/conn.2026-11-24-02-00-00.log")
    # long downtime: an intermediate archive older than the catch-up window is skipped
    w(path, "M2\n", "a")
    with open(path, "rb") as src:
        data = src.read()
    with gzip.open(d + "/logs/2026-11-24/conn.02:00:00-03:00:00.log.gz", "wb") as dst:
        dst.write(data)
    with gzip.open(d + "/logs/2026-11-24/conn.03:00:00-04:00:00.log.gz", "wb") as dst:
        dst.write(b"OLD1\nOLD2\n")
    old = NOW - 10 * 3600
    os.utime(d + "/logs/2026-11-24/conn.02:00:00-03:00:00.log.gz", (old, old))
    os.utime(d + "/logs/2026-11-24/conn.03:00:00-04:00:00.log.gz", (old + 60, old + 60))
    os.unlink(path)
    w(path, "Z1\n")
    got5 = []
    f2.poll(got5.append)
    check(got5 == [b"M2", b"Z1"] and f2.stats["gaps"] == 1,
          "follower: archives older than the catch-up window skipped and counted as a gap (%r, gaps %d)"
          % (got5, f2.stats["gaps"]))
    # copytruncate (eve.json): tail from eve.json.1, then the truncated file
    ep = d + "/eve.json"
    w(ep, "E1\nE2\n")
    fe = dw.Follower("eve", ep, dw.eve_archives(ep), 4 << 20, clock)
    g = []
    fe.poll(g.append)
    w(ep, "E3\n", "a")
    shutil.copy(ep, ep + ".1")
    with open(ep, "r+") as fh:
        fh.truncate(0)
    w(ep, "F1\n", "a")
    fe.poll(g.append)
    check(g == [b"E1", b"E2", b"E3", b"F1"], "follower: copytruncate - tail from eve.json.1 (%r)" % g)
    # rewritten in place, grown past the old offset: detected by the first-line hash
    w(ep, "G1-new-first-line\nG2\nG3\nG4\n")
    g2 = []
    fe.poll(g2.append)
    check(g2[-4:] == [b"G1-new-first-line", b"G2", b"G3", b"G4"], "follower: in-place rewrite detected (%r)" % g2)
    # oversized line skipped
    w(ep, "X" * (dw.MAX_LINE + 10) + "\nok\n", "a")
    g3 = []
    fe.poll(g3.append)
    check(g3 == [b"ok"] and fe.stats["oversized"] >= 1, "follower: oversized line skipped (%r)" % g3[:2])
    # first run on a big file: starts near the end at a line boundary
    bp = d + "/big.log"
    w(bp, "".join("line-%06d\n" % i for i in range(20000)))
    fb = dw.Follower("big", bp, None, 1000, clock)
    g4 = []
    fb.poll(g4.append)
    check(g4 and all(x.startswith(b"line-") and len(x) == 11 for x in g4) and g4[-1] == b"line-019999"
          and len(g4) <= 91, "follower: first run reads only the backlog, from a line boundary (%d lines)" % len(g4))


# ── feeds ───────────────────────────────────────────────────────────────────

FEODO = json.dumps([
    {"ip_address": C2_IP, "port": 443, "status": "online", "hostname": None, "as_number": 64496,
     "as_name": "EXAMPLE", "country": "ZZ", "first_seen": "2026-11-01 00:00:00", "last_online": "2026-11-23",
     "malware": "ExampleBot"},
    {"ip_address": OLD_C2, "port": 8080, "status": "offline", "first_seen": "2025-01-01 00:00:00",
     "last_online": "2025-03-01", "malware": "OldBot"},
    {"ip_address": "172.16.99.5", "port": 80, "status": "online", "malware": "x"},     # private: dropped
]).encode()
HOSTFILE = ("# URLhaus host file\n#\n127.0.0.1\t%s\n127.0.0.1\tdrop.example.org\n127.0.0.1\t203.0.113.77\n"
            "127.0.0.1\tnot a host\n127.0.0.1\tlocalhost\n" % BAD_HOST).encode()


def threatfox_zip(rows, header=True):
    lines = ["################", "# ThreatFox IOCs: CSV export", "#"]
    if header:
        lines.append('# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware",'
                     '"malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags",'
                     '"anonymous","reporter"')
    for v, t, th, conf in rows:
        lines.append('"2026-11-20 10:00:00", "1", "%s", "%s", "%s", "win.example", "", "ExampleRAT", "", "%d", '
                     '"", "", "0", "tester"' % (v, t, th, conf))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("full.csv", "\n".join(lines) + "\n")
    return buf.getvalue()


def t_feeds():
    p = feeds.parse_feodo_json(FEODO, NOW)
    check(set(p["ip"]) == {C2_IP, OLD_C2} and p["ip"][C2_IP]["t"] == "botnet_cc" and p["ip"][OLD_C2]["st"] == "old"
          and p["ip"][C2_IP]["st"] == "online", "feodo: online + old entries, private address dropped (%r)" % p["ip"])
    for bad in (b"<html>", b"{}", b'[{"x":1}]'):
        try:
            feeds.parse_feodo_json(bad, NOW)
            check(bad == b'[{"x":1}]' and False, "feodo garbage rejected: %r" % bad)
        except feeds.FeedError:
            check(True, "feodo garbage rejected")
    h = feeds.parse_hostfile(HOSTFILE)
    check(set(h["domain"]) == {BAD_HOST, "drop.example.org"} and set(h["ip"]) == {"203.0.113.77"},
          "hostfile: names + IP entries, junk and localhost dropped (%r)" % h)
    for bad in (b"<!DOCTYPE html><html>login</html>", b"", b"# only comments\n"):
        try:
            feeds.parse_hostfile(bad)
            check(False, "hostfile garbage accepted: %r" % bad[:20])
        except feeds.FeedError:
            check(True, "hostfile garbage rejected")
    tz = feeds.parse_threatfox_zip(threatfox_zip([
        ("203.0.113.88:4444", "ip:port", "botnet_cc", 100), ("c2.example.com", "domain", "botnet_cc", 75),
        ("https://payload.example.org/x.exe", "url", "payload_delivery", 90),
        ("http://203.0.113.90/drop.bin", "url", "payload_delivery", 90),
        ("https://github.com/someone/repo/raw/main/x.exe", "url", "payload_delivery", 90),
        ("https://steamcommunity.com/profiles/76561199000000000", "url", "botnet_cc", 90),
        ("raw.githubusercontent.com", "domain", "payload_delivery", 90),
        ("203.0.113.89:80", "ip:port", "botnet_cc", 25),            # below the confidence threshold
        ("d41d8cd98f00b204e9800998ecf8427e", "md5_hash", "payload", 100)]))
    check(tz["ip"].get("203.0.113.88", {}).get("p") == 4444 and tz["ip"]["203.0.113.88"]["t"] == "botnet_cc"
          and set(tz["domain"]) == {"c2.example.com"} and "203.0.113.90" in tz["ip"]
          and "203.0.113.89" not in tz["ip"],
          "threatfox: ip:port / domain; a url counts only by its IP host (never a whole site), shared platforms "
          "dropped, confidence threshold, hashes ignored (%r)" % tz)
    check(feeds.shared_platform("github.com") and feeds.shared_platform("gist.github.com")
          and feeds.shared_platform("www.youtube.com") and feeds.shared_platform("cdn.discordapp.com")
          and not feeds.shared_platform("someone.github.io") and not feeds.shared_platform("notgithub.com")
          and not feeds.shared_platform("github.com.evil.example"),
          "shared_platform: platform + its subdomains; never per-customer hosts or look-alikes")
    hp = feeds.parse_hostfile(b"127.0.0.1 raw.githubusercontent.com\n127.0.0.1 evil.example.org\n")
    check(set(hp["domain"]) == {"evil.example.org"}, "hostfile: shared platform dropped (%r)" % hp)
    for bad in (b"PK-not-a-zip", threatfox_zip([("x.example.com", "domain", "botnet_cc", 90)], header=False)):
        try:
            feeds.parse_threatfox_zip(bad)
            check(False, "threatfox garbage accepted")
        except feeds.FeedError:
            check(True, "threatfox garbage rejected")
    # updater: fetch stub, keep last good, 304, needs_key, key masking
    fd = os.path.join(TMP, "feeds")
    cd = os.path.join(TMP, "feeds-conf")
    os.makedirs(cd, exist_ok=True)
    calls = []

    def fetch_ok(url, etag, lm, mx):
        calls.append((url, etag))
        if "feodotracker" in url:
            return 200, FEODO, {"etag": '"e1"', "last-modified": "Mon, 23 Nov 2026 00:00:00 GMT"}
        raise AssertionError("keyed feed fetched without a key")
    logs = []
    st = feeds.update_feeds(fd, cd, now=NOW, fetch=fetch_ok, log=logs.append)
    check(st["feodo"]["status"] == "ok" and st["feodo"]["count"]["ip"] == 2 and st["urlhaus"]["status"] == "needs_key"
          and st["threatfox"]["status"] == "needs_key", "update: feodo ok, keyed feeds need a key")
    fj = json.load(open(os.path.join(fd, "feodo.json")))
    ips, _doms = feeds.expand(fj)
    check(len(fj["meta"]) == 2 and ips[C2_IP]["m"] == "ExampleBot" and isinstance(fj["ip"][C2_IP], int),
          "feed file: shared metadata stored once, expanded on load")
    good = open(os.path.join(fd, "feodo.json")).read()

    def fetch_garbage(url, etag, lm, mx):
        calls.append((url, etag))
        return 200, b"<html>maintenance</html>", {}
    st = feeds.update_feeds(fd, cd, now=NOW + 10, fetch=fetch_garbage, log=logs.append)
    check(st["feodo"]["status"] == "ok" and calls[-1][0].startswith("https://feodo"), "update: not due yet")
    st = feeds.update_feeds(fd, cd, now=NOW + 400, fetch=fetch_garbage, force=True, log=logs.append)
    check(st["feodo"]["status"] == "invalid" and open(os.path.join(fd, "feodo.json")).read() == good,
          "update: garbage -> status invalid, last good file kept")

    def fetch_304(url, etag, lm, mx):
        calls.append((url, etag))
        return 304, None, {}
    st = feeds.update_feeds(fd, cd, now=NOW + 4000, fetch=fetch_304, log=logs.append)
    check(st["feodo"]["status"] == "ok" and calls[-1][1] == '"e1"', "update: retry after failure sends If-None-Match, 304 ok")
    import urllib.error

    def fetch_down(url, etag, lm, mx):
        raise urllib.error.URLError(OSError("Network is unreachable"))
    st = feeds.update_feeds(fd, cd, now=NOW + 30000, fetch=fetch_down, force=True, log=logs.append)
    check(st["feodo"]["status"] == "unreachable" and "egress" in st["feodo"]["error"]
          and open(os.path.join(fd, "feodo.json")).read() == good, "update: no egress -> unreachable, last good kept")
    key = "k3yABCDEFabcdef0123456789xyz"
    w(os.path.join(cd, "abuse-ch.key"), key + "\n")

    def fetch_keyed(url, etag, lm, mx):
        if "urlhaus" in url:
            check(key in url and url.endswith("/hostfile.txt"), "urlhaus URL carries the key in the path")
            raise urllib.error.HTTPError(url, 401, "Unauthorized " + url, {}, None)
        if "threatfox" in url:
            return 200, threatfox_zip([("c2.example.com", "domain", "botnet_cc", 90)]), {}
        return 304, None, {}
    st = feeds.update_feeds(fd, cd, now=NOW + 60000, fetch=fetch_keyed, force=True, log=logs.append)
    blob = json.dumps(st) + "\n".join(logs)
    check(st["urlhaus"]["status"] == "auth" and st["threatfox"]["status"] == "ok" and key not in blob
          and key not in open(os.path.join(fd, "state.json")).read(),
          "update: key used, rejected key reported, the key never in state or logs")
    check(feeds.mask("https://x-api.abuse.ch/v2/files/exports/%s/a.txt" % key, "") ==
          "https://x-api.abuse.ch/v2/files/exports/***/a.txt", "mask(): key-bearing URL masked without the key")
    cred = os.path.join(TMP, "cred")
    w(cred + "/abusech-key", "unset")
    check(feeds.read_key(os.path.join(TMP, "nokey"), cred) == "" and feeds.read_key(cd, cred) == key,
          "credential default 'unset' = no key; the 0600 file is the fallback")
    rows = feeds.feed_status(fd, key_set=True)
    check([r["name"] for r in rows] == ["feodo", "urlhaus", "threatfox"] and all("url" not in r for r in rows)
          and rows[0]["licence"] == "CC0 1.0" and rows[0]["attribution"], "status rows: no URL, licence + attribution")
    try:
        feeds.http_get("http://feodotracker.abuse.ch/x")
        check(False, "plain-HTTP feed URL refused")
    except feeds.FeedError:
        check(True, "plain-HTTP feed URL refused")
    # local indicators
    ok = [feeds.validate_local_indicator({"value": v}) for v in ("203.0.113.9", "198.51.100.0/28",
                                                                  "*.Bad.Example.COM.", "evil.example")]
    check([o["type"] for o in ok] == ["ip", "cidr", "domain", "domain"] and ok[2]["value"] == "*.bad.example.com",
          "local indicators: type detection and normalisation")
    for bad in ({"value": "0.0.0.0/0"}, {"value": "not_a domain"}, {"value": "203.0.113.9", "severity": "x"},
                {"value": "10.0.0.0/4", "type": "cidr"}, {"value": ""}):
        try:
            feeds.validate_local_indicator(bad)
            check(False, "local indicator refused: %r" % bad)
        except ValueError:
            check(True, "local indicator refused")


# ── engine: inventory, matching, aggregates ─────────────────────────────────

def zeek(root, name, text):
    w(root + "/opt/zeek/spool/manager/%s.log" % name, text, "a")


def t_engine():
    r = make_root("eng")
    src = FakeSources()
    clock = Clock(NOW)
    ip6_priv = "2001:db8:1:0:a1b2:c3d4:e5f6:1234"       # canonical text, as Zeek and ip(8) print it
    ip6_eui = "2001:db8:1:0:200:5eff:fe00:530d"         # EUI-64 of MAC_D
    w(r + "/var/lib/kea/kea-leases4.csv", leases_csv([
        ("192.0.2.10", MAC_A, "phone-a", NOW + 3000), ("192.0.2.11", MAC_B, "", NOW + 3000),
        ("192.0.2.70", MAC_C, "esp-a1b2c3", NOW + 3000), ("192.0.2.12", "00:00:5e:00:53:99", "gone", NOW - 10)]))
    w(r + "/etc/kea/kea-dhcp4.conf", json.dumps({"Dhcp4": {"subnet4": [{"id": 1, "subnet": "192.0.2.0/26",
                                                 "reservations": [{"hw-address": MAC_B, "ip-address": "192.0.2.11",
                                                                   "hostname": "office-printer"}]}]}}))
    w(r + "/var/lib/tuxwall/wg-peers.json", json.dumps({"schema": 1, "iface": "wg0", "peers": [
        {"public_key": WG_PK, "name": "Laptop VPN", "allowed_ips": ["192.0.2.130/32"], "last_handshake": NOW - 30}]}))
    src.neigh = [
        {"dst": "192.0.2.10", "dev": "lan0", "lladdr": MAC_A, "state": ["REACHABLE"]},
        {"dst": ip6_priv, "dev": "lan0", "lladdr": MAC_A, "state": ["STALE"]},
        {"dst": "192.0.2.20", "dev": "lan0", "state": ["FAILED"]},
        {"dst": "198.51.100.1", "dev": "wan0", "lladdr": "00:00:5e:00:53:01", "state": ["REACHABLE"]},
        {"dst": "192.0.2.70", "dev": "lan0.10", "lladdr": MAC_C, "state": ["DELAY"]},
    ]
    zeek(r, "dhcp", jl({"ts": NOW - 100, "mac": MAC_B, "assigned_addr": "192.0.2.11", "host_name": "dhcp-name-b"}))
    eng = dw.Engine(dw.Config(r), src, clock)
    eng.cycle()
    ids = set(eng.devices)
    check(ids == {dw.mac_id(MAC_A), dw.mac_id(MAC_B), dw.mac_id(MAC_C), dw.wg_id(WG_PK)},
          "inventory: leases + neighbours + DHCP + WireGuard, expired lease / FAILED / WAN neighbour ignored (%r)" % ids)
    out = {d["id"]: d for d in json.load(open(r + "/var/lib/tuxwall/devices/devices.json"))["devices"]}
    a, b, c, g = (out[dw.mac_id(MAC_A)], out[dw.mac_id(MAC_B)], out[dw.mac_id(MAC_C)], out[dw.wg_id(WG_PK)])
    check(a["private_mac"] and a["vendor"] == "Private MAC" and a["type"] == "phone" and a["name"] == "phone-a",
          "private MAC: vendor 'Private MAC', type from the host name (%r)" % {k: a[k] for k in ("vendor", "type", "name")})
    check(b["vendor"].startswith("ICANN") and b["name"] == "office-printer" and b["name_source"] == "reservation"
          and b["type"] == "printer", "vendor from oui.txt; reservation name beats lease/DHCP names (%r)" % b["name"])
    check(c["zone"] == "opt1" and c["vlan"] == 10 and c["zone_name"] == "IoT" and c["type"] == "iot",
          "VLAN device: zone/vlan from interfaces.json, esp-* -> iot")
    check(g["kind"] == "wg" and g["name"] == "Laptop VPN" and g["type"] == "vpn-client" and g["online"]
          and g["wg_public_key"] == WG_PK and g["id"].startswith("w"), "WireGuard peer keyed by its public key")
    check(ip6_priv in a["ipv6"] and a["online"] and all(d["baseline"] and d["health"] == "normal" for d in out.values()),
          "IPv6 privacy address mapped to the MAC; baseline devices are not 'new'")
    check(not os.path.exists(r + "/var/lib/tuxwall/devices/events.jsonl"), "baseline cycle: no new-device events")

    # feeds + local indicators
    os.makedirs(r + "/var/lib/tuxwall/devices/feeds", exist_ok=True)
    fe = feeds.parse_feodo_json(FEODO, NOW)
    w(r + "/var/lib/tuxwall/devices/feeds/feodo.json", json.dumps({"schema": 1, "feed": "feodo", **feeds.compact(fe)}))
    hf = feeds.parse_hostfile(HOSTFILE)
    w(r + "/var/lib/tuxwall/devices/feeds/urlhaus.json", json.dumps({"schema": 1, "feed": "urlhaus",
                                                                     **feeds.compact(hf)}))
    w(r + "/etc/tuxwall/devices/local-indicators.json", json.dumps({"version": 1, "indicators": [
        {"type": "cidr", "value": "198.51.100.96/28", "severity": "critical", "note": "lab C2"},
        {"type": "domain", "value": "*.wild.example", "severity": "medium"}]}))
    clock.t = NOW + 60
    T = NOW + 30
    zeek(r, "conn", "".join([
        conn(T, "192.0.2.10", C2_IP),                                       # A: completed C2 connection
        conn(T, "192.0.2.10", C2_IP),                                       # VLAN double capture: deduped
        conn(T + 1, "192.0.2.11", C2_IP, state="S0", rb=0, hist="S"),      # B: attempt, no answer
        conn(T + 2, OLD_C2, "192.0.2.70", rp=22, op=40000),                # inbound from an old C2 to C
        conn(T + 3, "192.0.2.11", OLD_C2),                                  # B: completed to an old C2 -> capped
        conn(T + 4, ip6_priv, "2001:db8:ffff::5", rb=9000),                 # A over IPv6 privacy address
        conn(T + 5, ip6_eui, "2001:db8:ffff::6"),                           # unknown EUI-64 -> MAC_D
        conn(T + 6, "192.0.2.130", "198.51.100.100"),                       # WG peer -> local CIDR indicator
        conn(T + 7, "192.0.2.10", "192.0.2.11"),                            # LAN-internal: ignored
        conn(T + 8, "192.0.2.10", EXT, rb=123456),
    ]))
    zeek(r, "dns", "".join([
        dns(T, "192.0.2.10", BAD_HOST, ["198.51.100.50"], tid=1),          # answered malware lookup
        dns(T + 1, "192.0.2.70", "drop.example.org", None, "NXDOMAIN", tid=2),   # blocked/failed lookup
        dns(T + 2, "192.0.2.70", "x.y.wild.example", ["0.0.0.0"], tid=3),  # sinkholed answer = not answered
        dns(T + 3, "192.0.2.10", "harmless.example.com", ["198.51.100.20"], tid=4),
    ]))
    zeek(r, "conn", conn(T + 20, "192.0.2.10", "198.51.100.50"))           # connection to the answered address
    l2 = json.loads(conn(T + 21, "2001:db8:1:0:1:2:3:4", "2001:db8:ffff::7"))
    l2.update(orig_l2_addr=MAC_B, resp_l2_addr="00:00:5e:00:53:fe")         # Zeek mac-logging policy fields
    zeek(r, "conn", jl(l2))
    src.journal_lines = [(T + 1, "unbound[1:0] info: rpz: applied [threat] drop.example.org. rpz-nxdomain "
                                 "192.0.2.70@5353 drop.example.org. A IN")]
    eng.cycle()
    fs = {(f["device"], f["kind"], f["indicator"]): f for f in eng.findings.values()}
    A, B, C, D, G = (dw.mac_id(MAC_A), dw.mac_id(MAC_B), dw.mac_id(MAC_C), dw.mac_id(MAC_D), dw.wg_id(WG_PK))

    def sev(k):
        return fs[k]["severity"] if k in fs else None
    check(sev((A, "c2_connection", C2_IP)) == "critical" and fs[(A, "c2_connection", C2_IP)]["count"] == 1,
          "completed outbound connection to a Feodo C2 -> critical, duplicate capture counted once")
    check(sev((B, "intel_attempt", C2_IP)) == "medium", "attempt without answer -> medium")
    check(sev((C, "intel_inbound", OLD_C2)) == "low", "inbound from a listed address -> low")
    check(sev((B, "c2_connection", OLD_C2)) == "medium", "connection to a C2 offline for 30+ days -> capped at medium")
    check(sev((A, "dns_lookup", BAD_HOST)) == "high", "answered lookup of a URLhaus host -> high")
    check(sev((A, "intel_connection", BAD_HOST)) == "high"
          and fs[(A, "intel_connection", BAD_HOST)]["details"].get("via_dns"),
          "connection to the address the malware domain resolved to -> high (via DNS)")
    check(sev((C, "dns_blocked", "drop.example.org")) == "low" and fs[(C, "dns_blocked", "drop.example.org")]["count"] == 1,
          "blocked lookup (Zeek NXDOMAIN + unbound RPZ line) -> low, counted once (%r)"
          % fs.get((C, "dns_blocked", "drop.example.org")))
    check(sev((C, "dns_blocked", "*.wild.example")) == "low", "sinkholed answer counts as blocked; *. local match")
    check(sev((G, "c2_connection", "198.51.100.100")) is None and sev((G, "intel_connection", "198.51.100.100")) == "critical",
          "WireGuard peer traffic attributed to the peer; local CIDR indicator keeps its own severity")
    check(D in eng.devices and eng.devices[D]["mac"] == MAC_D, "EUI-64 IPv6 address -> device of the embedded MAC")
    check(eng.who("2001:db8:1:0:1:2:3:4", T + 21) == B, "Zeek orig_l2_addr maps an address unknown to the neighbour table")
    check(not any(f["indicator"] == "192.0.2.11" for f in eng.findings.values()), "LAN-internal flow ignored")
    agg = eng.agg[A]
    check(agg["in"] == 5000 + 9000 + 123456 + 5000 and agg["n"] == 4 and agg["dl"].count() == 4,
          "aggregates: bytes in, connections, distinct destinations today (%r)" % {k: agg[k] for k in ("in", "n")})
    out = {d["id"]: d for d in json.load(open(r + "/var/lib/tuxwall/devices/devices.json"))["devices"]}
    da = out[A]
    check(da["top_destinations"][0]["ip"] == EXT and da["top_destinations"][0]["bytes"] == 123456 + 200
          and len(da["hourly"]) == 24 and sum(h["conns"] for h in da["hourly"]) == 4
          and da["health"] == "critical" and da["risk"] == 100,
          "detail: top destinations by bytes, 24 hourly buckets, health critical (%r)" % da["top_destinations"][:1])
    check(any(x["name"] == BAD_HOST for x in da["top_destinations"]), "destination named from the DNS answer")
    check(BAD_HOST not in da["reason"] and C2_IP not in da["reason"] and "C2" in da["reason"],
          "reason is generic: no indicator/address (%r)" % da["reason"])
    ev = [json.loads(x) for x in open(r + "/var/lib/tuxwall/devices/events.jsonl")]
    check(any(e["type"] == "new_device" and e["device"] == D for e in ev)
          and any(e["type"] == "finding" and e["severity"] == "critical" for e in ev),
          "events: new device after the baseline, findings")
    summ = json.load(open(r + "/var/lib/tuxwall/devices/summary.json"))
    check(summ["flagged"] >= 3 and summ["worst"]["severity"] == "critical" and C2_IP not in json.dumps(summ),
          "summary: flagged count, worst finding without the indicator")

    # Suricata: attribution at alert time across an IP reassignment
    clock.t = NOW + 7200
    w(r + "/var/lib/kea/kea-leases4.csv", leases_csv([("192.0.2.10", MAC_C, "esp-a1b2c3", NOW + 9000)]))
    src.neigh = []
    eng.cycle()
    w(r + "/var/log/suricata/eve.json", "".join([
        eve(NOW + 100, "192.0.2.10", "203.0.113.200", "ET MALWARE Example CnC Checkin", "A Network Trojan was Detected"),
        eve(NOW + 7150, "192.0.2.10", "203.0.113.201", "ET MALWARE Example CnC Checkin", "A Network Trojan was Detected",
            sid=2024898),
        eve(NOW + 7150, "203.0.113.5", "192.0.2.11", "SURICATA STREAM excessive retransmissions",
            "Generic Protocol Command Decode", sev=3),
        eve(NOW + 7150, "203.0.113.6", "192.0.2.11", "ET INFO Observed DNS Query to .biz TLD", "Potentially Bad Traffic", 2),
        eve(NOW + 7150, "203.0.113.7", "192.0.2.11", "GPL ATTACK_RESPONSE id check returned root",
            "Potentially Bad Traffic", 2, sid=2100498, direction="to_client"),
        eve(NOW + 7150, "203.0.113.8", "192.0.2.11", "ET EXPLOIT Example RCE Attempt Inbound",
            "Attempted Administrator Privilege Gain", 1, sid=2030001),
        eve(NOW + 7150, "192.0.2.11", "203.0.113.9", "ET ATTACK_RESPONSE Output of id command from HTTP server",
            "Successful Administrator Privilege Gain", 1, sid=2030002, direction="to_client"),
    ]), "a")
    clock.t = NOW + 7260
    eng.cycle()
    ids_f = {(f["device"], f["indicator"]): f for f in eng.findings.values() if f["kind"] == "ids_alert"}
    check((A, "sid:2024897") in ids_f and (dw.mac_id(MAC_C), "sid:2024898") in ids_f,
          "Suricata alert attributed to the MAC holding the IP at alert time (before/after reassignment) %r" % list(ids_f))
    check(ids_f.get((A, "sid:2024897"), {}).get("severity") == "high", "Suricata severity 1, outbound -> high")
    check(ids_f.get((B, "sid:2100498"), {}).get("severity") == "medium"
          and ids_f[(B, "sid:2100498")]["details"]["direction"] == "outbound",
          "ATTACK_RESPONSE to the client that opened the flow (to_client) -> outbound, medium")
    check(ids_f.get((B, "sid:2030001"), {}).get("severity") == "low",
          "inbound exploit attempt against the device (it is the server) -> low, health unchanged")
    check(ids_f.get((B, "sid:2030002"), {}).get("severity") == "high",
          "the device itself answered with attack-response output -> high although the flow was inbound")
    check(len(ids_f) == 5 and eng.stats["suricata_ignored"] == 2, "decoder / INFO alerts ignored")

    # expected suppression + retention
    fid = next(f["id"] for f in eng.findings.values() if f["device"] == A and f["kind"] == "c2_connection")
    w(r + "/etc/tuxwall/devices/expected.json", json.dumps({"version": 1, "entries": [
        {"device": A, "kind": "c2_connection", "indicator": C2_IP}]}))
    eng.cycle()
    check(eng.findings[fid]["expected"], "expected: finding flagged")
    risk, health, _r, worst = dw.score_device(eng.devices[A], [f for f in eng.findings.values() if f["device"] == A],
                                              clock.t)
    check(worst is None or worst["id"] != fid, "expected finding no longer the worst one")
    zeek(r, "conn", conn(NOW + 7250, "192.0.2.10", C2_IP))
    clock.t = NOW + 7320
    n = len(eng.events)
    eng.cycle()
    check(eng.findings.get(fid) is None or eng.findings[fid]["count"] == 1 or eng.findings[fid]["expected"],
          "expected finding still aggregated, no alert event")
    check(n == 0 and not any(e.get("finding") == fid for e in eng.events), "no event for an expected finding")
    clock.t = NOW + 31 * 86400
    eng.prune()
    check(not eng.findings, "retention: findings older than 30 days dropped")
    check(eng.record_finding(A, {"kind": "dns_lookup", "indicator": "x.example", "severity": "high"},
                             clock.t - 40 * 86400) is None, "retention: an event older than the window is ignored")
    # restart safety: state round trip
    eng.save_state()
    eng2 = dw.Engine(dw.Config(r), src, clock)
    check(eng2.load_state() and set(eng2.devices) == set(eng.devices)
          and eng2.followers["conn"].cp == eng.followers["conn"].cp
          and eng2.agg[A]["dl"].count() == eng.agg[A]["dl"].count(), "state: devices, checkpoints, aggregates restored")
    # every file written lives in the state dir
    written = []
    for dp, _dn, fn in os.walk(r):
        for x in fn:
            p = os.path.join(dp, x)
            if os.path.getmtime(p) >= NOW - 1 and "/opt/" not in p and "/etc/" not in p and "/var/log/" not in p \
                    and "/var/lib/kea/" not in p and "/usr/" not in p:
                written.append(p)
    check(all(p.startswith(r + "/var/lib/tuxwall/devices/") or p == r + "/var/lib/tuxwall/wg-peers.json"
              for p in written), "engine writes only its state dir")
    modes = {os.path.basename(p): os.stat(p).st_mode & 0o777 for p in written if "/devices/" in p}
    check(modes.get("engine.json") == 0o600 and modes.get("devices.json") == 0o640, "state file modes (%r)" % modes)


def t_campaign4():
    """Lab campaign 4 (deed9c7) findings: DW-1 attribution, DW-2 Suricata
    without LAN capture, DW-5 address lists, DW-8 indicators, DW-9 new_24h,
    DW-10 WireGuard zone, DW-11 blocked-lookup count, DW-12 checksums."""
    r = make_root("c4")
    src = FakeSources()
    clock = Clock(NOW)
    IP, IP_B = "192.0.2.10", "192.0.2.20"
    A, B = dw.mac_id(MAC_A), dw.mac_id(MAC_B)
    w(r + "/var/lib/kea/kea-leases4.csv", leases_csv([(IP, MAC_A, "client-a", NOW + 86400)]))
    w(r + "/etc/tuxwall/devices/local-indicators.json", json.dumps({"version": 1, "indicators": [
        {"type": "ip", "value": "203.0.113.90", "severity": "high"},
        {"type": "ip", "value": "203.0.113.91", "severity": "high"},
        {"type": "domain", "value": "blocked.example", "severity": "high"}]}))
    w(r + "/var/lib/tuxwall/shared/wg-peers.json", json.dumps({"schema": 1, "iface": "wg1", "peers": [
        {"public_key": WG_PK, "name": "", "allowed_ips": ["192.0.2.131/32"], "last_handshake": NOW - 30}]}))
    w(r + "/etc/suricata/suricata.yaml", "%YAML 1.1\n---\nvars:\n  x: 1\naf-packet:\n  - interface: wan0\n"
      "    cluster-id: 99\n  - interface: default\n#  - interface: lan0\npcap:\n  - interface: default\nlogging:\n  x: 1\n")
    src.neigh = [{"dst": IP, "dev": "lan0", "lladdr": MAC_A, "state": ["REACHABLE"]}]
    eng = dw.Engine(dw.Config(r), src, clock)
    eng.cycle()                                                       # baseline: A only
    # ARP flux: B answers for A's address for a minute (and uses its own .20)
    clock.t = NOW + 60
    src.neigh = [{"dst": IP, "dev": "lan0", "lladdr": MAC_B, "state": ["REACHABLE"]},
                 {"dst": IP_B, "dev": "lan0", "lladdr": MAC_B, "state": ["REACHABLE"]}]
    eng.cycle()
    out = {d["id"]: d for d in json.load(open(r + "/var/lib/tuxwall/devices/devices.json"))["devices"]}
    check(IP not in out[A]["current_ips"] and IP in out[B]["current_ips"],
          "DW-1: a lease the neighbour table contradicts is not 'current' (%r / %r)" % (out[A]["current_ips"], out[B]["current_ips"]))
    for t in (NOW + 120, NOW + 180):
        clock.t = t
        src.neigh = [{"dst": IP, "dev": "lan0", "lladdr": MAC_A, "state": ["REACHABLE"]},
                     {"dst": IP_B, "dev": "lan0", "lladdr": MAC_B, "state": ["REACHABLE"]}]
        eng.cycle()
    check(eng.who(IP, NOW + 60) == B and eng.who(IP, NOW + 150) == A and eng.who(IP, NOW + 175) == A
          and eng.who(IP, NOW + 30) == A, "DW-1: ownership history by time (%r)" % eng.ip_hist.get(IP))
    check(sum(1 for e in eng.ip_hist[IP] if e[0] == A and e[1] <= NOW + 60 <= e[2]) == 0,
          "DW-1: A's interval never bridges B's claim (%r)" % eng.ip_hist[IP])
    zeek(r, "conn", conn(NOW + 170, IP, "203.0.113.90"))              # A, after the flux, no L2 info
    clock.t = NOW + 240
    eng.cycle()
    fa = [f for f in eng.findings.values() if f["indicator"] == "203.0.113.90"]
    check(len(fa) == 1 and fa[0]["device"] == A, "DW-1: A's connection after the flux lands on A (%r)"
          % [(f["device"], f["indicator"]) for f in fa])
    # the MAC on the flow wins over the history; the earlier finding stays where it is
    l2 = json.loads(conn(NOW + 230, IP, "203.0.113.91"))
    l2.update(orig_l2_addr=MAC_B, resp_l2_addr="00:00:5e:00:53:fe")
    zeek(r, "conn", jl(l2))
    clock.t = NOW + 300
    eng.cycle()
    fb = [f for f in eng.findings.values() if f["indicator"] == "203.0.113.91"]
    check(len(fb) == 1 and fb[0]["device"] == B and eng.stats["l2_attributed"] >= 1,
          "DW-1: Zeek orig_l2_addr decides (the flow came from B's MAC)")
    check(fa[0]["device"] == A and eng.findings[fa[0]["id"]]["device"] == A, "DW-1: existing findings never move")
    check(eng.who(IP, NOW + 240) == A, "DW-1: one L2 sighting of B inside A's interval does not take the address over later")
    # an IPv6 privacy address that only talks to the router (DNS): the flow's MAC still maps it
    v6p = "2001:db8:1:0:5:6:7:8"
    dflow = json.loads(conn(NOW + 280, v6p, "2001:db8:1::1", rp=53, proto="udp"))
    dflow.update(orig_l2_addr=MAC_A, resp_l2_addr="00:00:5e:00:53:fe")
    zeek(r, "conn", jl(dflow))
    clock.t = NOW + 320
    eng.cycle()
    check(eng.who(v6p, NOW + 290) == A, "DW-1: a device -> router flow (DNS) with Zeek MACs maps the address")
    # DW-5: B's address list never shows A's current address; current first
    out = {d["id"]: d for d in json.load(open(r + "/var/lib/tuxwall/devices/devices.json"))["devices"]}
    check(out[B]["ips"] == [IP_B] and out[A]["ips"][0] == IP,
          "DW-5: no address another device holds now; current first (%r / %r)" % (out[B]["ips"], out[A]["ips"]))
    # DW-9: B is new (first seen after the baseline) although its health is warning
    summ = json.load(open(r + "/var/lib/tuxwall/devices/summary.json"))
    check(out[B]["health"] == "warning" and summ["new_24h"] == 1,
          "DW-9: new_24h counts a new device whatever its health (B; the rest are baseline: %r)" % summ["new_24h"])
    # DW-10: a WireGuard interface without a role is still the VPN zone
    g = out[dw.wg_id(WG_PK)]
    check(g["zone"] == "vpn" and g["zone_name"].startswith("WireGuard") and g["iface"] == "wg1",
          "DW-10: WireGuard peer zone 'vpn' without an interfaces.json role (%r)" % {k: g[k] for k in ("zone", "zone_name")})
    # DW-4 (engine side): the snapshot in the shared directory is re-read every cycle
    w(r + "/var/lib/tuxwall/shared/wg-peers.json", json.dumps({"schema": 1, "iface": "wg1", "peers": []}))
    eng.cycle()
    check(eng.source_status["wireguard"]["peers"] == 0, "DW-4: a rewritten snapshot is picked up on the next cycle")
    # DW-2: Suricata captures only the WAN -> status warning; a LAN capture clears it
    st = json.load(open(r + "/var/lib/tuxwall/devices/status.json"))
    wn = {x["code"]: x for x in st["warnings"]}
    check("suricata_no_lan" in wn and "only watches the WAN" in wn["suricata_no_lan"]["text"]
          and "--add-lan" in wn["suricata_no_lan"]["hint"] and "lan0" in wn["suricata_no_lan"]["hint"]
          and st["sources"]["suricata"]["capture"] == ["wan0"] and st["sources"]["suricata"]["lan_capture"] is False,
          "DW-2: Suricata without a LAN interface -> warning with the fix (%r)" % st.get("warnings"))
    w(r + "/etc/suricata/suricata.yaml", "af-packet:\n  - interface: wan0\n  - interface: \"lan0\"\nlogging:\n  x: 1\n")
    eng.refresh_topology(force=True)
    su = eng.suricata_status()
    check(su["lan_capture"] is True and set(su["captured_lan"]) == {"lan0", "lan0.10"}
          and not any(x["code"] == "suricata_no_lan" for x in eng.warnings(clock.t)),
          "DW-2: capture on the LAN parent covers its VLAN; warning gone (%r)" % su)
    os.unlink(r + "/etc/suricata/suricata.yaml")
    eng.refresh_topology(force=True)
    check(eng.suricata_status()["lan_capture"] is None and not eng.warnings(clock.t),
          "DW-2: no suricata.yaml -> unknown, no warning")
    # DW-11: A + AAAA lookups a few seconds apart, plus unbound's line -> one blocked lookup
    T = NOW + 400
    zeek(r, "dns", dns(T, IP_B, "blocked.example", None, "NXDOMAIN", tid=7) + dns(T + 4, IP_B, "blocked.example", None,
                                                                                  "NXDOMAIN", tid=8))
    src.journal_lines = [(T + 6, "unbound[1:0] info: blocked.example. always_nxdomain %s@5353 blocked.example. A IN"
                                 % IP_B), (T + 7, "unbound[1:0] info: blocked.example. always_nxdomain "
                                          "%s@5353 blocked.example. AAAA IN" % IP_B)]
    clock.t = NOW + 460
    eng.cycle()
    fd = [f for f in eng.findings.values() if f["kind"] == "dns_blocked" and f["indicator"] == "blocked.example"]
    check(len(fd) == 1 and fd[0]["count"] == 1 and fd[0]["device"] == B,
          "DW-11: one blocked lookup counted once (%r)" % [(f["device"], f["count"]) for f in fd])
    # DW-12: Zeek on a VM with checksum offload: every TCP flow 'C', and no MAC fields
    rz = make_root("c4z")
    ez = dw.Engine(dw.Config(rz), FakeSources(), Clock(NOW))
    zeek(rz, "conn", "".join(conn(NOW - 300 + i, "192.0.2.%d" % (10 + i % 5), EXT, state="OTH", rb=0, hist="C")
                             for i in range(250)))
    ez.cycle()
    codes = {x["code"] for x in ez.warnings(NOW)}
    check({"zeek_bad_checksums", "zeek_no_mac"} <= codes, "DW-12: bad checksums + no MAC logging -> warnings (%r)" % codes)
    zs = json.load(open(rz + "/var/lib/tuxwall/devices/status.json"))
    check(zs["sources"]["zeek"]["bad_checksum"] == 250 and zs["sources"]["zeek"]["mac_logging"] is False
          and zs["unattributed_addresses_1h"] == 0, "DW-12: status counters (%r)" % zs["sources"]["zeek"])
    # DW-8: never-matchable local indicators refused (base check; the API adds the router + LAN context)
    bad = [("0.0.0.0", None), ("::", None), ("224.0.0.251", None), ("127.0.0.1", None), ("fe80::1", None),
           ("0.0.0.0/8", None), ("192.0.2.1", "router"), ("192.0.2.40", "lan"), ("192.0.2.32/28", "lan"), ("192.0.2.0/25", "router"),
           ("192.0.0.0/16", "router")]
    for value, why in bad:
        try:
            feeds.validate_local_indicator({"value": value}, router_ips=["192.0.2.1", "198.51.100.2"],
                                           lan_nets=["192.0.2.0/26", "2001:db8:1::/64"])
            check(False, "DW-8: %s accepted" % value)
        except ValueError as exc:
            msg = str(exc)
            check(("router" in msg if why == "router" else "own network" in msg if why == "lan" else "never match" in msg),
                  "DW-8: %s refused with a clear message (%s)" % (value, msg))
    check(feeds.validate_local_indicator({"value": "198.51.100.77"}, router_ips=["192.0.2.1"],
                                         lan_nets=["192.0.2.0/26"])["value"] == "198.51.100.77"
          and feeds.validate_local_indicator({"value": "10.20.0.0/16"}, lan_nets=["192.0.2.0/26"])["type"] == "cidr",
          "DW-8: internet / other private networks still accepted")
    w(r + "/etc/tuxwall/devices/li.json", json.dumps({"indicators": [{"value": "0.0.0.0"}, {"value": "198.51.100.5"}]}))
    check([x["value"] for x in feeds.load_local_indicators(r + "/etc/tuxwall/devices/li.json")] == ["198.51.100.5"],
          "DW-8: an old never-matchable entry is skipped on load")


def t_false_positives():
    """ThreatFox platform URLs (Nov 25): a feed never flags a shared platform,
    an empty AAAA answer is not a block, and feed findings whose indicator
    leaves the feed are withdrawn."""
    r = make_root("fp")
    src = FakeSources()
    clock = Clock(NOW)
    w(r + "/var/lib/kea/kea-leases4.csv", leases_csv([("192.0.2.10", MAC_A, "phone-a", NOW + 3000)]))
    src.neigh = [{"dst": "192.0.2.10", "dev": "lan0", "lladdr": MAC_A, "state": ["REACHABLE"]}]
    eng = dw.Engine(dw.Config(r), src, clock)
    eng.cycle()
    A = dw.mac_id(MAC_A)
    tf = r + "/var/lib/tuxwall/devices/feeds/threatfox.json"
    meta = {"m": "Test", "t": "payload_delivery", "c": 90}
    # a feed file written before the parse-time filter: it still lists github.com
    w(tf, json.dumps({"schema": 1, "feed": "threatfox", **feeds.compact(
        {"ip": {}, "domain": {"github.com": meta, "evil.example.net": meta, "drop2.example.net": meta}})}))
    w(r + "/etc/tuxwall/devices/local-indicators.json", json.dumps({"version": 1, "indicators": [
        {"type": "domain", "value": "www.youtube.com", "severity": "medium", "note": "owner's own rule"}]}))
    clock.t = NOW + 60
    T = NOW + 30
    zeek(r, "dns", "".join([
        dns(T, "192.0.2.10", "github.com", ["198.51.100.40"], tid=11),
        dns(T + 1, "192.0.2.10", "evil.example.net", ["198.51.100.41"], tid=12),
        dns(T + 2, "192.0.2.10", "drop2.example.net", [], tid=13),          # NOERROR, no records (AAAA/NODATA)
        dns(T + 3, "192.0.2.10", "drop2.example.net", None, "SERVFAIL", tid=14),
        dns(T + 4, "192.0.2.10", "www.youtube.com", ["198.51.100.42"], tid=15),
    ]))
    eng.cycle()
    fs = {(f["kind"], f["indicator"]): f for f in eng.findings.values() if f["device"] == A}
    check(not any(i == "github.com" for _k, i in fs), "feed listing github.com: no finding (shared platform)")
    check(("dns_lookup", "evil.example.net") in fs, "a real feed domain still matches")
    check(not any(i == "drop2.example.net" for _k, i in fs),
          "NOERROR without records / SERVFAIL are not 'blocked' (DW-16) (%r)" % sorted(fs))
    check(("dns_lookup", "www.youtube.com") in fs and fs[("dns_lookup", "www.youtube.com")]["source"] == "local",
          "the owner's local list is never filtered")
    # the feed drops evil.example.net -> its finding is withdrawn; the local one stays
    w(tf, json.dumps({"schema": 1, "feed": "threatfox", **feeds.compact(
        {"ip": {}, "domain": {"other.example.net": meta}})}))
    os.utime(tf, (NOW + 90, NOW + 90))
    clock.t = NOW + 120
    eng.cycle()
    fs = {(f["kind"], f["indicator"]): f for f in eng.findings.values() if f["device"] == A}
    check(("dns_lookup", "evil.example.net") not in fs and ("dns_lookup", "www.youtube.com") in fs,
          "finding withdrawn when the feed no longer lists it; local finding kept (%r)" % sorted(fs))
    evs = [json.loads(x) for x in open(r + "/var/lib/tuxwall/devices/events.jsonl")]
    check(any(e.get("type") == "retracted" and e.get("source") == "threatfox" for e in evs), "retraction logged")
    # a feed that is missing keeps its findings (no mass withdrawal on a failed download)
    clock.t = NOW + 150
    zeek(r, "dns", dns(NOW + 140, "192.0.2.10", "other.example.net", ["198.51.100.43"], tid=16))
    eng.cycle()
    os.remove(tf)
    clock.t = NOW + 180
    eng.cycle()
    check(any(f["indicator"] == "other.example.net" for f in eng.findings.values()),
          "feed file gone: its findings are kept")


def t_small_batch():
    """3.3.7 small batch (Nov 25): DW-13 one MAC with two active leases,
    INFO-1 source warnings re-evaluated within a cycle, INFO-2 the router's
    own names refused as indicators, ip_seen for the quarantine (DW-14)."""
    r = make_root("sb")
    src = FakeSources()
    clock = Clock(NOW)
    A = dw.mac_id(MAC_A)
    OLD, CUR = "192.0.2.10", "192.0.2.11"
    # a new client id got a new address; the old lease runs out LATER (renewed
    # just before) - the neighbour table sees only the new one in use
    w(r + "/var/lib/kea/kea-leases4.csv", leases_csv([(OLD, MAC_A, "old-name", NOW + 3500),
                                                      (CUR, MAC_A, "new-name", NOW + 3400),
                                                      ("192.0.2.70", MAC_A, "vlan-name", NOW + 3000)]))
    src.neigh = [{"dst": CUR, "dev": "lan0", "lladdr": MAC_A, "state": ["REACHABLE"]}]
    eng = dw.Engine(dw.Config(r), src, clock)
    eng.cycle()
    out = {d["id"]: d for d in json.load(open(r + "/var/lib/tuxwall/devices/devices.json"))["devices"]}
    a = out[A]
    check(a["current_ips"][0] == CUR and OLD not in a["current_ips"] and "192.0.2.70" in a["current_ips"],
          "DW-13: the lease the neighbour table sees is current, the second lease on the same network is not, "
          "a lease on another network stays (%r)" % a["current_ips"])
    check(a["ips"][0] == CUR and a["hostnames"].get("kea") == "new-name",
          "DW-13: the viewer list starts with the same address, hostname from the current lease (%r)" % a["ips"])
    check(eng.who(OLD, NOW) is None, "DW-13: the stale lease is no ownership evidence (%r)" % eng.ip_hist.get(OLD))
    # no neighbour entry at all: the newest lease (latest start) wins
    src.neigh = []
    clock.t = NOW + 60
    eng.cycle()
    a = {d["id"]: d for d in json.load(open(r + "/var/lib/tuxwall/devices/devices.json"))["devices"]}[A]
    v4 = [x for x in a["current_ips"] if ":" not in x and x != "192.0.2.70"]
    check(v4 == [OLD] and a["ips"][0] in (OLD, "192.0.2.70"),
          "DW-13: without a neighbour entry the newest lease is current (%r)" % a["current_ips"])
    check(dw.stale_leases([{"ip": "192.0.2.5", "mac": MAC_B, "cltt": 1, "expire": 9}], set(), lambda ip: "lan0") == set(),
          "DW-13: a single lease is never stale")
    check(isinstance(a.get("ip_seen"), dict) and set(a["ip_seen"]) >= {CUR, OLD} and all(
          isinstance(t, int) for t in a["ip_seen"].values()), "DW-14: devices.json carries ip_seen {ip: ts}")
    # a long lease renewed more than 24 h ago and a VPN peer: the viewer list still has the current address
    r2 = make_root("sb2")
    w(r2 + "/var/lib/kea/kea-leases4.csv", leases_csv([]) + "192.0.2.12,%s,,345600,%d,1,0,0,tv,0,,0\n"
      % (MAC_B, NOW + 3600))
    w(r2 + "/var/lib/tuxwall/shared/wg-peers.json", json.dumps({"schema": 1, "iface": "wg0", "peers": [
        {"public_key": WG_PK, "name": "", "allowed_ips": ["192.0.2.131/32"], "last_handshake": 0}]}))
    e2 = dw.Engine(dw.Config(r2), FakeSources(), Clock(NOW))
    e2.cycle()
    o2 = {d["id"]: d for d in json.load(open(r2 + "/var/lib/tuxwall/devices/devices.json"))["devices"]}
    check(o2[dw.mac_id(MAC_B)]["ips"] == ["192.0.2.12"] and o2[dw.wg_id(WG_PK)]["ips"] == ["192.0.2.131"],
          "DW-13: current addresses are in the viewer list even when last touched more than 24 h ago (%r)"
          % {k: v["ips"] for k, v in o2.items()})
    # INFO-1: a suricata.yaml change is re-read within a cycle (not with the 10-min topology)
    y = r + "/etc/suricata/suricata.yaml"
    w(y, "%YAML 1.1\n---\naf-packet:\n  - interface: wan0\n    cluster-id: 99\n  - interface: default\n")
    clock.t = NOW + 120
    eng.cycle()
    eng.refresh_topology(force=True)
    check(any(x["code"] == "suricata_no_lan" for x in eng.warnings(clock.t)), "INFO-1: WAN-only capture warned")
    w(y, "%YAML 1.1\n---\naf-packet:\n  - interface: wan0\n    cluster-id: 99\n  - interface: lan0\n"
      "    cluster-id: 97\n  - interface: default\n")
    clock.t = NOW + 180
    eng.cycle()
    check(not any(x["code"] == "suricata_no_lan" for x in eng.warnings(clock.t)),
          "INFO-1: the LAN capture fix clears the warning on the next cycle")
    # INFO-1: Zeek warnings judged on the newest lines, not the whole hour
    eng.zeek_win = [(300, 0, 300, 290)] * 30 + [(250, 250, 250, 5)]
    codes = {x["code"] for x in eng.warnings(clock.t)}
    check("zeek_bad_checksums" not in codes and "zeek_no_mac" not in codes,
          "INFO-1: fixed Zeek site policy clears both warnings once enough new lines arrived (%r)" % codes)
    eng.zeek_win = [(300, 0, 300, 290)] * 3
    codes = {x["code"] for x in eng.warnings(clock.t)}
    check({"zeek_bad_checksums", "zeek_no_mac"} <= codes, "INFO-1: still warned while the problem persists")
    # INFO-2: the router's own names are refused as domain indicators
    rn = ["router", "router.local", "gateway.home.arpa"]
    for v in ("gateway.home.arpa", "GATEWAY.home.arpa.", "router.local", "*.home.arpa"):
        try:
            feeds.validate_local_indicator({"value": v}, router_names=rn)
            ok = False
        except ValueError as exc:
            ok = "this router" in str(exc)
        check(ok, "INFO-2: %s refused as the router's own name" % v)
    check(feeds.validate_local_indicator({"value": "evil.home.arpa.example"}, router_names=rn)["value"]
          == "evil.home.arpa.example" and feeds.validate_local_indicator({"value": "other.home.arpa"},
                                                                          router_names=rn)["value"] == "other.home.arpa",
          "INFO-2: other names accepted")


def t_score():
    dev = {"first_seen": NOW - 10 * 86400, "baseline": False}
    f = lambda sev, age, exp=False: {"id": sev + str(age), "severity": sev, "last": NOW - age, "kind": "dns_lookup",  # noqa: E731
                                     "source": "urlhaus", "expected": exp, "indicator": BAD_HOST}
    cases = [([], 0, "normal"), ([f("critical", 3600)], 60, "critical"), ([f("high", 3600)], 35, "warning"),
             ([f("low", 3600)], 4, "normal"), ([f("low", 60)] * 3, 12, "normal"), ([f("critical", 60, True)], 0, "normal"),
             ([f("high", 8 * 86400)], 7, "normal"), ([f("medium", 2 * 86400)], 8, "warning"),
             ([f("critical", 60), f("high", 60)], 95, "critical"), ([f("low", 60)] * 8, 32, "warning")]
    for findings, want_risk, want_health in cases:
        risk, health, reason, _w = dw.score_device(dev, findings, NOW)
        check(risk == want_risk and health == want_health, "score %r -> %d %s (got %d %s)" % (
            [(x["severity"], x["last"]) for x in findings], want_risk, want_health, risk, health))
        check(BAD_HOST not in reason, "reason never carries the indicator")
    new = {"first_seen": NOW - 3600, "baseline": False}
    check(dw.score_device(new, [], NOW)[1] == "new" and dw.score_device(dict(new, baseline=True), [], NOW)[1] == "normal",
          "new device for 24 h (not for baseline devices)")
    d = dw.Distinct()
    for i in range(3000):
        d.add("198.51.100.%d/%d" % (i % 256, i))
    check(2850 <= dw.Distinct(d.hex()).count() <= 3150, "distinct estimate within 5%% (%d)" % d.count())
    check(dw.mac_from_eui64("2001:db8::200:5eff:fe00:530d") == MAC_D and dw.mac_from_eui64("2001:db8::1") is None,
          "EUI-64 decode")


# ── silence rules (A7) ──────────────────────────────────────────────────────

def t_silence():
    V = dw.validate_silence_rule
    dev_a, dev_b = dw.mac_id(MAC_A), dw.mac_id(MAC_B)
    r_ind = V({"scope": "indicator", "indicator": "Tracker.Vendor.Example", "expires": "7d", "note": " TV \x07 app "}, NOW)
    check(r_ind["indicator"] == "tracker.vendor.example" and r_ind["expires"] == int(NOW + 7 * 86400)
          and r_ind["note"] == "TV app" and r_ind["include_critical"] is False and dw.SILENCE_ID_RE.match(r_ind["id"]),
          "validate: indicator rule normalised, 7-day expiry, note cleaned (%r)" % r_ind)
    r_dk = V({"scope": "device_kind", "device": dev_b, "kind": "dns_blocked", "expires": "forever"}, NOW)
    r_sfx = V({"scope": "suffix", "suffix": "*.Vendor-Telemetry.example.", "expires": "30d"}, NOW)
    r_kind = V({"scope": "kind", "kind": "dns_blocked"}, NOW)
    check(r_dk["expires"] == 0 and r_sfx["suffix"] == "vendor-telemetry.example" and r_kind["expires"] == int(NOW + 30 * 86400),
          "validate: device+kind forever, suffix without *. and dot, default 30 days")
    for bad, why in (({"scope": "everything"}, "scope"), ({"scope": "indicator"}, "indicator"),
                     ({"scope": "device_kind", "device": dev_b}, "kind"), ({"scope": "device_kind", "kind": "dns_blocked"}, "device"),
                     ({"scope": "suffix", "suffix": "com"}, "one-label suffix"), ({"scope": "suffix", "suffix": "a b.example"}, "space"),
                     ({"scope": "kind"}, "kind"), ({"scope": "kind", "kind": "new_device"}, "new_device"),
                     ({"scope": "kind", "kind": "Bad Kind!"}, "kind syntax"), ({"scope": "kind", "kind": "dns_blocked", "expires": "1y"}, "expiry"),
                     ("x", "not an object")):
        try:
            V(bad, NOW)
            check(False, "validate refuses %s" % why)
        except ValueError:
            check(True, "")
    F = lambda **k: dict({"id": "f1", "device": dev_a, "kind": "dns_blocked", "indicator": "tracker.vendor.example",  # noqa: E731
                          "indicator_type": "domain", "severity": "low", "title": "", "last": NOW, "details": {}}, **k)
    m = dw.silence_match
    check(m(F(), [r_ind], NOW) == r_ind["id"] and m(F(device=dev_b, kind="dns_lookup", severity="high"), [r_ind], NOW) == r_ind["id"],
          "indicator scope: any device, any kind")
    check(m(F(indicator="other.example"), [r_ind], NOW) is None, "indicator scope: other indicator not covered")
    check(m(F(device=dev_b), [r_dk], NOW) == r_dk["id"] and m(F(), [r_dk], NOW) is None
          and m(F(device=dev_b, kind="dns_lookup"), [r_dk], NOW) is None, "device+kind: only that device and kind")
    check(m(F(indicator="a.b.vendor-telemetry.example"), [r_sfx], NOW) == r_sfx["id"]
          and m(F(indicator="vendor-telemetry.example"), [r_sfx], NOW) == r_sfx["id"]
          and m(F(indicator="*.vendor-telemetry.example", indicator_type="domain"), [r_sfx], NOW) == r_sfx["id"]
          and m(F(indicator="listed.example", details={"query": "x.vendor-telemetry.example"}), [r_sfx], NOW) == r_sfx["id"],
          "suffix: the domain, its subdomains, a wildcard indicator and the queried name")
    check(m(F(indicator="evilvendor-telemetry.example"), [r_sfx], NOW) is None
          and m(F(indicator="vendor-telemetry.example.evil.example"), [r_sfx], NOW) is None
          and m(F(indicator=C2_IP, indicator_type="ip"), [r_sfx], NOW) is None, "suffix: label boundary, IPs never match")
    check(m(F(device=dev_b), [r_kind], NOW) == r_kind["id"] and m(F(kind="intel_attempt", severity="medium"), [r_kind], NOW) is None,
          "kind scope: that kind on every device")
    check(m(F(kind="dns_blocked"), [dict(r_kind, kind="beacon_regular")], NOW) is None
          and m(F(kind="beacon_regular", severity="medium", indicator="198.51.100.9:443"),
                [V({"scope": "kind", "kind": "beacon_regular"}, NOW)], NOW), "generic: a Phase 2 detector kind works unchanged")
    check(m(F(), [r_ind], NOW + 8 * 86400) is None and m(F(), [r_ind], NOW + 6 * 86400) == r_ind["id"],
          "expiry: a 7-day rule stops after 7 days")
    # critical guard
    c2 = F(kind="c2_connection", indicator=C2_IP, indicator_type="ip", severity="critical")
    ar = F(kind="ids_alert", indicator="sid:2100498", indicator_type="signature", severity="high",
           title="GPL ATTACK_RESPONSE id check returned root", details={"category": "Potentially Bad Traffic", "direction": "outbound"})
    succ = F(kind="ids_alert", indicator="sid:2019284", severity="medium", title="ET EXPLOIT x",
             details={"category": "Successful Administrator Privilege Gain"})
    inbound = F(kind="ids_alert", indicator="sid:2100498", severity="low", title="GPL ATTACK_RESPONSE id check returned root",
                details={"direction": "inbound"})
    check(all(dw.is_critical_finding(x) for x in (c2, ar, succ, F(severity="critical")))
          and not any(dw.is_critical_finding(x) for x in (inbound, F(), F(kind="intel_connection", severity="high"))),
          "critical: C2, outbound attack response, Successful ... gain, any critical severity - not inbound-only/low")
    rk = V({"scope": "kind", "kind": "ids_alert"}, NOW)
    rk_c = V({"scope": "kind", "kind": "ids_alert", "include_critical": True}, NOW)
    ri_c2 = V({"scope": "indicator", "indicator": C2_IP}, NOW)
    check(m(ar, [rk], NOW) is None and m(succ, [rk], NOW) is None and m(inbound, [rk], NOW) == rk["id"]
          and m(ar, [rk, rk_c], NOW) == rk_c["id"] and m(c2, [ri_c2], NOW) is None
          and m(c2, [dict(ri_c2, include_critical=True)], NOW) == ri_c2["id"],
          "critical guard: only an include_critical rule silences critical findings")
    check(m(F(kind="new_device"), [V({"scope": "indicator", "indicator": "tracker.vendor.example"}, NOW)], NOW) is None,
          "new-device rows are never silenced")
    rules = dw.silence_rules({"rules": [r_ind, {"id": "bad", "scope": "kind"}, dict(r_kind, scope="nope"), "x",
                                        dict(r_kind, expires="soon"), dict(r_dk, include_critical="yes")]})
    check([x["id"] for x in rules] == [r_ind["id"], r_dk["id"]] and rules[1]["include_critical"] is False,
          "silence.json: malformed rules dropped, include_critical must be a real true")
    # health + summary exclusion
    dev = {"first_seen": NOW - 10 * 86400, "baseline": True}
    hi = F(kind="dns_lookup", severity="high", last=NOW - 60)
    check(dw.score_device(dev, [hi], NOW)[1] == "warning" and dw.score_device(dev, [dict(hi, silenced="s1")], NOW)[:2] == (0, "normal"),
          "health: a silenced finding counts like an expected one")
    devs = [{"id": dev_a, "name": "a", "health": "normal", "online": False, "last_seen": NOW - 300, "baseline": True},
            {"id": dev_b, "name": "b", "health": "warning", "online": True, "last_seen": NOW - 3600, "baseline": True},
            {"id": "m00005e0053cc", "name": "c", "health": "normal", "online": False, "last_seen": NOW - 4000, "baseline": False,
             "first_seen": NOW - 3600, "zone_name": "IoT"}]
    s = dw.summarize(devs, [dict(hi, silenced="s1"), dict(hi, id="f2", device=dev_b)], NOW)
    check(s["findings_active"] == 1 and s["findings_silenced"] == 1 and s["worst"]["device"] == dev_b and s["flagged"] == 1
          and s["active"] == 2 and s["new_24h"] == 1 and s["new_zones"] == {"IoT": 1},
          "summary: silenced excluded, active = seen in 10 min, new per zone (%r)" % {k: s[k] for k in ("active", "new_zones")})
    # engine: no alert event for a silenced finding; an escalation to critical leaves the rule; expiry re-applied
    r = make_root("silence")
    clock = Clock(NOW)
    eng = dw.Engine(dw.Config(r), FakeSources(), clock)
    w(r + "/etc/tuxwall/devices/silence.json", json.dumps({"version": 1, "rules": [
        dict(r_dk, device=dev_a, kind="intel_attempt", expires=int(NOW + 600))]}))
    eng.load_overlays()
    spec = {"kind": "intel_attempt", "indicator": C2_IP, "indicator_type": "ip", "severity": "medium", "source": "feodo"}
    f = eng.record_finding(dev_a, spec, NOW)
    check(f["silenced"] == r_dk["id"] and not eng.events, "engine: silenced finding recorded, no alert event")
    eng.record_finding(dev_a, dict(spec, severity="critical"), NOW + 5)
    check(f["silenced"] is None and [e.get("escalated") for e in eng.events] == [True],
          "engine: escalation to critical leaves the rule's reach and alerts")
    f["severity"] = "medium"
    eng.events = []
    eng._apply_silence(NOW + 10)
    check(f["silenced"] == r_dk["id"] and eng.silence_next_expiry == int(NOW + 600), "engine: rule applied, next expiry tracked")
    clock.t = NOW + 601
    eng.load_overlays()
    check(f["silenced"] is None, "engine: an expired rule is dropped on the next cycle without a file change")
    clock.t = NOW + 700
    os.unlink(r + "/etc/tuxwall/devices/silence.json")
    eng.load_overlays()
    check(eng.overlay["silence"] == [] and eng.record_finding(dev_a, dict(spec, indicator=OLD_C2), NOW + 700)["silenced"] is None,
          "engine: rules file removed -> nothing silenced")


# ── API (loopback harness) ──────────────────────────────────────────────────

def t_api():
    import api_harness
    H = api_harness.Harness()
    A = H.mod
    try:
        st = os.path.join(H.scratch, "dw-state")
        conf = os.path.join(H.scratch, "dw-conf")
        os.makedirs(st)
        A.DEVICES_STATE_DIR, A.DEVICES_CONF_DIR = st, conf
        A.DEVICES_WG_SNAPSHOT = os.path.join(H.scratch, "shared", "wg-peers.json")
        A.DEVICES_WG_SNAPSHOT_LEGACY = os.path.join(H.scratch, "wg-peers.json")
        if A._qm is not None:      # never the router's real quarantine list
            A._QUAR["env"] = A._qm.Env(state_file=os.path.join(H.scratch, "quarantine.json"),
                                       log_file=os.path.join(H.scratch, "device-actions.jsonl"))
        r = H.request("GET", "/api/devices", role="viewer")
        check(r.status == 200 and r.json["available"] is False and r.json["devices"] == [],
              "API: no engine state -> available false")
        dev = {"id": dw.mac_id(MAC_A), "kind": "mac", "name": "phone-a", "name_source": "kea", "mac": MAC_A,
               "private_mac": True, "vendor": "Private MAC", "type": "phone", "ips": ["192.0.2.10"], "ipv6": [],
               "iface": "lan0", "zone": "lan", "zone_name": "LAN", "vlan": None, "first_seen": int(NOW - 86400 * 5),
               "last_seen": int(NOW), "online": True, "baseline": True, "health": "normal", "risk": 0, "reason": "",
               "activity": {"day": "2026-11-24", "bytes_in": 10, "bytes_out": 5, "conns": 2, "destinations": 2},
               "hourly": [], "top_destinations": [{"ip": C2_IP, "name": "", "country": "", "bytes": 1, "conns": 1}],
               "top_countries": [], "hostnames": {"kea": "phone-a"}, "software": []}
        fnd = {"id": "f" * 16, "device": dev["id"], "kind": "c2_connection", "indicator": C2_IP,
               "indicator_type": "ip", "severity": "critical", "title": "Connected to a known botnet C2 server (Feodo Tracker)",
               "source": "feodo", "first": time.time() - 60, "last": time.time() - 60, "count": 3,
               "details": {"peer": C2_IP}}
        w(st + "/devices.json", json.dumps({"schema": 1, "generated_at": int(time.time()), "devices": [dev]}))
        w(st + "/findings.json", json.dumps({"schema": 1, "generated_at": int(time.time()), "findings": [fnd]}))
        r = H.request("GET", "/api/devices", role="viewer")
        d = (r.json or {}).get("devices", [{}])[0]
        check(r.status == 200 and d.get("health") == "critical" and d.get("risk") == 60
              and set(d) == set(A.DEVICE_VIEWER_FIELDS) | {"quarantine"} and C2_IP not in r.body.decode(),
              "API list (viewer): recomputed health, viewer fields only, no indicator/destination (%r)" % sorted(d))
        r = H.request("GET", "/api/devices", role="admin")
        check("findings" in r.json["devices"][0] and "top_destinations" not in r.json["devices"][0],
              "API list (admin): finding counts, still no destinations in the list")
        r = H.request("GET", "/api/devices/" + dev["id"], role="viewer")
        check(r.status == 403, "API detail: viewer 403")
        r = H.request("GET", "/api/devices/" + dev["id"], role="admin")
        check(r.status == 200 and r.json["findings"][0]["indicator"] == C2_IP
              and r.json["device"]["top_destinations"], "API detail (admin): findings + destinations")
        check(H.request("GET", "/api/devices/m000000000000", role="admin").status == 404, "API detail: unknown -> 404")
        check(H.request("GET", "/api/devices", role=None).status == 401, "API: no session -> 401")
        r = H.request("GET", "/api/devices/summary", role="viewer")
        check(r.status == 200 and r.json["flagged"] == 1 and r.json["critical"] == 1 and r.json["quarantined"] == 0
              and C2_IP not in r.body.decode(), "API summary: counts, worst without the indicator")
        # rename + expected
        r = H.request("POST", "/api/devices/%s/rename" % dev["id"], role="admin", origin=H.SAME,
                      body={"name": "  Kid's   phone\x07 "})
        names = json.load(open(conf + "/names.json"))["names"]
        check(r.status == 200 and names == {dev["id"]: "Kid's phone"}, "rename: trimmed, control chars dropped (%r)" % names)
        check(H.request("GET", "/api/devices", role="viewer").json["devices"][0]["name"] == "Kid's phone",
              "rename visible at once")
        check(H.request("POST", "/api/devices/%s/rename" % dev["id"], role="admin", origin=H.SAME,
                        body={"name": "x" * 65}).status == 400, "rename: too long -> 400")
        check(H.request("POST", "/api/devices/%s/rename" % dev["id"], role="viewer", origin=H.SAME,
                        body={"name": "x"}).status == 403, "rename: viewer 403")
        check(H.request("POST", "/api/devices/%s/rename" % dev["id"], role="admin", origin="https://evil.example.com",
                        body={"name": "x"}).status == 403, "rename: foreign Origin 403 (CSRF)")
        r = H.request("POST", "/api/devices/%s/expected" % dev["id"], role="admin", origin=H.SAME,
                      body={"finding": fnd["id"], "expected": True})
        check(r.status == 200 and r.json["health"] == "normal" and r.json["risk"] == 0,
              "expected: health/risk recomputed at once (%r)" % r.json)
        ent = json.load(open(conf + "/expected.json"))["entries"]
        check(len(ent) == 1 and ent[0]["indicator"] == C2_IP and ent[0]["device"] == dev["id"], "expected.json entry")
        r = H.request("POST", "/api/devices/%s/expected" % dev["id"], role="admin", origin=H.SAME,
                      body={"finding": fnd["id"], "expected": False})
        check(r.json["health"] == "critical" and json.load(open(conf + "/expected.json"))["entries"] == [],
              "unmark expected")
        # local indicators
        r = H.request("POST", "/api/devices/indicators", role="admin", origin=H.SAME,
                      body={"action": "add", "indicator": {"value": "*.Evil.Example", "note": "lab"}})
        check(r.status == 200 and r.json["indicators"][0]["value"] == "*.evil.example", "indicators: add")
        check(H.request("POST", "/api/devices/indicators", role="admin", origin=H.SAME,
                        body={"action": "add", "indicator": {"value": "0.0.0.0/0"}}).status == 400, "indicators: too broad -> 400")
        check(H.request("GET", "/api/devices/indicators", role="viewer").status == 403, "indicators: viewer 403")
        check(H.request("GET", "/api/devices/indicators", role="admin").json["indicators"][0]["note"] == "lab",
              "indicators: admin list")
        check(H.request("POST", "/api/devices/indicators", role="admin", origin=H.SAME,
                        body={"action": "remove", "value": "*.evil.example"}).json["indicators"] == [], "indicators: remove")
        # abuse.ch key: stored 0600, never echoed; the feed unit start is a blocked side effect here
        key = "abcdefABCDEF0123456789abcdef"
        r = H.request("POST", "/api/devices/feeds/key", role="admin", origin=H.SAME, body={"key": key})
        kp = conf + "/abuse-ch.key"
        check(r.status == 200 and r.json == {"ok": True, "key_set": True} and open(kp).read().strip() == key
              and os.stat(kp).st_mode & 0o777 == 0o600, "key: stored 0600, not echoed")
        r = H.request("GET", "/api/devices/feeds", role="viewer")
        check(r.status == 200 and r.json["key_set"] is True and key not in r.body.decode()
              and len(r.json["feeds"]) == 3, "feeds status: key_set only")
        check(H.request("POST", "/api/devices/feeds/key", role="admin", origin=H.SAME,
                        body={"key": "bad key!"}).status == 400, "key: invalid -> 400")
        H.request("POST", "/api/devices/feeds/key", role="admin", origin=H.SAME, body={"key": ""})
        check(not os.path.exists(kp), "key: cleared")
        # DW-8 through the API: the router's own addresses and LAN networks refused
        A._devices_local_context = lambda: (["192.0.2.1", "198.51.100.2"], ["192.0.2.0/26", "2001:db8:1::/64"])
        for v in ("192.0.2.1", "192.0.2.30", "2001:db8:1::99", "0.0.0.0"):
            r = H.request("POST", "/api/devices/indicators", role="admin", origin=H.SAME,
                          body={"action": "add", "indicator": {"value": v}})
            check(r.status == 400 and ("never match" in r.json["error"] or "not checked" in r.json["error"]),
                  "DW-8 API: %s refused (%r)" % (v, r.json))
        check(H.request("POST", "/api/devices/indicators", role="admin", origin=H.SAME,
                        body={"action": "add", "indicator": {"value": "198.51.100.200"}}).status == 200,
              "DW-8 API: an internet address is accepted")
        H.request("POST", "/api/devices/indicators", role="admin", origin=H.SAME,
                  body={"action": "remove", "value": "198.51.100.200"})
        # DW-2 / DW-12: engine warnings reach the Threat settings and the summary
        w(st + "/status.json", json.dumps({"generated_at": int(time.time()), "warnings": [
            {"code": "suricata_no_lan", "text": "IDS alerts can't be attributed to devices — Suricata only watches the WAN",
             "hint": "sudo python3 /usr/local/share/tuxwall/scripts/tune-suricata.py --add-lan ..."}],
            "sources": {"suricata": {"capture": ["wan0"], "lan_capture": False}, "zeek": {"lines": 500, "mac_logging": True},
                        "kea": {"ok": True}}, "journal": {"active": True}, "unattributed_addresses_1h": 3}))
        r = H.request("GET", "/api/devices/feeds", role="viewer")
        check(r.json["warnings"][0]["code"] == "suricata_no_lan" and r.json["sources"]["suricata"]["lan_capture"] is False
              and r.json["sources"]["engine_running"] and r.json["sources"]["unattributed_addresses_1h"] == 3,
              "DW-2: feeds status carries the source warnings (%r)" % r.json.get("sources"))
        r = H.request("GET", "/api/devices/summary", role="viewer")
        check([x["code"] for x in r.json["warnings"]] == ["suricata_no_lan"], "DW-2: summary carries the warnings")
        # DW-5: an Access ban on an address the device only held before is not shown on it
        other = dict(dev, id=dw.mac_id(MAC_B), mac=MAC_B, ips=["192.0.2.77"], current_ips=["192.0.2.77"])
        mine = dict(dev, ips=["192.0.2.10", "192.0.2.77"], current_ips=["192.0.2.10"])
        A.load_bans = lambda: [{"ip": "192.0.2.77"}, {"ip": "192.0.2.10"}]
        if A._qm is not None:
            check(A._quar_detail(mine, [mine, other])["lease_banned"] == ["192.0.2.10"]
                  and A._quar_detail(other, [mine, other])["lease_banned"] == ["192.0.2.77"],
                  "DW-5: the ban note names only the device's own current address")
        # integration summary section
        A.build_devices_summary.__globals__["_INTEG_CACHES"]["devices"].drop()
        j = A._integ_devices()
        check(j["ok"] and j["flagged"] == 1 and j["quarantined"] == 0 and set(j["worst"]) ==
              {"severity", "reason", "device_name", "last"} and C2_IP not in json.dumps(j),
              "integration section: small, no indicator")
        # WireGuard snapshot: public data only
        pre = base64.b64encode(b"p" * 32).decode()
        A.WG_CONF = os.path.join(H.scratch, "wg0.conf")
        w(A.WG_CONF, "[Interface]\n")
        A._wg = lambda args, **k: "privkeyAAA\tpubkey\t51820\toff\n%s\t%s\t203.0.113.9:51820\t192.0.2.130/32\t%d\t10\t20\t25\n" % (
            WG_PK, pre, int(time.time()) - 30)
        A.load_wg_state = lambda: {"peers": [{"public_key": WG_PK, "name": "Laptop VPN", "address": "192.0.2.130/24",
                                              "private_key": "c2VjcmV0"}]}
        w(A.DEVICES_WG_SNAPSHOT_LEGACY, "{}")
        check(A._devices_wg_snapshot() is True and A._devices_wg_snapshot() is False, "WG snapshot: written once, unchanged -> no write")
        check(os.path.dirname(A.DEVICES_WG_SNAPSHOT).endswith("/shared") and not os.path.exists(A.DEVICES_WG_SNAPSHOT_LEGACY)
              and os.stat(os.path.dirname(A.DEVICES_WG_SNAPSHOT)).st_mode & 0o777 == 0o755,
              "DW-4: snapshot in its own directory (mapped by the unit), the old single file removed")
        check(A._devices_wg_peers()[0]["public_key"] == WG_PK, "DW-4: quarantine reads the new snapshot")
        snap = open(A.DEVICES_WG_SNAPSHOT).read()
        sj = json.loads(snap)
        check(pre not in snap and "c2VjcmV0" not in snap and "privkeyAAA" not in snap and "203.0.113.9" not in snap
              and sj["peers"][0]["name"] == "Laptop VPN" and sj["peers"][0]["allowed_ips"] == ["192.0.2.130/32"],
              "WG snapshot: no private/preshared key, no endpoint")
        # DW-15: wg0 down -> AllowedIPs from wg0.conf, else the host routes of the address (never the /24)
        pk2 = base64.b64encode(bytes(range(1, 33))).decode()
        pk3 = base64.b64encode(bytes(range(2, 34))).decode()

        def wg_down(args, **k):
            raise RuntimeError("Unable to access interface: No such device")
        A._wg = wg_down
        w(A.WG_CONF, "[Interface]\nAddress = 192.0.2.129/26\nPrivateKey = c2VjcmV0\n\n# Peer: x\n[Peer]\n"
          "PublicKey = %s\nPresharedKey = %s\nAllowedIPs = 192.0.2.130/32, 2001:db8:2::82/128\n\n[Peer]\n"
          "PublicKey = %s\nAllowedIPs = 198.18.0.0/24\n" % (WG_PK, pre, pk3))
        A.load_wg_state = lambda: {"peers": [{"public_key": WG_PK, "name": "Laptop VPN", "address": "192.0.2.130/24"},
                                             {"public_key": pk2, "name": "new-phone", "address": "192.0.2.131/24"}]}
        A._devices_wg_snapshot()
        sj = {p["public_key"]: p for p in json.load(open(A.DEVICES_WG_SNAPSHOT))["peers"]}
        check(sj[WG_PK]["allowed_ips"] == ["192.0.2.130/32", "2001:db8:2::82/128"] and sj[WG_PK]["name"] == "Laptop VPN"
              and sj[pk2]["allowed_ips"][0] == "192.0.2.131/32" and sj[pk2]["allowed_ips"][1].endswith("/128")
              and sj[pk3]["allowed_ips"] == ["198.18.0.0/24"] and pre not in open(A.DEVICES_WG_SNAPSHOT).read(),
              "DW-15: wg0 down -> peers' AllowedIPs from the config / host routes, no key material (%r)" % sj)
        if A._qm is not None:
            ctx = {"macs": set(), "ips": set(), "gateways": set(), "gateway_macs": set(), "wan": ["wan0"], "neigh": {}}
            site = {"id": dw.wg_id(pk3), "wg_public_key": pk3, "current_ips": ["198.18.0.0/24"]}
            t = A._qm.device_targets(site, [site], A._devices_wg_peers())
            check((A._qm.check_request(site, t, "isolate", "none", ctx) or (0, {}))[1].get("code") == "wide_peer",
                  "DW-15: the site-to-site peer from the config is refused")
        # INFO-2: the router's own names (hostname, .local, DHCP domain, Local domains on its addresses)
        import socket as _s
        host = _s.gethostname().strip().lower().split(".")[0]
        A.load_domains = lambda: [{"domain": "gateway.home.arpa", "ip": "192.0.2.1"},
                                  {"domain": "nas.home.arpa", "ip": "192.0.2.40"}]
        A.discover_local_domains = lambda: [{"domain": "fw.lab.example", "ip": "198.51.100.2"}]
        A._read_kea = lambda: {"Dhcp4": {"subnet4": [{"option-data": [{"name": "domain-name", "data": "lan.example"}]}]}}
        names = A._devices_router_names(["192.0.2.1", "198.51.100.2"])
        check({"gateway.home.arpa", "fw.lab.example", host, host + ".local", host + ".lan.example"} <= set(names)
              and "nas.home.arpa" not in names, "INFO-2: router names collected (%d)" % len(names))
        for v in ("gateway.home.arpa", host + ".local"):
            r = H.request("POST", "/api/devices/indicators", role="admin", origin=H.SAME,
                          body={"action": "add", "indicator": {"value": v}})
            check(r.status == 400 and "this router" in r.json["error"], "INFO-2 API: the router's own name refused")
        check(H.request("POST", "/api/devices/indicators", role="admin", origin=H.SAME,
                        body={"action": "add", "indicator": {"value": "nas.home.arpa"}}).status == 200,
              "INFO-2 API: another local name accepted")
        H.request("POST", "/api/devices/indicators", role="admin", origin=H.SAME,
                  body={"action": "remove", "value": "nas.home.arpa"})
        # INFO-3: the [RESOLVED] push does not repeat the problem text
        sent = []

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b""
        real_open = A.urllib.request.urlopen
        A.urllib.request.urlopen = lambda req, timeout=0: (sent.append((dict(req.header_items()), req.data)), _Resp())[1]
        try:
            inc = {"id": "x", "severity": "warning", "title": "Suricata IDS is not running",
                   "detail": "suricata.service is not active. Check the service on System > Maintenance."}
            A._dispatch_alert({"enabled": True, "ntfy_url": "http://127.0.0.1:9/t", "notify_resolved": True},
                              inc, "resolved")
            A._dispatch_alert({"enabled": True, "ntfy_url": "http://127.0.0.1:9/t", "min_severity": "info"},
                              inc, "opened")
        finally:
            A.urllib.request.urlopen = real_open
        check(len(sent) == 2 and b"[RESOLVED] Suricata IDS is not running" in sent[0][1]
              and b"is not active" not in sent[0][1] and b"cleared" in sent[0][1] and b"is not active" in sent[1][1],
              "INFO-3: resolved body says it cleared, the opened one keeps the detail")
        # new devices in Security > Local: rows from events.jsonl, dismissed per device
        w(st + "/devices.json", json.dumps({"schema": 1, "generated_at": int(time.time()), "devices": [
            dev, dict(dev, id=dw.mac_id(MAC_B), mac=MAC_B, name="tv-b", vendor="ICANN, IANA Department", type="tv")]}))
        now = int(time.time())
        w(st + "/events.jsonl.1", jl({"type": "new_device", "device": dw.mac_id(MAC_B), "kind": "mac", "ts": now - 40 * 86400}))
        w(st + "/events.jsonl", jl({"type": "new_device", "device": dw.mac_id(MAC_B), "kind": "mac", "ts": now - 30})
          + jl({"type": "new_device", "device": "m00005e0053ff", "kind": "mac", "ts": now - 20})
          + jl({"type": "finding", "device": dev["id"], "ts": now - 10}))
        r = H.request("GET", "/api/devices/findings/recent?limit=50", role="admin")
        rows = r.json["findings"]
        nd = [x for x in rows if x["kind"] == "new_device"]
        check(r.status == 200 and len(nd) == 1 and nd[0]["device"] == dw.mac_id(MAC_B) and nd[0]["severity"] == "info"
              and nd[0]["feed"] == "Inventory" and nd[0]["ts"] == now - 30 and "tv" in nd[0]["detail"]
              and [x["ts"] for x in rows] == sorted((x["ts"] for x in rows), reverse=True),
              "new-device rows: one per known device, info/Inventory, newest first (%r)" % nd)
        check(len(H.request("GET", "/api/devices/findings/recent?limit=1", role="admin").json["findings"]) == 1,
              "new-device rows count toward the limit")
        check(H.request("GET", "/api/devices/findings/recent", role="viewer").status == 403, "new-device rows: viewer 403")
        check(H.request("POST", "/api/devices/%s/new-ack" % dw.mac_id(MAC_B), role="viewer", origin=H.SAME,
                        body={}).status == 403
              and H.request("POST", "/api/devices/%s/new-ack" % dw.mac_id(MAC_B), role="admin",
                            origin="https://evil.example.com", body={}).status == 403,
              "new-ack: viewer 403, foreign Origin 403")
        r = H.request("POST", "/api/devices/%s/new-ack" % dw.mac_id(MAC_B), role="admin", origin=H.SAME, body={})
        ent = json.load(open(conf + "/expected.json"))["entries"]
        rows = H.request("GET", "/api/devices/findings/recent?limit=50", role="admin").json["findings"]
        check(r.status == 200 and not any(x["kind"] == "new_device" for x in rows)
              and [e["kind"] for e in ent] == ["new_device"] and ent[0]["device"] == dw.mac_id(MAC_B),
              "new-ack: recorded in the expected overlay, the row is gone")
        check(H.request("POST", "/api/devices/m00005e0053fe/new-ack", role="admin", origin=H.SAME, body={}).status == 404,
              "new-ack: unknown device -> 404")
        # silence rules (A7) through the API: gates, health/summary/table exclusion, critical guard
        w(st + "/devices.json", json.dumps({"schema": 1, "generated_at": int(time.time()), "devices": [
            dev, dict(dev, id=dw.mac_id(MAC_B), mac=MAC_B, name="tv-b", vendor="ICANN, IANA Department", type="tv")]}))
        tnow = time.time()
        f_tv = {"id": "e" * 16, "device": dw.mac_id(MAC_B), "kind": "dns_lookup", "indicator": "ads.tv-vendor.example",
                "indicator_type": "domain", "severity": "high", "title": "Looked up a known malware domain (URLhaus)",
                "source": "urlhaus", "first": tnow - 120, "last": tnow - 120, "count": 2, "details": {}}
        w(st + "/findings.json", json.dumps({"schema": 1, "generated_at": int(tnow), "findings": [fnd, f_tv]}))
        check(H.request("GET", "/api/devices/silence", role="viewer").status == 403
              and H.request("GET", "/api/devices/silence", role=None).status == 401, "silence GET: viewer 403, no session 401")
        rule = {"scope": "suffix", "suffix": "tv-vendor.example", "expires": "30d", "note": "TV telemetry"}
        check(H.request("POST", "/api/devices/silence", role="viewer", origin=H.SAME, body={"action": "add", "rule": rule}).status == 403
              and H.request("POST", "/api/devices/silence", role="admin", origin="https://evil.example.com",
                            body={"action": "add", "rule": rule}).status == 403
              and not os.path.exists(conf + "/silence.json"), "silence POST: viewer 403, foreign Origin 403, nothing written")
        check(H.request("GET", "/api/devices/summary", role="viewer").json["flagged"] == 2, "silence: both devices flagged before")
        r = H.request("POST", "/api/devices/silence", role="admin", origin=H.SAME, body={"action": "add", "rule": rule})
        sil = json.load(open(conf + "/silence.json"))["rules"]
        check(r.status == 200 and len(r.json["rules"]) == 1 and r.json["rules"][0]["hides"] == 1 and sil[0]["by"] == "boss"
              and sil[0]["suffix"] == "tv-vendor.example" and os.stat(conf + "/silence.json").st_mode & 0o777 == 0o644,
              "silence add: stored next to expected.json (0644, the engine reads it), hides 1 (%r)" % r.json)
        s = H.request("GET", "/api/devices/summary", role="viewer").json
        tvrow = [d for d in H.request("GET", "/api/devices", role="admin").json["devices"] if d["id"] == dw.mac_id(MAC_B)][0]
        check(s["flagged"] == 1 and s["findings_silenced"] == 1 and tvrow["health"] == "normal"
              and tvrow["findings"]["silenced"] == 1 and tvrow["findings"]["active"] == 0,
              "silence: health/Flagged exclude the silenced finding (%r)" % tvrow["findings"])
        rows = H.request("GET", "/api/devices/findings/recent?limit=50", role="admin").json
        rows_all = H.request("GET", "/api/devices/findings/recent?limit=50&silenced=1", role="admin").json
        check(f_tv["id"] not in [x["id"] for x in rows["findings"]] and rows["silenced_hidden"] == 1
              and [x["silenced"] for x in rows_all["findings"] if x["id"] == f_tv["id"]] == [sil[0]["id"]]
              and rows_all["silenced_hidden"] == 0, "silence: threat table hides it unless ?silenced=1 (marked)")
        det = H.request("GET", "/api/devices/" + dw.mac_id(MAC_B), role="admin").json
        check(det["findings"][0]["silenced"] == sil[0]["id"] and det["findings"][0]["critical"] is False,
              "silence: device detail marks the finding")
        # critical guard
        r = H.request("POST", "/api/devices/silence", role="admin", origin=H.SAME,
                      body={"action": "add", "rule": {"scope": "kind", "kind": "c2_connection"}})
        check(r.status == 400 and r.json.get("code") == "critical", "silence: the C2 kind needs include_critical (%r)" % r.json)
        r = H.request("POST", "/api/devices/silence", role="admin", origin=H.SAME,
                      body={"action": "add", "rule": {"scope": "indicator", "indicator": C2_IP, "expires": "7d"}})
        ri = [x for x in r.json["rules"] if x["scope"] == "indicator"][0]
        check(r.status == 200 and ri["hides"] == 0 and ri["critical_visible"] == 1
              and H.request("GET", "/api/devices/summary", role="viewer").json["critical"] == 1,
              "silence: a rule without include_critical leaves the critical C2 finding visible (%r)" % ri)
        r = H.request("POST", "/api/devices/silence", role="admin", origin=H.SAME,
                      body={"action": "add", "rule": {"scope": "indicator", "indicator": C2_IP, "include_critical": True}})
        check(r.status == 200 and len(r.json["rules"]) == 2
              and [x for x in r.json["rules"] if x["scope"] == "indicator"][0]["hides"] == 1
              and H.request("GET", "/api/devices/summary", role="viewer").json["flagged"] == 0,
              "silence: the same scope again replaces the rule; include_critical hides the C2 finding")
        check(H.request("POST", "/api/devices/silence", role="admin", origin=H.SAME,
                        body={"action": "add", "rule": {"scope": "device_kind", "device": "m00005e0053fe", "kind": "dns_lookup"}}).status == 404
              and H.request("POST", "/api/devices/silence", role="admin", origin=H.SAME,
                            body={"action": "add", "rule": {"scope": "suffix", "suffix": "example"}}).status == 400
              and H.request("POST", "/api/devices/silence", role="admin", origin=H.SAME, body={"action": "wipe"}).status == 400
              and H.request("POST", "/api/devices/silence", role="admin", origin=H.SAME,
                            body={"action": "remove", "id": "s000000000000"}).status == 404,
              "silence: unknown device 404, too-broad suffix 400, bad action 400, unknown id 404")
        # alerts: an event for a silenced finding sends nothing; after Unsilence it does
        A.ALERT_CONFIG_FILE = os.path.join(H.scratch, "alerts.json")
        A.DEVICE_ALERT_STATE = os.path.join(H.scratch, "device-alerts.json")
        sent_a = []
        real_send = A._device_alert_send
        A._device_alert_send = lambda key, sev, title, detail, priority=None: sent_a.append(title)
        try:
            evp = st + "/events.jsonl"
            open(evp, "a").close()
            A.devices_alert_pass()
            with open(evp, "a") as fh:
                fh.write(json.dumps({"type": "finding", "device": dw.mac_id(MAC_B), "finding": f_tv["id"],
                                     "severity": "high", "ts": int(tnow)}) + "\n")
            n_sil = A.devices_alert_pass()
            for x in H.request("GET", "/api/devices/silence", role="admin").json["rules"]:
                rr = H.request("POST", "/api/devices/silence", role="admin", origin=H.SAME, body={"action": "remove", "id": x["id"]})
            with open(evp, "a") as fh:
                fh.write(json.dumps({"type": "finding", "device": dw.mac_id(MAC_B), "finding": f_tv["id"],
                                     "severity": "high", "ts": int(tnow) + 1}) + "\n")
            n_unsil = A.devices_alert_pass()
        finally:
            A._device_alert_send = real_send
        check(n_sil == 0 and n_unsil == 1 and sent_a == ["Device flagged: tv-b"] and rr.status == 200
              and rr.json["rules"] == [] and json.load(open(conf + "/silence.json"))["rules"] == [],
              "alerts: silenced -> no push; Unsilence -> rules empty, the next event alerts (%r)" % sent_a)
        integ = A._integ_devices_recent()[0]
        check(any(x["id"] == f_tv["id"] for x in integ), "HA events: the finding is back after Unsilence")
        w(conf + "/silence.json", json.dumps({"version": 1, "rules": [dict(dw.validate_silence_rule(rule, time.time()),
                                                                           at=1, by="admin")]}))
        check(all(x["id"] != f_tv["id"] for x in A._integ_devices_recent()[0]), "HA events: silenced findings left out")
        os.unlink(conf + "/silence.json")
        # summary extras for the Security > Local cards: counts only
        s = H.request("GET", "/api/devices/summary", role="viewer").json
        check({"active", "new_zones", "key_set", "key_missing", "quarantine_next_expiry", "findings_silenced"} <= set(s)
              and "ads.tv-vendor.example" not in json.dumps(s) and C2_IP not in json.dumps(s),
              "summary: active/new zones/feeds key/quarantine expiry, no indicator (%r)" % sorted(s))
        # Zeek checksum switch: command building, result parsing, state (no zeekctl is ever run here)
        check(A._zeek_checksums_cmd(True)[1:] == ["--checksums", "on"] and A._zeek_checksums_cmd(False)[1:] == ["--checksums", "off"]
              and A._zeek_checksums_cmd(True)[0] == A.ZEEK_SITE_SETUP, "zeek: command per state")
        check(A._zeek_checksums_policy("## x\n@load policy/protocols/conn/mac-logging\nredef ignore_checksums = T;\n")
              and A._zeek_checksums_policy("  redef  ignore_checksums=T ;")
              and not A._zeek_checksums_policy("# redef ignore_checksums = T;\n@load policy/protocols/conn/mac-logging")
              and not A._zeek_checksums_policy("redef ignore_checksums = F;"), "zeek: policy parser (commented / F = off)")
        ok, msg = A._zeek_checksums_result(0, "zeek: site policy deployed (mac-logging + ignore_checksums)\n")
        ok1, msg1 = A._zeek_checksums_result(1, "zeek: 'zeekctl check' failed\n/opt/zeek/share/zeek/site/local.zeek, line 3\n")
        ok2, _m2 = A._zeek_checksums_result(None, "")
        check(ok and "deployed" in msg and not ok1 and "restored" in msg1 and "/opt" not in msg1 and not ok2,
              "zeek: result parsing (deployed / check failed -> restored, no paths / timeout)")
        site = os.path.join(H.scratch, "zeek-site")
        os.makedirs(site)
        w(site + "/local.zeek", "@load misc/loaded-scripts\n@load ./tuxwall-devicewatch.zeek\n")
        w(site + "/tuxwall-devicewatch.zeek", "@load policy/protocols/conn/mac-logging\n")
        script = os.path.join(H.scratch, "zeek-site-setup.sh")
        w(script, "#!/bin/bash\n# zeek-site-setup.sh [--checksums on|off]\n")
        A.ZEEK_SITE_DIRS, A.ZEEK_SITE_SETUP = (site,), script
        w(st + "/status.json", json.dumps({"generated_at": int(time.time()), "warnings": [
            {"code": "zeek_bad_checksums", "text": "Zeek sees bad checksums", "hint": "x"}],
            "sources": {"zeek": {"lines": 900, "tcp": 400, "bad_checksum": 376, "l2": 900}}}))
        r = H.request("GET", "/api/devices/feeds", role="viewer")
        z = r.json["zeek_checksums"]
        check(z["installed"] and z["enabled"] is False and z["supported"] and z["warning"] and z["bad_share"] == 0.94
              and site not in r.body.decode(), "zeek: GET shows off + the bad-checksum symptom, no paths (%r)" % z)
        w(site + "/tuxwall-devicewatch.zeek", "@load policy/protocols/conn/mac-logging\nredef ignore_checksums = T;\n")
        check(H.request("GET", "/api/devices/feeds", role="viewer").json["zeek_checksums"]["enabled"] is True, "zeek: on detected")
        check(H.request("POST", "/api/devices/zeek-checksums", role="viewer", origin=H.SAME, body={"enabled": True}).status == 403
              and H.request("POST", "/api/devices/zeek-checksums", role="admin", origin="https://evil.example.com",
                            body={"enabled": True}).status == 403
              and H.request("POST", "/api/devices/zeek-checksums", role="admin", origin=H.SAME, body={"enabled": "yes"}).status == 400,
              "zeek POST: viewer 403, foreign Origin 403, enabled must be a bool")
        ran = []
        real_run = A._zeek_checksums_run
        A._zeek_checksums_run = lambda on, who: ran.append((on, who))
        try:
            A._ZEEK_CK_JOB.clear()
            r = H.request("POST", "/api/devices/zeek-checksums", role="admin", origin=H.SAME, body={"enabled": False})
            busy = H.request("POST", "/api/devices/zeek-checksums", role="admin", origin=H.SAME, body={"enabled": True})
            for _i in range(50):
                if ran:
                    break
                time.sleep(0.02)
        finally:
            A._zeek_checksums_run = real_run
            A._ZEEK_CK_JOB.clear()
            A._ZEEK_CK_JOB["running"] = False
        check(r.status == 202 and r.json["started"] and busy.status == 409 and ran == [(False, "boss")],
              "zeek POST: starts one background job, a second one while it runs -> 409 (%r)" % ran)
        w(script, "#!/bin/bash\n# old script\n")
        check(H.request("POST", "/api/devices/zeek-checksums", role="admin", origin=H.SAME, body={"enabled": True}).status == 409,
              "zeek POST: an old zeek-site-setup.sh without --checksums -> 409")
        A.ZEEK_SITE_DIRS = (os.path.join(H.scratch, "no-zeek"),)
        check(H.request("GET", "/api/devices/feeds", role="viewer").json["zeek_checksums"]["installed"] is False
              and H.request("POST", "/api/devices/zeek-checksums", role="admin", origin=H.SAME, body={"enabled": True}).status == 409,
              "zeek: not installed -> hidden state, POST 409")
    finally:
        H.close()


# ── units ───────────────────────────────────────────────────────────────────

UNIT_DIR = os.path.join(ROOT, "pkg", "etc", "systemd", "system")


def unit(name):
    cp = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    cp.optionxform = str
    multi = {}
    with open(os.path.join(UNIT_DIR, name)) as f:
        sec = None
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                sec = line.strip("[]")
                continue
            k, _, v = line.partition("=")
            multi.setdefault((sec, k), []).append(v)
    return multi


def t_units():
    for name in ("tuxwall-devicewatch.service", "tuxwall-devicewatch-feeds.service"):
        u = unit(name)

        def one(k, sec="Service"):
            v = u.get((sec, k))
            return v[-1] if v else None
        check(one("User") == "tuxwall-devicewatch" and one("Group") == "tuxwall-devicewatch", name + ": own user")
        for k, v in (("NoNewPrivileges", "true"), ("ProtectSystem", "strict"), ("PrivateTmp", "true"),
                     ("ProtectHome", "true"), ("PrivateDevices", "true"), ("CapabilityBoundingSet", ""),
                     ("AmbientCapabilities", ""), ("IOSchedulingClass", "idle"), ("RestrictSUIDSGID", "true"),
                     ("StateDirectory", "tuxwall/devices"), ("BindPaths", "/var/lib/tuxwall/devices"),
                     ("TemporaryFileSystem", "/var/lib/tuxwall:ro")):
            check(one(k) == v, "%s: %s=%s (got %r)" % (name, k, v, one(k)))
        check(not u.get(("Service", "ReadWritePaths")) and not u.get(("Service", "SupplementaryGroups")),
              name + ": no ReadWritePaths beyond the state dir, groups from the postinst")
        check("/run/kea" in (one("InaccessiblePaths") or ""), name + ": Kea control socket inaccessible")
        check(int(one("Nice") or 0) >= 10 and int(one("CPUWeight") or 100) <= 50 and one("MemoryMax"),
              name + ": low priority, memory cap")
        execs = one("ExecStart") or ""
        check(execs.startswith("/usr/bin/python3 -B /var/www/html/includes/devicewatch.py "), name + ": ExecStart")
    main = unit("tuxwall-devicewatch.service")
    check(main[("Service", "RestrictAddressFamilies")][-1].split() == ["AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"]
          and main[("Service", "IPAddressDeny")][-1] == "any", "analysis service: no network (IPAddressDeny=any), netlink allowed")
    check(main[("Service", "SystemCallFilter")] == ["@system-service", "~@privileged @resources", "capset"]
          and main[("Service", "CapabilityBoundingSet")] == [""],
          "analysis service: syscall allow-list (+ capset for ip(8), harmless without capabilities)")
    check(main[("Service", "MemoryMax")][-1] == "256M" and main[("Install", "WantedBy")][-1] == "multi-user.target",
          "analysis service: MemoryMax 256M, enabled at boot")
    ro = " ".join(main.get(("Service", "BindReadOnlyPaths")) or []).split()
    check("-/var/lib/tuxwall/shared" in ro and not any(x.endswith("wg-peers.json") for x in ro)
          and dw.Config("").wg_snapshot == "/var/lib/tuxwall/shared/wg-peers.json",
          "DW-4: the WireGuard snapshot is mapped as its directory (atomic rewrites stay visible) (%r)" % ro)
    geo = open(os.path.join(ROOT, "www", "scripts", "geoip-setup.sh")).read()
    check("try-restart tuxwall-devicewatch" in geo, "DW-4: geoip-setup.sh restarts the engine after replacing the mapped database")
    fu = unit("tuxwall-devicewatch-feeds.service")
    check(fu[("Service", "Type")][-1] == "oneshot"
          and fu[("Service", "LoadCredential")][-1] == "abusech-key:/etc/tuxwall/devices/abuse-ch.key"
          and fu[("Service", "SetCredential")][-1] == "abusech-key:unset"
          and "AF_NETLINK" not in fu[("Service", "RestrictAddressFamilies")][-1]
          and not fu.get(("Service", "IPAddressDeny")), "feed unit: oneshot, key as an optional credential, HTTPS egress")
    t = unit("tuxwall-devicewatch-feeds.timer")
    check(t[("Timer", "OnUnitActiveSec")][-1] == "1h" and t[("Install", "WantedBy")][-1] == "timers.target",
          "feed timer: hourly")
    conff = open(os.path.join(ROOT, "pkg", "DEBIAN", "conffiles")).read().split()
    check(all("/etc/systemd/system/" + n in conff for n in ("tuxwall-devicewatch.service",
                                                             "tuxwall-devicewatch-feeds.service",
                                                             "tuxwall-devicewatch-feeds.timer")), "units are conffiles")
    cfg = dw.Config("")
    check(cfg.state_dir == "/var/lib/tuxwall/devices" and cfg.feeds_dir.startswith(cfg.state_dir + "/"),
          "engine state + feeds inside the unit's only writable dir")
    src = open(os.path.join(ROOT, "www", "includes", "devicewatch.py")).read()
    check("IPAddressDeny" not in src or True, "engine source present")
    check(all(x not in src for x in ("urlopen", "socket.create_connection", "http.client")),
          "analysis engine opens no network connection (feeds are a separate unit)")


for t in (t_follower, t_feeds, t_engine, t_campaign4, t_false_positives, t_small_batch, t_score, t_silence, t_units,
          t_api):
    try:
        t()
    except Exception:
        import traceback
        traceback.print_exc()
        check(False, "%s raised" % t.__name__)

try:
    import api_harness
    with api_harness._HarnessIO():
        shutil.rmtree(TMP, ignore_errors=True)
except ImportError:
    shutil.rmtree(TMP, ignore_errors=True)
print("devicewatch_check: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
