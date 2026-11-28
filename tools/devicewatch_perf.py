#!/usr/bin/env python3
"""Device-monitoring engine performance: one hour of synthetic Zeek logs at
the maintainer router's volume (~16 MB conn.log + ~12 MB dns.log per hour,
~45 devices; mixed in: DNS/NTP to the router, Home Assistant polling the
IoT VLAN, a backup job, push check-ins, browser DoH, a beacon, a LAN sweep,
plus an ssl.log) and ThreatFox-sized indicator sets, processed by a fresh
engine process - once as Phase 1 (behaviour detectors off, no baselines)
and once with baselines + every behaviour detector in shadow mode - plus
one beaconing evaluation over a full day of check-ins. Reports CPU seconds
and peak RSS (VmHWM); fails above the targets.

    python3 tools/devicewatch_perf.py [--keep]

Targets: < 60 s CPU per hour of logs, < 200 MB peak RSS, and Phase 2
(baselines + behaviour detectors + a day of beaconing state) at most +50 %
of Phase 1 in CPU and memory. Documentation addresses and example domains
only.
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
INC = os.path.join(os.path.dirname(HERE), "www", "includes")
CPU_MAX = 60.0
RSS_MAX_MB = 200
BUDGET_RATIO = 1.5      # Phase 2: behaviour detection costs at most +50 % of Phase 1
CONN_BYTES = 16 << 20
DNS_BYTES = 12 << 20
DEVICES = 45
sys.path.insert(0, INC)
import devicewatch_feeds as feeds  # noqa: E402

# peak RSS of the child itself: VmHWM (ru_maxrss survives fork + exec, so it
# would report this parent's peak while it still held the generated logs)
HWM = r'''
def hwm_kb():
    try:
        for line in open("/proc/self/status"):
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def rss_kb():
    try:
        for line in open("/proc/self/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return 0
'''

CHILD = HWM + r'''
import json, os, resource, sys, time
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import devicewatch as dw
root, t0 = sys.argv[2], float(sys.argv[3])
devs = json.load(open(root + "/devs.json"))

class Src:
    def neighbours(self):
        out = []
        for mac, v4, v6 in devs:
            out.append({"dst": v4, "dev": "lan0", "lladdr": mac, "state": ["REACHABLE"]})
            out.append({"dst": v6, "dev": "lan0", "lladdr": mac, "state": ["STALE"]})
        return out
    def addresses(self):
        return [{"ifname": "lan0", "address": "00:00:5e:00:53:fe", "addr_info": [{"local": "192.0.2.1", "prefixlen": 25},
                                                 {"local": "2001:db8:1::1", "prefixlen": 64}]},
                {"ifname": "wan0", "addr_info": [{"local": "198.51.100.2", "prefixlen": 24}]}]
    def default_route_devs(self):
        return {"wan0"}
    def journal(self, cursor):
        return [], cursor, None

dw.LOG_BUDGET_BYTES = 64 << 20
if sys.argv[4] == "phase1":         # the 3.3.7 engine: no baselines either
    dw.Baselines.flow = dw.Baselines.dns = lambda *a, **k: None
eng = dw.Engine(dw.Config(root), Src(), lambda: t0 + 3600)
c0 = time.process_time()
eng.cycle()
cpu = time.process_time() - c0
ru = resource.getrusage(resource.RUSAGE_SELF)
st = eng.status(t0 + 3600)
print(json.dumps({"cpu": cpu, "rss_kb": hwm_kb(), "conn_lines": st["logs"]["conn"]["lines"],
                  "dns_lines": st["logs"]["dns"]["lines"], "devices": len(eng.devices),
                  "findings": len(eng.findings), "unattributed": st["stats"]["unattributed"],
                  "indicators": st["indicators"], "shadow": len(eng.shadow), "detectors": st["detectors"],
                  "modes": eng.modes}))
'''

# One full beaconing evaluation over a day of check-ins at the owner's
# volume (~35k flows/h -> ~850k connection starts/day spread over device x
# destination pairs, a few busy pairs capped at MAX_POINTS): the engine
# runs it at most every PAIR_EVAL seconds per pair (3600 / PAIR_EVAL per hour).
EVAL_CHILD = HWM + r'''
import json, random, resource, sys, time
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import devicewatch as dw
from array import array
rnd = random.Random(11)
now = 1795560000
det = dw.BeaconDetector()
import gc
gc.collect()
rss0 = rss_kb()
total = 0
for d in range(45):
    did = "m00005e0053%02x" % (d + 1)
    for k in range(600):
        r = rnd.random()
        n = 3000 if r < 0.004 else rnd.randrange(100, 1500) if r < 0.06 else rnd.randrange(24, 100) if r < 0.2 else rnd.randrange(1, 24)
        if total + n > 850000:
            n = 1
        step = 86400 // max(n, 1)
        times = array("I", sorted(now - 86400 + i * step + rnd.randrange(0, max(1, step // 3)) for i in range(n)))
        det.pairs[(did, "svc%d.example%d.com" % (k, d % 7))] = [times, array("I", [rnd.randrange(200, 4000) for _ in range(n)]),
                                                              "198.51.100.%d" % (k % 250), 443, "tcp", 0, 0, 0]
        total += n
class E:
    class intel:
        @staticmethod
        def match_ip(ip): return []
        @staticmethod
        def match_domain(q): return []
gc.collect()
state_kb = rss_kb() - rss0
c0 = time.process_time()
out = det.on_cycle(E(), now)
cpu = time.process_time() - c0
print(json.dumps({"eval_cpu": cpu, "points": total, "pairs": len(det.pairs), "reported": len(out),
                  "rss_kb": hwm_kb(), "state_kb": state_kb,
                  "per_hour": 3600.0 / det.PAIR_EVAL}))
'''


def main():
    rnd = random.Random(7)
    root = tempfile.mkdtemp(prefix="dw-perf-")
    t0 = float(int(time.time()) // 3600 * 3600 - 3600)
    spool = root + "/opt/zeek/spool/manager"
    os.makedirs(spool)
    os.makedirs(root + "/opt/zeek/logs")
    os.symlink(spool, root + "/opt/zeek/logs/current")
    os.makedirs(root + "/etc/tuxwall")
    with open(root + "/etc/tuxwall/interfaces.json", "w") as f:
        json.dump({"wan": {"device": "wan0"}, "lan": {"device": "lan0"}}, f)
    devs = []
    for i in range(DEVICES):
        mac = "00:00:5e:00:53:%02x" % (i + 1)
        devs.append((mac, "192.0.2.%d" % (i + 10), "2001:db8:1:0:%x:%x:%x:%x" % tuple(rnd.randrange(1, 65535) for _ in range(4))))
    with open(root + "/devs.json", "w") as f:
        json.dump(devs, f)
    ext = ["198.51.100.%d" % (i % 250 + 3) if i % 3 else "2001:db8:ffff::%x" % i for i in range(9000)]
    ext += ["203.0.113.%d" % i for i in range(1, 255)]
    domains = ["host%d.example%d.com" % (i, i % 97) for i in range(4000)]
    # indicators: ThreatFox-sized sets (+ a few that will match)
    fdir = root + "/var/lib/tuxwall/devices/feeds"
    os.makedirs(fdir)
    tf_ip = {"203.0.113.%d" % i: {"m": "ExampleRAT", "t": "botnet_cc", "c": 90} for i in range(1, 5)}
    for i in range(60000):
        tf_ip["2001:db8:ee:%x::%x" % (i // 4096, i % 4096)] = {"m": "x", "t": "botnet_cc", "c": 75}
    tf_dom = {"bad%d.example.net" % i: {"m": "x", "t": "payload_delivery", "c": 80} for i in range(150000)}
    tf_dom["host5.example5.com"] = {"m": "ExampleRAT", "t": "botnet_cc", "c": 100}
    with open(fdir + "/threatfox.json", "w") as f:
        json.dump(dict(feeds.compact({"ip": tf_ip, "domain": tf_dom}), schema=1, feed="threatfox"), f)
    with open(fdir + "/urlhaus.json", "w") as f:
        json.dump(dict(feeds.compact({"ip": {}, "domain": {"u%d.example.org" % i: {"t": "malware_host"}
                                                            for i in range(20000)}}), schema=1, feed="urlhaus"), f)
    # one hour of logs
    size = 0
    lines = []
    n = 0
    while size < CONN_BYTES:
        mac, v4, v6 = devs[rnd.randrange(DEVICES)]
        r = ext[rnd.randrange(len(ext))]
        o = v6 if ":" in r else v4
        ts = t0 + rnd.random() * 3600
        st = rnd.choice(("SF", "SF", "SF", "S0", "RSTO", "OTH", "SHR"))
        rec = {"ts": ts, "uid": "C%016x" % rnd.getrandbits(64), "id.orig_h": o, "id.orig_p": rnd.randrange(1024, 65535),
               "id.resp_h": r, "id.resp_p": rnd.choice((443, 443, 443, 80, 53, 123, 8883)),
               "proto": rnd.choice(("tcp", "tcp", "udp")), "service": "ssl", "duration": rnd.random() * 30,
               "orig_bytes": rnd.randrange(0, 5000), "resp_bytes": rnd.randrange(0, 200000), "conn_state": st,
               "local_orig": False, "local_resp": False, "missed_bytes": 0, "history": "ShADadFf",
               "orig_pkts": 12, "orig_ip_bytes": rnd.randrange(100, 9000), "resp_pkts": 20,
               "resp_ip_bytes": rnd.randrange(100, 250000), "ip_proto": 6,
               "orig_l2_addr": mac, "resp_l2_addr": "00:00:5e:00:53:fe"}      # Zeek mac-logging (live since 3.3.7)
        line = json.dumps(rec, separators=(",", ":")) + "\n"
        lines.append(line)
        size += len(line)
        n += 1
    # realistic periodic / benign traffic (Phase 2 detectors, 3.3.8): DNS and NTP
    # to the router, Home Assistant polling the IoT VLAN, a backup job to a NAS
    # port, push / update check-ins, browser DoH from phones, one beacon
    macs = {v4: mac for mac, v4, _v6 in devs}

    def rec(ts, o, mac, r, rp, proto="tcp", state="SF", ob=600, rb=1200):
        return json.dumps({"ts": ts, "uid": "C%016x" % rnd.getrandbits(64), "id.orig_h": o,
                           "id.orig_p": rnd.randrange(1024, 65535), "id.resp_h": r, "id.resp_p": rp, "proto": proto,
                           "duration": 0.2, "orig_bytes": ob, "resp_bytes": rb, "conn_state": state,
                           "history": "S" if state == "S0" else "ShADadFf",
                           "orig_pkts": 4, "orig_ip_bytes": ob + 120, "resp_pkts": 4 if rb else 0,
                           "resp_ip_bytes": rb + 120 if rb else 0, "orig_l2_addr": mac,
                           "resp_l2_addr": macs.get(r, "00:00:5e:00:53:fe")}, separators=(",", ":")) + "\n"
    periodic = []
    for i, (mac, v4, v6) in enumerate(devs):
        for k in range(rnd.randrange(20, 60)):                      # DNS to the router (filtered early)
            periodic.append(rec(t0 + rnd.random() * 3600, v4, mac, "192.0.2.1", 53, "udp", "SF", 60, 120))
        for k in range(56):                                          # NTP every 64 s
            periodic.append(rec(t0 + k * 64 + i, v4, mac, "203.0.113.123", 123, "udp", "SF", 76, 76))
        for k in range(4):                                           # push check-in every 15 min
            periodic.append(rec(t0 + k * 900 + i * 7, v4, mac, "198.51.100.%d" % (200 + i % 5), 5223))
    for k in range(120):                                             # Home Assistant polls 15 IoT devices / 30 s
        for j in range(30, 45):
            periodic.append(rec(t0 + k * 30 + j * 0.1, devs[0][1], devs[0][0], devs[j][1], 80))
    for k in range(60):                                              # backup job: one NAS port every minute
        periodic.append(rec(t0 + k * 60, devs[1][1], devs[1][0], devs[2][1], 445, ob=900000, rb=2000))
    for i in range(3, 8):                                            # phones with browser DoH
        for k in range(30):
            periodic.append(rec(t0 + rnd.random() * 3600, devs[i][1], devs[i][0], "1.1.1.1", 443, ob=900, rb=3000))
    for k in range(60):                                              # one regular beacon (every 60 s)
        periodic.append(rec(t0 + k * 60 + rnd.random(), devs[9][1], devs[9][0], "203.0.113.200", 443, ob=420, rb=900))
    for j in range(10, 60):                                          # a short LAN sweep from one device
        periodic.append(rec(t0 + 1800 + j * 0.5, devs[10][1], devs[10][0], "192.0.2.%d" % j, 22, state="S0", ob=0, rb=0))
    for line in periodic:
        lines[rnd.randrange(len(lines))] = line                      # same volume, mixed in
    with open(spool + "/conn.log", "w") as f:
        f.writelines(lines)
    conn_lines = n
    with open(spool + "/ssl.log", "w") as f:                         # TLS server names for ~1/4 of the flows
        for k in range(n // 4):
            r = ext[rnd.randrange(len(ext))]
            f.write(json.dumps({"ts": t0 + rnd.random() * 3600, "uid": "C%016x" % rnd.getrandbits(64),
                                "id.orig_h": devs[rnd.randrange(DEVICES)][1], "id.resp_h": r, "id.resp_p": 443,
                                "version": "TLSv13", "server_name": domains[rnd.randrange(len(domains))],
                                "established": True}, separators=(",", ":")) + "\n")
    size, lines, n = 0, [], 0
    while size < DNS_BYTES:
        mac, v4, v6 = devs[rnd.randrange(DEVICES)]
        q = domains[rnd.randrange(len(domains))]
        ts = t0 + rnd.random() * 3600
        ok = rnd.random() < 0.85
        rec = {"ts": ts, "uid": "D%016x" % rnd.getrandbits(64), "id.orig_h": rnd.choice((v4, v6)),
               "id.orig_p": rnd.randrange(1024, 65535), "id.resp_h": "192.0.2.1", "id.resp_p": 53, "proto": "udp",
               "trans_id": rnd.randrange(65535), "rtt": 0.01, "query": q, "qclass": 1, "qclass_name": "C_INTERNET",
               "qtype": 1, "qtype_name": "A", "rcode": 0 if ok else 3, "rcode_name": "NOERROR" if ok else "NXDOMAIN",
               "AA": False, "TC": False, "RD": True, "RA": True, "Z": 0, "rejected": False}
        if ok:
            rec["answers"] = [ext[rnd.randrange(len(ext))] for _ in range(rnd.randrange(1, 4))]
            rec["TTLs"] = [300.0] * len(rec["answers"])
        line = json.dumps(rec, separators=(",", ":")) + "\n"
        lines.append(line)
        size += len(line)
        n += 1
    with open(spool + "/dns.log", "w") as f:
        f.writelines(lines)
    for name in ("dhcp", "software", "known_hosts"):
        open(spool + "/%s.log" % name, "w").close()
    lines = None
    state = root + "/var/lib/tuxwall/devices"
    conf = root + "/etc/tuxwall/devices"
    os.makedirs(conf)

    def run(modes):
        """One fresh engine over the same hour of logs; modes None = the
        defaults (every behaviour detector in shadow mode)."""
        for name in os.listdir(state):
            if name != "feeds":
                os.unlink(os.path.join(state, name))
        cfgp = conf + "/devicewatch.json"
        if modes:
            with open(cfgp, "w") as f:
                json.dump({"detectors": modes}, f)
        elif os.path.exists(cfgp):
            os.unlink(cfgp)
        p = subprocess.run([sys.executable, "-c", CHILD, INC, root, str(t0), "phase1" if modes else "full"],
                           capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            print(p.stderr[-3000:])
            return None
        return json.loads(p.stdout.strip().splitlines()[-1])

    base = run({k: "off" for k in ("beaconing", "dns_bypass", "internal_scan")})
    res = run(None)
    ev = subprocess.run([sys.executable, "-c", EVAL_CHILD, INC], capture_output=True, text=True, timeout=600)
    evr = json.loads(ev.stdout.strip().splitlines()[-1]) if ev.returncode == 0 else None
    if base is None or res is None or evr is None:
        print(ev.stderr[-3000:])
        print("devicewatch_perf: engine failed")
        return 1
    rss_mb = res["rss_kb"] / 1024
    print("devicewatch_perf: 1 h of logs = %d conn + %d dns lines (%.0f + %.0f MB, incl. periodic/benign/LAN traffic),"
          " %d devices, indicators %s"
          % (conn_lines, n, CONN_BYTES / 1048576, DNS_BYTES / 1048576, res["devices"],
             {k: sum(v.values()) for k, v in res["indicators"].items()}))
    print("devicewatch_perf: Phase 1 only (behaviour detectors off, no baselines): CPU %.1f s, peak RSS %.0f MB"
          % (base["cpu"], base["rss_kb"] / 1024))
    eval_h = evr["per_hour"] * evr["eval_cpu"]
    mem = res["rss_kb"] / 1024 + evr["state_kb"] / 1024        # + a full day of beaconing state
    mem_ratio = mem / (base["rss_kb"] / 1024)
    total = res["cpu"] + eval_h
    ratio = total / base["cpu"] if base["cpu"] else 0
    print("devicewatch_perf: with baselines + behaviour detectors (shadow): CPU %.1f s + beacon evaluation %.1f s/h (%g x %.2f s for "
          "%d check-ins in %d pairs) = %.1f s (target < %.0f; %.2f x Phase 1, budget %.1f x), peak RSS %.0f MB "
          "+ %.0f MB for a day of beaconing state = %.0f MB (target < %d; %.2f x Phase 1), findings %d, shadow rows %d, "
          "unattributed %d"
          % (res["cpu"], eval_h, evr["per_hour"], evr["eval_cpu"], evr["points"], evr["pairs"], total, CPU_MAX, ratio, BUDGET_RATIO,
             rss_mb, evr["state_kb"] / 1024, mem, RSS_MAX_MB, mem_ratio, res["findings"], res["shadow"],
             res["unattributed"]))
    print("devicewatch_perf: detectors %s" % json.dumps(res["detectors"], sort_keys=True))
    ok = total < CPU_MAX and rss_mb < RSS_MAX_MB and res["conn_lines"] == conn_lines and res["dns_lines"] == n \
        and res["findings"] > 0 and res["findings"] == base["findings"] and mem < RSS_MAX_MB \
        and ratio <= BUDGET_RATIO and mem_ratio <= BUDGET_RATIO and set(res["modes"].values()) == {"shadow"} and res["shadow"] > 0
    if "--keep" in sys.argv:
        print("kept:", root)
    else:
        shutil.rmtree(root, ignore_errors=True)
    print("devicewatch_perf: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
