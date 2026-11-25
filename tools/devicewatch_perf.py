#!/usr/bin/env python3
"""Device-monitoring engine performance: one hour of synthetic Zeek logs at
the maintainer router's volume (~16 MB conn.log + ~12 MB dns.log per hour,
~45 devices) plus ThreatFox-sized indicator sets, processed by a fresh
engine process. Reports CPU seconds and peak RSS; fails above the targets.

    python3 tools/devicewatch_perf.py [--keep]

Targets: < 60 s CPU per hour of logs, < 200 MB peak RSS. Documentation
addresses and example domains only.
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
CONN_BYTES = 16 << 20
DNS_BYTES = 12 << 20
DEVICES = 45
sys.path.insert(0, INC)
import devicewatch_feeds as feeds  # noqa: E402

CHILD = r'''
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
        return [{"ifname": "lan0", "addr_info": [{"local": "192.0.2.1", "prefixlen": 25},
                                                 {"local": "2001:db8:1::1", "prefixlen": 64}]},
                {"ifname": "wan0", "addr_info": [{"local": "198.51.100.2", "prefixlen": 24}]}]
    def default_route_devs(self):
        return {"wan0"}
    def journal(self, cursor):
        return [], cursor, None

dw.LOG_BUDGET_BYTES = 64 << 20
eng = dw.Engine(dw.Config(root), Src(), lambda: t0 + 3600)
c0 = time.process_time()
eng.cycle()
cpu = time.process_time() - c0
ru = resource.getrusage(resource.RUSAGE_SELF)
st = eng.status(t0 + 3600)
print(json.dumps({"cpu": cpu, "rss_kb": ru.ru_maxrss, "conn_lines": st["logs"]["conn"]["lines"],
                  "dns_lines": st["logs"]["dns"]["lines"], "devices": len(eng.devices),
                  "findings": len(eng.findings), "unattributed": st["stats"]["unattributed"],
                  "indicators": st["indicators"]}))
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
    with open(spool + "/conn.log", "w") as f:
        f.writelines(lines)
    conn_lines = n
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
    p = subprocess.run([sys.executable, "-c", CHILD, INC, root, str(t0)], capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        print(p.stderr[-3000:])
        print("devicewatch_perf: engine failed")
        return 1
    res = json.loads(p.stdout.strip().splitlines()[-1])
    rss_mb = res["rss_kb"] / 1024
    print("devicewatch_perf: 1 h of logs = %d conn + %d dns lines (%.0f + %.0f MB), %d devices, indicators %s"
          % (conn_lines, n, CONN_BYTES / 1048576, DNS_BYTES / 1048576, res["devices"],
             {k: sum(v.values()) for k, v in res["indicators"].items()}))
    print("devicewatch_perf: processed %d conn + %d dns lines: CPU %.1f s (target < %.0f), peak RSS %.0f MB "
          "(target < %d), findings %d, unattributed %d"
          % (res["conn_lines"], res["dns_lines"], res["cpu"], CPU_MAX, rss_mb, RSS_MAX_MB, res["findings"],
             res["unattributed"]))
    ok = res["cpu"] < CPU_MAX and rss_mb < RSS_MAX_MB and res["conn_lines"] == conn_lines and res["dns_lines"] == n \
        and res["findings"] > 0
    if "--keep" in sys.argv:
        print("kept:", root)
    else:
        shutil.rmtree(root, ignore_errors=True)
    print("devicewatch_perf: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
