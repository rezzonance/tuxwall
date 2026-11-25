#!/usr/bin/env python3
"""Device quarantine (www/includes/quarantine.py + the API routes) without
touching the host:

  python3 tools/quarantine_check.py

Pure part: nftables rule generation from fixtures (internet / isolate /
WireGuard nets / empty table), the router + gateway filter in plan(),
address sync when a device's addresses change (and an address handed to
another device), expiry, persistence (0600, symlink refused, garbage
tolerated), the boot restore (expired entries skipped, nft failure -> rc 1),
the live-table comparison (no rewrite when it already matches), and every
refusal of the decision function (router MAC/address, upstream gateway,
the admin's own device by IP / neighbour MAC / VPN net, confirm_self, wide
VPN peers, no WAN for internet mode, bad mode/expiry, no address).
API part (tools/api_harness.py sandbox, nft stubbed): admin + CSRF only,
quarantine -> state + table + action log + alert, self refusal and
confirm_self, release, list/detail/summary fields, the minute sync (address
refresh, expiry + alert), device alert settings, the alert pass over the
engine's events.jsonl (first run starts at the end, dedupe, minimum
severity, LAN-only new-device alerts, rate limit, rotation).
"""
import json
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "www", "includes"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.dont_write_bytecode = True
import quarantine as Q  # noqa: E402

PASS = FAIL = 0
TMP = tempfile.mkdtemp(prefix="quarantine-check-")
NOW = 1_800_000_000.0
MAC_A = "02:00:5e:00:53:01"
MAC_B = "02:00:5e:00:53:02"
ROUTER_MAC = "02:00:5e:00:53:fe"
GW_MAC = "02:00:5e:00:53:fd"


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


class FakeNet:
    """Stub for ip(8) and nft(8): records nft scripts, keeps a fake table."""

    def __init__(self, nft_fail=False):
        self.scripts = []
        self.nft_fail = nft_fail
        self.table = None           # plan last applied
        self.neigh = [{"dst": "198.51.100.1", "lladdr": GW_MAC},
                      {"dst": "192.0.2.50", "lladdr": MAC_A},
                      {"dst": "192.0.2.60", "lladdr": MAC_B}]

    def __call__(self, cmd, text=None, timeout=20):
        prog = os.path.basename(cmd[0])
        if prog == "ip":
            a = cmd[1:]
            if a[:3] == ["-j", "link", "show"]:
                return 0, json.dumps([{"ifname": "lo", "address": "00:00:00:00:00:00"},
                                      {"ifname": "lan0", "address": ROUTER_MAC}])
            if a[:3] == ["-j", "addr", "show"]:
                return 0, json.dumps([{"ifname": "lan0", "addr_info": [{"local": "192.0.2.1"},
                                                                       {"local": "2001:db8::1"}]},
                                      {"ifname": "wan0", "addr_info": [{"local": "198.51.100.2"}]}])
            if a[:4] == ["-4", "-j", "route", "show"]:
                return 0, json.dumps([{"dst": "default", "gateway": "198.51.100.1", "dev": "wan0"}])
            if a[:4] == ["-6", "-j", "route", "show"]:
                return 0, json.dumps([])
            if a[:3] == ["-j", "neigh", "show"]:
                return 0, json.dumps(self.neigh)
            return 1, ""
        if prog == "nft":
            if cmd[1:3] == ["-f", "-"]:
                self.scripts.append(text)
                if self.nft_fail:
                    return 1, "Error: stub refused"
                self.table = text
                return 0, ""
            if cmd[1:3] == ["-j", "list"]:
                if self.table is None:
                    return 1, "Error: No such file or directory"
                return 0, json.dumps({"nftables": nft_json(self.table)})
        return 127, "unexpected command %r" % cmd


def nft_json(script):
    """nft -j list table output for a rendered script (what the kernel would hold)."""
    items = [{"table": {"family": "inet", "name": Q.TABLE}}]
    sets = {}
    for ln in script.splitlines():
        if ln.startswith("add set"):
            sets[ln.split()[4]] = []
        elif ln.startswith("add chain"):
            name = ln.split()[4]
            hook = ln.split("hook ")[1].split()[0] if "hook " in ln else None
            items.append({"chain": dict({"name": name}, **({"hook": hook} if hook else {}))})
        elif ln.startswith("add rule"):
            items.append({"rule": {"expr": []}})
        elif ln.startswith("add element"):
            name = ln.split()[4]
            for x in ln.split("{", 1)[1].rstrip(" }").split(","):
                x = x.strip()
                if "/" in x:
                    addr, ln_ = x.split("/")
                    sets[name].append({"prefix": {"addr": addr, "len": int(ln_)}})
                else:
                    sets[name].append(x)
    for n, el in sets.items():
        items.append({"set": dict({"name": n}, **({"elem": el} if el else {}))})
    return items


def env_for(name, net=None, clock=lambda: NOW):
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    os.makedirs(os.path.join(d, "sysnet", "lan0"), exist_ok=True)
    with open(os.path.join(d, "sysnet", "lan0", "address"), "w") as f:
        f.write(ROUTER_MAC + "\n")
    e = Q.Env(state_file=os.path.join(d, "etc", "quarantine.json"), log_file=os.path.join(d, "var", "actions.jsonl"),
              run=net or FakeNet(), clock=clock, sys_net=os.path.join(d, "sysnet"))
    e.nft, e.ip = "/usr/sbin/nft", "/usr/sbin/ip"
    return e


def dev(did, mac=None, ips=(), ipv6=(), cur=(), name="dev", **kw):
    return dict({"id": did, "name": name, "mac": mac, "ips": list(ips), "ipv6": list(ipv6), "current_ips": list(cur),
                 "private_mac": False}, **kw)


DA = dev("m02005e005301", MAC_A, ["192.0.2.50"], ["2001:db8::50", "fe80::1"], ["192.0.2.50"], name="laptop")
DB = dev("m02005e005302", MAC_B, ["192.0.2.60"], [], ["192.0.2.60"], name="tv")
WG_PK = "A" * 43 + "="
DW = dev("w0123456789abcdef", None, [], [], ["198.18.0.7/32", "2001:db8:7::7/128"], name="vpn-phone",
         wg_public_key=WG_PK)


# ── pure ─────────────────────────────────────────────────────────────────────

def t_render():
    ctx = {"macs": set(), "ips": set(), "gateways": set(), "gateway_macs": set(), "wan": ["wan0"]}
    ta = Q.device_targets(DA, [DA, DB])
    check(ta == {"kind": "mac", "mac": MAC_A, "ips": ["192.0.2.50"], "ipv6": ["2001:db8::50"], "nets": []},
          "targets: MAC + v4/v6, link-local dropped (%r)" % ta)
    tw = Q.device_targets(DW, [DW], [{"public_key": WG_PK, "allowed_ips": ["198.18.0.7/32"]}])
    check(tw["kind"] == "wg" and tw["mac"] == "" and tw["nets"] == ["198.18.0.7/32", "2001:db8:7::7/128"],
          "targets: WireGuard peer by allowed IPs (%r)" % tw)
    st = {"wan": ["wan0"], "entries": [Q.make_entry(DA, ta, "internet", "none", NOW),
                                        Q.make_entry(DW, tw, "isolate", "1h", NOW)]}
    p = Q.plan(st, ctx, NOW)
    check(p["internet"] == {"mac": [MAC_A], "v4": ["192.0.2.50"], "v6": ["2001:db8::50"]}
          and p["isolate"] == {"mac": [], "v4": ["198.18.0.7"], "v6": ["2001:db8:7::7"]}, "plan sets (%r)" % p)
    s = Q.render(p)
    rules = [ln for ln in s.splitlines() if ln.startswith("add rule")]
    check(s.startswith("add table inet tuxwall_quarantine\ndelete table inet tuxwall_quarantine\nadd table"),
          "render: atomic table swap")
    check('add rule inet tuxwall_quarantine forward oifname { "wan0" } ether saddr @inet_mac counter drop' in s
          and 'iifname { "wan0" } ip daddr @inet_v4' in s and 'oifname { "wan0" } ip6 saddr @inet_v6' in s,
          "render: internet = MAC + addresses to/from the WAN")
    check("forward ip daddr @iso_v4 counter drop" in s and "input ether saddr @iso_mac jump iso_in" in s
          and "iso_in udp dport { 53, 67, 547 } return" in s and "iso_in tcp dport { 53 } return" in s
          and "iso_in meta l4proto { icmp, ipv6-icmp } return" in s, "render: isolate = no forwarding, router DNS/DHCP/ICMP only")
    check(rules[-1].startswith("add rule inet tuxwall_quarantine iso_in counter drop"), "render: iso_in ends in a drop")
    check("add element inet tuxwall_quarantine inet_mac { %s }" % MAC_A in s
          and "add element inet tuxwall_quarantine iso_v6 { 2001:db8:7::7 }" in s, "render: elements")
    check(all("accept" not in ln for ln in rules), "render: no accept anywhere (drops only)")
    empty = Q.render(Q.plan({"entries": []}, ctx, NOW))
    check("add rule" not in empty and "add set inet tuxwall_quarantine iso_mac" in empty
          and "hook forward priority -5; policy accept" in empty, "render: empty table = sets + chains, no rules")
    # only internet entries: no isolate rules (and vice versa)
    s1 = Q.render(Q.plan({"wan": ["wan0"], "entries": st["entries"][:1]}, ctx, NOW))
    check("iso_in counter drop" not in s1 and "@inet_mac" in s1, "render: only the modes in use")
    s2 = Q.render(Q.plan({"wan": [], "entries": st["entries"][:1]}, dict(ctx, wan=[]), NOW))
    check("@inet_mac" not in s2, "render: no WAN known -> no internet rules (refused earlier)")


def t_plan_filter():
    ctx = {"macs": {ROUTER_MAC}, "ips": {"192.0.2.1"}, "gateways": {"198.51.100.1"}, "gateway_macs": {GW_MAC},
           "wan": ["wan0"]}
    bad = [Q._clean_entry({"device": "m02005e0053fe", "mode": "isolate", "mac": ROUTER_MAC, "ips": ["192.0.2.1"]}),
           Q._clean_entry({"device": "m02005e0053fd", "mode": "isolate", "mac": GW_MAC}),
           Q._clean_entry({"device": "m02005e005399", "mode": "internet", "ips": ["192.0.2.1", "198.51.100.1",
                                                                                   "192.0.2.77"]}),
           Q._clean_entry({"device": "w00000000000000aa", "mode": "isolate", "nets": ["192.0.2.0/24"]}),
           Q._clean_entry({"device": "m02005e005398", "mode": "isolate", "mac": MAC_B, "expires": NOW - 1}),
           Q._clean_entry({"device": "m02005e005397", "mode": "isolate", "mac": MAC_A, "expires": NOW + 60})]
    p = Q.plan({"wan": ["wan0"], "entries": bad}, ctx, NOW)
    allv = sum((p[m][k] for m in Q.MODES for k in ("mac", "v4", "v6")), [])
    check(ROUTER_MAC not in allv and GW_MAC not in allv and "192.0.2.1" not in allv and "198.51.100.1" not in allv
          and "192.0.2.0/24" not in allv, "plan: router/gateway MACs, addresses and covering nets never rendered (%r)" % allv)
    check("192.0.2.77" in p["internet"]["v4"] and MAC_A in p["isolate"]["mac"] and MAC_B not in allv,
          "plan: the rest stays; expired skipped, not yet expired kept")
    check({"expired", "router-mac", "router-net"} <= {r for _d, r in p["skipped"]}, "plan: skip reasons %r" % p["skipped"])
    check(Q._clean_entry({"device": "w00000000000000ab", "mode": "isolate", "nets": ["0.0.0.0/0"]}) is None,
          "state: a wide VPN net is never loaded")
    check(Q._clean_entry({"device": "x123", "mode": "isolate", "mac": MAC_A}) is None
          and Q._clean_entry({"device": "m02005e005301", "mode": "block", "mac": MAC_A}) is None
          and Q._clean_entry({"device": "m02005e005301", "mode": "isolate", "ips": ["127.0.0.1", "ff02::1"]}) is None,
          "state: bad id / mode / unusable addresses rejected")


def t_refusals():
    e = env_for("ref")
    ctx = Q.router_context(e, ["wan0"])
    check(ROUTER_MAC in ctx["macs"] and "192.0.2.1" in ctx["ips"] and ctx["gateways"] == {"198.51.100.1"}
          and ctx["gateway_macs"] == {GW_MAC} and ctx["neigh"]["192.0.2.50"] == MAC_A, "router context (%r)" % ctx)
    ta = Q.device_targets(DA, [DA, DB])

    def code(device, targets, mode="internet", expires="none", client="", confirm=False, c=ctx):
        r = Q.check_request(device, targets, mode, expires, c, client, confirm)
        return None if r is None else (r[0], r[1].get("code"))

    check(code(DA, ta, client="192.0.2.99") is None, "allowed: another admin device")
    check(code(DA, ta, mode="block") == (400, "mode") and code(DA, ta, expires="2h") == (400, "expires"),
          "bad mode / expiry -> 400")
    r = dev("m02005e0053fe", ROUTER_MAC, ["192.0.2.200"])
    check(code(r, Q.device_targets(r)) == (403, "router"), "router MAC refused")
    r = dev("i00000000000000aa", None, ["192.0.2.1"])
    check(code(r, Q.device_targets(r)) == (403, "router"), "router address refused")
    g = dev("m02005e0053fd", GW_MAC, [])
    check(code(g, Q.device_targets(g)) == (403, "gateway"), "upstream gateway MAC refused")
    g = dev("i00000000000000ab", None, ["198.51.100.1"])
    check(code(g, Q.device_targets(g)) == (403, "gateway"), "upstream gateway address refused")
    check(code(DA, ta, client="192.0.2.50") == (409, "self"), "self by IP refused")
    check(code(dev("m02005e005301", MAC_A, [], [], []), {"kind": "mac", "mac": MAC_A, "ips": [], "ipv6": [], "nets": []},
               client="192.0.2.50") == (409, "self"), "self by neighbour MAC refused (address not in the inventory)")
    check(code(DA, ta, client="::ffff:192.0.2.50") == (409, "self"), "self: IPv4-mapped client address")
    check(code(DA, ta, client="192.0.2.50", confirm=True) is None, "self + confirm_self -> allowed")
    check(code(DA, ta, client="127.0.0.1") is None, "loopback client (on the router) is not 'self'")
    tw = Q.device_targets(DW, [DW])
    check(code(DW, tw, mode="isolate", client="198.18.0.7") == (409, "self"), "self over the VPN (allowed IPs)")
    wide = {"kind": "wg", "mac": "", "ips": [], "ipv6": [], "nets": ["10.9.0.0/16"]}
    check(code(DW, wide, mode="isolate") == (409, "wide_peer"), "VPN peer routing a /16 refused")
    check(code(DA, ta, c=dict(ctx, wan=[])) == (409, "no_wan") and code(DA, ta, mode="isolate", c=dict(ctx, wan=[])) is None,
          "no WAN: internet refused, isolate allowed")
    check(code(dev("i00000000000000ac"), {"kind": "ip", "mac": "", "ips": [], "ipv6": [], "nets": []}) == (409, "no_address"),
          "nothing to match -> 409")
    w = Q.warnings_for(dict(DA, private_mac=True), ta, "isolate")
    check(len(w) == 2 and "private" in w[0] and "same switch" in w[1], "warnings: private MAC, same segment")


def t_sync_expiry():
    ta = Q.device_targets(DA, [DA, DB])
    st = {"wan": ["wan0"], "entries": [Q.make_entry(DA, ta, "internet", "1h", NOW),
                                        Q.make_entry(DB, Q.device_targets(DB, [DA, DB]), "isolate", "none", NOW)]}
    check(st["entries"][0]["expires"] == int(NOW) + 3600 and st["entries"][1]["expires"] is None, "expiry stored")
    moved = dict(DA, ips=["192.0.2.51"], ipv6=["2001:db8::51"], current_ips=["192.0.2.51"])
    stolen = dict(DB, current_ips=["192.0.2.50"], ips=["192.0.2.50"])      # DA's old address now on DB
    st2, exp, changed = Q.sync(st, [moved, stolen], NOW + 60, ["wan0"])
    e = {x["device"]: x for x in st2["entries"]}
    check(changed and not exp and e[DA["id"]]["ips"] == ["192.0.2.51"] and e[DA["id"]]["ipv6"] == ["2001:db8::51"],
          "sync: new addresses picked up (%r)" % e[DA["id"]])
    st3, _x, _c = Q.sync(st, [dict(DA, ips=["192.0.2.50", "192.0.2.51"], current_ips=["192.0.2.51"]), stolen],
                         NOW + 60, ["wan0"])
    check({x["device"]: x for x in st3["entries"]}[DA["id"]]["ips"] == ["192.0.2.51"],
          "sync: an address another device holds now is dropped")
    st4, _x, c4 = Q.sync(st2, [moved, stolen], NOW + 120, ["wan0"])
    check(not c4, "sync: unchanged -> no write")
    st5, exp5, _c = Q.sync(st2, [], NOW + 3601, ["wan0"])
    check([x["device"] for x in exp5] == [DA["id"]] and [x["device"] for x in st5["entries"]] == [DB["id"]],
          "sync: expired entry split off, device missing from the inventory kept as is")
    st6, _x, c6 = Q.sync(st2, [moved, stolen], NOW + 120, ["wan1"])
    check(c6 and st6["wan"] == ["wan1"], "sync: WAN rename recorded")


def t_persistence_restore():
    net = FakeNet()
    e = env_for("persist", net)
    check(Q.load_state(e) == {"version": 1, "wan": [], "entries": []}, "no file -> empty state")
    ta = Q.device_targets(DA, [DA])
    st = {"wan": ["wan0"], "entries": [Q.make_entry(DA, ta, "internet", "none", NOW, by="boss"),
                                        Q.make_entry(DB, Q.device_targets(DB), "isolate", "1h", NOW - 7200)]}
    Q.save_state(e, st)
    check(os.stat(e.state_file).st_mode & 0o777 == 0o600, "state file 0600")
    back = Q.load_state(e)
    check(back["entries"] == st["entries"] and back["wan"] == ["wan0"], "state round trip")
    check(Q.restore(e) == 0 and MAC_A in net.table and MAC_B not in net.table, "restore: loads, expired entry skipped")
    check("@inet_mac" in net.table and 'oifname { "wan0" }' in net.table, "restore: WAN from the state file (no detection)")
    live = Q.table_state(e)
    check(Q.matches(live, Q.plan(back, Q.router_context(e, ["wan0"]), NOW)), "live table matches the plan")
    n = len(net.scripts)
    check(Q.apply(e, Q.plan(back, Q.router_context(e, ["wan0"]), NOW)) == (False, "") and len(net.scripts) == n,
          "apply: matching table -> no rewrite")
    st2 = dict(back, entries=back["entries"][:1] + [Q.make_entry(DB, Q.device_targets(DB), "isolate", "none", NOW)])
    ch, err = Q.apply(e, Q.plan(st2, Q.router_context(e, ["wan0"]), NOW))
    check(ch and not err and MAC_B in net.table, "apply: changed plan -> rewrite")
    with open(e.state_file, "w") as f:
        f.write("{not json")
    check(Q.load_state(e)["entries"] == [], "garbage state -> empty")
    os.unlink(e.state_file)
    tgt = os.path.join(TMP, "persist", "elsewhere.json")
    with open(tgt, "w") as f:
        json.dump({"entries": st["entries"]}, f)
    os.symlink(tgt, e.state_file)
    check(Q.load_state(e)["entries"] == [], "symlinked state file refused (O_NOFOLLOW)")
    os.unlink(e.state_file)
    bad = env_for("persist-fail", FakeNet(nft_fail=True))
    Q.save_state(bad, st)
    check(Q.restore(bad) == 1, "restore: nft failure -> rc 1 (unit shows failed)")
    Q.log_action(e, {"action": "quarantine", "device": DA["id"], "mode": "internet", "by": "boss"})
    Q.log_action(e, {"action": "release", "device": DA["id"], "mode": "internet", "by": "boss"})
    acts = Q.read_actions(e, DA["id"])
    check([a["action"] for a in acts] == ["quarantine", "release"] and acts[0]["ts"] == int(NOW)
          and os.stat(e.log_file).st_mode & 0o777 == 0o600, "action log: appended, 0600")
    # CLI release-all on a stub env
    Q.save_state(e, st)
    net.scripts.clear()
    old_env = Q.Env
    Q.Env = lambda: e
    try:
        rc = Q.main(["quarantine.py", "release-all"])
    finally:
        Q.Env = old_env
    check(rc == 0 and Q.load_state(e)["entries"] == [] and "add rule" not in net.table, "CLI release-all: empty table")


# ── API ──────────────────────────────────────────────────────────────────────

def t_api():
    import api_harness
    H = api_harness.Harness()
    A = H.mod
    try:
        st = os.path.join(H.scratch, "dw-state")
        conf = os.path.join(H.scratch, "dw-conf")
        os.makedirs(st)
        A.DEVICES_STATE_DIR, A.DEVICES_CONF_DIR = st, conf
        A.DEVICES_WG_SNAPSHOT = os.path.join(H.scratch, "wg-peers.json")
        A.DEVICES_WG_SNAPSHOT_LEGACY = os.path.join(H.scratch, "legacy-wg-peers.json")
        A.ALERT_CONFIG_FILE = os.path.join(H.scratch, "alerts.json")
        A.DEVICE_ALERT_STATE = os.path.join(H.scratch, "device-alerts.json")
        A.CLIENT_BANS_FILE = os.path.join(H.scratch, "bans.json")
        net = FakeNet()
        qd = os.path.join(H.scratch, "q")
        os.makedirs(os.path.join(qd, "sysnet", "lan0"))
        with open(os.path.join(qd, "sysnet", "lan0", "address"), "w") as f:
            f.write(ROUTER_MAC)
        env = Q.Env(state_file=os.path.join(qd, "quarantine.json"), log_file=os.path.join(qd, "actions.jsonl"),
                    run=net, sys_net=os.path.join(qd, "sysnet"))
        env.nft, env.ip = "/usr/sbin/nft", "/usr/sbin/ip"
        A._QUAR["env"] = env
        A._detect_wan_iface = lambda: "wan0"
        sent = []
        A._notify_async = lambda inc, tr, force=False, priority=None: sent.append((inc, tr, force, priority))
        now = time.time()
        base = {"kind": "mac", "name_source": "kea", "vendor": "", "type": "laptop", "iface": "lan0", "zone": "lan",
                "zone_name": "LAN", "vlan": None, "first_seen": int(now - 86400 * 9), "last_seen": int(now),
                "online": True, "baseline": True, "health": "normal", "risk": 0, "reason": "",
                "activity": {"day": "x", "bytes_in": 0, "bytes_out": 0, "conns": 0, "destinations": 0},
                "hourly": [], "top_destinations": [], "top_countries": [], "hostnames": {}, "software": []}
        da, db = dict(base, **DA), dict(base, **DB)

        def write_devices(devs, findings=()):
            with open(st + "/devices.json", "w") as f:
                json.dump({"schema": 1, "generated_at": int(time.time()), "devices": devs}, f)
            with open(st + "/findings.json", "w") as f:
                json.dump({"schema": 1, "findings": list(findings)}, f)

        write_devices([da, db])
        url = "/api/devices/%s/quarantine" % da["id"]
        body = {"mode": "internet", "expires": "1h"}
        check(H.request("POST", url, role=None, origin=H.SAME, body=body).status == 401, "API: no session 401")
        check(H.request("POST", url, role="viewer", origin=H.SAME, body=body).status == 403, "API: viewer 403")
        check(H.request("POST", url, role="admin", origin="https://evil.example.com", body=body).status == 403,
              "API: foreign Origin 403 (CSRF)")
        check(not net.scripts, "refused requests never reached nft")
        r = H.request("POST", url, role="admin", origin=H.SAME, body=body, headers={"X-Real-IP": "192.0.2.50"})
        check(r.status == 409 and r.json.get("code") == "self" and not net.scripts, "API: own device -> 409 self")
        r = H.request("POST", url, role="admin", origin=H.SAME, body=dict(body, mode="nuke"))
        check(r.status == 400, "API: bad mode 400")
        r = H.request("POST", url, role="admin", origin=H.SAME, body=dict(body, confirm_self=True),
                      headers={"X-Real-IP": "192.0.2.50"})
        stj = json.load(open(env.state_file))
        check(r.status == 200 and r.json["quarantine"]["mode"] == "internet" and r.json["quarantine"]["expires"]
              and len(stj["entries"]) == 1 and stj["entries"][0]["mac"] == MAC_A and stj["wan"] == ["wan0"]
              and os.stat(env.state_file).st_mode & 0o777 == 0o600, "API: quarantine stored (%r)" % r.json)
        check(net.table and MAC_A in net.table and "@inet_mac" in net.table, "API: table rendered with the device")
        check(sent and sent[-1][0]["title"].startswith("Device quarantined") and sent[-1][2] is True,
              "API: quarantine alert sent (forced past the incident severity)")
        acts = Q.read_actions(env, da["id"])
        check([a["action"] for a in acts] == ["refused", "refused", "quarantine"] and acts[-1]["self"] is True
              and acts[-1]["by"] == "boss", "API: refusal + quarantine in the action log (%r)" % acts)
        r = H.request("GET", "/api/devices", role="viewer")
        rows = {d["id"]: d for d in r.json["devices"]}
        check(rows[da["id"]]["quarantine"]["mode"] == "internet" and rows[db["id"]]["quarantine"] is None
              and set(rows[da["id"]]["quarantine"]) == {"mode", "expires"}, "API list: quarantine state (viewer: mode/expiry)")
        r = H.request("GET", "/api/devices/" + da["id"], role="admin")
        q = r.json["quarantine"]
        check(q["supported"] and q["active"] and q["mode"] == "internet" and q["mac"] == MAC_A
              and q["remaining"] > 3000 and q["actions"][-1]["action"] == "quarantine", "API detail: quarantine block")
        check(H.request("GET", "/api/devices/summary", role="viewer").json["quarantined"] == 1, "API summary: quarantined 1")
        # router refused through the API
        rd = dict(base, **dev("m02005e0053fe", ROUTER_MAC, ["192.0.2.200"], name="router?"))
        write_devices([da, db, rd])
        r = H.request("POST", "/api/devices/%s/quarantine" % rd["id"], role="admin", origin=H.SAME,
                      body={"mode": "isolate", "expires": "none"})
        check(r.status == 403 and r.json["code"] == "router", "API: router refused")
        # minute sync: address change + expiry
        n0 = len(net.scripts)
        A.devices_quarantine_sync()
        check(len(net.scripts) == n0, "sync: nothing changed -> no rewrite")
        write_devices([dict(da, ips=["192.0.2.52"], current_ips=["192.0.2.52"], ipv6=[]), db])
        net.neigh = [n for n in net.neigh if n["dst"] != "192.0.2.50"]
        A.devices_quarantine_sync()
        check(len(net.scripts) == n0 + 1 and "192.0.2.52" in net.table and "192.0.2.50" not in net.table,
              "sync: new address -> table rewritten")
        # the neighbour table is read directly: a new address of the MAC is
        # blocked before the inventory knows it (DW-7)
        net.neigh.append({"dst": "192.0.2.53", "lladdr": MAC_A})
        net.neigh.append({"dst": "2001:db8::53", "lladdr": MAC_A})
        A.devices_quarantine_sync()
        check(len(net.scripts) == n0 + 2 and "192.0.2.53" in net.table and "2001:db8::53" in net.table
              and "192.0.2.52" in net.table, "sync: new neighbour address of the MAC blocked at once (DW-7)")
        r = H.request("POST", "/api/devices/%s/quarantine" % db["id"], role="admin", origin=H.SAME,
                      body={"mode": "isolate", "expires": "1h"})
        check(r.status == 200 and "iso_in" in net.table and r.json["warnings"], "API: isolate + warnings")
        data = json.load(open(env.state_file))
        for e in data["entries"]:
            if e["device"] == db["id"]:
                e["expires"] = int(time.time()) - 5
        with open(env.state_file, "w") as f:
            json.dump(data, f)
        sent.clear()
        res = A.devices_quarantine_sync()
        check(res["expired"] == 1 and MAC_B not in net.table and sent and "expired" in sent[-1][0]["detail"],
              "sync: expiry -> removed from the table + alert")
        check(Q.read_actions(env, db["id"])[-1]["action"] == "expire", "expiry logged")
        # release
        r = H.request("POST", "/api/devices/%s/unquarantine" % da["id"], role="admin", origin=H.SAME, body={})
        check(r.status == 200 and json.load(open(env.state_file))["entries"] == [] and "add rule" not in net.table,
              "API: release -> table empty")
        check(H.request("POST", "/api/devices/%s/unquarantine" % da["id"], role="admin", origin=H.SAME,
                        body={}).status == 404, "API: release of a free device -> 404")
        check(H.request("POST", "/api/devices/%s/unquarantine" % da["id"], role="viewer", origin=H.SAME,
                        body={}).status == 403, "API: release viewer 403")
        # nft failure: nothing stored
        net.nft_fail = True
        r = H.request("POST", url, role="admin", origin=H.SAME, body={"mode": "isolate", "expires": "none"})
        check(r.status == 500 and json.load(open(env.state_file))["entries"] == [], "API: nft failure -> 500, not stored")
        net.nft_fail = False
        # device alert settings
        check(H.request("GET", "/api/devices/alerts", role="viewer").status == 403, "alerts config: viewer 403")
        r = H.request("GET", "/api/devices/alerts", role="admin")
        check(r.json["config"] == A.DEVICE_ALERT_DEFAULTS, "alerts config: defaults")
        with open(A.ALERT_CONFIG_FILE, "w") as f:
            json.dump({"enabled": True, "ntfy_url": "https://ntfy.example/x", "min_severity": "critical"}, f)
        r = H.request("POST", "/api/devices/alerts", role="admin", origin=H.SAME,
                      body={"new_device": "all", "min_severity": "high"})
        raw = json.load(open(A.ALERT_CONFIG_FILE))
        check(r.status == 200 and raw["devices"]["new_device"] == "all" and raw["ntfy_url"] == "https://ntfy.example/x",
              "alerts config: saved next to the channel settings")
        check(H.request("POST", "/api/devices/alerts", role="admin", origin=H.SAME,
                        body={"new_device": "sometimes"}).status == 400, "alerts config: invalid -> 400")
        A.save_alert_config({"enabled": True, "ntfy_url": "https://ntfy.example/x", "min_severity": "warning"})
        check(json.load(open(A.ALERT_CONFIG_FILE)).get("devices", {}).get("new_device") == "all",
              "saving the incident alert settings keeps the device settings")
        A.save_device_alert_config({"new_device": "lan", "min_severity": "medium"})
        # alert pass over events.jsonl
        ev = st + "/events.jsonl"
        with open(ev, "w") as f:
            f.write(json.dumps({"type": "new_device", "device": "m0000000000aa", "ts": int(now)}) + "\n")
        sent.clear()
        check(A.devices_alert_pass() == 0 and not sent, "alerts: first pass starts at the end (no history replay)")
        iot = dict(base, **dev("m02005e005303", "02:00:5e:00:53:03", ["192.0.2.70"], name="plug"), zone="opt1",
                   zone_name="IoT", baseline=False, first_seen=int(now))
        newlan = dict(base, **dev("m02005e005304", "02:00:5e:00:53:04", ["192.0.2.71"], name="newbie"),
                      baseline=False, first_seen=int(now), vendor="Example Corp")
        f_hi = {"id": "a" * 16, "device": da["id"], "kind": "c2_connection", "indicator": "203.0.113.9",
                "severity": "critical", "title": "Connected to a known botnet C2 server", "source": "feodo",
                "first": now, "last": now, "count": 1}
        f_lo = dict(f_hi, id="b" * 16, severity="low", title="low thing")
        write_devices([da, db, iot, newlan], [f_hi, f_lo])
        with open(ev, "a") as f:
            for e in ({"type": "new_device", "device": iot["id"]}, {"type": "new_device", "device": newlan["id"]},
                      {"type": "finding", "device": da["id"], "finding": f_hi["id"], "severity": "critical"},
                      {"type": "finding", "device": da["id"], "finding": f_lo["id"], "severity": "low"}):
                f.write(json.dumps(dict(e, ts=int(now))) + "\n")
            f.write('{"type": "finding", "partial')        # incomplete line: left for the next pass
        check(A.devices_alert_pass() == 2, "alerts: LAN new device + critical finding sent")
        titles = [s[0]["title"] for s in sent]
        check(titles == ["New device on LAN: newbie", "Device flagged: laptop"] and sent[0][3] == "default"
              and sent[1][0]["severity"] == "critical", "alerts: IoT new device and low finding skipped (%r)" % titles)
        det = sent[1][0]["detail"]
        check("Connected to a known botnet C2 server (Feodo Tracker): 203.0.113.9" in det and det.count("Feodo") == 1,
              "DW-10: finding alert names the source once and what differs (the indicator) (%r)" % det)
        f_loc = {"title": "Connected to a known malware host (local indicator list)", "source": "local",
                 "kind": "intel_connection", "indicator": "203.0.113.10", "count": 4,
                 "details": {"port": 443, "proto": "tcp"}}
        txt = A._device_alert_what(f_loc)
        check(txt.count("local indicator list") == 1 and "203.0.113.10" in txt and "port 443/tcp" in txt
              and "seen 4 times" in txt, "DW-10: no '(local indicator list) - local indicator list' (%r)" % txt)
        t2 = A._device_alert_what({"title": "ET MALWARE Example", "source": "suricata", "kind": "ids_alert",
                                   "indicator": "sid:2024897", "details": {"peer": "203.0.113.11"}})
        check("signature 2024897" in t2 and "203.0.113.11" in t2 and "(Suricata)" in t2, "DW-10: IDS alert text (%r)" % t2)
        check("Example Corp." in sent[0][0]["detail"] and "private" not in sent[0][0]["detail"].lower(),
              "new device alert: vendor (%r)" % sent[0][0]["detail"])
        with open(ev, "a") as f:
            f.write('"}\n')
            f.write(json.dumps({"type": "finding", "device": da["id"], "finding": f_hi["id"], "severity": "critical",
                                "ts": int(now)}) + "\n")
        sent.clear()
        check(A.devices_alert_pass() == 0 and not sent, "alerts: same finding again -> deduped")
        with open(ev, "a") as f:
            f.write(json.dumps({"type": "finding", "device": da["id"], "finding": f_hi["id"], "severity": "critical",
                                "escalated": True, "ts": int(now)}) + "\n")
        check(A.devices_alert_pass() == 1, "alerts: escalation re-alerts")
        # rate limit
        fl = [dict(f_hi, id="%016x" % i) for i in range(15)]
        write_devices([da, db], fl)
        with open(ev, "a") as f:
            for x in fl:
                f.write(json.dumps({"type": "finding", "device": da["id"], "finding": x["id"], "severity": "critical",
                                    "ts": int(now)}) + "\n")
        sent.clear()
        n = A.devices_alert_pass()
        stj = json.load(open(A.DEVICE_ALERT_STATE))
        check(n == 7 and stj["held"] == 8 and len(stj["window"]) == 10, "alerts: max 10 per hour, rest held (%d, %r)"
              % (n, {k: stj[k] for k in ("held",)}))
        # rotation: the engine renames events.jsonl -> .1 and starts a new file
        os.replace(ev, ev + ".1")
        with open(ev, "w") as f:
            f.write(json.dumps({"type": "new_device", "device": newlan["id"] + "", "ts": int(now)}) + "\n")
        stj["window"] = []
        with open(A.DEVICE_ALERT_STATE, "w") as f:
            json.dump(stj, f)
        write_devices([da, db, newlan], [])
        A.save_device_alert_config({"new_device": "all"})
        sent.clear()
        A.devices_alert_pass()
        check(any("held back" in s[0]["detail"] or "held back" in s[0]["title"] for s in sent),
              "alerts: held-back count reported once the window has room")
        check(os.stat(A.DEVICE_ALERT_STATE).st_mode & 0o777 == 0o600, "alert state 0600")
        priv = dict(base, **dev("m02005e005305", "02:00:5e:00:53:05", ["192.0.2.72"], name="02:00:5e:00:53:05"))
        priv.update(baseline=False, first_seen=int(now), vendor="Private MAC", private_mac=True)
        write_devices([da, db, newlan, priv], [])
        with open(ev, "a") as f:
            f.write(json.dumps({"type": "new_device", "device": priv["id"], "private_mac": True, "ts": int(now)}) + "\n")
        sent.clear()
        A.devices_alert_pass()
        d0 = [s[0]["detail"] for s in sent if priv["name"] in s[0]["title"]]
        check(d0 and d0[0].startswith("Private (randomised) MAC address.") and "(private MAC)" not in d0[0],
              "DW-10: new-device alert says 'private MAC' once (%r)" % d0)
        # integration section
        A._INTEG_CACHES["devices"].drop()
        write_devices([da, db, newlan], [f_hi])
        j = A._integ_devices()
        check(j["ok"] and j["findings"][0]["id"] == f_hi["id"] and "203.0.113.9" not in json.dumps(j)
              and j["new_devices"][0]["id"] == newlan["id"] and j["quarantined"] == 0,
              "integration section: recent findings (no indicator) + new devices (%r)" % j)
    finally:
        H.close()


def t_campaign4():
    """Lab campaign 4 findings DW-3 / DW-6 / DW-7 / DW-10 (documentation addresses)."""
    ctx = {"macs": set(), "ips": set(), "gateways": set(), "gateway_macs": set(), "wan": ["wan0"]}
    # DW-3: after an address overlap A's current .101 is in B's history and
    # B's only address .77 in A's: each device keeps its CURRENT addresses
    # (only the other devices' current_ips are excluded)
    a = dev("m02005e005301", MAC_A, ["192.0.2.101", "192.0.2.100", "192.0.2.77"], ["2001:db8::a1"],
            ["192.0.2.101", "192.0.2.100"], name="client")
    b = dev("m02005e005302", MAC_B, ["192.0.2.101", "192.0.2.77"], [], ["192.0.2.77"], name="macvlan")
    ta, tb = Q.device_targets(a, [a, b]), Q.device_targets(b, [a, b])
    check(ta["ips"] == ["192.0.2.100", "192.0.2.101"] and tb["ips"] == ["192.0.2.77"],
          "DW-3: current addresses kept although another device once held them (%r / %r)" % (ta["ips"], tb["ips"]))
    p = Q.plan({"wan": ["wan0"], "entries": [Q.make_entry(a, ta, "isolate", "none", NOW)]}, ctx, NOW)
    s = Q.render(p)
    check("192.0.2.101" in p["isolate"]["v4"] and "forward ip daddr @iso_v4 counter drop" in s,
          "DW-3: forwarded traffic TO the isolated device's current address dropped (VLAN ping repro)")
    pi = Q.plan({"wan": ["wan0"], "entries": [Q.make_entry(a, ta, "internet", "none", NOW)]}, ctx, NOW)
    check("192.0.2.101" in pi["internet"]["v4"] and 'iifname { "wan0" } ip daddr @inet_v4' in Q.render(pi),
          "DW-3: inbound (port-forward) rule covers the current address")
    # an address both claim right now stays out of both (the MAC rule still applies)
    b2 = dict(b, current_ips=["192.0.2.77", "192.0.2.101"])
    check("192.0.2.101" not in Q.device_targets(a, [a, b2])["ips"], "DW-3: an address another device holds NOW is left out")
    # neighbour table: what the MAC uses right now, before the inventory
    tn = Q.device_targets(a, [a, b], neigh={"192.0.2.150": MAC_A, "2001:db8::a2": MAC_A, "192.0.2.100": MAC_B})
    check("192.0.2.150" in tn["ips"] and "2001:db8::a2" in tn["ipv6"] and "192.0.2.100" not in tn["ips"],
          "DW-7: neighbour addresses of the MAC added, an address the neighbour table gives to another MAC dropped (%r)" % tn)
    many = dev("m02005e005301", MAC_A, ["192.0.2.%d" % i for i in range(2, 60)], [], ["192.0.2.59"])
    check("192.0.2.59" in Q.device_targets(many, [many])["ips"], "targets: the cap keeps the current address")
    # DW-6: answers to router-initiated connections pass iso_in
    rules = [ln for ln in s.splitlines() if " iso_in " in ln and ln.startswith("add rule")]
    check(rules and rules[0].endswith("iso_in ct direction reply return") and rules[-1].split(" iso_in ")[1].startswith("counter drop"),
          "DW-6: iso_in returns replies to router-initiated connections first, still ends in a drop (%r)" % rules)
    live = nft_json(s)
    check(Q.matches({"sets": {x["set"]["name"]: [str(e) for e in x["set"].get("elem", [])] for x in live if "set" in x},
                     "rules": sum(1 for x in live if "rule" in x),
                     "chains": {x["chain"]["name"]: x["chain"].get("hook") for x in live if "chain" in x}}, p),
          "matches(): rule count follows the render (no rewrite loop)")
    # DW-7: sync refreshes a MAC entry from the neighbour table even with the engine down
    st = {"wan": ["wan0"], "entries": [Q.make_entry(a, ta, "internet", "none", NOW)]}
    st2, _e, ch = Q.sync(st, [], NOW + 10, ["wan0"], None, {"192.0.2.150": MAC_A})
    check(ch and "192.0.2.150" in st2["entries"][0]["ips"] and "192.0.2.101" in st2["entries"][0]["ips"],
          "DW-7: sync without inventory adds the neighbour address, keeps the stored ones")
    # DW-10: the same-switch note is not for VPN peers
    tw = Q.device_targets(DW, [DW], [{"public_key": WG_PK, "allowed_ips": ["198.18.0.7/32"]}])
    check(not any("same switch" in w for w in Q.warnings_for(DW, tw, "isolate"))
          and any("same switch" in w for w in Q.warnings_for(a, ta, "isolate")),
          "DW-10: 'same switch or Wi-Fi' warning only for LAN devices")


def main():
    for t in (t_render, t_plan_filter, t_refusals, t_sync_expiry, t_campaign4, t_persistence_restore, t_api):
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
    print("quarantine_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
