#!/usr/bin/env python3
"""Tripwire engine checks (pkg/usr/local/sbin/tuxwall-tripwire), all in a
temp sandbox: TUXWALL_TRIPWIRE_ROOT remaps every path and stubs the
firewall (rules are only recorded), pushes go to a file, the kernel log is
a plain file followed with tail. Nothing here touches iptables, systemd or
the network.

  python3 tools/tripwire_check.py            pure tests + a short daemon run (CI)

Covers: the eve pre-filter and event normalisation, evaluate() per mode and
deception-port absorption, config schema v2 (v1 migration as decided: Log
only, never Block; validation; confirm gate for arming Block; no strength
change while tripped; audit), per-check actions, exclusions (router /
loopback, the two real false positives, WAN-only, CIDRs, signature ids),
thresholds (sliding windows), the Test path (no side effects), the event
history (hook, filters, retention, one-time import of tripwire.log), the lockdown rule plan (high mode keeps WAN DHCP,
v6 ND and replies to router-opened connections above the DROP), stubbed
enforce/lift idempotence, notify dedupe + summary, notify-before-enforce,
the state lock (threads + processes) and atomic writes, set-mode audit and
the "still tripped" warning, resolve, eve rotation (rename + copytruncate +
oversized lines), the kernel follower, watcher death, and the daemon's
heartbeats and disabled-mode behaviour.
"""
import contextlib
import importlib.machinery
import io
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "..", "pkg", "usr", "local", "sbin", "tuxwall-tripwire")
sys.dont_write_bytecode = True

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


def wait_for(fn, timeout=8.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(step)
    return bool(fn())


ROOT = tempfile.mkdtemp(prefix="tw-check-")
PUSH = os.path.join(ROOT, "push.jsonl")
EVE_PATH = os.path.join(ROOT, "eve.json")
KLOG = os.path.join(ROOT, "kern.log")
for k in [k for k in os.environ if k.startswith("TUXWALL_TRIPWIRE_")]:
    del os.environ[k]
os.environ.update({"TUXWALL_TRIPWIRE_ROOT": ROOT, "TUXWALL_TRIPWIRE_PUSH_FILE": PUSH,
                   "TUXWALL_TRIPWIRE_EVE": EVE_PATH, "TUXWALL_TRIPWIRE_WAN": "wan0",
                   "TUXWALL_TRIPWIRE_KERNEL_CMD": "tail -n 0 -F %s" % KLOG,
                   # the router: LAN 192.168.1.1/24 (+ v6), VPN 10.0.0.1/24,
                   # WAN 73.0.0.2 on wan0, loopback
                   "TUXWALL_TRIPWIRE_OWN_IPS": "192.168.1.1/24 2001:db8:1::1/64 10.0.0.1/24 "
                                               "73.0.0.2/24 127.0.0.1/8 ::1/128",
                   "TUXWALL_TRIPWIRE_LAN_NETS": "192.168.1.1/24 2001:db8:1::1/64 10.0.0.1/24"})


def load_engine():
    loader = importlib.machinery.SourceFileLoader("tw_engine", ENGINE)
    spec = importlib.util.spec_from_loader("tw_engine", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


E = load_engine()
# hard stop: every path below must live in the sandbox, firewall stubbed
assert E.STUB_FIREWALL and not E.NETNS, "engine not sandboxed - refusing to test"
for p in (E.CONFIG, E.STATE, E.LOG, E.AUDIT, E.HEALTH, E.LOCK, E.ENFORCE_LOG, E.HISTORY,
          E.HISTORY_LOCK):
    assert p.startswith(ROOT), p


def reset():
    for name in os.listdir(ROOT):
        p = os.path.join(ROOT, name)
        shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
    os.makedirs(ROOT + "/etc/tuxwall")
    os.makedirs(ROOT + "/var/log/tuxwall")


def set_mode_file(mode):
    """A version-1 config file ({"mode"})."""
    with open(E.CONFIG, "w") as f:
        json.dump({"mode": mode}, f)


def write_cfg(action="log", strength="medium", enabled=True, **per_check):
    """A version-2 config: every check `action` unless overridden by
    per_check (check id with dots replaced by __ -> action or full dict)."""
    cfg = E.default_config()
    cfg.update(enabled=enabled, strength=strength)
    for cid in cfg["checks"]:
        cfg["checks"][cid]["action"] = action
    for key, val in per_check.items():
        cid = key.replace("__", ".").replace("_", "-")
        if isinstance(val, dict):
            E._apply_check(cfg["checks"][cid], val, cid)
        else:
            cfg["checks"][cid]["action"] = val
    cfg["mode"] = E.legacy_mode(cfg)
    with open(E.CONFIG, "w") as f:
        json.dump(cfg, f)
    return cfg


def history():
    return E.history_read()


def pushes():
    try:
        with open(PUSH) as f:
            return [json.loads(x) for x in f if x.strip()]
    except OSError:
        return []


def eve_line(cat="Attempted Administrator Privilege Gain", sev=1, dst="192.168.1.20",
             port=443, src="203.0.113.9", etype="alert", sig="ET TEST something"):
    return json.dumps({"timestamp": "2026-11-19T10:00:00+0000", "event_type": etype,
                       "src_ip": src, "src_port": 40000, "dest_ip": dst, "dest_port": port,
                       "proto": "TCP", "in_iface": "wan0",
                       "alert": {"action": "allowed", "signature_id": 2000001,
                                 "signature": sig, "category": cat, "severity": sev}},
                      separators=(",", ":"))


KLINE = ("[TUXWALL-CANARY-EGRESS] IN= OUT=wan0 SRC=73.0.0.2 DST=1.1.1.1 LEN=60 "
         "PROTO=TCP SPT=34236 DPT=443 SYN")
# The two real false positives on the owner's router:
# Home Assistant behind the nginx reverse proxy - the ROUTER (192.168.1.1)
# talks to 192.168.1.181:8123 (eve.json, 2026-11-18, trimmed)
HA_FP = json.dumps({
    "timestamp": "2026-11-18T10:51:33.150288-0500", "flow_id": 2122015245825773,
    "in_iface": "enp6s0", "event_type": "alert", "src_ip": "192.168.1.1", "src_port": 35092,
    "dest_ip": "192.168.1.181", "dest_port": 8123, "proto": "TCP", "ip_v": 4,
    "pkt_src": "wire/pcap", "tx_id": 84,
    "alert": {"action": "allowed", "gid": 1, "signature_id": 2031123, "rev": 2,
              "signature": "ET HUNTING Suspicious PHP Code in HTTP POST (Outbound)",
              "category": "Attempted Administrator Privilege Gain", "severity": 1},
    "app_proto": "http", "direction": "to_server"}, separators=(",", ":"))
# the Nov 8 canary-egress trip: a loopback connection (tripwire.log)
LO_FP = ("[TUXWALL-CANARY-EGRESS] IN= OUT=lo SRC=192.168.1.1 DST=192.168.1.1 LEN=60 "
         "TOS=0x00 PREC=0x00 TTL=64 ID=10243 DF PROTO=TCP SPT=50542 DPT=8744 WINDOW=43690 "
         "RES=0x00 SYN URGP=0")


# ── pre-filter, normalisation, evaluate ─────────────────────────────────────
def test_eval():
    flow = json.dumps({"event_type": "flow", "src_ip": "1.2.3.4"}, separators=(",", ":"))
    check(not E.eve_prefilter(flow.encode()), "prefilter drops flow lines")
    check(not E.eve_prefilter(eve_line(sev=3).encode()), "prefilter drops severity 3")
    check(not E.eve_prefilter(eve_line(sev=10).encode()), "prefilter drops severity 10")
    check(E.eve_prefilter(eve_line().encode()), "prefilter keeps severity 1 alerts")
    check(E.event_from_eve_line(eve_line(cat="Misc activity")) is None, "non-trip class ignored")
    check(E.event_from_eve_line('{"event_type":"alert","severity":1, broken') is None,
          "broken JSON ignored")
    ev = E.event_from_eve_line(eve_line())
    check(ev and ev["check"] == "suricata.attempted-admin", "category -> check id")
    check(ev and ev["dst"] == "192.168.1.20:443" and ev["src"] == "203.0.113.9", "src/dst kept")
    ev2 = E.event_from_eve({"event_type": "alert", "src_ip": "x", "dest_ip": "y",
                            "dest_port": 80, "alert": {"severity": 1,
                                                       "classtype": "trojan-activity"}})
    check(ev2 and ev2["check"] == "suricata.trojan-activity", "classtype -> check id")
    for cat, cid in (("Successful Administrator Privilege Gain", "suricata.successful-admin"),
                     ("Web Application Attack", "suricata.web-application-attack"),
                     ("Executable code was detected", "suricata.shellcode-detect"),
                     ("A Network Trojan was detected", "suricata.trojan-activity")):
        e = E.event_from_eve_line(eve_line(cat=cat))
        check(e and e["check"] == cid, "category %s" % cid)
    expect = {"disabled": "off", "logonly": "log", "medium": "block", "high": "block"}
    for mode, action in expect.items():
        check(E.evaluate(ev, mode)["action"] == action, "evaluate %s -> %s" % (mode, action))
    check(E.evaluate(ev, "high")["strength"] == "high", "block carries the strength")
    absorbed = E.event_from_eve_line(eve_line(port=5555))
    check("deception layer" in absorbed["dst"], "deception port annotated")
    for mode in ("logonly", "medium", "high"):
        check(E.evaluate(absorbed, mode)["action"] == "absorb", "absorbed in %s" % mode)
    check(E.evaluate(absorbed, "disabled")["action"] == "off", "off check: not even absorbed")
    k = E.event_from_kernel(KLINE)
    check(k and k["check"] == "canary.egress" and k["dst"] == "1.1.1.1:443"
          and k["iface"] == "wan0", "kernel line parsed")
    check(E.event_from_kernel("random kernel line") is None, "unrelated kernel line ignored")
    check(E.evaluate(k, "medium")["action"] == "block", "canary egress blocks in medium")
    check(set(E.CHECKS) >= {"canary.egress", "suricata.shellcode-detect"}, "registry")


# ── rule plan + stubbed enforcement ─────────────────────────────────────────
def test_rules():
    med = E.lockdown_rules("medium", "wan0")
    check([(i, c) for i, c, _ in med] == [("iptables", "FORWARD"), ("ip6tables", "FORWARD")],
          "medium = FORWARD drop v4+v6 only")
    high = E.lockdown_rules("high", "wan0")
    inp = {i: s for i, c, s in high if c == "INPUT"}
    check(set(inp) == {"iptables", "ip6tables"}, "high adds INPUT v4+v6")
    for ipt, specs in inp.items():
        check(specs[-1][-1] == "DROP" and "-i" in specs[-1], "%s INPUT drop last" % ipt)
        check(all(s[-1] == "ACCEPT" and E.MARK_ALLOW in s for s in specs[:-1]),
              "%s allows above the drop" % ipt)
        check(any("--ctdir" in s and "REPLY" in s for s in specs), "%s replies allowed" % ipt)
    j4 = [" ".join(s) for s in inp["iptables"]]
    j6 = [" ".join(s) for s in inp["ip6tables"]]
    check(any("--sport 67 --dport 68" in s for s in j4), "high allows DHCPv4")
    check(any("--sport 547 --dport 546" in s for s in j6), "high allows DHCPv6")
    check(sum("--icmpv6-type" in s for s in j6) == 3, "high allows v6 ND")
    check(not any("NEW" in s for s in j4 + j6), "no NEW state accepted")

    reset()
    set_mode_file("medium")
    check(not E.lockdown_active("medium"), "nothing active at start")
    check(E.enforce("medium") is True, "enforce adds")
    check(E.lockdown_active("medium"), "active after enforce")
    check(E.enforce("medium") is False, "enforce idempotent")
    with open(E.STATE, "w") as f:
        json.dump({"tripped": True, "mode": "medium"}, f)
    E.lift()
    check(not E.lockdown_active("medium"), "lift removes")
    check(E.enforce("high") is True and E.lockdown_active("high"), "high enforce")


# ── notify dedupe + order ───────────────────────────────────────────────────
def test_notify():
    reset()
    old = E.NOTIFY_WINDOW_S
    E.NOTIFY_WINDOW_S = 0.6
    try:
        sent = [E.notify("T", "m%d" % i, key="logonly:x") for i in range(10)]
        check(sent.count(True) == 1 and len(pushes()) == 1, "10 events -> 1 push")
        E.notify("U", "other", key="logonly:y")
        check(len(pushes()) == 2, "separate key pushes separately")
        E.flush_notify()
        check(len(pushes()) == 2, "no summary before the window ends")
        time.sleep(0.7)
        E.flush_notify()
        p = pushes()
        check(len(p) == 3 and "(+9)" in p[-1]["title"], "summary push with count")
        E.flush_notify()
        check(len(pushes()) == 3, "summary sent once")
        time.sleep(0.7)
        E.notify("T", "again", key="logonly:x")
        check(len(pushes()) == 4 and "+" not in pushes()[-1]["message"], "fresh window pushes")
        E.notify("T", "force", priority="urgent")
        check(pushes()[-1]["priority"] == "urgent", "unkeyed push always sent")
    finally:
        E.NOTIFY_WINDOW_S = old

    # notify BEFORE enforce
    reset()
    write_cfg("block", "high")
    order = []
    real_send, real_enf = E._send, E.enforce
    E._send = lambda *a, **k: order.append("push") or True
    E.enforce = lambda *a, **k: order.append("enforce") or True
    try:
        ev = E.event_from_eve_line(eve_line())
        d = E.handle_event(ev)
        check(d["action"] == "block" and order == ["push", "enforce"], "push before enforce")
        order.clear()
        E.handle_event(ev)
        check(order == [], "repeat while tripped: no push, no re-insert")
        st = E.load_state()
        check(st["tripped"] and st["trips"] == 2 and st["mode"] == "high"
              and st["check"] == "suricata.attempted-admin", "trip state recorded")
    finally:
        E._send, E.enforce = real_send, real_enf


# ── state lock + atomic writes ──────────────────────────────────────────────
def test_state():
    reset()

    def inc(st):
        st["n"] = int(st.get("n") or 0) + 1

    def worker():
        for _ in range(40):
            E.update_state(inc)
    ts = [threading.Thread(target=worker) for _ in range(6)]
    code = ("import importlib.machinery,importlib.util;"
            "l=importlib.machinery.SourceFileLoader('e',%r);"
            "s=importlib.util.spec_from_loader('e',l);m=importlib.util.module_from_spec(s);"
            "l.exec_module(m)\n"
            "for _ in range(40): m.update_state(lambda st: st.__setitem__('n', int(st.get('n') or 0)+1))"
            % ENGINE)
    procs = [subprocess.Popen([sys.executable, "-B", "-c", code]) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    rcs = [p.wait(60) for p in procs]
    check(rcs == [0, 0], "child processes ok")
    check(E.load_state().get("n") == 6 * 40 + 2 * 40, "no lost updates (threads + processes)")
    left = [n for n in os.listdir(os.path.dirname(E.STATE)) if n.endswith(".tmp")]
    check(not left, "no temp files left behind")
    check(oct(os.stat(E.STATE).st_mode & 0o777) == "0o644", "state file 0644")


# ── set-mode (legacy), audit, resolve ───────────────────────────────────────
def test_mode_resolve():
    reset()
    set_mode_file("medium")
    r = E.set_mode("logonly", by="alice", via="dashboard", client="192.168.1.5")
    check(r["ok"] and r["previous"] == "logonly" and r["mode"] == "logonly"
          and "warning" not in r, "legacy set-mode logonly ok (v1 medium migrated to Log)")
    cfg = E.get_config()
    check(cfg["version"] == 2 and cfg["strength"] == "medium"
          and all(c["action"] == "log" for c in cfg["checks"].values()), "config saved as v2")
    check(oct(os.stat(E.CONFIG).st_mode & 0o777) == "0o600", "config written 0600")
    r = E.set_mode("disabled", by="alice", via="dashboard", client="192.168.1.5")
    check(r["mode"] == "disabled" and E.get_config()["enabled"] is False
          and E.get_config()["checks"]["canary.egress"]["action"] == "log",
          "legacy disabled = master switch off, check settings kept")
    a = E.audit_tail()
    check(a and a[-1]["action"] == "config" and a[-1]["by"] == "alice"
          and a[-1]["previous_mode"] == "logonly" and a[-1]["mode"] == "disabled"
          and a[-1]["client"] == "192.168.1.5"
          and a[-1]["changes"] == [{"field": "enabled", "from": True, "to": False}],
          "legacy mode change audited with the user and the diff")
    n = len(E.audit_tail())
    E.set_mode("disabled", by="alice")
    check(len(E.audit_tail()) == n, "no audit entry for an unchanged setting")
    for bad in ("bogus", "medium", "high"):
        try:
            E.set_mode(bad)
            check(False, "legacy set-mode %s refused" % bad)
        except ValueError:
            check(True, "legacy set-mode %s refused" % bad)
    check(E.get_config()["enabled"] is False, "refusals change nothing")

    with open(E.STATE, "w") as f:
        json.dump({"tripped": True, "mode": "high", "since": time.time() - 120, "trips": 3}, f)
    E.enforce("high")
    r = E.set_mode("logonly", by="bob")
    check(r["tripped"] and "still TRIPPED" in (r.get("warning") or ""), "warns when tripped")
    check(E.load_state()["tripped"], "a settings change does not lift a trip")
    with contextlib.redirect_stdout(io.StringIO()):
        ok = E.resolve(by="carol", via="dashboard", client="10.0.0.2")
    check(ok is True, "resolve")
    st = E.load_state()
    check(not st["tripped"] and st["resolved_by"] == "carol" and st.get("resolved_at"),
          "resolved state")
    check(not E.lockdown_active("high"), "rules lifted")
    a = E.audit_tail()[-1]
    check(a["action"] == "resolve" and a["by"] == "carol" and a["via"] == "dashboard"
          and a["trips"] == 3, "resolve audited with the real user")
    with open(E.LOG) as f:
        txt = f.read()
    check("RESOLVE by=carol via=dashboard" in txt and "would restart unbound" in txt,
          "resolve logged, unbound restart stubbed")
    with contextlib.redirect_stdout(io.StringIO()):
        ok = E.resolve()
    check(ok is False, "resolve when not tripped is a no-op")


# ── config schema v2: migration, validation, confirm gate ───────────────────
def test_config():
    reset()
    # no file = fresh install: every check Off, nothing runs
    cfg = E.get_config()
    check(cfg["version"] == 2 and cfg["enabled"] and cfg["mode"] == "disabled"
          and all(c["action"] == "off" for c in cfg["checks"].values()), "fresh: all checks Off")
    check(set(cfg["checks"]) == set(E.CHECKS) and len(E.CHECKS) == 6, "six checks")
    check(cfg["checks"]["canary.egress"]["threshold"] == {"count": 1, "minutes": 5}
          and cfg["checks"]["suricata.trojan-activity"]["threshold"]["count"] == 1,
          "default thresholds")
    check(cfg["checks"]["suricata.attempted-admin"]["exclusions"]["wan_only"] is True,
          "WAN-only on by default")
    check(E.watchers_wanted(cfg) == {"suricata": False, "canary": False}, "fresh: no watchers")
    check(E.migrate_config_file() is None and not os.path.exists(E.CONFIG),
          "no file: nothing written")
    # v1 migration exactly as decided
    for old, strength in (("logonly", "medium"), ("medium", "medium"), ("high", "high")):
        cfg, frm = E.normalize_config({"mode": old})
        check(frm == old and cfg["enabled"] and cfg["strength"] == strength
              and all(c["action"] == "log" for c in cfg["checks"].values())
              and cfg["mode"] == "logonly", "v1 %s -> Log only (never Block)" % old)
    cfg, frm = E.normalize_config({"mode": "disabled"})
    check(frm == "disabled" and all(c["action"] == "off" for c in cfg["checks"].values()),
          "v1 disabled -> all Off")
    set_mode_file("logonly")
    os.chmod(E.CONFIG, 0o644)
    check(E.migrate_config_file() == "logonly", "migrated on disk")
    raw = json.load(open(E.CONFIG))
    check(raw["version"] == 2 and raw["mode"] == "logonly" and raw["migrated"]["from"]
          == {"mode": "logonly"} and not any(c["action"] == "block" for c in
                                             raw["checks"].values()), "file: v2, no Block")
    check(oct(os.stat(E.CONFIG).st_mode & 0o777) == "0o600", "migrated file 0600")
    a = E.audit_tail()[-1]
    check(a["action"] == "migrate" and a["previous_mode"] == "logonly", "migration audited")
    check(E.migrate_config_file() is None and len(E.audit_tail()) == 1, "migration runs once")
    # bad stored values fall back per field
    cfg, _ = E.normalize_config({"version": 2, "enabled": "yes", "strength": "extreme",
                                 "checks": {"canary.egress": {"action": "explode",
                                                              "threshold": {"count": 0,
                                                                            "minutes": 3}},
                                            "nope": {"action": "block"}}})
    check(cfg["enabled"] is True and cfg["strength"] == "medium"
          and cfg["checks"]["canary.egress"]["action"] == "off"
          and cfg["checks"]["canary.egress"]["threshold"] == {"count": 1, "minutes": 3}
          and "nope" not in cfg["checks"], "invalid stored values -> defaults")
    # validation
    for patch, why in (({"bogus": 1}, "unknown key"),
                       ({"strength": "extreme"}, "bad strength"),
                       ({"enabled": "yes"}, "enabled not bool"),
                       ({"checks": {"aide.change": {"action": "log"}}}, "coming-later check"),
                       ({"checks": {"x.y": {"action": "log"}}}, "unknown check"),
                       ({"checks": {"canary.egress": {"action": "maybe"}}}, "bad action"),
                       ({"checks": {"canary.egress": {"threshold": {"count": 0}}}}, "count 0"),
                       ({"checks": {"canary.egress": {"threshold": {"minutes": 99999}}}},
                        "minutes too big"),
                       ({"checks": {"canary.egress": {"threshold": {"count": 1.5}}}},
                        "fractional count"),
                       ({"checks": {"canary.egress": {"exclusions": {"sids": [1]}}}},
                        "sids on canary"),
                       ({"checks": {"suricata.trojan-activity": {"exclusions": {
                           "ips": ["10.0.0.0/33"]}}}}, "bad CIDR"),
                       ({"checks": {"suricata.trojan-activity": {"exclusions": {
                           "ips": ["evil.example"]}}}}, "hostname"),
                       ({"checks": {"suricata.trojan-activity": {"exclusions": {
                           "sids": ["abc"]}}}}, "bad sid"),
                       ({"checks": {"suricata.trojan-activity": {"exclusions": {
                           "ips": ["10.0.0.%d" % i for i in range(201)]}}}}, "too many IPs"),
                       ({"notify": {"window_minutes": 0}}, "notify window 0")):
        try:
            E.configure(patch, by="t")
            check(False, "refused: %s" % why)
        except ValueError:
            check(True, "refused: %s" % why)
    r = E.configure({"checks": {"suricata.trojan-activity": {
        "exclusions": {"ips": "192.168.1.181, 10.1.0.0/16 2001:db8::/32", "sids": "2031123 7"},
        "threshold": {"count": "3", "minutes": 10}}}, "notify": {"on_log": False}}, by="dora")
    c = r["config"]["checks"]["suricata.trojan-activity"]
    check(c["exclusions"]["ips"] == ["192.168.1.181", "10.1.0.0/16", "2001:db8::/32"]
          and c["exclusions"]["sids"] == [2031123, 7] and c["threshold"] ==
          {"count": 3, "minutes": 10} and r["config"]["notify"]["on_log"] is False,
          "lists parsed from text, numbers coerced")
    check(len(r["changes"]) == 5 and E.audit_tail()[-1]["by"] == "dora", "diff audited")
    # confirm gate: anything that arms (more) blocking
    try:
        E.configure({"checks": {"canary.egress": {"action": "block"}}}, by="t")
        check(False, "Block needs confirm")
    except E.ConfirmRequired:
        check(True, "Block needs confirm")
    check(E.get_config()["checks"]["canary.egress"]["action"] == "log", "unconfirmed: unchanged")
    E.configure({"checks": {"canary.egress": {"action": "block"}}}, by="t", confirm=True)
    check(E.get_config()["mode"] == "medium" and E.audit_tail()[-1]["confirmed"] is True,
          "confirmed Block saved, derived mode medium")
    try:
        E.configure({"strength": "high"}, by="t")
        check(False, "strength -> high with Block armed needs confirm")
    except E.ConfirmRequired:
        check(True, "strength -> high with Block armed needs confirm")
    E.configure({"enabled": False}, by="t")
    try:
        E.configure({"enabled": True}, by="t")
        check(False, "master on with a Block check needs confirm")
    except E.ConfirmRequired:
        check(True, "master on with a Block check needs confirm")
    E.configure({"enabled": True}, by="t", confirm=True)
    E.configure({"checks": {"canary.egress": {"action": "log"}}}, by="t")
    check(E.get_config()["mode"] == "logonly", "stepping down needs no confirm")
    E.configure({"strength": "high"}, by="t")
    check(E.get_config()["strength"] == "high", "strength change without Block: no confirm")
    # strength frozen while tripped
    with open(E.STATE, "w") as f:
        json.dump({"tripped": True, "mode": "high", "since": time.time()}, f)
    try:
        E.configure({"strength": "medium"}, by="t")
        check(False, "strength change refused while tripped")
    except ValueError as exc:
        check("tripped" in str(exc), "strength change refused while tripped")
    r = E.configure({"checks": {"canary.egress": {"action": "off"}}}, by="t")
    check("still TRIPPED" in r.get("warning", "") and E.load_state()["tripped"],
          "other changes allowed while tripped, with a warning")
    # CLI: exit codes 0 / 2 / 3 and stdin JSON
    env = dict(os.environ)
    run = lambda args, inp: subprocess.run([sys.executable, "-B", ENGINE] + args, env=env,
                                           input=inp, capture_output=True, text=True)
    r = run(["configure", "--by", "eve"], '{"checks":{"suricata.shellcode-detect":{"action":"block"}}}')
    check(r.returncode == 3 and json.loads(r.stdout)["confirm_required"], "CLI: confirm -> rc 3")
    r = run(["configure", "--by", "eve"], '{"strength":"low"}')
    check(r.returncode == 2 and not json.loads(r.stdout)["ok"], "CLI: refused -> rc 2")
    r = run(["configure", "--by", "eve"], '{"notify":{"window_minutes":20}}')
    check(r.returncode == 0 and json.loads(r.stdout)["ok"] and E.get_config()["notify"][
        "window_minutes"] == 20, "CLI: configure ok")
    r = run(["config"], "")
    js = json.loads(r.stdout)
    check(r.returncode == 0 and len(js["checks"]) == 6 and {x["id"] for x in js["coming_later"]}
          == {"aide.change", "auth.bruteforce", "crowdsec.critical"}
          and all(x["available"] is False for x in js["coming_later"]), "CLI: config view")


# ── exclusions, WAN-only, thresholds ────────────────────────────────────────
def test_exclusions():
    reset()
    cfg = write_cfg("log")
    ha = E.event_from_eve_line(HA_FP)
    check(ha and ha["check"] == "suricata.attempted-admin" and ha["sid"] == 2031123,
          "real HA alert parsed")
    d = E.evaluate(ha, cfg)
    check(d["action"] == "excluded" and "router-originated" in d["reason"],
          "REAL FP 1: router -> Home Assistant :8123 excluded")
    cfg_nowan = write_cfg("log", suricata__attempted_admin={"exclusions": {"wan_only": False}})
    check(E.evaluate(ha, cfg_nowan)["action"] == "excluded",
          "router-originated stays excluded with WAN-only off")
    check(E.evaluate(ha, "high")["action"] == "excluded", "...and in block configs")
    lo = E.event_from_kernel(LO_FP)
    check(lo and lo["iface"] == "lo", "real loopback canary line parsed")
    d = E.evaluate(lo, cfg)
    check(d["action"] == "excluded" and "loopback" in d["reason"],
          "REAL FP 2: Nov 8 OUT=lo canary egress excluded")
    check(E.evaluate(lo, "high")["action"] == "excluded", "loopback canary never blocks")
    k = E.event_from_kernel(KLINE.replace("OUT=wan0", "OUT=eth9").replace("1.1.1.1", "127.0.0.5"))
    check(E.evaluate(k, cfg)["action"] == "excluded", "loopback destination excluded")
    check(E.evaluate(E.event_from_kernel(KLINE), cfg)["action"] == "log", "real egress logged")

    def ev(src="198.51.100.7", dst="192.168.1.20", port=443, iface="wan0", sid=2000001):
        e = E.event_from_eve_line(eve_line(src=src, dst=dst, port=port))
        e.update(iface=iface, sid=sid)
        return e
    check(E.evaluate(ev(src="8.8.8.8", iface="enp6s0"), cfg)["action"] == "log",
          "public source counts on any interface")
    check(E.evaluate(ev(src="198.51.100.7"), cfg)["action"] == "log",
          "non-global source arriving on the WAN counts")
    d = E.evaluate(ev(src="192.168.1.50", dst="8.8.8.8", iface="enp6s0"), cfg)
    check(d["action"] == "excluded" and "not from the internet" in d["reason"],
          "LAN-sourced excluded (WAN-only)")
    e = ev(src="192.168.1.50", dst="8.8.8.8", iface="enp6s0")
    e["check"] = "suricata.trojan-activity"
    check(E.evaluate(e, cfg_nowan)["action"] == "excluded",
          "WAN-only is per check (other check still WAN-only)")
    e = ev(src="192.168.1.50", dst="8.8.8.8", iface="enp6s0")
    e["check"] = "suricata.attempted-admin"
    check(E.evaluate(e, cfg_nowan)["action"] == "log", "WAN-only off: LAN source counts")
    check(E.evaluate(ev(src="2001:db8:1::99"), cfg)["action"] == "excluded",
          "LAN IPv6 prefix is internal (even seen on the WAN side)")
    check(E.evaluate(ev(src="10.0.0.7"), cfg)["action"] == "excluded", "VPN client is internal")
    check(E.evaluate(ev(src="73.0.0.2"), cfg)["action"] == "excluded",
          "router's WAN address = router-originated")
    check(E.evaluate(ev(src="127.0.0.1"), cfg_nowan)["action"] == "excluded", "loopback source")
    check(E.evaluate(ev(src="fe80::1", iface="wan0"), cfg)["action"] == "excluded",
          "link-local never WAN-sourced")
    cx = write_cfg("block", suricata__attempted_admin={"exclusions": {
        "ips": ["8.8.0.0/16", "2001:db8:ffff::/48", "192.168.1.20"], "sids": [2000001]}},
        canary__egress={"exclusions": {"ips": ["1.1.1.0/24"]}})
    d = E.evaluate(ev(src="8.8.4.4", sid=5), cx)
    check(d["action"] == "excluded" and "8.8.0.0/16" in d["reason"], "source CIDR excluded")
    d = E.evaluate(ev(src="9.9.9.9", dst="192.168.1.20", sid=5), cx)
    check(d["action"] == "excluded" and "192.168.1.20" in d["reason"], "destination IP excluded")
    check(E.evaluate(ev(src="2001:db8:ffff::5", dst="192.168.1.30", sid=5), cx)["action"]
          == "excluded", "IPv6 CIDR excluded")
    d = E.evaluate(ev(src="9.9.9.9", dst="192.168.1.30"), cx)
    check(d["action"] == "excluded" and "signature 2000001" in d["reason"], "signature excluded")
    d = E.evaluate(ev(src="9.9.9.9", dst="192.168.1.30", sid=5), cx)
    check(d["action"] == "block" and d["strength"] == "medium", "not excluded -> Block")
    e = ev(src="9.9.9.9", dst="192.168.1.30", sid=5)
    e["check"] = "suricata.trojan-activity"
    check(E.evaluate(e, write_cfg("block", suricata__trojan_activity="off"))["action"] == "off",
          "per-check Off")
    check(E.evaluate(e, write_cfg("block", enabled=False))["action"] == "off", "master off")
    check(E.evaluate(e, write_cfg("block", suricata__trojan_activity="log"))["action"] == "log",
          "per-check Log next to Block checks")
    d = E.evaluate(ev(src="8.8.4.4", port=5555), cx)
    check(d["action"] == "absorb", "deception absorb comes before exclusions")
    check(E.evaluate(E.event_from_kernel(KLINE), cx)["action"] == "excluded",
          "canary destination excluded")


def test_threshold():
    reset()
    cfg = write_cfg("log", canary__egress={"threshold": {"count": 3, "minutes": 1}})
    k = E.event_from_kernel(KLINE)
    win = {}
    t0 = 1000000.0
    acts = []
    for i, dt in enumerate((0, 10, 20, 30, 40, 200, 205, 206)):
        e = dict(k, ts=t0 + dt)
        d = E.evaluate(e, cfg, windows=win)
        E._commit_window(win, d, e["ts"])
        acts.append(d["action"])
    check(acts == ["counted", "counted", "log", "counted", "counted", "counted", "counted",
                   "log"], "3 in 1 min: fires on the 3rd, resets, old events expire (%s)" % acts)
    check(len(win["canary.egress"]) <= 3 and win["canary.egress"].maxlen == 3,
          "window bounded by the count")
    d = E.evaluate(dict(k, ts=t0), cfg, windows={"canary.egress": [t0 - 5, t0 - 1]})
    check(d["action"] == "log" and d["threshold"]["seen"] == 3, "seen counts earlier events")
    d = E.evaluate(dict(k, ts=t0), cfg, windows={"canary.egress": [t0 - 120, t0 - 61]})
    check(d["action"] == "counted" and "1 of 3" in d["reason"], "expired events don't count")
    cfg = write_cfg("log")
    check(E.evaluate(k, cfg, windows=win)["action"] == "log", "count 1 fires immediately")
    # handle_event keeps the daemon's windows; dry runs never touch them
    reset()
    write_cfg("log", canary__egress={"threshold": {"count": 2, "minutes": 5}})
    w = {}
    d1 = E.handle_event(dict(k, ts=time.time()), windows=w)
    dd = E.handle_event(dict(k, ts=time.time()), windows=w, dry=True)
    d2 = E.handle_event(dict(k, ts=time.time()), windows=w)
    check(d1["action"] == "counted" and dd["action"] == "counted" and d2["action"] == "log",
          "handle_event: counted, (dry run ignored), fired")
    check([r["action"] for r in history()] == ["counted", "log"], "history: counted + log")
    check(len(pushes()) == 1, "only the threshold hit pushes")


# ── Test path: same evaluation, no side effects ─────────────────────────────
def test_test_path():
    reset()
    write_cfg("block", "high", canary__egress="log", suricata__shellcode_detect="off")
    before = (E.load_state(), os.path.exists(E.HISTORY), os.path.exists(E.ENFORCE_LOG))
    r = E.test_check("suricata.attempted-admin")
    d = r["decision"]
    check(d["action"] == "block" and d["strength"] == "high" and d["dry_run"]
          and any("HIGH" in x for x in d["would"]), "test: would block (HIGH)")
    check(r["event"]["test"] and r["event"]["iface"] == "wan0", "synthetic WAN event")
    r = E.test_check("canary.egress")
    check(r["decision"]["action"] == "log" and any("push" in x for x in r["decision"]["would"]),
          "test: would log + push")
    r = E.test_check("suricata.shellcode-detect")
    check(r["decision"]["action"] == "off", "test: check Off")
    r = E.test_check("suricata.trojan-activity", {"src": "192.168.1.1", "dst_ip": "192.168.1.181",
                                                   "dst_port": 8123, "iface": "enp6s0"})
    check(r["decision"]["action"] == "excluded" and "router-originated" in r["decision"]["reason"],
          "test: excluded because router-originated")
    r = E.test_check("canary.egress", {"iface": "lo"})
    check(r["decision"]["action"] == "excluded", "test: loopback canary excluded")
    r = E.test_check("suricata.trojan-activity", {"dst_port": 5555})
    check(r["decision"]["action"] == "absorb", "test: deception port absorbed")
    for cid, over in (("aide.change", None), ("nope", None),
                      ("canary.egress", {"src": "not-an-ip"}),
                      ("canary.egress", {"iface": "a b"}),
                      ("canary.egress", {"dst_port": 70000}),
                      ("canary.egress", {"evil": 1}),
                      ("canary.egress", {"sig": "x\ny"})):
        try:
            E.test_check(cid, over)
            check(False, "test refused: %s %s" % (cid, over))
        except ValueError:
            check(True, "test refused: %s %s" % (cid, over))
    after = (E.load_state(), os.path.exists(E.HISTORY), os.path.exists(E.ENFORCE_LOG))
    check(before == after and not pushes(), "test: no state, history, enforcement or push")
    r = subprocess.run([sys.executable, "-B", ENGINE, "test", "suricata.attempted-admin"],
                       env=dict(os.environ), input='{"src":"8.8.8.8"}', capture_output=True,
                       text=True)
    js = json.loads(r.stdout)
    check(r.returncode == 0 and js["decision"]["action"] == "block"
          and js["event"]["src"] == "8.8.8.8", "CLI test with overrides")
    check(not pushes() and not os.path.exists(E.HISTORY), "CLI test: no side effects")


# ── event history ───────────────────────────────────────────────────────────
OLD_LOG = """2026-11-08T14:49:38 DAEMON start mode=disabled
2026-11-08T14:52:00 TRIP mode=medium class=canary-egress sig='[TUXWALL-CANARY-EGRESS] IN= OUT=lo SRC=192.168.1.1 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=10243 DF PROTO=TCP SPT=50542 DPT=8744 WINDOW=43690 RES=0x' src=local:opencanary reason=Canary egress attempt (presumed deception-layer compromise) action=lockdown
2026-11-08T16:19:11 REPEAT class=canary-egress sig='x' src=local:opencanary trips=2 (already contained)
2026-11-09T00:58:40 WOULD-TRIP (log-only) class=canary-egress sig='[TUXWALL-CANARY-EGRESS] IN= OUT=lo SRC=192.168.1.1 DST=192.168.1.1 LEN=60 TOS=0x' src=local:opencanary reason=Canary egress attempt (presumed canary compromise) action=recorded
2026-11-09T06:57:30 DECEPTION-ABSORBED class=Attempted Administrator Privilege Gain src=115.99.237.100 -> 203.0.113.209:5555 [deception layer - absorbed] action=delegated (canary + ban pipeline own this)
2026-11-09T06:57:35 TRIP mode=high class=Attempted Administrator Privilege Gain src=115.99.237.100 -> 203.0.113.209:443 reason=Suricata priority-1 alert action=lockdown
2026-11-14T04:07:54 WOULD-TRIP (log-only) class=canary-egress src=local:opencanary ->  reason=Canary egress attempt (presumed canary compromise) action=recorded
2026-11-18T10:51:33 WOULD-TRIP (log-only) class=Attempted Administrator Privilege Gain src=192.168.1.1 -> 192.168.1.181:8123 reason=Suricata priority-1 alert action=recorded
2026-11-18T10:51:34 RESOLVE by=admin via=cli (contained 0 minutes, 1 trip events)
"""


def test_history():
    reset()
    cfg = write_cfg("log")
    for e in (E.event_from_eve_line(HA_FP), E.event_from_kernel(LO_FP),
              E.event_from_eve_line(eve_line(src="8.8.8.8", sig="real one")),
              E.event_from_eve_line(eve_line(src="8.8.8.8", port=5555)),
              E.event_from_kernel(KLINE)):
        E.handle_event(e, cfg, windows={})
    rows = history()
    check([r["action"] for r in rows] == ["excluded", "excluded", "log", "absorb", "log"],
          "every evaluated event recorded (%s)" % [r["action"] for r in rows])
    r0 = rows[0]
    check(r0["check"] == "suricata.attempted-admin" and r0["excluded"] is True
          and "router-originated" in r0["decision"] and r0["src"] == "192.168.1.1"
          and r0["dst"] == "192.168.1.181:8123" and r0["sid"] == 2031123
          and r0["src_port"] == 35092 and r0["iface"] == "enp6s0" and r0["sig"].startswith(
              "ET HUNTING"), "history entry fields")
    check(rows[1]["iface"] == "lo" and rows[1]["check"] == "canary.egress", "canary entry")
    check(len(pushes()) == 2, "excluded / absorbed events never push")
    st = E.load_state()
    check(st.get("logonly_events") == 2 and st.get("absorbed_events") == 1,
          "legacy counters: only real log-only / absorbed")
    check(oct(os.stat(E.HISTORY).st_mode & 0o777) == "0o640", "history file 0640")
    q = E.history_query(check="canary.egress")
    check(q["total"] == 2 and q["items"][0]["action"] == "log", "filter by check, newest first")
    q = E.history_query(action="excluded", limit=1)
    check(q["total"] == 2 and len(q["items"]) == 1 and q["items"][0]["check"] == "canary.egress",
          "filter by action + paging")
    q = E.history_query(action="excluded", limit=1, offset=1)
    check(q["items"][0]["check"] == "suricata.attempted-admin", "offset")
    check(E.history_query(since=time.time() + 60)["total"] == 0, "since filter")
    c = E.history_counts()
    check(c["canary.egress"]["day"] == 1 and c["canary.egress"]["excluded_week"] == 1,
          "per-check counts (excluded separately)")
    # retention: age
    now = time.time()
    E.history_append([{"ts": now - 91 * 86400, "check": "old", "action": "log"},
                      {"ts": now - 89 * 86400, "check": "keep", "action": "log"}])
    removed = E.history_prune()
    checks = [r["check"] for r in history()]
    check(removed == 1 and "old" not in checks and "keep" in checks, "90-day retention")
    # retention: size cap (trimmed to 80 %, newest kept)
    old = E.HISTORY_MAX_BYTES
    E.HISTORY_MAX_BYTES = 20000
    try:
        for i in range(300):
            E.history_append({"ts": now, "check": "bulk", "action": "log", "n": i,
                              "pad": "x" * 60})
        size = os.path.getsize(E.HISTORY)
        rows = history()
        check(size <= 20000 and rows[-1].get("n") == 299, "size cap keeps the newest (%d)" % size)
    finally:
        E.HISTORY_MAX_BYTES = old
    left = [n for n in os.listdir(os.path.dirname(E.HISTORY)) if n.endswith(".tmp")]
    check(not left, "no temp files after pruning")
    # one-time import of the old log
    reset()
    log_text = OLD_LOG
    for day, ago in (("2026-11-08", 11), ("2026-11-09", 10), ("2026-11-14", 5),
                     ("2026-11-18", 1)):
        log_text = log_text.replace(day, time.strftime("%Y-%m-%d",
                                                       time.localtime(time.time() - ago * 86400)))
    with open(E.LOG, "w") as f:
        f.write(log_text)
    E.history_append({"ts": time.time(), "check": "canary.egress", "action": "log"})
    n = E.import_old_log()
    rows = history()
    check(n == 6 and len(rows) == 7, "import: 6 events (no REPEAT/DAEMON/RESOLVE)")
    check(all(r.get("imported") for r in rows[:6]) and not rows[6].get("imported"),
          "imported events first, marked")
    acts = [(r["check"], r["action"]) for r in rows[:6]]
    check(acts == [("canary.egress", "block"), ("canary.egress", "log"),
                   ("suricata.attempted-admin", "absorb"), ("suricata.attempted-admin", "block"),
                   ("canary.egress", "log"), ("suricata.attempted-admin", "log")],
          "import: checks/actions mapped (%s)" % acts)
    check(rows[0]["iface"] == "lo" and rows[0]["strength"] == "medium"
          and rows[0]["dst"] == "192.168.1.1:8744", "import: canary details from the kernel line")
    check(rows[3]["dst"] == "203.0.113.209:443" and rows[3]["src"] == "115.99.237.100"
          and rows[3]["strength"] == "high", "import: trip details")
    check("loopback" in rows[0].get("now_excluded", "") and "router-originated" in
          rows[5].get("now_excluded", "") and "now_excluded" not in rows[3],
          "import: the two real false positives are flagged as excluded today")
    check(E.load_state()["history_imported"]["events"] == 6, "import marked in state")
    check(E.import_old_log() == 0 and len(history()) == 7, "import runs once")


# ── watchers ────────────────────────────────────────────────────────────────
def test_eve_tail():
    reset()
    got = []
    with open(EVE_PATH, "w") as f:
        f.write(eve_line(sig="OLD before start") + "\n")
    w = E.Watcher("suricata", E.tail_eve, got.append)
    w.start()
    try:
        time.sleep(0.4)
        check(got == [], "starts at EOF")

        def append(line):
            with open(EVE_PATH, "a") as f:
                f.write(line + "\n")
        append(json.dumps({"event_type": "flow"}))
        append(eve_line(sig="A1"))
        check(wait_for(lambda: [e["sig"] for e in got] == ["A1"]), "alert seen")
        # partial line completes later
        with open(EVE_PATH, "a") as f:
            f.write(eve_line(sig="A2")[:50])
        time.sleep(1.3)
        with open(EVE_PATH, "a") as f:
            f.write(eve_line(sig="A2")[50:] + "\n")
        check(wait_for(lambda: len(got) == 2 and got[-1]["sig"] == "A2"), "split line joined")
        # rename rotation: old file gets a last line, then a new file
        append(eve_line(sig="A3-last-in-old"))
        os.rename(EVE_PATH, EVE_PATH + ".1")
        with open(EVE_PATH, "w") as f:
            f.write(eve_line(sig="B1-new-file") + "\n")
        check(wait_for(lambda: [e["sig"] for e in got][-2:] == ["A3-last-in-old", "B1-new-file"]),
              "rename rotation: old drained, new read from start")
        # copytruncate
        with open(EVE_PATH, "r+") as f:
            f.truncate(0)
        time.sleep(1.3)
        append(eve_line(sig="C1-after-truncate"))
        check(wait_for(lambda: got[-1]["sig"] == "C1-after-truncate"), "copytruncate rewinds")
        # oversized line is skipped, the next line still works
        old = E.MAX_LINE
        E.MAX_LINE = 4096
        with open(EVE_PATH, "a") as f:
            f.write('{"event_type":"alert","x":"' + "y" * 20000 + '"}\n')
        append(eve_line(sig="D1-after-huge"))
        check(wait_for(lambda: got[-1]["sig"] == "D1-after-huge"), "oversized line skipped")
        E.MAX_LINE = old
        s = w.status()
        check(s["state"] == "running" and s["age"] < 3, "eve watcher heartbeat")
        with open(E.LOG) as f:
            txt = f.read()
        check("EVE-ROTATED" in txt and "EVE-TRUNCATED" in txt, "rotation logged")
    finally:
        w.halt()
    check(not w.alive() and w.status()["state"] == "off", "eve watcher stops")


def test_kernel():
    reset()
    open(KLOG, "w").close()
    got = []
    w = E.Watcher("canary", E.follow_kernel, got.append)
    w.start()
    try:
        time.sleep(0.5)
        with open(KLOG, "a") as f:
            f.write("unrelated\n" + KLINE + "\n")
        check(wait_for(lambda: len(got) == 1 and got[0]["check"] == "canary.egress"),
              "kernel follower sees the canary line")
        check(w.status()["state"] == "running", "kernel watcher running")
    finally:
        w.halt(wait=8)
    check(not w.alive(), "kernel watcher stops")
    old = E.KERNEL_CMD
    E.KERNEL_CMD = ["sh", "-c", "exit 3"]
    try:
        w2 = E.Watcher("canary", E.follow_kernel, got.append)
        w2.start()
        check(wait_for(lambda: not w2.alive()), "reader exit ends the thread")
        s = w2.status()
        check(s["state"] == "dead" and "exited" in s["error"], "dead watcher reported")
    finally:
        E.KERNEL_CMD = old


# ── the daemon, end to end (sandboxed subprocess) ───────────────────────────
def test_daemon():
    reset()
    set_mode_file("logonly")          # v1: migrated at start
    with open(E.LOG, "w") as f:
        f.write(time.strftime("%Y-%m-%dT%H:%M:%S") + " WOULD-TRIP (log-only) class=Web "
                "Application Attack src=192.168.1.1 -> 192.168.1.181:8123 reason=Suricata "
                "priority-1 alert action=recorded\n")
    open(KLOG, "w").close()
    with open(EVE_PATH, "w") as f:
        f.write("")
    env = dict(os.environ, TUXWALL_TRIPWIRE_TICK="0.3", TUXWALL_TRIPWIRE_BEAT="0.5",
               TUXWALL_TRIPWIRE_ENFORCE_S="0.5", TUXWALL_TRIPWIRE_NOTIFY_WINDOW="600")
    p = subprocess.Popen([sys.executable, "-B", ENGINE, "run"], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        def health():
            return E.read_json(E.HEALTH, {})

        def states():
            return {n: w.get("state") for n, w in (health().get("watchers") or {}).items()}
        check(wait_for(lambda: states() == {"suricata": "running", "canary": "running"}),
              "daemon: both watchers beat")
        cfg = json.load(open(E.CONFIG))
        check(cfg["version"] == 2 and cfg["mode"] == "logonly"
              and {c["action"] for c in cfg["checks"].values()} == {"log"},
              "daemon start migrated v1 logonly -> all checks Log only")
        check(health().get("wanted") == {"suricata": True, "canary": True}
              and health().get("enabled") is True, "health: wanted watchers")
        check(len(history()) == 1 and history()[0].get("imported"), "old log imported at start")
        time.sleep(0.5)
        with open(EVE_PATH, "a") as f:
            for i in range(6):
                f.write(eve_line(src="8.8.8.%d" % i, dst="192.168.1.20", port=443,
                                 sig="ET real x%d" % i) + "\n")
            f.write(HA_FP + "\n")
            f.write(eve_line(src="8.8.8.8", port=5555) + "\n")
        with open(KLOG, "a") as f:
            f.write(LO_FP + "\n")
        check(wait_for(lambda: E.load_state().get("logonly_events") == 6), "logonly counted")
        check(wait_for(lambda: E.load_state().get("absorbed_events") == 1), "absorbed counted")
        check(wait_for(lambda: len(history()) == 10), "history: 6 log + HA + absorb + lo + import")
        acts = sorted(r["action"] for r in history() if not r.get("imported"))
        check(acts == ["absorb", "excluded", "excluded"] + ["log"] * 6, "history actions")
        check(len(pushes()) == 1, "6 log-only events -> 1 push, excluded never push")
        check(not E.load_state().get("tripped") and (not os.path.exists(E.ENFORCE_LOG)
              or "-I" not in open(E.ENFORCE_LOG).read()), "log only never enforces")
        st = E.load_state()
        check(st["last_logonly"]["dst"] == "192.168.1.20:443"
              and st["last_logonly"]["check"] == "suricata.attempted-admin", "last_logonly")

        # canary check Off -> only its watcher stops
        E.configure({"checks": {"canary.egress": {"action": "off"}}}, by="t")
        check(wait_for(lambda: states() == {"suricata": "running", "canary": "off"}),
              "per-check off: canary watcher stops, suricata keeps running")
        check(wait_for(lambda: health().get("wanted") == {"suricata": True, "canary": False}),
              "health reports wanted")
        E.configure({"enabled": False}, by="t")
        check(wait_for(lambda: set(states().values()) == {"off"}), "master off: watchers stop")
        with open(EVE_PATH, "a") as f:
            f.write(eve_line(src="8.8.8.8", sig="while disabled") + "\n")
        time.sleep(1.0)
        check(E.load_state().get("logonly_events") == 6, "master off: nothing processed")

        E.configure({"enabled": True, "checks": {"canary.egress": {"action": "block"}}},
                    by="t", confirm=True)
        check(wait_for(lambda: set(states().values()) == {"running"}), "re-armed: watchers back")
        time.sleep(0.8)
        with open(KLOG, "a") as f:
            f.write(LO_FP + "\n")
        time.sleep(1.0)
        check(not E.load_state().get("tripped"), "Block: loopback canary line still ignored")
        with open(KLOG, "a") as f:
            f.write(KLINE + "\n")
        check(wait_for(lambda: E.load_state().get("tripped") is True), "Block: canary trips")
        st = E.load_state()
        check(st["mode"] == "medium" and st["check"] == "canary.egress"
              and st["dst"] == "1.1.1.1:443", "trip state")
        check(wait_for(lambda: E.lockdown_active("medium")), "medium: rules (stub) applied")
        check(any("TRIPPED" in x["title"] and x["priority"] == "urgent" for x in pushes()),
              "trip push sent")
        check(wait_for(lambda: any(r["action"] == "block" and not r.get("imported")
                                   for r in history())), "trip recorded in history")
        # rules removed behind the daemon's back -> re-enforced
        E.lift()
        check(wait_for(lambda: E.lockdown_active("medium")), "watchdog re-enforces")
        check(wait_for(lambda: "RE-ENFORCE" in open(E.LOG).read()), "re-enforce logged")
        # stepped down to log only while tripped: the trip holds
        E.set_mode("logonly", by="t")
        time.sleep(1.0)
        check(E.load_state()["tripped"] and E.lockdown_active("medium"), "trip holds in logonly")
        r = subprocess.run([sys.executable, "-B", ENGINE, "resolve", "--by", "dana",
                            "--via", "dashboard"], env=env, capture_output=True, text=True)
        check(r.returncode == 0 and "resolved" in r.stdout, "CLI resolve")
        time.sleep(1.2)
        check(not E.lockdown_active("medium") and not E.load_state()["tripped"],
              "resolved stays resolved (no watchdog race)")
        r = subprocess.run([sys.executable, "-B", ENGINE, "status"], env=env,
                           capture_output=True, text=True)
        js = json.loads(r.stdout)
        check(js["mode"] == "logonly" and js["health"].get("watchers")
              and js["checks"]["canary.egress"] == "log", "CLI status has health + checks")
        r = subprocess.run([sys.executable, "-B", ENGINE, "evaluate", "--mode", "high"],
                           env=env, input=eve_line() + "\n" + KLINE + "\n" + HA_FP + "\n",
                           capture_output=True, text=True)
        dec = [json.loads(x)["decision"]["action"] for x in r.stdout.splitlines()]
        check(dec == ["block", "block", "excluded"], "CLI evaluate dry run (%s)" % dec)
        check(E.load_state()["tripped"] is False, "evaluate has no side effects")
        r = subprocess.run([sys.executable, "-B", ENGINE, "history", "--action", "block",
                            "--limit", "5"], env=env, capture_output=True, text=True)
        js = json.loads(r.stdout)
        check(r.returncode == 0 and js["total"] == 1 and js["items"][0]["check"]
              == "canary.egress", "CLI history filter")
    finally:
        p.terminate()
        try:
            p.wait(15)
        except subprocess.TimeoutExpired:
            p.kill()
    err = p.stderr.read().decode() if p.stderr else ""
    check("Traceback" not in err, "daemon ran without tracebacks" + (": " + err[-400:] if err else ""))
    check("DAEMON stop" in open(E.LOG).read(), "daemon stops cleanly on SIGTERM")


def main():
    try:
        for t in (test_eval, test_rules, test_notify, test_state, test_mode_resolve,
                  test_config, test_exclusions, test_threshold, test_test_path,
                  test_history, test_eve_tail, test_kernel, test_daemon):
            t()
    finally:
        shutil.rmtree(ROOT, ignore_errors=True)
    print("tripwire_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
