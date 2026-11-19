#!/usr/bin/env python3
"""Tripwire engine checks (pkg/usr/local/sbin/tuxwall-tripwire), all in a
temp sandbox: TUXWALL_TRIPWIRE_ROOT remaps every path and stubs the
firewall (rules are only recorded), pushes go to a file, the kernel log is
a plain file followed with tail. Nothing here touches iptables, systemd or
the network.

  python3 tools/tripwire_check.py            pure tests + a short daemon run (CI)

Covers: the eve pre-filter and event normalisation, evaluate() per mode and
deception-port absorption, the lockdown rule plan (high mode keeps WAN DHCP,
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
                   "TUXWALL_TRIPWIRE_KERNEL_CMD": "tail -n 0 -F %s" % KLOG})


def load_engine():
    loader = importlib.machinery.SourceFileLoader("tw_engine", ENGINE)
    spec = importlib.util.spec_from_loader("tw_engine", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


E = load_engine()
# hard stop: every path below must live in the sandbox, firewall stubbed
assert E.STUB_FIREWALL and not E.NETNS, "engine not sandboxed - refusing to test"
for p in (E.CONFIG, E.STATE, E.LOG, E.AUDIT, E.HEALTH, E.LOCK, E.ENFORCE_LOG):
    assert p.startswith(ROOT), p


def reset():
    for name in os.listdir(ROOT):
        p = os.path.join(ROOT, name)
        shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
    os.makedirs(ROOT + "/etc/tuxwall")
    os.makedirs(ROOT + "/var/log/tuxwall")


def set_mode_file(mode):
    with open(E.CONFIG, "w") as f:
        json.dump({"mode": mode}, f)


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


KLINE = ("[TUXWALL-CANARY-EGRESS] IN= OUT=enp5s0 SRC=73.0.0.2 DST=1.1.1.1 LEN=60 "
         "PROTO=TCP SPT=34236 DPT=443 SYN")


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
    expect = {"disabled": "ignore", "logonly": "log", "medium": "trip", "high": "trip"}
    for mode, action in expect.items():
        check(E.evaluate(ev, mode)["action"] == action, "evaluate %s -> %s" % (mode, action))
    absorbed = E.event_from_eve_line(eve_line(port=5555))
    check("deception layer" in absorbed["dst"], "deception port annotated")
    for mode in E.MODES:
        check(E.evaluate(absorbed, mode)["action"] == "absorb", "absorbed in %s" % mode)
    k = E.event_from_kernel(KLINE)
    check(k and k["check"] == "canary.egress" and k["dst"] == "1.1.1.1:443"
          and k["iface"] == "enp5s0", "kernel line parsed")
    check(E.event_from_kernel("random kernel line") is None, "unrelated kernel line ignored")
    check(E.evaluate(k, "medium")["action"] == "trip", "canary egress trips in medium")
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
    set_mode_file("high")
    order = []
    real_send, real_enf = E._send, E.enforce
    E._send = lambda *a, **k: order.append("push") or True
    E.enforce = lambda *a, **k: order.append("enforce") or True
    try:
        ev = E.event_from_eve_line(eve_line())
        d = E.handle_event(ev)
        check(d["action"] == "trip" and order == ["push", "enforce"], "push before enforce")
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


# ── set-mode, audit, resolve ────────────────────────────────────────────────
def test_mode_resolve():
    reset()
    with open(E.CONFIG, "w") as f:
        json.dump({"mode": "medium", "future": {"x": 1}}, f)
    r = E.set_mode("logonly", by="alice", via="dashboard", client="192.168.1.5")
    check(r["ok"] and r["previous"] == "medium" and "warning" not in r, "set-mode ok")
    check(E.get_config().get("future") == {"x": 1}, "other config keys kept")
    a = E.audit_tail()
    check(a and a[-1]["action"] == "mode" and a[-1]["by"] == "alice"
          and a[-1]["previous"] == "medium" and a[-1]["mode"] == "logonly"
          and a[-1]["client"] == "192.168.1.5", "mode change audited")
    E.set_mode("logonly", by="alice")
    check(len(E.audit_tail()) == 1, "no audit entry for an unchanged mode")
    try:
        E.set_mode("bogus")
        check(False, "bad mode rejected")
    except ValueError:
        check(True, "bad mode rejected")

    with open(E.STATE, "w") as f:
        json.dump({"tripped": True, "mode": "high", "since": time.time() - 120, "trips": 3}, f)
    E.enforce("high")
    r = E.set_mode("disabled", by="bob")
    check(r["tripped"] and "still TRIPPED" in (r.get("warning") or ""), "warns when tripped")
    check(E.load_state()["tripped"], "mode change does not lift a trip")
    r = E.set_mode("high", by="bob")
    check("warning" not in r, "no warning for medium/high")
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
    set_mode_file("logonly")
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
        time.sleep(0.5)
        with open(EVE_PATH, "a") as f:
            for i in range(6):
                f.write(eve_line(src="192.168.1.1", dst="192.168.1.181", port=8123,
                                 sig="ET HUNTING x%d" % i) + "\n")
            f.write(eve_line(port=5555) + "\n")
        check(wait_for(lambda: E.load_state().get("logonly_events") == 6), "logonly counted")
        check(wait_for(lambda: E.load_state().get("absorbed_events") == 1), "absorbed counted")
        check(len(pushes()) == 1, "6 log-only events -> 1 push")
        check(not E.load_state().get("tripped") and not os.path.exists(E.ENFORCE_LOG)
              or "-I" not in open(E.ENFORCE_LOG).read(), "logonly never enforces")
        st = E.load_state()
        check(st["last_logonly"]["dst"] == "192.168.1.181:8123"
              and st["last_logonly"]["check"] == "suricata.attempted-admin", "last_logonly")

        set_mode_file("disabled")
        check(wait_for(lambda: set(states().values()) == {"off"}), "disabled: watchers stop")
        with open(EVE_PATH, "a") as f:
            f.write(eve_line(sig="while disabled") + "\n")
        time.sleep(1.0)
        check(E.load_state().get("logonly_events") == 6, "disabled: nothing processed")

        set_mode_file("medium")
        check(wait_for(lambda: set(states().values()) == {"running"}), "re-armed: watchers back")
        time.sleep(0.8)
        with open(KLOG, "a") as f:
            f.write(KLINE + "\n")
        check(wait_for(lambda: E.load_state().get("tripped") is True), "medium: canary trips")
        st = E.load_state()
        check(st["mode"] == "medium" and st["check"] == "canary.egress"
              and st["dst"] == "1.1.1.1:443", "trip state")
        check(wait_for(lambda: E.lockdown_active("medium")), "medium: rules (stub) applied")
        check(any("TRIPPED" in x["title"] and x["priority"] == "urgent" for x in pushes()),
              "trip push sent")
        # rules removed behind the daemon's back -> re-enforced
        E.lift()
        check(wait_for(lambda: E.lockdown_active("medium")), "watchdog re-enforces")
        check(wait_for(lambda: "RE-ENFORCE" in open(E.LOG).read()), "re-enforce logged")
        # mode switched to logonly while tripped: the trip holds
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
        check(js["mode"] == "logonly" and js["health"].get("watchers"), "CLI status has health")
        r = subprocess.run([sys.executable, "-B", ENGINE, "evaluate", "--mode", "high"],
                           env=env, input=eve_line() + "\n" + KLINE + "\n",
                           capture_output=True, text=True)
        dec = [json.loads(x)["decision"]["action"] for x in r.stdout.splitlines()]
        check(dec == ["trip", "trip"], "CLI evaluate dry run")
        check(E.load_state()["tripped"] is False, "evaluate has no side effects")
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
                  test_eve_tail, test_kernel, test_daemon):
            t()
    finally:
        shutil.rmtree(ROOT, ignore_errors=True)
    print("tripwire_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
