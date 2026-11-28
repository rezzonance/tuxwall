#!/usr/bin/env python3
"""Suricata rule suppression (3.3.7, A8) - sandboxed.

    python3 tools/suricata_suppress_check.py

Fixture threshold.config files (documentation SIDs/addresses only) in temp
dirs; suricata/suricatasc/systemctl answered by a fake runner. Checks:
- the owner's hand-written lines are never changed: add -> remove gives the
  original file byte for byte (also with CRLF-free odd spacing, comments,
  scoped hand lines, an empty file); a missing final newline is the only
  thing ever added; lines after an old block keep their text;
- the block format (metadata comment + suppress line; network-wide vs one
  device = `track by_either, ip [...]`, link-local/loopback dropped);
- a damaged block (two blocks, begin without end, foreign or edited line,
  comment without rule) is refused, never rewritten;
- hand-written SIDs are reported, add/replace/max, input validation, the
  INFO/POLICY risk flag;
- apply(): rejected test -> file untouched; ok -> written (mode kept,
  backup = previous file), reload-rules via suricatasc (fallback systemctl);
  failed reload -> previous file restored byte for byte + reloaded again;
  engine stopped -> saved without reload;
- the real `suricata -T` check (only where suricata is installed: good file
  accepted, bad syntax and bad address rejected);
- API (loopback harness): GET/POST admin only (401/403, CSRF), 202 job,
  hits in the last 24 h from a fixture eve.json, device scope by id and by
  address (current addresses), hand-written SID refused, device scope under
  a network-wide rule refused, remove, damaged block -> 409, one job at a time.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "www", "includes"))
sys.path.insert(0, HERE)
import suricata_suppress as S  # noqa: E402

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL: " + name)


HAND = """# Thresholding / suppression (owner's own lines)
# suppress gen_id <gid>, sig_id <sid>
suppress gen_id 1, sig_id 2200001
suppress gen_id 1, sig_id 2200002   
suppress gen_id 1,sig_id 2200003
suppress gen_id 1, sig_id 2200004, track by_src, ip 192.0.2.50
\tsuppress gen_id 1, sig_id 2200005

threshold gen_id 1, sig_id 2000001, type limit, track by_src, count 1, seconds 60
"""


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def entry(sid, scope="network", addrs=None, **kw):
    dev = {"id": "m00005e005301", "name": "phone", "addrs": addrs or []} if scope == "device" else None
    return S.validate_new(dict({"sid": sid, "scope": scope, "sig": "ET INFO Observed DNS Query to .biz TLD"}, **kw),
                          1700000000, "boss", dev)


def t_text():
    e1 = entry(2027863, note="ads\nin a game")
    new = S.render(HAND, [e1])
    check(new.startswith(HAND) and new.count(S.BEGIN) == 1 and new.endswith(S.END + "\n"),
          "add: the original text untouched, one block appended at the end")
    check("suppress gen_id 1, sig_id 2027863\n" in new and "\nin a game" not in new and "ads in a game" in new,
          "add: suppress line; the note is one line in the metadata comment")
    check(S.render(new, []) == HAND, "remove the last rule -> file byte-identical to the original")
    _b, block, _a = S.split(new)
    got = S.parse_block(block)
    check(len(got) == 1 and got[0]["sid"] == 2027863 and got[0]["scope"] == "network" and got[0]["by"] == "boss",
          "parse: the block reads back")
    e2 = entry(2027864, "device", ["192.0.2.10", "2001:db8::10", "fe80::1", "127.0.0.1", "192.0.2.10", "junk",
                                   "2001:db8::11/64"])
    check(e2["addrs"] == ["192.0.2.10", "2001:db8::10", "2001:db8::11"] and e2["device"] == "m00005e005301",
          "device scope: current addresses, link-local/loopback/duplicates/junk dropped (%r)" % e2["addrs"])
    two = S.render(new, S.merge(got, e2))
    check("suppress gen_id 1, sig_id 2027864, track by_either, ip [192.0.2.10,2001:db8::10,2001:db8::11]" in two,
          "device scope: track by_either with the address list")
    lines_before = [l for l in HAND.split("\n")]
    check(two.split("\n")[:len(lines_before) - 1] == lines_before[:-1], "two rules: every hand line unchanged")
    check(S.render(two, []) == HAND and sha(S.render(two, [])) == sha(HAND), "remove both -> original hash")
    _b, block, _a = S.split(two)
    rt = S.parse_block(block)
    check([x["sid"] for x in rt] == [2027863, 2027864] and rt[1]["addrs"] == e2["addrs"], "two rules read back")
    # replace (same sid + scope + device), max
    rep = S.merge(rt, entry(2027863, note="new note"))
    check(len(rep) == 2 and rep[-1]["note"] == "new note", "merge: the same rule again replaces it")
    try:
        S.merge([entry(1000 + i) for i in range(S.MAX_RULES)], entry(5))
        check(False, "merge: max rules")
    except ValueError:
        check(True, "merge: max rules")
    # odd files
    check(S.render("", [e1]).startswith(S.BEGIN) and S.render(S.render("", [e1]), []) == "", "empty file round trip")
    nonl = "suppress gen_id 1, sig_id 2200001"
    check(S.render(S.render(nonl, [e1]), []) == nonl + "\n", "no final newline: only a newline is added")
    after = S.render(HAND, [e1]) + "suppress gen_id 1, sig_id 2290001\n"       # owner appended after the block
    moved = S.render(after, [e1, entry(2027865)])
    check("suppress gen_id 1, sig_id 2290001\n" in moved and moved.count(S.BEGIN) == 1
          and moved.index("2290001") < moved.index(S.BEGIN), "owner line after the block kept (block stays last)")
    # hand-written SIDs
    hs = S.hand_sids(two)
    check([h["sid"] for h in hs] == [2200001, 2200002, 2200003, 2200004, 2200005]
          and [h["scoped"] for h in hs] == [False, False, False, True, False],
          "hand_sids: the owner's suppress lines (incl. odd spacing/tab), scoped ones marked (%r)" % hs)
    # damaged blocks
    bad = {
        "two blocks": two + S.BEGIN + "\n" + S.END + "\n",
        "begin only": HAND + S.BEGIN + "\nsuppress gen_id 1, sig_id 5\n",
        "end before begin": HAND + S.END + "\n" + S.BEGIN + "\n",
        "foreign line": two.replace(S.END, "suppress gen_id 1, sig_id 7\n" + S.END),
        "edited rule": two.replace("sig_id 2027863\n", "sig_id 2027869\n"),
        "comment without rule": two.replace(S.END, S.META + '{"sid": 9, "scope": "network"}\n' + S.END),
        "bad json": two.replace(S.META + "{", S.META + "{{"),
        "threshold line": two.replace(S.END, "threshold gen_id 1, sig_id 9, type limit\n" + S.END),
    }
    for name, txt in bad.items():
        try:
            _b, block, _a = S.split(txt)
            S.parse_block(block)
            check(False, "damaged block refused: " + name)
        except S.BlockError:
            check(True, "damaged block refused: " + name)
    st_err = None
    d = tempfile.mkdtemp()
    try:
        p = os.path.join(d, "threshold.config")
        open(p, "w").write(bad["foreign line"])
        st_err = S.state(p)
        open(p, "w").write(two)
        st_ok = S.state(p)
    finally:
        shutil.rmtree(d)
    check(st_err["error"] and st_err["entries"] == [] and len(st_err["hand"]) == 5, "state: damage reported, hand SIDs still listed")
    check(not st_ok["error"] and len(st_ok["entries"]) == 2 and st_ok["exists"], "state: entries")
    # validation
    for body, dev, why in (({"sid": "x"}, None, "sid not a number"), ({"sid": 0}, None, "sid 0"),
                           ({"sid": 2 ** 32}, None, "sid too big"), ({"sid": 5, "scope": "all"}, None, "bad scope"),
                           ({"sid": 5, "scope": "device"}, None, "device scope without device"),
                           ({"sid": 5, "scope": "device"}, {"id": "m1", "addrs": ["fe80::1"]}, "no usable address")):
        try:
            S.validate_new(body, 0, "boss", dev)
            check(False, "validate: " + why)
        except ValueError:
            check(True, "validate: " + why)
    check(S.validate_new({"sid": 5, "sig": "x" * 500, "note": "y" * 500}, 0, "boss")["note"] == "y" * S.NOTE_MAX,
          "validate: note/signature truncated")
    import devicewatch as dw
    check(all(p in S.LOW_RISK_PREFIXES for p in dw.SURICATA_IGNORE_PREFIXES),
          "risk flag: every class device monitoring ignores as noise counts as low risk")
    js = open(os.path.join(ROOT, "www", "scripts", "suricata-suppress.js")).read()
    check(all('"%s"' % p in js for p in S.LOW_RISK_PREFIXES), "risk flag: the dialog uses the same prefixes")
    check(not S.risky("ET INFO Observed DNS Query to .biz TLD") and not S.risky("ET POLICY curl UA")
          and S.risky("ET MALWARE Win32/Example CnC") and S.risky("ET ATTACK_RESPONSE id check returned root")
          and S.risky(""), "risk flag: INFO/POLICY low risk, malware/attack-response warned")


class Runner:
    def __init__(self, test_rc=0, test_out="", reload_out='{"message": "done", "return": "OK"}', reload_rc=0,
                 active=True, sysd_rc=0):
        self.calls = []
        self.test_rc, self.test_out, self.reload_out, self.reload_rc = test_rc, test_out, reload_out, reload_rc
        self.active, self.sysd_rc = active, sysd_rc
        self.seen_texts = []

    def __call__(self, cmd, timeout):
        self.calls.append(cmd[:3])
        if cmd[0] == "suricata":
            tf = cmd[cmd.index("--set") + 1].split("=", 1)[1]
            self.seen_texts.append(open(tf).read())
            return self.test_rc, self.test_out
        if cmd[0] == "suricatasc":
            return self.reload_rc, self.reload_out
        if cmd[:2] == ["systemctl", "is-active"]:
            return (0 if self.active else 3), ""
        if cmd[:2] == ["systemctl", "reload"]:
            return self.sysd_rc, ""
        return 127, "unexpected"


def t_apply():
    d = tempfile.mkdtemp()
    try:
        p = os.path.join(d, "threshold.config")
        sock = os.path.join(d, "sock")
        open(sock, "w").close()
        open(p, "w").write(HAND)
        os.chmod(p, 0o640)
        new = S.render(HAND, [entry(2027863)])
        # rejected by suricata -T: nothing written
        r = Runner(test_rc=1, test_out="E: threshold-config: pcre2_match parse error, ret -1, string suppress x\n")
        res = S.apply(new, path=p, run=r, yaml="/x.yaml", socket=sock)
        check(not res["ok"] and res["stage"] == "test" and open(p).read() == HAND and not os.path.exists(p + ".tuxwall.bak")
              and "parse error" in res["message"] and r.seen_texts == [new],
              "apply: rejected test -> file untouched, message from suricata (%r)" % res)
        # ok
        r = Runner()
        res = S.apply(new, path=p, run=r, yaml="/x.yaml", socket=sock)
        check(res["ok"] and res["reloaded"] and open(p).read() == new and open(p + ".tuxwall.bak").read() == HAND
              and os.stat(p).st_mode & 0o777 == 0o640 and ["suricatasc", "-c", "reload-rules"] in r.calls,
              "apply: tested, written (mode kept), backup = previous file, reload-rules")
        check(not [f for f in os.listdir(d) if f.startswith(".threshold.")], "apply: no temp file left")
        # reload fails (suricatasc NOK + systemctl fails) -> restore
        before = open(p).read()
        new2 = S.render(before, [])
        r = Runner(reload_out='{"message": "busy", "return": "NOK"}', sysd_rc=1)
        res = S.apply(new2, path=p, run=r, yaml="/x.yaml", socket=sock)
        check(not res["ok"] and res["stage"] == "reload" and open(p).read() == before and sha(open(p).read()) == sha(before)
              and r.calls.count(["suricatasc", "-c", "reload-rules"]) == 2,
              "apply: failed reload -> previous file restored byte for byte, reloaded again (%r)" % res)
        # suricatasc fails, systemctl reload works
        r = Runner(reload_rc=1, reload_out="")
        res = S.apply(new2, path=p, run=r, yaml="/x.yaml", socket=sock)
        check(res["ok"] and "systemctl" in res["message"] and open(p).read() == HAND, "apply: fallback systemctl reload")
        # no socket -> straight to systemctl
        r = Runner()
        res = S.apply(new, path=p, run=r, yaml="/x.yaml", socket=os.path.join(d, "nosock"))
        check(res["ok"] and ["suricatasc", "-c", "reload-rules"] not in r.calls, "apply: no control socket -> systemctl reload")
        # engine stopped
        r = Runner(active=False)
        res = S.apply(HAND, path=p, run=r, yaml="/x.yaml", socket=sock)
        check(res["ok"] and not res["reloaded"] and open(p).read() == HAND
              and not any(c[0] == "suricatasc" for c in r.calls), "apply: Suricata stopped -> saved, no reload")
        # the message never carries the temp path
        r = Runner(test_rc=1, test_out="")
        res = S.apply(new, path=p, run=r, yaml="/x.yaml", socket=sock)
        check("exit 1" in res["message"] and "/tmp" not in res["message"], "apply: generic test failure message")
    finally:
        shutil.rmtree(d)


def t_real_suricata():
    yaml = "/etc/suricata/suricata.yaml"
    if not (shutil.which("suricata") and os.access(yaml, os.R_OK)):
        print("skip: suricata not installed (real -T check)")
        return
    good = S.render(HAND, [entry(2027863), entry(2027864, "device", ["192.0.2.10", "2001:db8::10"])])
    ok, msg = S.test_text(good, yaml=yaml)
    check(ok, "real suricata -T: our block (network + device scope) accepted (%s)" % msg)
    ok, msg = S.test_text(HAND + "suppress gen_id 1, sig_id abc\n", yaml=yaml)
    check(not ok and "threshold" in msg.lower(), "real suricata -T: bad syntax rejected (%s)" % msg)
    ok, msg = S.test_text("suppress gen_id 1, sig_id 5, track by_either, ip [192.0.2.300]\n", yaml=yaml)
    check(not ok, "real suricata -T: bad address rejected (%s)" % msg)


def t_api():
    import api_harness
    H = api_harness.Harness()
    A = H.mod
    try:
        sc = H.scratch
        S2 = A._ssup
        check(S2 is not None, "API: suricata_suppress module loaded")
        S2.THRESHOLD_FILE = os.path.join(sc, "threshold.config")
        S2.SURICATA_YAML = os.path.join(sc, "suricata.yaml")
        S2.SOCKET = os.path.join(sc, "sock")
        open(S2.SURICATA_YAML, "w").write("%YAML 1.1\n")
        open(S2.SOCKET, "w").close()
        open(S2.THRESHOLD_FILE, "w").write(HAND)
        runner = Runner()
        S2._run = runner
        S2.tempfile.tempdir = sc
        st = os.path.join(sc, "dw-state")
        os.makedirs(st)
        A.DEVICES_STATE_DIR = st
        dev = {"id": "m00005e005301", "name": "phone-a", "mac": "00:00:5e:00:53:01", "type": "phone",
               "ips": ["192.0.2.10", "192.0.2.77"], "ipv6": ["2001:db8::10"], "current_ips": ["192.0.2.10", "2001:db8::10"]}
        with open(st + "/devices.json", "w") as f:
            json.dump({"schema": 1, "generated_at": int(time.time()), "devices": [dev]}, f)
        with open(st + "/findings.json", "w") as f:
            json.dump({"schema": 1, "generated_at": int(time.time()), "findings": []}, f)
        A.SURICATA_EVE_LOG = os.path.join(sc, "eve.json")
        now = time.time()

        def ev(sid, src, dst, age):
            ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(now - age))
            return json.dumps({"timestamp": ts, "event_type": "alert", "src_ip": src, "dest_ip": dst,
                               "alert": {"signature_id": sid, "signature": "ET INFO Observed DNS Query to .biz TLD",
                                         "severity": 3, "category": "Potentially Bad Traffic"}})
        with open(A.SURICATA_EVE_LOG, "w") as f:
            for line in [ev(2027863, "192.0.2.10", "192.0.2.1", 60)] * 5 + [ev(2027863, "192.0.2.20", "192.0.2.1", 60)] * 2 + \
                    [ev(2027863, "192.0.2.10", "192.0.2.1", 90000), ev(2027999, "192.0.2.10", "192.0.2.1", 60)]:
                f.write(line + "\n")

        def wait_job():
            for _ in range(200):
                with A._SUR_SUP_LOCK:
                    if not A._SUR_SUP_JOB.get("running"):
                        return dict(A._SUR_SUP_JOB)
                time.sleep(0.02)
            return None

        U = "/api/security/suricata/suppress"
        check(H.request("GET", U, role=None).status == 401 and H.request("GET", U, role="viewer").status == 403,
              "API GET: 401 without session, 403 for viewers")
        r = H.request("GET", U, role="admin")
        check(r.status == 200 and r.json["entries"] == [] and len(r.json["hand"]) == 5 and not r.json["error"]
              and "192.0.2.50" not in r.body.decode(), "API GET (admin): no managed rules, 5 hand SIDs (no addresses)")
        body = {"action": "add", "sid": 2027863, "sig": "ET INFO Observed DNS Query to .biz TLD", "note": "game ads"}
        check(H.request("POST", U, role="viewer", origin=H.SAME, body=body).status == 403
              and H.request("POST", U, role="admin", origin="https://evil.example.com", body=body).status == 403
              and H.request("POST", U, role=None, origin=H.SAME, body=body).status == 401
              and open(S2.THRESHOLD_FILE).read() == HAND, "API POST: viewer 403, foreign Origin 403, no session 401, file untouched")
        r = H.request("POST", U, role="admin", origin=H.SAME, body=body)
        job = wait_job()
        txt = open(S2.THRESHOLD_FILE).read()
        check(r.status == 202 and job and job["ok"] and txt.startswith(HAND) and "sig_id 2027863\n" in txt,
              "API add network-wide: 202, job ok, block appended (%r)" % (job,))
        r = H.request("GET", U, role="admin")
        e = (r.json.get("entries") or [{}])[0]
        check(e.get("hits_24h") == 7 and e.get("note") == "game ads" and e.get("by") == "boss" and e.get("key") == "2027863:network:"
              and e.get("risky") is False and r.json["job"]["ok"], "API GET: rule listed with 7 hits in 24 h before (%r)" % e)
        r = H.request("POST", U, role="admin", origin=H.SAME, body={"action": "add", "sid": 2027863, "scope": "device",
                                                                     "device": dev["id"]})
        check(r.status == 409 and "network-wide" in r.json["error"], "API: device scope under a network-wide rule -> 409")
        r = H.request("POST", U, role="admin", origin=H.SAME, body={"action": "add", "sid": 2200001})
        check(r.status == 409 and "hand-written" in r.json["error"], "API: SID already suppressed by hand -> 409")
        r = H.request("POST", U, role="admin", origin=H.SAME, body={"action": "add", "sid": 2027999, "scope": "device",
                                                                     "ip": "192.0.2.77", "sig": "ET MALWARE Example"})
        job = wait_job()
        txt = open(S2.THRESHOLD_FILE).read()
        check(r.status == 202 and job["ok"] and "sig_id 2027999, track by_either, ip [192.0.2.10,2001:db8::10,192.0.2.77]" in txt,
              "API add by address: the device's current addresses (+ the alert's address)")
        r = H.request("GET", U, role="admin")
        e2 = [x for x in r.json["entries"] if x["sid"] == 2027999][0]
        check(e2["hits_24h"] == 1 and e2["device"] == dev["id"] and e2["risky"] is True, "API: device rule hits counted on its addresses")
        check(H.request("POST", U, role="admin", origin=H.SAME, body={"action": "add", "sid": 5, "scope": "device",
                                                                       "device": "m000000000000"}).status == 404
              and H.request("POST", U, role="admin", origin=H.SAME, body={"action": "add", "sid": "x"}).status == 400
              and H.request("POST", U, role="admin", origin=H.SAME, body={"action": "wipe"}).status == 400
              and H.request("POST", U, role="admin", origin=H.SAME, body={"action": "remove", "key": "1:network:"}).status == 404,
              "API: unknown device 404, bad sid 400, bad action 400, unknown key 404")
        # one job at a time
        with A._SUR_SUP_LOCK:
            A._SUR_SUP_JOB["running"] = True
        check(H.request("POST", U, role="admin", origin=H.SAME, body={"action": "remove", "key": "2027863:network:"}).status == 409,
              "API: a second change while one is applied -> 409")
        with A._SUR_SUP_LOCK:
            A._SUR_SUP_JOB["running"] = False
        for k in ("2027863:network:", "2027999:device:" + dev["id"]):
            H.request("POST", U, role="admin", origin=H.SAME, body={"action": "remove", "key": k})
            wait_job()
        check(open(S2.THRESHOLD_FILE).read() == HAND, "API remove both -> threshold.config byte-identical to the original")
        # reload failure through the API restores
        runner.reload_out, runner.sysd_rc = '{"return": "NOK"}', 1
        H.request("POST", U, role="admin", origin=H.SAME, body=body)
        job = wait_job()
        check(not job["ok"] and "restored" in job["message"] and open(S2.THRESHOLD_FILE).read() == HAND,
              "API: failed reload -> job not ok, original restored")
        runner.reload_out, runner.sysd_rc = '{"return": "OK"}', 0
        # damaged block -> 409, file untouched
        dmg = HAND + S.BEGIN + "\nsuppress gen_id 1, sig_id 5\n"
        open(S2.THRESHOLD_FILE, "w").write(dmg)
        r = H.request("POST", U, role="admin", origin=H.SAME, body=body)
        check(r.status == 409 and "damaged" in r.json["error"] and open(S2.THRESHOLD_FILE).read() == dmg,
              "API: damaged block -> 409, never rewritten")
        check(H.request("GET", U, role="admin").json["error"], "API GET: damage reported")
    finally:
        H.close()


for t in (t_text, t_apply, t_real_suricata, t_api):
    try:
        t()
    except Exception as exc:
        import traceback
        traceback.print_exc()
        check(False, "%s raised %r" % (t.__name__, exc))
print("suricata_suppress_check: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
