#!/usr/bin/env python3
"""Custom banlist sync checks (www/includes/api_server.py), sandboxed:

  python3 tools/custom_blocklist_check.py

The banlist file is remapped into a temp dir and subprocess.run is a fake
CrowdSec (cscli decisions list/import/delete/add answered from an
in-memory decision table, systemctl recorded) - nothing touches the host.

Covers the idempotent apply that replaced the engine's file re-read on
every crowdsec start: parsing the file (comments, invalid and non-global
lines, duplicates, unreadable file), reading live bans (longest per
value, expired/other-scenario/non-ban ignored), the pure diff (add,
refresh after 20 days, remove, protected CDN ranges never auto-banned,
IPv6 notation), the mass-removal guard, dry-run (no cscli writes), one
import for all adds, exact-value deletes, a second sync being a no-op,
the dashboard add of an already-active entry not duplicating its ban,
and the remove flow re-syncing collateral range lifts.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT_DIR, "www", "includes", "api_server.py")
sys.dont_write_bytecode = True

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


spec = importlib.util.spec_from_file_location("api_server_cslist", TARGET)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)

TMP = tempfile.mkdtemp(prefix="cslist-check-")
A.CUSTOM_BLOCKLIST_FILE = os.path.join(TMP, "custom-blocklist.txt")
A.CROWDSEC_BIN = "/fake/cscli"
YEAR = A.CUSTOM_BLOCKLIST_DURATION_SECONDS
REASON = A.CUSTOM_BLOCKLIST_REASON


def go_dur(seconds):
    """Go time.Duration.String() style: sign once, no zero leading units."""
    sign = "-" if seconds < 0 else ""
    seconds = abs(int(seconds))
    h, m, s = seconds // 3600, seconds % 3600 // 60, seconds % 60
    if h:
        return "%s%dh%dm%ds" % (sign, h, m, s)
    if m:
        return "%s%dm%ds" % (sign, m, s)
    return "%s%ds" % (sign, s)


class FakeCrowdSec:
    """Decision table {id: dict}; answers the cscli calls the sync makes."""

    def __init__(self):
        self.decisions = {}
        self.next_id = 100
        self.calls = []
        self.fail_list = False

    def ban(self, value, remaining, scenario=REASON, dtype="ban", scope="Ip"):
        self.next_id += 1
        self.decisions[self.next_id] = {"id": self.next_id, "value": value, "scope": scope,
                                        "scenario": scenario, "type": dtype,
                                        "origin": "cscli", "remaining": remaining}

    def active(self, scenario=REASON):
        return [d for d in self.decisions.values()
                if d["scenario"] == scenario and d["remaining"] > 0]

    def run(self, args, **kw):
        self.calls.append((list(args), kw.get("input")))
        if args[0] == "systemctl":
            return Proc(0, "")
        assert args[0] == A.CROWDSEC_BIN, args
        sub = args[1:3]
        if sub == ["decisions", "list"]:
            if self.fail_list:
                return Proc(1, "", "LAPI unreachable")
            scen = args[args.index("-s") + 1]
            rows = [d for d in self.decisions.values() if d["scenario"] == scen]
            if not rows:
                return Proc(0, "null")
            alerts = [{"id": 1, "scenario": "x", "decisions": [
                {"id": d["id"], "value": d["value"], "scope": d["scope"], "scenario": d["scenario"],
                 "type": d["type"], "origin": d["origin"], "duration": go_dur(d["remaining"])}
                for d in rows]}]
            return Proc(0, json.dumps(alerts))
        if sub == ["decisions", "import"]:
            for item in json.loads(kw["input"]):
                assert item["reason"] == REASON and item["duration"] == "8760h", item
                assert item["scope"] in ("Ip", "Range"), item
                self.ban(item["value"], YEAR, scope=item["scope"])
            return Proc(0, "Imported")
        if sub == ["decisions", "delete"]:
            value = args[args.index("-v") + 1] if "-v" in args else None
            scen = args[args.index("-s") + 1] if "-s" in args else None
            ip = args[args.index("--ip") + 1] if "--ip" in args else None
            for d in self.decisions.values():
                if (value and d["value"] == value and d["scenario"] == scen) or \
                        (ip and d["value"] == ip):
                    d["remaining"] = -1
            return Proc(0, "deleted")
        if sub == ["decisions", "add"]:
            self.ban(args[args.index("--ip") + 1], YEAR)
            return Proc(0, "added")
        raise AssertionError("unexpected cscli call %r" % (args,))

    def writes(self):
        return [c for c, _ in self.calls
                if c[0] == A.CROWDSEC_BIN and c[2] in ("import", "delete", "add")]


class Proc:
    def __init__(self, rc, out, err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def write_file(*lines):
    with open(A.CUSTOM_BLOCKLIST_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def install(fake):
    A.subprocess.run = fake.run


FW_SYNCS = []
A._crowdsec_fw_sync_async = lambda delay=0: FW_SYNCS.append(delay)


try:
    # --- file parsing -------------------------------------------------------
    write_file("# comment", "", "  1.2.3.4  ", "1.2.3.4", "192.168.1.5", "not-an-ip",
               "5.6.7.0/24", "2a01:04f8::1", "1.2.3.4 # inline")
    entries, invalid, readable = A._custom_blocklist_file_entries()
    check(readable, "file readable")
    check([e["value"] for e in entries] == ["1.2.3.4", "5.6.7.0/24", "2a01:4f8::1"],
          "entries normalized, deduped, in order: %r" % entries)
    check(invalid == ["192.168.1.5", "not-an-ip", "1.2.3.4 # inline"],
          "non-global / bad / inline-comment lines reported: %r" % invalid)
    os.unlink(A.CUSTOM_BLOCKLIST_FILE)
    check(A._custom_blocklist_file_entries() == ([], [], False), "missing file -> unreadable")

    # --- live bans: longest per value --------------------------------------
    cur = A._custom_blocklist_current_from([
        {"decisions": [
            {"value": "1.2.3.4", "scenario": REASON, "type": "ban", "duration": "100h", "id": 1},
            {"value": "1.2.3.4", "scenario": REASON, "type": "ban", "duration": "8000h", "id": 2},
            {"value": "9.9.9.9", "scenario": REASON, "type": "ban", "duration": "-4s", "id": 3},
            {"value": "9.9.9.8", "scenario": REASON, "type": "ban", "duration": "-0h0m1s", "id": 6},
            {"value": "8.8.4.4", "scenario": "honeypot/tuxwall", "type": "ban", "duration": "9h", "id": 4},
            {"value": "7.7.7.7", "scenario": REASON, "type": "captcha", "duration": "9h", "id": 5},
        ]}, {"decisions": None}, "junk"])
    check(list(cur) == ["1.2.3.4"] and cur["1.2.3.4"]["id"] == 2,
          "longest active custom ban only: %r" % cur)

    # --- pure plan ---------------------------------------------------------
    def P(v):
        return A._parse_blocklist_entry(v)[0]
    current = {
        "1.1.1.10": {"value": "1.1.1.10", "remaining": YEAR - 3600},           # fresh
        "2.2.2.2": {"value": "2.2.2.2", "remaining": YEAR - 25 * 86400},       # aging
        "3.3.3.3": {"value": "3.3.3.3", "remaining": 5000},                     # unlisted
        "2a01:4f8::1": {"value": "2a01:4f8::1", "remaining": YEAR - 60},        # v6 notation
    }
    plan = A._custom_blocklist_plan(
        [P("1.1.1.10"), P("2.2.2.2"), P("4.4.4.4"), P("2a01:04f8::1"), P("104.23.172.128"),
         P("104.16.0.0/12")], current)
    check([p["value"] for p in plan["add"]] == ["4.4.4.4"], "add: %r" % plan["add"])
    check([p["value"] for p in plan["refresh"]] == ["2.2.2.2"], "refresh: %r" % plan["refresh"])
    check([c["value"] for c in plan["remove"]] == ["3.3.3.3"], "remove: %r" % plan["remove"])
    check([p["value"] for p in plan["protected"]] == ["104.23.172.128", "104.16.0.0/12"],
          "CDN IP and overlapping range are protected: %r" % plan["protected"])

    # --- mass-removal guard -------------------------------------------------
    check(A._custom_blocklist_removal_guard(1, 300, True) is None, "small removal allowed")
    check(A._custom_blocklist_removal_guard(11, 20, True), "mass removal held")
    check(A._custom_blocklist_removal_guard(1, 3, False), "unreadable file holds removals")

    # --- sync against a fake CrowdSec ---------------------------------------
    fake = FakeCrowdSec()
    install(fake)
    fake.ban("1.1.1.10", YEAR - 3600)
    fake.ban("1.1.1.10", YEAR - 7200)            # duplicate, shorter
    fake.ban("2.2.2.2", YEAR - 25 * 86400)
    fake.ban("3.3.3.3", 5000)
    fake.ban("5.6.7.0/24", YEAR - 10, scope="Range")
    fake.ban("8.8.4.4", 9000, scenario="honeypot/tuxwall")
    write_file("1.1.1.10", "2.2.2.2", "4.4.4.4", "5.6.7.0/24", "104.23.172.128", "6.6.6.0/24")

    res = A.sync_custom_blocklist(dry_run=True)
    check(res["ok"] and res["add"] == ["4.4.4.4", "6.6.6.0/24"] and res["refresh"] == ["2.2.2.2"]
          and res["remove"] == ["3.3.3.3"] and res["protected"] == ["104.23.172.128"],
          "dry-run diff: %r" % res)
    check(fake.writes() == [], "dry-run makes no cscli writes: %r" % fake.writes())
    check(FW_SYNCS == [], "dry-run does not trigger the nft reconcile")

    fake.calls.clear()
    res = A.sync_custom_blocklist()
    check(res["ok"] and not res["failed"], "sync ok: %r" % res)
    check(len(FW_SYNCS) == 1, "a sync with changes triggers one nft reconcile (Range bans)")
    imports = [(c, i) for c, i in fake.calls if c[2:3] == ["import"]]
    check(len(imports) == 1, "one import for all adds + refreshes")
    payload = json.loads(imports[0][1]) if imports else []
    check(sorted((p["value"], p["scope"]) for p in payload)
          == [("2.2.2.2", "Ip"), ("4.4.4.4", "Ip"), ("6.6.6.0/24", "Range")],
          "import payload: %r" % payload)
    deletes = [c for c, _ in fake.calls if c[2:3] == ["delete"]]
    check(deletes == [[A.CROWDSEC_BIN, "decisions", "delete", "-v", "3.3.3.3", "-s", REASON]],
          "exact value+scenario delete: %r" % deletes)
    check(["systemctl", "start", "--no-block", "crowdsec-dedupe.service"]
          in [c for c, _ in fake.calls], "dedupe started after a refresh")
    check(any(d["value"] == "8.8.4.4" and d["remaining"] > 0 for d in fake.decisions.values()),
          "other scenarios untouched")

    fake.calls.clear()
    res = A.sync_custom_blocklist()
    check(res["add"] == [] and res["refresh"] == [] and res["remove"] == [],
          "second sync is a no-op: %r" % res)
    check(fake.writes() == [], "second sync makes no cscli writes")
    check(len(FW_SYNCS) == 1, "a no-op sync does not trigger the nft reconcile")
    values = sorted(d["value"] for d in fake.active())
    check(values == ["1.1.1.10", "1.1.1.10", "2.2.2.2", "2.2.2.2", "4.4.4.4", "5.6.7.0/24",
                     "6.6.6.0/24"], "final custom bans (dupes left for crowdsec-dedupe): %r" % values)

    # mass removal held back: file truncated to one line
    write_file("1.1.1.10")
    fake.calls.clear()
    for i in range(20):
        fake.ban("10.%d.0.1" % i, YEAR)   # non-global values never parse, still counted live
    res = A.sync_custom_blocklist()
    check(res["remove_held"] and fake.writes() == [], "mass removal held: %r" % res["remove_held"])

    # CrowdSec down: no guess, no writes
    fake.fail_list = True
    fake.calls.clear()
    res = A.sync_custom_blocklist()
    check(not res["ok"] and fake.writes() == [], "cscli failure -> not ok, no writes")
    fake.fail_list = False

    # --- dashboard add/remove ----------------------------------------------
    fake = FakeCrowdSec()
    install(fake)
    fake.ban("1.1.1.10", YEAR - 3600)
    write_file("1.1.1.10")
    res = A.add_custom_blocklist_entry("1.1.1.10")
    check(res["ok"] and "active" in res["message"] and fake.writes() == [],
          "re-adding an active entry does not duplicate its ban: %r" % res)
    fake.decisions.clear()
    res = A.add_custom_blocklist_entry("1.1.1.10")
    check(res["ok"] and "re-applied" in res["message"] and len(fake.active()) == 1,
          "re-adding a lapsed entry re-applies it once: %r" % res)
    res = A.add_custom_blocklist_entry("9.8.7.6")
    with open(A.CUSTOM_BLOCKLIST_FILE) as fh:
        listed = fh.read().split()
    check(res["ok"] and "9.8.7.6" in listed and any(d["value"] == "9.8.7.6" for d in fake.active()),
          "new entry: appended + banned: %r" % res)
    check(not A.add_custom_blocklist_entry("10.0.0.1")["ok"], "private entry refused")

    synced = []
    A._custom_blocklist_sync_async = lambda: synced.append(1)
    res = A.remove_custom_blocklist_entry("9.8.7.6")
    with open(A.CUSTOM_BLOCKLIST_FILE) as fh:
        listed = fh.read().split()
    check(res["ok"] and "9.8.7.6" not in listed
          and not any(d["value"] == "9.8.7.6" for d in fake.active()),
          "remove: dropped from file + unbanned: %r" % res)
    check(synced == [1], "remove triggers a re-sync (collateral range lifts)")
finally:
    shutil.rmtree(TMP, ignore_errors=True)

print("custom_blocklist_check: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
