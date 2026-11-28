#!/usr/bin/env python3
"""Suricata rule suppression from the dashboard (TuxWall 3.3.7).

The owner's /etc/suricata/threshold.config may hold hand-written lines;
TuxWall only ever writes its own marker block, appended at the end:

    # >>> TuxWall managed suppressions (Security > Sensors) - edit them in the dashboard >>>
    # tuxwall: {"sid": 2027863, "scope": "network", "sig": "...", "note": "", "at": 0, "by": "admin", "hits_24h": 0}
    suppress gen_id 1, sig_id 2027863
    # <<< TuxWall managed suppressions <<<

Every managed rule is a metadata comment + one suppress line (network-wide:
`suppress gen_id 1, sig_id N`; one device: `..., track by_either, ip [a,b]`
with the device's current addresses, so alerts where the device is source
or destination are both covered). Lines outside the block are never
changed: removing the last managed rule removes the block and leaves the
file byte-identical to before (a missing final newline is the only thing
ever added). A damaged block (begin without end, two blocks, unknown lines
inside) is refused, never "repaired".

apply(): backup -> `suricata -T` with the new file as threshold-file and an
empty rule file (validates the threshold syntax in well under a second) ->
atomic write -> `suricatasc -c reload-rules` (fallback `systemctl reload
suricata`) -> on a failed reload the backup is restored and reloaded.
Pure functions take text; the runner is injectable for tests.
"""
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

THRESHOLD_FILE = "/etc/suricata/threshold.config"
SURICATA_YAML = "/etc/suricata/suricata.yaml"
SOCKET = "/var/run/suricata/suricata-command.socket"
BEGIN = "# >>> TuxWall managed suppressions (Security > Sensors) - edit them in the dashboard >>>"
END = "# <<< TuxWall managed suppressions <<<"
META = "# tuxwall: "
MAX_RULES = 200
MAX_ADDRS = 16
NOTE_MAX = 200
SIG_MAX = 160
SCOPES = ("network", "device")
TEST_TIMEOUT = 90
RELOAD_TIMEOUT = 240
# signatures that are normally safe to silence (the classes device monitoring
# ignores as noise: devicewatch.SURICATA_IGNORE_PREFIXES, plus GPL INFO);
# anything else (ET MALWARE / TROJAN / EXPLOIT / ATTACK_RESPONSE ...) gets a warning
LOW_RISK_PREFIXES = ("SURICATA ", "ET INFO", "ET POLICY", "ET SCAN", "ET HUNTING", "ET DNS ", "ET GAMES", "ET CHAT",
                     "ET P2P", "ET USER_AGENTS", "GPL ICMP", "ET DROP", "ET CINS", "ET DSHIELD", "ET COMPROMISED",
                     "ET TOR", "ET 3CORESEC", "GPL SCAN", "GPL POLICY", "ET VOIP", "GPL INFO")
_HAND_RE = re.compile(r"^\s*suppress\s+gen_id\s+(\d+)\s*,\s*sig_id\s+(\d+)\s*(,.*)?$")
_LINE_RE = re.compile(r"^suppress gen_id 1, sig_id (\d{1,10})(?:, track by_either, ip \[([0-9A-Fa-f:.,/]+)\])?$")


class BlockError(ValueError):
    """The managed block is damaged: refuse to write."""


def risky(sig):
    """True for a signature that is not INFO/POLICY-like (warn before suppressing)."""
    return not str(sig or "").upper().startswith(LOW_RISK_PREFIXES)


def _clean(s, n):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(s or "")).strip()[:n]


def _addr_list(addrs):
    out = []
    for a in addrs or []:
        try:
            ip = ipaddress.ip_address(str(a).strip().split("/")[0].split("%")[0])
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or (ip.version == 6 and ip.is_link_local):
            continue
        s = str(ip)
        if s not in out:
            out.append(s)
    return out[:MAX_ADDRS]


def split(text):
    """-> (before, block lines or None, after). Raises BlockError."""
    lines = text.split("\n")
    b = [i for i, l in enumerate(lines) if l.strip() == BEGIN]
    e = [i for i, l in enumerate(lines) if l.strip() == END]
    if not b and not e:
        return text, None, ""
    if len(b) != 1 or len(e) != 1 or e[0] < b[0]:
        raise BlockError("the TuxWall block in threshold.config is damaged (markers missing or doubled)")
    before = "\n".join(lines[:b[0]]) + ("\n" if b[0] else "")
    after = "\n".join(lines[e[0] + 1:])
    return before, lines[b[0] + 1:e[0]], after


def parse_block(block):
    """Managed block lines -> [entry]. Raises BlockError on anything foreign."""
    out = []
    meta = None
    for raw in block or []:
        line = raw.strip()
        if not line:
            continue
        if line.startswith(META):
            if meta is not None:
                raise BlockError("the TuxWall block in threshold.config is damaged (comment without a rule)")
            try:
                meta = json.loads(line[len(META):])
            except ValueError:
                raise BlockError("the TuxWall block in threshold.config is damaged (unreadable comment)")
            if not isinstance(meta, dict):
                raise BlockError("the TuxWall block in threshold.config is damaged (unreadable comment)")
            continue
        m = _LINE_RE.match(line)
        if not m or meta is None:
            raise BlockError("the TuxWall block in threshold.config holds a line TuxWall did not write")
        sid = int(m.group(1))
        addrs = m.group(2).split(",") if m.group(2) else []
        scope = "device" if addrs else "network"
        if meta.get("sid") != sid or meta.get("scope") != scope:
            raise BlockError("the TuxWall block in threshold.config was edited (comment and rule disagree)")
        out.append({"sid": sid, "scope": scope, "addrs": addrs, "sig": _clean(meta.get("sig"), SIG_MAX),
                    "category": _clean(meta.get("category"), 80), "device": _clean(meta.get("device"), 20),
                    "device_name": _clean(meta.get("device_name"), 64), "note": _clean(meta.get("note"), NOTE_MAX),
                    "at": int(meta.get("at") or 0), "by": _clean(meta.get("by"), 64),
                    "hits_24h": int(meta.get("hits_24h") or 0)})
        meta = None
    if meta is not None:
        raise BlockError("the TuxWall block in threshold.config is damaged (comment without a rule)")
    return out


def hand_sids(text):
    """SIDs suppressed outside the managed block (read-only for the UI):
    [{"sid", "scoped"}] - scoped = limited to addresses (track ...)."""
    before, _block, after = split(text)
    out = []
    for line in (before + "\n" + after).split("\n"):
        m = _HAND_RE.match(line)
        if m and m.group(1) == "1":
            out.append({"sid": int(m.group(2)), "scoped": bool(m.group(3))})
    return out


def render_entry(e):
    meta = {k: e.get(k) for k in ("sid", "scope", "sig", "category", "device", "device_name", "note", "at", "by",
                                  "hits_24h")}
    line = "suppress gen_id 1, sig_id %d" % e["sid"]
    if e["scope"] == "device":
        line += ", track by_either, ip [%s]" % ",".join(e["addrs"])
    return [META + json.dumps(meta, sort_keys=True, ensure_ascii=True), line]


def render(text, entries):
    """New file text: the outside untouched, the block rebuilt (or removed)."""
    before, _block, after = split(text)
    outside = before + after
    if not entries:
        return outside
    if outside and not outside.endswith("\n"):
        outside += "\n"
    body = [BEGIN]
    for e in entries:
        body += render_entry(e)
    body.append(END)
    return outside + "\n".join(body) + "\n"


def validate_new(body, now, by, device=None):
    """Request body -> entry (ValueError on bad input). device: the
    inventory record for scope "device" ({id, name, addrs})."""
    try:
        sid = int(body.get("sid"))
    except (TypeError, ValueError):
        raise ValueError("sid must be a number")
    if not 1 <= sid <= 4294967295:
        raise ValueError("sid out of range")
    scope = body.get("scope") or "network"
    if scope not in SCOPES:
        raise ValueError("scope must be network or device")
    e = {"sid": sid, "scope": scope, "addrs": [], "sig": _clean(body.get("sig"), SIG_MAX),
         "category": _clean(body.get("category"), 80), "device": "", "device_name": "",
         "note": _clean(body.get("note"), NOTE_MAX), "at": int(now), "by": _clean(by, 64),
         "hits_24h": max(0, int(body.get("hits_24h") or 0))}
    if scope == "device":
        if not device:
            raise ValueError("unknown device")
        addrs = _addr_list(device.get("addrs"))
        if not addrs:
            raise ValueError("this device has no current address to match")
        e.update(addrs=addrs, device=_clean(device.get("id"), 20), device_name=_clean(device.get("name"), 64))
    return e


def merge(entries, new):
    """Add or replace (same sid + scope + device) -> new list."""
    keep = [x for x in entries if not (x["sid"] == new["sid"] and x["scope"] == new["scope"]
                                       and x.get("device", "") == new.get("device", ""))]
    if len(keep) >= MAX_RULES:
        raise ValueError("too many suppressed rules (max %d)" % MAX_RULES)
    return keep + [new]


def entry_key(e):
    return "%d:%s:%s" % (e["sid"], e["scope"], e.get("device") or "")


# ── applying ─────────────────────────────────────────────────────────────────

def _run(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return None, "timed out"
    except OSError as exc:
        return 127, exc.__class__.__name__


def test_text(text, run=None, yaml=None):
    """(ok, message): `suricata -T` with `text` as the threshold file and no
    rules (only the threshold syntax and addresses are checked)."""
    run, yaml = run or _run, yaml or SURICATA_YAML
    d = tempfile.mkdtemp(prefix="tw-sur-")
    try:
        tf = os.path.join(d, "threshold.config")
        rf = os.path.join(d, "empty.rules")
        with open(tf, "w", encoding="utf-8") as f:
            f.write(text)
        open(rf, "w").close()
        rc, out = run(["suricata", "-T", "-c", yaml, "--set", "threshold-file=" + tf, "-S", rf, "-l", d],
                      TEST_TIMEOUT)
        errs = [l.strip() for l in out.splitlines() if "threshold" in l.lower() and
                (l.startswith("E:") or "<Error>" in l or "Error loading" in l)]
        if rc == 0 and not errs:
            return True, "ok"
        return False, (errs[0] if errs else "suricata -T failed (exit %s)" % rc)[:240].replace(tf, "threshold.config")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def reload_engine(run=None, socket=None):
    """(ok, how): reload rules + thresholds in the running engine."""
    run, socket = run or _run, socket or SOCKET
    if os.path.exists(socket):
        rc, out = run(["suricatasc", "-c", "reload-rules", socket], RELOAD_TIMEOUT)
        try:
            ok = rc == 0 and json.loads(out.strip().splitlines()[-1]).get("return") == "OK"
        except (ValueError, IndexError, AttributeError):
            ok = False
        if ok:
            return True, "suricatasc reload-rules"
    rc, _out = run(["systemctl", "reload", "suricata"], RELOAD_TIMEOUT)
    return rc == 0, "systemctl reload suricata"


def engine_running(run=None):
    rc, _out = (run or _run)(["systemctl", "is-active", "--quiet", "suricata"], 15)
    return rc == 0


def _write_atomic(path, text, like=None):
    st = os.stat(like or path) if os.path.exists(like or path) else None
    fd, tmp = tempfile.mkstemp(prefix=".threshold.", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, (st.st_mode & 0o7777) if st else 0o644)
        if st:
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def apply(new_text, path=None, run=None, yaml=None, socket=None):
    """Test, back up, write, reload; restore on a failed reload.
    -> {"ok", "stage", "message", "reloaded"}."""
    path = path or THRESHOLD_FILE
    ok, msg = test_text(new_text, run=run, yaml=yaml)
    if not ok:
        return {"ok": False, "stage": "test", "message": "Suricata rejected the change: " + msg, "reloaded": False}
    backup = path + ".tuxwall.bak"
    existed = os.path.exists(path)
    if existed:
        shutil.copy2(path, backup)
    _write_atomic(path, new_text, like=path if existed else None)
    if not engine_running(run=run):
        return {"ok": True, "stage": "saved", "reloaded": False,
                "message": "Saved - Suricata is not running; it applies at the next start"}
    ok, how = reload_engine(run=run, socket=socket)
    if ok:
        return {"ok": True, "stage": "reloaded", "reloaded": True, "message": "Applied (%s)" % how}
    if existed:
        _write_atomic(path, open(backup, encoding="utf-8").read(), like=backup)
    else:
        os.unlink(path)
    reload_engine(run=run, socket=socket)
    return {"ok": False, "stage": "reload", "reloaded": False,
            "message": "Suricata did not reload (%s) - the previous threshold.config was restored" % how}


def read(path=None):
    path = path or THRESHOLD_FILE
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def state(path=None):
    """GET view: managed entries, hand-written SIDs, damage."""
    path = path or THRESHOLD_FILE
    exists = os.path.exists(path)
    text = read(path)
    try:
        _b, block, _a = split(text)
        entries = parse_block(block)
        err = ""
    except BlockError as exc:
        entries, err = [], str(exc)
    try:
        hand = hand_sids(text)
    except BlockError:
        hand = []
    return {"exists": exists, "entries": entries, "hand": hand, "error": err, "checked": int(time.time())}
