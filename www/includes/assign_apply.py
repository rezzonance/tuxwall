"""TuxWall interface assignments: apply / confirm / rollback.

apply() re-renders the plan the admin reviewed (its plan_hash must match),
snapshots every target file, writes the files in apply order, runs the
service actions in order and starts a confirm window (60 s by default).
Without /confirm in time the snapshot is restored and the services are
reloaded again. Every step goes to /var/lib/tuxwall/assign-history.jsonl.

Locked by default: while /etc/tuxwall/interfaces.json does not say
"apply_locked": false, apply() returns 423 before it touches anything.
Only a root edit of that file unlocks it; nothing here changes the flag.

root= and runner= exist for tests: root prefixes every path (sandbox
tree) and runner(cmd) -> (rc, output) replaces subprocess.
"""
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid

import topology as T
import assign_plan as P

STATE_DIR = "/var/lib/tuxwall"
HISTORY = STATE_DIR + "/assign-history.jsonl"
SNAP_DIR = STATE_DIR + "/assign-snapshots"
CONFIRM_S = 60

_lock = threading.Lock()
_pending = {}  # id -> {root, snap, actions, after_reboot, expires, timer, user}


def _default_runner(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as exc:
        return 1, str(exc)


def is_locked(root=""):
    rec = T._read_json((root or "") + T.CONF)
    return not (isinstance(rec, dict) and rec.get("apply_locked") is False)


def locked_response():
    return 423, {"ok": False, "locked": True, "apply_locked": True, "error": P.LOCK_MESSAGE}


def _audit(root, entry):
    entry = dict(entry, at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    path = (root or "") + HISTORY
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        pass


def _write(path, text, mode):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tuxwall-assign.", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _snapshot(root, aid, paths, runner):
    """Copy every target file (or remember it was absent) plus firewall state."""
    sdir = (root or "") + SNAP_DIR + "/" + aid
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    manifest = []
    for k, path in enumerate(paths):
        full = (root or "") + path
        e = {"path": path, "existed": os.path.exists(full)}
        if e["existed"]:
            st = os.stat(full)
            e.update(copy="f%03d" % k, mode=st.st_mode & 0o7777, uid=st.st_uid, gid=st.st_gid)
            shutil.copy2(full, os.path.join(sdir, e["copy"]))
        manifest.append(e)
    fw = {}
    for name, cmd in (("ufw_status", ["ufw", "status", "numbered"]), ("iptables_save", ["iptables-save"]),
                      ("ip6tables_save", ["ip6tables-save"])):
        rc, out = runner(cmd)
        fw[name] = out if rc == 0 else ""
    with open(os.path.join(sdir, "firewall.json"), "w") as f:
        json.dump(fw, f)
    with open(os.path.join(sdir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    return sdir, manifest


def _restore(root, sdir, manifest):
    errors = []
    for e in manifest:
        full = (root or "") + e["path"]
        try:
            if e["existed"]:
                shutil.copy2(os.path.join(sdir, e["copy"]), full)
                os.chmod(full, e["mode"])
                try:
                    os.chown(full, e["uid"], e["gid"])
                except OSError:
                    pass
            elif os.path.exists(full):
                os.unlink(full)
        except OSError as exc:
            errors.append("%s: %s" % (e["path"], exc))
    return errors


def _run_actions(acts, runner, undo=False):
    log = []
    seq = acts
    if undo:
        # restore order: undo raw-rule removals, then reload every service again
        seq = [{"step": a["step"], "cmd": a["undo"]} for a in acts if a.get("undo")] + \
              [a for a in acts if not a.get("undo")]
    for a in seq:
        rc, out = runner(a["cmd"])
        log.append({"step": a["step"], "cmd": " ".join(a["cmd"]), "rc": rc, "output": (out or "")[-400:]})
        if rc != 0 and not undo:
            return log, False
    return log, True


def pending():
    with _lock:
        return [{"id": k, "expires_in": max(0, int(v["expires"] - time.time())) if v["expires"] else None,
                 "after_reboot": v["after_reboot"], "user": v["user"]} for k, v in _pending.items()]


def apply(body, session_ip="", user="", root="", runner=None, schedule=None, ttl=CONFIRM_S, raw=None):
    """Returns (http_status, payload)."""
    if is_locked(root):
        return locked_response()
    runner = runner or _default_runner
    body = body if isinstance(body, dict) else {}
    with _lock:
        if _pending:
            return 409, {"ok": False, "error": "Another interface change is waiting for confirmation.",
                         "pending": list(_pending)}
        ctx = P.Ctx(root=root, raw=raw, validate=False)
        res = P.build(body, session_ip, ctx)
        if not res.validation["ok"] or res.errors:
            return 400, {"ok": False, "error": "; ".join(res.validation["errors"] + res.errors)}
        if not res.files and not res.extra_actions:
            return 400, {"ok": False, "error": "Nothing to apply."}
        h = P.plan_hash(res)
        if body.get("plan_hash") != h:
            return 409, {"ok": False, "error": "The plan changed since it was reviewed; review it again.",
                         "plan_hash": h}
        if res.lockout and not body.get("ack_lockout"):
            return 409, {"ok": False, "lockout": True, "warnings": res.warnings,
                         "error": "This change affects the network you are connected through; confirm the warning first."}
        after_reboot = bool(body.get("after_reboot"))
        aid = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        ordered = P._ordered(res)
        sdir, manifest = _snapshot(root, aid, [p for p, _ in ordered], runner)
        acts = P.actions(res)
        _audit(root, {"event": "apply-start", "id": aid, "user": user, "ip": session_ip, "hash": h,
                      "files": [p for p, _ in ordered], "after_reboot": after_reboot})
        log = []
        try:
            for path, f in ordered:
                full = (root or "") + path
                if f["new"] is None:
                    if os.path.exists(full):
                        os.unlink(full)
                else:
                    _write(full, f["new"], f["mode"])
                log.append({"step": f["step"], "write": path})
            ok = True
            if not after_reboot:
                alog, ok = _run_actions(acts, runner)
                log += alog
            if not ok:
                raise RuntimeError("step '%s' failed: %s" % (log[-1]["step"], log[-1]["output"]))
        except Exception as exc:
            errs = _restore(root, sdir, manifest)
            ulog, _ = ([], True) if after_reboot else _run_actions(acts, runner, undo=True)
            _audit(root, {"event": "apply-failed-rolled-back", "id": aid, "error": str(exc),
                          "restore_errors": errs})
            return 500, {"ok": False, "error": "Apply failed and was rolled back: %s" % exc,
                         "log": log, "rollback_log": ulog, "restore_errors": errs}
        _pending[aid] = {"root": root, "sdir": sdir, "manifest": manifest, "actions": acts,
                         "after_reboot": after_reboot, "user": user, "runner": runner,
                         "expires": None if after_reboot else time.time() + ttl}
    if not after_reboot:
        if schedule:
            schedule(aid, ttl)
        else:
            t = threading.Timer(ttl, rollback, args=(aid, "timeout"))
            t.daemon = True
            _pending[aid]["timer"] = t
            t.start()
    _audit(root, {"event": "apply-done", "id": aid, "log": log})
    return 200, {"ok": True, "id": aid, "after_reboot": after_reboot, "log": log, "warnings": res.warnings,
                 "confirm_within_s": None if after_reboot else ttl,
                 "message": ("Files written; they take effect at the next reboot. Use Roll back to undo before "
                             "rebooting.") if after_reboot else
                 ("Applied. Confirm within %d s or everything is rolled back." % ttl)}


def confirm(aid, root=""):
    with _lock:
        p = _pending.pop(aid, None)
    if not p:
        return 404, {"ok": False, "error": "No pending interface change with that id (it may have rolled back)."}
    if p.get("timer"):
        p["timer"].cancel()
    _audit(p["root"], {"event": "confirmed", "id": aid})
    return 200, {"ok": True, "id": aid, "confirmed": True}


def rollback(aid=None, reason="manual", root=None):
    with _lock:
        if aid is None and _pending:
            aid = next(iter(_pending))
        p = _pending.pop(aid, None) if aid else None
    if not p:
        return 404, {"ok": False, "error": "Nothing to roll back."}
    if p.get("timer"):
        p["timer"].cancel()
    errs = _restore(p["root"], p["sdir"], p["manifest"])
    log, _ = ([], True) if p["after_reboot"] else _run_actions(p["actions"], p["runner"], undo=True)
    _audit(p["root"], {"event": "rolled-back", "id": aid, "reason": reason, "restore_errors": errs, "log": log})
    if reason == "timeout":
        print("[assign] ASSIGN-CONFIRM-EXPIRED: rolled back %s (no confirmation)" % aid, flush=True)
    return 200, {"ok": not errs, "id": aid, "rolled_back": True, "restore_errors": errs, "log": log}
