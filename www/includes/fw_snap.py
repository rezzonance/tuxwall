"""TuxWall firewall snapshot history: capture, list, diff, guarded restore,
download/upload and the legacy raw baseline (import only, never restored).

Snapshots live in <root>/var/lib/tuxwall/fw-snapshots/<id>/ (dir 700, files 600):
  meta.json, ufw files (user/user6/before/before6/after/after6 .rules),
  ufw.default (/etc/default/ufw), sysctl.conf (/etc/ufw/sysctl.conf), and
  iptables.save / ip6tables.save (reference and diff only, never restored).

Restore writes the ufw files of the snapshot, but managed rules always come
from the CURRENT state (classified by fw_guard), so a restore never rolls back
the honeypot/canary/tripwire/policy/WireGuard/NAT rules; then `ufw reload`,
re-applies raw owned rules through hooks, and arms a confirm-or-revert timer.
All I/O goes through fw_guard.Ctx (root + runner) so tests run in a temp root.
"""
import base64
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import threading
import time
import uuid

import fw_guard as G

SNAP_DIR = "/var/lib/tuxwall/fw-snapshots"
LEGACY_DIR = "/etc/tuxwall/fw-baseline"
UFW_FILES = {
    "user.rules": "/etc/ufw/user.rules",
    "user6.rules": "/etc/ufw/user6.rules",
    "before.rules": "/etc/ufw/before.rules",
    "before6.rules": "/etc/ufw/before6.rules",
    "after.rules": "/etc/ufw/after.rules",
    "after6.rules": "/etc/ufw/after6.rules",
    "ufw.default": "/etc/default/ufw",
    "sysctl.conf": "/etc/ufw/sysctl.conf",
}
RAW_FILES = {"iptables.save": "iptables-save", "ip6tables.save": "ip6tables-save"}
LEGACY_FILES = ("iptables.rules", "ip6tables.rules", "ufw-status.txt")
KEEP_AUTO = 20
CAP = 50
UPLOAD_MAX = 2 * 1024 * 1024
FILE_MAX = 1024 * 1024
CONFIRM_S = 60
_lock = threading.RLock()


class Refused(Exception):
    def __init__(self, status, payload):
        Exception.__init__(self, payload.get("error", "refused"))
        self.status = status
        self.payload = payload


def _sdir(ctx):
    return ctx.path(SNAP_DIR)


def _valid_id(sid):
    return bool(re.match(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{4,8}$", str(sid or "")))


def _write_private(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    os.replace(tmp, path)


def _sha(text):
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _norm_save(text):
    out = []
    for l in (text or "").splitlines():
        if l.startswith("#"):
            continue
        out.append(re.sub(r"\[\d+:\d+\]", "[0:0]", l))
    return "\n".join(out) + ("\n" if out else "")


def current_files(ctx):
    return {k: ctx.read(p) for k, p in UFW_FILES.items()}


def _ruleset_from_files(ctx, files, raw=None):
    f = {k: v for k, v in files.items() if k in UFW_FILES and k not in ("ufw.default", "sysctl.conf")}
    f["default"] = files.get("ufw.default", "")
    return G.load_ruleset(ctx, files=f, raw=raw if raw is not None else {})


def _counts(ctx, files, raw):
    rs = _ruleset_from_files(ctx, files, raw)
    cl = [G.classify_rule(r, ctx) for r in rs["v4"] + rs["v6"]]
    return {"ufw_v4": len(rs["v4"]), "ufw_v6": len(rs["v6"]),
            "managed": sum(1 for c in cl if c["managed"]),
            "yours": sum(1 for c in cl if not c["managed"]),
            "raw_v4": sum(1 for l in (raw.get("iptables.save") or "").splitlines() if l.startswith("-A ")),
            "raw_v6": sum(1 for l in (raw.get("ip6tables.save") or "").splitlines() if l.startswith("-A "))}


# ── list / read ──────────────────────────────────────────────────────────────

def _read_meta(ctx, sid):
    try:
        with open(os.path.join(_sdir(ctx), sid, "meta.json")) as f:
            m = json.load(f)
        m["id"] = sid
        return m
    except (OSError, ValueError):
        return None


def list_snaps(ctx):
    out = []
    try:
        names = os.listdir(_sdir(ctx))
    except OSError:
        names = []
    for n in names:
        if _valid_id(n):
            m = _read_meta(ctx, n)
            if m:
                out.append(m)
    out.sort(key=lambda m: m.get("ts", 0), reverse=True)
    return out


def legacy_info(ctx):
    d = ctx.path(LEGACY_DIR)
    p = os.path.join(d, "iptables.rules")
    try:
        st = os.stat(p)
    except OSError:
        return {"present": False}
    imported = next((m["id"] for m in list_snaps(ctx) if m.get("kind") == "legacy"), None)
    return {"present": True, "path": LEGACY_DIR, "ts": int(st.st_mtime),
            "time": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
            "files": [f for f in LEGACY_FILES + ("nftables.ruleset",)
                      if os.path.exists(os.path.join(d, f))],
            "restorable": False, "imported_as": imported,
            "label": "Legacy baseline (%s) — raw iptables, restore disabled"
                     % time.strftime("%b %-d", time.localtime(st.st_mtime))}


def listing(ctx):
    snaps = list_snaps(ctx)
    return {"ok": True, "snapshots": snaps, "legacy": legacy_info(ctx),
            "retention": {"keep_auto": KEEP_AUTO, "cap": CAP}}


def load_files(ctx, sid):
    if not _valid_id(sid):
        raise Refused(400, {"ok": False, "error": "Invalid snapshot id"})
    d = os.path.join(_sdir(ctx), sid)
    meta = _read_meta(ctx, sid)
    if not meta:
        raise Refused(404, {"ok": False, "error": "Snapshot not found"})
    files = {}
    for name in list(UFW_FILES) + list(RAW_FILES) + list(LEGACY_FILES):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            with open(p, "r", errors="replace") as f:
                files[name] = f.read()
    return meta, files


# ── create / retention ───────────────────────────────────────────────────────

def create(ctx, note="", kind="manual", who="", reason="", version="", dedupe=False,
           files=None, raw=None, extra=None):
    with _lock:
        files = current_files(ctx) if files is None else files
        if raw is None:
            raw = {}
            for name, tool in RAW_FILES.items():
                rc, out = ctx.run([tool])
                raw[name] = out if rc == 0 else ""
        hashes = {k: _sha(v) for k, v in files.items()}
        if dedupe:
            snaps = [m for m in list_snaps(ctx) if m.get("kind") != "legacy"]
            if snaps and snaps[0].get("hashes") == hashes:
                m = dict(snaps[0])
                m["deduplicated"] = True
                return m
        os.makedirs(_sdir(ctx), mode=0o700, exist_ok=True)
        os.chmod(_sdir(ctx), 0o700)
        ts = time.time()
        sid = time.strftime("%Y%m%d-%H%M%S-", time.localtime(ts)) + uuid.uuid4().hex[:4]
        d = os.path.join(_sdir(ctx), sid)
        os.makedirs(d, mode=0o700)
        for k, v in list(files.items()) + list(raw.items()):
            _write_private(os.path.join(d, k), v)
        meta = {"id": sid, "ts": int(ts), "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                "note": str(note or "")[:200], "kind": kind, "who": who or "", "reason": reason or "",
                "version": version or "", "hashes": hashes,
                "restorable": kind != "legacy",
                "counts": _counts(ctx, files, raw) if kind != "legacy" else {
                    "raw_v4": sum(1 for l in raw.get("iptables.save", "").splitlines() if l.startswith("-A ")),
                    "raw_v6": sum(1 for l in raw.get("ip6tables.save", "").splitlines() if l.startswith("-A "))}}
        meta.update(extra or {})
        _write_private(os.path.join(d, "meta.json"), json.dumps(meta, indent=2))
        prune(ctx)
        return meta


def prune(ctx):
    snaps = list_snaps(ctx)
    autos = [m for m in snaps if m.get("kind") == "auto"]
    drop = [m["id"] for m in autos[KEEP_AUTO:]]
    rest = [m for m in snaps if m["id"] not in drop]
    if len(rest) > CAP:
        # oldest auto first, then oldest manual/upload/legacy
        order = sorted(rest, key=lambda m: (m.get("kind") != "auto", m.get("ts", 0)))
        drop += [m["id"] for m in order[:len(rest) - CAP]]
    for sid in drop:
        shutil.rmtree(os.path.join(_sdir(ctx), sid), ignore_errors=True)
    return drop


def delete(ctx, sid):
    if not _valid_id(sid) or not _read_meta(ctx, sid):
        raise Refused(404, {"ok": False, "error": "Snapshot not found"})
    shutil.rmtree(os.path.join(_sdir(ctx), sid))
    return {"ok": True, "deleted": sid}


def import_legacy(ctx, who="", version=""):
    info = legacy_info(ctx)
    if not info.get("present"):
        raise Refused(404, {"ok": False, "error": "No legacy baseline found"})
    if info.get("imported_as"):
        return {"ok": True, "id": info["imported_as"], "already": True}
    d = ctx.path(LEGACY_DIR)
    def rd(n):
        try:
            with open(os.path.join(d, n), "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""
    raw = {"iptables.save": rd("iptables.rules"), "ip6tables.save": rd("ip6tables.rules"),
           "ufw-status.txt": rd("ufw-status.txt")}
    m = create(ctx, note="Legacy baseline (%s) imported" % info["time"], kind="legacy", who=who,
               version=version, files={}, raw=raw, extra={"legacy_ts": info["ts"]})
    return {"ok": True, "id": m["id"], "snapshot": m}


# ── diff ─────────────────────────────────────────────────────────────────────

def _udiff(a, b, name, limit=400):
    lines = list(difflib.unified_diff((a or "").splitlines(), (b or "").splitlines(),
                                      "snapshot/" + name, "current/" + name, lineterm="", n=2))
    return "\n".join(lines[:limit]) + ("\n… (%d more lines)" % (len(lines) - limit) if len(lines) > limit else "")


def diff(ctx, sid):
    meta, files = load_files(ctx, sid)
    cur = current_files(ctx)
    out = {"ok": True, "id": sid, "meta": meta, "changes": [], "unified": {}, "same": True}
    if meta.get("kind") == "legacy":
        for name, tool in RAW_FILES.items():
            rc, live = ctx.run([tool])
            a, b = _norm_save(files.get(name, "")), _norm_save(live if rc == 0 else "")
            if a != b:
                out["same"] = False
                out["unified"][name] = _udiff(a, b, name)
        la = set(_norm_save(files.get("iptables.save", "")).splitlines())
        lb = set(_norm_save(ctx.run(["iptables-save"])[1]).splitlines())
        out["changes"].append({"kind": "info", "text": "Raw iptables baseline: %d lines only in the "
                               "baseline, %d only in the live ruleset (IPv4)." % (len(la - lb), len(lb - la))})
        lost = [x for x in raw_owned_lost(ctx, files)]
        for x in lost:
            out["changes"].append({"kind": "owned-lost", "owner": x["owner"], "label": x["label"],
                                   "text": "Restoring it would drop: %s" % x["line"]})
        return out
    snap_rs = _ruleset_from_files(ctx, files)
    cur_rs = _ruleset_from_files(ctx, cur)
    sk = {r["key"]: r for r in snap_rs["v4"] + snap_rs["v6"]}
    ck = {r["key"]: r for r in cur_rs["v4"] + cur_rs["v6"]}
    for k, r in sk.items():
        if k not in ck:
            c = G.classify_rule(r, ctx)
            out["changes"].append({"kind": "only-snapshot", "family": r["family"], "rule": r["text"],
                                   "owner": c["owner"], "managed": c["managed"],
                                   "text": "Only in the snapshot: %s%s" % (
                                       r["text"], " (managed; not restored)" if c["managed"] else "")})
    for k, r in ck.items():
        if k not in sk:
            c = G.classify_rule(r, ctx)
            out["changes"].append({"kind": "only-current", "family": r["family"], "rule": r["text"],
                                   "owner": c["owner"], "managed": c["managed"],
                                   "text": "Added since the snapshot: %s%s" % (
                                       r["text"], " (managed; kept on restore)" if c["managed"] else "")})
    so = [r["key"] for r in snap_rs["v4"] + snap_rs["v6"] if r["key"] in ck]
    co = [r["key"] for r in cur_rs["v4"] + cur_rs["v6"] if r["key"] in sk]
    if so != co:
        out["changes"].append({"kind": "order", "text": "Rule order differs."})
    for k in ("input", "forward", "output"):
        a, b = snap_rs["defaults"].get(k), cur_rs["defaults"].get(k)
        if a != b:
            out["changes"].append({"kind": "default", "text": "Default %s policy: %s in the snapshot, %s now"
                                   % ({"input": "incoming", "forward": "routed", "output": "outgoing"}[k], a, b)})
    for name in UFW_FILES:
        if files.get(name, "") != cur.get(name, ""):
            out["unified"][name] = _udiff(files.get(name, ""), cur.get(name, ""), name)
            if name not in ("user.rules", "user6.rules"):
                out["changes"].append({"kind": "file", "file": name,
                                       "text": "%s differs" % UFW_FILES[name]})
    out["same"] = not out["unified"]
    if out["same"]:
        out["changes"].append({"kind": "same", "text": "Identical to the current firewall files."})
    return out


def raw_owned_lost(ctx, files):
    """Owned raw rules live now that the legacy raw baseline does not contain."""
    lost = []
    for fam, name, tool in (("v4", "iptables.save", "iptables-save"), ("v6", "ip6tables.save", "ip6tables-save")):
        rc, live = ctx.run([tool])
        base = set(_norm_save(files.get(name, "")).splitlines())
        for item in G.raw_rules(live if rc == 0 else "", fam):
            c = G.classify_raw(item, ctx)
            if c["managed"] and item["line"] not in base:
                lost.append({"family": fam, "line": item["line"], "owner": c["owner"], "label": c["label"]})
        # ufw user-chain rules for honeypot/canary ports
        for l in (live or "").splitlines():
            if l.startswith("-A ufw") and "-user-input" in l.split()[1] and l not in base:
                m = re.search(r"-i (\S+) .*--dport (\d+)", l)
                if m and m.group(1) == ctx.wan:
                    lost.append({"family": fam, "line": l, "owner": "deception",
                                 "label": "Deception (honeypot/canary) WAN port"})
    return lost


# ── restore ──────────────────────────────────────────────────────────────────

def _owned_before_lines(ctx, text, fam):
    out = []
    for l in (text or "").splitlines():
        if l.startswith("-A ") and "--uid-owner" in l:
            c = G.classify_raw({"family": fam, "table": "filter", "chain": l.split()[1], "line": l}, ctx)
            if c["managed"]:
                out.append(l)
    return out


def merge_before(ctx, snap_text, cur_text, fam):
    """Snapshot before.rules with the owned (containment) lines of the current file."""
    want = _owned_before_lines(ctx, cur_text, fam)
    have = _owned_before_lines(ctx, snap_text, fam)
    if want == have:
        return snap_text, False
    lines = (snap_text or "").splitlines()
    pos = None
    kept = []
    for l in lines:
        if l in have:
            if pos is None:
                pos = len(kept)
            continue
        kept.append(l)
    if pos is None:
        # before the COMMIT of the *filter table
        in_filter = False
        for i, l in enumerate(kept):
            if l.startswith("*filter"):
                in_filter = True
            elif in_filter and l.strip() == "COMMIT":
                pos = i
                while pos > 0 and kept[pos - 1].startswith("#"):
                    pos -= 1
                break
        if pos is None:
            pos = len(kept)
    block = ["# --- owned rules re-applied from the current firewall by snapshot restore ---"] + want
    kept[pos:pos] = block
    return "\n".join(kept) + "\n", True


def merge_owned(ctx, snap_rs, cur_rs):
    """Blocks per family: the snapshot's own (unmanaged) rules plus every managed
    rule of the CURRENT ruleset at its current relative position; missing
    honeypot ports are re-added from the honeypot config."""
    res = {}
    notes = []
    for fam in ("v4", "v6"):
        cur_blocks = cur_rs["blocks"][fam]
        cur_cls = [G.classify_rule(b["rule"], ctx) for b in cur_blocks]
        managed_keys = {b["rule"]["key"] for b, c in zip(cur_blocks, cur_cls) if c["managed"]}
        result = []
        snap_managed = set()
        for b in snap_rs["blocks"][fam]:
            c = G.classify_rule(b["rule"], ctx)
            if c["managed"] or b["rule"]["key"] in managed_keys:
                snap_managed.add(b["rule"]["key"])
                continue
            result.append(dict(b))
        dropped = len(snap_managed - managed_keys) + len(managed_keys - snap_managed)
        for i, (b, c) in enumerate(zip(cur_blocks, cur_cls)):
            if not c["managed"]:
                continue
            keys = [x["rule"]["key"] for x in result]
            pos = 0
            for j in range(i - 1, -1, -1):
                k = cur_blocks[j]["rule"]["key"]
                if k in keys:
                    pos = keys.index(k) + 1
                    break
            result.insert(pos, dict(b))
        hp = ctx.honeypot
        if hp["enabled"] and ctx.wan:
            have = [x["rule"] for x in result]
            for p in hp["ports"]:
                if not G._has_allow(have, ctx.wan, "tcp", p):
                    result.append(honeypot_block(ctx.wan, p, fam))
                    notes.append("Re-added honeypot port %d/tcp (%s) from the honeypot config" % (p, fam))
        res[fam] = result
        if dropped:
            notes.append("%d managed %s rule(s) differ between the snapshot and now; the current "
                         "managed rules are kept" % (dropped, fam))
    return res, notes


def honeypot_block(wan, port, fam):
    anyn = "0.0.0.0/0" if fam == "v4" else "::/0"
    chain = "ufw-user-input" if fam == "v4" else "ufw6-user-input"
    return {"tuple": "### tuple ### allow tcp %d %s any %s in_%s comment=%s" % (
                port, anyn, anyn, wan, G.HONEYPOT_TAG.encode().hex()),
            "body": ["-A %s -i %s -p tcp --dport %d -j ACCEPT" % (chain, wan, port)]}


def plan_restore(ctx, sid):
    meta, files = load_files(ctx, sid)
    if meta.get("kind") == "legacy" or not meta.get("restorable", True):
        raise Refused(409, {"ok": False, "error": "This is the legacy raw iptables baseline; it can't be "
                            "restored (it predates the managed rules). Use it for Diff only.",
                            "legacy": True})
    missing = [k for k in ("user.rules", "user6.rules", "before.rules", "ufw.default") if not files.get(k)]
    if missing:
        raise Refused(409, {"ok": False, "error": "Snapshot is incomplete (%s)" % ", ".join(missing)})
    cur_files = current_files(ctx)
    cur_rs = G.load_ruleset(ctx, files=dict({k: v for k, v in cur_files.items()}, default=cur_files["ufw.default"]))
    snap_rs = _ruleset_from_files(ctx, files, raw=cur_rs.get("raw"))
    blocks, notes = merge_owned(ctx, snap_rs, cur_rs)
    new_files = dict(files)
    for fam, name in (("v4", "before.rules"), ("v6", "before6.rules")):
        txt, changed = merge_before(ctx, files.get(name, ""), cur_files.get(name, ""), fam)
        new_files[name] = txt
        if changed:
            notes.append("%s: owned containment lines taken from the current file" % name)
    prop = G.rebuild(snap_rs, blocks["v4"], blocks["v6"],
                     files={"before.rules": new_files["before.rules"],
                            "before6.rules": new_files["before6.rules"]})
    prop["raw"] = cur_rs.get("raw")
    new_files["user.rules"] = prop["texts"]["user.rules"]
    new_files["user6.rules"] = prop["texts"]["user6.rules"]
    guard = G.check(cur_rs, prop, ctx)
    writes = {k: v for k, v in new_files.items() if k in UFW_FILES and v != cur_files.get(k)}
    ck = {r["key"] for r in cur_rs["v4"] + cur_rs["v6"]}
    pk = {r["key"] for r in prop["v4"] + prop["v6"]}
    removed = [r["text"] + " (" + r["family"] + ")" for r in cur_rs["v4"] + cur_rs["v6"] if r["key"] not in pk]
    added = [r["text"] + " (" + r["family"] + ")" for r in prop["v4"] + prop["v6"] if r["key"] not in ck]
    lock = [x for x in guard["new"] + guard["existing"] if x["id"] == "lockout"]
    return {"ok": True, "id": sid, "meta": meta, "guard": guard, "notes": notes,
            "writes": sorted(writes), "files": new_files, "rules_added": added,
            "rules_removed": removed, "managed_kept": sum(
                1 for r in prop["v4"] + prop["v6"] if G.classify_rule(r, ctx)["managed"]),
            "lockout_warning": (lock[0]["detail"] if lock else
                                "Your session %s via %s keeps access to the dashboard."
                                % (ctx.client_ip or "?", ctx.client_iface or "?")),
            "actions": ["write " + UFW_FILES[k] for k in sorted(writes)] +
                       (["ufw reload", "re-apply owned raw rules (WireGuard, port forwards, DMZ, "
                         "NAT, tripwire)", "confirm within %d s or auto-revert" % CONFIRM_S]
                        if writes else []),
            "no_changes": not writes}


def _write_ufw_files(ctx, files):
    for k, text in files.items():
        if k not in UFW_FILES:
            continue
        p = ctx.path(UFW_FILES[k])
        try:
            st = os.stat(p)
            mode = st.st_mode & 0o777
        except OSError:
            mode = 0o640
        tmp = p + ".tuxwall-tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, p)


def _apply(ctx, files, reapply):
    _write_ufw_files(ctx, files)
    rc, out = ctx.run(["ufw", "reload"])
    log = [{"step": "ufw reload", "rc": rc, "output": (out or "")[-300:]}]
    if rc != 0:
        return False, log
    for name, fn in (reapply or []):
        try:
            fn()
            log.append({"step": name, "rc": 0})
        except Exception as exc:
            log.append({"step": name, "rc": 1, "output": str(exc)[:300]})
    return True, log


_PENDING = {}


def restore(ctx, sid, who="", version="", reapply=None, schedule=None, ttl=CONFIRM_S):
    """Guarded restore. schedule(change_id, desc, revert_fn, ttl) arms the
    confirm-or-revert timer (api_server._fw_schedule_revert)."""
    with _lock:
        for cid, p in list(_PENDING.items()):
            if p["expires"] > time.time():
                raise Refused(409, {"ok": False, "error": "Another snapshot restore is waiting for "
                                    "confirmation (%s)." % cid, "pending": cid})
            _PENDING.pop(cid, None)
        plan = plan_restore(ctx, sid)
        if not plan["guard"]["ok"]:
            raise Refused(409, {"ok": False, "error": plan["guard"]["summary"],
                                "guard": plan["guard"], "plan": _public(plan)})
        if plan["no_changes"]:
            return {"ok": True, "no_changes": True, "plan": _public(plan),
                    "message": "The firewall files already match this snapshot (managed rules kept)."}
        pre = create(ctx, note="Before restoring %s" % sid, kind="auto", who=who,
                     reason="restore %s" % sid, version=version)
        _m, pre_files = load_files(ctx, pre["id"])
        pre_files = {k: v for k, v in pre_files.items() if k in UFW_FILES}
        writes = {k: plan["files"][k] for k in plan["writes"]}
        ok, log = _apply(ctx, writes, reapply)
        if not ok:
            _apply(ctx, pre_files, reapply)
            raise Refused(500, {"ok": False, "error": "ufw reload failed; the previous files were put back.",
                                "log": log})
        change_id = "fwsnap:%s:%s" % (sid, uuid.uuid4().hex[:6])

        def revert():
            _PENDING.pop(change_id, None)
            _apply(ctx, pre_files, reapply)
        _PENDING[change_id] = {"expires": time.time() + ttl, "pre": pre["id"], "sid": sid}
        if schedule:
            schedule(change_id, "snapshot restore %s" % sid, revert, ttl)
        return {"ok": True, "id": sid, "needs_confirmation": change_id, "confirm_within_s": ttl,
                "revert_snapshot": pre["id"], "log": log, "plan": _public(plan),
                "message": "Restored. Confirm within %d s or the previous firewall comes back." % ttl}


def _write_side(ctx, path, text):
    """Small state file (e.g. /etc/tuxwall/fw-disabled.json); None = delete."""
    p = ctx.path(path)
    if text is None:
        try:
            os.remove(p)
        except OSError:
            pass
        return
    os.makedirs(os.path.dirname(p), exist_ok=True)
    _write_private(p, text)


def apply_files(ctx, cur_rs, prop, desc, who="", version="", reapply=None, schedule=None,
                ttl=CONFIRM_S, side=None):
    """Guarded rule change (edit / enable / disable / reorder / insert):
    guard -> auto snapshot -> write user*.rules (+ side state files) -> ufw
    reload -> confirm-or-revert. Only user.rules/user6.rules are written."""
    with _lock:
        for cid, p in list(_PENDING.items()):
            if p["expires"] > time.time():
                raise Refused(409, {"ok": False, "pending": cid,
                                    "error": "Another firewall change is waiting for confirmation (%s). "
                                             "Confirm it or let it revert first." % cid})
            _PENDING.pop(cid, None)
        guard = G.check(cur_rs, prop, ctx)
        if not guard["ok"]:
            raise Refused(409, {"ok": False, "error": guard["summary"], "guard": guard})
        writes = {k: prop["texts"][k] for k in ("user.rules", "user6.rules")
                  if prop["texts"][k] != cur_rs["texts"][k]}
        side = dict(side or {})
        if not writes and not side:
            return {"ok": True, "no_changes": True, "guard": guard, "message": "Nothing to change."}
        pre = create(ctx, note="Before " + desc, kind="auto", who=who, reason=desc, version=version)
        _m, pre_all = load_files(ctx, pre["id"])
        pre_files = {k: v for k, v in pre_all.items() if k in writes}
        pre_side = {p: (ctx.read(p, None) if os.path.exists(ctx.path(p)) else None) for p in side}
        for p, t in side.items():
            _write_side(ctx, p, t)
        ok, log = _apply(ctx, writes, reapply)
        if not ok:
            _apply(ctx, pre_files, reapply)
            for p, t in pre_side.items():
                _write_side(ctx, p, t)
            raise Refused(500, {"ok": False, "error": "ufw reload failed; the previous rules were put back.",
                                "log": log})
        change_id = "fwedit:%s" % uuid.uuid4().hex[:8]

        def revert():
            _PENDING.pop(change_id, None)
            _apply(ctx, pre_files, reapply)
            for p, t in pre_side.items():
                _write_side(ctx, p, t)
        _PENDING[change_id] = {"expires": time.time() + ttl, "pre": pre["id"], "desc": desc}
        if schedule:
            schedule(change_id, desc, revert, ttl)
        return {"ok": True, "needs_confirmation": change_id, "confirm_within_s": ttl,
                "revert_snapshot": pre["id"], "guard": guard, "log": log,
                "message": "Applied. Confirm within %d s or the previous rules come back." % ttl}


def confirmed(change_id):
    _PENDING.pop(change_id, None)


def _public(plan):
    p = dict(plan)
    p.pop("files", None)
    return p


# ── legacy baseline restore (old "Restore baseline" button) ──────────────────

def legacy_restore_plan(ctx):
    """Guard verdict for the legacy raw baseline: which owned rules it would roll back."""
    info = legacy_info(ctx)
    if not info.get("present"):
        raise Refused(404, {"ok": False, "error": "No legacy baseline found"})
    d = ctx.path(LEGACY_DIR)
    files = {}
    for n, k in (("iptables.rules", "iptables.save"), ("ip6tables.rules", "ip6tables.save")):
        try:
            with open(os.path.join(d, n), errors="replace") as f:
                files[k] = f.read()
        except OSError:
            files[k] = ""
    lost = raw_owned_lost(ctx, files)
    blocking = [{"id": "legacy-owned:%d" % i, "severity": "critical", "owner": x["owner"],
                 "title": "Would roll back a managed rule (%s)" % x["label"], "detail": x["line"]}
                for i, x in enumerate(lost)]
    return {"ok": not blocking, "legacy": info, "lost": lost, "blocking": blocking,
            "files": files,
            "summary": ("Guard passed" if not blocking else
                        "The legacy baseline from %s would roll back %d managed rule(s) (canary "
                        "containment, honeypot/canary ports, CrowdSec, WireGuard, …). Restore refused. "
                        "Use Firewall → Settings → Snapshots instead." % (info["time"], len(blocking)))}


def legacy_restore(ctx, who="", version="", schedule=None, ttl=CONFIRM_S):
    """Only when the guard passes: restore the ufw user chains (never owned
    chains) from the legacy baseline with iptables-restore --noflush, under a
    confirm-or-revert timer. Refused otherwise."""
    plan = legacy_restore_plan(ctx)
    if not plan["ok"]:
        raise Refused(409, {"ok": False, "error": plan["summary"],
                            "guard": {"ok": False, "blocking": plan["blocking"]}})
    pre = create(ctx, note="Before legacy baseline restore", kind="auto", who=who,
                 reason="legacy restore", version=version)
    for fam, name, tool in (("v4", "iptables.save", "iptables-restore"), ("v6", "ip6tables.save", "ip6tables-restore")):
        payload = user_chains_only(plan["files"].get(name, ""), fam)
        if payload:
            rc, out = ctx.run_in([tool, "--noflush", "--wait", "5"], payload)
            if rc != 0:
                raise Refused(500, {"ok": False, "error": "%s failed: %s" % (tool, out[-200:])})
    change_id = "fwlegacy:" + uuid.uuid4().hex[:6]
    if schedule:
        _m, pre_files = load_files(ctx, pre["id"])
        pre_files = {k: v for k, v in pre_files.items() if k in UFW_FILES}
        schedule(change_id, "legacy baseline restore", lambda: _apply(ctx, pre_files, None), ttl)
    return {"ok": True, "needs_confirmation": change_id, "confirm_within_s": ttl,
            "revert_snapshot": pre["id"]}


def user_chains_only(text, fam):
    pre = "ufw-user-" if fam == "v4" else "ufw6-user-"
    out, decl = [], []
    in_filter = False
    for l in (text or "").splitlines():
        if l.startswith("*"):
            in_filter = l.strip() == "*filter"
        elif not in_filter:
            continue
        elif l.startswith(":" + pre):
            decl.append(l.split()[0] + " - [0:0]")
        elif l.startswith("-A " + pre):
            out.append(l)
    if not decl:
        return ""
    return "*filter\n" + "\n".join(decl + out) + "\nCOMMIT\n"


# ── download / upload ────────────────────────────────────────────────────────

def download(ctx, sid):
    meta, files = load_files(ctx, sid)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in [("meta.json", json.dumps(meta, indent=2))] + sorted(files.items()):
            data = text.encode("utf-8")
            ti = tarfile.TarInfo("tuxwall-fw-%s/%s" % (sid, name))
            ti.size = len(data)
            ti.mtime = meta.get("ts", int(time.time()))
            ti.mode = 0o600
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue(), "tuxwall-fw-%s.tar.gz" % sid


_DEFAULT_KEYS = {"IPV6", "DEFAULT_INPUT_POLICY", "DEFAULT_OUTPUT_POLICY", "DEFAULT_FORWARD_POLICY",
                 "DEFAULT_APPLICATION_POLICY", "MANAGE_BUILTINS", "IPT_SYSCTL", "IPT_MODULES"}
_RULES_LINE = re.compile(r"^(\*[a-z]+|:[A-Za-z0-9_-]+ (ACCEPT|DROP|-|REJECT) \[\d+:\d+\]|-[AIN] .*|COMMIT|#.*|)$")


def validate_files(files):
    errs = []
    for name, text in files.items():
        if name in ("ufw.default",):
            for l in text.splitlines():
                s = l.strip()
                if not s or s.startswith("#"):
                    continue
                m = re.match(r'^([A-Z_0-9]+)=("[A-Za-z0-9_./ -]*"|[A-Za-z0-9_./-]*)$', s)
                if not m or m.group(1) not in _DEFAULT_KEYS:
                    errs.append("%s: unexpected line %r" % (name, s[:80]))
        elif name == "sysctl.conf":
            for l in text.splitlines():
                s = l.strip()
                if s and not s.startswith("#") and not re.match(r"^[a-z0-9_./-]+\s*=\s*[A-Za-z0-9 _.-]+$", s):
                    errs.append("%s: unexpected line %r" % (name, s[:80]))
        elif name.endswith(".rules"):
            for l in text.splitlines():
                if not _RULES_LINE.match(l.rstrip()):
                    errs.append("%s: unexpected line %r" % (name, l[:80]))
                    break
                if re.search(r"[`$;|&]", l) and not l.startswith("#") and "--log-prefix" not in l \
                        and "--comment" not in l:
                    errs.append("%s: unexpected characters in %r" % (name, l[:80]))
                    break
            if name.startswith("user") and ("### RULES ###" not in text or "COMMIT" not in text):
                errs.append("%s: not a ufw user rules file" % name)
    return errs


def upload(ctx, data_b64, note="", who="", version=""):
    try:
        data = base64.b64decode(data_b64 or "", validate=True)
    except Exception:
        raise Refused(400, {"ok": False, "error": "Upload is not valid base64"})
    if not data or len(data) > UPLOAD_MAX:
        raise Refused(413, {"ok": False, "error": "Upload is empty or larger than 2 MB"})
    files, total = {}, 0
    allowed = set(UFW_FILES) | set(RAW_FILES)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for ti in tar.getmembers():
                if ti.isdir():
                    continue
                if not ti.isfile():
                    raise Refused(400, {"ok": False, "error": "Archive contains a non-regular file"})
                base = ti.name.rsplit("/", 1)[-1]
                if ".." in ti.name.split("/") or ti.name.startswith("/"):
                    raise Refused(400, {"ok": False, "error": "Archive contains an unsafe path"})
                if base == "meta.json":
                    continue
                if base not in allowed:
                    raise Refused(400, {"ok": False, "error": "Unexpected file in archive: %s" % base[:60]})
                if ti.size > FILE_MAX:
                    raise Refused(413, {"ok": False, "error": "%s is too large" % base})
                total += ti.size
                if total > 4 * UPLOAD_MAX:
                    raise Refused(413, {"ok": False, "error": "Archive expands too much"})
                files[base] = tar.extractfile(ti).read().decode("utf-8")
    except Refused:
        raise
    except Exception as exc:
        raise Refused(400, {"ok": False, "error": "Not a TuxWall firewall snapshot (.tar.gz): %s" % exc})
    for need in ("user.rules", "user6.rules", "before.rules", "ufw.default"):
        if need not in files:
            raise Refused(400, {"ok": False, "error": "Snapshot archive is missing %s" % need})
    errs = validate_files({k: v for k, v in files.items() if k in UFW_FILES})
    if errs:
        raise Refused(400, {"ok": False, "error": "Snapshot failed validation: " + "; ".join(errs[:3])})
    ufw_files = {k: files.get(k, "") for k in UFW_FILES}
    raw = {k: files.get(k, "") for k in RAW_FILES}
    m = create(ctx, note=note or "Uploaded snapshot", kind="upload", who=who, version=version,
               files=ufw_files, raw=raw)
    return {"ok": True, "id": m["id"], "snapshot": m}
