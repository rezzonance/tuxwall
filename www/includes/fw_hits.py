"""Per-rule hit counters for ufw user rules.

Maps every ufw tuple (user.rules / user6.rules block) to its packet counters
in `iptables-save -c` / `ip6tables-save -c` (read-only): the body lines of
each block appear, in file order, in the ufw-user-input|forward|output chains,
so the n-th body line of a chain is the n-th counter line of that chain. The
mapping is verified line by line (targets must match), otherwise the family
is reported as unmapped instead of guessing.

A sampler (api_server thread, every 5 min) appends cumulative counters to
/var/lib/tuxwall/fw-hits.jsonl (bounded) and folds deltas into
/var/lib/tuxwall/fw-hits-state.json ({key-hash: first, last_hit, total}), so
totals survive `ufw reload` / reboots (counter resets are detected).
"""
import hashlib
import json
import os
import re
import time

import fw_guard as G

HITS_FILE = "/var/lib/tuxwall/fw-hits.jsonl"
STATE_FILE = "/var/lib/tuxwall/fw-hits-state.json"
INTERVAL = 300
MAX_LINES = 2016          # 7 days at 5 min
TERMINAL = ("ACCEPT", "DROP", "REJECT")
_CNT = re.compile(r"^\[(\d+):(\d+)\]\s+(-A\s+(\S+)\s.*)$")


def _target(line):
    f = line.split()
    return f[f.index("-j") + 1] if "-j" in f else ""


def _main_chain(chain, fam):
    pre = "ufw" if fam == "v4" else "ufw6"
    return chain in ("%s-user-input" % pre, "%s-user-forward" % pre, "%s-user-output" % pre)


def counters(save_text, fam):
    """{chain: [(pkts, bytes, line)]} for the ufw user main chains."""
    out = {}
    table = ""
    for ln in (save_text or "").splitlines():
        if ln.startswith("*"):
            table = ln[1:].strip()
            continue
        if table != "filter":
            continue
        m = _CNT.match(ln)
        if m and _main_chain(m.group(4), fam):
            out.setdefault(m.group(4), []).append((int(m.group(1)), int(m.group(2)), m.group(3)))
    return out


def _counts_as_hit(target, fam):
    pre = "ufw" if fam == "v4" else "ufw6"
    return target in TERMINAL or target in (pre + "-user-limit", pre + "-user-limit-accept")


def map_hits(rs, saves):
    """{"v4": [ {key, pkts, bytes} per block ] | None, "v6": ...,
        "errors": {fam: reason}}"""
    res = {"errors": {}}
    for fam in ("v4", "v6"):
        cnt = counters((saves or {}).get(fam) or "", fam)
        if not cnt and rs["blocks"][fam]:
            res[fam] = None
            res["errors"][fam] = "no counters"
            continue
        pos = {c: 0 for c in cnt}
        rows, ok = [], True
        for b in rs["blocks"][fam]:
            pk = by = 0
            for bl in b["body"]:
                f = bl.split()
                if len(f) < 2 or f[0] != "-A" or not _main_chain(f[1], fam):
                    continue
                lst = cnt.get(f[1]) or []
                i = pos.get(f[1], 0)
                if i >= len(lst) or _target(lst[i][2]) != _target(bl):
                    ok = False
                    break
                pos[f[1]] = i + 1
                if _counts_as_hit(_target(bl), fam):
                    pk += lst[i][0]
                    by += lst[i][1]
            if not ok:
                break
            rows.append({"key": b["rule"]["key"], "pkts": pk, "bytes": by})
        if ok and any(pos.get(c, 0) != len(v) for c, v in cnt.items()):
            ok = False
        res[fam] = rows if ok else None
        if not ok:
            res["errors"][fam] = "ruleset and kernel counters differ (reload pending?)"
    return res


def hkey(key, n=0):
    return hashlib.sha1(("%s#%d" % (key, n)).encode()).hexdigest()[:10]


def keyed(mapped):
    """{hash: pkts} with duplicate keys disambiguated by occurrence."""
    out = {}
    for fam in ("v4", "v6"):
        seen = {}
        for row in mapped.get(fam) or []:
            n = seen.get(row["key"], 0)
            seen[row["key"]] = n + 1
            out[hkey(row["key"], n)] = row["pkts"]
    return out


def boot_id(ctx):
    return (ctx.read("/proc/sys/kernel/random/boot_id") or "").strip()[:8]


def sample(ctx, rs=None, now=None):
    """One read-only sample: (record, mapped)."""
    now = int(now or time.time())
    rs = rs or G.load_ruleset(ctx, raw={})
    saves = {}
    for fam, tool in (("v4", "iptables-save"), ("v6", "ip6tables-save")):
        rc, out = ctx.run([tool, "-c"])
        saves[fam] = out if rc == 0 else ""
    mapped = map_hits(rs, saves)
    return {"t": now, "b": boot_id(ctx), "c": keyed(mapped)}, mapped


def _load_state(ctx):
    try:
        with open(ctx.path(STATE_FILE)) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_atomic(path, text, mode=0o640):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def record(ctx, rec):
    """Append a sample and fold its deltas into the state file."""
    st = _load_state(ctx)
    rules = st.get("rules") or {}
    prev = st.get("last") or {}
    same_boot = st.get("boot") == rec["b"]
    for h, v in rec["c"].items():
        r = rules.setdefault(h, {"first": rec["t"], "total": 0, "last_hit": None})
        p = prev.get(h)
        if p is None:
            delta = 0          # first sighting: count from here on
        elif same_boot and v >= p:
            delta = v - p
        else:
            delta = v          # counters were reset (ufw reload / reboot)
        if delta > 0:
            r["total"] += delta
            r["last_hit"] = rec["t"]
    # forget rules gone for > 30 days
    for h in list(rules):
        if h not in rec["c"] and rec["t"] - (rules[h].get("last_seen") or rec["t"]) > 30 * 86400:
            del rules[h]
        elif h in rec["c"]:
            rules[h]["last_seen"] = rec["t"]
    st = {"boot": rec["b"], "last": rec["c"], "rules": rules, "updated": rec["t"]}
    _write_atomic(ctx.path(STATE_FILE), json.dumps(st, separators=(",", ":")))
    p = ctx.path(HITS_FILE)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    try:
        if os.path.getsize(p) > 64 * 1024:
            with open(p) as f:
                lines = f.readlines()
            if len(lines) > MAX_LINES * 1.1:
                _write_atomic(p, "".join(lines[-MAX_LINES:]))
    except OSError:
        pass
    return st


def history(ctx, since):
    out = []
    try:
        with open(ctx.path(HITS_FILE)) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if d.get("t", 0) >= since:
                    out.append(d)
    except OSError:
        pass
    return out


def view(ctx, rs, mapped=None, now=None, buckets=24, span=86400):
    """Per numbered rule: {number, key, hits (since the last ufw reload),
    total, last_hit, first, spark[buckets]}."""
    now = int(now or time.time())
    if mapped is None:
        _rec, mapped = sample(ctx, rs, now)
    st = _load_state(ctx).get("rules") or {}
    hist = history(ctx, now - span - INTERVAL)
    width = span / buckets
    rows = []
    n = 0
    for fam in ("v4", "v6"):
        seen = {}
        rows_f = mapped.get(fam)
        for i, r in enumerate(rs[fam]):
            n += 1
            k = seen.get(r["key"], 0)
            seen[r["key"]] = k + 1
            h = hkey(r["key"], k)
            cur = rows_f[i] if rows_f and i < len(rows_f) else None
            s = st.get(h) or {}
            spark = [0] * buckets
            prev = None
            for d in hist:
                v = (d.get("c") or {}).get(h)
                if v is None:
                    prev = None
                    continue
                if prev is not None:
                    pv, pb = prev
                    delta = v - pv if (v >= pv and pb == d.get("b")) else v
                    b = int((d["t"] - (now - span)) // width)
                    if 0 <= b < buckets and delta > 0:
                        spark[b] += delta
                prev = (v, d.get("b"))
            rows.append({"number": n, "key": r["key"], "family": fam,
                         "hits": cur["pkts"] if cur else None, "bytes": cur["bytes"] if cur else None,
                         "total": s.get("total"), "last_hit": s.get("last_hit"), "first": s.get("first"),
                         "spark": spark})
    return {"ok": True, "rules": rows, "mapped": {f: mapped.get(f) is not None for f in ("v4", "v6")},
            "errors": mapped.get("errors") or {}, "interval": INTERVAL,
            "samples_24h": len(hist), "since": min([v.get("first") or now for v in st.values()] or [now])}


def state_by_key(ctx, rs):
    """{rule key: state} for fw_lint zero-hit findings."""
    st = _load_state(ctx).get("rules") or {}
    out = {}
    for fam in ("v4", "v6"):
        seen = {}
        for r in rs[fam]:
            k = seen.get(r["key"], 0)
            seen[r["key"]] = k + 1
            s = st.get(hkey(r["key"], k))
            if s:
                out[r["key"]] = s
    return out
