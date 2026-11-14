"""TuxWall firewall rule editing: edit-in-place, enable/disable, reorder,
insert — computed as new user.rules/user6.rules texts (pure), applied by
fw_snap.apply_files (auto snapshot, ufw reload, 60 s confirm-or-revert).

Rule blocks (tuple comment + iptables lines) are generated with ufw's own
parser and formatter (no I/O), so a written file is what `ufw` itself would
write. Disabled rules are kept in /etc/tuxwall/fw-disabled.json and removed
from ufw; enabling re-inserts them after their old neighbour.
"""
import hashlib
import json
import re
import time
import uuid

import fw_guard as G

DISABLED_FILE = "/etc/tuxwall/fw-disabled.json"
_ACT_WORD = {"allow": "Allow", "deny": "Block (drop)", "reject": "Reject", "limit": "Allow (rate-limited)"}


class EditError(Exception):
    def __init__(self, status, msg, **extra):
        Exception.__init__(self, msg)
        self.status = status
        self.payload = dict({"ok": False, "error": msg}, **extra)


# ── blocks from rule text ───────────────────────────────────────────────────

_BAD = re.compile(r"[;|&$`!(){}<>\\\n\r]")


def parse_argv(rule_text):
    """Split + validate a ufw rule text ('allow in on eth1 to any port 22
    proto tcp comment "x"'). Returns argv (comment kept as one token)."""
    text = (rule_text or "").strip()
    comment = None
    m = re.search(r"\s+comment\s+(['\"])(.*?)\1\s*$", text)
    if m:
        comment = m.group(2)
        text = text[:m.start()]
    elif re.search(r"\s+comment\s+(\S+)\s*$", text):
        m = re.search(r"\s+comment\s+(\S+)\s*$", text)
        comment = m.group(1)
        text = text[:m.start()]
    argv = text.split()
    if not argv:
        raise EditError(400, "Rule is empty")
    verb = argv[1].lower() if argv[0].lower() == "route" and len(argv) > 1 else argv[0].lower()
    if verb not in ("allow", "deny", "reject", "limit"):
        raise EditError(400, "Unsupported rule verb %r (use allow/deny/reject/limit)" % verb)
    for tok in argv:
        if tok.startswith("-") or _BAD.search(tok):
            raise EditError(400, "Invalid token in rule: %r" % tok)
    if comment is not None:
        if re.search(r"['\"\\\n\r`]", comment) or len(comment) > 120:
            raise EditError(400, "Comments may not contain quotes, backslashes or newlines (max 120)")
        argv += ["comment", comment]
    return argv


def _formatted_lines(rule, fam):
    from ufw.backend_iptables import UFWBackendIptables
    prefix = "ufw" if fam == "v4" else "ufw6"
    suffix = "forward" if rule.forward else ("output" if rule.direction == "out" else "input")
    chain = "%s-user-%s" % (prefix, suffix)
    rs = "-A %s %s\n" % (chain, rule.format_rule())
    return [l.rstrip("\n") for l in UFWBackendIptables._get_rules_from_formatted(None, rs, prefix, suffix)]


def _tuple_line(r):
    action = ("route:" if r.forward else "") + r.action + (("_" + r.logtype) if r.logtype else "")
    if r.interface_in == "" and r.interface_out == "":
        ifaces = r.direction
    elif r.interface_in and r.interface_out:
        ifaces = "in_%s!out_%s" % (r.interface_in, r.interface_out)
    elif r.interface_in:
        ifaces = "%s_%s" % (r.direction, r.interface_in)
    else:
        ifaces = "%s_%s" % (r.direction, r.interface_out)
    t = "### tuple ### %s %s %s %s %s %s %s" % (action, r.protocol, r.dport, r.dst, r.sport, r.src, ifaces)
    if r.comment:
        t += " comment=%s" % r.comment
    return t


def blocks_from_text(rule_text):
    """{"v4": block|None, "v6": block|None, "argv": [...]} using ufw's parser."""
    argv = parse_argv(rule_text) if isinstance(rule_text, str) else list(rule_text)
    try:
        pr = G._ufw_parse(argv)
    except Exception as exc:
        raise EditError(400, "ufw cannot parse this rule: %s" % exc)
    r = pr.data.get("rule")
    if r is None:
        raise EditError(400, "Not a rule")
    if r.dapp or r.sapp:
        raise EditError(400, "Application-profile rules can't be edited here")
    iptype = pr.data.get("iptype", "both")
    out = {"v4": None, "v6": None, "argv": argv}
    for fam in ("v4", "v6"):
        if iptype not in ("both", fam):
            continue
        rr = r.dup_rule()
        if fam == "v6":
            rr.set_v6(True)
            if iptype == "both":
                if rr.src == "0.0.0.0/0":
                    rr.src = "::/0"
                if rr.dst == "0.0.0.0/0":
                    rr.dst = "::/0"
        else:
            rr.set_v6(False)
        try:
            rr.normalize()
        except Exception:
            pass
        out[fam] = {"tuple": _tuple_line(rr), "body": _formatted_lines(rr, fam)}
    return out


# ── plain language ──────────────────────────────────────────────────────────

def _addr(a, fam):
    if G._any(a):
        return "anywhere"
    return a


def plain(r, ctx=None):
    """'Allow TCP 22 from 192.168.1.0/24 arriving on enp6s0 to this router'."""
    names = {}
    if ctx is not None:
        t = ctx.topo
        if (t.get("wan") or {}).get("device"):
            names[t["wan"]["device"]] = "the WAN"
        if (t.get("lan") or {}).get("device"):
            names[t["lan"]["device"]] = "the LAN"
        for o in (t.get("opt") or []) + (t.get("vpn") or []):
            if o.get("device"):
                names[o["device"]] = o.get("name") or o["device"]
    nm = lambda i: ("%s (%s)" % (names[i], i)) if i in names else i  # noqa: E731
    verb = _ACT_WORD.get(r["action"], r["action"].title())
    what = ("all traffic" if r["proto"] == "any" and r["dport"] == "any" else
            ("%s %s" % (r["proto"].upper() if r["proto"] != "any" else "TCP/UDP",
                        ("port " + r["dport"]) if r["dport"] != "any" else "(any port)")))
    src = "from " + _addr(r["src"], r["family"]) + ((" port " + r["sport"]) if r["sport"] != "any" else "")
    if r["route"]:
        s = "%s forwarded %s %s" % (verb, what, src)
        if r["in"]:
            s += " arriving on " + nm(r["in"])
        s += " to " + _addr(r["dst"], r["family"])
        if r["out"]:
            s += " leaving on " + nm(r["out"])
    elif r["dir"] == "out":
        s = "%s %s sent by this router to %s%s" % (verb, what, _addr(r["dst"], r["family"]),
                                                   (" on " + nm(r["out"])) if r["out"] else "")
    else:
        s = "%s %s %s%s to %s" % (verb, what, src, (" arriving on " + nm(r["in"])) if r["in"]
                                   else " on any interface", "this router" if G._any(r["dst"])
                                   else r["dst"])
    s += " (IPv4)" if r["family"] == "v4" else " (IPv6)"
    if r["action"] == "limit":
        s += "; more than 6 new connections in 30 s from one address are rejected"
    return s


# ── locating rules ──────────────────────────────────────────────────────────

def locate(rs, number):
    """(family, index) of a `ufw status numbered` number."""
    n = int(number)
    n4 = len(rs["blocks"]["v4"])
    if 1 <= n <= n4:
        return "v4", n - 1
    if n4 < n <= n4 + len(rs["blocks"]["v6"]):
        return "v6", n - 1 - n4
    raise EditError(404, "Rule %s not found" % number)


def twin_index(rs, fam, idx):
    """Index of the same rule in the other family (dual-stack twin), or None
    when absent/ambiguous."""
    r = rs["blocks"][fam][idx]["rule"]
    other = "v6" if fam == "v4" else "v4"
    def sig(x):
        return (x["route"], x["action"], x["proto"], x["dport"], x["sport"], x["in"], x["out"], x["dir"],
                x["comment"], G._any(x["src"]), G._any(x["dst"]))
    if not (G._any(r["src"]) and G._any(r["dst"])):
        return None
    hits = [i for i, b in enumerate(rs["blocks"][other]) if sig(b["rule"]) == sig(r)]
    return hits[0] if len(hits) == 1 else None


def _check_expect(rs, fam, idx, expect):
    if expect and rs["blocks"][fam][idx]["rule"]["key"] != expect:
        raise EditError(409, "The ruleset changed since the page was rendered (that rule moved). "
                             "Refresh and retry.", stale=True)


def _managed(rs, fam, idx, ctx, verb):
    c = G.classify_rule(rs["blocks"][fam][idx]["rule"], ctx)
    if c["managed"]:
        raise EditError(403, G.managed_refusal(c, verb), managed=True, owner=c["owner"],
                        owner_label=c["label"])
    return c


# ── proposals ───────────────────────────────────────────────────────────────

def propose_edit(rs, ctx, number, rule_text, expect=None, twin=True):
    fam, idx = locate(rs, number)
    _check_expect(rs, fam, idx, expect)
    _managed(rs, fam, idx, ctx, "edited")
    new = blocks_from_text(rule_text)
    if not new[fam]:
        raise EditError(400, "The new rule does not apply to %s; a rule can't change family in place"
                        % ("IPv4" if fam == "v4" else "IPv6"))
    bl = {"v4": list(rs["blocks"]["v4"]), "v6": list(rs["blocks"]["v6"])}
    old = bl[fam][idx]["rule"]
    bl[fam][idx] = {"tuple": new[fam]["tuple"], "body": new[fam]["body"]}
    changed = [(fam, idx)]
    other = "v6" if fam == "v4" else "v4"
    t = twin_index(rs, fam, idx) if twin else None
    if t is not None and new[other]:
        bl[other][t] = {"tuple": new[other]["tuple"], "body": new[other]["body"]}
        changed.append((other, t))
    prop = G.rebuild(rs, bl["v4"], bl["v6"])
    return prop, {"op": "edit", "old": [old], "changed": changed,
                  "new": [G.parse_tuple(bl[f][i]["tuple"], f, i) for f, i in changed]}


def propose_insert(rs, ctx, rule_text, before=None):
    """Insert a new rule. before=<number>: at that position of its family
    (ufw `insert N` semantics); None = append."""
    new = blocks_from_text(rule_text)
    bl = {"v4": list(rs["blocks"]["v4"]), "v6": list(rs["blocks"]["v6"])}
    pos = {}
    if before:
        f, i = locate(rs, before)
        pos[f] = i
    added = []
    keys = {r["key"] for r in rs["v4"] + rs["v6"]}
    for fam in ("v4", "v6"):
        b = new[fam]
        if not b:
            continue
        if G.parse_tuple(b["tuple"], fam)["key"] in keys:
            continue
        i = pos.get(fam, len(bl[fam]))
        bl[fam].insert(i, {"tuple": b["tuple"], "body": b["body"]})
        added.append(G.parse_tuple(b["tuple"], fam, i))
    if not added:
        raise EditError(409, "That rule already exists")
    return G.rebuild(rs, bl["v4"], bl["v6"]), {"op": "insert", "old": [], "new": added}


def propose_move_to(rs, ctx, number, to_number, expect=None):
    """Move a rule to another position within its family (findings fix for
    deny-before-allow ordering)."""
    fam, i = locate(rs, number)
    _check_expect(rs, fam, i, expect)
    _managed(rs, fam, i, ctx, "moved")
    f2, j = locate(rs, to_number)
    if f2 != fam:
        raise EditError(400, "Rules can only move within their own family list")
    bl = list(rs["blocks"][fam])
    b = bl.pop(i)
    bl.insert(j, b)
    prop = G.rebuild(rs, *((bl, None) if fam == "v4" else (None, bl)))
    return prop, {"op": "move", "old": [b["rule"]], "new": [], "from": i, "to": j, "family": fam}


def _did(fam, tuple_line):
    return hashlib.sha1((fam + tuple_line + str(time.time()) + uuid.uuid4().hex).encode()).hexdigest()[:10]


def load_disabled(ctx):
    d = ctx.json(DISABLED_FILE, {}) or {}
    rules = d.get("rules") if isinstance(d, dict) else None
    return [r for r in (rules or []) if isinstance(r, dict) and r.get("tuple")]


def disabled_text(rules):
    return json.dumps({"version": 1, "rules": rules}, indent=1) + "\n"


def propose_disable(rs, ctx, number, expect=None, twin=True, who=""):
    fam, idx = locate(rs, number)
    _check_expect(rs, fam, idx, expect)
    _managed(rs, fam, idx, ctx, "disabled")
    bl = {"v4": list(rs["blocks"]["v4"]), "v6": list(rs["blocks"]["v6"])}
    targets = [(fam, idx)]
    t = twin_index(rs, fam, idx) if twin else None
    if t is not None:
        targets.append(("v6" if fam == "v4" else "v4", t))
    group = uuid.uuid4().hex[:8]
    recs, old = [], []
    for f, i in targets:
        b = rs["blocks"][f][i]
        prev = rs["blocks"][f][i - 1]["tuple"] if i > 0 else ""
        recs.append({"id": _did(f, b["tuple"]), "group": group, "family": f, "tuple": b["tuple"],
                     "body": b["body"], "index": i, "after": prev, "text": b["rule"]["text"],
                     "comment": b["rule"]["comment"], "disabled_at": int(time.time()), "who": who})
        old.append(b["rule"])
    for f, i in sorted(targets, key=lambda x: -x[1]):
        del bl[f][i]
    prop = G.rebuild(rs, bl["v4"], bl["v6"])
    return prop, {"op": "disable", "old": old, "new": [], "records": recs}


def propose_enable(rs, ctx, rec_id):
    dis = load_disabled(ctx)
    rec = next((r for r in dis if r["id"] == rec_id), None)
    if rec is None:
        raise EditError(404, "Disabled rule not found")
    group = [r for r in dis if r.get("group") and r.get("group") == rec.get("group")] or [rec]
    bl = {"v4": list(rs["blocks"]["v4"]), "v6": list(rs["blocks"]["v6"])}
    added = []
    keys = {r["key"] for r in rs["v4"] + rs["v6"]}
    for r in group:
        f = r["family"]
        k = G.parse_tuple(r["tuple"], f)["key"]
        if k in keys:
            continue  # already back (added by hand)
        pos = None
        if r.get("after"):
            hit = [i for i, b in enumerate(bl[f]) if b["tuple"] == r["after"]]
            if hit:
                pos = hit[0] + 1
        if pos is None:
            pos = 0 if not r.get("after") else min(int(r.get("index") or 0), len(bl[f]))
        bl[f].insert(pos, {"tuple": r["tuple"], "body": list(r.get("body") or [])})
        added.append(G.parse_tuple(r["tuple"], f, pos))
    prop = G.rebuild(rs, bl["v4"], bl["v6"])
    remaining = [r for r in dis if r not in group]
    return prop, {"op": "enable", "old": [], "new": added, "remaining": remaining,
                  "ids": [r["id"] for r in group]}


# ── plan summary (shared by preview and apply) ──────────────────────────────

def describe(rs, prop, info, ctx):
    """Plain-language preview + guard + file diff summary."""
    guard = G.check(rs, prop, ctx)
    lines = []
    for r in info.get("old") or []:
        lines.append({"kind": "remove" if info["op"] in ("edit", "disable") else "move",
                      "text": r["text"], "plain": plain(r, ctx), "family": r["family"]})
    for r in info.get("new") or []:
        lines.append({"kind": "add", "text": r["text"], "plain": plain(r, ctx), "family": r["family"]})
    lock = [x for x in guard["new"] + guard["existing"] if x["id"] == "lockout"]
    writes = [k for k in ("user.rules", "user6.rules") if prop["texts"][k] != rs["texts"][k]]
    return {"ok": True, "op": info["op"], "guard": guard, "changes": lines,
            "writes": writes, "no_changes": not writes,
            "lockout_warning": (lock[0]["detail"] if lock else
                                "Your session %s via %s keeps access to the dashboard."
                                % (ctx.client_ip or "?", ctx.client_iface or "?")),
            "actions": (["auto snapshot (revert point)"] + ["write /etc/ufw/" + k for k in writes] +
                        ["ufw reload", "confirm within 60 s or the previous rules come back"]) if writes else []}
