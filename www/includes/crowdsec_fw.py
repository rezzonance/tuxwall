"""CrowdSec firewall bouncer: which backend enforces the bans, its live state,
and TuxWall's corrections for the nftables backend.

The bouncer (crowdsec-firewall-bouncer) runs in one of two managed modes:

- iptables: ipsets ``<blacklists>-<n>`` + a CROWDSEC_CHAIN jump at the top of
  the configured iptables chains (INPUT). ipset caps timeouts at 2147483 s
  (~24.8 days), so longer bans silently fall out of the kernel.
- nftables: its own ``ip <table>`` / ``ip6 <table6>`` tables, one base chain
  ``<chain>-<hook>`` per configured hook (filter type, the configured
  priority, policy accept) and one timeout set ``<blacklists>-<origin>`` per
  decision origin, each with a ``saddr @set counter drop`` rule. Element
  timeouts are the full decision duration.

Two bouncer (v0.0.38) behaviours need a correction in nftables mode; the
TuxWall API runs ``reconcile()`` periodically for that:

1. An IP already present in ANY set is skipped when a new decision arrives,
   so a later, LONGER ban (a 1-year honeypot ban for an IP the community
   list holds for 7 days, CAPI renewals, the custom-blocklist refresh) never
   extends the element. It lapses with the shorter ban and the IP stays
   unenforced until the bouncer restarts. ``refresh_plan()`` finds elements
   expiring well before the longest active ban for their IP and
   ``render_refresh()`` re-times them with an atomic delete+add - the batch
   aborts if an element vanished meanwhile, so an IP the bouncer has just
   lifted is never resurrected. An element that lapsed although its ban is
   still active is re-added (``lapsed_plan()``).
2. Range decisions are truncated to their first address (the sets have no
   interval flag). TuxWall enforces them in its own table
   ``inet tuxwall_crowdsec_ranges`` (interval+timeout sets, input hook at the
   bouncer's priority), rebuilt from the active Range bans.

In iptables mode ipset hash:net holds ranges and ``add -exist`` re-times
entries, so neither correction applies (the range table is removed).

Pure helpers take text/JSON; I/O goes through an injected ``run(cmd)`` /
``run_in(cmd, text)`` and a CrowdSec SQLite path, so tests use fixtures.
"""
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import time

BOUNCER_CONFIG = "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
CROWDSEC_CONFIG = "/etc/crowdsec/config.yaml"
DEFAULT_DB = "/var/lib/crowdsec/data/crowdsec.db"
BOUNCER_UNIT = "crowdsec-firewall-bouncer"
NFT_FAMILY = {"v4": "ip", "v6": "ip6"}
RANGE_TABLE = "tuxwall_crowdsec_ranges"          # family inet, owned by TuxWall
RANGE_SETS = {"v4": "ranges4", "v6": "ranges6"}
RANGE_CHAIN = "input"
REFRESH_SLACK = 3600       # re-time elements expiring >1 h before their longest ban
BATCH = 400                # elements per nft transaction
UFW_FILTER_PRIORITY = 0    # iptables-nft (ufw) base chains: "priority filter"


# ── bouncer config ───────────────────────────────────────────────────────────

def _scalar(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("", "~", "null"):
        return None
    if re.match(r"^-?\d+$", v):
        return int(v)
    return v


def _mini_yaml(text):
    """Block-style maps / lists of scalars (all the bouncer config uses);
    only when PyYAML is unavailable."""
    root = {}
    stack = [(-1, root)]
    lines = []
    for raw in (text or "").splitlines():
        s = raw.split(" #")[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if s.strip():
            lines.append(s)
    for i, line in enumerate(lines):
        ind = len(line) - len(line.lstrip())
        body = line.strip()
        while stack and ind <= stack[-1][0] and len(stack) > 1:
            stack.pop()
        parent = stack[-1][1]
        if body.startswith("- "):
            if isinstance(parent, list):
                parent.append(_scalar(body[2:]))
            continue
        if ":" not in body:
            continue
        key, _, val = body.partition(":")
        key = key.strip()
        if not isinstance(parent, dict):
            continue
        if val.strip():
            parent[key] = _scalar(val)
            continue
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        nind = len(nxt) - len(nxt.lstrip())
        child = [] if nxt.strip().startswith("- ") and nind >= ind else {}
        parent[key] = child
        stack.append((ind, child))
    return root


def _yaml(text):
    if not (text or "").strip():
        return {}
    try:
        import yaml
        d = yaml.safe_load(text)
        return d if isinstance(d, dict) else {}
    except ImportError:
        return _mini_yaml(text)
    except Exception:
        return {}


def _merge(a, b):
    out = dict(a)
    for k, v in (b or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def bouncer_config(text, local_text=""):
    """Effective bouncer settings (defaults as in the bouncer's cfg package).
    mode: "iptables" | "nftables" | "ipset" | "pf" | "" (unknown/absent)."""
    d = _merge(_yaml(text), _yaml(local_text))
    mode = str(d.get("mode") or "").strip().lower()
    chains = [str(c) for c in (d.get("iptables_chains") or []) if c] or ["INPUT"]
    nft = d.get("nftables") if isinstance(d.get("nftables"), dict) else {}
    fams = {}
    for fam, key, tdef, cdef, blkey, bldef, dis in (
            ("v4", "ipv4", "crowdsec", "crowdsec-chain", "blacklists_ipv4", "crowdsec-blacklists",
             bool(d.get("disable_ipv4"))),
            ("v6", "ipv6", "crowdsec6", "crowdsec6-chain", "blacklists_ipv6", "crowdsec6-blacklists",
             bool(d.get("disable_ipv6")))):
        f = nft.get(key) if isinstance(nft.get(key), dict) else {}
        en = f.get("enabled")
        try:
            prio = int(f.get("priority") or 0)
        except (TypeError, ValueError):
            prio = 0
        fams[fam] = {"enabled": (not dis) if en is None else bool(en),
                     "set_only": bool(f.get("set-only")),
                     "family": NFT_FAMILY[fam],
                     "table": str(f.get("table") or tdef),
                     "chain": str(f.get("chain") or cdef),
                     "priority": prio,
                     "blacklist": str(d.get(blkey) or bldef)}
    hooks = [str(h) for h in (d.get("nftables_hooks") or []) if h] or ["input"]
    return {"present": bool(d), "mode": mode, "iptables_chains": chains, "nft": fams,
            "hooks": hooks, "deny_action": str(d.get("deny_action") or "DROP").upper()}


def read_bouncer_config(read=None):
    def _rd(p):
        try:
            with open(p, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""
    read = read or _rd
    return bouncer_config(read(BOUNCER_CONFIG), read(BOUNCER_CONFIG + ".local"))


# ── nft JSON ─────────────────────────────────────────────────────────────────

def nft_objects(text):
    """`nft -j ...` output -> list of {kind: body} (metainfo dropped)."""
    try:
        doc = json.loads(text or "")
    except ValueError:
        return []
    items = doc.get("nftables") if isinstance(doc, dict) else None
    return [o for o in (items or []) if isinstance(o, dict) and "metainfo" not in o]


def _norm_ip(text):
    try:
        return str(ipaddress.ip_address(str(text)))
    except ValueError:
        return str(text)


def _elem_key(val):
    if isinstance(val, dict):
        if "prefix" in val:
            p = val["prefix"]
            try:
                return str(ipaddress.ip_network("%s/%s" % (p.get("addr"), p.get("len")), strict=False))
            except ValueError:
                return "%s/%s" % (p.get("addr"), p.get("len"))
        if "range" in val and isinstance(val["range"], list) and len(val["range"]) == 2:
            return "%s-%s" % tuple(_norm_ip(x) for x in val["range"])
        return json.dumps(val, sort_keys=True)
    return _norm_ip(val)


def set_elements(set_obj):
    """{key: expires_seconds | None} of a JSON set object."""
    out = {}
    for e in set_obj.get("elem") or []:
        if isinstance(e, dict) and "elem" in e:
            body = e["elem"]
            exp = body.get("expires")
            if exp is None and body.get("timeout") is not None:
                exp = body.get("timeout")
            out[_elem_key(body.get("val"))] = int(exp) if exp is not None else None
        else:
            out[_elem_key(e)] = None
    return out


def _rule_info(rule):
    sets, counters, verdict = [], [], ""
    for ex in rule.get("expr") or []:
        if not isinstance(ex, dict):
            continue
        m = ex.get("match")
        if isinstance(m, dict) and isinstance(m.get("right"), str) and m["right"].startswith("@"):
            sets.append(m["right"][1:])
        if isinstance(ex.get("counter"), str):
            counters.append(ex["counter"])
        for v in ("drop", "reject", "accept"):
            if v in ex:
                verdict = v
    return {"sets": sets, "counters": counters, "verdict": verdict}


def parse_table(objs):
    """Objects of `nft -j [-t] list table F T` -> {chains, sets, rules, counters}."""
    t = {"present": False, "chains": {}, "sets": {}, "rules": [], "counters": {}}
    for o in objs:
        if "table" in o:
            t["present"] = True
        elif "chain" in o:
            c = o["chain"]
            t["chains"][c.get("name")] = {"name": c.get("name"), "hook": c.get("hook"),
                                          "prio": c.get("prio"), "policy": c.get("policy"),
                                          "type": c.get("type")}
        elif "set" in o:
            s = o["set"]
            t["sets"][s.get("name")] = {"name": s.get("name"), "type": s.get("type"),
                                        "flags": list(s.get("flags") or []),
                                        "elements": set_elements(s)}
        elif "rule" in o:
            r = o["rule"]
            info = _rule_info(r)
            info["chain"] = r.get("chain")
            t["rules"].append(info)
        elif "counter" in o:
            c = o["counter"]
            t["counters"][c.get("name")] = {"packets": int(c.get("packets") or 0),
                                            "bytes": int(c.get("bytes") or 0)}
    return t


def list_table(run, family, table, terse=True):
    """Parsed table, or None when it does not exist / nft is unavailable."""
    cmd = ["nft", "-j"] + (["-t"] if terse else []) + ["list", "table", family, table]
    try:
        rc, out = run(cmd)
    except Exception:
        return None
    if rc != 0:
        return None
    t = parse_table(nft_objects(out))
    return t if t["present"] else None


# ── live status / invariants input ───────────────────────────────────────────

def nft_family_state(cfg, fam, table):
    """Evaluate one family's bouncer table against the config.
    table: parse_table() result or None. Returns a status dict with
    problems [{id, severity, title, detail}]."""
    f = cfg["nft"][fam]
    st = {"family": f["family"], "table": f["table"], "present": table is not None,
          "hooks": [], "sets": {}, "rules": 0, "dropped": 0, "processed": 0, "problems": []}
    if not f["enabled"]:
        st["enabled"] = False
        return st
    st["enabled"] = True
    if table is None:
        st["problems"].append({"id": "crowdsec-nft-missing:%s" % fam, "severity": "high",
                               "title": "CrowdSec nftables table %s %s is missing" % (f["family"], f["table"]),
                               "detail": "The bouncer is in nftables mode but its %s table does not exist: "
                                         "no %s bans are enforced." % (f["table"], fam)})
        return st
    if f["set_only"]:
        return st
    for hook in cfg["hooks"]:
        name = "%s-%s" % (f["chain"], hook)
        c = table["chains"].get(name)
        if not c or c.get("hook") != hook:
            st["problems"].append({"id": "crowdsec-nft-hook-missing:%s:%s" % (fam, hook), "severity": "high",
                                   "title": "CrowdSec %s hook missing (%s)" % (hook, fam),
                                   "detail": "Chain %s in %s %s is missing or not hooked to %s."
                                             % (name, f["family"], f["table"], hook)})
            continue
        st["hooks"].append({"chain": name, "hook": hook, "prio": c.get("prio"), "policy": c.get("policy")})
        if str(c.get("policy") or "accept") != "accept":
            st["problems"].append({"id": "crowdsec-nft-policy:%s:%s" % (fam, hook), "severity": "high",
                                   "title": "CrowdSec %s chain policy is %s (%s)" % (hook, c.get("policy"), fam),
                                   "detail": "The bouncer chain must only drop banned sources (policy accept)."})
        try:
            prio = int(c.get("prio"))
        except (TypeError, ValueError):
            prio = None
        if prio is None or prio >= UFW_FILTER_PRIORITY:
            st["problems"].append({"id": "crowdsec-nft-priority:%s:%s" % (fam, hook), "severity": "medium",
                                   "title": "CrowdSec %s chain does not run before ufw (%s)" % (hook, fam),
                                   "detail": "Priority %s; ufw's iptables-nft chains use priority filter (0). "
                                             "Bans still drop (drop is final), but after ufw logging/limits. "
                                             "Set nftables.%s.priority to -10."
                                             % (c.get("prio"), "ipv4" if fam == "v4" else "ipv6")})
    for name, s in table["sets"].items():
        if name.startswith(f["blacklist"] + "-"):
            st["sets"][name] = len(s["elements"])
    st["rules"] = sum(1 for r in table["rules"] if r["sets"] and r["verdict"] in ("drop", "reject"))
    for name, c in table["counters"].items():
        if name == "processed":
            st["processed"] = c["packets"]
        elif name in table["sets"]:
            st["dropped"] += c["packets"]
    return st


def status(run, cfg=None, terse=True):
    """Live enforcement status. terse=True skips set elements (cheap)."""
    cfg = cfg or read_bouncer_config()
    out = {"mode": cfg["mode"], "hooks": cfg["hooks"], "families": {}}
    if cfg["mode"] != "nftables":
        return out
    for fam, f in cfg["nft"].items():
        tbl = list_table(run, f["family"], f["table"], terse=terse) if f["enabled"] else None
        st = nft_family_state(cfg, fam, tbl)
        if terse:   # a terse listing has no elements: sizes unknown, not zero
            st["sets"] = {k: None for k in st["sets"]}
        out["families"][fam] = st
    return out


# ── CrowdSec decisions (SQLite, read only) ───────────────────────────────────

def db_path(read=None):
    """SQLite path from the CrowdSec config, or None (other DB backends)."""
    try:
        if read:
            text = read(CROWDSEC_CONFIG)
        else:
            with open(CROWDSEC_CONFIG, "r", errors="replace") as f:
                text = f.read()
    except OSError:
        return DEFAULT_DB if os.path.exists(DEFAULT_DB) else None
    d = _yaml(text)
    db = d.get("db_config") if isinstance(d.get("db_config"), dict) else {}
    if str(db.get("type") or "sqlite").lower() not in ("sqlite", "sqlite3"):
        return None
    return str(db.get("db_path") or DEFAULT_DB)


def active_bans(path, now=None, values=None):
    """Longest active ban per value: {"ip": {ip: (until, origin)},
    "range": {cidr: (until, origin)}}. values: optional list to restrict to."""
    now = time.time() if now is None else now
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now))
    db = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=10)
    try:
        q = ("select value, lower(scope), "
             "cast(strftime('%s', substr(max(until), 1, 19)) as integer), origin "
             "from decisions where type = 'ban' and simulated = 0 and until > ?")
        args = [stamp]
        if values:
            q += " and value in (%s)" % ",".join("?" * len(values))
            args += list(values)
        q += " group by value, lower(scope)"
        rows = db.execute(q, args).fetchall()
    finally:
        db.close()
    out = {"ip": {}, "range": {}}
    for value, scope, until, origin in rows:
        if until is None:
            continue
        try:
            if scope == "range":
                key, kind = str(ipaddress.ip_network(value, strict=False)), "range"
            else:
                key, kind = str(ipaddress.ip_address(str(value).split("/")[0])), "ip"
        except ValueError:
            continue
        prev = out[kind].get(key)
        if prev is None or until > prev[0]:
            out[kind][key] = (int(until), origin or "")
    return out


# ── nftables corrections ─────────────────────────────────────────────────────

def refresh_plan(sets_by_fam, bans_ip, now, slack=REFRESH_SLACK):
    """Elements expiring > slack before their IP's longest active ban.
    sets_by_fam: {fam: {set: {ip: expires_s|None}}}; bans_ip: {ip: (until, origin)}.
    -> [(fam, set, ip, timeout_s)]"""
    items = []
    for fam in sorted(sets_by_fam):
        for sname in sorted(sets_by_fam[fam]):
            for ip, exp in sets_by_fam[fam][sname].items():
                ban = bans_ip.get(ip)
                if ban is None or exp is None:
                    continue
                want = int(ban[0] - now)
                if want - exp > slack:
                    items.append((fam, sname, ip, want))
    return items


def lapsed_plan(prev, cur_keys, bans_ip, now, slack=REFRESH_SLACK):
    """Elements seen last pass that have since EXPIRED (not been deleted:
    their recorded expiry is in the past) while their IP still has an active
    ban for longer than slack. prev: {(fam, set, ip): expires_at_epoch}.
    -> [(fam, set, ip, timeout_s)]"""
    items = []
    for key in sorted(prev):
        if key in cur_keys:
            continue
        fam, sname, ip = key
        exp_at = prev[key]
        ban = bans_ip.get(ip)
        if exp_at is None or exp_at > now + 5 or ban is None:
            continue
        want = int(ban[0] - now)
        if want > slack:
            items.append((fam, sname, ip, want))
    return items


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def render_refresh(family, table, sname, items):
    """One atomic nft transaction re-timing [(ip, timeout_s)] in set sname:
    delete (fails -> whole batch aborts if any element vanished) + add."""
    ips = ", ".join(ip for ip, _ in items)
    adds = ", ".join("%s timeout %ds" % (ip, max(1, t)) for ip, t in items)
    return ("delete element %s %s %s { %s }\nadd element %s %s %s { %s }\n"
            % (family, table, sname, ips, family, table, sname, adds))


def render_add(family, table, sname, items):
    adds = ", ".join("%s timeout %ds" % (ip, max(1, t)) for ip, t in items)
    return "add element %s %s %s { %s }\n" % (family, table, sname, adds)


def _apply_set_batches(run_in, family, table, plan, render):
    """plan: [(fam, set, ip, timeout)]; batches per set, a failed batch is
    retried element by element. -> (applied, failed)"""
    by_set = {}
    for _fam, sname, ip, t in plan:
        by_set.setdefault(sname, []).append((ip, t))
    ok = bad = 0
    for sname, items in sorted(by_set.items()):
        for chunk in _chunks(items, BATCH):
            rc, _ = run_in(["nft", "-f", "-"], render(family, table, sname, chunk))
            if rc == 0:
                ok += len(chunk)
                continue
            for one in chunk:
                rc1, _ = run_in(["nft", "-f", "-"], render(family, table, sname, [one]))
                if rc1 == 0:
                    ok += 1
                else:
                    bad += 1
    return ok, bad


def range_plan(ranges, now, families=("v4", "v6")):
    """Active Range bans -> {fam: [(cidr, timeout_s)]}, dropping ranges inside
    another listed range that lasts at least as long (interval sets reject
    overlaps)."""
    nets = []
    for cidr, (until, _o) in ranges.items():
        try:
            nets.append((ipaddress.ip_network(cidr, strict=False), int(until - now)))
        except ValueError:
            continue
    nets = [n for n in nets if n[1] > 0]
    nets.sort(key=lambda n: (n[0].version, n[0].prefixlen, str(n[0])))
    kept = []
    for net, t in nets:
        if any(k.version == net.version and net.subnet_of(k) and kt >= t for k, kt in kept):
            continue
        if any(k.version == net.version and net.overlaps(k) for k, _ in kept):
            continue    # partial overlap with a shorter container: the container wins
        kept.append((net, t))
    out = {fam: [] for fam in families}
    for net, t in kept:
        fam = "v4" if net.version == 4 else "v6"
        if fam in out:
            out[fam].append((str(net), t))
    return out


def render_range_table(priority, deny_action, plan, families=("v4", "v6")):
    """Whole TuxWall range table in one transaction (idempotent: declares,
    then flushes chain + sets and refills them)."""
    verdict = "reject with icmpx admin-prohibited" if deny_action == "REJECT" else "drop"
    t = RANGE_TABLE
    lines = ["add table inet %s" % t]
    for fam, typ in (("v4", "ipv4_addr"), ("v6", "ipv6_addr")):
        lines.append("add set inet %s %s { type %s; flags interval, timeout; }" % (t, RANGE_SETS[fam], typ))
    lines.append("add chain inet %s %s { type filter hook input priority %d; policy accept; }"
                 % (t, RANGE_CHAIN, int(priority)))
    lines.append("flush chain inet %s %s" % (t, RANGE_CHAIN))
    for fam, sel in (("v4", "ip saddr"), ("v6", "ip6 saddr")):
        lines.append("flush set inet %s %s" % (t, RANGE_SETS[fam]))
        if fam in families:
            lines.append("add rule inet %s %s %s @%s counter %s comment \"tuxwall: CrowdSec Range bans\""
                         % (t, RANGE_CHAIN, sel, RANGE_SETS[fam], verdict))
    for fam in families:
        items = plan.get(fam) or []
        for chunk in _chunks(items, BATCH):
            lines.append("add element inet %s %s { %s }" % (
                t, RANGE_SETS[fam], ", ".join("%s timeout %ds" % (c, max(1, s)) for c, s in chunk)))
    return "\n".join(lines) + "\n"


def range_table_matches(table, priority, plan, now_slack=REFRESH_SLACK):
    """True when the live range table already enforces plan (no rewrite)."""
    if table is None:
        return False
    c = table["chains"].get(RANGE_CHAIN)
    if not c or c.get("hook") != "input" or c.get("prio") != int(priority) or c.get("policy") != "accept":
        return False
    for fam in ("v4", "v6"):
        want = dict(plan.get(fam) or [])
        if want and not any(RANGE_SETS[fam] in r["sets"] for r in table["rules"]):
            return False
        have = (table["sets"].get(RANGE_SETS[fam]) or {}).get("elements")
        if have is None:
            return False
        if set(have) != set(want):
            return False
        for cidr, t in want.items():
            exp = have.get(cidr)
            if exp is None or t - exp > now_slack:
                return False
    return True


def _default_run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or ""
    except Exception as exc:
        return 127, str(exc)


def _default_run_in(cmd, text, timeout=60):
    try:
        p = subprocess.run(cmd, input=text, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return 127, str(exc)


def reconcile(state, run=None, run_in=None, cfg=None, db=None, now=None, dry_run=False):
    """One pass. state: dict kept by the caller between passes ("prev").
    Returns a summary; never raises for expected conditions."""
    run = run or _default_run
    run_in = run_in or _default_run_in
    cfg = cfg or read_bouncer_config()
    now = time.time() if now is None else now
    out = {"at": now, "mode": cfg["mode"], "families": {}, "refreshed": 0, "refresh_failed": 0,
           "readded": 0, "ranges": 0, "range_table": "absent", "errors": []}
    rt = list_table(run, "inet", RANGE_TABLE, terse=True)
    if cfg["mode"] != "nftables":
        state.pop("prev", None)
        if rt is not None and not dry_run:
            rc, msg = run_in(["nft", "-f", "-"], "delete table inet %s\n" % RANGE_TABLE)
            out["range_table"] = "removed" if rc == 0 else "remove-failed"
            if rc != 0:
                out["errors"].append("delete range table: %s" % msg.strip()[:200])
        return out
    db = db if db is not None else db_path()
    if not db or not os.path.exists(db):
        out["errors"].append("CrowdSec database unavailable (only SQLite is supported)")
        return out
    try:
        bans = active_bans(db, now)
    except Exception as exc:
        out["errors"].append("decisions query failed: %r" % exc)
        return out
    out["bans"] = {"ip": len(bans["ip"]), "range": len(bans["range"])}
    sets_by_fam, cur_keys, tables = {}, {}, {}
    for fam, f in cfg["nft"].items():
        if not f["enabled"] or f["set_only"]:
            continue
        tbl = list_table(run, f["family"], f["table"], terse=False)
        tables[fam] = tbl
        st = nft_family_state(cfg, fam, tbl)
        st.pop("problems", None)
        out["families"][fam] = st
        if tbl is None:
            continue
        sets_by_fam[fam] = {n: s["elements"] for n, s in tbl["sets"].items()
                            if n.startswith(f["blacklist"] + "-")}
        for sname, els in sets_by_fam[fam].items():
            for ip, exp in els.items():
                cur_keys[(fam, sname, ip)] = None if exp is None else now + exp
    present = {ip for (_f, _s, ip) in cur_keys}
    out["missing"] = sum(1 for ip, (until, _o) in bans["ip"].items()
                         if ip not in present and until - now > REFRESH_SLACK
                         and cfg["nft"]["v6" if ":" in ip else "v4"]["enabled"])
    refresh = refresh_plan(sets_by_fam, bans["ip"], now)
    lapsed = lapsed_plan(state.get("prev") or {}, cur_keys, bans["ip"], now)
    out["refresh_planned"], out["lapsed_planned"] = len(refresh), len(lapsed)
    if not dry_run:
        for fam in sorted(sets_by_fam):
            f = cfg["nft"][fam]
            ok, bad = _apply_set_batches(run_in, f["family"], f["table"],
                                         [x for x in refresh if x[0] == fam], render_refresh)
            out["refreshed"] += ok
            out["refresh_failed"] += bad
            for x in refresh:
                if x[0] == fam and (fam, x[1], x[2]) in cur_keys:
                    cur_keys[(fam, x[1], x[2])] = now + x[3]
            lap = [x for x in lapsed if x[0] == fam and x[1] in sets_by_fam[fam]]
            if lap:
                # re-check right before adding: never re-add a ban lifted meanwhile
                fresh = active_bans(db, time.time(), values=[x[2] for x in lap])["ip"]
                lap = [x for x in lap if x[2] in fresh]
                ok, _bad = _apply_set_batches(run_in, f["family"], f["table"], lap, render_add)
                out["readded"] += ok
                for x in lap:
                    cur_keys[(fam, x[1], x[2])] = now + x[3]
    state["prev"] = cur_keys
    fams = tuple(fam for fam in ("v4", "v6") if cfg["nft"][fam]["enabled"])
    rplan = range_plan(bans["range"], now, fams)
    out["ranges"] = sum(len(v) for v in rplan.values())
    prio = cfg["nft"]["v4"]["priority"] if cfg["nft"]["v4"]["enabled"] else cfg["nft"]["v6"]["priority"]
    if out["ranges"] == 0:
        if rt is not None and not dry_run:
            rc, msg = run_in(["nft", "-f", "-"], "delete table inet %s\n" % RANGE_TABLE)
            out["range_table"] = "removed" if rc == 0 else "remove-failed"
        return out
    rt_full = list_table(run, "inet", RANGE_TABLE, terse=False) if rt is not None else None
    if range_table_matches(rt_full, prio, rplan):
        out["range_table"] = "ok"
    elif not dry_run:
        rc, msg = run_in(["nft", "-f", "-"], render_range_table(prio, cfg["deny_action"], rplan, fams))
        out["range_table"] = "written" if rc == 0 else "write-failed"
        if rc != 0:
            out["errors"].append("range table: %s" % msg.strip()[:300])
    else:
        out["range_table"] = "would-write"
    return out
