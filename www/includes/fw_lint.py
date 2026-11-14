"""TuxWall firewall findings (lint) and suggestions.

Pure: reads through fw_guard.Ctx (file root + read-only runner), so tests use
fixtures. Nothing here changes the firewall; every fix is a *plan* that the UI
previews through the guarded edit flow (fw_edit + fw_snap.apply_files) or a
link to the page that owns the rule.

finding = {id, severity, title, detail, rules:[{number, family, text, key}],
           raw:[lines], fix:{kind, ...} | None, category, explain}
"""
import ipaddress
import re
import time

import fw_guard as G

try:
    import canary_egress as CE
except ImportError:  # pragma: no cover
    CE = None

SEV_RANK = {s: i for i, s in enumerate(G.SEVERITIES)}
RISKY_FORWARD = {21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL",
                 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
                 6379: "Redis", 9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB", 161: "SNMP"}
ZERO_HIT_DAYS = 7
NOISE_PORTS = {67, 68, 137, 138, 139, 1900, 5353, 5355, 3702}
LOG_RE = re.compile(r"^(?P<ts>\S+)\s+\S+\s+kernel:.*?\[UFW (?P<action>BLOCK|ALLOW|AUDIT)\]\s+IN=(?P<in>\S*)\s+OUT=(?P<out>\S*)"
                    r".*?SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)(?:\s+SPT=(?P<spt>\d+))?"
                    r"(?:\s+DPT=(?P<dpt>\d+))?")


# ── helpers ─────────────────────────────────────────────────────────────────

def numbers(rs):
    """{(family, index): ufw status number}"""
    n4 = len(rs["v4"])
    out = {("v4", i): i + 1 for i in range(n4)}
    out.update({("v6", i): n4 + i + 1 for i in range(len(rs["v6"]))})
    return out


def ref(rs, r):
    num = numbers(rs).get((r["family"], r["index"]))
    return {"number": num, "family": r["family"], "text": r["text"], "key": r["key"]}


def _f(fid, severity, title, detail="", rules=None, fix=None, category="", raw=None, explain=None):
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "rules": rules or [],
            "raw": raw or [], "fix": fix, "category": category, "explain": explain}


def _net(a):
    try:
        return ipaddress.ip_network(a, strict=False)
    except ValueError:
        return None


def _net_covers(a, b):
    if G._any(a):
        return True
    if G._any(b):
        return False
    na, nb = _net(a), _net(b)
    if na is None or nb is None or na.version != nb.version:
        return a == b
    return nb.subnet_of(na)


def _ports_cover(a, b):
    pa, pb = G._ports(a), G._ports(b)
    if pa is None:
        return True
    if pb is None:
        return False
    return pb <= pa


def covers(a, b):
    """Rule a matches every packet rule b matches (same chain)."""
    if a["route"] != b["route"] or a["dir"] != b["dir"] or a.get("app") or b.get("app"):
        return False
    if a["in"] and a["in"] != b["in"]:
        return False
    if a["out"] and a["out"] != b["out"]:
        return False
    if a["proto"] != "any" and a["proto"] != b["proto"]:
        return False
    if a["proto"] == "any" and b["proto"] not in ("any", "tcp", "udp") and a["dport"] != "any":
        return False
    return (_ports_cover(a["dport"], b["dport"]) and _ports_cover(a["sport"], b["sport"])
            and _net_covers(a["src"], b["src"]) and _net_covers(a["dst"], b["dst"]))


def verdict(action):
    return "accept" if action in ("allow", "limit") else "drop"


def zones(ctx):
    """[(name, device, network|None, kind)] from interfaces.json."""
    t = ctx.topo or {}
    out = []
    if (t.get("wan") or {}).get("device") or ctx.wan:
        out.append(("WAN", (t.get("wan") or {}).get("device") or ctx.wan, None, "wan"))
    lan = t.get("lan") or {}
    if lan.get("device"):
        out.append(("LAN", lan["device"], lan.get("address"), "lan"))
    for o in t.get("opt") or []:
        if o.get("device"):
            out.append((o.get("name") or o.get("id") or o["device"], o["device"], o.get("address"), "opt"))
    for v in t.get("vpn") or []:
        if v.get("device"):
            out.append((v.get("name") or v["device"], v["device"], v.get("address"), "vpn"))
    if not any(z[1] == ctx.wg["iface"] for z in out) and ctx.read("/etc/wireguard/wg0.conf"):
        out.append(("WireGuard", ctx.wg["iface"], (ctx.wg["nets"] or [None])[0], "vpn"))
    return out


def zone_name(ctx, dev):
    for name, d, _n, _k in zones(ctx):
        if d == dev:
            return "%s (%s)" % (name, dev)
    return dev


def evaluate_route(rules, defaults, iin, iout):
    """First match for a generic forwarded packet (any address/port) in -> out."""
    for r in rules:
        if not r["route"] or r.get("app"):
            continue
        if r["in"] and r["in"] != iin:
            continue
        if r["out"] and r["out"] != iout:
            continue
        if r["proto"] != "any" or r["dport"] != "any" or r["sport"] != "any":
            continue
        if not (G._any(r["src"]) and G._any(r["dst"])):
            continue
        return verdict(r["action"]) == "accept", r
    return defaults.get("forward", "DROP") == "ACCEPT", None


def kea_reservations(ctx):
    txt = ctx.read("/etc/kea/kea-dhcp4.conf")
    return set(re.findall(r'"ip-address"\s*:\s*"([0-9.]+)"', txt))


def kea_leases(ctx):
    out = set()
    now = time.time()
    for line in ctx.read("/var/lib/kea/kea-leases4.csv").splitlines()[1:]:
        f = line.split(",")
        if len(f) > 4:
            try:
                if int(f[4]) > now:
                    out.add(f[0])
            except ValueError:
                pass
    return out


def existing_ifaces(ctx):
    rc, out = ctx.run(["ip", "-o", "link", "show"])
    if rc != 0 or not out:
        return None
    names = set()
    for l in out.splitlines():
        m = re.match(r"^\d+:\s+([^:@\s]+)", l)
        if m:
            names.add(m.group(1))
    return names


# ── findings ────────────────────────────────────────────────────────────────

def _invariant_rules(rs, v):
    key = v["id"].split(":", 1)[1] if ":" in v["id"] else ""
    return [ref(rs, r) for r in rs["v4"] + rs["v6"] if key and r["key"] == key]


def _fix_from_repair(rep):
    if not rep:
        return None
    k = rep.get("kind")
    if k == "ufw-add":
        return {"kind": "plan", "op": "insert", "rule": rep["rule"], "label": "Add the rule"}
    if k == "default":
        return {"kind": "link", "href": "#firewall/settings", "label": "Firewall → Settings",
                "steps": ["Set the default %s policy to %s" % (rep["direction"], rep["policy"])]}
    if k == "before-rules-insert":
        return {"kind": "manual", "label": "Insert the containment (preview)", "diff": rep.get("diff", ""),
                "steps": ["sudo python3 /var/www/html/includes/canary_egress.py --apply"
                          "   (inserts the block above before the lo-ACCEPT anchor and reloads ufw)"]}
    if k == "run":
        return {"kind": "manual", "label": "Run", "steps": [" ".join(rep.get("cmd") or [])]}
    if k == "bouncer-restart":
        return {"kind": "manual", "label": "Restart the bouncer",
                "steps": ["sudo systemctl restart crowdsec-firewall-bouncer"]}
    return None


def _shadow_findings(rs, ctx, cls):
    out = []
    nums = numbers(rs)
    for fam in ("v4", "v6"):
        rules = rs[fam]
        unreach = {}   # shadowing rule index -> [shadowed rules]
        for j, b in enumerate(rules):
            for i in range(j):
                a = rules[i]
                if not covers(a, b):
                    continue
                cb = cls[(fam, j)]
                if verdict(a["action"]) != verdict(b["action"]):
                    unreach.setdefault(i, []).append(b)
                elif a["key"] == b["key"]:
                    if not cb["managed"]:
                        out.append(_f("duplicate:%s:%d" % (b["key"], j), "low",
                                      "Duplicate rule #%d (same as #%d)" % (nums[(fam, j)], nums[(fam, i)]),
                                      "%s appears twice; the second copy never matches." % b["text"],
                                      [ref(rs, b), ref(rs, a)],
                                      {"kind": "plan", "op": "disable", "number": nums[(fam, j)],
                                       "expect": b["key"], "label": "Disable the duplicate"}, "order"))
                elif not cb["managed"] and not (a["action"] == "allow" and b["action"] == "limit"):
                    out.append(_f("redundant:%s" % b["key"], "low",
                                  "Rule #%d never matters: #%d already %s it" % (
                                      nums[(fam, j)], nums[(fam, i)],
                                      "allows" if verdict(a["action"]) == "accept" else "blocks"),
                                  "#%d %s\ncovered by #%d %s" % (nums[(fam, j)], b["text"], nums[(fam, i)], a["text"]),
                                  [ref(rs, b), ref(rs, a)],
                                  {"kind": "plan", "op": "disable", "number": nums[(fam, j)],
                                   "expect": b["key"], "label": "Disable #%d (reversible)" % nums[(fam, j)]},
                                  "order"))
                elif a["action"] == "allow" and b["action"] == "limit" and not cb["managed"]:
                    out.append(_f("limit-shadowed:%s" % b["key"], "medium",
                                  "Rate limit on #%d never applies" % nums[(fam, j)],
                                  "#%d %s allows the same traffic first, without a limit." % (nums[(fam, i)], a["text"]),
                                  [ref(rs, b), ref(rs, a)],
                                  {"kind": "plan", "op": "move", "number": nums[(fam, j)],
                                   "to": nums[(fam, i)], "expect": b["key"],
                                   "label": "Move #%d above #%d" % (nums[(fam, j)], nums[(fam, i)])}, "order"))
                break
        for i, shadowed in sorted(unreach.items()):
            a = rules[i]
            last = max(s["index"] for s in shadowed)
            ca = cls[(fam, i)]
            what = "allow" if verdict(shadowed[0]["action"]) == "accept" else "block"
            lines = []
            for s in shadowed:
                c = cls[(fam, s["index"])]
                lines.append("#%d %s%s" % (nums[(fam, s["index"])], s["text"],
                                           (" — managed: " + c["label"]) if c["managed"] else ""))
            title = ("%d %s rule%s after #%d never match%s: “%s” comes first" % (
                len(shadowed), what, "s" if len(shadowed) > 1 else "", nums[(fam, i)],
                "" if len(shadowed) > 1 else "es", a["text"].split(" comment")[0]))
            fix = None
            if not ca["managed"]:
                fix = {"kind": "plan", "op": "move", "number": nums[(fam, i)], "to": nums[(fam, last)],
                       "expect": a["key"],
                       "label": "Move #%d below #%d" % (nums[(fam, i)], nums[(fam, last)])}
            sev = "medium" if verdict(a["action"]) == "drop" else "high"
            detail = "\n".join(lines)
            if verdict(a["action"]) == "accept":
                detail = "These block rules are bypassed because the earlier allow matches first:\n" + detail
            else:
                detail = "Traffic these rules mean to allow is dropped by the earlier rule:\n" + detail
            out.append(_f("%s-before-%s:%s" % ("deny" if verdict(a["action"]) == "drop" else "allow", what, a["key"]),
                          sev, title, detail, [ref(rs, a)] + [ref(rs, s) for s in shadowed], fix, "order"))
    return out


def _raw_findings(rs, ctx, cls_raw):
    out = []
    wg = ctx.wg["iface"]
    fwd = {"v4": [], "v6": []}
    inp = {"v4": [], "v6": []}
    other = []
    for c in cls_raw:
        if c.get("table") != "filter" or c["chain"] not in ("INPUT", "FORWARD"):
            continue
        if " -j ACCEPT" not in c["line"] + " ":
            continue
        if c["owner"] == "wireguard":
            (fwd if c["chain"] == "FORWARD" else inp)[c["family"]].append(c)
        elif c["owner"] == "user":
            other.append(c)
    if fwd["v4"] or fwd["v6"]:
        widened = []
        for fam in ("v4", "v6"):
            if not fwd[fam]:
                continue
            for name, dev, _net_, kind in zones(ctx):
                if dev == wg:
                    continue
                for iin, iout in ((dev, wg), (wg, dev)):
                    ok, _r = evaluate_route(rs[fam], rs["defaults"], iin, iout)
                    if not ok:
                        lbl = "%s → %s" % (zone_name(ctx, iin), zone_name(ctx, iout))
                        if kind == "wan" and iin == dev:
                            lbl += " (new inbound connections)"
                        widened.append((fam, lbl))
        pairs = []
        for fam, lbl in widened:
            if lbl not in pairs:
                pairs.append(lbl)
        lines = [c["line"] + " (" + c["family"] + ")" for f in ("v4", "v6") for c in fwd[f]]
        if pairs:
            detail = ("ensure_wg_routing appends -i/-o %s ACCEPT to FORWARD after the ufw chains, so any "
                      "forwarded VPN traffic that no ufw rule denies is accepted — the routed default-deny "
                      "does not apply to the VPN. Paths ufw itself would block but these rules let through:\n• %s"
                      "\nufw route rules that DENY still win (they are evaluated first)."
                      % (wg, "\n• ".join(pairs)))
            out.append(_f("raw-wg-forward", "high",
                          "Raw WireGuard FORWARD accepts bypass ufw (%d path%s opened)" % (
                              len(pairs), "s" if len(pairs) > 1 else ""), detail, [],
                          {"kind": "link", "href": "#interfaces", "label": "Open Interfaces → Policy matrix",
                           "steps": ["Model the VPN in the Interfaces policy matrix (VPN → LAN / WAN allowed, "
                                     "everything else denied). Applying it writes tagged ufw route rules and "
                                     "sets policy.wg_raw_forward=false, so ensure_wg_routing stops adding "
                                     "the raw accepts.",
                                     "Your existing ufw rules for the VPN (VPN to LAN / LAN to VPN / VPN to WAN) "
                                     "already cover the intended paths."]},
                          "bypass", raw=lines))
        else:
            out.append(_f("raw-wg-forward", "low", "Raw WireGuard FORWARD accepts duplicate ufw rules",
                          "Every path they accept is already allowed by ufw.", [], None, "bypass", raw=lines))
    for fam in ("v4", "v6"):
        if not inp[fam]:
            continue
        covered, refs_ = True, []
        for c in inp[fam]:
            m = re.search(r"-s (\S+)", c["line"])
            p = re.search(r"--dport (\d+)", c["line"])
            pr = re.search(r"-p (\w+)", c["line"])
            src = m.group(1).split("/")[0] if m else ("203.0.113.7" if fam == "v4" else "2001:db8::7")
            try:
                src = str(next(ipaddress.ip_network(m.group(1), strict=False).hosts())) if m else src
            except (ValueError, StopIteration):
                pass
            ok, by = G.evaluate_input(rs[fam], rs["defaults"], {"iface": wg, "src": src, "dst": "",
                                                               "proto": pr.group(1) if pr else "tcp",
                                                               "dport": int(p.group(1)) if p else 1})
            if ok and by:
                refs_.append(ref(rs, by))
            else:
                covered = False
        lines = [c["line"] for c in inp[fam]]
        if covered:
            out.append(_f("raw-wg-input:%s" % fam, "info",
                          "Raw INPUT accepts for VPN DNS duplicate ufw rules (%s)" % fam,
                          "They sit after the ufw chains and only repeat what ufw already allows.",
                          refs_, None, "bypass", raw=lines))
        else:
            out.append(_f("raw-wg-input:%s" % fam, "medium", "Raw INPUT accepts on %s bypass ufw (%s)" % (wg, fam),
                          "Traffic ufw would drop is accepted by these raw rules.", refs_, None, "bypass", raw=lines))
    if other:
        out.append(_f("raw-accept", "medium", "%d raw iptables ACCEPT rule%s outside ufw" % (
            len(other), "s" if len(other) > 1 else ""),
            "They are invisible in the Rules tab, are not part of snapshots, and accept traffic ufw "
            "may intend to drop.", [], None, "bypass", raw=[c["line"] for c in other]))
    return out


def _before_findings(rs, ctx):
    out = []
    for fam, name in (("v4", "before.rules"), ("v6", "before6.rules")):
        text = rs["texts"].get(name) or ""
        seen, dups = {}, []
        for ln in text.splitlines():
            if not ln.startswith("-A "):
                continue
            if ln in seen:
                dups.append(ln)
            seen[ln] = seen.get(ln, 0) + 1
        if not dups:
            continue
        canary = [l for l in dups if "--uid-owner opencanary" in l]
        title = ("Canary egress containment is in %s twice" % name if canary and len(canary) == len(dups)
                 else "%d duplicate line%s in %s" % (len(dups), "s" if len(dups) > 1 else "", name))
        fix = None
        if CE is not None and canary:
            new, removed = dedupe_containment(text, fam)
            if removed:
                import difflib
                path = "/etc/ufw/" + name
                fix = {"kind": "manual", "label": "Remove the second copy (preview)",
                       "diff": "".join(difflib.unified_diff(text.splitlines(True), new.splitlines(True),
                                                            path, path, n=2)),
                       "steps": ["Edit %s as shown, then `sudo ufw reload`. The first copy (with the "
                                 "[TUXWALL-CANARY-EGRESS] log lines the tripwire watches) stays." % path]}
        out.append(_f("before-dup:%s" % fam, "low", title,
                      "The second copy sits after the first copy's catch-all REJECT, so it never matches. "
                      "Harmless, but it makes the file harder to audit."
                      if canary else "Repeated lines in %s never match a second time." % name,
                      [], fix, "hygiene", raw=dups))
        if CE is not None and ctx.opencanary_user and CE.present(text, fam, ctx.opencanary_uid) \
                and not CE.has_log(text, fam, ctx.opencanary_uid):
            out.append(_f("canary-egress-nolog:%s" % fam, "medium",
                          "Canary egress containment has no log line (%s)" % name,
                          "Egress attempts are rejected but not logged, so the tripwire's canary trigger "
                          "([TUXWALL-CANARY-EGRESS]) never fires.", [], None, "deception"))
    return out


def dedupe_containment(text, fam):
    """Remove repeated canary containment blocks after the first one.
    Returns (new_text, removed_line_count)."""
    lines = text.split("\n")
    marks = [i for i, l in enumerate(lines) if l.startswith("# --- Tuxwall canary (opencanary) egress containment")]
    if len(marks) < 2:
        return text, 0
    drop = set()
    for m in marks[1:]:
        j = m
        block = [j]
        j += 1
        while j < len(lines) and ("--uid-owner opencanary" in lines[j] or
                                  (lines[j].startswith("#") and not lines[j].startswith("# ---"))):
            block.append(j)
            j += 1
        drop.update(block)
    new = [l for i, l in enumerate(lines) if i not in drop]
    if not CE.present("\n".join(new), fam):
        return text, 0
    return "\n".join(new), len(drop)


def findings(rs, ctx, hits=None, now=None):
    """All findings for ruleset rs (live: load_ruleset(ctx) with raw)."""
    now = now or time.time()
    out = []
    cls = {}
    for fam in ("v4", "v6"):
        for i, r in enumerate(rs[fam]):
            cls[(fam, i)] = G.classify_rule(r, ctx)
    # 1. guard invariants
    inv = G.invariants(rs, ctx, rs)
    inv_keys = set()
    for v in inv:
        rules = _invariant_rules(rs, v)
        inv_keys.update(x["key"] for x in rules)
        detail = v["detail"]
        if v["id"].startswith("mgmt-wan") and "22" in v["title"]:
            detail += "\nIf SSH must stay reachable, use `limit` and a source restriction."
        fix = _fix_from_repair(v.get("repair"))
        if not fix and rules and v["id"].startswith(("mgmt-wan", "deception-everywhere")):
            r0 = rules[0]
            fix = {"kind": "plan", "op": "disable", "number": r0["number"], "expect": r0["key"],
                   "label": "Disable #%d (reversible)" % r0["number"]}
        out.append(_f("guard:" + v["id"], v["severity"], v["title"], detail, rules, fix, "guard"))
    # 2. ordering: unreachable / redundant / duplicates
    out += _shadow_findings(rs, ctx, cls)
    # 3. raw rules bypassing ufw
    cl = G.classify(rs, ctx)
    out += _raw_findings(rs, ctx, cl["raw"])
    # 4. before.rules hygiene
    out += _before_findings(rs, ctx)
    # 5. allows without an interface
    for fam in ("v4", "v6"):
        for i, r in enumerate(rs[fam]):
            c = cls[(fam, i)]
            if (r["route"] or r["dir"] != "in" or verdict(r["action"]) != "accept" or r["in"]
                    or c["managed"] or r["key"] in inv_keys or not G._any(r["src"])):
                continue
            out.append(_f("no-iface:%s" % r["key"], "medium",
                          "Rule #%d allows %s on every interface, including the WAN" % (
                              numbers(rs)[(fam, i)], (r["dport"] + "/" + r["proto"]) if r["dport"] != "any"
                              else "everything"),
                          r["text"], [ref(rs, r)],
                          {"kind": "edit", "number": numbers(rs)[(fam, i)], "expect": r["key"],
                           "label": "Edit: add `in on <interface>`"}, "exposure"))
    # 6. port forwards
    res = kea_reservations(ctx)
    for pf in ctx.portforwards:
        if not pf.get("enabled", True):
            continue
        try:
            ip_ = str(pf.get("int_ip"))
            port = int(pf.get("int_port") or pf.get("ext_port"))
            ext = int(pf.get("ext_port"))
        except (TypeError, ValueError):
            continue
        label = pf.get("label") or "%s:%s" % (ip_, port)
        for p in {port, ext}:
            if p in RISKY_FORWARD:
                out.append(_f("pf-risky:%s:%d" % (pf.get("id"), p), "high",
                              "Port forward exposes %s (%d) on %s to the internet" % (RISKY_FORWARD[p], p, ip_),
                              "%s is a frequent attack target; prefer the VPN." % RISKY_FORWARD[p], [],
                              {"kind": "link", "href": "#firewall/nat", "label": "Firewall → NAT / Port Forward"},
                              "exposure", explain=ip_))
        if ip_ not in res:
            out.append(_f("pf-noreserve:%s" % pf.get("id"), "medium",
                          "Port forward “%s” targets %s without a DHCP reservation" % (label, ip_),
                          "If the device gets another address, the forward reaches whoever gets this one.",
                          [], {"kind": "link", "href": "#clients", "label": "Clients → reserve the address"},
                          "exposure", explain=ip_))
    # 7. stale references: hosts and interfaces
    ifaces = existing_ifaces(ctx)
    leases = kea_leases(ctx)
    internal = [ipaddress.ip_interface(z[2]).network for z in zones(ctx)
                if z[2] and z[3] in ("lan", "opt") and _net(z[2]) is not None]
    for fam in ("v4", "v6"):
        for i, r in enumerate(rs[fam]):
            num = numbers(rs)[(fam, i)]
            for dev in (r["in"], r["out"]):
                if dev and ifaces is not None and dev not in ifaces:
                    out.append(_f("no-iface-dev:%s:%s" % (dev, r["key"]), "medium",
                                  "Rule #%d refers to interface %s, which does not exist" % (num, dev),
                                  r["text"], [ref(rs, r)],
                                  {"kind": "plan", "op": "disable", "number": num, "expect": r["key"],
                                   "label": "Disable #%d" % num}, "stale"))
            if fam != "v4":
                continue
            for a in (r["src"], r["dst"]):
                n = _net(a)
                if n is None or G._any(a) or n.num_addresses != 1:
                    continue
                host = str(n.network_address)
                if any(n.subnet_of(x) for x in internal if x.version == 4) and host not in res and host not in leases:
                    out.append(_f("stale-host:%s:%s" % (host, r["key"]), "low",
                                  "Rule #%d refers to %s, which has no reservation or current lease" % (num, host),
                                  "The address may now belong to another device.\n" + r["text"], [ref(rs, r)],
                                  {"kind": "link", "href": "#clients", "label": "Clients → reserve the address"},
                                  "stale", explain=host))
    # 8. comments / tags
    unc = [ref(rs, rs[f][i]) for (f, i), c in sorted(cls.items(), key=lambda x: numbers(rs)[x[0]])
           if c["owner"] == "user" and not rs[f][i]["comment"]]
    if unc:
        out.append(_f("uncommented", "info", "%d of your rules have no comment" % len(unc),
                      "A short note (why the rule exists) makes later clean-ups safe. Use Edit on a rule "
                      "to add one.", unc, None, "hygiene"))
    untagged = [ref(rs, rs[f][i]) for (f, i), c in sorted(cls.items(), key=lambda x: numbers(rs)[x[0]])
                if c["owner"] == "honeypot" and c.get("matched_by") == "config"]
    if untagged:
        out.append(_f("honeypot-untagged", "info", "%d honeypot rules have no tuxwall-honeypot tag" % len(untagged),
                      "They are recognised by the honeypot config (ports %s on %s) and stay locked. New "
                      "honeypot rules carry the tag; these are left as they are." % (
                          ", ".join(map(str, ctx.honeypot["ports"])), ctx.wan),
                      untagged, None, "hygiene"))
    # 9. v4/v6 asymmetry
    out += _asymmetry(rs, ctx, cls)
    # 10. zero hits
    if hits:
        zero = []
        for (f, i), c in cls.items():
            if c["managed"]:
                continue
            h = hits.get(rs[f][i]["key"])
            if h and h.get("first") and now - h["first"] >= ZERO_HIT_DAYS * 86400 and not h.get("total"):
                zero.append(ref(rs, rs[f][i]))
        if zero:
            zero.sort(key=lambda x: x["number"])
            out.append(_f("zero-hit", "low", "%d of your rules matched nothing in %d+ days" % (len(zero), ZERO_HIT_DAYS),
                          "Unused allows can be disabled (reversible); unused blocks may still be wanted.",
                          zero, None, "usage"))
    # 11. logging
    lv = re.search(r"(?m)^LOGLEVEL=(\w+)", ctx.read("/etc/ufw/ufw.conf"))
    level = lv.group(1).lower() if lv else ""
    if re.search(r"(?m)^ENABLED=no", ctx.read("/etc/ufw/ufw.conf")):
        out.append(_f("ufw-disabled", "critical", "ufw is disabled", "No rule is enforced.", [],
                      {"kind": "link", "href": "#firewall/settings", "label": "Firewall → Settings"}, "policy"))
    if level == "off":
        out.append(_f("logging-off", "medium", "Firewall logging is off",
                      "Blocked traffic is not recorded, so Traffic, scanner suggestions and Diagnose "
                      "have nothing to show.", [],
                      {"kind": "link", "href": "#firewall/settings", "label": "Firewall → Settings → Logging: low"},
                      "policy"))
    elif level in ("high", "full"):
        out.append(_f("logging-%s" % level, "low", "Firewall logging is %s" % level,
                      "Every allowed packet is logged too; /var/log/ufw.log grows fast. `low` is enough.", [],
                      {"kind": "link", "href": "#firewall/settings", "label": "Firewall → Settings"}, "policy"))
    out.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["category"], f["id"]))
    return out


def _asymmetry(rs, ctx, cls):
    if not rs["v6"] or not rs["v4"]:
        return []
    sample = {"v4": "203.0.113.7", "v6": "2001:db8::7"}
    out = []
    for fam in ("v4", "v6"):
        other = "v6" if fam == "v4" else "v4"
        for i, r in enumerate(rs[fam]):
            if (r["route"] or r["dir"] != "in" or r.get("app") or not G._any(r["src"]) or not G._any(r["dst"])
                    or r["sport"] != "any" or cls[(fam, i)]["managed"]):
                continue
            p = G._ports(r["dport"])
            port = min(p) if p else 9
            pkt = {"iface": r["in"] or "__any__", "src": sample[fam], "dst": "", "proto":
                   r["proto"] if r["proto"] != "any" else "tcp", "dport": port}
            a, by_a = G.evaluate_input(rs[fam], rs["defaults"], dict(pkt, src=sample[fam]))
            b, by_b = G.evaluate_input(rs[other], rs["defaults"], dict(pkt, src=sample[other]))
            if by_a is not r:
                continue  # the rule itself is shadowed; ordering findings cover it
            if any(x["action"] == r["action"] and x["proto"] == r["proto"] and x["dport"] == r["dport"]
                   and x["in"] == r["in"] and x["dir"] == r["dir"] and not x["route"]
                   and G._any(x["src"]) and G._any(x["dst"]) for x in rs[other]):
                continue  # the twin exists but is shadowed there: an ordering finding covers it
            if a != b:
                num = numbers(rs)[(fam, i)]
                out.append(_f("asym:%s" % r["key"], "low",
                              "#%d only applies to %s: the same traffic is %s over %s" % (
                                  num, "IPv4" if fam == "v4" else "IPv6", "allowed" if b else "blocked",
                                  "IPv6" if fam == "v4" else "IPv4"),
                              r["text"] + ((" — %s decides it: %s" % (other, by_b["text"])) if by_b
                                           else " — the default policy decides it in %s" % other),
                              [ref(rs, r)] + ([ref(rs, by_b)] if by_b else []), None, "asymmetry"))
    return out


# ── suggestions ─────────────────────────────────────────────────────────────

def parse_log(text, limit=20000):
    ev = []
    for line in (text or "").splitlines()[-limit:]:
        m = LOG_RE.match(line)
        if m:
            ev.append(m.groupdict())
    return ev


def _multicast(dst):
    try:
        a = ipaddress.ip_address(dst)
        return a.is_multicast or str(a) in ("255.255.255.255",) or str(a).endswith(".255")
    except ValueError:
        return True


def suggestions(rs, ctx, log_text="", now=None):
    out = []
    zs = zones(ctx)
    wan = ctx.wan
    # 1. services listening on the router vs rules per network
    ls = ctx.listeners
    dns_addrs = {l["addr"] for l in ls if l["port"] == 53 and l["proto"].startswith("udp")}
    for name, dev, addr, kind in zs:
        if kind not in ("lan", "opt", "vpn") or not addr:
            continue
        try:
            ip_ = str(ipaddress.ip_interface(addr).ip)
            src = str(next(ipaddress.ip_interface(addr).network.hosts()))
        except (ValueError, StopIteration):
            continue
        if ip_ == src:
            continue
        up = any(l["addr"] == ip_ for l in ls)
        if not up and not (dns_addrs & {"0.0.0.0", "*"}):
            continue  # nothing bound on this network (interface down / not served)
        if ip_ in dns_addrs or dns_addrs & {"0.0.0.0", "*"}:
            ok, by = G.evaluate_input(rs["v4"], rs["defaults"],
                                      {"iface": dev, "src": src, "dst": ip_, "proto": "udp", "dport": 53})
            if not ok and by is None:
                out.append({"id": "svc-dns:%s" % dev, "kind": "service", "title":
                            "%s can't use the router's DNS" % zone_name(ctx, dev),
                            "detail": "unbound answers on %s, but no rule allows port 53 from %s (the default "
                                      "policy drops it)." % (ip_, dev),
                            "plan": {"op": "insert", "rule": "allow in on %s to any port 53 proto udp comment "
                                     "'DNS for %s'" % (dev, name)},
                            "extra": ["allow in on %s to any port 53 proto tcp comment 'DNS for %s'" % (dev, name)]})
    for l in ls:
        if l["addr"] not in ("0.0.0.0", "::", "*") or not wan:
            continue
        ok, by = G.evaluate_input(rs["v4"], rs["defaults"], {"iface": wan, "src": "203.0.113.7", "dst": "",
                                                            "proto": "udp" if l["proto"].startswith("udp") else "tcp",
                                                            "dport": l["port"]})
        if ok and by is not None and G.classify_rule(by, ctx)["owner"] not in ("honeypot", "canary", "wireguard"):
            num = numbers(rs)[(by["family"], by["index"])]
            out.append({"id": "svc-wan:%d" % l["port"], "kind": "service", "severity": "high",
                        "title": "%s (%d/%s) listens on all addresses and #%d allows it from the WAN" % (
                            l["proc"] or "a service", l["port"], l["proto"], num),
                        "detail": by["text"], "rules": [ref(rs, by)],
                        "plan": {"op": "edit", "number": num, "expect": by["key"],
                                 "rule": by["text"].replace(" in on %s " % wan, " in on %s " % (ctx.lan or wan))}})
    # log based
    ev = parse_log(log_text)
    internal = {}
    for name, dev, addr, kind in zs:
        if kind in ("lan", "opt", "vpn") and addr and _net(addr):
            internal[dev] = (name, ipaddress.ip_interface(addr).network)
    # 2. LAN devices repeatedly blocked
    grp = {}
    for e in ev:
        if e["action"] != "BLOCK" or e["in"] not in internal or not e.get("dpt"):
            continue
        try:
            if ipaddress.ip_address(e["src"]) not in internal[e["in"]][1]:
                continue
        except ValueError:
            continue
        dpt = int(e["dpt"])
        if dpt in NOISE_PORTS or _multicast(e["dst"]) or e["proto"] not in ("TCP", "UDP"):
            continue
        k = (e["in"], e["out"], e["src"], e["dst"], e["proto"].lower(), dpt)
        grp[k] = grp.get(k, 0) + 1
    for (iin, iout, src, dst, proto, dpt), n in sorted(grp.items(), key=lambda x: -x[1])[:5]:
        if n < 5:
            break
        if iout:
            rule = "route allow in on %s out on %s from %s to %s port %d proto %s comment 'suggested: %s'" % (
                iin, iout, src, dst, dpt, proto, "repeatedly blocked")
            by = None
        else:
            rule = "allow in on %s from %s to %s port %d proto %s comment 'suggested: repeatedly blocked'" % (
                iin, src, dst, dpt, proto)
            ok, by = G.evaluate_input(rs["v4"], rs["defaults"], {"iface": iin, "src": src, "dst": dst,
                                                                "proto": proto, "dport": dpt})
        out.append({"id": "lan-blocked:%s:%s:%d" % (src, dst, dpt), "kind": "blocked",
                    "title": "%s was blocked %d× reaching %s port %d/%s" % (src, n, dst, dpt, proto),
                    "detail": "From %s%s. If this is expected traffic, a narrowly scoped allow fixes it; "
                              "otherwise leave it blocked." % (zone_name(ctx, iin),
                                                               (" to " + zone_name(ctx, iout)) if iout else ""),
                    "plan": {"op": "insert", "rule": rule,
                             "before": numbers(rs)[(by["family"], by["index"])] if by else None},
                    "explain": src})
    # 3. scanners hitting WAN ports -> honeypot
    hp = ctx.honeypot
    taken = set(hp["ports"]) | set(G.MGMT_PORTS) | {ctx.wg["port"]}
    for r in rs["v4"] + rs["v6"]:
        if (r["comment"] or "").startswith("tuxwall-canary") or (r["in"] == wan and verdict(r["action"]) == "accept"):
            p = G._ports(r["dport"])
            if p and len(p) < 50:
                taken |= p
    listen = {l["port"] for l in ls if l["proto"].startswith("tcp")}
    pfp = set()
    for pf in ctx.portforwards:
        try:
            pfp.add(int(pf.get("ext_port")))
        except (TypeError, ValueError):
            pass
    scans = {}
    for e in ev:
        if e["action"] != "BLOCK" or e["in"] != wan or e["out"] or e["proto"] != "TCP" or not e.get("dpt"):
            continue
        scans.setdefault(int(e["dpt"]), set()).add(e["src"])
    cands = sorted(((p, len(s)) for p, s in scans.items()
                    if p not in taken and p not in listen and p not in pfp and len(s) >= 10),
                   key=lambda x: -x[1])[:3]
    for p, n in cands:
        out.append({"id": "honeypot-port:%d" % p, "kind": "honeypot",
                    "title": "%d scanners hit WAN port %d/tcp — add it to the honeypot" % (n, p),
                    "detail": "Instead of a silent drop, the honeypot accepts the connection, records it and "
                              "bans the scanner (%s). Nothing on this router listens on %d, and it is not a "
                              "management, canary or forwarded port." % (
                                  "auto-ban on" if (ctx.json("/var/lib/tuxwall/honeypot.json", {}) or {}).get("auto_ban")
                                  else "auto-ban is off", p),
                    "plan": {"op": "honeypot-add", "port": p, "ports": sorted(set(hp["ports"]) | {p}),
                             "rule": "allow in on %s to any port %d proto tcp comment %s" % (wan, p, G.HONEYPOT_TAG)},
                    "href": "#security/deception"})
    # 4. templates
    lan = ctx.lan
    ssh_wan = [r for r in rs["v4"] + rs["v6"] if not r["route"] and r["dir"] == "in"
               and verdict(r["action"]) == "accept" and (not r["in"] or r["in"] == wan)
               and (G._ports(r["dport"]) is None or 22 in G._ports(r["dport"]))
               and G.classify_rule(r, ctx)["owner"] not in ("canary", "honeypot")]
    allow_all_lan = next((r for r in rs["v4"] if not r["route"] and r["in"] == lan and r["proto"] == "any"
                          and r["dport"] == "any" and verdict(r["action"]) == "accept"), None)
    out.append({"id": "tpl-ssh", "kind": "template", "title": "SSH: LAN-only, rate limited",
                "status": "attention" if ssh_wan else "ok",
                "detail": ("SSH is allowed from the WAN by: " + "; ".join(r["text"] for r in ssh_wan)) if ssh_wan
                else "SSH is not reachable from the WAN (the WAN port 22 rule belongs to the canary decoy). "
                     "A limit rule on the LAN slows down password guessing from an infected device.",
                "plan": {"op": "insert", "rule": "limit in on %s to any port 22 proto tcp comment 'SSH LAN only, "
                                                 "rate limited'" % (lan or "<lan>"),
                         "before": numbers(rs)[("v4", allow_all_lan["index"])] if allow_all_lan else None}})
    opts = [z for z in zs if z[3] == "opt"]
    has_policy = bool(ctx.topo)
    for tid, title, want in (("tpl-guest", "Guest isolation", "guest"), ("tpl-iot", "IoT: internet only", "iot")):
        z = next((z for z in opts if want in (z[0] or "").lower()), None)
        dev = z[1] if z else "<%s-interface>" % want
        rules = ["route allow in on %s out on %s comment '%s -> internet'" % (dev, wan, want),
                 "route deny in on %s comment '%s: no other networks'" % (dev, want),
                 "allow in on %s to any port 53 proto udp comment '%s DNS'" % (dev, want),
                 "allow in on %s to any port 67 proto udp comment '%s DHCP'" % (dev, want),
                 "deny in on %s comment '%s: no router access'" % (dev, want)]
        status = "n/a"
        if z:
            ok_wan, _ = evaluate_route(rs["v4"], rs["defaults"], dev, wan)
            ok_lan, _ = evaluate_route(rs["v4"], rs["defaults"], dev, lan)
            status = "ok" if ok_wan and not ok_lan else "attention"
        out.append({"id": tid, "kind": "template", "title": title, "status": status,
                    "detail": ("%s: %s." % (zone_name(ctx, dev),
                                            "internet allowed, other networks blocked" if status == "ok"
                                            else "check the forwarding rules") if z
                               else "No %s network found in Interfaces." % want) +
                    (" Use the Interfaces policy matrix: it writes tagged, managed rules for every "
                     "network pair." if has_policy else ""),
                    "href": "#interfaces" if has_policy else None,
                    "plan": {"op": "template", "rules": rules}})
    return out
