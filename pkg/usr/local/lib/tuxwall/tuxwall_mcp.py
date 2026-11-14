#!/usr/bin/env python3
"""TuxWall read-only MCP server (stdio) for the dashboard's opencode agent.

Speaks JSON-RPC 2.0 over newline-delimited stdin/stdout (MCP stdio
transport) and answers from the TuxWall dashboard API on 127.0.0.1:8008,
authenticated with the agent read token (/etc/tuxwall/agent/api.token,
group tuxwall-agent). The API only accepts that token for direct loopback
GETs of an explicit allowlist of read endpoints, so nothing here can change
the router. Python 3 standard library only.
"""
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

API_BASE = "http://127.0.0.1:8008"
TOKEN_FILE = "/etc/tuxwall/agent/api.token"
TOKEN_HEADER = "X-TuxWall-Agent-Token"
FACTS_FILE = "/var/lib/tuxwall/agent/facts.md"
MAX_OUT = 8000
MAX_BODY = 32 * 1024 * 1024
SERVER_INFO = {"name": "tuxwall", "title": "TuxWall (read-only)", "version": "1.0.0"}
PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
INSTRUCTIONS = (
    "Read-only live state of this TuxWall router, straight from the dashboard's own API "
    "(firewall rules/findings, interfaces and zone policy, DHCP leases, DNS, CrowdSec, "
    "attack events, incidents, metrics history). Prefer these tools over shell commands "
    "for current state; they cannot change anything. Outputs are trimmed - use the "
    "filter/limit arguments to narrow them."
)


class ToolError(Exception):
    pass


# ---------------------------------------------------------------- helpers

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _token():
    try:
        with open(TOKEN_FILE) as f:
            tok = f.read().strip()
    except PermissionError:
        raise ToolError("Cannot read the TuxWall agent token (permission denied); "
                        "this tool must run as a member of group tuxwall-agent.")
    except OSError:
        raise ToolError("TuxWall agent token missing; it is created when the TuxWall API "
                        "(tuxwall.service) starts.")
    if not tok:
        raise ToolError("TuxWall agent token is empty.")
    return tok


def api(path, params=None):
    url = API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        TOKEN_HEADER: _token(), "Accept": "application/json", "User-Agent": "tuxwall-mcp/1.0"})
    try:
        with _opener.open(req, timeout=45) as resp:
            raw = resp.read(MAX_BODY + 1)
    except urllib.error.HTTPError as exc:
        msg = ""
        try:
            msg = json.loads(exc.read(4096).decode("utf-8", "replace")).get("error", "")
        except Exception:
            pass
        raise ToolError("TuxWall API %s returned HTTP %s%s" % (path, exc.code, ": " + msg if msg else ""))
    except Exception as exc:
        raise ToolError("TuxWall API unreachable (%s); is tuxwall.service running?"
                        % type(exc).__name__)
    if len(raw) > MAX_BODY:
        raise ToolError("TuxWall API %s response too large" % path)
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        raise ToolError("TuxWall API %s returned invalid JSON" % path)
    if isinstance(data, dict) and data.get("ok") is False:
        raise ToolError("TuxWall API %s: %s" % (path, data.get("error") or "request failed"))
    return data


_SECRET_KV = re.compile(
    r'(?i)("?\b(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key|'
    r'preshared[_-]?key|psk|auth[_-]?key)"?\s*[:=]\s*"?)([^\s",}\]]{4,})')
_WG_KEY = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])')
_LONG_ID = re.compile(r'(?<![\w-])(?=[\w-]*\d)(?=[\w-]*[A-Za-z])[\w-]{40,}(?![\w-])')


_OWN = {"at": 0.0, "v4": (), "nets6": ()}
_V6_CAND = re.compile(r"(?<![0-9A-Za-z:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?(?![0-9A-Za-z:])")


def _own_public():
    """The router's own public IPv4 addresses and IPv6 prefixes (cached 5 min)."""
    if time.time() - _OWN["at"] < 300:
        return _OWN
    v4, nets6 = set(), set()
    try:
        it = api("/api/interfaces")
        for d in it.get("inventory") or []:
            for a in d.get("addresses") or []:
                try:
                    ifc = ipaddress.ip_interface(a.get("cidr", ""))
                except ValueError:
                    continue
                if not ifc.ip.is_global:
                    continue
                if ifc.version == 4:
                    v4.add(str(ifc.ip))
                else:
                    nets6.add(ipaddress.ip_network("%s/64" % ifc.ip, strict=False))
        for n in it.get("networks") or []:
            for net in n.get("subnets6") or []:
                try:
                    net = ipaddress.ip_network(net, strict=False)
                except ValueError:
                    continue
                if net.is_global:
                    nets6.add(net)
    except ToolError:
        pass
    _OWN.update(at=time.time(), v4=tuple(v4), nets6=tuple(nets6))
    return _OWN


def _mask_own(text):
    own = _own_public()
    for ip in own["v4"]:
        text = re.sub(r"(?<![\d.])%s(?![\d.])" % re.escape(ip), "[router public IPv4]", text)
    if own["nets6"]:
        def sub(m):
            try:
                net = ipaddress.ip_network(m.group(0), strict=False)
            except ValueError:
                return m.group(0)
            if any(net.version == o.version and (net.subnet_of(o) or o.subnet_of(net)) for o in own["nets6"]):
                return "[router public IPv6]"
            return m.group(0)
        text = _V6_CAND.sub(sub, text)
    return text


def redact(text):
    try:
        tok = _token()
    except ToolError:
        tok = ""
    if tok:
        text = text.replace(tok, "[redacted]")
    text = _mask_own(text)
    text = _SECRET_KV.sub(lambda m: m.group(1) + "[redacted]", text)
    text = _WG_KEY.sub("[redacted-key]", text)
    return _LONG_ID.sub("[redacted-id]", text)


def trim(text, limit=MAX_OUT):
    if len(text) <= limit:
        return text
    cut = text.rfind("\n", 0, limit - 200)
    if cut < limit // 2:
        cut = limit - 200
    shown = text[:cut]
    return shown + ("\n... [output truncated: showing %d of %d characters; narrow it with the "
                    "tool's filter/limit arguments]" % (len(shown), len(text)))


def ts(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return str(v) if v not in (None, "") else "-"
    if v <= 0:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(v))


def ago(v):
    try:
        d = time.time() - float(v)
    except (TypeError, ValueError):
        return "-"
    if d < 0:
        return "in %s" % _dur(-d)
    return "%s ago" % _dur(d)


def _dur(d):
    d = int(d)
    if d < 90:
        return "%ds" % d
    if d < 5400:
        return "%dm" % (d // 60)
    if d < 172800:
        return "%dh" % (d // 3600)
    return "%dd" % (d // 86400)


def clip(s, n=200):
    s = " ".join(str(s if s is not None else "").split())
    return s if len(s) <= n else s[: n - 1] + "\u2026"


def as_int(v, default, lo, hi):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def sarg(args, key):
    v = args.get(key)
    return "" if v is None else str(v).strip()


def as_bool(v, default):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def own_addr(cidr):
    """This router's own public addresses stay out of the model context (the
    facts file hides them too); private/ULA addresses are shown."""
    try:
        ip = ipaddress.ip_interface(cidr).ip
    except ValueError:
        return cidr
    if ip.is_global:
        return "public IPv%d (not shown)" % ip.version
    return cidr


def own_net(net):
    try:
        if ipaddress.ip_network(net, strict=False).is_global:
            return "ISP-delegated prefix (not shown)"
    except ValueError:
        pass
    return net


def counts_line(counter, n=12):
    return ", ".join("%s %d" % (k, c) for k, c in counter.most_common(n)) or "-"


# ------------------------------------------------------------------ tools

def t_overview(args):
    try:
        with open(FACTS_FILE) as f:
            facts = f.read()
    except OSError:
        facts = ""
    if facts.strip():
        return facts, 12000
    st = api("/api/status")
    svc = ", ".join("%s %s" % (k, "up" if v else "DOWN") for k, v in (st.get("services") or {}).items())
    return ("Facts file unavailable; basic status only.\nHost %s at %s, load %s\nServices: %s"
            % (st.get("hostname"), st.get("time"), st.get("load"), svc)), None


_IFACE_RE = re.compile(r"\b(in|out) on (\S+)")


def t_firewall_rules(args):
    f_if = sarg(args, "interface")
    f_owner = sarg(args, "owner").lower()
    f_text = sarg(args, "text").lower()
    f_group = sarg(args, "group").lower()
    limit = as_int(args.get("limit"), 60, 1, 200)
    with_hits = as_bool(args.get("include_hits"), False)
    fw = api("/api/firewall")
    try:
        managed = {(r.get("number"), r.get("family")): r for r in api("/api/firewall/managed").get("rules") or []}
    except ToolError:
        managed = {}
    hits = {}
    if with_hits:
        try:
            for h in api("/api/firewall/hits").get("rules") or []:
                hits[h.get("number")] = h
        except ToolError:
            pass
    rows = []
    for r in fw.get("rules") or []:
        fam = "v6" if r.get("v6") else "v4"
        m = managed.get((r.get("number"), fam)) or {}
        text = m.get("text") or ("%s %s -> %s" % (r.get("action"), clip(r.get("from"), 80), r.get("to")))
        ifs = ["%s:%s" % (d, i) for d, i in _IFACE_RE.findall(text)]
        if not ifs and r.get("iface"):
            ifs = [r.get("iface")]
        rows.append({"n": r.get("number"), "fam": fam, "text": text, "ifs": ifs,
                     "devs": sorted({x.split(":")[-1] for x in ifs}),
                     "owner": r.get("owner") or "user", "label": r.get("owner_label") or "",
                     "group": r.get("group") or "", "managed": bool(r.get("managed")),
                     "action": r.get("action") or ""})
    by_if, by_owner, by_group = Counter(), Counter(), Counter()
    for x in rows:
        for d in x["devs"] or ["(any interface)"]:
            by_if[d] += 1
        by_owner[x["owner"]] += 1
        by_group[x["group"] or "-"] += 1
    sel = []
    for x in rows:
        if f_if and (f_if.lower() not in [d.lower() for d in x["devs"]]
                     and not (f_if.lower() == "any" and not x["devs"])):
            continue
        if f_owner and f_owner not in x["owner"].lower() and f_owner not in x["label"].lower():
            continue
        if f_group and f_group != x["group"].lower():
            continue
        if f_text and f_text not in ("%s %s %s" % (x["text"], x["owner"], x["label"])).lower():
            continue
        sel.append(x)
    d = fw.get("defaults") or {}
    out = ["UFW %s, logging %s, defaults: incoming %s, outgoing %s, routed %s"
           % (fw.get("status"), fw.get("logging"), d.get("incoming"), d.get("outgoing"), d.get("routed")),
           "Total rules: %d (%s)" % (len(rows), counts_line(by_group)),
           "Rules per interface (a rule naming in+out interfaces counts for both): " + counts_line(by_if, 20),
           "Rules per owner: " + counts_line(by_owner, 20),
           "Owner 'user' = the owner's own rules; other owners are managed by TuxWall features "
           "(change them via that feature, not by editing the rule). Line format: #number family ufw-rule [owner].",
           ""]
    flt = ", ".join("%s=%s" % (k, v) for k, v in (("interface", f_if), ("owner", f_owner),
                                                    ("group", f_group), ("text", f_text)) if v)
    out.append("Matching rules: %d%s%s" % (len(sel), " (filter: %s)" % flt if flt else "",
                                          ", showing first %d" % limit if len(sel) > limit else ""))
    for x in sel[:limit]:
        line = "#%s %s %s [%s%s]" % (x["n"], x["fam"], x["text"], x["owner"], ", managed" if x["managed"] else "")
        h = hits.get(x["n"]) if with_hits else None
        if h and h.get("family", x["fam"]) == x["fam"]:
            line += " | hits24h=%s last=%s" % (h.get("hits", 0), ago(h["last_hit"]) if h.get("last_hit") else "never")
        out.append(line)
    return "\n".join(out), None


def t_firewall_findings(args):
    with_sugg = as_bool(args.get("include_suggestions"), True)
    fd = api("/api/firewall/findings")
    items = fd.get("findings") or []
    c = fd.get("counts") or {}
    out = ["Firewall Findings (generated %s): %d total - %s" % (
        ts(fd.get("generated")), len(items),
        ", ".join("%s %s" % (k, c.get(k, 0)) for k in ("critical", "high", "medium", "low", "info")))]
    if not items:
        out.append("No open findings.")
    for f in items[:40]:
        out.append("- [%s] %s (id %s%s)" % (f.get("severity"), clip(f.get("title"), 160), f.get("id"),
                                           ", category %s" % f["category"] if f.get("category") else ""))
        if f.get("detail"):
            out.append("  detail: " + clip(f.get("detail"), 300))
        if f.get("rules"):
            out.append("  rules: " + clip(", ".join(str(r) for r in f["rules"]), 200))
        fix = f.get("fix")
        if fix:
            out.append("  fix: " + clip(fix.get("label") or fix.get("title") or json.dumps(fix)
                                        if isinstance(fix, dict) else fix, 200))
    if len(items) > 40:
        out.append("... %d more findings not shown" % (len(items) - 40))
    if with_sugg:
        try:
            sg = api("/api/firewall/suggestions").get("suggestions") or []
        except ToolError as exc:
            sg = []
            out.append("Suggestions unavailable: %s" % exc)
        out.append("")
        out.append("Suggestions (optional improvements, not problems): %d" % len(sg))
        for s in sg[:20]:
            out.append("- [%s] %s" % (s.get("kind"), clip(s.get("title"), 160)))
            if s.get("detail"):
                out.append("  " + clip(s.get("detail"), 260))
    out.append("Changes go through the dashboard (Firewall -> Findings) or the tuxwall-firewall-change "
               "skill (snapshot, guard preview, 60 s confirm).")
    return "\n".join(out), None


def t_interfaces(args):
    with_policy = as_bool(args.get("include_policy"), True)
    it = api("/api/interfaces")
    out = ["Interface Apply locked: %s (apply_locked=%s)" % ("yes" if it.get("apply_locked") else "no",
                                                          it.get("apply_locked"))]
    topo = it.get("topology") or {}
    wan = topo.get("wan") or {}
    out.append("WAN: %s (%s)" % (wan.get("device"), wan.get("mode")))
    out.append("Networks:")
    for n in it.get("networks") or []:
        out.append("- %s %s (%s) %s on %s, subnet %s%s, dhcp=%s ra=%s%s" % (
            n.get("role"), n.get("id"), n.get("name"), n.get("address"), n.get("device"), n.get("subnet"),
            (" + " + ", ".join(own_net(x) for x in n.get("subnets6"))) if n.get("subnets6") else "",
            n.get("dhcp"), n.get("ra"), (" vlan %s on %s" % (n.get("vlan"), n.get("parent"))) if n.get("vlan") else ""))
    out.append("Devices:")
    for d in it.get("inventory") or []:
        addrs = ", ".join(own_addr(a.get("cidr", "")) for a in d.get("addresses") or [] if a.get("scope") != "link")
        out.append("- %s: role=%s kind=%s %s carrier=%s%s%s" % (
            d.get("device"), d.get("role") or "-", d.get("kind"), d.get("operstate"), d.get("carrier"),
            " %sMb/s" % d["speed_mbit"] if d.get("speed_mbit") else "", (" addrs: " + addrs) if addrs else ""))
    v = it.get("validation") or {}
    if v.get("errors") or v.get("warnings"):
        out.append("Validation: errors=%s warnings=%s" % (v.get("errors"), v.get("warnings")))
    if it.get("pending"):
        out.append("Pending (not applied): %s" % clip(json.dumps(it.get("pending")), 400))
    if with_policy:
        try:
            p = api("/api/interfaces/policy")
            out.append("")
            out.append("Zone policy matrix (row = from, column = to; source %s):" % p.get("source"))
            names = {c.get("id"): "%s(%s)" % (c.get("name"), c.get("device")) for c in
                     (p.get("columns") or []) + (p.get("rows") or [])}
            for src, row in (p.get("cells") or {}).items():
                for dst, cell in (row or {}).items():
                    if cell.get("state") == "self":
                        continue
                    ex = cell.get("exceptions") or []
                    out.append("- %s -> %s: %s%s" % (names.get(src, src), names.get(dst, dst), cell.get("state"),
                                                    ("; exceptions: " + "; ".join(clip(e, 110) for e in ex[:4])
                                                     + (" (+%d more)" % (len(ex) - 4) if len(ex) > 4 else ""))
                                                    if ex else ""))
            d = p.get("defaults") or {}
            out.append("Chain defaults: %s" % ", ".join("%s %s" % kv for kv in d.items()))
            for n in p.get("notes") or []:
                out.append("Note: " + clip(n, 240))
        except ToolError as exc:
            out.append("Policy unavailable: %s" % exc)
    return "\n".join(out), None


def t_dhcp_leases(args):
    q = sarg(args, "search").lower()
    online_only = as_bool(args.get("online_only"), False)
    limit = as_int(args.get("limit"), 60, 1, 300)
    leases = api("/api/leases").get("leases") or []
    per_net = Counter(".".join(str(l.get("ip", "")).split(".")[:3]) + ".0/24" for l in leases)
    online = sum(1 for l in leases if l.get("online"))
    sel = []
    for l in leases:
        if online_only and not l.get("online"):
            continue
        if q and q not in " ".join(str(l.get(k) or "") for k in ("ip", "hostname", "mac", "vendor", "os")).lower():
            continue
        sel.append(l)
    out = ["DHCP leases: %d total, %d online; per subnet: %s" % (len(leases), online, counts_line(per_net)),
           "Matching: %d%s" % (len(sel), ", showing first %d" % limit if len(sel) > limit else "")]
    for l in sel[:limit]:
        flags = [f for f, on in (("online", l.get("online")), ("static", l.get("static")),
                                 ("BANNED", l.get("banned"))) if on]
        out.append("- %s %s mac=%s%s os=%s expires=%s%s" % (
            l.get("ip"), l.get("hostname") or "(no name)", l.get("mac"),
            " vendor=%s" % clip(l["vendor"], 40) if l.get("vendor") else "", l.get("os") or "-",
            ago(l["expires"]) if l.get("expires") else "-", (" [" + ", ".join(flags) + "]") if flags else ""))
    return "\n".join(out), None


def t_dns_stats(args):
    d = api("/api/dns")
    t = d.get("totals") or {}
    out = ["Unbound %s, %s threads, up %s" % (d.get("version"), d.get("threads"), _dur(d.get("uptime") or 0)),
           "Totals since start: " + ", ".join("%s=%s" % kv for kv in t.items()),
           "Cache: " + ", ".join("%s=%s" % kv for kv in (d.get("caches") or {}).items()),
           "Query types: " + ", ".join("%s %s" % (x.get("label"), x.get("count")) for x in d.get("qtypes") or []),
           "Response codes: " + ", ".join("%s %s" % (x.get("label"), x.get("count")) for x in d.get("rcodes") or [])]
    return "\n".join(out), None


def t_crowdsec_decisions(args):
    ip = sarg(args, "ip")
    limit = as_int(args.get("limit"), 20, 1, 100)
    cs = api("/api/crowdsec")
    dec = cs.get("decisions") or []
    alerts = cs.get("alerts") or []
    out = ["CrowdSec: %s active decisions (%s bans)" % (cs.get("active_count", len(dec)), cs.get("bans_count")),
           "By scenario: " + counts_line(Counter(x.get("scenario") for x in dec), 12),
           "By origin: " + counts_line(Counter(x.get("origin") for x in dec)),
           "Bouncers: " + "; ".join("%s (%s) last pull %s%s" % (b.get("name"), b.get("type"), b.get("last_pull"),
                                                               " REVOKED" if b.get("revoked") else "")
                                    for b in cs.get("bouncers") or []) or "none"]
    if ip:
        sel = [x for x in dec if ip in str(x.get("ip"))]
        out.append("")
        out.append("Decisions matching %r: %d%s" % (ip, len(sel), "" if sel else " (not banned)"))
        al = [a for a in alerts if ip in str((a.get("source") or {}).get("value") or (a.get("source") or {}).get("ip"))]
    else:
        sel = sorted(dec, key=lambda x: str(x.get("created") or ""), reverse=True)
        out.append("")
        out.append("Most recent %d decisions:" % min(limit, len(sel)))
        al = alerts
    for x in sel[:limit]:
        out.append("- %s %s %s via %s, created %s, until %s%s" % (
            x.get("type"), x.get("ip"), x.get("scenario"), x.get("origin"), x.get("created"), x.get("until"),
            " (simulated)" if x.get("simulated") else ""))
    if al:
        out.append("")
        out.append("Recent alerts%s (%d of the latest %d): %s" % (
            " for %s" % ip if ip else "", len(al), len(alerts), counts_line(Counter(a.get("scenario") for a in al), 8)))
        for a in al[:min(limit, 10)]:
            src = a.get("source") or {}
            out.append("- %s %s from %s (%s events%s)" % (
                a.get("created_at"), a.get("scenario"), src.get("value") or src.get("ip"),
                a.get("events_count"), ", " + src["cn"] if src.get("cn") else ""))
    return "\n".join(out), None


def t_security_events(args):
    limit = as_int(args.get("limit"), 20, 1, 50)
    s = api("/api/security")
    st = s.get("stats") or {}
    out = ["WAN attack monitor (blocked inbound probes) since %s: %s hits from %s IPs in %s countries; "
           "last minute %s, last 10 min %s; last event %s" % (
               ts(s.get("started")), st.get("hits"), st.get("unique_ips"), st.get("countries"),
               st.get("hits_1m"), st.get("hits_10m"), ago(st["last_event"]) if st.get("last_event") else "-"),
           "Top countries: " + ", ".join("%s %s" % (c.get("iso") or c.get("name"), c.get("count"))
                                         for c in (s.get("countries") or [])[:12]),
           "", "Top source IPs:"]
    for b in (s.get("by_ip") or [])[:limit]:
        out.append("- %s x%s (%s, %s, AS%s %s) last %s, port %s" % (
            b.get("ip"), b.get("count"), b.get("iso"), clip(b.get("city"), 30), b.get("asn"), clip(b.get("isp"), 40),
            ago(b.get("last")), b.get("port")))
    out.append("")
    out.append("Recent events:")
    for e in (s.get("events") or [])[:limit]:
        out.append("- %s %s (%s) -> WAN port %s" % (ts(e.get("ts")), e.get("src"), e.get("iso"), e.get("port")))
    return "\n".join(out), None


def t_incidents(args):
    limit = as_int(args.get("limit"), 20, 1, 120)
    active_only = as_bool(args.get("active_only"), False)
    d = api("/api/incidents", {"limit": 120})
    items = d.get("incidents") or []
    if active_only:
        items = [i for i in items if i.get("status") == "active"]
    out = ["Incidents: %s active (%s critical, %s warning, %s unacknowledged); checked %s" % (
        d.get("active"), d.get("critical"), d.get("warning"), d.get("unacknowledged"), ts(d.get("checked_at")))]
    if not items:
        out.append("No %sincidents recorded." % ("active " if active_only else ""))
    for i in items[:limit]:
        out.append("- [%s/%s%s] %s - first %s, last %s%s" % (
            i.get("severity"), i.get("status"), ", acked" if i.get("acknowledged") else "",
            clip(i.get("title"), 140), ts(i.get("first_seen")), ago(i.get("last_seen")),
            ("\n  " + clip(i.get("detail"), 260)) if i.get("detail") else ""))
    if len(items) > limit:
        out.append("... %d more not shown" % (len(items) - limit))
    return "\n".join(out), None


_INSIGHT_LABELS = {
    "cpu": "CPU %", "mem": "memory %", "temp": "CPU temp C", "load": "load avg", "disk": "disk %",
    "swap": "swap %", "rx": "WAN rx B/s", "tx": "WAN tx B/s", "atk": "attacks/min", "qpm": "DNS queries/min",
    "blk": "DNS blocked/min", "hit": "DNS cache hit %", "sf": "DNS servfail/min", "v6": "IPv6 share %",
    "fwa": "fw allowed/min", "fwb": "fw blocked/min",
}


def t_insights(args):
    rng = str(args.get("range") or "1h")
    if rng not in ("15m", "1h", "6h", "24h"):
        rng = "1h"
    d = api("/api/insights/history", {"range": rng})
    keys = d.get("keys") or []
    pts = [p for p in d.get("points") or [] if isinstance(p, list) and len(p) == len(keys) + 1]
    out = ["Router metrics over the last %s (%d samples, step %ss). min / avg / max / latest:" % (
        d.get("range"), len(pts), d.get("step"))]

    def f(v):
        return ("%.0f" % v) if abs(v) >= 100 else ("%.1f" % v)
    for idx, k in enumerate(keys, 1):
        vals = [p[idx] for p in pts if isinstance(p[idx], (int, float))]
        if not vals:
            out.append("- %s (%s): no data" % (k, _INSIGHT_LABELS.get(k, k)))
            continue
        out.append("- %s (%s): %s / %s / %s / %s" % (k, _INSIGHT_LABELS.get(k, k), f(min(vals)),
                                                    f(sum(vals) / len(vals)), f(max(vals)), f(vals[-1])))
    out.append("Labels are best-effort; rates are per-minute averages collected by the TuxWall API.")
    return "\n".join(out), None


_RO = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}


def _tool(name, title, desc, props=None, fn=None):
    return {"name": name, "title": title, "description": desc,
            "inputSchema": {"type": "object", "properties": props or {}, "additionalProperties": False},
            "annotations": dict(_RO, title=title)}, fn


_TOOL_DEFS = [
    _tool("overview", "Router overview",
          "Current TuxWall facts: version, interface roles and subnets, zone policy, NAT, firewall summary "
          "(rule counts, Findings, latest snapshot), deception, key services, DHCP, WireGuard, CrowdSec and "
          "recent incidents. Regenerated every 5 minutes. Start here for status questions.",
          fn=t_overview),
    _tool("firewall_rules", "Firewall rules",
          "UFW rules with owner (user vs TuxWall feature such as honeypot, canary, nat, wireguard), group "
          "(yours/managed) and interfaces, plus totals per interface, owner and group. Filters combine (AND).",
          {"interface": {"type": "string", "description": "Only rules on this device, e.g. enp5s0, wg0; 'any' = rules without an interface"},
           "owner": {"type": "string", "description": "Owner or feature substring, e.g. user, honeypot, canary, nat, wireguard"},
           "group": {"type": "string", "enum": ["yours", "managed", "policy"], "description": "Rule group"},
           "text": {"type": "string", "description": "Case-insensitive substring of the rule text/comment, e.g. a port or IP"},
           "include_hits": {"type": "boolean", "description": "Add 24 h hit counters per rule (default false)"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Max rules listed (default 60)"}},
          t_firewall_rules),
    _tool("firewall_findings", "Firewall findings",
          "Open firewall Findings (problems: severity, title, detail, affected rules) from the dashboard's "
          "rule linter, plus optional improvement suggestions.",
          {"include_suggestions": {"type": "boolean", "description": "Also list suggestions (default true)"}},
          t_firewall_findings),
    _tool("interfaces", "Interfaces and zone policy",
          "Interface roles (WAN/LAN/OPT/VPN), addresses, subnets, link state, apply_locked flag, validation, "
          "and the inter-zone forwarding policy matrix with exceptions.",
          {"include_policy": {"type": "boolean", "description": "Include the zone policy matrix (default true)"}},
          t_interfaces),
    _tool("dhcp_leases", "DHCP leases",
          "Kea DHCP leases with hostname, MAC, vendor, OS guess, online/static/banned flags and counts per subnet.",
          {"search": {"type": "string", "description": "Substring of IP, hostname, MAC, vendor or OS"},
           "online_only": {"type": "boolean", "description": "Only clients seen online (default false)"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 300, "description": "Max leases listed (default 60)"}},
          t_dhcp_leases),
    _tool("dns_stats", "DNS statistics",
          "Unbound resolver statistics: queries, cache hit rate, NXDOMAIN, recursion time, query types, "
          "response codes, cache sizes.", fn=t_dns_stats),
    _tool("crowdsec_decisions", "CrowdSec decisions",
          "CrowdSec active decisions (bans) with counts by scenario and origin, bouncer status, recent alerts. "
          "Give ip to check whether a specific address is banned and why.",
          {"ip": {"type": "string", "description": "IP or IP prefix to look up"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Max decisions listed (default 20)"}},
          t_crowdsec_decisions),
    _tool("security_events", "WAN attack events",
          "Blocked inbound probes on the WAN seen by the attack monitor: totals, top countries, top source IPs "
          "(with ASN/ISP) and the most recent events.",
          {"limit": {"type": "integer", "minimum": 1, "maximum": 50, "description": "Max IPs/events listed (default 20)"}},
          t_security_events),
    _tool("incidents", "Incidents",
          "Dashboard incidents (service down, WAN loss, attacks etc.): active counts and recent incidents "
          "with severity, status, first/last seen and detail.",
          {"active_only": {"type": "boolean", "description": "Only active incidents (default false)"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 120, "description": "Max incidents listed (default 20)"}},
          t_incidents),
    _tool("insights", "Metrics history",
          "Router metrics history summarised as min/avg/max/latest: CPU, memory, temperature, load, disk, "
          "WAN throughput, attacks, DNS queries/blocks/cache hits, firewall allowed/blocked.",
          {"range": {"type": "string", "enum": ["15m", "1h", "6h", "24h"], "description": "Time range (default 1h)"}},
          t_insights),
]
TOOLS = [t for t, _ in _TOOL_DEFS]
HANDLERS = {t["name"]: fn for t, fn in _TOOL_DEFS}


# --------------------------------------------------------------- JSON-RPC

def call_tool(params):
    name = params.get("name")
    args = params.get("arguments") or {}
    if not isinstance(args, dict):
        args = {}
    fn = HANDLERS.get(name)
    try:
        text, limit = fn(args)
        text = trim(redact(text), limit or MAX_OUT)
        return {"content": [{"type": "text", "text": text}], "isError": False}
    except ToolError as exc:
        msg = str(exc)
    except Exception as exc:
        msg = "Internal error in tool %s (%s)" % (name, type(exc).__name__)
    return {"content": [{"type": "text", "text": redact(msg)}], "isError": True}


def handle(msg):
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    method = msg.get("method")
    is_request = "id" in msg
    if not isinstance(method, str):
        return None   # a response to something we never send, or junk
    if not is_request:
        return None   # notifications (initialized, cancelled, ...) need no reply
    rid = msg.get("id")
    params = msg.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    def ok(result):
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def err(code, message):
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

    if method == "initialize":
        want = params.get("protocolVersion")
        return ok({"protocolVersion": want if want in PROTOCOLS else PROTOCOLS[0],
                   "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": SERVER_INFO, "instructions": INSTRUCTIONS})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        if params.get("name") not in HANDLERS:
            return err(-32602, "Unknown tool: %s" % clip(params.get("name"), 80))
        return ok(call_tool(params))
    return err(-32601, "Method not found: %s" % clip(method, 80))


def send(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main():
    try:
        os.umask(0o077)
    except Exception:
        pass
    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline()
        if not line:
            return
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line.decode("utf-8"))
        except ValueError:
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        try:
            if isinstance(msg, list):
                replies = [r for r in (handle(m) for m in msg) if r]
                if replies:
                    send(replies)
            else:
                reply = handle(msg)
                if reply:
                    send(reply)
        except Exception as exc:
            rid = msg.get("id") if isinstance(msg, dict) else None
            send({"jsonrpc": "2.0", "id": rid,
                  "error": {"code": -32603, "message": "Internal error (%s)" % type(exc).__name__}})


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
