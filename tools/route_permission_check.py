#!/usr/bin/env python3
"""Route-permission suite for www/includes/api_server.py.

    python3 tools/route_permission_check.py              # coverage + full matrix
    python3 tools/route_permission_check.py --mutants    # + prove gate removals are caught
    python3 tools/route_permission_check.py --dump       # print the observed matrix
    python3 tools/route_permission_check.py -v           # also list blocked side effects
    python3 tools/route_permission_check.py --target X   # check another copy of api_server.py

1. Discovery (tools/route_discovery.py, AST): every route of every do_<METHOD>
   handler incl. helpers that receive the path, prefix and regex routes.
   Coverage vs a crude grep of "/api/..." literals must be >= MIN_COVERAGE
   and every uncovered literal needs a reason in route_policy.NOT_ROUTES.
2. Matrix over the real Handler on loopback (tools/api_harness.py, sandboxed:
   a handler that reaches a subprocess, a write outside the scratch dir or a
   network connection gets an exception instead). For EVERY route x method:
     no session -> 401 unless PUBLIC/TOKEN_AUTH; viewer -> 403 unless
     VIEWER_OK; POST with a foreign Origin, "Origin: null" or a foreign
     Referer -> 403 (CSRF) even for an admin unless CSRF_EXEMPT; POST without
     Origin per NO_ORIGIN_DEFAULT / ORIGIN_REQUIRED; admin + same Origin ->
     reaches the handler; agent read token -> only AGENT_TOKEN_OK GETs;
     methods without a do_<METHOD> -> 501; unknown /api/ paths -> 401 without
     a session and 404 with one; path-normalisation variants of admin-only
     routes never return data to a viewer.
   Refused requests must not have attempted any side effect, and every
   unauthenticated /api/ answer is JSON without tracebacks or file paths.
   The session cookie attributes are checked per route_policy.COOKIE_CASES.
3. --mutants: the same checks against patched copies of api_server.py (an
   admin GET prefix removed, the CSRF Origin check bypassed, the POST role
   gate removed, the GET session gate removed); each must be caught.
"""
import concurrent.futures
import os
import re
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import api_harness  # noqa: E402
import route_discovery  # noqa: E402
import route_policy as P  # noqa: E402

TARGET = api_harness.TARGET
FOREIGN = "https://evil.example.com"
GATE_ERRORS = ("Authentication required", "Administrator role required", "Administrator access required",
               "Cross-site request rejected", "Origin header required", "Forbidden")
OTHER_METHODS = ("PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")
LEAK_RE = re.compile(r"Traceback \(most recent|File \"/|/var/www|/etc/tuxwall|/home/|/usr/(local/)?lib|"
                     r"\.py\b|api_server|SideEffectBlocked|side effect blocked")
VERBOSE = "-v" in sys.argv


def policy_lookup(table, key):
    """Exact key, or a prefix entry ("GET /api/x*") covering it."""
    if key in table:
        return key
    for k in table:
        if k.endswith("*") and key.startswith(k[:-1]):
            return k
    return None


class Result:
    def __init__(self, label):
        self.label = label
        self.passed = 0
        self.failures = []       # (kind, message)
        self.info = []
        self._lock = threading.Lock()

    def ok(self, cond, kind, msg):
        with self._lock:
            if cond:
                self.passed += 1
            else:
                self.failures.append((kind, msg))
        return cond


def describe(r):
    err = ""
    if isinstance(r.json, dict) and isinstance(r.json.get("error"), str):
        err = " %r" % r.json["error"][:60]
    return "%s%s%s" % (r.status if r.status is not None else r.error or "no answer", err,
                       " [side effects: %s]" % ", ".join(sorted({k for k, _ in r.effects})) if r.effects else "")


def is_gate_refusal(r):
    return r.status in (401, 403) and isinstance(r.json, dict) and r.json.get("error") in GATE_ERRORS


def reached(r, key):
    """Admin/token request got past every gate."""
    if r.status is None:
        return True              # handler hung/dropped after a blocked side effect: past the gates
    if r.status not in (401, 403):
        return True
    return policy_lookup(P.HANDLER_MAY_REFUSE, key) is not None and not is_gate_refusal(r)


def hygiene(res, r, what):
    """Unauthenticated/refused answers: JSON for /api/, no internals."""
    text = r.body.decode("utf-8", "replace") if r.body else ""
    res.ok(r.status is not None and (r.status < 500 or r.status == 501), "hygiene", "%s: answered %s" % (what, describe(r)))
    res.ok(not LEAK_RE.search(text), "hygiene",
           "%s: body exposes internals (matched %r)" % (what, (LEAK_RE.search(text) or [""])[0]))
    if what.split()[1].startswith("/api/") and r.status is not None and r.status != 501:
        res.ok(r.content_type == "application/json", "hygiene",
               "%s: content type %r, expected application/json" % (what, r.content_type))


def no_effects(res, h, r, what):
    h.refresh(r)
    res.ok(not r.effects, "side-effect",
           "%s: refused request attempted side effects before the gate: %s" % (
               what, ", ".join(sorted({k for k, _ in r.effects}))))


def build_cases(d):
    """[(key, method, path, route)] for every discovered route."""
    cases = []
    for key, route in sorted(d.routes.items()):
        for p in route.paths():
            cases.append((key, route.method, p, route))
    return cases


def run_matrix(h, d, res, dump=None):
    methods = set(d.methods())
    cases = build_cases(d)
    jobs = []      # (callable producing check closures)

    def job(fn, *a):
        jobs.append((fn, a))

    def token_headers(key):
        where, name, attr = P.TOKEN_AUTH[key]["token"]
        return where, name, getattr(api_harness, attr)

    def check_get(key, path):
        what = "GET %s" % path
        public = policy_lookup(P.PUBLIC, key)
        viewer_ok = policy_lookup(P.VIEWER_OK, key)
        anon = h.request("GET", path)
        viewer = h.request("GET", path, role="viewer")
        admin = h.request("GET", path, role="admin")
        agent = h.request("GET", path, headers={"X-TuxWall-Agent-Token": api_harness.AGENT_TOKEN})
        out = [("anon", anon), ("viewer", viewer), ("admin", admin), ("agent", agent)]
        if public:
            res.ok(anon.status not in (401, 403) and anon.status is not None, "public",
                   "%s is PUBLIC (%s) but refused anonymously: %s" % (what, P.PUBLIC[public], describe(anon)))
        else:
            res.ok(anon.status == 401, "no-session",
                   "%s without a session -> %s, expected 401 (classify %s in tools/route_policy.py PUBLIC "
                   "only if that is intended)" % (what, describe(anon), key))
            no_effects(res, h, anon, what + " (no session)")
        hygiene(res, anon, what + " (no session)")
        if public:
            pass
        elif viewer_ok:
            res.ok(not is_gate_refusal(viewer) and viewer.status not in (401, 403), "viewer",
                   "%s is VIEWER_OK but a viewer got %s" % (what, describe(viewer)))
        else:
            res.ok(viewer.status == 403, "viewer",
                   "%s as viewer -> %s, expected 403: classify %s in tools/route_policy.py VIEWER_OK or "
                   "gate it (ADMIN_GET_PREFIXES)" % (what, describe(viewer), key))
            if viewer.status == 403:
                no_effects(res, h, viewer, what + " (viewer)")
        res.ok(reached(admin, key), "admin", "%s as admin -> %s, expected to reach the handler" % (
            what, describe(admin)))
        if route_kind(d, key) == "exact" and admin.status == 404 and isinstance(admin.json, dict) \
                and admin.json.get("error") == "Not found":
            res.failures.append(("discovery", "%s: discovered route answers the generic 404 for an admin "
                                              "(dead route or discovery error)" % what))
        if policy_lookup(P.AGENT_TOKEN_OK, key):
            res.ok(reached(agent, key), "agent-token", "%s is AGENT_TOKEN_OK but the agent token got %s" % (
                what, describe(agent)))
        else:
            res.ok(agent.status == 403, "agent-token",
                   "%s with the agent read token -> %s, expected 403 (AGENT_TOKEN_OK lists what it may read)"
                   % (what, describe(agent)))
            if agent.status == 403:
                no_effects(res, h, agent, what + " (agent token)")
        if dump is not None:
            dump.append((what, out))

    def check_post(key, path, method="POST"):
        what = "%s %s" % (method, path)
        public = policy_lookup(P.PUBLIC, key)
        token = policy_lookup(P.TOKEN_AUTH, key)
        viewer_ok = policy_lookup(P.VIEWER_OK, key)
        exempt = policy_lookup(P.CSRF_EXEMPT, key)
        required = policy_lookup(P.ORIGIN_REQUIRED, key)
        no_origin_ok = policy_lookup(P.NO_ORIGIN_OK, key)
        anon = h.request(method, path)
        anon_x = h.request(method, path, origin=FOREIGN)
        viewer = h.request(method, path, role="viewer", origin=h.SAME)
        admin_x = h.request(method, path, role="admin", origin=FOREIGN)
        admin_null = h.request(method, path, role="admin", origin="null")
        admin_ref = h.request(method, path, role="admin", headers={"Referer": FOREIGN + "/page"})
        admin_port = h.request(method, path, role="admin", origin="http://127.0.0.1:1")
        admin_none = h.request(method, path, role="admin")
        admin = h.request(method, path, role="admin", origin=h.SAME)
        agent = h.request(method, path, headers={"X-TuxWall-Agent-Token": api_harness.AGENT_TOKEN})
        out = [("anon", anon), ("anon-xorigin", anon_x), ("viewer", viewer), ("admin-xorigin", admin_x),
               ("admin-null", admin_null), ("admin-xreferer", admin_ref), ("admin-otherport", admin_port),
               ("admin-noorigin", admin_none), ("admin", admin), ("agent", agent)]
        # no session
        if public:
            res.ok(anon.status not in (401,) and anon.status is not None, "public",
                   "%s is PUBLIC (%s) but answered %s" % (what, P.PUBLIC[public], describe(anon)))
        elif token:
            res.ok(anon.status in (401, 403), "token", "%s without its token -> %s, expected 401/403" % (
                what, describe(anon)))
            no_effects(res, h, anon, what + " (no token)")
            where, name, val = token_headers(token)
            tpath = path + ("&" if "?" in path else "?") + "%s=%s" % (name, val) if where == "query" else path
            thdr = {name: val} if where == "header" else {}
            with_tok = h.request(method, tpath, headers=thdr)
            res.ok(reached(with_tok, "") or with_tok.status not in (401, 403), "token",
                   "%s with its token -> %s, expected to pass the gate" % (what, describe(with_tok)))
            proxied = h.request(method, tpath, headers=dict(thdr, **{"X-Real-IP": "192.0.2.10"}))
            if P.TOKEN_AUTH[token]["direct"]:
                res.ok(proxied.status == 403, "token", "%s via the proxy (X-Real-IP) -> %s, expected 403" % (
                    what, describe(proxied)))
                no_effects(res, h, proxied, what + " (token via proxy)")
            out += [("token", with_tok), ("token-proxied", proxied)]
        else:
            res.ok(anon.status == 401, "no-session",
                   "%s without a session -> %s, expected 401 (classify %s in tools/route_policy.py)" % (
                       what, describe(anon), key))
            no_effects(res, h, anon, what + " (no session)")
        hygiene(res, anon, what + " (no session)")
        # CSRF: foreign Origin / Origin null / foreign Referer
        for label, r in (("foreign Origin, no session", anon_x), ("foreign Origin, admin", admin_x),
                         ("Origin: null, admin", admin_null), ("foreign Referer, admin", admin_ref)):
            if exempt:
                continue
            res.ok(r.status == 403, "csrf", "%s with %s -> %s, expected 403 (CSRF) - or CSRF_EXEMPT with a "
                                            "reason" % (what, label, describe(r)))
            if r.status == 403:
                no_effects(res, h, r, "%s (%s)" % (what, label))
            hygiene(res, r, "%s (%s)" % (what, label))
        session_ok = not token or P.TOKEN_AUTH[token]["session"]
        if not session_ok:
            for label, r in (("admin + same Origin", admin), ("admin, no Origin", admin_none),
                             ("admin, other port", admin_port), ("viewer", viewer)):
                res.ok(r.status in (401, 403), "token", "%s (%s) -> %s: the session must not grant this "
                                                        "token-only route" % (what, label, describe(r)))
                no_effects(res, h, r, "%s (%s)" % (what, label))
        elif P.SAME_HOST_OTHER_PORT == "accept":
            res.ok(reached(admin_port, key), "csrf", "%s: same host, other port Origin -> %s (policy: accept)"
                   % (what, describe(admin_port)))
        else:
            res.ok(admin_port.status == 403, "csrf", "%s: same host, other port Origin -> %s, expected 403" % (
                what, describe(admin_port)))
        # missing Origin
        refuse_missing = required or (P.NO_ORIGIN_DEFAULT != "allow" and not no_origin_ok)
        if not session_ok:
            pass
        elif refuse_missing and not exempt:
            res.ok(admin_none.status == 403, "csrf", "%s without Origin/Referer (admin) -> %s, expected 403" % (
                what, describe(admin_none)))
            if admin_none.status == 403:
                no_effects(res, h, admin_none, what + " (no Origin)")
        else:
            res.ok(reached(admin_none, key), "no-origin",
                   "%s without Origin (admin, e.g. the Ban Management page) -> %s, expected to reach the "
                   "handler%s" % (what, describe(admin_none), "" if no_origin_ok else
                                  " - or add it to ORIGIN_REQUIRED"))
        # viewer
        if not public and session_ok:
            if viewer_ok:
                res.ok(not is_gate_refusal(viewer), "viewer", "%s is VIEWER_OK but a viewer got %s" % (
                    what, describe(viewer)))
            else:
                res.ok(viewer.status == 403, "viewer",
                       "%s as viewer -> %s, expected 403: classify %s in tools/route_policy.py VIEWER_OK" % (
                           what, describe(viewer), key))
                if viewer.status == 403:
                    no_effects(res, h, viewer, what + " (viewer)")
        if session_ok:
            res.ok(reached(admin, key), "admin", "%s as admin + same Origin -> %s, expected to reach the "
                                                 "handler" % (what, describe(admin)))
        if route_kind(d, key) == "exact" and admin.status == 404 and isinstance(admin.json, dict) \
                and admin.json.get("error") == "Not found":
            res.failures.append(("discovery", "%s: discovered route answers the generic 404 for an admin" % what))
        res.ok(agent.status == 403, "agent-token", "%s with the agent read token -> %s, expected 403 (GET-only)" % (
            what, describe(agent)))
        if dump is not None:
            dump.append((what, out))

    def check_unimplemented(method, path):
        what = "%s %s" % (method, path)
        anon = h.request(method, path)
        admin = h.request(method, path, role="admin", origin=h.SAME)
        for label, r in (("no session", anon), ("admin", admin)):
            res.ok(r.status == 501, "method", "%s (%s) -> %s, expected 501 (no do_%s handler)" % (
                what, label, describe(r), method))
            no_effects(res, h, r, "%s (%s)" % (what, label))
            hygiene(res, r, "%s (%s)" % (what, label))

    paths_seen = set()
    for key, method, path, route in cases:
        if method == "GET":
            job(check_get, key, path)
        elif method == "HEAD":
            continue
        else:
            job(check_post, key, path, method)
        paths_seen.add(path)
    for m in OTHER_METHODS:
        if m in methods:
            continue
        for path in sorted(paths_seen):
            job(check_unimplemented, m, path)
    for fn, a in [(check_unknown, (h, res)), (check_variants, (h, d, res)), (check_cookies, (h, res)),
                  (check_origin_parsing, (h, res)),
                  (check_gate_lists, (h, d, res))]:
        job(fn, *a)

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        futs = [ex.submit(fn, *a) for fn, a in jobs]
        for f in futs:
            f.result()
    # effects recorded by background threads after their request finished
    stray = api_harness.untagged_effects()
    if stray:
        res.info.append("untagged side effects (background threads): %d blocked (%s)" % (
            len(stray), ", ".join(sorted({k for k, _ in stray}))))


def route_kind(d, key):
    r = d.routes.get(key)
    return r.kind if r else ""


def check_unknown(h, res):
    for path in ("/api/route-policy-unknown", "/api/status/route-policy-unknown", "/api/auth/route-policy-unknown"):
        for method in ("GET", "POST"):
            what = "%s %s (unknown)" % (method, path)
            anon = h.request(method, path, origin=h.SAME)
            admin = h.request(method, path, role="admin", origin=h.SAME)
            viewer = h.request(method, path, role="viewer", origin=h.SAME)
            res.ok(anon.status == 401, "unknown", "%s without a session -> %s, expected 401" % (what, describe(anon)))
            res.ok(admin.status == 404, "unknown", "%s as admin -> %s, expected 404" % (what, describe(admin)))
            res.ok(viewer.status == (404 if method == "GET" else 403), "unknown",
                   "%s as viewer -> %s" % (what, describe(viewer)))
            for r in (anon, admin, viewer):
                hygiene(res, r, what)
                no_effects(res, h, r, what)
    for path in ("/route-policy-unknown", "/index.html", "/includes/api_server.py", "/../etc/passwd"):
        for method in ("GET", "POST"):
            what = "%s %s (non-API)" % (method, path)
            anon = h.request(method, path)
            res.ok(anon.status == 404, "unknown", "%s -> %s, expected 404" % (what, describe(anon)))
            hygiene(res, anon, what)
            no_effects(res, h, anon, what)


def check_variants(h, d, res):
    """Path spellings that must not slip past a prefix gate."""
    targets = sorted({r.paths()[0] for k, r in d.routes.items() if r.method == "GET"
                      and not policy_lookup(P.VIEWER_OK, k) and not policy_lookup(P.PUBLIC, k)})
    for path in targets:
        tail = path[len("/api/"):]
        variants = ["/api//" + tail, "/API/" + tail, "/api/%" + "%02X" % ord(tail[0]) + tail[1:],
                    path + "/", path + "?x=1", path + "#x", path + "%2F", "/api/./" + tail,
                    "/api/x/../" + tail, path + ";x"]
        for v in variants:
            r = h.request("GET", v, role="viewer")
            data = r.status == 200 and not (isinstance(r.json, dict) and r.json.get("ok") is False)
            res.ok(not data and r.status in (400, 401, 403, 404), "variant",
                   "GET %s as viewer -> %s: path spelling slips past the admin gate" % (v, describe(r)))
            r = h.request("GET", v)
            res.ok(r.status in (400, 401, 404), "variant", "GET %s without a session -> %s" % (v, describe(r)))
    for v in ("/api//firewall/reset", "/API/firewall/reset", "/api/firewall/reset/", "/api/firewall/reset?x=1"):
        r = h.request("POST", v, role="viewer", origin=h.SAME)
        res.ok(r.status in (403, 404), "variant", "POST %s as viewer -> %s" % (v, describe(r)))
        no_effects(res, h, r, "POST %s (viewer)" % v)


def check_origin_parsing(h, res):
    """Host/Origin comparison details (POST /api/crowdsec/ban with an empty
    body only validates and answers "Invalid IP")."""
    path = "/api/crowdsec/ban"
    cases = [
        ({"Host": "[fd00::1]", "Origin": "http://[fd00::1]"}, True, "IPv6 literal, same host"),
        ({"Host": "[fd00::1]:80", "Origin": "http://[fd00::1]"}, True, "IPv6 literal with port in Host"),
        ({"Host": "[fd00::1]", "Origin": "http://[fd00::2]"}, False, "IPv6 literal, other host"),
        ({"Host": "router.lan", "Origin": "http://ROUTER.lan"}, True, "host name case-insensitive"),
        ({"Host": "router.lan", "Origin": "http://router.lan.evil.example.com"}, False, "suffix trick"),
        ({"Host": "router.lan", "Origin": "null"}, False, "Origin: null"),
        ({"Host": "router.lan", "Origin": "router.lan"}, False, "Origin without a scheme"),
        ({"Host": "router.lan", "Referer": "http://router.lan/index.html"}, True, "same-host Referer, no Origin"),
        ({"Host": "router.lan", "Origin": "null", "Referer": "http://router.lan/"}, False, "null Origin wins"),
        ({"Host": "", "Origin": "http://router.lan"}, False, "empty Host"),
    ]
    for hdrs, accept, label in cases:
        r = h.request("POST", path, role="admin", headers=hdrs)
        if accept:
            res.ok(reached(r, "POST " + path), "csrf", "Origin parsing (%s) -> %s, expected accepted" % (
                label, describe(r)))
        else:
            res.ok(r.status == 403, "csrf", "Origin parsing (%s) -> %s, expected 403" % (label, describe(r)))
            no_effects(res, h, r, "Origin parsing (%s)" % label)


def check_cookies(h, res):
    for n, (hdrs, need, forbid) in enumerate(P.COOKIE_CASES):
        extra = dict(hdrs, **{"X-Real-IP": "198.51.100.%d" % (n + 1)})
        r = h.request("POST", "/api/auth/login", origin=h.SAME, headers=extra,
                      body={"username": "boss", "password": h.passwords["boss"]})
        cookies = [c for c in r.set_cookies() if c.startswith(h.mod.SESSION_COOKIE + "=")]
        if not res.ok(r.status == 200 and len(cookies) == 1, "cookie",
                      "login with %s -> %s, %d session cookies" % (hdrs or "no extra headers", describe(r),
                                                                    len(cookies))):
            continue
        attrs = [a.strip() for a in cookies[0].split(";")[1:]]
        for a in need:
            res.ok(a in attrs, "cookie", "session cookie (%s) lacks %s" % (hdrs or "plain", a))
        for a in forbid:
            res.ok(a not in attrs, "cookie", "session cookie (%s) has %s" % (hdrs or "plain", a))


def check_gate_lists(h, d, res):
    """The code's gate lists name real routes and match the policy table."""
    mod = h.mod
    gets = {r.value for r in d.routes.values() if r.method == "GET" and r.kind == "exact"}
    posts = {r.value for r in d.routes.values() if r.method == "POST" and r.kind == "exact"}
    for p in sorted(getattr(mod, "AGENT_API_READ_PATHS", ())):
        res.ok(p in gets, "gate-list", "AGENT_API_READ_PATHS lists %s, which no GET handler serves" % p)
        res.ok("GET " + p in P.AGENT_TOKEN_OK, "gate-list",
               "AGENT_API_READ_PATHS lists %s: add it to route_policy.AGENT_TOKEN_OK with a reason" % p)
    for k in P.AGENT_TOKEN_OK:
        res.ok(k.split(" ", 1)[1] in getattr(mod, "AGENT_API_READ_PATHS", ()), "gate-list",
               "route_policy.AGENT_TOKEN_OK has %s but AGENT_API_READ_PATHS does not" % k)
    for p in sorted(getattr(mod, "VIEWER_POST_PATHS", ())):
        res.ok(p in posts, "gate-list", "VIEWER_POST_PATHS lists %s, which no POST handler serves" % p)


def check_policy_table(d, res):
    """Every table entry names a discovered route (no stale entries)."""
    keys = set(d.routes)

    def known(k):
        if k in keys:
            return True
        if k.endswith("*"):
            return any(x.startswith(k[:-1]) for x in keys)
        m, p = k.split(" ", 1)
        return any(r.method == m and r.kind != "exact" and r.matches(p) for r in d.routes.values())

    for name in ("PUBLIC", "TOKEN_AUTH", "VIEWER_OK", "AGENT_TOKEN_OK", "CSRF_EXEMPT", "NO_ORIGIN_OK",
                 "ORIGIN_REQUIRED", "HANDLER_MAY_REFUSE"):
        for k, v in getattr(P, name).items():
            res.ok(known(k), "policy", "route_policy.%s: %s is not a discovered route (stale entry?)" % (name, k))
            reason = v.get("reason") if isinstance(v, dict) else v
            res.ok(isinstance(reason, str) and len(reason.strip()) >= 8, "policy",
                   "route_policy.%s: %s needs a one-line reason" % (name, k))


def check_coverage(d, res, report=True):
    covered, uncovered = d.coverage()
    total = len(covered) + len(uncovered)
    explained = {lit: P.NOT_ROUTES[lit] for lit in uncovered if lit in P.NOT_ROUTES}
    unexplained = sorted(set(uncovered) - set(explained))
    route_like = total - len(explained)
    pct = len(covered) / route_like if route_like else 1.0
    if report:
        print("discovery: %d routes (%s) from %s; gates: %d; regexes expanded: %d" % (
            len(d.routes), ", ".join("%s %d" % (m, sum(1 for r in d.routes.values() if r.method == m))
                                     for m in d.methods()),
            ", ".join("do_" + m for m in d.methods()), len(d.gates),
            sum(1 for r in d.routes.values() if r.kind == "regex")))
        print("coverage: %d of %d \"/api/...\" literals map to a discovered route or gate; %d are not routes "
              "(reasons in route_policy.NOT_ROUTES) -> %.1f%% of route literals" % (
                  len(covered), total, len(explained), 100 * pct))
        if VERBOSE:
            for lit, why in sorted(explained.items()):
                print("  not a route: %-28s %s" % (lit, why))
    for lit in unexplained:
        res.failures.append(("coverage", "\"%s\" (api_server.py line %d) is not covered by route discovery: "
                                         "teach tools/route_discovery.py the pattern, or list it in "
                                         "route_policy.NOT_ROUTES with a reason" % (lit, uncovered[lit])))
    res.ok(pct >= P.MIN_COVERAGE, "coverage", "coverage %.1f%% < %.0f%%" % (100 * pct, 100 * P.MIN_COVERAGE))
    for n in d.notes:
        res.failures.append(("coverage", n))
    for lit in P.NOT_ROUTES:
        res.ok(lit in uncovered or lit not in covered, "policy",
               "route_policy.NOT_ROUTES lists %s, which is a discovered route" % lit)


def run(target, label, dump=False, report=True):
    res = Result(label)
    d = route_discovery.discover(target)
    check_coverage(d, res, report)
    check_policy_table(d, res)
    h = api_harness.Harness(target=target, name="api_server_routes_%s" % re.sub(r"\W", "_", label))
    rows = [] if dump else None
    t0 = time.time()
    try:
        run_matrix(h, d, res, rows)
    finally:
        h.close()
    res.info.append("matrix: %.1f s" % (time.time() - t0))
    if rows is not None:
        for what, out in sorted(rows, key=lambda row: row[0]):
            print("%-62s %s" % (what, "  ".join("%s=%s" % (k, describe(r)) for k, r in out)))
    if VERBOSE:
        blocked = {}
        for tag, eff in list(api_harness._effects.items()):
            for k, _ in eff:
                blocked[k] = blocked.get(k, 0) + 1
        res.info.append("side effects blocked by the sandbox (admin requests past the gates): %s" % (
            ", ".join("%s %d" % kv for kv in sorted(blocked.items())) or "none"))
    return res


# ── mutation self-test ──────────────────────────────────────────────────────
MUTANTS = [
    # (name, failure kind that must show up, [(old, new), ...])
    ("admin GET prefix /api/logs removed", "viewer",
     [('    "/api/logs",\n    "/api/firewall/snapshots",', '    "/api/firewall/snapshots",')]),
    ("CSRF Origin check bypassed", "csrf",
     [("            if not o_host or o_host.lower() != h_host.lower():", "            if False:")]),
    ("POST role gates removed (both layers)", "viewer",
     [("            if path not in VIEWER_POST_PATHS:", "            if False:"),
      ('        if identity.get("role") != "admin":\n            self._send(403, {"ok": False, "error": '
       '"Administrator access required"})', '        if False:\n            self._send(403, {"ok": False, '
       '"error": "Administrator access required"})')]),
    ("GET session gate removed", "no-session",
     [('        if path.startswith("/api/") and identity is None:\n            self._send(401, {"ok": False, '
       '"error": "Authentication required"})\n            return\n        if (path.startswith(ADMIN_GET_PREFIXES)',
       '        if (path.startswith(ADMIN_GET_PREFIXES)')]),
]


def run_mutants(scratch):
    with open(TARGET, encoding="utf-8") as f:
        src = f.read()
    ok = True
    for name, kind, edits in MUTANTS:
        mutated, bad = src, [n for n in (src.count(o) for o, _ in edits) if n != 1]
        if bad:
            print("MUTANT %-40s CANNOT APPLY (a pattern is not unique/present) - update MUTANTS in %s" % (
                name, os.path.basename(__file__)))
            ok = False
            continue
        for o, n in edits:
            mutated = mutated.replace(o, n)
        path = os.path.join(scratch, "api_server.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(mutated)
        res = run(path, "mutant-" + name, report=False)
        kinds = {k for k, _ in res.failures}
        caught = kind in kinds
        ok &= caught
        print("MUTANT %-40s %s (%d failures; kinds: %s)" % (
            name, "caught" if caught else "NOT CAUGHT", len(res.failures), ", ".join(sorted(kinds)) or "-"))
        if VERBOSE:
            for k, m in res.failures[:3]:
                print("    e.g. [%s] %s" % (k, m))
    return ok


def main():
    t0 = time.time()
    # created before the sandbox is installed (it refuses mkdir outside scratch)
    scratch = tempfile.mkdtemp(prefix="tw-route-mutants-") if "--mutants" in sys.argv else None
    target = sys.argv[sys.argv.index("--target") + 1] if "--target" in sys.argv else TARGET
    res = run(target, "main", dump="--dump" in sys.argv)
    for kind, msg in res.failures:
        print("FAIL [%s] %s" % (kind, msg))
    for i in res.info:
        print("info:", i)
    print("route permissions: %d passed, %d failed (%.1f s)" % (res.passed, len(res.failures), time.time() - t0))
    ok = not res.failures
    if "--mutants" in sys.argv:
        api_harness._allowed_dirs.append(os.path.realpath(scratch))
        try:
            ok &= run_mutants(scratch)
        finally:
            import shutil
            shutil.rmtree(scratch, ignore_errors=True)
        print("mutation self-test: %s (%.1f s total)" % ("all caught" if ok else "FAILED", time.time() - t0))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
