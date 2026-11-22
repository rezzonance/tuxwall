#!/usr/bin/env python3
"""HTTP-layer role gates of www/includes/api_server.py (loopback, sandboxed):

  python3 tools/auth_gate_check.py

The real Handler serves on 127.0.0.1:<random>; users and sessions are
in-memory fixtures (the real session/cookie code runs), the UI config is a
fixture with a router location. Checks:

- /api/auth/session without a session: no router_lat/router_lon (3.3.3;
  it answers the login page), but theme/setup fields still there; with a
  viewer or admin session the location is returned (attack map).
- /api/logs/tail and /api/logs/services: 401 without a session, 403 for a
  viewer, 200 for an admin (services); "/api/logs" is in ADMIN_GET_PREFIXES.
- other viewer GETs (e.g. /api/status) are not caught by the logs gate.
- CrowdSec allowlists (Ban Management "Whitelist"): GET /api/crowdsec/allowlists
  and POST .../add|remove|create are 401 without a session and 403 for a
  viewer; a cross-site Origin is refused (403) before anything runs; an
  admin reaches the handler, which gets the JSON body, the identity and the
  client address (X-Real-IP from the loopback proxy).
"""
import http.client
import importlib.util
import json
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "www", "includes", "api_server.py")
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("api_server_auth_gate", TARGET)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


USERS = [{"username": "boss", "role": "admin", "owner": True},
         {"username": "watcher", "role": "viewer"}]
mod._ensure_default_auth = lambda: None
mod._load_users = lambda: [dict(u) for u in USERS]
mod.load_ui_conf = lambda: {"router_lat": 40.1, "router_lon": -75.2, "active_theme": "dark"}
mod._custom_theme_files = lambda: []
mod.build_status = lambda: {"ok": True, "stub": True}
AL_CALLS = []
mod.build_allowlists = lambda: (200, {"ok": True, "lists": [], "stub": True})
for _n in ("add", "remove", "create"):
    setattr(mod, "allowlist_" + _n, (lambda n: lambda body, ident, ip: (
        AL_CALLS.append((n, body, ident.get("username"), ip)) or (200, {"ok": True, "stub": n})))(_n))
now = time.time()
for tok, user in (("tok-admin", "boss"), ("tok-viewer", "watcher")):
    mod._sessions[tok] = {"username": user, "exp": now + 3600, "last": now}

server = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
server.daemon_threads = True
threading.Thread(target=server.serve_forever, daemon=True).start()
PORT = server.server_address[1]


def get(path, token=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    headers = {"Cookie": "%s=%s" % (mod.SESSION_COOKIE, token)} if token else {}
    c.request("GET", path, headers=headers)
    r = c.getresponse()
    body = r.read()
    c.close()
    try:
        return r.status, json.loads(body or b"{}")
    except ValueError:
        return r.status, {}


def post(path, body, token=None, extra=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = "%s=%s" % (mod.SESSION_COOKIE, token)
    headers.update(extra or {})
    c.request("POST", path, body=json.dumps(body), headers=headers)
    r = c.getresponse()
    data = r.read()
    c.close()
    try:
        return r.status, json.loads(data or b"{}")
    except ValueError:
        return r.status, {}


try:
    st, d = get("/api/auth/session")
    check(st == 200 and d.get("authenticated") is False, "session endpoint answers unauthenticated")
    check("router_lat" not in d and "router_lon" not in d, "no router location before login (%r)" % sorted(d))
    check(isinstance(d.get("active_theme"), dict), "login page still gets the theme")
    for tok in ("tok-viewer", "tok-admin"):
        st, d = get("/api/auth/session", tok)
        check(st == 200 and d.get("authenticated") and d.get("router_lat") == 40.1 and d.get("router_lon") == -75.2,
              "router location for a signed-in %s" % tok)

    check(any("/api/logs".startswith(p) or p == "/api/logs" for p in mod.ADMIN_GET_PREFIXES),
          "/api/logs listed in ADMIN_GET_PREFIXES")
    for path in ("/api/logs/tail?source=system&lines=5", "/api/logs/services"):
        st, _ = get(path)
        check(st == 401, "%s without a session -> 401 (got %s)" % (path, st))
        st, _ = get(path, "tok-viewer")
        check(st == 403, "%s as viewer -> 403 (got %s)" % (path, st))
    st, d = get("/api/logs/services", "tok-admin")
    check(st == 200 and d.get("ok") and isinstance(d.get("sources"), list), "/api/logs/services as admin -> 200")
    st, d = get("/api/status", "tok-viewer")
    check(st == 200 and d.get("stub"), "viewer GETs outside the admin prefixes still work")
    check("/api/crowdsec/allowlists" in mod.ADMIN_GET_PREFIXES, "allowlists GET is admin-only")
    st, _ = get("/api/crowdsec/allowlists")
    check(st == 401, "allowlists GET without a session -> 401 (got %s)" % st)
    st, _ = get("/api/crowdsec/allowlists", "tok-viewer")
    check(st == 403, "allowlists GET as viewer -> 403 (got %s)" % st)
    st, d = get("/api/crowdsec/allowlists", "tok-admin")
    check(st == 200 and d.get("stub"), "allowlists GET as admin -> 200")
    for act in ("add", "remove", "create"):
        path = "/api/crowdsec/allowlists/" + act
        st, _ = post(path, {"list": "home", "value": "192.0.2.1"})
        check(st == 401, "%s without a session -> 401 (got %s)" % (path, st))
        st, _ = post(path, {"list": "home", "value": "192.0.2.1"}, "tok-viewer")
        check(st == 403, "%s as viewer -> 403 (got %s)" % (path, st))
        st, _ = post(path, {"list": "home", "value": "192.0.2.1"}, "tok-admin",
                     {"Origin": "https://evil.example.com"})
        check(st == 403, "%s cross-site Origin -> 403 (got %s)" % (path, st))
    check(not AL_CALLS, "no allowlist handler ran for refused requests")
    st, d = post("/api/crowdsec/allowlists/add", {"list": "home", "value": "192.0.2.1", "confirm_broad": True},
                 "tok-admin", {"X-Real-IP": "192.168.1.50"})
    check(st == 200 and d.get("stub") == "add", "allowlist add as admin reaches the handler")
    check(AL_CALLS and AL_CALLS[-1] == ("add", {"list": "home", "value": "192.0.2.1", "confirm_broad": True},
                                        "boss", "192.168.1.50"), "handler gets body, identity and client IP")
    st, d = post("/api/crowdsec/allowlists/remove", {"list": "home", "value": "192.0.2.1"}, "tok-admin",
                 {"Origin": "http://127.0.0.1:%d" % PORT})
    check(st == 200 and d.get("stub") == "remove", "same-origin remove as admin reaches the handler")
finally:
    server.shutdown()

print("auth gates: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
