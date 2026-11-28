"""Who may reach which API route - the policy table checked by
tools/route_permission_check.py against EVERY route discovered in
www/includes/api_server.py (tools/route_discovery.py).

Default for every route not listed here: ADMIN ONLY, i.e.
    no session            -> 401
    viewer session        -> 403
    POST, foreign Origin  -> 403 (CSRF), also with an admin session
    admin + same Origin   -> reaches the handler (not 401/403)
A route that behaves differently fails CI until it is classified here with a
one-line reason ("classify GET /api/x in tools/route_policy.py"). Entries
whose reason starts with "REVIEW:" are current behaviour kept pending an
owner decision - do not copy them as precedent.

Keys are "METHOD /path"; a trailing "*" covers a prefix route (the key as
printed by route_discovery, e.g. "GET /api/plugins/*").
"""

# ── reachable without a session ─────────────────────────────────────────────
PUBLIC = {
    "GET /api/auth/session": "login page bootstrap (theme, setup state); no router location until signed in (3.3.3)",
    "GET /health": "loopback liveness probe; nginx proxies only /api/, so not reachable from the LAN",
    "POST /api/auth/login": "the login form; rate-limited per client address",
    "POST /api/auth/logout": "drops only the caller's own session",
    "POST /api/auth/setup": "first-admin setup; refuses (403) once any user exists",
}

# Machine endpoints authenticated by a token instead of (or besides) a
# session. The check sends the request without the token (must be refused:
# 401/403) and with it from loopback (must pass the gate).
#   token:   (where, name, value attribute in tools/api_harness.py)
#   session: whether an admin session alone is accepted too
#   direct:  token only honoured on a direct loopback call (X-Real-IP -> 403)
TOKEN_AUTH = {
    "POST /api/canary/hit": {
        "token": ("query", "token", "CANARY_TOKEN"), "session": False, "direct": True,
        "reason": "OpenCanary webhook: loopback peer + ?token=; a session does not grant it"},
    "POST /api/system/self-restart": {
        "token": ("header", "X-Tuxwall-Token", "INTERNAL_TOKEN"), "session": True, "direct": False,
        "reason": "internal self-restart: loopback + root-only internal token, or an admin session"},
    "POST /api/blocklists/update": {
        "token": ("header", "X-Tuxwall-Token", "INTERNAL_TOKEN"), "session": True, "direct": False,
        "reason": "tuxwall-blocklist-update.timer: loopback + internal token, or an admin session"},
}

# ── viewer sessions ─────────────────────────────────────────────────────────
# GETs are viewer-readable unless they fall under ADMIN_GET_PREFIXES (or
# check the role themselves); every entry is a conscious "a viewer may read
# this" decision. POSTs: only the self-service account actions.
VIEWER_OK = {
    # account self-service (VIEWER_POST_PATHS)
    "POST /api/auth/password": "change one's own password (current password required)",
    "POST /api/auth/totp/setup": "own two-factor enrolment",
    "POST /api/auth/totp/confirm": "own two-factor enrolment",
    "POST /api/auth/totp/disable": "own two-factor removal (password/code required)",
    # dashboard / overview
    "GET /api/status": "dashboard overview",
    "GET /api/system": "system page (CPU, memory, disks, versions)",
    "GET /api/system/fastfetch": "system page host summary",
    "GET /api/system/services": "service status list (read-only)",
    "GET /api/system/updates": "pending package updates (read-only list)",
    "GET /api/bandwidth": "traffic graphs",
    "GET /api/traffic-monitor": "traffic monitor page",
    "GET /api/latency/history": "latency graph",
    "GET /api/insights/history": "insights graph",
    "GET /api/baselines": "insights baselines",
    "GET /api/incidents": "incident list (acknowledging is admin)",
    "GET /api/themes": "theme list for the appearance menu",
    # network
    "GET /api/leases": "DHCP leases / device list",
    "GET /api/reservations": "DHCP reservations",
    "GET /api/dhcp/subnets": "DHCP subnet overview",
    "GET /api/dns": "DNS page",
    "GET /api/domains": "local DNS records",
    "GET /api/portforward": "port-forward list",
    "GET /api/dmz": "DMZ state",
    "GET /api/vlans": "VLAN list",
    "GET /api/interfaces": "interface assignments view",
    "GET /api/interfaces/policy": "inter-zone policy view",
    "GET /api/interfaces/vlans": "VLAN/AP view of the interface page",
    "GET /api/interfaces/lock": "whether interface apply is locked",
    "GET /api/wireguard": "VPN peers (public keys/addresses only; configs are an admin POST)",
    "GET /api/sqm": "SQM / bufferbloat settings view",
    "GET /api/sqm/speedtest/status": "speed-test progress (starting one is admin)",
    # firewall (read-only views)
    "GET /api/firewall": "firewall rule list",
    "GET /api/firewall/interfaces": "firewall interface list",
    "GET /api/firewall/managed": "managed-rule view",
    "GET /api/firewall/findings": "lint findings",
    "GET /api/firewall/suggestions": "lint suggestions",
    "GET /api/firewall/hits": "rule hit counters",
    "GET /api/firewall/disabled": "disabled-rule list",
    "GET /api/firewall/plan": "dry-run plan preview (computes, never applies)",
    # security pages
    "GET /api/security": "security monitor snapshot",
    "GET /api/security/suricata": "IDS alerts view",
    # Suricata rule suppression (A8, 3.3.7) keeps the default (admin only): GET
    # /api/security/suricata/suppress names devices and their addresses (ADMIN_GET_PREFIXES), POST
    # (add/remove a rule in TuxWall's block of threshold.config; root reloads Suricata) is admin + same Origin.
    "GET /api/security/zeek": "Zeek view",
    "GET /api/security/zeek/quic": "Zeek QUIC view",
    "GET /api/security/aide": "AIDE status (running a check is admin)",
    "GET /api/security/honeypot": "honeypot view",
    "GET /api/security/deception": "deception ban counter",
    "GET /api/security/canary": "canary view",
    "GET /api/security/tripwire": "tripwire status",
    "GET /api/security/tripwire/history": "tripwire history",
    "GET /api/security/tripwire/recovery": "recovery-mode preview; AI provider list only for admins",
    "GET /api/security/ai-models": "model list for the AI summary picker",
    "GET /api/ai/chat/models": "model list for the AI chat picker (chat itself is admin)",
    # CrowdSec / blocklists
    "GET /api/crowdsec": "CrowdSec decisions view",
    "GET /api/crowdsec/summary": "CrowdSec counts for integrations (Home Assistant)",
    "GET /api/integration/summary": "Home Assistant: counts/states of the viewer pages plus backup age, "
                                    "certificate expiry and update state (no logs, paths or keys)",
    "GET /api/crowdsec/blocklist": "custom banlist view",
    "GET /api/crowdsec/ban-state": "ban state view",
    "GET /api/crowdsec/community-bans": "community ban view",
    "GET /api/crowdsec/reporting/status": "community reporting status (settings are admin)",
    "GET /api/blocklists": "blocklist subscriptions",
    "GET /api/blocklists/catalog": "blocklist catalog",
    "GET /api/rpz": "DNS firewall (RPZ) view",
    # device monitoring (3.3.7): detail (findings, destinations, countries) and the
    # local indicator list stay admin-only (also GET /api/devices/findings/recent: destinations and
    # indicators, gated by ADMIN_GET_PREFIXES, so it needs no entry here); every POST is admin
    # (default: admin + same Origin), incl. POST /api/devices/<id>/new-ack (dismiss a new-device row
    # of Security > Local; writes the expected-marks overlay) - deliberately not listed here.
    # Silence rules (A7): GET /api/devices/silence is admin-only (ADMIN_GET_PREFIXES: it names devices and
    # indicators), POST /api/devices/silence (add/remove a rule) and POST /api/devices/zeek-checksums (root
    # runs zeek-site-setup.sh --checksums on|off; Zeek restarts) keep the default: admin + same Origin.
    # The Zeek switch state rides on GET /api/devices/feeds (zeek_checksums: on/off + bad-checksum share).
    # Behaviour detection (3.3.8): GET /api/devices/detectors is admin-only (ADMIN_GET_PREFIXES: shadow findings
    # name devices and destinations), POST /api/devices/detectors (mode off|shadow|on per detector, written to
    # devicewatch.json) keeps the default: admin + same Origin.
    "GET /api/devices": "device list: identity, health, generic reason, today's traffic totals "
                        "(no findings, indicators or destinations for viewers)",
    "GET /api/devices/summary": "device-threat counts for the Security card / Overview / Home Assistant",
    "GET /api/devices/feeds": "threat-feed status (name, licence, counts, last update; never the Auth-Key)",
}

# ── the AI assistant's read-only MCP token (X-TuxWall-Agent-Token) ──────────
# GET-only, direct loopback only; must mirror AGENT_API_READ_PATHS.
AGENT_TOKEN_OK = {
    "GET /api/status": "MCP: router overview",
    "GET /api/system": "MCP: system information",
    "GET /api/system/services": "MCP: service status",
    "GET /api/firewall": "MCP: firewall rule list",
    "GET /api/firewall/managed": "MCP: managed-rule view",
    "GET /api/firewall/findings": "MCP: firewall lint findings",
    "GET /api/firewall/suggestions": "MCP: firewall lint suggestions",
    "GET /api/firewall/hits": "MCP: rule hit counters",
    "GET /api/firewall/interfaces": "MCP: firewall interfaces",
    "GET /api/interfaces": "MCP: interface assignments",
    "GET /api/interfaces/policy": "MCP: inter-zone policy",
    "GET /api/leases": "MCP: DHCP leases / devices",
    "GET /api/dns": "MCP: DNS overview",
    "GET /api/crowdsec": "MCP: CrowdSec decisions",
    "GET /api/crowdsec/summary": "MCP: CrowdSec counts",
    "GET /api/security": "MCP: security monitor snapshot",
    "GET /api/incidents": "MCP: incident list",
    "GET /api/insights/history": "MCP: insights history",
}

# ── CSRF ────────────────────────────────────────────────────────────────────
# POSTs that may be sent with a foreign (cross-site) Origin. Every /api/ POST
# is currently Origin-checked before anything else, token endpoints included.
CSRF_EXEMPT = {}

# POSTs WITHOUT Origin/Referer. Browsers always send Origin on POST, so a
# missing header means a non-browser client.
NO_ORIGIN_DEFAULT = "allow"
NO_ORIGIN_DEFAULT_REASON = (
    "REVIEW: a POST without Origin/Referer passes the CSRF check (the session cookie is SameSite=Lax and "
    "browsers always send Origin on POST). Server-side callers rely on it: the Ban Management page "
    "(PHP dash(): crowdsec/ban, crowdsec/unban, crowdsec/allowlists/*, auth/login, auth/logout), the "
    "blocklist timer and canary webhook (token endpoints). Requiring Origin everywhere needs those "
    "callers (NO_ORIGIN_OK) exempted or taught to send one - owner decision.")
# Must keep working without Origin whatever NO_ORIGIN_DEFAULT becomes.
NO_ORIGIN_OK = {
    "POST /api/auth/login": "Ban Management login (server-side PHP, no Origin)",
    "POST /api/auth/logout": "Ban Management logout (server-side PHP)",
    "POST /api/crowdsec/ban": "Ban Management (server-side PHP with the browser's cookie)",
    "POST /api/crowdsec/unban": "Ban Management (server-side PHP)",
    "POST /api/crowdsec/allowlists/add": "Ban Management whitelist (server-side PHP)",
    "POST /api/crowdsec/allowlists/remove": "Ban Management whitelist (server-side PHP)",
    "POST /api/crowdsec/allowlists/create": "Ban Management whitelist (server-side PHP)",
    "POST /api/canary/hit": "OpenCanary webhook (token)",
    "POST /api/blocklists/update": "systemd timer (internal token)",
    "POST /api/system/self-restart": "internal self-restart (internal token)",
}
# Refuse a POST that carries neither Origin nor Referer even when
# NO_ORIGIN_DEFAULT is "allow".
ORIGIN_REQUIRED = {
    "POST /api/community/settings": "switches community reporting / sharing on; explicit Origin check in the handler",
}
# An Origin on the same host but another port (e.g. the Ban Management page
# on :8744) is accepted: the check compares host names only.
SAME_HOST_OTHER_PORT = "accept"
SAME_HOST_OTHER_PORT_REASON = (
    "REVIEW: the Origin check compares host names only (scheme and port ignored); cookies are not "
    "port-scoped either, so any page served from the router's host name counts as same-origin. Kept on "
    "purpose while the dashboard moves to HTTPS (3.3.6): http:// and https:// pages of the router must both "
    "work during the transition and behind the escape hatch (/etc/tuxwall/no-https-redirect). Tighten to "
    "scheme+host once https-only is the norm.")

# ── handler-level refusals that are not gate slips ──────────────────────────
# With an admin (owner) session and same Origin these routes may still answer
# 401/403 from inside the handler (fixture has no real secret/state).
HANDLER_MAY_REFUSE = {
    "POST /api/auth/login": "wrong/empty credentials -> 403",
    "POST /api/auth/setup": "users exist -> 403",
    "POST /api/auth/password": "current password required -> 403",
    "POST /api/auth/totp/disable": "password/code required -> 403",
    "POST /api/auth/totp/confirm": "enrolment code required -> 403",
    "POST /api/security/tripwire/resolve": "re-enter the admin password -> 403 when wrong",
    "POST /api/security/tripwire/recovery/start": "re-enter the admin password -> 403 when wrong",
}

# ── session cookie attributes (HTTPS: 3.3.6) ────────────────────────────────
# (extra request headers on the login POST, required attributes, forbidden
# attributes[, peer]). Without a peer the login goes over HTTP to the loopback
# harness (= the local nginx). With a peer, _session_cookie_value() is called
# for that connection address directly: X-Forwarded-Proto is only trusted from
# the local proxy (the API listens on loopback; a header from anyone else must
# not decide the cookie flags).
LAX = ("HttpOnly", "SameSite=Lax", "Path=/")
COOKIE_CASES = [
    ({}, LAX, ("Secure",)),
    ({"X-Forwarded-Proto": "http"}, LAX, ("Secure",)),
    ({"X-Forwarded-Proto": "https"}, LAX + ("Secure",), ()),
    ({"X-Forwarded-Proto": "HTTPS"}, LAX + ("Secure",), ()),
    ({"X-Forwarded-Proto": "https, http"}, LAX + ("Secure",), ()),      # first hop counts
    ({"X-Forwarded-Proto": "http, https"}, LAX, ("Secure",)),
    ({"X-Forwarded-Proto": "https"}, LAX + ("Secure",), (), "::1"),
    ({"X-Forwarded-Proto": "https"}, LAX + ("Secure",), (), "::ffff:127.0.0.1"),
    ({"X-Forwarded-Proto": "https"}, LAX, ("Secure",), "192.0.2.50"),     # spoofed, LAN peer
    ({"X-Forwarded-Proto": "https"}, LAX, ("Secure",), "fd00:1::50"),
    ({"X-Forwarded-Proto": "https"}, LAX, ("Secure",), ""),
]

# ── route discovery coverage ────────────────────────────────────────────────
# "/api/..." string literals in api_server.py that are not served routes.
OPENCODE_UPSTREAM = "upstream opencode agent API path (the server calls it on 127.0.0.1:4096; not served)"
NOT_ROUTES = {lit: OPENCODE_UPSTREAM for lit in (
    "/api/config", "/api/credential", "/api/credential/", "/api/event", "/api/form", "/api/form/",
    "/api/info", "/api/integration", "/api/location", "/api/model", "/api/model/default",
    "/api/permission/", "/api/permission/request", "/api/provider", "/api/session", "/api/session/",
    "/api/session/active", "/api/vcs", "/api/vcs/init",
)}
MIN_COVERAGE = 0.95
