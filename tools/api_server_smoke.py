#!/usr/bin/env python3
"""Import-time smoke test for www/includes/api_server.py.

Usage: python3 tools/api_server_smoke.py
CI: .github/workflows/ci.yml runs this on every push and pull request.

Catches the release bug class that syntax checks and the module-level
name-order gate both miss: an identifier that compiles fine but does
not resolve at runtime. The 3.2.0 release shipped exactly that - the
heavy-list fetch referenced CROWDSEC_LIST_TIMEOUT while the definition
was _CROWDSEC_LIST_TIMEOUT - and every install's CrowdSec panel raised
NameError on load.

The module is imported as a plain module (main() never runs, no ports
bind, module level is side-effect-free by construction) and key
surfaces are asserted to exist and behave. Safe on a bare CI host:
the cscli-backed fetch must degrade to a clean error dict, never a
NameError.
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "www", "includes", "api_server.py")

spec = importlib.util.spec_from_file_location("api_server_smoke", TARGET)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# --- Pinned regression: the 3.2.0/3.2.1 bug, by exact name ---------------
# The heavy-list timeout must exist under the name the fetch path uses.
# A definition/usage name mismatch here is what shipped in 3.2.0.
assert hasattr(mod, "_CROWDSEC_LIST_TIMEOUT"), \
    "_CROWDSEC_LIST_TIMEOUT is not defined at module level"

# --- Key API surfaces must resolve to callables ---------------------------
for name in (
    "build_crowdsec",
    "build_crowdsec_ban_state",
    "_crowdsec_active_decisions",
    "_fetch_crowdsec_active_decisions",
    "report_ban_to_org",
    "_honey_ban",
):
    assert callable(getattr(mod, name, None)), \
        f"{name} is missing or not callable"

# --- Pure helpers must behave ---------------------------------------------
assert mod.report_category_for("rdp probe", "") == "rdp"
assert mod.report_category_for("sshd brute force", "") == "ssh"
assert mod.report_category_for("brute force attempt", "") == "bruteforce"
assert mod.report_category_for("port scan", "") == "scan"

# --- The call that shipped broken must degrade cleanly --------------------
# On a bare host cscli does not exist; the fetch must return a clean
# error dict - the assertion is that no undefined name survives to
# runtime, which is exactly what 3.2.0 got wrong.
result = mod._fetch_crowdsec_active_decisions()
assert isinstance(result, dict) and result.get("ok") is False, \
    f"unexpected fetch result shape: {result!r:.120}"
err = str(result.get("error", ""))
assert "not defined" not in err, \
    f"undefined name survived to runtime: {err}"

# --- Backups: sibling module loads, legacy dashboard-backup routes are gone
assert mod._bk is not None, "includes/backups.py failed to import"
assert "/api/backups/restore" in mod.LEGACY_BACKUP_PATHS
assert callable(getattr(mod, "restore_system_backup_member", None))
assert mod._bk.failure_incident("/nonexistent-root") is None

# --- Tripwire status: every field the dashboard renders, no host needed ----
mod.TRIPWIRE_CONF = mod.TRIPWIRE_STATE = mod.TRIPWIRE_HEALTH = "/nonexistent/tw.json"
mod.TRIPWIRE_AUDIT = "/nonexistent/tw-audit.log"
mod.TRIPWIRE_BIN = "/nonexistent/tuxwall-tripwire"
mod.TRIPWIRE_HISTORY = "/nonexistent/tw-events.jsonl"
tw = mod.tripwire_status()
for key in ("mode", "tripped", "trip_mode", "dst", "logonly_events", "last_logonly",
            "absorbed_events", "last_absorbed", "resolved_at", "engine", "audit",
            "enabled", "strength", "notify", "checks", "coming_later", "config_available"):
    assert key in tw, f"tripwire status lacks {key}"
assert tw["mode"] == "disabled" and tw["engine"]["needed"] is False
assert tw["config_available"] is False and tw["checks"] == []
assert mod.tripwire_health("logonly")["healthy"] is False
h = mod.tripwire_history({"check": ["canary.egress"], "limit": ["5"]})
assert h["ok"] and h["items"] == [] and h["total"] == 0
for bad in ({"action": ["nope"]}, {"limit": ["x"]}):
    try:
        mod.tripwire_history(bad)
        raise AssertionError("tripwire_history accepted %r" % bad)
    except ValueError:
        pass
for bad in ({"bogus": 1}, {}, {"confirm": True}):
    try:
        mod.tripwire_configure(bad, {"username": "t"})
        raise AssertionError("tripwire_configure accepted %r" % bad)
    except ValueError:
        pass
try:
    mod.tripwire_test({"check": "../../x"})
    raise AssertionError("tripwire_test accepted a bad check id")
except ValueError:
    pass

print("api_server smoke test OK")
