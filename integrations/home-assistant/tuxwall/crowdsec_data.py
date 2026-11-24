"""Read CrowdSec numbers from either API shape (no Home Assistant imports).

TuxWall serves GET /api/crowdsec/summary (counts + the first IPs, a few KB);
older routers only have GET /api/crowdsec (every decision, megabytes on a
busy router). The coordinator stores whichever it got under "crowdsec";
an unavailable CrowdSec reads as 0 bans / no IPs, as before.
"""
from __future__ import annotations

from typing import Any

CROWDSEC_IPS = 25


def crowdsec_active_count(cs: Any) -> int | None:
    cs = cs if isinstance(cs, dict) else {}
    if isinstance(cs.get("active_count"), int):
        return cs["active_count"]
    decisions = cs.get("decisions") or []
    return len(decisions) if isinstance(decisions, list) else None


def crowdsec_ips(cs: Any, limit: int = CROWDSEC_IPS) -> list[Any] | None:
    cs = cs if isinstance(cs, dict) else {}
    if isinstance(cs.get("recent"), list):
        return cs["recent"][:limit]
    decisions = cs.get("decisions") or []
    if not isinstance(decisions, list):
        return None
    return [d.get("ip") or d.get("value") for d in decisions[:limit] if isinstance(d, dict)]
