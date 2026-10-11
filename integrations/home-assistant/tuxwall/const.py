"""Constants for the TuxWall integration."""
from __future__ import annotations

import logging
from typing import Final

DOMAIN: Final = "tuxwall"
DEFAULT_SCAN_INTERVAL: Final = 30

CONF_TOTP_CODE: Final = "totp_code"
# Own constant: CONF_SCAN_INTERVAL was deprecated in HA 2024.10 and may be
# removed on current versions - never import it from homeassistant.const.
CONF_SCAN_INTERVAL: Final = "scan_interval"

EVENT_TYPE: Final = "tuxwall_event"

ATTR_DOWN_SERVICES: Final = "down_services"
ATTR_IFNAME: Final = "ifname"
ATTR_IPV6: Final = "ipv6"
ATTR_ROLE: Final = "role"
ATTR_USERNAME: Final = "username"

# Core gateway services surfaced as binary sensors (mirrors the dashboard's
# Services Status card). Only services present in the systemd list are
# created, so a unit absent on an install is skipped rather than shown down.
CORE_SERVICES: Final[list[str]] = [
    "unbound.service",
    "kea-dhcp4-server.service",
    "radvd.service",
    "nginx.service",
    "suricata.service",
    "crowdsec.service",
    "crowdsec-firewall-bouncer.service",
    "wg-quick@wg0.service",
    "tuxwall.service",
    "tuxwall-agent.service",
    "tuxwall-collector.service",
    "tuxwall-nat.service",
    "tuxwall-sqm.service",
]

LOGGER: Final = logging.getLogger(__package__)
