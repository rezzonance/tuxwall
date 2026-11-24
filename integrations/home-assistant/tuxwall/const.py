"""Constants for the TuxWall integration."""
from __future__ import annotations

import logging
from typing import Final

DOMAIN: Final = "tuxwall"
DEFAULT_SCAN_INTERVAL: Final = 30

CONF_TOTP_CODE: Final = "totp_code"
# HTTPS (TuxWall 3.3.6+ serves the dashboard over https with the router's
# own CA): a CA file readable by Home Assistant (e.g. /config/tuxwall-ca.crt),
# or verify_ssl off as a last resort.
CONF_VERIFY_SSL: Final = "verify_ssl"
CONF_CA_CERT: Final = "ca_cert"
# Own constant: CONF_SCAN_INTERVAL was deprecated in HA 2024.10 and may be
# removed on current versions - never import it from homeassistant.const.
CONF_SCAN_INTERVAL: Final = "scan_interval"

EVENT_TYPE: Final = "tuxwall_event"

# TuxWall after 3.3.6: one compact payload per poll; older routers answer 404 and
# the per-page endpoints are polled instead (the summary is retried hourly)
INTEGRATION_SUMMARY_PATH: Final = "/api/integration/summary"
SUMMARY_RETRY_SECONDS: Final = 3600

# latest version when the router does not report one: the apt repository
# index, fetched by Home Assistant at most every 6 h
APT_PACKAGES_URL: Final = "https://rezzonance.github.io/tuxwall/dists/stable/main/binary-all/Packages"
APT_CHECK_SECONDS: Final = 6 * 3600
RELEASE_URL: Final = "https://github.com/rezzonance/tuxwall/releases/tag/v{version}"
RELEASES_URL: Final = "https://github.com/rezzonance/tuxwall/releases"

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
