"""The TuxWall integration: coordinator, services and event bridging.

Polls the gateway's dashboard API (services, security, firewall, DNS,
CrowdSec, honeypot, WAN) and exposes it as sensors. Fires Home Assistant
events (``tuxwall_event``) when security-relevant things change so
automations can react - e.g. a core service dropping, the WAN IP
changing, or a tarpit catch. Also watches Home Assistant's own failed
login notifications and fires an event for those: HA auth failures are
data only the HAOS side has, and the router cannot see east-west LAN
traffic, so this closes both blind spots from inside.
"""
from __future__ import annotations

import re
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
import voluptuous as vol

from .api import TuxwallApiClient, TuxwallApiError, TuxwallAuthError
from .const import (
    CONF_TOTP_CODE,
    CORE_SERVICES,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    EVENT_TYPE,
    LOGGER,
)
from .coordinator import TuxwallCoordinator

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR]

SERVICE_BAN_DEVICE: str = "ban_device"
SERVICE_UNBAN_DEVICE: str = "unban_device"
SERVICE_BAN_SCHEMA = vol.Schema({vol.Required("ip"): cv.string})
HA_LOGIN_FAIL_RE = re.compile(
    r"invalid authentication|Login attempt.*from", re.IGNORECASE
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    client = TuxwallApiClient(
        entry.data[CONF_HOST],
        entry.data[CONF_USERNAME],
        entry.data[CONF_PASSWORD],
        entry.data.get(CONF_TOTP_CODE, ""),
    )
    try:
        await client.login()
        whoami = await client.whoami()
    except TuxwallAuthError as exc:
        await client.close()
        raise ConfigEntryAuthFailed(str(exc)) from exc
    except TuxwallApiError as exc:
        await client.close()
        raise ConfigEntryNotReady(str(exc)) from exc

    coordinator = TuxwallCoordinator(hass, client, entry)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
        "role": whoami.get("role", "viewer"),
    }
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    async def ban_device(call: ServiceCall) -> None:
        await client.post(
            "/api/leases/ban",
            {"ip": call.data["ip"], "hostname": call.data.get("hostname", "")},
        )

    async def unban_device(call: ServiceCall) -> None:
        await client.post("/api/leases/unban", {"ip": call.data["ip"]})

    hass.services.async_register(
        DOMAIN, SERVICE_BAN_DEVICE, ban_device, schema=SERVICE_BAN_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_UNBAN_DEVICE, unban_device, schema=SERVICE_BAN_SCHEMA
    )

    _watch_ha_login_failures(hass)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        data = hass.data[DOMAIN].pop(entry.entry_id)
        await data["client"].close()
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_BAN_DEVICE)
            hass.services.async_remove(DOMAIN, SERVICE_UNBAN_DEVICE)
    return unload_ok


@callback
def _watch_ha_login_failures(hass: HomeAssistant) -> None:
    """Fire ``tuxwall_event`` for Home Assistant's own failed-login alerts.

    HA raises a persistent notification ("Login attempt or request with
    invalid authentication from <ip>") on failed logins against the HA
    frontend/API - data the router can never see (east-west blind spot).
    The watch is registered once per HA instance.
    """
    if getattr(hass.data.get(DOMAIN), "ha_login_watch", False):
        return

    @callback
    def on_notification(event) -> None:
        data = event.data or {}
        notification = data.get("notification") or data
        message = str(notification.get("message", "")) if isinstance(notification, dict) else ""
        if data.get("action") not in (None, "create"):
            return
        if message and HA_LOGIN_FAIL_RE.search(message):
            hass.bus.async_fire(
                EVENT_TYPE,
                {"type": "ha_login_failure", "message": message[:200]},
            )

    hass.bus.async_listen("persistent_notification", on_notification)
    hass.data.setdefault(DOMAIN, {})["ha_login_watch"] = True


def down_services(coordinator: TuxwallCoordinator) -> list[str]:
    """Core service units currently not active (for attributes/events)."""
    services = coordinator.data.get("services", [])
    present = {s.get("unit"): s.get("active") for s in services}
    return [u for u in CORE_SERVICES if u in present and present[u] != "active"]
