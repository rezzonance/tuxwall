"""DataUpdateCoordinator pulling the security-relevant TuxWall state."""
from __future__ import annotations

from datetime import timedelta
import time
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import TuxwallApiClient, TuxwallApiError, TuxwallAuthError
from .const import (
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    EVENT_TYPE,
    LOGGER,
)


class TuxwallCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    def __init__(self, hass: HomeAssistant, client: TuxwallApiClient, entry: ConfigEntry) -> None:
        interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        super().__init__(
            hass,
            LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=interval),
        )
        self.client = client
        self.prev: dict[str, Any] = {}

    def _changed(self, key: str, value: Any) -> bool:
        return self.prev.get(key) != value

    async def _async_update_data(self) -> dict[str, Any]:
        async def safe(path: str, default):
            try:
                return await self.client.get(path)
            except TuxwallApiError as exc:
                LOGGER.debug("%s unavailable: %s", path, exc)
                return default

        data: dict[str, Any] = {
            "services": (await safe("/api/system/services", {})).get("services", []),
            "security": await safe("/api/security", {}),
            "firewall": await safe("/api/firewall", {}),
            "crowdsec": await safe("/api/crowdsec", {}),
            "dns": await safe("/api/dns", {}),
            "system": await safe("/api/system", {}),
            "honeypot": await safe("/api/security/honeypot", {}),
            "wireguard": await safe("/api/wireguard", {}),
        }
        self._fire_security_events(data)
        self.prev = data
        return data

    def _fire_security_events(self, data: dict[str, Any]) -> None:
        """Fire HA events for security-relevant transitions.

        Events are fired on the coordinator thread's behalf; bus fire is
        thread-safe to call from async context only, so guard with
        hass.is_running and use hass.async_create_task for safety.
        """

        def fire(payload: dict[str, Any]) -> None:
            if self.hass.is_running:
                self.hass.bus.async_fire(EVENT_TYPE, payload)

        # core service up <-> down transitions
        now_down = self._down_list(data)
        before_down = self._down_list(self.prev) if self.prev else now_down
        for unit in sorted(set(now_down) - set(before_down)):
            fire({"type": "service_down", "service": unit})
        for unit in sorted(set(before_down) - set(now_down)):
            fire({"type": "service_up", "service": unit})

        # WAN address change (dynamic WANs + IoT VLAN automations key on this)
        wan_now = ((data.get("system") or {}).get("wan") or {})
        wan_prev = ((self.prev.get("system") or {}).get("wan") or {})
        if wan_now.get("ipv4") and wan_prev.get("ipv4") and \
                wan_now.get("ipv4") != wan_prev.get("ipv4"):
            fire({
                "type": "wan_ip_change",
                "old": wan_prev.get("ipv4"),
                "new": wan_now.get("ipv4"),
            })

        # honeypot activity: log grows when a trap fires
        hp_now = ((data.get("honeypot") or {}).get("log") or [])
        hp_prev = ((self.prev.get("honeypot") or {}).get("log") or [])
        if len(hp_now) > len(hp_prev) and hp_now:
            new_lines = hp_now[len(hp_prev):] if hp_prev else hp_now[-1:]
            for line in new_lines[-3:]:
                if "auto-banned" in line or "trapped" in line.lower():
                    fire({"type": "tarpit_catch", "message": line[:200]})

    def _down_list(self, data: dict[str, Any]) -> list[str]:
        from . import CORE_SERVICES

        services = data.get("services", [])
        present = {s.get("unit"): s.get("active") for s in services}
        return [u for u in CORE_SERVICES if u in present and present[u] != "active"]
