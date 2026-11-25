"""DataUpdateCoordinator pulling the security-relevant TuxWall state."""
from __future__ import annotations

import asyncio
from datetime import timedelta
import time
from typing import Any

import aiohttp
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import TuxwallApiClient, TuxwallApiError, TuxwallAuthError, TuxwallNotFound
from .const import (
    APT_CHECK_SECONDS,
    APT_PACKAGES_URL,
    CONF_SCAN_INTERVAL,
    CORE_SERVICES,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    EVENT_DEVICE_FINDING,
    EVENT_NEW_DEVICE,
    EVENT_TYPE,
    INTEGRATION_SUMMARY_PATH,
    LOGGER,
    SUMMARY_RETRY_SECONDS,
)
from .summary_data import (
    device_events,
    normalize_legacy,
    normalize_summary,
    packages_latest,
    router_latest,
    section,
)

# legacy (routers without /api/integration/summary): CrowdSec counts
SUMMARY_PATH = "/api/crowdsec/summary"
LEGACY_PATHS = {
    "services": "/api/system/services",
    "security": "/api/security",
    "firewall": "/api/firewall",
    "dns": "/api/dns",
    "system": "/api/system",
    "honeypot": "/api/security/honeypot",
    "wireguard": "/api/wireguard",
}


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
        # monotonic times until which the summaries are not tried again (the
        # router answered 404: older TuxWall without the endpoint)
        self._no_integration_until = 0.0
        self._no_summary_until = 0.0
        # newest TuxWall version in the apt repository (when the router
        # does not report one): (version, monotonic time of the fetch)
        self.repo_latest: str | None = None
        self._repo_checked = -APT_CHECK_SECONDS
        # finding / new-device ids already announced (None until the first poll)
        self._device_seen: dict | None = None

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            data = None
            if time.monotonic() >= self._no_integration_until:
                try:
                    data = normalize_summary(await self.client.get(INTEGRATION_SUMMARY_PATH))
                except TuxwallNotFound:
                    LOGGER.info("%s not available on this TuxWall, polling the per-page endpoints",
                                INTEGRATION_SUMMARY_PATH)
                    self._no_integration_until = time.monotonic() + SUMMARY_RETRY_SECONDS
            if data is None:
                data = await self._legacy()
        except TuxwallAuthError as exc:
            raise UpdateFailed(f"TuxWall login failed: {exc}") from exc
        except TuxwallApiError as exc:
            raise UpdateFailed(str(exc)) from exc
        if router_latest(data) is None:
            await self._check_repo()
        self._fire_security_events(data)
        self.prev = data
        return data

    async def _legacy(self) -> dict[str, Any]:
        """1.1.0's per-endpoint polling; a failing endpoint leaves its
        sections empty, all of them failing fails the update."""
        failures: list[str] = []

        async def safe(path: str) -> Any:
            try:
                return await self.client.get(path)
            except TuxwallApiError as exc:
                LOGGER.debug("%s unavailable: %s", path, exc)
                failures.append(f"{path}: {exc}")
                return {}

        parts: dict[str, Any] = {key: await safe(path) for key, path in LEGACY_PATHS.items()}
        if len(failures) == len(LEGACY_PATHS):
            raise TuxwallApiError(failures[0])
        parts["crowdsec"] = await self._crowdsec(safe)
        return normalize_legacy(parts)

    async def _crowdsec(self, safe) -> Any:
        """CrowdSec counts: the compact summary (a few KB); routers without
        it (404) get the full /api/crowdsec list, retried hourly."""
        if time.monotonic() >= self._no_summary_until:
            try:
                return await self.client.get(SUMMARY_PATH)
            except TuxwallNotFound:
                LOGGER.info("%s not available on this TuxWall, using /api/crowdsec", SUMMARY_PATH)
                self._no_summary_until = time.monotonic() + SUMMARY_RETRY_SECONDS
            except TuxwallApiError as exc:
                LOGGER.debug("%s unavailable: %s", SUMMARY_PATH, exc)
                return {}
        return await safe("/api/crowdsec")

    async def _check_repo(self) -> None:
        """Newest TuxWall in the apt repository's Packages index, at most
        every APT_CHECK_SECONDS (failures wait for the next window too)."""
        if time.monotonic() - self._repo_checked < APT_CHECK_SECONDS:
            return
        self._repo_checked = time.monotonic()
        try:
            session = async_get_clientsession(self.hass)
            async with session.get(APT_PACKAGES_URL, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    raise aiohttp.ClientError(f"HTTP {resp.status}")
                text = await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            LOGGER.debug("TuxWall apt index unavailable: %s", exc)
            return
        latest = packages_latest(text)
        if latest:
            self.repo_latest = latest

    def _fire_security_events(self, data: dict[str, Any]) -> None:
        """Fire HA events for security-relevant transitions (bus fire is
        only safe from the event loop, where the coordinator runs)."""

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
        wan_now = section(data, "wan") or {}
        wan_prev = section(self.prev, "wan") or {} if self.prev else {}
        if wan_now.get("ipv4") and wan_prev.get("ipv4") and \
                wan_now.get("ipv4") != wan_prev.get("ipv4"):
            fire({
                "type": "wan_ip_change",
                "old": wan_prev.get("ipv4"),
                "new": wan_now.get("ipv4"),
            })

        # tarpit activity: new lines in the tarpit log (the newest five)
        hp_now = (section(data, "tarpit") or {}).get("log") or []
        hp_prev = (section(self.prev, "tarpit") or {}).get("log") or [] if self.prev else hp_now
        new_lines = [line for line in hp_now if line not in hp_prev]
        for line in new_lines[-3:]:
            if "auto-banned" in line or "trapped" in line.lower():
                fire({"type": "tarpit_catch", "message": str(line)[:200]})

        # device monitoring: new findings / new devices (deduped by id)
        if section(data, "devices") is not None:
            events, self._device_seen = device_events(data, self._device_seen)
            for etype, payload in events:
                if etype in (EVENT_DEVICE_FINDING, EVENT_NEW_DEVICE) and self.hass.is_running:
                    self.hass.bus.async_fire(etype, payload)

    def _down_list(self, data: dict[str, Any]) -> list[str]:
        services = data.get("services", [])
        present = {s.get("unit"): s.get("active") for s in services}
        return [u for u in CORE_SERVICES if u in present and present[u] != "active"]
