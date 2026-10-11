"""Binary sensors: per-core-service health plus an aggregate."""
from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import TuxwallCoordinator
from .const import ATTR_DOWN_SERVICES, CORE_SERVICES, DOMAIN

FRIENDLY = {
    "unbound.service": "Unbound DNS",
    "kea-dhcp4-server.service": "Kea DHCP",
    "radvd.service": "radvd",
    "nginx.service": "nginx",
    "suricata.service": "Suricata IDS",
    "crowdsec.service": "CrowdSec",
    "crowdsec-firewall-bouncer.service": "CrowdSec Bouncer",
    "wg-quick@wg0.service": "WireGuard",
    "tuxwall.service": "tuxwall",
    "tuxwall-agent.service": "tuxwall-agent",
    "tuxwall-collector.service": "tuxwall-collector",
    "tuxwall-nat.service": "tuxwall-nat",
    "tuxwall-sqm.service": "tuxwall-sqm",
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TuxwallCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities: list[BinarySensorEntity] = [CoreServicesHealthy(coordinator, entry)]
    entities.extend(
        ServiceBinarySensor(coordinator, entry, unit)
        for unit in CORE_SERVICES
        if _present(coordinator, unit)
    )
    async_add_entities(entities)


def _present(coordinator: TuxwallCoordinator, unit: str) -> bool:
    return any(s.get("unit") == unit for s in coordinator.data.get("services", []))


def _active(coordinator: TuxwallCoordinator, unit: str) -> bool:
    return next(
        (s.get("active") == "active" for s in coordinator.data.get("services", [])
         if s.get("unit") == unit),
        False,
    )


class ServiceBinarySensor(BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.RUNNING

    def __init__(self, coordinator: TuxwallCoordinator, entry: ConfigEntry, unit: str) -> None:
        self.coordinator = coordinator
        self.unit = unit
        self._attr_name = f"TuxWall {FRIENDLY.get(unit, unit)}"
        self._attr_unique_id = f"{entry.entry_id}_svc_{unit.replace('@', '_')}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.data[CONF_HOST])},
            "name": "TuxWall Gateway",
            "manufacturer": "rezzonance",
            "model": "TuxWall",
        }

    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success and _present(self.coordinator, self.unit)

    @property
    def is_on(self) -> bool:
        return _active(self.coordinator, self.unit)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        svc = next(
            (s for s in self.coordinator.data.get("services", []) if s.get("unit") == self.unit),
            {},
        )
        return {"sub": svc.get("sub"), "description": svc.get("desc")}

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self.async_write_ha_state))


class CoreServicesHealthy(ServiceBinarySensor):
    def __init__(self, coordinator: TuxwallCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "__core__")
        self._attr_name = "TuxWall core services healthy"
        self._attr_unique_id = f"{entry.entry_id}_core_healthy"
        self._attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def is_on(self) -> bool:
        return not any(
            s.get("active") != "active"
            for s in self.coordinator.data.get("services", [])
            if s.get("unit") in CORE_SERVICES
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        down = [
            s.get("unit")
            for s in self.coordinator.data.get("services", [])
            if s.get("unit") in CORE_SERVICES and s.get("active") != "active"
        ]
        return {ATTR_DOWN_SERVICES: down}
