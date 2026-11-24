"""Binary sensors: per-core-service health plus an aggregate, Tripwire and
WAN / IPv6 connectivity."""
from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import summary_data
from .const import ATTR_DOWN_SERVICES, CORE_SERVICES, DOMAIN
from .coordinator import TuxwallCoordinator
from .entity import TuxwallEntity, iso_attributes

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

BINARY_SENSORS: tuple[BinarySensorEntityDescription, ...] = (
    BinarySensorEntityDescription(key="tripwire", translation_key="tripwire", has_entity_name=True,
                                  device_class=BinarySensorDeviceClass.PROBLEM),
    BinarySensorEntityDescription(key="wan_connectivity", translation_key="wan_connectivity",
                                  has_entity_name=True, device_class=BinarySensorDeviceClass.CONNECTIVITY),
    BinarySensorEntityDescription(key="ipv6_connectivity", translation_key="ipv6_connectivity",
                                  has_entity_name=True, device_class=BinarySensorDeviceClass.CONNECTIVITY),
)


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
        if _service(coordinator, unit) is not None
    )
    entities.extend(TuxwallBinarySensor(coordinator, entry, desc) for desc in BINARY_SENSORS)
    async_add_entities(entities)


def _services(coordinator: TuxwallCoordinator) -> list[dict[str, Any]]:
    return (coordinator.data or {}).get("services") or []


def _service(coordinator: TuxwallCoordinator, unit: str) -> dict[str, Any] | None:
    return next((s for s in _services(coordinator) if s.get("unit") == unit), None)


def _services_known(coordinator: TuxwallCoordinator) -> bool:
    return summary_data.section(coordinator.data, "services") is not None


class ServiceBinarySensor(TuxwallEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.RUNNING

    def __init__(self, coordinator: TuxwallCoordinator, entry: ConfigEntry, unit: str) -> None:
        super().__init__(coordinator, entry)
        self.unit = unit
        self._attr_name = f"TuxWall {FRIENDLY.get(unit, unit)}"
        self._attr_unique_id = f"{entry.entry_id}_svc_{unit.replace('@', '_')}"

    @property
    def available(self) -> bool:
        return super().available and _service(self.coordinator, self.unit) is not None

    @property
    def is_on(self) -> bool:
        return (_service(self.coordinator, self.unit) or {}).get("active") == "active"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        svc = _service(self.coordinator, self.unit) or {}
        return {"sub": svc.get("sub"), "description": svc.get("desc")}


class CoreServicesHealthy(TuxwallEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.RUNNING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: TuxwallCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry)
        self._attr_name = "TuxWall core services healthy"
        self._attr_unique_id = f"{entry.entry_id}_core_healthy"

    def _down(self) -> list[str]:
        return [
            s.get("unit")
            for s in _services(self.coordinator)
            if s.get("unit") in CORE_SERVICES and s.get("active") != "active"
        ]

    @property
    def available(self) -> bool:
        return super().available and _services_known(self.coordinator)

    @property
    def is_on(self) -> bool:
        return not self._down()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {ATTR_DOWN_SERVICES: self._down()}


class TuxwallBinarySensor(TuxwallEntity, BinarySensorEntity):
    def __init__(
        self,
        coordinator: TuxwallCoordinator,
        entry: ConfigEntry,
        description: BinarySensorEntityDescription,
    ) -> None:
        super().__init__(coordinator, entry)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"

    @property
    def available(self) -> bool:
        return super().available and summary_data.available(
            self.coordinator.data, self.entity_description.key)

    @property
    def is_on(self) -> bool | None:
        value = summary_data.value(self.coordinator.data, self.entity_description.key)
        return None if value is None else bool(value)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return iso_attributes(summary_data.attributes(self.coordinator.data, self.entity_description.key))
