"""Sensors derived from the TuxWall coordinator data (see summary_data.VALUES)."""
from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTemperature, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import summary_data
from .const import DOMAIN
from .coordinator import TuxwallCoordinator
from .entity import TuxwallEntity, iso_attributes, to_datetime

MEASUREMENT = SensorStateClass.MEASUREMENT
DIAGNOSTIC = EntityCategory.DIAGNOSTIC

# 1.0 sensors: names and unique_ids are kept as they were (dashboards and
# automations refer to them).
SENSORS: tuple[SensorEntityDescription, ...] = (
    SensorEntityDescription(
        key="attacks_per_min",
        name="Attacks per minute",
        icon="mdi:shield-alert",
        native_unit_of_measurement="/min",
        state_class=MEASUREMENT,
    ),
    SensorEntityDescription(
        key="fw_blocks",
        name="Firewall blocks",
        icon="mdi:firewall",
        state_class=MEASUREMENT,
    ),
    SensorEntityDescription(
        key="crowdsec_bans",
        name="CrowdSec active bans",
        icon="mdi:account-cancel",
        state_class=MEASUREMENT,
    ),
    SensorEntityDescription(
        key="dns_queries",
        name="DNS queries (since restart)",
        icon="mdi:server-network",
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    SensorEntityDescription(
        key="dns_blocked_pct",
        name="DNS blocked",
        icon="mdi:cloud-off-outline",
        native_unit_of_measurement="%",
        state_class=MEASUREMENT,
    ),
    SensorEntityDescription(
        key="dns_cache_hitrate",
        name="DNS cache hit rate",
        icon="mdi:database-check",
        native_unit_of_measurement="%",
        state_class=MEASUREMENT,
    ),
    SensorEntityDescription(
        key="wan_ip",
        name="WAN IP",
        icon="mdi:wan",
    ),
    SensorEntityDescription(
        key="vpn_peers_online",
        name="VPN peers online",
        icon="mdi:vpn",
        state_class=MEASUREMENT,
    ),
    SensorEntityDescription(
        key="honeypot_trapped",
        name="Tarpit trapped connections",
        icon="mdi:spider",
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
)

# 1.2 sensors: translated names (strings.json), icons in icons.json.
NEW_SENSORS: tuple[SensorEntityDescription, ...] = (
    # security
    SensorEntityDescription(key="tarpit_active", translation_key="tarpit_active",
                            has_entity_name=True, state_class=MEASUREMENT),
    SensorEntityDescription(key="canary_hits_24h", translation_key="canary_hits_24h",
                            has_entity_name=True, state_class=MEASUREMENT),
    SensorEntityDescription(key="top_attack_country", translation_key="top_attack_country",
                            has_entity_name=True),
    SensorEntityDescription(key="community_reporting", translation_key="community_reporting",
                            has_entity_name=True, device_class=SensorDeviceClass.ENUM,
                            options=summary_data.COMMUNITY_STATES),
    # network
    SensorEntityDescription(key="internet_latency", translation_key="internet_latency",
                            has_entity_name=True, device_class=SensorDeviceClass.DURATION,
                            native_unit_of_measurement=UnitOfTime.MILLISECONDS,
                            state_class=MEASUREMENT, suggested_display_precision=1),
    SensorEntityDescription(key="dhcp_clients", translation_key="dhcp_clients",
                            has_entity_name=True, state_class=MEASUREMENT),
    SensorEntityDescription(key="blocked_domains", translation_key="blocked_domains",
                            has_entity_name=True, state_class=MEASUREMENT),
    # system (diagnostic)
    SensorEntityDescription(key="cpu_usage", translation_key="cpu_usage", has_entity_name=True,
                            native_unit_of_measurement=PERCENTAGE, state_class=MEASUREMENT,
                            entity_category=DIAGNOSTIC, suggested_display_precision=1),
    SensorEntityDescription(key="memory_usage", translation_key="memory_usage", has_entity_name=True,
                            native_unit_of_measurement=PERCENTAGE, state_class=MEASUREMENT,
                            entity_category=DIAGNOSTIC, suggested_display_precision=1),
    SensorEntityDescription(key="disk_usage", translation_key="disk_usage", has_entity_name=True,
                            native_unit_of_measurement=PERCENTAGE, state_class=MEASUREMENT,
                            entity_category=DIAGNOSTIC, suggested_display_precision=1),
    SensorEntityDescription(key="temperature", translation_key="temperature", has_entity_name=True,
                            device_class=SensorDeviceClass.TEMPERATURE,
                            native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                            state_class=MEASUREMENT, entity_category=DIAGNOSTIC),
    SensorEntityDescription(key="last_boot", translation_key="last_boot", has_entity_name=True,
                            device_class=SensorDeviceClass.TIMESTAMP, entity_category=DIAGNOSTIC),
    SensorEntityDescription(key="tuxwall_version", translation_key="tuxwall_version",
                            has_entity_name=True, entity_category=DIAGNOSTIC),
    # maintenance (diagnostic)
    SensorEntityDescription(key="last_backup", translation_key="last_backup", has_entity_name=True,
                            device_class=SensorDeviceClass.TIMESTAMP, entity_category=DIAGNOSTIC),
    SensorEntityDescription(key="certificate_expiry", translation_key="certificate_expiry",
                            has_entity_name=True, device_class=SensorDeviceClass.TIMESTAMP,
                            entity_category=DIAGNOSTIC),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TuxwallCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities(TuxwallSensor(coordinator, entry, desc) for desc in SENSORS + NEW_SENSORS)


class TuxwallSensor(TuxwallEntity, SensorEntity):
    def __init__(
        self,
        coordinator: TuxwallCoordinator,
        entry: ConfigEntry,
        description: SensorEntityDescription,
    ) -> None:
        super().__init__(coordinator, entry)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"

    @property
    def available(self) -> bool:
        return super().available and summary_data.available(
            self.coordinator.data, self.entity_description.key)

    @property
    def native_value(self) -> Any:
        value = summary_data.value(self.coordinator.data, self.entity_description.key)
        if self.entity_description.device_class == SensorDeviceClass.TIMESTAMP:
            return to_datetime(value)
        return value

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return iso_attributes(summary_data.attributes(self.coordinator.data, self.entity_description.key))
