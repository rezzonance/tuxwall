"""Sensors derived from the TuxWall coordinator data."""
from __future__ import annotations

import time
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import TuxwallCoordinator
from .const import ATTR_IFNAME, ATTR_IPV6, DOMAIN

SENSORS: tuple[SensorEntityDescription, ...] = (
    SensorEntityDescription(
        key="attacks_per_min",
        name="Attacks per minute",
        icon="mdi:shield-alert",
        native_unit_of_measurement="/min",
    ),
    SensorEntityDescription(
        key="fw_blocks",
        name="Firewall blocks",
        icon="mdi:firewall",
    ),
    SensorEntityDescription(
        key="crowdsec_bans",
        name="CrowdSec active bans",
        icon="mdi:account-cancel",
    ),
    SensorEntityDescription(
        key="dns_queries",
        name="DNS queries (since restart)",
        icon="mdi:server-network",
    ),
    SensorEntityDescription(
        key="dns_blocked_pct",
        name="DNS blocked",
        icon="mdi:cloud-off-outline",
        native_unit_of_measurement="%",
    ),
    SensorEntityDescription(
        key="dns_cache_hitrate",
        name="DNS cache hit rate",
        icon="mdi:database-check",
        native_unit_of_measurement="%",
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
    ),
    SensorEntityDescription(
        key="honeypot_trapped",
        name="Tarpit trapped connections",
        icon="mdi:spider",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TuxwallCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities(
        [TuxwallSensor(coordinator, entry, desc) for desc in SENSORS],
        update_before_add=False,
    )


class TuxwallSensor(SensorEntity):
    def __init__(
        self,
        coordinator: TuxwallCoordinator,
        entry: ConfigEntry,
        description: SensorEntityDescription,
    ) -> None:
        self.coordinator = coordinator
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.data[CONF_HOST])},
            "name": "TuxWall Gateway",
            "manufacturer": "rezzonance",
            "model": "TuxWall",
        }

    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success

    @property
    def native_value(self) -> Any:
        d = self.coordinator.data
        key = self.entity_description.key
        if key == "attacks_per_min":
            return ((d.get("security") or {}).get("stats") or {}).get("hits_1m")
        if key == "fw_blocks":
            return ((d.get("firewall") or {}).get("traffic") or {}).get("block")
        if key == "crowdsec_bans":
            bans = (d.get("crowdsec") or {}).get("decisions") or []
            return len(bans) if isinstance(bans, list) else None
        if key == "dns_queries":
            return ((d.get("dns") or {}).get("totals") or {}).get("queries")
        if key == "dns_blocked_pct":
            totals = (d.get("dns") or {}).get("totals") or {}
            q, nx = totals.get("queries"), totals.get("nxdomain")
            if not q:
                return None
            return round(100.0 * (nx or 0) / q, 1)
        if key == "dns_cache_hitrate":
            hr = ((d.get("dns") or {}).get("totals") or {}).get("hitrate")
            return round(100.0 * hr, 1) if hr is not None else None
        if key == "wan_ip":
            return ((d.get("system") or {}).get("wan") or {}).get("ipv4")
        if key == "vpn_peers_online":
            peers = (d.get("wireguard") or {}).get("peers") or []
            if not isinstance(peers, list):
                return None
            now = int(time.time())
            return sum(
                1 for p in peers if (p.get("last_handshake") or 0) > now - 180
            )
        if key == "honeypot_trapped":
            hp = d.get("honeypot") or {}
            return hp.get("trapped") if hp.get("enabled") else 0
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        d = self.coordinator.data
        if self.entity_description.key == "wan_ip":
            wan = (d.get("system") or {}).get("wan") or {}
            return {
                ATTR_IFNAME: wan.get("ifname"),
                ATTR_IPV6: (wan.get("ipv6") or [])[:2],
            }
        if self.entity_description.key == "crowdsec_bans":
            bans = (d.get("crowdsec") or {}).get("decisions") or []
            if isinstance(bans, list):
                return {"ips": [b.get("ip") or b.get("value") for b in bans][:25]}
        if self.entity_description.key == "attacks_per_min":
            stats = (d.get("security") or {}).get("stats") or {}
            return {k: stats.get(k) for k in ("unique_ips", "hits_1h")}
        return {}

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self.async_write_ha_state))
