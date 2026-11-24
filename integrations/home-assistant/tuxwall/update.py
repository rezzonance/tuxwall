"""Update entity "TuxWall": installed vs latest TuxWall version (read-only;
upgrades stay on the router: dashboard System > Updates or apt)."""
from __future__ import annotations

from typing import Any

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, RELEASE_URL, RELEASES_URL
from .coordinator import TuxwallCoordinator
from .entity import TuxwallEntity, iso_attributes
from .summary_data import installed_version, router_latest, section, version_key


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TuxwallCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities([TuxwallUpdate(coordinator, entry)])


class TuxwallUpdate(TuxwallEntity, UpdateEntity):
    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_name = "TuxWall"
    _attr_title = "TuxWall"

    def __init__(self, coordinator: TuxwallCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_update"

    @property
    def available(self) -> bool:
        return super().available and self.installed_version is not None

    @property
    def installed_version(self) -> str | None:
        return installed_version(self.coordinator.data)

    @property
    def latest_version(self) -> str | None:
        latest = router_latest(self.coordinator.data) or self.coordinator.repo_latest
        installed = self.installed_version
        if latest and installed and version_key(installed) > version_key(latest):
            return installed        # a build newer than the repository's
        return latest

    @property
    def release_url(self) -> str:
        latest = self.latest_version
        return RELEASE_URL.format(version=latest) if latest else RELEASES_URL

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        upd = section(self.coordinator.data, "update") or {}
        return iso_attributes({
            "latest_source": "router (apt)" if router_latest(self.coordinator.data)
            else ("apt repository" if self.coordinator.repo_latest else None),
            # when the router last downloaded the apt index
            "checked_at": upd.get("checked_at"),
        })
