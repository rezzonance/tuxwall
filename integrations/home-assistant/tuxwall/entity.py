"""Base entity: one TuxWall Gateway device, fed by the coordinator."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TuxwallCoordinator
from .summary_data import TIMESTAMP_ATTRS, installed_version


def to_datetime(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc)


def iso_attributes(attrs: dict[str, Any]) -> dict[str, Any]:
    """Epoch-second attributes as ISO 8601 strings (readable, templatable)."""
    out = dict(attrs)
    for key in TIMESTAMP_ATTRS & out.keys():
        dt = to_datetime(out[key])
        out[key] = dt.isoformat() if dt else None
    return out


class TuxwallEntity(CoordinatorEntity[TuxwallCoordinator]):
    def __init__(self, coordinator: TuxwallCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        host = entry.data[CONF_HOST]
        self._attr_device_info = {
            "identifiers": {(DOMAIN, host)},
            "name": "TuxWall Gateway",
            "manufacturer": "rezzonance",
            "model": "TuxWall",
            "sw_version": installed_version(coordinator.data),
            "configuration_url": host if host.startswith(("http://", "https://")) else None,
        }
