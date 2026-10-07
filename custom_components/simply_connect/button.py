"""Entidade button (abertura parcial/pedestre) do Simply Connect."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SimplyConnectCoordinator
from .const import COMMAND_PARTIAL, DOMAIN, LOGICAL_STATUS_CLOSED


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinators: list[SimplyConnectCoordinator] = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(SimplyConnectPedestrianButton(c) for c in coordinators)


class SimplyConnectPedestrianButton(CoordinatorEntity[SimplyConnectCoordinator], ButtonEntity):
    """Abertura parcial (passagem de pedestre), sem abrir o portão todo."""

    _attr_icon = "mdi:walk"

    def __init__(self, coordinator: SimplyConnectCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"simply_connect_{coordinator.access_point_id}_pedestrian"
        self._attr_name = "Abrir Parcial"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.access_point_id)},
        )

    @property
    def _logical_status(self) -> int | None:
        if self.coordinator.optimistic_status is not None:
            return self.coordinator.optimistic_status
        if not self.coordinator.data:
            return None
        return self.coordinator.data.get("logicalStatus")

    @property
    def available(self) -> bool:
        if not self.coordinator.data:
            return False
        if self.coordinator.locked:
            return False
        if not self.coordinator.data.get("online", False):
            return False
        # Só faz sentido parcial com o portão fechado — aberto/abrindo/
        # fechando fica indisponível em vez de mandar um comando com
        # efeito desconhecido nesses estados.
        return self._logical_status == LOGICAL_STATUS_CLOSED

    async def async_press(self) -> None:
        if not self.available:
            return
        await self.coordinator.async_send_command(COMMAND_PARTIAL)
