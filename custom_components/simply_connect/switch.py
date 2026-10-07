"""Entidade switch (trava local) do Simply Connect."""
from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SimplyConnectCoordinator
from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinators: list[SimplyConnectCoordinator] = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(SimplyConnectLockSwitch(c) for c in coordinators)


class SimplyConnectLockSwitch(CoordinatorEntity[SimplyConnectCoordinator], RestoreEntity, SwitchEntity):
    """Trava local do portão, independente da API.

    Quando ligado, bloqueia os comandos de abrir e parar vindos do HA —
    só fechar continua permitido. Pensado pra automações (ex.: travar
    junto com o alarme, pra Alexa/voz não conseguir abrir o portão
    enquanto a casa está trancada).
    """

    _attr_icon = "mdi:lock"

    def __init__(self, coordinator: SimplyConnectCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"simply_connect_{coordinator.access_point_id}_locked"
        self._attr_name = "Trancado"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.access_point_id)},
        )

    @property
    def is_on(self) -> bool:
        return self.coordinator.locked

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state is not None:
            self.coordinator.locked = last_state.state == "on"
            self.coordinator.async_update_listeners()

    async def async_turn_on(self, **kwargs: Any) -> None:
        self.coordinator.locked = True
        self._notify()

    async def async_turn_off(self, **kwargs: Any) -> None:
        self.coordinator.locked = False
        self._notify()

    def _notify(self) -> None:
        self.async_write_ha_state()
        # coordinator.locked não vem de um refresh da API — sem isso as
        # outras entidades (cover, button) do mesmo coordinator só
        # reavaliariam available/supported_features no próximo polling.
        self.coordinator.async_update_listeners()
