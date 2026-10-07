"""Entidade cover (portão) do Simply Connect."""
from __future__ import annotations

from typing import Any

from homeassistant.components.cover import (
    CoverDeviceClass,
    CoverEntity,
    CoverEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SimplyConnectCoordinator
from .const import (
    COMMAND_STOP,
    COMMAND_TOGGLE,
    DOMAIN,
    LOGICAL_STATUS_CLOSED,
    LOGICAL_STATUS_CLOSING,
    LOGICAL_STATUS_OPEN,
    LOGICAL_STATUS_OPENING,
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinators: list[SimplyConnectCoordinator] = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(SimplyConnectGate(c) for c in coordinators)


class SimplyConnectGate(CoordinatorEntity[SimplyConnectCoordinator], CoverEntity):
    """Representa o portão como um cover do tipo gate."""

    _attr_device_class = CoverDeviceClass.GATE
    _attr_icon = "mdi:gate"
    # device_class GATE não tem tradução pt-BR completa pro estado
    # (opening/closing ficavam em inglês) no core do HA — definindo isso
    # a gente fornece a tradução pela própria integração (ver strings.json
    # "entity.cover.gate.state").
    _attr_translation_key = "gate"

    def __init__(self, coordinator: SimplyConnectCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"simply_connect_{coordinator.access_point_id}"
        self._attr_name = coordinator.gate_name
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.access_point_id)},
            name=coordinator.gate_name,
            manufacturer="FAAC / Rossi",
            model="Simply Connect",
        )

    @property
    def _logical_status(self) -> int | None:
        if self.coordinator.optimistic_status is not None:
            return self.coordinator.optimistic_status
        if not self.coordinator.data:
            return None
        return self.coordinator.data.get("logicalStatus")

    @property
    def is_closed(self) -> bool | None:
        status = self._logical_status
        if status is None:
            return None
        return status == LOGICAL_STATUS_CLOSED

    @property
    def is_opening(self) -> bool:
        return self._logical_status == LOGICAL_STATUS_OPENING

    @property
    def is_closing(self) -> bool:
        return self._logical_status == LOGICAL_STATUS_CLOSING

    @property
    def available(self) -> bool:
        if not self.coordinator.data:
            return False
        return bool(self.coordinator.data.get("online", False))

    @property
    def supported_features(self) -> CoverEntityFeature:
        # Trancado: some OPEN e STOP do card (fica cinza/sem clique),
        # não só ignora silenciosamente — só CLOSE continua disponível.
        if self.coordinator.locked:
            return CoverEntityFeature.CLOSE
        return (
            CoverEntityFeature.OPEN | CoverEntityFeature.CLOSE | CoverEntityFeature.STOP
        )

    async def async_open_cover(self, **kwargs: Any) -> None:
        if self.coordinator.locked:
            return
        if self._logical_status in (LOGICAL_STATUS_OPEN, LOGICAL_STATUS_OPENING):
            return
        await self.coordinator.async_send_command(COMMAND_TOGGLE)

    async def async_close_cover(self, **kwargs: Any) -> None:
        # Fechar é sempre permitido, mesmo trancado (é literalmente o
        # ponto da trava: impedir abrir, não impedir fechar).
        if self._logical_status in (LOGICAL_STATUS_CLOSED, LOGICAL_STATUS_CLOSING):
            return
        await self.coordinator.async_send_command(COMMAND_TOGGLE)

    async def async_stop_cover(self, **kwargs: Any) -> None:
        if self.coordinator.locked:
            return
        await self.coordinator.async_send_command(COMMAND_STOP)
