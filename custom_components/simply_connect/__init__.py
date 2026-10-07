"""Integração Simply Connect (FAAC/Rossi) — engenharia reversa, ver PROGRESS.md."""
from __future__ import annotations

import logging
import time
from dataclasses import asdict
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    InvalidAuth,
    MfaRequired,
    Session,
    SimplyConnectClient,
    SimplyConnectError,
    derive_aes_key,
)
from .const import (
    COMMAND_STOP,
    COMMAND_TOGGLE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    FAST_POLL_DURATION,
    FAST_POLL_INTERVAL,
    LOGICAL_STATUS_CLOSED,
    LOGICAL_STATUS_CLOSING,
    LOGICAL_STATUS_OPEN,
    LOGICAL_STATUS_OPENING,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["cover", "switch", "button"]


class SimplyConnectAccount:
    """Gerencia login/refresh de UMA sessão compartilhada por todos os
    access points da conta — evita logins redundantes (cada login cria uma
    sessão nova no backend, o que pode interferir em identidades recém
    registradas).

    A sessão (token/refreshToken) é persistida na ConfigEntry pra sobreviver
    a restarts do HA: como o login agora pode exigir MFA por e-mail (ver
    api.py), um login() do zero a cada restart exigiria digitar um código a
    cada vez. Com a sessão salva, só precisamos de login() de verdade quando
    o refreshToken expira ou é revogado — e, se isso acontecer sem um
    humano disponível pra digitar o código, levantamos ConfigEntryAuthFailed
    pra disparar o fluxo de reautenticação do próprio Home Assistant.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: SimplyConnectClient,
        identifier: str,
        password: str,
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.client = client
        self._identifier = identifier
        self._password = password
        stored = entry.data.get("session")
        self._session: Session | None = Session(**stored) if stored else None

    def _persist_session(self) -> None:
        self.hass.config_entries.async_update_entry(
            self.entry, data={**self.entry.data, "session": asdict(self._session)}
        )

    async def _login_from_scratch(self) -> None:
        try:
            self._session = await self.client.login(self._identifier, self._password)
        except (MfaRequired, InvalidAuth) as err:
            raise ConfigEntryAuthFailed(str(err)) from err

    async def get_token(self) -> str:
        session_changed = False
        if self._session is None:
            await self._login_from_scratch()
            session_changed = True
        elif self._session.expires_at < time.time():
            try:
                self._session = await self.client.refresh(self._session)
            except SimplyConnectError:
                _LOGGER.debug("Refresh falhou, tentando login de novo")
                await self._login_from_scratch()
            session_changed = True

        if session_changed:
            self._persist_session()
        return self._session.token


class SimplyConnectCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordena polling de status de um access point."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: SimplyConnectClient,
        account: SimplyConnectAccount,
        access_point_id: str,
        uuidm: str,
        private_key_hex: str,
        name: str,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"simply_connect_{access_point_id}",
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )
        self.client = client
        self.account = account
        self.access_point_id = access_point_id
        self.uuidm = uuidm
        self._private_key_hex = private_key_hex
        self.gate_name = name
        self._aes_key: bytes | None = None
        self.optimistic_status: int | None = None
        self._optimistic_target: int | None = None
        self._fast_poll_until: float = 0.0
        # Trava local (switch "Trancado", ver switch.py) — não é estado da
        # API, só bloqueia comandos de abrir/parar vindos do HA.
        self.locked: bool = False

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            token = await self.account.get_token()
            data = await self.client.get_access_point(token, self.access_point_id)
        except SimplyConnectError as err:
            raise UpdateFailed(str(err)) from err

        if self._aes_key is None:
            device_public_key = bytes(data["device"]["publicKey"])
            self._aes_key = derive_aes_key(self._private_key_hex, device_public_key)

        now = time.time()
        if self.optimistic_status is not None:
            if data.get("logicalStatus") == self._optimistic_target:
                # Chegou no estado final esperado de verdade — pode confiar
                # no dado real a partir de agora.
                self.optimistic_status = None
                self._optimistic_target = None
            elif now >= self._fast_poll_until:
                # Estourou o tempo de espera sem confirmar — desiste do
                # otimista pra não travar mostrando algo errado pra sempre.
                self.optimistic_status = None
                self._optimistic_target = None
            # Senão: mantém o otimista, mesmo que o dado real ainda mostre o
            # status antigo (o portão pode levar alguns segundos pra sair do
            # estado antigo de verdade, ver PROGRESS.md).

        if now >= self._fast_poll_until:
            self.update_interval = timedelta(seconds=DEFAULT_SCAN_INTERVAL)

        return data

    def _guess_optimistic_status(self, com: int) -> tuple[int | None, int | None]:
        """Retorna (status otimista, status real que confirma a transição)."""
        current = self.optimistic_status
        if current is None and self.data:
            current = self.data.get("logicalStatus")
        if com == COMMAND_TOGGLE:
            if current == LOGICAL_STATUS_CLOSED:
                return LOGICAL_STATUS_OPENING, LOGICAL_STATUS_OPEN
            if current == LOGICAL_STATUS_OPEN:
                return LOGICAL_STATUS_CLOSING, LOGICAL_STATUS_CLOSED
        # com == COMMAND_STOP (ou estado atual desconhecido): não dá pra
        # adivinhar com confiança, deixa o poll real decidir.
        return None, None

    async def async_send_command(self, com: int) -> None:
        token = await self.account.get_token()
        if self._aes_key is None:
            await self.async_request_refresh()

        self.optimistic_status, self._optimistic_target = self._guess_optimistic_status(com)
        self.async_update_listeners()  # atualiza a UI já com o estado otimista

        await self.client.send_command(
            token, self.access_point_id, self.uuidm, self._aes_key, com
        )

        self._fast_poll_until = time.time() + FAST_POLL_DURATION
        self.update_interval = timedelta(seconds=FAST_POLL_INTERVAL)
        await self.async_request_refresh()


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    session = async_get_clientsession(hass)
    client = SimplyConnectClient(session)
    account = SimplyConnectAccount(
        hass, entry, client, entry.data["identifier"], entry.data["password"]
    )

    coordinators: list[SimplyConnectCoordinator] = []
    for ap in entry.data.get("access_points", []):
        coordinator = SimplyConnectCoordinator(
            hass,
            client,
            account,
            ap["access_point_id"],
            ap["uuidm"],
            ap["private_key"],
            ap["name"],
        )
        await coordinator.async_config_entry_first_refresh()
        coordinators.append(coordinator)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinators

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok
