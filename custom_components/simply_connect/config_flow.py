"""Config flow do Simply Connect.

Fluxo em 2 passos, replicando exatamente o que o app oficial faz (confirmado
via engenharia reversa + captura em runtime, ver PROGRESS.md):

  1. Email/senha -> login -> gera uma identidade EC nova pra essa instalação
     do HA e registra a chave pública A NÍVEL DE CONTA (não por access
     point!). É esse registro que faz a identidade aparecer como "pendente"
     pra qualquer dispositivo já confiável na conta.
  2. No passo "authorize", chamamos `register_automatic_trust` pra cada
     access point — o endpoint real `POST /cb/v1/whitelist/access-point/
     {id}/automatic-trust`, descoberto via captura de tráfego real do app
     oficial (mitmproxy + emulador Android, v2.6.123): é isso que roda por
     trás do popup "Autorizando... detectamos que você está usando um
     dispositivo não autorizado" que o app mostra pro DONO da conta logo
     após o login. Não precisa de outro dispositivo confiável — o próprio
     servidor ensina o firmware a confiar, usando só a permissão da conta
     no próprio portão. Isso bypassa de vez a tela manual "Usuários ->
     Você -> GERENCIAR -> autorizar todos dispositivos", que numa conta
     com MFA nem está mais disponível pra usuário final (só instalador).

Desde a v2.6.58 do app oficial, o `/login` pode exigir MFA (TOTP ou código
por e-mail) antes de liberar a sessão. Confirmado via engenharia reversa do
app oficial (v2.6.123, decompilado com jadx): não existe endpoint separado
pra confirmar o código — o app chama o mesmo `/login` de novo, mandando
`mailOtp` + `preAuthToken` (ver `SimplyConnectClient.confirm_email_otp`).
Só implementamos o fluxo EMAIL_OTP aqui (é o que o backend está exigindo da
nossa conta); TOTP cai em erro "unsupported_mfa".
"""
from __future__ import annotations

import logging
import secrets
from dataclasses import asdict
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    CannotConnect,
    InvalidAuth,
    MfaRequired,
    Session,
    SimplyConnectClient,
    SimplyConnectError,
    generate_keypair,
    generate_mobile_id,
)
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("identifier"): str,
        vol.Required("password"): str,
    }
)
STEP_MFA_EMAIL_DATA_SCHEMA = vol.Schema({vol.Required("code"): str})
STEP_REAUTH_CONFIRM_DATA_SCHEMA = vol.Schema({vol.Required("password"): str})


class SimplyConnectConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow."""

    VERSION = 1

    def __init__(self) -> None:
        self._identifier: str | None = None
        self._password: str | None = None
        self._pre_auth_token: str | None = None
        self._login: Session | None = None
        self._access_points: list[dict[str, Any]] = []
        self._mobile_id: str | None = None
        self._private_key_hex: str | None = None
        self._public_key: list[int] | None = None
        self._reauth_entry: config_entries.ConfigEntry | None = None
        self._client: SimplyConnectClient | None = None

    async def _finish_login(self, client: SimplyConnectClient, login: Session) -> str | None:
        """Pós-login: descobre access points e registra a chave da conta.

        Em sucesso guarda o estado em self.* e retorna None; em erro retorna
        a chave de erro pra mostrar no form que chamou.
        """
        await self.async_set_unique_id(login.user_id)
        self._abort_if_unique_id_configured()

        try:
            access_points = await client.get_access_points(login.token)
            _LOGGER.debug("Access points encontrados: %s", access_points)
        except SimplyConnectError:
            _LOGGER.exception("Erro buscando access points")
            return "unknown"

        if not access_points:
            return "no_access_points"

        private_key, public_key = generate_keypair()
        # Seed aleatório (não o core_uuid fixo): cada tentativa de setup gera
        # um keypair novo, e o backend parece rejeitar reusar o mesmo
        # mobileId com uma publicKey diferente (ver histórico de erros
        # invalid-parameters ao repetir a configuração).
        mobile_id = generate_mobile_id(secrets.token_hex(16))
        client.set_mobile_id(mobile_id)

        try:
            # Precisa vir ANTES do resto: dá os headers device-Id/
            # configuration-id que o automatic-trust exige (ver api.py) —
            # sem isso ele responde "ok" mas não autoriza nada de verdade.
            await client.register_device()
            await client.register_account_public_key(
                login.token, mobile_id, "Home Assistant", public_key
            )
        except SimplyConnectError:
            _LOGGER.exception("Erro registrando o device/chave pública")
            return "unknown"

        self._login = login
        self._client = client
        self._access_points = access_points
        self._mobile_id = mobile_id
        self._private_key_hex = private_key.hex()
        self._public_key = public_key
        return None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            client = SimplyConnectClient(session)

            try:
                login = await client.login(user_input["identifier"], user_input["password"])
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except MfaRequired as mfa:
                if mfa.challenge.mfa_type != "EMAIL_OTP":
                    errors["base"] = "unsupported_mfa"
                else:
                    self._identifier = user_input["identifier"]
                    self._password = user_input["password"]
                    self._pre_auth_token = mfa.challenge.pre_auth_token
                    return await self.async_step_mfa_email()
            except SimplyConnectError:
                _LOGGER.exception("Erro inesperado no login")
                errors["base"] = "unknown"
            else:
                self._identifier = user_input["identifier"]
                self._password = user_input["password"]
                error = await self._finish_login(client, login)
                if error:
                    errors["base"] = error
                else:
                    return await self.async_step_authorize()

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_mfa_email(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Segundo passo do login: código recebido por e-mail (MFA)."""
        errors: dict[str, str] = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            client = SimplyConnectClient(session)

            try:
                login = await client.confirm_email_otp(
                    self._identifier, self._password, user_input["code"], self._pre_auth_token
                )
            except InvalidAuth:
                errors["base"] = "invalid_otp"
            except SimplyConnectError:
                _LOGGER.exception("Erro confirmando código MFA")
                errors["base"] = "unknown"
            else:
                error = await self._finish_login(client, login)
                if error:
                    errors["base"] = error
                else:
                    return await self.async_step_authorize()

        return self.async_show_form(
            step_id="mfa_email", data_schema=STEP_MFA_EMAIL_DATA_SCHEMA, errors=errors
        )

    async def async_step_authorize(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Autoriza automaticamente (sem interação manual no outro
        dispositivo) via `register_automatic_trust` — ver docstring do
        método em api.py. Só mostra um form se a autorização falhar, com
        um botão "tentar de novo" que reusa a sessão já logada (sem pedir
        identifier/password/código de novo)."""
        assert self._client is not None
        client = self._client

        result: list[dict[str, Any]] = []
        for ap in self._access_points:
            ap_id = ap["id"]
            try:
                await client.register_automatic_trust(
                    self._login.token, ap_id, "Home Assistant", self._public_key
                )
            except SimplyConnectError:
                _LOGGER.warning("Erro na autorização automática de %s", ap_id)

            try:
                entry = await client.get_whitelist_entry(
                    self._login.token, ap_id, self._mobile_id
                )
            except SimplyConnectError:
                _LOGGER.warning("Erro consultando whitelist de %s", ap_id)
                continue
            if entry is None:
                _LOGGER.warning("Identidade ainda não autorizada em %s — pulei", ap_id)
                continue
            result.append(
                {
                    "access_point_id": ap_id,
                    "name": ap.get("name", "Portão"),
                    "uuidm": entry["uuidm"],
                    "private_key": self._private_key_hex,
                }
            )

        if not result:
            return self.async_show_form(
                step_id="authorize",
                data_schema=vol.Schema({}),
                errors={"base": "not_authorized_yet"},
            )

        return self.async_create_entry(
            title=f"Simply Connect ({self._login.email})",
            data={
                "identifier": self._identifier,
                "password": self._password,
                "access_points": result,
                "session": asdict(self._login),
            },
        )

    # --- Reauth: disparado pelo HA quando a integração levanta
    # ConfigEntryAuthFailed (sessão não dá mais pra renovar sozinha, por
    # senha errada ou MFA pedido de novo) ---

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> config_entries.ConfigFlowResult:
        self._reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}
        assert self._reauth_entry is not None

        if user_input is not None:
            identifier = self._reauth_entry.data["identifier"]
            password = user_input["password"]
            client = SimplyConnectClient(async_get_clientsession(self.hass))

            try:
                login = await client.login(identifier, password)
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except MfaRequired as mfa:
                if mfa.challenge.mfa_type != "EMAIL_OTP":
                    errors["base"] = "unsupported_mfa"
                else:
                    self._identifier = identifier
                    self._password = password
                    self._pre_auth_token = mfa.challenge.pre_auth_token
                    return await self.async_step_reauth_mfa_email()
            except SimplyConnectError:
                _LOGGER.exception("Erro inesperado no reauth")
                errors["base"] = "unknown"
            else:
                return self._update_reauth_entry(login, password)

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=STEP_REAUTH_CONFIRM_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth_mfa_email(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            client = SimplyConnectClient(async_get_clientsession(self.hass))
            try:
                login = await client.confirm_email_otp(
                    self._identifier, self._password, user_input["code"], self._pre_auth_token
                )
            except InvalidAuth:
                errors["base"] = "invalid_otp"
            except SimplyConnectError:
                _LOGGER.exception("Erro confirmando código MFA no reauth")
                errors["base"] = "unknown"
            else:
                return self._update_reauth_entry(login, self._password)

        return self.async_show_form(
            step_id="reauth_mfa_email", data_schema=STEP_MFA_EMAIL_DATA_SCHEMA, errors=errors
        )

    def _update_reauth_entry(
        self, login: Session, password: str
    ) -> config_entries.ConfigFlowResult:
        assert self._reauth_entry is not None
        new_data = {**self._reauth_entry.data, "password": password, "session": asdict(login)}
        return self.async_update_reload_and_abort(self._reauth_entry, data=new_data)
