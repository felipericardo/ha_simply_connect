"""Cliente da API do Simply Connect (FAAC/Rossi), engenharia reversa documentada em PROGRESS.md."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import aiohttp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .const import API_ROOT, BASE_URL, COMMAND_STOP, COMMAND_TOGGLE

_LOGGER = logging.getLogger(__name__)


class SimplyConnectError(Exception):
    """Erro genérico da API."""


class InvalidAuth(SimplyConnectError):
    """Credenciais inválidas."""


class CannotConnect(SimplyConnectError):
    """Não foi possível conectar."""


@dataclass
class MfaChallenge:
    """Dados devolvidos pelo backend quando o login pede confirmação de MFA.

    Descoberto via engenharia reversa do app oficial (v2.6.123): não existe
    endpoint separado pra confirmar o código — o app chama o mesmo `/login`
    de novo, mandando `mailOtp` (código recebido por e-mail) + `preAuthToken`
    (o valor devolvido aqui, que pode legitimamente vir `None` — o app
    reenvia `None` nesse caso e funciona do mesmo jeito)."""

    mfa_type: str | None
    pre_auth_token: str | None


class MfaRequired(SimplyConnectError):
    """Backend pediu confirmação de MFA (ex.: código por e-mail) antes de liberar a sessão."""

    def __init__(self, challenge: MfaChallenge) -> None:
        super().__init__(f"Login requer confirmação de MFA (tipo={challenge.mfa_type})")
        self.challenge = challenge


@dataclass
class Session:
    token: str
    refresh_token: str
    expires_at: float
    user_id: str
    email: str


def generate_keypair() -> tuple[bytes, list[int]]:
    """Gera um par de chaves EC P-256. Retorna (chave privada 32 bytes, chave pública comprimida como lista de ints)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    compressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    private_bytes = private_key.private_numbers().private_value.to_bytes(32, "big")
    return private_bytes, list(compressed)


def generate_mobile_id(seed: str) -> str:
    """Gera um `mobileId` estável (determinístico a partir de `seed`) no
    mesmo formato que o app oficial usa de verdade: o app usa o Firebase
    Instance ID (~22 caracteres, alfabeto base64url) como `mobileId` — ver
    `register_account_public_key`. Não registramos nada no Firebase (não
    mandamos push), só imitamos a FORMA, porque suspeitamos que o backend
    passou a validar isso (`invalid-parameters` com o ID curto anterior,
    tipo "ha-xxxxxxxxxxxx")."""
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")[:22]


def derive_aes_key(private_key_hex: str, device_public_key_bytes: bytes) -> bytes:
    """ECDH (P-256) + SHA-256, replicando o algoritmo do app (ver PROGRESS.md)."""
    priv_int = int(private_key_hex, 16)
    private_key = ec.derive_private_key(priv_int, ec.SECP256R1(), default_backend())
    device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), device_public_key_bytes
    )
    shared_secret = private_key.exchange(ec.ECDH(), device_public_key)
    if len(shared_secret) > 32:
        shared_secret = shared_secret[-32:]
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    return digest.finalize()


def compute_cks(com: int) -> int:
    """Checksum determinístico do campo `com` (replica p299pe.D.a() do app)."""
    b = com.to_bytes(4, "big", signed=True)
    checksum = (sum(b) % 256 + 1) % 256
    return (~checksum) & 0xFF


def _aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    pad_len = (16 - len(plaintext) % 16) % 16
    padded = plaintext + b"\x00" * pad_len
    encryptor = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def encrypt_command_payload(aes_key: bytes, com: int) -> tuple[bytes, int]:
    cks = compute_cks(com)
    payload = {"cks": cks, "com": com, "token": int(time.time() * 1000)}
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return _aes_ecb_encrypt(aes_key, plaintext), cks


def encrypt_add_whitelist_payload(
    aes_key: bytes, new_uuidm: str, new_public_key: list[int], is_admin: bool = False
) -> bytes:
    public_key_hex = bytes(new_public_key).hex().upper()
    payload = {
        "uuidm": new_uuidm,
        "val": public_key_hex,
        "isOtp": 0,
        "isAdmin": 1 if is_admin else 0,
        "token": int(time.time() * 1000),
    }
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return _aes_ecb_encrypt(aes_key, plaintext)


class SimplyConnectClient:
    """Cliente async pra API do Simply Connect."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self._session = session
        self._mobile_id: str | None = None
        self._device_id: str | None = None
        self._configuration_id: str | None = None

    def set_mobile_id(self, mobile_id: str) -> None:
        """Associa o `mobileId` dessa identidade a TODAS as chamadas
        seguintes (header `mobile-id`) — o app oficial manda isso desde o
        início da sessão, confirmado via captura de tráfego real."""
        self._mobile_id = mobile_id

    async def register_device(self) -> None:
        """Registra um "device" de tracking e guarda `deviceId`/
        `configurationId` pra incluir como headers nas próximas chamadas.

        Descoberto via captura de tráfego real do app oficial (mitmproxy):
        o `/cb/v1/whitelist/access-point/{id}/automatic-trust` (ver
        `register_automatic_trust`) exige os headers `device-Id` e
        `configuration-id` — sem eles, a chamada responde "ok" mas não
        autoriza nada de verdade. Esses valores só existem depois de
        chamar esse endpoint pelo menos uma vez.
        """
        body = {
            "appName": "simplyconnect_enduser",
            "appVersion": "2.6.123",
            "country": "US",
            "details": {"model": "Home Assistant"},
            "operativeSystem": "android",
            "operativeSystemVersion": "13",
        }
        async with self._session.post(
            f"{BASE_URL}/tracking/device/register", json=body, headers=self._headers()
        ) as resp:
            status = resp.status
            data = await resp.json()
        _LOGGER.debug("register_device (tracking/device/register) status=%s body=%s", status, data)
        if status >= 400 or data.get("status") == "error":
            raise SimplyConnectError(
                f"Falha registrando device de tracking (status={status}, corpo={data})"
            )
        item = data.get("item", {})
        self._device_id = item.get("deviceId")
        self._configuration_id = item.get("configurationId")

    def _headers(self, token: str | None = None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "app-name": "simplyconnect_enduser",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if self._mobile_id:
            headers["mobile-id"] = self._mobile_id
        if self._device_id:
            headers["device-Id"] = self._device_id
        if self._configuration_id:
            headers["configuration-id"] = self._configuration_id
        return headers

    async def _post_login(self, body: dict[str, Any]) -> Session:
        try:
            async with self._session.post(
                f"{BASE_URL}/login", json=body, headers=self._headers()
            ) as resp:
                data = await resp.json()
        except aiohttp.ClientError as err:
            raise CannotConnect from err

        if data.get("status") == "error":
            code = data.get("error", {}).get("code")
            if code == "invalid-credentials":
                # Confirmado via engenharia reversa: o backend reusa o mesmo
                # código tanto pra senha errada quanto pra código MFA errado.
                raise InvalidAuth(data["error"].get("message"))
            raise SimplyConnectError(data["error"].get("message", "unknown error"))

        item = data["item"]
        if item.get("isOtpRequired") or not item.get("user"):
            # Confirmado via engenharia reversa do app oficial (v2.6.123): não
            # existe endpoint separado de "confirmar OTP" — o app chama esse
            # mesmo /login de novo passando mailOtp + preAuthToken (ver
            # confirm_email_otp). preAuthToken pode legitimamente vir None.
            _LOGGER.debug("login pendente de MFA; corpo=%s", data)
            raise MfaRequired(
                MfaChallenge(
                    mfa_type=item.get("mfaType"), pre_auth_token=item.get("preAuthToken")
                )
            )

        _LOGGER.debug("login OK, user=%s userId=%s", item["user"]["email"], item["user"]["userId"])
        return Session(
            token=item["token"],
            refresh_token=item["refreshToken"],
            expires_at=time.time() + item.get("tokenExpiresIn", 3600) - 60,
            user_id=item["user"]["userId"],
            email=item["user"]["email"],
        )

    async def login(self, identifier: str, password: str) -> Session:
        # O app oficial usa a versão de login sem deviceUUID (fica None) pro
        # fluxo normal de email/senha — replicamos isso. Mandar um deviceUUID
        # aleatório a cada chamada parece confundir o backend (associado ao
        # desaparecimento espontâneo de identidades recém-registradas).
        body = {
            "identifier": identifier,
            "password": password,
            "scope": "smartaccess",
        }
        return await self._post_login(body)

    async def confirm_email_otp(
        self, identifier: str, password: str, code: str, pre_auth_token: str | None
    ) -> Session:
        """Segundo passo do login quando MfaRequired(mfa_type="EMAIL_OTP") é levantado.

        Apesar do app oficial ter um campo `mailOtp` em `Login`, o setter
        correspondente (visto no decompilado) na verdade grava no campo
        `totp` — um artefato de otimização do R8 que colapsou os dois
        setters num só. `mailOtp` nunca é escrito por ninguém e fica sempre
        None (não vai no JSON). É `totp` quem de fato carrega o código,
        tanto pro fluxo EMAIL_OTP quanto pro TOTP.
        """
        body = {
            "identifier": identifier,
            "password": password,
            "totp": code,
            "preAuthToken": pre_auth_token,
            "scope": "smartaccess",
        }
        return await self._post_login(body)

    async def refresh(self, session: Session) -> Session:
        body = {"refreshToken": session.refresh_token}
        async with self._session.post(
            f"{BASE_URL}/refresh",
            json=body,
            headers=self._headers(session.token),
        ) as resp:
            data = await resp.json()
        if data.get("status") == "error":
            raise InvalidAuth(data.get("error", {}).get("message", "refresh failed"))
        item = data["item"]
        return Session(
            token=item["token"],
            refresh_token=item["refreshToken"],
            expires_at=time.time() + item.get("tokenExpiresIn", 3600) - 60,
            user_id=session.user_id,
            email=session.email,
        )

    async def get_access_points(self, token: str) -> list[dict[str, Any]]:
        url = f"{BASE_URL}/simply-connect/access-points"
        params = {"page": 1, "pageSize": 100, "disabled": "false"}
        async with self._session.get(
            url, params=params, headers=self._headers(token)
        ) as resp:
            status = resp.status
            data = await resp.json()
        _LOGGER.debug(
            "get_access_points (simply-connect/access-points) status=%s body=%s",
            status,
            data,
        )
        # A resposta real vem como {"status":"ok","total":N,"page":{"items":[...]}}
        return data.get("page", {}).get("items", [])

    async def get_access_point(self, token: str, access_point_id: str) -> dict[str, Any]:
        url = f"{BASE_URL}/smartaccess/access-point/{access_point_id}"
        async with self._session.get(url, headers=self._headers(token)) as resp:
            data = await resp.json()
        return data["item"]

    async def get_whitelist_entry(
        self, token: str, access_point_id: str, mobile_id: str
    ) -> dict[str, Any] | None:
        url = f"{BASE_URL}/simply-connect/automations/{access_point_id}/whitelist"
        params = {"pu": "true"}
        async with self._session.get(
            url, params=params, headers=self._headers(token)
        ) as resp:
            data = await resp.json()
        for item in data.get("items", []):
            for entry in item.get("uuidmAndPublicKeys", []):
                if entry.get("mobileId") == mobile_id:
                    return entry
        return None

    async def register_account_public_key(
        self,
        token: str,
        mobile_id: str,
        mobile_name: str,
        public_key: list[int],
    ) -> None:
        """Registra a chave pública a nível de CONTA (não por access point).

        É isso que o app real faz automaticamente no login (ver `U0.h()` no
        decompilado, builder `PublicKeyRequest.Builder().mobileId(...).mobileName(...).key(...)`
        — sem `userId`) — e é o que faz a identidade aparecer como "pendente"
        pra qualquer dispositivo já confiável autorizar via Usuários -> Você
        -> GERENCIAR. Chamar o endpoint por access point diretamente
        (`smartaccess/access-point/{id}/whitelist`) marca como "autorizado"
        na hora só no banco da nuvem, sem o firmware nunca aprender a
        confiar na chave — descoberto via engenharia reversa, ver PROGRESS.md.

        `publicKey` vai como array de bytes SEM sinal (0-255) — confirmado
        lendo a resposta real da API no HAR antigo (`device.publicKey` vem
        com valores como 255, 207, 234, nunca negativos). Uma tentativa
        anterior de converter pra signed (-128..127) estava errada e foi
        revertida.
        """
        url = f"{BASE_URL}/smartaccess/user/public-key"
        body = {
            "mobileId": mobile_id,
            "mobileName": mobile_name,
            "publicKey": public_key,
        }
        async with self._session.post(
            url, json=body, headers=self._headers(token)
        ) as resp:
            status = resp.status
            data = await resp.json()
        _LOGGER.debug(
            "register_account_public_key (smartaccess/user/public-key) status=%s body=%s",
            status,
            data,
        )
        if status >= 400 or data.get("status") == "error":
            raise SimplyConnectError(
                f"Falha registrando chave pública (status={status}, corpo={data})"
            )

    async def register_automatic_trust(
        self,
        token: str,
        access_point_id: str,
        mobile_name: str,
        public_key: list[int],
    ) -> None:
        """Auto-autoriza a identidade atual (do token logado) num access
        point específico — SEM precisar de outro dispositivo confiável.

        Descoberto via captura de tráfego real do app oficial (mitmproxy
        contra um emulador Android, v2.6.123): é exatamente isso que o
        popup "Autorizando... detectamos que você está usando um
        dispositivo não autorizado" faz por trás dos panos, pro próprio
        dono da conta. Não é o `smartaccess/access-point/{id}/whitelist`
        "cru" que a engenharia reversa antiga (pré-MFA) tinha mapeado —
        é um endpoint novo, sob `/cb/` (fora do prefixo `/v2`).

        `publicKey` vai como bytes COM sinal (-128..127, semântica Java
        byte) — confirmado na captura real (valores negativos no corpo).
        """
        url = f"{API_ROOT}/cb/v1/whitelist/access-point/{access_point_id}/automatic-trust"
        signed_public_key = [v - 256 if v > 127 else v for v in public_key]
        body = {
            "mobileDeviceTime": int(time.time() * 1000),
            "mobileName": mobile_name,
            "publicKey": signed_public_key,
        }
        async with self._session.post(
            url, json=body, headers=self._headers(token)
        ) as resp:
            status = resp.status
            data = await resp.json()
        _LOGGER.debug(
            "register_automatic_trust (cb/v1/whitelist/access-point/%s/automatic-trust) "
            "status=%s body=%s",
            access_point_id,
            status,
            data,
        )
        if status >= 400 or data.get("status") == "error":
            raise SimplyConnectError(
                f"Falha na autorização automática (status={status}, corpo={data})"
            )

    async def register_access_point_whitelist(
        self,
        token: str,
        access_point_id: str,
        user_id: str,
        mobile_id: str,
        mobile_name: str,
        public_key: list[int],
    ) -> None:
        """Registra a identidade DIRETO na whitelist de UM access point específico.

        Mantido como referência/fallback, mas não é mais usado pelo
        config_flow — ver `register_automatic_trust`, que é o que o app
        oficial de verdade faz e dá pro firmware aprender a confiar sozinho.

        Diferente de `register_account_public_key` (nível de conta, que
        deveria aparecer como "pendente" pra outro dispositivo aprovar):
        esse endpoint cria a entrada imediatamente, sem gate de aprovação —
        confirmado via engenharia reversa (ver PROGRESS.md): quem tem
        `EDIT_USERS_IN_WHITELIST` no access point (o próprio dono da conta
        tem, no seu próprio portão) consegue inserir direto, servidor
        responde ok e atribui um `uuidm` na hora.

        ATENÇÃO: isso só garante o registro no banco da nuvem. O FIRMWARE
        do portão só aprende a confiar na chave via um comando MQTT
        `ADD_WHITELIST` assinado por uma identidade que ele já confia —
        sem isso, comandos podem voltar com `{"status":"ok"}` mas o portão
        não se move fisicamente de verdade (já visto acontecer antes).
        """
        url = f"{BASE_URL}/smartaccess/access-point/{access_point_id}/whitelist"
        body = {
            "userId": user_id,
            "mobileId": mobile_id,
            "mobileName": mobile_name,
            "publicKey": public_key,
        }
        async with self._session.post(
            url, json=body, headers=self._headers(token)
        ) as resp:
            status = resp.status
            data = await resp.json()
        _LOGGER.debug(
            "register_access_point_whitelist (access-point/%s/whitelist) status=%s body=%s",
            access_point_id,
            status,
            data,
        )
        if status >= 400 or data.get("status") == "error":
            raise SimplyConnectError(
                f"Falha registrando whitelist do access point (status={status}, corpo={data})"
            )

    async def send_add_whitelist(
        self,
        token: str,
        access_point_id: str,
        bootstrap_uuidm: str,
        bootstrap_aes_key: bytes,
        new_uuidm: str,
        new_public_key: list[int],
    ) -> None:
        crypted = encrypt_add_whitelist_payload(bootstrap_aes_key, new_uuidm, new_public_key)
        public_key_hex = bytes(new_public_key).hex().upper()
        body = {
            "uuidm": bootstrap_uuidm,
            "cryptedPyl": list(crypted),
            "cmd": 26,
            "pyl": {"uuidm": new_uuidm, "val": public_key_hex, "isOtp": 0, "isAdmin": 0},
        }
        url = f"{BASE_URL}/smartaccess/access-point/{access_point_id}/mqtt-message"
        async with self._session.post(
            url, json=body, headers=self._headers(token)
        ) as resp:
            await resp.json()

    async def send_command(
        self,
        token: str,
        access_point_id: str,
        uuidm: str,
        aes_key: bytes,
        com: int,
    ) -> None:
        crypted, cks = encrypt_command_payload(aes_key, com)
        body = {
            "uuidm": uuidm,
            "cryptedPyl": list(crypted),
            "cmd": 20,
            "pyl": {"com": com, "cks": cks},
        }
        url = f"{BASE_URL}/smartaccess/access-point/{access_point_id}/mqtt-message"
        async with self._session.post(
            url, json=body, headers=self._headers(token)
        ) as resp:
            await resp.json()

    async def open_gate(self, token, access_point_id, uuidm, aes_key):
        await self.send_command(token, access_point_id, uuidm, aes_key, COMMAND_TOGGLE)

    async def close_gate(self, token, access_point_id, uuidm, aes_key):
        await self.send_command(token, access_point_id, uuidm, aes_key, COMMAND_TOGGLE)

    async def stop_gate(self, token, access_point_id, uuidm, aes_key):
        await self.send_command(token, access_point_id, uuidm, aes_key, COMMAND_STOP)
