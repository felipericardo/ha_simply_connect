"""Constants for the Simply Connect (FAAC/Rossi) integration."""

DOMAIN = "simply_connect"

BASE_URL = "https://us-api-prod.faacsimplyconnect.com/v2"
# Alguns endpoints novos (ex.: automatic-trust) não ficam sob /v2 — descoberto
# via captura de tráfego real do app oficial (mitmproxy, v2.6.123).
API_ROOT = BASE_URL.removesuffix("/v2")

APP_HEADERS = {
    "app-name": "simplyconnect_enduser",
}

# Mapeamento empírico confirmado (ver PROGRESS.md, observado durante um ciclo
# real de abrir/fechar com polling rápido):
LOGICAL_STATUS_CLOSED = 0
LOGICAL_STATUS_OPENING = 1
LOGICAL_STATUS_OPEN = 2
LOGICAL_STATUS_CLOSING = 5

COMMAND_TOGGLE = 1
COMMAND_PARTIAL = 2
COMMAND_STOP = 3

DEFAULT_SCAN_INTERVAL = 15  # segundos

# Depois de mandar um comando, faz polling rápido por um tempo pra pegar a
# transição (aberto/fechado geralmente demora uns 5-11s, ver PROGRESS.md)
# antes de voltar pro intervalo normal.
FAST_POLL_INTERVAL = 1  # segundos
FAST_POLL_DURATION = 15  # segundos
