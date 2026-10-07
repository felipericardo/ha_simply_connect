# Simply Connect (FAAC/Rossi) para Home Assistant

Integração **não oficial** para controlar portões/automações FAAC/Rossi que usam o app **Simply Connect**, feita via engenharia reversa da API (não há suporte, documentação ou afiliação da FAAC).

> ⚠️ Sem garantias. A FAAC pode mudar a API/backend a qualquer momento e quebrar esta integração sem aviso.

## O que a integração expõe

Para cada portão da sua conta:

- **`cover`** — abrir, fechar e parar, com status (aberto/fechado/abrindo/fechando).
- **`switch` "Trancado"** — trava local (não mexe na API): quando ligada, bloqueia abrir/parar pelo HA (só fechar continua permitido). Útil pra travar junto com o alarme, ex. pra Alexa não conseguir abrir o portão à noite.
- **`button` "Abrir Parcial"** — abertura parcial (passagem de pedestre), disponível só quando o portão está fechado e destrancado.

## Instalação

### Via HACS (repositório personalizado)

1. HACS → ⋮ → **Repositórios personalizados**
2. URL: `https://github.com/felipericardo/ha_simply_connect`, categoria **Integration**
3. Instale e reinicie o Home Assistant

### Manual

Copie a pasta `custom_components/simply_connect` pra dentro de `custom_components/` da sua instalação do Home Assistant e reinicie.

## Configuração

Configurações → Dispositivos e Serviços → Adicionar Integração → **Simply Connect (FAAC/Rossi)**.

1. Email e senha da sua conta Simply Connect.
2. Se a conta tiver MFA por e-mail ativado, você digita o código recebido.
3. A integração se autoriza automaticamente nos portões da conta (sem precisar aprovar em outro dispositivo).

## Limitações conhecidas

- Só suporta MFA por **e-mail** (não autenticador/TOTP).
- Pensado pra uma conta dona do(s) portão(ões) — não testado com contas convidadas/instalador.
