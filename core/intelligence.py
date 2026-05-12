import os
import logging
import ipaddress
from typing import Any

import requests
from dotenv import load_dotenv
from core.engine import BASE_DIR

load_dotenv(BASE_DIR / ".env")
token = os.getenv("TELEGRAM_BOT_TOKEN")

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = os.getenv(
    "ABUSEIPDB_URL",
    "https://api.abuseipdb.com/api/v2/check"
)

TELEGRAM_API_URL = os.getenv(
    "TELEGRAM_API_URL",
    "https://api.telegram.org"
)

ABUSEIPDB_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
ALERTAR_RISCOS = set(
    os.getenv("TELEGRAM_ALERTAR_RISCOS", "alto,critico")
    .lower()
    .replace(" ", "")
    .split(",")
)


def _get_env_required(nome: str) -> str:
    valor = os.getenv(nome)

    if not valor:
        raise RuntimeError(f"Variável de ambiente obrigatória não configurada: {nome}")

    return valor


def _validar_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError("IP inválido")


def _emoji_risco(risco: str) -> str:
    return {
        "critico": "🔴",
        "alto": "🟠",
        "medio": "🟡",
        "baixo": "🟢",
    }.get(risco.lower(), "⚪")


def _telegram_send_message(texto: str) -> dict[str, Any]:
    token = _get_env_required("TELEGRAM_BOT_TOKEN")
    chat_id = _get_env_required("TELEGRAM_CHAT_ID")

    url = f"{TELEGRAM_API_URL}/bot{token}/sendMessage"

    payload = {
        "chat_id": chat_id,
        "text": texto,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }

    response = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()

    resposta = response.json()

    if not resposta.get("ok"):
        raise RuntimeError(resposta.get("description", "Erro ao enviar mensagem Telegram"))

    return resposta


def enviar_alerta_telegram(ip: str, risco: str, score: int, total_reports: int = 0):
    try:
        ip = _validar_ip(ip)
        emoji = _emoji_risco(risco)

        mensagem = (
            "🚨 *ALERTA DE SEGURANÇA*\n\n"
            f"🌐 *IP:* `{ip}`\n"
            f"📊 *Score de Risco:* *{score}%*\n"
            f"📑 *Total de Relatórios:* *{total_reports}*\n"
            f"{emoji} *Classificação:* *{risco.upper()}*\n"
            "🕒 *Status:* Auditoria concluída"
        )

        resposta = _telegram_send_message(mensagem)

        logger.info("Alerta Telegram enviado com sucesso para IP %s", ip)

        return {
            "sucesso": True,
            "erro": None,
            "data": {
                "message_id": resposta.get("result", {}).get("message_id"),
                "chat_id": resposta.get("result", {}).get("chat", {}).get("id"),
            },
        }

    except Exception as e:
        logger.exception("Falha ao enviar alerta Telegram para IP %s", ip)
        return {
            "sucesso": False,
            "erro": str(e),
            "data": {},
        }


def consultar_reputacao_ip(ip: str) -> dict:
    try:
        ip = _validar_ip(ip)
        api_key = _get_env_required("ABUSEIPDB_API_KEY")

        headers = {
            "Accept": "application/json",
            "Key": api_key,
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS,
            "verbose": "",
        }

        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        data = response.json().get("data", {})

        return {
            "sucesso": True,
            "erro": None,
            "data": {
                "ip": data.get("ipAddress"),
                "score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "pais": data.get("countryCode"),
                "isp": data.get("isp"),
                "dominio": data.get("domain"),
                "uso": data.get("usageType"),
                "ultimo_relato": data.get("lastReportedAt"),
                "is_public": data.get("isPublic"),
                "ip_version": data.get("ipVersion"),
                "is_whitelisted": data.get("isWhitelisted"),
                "raw": data,
            },
        }

    except Exception as e:
        logger.exception("Erro ao consultar reputação do IP %s", ip)
        return {
            "sucesso": False,
            "erro": str(e),
            "data": {},
        }


def avaliar_risco_abuseipdb(ip: str) -> dict:
    resultado = consultar_reputacao_ip(ip)

    if not resultado["sucesso"]:
        return {
            "sucesso": False,
            "erro": resultado["erro"],
            "risco": "desconhecido",
            "score": 0,
            "total_reports": 0,
            "alerta_telegram": None,
            "data": {},
        }

    dados = resultado["data"]
    score = int(dados.get("score", 0))
    total_reports = int(dados.get("total_reports", 0))

    if score >= int(os.getenv("RISCO_CRITICO_MIN", "80")):
        risco = "critico"
    elif score >= int(os.getenv("RISCO_ALTO_MIN", "50")):
        risco = "alto"
    elif score >= int(os.getenv("RISCO_MEDIO_MIN", "20")):
        risco = "medio"
    else:
        risco = "baixo"

    return {
        "sucesso": True,
        "erro": None,
        "risco": risco,
        "score": score,
        "total_reports": total_reports,
        "alerta_telegram": None,
        "data": dados,
    }    