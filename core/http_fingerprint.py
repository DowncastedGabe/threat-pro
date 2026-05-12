import os
import logging
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = float(os.getenv("HTTP_FINGERPRINT_TIMEOUT", "8"))
_USER_AGENT = os.getenv("HTTP_FINGERPRINT_USER_AGENT", "ThreatIntelFingerprint/1.0")

from core.utils_security import validar_url_segura

def _normalizar_url(valor: str) -> str:
    return validar_url_segura(valor)


def _detectar_tecnologias(headers: dict[str, str], cookies: dict[str, str]) -> tuple[list[str], str | None]:
    tecnologias = []
    waf = None

    server = headers.get("server", "").lower()
    powered = headers.get("x-powered-by", "").lower()

    if "cloudflare" in server:
        tecnologias.append("Cloudflare")
        waf = "Cloudflare"
    if "nginx" in server:
        tecnologias.append("Nginx")
    if "apache" in server:
        tecnologias.append("Apache")
    if "iis" in server:
        tecnologias.append("Microsoft IIS")

    if "php" in powered:
        tecnologias.append("PHP")
    if "express" in powered:
        tecnologias.append("Express")
    if "asp.net" in powered:
        tecnologias.append("ASP.NET")

    cookie_names = {k.lower() for k in cookies.keys()}

    if "__cf_bm" in cookie_names or "cf_clearance" in cookie_names:
        if "Cloudflare" not in tecnologias:
            tecnologias.append("Cloudflare")
        waf = waf or "Cloudflare"

    if "laravel_session" in cookie_names:
        tecnologias.append("Laravel")
    if "phpsessid" in cookie_names:
        tecnologias.append("PHP Session")
    if "jsessionid" in cookie_names:
        tecnologias.append("Java / JSESSIONID")
    if "connect.sid" in cookie_names:
        tecnologias.append("Express Session")

    tecnologias = list(dict.fromkeys(tecnologias))
    return tecnologias, waf


def analisar_http_fingerprint(url: str) -> dict[str, Any]:
    try:
        url = _normalizar_url(url)

        response = requests.get(
            url,
            timeout=_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": _USER_AGENT},
        )

        headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = response.cookies.get_dict()

        tecnologias, waf = _detectar_tecnologias(headers, cookies)

        return {
            "sucesso": True,
            "erro": None,
            "data": {
                "url": url,
                "url_final": response.url,
                "status_code": response.status_code,
                "server": headers.get("server"),
                "powered_by": headers.get("x-powered-by"),
                "tecnologias_detectadas": tecnologias,
                "possivel_waf": waf,
                "cookies_detectados": list(cookies.keys()),
            },
        }

    except requests.exceptions.Timeout:
        return {"sucesso": False, "erro": "Timeout ao analisar fingerprint HTTP", "data": {}}

    except requests.exceptions.RequestException as e:
        logger.error("Erro fingerprint HTTP: %s", e)
        return {"sucesso": False, "erro": "Erro de conexão ao analisar fingerprint HTTP", "data": {}}

    except Exception as e:
        logger.exception("Erro inesperado fingerprint HTTP")
        return {"sucesso": False, "erro": str(e), "data": {}}