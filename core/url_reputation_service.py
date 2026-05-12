import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_GSB_API_KEY  = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
_GSB_BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_GSB_TIMEOUT  = int(os.getenv("GSB_TIMEOUT", "10"))

_URLVOID_API_KEY  = os.getenv("URLVOID_API_KEY", "")
_URLVOID_BASE_URL = "https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/"
_URLVOID_TIMEOUT  = int(os.getenv("URLVOID_TIMEOUT", "10"))

_THREAT_LABELS = {
    "MALWARE":                         "Malware",
    "SOCIAL_ENGINEERING":              "Phishing / Engenharia Social",
    "UNWANTED_SOFTWARE":               "Software Indesejado",
    "POTENTIALLY_HARMFUL_APPLICATION": "Aplicativo Potencialmente Nocivo",
}

_ERR_BASE = {"sucesso": False, "ameacas": [], "relatorio": None}


def _consultar_google_safe_browsing(url: str) -> dict:
    payload = {
        "client": {"clientId": "threatintel-pro", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes":      list(_THREAT_LABELS.keys()),
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }
    try:
        resp = requests.post(
            _GSB_BASE_URL, json=payload,
            params={"key": _GSB_API_KEY},
            timeout=_GSB_TIMEOUT,
        )
        resp.raise_for_status()
        matches = resp.json().get("matches", [])

        if not matches:
            return {"sucesso": True, "fonte": "google_safe_browsing",
                    "status": "segura", "ameacas": [],
                    "relatorio": {"matches": [], "url": url}, "erro": None}

        ameacas = [
            {
                "tipo":       m.get("threatType"),
                "descricao":  _THREAT_LABELS.get(m.get("threatType", ""), m.get("threatType")),
                "plataforma": m.get("platformType"),
            }
            for m in matches
        ]
        return {"sucesso": True, "fonte": "google_safe_browsing",
                "status": "maliciosa", "ameacas": ameacas,
                "relatorio": {"matches": matches, "url": url}, "erro": None}

    except requests.exceptions.Timeout:
        return {**_ERR_BASE, "fonte": "google_safe_browsing",
                "status": "desconhecida", "erro": "Timeout ao consultar Google Safe Browsing."}
    except requests.exceptions.RequestException as exc:
        return {**_ERR_BASE, "fonte": "google_safe_browsing",
                "status": "desconhecida", "erro": str(exc)}


def _consultar_urlvoid(url: str) -> dict:
    if not _URLVOID_API_KEY:
        return {**_ERR_BASE, "fonte": "urlvoid",
                "status": "desconhecida", "erro": "URLVOID_API_KEY não configurada."}
    try:
        resp = requests.get(
            _URLVOID_BASE_URL,
            params={"key": _URLVOID_API_KEY, "host": url},
            timeout=_URLVOID_TIMEOUT,
        )
        resp.raise_for_status()
        report = resp.json().get("data", {}).get("report", {})
        risk   = report.get("risk_score", {}).get("result", "low")
        status = "maliciosa" if risk == "high" else "suspeita" if risk == "medium" else "segura"
        return {"sucesso": True, "fonte": "urlvoid", "status": status,
                "ameacas": [], "relatorio": report, "erro": None}
    except requests.exceptions.RequestException as exc:
        return {**_ERR_BASE, "fonte": "urlvoid", "status": "desconhecida", "erro": str(exc)}


def verificar_reputacao_url(url: str) -> dict:
    if _GSB_API_KEY:
        return _consultar_google_safe_browsing(url)
    logger.warning("GOOGLE_SAFE_BROWSING_API_KEY não configurada — usando URLVoid.")
    return _consultar_urlvoid(url)
