import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_VT_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
_VT_BASE_URL = "https://www.virustotal.com/api/v3"
_VT_TIMEOUT  = int(os.getenv("VT_TIMEOUT", "15"))

_MALICIOUS_THRESHOLD_PCT = 15


def _headers() -> dict:
    return {"x-apikey": _VT_API_KEY, "Accept": "application/json"}


def _classify(detected: int, total: int) -> str:
    if detected == 0:
        return "limpo"
    pct = (detected / total * 100) if total else 0
    return "suspeito" if pct < _MALICIOUS_THRESHOLD_PCT else "malicioso"


def consultar_hash_virustotal(file_hash: str) -> dict:
    if not _VT_API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY não configurada.")
        return {"sucesso": False, "status": "nao_analisado", "total_engines": 0,
                "total_detected": 0, "relatorio": None, "erro": "API key não configurada."}

    try:
        resp = requests.get(
            f"{_VT_BASE_URL}/files/{file_hash}",
            headers=_headers(),
            timeout=_VT_TIMEOUT,
        )
        if resp.status_code == 404:
            return {"sucesso": True, "status": "nao_analisado", "total_engines": 0,
                    "total_detected": 0, "relatorio": None, "erro": None}

        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        total_engines  = sum(stats.values())
        total_detected = stats.get("malicious", 0) + stats.get("suspicious", 0)

        deteccoes = {
            engine: res
            for engine, res in attrs.get("last_analysis_results", {}).items()
            if res.get("category") in ("malicious", "suspicious")
        }

        return {
            "sucesso":        True,
            "status":         _classify(total_detected, total_engines),
            "total_engines":  total_engines,
            "total_detected": total_detected,
            "relatorio": {
                "stats":          stats,
                "deteccoes":      deteccoes,
                "sha256":         attrs.get("sha256"),
                "md5":            attrs.get("md5"),
                "sha1":           attrs.get("sha1"),
                "nome_popular":   attrs.get("meaningful_name"),
                "tipo_arquivo":   attrs.get("type_description"),
                "primeiro_visto": attrs.get("first_submission_date"),
                "ultimo_analise": attrs.get("last_analysis_date"),
                "tags":           attrs.get("tags", []),
            },
            "erro": None,
        }

    except requests.exceptions.Timeout:
        logger.error("Timeout ao consultar VirusTotal (hash=%s)", file_hash)
        return {"sucesso": False, "status": "nao_analisado", "total_engines": 0,
                "total_detected": 0, "relatorio": None, "erro": "Timeout."}
    except requests.exceptions.RequestException as exc:
        logger.error("Erro ao consultar VirusTotal: %s", exc)
        return {"sucesso": False, "status": "nao_analisado", "total_engines": 0,
                "total_detected": 0, "relatorio": None, "erro": str(exc)}
