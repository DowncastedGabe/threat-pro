import os
import logging
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_RDAP_TIMEOUT = float(os.getenv("RDAP_TIMEOUT", "8"))
_RDAP_BASE_URL = os.getenv("RDAP_BASE_URL", "https://rdap.org/domain/")


def _extrair_dominio(valor: str) -> str:
    valor = valor.strip().lower()

    if not valor.startswith(("http://", "https://")):
        valor = f"https://{valor}"

    host = urlparse(valor).hostname

    if not host or "." not in host:
        raise ValueError("Domínio inválido")

    return host


def consultar_rdap(url_ou_dominio: str) -> dict[str, Any]:
    try:
        dominio = _extrair_dominio(url_ou_dominio)

        response = requests.get(
            f"{_RDAP_BASE_URL}{dominio}",
            timeout=_RDAP_TIMEOUT,
            headers={"Accept": "application/rdap+json"},
        )

        if response.status_code == 404:
            return {
                "sucesso": False,
                "erro": "Domínio não encontrado no RDAP",
                "data": {}
            }

        response.raise_for_status()
        data = response.json()

        eventos = {
            e.get("eventAction"): e.get("eventDate")
            for e in data.get("events", [])
            if e.get("eventAction") and e.get("eventDate")
        }

        entidades = []
        for e in data.get("entities", []):
            nome = None
            vcard = e.get("vcardArray", [])

            if len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if len(item) >= 4 and item[0] == "fn":
                        nome = item[3]
                        break

            entidades.append({
                "roles": e.get("roles", []),
                "nome": nome,
            })

        return {
            "sucesso": True,
            "erro": None,
            "data": {
                "dominio": dominio,
                "registrar": data.get("registrar"),
                "status": data.get("status", []),
                "nameservers": [
                    n.get("ldhName")
                    for n in data.get("nameservers", [])
                    if n.get("ldhName")
                ],
                "eventos": eventos,
                "entidades": entidades,
                "raw": data,
            },
        }

    except requests.exceptions.Timeout:
        return {
            "sucesso": False,
            "erro": "Timeout ao consultar RDAP",
            "data": {}
        }

    except requests.exceptions.RequestException as e:
        logger.error("Erro RDAP: %s", e)
        return {
            "sucesso": False,
            "erro": "Erro de conexão com RDAP",
            "data": {}
        }

    except Exception as e:
        logger.exception("Erro inesperado RDAP")
        return {
            "sucesso": False,
            "erro": str(e),
            "data": {}
        }