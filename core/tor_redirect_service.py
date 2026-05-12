import logging
import os
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_TOR_PROXY    = os.getenv("TOR_PROXY", "socks5h://tor:9050")
_TOR_TIMEOUT  = int(os.getenv("TOR_TIMEOUT", "20"))
_MAX_HOPS     = 10
_REDIRECT_CODES = (301, 302, 303, 307, 308)

_PROXIES = {"http": _TOR_PROXY, "https": _TOR_PROXY}
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"}


def _resolve_location(base_url: str, location: str) -> str:
    if location.startswith("/"):
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}{location}"
    return location


def rastrear_redirects_tor(url: str) -> dict:
    hops        = []
    current_url = url
    session     = requests.Session()
    session.max_redirects = 0

    for i in range(_MAX_HOPS):
        try:
            resp = session.head(
                current_url,
                proxies=_PROXIES,
                headers=_HEADERS,
                timeout=_TOR_TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
            location = resp.headers.get("Location")
            hops.append({"ordem": i + 1, "url": current_url,
                          "status_code": resp.status_code, "location": location})

            if resp.status_code in _REDIRECT_CODES and location:
                current_url = _resolve_location(current_url, location)
            else:
                return {"sucesso": True, "via_tor": True, "hops": hops,
                        "url_final": current_url,
                        "content_type": resp.headers.get("Content-Type"), "erro": None}

        except requests.exceptions.ProxyError as exc:
            logger.warning("Tor proxy indisponível: %s", exc)
            return _rastrear_sem_tor(url, hops, str(exc))
        except requests.exceptions.Timeout:
            return {"sucesso": False, "via_tor": True, "hops": hops,
                    "url_final": current_url, "content_type": None,
                    "erro": f"Timeout após {i + 1} hop(s)."}
        except requests.exceptions.RequestException as exc:
            return {"sucesso": False, "via_tor": True, "hops": hops,
                    "url_final": current_url, "content_type": None, "erro": str(exc)}

    return {"sucesso": True, "via_tor": True, "hops": hops, "url_final": current_url,
            "content_type": None, "erro": f"Limite de {_MAX_HOPS} redirects atingido."}


def _rastrear_sem_tor(url: str, hops_parciais: list, tor_erro: str) -> dict:
    try:
        resp = requests.head(url, headers=_HEADERS, timeout=10, allow_redirects=True)
        hop  = {"ordem": len(hops_parciais) + 1, "url": resp.url,
                "status_code": resp.status_code, "location": None}
        return {"sucesso": True, "via_tor": False, "hops": hops_parciais + [hop],
                "url_final": resp.url, "content_type": resp.headers.get("Content-Type"),
                "erro": f"Tor indisponível: {tor_erro}"}
    except Exception as exc:
        return {"sucesso": False, "via_tor": False, "hops": hops_parciais,
                "url_final": None, "content_type": None, "erro": str(exc)}
