"""
core/tor_service.py — Proxy Tor + OSINT Dorker via DuckDuckGo.

Arquitetura:
  - get_tor_session()   → requests.Session com proxy SOCKS5h (tor:9050)
  - verificar_tor()     → testa conectividade antes de usar
  - dorker_duckduckgo() → busca via DDG Lite com query intitle:index.of

DuckDuckGo foi escolhido por:
  - Não exigir autenticação ou chave de API
  - Funcionar via Tor sem CAPTCHAs frequentes
  - Retornar resultados de "index.of" de forma confiável

Se o Tor estiver indisponível, o fallback é executar a busca sem proxy
com um aviso explícito no retorno.
"""

import os
import logging
import re
from typing import Any
from urllib.parse import urlencode, quote_plus

import requests

logger = logging.getLogger(__name__)

_TOR_PROXY   = os.getenv("TOR_PROXY",   "socks5h://tor:9050")
_TOR_TIMEOUT = int(os.getenv("TOR_TIMEOUT", "20"))
_DDG_URL     = "https://html.duckduckgo.com/html/"

# User-Agent genérico para não ser bloqueado como bot
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
)


class TorUnavailableError(Exception):
    """Levantado quando o proxy Tor não está acessível."""


def get_tor_session() -> requests.Session:
    """
    Cria uma requests.Session configurada com o proxy Tor (SOCKS5h).

    SOCKS5h resolve DNS dentro do Tor (evita DNS leak).
    """
    session = requests.Session()
    session.proxies = {
        "http":  _TOR_PROXY,
        "https": _TOR_PROXY,
    }
    session.headers["User-Agent"] = _USER_AGENT
    return session


def verificar_tor() -> dict[str, Any]:
    """
    Verifica se o Tor está acessível e retorna o IP de saída.

    Returns:
        {"ativo": bool, "ip_tor": str | None, "erro": str | None}
    """
    try:
        session = get_tor_session()
        resp = session.get(
            "https://check.torproject.org/api/ip",
            timeout=_TOR_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        ip_tor = data.get("IP")
        is_tor = data.get("IsTor", False)

        logger.info("Tor verificado — IP de saída: %s | IsTor: %s", ip_tor, is_tor)
        return {"ativo": True, "ip_tor": ip_tor, "erro": None}

    except Exception as exc:
        logger.warning("Tor indisponível: %s", exc)
        return {"ativo": False, "ip_tor": None, "erro": str(exc)}


def _parsear_ddg_html(html: str) -> list[dict[str, str]]:
    """
    Parser simples de HTML do DuckDuckGo (HTML endpoint).
    Extrai links, títulos e snippets sem depender de bibliotecas pesadas.
    """
    resultados: list[dict[str, str]] = []

    # Regex para capturar os blocos "result__body" que contêm cada resultado
    blocos = re.findall(r'<div[^>]+class="[^"]*result__body[^"]*"[^>]*>(.*?)<div class="clear"></div>', html, re.DOTALL)

    for bloco in blocos:
        # Extrai URL (da tag result__url)
        url_match = re.search(r'<a[^>]+class="result__url"[^>]*href="([^"]+)"', bloco)
        url = url_match.group(1) if url_match else None

        # Extrai título (da tag result__a)
        titulo_match = re.search(r'<a[^>]+class="result__a"[^>]*>(.*?)</a>', bloco, re.DOTALL)
        titulo = titulo_match.group(1) if titulo_match else None

        # Extrai snippet (da tag result__snippet)
        snippet_match = re.search(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', bloco, re.DOTALL)
        snippet = snippet_match.group(1) if snippet_match else None

        if url and titulo:
            titulo_limpo = re.sub(r"<[^>]+>", "", titulo).strip()
            snippet_limpo = re.sub(r"<[^>]+>", "", snippet).strip() if snippet else None

            # Ignorar lixo ou resultados de publicidade sem snippet claro se necessário,
            # mas vamos adicionar todos os resultados orgânicos.
            resultados.append({
                "url": url,
                "titulo": titulo_limpo,
                "snippet": snippet_limpo,
            })

    return resultados


def dorker_duckduckgo(
    dominio: str,
    usar_tor: bool = True,
) -> dict[str, Any]:
    """
    Executa uma busca OSINT no DuckDuckGo buscando diretórios expostos.

    Query utilizada: site:{dominio} intitle:"index of"

    Args:
        dominio: Domínio alvo (ex: "example.com")
        usar_tor: Se True, roteia via Tor. Se False, usa conexão direta.

    Returns:
        {
          "sucesso": bool,
          "dominio": str,
          "query": str,
          "via_tor": bool,
          "resultados": list[{url, titulo, snippet}],
          "erro": str | None,
        }
    """
    query     = f'site:{dominio} intitle:"index of"'
    via_tor   = False
    resultados: list[dict] = []

    try:
        if usar_tor:
            status_tor = verificar_tor()
            if status_tor["ativo"]:
                session = get_tor_session()
                via_tor = True
                logger.info("Dorking via Tor (IP: %s)", status_tor["ip_tor"])
            else:
                # Fallback: conexão direta com aviso
                logger.warning(
                    "Tor indisponível (%s) — usando conexão direta.", status_tor["erro"]
                )
                session = requests.Session()
                session.headers["User-Agent"] = _USER_AGENT
        else:
            session = requests.Session()
            session.headers["User-Agent"] = _USER_AGENT

        params = {"q": query, "kl": "br-pt"}
        resp = session.post(
            _DDG_URL,
            data=params,
            timeout=_TOR_TIMEOUT,
        )
        resp.raise_for_status()
        resultados = _parsear_ddg_html(resp.text)

        return {
            "sucesso":    True,
            "dominio":    dominio,
            "query":      query,
            "via_tor":    via_tor,
            "resultados": resultados,
            "erro":       None,
        }

    except requests.exceptions.HTTPError as exc:
        logger.warning("HTTP Error no Dorker: %s", exc)
        if exc.response is not None and exc.response.status_code == 403:
            msg = "O DuckDuckGo bloqueou o nó de saída atual do Tor (403 Forbidden). Reinicie o container do Tor para obter um novo IP."
        else:
            msg = f"Erro no serviço de busca: {exc}"
        return {
            "sucesso":    False,
            "dominio":    dominio,
            "query":      query,
            "via_tor":    via_tor,
            "resultados": [],
            "erro":       msg,
        }
    except Exception as exc:
        logger.exception("Erro no Dorker para domínio %s", dominio)
        return {
            "sucesso":    False,
            "dominio":    dominio,
            "query":      query,
            "via_tor":    via_tor,
            "resultados": [],
            "erro":       str(exc),
        }
