"""
core/shodan_service.py — Enriquecimento de inteligência via Shodan.

Suporta o plano Academic/Enterprise (CVEs via 'vulns' na raiz e por banner).
Graciosamente degradado: retorna {disponivel: False} se a chave não estiver configurada.

Estratégia de extração de CVEs:
    1. host['vulns']              → dicionário de CVEs globais do IP (plano Academic+)
    2. host['data'][n]['vulns']   → CVEs atreladas a serviços específicos por porta
    As duas fontes são consolidadas e deduplicadas em uma lista única ordenada por CVSS.

Rate limiting:
    Pausa de 1s entre chamadas para evitar erros 503 em sequências rápidas (scans agendados).
"""

import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

_API_KEY = os.getenv("SHODAN_API_KEY", "")
_TIMEOUT = int(os.getenv("SHODAN_TIMEOUT", "10"))


# ── Helpers internos ──────────────────────────────────────────────────────────

def _normalizar_cvss(raw: Any) -> float | None:
    """Converte o valor bruto do CVSS para float, retorna None se inválido."""
    try:
        return float(raw) if raw is not None else None
    except (ValueError, TypeError):
        return None


def _severidade_cvss(cvss: float | None) -> str:
    """Classifica CVSS em nível de severidade textual (CVSS v3 base)."""
    if cvss is None:  return "desconhecido"
    if cvss >= 9.0:   return "critico"
    if cvss >= 7.0:   return "alto"
    if cvss >= 4.0:   return "medio"
    return "baixo"


def _consolidar_cves(host: dict) -> list[dict]:
    """
    Consolida CVEs de TODAS as fontes presentes na resposta Shodan:

      Fonte 1 — host['vulns']:
        Dicionário de CVEs vinculadas ao IP como um todo.
        Disponível apenas nos planos Academic e Enterprise.

      Fonte 2 — host['data'][n]['vulns']:
        CVEs vinculadas a serviços/banners individuais por porta.
        Frequentemente contém CVEs que não aparecem na raiz.

    Deduplicação: CVEs da raiz têm precedência (não são sobrescritas por banners).
    Ordenação: CVSS decrescente (crítico → baixo).

    Args:
        host: Dicionário bruto retornado por api.host(ip).

    Returns:
        Lista de dicts com chaves: cve_id, cvss, severidade, summary.
    """
    cves_map: dict[str, dict] = {}

    # ── Fonte 1: raiz ────────────────────────────────────────────────────────
    vulns_raiz = host.get("vulns")
    if vulns_raiz:
        logger.debug("[Shodan] CVEs na raiz do host: %d", len(vulns_raiz))
        if isinstance(vulns_raiz, list):
            for cve_id in vulns_raiz:
                cves_map[cve_id] = {
                    "cve_id":     cve_id,
                    "cvss":       None,
                    "severidade": "desconhecido",
                    "summary":    "",
                }
        elif isinstance(vulns_raiz, dict):
            for cve_id, info in vulns_raiz.items():
                cvss = _normalizar_cvss(info.get("cvss"))
                cves_map[cve_id] = {
                    "cve_id":     cve_id,
                    "cvss":       cvss,
                    "severidade": _severidade_cvss(cvss),
                    "summary":    (info.get("summary") or "")[:300],
                }
    else:
        logger.debug(
            "[Shodan] Campo 'vulns' ausente/vazio na raiz. "
            "Verifique se o plano suporta este campo (Academic/Enterprise)."
        )

    # ── Fonte 2: banners (host['data'][n]['vulns']) ───────────────────────────
    banners_com_cves = 0
    for banner in (host.get("data") or []):
        vulns_banner = banner.get("vulns")
        if not vulns_banner:
            continue
        banners_com_cves += 1
        porta = banner.get("port", "?")
        logger.debug(
            "[Shodan] Banner porta %s — %d CVE(s) encontrada(s)",
            porta, len(vulns_banner),
        )
        
        if isinstance(vulns_banner, list):
            for cve_id in vulns_banner:
                if cve_id not in cves_map:
                    cves_map[cve_id] = {
                        "cve_id":     cve_id,
                        "cvss":       None,
                        "severidade": "desconhecido",
                        "summary":    "",
                    }
        elif isinstance(vulns_banner, dict):
            for cve_id, info in vulns_banner.items():
                if cve_id not in cves_map:  # prioridade para raiz; não sobrescreve
                    cvss = _normalizar_cvss(info.get("cvss"))
                    cves_map[cve_id] = {
                        "cve_id":     cve_id,
                        "cvss":       cvss,
                        "severidade": _severidade_cvss(cvss),
                        "summary":    (info.get("summary") or "")[:300],
                    }

    if banners_com_cves:
        logger.debug("[Shodan] Banners com CVEs: %d", banners_com_cves)

    resultado = sorted(cves_map.values(), key=lambda c: c.get("cvss") or 0.0, reverse=True)

    logger.info(
        "[Shodan] CVEs consolidadas — raiz: %d | banners: total único: %d",
        len(vulns_raiz or []), len(resultado),
    )
    return resultado


def _extrair_banners(host: dict) -> list[dict]:
    """Extrai e normaliza banners do campo host['data']."""
    banners: list[dict] = []
    for item in (host.get("data") or []):
        # Postgres JSONB não suporta \u0000 (caracteres nulos)
        banner_raw = (item.get("data") or "")[:500]
        banner_limpo = banner_raw.replace("\x00", "")
        
        banners.append({
            "porta":     item.get("port"),
            "protocolo": item.get("transport", "tcp"),
            "produto":   item.get("product"),
            "versao":    item.get("version"),
            "banner":    banner_limpo,
        })
    return banners


# ── Interface pública ─────────────────────────────────────────────────────────

def consultar_shodan(ip: str) -> dict[str, Any]:
    """
    Consulta o Shodan para um IP e extrai portas, banners e CVEs consolidadas.

    A extração de CVEs percorre tanto a raiz quanto cada banner individualmente,
    garantindo cobertura total independente de como o Shodan organiza os dados
    para o plano da conta.

    Args:
        ip: Endereço IP público a consultar.

    Returns:
        {
          "sucesso":    bool,
          "disponivel": bool,   # False se sem chave configurada
          "ip":         str,
          "org":        str | None,
          "isp":        str | None,
          "os":         str | None,
          "portas":     list[int],
          "banners":    list[{porta, protocolo, produto, versao, banner}],
          "cves":       list[{cve_id, cvss, severidade, summary}],
          "erro":       str | None,
        }
    """
    if not _API_KEY:
        logger.info("[Shodan] Desativado: SHODAN_API_KEY não configurada.")
        return _resultado_sem_dados(ip, sucesso=False, erro="SHODAN_API_KEY não configurada.")

    try:
        import shodan  # importação local: evita crash se lib não instalada no ambiente

        api         = shodan.Shodan(_API_KEY)
        api.timeout = _TIMEOUT          # timeout configurado no objeto, não em .host()
        host        = api.host(ip)

        logger.info(
            "[Shodan] Resposta recebida para %s — org='%s', portas=%s, banners=%d",
            ip,
            host.get("org", "N/A"),
            host.get("ports", []),
            len(host.get("data") or []),
        )

        # Verificação de plano (informativa, não bloqueia o fluxo)
        _verificar_acesso_vulns(api, host, ip)

        portas  = host.get("ports", [])
        banners = _extrair_banners(host)
        cves    = _consolidar_cves(host)

        # Pausa de cortesia entre chamadas (evita 503 em sequências de scans)
        time.sleep(1)

        return {
            "sucesso":    True,
            "disponivel": True,
            "ip":         host.get("ip_str", ip),
            "org":        host.get("org"),
            "isp":        host.get("isp"),
            "os":         host.get("os"),
            "portas":     portas,
            "banners":    banners,
            "cves":       cves,
            "erro":       None,
        }

    except Exception as exc:
        return _tratar_excecao(ip, exc)


def _verificar_acesso_vulns(api: Any, host: dict, ip: str) -> None:
    """
    Verifica se o plano da conta tem acesso ao campo 'vulns'.
    Emite warning no log se CVEs estiverem ausentes e o plano não for compatível.
    Não lança exceção — é puramente informativa.
    """
    try:
        info  = api.info()
        plano = (info.get("plan") or "").lower()
        tem_vulns_raiz    = bool(host.get("vulns"))
        tem_vulns_banners = any(bool(b.get("vulns")) for b in (host.get("data") or []))

        if not tem_vulns_raiz and not tem_vulns_banners:
            if not any(k in plano for k in ("edu", "academic", "corp", "enterprise", "small", "medium")):
                logger.warning(
                    "[Shodan] IP %s: campo 'vulns' vazio. Plano atual: '%s'. "
                    "CVEs exigem plano Academic ou superior. "
                    "Verifique em: https://account.shodan.io/billing/plan",
                    ip, plano,
                )
            else:
                logger.info(
                    "[Shodan] IP %s: campo 'vulns' vazio (plano '%s' OK — IP pode não ter CVEs indexadas).",
                    ip, plano,
                )
    except Exception as e:
        # Falha ao consultar info da conta não deve interromper o fluxo principal
        logger.debug("[Shodan] Não foi possível verificar plano: %s", e)


def _resultado_sem_dados(
    ip: str,
    sucesso: bool,
    disponivel: bool = True,
    erro: str | None = None,
) -> dict[str, Any]:
    """Retorna estrutura padrão vazia para casos de erro ou IP não indexado."""
    return {
        "sucesso":    sucesso,
        "disponivel": disponivel,
        "ip":         ip,
        "org":        None,
        "isp":        None,
        "os":         None,
        "portas":     [],
        "banners":    [],
        "cves":       [],
        "erro":       erro,
    }


def _tratar_excecao(ip: str, exc: Exception) -> dict[str, Any]:
    """Classifica e trata exceções do Shodan de forma granular."""
    erro_str = str(exc)
    logger.warning("[Shodan] Erro para %s: %s", ip, erro_str)

    # IP não indexado — situação normal, não é falha crítica
    if "No information available" in erro_str or "404" in erro_str:
        return _resultado_sem_dados(
            ip,
            sucesso=True,   # não é erro de sistema — IP simplesmente não está no índice
            disponivel=True,
            erro="IP não indexado no Shodan.",
        )

    # Chave inválida ou sem permissão
    if "Invalid API key" in erro_str or "Access denied" in erro_str or "403" in erro_str:
        logger.error("[Shodan] API key inválida ou sem permissão para este endpoint.")
        return _resultado_sem_dados(ip, sucesso=False, disponivel=False, erro=erro_str)

    # Timeout
    if "timed out" in erro_str.lower() or "timeout" in erro_str.lower():
        logger.error("[Shodan] Timeout na consulta de %s (limite: %ds)", ip, _TIMEOUT)
        return _resultado_sem_dados(ip, sucesso=False, disponivel=True, erro=f"Timeout: {erro_str}")

    # Erro genérico
    return _resultado_sem_dados(ip, sucesso=False, disponivel=True, erro=erro_str)
