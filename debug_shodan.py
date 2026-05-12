"""
debug_shodan.py — Script de inspeção completa da resposta da API Shodan.

Uso:
    python debug_shodan.py <IP>
    python debug_shodan.py 80.82.77.139        # Shodan HQ — rico em CVEs
    python debug_shodan.py 89.248.167.131      # Sensor do Shodan com serviços expostos

Requer:
    SHODAN_API_KEY definida no .env ou como variável de ambiente.
"""

import json
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("shodan_debug")

API_KEY = os.getenv("SHODAN_API_KEY", "")
if not API_KEY:
    logger.error("SHODAN_API_KEY não encontrada no ambiente. Defina no .env antes de rodar.")
    sys.exit(1)


def inspecionar_plano() -> dict:
    """Verifica o plano atual e as permissões da chave Shodan."""
    import shodan

    api = shodan.Shodan(API_KEY)
    try:
        info = api.info()
        logger.info("=== PLANO SHODAN ===")
        logger.info("  Plan      : %s", info.get("plan", "N/A"))
        logger.info("  Credits   : %s", info.get("query_credits", "N/A"))
        logger.info("  Scan Cred : %s", info.get("scan_credits", "N/A"))
        logger.info("  Monitored : %s IPs", info.get("monitored_ips", "N/A"))

        plano = info.get("plan", "").lower()
        if "edu" in plano or "academic" in plano or "corp" in plano:
            logger.info("  ✅ Plano suporta CVEs (vulns field)")
        else:
            logger.warning(
                "  ⚠️  Plano '%s' pode NÃO incluir o campo 'vulns'. "
                "CVEs requerem plano Academic/Enterprise.",
                plano,
            )
        return info
    except Exception as e:
        logger.error("Falha ao consultar info da conta: %s", e)
        return {}


def inspecionar_host(ip: str) -> dict:
    """
    Faz dump completo da resposta api.host(ip) para análise de estrutura.
    Inspeciona: raiz, banners (data[]), vulns raiz e vulns por banner.
    """
    import shodan

    api = shodan.Shodan(API_KEY)
    api.timeout = int(os.getenv("SHODAN_TIMEOUT", "10"))

    logger.info("\n" + "=" * 60)
    logger.info("CONSULTANDO IP: %s", ip)
    logger.info("=" * 60)

    try:
        api.timeout = int(os.getenv("SHODAN_TIMEOUT", "10"))  # timeout no objeto
        host = api.host(ip)
    except Exception as e:
        logger.error("Erro na consulta: %s", e)
        return {}

    # ── 1. Chaves de nível raiz ──────────────────────────────────────────────
    logger.info("\n[1] CHAVES NA RAIZ DA RESPOSTA:")
    for key in sorted(host.keys()):
        valor = host[key]
        tipo  = type(valor).__name__
        preview = str(valor)[:120] if not isinstance(valor, (list, dict)) else f"<{tipo} len={len(valor)}>"
        logger.info("    %-25s : %s  → %s", key, tipo, preview)

    # ── 2. Campo 'vulns' na raiz ─────────────────────────────────────────────
    vulns_raiz = host.get("vulns")
    if vulns_raiz:
        logger.info("\n[2] CVEs NA RAIZ (host['vulns']): %d encontrada(s)", len(vulns_raiz))
        if isinstance(vulns_raiz, list):
            for cve_id in vulns_raiz[:5]:
                logger.info("    %s → (sem mais detalhes na lista)", cve_id)
        elif isinstance(vulns_raiz, dict):
            for cve_id, info in list(vulns_raiz.items())[:5]:  # mostra até 5
                logger.info("    %s → cvss=%s | %s", cve_id, info.get("cvss"), str(info.get("summary", ""))[:80])
    else:
        logger.info("\n[2] CVEs NA RAIZ: 0 encontrada(s)")

    # ── 3. Banners (host['data']) ────────────────────────────────────────────
    banners = host.get("data", [])
    logger.info("\n[3] BANNERS (host['data']): %d serviço(s) detectado(s)", len(banners))
    total_cves_banners = 0

    for idx, banner in enumerate(banners):
        porta     = banner.get("port")
        produto   = banner.get("product", "N/A")
        versao    = banner.get("version", "N/A")
        transport = banner.get("transport", "tcp")
        vulns_banner = banner.get("vulns")
        if not vulns_banner:
            continue
            
        total_cves_banners += len(vulns_banner)

        logger.info(
            "    Banner #%d → %s/%s  produto='%s %s'  CVEs neste banner: %d",
            idx, porta, transport, produto, versao, len(vulns_banner),
        )
        if isinstance(vulns_banner, list):
            for cve_id in vulns_banner[:3]:
                logger.info("        └─ %s (sem mais detalhes)", cve_id)
        elif isinstance(vulns_banner, dict):
            for cve_id, info in list(vulns_banner.items())[:3]:
                logger.info(
                    "        └─ %s  cvss=%-4s  %s",
                    cve_id, info.get("cvss"), str(info.get("summary", ""))[:70],
                )

    logger.info("\n[3] TOTAL de CVEs em banners: %d", total_cves_banners)

    # ── 4. Dump JSON completo (opcional — ative se quiser inspecionar tudo) ──
    dump_path = f"shodan_dump_{ip.replace('.', '_')}.json"
    with open(dump_path, "w", encoding="utf-8") as f:
        json.dump(host, f, indent=2, default=str)
    logger.info("\n[4] Dump completo salvo em: %s", dump_path)

    return host


def consolidar_cves(host: dict) -> list[dict]:
    """
    Consolida CVEs de TODAS as fontes da resposta Shodan:
      - host['vulns']              → CVEs globais do IP
      - host['data'][n]['vulns']   → CVEs por serviço/banner

    Retorna lista única deduplicada, ordenada por CVSS desc.
    """
    cves_map: dict[str, dict] = {}

    def _normalizar_cvss(raw) -> float | None:
        try:
            return float(raw) if raw is not None else None
        except (ValueError, TypeError):
            return None

    def _severidade(cvss: float | None) -> str:
        if cvss is None:   return "desconhecido"
        if cvss >= 9.0:    return "critico"
        if cvss >= 7.0:    return "alto"
        if cvss >= 4.0:    return "medio"
        return "baixo"

    # Fonte 1: raiz
    vulns_raiz = host.get("vulns")
    if isinstance(vulns_raiz, list):
        for cve_id in vulns_raiz:
            cves_map[cve_id] = {
                "cve_id":    cve_id,
                "cvss":      None,
                "severidade": "desconhecido",
                "summary":   "",
                "fonte":     "raiz",
            }
    elif isinstance(vulns_raiz, dict):
        for cve_id, info in vulns_raiz.items():
            cvss = _normalizar_cvss(info.get("cvss"))
            cves_map[cve_id] = {
                "cve_id":    cve_id,
                "cvss":      cvss,
                "severidade": _severidade(cvss),
                "summary":   (info.get("summary") or "")[:300],
                "fonte":     "raiz",
            }

    # Fonte 2: banners
    for banner in host.get("data", []):
        porta = banner.get("port")
        vulns_banner = banner.get("vulns")
        if isinstance(vulns_banner, list):
            for cve_id in vulns_banner:
                if cve_id not in cves_map:
                    cves_map[cve_id] = {
                        "cve_id":    cve_id,
                        "cvss":      None,
                        "severidade": "desconhecido",
                        "summary":   "",
                        "fonte":     f"banner_porta_{porta}",
                    }
        elif isinstance(vulns_banner, dict):
            for cve_id, info in vulns_banner.items():
                if cve_id not in cves_map:  # não sobrescreve se já veio da raiz
                    cvss = _normalizar_cvss(info.get("cvss"))
                    cves_map[cve_id] = {
                        "cve_id":    cve_id,
                        "cvss":      cvss,
                        "severidade": _severidade(cvss),
                        "summary":   (info.get("summary") or "")[:300],
                        "fonte":     f"banner_porta_{porta}",
                    }

    resultado = sorted(cves_map.values(), key=lambda c: c.get("cvss") or 0, reverse=True)
    logger.info("\n[CONSOLIDAÇÃO] Total de CVEs únicas: %d", len(resultado))
    for cve in resultado[:10]:
        logger.info(
            "  %s  cvss=%-5s  sev=%-12s  fonte=%s",
            cve["cve_id"], cve["cvss"], cve["severidade"], cve["fonte"],
        )
    return resultado


if __name__ == "__main__":
    ip_alvo = sys.argv[1] if len(sys.argv) > 1 else "80.82.77.139"

    print("\n" + "=" * 60)
    print(f"  ThreatIntel Pro — Debug Shodan")
    print(f"  IP alvo: {ip_alvo}")
    print("=" * 60 + "\n")

    inspecionar_plano()
    host_data = inspecionar_host(ip_alvo)
    if host_data:
        cves = consolidar_cves(host_data)
        print(f"\n✅ Debug concluído — {len(cves)} CVE(s) consolidada(s).")
    else:
        print("\n❌ Sem dados retornados pelo Shodan para este IP.")
