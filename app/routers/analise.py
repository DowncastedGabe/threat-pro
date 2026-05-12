"""
Rotas:
  GET  /validar/{valor}      — Valida formato de IP
  POST /analisar/            — Scan completo de IP (Nmap + Shodan + AbuseIPDB + GeoIP + Drift)
  POST /analisar-site/       — Análise de site (Headers + TLS + DNS + RDAP + Fingerprint)
  GET  /osint/dork/          — Busca OSINT via DuckDuckGo (roteada pelo Tor)
  GET  /osint/tor-status/    — Verifica se o Tor está ativo e retorna IP de saída
"""

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Security
from pydantic import ValidationError
from sqlmodel import Session, select

from app.dependencies import (
    RATE_LIMIT_ANALISAR,
    RATE_LIMIT_ANALISAR_SITE,
    RATE_LIMIT_OSINT,
    limiter,
    validar_api_key,
)
from app.models import (
    AnaliseIP,
    AnaliseRequest,
    AnaliseResponse,
    AnaliseSite,
    AnaliseSiteRead,
    CveInfo,
    DorkResult,
    DriftAnalise,
    ListaAnalisesSiteResponse,
    OsintDorkResponse,
    ScanPorta,
    ShodanInfo,
    SiteAnaliseResponse,
    SiteRequest,
)
from core.geoip_service import consultar_geoip
from core.http_fingerprint import analisar_http_fingerprint
from core.intelligence import avaliar_risco_abuseipdb, enviar_alerta_telegram
from core.nmap_service import escanear_portas
from core.rdap_service import consultar_rdap
from core.dns_service import consultar_dns, consultar_infra_health
from core.security_headers import analisar_headers_seguranca
from core.session import get_session
from core.shodan_service import consultar_shodan
from core.tls_service import analisar_tls_ssl
from core.tor_service import dorker_duckduckgo, verificar_tor
from core.osint_service import osint_completo_site
from core.utils import comparar_portas, extrair_portas_abertas_do_scan
from datetime import datetime, timezone
import urllib.parse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Análise"])


# ── Helpers internos (exclusivos deste módulo) ────────────────────────────────

def _salvar_snapshot_portas(session: Session, analise_id: int, portas: list[dict]) -> None:
    """Persiste o snapshot das portas abertas vinculado a uma análise de IP."""
    for p in portas:
        session.add(ScanPorta(
            analise_ip_id=analise_id,
            porta=p.get("porta", 0),
            protocolo=p.get("protocolo", "tcp"),
            estado=p.get("estado", ""),
            servico=p.get("servico"),
            produto=p.get("produto"),
            versao=p.get("versao"),
        ))


def _calcular_e_salvar_drift(
    session: Session,
    ip: str,
    analise_anterior: AnaliseIP,
    analise_atual: AnaliseIP,
    portas_atuais: list[dict],
) -> dict | None:
    """
    Compara o snapshot de portas atual com o anterior e persiste o DriftAnalise.
    Retorna o dict de diferenças se houver mudanças, ou None caso contrário.
    """
    stmt = select(ScanPorta).where(ScanPorta.analise_ip_id == analise_anterior.id)
    portas_anteriores = [
        {
            "porta": p.porta,
            "protocolo": p.protocolo,
            "estado": p.estado,
            "servico": p.servico,
            "produto": p.produto,
            "versao": p.versao,
        }
        for p in session.exec(stmt).all()
    ]
    diff = comparar_portas(portas_anteriores, portas_atuais)
    drift = DriftAnalise(
        ip=ip,
        analise_anterior_id=analise_anterior.id,
        analise_atual_id=analise_atual.id,
        portas_novas=diff["novas"],
        portas_fechadas=diff["fechadas"],
        versoes_mudaram=diff["versoes_mudaram"],
        tem_mudancas=diff["tem_mudancas"],
    )
    session.add(drift)
    return diff if diff["tem_mudancas"] else None


def _shodan_data_to_schema(shodan_raw: dict) -> ShodanInfo:
    """Converte o dict bruto do shodan_service em ShodanInfo Pydantic."""
    cves = [
        CveInfo(
            cve_id=c["cve_id"],
            cvss=c.get("cvss"),
            summary=c.get("summary"),
        )
        for c in shodan_raw.get("cves", [])
    ]
    return ShodanInfo(
        portas=shodan_raw.get("portas", []),
        cves=cves,
        banners=shodan_raw.get("banners", []),
        org=shodan_raw.get("org"),
        isp=shodan_raw.get("isp"),
        os=shodan_raw.get("os"),
        disponivel=shodan_raw.get("disponivel", True),
        erro=shodan_raw.get("erro"),
    )


def _extrair_ip_alvo_dns(dns_data: dict) -> str | None:
    registros = dns_data.get("registros") if isinstance(dns_data, dict) else {}
    ips = registros.get("a") if isinstance(registros, dict) else []
    if isinstance(ips, list) and ips:
        return str(ips[0])
    return None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/validar/{valor}")
async def validar_valor(
    valor: str,
    api_key: str = Security(validar_api_key),
):
    """Valida se o valor informado é um IP bem formatado."""
    try:
        AnaliseRequest(ip=valor)
        return {"mensagem": f"Valor de IP válido '{valor}'.", "status": "sucesso"}
    except ValidationError:
        logger.error("Validação falhou para valor: %s", valor)
        raise HTTPException(status_code=400, detail=f"Valor de IP inválido '{valor}'.")


@router.post("/analisar/", response_model=AnaliseResponse)
@limiter.limit(RATE_LIMIT_ANALISAR)
async def analisar_ip(
    request: Request,
    dados: AnaliseRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """
    Executa scan completo de IP:
    AbuseIPDB → GeoIP → Shodan → Nmap → Drift → Security Headers.
    Envia alerta Telegram em background para IPs com risco detectado.
    """
    ip_str = str(dados.ip)
    logger.info("Iniciando análise de IP: %s", ip_str)

    # AbuseIPDB
    resultado = avaliar_risco_abuseipdb(ip_str)
    if not isinstance(resultado, dict):
        logger.error("Resposta inválida de avaliar_risco_abuseipdb para %s", ip_str)
        raise HTTPException(status_code=500, detail="Resposta inválida da função avaliar_risco_abuseipdb")
    if not resultado.get("sucesso", False):
        logger.error("Erro na consulta AbuseIPDB para %s: %s", ip_str, resultado.get("erro"))
        raise HTTPException(status_code=502, detail=f"Erro na consulta externa: {resultado.get('erro')}")

    risco         = resultado.get("risco", "desconhecido")
    score         = resultado.get("score", 0)
    total_reports = resultado.get("total_reports", 0)
    dados_externos = resultado.get("data", {})

    # GeoIP
    geoip_resultado = consultar_geoip(ip_str)
    geoip = geoip_resultado.get("data") if geoip_resultado.get("sucesso") else None

    # Shodan
    shodan_raw  = consultar_shodan(ip_str)
    shodan_info = _shodan_data_to_schema(shodan_raw)
    vulns_json = (
        {
            "cves":    shodan_raw.get("cves", []),
            "banners": shodan_raw.get("banners", []),
            "portas":  shodan_raw.get("portas", []),
            "org":     shodan_raw.get("org"),
        }
        if shodan_raw.get("sucesso") and shodan_raw.get("disponivel")
        else None
    )

    # Agrava o risco com base nas CVEs do Shodan
    if vulns_json and vulns_json.get("cves"):
        for cve in vulns_json["cves"]:
            sev = cve.get("severidade")
            if sev == "critico":
                risco = "critico"
                break  # Risco máximo atingido
            elif sev == "alto" and risco not in ["critico"]:
                risco = "alto"
            elif sev == "medio" and risco not in ["critico", "alto"]:
                risco = "medio"

    # Busca análise anterior para drift
    analise_anterior = session.exec(
        select(AnaliseIP).where(AnaliseIP.ip == ip_str).order_by(AnaliseIP.id.desc())
    ).first()

    analise = AnaliseIP(
        ip=ip_str,
        risco=risco,
        score=score,
        total_reports=total_reports,
        pais=dados_externos.get("pais"),
        provedor=dados_externos.get("isp"),
        latitude=geoip.get("latitude") if geoip else None,
        longitude=geoip.get("longitude") if geoip else None,
        vulnerabilidades=vulns_json,
        timestamp_auditoria=datetime.now(tz=timezone.utc),
    )
    session.add(analise)
    session.commit()
    session.refresh(analise)

    # Nmap + Drift
    portas_abertas: list[dict] = []
    drift_resultado: dict | None = None
    scan = escanear_portas(ip_str)
    if scan.get("sucesso"):
        portas_abertas = extrair_portas_abertas_do_scan(scan.get("data", {}))
        _salvar_snapshot_portas(session, analise.id, portas_abertas)
        if analise_anterior is not None:
            drift_diff = _calcular_e_salvar_drift(session, ip_str, analise_anterior, analise, portas_abertas)
            if drift_diff:
                drift_resultado = {
                    "novas":          drift_diff["novas"],
                    "fechadas":       drift_diff["fechadas"],
                    "versoes_mudaram": drift_diff["versoes_mudaram"],
                    "tem_mudancas":   True,
                }
        session.commit()
    else:
        logger.warning("Nmap falhou para %s: %s", ip_str, scan.get("erro"))

    # Security Headers
    headers_resultado = analisar_headers_seguranca(ip_str)
    headers_seguranca = headers_resultado.get("data") if headers_resultado.get("sucesso") else None

    # Alerta Telegram (background)
    if risco in ["baixo", "medio", "alto", "critico"]:
        background_tasks.add_task(enviar_alerta_telegram, ip_str, risco, score, total_reports)

    logger.info("Análise concluída para %s — risco: %s, score: %d", ip_str, risco, score)
    return {
        "resultado":      risco,
        "detalhes":       f"Análise concluída para {ip_str}",
        "score":          score,
        "total_reports":  total_reports,
        "portas_abertas": portas_abertas,
        "headers_seguranca": headers_seguranca,
        "geoip":          geoip,
        "drift":          drift_resultado,
        "shodan":         shodan_info,
    }


@router.post("/analisar-site/", response_model=SiteAnaliseResponse)
@limiter.limit(RATE_LIMIT_ANALISAR_SITE)
async def analisar_site(
    request: Request,
    dados: SiteRequest,
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """
    Análise completa de um site:
    Security Headers → TLS/SSL → DNS → RDAP → HTTP Fingerprint.
    """
    url = dados.url
    logger.info("Iniciando análise de site: %s", url)
    
    # Extrai o domínio
    try:
        parsed_url = urllib.parse.urlparse(url)
        dominio = parsed_url.netloc or parsed_url.path
    except Exception:
        dominio = url

    headers_resultado     = analisar_headers_seguranca(url)
    tls_resultado         = analisar_tls_ssl(url)
    dns_resultado         = consultar_dns(url)
    infra_resultado       = await consultar_infra_health(url)
    rdap_resultado        = consultar_rdap(url)
    fingerprint_resultado = analisar_http_fingerprint(url)
    osint_resultado       = osint_completo_site(dominio)

    headers_data     = headers_resultado.get("data")     if headers_resultado.get("sucesso")     else {}
    tls_data         = tls_resultado.get("data")         if tls_resultado.get("sucesso")         else {}
    fingerprint_data = fingerprint_resultado.get("data") if fingerprint_resultado.get("sucesso") else {}
    dns_data         = dns_resultado.get("data")         if dns_resultado.get("sucesso")         else {}
    infra_data       = infra_resultado.get("data")       if infra_resultado.get("sucesso")       else {}
    rdap_data        = rdap_resultado.get("data")        if rdap_resultado.get("sucesso")        else {}
    osint_data       = osint_resultado.get("data")       if osint_resultado.get("sucesso")       else {}
    ip_alvo          = _extrair_ip_alvo_dns(dns_data)

    # Lógica de Risco Score
    risco_score = 0
    if not tls_data.get("valido"):
        risco_score += 30
    if headers_data.get("score_http", 100) < 50:
        risco_score += 20
    if osint_data.get("bruteforce") and len(osint_data["bruteforce"]) > 0:
        risco_score += 50
    if risco_score > 100:
        risco_score = 100

    analise_site = AnaliseSite(
        url=url,
        dominio=dominio,
        ip_alvo=ip_alvo,
        risco_score=risco_score,
        timestamp=datetime.now(tz=timezone.utc),
        certificados_tls=tls_data,
        headers_seguranca=headers_data,
        registros_dns=dns_data,
        infra_health=infra_data,
        dns_records=dns_data,
        infra_status=infra_data,
        http_fingerprint=fingerprint_data,
        diretorios_expostos=osint_data,
    )
    session.add(analise_site)
    session.commit()

    logger.info("Análise de site concluída: %s", url)
    return {
        "url":                 url,
        "dominio":             dominio,
        "ip_alvo":             ip_alvo,
        "risco_score":         risco_score,
        "headers_seguranca":   headers_data if headers_data else None,
        "certificados_tls":    tls_data if tls_data else None,
        "registros_dns":       dns_data if dns_data else None,
        "infra_health":        infra_data if infra_data else None,
        "dns_records":         dns_data if dns_data else None,
        "infra_status":        infra_data if infra_data else None,
        "rdap":                rdap_data if rdap_data else None,
        "http_fingerprint":    fingerprint_data if fingerprint_data else None,
        "diretorios_expostos": osint_data if osint_data else None,
    }


@router.get("/osint/dork/", response_model=OsintDorkResponse)
@limiter.limit(RATE_LIMIT_OSINT)
async def osint_dork(
    request: Request,
    dominio: str,
    api_key: str = Security(validar_api_key),
):
    """
    Executa busca OSINT no DuckDuckGo por diretórios expostos do domínio.
    A requisição é roteada pelo Tor quando disponível.
    """
    if not dominio or len(dominio) > 253:
        raise HTTPException(status_code=400, detail="Domínio inválido.")

    logger.info("OSINT dork iniciado para domínio: %s", dominio)
    resultado = dorker_duckduckgo(dominio=dominio, usar_tor=True)

    return OsintDorkResponse(
        dominio=resultado["dominio"],
        query=resultado["query"],
        via_tor=resultado["via_tor"],
        resultados=[
            DorkResult(url=r["url"], titulo=r.get("titulo"), snippet=r.get("snippet"))
            for r in resultado["resultados"]
        ],
        erro=resultado.get("erro"),
    )


@router.get("/osint/tor-status/")
async def tor_status(api_key: str = Security(validar_api_key)):
    """Verifica se o Tor está ativo e retorna o IP de saída."""
    return verificar_tor()
