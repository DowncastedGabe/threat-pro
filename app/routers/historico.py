"""
app/routers/historico.py — Endpoints de consulta ao banco de dados.

Rotas:
  GET /historico/                    — Lista todas as análises de IP
  GET /historico-sites/              — Lista todas as análises de sites
  GET /historico/{ip}/timeline       — Cronologia de eventos (scans + drifts) por IP
  GET /drift/{ip}                    — Lista todos os drifts detectados para um IP
  GET /mapa/                         — Pontos geográficos únicos para mapa de calor
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from sqlalchemy import func
from sqlmodel import Session, select

from app.dependencies import validar_api_key
from app.models import (
    AnaliseIP,
    AnaliseIPRead,
    AnaliseSite,
    AnaliseSiteRead,
    DriftAnalise,
    DriftRead,
    GeoMapPoint,
    ListaAnalisesResponse,
    ListaAnalisesSiteResponse,
    TimelineEvento,
)
from app.api.dependencies.use_cases import get_list_site_history_use_case
from app.domain.entities.site_analysis import SiteAnalysis
from app.use_cases.site_history.list_site_history import ListSiteHistoryUseCase
from core.session import get_session
from core.utils_security import validar_ip_seguro

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Histórico"])


def _aplicar_filtro_risco_site(stmt, risco: str | None):
    if not risco:
        return stmt

    risco_normalizado = risco.lower()
    if risco_normalizado == "baixo":
        return stmt.where(AnaliseSite.risco_score < 20)
    if risco_normalizado == "medio":
        return stmt.where(AnaliseSite.risco_score >= 20).where(AnaliseSite.risco_score < 50)
    if risco_normalizado == "alto":
        return stmt.where(AnaliseSite.risco_score >= 50).where(AnaliseSite.risco_score < 80)
    if risco_normalizado in {"critico", "crítico"}:
        return stmt.where(AnaliseSite.risco_score >= 80)
    return stmt


def _site_to_read(a: SiteAnalysis | AnaliseSite) -> AnaliseSiteRead:
    registros_dns = getattr(a, "registros_dns", None) or getattr(a, "dns_records", None)
    infra_health = getattr(a, "infra_health", None) or getattr(a, "infra_status", None)
    timestamp = getattr(a, "timestamp", None) or getattr(a, "timestamp_auditoria", None)

    return AnaliseSiteRead(
        id=a.id,
        url=a.url,
        dominio=a.dominio,
        ip_alvo=a.ip_alvo,
        risco_score=a.risco_score,
        diretorios_expostos=a.diretorios_expostos,
        certificados_tls=a.certificados_tls,
        registros_dns=registros_dns,
        infra_health=infra_health,
        dns_records=registros_dns,
        infra_status=infra_health,
        headers_seguranca=getattr(a, "headers_seguranca", None),
        http_fingerprint=getattr(a, "http_fingerprint", None),
        timestamp=timestamp,
        timestamp_auditoria=getattr(a, "timestamp_auditoria", None) or timestamp,
    )


@router.get("/historico/", response_model=ListaAnalisesResponse)
async def historico(
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """Retorna todas as análises de IP registradas no banco de dados."""
    analises = session.exec(select(AnaliseIP)).all()
    return ListaAnalisesResponse(
        total=len(analises),
        dados=[
            AnaliseIPRead(
                id=a.id,
                ip=a.ip,
                risco=a.risco,
                score=a.score,
                pais=a.pais,
                latitude=a.latitude,
                longitude=a.longitude,
                vulnerabilidades=a.vulnerabilidades,
                timestamp_auditoria=a.timestamp_auditoria,
            )
            for a in analises
        ],
    )


@router.get("/historico-sites/", response_model=ListaAnalisesSiteResponse)
async def historico_sites(
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """Compatibilidade: retorna as analises de sites sem filtros explicitos."""
    return await historico_sites_paginado(
        pagina=1,
        por_pagina=500,
        dominio=None,
        risco=None,
        api_key=api_key,
        session=session,
    )


@router.get("/historico/sites", response_model=ListaAnalisesSiteResponse)
async def historico_sites_paginado(
    pagina: int = Query(default=1, ge=1),
    por_pagina: int = Query(default=25, ge=1, le=100),
    dominio: str | None = Query(default=None, min_length=1, max_length=253),
    risco: str | None = Query(default=None, pattern="^(baixo|medio|alto|critico|crítico)$"),
    api_key: str = Security(validar_api_key),
    use_case: ListSiteHistoryUseCase = Depends(get_list_site_history_use_case),
):
    """Retorna historico de sites com paginacao e filtros por dominio/risco."""
    page = use_case.execute(pagina=pagina, por_pagina=por_pagina, dominio=dominio, risco=risco)
    return ListaAnalisesSiteResponse(
        total=page.total,
        pagina=page.pagina,
        por_pagina=page.por_pagina,
        dados=[_site_to_read(a) for a in page.dados],
    )


@router.get("/historico/{ip}/timeline", response_model=list[TimelineEvento])
async def timeline_ip(
    ip: str,
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """
    Retorna cronologia de eventos (scans + drifts) para um IP específico.
    Permite visualização temporal completa na interface.
    """
    try:
        ip_validado = validar_ip_seguro(ip)
    except ValueError as e:
        logger.error("IP inválido na timeline: %s — %s", ip, e)
        raise HTTPException(status_code=400, detail=str(e))

    analises = session.exec(
        select(AnaliseIP)
        .where(AnaliseIP.ip == ip_validado)
        .order_by(AnaliseIP.timestamp_auditoria)
    ).all()

    drifts = session.exec(
        select(DriftAnalise)
        .where(DriftAnalise.ip == ip_validado)
        .order_by(DriftAnalise.timestamp)
    ).all()

    # Indexa drifts pelo analise_atual_id para lookup O(1)
    drift_por_analise: dict[int, DriftAnalise] = {d.analise_atual_id: d for d in drifts}

    eventos: list[TimelineEvento] = []
    for analise in analises:
        tipo  = "scan_agendado" if analise.risco == "agendado" else "scan_manual"
        drift = drift_por_analise.get(analise.id)
        tem_alerta = bool(drift and drift.tem_mudancas)

        if tem_alerta and drift:
            n = len(drift.portas_novas or [])
            f = len(drift.portas_fechadas or [])
            v = len(drift.versoes_mudaram or [])
            descricao = f"Drift detectado — {n} porta(s) nova(s), {f} fechada(s), {v} versão(ões) alterada(s)"
            tipo = "drift"
        else:
            cves   = analise.vulnerabilidades.get("cves", []) if analise.vulnerabilidades else []
            n_cves = len(cves)
            descricao = (
                f"Scan {'agendado' if tipo == 'scan_agendado' else 'manual'} — "
                f"Risco: {analise.risco.upper()}, Score: {analise.score}"
                + (f", {n_cves} CVE(s) detectado(s)" if n_cves else "")
            )

        eventos.append(TimelineEvento(
            tipo=tipo,
            timestamp=analise.timestamp_auditoria,
            descricao=descricao,
            tem_alerta=tem_alerta,
            detalhes={
                "analise_id": analise.id,
                "risco":      analise.risco,
                "score":      analise.score,
                "drift_id":   drift.id if drift else None,
            },
        ))

    return eventos


@router.get("/drift/{ip}", response_model=list[DriftRead])
async def drift_ip(
    ip: str,
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """Retorna todos os registros de drift detectados para um IP específico."""
    try:
        ip_validado = validar_ip_seguro(ip)
    except ValueError as e:
        logger.error("IP inválido no drift: %s — %s", ip, e)
        raise HTTPException(status_code=400, detail=str(e))

    drifts = session.exec(
        select(DriftAnalise)
        .where(DriftAnalise.ip == ip_validado)
        .order_by(DriftAnalise.id.desc())
    ).all()

    return [
        DriftRead(
            id=d.id,
            ip=d.ip,
            analise_anterior_id=d.analise_anterior_id,
            analise_atual_id=d.analise_atual_id,
            portas_novas=d.portas_novas or [],
            portas_fechadas=d.portas_fechadas or [],
            versoes_mudaram=d.versoes_mudaram or [],
            tem_mudancas=d.tem_mudancas,
            timestamp=d.timestamp,
        )
        for d in drifts
    ]


@router.get("/mapa/", response_model=list[GeoMapPoint])
async def mapa_calor(
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """
    Retorna pontos geográficos únicos (um por IP) para o mapa de calor.
    Usa o registro mais recente de cada IP com coordenadas disponíveis.
    """
    stmt = (
        select(AnaliseIP)
        .where(AnaliseIP.latitude.is_not(None))
        .where(AnaliseIP.longitude.is_not(None))
        .order_by(AnaliseIP.id.desc())
    )
    analises = session.exec(stmt).all()

    vistos: set[str] = set()
    pontos: list[GeoMapPoint] = []
    for a in analises:
        if a.ip not in vistos:
            vistos.add(a.ip)
            pontos.append(GeoMapPoint(
                ip=a.ip,
                latitude=a.latitude,
                longitude=a.longitude,
                pais=a.pais,
                risco=a.risco,
                score=a.score,
            ))

    return pontos
