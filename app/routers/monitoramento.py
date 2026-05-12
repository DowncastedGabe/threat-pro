"""
app/routers/monitoramento.py — Endpoints para gerenciar agendamentos do APScheduler.

Rotas:
  POST   /monitorar/            — Cria novo monitoramento agendado para um IP
  GET    /monitorar/            — Lista todos os monitoramentos registrados
  DELETE /monitorar/{id}        — Desativa monitoramento e remove o job do scheduler
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Security
from sqlmodel import Session, select

from app.dependencies import validar_api_key
from app.models import (
    MonitoramentoAgendado,
    MonitoramentoCreate,
    MonitoramentoRead,
)
from core.scheduler import adicionar_job_monitoramento, remover_job_monitoramento
from core.session import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/monitorar", tags=["Monitoramento"])


@router.post("/", response_model=MonitoramentoRead, status_code=201)
async def criar_monitoramento(
    dados: MonitoramentoCreate,
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """
    Cria um novo monitoramento agendado para um IP.
    Retorna 409 se já existir monitoramento ativo para o mesmo IP.
    """
    ip_str = str(dados.ip)

    existente = session.exec(
        select(MonitoramentoAgendado)
        .where(MonitoramentoAgendado.ip == ip_str)
        .where(MonitoramentoAgendado.ativo == True)  # noqa: E712
    ).first()

    if existente:
        logger.warning("Tentativa de criar monitoramento duplicado para IP: %s (id=%d)", ip_str, existente.id)
        raise HTTPException(
            status_code=409,
            detail=f"Já existe monitoramento ativo para {ip_str} (id={existente.id}).",
        )

    monitoramento = MonitoramentoAgendado(
        ip=ip_str,
        frequencia_horas=dados.frequencia_horas,
        ativo=True,
        criado_em=datetime.now(tz=timezone.utc),
    )
    session.add(monitoramento)
    session.commit()
    session.refresh(monitoramento)

    adicionar_job_monitoramento(monitoramento.id, ip_str, dados.frequencia_horas)
    logger.info("Monitoramento criado — IP: %s, frequência: %dh, id: %d", ip_str, dados.frequencia_horas, monitoramento.id)

    return MonitoramentoRead(
        id=monitoramento.id,
        ip=monitoramento.ip,
        frequencia_horas=monitoramento.frequencia_horas,
        ativo=monitoramento.ativo,
        ultimo_scan=monitoramento.ultimo_scan,
        criado_em=monitoramento.criado_em,
    )


@router.get("/", response_model=list[MonitoramentoRead])
async def listar_monitoramentos(
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """Retorna todos os monitoramentos registrados (ativos e inativos)."""
    return [
        MonitoramentoRead(
            id=m.id,
            ip=m.ip,
            frequencia_horas=m.frequencia_horas,
            ativo=m.ativo,
            ultimo_scan=m.ultimo_scan,
            criado_em=m.criado_em,
        )
        for m in session.exec(select(MonitoramentoAgendado)).all()
    ]


@router.delete("/{monitoramento_id}", status_code=204)
async def remover_monitoramento(
    monitoramento_id: int,
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    """
    Desativa um monitoramento e remove o job correspondente do APScheduler.
    O registro permanece no banco com `ativo=False` para auditoria.
    """
    monitoramento = session.get(MonitoramentoAgendado, monitoramento_id)
    if not monitoramento:
        raise HTTPException(status_code=404, detail="Monitoramento não encontrado.")

    remover_job_monitoramento(monitoramento_id)
    monitoramento.ativo = False
    session.add(monitoramento)
    session.commit()
    logger.info("Monitoramento desativado — id: %d, IP: %s", monitoramento_id, monitoramento.ip)
