"""
core/scheduler.py — Agendador de scans periódicos com APScheduler.

Usa AsyncIOScheduler para integração nativa com o event loop do FastAPI.
Os scans de Nmap (bloqueantes) são executados em run_in_executor
para não bloquear o loop de eventos.
"""

import asyncio
import logging
from datetime import datetime, timezone

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger
except ModuleNotFoundError:
    class AsyncIOScheduler:
        def __init__(self, *args, **kwargs):
            self.running = False

        def start(self):
            self.running = True

        def shutdown(self, wait=False):
            self.running = False

        def add_job(self, *args, **kwargs):
            return None

        def remove_job(self, *args, **kwargs):
            return None

        def get_job(self, *args, **kwargs):
            return None

    class IntervalTrigger:
        def __init__(self, *args, **kwargs):
            pass
from sqlmodel import Session, select

from core.engine import engine
from core.nmap_service import escanear_portas
from core.shodan_service import consultar_shodan
from core.utils import comparar_portas, extrair_portas_abertas_do_scan
from app.models import (
    AnaliseIP,
    MonitoramentoAgendado,
    ScanPorta,
    DriftAnalise,
)

logger = logging.getLogger(__name__)

# Instância global do scheduler
scheduler = AsyncIOScheduler(timezone="UTC")


# ── Tarefa de scan agendado ───────────────────────────────────────────────────

async def tarefa_scan_agendado(ip: str, monitoramento_id: int) -> None:
    """
    Executa um scan Nmap para o IP informado, calcula drift em relação ao
    scan anterior e persiste o resultado no banco de dados.

    Roda o Nmap (bloqueante) em um thread pool para não bloquear o event loop.
    """
    logger.info("[Scheduler] Iniciando scan agendado — IP: %s (job_id: %s)", ip, monitoramento_id)

    loop = asyncio.get_event_loop()

    # Executa o Nmap em thread separado (é bloqueante por natureza)
    scan = await loop.run_in_executor(None, escanear_portas, ip)

    if not scan.get("sucesso"):
        logger.warning("[Scheduler] Scan falhou para %s: %s", ip, scan.get("erro"))
        return

    portas_atuais = extrair_portas_abertas_do_scan(scan.get("data", {}))

    with Session(engine) as session:
        # Busca scan mais recente do IP para calcular drift
        stmt_anterior = (
            select(AnaliseIP)
            .where(AnaliseIP.ip == ip)
            .order_by(AnaliseIP.id.desc())
        )
        ultima_analise = session.exec(stmt_anterior).first()

        # Cria novo registro de análise
        shodan_data = await loop.run_in_executor(None, consultar_shodan, ip)
        vulns_json = {
            "cves":    shodan_data.get("cves", []),
            "banners": shodan_data.get("banners", []),
            "portas":  shodan_data.get("portas", []),
            "org":     shodan_data.get("org"),
        } if shodan_data.get("sucesso") else None

        nova_analise = AnaliseIP(
            ip=ip,
            risco="agendado",
            score=0,
            total_reports=0,
            vulnerabilidades=vulns_json,
            timestamp_auditoria=datetime.now(tz=timezone.utc),
        )
        session.add(nova_analise)
        session.commit()
        session.refresh(nova_analise)

        # Salva snapshot das portas
        for porta in portas_atuais:
            scan_porta = ScanPorta(
                analise_ip_id=nova_analise.id,
                porta=porta.get("porta", 0),
                protocolo=porta.get("protocolo", "tcp"),
                estado=porta.get("estado", ""),
                servico=porta.get("servico"),
                produto=porta.get("produto"),
                versao=porta.get("versao"),
            )
            session.add(scan_porta)

        # Calcula drift se houver análise anterior
        if ultima_analise is not None:
            stmt_portas = select(ScanPorta).where(
                ScanPorta.analise_ip_id == ultima_analise.id
            )
            portas_anteriores_db = session.exec(stmt_portas).all()
            portas_anteriores = [
                {
                    "porta": p.porta,
                    "protocolo": p.protocolo,
                    "estado": p.estado,
                    "servico": p.servico,
                    "produto": p.produto,
                    "versao": p.versao,
                }
                for p in portas_anteriores_db
            ]

            diff = comparar_portas(portas_anteriores, portas_atuais)

            drift = DriftAnalise(
                ip=ip,
                analise_anterior_id=ultima_analise.id,
                analise_atual_id=nova_analise.id,
                portas_novas=diff["novas"],
                portas_fechadas=diff["fechadas"],
                versoes_mudaram=diff["versoes_mudaram"],
                tem_mudancas=diff["tem_mudancas"],
            )
            session.add(drift)

            if diff["tem_mudancas"]:
                logger.info(
                    "[Scheduler] Drift detectado para %s — novas: %d, fechadas: %d, versões: %d",
                    ip,
                    len(diff["novas"]),
                    len(diff["fechadas"]),
                    len(diff["versoes_mudaram"]),
                )

        # Atualiza timestamp do monitoramento
        monitoramento = session.get(MonitoramentoAgendado, monitoramento_id)
        if monitoramento:
            monitoramento.ultimo_scan = datetime.now(tz=timezone.utc)
            session.add(monitoramento)

        session.commit()
        logger.info("[Scheduler] Scan agendado concluído para %s", ip)


# ── Registro de jobs a partir do banco ───────────────────────────────────────

def registrar_jobs_do_banco() -> None:
    """
    Lê todos os MonitoramentoAgendado ativos no banco e cria/atualiza
    os jobs correspondentes no scheduler.

    Chamado no startup da aplicação para restaurar jobs após reinício do container.
    """
    with Session(engine) as session:
        agendamentos = session.exec(
            select(MonitoramentoAgendado).where(MonitoramentoAgendado.ativo == True)  # noqa: E712
        ).all()

    for ag in agendamentos:
        _adicionar_job(ag.id, ag.ip, ag.frequencia_horas)

    logger.info("[Scheduler] %d job(s) restaurado(s) do banco.", len(agendamentos))


def _adicionar_job(monitoramento_id: int, ip: str, frequencia_horas: int) -> None:
    """Registra ou substitui um job no scheduler."""
    job_id = f"scan_{monitoramento_id}"
    scheduler.add_job(
        tarefa_scan_agendado,
        trigger=IntervalTrigger(hours=frequencia_horas),
        id=job_id,
        args=[ip, monitoramento_id],
        replace_existing=True,
        misfire_grace_time=300,  # 5 min de tolerância se o container estava parado
    )
    logger.info(
        "[Scheduler] Job registrado — id=%s, ip=%s, a cada %dh",
        job_id, ip, frequencia_horas,
    )


def adicionar_job_monitoramento(monitoramento_id: int, ip: str, frequencia_horas: int) -> None:
    """API pública para adicionar um job a partir de um endpoint."""
    _adicionar_job(monitoramento_id, ip, frequencia_horas)


def remover_job_monitoramento(monitoramento_id: int) -> bool:
    """Remove um job do scheduler. Retorna True se o job existia."""
    job_id = f"scan_{monitoramento_id}"
    job = scheduler.get_job(job_id)
    if job:
        scheduler.remove_job(job_id)
        logger.info("[Scheduler] Job removido — id=%s", job_id)
        return True
    return False
