"""
app/main.py — Ponto de entrada da aplicação ThreatIntel Pro.

Responsabilidades:
  - Configuração de middlewares (CORS, SlowAPI)
  - Gerenciador de ciclo de vida (lifespan): banco de dados + APScheduler
  - Registro dos APIRouters modulares
  - Endpoints públicos sem autenticação (/ e /health)
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
try:
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
except ModuleNotFoundError:
    _rate_limit_exceeded_handler = None
    RateLimitExceeded = None
    SlowAPIMiddleware = None
from sqlalchemy import text
from sqlmodel import SQLModel

from app.dependencies import limiter
from app.api.middlewares.auth_context import AuthContextMiddleware
from app.api.middlewares.request_context import RequestContextMiddleware
from app.api.routes.v1.router import api_v1_router
from app.core.config.settings import settings
from app.core.exceptions.handlers import register_exception_handlers
from app.core.logging.config import configure_logging
from app.routers import analise, historico, monitoramento, sandbox
from app.infrastructure.database.base import Base
from app.infrastructure.database.models import UserModel
from core.engine import engine
from core.scheduler import registrar_jobs_do_banco, scheduler

configure_logging()
logger = logging.getLogger(__name__)


def _aplicar_migracoes_leves() -> None:
    """Ajustes aditivos simples para bancos existentes sem Alembic."""
    if engine.dialect.name != "postgresql":
        return

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE analisesite ADD COLUMN IF NOT EXISTS infra_status JSONB"))
        conn.execute(text("ALTER TABLE analisesite ADD COLUMN IF NOT EXISTS ip_alvo VARCHAR"))
        conn.execute(text("ALTER TABLE analisesite ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP"))
        conn.execute(text("ALTER TABLE analisesite ADD COLUMN IF NOT EXISTS registros_dns JSONB"))
        conn.execute(text("ALTER TABLE analisesite ADD COLUMN IF NOT EXISTS infra_health JSONB"))
        conn.execute(text("UPDATE analisesite SET timestamp = timestamp_auditoria WHERE timestamp IS NULL"))
        conn.execute(text("UPDATE analisesite SET registros_dns = dns_records WHERE registros_dns IS NULL AND dns_records IS NOT NULL"))
        conn.execute(text("UPDATE analisesite SET infra_health = infra_status WHERE infra_health IS NULL AND infra_status IS NOT NULL"))
        # Sandbox: novas tabelas (criadas via SQLModel.metadata.create_all, mas migração defensiva)
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS analisearquivo (
                id SERIAL PRIMARY KEY,
                nome_original VARCHAR NOT NULL,
                tamanho_bytes INTEGER DEFAULT 0,
                mime_type VARCHAR,
                extensao_declarada VARCHAR,
                md5 VARCHAR NOT NULL,
                sha1 VARCHAR NOT NULL,
                sha256 VARCHAR NOT NULL,
                vt_relatorio JSONB,
                vt_total_engines INTEGER DEFAULT 0,
                vt_total_detected INTEGER DEFAULT 0,
                vt_status VARCHAR DEFAULT 'limpo',
                timestamp TIMESTAMP DEFAULT NOW()
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS analiseurl (
                id SERIAL PRIMARY KEY,
                url_original VARCHAR NOT NULL,
                reputacao_status VARCHAR DEFAULT 'desconhecida',
                reputacao_fonte VARCHAR,
                reputacao_relatorio JSONB,
                redirect_hops JSONB,
                url_final VARCHAR,
                content_type_final VARCHAR,
                via_tor BOOLEAN DEFAULT FALSE,
                tor_erro VARCHAR,
                timestamp TIMESTAMP DEFAULT NOW()
            )
        """))


# ── Ciclo de vida da aplicação ────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Inicializa e encerra os serviços da aplicação:
    - Criação das tabelas SQLModel no banco de dados
    - Start/shutdown do APScheduler com restauração dos jobs persistidos
    """
    logger.info("Criando tabelas no banco de dados...")
    SQLModel.metadata.create_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    _aplicar_migracoes_leves()

    logger.info("Iniciando scheduler de tarefas periódicas...")
    scheduler.start()
    registrar_jobs_do_banco()

    yield

    logger.info("Encerrando scheduler...")
    scheduler.shutdown(wait=False)
    logger.info("Aplicação encerrada com sucesso.")


# ── Instância FastAPI ─────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    description="Plataforma de inteligência de ameaças com análise de IP, site e OSINT.",
    version=settings.app_version,
    lifespan=lifespan,
    docs_url=None    if settings.is_prod else "/docs",
    redoc_url=None   if settings.is_prod else "/redoc",
    openapi_url=None if settings.is_prod else "/openapi.json",
)


# ── Middlewares ───────────────────────────────────────────────────────────────

app.state.limiter = limiter
if RateLimitExceeded and _rate_limit_exceeded_handler and SlowAPIMiddleware:
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(AuthContextMiddleware)
register_exception_handlers(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routers modulares ─────────────────────────────────────────────────────────

app.include_router(analise.router)
app.include_router(historico.router)
app.include_router(monitoramento.router)
app.include_router(sandbox.router)
app.include_router(api_v1_router)


# ── Endpoints públicos (sem autenticação) ─────────────────────────────────────

@app.get("/", tags=["Status"])
async def root():
    """Verifica se a API está online."""
    return {"message": "API Online!"}


@app.get("/health", tags=["Status"])
async def health():
    """Health check para orquestradores (Docker, Kubernetes)."""
    return {"status": "ok", "service": "threat-intel-api"}
