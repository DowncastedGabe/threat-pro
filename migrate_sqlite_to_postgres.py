"""
Script para migrar dados do SQLite (antigo DB_DASHBOARD.db) para o novo PostgreSQL.

Como usar:
1. Garanta que os containers docker (especialmente o 'db') estejam rodando:
   $ docker compose up -d db

2. Instale as dependências localmente se ainda não as tiver (ou rode dentro do container da API):
   $ pip install sqlmodel psycopg2-binary python-dotenv

3. Execute o script:
   $ python migrate_sqlite_to_postgres.py
"""

import os
import logging
from pathlib import Path

from sqlmodel import Session, select, create_engine, SQLModel
from sqlalchemy import text
from dotenv import load_dotenv

# Importa todos os modelos para garantir que as tabelas sejam conhecidas
from app.models import AnaliseIP, AnaliseSite, ScanPorta, DriftAnalise, MonitoramentoAgendado

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migration")

# ── Configurações das Conexões ────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
SQLITE_DB_PATH = BASE_DIR / "data" / "DB_DASHBOARD.db"

if not SQLITE_DB_PATH.exists():
    logger.error("Banco SQLite não encontrado em %s", SQLITE_DB_PATH)
    exit(1)

SQLITE_URL = f"sqlite:///{SQLITE_DB_PATH}"
POSTGRES_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/threatintel"
)

logger.info("Lendo de: %s", SQLITE_URL)
logger.info("Gravando em: %s", POSTGRES_URL)

sqlite_engine = create_engine(SQLITE_URL)
pg_engine = create_engine(POSTGRES_URL)


# ── Função de Migração Genérica ───────────────────────────────────────────────

def migrar_tabela(tabela: type[SQLModel], nome_tabela: str):
    logger.info("Migrando tabela: %s", nome_tabela)
    
    with Session(sqlite_engine) as session_in:
        registros = session_in.exec(select(tabela)).all()
    
    if not registros:
        logger.info("Nenhum registro encontrado para %s", nome_tabela)
        return

    logger.info("Lidos %d registros. Inserindo no Postgres...", len(registros))
    
    with Session(pg_engine) as session_out:
        for r in registros:
            # SQLModel/SQLAlchemy lidará com a inserção incluindo o ID original.
            # Como instanciamos os objetos lidos da sessão anterior e os adicionamos na nova,
            # os IDs são preservados (o que é importante por causa das chaves estrangeiras).
            session_out.add(r)
        
        session_out.commit()

    # Como inserimos IDs explícitos, a sequence (autoincrement) do Postgres não é atualizada.
    # Precisamos sincronizar a sequence para não dar erro na próxima inserção feita pela API.
    with pg_engine.connect() as conn:
        query = f"""
            SELECT setval(pg_get_serial_sequence('{nome_tabela.lower()}', 'id'), 
            COALESCE(MAX(id), 0) + 1, false) FROM {nome_tabela.lower()};
        """
        conn.execute(text(query))
        conn.commit()

    logger.info("Tabela %s concluída e sequence sincronizada.", nome_tabela)


# ── Fluxo Principal ───────────────────────────────────────────────────────────

def executar_migracao():
    logger.info("Criando tabelas no PostgreSQL (se não existirem)...")
    SQLModel.metadata.create_all(bind=pg_engine)

    # A ordem importa por causa das foreign keys:
    # 1. Tabelas sem chaves estrangeiras
    migrar_tabela(AnaliseIP, "AnaliseIP")
    migrar_tabela(AnaliseSite, "AnaliseSite")
    migrar_tabela(MonitoramentoAgendado, "MonitoramentoAgendado")

    # 2. Tabelas dependentes
    migrar_tabela(ScanPorta, "ScanPorta")  # FK -> AnaliseIP
    migrar_tabela(DriftAnalise, "DriftAnalise") # Tem IDs baseados no AnaliseIP
    
    logger.info("✅ Migração concluída com sucesso!")

if __name__ == "__main__":
    executar_migracao()
