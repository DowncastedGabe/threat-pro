from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database.base import Base


class SiteAnalysisModel(Base):
    __tablename__ = "site_analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    dominio: Mapped[str] = mapped_column(String(253), index=True, nullable=False)
    ip_alvo: Mapped[str | None] = mapped_column(String(64), index=True)
    risco_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    registros_dns: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    certificados_tls: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    infra_health: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    diretorios_expostos: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
