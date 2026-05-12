from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class SiteAnalysis:
    id: int | None
    url: str
    dominio: str
    risco_score: int
    ip_alvo: str | None = None
    registros_dns: dict[str, Any] | None = field(default_factory=dict)
    certificados_tls: dict[str, Any] | None = field(default_factory=dict)
    infra_health: dict[str, Any] | None = field(default_factory=dict)
    diretorios_expostos: dict[str, Any] | None = field(default_factory=dict)
    headers_seguranca: dict[str, Any] | None = field(default_factory=dict)
    http_fingerprint: dict[str, Any] | None = field(default_factory=dict)
    timestamp: datetime | None = None
    timestamp_auditoria: datetime | None = None

    @property
    def risk_level(self) -> str:
        if self.risco_score >= 80:
            return "critico"
        if self.risco_score >= 50:
            return "alto"
        if self.risco_score >= 20:
            return "medio"
        return "baixo"
