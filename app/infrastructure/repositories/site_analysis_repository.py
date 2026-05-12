from sqlalchemy import func
from sqlmodel import Session, select

from app.domain.entities.site_analysis import SiteAnalysis
from app.domain.services.site_risk_service import SiteRiskService
from app.models import AnaliseSite


class SqlModelSiteAnalysisRepository:
    def __init__(self, session: Session):
        self.session = session

    def _apply_filters(self, stmt, *, dominio: str | None, risco: str | None):
        if dominio:
            filtro = f"%{dominio.strip().lower()}%"
            stmt = stmt.where(func.lower(AnaliseSite.dominio).like(filtro))

        min_score, max_score = SiteRiskService.score_filter_bounds(risco)
        if min_score is not None:
            stmt = stmt.where(AnaliseSite.risco_score >= min_score)
        if max_score is not None:
            stmt = stmt.where(AnaliseSite.risco_score < max_score)
        return stmt

    def count(self, *, dominio: str | None = None, risco: str | None = None) -> int:
        stmt = self._apply_filters(
            select(func.count(AnaliseSite.id)),
            dominio=dominio,
            risco=risco,
        )
        return int(self.session.exec(stmt).one())

    def list(
        self,
        *,
        dominio: str | None = None,
        risco: str | None = None,
        offset: int = 0,
        limit: int = 25,
    ) -> list[SiteAnalysis]:
        stmt = self._apply_filters(select(AnaliseSite), dominio=dominio, risco=risco)
        rows = self.session.exec(
            stmt.order_by(AnaliseSite.timestamp.desc(), AnaliseSite.id.desc())
            .offset(offset)
            .limit(limit)
        ).all()
        return [self._to_domain(row) for row in rows]

    @staticmethod
    def _to_domain(row: AnaliseSite) -> SiteAnalysis:
        registros_dns = row.registros_dns or row.dns_records or {}
        infra_health = row.infra_health or row.infra_status or {}
        timestamp = row.timestamp or row.timestamp_auditoria
        return SiteAnalysis(
            id=row.id,
            url=row.url,
            dominio=row.dominio,
            ip_alvo=row.ip_alvo,
            risco_score=row.risco_score,
            registros_dns=registros_dns,
            certificados_tls=row.certificados_tls or {},
            infra_health=infra_health,
            diretorios_expostos=row.diretorios_expostos or {},
            headers_seguranca=row.headers_seguranca or {},
            http_fingerprint=row.http_fingerprint or {},
            timestamp=timestamp,
            timestamp_auditoria=row.timestamp_auditoria,
        )
