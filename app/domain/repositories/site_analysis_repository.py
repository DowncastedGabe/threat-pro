from typing import Protocol

from app.domain.entities.site_analysis import SiteAnalysis


class SiteAnalysisRepository(Protocol):
    def count(self, *, dominio: str | None = None, risco: str | None = None) -> int:
        ...

    def list(
        self,
        *,
        dominio: str | None = None,
        risco: str | None = None,
        offset: int = 0,
        limit: int = 25,
    ) -> list[SiteAnalysis]:
        ...
