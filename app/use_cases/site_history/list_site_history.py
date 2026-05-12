from dataclasses import dataclass

from app.domain.entities.site_analysis import SiteAnalysis
from app.domain.repositories.site_analysis_repository import SiteAnalysisRepository


@dataclass(slots=True)
class SiteHistoryPage:
    total: int
    pagina: int
    por_pagina: int
    dados: list[SiteAnalysis]


class ListSiteHistoryUseCase:
    def __init__(self, repository: SiteAnalysisRepository):
        self.repository = repository

    def execute(
        self,
        *,
        pagina: int = 1,
        por_pagina: int = 25,
        dominio: str | None = None,
        risco: str | None = None,
    ) -> SiteHistoryPage:
        offset = (pagina - 1) * por_pagina
        total = self.repository.count(dominio=dominio, risco=risco)
        dados = self.repository.list(
            dominio=dominio,
            risco=risco,
            offset=offset,
            limit=por_pagina,
        )
        return SiteHistoryPage(total=total, pagina=pagina, por_pagina=por_pagina, dados=dados)
