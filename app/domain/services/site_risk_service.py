class SiteRiskService:
    @staticmethod
    def level_from_score(score: int) -> str:
        if score >= 80:
            return "critico"
        if score >= 50:
            return "alto"
        if score >= 20:
            return "medio"
        return "baixo"

    @staticmethod
    def score_filter_bounds(risco: str | None) -> tuple[int | None, int | None]:
        if not risco:
            return None, None
        risco = risco.lower()
        if risco == "baixo":
            return None, 20
        if risco == "medio":
            return 20, 50
        if risco == "alto":
            return 50, 80
        if risco == "critico":
            return 80, None
        return None, None
