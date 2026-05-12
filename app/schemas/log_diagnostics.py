from pydantic import BaseModel, Field


class LogDiagnosticEvidence(BaseModel):
    source: str
    sample: str


class LogDiagnosticFinding(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    status: str
    reason: str
    impact: str
    recommendation: str
    evidence: list[LogDiagnosticEvidence] = Field(default_factory=list)
    related_endpoints: list[str] = Field(default_factory=list)


class LogDiagnosticSummary(BaseModel):
    total_findings: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    main_causes: list[str]
    recommendations: list[str]


class LogDiagnosticsResponse(BaseModel):
    summary: LogDiagnosticSummary
    findings: list[LogDiagnosticFinding]


class LogDiagnosticCategoriesResponse(BaseModel):
    categories: list[str]

