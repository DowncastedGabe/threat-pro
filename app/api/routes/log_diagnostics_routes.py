from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.dependencies.rate_limit import limiter
from app.schemas.log_diagnostics import (
    LogDiagnosticCategoriesResponse,
    LogDiagnosticFinding,
    LogDiagnosticsResponse,
)
from app.use_cases.log_diagnostics.list_log_diagnostics import (
    ListLogDiagnosticsUseCase,
    get_finding,
    list_categories,
)

router = APIRouter(prefix="/log-diagnostics", tags=["Log Diagnostics"])


def get_list_log_diagnostics_use_case() -> ListLogDiagnosticsUseCase:
    return ListLogDiagnosticsUseCase()


@router.get("/", response_model=LogDiagnosticsResponse)
@limiter.limit("30/minute")
async def list_log_diagnostics(
    request: Request,
    category: str | None = Query(default=None, max_length=64),
    severity: str | None = Query(default=None, max_length=32),
    q: str | None = Query(default=None, max_length=120),
    use_case: ListLogDiagnosticsUseCase = Depends(get_list_log_diagnostics_use_case),
):
    summary, findings = use_case.execute(
        category=category,
        severity=severity,
        query=q,
    )
    return LogDiagnosticsResponse(summary=summary, findings=findings)


@router.get("/categories", response_model=LogDiagnosticCategoriesResponse)
@limiter.limit("30/minute")
async def get_log_diagnostic_categories(request: Request):
    return LogDiagnosticCategoriesResponse(categories=list_categories())


@router.get("/{finding_id}", response_model=LogDiagnosticFinding)
@limiter.limit("30/minute")
async def get_log_diagnostic_finding(request: Request, finding_id: str):
    finding = get_finding(finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Diagnostico nao encontrado.",
        )
    return finding

