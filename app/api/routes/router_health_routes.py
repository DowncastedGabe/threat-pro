import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.dependencies.rate_limit import limiter
from app.schemas.router_health import RouterHealthScanRequest, RouterHealthScanResponse
from app.use_cases.router_health.scan_router_health import ScanRouterHealthUseCase
from app.infrastructure.external_services.router_health_scanner import RouterHealthValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/router-health", tags=["Router Health"])


def get_scan_router_health_use_case() -> ScanRouterHealthUseCase:
    return ScanRouterHealthUseCase()


@router.post("/scan", response_model=RouterHealthScanResponse)
@limiter.limit("8/minute")
async def scan_router_health_endpoint(
    request: Request,
    payload: RouterHealthScanRequest,
    use_case: ScanRouterHealthUseCase = Depends(get_scan_router_health_use_case),
):
    try:
        return await use_case.execute(
            target=payload.target,
            timeout_seconds=payload.timeout_seconds,
        )
    except RouterHealthValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Falha ao verificar saude do roteador")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Nao foi possivel concluir a verificacao do roteador.",
        ) from exc
