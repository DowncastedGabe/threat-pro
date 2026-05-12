import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.dependencies.rate_limit import limiter
from app.core.config.settings import settings
from app.infrastructure.external_services.disk_mapping_service import DiskMappingValidationError
from app.schemas.disk_mapping import DiskMappingResponse, DiskTreeRequest
from app.use_cases.disk_mapping.get_disk_mapping import GetDiskMappingUseCase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/disk-mapping", tags=["Disk Mapping"])


def get_disk_mapping_use_case() -> GetDiskMappingUseCase:
    return GetDiskMappingUseCase()


@router.post("/scan", response_model=DiskMappingResponse)
@limiter.limit(settings.rate_limit_disk_mapping)
async def scan_disk_mapping(
    request: Request,
    payload: DiskTreeRequest,
    use_case: GetDiskMappingUseCase = Depends(get_disk_mapping_use_case),
):
    try:
        return use_case.execute(
            root_path=payload.root_path,
            max_depth=payload.max_depth,
            max_nodes=payload.max_nodes,
        )
    except DiskMappingValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Falha ao mapear disco")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Nao foi possivel concluir o mapeamento de disco.",
        ) from exc
