import logging

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status

from app.api.dependencies.rate_limit import limiter
from app.core.config.settings import settings
from app.infrastructure.external_services.ingestion_engine import IngestionValidationError
from app.schemas.ingestion import IngestionResponse, UrlIngestionRequest
from app.use_cases.ingestion.process_ingestion import ProcessIngestionUseCase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingestion", tags=["Ingestion"])


def get_process_ingestion_use_case() -> ProcessIngestionUseCase:
    return ProcessIngestionUseCase()


@router.post("/url", response_model=IngestionResponse)
@limiter.limit(settings.rate_limit_ingestion)
async def ingest_url(
    request: Request,
    payload: UrlIngestionRequest,
    use_case: ProcessIngestionUseCase = Depends(get_process_ingestion_use_case),
):
    try:
        document = use_case.from_url(
            url=str(payload.url),
            extract_text=payload.extract_text,
        )
        return document.to_response(include_buffer_base64=payload.include_buffer_base64)
    except IngestionValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Falha ao ingerir URL")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Nao foi possivel ingerir a URL informada.",
        ) from exc


@router.post("/upload", response_model=IngestionResponse)
@limiter.limit(settings.rate_limit_ingestion)
async def ingest_upload(
    request: Request,
    file: UploadFile = File(...),
    extract_text: bool = Query(default=True),
    include_buffer_base64: bool = Query(default=False),
    use_case: ProcessIngestionUseCase = Depends(get_process_ingestion_use_case),
):
    try:
        document = await use_case.from_upload(file=file, extract_text=extract_text)
        return document.to_response(include_buffer_base64=include_buffer_base64)
    except IngestionValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Falha ao ingerir upload")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Nao foi possivel ingerir o arquivo enviado.",
        ) from exc

