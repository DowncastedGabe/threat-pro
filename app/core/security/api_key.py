import logging

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.config.settings import settings

logger = logging.getLogger(__name__)

API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


async def validar_api_key(api_key: str = Security(api_key_header)) -> str:
    if not settings.api_key:
        raise RuntimeError("API_KEY nao configurada no ambiente")
    if not api_key:
        logger.warning("Tentativa de acesso sem API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key ausente. Envie o header 'x-api-key'.",
        )
    if api_key != settings.api_key:
        logger.warning("Tentativa de acesso com API key invalida")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API key invalida.")
    return api_key
