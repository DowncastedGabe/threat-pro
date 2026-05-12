from fastapi import APIRouter, Depends

from app.api.routes import (
    auth_routes,
    disk_mapping_routes,
    ingestion_routes,
    log_diagnostics_routes,
    router_health_routes,
)
from app.api.dependencies.auth import get_current_user
from app.routers import analise, historico, monitoramento

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(auth_routes.router)

protected_v1_router = APIRouter(dependencies=[Depends(get_current_user)])
protected_v1_router.include_router(analise.router)
protected_v1_router.include_router(historico.router)
protected_v1_router.include_router(monitoramento.router)
protected_v1_router.include_router(router_health_routes.router)
protected_v1_router.include_router(disk_mapping_routes.router)
protected_v1_router.include_router(log_diagnostics_routes.router)
protected_v1_router.include_router(ingestion_routes.router)

api_v1_router.include_router(protected_v1_router)
