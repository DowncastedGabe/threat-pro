from app.infrastructure.external_services.router_health_scanner import scan_router_health


class ScanRouterHealthUseCase:
    async def execute(self, target: str | None, timeout_seconds: float) -> dict:
        return await scan_router_health(target=target, timeout_seconds=timeout_seconds)
