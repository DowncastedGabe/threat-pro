from pydantic import BaseModel, Field


class RouterHealthScanRequest(BaseModel):
    target: str | None = Field(
        default=None,
        max_length=255,
        description="Optional private router IP/hostname. If omitted, the local gateway is detected.",
    )
    timeout_seconds: float = Field(default=1.5, ge=0.2, le=3.0)


class RouterPortStatus(BaseModel):
    port: int
    service: str
    status: str
    latency_ms: float | None = None
    risk: str
    recommendation: str


class RouterHealthSummary(BaseModel):
    risk_score: int
    risk_level: str
    open_ports: int
    checked_ports: int


class RouterHealthScanResponse(BaseModel):
    target: str
    detected_gateway: bool
    scan_policy: str
    summary: RouterHealthSummary
    ports: list[RouterPortStatus]
    findings: list[str]
    recommendations: list[str]
