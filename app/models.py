from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, IPvAnyAddress
from sqlmodel import SQLModel, Field, Column
from sqlalchemy.dialects.postgresql import JSONB




class AnaliseIP(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ip: str
    risco: str
    score: int = 0
    total_reports: int = 0
    pais: Optional[str] = None
    provedor: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    vulnerabilidades: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    timestamp_auditoria: datetime = Field(default_factory=datetime.utcnow)


class AnaliseSite(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str
    dominio: str = Field(index=True)
    ip_alvo: Optional[str] = Field(default=None, index=True)
    risco_score: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    diretorios_expostos: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    certificados_tls: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    registros_dns: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    infra_health: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    dns_records: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    infra_status: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    headers_seguranca: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    http_fingerprint: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    timestamp_auditoria: datetime = Field(default_factory=datetime.utcnow)


class ScanPorta(SQLModel, table=True):

    id: Optional[int] = Field(default=None, primary_key=True)
    analise_ip_id: int = Field(foreign_key="analiseip.id", index=True)
    porta: int
    protocolo: str = "tcp"
    estado: str
    servico: Optional[str] = None
    produto: Optional[str] = None
    versao: Optional[str] = None


class DriftAnalise(SQLModel, table=True):

    id: Optional[int] = Field(default=None, primary_key=True)
    ip: str = Field(index=True)
    analise_anterior_id: int
    analise_atual_id: int
    portas_novas: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    portas_fechadas: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    versoes_mudaram: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    tem_mudancas: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MonitoramentoAgendado(SQLModel, table=True):

    id: Optional[int] = Field(default=None, primary_key=True)
    ip: str = Field(index=True)
    frequencia_horas: int = Field(default=24, ge=1, le=8760)
    ativo: bool = True
    ultimo_scan: Optional[datetime] = None
    criado_em: datetime = Field(default_factory=datetime.utcnow)


class AnaliseArquivo(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    nome_original: str
    tamanho_bytes: int = 0
    mime_type: Optional[str] = None
    extensao_declarada: Optional[str] = None
    md5: str = Field(index=True)
    sha1: str
    sha256: str = Field(index=True)
    vt_relatorio: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    vt_total_engines: int = 0
    vt_total_detected: int = 0
    vt_status: str = "limpo"
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)


class AnaliseURL(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url_original: str = Field(index=True)
    reputacao_status: str = "desconhecida"
    reputacao_fonte: Optional[str] = None
    reputacao_relatorio: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    redirect_hops: Optional[Any] = Field(default=None, sa_column=Column(JSONB))
    url_final: Optional[str] = None
    content_type_final: Optional[str] = None
    via_tor: bool = False
    tor_erro: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)




class AnaliseRequest(BaseModel):
    ip: IPvAnyAddress


class CveInfo(BaseModel):
    cve_id: str
    cvss: Optional[float] = None
    summary: Optional[str] = None


class ShodanInfo(BaseModel):
    portas: list[int] = []
    cves: list[CveInfo] = []
    banners: list[dict[str, Any]] = []
    org: Optional[str] = None
    isp: Optional[str] = None
    os: Optional[str] = None
    disponivel: bool = True
    erro: Optional[str] = None


class AnaliseResponse(BaseModel):
    resultado: str
    detalhes: str
    score: int
    total_reports: int
    portas_abertas: list[dict[str, Any]] = []
    headers_seguranca: dict[str, Any] | None = None
    geoip: dict[str, Any] | None = None
    drift: dict[str, Any] | None = None
    shodan: ShodanInfo | None = None


class AnaliseIPRead(BaseModel):
    id: int
    ip: str
    risco: str
    score: int
    pais: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    vulnerabilidades: Optional[Any] = None
    timestamp_auditoria: datetime


class ListaAnalisesResponse(BaseModel):
    total: int
    dados: list[AnaliseIPRead]


class SiteRequest(BaseModel):
    url: str


class SiteAnaliseResponse(BaseModel):
    url: str
    dominio: str
    ip_alvo: Optional[str] = None
    risco_score: int
    certificados_tls: dict[str, Any] | None = None
    headers_seguranca: dict[str, Any] | None = None
    registros_dns: dict[str, Any] | None = None
    infra_health: dict[str, Any] | None = None
    dns_records: dict[str, Any] | None = None
    infra_status: dict[str, Any] | None = None
    http_fingerprint: dict[str, Any] | None = None
    diretorios_expostos: dict[str, Any] | None = None


class AnaliseSiteRead(BaseModel):
    id: int
    url: str
    dominio: str
    ip_alvo: Optional[str] = None
    risco_score: int
    diretorios_expostos: Optional[Any] = None
    certificados_tls: Optional[Any] = None
    registros_dns: Optional[Any] = None
    infra_health: Optional[Any] = None
    dns_records: Optional[Any] = None
    infra_status: Optional[Any] = None
    headers_seguranca: Optional[Any] = None
    http_fingerprint: Optional[Any] = None
    timestamp: Optional[datetime] = None
    timestamp_auditoria: datetime


class ListaAnalisesSiteResponse(BaseModel):
    total: int
    pagina: int = 1
    por_pagina: int = 50
    dados: list[AnaliseSiteRead]


class MonitoramentoCreate(BaseModel):
    ip: IPvAnyAddress
    frequencia_horas: int = 24


class MonitoramentoRead(BaseModel):
    id: int
    ip: str
    frequencia_horas: int
    ativo: bool
    ultimo_scan: Optional[datetime] = None
    criado_em: datetime


class DriftRead(BaseModel):
    id: int
    ip: str
    analise_anterior_id: int
    analise_atual_id: int
    portas_novas: list[dict[str, Any]]
    portas_fechadas: list[dict[str, Any]]
    versoes_mudaram: list[dict[str, Any]]
    tem_mudancas: bool
    timestamp: datetime


class GeoMapPoint(BaseModel):
    ip: str
    latitude: float
    longitude: float
    pais: Optional[str] = None
    risco: str
    score: int


class TimelineEvento(BaseModel):
    """Evento de timeline para um IP — usado na visualização histórica."""
    tipo: str          # "scan_manual" | "scan_agendado" | "drift"
    timestamp: datetime
    descricao: str
    tem_alerta: bool = False
    detalhes: Optional[dict[str, Any]] = None


class DorkResult(BaseModel):
    """Resultado individual de uma busca OSINT via Tor."""
    url: str
    titulo: Optional[str] = None
    snippet: Optional[str] = None


class OsintDorkResponse(BaseModel):
    dominio: str
    query: str
    via_tor: bool
    resultados: list[DorkResult]
    erro: Optional[str] = None


class ArquivoScanResponse(BaseModel):
    id: int
    nome_original: str
    tamanho_bytes: int
    mime_type: Optional[str] = None
    extensao_declarada: Optional[str] = None
    md5: str
    sha1: str
    sha256: str
    vt_total_engines: int
    vt_total_detected: int
    vt_status: str
    vt_relatorio: Optional[Any] = None
    timestamp: datetime


class URLScanRequest(BaseModel):
    url: str


class RedirectHop(BaseModel):
    ordem: int
    url: str
    status_code: Optional[int] = None
    location: Optional[str] = None


class URLScanResponse(BaseModel):
    id: int
    url_original: str
    reputacao_status: str
    reputacao_fonte: Optional[str] = None
    reputacao_relatorio: Optional[Any] = None
    redirect_hops: Optional[list[RedirectHop]] = None
    url_final: Optional[str] = None
    content_type_final: Optional[str] = None
    via_tor: bool
    tor_erro: Optional[str] = None
    timestamp: datetime
