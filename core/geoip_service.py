"""
core/geoip_service.py — Serviço de Geolocalização com fallback e TypedDict.

Fluxo:
  1. Tenta ipwho.is (principal)
  2. Se lat/lon vier None ou a requisição falhar → tenta ip-api.com (fallback)
  3. Garante que latitude/longitude nunca sejam None no retorno de sucesso.
"""

import os
import logging
from typing import Any, TypedDict

import ipaddress
import requests

logger = logging.getLogger(__name__)

_GEOIP_URL_PRINCIPAL = os.getenv("GEOIP_URL", "https://ipwho.is/")
_GEOIP_URL_FALLBACK = "http://ip-api.com/json/"
_GEOIP_TIMEOUT = float(os.getenv("GEOIP_TIMEOUT", "8"))


class GeoIPData(TypedDict):
    ip: str
    tipo: str | None
    pais: str | None
    codigo_pais: str | None
    regiao: str | None
    cidade: str | None
    latitude: float | None
    longitude: float | None
    asn: Any
    organizacao: str | None
    isp: str | None
    dominio: str | None
    timezone: str | None


def _validar_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError("IP inválido")


def _consultar_principal(ip: str) -> GeoIPData | None:
    """Consulta ipwho.is. Retorna None se lat/lon não disponíveis ou erro."""
    try:
        resp = requests.get(f"{_GEOIP_URL_PRINCIPAL}{ip}", timeout=_GEOIP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        if not data.get("success", True):
            return None

        lat = data.get("latitude")
        lon = data.get("longitude")
        # Rejeita se coords inválidas (None, 0.0, 0)
        if lat is None or lon is None or (float(lat) == 0.0 and float(lon) == 0.0):
            return None

        connection = data.get("connection") or {}
        timezone = data.get("timezone") or {}

        return GeoIPData(
            ip=ip,
            tipo=data.get("type"),
            pais=data.get("country"),
            codigo_pais=data.get("country_code"),
            regiao=data.get("region"),
            cidade=data.get("city"),
            latitude=float(lat),
            longitude=float(lon),
            asn=connection.get("asn"),
            organizacao=connection.get("org"),
            isp=connection.get("isp"),
            dominio=connection.get("domain"),
            timezone=timezone.get("id"),
        )
    except Exception:
        return None


def _consultar_fallback(ip: str) -> GeoIPData | None:
    """Fallback: ip-api.com (gratuito, sem chave, 45 req/min)."""
    try:
        resp = requests.get(
            f"{_GEOIP_URL_FALLBACK}{ip}",
            params={"fields": "status,country,countryCode,regionName,city,lat,lon,isp,org,as,timezone,query"},
            timeout=_GEOIP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            return None

        lat = data.get("lat")
        lon = data.get("lon")
        if lat is None or lon is None:
            return None

        return GeoIPData(
            ip=ip,
            tipo="IPv4",
            pais=data.get("country"),
            codigo_pais=data.get("countryCode"),
            regiao=data.get("regionName"),
            cidade=data.get("city"),
            latitude=float(lat),
            longitude=float(lon),
            asn=data.get("as"),
            organizacao=data.get("org"),
            isp=data.get("isp"),
            dominio=None,
            timezone=data.get("timezone"),
        )
    except Exception:
        return None


def consultar_geoip(ip: str) -> dict[str, Any]:
    """
    Consulta GeoIP com fallback automático.

    Returns:
        {"sucesso": True, "erro": None, "data": GeoIPData}
        ou
        {"sucesso": False, "erro": str, "data": {}}
    """
    try:
        ip = _validar_ip(ip)
    except ValueError as e:
        return {"sucesso": False, "erro": str(e), "data": {}}

    # 1. Tenta fonte principal
    dados = _consultar_principal(ip)

    # 2. Fallback se necessário
    if dados is None:
        logger.info("GeoIP principal falhou para %s — usando fallback ip-api.com", ip)
        dados = _consultar_fallback(ip)

    if dados is None:
        return {
            "sucesso": False,
            "erro": "Não foi possível obter geolocalização (ambas as fontes falharam)",
            "data": {},
        }

    return {"sucesso": True, "erro": None, "data": dados}