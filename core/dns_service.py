import os
import logging
import asyncio
import ipaddress
import re
import time
from typing import Any
from urllib.parse import urlparse

import dns.resolver

logger = logging.getLogger(__name__)

_DNS_LIFETIME = float(os.getenv("DNS_LIFETIME", "5"))
_DNS_NAMESERVERS = [
    servidor.strip()
    for servidor in os.getenv("DNS_NAMESERVERS", "").split(",")
    if servidor.strip()
]
_DNS_RECORDS  = [
    tipo.strip().upper()
    for tipo in os.getenv("DNS_RECORDS", "A,AAAA,MX,TXT,CNAME").split(",")
    if tipo.strip()
]
_SPF_TIMEOUT = float(os.getenv("SPF_HEALTH_TIMEOUT", "3"))
_SPF_HEALTH_PORTS = (443, 80)
_SPF_SERVICE_NAMES = {
    "include:sendgrid.net": "SendGrid",
    "include:_spf.google.com": "Google Workspace",
    "include:spf.protection.outlook.com": "Microsoft 365",
    "include:mail.zendesk.com": "Zendesk",
    "include:_spf.zendesk.com": "Zendesk",
}

_SPF_IP4_RE = re.compile(r"(?i)(?:^|\s)ip4:([^\s]+)")
_SPF_IP6_RE = re.compile(r"(?i)(?:^|\s)ip6:([^\s]+)")
_SPF_INCLUDE_RE = re.compile(r"(?i)(?:^|\s)include:([^\s]+)")


def _extrair_dominio(url_ou_dominio: str) -> str:
    valor = url_ou_dominio.strip()
    if not valor.startswith(("http://", "https://")):
        valor = f"https://{valor}"
    parsed = urlparse(valor)
    if not parsed.hostname:
        raise ValueError("Domínio ou URL inválida")
    return parsed.hostname


def _resolver_padrao() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    if _DNS_NAMESERVERS:
        resolver.nameservers = _DNS_NAMESERVERS
    return resolver


def _resolver_registro(dominio: str, tipo: str) -> list[str]:
    try:
        resolver = _resolver_padrao()
        try:
            respostas = resolver.resolve(dominio, tipo, lifetime=_DNS_LIFETIME)
        except dns.exception.Timeout:
            # Alguns dominios, como oracle.com, podem ter respostas TXT grandes.
            # Repetir via TCP evita perda por fragmentacao/timeout em UDP.
            respostas = resolver.resolve(dominio, tipo, lifetime=_DNS_LIFETIME, tcp=True)

        if tipo == "MX":
            return [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in respostas]
        if tipo == "TXT":
            return ["".join(p.decode("utf-8", errors="ignore") for p in r.strings) for r in respostas]
        return [r.to_text().rstrip(".") for r in respostas]

    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        raise ValueError("Domínio não existe")
    except dns.exception.Timeout:
        raise TimeoutError("Timeout ao consultar DNS")
    except Exception as e:
        logger.warning("Erro ao consultar %s para %s: %s", tipo, dominio, e)
        return []


def consultar_dns(url_ou_dominio: str) -> dict[str, Any]:
    try:
        dominio   = _extrair_dominio(url_ou_dominio)
        registros: dict[str, list[str]] = {}
        erros: dict[str, str] = {}

        for tipo in _DNS_RECORDS:
            try:
                registros[tipo.lower()] = _resolver_registro(dominio, tipo)
            except ValueError:
                raise
            except Exception as e:
                logger.warning("Falha ao consultar %s para %s: %s", tipo, dominio, e)
                registros[tipo.lower()] = []
                erros[tipo.lower()] = str(e)

        data: dict[str, Any] = {"dominio": dominio, "registros": registros}
        if erros:
            data["erros"] = erros
        return {"sucesso": True, "erro": None, "data": data}
    except Exception as e:
        logger.exception("Erro ao consultar DNS")
        return {"sucesso": False, "erro": str(e), "data": {}}


def _detectar_servico(mecanismo: str, valor: str) -> str | None:
    chave = f"{mecanismo}:{valor}".lower()
    if chave in _SPF_SERVICE_NAMES:
        return _SPF_SERVICE_NAMES[chave]

    valor_lower = valor.lower()
    if "sendgrid.net" in valor_lower:
        return "SendGrid"
    if "google.com" in valor_lower or "googlemail.com" in valor_lower:
        return "Google Workspace"
    if "zendesk.com" in valor_lower:
        return "Zendesk"
    if "protection.outlook.com" in valor_lower:
        return "Microsoft 365"
    return None


def extrair_spf(url_ou_dominio: str) -> dict[str, Any]:
    """
    Consulta registros TXT SPF e extrai mecanismos ip4, ip6 e include.
    CIDRs sao preservados como alvos, mas nao expandidos para evitar varredura.
    """
    dominio = _extrair_dominio(url_ou_dominio)
    txt_records = _resolver_registro(dominio, "TXT")
    spf_records = [txt for txt in txt_records if txt.lower().startswith("v=spf1")]

    alvos: list[dict[str, Any]] = []
    vistos: set[tuple[str, str]] = set()

    for spf in spf_records:
        matches = [
            ("ip4", valor) for valor in _SPF_IP4_RE.findall(spf)
        ] + [
            ("ip6", valor) for valor in _SPF_IP6_RE.findall(spf)
        ] + [
            ("include", valor.rstrip(".")) for valor in _SPF_INCLUDE_RE.findall(spf)
        ]

        for tipo, valor in matches:
            chave = (tipo, valor.lower())
            if chave in vistos:
                continue
            vistos.add(chave)

            alvos.append({
                "tipo": tipo,
                "valor": valor,
                "servico": _detectar_servico(tipo, valor),
                "spf_record": spf,
            })

    return {
        "dominio": dominio,
        "spf_records": spf_records,
        "alvos": alvos,
    }


def _eh_cidr(valor: str) -> bool:
    try:
        ipaddress.ip_network(valor, strict=False)
        return "/" in valor
    except ValueError:
        return False


def _ip_publico_permitido(valor: str) -> bool:
    try:
        ip = ipaddress.ip_address(valor)
    except ValueError:
        return False
    return ip.is_global


def _resolver_hosts_publicos(host: str) -> list[str]:
    try:
        ip = ipaddress.ip_address(host)
        return [host] if ip.is_global else []
    except ValueError:
        pass

    enderecos: list[str] = []
    for tipo in ("A", "AAAA"):
        for registro in _resolver_registro(host, tipo):
            if _ip_publico_permitido(registro):
                enderecos.append(registro)
    return list(dict.fromkeys(enderecos))


async def _testar_conexao_tcp(host: str, porta: int, timeout: float) -> tuple[bool, float | None, str | None]:
    inicio = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=porta),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)
        return True, latencia_ms, None
    except Exception as exc:
        return False, None, exc.__class__.__name__


async def _verificar_alvo_spf(alvo: dict[str, Any], timeout: float) -> dict[str, Any]:
    valor = alvo["valor"]

    if _eh_cidr(valor):
        return {
            **alvo,
            "status": "Inconclusivo",
            "latencia_ms": None,
            "porta": None,
            "erro": "CIDR SPF preservado sem varredura de faixa",
        }

    hosts_publicos = await asyncio.to_thread(_resolver_hosts_publicos, valor)
    if not hosts_publicos:
        return {
            **alvo,
            "status": "Inconclusivo",
            "latencia_ms": None,
            "porta": None,
            "erro": "Sem IP publico autorizado para conexao segura",
        }

    testes = [
        _testar_conexao_tcp(host, porta, timeout)
        for host in hosts_publicos
        for porta in _SPF_HEALTH_PORTS
    ]
    resultados = await asyncio.gather(*testes)

    pares = [
        (host, porta)
        for host in hosts_publicos
        for porta in _SPF_HEALTH_PORTS
    ]

    for (host, porta), (online, latencia_ms, erro) in zip(pares, resultados):
        if online:
            return {
                **alvo,
                "status": "Online",
                "ip_testado": host,
                "latencia_ms": latencia_ms,
                "porta": porta,
                "erro": None,
            }

    erros = [erro for _, _, erro in resultados if erro]
    return {
        **alvo,
        "status": "Offline",
        "latencia_ms": None,
        "porta": None,
        "erro": ", ".join(sorted(set(erros))) if erros else "Sem resposta TCP",
    }


async def consultar_infra_health(url_ou_dominio: str, timeout: float = _SPF_TIMEOUT) -> dict[str, Any]:
    """
    Executa o Infra Health Check a partir do SPF do dominio.
    A checagem limita-se a conexoes TCP 443/80 com timeout curto.
    """
    try:
        spf = extrair_spf(url_ou_dominio)
        alvos = spf["alvos"]
        resultados = await asyncio.gather(
            *[_verificar_alvo_spf(alvo, timeout=timeout) for alvo in alvos]
        ) if alvos else []

        return {
            "sucesso": True,
            "erro": None,
            "data": {
                "dominio": spf["dominio"],
                "spf_records": spf["spf_records"],
                "timeout_s": timeout,
                "portas_testadas": list(_SPF_HEALTH_PORTS),
                "itens": resultados,
            },
        }
    except Exception as e:
        logger.exception("Erro no Infra Health Check")
        return {"sucesso": False, "erro": str(e), "data": {}}
