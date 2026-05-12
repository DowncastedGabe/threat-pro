import os
import socket
import ssl
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_PORTA_PADRAO = int(os.getenv("TLS_PORTA_PADRAO", "443"))
_TIMEOUT_PADRAO = int(os.getenv("TLS_TIMEOUT", "10"))
_FORMATO_DATA = os.getenv("TLS_FORMATO_DATA", "%b %d %H:%M:%S %Y %Z")

from core.utils_security import validar_url_segura

def _extrair_hostname(url_ou_dominio: str) -> str:
    url_segura = validar_url_segura(url_ou_dominio)
    parsed = urlparse(url_segura)
    
    if not parsed.hostname:
        raise ValueError("Domínio ou URL inválida")

    return parsed.hostname


def _validar_porta(porta: int) -> int:
    porta = int(porta)

    if porta < 1 or porta > 65535:
        raise ValueError("Porta inválida")

    return porta


def _parsear_certificado(cert: dict) -> dict[str, Any]:
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")

    if not not_before or not not_after:
        raise ValueError("Certificado sem datas de validade")

    def parse_dt(s: str) -> datetime:
        return datetime.strptime(s, _FORMATO_DATA).replace(tzinfo=timezone.utc)

    inicio = parse_dt(not_before)
    expiracao = parse_dt(not_after)
    agora = datetime.now(timezone.utc)
    expirado = expiracao < agora

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))

    return {
        "valido": not expirado,
        "expirado": expirado,
        "dias_restantes": (expiracao - agora).days,
        "emitido_em": inicio.isoformat(),
        "expira_em": expiracao.isoformat(),
        "emissor": issuer,
        "sujeito": subject,
        "common_name": subject.get("commonName"),
        "issuer_common_name": issuer.get("commonName"),
        "san": cert.get("subjectAltName", []),
    }


def _erro(msg: str) -> dict[str, Any]:
    return {
        "sucesso": False,
        "erro": msg,
        "data": {}
    }


def analisar_tls_ssl(
    url_ou_dominio: str,
    porta: int = _PORTA_PADRAO,
    timeout: int = _TIMEOUT_PADRAO,
) -> dict[str, Any]:
    try:
        hostname = _extrair_hostname(url_ou_dominio)
        porta = _validar_porta(porta)

        ctx = ssl.create_default_context()

        with socket.create_connection((hostname, porta), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        return {
            "sucesso": True,
            "erro": None,
            "data": {
                "hostname": hostname,
                "porta": porta,
                **_parsear_certificado(cert),
            },
        }

    except ValueError as e:
        return _erro(str(e))

    except ssl.SSLCertVerificationError as e:
        logger.error("Erro de verificação SSL em %s: %s", url_ou_dominio, e)
        return _erro("Certificado SSL inválido ou não confiável")

    except socket.gaierror as e:
        logger.error("Erro de DNS em %s: %s", url_ou_dominio, e)
        return _erro("Não foi possível resolver o domínio")

    except ConnectionRefusedError:
        return _erro("Conexão recusada pelo host")

    except socket.timeout:
        return _erro("Timeout ao conectar no host")

    except OSError as e:
        logger.error("Erro de conexão TLS em %s: %s", url_ou_dominio, e)
        return _erro("Erro de conexão com o host")

    except Exception:
        logger.exception("Erro ao analisar TLS/SSL")
        return _erro("Erro inesperado ao analisar TLS/SSL")