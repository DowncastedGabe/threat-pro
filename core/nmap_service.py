import ipaddress
import logging
import shutil
from typing import Any

import nmap

logger = logging.getLogger(__name__)


NMAP_ARGUMENTS = "-Pn -T4 --top-ports 20"

from core.utils_security import validar_ip_seguro
 
def _validar_ip(ip: str) -> str:
    return validar_ip_seguro(ip)


def _nmap_instalado() -> bool:
    return shutil.which("nmap") is not None


def escanear_portas(ip: str) -> dict[str, Any]:
    """
    Executa um scan Nmap seguro e limitado.

    Usa:
    - -Pn: não tenta descobrir host antes do scan
    - -T4: velocidade moderada/rápida
    - --top-ports 20: limita a quantidade de portas testadas
    """

    try:
        ip = _validar_ip(ip)

        if not _nmap_instalado():
            return {
                "sucesso": False,
                "erro": "Nmap não está instalado no ambiente",
                "data": {},
            }

        scanner = nmap.PortScanner()
        scanner.scan(
            hosts=ip,
            arguments=NMAP_ARGUMENTS,
            timeout=30
        )

        hosts = {}

        for host in scanner.all_hosts():
            host_data = {
                "estado": scanner[host].state(),
                "protocolos": {},
            }

            for protocolo in scanner[host].all_protocols():
                portas_abertas = []

                portas = sorted(scanner[host][protocolo].keys())

                for porta in portas:
                    info = scanner[host][protocolo][porta]

                    portas_abertas.append({
                        "porta": porta,
                        "estado": info.get("state"),
                        "servico": info.get("name"),
                        "produto": info.get("product"),
                        "versao": info.get("version"),
                        "extra": info.get("extrainfo"),
                    })

                host_data["protocolos"][protocolo] = portas_abertas

            hosts[host] = host_data

        return {
            "sucesso": True,
            "erro": None,
            "data": {
                "ip": ip,
                "argumentos": NMAP_ARGUMENTS,
                "total_hosts": len(hosts),
                "hosts": hosts,
            },
        }

    except nmap.PortScannerError as e:
        logger.exception("Erro do Nmap ao escanear IP %s", ip)
        return {
            "sucesso": False,
            "erro": f"Erro do Nmap: {e}",
            "data": {},
        }

    except Exception as e:
        logger.exception("Erro inesperado ao escanear IP %s", ip)
        return {
            "sucesso": False,
            "erro": str(e),
            "data": {},
        }