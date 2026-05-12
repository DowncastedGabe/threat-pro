import asyncio
import ipaddress
import re
import socket
import subprocess
import time
from dataclasses import dataclass


SAFE_ROUTER_PORTS: tuple[tuple[int, str], ...] = (
    (80, "HTTP admin"),
    (443, "HTTPS admin"),
    (22, "SSH"),
    (23, "Telnet"),
    (53, "DNS"),
    (7547, "TR-069/CWMP"),
    (8080, "HTTP admin alternativo"),
    (8443, "HTTPS admin alternativo"),
)

PORT_RECOMMENDATIONS = {
    22: "Restrinja SSH a uma rede administrativa ou desative se nao for usado.",
    23: "Desative Telnet. Prefira SSH e credenciais fortes.",
    53: "Garanta que DNS recursivo nao esteja aberto para redes nao confiaveis.",
    7547: "Desative gerenciamento remoto TR-069 se nao for necessario.",
    80: "Prefira painel administrativo via HTTPS e senha forte.",
    443: "Mantenha firmware atualizado e use senha forte.",
    8080: "Evite painel administrativo alternativo exposto sem necessidade.",
    8443: "Verifique certificado, firmware e acesso administrativo restrito.",
}

HIGH_RISK_PORTS = {23, 7547}
MEDIUM_RISK_PORTS = {22, 53, 80, 8080, 8443}


class RouterHealthValidationError(ValueError):
    pass


@dataclass(frozen=True)
class PortCheckResult:
    port: int
    service: str
    status: str
    latency_ms: float | None
    risk: str
    recommendation: str


def detect_default_gateway() -> str | None:
    gateway = _detect_gateway_windows() or _detect_gateway_linux()
    return gateway


def _detect_gateway_windows() -> str | None:
    try:
        output = subprocess.check_output(
            ["ipconfig"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2,
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return None

    gateway_pattern = re.compile(r"(Default Gateway|Gateway Padrao|Gateway Padr.o).*?:\s*([0-9a-fA-F:.]+)?")
    pending_gateway = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = gateway_pattern.search(line)
        if match:
            value = (match.group(2) or "").strip()
            if value and _looks_like_ip(value):
                return value
            pending_gateway = True
            continue

        if pending_gateway and _looks_like_ip(line):
            return line
        pending_gateway = False

    return None


def _detect_gateway_linux() -> str | None:
    try:
        output = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
    except Exception:
        return None

    match = re.search(r"default via\s+([0-9a-fA-F:.]+)", output)
    return match.group(1) if match else None


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
        return True
    except ValueError:
        return False


def validate_private_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise RouterHealthValidationError("Informe um alvo valido.")

    try:
        ip = ipaddress.ip_address(target.split("%", 1)[0])
        if not _is_allowed_router_address(ip):
            raise RouterHealthValidationError("A verificacao aceita apenas IPs privados ou locais.")
        return str(ip)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RouterHealthValidationError("Nao foi possivel resolver o alvo informado.") from exc

    resolved_ips = {info[4][0].split("%", 1)[0] for info in infos}
    if not resolved_ips:
        raise RouterHealthValidationError("Nao foi possivel resolver o alvo informado.")

    for resolved in resolved_ips:
        try:
            ip = ipaddress.ip_address(resolved)
        except ValueError as exc:
            raise RouterHealthValidationError("Resolucao DNS retornou um endereco invalido.") from exc
        if not _is_allowed_router_address(ip):
            raise RouterHealthValidationError("Hostnames so podem resolver para IPs privados ou locais.")

    return target


def _is_allowed_router_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip.is_private or ip.is_loopback or ip.is_link_local


async def scan_router_health(target: str | None, timeout_seconds: float = 1.5) -> dict:
    detected_gateway = False
    if not target:
        gateway = detect_default_gateway()
        if not gateway:
            raise RouterHealthValidationError("Gateway local nao detectado. Informe o IP privado do roteador.")
        target = gateway
        detected_gateway = True

    validated_target = validate_private_target(target)
    timeout = min(max(timeout_seconds, 0.2), 3.0)

    checks = [
        _check_tcp_port(validated_target, port, service, timeout)
        for port, service in SAFE_ROUTER_PORTS
    ]
    port_results = await asyncio.gather(*checks)
    findings, recommendations, risk_score = _summarize(port_results)
    risk_level = _risk_level(risk_score)

    return {
        "target": validated_target,
        "detected_gateway": detected_gateway,
        "scan_policy": "Conexao TCP curta em portas comuns de roteadores; sem autenticacao, brute force ou exploracao.",
        "summary": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "open_ports": sum(1 for item in port_results if item.status == "open"),
            "checked_ports": len(port_results),
        },
        "ports": [item.__dict__ for item in port_results],
        "findings": findings,
        "recommendations": recommendations,
    }


async def _check_tcp_port(target: str, port: int, service: str, timeout: float) -> PortCheckResult:
    started_at = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2)
        return PortCheckResult(
            port=port,
            service=service,
            status="open",
            latency_ms=latency_ms,
            risk=_port_risk(port),
            recommendation=PORT_RECOMMENDATIONS.get(port, "Restrinja o servico se nao for necessario."),
        )
    except (asyncio.TimeoutError, OSError):
        return PortCheckResult(
            port=port,
            service=service,
            status="closed_or_filtered",
            latency_ms=None,
            risk="low",
            recommendation="Sem exposicao TCP detectada nesta porta.",
        )


def _port_risk(port: int) -> str:
    if port in HIGH_RISK_PORTS:
        return "high"
    if port in MEDIUM_RISK_PORTS:
        return "medium"
    return "low"


def _summarize(port_results: list[PortCheckResult]) -> tuple[list[str], list[str], int]:
    findings: list[str] = []
    recommendations: list[str] = []
    risk_score = 0

    for item in port_results:
        if item.status != "open":
            continue
        if item.risk == "high":
            risk_score += 35
        elif item.risk == "medium":
            risk_score += 15
        else:
            risk_score += 5
        findings.append(f"{item.service} acessivel na porta {item.port}.")
        recommendations.append(item.recommendation)

    if not findings:
        findings.append("Nenhuma porta administrativa comum respondeu durante a verificacao.")
        recommendations.append("Mantenha firmware atualizado, WPA2/WPA3 ativo e senha administrativa forte.")

    return findings, sorted(set(recommendations)), min(risk_score, 100)


def _risk_level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"
