import ipaddress
from urllib.parse import urlparse

_ESQUEMAS_PERMITIDOS = frozenset({"http", "https"})

_FAIXAS_PRIVADAS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def validar_ip_seguro(ip: str) -> str:
    """
    Valida se o IP é válido e não pertence a uma faixa privada ou de loopback.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("IP inválido")

    if addr.is_loopback or addr.is_private or addr.is_link_local:
        raise ValueError(f"IP privado/loopback não permitido: {ip}")
        
    for faixa in _FAIXAS_PRIVADAS:
        if addr in faixa:
            raise ValueError(f"IP em faixa privada não permitido: {ip}")

    return str(addr)

def validar_url_segura(url: str) -> str:
    """
    Normaliza e valida a URL garantindo proteção contra SSRF.

    Raises:
        ValueError: se a URL for inválida, usar esquema proibido ou
                    apontar para um endereço IP privado/loopback (SSRF).
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)

    if parsed.scheme not in _ESQUEMAS_PERMITIDOS:
        raise ValueError(f"Esquema não permitido: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL sem hostname válido.")

    # Bloqueia "localhost" e variações
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Acesso a localhost não permitido.")

    # Bloqueia IPs privados para mitigar SSRF
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_loopback or addr.is_private or addr.is_link_local:
            raise ValueError(f"IP privado/loopback não permitido: {hostname}")
        for faixa in _FAIXAS_PRIVADAS:
            if addr in faixa:
                raise ValueError(f"IP em faixa privada não permitido: {hostname}")
    except ValueError as exc:
        if "não permitido" in str(exc):
            raise

    return url
