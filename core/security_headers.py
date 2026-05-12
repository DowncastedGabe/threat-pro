import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse
from core.utils_security import validar_url_segura
 
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
 
logger = logging.getLogger(__name__)
 

def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "")
    if raw.strip().isdigit():
        return int(raw.strip())
    return default
 
 
@dataclass(frozen=True)
class Config:
    timeout: int = field(default_factory=lambda: _env_int("SECURITY_HEADERS_TIMEOUT", 10))
    user_agent: str = field(
        default_factory=lambda: os.getenv(
            "SECURITY_HEADERS_USER_AGENT", "SecurityHeadersAnalyzer/1.0"
        )
    )
    score_bom: float = field(
        default_factory=lambda: float(os.getenv("SECURITY_HEADERS_SCORE_BOM", "80"))
    )
    score_medio: float = field(
        default_factory=lambda: float(os.getenv("SECURITY_HEADERS_SCORE_MEDIO", "50"))
    )
    max_redirects: int = field(
        default_factory=lambda: _env_int("SECURITY_HEADERS_MAX_REDIRECTS", 5)
    )
 
 
CONFIG = Config()

@dataclass(frozen=True)
class HeaderSpec:
    nome: str
    peso: int
    descricao: str

HEADERS_AVALIADOS: dict[str, HeaderSpec] = {
    "strict-transport-security": HeaderSpec(
        nome="Strict-Transport-Security",
        peso=20,
        descricao="Força o uso de HTTPS em conexões futuras.",
    ),
    "content-security-policy": HeaderSpec(
        nome="Content-Security-Policy",
        peso=25,
        descricao="Ajuda a mitigar XSS e injeção de conteúdo.",
    ),
    "x-frame-options": HeaderSpec(
        nome="X-Frame-Options",
        peso=15,
        descricao="Protege contra clickjacking.",
    ),
    "x-content-type-options": HeaderSpec(
        nome="X-Content-Type-Options",
        peso=10,
        descricao="Evita MIME sniffing.",
    ),
    "referrer-policy": HeaderSpec(
        nome="Referrer-Policy",
        peso=10,
        descricao="Controla envio de informações de referência.",
    ),
    "permissions-policy": HeaderSpec(
        nome="Permissions-Policy",
        peso=10,
        descricao="Limita acesso a recursos do navegador.",
    ),
    "cross-origin-opener-policy": HeaderSpec(
        nome="Cross-Origin-Opener-Policy",
        peso=5,
        descricao="Ajuda a isolar contexto de navegação.",
    ),
    "cross-origin-resource-policy": HeaderSpec(
        nome="Cross-Origin-Resource-Policy",
        peso=5,
        descricao="Controla carregamento cross-origin de recursos.",
    ),
}
 
_PESO_TOTAL = sum(spec.peso for spec in HEADERS_AVALIADOS.values())
assert _PESO_TOTAL == 100, f"Pesos devem somar 100, mas somam {_PESO_TOTAL}"


 
def _criar_sessao(config: Config) -> requests.Session:
    session = requests.Session()
    session.max_redirects = config.max_redirects
    session.headers.update({"User-Agent": config.user_agent})
 
    retry = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist={500, 502, 503, 504},
        allowed_methods={"GET"},
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
 
    return session
 
def _classificar(score: float, config: Config) -> str:
    if score >= config.score_bom:
        return "bom"
    if score >= config.score_medio:
        return "medio"
    return "fraco"
 
 
def _avaliar_headers(
    headers: dict[str, str],
) -> tuple[list[dict], list[dict], float]:
    """
    Retorna (encontrados, ausentes, score_percentual).
    """
    encontrados: list[dict] = []
    ausentes: list[dict] = []
    score = 0
 
    for chave, spec in HEADERS_AVALIADOS.items():
        if chave in headers:
            score += spec.peso
            encontrados.append(
                {
                    "header": spec.nome,
                    "valor": headers[chave],
                    "peso": spec.peso,
                    "descricao": spec.descricao,
                }
            )
        else:
            ausentes.append(
                {
                    "header": spec.nome,
                    "peso": spec.peso,
                    "descricao": spec.descricao,
                }
            )
 
    score_percentual = round((score / _PESO_TOTAL) * 100, 2)
    return encontrados, ausentes, score_percentual

def analisar_headers_seguranca(
    url: str,
    *,
    config: Config = CONFIG,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """
    Analisa os headers HTTP de segurança de uma URL.
 
    Args:
        url:     Endereço a ser analisado.
        config:  Instância de Config (usa CONFIG global por padrão).
        session: Sessão requests reutilizável (cria uma nova se None).
 
    Returns:
        Dicionário com chaves ``sucesso``, ``erro`` e ``data``.
    """
    _session = session or _criar_sessao(config)
 
    try:
        url = validar_url_segura(url)
    except ValueError as exc:
        return {"sucesso": False, "erro": str(exc), "data": {}}
 
    try:
        response = _session.get(url, timeout=config.timeout, allow_redirects=True)
    except requests.exceptions.TooManyRedirects:
        logger.warning("Muitos redirecionamentos para %s", url)
        return {
            "sucesso": False,
            "erro": "Muitos redirecionamentos.",
            "data": {},
        }
    except requests.exceptions.Timeout:
        logger.error("Timeout ao analisar %s", url)
        return {
            "sucesso": False,
            "erro": "Timeout ao conectar com o servidor.",
            "data": {},
        }
    except requests.exceptions.SSLError as exc:
        logger.error("Erro SSL em %s: %s", url, exc)
        return {
            "sucesso": False,
            "erro": "Erro de certificado SSL.",
            "data": {},
        }
    except requests.exceptions.RequestException as exc:
        logger.error("Erro de conexão em %s: %s", url, exc)
        return {
            "sucesso": False,
            "erro": "Erro de conexão com o servidor.",
            "data": {},
        }
 
    headers_normalizados = {k.lower(): v for k, v in response.headers.items()}
    encontrados, ausentes, score = _avaliar_headers(headers_normalizados)
 
    return {
        "sucesso": True,
        "erro": None,
        "data": {
            "url": url,
            "status_code": response.status_code,
            "url_final": response.url,
            "score_http": score,
            "classificacao": _classificar(score, config),
            "headers_encontrados": encontrados,
            "headers_ausentes": ausentes,
            "headers_raw": dict(response.headers),
        },
    }