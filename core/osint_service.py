import concurrent.futures
import logging
import urllib.parse

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

# Proxy Tor interno ao docker-compose (não é exposto para a máquina host)
PROXIES = {
    "http": "socks5h://tor:9050",
    "https": "socks5h://tor:9050"
}

# Wordlist consolidada baseada em payloads reais, DIRB, e SecLists
WORDLIST_DIRETORIOS = [
    # Painéis Administrativos e CMS
    "/admin/", "/admin.php", "/administrator/", "/wp-admin/", "/wp-login.php",
    "/joomla/", "/login/", "/dashboard/", "/manager/", "/phpmyadmin/",
    # Versionamento e Git
    "/.git/", "/.git/config", "/.svn/", "/.hg/", "/.bzr/",
    # Configurações e Variáveis de Ambiente
    "/.env", "/.env.example", "/.env.backup", "/.env.dev", "/.env.prod",
    "/config.php", "/wp-config.php", "/wp-config.php.bak", "/config.json", "/config.yml",
    # Backups e Dumps de Banco de Dados
    "/backup/", "/backups/", "/db.sql", "/database.sql", "/dump.sql", "/backup.sql",
    "/backup.zip", "/backup.tar.gz", "/archive.zip", "/site.zip",
    # Arquivos de Log e Debug
    "/debug/", "/logs/", "/log/", "/error.log", "/access.log", "/debug.log",
    # Pastas expostas e Infraestrutura
    "/api/", "/swagger-ui.html", "/v1/api-docs", "/server-status", "/.ssh/id_rsa",
    "/robots.txt", "/sitemap.xml", "/.well-known/"
]

def _testar_url(url: str, path: str) -> dict | None:
    """Faz request via Tor para um caminho específico e analisa a resposta."""
    target = urllib.parse.urljoin(url, path)
    try:
        response = requests.get(
            target,
            proxies=PROXIES,
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINT/1.0"}
        )
        
        # O diretório/arquivo existe e está aberto publicamente
        if response.status_code == 200:
            return {
                "path": path,
                "status": 200,
                "url": target,
                "observacao": "Aberto (Conteúdo acessível publicamente)"
            }
            
        # O diretório/arquivo existe, mas bloqueado por ACL
        elif response.status_code in [401, 403]:
            # Damos importância apenas para arquivos que confirmem infraestrutura sensível
            if path in ["/admin/", "/.env", "/wp-admin/", "/.git/", "/.ssh/id_rsa", "/backup/"]:
                return {
                    "path": path,
                    "status": response.status_code,
                    "url": target,
                    "observacao": "Restrito (Existe, mas exige autenticação)"
                }
    except RequestException as e:
        logger.debug("Falha na requisição OSINT %s via Tor: %s", target, e)
    
    return None

def buscar_diretorios_expostos_tor(url: str) -> dict:
    """Executa um bruteforce nos caminhos mais sensíveis usando Threads roteadas pelo Tor."""
    if not url.startswith("http"):
        url = "http://" + url
        
    if not url.endswith("/"):
        url += "/"

    logger.info("Iniciando OSINT bruteforce via Tor para: %s", url)
    resultados = []
    
    # 10 workers é seguro para evitar derrubar o circuito do Tor
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {executor.submit(_testar_url, url, path): path for path in WORDLIST_DIRETORIOS}
        
        for future in concurrent.futures.as_completed(future_to_path):
            res = future.result()
            if res:
                resultados.append(res)
                
    # Ordena os que deram 200 primeiro
    resultados = sorted(resultados, key=lambda x: x["status"])
                
    return {
        "sucesso": True,
        "total_testados": len(WORDLIST_DIRETORIOS),
        "encontrados": len(resultados),
        "data": resultados
    }

def osint_completo_site(dominio: str) -> dict:
    """
    Coordena as duas frentes de OSINT:
    1. Bruteforce direto nos servidores do alvo via Tor.
    2. DuckDuckGo Dorks (intitle:index.of) roteado via Tor.
    """
    from core.tor_service import dorker_duckduckgo
    
    url = f"https://{dominio}"
    
    logger.info("Iniciando bateria OSINT Completa para %s", dominio)
    
    # Fase 1: Força Bruta
    brute_res = buscar_diretorios_expostos_tor(url)
    
    # Fase 2: Dorks
    dorks_res = dorker_duckduckgo(dominio=dominio, usar_tor=True)
    
    return {
        "sucesso": True,
        "data": {
            "bruteforce": brute_res.get("data", []),
            "dorks": dorks_res.get("resultados", []),
            "via_tor": True
        }
    }
