from app.schemas.log_diagnostics import (
    LogDiagnosticEvidence,
    LogDiagnosticFinding,
    LogDiagnosticSummary,
)


class ListLogDiagnosticsUseCase:
    def execute(
        self,
        category: str | None = None,
        severity: str | None = None,
        query: str | None = None,
    ) -> tuple[LogDiagnosticSummary, list[LogDiagnosticFinding]]:
        findings = _build_findings()

        if category:
            findings = [
                finding for finding in findings
                if finding.category.lower() == category.lower()
            ]

        if severity:
            findings = [
                finding for finding in findings
                if finding.severity.lower() == severity.lower()
            ]

        if query:
            normalized_query = query.lower()
            findings = [
                finding for finding in findings
                if normalized_query in " ".join([
                    finding.id,
                    finding.title,
                    finding.category,
                    finding.reason,
                    finding.impact,
                    finding.recommendation,
                ]).lower()
            ]

        return _summarize(findings), findings


def list_categories() -> list[str]:
    return sorted({finding.category for finding in _build_findings()})


def get_finding(finding_id: str) -> LogDiagnosticFinding | None:
    for finding in _build_findings():
        if finding.id == finding_id:
            return finding
    return None


def _summarize(findings: list[LogDiagnosticFinding]) -> LogDiagnosticSummary:
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}

    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1

    return LogDiagnosticSummary(
        total_findings=len(findings),
        by_severity=by_severity,
        by_category=by_category,
        main_causes=[finding.title for finding in findings],
        recommendations=list(dict.fromkeys(
            finding.recommendation for finding in findings
        )),
    )


def _build_findings() -> list[LogDiagnosticFinding]:
    return [
        LogDiagnosticFinding(
            id="ssl-ip-mismatch",
            title="Falha SSL ao consultar HTTPS por IP direto",
            category="security_headers",
            severity="medium",
            status="expected_target_behavior",
            reason=(
                "A rotina de security headers acessa enderecos como "
                "https://169.60.135.76. Certificados TLS normalmente sao "
                "emitidos para hostnames, nao para o IP cru, entao a "
                "validacao acusa IP address mismatch."
            ),
            impact=(
                "A analise de IP termina com sucesso, mas a coleta de "
                "headers HTTPS fica indisponivel para esses alvos."
            ),
            recommendation=(
                "Quando possivel, executar security headers contra o dominio. "
                "Para IP puro, retornar status inconclusivo em vez de tratar "
                "como falha interna da API."
            ),
            related_endpoints=["POST /analisar/", "POST /api/v1/analisar/"],
            evidence=[
                LogDiagnosticEvidence(
                    source="threat-intel-api",
                    sample=(
                        "ERROR [core.security_headers] Erro SSL em "
                        "https://216.150.1.129: certificate verify failed: "
                        "IP address mismatch"
                    ),
                ),
            ],
        ),
        LogDiagnosticFinding(
            id="https-target-timeout",
            title="Timeout ao analisar HTTPS de alvo externo",
            category="network",
            severity="medium",
            status="external_target_unavailable",
            reason=(
                "O alvo nao respondeu dentro do tempo configurado para a "
                "conexao HTTPS na porta 443."
            ),
            impact=(
                "A API conclui a analise, mas nao consegue obter headers "
                "de seguranca daquele host."
            ),
            recommendation=(
                "Separar no retorno da API erro interno de alvo sem resposta "
                "e permitir ajuste de timeout quando necessario."
            ),
            related_endpoints=["POST /analisar/", "POST /api/v1/analisar/"],
            evidence=[
                LogDiagnosticEvidence(
                    source="threat-intel-api",
                    sample=(
                        "ERROR [core.security_headers] Timeout ao analisar "
                        "https://161.148.50.192"
                    ),
                ),
            ],
        ),
        LogDiagnosticFinding(
            id="shodan-no-data",
            title="Shodan sem dados para IP consultado",
            category="shodan",
            severity="low",
            status="external_provider_no_data",
            reason=(
                "O Shodan respondeu que nao havia informacoes disponiveis "
                "para o IP consultado."
            ),
            impact=(
                "A analise segue sem enriquecimento de portas, banners ou "
                "CVEs vindos do Shodan para esse IP."
            ),
            recommendation=(
                "Exibir como 'sem dados no Shodan' no frontend e nao como "
                "erro operacional."
            ),
            related_endpoints=["POST /analisar/", "POST /api/v1/analisar/"],
            evidence=[
                LogDiagnosticEvidence(
                    source="threat-intel-api",
                    sample=(
                        "WARNING [core.shodan_service] [Shodan] Erro para "
                        "161.148.50.192: No information available for that IP."
                    ),
                ),
            ],
        ),
        LogDiagnosticFinding(
            id="auth-validation-errors",
            title="Requisicoes recusadas por autenticacao ou payload invalido",
            category="auth_validation",
            severity="low",
            status="handled_client_error",
            reason=(
                "As logs mostram respostas 400 e 401 em login, refresh token, "
                "router health e disk mapping. Isso indica token ausente, "
                "credencial incorreta, token expirado/reutilizado ou payload "
                "fora da validacao do endpoint."
            ),
            impact=(
                "Nao ha sinal de queda do backend, mas o usuario pode perceber "
                "a resposta como erro generico se o frontend nao detalhar."
            ),
            recommendation=(
                "Melhorar mensagens no frontend para diferenciar sessao "
                "expirada, senha incorreta, alvo invalido e caminho de disco "
                "invalido."
            ),
            related_endpoints=[
                "POST /api/v1/auth/login",
                "POST /api/v1/auth/refresh",
                "POST /api/v1/router-health/scan",
                "POST /api/v1/disk-mapping/scan",
            ],
            evidence=[
                LogDiagnosticEvidence(
                    source="threat-intel-api",
                    sample='POST /api/v1/router-health/scan HTTP/1.1" 401 Unauthorized',
                ),
                LogDiagnosticEvidence(
                    source="threat-intel-api",
                    sample='POST /api/v1/auth/login HTTP/1.1" 400 Bad Request',
                ),
            ],
        ),
        LogDiagnosticFinding(
            id="postgres-container-restarts",
            title="Postgres recuperou apos reinicios de container",
            category="database",
            severity="medium",
            status="recovered",
            reason=(
                "O banco recebeu shutdowns administrativos e, em alguns "
                "momentos, iniciou recuperacao automatica de WAL apos "
                "encerramento nao limpo."
            ),
            impact=(
                "O banco voltou a aceitar conexoes. As linhas analisadas nao "
                "indicam corrupcao persistente, mas reinicios frequentes podem "
                "interromper requisicoes em andamento."
            ),
            recommendation=(
                "Usar docker compose down para paradas manuais e investigar "
                "Docker Desktop, WSL ou energia se os reinicios nao foram "
                "intencionais."
            ),
            related_endpoints=[],
            evidence=[
                LogDiagnosticEvidence(
                    source="threat-intel-db",
                    sample="LOG: database system was not properly shut down; automatic recovery in progress",
                ),
                LogDiagnosticEvidence(
                    source="threat-intel-db",
                    sample="FATAL: terminating connection due to administrator command",
                ),
            ],
        ),
        LogDiagnosticFinding(
            id="tor-outdated-open-listeners",
            title="Tor antigo e listeners em endereco amplo",
            category="tor",
            severity="medium",
            status="operational_with_warnings",
            reason=(
                "A imagem atual usa Tor 0.4.3.5 e registra avisos de protocolo "
                "desatualizado. Tambem avisa sobre SocksPort/TransPort em "
                "0.0.0.0, embora no docker-compose a porta nao esteja publicada "
                "para fora do host."
            ),
            impact=(
                "O Tor sobe e chega a Bootstrapped 100%, mas pode perder "
                "compatibilidade no futuro e gerar instabilidade em OSINT."
            ),
            recommendation=(
                "Atualizar a imagem Tor e restringir listeners ao escopo "
                "necessario dentro da rede Docker."
            ),
            related_endpoints=["GET /osint/tor-status/", "GET /api/v1/osint/tor-status/"],
            evidence=[
                LogDiagnosticEvidence(
                    source="threat-intel-tor",
                    sample="At least one protocol listed as recommended in the consensus is not supported",
                ),
                LogDiagnosticEvidence(
                    source="threat-intel-tor",
                    sample="You specified a public address '0.0.0.0:9050' for SocksPort",
                ),
            ],
        ),
        LogDiagnosticFinding(
            id="oracle-dns-large-txt-timeout",
            title="DNS Oracle com respostas TXT grandes",
            category="dns",
            severity="medium",
            status="fixed_in_code",
            reason=(
                "Consultas como oracle.com podem retornar muitos registros TXT. "
                "Em UDP, respostas grandes podem fragmentar ou estourar timeout "
                "em alguns resolvedores."
            ),
            impact=(
                "Antes da correcao, um timeout em um tipo de registro podia "
                "zerar toda a resposta DNS do endpoint de analise de site."
            ),
            recommendation=(
                "Manter retry via TCP e continuar retornando erros por tipo de "
                "registro para preservar resultados parciais."
            ),
            related_endpoints=["POST /analisar-site/", "POST /api/v1/analisar-site/"],
            evidence=[
                LogDiagnosticEvidence(
                    source="core.dns_service",
                    sample="oracle.com retornou A/MX/TXT apos retry via TCP",
                ),
            ],
        ),
    ]

