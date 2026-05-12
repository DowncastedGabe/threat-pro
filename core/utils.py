"""
core/utils.py — Lógica de comparação de portas (Drift Analysis)

Todas as funções são puras (sem efeitos colaterais) para facilitar testes unitários.
"""

from typing import TypedDict


class PortaInfo(TypedDict):
    porta: int
    protocolo: str
    estado: str
    servico: str | None
    produto: str | None
    versao: str | None


class DiffPortas(TypedDict):
    novas: list[PortaInfo]
    fechadas: list[PortaInfo]
    versoes_mudaram: list[dict]  # {antes: PortaInfo, depois: PortaInfo}
    tem_mudancas: bool


def _normalizar_porta(porta: dict) -> PortaInfo:
    """Garante estrutura uniforme independente da origem (Nmap ou DB)."""
    return PortaInfo(
        porta=int(porta.get("porta", 0)),
        protocolo=str(porta.get("protocolo", "tcp")),
        estado=str(porta.get("estado", "")),
        servico=porta.get("servico") or None,
        produto=porta.get("produto") or None,
        versao=porta.get("versao") or None,
    )


def _chave_porta(p: PortaInfo) -> tuple[int, str]:
    """Chave única: (número da porta, protocolo)."""
    return (p["porta"], p["protocolo"])


def comparar_portas(
    portas_anteriores: list[dict],
    portas_atuais: list[dict],
) -> DiffPortas:
    """
    Compara dois snapshots de portas e retorna as diferenças.

    Args:
        portas_anteriores: Lista de dicts do scan mais antigo.
        portas_atuais:     Lista de dicts do scan mais recente.

    Returns:
        DiffPortas com:
          - novas:           portas abertas que não existiam antes
          - fechadas:        portas que existiam e agora sumiram ou fecharam
          - versoes_mudaram: portas onde produto ou versão mudaram
          - tem_mudancas:    True se qualquer lista não estiver vazia
    """
    anteriores: dict[tuple, PortaInfo] = {
        _chave_porta(p): _normalizar_porta(p)
        for p in portas_anteriores
        if p.get("estado") == "open"
    }
    atuais: dict[tuple, PortaInfo] = {
        _chave_porta(p): _normalizar_porta(p)
        for p in portas_atuais
        if p.get("estado") == "open"
    }

    chaves_anteriores = set(anteriores)
    chaves_atuais = set(atuais)

    novas: list[PortaInfo] = [atuais[k] for k in chaves_atuais - chaves_anteriores]
    fechadas: list[PortaInfo] = [anteriores[k] for k in chaves_anteriores - chaves_atuais]

    versoes_mudaram: list[dict] = []
    for chave in chaves_anteriores & chaves_atuais:
        antes = anteriores[chave]
        depois = atuais[chave]
        if antes["produto"] != depois["produto"] or antes["versao"] != depois["versao"]:
            versoes_mudaram.append({"antes": antes, "depois": depois})

    tem_mudancas = bool(novas or fechadas or versoes_mudaram)

    return DiffPortas(
        novas=novas,
        fechadas=fechadas,
        versoes_mudaram=versoes_mudaram,
        tem_mudancas=tem_mudancas,
    )


def extrair_portas_abertas_do_scan(scan_data: dict) -> list[dict]:
    """
    Extrai a lista flat de portas abertas a partir do dict retornado por escanear_portas().

    Args:
        scan_data: O campo 'data' do retorno de escanear_portas().

    Returns:
        Lista de dicts com porta, estado, servico, produto, versao.
    """
    portas: list[dict] = []
    hosts = scan_data.get("hosts", {})
    for host_data in hosts.values():
        for protocolo, lista in host_data.get("protocolos", {}).items():
            for p in lista:
                portas.append({
                    "porta": p.get("porta"),
                    "protocolo": protocolo,
                    "estado": p.get("estado"),
                    "servico": p.get("servico"),
                    "produto": p.get("produto"),
                    "versao": p.get("versao"),
                })
    return portas