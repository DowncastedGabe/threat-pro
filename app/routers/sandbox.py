import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Security, UploadFile
from sqlmodel import Session, select

from app.dependencies import validar_api_key
from app.models import (
    AnaliseArquivo,
    AnaliseURL,
    ArquivoScanResponse,
    RedirectHop,
    URLScanRequest,
    URLScanResponse,
)
from core.session import get_session
from core.virustotal_service import consultar_hash_virustotal
from core.url_reputation_service import verificar_reputacao_url
from core.tor_redirect_service import rastrear_redirects_tor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox", tags=["Sandbox"])

_MAX_FILE_SIZE = 32 * 1024 * 1024


def _gerar_hashes(conteudo: bytes) -> dict:
    return {
        "md5":    hashlib.md5(conteudo).hexdigest(),
        "sha1":   hashlib.sha1(conteudo).hexdigest(),
        "sha256": hashlib.sha256(conteudo).hexdigest(),
    }


def _detectar_mime(conteudo: bytes) -> Optional[str]:
    try:
        import magic
        return magic.from_buffer(conteudo, mime=True)
    except ImportError:
        logger.warning("python-magic não instalado — MIME type não detectado.")
        return None
    except Exception as exc:
        logger.warning("Falha ao detectar MIME type: %s", exc)
        return None


@router.post("/arquivo/", response_model=ArquivoScanResponse)
async def analisar_arquivo(
    file: UploadFile = File(...),
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    conteudo = await file.read()

    if not conteudo:
        raise HTTPException(status_code=400, detail="Arquivo vazio.")
    if len(conteudo) > _MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Arquivo muito grande. Limite: {_MAX_FILE_SIZE // 1024 // 1024} MB.",
        )

    nome_original      = file.filename or "desconhecido"
    extensao_declarada = os.path.splitext(nome_original)[1].lower() or None
    hashes             = _gerar_hashes(conteudo)
    mime_type          = _detectar_mime(conteudo)

    logger.info("Arquivo recebido: %s | SHA-256: %s | MIME: %s",
                nome_original, hashes["sha256"], mime_type)

    vt = consultar_hash_virustotal(hashes["sha256"])
    if vt.get("status") == "nao_analisado" and vt.get("sucesso"):
        vt = consultar_hash_virustotal(hashes["md5"])

    analise = AnaliseArquivo(
        nome_original=nome_original,
        tamanho_bytes=len(conteudo),
        mime_type=mime_type,
        extensao_declarada=extensao_declarada,
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        vt_relatorio=vt.get("relatorio"),
        vt_total_engines=vt.get("total_engines", 0),
        vt_total_detected=vt.get("total_detected", 0),
        vt_status=vt.get("status", "nao_analisado"),
        timestamp=datetime.now(tz=timezone.utc),
    )
    session.add(analise)
    session.commit()
    session.refresh(analise)

    logger.info("Scan concluído: %s — %s (%d/%d engines)",
                nome_original, analise.vt_status,
                analise.vt_total_detected, analise.vt_total_engines)

    return ArquivoScanResponse(
        id=analise.id,
        nome_original=analise.nome_original,
        tamanho_bytes=analise.tamanho_bytes,
        mime_type=analise.mime_type,
        extensao_declarada=analise.extensao_declarada,
        md5=analise.md5,
        sha1=analise.sha1,
        sha256=analise.sha256,
        vt_total_engines=analise.vt_total_engines,
        vt_total_detected=analise.vt_total_detected,
        vt_status=analise.vt_status,
        vt_relatorio=analise.vt_relatorio,
        timestamp=analise.timestamp,
    )


@router.get("/arquivos/", response_model=list[ArquivoScanResponse])
async def listar_analises_arquivo(
    limite: int = 50,
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    analises = session.exec(
        select(AnaliseArquivo).order_by(AnaliseArquivo.timestamp.desc()).limit(limite)
    ).all()
    return [
        ArquivoScanResponse(
            id=a.id, nome_original=a.nome_original, tamanho_bytes=a.tamanho_bytes,
            mime_type=a.mime_type, extensao_declarada=a.extensao_declarada,
            md5=a.md5, sha1=a.sha1, sha256=a.sha256,
            vt_total_engines=a.vt_total_engines, vt_total_detected=a.vt_total_detected,
            vt_status=a.vt_status, vt_relatorio=a.vt_relatorio, timestamp=a.timestamp,
        )
        for a in analises
    ]


@router.post("/url/", response_model=URLScanResponse)
async def analisar_url(
    dados: URLScanRequest,
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    url = dados.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL deve começar com http:// ou https://")

    logger.info("Análise de URL iniciada: %s", url)

    rep      = verificar_reputacao_url(url)
    redirect = rastrear_redirects_tor(url)

    hops = [
        RedirectHop(
            ordem=h["ordem"], url=h["url"],
            status_code=h.get("status_code"), location=h.get("location"),
        )
        for h in redirect.get("hops", [])
    ]

    analise = AnaliseURL(
        url_original=url,
        reputacao_status=rep.get("status", "desconhecida"),
        reputacao_fonte=rep.get("fonte"),
        reputacao_relatorio=rep.get("relatorio"),
        redirect_hops=[h.model_dump() for h in hops],
        url_final=redirect.get("url_final"),
        content_type_final=redirect.get("content_type"),
        via_tor=redirect.get("via_tor", False),
        tor_erro=redirect.get("erro"),
        timestamp=datetime.now(tz=timezone.utc),
    )
    session.add(analise)
    session.commit()
    session.refresh(analise)

    logger.info("Scan de URL concluído: %s — %s | hops: %d | tor: %s",
                url, analise.reputacao_status, len(hops), analise.via_tor)

    return URLScanResponse(
        id=analise.id,
        url_original=analise.url_original,
        reputacao_status=analise.reputacao_status,
        reputacao_fonte=analise.reputacao_fonte,
        reputacao_relatorio=analise.reputacao_relatorio,
        redirect_hops=hops,
        url_final=analise.url_final,
        content_type_final=analise.content_type_final,
        via_tor=analise.via_tor,
        tor_erro=analise.tor_erro,
        timestamp=analise.timestamp,
    )


@router.get("/urls/", response_model=list[URLScanResponse])
async def listar_analises_url(
    limite: int = 50,
    api_key: str = Security(validar_api_key),
    session: Session = Depends(get_session),
):
    analises = session.exec(
        select(AnaliseURL).order_by(AnaliseURL.timestamp.desc()).limit(limite)
    ).all()
    return [
        URLScanResponse(
            id=a.id, url_original=a.url_original,
            reputacao_status=a.reputacao_status, reputacao_fonte=a.reputacao_fonte,
            reputacao_relatorio=a.reputacao_relatorio,
            redirect_hops=[RedirectHop(**h) for h in (a.redirect_hops or [])],
            url_final=a.url_final, content_type_final=a.content_type_final,
            via_tor=a.via_tor, tor_erro=a.tor_erro, timestamp=a.timestamp,
        )
        for a in analises
    ]
