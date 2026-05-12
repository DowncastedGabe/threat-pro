from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import mimetypes
import re
import socket
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from fastapi import UploadFile

from app.core.config.settings import settings


class IngestionValidationError(ValueError):
    pass


@dataclass(frozen=True)
class IngestedDocument:
    source_type: str
    source_name: str
    content_type: str | None
    size_bytes: int
    sha256: str
    buffer: bytes
    stored_path: Path | None = None
    text: str = ""
    warnings: tuple[str, ...] = ()

    def to_response(self, include_buffer_base64: bool = False) -> dict:
        return {
            "source_type": self.source_type,
            "source_name": self.source_name,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "stored_path": str(self.stored_path) if self.stored_path else None,
            "text": self.text,
            "warnings": list(self.warnings),
            "buffer_base64": base64.b64encode(self.buffer).decode("ascii") if include_buffer_base64 else None,
        }


class IngestionEngine:
    allowed_extensions = {".pdf", ".txt", ".log", ".json", ".md", ".markdown"}
    allowed_schemes = {"http", "https"}
    max_redirects = 5

    def __init__(
        self,
        temp_dir: str | Path | None = None,
        max_bytes: int | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        self.temp_dir = Path(temp_dir or settings.ingestion_temp_dir).expanduser().resolve()
        self.max_bytes = max_bytes or settings.ingestion_max_bytes
        self.timeout_seconds = timeout_seconds or settings.ingestion_timeout_seconds
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def fetch_url(self, url: str, extract_text: bool = True) -> IngestedDocument:
        current_url = self._validate_safe_url(url)
        response = None

        for _ in range(self.max_redirects + 1):
            response = self._download_once(current_url)
            if not response.is_redirect:
                break

            location = response.headers.get("Location")
            if not location:
                raise IngestionValidationError("Redirecionamento sem cabecalho Location.")
            current_url = self._validate_safe_url(urljoin(current_url, location))
        else:
            raise IngestionValidationError("Limite de redirecionamentos excedido.")

        if response is None:
            raise IngestionValidationError("Nao foi possivel baixar a URL.")

        content_type = response.headers.get("Content-Type", "").split(";", 1)[0] or None
        filename = Path(urlparse(current_url).path).name or "download"
        buffer = self._read_limited_response(response)
        text, warnings = self.extract_text(buffer, content_type=content_type, filename=filename) if extract_text else ("", [])

        # Proximo estagio: envie `text`, `sha256`, `source_name` e metadados para o motor
        # de Analise de Ameacas. O `buffer` deve ser repassado apenas quando a etapa
        # seguinte precisar reprocessar o artefato bruto em ambiente isolado.
        return IngestedDocument(
            source_type="url",
            source_name=current_url,
            content_type=content_type,
            size_bytes=len(buffer),
            sha256=hashlib.sha256(buffer).hexdigest(),
            buffer=buffer,
            text=text,
            warnings=tuple(warnings),
        )

    async def ingest_upload(self, file: UploadFile, extract_text: bool = True) -> IngestedDocument:
        original_name = file.filename or "upload"
        safe_name = self._safe_filename(original_name)
        extension = Path(safe_name).suffix.lower()
        if extension not in self.allowed_extensions:
            raise IngestionValidationError("Tipo de arquivo nao permitido. Use PDF, TXT, LOG, JSON ou MD.")

        buffer = await self._read_limited_upload(file)
        self._validate_file_signature(buffer, extension)

        stored_path = self._safe_temp_path(safe_name)
        stored_path.write_bytes(buffer)

        content_type = file.content_type or mimetypes.guess_type(safe_name)[0]
        text, warnings = self.extract_text(buffer, content_type=content_type, filename=safe_name) if extract_text else ("", [])

        # Proximo estagio: trate o retorno como um envelope de ingestao. A Analise de
        # Ameacas deve consumir o texto normalizado e o hash, mantendo `stored_path`
        # como referencia temporaria auditavel, sem confiar no nome original do usuario.
        return IngestedDocument(
            source_type="upload",
            source_name=safe_name,
            content_type=content_type,
            size_bytes=len(buffer),
            sha256=hashlib.sha256(buffer).hexdigest(),
            buffer=buffer,
            stored_path=stored_path,
            text=text,
            warnings=tuple(warnings),
        )

    def extract_text(
        self,
        buffer: bytes,
        content_type: str | None = None,
        filename: str | None = None,
    ) -> tuple[str, list[str]]:
        extension = Path(filename or "").suffix.lower()
        warnings: list[str] = []

        if content_type == "application/pdf" or extension == ".pdf" or buffer.startswith(b"%PDF"):
            return self._extract_pdf_text(buffer)

        if content_type in {"text/html", "application/xhtml+xml"} or extension in {".html", ".htm"}:
            return self._extract_html_text(buffer)

        decoded = self._decode_text(buffer)
        if extension == ".json" or content_type == "application/json":
            try:
                parsed = json.loads(decoded)
                return json.dumps(parsed, ensure_ascii=False, indent=2), warnings
            except json.JSONDecodeError as exc:
                warnings.append(f"JSON invalido lido como texto bruto: {exc}")

        return decoded, warnings

    def _download_once(self, url: str) -> requests.Response:
        response = requests.get(
            url,
            allow_redirects=False,
            stream=True,
            timeout=(3.05, self.timeout_seconds),
            headers={"User-Agent": "ThreatIntelPro-IngestionEngine/1.0"},
        )
        response.raise_for_status()
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > self.max_bytes:
            raise IngestionValidationError("Conteudo remoto excede o limite configurado.")
        return response

    def _read_limited_response(self, response: requests.Response) -> bytes:
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > self.max_bytes:
                raise IngestionValidationError("Conteudo remoto excede o limite configurado.")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _read_limited_upload(self, file: UploadFile) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await file.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > self.max_bytes:
                raise IngestionValidationError("Arquivo excede o limite configurado.")
            chunks.append(chunk)
        return b"".join(chunks)

    def _extract_pdf_text(self, buffer: bytes) -> tuple[str, list[str]]:
        try:
            import fitz
        except ModuleNotFoundError as exc:
            raise IngestionValidationError("Dependencia PyMuPDF ausente para extrair PDFs.") from exc

        warnings: list[str] = []
        pages: list[str] = []
        try:
            with fitz.open(stream=buffer, filetype="pdf") as document:
                for page in document:
                    pages.append(page.get_text("text"))
        except Exception as exc:
            raise IngestionValidationError(f"Nao foi possivel extrair texto do PDF: {exc}") from exc

        if not any(page.strip() for page in pages):
            warnings.append("PDF sem texto extraivel; OCR pode ser necessario.")
        return "\n".join(pages).strip(), warnings

    def _extract_html_text(self, buffer: bytes) -> tuple[str, list[str]]:
        try:
            from bs4 import BeautifulSoup
        except ModuleNotFoundError as exc:
            raise IngestionValidationError("Dependencia beautifulsoup4 ausente para extrair HTML.") from exc

        soup = BeautifulSoup(self._decode_text(buffer), "html.parser")
        for tag in soup(["script", "style", "noscript", "template"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(lines), []

    def _decode_text(self, buffer: bytes) -> str:
        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                return buffer.decode(encoding)
            except UnicodeDecodeError:
                continue
        return buffer.decode("utf-8", errors="replace")

    def _validate_safe_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in self.allowed_schemes:
            raise IngestionValidationError("URL deve usar HTTP ou HTTPS.")
        if not parsed.hostname:
            raise IngestionValidationError("URL sem hostname valido.")
        if parsed.username or parsed.password:
            raise IngestionValidationError("URL com credenciais nao e permitida.")

        for resolved_ip in self._resolve_host(parsed.hostname):
            if self._is_blocked_ip(resolved_ip):
                raise IngestionValidationError("URL bloqueada por protecao SSRF.")

        return parsed.geturl()

    def _resolve_host(self, hostname: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        try:
            literal_ip = ipaddress.ip_address(hostname)
            return {literal_ip}
        except ValueError:
            pass

        try:
            records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise IngestionValidationError("Hostname nao pode ser resolvido.") from exc

        return {ipaddress.ip_address(record[4][0]) for record in records}

    def _is_blocked_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

    def _safe_filename(self, filename: str) -> str:
        basename = Path(filename.replace("\\", "/")).name
        sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", basename).strip("._")
        if not sanitized:
            raise IngestionValidationError("Nome de arquivo invalido.")
        return sanitized[:180]

    def _safe_temp_path(self, safe_name: str) -> Path:
        candidate = (self.temp_dir / f"{uuid.uuid4().hex}_{safe_name}").resolve()
        try:
            candidate.relative_to(self.temp_dir)
        except ValueError as exc:
            raise IngestionValidationError("Caminho temporario invalido.") from exc
        return candidate

    def _validate_file_signature(self, buffer: bytes, extension: str) -> None:
        if extension == ".pdf" and not buffer.startswith(b"%PDF"):
            raise IngestionValidationError("Arquivo PDF sem assinatura valida.")
        if extension == ".json":
            try:
                json.loads(self._decode_text(buffer))
            except json.JSONDecodeError as exc:
                raise IngestionValidationError(f"JSON invalido: {exc}") from exc
        if extension in {".txt", ".log"} and b"\x00" in buffer[:4096]:
            raise IngestionValidationError("Arquivo de texto contem bytes nulos.")
