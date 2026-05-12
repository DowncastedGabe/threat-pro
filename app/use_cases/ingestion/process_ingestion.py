from __future__ import annotations

from fastapi import UploadFile

from app.infrastructure.external_services.ingestion_engine import IngestionEngine


class ProcessIngestionUseCase:
    def __init__(self, engine: IngestionEngine | None = None) -> None:
        self.engine = engine or IngestionEngine()

    def from_url(self, url: str, extract_text: bool = True):
        return self.engine.fetch_url(url=url, extract_text=extract_text)

    async def from_upload(self, file: UploadFile, extract_text: bool = True):
        return await self.engine.ingest_upload(file=file, extract_text=extract_text)

