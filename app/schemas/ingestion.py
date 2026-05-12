from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl


class UrlIngestionRequest(BaseModel):
    url: HttpUrl
    extract_text: bool = True
    include_buffer_base64: bool = False


class IngestionResponse(BaseModel):
    source_type: str
    source_name: str
    content_type: str | None = None
    size_bytes: int
    sha256: str
    stored_path: str | None = None
    text: str = ""
    warnings: list[str] = Field(default_factory=list)
    buffer_base64: str | None = None

