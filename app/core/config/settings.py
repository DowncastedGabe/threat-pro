import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parents[3]
load_dotenv(BASE_DIR / ".env")


class Settings(BaseModel):
    app_name: str = "ThreatIntel Pro"
    app_version: str = "2.0.0"
    environment: str = os.getenv("ENVIRONMENT", "dev")

    api_key: str | None = os.getenv("API_KEY")
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:5173")

    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/threatintel",
    )
    db_echo: bool = os.getenv("DB_ECHO", "false").lower() == "true"
    db_pool_size: int = int(os.getenv("DB_POOL_SIZE", "10"))
    db_max_overflow: int = int(os.getenv("DB_MAX_OVERFLOW", "20"))
    db_pool_pre_ping: bool = os.getenv("DB_POOL_PRE_PING", "true").lower() == "true"

    rate_limit_analisar: str = os.getenv("RATE_LIMIT_ANALISAR", "10/minute")
    rate_limit_analisar_site: str = os.getenv("RATE_LIMIT_ANALISAR_SITE", "10/minute")
    rate_limit_osint: str = os.getenv("RATE_LIMIT_OSINT", "5/minute")
    rate_limit_disk_mapping: str = os.getenv("RATE_LIMIT_DISK_MAPPING", "12/minute")
    rate_limit_ingestion: str = os.getenv("RATE_LIMIT_INGESTION", "12/minute")
    disk_mapping_allowed_roots: str = os.getenv("DISK_MAPPING_ALLOWED_ROOTS", str(BASE_DIR))
    ingestion_temp_dir: str = os.getenv("INGESTION_TEMP_DIR", str(BASE_DIR / "data" / "ingestion_tmp"))
    ingestion_max_bytes: int = int(os.getenv("INGESTION_MAX_BYTES", str(10 * 1024 * 1024)))
    ingestion_timeout_seconds: int = int(os.getenv("INGESTION_TIMEOUT_SECONDS", "10"))

    jwt_secret: str = os.getenv("JWT_SECRET", "change-me")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_minutes: int = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
    refresh_token_days: int = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))

    @property
    def is_prod(self) -> bool:
        return self.environment.lower() == "prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
