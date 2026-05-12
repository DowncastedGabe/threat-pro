from app.core.config.settings import settings
from app.core.database.session import engine
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_URL = settings.database_url
