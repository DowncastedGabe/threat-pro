from fastapi import Depends
from sqlmodel import Session

from app.infrastructure.repositories.site_analysis_repository import SqlModelSiteAnalysisRepository
from app.infrastructure.repositories.refresh_token_repository import SqlAlchemyRefreshTokenRepository
from app.infrastructure.repositories.user_repository import SqlAlchemyUserRepository
from app.core.database.session import get_session


def get_site_analysis_repository(session: Session = Depends(get_session)) -> SqlModelSiteAnalysisRepository:
    return SqlModelSiteAnalysisRepository(session)


def get_user_repository(session: Session = Depends(get_session)) -> SqlAlchemyUserRepository:
    return SqlAlchemyUserRepository(session)


def get_refresh_token_repository(session: Session = Depends(get_session)) -> SqlAlchemyRefreshTokenRepository:
    return SqlAlchemyRefreshTokenRepository(session)
