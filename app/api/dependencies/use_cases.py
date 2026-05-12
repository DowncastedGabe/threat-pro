from fastapi import Depends

from app.api.dependencies.repositories import get_refresh_token_repository, get_site_analysis_repository, get_user_repository
from app.domain.repositories.site_analysis_repository import SiteAnalysisRepository
from app.domain.repositories.user_repository import UserRepository
from app.use_cases.site_history.list_site_history import ListSiteHistoryUseCase
from app.use_cases.auth.get_current_user import GetCurrentUserUseCase
from app.use_cases.auth.login_user import LoginUserUseCase
from app.use_cases.auth.logout_user import LogoutUserUseCase
from app.use_cases.auth.refresh_token import RefreshTokenUseCase
from app.use_cases.auth.register_user import RegisterUserUseCase


def get_list_site_history_use_case(
    repository: SiteAnalysisRepository = Depends(get_site_analysis_repository),
) -> ListSiteHistoryUseCase:
    return ListSiteHistoryUseCase(repository)


def get_register_user_use_case(
    repository: UserRepository = Depends(get_user_repository),
    refresh_token_repository=Depends(get_refresh_token_repository),
) -> RegisterUserUseCase:
    return RegisterUserUseCase(repository, refresh_token_repository)


def get_login_user_use_case(
    repository: UserRepository = Depends(get_user_repository),
    refresh_token_repository=Depends(get_refresh_token_repository),
) -> LoginUserUseCase:
    return LoginUserUseCase(repository, refresh_token_repository)


def get_refresh_token_use_case(
    repository: UserRepository = Depends(get_user_repository),
    refresh_token_repository=Depends(get_refresh_token_repository),
) -> RefreshTokenUseCase:
    return RefreshTokenUseCase(repository, refresh_token_repository)


def get_current_user_use_case(repository: UserRepository = Depends(get_user_repository)) -> GetCurrentUserUseCase:
    return GetCurrentUserUseCase(repository)


def get_logout_user_use_case(refresh_token_repository=Depends(get_refresh_token_repository)) -> LogoutUserUseCase:
    return LogoutUserUseCase(refresh_token_repository)
