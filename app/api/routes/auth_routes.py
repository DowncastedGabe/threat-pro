from fastapi import APIRouter, Depends, status

from app.api.dependencies.auth import get_current_user, require_admin
from app.api.dependencies.use_cases import (
    get_login_user_use_case,
    get_logout_user_use_case,
    get_refresh_token_use_case,
    get_register_user_use_case,
)
from app.domain.entities.user import User
from app.schemas.auth import (
    CurrentUserResponse,
    LoginRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenPairResponse,
)
from app.use_cases.auth.common import user_to_response
from app.use_cases.auth.login_user import LoginUserUseCase
from app.use_cases.auth.logout_user import LogoutUserUseCase
from app.use_cases.auth.refresh_token import RefreshTokenUseCase
from app.use_cases.auth.register_user import RegisterUserUseCase

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register", response_model=TokenPairResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    use_case: RegisterUserUseCase = Depends(get_register_user_use_case),
):
    return use_case.execute(payload)


@router.post("/login", response_model=TokenPairResponse)
def login(
    payload: LoginRequest,
    use_case: LoginUserUseCase = Depends(get_login_user_use_case),
):
    return use_case.execute(payload)


@router.post("/refresh", response_model=TokenPairResponse)
def refresh(
    payload: RefreshTokenRequest,
    use_case: RefreshTokenUseCase = Depends(get_refresh_token_use_case),
):
    return use_case.execute(payload)


@router.post("/logout")
def logout(
    payload: RefreshTokenRequest,
    use_case: LogoutUserUseCase = Depends(get_logout_user_use_case),
):
    return use_case.execute(payload)


@router.get("/me", response_model=CurrentUserResponse)
def me(current_user: User = Depends(get_current_user)):
    return user_to_response(current_user)


@router.get("/admin-check", response_model=CurrentUserResponse)
def admin_check(current_user: User = Depends(require_admin)):
    return user_to_response(current_user)
