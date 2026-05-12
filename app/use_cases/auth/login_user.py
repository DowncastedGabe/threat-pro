import logging

from app.core.exceptions.base import DomainError
from app.core.security.password import verify_password
from app.domain.repositories.user_repository import UserRepository
from app.schemas.auth import LoginRequest, TokenPairResponse
from app.use_cases.auth.common import access_token_expires_in_seconds, user_to_response
from app.use_cases.auth.session_tokens import issue_token_pair

logger = logging.getLogger(__name__)


class LoginUserUseCase:
    def __init__(self, repository: UserRepository, refresh_token_repository):
        self.repository = repository
        self.refresh_token_repository = refresh_token_repository

    def execute(self, payload: LoginRequest) -> TokenPairResponse:
        user = self.repository.get_by_email(payload.email)
        if not user or not verify_password(payload.password, user.password_hash):
            logger.warning("Falha de login para email: %s", payload.email)
            raise DomainError("Credenciais invalidas.")
        if not user.can_login():
            raise DomainError("Usuario inativo.")

        self.repository.update_last_login(user.id)
        user = self.repository.get_by_id(user.id) or user
        logger.info("Login realizado: %s", user.email)
        access_token, refresh_token = issue_token_pair(user, self.refresh_token_repository)
        return TokenPairResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=access_token_expires_in_seconds(),
            user=user_to_response(user),
        )
