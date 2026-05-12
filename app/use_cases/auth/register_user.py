import logging

from app.core.exceptions.base import DomainError
from app.core.security.password import hash_password
from app.domain.entities.user import UserRole
from app.domain.repositories.user_repository import UserRepository
from app.schemas.auth import RegisterRequest, TokenPairResponse
from app.use_cases.auth.common import access_token_expires_in_seconds, user_to_response
from app.use_cases.auth.session_tokens import issue_token_pair

logger = logging.getLogger(__name__)


class RegisterUserUseCase:
    def __init__(self, repository: UserRepository, refresh_token_repository):
        self.repository = repository
        self.refresh_token_repository = refresh_token_repository

    def execute(self, payload: RegisterRequest) -> TokenPairResponse:
        existing = self.repository.get_by_email(payload.email)
        if existing:
            raise DomainError("Email ja cadastrado.", details={"field": "email"})

        user = self.repository.create(
            name=payload.name,
            email=payload.email,
            password_hash=hash_password(payload.password),
            role=UserRole.USER,
        )
        logger.info("Novo usuario cadastrado: %s", user.email)
        access_token, refresh_token = issue_token_pair(user, self.refresh_token_repository)
        return TokenPairResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=access_token_expires_in_seconds(),
            user=user_to_response(user),
        )
