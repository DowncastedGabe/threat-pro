from uuid import UUID

from app.core.exceptions.base import DomainError
from app.core.security.jwt import decode_token
from app.core.security.token_hash import hash_token
from app.domain.repositories.user_repository import UserRepository
from app.schemas.auth import RefreshTokenRequest, TokenPairResponse
from app.use_cases.auth.common import access_token_expires_in_seconds, user_to_response
from app.use_cases.auth.session_tokens import issue_token_pair


class RefreshTokenUseCase:
    def __init__(self, repository: UserRepository, refresh_token_repository):
        self.repository = repository
        self.refresh_token_repository = refresh_token_repository

    def execute(self, payload: RefreshTokenRequest) -> TokenPairResponse:
        claims = decode_token(payload.refresh_token, expected_type="refresh")
        stored_token = self.refresh_token_repository.get_active_by_hash(hash_token(payload.refresh_token))
        if not stored_token or stored_token.jti != claims.get("jti"):
            raise DomainError("Refresh token invalido.")
        user = self.repository.get_by_uuid(UUID(claims["sub"]))
        if not user or not user.can_login():
            raise DomainError("Sessao invalida.")

        self.refresh_token_repository.revoke(stored_token.id)
        access_token, refresh_token = issue_token_pair(user, self.refresh_token_repository)
        return TokenPairResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=access_token_expires_in_seconds(),
            user=user_to_response(user),
        )
