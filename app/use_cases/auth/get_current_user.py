from uuid import UUID

from app.core.exceptions.base import DomainError
from app.core.security.jwt import decode_token
from app.domain.entities.user import User
from app.domain.repositories.user_repository import UserRepository


class GetCurrentUserUseCase:
    def __init__(self, repository: UserRepository):
        self.repository = repository

    def execute(self, access_token: str) -> User:
        claims = decode_token(access_token, expected_type="access")
        user = self.repository.get_by_uuid(UUID(claims["sub"]))
        if not user or not user.can_login():
            raise DomainError("Usuario nao autorizado.")
        return user
