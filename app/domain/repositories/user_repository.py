from typing import Protocol
from uuid import UUID

from app.domain.entities.user import User


class UserRepository(Protocol):
    def get_by_id(self, user_id: int) -> User | None:
        ...

    def get_by_uuid(self, user_uuid: UUID) -> User | None:
        ...

    def get_by_email(self, email: str) -> User | None:
        ...

    def create(self, *, name: str, email: str, password_hash: str, role: str) -> User:
        ...

    def update_last_login(self, user_id: int) -> None:
        ...
