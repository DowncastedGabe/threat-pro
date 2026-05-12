from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class UserRole(StrEnum):
    ADMIN = "admin"
    USER = "user"


@dataclass(slots=True)
class User:
    id: int | None
    uuid: UUID
    name: str
    email: str
    password_hash: str
    role: UserRole
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login: datetime | None = None

    def can_login(self) -> bool:
        return self.is_active

    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN
