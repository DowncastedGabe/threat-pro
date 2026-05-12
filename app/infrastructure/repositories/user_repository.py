from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.entities.user import User, UserRole
from app.infrastructure.database.models.user_model import UserModel


class SqlAlchemyUserRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, user_id: int) -> User | None:
        row = self.session.get(UserModel, user_id)
        return self._to_domain(row) if row else None

    def get_by_uuid(self, user_uuid: UUID) -> User | None:
        row = self.session.execute(select(UserModel).where(UserModel.uuid == user_uuid)).scalar_one_or_none()
        return self._to_domain(row) if row else None

    def get_by_email(self, email: str) -> User | None:
        row = self.session.execute(select(UserModel).where(UserModel.email == email.lower())).scalar_one_or_none()
        return self._to_domain(row) if row else None

    def create(self, *, name: str, email: str, password_hash: str, role: str = UserRole.USER) -> User:
        row = UserModel(
            name=name.strip(),
            email=email.lower(),
            password_hash=password_hash,
            role=UserRole(role),
        )
        self.session.add(row)
        self.session.commit()
        self.session.refresh(row)
        return self._to_domain(row)

    def update_last_login(self, user_id: int) -> None:
        row = self.session.get(UserModel, user_id)
        if row:
            row.last_login = datetime.utcnow()
            self.session.add(row)
            self.session.commit()

    @staticmethod
    def _to_domain(row: UserModel) -> User:
        return User(
            id=row.id,
            uuid=row.uuid,
            name=row.name,
            email=row.email,
            password_hash=row.password_hash,
            role=row.role,
            is_active=row.is_active,
            is_verified=row.is_verified,
            created_at=row.created_at,
            updated_at=row.updated_at,
            last_login=row.last_login,
        )
