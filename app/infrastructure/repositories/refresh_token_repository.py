from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domain.entities.refresh_token import RefreshToken
from app.infrastructure.database.models.refresh_token_model import RefreshTokenModel


class SqlAlchemyRefreshTokenRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, *, user_id: int, token_hash: str, jti: str, expires_at) -> RefreshToken:
        row = RefreshTokenModel(user_id=user_id, token_hash=token_hash, jti=jti, expires_at=expires_at)
        self.session.add(row)
        self.session.commit()
        self.session.refresh(row)
        return self._to_domain(row)

    def get_active_by_hash(self, token_hash: str) -> RefreshToken | None:
        row = self.session.execute(
            select(RefreshTokenModel)
            .where(RefreshTokenModel.token_hash == token_hash)
            .where(RefreshTokenModel.revoked_at.is_(None))
        ).scalar_one_or_none()
        return self._to_domain(row) if row else None

    def revoke(self, token_id: int) -> None:
        row = self.session.get(RefreshTokenModel, token_id)
        if row and row.revoked_at is None:
            row.revoked_at = datetime.utcnow()
            self.session.add(row)
            self.session.commit()

    def revoke_all_for_user(self, user_id: int) -> None:
        rows = self.session.execute(
            select(RefreshTokenModel)
            .where(RefreshTokenModel.user_id == user_id)
            .where(RefreshTokenModel.revoked_at.is_(None))
        ).scalars().all()
        now = datetime.utcnow()
        for row in rows:
            row.revoked_at = now
            self.session.add(row)
        self.session.commit()

    @staticmethod
    def _to_domain(row: RefreshTokenModel) -> RefreshToken:
        return RefreshToken(
            id=row.id,
            user_id=row.user_id,
            token_hash=row.token_hash,
            jti=row.jti,
            expires_at=row.expires_at,
            created_at=row.created_at,
            revoked_at=row.revoked_at,
        )
