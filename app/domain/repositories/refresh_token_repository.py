from app.domain.entities.refresh_token import RefreshToken


class RefreshTokenRepository:
    def create(self, *, user_id: int, token_hash: str, jti: str, expires_at) -> RefreshToken:
        ...

    def get_active_by_hash(self, token_hash: str) -> RefreshToken | None:
        ...

    def revoke(self, token_id: int) -> None:
        ...

    def revoke_all_for_user(self, user_id: int) -> None:
        ...
