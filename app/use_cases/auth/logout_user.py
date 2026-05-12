from app.core.security.token_hash import hash_token
from app.schemas.auth import RefreshTokenRequest


class LogoutUserUseCase:
    def __init__(self, refresh_token_repository):
        self.refresh_token_repository = refresh_token_repository

    def execute(self, payload: RefreshTokenRequest) -> dict:
        stored_token = self.refresh_token_repository.get_active_by_hash(hash_token(payload.refresh_token))
        if stored_token:
            self.refresh_token_repository.revoke(stored_token.id)
        return {"message": "Logout efetuado."}
