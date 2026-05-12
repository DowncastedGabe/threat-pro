from datetime import datetime, timezone

from app.core.security.jwt import create_access_token, create_refresh_token, decode_token
from app.core.security.token_hash import hash_token
from app.domain.entities.user import User


def issue_token_pair(user: User, refresh_token_repository):
    claims = {"role": str(user.role), "email": user.email}
    access_token = create_access_token(str(user.uuid), claims)
    refresh_token = create_refresh_token(str(user.uuid), claims)
    refresh_claims = decode_token(refresh_token, expected_type="refresh")
    refresh_token_repository.create(
        user_id=user.id,
        token_hash=hash_token(refresh_token),
        jti=refresh_claims["jti"],
        expires_at=datetime.fromtimestamp(refresh_claims["exp"], tz=timezone.utc).replace(tzinfo=None),
    )
    return access_token, refresh_token
