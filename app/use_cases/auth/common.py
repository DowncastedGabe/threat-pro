from app.core.config.settings import settings
from app.domain.entities.user import User
from app.schemas.auth import UserResponse


def user_to_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        uuid=str(user.uuid),
        name=user.name,
        email=user.email,
        role=str(user.role),
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
        last_login=user.last_login,
    )


def access_token_expires_in_seconds() -> int:
    return settings.access_token_minutes * 60
