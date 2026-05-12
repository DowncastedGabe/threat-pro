from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class RefreshToken:
    id: int | None
    user_id: int
    token_hash: str
    jti: str
    expires_at: datetime
    created_at: datetime
    revoked_at: datetime | None = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None
