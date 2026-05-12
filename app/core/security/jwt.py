from datetime import datetime, timedelta, timezone
from typing import Any
import base64
import hashlib
import hmac
import json
import secrets

from app.core.config.settings import settings
from app.core.exceptions.base import AppError


class TokenError(AppError):
    status_code = 401
    code = "invalid_token"


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(signing_input: bytes) -> bytes:
    if settings.jwt_algorithm != "HS256":
        raise RuntimeError("Somente HS256 esta configurado neste projeto.")
    return hmac.new(settings.jwt_secret.encode(), signing_input, hashlib.sha256).digest()


def create_token(
    *,
    subject: str,
    token_type: str,
    expires_delta: timedelta,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    header = {"alg": settings.jwt_algorithm, "typ": "JWT"}
    payload = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": secrets.token_urlsafe(16),
        **(extra_claims or {}),
    }
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = header_b64 + b"." + payload_b64
    signature = _sign(signing_input)
    return (signing_input + b"." + _b64url(signature)).decode()


def create_access_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    return create_token(
        subject=subject,
        token_type="access",
        expires_delta=timedelta(minutes=settings.access_token_minutes),
        extra_claims=extra_claims,
    )


def create_refresh_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    return create_token(
        subject=subject,
        token_type="refresh",
        expires_delta=timedelta(days=settings.refresh_token_days),
        extra_claims=extra_claims,
    )


def decode_token(token: str, *, expected_type: str | None = None) -> dict[str, Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected_signature = _b64url(_sign(signing_input)).decode()
        if not hmac.compare_digest(signature_b64, expected_signature):
            raise TokenError("Assinatura do token invalida.")
        payload = json.loads(_b64url_decode(payload_b64))
    except AppError:
        raise
    except Exception as exc:
        raise TokenError("Token malformado.") from exc

    exp = payload.get("exp")
    if not exp or datetime.now(timezone.utc).timestamp() > int(exp):
        raise TokenError("Token expirado.")

    if expected_type and payload.get("type") != expected_type:
        raise TokenError("Tipo de token invalido.")

    return payload
