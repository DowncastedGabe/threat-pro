from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.security.jwt import TokenError, decode_token


class AuthContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.auth_claims = None
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
            try:
                request.state.auth_claims = decode_token(token, expected_type="access")
            except TokenError:
                request.state.auth_claims = None
        return await call_next(request)
