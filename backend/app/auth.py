"""In-app authentication: credential check, signed bearer tokens, and a gate.

Active only when ``APP_PASSWORD`` is set. The static UI, ``/health`` and the
auth endpoints stay public so the login screen can load; everything under
``/api`` (plus the API docs) requires a valid bearer token issued by
``POST /api/auth/login``. Tokens are stateless HMAC-signed values with an expiry
so nothing needs to be stored server-side (works on ephemeral hosts).
"""

import base64
import hashlib
import hmac
import os
import secrets
import time
from urllib.parse import parse_qs

from starlette.responses import JSONResponse

TOKEN_TTL = 12 * 60 * 60  # 12 hours


def auth_required() -> bool:
    """Auth is enforced only when a password is configured."""
    return bool(os.getenv("APP_PASSWORD"))


def _expected_credentials() -> tuple[str, str]:
    return os.getenv("APP_USERNAME", "admin"), os.getenv("APP_PASSWORD", "")


def _signing_secret() -> bytes:
    return (os.getenv("APP_SECRET") or os.getenv("APP_PASSWORD") or "insecure-dev-secret").encode()


def check_credentials(username: str, password: str) -> bool:
    """Constant-time check of submitted login credentials."""
    user, pw = _expected_credentials()
    if not pw:
        return True
    user_ok = secrets.compare_digest(username or "", user)
    pw_ok = secrets.compare_digest(password or "", pw)
    return user_ok and pw_ok


def issue_token(subject: str, ttl: int = TOKEN_TTL) -> str:
    """Create a signed ``subject|expiry|signature`` bearer token."""
    expiry = str(int(time.time()) + ttl)
    payload = f"{subject}|{expiry}"
    signature = hmac.new(_signing_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{signature}".encode()).decode()


def verify_token(token: str) -> bool:
    """Validate signature and expiry of a bearer token."""
    if not token:
        return False
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        subject, expiry, signature = decoded.split("|")
        payload = f"{subject}|{expiry}"
        expected = hmac.new(_signing_secret(), payload.encode(), hashlib.sha256).hexdigest()
    except Exception:  # noqa: BLE001 - malformed token -> invalid
        return False
    if not hmac.compare_digest(signature, expected):
        return False
    return int(expiry) >= int(time.time())


def _is_gated(path: str) -> bool:
    """Gate the API surface and docs; the static UI and health stay public."""
    if path == "/health" or path.startswith("/api/auth/"):
        return False
    return path.startswith("/api") or path in ("/docs", "/redoc", "/openapi.json")


def _token_from_scope(scope, headers: dict) -> str:
    authz = headers.get("authorization", "")
    if authz.startswith("Bearer "):
        return authz[7:]
    # Fall back to a ?token= query param (used by report download links and the
    # progress WebSocket, which can't set an Authorization header).
    query = parse_qs(scope.get("query_string", b"").decode())
    return query.get("token", [""])[0]


class AuthMiddleware:
    """Pure-ASGI bearer-token gate covering HTTP and WebSocket scopes."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket") or not auth_required():
            await self.app(scope, receive, send)
            return

        if not _is_gated(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        if verify_token(_token_from_scope(scope, headers)):
            await self.app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        response = JSONResponse({"detail": "authentication required"}, status_code=401)
        await response(scope, receive, send)
