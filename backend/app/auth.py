"""Optional HTTP Basic authentication gate.

Active only when ``APP_PASSWORD`` is set in the environment, so local and CI
runs are unaffected. When enabled, every request except the ``/health`` probe
must present the configured username/password (shared only with the people you
want to let in). Covers both HTTP and WebSocket connections.
"""

import base64
import os
import secrets

from starlette.responses import PlainTextResponse

_REALM = 'Basic realm="AI Penetration Tester", charset="UTF-8"'


def _expected_credentials() -> tuple[str, str]:
    return os.getenv("APP_USERNAME", "admin"), os.getenv("APP_PASSWORD", "")


def is_authorized(auth_header: str, username: str, password: str) -> bool:
    """Constant-time check of an HTTP Basic ``Authorization`` header value."""
    if not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
    except Exception:  # noqa: BLE001 - malformed header -> unauthorized
        return False
    req_user, sep, req_pw = decoded.partition(":")
    if not sep:
        return False
    user_ok = secrets.compare_digest(req_user, username)
    pw_ok = secrets.compare_digest(req_pw, password)
    return user_ok and pw_ok


class BasicAuthMiddleware:
    """Pure-ASGI Basic auth covering HTTP and WebSocket scopes.

    Disabled (pass-through) when no ``APP_PASSWORD`` is configured. The health
    endpoint is always exempt so container/platform probes keep working.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        username, password = _expected_credentials()
        path = scope.get("path", "")
        if not password or path == "/health":
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        if is_authorized(headers.get("authorization", ""), username, password):
            await self.app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        response = PlainTextResponse(
            "Authentication required.",
            status_code=401,
            headers={"WWW-Authenticate": _REALM},
        )
        await response(scope, receive, send)
