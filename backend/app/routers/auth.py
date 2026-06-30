"""Authentication endpoints: login (issues a bearer token) and status.

Both routes are public (the gate in ``app.auth`` exempts ``/api/auth/*``) so the
login screen can load and submit before the user holds a token.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.auth import auth_required, check_credentials, issue_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = ""
    password: str = ""


class TokenResponse(BaseModel):
    token: str


class AuthStatus(BaseModel):
    auth_required: bool


@router.get("/status", response_model=AuthStatus)
def status_() -> AuthStatus:
    """Tell the frontend whether a login is needed."""
    return AuthStatus(auth_required=auth_required())


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest) -> TokenResponse:
    """Validate credentials and return a signed bearer token."""
    if not auth_required():
        return TokenResponse(token=issue_token("anonymous"))
    if check_credentials(body.username, body.password):
        return TokenResponse(token=issue_token(body.username or "user"))
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password.",
    )
