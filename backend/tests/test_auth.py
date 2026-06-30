"""Tests for the HTTP Basic auth credential check."""

import base64

from app.auth import is_authorized


def _header(user: str, pw: str) -> str:
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {token}"


def test_correct_credentials_authorized():
    assert is_authorized(_header("recruiter", "s3cret"), "recruiter", "s3cret")


def test_wrong_password_rejected():
    assert not is_authorized(_header("recruiter", "nope"), "recruiter", "s3cret")


def test_wrong_user_rejected():
    assert not is_authorized(_header("intruder", "s3cret"), "recruiter", "s3cret")


def test_missing_or_malformed_header_rejected():
    assert not is_authorized("", "recruiter", "s3cret")
    assert not is_authorized("Bearer abc", "recruiter", "s3cret")
    assert not is_authorized("Basic not-base64!!", "recruiter", "s3cret")
