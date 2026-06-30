"""Tests for the custom auth/header analysis adapter."""

import asyncio

from app.adapters.auth_checks import AuthChecksAdapter
from app.models import Severity


def _build_raw(
    headers: dict[str, str] | None = None,
    cookies: list[str] | None = None,
    body: str = "",
) -> str:
    parts = ["STATUS 200"]
    for name, value in (headers or {}).items():
        parts.append(f"HEADER {name}: {value}")
    for cookie in cookies or []:
        parts.append(f"HEADER set-cookie: {cookie}")
    parts.append(f"BODY_START\n{body}\nBODY_END")
    return "\n".join(parts)


def test_detects_missing_security_headers():
    raw = _build_raw(headers={"content-type": "text/html"})
    findings = AuthChecksAdapter().parse(raw)
    missing = {f.vuln_type for f in findings}
    assert "missing-header-strict-transport-security" in missing
    assert "missing-header-content-security-policy" in missing
    assert "missing-header-x-frame-options" in missing
    assert "missing-header-x-content-type-options" in missing


def test_no_missing_headers_when_all_present():
    raw = _build_raw(headers={
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
    })
    findings = AuthChecksAdapter().parse(raw)
    header_findings = [f for f in findings if f.vuln_type.startswith("missing-header-")]
    assert header_findings == []


def test_detects_cookie_flag_issues():
    raw = _build_raw(cookies=["session=abc123; Path=/"])
    findings = AuthChecksAdapter().parse(raw)
    types = {f.vuln_type for f in findings}
    assert "cookie-missing-httponly" in types
    assert "cookie-missing-secure" in types
    assert "cookie-missing-samesite" in types


def test_no_cookie_flag_issues_when_all_set():
    raw = _build_raw(cookies=["session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"])
    findings = AuthChecksAdapter().parse(raw)
    cookie_findings = [f for f in findings if f.vuln_type.startswith("cookie-")]
    assert cookie_findings == []


def test_detects_missing_csrf_token():
    form_html = '<form method="post" action="/login"><input name="user"></form>'
    raw = _build_raw(body=form_html)
    findings = AuthChecksAdapter().parse(raw)
    assert any(f.vuln_type == "missing-csrf-token" for f in findings)


def test_no_csrf_finding_when_token_present():
    form_html = '<form><input name="csrf_token" value="abc123"></form>'
    raw = _build_raw(body=form_html)
    findings = AuthChecksAdapter().parse(raw)
    assert not any(f.vuln_type == "missing-csrf-token" for f in findings)


def test_detects_no_session_cookie():
    raw = _build_raw()
    findings = AuthChecksAdapter().parse(raw)
    assert any(f.vuln_type == "no-session-cookie" for f in findings)


def test_is_available_always_true():
    assert AuthChecksAdapter().is_available() is True
