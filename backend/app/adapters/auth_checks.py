"""Custom authentication and security-header analysis.

No external tool — inspects HTTP responses directly to flag:
- Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Weak or missing cookie flags (HttpOnly, Secure, SameSite)
- Absence of CSRF tokens in HTML forms
- Basic session handling (exposes when no session cookie is set at all)

Each issue is emitted as a unified Finding with the appropriate severity and
OWASP category, enabling the report to include auth/header findings even when
ZAP or Nuclei isn't available.
"""

import re
from typing import Optional
from http.cookies import SimpleCookie

import httpx

from app.adapters.base import EngineAdapter
from app.models import ScanType, Severity
from app.schemas import NormalizedFinding

_CSRF_TOKEN_NAMES = re.compile(
    r'name=["\']?(csrf|_token|csrfmiddlewaretoken|__requestverificationtoken'
    r"|_csrf_token|authenticity_token)[\"']?",
    re.IGNORECASE,
)

_EXPECTED_HEADERS = {
    "Strict-Transport-Security": (Severity.MEDIUM, "CWE-319", "A02:2021-Cryptographic Failures"),
    "Content-Security-Policy": (Severity.MEDIUM, "CWE-693", "A05:2021-Security Misconfiguration"),
    "X-Frame-Options": (Severity.LOW, "CWE-1021", "A05:2021-Security Misconfiguration"),
    "X-Content-Type-Options": (Severity.LOW, "CWE-693", "A05:2021-Security Misconfiguration"),
}


class AuthChecksAdapter(EngineAdapter):
    """Lightweight HTTP inspection for auth/session/header weaknesses."""

    name = "auth-checks"
    supported_scan_types = (ScanType.DAST,)

    def is_available(self) -> bool:
        return True  # no external dependency

    async def run(self, target: str, on_progress=None, **kwargs) -> str:
        """Fetch the target and serialize response details for parsing."""
        if on_progress:
            await on_progress(10, "fetching target for auth analysis")
        try:
            async with httpx.AsyncClient(
                timeout=15, follow_redirects=True, verify=False
            ) as client:
                resp = await client.get(target)
                # Build a simple text block: status, headers, body snippet for parsing.
                parts = [f"STATUS {resp.status_code}"]
                for name, value in resp.headers.multi_items():
                    parts.append(f"HEADER {name}: {value}")
                body = resp.text[:50000] if resp.text else ""
                parts.append(f"BODY_START\n{body}\nBODY_END")
                if on_progress:
                    await on_progress(100, "auth analysis complete")
                return "\n".join(parts)
        except Exception:  # noqa: BLE001
            return ""

    def parse(self, raw: str) -> list[NormalizedFinding]:
        if not raw:
            return []

        findings: list[NormalizedFinding] = []
        headers: dict[str, list[str]] = {}
        body = ""
        lines = raw.splitlines()
        in_body = False
        for line in lines:
            if line == "BODY_START":
                in_body = True
                continue
            if line == "BODY_END":
                in_body = False
                continue
            if in_body:
                body += line + "\n"
                continue
            if line.startswith("HEADER "):
                h = line[7:]
                name, _, value = h.partition(": ")
                headers.setdefault(name.lower(), []).append(value)

        # Security headers check.
        for header, (severity, cwe, owasp) in _EXPECTED_HEADERS.items():
            if header.lower() not in headers:
                findings.append(NormalizedFinding(
                    engine="auth-checks",
                    vuln_type=f"missing-header-{header.lower()}",
                    severity=severity,
                    title=f"Missing {header} header",
                    cwe_id=cwe,
                    owasp_category=owasp,
                    remediation=f"Set the {header} response header with an appropriate value.",
                ))

        # Cookie flags check.
        for raw_cookie in headers.get("set-cookie", []):
            findings.extend(self._check_cookie(raw_cookie))

        # CSRF token check on HTML forms.
        if "<form" in body.lower():
            if not _CSRF_TOKEN_NAMES.search(body):
                findings.append(NormalizedFinding(
                    engine="auth-checks",
                    vuln_type="missing-csrf-token",
                    severity=Severity.MEDIUM,
                    title="HTML form without CSRF token",
                    cwe_id="CWE-352",
                    owasp_category="A01:2021-Broken Access Control",
                    remediation="Include a unique CSRF token in every state-changing form.",
                ))

        # No session cookie at all.
        if not headers.get("set-cookie"):
            findings.append(NormalizedFinding(
                engine="auth-checks",
                vuln_type="no-session-cookie",
                severity=Severity.INFO,
                title="No Set-Cookie header observed",
                evidence="The response set no cookies; session management could not be evaluated.",
                owasp_category="A07:2021-Identification and Authentication Failures",
            ))

        return findings

    @staticmethod
    def _check_cookie(raw_cookie: str) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        lower = raw_cookie.lower()
        # Extract cookie name.
        name = raw_cookie.split("=", 1)[0].strip()

        if "httponly" not in lower:
            findings.append(NormalizedFinding(
                engine="auth-checks",
                vuln_type="cookie-missing-httponly",
                severity=Severity.MEDIUM,
                title=f"Cookie '{name}' missing HttpOnly flag",
                affected_param=name,
                cwe_id="CWE-1004",
                owasp_category="A05:2021-Security Misconfiguration",
                remediation="Set the HttpOnly flag on cookies to prevent client-side script access.",
            ))
        if "secure" not in lower:
            findings.append(NormalizedFinding(
                engine="auth-checks",
                vuln_type="cookie-missing-secure",
                severity=Severity.MEDIUM,
                title=f"Cookie '{name}' missing Secure flag",
                affected_param=name,
                cwe_id="CWE-614",
                owasp_category="A02:2021-Cryptographic Failures",
                remediation="Set the Secure flag so the cookie is only sent over HTTPS.",
            ))
        if "samesite" not in lower:
            findings.append(NormalizedFinding(
                engine="auth-checks",
                vuln_type="cookie-missing-samesite",
                severity=Severity.LOW,
                title=f"Cookie '{name}' missing SameSite attribute",
                affected_param=name,
                cwe_id="CWE-1275",
                owasp_category="A01:2021-Broken Access Control",
                remediation="Set SameSite=Strict or SameSite=Lax to mitigate CSRF.",
            ))
        return findings
