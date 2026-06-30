"""Best-effort mapping from CWE identifiers to OWASP Top 10 (2021) categories.

Shared by the engine adapters so findings carry a consistent OWASP label where a
CWE is known. Returns None for CWEs we don't have a confident mapping for.
"""

from typing import Optional

_CWE_TO_OWASP = {
    79: "A03:2021-Injection",  # Cross-site scripting
    80: "A03:2021-Injection",
    89: "A03:2021-Injection",  # SQL injection
    78: "A03:2021-Injection",  # OS command injection
    91: "A03:2021-Injection",  # XML injection
    94: "A03:2021-Injection",  # Code injection
    943: "A03:2021-Injection",
    918: "A10:2021-Server-Side Request Forgery (SSRF)",
    352: "A01:2021-Broken Access Control",  # CSRF
    284: "A01:2021-Broken Access Control",
    285: "A01:2021-Broken Access Control",
    639: "A01:2021-Broken Access Control",
    22: "A01:2021-Broken Access Control",  # Path traversal
    200: "A01:2021-Broken Access Control",  # Information exposure
    287: "A07:2021-Identification and Authentication Failures",
    306: "A07:2021-Identification and Authentication Failures",
    798: "A07:2021-Identification and Authentication Failures",
    319: "A02:2021-Cryptographic Failures",
    326: "A02:2021-Cryptographic Failures",
    327: "A02:2021-Cryptographic Failures",
    611: "A05:2021-Security Misconfiguration",  # XXE
    16: "A05:2021-Security Misconfiguration",
    693: "A05:2021-Security Misconfiguration",  # Missing security headers
    1021: "A05:2021-Security Misconfiguration",  # Clickjacking / framing
    502: "A08:2021-Software and Data Integrity Failures",
}


def _to_int(cwe) -> Optional[int]:
    if cwe is None:
        return None
    if isinstance(cwe, int):
        return cwe
    text = str(cwe).strip().upper()
    if text.startswith("CWE-"):
        text = text[4:]
    try:
        return int(text)
    except ValueError:
        return None


def owasp_for_cwe(cwe) -> Optional[str]:
    """Return the OWASP Top 10 (2021) category for a CWE, or None if unknown.

    Accepts an int (79), or a string ("79" / "CWE-79"). Example return value:
    "A03:2021-Injection".
    """
    cwe_int = _to_int(cwe)
    if cwe_int is None:
        return None
    return _CWE_TO_OWASP.get(cwe_int)
