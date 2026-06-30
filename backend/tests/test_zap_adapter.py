"""Tests for the OWASP ZAP adapter: alert mapping and availability."""

import asyncio
import json
import os

import pytest

from app.adapters.zap import ZapAdapter
from app.models import Severity

# A representative ZAP /core/view/alerts response covering XSS, SSRF, CSRF, and
# a missing security header.
SAMPLE_ALERTS = {
    "alerts": [
        {
            "alert": "Cross Site Scripting (Reflected)",
            "name": "Cross Site Scripting (Reflected)",
            "riskcode": "3",
            "confidence": "2",
            "url": "https://victim.test/search?q=test",
            "param": "q",
            "attack": "<script>alert(1)</script>",
            "evidence": "<script>alert(1)</script>",
            "cweid": "79",
            "solution": "Encode output and validate input.",
        },
        {
            "alert": "Server Side Request Forgery",
            "riskcode": "3",
            "url": "https://victim.test/fetch?url=http://169.254.169.254/",
            "param": "url",
            "cweid": "918",
            "solution": "Restrict outbound requests.",
        },
        {
            "alert": "Absence of Anti-CSRF Tokens",
            "riskcode": "1",
            "url": "https://victim.test/profile",
            "param": "",
            "cweid": "352",
            "otherinfo": "No Anti-CSRF tokens were found in a HTML submission form.",
        },
        {
            "alert": "Missing Anti-clickjacking Header",
            "riskcode": "1",
            "url": "https://victim.test/",
            "cweid": "693",
            "evidence": "",
        },
    ]
}


def test_parse_maps_alerts_to_findings():
    findings = ZapAdapter().parse(json.dumps(SAMPLE_ALERTS))
    assert len(findings) == 4
    assert all(f.engine == "zap" for f in findings)

    by_type = {f.vuln_type: f for f in findings}
    assert "Cross Site Scripting (Reflected)" in by_type
    assert "Server Side Request Forgery" in by_type
    assert "Absence of Anti-CSRF Tokens" in by_type


def test_parse_maps_severity_cwe_and_owasp():
    findings = ZapAdapter().parse(json.dumps(SAMPLE_ALERTS))
    xss = next(f for f in findings if f.vuln_type.startswith("Cross Site"))
    assert xss.severity is Severity.HIGH  # riskcode 3
    assert xss.cwe_id == "CWE-79"
    assert xss.owasp_category == "A03:2021-Injection"
    assert xss.affected_param == "q"
    assert xss.location == "https://victim.test/search?q=test"

    ssrf = next(f for f in findings if "Request Forgery" in f.vuln_type)
    assert ssrf.cwe_id == "CWE-918"
    assert ssrf.owasp_category.startswith("A10:2021")

    csrf = next(f for f in findings if "CSRF" in f.vuln_type)
    assert csrf.severity is Severity.LOW  # riskcode 1
    assert csrf.cwe_id == "CWE-352"


def test_parse_handles_empty_and_malformed():
    assert ZapAdapter().parse("") == []
    assert ZapAdapter().parse("{not json") == []
    assert ZapAdapter().parse(json.dumps({"alerts": []})) == []


def test_is_available_false_when_daemon_unreachable():
    # Nothing is listening here, so availability must be False (graceful).
    adapter = ZapAdapter(api_url="http://127.0.0.1:1", overall_timeout=5)
    assert adapter.is_available() is False


@pytest.mark.integration
@pytest.mark.skipif(not ZapAdapter().is_available(), reason="ZAP daemon not reachable")
def test_zap_live_smoke():
    adapter = ZapAdapter()
    raw = asyncio.run(adapter.run(os.getenv("ZAP_TEST_TARGET", "http://localhost")))
    assert isinstance(adapter.parse(raw), list)
