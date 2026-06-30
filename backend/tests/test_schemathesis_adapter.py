"""Tests for the schemathesis adapter: output parsing and no-spec no-op."""

from app.adapters.schemathesis_adapter import SchemathesisAdapter
from app.models import Severity

SAMPLE_OUTPUT = """
======================= Schemathesis test session starts =======================
Schema location: http://localhost:8000/openapi.json
Base URL: http://localhost:8000
Specification version: Open API 3.0.0

FAILURES
========
POST /api/users
  1. Received a response with 5xx status code: 500
     Response payload: {"detail": "Internal Server Error"}

GET /api/items/{id}
  1. Response violates schema: 'name' is a required property

SUMMARY
=======
Performed checks:
    not_a_server_error             2 / 150 passed          FAILED
    response_schema_conformance    1 / 150 passed          FAILED
"""


def test_parse_captures_5xx_failures():
    findings = SchemathesisAdapter().parse(SAMPLE_OUTPUT)
    assert len(findings) >= 2
    assert all(f.engine == "schemathesis" for f in findings)
    post_finding = next(f for f in findings if "POST /api/users" in f.title)
    assert post_finding.severity is Severity.MEDIUM
    assert "5xx" in post_finding.evidence


def test_parse_captures_schema_violations():
    findings = SchemathesisAdapter().parse(SAMPLE_OUTPUT)
    get_finding = next(f for f in findings if "GET /api/items" in f.title)
    assert "violates" in get_finding.evidence.lower()


def test_parse_empty_returns_no_findings():
    assert SchemathesisAdapter().parse("") == []


def test_run_without_spec_url_returns_empty():
    import asyncio

    raw = asyncio.run(SchemathesisAdapter().run("http://example.com"))
    assert raw == ""


def test_is_available_false_when_binary_missing():
    assert SchemathesisAdapter(binary="no-such-st-xyz").is_available() is False
