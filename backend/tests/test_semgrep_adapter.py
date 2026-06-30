"""Tests for the Semgrep SAST adapter: JSON result parsing."""

import json

from app.adapters.semgrep import SemgrepAdapter
from app.models import Severity

SAMPLE_OUTPUT = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected",
            "path": "app/utils.py",
            "start": {"line": 42, "col": 1},
            "end": {"line": 42, "col": 25},
            "extra": {
                "severity": "WARNING",
                "message": "Detected use of exec(). This is dangerous.",
                "lines": "    exec(user_input)",
                "metadata": {
                    "cwe": ["CWE-94: Code Injection"],
                    "owasp": ["A03:2021"],
                    "fix": "Avoid using exec(); use ast.literal_eval() for safe evaluation.",
                },
            },
        },
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "app/config.py",
            "start": {"line": 10, "col": 1},
            "end": {"line": 10, "col": 30},
            "extra": {
                "severity": "ERROR",
                "message": "Hardcoded password detected.",
                "lines": "PASSWORD = 'admin123'",
                "metadata": {"cwe": ["CWE-798"]},
            },
        },
        {
            "check_id": "generic.info-only",
            "path": "README.md",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 5},
            "extra": {
                "severity": "INFO",
                "message": "Informational finding.",
                "metadata": {},
            },
        },
    ],
    "errors": [],
})


def test_parse_maps_results_to_findings():
    findings = SemgrepAdapter().parse(SAMPLE_OUTPUT)
    assert len(findings) == 3
    assert all(f.engine == "semgrep" for f in findings)


def test_parse_maps_severity():
    findings = SemgrepAdapter().parse(SAMPLE_OUTPUT)
    by_id = {f.vuln_type: f for f in findings}
    assert by_id["python.lang.security.audit.exec-detected"].severity is Severity.MEDIUM
    assert by_id["python.lang.security.audit.hardcoded-password"].severity is Severity.HIGH
    assert by_id["generic.info-only"].severity is Severity.LOW


def test_parse_maps_location_and_evidence():
    findings = SemgrepAdapter().parse(SAMPLE_OUTPUT)
    exec_finding = next(f for f in findings if "exec" in f.vuln_type)
    assert exec_finding.location == "app/utils.py:42"
    assert "exec(user_input)" in exec_finding.evidence


def test_parse_maps_cwe_and_owasp():
    findings = SemgrepAdapter().parse(SAMPLE_OUTPUT)
    exec_finding = next(f for f in findings if "exec" in f.vuln_type)
    assert exec_finding.cwe_id == "CWE-94"
    assert exec_finding.owasp_category == "A03:2021-Injection"


def test_parse_empty_returns_no_findings():
    assert SemgrepAdapter().parse("") == []
    assert SemgrepAdapter().parse(json.dumps({"results": []})) == []


def test_run_without_source_path_returns_empty():
    import asyncio

    raw = asyncio.run(SemgrepAdapter().run("http://example.com"))
    assert raw == ""


def test_is_available_false_when_binary_missing():
    assert SemgrepAdapter(binary="no-such-semgrep-xyz").is_available() is False
