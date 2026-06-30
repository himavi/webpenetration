"""Tests for the Nikto adapter: JSON output parsing and availability."""

import json
import sys

from app.adapters.nikto import NiktoAdapter
from app.models import Severity

SAMPLE_JSON = json.dumps({
    "host": "example.com",
    "vulnerabilities": [
        {
            "OSVDB": "3092",
            "url": "/admin/",
            "method": "GET",
            "msg": "/admin/: Directory listing found. This is a sensitive directory.",
        },
        {
            "OSVDB": "0",
            "url": "/",
            "method": "GET",
            "msg": "Server leaks inodes via ETags, header found with file /.",
        },
        {
            "OSVDB": "877",
            "url": "/cgi-bin/test-cgi",
            "method": "GET",
            "msg": "Remote code execution vulnerability in test CGI script.",
        },
    ],
})


def test_parse_maps_vulnerabilities():
    findings = NiktoAdapter().parse(SAMPLE_JSON)
    assert len(findings) == 3
    assert all(f.engine == "nikto" for f in findings)
    assert all(f.owasp_category == "A05:2021-Security Misconfiguration" for f in findings)


def test_parse_severity_heuristic():
    findings = NiktoAdapter().parse(SAMPLE_JSON)
    by_osvdb = {f.vuln_type: f for f in findings}
    assert by_osvdb["nikto-3092"].severity is Severity.MEDIUM  # "sensitive"
    assert by_osvdb["nikto-877"].severity is Severity.CRITICAL  # "remote code"


def test_parse_location_includes_method():
    findings = NiktoAdapter().parse(SAMPLE_JSON)
    assert any("GET /admin/" in (f.location or "") for f in findings)


def test_parse_empty_and_malformed():
    assert NiktoAdapter().parse("") == []
    assert NiktoAdapter().parse("{bad json") == []
    assert NiktoAdapter().parse(json.dumps({"vulnerabilities": []})) == []


def test_is_available_false_when_binary_missing():
    assert NiktoAdapter(binary="definitely-not-nikto-xyz").is_available() is False
