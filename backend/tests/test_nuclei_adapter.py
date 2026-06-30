"""Tests for the Nuclei adapter: JSONL parsing and availability detection."""

import json
import sys

from app.adapters.nuclei import NucleiAdapter
from app.models import Severity

SAMPLE_JSONL = "\n".join(
    [
        json.dumps(
            {
                "template-id": "tech-detect",
                "info": {"name": "Technology Detection", "severity": "info", "tags": ["tech"]},
                "type": "http",
                "host": "https://example.com",
                "matched-at": "https://example.com",
                "extracted-results": ["nginx"],
            }
        ),
        json.dumps(
            {
                "template-id": "CVE-2021-99999",
                "info": {
                    "name": "Example RCE",
                    "severity": "critical",
                    "classification": {"cwe-id": ["CWE-77"]},
                    "remediation": "Upgrade to the patched release.",
                },
                "matched-at": "https://example.com/api?q=1",
                "matcher-name": "status-code",
            }
        ),
        "   ",  # blank line -> skipped
        "{not-valid-json",  # malformed -> skipped
    ]
)


def test_parse_maps_core_fields():
    findings = NucleiAdapter().parse(SAMPLE_JSONL)
    assert len(findings) == 2

    info_finding = findings[0]
    assert info_finding.engine == "nuclei"
    assert info_finding.vuln_type == "tech-detect"
    assert info_finding.severity is Severity.INFO
    assert info_finding.title == "Technology Detection"
    assert info_finding.location == "https://example.com"
    assert "nginx" in (info_finding.evidence or "")


def test_parse_maps_classification_and_remediation():
    finding = NucleiAdapter().parse(SAMPLE_JSONL)[1]
    assert finding.severity is Severity.CRITICAL
    assert finding.cwe_id == "CWE-77"
    assert finding.remediation == "Upgrade to the patched release."
    assert finding.location == "https://example.com/api?q=1"


def test_parse_skips_blank_and_malformed_lines():
    # Two valid lines remain out of the four supplied.
    assert len(NucleiAdapter().parse(SAMPLE_JSONL)) == 2


def test_unknown_severity_degrades_to_info():
    line = json.dumps(
        {"template-id": "x", "info": {"name": "X", "severity": "weird"}, "matched-at": "http://h"}
    )
    assert NucleiAdapter().parse(line)[0].severity is Severity.INFO


def test_is_available_false_when_binary_missing():
    assert NucleiAdapter(binary="definitely-not-a-real-binary-xyz").is_available() is False


def test_is_available_true_when_binary_present():
    # Use the running Python interpreter as a stand-in for an installed binary.
    assert NucleiAdapter(binary=sys.executable).is_available() is True
