"""Tests for the normalized finding schema validation."""

import pytest
from pydantic import ValidationError

from app.models import Severity
from app.schemas import NormalizedFinding


def test_accepts_valid_finding_and_coerces_severity():
    finding = NormalizedFinding(
        engine="nuclei", vuln_type="reflected-xss", severity="high", title="XSS"
    )
    assert finding.severity is Severity.HIGH
    assert finding.location is None


def test_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        NormalizedFinding(
            engine="nuclei", vuln_type="reflected-xss", severity="catastrophic", title="XSS"
        )


def test_rejects_missing_required_fields():
    with pytest.raises(ValidationError):
        # missing vuln_type and title
        NormalizedFinding(engine="nuclei", severity="high")


def test_rejects_empty_required_string():
    with pytest.raises(ValidationError):
        NormalizedFinding(engine="nuclei", vuln_type="reflected-xss", severity="high", title="")


def test_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        NormalizedFinding(
            engine="nuclei",
            vuln_type="reflected-xss",
            severity="high",
            title="XSS",
            bogus="nope",
        )
