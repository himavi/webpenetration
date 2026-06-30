"""Tests for the AI explanation service (LLM + template fallback + cache)."""

from types import SimpleNamespace

from app import explainer


def _finding(**kwargs):
    base = {
        "engine": "nuclei",
        "vuln_type": "x",
        "severity": "medium",
        "title": "Some finding",
        "cwe_id": None,
        "owasp_category": None,
        "evidence": None,
        "remediation": None,
        "explanation": None,
        "impact": None,
        "ai_remediation": None,
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_template_fallback_when_no_key():
    findings = [
        _finding(vuln_type="reflected-xss", cwe_id="CWE-79", title="Reflected XSS"),
        _finding(vuln_type="some-misc", cwe_id=None, title="Generic issue"),
    ]
    explainer.explain_findings(findings)

    xss = findings[0]
    assert xss.explanation and "cross-site scripting" in xss.explanation.lower()
    assert xss.impact
    assert xss.ai_remediation

    generic = findings[1]
    assert generic.explanation  # generic template still populates all fields
    assert generic.impact
    assert generic.ai_remediation


def test_uses_llm_when_key_present(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")

    captured = {"calls": 0}

    def fake_call(reps, provider, timeout=30.0):
        captured["calls"] += 1
        return [
            {"explanation": "LLM explanation", "impact": "LLM impact", "remediation": "LLM fix"}
            for _ in reps
        ]

    monkeypatch.setattr(explainer, "_call_llm", fake_call)

    findings = [_finding(vuln_type="sqli", cwe_id="CWE-89")]
    explainer.explain_findings(findings)

    assert captured["calls"] == 1
    assert findings[0].explanation == "LLM explanation"
    assert findings[0].impact == "LLM impact"
    assert findings[0].ai_remediation == "LLM fix"


def test_cache_avoids_second_call(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    captured = {"calls": 0}

    def fake_call(reps, provider, timeout=30.0):
        captured["calls"] += 1
        return [{"explanation": "e", "impact": "i", "remediation": "r"} for _ in reps]

    monkeypatch.setattr(explainer, "_call_llm", fake_call)

    # Two findings sharing the same (vuln_type, cwe) signature -> one LLM rep.
    first = [_finding(vuln_type="sqli", cwe_id="CWE-89")]
    second = [
        _finding(vuln_type="sqli", cwe_id="CWE-89"),
        _finding(vuln_type="sqli", cwe_id="CWE-89"),
    ]
    explainer.explain_findings(first)
    explainer.explain_findings(second)

    assert captured["calls"] == 1  # cached after the first explanation
    assert all(f.explanation == "e" for f in second)


def test_rate_limit_falls_back_to_template(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")

    def boom(reps, provider, timeout=30.0):
        raise RuntimeError("429 rate limited")

    monkeypatch.setattr(explainer, "_call_llm", boom)

    findings = [_finding(vuln_type="reflected-xss", cwe_id="CWE-79")]
    explainer.explain_findings(findings)

    # Falls back to the XSS template rather than failing.
    assert "cross-site scripting" in findings[0].explanation.lower()


def test_empty_findings_is_noop():
    explainer.explain_findings([])  # should not raise
