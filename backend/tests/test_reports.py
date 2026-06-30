"""Tests for report generation (data assembly, HTML, JSON, and PDF endpoints)."""

import pytest
from sqlmodel import Session

from app import reports
from app.database import engine
from app.models import Finding, Scan, ScanStatus, ScanType, Severity


def _seed_scan_with_findings() -> int:
    with Session(engine) as session:
        scan = Scan(
            target="https://victim.test",
            scan_type=ScanType.DAST,
            status=ScanStatus.DONE,
            progress=100,
        )
        scan.findings.append(Finding(
            engine="zap", vuln_type="xss", severity=Severity.HIGH, title="Reflected XSS",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection", location="https://victim.test/q",
            explanation="XSS explanation", impact="XSS impact", ai_remediation="Encode output.",
        ))
        scan.findings.append(Finding(
            engine="nuclei", vuln_type="tech", severity=Severity.INFO, title="Tech detected",
        ))
        scan.findings.append(Finding(
            engine="sqlmap", vuln_type="sql-injection", severity=Severity.CRITICAL,
            title="SQL injection", cwe_id="CWE-89", owasp_category="A03:2021-Injection",
        ))
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def _build_data(scan_id: int) -> dict:
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        findings = scan.findings
        return reports.build_report_data(scan, findings)


def test_report_data_severity_summary_counts():
    scan_id = _seed_scan_with_findings()
    data = _build_data(scan_id)
    assert data["total_findings"] == 3
    assert data["severity_summary"]["critical"] == 1
    assert data["severity_summary"]["high"] == 1
    assert data["severity_summary"]["info"] == 1
    assert data["severity_summary"]["medium"] == 0


def test_report_data_owasp_and_cwe_mapping():
    scan_id = _seed_scan_with_findings()
    data = _build_data(scan_id)
    assert data["owasp_summary"]["A03:2021-Injection"] == 2
    assert "CWE-79" in data["cwe_summary"]
    assert "CWE-89" in data["cwe_summary"]
    assert data["executive_summary"]


def test_report_findings_sorted_most_severe_first():
    scan_id = _seed_scan_with_findings()
    data = _build_data(scan_id)
    severities = [f["severity"] for f in data["findings"]]
    assert severities[0] == "critical"


def test_html_report_includes_all_findings():
    scan_id = _seed_scan_with_findings()
    data = _build_data(scan_id)
    html = reports.render_html(data)
    assert "Reflected XSS" in html
    assert "SQL injection" in html
    assert "Tech detected" in html
    assert "XSS explanation" in html
    assert "A03:2021-Injection" in html


def test_json_endpoint_returns_full_report(client):
    scan_id = _seed_scan_with_findings()
    resp = client.get(f"/api/scans/{scan_id}/report.json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_findings"] == 3
    assert len(body["findings"]) == 3


def test_html_endpoint_returns_html(client):
    scan_id = _seed_scan_with_findings()
    resp = client.get(f"/api/scans/{scan_id}/report.html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Security Report" in resp.text


def test_report_endpoints_404_for_unknown_scan(client):
    assert client.get("/api/scans/999999/report.json").status_code == 404


@pytest.mark.skipif(not reports.pdf_available(), reason="WeasyPrint not installed")
def test_pdf_endpoint_generates_pdf(client):
    scan_id = _seed_scan_with_findings()
    resp = client.get(f"/api/scans/{scan_id}/report.pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"


def test_pdf_renderer_unit():
    if not reports.pdf_available():
        pytest.skip("WeasyPrint not installed")
    pdf = reports.render_pdf("<html><body><h1>Hello</h1></body></html>")
    assert pdf[:4] == b"%PDF"
