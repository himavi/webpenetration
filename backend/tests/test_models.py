"""Tests for the SQLModel data layer: create and query a Scan with Findings."""

from app.models import Finding, Report, ReportFormat, Scan, ScanStatus, ScanType, Severity


def test_create_and_query_scan_with_findings(session):
    scan = Scan(target="https://victim.test", scan_type=ScanType.DAST)
    scan.findings.append(
        Finding(engine="nuclei", vuln_type="reflected-xss", severity=Severity.HIGH, title="XSS")
    )
    scan.findings.append(
        Finding(engine="zap", vuln_type="csrf", severity=Severity.MEDIUM, title="Missing CSRF token")
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    assert scan.id is not None
    # status defaults to QUEUED even though we never set it explicitly.
    assert scan.status == ScanStatus.QUEUED
    assert scan.created_at is not None

    fetched = session.get(Scan, scan.id)
    assert len(fetched.findings) == 2
    assert {f.vuln_type for f in fetched.findings} == {"reflected-xss", "csrf"}
    # severities round-trip back into the enum type.
    assert all(isinstance(f.severity, Severity) for f in fetched.findings)
    # the back-reference resolves to the owning scan.
    assert fetched.findings[0].scan.id == scan.id


def test_enum_columns_persist_lowercase_values(session):
    scan = Scan(target="https://victim.test", scan_type=ScanType.SAST)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # Raw stored values are the lowercase enum values, matching the JSON API.
    row = session.connection().exec_driver_sql(
        "SELECT scan_type, status FROM scan WHERE id = ?", (scan.id,)
    ).first()
    assert row == ("sast", "queued")


def test_report_links_to_scan(session):
    scan = Scan(target="https://victim.test", scan_type=ScanType.DAST)
    scan.reports.append(Report(format=ReportFormat.JSON, payload="{}"))
    session.add(scan)
    session.commit()
    session.refresh(scan)

    assert len(scan.reports) == 1
    assert scan.reports[0].format == ReportFormat.JSON
    assert scan.reports[0].scan_id == scan.id
