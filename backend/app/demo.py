"""Demo mode: scope allowlist and sample report seeding.

When DEMO_MODE=1 the app restricts scanning to an allowlist of safe targets
(the bundled Juice Shop and localhost) and seeds a sample completed scan with
findings so recruiters can view a report immediately without running a live scan.
"""

import os

DEMO_MODE = os.getenv("DEMO_MODE", "").strip() in ("1", "true", "yes")

# The single target permitted in demo mode. Defaults to the bundled Juice Shop
# (docker-compose); the all-in-one Spaces image sets this to the app's own URL
# so a recruiter can run a real (self) scan in a single free container.
DEMO_TARGET = os.getenv("DEMO_TARGET", "http://juiceshop:3000")

# Targets allowed in demo mode. Only the bundled Juice Shop (by compose service
# name and common aliases) and localhost are permitted.
DEMO_ALLOWLIST = [
    "http://juiceshop",
    "http://juiceshop:3000",
    "http://localhost",
    "http://localhost:",
    "http://127.0.0.1",
]


def is_target_allowed(target: str) -> bool:
    """Return True if the target is permitted under the current mode."""
    if not DEMO_MODE:
        return True
    low = target.lower().strip()
    prefixes = DEMO_ALLOWLIST + [DEMO_TARGET.lower().strip()]
    return any(low.startswith(prefix) for prefix in prefixes)


def seed_sample_data():
    """Insert a pre-built scan + findings + report if the DB is empty.

    Called once at startup when DEMO_MODE is on so a recruiter can immediately
    view a professional report without waiting for a live scan.
    """
    if not DEMO_MODE:
        return

    from app.database import engine as db_engine
    from app.models import Finding, Report, ReportFormat, Scan, ScanStatus, ScanType, Severity
    from sqlmodel import Session, select

    with Session(db_engine) as session:
        existing = session.exec(select(Scan)).first()
        if existing is not None:
            return  # already seeded or user ran a scan

        scan = Scan(
            target="http://juiceshop:3000",
            scan_type=ScanType.DAST,
            status=ScanStatus.DONE,
            progress=100,
            message="done",
        )
        session.add(scan)
        session.flush()

        sample_findings = [
            Finding(
                scan_id=scan.id,
                engine="nuclei",
                vuln_type="xss-reflected",
                severity=Severity.HIGH,
                title="Reflected XSS in search parameter",
                location="http://juiceshop:3000/#/search?q=<script>alert(1)</script>",
                affected_param="q",
                evidence="Payload reflected unencoded in response body.",
                cwe_id="CWE-79",
                owasp_category="A03:2021-Injection",
                remediation="Contextually output-encode user input.",
                explanation="Cross-site scripting (XSS) lets an attacker inject script that runs in other users' browsers.",
                impact="Session hijacking, credential theft, or defacement.",
                ai_remediation="Apply context-aware output encoding and a strict Content-Security-Policy.",
            ),
            Finding(
                scan_id=scan.id,
                engine="zap",
                vuln_type="sql-injection",
                severity=Severity.CRITICAL,
                title="SQL Injection in login endpoint",
                location="http://juiceshop:3000/rest/user/login",
                affected_param="email",
                evidence="' OR 1=1-- returned 200 with admin session",
                cwe_id="CWE-89",
                owasp_category="A03:2021-Injection",
                remediation="Use parameterized queries.",
                explanation="SQL injection allows arbitrary database queries.",
                impact="Full database compromise, authentication bypass.",
                ai_remediation="Replace string concatenation with parameterized/prepared statements.",
            ),
            Finding(
                scan_id=scan.id,
                engine="nikto",
                vuln_type="nikto-server-info",
                severity=Severity.LOW,
                title="Server version disclosed in headers",
                location="http://juiceshop:3000/",
                cwe_id="CWE-200",
                owasp_category="A05:2021-Security Misconfiguration",
                remediation="Remove or suppress server version banners.",
                explanation="The server discloses its software version in HTTP headers.",
                impact="Aids attacker reconnaissance for targeted exploits.",
                ai_remediation="Configure the web server to suppress version information.",
            ),
            Finding(
                scan_id=scan.id,
                engine="auth-checks",
                vuln_type="missing-security-headers",
                severity=Severity.MEDIUM,
                title="Missing Content-Security-Policy header",
                location="http://juiceshop:3000/",
                cwe_id="CWE-693",
                owasp_category="A05:2021-Security Misconfiguration",
                remediation="Add a strict Content-Security-Policy header.",
                explanation="A protective HTTP security header is missing.",
                impact="Makes XSS and injection attacks easier to exploit.",
                ai_remediation="Define a restrictive CSP that blocks inline scripts and restricts sources.",
            ),
        ]
        session.add_all(sample_findings)
        session.flush()

        # Generate and persist the JSON report so it's instantly downloadable.
        from app.reports import build_report_data, render_html

        data = build_report_data(scan, sample_findings)
        import json

        session.add(Report(scan_id=scan.id, format=ReportFormat.JSON, payload=json.dumps(data, indent=2)))
        session.add(Report(scan_id=scan.id, format=ReportFormat.HTML, payload=render_html(data)))
        session.commit()
