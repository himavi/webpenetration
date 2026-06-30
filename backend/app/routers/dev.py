"""TEMPORARY developer routes to seed and fetch sample data.

These exist only so the data layer is demoable now (Task 2): seed a sample
finding and fetch it back through the API. They are not part of the real API
surface and will be removed once scan submission and the orchestrator land.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from app.database import get_session
from app.models import Finding, Scan, ScanType, Severity
from app.schemas import FindingRead, ScanRead, ScanWithFindings, SeedResponse

router = APIRouter(prefix="/api/dev", tags=["dev (temporary)"])

# A representative finding so the demo shows a fully-populated shape.
SAMPLE_FINDING = {
    "engine": "nuclei",
    "vuln_type": "reflected-xss",
    "severity": Severity.HIGH,
    "title": "Reflected XSS in search parameter",
    "location": "https://example.com/search?q=test",
    "affected_param": "q",
    "evidence": "Payload <script>alert(1)</script> reflected unencoded in the response body.",
    "cwe_id": "CWE-79",
    "owasp_category": "A03:2021-Injection",
    "remediation": "Contextually output-encode user input and apply a strict Content-Security-Policy.",
}


@router.post("/seed", response_model=SeedResponse, status_code=status.HTTP_201_CREATED)
def seed_sample(session: Session = Depends(get_session)) -> SeedResponse:
    """Create a sample DAST scan with one finding and return both."""
    scan = Scan(target="https://example.com", scan_type=ScanType.DAST)
    scan.findings.append(Finding(**SAMPLE_FINDING))
    session.add(scan)
    session.commit()
    session.refresh(scan)
    finding = scan.findings[0]
    return SeedResponse(
        scan=ScanRead.model_validate(scan),
        finding=FindingRead.model_validate(finding),
    )


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: int, session: Session = Depends(get_session)) -> Finding:
    """Fetch a single finding by id."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return finding


@router.get("/scans/{scan_id}", response_model=ScanWithFindings)
def get_scan(scan_id: int, session: Session = Depends(get_session)) -> Scan:
    """Fetch a scan together with its related findings."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    # Touch the relationship so it loads while the session is still open.
    _ = scan.findings
    return scan
