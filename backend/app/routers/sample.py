"""Public, read-only example report.

The only API endpoints reachable without signing in (besides auth and health):
they return a fixed example report built in memory, never data from real scans.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app.demo import sample_payload, sample_report_html

router = APIRouter(prefix="/api", tags=["sample"])

PUBLIC_PATHS = ("/api/sample", "/api/sample/report.html")


@router.get("/sample")
def get_sample() -> dict:
    return sample_payload()


@router.get("/sample/report.html", response_class=HTMLResponse)
def get_sample_report_html() -> str:
    return sample_report_html()
