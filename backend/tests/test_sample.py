"""The example report is public; everything else stays behind the login."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def gated_client(monkeypatch):
    monkeypatch.setenv("APP_USERNAME", "recruiter")
    monkeypatch.setenv("APP_PASSWORD", "s3cret")
    with TestClient(app) as client:
        yield client


def test_sample_report_is_public(gated_client):
    res = gated_client.get("/api/sample")
    assert res.status_code == 200
    body = res.json()
    assert body["scan"]["status"] == "done" and body["scan"]["id"] is None
    assert len(body["findings"]) == 4
    assert {f["severity"] for f in body["findings"]} >= {"critical", "high", "medium", "low"}

    html = gated_client.get("/api/sample/report.html")
    assert html.status_code == 200 and "<html" in html.text.lower()


def test_scanning_still_requires_login(gated_client):
    assert gated_client.post("/api/scans", json={"target": "http://localhost:7860", "authorized": True}).status_code == 401
    assert gated_client.get("/api/scans/1").status_code == 401
    assert gated_client.get("/api/scans/1/findings").status_code == 401
    assert gated_client.get("/api/scans/1/report.json").status_code == 401
    # Nearby paths are not accidentally opened up.
    assert gated_client.get("/api/sample/../scans/1").status_code in (401, 404)
    assert gated_client.get("/api/samples").status_code == 401
