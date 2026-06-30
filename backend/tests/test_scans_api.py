"""Tests for scan submission and status (the consent gate + queued creation)."""

import pytest

from app import orchestrator


@pytest.fixture(autouse=True)
def _no_orchestrator(monkeypatch):
    """Keep these tests deterministic: don't actually run the background job."""
    monkeypatch.setattr(orchestrator, "schedule_scan", lambda *args, **kwargs: None)


def test_post_scan_without_consent_field_is_rejected(client):
    response = client.post(
        "/api/scans", json={"target": "https://example.com", "scan_type": "dast"}
    )
    assert response.status_code == 422


def test_post_scan_with_consent_false_is_rejected(client):
    response = client.post(
        "/api/scans",
        json={"target": "https://example.com", "scan_type": "dast", "authorized": False},
    )
    assert response.status_code == 422


def test_post_scan_with_consent_creates_queued_scan(client):
    response = client.post(
        "/api/scans",
        json={"target": "https://example.com", "scan_type": "dast", "authorized": True},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["id"] > 0
    assert body["status"] == "queued"
    assert body["progress"] == 0
    assert body["scan_type"] == "dast"


def test_post_dast_scan_rejects_non_url_target(client):
    response = client.post(
        "/api/scans",
        json={"target": "not-a-url", "scan_type": "dast", "authorized": True},
    )
    assert response.status_code == 422


def test_get_scan_returns_status_and_progress(client):
    created = client.post(
        "/api/scans",
        json={"target": "https://example.com", "scan_type": "dast", "authorized": True},
    ).json()

    response = client.get(f"/api/scans/{created['id']}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["status"] == "queued"
    assert body["progress"] == 0


def test_get_unknown_scan_returns_404(client):
    assert client.get("/api/scans/999999").status_code == 404
