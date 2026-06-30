"""Tests for the health check endpoint."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_200():
    response = client.get("/health")
    assert response.status_code == 200


def test_health_payload_reports_ok():
    response = client.get("/health")
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "ai-pentester-backend"
    assert "version" in body and body["version"]


def test_root_points_to_health_and_docs():
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["health"] == "/health"
    assert body["docs"] == "/docs"
