"""Tests for demo mode: allowlist enforcement and sample seeding."""

import pytest
from unittest.mock import patch


def test_demo_rejects_out_of_scope_target(client):
    """In demo mode, external targets are rejected with 403."""
    with patch("app.demo.DEMO_MODE", True):
        resp = client.post(
            "/api/scans",
            json={"target": "https://evil.com", "scan_type": "dast", "authorized": True},
        )
    assert resp.status_code == 403
    assert "demo mode" in resp.json()["detail"].lower()


def test_demo_allows_juiceshop_target(client):
    """In demo mode, the bundled Juice Shop target is allowed."""
    with patch("app.demo.DEMO_MODE", True):
        resp = client.post(
            "/api/scans",
            json={"target": "http://juiceshop:3000/", "scan_type": "dast", "authorized": True},
        )
    assert resp.status_code == 201


def test_normal_mode_allows_any_target(client):
    """With DEMO_MODE off, any target passes."""
    with patch("app.demo.DEMO_MODE", False):
        resp = client.post(
            "/api/scans",
            json={"target": "https://example.com", "scan_type": "dast", "authorized": True},
        )
    assert resp.status_code == 201


def test_seed_creates_sample_scan():
    """seed_sample_data creates a scan with findings when DB is empty."""
    from app.demo import seed_sample_data
    from app.database import engine
    from app.models import Scan, Finding
    from sqlmodel import Session, select

    with patch("app.demo.DEMO_MODE", True):
        seed_sample_data()

    with Session(engine) as session:
        scans = session.exec(select(Scan)).all()
        assert len(scans) >= 1
        findings = session.exec(select(Finding)).all()
        assert len(findings) >= 4
