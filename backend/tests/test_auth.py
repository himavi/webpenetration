"""Tests for credential checks and signed bearer tokens."""

import time

import pytest

from app import auth


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setenv("APP_USERNAME", "recruiter")
    monkeypatch.setenv("APP_PASSWORD", "s3cret")
    monkeypatch.delenv("APP_SECRET", raising=False)


def test_auth_required_reflects_password(monkeypatch):
    monkeypatch.delenv("APP_PASSWORD", raising=False)
    assert auth.auth_required() is False
    monkeypatch.setenv("APP_PASSWORD", "x")
    assert auth.auth_required() is True


def test_check_credentials(creds):
    assert auth.check_credentials("recruiter", "s3cret")
    assert not auth.check_credentials("recruiter", "nope")
    assert not auth.check_credentials("intruder", "s3cret")


def test_token_roundtrip(creds):
    token = auth.issue_token("recruiter")
    assert auth.verify_token(token)


def test_token_rejects_tampering(creds):
    token = auth.issue_token("recruiter")
    assert not auth.verify_token(token + "x")
    assert not auth.verify_token("garbage")
    assert not auth.verify_token("")


def test_token_expiry(creds):
    expired = auth.issue_token("recruiter", ttl=-1)
    assert not auth.verify_token(expired)


def test_token_invalid_after_secret_change(creds, monkeypatch):
    token = auth.issue_token("recruiter")
    monkeypatch.setenv("APP_PASSWORD", "rotated")
    assert not auth.verify_token(token)


def test_gating_rules():
    assert auth._is_gated("/api/scans")
    assert auth._is_gated("/api/config")
    assert auth._is_gated("/docs")
    assert not auth._is_gated("/health")
    assert not auth._is_gated("/api/auth/login")
    assert not auth._is_gated("/")
    assert not auth._is_gated("/assets/index.js")


def test_login_endpoint(client, monkeypatch):
    monkeypatch.setenv("APP_USERNAME", "recruiter")
    monkeypatch.setenv("APP_PASSWORD", "s3cret")
    ok = client.post("/api/auth/login", json={"username": "recruiter", "password": "s3cret"})
    assert ok.status_code == 200
    assert auth.verify_token(ok.json()["token"])

    bad = client.post("/api/auth/login", json={"username": "recruiter", "password": "wrong"})
    assert bad.status_code == 401


def test_status_endpoint(client):
    resp = client.get("/api/auth/status")
    assert resp.status_code == 200
    assert "auth_required" in resp.json()
