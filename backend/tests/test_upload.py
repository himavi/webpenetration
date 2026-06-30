"""Tests for the secure source zip upload endpoint."""

import io
import zipfile

import pytest

from app import orchestrator


@pytest.fixture(autouse=True)
def _no_orchestrator(monkeypatch):
    monkeypatch.setattr(orchestrator, "schedule_scan", lambda *a, **kw: None)


def _make_zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf


def test_upload_creates_sast_scan(client):
    zf = _make_zip({"main.py": "print('hello')"})
    resp = client.post(
        "/api/scans/upload",
        files={"file": ("source.zip", zf, "application/zip")},
        data={"target": "my-app", "scan_type": "sast", "authorized": "true"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["scan_type"] == "sast"
    assert body["status"] == "queued"


def test_upload_rejects_missing_consent(client):
    zf = _make_zip({"x.py": ""})
    resp = client.post(
        "/api/scans/upload",
        files={"file": ("source.zip", zf, "application/zip")},
        data={"target": "app", "authorized": "false"},
    )
    assert resp.status_code == 422


def test_upload_rejects_non_zip(client):
    resp = client.post(
        "/api/scans/upload",
        files={"file": ("code.tar.gz", io.BytesIO(b"not a zip"), "application/gzip")},
        data={"authorized": "true"},
    )
    assert resp.status_code == 400


def test_upload_rejects_zip_slip(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0")
    buf.seek(0)
    resp = client.post(
        "/api/scans/upload",
        files={"file": ("evil.zip", buf, "application/zip")},
        data={"authorized": "true"},
    )
    assert resp.status_code == 400
    assert "zip-slip" in resp.json()["detail"].lower() or "Zip-slip" in resp.json()["detail"]
