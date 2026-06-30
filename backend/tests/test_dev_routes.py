"""Tests for the temporary dev seed/fetch routes."""


def test_seed_then_fetch_finding(client):
    seeded = client.post("/api/dev/seed")
    assert seeded.status_code == 201
    body = seeded.json()
    finding_id = body["finding"]["id"]
    scan_id = body["scan"]["id"]
    assert body["finding"]["severity"] == "high"
    assert body["scan"]["scan_type"] == "dast"
    assert body["scan"]["status"] == "queued"

    fetched = client.get(f"/api/dev/findings/{finding_id}")
    assert fetched.status_code == 200
    finding = fetched.json()
    assert finding["id"] == finding_id
    assert finding["scan_id"] == scan_id
    assert finding["cwe_id"] == "CWE-79"
    assert finding["owasp_category"] == "A03:2021-Injection"


def test_seed_scan_includes_findings(client):
    scan_id = client.post("/api/dev/seed").json()["scan"]["id"]

    scan = client.get(f"/api/dev/scans/{scan_id}")
    assert scan.status_code == 200
    body = scan.json()
    assert body["id"] == scan_id
    assert len(body["findings"]) == 1
    assert body["findings"][0]["vuln_type"] == "reflected-xss"


def test_fetch_missing_finding_returns_404(client):
    missing = client.get("/api/dev/findings/999999")
    assert missing.status_code == 404
