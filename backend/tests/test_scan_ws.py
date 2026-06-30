"""Integration test: live progress streams over the WebSocket until done."""


def test_ws_streams_progress_until_done(client, monkeypatch):
    # A delay so the socket can observe the running state before completion
    # (with no engines installed in tests, the scan otherwise finishes at once).
    monkeypatch.setenv("SCAN_STEP_DELAY", "0.2")

    created = client.post(
        "/api/scans",
        json={"target": "https://example.com", "scan_type": "dast", "authorized": True},
    ).json()
    scan_id = created["id"]

    statuses = []
    last = None
    with client.websocket_connect(f"/api/scans/{scan_id}/ws") as ws:
        while True:
            message = ws.receive_json()
            statuses.append(message["status"])
            last = message
            if message["status"] in ("done", "failed"):
                break

    assert "running" in statuses
    assert last["status"] == "done"
    assert last["progress"] == 100
