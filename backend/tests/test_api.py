"""API integration tests - full HTTP surface through FastAPI/ASGI."""


async def test_health_live(client):
    resp = await client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_health_ready(client, db_tables):
    resp = await client.get("/health/ready")
    assert resp.status_code == 200
    assert resp.json()["services"]["db"] == "up"


async def test_tools_require_auth(client):
    assert (await client.get("/tools")).status_code == 401
    resp = await client.get("/tools", headers={"X-AEGIS-Key": "test-key"})
    assert resp.status_code == 200
    names = [t["name"] for t in resp.json()]
    assert "echo" in names


async def test_create_probe_scan_and_get_state(client, api_headers, db_tables):
    resp = await client.post(
        "/scans",
        json={"target_url": "https://example.com/", "intensity": "passive"},
        headers=api_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["mode"] == "MODE_1"
    assert body["status"] == "COMPLETED"

    scan_id = body["scan_id"]
    state_resp = await client.get(f"/scans/{scan_id}", headers=api_headers)
    assert state_resp.status_code == 200
    state = state_resp.json()
    assert state["status"] == "COMPLETED"
    assert state["mode"] == "MODE_1"
    assert state["state"]["task_graph"]["discovery"]["probe.echo"]["status"] == "COMPLETED"

    checkpoints = await client.get(f"/scans/{scan_id}/checkpoints", headers=api_headers)
    assert checkpoints.status_code == 200
    assert checkpoints.json()["latest"] in {"started", "completed", "failed"}


async def test_scan_requires_auth(client):
    resp = await client.post("/scans", json={"target_url": "https://example.com/"})
    assert resp.status_code == 401


async def test_scan_rejects_no_inputs(client, api_headers):
    resp = await client.post("/scans", json={}, headers=api_headers)
    assert resp.status_code == 422


async def test_probe_scan_writes_audit(client, api_headers, db_tables):
    await client.post(
        "/scans",
        json={"target_url": "https://example.com/", "intensity": "passive"},
        headers=api_headers,
    )
    audit = await client.get("/audit", headers=api_headers)
    assert audit.status_code == 200
    entries = audit.json()
    assert any(e["tool"] == "echo" and e["result"] == "SUCCESS" for e in entries)


async def test_audit_requires_auth(client):
    assert (await client.get("/audit")).status_code == 401