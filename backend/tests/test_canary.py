"""Phase 1.1 - local ephemeral SSRF canary tests (rules.md §3.5).

The canary binds a loopback interface only, records hits with full HTTP detail,
and must refuse any non-loopback bind.
"""

import httpx
import pytest

from app.control_plane.canary import CanaryHostError, SsrfCanary


def test_canary_binds_loopback_only():
    with pytest.raises(CanaryHostError):
        SsrfCanary(host="0.0.0.0")  # must never bind externally
    with pytest.raises(CanaryHostError):
        SsrfCanary(host="10.0.0.5")


def test_canary_records_hit_end_to_end():
    canary = SsrfCanary()
    canary.start()
    try:
        assert canary.origin[0] == "127.0.0.1"
        assert canary.origin[1] > 0
        resp = httpx.get(f"{canary.base_url}/cb?ref=aegis-test", timeout=3.0)
        assert resp.status_code == 200
        assert resp.text == "canary:ok"

        hits = canary.hits()
        assert len(hits) == 1
        hit = hits[0]
        assert hit.path == "/cb?ref=aegis-test"
        assert hit.method == "GET"
        assert hit.remote_addr in {"127.0.0.1", "::1"}
        assert any(k.lower() == "host" for k in hit.headers)  # full header capture
    finally:
        canary.stop()
    assert canary.hits()  # records survive shutdown while the object lives


def test_canary_is_single_hit_based_on_request():
    canary = SsrfCanary()
    canary.start()
    try:
        httpx.get(f"{canary.base_url}/one", timeout=3.0)
        httpx.post(f"{canary.base_url}/two", timeout=3.0)
        assert [h.path for h in canary.hits()] == ["/one", "/two"]
        assert canary.hits()[1].method == "POST"
    finally:
        canary.stop()


async def test_canary_waits_for_hit():
    import asyncio

    import httpx

    canary = SsrfCanary()
    canary.start()
    try:
        async def ping():
            await asyncio.sleep(0.1)
            httpx.get(f"{canary.base_url}/async-hook", timeout=3.0)

        await ping()
        hit = await canary.wait_for_hit(timeout=2.0)
        assert hit is not None
        assert hit.path == "/async-hook"
    finally:
        canary.stop()