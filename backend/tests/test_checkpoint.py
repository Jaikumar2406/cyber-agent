"""Checkpoint Manager tests - stage snapshots for resume-from-failure.

Each test uses a unique scan_id to avoid collisions in the shared test DB.
"""

import uuid

import pytest

from app.harness.checkpoint_manager import CheckpointManager


@pytest.fixture
def cm(session_factory):
    return CheckpointManager(session_factory=session_factory)


@pytest.fixture
def scan_id():
    return str(uuid.uuid4())


async def test_save_and_load_stage(cm, scan_id):
    await cm.save(scan_id, "crypto.stage2", {"stage": 2, "assets": ["RSA", "AES"]})
    state = await cm.load(scan_id, "crypto.stage2")
    assert state["stage"] == 2
    assert state["assets"] == ["RSA", "AES"]


async def test_stages_ordered(cm, scan_id):
    await cm.save(scan_id, "runtime.auth", {"done": True})
    await cm.save(scan_id, "runtime.discovery", {"done": True})
    stages = await cm.stages(scan_id)
    assert set(stages) == {"runtime.auth", "runtime.discovery"}


async def test_latest_stage(cm, scan_id):
    await cm.save(scan_id, "a", {})
    await cm.save(scan_id, "b", {})
    assert await cm.latest_stage(scan_id) == "b"


async def test_overwrite_same_stage(cm, scan_id):
    await cm.save(scan_id, "x", {"v": 1})
    await cm.save(scan_id, "x", {"v": 2})
    assert await cm.load(scan_id, "x") == {"v": 2}


async def test_resume_from_latest_stage(cm, scan_id):
    """Mimics a failed Crypto Engine: stages written through stage 3, then
    resume reads stage 3 snapshot to continue, not restart."""
    await cm.save(scan_id, "crypto.stage1", {"collectors_done": ["source"]})
    await cm.save(scan_id, "crypto.stage2", {"collectors_done": ["source", "dependency"]})
    await cm.save(scan_id, "crypto.stage3", {"collectors_done": ["source", "dependency", "certs"]})
    latest = await cm.latest_stage(scan_id)
    resumed = await cm.load(scan_id, latest)
    assert resumed["collectors_done"] == ["source", "dependency", "certs"]