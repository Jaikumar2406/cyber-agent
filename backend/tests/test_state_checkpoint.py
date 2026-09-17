"""State/checkpoint persistence tests - exit criterion #2:
"investigation state persists to PostgreSQL [our source of truth] and can be
checkpointed/resumed". SQLite exercises the same ORM path the asyncpg driver
will use in Docker."""

import uuid

import pytest

from app.harness.checkpoint_manager import CheckpointManager
from app.harness.state_manager import InvestigationNotFoundError, InvestigationState, StateManager


@pytest.fixture
def sm(session_factory):
    return StateManager(session_factory=session_factory)


async def test_state_created_and_reloaded(sm):
    scan_id = str(uuid.uuid4())
    state = InvestigationState(scan_id=scan_id, target_url="https://example.com/", target_repo=None, user="admin")
    state["mode"] = "MODE_1"
    state["status"] = "RUNNING"
    await sm.create(state=state)

    loaded = await sm.get(scan_id)
    assert loaded.scan_id == scan_id
    assert loaded["mode"] == "MODE_1"
    assert loaded["status"] == "RUNNING"
    assert loaded["target_url"] == "https://example.com/"


async def test_state_update_persists(sm):
    scan_id = str(uuid.uuid4())
    state = InvestigationState(scan_id=scan_id, target_url=None, target_repo=None, user="admin")
    await sm.create(state=state)

    state["status"] = "COMPLETED"
    state["task_graph"] = {"nodes": {"a": {"status": "COMPLETED"}}}
    state.record_tool_call({"tool": "echo", "status": "SUCCESS"})
    await sm.update(state)

    loaded = await sm.get(scan_id)
    assert loaded["status"] == "COMPLETED"
    assert loaded["task_graph"]["nodes"]["a"]["status"] == "COMPLETED"
    assert len(loaded["tool_calls"]) == 1


async def test_missing_investigation_raises(sm):
    with pytest.raises(InvestigationNotFoundError):
        await sm.get(uuid.uuid4().hex)


async def test_full_resume_sequence(sm, session_factory):
    """create -> checkpoint stage -> 'crash' -> reload + resume from checkpoint."""
    scan_id = str(uuid.uuid4())
    state = InvestigationState(scan_id=scan_id, target_url="https://example.com/", target_repo=None, user="admin")
    state["mode"] = "MODE_1"
    state["status"] = "RUNNING"
    await sm.create(state=state)

    cm = CheckpointManager(session_factory=session_factory)
    await cm.save(scan_id, "runtime.discovery", {"endpoints": ["/", "/api/users"]})
    await cm.save(scan_id, "runtime.auth", {"identities": ["user_a", "user_b"]})

    # Simulated restart: fresh StateManager loads durable state from DB.
    fresh = StateManager(session_factory=session_factory)
    recovered = await fresh.load(scan_id)
    assert recovered["mode"] == "MODE_1"
    assert recovered["status"] == "RUNNING"

    # Resume from the latest persisted checkpoint.
    latest = await cm.latest_stage(scan_id)
    checkpoint_state = await cm.load(scan_id, latest)
    assert latest == "runtime.auth"
    assert checkpoint_state["identities"] == ["user_a", "user_b"]