"""Evidence Normalizer tests - common-schema contract + dedup."""

import pytest
from pydantic import ValidationError

from app.evidence.normalizer import EvidenceNormalizer
from app.schemas.evidence import EvidenceInput


@pytest.fixture
def normalizer(session_factory):
    return EvidenceNormalizer(session_factory=session_factory)


def test_schema_rejects_unknown_source():
    with pytest.raises(ValidationError):
        EvidenceInput(source="NOT_A_SOURCE", evidence_type="x")


async def test_add_persists(normalizer, db_tables):
    from app.core.db import get_session_factory
    from app.core.orchestrator import Phase0Orchestrator
    import uuid as _uuid
    from app.harness.state_manager import InvestigationState, StateManager

    scan_id = str(_uuid.uuid4())
    st = InvestigationState(scan_id=scan_id, target_url="https://example.com/", target_repo=None, user="admin")
    await StateManager(session_factory=get_session_factory()).create(state=st)

    record = await normalizer.add(
        scan_id=scan_id,
        source="RUNTIME",
        evidence_type="http.observation",
        confidence="CONFIRMED",
        location={"endpoint": "/api/users/{id}", "method": "GET"},
        payload={"status": 200, "user_a": "accessed_user_b"},
    )
    assert record.investigation_id is not None
    assert record.confidence == "CONFIRMED"
    assert record.dedup_key


async def test_dedup_returns_same_record(normalizer, db_tables):
    from app.core.db import get_session_factory
    import uuid as _uuid
    from app.harness.state_manager import InvestigationState, StateManager

    scan_id = str(_uuid.uuid4())
    st = InvestigationState(scan_id=scan_id, target_url="https://example.com/", target_repo=None, user="admin")
    await StateManager(session_factory=get_session_factory()).create(state=st)

    payload = {"echo": "same", "seq": 1}
    first = await normalizer.add(
        scan_id=scan_id, source="HARNESS", evidence_type="tool:echo", payload=payload
    )
    second = await normalizer.add(
        scan_id=scan_id, source="HARNESS", evidence_type="tool:echo", payload=payload
    )
    assert first.id == second.id