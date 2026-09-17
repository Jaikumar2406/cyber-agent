"""State Manager - per-scan structured investigation state (architecture §22).

The durable copy lives in the `investigations` row (JSONB `state`); this class
is the in-memory working view plus persistence helpers. Everything here is
JSON-serializable so checkpoints/resume work without schema loss.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.investigation import Investigation

log = get_logger("aegis.harness.state")


class InvestigationNotFoundError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class InvestigationState:
    """Mutable per-scan state container keyed by scan_id."""

    def __init__(self, *, scan_id: str, target_url: str | None, target_repo: str | None,
                 user: str | None) -> None:
        self.scan_id = scan_id
        self.data: dict[str, Any] = {
            "scan_id": scan_id,
            "target_url": target_url,
            "target_repo": target_repo,
            "mode": None,
            "plan": {},
            "task_graph": {"nodes": {}, "edges": [], "status": "DRAFT"},
            "current_task": None,
            "agent_states": {},
            "tool_calls": [],
            "evidence": [],  # references, not copies (rules.md §5.6)
            "findings": [],
            "graph_entities": [],
            "correlations": [],
            "risk_results": [],
            "artifacts": [],
            "errors": [],
            "budgets": {},
            "user": user,
            "status": "CREATED",
            "created_at": _now(),
            "updated_at": _now(),
        }

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.data[key] = value
        self.data["updated_at"] = _now()

    def record_tool_call(self, entry: dict[str, Any]) -> None:
        self.data["tool_calls"].append(entry)

    def add_evidence_ref(self, evidence_id: str) -> None:
        self.data["evidence"].append({"evidence_id": evidence_id, "created_at": _now()})


class StateManager:
    def __init__(self, session_factory=None) -> None:
        from app.core.db import get_session_factory

        self._session_factory = session_factory or get_session_factory()

    async def create(self, *, state: InvestigationState) -> str:
        row = Investigation(
            id=uuid.UUID(state.scan_id),
            target_url=state.data["target_url"],
            target_repo=state.data["target_repo"],
            mode=state.data.get("mode"),
            status=state.data["status"],
            user=state.data.get("user"),
            state=state.data,
        )
        async with self._session_factory() as session:
            session.add(row)
            await session.commit()
        log.info("state.created", scan_id=state.scan_id)
        return state.scan_id

    async def update(self, state: InvestigationState) -> None:
        state.data["updated_at"] = _now()
        async with self._session_factory() as session:
            row = await session.get(Investigation, uuid.UUID(state.scan_id))
            if row is None:
                raise InvestigationNotFoundError(state.scan_id)
            row.state = state.data
            row.status = state.data["status"]
            row.mode = state.data.get("mode")
            await session.commit()

    async def load(self, scan_id: str) -> InvestigationState:
        async with self._session_factory() as session:
            row = await session.get(Investigation, uuid.UUID(scan_id))
            if row is None:
                raise InvestigationNotFoundError(scan_id)
            return StateManager._from_row(row)

    @staticmethod
    def _from_row(row: Investigation) -> InvestigationState:
        state = InvestigationState(
            scan_id=str(row.id),
            target_url=row.target_url,
            target_repo=row.target_repo,
            user=row.user,
        )
        state.data.update(row.state or {})
        return state

    async def get(self, scan_id: str) -> InvestigationState:
        async with self._session_factory() as session:
            row = await session.get(Investigation, uuid.UUID(scan_id))
            if row is None:
                raise InvestigationNotFoundError(scan_id)
            return StateManager._from_row(row)

    async def set_status(self, scan_id: str, status: str) -> None:
        state = await self.get(scan_id)
        state["status"] = status
        await self.update(state)