"""Audit Logger (rules.md §7.1-7.2).

Append-only structured records in PostgreSQL. Every tool call, permission
decision, and state transition is recorded with all required fields; a record
missing a mandatory field is a bug. Rows are never updated or deleted - the
PostgreSQL triggers in scripts/db_init.sql enforce this at the DB level.
"""

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.audit import AuditRecord

log = get_logger("aegis.harness.audit")

# Fields that must ALWAYS be populated per rules.md §7.2. user/scan_id/tool/
# target/evidence_ref/retry_info may be legitimately absent in some flows and
# are nullable in the schema; the core verdict fields never are.
MANDATORY_KEYS = {"agent", "action", "result"}


@dataclass
class AuditEvent:
    user: str | None
    scan_id: str | None
    agent: str
    tool: str | None = None
    target: str | None = None
    action: str = ""
    permission_decision: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    result: str = "PENDING"
    evidence_ref: str | None = None
    retry_info: dict[str, Any] | None = None


class AuditLogger:
    def __init__(self, session_factory=None) -> None:
        from app.core.db import get_session_factory  # local import avoids cycles

        self._session_factory = session_factory or get_session_factory()

    async def log(self, event: AuditEvent) -> str:
        """Persist one immutably-stored audit record; returns event id."""
        missing = MANDATORY_KEYS - {k for k in MANDATORY_KEYS if getattr(event, k)}
        if missing:
            raise ValueError(f"audit event missing required fields: {missing}")

        record_id = uuid.uuid4()
        record = AuditRecord(
            id=record_id,
            user=event.user,
            scan_id=event.scan_id,
            agent=event.agent,
            tool=event.tool,
            target=event.target,
            action=event.action,
            permission_decision=event.permission_decision,
            reason=event.reason,
            result=event.result,
            evidence_ref=event.evidence_ref,
            retry_info=event.retry_info,
        )
        async with self._session_factory() as session:
            session.add(record)
            await session.commit()
        log.info("audit.written", event_id=str(record_id), action=event.action, result=event.result)
        return str(record_id)

    async def record_tool_call(
        self,
        *,
        user: str | None,
        scan_id: str | None,
        agent: str,
        tool: str,
        target: str | None,
        action: str,
        allowed: bool,
        decision_reason: str,
        result: str,
        requires_approval: bool = False,
        evidence_ref: str | None = None,
        retry_info: dict[str, Any] | None = None,
    ) -> str:
        return await self.log(
            AuditEvent(
                user=user,
                scan_id=scan_id,
                agent=agent,
                tool=tool,
                target=target,
                action=action,
                permission_decision={
                    "allowed": allowed,
                    "reason": decision_reason,
                    "requires_approval": requires_approval,
                },
                reason=decision_reason,
                result=result,
                evidence_ref=evidence_ref,
                retry_info=retry_info,
            )
        )

    async def list_recent(self, session: AsyncSession, limit: int = 200) -> list[AuditRecord]:
        result = await session.execute(select(AuditRecord).order_by(AuditRecord.created_at.desc()).limit(limit))
        return list(result.scalars().all())

    async def count(self, session: AsyncSession) -> int:
        from sqlalchemy import func

        result = await session.execute(select(func.count(AuditRecord.id)))
        return int(result.scalar_one())