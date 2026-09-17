"""Checkpoint Manager (rules.md §6.5).

Saves stage snapshots so scans resume from the last good stage rather than
restarting. Crypto Engine multi-stage pipelines, Runtime/Code agent stages, and
the overall scan lifecycle all write stage checkpoints here.
"""

import json
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.checkpoint import Checkpoint

log = get_logger("aegis.harness.checkpoint")


class CheckpointManager:
    def __init__(self, session_factory=None) -> None:
        from app.core.db import get_session_factory

        self._session_factory = session_factory or get_session_factory()

    async def save(self, scan_id: str, stage: str, state: dict[str, Any]) -> None:
        async with self._session_factory() as session:
            existing = await session.scalar(
                select(Checkpoint).where(Checkpoint.scan_id == scan_id, Checkpoint.stage == stage)
            )
            if existing is not None:
                existing.state = state
            else:
                session.add(Checkpoint(scan_id=scan_id, stage=stage, state=state))
            await session.commit()
        log.info("checkpoint.saved", scan_id=scan_id, stage=stage)

    async def load(self, scan_id: str, stage: str) -> dict | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(Checkpoint).where(Checkpoint.scan_id == scan_id, Checkpoint.stage == stage)
            )
            return json.loads(json.dumps(row.state)) if row else None

    async def stages(self, scan_id: str) -> list[str]:
        async with self._session_factory() as session:
            rows = await session.scalars(select(Checkpoint.stage).where(Checkpoint.scan_id == scan_id))
            return list(rows.all())

    async def latest_stage(self, scan_id: str) -> str | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(Checkpoint.stage)
                .where(Checkpoint.scan_id == scan_id)
                .order_by(Checkpoint.created_at.desc())
                .limit(1)
            )
            return row

    async def delete_checkpoints(self, scan_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(delete(Checkpoint).where(Checkpoint.scan_id == scan_id))
            await session.commit()
        log.info("checkpoint.deleted", scan_id=scan_id)