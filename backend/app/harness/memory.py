"""Memory Manager (architecture §22).

Short-term memory = current investigation context (already stored in State).
Persistent memory = cross-scan metadata (asset metadata, remediation history)
in PostgreSQL. Phase 0: thin read/write over the investigations table plus a
placeholder contract; the "evidence is references not copies" rule (§5.6) is
enforced in StateManager and EvidenceNormalizer.
"""

from sqlalchemy import select

from app.core.logging import get_logger
from app.models.investigation import Investigation

log = get_logger("aegis.harness.memory")


class MemoryManager:
    """Persistent, cross-scan memory. Raw secrets/repo text are never stored
    (rules.md §5.5/§5.6); only metadata and evidence references."""

    def __init__(self, session_factory=None) -> None:
        from app.core.db import get_session_factory

        self._session_factory = session_factory or get_session_factory()

    async def remember_asset(self, *, host: str, discovered_at: str) -> None:
        """Stub contract - Phase 1+ seeds a real asset/metadata table."""
        log.info("memory.remember_asset", host=host, discovered_at=discovered_at)

    async def historical_scans_for_target(self, host: str) -> list[dict]:
        """Stub: return prior scan ids for a target (metadata only)."""
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(Investigation).where(Investigation.target_url.contains(host))
            )
            return [
                {"scan_id": str(r.id), "status": r.status, "mode": r.mode, "created_at": str(r.created_at)}
                for r in rows
            ]