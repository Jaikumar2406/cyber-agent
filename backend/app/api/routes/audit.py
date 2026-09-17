"""Audit trail API (read-only; records are immutable by design)."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, session_factory_from
from app.control_plane.auth import require_api_key
from app.harness.audit_logger import AuditLogger
from app.models.audit import AuditRecord
from app.schemas.scan import AuditEntryResponse

router = APIRouter(prefix="/audit", tags=["audit"], dependencies=[Depends(require_api_key)])


def _to_response(r: AuditRecord) -> AuditEntryResponse:
    return AuditEntryResponse(
        id=r.id,
        user=r.user,
        scan_id=r.scan_id,
        agent=r.agent,
        tool=r.tool,
        target=r.target,
        action=r.action,
        permission_decision=r.permission_decision or {},
        reason=r.reason,
        result=r.result,
        created_at=r.created_at,
    )


@router.get("", response_model=list[AuditEntryResponse])
async def list_audit(limit: int = 200, session: AsyncSession = Depends(db_session)) -> list[AuditEntryResponse]:
    logger = AuditLogger(session_factory=session_factory_from(session))
    rows = await logger.list_recent(session, limit=limit)
    return [_to_response(r) for r in rows]


@router.get("/count")
async def count_audit(session: AsyncSession = Depends(db_session)) -> dict:
    logger = AuditLogger(session_factory=session_factory_from(session))
    return {"count": await logger.count(session)}