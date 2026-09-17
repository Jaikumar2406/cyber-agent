"""Scan lifecycle API (Phase 1.9: full Mode-1 Deep Agent chain).

POST /scans        -> control plane (auth -> authorization -> policy -> mode)
                       -> deterministic Deep Agent planning -> supervised
                          execution (discovery -> auth -> model -> tests)
                       -> evidence + report
GET  /scans/{id}   -> current investigation state
GET  /scans/{id}/approvals             -> pending/decided human approvals
POST /scans/{id}/approvals/{id}/decision -> operator verdict (Phase 1 exit #5)
POST /scans/{id}/resume                -> explicit resume after approval
GET  /scans/{id}/checkpoints -> stages for resume-from-failure
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, session_factory_from
from app.control_plane.auth import Principal, require_api_key
from app.control_plane.credentials import CredentialCatalog
from app.harness.audit_logger import AuditLogger
from app.harness.checkpoint_manager import CheckpointManager
from app.harness.state_manager import InvestigationNotFoundError, StateManager
from app.planner.orchestrator import DeepAgentOrchestrator, OrchestrationError
from app.schemas.common import ScanStatus
from app.schemas.scan import (
    ApprovalInfo,
    ScanApprovalDecisionRequest,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanResumeRequest,
    ScanStatusResponse,
)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse, status_code=201, dependencies=[Depends(require_api_key)])
async def create_scan(payload: ScanCreateRequest, principal: Principal = Depends(require_api_key)) -> dict:
    if payload.target_url is None and payload.target_repo is None:
        raise HTTPException(status_code=422, detail="supply target_url and/or target_repo")

    try:
        credentials = CredentialCatalog(payload.credentials) if payload.credentials else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid credentials: {exc}") from exc

    try:
        scan_id = await DeepAgentOrchestrator().run_mode1_scan(
            principal=principal.username,
            target_url=payload.target_url,
            target_repo=payload.target_repo,
            intensity=payload.intensity,
            rate_limit_rps=payload.rate_limit_rps,
            allowed_methods=payload.allowed_methods,
            hint_endpoints=payload.hint_endpoints,
            credentials=credentials,
        )
    except OrchestrationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # A scan that paused for a human decision reports that verbatim: the gate is
    # the surface (Phase 1 exit #5), not a hard-coded "COMPLETED".
    state = await StateManager().get(scan_id)
    status = ScanStatus(state["status"])
    return {
        "scan_id": scan_id,
        "mode": "MODE_1",
        "status": status.value,
        "target_url": payload.target_url,
        "target_repo": payload.target_repo,
    }


@router.get("/{scan_id}", response_model=ScanStatusResponse, dependencies=[Depends(require_api_key)])
async def get_scan(scan_id: str, session: AsyncSession = Depends(db_session)) -> dict:
    sm = StateManager(session_factory=session_factory_from(session))
    try:
        state = await sm.get(scan_id)
    except InvestigationNotFoundError:
        raise HTTPException(status_code=404, detail="scan not found")
    return {
        "scan_id": scan_id,
        "status": state["status"],
        "mode": state["mode"],
        "state": state.data,
        "updated_at": state.data.get("updated_at"),
    }


@router.get("/{scan_id}/approvals", response_model=list[ApprovalInfo], dependencies=[Depends(require_api_key)])
async def list_approvals(scan_id: str, session: AsyncSession = Depends(db_session)) -> list[dict]:
    sm = StateManager(session_factory=session_factory_from(session))
    try:
        state = await sm.get(scan_id)
    except InvestigationNotFoundError:
        raise HTTPException(status_code=404, detail="scan not found")
    decisions = state.data.get("approval_decisions") or {}
    pending = state.data.get("pending_approvals") or []
    return [
        {
            "approval_id": entry["approval_id"],
            "tool": entry.get("tool"),
            "target": entry.get("target"),
            "decision": decisions.get(entry["approval_id"]),
            "status": "PENDING_APPROVAL"
            if decisions.get(entry["approval_id"]) is None
            else ("APPROVED" if decisions[entry["approval_id"]] else "REJECTED"),
        }
        for entry in pending
    ]


@router.post(
    "/{scan_id}/approvals/{approval_id}/decision",
    dependencies=[Depends(require_api_key)],
)
async def decide_approval(
    scan_id: str,
    approval_id: str,
    payload: ScanApprovalDecisionRequest,
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(require_api_key),
) -> dict:
    factory = session_factory_from(session)
    sm = StateManager(session_factory=factory)
    try:
        state = await sm.get(scan_id)
    except InvestigationNotFoundError:
        raise HTTPException(status_code=404, detail="scan not found")

    pending = state.data.get("pending_approvals") or []
    entry = next((p for p in pending if p.get("approval_id") == approval_id), None)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"no pending approval {approval_id!r} for this scan")
    decisions = state.data.get("approval_decisions") or {}
    if decisions.get(approval_id) is not None:
        raise HTTPException(status_code=409, detail=f"approval {approval_id!r} already decided")

    # Record the decision on state (append-only audit + explicit operator verdict).
    decisions[approval_id] = bool(payload.approved)
    state["approval_decisions"] = decisions
    await sm.update(state)

    await AuditLogger(session_factory=factory).record_tool_call(
        user=principal.username,
        scan_id=scan_id,
        agent="harness",
        tool="approval",
        target=entry.get("target") or state.data.get("target_url"),
        action=f"approval:{approval_id}",
        allowed=bool(payload.approved),
        decision_reason=payload.reason or f"operator {'approved' if payload.approved else 'rejected'} approval {approval_id}",
        result="APPROVED" if payload.approved else "REJECTED",
        requires_approval=True,
    )
    return {
        "scan_id": scan_id,
        "approval_id": approval_id,
        "approved": bool(payload.approved),
        "status": "APPROVED" if payload.approved else "REJECTED",
    }


@router.post("/{scan_id}/resume", dependencies=[Depends(require_api_key)])
async def resume_scan(
    scan_id: str,
    payload: ScanResumeRequest,
    session: AsyncSession = Depends(db_session),
    principal: Principal = Depends(require_api_key),
) -> dict:
    try:
        credentials = CredentialCatalog(payload.credentials) if payload.credentials else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid credentials: {exc}") from exc
    try:
        await DeepAgentOrchestrator().resume_mode1_scan(
            principal=principal.username, scan_id=scan_id, credentials=credentials
        )
    except OrchestrationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    sm = StateManager(session_factory=session_factory_from(session))
    try:
        state = await sm.get(scan_id)
    except InvestigationNotFoundError:
        raise HTTPException(status_code=404, detail="scan not found")
    return {
        "scan_id": scan_id,
        "status": state["status"],
    }


@router.get("/{scan_id}/checkpoints", dependencies=[Depends(require_api_key)])
async def get_checkpoints(scan_id: str, session: AsyncSession = Depends(db_session)) -> dict:
    cm = CheckpointManager(session_factory=session_factory_from(session))
    stages = await cm.stages(scan_id)
    latest = await cm.latest_stage(scan_id)
    return {"scan_id": scan_id, "stages": stages, "latest": latest}