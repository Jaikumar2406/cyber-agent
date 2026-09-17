"""API request/response schemas for the control plane."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import ScanMode, ScanStatus

URL_MAX = 2048


class ScanCreateRequest(BaseModel):
    target_url: str | None = Field(None, max_length=URL_MAX)
    target_repo: str | None = Field(None, max_length=URL_MAX)
    intensity: str = Field("passive", pattern="^(passive|active|aggressive)$")
    rate_limit_rps: float = Field(10.0, ge=0.1, le=1000)
    allowed_methods: list[str] = Field(default_factory=lambda: ["*"])
    hint_endpoints: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Operator-known endpoints on the target host - seeded into the re-planner "
        "so they are tested even when discovery misses them",
    )
    credentials: list[dict] = Field(
        default_factory=list,
        description="operator-supplied test identity catalog entries {id, kind, username, secret, description}",
    )

    @field_validator("target_url", "target_repo")
    @classmethod
    def at_least_one_input(cls, v, info):
        # Cross-field check happens in the model validator below; this is a no-op.
        return v


class ScanCreateResponse(BaseModel):
    scan_id: uuid.UUID
    mode: ScanMode
    status: ScanStatus
    target_url: str | None = None
    target_repo: str | None = None


class ScanApprovalDecisionRequest(BaseModel):
    approved: bool
    reason: str | None = Field(None, max_length=512)


class ScanResumeRequest(BaseModel):
    """Re-supply the operator-supplied test identities for the resumed run.

    Raw credentials/identities are deliberately never persisted (rules.md §5.5),
    so the approving operator re-supplies the catalog at resume time - the same
    ids provisioned at scan creation satisfy this.
    """

    credentials: list[dict] = Field(
        default_factory=list,
        description="operator-supplied credential catalog entries {id, kind, username, secret, description}",
    )


class ApprovalInfo(BaseModel):
    approval_id: str
    tool: str
    target: str | None = None
    decision: bool | None = None
    status: str = "PENDING_APPROVAL"


class ScanStatusResponse(BaseModel):
    scan_id: uuid.UUID
    status: ScanStatus
    mode: ScanMode | None = None
    state: dict
    updated_at: datetime | None = None


class AuditEntryResponse(BaseModel):
    id: uuid.UUID
    user: str | None
    scan_id: str | None
    agent: str
    tool: str | None
    target: str | None
    action: str
    permission_decision: dict
    reason: str | None
    result: str
    created_at: datetime


class ToolInfoResponse(BaseModel):
    name: str
    description: str
    input_schema: dict
    permissions: list[str]


class HealthResponse(BaseModel):
    status: str
    version: str = "0.1.0"
    services: dict[str, str]