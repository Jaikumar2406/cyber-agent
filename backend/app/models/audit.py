"""Append-only audit log (rules.md §7).

Records are considered immutable. PostgreSQL gets database-level UPDATE/DELETE
triggers (scripts/db_init.sql); the application itself never updates or deletes
these rows.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditRecord(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(String(36), nullable=True, index=True)
    agent: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str | None] = mapped_column(String(128), nullable=True)
    target: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    permission_decision: Mapped[dict] = mapped_column(JSON, default=dict)
    reason: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    result: Mapped[str] = mapped_column(String(32))
    evidence_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    retry_info: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )