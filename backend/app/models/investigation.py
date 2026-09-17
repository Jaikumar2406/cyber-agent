"""Investigation (scan) record - the durable per-scan source of truth.

Holds the full structured investigation state described in SYSTEM_ARCHITECTURE.md
§22. Everything that must survive a crash lives in PostgreSQL; the in-memory
StateManager (see harness/state_manager.py) is a per-scan working copy backed
by this table.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    target_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    target_repo: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="CREATED", index=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Structured investigation state (plan, task graph, agent states, budgets)
    state: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
    )