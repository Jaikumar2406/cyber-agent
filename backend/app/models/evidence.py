"""Evidence records - every security fact must trace here (evidence-first rule).

Evidence is the single currency of truth between engines, the Evidence
Normalizer, the Security Graph (Phase 4) and the Risk Engine (Phase 4). Phase 0
defines the common schema; real engines populate it from Phase 1 onward.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class EvidenceRecord(Base):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("dedup_key", name="uq_evidence_dedup"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(16))  # RUNTIME | CODE | CRYPTO | HARNESS
    evidence_type: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[str] = mapped_column(String(16), default="POTENTIAL")
    location: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    dedup_key: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=lambda: datetime.now(timezone.utc)
    )