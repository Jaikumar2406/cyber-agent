"""Evidence schema - the common intelligence currency.

Matches models/evidence.py; used by the Evidence Normalizer and by tools when
they emit structured observations.
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import Confidence, EvidenceSource


class EvidenceInput(BaseModel):
    source: EvidenceSource
    evidence_type: str = Field(max_length=64)
    confidence: Confidence = Confidence.POTENTIAL
    location: dict[str, Any] | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class EvidenceRecordSchema(EvidenceInput):
    id: uuid.UUID
    investigation_id: uuid.UUID
    dedup_key: str | None = None
    created_at: datetime