"""Evidence Normalizer stub (architecture §17).

Converts engine observations into the common evidence schema and persists
EvidenceRecord rows. Phase 0 is a pass-through validator: it guarantees the
common vocabulary (source/type/confidence/location/payload), assigns ids +
dedup keys, and de-duplicates by key so the same observation is one record with
proper evidence references (rules.md §2.3).

Real normalization (severity mapping, cross-engine relationship inference) is
Phase 4; the contract and storage are established here.
"""

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import select

from app.core.logging import get_logger
from app.models.evidence import EvidenceRecord
from app.schemas.common import Confidence, EvidenceSource
from app.schemas.evidence import EvidenceInput

log = get_logger("aegis.evidence.normalizer")


class InvalidEvidenceError(Exception):
    pass


def compute_dedup_key(source: EvidenceSource, evidence_type: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(f"{source}:{evidence_type}:{canonical}".encode()).hexdigest()[:32]


class EvidenceNormalizer:
    def __init__(self, session_factory=None) -> None:
        from app.core.db import get_session_factory

        self._session_factory = session_factory or get_session_factory()

    def normalize(self, raw: EvidenceInput) -> EvidenceRecord:
        """Validate raw observation -> schema. Raises InvalidEvidenceError."""
        try:
            source = EvidenceSource(raw.source)
            confidence = Confidence(raw.confidence)
        except ValueError as exc:
            raise InvalidEvidenceError(f"invalid evidence vocabulary: {exc}") from exc
        return EvidenceRecord(
            source=source.value,
            evidence_type=raw.evidence_type,
            confidence=confidence.value,
            location=raw.location,
            payload=raw.payload,
        )

    async def add(
        self,
        *,
        scan_id: str,
        source: str,
        evidence_type: str,
        confidence: str = "POTENTIAL",
        location: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        raw = EvidenceInput(
            source=source,
            evidence_type=evidence_type,
            confidence=confidence,
            location=location,
            payload=payload or {},
        )
        record = self.normalize(raw)
        record.id = uuid.uuid4()
        record.investigation_id = uuid.UUID(scan_id)
        record.dedup_key = compute_dedup_key(record.source, record.evidence_type, record.payload)

        async with self._session_factory() as session:
            existing = await session.scalar(
                select(EvidenceRecord).where(EvidenceRecord.dedup_key == record.dedup_key)
            )
            if existing is not None:
                log.info("evidence.deduped", evidence_id=str(existing.id), dedup_key=record.dedup_key)
                return existing
            session.add(record)
            await session.commit()
            log.info("evidence.added", evidence_id=str(record.id), source=record.source,
                     evidence_type=record.evidence_type)
            return record

    async def list_for_scan(self, scan_id: str) -> list[EvidenceRecord]:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(EvidenceRecord).where(EvidenceRecord.investigation_id == uuid.UUID(scan_id))
            )
            return list(rows.all())