"""Structured security finding (phases.md §1.5, §1.7).

A `Finding` is the unit of output every security test module produces. It is
deliberately evidence-first: it records *what* was observed, *how* it was
proven, and *how confident* the detector is - never a free-form LLM guess
(rules.md §2). Findings are JSON-serializable so the Executor can persist them
as evidence and §1.7 can normalize severity/confidence/OWASP mapping.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any

# Finding categories (kept as plain strings for easy JSON round-tripping).
NUCLEI = "nuclei"
BOLA = "bola"
BFLA = "bfla"
ACCESS_CONTROL_ASYMMETRY = "access_control_asymmetry"
SSRF = "ssrf"
INJECTION = "injection"
AUTH_WEAKNESS = "auth_weakness"
MISCONFIGURATION = "misconfiguration"

ALL_CATEGORIES = (
    NUCLEI,
    BOLA,
    BFLA,
    ACCESS_CONTROL_ASYMMETRY,
    SSRF,
    INJECTION,
    AUTH_WEAKNESS,
    MISCONFIGURATION,
)


def finding_id(category: str, endpoint: str, discriminator: str = "") -> str:
    """Deterministic, stable id so the same observation always yields the same
    finding id (dedup-friendly for §1.7 normalization)."""
    raw = f"{category}|{endpoint}|{discriminator}".encode("utf-8")
    return f"F-{hashlib.sha256(raw).hexdigest()[:16]}"


@dataclass(frozen=True)
class Finding:
    """One confirmed/suspected security observation."""

    title: str
    category: str
    severity: str  # schemas.common.Severity value
    confidence: str  # schemas.common.Confidence value
    endpoint: str  # "METHOD absolute-url"
    summary: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    identity_proof: dict[str, Any] | None = None  # cross-user proof (BOLA/BFLA)
    payload_id: str | None = None  # controlled-payload id, when one was sent
    cwe: str | None = None
    owasp: str | None = None
    detector: str | None = None
    id: str = ""
    evidence_ref: str | None = None  # reference to persisted raw/captured evidence

    def __post_init__(self) -> None:
        if not self.id:
            discriminator = self.payload_id or self.detector or self.title
            object.__setattr__(self, "id", finding_id(self.category, self.endpoint, discriminator))

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "endpoint": self.endpoint,
            "summary": self.summary,
            "remediation": self.remediation,
            "evidence": dict(self.evidence),
            "identity_proof": dict(self.identity_proof) if self.identity_proof else None,
            "payload_id": self.payload_id,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "detector": self.detector,
            "evidence_ref": self.evidence_ref,
        }
