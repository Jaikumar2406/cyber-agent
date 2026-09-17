"""Runtime-only report context (phases.md §1.8).

Builds the deterministic, evidence-backed snapshot a standalone report is
rendered from: the scan's RUNTIME evidence records (each one is a normalized
finding, rules.md §2.3 — no finding reaches a report without an evidence
reference), plus honest coverage data (what tools ran, which endpoint assets
were probed, and which detection categories produced no confirmed finding —
rules.md §7.4).

Nothing here touches the network. Rendering drivers live in the sibling
modules (html.py, sarif.py, pdf.py).
"""

import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from app.harness.state_manager import InvestigationNotFoundError
from app.models.evidence import EvidenceRecord
from app.models.investigation import Investigation
from app.testing.finding import ALL_CATEGORIES

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_CONFIDENCE_RANK = {"CONFIRMED": 0, "PROBABLE": 1, "POTENTIAL": 2}
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CONFIDENCE_ORDER = ("CONFIRMED", "PROBABLE", "POTENTIAL")

_MODE_1_LIMITATIONS = (
    "Source-code root-cause attribution is NOT included (this report is Mode 1 "
    "runtime evidence only).",
    "Cryptography analysis is NOT included (the crypto engine runs in Mode 2/3).",
    "Findings summarize what was observed at scan time; absence of a finding is "
    "not a guarantee the issue cannot exist under other conditions.",
)


@dataclass(frozen=True)
class ReportFinding:
    """A normalized runtime finding bound to its EvidenceRecord id."""

    record_id: str  # the EvidenceRecord reference (rules.md §2.3)
    raw: dict[str, Any]

    @property
    def title(self) -> str:
        return str(self.raw.get("title", ""))
    @property
    def category(self) -> str:
        return str(self.raw.get("category", ""))
    @property
    def severity(self) -> str:
        return str(self.raw.get("severity", "INFO"))
    @property
    def confidence(self) -> str:
        return str(self.raw.get("confidence", "POTENTIAL"))
    @property
    def endpoint(self) -> str:
        return str(self.raw.get("endpoint", ""))
    @property
    def summary(self) -> str:
        return str(self.raw.get("summary", ""))
    @property
    def remediation(self) -> str:
        return str(self.raw.get("remediation", ""))
    @property
    def owasp_code(self) -> str:
        cat = self.raw.get("owasp_category") or {}
        return str(cat.get("code") or self.raw.get("owasp") or "A00")
    @property
    def owasp_name(self) -> str:
        cat = self.raw.get("owasp_category") or {}
        return str(cat.get("name") or "")
    @property
    def asset(self) -> dict[str, Any]:
        return self.raw.get("affected_asset") or {}
    @property
    def evidence(self) -> dict[str, Any]:
        return self.raw.get("evidence") or {}
    @property
    def identity_proof(self) -> dict[str, Any] | None:
        return self.raw.get("identity_proof")
    @property
    def detector(self) -> str:
        return str(self.raw.get("detector") or "")
    @property
    def cwe(self) -> str:
        return str(self.raw.get("cwe") or "")
    @property
    def finding_id(self) -> str:
        return str(self.raw.get("id") or "")

    def sort_key(self) -> tuple[int, int, str]:
        return (
            _SEVERITY_RANK.get(self.severity, 99),
            _CONFIDENCE_RANK.get(self.confidence, 99),
            self.title,
        )


@dataclass
class Coverage:
    tools_executed: list[str] = field(default_factory=list)
    endpoints_tested: list[str] = field(default_factory=list)
    categories_without_findings: list[str] = field(default_factory=list)


@dataclass
class ReportContext:
    scan_id: str
    target_url: str | None
    mode: str | None
    generated_at: str
    findings: list[ReportFinding]
    coverage: Coverage
    severity_counts: dict[str, int]
    confidence_counts: dict[str, int]
    owasp_counts: dict[str, int]
    limitations: tuple[str, ...] = _MODE_1_LIMITATIONS

    @property
    def total(self) -> int:
        return len(self.findings)


async def build_report_context(scan_id: str, session_factory=None) -> ReportContext:
    """Load the Runtime-only report snapshot for a scan from evidence alone."""
    from app.core.db import get_session_factory

    factory = session_factory or get_session_factory()
    try:
        scan_uuid = uuid.UUID(scan_id)
    except (ValueError, AttributeError):
        raise InvestigationNotFoundError(scan_id)

    async with factory() as session:
        investigation = await session.get(Investigation, scan_uuid)
        if investigation is None:
            raise InvestigationNotFoundError(scan_id)
        rows = list(
            (
                await session.execute(
                    select(EvidenceRecord)
                    .where(EvidenceRecord.investigation_id == scan_uuid)
                    .order_by(EvidenceRecord.created_at)
                )
            ).scalars().all()
        )

    runtime = [r for r in rows if r.source == "RUNTIME" and r.evidence_type.startswith("finding:")]
    harness = [r for r in rows if r.source == "HARNESS"]

    findings: list[ReportFinding] = []
    endpoints_seen: set[str] = set()
    for record in runtime:
        raw = dict(record.payload or {})
        findings.append(ReportFinding(record_id=str(record.id), raw=raw))
        asset = raw.get("affected_asset") or {}
        url = str(asset.get("url") or "")
        if url and url not in endpoints_seen:
            endpoints_seen.add(url)
    findings.sort(key=lambda f: f.sort_key())

    tools_executed = sorted(
        {str(r.evidence_type).removeprefix("tool:") for r in harness if r.evidence_type}
    )
    present_categories = {f.category for f in findings}
    categories_without = [c for c in ALL_CATEGORIES if c not in present_categories]

    severity_counts = Counter(f.severity for f in findings)
    confidence_counts = Counter(f.confidence for f in findings)
    owasp_counts = Counter(f.owasp_code for f in findings)

    return ReportContext(
        scan_id=scan_id,
        target_url=investigation.target_url,
        mode=investigation.mode or "MODE_1",
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        findings=findings,
        coverage=Coverage(
            tools_executed=tools_executed,
            endpoints_tested=sorted(endpoints_seen),
            categories_without_findings=categories_without,
        ),
        severity_counts={sev: severity_counts.get(sev, 0) for sev in SEVERITY_ORDER},
        confidence_counts={conf: confidence_counts.get(conf, 0) for conf in CONFIDENCE_ORDER},
        owasp_counts=dict(owasp_counts),
    )