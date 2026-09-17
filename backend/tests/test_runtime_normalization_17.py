"""phases.md §1.7 — Runtime Finding Normalizer tests.

Covers:
- OWASP 2021 category mapping for every Aegis finding category
- Severity / confidence validation with fallback defaults
- Affected-asset extraction from endpoint strings
- normalize_findings list helper
- Preservation of engine-provided owasp field
- RUNTIME evidence record emission via _attach_runtime_findings
- EvidenceRecord.payload carries normalized metadata
- Normalized payload retains §1.6 redacted evidence (no secret leakage)
"""

import uuid
import pytest
from sqlalchemy import select

from app.schemas.common import Confidence, Severity
from app.models.evidence import EvidenceRecord


# ─── OWASP mapping ────────────────────────────────────────────────────────


class TestOwaspMapping:
    @pytest.mark.parametrize(
        ("category", "expected_code"),
        [
            ("bola", "A01"),
            ("bfla", "A01"),
            ("access_control_asymmetry", "A01"),
            ("injection", "A03"),
            ("ssrf", "A10"),
            ("misconfiguration", "A05"),
            ("auth_weakness", "A07"),
            ("nuclei", "A00"),
        ],
    )
    def test_known_category_maps(self, category, expected_code):
        from app.testing.runtime_normalizer import owasp_for
        result = owasp_for(category)
        assert result.code == expected_code
        assert isinstance(result.name, str) and len(result.name) > 5

    def test_unknown_category_defaults(self):
        from app.testing.runtime_normalizer import owasp_for
        result = owasp_for("something_new")
        assert result.code == "A00"
        assert "Uncategorized" in result.name


# ─── Severity / confidence validation ─────────────────────────────────────


class TestValidation:
    @pytest.mark.parametrize("sev", [s.value for s in Severity])
    def test_valid_severity_passes(self, sev):
        from app.testing.runtime_normalizer import normalize_finding
        out = normalize_finding({"severity": sev, "category": "bola", "endpoint": "GET http://x"})
        assert out["severity"] == sev

    def test_invalid_severity_defaults_to_medium(self):
        from app.testing.runtime_normalizer import normalize_finding
        out = normalize_finding({"severity": "BOGUS", "category": "bola", "endpoint": "GET http://x"})
        assert out["severity"] == "MEDIUM"

    @pytest.mark.parametrize("conf", [c.value for c in Confidence])
    def test_valid_confidence_passes(self, conf):
        from app.testing.runtime_normalizer import normalize_finding
        out = normalize_finding({"confidence": conf, "category": "injection", "endpoint": "POST http://x"})
        assert out["confidence"] == conf

    def test_invalid_confidence_defaults_to_potential(self):
        from app.testing.runtime_normalizer import normalize_finding
        out = normalize_finding({"confidence": "MAYBE", "category": "injection", "endpoint": "POST http://x"})
        assert out["confidence"] == "POTENTIAL"


# ─── Affected asset extraction ────────────────────────────────────────────


class TestAffectedAsset:
    def test_normal_endpoint(self):
        from app.testing.runtime_normalizer import normalize_finding
        out = normalize_finding({
            "category": "bola",
            "severity": "HIGH",
            "confidence": "CONFIRMED",
            "endpoint": "GET http://aegis.local/api/users/2",
            "evidence": {},
        })
        asset = out["affected_asset"]
        assert asset == {
            "host": "aegis.local",
            "url": "http://aegis.local/api/users/2",
            "method": "GET",
        }

    def test_nuclei_style_endpoint(self):
        from app.testing.runtime_normalizer import normalize_finding
        out = normalize_finding({
            "category": "nuclei",
            "severity": "LOW",
            "confidence": "CONFIRMED",
            "endpoint": "nuclei https://target.example.com:8443/vuln",
            "evidence": {},
        })
        assert out["affected_asset"]["host"] == "target.example.com"
        assert out["affected_asset"]["method"] == "NUCLEI"

    def test_empty_endpoint_still_works(self):
        from app.testing.runtime_normalizer import normalize_finding
        out = normalize_finding({
            "category": "misconfiguration",
            "severity": "INFO",
            "confidence": "PROBABLE",
            "endpoint": "",
            "evidence": {},
        })
        assert out["affected_asset"]["host"] == ""
        assert out["affected_asset"]["method"] == "UNKNOWN"


# ─── normalize_findings list + owasp field preservation ───────────────────


class TestNormalizeFindings:
    def test_returns_list_same_length(self):
        from app.testing.runtime_normalizer import normalize_findings
        raw = [
            {"category": "bola", "endpoint": "GET http://x", "severity": "HIGH", "confidence": "CONFIRMED"},
            {"category": "ssrf", "endpoint": "POST http://y", "severity": "CRITICAL", "confidence": "CONFIRMED"},
        ]
        result = normalize_findings(raw)
        assert len(result) == 2
        assert result[0]["owasp_category"]["code"] == "A01"
        assert result[1]["owasp_category"]["code"] == "A10"

    def test_existing_owasp_not_overwritten(self):
        from app.testing.runtime_normalizer import normalize_finding
        out = normalize_finding({"category": "bola", "owasp": "A01-CUSTOM", "endpoint": "GET http://x"})
        assert out["owasp"] == "A01-CUSTOM"
        assert out["owasp_category"]["code"] == "A01"

    def test_raw_dict_not_mutated(self):
        from app.testing.runtime_normalizer import normalize_finding
        raw = {"category": "bola", "endpoint": "GET http://x", "severity": "CRITICAL"}
        out = normalize_finding(raw)
        assert "owasp" not in raw
        assert raw.get("severity") == "CRITICAL"
        assert out["severity"] == "CRITICAL"


# ─── RUNTIME evidence emission (end-to-end via executor) ──────────────────


async def test_finding_tool_emits_runtime_evidence(session_factory, db_tables):
    """Tool whose output includes a findings list → one RUNTIME row per finding."""
    import uuid as _uuid
    from app.core.db import get_session_factory
    from app.harness.state_manager import InvestigationState, StateManager
    from app.harness.executor import ToolExecutor
    from app.harness.tools import BaseTool, ToolResult
    from app.harness.tool_registry import ToolRegistry
    from app.harness.sandbox_manager import SandboxManager
    from app.schemas.common import ToolResultStatus
    from app.harness.audit_logger import AuditLogger

    class _FindingTool(BaseTool):
        name = "test.normalize"
        description = "emits normalized findings"
        input_schema = {"type": "object", "properties": {}}

        async def run(self, args, context):
            return ToolResult(
                status=ToolResultStatus.SUCCESS,
                output={
                    "findings": [
                        {
                            "id": "F-bola",
                            "title": "BOLA on /api/users",
                            "category": "bola",
                            "severity": "CRITICAL",
                            "confidence": "CONFIRMED",
                            "endpoint": "GET http://aegis.local/api/users/2",
                            "summary": "User A accesses User B",
                            "remediation": "Add auth check",
                            "evidence": {"http": {"timing_ms": 12, "response": {"status_code": 200}}},
                        },
                        {
                            "id": "F-inject",
                            "title": "Injection in search",
                            "category": "injection",
                            "severity": "HIGH",
                            "confidence": "CONFIRMED",
                            "endpoint": "POST http://aegis.local/search?q=",
                            "summary": "SQL in q param",
                            "remediation": "Use parameterized queries",
                            "evidence": {"http": {"timing_ms": 8, "response": {"status_code": 500}}},
                        },
                    ]
                },
            )

    sid = str(_uuid.uuid4())
    await StateManager(session_factory=get_session_factory()).create(
        state=InvestigationState(scan_id=sid, target_url="http://example.com/", target_repo=None, user="admin")
    )

    registry = ToolRegistry()
    registry.register(_FindingTool())
    executor = ToolExecutor(
        registry=registry,
        sandbox=SandboxManager(),
        audit=AuditLogger(session_factory=get_session_factory()),
    )
    record = await executor.execute_tool(
        "test.normalize", {}, principal="admin", scan_id=sid, target="http://example.com/",
    )

    assert record.status == ToolResultStatus.SUCCESS
    assert len(record.evidence_refs) == 3  # 1 HARNESS + 2 RUNTIME

    async with session_factory() as session:
        runtime_rows = list(
            (await session.execute(
                select(EvidenceRecord).where(
                    EvidenceRecord.investigation_id == _uuid.UUID(sid),
                    EvidenceRecord.source == "RUNTIME",
                )
            )).scalars().all()
        )
        assert len(runtime_rows) == 2
        types = {r.evidence_type for r in runtime_rows}
        assert types == {"finding:bola", "finding:injection"}

        bola_row = next(r for r in runtime_rows if r.evidence_type == "finding:bola")
        assert bola_row.location["owasp"]["code"] == "A01"
        assert bola_row.location["affected_asset"]["host"] == "aegis.local"
        assert bola_row.location["finding_id"] == "F-bola"
        assert bola_row.payload["severity"] == "CRITICAL"
        assert "aegis.local" in bola_row.payload["affected_asset"]["url"]

        inject_row = next(r for r in runtime_rows if r.evidence_type == "finding:injection")
        assert inject_row.location["owasp"]["code"] == "A03"
        assert inject_row.payload["affected_asset"]["method"] == "POST"


async def test_no_findings_no_runtime_evidence(session_factory, db_tables):
    """Tool with no findings list → no RUNTIME evidence rows."""
    import uuid as _uuid
    from app.core.db import get_session_factory
    from app.harness.state_manager import InvestigationState, StateManager
    from app.harness.executor import ToolExecutor
    from app.harness.tools import BaseTool, ToolResult
    from app.harness.tool_registry import ToolRegistry
    from app.harness.sandbox_manager import SandboxManager
    from app.schemas.common import ToolResultStatus
    from app.harness.audit_logger import AuditLogger

    class _NoFindingTool(BaseTool):
        name = "test.nofindings"
        description = "no findings"
        input_schema = {"type": "object", "properties": {}}

        async def run(self, args, context):
            return ToolResult(status=ToolResultStatus.SUCCESS, output={"ok": True})

    sid = str(_uuid.uuid4())
    await StateManager(session_factory=get_session_factory()).create(
        state=InvestigationState(scan_id=sid, target_url="http://example.com/", target_repo=None, user="admin")
    )

    registry = ToolRegistry()
    registry.register(_NoFindingTool())
    executor = ToolExecutor(registry=registry, sandbox=SandboxManager(),
                            audit=AuditLogger(session_factory=get_session_factory()))
    record = await executor.execute_tool(
        "test.nofindings", {}, principal="admin", scan_id=sid, target="http://example.com/",
    )
    assert record.status == ToolResultStatus.SUCCESS
    # Only 1 HARNESS record, 0 RUNTIME
    assert len(record.evidence_refs) == 1


# ─── Payload retains redacted evidence; no raw secrets in location ────────


def test_normalized_payload_omits_secrets():
    """Rules.md §5.5: normalized location never carries credential values."""
    from app.testing.runtime_normalizer import normalize_finding
    out = normalize_finding({
        "category": "auth_weakness",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "endpoint": "GET http://x/admin",
        "evidence": {"http": {"request": {"headers": {"Authorization": "[REDACTED]"}}}},
        "identity_proof": {"session_ref": "abc123"},
    })
    assert "Authorization" not in out["affected_asset"]
    assert "session_secret" not in out
    assert out["identity_proof"]["session_ref"] == "abc123"
