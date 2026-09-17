"""phases.md §1.8 — Runtime-only Report tests.

Covers:
- build_report_context: findings from RUNTIME evidence, coverage, stats
- HTML report: content, badges, coverage, mode limitations, redaction
- SARIF 2.1.0: structure, rule mapping, level mapping, artifact URIs, properties
- PDF: valid header/trailer, page objects, content text, ASCII sanitization
- API routes: HTML/SARIF/PDF responses, 404 for unknown scan
- rules.md §9: every finding in report traces to an EvidenceRecord id
"""

import json

import pytest
from sqlalchemy import select

from app.models.evidence import EvidenceRecord
from app.reporting import build_report_context, render_html, render_pdf, render_sarif

SEED_FINDINGS = [
    {
        "id": "F-bola-1",
        "title": "BOLA on /api/users/{id}",
        "category": "bola",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "endpoint": "GET http://127.0.0.1/api/users/2",
        "summary": "Identity A read identity B private data.",
        "remediation": "Enforce object-level authorization checks.",
        "evidence": {
            "http": {
                "request": {"method": "GET", "url": "http://127.0.0.1/api/users/2",
                            "headers": {"Authorization": "[REDACTED]"}},
                "response": {"status_code": 200,
                             "headers": {"Content-Type": "application/json"},
                             "body": '{"user":"b"}'},
                "timing_ms": 12.5,
            }
        },
        "identity_proof": {"session_ref": "sha256:redacted", "username": "alice"},
        "payload_id": "p-bola-1",
        "cwe": "CWE-200",
        "detector": "access_control:asymmetry",
    },
    {
        "id": "F-inj-1",
        "title": "SQL injection in search",
        "category": "injection",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "endpoint": "POST http://127.0.0.1/search?q=",
        "summary": "Single quote produced a SQL error in the response body.",
        "remediation": "Use parameterized queries.",
        "evidence": {"http": {"request": {"method": "POST", "url": "http://127.0.0.1/search?q='"},
                               "response": {"status_code": 500, "body": "SQL syntax error"},
                               "timing_ms": 8.0}},
        "detector": "injection:sql_quote",
    },
]


@pytest.fixture
async def seeded_scan(db_tables, session_factory):
    """Seed an investigation + RUNTIME findings + HARNESS evidence.
    Rows are inserted directly (bypassing the Evidence Normalizer's global dedup)
    so each test's scan owns its own evidence records."""
    import uuid as _uuid
    from app.core.db import get_session_factory
    from app.harness.state_manager import InvestigationState, StateManager
    from app.models.evidence import EvidenceRecord

    sid = str(_uuid.uuid4())
    await StateManager(session_factory=get_session_factory()).create(
        state=InvestigationState(scan_id=sid, target_url="http://127.0.0.1",
                                 target_repo=None, user="admin")
    )
    scan_uuid = _uuid.UUID(sid)
    async with session_factory() as session:
        for i, finding in enumerate(SEED_FINDINGS):
            from app.testing.runtime_normalizer import normalize_finding
            norm = normalize_finding(finding)
            record = EvidenceRecord(
                id=_uuid.uuid4(),
                investigation_id=scan_uuid,
                source="RUNTIME",
                evidence_type=f"finding:{norm['category']}",
                confidence=norm["confidence"],
                location={"endpoint": norm["endpoint"], "affected_asset": norm["affected_asset"],
                          "owasp": norm["owasp_category"], "finding_id": norm["id"]},
                payload=norm,
                dedup_key=f"test-runtime-{sid}-{i}",
            )
            session.add(record)
        for idx, tool in enumerate(("runtime.test.access_control", "runtime.test.injection")):
            session.add(EvidenceRecord(
                id=_uuid.uuid4(),
                investigation_id=scan_uuid,
                source="HARNESS",
                evidence_type=f"tool:{tool}",
                confidence="POTENTIAL",
                location={"tool": tool},
                payload={"output": {"findings": SEED_FINDINGS}},
                dedup_key=f"test-harness-{sid}-{idx}",
            ))
        await session.commit()
    return sid


# ─── Context ───────────────────────────────────────────────────────────────


class TestContext:
    async def test_loads_findings_from_runtime_evidence(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        assert ctx.total == 2
        titles = {f.title for f in ctx.findings}
        assert titles == {"BOLA on /api/users/{id}", "SQL injection in search"}
        # every report finding traces to an evidence record id (rules.md §2.3)
        for f in ctx.findings:
            assert f.record_id
            assert f.owasp_code in {"A01", "A03"}

    async def test_findings_sorted_by_severity(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        assert [f.severity for f in ctx.findings][0] == "CRITICAL"

    async def test_coverage_from_harness_and_assets(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        assert "runtime.test.access_control" in ctx.coverage.tools_executed
        assert "runtime.test.injection" in ctx.coverage.tools_executed
        assert "http://127.0.0.1/api/users/2" in ctx.coverage.endpoints_tested
        assert "bola" not in ctx.coverage.categories_without_findings  # bola HAS findings
        assert "nuclei" in ctx.coverage.categories_without_findings

    async def test_stats(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        assert ctx.severity_counts["CRITICAL"] == 1
        assert ctx.severity_counts["HIGH"] == 1
        assert ctx.severity_counts["LOW"] == 0
        assert ctx.owasp_counts.get("A01") == 1
        assert ctx.owasp_counts.get("A03") == 1

    async def test_unknown_scan_raises(self, session_factory):
        from app.harness.state_manager import InvestigationNotFoundError
        import uuid as _uuid
        with pytest.raises(InvestigationNotFoundError):
            await build_report_context(str(_uuid.uuid4()), session_factory)


# ─── HTML ──────────────────────────────────────────────────────────────────


class TestHtml:
    async def test_contains_report_sections(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        doc = render_html(ctx)
        assert "<title>AEGIS Runtime Security Report</title>" in doc
        assert f"Scan: <code>{seeded_scan}</code>" in doc
        assert "Mode limitations" in doc
        assert "Source-code root-cause attribution" in doc  # Mode-1 limitation
        assert "Coverage" in doc
        assert "Findings (2)" in doc
        assert "SQL injection in search" in doc
        assert "Enforce object-level authorization checks." in doc

    async def test_no_secret_leakage(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        doc = render_html(ctx)
        assert "[REDACTED]" in doc
        # 1.6 redaction holds: no raw credential values escaped into the report
        assert "Bearer " not in doc
        assert "Authorization: mysecret" not in doc
        assert "sha256:redacted" in doc  # identity proof shown, but it's a hash ref

    async def test_evidence_body_present(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        doc = render_html(ctx)
        assert "SQL syntax error" in doc
        assert "timing_ms" in doc


# ─── SARIF ─────────────────────────────────────────────────────────────────


class TestSarif:
    async def test_structure(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        sarif = render_sarif(ctx)
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "AEGIS"
        assert len(run["results"]) == 2
        assert run["properties"]["scanId"] == seeded_scan
        assert run["properties"]["evidenceSource"] == "RUNTIME"

    async def test_rules_and_levels(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        sarif = render_sarif(ctx)
        run = sarif["runs"][0]
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        assert "AEGIS-RUNTIME-BOLA" in rules
        assert "AEGIS-RUNTIME-INJECTION" in rules
        by_rule = {r["ruleId"]: r for r in run["results"]}
        assert by_rule["AEGIS-RUNTIME-BOLA"]["level"] == "error"  # CRITICAL
        assert by_rule["AEGIS-RUNTIME-INJECTION"]["level"] == "error"  # HIGH

    async def test_locations_and_properties(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        sarif = render_sarif(ctx)
        run = sarif["runs"][0]
        bola = next(r for r in run["results"] if r["ruleId"] == "AEGIS-RUNTIME-BOLA")
        uri = bola["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "http://127.0.0.1/api/users/2"
        assert bola["properties"]["owasp"] == "A01"
        assert bola["properties"]["severity"] == "CRITICAL"
        assert bola["properties"]["confidence"] == "CONFIRMED"
        assert bola["properties"]["evidenceRecordId"]
        assert bola["partialFingerprints"]["aegisFindingId"] == "F-bola-1"


# ─── PDF ───────────────────────────────────────────────────────────────────


class TestPdf:
    async def test_valid_header_and_trailer(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        data = render_pdf(ctx)
        assert data.startswith(b"%PDF-1.4")
        assert data.rstrip().endswith(b"%%EOF")
        assert b"startxref" in data
        assert b"/Type /Page" in data
        assert b"/Type /Pages" in data
        assert b"/Count " in data

    async def test_content_text(self, seeded_scan, session_factory):
        ctx = await build_report_context(seeded_scan, session_factory)
        data = render_pdf(ctx)
        assert "AEGIS Runtime Security Report".encode() in data
        assert "SQL injection in search".encode() in data
        assert "Enforce object-level authorization checks.".encode() in data

    async def test_ascii_sanitization(self, session_factory):
        from app.reporting.context import ReportContext, ReportFinding, Coverage
        finding = ReportFinding(
            record_id="ev-1",
            raw={
                "id": "F-1", "title": "non-ascii üñï \u2192 arrow",
                "category": "bola", "severity": "MEDIUM", "confidence": "PROBABLE",
                "endpoint": "GET http://x/y", "summary": "s", "remediation": "r",
                "owasp_category": {"code": "A01", "name": "Broken Access Control"},
                "affected_asset": {"host": "x", "url": "http://x/y", "method": "GET"},
                "evidence": {},
            },
        )
        ctx = ReportContext(
            scan_id="s", target_url="http://x", mode="MODE_1",
            generated_at="2026-01-01T00:00:00+00:00", findings=[finding],
            coverage=Coverage(), severity_counts={}, confidence_counts={}, owasp_counts={},
        )
        data = render_pdf(ctx)
        # every byte must be Latin-1 safe (it is, by construction)
        data.decode("latin-1")
        assert "?".encode() in data  # non-ascii replaced


# ─── API ───────────────────────────────────────────────────────────────────


class TestApi:
    async def test_html_route(self, client, api_headers, seeded_scan):
        resp = await client.get(f"/scans/{seeded_scan}/report", headers=api_headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")
        assert "AEGIS Runtime Security Report" in resp.text
        assert "SQL injection in search" in resp.text

    async def test_sarif_route(self, client, api_headers, seeded_scan):
        resp = await client.get(f"/scans/{seeded_scan}/report/sarif", headers=api_headers)
        assert resp.status_code == 200
        doc = resp.json()
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"][0]["results"]) == 2

    async def test_pdf_route(self, client, api_headers, seeded_scan):
        resp = await client.get(f"/scans/{seeded_scan}/report/pdf", headers=api_headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content.startswith(b"%PDF")

    async def test_unknown_scan_404(self, client, api_headers):
        resp = await client.get("/scans/not-a-scan/report", headers=api_headers)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "scan not found"