"""Phase 1.5 - nuclei module (offline, air-gapped) tests.

Covers: registration, offline execution against a fake local binary + bundled
templates, JSONL parsing into Finding model with evidence_ref, redaction,
scope/policy/permission enforcement, evidence capture, audit, and
missing-binary/template handling. No network, no downloads.
"""

import json
import os
import sys
import uuid

import pytest

from app.core.db import get_session_factory
from app.control_plane.policy import PolicyGuard, ScanPolicy
from app.control_plane.scope import ScopeGuard
from app.evidence.normalizer import EvidenceNormalizer
from app.harness.audit_logger import AuditLogger
from app.harness.budget_manager import BudgetManager
from app.harness.executor import ToolExecutor
from app.harness.permission_manager import PermissionManager
from app.harness.retry_manager import RetryManager
from app.harness.sandbox_manager import SandboxManager
from app.harness.state_manager import InvestigationState, StateManager
from app.harness.tool_registry import get_tool_registry
from app.harness.tools import ToolContext
from app.schemas.common import ToolResultStatus
from app.tools.test_nuclei import (
    NucleiTestTool,
    _origins_from_model,
    _parse_rows,
    _redact_row,
    _resolve_binary,
    _templates_available,
)

FAKE_SCRIPT = """
import json, sys
args = sys.argv[1:]
out = origin = templates = None
for i, a in enumerate(args):
    if a in ("-o", "-u", "-t") and i + 1 < len(args):
        value = args[i + 1]
        if a == "-o":
            out = value
        elif a == "-u":
            origin = value
        elif a == "-t":
            templates = value
if "-disable-update-check" not in args:
    sys.stderr.write("offline flag -disable-update-check missing\\n")
    sys.exit(2)
if not templates:
    sys.stderr.write("no templates dir\\n")
    sys.exit(3)
rows = [
    {
        "template-id": "demo-high",
        "info": {"name": "Demo High Finding", "severity": "high", "tags": ["demo", "config"]},
        "matcher-name": "exposure",
        "matched-at": origin + "/",
        "host": "127.0.0.1",
        "ip": "127.0.0.1",
        "port": "80",
        "type": "http",
        "extracted-results": ["token=SECRETALUE"],
        "request": "GET / HTTP/1.1",
        "response": "HTTP/1.1 200 OK",
        "curl-command": "curl 'http://host/' -H 'Cookie: sid=abc123'",
    },
    {
        "template-id": "demo-info",
        "info": {"name": "Demo Info Finding", "severity": "info", "tags": ["tech"]},
        "matcher-name": "",
        "matched-at": origin + "/index",
        "host": "127.0.0.1",
        "ip": "127.0.0.1",
        "port": "80",
        "type": "http",
        "extracted-results": ["header: nothing"],
        "request": "GET /index HTTP/1.1",
        "response": "HTTP/1.1 200 OK",
        "curl-command": "",
    },
]
with open(out, "w", encoding="utf-8") as handle:
    for r in rows:
        handle.write(json.dumps(r) + "\\n")
"""


@pytest.fixture
def nuclei_env(tmp_path):
    binary_path = tmp_path / "fake_nuclei.py"
    binary_path.write_text(FAKE_SCRIPT, encoding="utf-8")
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "demo.yaml").write_text("id: demo-http\n", encoding="utf-8")
    return {
        "binary_path": str(binary_path),
        "templates_dir": str(templates),
    }


@pytest.fixture
async def scan_id(db_tables):
    sid = str(uuid.uuid4())
    state = InvestigationState(scan_id=sid, target_url="http://127.0.0.1",
                               target_repo=None, user="admin")
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=state)
    return sid


def _executor(intensity="active", permissions=None):
    scope = ScopeGuard(allowed_targets=["127.0.0.1"])
    policy = ScanPolicy.from_request(intensity=intensity, rate_limit_rps=100,
                                     allowed_methods=["*"])
    executor = ToolExecutor(
        registry=get_tool_registry(), scope=scope,
        permissions=permissions or PermissionManager(),
        sandbox=SandboxManager(), budget=BudgetManager(),
        retry=RetryManager(max_retries=0),
        audit=AuditLogger(session_factory=get_session_factory()),
        state=StateManager(session_factory=get_session_factory()),
    )
    return executor, PolicyGuard(policy=policy)


def _model(origin):
    return {
        "endpoints": [
            {"method": "GET", "path": "/", "url": f"{origin}/", "source": "crawl"},
            {"method": "POST", "path": "/api", "url": f"{origin}/api", "source": "openapi"},
        ],
        "login_endpoints": [],
        "auth_mechanism_summary": {},
        "total_endpoints": 2,
    }


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_nuclei_tool_registered():
    assert get_tool_registry().has("runtime.test.nuclei")
    tool = get_tool_registry().get("runtime.test.nuclei")
    assert tool.permissions == ("runtime:test:nuclei",)
    assert "injection" in tool.policy_requirements


def test_nuclei_granted_permission():
    assert "runtime:test:nuclei" in PermissionManager().effective_permissions()


# ---------------------------------------------------------------------------
# Offline execution (fake binary + bundled templates)
# ---------------------------------------------------------------------------

async def test_nuclei_runs_offline(scan_id, nuclei_env):
    executor, guard = _executor(intensity="active")
    origin = f"http://127.0.0.1:{9999}"
    rec = await executor.execute_tool(
        "runtime.test.nuclei",
        {"application_model": _model(origin),
         "binary_path": nuclei_env["binary_path"],
         "templates_dir": nuclei_env["templates_dir"]},
        principal="admin", scan_id=scan_id, target=origin,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] == 2
    assert rec.output["origins_scanned"] == [origin]
    assert rec.output["scans_run"] == 1
    return rec


async def test_nuclei_no_endpoints_fails(scan_id, nuclei_env):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.nuclei",
        {"application_model": {"endpoints": []},
         "binary_path": nuclei_env["binary_path"],
         "templates_dir": nuclei_env["templates_dir"]},
        principal="admin", scan_id=scan_id, target="http://127.0.0.1:9999",
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.FAILURE
    assert "no endpoints" in (rec.error or "").lower()


# ---------------------------------------------------------------------------
# Scope / policy enforcement
# ---------------------------------------------------------------------------

async def test_nuclei_off_scope_blocked(scan_id, nuclei_env):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.nuclei",
        {"application_model": _model("http://127.0.0.1:9999"),
         "binary_path": nuclei_env["binary_path"],
         "templates_dir": nuclei_env["templates_dir"]},
        principal="admin", scan_id=scan_id, target="https://evil.example.com",
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SCOPE_VIOLATION


async def test_nuclei_model_origin_out_of_scope(scan_id, nuclei_env):
    executor, guard = _executor(intensity="active")
    model = _model("http://127.0.0.1:9999")
    model["endpoints"][0]["url"] = "https://evil.example.com/"
    rec = await executor.execute_tool(
        "runtime.test.nuclei",
        {"application_model": model,
         "binary_path": nuclei_env["binary_path"],
         "templates_dir": nuclei_env["templates_dir"]},
        principal="admin", scan_id=scan_id, target="http://127.0.0.1:9999",
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SCOPE_VIOLATION
    assert "scope" in (rec.error or "").lower()


async def test_nuclei_passive_denied(scan_id, nuclei_env):
    executor, guard = _executor(intensity="passive")
    rec = await executor.execute_tool(
        "runtime.test.nuclei",
        {"application_model": _model("http://127.0.0.1:9999"),
         "binary_path": nuclei_env["binary_path"],
         "templates_dir": nuclei_env["templates_dir"]},
        principal="admin", scan_id=scan_id, target="http://127.0.0.1:9999",
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.POLICY_DENIED
    assert "injection" in (rec.error or "").lower()


async def test_nuclei_permission_denied(scan_id, nuclei_env):
    restricted = PermissionManager(granted_permissions=("runtime:http:get",))
    executor, guard = _executor(intensity="active", permissions=restricted)
    rec = await executor.execute_tool(
        "runtime.test.nuclei",
        {"application_model": _model("http://127.0.0.1:9999"),
         "binary_path": nuclei_env["binary_path"],
         "templates_dir": nuclei_env["templates_dir"]},
        principal="admin", scan_id=scan_id, target="http://127.0.0.1:9999",
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.PERMISSION_DENIED


# ---------------------------------------------------------------------------
# Evidence + audit
# ---------------------------------------------------------------------------

async def test_nuclei_evidence_and_audit(scan_id, nuclei_env, session_factory):
    rec = await test_nuclei_runs_offline(scan_id, nuclei_env)
    # refs[0] = HARNESS wrapper; refs[1:] = one RUNTIME row per finding (§1.7)
    assert len(rec.evidence_refs) == 3
    assert rec.audit_id is not None
    from sqlalchemy import select
    from app.models.evidence import EvidenceRecord
    async with session_factory() as session:
        rows = (await session.execute(
            select(EvidenceRecord).where(EvidenceRecord.id == uuid.UUID(rec.evidence_refs[0]))
        )).scalars().all()
        assert len(rows) == 1
        assert rows[0].source == "HARNESS"
        assert rows[0].evidence_type == "tool:runtime.test.nuclei"


# ---------------------------------------------------------------------------
# Finding model + redaction in output
# ---------------------------------------------------------------------------

async def test_nuclei_findings_have_evidence_ref(scan_id, nuclei_env):
    rec = await test_nuclei_runs_offline(scan_id, nuclei_env)
    for finding in rec.output["findings"]:
        assert finding["category"] == "nuclei"
        assert finding["confidence"] == "CONFIRMED"
        assert finding["evidence_ref"].startswith("NREF-")
    sevs = {f["severity"] for f in rec.output["findings"]}
    assert sevs == {"HIGH", "INFO"}


async def test_nuclei_redacts_secrets(scan_id, nuclei_env):
    rec = await test_nuclei_runs_offline(scan_id, nuclei_env)
    blob = json.dumps(rec.output)
    assert "SECRETALUE" not in blob
    assert "sid=abc123" not in blob
    for row in rec.output["raw_evidence_rows"]:
        assert "request" not in row
        assert "curl-command" not in row
        assert "response" not in row


# ---------------------------------------------------------------------------
# Missing binary / templates handling
# ---------------------------------------------------------------------------

async def test_nuclei_missing_binary(scan_id, nuclei_env):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.nuclei",
        {"application_model": _model("http://127.0.0.1:9999"),
         "binary_path": "definitely-not-a-nuclei-binary",
         "templates_dir": nuclei_env["templates_dir"]},
        principal="admin", scan_id=scan_id, target="http://127.0.0.1:9999",
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.FAILURE
    assert "binary" in (rec.error or "").lower()


async def test_nuclei_missing_templates(scan_id, nuclei_env):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.nuclei",
        {"application_model": _model("http://127.0.0.1:9999"),
         "binary_path": nuclei_env["binary_path"],
         "templates_dir": ""},
        principal="admin", scan_id=scan_id, target="http://127.0.0.1:9999",
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.FAILURE
    assert "templates" in (rec.error or "").lower()


async def test_nuclei_empty_templates_dir(scan_id, tmp_path):
    empty = tmp_path / "empty_templates"
    empty.mkdir()
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.nuclei",
        {"application_model": _model("http://127.0.0.1:9999"),
         "binary_path": str(tmp_path / "fake_nuclei.py"),
         "templates_dir": str(empty)},
        principal="admin", scan_id=scan_id, target="http://127.0.0.1:9999",
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.FAILURE


# ---------------------------------------------------------------------------
# Pure parsing helpers
# ---------------------------------------------------------------------------

class TestNucleiParsing:
    def _row(self, severity="high"):
        return {
            "template-id": "demo-x",
            "info": {"name": "Demo X", "severity": severity, "tags": ["t"]},
            "matcher-name": "m1",
            "matched-at": "http://127.0.0.1/",
            "host": "127.0.0.1",
            "ip": "127.0.0.1",
            "port": "80",
            "type": "http",
            "extracted-results": [{"broken": "token=SEC"}],
            "request": "GET /",
            "response": "HTTP/1.1 200",
            "curl-command": "curl -H 'Cookie: sid=x'",
        }

    def test_parse_rows_severity_filter(self):
        rows = [self._row("high"), self._row("info"), self._row("critical")]
        parsed = _parse_rows(rows, "http://127.0.0.1", allowed={"high", "info"})
        assert len(parsed) == 2
        assert all(f.category == "nuclei" for f, _ in parsed)
        assert all(f.severity != "CRITICAL" for f, _ in parsed)

    def test_parse_rows_finding_fields(self):
        (finding, row), = _parse_rows([self._row()], "http://127.0.0.1", allowed={"high"})
        assert finding.title == "Demo X"
        assert finding.severity == "HIGH"
        assert finding.confidence == "CONFIRMED"
        assert finding.endpoint.startswith("nuclei ")
        assert finding.evidence_ref.startswith("NREF-")
        assert finding.evidence["template_id"] == "demo-x"
        assert finding.detector == "nuclei:demo-x"

    def test_redact_row_strips_requests(self):
        row = self._row()
        redacted = _redact_row(row)
        assert "request" not in redacted
        assert "response" not in redacted
        assert "curl-command" not in redacted
        blob = json.dumps(redacted)
        assert "SEC" not in blob
        ext = redacted.get("extracted-results")
        assert "token=[REDACTED]" in json.dumps(ext)

    def test_origins_from_model_dedup(self):
        model = {
            "endpoints": [
                {"url": "http://127.0.0.1:80/a"},
                {"url": "http://127.0.0.1:80/b"},
                {"url": "https://other.example/x"},
                {"url": "ftp://nope/y"},
                {"url": ""},
            ]
        }
        assert _origins_from_model(model) == ["http://127.0.0.1:80", "https://other.example"]

    def test_resolve_binary_py(self, tmp_path):
        script = tmp_path / "fake.py"
        script.write_text("pass", encoding="utf-8")
        assert _resolve_binary(str(script)) == [sys.executable, str(script)]
        assert _resolve_binary("definitely-not-a-real-binary-xyz") is None

    def test_templates_available(self, tmp_path):
        tests = tmp_path / "tests_dir"
        tests.mkdir()
        assert not _templates_available(str(tests))
        (tests / "a.yaml").write_text("x", encoding="utf-8")
        assert _templates_available(str(tests))
        assert not _templates_available(str(tmp_path / "missing"))
        assert not _templates_available("")

    async def test_model_origin_in_scope_violation(self, nuclei_env):
        tool = NucleiTestTool()
        model = _model("http://127.0.0.1:9999")
        model["endpoints"][0]["url"] = "https://evil.example.com/"
        scope = ScopeGuard(allowed_targets=["127.0.0.1"])
        ctx = ToolContext(target="http://127.0.0.1:9999", scope_guard=scope)
        result = await tool.run(
            {"application_model": model,
             "binary_path": nuclei_env["binary_path"],
             "templates_dir": nuclei_env["templates_dir"]},
            ctx,
        )
        assert result.status == ToolResultStatus.SCOPE_VIOLATION