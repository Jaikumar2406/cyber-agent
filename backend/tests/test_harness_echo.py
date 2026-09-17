"""Phase 0 exit criterion #1 - end-to-end harness path for the echo probe.

register -> permission check -> sandbox -> execute -> retry -> audit -> evidence
"""

import uuid

import pytest
from sqlalchemy import select

from app.control_plane.scope import ScopeGuard
from app.core.db import get_session_factory
from app.core.orchestrator import Phase0Orchestrator
from app.evidence.normalizer import EvidenceNormalizer
from app.harness.executor import ToolExecutor
from app.harness.sandbox_manager import SandboxManager
from app.harness.state_manager import InvestigationState, StateManager
from app.harness.tool_registry import ToolRegistry
from app.harness.tools import BaseTool, ToolExecutionError, ToolContext, ToolResult
from app.models.audit import AuditRecord
from app.models.evidence import EvidenceRecord
from app.schemas.common import ToolResultStatus
from app.tools.echo import EchoTool


class FlakyEchoTool(BaseTool):
    """Echo that raises once then succeeds - exercises the Retry path
    through the Executor."""

    name = "echo.flaky"
    description = "flaky echo"
    input_schema = {"type": "object", "properties": {"x": {"type": "string"}}, "required": []}
    permissions = ()

    def __init__(self):
        self._failures_left = 1

    async def run(self, args, context):
        if self._failures_left > 0:
            self._failures_left -= 1
            raise ToolExecutionError("transient: once")
        return ToolResult(status=ToolResultStatus.SUCCESS, output={"x": args.get("x", "")})


@pytest.fixture
def registry_with_echo():
    registry = ToolRegistry()
    registry.register(EchoTool())
    return registry


async def test_echo_executes_end_to_end(registry_with_echo):
    executor = ToolExecutor(
        registry=registry_with_echo,
        sandbox=SandboxManager(mode="process"),
    )
    record = await executor.execute_tool(
        "echo",
        {"text": "hello", "iterations": 2, "delay_ms": 1},
        principal="admin",
        target="https://example.com/",
    )

    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["echo"] == "hello"
    assert record.output["iterations"] == 2
    assert record.audit_id is not None
    assert record.decisions["registry"]["found"]
    assert record.decisions["scope"]["allowed"]
    assert record.decisions["permission"]["allowed"]


async def test_echo_produces_audit_record(registry_with_echo, session_factory):
    executor = ToolExecutor(registry=registry_with_echo)
    record = await executor.execute_tool(
        "echo", {"text": "bye"}, principal="admin", target="https://example.com/"
    )

    async with session_factory() as session:
        row = (await session.execute(
            select(AuditRecord).where(AuditRecord.id == uuid.UUID(record.audit_id))
        )).scalar_one()
        assert row.agent == "harness"
        assert row.tool == "echo"
        assert row.action == "tool:echo"
        assert row.result == "SUCCESS"
        assert row.permission_decision["allowed"] is True


async def test_echo_produces_evidence(registry_with_echo, session_factory, db_tables):
    import uuid as _uuid

    orchestrator = Phase0Orchestrator(session_factory=get_session_factory())
    pre = InvestigationState(
        scan_id=str(_uuid.uuid4()),
        target_url="https://example.com/",
        target_repo=None,
        user="admin",
    )
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=pre)

    executor = ToolExecutor(registry=registry_with_echo)
    record = await executor.execute_tool(
        "echo", {"text": "evidence"}, principal="admin", scan_id=pre.scan_id, target="https://example.com/"
    )
    assert len(record.evidence_refs) == 1

    async with session_factory() as session:
        rows = (await session.execute(
            select(EvidenceRecord).where(EvidenceRecord.id == uuid.UUID(record.evidence_refs[0]))
        )).scalars().all()
        assert len(rows) == 1
        assert rows[0].source == "HARNESS"
        assert rows[0].evidence_type == "tool:echo"
        assert rows[0].payload["output"]["echo"] == "evidence"


async def test_flaky_tool_retried_through_executor(session_factory):
    registry = ToolRegistry()
    registry.register(FlakyEchoTool())
    executor = ToolExecutor(registry=registry)
    record = await executor.execute_tool(
        "echo.flaky", {"x": "1"}, principal="admin", target="https://example.com/"
    )
    assert record.status == ToolResultStatus.SUCCESS


async def test_scope_violation_blocks_execution(registry_with_echo):
    executor = ToolExecutor(registry=registry_with_echo, scope=ScopeGuard(allowed_targets=[]))
    record = await executor.execute_tool("echo", {}, principal="admin", target="https://evil.io/")
    assert record.status == ToolResultStatus.SCOPE_VIOLATION