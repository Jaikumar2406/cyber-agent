"""Phase 1.1 - runtime HTTP tool through the full harness path.

Proves the Scope & Policy Guard works at request granularity: every hop is
re-scoped, rate-limited, and audited; controlled payloads are enforced; the
canary is reachable only as a local origin.
"""

import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from app.control_plane.canary import SsrfCanary
from app.control_plane.policy import PolicyGuard, ScanPolicy
from app.control_plane.scope import ScopeGuard
from app.core.db import get_session_factory
from app.harness.audit_logger import AuditLogger
from app.harness.budget_manager import BudgetManager
from app.harness.executor import ToolExecutor
from app.harness.permission_manager import PermissionManager
from app.harness.retry_manager import RetryManager
from app.harness.sandbox_manager import SandboxManager
from app.harness.state_manager import InvestigationState, StateManager
from app.harness.tool_registry import get_tool_registry
from app.schemas.common import ToolResultStatus


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/plain", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/ok":
            self._send(200, b"hello world")
        elif self.path == "/redirect":
            self._send(302, extra={"Location": "/ok"})
        elif self.path == "/redirect-evil":
            self._send(302, extra={"Location": "https://evil.example.net/x"})
        elif self.path.startswith("/echo-auth"):
            auth = self.headers.get("Authorization", "")
            self._send(200, f"auth={auth}".encode())
        elif self.path.startswith("/sink"):
            value = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            self._send(200, f"echo:{value}".encode())
        else:
            self._send(404, b"nope")

    def do_POST(self):  # noqa: N802
        if self.path == "/create":
            self._send(201, b"created")
        else:
            self._send(404, b"nope")

    def log_message(self, fmt, *args):  # silence
        pass


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
async def scan_id(db_tables):
    sid = str(uuid.uuid4())
    state = InvestigationState(
        scan_id=sid, target_url="http://127.0.0.1", target_repo=None, user="admin"
    )
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=state)
    return sid


def _executor(intensity="active", *, canary=None, rps=100.0) -> tuple[ToolExecutor, PolicyGuard]:
    scope = ScopeGuard(allowed_targets=["127.0.0.1"], canary=canary)
    policy = ScanPolicy.from_request(intensity=intensity, rate_limit_rps=rps, allowed_methods=["*"])
    guard = PolicyGuard(policy=policy)
    executor = ToolExecutor(
        registry=get_tool_registry(),
        scope=scope,
        permissions=PermissionManager(),
        sandbox=SandboxManager(),
        budget=BudgetManager(),
        retry=RetryManager(max_retries=0),
        audit=AuditLogger(session_factory=get_session_factory()),
        state=StateManager(session_factory=get_session_factory()),
    )
    return executor, guard


async def test_http_get_succeeds_with_evidence(scan_id, local_server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/ok"},
        principal="admin", scan_id=scan_id, target=f"{local_server}/ok",
        policy_guard=guard, canary=None,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["status_code"] == 200
    assert "hello world" in record.output["body_excerpt"]
    assert len(record.evidence_refs) == 1
    assert record.audit_id is not None
    assert record.decisions["scope"]["allowed"]
    assert record.decisions["permission"]["allowed"]


async def test_http_post_denied_at_passive_intensity(scan_id, local_server):
    executor, guard = _executor(intensity="passive")
    record = await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/create", "method": "POST"},
        principal="admin", scan_id=scan_id, target=f"{local_server}/create",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.POLICY_DENIED


async def test_http_post_allowed_at_active_intensity(scan_id, local_server):
    executor, guard = _executor(intensity="active")
    record = await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/create", "method": "POST"},
        principal="admin", scan_id=scan_id, target=f"{local_server}/create",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["status_code"] == 201


async def test_http_off_scope_target_denied(scan_id):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.http.request",
        {"url": "https://evil.example.net/x"},
        principal="admin", scan_id=scan_id, target="https://evil.example.net/x",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SCOPE_VIOLATION


async def test_http_follows_in_scope_redirect(scan_id, local_server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/redirect", "max_redirects": 3},
        principal="admin", scan_id=scan_id, target=f"{local_server}/redirect",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["status_code"] == 200
    assert len(record.output["redirect_chain"]) == 2  # redirect + final


async def test_http_blocks_out_of_scope_redirect(scan_id, local_server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/redirect-evil", "max_redirects": 3},
        principal="admin", scan_id=scan_id, target=f"{local_server}/redirect-evil",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SCOPE_VIOLATION
    assert "redirect out of scope" in record.error


async def test_http_injects_controlled_payload(scan_id, local_server):
    executor, guard = _executor(intensity="active")
    record = await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/sink", "payload_id": "sqli.single-quote", "payload_param": "q"},
        principal="admin", scan_id=scan_id, target=f"{local_server}/sink",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["injected_param"] == "q"
    assert "'" in record.output["body_excerpt"]  # target reflected the controlled payload


async def test_http_ssrf_canary_payload_blocked_below_aggressive(scan_id, local_server):
    executor, guard = _executor(intensity="active")
    record = await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/sink", "payload_id": "ssrf.canary", "payload_param": "q"},
        principal="admin", scan_id=scan_id, target=f"{local_server}/sink",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.POLICY_DENIED


async def test_http_canary_reachable_only_via_scope(scan_id):
    canary = SsrfCanary()
    canary.start()
    try:
        executor, guard = _executor(intensity="aggressive", canary=canary)
        record = await executor.execute_tool(
            "runtime.http.request",
            {"url": f"{canary.base_url}/cb"},
            principal="admin", scan_id=scan_id, target=f"{canary.base_url}/cb",
            policy_guard=guard, canary=canary,
        )
        assert record.status == ToolResultStatus.SUCCESS
        assert any(h.path.startswith("/cb") for h in canary.hits())
    finally:
        canary.stop()


async def test_http_captured_evidence_redacts_credentials(scan_id, local_server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/echo-auth", "headers": {"Authorization": "Bearer tops3cret"}},
        principal="admin", scan_id=scan_id, target=f"{local_server}/echo-auth",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    body = record.output["body_excerpt"]
    assert "tops3cret" not in body, "authorization value leaked into evidence"
    assert "[REDACTED]" in body

    from sqlalchemy import select

    from app.models.evidence import EvidenceRecord

    async with get_session_factory()() as session:
        rows = (await session.execute(
            select(EvidenceRecord).where(EvidenceRecord.id == uuid.UUID(record.evidence_refs[0]))
        )).scalars().all()
    assert len(rows) == 1
    assert "tops3cret" not in str(rows[0].payload)


async def test_http_rate_limiter_applied(scan_id, local_server):
    executor, guard = _executor(intensity="active", rps=500)
    await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/ok"},
        principal="admin", scan_id=scan_id, target=f"{local_server}/ok",
        policy_guard=guard,
    )
    await executor.execute_tool(
        "runtime.http.request",
        {"url": f"{local_server}/ok"},
        principal="admin", scan_id=scan_id, target=f"{local_server}/ok",
        policy_guard=guard,
    )
    assert guard.limiter.snapshot()["requests_granted"] >= 2