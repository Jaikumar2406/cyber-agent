"""Phase 1.2 - discovery tools through the full harness path.

Proves the Attack Surface Discovery tools (crawl + openapi) flow through
Scope -> Policy -> Permission -> Budget -> Sandbox -> Retry -> Audit -> Evidence,
same as the HTTP tool, and only ever touch in-scope resources.
"""

import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

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

OPENAPI_JSON = """{
  "openapi": "3.0.0",
  "info": {"title": "demo", "version": "1.0"},
  "paths": {
    "/api/users": {"get": {"summary": "list"}},
    "/api/login": {"post": {"summary": "login"}}
  }
}"""


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            body = b'<a href="/about">about</a><a href="/admin">admin</a><a href="https://evil.example.net/x">evil</a>'
            self._send(200, body, "text/html")
        elif self.path == "/about":
            self._send(200, b"<p>about</p>", "text/html")
        elif self.path == "/admin":
            self._send(200, b"<p>admin</p>", "text/html")
        elif self.path == "/openapi.json":
            self._send(200, OPENAPI_JSON.encode(), "application/json")
        elif self.path == "/swagger.json":
            self._send(200, OPENAPI_JSON.encode(), "application/json")
        else:
            self._send(404, b"nope")

    def log_message(self, fmt, *args):  # silence
        pass


@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
async def scan_id(db_tables):
    sid = str(uuid.uuid4())
    state = InvestigationState(
        scan_id=sid, target_url="http://127.0.0.1", target_repo=None, user="admin"
    )
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=state)
    return sid


def _executor(intensity="active", *, only_localhost=True) -> tuple[ToolExecutor, PolicyGuard]:
    scope = ScopeGuard(allowed_targets=["127.0.0.1"] if only_localhost else None)
    policy = ScanPolicy.from_request(intensity=intensity, rate_limit_rps=100, allowed_methods=["*"])
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


async def test_crawl_discovers_endpoints(scan_id, server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.discovery.crawl",
        {"url": f"{server}/", "max_pages": 5, "max_depth": 2},
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    paths = {e["path"] for e in record.output["endpoints"]}
    assert "/" in paths and "/about" in paths and "/admin" in paths
    assert record.output["stats"]["pages_fetched"] == 3
    assert len(record.evidence_refs) == 1
    assert record.decisions["scope"]["allowed"]
    assert record.decisions["permission"]["allowed"]
    assert record.audit_id is not None


async def test_crawl_never_touches_offsite(scan_id, server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.discovery.crawl",
        {"url": f"{server}/", "max_pages": 10, "max_depth": 3},
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert all("evil" not in e["found_in"] for e in record.output["endpoints"])


async def test_crawl_off_scope_start_blocked(scan_id):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.discovery.crawl",
        {"url": "https://evil.example.net/", "max_pages": 5},
        principal="admin", scan_id=scan_id, target="https://evil.example.net/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SCOPE_VIOLATION


async def test_crawl_passive_intensity_allowed(scan_id, server):
    # discovery is read_only -> legal at passive intensity
    executor, guard = _executor(intensity="passive")
    record = await executor.execute_tool(
        "runtime.discovery.crawl",
        {"url": f"{server}/", "max_pages": 3, "max_depth": 1},
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS


async def test_openapi_discovers_spec_endpoints(scan_id, server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.discovery.openapi",
        {"url": f"{server}/"},
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["spec_url"].endswith("/openapi.json")
    assert {e["path"] for e in record.output["endpoints"]} == {"/api/users", "/api/login"}
    assert len(record.evidence_refs) == 1


async def test_openapi_explicit_spec_url(scan_id, server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.discovery.openapi",
        {"url": f"{server}/", "spec_url": f"{server}/swagger.json"},
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["spec_url"].endswith("/swagger.json")


async def test_openapi_off_scope_spec_blocked(scan_id):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.discovery.openapi",
        {"url": "https://evil.example.net/", "spec_url": "https://evil.example.net/openapi.json"},
        principal="admin", scan_id=scan_id, target="https://evil.example.net/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SCOPE_VIOLATION


async def test_both_tools_registered_in_default_registry():
    registry = get_tool_registry()
    assert registry.has("runtime.discovery.crawl")
    assert registry.has("runtime.discovery.openapi")