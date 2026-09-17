"""Phase 1.4 — model.build tool through the full harness path.

Proves the Application Model Builder flows through Scope -> Policy ->
Permission -> Budget -> Sandbox -> Retry -> Audit -> Evidence.
"""

import json
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

OPENAPI_SPEC = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "test", "version": "1.0"},
    "components": {
        "securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}}
    },
    "paths": {
        "/api/users": {
            "get": {
                "summary": "list users",
                "parameters": [{"name": "page", "in": "query"}],
            },
            "post": {"summary": "create user"},
        },
        "/api/users/{id}": {
            "get": {
                "summary": "get user",
                "parameters": [{"name": "id", "in": "path"}],
            }
        },
        "/api/health": {"get": {"summary": "health check"}},
    },
})


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/plain", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            body = (
                b'<a href="/login">Login</a>'
                b'<a href="/about">About</a>'
                b'<a href="/api/users">Users</a>'
            )
            self._send(200, body, "text/html")
        elif self.path == "/login":
            html = (
                b'<form action="/login" method="POST">'
                b'<input type="password" name="password"/></form>'
            )
            self._send(200, html, "text/html",
                       extra_headers={"Set-Cookie": "preauth=1; Path=/; HttpOnly"})
        elif self.path == "/about":
            self._send(200, b"<p>About</p>", "text/html")
        elif self.path == "/api/users":
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                self._send(200, b'[{"id":1}]', "application/json")
            else:
                self._send(401, b'{"error":"unauthorized"}', "application/json",
                           extra_headers={"WWW-Authenticate": "Bearer"})
        elif self.path == "/api/health":
            self._send(200, b'{"ok":true}', "application/json")
        elif self.path == "/openapi.json":
            self._send(200, OPENAPI_SPEC.encode(), "application/json")
        else:
            self._send(404, b"not found")

    def do_POST(self):  # noqa: N802
        if self.path == "/login":
            self._send(200, b'{"access_token":"eyJhbGciOiJub25lIn0."}',
                       "application/json",
                       extra_headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly"})
        else:
            self._send(404, b"not found")

    def log_message(self, fmt, *args):
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


def _executor(intensity="passive"):
    scope = ScopeGuard(allowed_targets=["127.0.0.1"])
    policy = ScanPolicy.from_request(intensity=intensity, rate_limit_rps=100, allowed_methods=["*"])
    guard = PolicyGuard(policy=policy)
    return ToolExecutor(
        registry=get_tool_registry(),
        scope=scope,
        permissions=PermissionManager(),
        sandbox=SandboxManager(),
        budget=BudgetManager(),
        retry=RetryManager(max_retries=0),
        audit=AuditLogger(session_factory=get_session_factory()),
        state=StateManager(session_factory=get_session_factory()),
    ), guard


# ---------------------------------------------------------------------------
# Helpers — synthesize crawl_result and auth_analysis dicts
# ---------------------------------------------------------------------------

def _crawl_result(server_url):
    return {
        "seed_url": f"{server_url}/",
        "endpoints": [
            {"method": "GET", "path": "/", "source": "crawl", "found_in": None, "query_params": [], "body_media_type": None, "extra": {}},
            {"method": "GET", "path": "/login", "source": "crawl", "found_in": f"{server_url}/", "query_params": [], "body_media_type": None, "extra": {}},
            {"method": "POST", "path": "/login", "source": "crawl", "found_in": f"{server_url}/", "query_params": [], "body_media_type": None, "extra": {}},
            {"method": "GET", "path": "/about", "source": "crawl", "found_in": f"{server_url}/", "query_params": [], "body_media_type": None, "extra": {}},
            {"method": "GET", "path": "/api/users", "source": "openapi", "found_in": None, "query_params": ["page"], "body_media_type": None, "extra": {}},
            {"method": "POST", "path": "/api/users", "source": "openapi", "found_in": None, "query_params": [], "body_media_type": "application/json", "extra": {}},
            {"method": "GET", "path": "/api/health", "source": "openapi", "found_in": None, "query_params": [], "body_media_type": None, "extra": {}},
        ],
        "stats": {
            "pages_fetched": 4, "requests_made": 4, "out_of_scope_bounced": 0,
            "duplicates_skipped": 0, "max_depth_reached": False, "page_cap_reached": False,
            "total_depth": 2,
        },
    }


def _auth_analysis(server_url):
    return {
        "mechanisms": [{"kind": "jwt", "confidence": "CONFIRMED", "sources": ["header"]}],
        "mechanism_count": 1,
        "candidate_login_endpoints": {
            "form_actions": [f"{server_url}/login"],
            "auth_links": [],
            "seen_urls": [f"{server_url}/login"],
        },
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def test_model_build_produces_attack_surface(scan_id, server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.model.build",
        {
            "crawl_result": _crawl_result(server),
            "auth_analysis": _auth_analysis(server),
        },
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    output = record.output
    assert output["total_endpoints"] == 7
    assert len(output["protected_endpoints"]) >= 2  # /api/users
    assert len(output["public_endpoints"]) >= 3  # /, /login, /about
    assert f"{server}/login" in output["login_endpoints"]
    assert len(record.evidence_refs) == 1
    assert record.decisions["scope"]["allowed"]


async def test_model_marks_protected_endpoints(scan_id, server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.model.build",
        {
            "crawl_result": _crawl_result(server),
            "auth_analysis": _auth_analysis(server),
        },
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    protected = {ep["path"] for ep in record.output["protected_endpoints"]}
    assert "/api/users" in protected
    public = {ep["path"] for ep in record.output["public_endpoints"]}
    assert "/" in public
    assert "/login" in public


async def test_model_with_openapi_enriches_params(scan_id, server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.model.build",
        {
            "crawl_result": _crawl_result(server),
            "auth_analysis": _auth_analysis(server),
            "spec_url": f"{server}/openapi.json",
        },
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    endpoints = record.output["endpoints"]
    users_get = next(ep for ep in endpoints if ep["path"] == "/api/users" and ep["method"] == "GET")
    assert "page" in users_get["query_params"]


async def test_model_captures_set_cookie(scan_id, server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.model.build",
        {
            "crawl_result": _crawl_result(server),
            "auth_analysis": _auth_analysis(server),
        },
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    login_ep = next(
        ep for ep in record.output["endpoints"]
        if ep["path"] == "/login" and ep["method"] == "GET"
    )
    assert "preauth" in login_ep["set_cookie_names"]


async def test_model_passive_intensity_allowed(scan_id, server):
    executor, guard = _executor(intensity="passive")
    record = await executor.execute_tool(
        "runtime.model.build",
        {
            "crawl_result": _crawl_result(server),
            "auth_analysis": _auth_analysis(server),
        },
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS


async def test_model_off_scope_blocked(scan_id):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.model.build",
        {
            "crawl_result": {"seed_url": "https://evil.example.com/", "endpoints": [
                {"method": "GET", "path": "/", "source": "crawl", "found_in": None,
                 "query_params": [], "body_media_type": None, "extra": {}}
            ]},
            "auth_analysis": {},
        },
        principal="admin", scan_id=scan_id, target="https://evil.example.com/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SCOPE_VIOLATION


async def test_model_empty_crawl_produces_empty_model(scan_id, server):
    executor, guard = _executor()
    record = await executor.execute_tool(
        "runtime.model.build",
        {
            "crawl_result": {"seed_url": f"{server}/", "endpoints": [], "stats": {
                "pages_fetched": 0, "requests_made": 0, "out_of_scope_bounced": 0,
                "duplicates_skipped": 0, "max_depth_reached": False, "page_cap_reached": False,
                "total_depth": 0,
            }},
            "auth_analysis": {},
        },
        principal="admin", scan_id=scan_id, target=f"{server}/",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["total_endpoints"] == 0


async def test_model_registered():
    assert get_tool_registry().has("runtime.model.build")