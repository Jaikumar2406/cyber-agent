"""Phase 1.3 - auth tools through the full harness path.

Proves auth.analyze (passive) and auth.login (active cross-user) flow through
Scope -> Policy -> Permission -> Budget -> Sandbox -> Retry -> Audit -> Evidence
with secrets kept entirely out of evidence (rules.md §3.4, §5.5).
"""

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

from app.auth_analysis.identity import IdentityStore
from app.control_plane.credentials import CredentialCatalog
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

# ---------------------------------------------------------------------------
# Local auth server
# ---------------------------------------------------------------------------

OPENAPI_WITH_SECURITY = """{
  "openapi": "3.0.0",
  "info": {"title": "auth-demo", "version": "1.0"},
  "components": {
    "securitySchemes": {
      "BearerAuth": {"type": "http", "scheme": "bearer"}
    }
  },
  "paths": {
    "/api/data": {"get": {"summary": "data", "security": [{"BearerAuth": []}]}}
  }
}"""

_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig1234567890"


class _AuthHandler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/plain", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for key, val in (extra_headers or {}).items():
            self.send_header(key, val)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/login":
            html = (
                '<!DOCTYPE html><html><body>'
                '<form action="/login" method="POST">'
                '<input type="text" name="username"/>'
                '<input type="password" name="password"/>'
                '<input type="submit" value="Sign in"/>'
                '</form>'
                '<a href="/oauth/start">Sign in with OAuth</a>'
                '</body></html>'
            ).encode()
            self._send(200, html, "text/html")

        elif self.path == "/login-set-cookie":
            html = b'<form action="/login" method="POST"><input type="password" name="password"/></form>'
            self._send(200, html, "text/html",
                       extra_headers={"Set-Cookie": "aegis_preauth=1; Path=/; HttpOnly"})

        elif self.path == "/api/protected":
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer ") and auth.split(" ", 1)[1] == _TOKEN:
                self._send(200, b'{"status":"ok"}', "application/json")
            else:
                self._send(401, b'{"error":"unauthorized"}', "application/json",
                           extra_headers={"WWW-Authenticate": 'Bearer realm="api"'})

        elif self.path == "/basic-protected":
            auth = self.headers.get("Authorization", "")
            if auth == "Basic YWxpY2U6c2VjcmV0":
                self._send(200, b'{"role":"admin"}', "application/json")
            else:
                self._send(401, b'{}', "application/json",
                           extra_headers={"WWW-Authenticate": 'Basic realm="api"'})

        elif self.path == "/openapi.json":
            self._send(200, OPENAPI_WITH_SECURITY.encode(), "application/json")

        elif self.path == "/bearer-protected":
            auth = self.headers.get("Authorization", "")
            if auth == f"Bearer {_TOKEN}":
                self._send(200, b'{"role":"user"}', "application/json")
            else:
                self._send(401, b'{}', "application/json",
                           extra_headers={"WWW-Authenticate": 'Bearer'})

        else:
            self._send(404, b"not found")

    def do_POST(self):  # noqa: N802
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length).decode()
            params = parse_qs(data)
            username = (params.get("username") or [None])[0]
            password = (params.get("password") or [None])[0]
            if username == "alice" and password == "alice-pw":
                body = json.dumps({"access_token": _TOKEN}).encode()
                self._send(200, body, "application/json",
                           extra_headers={"Set-Cookie": f"session=alice-sid-{username}; Path=/; HttpOnly"})
            elif username == "bob" and password == "bob-pw":
                body = json.dumps({"access_token": _TOKEN}).encode()
                self._send(200, body, "application/json",
                           extra_headers={"Set-Cookie": f"session=bob-sid-{username}; Path=/; HttpOnly"})
            elif username == "carol" and password == "carol-pw":
                body = json.dumps({"access_token": _TOKEN}).encode()
                self._send(200, body, "application/json",
                           extra_headers={"Set-Cookie": f"session=carol-sid-{username}; Path=/; HttpOnly"})
            else:
                self._send(401, b'{"error":"invalid credentials"}', "application/json")
        else:
            self._send(404, b"not found")

    def log_message(self, fmt, *args):
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
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


def _executor(
    intensity="active",
    credentials: dict | None = None,
    identity_store: IdentityStore | None = None,
) -> tuple[ToolExecutor, PolicyGuard, IdentityStore]:
    scope = ScopeGuard(allowed_targets=["127.0.0.1"])
    policy = ScanPolicy.from_request(intensity=intensity, rate_limit_rps=100, allowed_methods=["*"])
    catalog = CredentialCatalog(credentials) if credentials is not None else None
    guard = PolicyGuard(policy=policy, credentials=catalog)
    store = identity_store or IdentityStore()
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
    return executor, guard, store


# ---------------------------------------------------------------------------
# auth.analyze
# ---------------------------------------------------------------------------

async def test_analyze_detects_login_form(scan_id, server):
    executor, guard, store = _executor(intensity="passive")
    record = await executor.execute_tool(
        "runtime.auth.analyze",
        {"url": f"{server}/login"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.SUCCESS
    kinds = {m["kind"] for m in record.output["mechanisms"]}
    assert "credentials" in kinds
    assert record.output["mechanism_count"] >= 1
    assert record.output["status_code"] == 200
    login_form = record.output["candidate_login_endpoints"]["form_actions"]
    assert any("/login" in action for action in login_form)
    assert len(record.evidence_refs) == 1


async def test_analyze_detects_cookie_on_login_page(scan_id, server):
    executor, guard, store = _executor(intensity="passive")
    record = await executor.execute_tool(
        "runtime.auth.analyze",
        {"url": f"{server}/login-set-cookie"},
        principal="admin", scan_id=scan_id, target=f"{server}/login-set-cookie",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.SUCCESS
    kinds = {m["kind"] for m in record.output["mechanisms"]}
    assert "cookie" in kinds  # Set-Cookie confirmed on wire
    # Session cookie value must not leak into evidence
    full_output = json.dumps(record.output)
    assert "aegis_preauth=1" not in full_output


async def test_analyze_with_spec_url(scan_id, server):
    executor, guard, store = _executor(intensity="passive")
    record = await executor.execute_tool(
        "runtime.auth.analyze",
        {"url": f"{server}/login", "spec_url": f"{server}/openapi.json"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["spec_checked"] is True
    assert record.output["openapi_endpoint_count"] == 1
    kinds = {m["kind"] for m in record.output["mechanisms"]}
    assert "jwt" in kinds  # from openapi securitySchemes


async def test_analyze_passive_intensity_allowed(scan_id, server):
    executor, guard, store = _executor(intensity="passive")
    record = await executor.execute_tool(
        "runtime.auth.analyze",
        {"url": f"{server}/login"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.SUCCESS


async def test_analyze_off_scope_blocked(scan_id):
    executor, guard, store = _executor(intensity="active")
    record = await executor.execute_tool(
        "runtime.auth.analyze",
        {"url": "https://evil.example.com/login"},
        principal="admin", scan_id=scan_id, target="https://evil.example.com/login",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.SCOPE_VIOLATION


# ---------------------------------------------------------------------------
# auth.login - policy enforcement
# ---------------------------------------------------------------------------

async def test_login_passive_denied(scan_id, server):
    """cross_user requires active+ intensity."""
    executor, guard, store = _executor(
        intensity="passive",
        credentials={"alice": {"kind": "form", "username": "alice", "secret": "alice-pw",
                                "description": "test user alice"}},
    )
    record = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/login", "credential_id": "alice"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.POLICY_DENIED
    assert "cross_user" in record.output.get("error", "") or "cross_user" in (record.error or "")


async def test_login_unknown_credential_denied(scan_id, server):
    executor, guard, store = _executor(
        intensity="active",
        credentials={"alice": {"kind": "form", "username": "alice", "secret": "alice-pw",
                                "description": "test user alice"}},
    )
    record = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/login", "credential_id": "mallory"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.POLICY_DENIED


# ---------------------------------------------------------------------------
# auth.login - form login success
# ---------------------------------------------------------------------------

async def test_login_form_success(scan_id, server):
    creds = [
        {"id": "alice", "kind": "form", "username": "alice", "secret": "alice-pw", "description": "alice"},
    ]
    executor, guard, store = _executor(intensity="active", credentials=creds)
    record = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/login", "credential_id": "alice"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.SUCCESS
    identity = record.output["identity"]
    assert identity["credential_id"] == "alice"
    assert identity["kind"] == "form"
    assert identity["session_ref"] is not None  # sha256 hex ref
    assert "alice-pw" not in json.dumps(record.output)
    assert store.count() == 1
    stored = store.by_credential("alice")
    assert stored is not None
    assert stored.session_secret is not None
    assert len(record.evidence_refs) == 1


async def test_login_form_sets_cookie_jar(scan_id, server):
    creds = [{"id": "bob", "kind": "form", "username": "bob", "secret": "bob-pw", "description": "bob"}]
    executor, guard, store = _executor(intensity="active", credentials=creds)
    record = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/login", "credential_id": "bob"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.SUCCESS
    stored = store.by_credential("bob")
    assert "session" in stored.session_cookies


# ---------------------------------------------------------------------------
# auth.login - basic auth
# ---------------------------------------------------------------------------

async def test_login_basic_success(scan_id, server):
    # alice:secret -> base64 "YWxpY2U6c2VjcmV0"
    creds = [{"id": "alice-basic", "kind": "basic", "username": "alice", "secret": "secret", "description": "alice basic"}]
    executor, guard, store = _executor(intensity="active", credentials=creds)
    record = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/basic-protected", "credential_id": "alice-basic", "kind": "basic"},
        principal="admin", scan_id=scan_id, target=f"{server}/basic-protected",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["identity"]["kind"] == "basic"
    # Basic auth header (contains the credential) is not in evidence
    assert "YXBpY2U6" not in json.dumps(record.output)


async def test_login_basic_rejected(scan_id, server):
    creds = [{"id": "bad", "kind": "basic", "username": "alice", "secret": "wrong", "description": "bad creds"}]
    executor, guard, store = _executor(intensity="active", credentials=creds)
    record = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/basic-protected", "credential_id": "bad", "kind": "basic"},
        principal="admin", scan_id=scan_id, target=f"{server}/basic-protected",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.FAILURE


# ---------------------------------------------------------------------------
# auth.login - bearer auth
# ---------------------------------------------------------------------------

async def test_login_bearer_success(scan_id, server):
    creds = [{"id": "svc", "kind": "bearer", "username": "", "secret": _TOKEN, "description": "service token"}]
    executor, guard, store = _executor(intensity="active", credentials=creds)
    record = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/bearer-protected", "credential_id": "svc", "kind": "bearer"},
        principal="admin", scan_id=scan_id, target=f"{server}/bearer-protected",
        policy_guard=guard,
        identity_store=store,
    )
    assert record.status == ToolResultStatus.SUCCESS
    assert record.output["identity"]["kind"] == "bearer"
    # Token must not leak into evidence
    assert _TOKEN not in json.dumps(record.output)


# ---------------------------------------------------------------------------
# auth.login - identity store guardrails
# ---------------------------------------------------------------------------

async def test_login_no_identity_store_fails(scan_id, server):
    creds = [{"id": "alice", "kind": "form", "username": "alice", "secret": "alice-pw", "description": "alice"}]
    executor, guard, _ = _executor(intensity="active", credentials=creds)
    record = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/login", "credential_id": "alice"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard,
    )
    assert record.status == ToolResultStatus.FAILURE
    assert "identity store" in (record.error or "").lower()


async def test_login_duplicate_credential_fails(scan_id, server):
    creds = [{"id": "alice", "kind": "form", "username": "alice", "secret": "alice-pw", "description": "alice"}]
    store = IdentityStore()
    executor, guard, _ = _executor(intensity="active", credentials=creds, identity_store=store)
    r1 = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/login", "credential_id": "alice"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard, identity_store=store,
    )
    assert r1.status == ToolResultStatus.SUCCESS
    r2 = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/login", "credential_id": "alice"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard, identity_store=store,
    )
    assert r2.status == ToolResultStatus.FAILURE


async def test_login_store_full_fails(scan_id, server):
    creds = [
        {"id": "alice", "kind": "form", "username": "alice", "secret": "alice-pw", "description": "alice"},
        {"id": "bob", "kind": "form", "username": "bob", "secret": "bob-pw", "description": "bob"},
        {"id": "carol", "kind": "form", "username": "carol", "secret": "carol-pw", "description": "carol"},
    ]
    store = IdentityStore()
    executor, guard, _ = _executor(intensity="active", credentials=creds, identity_store=store)

    for cid in ("alice", "bob"):
        r = await executor.execute_tool(
            "runtime.auth.login",
            {"url": f"{server}/login", "credential_id": cid},
            principal="admin", scan_id=scan_id, target=f"{server}/login",
            policy_guard=guard, identity_store=store,
        )
        assert r.status == ToolResultStatus.SUCCESS

    r3 = await executor.execute_tool(
        "runtime.auth.login",
        {"url": f"{server}/login", "credential_id": "carol"},
        principal="admin", scan_id=scan_id, target=f"{server}/login",
        policy_guard=guard, identity_store=store,
    )
    assert r3.status == ToolResultStatus.FAILURE
    assert "identity" in (r3.error or "").lower() or "conflict" in str(r3.output)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

async def test_auth_tools_registered():
    registry = get_tool_registry()
    assert registry.has("runtime.auth.analyze")
    assert registry.has("runtime.auth.login")