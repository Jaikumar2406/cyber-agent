"""Phase 1.5 - security test tools through the full harness path.

Each test exercises one tool end-to-end: Scope -> Policy -> Permission ->
Budget -> Sandbox -> Retry -> Audit -> Evidence.
"""

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, urljoin

import pytest

from app.auth_analysis.identity import IdentityRecord, IdentityStore
from app.control_plane.canary import SsrfCanary
from app.control_plane.policy import PolicyGuard, ScanPolicy
from app.control_plane.scope import ScopeGuard
from app.core.db import get_session_factory
from app.harness.audit_logger import AuditLogger
from app.harness.approval_manager import ApprovalContext
from app.harness.budget_manager import BudgetManager
from app.harness.executor import ToolExecutor
from app.harness.permission_manager import PermissionManager
from app.harness.retry_manager import RetryManager
from app.harness.sandbox_manager import SandboxManager
from app.harness.state_manager import InvestigationState, StateManager
from app.harness.tool_registry import get_tool_registry
from app.schemas.common import ToolResultStatus


# ---------------------------------------------------------------------------
# Local test server
# ---------------------------------------------------------------------------

class _TestHandler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/plain", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/insecure":
            self._send(200, b"ok", extra_headers={"Server": "nginx/1.2.3"})

        elif path == "/secure":
            self._send(200, b"ok", extra_headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
                "Strict-Transport-Security": "max-age=31536000",
            })

        elif path == "/cors-bad":
            self._send(200, b"ok", extra_headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            })

        elif path == "/debug":
            self._send(200, b"debug info", extra_headers={"Server": "Werkzeug/2.0"})

        elif path == "/set-cookie-bad":
            self._send(200, b"ok",
                       extra_headers={"Set-Cookie": "sessionid=abc123; Path=/"})

        elif path == "/set-cookie-good":
            self._send(200, b"ok",
                       extra_headers={"Set-Cookie": "sid=xyz; Path=/; HttpOnly; Secure; SameSite=Strict"})

        elif path == "/search":
            q = (params.get("q") or [""])[0]
            if q == "'":
                body = "You have an error in your SQL syntax near '1=1'"
            elif "AEGIS_CMD_INJECTION_MARKER" in q:
                body = "output: AEGIS_CMD_INJECTION_MARKER"
            elif q in ("{{7*7}}", "${7*7}"):
                body = "result: 49"
            elif "pg_sleep" in q:
                time.sleep(0.35)
                body = "ok"
            else:
                body = f"results for: {q}".encode()
                if isinstance(body, str):
                    body = body.encode()
            if isinstance(body, str):
                body = body.encode()
            self._send(200, body)

        elif path == "/account":
            cookie = self.headers.get("Cookie", "")
            if "session=alice" in cookie:
                self._send(200, b'{"user":"shared_data"}')
            elif "session=bob" in cookie:
                self._send(200, b'{"user":"shared_data"}')
            else:
                self._send(401, b'{"error":"unauthorized"}')

        elif path == "/admin/users":
            cookie = self.headers.get("Cookie", "")
            if "session=alice" in cookie:
                self._send(200, b'["alice","bob"]')
            else:
                self._send(200, b'["alice","bob"]')

        elif path == "/fetch":
            url = (params.get("url") or [None])[0]
            if url:
                import urllib.request
                try:
                    urllib.request.urlopen(url, timeout=2)
                except Exception:
                    pass
            self._send(200, b"fetched")

        elif path == "/noop":
            self._send(200, b"nothing")

        elif path == "/error-body":
            self._send(500, b"Traceback (most recent call last):\n  File app.py line 1")

        else:
            self._send(404, b"not found")

    def log_message(self, fmt, *args):
        pass


@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _TestHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
async def scan_id(db_tables):
    sid = str(uuid.uuid4())
    state = InvestigationState(scan_id=sid, target_url="http://127.0.0.1", target_repo=None, user="admin")
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=state)
    return sid


def _executor(intensity="passive", canary=None, approval=None):
    scope = ScopeGuard(allowed_targets=["127.0.0.1"])
    policy = ScanPolicy.from_request(intensity=intensity, rate_limit_rps=100, allowed_methods=["*"])
    guard = PolicyGuard(policy=policy)
    executor = ToolExecutor(
        registry=get_tool_registry(), scope=scope,
        permissions=PermissionManager(), sandbox=SandboxManager(),
        budget=BudgetManager(), retry=RetryManager(max_retries=0),
        audit=AuditLogger(session_factory=get_session_factory()),
        state=StateManager(session_factory=get_session_factory()),
        approval=approval,
    )
    return executor, guard


def _approved_access_control(server):
    return ApprovalContext(decisions={
        ApprovalContext.request_id("runtime.test.access_control", server): True
    })


def _model(server_url, endpoints):
    return {
        "endpoints": [
            {**ep, "url": f"{server_url}{ep['path']}"}
            for ep in endpoints
        ],
        "login_endpoints": [],
        "auth_mechanism_summary": {},
        "total_endpoints": len(endpoints),
    }


# ---------------------------------------------------------------------------
# runtime.test.misconfig
# ---------------------------------------------------------------------------

async def test_misconfig_insecure_headers(scan_id, server):
    executor, guard = _executor(intensity="passive")
    model = _model(server, [
        {"method": "GET", "path": "/insecure", "status_code": 200,
         "response_headers": {"Server": "nginx/1.2.3"}},
    ])
    rec = await executor.execute_tool(
        "runtime.test.misconfig", {"application_model": model},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] >= 3
    cats = [f["category"] for f in rec.output["findings"]]
    assert all(c == "misconfiguration" for c in cats)


async def test_misconfig_secure_no_findings(scan_id, server):
    executor, guard = _executor(intensity="passive")
    model = _model(server, [
        {"method": "GET", "path": "/secure", "status_code": 200, "response_headers": {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Strict-Transport-Security": "max-age=31536000",
        }},
    ])
    rec = await executor.execute_tool(
        "runtime.test.misconfig", {"application_model": model},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] == 0


async def test_misconfig_cors(scan_id, server):
    executor, guard = _executor(intensity="passive")
    model = _model(server, [
        {"method": "GET", "path": "/cors-bad", "status_code": 200, "response_headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }},
    ])
    rec = await executor.execute_tool(
        "runtime.test.misconfig", {"application_model": model},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    cors = [f for f in rec.output["findings"] if f["detector"] == "misconfig.cors"]
    assert cors and cors[0]["severity"] == "HIGH"


async def test_misconfig_passive_intensity_allowed(scan_id, server):
    executor, guard = _executor(intensity="passive")
    model = _model(server, [
        {"method": "GET", "path": "/insecure", "status_code": 200, "response_headers": {}},
    ])
    rec = await executor.execute_tool(
        "runtime.test.misconfig", {"application_model": model},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS


# ---------------------------------------------------------------------------
# runtime.test.auth_session
# ---------------------------------------------------------------------------

async def test_auth_session_insecure_cookie(scan_id, server):
    executor, guard = _executor(intensity="passive")
    rec = await executor.execute_tool(
        "runtime.test.auth_session",
        {"urls": [f"{server}/set-cookie-bad"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] >= 2
    detectors = {f["detector"] for f in rec.output["findings"]}
    assert "auth_session.cookie_httponly" in detectors


async def test_auth_session_secure_cookie(scan_id, server):
    executor, guard = _executor(intensity="passive")
    rec = await executor.execute_tool(
        "runtime.test.auth_session",
        {"urls": [f"{server}/set-cookie-good"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    flag_detectors = {f["detector"] for f in rec.output["findings"]}
    assert "auth_session.cookie_httponly" not in flag_detectors
    assert "auth_session.cookie_secure" not in flag_detectors
    assert "auth_session.cookie_samesite" not in flag_detectors
    assert flag_detectors <= {"auth_session.cleartext_session"}


async def test_auth_session_passive_allowed(scan_id, server):
    executor, guard = _executor(intensity="passive")
    rec = await executor.execute_tool(
        "runtime.test.auth_session",
        {"urls": [f"{server}/set-cookie-bad"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS


async def test_auth_session_cookie_value_not_in_evidence(scan_id, server):
    executor, guard = _executor(intensity="passive")
    rec = await executor.execute_tool(
        "runtime.test.auth_session",
        {"urls": [f"{server}/set-cookie-bad"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    full = json.dumps(rec.output)
    assert "abc123" not in full


# ---------------------------------------------------------------------------
# runtime.test.injection
# ---------------------------------------------------------------------------

async def test_injection_sqli_error(scan_id, server):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.injection",
        {"targets": [{"url": f"{server}/search", "params": ["q"]}],
         "payload_ids": ["sqli.single-quote"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] == 1
    assert rec.output["findings"][0]["payload_id"] == "sqli.single-quote"


async def test_injection_cmdi(scan_id, server):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.injection",
        {"targets": [{"url": f"{server}/search", "params": ["q"]}],
         "payload_ids": ["cmdi.echo-marker"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    f = rec.output["findings"][0]
    assert f["confidence"] == "CONFIRMED"


async def test_injection_ssti(scan_id, server):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.injection",
        {"targets": [{"url": f"{server}/search", "params": ["q"]}],
         "payload_ids": ["ssti.math-marker"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] == 1
    assert rec.output["findings"][0]["payload_id"] == "ssti.math-marker"


async def test_injection_xss_reflected(scan_id, server):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.injection",
        {"targets": [{"url": f"{server}/search", "params": ["q"]}],
         "payload_ids": ["xss.img-marker"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    f = rec.output["findings"][0]
    assert f["confidence"] == "CONFIRMED"


async def test_injection_sqli_timing(scan_id, server):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.injection",
        {"targets": [{"url": f"{server}/search", "params": ["q"]}],
         "payload_ids": ["sqli.time-marker"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] == 1
    assert rec.output["findings"][0]["evidence"]["detection"]["detail"]["signal"] == "timing_delta"


async def test_injection_passive_denied(scan_id, server):
    executor, guard = _executor(intensity="passive")
    rec = await executor.execute_tool(
        "runtime.test.injection",
        {"targets": [{"url": f"{server}/search", "params": ["q"]}],
         "payload_ids": ["sqli.single-quote"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.POLICY_DENIED


async def test_injection_requests_sent(scan_id, server):
    executor, guard = _executor(intensity="active")
    rec = await executor.execute_tool(
        "runtime.test.injection",
        {"targets": [{"url": f"{server}/search", "params": ["q", "r"]}],
         "payload_ids": ["sqli.single-quote", "cmdi.echo-marker"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["requests_sent"] >= 5


# ---------------------------------------------------------------------------
# runtime.test.access_control
# ---------------------------------------------------------------------------

def _two_identities():
    store = IdentityStore()
    a = store.create(
        credential_id="alice", kind="form", username="alice",
        session_cookies={"session": "alice"},
    )
    b = store.create(
        credential_id="bob", kind="form", username="bob",
        session_cookies={"session": "bob"},
    )
    return store, a, b


async def test_access_control_bola(scan_id, server):
    store, a, b = _two_identities()
    executor, guard = _executor(intensity="active", approval=_approved_access_control(server))
    model = _model(server, [
        {"method": "GET", "path": "/account", "auth_required": True,
         "response_headers": {}},
    ])
    rec = await executor.execute_tool(
        "runtime.test.access_control",
        {"application_model": model, "identity_ids": [a.identity_id, b.identity_id]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard, identity_store=store,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] == 1
    f = rec.output["findings"][0]
    assert f["category"] == "bola"


async def test_access_control_bfla(scan_id, server):
    store, a, b = _two_identities()
    executor, guard = _executor(intensity="active", approval=_approved_access_control(server))
    model = _model(server, [
        {"method": "GET", "path": "/admin/users", "auth_required": True,
         "response_headers": {}},
    ])
    rec = await executor.execute_tool(
        "runtime.test.access_control",
        {"application_model": model, "identity_ids": [a.identity_id, b.identity_id]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard, identity_store=store,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] == 1
    assert rec.output["findings"][0]["category"] == "bfla"


async def test_access_control_passive_denied(scan_id, server):
    store, a, b = _two_identities()
    executor, guard = _executor(intensity="passive")
    model = _model(server, [
        {"method": "GET", "path": "/account", "auth_required": True, "response_headers": {}},
    ])
    rec = await executor.execute_tool(
        "runtime.test.access_control",
        {"application_model": model, "identity_ids": [a.identity_id, b.identity_id]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard, identity_store=store,
    )
    assert rec.status == ToolResultStatus.POLICY_DENIED


async def test_access_control_no_store_denied(scan_id, server):
    executor, guard = _executor(intensity="active", approval=_approved_access_control(server))
    model = _model(server, [
        {"method": "GET", "path": "/account", "auth_required": True, "response_headers": {}},
    ])
    rec = await executor.execute_tool(
        "runtime.test.access_control",
        {"application_model": model, "identity_ids": ["id-x", "id-y"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.POLICY_DENIED
    assert "identit" in (rec.error or "").lower()


async def test_access_control_identity_proof_present(scan_id, server):
    store, a, b = _two_identities()
    executor, guard = _executor(intensity="active", approval=_approved_access_control(server))
    model = _model(server, [
        {"method": "GET", "path": "/account", "auth_required": True, "response_headers": {}},
    ])
    rec = await executor.execute_tool(
        "runtime.test.access_control",
        {"application_model": model, "identity_ids": [a.identity_id, b.identity_id]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard, identity_store=store,
    )
    f = rec.output["findings"][0]
    assert f["identity_proof"] is not None
    assert "identity_a" in f["identity_proof"]


# ---------------------------------------------------------------------------
# runtime.test.ssrf
# ---------------------------------------------------------------------------

async def test_ssrf_canary_confirmed(scan_id, server):
    canary = SsrfCanary()
    canary.start()
    try:
        executor, guard = _executor(intensity="aggressive", canary=canary)
        rec = await executor.execute_tool(
            "runtime.test.ssrf",
            {"targets": [{"url": f"{server}/fetch", "params": ["url"]}]},
            principal="admin", scan_id=scan_id, target=server,
            policy_guard=guard, canary=canary,
        )
        assert rec.status == ToolResultStatus.SUCCESS
        assert rec.output["finding_count"] == 1
        f = rec.output["findings"][0]
        assert f["category"] == "ssrf"
        assert f["confidence"] == "CONFIRMED"
    finally:
        canary.stop()


async def test_ssrf_safe_endpoint(scan_id, server):
    canary = SsrfCanary()
    canary.start()
    try:
        executor, guard = _executor(intensity="aggressive", canary=canary)
        rec = await executor.execute_tool(
            "runtime.test.ssrf",
            {"targets": [{"url": f"{server}/noop", "params": ["url"]}]},
            principal="admin", scan_id=scan_id, target=server,
            policy_guard=guard, canary=canary,
        )
        assert rec.status == ToolResultStatus.SUCCESS
        assert rec.output["finding_count"] == 0
    finally:
        canary.stop()


async def test_ssrf_active_denied(scan_id, server):
    canary = SsrfCanary()
    canary.start()
    try:
        executor, guard = _executor(intensity="active", canary=canary)
        rec = await executor.execute_tool(
            "runtime.test.ssrf",
            {"targets": [{"url": f"{server}/fetch", "params": ["url"]}]},
            principal="admin", scan_id=scan_id, target=server,
            policy_guard=guard, canary=canary,
        )
        assert rec.status == ToolResultStatus.POLICY_DENIED
    finally:
        canary.stop()


async def test_ssrf_no_canary_denied(scan_id, server):
    executor, guard = _executor(intensity="aggressive")
    rec = await executor.execute_tool(
        "runtime.test.ssrf",
        {"targets": [{"url": f"{server}/fetch", "params": ["url"]}]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.FAILURE
    assert "canary" in (rec.error or "").lower()


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

async def test_all_1_5_tools_registered():
    registry = get_tool_registry()
    for name in [
        "runtime.test.misconfig",
        "runtime.test.auth_session",
        "runtime.test.injection",
        "runtime.test.access_control",
        "runtime.test.ssrf",
    ]:
        assert registry.has(name), f"{name} not registered"
