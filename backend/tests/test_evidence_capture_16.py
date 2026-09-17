"""Phase 1.6 - evidence collection tests.

Covers: the shared redacted request/response capture helper, per-finding HTTP
exchange evidence attached by every runtime test tool, secret redaction in
captured evidence, and auth-identity proof on EvidenceRecord.location for
cross-user tools. Fully offline against a local test server.
"""

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest
from sqlalchemy import select

from app.auth_analysis.identity import IdentityStore
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
from app.models.evidence import EvidenceRecord
from app.schemas.common import ToolResultStatus
from app.testing.transport import (
    capture_exchange,
    redact,
    redact_body_excerpt,
    redact_headers,
    redact_url,
)


# ---------------------------------------------------------------------------
# Redaction helper units (§1.6 secret-cleanup guarantees)
# ---------------------------------------------------------------------------

def test_redaction_scrubs_tokens_and_secrets():
    assert "[REDACTED]" in redact("token=SECRETALUE")
    assert "[REDACTED]" in redact("api_key=abc123&other=1")
    assert "[REDACTED]" in redact("password: supersecret")
    assert "SECRETALUE" not in redact("token=SECRETALUE")
    assert redact("plain text") == "plain text"


def test_redact_url_scrubs_sensitive_query_values():
    out = redact_url("http://host/api?api_key=abc&token=xyz&page=2")
    assert "REDACTED" in out
    assert "abc" not in out
    assert "xyz" not in out
    assert "page=2" in out


def test_redact_headers_drops_sensitive_values():
    out = redact_headers({
        "Authorization": "Bearer sekrit",
        "Cookie": "sid=abc",
        "Server": "nginx/1.2.3",
    })
    assert out["Authorization"] == "[REDACTED]"
    assert out["Cookie"] == "[REDACTED]"
    assert out["Server"] == "nginx/1.2.3"


def test_redact_body_excerpt_caps_length():
    long = "x" * 10_000
    excerpt = redact_body_excerpt(long)
    assert len(excerpt) < 4100
    assert "…[" in excerpt


# ---------------------------------------------------------------------------
# Local test server
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", extra=None):
        self.send_response(code)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        from urllib.parse import parse_qs

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/search":
            q = (params.get("q") or [""])[0]
            body = b"you have an error in your sql syntax" if q == "'" else b"results"
            self._send(200, body)
        elif parsed.path == "/fetch":
            url = (params.get("url") or [None])[0]
            if url:
                import urllib.request

                try:
                    urllib.request.urlopen(url, timeout=2)
                except Exception:
                    pass
            self._send(200, b"fetched")
        elif parsed.path == "/set-cookie":
            self._send(200, b"ok", extra={"Set-Cookie": "sessionid=abc123; Path=/"})
        elif parsed.path == "/account":
            self._send(200, b'{"user":"shared_data"}')
        elif parsed.path == "/insecure":
            self._send(200, b"ok", extra={"Server": "nginx/1.2.3"})
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
    state = InvestigationState(scan_id=sid, target_url="http://127.0.0.1",
                               target_repo=None, user="admin")
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=state)
    return sid


def _executor(intensity="active", approval=None):
    scope = ScopeGuard(allowed_targets=["127.0.0.1"])
    policy = ScanPolicy.from_request(intensity=intensity, rate_limit_rps=100,
                                     allowed_methods=["*"])
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
            {**ep, "url": f"{server_url}{ep['path']}"} for ep in endpoints
        ],
        "login_endpoints": [],
        "auth_mechanism_summary": {},
        "total_endpoints": len(endpoints),
    }


# ---------------------------------------------------------------------------
# Per-finding HTTP exchange evidence
# ---------------------------------------------------------------------------

async def test_injection_finding_has_baseline_and_injected_exchange(scan_id, server):
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
    http = rec.output["findings"][0]["evidence"]["http"]
    assert "baseline" in http and "injected" in http
    for side in ("baseline", "injected"):
        assert http[side]["request"]["method"] == "GET"
        assert http[side]["request"]["url"].startswith(server)
        assert http[side]["response"]["status_code"] == 200
        assert isinstance(http[side]["timing_ms"], float)


async def test_auth_session_finding_has_exchange_and_redacts_cookies(scan_id, server):
    executor, guard = _executor(intensity="passive")
    rec = await executor.execute_tool(
        "runtime.test.auth_session",
        {"urls": [f"{server}/set-cookie"]},
        principal="admin", scan_id=scan_id, target=server,
        policy_guard=guard,
    )
    assert rec.status == ToolResultStatus.SUCCESS
    assert rec.output["finding_count"] >= 1
    finding = rec.output["findings"][0]
    http = finding["evidence"]["http"]
    assert http["request"]["method"] == "GET"
    # raw session cookie value must never appear in the capture
    assert "abc123" not in json.dumps(http)
    assert "abc123" not in json.dumps(rec.output)
    assert http["response"]["status_code"] == 200


async def test_ssrf_finding_has_exchange(scan_id, server):
    from app.control_plane.canary import SsrfCanary

    canary = SsrfCanary()
    canary.start()
    try:
        scope = ScopeGuard(allowed_targets=["127.0.0.1"])
        policy = ScanPolicy.from_request(intensity="aggressive", rate_limit_rps=100,
                                         allowed_methods=["*"])
        guard = PolicyGuard(policy=policy)
        executor = ToolExecutor(
            registry=get_tool_registry(), scope=scope,
            permissions=PermissionManager(), sandbox=SandboxManager(),
            budget=BudgetManager(), retry=RetryManager(max_retries=0),
            audit=AuditLogger(session_factory=get_session_factory()),
            state=StateManager(session_factory=get_session_factory()),
        )
        rec = await executor.execute_tool(
            "runtime.test.ssrf",
            {"targets": [{"url": f"{server}/fetch", "params": ["url"]}]},
            principal="admin", scan_id=scan_id, target=server,
            policy_guard=guard, canary=canary,
        )
        assert rec.status == ToolResultStatus.SUCCESS
        assert rec.output["finding_count"] == 1
        http = rec.output["findings"][0]["evidence"]["http"]
        assert http["request"]["method"] == "GET"
        assert http["request"]["url"].startswith(server)
        assert http["response"]["status_code"] == 200
        assert isinstance(http["timing_ms"], float)
    finally:
        canary.stop()


async def test_misconfig_finding_has_observed_response(scan_id, server):
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
    assert rec.output["finding_count"] >= 1
    observed = rec.output["findings"][0]["evidence"]["http"]["observed_response"]
    assert observed["status_code"] == 200
    assert observed["headers"]["Server"] == "nginx/1.2.3"


# ---------------------------------------------------------------------------
# Cross-user evidence: transfers + auth-identity proof on EvidenceRecord.location
# ---------------------------------------------------------------------------

def _two_identities():
    store = IdentityStore()
    a = store.create(credential_id="alice", kind="form", username="alice",
                     session_cookies={"session": "alice"})
    b = store.create(credential_id="bob", kind="form", username="bob",
                     session_cookies={"session": "bob"})
    return store, a, b


async def test_access_control_finding_has_identity_exchanges(scan_id, server):
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
    http = rec.output["findings"][0]["evidence"]["http"]
    assert set(http["exchanges"]) == {"identity_a", "identity_b"}
    for exchange in http["exchanges"].values():
        assert exchange["request"]["method"] == "GET"
        assert exchange["response"]["status_code"] == 200
    # cookie values are never persisted inside the cross-user exchange capture
    assert "alice" not in json.dumps(http)
    assert "bob" not in json.dumps(http)


async def test_cross_user_evidence_location_carries_identity(scan_id, server, session_factory):
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
    # refs[0] = HARNESS wrapper; refs[1:] = one RUNTIME record per finding (§1.7)
    assert len(rec.evidence_refs) >= 2
    async with session_factory() as session:
        row = (await session.execute(
            select(EvidenceRecord).where(EvidenceRecord.id == uuid.UUID(rec.evidence_refs[0]))
        )).scalar_one()
        identity = row.location.get("identity")
        assert identity is not None
        assert len(identity) == 2
        usernames = {item["username"] for item in identity}
        assert usernames == {"alice", "bob"}
        # the secrets store never exposed cookie VALUES (names only)
        assert "alice" not in json.dumps([i.get("cookie_values") for i in identity])
        for item in identity:
            assert "session_secret" not in item