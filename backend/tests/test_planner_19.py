"""Phase 1.9 - Deep Agent Supervisor: deterministic planner, re-planner,
offline LLM annotator (annotate-only), and the supervised Mode-1 pipeline.

The planner is the authority: given (target, policy, capabilities) it returns
the ordered Stage/PlanTask graph with NO DB/network/LLM involvement. The
re-planner adds extra test tasks for endpoints the current plan does not yet
cover and is idempotent. The LLM annotator can only annotate and degrades to a
no-op. The supervisor e2e exercises the full chain against a live local server
through the real Tool Executor (scope->policy->permission->budget->sandbox->
retry->audit->evidence), and the API e2e runs it through POST /scans.
"""

import asyncio
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
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
from app.planner.llm import LlmAnnotator
from app.planner.planner import (
    ACTIVE_PAYLOAD_IDS,
    AGGRESSIVE_PAYLOAD_IDS,
    Capabilities,
    Mode1Planner,
    STAGE_DISCOVERY,
    STAGE_MODEL,
    STAGE_TESTS,
    _payload_ids_for,
)
from app.planner.supervisor import DeepAgentSupervisor
from app.auth_analysis.identity import IdentityStore
from app.control_plane.credentials import CredentialCatalog
from app.harness.approval_manager import ApprovalContext
from app.schemas.common import ToolResultStatus


# ---------------------------------------------------------------------------
# Planner - pure planning decisions
# ---------------------------------------------------------------------------

def _policy(intensity="passive", allowed_methods=("*",)):
    return ScanPolicy.from_request(
        intensity=intensity, rate_limit_rps=1000, allowed_methods=list(allowed_methods)
    )


def _runtests(planner, intensity="passive", model=None, caps=None):
    planner = planner or Mode1Planner()
    return planner.plan_tests(
        model or _model(),
        target_url="http://127.0.0.1/",
        policy=_policy(intensity),
        capabilities=caps,
    )


def _model(url="http://127.0.0.1/", endpoints=None, login=()):
    endpoints = endpoints or []
    return {
        "endpoints": endpoints,
        "login_endpoints": list(login),
        "auth_mechanism_summary": {},
        "total_endpoints": len(endpoints),
    }


def _search_ep(url="http://127.0.0.1/search"):
    return {"method": "GET", "url": url, "path": "/search", "query_params": ["q"]}


def test_plan_discovery_and_model_stages_for_every_intensity():
    for intensity in ("passive", "active", "aggressive"):
        plan = Mode1Planner().plan(target_url="http://127.0.0.1/", policy=_policy(intensity))
        tools = {t.tool for t in plan.tasks}
        assert {"echo", "runtime.discovery.crawl", "runtime.discovery.openapi",
                "runtime.auth.analyze", "runtime.model.build"} <= tools
        assert {t.stage for t in plan.tasks} <= {STAGE_DISCOVERY, STAGE_MODEL}
        assert plan.task_ids() == {
            "probe.echo", "discovery.crawl", "discovery.openapi",
            "auth.analyze", "model.build",
        }
        assert not any(t.stage == STAGE_TESTS for t in plan.tasks)


def test_plan_payload_ids_follow_intensity():
    assert _payload_ids_for(_policy("passive")) == ()
    active = _payload_ids_for(_policy("active"))
    assert "sqli.single-quote" in active and "sqli.time-marker" not in active
    aggressive = _payload_ids_for(_policy("aggressive"))
    assert set(AGGRESSIVE_PAYLOAD_IDS) == set(aggressive)
    assert set(ACTIVE_PAYLOAD_IDS) <= set(aggressive)


def test_plan_notes_track_capabilities():
    passive = Mode1Planner().plan(target_url="http://127.0.0.1/", policy=_policy("passive"))
    assert any("injection not planned" in n for n in passive.notes)
    assert any("ssrf not planned" in n for n in passive.notes)
    assert any("no operator-supplied credentials" in n for n in passive.notes)
    active = Mode1Planner().plan(target_url="http://127.0.0.1/", policy=_policy("active"))
    assert any("injection enabled" in n for n in active.notes)
    hinted = Mode1Planner().plan(
        target_url="http://127.0.0.1/",
        policy=_policy("passive"),
        hint_endpoints=["http://127.0.0.1/hidden-admin"],
    )
    assert any("1 additional endpoint" in n for n in hinted.notes)


# ---------------------------------------------------------------------------
# plan_tests - test-stage task selection
# ---------------------------------------------------------------------------

def test_plan_tests_passive_covers_misconfig_and_session():
    tasks = _runtests(None, "passive", _model(
        endpoints=[{"method": "GET", "url": "http://127.0.0.1/search", "path": "/search"}],
        login=["http://127.0.0.1/login"],
    ))
    tools = {t.tool for t in tasks}
    assert "runtime.test.misconfig" in tools
    assert "runtime.test.auth_session" in tools
    assert "runtime.test.injection" not in tools
    assert "runtime.test.ssrf" not in tools
    assert "runtime.test.nuclei" not in tools
    assert "runtime.test.access_control" not in tools
    auth = next(t for t in tasks if t.tool == "runtime.test.auth_session")
    assert "http://127.0.0.1/search" in auth.args["urls"]
    assert "http://127.0.0.1/login" in auth.args["urls"]
    assert "http://127.0.0.1/" in auth.args["urls"]


def test_plan_tests_active_adds_injection_on_queried_endpoint():
    tasks = _runtests(None, "active", _model(endpoints=[_search_ep()]))
    inj = next(t for t in tasks if t.tool == "runtime.test.injection")
    assert inj.args["targets"] == [
        {"url": "http://127.0.0.1/search", "method": "GET", "params": ["q"], "location": "query"}
    ]
    assert set(inj.args["payload_ids"]) == set(ACTIVE_PAYLOAD_IDS)
    assert "runtime.test.ssrf" not in {t.tool for t in tasks}


def test_plan_tests_aggressive_adds_ssrf():
    tasks = _runtests(None, "aggressive", _model(endpoints=[_search_ep()]))
    tools = {t.tool for t in tasks}
    assert "runtime.test.ssrf" in tools
    ssrf = next(t for t in tasks if t.tool == "runtime.test.ssrf")
    assert ssrf.args["targets"][0]["url"] == "http://127.0.0.1/search"
    inj = next(t for t in tasks if t.tool == "runtime.test.injection")
    assert set(inj.args["payload_ids"]) == set(AGGRESSIVE_PAYLOAD_IDS)


def test_plan_tests_injection_skipped_without_query_params():
    tasks = _runtests(None, "active", _model(endpoints=[
        {"method": "GET", "url": "http://127.0.0.1/static", "path": "/static"},
    ]))
    assert "runtime.test.injection" not in {t.tool for t in tasks}


def test_plan_tests_injection_respects_allowed_methods():
    # METHOD not in the policy's allowed set -> endpoint skipped
    tasks = Mode1Planner().plan_tests(
        _model(endpoints=[
            {"method": "POST", "url": "http://127.0.0.1/upload", "path": "/upload", "query_params": ["file"]},
        ]),
        target_url="http://127.0.0.1/",
        policy=_policy("active", allowed_methods=["GET"]),
    )
    assert "runtime.test.injection" not in {t.tool for t in tasks}

    # allowed method + form body -> query-param tool targets use form location
    tasks = Mode1Planner().plan_tests(
        _model(endpoints=[
            {"method": "POST", "url": "http://127.0.0.1/upload", "path": "/upload",
             "query_params": ["name"], "body_media_type": "application/x-www-form-urlencoded",
             "form_fields": ["name"]},
        ]),
        target_url="http://127.0.0.1/",
        policy=_policy("active", allowed_methods=["POST"]),
    )
    inj = next(t for t in tasks if t.tool == "runtime.test.injection")
    assert inj.args["targets"][0]["location"] == "form"
    assert inj.args["targets"][0]["method"] == "POST"


def test_plan_tests_caps_override_policy_for_injection():
    caps = Capabilities(payload_ids=("sqli.single-quote",))
    tasks = _runtests(None, "active", _model(endpoints=[_search_ep()]), caps=caps)
    inj = next(t for t in tasks if t.tool == "runtime.test.injection")
    assert inj.args["payload_ids"] == ["sqli.single-quote"]


def test_plan_tests_access_control_needs_two_identities():
    single = _runtests(
        None, "active", _model(endpoints=[_search_ep()]),
        caps=Capabilities(payload_ids=(), credential_ids=("alice",)),
    )
    assert "runtime.test.access_control" not in {t.tool for t in single}

    both = _runtests(
        None, "active", _model(endpoints=[_search_ep()]),
        caps=Capabilities(payload_ids=(), credential_ids=("alice", "bob")),
    )
    ac = next(t for t in both if t.tool == "runtime.test.access_control")
    assert ac.args["identity_ids"] == ["alice", "bob"]


def test_plan_tests_nuclei_gated_on_engine():
    without = _runtests(None, "active", _model(endpoints=[_search_ep()]),
                        caps=Capabilities(payload_ids=(), nuclei_available=False))
    assert "runtime.test.nuclei" not in {t.tool for t in without}
    with_nuclei = _runtests(None, "active", _model(endpoints=[_search_ep()]),
                            caps=Capabilities(payload_ids=(), nuclei_available=True))
    assert "runtime.test.nuclei" in {t.tool for t in with_nuclei}


def test_plan_tests_misconfig_carries_full_model():
    model = _model(endpoints=[_search_ep()])
    tasks = _runtests(None, "passive", model)
    mis = next(t for t in tasks if t.tool == "runtime.test.misconfig")
    assert mis.args["application_model"]["total_endpoints"] == 1


# ---------------------------------------------------------------------------
# Re-planner - idempotent delta planning
# ---------------------------------------------------------------------------

def test_replan_adds_uncovered_endpoints():
    plan = Mode1Planner().plan(target_url="http://127.0.0.1/", policy=_policy("passive"))
    plan.tasks.extend(_runtests(None, "passive", _model(endpoints=[_search_ep()])))
    extra = Mode1Planner().replan(
        plan,
        model=_model(endpoints=[_search_ep()]),
        policy=_policy("passive"),
        discovered_endpoints=["http://127.0.0.1/hidden-admin"],
    )
    assert extra
    assert len(extra) == 1
    replan = extra[0]
    assert replan.tool == "runtime.test.auth_session"
    assert "http://127.0.0.1/hidden-admin" in replan.args["urls"]
    assert any("re-planner" in n for n in plan.notes)


def test_replan_idempotent_when_everything_covered():
    plan = Mode1Planner().plan(target_url="http://127.0.0.1/", policy=_policy("passive"))
    model = _model(endpoints=[_search_ep()])
    plan.tasks.extend(_runtests(None, "passive", model))
    extra = Mode1Planner().replan(
        plan,
        model=model,
        policy=_policy("passive"),
        discovered_endpoints=["http://127.0.0.1/search"],
    )
    assert extra == []


def test_replan_deduplicates_candidates_from_login_and_hints():
    planner = Mode1Planner()
    plan = planner.plan(target_url="http://127.0.0.1/", policy=_policy("passive"))
    plan.tasks.extend(_runtests(planner, "passive", _model(endpoints=[_search_ep()])))
    extra = planner.replan(
        plan,
        model=_model(endpoints=[_search_ep()], login=["http://127.0.0.1/login"]),
        policy=_policy("passive"),
        discovered_endpoints=["http://127.0.0.1/login", "http://127.0.0.1/login"],
    )
    urls = extra[0].args["urls"] if extra else []
    assert urls.count("http://127.0.0.1/login") == 1


# ---------------------------------------------------------------------------
# LLM annotator - annotate-only, graceful degradation
# ---------------------------------------------------------------------------

def _llm_settings(enabled=True, path="", timeout=2.0):
    return SimpleNamespace(
        llm_enabled=enabled,
        llm_model_path=path,
        llm_n_ctx=1024,
        llm_n_threads=1,
        llm_max_tokens=64,
        llm_timeout_seconds=timeout,
    )


def test_annotator_disabled_when_flag_off():
    a = LlmAnnotator(settings=_llm_settings(enabled=False))
    assert not a.enabled


def test_annotator_enabled_requires_model_file(tmp_path):
    present = _llm_settings(path=str(tmp_path / "qwen.gguf"))
    (tmp_path / "qwen.gguf").write_bytes(b"fake-gguf")
    a = LlmAnnotator(settings=present)
    assert a.enabled  # package installed + flag on + file present
    a = LlmAnnotator(settings=_llm_settings(path=str(tmp_path / "missing.gguf")))
    assert not a.enabled


def test_annotator_degraded_to_empty_on_inference_error(tmp_path, monkeypatch):
    model_file = tmp_path / "qwen.gguf"
    model_file.write_bytes(b"fake-gguf")
    a = LlmAnnotator(settings=_llm_settings(path=str(model_file)))
    assert a.enabled

    def boom(plan_text, target):
        raise RuntimeError("local model exploded")

    monkeypatch.setattr(a, "_generate", boom)
    result = asyncio.run(a.annotate_plan("plan: x", target="http://127.0.0.1/"))
    assert result == []


def test_annotator_times_out_to_empty(tmp_path, monkeypatch):
    model_file = tmp_path / "qwen.gguf"
    model_file.write_bytes(b"fake-gguf")
    a = LlmAnnotator(settings=_llm_settings(path=str(model_file), timeout=30.0))

    def blocker(plan_text, target):
        time.sleep(5)

    monkeypatch.setattr(a, "_generate", blocker)
    result = asyncio.run(a.annotate_plan("plan: x", target="http://127.0.0.1/", timeout=0.05))
    assert result == []


def test_annotator_not_enabled_returns_none():
    a = LlmAnnotator(settings=_llm_settings(enabled=False))
    assert asyncio.run(a.annotate_plan("plan: x", target="http://127.0.0.1/")) is None


def test_annotator_describe_marks_annotate_only():
    a = LlmAnnotator(settings=_llm_settings(enabled=False))
    desc = a.describe()
    assert "Annotate-only" in desc["notes"]
    assert desc["enabled"] is False


# ---------------------------------------------------------------------------
# Supervisor - full Mode-1 pipeline against a live local server
# ---------------------------------------------------------------------------

class _Phase19Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        if path == "/":
            html = (
                "<html><body>"
                '<a href="/insecure">insecure</a>'
                '<a href="/set-cookie-bad">bad</a>'
                '<a href="/search">search</a>'
                '<a href="/login">login</a>'
                '<form action="/session" method="POST">'
                '<input name="username" /><input name="password" />'
                "</form>"
                "</body></html>"
            )
            self._send(200, html.encode())
        elif path == "/insecure":
            self._send(200, b"ok", extra={"Server": "nginx/1.2.3"})
        elif path == "/set-cookie-bad":
            self._send(200, b"ok", extra={"Set-Cookie": "sessionid=abc123; Path=/"})
        elif path == "/hidden-admin":
            self._send(200, b"admin", extra={"Set-Cookie": "session=h; Path=/"})
        elif path == "/search":
            q = (params.get("q") or [""])[0]
            self._send(200, f"results for: {q}".encode(), ctype="text/plain")
        elif path == "/login":
            self._send(200, b'<form action="/session"><input name="u"/></form>')
        elif path == "/session":
            self._send(200, b"ok", extra={"Set-Cookie": "sessionid=s; Path=/"})
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if urlparse(self.path).path == "/session":
            self._send(200, b"ok", extra={"Set-Cookie": "sessionid=p; Path=/"})
        else:
            self._send(404, b"not found")

    def log_message(self, fmt, *args):
        pass


@pytest.fixture
def app_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Phase19Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _supervisor_harness(app_server, state, hint_endpoints=None):
    scope = ScopeGuard(allowed_targets=["127.0.0.1"])
    guard = PolicyGuard(policy=ScanPolicy.from_request(intensity="passive", rate_limit_rps=1000, allowed_methods=["*"]))
    executor = ToolExecutor(
        registry=get_tool_registry(), scope=scope,
        permissions=PermissionManager(), sandbox=SandboxManager(),
        budget=BudgetManager(), retry=RetryManager(max_retries=0),
        audit=AuditLogger(session_factory=get_session_factory()),
        state=StateManager(session_factory=get_session_factory()),
    )
    canary = SsrfCanary()
    canary.start()
    supervisor = DeepAgentSupervisor(
        executor=executor,
        policy_guard=guard,
        canary=canary,
        identity_store=IdentityStore(),
        state=state,
        principal="admin",
        hint_endpoints=hint_endpoints or [],
    )
    return supervisor, canary


async def test_supervisor_runs_full_pipeline_with_findings_and_replan(db_tables, app_server):
    scan_id = str(uuid.uuid4())
    state = InvestigationState(scan_id=scan_id, target_url=app_server, target_repo=None, user="admin")
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=state)

    supervisor, canary = _supervisor_harness(
        app_server, state, hint_endpoints=[f"{app_server}/hidden-admin"]
    )
    try:
        result = await supervisor.run(scan_id=scan_id, target=app_server)
    finally:
        canary.stop()

    assert result.harness_ok
    assert result.finding_count >= 3

    tools = {c["tool"] for c in result.tool_calls}
    assert {
        "echo",
        "runtime.discovery.crawl",
        "runtime.discovery.openapi",
        "runtime.auth.analyze",
        "runtime.model.build",
        "runtime.test.misconfig",
        "runtime.test.auth_session",
    } <= tools

    assert set(result.task_graphs) >= {"discovery", "model", "tests.initial"}
    assert result.task_graphs["discovery"]["probe.echo"]["status"] == "COMPLETED"

    # re-planner covered the operator-hinted endpoint not discovered by crawl
    assert "tests.replan" in result.task_graphs
    assert any("re-planner" in n for n in result.plan.notes)
    all_notes = json.dumps(result.plan.notes)
    assert "/hidden-admin" in all_notes

    # report slice task appended, plan persisted to state
    assert "report.generate" in {t.id for t in result.plan.tasks}
    assert result.plan.intensity == "passive"
    assert result.llm_annotations == []

    # harness evidence + runtime findings recorded in scan state
    assert len(state["evidence"]) >= 1
    assert state["finding_count"] >= 1
    task_ids = {t["id"] for t in state["plan"]["tasks"]}
    assert "report.generate" in task_ids


async def test_supervisor_marks_unreachable_target(db_tables):
    # Regression B: a target that never answers during discovery is a failure to
    # scan, NOT a completed zero-finding scan. Discovery has to prove reachability.
    target = "http://127.0.0.1:1/"
    scan_id = str(uuid.uuid4())
    state = InvestigationState(scan_id=scan_id, target_url=target, target_repo=None, user="admin")
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=state)

    supervisor, canary = _supervisor_harness(target, state)
    try:
        result = await supervisor.run(scan_id=scan_id, target=target)
    finally:
        canary.stop()

    assert result.finding_count == 0
    assert result.target_reachable is False
    assert result.harness_ok is False

    # the crawl never got an HTTP response and says so explicitly
    crawl = next(c for c in result.tool_calls if c["tool"] == "runtime.discovery.crawl")
    assert crawl["status"] == "FAILURE"
    assert crawl["output"]["reachable"] is False
    assert "connection/transport" in crawl["output"]["unreachable_reason"]


async def test_supervisor_reachable_target_is_reachable(db_tables, app_server):
    # Regression A: a target that answers discovery is reported as reachable and
    # the harness passes (probe.echo + real HTTP round-trip).
    target = app_server
    scan_id = str(uuid.uuid4())
    state = InvestigationState(scan_id=scan_id, target_url=target, target_repo=None, user="admin")
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=state)

    supervisor, canary = _supervisor_harness(target, state, hint_endpoints=[f"{app_server}/hidden-admin"])
    try:
        result = await supervisor.run(scan_id=scan_id, target=target)
    finally:
        canary.stop()

    assert result.target_reachable is True
    assert result.harness_ok
    auth = next(c for c in result.tool_calls if c["tool"] == "runtime.auth.analyze")
    assert auth["status"] == "SUCCESS"


# ---------------------------------------------------------------------------
# auth.analyze scope honesty: transport failure vs. real scope denial
# ---------------------------------------------------------------------------

async def _run_auth_analyze(target: str, args: dict):
    scope = ScopeGuard(allowed_targets=["127.0.0.1"])
    guard = PolicyGuard(
        policy=ScanPolicy.from_request(intensity="passive", rate_limit_rps=1000, allowed_methods=["*"])
    )
    executor = ToolExecutor(
        registry=get_tool_registry(), scope=scope,
        permissions=PermissionManager(), sandbox=SandboxManager(),
        budget=BudgetManager(), retry=RetryManager(max_retries=0),
        audit=AuditLogger(session_factory=get_session_factory()),
        state=StateManager(session_factory=get_session_factory()),
    )
    return await executor.execute_tool(
        "runtime.auth.analyze", args, principal="admin",
        scan_id=str(uuid.uuid4()), target=target, policy_guard=guard,
        identity_store=IdentityStore(), credentials=CredentialCatalog(),
        stage="discovery",
    )


async def test_auth_analyze_transport_failure_is_not_scope_violation(db_tables):
    # Regression D: an authorized localhost that simply refuses connections must
    # be reported as an unreachable/failed fetch, never as SCOPE_VIOLATION.
    target = "http://127.0.0.1:1/"
    record = await _run_auth_analyze(target, {"url": target, "timeout": 3.0})
    assert record.status == ToolResultStatus.FAILURE, record.status
    assert "could not be sampled" in (record.error or "")
    assert "out of scope" not in (record.error or "")


async def test_auth_analyze_success_on_authorized_localhost(db_tables, app_server):
    # Regression C: localhost passes the scope guard and auth.analyze samples it.
    record = await _run_auth_analyze(app_server, {"url": app_server, "timeout": 5.0})
    assert record.status == ToolResultStatus.SUCCESS, record.error
    assert record.output["page"] == app_server


# ---------------------------------------------------------------------------
# API e2e - POST /scans runs the supervised chain end-to-end
# ---------------------------------------------------------------------------

async def test_api_full_mode1_scan_with_hints_findings_reports(client, api_headers, db_tables, app_server):
    resp = await client.post(
        "/scans",
        json={
            "target_url": app_server,
            "intensity": "passive",
            "hint_endpoints": [f"{app_server}/hidden-admin"],
        },
        headers=api_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["mode"] == "MODE_1"
    scan_id = body["scan_id"]

    state_resp = await client.get(f"/scans/{scan_id}", headers=api_headers)
    assert state_resp.status_code == 200
    st = state_resp.json()
    assert st["status"] == "COMPLETED", st
    assert st["state"]["finding_count"] >= 3
    assert st["state"]["target_reachable"] is True
    assert st["state"]["supervisor"]["harness_ok"] is True

    graph = st["state"]["task_graph"]
    assert graph["discovery"]["probe.echo"]["status"] == "COMPLETED"
    assert {"discovery", "model", "tests.initial", "tests.replan"} <= set(graph)

    tools = {c["tool"]: c["status"] for c in st["state"]["tool_calls"]}
    assert "runtime.test.misconfig" in tools
    assert "runtime.test.auth_session" in tools
    assert tools["runtime.discovery.crawl"] == "SUCCESS"
    assert tools["runtime.auth.analyze"] == "SUCCESS"

    plan_tasks = {t["id"] for t in st["state"]["plan"]["tasks"]}
    assert "report.generate" in plan_tasks

    re_notes = [n for n in st["state"]["plan"]["notes"] if "re-planner" in n]
    assert re_notes and f"{app_server}/hidden-admin" in re_notes[0]

    html = await client.get(f"/scans/{scan_id}/report", headers=api_headers)
    assert html.status_code == 200
    assert "Findings" in html.text

    sarif = await client.get(f"/scans/{scan_id}/report/sarif", headers=api_headers)
    assert sarif.status_code == 200
    results = sarif.json()["runs"][0]["results"]
    assert len(results) >= 3


async def test_api_unreachable_target_reports_unreachable(client, api_headers, db_tables):
    # Regression B (API confirm): a down target is UNREACHABLE, harness not OK,
    # and auth.analyze reports the transport failure - never a scope violation.
    target = "http://127.0.0.1:1/"
    resp = await client.post(
        "/scans",
        json={"target_url": target, "intensity": "passive"},
        headers=api_headers,
    )
    assert resp.status_code == 201, resp.text
    scan_id = resp.json()["scan_id"]

    st = (await client.get(f"/scans/{scan_id}", headers=api_headers)).json()
    assert st["status"] == "UNREACHABLE", st
    assert st["state"]["target_reachable"] is False
    assert st["state"]["supervisor"]["harness_ok"] is False
    auth_status = [
        c["status"] for c in st["state"]["tool_calls"] if c["tool"] == "runtime.auth.analyze"
    ]
    assert auth_status == ["FAILURE"], auth_status
    assert any("could not be reached during discovery" in e["error"] for e in st["state"]["errors"])


async def test_api_invalid_credentials_return_422(client, api_headers, db_tables):
    # Invalid operator-supplied credentials are a 422 (bad request), not a 500.
    resp = await client.post(
        "/scans",
        json={
            "target_url": "http://127.0.0.1:1/",
            "intensity": "passive",
            "credentials": [
                {"id": "cred", "username": "alice", "secret": "s", "description": "d"}
            ],
        },
        headers=api_headers,
    )
    assert resp.status_code == 422, resp.text


async def test_llm_status_endpoint_requires_auth_and_reports_annotate_only(client, api_headers):
    assert (await client.get("/llm/status")).status_code == 401
    resp = await client.get("/llm/status", headers=api_headers)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False
    assert "Annotate-only" in resp.json()["notes"]


# ---------------------------------------------------------------------------
# Phase 1 exit #2 (gap 1): ONE authorized active scan that exercises the FULL
# chain through every category - discovery -> auth -> model -> access control
# (BOLA/BFLA) -> injection -> ssrf (canary) -> misconfig -> evidence -> report.
# ---------------------------------------------------------------------------

class _Gap1Handler(BaseHTTPRequestHandler):
    """Deterministic vuln-app fixture for the full agressive-chain test.

    /session POST echoes the submitted username as the identity's session cookie
    (so runtime.auth.login provisions the two operator-supplied identities), and
    the protected endpoints return inline, vulnerable, deterministic responses.
    """

    def _send(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        if path == "/":
            html = (
                "<html><body>"
                '<form action="/session" method="POST">'
                '<input name="username" type="text"/>'
                '<input name="password" type="password"/>'
                '<input name="submit" type="submit"/>'
                "</form>"
                '<a href="/insecure">insecure</a>'
                '<a href="/set-cookie-bad">bad</a>'
                '<a href="/search">search</a>'
                '<a href="/fetch">fetch</a>'
                '<a href="/login">login</a>'
                '<a href="/account">account</a>'
                '<a href="/admin/users">users</a>'
                "</body></html>"
            )
            self._send(200, html.encode(), extra={"Set-Cookie": "session=guest; Path=/"})
        elif path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "gap1", "version": "1.0.0"},
                "paths": {
                    "/search": {
                        "get": {
                            "parameters": [
                                {"in": "query", "name": "q", "schema": {"type": "string"}}
                            ],
                            "responses": {"200": {"description": "ok"}},
                        }
                    },
                    "/fetch": {
                        "get": {
                            "parameters": [
                                {"in": "query", "name": "url", "schema": {"type": "string", "format": "uri"}}
                            ],
                            "responses": {"200": {"description": "ok"}},
                        }
                    },
                },
            }
            import json as _json
            self._send(200, _json.dumps(spec).encode(), ctype="application/json")
        elif path == "/insecure":
            self._send(200, b"ok", extra={"Server": "nginx/1.2.3"})
        elif path == "/set-cookie-bad":
            self._send(200, b"ok", extra={"Set-Cookie": "sessionid=abc123; Path=/"})
        elif path == "/search":
            q = (params.get("q") or [""])[0]
            self._send(200, f"search results for: {q}".encode(), ctype="text/plain")
        elif path == "/fetch":
            url = (params.get("url") or [""])[0]
            if not url:
                self._send(400, b"missing url")
                return
            import urllib.request
            try:
                with urllib.request.urlopen(url, timeout=1.5) as resp:
                    body = resp.read()
                self._send(200, body[:256])
            except Exception as exc:
                self._send(502, f"fetch failed: {exc}".encode(), ctype="text/plain")
        elif path == "/login":
            self._send(
                200,
                b'<html><form action="/session" method="POST">'
                b'<input name="username" type="text"/>'
                b'<input name="password" type="password"/>'
                b'<input name="submit" type="submit"/></form></html>',
            )
        elif path == "/session":
            self._send(200, b"ok", extra={"Set-Cookie": "session=guest; Path=/"})
        elif path == "/account":
            # shared resource, identical for every identity -> BOLA signal
            self._send(200, b"ACCOUNT-RESOURCE-123", ctype="text/plain")
        elif path == "/admin/users":
            # privileged-looking path reachable by a test identity -> BFLA signal
            self._send(200, b"USER-LIST-ADMIN", ctype="text/plain")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/session":
            self._send(404, b"not found")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else ""
        username = ""
        for pair in raw.split("&"):
            k, _, v = pair.partition("=")
            if k == "username":
                username = v.replace("+", " ")
        self._send(200, b"ok", extra={f"Set-Cookie": f"session={username or 'guest'}; Path=/"})

    def log_message(self, fmt, *args):
        pass


@pytest.fixture
def gap1_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Gap1Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


GAP1_CREDENTIALS = [
    {"id": "alice", "kind": "form", "username": "alice", "secret": "alice-secret",
     "description": "operator-supplied test identity A"},
    {"id": "bob", "kind": "form", "username": "bob", "secret": "bob-secret",
     "description": "operator-supplied test identity B"},
]


def _aggressive_supervisor_harness(gap1_server, state):
    scope = ScopeGuard(allowed_targets=["127.0.0.1"])
    guard = PolicyGuard(
        policy=ScanPolicy.from_request(intensity="aggressive", rate_limit_rps=1000, allowed_methods=["*"]),
        credentials=CredentialCatalog(GAP1_CREDENTIALS),
    )
    budget = BudgetManager(max_tool_calls=500, max_scan_seconds=120)
    budget.start()
    executor = ToolExecutor(
        registry=get_tool_registry(), scope=scope,
        permissions=PermissionManager(), sandbox=SandboxManager(),
        budget=budget, retry=RetryManager(max_retries=0, base_backoff_seconds=0.0),
        audit=AuditLogger(session_factory=get_session_factory()),
        state=StateManager(session_factory=get_session_factory()),
        approval=ApprovalContext(decisions={
            ApprovalContext.request_id("runtime.test.access_control", gap1_server): True
        }),
    )
    canary = SsrfCanary()
    canary.start()
    supervisor = DeepAgentSupervisor(
        executor=executor, policy_guard=guard, canary=canary,
        identity_store=IdentityStore(), state=state, principal="admin",
        budget=budget, budget_interval_s=0.01,
    )
    return supervisor, canary


async def test_supervisor_full_aggressive_chain_all_categories(db_tables, gap1_server):
    """Phase 1 exit #2: the whole Mode-1 chain in one authorized, pre-approved scan."""
    scan_id = str(uuid.uuid4())
    state = InvestigationState(scan_id=scan_id, target_url=gap1_server, target_repo=None, user="admin")
    sm = StateManager(session_factory=get_session_factory())
    await sm.create(state=state)

    supervisor, canary = _aggressive_supervisor_harness(gap1_server, state)
    try:
        result = await supervisor.run(scan_id=scan_id, target=gap1_server)
    finally:
        canary.stop()

    assert result.harness_ok, result.tool_calls
    assert result.finding_count >= 4

    tools = {c["tool"] for c in result.tool_calls}
    assert {
        "echo",
        "runtime.discovery.crawl",
        "runtime.discovery.openapi",
        "runtime.auth.analyze",
        "runtime.model.build",
        "runtime.auth.login",
        "runtime.test.misconfig",
        "runtime.test.auth_session",
        "runtime.test.injection",
        "runtime.test.access_control",
        "runtime.test.ssrf",
    } <= tools

    assert {"discovery", "model", "tests.auth", "tests.initial"} <= set(result.task_graphs)

    # every planned stage ran with the probe and the harness survived
    assert result.task_graphs["discovery"]["probe.echo"]["status"] == "COMPLETED"
    assert any("auth_login" in node for node in result.task_graphs["tests.auth"])

    all_cats = set()
    for call in result.tool_calls:
        for finding in (call.get("output") or {}).get("findings", []) or []:
            all_cats.add(finding.get("category"))

    assert {"bola", "bfla", "misconfiguration", "ssrf"} <= all_cats, sorted(all_cats)
    assert "injection" in all_cats, sorted(all_cats)  # active payloads fired at /search

    # identities provisioned in-scan (secrets never persisted, rules.md §5.5)
    stored = state.data
    assert stored["finding_count"] >= 4
    raw_state = json.dumps(stored)
    assert "alice-secret" not in raw_state and "bob-secret" not in raw_state


# ---------------------------------------------------------------------------
# Phase 1 exit #5 (gap 2): the Human Approval gate end-to-end over the API.
# ---------------------------------------------------------------------------

async def test_api_pending_approval_decision_resume_flow(client, api_headers, db_tables, gap1_server):
    """A protected action pauses the scan; an explicit decision resumes it.

    Flow: POST /scans (no approval seeded) -> PENDING_APPROVAL -> GET approvals
    -> operator approves -> POST resume (re-supplied identities) -> COMPLETED.
    """
    resp = await client.post(
        "/scans",
        json={
            "target_url": gap1_server,
            "intensity": "active",
            "credentials": GAP1_CREDENTIALS,
        },
        headers=api_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    scan_id = body["scan_id"]
    assert body["status"] == "PENDING_APPROVAL", body

    approvals = await client.get(f"/scans/{scan_id}/approvals", headers=api_headers)
    assert approvals.status_code == 200, approvals.text
    entries = approvals.json()
    ac = [e for e in entries if e["tool"] == "runtime.test.access_control"]
    assert ac and ac[0]["decision"] is None and ac[0]["status"] == "PENDING_APPROVAL"

    # resume before a decision is refused - there is nothing to resume yet
    blocked = await client.post(
        f"/scans/{scan_id}/resume", json={"credentials": GAP1_CREDENTIALS}, headers=api_headers
    )
    assert blocked.status_code == 409, blocked.text

    decision = await client.post(
        f"/scans/{scan_id}/approvals/{ac[0]['approval_id']}/decision",
        json={"approved": True, "reason": "operator accepts cross-user test on sandbox target"},
        headers=api_headers,
    )
    assert decision.status_code == 200, decision.text
    assert decision.json()["approved"] is True

    resumed = await client.post(
        f"/scans/{scan_id}/resume", json={"credentials": GAP1_CREDENTIALS}, headers=api_headers
    )
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["status"] == "COMPLETED", resumed.text

    state_resp = await client.get(f"/scans/{scan_id}", headers=api_headers)
    st = state_resp.json()
    assert st["status"] == "COMPLETED"
    tools = {c["tool"] for c in st["state"]["tool_calls"]}
    assert "runtime.test.access_control" in tools
    assert st["state"]["finding_count"] >= 4

    # the operator decision is audited on the record
    audit = await client.get("/audit", headers=api_headers)
    assert audit.status_code == 200
    approval_actions = [
        a for a in audit.json()
        if a["tool"] == "approval" and a["scan_id"] == scan_id
        and a["action"] == f"approval:{ac[0]['approval_id']}"
    ]
    assert approval_actions, "approval decision must be present in the audit trail"
    assert approval_actions[0]["permission_decision"]["allowed"] is True
    assert approval_actions[0]["result"] == "APPROVED"


async def test_api_approval_rejected_skips_protected_action(client, api_headers, db_tables, gap1_server):
    """Rejecting the request leaves the protected action out of the run."""
    resp = await client.post(
        "/scans",
        json={
            "target_url": gap1_server,
            "intensity": "active",
            "credentials": GAP1_CREDENTIALS,
        },
        headers=api_headers,
    )
    assert resp.status_code == 201, resp.text
    scan_id = resp.json()["scan_id"]
    assert resp.json()["status"] == "PENDING_APPROVAL"

    approvals = (await client.get(f"/scans/{scan_id}/approvals", headers=api_headers)).json()
    ac = next(e for e in approvals if e["tool"] == "runtime.test.access_control")

    decision = await client.post(
        f"/scans/{scan_id}/approvals/{ac['approval_id']}/decision",
        json={"approved": False},
        headers=api_headers,
    )
    assert decision.status_code == 200
    assert decision.json()["status"] == "REJECTED"

    resumed = await client.post(
        f"/scans/{scan_id}/resume", json={"credentials": GAP1_CREDENTIALS}, headers=api_headers
    )
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["status"] == "COMPLETED"

    st = (await client.get(f"/scans/{scan_id}", headers=api_headers)).json()
    tools = {c["tool"] for c in st["state"]["tool_calls"]}
    # the protected action never RAN: recorded only as the denied gate outcome
    ac_calls = [c for c in st["state"]["tool_calls"] if c["tool"] == "runtime.test.access_control"]
    assert ac_calls and all(c["status"] == "APPROVAL_DENIED" for c in ac_calls), ac_calls
    all_cats = set()
    for c in st["state"]["tool_calls"]:
        for finding in (c.get("output") or {}).get("findings", []) or []:
            all_cats.add(finding.get("category"))
    assert "bola" not in all_cats and "bfla" not in all_cats
    # the rejected attempt is nonetheless in the audit trail as REQUIRED then DENIED
    audit = (await client.get("/audit", headers=api_headers)).json()
    ac_rows = [
        a for a in audit
        if a["tool"] == "runtime.test.access_control" and a["scan_id"] == scan_id
    ]
    assert ac_rows
    assert any(r["result"] == "APPROVAL_DENIED" for r in ac_rows)