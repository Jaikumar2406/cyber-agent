"""Deep Agent Supervisor (runtime slice) - phases.md §1.9.

Executes a deterministic Mode-1 plan through the Tool Executor (the single
enforcement path: Scope -> Policy -> Permission -> Budget -> Sandbox -> Retry
-> Audit -> Evidence) in stages:

    discovery (crawl + openapi + auth.analyze, parallel)
        -> model (model.build merged from discovery outputs)
        -> tests (misconfig/auth_session/injection/access_control/ssrf/nuclei)
        -> re-plan (extra tests for endpoints discovery surfaced but unplanned)

Stage failures are best-effort: a tool node that fails (e.g. crawl found no
endpoints on a reachable site) is recorded as FAILED in the task graph and the
scan continues. Only terminal failures (budget exhaustion, unknown tool,
invalid args) abort.

Discovery MUST prove the target is reachable: the scan is only COMPLETED when
the harness path executed (probe.echo succeeded) AND discovery performed a real
HTTP round-trip to the target (crawl produced endpoints, auth.analyze sampled
the page, or OpenAPI fetched a spec). A target that never answers ANY request
during discovery yields an UNREACHABLE outcome (harness_ok=False) - a down or
unreachable target is a failure to scan, not a scan with zero findings.

The offline LLM annotator runs *after* planning and can only add words to the
plan - it never changes what the supervisor executes (rules.md §2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.control_plane.policy import OPERATIONS_BY_INTENSITY
from app.harness.approval_manager import ApprovalRequired
from app.harness.executor import ToolCallRecord, ToolExecutor, ToolTerminalFailure
from app.harness.task_graph import TaskGraph, TaskNode
from app.planner.llm import LlmAnnotator
from app.planner.planner import (
    Mode1Planner,
    PlanTask,
    RuntimePlan,
    STAGE_DISCOVERY,
    STAGE_MODEL,
    STAGE_TESTS,
    task_id,
)
from app.schemas.common import ToolResultStatus

log = get_logger("aegis.planner.supervisor")


class _NodeFailed(Exception):
    """Carries a best-effort per-node failure through the task graph."""

    def __init__(self, status: str, error: str | None = None) -> None:
        super().__init__(error or status)
        self.status = status
        self.error = error or status


@dataclass
class SupervisorResult:
    plan: RuntimePlan
    stages: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    finding_count: int = 0
    harness_ok: bool = False
    target_reachable: bool = False
    task_graphs: dict[str, dict[str, Any]] = field(default_factory=dict)
    llm_annotations: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "finding_count": self.finding_count,
            "harness_ok": self.harness_ok,
            "target_reachable": self.target_reachable,
            "stages": self.stages,
            "tool_calls": self.tool_calls,
            "plan": self.plan.summary(),
        }


class DeepAgentSupervisor:
    def __init__(
        self,
        *,
        executor: ToolExecutor,
        policy_guard,
        canary,
        identity_store,
        state,
        principal: str,
        budget=None,
        budget_interval_s: float = 0.05,
        planner: Mode1Planner | None = None,
        annotator: LlmAnnotator | None = None,
        hint_endpoints: list[str] | None = None,
    ) -> None:
        self.executor = executor
        self.policy_guard = policy_guard
        self.canary = canary
        self.identity_store = identity_store
        self.state = state
        self.principal = principal
        self.budget = budget
        self.budget_interval_s = budget_interval_s
        self.planner = planner or Mode1Planner()
        self.annotator = annotator if annotator is not None else LlmAnnotator()
        self.hint_endpoints = list(hint_endpoints or [])
        self._tool_calls: list[dict[str, Any]] = []
        self._finding_total = 0
        self._pending_approvals: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ run

    async def run(
        self,
        *,
        scan_id: str,
        target: str,
    ) -> SupervisorResult:
        from app.control_plane.policy import OPERATIONS_BY_INTENSITY

        from app.planner.planner import _payload_ids_for

        policy = self.policy_guard.policy
        operations = OPERATIONS_BY_INTENSITY[policy.intensity]
        capabilities = self._compute_capabilities(
            payload_ids=_payload_ids_for(policy),
            operations=operations,
        )

        plan = self.planner.plan(
            target_url=target,
            policy=policy,
            capabilities=capabilities,
            hint_endpoints=self.hint_endpoints,
        )
        plan.llm_annotations = self._annotate(plan) or []
        self.state["plan"] = plan.summary()

        result = SupervisorResult(plan=plan)

        discovery_nodes = [self._to_node(t) for t in plan.tasks if t.stage == STAGE_DISCOVERY]
        graph, _records = await self._run_stage(
            scan_id, target, discovery_nodes, plan, node_name=STAGE_DISCOVERY
        )
        result.stages.append(
            {"stage": STAGE_DISCOVERY, "tasks": _stage_summary(plan, STAGE_DISCOVERY), "nodes": dict(graph)}
        )
        result.task_graphs[STAGE_DISCOVERY] = graph

        crawl = _output_of(self._tool_calls, "runtime.discovery.crawl")
        openapi = _output_of(self._tool_calls, "runtime.discovery.openapi")
        auth = _output_of(self._tool_calls, "runtime.auth.analyze")

        model_args = {
            "crawl_result": crawl or {},
            "auth_analysis": auth or {},
        }
        spec_url = (openapi or {}).get("spec_url")
        if spec_url:
            model_args["spec_url"] = spec_url
        model_node = TaskNode(
            id="model.build",
            tool_name="runtime.model.build",
            args=model_args,
        )
        graph, _records = await self._run_stage(scan_id, target, [model_node], plan, node_name=STAGE_MODEL)
        result.stages.append(
            {"stage": STAGE_MODEL, "tasks": _stage_summary(plan, STAGE_MODEL), "nodes": dict(graph)}
        )
        result.task_graphs[STAGE_MODEL] = graph
        model_out = _output_of(self._tool_calls, "runtime.model.build") or {}

        # --- Auth stage (phases.md §1.3): provision the two operator-supplied test
        # identities BEFORE the cross-user tests run. Only planned when the scan has
        # test identities (active+) and discovery surfaced a login endpoint. Runs in
        # its own stage ahead of tests.initial so access_control finds them in the
        # in-memory identity store.
        login_tasks = self._plan_login_tasks(model_out, capabilities)
        if login_tasks:
            plan.tasks.extend(login_tasks)
            graph, _records = await self._run_stage(
                scan_id, target, [self._to_node(t) for t in login_tasks], plan,
                node_name="tests.auth",
            )
            result.stages.append(
                {"stage": STAGE_TESTS, "tasks": [t.id for t in login_tasks], "nodes": dict(graph)}
            )
            result.task_graphs["tests.auth"] = graph

        test_tasks = self.planner.plan_tests(
            model_out,
            target_url=target,
            policy=policy,
            capabilities=capabilities,
        )
        plan.tasks.extend(test_tasks)
        test_nodes = [self._to_node(t) for t in test_tasks if t.is_tool]
        graph, _records = await self._run_stage(
            scan_id, target, test_nodes, plan, node_name="tests.initial"
        )
        result.stages.append(
            {"stage": STAGE_TESTS, "tasks": _stage_summary(plan, STAGE_TESTS), "nodes": dict(graph)}
        )
        result.task_graphs["tests.initial"] = graph

        # A protected action returned PENDING_APPROVAL: pause the scan here so the
        # operator can decide (Phase 1 exit #5). The pending request is already
        # audited + recorded on state by the executor/supervisor node path.
        self._raise_if_approval_pending()

        extra = self.planner.replan(
            plan,
            model=model_out,
            policy=policy,
            capabilities=capabilities,
            discovered_endpoints=self.hint_endpoints,
        )
        if extra:
            plan.tasks.extend(extra)
            extra_nodes = [self._to_node(t) for t in extra if t.is_tool]
            graph, _records = await self._run_stage(scan_id, target, extra_nodes, plan, node_name="tests.replan")
            result.stages.append(
                {"stage": STAGE_TESTS, "tasks": [t.id for t in extra], "nodes": dict(graph)}
            )
            result.task_graphs["tests.replan"] = graph

        plan.tasks = [t for t in plan.tasks if not (t.stage == STAGE_TESTS and not t.is_tool)]
        plan.tasks.append(
            PlanTask(id="report.generate", tool="report", stage="report", note="report slice (Phase 1.8)")
        )
        self.state["plan"] = plan.summary()

        result.plan = plan
        result.tool_calls = list(self._tool_calls)
        result.finding_count = self._finding_total
        result.llm_annotations = plan.llm_annotations
        result.target_reachable = self._target_reachable()
        result.harness_ok = (
            any(
                c.get("tool") == "echo" and c.get("status") == "SUCCESS" for c in self._tool_calls
            )
            and result.target_reachable
        )
        if result.finding_count:
            self.state["finding_count"] = result.finding_count
        log.info(
            "supervisor.completed",
            scan_id=scan_id,
            target=target,
            findings=result.finding_count,
            tools=len(result.tool_calls),
            harness_ok=result.harness_ok,
            target_reachable=result.target_reachable,
        )
        return result

    # ------------------------------------------------------------------ helpers

    async def _run_stage(
        self,
        scan_id: str,
        target: str,
        nodes: list[TaskNode],
        plan: RuntimePlan,
        node_name: str,
    ) -> tuple[dict[str, Any], None]:
        from app.harness.budget_manager import AsyncBudgetGuard

        graph = TaskGraph()
        for node in nodes:
            graph.add(node)

        def _stage_of(node: TaskNode) -> str:
            return next((t.stage for t in plan.tasks if t.id == node.id), node_name)

        async def execute_node(node: TaskNode) -> None:
            record: ToolCallRecord = await self.executor.execute_tool(
                node.tool_name,
                node.args,
                principal=self.principal,
                scan_id=scan_id,
                target=target,
                policy_guard=self.policy_guard,
                canary=self.canary,
                identity_store=self.identity_store,
                stage=_stage_of(node),
            )
            node.result = record.__dict__
            node.error = record.error or record.status.value
            call = {
                "tool": record.tool,
                "args": record.args,
                "status": record.status.value,
                "output": record.output,
                "finding_count": int(record.output.get("finding_count", 0)),
                "evidence_refs": list(record.evidence_refs),
                "audit_id": record.audit_id,
                "stage": _stage_of(node),
            }
            self._tool_calls.append(call)
            self._finding_total += call["finding_count"]
            self.state.record_tool_call({k: v for k, v in call.items() if k != "output"})
            for ref in record.evidence_refs:
                self.state.add_evidence_ref(ref)
            if record.status == ToolResultStatus.PENDING_APPROVAL:
                request = dict(record.output or {})
                self._pending_approvals.append(request)
                self.state["pending_approvals"] = list(self._pending_approvals)
            if record.status.value != "SUCCESS":
                raise _NodeFailed(record.status.value, node.error)

        if self.budget is not None:
            outcome = await AsyncBudgetGuard(self.budget, interval_s=self.budget_interval_s).run(
                graph.run(execute_node)
            )
        else:
            outcome = await graph.run(execute_node)

        snapshot = graph.snapshot()
        return snapshot["nodes"], None

    def _annotate(self, plan: RuntimePlan) -> list[str]:
        if not self.annotator.enabled:
            return []
        plan_text = "\n".join(
            f"- {t.stage}/{t.tool} (deps: {','.join(t.deps) or '-'}): {t.note or t.id}"
            for t in plan.tasks
            if t.is_tool
        )
        return self.annotator.annotate_plan(plan_text, target=plan.target) or []

    def _plan_login_tasks(self, model: dict[str, Any], capabilities) -> list[PlanTask]:
        """Planning for phases.md §1.3: one auth.login task per operator-supplied
        test identity, submitted to the discovered login endpoint.

        Only planned when the scan carries test identities (active+) and discovery
        surfaced a login URL - otherwise cross-user tests simply find no
        identities and the scan keeps the honest "no store" outcome.
        """
        operations = OPERATIONS_BY_INTENSITY[self.policy_guard.policy.intensity]
        if "cross_user" not in operations or not capabilities.credential_ids:
            return []
        login_urls = model.get("login_endpoints") or []
        if not login_urls:
            return []
        login_url = str(login_urls[0])

        catalog = getattr(self.policy_guard, "credentials", None)
        tasks: list[PlanTask] = []
        for credential_id in capabilities.credential_ids[:2]:
            kind = "form"
            if catalog is not None:
                credential = catalog.by_id(credential_id)
                if credential is not None:
                    kind = credential.kind
            tasks.append(
                PlanTask(
                    id=task_id("auth", "auth_login", credential_id),
                    tool="runtime.auth.login",
                    args={"url": login_url, "credential_id": credential_id, "kind": kind},
                    stage=STAGE_TESTS,
                    note=f"provision test identity for operator-supplied credential {credential_id!r}",
                )
            )
        return tasks

    def _raise_if_approval_pending(self) -> None:
        """Pause the scan when a protected action is awaiting operator approval."""
        if self._pending_approvals:
            raise ApprovalRequired(self._pending_approvals[-1])

    def _target_reachable(self) -> bool:
        """Whether mandatory discovery performed a real HTTP round-trip to the target.

        Discovery MUST prove reachability: a crawl that never received an HTTP
        response from the seed (0 endpoints, pages_fetched == 0, no explicit
        `reachable` flag) means the target could not be scanned at all. A
        successful single-page crawl, auth.analyze sample, or OpenAPI fetch is
        sufficient proof; otherwise the scan is reported as UNREACHABLE rather
        than an honest-but-empty COMPLETED run (scope checks are unchanged).
        """
        crawl_out = _output_of(self._tool_calls, "runtime.discovery.crawl")
        if crawl_out.get("endpoints"):
            return True
        if crawl_out.get("reachable") is True:
            return True
        for tool in ("runtime.auth.analyze", "runtime.discovery.openapi"):
            if any(
                c.get("tool") == tool and c.get("status") == "SUCCESS" for c in self._tool_calls
            ):
                return True
        return False

    def _compute_capabilities(self, *, payload_ids: tuple[str, ...], operations: frozenset[str]):
        from app.planner.planner import Capabilities

        credentials = getattr(self.policy_guard, "credentials", None)
        credential_ids = tuple(
            c["id"] for c in credentials.describe()
        ) if credentials is not None else ()
        return Capabilities(
            payload_ids=payload_ids,
            credential_ids=credential_ids,
            nuclei_available=DeepAgentSupervisor._nuclei_available(),
        )

    @staticmethod
    def _nuclei_available() -> bool:
        try:
            from app.core.config import get_settings
            from app.tools.test_nuclei import _resolve_binary, _templates_available

            settings = get_settings()
            return (
                _resolve_binary(settings.nuclei_binary) is not None
                and _templates_available(settings.nuclei_templates_dir)
            )
        except Exception:  # noqa: BLE001 - a capability probe never blocks planning
            return False

    @staticmethod
    def _to_node(task: PlanTask) -> TaskNode:
        return TaskNode(id=task.id, tool_name=task.tool, args=task.args, deps=list(task.deps))


def _output_of(calls: list[dict[str, Any]], tool: str) -> dict[str, Any] | None:
    for call in calls:
        if call.get("tool") == tool:
            out = call.get("output") or {}
            return out if isinstance(out, dict) else {}
    return {}


def _stage_summary(plan: RuntimePlan, stage: str) -> list[str]:
    return [t.id for t in plan.tasks if t.stage == stage and t.is_tool]