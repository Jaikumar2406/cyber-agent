"""Phase 0 orchestrator - proves the full harness path with a probe scan.

The real Deep Agent Supervisor (planning/re-planning) arrives in Phase 1+.
This orchestrator exercises every Phase 0 component in the exact order the
architecture mandates:

    Control Plane chain -> Mode Selector -> State -> Task Graph
        -> Tool Executor (scope/permission/budget/sandbox/retry/audit)
        -> Evidence Normalizer -> Checkpoint -> Status

It runs the `echo` probe tool as the "dummy capability" so Phase 0 exit
criterion #1 is demonstrable end-to-end.
"""

import asyncio
from dataclasses import dataclass
from typing import Any

from app.control_plane.authorization import AuthorizationStub
from app.control_plane.canary import SsrfCanary
from app.control_plane.mode_selector import ModeSelection, select_mode
from app.control_plane.policy import PolicyGuard, PolicyValidationError, ScanPolicy
from app.control_plane.scope import ScopeGuard, TargetApproval
from app.core.logging import get_logger
from app.harness.audit_logger import AuditLogger
from app.harness.budget_manager import AsyncBudgetGuard, BudgetManager
from app.harness.checkpoint_manager import CheckpointManager
from app.harness.executor import ToolExecutor, ToolTerminalFailure
from app.harness.observer import get_observer
from app.harness.permission_manager import PermissionManager
from app.harness.retry_manager import RetryManager
from app.harness.sandbox_manager import SandboxManager
from app.harness.state_manager import InvestigationState, StateManager
from app.harness.task_graph import TaskGraph, TaskNode
from app.schemas.common import ScanStatus

log = get_logger("aegis.orchestrator")


class OrchestrationError(Exception):
    pass


@dataclass
class Phase0Config:
    max_tool_calls: int = 5
    max_scan_seconds: float = 30.0
    probe_delay_ms: float = 5.0


class Phase0Orchestrator:
    def __init__(
        self,
        *,
        config: Phase0Config | None = None,
        session_factory=None,
        audit: AuditLogger | None = None,
        state: StateManager | None = None,
        checkpoints: CheckpointManager | None = None,
        observer=None,
    ) -> None:
        self.config = config or Phase0Config()
        from app.core.db import get_session_factory

        self._session_factory = session_factory or get_session_factory()
        self.audit = audit or AuditLogger(session_factory=self._session_factory)
        self.state = state or StateManager(session_factory=self._session_factory)
        self.checkpoints = checkpoints or CheckpointManager(session_factory=self._session_factory)
        self.observer = observer or get_observer()
        self._authz = AuthorizationStub()

    async def run_probe_scan(
        self,
        *,
        principal: str,
        target_url: str | None,
        target_repo: str | None,
        intensity: str = "passive",
        rate_limit_rps: float = 10.0,
        allowed_methods: list[str] | None = None,
    ) -> str:
        # --- Control Plane: auth (done by API layer) + authorization -----------
        from app.control_plane.auth import Principal as _Principal

        authz = self._authz.check(_Principal(username=principal), "write:scan:create")
        if not authz.allowed:
            raise OrchestrationError(f"authorization denied: {authz.reason}")

        # --- Policy validation + real ScanPolicy (Scope & Policy Guard, §1.1) -
        try:
            scan_policy = ScanPolicy.from_request(
                intensity=intensity,
                rate_limit_rps=rate_limit_rps,
                allowed_methods=allowed_methods,
            )
        except PolicyValidationError as exc:
            raise OrchestrationError(f"policy invalid: {exc.issues}")

        # --- Mode selection --------------------------------------------------
        selection: ModeSelection = select_mode(target_url=target_url, target_repo=target_repo)

        # --- Explicit target approval (audited) + live canary -----------------
        canary = SsrfCanary()
        canary.start()
        try:
            scope_guard = ScopeGuard(canary=canary)
            approval = await TargetApproval(scope_guard=scope_guard, audit=self.audit).authorize(
                target=target_url, principal=principal
            )
            if not approval.approved:
                raise OrchestrationError(
                    f"target not approved for scanning (explicit authorization "
                    f"required, rules.md §3.1): {approval.reason}"
                )
        except Exception:
            canary.stop()
            raise

        # --- State creation ---------------------------------------------------
        import uuid as _uuid

        scan_id = str(_uuid.uuid4())
        state = InvestigationState(
            scan_id=scan_id,
            target_url=target_url,
            target_repo=target_repo,
            user=principal,
        )
        state["mode"] = selection.mode.value
        state["plan"] = {
            "intent": "phase0_probe",
            "engines": list(selection.dependencies.engines),
            "policy": scan_policy.as_dict(),
        }
        state["scope_approval"] = {
            "target": target_url,
            "approved": True,
            "reason": approval.reason,
        }
        await self.state.create(state=state)
        self.observer.emit("scan.created", scan_id=scan_id, mode=selection.mode.value)

        budget = BudgetManager(max_scan_seconds=self.config.max_scan_seconds)
        budget.start()

        policy_guard = PolicyGuard(policy=scan_policy)

        executor = ToolExecutor(
            scope=scope_guard,
            permissions=PermissionManager(),
            sandbox=SandboxManager(),
            budget=budget,
            retry=RetryManager(),
            audit=self.audit,
            state=self.state,
        )

        # --- Task graph: single probe node (Mode 1 shape) ---------------------
        graph = TaskGraph()
        graph.add(
            TaskNode(
                id="probe.echo",
                tool_name="echo",
                args={"text": f"aegis-phase0:{scan_id[:8]}", "iterations": 1, "delay_ms": self.config.probe_delay_ms},
            )
        )

        async def execute_node(node: TaskNode) -> None:
            if not state["budgets"]:
                state["budgets"] = budget.snapshot().__dict__
            record = await executor.execute_tool(
                node.tool_name,
                node.args,
                principal=principal,
                scan_id=scan_id,
                target=target_url,
                policy_guard=policy_guard,
                canary=canary,
                stage="probe",
            )
            node.result = record.__dict__
            node.status = "FAILED" if record.status.value != "SUCCESS" else "COMPLETED"
            if node.status == "FAILED":
                node.error = record.error or record.status.value
            state.record_tool_call(
                {"tool": record.tool, "args": record.args, "status": record.status.value,
                 "evidence_refs": record.evidence_refs, "audit_id": record.audit_id}
            )
            for ref in record.evidence_refs:
                state.add_evidence_ref(ref)
            if record.status.value in ("PERMISSION_DENIED", "SCOPE_VIOLATION", "FAILURE"):
                raise ToolTerminalFailure(record.error or record.status.value)

        try:
            state["status"] = ScanStatus.RUNNING.value
            await self.state.update(state)
            await self.checkpoints.save(scan_id, "started", state.data)

            result = await AsyncBudgetGuard(budget, interval_s=0.05).run(graph.run(execute_node))

            state["task_graph"] = graph.snapshot()
            state["status"] = ScanStatus.COMPLETED.value if result.all_succeeded else ScanStatus.FAILED.value
            state["budgets"] = budget.snapshot().__dict__
            await self.checkpoints.save(scan_id, "completed", state.data)
            await self.state.update(state)
            self.observer.emit("scan.completed", scan_id=scan_id,
                               ok=result.all_succeeded, tool_calls=budget.tool_calls_used)
            return scan_id

        except asyncio.CancelledError:
            state["status"] = ScanStatus.FAILED.value
            state["errors"].append({"error": "runaway loop hard-stopped by Budget Manager", "stage": "probe"})
            await self.state.update(state)
            await self.checkpoints.save(scan_id, "failed", state.data)
            self.observer.emit("scan.hard_stopped", scan_id=scan_id)
            raise

        except Exception as exc:
            state["status"] = ScanStatus.FAILED.value
            state["errors"].append({"error": str(exc), "stage": "probe"})
            await self.state.update(state)
            await self.checkpoints.save(scan_id, "failed", state.data)
            self.observer.emit("scan.failed", scan_id=scan_id, error=str(exc))
            raise
        finally:
            canary.stop()