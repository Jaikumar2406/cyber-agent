"""Phase 1.9 orchestrator - one POST /scans runs the full Mode-1 chain.

Control Plane chain (auth -> authorization -> policy -> mode -> target
approval) then the Deep Agent Supervisor drives the deterministic planner
through the Tool Executor:

    discovery -> model -> tests -> re-plan -> evidence -> (report slice)

A completed scan means the harness path executed (the probe.echo node
succeeded) AND discovery proved the target is reachable. A target that never
answers during discovery is UNREACHABLE - a failure to scan, not a completed
scan with zero findings (the report stays honest in both cases).
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import Any

from app.control_plane.authorization import AuthorizationStub
from app.control_plane.canary import SsrfCanary
from app.control_plane.credentials import CredentialCatalog
from app.control_plane.mode_selector import ModeSelectionError, select_mode
from app.control_plane.policy import PolicyGuard, PolicyValidationError, ScanPolicy
from app.control_plane.scope import ScopeGuard, TargetApproval
from app.core.logging import get_logger
from app.harness.approval_manager import ApprovalContext, ApprovalRequired
from app.harness.audit_logger import AuditLogger
from app.harness.budget_manager import AsyncBudgetGuard, BudgetManager
from app.harness.checkpoint_manager import CheckpointManager
from app.harness.executor import ToolExecutor
from app.harness.observer import get_observer
from app.harness.permission_manager import PermissionManager
from app.harness.retry_manager import RetryManager
from app.harness.sandbox_manager import SandboxManager
from app.harness.state_manager import InvestigationState, StateManager
from app.planner.supervisor import DeepAgentSupervisor
from app.schemas.common import ScanStatus
from app.auth_analysis.identity import IdentityStore

log = get_logger("aegis.planner.orchestrator")


class OrchestrationError(Exception):
    pass


@dataclass
class DeepAgentConfig:
    max_tool_calls: int = 100
    max_scan_seconds: float = 1800.0
    budget_interval_s: float = 0.05


class DeepAgentOrchestrator:
    def __init__(
        self,
        *,
        config: DeepAgentConfig | None = None,
        session_factory=None,
        audit: AuditLogger | None = None,
        state: StateManager | None = None,
        checkpoints: CheckpointManager | None = None,
        observer=None,
    ) -> None:
        self.config = config or DeepAgentConfig()
        from app.core.db import get_session_factory

        self._session_factory = session_factory or get_session_factory()
        self.audit = audit or AuditLogger(session_factory=self._session_factory)
        self.state = state or StateManager(session_factory=self._session_factory)
        self.checkpoints = checkpoints or CheckpointManager(session_factory=self._session_factory)
        self.observer = observer or get_observer()
        self._authz = AuthorizationStub()

    async def run_mode1_scan(
        self,
        *,
        principal: str,
        target_url: str | None,
        target_repo: str | None,
        intensity: str = "passive",
        rate_limit_rps: float = 10.0,
        allowed_methods: list[str] | None = None,
        hint_endpoints: list[str] | None = None,
        credentials: CredentialCatalog | None = None,
    ) -> str:
        from app.control_plane.auth import Principal as _Principal

        authz = self._authz.check(_Principal(username=principal), "write:scan:create")
        if not authz.allowed:
            raise OrchestrationError(f"authorization denied: {authz.reason}")

        try:
            scan_policy = ScanPolicy.from_request(
                intensity=intensity,
                rate_limit_rps=rate_limit_rps,
                allowed_methods=allowed_methods,
            )
        except PolicyValidationError as exc:
            raise OrchestrationError(f"policy invalid: {exc.issues}") from exc

        try:
            selection = select_mode(target_url=target_url, target_repo=target_repo)
        except ModeSelectionError as exc:
            raise OrchestrationError(str(exc)) from exc

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

        scan_id = str(uuid.uuid4())
        investigation = InvestigationState(
            scan_id=scan_id,
            target_url=target_url,
            target_repo=target_repo,
            user=principal,
        )
        investigation["mode"] = selection.mode.value
        investigation["intensity"] = scan_policy.intensity.value
        investigation["scope_approval"] = {
            "target": target_url,
            "approved": True,
            "reason": approval.reason,
        }
        investigation["hint_endpoints"] = list(hint_endpoints or [])
        investigation["plan"] = {
            "intent": "mode1_deep_agent",
            "engines": list(selection.dependencies.engines),
            "policy": scan_policy.as_dict(),
        }
        investigation["policy"] = scan_policy.as_dict()
        await self.state.create(state=investigation)
        self.observer.emit("scan.created", scan_id=scan_id, mode=selection.mode.value)

        budget = BudgetManager(
            max_tool_calls=self.config.max_tool_calls,
            max_scan_seconds=self.config.max_scan_seconds,
        )
        budget.start()

        approval_context = ApprovalContext()
        policy_guard = PolicyGuard(policy=scan_policy, credentials=credentials)
        executor = ToolExecutor(
            scope=scope_guard,
            permissions=PermissionManager(),
            sandbox=SandboxManager(),
            budget=budget,
            retry=RetryManager(),
            audit=self.audit,
            state=self.state,
            approval=approval_context,
        )
        identity_store = IdentityStore()

        supervisor = DeepAgentSupervisor(
            executor=executor,
            policy_guard=policy_guard,
            canary=canary,
            identity_store=identity_store,
            state=investigation,
            principal=principal,
            budget=budget,
            budget_interval_s=self.config.budget_interval_s,
            hint_endpoints=hint_endpoints,
        )

        try:
            investigation["status"] = ScanStatus.RUNNING.value
            await self.state.update(investigation)
            await self.checkpoints.save(scan_id, "started", investigation.data)

            result = await AsyncBudgetGuard(budget, interval_s=self.config.budget_interval_s).run(
                supervisor.run(scan_id=scan_id, target=target_url or "http://localhost/")
            )

            investigation["supervisor"] = result.summary()
            investigation["task_graph"] = {
                stage: nodes for stage, nodes in result.task_graphs.items()
            }
            investigation["tool_calls"] = result.tool_calls
            investigation["finding_count"] = result.finding_count
            investigation["budgets"] = budget.snapshot().__dict__
            investigation["target_reachable"] = result.target_reachable
            if not result.target_reachable:
                investigation["status"] = ScanStatus.UNREACHABLE.value
                investigation["errors"].append(
                    {
                        "error": (
                            f"target {target_url!r} could not be reached during discovery: "
                            "discovery never received an HTTP response from the target"
                        ),
                        "stage": "discovery",
                    }
                )
                checkpoint = "unreachable"
            else:
                investigation["status"] = (
                    ScanStatus.COMPLETED.value if result.harness_ok else ScanStatus.FAILED.value
                )
                checkpoint = "completed"

            await self.checkpoints.save(scan_id, checkpoint, investigation.data)
            await self.state.update(investigation)
            self.observer.emit(
                "scan.unreachable" if not result.target_reachable else "scan.completed",
                scan_id=scan_id,
                ok=result.harness_ok,
                tool_calls=budget.tool_calls_used,
                findings=result.finding_count,
            )
            return scan_id

        except ApprovalRequired as exc:
            # Phase 1 exit #5: a protected action paused the scan for explicit
            # operator approval. The request is audited; the decision is persisted
            # in the scan state for the explicit resume path.
            investigation["pending_approvals"] = list(
                investigation.data.get("pending_approvals") or []
            ) or [exc.request]
            investigation["approval_decisions"] = approval_context.snapshot()
            partial_tool_calls = investigation.data.get("tool_calls") or []
            investigation["tool_calls"] = partial_tool_calls
            investigation["finding_count"] = sum(
                int(c.get("finding_count", 0)) for c in partial_tool_calls
            )
            investigation["budgets"] = budget.snapshot().__dict__
            investigation["supervisor"] = {"status": "PENDING_APPROVAL", "reason": str(exc)}
            investigation["status"] = ScanStatus.PENDING_APPROVAL.value
            await self.checkpoints.save(scan_id, "approval_pending", investigation.data)
            await self.state.update(investigation)
            self.observer.emit("scan.awaiting_approval", scan_id=scan_id, request=exc.request)
            return scan_id

        except asyncio.CancelledError:
            investigation["status"] = ScanStatus.FAILED.value
            investigation["errors"].append(
                {"error": "runaway loop hard-stopped by Budget Manager", "stage": "mode1"}
            )
            await self.state.update(investigation)
            await self.checkpoints.save(scan_id, "failed", investigation.data)
            self.observer.emit("scan.hard_stopped", scan_id=scan_id)
            raise

        except Exception as exc:
            investigation["status"] = ScanStatus.FAILED.value
            investigation["errors"].append({"error": str(exc), "stage": "mode1"})
            await self.state.update(investigation)
            await self.checkpoints.save(scan_id, "failed", investigation.data)
            self.observer.emit("scan.failed", scan_id=scan_id, error=str(exc))
            raise

        finally:
            canary.stop()

    async def resume_mode1_scan(
        self,
        *,
        principal: str,
        scan_id: str,
        credentials: CredentialCatalog | None = None,
    ) -> str:
        """Explicit resume of a PENDING_APPROVAL scan (Phase 1 exit #5).

        Rebuilds the scan from its persisted state, seeds the approval context
        with the recorded operator decisions, and re-runs the supervised chain.
        Undecided approvals block the resume (there is nothing to resume yet).
        The credential catalog is re-supplied by the approving operator because
        the raw test credentials/identities are deliberately never persisted.
        """
        from app.control_plane.auth import Principal as _Principal

        authz = self._authz.check(_Principal(username=principal), "write:scan:resume")
        if not authz.allowed:
            raise OrchestrationError(f"authorization denied: {authz.reason}")

        investigation = await self.state.get(scan_id)
        if investigation.data.get("status") != ScanStatus.PENDING_APPROVAL.value:
            raise OrchestrationError(
                f"scan {scan_id} is not awaiting approval (status={investigation.data.get('status')})"
            )

        pending = investigation.data.get("pending_approvals") or []
        decisions = investigation.data.get("approval_decisions") or {}
        undecided = [p for p in pending if decisions.get(p["approval_id"]) is None]
        if undecided:
            raise OrchestrationError(
                "scan still has unresolved approval requests: "
                + ", ".join(p.get("approval_id", "?") for p in undecided)
            )

        policy_dict = investigation.data.get("policy") or (investigation.data.get("plan") or {}).get("policy") or {}
        try:
            scan_policy = ScanPolicy.from_request(
                intensity=policy_dict.get("intensity", "passive"),
                rate_limit_rps=policy_dict.get("rate_limit_rps", 10.0),
                allowed_methods=policy_dict.get("allowed_methods"),
            )
        except PolicyValidationError as exc:
            raise OrchestrationError(f"persisted policy invalid: {exc.issues}") from exc

        hint_endpoints = investigation.data.get("hint_endpoints") or []
        target_url = investigation.data.get("target_url")

        canary = SsrfCanary()
        canary.start()
        try:
            scope_guard = ScopeGuard(canary=canary)
            approval = await TargetApproval(scope_guard=scope_guard, audit=self.audit).authorize(
                target=target_url, principal=principal
            )
            if not approval.approved:
                raise OrchestrationError(
                    f"target not approved for resume (rules.md §3.1): {approval.reason}"
                )
        except Exception:
            canary.stop()
            raise

        budget = BudgetManager(
            max_tool_calls=self.config.max_tool_calls,
            max_scan_seconds=self.config.max_scan_seconds,
        )
        budget.start()

        approval_context = ApprovalContext(
            decisions={aid: bool(decided) for aid, decided in decisions.items()}
        )
        policy_guard = PolicyGuard(policy=scan_policy, credentials=credentials)
        executor = ToolExecutor(
            scope=scope_guard,
            permissions=PermissionManager(),
            sandbox=SandboxManager(),
            budget=budget,
            retry=RetryManager(),
            audit=self.audit,
            state=self.state,
            approval=approval_context,
        )
        identity_store = IdentityStore()

        supervisor = DeepAgentSupervisor(
            executor=executor,
            policy_guard=policy_guard,
            canary=canary,
            identity_store=identity_store,
            state=investigation,
            principal=principal,
            budget=budget,
            budget_interval_s=self.config.budget_interval_s,
            hint_endpoints=hint_endpoints,
        )

        try:
            investigation["status"] = ScanStatus.RUNNING.value
            await self.state.update(investigation)
            await self.checkpoints.save(scan_id, "resumed", investigation.data)

            result = await AsyncBudgetGuard(budget, interval_s=self.config.budget_interval_s).run(
                supervisor.run(scan_id=scan_id, target=target_url or "http://localhost/")
            )

            investigation["supervisor"] = result.summary()
            investigation["task_graph"] = {
                stage: nodes for stage, nodes in result.task_graphs.items()
            }
            investigation["tool_calls"] = result.tool_calls
            investigation["finding_count"] = result.finding_count
            investigation["budgets"] = budget.snapshot().__dict__
            investigation["target_reachable"] = result.target_reachable
            if not result.target_reachable:
                investigation["status"] = ScanStatus.UNREACHABLE.value
                investigation["errors"].append(
                    {
                        "error": (
                            f"target {target_url!r} could not be reached during discovery: "
                            "discovery never received an HTTP response from the target"
                        ),
                        "stage": "discovery",
                    }
                )
                checkpoint = "unreachable"
            else:
                investigation["status"] = (
                    ScanStatus.COMPLETED.value if result.harness_ok else ScanStatus.FAILED.value
                )
                checkpoint = "completed"

            await self.checkpoints.save(scan_id, checkpoint, investigation.data)
            await self.state.update(investigation)
            self.observer.emit(
                "scan.unreachable" if not result.target_reachable else "scan.completed",
                scan_id=scan_id,
                ok=result.harness_ok,
                tool_calls=budget.tool_calls_used,
                findings=result.finding_count,
            )
            return scan_id

        except ApprovalRequired as exc:
            pending_so_far = list(investigation.data.get("pending_approvals") or [])
            new_request = exc.request
            if not any(p.get("approval_id") == new_request.get("approval_id") for p in pending_so_far):
                pending_so_far.append(new_request)
            investigation["pending_approvals"] = pending_so_far
            investigation["approval_decisions"] = approval_context.snapshot()
            investigation["status"] = ScanStatus.PENDING_APPROVAL.value
            await self.checkpoints.save(scan_id, "approval_pending", investigation.data)
            await self.state.update(investigation)
            self.observer.emit("scan.awaiting_approval", scan_id=scan_id, request=exc.request)
            return scan_id

        except asyncio.CancelledError:
            investigation["status"] = ScanStatus.FAILED.value
            investigation["errors"].append(
                {"error": "runaway loop hard-stopped by Budget Manager", "stage": "resume"}
            )
            await self.state.update(investigation)
            await self.checkpoints.save(scan_id, "failed", investigation.data)
            raise

        except Exception as exc:
            investigation["status"] = ScanStatus.FAILED.value
            investigation["errors"].append({"error": str(exc), "stage": "resume"})
            await self.state.update(investigation)
            await self.checkpoints.save(scan_id, "failed", investigation.data)
            self.observer.emit("scan.failed", scan_id=scan_id, error=str(exc))
            raise

        finally:
            canary.stop()