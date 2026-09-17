"""Tool Executor - the single enforcement path (rules.md §6.2).

Every tool call flows:
    Tool Registry  ->  Scope Guard  ->  Policy Guard  ->  Permission Manager
        ->  Budget Manager  ->  Sandbox  ->  Retry Manager
        ->  evidence/normalization  ->  Audit

This module is the wiring; the Agent Supervisor (Phase 5) and the orchestrator
both call it and cannot bypass any step (rules.md §6.1-6.2).
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.control_plane.policy import PolicyGuard, PolicyViolation
from app.harness.approval_manager import ApprovalContext
from app.harness.audit_logger import AuditLogger
from app.harness.budget_manager import BudgetManager, BudgetExceeded
from app.harness.permission_manager import PermissionManager, PermissionDecision
from app.harness.retry_manager import RetryManager
from app.harness.sandbox_manager import SandboxManager, SandboxTaskSpec
from app.harness.state_manager import StateManager
from app.harness.tool_registry import ToolArgumentError, ToolNotFoundError, ToolRegistry
from app.harness.tools import ToolContext
from app.schemas.common import ToolResultStatus
from app.control_plane.scope import ScopeGuard, ScopeViolation

log = get_logger("aegis.harness.executor")


class ToolTerminalFailure(Exception):
    """Terminal outcome (permission/scope/budget) - not retriable."""


@dataclass
class ToolCallRecord:
    tool: str
    args: dict[str, Any]
    status: ToolResultStatus
    output: dict[str, Any]
    error: str | None
    duration_ms: float
    audit_id: str | None
    evidence_refs: list[str]
    decisions: dict[str, Any] = field(default_factory=dict)


class ToolExecutor:
    def __init__(
        self,
        *,
        registry: ToolRegistry | None = None,
        scope: ScopeGuard | None = None,
        permissions: PermissionManager | None = None,
        sandbox: SandboxManager | None = None,
        budget: BudgetManager | None = None,
        retry: RetryManager | None = None,
        audit: AuditLogger | None = None,
        state: StateManager | None = None,
        approval: ApprovalContext | None = None,
    ) -> None:
        from app.harness.tool_registry import get_tool_registry

        self.registry = registry or get_tool_registry()
        self.scope = scope if scope is not None else ScopeGuard()
        self.permissions = permissions or PermissionManager()
        self.sandbox = sandbox or SandboxManager()
        self.budget = budget or BudgetManager()
        self.retry = retry or RetryManager()
        self.audit = audit or AuditLogger()
        self.state = state or StateManager()
        self.approval = approval

    async def execute_tool(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        *,
        principal: str | None = None,
        scan_id: str | None = None,
        target: str | None = None,
        policy: dict[str, Any] | None = None,
        policy_guard: PolicyGuard | None = None,
        canary: Any | None = None,
        credentials: Any | None = None,
        identity_store: Any | None = None,
        stage: str = "general",
    ) -> ToolCallRecord:
        started = time.monotonic()
        args = args or {}
        decisions: dict[str, Any] = {}
        evidence_refs: list[str] = []

        try:
            tool = self.registry.get(tool_name)
        except ToolNotFoundError as exc:
            raise ToolTerminalFailure(str(exc)) from exc

        decisions["registry"] = {"found": True, "name": tool_name}

        # 1. Scope check - BEFORE every execution (rules.md §3.2).
        try:
            self.scope.check(target, scope_kind=stage)
            decisions["scope"] = {"allowed": True}
        except ScopeViolation as exc:
            decisions["scope"] = {"allowed": False, "reason": str(exc)}
            audit_id = await self.audit.record_tool_call(
                user=principal, scan_id=scan_id, agent="harness", tool=tool_name,
                target=target, action=f"tool:{tool_name}", allowed=False,
                decision_reason=str(exc), result="DENIED",
            )
            return self._record(tool_name, args, ToolResultStatus.SCOPE_VIOLATION, {}, str(exc),
                                started, audit_id, evidence_refs, decisions)

        # 2. Policy check - operation gate, controlled payloads (rules.md §3.8).
        if policy_guard is not None:
            try:
                policy_guard.enforce_tool(tool, args)
                decisions["policy"] = {"allowed": True}
            except PolicyViolation as exc:
                decisions["policy"] = {"allowed": False, "reason": str(exc)}
                audit_id = await self.audit.record_tool_call(
                    user=principal, scan_id=scan_id, agent="harness", tool=tool_name,
                    target=target, action=f"tool:{tool_name}", allowed=False,
                    decision_reason=str(exc), result="POLICY_DENIED",
                )
                return self._record(tool_name, args, ToolResultStatus.POLICY_DENIED, {}, str(exc),
                                    started, audit_id, evidence_refs, decisions)

        # 3. Schema validation of arguments.
        try:
            self.registry.validate_args(tool_name, args)
            decisions["args"] = {"valid": True}
        except ToolArgumentError as exc:
            raise ToolTerminalFailure(str(exc)) from exc

        # 4. Permission check.
        perm: PermissionDecision = self.permissions.check(tool, principal=principal, target=target)
        decisions["permission"] = {"allowed": perm.allowed, "requires_approval": perm.requires_approval}
        if not perm.allowed:
            audit_id = await self.audit.record_tool_call(
                user=principal, scan_id=scan_id, agent="harness", tool=tool_name,
                target=target, action=f"tool:{tool_name}", allowed=False,
                decision_reason=perm.reason, result="DENIED",
                requires_approval=perm.requires_approval,
            )
            return self._record(tool_name, args, ToolResultStatus.PERMISSION_DENIED, {}, perm.reason,
                                started, audit_id, evidence_refs, decisions)

        # 4b. Human approval gate (rules.md §10, Phase 1 exit #5). Runs AFTER the
        # permission check (so the grant is verified first) but BEFORE budgeting /
        # execution (so a protected action is never scheduled unreviewed). It sits
        # on TOP of Scope/Policy/Permission - it never bypasses them, and it is
        # deny-closed: no approval context => the action is refused.
        if perm.requires_approval:
            decisions["approval"] = {"required": True}
            approval_context: ApprovalContext | None = getattr(self, "approval", None)
            if approval_context is None:
                decisions["approval"]["decision"] = "denied"
                audits = await self.audit.record_tool_call(
                    user=principal, scan_id=scan_id, agent="harness", tool=tool_name,
                    target=target, action=f"tool:{tool_name}", allowed=True,
                    decision_reason="approval context not provisioned - deny-closed refusal",
                    result="APPROVAL_DENIED", requires_approval=True,
                )
                return self._record(tool_name, args, ToolResultStatus.APPROVAL_DENIED, {}, "deny-closed: no approval context", started, audits, evidence_refs, decisions)
            request = approval_context.request(tool_name, target)
            decision = approval_context.decision_for(tool_name, target)
            decisions["approval"].update({"approval_id": request["approval_id"], "decision": decision})
            if decision is None:
                # Undecided: the scan pauses here. The request is audited verbatim
                # and the Supervisor surfaces it for the operator.
                audit_id = await self.audit.record_tool_call(
                    user=principal, scan_id=scan_id, agent="harness", tool=tool_name,
                    target=target, action=f"tool:{tool_name}", allowed=True,
                    decision_reason=f"human approval required (approval_id={request['approval_id']})",
                    result="PENDING_APPROVAL", requires_approval=True,
                )
                return self._record(
                    tool_name, args, ToolResultStatus.PENDING_APPROVAL, request,
                    f"approval required for {tool_name} (approval_id={request['approval_id']})",
                    started, audit_id, evidence_refs, decisions,
                )
            if not decision:
                # Explicitly rejected: the action is refused and recorded.
                audit_id = await self.audit.record_tool_call(
                    user=principal, scan_id=scan_id, agent="harness", tool=tool_name,
                    target=target, action=f"tool:{tool_name}", allowed=False,
                    decision_reason=f"operator rejected approval {request['approval_id']}",
                    result="APPROVAL_DENIED", requires_approval=True,
                )
                return self._record(tool_name, args, ToolResultStatus.APPROVAL_DENIED, request, "operator denied approval", started, audit_id, evidence_refs, decisions)
            log.info("approval.granted", tool=tool_name, approval_id=request["approval_id"])
            decisions["approval"]["decision"] = True

        # 5. Budget check.
        try:
            self.budget.charge_tool_call()
        except BudgetExceeded as exc:
            decisions["budget"] = {"allowed": False, "reason": str(exc)}
            await self.audit.record_tool_call(
                user=principal, scan_id=scan_id, agent="harness", tool=tool_name,
                target=target, action=f"tool:{tool_name}", allowed=True,
                decision_reason=str(exc), result="BUDGET_EXHAUSTED",
            )
            raise ToolTerminalFailure(str(exc)) from exc
        decisions["budget"] = {"allowed": True}

        policy_dict = policy or (policy_guard.policy.as_dict() if policy_guard else {})
        context = ToolContext(
            scan_id=scan_id,
            principal=principal,
            target=target,
            policy=policy_dict,
            scope_guard=self.scope,
            rate_limiter=policy_guard.limiter if policy_guard is not None else None,
            canary=canary,
            credentials=credentials or (policy_guard.credentials if policy_guard else None),
            identity_store=identity_store,
        )

        # 6. Execute inside the sandbox, wrapped by the Retry Manager.
        async def run_once():
            result = await self.sandbox.execute(
                SandboxTaskSpec(function=tool.run, args=(args, context), sandbox=tool.sandbox)
            )
            return result

        try:
            outcome = await self.retry.execute(run_once)
            result: Any = outcome.result
            status = ToolResultStatus(result.status.value) if hasattr(result, "status") else ToolResultStatus.SUCCESS
            output = dict(result.output) if hasattr(result, "output") else dict(result)
            retry_info = {"attempts": outcome.attempts, "history": outcome.retry_history}
        except Exception as exc:
            result = None
            status = ToolResultStatus.FAILURE
            output = {}
            retry_info = {"error": str(exc)}
            log.warning("tool_execution_raised", tool=tool_name, error=str(exc))

        duration_ms = round((time.monotonic() - started) * 1000, 2)
        audit_id = await self.audit.record_tool_call(
            user=principal, scan_id=scan_id, agent="harness", tool=tool_name,
            target=target, action=f"tool:{tool_name}", allowed=True,
            decision_reason="executed within scope and permissions", result=status.value,
            retry_info=retry_info,
        )

        if status == ToolResultStatus.SUCCESS and output:
            evidence_refs = await self._attach_evidence(
                scan_id, tool_name, output, args, tool=tool, identity_store=identity_store
            )
            evidence_refs += await self._attach_runtime_findings(scan_id, output)

        result_error = getattr(result, "error", None) or output.get("error")
        return self._record(tool_name, args, status, output, result_error, duration_ms,
                            audit_id, evidence_refs, decisions)

    async def _attach_evidence(
        self,
        scan_id: str | None,
        tool_name: str,
        output: dict,
        args: dict,
        *,
        tool: Any | None = None,
        identity_store: Any | None = None,
    ) -> list[str]:
        """Persist a harness evidence record for a successful tool output.

        phases.md §1.6: cross-user tools additionally attach the redacted test
        identity context to the evidence *location* so every cross-user finding
        carries auth-identity proof.
        """
        if not scan_id:
            return []
        from app.evidence.normalizer import EvidenceNormalizer
        normalizer = EvidenceNormalizer(session_factory=self.audit._session_factory)
        location: dict[str, Any] = {"tool": tool_name, "args": args}
        if tool is not None and "cross_user" in getattr(tool, "policy_requirements", ()):
            summaries = (
                identity_store.redacted_summaries()
                if identity_store is not None and hasattr(identity_store, "redacted_summaries")
                else output.get("identities")
            )
            if summaries:
                location["identity"] = summaries
        evidence = await normalizer.add(
            scan_id=scan_id,
            source="HARNESS",
            evidence_type=f"tool:{tool_name}",
            confidence="POTENTIAL",
            location=location,
            payload={"output": output},
        )
        return [str(evidence.id)]

    async def _attach_runtime_findings(self, scan_id: str | None, output: dict) -> list[str]:
        """phases.md §1.7: normalize every finding in a successful tool output
        and persist one real ``RUNTIME`` EvidenceRecord per finding.

        Each record carries OWASP category, affected asset, validated
        severity/confidence (rules.md §2 — severity/confidence flow upward from
        the engine, never downward from the LLM) and the binary of secrets
        already redacted by §1.6 capture.
        """
        if not scan_id:
            return []
        from app.evidence.normalizer import EvidenceNormalizer
        from app.testing.runtime_normalizer import normalize_findings
        normalizer = EvidenceNormalizer(session_factory=self.audit._session_factory)
        refs: list[str] = []
        for finding in normalize_findings(output.get("findings") or []):
            record = await normalizer.add(
                scan_id=scan_id,
                source="RUNTIME",
                evidence_type=f"finding:{finding['category']}",
                confidence=finding["confidence"],
                location={
                    "endpoint": finding["endpoint"],
                    "affected_asset": finding["affected_asset"],
                    "owasp": finding["owasp_category"],
                    "finding_id": finding["id"],
                },
                payload=finding,
            )
            refs.append(str(record.id))
        return refs

    @staticmethod
    def _record(tool_name, args, status, output, error, started, audit_id, evidence_refs, decisions):
        return ToolCallRecord(
            tool=tool_name,
            args=args,
            status=status,
            output=output,
            error=error,
            duration_ms=round((time.monotonic() - started) * 1000, 2),
            audit_id=audit_id,
            evidence_refs=evidence_refs,
            decisions=decisions,
        )