"""Approval Manager - the human-approval gate (phases.md Phase 1 exit #5).

rules.md §10: high-impact actions (active/production-like BOLA tests, scope
expansion, ...) require explicit, audited human approval before execution. This
gate cannot be disabled by configuration alone.

The gate lives in the Tool Executor BETWEEN the permission check and the budget
check, so a protected action is never scheduled/charged before an operator has
explicitly approved it - and the existing Scope/Policy/Permission checks always
run first. The context is deny-closed: a tool that declares an approval-required
permission, called without any provisioned approval decision, does NOT run.

Flow:
    tool call -> ... -> permission (allowed) -> approval gate
        unknown decision => PENDING_APPROVAL (audited, scan pauses)
        denied context    => APPROVAL_DENIED (audited, action skipped)
        approved decision => proceeds under the normal budget/sandbox path

Approval requests are identified deterministically by
``sha256("{tool}::{target}")[:16]`` so a paused scan can be resumed and re-pauses
on the SAME approval id; decisions are persisted in the scan state (ids only -
the credential/identity secrets stay in-memory, rules.md §5.5).
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.core.logging import get_logger

log = get_logger("aegis.harness.approval")


class ApprovalRequired(Exception):
    """A protected action needs explicit operator approval before it may run."""

    def __init__(self, request: dict[str, Any]) -> None:
        super().__init__(
            f"approval required for {request.get('tool')!r} (approval_id={request.get('approval_id')})"
        )
        self.request = request


class ApprovalContext:
    """Per-run approval decisions. Deny-closed: an action with no recorded
    decision is pending (and therefore does not run).

    Decisions are ``{approval_id: bool or None}``. They are seeded from the
    persisted scan state on resume, so an operator decision survives a pause.
    """

    def __init__(self, decisions: dict[str, bool | None] | None = None) -> None:
        self._decisions: dict[str, bool | None] = dict(decisions or {})

    @staticmethod
    def request_id(tool: str, target: str | None) -> str:
        key = f"{tool}::{target or ''}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def decision_for(self, tool: str, target: str | None) -> bool | None:
        """None = undecided (pending); True/False = operator verdict."""
        return self._decisions.get(self.request_id(tool, target))

    def request(self, tool: str, target: str | None) -> dict[str, Any]:
        approval_id = self.request_id(tool, target)
        return {
            "approval_id": approval_id,
            "tool": tool,
            "target": target,
            "status": "PENDING_APPROVAL",
        }

    def record_decision(self, approval_id: str, approved: bool) -> None:
        """Replay a persisted operator decision (used on resume)."""
        self._decisions[approval_id] = bool(approved)

    def pending_ids(self) -> list[str]:
        return [aid for aid, decision in self._decisions.items() if decision is None]

    def snapshot(self) -> dict[str, Any]:
        """JSON-safe copy for checkpointing into the scan state."""
        return {aid: decision for aid, decision in self._decisions.items()}