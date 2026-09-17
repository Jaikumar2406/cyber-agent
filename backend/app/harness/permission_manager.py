"""Permission Manager - checked BEFORE every tool execution (rules.md §6.2).

Phase 1 permission model:
  * Tools declare the permissions they need (e.g., runtime:http:get).
  * A principal's effective permissions come from Control Plane authorization
    (single-tenant operator grant for now).
  * Network-capable runtime permissions were withheld in Phase 0; from Phase 1
    the default operator grant includes them, because scope (not permission)
    is what bounds where requests may go (Scope Guard + Network Policy).
"""

from dataclasses import dataclass

from app.core.logging import get_logger
from app.harness.tools import BaseTool

log = get_logger("aegis.harness.permissions")


@dataclass(frozen=True)
class PermissionDecision:
    allowed: bool
    reason: str
    requires_approval: bool = False


# Phase 1 operator grant: probe + runtime HTTP/network testing capabilities.
# Scope Guard / Network Policy bound WHERE these may be used; the grant only
# enables the capability itself.
PHASE1_GRANTED_PERMISSIONS: tuple[str, ...] = (
    "runtime:http:get",
    "runtime:http:head",
    "runtime:http:post",
    "runtime:http:put",
    "runtime:http:patch",
    "runtime:http:delete",
    "runtime:http:options",
    "runtime:oob:canary",
    "runtime:discovery:crawl",
    "runtime:discovery:openapi",
    "runtime:auth:analyze",
    "runtime:auth:login",
    "runtime:model:build",
    "runtime:test:misconfig",
    "runtime:test:auth_session",
    "runtime:test:injection",
    "runtime:test:access_control",
    "runtime:test:nuclei",
    "runtime:test:ssrf",
)

# Permissions whose tools may only run after an explicit, audited human
# approval (rules.md §10) - Phase 1 exit criterion #5. Default deny-closed:
# the approval gate in the Executor refuses to schedule these unless a decision
# has been provisioned in the ApprovalContext.
APPROVAL_REQUIRED_PERMISSIONS: frozenset[str] = frozenset({"runtime:test:access_control"})


class PermissionManager:
    def __init__(self, granted_permissions: tuple[str, ...] = PHASE1_GRANTED_PERMISSIONS) -> None:
        self._granted = set(granted_permissions)

    def check(self, tool: BaseTool, *, principal: str | None, target: str | None) -> PermissionDecision:
        # A tool with no declared permissions is a no-op probe and is always allowed.
        if not tool.permissions:
            return PermissionDecision(True, "tool declares no permissions (probe)")

        missing = [p for p in tool.permissions if p not in self._granted]
        if missing:
            return PermissionDecision(False, f"principal lacks required permissions: {missing}")

        # The permission itself is granted, but the ACTION requires an explicit,
        # audited human approval before the Executor may schedule it (§10).
        requires_approval = bool(APPROVAL_REQUIRED_PERMISSIONS & set(tool.permissions))
        if requires_approval:
            return PermissionDecision(
                True, "permissions granted; human approval required before execution",
                requires_approval=True,
            )
        return PermissionDecision(True, "permissions granted")

    def effective_permissions(self) -> set[str]:
        return set(self._granted)