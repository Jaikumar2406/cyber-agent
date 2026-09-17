"""Control Plane - authorization stub.

Phase 0: a single discoverable policy module. Authenticated principals may
read; scan creation requires an authenticated principal. RBAC/role checks are
stubs that Phase 1 wire-in with real policy (rules.md §3).
"""

from dataclasses import dataclass

from app.control_plane.auth import Principal
from app.core.logging import get_logger

log = get_logger("aegis.control_plane.authorization")


class AuthorizationDenied(Exception):
    pass


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str


class AuthorizationStub:
    """Deterministic, explicit allow-list stub. Default: deny writes to
    anonymous principals."""

    def check(self, principal: Principal | None, action: str) -> AuthorizationDecision:
        if action.startswith("read:"):
            return AuthorizationDecision(True, "read actions allowed for any authenticated session")
        if action.startswith("write:"):
            if principal is None:
                return AuthorizationDecision(False, "anonymous write denied")
            return AuthorizationDecision(True, f"authenticated principal {principal.username}")
        return AuthorizationDecision(False, f"unknown action {action!r}")


def check_or_raise(principal: Principal | None, action: str) -> None:
    decision = AuthorizationStub().check(principal, action)
    log.info("authorization_checked", action=action, allowed=decision.allowed, reason=decision.reason)
    if not decision.allowed:
        raise AuthorizationDenied(decision.reason)