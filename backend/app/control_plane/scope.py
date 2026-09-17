"""Control Plane - Scope Guard, real enforcement (rules.md §3, phases.md §1.1).

Phase 1.1 replaces the Phase 0 host-list stub. Enforcement covers:

  * Explicit prior authorization - a target is only scannable if it resolves
    into the *configured authorized scope*; the orchestrator records an
    explicit, audited approval per target before any tool runs (§1.1:
    "target authorization - explicit approval required").
  * Domain restrictions (exact + `*.example.com` wildcard), with hard
    block-lists that win over allow-lists (rules.md §3).
  * IP/CIDR restrictions - every resolved address must be inside an allowed
    range and outside blocked ranges (checked only when CIDRs are configured,
    keeping default offline-friendly).
  * Endpoint (path) restrictions via glob allow/deny lists.
  * HTTP-method restrictions.
  * Redirect policy - every redirect hop must itself pass scope, and an HTTPS
    -> HTTP downgrade is refused.
  * Canary awareness - the platform SSRF canary origin is explicitly reachable;
    everything else that is not authorized is denied by default.

The Harness calls into `check()` before EVERY tool execution, never only once
at scan start (rules.md §3.2). Tools that perform network I/O re-validate each
request/redirect hop via `validate_redirect` / `validate_target`.
"""

import fnmatch
import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from pydantic import AnyUrl, ValidationError

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger("aegis.control_plane.scope")

ALLOWED_SCHEMES = {"http", "https"}

# Hostname forms that are implicitly localhost (loopback) references.
LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ScopeViolation(Exception):
    pass


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matches: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def _normalize_host(host: str) -> str:
    host = host.strip().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _strip_port(host: str) -> str:
    if ":" in host:
        # IPv6 literal (bracketed or not) has colons but no decimal port suffix.
        if host.startswith("["):
            return _normalize_host(host)
        # "host:port" form only when the tail is numeric.
        head, _, tail = host.rpartition(":")
        if tail.isdigit():
            return head
    return host


def _host_matches(host: str, pattern: str) -> bool:
    pattern = pattern.strip().lower()
    host = host.lower()
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return False


class ScopeGuard:
    """Deny-by-default target authorization for runtime testing.

    Parameters override configuration for tests; `None` means "use the
    configured value". An explicitly empty `allowed_targets=[]` means
    deny-everything (no implicit authorization)."""

    def __init__(
        self,
        *,
        allowed_targets: list[str] | None = None,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
        allowed_cidrs: list[str] | None = None,
        blocked_cidrs: list[str] | None = None,
        allowed_paths: list[str] | None = None,
        denied_paths: list[str] | None = None,
        allowed_methods: list[str] | None = None,
        allow_localhost: bool = True,
        canary=None,
    ) -> None:
        settings = get_settings()
        self.allowed_targets = (
            [_strip_port(t) for t in allowed_targets]
            if allowed_targets is not None
            else settings.allowed_targets_list
        )
        self.allowed_domains = [
            d.lower() for d in (allowed_domains if allowed_domains is not None else (settings.allowed_domains_list or self.allowed_targets))
        ]
        self.blocked_domains = [d.lower() for d in (blocked_domains if blocked_domains is not None else settings.blocked_domains_list)]
        self.allowed_cidrs = allowed_cidrs if allowed_cidrs is not None else settings.allowed_cidr_list
        self.blocked_cidrs = blocked_cidrs if blocked_cidrs is not None else settings.blocked_cidr_list
        self.allowed_paths = allowed_paths if allowed_paths is not None else settings.allowed_path_list
        self.denied_paths = denied_paths if denied_paths is not None else settings.denied_path_list
        self.allowed_methods = {m.upper() for m in (allowed_methods or [])}
        self.allow_localhost = allow_localhost
        self.canary = canary
        log.info(
            "scope_guard_initialized",
            domains=self.allowed_domains,
            cidrs=self.allowed_cidrs,
            blocked_domains=self.blocked_domains,
            allow_localhost=self.allow_localhost,
        )

    # ------------------------------------------------------------------ URLs

    def validate_target(self, target: str | None, *, method: str | None = None) -> ScopeDecision:
        """Full URL-level scope check: scheme -> host -> IP/CIDR -> path -> method."""
        if target is None or not target.strip():
            return ScopeDecision(False, "no target provided - nothing is implicitly authorized")
        try:
            parsed = AnyUrl(target)
        except ValidationError:
            return ScopeDecision(False, "malformed target URL")

        scheme = parsed.scheme  # type: ignore[attr-defined]
        if scheme not in ALLOWED_SCHEMES:
            return ScopeDecision(False, f"scheme {scheme!r} not permitted (http/https only)")
        host = parsed.host  # type: ignore[attr-defined]
        if host is None:
            return ScopeDecision(False, "target has no host")
        host = _normalize_host(host)

        decision = self._check_host(host)
        if not decision.allowed:
            return decision
        if self.allowed_cidrs or self.blocked_cidrs:
            cidr_decision = self._check_ip(host)
            if not cidr_decision.allowed:
                return cidr_decision

        path = parsed.path or "/"  # type: ignore[attr-defined]
        decision = self._check_path(path)
        if not decision.allowed:
            return decision
        if method is not None:
            decision = self._check_method(method)
            if not decision.allowed:
                return decision

        return ScopeDecision(
            True,
            f"target {host!r} is authorized for scope",
            matches=host,
            detail={"scheme": scheme, "host": host, "path": path},
        )

    def _check_host(self, host: str) -> ScopeDecision:
        if host in LOCALHOST_HOSTS:
            if self.allow_localhost and not any(_host_matches(host, d) for d in self.blocked_domains):
                return ScopeDecision(True, f"localhost host {host!r} is implicitly authorized")
        if any(_host_matches(host, d) for d in self.blocked_domains):
            return ScopeDecision(False, f"host {host!r} is on the blocked-domain list")
        if not self.allowed_domains:
            return ScopeDecision(False, f"host {host!r} is not authorized (no allow-list configured)")
        if not any(_host_matches(host, d) for d in self.allowed_domains):
            return ScopeDecision(False, f"host {host!r} is not in the authorized domain list")
        return ScopeDecision(True, f"host {host!r} matches an authorized domain")

    def _check_ip(self, host: str) -> ScopeDecision:
        candidates: list[str] = []
        if ":" in host or host == "127.0.0.1" or host == "::1":
            candidates.append(host)
        else:
            try:
                candidates = [sock[4][0] for sock in socket.getaddrinfo(host, None)]
            except socket.gaierror:
                candidates = []  # unresolved; rely on host-name rules alone
        for addr in candidates:
            if ":" in addr and not addr.startswith("[") and addr != "::1":
                addr = "[%s]" % addr
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if any(ip in ipaddress.ip_network(c, strict=False) for c in self.blocked_cidrs):
                return ScopeDecision(False, f"host {host!r} resolves to {addr}, which is blocked by CIDR")
            if self.allowed_cidrs and not any(
                ip in ipaddress.ip_network(c, strict=False) for c in self.allowed_cidrs
            ):
                return ScopeDecision(
                    False, f"host {host!r} resolves to {addr}, outside the allowed CIDR ranges"
                )
        if self.allowed_cidrs and not candidates:
            return ScopeDecision(False, f"host {host!r} could not be resolved for CIDR authorization")
        return ScopeDecision(True, f"host {host!r} addresses satisfy IP/CIDR restrictions")

    def _check_path(self, path: str) -> ScopeDecision:
        if any(fnmatch.fnmatch(path, g) for g in self.denied_paths):
            return ScopeDecision(False, f"path {path!r} is on the denied-path list")
        if self.allowed_paths and not any(fnmatch.fnmatch(path, g) for g in self.allowed_paths):
            return ScopeDecision(False, f"path {path!r} is not in the allowed-path list")
        return ScopeDecision(True, f"path {path!r} allowed")

    def _check_method(self, method: str | None) -> ScopeDecision:
        if not method:
            return ScopeDecision(True, "no method restriction configured")
        m = method.upper()
        if self.allowed_methods and m not in self.allowed_methods:
            return ScopeDecision(
                False, f"HTTP method {m!r} is not in the allowed method set"
            )
        return ScopeDecision(True, f"HTTP method {m!r} allowed")

    # ------------------------------------------------------------ redirects

    def validate_redirect(self, current_url: str, next_url: str) -> ScopeDecision:
        """A redirect hop must independently pass scope, and cannot downgrade
        HTTPS -> HTTP (anti exfiltration / anti-pivot)."""
        decision = self.validate_target(next_url)
        if not decision.allowed:
            return decision
        try:
            current_scheme = AnyUrl(current_url).scheme  # type: ignore[attr-defined]
            next_scheme = AnyUrl(next_url).scheme  # type: ignore[attr-defined]
        except ValidationError:
            return ScopeDecision(False, "malformed redirect URL")
        if current_scheme == "https" and next_scheme != "https":
            return ScopeDecision(
                False, f"redirect downgrade refused: {current_scheme} -> {next_scheme}"
            )
        return ScopeDecision(True, f"redirect to {next_url!r} is within scope")

    # ---------------------------------------------------------------- canary

    def validate_destination(self, *, host: str, port: int) -> ScopeDecision:
        """For connection targets (canary callback / out-of-band endpoints): only
        the authorized hosts and the scan's own canary origin are reachable.

        When a canary is active, a loopback destination must hit the canary's
        exact origin port - never an arbitrary localhost port (would otherwise
        permit port-scan SSRF against the host's own services)."""
        host = _normalize_host(host).lower()
        if host in LOCALHOST_HOSTS:
            if self.canary is not None:
                _, canary_port = self.canary.origin
                if port == canary_port:
                    return ScopeDecision(True, "target is the platform SSRF canary origin", matches=host)
                return ScopeDecision(
                    False, f"localhost:{port} is not the platform canary port {canary_port}"
                )
            if self.allow_localhost:
                return ScopeDecision(True, f"host {host!r} is localhost", matches=host)
        if any(_host_matches(host, d) for d in self.allowed_domains):
            return ScopeDecision(True, f"host {host!r} is an authorized target", matches=host)
        return ScopeDecision(False, f"host {host!r}:{port} is not authorized as a destination")

    # ------------------------------------------------------------- executor

    def check(self, target: str | None, *, scope_kind: str = "runtime", method: str | None = None) -> None:
        decision = self.validate_target(target, method=method)
        log.info(
            "scope_checked",
            target=target,
            allowed=decision.allowed,
            reason=decision.reason,
            scope_kind=scope_kind,
        )
        if not decision.allowed:
            raise ScopeViolation(decision.reason)


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    reason: str
    decision: ScopeDecision


class TargetApproval:
    """Explicit prior-authorization gate (phases.md §1.1, rules.md §3.1).

    A scan may only start once its target has cleared the configured authorized
    scope AND the approval has been written to the immutable audit log. There
    is no implicit 'scan whatever the user pastes' behavior."""

    def __init__(self, scope_guard: ScopeGuard, audit=None) -> None:
        self.scope_guard = scope_guard
        from app.harness.audit_logger import AuditEvent, AuditLogger

        self.audit = audit or AuditLogger()
        self._AuditEvent = AuditEvent

    async def authorize(
        self,
        *,
        target: str | None,
        principal: str | None,
        scan_id: str | None = None,
        method: str | None = None,
    ) -> ApprovalDecision:
        if target is None:
            return ApprovalDecision(False, "no target to authorize", decision=ScopeDecision(False, "no target"))
        decision = self.scope_guard.validate_target(target, method=method)
        await self.audit.log(
            self._AuditEvent(
                user=principal,
                scan_id=scan_id,
                agent="control_plane",
                tool=None,
                target=target,
                action="target.approve",
                permission_decision={
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "requires_approval": False,
                },
                reason=decision.reason,
                result="APPROVED" if decision.allowed else "DENIED",
            )
        )
        log.info("target.approval_recorded", target=target, allowed=decision.allowed, reason=decision.reason)
        if not decision.allowed:
            return ApprovalDecision(False, decision.reason, decision=decision)
        return ApprovalDecision(True, decision.reason, decision=decision)