"""Control Plane - Scope & Policy Guard: policy enforcement (rules.md §3).

Phase 1.1 replaces the Phase 0 schema-only stub with real enforcement:

  * Scan intensity (passive / active / aggressive) gates which security
    operations a tool may perform (read-only crawl, cross-user tests,
    injections, SSRF validation, destructive methods).
  * HTTP method restrictions - enforced per request.
  * Rate limiting - a per-scan token bucket every network request passes
    through before it is sent.
  * Controlled-payload-only - a tool may only reference payload ids from the
    bundled catalog (`payloads.py`); anything else is a violation.

The Policy Guard is invoked by the Tool Executor BEFORE every tool execution,
and the Runtime HTTP tool consults it before every individual request and
every redirect hop (rules.md §3.2, §3.8).
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from app.control_plane.credentials import (
    CredentialCatalog,
    get_empty_credential_catalog,
)
from app.control_plane.payloads import PayloadCatalog, get_payload_catalog
from app.core.logging import get_logger
from app.harness.tools import BaseTool
from app.schemas.common import Intensity

log = get_logger("aegis.control_plane.policy")

ALLOWED_INTENSITIES = {i.value for i in Intensity}

# Security operations a tool can require, gated by scan intensity:
#   read_only        - GET/HEAD observation only (headers, misconfig, crawl)
#   cross_user       - two-identity authorization testing (BOLA/BFLA)
#   injection        - controlled injection payloads (SQLi/CMDi/SSTi/XSS)
#   ssrf_validation  - canary-based SSRF proof (requires a live local canary)
#   destructive_modes- DELETE/PATCH/TRACE etc - only under aggressive
OPERATIONS_BY_INTENSITY: dict[Intensity, frozenset[str]] = {
    Intensity.PASSIVE: frozenset({"read_only"}),
    Intensity.ACTIVE: frozenset({"read_only", "cross_user", "injection"}),
    Intensity.AGGRESSIVE: frozenset(
        {"read_only", "cross_user", "injection", "ssrf_validation", "destructive_modes"}
    ),
}

METHODS_BY_INTENSITY: dict[Intensity, frozenset[str]] = {
    Intensity.PASSIVE: frozenset({"GET", "HEAD"}),
    Intensity.ACTIVE: frozenset({"GET", "HEAD", "POST", "PUT", "OPTIONS"}),
    Intensity.AGGRESSIVE: frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}),
}

# Controlled payload category -> the security operation it requires (and which
# intensity grants). Injection payloads require "injection"; the canary-based
# SSRF payload requires "ssrf_validation".
_PAYLOAD_OPERATION: dict[str, str] = {
    "sqli": "injection",
    "cmdi": "injection",
    "ssti": "injection",
    "xss": "injection",
    "ssrf": "ssrf_validation",
}


class PolicyViolation(Exception):
    pass


class PolicyValidationError(Exception):
    def __init__(self, issues: list[str]) -> None:
        super().__init__("; ".join(issues))
        self.issues = issues


class RateLimiter:
    """Per-scan token bucket. `rps` tokens/sec; network tools acquire one token
    per request before sending (rate limits enforced by the guard, not by
    individual tool self-discipline - rules.md §3.8)."""

    def __init__(self, rps: float) -> None:
        self.rate = max(float(rps), 0.001)
        self.capacity = 1.0
        self._tokens = 1.0
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()
        self._granted = 0

    async def acquire(self) -> None:
        wait = 0.0
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
            self._updated = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                self._granted += 1
                return
            wait = (1.0 - self._tokens) / self.rate
            self._granted += 1
        await asyncio.sleep(wait)
        self._tokens = 0.0
        self._updated = time.monotonic()

    def snapshot(self) -> dict[str, Any]:
        return {"rate_limit_rps": self.rate, "requests_granted": self._granted}


@dataclass(frozen=True)
class ScanPolicy:
    """Effective, validated policy for one scan. Always built from a request
    through `from_request` - never constructed ad-hoc by tools."""

    intensity: Intensity
    rate_limit_rps: float
    allowed_methods: frozenset[str]
    payload_categories: frozenset[str]

    @classmethod
    def from_request(
        cls,
        *,
        intensity: str | Intensity,
        rate_limit_rps: float,
        allowed_methods: list[str] | None = None,
    ) -> "ScanPolicy":
        issues: list[str] = []
        try:
            level = Intensity(intensity)
        except ValueError:
            issues.append(f"intensity must be one of {sorted(ALLOWED_INTENSITIES)}; got {intensity!r}")
            level = Intensity.PASSIVE
        if rate_limit_rps <= 0:
            issues.append("rate_limit_rps must be positive")
        methods = METHODS_BY_INTENSITY[level]
        if allowed_methods:
            requested_raw = {m.upper() for m in allowed_methods}
            # "*" means "the intensity's full method set" (used by tests/config).
            requested = requested_raw - {"*"}
            if "*" in requested_raw:
                methods = METHODS_BY_INTENSITY[level]
            else:
                denied = requested - methods
                if denied:
                    issues.append(
                        f"methods {sorted(denied)} not permitted at intensity {level.value}"
                    )
                methods = frozenset(requested & methods)
        if issues:
            raise PolicyValidationError(issues)
        return cls(
            intensity=level,
            rate_limit_rps=float(rate_limit_rps),
            allowed_methods=methods,
            payload_categories=frozenset(OPERATIONS_BY_INTENSITY[level]),
        )

    @classmethod
    def from_settings(cls, settings=None) -> "ScanPolicy":
        from app.core.config import get_settings

        settings = settings or get_settings()
        return cls(
            intensity=Intensity(settings.default_intensity),
            rate_limit_rps=10.0,
            allowed_methods=METHODS_BY_INTENSITY[Intensity(settings.default_intensity)],
            payload_categories=frozenset(OPERATIONS_BY_INTENSITY[Intensity(settings.default_intensity)]),
        )

    def allows_method(self, method: str | None) -> bool:
        if not method:
            return True
        return method.upper() in self.allowed_methods

    def allows_operation(self, operation: str) -> bool:
        return operation in OPERATIONS_BY_INTENSITY[self.intensity]

    def as_dict(self) -> dict[str, Any]:
        return {
            "intensity": self.intensity.value,
            "rate_limit_rps": self.rate_limit_rps,
            "allowed_methods": sorted(self.allowed_methods),
            "operations": sorted(OPERATIONS_BY_INTENSITY[self.intensity]),
        }


class PolicyGuard:
    """Enforcement object. Holds one scan's policy + rate limiter and is passed
    down the execution stack so every enforcement decision is centralized."""

    def __init__(
        self,
        *,
        policy: ScanPolicy,
        payloads: PayloadCatalog | None = None,
        credentials: CredentialCatalog | None = None,
        limiter: RateLimiter | None = None,
    ) -> None:
        self.policy = policy
        self.payloads = payloads or get_payload_catalog()
        self.credentials = credentials or get_empty_credential_catalog()
        self.limiter = limiter or RateLimiter(policy.rate_limit_rps)

    def enforce_operation(self, operation: str) -> None:
        if not self.policy.allows_operation(operation):
            raise PolicyViolation(
                f"operation {operation!r} is not permitted at intensity {self.policy.intensity.value}"
            )

    def enforce_method(self, method: str) -> None:
        if not self.policy.allows_method(method):
            raise PolicyViolation(
                f"HTTP method {method.upper()!r} is not permitted at intensity "
                f"{self.policy.intensity.value} (allowed: {sorted(self.policy.allowed_methods)})"
            )

    def enforce_payload(self, payload_id: str | None, category: str | None = None) -> None:
        try:
            payload = self.payloads.require(payload_id)
        except Exception as exc:  # unknown id => controlled-payload violation
            raise PolicyViolation(f"payload {payload_id!r} is not in the controlled catalog") from exc
        if category and payload.category != category:
            raise PolicyViolation(
                f"payload {payload_id!r} is category {payload.category!r}, expected {category!r}"
            )
        required_operation = _PAYLOAD_OPERATION.get(payload.category)
        if required_operation:
            self.enforce_operation(required_operation)

    def enforce_credential(self, credential_id: str | None, kind: str | None = None) -> None:
        """A login tool may only use an operator-supplied test identity whose id is
        in the controlled catalog (rules.md §3.4 - no brute force, no theft).

        Supplying a credential is a cross-user operation: it provisions an
        identity for subsequent BOLA/BFLA tests, so it is gated by intensity.
        """
        self.enforce_operation("cross_user")
        try:
            credential = self.credentials.require(credential_id)
        except Exception as exc:  # unknown id => not an authorized test identity
            raise PolicyViolation(
                f"credential {credential_id!r} is not in the operator-supplied catalog"
            ) from exc
        if kind and credential.kind != kind:
            raise PolicyViolation(
                f"credential {credential_id!r} is kind {credential.kind!r}, expected {kind!r}"
            )

    def enforce_tool(self, tool: BaseTool, args: dict[str, Any]) -> None:
        """Full pre-execution policy gate for one tool call (rules.md §3.8)."""
        for operation in tool.policy_requirements:
            self.enforce_operation(operation)
        for field_name in tool.payload_fields:
            payload_id = args.get(field_name)
            if isinstance(payload_id, (list, tuple)):
                for single in payload_id:
                    self.enforce_payload(str(single))
            elif payload_id:
                self.enforce_payload(str(payload_id))
        for field_name in tool.credential_fields:
            credential_id = args.get(field_name)
            if isinstance(credential_id, (list, tuple)):
                for single in credential_id:
                    self.enforce_credential(str(single))
            elif credential_id:
                self.enforce_credential(str(credential_id))

    async def rate_limit(self) -> None:
        await self.limiter.acquire()

    def snapshot(self) -> dict[str, Any]:
        return {**self.policy.as_dict(), "rate_limiter": self.limiter.snapshot()}