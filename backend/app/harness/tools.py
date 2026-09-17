"""Tool protocol - the contract every engine tool implements (rules.md §6).

A tool is registered with a JSON input schema, an explicit permission set, and
a sandbox strategy. The Deep Agent (Phase 5) may only invoke tools that exist
in the Tool Registry with schema-validated arguments.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from app.schemas.common import ToolResultStatus


class ToolResult(BaseModel):
    status: ToolResultStatus
    output: dict[str, Any] = field(default_factory=dict)  # type: ignore[assignment]
    error: str | None = None
    duration_ms: float = 0.0
    evidence_refs: list[str] = field(default_factory=list)  # type: ignore[assignment]


class ToolContext(BaseModel):
    """Context handed to a tool at execution time."""

    scan_id: str | None = None
    principal: str | None = None
    target: str | None = None
    policy: dict[str, Any] = field(default_factory=dict)
    # Runtime enforcement handles installed by the Executor (Phase 1.1):
    scope_guard: Any | None = None
    rate_limiter: Any | None = None
    canary: Any | None = None
    # Phase 1.3 auth support: the operator-supplied credential catalog that
    # login tools may reference, and the per-scan test identity store.
    credentials: Any | None = None
    identity_store: Any | None = None


@dataclass(frozen=True)
class SandboxSpec:
    """Sandbox requirements for this tool."""

    mode: str = "process"  # "process" | "docker"
    network: bool = False  # whether the tool needs network access (Phase 1 tests)
    cpu_limit: float | None = None
    mem_limit_mb: int | None = None
    timeout_seconds: float | None = None
    workspace_isolated: bool = True


class BaseTool(ABC):
    name: str = "base"
    description: str = ""
    input_schema: dict[str, Any] = {"type": "object", "properties": {}}
    permissions: tuple[str, ...] = ()
    sandbox: SandboxSpec = SandboxSpec()
    # Policy requirements (phases.md §1.1): security operations this tool may
    # only perform if the scan's intensity grants them ("read_only",
    # "cross_user", "injection", "ssrf_validation", "destructive_modes").
    policy_requirements: tuple[str, ...] = ()
    # Argument fields that must reference a controlled payload catalog id; the
    # Policy Guard validates them before execution (rules.md §3.8).
    payload_fields: tuple[str, ...] = ()
    # Argument fields that must reference an operator-supplied credential catalog
    # id (rules.md §3.4 - no inline/bruteforced credentials, only explicit ones).
    credential_fields: tuple[str, ...] = ()

    @abstractmethod
    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        """Execute the tool and return a structured result.

        Raises:
            ToolExecutionError: for retriable transient failures (timeout /
                crash). Permission/scope/budget failures are handled by the
                Harness, never raised here.
        """
        raise NotImplementedError


class ToolExecutionError(Exception):
    """Transient execution failure - safe for the Retry Manager to retry."""


class ToolPermanentError(Exception):
    """Non-transient failure; the Retry Manager must NOT retry this."""