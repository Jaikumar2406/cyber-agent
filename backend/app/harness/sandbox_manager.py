"""Sandbox Manager (rules.md §5) - resource-capped, isolated execution.

Two backends:

  * "process" - in-process execution with hard timeout + output-size cap. Used
    for Phase 0 tests and lightweight local runs. True filesystem/process
    isolation is the Docker backend's job.
  * "docker" - `docker run` with `--network none`, CPU/memory limits, and a
    read-only workspace. This is the production sandbox path that encodes
    `egress: drop` at the container boundary.

Both backends enforce: execution timeout, CPU/memory caps (docker), and output
size limits. No unbounded task exists, even in dev (rules.md §5.2).
"""

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from app.core.config import get_settings
from app.core.logging import get_logger
from app.harness.tools import SandboxSpec, ToolExecutionError, ToolPermanentError

log = get_logger("aegis.harness.sandbox")

MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB per tool output


class SandboxTimeoutError(ToolExecutionError):
    pass


class OutputTooLargeError(ToolPermanentError):
    pass


@dataclass
class SandboxTaskSpec:
    function: Callable[..., Coroutine[Any, Any, Any]] | None = None
    args: tuple[Any, ...] = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    command: list[str] | None = None
    sandbox: SandboxSpec = SandboxSpec()

    @property
    def timeout_seconds(self) -> float:
        if self.sandbox.timeout_seconds is not None:
            return self.sandbox.timeout_seconds
        return get_settings().max_tool_timeout_seconds


def _cap_output(data: Any) -> Any:
    serialized = json.dumps(data, default=str)
    if len(serialized.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise OutputTooLargeError(f"tool output exceeded {MAX_OUTPUT_BYTES} bytes")
    return data


class SandboxManager:
    def __init__(self, mode: str | None = None) -> None:
        self.mode = mode or get_settings().sandbox_mode
        log.info("sandbox_initialized", mode=self.mode)

    async def execute(self, spec: SandboxTaskSpec) -> Any:
        if self.mode == "docker" and spec.sandbox.network:
            # The Docker backend is deliberately `--network none` (egress:drop).
            # Network-capable runtime tools run on the isolated compose internal
            # network; wiring that isolated-network profile is deployed in
            # Phase 7. We refuse here rather than silently dropping egress:drop.
            raise ToolPermanentError(
                "network-capable sandbox requires the Phase 7 isolated-network profile"
            )
        if self.mode == "docker":
            return await self._execute_docker(spec)
        return await self._execute_process(spec)

    async def _execute_process(self, spec: SandboxTaskSpec) -> Any:
        if spec.function is None:
            raise ToolPermanentError("process sandbox requires a callable")

        async def run_bound():
            try:
                return await spec.function(*spec.args, **spec.kwargs)
            except asyncio.CancelledError:
                raise
            except ToolExecutionError:
                raise
            except Exception as exc:  # unexpected crash -> transient, retriable
                raise ToolExecutionError(f"tool crashed: {exc}") from exc

        try:
            result = await asyncio.wait_for(run_bound(), timeout=spec.timeout_seconds)
        except TimeoutError as exc:
            raise SandboxTimeoutError(
                f"tool exceeded timeout of {spec.timeout_seconds}s"
            ) from exc
        except asyncio.TimeoutError as exc:
            raise SandboxTimeoutError(
                f"tool exceeded timeout of {spec.timeout_seconds}s"
            ) from exc
        return _cap_output(result)

    async def _execute_docker(self, spec: SandboxTaskSpec) -> Any:
        if not spec.command or not shutil.which("docker"):
            raise ToolPermanentError("docker sandbox requires the docker CLI")
        mem = spec.sandbox.mem_limit_mb or 512
        cpus = spec.sandbox.cpu_limit if spec.sandbox.cpu_limit else "1.0"
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--memory",
            f"{mem}m",
            "--cpus",
            str(cpus),
            "--read-only",
            "python:3.12-slim",
            "python",
            "-c",
            *spec.command,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=spec.timeout_seconds)
        except TimeoutError:
            proc.kill()
            raise SandboxTimeoutError(f"docker task exceeded timeout of {spec.timeout_seconds}s")
        if proc.returncode != 0:
            raise ToolExecutionError(f"docker task failed ({proc.returncode}): {stderr.decode()[:2048]}")
        return _cap_output(json.loads(stdout.decode()) if stdout else {})