"""Sandbox Manager tests - the exit criterion "no unbounded task" (rules §5.2)."""

import asyncio

import pytest

from app.harness.sandbox_manager import SandboxManager, SandboxTaskSpec, SandboxTimeoutError
from app.harness.tools import SandboxSpec


async def _slow_fn(delay_s: float):
    await asyncio.sleep(delay_s)
    return {"done": True}


async def _fast_fn():
    return {"fast": "yes"}


async def _crash_fn():
    raise RuntimeError("boom")


async def test_process_backend_returns_output():
    sandbox = SandboxManager(mode="process")
    result = await sandbox.execute(SandboxTaskSpec(function=_fast_fn, sandbox=SandboxSpec(timeout_seconds=2)))
    assert result == {"fast": "yes"}


async def test_process_backend_enforces_timeout():
    sandbox = SandboxManager(mode="process")
    spec = SandboxTaskSpec(
        function=_slow_fn,
        args=(10,),
        sandbox=SandboxSpec(timeout_seconds=0.1),
    )
    with pytest.raises(SandboxTimeoutError):
        await sandbox.execute(spec)


async def test_crash_is_transient_tool_error():
    from app.harness.tools import ToolExecutionError

    sandbox = SandboxManager(mode="process")
    spec = SandboxTaskSpec(function=_crash_fn, sandbox=SandboxSpec(timeout_seconds=2))
    with pytest.raises(ToolExecutionError):
        await sandbox.execute(spec)


async def test_network_capable_sandbox_allowed_in_process_mode():
    # Phase 1: the process backend executes network-capable tools; the scope /
    # policy guard (not the sandbox) bounds where requests may go. The Docker
    # backend (--network none) is the air-gapped production posture.
    sandbox = SandboxManager(mode="process")
    result = await sandbox.execute(
        SandboxTaskSpec(function=_fast_fn, sandbox=SandboxSpec(network=True, timeout_seconds=2))
    )
    assert result == {"fast": "yes"}


async def test_network_capable_sandbox_blocked_in_docker_mode():
    from app.harness.tools import ToolPermanentError

    sandbox = SandboxManager(mode="docker")
    with pytest.raises(ToolPermanentError):
        await sandbox.execute(
            SandboxTaskSpec(function=_fast_fn, sandbox=SandboxSpec(network=True, timeout_seconds=2))
        )