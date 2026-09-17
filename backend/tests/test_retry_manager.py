"""Retry Manager tests - fixed retry/no-retry policy (rules.md §6.4)."""

import asyncio

import pytest

from app.control_plane.scope import ScopeViolation
from app.harness.budget_manager import BudgetExceeded
from app.harness.retry_manager import RetryManager, TerminalFailure
from app.harness.tools import ToolExecutionError, ToolPermanentError


async def _fail_then_succeed(fail_count):
    attempts = {"n": 0}

    async def run():
        attempts["n"] += 1
        if attempts["n"] <= fail_count:
            raise ToolExecutionError("transient blip")
        return {"ok": True, "attempts": attempts["n"]}

    return run


async def test_retries_transient_failure():
    retry = RetryManager(max_retries=3, base_backoff_seconds=0.01)
    outcome = await retry.execute(await _fail_then_succeed(2))
    assert outcome.result == {"ok": True, "attempts": 3}
    assert len(outcome.retry_history) == 2


async def test_succeeds_first_try_no_retries():
    retry = RetryManager(max_retries=3, base_backoff_seconds=0.01)
    outcome = await retry.execute(async_identity)
    assert outcome.attempts == 1
    assert outcome.retry_history == []


async def test_gives_up_after_max_retries():
    retry = RetryManager(max_retries=2, base_backoff_seconds=0.01)

    async def always_fails():
        raise ToolExecutionError("persistent")

    with pytest.raises(TerminalFailure):
        await retry.execute(always_fails)


async def test_never_retries_permanent_error():
    retry = RetryManager(max_retries=5, base_backoff_seconds=0.01)

    async def permanent():
        raise ToolPermanentError("no point retrying")

    with pytest.raises(ToolPermanentError):
        await retry.execute(permanent)


async def test_never_retries_scope_violation():
    retry = RetryManager(max_retries=5, base_backoff_seconds=0.01)

    async def violation():
        raise ScopeViolation("out of scope")

    with pytest.raises(ScopeViolation):
        await retry.execute(violation)


async def test_never_retries_budget_exhaustion():
    retry = RetryManager(max_retries=5, base_backoff_seconds=0.01)

    async def exhausted():
        raise BudgetExceeded("no budget")

    with pytest.raises(BudgetExceeded):
        await retry.execute(exhausted)


async def async_identity():
    return {"ok": True}