"""Budget Manager tests - exit criterion: "hard-stop a runaway loop"."""

import asyncio

import pytest

from app.harness.budget_manager import AsyncBudgetGuard, BudgetExceeded, BudgetManager


async def test_tool_call_budget_exhaustion():
    budget = BudgetManager(max_tool_calls=2, max_llm_calls=100, max_scan_seconds=1000)
    budget.start()
    budget.charge_tool_call()
    budget.charge_tool_call()
    with pytest.raises(BudgetExceeded):
        budget.charge_tool_call()


async def test_llm_budget_exhaustion():
    budget = BudgetManager(max_tool_calls=100, max_llm_calls=1, max_scan_seconds=1000)
    budget.start()
    budget.charge_llm_call()
    with pytest.raises(BudgetExceeded):
        budget.charge_llm_call()


async def test_watchdog_hard_stops_runaway_loop():
    """A loop that never terminates is cancelled by the AsyncBudgetGuard once
    the scan-duration budget is breached -> CancelledError surfaces."""
    budget = BudgetManager(max_tool_calls=10**9, max_llm_calls=10**9, max_scan_seconds=0.2)
    budget.start()

    async def runaway():
        while True:
            budget.charge_tool_call()
            await asyncio.sleep(0.01)

    with pytest.raises(asyncio.CancelledError):
        await AsyncBudgetGuard(budget, interval_s=0.05).run(runaway())


async def test_duration_budget_assert():
    budget = BudgetManager(max_tool_calls=10**9, max_llm_calls=10**9, max_scan_seconds=0.1)
    budget.start()
    await asyncio.sleep(0.2)
    with pytest.raises(BudgetExceeded):
        budget.assert_within_duration()


async def test_snapshot_reports_usage():
    budget = BudgetManager(max_tool_calls=5, max_llm_calls=5, max_scan_seconds=100)
    budget.start()
    budget.charge_tool_call()
    snap = budget.snapshot()
    assert snap.tool_calls_used == 1
    assert snap.max_tool_calls == 5