"""Budget Manager (rules.md §6.3) - enforced from day one.

No component self-polices budgets. Every LLM call, tool call, planning
iteration, and scan-duration tick is charged through here; exceeding any budget
raises BudgetExceeded which the Harness treats as terminal (no retry). A
concurrent, out-of-policy runaway loop is hard-stopped by the scan-duration
budget - exercised directly by a Phase 0 test.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger("aegis.harness.budget")


class BudgetExceeded(Exception):
    pass


@dataclass
class BudgetSnapshot:
    tool_calls_used: int
    llm_calls_used: int
    scan_seconds_used: float
    max_tool_calls: int
    max_llm_calls: int
    max_scan_seconds: float
    exhausted: list[str] = field(default_factory=list)


class BudgetManager:
    def __init__(
        self,
        *,
        max_tool_calls: int | None = None,
        max_llm_calls: int | None = None,
        max_scan_seconds: float | None = None,
    ) -> None:
        settings = get_settings()
        self.max_tool_calls = max_tool_calls if max_tool_calls is not None else settings.max_tool_calls
        self.max_llm_calls = max_llm_calls if max_llm_calls is not None else settings.max_llm_calls
        self.max_scan_seconds = max_scan_seconds if max_scan_seconds is not None else settings.max_scan_seconds
        self.tool_calls_used = 0
        self.llm_calls_used = 0
        self._started_at: float | None = None

    def start(self) -> None:
        self._started_at = time.monotonic()

    @property
    def scan_seconds_used(self) -> float:
        if self._started_at is None:
            return 0.0
        return time.monotonic() - self._started_at

    def _raise_if_counts_exhausted(self) -> None:
        if self.tool_calls_used >= self.max_tool_calls:
            raise BudgetExceeded(
                f"budget exhausted: tool_calls ({self.tool_calls_used}/{self.max_tool_calls})"
            )
        if self.llm_calls_used >= self.max_llm_calls:
            raise BudgetExceeded(
                f"budget exhausted: llm_calls ({self.llm_calls_used}/{self.max_llm_calls})"
            )

    def _exhausted_list(self) -> list[str]:
        out = []
        if self.tool_calls_used >= self.max_tool_calls:
            out.append(f"tool_calls ({self.tool_calls_used}/{self.max_tool_calls})")
        if self.llm_calls_used >= self.max_llm_calls:
            out.append(f"llm_calls ({self.llm_calls_used}/{self.max_llm_calls})")
        if self.scan_seconds_used >= self.max_scan_seconds:
            out.append(f"scan_seconds ({self.scan_seconds_used:.1f}/{self.max_scan_seconds})")
        return out

    def charge_tool_call(self) -> None:
        self._raise_if_counts_exhausted()
        self.tool_calls_used += 1
        log.info("budget.charge_tool_call", calls=self.tool_calls_used, cap=self.max_tool_calls)

    def charge_llm_call(self) -> None:
        self._raise_if_counts_exhausted()
        self.llm_calls_used += 1
        log.info("budget.charge_llm_call", calls=self.llm_calls_used, cap=self.max_llm_calls)

    def assert_within_duration(self) -> None:
        """Hard-stop check: raises if scan duration budget is breached.

        Duration is enforced by the AsyncBudgetGuard watchdog (and any periodic
        Harness tick), not by per-call charging, so a runaway loop is cancelled
        deterministically rather than racing on charge boundaries."""
        if self.scan_seconds_used >= self.max_scan_seconds:
            raise BudgetExceeded(
                f"budget exhausted: scan_seconds ({self.scan_seconds_used:.1f}/{self.max_scan_seconds})"
            )

    def snapshot(self) -> BudgetSnapshot:
        budget = BudgetSnapshot(
            tool_calls_used=self.tool_calls_used,
            llm_calls_used=self.llm_calls_used,
            scan_seconds_used=round(self.scan_seconds_used, 3),
            max_tool_calls=self.max_tool_calls,
            max_llm_calls=self.max_llm_calls,
            max_scan_seconds=self.max_scan_seconds,
        )
        budget.exhausted = self._exhausted_list()
        return budget


class AsyncBudgetGuard:
    """Couple a BudgetManager with an asyncio task so a runaway loop can be
    killed when the scan-duration budget is breached.

    Task A (the scan loop) runs under this guard. A watcher task asserts the
    duration budget every `interval_s`; on breach it cancels task A. This is the
    "Budget Manager can hard-stop a runaway loop" exit criterion.
    """

    def __init__(self, budget: BudgetManager, interval_s: float = 0.01) -> None:
        self.budget = budget
        self.interval_s = interval_s

    async def run(self, coro) -> Any:
        task = asyncio.ensure_future(coro)
        watcher = asyncio.ensure_future(self._watch(task))
        try:
            return await task
        finally:
            watcher.cancel()
            try:
                await watcher
            except asyncio.CancelledError:
                pass

    async def _watch(self, task: asyncio.Task) -> None:
        while True:
            await asyncio.sleep(self.interval_s)
            try:
                self.budget.assert_within_duration()
            except BudgetExceeded as exc:
                task.cancel()
                log.warning("budget.hard_stop", reason=str(exc))
                return
            if task.done():
                return