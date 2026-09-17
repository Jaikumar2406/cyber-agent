"""Retry Manager (rules.md §6.4).

Fixed policy:
  * RETRY on: timeout, transient tool crash/error (ToolExecutionError), network
    blips.
  * NEVER retry on: permission denied, scope violation, budget exhaustion -
    these are terminal failures surfaced immediately.

Exponential backoff with jitter. Default 3 retries.
"""

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any, Callable

from app.core.config import get_settings
from app.core.logging import get_logger
from app.harness.budget_manager import BudgetExceeded
from app.harness.tools import ToolExecutionError, ToolPermanentError
from app.schemas.common import TerminationReason
from app.control_plane.scope import ScopeViolation

log = get_logger("aegis.harness.retry")

TERMINAL_EXCEPTIONS = (BudgetExceeded, ToolPermanentError, ScopeViolation)


@dataclass(frozen=True)
class RetryOutcome:
    result: Any
    attempts: int
    retry_history: list[dict]


class RetryManager:
    def __init__(self, max_retries: int | None = None, base_backoff_seconds: float | None = None) -> None:
        settings = get_settings()
        self.max_retries = max_retries if max_retries is not None else settings.max_retries
        self.base_backoff = (
            base_backoff_seconds if base_backoff_seconds is not None else settings.retry_base_backoff_seconds
        )

    async def execute(self, fn: Callable[[], Any]) -> RetryOutcome:
        history: list[dict] = []
        for attempt in range(1, self.max_retries + 2):
            try:
                result = await fn()
                return RetryOutcome(result=result, attempts=attempt, retry_history=history)
            except asyncio.CancelledError:
                raise
            except TERMINAL_EXCEPTIONS:
                raise  # terminal: never retried
            except (ToolExecutionError, TimeoutError) as exc:
                is_timeout = isinstance(exc, TimeoutError) or "timeout" in str(exc).lower()
                if attempt > self.max_retries:
                    reason = TerminationReason.TIMEOUT if is_timeout else TerminationReason.TOOL_FAILURE
                    raise TerminalFailure(str(exc), reason=reason, history=history) from exc
                delay = self.base_backoff * (2 ** (attempt - 1)) + random.uniform(0, 0.2)
                history.append({"attempt": attempt, "error": str(exc), "retry_after_s": round(delay, 3)})
                log.info("retry.scheduling", attempt=attempt, delay_s=delay, error=str(exc))
                await asyncio.sleep(delay)
            except Exception as exc:  # unexpected -> treated as a transient crash
                if attempt > self.max_retries:
                    raise TerminalFailure(str(exc), reason=TerminationReason.TOOL_FAILURE, history=history) from exc
                delay = self.base_backoff * (2 ** (attempt - 1)) + random.uniform(0, 0.2)
                history.append({"attempt": attempt, "error": str(exc), "retry_after_s": round(delay, 3)})
                await asyncio.sleep(delay)
        raise AssertionError("unreachable")


class TerminalFailure(Exception):
    def __init__(self, message: str, *, reason: TerminationReason, history: list[dict]) -> None:
        super().__init__(message)
        self.reason = reason
        self.history = history