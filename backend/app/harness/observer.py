"""Observability stub (architecture §25).

Structured event stream for scan/tool/engine lifecycle. Phase 0 emits log
events + in-memory counters; Prometheus metrics, OpenTelemetry traces, and
agent-execution history arrive in Phase 6 alongside the feature they observe.
"""

import time
from typing import Any

from app.core.logging import get_logger

log = get_logger("aegis.harness.observer")


class Observer:
    def __init__(self) -> None:
        self._metrics: dict[str, int] = {}
        self._events: list[dict[str, Any]] = []

    def emit(self, event: str, **fields: Any) -> None:
        self._metrics[event] = self._metrics.get(event, 0) + 1
        record = {"event": event, "ts": time.time(), **fields}
        self._events.append(record)
        log.info("observer", metric=event, **{k: v for k, v in record.items() if k != "event"})

    def metric(self, name: str) -> int:
        return self._metrics.get(name, 0)

    def counter(self, name: str, by: int = 1) -> None:
        self._metrics[name] = self._metrics.get(name, 0) + by

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._events[-limit:]


_default_observer: Observer | None = None


def get_observer() -> Observer:
    global _default_observer
    if _default_observer is None:
        _default_observer = Observer()
    return _default_observer