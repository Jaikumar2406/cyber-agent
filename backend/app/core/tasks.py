"""Celery tasks (Phase 0: queue scaffold).

`queue_probe_scan` enqueues a probe scan on the broker; the worker executes the
same Phase 0 orchestrator path as the API route. This wiring is what Phase 1+
engine tasks will use - queueing infrastructure exists from day one.
"""

import asyncio

from app.core.celery_app import celery
from app.core.orchestrator import Phase0Orchestrator
from app.core.logging import get_logger

log = get_logger("aegis.tasks")


@celery.task(name="aegis.probe_scan")
def queue_probe_scan(principal: str, target_url: str | None, target_repo: str | None, **policy) -> str:
    async def _run() -> str:
        orchestrator = Phase0Orchestrator()
        return await orchestrator.run_probe_scan(
            principal=principal, target_url=target_url, target_repo=target_repo, **policy
        )

    loop = asyncio.new_event_loop()
    try:
        scan_id = loop.run_until_complete(_run())
    finally:
        loop.close()
    log.info("task.probe_scan_done", scan_id=scan_id)
    return scan_id