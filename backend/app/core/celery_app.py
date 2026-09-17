"""Celery application (Phase 0: queue scaffold only).

Long-running scans are dispatched to Celery workers. The worker herd runs on
the same air-gapped internal network. No task logic yet - the wiring exists so
Phase 1+ can enqueue real engine runs without changing infrastructure.
"""

from celery import Celery

from app.core.config import get_settings

_settings = get_settings()

celery = Celery(
    "aegis",
    broker=_settings.redis_url,
    backend=_settings.redis_url,
    include=["app.core.tasks"],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_time_limit=5400,
    task_soft_time_limit=3600,
    worker_max_tasks_per_child=50,
    worker_prefetch_multiplier=1,
)