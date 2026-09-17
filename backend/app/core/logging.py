"""Structured JSON logging (structlog).

Every component logs structured events. The Audit Logger (append-only DB
records) is separate from these process logs; this logger is the observability
stream, not the audit trail.
"""

import logging
import sys

import structlog

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.NOTSET),
    logger_factory=structlog.PrintLoggerFactory(sys.stdout),
    cache_logger_on_first_use=True,
)


def get_logger(name: str = "aegis") -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)