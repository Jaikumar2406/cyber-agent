"""Security test modules (phases.md §1.5).

Each module is a *pure, deterministic* detector library plus a thin tool that
drives scoped network I/O through the Harness. Detectors never guess: a finding
is emitted only from an observable, reproducible signal (a reflected marker, a
timing delta, a canary hit, an access-control asymmetry), and every finding
carries an explicit confidence and structured evidence.

Modules:
    misconfiguration  - headers, CORS, banners, debug exposure (passive)
    auth_session      - cookie flags, cleartext transport, basic auth (passive)
    injection         - SQLi/CMDi/SSTi/XSS via controlled payloads
    access_control    - BOLA/BFLA via two test identities (cross-user)
    ssrf              - canary-proven server-side fetch
"""

from app.testing.finding import (
    ACCESS_CONTROL_ASYMMETRY,
    AUTH_WEAKNESS,
    BFLA,
    BOLA,
    INJECTION,
    MISCONFIGURATION,
    NUCLEI,
    SSRF,
    Finding,
)

__all__ = [
    "Finding",
    "BOLA",
    "BFLA",
    "SSRF",
    "INJECTION",
    "AUTH_WEAKNESS",
    "MISCONFIGURATION",
    "ACCESS_CONTROL_ASYMMETRY",
    "NUCLEI",
]
