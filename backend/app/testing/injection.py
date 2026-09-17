"""Injection detectors (phases.md §1.5, active — controlled payloads only).

All detectors are pure functions over a baseline response and an injected
response. The tool layer supplies the controlled payload from the bundled
catalog (rules.md §3.8); this module never defines payload values itself.

Detection strategy per family:
  * SQL error  - database error strings appear in the injected response.
  * SQL boolean- status/body diverges from the baseline for a tautology marker.
  * SQL time   - injected response is materially slower than the baseline.
  * CMDi       - the fixed `AEGIS_CMD_INJECTION_MARKER` token is echoed back.
  * SSTi       - a template expression is *evaluated* (e.g. `{{7*7}}` -> `49`).
  * XSS        - the marker payload is reflected verbatim (never executed here).
"""

from dataclasses import dataclass
from typing import Any

SQL_ERROR_MARKERS: tuple[str, ...] = (
    "sqlstate[",
    "you have an error in your sql syntax",
    "syntax error at or near",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-01756",
    "ora-00933",
    "pg::syntaxerror",
    "mysql_fetch",
    "sqlite error",
    "microsoft ole db provider for sql server",
)

CMDI_MARKER = "AEGIS_CMD_INJECTION_MARKER"

_TIME_DELTA_MS_DEFAULT = 150.0


@dataclass(frozen=True)
class Detection:
    hit: bool
    confidence: str
    detail: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"hit": self.hit, "confidence": self.confidence, "detail": dict(self.detail)}


def detect_sql_error(body: str) -> str | None:
    lowered = (body or "").lower()
    for marker in SQL_ERROR_MARKERS:
        if marker in lowered:
            return marker
    return None


def detect_cmdi_marker(body: str) -> bool:
    return CMDI_MARKER in (body or "")


def detect_reflection(payload_value: str, body: str) -> bool:
    return bool(payload_value) and payload_value in (body or "")


def detect_ssti(payload_value: str, body: str) -> bool:
    """True when the template expression appears evaluated (`49`) but the raw
    expression is not merely reflected."""
    body = body or ""
    if "49" not in body:
        return False
    return payload_value not in body


def body_diverges(baseline: str, injected: str, *, min_delta: int = 8) -> bool:
    """A boolean-injection tautology typically changes content length/shape."""
    return abs(len(baseline or "") - len(injected or "")) >= min_delta


def timing_delta(baseline_ms: float, injected_ms: float, threshold_ms: float = _TIME_DELTA_MS_DEFAULT) -> bool:
    return (injected_ms - baseline_ms) >= threshold_ms


def detect(
    *,
    payload: Any,
    baseline_body: str,
    injected_body: str,
    baseline_status: int | None,
    injected_status: int | None,
    baseline_ms: float,
    injected_ms: float,
) -> Detection:
    """Dispatch detection for a single controlled payload against a parameter."""
    category = getattr(payload, "category", None)
    value = getattr(payload, "value", "")
    payload_id = getattr(payload, "id", "")

    if category == "sqli":
        error = detect_sql_error(injected_body)
        if error:
            return Detection(True, "PROBABLE", {"signal": "sql_error", "marker": error})
        if value in ("' OR '1'='1",):
            if body_diverges(baseline_body, injected_body) or (
                baseline_status != injected_status and injected_status is not None
            ):
                return Detection(
                    True,
                    "POTENTIAL",
                    {
                        "signal": "boolean_divergence",
                        "baseline_status": baseline_status,
                        "injected_status": injected_status,
                    },
                )
        if "sleep" in value.lower() and timing_delta(baseline_ms, injected_ms):
            return Detection(
                True,
                "PROBABLE",
                {"signal": "timing_delta", "delta_ms": round(injected_ms - baseline_ms, 1)},
            )
        return Detection(False, "POTENTIAL", {})

    if category == "cmdi":
        if detect_cmdi_marker(injected_body):
            return Detection(True, "CONFIRMED", {"signal": "command_marker", "marker": CMDI_MARKER})
        return Detection(False, "POTENTIAL", {})

    if category == "ssti":
        if detect_ssti(value, injected_body):
            return Detection(True, "PROBABLE", {"signal": "template_evaluated", "expected": "49"})
        return Detection(False, "POTENTIAL", {})

    if category == "xss":
        if detect_reflection(value, injected_body):
            return Detection(True, "CONFIRMED", {"signal": "reflected", "payload_id": payload_id})
        return Detection(False, "POTENTIAL", {})

    return Detection(False, "POTENTIAL", {"signal": "unsupported_category", "category": category})
