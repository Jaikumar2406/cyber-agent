"""Controlled payload library (rules.md §3.8, PRD FR-15; "controlled payloads only").

Every injection payload AEGIS may send is defined here, bundled offline, and
carries an id (used in evidence) - it is never invented or supplied inline by a
tool call. Payloads are deliberately non-destructive: they verify the presence
of an injection sink with a benign marker, never corrupt or destroy data.

The SSRF payload is special: the *value* is the platform canary origin, which
is only resolvable while a scan owns a live canary. The guard validates the
payload *id*; the tool substitutes `{canary}` with the scan's canary base URL.
"""

from dataclasses import dataclass


class PayloadNotAllowed(Exception):
    pass


@dataclass(frozen=True)
class Payload:
    id: str
    category: str  # sqli | cmdi | ssti | xss | ssrf
    description: str
    value: str  # literal value sent in the injected parameter; "{canary}" reserved for SSRF


_PAYLOADS: tuple[Payload, ...] = (
    Payload(
        "sqli.single-quote",
        "sqli",
        "single quote - classic indicator of a SQL injection sink",
        "'",
    ),
    Payload(
        "sqli.boolean-marker",
        "sqli",
        "boolean tautology marker ' OR '1'='1 - verified response difference, never destructive",
        "' OR '1'='1",
    ),
    Payload(
        "sqli.time-marker",
        "sqli",
        "time-based marker SELECT pg_sleep(0.2) - timing delta proves a sink without data mutation",
        "' OR 1=1; SELECT pg_sleep(0.2); --",
    ),
    Payload(
        "cmdi.echo-marker",
        "cmdi",
        "command injection marker echoing a fixed token",
        "; echo AEGIS_CMD_INJECTION_MARKER;",
    ),
    Payload(
        "ssti.math-marker",
        "ssti",
        "server-side template injection marker {{7*7}} rendered by the template engine",
        "{{7*7}}",
    ),
    Payload(
        "ssti.dollar-marker",
        "ssti",
        "Jinja/dollar-style template marker ${7*7}",
        "${7*7}",
    ),
    Payload(
        "xss.img-marker",
        "xss",
        "reflected XSS marker - only ever rendered by the target, never executed by AEGIS",
        '<img src="x" onerror="window.__aegisReflected=1">',
    ),
    Payload(
        "ssrf.canary",
        "ssrf",
        "platform-controlled canary URL (localhost only) used to prove server-side fetch",
        "{canary}",
    ),
)

_CATEGORIES = ("sqli", "cmdi", "ssti", "xss", "ssrf")


class PayloadCatalog:
    def __init__(self, payloads: tuple[Payload, ...] | None = None) -> None:
        self._by_id: dict[str, Payload] = {}
        for payload in payloads if payloads is not None else _PAYLOADS:
            if payload.id in self._by_id:
                raise ValueError(f"duplicate payload id {payload.id!r}")
            self._by_id[payload.id] = payload

    def by_id(self, payload_id: str | None) -> Payload | None:
        if not payload_id:
            return None
        return self._by_id.get(payload_id)

    def require(self, payload_id: str | None) -> Payload:
        payload = self.by_id(payload_id)
        if payload is None:
            raise PayloadNotAllowed(f"payload {payload_id!r} is not in the controlled catalog")
        return payload

    def list(self, category: str | None = None) -> list[Payload]:
        items = [p for p in self._by_id.values() if category is None or p.category == category]
        return sorted(items, key=lambda p: p.id)

    @property
    def categories(self) -> tuple[str, ...]:
        return _CATEGORIES


_default_catalog: PayloadCatalog | None = None


def get_payload_catalog() -> PayloadCatalog:
    global _default_catalog
    if _default_catalog is None:
        _default_catalog = PayloadCatalog()
    return _default_catalog