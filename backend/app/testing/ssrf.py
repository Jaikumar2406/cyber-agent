"""SSRF validation helpers (phases.md §1.5, canary-only).

rules.md §3.5/§10: AEGIS proves server-side request forgery ONLY with its own
loopback canary - never an external webhook, never a third-party SaaS. The
canary's hit log (method/path/source) is the sole proof of a server-side fetch.

This module is pure/offline: it just decides which parameters are plausible URL
sinks and formats canary-hit evidence. The tool owns the actual requests.
"""

from typing import Any

URL_PARAM_HINTS: tuple[str, ...] = (
    "url",
    "uri",
    "link",
    "src",
    "source",
    "dest",
    "destination",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "return",
    "returnurl",
    "return_url",
    "continue",
    "callback",
    "target",
    "host",
    "fetch",
    "image",
    "img",
    "path",
    "file",
    "load",
    "page",
    "proxy",
    "feed",
    "site",
    "domain",
    "webhook",
)


def is_url_param(name: str) -> bool:
    lowered = (name or "").strip().lower().replace("-", "_")
    return any(hint == lowered or hint in lowered for hint in URL_PARAM_HINTS)


def find_url_params(params: list[str] | tuple[str, ...]) -> list[str]:
    return [p for p in (params or []) if is_url_param(p)]


def hit_evidence(hit: Any) -> dict[str, Any]:
    """Format a CanaryHit into evidence. Header values are intentionally
    excluded (they could contain secrets) - only method/path/source/time."""
    return {
        "canary_hit_id": getattr(hit, "hit_id", None),
        "method": getattr(hit, "method", None),
        "path": getattr(hit, "path", None),
        "remote_addr": getattr(hit, "remote_addr", None),
        "timestamp": getattr(hit, "timestamp", None),
    }
