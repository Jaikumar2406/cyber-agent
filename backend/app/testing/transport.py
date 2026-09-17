"""Shared transport helper for security test modules (phases.md §1.5, §1.6).

Every active test module sends requests through the SAME enforcement path as
the rest of the runtime: the Scope Guard validates each request before it is
sent and the scan rate limiter is honoured (rules.md §3.2, §3.8). This helper
exists so no test module can accidentally bypass those checks.

§1.6 evidence: `capture_exchange` builds the full, redacted request/response
snapshot (method, URL, headers, params/body, status, body excerpt, timing) that
every finding must carry. Secrets are redacted before the capture is persisted
(rules.md §5.5/§5.6) - authorization/cookie values are dropped entirely and
token/key/secret-like values are scrubbed.
"""

import re
from typing import Any

import httpx

from app.harness.tools import ToolContext

_MAX_BODY_CHARS = 4000

_REDACTION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(api[_-]?key\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(secret\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(password\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(passwd\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(token\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(authorization\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(bearer\s+)(\S+)", r"\1[REDACTED]"),
    (r"(cookie\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
)

_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
}

_SENSITIVE_PARAM_NAME = re.compile(
    r"(token|key|secret|password|passwd|session|auth|cookie|sid|signature)", re.IGNORECASE
)


class OutOfScope(Exception):
    pass


def redact(text: str) -> str:
    """Scrub token/key/secret-like values from free text before persistence."""
    for pat, rep in _REDACTION_PATTERNS:
        text = re.sub(pat, rep, str(text), flags=re.IGNORECASE)
    return text


def _redact_value(name: str, value: Any) -> str:
    if _SENSITIVE_PARAM_NAME.search(str(name)):
        return "[REDACTED]"
    return redact(str(value))


def redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Redact a header map: sensitive headers drop their entire value."""
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if str(key).lower() in _SENSITIVE_HEADER_NAMES:
            out[str(key)] = "[REDACTED]"
        else:
            out[str(key)] = redact(str(value))
    return out


def redact_url(url: str) -> str:
    """Redact sensitive query parameter values inside a URL string."""
    try:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

        parts = urlsplit(str(url))
        if parts.query:
            cleaned = [
                (key, _redact_value(key, value))
                for key, value in parse_qsl(parts.query, keep_blank_values=True)
            ]
            query = urlencode(cleaned)
        else:
            query = ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
    except Exception:
        return redact(str(url))


def redact_body_excerpt(text: str) -> str:
    """Redact secrets and cap the body excerpt at _MAX_BODY_CHARS characters."""
    text = redact(str(text or ""))
    if len(text) > _MAX_BODY_CHARS:
        text = text[:_MAX_BODY_CHARS] + f"…[{len(text)} chars]"
    return text


async def scoped_request(
    method: str,
    url: str,
    *,
    context: ToolContext,
    timeout: float = 5.0,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    cookies: dict[str, str] | None = None,
) -> httpx.Response:
    """Scope-check + rate-limit + send a single request. Never follows
    redirects (each hop would need its own scope check)."""
    scope_guard = context.scope_guard
    if scope_guard is None:
        raise RuntimeError("security test module requires a scope guard in context")
    decision = scope_guard.validate_target(url, method=method)
    if not decision.allowed:
        raise OutOfScope(decision.reason)
    if context.rate_limiter is not None:
        await context.rate_limiter.acquire()
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        return await client.request(
            method.upper(),
            url,
            headers=headers,
            params=params,
            data=data,
            cookies=cookies,
            timeout=timeout,
        )


def identity_auth(identity: Any) -> tuple[dict[str, str], dict[str, str]]:
    """Build (headers, cookies) for a stored test identity without exposing the
    secret: the raw secret is only ever placed into the outbound request.

    ``identity`` is an `app.auth_analysis.identity.IdentityRecord`.
    """
    headers: dict[str, str] = {}
    kind = (getattr(identity, "kind", "") or "").lower()
    secret = getattr(identity, "session_secret", None)
    if secret:
        lowered = secret.lower()
        if kind == "basic":
            headers["Authorization"] = secret if lowered.startswith("basic ") else f"Basic {secret}"
        elif kind == "bearer":
            headers["Authorization"] = secret if lowered.startswith("bearer ") else f"Bearer {secret}"
    cookies = dict(getattr(identity, "session_cookies", {}) or {})
    return headers, cookies


def capture_exchange(
    *,
    method: str,
    url: str,
    response: httpx.Response,
    elapsed_ms: float,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Full, redacted HTTP request/response evidence for one exchange (§1.6).

    Returns a JSON-safe dict::

        {
          "request":  {"method", "url", "headers", "cookies"(names only),
                       "params"(redacted), "data"(redacted)},
          "response": {"status_code", "headers", "body"(excerpt)},
          "timing_ms": <round-tripped float>,
        }

    Never persists raw credentials: Authorization/Cookie/Set-Cookie values are
    replaced by ``[REDACTED]`` and token/key/secret-looking values in URLs,
    params and bodies are scrubbed (rules.md §5.5).
    """
    request_headers = dict(headers or {})
    if cookies:
        request_headers["Cookie"] = "; ".join(f"{name}=<redacted>" for name in cookies)
    request: dict[str, Any] = {
        "method": (method or "GET").upper(),
        "url": redact_url(url),
        "headers": redact_headers(request_headers),
    }
    if cookies:
        request["cookie_names"] = sorted(cookies.keys())
    if params:
        request["params"] = {str(k): _redact_value(k, v) for k, v in params.items()}
    if data:
        request["data"] = {str(k): _redact_value(k, v) for k, v in data.items()}

    return {
        "request": request,
        "response": {
            "status_code": int(response.status_code),
            "headers": redact_headers(dict(response.headers)),
            "body": redact_body_excerpt(response.text),
        },
        "timing_ms": round(float(elapsed_ms), 2),
    }
