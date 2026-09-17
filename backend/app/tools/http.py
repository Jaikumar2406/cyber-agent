"""Runtime HTTP request tool (phases.md §1.1 enforcement demo + Phase 1.x base).

The first tool that actually touches the network, and therefore the first tool
that MUST prove the Scope & Policy Guard works at request granularity:

  * before EVERY request (and every redirect hop, rules.md §3.2) the URL is
    re-scoped - method, host, IP/CIDR, and path - through the Scope Guard;
  * HTTP method is checked against the scan policy's allowed-method set
    (derived from scan intensity);
  * every request passes through the Policy Guard's per-scan rate limiter;
  * payloads are only referenced by controlled-catalog id (never inline); the
    `ssrf.canary` payload value `{canary}` is substituted with the scan's own
    local canary origin at runtime.

Responses are captured as structured evidence (status, headers, body excerpt,
timing) exactly as PRD FR-17 requires for findings. Secrets (Authorization /
Cookie / Set-Cookie and common key patterns) are redacted from that evidence.
"""

import re
import time
from typing import Any
from urllib.parse import urlencode, urljoin

import httpx

from app.control_plane.payloads import get_payload_catalog
from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import ToolResultStatus

_BODY_EXCERPT_CHARS = 4096
_REDACTION_PATTERNS = (
    "api[_-]?key",
    "secret",
    "passw(or)?d",
    "token",
    "authorization",
    "cookie",
)


def _is_sensitive_header(name: str) -> bool:
    lowered = name.lower()
    return any(re.search(pattern, lowered) for pattern in _REDACTION_PATTERNS)


def _sensitive_values(headers: dict[str, str]) -> set[str]:
    return {value for key, value in headers.items() if _is_sensitive_header(key)}


def _redact(text: str, *, secrets: set[str] | None = None) -> str:
    lowered = text
    for pattern in _REDACTION_PATTERNS:
        lowered = re.sub(
            rf"({pattern}\s*[=:]\s*)([^\\s&;,'\"]+)", r"\1[REDACTED]", lowered, flags=re.IGNORECASE
        )
    for secret in sorted((secrets or set()) - {""}, key=len, reverse=True):
        lowered = lowered.replace(secret, "[REDACTED]")
    return lowered


class HttpRequestTool(BaseTool):
    name = "runtime.http.request"
    description = (
        "Send a single HTTP request inside the Scope & Policy Guard. Every hop is "
        "re-scoped, rate-limited, and audited; payloads must be controlled-catalog ids."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "minLength": 1},
            "method": {
                "type": "string",
                "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "default": "GET",
            },
            "headers": {"type": "object", "default": {}},
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 10.0},
            "max_redirects": {"type": "integer", "minimum": 0, "maximum": 10, "default": 3},
            "payload_id": {"type": "string"},
            "payload_param": {"type": "string", "minLength": 1},
        },
        "required": ["url"],
    }
    permissions = (
        "runtime:http:get",
        "runtime:http:head",
        "runtime:http:post",
        "runtime:http:put",
        "runtime:http:patch",
        "runtime:http:delete",
        "runtime:http:options",
    )
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("read_only",)
    payload_fields = ("payload_id",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        url = str(args["url"])
        method = str(args.get("method", "GET")).upper()
        headers = dict(args.get("headers") or {})
        timeout = float(args.get("timeout", 10.0))
        max_redirects = int(args.get("max_redirects", 3))
        secrets = _sensitive_values(headers)

        # --- Build the effective URL, resolving controlled payloads ----------
        payload_id = args.get("payload_id")
        injected_param: str | None = None
        if payload_id:
            payload = get_payload_catalog().by_id(str(payload_id))
            if payload is None:
                return self._policy_deny("payload_id references a non-controlled payload")
            value = payload.value
            if "{canary}" in value:
                if context.canary is None:
                    return self._policy_deny("ssrf.canary payload requires a live scan canary")
                value = value.replace("{canary}", context.canary.base_url)
            param = str(args.get("payload_param") or "q")
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{urlencode({param: value})}"
            injected_param = param

        # --- Policy: method + rate limit, then scope, per hop -----------------
        scope_guard = context.scope_guard
        if scope_guard is None:
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error="http tool requires a scope guard in context",
            )
        allowed_methods = (context.policy or {}).get("allowed_methods")
        if allowed_methods and method not in allowed_methods and "*" not in allowed_methods:
            return self._policy_deny(f"HTTP method {method!r} not permitted by scan policy")

        chain: list[dict[str, Any]] = []
        current_url = url
        current_method = method
        for _hop in range(max_redirects + 1):
            scope = scope_guard.validate_target(current_url, method=current_method)
            if not scope.allowed:
                return ToolResult(
                    status=ToolResultStatus.SCOPE_VIOLATION,
                    error=f"request {current_url!r} out of scope: {scope.reason}",
                )
            if context.rate_limiter is not None:
                await context.rate_limiter.acquire()

            start = time.monotonic()
            try:
                async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
                    resp = await client.request(
                        current_method, current_url, headers=headers, timeout=timeout
                    )
            except httpx.HTTPError as exc:
                return ToolResult(
                    status=ToolResultStatus.FAILURE,
                    error=f"http request failed: {exc}",
                    output={
                        "url": current_url,
                        "method": current_method,
                        "error": str(exc),
                        "redirect_chain": chain,
                    },
                )
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)

            body = resp.text
            excerpt = body[:_BODY_EXCERPT_CHARS]
            hop = {
                "url": _redact(current_url, secrets=secrets),
                "method": current_method,
                "status_code": resp.status_code,
                "headers": {k: _redact(v, secrets=secrets) for k, v in resp.headers.items()},
                "body_excerpt": _redact(excerpt, secrets=secrets),
                "elapsed_ms": elapsed_ms,
            }
            chain.append(hop)

            location = resp.headers.get("location")
            if resp.is_redirect:
                if location is None or _hop >= max_redirects:
                    current_url = urljoin(current_url, location) if location else current_url
                    return ToolResult(
                        status=ToolResultStatus.SUCCESS,
                        output={
                            "final_url": _redact(current_url, secrets=secrets),
                            "status_code": resp.status_code,
                            "redirect_chain": chain,
                            "stopped_at_redirect": True,
                            "payload_id": payload_id,
                            "injected_param": injected_param,
                        },
                    )
                next_url = urljoin(current_url, location)
                redirect_decision = scope_guard.validate_redirect(current_url, next_url)
                if not redirect_decision.allowed:
                    return ToolResult(
                        status=ToolResultStatus.SCOPE_VIOLATION,
                        error=f"redirect out of scope: {redirect_decision.reason}",
                        output={"redirect_chain": chain, "blocked_redirect": _redact(next_url, secrets=secrets)},
                    )
                current_url = next_url
                # RFC 7231: 302/303 -> GET for the next hop.
                if resp.status_code in (302, 303) and current_method not in ("GET", "HEAD"):
                    current_method = "GET"
                continue

            return ToolResult(
                status=ToolResultStatus.SUCCESS,
                output={
                    "final_url": _redact(current_url, secrets=secrets),
                    "status_code": resp.status_code,
                    "method": current_method,
                    "headers": hop["headers"],
                    "body_excerpt": body and hop["body_excerpt"] or "",
                    "elapsed_ms": elapsed_ms,
                    "redirect_chain": chain,
                    "payload_id": payload_id,
                    "injected_param": injected_param,
                },
            )

        return ToolResult(
            status=ToolResultStatus.FAILURE,
            error=f"redirect limit of {max_redirects} exceeded",
            output={"redirect_chain": chain},
        )

    @staticmethod
    def _policy_deny(reason: str) -> ToolResult:
        return ToolResult(status=ToolResultStatus.POLICY_DENIED, error=reason)