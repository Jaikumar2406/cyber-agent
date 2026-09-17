"""runtime.discovery.openapi - OpenAPI/Swagger spec discovery tool (phases.md §1.2).

Probes a base URL for a hosted OpenAPI/Swagger spec (openapi.json, swagger.json,
...), fetches it through the Scope & Policy Guard, parses it into discovered
endpoints, and returns them as evidence. Pure offline parsing - no third-party
spec libraries (rules.md §3).
"""

from typing import Any

import httpx

from app.core.logging import get_logger
from app.discovery.openapi_parser import (
    OpenApiParseError,
    parse_openapi_spec,
    spec_urls_for_base,
)
from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import ToolResultStatus

log = get_logger("aegis.tools.openapi")


class OpenApiTool(BaseTool):
    name = "runtime.discovery.openapi"
    description = (
        "Fetch and parse an OpenAPI/Swagger spec (probed from a base URL or an "
        "explicit spec URL) into discovered endpoints. Scoped and rate-limited "
        "per request; offline parsing only."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "format": "uri", "description": "base URL to probe for a spec"},
            "spec_url": {"type": "string", "format": "uri", "description": "explicit spec URL (optional)"},
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 10.0},
            "max_redirects": {"type": "integer", "minimum": 0, "maximum": 10, "default": 3},
        },
        "required": ["url"],
    }
    permissions = ("runtime:discovery:openapi", "runtime:http:get")
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("read_only",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        url = str(args["url"]).rstrip("/")
        spec_url = (args.get("spec_url") or "").strip() or None
        timeout = float(args.get("timeout", 10.0))
        max_redirects = int(args.get("max_redirects", 3))

        scope_guard = context.scope_guard
        if scope_guard is None:
            return ToolResult(status=ToolResultStatus.FAILURE, error="openapi tool requires a scope guard in context")

        candidates = [spec_url] if spec_url else spec_urls_for_base(url)

        for candidate in candidates:
            scope = scope_guard.validate_target(candidate, method="GET")
            if not scope.allowed:
                continue
            if context.rate_limiter is not None:
                await context.rate_limiter.acquire()

            current = candidate
            for _hop in range(max_redirects + 1):
                scope = scope_guard.validate_target(current, method="GET")
                if not scope.allowed:
                    current = None
                    break
                try:
                    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
                        resp = await client.get(current, timeout=timeout)
                except httpx.HTTPError:
                    current = None
                    break
                if resp.is_redirect:
                    location = resp.headers.get("location")
                    if location is None or _hop >= max_redirects:
                        current = None
                        break
                    next_url = httpx.URL(current).join(location).__str__()
                    if not scope_guard.validate_redirect(current, next_url).allowed:
                        current = None
                        break
                    current = next_url
                    continue
                if resp.status_code == 200 and resp.text.strip():
                    try:
                        endpoints = parse_openapi_spec(resp.text, found_in=current)
                    except OpenApiParseError:
                        endpoints = []
                    if endpoints:
                        return ToolResult(
                            status=ToolResultStatus.SUCCESS,
                            output={
                                "spec_url": current,
                                "endpoints": [e.as_dict() for e in endpoints],
                                "endpoint_count": len(endpoints),
                                "candidates_probed": candidates,
                            },
                        )
                current = None
                break

        return ToolResult(
            status=ToolResultStatus.FAILURE,
            error=f"no OpenAPI/Swagger spec found at {url!r}",
            output={
                "spec_url": None,
                "endpoints": [],
                "candidates_probed": candidates,
            },
        )