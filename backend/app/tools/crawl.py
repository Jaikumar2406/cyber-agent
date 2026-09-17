"""runtime.discovery.crawl - spider tool (phases.md §1.2).

Scopes and rate-limits every HTTP request through the Scope & Policy Guard
(same guarantees as the HTTP request tool), records every page and form action
as a discovered endpoint, returns the crawl as evidence.

Network access flows through the desired_state enforced by the Harness - the
tool never bypasses scope: each page fetch is validated by the Scope Guard's
`validate_target` and, on redirect, by `validate_redirect` (rules.md §3.2).
"""

from typing import Any

import httpx

from app.core.logging import get_logger
from app.discovery.crawler import (
    Crawler,
    CrawlerConfig,
    DiscoveryFetchError,
)
from app.discovery.models import CrawlResult
from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import ToolResultStatus

log = get_logger("aegis.tools.crawl")

_DEFAULT_MAX_PAGES = 20
_DEFAULT_MAX_DEPTH = 3


class CrawlTool(BaseTool):
    name = "runtime.discovery.crawl"
    description = (
        "Crawl a same-host web application from a start URL, recording every page "
        "and form as a discovered endpoint. Every request is scoped, rate-limited, "
        "and audited. Produces a discovered-endpoint list as evidence."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "format": "uri"},
            "max_pages": {"type": "integer", "minimum": 1, "maximum": 500, "default": _DEFAULT_MAX_PAGES},
            "max_depth": {"type": "integer", "minimum": 1, "maximum": 10, "default": _DEFAULT_MAX_DEPTH},
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 10.0},
            "max_redirects": {"type": "integer", "minimum": 0, "maximum": 10, "default": 3},
        },
        "required": ["url"],
    }
    permissions = ("runtime:discovery:crawl", "runtime:http:get")
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("read_only",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        url = str(args["url"])
        max_pages = int(args.get("max_pages", _DEFAULT_MAX_PAGES))
        max_depth = int(args.get("max_depth", _DEFAULT_MAX_DEPTH))
        timeout = float(args.get("timeout", 10.0))
        max_redirects = int(args.get("max_redirects", 3))

        scope_guard = context.scope_guard
        if scope_guard is None:
            return ToolResult(status=ToolResultStatus.FAILURE, error="crawl tool requires a scope guard in context")

        async def fetch(target_url: str) -> tuple[str | None, str | None]:
            """Scope + rate-limit + retrieve one page. Returns (final_url, body).

            (None, None) signals the target was out of scope / a redirect left
            scope - the crawler counts it as a bounce and records nothing.
            """
            scope = scope_guard.validate_target(target_url, method="GET")
            if not scope.allowed:
                return None, None
            if context.rate_limiter is not None:
                await context.rate_limiter.acquire()

            current = target_url
            for _hop in range(max_redirects + 1):
                scope = scope_guard.validate_target(current, method="GET")
                if not scope.allowed:
                    return None, None
                try:
                    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
                        resp = await client.get(current, timeout=timeout)
                except httpx.HTTPError as exc:
                    raise DiscoveryFetchError(f"http request failed: {exc}") from exc

                if resp.is_redirect:
                    location = resp.headers.get("location")
                    if location is None or _hop >= max_redirects:
                        return None, None
                    next_url = httpx.URL(current).join(location).__str__()
                    redirect = scope_guard.validate_redirect(current, next_url)
                    if not redirect.allowed:
                        return None, None
                    current = next_url
                    continue
                return current, resp.text

            return None, None

        config = CrawlerConfig(
            max_pages=max_pages,
            max_depth=max_depth,
            same_host_only=True,
            include_forms=True,
        )
        crawler = Crawler(config=config, fetch=fetch)
        try:
            result: CrawlResult = await crawler.crawl(url)
        except DiscoveryFetchError as exc:
            return ToolResult(status=ToolResultStatus.FAILURE, error=str(exc))

        if not result.endpoints:
            output = result.as_dict()
            output["reachable"] = result.stats.pages_fetched > 0
            if not output["reachable"]:
                if result.stats.out_of_scope_bounced:
                    output["unreachable_reason"] = "the target rejected every request as out of scope"
                else:
                    output["unreachable_reason"] = (
                        "the target never returned an HTTP response (connection/transport failure)"
                    )
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error=f"crawl produced no endpoints from {url!r}",
                output=output,
            )
        return ToolResult(
            status=ToolResultStatus.SUCCESS,
            output=result.as_dict(),
            error=None,
        )