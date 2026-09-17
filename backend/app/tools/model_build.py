"""runtime.model.build — Application Model Builder tool (phases.md §1.4).

Takes the outputs of 1.2 (crawl) and 1.3 (auth.analyze), samples each
discovered endpoint with a lightweight scoped GET/HEAD to capture the
response shape, then assembles the full ApplicationModel — the single
attack-surface map that 1.5 security test modules consume.

Network access is scoped, rate-limited, and audited through the Harness
(rules.md §3.2, §3.8).  Intensity stays passive (read_only).
"""

from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.logging import get_logger
from app.discovery.models import CrawlerStats, DiscoveredEndpoint
from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.model.builder import build_application_model
from app.model.application_model import ApplicationModel
from app.schemas.common import ToolResultStatus

log = get_logger("aegis.tools.model_build")

_BODY_EXCERPT_CHARS = 2048


class ModelBuildTool(BaseTool):
    name = "runtime.model.build"
    description = (
        "Assemble the Application Model from crawl output and auth analysis. "
        "Samples each endpoint with a lightweight scoped GET/HEAD to record the "
        "response shape, then builds the full attack-surface map for 1.5 tests."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "crawl_result": {
                "type": "object",
                "description": "Output dict from runtime.discovery.crawl (must contain 'endpoints' list)",
            },
            "auth_analysis": {
                "type": "object",
                "description": "Output dict from runtime.auth.analyze (mechanisms, login endpoints, etc.)",
            },
            "spec_url": {
                "type": "string",
                "format": "uri",
                "description": "Optional OpenAPI spec URL to enrich parameters",
            },
            "sample_methods": {
                "type": "array",
                "items": {"type": "string"},
                "default": ["GET"],
                "description": "HTTP methods to sample (default: GET only)",
            },
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 5.0},
        },
        "required": ["crawl_result"],
    }
    permissions = ("runtime:model:build", "runtime:http:get")
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("read_only",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        crawl_result = args.get("crawl_result") or {}
        auth_analysis = args.get("auth_analysis") or {}
        spec_url = args.get("spec_url")
        sample_methods = list(args.get("sample_methods") or ["GET"])
        timeout = float(args.get("timeout", 5.0))

        scope_guard = context.scope_guard
        if scope_guard is None:
            return ToolResult(status=ToolResultStatus.FAILURE,
                              error="model.build requires a scope guard in context")

        # --- Parse crawl endpoints into DiscoveredEndpoint objects ----------------
        raw_endpoints = crawl_result.get("endpoints") or []
        discovered = [_parse_endpoint(ep) for ep in raw_endpoints]

        # --- Resolve OpenAPI doc if spec_url provided ---------------------------
        openapi_doc: dict[str, Any] | None = None
        if spec_url:
            openapi_doc = await self._fetch_spec(str(spec_url), scope_guard, context, timeout)

        # --- HTTP-sample each endpoint (scoped + rate-limited per request) -----
        base_url = str(crawl_result.get("seed_url") or context.target or "")
        samples = await self._sample_endpoints(
            discovered, sample_methods, base_url, scope_guard, context, timeout
        )

        # --- Build the model via pure builder -----------------------------------
        model: ApplicationModel = build_application_model(
            discovered_endpoints=discovered,
            auth_analysis=auth_analysis,
            openapi_doc=openapi_doc,
            http_samples=samples,
            base_url=base_url,
        )

        return ToolResult(
            status=ToolResultStatus.SUCCESS,
            output=model.as_dict(),
            error=None,
        )

    # ---------------------------------------------------------------------------
    # HTTP sampling
    # ---------------------------------------------------------------------------

    async def _sample_endpoints(
        self,
        endpoints: list[DiscoveredEndpoint],
        methods: list[str],
        base_url: str,
        scope_guard: Any,
        context: ToolContext,
        timeout: float,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Scoped, rate-limited GET/HEAD of each endpoint.  Returns a lookup
        keyed by (method, url) with observed response data."""
        samples: dict[tuple[str, str], dict[str, Any]] = {}
        seen: set[tuple[str, str]] = set()

        for ep in endpoints:
            for method in methods:
                method = method.upper()
                if method not in ("GET", "HEAD"):
                    continue
                url = _resolve_url(ep.path, base_url)
                if not url:
                    continue
                sample_key = (method, url)
                if sample_key in seen:
                    continue
                seen.add(sample_key)

                scope = scope_guard.validate_target(url, method=method)
                if not scope.allowed:
                    continue
                if context.rate_limiter is not None:
                    await context.rate_limiter.acquire()

                try:
                    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
                        resp = await client.request(method, url, timeout=timeout)
                    cookie_names = _extract_cookie_names(resp)
                    samples[sample_key] = {
                        "status_code": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "headers": {k: v for k, v in resp.headers.items()
                                    if k.lower() not in ("set-cookie", "authorization")},
                        "set_cookie_names": cookie_names,
                    }
                except httpx.HTTPError:
                    pass  # Failed sample → skip, model records None for this endpoint
        return samples

    async def _fetch_spec(self, url: str, scope_guard: Any, context: ToolContext, timeout: float) -> dict[str, Any] | None:
        scope = scope_guard.validate_target(url, method="GET")
        if not scope.allowed:
            return None
        if context.rate_limiter is not None:
            await context.rate_limiter.acquire()
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
                resp = await client.get(url, timeout=timeout)
            from app.discovery.openapi_parser import load_openapi_document
            return load_openapi_document(resp.text)
        except Exception as exc:
            log.info("model.build.spec_fetch_failed", error=str(exc))
            return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_url(path: str, base_url: str) -> str | None:
    """Turn a relative path or absolute URL into a full URL."""
    if not path:
        return None
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if base_url:
        return urljoin(base_url if base_url.endswith("/") else base_url + "/", path)
    return None


def _parse_endpoint(raw: dict[str, Any]) -> DiscoveredEndpoint:
    """Reconstruct a DiscoveredEndpoint from the crawl output dict."""
    query = raw.get("query_params") or ()
    if isinstance(query, list):
        query = tuple(query)
    return DiscoveredEndpoint(
        method=str(raw.get("method", "GET")).upper(),
        path=str(raw.get("path", "/")),
        source=str(raw.get("source", "crawl")),
        found_in=raw.get("found_in"),
        query_params=query,
        body_media_type=raw.get("body_media_type"),
        extra=raw.get("extra") or {},
    )


def _extract_cookie_names(resp: httpx.Response) -> list[str]:
    """Pull cookie names from Set-Cookie headers (no values)."""
    names: list[str] = []
    values = resp.headers.get_list("set-cookie") or (
        [resp.headers.get("set-cookie")] if resp.headers.get("set-cookie") else []
    )
    for raw in values:
        if not raw:
            continue
        name = raw.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names