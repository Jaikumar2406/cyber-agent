"""runtime.auth.analyze - passive authentication discovery (phases.md §1.3).

Determines HOW a target authenticates without ever sending credentials:
samples the login URL and an optional OpenAPI spec, classifies mechanisms
(JWT / cookie-session / OAuth / Basic / api-key / form-login) from on-wire
headers and page structure, and flags candidate login endpoints for the later
identity-provisioning tool.

Every request is scoped and rate-limited through the Scope & Policy Guard
(rules.md §3.2, §3.8). This is strictly a read-only observation tool.
"""

from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

import httpx

from app.auth_analysis.detector import (
    detect_all,
    summarize,
)
from app.core.logging import get_logger
from app.discovery.openapi_parser import (
    OpenApiParseError,
    load_openapi_document,
    parse_openapi_spec,
)
from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import ToolResultStatus
from app.tools.http import _is_sensitive_header, _redact, _sensitive_values

log = get_logger("aegis.tools.auth_analyze")

_LOGIN_TEXT = ("login", "log in", "sign in", "signin", "authenticate", "identity")
_BODY_EXCERPT_CHARS = 4096


class _FetchFailed(Exception):
    """A scoped sample could not be retrieved for non-scope reasons (transport
    error, redirect limit). Kept separate from scope denial so a connection
    failure is never misreported as a scope violation."""


def _candidate_login_links(html: str, base_url: str) -> list[str]:
    """Absolute URLs of anchors that look like auth entry points."""
    class _AnchorParser(HTMLParser):  # noqa: N801
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.candidates: list[tuple[str, str]] = []  # (href, text)
            self._buf: list[str] = []  # anchor text buffer
            self._depth = 0

        def handle_starttag(self, tag, attrs) -> None:  # noqa: N802
            if tag == "a":
                self._depth += 1
                self._buf = []
                self._current_href = dict(attrs).get("href") or ""

        def handle_data(self, data) -> None:  # noqa: N802
            if self._depth > 0:
                self._buf.append(data)

        def handle_endtag(self, tag) -> None:  # noqa: N802
            if tag == "a" and self._depth > 0:
                self._depth -= 1
                text = " ".join("".join(self._buf).split()).lower()
                href = (self._current_href or "").strip()
                if href and any(tok in text for tok in _LOGIN_TEXT):
                    self.candidates.append((href, text))

    parser = _AnchorParser()
    parser.feed(html or "")
    resolved: list[str] = []
    for href, _ in parser.candidates:
        try:
            resolved.append(urljoin(base_url, href))
        except ValueError:
            continue
    return resolved


class AuthAnalyzeTool(BaseTool):
    name = "runtime.auth.analyze"
    description = (
        "Passively determine how a target authenticates (JWT / cookie / OAuth / "
        "Basic / api-key / form login) by sampling a login URL and optional "
        "OpenAPI spec. Never sends credentials."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "format": "uri",
                "description": "login page or base URL to sample",
            },
            "spec_url": {
                "type": "string",
                "format": "uri",
                "description": "optional OpenAPI/Swagger spec to classify security schemes",
            },
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 10.0},
            "max_redirects": {"type": "integer", "minimum": 0, "maximum": 10, "default": 3},
        },
        "required": ["url"],
    }
    permissions = ("runtime:auth:analyze", "runtime:http:get")
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("read_only",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        url = str(args["url"])
        spec_url = args.get("spec_url")
        timeout = float(args.get("timeout", 10.0))
        max_redirects = int(args.get("max_redirects", 3))

        scope_guard = context.scope_guard
        if scope_guard is None:
            return ToolResult(status=ToolResultStatus.FAILURE, error="auth.analyze requires a scope guard in context")

        # --- Sample the page (scoped + rate-limited per hop) ------------------
        try:
            sampled = await self._fetch(url, "GET", context, timeout, max_redirects)
        except _FetchFailed as exc:
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error=f"login URL {url!r} could not be sampled: {exc}",
            )
        if sampled is None:
            return ToolResult(
                status=ToolResultStatus.SCOPE_VIOLATION,
                error=f"login URL {url!r} out of scope",
            )
        status_code, headers, body = sampled
        seen_urls = [url]

        hints = detect_all(headers=headers, html=body, base_url=url)

        # --- Optional OpenAPI securitySchemes --------------------------------
        spec_checked = False
        openapi_endpoint_count = 0
        if spec_url:
            try:
                spec_sampled = await self._fetch(str(spec_url), "GET", context, timeout, max_redirects)
            except _FetchFailed as exc:
                log.info("auth.analyze.openapi_unreachable", spec_url=str(spec_url), error=str(exc))
                spec_sampled = None
            if spec_sampled is not None:
                _, _headers, spec_body = spec_sampled
                try:
                    endpoints = parse_openapi_spec(spec_body, found_in=str(spec_url))
                    openapi_endpoint_count = len(endpoints)
                    # Re-load the raw doc for securitySchemes (parser drops them).
                    raw = load_openapi_document(spec_body)
                    hints.extend(detect_all(openapi_doc=raw))
                    spec_checked = True
                except OpenApiParseError as exc:
                    log.info("auth.analyze.openapi_unparsable", error=str(exc))
            else:
                log.info("auth.analyze.openapi_skipped", spec_url=str(spec_url))

        # --- Candidate login endpoints (form actions + auth anchors) ---------
        from app.discovery.link_extractor import extract_forms

        form_actions = [action for action, method in extract_forms(body, url) if method in ("GET", "POST")]
        login_links = [link for link in _candidate_login_links(body, url) if self._same_host(link, url)]

        self_seen = {"page": url, "status_code": status_code}
        summary = summarize(hints)
        # Never persist raw auth material: redact sensitive header values and any
        # secret literals echoed in the body (rules.md §5.5).
        secrets = _sensitive_values(headers)
        safe_headers = {
            key: "[REDACTED]" if _is_sensitive_header(key) else _redact(value, secrets=secrets)
            for key, value in headers.items()
        }

        output: dict[str, Any] = {
            **self_seen,
            "headers": safe_headers,
            "body_excerpt": _redact(body[:_BODY_EXCERPT_CHARS], secrets=secrets),
            "mechanisms": summary["mechanisms"],
            "mechanism_count": summary["count"],
            "spec_checked": spec_checked,
            "openapi_endpoint_count": openapi_endpoint_count,
            "candidate_login_endpoints": {
                "form_actions": form_actions,
                "auth_links": login_links,
                "seen_urls": seen_urls,
            },
        }
        return ToolResult(status=ToolResultStatus.SUCCESS, output=output, error=None)

    async def _fetch(self, url, method, context, timeout, max_redirects):
        """One scoped, rate-limited GET. Returns (status_code, dict_headers, body).

        Returns None ONLY when the URL (or a redirect hop) is out of scope.
        Non-scope retrieval failures (transport errors, redirect limits) raise
        _FetchFailed so callers never mistake them for scope violations.
        """
        scope_guard = context.scope_guard
        scope = scope_guard.validate_target(url, method=method)
        if not scope.allowed:
            return None
        current = url
        for _hop in range(max_redirects + 1):
            scope = scope_guard.validate_target(current, method="GET")
            if not scope.allowed:
                return None
            if context.rate_limiter is not None:
                await context.rate_limiter.acquire()
            try:
                async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
                    resp = await client.get(current, timeout=timeout)
            except httpx.HTTPError as exc:
                raise _FetchFailed(f"http request failed: {exc}") from exc
            if resp.is_redirect:
                location = resp.headers.get("location")
                if not location or _hop >= max_redirects:
                    raise _FetchFailed(f"redirect limit exceeded while sampling {current!r}")
                next_url = urljoin(current, location)
                redirect = scope_guard.validate_redirect(current, next_url)
                if not redirect.allowed:
                    return None
                current = next_url
                continue
            return resp.status_code, dict(resp.headers), resp.text
        raise _FetchFailed(f"redirect limit exceeded while sampling {url!r}")

    @staticmethod
    def _same_host(url_a: str, url_b: str) -> bool:
        from urllib.parse import urlsplit

        return (urlsplit(url_a).hostname or "").lower() == (urlsplit(url_b).hostname or "").lower()