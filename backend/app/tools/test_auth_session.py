"""runtime.test.auth_session - authentication/session weakness module (§1.5, §1.6).

Fetches each target URL with a scoped read-only GET, captures the Set-Cookie
attributes and flags: missing HttpOnly/Secure/SameSite, session cookies over
cleartext HTTP, and HTTP Basic authentication. Secret cookie values are never
recorded - only names and flags (rules.md §5.5/§5.6). Findings include the
redacted HTTP exchange for the observed URL (§1.6).
"""

import time
from typing import Any

from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import ToolResultStatus
from app.testing import auth_session
from app.testing.transport import OutOfScope, capture_exchange, scoped_request


class AuthSessionTestTool(BaseTool):
    name = "runtime.test.auth_session"
    description = (
        "Check authentication/session weaknesses: insecure cookie flags "
        "(HttpOnly/Secure/SameSite), cleartext session transport and HTTP Basic auth."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "urls": {
                "type": "array",
                "items": {"type": "string", "format": "uri"},
                "minItems": 1,
                "description": "URLs to fetch and analyze (login pages, session-establishing endpoints)",
            },
            "auth_analysis": {
                "type": "object",
                "description": "Optional output dict from runtime.auth.analyze",
            },
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 5.0},
        },
        "required": ["urls"],
    }
    permissions = ("runtime:test:auth_session", "runtime:http:get")
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("read_only",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        urls = [str(u) for u in (args.get("urls") or [])]
        auth_analysis = args.get("auth_analysis") or {}
        timeout = float(args.get("timeout", 5.0))

        findings: list[dict[str, Any]] = []
        fetched: list[str] = []
        exchanges: dict[str, dict[str, Any]] = {}
        for url in urls:
            try:
                start = time.monotonic()
                resp = await scoped_request("GET", url, context=context, timeout=timeout)
                elapsed_ms = (time.monotonic() - start) * 1000.0
            except OutOfScope:
                continue
            except Exception:
                continue
            fetched.append(url)
            exchanges[url] = capture_exchange(
                method="GET", url=url, response=resp, elapsed_ms=elapsed_ms,
            )
            set_cookie = resp.headers.get_list("set-cookie") or (
                [resp.headers.get("set-cookie")] if resp.headers.get("set-cookie") else []
            )
            for finding in auth_session.analyze_cookies(url=url, set_cookie_headers=set_cookie):
                finding.evidence["http"] = exchanges[url]
                findings.append(finding.as_dict())

        if auth_analysis:
            for url in fetched:
                for finding in auth_session.analyze_auth_mechanism(url=url, auth_analysis=auth_analysis):
                    finding.evidence["http"] = exchanges[url]
                    findings.append(finding.as_dict())

        return ToolResult(
            status=ToolResultStatus.SUCCESS,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "urls_analyzed": fetched,
            },
        )
