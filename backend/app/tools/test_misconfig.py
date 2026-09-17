"""runtime.test.misconfig - misconfiguration module (phases.md §1.5, §1.6).

Pure/offline analysis of the Application Model (§1.4): it reads the response
metadata already recorded during sampling and reports missing security headers,
permissive CORS, banner disclosure and exposed debug endpoints. No new network
requests are made, so it is read-only (passive-safe). Each finding attaches the
observed response metadata (status + redacted headers) as its §1.6 evidence.
"""

from typing import Any

from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import ToolResultStatus
from app.testing import misconfig
from app.testing.transport import redact_headers


class MisconfigTestTool(BaseTool):
    name = "runtime.test.misconfig"
    description = (
        "Analyze the Application Model for misconfigurations: missing security "
        "headers, permissive CORS, version disclosure and exposed debug endpoints."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "application_model": {
                "type": "object",
                "description": "Output dict from runtime.model.build (must contain 'endpoints')",
            },
            "bodies": {
                "type": "object",
                "description": "Optional map of absolute URL -> response body excerpt for verbose-error checks",
            },
        },
        "required": ["application_model"],
    }
    permissions = ("runtime:test:misconfig",)
    sandbox = SandboxSpec(mode="process", network=False)
    policy_requirements = ("read_only",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        model = args.get("application_model") or {}
        endpoints = model.get("endpoints") or []
        bodies: dict[str, str] = args.get("bodies") or {}

        findings: list[dict[str, Any]] = []
        for ep in endpoints:
            url = str(ep.get("url", ""))
            body = bodies.get(url)
            observed = {
                "status_code": ep.get("status_code"),
                "headers": redact_headers(ep.get("response_headers") or {}),
            }
            for finding in misconfig.analyze_endpoint(ep, body=body):
                finding.evidence["http"] = {"observed_response": observed}
                findings.append(finding.as_dict())

        return ToolResult(
            status=ToolResultStatus.SUCCESS,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "endpoints_analyzed": len(endpoints),
            },
        )
