"""runtime.test.access_control - BOLA/BFLA module (phases.md §1.5, §1.6).

Requires exactly two provisioned test identities (§1.3). For each protected
endpoint it replays the request as both identities and applies the deterministic
classifier in `app.testing.access_control`. Raw session secrets never appear in
output - only the redacted identity summaries. Every finding carries the full,
redacted request/response exchange for both identities plus the auth-identity
proof tie-in (phases.md §1.6).
"""

import time
from typing import Any

from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import ToolResultStatus
from app.testing import access_control
from app.testing.transport import OutOfScope, capture_exchange, identity_auth, scoped_request


class AccessControlTestTool(BaseTool):
    name = "runtime.test.access_control"
    description = (
        "BOLA/BFLA cross-identity testing: replay protected endpoints as two test "
        "identities and flag broken object/function-level authorization. "
        "Requires active+ intensity and two provisioned identities."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "application_model": {
                "type": "object",
                "description": "Output dict from runtime.model.build (must contain 'endpoints')",
            },
            "identity_ids": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 2,
                "maxItems": 2,
                "description": "Exactly two identity ids from the scan identity store",
            },
            "methods": {
                "type": "array",
                "items": {"type": "string"},
                "default": ["GET"],
            },
            "max_endpoints": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25},
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 5.0},
        },
        "required": ["application_model", "identity_ids"],
    }
    permissions = ("runtime:test:access_control", "runtime:http:get")
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("cross_user",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        store = getattr(context, "identity_store", None)
        if store is None or store.count() < 2:
            return ToolResult(
                status=ToolResultStatus.POLICY_DENIED,
                error=(
                    "access-control testing requires two provisioned test identities "
                    "(run runtime.auth.login for two operator-supplied credentials first)"
                ),
            )

        identity_ids = [str(i) for i in (args.get("identity_ids") or [])]
        identities = []
        for identity_id in identity_ids:
            identity = store.get(identity_id)
            if identity is None:
                identity = store.by_credential(identity_id)
            identities.append(identity)
        if len(identities) != 2 or any(i is None for i in identities):
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error="identity_ids must reference exactly two known identities",
            )
        identity_a, identity_b = identities

        model = args.get("application_model") or {}
        endpoints = model.get("endpoints") or []
        methods = {str(m).upper() for m in (args.get("methods") or ["GET"])}
        max_endpoints = int(args.get("max_endpoints", 25))
        timeout = float(args.get("timeout", 5.0))

        headers_a, cookies_a = identity_auth(identity_a)
        headers_b, cookies_b = identity_auth(identity_b)
        redacted_a = identity_a.redacted()
        redacted_b = identity_b.redacted()

        findings: list[dict[str, Any]] = []
        tested = 0
        for ep in endpoints:
            if tested >= max_endpoints:
                break
            if not ep.get("auth_required"):
                continue
            method = str(ep.get("method", "GET")).upper()
            if method not in methods:
                continue
            url = str(ep.get("url", ""))
            if not url:
                continue

            resp_a = await self._send(method, url, headers_a, cookies_a, context, timeout)
            resp_b = await self._send(method, url, headers_b, cookies_b, context, timeout)
            if resp_a is None or resp_b is None:
                continue
            tested += 1
            status_a, body_a, exchange_a = resp_a
            status_b, body_b, exchange_b = resp_b

            finding = access_control.classify_pair(
                method=method,
                url=url,
                path=str(ep.get("path", "/")),
                status_a=status_a,
                body_a=body_a,
                status_b=status_b,
                body_b=body_b,
                identity_a=redacted_a,
                identity_b=redacted_b,
            )
            if finding is not None:
                finding.evidence["http"] = {
                    "exchanges": {
                        "identity_a": exchange_a,
                        "identity_b": exchange_b,
                    },
                    "endpoint_path": ep.get("path"),
                }
                findings.append(finding.as_dict())

        return ToolResult(
            status=ToolResultStatus.SUCCESS,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "endpoints_tested": tested,
                "identities": [redacted_a, redacted_b],
            },
        )

    async def _send(self, method, url, headers, cookies, context, timeout):
        try:
            start = time.monotonic()
            resp = await scoped_request(
                method, url, context=context, timeout=timeout,
                headers=headers, cookies=cookies,
            )
            elapsed_ms = (time.monotonic() - start) * 1000.0
            exchange = capture_exchange(
                method=method, url=url, response=resp, elapsed_ms=elapsed_ms,
                headers=headers, cookies=cookies,
            )
            return resp.status_code, resp.text, exchange
        except OutOfScope:
            return None
        except Exception:
            return None
