"""runtime.test.ssrf - SSRF module (phases.md §1.5, §1.6, canary-only).

rules.md §3.5: server-side request forgery is proven ONLY with the platform's
own loopback canary. This tool injects the canary URL (via the controlled
`ssrf.canary` payload) into candidate URL parameters and treats a canary hit as
conclusive proof. Requires aggressive intensity and a live canary.
"""

import asyncio
import time
from typing import Any

from app.control_plane.payloads import get_payload_catalog
from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import Confidence, Severity, ToolResultStatus
from app.testing import ssrf
from app.testing.finding import SSRF, Finding
from app.testing.transport import OutOfScope, capture_exchange, scoped_request


class SsrfTestTool(BaseTool):
    name = "runtime.test.ssrf"
    description = (
        "Prove SSRF via the platform loopback canary only. Injects the canary URL "
        "into candidate URL parameters and confirms on a canary hit. "
        "Requires aggressive intensity and a live canary."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "targets": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "format": "uri"},
                        "method": {"type": "string", "default": "GET"},
                        "params": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "location": {"type": "string", "enum": ["query", "form"], "default": "query"},
                    },
                    "required": ["url", "params"],
                },
            },
            "payload_id": {
                "type": "string",
                "enum": ["ssrf.canary"],
                "default": "ssrf.canary",
            },
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 5.0},
        },
        "required": ["targets"],
    }
    permissions = ("runtime:test:ssrf", "runtime:http:get")
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("ssrf_validation",)
    payload_fields = ("payload_id",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        canary = getattr(context, "canary", None)
        if canary is None:
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error="SSRF testing requires a live local canary in context",
            )

        payload_id = str(args.get("payload_id") or "ssrf.canary")
        payload = get_payload_catalog().require(payload_id)
        canary_value = canary.base_url
        targets = args.get("targets") or []
        timeout = float(args.get("timeout", 5.0))

        findings: list[dict[str, Any]] = []
        requests_sent = 0
        for target in targets:
            url = str(target.get("url", ""))
            method = str(target.get("method", "GET")).upper()
            location = str(target.get("location", "query"))
            params = [str(p) for p in (target.get("params") or [])]
            if not url or not params:
                continue

            for param in params:
                before = len(canary.hits())
                values = {p: "1" for p in params}
                values[param] = canary_value
                exchange = await self._send(method, url, values, location, context, timeout)
                if exchange is None:
                    continue
                requests_sent += 1
                hit = await self._wait_for_new_hit(canary, before)
                if hit is None:
                    continue
                findings.append(
                    Finding(
                        title=f"Server-side request forgery via parameter {param!r}",
                        category=SSRF,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        endpoint=f"{method} {url}",
                        summary=(
                            f"Injecting the canary URL into `{param}` caused a server-side "
                            "fetch that reached the AEGIS loopback canary."
                        ),
                        remediation="Validate/allow-list outbound destinations; never fetch user-supplied URLs server-side.",
                        evidence={
                            "parameter": param,
                            "location": location,
                            "canary_hit": ssrf.hit_evidence(hit),
                            "http": exchange,
                        },
                        payload_id=payload.id,
                        cwe="CWE-918",
                        detector="ssrf.canary",
                    ).as_dict()
                )

        return ToolResult(
            status=ToolResultStatus.SUCCESS,
            output={
                "findings": findings,
                "finding_count": len(findings),
                "requests_sent": requests_sent,
            },
        )

    async def _send(self, method, url, values, location, context, timeout):
        try:
            start = time.monotonic()
            if location == "form":
                resp = await scoped_request(
                    method if method != "GET" else "POST", url,
                    context=context, timeout=timeout, data=values,
                )
            else:
                resp = await scoped_request(method, url, context=context, timeout=timeout, params=values)
            elapsed_ms = (time.monotonic() - start) * 1000.0
            return capture_exchange(
                method=method, url=url, response=resp, elapsed_ms=elapsed_ms,
                params=values if location == "query" else None,
                data=values if location == "form" else None,
            )
        except OutOfScope:
            return None
        except Exception:
            return None

    @staticmethod
    async def _wait_for_new_hit(canary, before_count: int, timeout: float = 1.5):
        deadline = timeout
        step = 0.05
        while deadline > 0:
            hits = canary.hits()
            if len(hits) > before_count:
                return hits[before_count]
            await asyncio.sleep(step)
            deadline -= step
        return None
