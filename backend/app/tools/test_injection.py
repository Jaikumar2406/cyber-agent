"""runtime.test.injection - injection module (phases.md §1.5, §1.6).

For each target parameter it sends every requested controlled payload (resolved
from the bundled catalog - rules.md §3.8), comparing against a baseline request,
and emits a finding only when a deterministic detector fires. Payload ids are
validated by the Policy Guard before execution (``payload_fields``). Findings
carry the full redacted HTTP exchange (baseline + injected) per §1.6.
"""

import time
from typing import Any

from app.control_plane.payloads import get_payload_catalog
from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import Severity, ToolResultStatus
from app.testing import injection
from app.testing.finding import INJECTION, Finding
from app.testing.transport import OutOfScope, capture_exchange, scoped_request

_PAYLOAD_SEVERITY: dict[str, str] = {
    "sqli": Severity.HIGH,
    "cmdi": Severity.HIGH,
    "ssti": Severity.HIGH,
    "xss": Severity.MEDIUM,
}

_BASELINE_VALUE = "1"


class InjectionTestTool(BaseTool):
    name = "runtime.test.injection"
    description = (
        "Test parameters for SQL/command/template/reflected-XSS injection using "
        "controlled, non-destructive payloads. Requires active+ intensity."
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
            "payload_ids": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "description": "Controlled payload ids from the bundled catalog",
            },
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 5.0},
        },
        "required": ["targets", "payload_ids"],
    }
    permissions = ("runtime:test:injection", "runtime:http:get", "runtime:http:post")
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("injection",)
    payload_fields = ("payload_ids",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        targets = args.get("targets") or []
        payload_ids = [str(p) for p in (args.get("payload_ids") or [])]
        timeout = float(args.get("timeout", 5.0))

        catalog = get_payload_catalog()
        payloads = []
        for pid in payload_ids:
            payload = catalog.by_id(pid)
            if payload is not None and payload.category in _PAYLOAD_SEVERITY:
                payloads.append(payload)

        findings: list[dict[str, Any]] = []
        requests_sent = 0
        for target in targets:
            url = str(target.get("url", ""))
            method = str(target.get("method", "GET")).upper()
            params = [str(p) for p in (target.get("params") or [])]
            location = str(target.get("location", "query"))
            if not url or not params:
                continue

            baseline_values = {p: _BASELINE_VALUE for p in params}
            baseline = await self._send(method, url, baseline_values, location, context, timeout)
            if baseline is None:
                continue
            requests_sent += 1
            base_status, base_body, base_ms, base_exchange = baseline

            for payload in payloads:
                for param in params:
                    injected_values = {p: _BASELINE_VALUE for p in params}
                    injected_values[param] = payload.value
                    injected = await self._send(method, url, injected_values, location, context, timeout)
                    if injected is None:
                        continue
                    requests_sent += 1
                    inj_status, inj_body, inj_ms, inj_exchange = injected
                    detection = injection.detect(
                        payload=payload,
                        baseline_body=base_body,
                        injected_body=inj_body,
                        baseline_status=base_status,
                        injected_status=inj_status,
                        baseline_ms=base_ms,
                        injected_ms=inj_ms,
                    )
                    if not detection.hit:
                        continue
                    findings.append(
                        Finding(
                            title=f"Potential {payload.category.upper()} injection in parameter {param!r}",
                            category=INJECTION,
                            severity=_PAYLOAD_SEVERITY.get(payload.category, Severity.MEDIUM),
                            confidence=detection.confidence,
                            endpoint=f"{method} {url}",
                            summary=(
                                f"Payload {payload.id} triggered a {detection.detail.get('signal')} "
                                f"signal on parameter `{param}`."
                            ),
                            remediation=(
                                "Use parameterized queries / safe APIs, avoid shell invocation, "
                                "and context-aware output encoding."
                            ),
                            evidence={
                                "parameter": param,
                                "location": location,
                                "detection": detection.as_dict(),
                                "baseline_status": base_status,
                                "injected_status": inj_status,
                                "payload_description": payload.description,
                                "http": {
                                    "baseline": base_exchange,
                                    "injected": inj_exchange,
                                },
                            },
                            payload_id=payload.id,
                            cwe="CWE-74",
                            detector=f"injection.{payload.category}",
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
                resp = await scoped_request(
                    method, url, context=context, timeout=timeout, params=values,
                )
            elapsed_ms = (time.monotonic() - start) * 1000.0
            exchange = capture_exchange(
                method=method, url=url, response=resp, elapsed_ms=elapsed_ms,
                params=values if location == "query" else None,
                data=values if location == "form" else None,
            )
            return resp.status_code, resp.text, elapsed_ms, exchange
        except OutOfScope:
            return None
        except Exception:
            return None
