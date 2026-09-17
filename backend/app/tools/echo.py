"""Phase 0 probe tool - the 'echo' that exercises the full harness path.

Registered, permission-checked, sandboxed, budgeted, retried, audited,
and evidence-producing. Purpose: prove Phase 0's exit criterion #1 end-to-end
with zero security logic.
"""

from typing import Any

from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import ToolResultStatus


class EchoTool(BaseTool):
    name = "echo"
    description = "Phase 0 probe: echoes arguments back, optionally after a delay; no-op security probe."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "text": {"type": "string", "default": ""},
            "iterations": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 1},
            "delay_ms": {"type": "number", "minimum": 0, "maximum": 30000, "default": 0},
        },
        "required": [],
    }
    permissions: tuple[str, ...] = ()  # pure probe: no capabilities required
    sandbox = SandboxSpec(mode="process")

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        import asyncio

        delay_ms = float(args.get("delay_ms", 0))
        iterations = int(args.get("iterations", 1))
        text = str(args.get("text", ""))

        if delay_ms > 0 and iterations > 1:
            for i in range(iterations):
                await asyncio.sleep(delay_ms / 1000.0)
                seq = i + 1
        elif delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)
            seq = iterations
        else:
            seq = iterations

        return ToolResult(
            status=ToolResultStatus.SUCCESS,
            output={
                "echo": text,
                "iterations": iterations,
                "final_sequence": seq,
                "scan_id": context.scan_id,
                "recipient": context.principal,
            },
        )