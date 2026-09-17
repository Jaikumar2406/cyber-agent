"""Tool Registry (rules.md §6.1).

Schema-validated registration. Every tool execution originates here - there is
no dynamic/ad-hoc invocation path.
"""

import jsonschema
from typing import Any

from app.core.logging import get_logger
from app.harness.tools import BaseTool

log = get_logger("aegis.harness.tool_registry")


class ToolRegistrationError(Exception):
    pass


class ToolNotFoundError(Exception):
    pass


class ToolArgumentError(Exception):
    pass


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        if not tool.name:
            raise ToolRegistrationError("tool name must be non-empty")
        if tool.name in self._tools:
            raise ToolRegistrationError(f"tool {tool.name!r} already registered")
        self.validate_schema(tool.input_schema)
        self._tools[tool.name] = tool
        log.info("tool_registered", tool=tool.name, permissions=list(tool.permissions))

    def validate_schema(self, schema: dict[str, Any]) -> None:
        try:
            jsonschema.Draft202012Validator.check_schema(schema)
        except jsonschema.SchemaError as exc:
            raise ToolRegistrationError(f"invalid JSON schema: {exc}") from exc

    def get(self, name: str) -> BaseTool:
        if name not in self._tools:
            raise ToolNotFoundError(f"tool {name!r} is not registered")
        return self._tools[name]

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "permissions": list(t.permissions),
            }
            for t in sorted(self._tools.values(), key=lambda t: t.name)
        ]

    def validate_args(self, name: str, args: dict[str, Any]) -> None:
        tool = self.get(name)
        try:
            jsonschema.validate(instance=args, schema=tool.input_schema)
        except jsonschema.ValidationError as exc:
            raise ToolArgumentError(f"invalid args for {name!r}: {exc.message}") from exc

    def has(self, name: str) -> bool:
        return name in self._tools


_default_registry: ToolRegistry | None = None


def get_tool_registry() -> ToolRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = ToolRegistry()
        from app.tools.auth_analyze import AuthAnalyzeTool
        from app.tools.auth_login import AuthLoginTool
        from app.tools.crawl import CrawlTool
        from app.tools.echo import EchoTool
        from app.tools.http import HttpRequestTool
        from app.tools.model_build import ModelBuildTool
        from app.tools.openapi import OpenApiTool
        from app.tools.test_access_control import AccessControlTestTool
        from app.tools.test_auth_session import AuthSessionTestTool
        from app.tools.test_injection import InjectionTestTool
        from app.tools.test_misconfig import MisconfigTestTool
        from app.tools.test_nuclei import NucleiTestTool
        from app.tools.test_ssrf import SsrfTestTool

        _default_registry.register(EchoTool())
        _default_registry.register(HttpRequestTool())
        _default_registry.register(CrawlTool())
        _default_registry.register(OpenApiTool())
        _default_registry.register(AuthAnalyzeTool())
        _default_registry.register(AuthLoginTool())
        _default_registry.register(ModelBuildTool())
        _default_registry.register(MisconfigTestTool())
        _default_registry.register(AuthSessionTestTool())
        _default_registry.register(InjectionTestTool())
        _default_registry.register(AccessControlTestTool())
        _default_registry.register(SsrfTestTool())
        _default_registry.register(NucleiTestTool())
    return _default_registry