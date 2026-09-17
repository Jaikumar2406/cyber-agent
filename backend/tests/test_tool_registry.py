"""Tool Registry unit tests."""

import pytest

from app.harness.tool_registry import (
    ToolArgumentError,
    ToolNotFoundError,
    ToolRegistrationError,
    ToolRegistry,
)
from app.harness.tools import BaseTool, ToolResult
from app.schemas.common import ToolResultStatus


class PingTool(BaseTool):
    name = "ping.test"
    description = "test tool"
    input_schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    }
    permissions = ("ping:test",)

    async def run(self, args, context):
        return ToolResult(status=ToolResultStatus.SUCCESS, output={"name": args["name"]})


@pytest.fixture
def registry():
    return ToolRegistry()


def test_register_and_get(registry):
    registry.register(PingTool())
    assert registry.get("ping.test").name == "ping.test"


def test_duplicate_registration_rejected(registry):
    registry.register(PingTool())
    with pytest.raises(ToolRegistrationError):
        registry.register(PingTool())


def test_invalid_schema_rejected(registry):
    class BadTool(PingTool):
        input_schema = {"type": "nope"}

    with pytest.raises(ToolRegistrationError):
        registry.register(BadTool())


def test_unknown_tool_raises(registry):
    with pytest.raises(ToolNotFoundError):
        registry.get("does.not.exist")


def test_args_validated(registry):
    registry.register(PingTool())
    registry.validate_args("ping.test", {"name": "alice"})
    with pytest.raises(ToolArgumentError):
        registry.validate_args("ping.test", {})


def test_list_tools_shape(registry):
    registry.register(PingTool())
    listing = registry.list_tools()
    assert listing[0]["name"] == "ping.test"
    assert "input_schema" in listing[0]
    assert listing[0]["permissions"] == ["ping:test"]


def test_default_registry_has_echo():
    from app.harness.tool_registry import get_tool_registry

    assert get_tool_registry().has("echo")