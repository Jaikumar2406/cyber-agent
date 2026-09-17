"""Tool registry introspection.

Exposes registered tools (schemas/permissions) so operators and the future
Deep Agent can discover the exact subset of approved capabilities.
"""

from fastapi import APIRouter, Depends

from app.control_plane.auth import Principal, require_api_key
from app.harness.tool_registry import get_tool_registry
from app.schemas.scan import ToolInfoResponse

router = APIRouter(prefix="/tools", tags=["tools"], dependencies=[Depends(require_api_key)])


@router.get("", response_model=list[ToolInfoResponse])
async def list_tools() -> list[dict]:
    return get_tool_registry().list_tools()