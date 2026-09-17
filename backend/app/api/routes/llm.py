"""Offline LLM status introspection (phases.md §1.9).

Lets an operator confirm whether the local planning-annotation model (e.g. a
Qwen3-4B Q4_K_M GGUF) is present and active. The LLM is annotate-only and
never decides anything, so this is purely informational.
"""

from fastapi import APIRouter, Depends

from app.control_plane.auth import require_api_key
from app.planner.llm import get_llm_annotator

router = APIRouter(prefix="/llm", tags=["llm"], dependencies=[Depends(require_api_key)])


@router.get("/status")
async def llm_status() -> dict:
    return get_llm_annotator().describe()