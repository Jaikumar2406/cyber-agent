"""Health endpoints (liveness/readiness)."""

from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.api.deps import db_session
from app.schemas.scan import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health/live", response_model=HealthResponse)
async def live() -> HealthResponse:
    return HealthResponse(status="ok", services={"api": "up"})


@router.get("/health/ready", response_model=HealthResponse)
async def ready(session=Depends(db_session)) -> HealthResponse:
    db_status = "up"
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        db_status = "down"
    return HealthResponse(status="ok" if db_status == "up" else "degraded", services={"db": db_status})