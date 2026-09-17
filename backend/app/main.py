"""AEGIS - Phase 0 FastAPI application (Control Plane + API Gateway skeleton)."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import audit, health, llm, reports, scans, tools
from app.core.config import get_settings
from app.core.db import init_db
from app.core.logging import get_logger

log = get_logger("aegis.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("startup.init_db")
    await init_db()
    log.info("startup.complete")
    yield


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="AEGIS Phase 0 - Control Plane + Agent Harness skeleton (offline/air-gapped).",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],  # React dev (frontend phase)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(tools.router)
app.include_router(llm.router)
app.include_router(scans.router)
app.include_router(audit.router)
app.include_router(reports.router)