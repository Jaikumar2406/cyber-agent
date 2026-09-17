"""Shared test fixtures.

Phase 0 tests run fully offline against a file-based SQLite backend - no
Docker, no PostgreSQL, no network required. Env is set here BEFORE any app
module is imported so the (cached) Settings singleton reads test values.
"""

import os
import tempfile
from pathlib import Path

# --- Test environment (must precede app imports) ---------------------------
_TMP = Path(tempfile.mkdtemp(prefix="aegis_test_"))
os.environ["AEGIS_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMP / 'test_aegis.db'}"
os.environ["AEGIS_REDIS_URL"] = "redis://localhost:6379/15"
os.environ["AEGIS_ENVIRONMENT"] = "test"
os.environ["AEGIS_API_KEY"] = "test-key"
os.environ["AEGIS_SANDBOX_MODE"] = "process"
os.environ["AEGIS_ALLOWED_TARGETS"] = "example.com,localhost,127.0.0.1"
os.environ["AEGIS_MAX_TOOL_TIMEOUT_SECONDS"] = "60"

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.db import dispose_db, get_session_factory, get_session
from app.main import app


@pytest.fixture(scope="session", autouse=True)
async def db_tables():
    """Create the schema once per test session in the file-based sqlite DB."""
    from app.core.db import init_db

    await init_db()
    yield
    await dispose_db()
    get_settings.cache_clear()


@pytest.fixture
async def session() -> AsyncSession:
    factory = get_session_factory()
    async with factory() as s:
        yield s


@pytest.fixture
def session_factory():
    # The async_sessionmaker itself: calling it with no args yields an
    # AsyncSession context manager - exactly what the managers expect.
    return get_session_factory()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def api_headers():
    return {"X-AEGIS-Key": "test-key"}


@pytest.fixture
def settings():
    return get_settings()