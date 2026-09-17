"""Shared FastAPI dependencies."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_session


async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_session():
        yield session


class SessionCtx:
    """Adapts a request-scoped AsyncSession to the `async with SessionCtx(s)` 
    contract that State/Checkpoint/Audit/Evidence managers expect.

    Managers call `async with session_factory() as session:`. This wrapper lets
    them share the request's DB session without opening a new transaction.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def __aenter__(self) -> AsyncSession:
        return self._session

    async def __aexit__(self, *args) -> None:
        pass


def session_factory_from(session: AsyncSession):
    """Return a zero-argument callable producing a session context for the
    request-scoped session."""
    return lambda: SessionCtx(session)