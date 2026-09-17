"""Control Plane - authentication.

Phase 0 is single-tenant: the operator presents the platform API key
(`AEGIS_API_KEY`) in the `X-AEGIS-Key` header. Nothing is sent or stored
externally; the value lives in environment/config only.
"""

import secrets
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from app.core.config import get_settings

API_KEY_HEADER = "X-AEGIS-Key"


@dataclass(frozen=True)
class Principal:
    """The authenticated actor initiating a request / scan."""

    username: str


def _verify_key(provided: str | None) -> bool:
    settings = get_settings()
    if not provided:
        return False
    return secrets.compare_digest(provided, settings.api_key)


async def require_api_key(x_aegis_key: str | None = Header(default=None)) -> Principal:
    if not _verify_key(x_aegis_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-AEGIS-Key",
        )
    return Principal(username=get_settings().default_user)