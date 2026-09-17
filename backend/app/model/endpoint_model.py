"""EndpointModel — one record per unique endpoint in the target application.

Each record captures what the Application Model Builder (§1.4) observed about
the endpoint during discovery (§1.2), auth analysis (§1.3), and lightweight
HTTP sampling. Security test modules (§1.5) read these directly to plan their
injections and cross-user tests.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EndpointModel:
    """One endpoint's full attack-surface profile."""

    method: str  # "GET", "POST", ...
    url: str  # absolute URL — unique composite key together with method
    path: str  # URL path portion (for grouping / param extraction)

    # --- discovery provenance --------------------------------------------------
    source: str  # "crawl" | "openapi" | "browser" | "combined"
    depth: int | None  # crawl depth at discovery (None if from spec)
    found_in: str | None  # URL that linked to this endpoint

    # --- observed response (from lightweight sampling in the tool) -----------
    status_code: int | None = None
    content_type: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)

    # --- request parameters ----------------------------------------------------
    query_params: tuple[str, ...] = ()
    path_params: tuple[str, ...] = ()
    body_media_type: str | None = None
    form_fields: tuple[str, ...] = ()  # HTML form input names if discovered via crawl

    # --- auth classification ---------------------------------------------------
    auth_required: bool = False
    protected_by: str | None = None  # "jwt" | "cookie" | "basic" | "bearer" | "api_key" | None

    # --- cookie / header observations ------------------------------------------
    set_cookie_names: tuple[str, ...] = ()

    # --- navigation links out (from crawler) -----------------------------------
    links_out: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "path": self.path,
            "source": self.source,
            "depth": self.depth,
            "found_in": self.found_in,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "query_params": list(self.query_params),
            "path_params": list(self.path_params),
            "body_media_type": self.body_media_type,
            "form_fields": list(self.form_fields),
            "auth_required": self.auth_required,
            "protected_by": self.protected_by,
            "set_cookie_names": list(self.set_cookie_names),
            "links_out": list(self.links_out),
        }