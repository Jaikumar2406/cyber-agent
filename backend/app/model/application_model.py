"""ApplicationModel — the complete attack-surface map of a target application.

Aggregates all `EndpointModel` records and surfaces the top-level summary
metadata that 1.5 security test modules need without scanning every record:
which endpoints are login endpoints, which are auth-protected, which are public.
"""

from dataclasses import dataclass, field
from typing import Any

from app.model.endpoint_model import EndpointModel


@dataclass
class ApplicationModel:
    """Collection of endpoint records plus application-wide metadata."""

    endpoints: list[EndpointModel] = field(default_factory=list)
    login_endpoints: list[str] = field(default_factory=list)  # absolute URLs
    auth_mechanism_summary: dict[str, Any] = field(default_factory=dict)
    total_endpoints: int = 0
    discovered_at: str | None = None  # ISO timestamp of the scan

    def add(self, endpoint: EndpointModel) -> None:
        self.endpoints.append(endpoint)
        self.total_endpoints = len(self.endpoints)

    def get(self, url: str, method: str = "GET") -> EndpointModel | None:
        for ep in self.endpoints:
            if ep.url == url and ep.method == method.upper():
                return ep
        return None

    def by_method(self, method: str) -> list[EndpointModel]:
        return [ep for ep in self.endpoints if ep.method == method.upper()]

    def protected_endpoints(self) -> list[EndpointModel]:
        return [ep for ep in self.endpoints if ep.auth_required]

    def public_endpoints(self) -> list[EndpointModel]:
        return [ep for ep in self.endpoints if not ep.auth_required]

    def as_dict(self) -> dict[str, Any]:
        return {
            "endpoints": [ep.as_dict() for ep in self.endpoints],
            "login_endpoints": list(self.login_endpoints),
            "auth_mechanism_summary": dict(self.auth_mechanism_summary),
            "total_endpoints": self.total_endpoints,
            "discovered_at": self.discovered_at,
            "protected_endpoints": [ep.as_dict() for ep in self.protected_endpoints()],
            "public_endpoints": [ep.as_dict() for ep in self.public_endpoints()],
        }