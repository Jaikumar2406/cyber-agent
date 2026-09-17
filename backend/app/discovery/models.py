"""Discovery data models (phases.md §1.2).

`DiscoveredEndpoint` is the single normalized unit every discovery source emits,
so the Application Model Builder (§1.4) and security test modules (§1.5) consume
one shape regardless of where an endpoint came from.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DiscoveredEndpoint:
    method: str
    path: str
    source: str  # "crawl" | "openapi" | "browser"
    found_in: str | None  # the URL the endpoint was discovered from (or spec description)
    query_params: tuple[str, ...] = ()
    body_media_type: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "source": self.source,
            "found_in": self.found_in,
            "query_params": list(self.query_params),
            "body_media_type": self.body_media_type,
            "extra": self.extra,
        }


@dataclass(frozen=True)
class CrawlerStats:
    pages_fetched: int
    requests_made: int
    out_of_scope_bounced: int
    duplicates_skipped: int
    max_depth_reached: bool
    page_cap_reached: bool
    total_depth: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "pages_fetched": self.pages_fetched,
            "requests_made": self.requests_made,
            "out_of_scope_bounced": self.out_of_scope_bounced,
            "duplicates_skipped": self.duplicates_skipped,
            "max_depth_reached": self.max_depth_reached,
            "page_cap_reached": self.page_cap_reached,
            "total_depth": self.total_depth,
        }


@dataclass(frozen=True)
class CrawlResult:
    seed_url: str
    endpoints: tuple[DiscoveredEndpoint, ...]
    stats: CrawlerStats

    def as_dict(self) -> dict[str, Any]:
        return {
            "seed_url": self.seed_url,
            "endpoints": [e.as_dict() for e in self.endpoints],
            "stats": self.stats.as_dict(),
        }