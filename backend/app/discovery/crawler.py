"""Crawler (spider) engine - phases.md §1.2.

BFS over same-host pages up to a page cap and depth cap. Every fetched page is
recorded as a GET endpoint; `<form>` actions are recorded with their methods.
The fetch function is injected by the tool so this module stays offline-testable,
and the Scope & Policy Guard stays the single enforcement point (enforced in the
fetch callback, not re-implemented here).
"""

import urllib.parse
from collections import deque
from typing import Awaitable, Callable

from app.core.logging import get_logger
from app.discovery.link_extractor import extract_forms, extract_links, is_same_host
from app.discovery.models import CrawlResult, CrawlerStats, DiscoveredEndpoint

log = get_logger("aegis.discovery.crawler")

# A fetch callable: returns (final_url, body) on success, or (None, None) when
# the page was out of scope / could not be retrieved within scope. May raise
# DiscoveryFetchError for transient HTTP failures.
FetchFn = Callable[[str], Awaitable[tuple[str | None, str | None]]]


class DiscoveryFetchError(Exception):
    """Raised by a fetch function when a page could not be retrieved."""


class CrawlerConfig:
    def __init__(
        self,
        *,
        max_pages: int = 20,
        max_depth: int = 3,
        same_host_only: bool = True,
        include_forms: bool = True,
    ) -> None:
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.same_host_only = same_host_only
        self.include_forms = include_forms


class Crawler:
    def __init__(self, *, config: CrawlerConfig | None = None, fetch: FetchFn) -> None:
        self.config = config or CrawlerConfig()
        self.fetch = fetch

    async def crawl(self, seed_url: str) -> CrawlResult:
        pages_fetched = 0
        requests_made = 0
        out_of_scope_bounced = 0
        duplicates_skipped = 0
        max_depth_reached = False
        page_cap_reached = False
        total_depth = 0

        endpoints: list[DiscoveredEndpoint] = []
        visited: set[str] = set()

        queue: deque[tuple[str, int]] = deque([(seed_url, 0)])

        while queue and pages_fetched < self.config.max_pages:
            url, depth = queue.popleft()

            if url in visited:
                duplicates_skipped += 1
                continue
            visited.add(url)
            requests_made += 1

            try:
                final_url, body = await self.fetch(url)
            except DiscoveryFetchError as exc:
                log.info("crawler.fetch_failed", url=url, error=str(exc))
                if exc.args and exc.args[0].startswith("scope:"):
                    out_of_scope_bounced += 1
                continue

            if final_url is None:
                out_of_scope_bounced += 1
                continue

            # Every fetched page IS a discovered endpoint.
            path = urllib.parse.urlsplit(final_url).path or "/"
            query = urllib.parse.urlsplit(final_url).query
            query_params = tuple(sorted({k for k, _ in urllib.parse.parse_qsl(query)}))
            endpoints.append(
                DiscoveredEndpoint(
                    method="GET",
                    path=path,
                    source="crawl",
                    found_in=url,
                    query_params=query_params,
                )
            )
            pages_fetched += 1
            total_depth += depth
            max_depth_reached = max_depth_reached or depth >= self.config.max_depth

            if depth >= self.config.max_depth or pages_fetched >= self.config.max_pages:
                if pages_fetched >= self.config.max_pages:
                    page_cap_reached = True
                continue

            if body is None:
                continue

            if self.config.include_forms:
                for action, method in extract_forms(body, final_url):
                    action_path = urllib.parse.urlsplit(action).path or "/"
                    endpoints.append(
                        DiscoveredEndpoint(
                            method=method,
                            path=action_path,
                            source="crawl",
                            found_in=final_url,
                        )
                    )
                    if self._crawlable(action, depth, seed_url) and action not in visited:
                        queue.append((action, depth + 1))

            for link in extract_links(body, final_url):
                if not self._crawlable(link, depth, seed_url):
                    continue
                if link in visited or any(candidate == link for candidate, _ in queue):
                    duplicates_skipped += 1
                    continue
                queue.append((link, depth + 1))

        if pages_fetched >= self.config.max_pages:
            page_cap_reached = True

        log.info(
            "crawler.finished",
            seed_url=seed_url,
            pages_fetched=pages_fetched,
            endpoints=len(endpoints),
            bounce=out_of_scope_bounced,
        )

        stats = CrawlerStats(
            pages_fetched=pages_fetched,
            requests_made=requests_made,
            out_of_scope_bounced=out_of_scope_bounced,
            duplicates_skipped=duplicates_skipped,
            max_depth_reached=max_depth_reached,
            page_cap_reached=page_cap_reached,
            total_depth=total_depth,
        )
        return CrawlResult(seed_url=seed_url, endpoints=tuple(endpoints), stats=stats)

    def _crawlable(self, url: str, parent_depth: int, seed_url: str) -> bool:
        if url in ("", "#"):
            return False
        if self.config.same_host_only and not is_same_host(url, seed_url):
            return False
        if parent_depth + 1 > self.config.max_depth:
            return False
        return True