"""Unit tests for discovery logic (phases.md §1.2).

Covers link extraction, crawler behavior (caps, same-host enforcement, dedup,
forms), and offline OpenAPI/Swagger parsing. No network required.
"""

import pytest

from app.discovery.crawler import Crawler, CrawlerConfig, DiscoveryFetchError
from app.discovery.link_extractor import extract_forms, extract_links, is_same_host
from app.discovery.models import CrawlResult
from app.discovery.openapi_parser import (
    OpenApiParseError,
    parse_openapi_spec,
    spec_urls_for_base,
)


# ---------------------------------------------------------------- extractors

def test_extract_links_absolute_and_relative():
    html = """
      <a href="/about">About</a>
      <a href="https://cdn.example.com/x.js">cdn</a>
      <a href="#frag">frag</a>
      <a href="mailto:x@example.com">mail</a>
      <a href="javascript:void(0)">js</a>
      <link rel="stylesheet" href="/static/app.css">
      <script src="/app.js"></script>
    """
    links = extract_links(html, "https://example.com/home")
    assert "https://example.com/about" in links
    assert "https://example.com/app.js" in links
    assert "https://example.com/static/app.css" in links
    assert "https://cdn.example.com/x.js" in links
    assert not any("mailto" in l for l in links)
    assert not any("javascript" in l for l in links)


def test_extract_forms_captures_method():
    html = '<form action="/login" method="post">...</form><form action="/search"></form>'
    forms = extract_forms(html, "https://example.com/")
    assert ("https://example.com/login", "POST") in forms
    assert ("https://example.com/search", "GET") in forms


def test_is_same_host_ignores_port_and_case():
    assert is_same_host("https://Example.com:443/a", "https://example.com/b")
    assert not is_same_host("https://example.com/a", "https://other.com/b")


# ------------------------------------------------------------------- crawler

class _FakeFetch:
    """Deterministic page map robot for the crawler."""

    def __init__(self, pages: dict[str, tuple[str, str | None]], bounce: set[str] | None = None):
        self.pages = pages
        self.bounce = bounce or set()
        self.hits: list[str] = []

    async def __call__(self, url: str) -> tuple[str | None, str | None]:
        self.hits.append(url)
        if url in self.bounce:
            return None, None  # out-of-scope bounce
        if url in self.pages:
            final, body = self.pages[url]
            return final, body
        raise DiscoveryFetchError("http request failed: 404")


async def test_crawler_follows_same_host_links_only():
    pages = {
        "https://example.com/": ("https://example.com/", '<a href="/about">x</a><a href="https://evil.net/xx">evil</a>'),
        "https://example.com/about": ("https://example.com/about", "<p>hi</p>"),
    }
    fetch = _FakeFetch(pages)
    crawler = Crawler(config=CrawlerConfig(max_pages=10, max_depth=3), fetch=fetch)
    result: CrawlResult = await crawler.crawl("https://example.com/")
    assert result.stats.pages_fetched == 2
    paths = {e.path for e in result.endpoints}
    assert "/" in paths and "/about" in paths
    # never touched the offsite host
    assert not any("evil.net" in h for h in fetch.hits)
    assert not any("evil.net" in e.found_in for e in result.endpoints)


async def test_crawler_page_cap_respected():
    pages = {
        f"https://example.com/p{i}": (f"https://example.com/p{i}", f'<a href="/p{(i + 1) % 5}">next</a>')
        for i in range(5)
    }
    fetch = _FakeFetch(pages)
    crawler = Crawler(config=CrawlerConfig(max_pages=3, max_depth=5), fetch=fetch)
    result = await crawler.crawl("https://example.com/p0")
    assert result.stats.pages_fetched == 3
    assert result.stats.page_cap_reached


async def test_crawler_bounces_out_of_scope():
    fetch = _FakeFetch({}, bounce={"https://example.com/"})
    crawler = Crawler(config=CrawlerConfig(max_pages=5, max_depth=2), fetch=fetch)
    result = await crawler.crawl("https://example.com/")
    assert result.stats.pages_fetched == 0
    assert result.stats.out_of_scope_bounced == 1
    assert [e.source for e in result.endpoints] == []


async def test_crawler_records_form_endpoints():
    pages = {
        "https://example.com/": ("https://example.com/", '<form action="/login" method="post"></form>'),
    }
    crawler = Crawler(config=CrawlerConfig(max_pages=5, max_depth=2, include_forms=True), fetch=_FakeFetch(pages))
    result = await crawler.crawl("https://example.com/")
    assert any(e.method == "POST" and e.path == "/login" for e in result.endpoints)


async def test_crawler_out_of_scope_fetch_raises_propagated():
    pages = {
        "https://example.com/": ("https://example.com/", '<a href="/x">x</a>'),
    }

    async def strict_fetch(url: str) -> tuple[str, str | None]:
        if url != "https://example.com/":
            raise DiscoveryFetchError("http request failed: connection refused")
        return pages[url]

    crawler = Crawler(config=CrawlerConfig(max_pages=5, max_depth=2), fetch=strict_fetch)
    result = await crawler.crawl("https://example.com/")
    assert result.stats.pages_fetched == 1  # other pages fail cleanly, crawl survives


# ---------------------------------------------------------------- openapi

OPENAPI_3 = """{
  "openapi": "3.0.0",
  "info": {"title": "t", "version": "1.0"},
  "paths": {
    "/users": {
      "get": {"summary": "list", "parameters": [{"name": "role", "in": "query"}]},
      "post": {"summary": "create", "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}}
    },
    "/users/{id}": {
      "parameters": [{"name": "id", "in": "path", "required": true}],
      "delete": {"summary": "remove"}
    }
  }
}"""


def test_parse_openapi3():
    endpoints = parse_openapi_spec(OPENAPI_3, found_in="https://example.com/openapi.json")
    idx = {(e.method, e.path): e for e in endpoints}
    assert ("GET", "/users") in idx
    assert ("POST", "/users") in idx
    assert ("DELETE", "/users/{id}") in idx
    get_users = idx[("GET", "/users")]
    assert get_users.query_params == ("role",)
    assert get_users.body_media_type is None
    post_users = idx[("POST", "/users")]
    assert post_users.body_media_type == "application/json"


SWAGGER_2 = """{
  "swagger": "2.0",
  "info": {"title": "t", "version": "2"},
  "paths": {
    "/health": {"get": {"summary": "health"}}
  }
}"""


def test_parse_swagger2():
    endpoints = parse_openapi_spec(SWAGGER_2)
    assert [e.as_dict()["path"] for e in endpoints if e.method == "GET"] == ["/health"]


def test_parse_rejects_non_spec():
    with pytest.raises(OpenApiParseError):
        parse_openapi_spec("<html>no spec here</html>")


def test_parse_empty_paths_map():
    assert parse_openapi_spec('{"openapi": "3.0.0", "paths": {}}') == []


def test_spec_urls_for_base():
    urls = spec_urls_for_base("https://example.com/api")
    assert urls[0] == "https://example.com/api/openapi.json"
    assert all(u.startswith("https://example.com/api/") for u in urls)