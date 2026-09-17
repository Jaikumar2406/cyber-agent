"""Phase 1.4 — unit tests for Application Model Builder (pure, no network).

Tests EndpointModel, ApplicationModel, and the pure build_application_model
function using only in-memory data.
"""

import pytest

from app.discovery.models import CrawlerStats, DiscoveredEndpoint
from app.model.application_model import ApplicationModel
from app.model.builder import (
    _extract_login_urls,
    _index_openapi_params,
    _merge_endpoints,
    _strongest_mechanism,
    build_application_model,
)
from app.model.endpoint_model import EndpointModel


# ---------------------------------------------------------------------------
# EndpointModel
# ---------------------------------------------------------------------------

class TestEndpointModel:
    def test_as_dict_roundtrip(self):
        ep = EndpointModel(
            method="POST", url="http://app/login", path="/login",
            source="crawl", depth=1, found_in="http://app/",
            status_code=200, content_type="text/html",
            query_params=("q",), body_media_type="application/json",
            auth_required=False, protected_by=None,
        )
        d = ep.as_dict()
        assert d["method"] == "POST"
        assert d["url"] == "http://app/login"
        assert d["query_params"] == ["q"]
        assert d["auth_required"] is False

    def test_frozen(self):
        ep = EndpointModel(method="GET", url="http://x/", path="/",
                           source="crawl", depth=0, found_in=None)
        with pytest.raises(AttributeError):
            ep.method = "POST"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ApplicationModel
# ---------------------------------------------------------------------------

class TestApplicationModel:
    def _make_ep(self, path, method="GET", auth_required=False, protected_by=None):
        return EndpointModel(
            method=method, url=f"http://app{path}", path=path,
            source="crawl", depth=0, found_in=None,
            auth_required=auth_required, protected_by=protected_by,
        )

    def test_add_and_count(self):
        model = ApplicationModel()
        model.add(self._make_ep("/"))
        model.add(self._make_ep("/admin", auth_required=True, protected_by="jwt"))
        assert model.total_endpoints == 2
        assert len(model.protected_endpoints()) == 1
        assert len(model.public_endpoints()) == 1

    def test_get_by_url_and_method(self):
        model = ApplicationModel()
        ep = self._make_ep("/users", method="POST")
        model.add(ep)
        assert model.get("http://app/users", "POST") is ep
        assert model.get("http://app/users", "GET") is None
        assert model.get("http://app/other", "POST") is None

    def test_by_method(self):
        model = ApplicationModel()
        model.add(self._make_ep("/a", method="GET"))
        model.add(self._make_ep("/b", method="POST"))
        model.add(self._make_ep("/c", method="GET"))
        assert len(model.by_method("GET")) == 2

    def test_as_dict_keys(self):
        model = ApplicationModel()
        model.add(self._make_ep("/"))
        d = model.as_dict()
        assert "endpoints" in d
        assert "protected_endpoints" in d
        assert "public_endpoints" in d
        assert "login_endpoints" in d
        assert "total_endpoints" in d


# ---------------------------------------------------------------------------
# _merge_endpoints
# ---------------------------------------------------------------------------

class TestMergeEndpoints:
    def test_merge_preserves_richer_source(self):
        ep1 = DiscoveredEndpoint(method="GET", path="/api", source="crawl",
                                  found_in="http://app/", query_params=("q",))
        ep2 = DiscoveredEndpoint(method="GET", path="/api", source="openapi",
                                  found_in=None, query_params=("q", "page"))
        merged = _merge_endpoints([ep1, ep2])
        # OpenAPI should win for query params
        assert merged[("GET", "/api")].query_params == ("q", "page")

    def test_merge_deduplicates(self):
        ep1 = DiscoveredEndpoint(method="GET", path="/", source="crawl", found_in=None)
        ep2 = DiscoveredEndpoint(method="GET", path="/", source="crawl", found_in=None)
        merged = _merge_endpoints([ep1, ep2])
        assert len(merged) == 1


# ---------------------------------------------------------------------------
# _strongest_mechanism
# ---------------------------------------------------------------------------

class TestStrongestMechanism:
    def test_jwt_beats_cookie(self):
        mechanisms = [
            {"kind": "cookie", "confidence": "CONFIRMED"},
            {"kind": "jwt", "confidence": "PROBABLE"},
        ]
        assert _strongest_mechanism(mechanisms) == "jwt"

    def test_empty_returns_none(self):
        assert _strongest_mechanism([]) is None

    def test_single_mechanism(self):
        assert _strongest_mechanism([{"kind": "basic"}]) == "basic"

    def test_credentials_maps_to_cookie(self):
        assert _strongest_mechanism([{"kind": "credentials"}]) == "cookie"


# ---------------------------------------------------------------------------
# _extract_login_urls
# ---------------------------------------------------------------------------

class TestExtractLoginUrls:
    def test_extracts_from_candidate_endpoints(self):
        auth = {
            "candidate_login_endpoints": {
                "form_actions": ["http://app/login"],
                "auth_links": ["http://app/oauth/authorize"],
            }
        }
        urls = _extract_login_urls(auth)
        assert "http://app/login" in urls
        assert "http://app/oauth/authorize" in urls

    def test_empty_analysis(self):
        assert _extract_login_urls({}) == []


# ---------------------------------------------------------------------------
# _index_openapi_params
# ---------------------------------------------------------------------------

class TestIndexOpenapiParams:
    def test_indexes_query_and_path_params(self):
        doc = {
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path"},
                            {"name": "fields", "in": "query"},
                        ],
                        "requestBody": {"content": {"application/json": {}}},
                    }
                }
            }
        }
        index = _index_openapi_params(doc)
        assert "/users/{id}" in index
        assert "id" in index["/users/{id}"]["path_params"]
        assert "fields" in index["/users/{id}"]["query_params"]
        assert index["/users/{id}"]["body_media_type"] == "application/json"

    def test_empty_doc(self):
        assert _index_openapi_params(None) == {}
        assert _index_openapi_params({}) == {}


# ---------------------------------------------------------------------------
# build_application_model (pure, offline)
# ---------------------------------------------------------------------------

class TestBuildApplicationModel:
    def _endpoints(self):
        return [
            DiscoveredEndpoint(method="GET", path="/", source="crawl", found_in=None),
            DiscoveredEndpoint(method="GET", path="/login", source="crawl", found_in="http://app/"),
            DiscoveredEndpoint(method="POST", path="/login", source="crawl", found_in="http://app/"),
            DiscoveredEndpoint(method="GET", path="/api/users", source="openapi", found_in=None),
            DiscoveredEndpoint(method="POST", path="/api/users", source="openapi", found_in=None),
        ]

    def test_basic_build(self):
        model = build_application_model(self._endpoints())
        assert model.total_endpoints == 5
        # Without auth analysis, all are public
        assert len(model.public_endpoints()) == 5
        assert len(model.protected_endpoints()) == 0

    def test_with_auth_analysis(self):
        auth = {
            "mechanisms": [{"kind": "jwt", "confidence": "CONFIRMED", "sources": ["header"]}],
            "candidate_login_endpoints": {"form_actions": ["http://app/login"], "auth_links": []},
        }
        model = build_application_model(self._endpoints(), auth_analysis=auth)
        # / and /login should be public; /api/users should be protected
        protected = {ep.path for ep in model.protected_endpoints()}
        assert "/api/users" in protected
        public = {ep.path for ep in model.public_endpoints()}
        assert "/" in public
        assert "/login" in public
        assert "http://app/login" in model.login_endpoints

    def test_with_openapi_params(self):
        doc = {
            "paths": {
                "/api/users": {
                    "get": {"parameters": [{"name": "page", "in": "query"}]}
                }
            }
        }
        model = build_application_model(self._endpoints(), openapi_doc=doc, base_url="http://app")
        ep = model.get("http://app/api/users", "GET")
        assert ep is not None
        assert "page" in ep.query_params

    def test_with_http_samples(self):
        samples = {
            ("GET", "http://app/"): {
                "status_code": 200,
                "content_type": "text/html",
                "set_cookie_names": ["session"],
            }
        }
        model = build_application_model(self._endpoints(), http_samples=samples, base_url="http://app")
        ep = model.get("http://app/", "GET")
        assert ep.status_code == 200
        assert "session" in ep.set_cookie_names

    def test_protected_by_strongest(self):
        auth = {
            "mechanisms": [
                {"kind": "cookie", "confidence": "CONFIRMED"},
                {"kind": "jwt", "confidence": "PROBABLE"},
            ],
        }
        endpoints = [DiscoveredEndpoint(method="GET", path="/api/data", source="crawl", found_in=None)]
        model = build_application_model(endpoints, auth_analysis=auth, base_url="http://app")
        ep = model.get("http://app/api/data", "GET")
        assert ep.auth_required is True
        assert ep.protected_by == "jwt"

    def test_as_dict_structure(self):
        model = build_application_model(self._endpoints())
        d = model.as_dict()
        assert "endpoints" in d
        assert "login_endpoints" in d
        assert "protected_endpoints" in d
        assert "public_endpoints" in d
        assert "auth_mechanism_summary" in d
        assert "total_endpoints" in d