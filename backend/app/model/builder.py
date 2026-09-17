"""Pure Application Model Builder — no network calls.

Assembles an `ApplicationModel` from discovery endpoints, the auth analysis
summary, an optional raw OpenAPI document (for param extraction), and optional
HTTP samples (observed response data).  The network-dependent HTTP sampling is
done by the tool; this function only performs grouping, classification, and
model assembly.

The model is the single source of truth that 1.5 security test modules
consume to decide WHERE to inject, WHERE to test cross-user, and WHAT
parameter shapes to send.
"""

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

from app.core.logging import get_logger
from app.discovery.models import DiscoveredEndpoint
from app.model.application_model import ApplicationModel
from app.model.endpoint_model import EndpointModel

log = get_logger("aegis.model.builder")

# Paths that are very likely public (no auth required) in most web apps.
# Used to classify endpoints when auth mechanisms are detected but per-endpoint
# evidence is unavailable.
_PUBLIC_PATHS: frozenset[str] = frozenset({
    "/",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/login",
    "/register",
    "/signup",
    "/about",
    "/status",
    "/favicon.ico",
    "/robots.txt",
})

# Mechanism kind → effective protection label (strongest first).
_PROTECTION_MAP: dict[str, str] = {
    "jwt": "jwt",
    "basic": "basic",
    "api_key": "api_key",
    "cookie": "cookie",
    "credentials": "cookie",  # password form implies session/cookie auth
    "oauth": "oauth",
}

# Strength ordering for selecting the strongest mechanism.
_MECH_STRENGTH: dict[str, int] = {
    "jwt": 5,
    "basic": 4,
    "api_key": 3,
    "oauth": 2,  # OAuth redirects → cookie or JWT at landing
    "cookie": 1,
    "credentials": 0,
}


def build_application_model(
    discovered_endpoints: list[DiscoveredEndpoint] | tuple[DiscoveredEndpoint, ...],
    auth_analysis: dict[str, Any] | None = None,
    openapi_doc: dict[str, Any] | None = None,
    http_samples: dict[tuple[str, str], dict[str, Any]] | None = None,
    base_url: str | None = None,
) -> ApplicationModel:
    """Assemble an ApplicationModel from the collected evidence.

    Parameters
    ----------
    discovered_endpoints:
        Endpoints produced by the 1.2 crawl / OpenAPI tools.
    auth_analysis:
        The *output* dict from `runtime.auth.analyze` (keys: mechanisms,
        mechanism_count, login endpoints, etc.).
    openapi_doc:
        The raw OpenAPI/Swagger dict.  Used to extract query / path / body
        parameters that discovery alone cannot see.
    http_samples:
        Pre-collected HTTP samples keyed by (method, url) with values like
        ``{"status_code": 200, "content_type": "text/html", ...}``.
    base_url:
        The application root (e.g. ``http://app/``).  Used to turn relative
        paths into absolute URLs for the EndpointModel.url field and for
        matching http_samples keys.
    """
    auth_analysis = auth_analysis or {}
    http_samples = http_samples or {}
    mechanisms: list[dict[str, Any]] = auth_analysis.get("mechanisms") or []
    login_urls: list[str] = _extract_login_urls(auth_analysis)
    protected_by = _strongest_mechanism(mechanisms)
    has_auth = bool(mechanisms) and protected_by is not None

    # --- Build a lookup from OpenAPI params by path ---------------------------
    openapi_params: dict[str, dict[str, Any]] = _index_openapi_params(openapi_doc)

    # --- De-duplicate discovered endpoints by (method, path) ------------------
    merged = _merge_endpoints(discovered_endpoints)

    # --- Assemble EndpointModel records ----------------------------------------
    model = ApplicationModel(
        login_endpoints=list(login_urls),
        auth_mechanism_summary=auth_analysis,
        discovered_at=datetime.now(timezone.utc).isoformat(),
    )

    for key, ep in merged.items():
        method, path = key
        url = _absolute_url(path, base_url)
        oa = openapi_params.get(path, {})
        sample = http_samples.get((method, url)) or http_samples.get((method, path)) or {}

        normalized = _normalize_path(path)
        is_login = url in login_urls or normalized in _login_paths(login_urls)
        is_public = not has_auth or normalized in _PUBLIC_PATHS or is_login

        model.add(EndpointModel(
            method=method,
            url=url,
            path=normalized,
            source=ep.source,
            depth=ep.extra.get("depth"),
            found_in=ep.found_in,
            status_code=sample.get("status_code"),
            content_type=sample.get("content_type"),
            response_headers=sample.get("headers") or {},
            query_params=ep.query_params or tuple(oa.get("query_params", ())),
            path_params=tuple(oa.get("path_params", ())),
            body_media_type=ep.body_media_type or oa.get("body_media_type"),
            form_fields=tuple(oa.get("form_fields", ())),
            auth_required=has_auth and not is_public,
            protected_by=protected_by if (has_auth and not is_public) else None,
            set_cookie_names=tuple(sample.get("set_cookie_names") or []),
            links_out=tuple(sample.get("links_out") or []),
        ))

    log.info(
        "application_model.built",
        total=model.total_endpoints,
        protected=len(model.protected_endpoints()),
        public=len(model.public_endpoints()),
        login=len(model.login_endpoints),
    )
    return model


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _merge_endpoints(
    discovered: list[DiscoveredEndpoint] | tuple[DiscoveredEndpoint, ...],
) -> dict[tuple[str, str], DiscoveredEndpoint]:
    """De-duplicate by (method, path), merging richer data from later sources."""
    merged: dict[tuple[str, str], DiscoveredEndpoint] = {}
    for ep in discovered:
        key = (ep.method.upper(), ep.path)
        if key in merged:
            existing = merged[key]
            # Prefer OpenAPI param data over crawl data (richer parameter set).
            if ep.source == "openapi" and len(ep.query_params) > len(existing.query_params):
                merged[key] = ep
            # Prefer a source that carries query params the other lacks.
            elif ep.query_params and not existing.query_params:
                merged[key] = ep
            # Prefer a source that knows where the endpoint was found.
            elif ep.found_in and not existing.found_in:
                merged[key] = ep
        else:
            merged[key] = ep
    return merged


def _absolute_url(path: str, base_url: str | None) -> str:
    """Return an absolute URL for a path, resolving against base_url when given."""
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if base_url:
        root = base_url if base_url.endswith("/") else base_url + "/"
        return urljoin(root, path.lstrip("/"))
    return path


def _normalize_path(path: str) -> str:
    """Normalize a path for classification/lookup: '' -> '/', strip trailing '/'."""
    if not path:
        return "/"
    if path == "/":
        return "/"
    return path.rstrip("/") or "/"


def _login_paths(login_urls: list[str]) -> set[str]:
    """Path components of login URLs, normalized for comparison."""
    return {_normalize_path(urlsplit(u).path) for u in login_urls}


def _extract_login_urls(auth_analysis: dict[str, Any]) -> list[str]:
    """Pull login form actions and auth links from the auth analysis output."""
    urls: list[str] = []
    login_info = auth_analysis.get("candidate_login_endpoints") or {}
    urls.extend(login_info.get("form_actions") or [])
    urls.extend(login_info.get("auth_links") or [])
    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def _strongest_mechanism(mechanisms: list[dict[str, Any]]) -> str | None:
    """Select the strongest protection mechanism from the analysis summary."""
    if not mechanisms:
        return None
    best: str | None = None
    best_strength = -1
    for mech in mechanisms:
        kind = mech.get("kind") or ""
        strength = _MECH_STRENGTH.get(kind, -1)
        if strength > best_strength:
            best_strength = strength
            best = _PROTECTION_MAP.get(kind, kind)
    return best


def _index_openapi_params(doc: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Index OpenAPI parameters by path for quick lookup."""
    if not doc:
        return {}
    paths: dict[str, Any] = doc.get("paths") or {}
    index: dict[str, dict[str, Any]] = {}
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_params_raw = path_item.get("parameters") or []
        query_params: set[str] = set()
        path_params: set[str] = set()
        body_media_type: str | None = None

        for param in path_params_raw:
            if not isinstance(param, dict):
                continue
            location = param.get("in", "")
            name = param.get("name", "")
            if location == "query" and name:
                query_params.add(name)
            elif location == "path" and name:
                path_params.add(name)

        # Look at a sample operation for requestBody
        for method in ("get", "post", "put", "patch", "delete"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            op_params = op.get("parameters") or []
            for param in op_params:
                if not isinstance(param, dict):
                    continue
                location = param.get("in", "")
                name = param.get("name", "")
                if location == "query" and name:
                    query_params.add(name)
                elif location == "path" and name:
                    path_params.add(name)
            request_body = op.get("requestBody")
            if isinstance(request_body, dict) and not body_media_type:
                media_types = (request_body.get("content") or {})
                if media_types:
                    body_media_type = next(iter(media_types))

        index[path] = {
            "query_params": sorted(query_params),
            "path_params": sorted(path_params),
            "body_media_type": body_media_type,
        }
    return index