"""OpenAPI / Swagger spec parser - phases.md §1.2.

Parses OpenAPI 3.x and Swagger 2.0 documents (JSON, or YAML when PyYAML is
available) into `DiscoveredEndpoint` records. Deliberately registry-free: no
third-party parser at runtime, keeping the air-gap promise (rules.md §3).
"""

import json
from typing import Any

from app.core.logging import get_logger
from app.discovery.models import DiscoveredEndpoint

log = get_logger("aegis.discovery.openapi")


class OpenApiParseError(Exception):
    pass


def _try_yaml(text: str) -> dict[str, Any] | None:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _load_document(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = _try_yaml(text)
    if not isinstance(data, dict):
        raise OpenApiParseError("spec is not a JSON map (and YAML unavailable/invalid)")
    if "openapi" not in data and "swagger" not in data:
        raise OpenApiParseError("document is neither OpenAPI nor Swagger (missing openapi/swagger key)")
    return data


def _method_name(value: str) -> bool:
    return value in ("get", "post", "put", "patch", "delete", "head", "options", "trace")


def parse_openapi_spec(text: str, *, found_in: str | None = None) -> list[DiscoveredEndpoint]:
    """Parse an OpenAPI 3.x / Swagger 2.0 spec into discovered endpoints."""
    doc = _load_document(text)
    paths = doc.get("paths") or {}
    endpoints: list[DiscoveredEndpoint] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_params = path_item.get("parameters") or []
        for method, operation in path_item.items():
            if not _method_name(method) or not isinstance(operation, dict):
                continue
            op_params = operation.get("parameters") or []
            all_params = list(path_params) + list(op_params)
            query_params = tuple(
                sorted(
                    {
                        str(p["name"])
                        for p in all_params
                        if isinstance(p, dict) and p.get("in") == "query" and p.get("name")
                    }
                )
            )
            body_media_type = None
            request_body = operation.get("requestBody")
            if isinstance(request_body, dict):
                media_types = tuple((request_body.get("content") or {}).keys())
                body_media_type = media_types[0] if media_types else None
            endpoints.append(
                DiscoveredEndpoint(
                    method=method.upper(),
                    path=path,
                    source="openapi",
                    found_in=found_in,
                    query_params=query_params,
                    body_media_type=body_media_type,
                    extra={"summary": operation.get("summary")},
                )
            )
    if not endpoints:
        log.info("openapi.no_endpoints", found_in=found_in)
    return endpoints


def load_openapi_document(text: str) -> dict[str, Any]:
    """Parse (JSON, or YAML when available) into the raw OpenAPI/Swagger mapping.

    Phase 1.3 uses this to reach `components.securitySchemes`, which the
    endpoint parser deliberately discards.
    """
    return _load_document(text)


def spec_urls_for_base(base_url: str) -> list[str]:
    """Likely spec locations to probe for discovery (phases.md §1.2)."""
    base = base_url.rstrip("/")
    return [
        f"{base}/openapi.json",
        f"{base}/swagger.json",
        f"{base}/swagger-ui.json",
        f"{base}/api-docs",
        f"{base}/v3/api-docs",
    ]