"""Misconfiguration detection (phases.md §1.5, passive).

Analyzes already-observed response metadata (headers/status) recorded by the
Application Model Builder (§1.4) plus optional body excerpts. No new requests
are required, so this module is genuinely read-only and safe at passive
intensity.

Checks:
  * Missing security response headers (HSTS/CSP/X-Frame-Options/...).
  * Permissive CORS (`Access-Control-Allow-Origin: *` with credentials, or
    arbitrary-origin reflection).
  * Version/banner disclosure via `Server` / `X-Powered-By`.
  * Exposed debug/actuator endpoints.
  * Verbose error / stack-trace leakage (when a body excerpt is supplied).
"""

import re
from dataclasses import dataclass
from typing import Any

from app.schemas.common import Confidence, Severity
from app.testing.finding import MISCONFIGURATION, Finding


@dataclass(frozen=True)
class HeaderRule:
    header: str
    title: str
    severity: str
    remediation: str
    https_only: bool = False
    cwe: str = "CWE-693"


_SECURITY_HEADERS: tuple[HeaderRule, ...] = (
    HeaderRule(
        "strict-transport-security",
        "Missing HTTP Strict-Transport-Security (HSTS) header",
        Severity.MEDIUM,
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.",
        https_only=True,
        cwe="CWE-319",
    ),
    HeaderRule(
        "content-security-policy",
        "Missing Content-Security-Policy (CSP) header",
        Severity.MEDIUM,
        "Define a restrictive Content-Security-Policy appropriate for the application.",
        cwe="CWE-1021",
    ),
    HeaderRule(
        "x-content-type-options",
        "Missing X-Content-Type-Options header",
        Severity.LOW,
        "Send `X-Content-Type-Options: nosniff`.",
        cwe="CWE-693",
    ),
    HeaderRule(
        "x-frame-options",
        "Missing X-Frame-Options header (clickjacking)",
        Severity.LOW,
        "Send `X-Frame-Options: DENY` (or a frame-ancestors CSP directive).",
        cwe="CWE-1021",
    ),
    HeaderRule(
        "referrer-policy",
        "Missing Referrer-Policy header",
        Severity.LOW,
        "Send `Referrer-Policy: no-referrer` or a stricter policy.",
        cwe="CWE-200",
    ),
    HeaderRule(
        "permissions-policy",
        "Missing Permissions-Policy header",
        Severity.INFO,
        "Send a Permissions-Policy that disables unused browser features.",
        cwe="CWE-693",
    ),
)

# Endpoint path fragments that should never be publicly reachable.
DEBUG_PATH_PATTERNS: tuple[str, ...] = (
    "/debug",
    "/actuator",
    "/.env",
    "/server-status",
    "/phpinfo",
    "/trace",
    "/console",
    "/swagger-ui",
    "/api-docs",
    "/.git/",
)

_VERBOSE_ERROR_MARKERS: tuple[str, ...] = (
    "traceback (most recent call last)",
    "sqlstate[",
    "syntax error at or near",
    "you have an error in your sql syntax",
    "ora-0",
    "stack trace:",
    "at java.",
    "django.core.exceptions",
    "werkzeug.debug",
)

_VERSION_RE = re.compile(r"\d+\.\d+")


def _header_lookup(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in (headers or {}).items():
        if key.lower() == target:
            return value
    return None


def _is_success(status_code: int | None) -> bool:
    return status_code is not None and 200 <= status_code < 300


def analyze_headers(
    *,
    method: str,
    url: str,
    path: str,
    status_code: int | None,
    headers: dict[str, str],
) -> list[Finding]:
    """Header/CORS/banner/debug checks for one observed endpoint."""
    findings: list[Finding] = []
    if not _is_success(status_code):
        return findings

    endpoint = f"{method.upper()} {url}"
    is_https = url.lower().startswith("https://")

    for rule in _SECURITY_HEADERS:
        if rule.https_only and not is_https:
            continue
        if _header_lookup(headers, rule.header) is None:
            findings.append(
                Finding(
                    title=rule.title,
                    category=MISCONFIGURATION,
                    severity=rule.severity,
                    confidence=Confidence.CONFIRMED,
                    endpoint=endpoint,
                    summary=f"Response {status_code} from {url} does not set `{rule.header}`.",
                    remediation=rule.remediation,
                    evidence={"missing_header": rule.header, "status_code": status_code},
                    cwe=rule.cwe,
                    detector="misconfig.security_headers",
                )
            )

    cors = _header_lookup(headers, "access-control-allow-origin")
    if cors is not None:
        allow_creds = (_header_lookup(headers, "access-control-allow-credentials") or "").lower()
        if cors.strip() == "*" and allow_creds == "true":
            findings.append(
                Finding(
                    title="Permissive CORS with credentials",
                    category=MISCONFIGURATION,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    endpoint=endpoint,
                    summary=(
                        "`Access-Control-Allow-Origin: *` is combined with "
                        "`Access-Control-Allow-Credentials: true`."
                    ),
                    remediation="Never combine a wildcard origin with credentials; echo only an explicit allow-list of origins.",
                    evidence={
                        "access_control_allow_origin": cors,
                        "access_control_allow_credentials": allow_creds,
                    },
                    cwe="CWE-942",
                    detector="misconfig.cors",
                )
            )

    server = _header_lookup(headers, "server")
    powered = _header_lookup(headers, "x-powered-by")
    for name, value in (("server", server), ("x-powered-by", powered)):
        if value and _VERSION_RE.search(value):
            findings.append(
                Finding(
                    title=f"Technology/version disclosure via {name} header",
                    category=MISCONFIGURATION,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    endpoint=endpoint,
                    summary=f"`{name}: {value}` reveals component/version information.",
                    remediation=f"Suppress or genericize the `{name}` response header.",
                    evidence={"header": name, "value": value},
                    cwe="CWE-200",
                    detector="misconfig.banner",
                )
            )

    normalized_path = (path or "/").lower()
    if any(pattern in normalized_path for pattern in DEBUG_PATH_PATTERNS):
        findings.append(
            Finding(
                title="Potentially exposed debug/administration endpoint",
                category=MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.PROBABLE,
                endpoint=endpoint,
                summary=f"`{path}` returned {status_code} and matches a known debug/actuator path.",
                remediation="Disable debug actuators/consoles in production and restrict them to trusted networks.",
                evidence={"path": path, "status_code": status_code},
                cwe="CWE-489",
                detector="misconfig.debug_endpoint",
            )
        )

    return findings


def detect_verbose_error(body: str) -> str | None:
    """Return the matched marker if a body leaks a stack trace / DB error."""
    lowered = (body or "").lower()
    for marker in _VERBOSE_ERROR_MARKERS:
        if marker in lowered:
            return marker
    return None


def analyze_body(*, method: str, url: str, body: str) -> list[Finding]:
    marker = detect_verbose_error(body)
    if marker is None:
        return []
    return [
        Finding(
            title="Verbose error / stack-trace disclosure",
            category=MISCONFIGURATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            endpoint=f"{method.upper()} {url}",
            summary=f"Response body contains a verbose error marker ({marker!r}).",
            remediation="Return generic error messages and log details server-side only.",
            evidence={"marker": marker},
            cwe="CWE-209",
            detector="misconfig.verbose_error",
        )
    ]


def analyze_endpoint(endpoint: dict[str, Any], body: str | None = None) -> list[Finding]:
    """Convenience entry point for one endpoint record (as produced by §1.4)."""
    findings = analyze_headers(
        method=str(endpoint.get("method", "GET")),
        url=str(endpoint.get("url", "")),
        path=str(endpoint.get("path", "/")),
        status_code=endpoint.get("status_code"),
        headers=endpoint.get("response_headers") or {},
    )
    if body:
        findings.extend(
            analyze_body(
                method=str(endpoint.get("method", "GET")),
                url=str(endpoint.get("url", "")),
                body=body,
            )
        )
    return findings
