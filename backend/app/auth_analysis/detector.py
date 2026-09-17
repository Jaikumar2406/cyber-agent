"""Authentication mechanism detection (phases.md §1.3).

Pure, offline classifier that inspects discovery evidence (<form> actions,
OAuth redirect patterns, login pages) and sampled HTTP headers (Set-Cookie,
WWW-Authenticate, Authorization) to determine how a target authenticates.

Detection is *passive*: it never sends credentials, never intents a login, and
never leaks secrets - it only classifies what it observes (rules.md §3.4).
"""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

from app.core.logging import get_logger
from app.schemas.common import Confidence

log = get_logger("aegis.auth_analysis.detector")

AUTH_KINDS = ("jwt", "cookie", "oauth", "basic", "api_key", "credentials")

# (header, regex, mechanism kind) - on-wire confirmations.
_HEADER_SIGNALS: tuple[tuple[str, str, str], ...] = (
    ("www-authenticate", r"bearer", "jwt"),
    ("www-authenticate", r"basic", "basic"),
    ("set-cookie", r"(?:^|;)\s*\w*(?:session|sess|sid|auth|token|jwt)\w*\s*=", "cookie"),
    ("location", r"(?:oauth|authorize|/realms/|/authorization)", "oauth"),
)

_CONFIDENCE_ORDER = {
    Confidence.CONFIRMED.value: 3,
    Confidence.PROBABLE.value: 2,
    Confidence.POTENTIAL.value: 1,
}


@dataclass(frozen=True)
class MechanismHint:
    kind: str  # one of AUTH_KINDS
    confidence: str  # Confidence enum value ("CONFIRMED" | "PROBABLE" | "POTENTIAL")
    source: str  # "header" | "html" | "openapi"
    detail: dict[str, Any] = field(default_factory=dict)


def _dedupe(hints: list[MechanismHint]) -> list[MechanismHint]:
    out: list[MechanismHint] = []
    seen: set[tuple[str, str, str]] = set()
    for hint in hints:
        key = (hint.kind, hint.confidence, hint.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(hint)
    return out


def detect_from_headers(headers: dict[str, str]) -> list[MechanismHint]:
    """Classify auth mechanism strictly from response headers.

    A `Set-Cookie` session cookie or a `WWW-Authenticate` challenge is
    *confirmed* on-wire evidence; a `Location` to an OAuth endpoint is probable.
    """
    h = {k.lower(): v for k, v in (headers or {}).items()}
    hints: list[MechanismHint] = []
    for header, pattern, kind in _HEADER_SIGNALS:
        value = h.get(header, "")
        if re.search(pattern, value, re.IGNORECASE):
            hints.append(MechanismHint(kind, _confidence_for(header, kind), "header",
                                       {"header": header}))
    return _dedupe(hints)


def _confidence_for(header: str, kind: str) -> str:
    # Set-Cookie / WWW-Authenticate are confirmed on-wire; a Location redirect
    # to an OAuth endpoint is only probable (it could be a normal auth page).
    if kind == "oauth":
        return Confidence.PROBABLE.value
    return Confidence.CONFIRMED.value


def detect_from_html(html: str, base_url: str | None = None) -> list[MechanismHint]:
    """Classify from a login page's structure.

    A form with a password field => credential-based login (probable). An OAuth
    authorize identity link => OAuth (potential).
    """
    hints: list[MechanismHint] = []

    class _LoginPageParser(HTMLParser):  # noqa: N801
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.has_password = False
            self.has_form = False

        def handle_starttag(self, tag, attrs) -> None:  # noqa: N802
            attrs = dict(attrs)
            if tag == "input" and attrs.get("type") == "password":
                self.has_password = True
            if tag == "form":
                self.has_form = True

    parser = _LoginPageParser()
    parser.feed(html or "")
    if parser.has_password:
        hints.append(MechanismHint("credentials", Confidence.PROBABLE.value, "html",
                                   {"form": True, "password_field": True, "base_url": base_url}))
    if re.search(r"(?:oauth|identity|/realms/|authorize|sign in with)", html or "", re.IGNORECASE):
        hints.append(MechanismHint("oauth", Confidence.POTENTIAL.value, "html",
                                   {"base_url": base_url}))
    return _dedupe(hints)


def detect_from_openapi(doc: dict[str, Any]) -> list[MechanismHint]:
    """Classify from OpenAPI/Swagger securitySchemes.

    The spec documents how clients are *intended* to authenticate; on-wire
    headers remain the ground truth, so these are PROBABLE.
    """
    hints: list[MechanismHint] = []
    components = (doc or {}).get("components") or {}
    schemes = (components.get("securitySchemes") or {})
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        scheme_type = (scheme.get("type") or "").lower()
        if scheme_type == "http":
            bearer = (scheme.get("scheme") or "").lower() == "bearer"
            hints.append(MechanismHint(
                "jwt" if bearer else "basic", Confidence.PROBABLE.value, "openapi",
                {"name": name, "scheme": scheme.get("scheme")},
            ))
        elif scheme_type == "apikey":
            hints.append(MechanismHint("api_key", Confidence.PROBABLE.value, "openapi",
                                       {"name": name, "in": scheme.get("in")}))
        elif scheme_type == "oauth2":
            hints.append(MechanismHint("oauth", Confidence.PROBABLE.value, "openapi",
                                       {"name": name, "type": "oauth2"}))
    return _dedupe(hints)


def detect_from_spec_url_paths(paths: dict[str, Any]) -> list[MechanismHint]:
    """OAuth protocol endpoints (/userinfo, /oauth/token, /authorize) in a spec."""
    joined = " ".join((paths or {}).keys())
    if re.search(r"(?:/userinfo|/oauth/token|/token|/authorize|/realms/)", joined, re.IGNORECASE):
        return [MechanismHint("oauth", Confidence.PROBABLE.value, "openapi", {"paths": True})]
    return []


def detect_all(
    *,
    headers: dict[str, str] | None = None,
    html: str | None = None,
    base_url: str | None = None,
    openapi_doc: dict[str, Any] | None = None,
) -> list[MechanismHint]:
    """Merge all passive signals into one deduplicated hint list."""
    hints: list[MechanismHint] = []
    if headers:
        hints.extend(detect_from_headers(headers))
    if html:
        hints.extend(detect_from_html(html, base_url))
    if openapi_doc:
        hints.extend(detect_from_openapi(openapi_doc))
        if openapi_doc.get("paths"):
            hints.extend(detect_from_spec_url_paths(openapi_doc.get("paths")))
    return _dedupe(hints)


def summarize(hints: list[MechanismHint]) -> dict[str, Any]:
    """Group hints by kind; keep the strongest confidence per kind and drop any
    detail that could carry secrets (only safe, low-cardinality keys survive)."""
    SAFE_DETAIL_KEYS = ("name", "scheme", "in", "type")
    by_kind: dict[str, list[MechanismHint]] = {}
    for hint in hints:
        by_kind.setdefault(hint.kind, []).append(hint)

    summary: list[dict[str, Any]] = []
    for kind in sorted(by_kind):
        group = by_kind[kind]
        best = max(group, key=lambda h: _CONFIDENCE_ORDER.get(h.confidence, 0))
        downstream_detail: dict[str, Any] = {}
        for item in group:
            for key in SAFE_DETAIL_KEYS:
                if key in (item.detail or {}) and key not in downstream_detail:
                    downstream_detail[key] = item.detail[key]
        summary.append({
            "kind": best.kind,
            "confidence": best.confidence,
            "sources": sorted({h.source for h in group}),
            "evidence_count": len(group),
            "detail": downstream_detail,
        })
    return {"mechanisms": summary, "count": len(summary)}