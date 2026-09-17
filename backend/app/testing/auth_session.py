"""Authentication / session weakness detection (phases.md §1.5, passive).

Operates on `Set-Cookie` headers (and optionally the §1.3 auth analysis). It
never handles secret *values*: only cookie names and their security flags are
inspected, matching rules.md §5.5 (secrets are never persisted in evidence).

Checks:
  * Cookie missing `HttpOnly` (session-hijack via XSS).
  * Cookie missing `Secure` on HTTPS.
  * Cookie missing `SameSite`.
  * Session cookie issued over cleartext HTTP.
  * HTTP Basic authentication in use.
"""

import re
from dataclasses import dataclass, field

from app.schemas.common import Confidence, Severity
from app.testing.finding import AUTH_WEAKNESS, Finding

_SESSION_NAME_RE = re.compile(
    r"(?:sess|sid|auth|token|jwt|login|remember|csrf|xsrf)", re.IGNORECASE
)


@dataclass(frozen=True)
class CookieFlags:
    name: str
    flags: dict[str, bool] = field(default_factory=dict)

    @property
    def is_session_like(self) -> bool:
        return bool(_SESSION_NAME_RE.search(self.name))

    def has(self, flag: str) -> bool:
        return self.flags.get(flag.lower(), False)


def parse_set_cookie(raw: str) -> CookieFlags | None:
    """Parse one Set-Cookie header into a name + normalized flag map."""
    if not raw:
        return None
    parts = [p.strip() for p in raw.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    flags: dict[str, bool] = {}
    for attr in parts[1:]:
        key = attr.split("=", 1)[0].strip().lower()
        if key:
            flags[key] = True
    return CookieFlags(name=name, flags=flags)


def parse_set_cookie_headers(raw_headers: list[str]) -> list[CookieFlags]:
    parsed = [parse_set_cookie(raw) for raw in raw_headers or []]
    return [c for c in parsed if c is not None]


def analyze_cookies(
    *,
    url: str,
    set_cookie_headers: list[str],
    endpoint: str | None = None,
) -> list[Finding]:
    """Flag insecure cookie attributes. Values are never included in evidence."""
    endpoint = endpoint or f"GET {url}"
    is_https = url.lower().startswith("https://")
    findings: list[Finding] = []
    for cookie in parse_set_cookie_headers(set_cookie_headers):
        base_evidence = {"cookie_name": cookie.name, "flags": sorted(cookie.flags)}
        severity = Severity.MEDIUM if cookie.is_session_like else Severity.LOW
        if not cookie.has("httponly"):
            findings.append(
                Finding(
                    title=f"Cookie {cookie.name!r} is missing the HttpOnly flag",
                    category=AUTH_WEAKNESS,
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    endpoint=endpoint,
                    summary=f"Cookie `{cookie.name}` can be read by client-side script (no HttpOnly).",
                    remediation="Set the HttpOnly attribute on all session/authentication cookies.",
                    evidence={**base_evidence, "missing_flag": "HttpOnly"},
                    cwe="CWE-1004",
                    detector="auth_session.cookie_httponly",
                )
            )
        if is_https and not cookie.has("secure"):
            findings.append(
                Finding(
                    title=f"Cookie {cookie.name!r} is missing the Secure flag",
                    category=AUTH_WEAKNESS,
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    endpoint=endpoint,
                    summary=f"Cookie `{cookie.name}` may be transmitted over cleartext HTTP (no Secure).",
                    remediation="Set the Secure attribute on all cookies delivered over HTTPS.",
                    evidence={**base_evidence, "missing_flag": "Secure"},
                    cwe="CWE-614",
                    detector="auth_session.cookie_secure",
                )
            )
        if not cookie.has("samesite"):
            findings.append(
                Finding(
                    title=f"Cookie {cookie.name!r} is missing the SameSite attribute",
                    category=AUTH_WEAKNESS,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    endpoint=endpoint,
                    summary=f"Cookie `{cookie.name}` has no SameSite policy (CSRF exposure).",
                    remediation="Set SameSite=Lax or SameSite=Strict on session cookies.",
                    evidence={**base_evidence, "missing_flag": "SameSite"},
                    cwe="CWE-1275",
                    detector="auth_session.cookie_samesite",
                )
            )
        if not is_https and cookie.is_session_like:
            findings.append(
                Finding(
                    title=f"Session cookie {cookie.name!r} issued over cleartext HTTP",
                    category=AUTH_WEAKNESS,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    endpoint=endpoint,
                    summary=f"Session cookie `{cookie.name}` is set over HTTP and is vulnerable to interception.",
                    remediation="Serve the application exclusively over HTTPS and mark cookies Secure.",
                    evidence={**base_evidence, "scheme": "http"},
                    cwe="CWE-319",
                    detector="auth_session.cleartext_session",
                )
            )
    return findings


def analyze_auth_mechanism(*, url: str, auth_analysis: dict) -> list[Finding]:
    """Flag weak mechanisms reported by §1.3 (e.g. HTTP Basic authentication)."""
    findings: list[Finding] = []
    mechanisms = auth_analysis.get("mechanisms") or auth_analysis.get("kinds") or []
    normalized: set[str] = set()
    for item in mechanisms:
        if isinstance(item, dict):
            kind = item.get("kind") or item.get("type")
        else:
            kind = item
        if kind:
            normalized.add(str(kind).lower())
    endpoint = f"GET {url}"
    if "basic" in normalized:
        findings.append(
            Finding(
                title="HTTP Basic authentication in use",
                category=AUTH_WEAKNESS,
                severity=Severity.LOW,
                confidence=Confidence.PROBABLE,
                endpoint=endpoint,
                summary="The application advertises HTTP Basic authentication (`WWW-Authenticate: Basic`).",
                remediation="Prefer token/session-based authentication and always enforce HTTPS for Basic auth.",
                evidence={"mechanisms": sorted(normalized)},
                cwe="CWE-522",
                detector="auth_session.basic_auth",
            )
        )
    return findings


def analyze(
    *,
    url: str,
    set_cookie_headers: list[str],
    auth_analysis: dict | None = None,
) -> list[Finding]:
    findings = analyze_cookies(url=url, set_cookie_headers=set_cookie_headers)
    if auth_analysis:
        findings.extend(analyze_auth_mechanism(url=url, auth_analysis=auth_analysis))
    return findings
