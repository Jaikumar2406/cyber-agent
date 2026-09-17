"""Runtime Finding Normalizer (phases.md §1.7).

Converts raw tool-output findings into normalized, evidence-ready records with:
  - Severity / confidence validated against the platform vocabulary
  - OWASP 2021 category assigned from the Aegis detection category
  - Affected asset (host, URL, method) extracted from the finding endpoint

The output feeds the Evidence Normalizer (Phase 0) to create real RUNTIME
evidence rows per finding (source=RUNTIME), complementing the single HARNESS
wrapper record that the executor already persists.

Rules honored:
  - rules.md §2: truth flows from engines upward; this normalizer never
    overwrites engine-assigned severity/confidence — it only validates and
    assigns OWASP/asset metadata.
  - rules.md §5.5: no secret values are written into normalized location.
"""

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from app.schemas.common import Confidence, Severity

# ---------------------------------------------------------------------------
# OWASP 2021 mapping (§1.7) — Aegis category → OWASP Top-10 code + label
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OwaspCategory:
    code: str
    name: str


_OWASP_RUNTIME_MAP: dict[str, OwaspCategory] = {
    "bola":                       OwaspCategory("A01", "Broken Access Control"),
    "bfla":                       OwaspCategory("A01", "Broken Access Control"),
    "access_control_asymmetry":   OwaspCategory("A01", "Broken Access Control"),
    "injection":                  OwaspCategory("A03", "Injection"),
    "ssrf":                       OwaspCategory("A10", "Server-Side Request Forgery"),
    "misconfiguration":           OwaspCategory("A05", "Security Misconfiguration"),
    "auth_weakness":              OwaspCategory("A07", "Identification and Authentication Failures"),
    "nuclei":                     OwaspCategory("A00", "Uncategorized (template-based)"),
}

_DEFAULT_OASP = OwaspCategory("A00", "Uncategorized")


def owasp_for(category: str) -> OwaspCategory:
    """Return the OWASP 2021 top-10 category for an Aegis finding category."""
    return _OWASP_RUNTIME_MAP.get(category, _DEFAULT_OASP)


# ---------------------------------------------------------------------------
# Severity / confidence validation
# ---------------------------------------------------------------------------

def _validate_severity(raw: str) -> str:
    try:
        return Severity(raw.upper()).value
    except ValueError:
        return Severity.MEDIUM.value


def _validate_confidence(raw: str) -> str:
    try:
        return Confidence(raw.upper()).value
    except ValueError:
        return Confidence.POTENTIAL.value


# ---------------------------------------------------------------------------
# Affected asset extraction (from endpoint string)
# ---------------------------------------------------------------------------

def _affected_asset(endpoint: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Best-effort extraction of {host, url, method} from the finding's
    ``endpoint`` string (format: ``METHOD absolute-url``)."""
    parts = (endpoint or "").strip().split(None, 1)
    method = parts[0].upper() if parts else "UNKNOWN"
    raw_url = parts[1] if len(parts) > 1 else ""
    try:
        parsed = urlsplit(raw_url)
        host = parsed.hostname or ""
        return {"host": host, "url": raw_url, "method": method}
    except Exception:
        return {"host": "", "url": raw_url, "method": method}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a single raw finding dict.

    Returns a *new* dict containing all original fields plus:
      - ``owasp``: OWASP 2021 code (e.g. ``"A01"``) when the raw finding did
        not already carry one
      - ``owasp_category``: ``{"code": "A01", "name": "Broken Access Control"}``
      - ``affected_asset``: ``{"host": ..., "url": ..., "method": ...}``
      - ``severity``: validated Severity value
      - ``confidence``: validated Confidence value

    The original raw dict is not mutated.
    """
    category = str(raw.get("category", "")).strip()
    severity = _validate_severity(str(raw.get("severity", "MEDIUM")))
    confidence = _validate_confidence(str(raw.get("confidence", "POTENTIAL")))
    owasp = owasp_for(category)
    asset = _affected_asset(str(raw.get("endpoint", "")), raw.get("evidence") or {})

    normalized = dict(raw)
    normalized["severity"] = severity
    normalized["confidence"] = confidence
    if not normalized.get("owasp"):
        normalized["owasp"] = owasp.code
    normalized["owasp_category"] = {"code": owasp.code, "name": owasp.name}
    normalized["affected_asset"] = asset
    return normalized


def normalize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize every finding in a tool output's ``findings`` list."""
    return [normalize_finding(f) for f in findings]