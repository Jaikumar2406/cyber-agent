"""BOLA / BFLA access-control analysis (phases.md §1.5, cross-user).

Deterministic comparison of the SAME endpoint requested with two distinct test
identities (provisioned in §1.3). Two signals are derived:

  * **BFLA (function-level)** - a *privileged-looking* endpoint (admin path or a
    state-changing method) is reachable by an identity.
  * **BOLA (object-level)** - two different identities receive the *same,
    non-empty* successful response for a protected endpoint, indicating the
    resource is not scoped to its owner.

Because object ownership is not knowable without per-user identifiers, BOLA is
reported at POTENTIAL confidence; results are always attached to the two
identity references (redacted) that produced them (rules.md §1.3/§1.6).
"""

from typing import Any

from app.schemas.common import Confidence, Severity
from app.testing.finding import ACCESS_CONTROL_ASYMMETRY, BFLA, BOLA, Finding

_PRIVILEGED_PATH_FRAGMENTS: tuple[str, ...] = (
    "/admin",
    "/manage",
    "/management",
    "/internal",
    "/users",
    "/settings",
    "/config",
    "/roles",
    "/permissions",
)
_STATE_CHANGING_METHODS = {"DELETE", "PUT", "PATCH"}


def is_success(status_code: int | None) -> bool:
    return status_code is not None and 200 <= status_code < 300


def is_privileged_endpoint(method: str, path: str) -> bool:
    method = (method or "GET").upper()
    if method in _STATE_CHANGING_METHODS:
        return True
    lowered = (path or "").lower()
    return any(frag in lowered for frag in _PRIVILEGED_PATH_FRAGMENTS)


def classify_pair(
    *,
    method: str,
    url: str,
    path: str,
    status_a: int | None,
    body_a: str,
    status_b: int | None,
    body_b: str,
    identity_a: dict[str, Any],
    identity_b: dict[str, Any],
) -> Finding | None:
    """Compare two identities' responses for one endpoint. Returns at most one
    finding (stronger signal wins: BFLA > BOLA > asymmetry)."""
    endpoint = f"{method.upper()} {url}"
    success_a = is_success(status_a)
    success_b = is_success(status_b)
    privileged = is_privileged_endpoint(method, path)
    proof = {
        "identity_a": identity_a,
        "identity_b": identity_b,
        "status_a": status_a,
        "status_b": status_b,
    }

    if privileged and (success_a or success_b):
        return Finding(
            title="Broken function-level authorization (privileged endpoint reachable)",
            category=BFLA,
            severity=Severity.HIGH,
            confidence=Confidence.PROBABLE,
            endpoint=endpoint,
            summary=(
                f"A privileged endpoint ({path}) returned a success response for a "
                f"test identity (A={status_a}, B={status_b})."
            ),
            remediation="Enforce role checks server-side on every privileged function, not just in the UI.",
            evidence={**proof, "path": path, "privileged": True},
            identity_proof=proof,
            cwe="CWE-285",
            detector="access_control.bfla",
        )

    if success_a and success_b and (body_a or body_b):
        if (body_a or "") == (body_b or ""):
            return Finding(
                title="Possible broken object-level authorization (BOLA)",
                category=BOLA,
                severity=Severity.HIGH,
                confidence=Confidence.POTENTIAL,
                endpoint=endpoint,
                summary=(
                    "Two distinct identities received an identical successful response "
                    "for a protected endpoint (resource may not be owner-scoped)."
                ),
                remediation="Scope object lookups to the authenticated principal (server-side ownership check).",
                evidence={**proof, "identical_body": True, "body_length": len(body_a or "")},
                identity_proof=proof,
                cwe="CWE-639",
                detector="access_control.bola",
            )

    if success_a != success_b and (success_a or success_b):
        return Finding(
            title="Access-control response asymmetry between identities",
            category=ACCESS_CONTROL_ASYMMETRY,
            severity=Severity.MEDIUM,
            confidence=Confidence.POTENTIAL,
            endpoint=endpoint,
            summary=(
                f"Endpoint returned inconsistent authorization decisions across identities "
                f"(A={status_a}, B={status_b})."
            ),
            remediation="Review authorization logic for identity-dependent inconsistencies.",
            evidence=proof,
            identity_proof=proof,
            cwe="CWE-285",
            detector="access_control.asymmetry",
        )

    return None
