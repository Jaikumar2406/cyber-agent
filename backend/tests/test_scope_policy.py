"""Phase 1.1 - Scope & Policy Guard tests (real enforcement).

Covers: domain/IP/CIDR/path/method restrictions, redirect policy, explicit
target approval, intensity-gated operations, controlled payloads, rate limits,
and canary destination validation. All offline (no real outbound network).
"""

import time

import pytest

from app.control_plane.canary import SsrfCanary
from app.control_plane.payloads import PayloadCatalog, PayloadNotAllowed
from app.control_plane.policy import PolicyGuard, PolicyValidationError, PolicyViolation, RateLimiter, ScanPolicy
from app.control_plane.scope import ScopeGuard, ScopeViolation, TargetApproval


# ---------------------------------------------------------------- ScopeGuard

def test_scope_denied_by_default():
    assert not ScopeGuard(allowed_targets=[]).validate_target("https://example.com/").allowed


def test_scope_allows_authorized_host():
    guard = ScopeGuard(allowed_targets=["example.com"])
    decision = guard.validate_target("https://example.com/app")
    assert decision.allowed
    assert decision.matches == "example.com"


def test_scope_rejects_unlisted_host():
    guard = ScopeGuard(allowed_targets=["example.com"])
    assert not guard.validate_target("https://evil.example.net/").allowed


def test_scope_rejects_malformed_url():
    assert not ScopeGuard().validate_target("not a url").allowed


def test_scope_rejects_wrong_scheme():
    guard = ScopeGuard(allowed_targets=["example.com"])
    assert not guard.validate_target("ftp://example.com/file").allowed
    assert not guard.validate_target("file:///etc/passwd").allowed


def test_scope_wildcard_subdomain_matches():
    guard = ScopeGuard(allowed_domains=["*.example.com"])
    assert guard.validate_target("https://api.example.com/x").allowed
    assert not guard.validate_target("https://example.com/x").allowed
    assert not guard.validate_target("https://evil.com/x").allowed


def test_scope_blocked_domain_wins_over_allowlist():
    guard = ScopeGuard(allowed_domains=["example.com", "blocked.example.com"], blocked_domains=["blocked.example.com"])
    assert guard.validate_target("https://example.com/").allowed
    assert not guard.validate_target("https://blocked.example.com/").allowed


def test_scope_path_allow_and_deny_globs():
    guard = ScopeGuard(allowed_domains=["127.0.0.1"], denied_paths=["/admin/*", "/private"])
    assert guard.validate_target("http://127.0.0.1:8000/public").allowed
    assert not guard.validate_target("http://127.0.0.1:8000/admin/users").allowed
    assert not guard.validate_target("http://127.0.0.1:8000/private").allowed

    restricted = ScopeGuard(allowed_domains=["127.0.0.1"], allowed_paths=["/public/*"])
    assert restricted.validate_target("http://127.0.0.1:8000/public/x").allowed
    assert not restricted.validate_target("http://127.0.0.1:8000/admin").allowed


def test_scope_method_restriction():
    guard = ScopeGuard(allowed_targets=["example.com"], allowed_methods=["GET", "HEAD"])
    assert guard.validate_target("https://example.com/", method="GET").allowed
    assert not guard.validate_target("https://example.com/", method="POST").allowed
    assert guard.validate_target("https://example.com/", method=None).allowed  # unset method = no restriction


def test_scope_localhost_implicitly_allowed():
    guard = ScopeGuard(allowed_targets=[])
    assert guard.validate_target("http://127.0.0.1:9000/health").allowed
    assert guard.validate_target("http://localhost:9000/health").allowed
    blocked = ScopeGuard(allowed_targets=[], blocked_domains=["localhost"])
    assert not blocked.validate_target("http://localhost:9000/health").allowed


def test_scope_cidr_enforcement():
    guard = ScopeGuard(
        allowed_targets=["127.0.0.1"],
        allowed_cidrs=["127.0.0.0/8"],
        blocked_cidrs=["127.0.0.5/32"],
    )
    assert guard.validate_target("http://127.0.0.1:8000/").allowed
    assert not guard.validate_target("http://127.0.0.5:8000/").allowed  # blocked CIDR


def test_scope_redirect_within_scope_passes():
    guard = ScopeGuard(allowed_targets=["example.com"])
    decision = guard.validate_redirect("https://example.com/a", "https://example.com/b")
    assert decision.allowed


def test_scope_redirect_to_unlisted_host_blocked():
    guard = ScopeGuard(allowed_targets=["example.com"])
    decision = guard.validate_redirect("https://example.com/a", "https://evil.net/b")
    assert not decision.allowed


def test_scope_redirect_https_downgrade_blocked():
    guard = ScopeGuard(allowed_targets=["example.com"])
    decision = guard.validate_redirect("https://example.com/a", "http://example.com/b")
    assert not decision.allowed


def test_scope_check_raises_on_violation():
    guard = ScopeGuard(allowed_targets=["example.com"])
    with pytest.raises(ScopeViolation):
        guard.check("https://evil.net/", scope_kind="runtime")


def test_scope_canary_destination():
    canary = SsrfCanary()
    canary.start()
    try:
        guard = ScopeGuard(allowed_targets=["127.0.0.1"], canary=canary)
        host, port = canary.origin
        assert guard.validate_destination(host=host, port=port).allowed
        assert not guard.validate_destination(host=host, port=port + 1).allowed
        assert not guard.validate_destination(host="169.254.169.254", port=80).allowed  # metadata IP
    finally:
        canary.stop()


# ---------------------------------------------------------------- Payloads

def test_payload_catalog_ids_lookup():
    catalog = PayloadCatalog()
    assert catalog.require("sqli.single-quote").category == "sqli"
    assert catalog.by_id("nope") is None
    with pytest.raises(PayloadNotAllowed):
        catalog.require("nope")


def test_payload_ssrf_placeholder():
    catalog = PayloadCatalog()
    ssrf = catalog.by_id("ssrf.canary")
    assert ssrf is not None and ssrf.value == "{canary}"
    assert catalog.by_id("sqli.boolean-marker") is not None


# -------------------------------------------------------------- PolicyGuard

def _guard(intensity: str, **kwargs) -> PolicyGuard:
    return PolicyGuard(policy=ScanPolicy.from_request(intensity=intensity, rate_limit_rps=100, allowed_methods=["*"]))


def test_policy_enforce_operation_gated_by_intensity():
    passive = _guard("passive")
    with pytest.raises(PolicyViolation):
        passive.enforce_operation("injection")
    active = _guard("active")
    active.enforce_operation("injection")
    with pytest.raises(PolicyViolation):
        active.enforce_operation("ssrf_validation")


def test_policy_enforce_method():
    passive = _guard("passive")
    passive.enforce_method("GET")
    with pytest.raises(PolicyViolation):
        passive.enforce_method("POST")


def test_policy_enforce_payload_injection_requires_injection_op():
    passive, active = _guard("passive"), _guard("active")
    with pytest.raises(PolicyViolation):
        passive.enforce_payload("sqli.single-quote")
    active.enforce_payload("sqli.single-quote")
    with pytest.raises(PolicyViolation):
        active.enforce_payload("ssrf.canary")  # needs ssrf_validation -> aggressive


def test_policy_enforce_payload_unknown_id():
    guard = _guard("aggressive")
    with pytest.raises(PolicyViolation):
        guard.enforce_payload("payload.evil")  # not in controlled catalog


def test_scan_policy_rejects_bad_request():
    with pytest.raises(PolicyValidationError):
        ScanPolicy.from_request(intensity="nuclear", rate_limit_rps=5, allowed_methods=["GET"])


# --------------------------------------------------------------- RateLimiter

async def test_rate_limiter_grants_with_throttle():
    limiter = RateLimiter(rps=5)
    start = time.monotonic()
    await limiter.acquire()  # instant: bucket starts full
    await limiter.acquire()  # waits for one token (~0.2s)
    elapsed = time.monotonic() - start
    assert elapsed >= 0.15
    assert limiter.snapshot()["requests_granted"] == 2


async def test_rate_limiter_high_rps_is_quick():
    limiter = RateLimiter(rps=500)
    start = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    assert time.monotonic() - start < 0.5


# ------------------------------------------------------- Explicit approval

async def test_target_approval_authorizes_in_scope_target(session_factory, db_tables):
    guard = ScopeGuard(allowed_targets=["example.com"])
    approval = await TargetApproval(guard).authorize(
        target="https://example.com/app", principal="admin"
    )
    assert approval.approved


async def test_target_approval_rejects_out_of_scope_target(db_tables):
    guard = ScopeGuard(allowed_targets=["example.com"])
    approval = await TargetApproval(guard).authorize(
        target="https://evil.net/app", principal="admin"
    )
    assert not approval.approved
    assert "evil.net" in approval.reason


async def test_target_approval_is_audited(db_tables):
    from sqlalchemy import select

    from app.core.db import get_session_factory
    from app.models.audit import AuditRecord

    guard = ScopeGuard(allowed_targets=["example.com"])
    await TargetApproval(guard).authorize(target="https://example.com/", principal="admin")
    async with get_session_factory()() as session:
        rows = (await session.execute(
            select(AuditRecord).where(
                AuditRecord.action == "target.approve",
                AuditRecord.target == "https://example.com/",
                AuditRecord.user == "admin",
            )
        )).scalars().all()
    assert len(rows) >= 1
    assert rows[-1].result == "APPROVED"
    assert rows[-1].permission_decision["allowed"] is True