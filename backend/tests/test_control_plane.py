"""Control plane tests: auth, authorization, scope, policy."""

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.control_plane.auth import Principal, require_api_key
from app.control_plane.authorization import AuthorizationDenied, AuthorizationStub, check_or_raise
from app.control_plane.policy import PolicyValidationError, ScanPolicy
from app.control_plane.scope import ScopeGuard, ScopeViolation
from app.core.config import get_settings


@pytest.mark.asyncio
async def test_auth_accepts_valid_key():
    principal = await require_api_key("test-key")
    assert principal.username == get_settings().default_user


@pytest.mark.asyncio
async def test_auth_rejects_missing_key():
    with pytest.raises(HTTPException) as exc:
        await require_api_key(None)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_auth_rejects_wrong_key():
    with pytest.raises(HTTPException):
        await require_api_key("not-the-key")


def test_authorization_denies_anonymous_write():
    with pytest.raises(AuthorizationDenied):
        check_or_raise(None, "write:scan:create")


def test_authorization_allows_authenticated_write():
    check_or_raise(Principal(username="admin"), "write:scan:create")


def test_scope_denied_by_default():
    guard = ScopeGuard(allowed_targets=[])
    assert not guard.validate_target("https://example.com/").allowed


def test_scope_allows_authorized_host():
    guard = ScopeGuard(allowed_targets=["example.com"])
    decision = guard.validate_target("https://example.com/app")
    assert decision.allowed
    assert decision.matches == "example.com"


def test_scope_rejects_malformed_url():
    guard = ScopeGuard()
    with pytest.raises(ScopeViolation):
        guard.check("not a url", scope_kind="runtime")


def test_scope_rejects_unlisted_host():
    guard = ScopeGuard(allowed_targets=["example.com"])
    with pytest.raises(ScopeViolation):
        guard.check("https://evil.example.net/")


def test_policy_validates_intensity():
    policy = ScanPolicy.from_request(intensity="aggressive", rate_limit_rps=5)
    assert policy.intensity.value == "aggressive"
    assert "GET" in policy.allowed_methods
    assert "DELETE" in policy.allowed_methods


def test_policy_allows_wildcard_methods():
    policy = ScanPolicy.from_request(intensity="aggressive", rate_limit_rps=5, allowed_methods=["*"])
    assert "DELETE" in policy.allowed_methods


def test_policy_rejects_bad_intensity():
    with pytest.raises(PolicyValidationError) as err:
        ScanPolicy.from_request(intensity="nuclear", rate_limit_rps=5, allowed_methods=["GET"])
    assert any("intensity" in i for i in err.value.issues)


def test_policy_rejects_method_beyond_intensity():
    with pytest.raises(PolicyValidationError) as err:
        ScanPolicy.from_request(intensity="passive", rate_limit_rps=5, allowed_methods=["POST"])
    assert any("POST" in i for i in err.value.issues)


def test_policy_intensity_gates_operations():
    passive = ScanPolicy.from_request(intensity="passive", rate_limit_rps=5, allowed_methods=["*"])
    active = ScanPolicy.from_request(intensity="active", rate_limit_rps=5, allowed_methods=["*"])
    aggressive = ScanPolicy.from_request(intensity="aggressive", rate_limit_rps=5, allowed_methods=["*"])
    assert passive.allows_operation("read_only")
    assert not passive.allows_operation("injection")
    assert active.allows_operation("injection")
    assert not active.allows_operation("ssrf_validation")
    assert aggressive.allows_operation("ssrf_validation")