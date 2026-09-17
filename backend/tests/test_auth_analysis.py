"""Phase 1.3 - unit tests for authentication analysis and controlled credentials.

Detector (pure, no network) + IdentityStore + CredentialCatalog
"""

import pytest

from app.auth_analysis.detector import (
    detect_all,
    detect_from_headers,
    detect_from_html,
    detect_from_openapi,
    summarize,
)
from app.auth_analysis.identity import IdentityStore, MAX_IDENTITIES, IdentityRecord
from app.control_plane.credentials import CredentialCatalog, CredentialNotAllowed, get_empty_credential_catalog
from app.schemas.common import Confidence

# ---------------------------------------------------------------------------
# Detector: headers
# ---------------------------------------------------------------------------

class TestHeadersDetection:
    def test_bearer_jwt_confirmed(self):
        hints = detect_from_headers({"WWW-Authenticate": 'Bearer realm="api"'})
        assert len(hints) == 1
        h = hints[0]
        assert h.kind == "jwt"
        assert h.confidence == Confidence.CONFIRMED.value
        assert h.source == "header"

    def test_basic_confirmed(self):
        hints = detect_from_headers({"WWW-Authenticate": "Basic"})
        assert len(hints) == 1
        assert hints[0].kind == "basic"

    def test_cookie_confirmed(self):
        hints = detect_from_headers({"Set-Cookie": "session=abc123; Path=/; HttpOnly"})
        assert len(hints) == 1
        assert hints[0].kind == "cookie"

    def test_oauth_from_location(self):
        hints = detect_from_headers({"Location": "https://app.example.com/authorize?client_id=123"})
        assert len(hints) == 1
        assert hints[0].kind == "oauth"
        assert hints[0].confidence == Confidence.PROBABLE.value

    def test_empty_headers(self):
        hints = detect_from_headers({})
        assert hints == []

    def test_none_headers(self):
        hints = detect_from_headers(None)
        assert hints == []

    def test_unrelated_headers_no_hints(self):
        hints = detect_from_headers({"Content-Type": "text/html", "X-Frame-Options": "DENY"})
        assert hints == []

    def test_both_bearer_and_cookie(self):
        hints = detect_from_headers({
            "WWW-Authenticate": "Bearer",
            "Set-Cookie": "auth=xyz; HttpOnly",
        })
        kinds = {h.kind for h in hints}
        assert kinds == {"jwt", "cookie"}

    def test_dedupe_identical_signals(self):
        hints = detect_from_headers({"WWW-Authenticate": "Bearer"})
        assert len(hints) == 1

# ---------------------------------------------------------------------------
# Detector: HTML
# ---------------------------------------------------------------------------

class TestHtmlDetection:
    def test_password_form_detected(self):
        html = '<form action="/login" method="POST"><input type="text" name="username"/><input type="password" name="password"/></form>'
        hints = detect_from_html(html, base_url="http://app/login")
        assert len(hints) == 1
        assert hints[0].kind == "credentials"
        assert hints[0].confidence == Confidence.PROBABLE.value
        assert hints[0].detail["password_field"] is True

    def test_oauth_sign_in_link(self):
        html = '<a href="/oauth/authorize">Sign in with OAuth</a>'
        hints = detect_from_html(html, base_url="http://app/")
        assert any(h.kind == "oauth" and h.confidence == Confidence.POTENTIAL.value for h in hints)

    def test_empty_html(self):
        assert detect_from_html("") == []

    def test_none_html(self):
        assert detect_from_html(None) == []

    def test_no_password_no_hints(self):
        html = '<form><input type="text" name="q"/></form>'
        assert detect_from_html(html) == []

# ---------------------------------------------------------------------------
# Detector: OpenAPI
# ---------------------------------------------------------------------------

class TestOpenApiDetection:
    def test_jwt_bearer_scheme(self):
        doc = {"components": {"securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}}}}
        hints = detect_from_openapi(doc)
        assert len(hints) == 1
        assert hints[0].kind == "jwt"
        assert hints[0].confidence == Confidence.PROBABLE.value

    def test_basic_scheme(self):
        doc = {"components": {"securitySchemes": {"BasicAuth": {"type": "http", "scheme": "basic"}}}}
        hints = detect_from_openapi(doc)
        assert hints[0].kind == "basic"

    def test_apikey_scheme(self):
        doc = {"components": {"securitySchemes": {"ApiKey": {"type": "apiKey", "in": "header", "name": "X-Api-Key"}}}}
        hints = detect_from_openapi(doc)
        assert hints[0].kind == "api_key"
        assert hints[0].detail["in"] == "header"

    def test_oauth2_scheme(self):
        doc = {"components": {"securitySchemes": {"OAuth": {"type": "oauth2"}}}}
        hints = detect_from_openapi(doc)
        assert hints[0].kind == "oauth"

    def test_empty_doc(self):
        assert detect_from_openapi({}) == []

    def test_none_doc(self):
        assert detect_from_openapi(None) == []

    def test_multiple_schemes(self):
        doc = {"components": {"securitySchemes": {
            "B": {"type": "http", "scheme": "bearer"},
            "K": {"type": "apiKey", "in": "header", "name": "X-Key"},
        }}}
        kinds = {h.kind for h in detect_from_openapi(doc)}
        assert kinds == {"jwt", "api_key"}

# ---------------------------------------------------------------------------
# Detector: summarize
# ---------------------------------------------------------------------------

class TestSummarize:
    def test_groups_by_kind_keeps_best_confidence(self):
        from app.auth_analysis.detector import MechanismHint
        hints = [
            MechanismHint("jwt", Confidence.PROBABLE.value, "openapi", {"name": "Auth"}),
            MechanismHint("jwt", Confidence.CONFIRMED.value, "header", {"header": "WWW-Authenticate"}),
        ]
        s = summarize(hints)
        assert s["count"] == 1
        jwt_mech = s["mechanisms"][0]
        assert jwt_mech["kind"] == "jwt"
        assert jwt_mech["confidence"] == Confidence.CONFIRMED.value
        assert "header" in jwt_mech["sources"]
        assert "openapi" in jwt_mech["sources"]

    def test_safe_detail_keys_only(self):
        from app.auth_analysis.detector import MechanismHint
        hints = [MechanismHint("jwt", Confidence.PROBABLE.value, "openapi",
                               {"name": "Auth", "secret_value": "LEAKED"})]
        s = summarize(hints)
        detail = s["mechanisms"][0]["detail"]
        assert "name" in detail
        assert "secret_value" not in detail

# ---------------------------------------------------------------------------
# IdentityStore
# ---------------------------------------------------------------------------

class TestIdentityStore:
    def test_create_and_retrieve(self):
        store = IdentityStore()
        identity = store.create(
            credential_id="alice",
            kind="form",
            username="alice",
            session_secret="sess-token-abc",
            session_cookies={"session": "abc123"},
            associated_with="http://app/login",
        )
        assert identity.credential_id == "alice"
        assert identity.session_secret == "sess-token-abc"
        assert store.count() == 1
        assert store.get(identity.identity_id) is identity
        assert store.by_credential("alice") is identity

    def test_max_identities_enforced(self):
        store = IdentityStore()
        store.create(credential_id="alice", kind="form", username="alice")
        store.create(credential_id="bob", kind="basic", username="bob")
        with pytest.raises(ValueError, match="identity store full"):
            store.create(credential_id="carol", kind="bearer", username="carol")

    def test_duplicate_credential_rejected(self):
        store = IdentityStore()
        store.create(credential_id="alice", kind="form", username="alice")
        with pytest.raises(ValueError, match="already provisioned"):
            store.create(credential_id="alice", kind="form", username="alice2")

    def test_redacted_summary_hides_secret(self):
        store = IdentityStore()
        identity = store.create(
            credential_id="bob", kind="bearer", username="bob",
            session_secret="sk-super-secret-value",
            session_cookies={"sid": "abc123"},
        )
        summaries = store.redacted_summaries()
        assert len(summaries) == 1
        s = summaries[0]
        assert s["credential_id"] == "bob"
        assert s["kind"] == "bearer"
        assert s["session_ref"] is not None  # sha256 hex ref
        assert "sk-super-secret-value" not in str(s)
        assert s["cookie_names"] == ["sid"]

    def test_empty_store(self):
        store = IdentityStore()
        assert store.count() == 0
        assert store.redacted_summaries() == []

# ---------------------------------------------------------------------------
# CredentialCatalog
# ---------------------------------------------------------------------------

class TestCredentialCatalog:
    def test_empty_default(self):
        cat = get_empty_credential_catalog()
        assert len(cat) == 0
        assert cat.by_id("anything") is None
        with pytest.raises(CredentialNotAllowed):
            cat.require("anything")

    def test_custom_catalog(self):
        creds = [
            {"id": "alice", "kind": "form", "username": "alice", "secret": "pw", "description": "alice"},
            {"id": "bob", "kind": "basic", "username": "bob", "secret": "pw2", "description": "bob"},
        ]
        cat = CredentialCatalog(credentials=creds)
        assert len(cat) == 2
        assert cat.by_id("alice").username == "alice"
        assert cat.by_id("bob").kind == "basic"

    def test_dict_format(self):
        creds = {"alice": {"kind": "bearer", "username": "alice", "secret": "tok", "description": "alice"}}
        cat = CredentialCatalog(credentials=creds)
        assert len(cat) == 1
        assert cat.require("alice").secret == "tok"

    def test_require_unknown_raises(self):
        cat = CredentialCatalog([{"id": "a", "kind": "form", "username": "a", "secret": "s", "description": "a"}])
        with pytest.raises(CredentialNotAllowed):
            cat.require("mallory")

    def test_describe_redacts_secret(self):
        cat = CredentialCatalog([{"id": "a", "kind": "form", "username": "a", "secret": "supersecret", "description": "a"}])
        listing = cat.describe()
        assert len(listing) == 1
        assert listing[0]["id"] == "a"
        assert "supersecret" not in str(listing)
        assert "secret" not in listing[0]  # no 'secret' key in describe output

    def test_duplicate_id_raises(self):
        with pytest.raises(ValueError, match="duplicate"):
            CredentialCatalog([
                {"id": "a", "kind": "form", "username": "a", "secret": "s1", "description": "1"},
                {"id": "a", "kind": "form", "username": "a2", "secret": "s2", "description": "2"},
            ])

    def test_invalid_kind_raises(self):
        with pytest.raises(ValueError, match="kind must be"):
            CredentialCatalog([{"id": "a", "kind": "oauth", "username": "a", "secret": "s", "description": "d"}])

    def test_missing_required_key_raises(self):
        with pytest.raises(ValueError, match="missing required key"):
            CredentialCatalog([{"id": "a", "kind": "form"}])