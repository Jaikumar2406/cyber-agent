"""Phase 1.5 - pure security-test detectors (offline unit tests).

Exercises deterministic detection logic in app.testing.* without any
network I/O: header misconfig, cookie flags, injection signals,
BOLA/BFLA classification and SSRF parameter heuristics.
"""

from app.control_plane.payloads import get_payload_catalog
from app.schemas.common import Confidence, Severity
from app.testing import access_control, auth_session, injection, misconfig, ssrf
from app.testing.finding import (
    ACCESS_CONTROL_ASYMMETRY,
    AUTH_WEAKNESS,
    BFLA,
    BOLA,
    INJECTION,
    MISCONFIGURATION,
    SSRF,
    Finding,
)


class TestFindingModel:
    def test_id_is_deterministic(self):
        a = Finding(title="t", category=MISCONFIGURATION, severity="LOW",
                    confidence="CONFIRMED", endpoint="GET http://x/",
                    summary="s", remediation="r", detector="d")
        b = Finding(title="t", category=MISCONFIGURATION, severity="LOW",
                    confidence="CONFIRMED", endpoint="GET http://x/",
                    summary="s", remediation="r", detector="d")
        assert a.id == b.id
        assert a.id.startswith("F-")

    def test_as_dict_is_json_ready(self):
        f = Finding(title="t", category=INJECTION, severity="HIGH",
                    confidence="PROBABLE", endpoint="GET http://x/",
                    summary="s", remediation="r", evidence={"a": 1},
                    payload_id="sqli.single-quote")
        d = f.as_dict()
        assert d["payload_id"] == "sqli.single-quote"
        assert d["category"] == INJECTION
        assert d["evidence"]["a"] == 1


class TestMisconfig:
    def _analyze(self, headers, status=200, path="/", url="https://app/x"):
        return misconfig.analyze_headers(
            method="GET", url=url, path=path, status_code=status, headers=headers,
        )

    def test_missing_security_headers_flagged(self):
        findings = self._analyze({"content-type": "text/html"})
        titles = {f.title for f in findings}
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("X-Content-Type-Options" in t for t in titles)
        assert all(f.category == MISCONFIGURATION for f in findings)

    def test_hsts_only_checked_over_https(self):
        http_findings = self._analyze({}, url="http://app/x")
        assert not any("Strict-Transport-Security" in f.title for f in http_findings)
        https_findings = self._analyze({}, url="https://app/x")
        assert any("Strict-Transport-Security" in f.title for f in https_findings)

    def test_security_headers_present_no_finding(self):
        headers = {
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "strict-transport-security": "max-age=31536000",
        }
        assert self._analyze(headers, url="https://app/x") == []

    def test_non_success_not_analyzed(self):
        assert self._analyze({}, status=404) == []

    def test_permissive_cors_flagged(self):
        findings = self._analyze({
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        })
        cors = [f for f in findings if f.detector == "misconfig.cors"]
        assert cors and cors[0].severity == Severity.HIGH

    def test_wildcard_without_credentials_not_flagged(self):
        findings = self._analyze({"access-control-allow-origin": "*"})
        assert not any(f.detector == "misconfig.cors" for f in findings)

    def test_banner_disclosure(self):
        findings = self._analyze({"server": "nginx/1.2.3"})
        assert any(f.detector == "misconfig.banner" for f in findings)

    def test_debug_endpoint_flagged(self):
        findings = self._analyze({}, path="/actuator/env")
        debug = [f for f in findings if f.detector == "misconfig.debug_endpoint"]
        assert debug and debug[0].confidence == Confidence.PROBABLE

    def test_verbose_error_body(self):
        assert misconfig.detect_verbose_error("Traceback (most recent call last):") is not None
        assert misconfig.detect_verbose_error("all good") is None
        findings = misconfig.analyze_body(
            method="GET", url="https://app/x", body="... SQLSTATE[42000] ...",
        )
        assert findings and findings[0].cwe == "CWE-209"


class TestAuthSession:
    def test_parse_set_cookie(self):
        cookie = auth_session.parse_set_cookie("sid=abc; Path=/; HttpOnly; Secure")
        assert cookie.name == "sid"
        assert cookie.has("httponly") and cookie.has("secure")
        assert auth_session.parse_set_cookie("") is None
        assert auth_session.parse_set_cookie("novalue") is None

    def test_insecure_cookie_flags(self):
        findings = auth_session.analyze_cookies(
            url="http://app/", set_cookie_headers=["sessionid=abc; Path=/"],
        )
        detectors = {f.detector for f in findings}
        assert "auth_session.cookie_httponly" in detectors
        assert "auth_session.cookie_samesite" in detectors
        assert "auth_session.cleartext_session" in detectors
        assert all(f.category == AUTH_WEAKNESS for f in findings)

    def test_secure_cookie_over_https_no_findings(self):
        findings = auth_session.analyze_cookies(
            url="https://app/",
            set_cookie_headers=["sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"],
        )
        assert findings == []

    def test_httponly_only_missing_on_https(self):
        findings = auth_session.analyze_cookies(
            url="https://app/",
            set_cookie_headers=["sid=abc; Path=/; HttpOnly; Secure"],
        )
        detectors = {f.detector for f in findings}
        assert detectors == {"auth_session.cookie_samesite"}

    def test_cookie_value_never_in_evidence(self):
        findings = auth_session.analyze_cookies(
            url="http://app/", set_cookie_headers=["session=SUPERSECRET; Path=/"],
        )
        blob = str([f.as_dict() for f in findings])
        assert "SUPERSECRET" not in blob

    def test_basic_auth_mechanism(self):
        findings = auth_session.analyze_auth_mechanism(
            url="https://app/", auth_analysis={"mechanisms": [{"kind": "basic"}]},
        )
        assert findings and findings[0].detector == "auth_session.basic_auth"


class TestInjectionDetectors:
    def _payload(self, pid):
        return get_payload_catalog().by_id(pid)

    def test_sql_error(self):
        assert injection.detect_sql_error("... SQLSTATE[42000] ...") == "sqlstate["
        assert injection.detect_sql_error("normal") is None

    def test_cmdi_marker(self):
        assert injection.detect_cmdi_marker("x AEGIS_CMD_INJECTION_MARKER y")
        assert not injection.detect_cmdi_marker("x y")

    def test_ssti_evaluation(self):
        assert injection.detect_ssti("{{7*7}}", "result: 49")
        assert not injection.detect_ssti("{{7*7}}", "echo: {{7*7}}")
        assert not injection.detect_ssti("{{7*7}}", "no number")

    def test_reflection(self):
        assert injection.detect_reflection("marker123", "body marker123 end")
        assert not injection.detect_reflection("marker123", "body other end")

    def test_body_divergence(self):
        assert injection.body_diverges("hello", "hello world xxxxxxxxxx")
        assert not injection.body_diverges("hello", "hello")

    def test_timing_delta(self):
        assert injection.timing_delta(50.0, 300.0, threshold_ms=150.0)
        assert not injection.timing_delta(50.0, 60.0, threshold_ms=150.0)

    def test_detect_sqli_error(self):
        payload = self._payload("sqli.single-quote")
        det = injection.detect(
            payload=payload, baseline_body="ok", injected_body="SQLSTATE[42000]",
            baseline_status=200, injected_status=200, baseline_ms=10.0, injected_ms=10.0,
        )
        assert det.hit and det.confidence == "PROBABLE"

    def test_detect_cmdi(self):
        payload = self._payload("cmdi.echo-marker")
        det = injection.detect(
            payload=payload, baseline_body="ok",
            injected_body="output: AEGIS_CMD_INJECTION_MARKER",
            baseline_status=200, injected_status=200, baseline_ms=10.0, injected_ms=10.0,
        )
        assert det.hit and det.confidence == "CONFIRMED"

    def test_detect_ssti(self):
        payload = self._payload("ssti.math-marker")
        det = injection.detect(
            payload=payload, baseline_body="ok", injected_body="result: 49",
            baseline_status=200, injected_status=200, baseline_ms=10.0, injected_ms=10.0,
        )
        assert det.hit and det.confidence == "PROBABLE"

    def test_detect_xss_reflected(self):
        payload = self._payload("xss.img-marker")
        det = injection.detect(
            payload=payload, baseline_body="ok",
            injected_body='echo: <img src="x" onerror="window.__aegisReflected=1">',
            baseline_status=200, injected_status=200, baseline_ms=10.0, injected_ms=10.0,
        )
        assert det.hit and det.confidence == "CONFIRMED"

    def test_detect_sqli_timing(self):
        payload = self._payload("sqli.time-marker")
        det = injection.detect(
            payload=payload, baseline_body="ok", injected_body="ok",
            baseline_status=200, injected_status=200, baseline_ms=10.0, injected_ms=300.0,
        )
        assert det.hit and det.confidence == "PROBABLE"


class TestAccessControl:
    def test_is_privileged(self):
        assert access_control.is_privileged_endpoint("DELETE", "/api/items")
        assert access_control.is_privileged_endpoint("GET", "/admin/users")
        assert not access_control.is_privileged_endpoint("GET", "/api/items")

    def test_bola_found_identical_body(self):
        finding = access_control.classify_pair(
            method="GET", url="http://app/api/1", path="/api/1",
            status_a=200, body_a='{"data":"x"}',
            status_b=200, body_b='{"data":"x"}',
            identity_a={"id": "a"}, identity_b={"id": "b"},
        )
        assert finding is not None
        assert finding.category == BOLA
        assert finding.confidence == Confidence.POTENTIAL

    def test_no_finding_different_bodies(self):
        finding = access_control.classify_pair(
            method="GET", url="http://app/api/1", path="/api/1",
            status_a=200, body_a='{"user":"alice"}',
            status_b=200, body_b='{"user":"bob"}',
            identity_a={"id": "a"}, identity_b={"id": "b"},
        )
        assert finding is None

    def test_bfla_privileged_reachable(self):
        finding = access_control.classify_pair(
            method="GET", url="http://app/admin/users", path="/admin/users",
            status_a=200, body_a="list",
            status_b=403, body_b="denied",
            identity_a={"id": "a"}, identity_b={"id": "b"},
        )
        assert finding is not None
        assert finding.category == BFLA
        assert finding.confidence == Confidence.PROBABLE

    def test_asymmetry_non_privileged(self):
        finding = access_control.classify_pair(
            method="GET", url="http://app/dashboard", path="/dashboard",
            status_a=200, body_a="ok",
            status_b=403, body_b="denied",
            identity_a={"id": "a"}, identity_b={"id": "b"},
        )
        assert finding is not None
        assert finding.category == ACCESS_CONTROL_ASYMMETRY

    def test_no_finding_both_forbidden(self):
        finding = access_control.classify_pair(
            method="GET", url="http://app/x", path="/x",
            status_a=403, body_a="denied",
            status_b=403, body_b="denied",
            identity_a={"id": "a"}, identity_b={"id": "b"},
        )
        assert finding is None


class TestSsrfHelpers:
    def test_is_url_param(self):
        assert ssrf.is_url_param("url")
        assert ssrf.is_url_param("redirect_uri")
        assert ssrf.is_url_param("callback")
        assert not ssrf.is_url_param("name")
        assert not ssrf.is_url_param("q")

    def test_find_url_params(self):
        result = ssrf.find_url_params(["q", "url", "name", "redirect"])
        assert result == ["url", "redirect"]

    def test_hit_evidence_no_secrets(self):
        class FakeHit:
            hit_id = "h1"
            method = "GET"
            path = "/probe"
            remote_addr = "127.0.0.1"
            timestamp = "2026-01-01"
        ev = ssrf.hit_evidence(FakeHit())
        assert ev["method"] == "GET"
        assert ev["path"] == "/probe"
