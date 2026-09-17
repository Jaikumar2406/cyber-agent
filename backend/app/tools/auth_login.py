"""runtime.auth.login - provision a test identity (phases.md §1.3, §1.6).

Rules.md §3.4: AEGIS never brute-forces and never steals credentials. This tool
only acts on an *operator-supplied, explicitly authorized* test identity from
the controlled credential catalog. The Policy Guard validates the credential id
before execution and requires scan intensity >= active (`cross_user` operation).

The raw session secret (JWT / session cookie) is written ONLY into the scan's
in-memory identity store - never into `output`, which the Executor persists as
evidence (rules.md §5.5/§5.6). Consumers reference identities by id and receive
the redacted summary (sha256 reference + cookie names).
"""

import base64
from typing import Any
from urllib.parse import urljoin

import httpx

from app.core.logging import get_logger
from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult, ToolPermanentError
from app.schemas.common import ToolResultStatus

log = get_logger("aegis.tools.auth_login")

_KINDS = ("form", "basic", "bearer")


class AuthLoginTool(BaseTool):
    name = "runtime.auth.login"
    description = (
        "Provision a test identity (BOLA/BFLA cross-user phase) by authenticating "
        "with an operator-supplied credential id from the controlled catalog. "
        "Requires active+ intensity; secrets never appear in evidence."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "format": "uri",
                "description": "login form action, or endpoint that accepts Basic/Bearer",
            },
            "credential_id": {
                "type": "string",
                "minLength": 1,
                "description": "id in the operator-supplied credential catalog",
            },
            "kind": {
                "type": "string",
                "enum": ["form", "basic", "bearer"],
                "description": "how to submit the credential (default: infer by presence of fields)",
            },
            "username_field": {"type": "string", "default": "username", "minLength": 1},
            "password_field": {"type": "string", "default": "password", "minLength": 1},
            "submit": {"type": "string", "default": "submit", "minLength": 1},
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 30, "default": 10.0},
            "max_redirects": {"type": "integer", "minimum": 0, "maximum": 10, "default": 3},
        },
        "required": ["url", "credential_id"],
    }
    permissions = ("runtime:auth:login", "runtime:http:post")
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("cross_user",)
    credential_fields = ("credential_id",)

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        url = str(args["url"])
        credential_id = str(args["credential_id"])
        kind = str(args.get("kind") or "form")
        timeout = float(args.get("timeout", 10.0))
        max_redirects = int(args.get("max_redirects", 3))

        catalog = getattr(context, "credentials", None)
        identity_store = getattr(context, "identity_store", None)
        if catalog is None or catalog.by_id(credential_id) is None:
            return ToolResult(
                status=ToolResultStatus.POLICY_DENIED,
                error=f"credential {credential_id!r} not available in the operator-supplied catalog",
            )
        if identity_store is None:
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error="auth.login requires an identity store in context (secure secret handling)",
            )
        credential = catalog.by_id(credential_id)
        secrets = {credential.secret}
        username = getattr(credential, "username", "")

        try:
            if kind == "form":
                identity = await self._form_login(args, credential_id, username, credential.secret,
                                                  secrets, context, timeout, max_redirects)
            elif kind == "basic":
                identity = await self._basic_login(url, credential_id, username, credential.secret,
                                                   secrets, context, timeout, max_redirects)
            elif kind == "bearer":
                identity = await self._bearer_login(url, credential_id, credential.secret,
                                                    secrets, context, timeout, max_redirects)
            else:
                return ToolResult(status=ToolResultStatus.FAILURE, error=f"unknown kind {kind!r}")
        except _OutOfScope:
            return ToolResult(
                status=ToolResultStatus.SCOPE_VIOLATION,
                error="login request left authorized scope",
            )
        except httpx.HTTPError as exc:
            return ToolResult(status=ToolResultStatus.FAILURE, error=f"auth request failed: {exc}")

        if identity is None:
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error="authentication was not accepted by the target",
            )

        try:
            stored = identity_store.create(**identity)
        except ValueError as exc:
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error=str(exc),
                output={"identity_conflict": True, "existing": identity_store.redacted_summaries()},
            )
        return ToolResult(
            status=ToolResultStatus.SUCCESS,
            output={
                "identity": stored.redacted(),
                "target": url,
            },
            error=None,
        )

    # --- submission strategies -------------------------------------------------

    async def _form_login(self, args, credential_id, username, secret, secrets, context, timeout, max_redirects):
        url = str(args["url"])
        username_field = str(args.get("username_field", "username"))
        password_field = str(args.get("password_field", "password"))
        submit = str(args.get("submit", "submit"))
        data = {username_field: username, password_field: secret, submit: ""}
        resp, jar = await self._request("POST", url, data=data, secrets=secrets,
                                        context=context, timeout=timeout, max_redirects=max_redirects)
        body = resp.text
        status_code = resp.status_code
        cookie_jar = jar

        token = self._extract_token(body)
        session_secret = token or cookie_jar.get("session") or self._joined_cookies(cookie_jar)
        if session_secret and status_code < 400:
            return {
                "credential_id": credential_id,
                "kind": "form",
                "username": username,
                "session_secret": session_secret,
                "session_cookies": cookie_jar,
                "associated_with": self._final_url(resp, url),
            }
        return None

    async def _basic_login(self, url, credential_id, username, secret, secrets, context, timeout, max_redirects):
        encoded = "Basic " + base64.b64encode(f"{username}:{secret}".encode()).decode()
        resp, jar = await self._request("GET", url, headers={"Authorization": encoded},
                                        secrets=secrets, context=context,
                                        timeout=timeout, max_redirects=max_redirects)
        if resp.status_code < 400:
            return {
                "credential_id": credential_id,
                "kind": "basic",
                "username": username,
                "session_secret": encoded,
                "session_cookies": jar,
                "associated_with": self._final_url(resp, url),
            }
        return None

    async def _bearer_login(self, url, credential_id, secret, secrets, context, timeout, max_redirects):
        resp, jar = await self._request("GET", url, headers={"Authorization": f"Bearer {secret}"},
                                        secrets=secrets, context=context,
                                        timeout=timeout, max_redirects=max_redirects)
        if resp.status_code < 400:
            return {
                "credential_id": credential_id,
                "kind": "bearer",
                "username": "",
                "session_secret": secret,
                "session_cookies": jar,
                "associated_with": self._final_url(resp, url),
            }
        return None

    # --- transport helpers (scope + rate limit per hop) -----------------------

    async def _request(self, method, url, *, headers=None, data=None, secrets,
                       context, timeout, max_redirects):
        scope_guard = context.scope_guard
        if scope_guard is None:
            raise ToolPermanentError("auth.login requires a scope guard in context")
        allowed_methods = (context.policy or {}).get("allowed_methods")
        if allowed_methods and method not in allowed_methods and "*" not in allowed_methods:
            raise ToolPermanentError(f"HTTP method {method!r} not permitted by scan policy")

        current = url
        jar: dict[str, str] = {}
        for _hop in range(max_redirects + 1):
            scope = scope_guard.validate_target(current, method=method)
            if not scope.allowed:
                raise _OutOfScope(f"{current!r} out of scope")
            if context.rate_limiter is not None:
                await context.rate_limiter.acquire()
            async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
                resp = await client.request(method, current, headers=headers, data=data, timeout=timeout)
            jar.update(self._cookies_from(resp))
            if resp.is_redirect:
                location = resp.headers.get("location")
                if not location or _hop >= max_redirects:
                    return resp, jar
                next_url = urljoin(current, location)
                redirect = scope_guard.validate_redirect(current, next_url)
                if not redirect.allowed:
                    raise _OutOfScope(f"redirect {next_url!r} out of scope")
                current = next_url
                if method in ("POST",) and resp.status_code in (302, 303):
                    method = "GET"
                    data = None
                continue
            return resp, jar
        raise httpx.TransportError("redirect limit exceeded")

    @staticmethod
    def _cookies_from(resp) -> dict[str, str]:
        jar: dict[str, str] = {}
        values = resp.headers.get_list("set-cookie") or ([resp.headers.get("set-cookie")] if resp.headers.get("set-cookie") else [])
        for raw in values:
            if not raw:
                continue
            name, _, rest = raw.partition("=")
            if not name:
                continue
            value = rest.split(";", 1)[0]
            jar[name.strip()] = value.strip()
        return jar

    @staticmethod
    def _extract_token(body: str) -> str | None:
        import re
        match = re.search(r"\"?(?:access_token|token|jwt|id_token)\"?\s*[:=]\s*\"([A-Za-z0-9_.\-]{12,})\"", body or "")
        return match.group(1) if match else None

    @staticmethod
    def _joined_cookies(jar: dict[str, str]) -> str | None:
        return "&".join(f"{k}={v}" for k, v in jar.items()) if jar else None

    @staticmethod
    def _final_url(resp, fallback):
        return str(resp.url) if getattr(resp, "url", None) else fallback


class _OutOfScope(Exception):
    pass