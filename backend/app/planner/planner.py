"""Deterministic Deep Agent planner + re-planner (phases.md §1.9).

The planner is the AUTHORITY for what the mode-1 scan does. It is pure Python
(no DB, no network, no LLM): given a target, the effective scan policy, and a
capability report it returns an ordered Stage/PlanTask graph.

Stages (Mode 1 runtime slice):
    discovery    crawl + openapi + auth.analyze           (parallel, deps none)
    model        model.build over the discovery outputs   (deps: all discovery)
    tests        misconfig/auth_session/injection/access_control/ssrf/nuclei
    report       (no tool node - handled by the reporting slice)

Re-planner (phases.md §1.9: "adjusts test plan when discovery reveals new
endpoints"): after a model refresh, endpoints that discovery surfaced but the
current test plan does not yet cover (auth-discovered login URLs, operator-hint
URLs) yield ADDITIONAL test tasks. Idempotent - already-covered endpoints never
yield duplicates. The LLM ("Deep Agent Supervisor") may annotate this plan but
never changes it (rules.md §2 - truth flows upward from engines).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from app.control_plane.policy import OPERATIONS_BY_INTENSITY, ScanPolicy
from app.schemas.common import Intensity

# Controlled payload ids chosen per intensity (bundled catalog, rules.md §3.8).
ACTIVE_PAYLOAD_IDS: tuple[str, ...] = (
    "sqli.single-quote",
    "cmdi.echo-marker",
    "ssti.math-marker",
    "xss.img-marker",
)
AGGRESSIVE_PAYLOAD_IDS: tuple[str, ...] = (
    "sqli.boolean-marker",
    "sqli.time-marker",
    "ssti.dollar-marker",
    *ACTIVE_PAYLOAD_IDS,
)

STAGE_DISCOVERY = "discovery"
STAGE_MODEL = "model"
STAGE_TESTS = "tests"
STAGE_REPORT = "report"

STAGE_ORDER = (STAGE_DISCOVERY, STAGE_MODEL, STAGE_TESTS, STAGE_REPORT)


@dataclass(frozen=True)
class Capabilities:
    """What tooling/assets a scan can actually call on (computed by the runner)."""

    payload_ids: tuple[str, ...] = ()  # injection payload ids permitted by intensity
    credential_ids: tuple[str, ...] = ()  # operator-supplied test identities
    nuclei_available: bool = False  # offline nuclei binary + bundled templates
    max_injection_targets: int = 10
    max_ssrf_targets: int = 10
    max_endpoints_per_test: int = 25


@dataclass(frozen=True)
class PlanTask:
    id: str
    tool: str
    """Name of the registered runtime tool, or the reserved marker ``report``."""

    args: dict[str, Any] = field(default_factory=dict)
    deps: tuple[str, ...] = ()
    stage: str = STAGE_TESTS
    note: str | None = None

    @property
    def is_tool(self) -> bool:
        return self.tool != "report"


def task_id(stage: str, tool: str, suffix: str) -> str:
    digest = hashlib.sha256(f"{stage}:{tool}:{suffix}".encode("utf-8")).hexdigest()[:8]
    return f"{stage}.{tool}.{digest}"


@dataclass
class RuntimePlan:
    target: str
    intensity: str
    stages: list[str] = field(default_factory=lambda: list(STAGE_ORDER))
    tasks: list[PlanTask] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    llm_annotations: list[str] = field(default_factory=list)

    def task_ids(self) -> set[str]:
        return {t.id for t in self.tasks}

    def summary(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "intensity": self.intensity,
            "stages": self.stages,
            "tasks": [
                {
                    "id": t.id,
                    "tool": t.tool,
                    "stage": t.stage,
                    "deps": list(t.deps),
                    "args": t.args,
                    "note": t.note,
                }
                for t in self.tasks
            ],
            "notes": self.notes,
            "llm_annotations": self.llm_annotations,
        }


def _operations(policy: ScanPolicy | None) -> frozenset[str]:
    if policy is None:
        return OPERATIONS_BY_INTENSITY[Intensity.PASSIVE]
    return OPERATIONS_BY_INTENSITY[policy.intensity]


def _payload_ids_for(policy: ScanPolicy | None) -> tuple[str, ...]:
    if policy is None or policy.intensity == Intensity.PASSIVE:
        return ()
    if policy.intensity == Intensity.AGGRESSIVE:
        return AGGRESSIVE_PAYLOAD_IDS
    return ACTIVE_PAYLOAD_IDS


def _capabilities_for(policy: ScanPolicy | None, capabilities: Capabilities | None) -> Capabilities:
    capabilities = capabilities or Capabilities()
    if capabilities.payload_ids:
        return capabilities
    return Capabilities(
        payload_ids=_payload_ids_for(policy),
        credential_ids=capabilities.credential_ids,
        nuclei_available=capabilities.nuclei_available,
        max_injection_targets=capabilities.max_injection_targets,
        max_ssrf_targets=capabilities.max_ssrf_targets,
        max_endpoints_per_test=capabilities.max_endpoints_per_test,
    )


class Mode1Planner:
    """Builds the deterministic Mode-1 plan for (target, policy, capabilities)."""

    def __init__(self, *, capabilities: Capabilities | None = None) -> None:
        self.capabilities = capabilities

    def plan(
        self,
        *,
        target_url: str,
        policy: ScanPolicy | None = None,
        capabilities: Capabilities | None = None,
        hint_endpoints: list[str] | None = None,
    ) -> RuntimePlan:
        capabilities = _capabilities_for(policy, capabilities or self.capabilities)
        operations = _operations(policy)

        plan = RuntimePlan(target=target_url, intensity=policy.intensity.value if policy else Intensity.PASSIVE.value)
        plan.notes.append("deterministic mode-1 plan: discovery -> auth -> model -> tests")

        # --- Stage discovery -------------------------------------------------
        plan.tasks.append(
            PlanTask(
                id="probe.echo",
                tool="echo",
                args={"text": f"aegis-probe:{_short(target_url)}", "iterations": 1, "delay_ms": 5.0},
                stage=STAGE_DISCOVERY,
                note="harness path integrity probe (Phase 0 contract)",
            )
        )
        plan.tasks.append(
            PlanTask(
                id="discovery.crawl",
                tool="runtime.discovery.crawl",
                args={"url": target_url},
                stage=STAGE_DISCOVERY,
                note="same-host crawl of the target origin",
            )
        )
        plan.tasks.append(
            PlanTask(
                id="discovery.openapi",
                tool="runtime.discovery.openapi",
                args={"url": target_url},
                stage=STAGE_DISCOVERY,
                note="probe for a hosted OpenAPI/Swagger spec",
            )
        )
        plan.tasks.append(
            PlanTask(
                id="auth.analyze",
                tool="runtime.auth.analyze",
                args={"url": target_url},
                stage=STAGE_DISCOVERY,
                note="passive auth-mechanism classification",
            )
        )

        # --- Stage model ------------------------------------------------------
        plan.tasks.append(
            PlanTask(
                id="model.build",
                tool="runtime.model.build",
                args={},
                stage=STAGE_MODEL,
                deps=("discovery.crawl", "discovery.openapi", "auth.analyze"),
                note="merge discovery outputs + HTTP sampling into the Application Model",
            )
        )

        # --- Stage tests: planning notes (tasks built after model exists) --------
        if capabilities.payload_ids:
            plan.notes.append(
                f"injection enabled at {plan.intensity} (payloads: {', '.join(capabilities.payload_ids)})"
            )
        else:
            plan.notes.append("injection not planned (requires active+ intensity)")
        if "ssrf_validation" in operations:
            plan.notes.append("ssrf canary validation enabled (aggressive intensity)")
        else:
            plan.notes.append("ssrf not planned (requires aggressive intensity)")
        if not capabilities.credential_ids:
            plan.notes.append("no operator-supplied credentials: cross-user tests are not planned")
        if capabilities.nuclei_available:
            plan.notes.append("offline nuclei engine available - active template checks planned")
        else:
            plan.notes.append("offline nuclei engine not available - nuclei stage skipped")
        plan.notes.append(
            f"operator hints: {len(hint_endpoints or [])} additional endpoint(s) seeded for re-planning"
        )

        return plan

    def plan_tests(
        self,
        model: dict[str, Any],
        *,
        target_url: str,
        policy: ScanPolicy | None = None,
        capabilities: Capabilities | None = None,
    ) -> list[PlanTask]:
        """Build the test-stage tasks from a built Application Model dict.

        Pure function of the model: misconfig/auth_session always; injection on
        any queried endpoint under active+; cross-user access-control when test
        identities exist; SSRF under aggressive; nuclei when available.
        """
        capabilities = _capabilities_for(policy, capabilities or self.capabilities)
        operations = _operations(policy)
        endpoints = model.get("endpoints") or []
        login_endpoints = model.get("login_endpoints") or []
        tasks: list[PlanTask] = []

        # --- misconfig: pure analysis of the model (read-only, always) ----------
        tasks.append(
            PlanTask(
                id=task_id(STAGE_TESTS, "misconfig", target_url),
                tool="runtime.test.misconfig",
                args={"application_model": model},
                stage=STAGE_TESTS,
                note="missing headers / permissive CORS / banner / debug endpoints",
            )
        )

        # --- auth_session: check user-facing URLs for cookie hygiene -------------
        auth_urls = _unique_urls([*[ep.get("url") for ep in endpoints], *login_endpoints, target_url])
        if auth_urls:
            tasks.append(
                PlanTask(
                    id=task_id(STAGE_TESTS, "auth_session", target_url),
                    tool="runtime.test.auth_session",
                    args={"urls": auth_urls, "auth_analysis": model.get("auth_mechanism_summary") or {}},
                    stage=STAGE_TESTS,
                    note="cookie attributes (HttpOnly/Secure/SameSite) + transport checks",
                )
            )

        # --- injection: queried endpoints only, active+ -------------------------
        if capabilities.payload_ids:
            injection_targets = self._queried_endpoints(endpoints, policy)[: capabilities.max_injection_targets]
            if injection_targets:
                tasks.append(
                    PlanTask(
                        id=task_id(STAGE_TESTS, "injection", target_url),
                        tool="runtime.test.injection",
                        args={
                            "targets": injection_targets,
                            "payload_ids": list(capabilities.payload_ids),
                        },
                        stage=STAGE_TESTS,
                        note="controlled injection payloads on discovered query parameters",
                    )
                )

        # --- access_control: BOLA/BFLA with two provisioned identities ----------
        if len(capabilities.credential_ids) >= 2 and "cross_user" in operations:
            tasks.append(
                PlanTask(
                    id=task_id(STAGE_TESTS, "access_control", target_url),
                    tool="runtime.test.access_control",
                    args={"application_model": model, "identity_ids": list(capabilities.credential_ids[:2])},
                    stage=STAGE_TESTS,
                    note="cross-identity BOLA/BFLA replay over protected endpoints",
                )
            )

        # --- ssrf: canary proof under aggressive intensity -----------------------
        if "ssrf_validation" in operations:
            targets = self._queried_endpoints(endpoints, policy)[: capabilities.max_ssrf_targets]
            if targets:
                tasks.append(
                    PlanTask(
                        id=task_id(STAGE_TESTS, "ssrf", target_url),
                        tool="runtime.test.ssrf",
                        args={"targets": targets},
                        stage=STAGE_TESTS,
                        note="canary-based SSRF proof over URL parameters",
                    )
                )

        # --- nuclei: offline engine ----------------------------------------------
        if capabilities.nuclei_available:
            tasks.append(
                PlanTask(
                    id=task_id(STAGE_TESTS, "nuclei", target_url),
                    tool="runtime.test.nuclei",
                    args={"application_model": model},
                    stage=STAGE_TESTS,
                    note="offline bundled-template security checks",
                )
            )

        return tasks

    def replan(
        self,
        previous: RuntimePlan,
        *,
        model: dict[str, Any],
        policy: ScanPolicy | None = None,
        capabilities: Capabilities | None = None,
        discovered_endpoints: list[str] | None = None,
    ) -> list[PlanTask]:
        """Re-planner: extra test tasks for endpoints discovery surfaced but the
        current plan does not yet cover.

        ``covered`` is every URL already handled by a test task in ``previous``.
        New candidates are discovered model/login/hint endpoints not covered.
        Returns an empty list when discovery added nothing new (idempotent).
        """
        capabilities = _capabilities_for(policy, capabilities or self.capabilities)
        endpoints = model.get("endpoints") or []
        login_endpoints = model.get("login_endpoints") or []
        candidates = _unique_urls(
            [*[ep.get("url") for ep in endpoints], *login_endpoints, *(discovered_endpoints or [])]
        )
        non_tool = [t for t in previous.tasks if t.is_tool]
        covered = set()
        for task in non_tool:
            if task.tool == "runtime.test.auth_session":
                covered.update(task.args.get("urls") or [])
            elif task.tool in ("runtime.test.injection", "runtime.test.ssrf"):
                covered.update(t.get("url") for t in (task.args.get("targets") or []))
            elif task.tool in ("runtime.test.misconfig", "runtime.test.nuclei"):
                covered.update(ep.get("url") for ep in (task.args.get("application_model") or {}).get("endpoints") or [])
            elif task.tool == "runtime.test.access_control":
                covered.update(ep.get("url") for ep in (task.args.get("application_model") or {}).get("endpoints") or [])

        unplanned = [url for url in candidates if url and url not in covered]
        if not unplanned:
            return []

        extra: list[PlanTask] = []
        auth_session = PlanTask(
            id=task_id(STAGE_TESTS, "auth_session", "replan"),
            tool="runtime.test.auth_session",
            args={"urls": unplanned, "auth_analysis": model.get("auth_mechanism_summary") or {}},
            stage=STAGE_TESTS,
            note="re-planner: session/conduit checks for newly discovered endpoints",
        )
        extra.append(auth_session)
        previous.notes.append(
            f"re-planner: {len(unplanned)} newly discovered endpoint(s) scheduled for testing "
            f"({', '.join(unplanned)})"
        )
        return extra

    @staticmethod
    def _queried_endpoints(endpoints: list[dict[str, Any]], policy: ScanPolicy | None) -> list[dict[str, Any]]:
        allowed = policy.allowed_methods if policy is not None else {"GET", "HEAD", "POST"}
        targets: list[dict[str, Any]] = []
        for ep in endpoints:
            params = [p for p in (ep.get("query_params") or [])]
            if not params:
                continue
            method = str(ep.get("method", "GET")).upper()
            if method not in allowed:
                continue
            location = _injection_location(method, ep)
            targets.append(
                {
                    "url": ep.get("url"),
                    "method": method,
                    "params": params,
                    "location": location,
                }
            )
        return targets


def _injection_location(method: str, endpoint: dict[str, Any]) -> str:
    form_fields = endpoint.get("form_fields") or []
    if method != "GET" and endpoint.get("body_media_type") in (
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    ) and form_fields:
        return "form"
    return "query"


def _unique_urls(urls: list[str | None]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        result.append(url)
    return result


def _short(target: str) -> str:
    from urllib.parse import urlsplit

    try:
        netloc = urlsplit(target).netloc
        return netloc or target[:32]
    except ValueError:
        return target[:32]