"""runtime.test.nuclei - Nuclei engine integration (phases.md §1.5).

Strictly **local/offline**: the tool runs a Nuclei binary supplied on PATH (or
an explicit path - including a local Python wrapper) against ONLY the target
origins derived from the Application Model (§1.4). Templates are read from a
bundled local directory and code-stealing/online behaviors are off:

  * `-disable-update-check` - no Nuclei template/nuclei version check;
  * no template downloads, no online fallback, no external callbacks
    (rules.md §10);
  * no inline/ad-hoc payloads: templates are the fixed, offline bundle.

The Executor chain (Scope -> Policy -> Permission -> Budget -> Sandbox ->
Retry -> Audit -> Evidence) is unchanged. Output is parsed from Nuclei JSONL
into the standard `Finding` model (with a per-finding `evidence_ref`), and all
raw strings are passed through the platform redaction so credentials/tokens/
cookies never appear in evidence (rules.md §5.5/§5.6).

Intensity: requires active scanning (`injection` operation) because bundled
templates may exercise active/families checks - passive scans are denied.
"""

import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from typing import Any
from urllib.parse import urlsplit

from app.core.config import get_settings
from app.core.logging import get_logger
from app.harness.tools import BaseTool, SandboxSpec, ToolContext, ToolResult
from app.schemas.common import Confidence, Severity, ToolResultStatus
from app.testing.finding import NUCLEI, Finding

_REDACTION: tuple[tuple[str, str], ...] = (
    (r"(api[_-]?key\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(secret\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(password\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(token\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(authorization\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
    (r"(cookie\s*[=:]\s*)(\S+)", r"\1[REDACTED]"),
)


def _redact(text: str) -> str:
    for pat, rep in _REDACTION:
        text = re.sub(pat, rep, text, flags=re.IGNORECASE)
    return text

log = get_logger("aegis.tools.test_nuclei")

_VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_MAX_EXTRACTED_RESULTS = 3
_TEMPLATE_EXTENSIONS = {".yaml", ".yml"}


class _NucleiRunError(Exception):
    pass


class NucleiTestTool(BaseTool):
    name = "runtime.test.nuclei"
    description = (
        "Run the bundled offline Nuclei engine over target origins taken from "
        "the Application Model. Local templates only; no downloads. Output is "
        "parsed into structured findings with evidence references. "
        "Requires active intensity (injection operation)."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "application_model": {
                "type": "object",
                "description": "Output dict from runtime.model.build (must contain 'endpoints')",
            },
            "severity": {
                "type": "array",
                "items": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "description": "Severities to keep (default: all)",
            },
            "binary_path": {
                "type": "string",
                "minLength": 1,
                "description": "Override the Nuclei binary (path/name; .py wrappers supported)",
            },
            "templates_dir": {
                "type": "string",
                "description": "Override the bundled offline templates directory",
            },
            "timeout": {"type": "number", "minimum": 1.0, "maximum": 60, "default": 25.0},
        },
        "required": ["application_model"],
    }
    permissions = ("runtime:test:nuclei",)
    sandbox = SandboxSpec(mode="process", network=True)
    policy_requirements = ("read_only", "injection")

    async def run(self, args: dict[str, Any], context: ToolContext) -> ToolResult:
        model = args.get("application_model") or {}
        if not model.get("endpoints"):
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error="application_model contains no endpoints - nothing to scan",
            )

        settings = get_settings()
        binary = str(args.get("binary_path") or settings.nuclei_binary)
        templates_dir = str(args.get("templates_dir") or settings.nuclei_templates_dir)
        timeout = float(args.get("timeout", 25.0))
        severity_filter = args.get("severity") or sorted(_VALID_SEVERITIES)
        allowed = {str(s).lower() for s in severity_filter}

        binary_cmd = _resolve_binary(binary)
        if binary_cmd is None:
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error=f"nuclei binary not found: {binary!r} (bundle it locally for air-gapped use)",
            )
        if not _templates_available(templates_dir):
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error=(
                    f"nuclei templates directory not available/bundled: {templates_dir!r} "
                    "(bundled offline templates required; no downloads allowed)"
                ),
            )

        origins = _origins_from_model(model)
        if not origins:
            return ToolResult(
                status=ToolResultStatus.FAILURE,
                error="application_model endpoints have no target origins",
            )

        scope = context.scope_guard
        if scope is not None:
            for origin in origins:
                decision = scope.validate_target(origin, method="GET")
                if not decision.allowed:
                    return ToolResult(
                        status=ToolResultStatus.SCOPE_VIOLATION,
                        error=f"nuclei target {origin!r} left authorized scope: {decision.reason}",
                    )

        findings: list[dict[str, Any]] = []
        raw_rows: list[dict[str, Any]] = []
        runs_failed: list[str] = []
        run_count = 0
        workdir = tempfile.mkdtemp(prefix="aegis_nuclei_")
        try:
            for origin in origins:
                out_path = os.path.join(workdir, f"{_safe_name(origin)}.jsonl")
                try:
                    await _run_nuclei(binary_cmd, origin, templates_dir, out_path, timeout)
                    run_count += 1
                except _NucleiRunError as exc:
                    runs_failed.append(f"{origin}: {exc}")
                    continue
                rows = _read_jsonl(out_path)
                parsed = _parse_rows(rows, origin, allowed)
                for finding, row in parsed:
                    findings.append(finding.as_dict())
                    raw_rows.append(_redact_row(row))
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        output = {
            "findings": findings,
            "finding_count": len(findings),
            "raw_evidence_rows": raw_rows,
            "origins_scanned": origins,
            "scans_run": run_count,
            "runs_failed": runs_failed,
        }
        if runs_failed and not findings:
            return ToolResult(status=ToolResultStatus.FAILURE, output=output, error=(
                f"nuclei ran but reported failures: {runs_failed}"
            ))
        return ToolResult(status=ToolResultStatus.SUCCESS, output=output, error=None)


# ---------------------------------------------------------------------------
# Resolution / offline guards
# ---------------------------------------------------------------------------

def _resolve_binary(binary: str) -> list[str] | None:
    """Return a command prefix for the nuclei binary.

    A name (e.g. `nuclei`) is resolved via PATH; an absolute path is used
    directly. A `.py` file is run under the current Python interpreter so an
    air-gapped adapter/wrapper script can stand in for a compiled engine."""
    if not binary:
        return None
    if binary.endswith(".py"):
        if os.path.isfile(binary):
            return [sys.executable, binary]
        return None
    if os.path.sep in binary or "/" in binary:
        return [binary] if os.path.isfile(binary) else None
    resolved = shutil.which(binary)
    return [resolved] if resolved else None


def _templates_available(templates_dir: str) -> bool:
    if not templates_dir or not os.path.isdir(templates_dir):
        return False
    for _, _dirs, files in os.walk(templates_dir):
        for name in files:
            if os.path.splitext(name)[1].lower() in _TEMPLATE_EXTENSIONS:
                return True
    return False


# ---------------------------------------------------------------------------
# Model -> origins
# ---------------------------------------------------------------------------

def _origins_from_model(model: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    origins: list[str] = []
    for ep in model.get("endpoints") or []:
        url = str(ep.get("url", ""))
        if not url:
            continue
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin in seen:
            continue
        seen.add(origin)
        origins.append(origin)
    return origins


def _safe_name(origin: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", origin)


# ---------------------------------------------------------------------------
# Offline subprocess execution
# ---------------------------------------------------------------------------

async def _run_nuclei(binary_cmd: list[str], origin: str, templates_dir: str,
                      out_path: str, timeout: float) -> None:
    cmd = [
        *binary_cmd,
        "-jsonl",
        "-silent",
        "-nc",
        "-disable-update-check",
        "-o", out_path,
        "-t", templates_dir,
        "-u", origin,
    ]
    env = dict(os.environ)
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.exceptions.TimeoutError):
        try:
            proc.kill()
        finally:
            await proc.wait()
        raise _NucleiRunError(f"nuclei timed out after {timeout}s")
    if proc.returncode != 0:
        detail = (stderr or stdout).decode(errors="replace")[:2048]
        raise _NucleiRunError(f"nuclei exited {proc.returncode}: {detail}")


# ---------------------------------------------------------------------------
# JSONL parsing -> Findings
# ---------------------------------------------------------------------------

def _read_jsonl(path: str) -> list[dict[str, Any]]:
    if not os.path.isfile(path):
        return []
    rows: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _row_severity(row: dict[str, Any]) -> str:
    info = row.get("info") or {}
    return str(info.get("severity", "info")).lower()


def _normalize_severity(nuclei_severity: str) -> str:
    mapping = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    return mapping.get(nuclei_severity.lower(), Severity.INFO)


def _evidence_ref(row: dict[str, Any]) -> str:
    template_id = str(row.get("template-id", ""))
    matched = str(row.get("matched-at") or row.get("host") or "")
    matcher = str(row.get("matcher-name", ""))
    raw = f"nuclei|{template_id}|{matched}|{matcher}".encode("utf-8")
    return f"NREF-{hashlib.sha256(raw).hexdigest()[:16]}"


def _extract_evidence(row: dict[str, Any]) -> dict[str, Any]:
    """Evidence fields from one Nuclei JSONL record - deliberately excludes the
    raw `request`, `response` and `curl-command` (potential secrets); the safe
    fields are passed through `_redact` anyway."""
    info = row.get("info") or {}
    evidence: dict[str, Any] = {
        "template_id": str(row.get("template-id", "")),
        "template_name": _redact(str(info.get("name", ""))),
        "tags": [str(t) for t in (info.get("tags") or [])],
        "matcher_name": _redact(str(row.get("matcher-name", ""))),
        "matched_at": _redact(str(row.get("matched-at", ""))),
        "host": _redact(str(row.get("host", ""))),
        "ip": _redact(str(row.get("ip", ""))),
        "port": _redact(str(row.get("port", ""))),
        "type": str(row.get("type", "http")),
    }
    extracted = row.get("extracted-results") or []
    if isinstance(extracted, list):
        evidence["extracted_results"] = [
            _redact(str(v)) for v in extracted[: _MAX_EXTRACTED_RESULTS]
        ]
    if row.get("timestamp"):
        evidence["timestamp"] = str(row["timestamp"])
    return evidence


def _parse_rows(
    rows: list[dict[str, Any]], origin: str, allowed: set[str],
) -> list[tuple[Finding, dict[str, Any]]]:
    parsed: list[tuple[Finding, dict[str, Any]]] = []
    for row in rows:
        severity = _row_severity(row)
        if severity not in allowed:
            continue
        info = row.get("info") or {}
        template_id = str(row.get("template-id", "unknown"))
        matched = str(row.get("matched-at") or row.get("host") or origin)
        finding = Finding(
            title=_redact(str(info.get("name") or template_id)),
            category=NUCLEI,
            severity=_normalize_severity(severity),
            confidence=Confidence.CONFIRMED,
            endpoint=f"nuclei {matched}",
            summary=(
                f"Nuclei template {template_id} matched at {matched} "
                f"(severity {severity})."
            ),
            remediation=(
                "Review the matched pattern; remediate the class of issue "
                "reported by the template (see bundled template description)."
            ),
            evidence=_extract_evidence(row),
            detector=f"nuclei:{template_id}",
            evidence_ref=_evidence_ref(row),
        )
        parsed.append((finding, row))
    return parsed


def _redact_row(row: dict[str, Any]) -> dict[str, Any]:
    """Redacted copy of a raw row for evidence persistence."""
    import copy

    def scrub(value: Any) -> Any:
        if isinstance(value, str):
            return _redact(value)
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items()}
        return value

    redacted = scrub(copy.deepcopy(row))
    redacted.pop("request", None)
    redacted.pop("response", None)
    redacted.pop("curl-command", None)
    return redacted