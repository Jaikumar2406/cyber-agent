"""SARIF 2.1.0 export for Runtime findings (phases.md §1.8, PRD FR-65).

Maps the normalized Runtime findings to the SARIF 2.1.0 JSON schema for IDE/CI
consumption: one rule per Aegis category, one result per finding with severity
mapped to a SARIF level, the affected asset as the artifact URI, and rich
properties (OWASP, severity, confidence, remediation, evidence record id) so no
report content is lost in the conversion.
"""

from typing import Any

from app.reporting.context import ReportContext

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_VERSION = "2.1.0"

_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _rule_id(category: str) -> str:
    return f"AEGIS-RUNTIME-{str(category).upper().replace('-', '_')}"


def _build_rules(ctx: ReportContext) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """One rule per distinct category; returns (rules, {rule_id: index})."""
    by_category: dict[str, list] = {}
    for finding in ctx.findings:
        by_category.setdefault(finding.category, []).append(finding)
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    for category, members in by_category.items():
        rid = _rule_id(category)
        index[rid] = len(rules)
        descriptions = (
            f"{m.title}: {m.summary}"
            for m in members
        )
        owasp_labels = sorted({f"{m.owasp_code} {m.owasp_name}".strip() for m in members})
        rules.append({
            "id": rid,
            "name": f"{category} (runtime)",
            "shortDescription": {"text": f"AEGIS runtime finding: {category}"},
            "fullDescription": {"text": "; ".join(descriptions)[:2000]},
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "category": category,
                "owasp": ", ".join(owasp_labels),
                "owaspCodes": sorted({m.owasp_code for m in members}),
                "tags": sorted({m.owasp_code for m in members}),
            },
        })
    return rules, index


def _result(finding, rule_index: int, rule_id: str) -> dict[str, Any]:
    asset = finding.asset
    uri = asset.get("url") or finding.endpoint or None
    locations: list[dict[str, Any]] = []
    if uri:
        locations = [{
            "physicalLocation": {
                "artifactLocation": {"uri": str(uri)},
            },
        }]
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL.get(finding.severity, "note"),
        "message": {"text": f"{finding.title}: {finding.summary}"},
        "locations": locations,
        "partialFingerprints": {"aegisFindingId": finding.finding_id},
        "properties": {
            "severity": finding.severity,
            "confidence": finding.confidence,
            "category": finding.category,
            "owasp": finding.owasp_code,
            "affectedAsset": asset,
            "endpoint": finding.endpoint,
            "remediation": finding.remediation,
            "evidenceRecordId": finding.record_id,
            "detector": finding.detector,
        },
    }


def render_sarif(ctx: ReportContext) -> dict[str, Any]:
    rules, rule_index = _build_rules(ctx)
    results = [_result(f, rule_index[_rule_id(f.category)], _rule_id(f.category))
               for f in ctx.findings]
    return {
        "$schema": _SCHEMA,
        "version": _VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AEGIS",
                        "version": "0.1.0",
                        "informationUri": "https://aegis.local/",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "scanId": ctx.scan_id,
                    "mode": ctx.mode,
                    "target": ctx.target_url,
                    "evidenceSource": "RUNTIME",
                    "generatedAt": ctx.generated_at,
                },
            }
        ],
    }


async def render_sarif_report(scan_id: str, session_factory=None) -> dict[str, Any]:
    """One-call helper: load context and render the SARIF document."""
    from app.reporting.context import build_report_context

    return render_sarif(await build_report_context(scan_id, session_factory=session_factory))