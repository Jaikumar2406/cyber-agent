"""Self-contained HTML runtime report (phases.md §1.8, PRD §10, rules.md §9).

Generates a single-file, offline HTML artifact (embedded CSS, no CDN links, no
JS) that states mode limitations and coverage honestly and renders every finding
from its EvidenceRecord-backed normalized dict. Fetching nothing and posting
nothing, it satisfies the air-gap rule (rules.md §3).
"""

import html
from typing import Any

from app.reporting.context import ReportContext

_SEVERITY_CLASS = {
    "CRITICAL": "sev-critical",
    "HIGH": "sev-high",
    "MEDIUM": "sev-medium",
    "LOW": "sev-low",
    "INFO": "sev-info",
}

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
       margin: 0; background: #f5f7fa; color: #1f2937; }
.wrap { max-width: 980px; margin: 0 auto; padding: 24px 20px 64px; }
header.report { background: #111827; color: #f9fafb; border-radius: 10px;
                padding: 22px 26px; margin-bottom: 20px; }
header.report h1 { margin: 0 0 6px; font-size: 26px; }
header.report .meta { color: #cbd5e1; font-size: 13px; line-height: 1.6; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px 18px; }
.card h2 { margin: 0 0 10px; font-size: 15px; text-transform: uppercase;
           letter-spacing: .04em; color: #4b5563; }
.stat { font-size: 30px; font-weight: 700; }
.stat small { display: block; font-size: 12px; color: #6b7280; font-weight: 500; }
.notice { border-left: 4px solid #f59e0b; background: #fffbeb; padding: 12px 16px;
          border-radius: 0 8px 8px 0; margin: 16px 0; font-size: 14px; }
.notice h3 { margin: 0 0 6px; color: #92400e; font-size: 14px; }
.notice ul { margin: 0; padding-left: 18px; }
.notice li { margin: 3px 0; }
.chips span { display: inline-block; background: #eef2ff; color: #3730a3;
              border-radius: 999px; padding: 3px 10px; font-size: 12px; margin: 3px 3px 3px 0; }
.chips .chip-none { background: #f3f4f6; color: #6b7280; }
ol.findings { list-style: none; padding: 0; margin: 0; }
li.finding { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px;
             margin: 18px 0; padding: 18px 22px; }
.finding-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.finding-head h3 { margin: 0 0 6px; font-size: 17px; flex: 1 1 100%; }
.badge { border-radius: 999px; padding: 3px 11px; font-size: 12px; font-weight: 600; }
.badge-owasp { background: #f3e8ff; color: #6b21a8; }
.badge-id { background: #e5e7eb; color: #374151; font-variant: tabular-nums; }
.sev-critical { background: #fee2e2; color: #991b1b; }
.sev-high { background: #ffedd5; color: #9a3412; }
.sev-medium { background: #fef3c7; color: #92400e; }
.sev-low { background: #e0f2fe; color: #075985; }
.sev-info { background: #f3f4f6; color: #4b5563; }
.conf { background: #dcfce7; color: #14532d; }
.finding .asset { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                  font-size: 13px; color: #0f766e; margin: 6px 0 12px; }
.finding p { margin: 6px 0; font-size: 14px; line-height: 1.5; }
.evidence { background: #0f172a; color: #d1e5ff; border-radius: 8px; padding: 12px 14px;
            margin: 10px 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 12px; line-height: 1.5; overflow-x: auto; max-height: 420px; overflow-y: auto; }
.evidence div { white-space: pre-wrap; word-break: break-word; }
.meta-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr));
             gap: 6px 18px; font-size: 13px; margin: 8px 0; }
.meta-list b { color: #4b5563; }
footer.report { margin-top: 26px; color: #6b7280; font-size: 12px; line-height: 1.7;
                border-top: 1px solid #e5e7eb; padding-top: 14px; }
@media print { body { background:#fff; } .wrap { max-width:100%; padding: 0; }
               li.finding, .card { break-inside: avoid; } }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _flatten_evidence(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Flatten a (redacted) evidence dict into small ``path -> value`` lines."""
    lines: list[tuple[str, str]] = []
    _MAX_VALUE = 500

    def walk(o: Any, p: str) -> None:
        if len(lines) >= 220:
            lines.append(("…(evidence truncated)", ""))
            return
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{p}.{k}" if p else str(k))
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{p}[{i}]")
        else:
            text = str(o)
            if len(text) > _MAX_VALUE:
                text = text[:_MAX_VALUE] + "…"
            lines.append((p, text))

    walk(obj, prefix)
    return lines


def _render_evidence(finding) -> str:
    """Render evidence (already redacted by §1.6) as an HTML <pre> block."""
    blocks: list[str] = []
    http = finding.evidence.get("http")
    if isinstance(http, dict):
        lines = _flatten_evidence(http, "http")
        for path, value in lines:
            blocks.append(f"<div>{_esc(path)}: {_esc(value)}</div>")
    if finding.identity_proof:
        blocks.append(f"<div class='proof'>identity_proof: {_esc(finding.identity_proof)}</div>")
    if finding.evidence.get("payload") is not None and not blocks:
        blocks.append(f"<div>payload: {_esc(finding.evidence.get('payload'))}</div>")
    if not blocks:
        blocks.append("<div>(no HTTP exchange captured)</div>")
    return "".join(blocks)


def _finding_card(finding) -> str:
    sev_cls = _SEVERITY_CLASS.get(finding.severity, "sev-info")
    asset = finding.asset
    asset_text = f"{asset.get('method', '')} {asset.get('url', finding.endpoint)}" if asset else finding.endpoint
    if asset.get("host"):
        asset_text += f" (host {asset['host']})"
    meta_rows = [
        ("Category", finding.category),
        ("OWASP", f"{finding.owasp_code} {finding.owasp_name}".strip()),
        ("Detector", finding.detector),
        ("CWE", finding.cwe),
        ("Finding ID", finding.finding_id),
        ("Evidence record", finding.record_id),
    ]
    meta = "".join(
        f"<div><b>{_esc(label)}:</b> <span>{_esc(value)}</span></div>"
        for label, value in meta_rows
        if value
    )
    proof = ""
    if finding.identity_proof:
        proof = (
            "<p><b>Auth-identity proof:</b> "
            f"<code>{_esc(finding.identity_proof)}</code></p>"
        )
    return f"""
<li class="finding">
  <div class="finding-head">
    <h3>{_esc(finding.title)}</h3>
    <span class="badge {sev_cls}">{_esc(finding.severity)}</span>
    <span class="badge conf">{_esc(finding.confidence)}</span>
    <span class="badge badge-owasp">{_esc(finding.owasp_code)}</span>
    <span class="badge badge-id">{_esc(finding.finding_id)}</span>
  </div>
  <div class="asset">{_esc(asset_text)}</div>
  <p>{_esc(finding.summary)}</p>
  <div class="evidence">{_render_evidence(finding)}</div>
  {proof}
  <div class="meta-list">{meta}</div>
  <p><b>Remediation / verification:</b> {_esc(finding.remediation)}</p>
</li>"""


def render_html(ctx: ReportContext) -> str:
    findings_block = (
        "".join(_finding_card(f) for f in ctx.findings)
        if ctx.findings
        else "<div class='card'><h2>Findings</h2><p>No RUNTIME findings recorded for this scan.</p></div>"
    )

    severity_cols = "".join(
        f"<div class='card'><div class='stat'>{ctx.severity_counts.get(sev, 0)}"
        f"<small>{_esc(sev)}</small></div></div>"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    owasp_chips = "".join(
        f"<span>{_esc(code)} ({count})</span>"
        for code, count in sorted(ctx.owasp_counts.items())
    ) or "<span class='chip-none'>none</span>"

    tool_chips = "".join(f"<span>{_esc(t)}</span>" for t in ctx.coverage.tools_executed) or \
        "<span class='chip-none'>none</span>"

    untested = ctx.coverage.categories_without_findings
    untested_text = (
        "No confirmed findings for: " + ", ".join(untested)
        if untested
        else "All detection categories produced at least one finding."
    )

    limitations = "".join(f"<li>{_esc(lim)}</li>" for lim in ctx.limitations)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="AEGIS runtime report (offline/deterministic)">
<title>AEGIS Runtime Security Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
<header class="report">
  <h1>AEGIS Runtime Security Report</h1>
  <div class="meta">
    Scan: <code>{_esc(ctx.scan_id)}</code><br>
    Target: <code>{_esc(ctx.target_url or "—")}</code> ·
    Mode: <code>{_esc(ctx.mode or "MODE_1")}</code><br>
    Generated: <code>{_esc(ctx.generated_at)}</code> (local, offline)
  </div>
</header>

<section class="grid">{severity_cols}</section>

<div class="notice">
  <h3>Mode limitations (Mode 1 · runtime evidence only)</h3>
  <ul>{limitations}</ul>
</div>

<section>
  <div class="card"><h2>Coverage</h2>
    <p><b>Tools executed:</b></p>
    <div class="chips">{tool_chips}</div>
    <p><b>Assessed targets ({len(ctx.coverage.endpoints_tested)}):</b></p>
    <div class="chips">{"".join(f"<span>{_esc(u)}</span>" for u in ctx.coverage.endpoints_tested) or "<span class='chip-none'>none</span>"}</div>
    <p><b>OWASP categories with findings:</b></p>
    <div class="chips">{owasp_chips}</div>
    <p>{_esc(untested_text)}</p>
  </div>
</section>

<h2 style="margin:22px 0 6px;">Findings ({ctx.total})</h2>
<ol class="findings">{findings_block}</ol>

<footer class="report">
  Generated deterministically from RUNTIME evidence records — no LLM inference,
  no external calls (100% offline / air-gapped). Secrets were redacted before
  persistence and are not present in this report.
</footer>
</div>
</body>
</html>
"""


async def render_html_report(scan_id: str, session_factory=None) -> str:
    """One-call helper: load context and render the HTML report."""
    from app.reporting.context import build_report_context

    return render_html(await build_report_context(scan_id, session_factory=session_factory))