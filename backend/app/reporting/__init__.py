"""Runtime reporting package (phases.md §1.8).

Renders the deterministic, evidence-backed Runtime Security Report in three
offline formats from RUNTIME evidence records alone:
  - HTML  (self-contained, primary human-readable artifact)
  - SARIF (2.1.0, for IDE/CI integration)
  - PDF   (minimal, dependency-free stdlib writer)

All renderers are pure functions over `ReportContext`; no network, no LLM.
"""

from app.reporting.context import (
    ReportContext,
    ReportFinding,
    Coverage,
    build_report_context,
)
from app.reporting.html import render_html, render_html_report
from app.reporting.sarif import render_sarif, render_sarif_report
from app.reporting.pdf import render_pdf, render_pdf_report

__all__ = [
    "ReportContext",
    "ReportFinding",
    "Coverage",
    "build_report_context",
    "render_html",
    "render_html_report",
    "render_sarif",
    "render_sarif_report",
    "render_pdf",
    "render_pdf_report",
]