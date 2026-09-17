"""Minimal, dependency-free PDF runtime report (phases.md §1.8).

Renders the deterministic Runtime evidence content into a valid PDF using the
standard PDF core fonts (Helvetica / Helvetica-Bold) so generation stays 100%
offline with zero extra dependencies (rules.md §3, tech.md "offline-buildable").
Output is plain-text structured — intentionally not typographic — but valid,
printable and searchable.

Only ASCII is emitted: non-ASCII characters are replaced with ``?``.
"""

from app.reporting.context import ReportContext

_PAGE_W = 612
_PAGE_H = 792
_LEFT = 50
_TOP = 760
_BOTTOM = 40
_MAX_CHARS = 96  # rough character width at 9pt Helvetica
_LEAD = 13

_FONT_NORMAL = b"/Helvetica"
_FONT_BOLD = b"/Helvetica-Bold"


def _pdf_escape(text: str) -> str:
    """Escape a PDF literal string and ASCII-sanitize it."""
    out = []
    for ch in str(text):
        code = ord(ch)
        if ch in ("\\", "(", ")"):
            out.append("\\" + ch)
        elif ch == "\n":
            out.append(" ")
        elif code < 32 or code > 126:
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


def _wrap(text: str, width: int) -> list[str]:
    words = str(text).split(" ")
    lines: list[str] = []
    current = ""
    for w in words:
        candidate = f"{current} {w}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = w
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]


def _collect_lines(ctx: ReportContext) -> list[tuple[str, str]]:
    """(kind, text) rows. kinds: h1 / h2 / body."""
    rows: list[tuple[str, str]] = [
        ("h1", "AEGIS Runtime Security Report"),
        ("body", f"Scan: {ctx.scan_id}"),
        ("body", f"Target: {ctx.target_url or '-'}   Mode: {ctx.mode or 'MODE_1'}"),
        ("body", f"Generated: {ctx.generated_at} (local, offline)"),
        ("body", f"Total findings: {ctx.total}"),
        ("body", ""),
        ("h2", "Summary by severity"),
        ("body", "  CRITICAL {} | HIGH {} | MEDIUM {} | LOW {} | INFO {}".format(
            ctx.severity_counts.get("CRITICAL", 0),
            ctx.severity_counts.get("HIGH", 0),
            ctx.severity_counts.get("MEDIUM", 0),
            ctx.severity_counts.get("LOW", 0),
            ctx.severity_counts.get("INFO", 0),
        )),
        ("body", ""),
        ("h2", "Mode limitations (Mode 1 - runtime evidence only)"),
    ]
    for lim in ctx.limitations:
        rows.append(("body", "- " + lim))
    rows.append(("body", ""))
    rows.append(("h2", "Coverage"))
    rows.append(("body", "Tools executed: " + (", ".join(ctx.coverage.tools_executed) or "none")))
    rows.append(("body", "Assessed targets: " + (", ".join(ctx.coverage.endpoints_tested) or "none")))
    rows.append(("body", "No confirmed findings for: " + (
        ", ".join(ctx.coverage.categories_without_findings) or "all categories had findings"
    )))
    rows.append(("body", ""))
    for finding in ctx.findings:
        rows.append(("h2", f"[{finding.severity}/{finding.confidence}] {finding.title}"))
        rows.append(("body", finding.endpoint or "(no endpoint)"))
        rows.append(("body", finding.summary))
        if finding.identity_proof:
            rows.append(("body", f"identity_proof: {finding.identity_proof}"))
        rows.append(("body", f"Remediation: {finding.remediation}"))
        rows.append(("body", f"Owasp {finding.owasp_code} {finding.owasp_name}  "
                            f"Finding {finding.finding_id}  Evidence {finding.record_id}"))
        rows.append(("body", ""))
    return rows


def _paginate(rows: list[tuple[str, str]], width: int) -> list[list[tuple[str, str]]]:
    pages: list[list[tuple[str, str]]] = [[]]
    used = 0
    for kind, text in rows:
        size = 17 if kind == "h1" else 12 if kind == "h2" else 9
        wrapped = _wrap(text, width)
        needed = (size + 6) + (len(wrapped) - 1) * _LEAD
        if used + needed > (_TOP - _BOTTOM):
            pages.append([])
            used = 0
        pages[-1].append((kind, text))
        used += needed
    return pages


def _content_stream(page: list[tuple[str, str]]) -> tuple[bytes, int]:
    """Render one page's text content stream. Returns (stream, max_font_size)."""
    lines: list[str] = ["BT", "/Helvetica 9 Tf", f"{_LEFT} {_TOP} Td", f"{_LEAD} TL"]
    y = _TOP
    max_size = 9
    for kind, text in page:
        font = _FONT_BOLD if kind != "body" else _FONT_NORMAL
        size = 17 if kind == "h1" else 12 if kind == "h2" else 9
        max_size = max(max_size, size)
        wrapped = _wrap(text, _MAX_CHARS)
        row_h = (size + 6) + (len(wrapped) - 1) * _LEAD
        if y - row_h < _BOTTOM:
            break  # safety net; _paginate should have prevented this
        for line in wrapped:
            lines.append(f"/{font.decode()[1:]} {size} Tf")
            lines.append(f"({_pdf_escape(line)}) Tj")
            lines.append("T*")
        y -= row_h
    lines.append("ET")
    return "\n".join(lines).encode("latin-1"), max_size


class _PdfBuilder:
    """Writes objects and records byte offsets for the xref table."""

    def __init__(self) -> None:
        self.buf = bytearray(b"%PDF-1.4\n")
        self.offsets: dict[int, int] = {}

    def obj(self, num: int, body: bytes) -> None:
        self.offsets[num] = len(self.buf)
        self.buf += f"{num} 0 obj\n".encode("latin-1")
        self.buf += body
        self.buf += b"\nendobj\n"


def _build(builder: _PdfBuilder, size: int) -> bytes:
    xref_pos = len(builder.buf)
    xref = f"xref\n0 {size}\n0000000000 65535 f \n".encode("latin-1")
    for i in range(1, size):
        xref += f"{builder.offsets.get(i, 0):010d} 00000 n \n".encode("latin-1")
    trailer = (
        f"trailer\n<< /Size {size} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode("latin-1")
    return bytes(builder.buf) + xref + trailer


def render_pdf(ctx: ReportContext) -> bytes:
    rows = _collect_lines(ctx)
    pages = _paginate(rows, _MAX_CHARS)

    # Object numbering: 1 Catalog, 2 Pages, 3/4 .. page/content pairs,
    # then two font objects.
    n_pages = len(pages)
    f_normal = 3 + 2 * n_pages
    f_bold = f_normal + 1
    size = f_bold + 1

    builder = _PdfBuilder()
    builder.obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{3 + 2 * i} 0 R" for i in range(n_pages))
    builder.obj(2, f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode("latin-1"))

    for i, page in enumerate(pages):
        stream, _ = _content_stream(page)
        page_obj = 3 + 2 * i
        content_obj = 4 + 2 * i
        builder.obj(content_obj, f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream")
        builder.obj(
            page_obj,
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
                f"/Resources << /Font << /F1 {f_normal} 0 R /F2 {f_bold} 0 R >> >> "
                f"/Contents {content_obj} 0 R >>"
            ).encode("latin-1"),
        )

    builder.obj(f_normal, f"<< /Type /Font /Subtype /Type1 /BaseFont {_FONT_NORMAL.decode()} >>".encode("latin-1"))
    builder.obj(f_bold, f"<< /Type /Font /Subtype /Type1 /BaseFont {_FONT_BOLD.decode()} >>".encode("latin-1"))

    return _build(builder, size)


async def render_pdf_report(scan_id: str, session_factory=None) -> bytes:
    """One-call helper: load context and render the PDF report."""
    from app.reporting.context import build_report_context

    return render_pdf(await build_report_context(scan_id, session_factory=session_factory))