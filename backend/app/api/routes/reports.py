"""Report export API (phases.md §1.8) — offline Runtime-only artifacts.

GET /scans/{scan_id}/report       -> standalone HTML report
GET /scans/{scan_id}/report/sarif -> SARIF 2.1.0 JSON (IDE/CI)
GET /scans/{scan_id}/report/pdf   -> minimal runtime PDF
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, session_factory_from
from app.control_plane.auth import require_api_key
from app.harness.state_manager import InvestigationNotFoundError

router = APIRouter(prefix="/scans/{scan_id}/report", tags=["reports"])


def _missing_scan(exc: InvestigationNotFoundError) -> HTTPException:
    return HTTPException(status_code=404, detail="scan not found")


def _session_arg(session: AsyncSession):
    return session_factory_from(session)


@router.get(
    "",
    response_class=HTMLResponse,
    dependencies=[Depends(require_api_key)],
    summary="Render the standalone Runtime HTML report",
)
async def runtime_html_report(
    scan_id: str, session: AsyncSession = Depends(db_session)
) -> HTMLResponse:
    from app.reporting import render_html_report

    try:
        body = await render_html_report(scan_id, _session_arg(session))
    except InvestigationNotFoundError as exc:
        raise _missing_scan(exc) from exc
    return HTMLResponse(content=body)


@router.get(
    "/sarif",
    dependencies=[Depends(require_api_key)],
    summary="Export Runtime findings as SARIF 2.1.0",
)
async def runtime_sarif_report(
    scan_id: str, session: AsyncSession = Depends(db_session)
) -> JSONResponse:
    from app.reporting import render_sarif_report

    try:
        doc = await render_sarif_report(scan_id, _session_arg(session))
    except InvestigationNotFoundError as exc:
        raise _missing_scan(exc) from exc
    return JSONResponse(content=doc)


@router.get(
    "/pdf",
    dependencies=[Depends(require_api_key)],
    summary="Render the minimal offline Runtime PDF report",
)
async def runtime_pdf_report(
    scan_id: str, session: AsyncSession = Depends(db_session)
) -> Response:
    from app.reporting import render_pdf_report

    try:
        data = await render_pdf_report(scan_id, _session_arg(session))
    except InvestigationNotFoundError as exc:
        raise _missing_scan(exc) from exc
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="aegis-runtime-{scan_id[:8]}.pdf"'},
    )