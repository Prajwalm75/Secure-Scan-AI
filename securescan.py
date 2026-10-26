"""
=============================================================
  SecureScan AI — Main Application Code
  Project  : Passive Website Security Configuration Scanner
  File     : securescan.py
  Language : Python 3.12
  Framework: FastAPI
=============================================================

  This file is the entry point of the SecureScan AI backend.
  It defines all API routes, CORS middleware, per-IP rate
  limiting, and PDF report generation.

  API Routes:
    GET  /health                          - Service health check
    POST /api/scan                        - Submit a URL for scanning
    GET  /api/scan/{scan_id}              - Retrieve a scan report
    GET  /api/scans                       - List recent scan history
    GET  /api/scan/{scan_id}/report       - Download report (JSON or PDF)

  To run:
    pip install -r backend/requirements.txt
    PYTHONPATH=backend uvicorn securescan:app --reload --port 8000
=============================================================
"""

from __future__ import annotations

import io
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from html import escape

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from app.config import RATE_LIMIT, ScanInputError, normalize_url
from app.scanner import scan_target
from app.schemas import ScanRequest
from app.storage import get_report, init_db, list_reports, save_report

# ---------------------------------------------------------------------------
# Rate limiting — sliding window per client IP
# ---------------------------------------------------------------------------
rate_events: dict[str, deque[float]] = defaultdict(deque)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialise the SQLite database on startup."""
    init_db()
    yield


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(title="SecureScan AI API", version="1.0.0", lifespan=lifespan)

frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in frontend_origin.split(",") if origin.strip()] or ["http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


def allow_request(request: Request) -> bool:
    """Return True if the client is within their per-minute scan budget."""
    key = request.client.host if request.client else "unknown"
    now = time.monotonic()
    events = rate_events[key]
    while events and now - events[0] > 60:
        events.popleft()
    if len(events) >= RATE_LIMIT:
        return False
    events.append(now)
    return True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict[str, str]:
    """Service liveness check."""
    return {"status": "ok", "service": "securescan-api", "version": "1.0.0"}


@app.post("/api/scan")
async def create_scan(payload: ScanRequest, request: Request):
    """
    Validate the submitted URL, run a passive security scan and return
    the full structured report.  Raises 400 for invalid/unsafe URLs and
    429 when the per-IP rate limit is exceeded.
    """
    if not allow_request(request):
        raise HTTPException(
            status_code=429,
            detail="Scan rate limit reached. Please wait a minute before trying again.",
        )
    try:
        normalize_url(payload.target_url)
        report = await scan_target(payload.target_url)
        save_report(report)
        return report
    except ScanInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/scan/{scan_id}")
async def read_scan(scan_id: str):
    """Retrieve a previously stored scan report by its UUID."""
    report = get_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan report not found.")
    return report


@app.get("/api/scans")
async def read_scan_history(limit: int = Query(default=12, ge=1, le=50)):
    """Return the most recent scan summaries (max 50)."""
    return {"items": list_reports(limit)}


# ---------------------------------------------------------------------------
# PDF generation
# ---------------------------------------------------------------------------

def pdf_bytes(report) -> bytes:
    """Build a structured PDF report from a ScanReport and return the bytes."""
    buffer = io.BytesIO()
    from reportlab.lib import colors as rl_colors  # noqa: F401
    from reportlab.lib.units import inch  # noqa: F401

    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54,
    )
    styles = getSampleStyleSheet()

    # Title block
    story = [
        Paragraph("SecureScan AI", styles["Title"]),
        Paragraph("Passive Security Configuration Report", styles["h2"]),
        Spacer(1, 8),
    ]

    # Summary fields
    summary_fields = [
        ("Target URL", report.normalized_url),
        ("Scan ID", report.scan_id),
        ("Scanned At", report.scanned_at.strftime("%Y-%m-%d %H:%M UTC")),
        ("Completed At", report.completed_at.strftime("%Y-%m-%d %H:%M UTC")),
        ("HTTP Status", str(report.status_code or "unreachable")),
        ("TLS / HTTPS", "Valid certificate" if report.tls.valid_certificate else ("TLS error" if report.tls.available is False else "Not assessed")),
        ("Checks Completed", str(report.checks_completed)),
        ("Total Findings", str(len(report.findings))),
        ("Configuration Score", f"{report.score if report.score is not None else 'Insufficient data'} / 100 — {report.score_label}"),
    ]
    for label, value in summary_fields:
        story.append(Paragraph(f"<b>{escape(label)}:</b> {escape(value)}", styles["BodyText"]))
        story.append(Spacer(1, 4))

    # Findings summary counts
    story.append(Spacer(1, 12))
    story.append(Paragraph("Findings by Severity", styles["Heading2"]))
    s = report.summary
    story.append(Paragraph(
        f"Critical: {s.critical}  ·  High: {s.high}  ·  Medium: {s.medium}  ·  Low: {s.low}  ·  Informational: {s.informational}",
        styles["BodyText"],
    ))
    story.append(Spacer(1, 14))

    # Individual findings
    story.append(Paragraph("Detailed Findings", styles["Heading2"]))
    if report.findings:
        for item in report.findings:
            story.append(Paragraph(f"<b>[{escape(item.severity.upper())}] {escape(item.title)}</b>", styles["Heading3"]))
            story.append(Paragraph(f"<b>Category:</b> {escape(item.category)}", styles["BodyText"]))
            story.append(Paragraph(f"<b>Evidence:</b> {escape(item.evidence)}", styles["BodyText"]))
            story.append(Paragraph(f"<b>Why it matters:</b> {escape(item.why_it_matters)}", styles["BodyText"]))
            story.append(Paragraph(f"<b>Risk:</b> {escape(item.risk)}", styles["BodyText"]))
            story.append(Paragraph(f"<b>Recommendation:</b> {escape(item.recommendation)}", styles["BodyText"]))
            story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("No findings were recorded in the checks performed.", styles["BodyText"]))

    # Public signals
    if report.public_signals:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Public Signals Observed", styles["Heading2"]))
        for sig in report.public_signals:
            story.append(Paragraph(f"• {escape(sig)}", styles["BodyText"]))

    # Scanner errors/notes
    if report.errors:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Scanner Notes", styles["Heading2"]))
        for err in report.errors:
            story.append(Paragraph(f"• {escape(err)}", styles["BodyText"]))

    # Scope note
    story.append(Spacer(1, 14))
    story.append(Paragraph("Scope &amp; Limitations", styles["Heading2"]))
    for note in report.limitations:
        story.append(Paragraph(f"• {escape(note)}", styles["BodyText"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report contains passive configuration observations obtained without authentication or exploitation. "
        "It is not a complete vulnerability assessment and cannot confirm that a website is secure.",
        styles["Italic"],
    ))

    document.build(story)
    return buffer.getvalue()


@app.get("/api/scan/{scan_id}/report")
async def export_scan(scan_id: str, format: str = Query(default="json", pattern="^(json|pdf)$")):
    """Download a scan report as JSON or PDF."""
    report = get_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan report not found.")
    if format == "pdf":
        return StreamingResponse(
            io.BytesIO(pdf_bytes(report)),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="securescan-{scan_id}.pdf"'},
        )
    return JSONResponse(
        content=report.model_dump(mode="json"),
        headers={"Content-Disposition": f'attachment; filename="securescan-{scan_id}.json"'},
    )
