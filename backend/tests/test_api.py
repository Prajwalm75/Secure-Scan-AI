from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import Finding, ScanReport, ScanSummary, TlsStatus
from app.storage import save_report


def sample_report() -> ScanReport:
    return ScanReport(
        scan_id="test-scan",
        target_url="https://example.com",
        normalized_url="https://example.com",
        hostname="example.com",
        scanned_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        reachable=True,
        status_code=200,
        final_url="https://example.com",
        response_time_ms=120,
        request_count=2,
        checks_completed=8,
        evidence_sufficient=True,
        score=92,
        score_label="Good configuration",
        score_note="Configuration checks only.",
        summary=ScanSummary(),
        tls=TlsStatus(requested_https=True, available=True, valid_certificate=True),
        findings=[Finding(id="test", severity="informational", title="Test", category="Test", evidence="mock", description="mock", why_it_matters="mock", risk="mock", recommendation="mock")],
    )


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_report_retrieval_and_export():
    report = sample_report()
    save_report(report)
    with TestClient(app) as client:
        response = client.get("/api/scan/test-scan")
        assert response.status_code == 200
        assert response.json()["score"] == 92
        download = client.get("/api/scan/test-scan/report?format=json")
        assert download.status_code == 200
        assert "attachment" in download.headers["content-disposition"]
        pdf = client.get("/api/scan/test-scan/report?format=pdf")
        assert pdf.status_code == 200
        assert pdf.headers["content-type"].startswith("application/pdf")
