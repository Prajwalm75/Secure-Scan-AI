from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from .schemas import ScanListItem, ScanReport


def db_path() -> Path:
    configured = os.getenv("SECURESCAN_DB_PATH", "./data/securescan.db")
    path = Path(configured)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[2] / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(db_path())
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with connect() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                score INTEGER,
                score_label TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                report_json TEXT NOT NULL
            )"""
        )
        connection.commit()


def save_report(report: ScanReport) -> None:
    payload = report.model_dump(mode="json")
    with connect() as connection:
        connection.execute(
            """INSERT OR REPLACE INTO scans
            (scan_id, target_url, hostname, scanned_at, score, score_label, finding_count, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report.scan_id,
                report.target_url,
                report.hostname,
                report.scanned_at.isoformat(),
                report.score,
                report.score_label,
                len(report.findings),
                json.dumps(payload),
            ),
        )
        connection.commit()


def get_report(scan_id: str) -> ScanReport | None:
    with connect() as connection:
        row = connection.execute("SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    return ScanReport.model_validate(json.loads(row["report_json"]))


def list_reports(limit: int = 20) -> list[ScanListItem]:
    limit = min(max(limit, 1), 50)
    with connect() as connection:
        rows = connection.execute(
            "SELECT scan_id, target_url, hostname, scanned_at, score, score_label, finding_count FROM scans ORDER BY scanned_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [ScanListItem.model_validate(dict(row)) for row in rows]
