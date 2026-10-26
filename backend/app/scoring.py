from __future__ import annotations

from collections import Counter
from typing import Iterable

from .schemas import Finding, ScanSummary

WEIGHTS = {
    "critical": 30,
    "high": 15,
    "medium": 8,
    "low": 3,
    "informational": 0,
}


def summarize(findings: Iterable[Finding]) -> ScanSummary:
    counts = Counter(f.severity for f in findings)
    return ScanSummary(
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        informational=counts.get("informational", 0),
    )


def score_findings(findings: Iterable[Finding], evidence_sufficient: bool) -> tuple[int | None, str, str]:
    if not evidence_sufficient:
        return None, "Insufficient data", "The target did not provide enough reliable evidence for a meaningful configuration score."

    # A finding id represents one control family, so repeated evidence cannot double-count it.
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.id, finding)

    score = max(0, 100 - sum(WEIGHTS.get(f.severity, 0) for f in unique.values()))
    if score >= 90:
        label = "Good configuration"
    elif score >= 75:
        label = "Low apparent configuration risk"
    elif score >= 50:
        label = "Moderate configuration risk"
    elif score >= 25:
        label = "High configuration risk"
    else:
        label = "Very high configuration risk"
    note = "This score measures the passive configuration checks that completed; it is not a complete vulnerability assessment."
    return score, label, note
