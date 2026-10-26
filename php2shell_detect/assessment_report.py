"""JSON and CSV exporters for passive metadata assessment results."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .scoring import AssessmentResult, DISCLAIMER

_FINDING_FIELDS = (
    "id",
    "title",
    "category",
    "observation",
    "evidence",
    "severity",
    "confidence",
    "recommendation",
    "reference",
    "points_deduction",
    "status",
)
_CSV_FIELDS = (
    "target",
    "normalized_url",
    "final_url",
    "status_code",
    "hardening_score",
    "grade",
    "ruleset_version",
    "timestamp",
    "scope",
    "response_headers",
    "cookies",
    "https_used",
    "certificate_valid",
    "disclaimer",
    *_FINDING_FIELDS,
)


def _spreadsheet_safe(value: object) -> object:
    if not isinstance(value, str):
        return value
    if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def write_json_report(assessment: AssessmentResult, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(assessment.to_dict(), handle, indent=2, ensure_ascii=False)


def write_csv_report(assessment: AssessmentResult, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = {
        "target": assessment.observations.target,
        "normalized_url": assessment.observations.normalized_url,
        "final_url": assessment.observations.final_url,
        "status_code": assessment.observations.status_code,
        "hardening_score": assessment.score,
        "grade": assessment.grade,
        "ruleset_version": assessment.ruleset_version,
        "timestamp": assessment.observations.checked_at.isoformat(),
        "scope": assessment.observations.scope,
        "response_headers": json.dumps(assessment.observations.to_dict()["response_headers"]),
        "cookies": json.dumps(assessment.observations.to_dict()["cookies"]),
        "https_used": assessment.observations.https_used,
        "certificate_valid": assessment.observations.certificate_valid,
        "disclaimer": DISCLAIMER,
    }
    findings = assessment.findings or (None,)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_CSV_FIELDS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for finding in findings:
            row = dict(metadata)
            row.update(finding.to_dict() if finding is not None else {})
            writer.writerow({key: _spreadsheet_safe(value) for key, value in row.items()})
