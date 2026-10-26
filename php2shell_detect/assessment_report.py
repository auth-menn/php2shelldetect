"""JSON and CSV exporters for passive metadata assessment results."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Mapping

from .domain_check import ValidatedTarget
from .scoring import AssessmentResult, DISCLAIMER
from .verification_guide import (
    GUIDE_VERSION,
    VERIFICATION_STATUSES,
    VerificationState,
    guide_for_finding,
    render_command,
    verification_key,
)

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
    "http_used",
    "certificate_valid",
    "disclaimer",
    "verification_status",
    "verification_note",
    "first_manual_step",
    *_FINDING_FIELDS,
)


def _spreadsheet_safe(value: object) -> object:
    if not isinstance(value, str):
        return value
    if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _state_values(
    states: Mapping[str, VerificationState | Mapping[str, str]] | None,
    key: str,
) -> tuple[str, str]:
    value = (states or {}).get(key)
    if isinstance(value, VerificationState):
        status, note = value.status, value.note
    elif value is not None:
        status = value.get("status", VERIFICATION_STATUSES[0])
        note = value.get("note", "")
    else:
        status, note = VERIFICATION_STATUSES[0], ""
    if status not in VERIFICATION_STATUSES:
        status = VERIFICATION_STATUSES[0]
    return status, str(note)


def _finding_export(
    finding,
    index: int,
    states: Mapping[str, VerificationState | Mapping[str, str]] | None,
    validated_target: ValidatedTarget | None,
) -> dict:
    guide = guide_for_finding(finding.id)
    status, note = _state_values(states, verification_key(finding.id, index))
    guide_data = guide.to_dict() if guide is not None else None
    if guide_data is not None and validated_target is not None:
        for step_data, step in zip(guide_data["manual_steps"], guide.manual_steps):
            if step.command_template is not None:
                try:
                    step_data["command"] = render_command(step, validated_target)
                except ValueError:
                    step_data["command"] = None
    manual_verification = {
        "finding_id": finding.id,
        "summary": guide_data["summary"] if guide_data else "",
        "why_it_matters": guide_data["why_it_matters"] if guide_data else "",
        "steps": guide_data["manual_steps"] if guide_data else [],
        "expected_if_confirmed": (
            guide_data["expected_if_confirmed"] if guide_data else ""
        ),
        "expected_if_false_positive": (
            guide_data["expected_if_false_positive"] if guide_data else ""
        ),
        "common_false_positives": (
            guide_data["common_false_positives"] if guide_data else []
        ),
        "report_tips": guide_data["report_tips"] if guide_data else "",
        "references": guide_data["references"] if guide_data else [],
        "safety_note": guide_data["safety_note"] if guide_data else "",
        "user_status": status,
        "user_note": note,
    }
    return {
        **finding.to_dict(),
        "manual_verification": manual_verification,
    }


def _report_data(
    assessment: AssessmentResult,
    states: Mapping[str, VerificationState | Mapping[str, str]] | None,
    validated_target: ValidatedTarget | None,
) -> dict:
    data = assessment.to_dict()
    data["guide_version"] = GUIDE_VERSION
    occurrences: dict[str, int] = {}
    exported_findings = []
    for finding in assessment.findings:
        occurrence = occurrences.get(finding.id, 0)
        occurrences[finding.id] = occurrence + 1
        exported_findings.append(
            _finding_export(finding, occurrence, states, validated_target)
        )
    data["findings"] = exported_findings
    return data


def write_json_report(
    assessment: AssessmentResult,
    output_path: str | Path,
    verification_states: Mapping[str, VerificationState | Mapping[str, str]] | None = None,
    validated_target: ValidatedTarget | None = None,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(
            _report_data(assessment, verification_states, validated_target),
            handle,
            indent=2,
            ensure_ascii=False,
        )


def write_csv_report(
    assessment: AssessmentResult,
    output_path: str | Path,
    verification_states: Mapping[str, VerificationState | Mapping[str, str]] | None = None,
    validated_target: ValidatedTarget | None = None,
) -> None:
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
        "http_used": assessment.observations.http_used,
        "certificate_valid": assessment.observations.certificate_valid,
        "disclaimer": DISCLAIMER,
    }
    findings = assessment.findings or (None,)
    occurrences: dict[str, int] = {}
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_CSV_FIELDS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for finding in findings:
            occurrence = occurrences.get(finding.id, 0) if finding is not None else 0
            if finding is not None:
                occurrences[finding.id] = occurrence + 1
            row = dict(metadata)
            if finding is not None:
                exported = _finding_export(
                    finding, occurrence, verification_states, validated_target
                )
                row.update({key: value for key, value in exported.items() if key != "manual_verification"})
                guide = guide_for_finding(finding.id)
                state, note = _state_values(
                    verification_states, verification_key(finding.id, occurrence)
                )
                row["verification_status"] = state
                row["verification_note"] = note
                row["first_manual_step"] = (
                    guide.manual_steps[0].instructions if guide and guide.manual_steps else ""
                )
            writer.writerow({key: _spreadsheet_safe(value) for key, value in row.items()})


def _markdown_escape(value: object) -> str:
    text = str(value).replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    text = "".join(character for character in text if ord(character) >= 32 and ord(character) != 127)
    for character in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "#", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def write_markdown_report(
    assessment: AssessmentResult,
    output_path: str | Path,
    verification_states: Mapping[str, VerificationState | Mapping[str, str]] | None = None,
    validated_target: ValidatedTarget | None = None,
) -> None:
    """Write a readable checklist; never execute any displayed command."""
    lines = [
        "# Manual Verification Guide",
        "",
        f"- Target: {_markdown_escape(assessment.observations.target)}",
        f"- Normalized URL: {_markdown_escape(assessment.observations.normalized_url)}",
        f"- Final URL: {_markdown_escape(assessment.observations.final_url)}",
        f"- Timestamp: {_markdown_escape(assessment.observations.checked_at.isoformat())}",
        f"- Hardening Score: {assessment.score}/100 ({assessment.grade})",
        f"- Guide version: {GUIDE_VERSION}",
        "",
        "Only verify within the authorized program scope and rules of engagement. "
        "This report is passive guidance, not proof of a vulnerability.",
        "",
    ]
    occurrences: dict[str, int] = {}
    for finding in assessment.findings:
        occurrence = occurrences.get(finding.id, 0)
        occurrences[finding.id] = occurrence + 1
        guide = guide_for_finding(finding.id)
        state, note = _state_values(
            verification_states, verification_key(finding.id, occurrence)
        )
        lines.extend(
            (
                f"## {_markdown_escape(finding.title)}",
                "",
                f"- Finding ID: `{_markdown_escape(finding.id)}`",
                f"- Severity: {_markdown_escape(finding.severity)}",
                f"- Observation: {_markdown_escape(finding.observation)}",
                f"- Evidence: {_markdown_escape(finding.evidence)}",
                f"- Verification status: {_markdown_escape(state)}",
                f"- Verification note: {_markdown_escape(note)}",
                "",
            )
        )
        if guide is None:
            continue
        lines.extend(
            (
                "### Ringkasan",
                "",
                _markdown_escape(guide.summary),
                "",
                "### Mengapa Penting",
                "",
                _markdown_escape(guide.why_it_matters),
                "",
                "### Langkah Verifikasi",
                "",
            )
        )
        for step_number, step in enumerate(guide.manual_steps, start=1):
            lines.extend(
                (
                    f"{step_number}. **{_markdown_escape(step.title)}** ({_markdown_escape(step.tool)}): "
                    f"{_markdown_escape(step.instructions)}",
                )
            )
            if step.command_template is not None:
                if validated_target is not None:
                    try:
                        command = render_command(step, validated_target)
                    except ValueError:
                        command = step.command_template
                else:
                    command = step.command_template
                lines.extend(("", f"   `{_markdown_escape(command)}`"))
        lines.extend(
            (
                "",
                "### Hasil yang Diharapkan",
                "",
                f"- Jika Terkonfirmasi: {_markdown_escape(guide.expected_if_confirmed)}",
                f"- Jika False Positive: {_markdown_escape(guide.expected_if_false_positive)}",
                "",
                "### Kemungkinan False Positive",
                "",
                *[f"- {_markdown_escape(item)}" for item in guide.common_false_positives],
                "",
                "### Tips Laporan",
                "",
                _markdown_escape(guide.report_tips),
                "",
                "### Referensi",
                "",
                *[f"- <{url}>" for url in guide.references],
                "",
                "### Catatan Keamanan",
                "",
                _markdown_escape(guide.safety_note),
                "",
            )
        )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
