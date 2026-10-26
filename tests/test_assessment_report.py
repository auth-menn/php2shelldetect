import csv
import json
from datetime import datetime, timezone

from php2shell_detect.assessment_report import write_csv_report, write_json_report
from php2shell_detect.domain_check import DomainCheckResult
from php2shell_detect.scoring import DISCLAIMER, evaluate


def _assessment():
    observations = DomainCheckResult(
        target='="formula",\nnext line',
        normalized_url="https://example.com",
        final_url="https://example.com/final",
        status_code=200,
        response_headers=(
            ("Server", 'nginx, "quoted"\nsecond line'),
            ("X-Content-Type-Options", "nosniff"),
        ),
        cookies=(),
        https_used=True,
        certificate_valid=True,
        checked_at=datetime(2026, 10, 26, 12, 30, tzinfo=timezone.utc),
    )
    return evaluate(observations)


def test_json_export_contains_assessment_metadata_and_findings(tmp_path):
    path = tmp_path / "report.json"
    assessment = _assessment()
    write_json_report(assessment, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target"] == '="formula",\nnext line'
    assert data["normalized_url"] == "https://example.com"
    assert data["final_url"] == "https://example.com/final"
    assert data["hardening_score"] == assessment.score
    assert data["grade"] == assessment.grade
    assert data["ruleset_version"] == assessment.ruleset_version
    assert data["timestamp"] == assessment.observations.checked_at.isoformat()
    assert data["findings"]
    assert data["disclaimer"] == DISCLAIMER
    assert "Set-Cookie" not in json.dumps(data)


def test_csv_export_quotes_special_characters_and_neutralizes_formulas(tmp_path):
    path = tmp_path / "report.csv"
    write_csv_report(_assessment(), path)
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert rows[0]["target"] == "'" + '="formula",\nnext line'
    assert rows[0]["final_url"] == "https://example.com/final"
    assert rows[0]["hardening_score"] != ""
    matching = next(row for row in rows if row["id"] == "disclosure.server")
    assert 'nginx, "quoted"\nsecond line' in matching["evidence"]
    assert matching["disclaimer"] == DISCLAIMER


def test_csv_formula_escape_applies_to_leading_formula_characters():
    from php2shell_detect.assessment_report import _spreadsheet_safe

    for value in ("=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", " \t=1+1"):
        assert _spreadsheet_safe(value).startswith("'")
    assert _spreadsheet_safe("ordinary text") == "ordinary text"


def test_csv_export_writes_metadata_even_when_there_are_no_findings(tmp_path):
    observations = DomainCheckResult(
        target="example.com",
        normalized_url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        response_headers=(),
        cookies=(),
        https_used=True,
        certificate_valid=True,
        checked_at=datetime(2026, 10, 26, tzinfo=timezone.utc),
    )
    assessment = evaluate(observations)
    assessment = type(assessment)(observations, (), 100, "A")
    path = tmp_path / "empty.csv"
    write_csv_report(assessment, path)
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["target"] == "example.com"
    assert rows[0]["hardening_score"] == "100"
