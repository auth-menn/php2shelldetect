from datetime import datetime, timezone

from gui import assessment_finding_to_row, filter_assessment_findings
from php2shell_detect.domain_check import DomainCheckResult
from php2shell_detect.scoring import evaluate


def test_gui_result_mapping_includes_finding_fields_and_not_assessed_status():
    observations = DomainCheckResult(
        target="http://example.com",
        normalized_url="http://example.com",
        final_url="http://example.com",
        status_code=200,
        response_headers=(),
        cookies=(),
        https_used=False,
        certificate_valid=None,
        checked_at=datetime(2026, 10, 26, tzinfo=timezone.utc),
    )
    assessment = evaluate(observations)
    certificate = next(
        finding for finding in assessment.findings if finding.id == "transport.certificate_not_assessed"
    )
    row = assessment_finding_to_row(certificate)
    assert row[0] == "Info"
    assert row[1] == "Transport"
    assert row[2].startswith("Not assessed:")
    assert row[3]
    assert row[4] == "Low"
    assert row[5]


def test_gui_severity_filter_only_returns_matching_findings():
    observations = DomainCheckResult(
        target="https://example.com",
        normalized_url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        response_headers=(),
        cookies=(),
        https_used=True,
        certificate_valid=True,
        checked_at=datetime(2026, 10, 26, tzinfo=timezone.utc),
    )
    findings = evaluate(observations).findings
    assert filter_assessment_findings(findings, "All") == findings
    assert all(
        finding.severity == "Medium"
        for finding in filter_assessment_findings(findings, "Medium")
    )
