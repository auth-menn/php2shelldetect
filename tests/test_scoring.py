from datetime import datetime, timezone

import pytest

from php2shell_detect.domain_check import CookieAttributes, DomainCheckResult
from php2shell_detect.scoring import DISCLAIMER, RULESET_VERSION, _grade, evaluate


def _observations(
    headers=(),
    cookies=(),
    *,
    url="https://example.com",
    certificate_valid=True,
    status=200,
):
    return DomainCheckResult(
        target=url,
        normalized_url=url,
        final_url=url,
        status_code=status,
        response_headers=tuple(headers),
        cookies=tuple(cookies),
        https_used=url.startswith("https:"),
        certificate_valid=certificate_valid,
        checked_at=datetime(2026, 10, 26, tzinfo=timezone.utc),
    )


def _ids(result):
    return {finding.id for finding in result.findings}


def test_missing_headers_each_produce_expected_hardening_findings():
    result = evaluate(_observations())
    ids = _ids(result)
    assert {
        "headers.hsts",
        "headers.csp",
        "headers.content_type_options",
        "headers.frame_protection",
        "headers.referrer_policy",
        "headers.permissions_policy",
    } <= ids
    assert next(f for f in result.findings if f.id == "headers.csp").severity == "Medium"
    assert next(f for f in result.findings if f.id == "headers.content_type_options").severity == "Low"


def test_transport_http_and_certificate_failure_are_high_severity():
    http_result = evaluate(
        _observations(url="http://example.com", certificate_valid=None)
    )
    assert next(f for f in http_result.findings if f.id == "transport.http").severity == "High"
    cert_result = evaluate(_observations(certificate_valid=False))
    assert next(f for f in cert_result.findings if f.id == "transport.certificate").severity == "High"


def test_http_200_is_not_reported_as_a_vulnerability():
    result = evaluate(_observations(status=200))
    assert not any("200" in f.observation for f in result.findings)
    assert all("vulnerability" not in f.observation.lower() for f in result.findings)


@pytest.mark.parametrize(
    "csp",
    [
        "default-src *",
        "default-src 'self'; script-src 'unsafe-inline'",
        "script-src 'unsafe-eval'",
    ],
)
def test_potentially_permissive_csp_is_flagged(csp):
    result = evaluate(_observations(headers=[("Content-Security-Policy", csp)]))
    finding = next(f for f in result.findings if f.id == "headers.csp_weak")
    assert finding.severity == "Medium"


def test_valid_headers_and_csp_frame_ancestors_prevent_missing_header_findings():
    result = evaluate(
        _observations(
            headers=[
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Permissions-Policy", "camera=(), microphone=()"),
            ]
        )
    )
    ids = _ids(result)
    assert not {"headers.hsts", "headers.csp", "headers.content_type_options",
                "headers.frame_protection", "headers.referrer_policy",
                "headers.permissions_policy"} & ids


def test_x_frame_options_also_counts_as_frame_protection():
    result = evaluate(_observations(headers=[("X-Frame-Options", "SAMEORIGIN")]))
    assert "headers.frame_protection" not in _ids(result)


def test_hsts_is_not_assessed_for_http():
    result = evaluate(_observations(url="http://example.com", certificate_valid=None))
    assert "headers.hsts" not in _ids(result)


def test_cookie_missing_attributes_are_reported_without_cookie_values():
    result = evaluate(
        _observations(
            cookies=(CookieAttributes("session", False, False, None),)
        )
    )
    by_id = {finding.id: finding for finding in result.findings}
    assert by_id["cookies.secure"].severity == "Medium"
    assert by_id["cookies.httponly"].severity == "Low"
    assert by_id["cookies.samesite"].severity == "Low"
    assert all("secret" not in finding.evidence.lower() for finding in result.findings)


def test_secure_cookie_attribute_is_not_penalized_over_http():
    result = evaluate(
        _observations(
            url="http://example.com",
            certificate_valid=None,
            cookies=(CookieAttributes("session", False, True, "Lax"),),
        )
    )
    secure = next(f for f in result.findings if f.id == "cookies.secure_not_assessed")
    assert secure.status == "Not assessed"
    assert secure.points_deduction == 0
    assert "cookies.secure" not in _ids(result)


def test_technology_disclosure_is_low_or_info_and_has_no_cve_mapping():
    result = evaluate(
        _observations(
            headers=[
                ("Server", "nginx"),
                ("X-Powered-By", "PHP/8.2.3"),
            ]
        )
    )
    server = next(f for f in result.findings if f.id == "disclosure.server")
    php = next(f for f in result.findings if f.id == "disclosure.powered_by")
    assert server.severity == "Info"
    assert php.severity == "Low"
    assert "manually verify" in php.recommendation.lower()
    assert "CVE" not in str(result.to_dict())
    assert "spoofed or generic" in php.observation


def test_not_assessed_information_does_not_deduct_score():
    result = evaluate(
        _observations(
            url="http://example.com",
            certificate_valid=None,
            headers=[
                ("Content-Security-Policy", "default-src 'self'"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                ("Permissions-Policy", "camera=()"),
            ],
        )
    )
    certificate = next(
        finding
        for finding in result.findings
        if finding.id == "transport.certificate_not_assessed"
    )
    assert certificate.status == "Not assessed"
    assert certificate.points_deduction == 0
    assert result.score == 75


def test_score_clamps_at_zero_and_is_deterministic():
    many_cookies = tuple(
        CookieAttributes(f"cookie-{index}", False, False, None) for index in range(12)
    )
    observations = _observations(cookies=many_cookies)
    first = evaluate(observations)
    second = evaluate(observations)
    assert first.score == 0
    assert first.grade == "F"
    assert first.to_dict() == second.to_dict()


@pytest.mark.parametrize(
    ("score", "grade"),
    [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"),
     (60, "C"), (59, "D"), (40, "D"), (39, "F"), (0, "F")],
)
def test_grade_boundaries(score, grade):
    assert _grade(score) == grade


def test_result_includes_ruleset_disclaimer_and_severity_counts():
    result = evaluate(_observations())
    serialized = result.to_dict()
    assert result.ruleset_version == RULESET_VERSION
    assert serialized["disclaimer"] == DISCLAIMER
    assert serialized["severity_counts"]["High"] == 0
