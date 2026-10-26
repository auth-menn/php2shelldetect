from datetime import datetime, timezone
from urllib.parse import urlsplit

import pytest

from php2shell_detect.domain_check import (
    CookieAttributes,
    DomainCheckResult,
    ValidatedTarget,
    normalize_url,
)
from php2shell_detect.scoring import SCORING_RULE_IDS, evaluate
from php2shell_detect.verification_guide import (
    GUIDES,
    REFERENCE_URLS,
    Step,
    VerificationState,
    guide_for_finding,
    render_command,
    verification_key,
)


def _assessment_for_all_rules():
    checked_at = datetime(2026, 10, 26, tzinfo=timezone.utc)
    header_observations = DomainCheckResult(
        target="https://example.com",
        normalized_url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        response_headers=(
            ("Content-Security-Policy", "script-src *"),
            ("Server", "nginx/1.24"),
            ("X-Powered-By", "PHP/8.2"),
        ),
        cookies=(CookieAttributes("session", False, False, None),),
        https_used=True,
        certificate_valid=True,
        checked_at=checked_at,
    )
    transport_observations = DomainCheckResult(
        target="http://example.com",
        normalized_url="http://example.com",
        final_url="http://example.com",
        status_code=None,
        response_headers=(),
        cookies=(),
        https_used=False,
        certificate_valid=None,
        checked_at=checked_at,
        http_used=True,
    )
    certificate_failure = DomainCheckResult(
        target="https://example.com",
        normalized_url="https://example.com",
        final_url="https://example.com",
        status_code=None,
        response_headers=(),
        cookies=(),
        https_used=True,
        certificate_valid=False,
        checked_at=checked_at,
    )
    empty_csp = DomainCheckResult(
        target="https://example.com",
        normalized_url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        response_headers=(),
        cookies=(),
        https_used=True,
        certificate_valid=True,
        checked_at=checked_at,
    )
    http_cookie = DomainCheckResult(
        target="http://example.com",
        normalized_url="http://example.com",
        final_url="http://example.com",
        status_code=200,
        response_headers=(),
        cookies=(CookieAttributes("session", False, False, None),),
        https_used=False,
        certificate_valid=None,
        checked_at=checked_at,
        http_used=True,
    )
    return (
        header_observations,
        transport_observations,
        certificate_failure,
        empty_csp,
        http_cookie,
    )


def test_every_scoring_finding_id_has_a_complete_guide():
    observations = _assessment_for_all_rules()
    emitted_ids = set()
    for item in observations:
        emitted_ids.update(finding.id for finding in evaluate(item).findings)
    assert emitted_ids == SCORING_RULE_IDS
    assert emitted_ids <= GUIDES.keys()
    for finding_id in emitted_ids:
        guide = GUIDES[finding_id]
        assert guide.manual_steps
        assert guide.expected_if_confirmed
        assert guide.expected_if_false_positive
        assert guide.references
        assert set(guide.references) <= set(REFERENCE_URLS.values())


def test_catalog_has_no_active_testing_instructions():
    forbidden = (
        "sqlmap",
        "nmap",
        "nikto",
        "hydra",
        "gobuster",
        "ffuf",
        "payload",
        "exploit",
        "shell upload",
    )
    for guide in GUIDES.values():
        content = str(guide.to_dict()).lower()
        assert not any(term in content for term in forbidden)
    for guide in GUIDES.values():
        for step in guide.manual_steps:
            if step.command_template:
                assert not any(term in step.command_template.lower() for term in forbidden)


def test_cookie_guides_include_browser_and_read_only_command_steps():
    for finding_id in ("cookies.secure", "cookies.httponly", "cookies.samesite"):
        guide = GUIDES[finding_id]
        assert any(step.tool == "Browser DevTools" for step in guide.manual_steps)
        assert any(
            step.command_template and step.command_template.startswith("curl.exe")
            for step in guide.manual_steps
        )
        assert any(
            step.command_template and step.command_template.startswith("Invoke-WebRequest")
            for step in guide.manual_steps
        )


@pytest.mark.parametrize(
    ("url", "address", "expected"),
    [
        ("https://example.com", "8.8.8.8", "https://example.com"),
        ("https://8.8.8.8", "8.8.8.8", "https://8.8.8.8"),
        (
            "https://[2606:4700:4700::1111]",
            "2606:4700:4700::1111",
            "https://[2606:4700:4700::1111]",
        ),
        (
            "https://xn--bcher-kva.example",
            "8.8.8.8",
            "https://xn--bcher-kva.example",
        ),
        (
            "https://example.com:8443/status",
            "8.8.8.8",
            "https://example.com:8443/status",
        ),
    ],
)
def test_render_command_handles_validated_target_forms(url, address, expected):
    step = GUIDES["headers.hsts"].manual_steps[1]
    parsed = urlsplit(url)
    target = ValidatedTarget(
        url,
        parsed.hostname or "",
        parsed.port or (443 if parsed.scheme == "https" else 80),
        parsed.scheme,
        (address,),
    )
    command = render_command(step, target)
    assert expected in command
    assert command.startswith("curl.exe ")
    powershell_step = GUIDES["headers.hsts"].manual_steps[2]
    assert render_command(powershell_step, target).startswith("Invoke-WebRequest ")
    if ":" in (parsed.hostname or ""):
        certificate_step = GUIDES["transport.certificate"].manual_steps[-1]
        openssl_command = render_command(certificate_step, target)
        assert f"-connect [{parsed.hostname}]:443" in openssl_command
        assert "-servername" not in openssl_command


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/a;whoami",
        "https://example.com/a&b",
        "https://example.com/a|b",
        "https://example.com/a`b",
        "https://example.com/$(whoami)",
        "https://example.com/a'b",
        'https://example.com/a"b',
        "https://example.com/a\nb",
        "https://example.com/a b",
    ],
)
def test_render_command_rejects_shell_injection_characters(url):
    target = ValidatedTarget(url, "example.com", 443, "https", ("8.8.8.8",))
    with pytest.raises(ValueError):
        render_command(GUIDES["headers.hsts"].manual_steps[1], target)


def test_render_command_rejects_untrusted_template_and_non_public_target():
    with pytest.raises(ValueError):
        render_command(
            Step("bad", "PowerShell", "bad", "Invoke-Expression {url}"),
            ValidatedTarget("https://example.com", "example.com", 443, "https", ("8.8.8.8",)),
        )
    with pytest.raises(ValueError):
        render_command(
            GUIDES["headers.hsts"].manual_steps[1],
            ValidatedTarget("https://example.com", "example.com", 443, "https", ("127.0.0.1",)),
        )


def test_guide_lookup_returns_guide_for_selected_finding_id():
    guide = guide_for_finding("headers.csp")
    assert guide is GUIDES["headers.csp"]
    assert guide_for_finding("not.a.finding") is None


def test_verification_state_key_distinguishes_repeated_rule_occurrences():
    assert verification_key("cookies.httponly", 0) != verification_key(
        "cookies.httponly", 1
    )
    assert verification_key("headers.csp", 0) == "headers.csp::0"


def test_verification_status_does_not_change_hardening_score():
    assessment = evaluate(_assessment_for_all_rules()[0])
    original_score = assessment.score
    states = {
        verification_key(finding.id, index): VerificationState("False Positive", "Checked manually")
        for index, finding in enumerate(assessment.findings)
    }
    assert states
    assert evaluate(_assessment_for_all_rules()[0]).score == original_score


def test_render_command_preserves_normalized_idn_and_custom_port():
    idn = normalize_url("bücher.example")
    idn_target = ValidatedTarget(
        idn, "xn--bcher-kva.example", 443, "https", ("8.8.8.8",)
    )
    assert "https://xn--bcher-kva.example" in render_command(
        GUIDES["headers.hsts"].manual_steps[1], idn_target
    )
    custom = normalize_url("https://example.com:8443/status")
    custom_target = ValidatedTarget(
        custom, "example.com", 8443, "https", ("8.8.8.8",)
    )
    command = render_command(GUIDES["transport.certificate"].manual_steps[-1], custom_target)
    assert "example.com:8443" in command
    assert "-servername example.com" in command
