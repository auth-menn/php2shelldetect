"""Mocked tests for strict target validation and bounded passive collection."""

import io
import socket
import ssl

import pytest

from php2shell_detect import domain_check
from php2shell_detect.domain_check import (
    DomainCheckError,
    HttpResponseError,
    NetworkError,
    ValidationError,
    analyze_headers,
    check_domain,
    normalize_url,
    validate_target,
)
from php2shell_detect.scoring import evaluate


def _dns_answers(*addresses):
    return [
        (socket.AF_INET6 if ":" in address else socket.AF_INET,
         socket.SOCK_STREAM,
         socket.IPPROTO_TCP,
         "",
         (address, 443))
        for address in addresses
    ]


def _mock_dns(monkeypatch, answers=None):
    monkeypatch.setattr(
        domain_check.socket,
        "getaddrinfo",
        lambda host, port, type: answers if answers is not None else _dns_answers("8.8.8.8"),
    )


class FakeSocket:
    def __init__(self, response=b"HTTP/1.1 200 OK\r\nServer: example\r\n\r\n"):
        self.response = response
        self.request = b""
        self.closed = False

    def getpeername(self):
        return ("8.8.8.8", 443)

    def settimeout(self, _timeout):
        pass

    def sendall(self, request):
        self.request = request

    def makefile(self, _mode):
        return io.BytesIO(self.response)

    def close(self):
        self.closed = True


def test_normalize_url_adds_https_when_no_scheme():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_explicit_http_and_https_path():
    assert normalize_url("http://example.com") == "http://example.com"
    assert normalize_url("https://example.com/login") == "https://example.com/login"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("8.8.8.8", "https://8.8.8.8"),
        ("https://8.8.8.8:8443/path", "https://8.8.8.8:8443/path"),
        ("2606:4700:4700::1111", "https://[2606:4700:4700::1111]"),
        ("https://[2606:4700:4700::1111]/health", "https://[2606:4700:4700::1111]/health"),
        ("bücher.example", "https://xn--bcher-kva.example"),
        ("example.com:8443/path", "https://example.com:8443/path"),
        ("https://example.com/café", "https://example.com/caf%C3%A9"),
    ],
)
def test_normalize_url_accepts_domains_urls_ips_and_idn(target, expected):
    assert normalize_url(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "",
        " ",
        " example.com",
        "example.com ",
        "https://example .com",
        "https://example.com/a\tb",
        "https://example.com\x00",
        "ftp://example.com",
        "mailto:user@example.com",
        "http:80",
        "https:443",
        "https://",
        "https:///path",
        "https://-bad.example",
        "https://bad_name.example",
        "https://999.1.1.1",
        "https://user:pass@example.com",
        "https://example.com/#fragment",
        "https://example.com:0",
        "https://example.com:",
        "https://example.com:65536",
        "https://example.com:notaport",
        "https://example.com/%zz",
        "https://[2001:db8::1",
        "https://2001:db8::1",
    ],
)
def test_normalize_url_rejects_malformed_or_unsupported_targets(target):
    with pytest.raises(ValidationError):
        normalize_url(target)


def test_domain_check_error_remains_compatibility_alias():
    assert DomainCheckError is ValidationError


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "192.0.2.1",
        "192.0.0.9",
        "::",
        "::1",
        "::808:808",
        "64:ff9b::808:808",
        "64:ff9b:1::808:808",
        "2001::1",
        "2002:808:808::",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
    ],
)
def test_validate_target_rejects_non_public_ip_answers(monkeypatch, address):
    _mock_dns(monkeypatch, _dns_answers(address))
    with pytest.raises(ValidationError, match="non-public"):
        validate_target("example.com")


def test_validate_target_rejects_mixed_public_and_non_public_dns_answers(monkeypatch):
    _mock_dns(monkeypatch, _dns_answers("8.8.8.8", "10.0.0.5"))
    with pytest.raises(ValidationError, match="non-public"):
        validate_target("example.com")


def test_validate_target_accepts_public_ipv4_and_ipv6_answers(monkeypatch):
    _mock_dns(monkeypatch, _dns_answers("8.8.8.8"))
    assert validate_target("example.com").addresses == ("8.8.8.8",)
    _mock_dns(monkeypatch, _dns_answers("2606:4700:4700::1111"))
    assert validate_target("https://[2606:4700:4700::1111]").addresses == (
        "2606:4700:4700::1111",
    )


def test_validate_target_maps_dns_errors_to_network_error(monkeypatch):
    def fail_dns(*_args, **_kwargs):
        raise socket.gaierror("DNS unavailable")

    monkeypatch.setattr(domain_check.socket, "getaddrinfo", fail_dns)
    with pytest.raises(NetworkError, match="DNS resolution failed"):
        validate_target("example.com")


def test_analyze_headers_detects_missing_and_present_security_headers():
    observations = analyze_headers([], "https")
    statuses = {item.item: item.status for item in observations if item.category == "security_header"}
    assert statuses["Strict-Transport-Security"] == "tidak_ditemukan"
    assert statuses["X-Frame-Options"] == "tidak_ditemukan"
    present = analyze_headers([("Strict-Transport-Security", "max-age=31536000")], "https")
    hsts = next(item for item in present if item.item == "Strict-Transport-Security")
    assert hsts.status == "ditemukan"
    assert "max-age=31536000" in hsts.detail


def test_analyze_headers_exposes_server_and_php_version_without_cve_claims():
    observations = analyze_headers(
        [("Server", "nginx/1.24.0"), ("X-Powered-By", "PHP/8.1.2")], "https"
    )
    assert "nginx/1.24.0" in next(item for item in observations if item.item == "Server").detail
    assert "PHP/8.1.2" in next(item for item in observations if item.item == "X-Powered-By").detail


def test_analyze_headers_cookie_flags_and_multiple_cookies():
    observations = analyze_headers(
        [
            ("Set-Cookie", "session=secret; path=/"),
            ("Set-Cookie", "tracking=secret; Secure; HttpOnly; SameSite=Lax"),
        ],
        "https",
    )
    cookies = {item.item: item.detail for item in observations if item.category == "cookie"}
    assert set(cookies) == {"session", "tracking"}
    assert "Secure" in cookies["session"] and "HttpOnly" in cookies["session"]
    assert "semuanya ditemukan" in cookies["tracking"]
    assert all("secret" not in detail for detail in cookies.values())


def test_analyze_headers_http_is_reported_without_vulnerability_claims():
    observations = analyze_headers(
        [("Server", "Apache/2.4.1"), ("Set-Cookie", "session=abc")], "http"
    )
    assert "TIDAK terenkripsi" in next(item for item in observations if item.category == "https").detail
    prohibited = ("rentan", "vulnerable", "berbahaya", "vulnerability")
    for item in observations:
        assert not any(word in f"{item.item} {item.detail}".lower() for word in prohibited)


def test_request_pins_to_validated_ip_and_reads_metadata_only(monkeypatch):
    fake = FakeSocket()
    monkeypatch.setattr(domain_check.socket, "create_connection", lambda address, timeout: fake)
    target = domain_check.ValidatedTarget(
        "http://example.com/check?q=1", "example.com", 80, "http", ("8.8.8.8",)
    )
    status, headers, certificate_valid = domain_check._request_once(target, 1)
    assert status == 200
    assert headers == [("Server", "example")]
    assert certificate_valid is None
    assert b"HEAD /check?q=1 HTTP/1.1" in fake.request
    assert b"Host: example.com" in fake.request
    assert fake.closed


def test_request_rejects_peer_address_not_equal_to_validated_ip(monkeypatch):
    fake = FakeSocket()
    fake.getpeername = lambda: ("1.1.1.1", 443)
    monkeypatch.setattr(domain_check.socket, "create_connection", lambda address, timeout: fake)
    target = domain_check.ValidatedTarget(
        "http://example.com", "example.com", 80, "http", ("8.8.8.8",)
    )
    with pytest.raises(NetworkError, match="peer"):
        domain_check._request_once(target, 1)


def test_connection_timeout_and_connection_errors_are_network_errors(monkeypatch):
    _mock_dns(monkeypatch)
    monkeypatch.setattr(
        domain_check.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(socket.timeout("late")),
    )
    with pytest.raises(NetworkError, match="timed out"):
        check_domain("http://example.com")
    monkeypatch.setattr(
        domain_check.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(ConnectionRefusedError("refused")),
    )
    with pytest.raises(NetworkError, match="Connection failed"):
        check_domain("http://example.com")


def test_response_read_timeout_is_a_network_error(monkeypatch):
    _mock_dns(monkeypatch)

    class TimedOutReader:
        def readline(self, _limit):
            raise socket.timeout("read timeout")

        def close(self):
            pass

    class ReadTimeoutSocket(FakeSocket):
        def makefile(self, _mode):
            return TimedOutReader()

    monkeypatch.setattr(
        domain_check.socket,
        "create_connection",
        lambda address, timeout: ReadTimeoutSocket(),
    )
    with pytest.raises(NetworkError, match="timed out"):
        check_domain("http://example.com")


def test_tls_certificate_validation_failure_is_an_observation(monkeypatch):
    _mock_dns(monkeypatch)
    fake = FakeSocket()
    monkeypatch.setattr(domain_check.socket, "create_connection", lambda address, timeout: fake)

    class InvalidCertificateContext:
        def wrap_socket(self, _sock, server_hostname):
            assert server_hostname == "example.com"
            raise ssl.SSLCertVerificationError("certificate rejected")

    monkeypatch.setattr(domain_check.ssl, "create_default_context", InvalidCertificateContext)
    result = check_domain("https://example.com")
    assert result.certificate_valid is False
    assert result.status_code is None
    assert result.https_used


def test_tls_certificate_validation_success_is_reported(monkeypatch):
    fake = FakeSocket()
    monkeypatch.setattr(domain_check.socket, "create_connection", lambda address, timeout: fake)

    class ValidCertificateContext:
        def wrap_socket(self, sock, server_hostname):
            assert sock is fake
            assert server_hostname == "example.com"
            return sock

    monkeypatch.setattr(domain_check.ssl, "create_default_context", ValidCertificateContext)
    target = domain_check.ValidatedTarget(
        "https://example.com", "example.com", 443, "https", ("8.8.8.8",)
    )
    _status, _headers, certificate_valid = domain_check._request_once(target, 1)
    assert certificate_valid is True


def test_validated_request_count_is_capped_at_five(monkeypatch):
    _mock_dns(monkeypatch)
    requested = []

    def redirect(target, _timeout):
        requested.append(target.url)
        return 302, [("Location", "/next")], None

    monkeypatch.setattr(domain_check, "_request_once", redirect)
    with pytest.raises(HttpResponseError, match="maximum 5"):
        check_domain("http://example.com")
    assert len(requested) == domain_check.MAX_REQUESTS == 5


def test_redirect_to_private_ip_is_rejected_before_second_request(monkeypatch):
    calls = []
    answers = [_dns_answers("8.8.8.8"), _dns_answers("127.0.0.1")]
    monkeypatch.setattr(
        domain_check.socket, "getaddrinfo", lambda *args, **kwargs: answers.pop(0)
    )

    def redirect(_target, _timeout):
        calls.append("request")
        return 302, [("Location", "http://private.example/")], None

    monkeypatch.setattr(domain_check, "_request_once", redirect)
    with pytest.raises(HttpResponseError, match="Redirect target rejected"):
        check_domain("http://example.com")
    assert calls == ["request"]


def test_redirects_are_manual_and_final_url_is_reported(monkeypatch):
    _mock_dns(monkeypatch)
    results = iter(
        [
            (302, [("Location", "https://example.com/final")], None),
            (200, [("Content-Security-Policy", "default-src 'self'")], True),
        ]
    )
    requested = []

    def request(target, _timeout):
        requested.append(target.url)
        return next(results)

    monkeypatch.setattr(domain_check, "_request_once", request)
    result = check_domain("https://example.com/start")
    assert requested == ["https://example.com/start", "https://example.com/final"]
    assert result.final_url == "https://example.com/final"
    assert result.status_code == 200
    assert result.certificate_valid is True


def test_http_redirecting_to_https_is_still_reported_as_http_used(monkeypatch):
    _mock_dns(monkeypatch)
    results = iter(
        [
            (301, [("Location", "https://example.com/secure")], None),
            (200, [("Strict-Transport-Security", "max-age=31536000")], True),
        ]
    )
    monkeypatch.setattr(
        domain_check, "_request_once", lambda _target, _timeout: next(results)
    )
    result = check_domain("http://example.com/")
    assert result.final_url == "https://example.com/secure"
    assert result.http_used
    assert result.https_used
    assert "transport.http" in {finding.id for finding in evaluate(result).findings}


def test_response_headers_are_bounded_and_malformed_responses_rejected():
    with pytest.raises(HttpResponseError, match="invalid HTTP status"):
        domain_check._read_response(FakeSocket(b"not HTTP\r\n\r\n"))
    oversized = b"HTTP/1.1 200 OK\r\nX-Large: " + b"a" * domain_check.MAX_RESPONSE_HEADER_BYTES
    with pytest.raises(HttpResponseError, match="64 KiB"):
        domain_check._read_response(FakeSocket(oversized))


def test_check_domain_rejects_invalid_input_before_dns(monkeypatch):
    def unexpected_dns(*_args, **_kwargs):
        pytest.fail("DNS must not run for invalid input")

    monkeypatch.setattr(domain_check.socket, "getaddrinfo", unexpected_dns)
    with pytest.raises(ValidationError):
        check_domain("not a valid url with spaces")


def test_check_domain_has_no_live_network_dependency(monkeypatch):
    _mock_dns(monkeypatch)
    monkeypatch.setattr(
        domain_check,
        "_request_once",
        lambda _target, _timeout: (
            200,
            [
                ("Server", "nginx"),
                ("Set-Cookie", "session=secret-value; Secure; HttpOnly; SameSite=Lax"),
            ],
            True,
        ),
    )
    result = check_domain("example.com")
    assert result.status_code == 200
    assert result.certificate_valid is True
    assert result.cookies[0].name == "session"
    assert result.cookies[0].secure and result.cookies[0].httponly
    assert "secret-value" not in str(result.to_dict())


def test_response_export_omits_cookie_auth_token_and_redirect_headers():
    safe = domain_check._safe_response_headers(
        [
            ("Server", "nginx"),
            ("Set-Cookie", "session=secret"),
            ("X-API_Key", "secret"),
            ("X-Session-Token", "secret"),
            ("WWW-Authenticate", "Bearer secret"),
            ("Location", "https://example.com/?token=secret"),
        ]
    )
    assert safe == (("Server", "nginx"),)


def test_response_parser_rejects_control_characters_in_header_values():
    response = FakeSocket(b"HTTP/1.1 200 OK\r\nX-Header: bad\x00value\r\n\r\n")
    with pytest.raises(HttpResponseError, match="control character"):
        domain_check._read_response(response)
