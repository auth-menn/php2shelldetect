"""Bounded passive HTTP metadata collection for one validated public target."""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

DEFAULT_TIMEOUT_SECONDS = 5
MAX_REQUESTS = 5
MAX_RESPONSE_HEADER_BYTES = 65536
MAX_RESPONSE_HEADERS = 100
_ALLOWED_SCHEMES = ("http", "https")
_USER_AGENT = "php2shell-detect/2.0 (bounded passive metadata assessment)"
ASSESSMENT_SCOPE = (
    "Single user-supplied URL; metadata-only GET; at most 5 validated requests "
    "including redirects; no crawling or endpoint discovery."
)
_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)
_SENSITIVE_HEADER_MARKERS = ("authorization", "cookie", "token", "secret", "password", "api-key")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_STATUS_LINE = re.compile(rb"^HTTP/1\.[01] ([0-9]{3})(?: .*)?\r?\n$")
_SCHEME_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:(?![0-9])")


class ValidationError(ValueError):
    """The supplied URL or a redirect target is invalid or unsafe."""


class NetworkError(OSError):
    """DNS, connection, or timeout failure while contacting a validated target."""


class HttpResponseError(RuntimeError):
    """The response is malformed, exceeds bounds, or redirects too many times."""


# Kept as a compatibility name for callers of the original domain-check API.
DomainCheckError = ValidationError


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    host: str
    port: int
    scheme: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class CookieAttributes:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "name": self.name,
            "secure": self.secure,
            "httponly": self.httponly,
            "samesite": self.samesite,
        }


@dataclass(frozen=True)
class DomainCheckResult:
    target: str
    normalized_url: str
    final_url: str
    status_code: int | None
    response_headers: tuple[tuple[str, str], ...]
    cookies: tuple[CookieAttributes, ...]
    https_used: bool
    certificate_valid: bool | None
    checked_at: datetime
    scope: str = ASSESSMENT_SCOPE

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "normalized_url": self.normalized_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "response_headers": [
                {"name": name, "value": value} for name, value in self.response_headers
            ],
            "cookies": [cookie.to_dict() for cookie in self.cookies],
            "https_used": self.https_used,
            "certificate_valid": self.certificate_valid,
            "timestamp": self.checked_at.isoformat(),
            "scope": self.scope,
        }


def normalize_url(raw_input: str) -> str:
    """Validate a target and return a URL, adding HTTPS only when no scheme exists."""
    if not isinstance(raw_input, str) or not raw_input:
        raise ValidationError("Target must be a non-empty URL, domain, or IP address.")
    if any(character.isspace() for character in raw_input) or "\\" in raw_input:
        raise ValidationError("Whitespace and backslashes are not allowed in a target.")

    raw = raw_input
    try:
        literal_ip = ipaddress.ip_address(raw)
    except ValueError:
        literal_ip = None
    if isinstance(literal_ip, ipaddress.IPv6Address):
        raw = f"https://[{literal_ip.compressed}]"
    elif not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", raw) and not _SCHEME_PREFIX.match(raw):
        raw = f"https://{raw}"

    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ValidationError(f"Malformed URL or invalid port: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValidationError("Only http:// and https:// targets are supported.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValidationError("URL credentials are not allowed.")
    if parsed.fragment:
        raise ValidationError("URL fragments are not allowed.")
    if not parsed.hostname or not parsed.netloc:
        raise ValidationError("The URL must include a hostname.")

    host = parsed.hostname
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValidationError("The hostname is not valid IDN.") from exc
        check_host = ascii_host[:-1] if ascii_host.endswith(".") else ascii_host
        labels = check_host.split(".")
        if (
            not check_host
            or len(ascii_host) > 254
            or any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in labels
            )
            or re.fullmatch(r"[0-9.]+", ascii_host)
        ):
            raise ValidationError("The hostname is malformed.")
        host = ascii_host
        netloc_host = host
    else:
        if isinstance(host_ip, ipaddress.IPv6Address):
            netloc_host = f"[{host_ip.compressed}]"
        else:
            netloc_host = str(host_ip)
            host = str(host_ip)

    if port is not None and not 1 <= port <= 65535:
        raise ValidationError("Port must be between 1 and 65535.")
    effective_port = port or (443 if scheme == "https" else 80)
    netloc = f"{netloc_host}:{port}" if port is not None else netloc_host
    return urlunsplit((scheme, netloc, parsed.path, parsed.query, ""))


def _is_public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value.split("%", 1)[0])
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (
        address.is_global
        and not address.is_loopback
        and not address.is_private
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


def _resolve_public_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NetworkError(f"DNS resolution failed: {exc}") from exc
    addresses: list[str] = []
    for answer in answers:
        address = answer[4][0].split("%", 1)[0]
        try:
            public = _is_public_ip(address)
        except ValueError as exc:
            raise NetworkError(f"DNS returned an invalid address: {address}") from exc
        if not public:
            raise ValidationError(
                "Target rejected: DNS returned a non-public, reserved, or special-use IP."
            )
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise NetworkError("DNS returned no addresses.")
    return tuple(addresses)


def validate_target(raw_input: str) -> ValidatedTarget:
    """Normalize a target and reject it unless every DNS answer is public."""
    normalized = normalize_url(raw_input)
    parsed = urlsplit(normalized)
    host = parsed.hostname
    if host is None:
        raise ValidationError("The URL must include a hostname.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = _resolve_public_addresses(host, port)
    return ValidatedTarget(normalized, host, port, parsed.scheme, addresses)


def _read_response(sock: socket.socket) -> tuple[int, list[tuple[str, str]]]:
    stream = sock.makefile("rb")
    total_bytes = 0
    try:
        status_line = stream.readline(MAX_RESPONSE_HEADER_BYTES + 1)
        total_bytes += len(status_line)
        match = _STATUS_LINE.fullmatch(status_line)
        if not match:
            raise HttpResponseError("The target returned an invalid HTTP status line.")
        status = int(match.group(1))
        headers: list[tuple[str, str]] = []
        while True:
            line = stream.readline(MAX_RESPONSE_HEADER_BYTES - total_bytes + 1)
            total_bytes += len(line)
            if total_bytes > MAX_RESPONSE_HEADER_BYTES:
                raise HttpResponseError("HTTP response headers exceed the 64 KiB limit.")
            if line in (b"\r\n", b"\n"):
                break
            if not line or len(headers) >= MAX_RESPONSE_HEADERS:
                raise HttpResponseError("The target returned incomplete or excessive headers.")
            if line[:1] in (b" ", b"\t") or b":" not in line:
                raise HttpResponseError("The target returned a malformed HTTP header.")
            name_bytes, value_bytes = line.split(b":", 1)
            try:
                name = name_bytes.decode("ascii")
                value = value_bytes.decode("latin-1").strip(" \t\r\n")
            except UnicodeDecodeError as exc:
                raise HttpResponseError("The target returned a malformed HTTP header.") from exc
            if not _HEADER_NAME.fullmatch(name):
                raise HttpResponseError("The target returned an invalid HTTP header name.")
            headers.append((name, value))
        return status, headers
    finally:
        stream.close()


def _request_once(
    target: ValidatedTarget, timeout: float
) -> tuple[int, list[tuple[str, str]], bool | None]:
    parsed = urlsplit(target.url)
    request_path = parsed.path or "/"
    if parsed.query:
        request_path += f"?{parsed.query}"
    peer_ip: str | None = None
    sock: socket.socket | None = None
    try:
        last_error: OSError | None = None
        for address in target.addresses:
            try:
                candidate = socket.create_connection((address, target.port), timeout=timeout)
                peer_ip = candidate.getpeername()[0].split("%", 1)[0]
                if ipaddress.ip_address(peer_ip) != ipaddress.ip_address(address):
                    candidate.close()
                    raise NetworkError("Connected peer did not match the validated IP address.")
                sock = candidate
                break
            except NetworkError:
                raise
            except OSError as exc:
                last_error = exc
        if sock is None:
            raise last_error or OSError("Unable to connect to a validated address.")
        sock.settimeout(timeout)
        certificate_valid: bool | None = None
        if target.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=target.host)
            certificate_valid = True

        host_header = parsed.netloc
        request = (
            f"GET {request_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        status, headers = _read_response(sock)
        return status, headers, certificate_valid
    except (socket.timeout, TimeoutError) as exc:
        raise NetworkError(f"Connection timed out: {exc}") from exc
    except ssl.SSLCertVerificationError:
        raise
    except ssl.SSLError as exc:
        raise NetworkError(f"TLS negotiation failed: {exc}") from exc
    except (http.client.HTTPException, OSError) as exc:
        if isinstance(exc, NetworkError):
            raise
        raise NetworkError(f"Connection failed: {exc}") from exc
    finally:
        if sock is not None:
            sock.close()


def _safe_response_headers(headers: list[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    return tuple(
        (name, value)
        for name, value in headers
        if name.lower() != "set-cookie"
        and not any(marker in name.lower() for marker in _SENSITIVE_HEADER_MARKERS)
    )


def _parse_cookies(headers: list[tuple[str, str]]) -> tuple[CookieAttributes, ...]:
    cookies: list[CookieAttributes] = []
    for header_name, header_value in headers:
        if header_name.lower() != "set-cookie":
            continue
        parts = [part.strip() for part in header_value.split(";")]
        name = parts[0].split("=", 1)[0].strip() if parts else ""
        if not name:
            continue
        attributes = {}
        for part in parts[1:]:
            key, separator, value = part.partition("=")
            attributes[key.strip().lower()] = value.strip() if separator else None
        cookies.append(
            CookieAttributes(
                name=name,
                secure="secure" in attributes,
                httponly="httponly" in attributes,
                samesite=attributes.get("samesite"),
            )
        )
    return tuple(cookies)


def check_domain(raw_input: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> DomainCheckResult:
    """Collect metadata from a bounded sequence of IP-pinned, validated requests."""
    normalized = normalize_url(raw_input)
    current_url = normalized
    final_status: int | None = None
    final_headers: list[tuple[str, str]] = []
    certificate_valid: bool | None = None

    for request_number in range(MAX_REQUESTS):
        target = validate_target(current_url)
        try:
            status, headers, certificate_valid = _request_once(target, timeout)
        except ssl.SSLCertVerificationError:
            if target.scheme != "https":
                raise
            return DomainCheckResult(
                target=raw_input,
                normalized_url=normalized,
                final_url=current_url,
                status_code=None,
                response_headers=(),
                cookies=(),
                https_used=True,
                certificate_valid=False,
                checked_at=datetime.now(timezone.utc),
            )
        final_status, final_headers = status, headers
        if status not in (301, 302, 303, 307, 308):
            break
        location = next(
            (value for name, value in headers if name.lower() == "location"), None
        )
        if not location:
            break
        if request_number == MAX_REQUESTS - 1:
            raise HttpResponseError("Redirect limit reached (maximum 5 requests).")
        candidate = urljoin(current_url, location)
        try:
            current_url = normalize_url(candidate)
            validate_target(current_url)
        except ValidationError as exc:
            raise HttpResponseError(f"Redirect target rejected: {exc}") from exc

    parsed_final = urlsplit(current_url)
    return DomainCheckResult(
        target=raw_input,
        normalized_url=normalized,
        final_url=current_url,
        status_code=final_status,
        response_headers=_safe_response_headers(final_headers),
        cookies=_parse_cookies(final_headers),
        https_used=parsed_final.scheme == "https",
        certificate_valid=certificate_valid if parsed_final.scheme == "https" else None,
        checked_at=datetime.now(timezone.utc),
    )


# Compatibility data model and pure header analyzer retained for existing callers.
@dataclass
class DomainObservation:
    category: str
    item: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"category": self.category, "item": self.item, "status": self.status, "detail": self.detail}


def analyze_headers(
    header_items: list[tuple[str, str]], scheme: str
) -> list[DomainObservation]:
    observations: list[DomainObservation] = []
    observations.append(
        DomainObservation(
            "https",
            "Skema URL",
            "info",
            "Request dilakukan lewat HTTPS (certificate validation passed)."
            if scheme == "https"
            else "Request dilakukan lewat HTTP biasa (TIDAK terenkripsi).",
        )
    )
    headers = {name.lower(): value for name, value in header_items}
    for name in _SECURITY_HEADERS:
        value = headers.get(name.lower())
        observations.append(
            DomainObservation(
                "security_header",
                name,
                "ditemukan" if value else "tidak_ditemukan",
                f"Nilai: {value}" if value else "Header ini tidak ada di response.",
            )
        )
    for name in ("Server", "X-Powered-By"):
        value = headers.get(name.lower())
        if value:
            observations.append(
                DomainObservation("server_info", name, "ditemukan", f"Nilai terekspos: '{value}'.")
            )
    for cookie in _parse_cookies(header_items):
        missing = [
            name
            for name, present in (
                ("Secure", cookie.secure),
                ("HttpOnly", cookie.httponly),
                ("SameSite", cookie.samesite is not None),
            )
            if not present
        ]
        detail = (
            "Flag Secure, HttpOnly, dan SameSite semuanya ditemukan pada cookie ini."
            if not missing
            else f"Flag yang TIDAK ditemukan pada cookie ini: {', '.join(missing)}."
        )
        observations.append(DomainObservation("cookie", cookie.name, "info", detail))
    return observations


def fetch_headers(
    url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> tuple[int, list[tuple[str, str]]]:
    """Compatibility wrapper for one safe request; redirects are handled by check_domain."""
    target = validate_target(url)
    status, headers, _ = _request_once(target, timeout)
    return status, headers
