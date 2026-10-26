"""Deterministic passive-metadata hardening scoring, separate from log analysis."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from .domain_check import DomainCheckResult

RULESET_VERSION = "1.0"
DISCLAIMER = "Based on passive metadata from a single bounded request set."
SEVERITY_DEDUCTIONS = {"High": 25, "Medium": 12, "Low": 4, "Info": 0}
GRADE_THRESHOLDS = (("A", 90), ("B", 75), ("C", 60), ("D", 40), ("F", 0))
Severity = Literal["Info", "Low", "Medium", "High"]
Confidence = Literal["Low", "Medium", "High"]


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    category: str
    observation: str
    evidence: str
    severity: Severity
    confidence: Confidence
    recommendation: str
    reference: str
    points_deduction: int
    status: Literal["Assessed", "Not assessed"] = "Assessed"

    def to_dict(self) -> dict[str, str | int]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "observation": self.observation,
            "evidence": self.evidence,
            "severity": self.severity,
            "confidence": self.confidence,
            "recommendation": self.recommendation,
            "reference": self.reference,
            "points_deduction": self.points_deduction,
            "status": self.status,
        }


@dataclass(frozen=True)
class AssessmentResult:
    observations: DomainCheckResult
    findings: tuple[Finding, ...]
    score: int
    grade: str
    ruleset_version: str = RULESET_VERSION

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = Counter(finding.severity for finding in self.findings)
        return {severity: counts.get(severity, 0) for severity in ("High", "Medium", "Low", "Info")}

    def to_dict(self) -> dict:
        return {
            **self.observations.to_dict(),
            "hardening_score": self.score,
            "grade": self.grade,
            "ruleset_version": self.ruleset_version,
            "severity_counts": self.severity_counts,
            "findings": [finding.to_dict() for finding in self.findings],
            "disclaimer": DISCLAIMER,
        }


def _make_finding(
    finding_id: str,
    title: str,
    category: str,
    observation: str,
    evidence: str,
    severity: Severity,
    confidence: Confidence,
    recommendation: str,
    reference: str,
    *,
    status: Literal["Assessed", "Not assessed"] = "Assessed",
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        category=category,
        observation=observation,
        evidence=evidence,
        severity=severity,
        confidence=confidence,
        recommendation=recommendation,
        reference=reference,
        points_deduction=0 if status == "Not assessed" else SEVERITY_DEDUCTIONS[severity],
        status=status,
    )


def _header_values(headers: tuple[tuple[str, str], ...], name: str) -> list[str]:
    return [value for key, value in headers if key.lower() == name.lower()]


def _grade(score: int) -> str:
    for grade, threshold in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def evaluate(observations: DomainCheckResult) -> AssessmentResult:
    """Evaluate passive response metadata into a deterministic hardening score."""
    findings: list[Finding] = []
    headers = observations.response_headers
    scheme = observations.final_url.partition(":")[0].lower()

    if scheme == "http":
        findings.append(
            _make_finding(
                "transport.http",
                "Unencrypted HTTP used",
                "Transport",
                "The final URL uses HTTP without transport encryption.",
                f"Final URL: {observations.final_url}",
                "High",
                "High",
                "Serve the site over HTTPS and redirect HTTP to HTTPS after confirming compatibility.",
                "MDN: HTTPS",
            )
        )
    if observations.certificate_valid is False:
        findings.append(
            _make_finding(
                "transport.certificate",
                "TLS certificate validation failed",
                "Transport",
                "The TLS certificate could not be validated by the system trust store.",
                "HTTPS handshake failed certificate validation; no certificate or response headers were trusted.",
                "High",
                "High",
                "Review the certificate chain, hostname, and validity dates; do not disable certificate validation.",
                "OWASP Secure Headers Project: Transport Layer Security",
            )
        )
    elif observations.certificate_valid is None:
        findings.append(
            _make_finding(
                "transport.certificate_not_assessed",
                "TLS certificate validation",
                "Transport",
                "Not assessed: the final response did not establish a verifiable HTTPS connection.",
                "TLS certificate outcome unavailable for the final URL.",
                "Info",
                "Low",
                "Use an HTTPS target when TLS configuration should be assessed.",
                "MDN: HTTPS",
                status="Not assessed",
            )
        )

    if scheme == "https":
        hsts = _header_values(headers, "Strict-Transport-Security")
        if not hsts or not any(re.search(r"(?:^|;)\s*max-age\s*=\s*[1-9][0-9]*", v, re.I) for v in hsts):
            findings.append(
                _make_finding(
                    "headers.hsts",
                    "Missing or ineffective HSTS",
                    "Headers",
                    "HSTS is absent or has no positive max-age on the HTTPS response.",
                    "Strict-Transport-Security: " + ("; ".join(hsts) if hsts else "not present"),
                    "Medium",
                    "High",
                    "Set a suitable positive max-age after confirming HTTPS works for all intended hosts.",
                    "OWASP Secure Headers Project",
                )
            )

    csp_values = _header_values(headers, "Content-Security-Policy")
    if not csp_values:
        findings.append(
            _make_finding(
                "headers.csp",
                "Content Security Policy not observed",
                "Headers",
                "No Content-Security-Policy response header was observed.",
                "Content-Security-Policy: not present",
                "Medium",
                "High",
                "Define and test a policy appropriate to the application; deploy gradually if needed.",
                "MDN: Content-Security-Policy",
            )
        )
    else:
        joined_csp = "; ".join(csp_values)
        if re.search(r"(?i)(?:\*|'unsafe-inline'|'unsafe-eval')", joined_csp):
            findings.append(
                _make_finding(
                    "headers.csp_weak",
                    "Potentially permissive Content Security Policy",
                    "Headers",
                    "The observed policy contains a broad wildcard or an unsafe script directive.",
                    f"Content-Security-Policy: {joined_csp}",
                    "Medium",
                    "Medium",
                    "Review whether broad sources or unsafe script directives can be removed.",
                    "MDN: Content-Security-Policy",
                )
            )

    xcto = _header_values(headers, "X-Content-Type-Options")
    if not xcto or not any(value.strip().lower() == "nosniff" for value in xcto):
        findings.append(
            _make_finding(
                "headers.content_type_options",
                "X-Content-Type-Options missing or weak",
                "Headers",
                "The response does not expose the expected nosniff value.",
                "X-Content-Type-Options: " + ("; ".join(xcto) if xcto else "not present"),
                "Low",
                "High",
                "Set X-Content-Type-Options: nosniff where appropriate.",
                "MDN: X-Content-Type-Options",
            )
        )

    xfo_values = _header_values(headers, "X-Frame-Options")
    csp_has_frame_ancestors = any(
        re.search(r"(?i)(?:^|;)\s*frame-ancestors\s+(?![^;]*\*)[^;]+", value)
        for value in csp_values
    )
    xfo_protects = any(value.strip().lower() in ("deny", "sameorigin") for value in xfo_values)
    if not xfo_protects and not csp_has_frame_ancestors:
        findings.append(
            _make_finding(
                "headers.frame_protection",
                "Frame protection not observed",
                "Headers",
                "Neither a recognized X-Frame-Options value nor CSP frame-ancestors was observed.",
                "X-Frame-Options: "
                + ("; ".join(xfo_values) if xfo_values else "not present")
                + "; CSP frame-ancestors: "
                + ("present" if csp_has_frame_ancestors else "not present"),
                "Low",
                "High",
                "Set an appropriate X-Frame-Options or Content-Security-Policy frame-ancestors directive.",
                "OWASP Secure Headers Project",
            )
        )

    referrer_values = _header_values(headers, "Referrer-Policy")
    weak_referrer = any(value.strip().lower() == "unsafe-url" for value in referrer_values)
    if not referrer_values or weak_referrer:
        findings.append(
            _make_finding(
                "headers.referrer_policy",
                "Referrer-Policy missing or permissive",
                "Headers",
                "Referrer-Policy is absent or uses unsafe-url.",
                "Referrer-Policy: " + ("; ".join(referrer_values) if referrer_values else "not present"),
                "Low",
                "High",
                "Choose a Referrer-Policy appropriate to the site's privacy requirements.",
                "MDN: Referrer-Policy",
            )
        )

    permissions = _header_values(headers, "Permissions-Policy")
    if not permissions:
        findings.append(
            _make_finding(
                "headers.permissions_policy",
                "Permissions-Policy not observed",
                "Headers",
                "No Permissions-Policy response header was observed.",
                "Permissions-Policy: not present",
                "Info",
                "High",
                "Consider explicitly limiting browser features the application does not need.",
                "MDN: Permissions-Policy",
            )
        )

    for cookie in observations.cookies:
        if scheme == "https" and not cookie.secure:
            findings.append(
                _make_finding(
                    "cookies.secure",
                    f"Cookie '{cookie.name}' missing Secure",
                    "Cookies",
                    f"Cookie '{cookie.name}' was observed without the Secure attribute.",
                    f"Set-Cookie attributes for {cookie.name}: Secure=missing",
                    "Medium",
                    "High",
                    "Set Secure on cookies that should only be sent over HTTPS.",
                    "MDN: Set-Cookie",
                )
            )
        elif scheme != "https":
            findings.append(
                _make_finding(
                    "cookies.secure_not_assessed",
                    f"Cookie '{cookie.name}' Secure attribute",
                    "Cookies",
                    f"Not assessed: Secure is relevant to HTTPS delivery for cookie '{cookie.name}'.",
                    "Cookie value withheld; Secure attribute not scored over HTTP.",
                    "Info",
                    "Low",
                    "Assess cookie transport flags after establishing HTTPS.",
                    "MDN: Set-Cookie",
                    status="Not assessed",
                )
            )
        if not cookie.httponly:
            findings.append(
                _make_finding(
                    "cookies.httponly",
                    f"Cookie '{cookie.name}' missing HttpOnly",
                    "Cookies",
                    f"Cookie '{cookie.name}' was observed without the HttpOnly attribute.",
                    f"Set-Cookie attributes for {cookie.name}: HttpOnly=missing",
                    "Low",
                    "High",
                    "Set HttpOnly on cookies that do not need to be read by client-side scripts.",
                    "MDN: Set-Cookie",
                )
            )
        if not cookie.samesite:
            findings.append(
                _make_finding(
                    "cookies.samesite",
                    f"Cookie '{cookie.name}' missing SameSite",
                    "Cookies",
                    f"Cookie '{cookie.name}' was observed without SameSite.",
                    f"Set-Cookie attributes for {cookie.name}: SameSite=missing",
                    "Low",
                    "High",
                    "Choose an appropriate SameSite value for the cookie's use.",
                    "MDN: Set-Cookie",
                )
            )

    for header_name, header_id in (("Server", "disclosure.server"), ("X-Powered-By", "disclosure.powered_by")):
        for value in _header_values(headers, header_name):
            has_version = bool(re.search(r"\d+(?:\.\d+){1,3}", value))
            php_banner = bool(re.search(r"(?i)\bphp(?:/|\s)", value))
            severity: Severity = "Low" if has_version or php_banner else "Info"
            findings.append(
                _make_finding(
                    header_id,
                    f"{header_name} banner exposed",
                    "Disclosure",
                    f"{header_name} exposes a generic or version-like banner; banners can be spoofed or generic.",
                    f"{header_name}: {value}",
                    severity,
                    "Medium",
                    "Consider minimizing unnecessary server-technology disclosure; manually verify exposed information.",
                    "OWASP Secure Headers Project",
                )
            )

    score = max(0, min(100, 100 - sum(item.points_deduction for item in findings)))
    return AssessmentResult(observations, tuple(findings), score, _grade(score))
