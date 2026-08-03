"""
analyzer.py
-----------
Core scanning logic for the Security Header Analyzer.

Responsible for:
  * Safely fetching the target URL over HTTPS (and HTTP as a fallback check)
  * Parsing security-relevant response headers and Set-Cookie attributes
  * Producing a list of structured findings using findings_db.py

This module has no Flask/UI dependencies so it can be reused from the CLI,
tests, or a different frontend.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import requests

from findings_db import FINDINGS

USER_AGENT = "SecurityHeaderAnalyzer/1.0 (+internal security tooling)"
REQUEST_TIMEOUT = 10  # seconds
MAX_REDIRECTS = 5

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str
    impact: str
    remediation: str
    owasp: str
    cwe: str
    standards: str
    evidence: Optional[str] = None

    @classmethod
    def from_template(cls, finding_id: str, evidence: str | None = None) -> "Finding":
        tpl = FINDINGS[finding_id]
        return cls(id=finding_id, evidence=evidence, **tpl)


@dataclass
class CookieAnalysis:
    name: str
    raw: str
    http_only: bool
    secure: bool
    samesite: Optional[str]


@dataclass
class ScanResult:
    target: str
    final_url: str
    status_code: Optional[int] = None
    used_https: bool = False
    headers: dict = field(default_factory=dict)
    cookies: List[CookieAnalysis] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def findings_sorted(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def summary_counts(self) -> dict:
        counts = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


class InvalidTargetError(ValueError):
    """Raised when the supplied target fails validation (SSRF guard, etc.)."""


def _validate_target(url: str) -> str:
    """
    Basic SSRF / input-safety guard for a self-hosted scanning tool.
    Ensures the URL is well-formed http(s) and does not resolve to a
    private / loopback / link-local address, which would allow the tool to
    be abused to probe the operator's internal network.
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise InvalidTargetError("URL must be a valid http:// or https:// address.")

    hostname = parsed.hostname
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise InvalidTargetError(f"Could not resolve host '{hostname}': {exc}") from exc

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise InvalidTargetError(
                "Target resolves to a private/internal address and cannot be scanned."
            )

    return url


def _parse_cookies(response: requests.Response) -> List[CookieAnalysis]:
    cookies = []
    for raw_header in response.raw.headers.get_all("Set-Cookie") or []:
        parts = [p.strip() for p in raw_header.split(";")]
        name = parts[0].split("=", 1)[0] if parts else "unknown"
        lowered = [p.lower() for p in parts[1:]]
        http_only = any(p == "httponly" for p in lowered)
        secure = any(p == "secure" for p in lowered)
        samesite = None
        for p in parts[1:]:
            if p.lower().startswith("samesite="):
                samesite = p.split("=", 1)[1]
        cookies.append(
            CookieAnalysis(
                name=name,
                raw=raw_header,
                http_only=http_only,
                secure=secure,
                samesite=samesite,
            )
        )
    return cookies


def _analyze_hsts(headers: dict, used_https: bool, findings: List[Finding]):
    if not used_https:
        return  # HSTS is meaningless without HTTPS; no_https finding already raised
    value = headers.get("strict-transport-security")
    if not value:
        findings.append(Finding.from_template("hsts_missing"))
        return
    max_age_match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    if max_age < 31536000:
        findings.append(Finding.from_template("hsts_short_max_age", evidence=value))
    if "includesubdomains" not in value.lower():
        findings.append(Finding.from_template("hsts_no_subdomains", evidence=value))


def _analyze_csp(headers: dict, findings: List[Finding]):
    value = headers.get("content-security-policy")
    if not value:
        findings.append(Finding.from_template("csp_missing"))
        return
    lowered = value.lower()
    if "unsafe-inline" in lowered:
        findings.append(Finding.from_template("csp_unsafe_inline", evidence=value))
    if "unsafe-eval" in lowered:
        findings.append(Finding.from_template("csp_unsafe_eval", evidence=value))
    if re.search(r"(^|\s)\*(\s|;|$)", lowered) or "https:" in lowered.split(";")[0]:
        findings.append(Finding.from_template("csp_wildcard_source", evidence=value))
    if "frame-ancestors" not in lowered:
        findings.append(Finding.from_template("csp_missing_frame_ancestors", evidence=value))


def _analyze_xfo(headers: dict, csp_value: Optional[str], findings: List[Finding]):
    value = headers.get("x-frame-options")
    has_frame_ancestors = csp_value and "frame-ancestors" in csp_value.lower()
    if not value:
        if not has_frame_ancestors:
            findings.append(Finding.from_template("xfo_missing"))
        return
    if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(Finding.from_template("xfo_weak_value", evidence=value))


def _analyze_xcto(headers: dict, findings: List[Finding]):
    value = headers.get("x-content-type-options")
    if not value or value.strip().lower() != "nosniff":
        findings.append(Finding.from_template("xcto_missing", evidence=value))


def _analyze_referrer_policy(headers: dict, findings: List[Finding]):
    value = headers.get("referrer-policy")
    if not value:
        findings.append(Finding.from_template("referrer_policy_missing"))
        return
    permissive = {"unsafe-url", "no-referrer-when-downgrade"}
    if value.strip().lower() in permissive:
        findings.append(Finding.from_template("referrer_policy_permissive", evidence=value))


def _analyze_permissions_policy(headers: dict, findings: List[Finding]):
    if not headers.get("permissions-policy"):
        findings.append(Finding.from_template("permissions_policy_missing"))


def _analyze_cookies(cookies: List[CookieAnalysis], findings: List[Finding]):
    for c in cookies:
        if not c.http_only:
            findings.append(Finding.from_template("cookie_missing_httponly", evidence=f"{c.name}: {c.raw}"))
        if not c.secure:
            findings.append(Finding.from_template("cookie_missing_secure", evidence=f"{c.name}: {c.raw}"))
        if not c.samesite:
            findings.append(Finding.from_template("cookie_missing_samesite", evidence=f"{c.name}: {c.raw}"))
        elif c.samesite.lower() == "none" and not c.secure:
            findings.append(Finding.from_template("cookie_samesite_none_insecure", evidence=f"{c.name}: {c.raw}"))


def scan(target: str) -> ScanResult:
    """
    Run a full header/cookie security scan against `target`.

    Returns a populated ScanResult. Network / validation errors are captured
    in ScanResult.error rather than raised, so callers (web UI, CLI, tests)
    can render a clean error message.
    """
    try:
        url = _validate_target(target)
    except InvalidTargetError as exc:
        return ScanResult(target=target, final_url=target, error=str(exc))

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )
    except requests.exceptions.SSLError:
        # HTTPS failed outright -> treat as "no HTTPS enforced"
        result = ScanResult(target=target, final_url=url, used_https=False)
        result.findings.append(Finding.from_template("no_https"))
        return result
    except requests.exceptions.RequestException as exc:
        return ScanResult(target=target, final_url=url, error=f"Request failed: {exc}")

    used_https = response.url.lower().startswith("https://")
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    cookies = _parse_cookies(response)

    result = ScanResult(
        target=target,
        final_url=response.url,
        status_code=response.status_code,
        used_https=used_https,
        headers=dict(response.headers),
        cookies=cookies,
    )

    if not used_https:
        result.findings.append(Finding.from_template("no_https"))

    _analyze_hsts(headers_lower, used_https, result.findings)
    _analyze_csp(headers_lower, result.findings)
    _analyze_xfo(headers_lower, headers_lower.get("content-security-policy"), result.findings)
    _analyze_xcto(headers_lower, result.findings)
    _analyze_referrer_policy(headers_lower, result.findings)
    _analyze_permissions_policy(headers_lower, result.findings)
    _analyze_cookies(cookies, result.findings)

    return result
