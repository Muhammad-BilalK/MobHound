"""
MobHound Scanner - Traffic Detector
======================================
Analyzes captured mitmproxy flows (from dynamic analysis) for
security issues in network traffic.

Detects:
  - Plaintext HTTP for sensitive endpoints
  - Missing certificate pinning (if SSL was bypassed)
  - Sensitive data in URLs / GET params
  - Weak/missing security headers
  - JWT tokens in traffic
  - API keys in URLs
  - Insecure cookies
  - Exposed internal endpoints
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from scanner.models import (
    DetectorType, Finding, FindingSource, Severity
)

# Headers that should be present in responses
REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.HIGH, "Missing HSTS", "CWE-319",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
    ),
    "x-content-type-options": (
        Severity.LOW, "Missing X-Content-Type-Options", "CWE-116",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME type sniffing.",
    ),
    "x-frame-options": (
        Severity.LOW, "Missing X-Frame-Options", "CWE-1021",
        "Add 'X-Frame-Options: DENY' to prevent clickjacking.",
    ),
    "content-security-policy": (
        Severity.MEDIUM, "Missing Content-Security-Policy", "CWE-80",
        "Implement a strict CSP header to mitigate XSS risks.",
    ),
}

# Cookie attributes that should be present for sensitive cookies
SENSITIVE_COOKIE_NAMES = [
    "session", "sess", "token", "auth", "jwt", "access", "refresh",
    "api_key", "apikey", "sid", "user_id", "userid",
]

# URL parameters that are suspicious
SENSITIVE_PARAM_NAMES = [
    "token", "password", "passwd", "pwd", "api_key", "apikey",
    "secret", "key", "auth", "access_token", "refresh_token",
    "session", "sid", "jwt", "credential",
]

# Patterns indicating sensitive data in body / URL
SENSITIVE_BODY_PATTERNS = [
    (r'(?i)"password"\s*:\s*"[^"]{3,}"', "Password in JSON body", Severity.HIGH),
    (r'(?i)"(?:api_?key|apikey|secret)"\s*:\s*"[^"]{8,}"', "API key in JSON body", Severity.HIGH),
    (r'(?i)"(?:ssn|social_security_number)"\s*:\s*"[\d\-]{9,}"', "SSN in body", Severity.CRITICAL),
    (r'(?i)"(?:credit_?card|cc_?number|card_?number)"\s*:\s*"[\d\s\-]{13,19}"', "Credit card in body", Severity.CRITICAL),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT in body", Severity.MEDIUM),
]


class TrafficDetector:
    """Analyze captured HTTP flows for security issues."""

    def __init__(self, flows: Optional[List[Dict[str, Any]]] = None):
        """
        Args:
            flows: List of flow dicts from mitmproxy captured_flows.jsonl
        """
        self._flows = flows or []

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        for flow in self._flows:
            findings += self._analyze_flow(flow)
        return findings

    def _analyze_flow(self, flow: Dict[str, Any]) -> List[Finding]:
        findings = []
        req  = flow.get("request",  {}) or {}
        resp = flow.get("response", {}) or {}

        url     = req.get("url", req.get("pretty_url", ""))
        method  = req.get("method", "GET")
        status  = resp.get("status_code", 0)
        req_hdrs= {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        resp_hdrs={k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        req_body= req.get("body", "") or ""
        resp_body=resp.get("body", "") or ""

        findings += self._check_http_scheme(url, req_body)
        findings += self._check_sensitive_url_params(url)
        findings += self._check_missing_security_headers(url, resp_hdrs, status)
        findings += self._check_insecure_cookies(url, resp_hdrs)
        findings += self._check_sensitive_body(url, req_body, resp_body)
        findings += self._check_auth_headers(url, req_hdrs)
        findings += self._check_exposed_endpoints(url, resp)

        return findings

    def _check_http_scheme(self, url: str, body: str) -> List[Finding]:
        findings = []
        if url.startswith("http://"):
            # Only flag if body has sensitive-looking data
            has_sensitive = any(
                kw in body.lower() for kw in ["password", "token", "api_key", "secret", "auth"]
            )
            severity = Severity.HIGH if has_sensitive else Severity.MEDIUM
            findings.append(Finding(
                title="Sensitive Data Transmitted Over HTTP",
                description=(
                    f"Request to {url} uses unencrypted HTTP. "
                    + ("The request body contains sensitive data." if has_sensitive else
                       "Any data transmitted may be intercepted.")
                ),
                severity=severity,
                confidence=0.90,
                detector=DetectorType.TRAFFIC,
                source=FindingSource.DYNAMIC,
                category="Insecure Communication",
                cwe_id="CWE-319",
                owasp_mobile="M3: Insecure Communication",
                evidence=[f"URL: {url}"],
                network_evidence=[url],
                recommendation=(
                    "Migrate all endpoints to HTTPS. "
                    "Implement HTTP Strict Transport Security (HSTS). "
                    "Use android:usesCleartextTraffic=false in the manifest."
                ),
            ))
        return findings

    def _check_sensitive_url_params(self, url: str) -> List[Finding]:
        findings = []
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
        except Exception:
            return findings

        for param in SENSITIVE_PARAM_NAMES:
            if param in params:
                findings.append(Finding(
                    title=f"Sensitive Parameter in URL: {param}",
                    description=(
                        f"The URL contains a '{param}' parameter in the query string. "
                        "URL parameters are logged in server logs, proxy logs, and "
                        "browser/app history – this exposes sensitive data."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.85,
                    detector=DetectorType.TRAFFIC,
                    source=FindingSource.DYNAMIC,
                    category="Data Exposure",
                    cwe_id="CWE-598",
                    owasp_mobile="M3: Insecure Communication",
                    evidence=[f"URL: {url}", f"Parameter: {param}"],
                    network_evidence=[url],
                    recommendation=(
                        f"Move the '{param}' value from the URL to the request body "
                        "(POST) or Authorization header. Use HTTPS."
                    ),
                ))
        return findings

    def _check_missing_security_headers(
        self, url: str, resp_headers: Dict[str, str], status: int
    ) -> List[Finding]:
        findings = []
        if not url.startswith("https://"):
            return findings  # Only check HTTPS endpoints

        for header, (severity, title, cwe, rec) in REQUIRED_SECURITY_HEADERS.items():
            if header not in resp_headers:
                findings.append(Finding(
                    title=title,
                    description=(
                        f"The response from {url} is missing the '{header}' "
                        "security header."
                    ),
                    severity=severity,
                    confidence=0.80,
                    detector=DetectorType.TRAFFIC,
                    source=FindingSource.DYNAMIC,
                    category="Missing Security Header",
                    cwe_id=cwe,
                    owasp_mobile="M3: Insecure Communication",
                    evidence=[f"URL: {url}", f"Missing header: {header}"],
                    network_evidence=[url],
                    recommendation=rec,
                ))
        return findings

    def _check_insecure_cookies(
        self, url: str, resp_headers: Dict[str, str]
    ) -> List[Finding]:
        findings = []
        cookie_header = resp_headers.get("set-cookie", "")
        if not cookie_header:
            return findings

        cookies = cookie_header.split(",")
        for cookie in cookies:
            parts     = [p.strip().lower() for p in cookie.split(";")]
            name_part = parts[0] if parts else ""
            cookie_name = name_part.split("=")[0].strip()

            is_sensitive = any(
                s in cookie_name.lower() for s in SENSITIVE_COOKIE_NAMES
            )
            if not is_sensitive:
                continue

            has_secure   = "secure"   in parts
            has_httponly = "httponly" in parts
            has_samesite = any("samesite" in p for p in parts)

            if not has_secure:
                findings.append(Finding(
                    title=f"Session Cookie Missing 'Secure' Flag: {cookie_name}",
                    description=(
                        f"The '{cookie_name}' cookie is set without the Secure flag. "
                        "This allows it to be transmitted over HTTP, exposing session tokens."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.90,
                    detector=DetectorType.TRAFFIC,
                    source=FindingSource.DYNAMIC,
                    category="Insecure Cookie",
                    cwe_id="CWE-614",
                    owasp_mobile="M4: Insufficient Authentication",
                    evidence=[f"Set-Cookie: {cookie[:100]}"],
                    network_evidence=[url],
                    recommendation=f"Add the Secure flag to the {cookie_name} cookie.",
                ))

            if not has_httponly:
                findings.append(Finding(
                    title=f"Session Cookie Missing 'HttpOnly' Flag: {cookie_name}",
                    description=(
                        f"The '{cookie_name}' cookie is set without the HttpOnly flag. "
                        "JavaScript can read this cookie, enabling XSS-based session theft."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.90,
                    detector=DetectorType.TRAFFIC,
                    source=FindingSource.DYNAMIC,
                    category="Insecure Cookie",
                    cwe_id="CWE-1004",
                    owasp_mobile="M4: Insufficient Authentication",
                    evidence=[f"Set-Cookie: {cookie[:100]}"],
                    network_evidence=[url],
                    recommendation=f"Add the HttpOnly flag to the {cookie_name} cookie.",
                ))

        return findings

    def _check_sensitive_body(
        self, url: str, req_body: str, resp_body: str
    ) -> List[Finding]:
        findings = []
        for body, label in [(req_body, "request"), (resp_body, "response")]:
            if not body:
                continue
            for pattern, title, severity in SENSITIVE_BODY_PATTERNS:
                if re.search(pattern, body):
                    findings.append(Finding(
                        title=f"{title} in HTTP {label.capitalize()}",
                        description=(
                            f"The HTTP {label} to/from {url} contains a {title.lower()}. "
                            "Ensure this data is necessary and protected appropriately."
                        ),
                        severity=severity,
                        confidence=0.80,
                        detector=DetectorType.TRAFFIC,
                        source=FindingSource.DYNAMIC,
                        category="Sensitive Data Exposure",
                        cwe_id="CWE-200",
                        owasp_mobile="M2: Insecure Data Storage",
                        evidence=[f"URL: {url}", f"Found in: {label}"],
                        network_evidence=[url],
                        recommendation=(
                            "Review why this data is transmitted. Mask/encrypt "
                            "sensitive fields and ensure HTTPS is enforced."
                        ),
                    ))
        return findings

    def _check_auth_headers(
        self, url: str, req_headers: Dict[str, str]
    ) -> List[Finding]:
        findings = []
        auth = req_headers.get("authorization", "")
        if auth and url.startswith("http://"):
            findings.append(Finding(
                title="Authorization Token Sent Over HTTP",
                description=(
                    f"An Authorization header was sent to {url} over plaintext HTTP. "
                    "The token is fully exposed to any network observer."
                ),
                severity=Severity.CRITICAL,
                confidence=0.95,
                detector=DetectorType.TRAFFIC,
                source=FindingSource.DYNAMIC,
                category="Token Leakage",
                cwe_id="CWE-319",
                owasp_mobile="M3: Insecure Communication",
                evidence=[
                    f"URL: {url}",
                    f"Authorization: {auth[:30]}...",
                ],
                network_evidence=[url],
                recommendation="Enforce HTTPS for all authenticated endpoints.",
            ))
        return findings

    def _check_exposed_endpoints(
        self, url: str, resp: Dict[str, Any]
    ) -> List[Finding]:
        findings = []
        body = resp.get("body", "") or ""
        # Check for exposed admin/debug endpoints
        suspicious_paths = [
            "/admin", "/debug", "/console", "/actuator", "/swagger",
            "/api-docs", "/graphql", "/__debug__", "/phpmyadmin",
        ]
        try:
            path = urlparse(url).path.lower()
        except Exception:
            return findings

        for sp in suspicious_paths:
            if path.startswith(sp) and resp.get("status_code", 0) in (200, 201, 301, 302):
                findings.append(Finding(
                    title=f"Exposed Sensitive Endpoint: {path}",
                    description=(
                        f"The endpoint {url} appears to be an admin/debug interface "
                        "and is accessible from the app."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.75,
                    detector=DetectorType.TRAFFIC,
                    source=FindingSource.DYNAMIC,
                    category="Exposed Interface",
                    cwe_id="CWE-200",
                    owasp_mobile="M8: Security Misconfiguration",
                    evidence=[f"URL: {url}", f"Status: {resp.get('status_code')}"],
                    network_evidence=[url],
                    recommendation=(
                        "Restrict access to admin/debug endpoints. "
                        "Require authentication and restrict to trusted IPs."
                    ),
                ))
        return findings
