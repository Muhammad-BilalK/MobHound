"""
MobHound Scanner - Auth Detector
===================================
Detects authentication and session management weaknesses in code and traffic.

Checks:
  - JWT none algorithm / no verification
  - Hardcoded credentials used in auth
  - Broken biometric auth implementation
  - Insecure token storage
  - Missing token expiry checks
  - OAuth implicit flow misuse
  - Cleartext credential transmission
  - Weak session management
  - PIN/password strength bypass
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scanner.models import DetectorType, Finding, FindingSource, Severity

AUTH_CODE_PATTERNS: List[Tuple[str, str, Severity, float, str, str, str]] = [

    # JWT none algorithm
    (
        "JWT 'none' Algorithm Accepted",
        r'(?i)(?:alg|algorithm)\s*[=:]\s*["\']none["\']',
        Severity.CRITICAL, 0.93, "CWE-347",
        "M4: Insufficient Authentication",
        "Never accept JWT with 'none' algorithm. Always verify the signature with a strong key.",
    ),

    # JWT not verified
    (
        "JWT Decoded Without Verification",
        r'(?i)(?:decode|parse)(?:JWT|Token|jwt)\s*\([^)]*(?:false|null|skip|no.?verify)',
        Severity.CRITICAL, 0.88, "CWE-347",
        "M4: Insufficient Authentication",
        "Always verify the JWT signature. Never set verify=false in production.",
    ),

    # Hardcoded credentials in auth flow
    (
        "Hardcoded Credential in Auth Check",
        r'(?i)(?:password|passwd|pin|secret)\s*[=:=]{1,3}\s*["\'][^"\']{4,}["\']',
        Severity.CRITICAL, 0.85, "CWE-259",
        "M4: Insufficient Authentication",
        "Remove hardcoded credentials. Use secure server-side authentication.",
    ),

    # Biometric auth — always authenticate
    (
        "Biometric Auth Always Returns True",
        r'(?i)onAuthenticationSucceeded|BiometricPrompt.*?(?:always|true)',
        Severity.HIGH, 0.72, "CWE-287",
        "M4: Insufficient Authentication",
        "Use CryptoObject with BiometricPrompt to tie biometric auth to a crypto operation. "
        "Do not rely on onAuthenticationSucceeded alone.",
    ),

    # Crypto key not bound to auth
    (
        "Keystore Key Not Requiring User Authentication",
        r'setUserAuthenticationRequired\s*\(\s*false\s*\)',
        Severity.HIGH, 0.88, "CWE-522",
        "M4: Insufficient Authentication",
        "Set setUserAuthenticationRequired(true) for keys that protect sensitive data.",
    ),

    # Insecure remember me
    (
        "Credentials Persisted in SharedPreferences",
        r'(?i)(?:putString|edit\(\)\.put)\s*\([^,]*(?:password|token|pass|pwd|secret)[^,]*,',
        Severity.HIGH, 0.82, "CWE-312",
        "M2: Insecure Data Storage",
        "Never store passwords in SharedPreferences. Use Android Keystore with EncryptedSharedPreferences.",
    ),

    # No token expiry check
    (
        "Token Stored Without Expiry Tracking",
        r'(?i)(?:access_token|auth_token|bearer)\s*=\s*(?:response|data|json)',
        Severity.MEDIUM, 0.70, "CWE-613",
        "M4: Insufficient Authentication",
        "Implement token expiry tracking and automatic refresh logic.",
    ),

    # OAuth implicit flow
    (
        "OAuth Implicit Flow (token in URL fragment)",
        r'(?i)response_type\s*=\s*["\']?token["\']?',
        Severity.HIGH, 0.80, "CWE-601",
        "M4: Insufficient Authentication",
        "Use OAuth Authorization Code flow with PKCE instead of implicit flow. "
        "Tokens in URL fragments can be leaked via referrer headers.",
    ),

    # Weak PIN validation
    (
        "Weak PIN Validation (short PIN allowed)",
        r'(?i)(?:pin|passcode)\.length\s*(?:>=|>|==)\s*[1-3](?!\d)',
        Severity.MEDIUM, 0.78, "CWE-521",
        "M4: Insufficient Authentication",
        "Enforce a minimum PIN length of 6 digits with complexity requirements.",
    ),

    # SSL with no hostname verification
    (
        "HostnameVerifier Always Returns True",
        r'(?i)verify\s*\(\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)\s*\{[^}]*return\s+true',
        Severity.CRITICAL, 0.95, "CWE-297",
        "M3: Insecure Communication",
        "Never return true unconditionally in HostnameVerifier.verify(). "
        "This disables hostname verification entirely.",
    ),

    # Trust all certs
    (
        "TrustManager Accepts All Certificates",
        r'(?i)checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}',
        Severity.CRITICAL, 0.93, "CWE-295",
        "M3: Insecure Communication",
        "Implement proper certificate validation in checkServerTrusted(). "
        "An empty method accepts all certificates including malicious ones.",
    ),

    # Weak hash for passwords
    (
        "MD5/SHA1 Used for Password Hashing",
        r'(?i)MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-?1)["\']',
        Severity.HIGH, 0.90, "CWE-916",
        "M5: Insufficient Cryptography",
        "Use bcrypt, Argon2, or PBKDF2 with at least 100,000 iterations for password hashing.",
    ),
]

# Traffic-based auth checks
AUTH_TRAFFIC_CHECKS = [
    ("Basic Auth over HTTP", r'(?i)^Basic ', Severity.CRITICAL,
     "Basic credentials transmitted over HTTP are base64-encoded (not encrypted)."),
    ("Bearer Token over HTTP", r'(?i)^Bearer ', Severity.CRITICAL,
     "Bearer tokens transmitted over HTTP can be stolen by network observers."),
]


class AuthDetector:
    """Detect authentication weaknesses in code and HTTP traffic."""

    def __init__(self, scan_root: Optional[Path] = None,
                 traffic_flows: Optional[List[Dict[str, Any]]] = None):
        self._root   = scan_root
        self._flows  = traffic_flows or []

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        if self._root and self._root.exists():
            for ext in ("*.java", "*.kt"):
                for path in self._root.rglob(ext):
                    findings += self._scan_code(path)

        findings += self._scan_traffic()
        return findings

    def _scan_code(self, path: Path) -> List[Finding]:
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except OSError:
            return []

        findings = []
        for label, pattern, severity, confidence, cwe, owasp, rec in AUTH_CODE_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE | re.DOTALL | re.IGNORECASE)
            except re.error:
                continue
            for match in compiled.finditer(text):
                ln  = text[:match.start()].count("\n") + 1
                ctx = lines[ln - 1].strip() if ln <= len(lines) else ""
                findings.append(Finding(
                    title=label,
                    description=f"Detected '{label}' in '{path.name}'.",
                    severity=severity,
                    confidence=confidence,
                    detector=DetectorType.AUTH,
                    source=FindingSource.STATIC,
                    category="Weak Authentication",
                    cwe_id=cwe,
                    owasp_mobile=owasp,
                    evidence=[f"File: {path}:{ln}", f"Code: {ctx[:120]}"],
                    affected_files=[str(path)],
                    line_numbers=[ln],
                    recommendation=rec,
                ))
        return findings

    def _scan_traffic(self) -> List[Finding]:
        findings = []
        for flow in self._flows:
            req     = flow.get("request", {}) or {}
            url     = req.get("url", "")
            headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
            auth    = headers.get("authorization", "")

            if not auth or not url.startswith("http://"):
                continue

            for label, pattern, severity, msg in AUTH_TRAFFIC_CHECKS:
                if re.match(pattern, auth):
                    findings.append(Finding(
                        title=label,
                        description=f"{msg} URL: {url}",
                        severity=severity,
                        confidence=0.97,
                        detector=DetectorType.AUTH,
                        source=FindingSource.DYNAMIC,
                        category="Credential Exposure",
                        cwe_id="CWE-319",
                        owasp_mobile="M3: Insecure Communication",
                        evidence=[f"URL: {url}", f"Authorization: {auth[:40]}..."],
                        network_evidence=[url],
                        recommendation="Enforce HTTPS for all authenticated endpoints.",
                    ))
        return findings
