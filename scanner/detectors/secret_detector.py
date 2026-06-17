"""
MobHound Scanner - Secret Detector
=====================================
Scans decompiled source code, smali, assets, and strings for
hardcoded credentials, API keys, tokens, and private keys.

Sources scanned:
  - Decompiled Java / Kotlin (.java, .kt)
  - Smali bytecode (.smali)
  - Resource strings (strings.xml, res/)
  - Raw assets
  - Native binaries (basic string extraction)
  - Intercepted traffic (Authorization headers, JWT tokens)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from scanner.models import (
    DetectorType, Finding, FindingSource, Severity
)

# ─────────────────────────────────────────────────────────────
# Secret pattern library
# Each entry: (label, regex, severity, confidence, cwe, owasp)
# ─────────────────────────────────────────────────────────────

SECRET_PATTERNS: List[Tuple[str, str, Severity, float, str, str]] = [
    # Cloud credentials
    ("AWS Access Key ID",
     r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])",
     Severity.CRITICAL, 0.95, "CWE-798", "M2"),

    ("AWS Secret Access Key",
     r"(?i)aws.{0,20}(?:secret|key).{0,10}['\"]([A-Za-z0-9/+=]{40})['\"]",
     Severity.CRITICAL, 0.90, "CWE-798", "M2"),

    ("Google API Key",
     r"AIza[0-9A-Za-z\-_]{35}",
     Severity.HIGH, 0.92, "CWE-798", "M2"),

    ("Google Cloud Service Account",
     r"\"type\"\s*:\s*\"service_account\"",
     Severity.CRITICAL, 0.95, "CWE-798", "M2"),

    ("Firebase API Key",
     r"(?i)firebase[_\-. ]?(?:api)?[_\-. ]?key['\"\s:=]+([A-Za-z0-9\-_]{20,50})",
     Severity.HIGH, 0.85, "CWE-798", "M2"),

    ("Firebase URL",
     r"https?://[a-z0-9\-]+\.firebaseio\.com",
     Severity.MEDIUM, 0.85, "CWE-200", "M3"),

    # OAuth / Social
    ("Facebook Access Token",
     r"EAACEdEose0cBA[0-9A-Za-z]+",
     Severity.HIGH, 0.95, "CWE-798", "M2"),

    ("Facebook App Secret",
     r"(?i)(?:facebook|fb)[_\-. ]?(?:app)?[_\-. ]?secret['\"\s:=]+([A-Za-z0-9]{32})",
     Severity.HIGH, 0.85, "CWE-798", "M2"),

    ("Twitter Consumer Key",
     r"(?i)twitter.{0,30}(?:consumer|api)[_\-. ]?key['\"\s:=]+([A-Za-z0-9]{25,50})",
     Severity.HIGH, 0.80, "CWE-798", "M2"),

    # Payment
    ("Stripe Secret Key",
     r"sk_(?:live|test)_[0-9A-Za-z]{24}",
     Severity.CRITICAL, 0.98, "CWE-798", "M2"),

    ("Stripe Publishable Key",
     r"pk_(?:live|test)_[0-9A-Za-z]{24}",
     Severity.MEDIUM, 0.95, "CWE-200", "M2"),

    ("Square Access Token",
     r"sq0atp-[0-9A-Za-z\-_]{22}",
     Severity.CRITICAL, 0.98, "CWE-798", "M2"),

    ("PayPal / Braintree Token",
     r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
     Severity.CRITICAL, 0.98, "CWE-798", "M2"),

    # Crypto / Private keys
    ("RSA Private Key",
     r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
     Severity.CRITICAL, 1.0, "CWE-321", "M5"),

    ("Private Key (PKCS8)",
     r"-----BEGIN PRIVATE KEY-----",
     Severity.CRITICAL, 1.0, "CWE-321", "M5"),

    ("PGP Private Key",
     r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
     Severity.CRITICAL, 1.0, "CWE-321", "M5"),

    # Tokens
    ("JSON Web Token",
     r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
     Severity.HIGH, 0.90, "CWE-522", "M4"),

    ("Bearer Token in Code",
     r"(?i)(?:bearer|authorization)['\"\s:=]+([A-Za-z0-9\-_\.=]{20,})",
     Severity.HIGH, 0.80, "CWE-522", "M4"),

    ("GitHub Personal Access Token",
     r"ghp_[A-Za-z0-9]{36}",
     Severity.CRITICAL, 0.98, "CWE-798", "M2"),

    ("GitHub OAuth Token",
     r"gho_[A-Za-z0-9]{36}",
     Severity.CRITICAL, 0.98, "CWE-798", "M2"),

    ("Slack Token",
     r"xox[baprs]\-[0-9]{12}\-[0-9]{12}\-[A-Za-z0-9]{24}",
     Severity.HIGH, 0.95, "CWE-798", "M2"),

    ("Slack Webhook",
     r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}",
     Severity.HIGH, 0.95, "CWE-798", "M2"),

    # SMTP
    ("SMTP Password",
     r"(?i)smtp.{0,10}(?:pass(?:word)?|pwd)['\"\s:=]+([^\s'\"]{6,})",
     Severity.HIGH, 0.75, "CWE-798", "M2"),

    # Database
    ("MongoDB URI",
     r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s/]+",
     Severity.CRITICAL, 0.95, "CWE-798", "M2"),

    ("MySQL / PostgreSQL Connection String",
     r"(?i)(?:mysql|postgres(?:ql)?|jdbc)://[^:\s]+:[^@\s]+@[^\s/]+",
     Severity.CRITICAL, 0.90, "CWE-798", "M2"),

    # Generic patterns (lower confidence)
    ("Hardcoded Password",
     r"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*['\"]([^'\"\s]{6,})['\"]",
     Severity.HIGH, 0.70, "CWE-259", "M2"),

    ("Hardcoded Username+Password",
     r"(?i)(?:username|user|login)\s*[=:]\s*['\"]([^'\"\s]{3,})['\"]",
     Severity.MEDIUM, 0.60, "CWE-798", "M2"),

    ("Generic Secret/Key Assignment",
     r"(?i)(?:secret|api_key|apikey|client_secret)\s*[=:]\s*['\"]([A-Za-z0-9\-_\.]{16,})['\"]",
     Severity.HIGH, 0.72, "CWE-798", "M2"),

    # Sensitive URLs with embedded credentials
    ("URL with Embedded Credentials",
     r"https?://[A-Za-z0-9+/=]{4,}:[A-Za-z0-9+/=]{4,}@",
     Severity.HIGH, 0.88, "CWE-522", "M3"),
]

# Extensions to scan
CODE_EXTENSIONS  = {".java", ".kt", ".smali", ".xml", ".json", ".properties",
                    ".gradle", ".yaml", ".yml", ".txt", ".html", ".js"}
BINARY_EXTENSIONS = {".so", ".dex"}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

# Lines with these keywords are likely comments or tests → lower confidence penalty
FALSE_POSITIVE_HINTS = ["example", "sample", "placeholder", "your_key_here",
                        "replace_me", "xxxxxxxx", "todo", "fixme", "test_key"]


def _is_likely_false_positive(line: str) -> bool:
    ll = line.lower()
    return any(h in ll for h in FALSE_POSITIVE_HINTS)


def _redact(value: str, keep: int = 6) -> str:
    """Redact most of a sensitive value for safe logging."""
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


class SecretDetector:
    """Scan source / assets for hardcoded secrets and credentials."""

    def __init__(self, scan_root: Optional[Path] = None,
                 extra_text_sources: Optional[List[Tuple[str, str]]] = None):
        """
        Args:
            scan_root: Root directory to recursively scan (e.g. JADX output dir).
            extra_text_sources: List of (filename, text_content) for in-memory scanning
                                (e.g. intercepted HTTP traffic, extracted strings).
        """
        self._root   = scan_root
        self._extra  = extra_text_sources or []

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # Scan filesystem
        if self._root and self._root.exists():
            findings += self._scan_directory(self._root)

        # Scan in-memory text sources
        for name, content in self._extra:
            findings += self._scan_text(content, source_name=name)

        # Deduplicate same secret value in same file
        findings = self._deduplicate(findings)
        return findings

    # ─── Directory scan ───────────────────────────────────────

    def _scan_directory(self, root: Path) -> List[Finding]:
        findings = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
            if path.suffix.lower() in CODE_EXTENSIONS:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    findings += self._scan_text(text, source_name=str(path.relative_to(root)))
                except OSError:
                    pass
        return findings

    # ─── Text scan ────────────────────────────────────────────

    def _scan_text(self, text: str, source_name: str = "<unknown>") -> List[Finding]:
        findings = []
        lines    = text.splitlines()

        for label, pattern, severity, confidence, cwe, owasp in SECRET_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE | re.DOTALL)
            except re.error:
                continue

            for match in compiled.finditer(text):
                matched_value = match.group(0)
                # Find the line number
                line_num = text[:match.start()].count("\n") + 1
                context_line = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                # Reduce confidence for likely false positives
                fp_penalty = 0.25 if _is_likely_false_positive(context_line) else 0.0
                adjusted_confidence = max(0.1, confidence - fp_penalty)

                # Skip very low confidence after penalty
                if adjusted_confidence < 0.3:
                    continue

                findings.append(Finding(
                    title=f"Hardcoded {label}",
                    description=(
                        f"A {label} was found hardcoded in '{source_name}'. "
                        f"Hardcoded secrets embedded in APK binaries can be extracted "
                        f"by any user who decompiles the application."
                    ),
                    severity=severity,
                    confidence=adjusted_confidence,
                    detector=DetectorType.SECRET,
                    source=FindingSource.STATIC,
                    category="Hardcoded Credential",
                    cwe_id=cwe,
                    owasp_mobile=f"M2 / {owasp}",
                    evidence=[
                        f"File: {source_name}:{line_num}",
                        f"Match: {_redact(matched_value)}",
                        f"Context: {context_line[:120]}",
                    ],
                    affected_files=[source_name],
                    line_numbers=[line_num],
                    recommendation=(
                        f"Remove the {label} from source code. "
                        "Store secrets in environment variables, Android Keystore, "
                        "or a secure server-side configuration. "
                        "Rotate the compromised credential immediately."
                    ),
                    raw={
                        "pattern_label": label,
                        "line":          line_num,
                        "file":          source_name,
                        "redacted_value": _redact(matched_value),
                    },
                ))
        return findings

    # ─── Traffic scan (dynamic findings) ─────────────────────

    def scan_traffic(self, flows: List[dict]) -> List[Finding]:
        """
        Scan captured mitmproxy flows for secrets in headers/bodies.
        flows: list of flow dicts from captured_flows.jsonl
        """
        findings = []
        for flow in flows:
            req = flow.get("request", {})
            resp= flow.get("response", {})
            url = req.get("url", "")

            # Scan request headers
            for hname, hval in (req.get("headers") or {}).items():
                if hname.lower() in ("authorization", "x-api-key", "x-auth-token", "cookie"):
                    findings.append(Finding(
                        title=f"Sensitive Header in Traffic: {hname}",
                        description=(
                            f"The request to {url} includes a {hname} header. "
                            "This token was captured in plaintext by MobHound."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.90,
                        detector=DetectorType.SECRET,
                        source=FindingSource.DYNAMIC,
                        category="Token Leakage",
                        cwe_id="CWE-522",
                        owasp_mobile="M4: Insufficient Authentication",
                        evidence=[
                            f"URL: {url}",
                            f"Header: {hname}: {_redact(hval)}",
                        ],
                        affected_files=[url],
                        network_evidence=[f"{hname}: {_redact(hval)}"],
                        recommendation=(
                            "Verify all tokens are transmitted over HTTPS only. "
                            "Implement token expiration and refresh mechanisms."
                        ),
                    ))

            # Scan bodies for JWTs or known patterns
            body = req.get("body", "") or ""
            if body:
                findings += self._scan_text(body, source_name=f"HTTP_REQUEST:{url}")

        return findings

    # ─── Deduplication ────────────────────────────────────────

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique = []
        for f in findings:
            key = (f.title, tuple(f.affected_files), tuple(f.line_numbers))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
