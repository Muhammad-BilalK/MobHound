"""
MobHound Scanner - Permission & WebView Detector
=================================================
Scans decompiled code for:
  - WebView misconfigurations (JS, file access, addJavascriptInterface)
  - Insecure storage patterns (SharedPreferences, external storage, SQLite)
  - Dangerous permission usage in code (not just manifest)
  - Logging of sensitive data
  - Intent data exposure
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from scanner.models import (
    DetectorType, Finding, FindingSource, Severity
)

# ─────────────────────────────────────────────────────────────
# Pattern definitions
# ─────────────────────────────────────────────────────────────

WEBVIEW_PATTERNS: List[Tuple[str, str, Severity, float, str, str, str]] = [
    (
        "WebView JavaScript Enabled",
        r'\.setJavaScriptEnabled\s*\(\s*true\s*\)',
        Severity.MEDIUM, 0.90, "CWE-79",
        "M1: Improper Platform Usage",
        "Disable JavaScript unless required. If enabled, ensure no untrusted content is loaded."
    ),
    (
        "WebView File Access Enabled",
        r'\.setAllowFileAccess\s*\(\s*true\s*\)',
        Severity.HIGH, 0.92, "CWE-200",
        "M1: Improper Platform Usage",
        "Disable file access in WebView (setAllowFileAccess(false)) unless absolutely necessary."
    ),
    (
        "WebView Universal File Access",
        r'\.setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
        Severity.CRITICAL, 0.97, "CWE-200",
        "M1: Improper Platform Usage",
        "Never enable setAllowUniversalAccessFromFileURLs. This allows cross-origin file access (local file XSS)."
    ),
    (
        "WebView File URL Content Access",
        r'\.setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
        Severity.HIGH, 0.92, "CWE-200",
        "M1: Improper Platform Usage",
        "Disable setAllowFileAccessFromFileURLs to prevent cross-origin file access."
    ),
    (
        "addJavascriptInterface (RCE Risk < API 17)",
        r'\.addJavascriptInterface\s*\(',
        Severity.CRITICAL, 0.90, "CWE-749",
        "M1: Improper Platform Usage",
        (
            "addJavascriptInterface before API 17 allows JavaScript RCE via Java reflection. "
            "Use @JavascriptInterface annotation on all exposed methods and target API >= 17."
        ),
    ),
    (
        "WebView loading http:// URL",
        r'(?:loadUrl|loadData|loadDataWithBaseURL)\s*\(\s*["\']http://',
        Severity.HIGH, 0.85, "CWE-319",
        "M3: Insecure Communication",
        "Load only HTTPS URLs in WebView. HTTP traffic can be intercepted."
    ),
    (
        "WebView with Cleartext HTTP (dynamic URL)",
        r'(?:webView|wv|mWebView)\.loadUrl\s*\([^)]*\+',
        Severity.MEDIUM, 0.65, "CWE-319",
        "M3: Insecure Communication",
        "Validate and sanitize any URL loaded dynamically in WebView."
    ),
]

STORAGE_PATTERNS: List[Tuple[str, str, Severity, float, str, str, str]] = [
    (
        "SharedPreferences – World Readable",
        r'getSharedPreferences\s*\([^,]+,\s*(?:1|MODE_WORLD_READABLE)',
        Severity.HIGH, 0.95, "CWE-312",
        "M2: Insecure Data Storage",
        "Use MODE_PRIVATE (0) for SharedPreferences. MODE_WORLD_READABLE was deprecated in API 17."
    ),
    (
        "SharedPreferences – World Writeable",
        r'getSharedPreferences\s*\([^,]+,\s*(?:2|MODE_WORLD_WRITEABLE)',
        Severity.HIGH, 0.95, "CWE-312",
        "M2: Insecure Data Storage",
        "Use MODE_PRIVATE (0) for SharedPreferences."
    ),
    (
        "External Storage Write",
        r'(?:Environment\.getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir)',
        Severity.MEDIUM, 0.82, "CWE-312",
        "M2: Insecure Data Storage",
        "Avoid storing sensitive data on external storage. Use getFilesDir() for private internal storage."
    ),
    (
        "SQLite Database – Raw Query (SQL Injection Risk)",
        r'\.rawQuery\s*\(\s*["\'][^"\']*\+',
        Severity.HIGH, 0.85, "CWE-89",
        "M7: Client Code Quality",
        "Use parameterized queries (selectionArgs) instead of string concatenation to prevent SQL injection."
    ),
    (
        "Sensitive Data Written to Log",
        r'Log\.[diewtv]\s*\([^,]+,\s*[^)]*(?:password|token|secret|key|auth|credential)',
        Severity.HIGH, 0.82, "CWE-532",
        "M2: Insecure Data Storage",
        "Never log sensitive data. Use ProGuard rules to strip Log calls in release builds."
    ),
    (
        "printStackTrace – Information Disclosure",
        r'\.printStackTrace\s*\(\s*\)',
        Severity.LOW, 0.75, "CWE-209",
        "M2: Insecure Data Storage",
        "Use a logging framework. Avoid printing stack traces in production builds."
    ),
    (
        "openFileOutput – World Readable",
        r'openFileOutput\s*\([^,]+,\s*(?:1|MODE_WORLD_READABLE)',
        Severity.HIGH, 0.90, "CWE-312",
        "M2: Insecure Data Storage",
        "Use MODE_PRIVATE for openFileOutput."
    ),
    (
        "SQLiteDatabase – No Encryption",
        r'SQLiteDatabase\.openOrCreateDatabase',
        Severity.MEDIUM, 0.70, "CWE-312",
        "M2: Insecure Data Storage",
        "Consider using SQLCipher for encrypted SQLite databases containing sensitive data."
    ),
]

INTENT_PATTERNS: List[Tuple[str, str, Severity, float, str, str, str]] = [
    (
        "Sensitive Data in Intent Extra",
        r'(?:putExtra|getStringExtra)\s*\([^)]*(?:password|token|secret|key|auth)',
        Severity.HIGH, 0.80, "CWE-926",
        "M1: Improper Platform Usage",
        "Do not pass sensitive data via Intent extras. Use EncryptedSharedPreferences or Keystore."
    ),
    (
        "Implicit Intent for Sensitive Action",
        r'new\s+Intent\s*\(\s*["\'][a-zA-Z.]+ACTION[^"\']*["\']',
        Severity.MEDIUM, 0.65, "CWE-926",
        "M1: Improper Platform Usage",
        "Use explicit intents with component names for sensitive actions to prevent intent hijacking."
    ),
    (
        "PendingIntent with FLAG_MUTABLE (Android 12+)",
        r'PendingIntent\.get\w+\s*\([^)]*FLAG_MUTABLE',
        Severity.MEDIUM, 0.80, "CWE-926",
        "M1: Improper Platform Usage",
        "Use FLAG_IMMUTABLE for PendingIntents unless mutability is strictly required."
    ),
]


class PermissionWebViewDetector:
    """Detect WebView misconfigurations, insecure storage, and intent issues."""

    def __init__(self, scan_root: Optional[Path] = None):
        self._root = scan_root

    def run(self) -> List[Finding]:
        if not self._root or not self._root.exists():
            return []

        findings: List[Finding] = []
        for path in self._root.rglob("*.java"):
            findings += self._scan(path)
        for path in self._root.rglob("*.kt"):
            findings += self._scan(path)

        return findings

    def _scan(self, path: Path) -> List[Finding]:
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except OSError:
            return []

        findings = []

        for group, detector_type in [
            (WEBVIEW_PATTERNS,  DetectorType.WEBVIEW),
            (STORAGE_PATTERNS,  DetectorType.STORAGE),
            (INTENT_PATTERNS,   DetectorType.API),
        ]:
            for label, pattern, severity, confidence, cwe, owasp, rec in group:
                try:
                    compiled = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
                except re.error:
                    continue

                for match in compiled.finditer(text):
                    line_num = text[:match.start()].count("\n") + 1
                    ctx      = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    findings.append(Finding(
                        title=label,
                        description=(
                            f"Found '{label}' in '{path.name}'. "
                            "This can expose the app to security vulnerabilities."
                        ),
                        severity=severity,
                        confidence=confidence,
                        detector=detector_type,
                        source=FindingSource.STATIC,
                        category=detector_type.value.capitalize(),
                        cwe_id=cwe,
                        owasp_mobile=owasp,
                        evidence=[
                            f"File: {path}:{line_num}",
                            f"Code: {ctx[:120]}",
                        ],
                        affected_files=[str(path)],
                        line_numbers=[line_num],
                        recommendation=rec,
                    ))

        return findings
