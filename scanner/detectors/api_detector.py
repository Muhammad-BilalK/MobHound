"""
MobHound Scanner - API Detector
==================================
Scans decompiled code for:
  - Insecure exported component usage
  - Deep link parameter injection
  - Implicit Intent misuse
  - IPC abuse patterns
  - Dynamic broadcast receivers
  - Pending Intent misuse
  - Content Provider path traversal
  - JavaScript interface abuse
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from scanner.models import DetectorType, Finding, FindingSource, Severity

# ─────────────────────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────────────────────

API_PATTERNS: List[Tuple[str, str, Severity, float, str, str, str]] = [

    # Content Provider path traversal
    (
        "Content Provider Path Traversal",
        r'(?i)getContentResolver\(\)\.query\s*\([^)]*\+',
        Severity.HIGH, 0.82, "CWE-22",
        "M1: Improper Platform Usage",
        "Validate and sanitize all URI parameters in ContentProvider queries to prevent path traversal.",
    ),
    (
        "Content Provider openFile without Validation",
        r'(?i)openFile\s*\(Uri\s+uri[^)]*\)',
        Severity.HIGH, 0.78, "CWE-22",
        "M1: Improper Platform Usage",
        "Validate the URI path in openFile() to prevent directory traversal attacks.",
    ),

    # Dynamic receiver
    (
        "Dynamic BroadcastReceiver without Permission",
        r'registerReceiver\s*\(\s*\w+\s*,\s*new\s+IntentFilter',
        Severity.MEDIUM, 0.80, "CWE-925",
        "M1: Improper Platform Usage",
        "Pass a custom permission string to registerReceiver() to restrict who can send broadcasts.",
    ),

    # Implicit intents for sensitive actions
    (
        "Implicit Intent for Sensitive Data",
        r'new\s+Intent\s*\(\s*["\'][^"\']*(?:SEND|SHARE|VIEW|PICK)[^"\']*["\']',
        Severity.MEDIUM, 0.70, "CWE-926",
        "M1: Improper Platform Usage",
        "Use explicit intents with a specific component name for sensitive operations.",
    ),

    # PendingIntent FLAG_MUTABLE
    (
        "Mutable PendingIntent",
        r'PendingIntent\.get\w+\s*\([^)]*FLAG_MUTABLE',
        Severity.MEDIUM, 0.82, "CWE-926",
        "M1: Improper Platform Usage",
        "Use FLAG_IMMUTABLE for PendingIntents unless mutability is strictly required (API 31+).",
    ),

    # startActivity with unvalidated Intent data
    (
        "startActivity with External Intent Data",
        r'startActivity\s*\(\s*getIntent\s*\(\s*\)',
        Severity.HIGH, 0.75, "CWE-926",
        "M1: Improper Platform Usage",
        "Validate getIntent() data before passing to startActivity to prevent Intent redirection.",
    ),

    # Deep link parameter directly used
    (
        "Deep Link URI Data Used Without Validation",
        r'getIntent\s*\(\s*\)\.getData\s*\(\s*\)',
        Severity.HIGH, 0.78, "CWE-601",
        "M1: Improper Platform Usage",
        "Validate and sanitize all deep link URI parameters before use. Never pass them to WebView directly.",
    ),

    # JavaScript addJavascriptInterface
    (
        "addJavascriptInterface Exposed",
        r'addJavascriptInterface\s*\(\s*\w+\s*,\s*["\'][^"\']+["\']',
        Severity.CRITICAL, 0.92, "CWE-749",
        "M1: Improper Platform Usage",
        "Annotate all exposed methods with @JavascriptInterface. Avoid exposing sensitive objects. Target API >= 17.",
    ),

    # Fragment injection
    (
        "Fragment Injection via PreferenceActivity",
        r'PreferenceActivity',
        Severity.HIGH, 0.72, "CWE-470",
        "M1: Improper Platform Usage",
        "Override isValidFragment() in PreferenceActivity to prevent fragment injection on API < 19.",
    ),

    # Unsafe reflection
    (
        "Unsafe Reflection",
        r'(?i)Class\.forName\s*\(\s*(?:getIntent|getExtra|getString)\s*\(',
        Severity.HIGH, 0.80, "CWE-470",
        "M1: Improper Platform Usage",
        "Never use user-controlled input as class name in Class.forName(). This can lead to RCE.",
    ),

    # Object deserialization
    (
        "Insecure Object Deserialization",
        r'(?i)ObjectInputStream|readObject\s*\(\s*\)|Parcel\.obtain',
        Severity.HIGH, 0.78, "CWE-502",
        "M8: Security Misconfiguration",
        "Avoid Java serialization. Use Parcelable with explicit type checking or JSON/Protobuf instead.",
    ),

    # Dynamic code loading
    (
        "Dynamic DEX/Class Loading",
        r'(?i)DexClassLoader|PathClassLoader|InMemoryDexClassLoader',
        Severity.HIGH, 0.88, "CWE-829",
        "M9: Insecure Data Storage",
        "Dynamic code loading can be abused to load malicious code. Verify sources and use integrity checks.",
    ),

    # Native command execution
    (
        "Native Command Execution via exec()",
        r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(',
        Severity.HIGH, 0.82, "CWE-78",
        "M7: Client Code Quality",
        "Avoid Runtime.exec(). If necessary, use explicit command arrays and validate all inputs.",
    ),

    # Sticky broadcast
    (
        "Sticky Broadcast (Deprecated + Insecure)",
        r'sendStickyBroadcast\s*\(',
        Severity.MEDIUM, 0.88, "CWE-925",
        "M1: Improper Platform Usage",
        "sendStickyBroadcast is deprecated and insecure. Use explicit broadcasts or LocalBroadcastManager.",
    ),

    # Zip Slip
    (
        "Zip Slip — Path Traversal in ZIP Extraction",
        r'ZipEntry\s*\w+\s*=.*?getNextEntry|zipEntry\.getName\s*\(\s*\)',
        Severity.HIGH, 0.78, "CWE-22",
        "M7: Client Code Quality",
        "Validate ZipEntry names to prevent path traversal. Reject entries with '../' or absolute paths.",
    ),
]


class APIDetector:
    """Detect insecure API usage patterns in decompiled Java/Kotlin code."""

    def __init__(self, scan_root: Optional[Path] = None):
        self._root = scan_root

    def run(self) -> List[Finding]:
        if not self._root or not self._root.exists():
            return []

        findings: List[Finding] = []
        for ext in ("*.java", "*.kt", "*.smali"):
            for path in self._root.rglob(ext):
                findings += self._scan(path)
        return findings

    def _scan(self, path: Path) -> List[Finding]:
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except OSError:
            return []

        findings = []
        for label, pattern, severity, confidence, cwe, owasp, rec in API_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            except re.error:
                continue
            for match in compiled.finditer(text):
                ln  = text[:match.start()].count("\n") + 1
                ctx = lines[ln - 1].strip() if ln <= len(lines) else ""
                findings.append(Finding(
                    title=label,
                    description=f"Found '{label}' in '{path.name}'. This may expose the app to exploitation.",
                    severity=severity,
                    confidence=confidence,
                    detector=DetectorType.API,
                    source=FindingSource.STATIC,
                    category="Insecure API Usage",
                    cwe_id=cwe,
                    owasp_mobile=owasp,
                    evidence=[f"File: {path}:{ln}", f"Code: {ctx[:120]}"],
                    affected_files=[str(path)],
                    line_numbers=[ln],
                    recommendation=rec,
                ))
        return findings
