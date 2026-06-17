"""
MobHound Scanner - Storage Detector
======================================
Detects insecure data storage patterns.

Checks:
  - SharedPreferences with sensitive data
  - Unencrypted SQLite databases
  - External storage misuse
  - Insecure file permissions
  - Hardcoded file paths with sensitive data
  - Caching sensitive HTTP responses
  - Insecure clipboard usage
  - Screenshot prevention missing
  - Unencrypted Realm/Room databases
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from scanner.models import DetectorType, Finding, FindingSource, Severity

STORAGE_PATTERNS: List[Tuple[str, str, Severity, float, str, str, str]] = [

    # SharedPreferences sensitive data
    (
        "Sensitive Data in SharedPreferences (Unencrypted)",
        r'(?i)\.putString\s*\(\s*["\'][^"\']*(?:password|token|secret|key|auth|pin|credential)[^"\']*["\']',
        Severity.HIGH, 0.88, "CWE-312",
        "M2: Insecure Data Storage",
        "Use EncryptedSharedPreferences (Jetpack Security) for sensitive data.",
    ),

    # SQLite raw insert with sensitive columns
    (
        "Sensitive Data Inserted into SQLite",
        r'(?i)(?:insert|execSQL)\s*\([^)]*(?:password|token|secret|credit_card|ssn)',
        Severity.HIGH, 0.82, "CWE-312",
        "M2: Insecure Data Storage",
        "Encrypt sensitive columns using SQLCipher or Android Keystore before storing.",
    ),

    # SQL injection in query
    (
        "SQL Injection via String Concatenation",
        r'(?i)(?:rawQuery|execSQL)\s*\(\s*["\'][^"\']*\+|\+\s*\w+\s*\+',
        Severity.HIGH, 0.85, "CWE-89",
        "M7: Client Code Quality",
        "Use parameterized queries with selectionArgs[] to prevent SQL injection.",
    ),

    # External storage with sensitive data
    (
        "Sensitive File Written to External Storage",
        r'(?i)(?:getExternalFilesDir|getExternalStorageDirectory|getExternalCacheDir)[^;]*(?:write|output|save|store)',
        Severity.HIGH, 0.80, "CWE-312",
        "M2: Insecure Data Storage",
        "Never write sensitive data to external storage. Use getFilesDir() for private internal storage.",
    ),

    # World-readable file
    (
        "World-Readable File Created",
        r'(?i)openFileOutput\s*\([^,]+,\s*(?:1|MODE_WORLD_READABLE)',
        Severity.HIGH, 0.92, "CWE-732",
        "M2: Insecure Data Storage",
        "Use MODE_PRIVATE (0) for all file operations.",
    ),

    # Clipboard with sensitive data
    (
        "Sensitive Data Copied to Clipboard",
        r'(?i)(?:ClipboardManager|setPrimaryClip)\s*.*(?:password|token|key|secret|card)',
        Severity.MEDIUM, 0.78, "CWE-312",
        "M2: Insecure Data Storage",
        "Avoid copying sensitive data to clipboard. If unavoidable, clear it after use.",
    ),

    # Screenshot not prevented on sensitive screens
    (
        "FLAG_SECURE Not Set (Screenshots Allowed)",
        r'(?i)class\s+\w*(?:Login|Password|Payment|Auth|Pin|Wallet)\w*\s*extends\s*(?:Activity|Fragment)',
        Severity.MEDIUM, 0.70, "CWE-200",
        "M2: Insecure Data Storage",
        "Add getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, ...) "
        "on all screens containing sensitive data.",
    ),

    # HTTP response caching
    (
        "Sensitive HTTP Response May Be Cached",
        r'(?i)(?:Cache-Control|cache\.put|HttpResponseCache)',
        Severity.MEDIUM, 0.68, "CWE-524",
        "M2: Insecure Data Storage",
        "Set 'Cache-Control: no-store' for responses containing sensitive data.",
    ),

    # Realm without encryption
    (
        "Realm Database Without Encryption",
        r'(?i)RealmConfiguration\.Builder\s*\(\s*\)(?!.*encryptionKey)',
        Severity.HIGH, 0.80, "CWE-312",
        "M2: Insecure Data Storage",
        "Use RealmConfiguration.Builder().encryptionKey(key) with an Android Keystore-managed key.",
    ),

    # Room without encryption
    (
        "Room Database Without Encryption",
        r'@Database\s*\(',
        Severity.MEDIUM, 0.65, "CWE-312",
        "M2: Insecure Data Storage",
        "Consider using SQLCipher for Room or encrypt sensitive columns individually.",
    ),

    # Logging sensitive data
    (
        "Sensitive Data Written to Log",
        r'(?i)Log\.[dievw]\s*\([^,]+,\s*[^)]*(?:password|token|key|secret|auth|card|ssn)',
        Severity.HIGH, 0.88, "CWE-532",
        "M2: Insecure Data Storage",
        "Remove all logging of sensitive data. Add ProGuard rules to strip Log calls in release.",
    ),

    # printStackTrace
    (
        "Stack Trace Exposure",
        r'\.printStackTrace\s*\(\s*\)',
        Severity.LOW, 0.75, "CWE-209",
        "M2: Insecure Data Storage",
        "Replace printStackTrace() with a logging framework that can be disabled in production.",
    ),

    # Hardcoded file path
    (
        "Hardcoded Internal File Path",
        r'(?i)["\'](?:/data/data/|/sdcard/|/storage/emulated/0/)[^"\']+["\']',
        Severity.MEDIUM, 0.78, "CWE-426",
        "M2: Insecure Data Storage",
        "Use context.getFilesDir() or Environment APIs instead of hardcoded paths.",
    ),
]


class StorageDetector:
    """Detect insecure data storage patterns in decompiled code."""

    def __init__(self, scan_root: Optional[Path] = None):
        self._root = scan_root

    def run(self) -> List[Finding]:
        if not self._root or not self._root.exists():
            return []

        findings: List[Finding] = []
        for ext in ("*.java", "*.kt", "*.smali"):
            for path in self._root.rglob(ext):
                findings += self._scan(path)
        return self._deduplicate(findings)

    def _scan(self, path: Path) -> List[Finding]:
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except OSError:
            return []

        findings = []
        for label, pattern, severity, confidence, cwe, owasp, rec in STORAGE_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            except re.error:
                continue
            for match in compiled.finditer(text):
                ln  = text[:match.start()].count("\n") + 1
                ctx = lines[ln - 1].strip() if ln <= len(lines) else ""
                findings.append(Finding(
                    title=label,
                    description=f"Insecure storage pattern found in '{path.name}'.",
                    severity=severity,
                    confidence=confidence,
                    detector=DetectorType.STORAGE,
                    source=FindingSource.STATIC,
                    category="Insecure Data Storage",
                    cwe_id=cwe,
                    owasp_mobile=owasp,
                    evidence=[f"File: {path}:{ln}", f"Code: {ctx[:120]}"],
                    affected_files=[str(path)],
                    line_numbers=[ln],
                    recommendation=rec,
                ))
        return findings

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        seen, unique = set(), []
        for f in findings:
            key = (f.title, tuple(f.affected_files), tuple(f.line_numbers))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
