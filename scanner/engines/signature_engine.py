"""
MobHound Scanner - Signature Engine
======================================
Matches known CVE signatures, vulnerable library versions,
and well-known vulnerability patterns.

Sources:
  - Known vulnerable Android libraries
  - OWASP Mobile Top 10 signatures
  - Common Android CVEs
  - Known vulnerable SDK patterns
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scanner.models import DetectorType, Finding, FindingSource, Severity


# ─────────────────────────────────────────────────────────────
# Vulnerable library version database
# Format: (lib_name, version_pattern, CVE, severity, description, fix)
# ─────────────────────────────────────────────────────────────

VULNERABLE_LIBS: List[Dict[str, Any]] = [
    {
        "name": "OkHttp < 3.12.1",
        "patterns": [r"okhttp['\"]?\s*[:\s]+['\"]?3\.(?:[0-9]\.|1[01]\.)"],
        "cve": "CVE-2018-20200",
        "severity": Severity.HIGH,
        "description": "OkHttp versions before 3.12.1 are vulnerable to certificate pinning bypass.",
        "fix": "Upgrade OkHttp to 3.12.13+ or 4.10.0+",
    },
    {
        "name": "Log4j (if used in backend SDK)",
        "patterns": [r"log4j['\"]?\s*[:\s]+['\"]?2\.(?:[0-9]\.|1[0-6]\.)"],
        "cve": "CVE-2021-44228",
        "severity": Severity.CRITICAL,
        "description": "Log4Shell: Remote code execution via JNDI injection in log messages.",
        "fix": "Upgrade Log4j to 2.17.1+ or remove JNDI lookup functionality.",
    },
    {
        "name": "Retrofit < 2.9.0",
        "patterns": [r"retrofit['\"]?\s*[:\s]+['\"]?[12]\.[0-8]\."],
        "cve": "CVE-2020-10190",
        "severity": Severity.MEDIUM,
        "description": "Older Retrofit versions may use vulnerable OkHttp versions.",
        "fix": "Upgrade Retrofit to 2.9.0+",
    },
    {
        "name": "Conscrypt < 2.5.0",
        "patterns": [r"conscrypt['\"]?\s*[:\s]+['\"]?[01]\.|2\.[0-4]\."],
        "cve": "CVE-2021-22570",
        "severity": Severity.HIGH,
        "description": "Older Conscrypt versions have TLS vulnerabilities.",
        "fix": "Upgrade Conscrypt to 2.5.0+",
    },
    {
        "name": "BouncyCastle < 1.70",
        "patterns": [r"bcprov['\"]?\s*[:\s]+['\"]?1\.[0-6][0-9]"],
        "cve": "CVE-2020-28052",
        "severity": Severity.HIGH,
        "description": "Older BouncyCastle versions have vulnerabilities in OpenBSD Blowfish password hashing.",
        "fix": "Upgrade BouncyCastle to 1.70+",
    },
    {
        "name": "Apache Cordova < 8.0.0",
        "patterns": [r"cordova['\"]?\s*[:\s]+['\"]?[0-7]\."],
        "cve": "CVE-2018-8120",
        "severity": Severity.HIGH,
        "description": "Old Cordova versions have multiple XSS and intent injection vulnerabilities.",
        "fix": "Upgrade Apache Cordova to 8.0.0+",
    },
    {
        "name": "React Native < 0.64",
        "patterns": [r"react-native['\"]?\s*[:\s]+['\"]?0\.(?:[1-5][0-9]|6[0-3])\."],
        "cve": "CVE-2021-21382",
        "severity": Severity.MEDIUM,
        "description": "Older React Native versions have bundle loading vulnerabilities.",
        "fix": "Upgrade React Native to 0.64+",
    },
    {
        "name": "WebView with targetSdkVersion < 17",
        "patterns": [r"targetSdkVersion\s*[\"']?\s*(?:[1-9]|1[0-6])\b"],
        "cve": "CVE-2012-6636",
        "severity": Severity.CRITICAL,
        "description": "Apps targeting API < 17 are vulnerable to JavaScript interface RCE via reflection.",
        "fix": "Set targetSdkVersion >= 17 and annotate all @JavascriptInterface methods.",
    },
]

# ─────────────────────────────────────────────────────────────
# Known CVE code signatures
# ─────────────────────────────────────────────────────────────

CVE_SIGNATURES: List[Tuple[str, str, str, Severity, float, str]] = [
    # Stagefright - media file parsing
    (
        "CVE-2015-1538 (Stagefright)",
        r'(?i)android\.media\.MediaPlayer|android\.media\.MediaMetadataRetriever',
        "Stagefright vulnerabilities affected MediaPlayer in Android < 5.1.1. "
        "Verify device is patched.",
        Severity.HIGH, 0.55,
        "Ensure all devices running this app are on Android 5.1.1+ with August 2015 patches.",
    ),
    # JANUS APK Signature Bypass
    (
        "CVE-2017-13156 (JANUS APK Signature Bypass)",
        r'(?i)DEX_MAGIC|dex\n035\n',
        "App may be vulnerable to JANUS APK signing bypass if not using APK Signature Scheme v2.",
        Severity.HIGH, 0.72,
        "Use APK Signature Scheme v2 or v3. Verify signingConfig in build.gradle.",
    ),
    # Insecure Android Keystore export
    (
        "CVE-2016-2431 (Keystore Export Vulnerability)",
        r'(?i)KeyStore\.getInstance\s*\(\s*["\']AndroidKeyStore["\']',
        "Android Keystore had a vulnerability in pre-6.0 devices allowing key extraction.",
        Severity.MEDIUM, 0.60,
        "Require Android 6.0+ (API 23) as minimum SDK for apps using Android Keystore.",
    ),
    # Fragment injection via Intent
    (
        "CVE-2014-1977 (Fragment Injection)",
        r'(?i)PreferenceActivity.*isValidFragment|addPreferencesFromResource',
        "PreferenceActivity is vulnerable to fragment injection on API < 19.",
        Severity.HIGH, 0.78,
        "Override isValidFragment() to return true only for expected fragment class names.",
    ),
    # Zip path traversal
    (
        "CVE-2014-7911 (Zip Path Traversal)",
        r'(?i)new\s+ZipInputStream|ZipFile\s*\(',
        "Zip extraction without path validation is vulnerable to Zip Slip attacks.",
        Severity.HIGH, 0.72,
        "Validate all ZipEntry names before extraction. Reject entries with '../' or absolute paths.",
    ),
]


class SignatureEngine:
    """Match known CVE signatures and vulnerable library versions."""

    def __init__(self, scan_root: Optional[Path] = None,
                 gradle_files: Optional[List[Path]] = None):
        self._root   = scan_root
        self._gradle = gradle_files or []

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        findings += self._scan_vulnerable_libs()
        if self._root and self._root.exists():
            findings += self._scan_cve_signatures()
        return findings

    # ─── Vulnerable library detection ─────────────────────────

    def _scan_vulnerable_libs(self) -> List[Finding]:
        findings = []
        gradle_texts: List[Tuple[str, str]] = []

        # Search for build.gradle files
        if self._root:
            for gf in self._root.rglob("build.gradle"):
                try:
                    gradle_texts.append((str(gf), gf.read_text(encoding="utf-8", errors="replace")))
                except OSError:
                    pass
            for gf in self._root.rglob("build.gradle.kts"):
                try:
                    gradle_texts.append((str(gf), gf.read_text(encoding="utf-8", errors="replace")))
                except OSError:
                    pass

        for gf_path in self._gradle:
            try:
                gradle_texts.append((str(gf_path), gf_path.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                pass

        for lib in VULNERABLE_LIBS:
            for file_path, text in gradle_texts:
                for pat in lib["patterns"]:
                    if re.search(pat, text, re.IGNORECASE):
                        findings.append(Finding(
                            title=f"Vulnerable Library: {lib['name']}",
                            description=lib["description"],
                            severity=lib["severity"],
                            confidence=0.88,
                            detector=DetectorType.API,
                            source=FindingSource.STATIC,
                            category="Vulnerable Dependency",
                            cve_id=lib.get("cve"),
                            owasp_mobile="M8: Security Misconfiguration",
                            evidence=[f"Found in: {file_path}"],
                            affected_files=[file_path],
                            recommendation=lib["fix"],
                            tags=["known_cve", "dependency"],
                        ))

        return findings

    # ─── CVE code signature matching ──────────────────────────

    def _scan_cve_signatures(self) -> List[Finding]:
        findings = []
        for ext in ("*.java", "*.kt", "*.smali", "*.xml"):
            for path in self._root.rglob(ext):
                try:
                    text  = path.read_text(encoding="utf-8", errors="replace")
                    lines = text.splitlines()
                except OSError:
                    continue

                for cve_id, pattern, desc, severity, confidence, rec in CVE_SIGNATURES:
                    if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                        ln = 1
                        m  = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
                        if m:
                            ln = text[:m.start()].count("\n") + 1
                        ctx = lines[ln - 1].strip() if ln <= len(lines) else ""
                        findings.append(Finding(
                            title=f"Potential {cve_id}",
                            description=desc,
                            severity=severity,
                            confidence=confidence,
                            detector=DetectorType.API,
                            source=FindingSource.STATIC,
                            category="Known CVE",
                            cve_id=cve_id,
                            owasp_mobile="M8: Security Misconfiguration",
                            evidence=[f"File: {path}:{ln}", f"Code: {ctx[:120]}"],
                            affected_files=[str(path)],
                            line_numbers=[ln],
                            recommendation=rec,
                            tags=["known_cve"],
                        ))
        return findings
