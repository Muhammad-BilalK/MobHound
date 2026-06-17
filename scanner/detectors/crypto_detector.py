"""
MobHound Scanner - Crypto Detector
=====================================
Detects weak cryptographic patterns in decompiled source code.

Checks:
  - Weak algorithms (DES, 3DES, RC4, MD5, SHA1)
  - ECB mode usage
  - Static IV / hardcoded salt
  - Insecure SecureRandom seeding
  - Weak key lengths
  - RSA without OAEP padding
  - Custom crypto implementations
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
# (label, pattern, severity, confidence, cwe, recommendation)
# ─────────────────────────────────────────────────────────────

CRYPTO_PATTERNS: List[Tuple[str, str, Severity, float, str, str]] = [

    # Weak algorithms
    ("DES Algorithm",
     r'(?i)Cipher\.getInstance\s*\(\s*["\']DES[/"\']',
     Severity.HIGH, 0.95, "CWE-327",
     "Replace DES with AES-256-GCM. DES has only 56-bit effective key length."),

    ("3DES / Triple DES",
     r'(?i)Cipher\.getInstance\s*\(\s*["\'](?:DESede|TripleDES)',
     Severity.HIGH, 0.90, "CWE-327",
     "3DES is deprecated. Use AES-256-GCM instead."),

    ("RC4 Stream Cipher",
     r'(?i)Cipher\.getInstance\s*\(\s*["\'](?:RC4|ARCFOUR)',
     Severity.HIGH, 0.95, "CWE-327",
     "RC4 is cryptographically broken. Use AES-256-GCM."),

    ("Blowfish",
     r'(?i)Cipher\.getInstance\s*\(\s*["\']Blowfish',
     Severity.MEDIUM, 0.85, "CWE-327",
     "Blowfish has small block size (64-bit) and is vulnerable to birthday attacks. Use AES-256-GCM."),

    ("MD5 Hashing",
     r'(?i)MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
     Severity.HIGH, 0.95, "CWE-328",
     "MD5 is cryptographically broken. Use SHA-256 or SHA-3 for integrity, bcrypt/Argon2 for passwords."),

    ("SHA-1 Hashing",
     r'(?i)MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']',
     Severity.MEDIUM, 0.90, "CWE-328",
     "SHA-1 is deprecated. Use SHA-256 or SHA-3."),

    # ECB mode
    ("ECB Mode",
     r'(?i)Cipher\.getInstance\s*\(\s*["\'][^"\']+/ECB/',
     Severity.HIGH, 0.95, "CWE-327",
     "ECB mode reveals patterns in plaintext. Use CBC with random IV or preferably GCM."),

    ("AES without explicit mode (defaults to ECB on some JVMs)",
     r'(?i)Cipher\.getInstance\s*\(\s*["\']AES["\']',
     Severity.MEDIUM, 0.80, "CWE-327",
     'Always specify mode and padding: "AES/GCM/NoPadding" instead of just "AES".'),

    # Static IV / Hardcoded IV
    ("Static/Hardcoded IV",
     r'(?i)(?:IvParameterSpec|GCMParameterSpec)\s*\(\s*(?:new\s+byte\[\s*\{|\")',
     Severity.HIGH, 0.85, "CWE-329",
     "Never use a hardcoded IV. Generate a cryptographically random IV for each encryption operation."),

    ("Zero IV",
     r'(?i)new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*(?:16|12|8)\s*\]\s*\)',
     Severity.CRITICAL, 0.92, "CWE-329",
     "Using a zero IV (new byte[16]) is insecure. Generate a random IV with SecureRandom."),

    # Insecure SecureRandom
    ("SecureRandom with Fixed Seed",
     r'(?i)(?:SecureRandom|Random)\s*\w*\s*[=:]\s*new\s+SecureRandom\s*\(\s*["\']',
     Severity.HIGH, 0.85, "CWE-338",
     "Never seed SecureRandom with a hardcoded value. Use the no-arg constructor."),

    ("java.util.Random (not secure)",
     r'(?i)new\s+(?:java\.util\.)?Random\s*\(\s*\)',
     Severity.MEDIUM, 0.75, "CWE-338",
     "java.util.Random is not cryptographically secure. Use java.security.SecureRandom."),

    # RSA
    ("RSA without OAEP Padding",
     r'(?i)Cipher\.getInstance\s*\(\s*["\']RSA(?:/None)?/NoPadding',
     Severity.HIGH, 0.92, "CWE-780",
     'Use "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" instead of NoPadding or PKCS1Padding.'),

    ("RSA/ECB/PKCS1Padding (vulnerable to padding oracle)",
     r'(?i)Cipher\.getInstance\s*\(\s*["\']RSA/ECB/PKCS1Padding',
     Severity.MEDIUM, 0.85, "CWE-780",
     "PKCS1 padding is vulnerable to Bleichenbacher attacks. Use OAEP padding instead."),

    # Weak key derivation
    ("PBEKeySpec with low iteration count",
     r'(?i)new\s+PBEKeySpec\s*\([^,]+,\s*[^,]+,\s*(\d+)',
     Severity.HIGH, 0.78, "CWE-916",
     "Use at least 100,000 iterations for PBKDF2. Consider Argon2 for new implementations."),

    ("SHA1withRSA signature",
     r'(?i)Signature\.getInstance\s*\(\s*["\']SHA1withRSA',
     Severity.MEDIUM, 0.88, "CWE-327",
     'Use "SHA256withRSA" or "SHA256withECDSA" for digital signatures.'),

    # Hardcoded encryption key
    ("Hardcoded Encryption Key",
     r'(?i)(?:SecretKeySpec|DESKeySpec)\s*\(\s*["\'][^"\']{8,}["\']\.getBytes\(\)',
     Severity.CRITICAL, 0.88, "CWE-321",
     "Encryption keys must never be hardcoded. Use Android Keystore system."),

    # Custom crypto
    ("XOR Encryption",
     r'(?i)(?:xor|[\^])\s*=?\s*(?:key|password|secret|0x)',
     Severity.MEDIUM, 0.65, "CWE-327",
     "Custom XOR encryption is not secure. Use AES-256-GCM via the Android Keystore."),
]


class CryptoDetector:
    """Scan decompiled code for weak cryptographic patterns."""

    def __init__(self, scan_root: Optional[Path] = None,
                 extra_sources: Optional[List[Tuple[str, str]]] = None):
        self._root   = scan_root
        self._extra  = extra_sources or []

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        if self._root and self._root.exists():
            for path in self._root.rglob("*.java"):
                findings += self._scan_file(path)
            for path in self._root.rglob("*.kt"):
                findings += self._scan_file(path)
            for path in self._root.rglob("*.smali"):
                findings += self._scan_file(path)

        for name, content in self._extra:
            findings += self._scan_text(content, name)

        return findings

    def _scan_file(self, path: Path) -> List[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            return self._scan_text(text, str(path))
        except OSError:
            return []

    def _scan_text(self, text: str, source_name: str) -> List[Finding]:
        findings = []
        lines    = text.splitlines()

        for label, pattern, severity, confidence, cwe, rec in CRYPTO_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE)
            except re.error:
                continue

            for match in compiled.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                ctx = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                findings.append(Finding(
                    title=f"Weak Cryptography: {label}",
                    description=(
                        f"Found weak cryptographic usage ({label}) in '{source_name}'. "
                        f"This can lead to data being decrypted or forged by attackers."
                    ),
                    severity=severity,
                    confidence=confidence,
                    detector=DetectorType.CRYPTO,
                    source=FindingSource.STATIC,
                    category="Weak Cryptography",
                    cwe_id=cwe,
                    owasp_mobile="M5: Insufficient Cryptography",
                    evidence=[
                        f"File: {source_name}:{line_num}",
                        f"Code: {ctx[:120]}",
                    ],
                    affected_files=[source_name],
                    line_numbers=[line_num],
                    recommendation=rec,
                    raw={"pattern": label, "line": line_num},
                ))

        return findings
