"""
MobHound Scanner - Heuristic Engine
======================================
Rule-based heuristic analysis that works on aggregated scan data
rather than individual pattern matches.

Rules:
  - Obfuscation score (class name entropy, string density)
  - Permission to feature ratio (over-privileged apps)
  - Network to crypto ratio
  - Component exposure ratio
  - Code complexity indicators
  - APK structure anomalies
"""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from scanner.models import DetectorType, Finding, FindingSource, Severity

logger = logging.getLogger("mobhound.scanner.heuristic")


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


class HeuristicEngine:
    """
    Rule-based heuristic analysis.
    Works on summary data from other detectors + filesystem scan.
    """

    def __init__(
        self,
        scan_root:             Optional[Path]       = None,
        declared_permissions:  Optional[List[str]]  = None,
        exported_count:        int                  = 0,
        total_components:      int                  = 0,
        static_findings:       Optional[List]       = None,
    ):
        self._root        = scan_root
        self._permissions = declared_permissions or []
        self._exported    = exported_count
        self._total_comp  = total_components
        self._static      = static_findings or []

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        findings += self._check_obfuscation()
        findings += self._check_permission_bloat()
        findings += self._check_exposure_ratio()
        findings += self._check_finding_density()
        findings += self._check_apk_structure()
        return findings

    # ─── Obfuscation score ────────────────────────────────────

    def _check_obfuscation(self) -> List[Finding]:
        if not self._root or not self._root.exists():
            return []

        short_names = 0
        total_names = 0

        # Sample class file names from JADX output
        for path in list(self._root.rglob("*.java"))[:200]:
            name = path.stem
            total_names += 1
            # Short meaningless names like "a", "b", "aa" = obfuscated
            if len(name) <= 2 or re.fullmatch(r'[a-zA-Z]{1,3}', name):
                short_names += 1

        if total_names == 0:
            return []

        ratio = short_names / total_names

        if ratio > 0.6:
            return [Finding(
                title="Heavy Code Obfuscation Detected",
                description=(
                    f"{short_names}/{total_names} ({ratio:.0%}) class names appear obfuscated. "
                    "Heavy obfuscation makes reverse engineering harder but may hide malicious behavior. "
                    "Dynamic analysis is strongly recommended."
                ),
                severity=Severity.MEDIUM,
                confidence=min(0.9, 0.5 + ratio * 0.5),
                detector=DetectorType.MALWARE,
                source=FindingSource.STATIC,
                category="Obfuscation",
                cwe_id="CWE-693",
                owasp_mobile="M9: Reverse Engineering",
                evidence=[
                    f"Obfuscated classes: {short_names}/{total_names} ({ratio:.0%})",
                ],
                recommendation=(
                    "Run dynamic analysis to observe runtime behavior. "
                    "Use Frida scripts to extract runtime strings and API calls."
                ),
                tags=["obfuscation"],
            )]
        return []

    # ─── Permission bloat ─────────────────────────────────────

    def _check_permission_bloat(self) -> List[Finding]:
        dangerous = [
            p for p in self._permissions
            if "READ_" in p or "WRITE_" in p or "ACCESS_" in p
            or "RECORD_" in p or "CAMERA" in p or "SEND_SMS" in p
        ]

        if len(self._permissions) > 20:
            return [Finding(
                title=f"Excessive Permissions Declared ({len(self._permissions)} total)",
                description=(
                    f"The app declares {len(self._permissions)} permissions, "
                    f"including {len(dangerous)} dangerous ones. "
                    "This violates the principle of least privilege."
                ),
                severity=Severity.MEDIUM,
                confidence=0.80,
                detector=DetectorType.PERMISSION,
                source=FindingSource.STATIC,
                category="Excessive Permissions",
                cwe_id="CWE-250",
                owasp_mobile="M1: Improper Platform Usage",
                evidence=[
                    f"Total permissions: {len(self._permissions)}",
                    f"Dangerous permissions: {len(dangerous)}",
                ],
                recommendation=(
                    "Audit all permissions and remove any not strictly required. "
                    "Use the minimum necessary permissions."
                ),
                tags=["permission_bloat"],
            )]
        return []

    # ─── Component exposure ratio ─────────────────────────────

    def _check_exposure_ratio(self) -> List[Finding]:
        if self._total_comp == 0:
            return []

        ratio = self._exported / self._total_comp
        if ratio > 0.5 and self._exported >= 5:
            return [Finding(
                title=f"High Component Exposure Ratio ({self._exported}/{self._total_comp} exported)",
                description=(
                    f"{self._exported} out of {self._total_comp} components are exported ({ratio:.0%}). "
                    "A high exposure ratio significantly increases the attack surface."
                ),
                severity=Severity.HIGH,
                confidence=0.82,
                detector=DetectorType.MANIFEST,
                source=FindingSource.STATIC,
                category="Attack Surface",
                cwe_id="CWE-926",
                owasp_mobile="M1: Improper Platform Usage",
                evidence=[
                    f"Exported: {self._exported}/{self._total_comp} ({ratio:.0%})",
                ],
                recommendation=(
                    "Review each exported component. Set android:exported=false "
                    "unless external access is intentionally required."
                ),
                tags=["high_exposure"],
            )]
        return []

    # ─── Finding density (quality signal) ────────────────────

    def _check_finding_density(self) -> List[Finding]:
        critical = sum(1 for f in self._static if hasattr(f, 'severity')
                       and f.severity.value == "CRITICAL")
        high     = sum(1 for f in self._static if hasattr(f, 'severity')
                       and f.severity.value == "HIGH")

        if critical >= 5:
            return [Finding(
                title=f"High Critical Vulnerability Density ({critical} critical findings)",
                description=(
                    f"Static analysis found {critical} critical and {high} high severity issues. "
                    "This indicates systemic security neglect rather than isolated oversights."
                ),
                severity=Severity.CRITICAL,
                confidence=0.88,
                detector=DetectorType.MALWARE,
                source=FindingSource.STATIC,
                category="Security Posture",
                owasp_mobile="OWASP Mobile Top 10 (multiple)",
                evidence=[
                    f"Critical findings: {critical}",
                    f"High findings: {high}",
                ],
                recommendation=(
                    "Conduct a full security review. Prioritize critical findings first. "
                    "Consider a professional penetration test."
                ),
                tags=["high_density"],
            )]
        return []

    # ─── APK structure anomalies ──────────────────────────────

    def _check_apk_structure(self) -> List[Finding]:
        if not self._root or not self._root.exists():
            return []

        findings = []

        # Check for multiple DEX files (app might load code dynamically)
        dex_files = list(self._root.glob("*.dex")) + list(self._root.rglob("classes*.dex"))
        if len(dex_files) > 3:
            findings.append(Finding(
                title=f"Multiple DEX Files Detected ({len(dex_files)} files)",
                description=(
                    f"The APK contains {len(dex_files)} DEX files. "
                    "While multidex is legitimate, it can also be used to hide code "
                    "from static analysis tools."
                ),
                severity=Severity.LOW,
                confidence=0.65,
                detector=DetectorType.MALWARE,
                source=FindingSource.STATIC,
                category="APK Structure",
                cwe_id="CWE-829",
                owasp_mobile="M9: Reverse Engineering",
                evidence=[f"DEX files: {[f.name for f in dex_files[:5]]}"],
                recommendation="Verify all DEX files are expected. Analyze secondary DEX files manually.",
                tags=["multidex"],
            ))

        # Check for embedded APKs (dropper behavior)
        embedded_apks = list(self._root.rglob("*.apk"))
        if embedded_apks:
            findings.append(Finding(
                title=f"Embedded APK(s) Found ({len(embedded_apks)} files)",
                description=(
                    f"Found {len(embedded_apks)} APK file(s) embedded inside the app. "
                    "This is a common dropper/malware pattern."
                ),
                severity=Severity.HIGH,
                confidence=0.88,
                detector=DetectorType.MALWARE,
                source=FindingSource.STATIC,
                category="Dropper Behavior",
                cwe_id="CWE-829",
                owasp_mobile="M9: Reverse Engineering",
                evidence=[f"Embedded APKs: {[f.name for f in embedded_apks[:3]]}"],
                recommendation="Investigate all embedded APK files. This is a strong malware indicator.",
                tags=["embedded_apk", "dropper", "malware_indicator"],
            ))

        # Check for native .so files with suspicious names
        suspicious_so = [
            f for f in self._root.rglob("*.so")
            if any(kw in f.name.lower() for kw in ["hook", "inject", "patch", "bypass", "hide"])
        ]
        if suspicious_so:
            findings.append(Finding(
                title=f"Suspicious Native Libraries Found",
                description=(
                    f"Found native library files with suspicious names: "
                    f"{[f.name for f in suspicious_so[:3]]}. "
                    "These may perform hooking, injection, or bypass operations."
                ),
                severity=Severity.HIGH,
                confidence=0.80,
                detector=DetectorType.MALWARE,
                source=FindingSource.STATIC,
                category="Suspicious Native Code",
                cwe_id="CWE-829",
                owasp_mobile="M9: Reverse Engineering",
                evidence=[f"Files: {[f.name for f in suspicious_so[:3]]}"],
                recommendation="Reverse engineer these native libraries to understand their purpose.",
                tags=["suspicious_native", "malware_indicator"],
            ))

        return findings
