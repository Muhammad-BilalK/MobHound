"""
MobHound Scanner - Manifest Detector
======================================
Analyzes AndroidManifest.xml for security misconfigurations.

Detects:
  - Exported components without permissions
  - Debuggable / backup-enabled flags
  - Dangerous permission combinations
  - Deep link / intent filter hijacking
  - Network security config issues
  - Custom permission misuse
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

from scanner.models import (
    DetectorType, Finding, FindingSource, Severity
)


# ─────────────────────────────────────────────────────────────
# Dangerous permissions (OWASP Mobile Top 10)
# ─────────────────────────────────────────────────────────────

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS":        (Severity.HIGH,   "M2"),
    "android.permission.WRITE_CONTACTS":       (Severity.HIGH,   "M2"),
    "android.permission.READ_CALL_LOG":        (Severity.HIGH,   "M2"),
    "android.permission.WRITE_CALL_LOG":       (Severity.HIGH,   "M2"),
    "android.permission.PROCESS_OUTGOING_CALLS":(Severity.HIGH,  "M2"),
    "android.permission.READ_SMS":             (Severity.HIGH,   "M2"),
    "android.permission.RECEIVE_SMS":          (Severity.HIGH,   "M2"),
    "android.permission.SEND_SMS":             (Severity.HIGH,   "M2"),
    "android.permission.RECORD_AUDIO":         (Severity.HIGH,   "M2"),
    "android.permission.CAMERA":               (Severity.MEDIUM, "M2"),
    "android.permission.ACCESS_FINE_LOCATION": (Severity.MEDIUM, "M2"),
    "android.permission.ACCESS_COARSE_LOCATION":(Severity.LOW,   "M2"),
    "android.permission.READ_EXTERNAL_STORAGE":(Severity.MEDIUM, "M2"),
    "android.permission.WRITE_EXTERNAL_STORAGE":(Severity.MEDIUM,"M2"),
    "android.permission.GET_ACCOUNTS":         (Severity.MEDIUM, "M2"),
    "android.permission.MANAGE_ACCOUNTS":      (Severity.HIGH,   "M2"),
    "android.permission.USE_CREDENTIALS":      (Severity.HIGH,   "M2"),
    "android.permission.INTERNET":             (Severity.LOW,    "M3"),
    "android.permission.CHANGE_NETWORK_STATE": (Severity.LOW,    "M3"),
    "android.permission.RECEIVE_BOOT_COMPLETED":(Severity.LOW,   "M8"),
    "android.permission.SYSTEM_ALERT_WINDOW":  (Severity.HIGH,   "M1"),
    "android.permission.BIND_DEVICE_ADMIN":    (Severity.CRITICAL,"M1"),
    "android.permission.MASTER_CLEAR":         (Severity.CRITICAL,"M1"),
    "android.permission.FACTORY_TEST":         (Severity.CRITICAL,"M1"),
}

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(elem: ET.Element, name: str) -> Optional[str]:
    return elem.get(f"{{{ANDROID_NS}}}{name}") or elem.get(name)


def _is_true(val: Optional[str]) -> bool:
    return val is not None and val.lower() in ("true", "1")


# ─────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────

class ManifestDetector:
    """Parse AndroidManifest.xml and emit security findings."""

    def __init__(self, manifest_path: Optional[Path] = None,
                 manifest_element: Optional[ET.Element] = None):
        self._path    = manifest_path
        self._element = manifest_element

    def _get_root(self) -> Optional[ET.Element]:
        if self._element is not None:
            return self._element
        if self._path and self._path.exists():
            try:
                tree = ET.parse(str(self._path))
                return tree.getroot()
            except ET.ParseError:
                return None
        return None

    # ─── Public API ───────────────────────────────────────────

    def run(self) -> List[Finding]:
        root = self._get_root()
        if root is None:
            return []

        findings: List[Finding] = []
        findings += self._check_application_flags(root)
        findings += self._check_dangerous_permissions(root)
        findings += self._check_exported_components(root)
        findings += self._check_deep_links(root)
        findings += self._check_network_security_config(root)
        findings += self._check_backup_agent(root)
        return findings

    # ─── Sub-checks ──────────────────────────────────────────

    def _check_application_flags(self, root: ET.Element) -> List[Finding]:
        findings = []
        app = root.find("application")
        if app is None:
            return findings

        debuggable  = _attr(app, "debuggable")
        backup      = _attr(app, "allowBackup")
        cleartext   = _attr(app, "usesCleartextTraffic")
        test_only   = _attr(app, "testOnly")

        if _is_true(debuggable):
            findings.append(Finding(
                title="Application is Debuggable",
                description=(
                    "The android:debuggable flag is set to true. This allows "
                    "attackers with physical access to extract app data, bypass "
                    "certificate pinning, and attach a debugger."
                ),
                severity=Severity.HIGH,
                confidence=1.0,
                detector=DetectorType.MANIFEST,
                source=FindingSource.STATIC,
                category="Misconfiguration",
                cwe_id="CWE-489",
                owasp_mobile="M8: Security Misconfiguration",
                evidence=["android:debuggable=\"true\""],
                affected_files=["AndroidManifest.xml"],
                recommendation=(
                    "Remove android:debuggable from the manifest or set it to false. "
                    "In release builds this attribute should not be present."
                ),
            ))

        if backup is None or _is_true(backup):
            findings.append(Finding(
                title="Application Backup Enabled",
                description=(
                    "android:allowBackup is true (default). Sensitive app data "
                    "can be extracted via 'adb backup' without root access."
                ),
                severity=Severity.MEDIUM,
                confidence=0.9,
                detector=DetectorType.MANIFEST,
                source=FindingSource.STATIC,
                category="Data Exposure",
                cwe_id="CWE-532",
                owasp_mobile="M2: Insecure Data Storage",
                evidence=['android:allowBackup="true"'],
                affected_files=["AndroidManifest.xml"],
                recommendation='Set android:allowBackup="false" in <application>.',
            ))

        if _is_true(cleartext):
            findings.append(Finding(
                title="Cleartext Traffic Allowed",
                description=(
                    "android:usesCleartextTraffic is true. The app may transmit "
                    "sensitive data over unencrypted HTTP connections."
                ),
                severity=Severity.HIGH,
                confidence=1.0,
                detector=DetectorType.MANIFEST,
                source=FindingSource.STATIC,
                category="Insecure Communication",
                cwe_id="CWE-319",
                owasp_mobile="M3: Insecure Communication",
                evidence=['android:usesCleartextTraffic="true"'],
                affected_files=["AndroidManifest.xml"],
                recommendation=(
                    'Set android:usesCleartextTraffic="false" and use a '
                    'Network Security Configuration to enforce HTTPS.'
                ),
            ))

        if _is_true(test_only):
            findings.append(Finding(
                title="Application Marked as testOnly",
                description=(
                    "android:testOnly is true. This allows installation of apps "
                    "not signed for release and may expose additional attack surface."
                ),
                severity=Severity.MEDIUM,
                confidence=1.0,
                detector=DetectorType.MANIFEST,
                source=FindingSource.STATIC,
                category="Misconfiguration",
                cwe_id="CWE-489",
                owasp_mobile="M8: Security Misconfiguration",
                evidence=['android:testOnly="true"'],
                affected_files=["AndroidManifest.xml"],
                recommendation="Remove android:testOnly from release builds.",
            ))

        return findings

    def _check_dangerous_permissions(self, root: ET.Element) -> List[Finding]:
        findings = []
        requested = []

        for perm in root.findall("uses-permission"):
            name = _attr(perm, "name") or ""
            requested.append(name)
            if name in DANGEROUS_PERMISSIONS:
                severity, owasp = DANGEROUS_PERMISSIONS[name]
                findings.append(Finding(
                    title=f"Dangerous Permission: {name.split('.')[-1]}",
                    description=(
                        f"The app requests {name}, which grants access to "
                        f"sensitive device resources."
                    ),
                    severity=severity,
                    confidence=0.85,
                    detector=DetectorType.PERMISSION,
                    source=FindingSource.STATIC,
                    category="Excessive Permissions",
                    cwe_id="CWE-250",
                    owasp_mobile=f"M2 / {owasp}",
                    evidence=[f'<uses-permission android:name="{name}"/>'],
                    affected_files=["AndroidManifest.xml"],
                    recommendation=(
                        f"Verify that {name} is strictly required. "
                        "Apply the principle of least privilege."
                    ),
                ))

        # Dangerous combo: SMS + INTERNET → possible data exfiltration
        if ("android.permission.READ_SMS" in requested and
                "android.permission.INTERNET" in requested):
            findings.append(Finding(
                title="Suspicious Permission Combo: SMS + INTERNET",
                description=(
                    "The app requests both READ_SMS and INTERNET permissions. "
                    "This combination is commonly found in spyware that exfiltrates SMS data."
                ),
                severity=Severity.CRITICAL,
                confidence=0.75,
                detector=DetectorType.PERMISSION,
                source=FindingSource.STATIC,
                category="Potential Malware",
                cwe_id="CWE-200",
                owasp_mobile="M1: Improper Platform Usage",
                evidence=["READ_SMS + INTERNET permission combination"],
                affected_files=["AndroidManifest.xml"],
                recommendation=(
                    "Review whether both permissions are legitimately needed. "
                    "If READ_SMS is not required, remove it immediately."
                ),
            ))

        return findings

    def _check_exported_components(self, root: ET.Element) -> List[Finding]:
        findings = []
        app = root.find("application")
        if app is None:
            return findings

        component_tags = ["activity", "service", "receiver", "provider"]

        for tag in component_tags:
            for comp in app.findall(tag):
                name      = _attr(comp, "name") or "unknown"
                exported  = _attr(comp, "exported")
                permission= _attr(comp, "permission")

                # Determine effective exported state
                has_intent_filter = comp.find("intent-filter") is not None
                # Android <12: default is true if intent-filter present, else false
                # Android 12+: must be explicit
                effectively_exported = (
                    _is_true(exported) or
                    (exported is None and has_intent_filter)
                )

                if effectively_exported and not permission:
                    severity = Severity.HIGH if tag in ("activity", "provider") else Severity.MEDIUM

                    findings.append(Finding(
                        title=f"Exported {tag.capitalize()} Without Permission: {name.split('.')[-1]}",
                        description=(
                            f"{name} is exported without a permission check. "
                            f"Any installed app can invoke this {tag}, potentially "
                            f"leading to unauthorized access or data exposure."
                        ),
                        severity=severity,
                        confidence=0.9,
                        detector=DetectorType.MANIFEST,
                        source=FindingSource.STATIC,
                        category="Insecure Component",
                        cwe_id="CWE-926",
                        owasp_mobile="M1: Improper Platform Usage",
                        evidence=[
                            f'<{tag} android:name="{name}" android:exported="true"/>',
                        ],
                        affected_files=["AndroidManifest.xml"],
                        recommendation=(
                            f'Add android:permission="<custom_permission>" to restrict '
                            f'access to this {tag}, or set android:exported="false" if '
                            "it should not be externally accessible."
                        ),
                    ))

        return findings

    def _check_deep_links(self, root: ET.Element) -> List[Finding]:
        findings = []
        app = root.find("application")
        if app is None:
            return findings

        for activity in app.findall("activity"):
            name = _attr(activity, "name") or "unknown"
            for intent_filter in activity.findall("intent-filter"):
                for data in intent_filter.findall("data"):
                    scheme = _attr(data, "scheme") or ""
                    host   = _attr(data, "host") or ""
                    if scheme and scheme not in ("http", "https", "content", "file"):
                        findings.append(Finding(
                            title=f"Custom Deep Link Scheme: {scheme}://",
                            description=(
                                f"Activity '{name}' handles custom URI scheme '{scheme}://'. "
                                f"Without proper input validation, this can lead to deep link "
                                f"hijacking or intent injection attacks."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=0.8,
                            detector=DetectorType.MANIFEST,
                            source=FindingSource.STATIC,
                            category="Deep Link Hijacking",
                            cwe_id="CWE-601",
                            owasp_mobile="M1: Improper Platform Usage",
                            evidence=[
                                f'<data android:scheme="{scheme}" android:host="{host}"/>',
                            ],
                            affected_files=["AndroidManifest.xml"],
                            recommendation=(
                                "Validate all incoming deep link parameters. "
                                "Use App Links (HTTPS) instead of custom schemes where possible. "
                                "Never trust URI parameters for authentication."
                            ),
                        ))
        return findings

    def _check_network_security_config(self, root: ET.Element) -> List[Finding]:
        findings = []
        app = root.find("application")
        if app is None:
            return findings

        nsc = _attr(app, "networkSecurityConfig")
        if not nsc:
            findings.append(Finding(
                title="No Network Security Configuration Defined",
                description=(
                    "The app does not define a Network Security Configuration "
                    "(android:networkSecurityConfig). Without this, the app uses "
                    "system defaults which may allow cleartext traffic on older APIs."
                ),
                severity=Severity.LOW,
                confidence=0.7,
                detector=DetectorType.MANIFEST,
                source=FindingSource.STATIC,
                category="Insecure Communication",
                cwe_id="CWE-319",
                owasp_mobile="M3: Insecure Communication",
                evidence=["No android:networkSecurityConfig attribute in <application>"],
                affected_files=["AndroidManifest.xml"],
                recommendation=(
                    "Add a res/xml/network_security_config.xml that pins certificates "
                    "and disables cleartext traffic. Reference it with "
                    'android:networkSecurityConfig="@xml/network_security_config".'
                ),
            ))
        return findings

    def _check_backup_agent(self, root: ET.Element) -> List[Finding]:
        """Check for sensitive data in backup agent if one is declared."""
        findings = []
        app = root.find("application")
        if app is None:
            return findings

        backup_agent = _attr(app, "backupAgent")
        if backup_agent:
            findings.append(Finding(
                title=f"Custom Backup Agent: {backup_agent}",
                description=(
                    f"A custom BackupAgent '{backup_agent}' is declared. "
                    "Ensure it does not back up sensitive data such as session tokens, "
                    "encryption keys, or user credentials."
                ),
                severity=Severity.LOW,
                confidence=0.65,
                detector=DetectorType.MANIFEST,
                source=FindingSource.STATIC,
                category="Data Exposure",
                cwe_id="CWE-312",
                owasp_mobile="M2: Insecure Data Storage",
                evidence=[f'android:backupAgent="{backup_agent}"'],
                affected_files=["AndroidManifest.xml"],
                recommendation=(
                    "Review the BackupAgent implementation. Exclude sensitive files "
                    "using fullBackupContent or dataExtractionRules."
                ),
            ))
        return findings
