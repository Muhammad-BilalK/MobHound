"""
MobHound Scanner - Core Data Models
====================================
Shared dataclasses used across all scanner components.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class FindingSource(str, Enum):
    STATIC   = "static"
    DYNAMIC  = "dynamic"
    AI       = "ai"
    COMBINED = "combined"


class DetectorType(str, Enum):
    MANIFEST   = "manifest"
    SECRET     = "secret"
    CRYPTO     = "crypto"
    TRAFFIC    = "traffic"
    PERMISSION = "permission"
    WEBVIEW    = "webview"
    STORAGE    = "storage"
    AUTH       = "auth"
    API        = "api"
    MALWARE    = "malware"


# ─────────────────────────────────────────────────────────────
# Finding model
# ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single vulnerability / security finding."""

    # Identity
    finding_id:   str = field(default_factory=lambda: str(uuid.uuid4()))
    title:        str = ""
    description:  str = ""
    severity:     Severity = Severity.INFO
    confidence:   float    = 0.5          # 0.0 – 1.0

    # Classification
    detector:     DetectorType = DetectorType.MANIFEST
    source:       FindingSource = FindingSource.STATIC
    category:     str = ""                # e.g. "Insecure Storage"

    # Mappings
    cwe_id:       Optional[str] = None    # e.g. "CWE-312"
    owasp_mobile: Optional[str] = None    # e.g. "M2: Insecure Data Storage"
    cve_id:       Optional[str] = None

    # Evidence
    evidence:     List[str]         = field(default_factory=list)   # code snippets / lines
    affected_files: List[str]       = field(default_factory=list)
    line_numbers:   List[int]       = field(default_factory=list)
    runtime_traces: List[str]       = field(default_factory=list)   # from Frida/mitmproxy
    network_evidence: List[str]     = field(default_factory=list)   # HTTP traffic

    # Recommendation
    recommendation: str = ""
    reproduction:   str = ""    # reproduction steps

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags:      List[str] = field(default_factory=list)
    raw:       Dict[str, Any] = field(default_factory=dict)  # detector-specific raw data

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"]  = self.severity.value
        d["source"]    = self.source.value
        d["detector"]  = self.detector.value
        return d

    @property
    def risk_score(self) -> float:
        """Numeric risk score 0-10 based on severity × confidence."""
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH:      7.5,
            Severity.MEDIUM:    5.0,
            Severity.LOW:       2.5,
            Severity.INFO:      1.0,
        }
        return round(weights[self.severity] * self.confidence, 2)


# ─────────────────────────────────────────────────────────────
# Feature vector (for AI engine)
# ─────────────────────────────────────────────────────────────

@dataclass
class FeatureVector:
    """Numeric feature vector used by the AI classifier."""

    # Static features
    dangerous_permissions:   int   = 0
    exported_components:     int   = 0
    weak_crypto_count:       int   = 0
    hardcoded_urls:          int   = 0
    hardcoded_secrets:       int   = 0
    reflection_usage:        int   = 0
    dynamic_code_loading:    int   = 0
    native_lib_usage:        int   = 0
    obfuscation_score:       float = 0.0  # 0-1
    webview_js_enabled:      int   = 0
    webview_file_access:     int   = 0
    insecure_random:         int   = 0
    http_usage:              int   = 0    # plain HTTP (not HTTPS)
    debuggable:              int   = 0
    backup_enabled:          int   = 0

    # Dynamic features
    ssl_bypass_detected:     int   = 0
    root_check_bypassed:     int   = 0
    runtime_secrets_found:   int   = 0
    suspicious_traffic:      int   = 0
    sql_queries_seen:        int   = 0
    file_access_sensitive:   int   = 0
    ipc_activity:            int   = 0
    crypto_api_calls:        int   = 0

    def to_list(self) -> List[float]:
        return [float(v) for v in asdict(self).values()]

    @staticmethod
    def feature_names() -> List[str]:
        return list(FeatureVector.__dataclass_fields__.keys())


# ─────────────────────────────────────────────────────────────
# Scan result (top-level output)
# ─────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Complete result of a MobHound scan."""

    scan_id:        str = field(default_factory=lambda: str(uuid.uuid4()))
    apk_path:       str = ""
    package_name:   str = ""
    scan_started:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_finished:  str = ""

    findings:       List[Finding] = field(default_factory=list)
    feature_vector: Optional[FeatureVector] = None
    ai_risk_label:  str   = "UNKNOWN"   # e.g. "HIGH_RISK"
    ai_confidence:  float = 0.0

    # Stats
    static_findings_count:  int = 0
    dynamic_findings_count: int = 0
    ai_findings_count:      int = 0

    metadata: Dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> None:
        self.scan_finished = datetime.now(timezone.utc).isoformat()
        self.static_findings_count  = sum(1 for f in self.findings if f.source == FindingSource.STATIC)
        self.dynamic_findings_count = sum(1 for f in self.findings if f.source == FindingSource.DYNAMIC)
        self.ai_findings_count      = sum(1 for f in self.findings if f.source == FindingSource.AI)

    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        if self.feature_vector:
            d["feature_vector"] = asdict(self.feature_vector)
        return d
