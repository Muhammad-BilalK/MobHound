"""
MobHound Scanner - Dynamic Engine
====================================
Processes dynamic analysis data from Frida and mitmproxy.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from scanner.models import DetectorType, Finding, FindingSource, Severity
from scanner.detectors.traffic_detector import TrafficDetector
from scanner.detectors.secret_detector  import SecretDetector
from scanner.detectors.auth_detector    import AuthDetector

logger = logging.getLogger("mobhound.scanner.dynamic")


class DynamicEngine:
    """Process dynamic analysis artifacts into findings."""

    def run(
        self,
        traffic_flows: Optional[List[Dict[str, Any]]] = None,
        frida_events:  Optional[List[Dict[str, Any]]] = None,
    ) -> List[Finding]:
        traffic_flows = traffic_flows or []
        frida_events  = frida_events  or []

        findings: List[Finding] = []

        # ── 1. Traffic analysis ──────────────────────────────
        traffic_det = TrafficDetector(flows=traffic_flows)
        tf = traffic_det.run()
        findings += tf
        logger.info("Traffic detector: %d findings", len(tf))

        # ── 2. Auth check on traffic ─────────────────────────
        auth_det = AuthDetector(traffic_flows=traffic_flows)
        authf = auth_det.run()
        findings += authf
        logger.info("Auth (dynamic): %d findings", len(authf))

        # ── 3. Secrets in traffic ────────────────────────────
        secret_det = SecretDetector()
        secret_flow_f = secret_det.scan_traffic(traffic_flows)
        findings += secret_flow_f
        logger.info("Traffic secrets: %d findings", len(secret_flow_f))

        # ── 4. Frida event processing ────────────────────────
        frida_findings = self._process_frida_events(frida_events)
        findings += frida_findings
        logger.info("Frida events: %d findings", len(frida_findings))

        logger.info("Dynamic engine total: %d findings", len(findings))
        return findings

    def _process_frida_events(self, events: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []

        for ev in events:
            ev_type = (ev.get("event") or "").upper()
            url     = ev.get("url", "")
            method  = ev.get("method", "GET")

            # HTTP request with sensitive headers
            if ev_type == "HTTP_REQUEST":
                for secret in ev.get("secrets", []):
                    hname = secret.get("header", "Unknown")
                    hval  = secret.get("value", "")[:40]
                    findings.append(Finding(
                        title=f"Runtime Token Captured: {hname}",
                        description=(
                            f"Frida captured a {hname} header "
                            f"in a {method} request to {url}."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.92,
                        detector=DetectorType.SECRET,
                        source=FindingSource.DYNAMIC,
                        category="Token Leakage",
                        cwe_id="CWE-522",
                        owasp_mobile="M4: Insufficient Authentication",
                        evidence=[f"URL: {url}", f"Header: {hname}: {hval}..."],
                        runtime_traces=[json.dumps(ev)[:200]],
                        recommendation="Ensure tokens are only sent over HTTPS.",
                    ))

            # Plain HTTP URL discovered at runtime
            elif ev_type == "URL_DISCOVERED" and url.startswith("http://"):
                findings.append(Finding(
                    title=f"Runtime HTTP URL: {url[:80]}",
                    description=f"Frida detected plaintext HTTP URL constructed at runtime: {url}",
                    severity=Severity.MEDIUM,
                    confidence=0.80,
                    detector=DetectorType.TRAFFIC,
                    source=FindingSource.DYNAMIC,
                    category="Insecure Communication",
                    cwe_id="CWE-319",
                    owasp_mobile="M3: Insecure Communication",
                    evidence=[f"Runtime URL: {url}"],
                    runtime_traces=[url],
                    recommendation="Replace all HTTP URLs with HTTPS.",
                ))

            # Crypto API calls — weak algorithms at runtime
            elif ev_type in ("CRYPTO_API", "JAVA_CRYPTO"):
                algo = ev.get("algorithm", "unknown")
                if algo.upper() in ("DES", "RC4", "MD5", "SHA1", "3DES"):
                    findings.append(Finding(
                        title=f"Weak Crypto Used at Runtime: {algo}",
                        description=f"Frida detected {algo} being used at runtime in {ev.get('class', 'unknown')}.",
                        severity=Severity.HIGH,
                        confidence=0.90,
                        detector=DetectorType.CRYPTO,
                        source=FindingSource.DYNAMIC,
                        category="Weak Cryptography",
                        cwe_id="CWE-327",
                        owasp_mobile="M5: Insufficient Cryptography",
                        evidence=[f"Algorithm: {algo}", f"Class: {ev.get('class', '')}"],
                        runtime_traces=[json.dumps(ev)[:200]],
                        recommendation=f"Replace {algo} with AES-256-GCM or SHA-256.",
                    ))

            # SQL query monitoring
            elif ev_type == "SQL_QUERY":
                query = ev.get("query", "")
                if "'" in query or "--" in query or "OR 1=1" in query.upper():
                    findings.append(Finding(
                        title="Potential SQL Injection Pattern in Runtime Query",
                        description=f"Frida detected a suspicious SQL query at runtime: {query[:100]}",
                        severity=Severity.HIGH,
                        confidence=0.82,
                        detector=DetectorType.STORAGE,
                        source=FindingSource.DYNAMIC,
                        category="SQL Injection",
                        cwe_id="CWE-89",
                        owasp_mobile="M7: Client Code Quality",
                        evidence=[f"Query: {query[:120]}"],
                        runtime_traces=[json.dumps(ev)[:200]],
                        recommendation="Use parameterized queries to prevent SQL injection.",
                    ))

            # File access to sensitive paths
            elif ev_type == "FILE_ACCESS":
                path = ev.get("path", "")
                sensitive_paths = ["/data/data/", "/sdcard/", "/proc/", "/sys/"]
                if any(path.startswith(sp) for sp in sensitive_paths):
                    findings.append(Finding(
                        title=f"Sensitive File Access at Runtime: {path[:60]}",
                        description=f"Frida detected file access to sensitive path: {path}",
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        detector=DetectorType.STORAGE,
                        source=FindingSource.DYNAMIC,
                        category="Sensitive File Access",
                        cwe_id="CWE-312",
                        owasp_mobile="M2: Insecure Data Storage",
                        evidence=[f"Path: {path}"],
                        runtime_traces=[json.dumps(ev)[:200]],
                        recommendation="Review why this path is being accessed at runtime.",
                    ))

        return findings
