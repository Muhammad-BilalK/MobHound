"""
MobHound - Scanner Module
===========================
Central vulnerability detection engine for MobHound.

Orchestrates:
  ┌─────────────────────────────────────────────┐
  │  APK Input                                  │
  │     ↓                                       │
  │  Reverse Engineering Module                 │
  │     ↓  (StructuredREOutput)                 │
  │  Static Engine → Detectors                  │
  │     ↓                                       │
  │  Dynamic Engine ← Frida + mitmproxy data    │
  │     ↓                                       │
  │  AI Engine → FeatureVector → RF Classifier  │
  │     ↓                                       │
  │  Correlation Engine → Dedup + Score         │
  │     ↓                                       │
  │  Report Generator → JSON + HTML             │
  └─────────────────────────────────────────────┘

Usage:
    from scanner_module import ScannerModule

    scanner = ScannerModule(project_dir=Path("projects/my_app"))
    result  = scanner.run(
        apk_path       = "path/to/app.apk",
        re_output      = re_pipeline.run(...),     # StructuredREOutput
        traffic_flows  = load_flows(...),           # mitmproxy JSONL
        frida_events   = load_frida_events(...),    # Frida send() events
    )
    print(f"Found {len(result.findings)} issues | Risk: {result.ai_risk_label}")
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

# ── Scanner sub-modules ──────────────────────────────────────
from scanner.models import (
    Finding, FindingSource, ScanResult, Severity
)
# Engines (now properly separated into their own files)
from scanner.engines.static_engine      import StaticEngine
from scanner.engines.dynamic_engine     import DynamicEngine
from scanner.engines.ai_engine          import AIEngine
from scanner.engines.correlation_engine import CorrelationEngine
from scanner.malware.pipeline           import MalwareAnalysisPipeline
from scanner.reports.report_generator   import ReportGenerator, UnifiedReporter

# ── RE Backend Service integration ──────────────────────────
try:
    from reverse_engineering.re_backend_service import REService, REResult, get_service as get_re_service
    from reverse_engineering.apk_reverse_engineering_backend import StructuredREOutput
    RE_INTEGRATION = True
except ImportError:
    REService = None        # type: ignore
    REResult  = None        # type: ignore
    StructuredREOutput = None
    RE_INTEGRATION = False

logger = logging.getLogger("mobhound.scanner")

# ─────────────────────────────────────────────────────────────
# Project directory layout expected by the scanner
# ─────────────────────────────────────────────────────────────
_PROJECT_SUBDIRS = [
    "apk", "reverse_engineering", "dynamic_analysis",
    "scanner_results", "ai_models", "traffic", "logs", "reports", "cache",
]


def _ensure_project_dirs(root: Path) -> None:
    for sub in _PROJECT_SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────
# Helper – load mitmproxy JSONL flows
# ─────────────────────────────────────────────────────────────

def load_traffic_flows(jsonl_path: Path) -> List[Dict[str, Any]]:
    flows = []
    if not jsonl_path.exists():
        return flows
    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                flows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    logger.info("Loaded %d traffic flows from %s", len(flows), jsonl_path)
    return flows


# ─────────────────────────────────────────────────────────────
# Helper – load Frida send() events
# ─────────────────────────────────────────────────────────────

def load_frida_events(jsonl_path: Path) -> List[Dict[str, Any]]:
    events = []
    if not jsonl_path.exists():
        return events
    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    logger.info("Loaded %d Frida events from %s", len(events), jsonl_path)
    return events


# ─────────────────────────────────────────────────────────────
# Static Engine (internal)
# ─────────────────────────────────────────────────────────────

class _StaticEngine:
    """Coordinates all static detectors."""

    def run(
        self,
        re_output:     Optional["StructuredREOutput"],
        re_output_raw: Optional[Dict[str, Any]],
        jadx_dir:      Optional[Path],
        manifest_path: Optional[Path],
        manifest_elem: Optional[ET.Element],
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Manifest
        manifest_det = ManifestDetector(
            manifest_path=manifest_path,
            manifest_element=manifest_elem,
        )
        manifest_findings = manifest_det.run()
        findings += manifest_findings
        logger.info("Manifest detector: %d findings", len(manifest_findings))

        # 2. Secret detector (source code)
        secret_det = SecretDetector(scan_root=jadx_dir)
        secret_findings = secret_det.run()
        findings += secret_findings
        logger.info("Secret detector: %d findings", len(secret_findings))

        # 3. Crypto detector
        crypto_det = CryptoDetector(scan_root=jadx_dir)
        crypto_findings = crypto_det.run()
        findings += crypto_findings
        logger.info("Crypto detector: %d findings", len(crypto_findings))

        # 4. Permission / WebView / Storage detector
        perm_det = PermissionWebViewDetector(scan_root=jadx_dir)
        perm_findings = perm_det.run()
        findings += perm_findings
        logger.info("Permission/WebView detector: %d findings", len(perm_findings))

        # 5. Consume StructuredREOutput findings (from reverse engineering module)
        if re_output is not None and RE_INTEGRATION:
            re_findings = self._convert_re_findings(re_output)
            findings += re_findings
            logger.info("RE module: %d findings converted", len(re_findings))
        elif re_output_raw:
            re_findings = self._convert_re_findings_raw(re_output_raw)
            findings += re_findings

        return findings

    def _convert_re_findings(self, re_output: "StructuredREOutput") -> List[Finding]:
        """Convert StructuredREOutput.findings → scanner Findings."""
        result = []
        for ref in re_output.findings:
            sev = Severity.MEDIUM
            if "critical" in ref.security_relevance.lower():
                sev = Severity.CRITICAL
            elif "high" in ref.security_relevance.lower():
                sev = Severity.HIGH
            elif "low" in ref.security_relevance.lower():
                sev = Severity.LOW

            result.append(Finding(
                title=ref.title,
                description=ref.summary,
                severity=sev,
                confidence=float(ref.confidence),
                source=FindingSource.STATIC,
                category="Reverse Engineering",
                evidence=[ref.security_relevance],
                recommendation="Review the decompiled code for this finding.",
                tags=["from_re_module"],
            ))
        return result

    def _convert_re_findings_raw(self, raw: Dict[str, Any]) -> List[Finding]:
        result = []
        for ref in raw.get("findings", []):
            result.append(Finding(
                title=ref.get("title", "RE Finding"),
                description=ref.get("summary", ""),
                severity=Severity.MEDIUM,
                confidence=float(ref.get("confidence", 0.5)),
                source=FindingSource.STATIC,
                category="Reverse Engineering",
                tags=["from_re_module"],
            ))
        return result


# ─────────────────────────────────────────────────────────────
# Dynamic Engine (internal)
# ─────────────────────────────────────────────────────────────

class _DynamicEngine:
    """Processes dynamic analysis data."""

    def run(
        self,
        traffic_flows: List[Dict[str, Any]],
        frida_events:  List[Dict[str, Any]],
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Traffic analysis
        traffic_det = TrafficDetector(flows=traffic_flows)
        traffic_findings = traffic_det.run()
        findings += traffic_findings
        logger.info("Traffic detector: %d findings", len(traffic_findings))

        # 2. Secret detector on traffic
        secret_det = SecretDetector(extra_text_sources=[
            (f["request"].get("url", "flow"), json.dumps(f))
            for f in traffic_flows
            if f.get("request")
        ])
        traffic_secrets = secret_det.scan_traffic(traffic_flows)
        findings += traffic_secrets
        logger.info("Traffic secrets: %d findings", len(traffic_secrets))

        # 3. Process Frida events
        frida_findings = self._process_frida_events(frida_events)
        findings += frida_findings
        logger.info("Frida events: %d findings", len(frida_findings))

        return findings

    def _process_frida_events(self, events: List[Dict[str, Any]]) -> List[Finding]:
        findings = []
        for ev in events:
            ev_type = ev.get("event", "").upper()
            url     = ev.get("url", "")
            method  = ev.get("method", "")

            if ev_type == "HTTP_REQUEST":
                # Check for secrets in headers captured by Frida traffic tagger
                secrets = ev.get("secrets", [])
                for secret in secrets:
                    findings.append(Finding(
                        title=f"Runtime Token Captured: {secret.get('header', 'Unknown')}",
                        description=(
                            f"Frida captured a {secret.get('header')} header in a "
                            f"{method} request to {url}."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.92,
                        source=FindingSource.DYNAMIC,
                        category="Token Leakage",
                        cwe_id="CWE-522",
                        owasp_mobile="M4: Insufficient Authentication",
                        evidence=[
                            f"URL: {url}",
                            f"Header: {secret.get('header')}: {secret.get('value', '')[:40]}",
                        ],
                        runtime_traces=[json.dumps(ev)[:200]],
                        recommendation="Ensure tokens are only transmitted over HTTPS.",
                    ))

            elif ev_type == "URL_DISCOVERED":
                if url.startswith("http://"):
                    findings.append(Finding(
                        title=f"Runtime HTTP URL Discovery: {url[:80]}",
                        description=(
                            f"Frida detected a plaintext HTTP URL constructed at runtime: {url}"
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.80,
                        source=FindingSource.DYNAMIC,
                        category="Insecure Communication",
                        cwe_id="CWE-319",
                        owasp_mobile="M3: Insecure Communication",
                        evidence=[f"Runtime URL: {url}"],
                        runtime_traces=[url],
                        recommendation="Replace all HTTP URLs with HTTPS.",
                    ))

        return findings


# ─────────────────────────────────────────────────────────────
# ScannerModule  (public API)
# ─────────────────────────────────────────────────────────────

class ScannerModule:
    """
    Main entry point for MobHound scanning.

    Parameters
    ----------
    project_dir : Path
        MobHound project root directory. Scanner results, AI models,
        and reports are stored here.
    """

    def __init__(self, project_dir: Path):
        self._project_dir = project_dir
        _ensure_project_dirs(project_dir)

        self._static_engine  = StaticEngine()
        self._dynamic_engine = DynamicEngine()
        self._ai_engine      = AIEngine(model_dir=project_dir / "ai_models")
        self._malware_engine = MalwareAnalysisPipeline(model_dir=project_dir / "ai_models" / "malware")
        self._correlation    = CorrelationEngine()
        self._reporter       = UnifiedReporter(report_dir=project_dir / "reports")

        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s][%(name)s] %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(str(project_dir / "logs" / "scanner.log")),
            ],
        )

    # ─── Main scan entry point ────────────────────────────────

    def run(
        self,
        apk_path:       str,
        re_output:      Optional[Any]            = None,   # StructuredREOutput
        re_output_raw:  Optional[Dict[str, Any]] = None,   # fallback dict
        jadx_dir:       Optional[Path]           = None,   # decompiled Java
        manifest_path:  Optional[Path]           = None,
        manifest_elem:  Optional[ET.Element]     = None,
        traffic_flows:  Optional[List[Dict]]     = None,   # mitmproxy
        frida_events:   Optional[List[Dict]]     = None,   # Frida
        manifest_data:  Optional[Dict[str, Any]] = None,   # for AI features
        scan_config:    Optional[Dict[str, bool]] = None,
    ) -> ScanResult:
        """
        Run a complete MobHound scan.

        scan_config keys default to True when omitted:
            run_static_engine, run_ai_engine, run_secret_detector,
            run_crypto_detector, run_malware_engine.
        """
        cfg = scan_config or {}
        run_static = cfg.get("run_static_engine", True)
        run_ai = cfg.get("run_ai_engine", True)
        run_secrets = cfg.get("run_secret_detector", True)
        run_crypto = cfg.get("run_crypto_detector", True)
        run_malware = cfg.get("run_malware_engine", True)

        t_start = time.time()
        logger.info("=" * 60)
        logger.info("MobHound Scanner starting for: %s", apk_path)
        logger.info(
            "Scan options: Static=%s AI=%s Secrets=%s Crypto=%s Malware=%s",
            run_static, run_ai, run_secrets, run_crypto, run_malware,
        )

        result = ScanResult(
            apk_path=apk_path,
            package_name=self._guess_package(re_output, re_output_raw),
        )

        traffic_flows = traffic_flows or []
        frida_events  = frida_events  or []

        # ── 1. Static analysis ──────────────────────────────
        if run_static or run_secrets or run_crypto or run_malware:
            logger.info("[1/5] Running static analysis...")
            static_findings = self._static_engine.run(
                re_output=re_output,
                re_output_raw=re_output_raw,
                jadx_dir=jadx_dir,
                manifest_path=manifest_path,
                manifest_elem=manifest_elem,
            )
            if not run_secrets:
                static_findings = [
                    finding for finding in static_findings
                    if getattr(finding.detector, "value", "").lower() not in ("secret", "secrets")
                    and "secret" not in str(getattr(finding, "category", "")).lower()
                    and "credential" not in str(getattr(finding, "category", "")).lower()
                ]
                logger.info("Secrets detection disabled — filtered secret findings")
            if not run_crypto:
                static_findings = [
                    finding for finding in static_findings
                    if getattr(finding.detector, "value", "").lower() not in ("crypto", "cryptography")
                    and "crypto" not in str(getattr(finding, "category", "")).lower()
                    and "cryptograph" not in str(getattr(finding, "category", "")).lower()
                ]
                logger.info("Cryptography analysis disabled — filtered crypto findings")
            if not run_malware:
                static_findings = [
                    finding for finding in static_findings
                    if getattr(finding.detector, "value", "").lower() not in ("malware", "heuristic")
                    and "malware" not in str(getattr(finding, "category", "")).lower()
                    and "behavior" not in str(getattr(finding, "category", "")).lower()
                ]
                logger.info("Malware behavioral analysis disabled — filtered malware findings")
        else:
            static_findings = []
            logger.info("[1/5] Static analysis disabled — skipped")

        # ── 2. Dynamic analysis ─────────────────────────────
        logger.info("[2/5] Processing dynamic data...")
        dynamic_findings = self._dynamic_engine.run(
            traffic_flows=traffic_flows,
            frida_events=frida_events,
        )

        # ── 3. AI classification ────────────────────────────
        if run_ai:
            logger.info("[3/5] Running AI engine...")
            fv = self._ai_engine.extract_features(
                static_findings=static_findings,
                dynamic_findings=dynamic_findings,
                manifest_data=manifest_data,
                frida_events=frida_events,
            )
            ai_label, ai_conf, ai_findings = self._ai_engine.classify(fv)
        else:
            logger.info("[3/5] AI classification disabled — using neutral risk label")
            from scanner.models import FeatureVector
            fv = FeatureVector()
            ai_label = "MEDIUM_RISK"
            ai_conf = 0.50
            ai_findings = []

        malware_static_findings: List[Finding] = []
        malware_ai_findings: List[Finding] = []
        malware_metadata: Dict[str, Any] = {"enabled": False, "findings": []}
        if run_malware:
            logger.info("[4/5] Running V2 malware-analysis pipeline...")
            malware_result = self._malware_engine.analyze(
                apk_path=apk_path,
                static_findings=static_findings,
                dynamic_findings=dynamic_findings,
                manifest_data=manifest_data,
                frida_events=frida_events,
            )
            malware_static_findings = malware_result.get("static_findings", [])
            malware_ai_findings = malware_result.get("ai_findings", [])
            malware_metadata = {
                "enabled": True,
                "bootstrap": malware_result.get("bootstrap", {}),
                "yara_result": malware_result.get("yara_result", {}),
                "permission_result": malware_result.get("permission_result", {}),
                "features": malware_result.get("features", {}),
                "ai_result": malware_result.get("ai_result", {}),
                "risk_result": malware_result.get("risk_result", {}),
                "findings": [
                    finding.to_dict()
                    for finding in ((malware_result.get("static_findings", []) or []) + (malware_result.get("ai_findings", []) or []))
                ],
            }
            logger.info(
                "Malware pipeline complete: %d static findings, %d AI findings, prediction=%s",
                len(malware_static_findings),
                len(malware_ai_findings),
                (malware_metadata.get("ai_result") or {}).get("prediction"),
            )
        else:
            logger.info("[4/5] Malware analysis disabled â€” skipped")

        result.feature_vector = fv
        result.ai_risk_label  = ai_label
        result.ai_confidence  = ai_conf
        result.metadata["malware_analysis"] = malware_metadata

        # ── 4. Correlation ──────────────────────────────────
        logger.info("[4/5] Correlating and deduplicating findings...")
        all_findings = self._correlation.run(
            static_findings=static_findings,
            dynamic_findings=dynamic_findings,
            ai_findings=ai_findings,
        )
        result.findings = all_findings
        result.finalize()

        # ── 5. Report generation ────────────────────────────
        logger.info("[5/5] Generating reports...")
        report_paths = self._reporter.save_all(result)
        json_path = report_paths.get("json")
        html_path = report_paths.get("html")
        pdf_path  = report_paths.get("pdf")

        elapsed = time.time() - t_start
        logger.info("=" * 60)
        logger.info(
            "Scan complete in %.1fs | %d findings | AI: %s (%.0f%%)",
            elapsed, len(all_findings), ai_label, ai_conf * 100,
        )
        logger.info("JSON report: %s", json_path)
        logger.info("HTML report: %s", html_path)

        # Save scan result JSON to scanner_results/
        results_path = self._project_dir / "scanner_results" / f"{result.scan_id[:8]}_result.json"
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

        return result

    # ─── Convenience methods ──────────────────────────────────

    def run_from_project_dir(self) -> Optional[ScanResult]:
        """
        Auto-detect all artifacts in the project directory and run a scan.
        Looks for:
          - project_dir/apk/*.apk
          - project_dir/reverse_engineering/  (JADX output)
          - project_dir/dynamic_analysis/     (AndroidManifest.xml)
          - project_dir/traffic/captured_flows.jsonl
          - project_dir/dynamic_analysis/frida_events.jsonl
        """
        apks = list((self._project_dir / "apk").glob("*.apk"))
        if not apks:
            logger.warning("No APK found in %s/apk/", self._project_dir)
            return None

        apk_path  = str(apks[0])
        jadx_dir  = self._project_dir / "reverse_engineering"
        manifest_p= jadx_dir / "resources" / "AndroidManifest.xml"
        traffic_p = self._project_dir / "traffic" / "captured_flows.jsonl"
        frida_p   = self._project_dir / "dynamic_analysis" / "frida_events.jsonl"

        traffic  = load_traffic_flows(traffic_p)
        frida_ev = load_frida_events(frida_p)

        # Auto-run RE pipeline if JADX output not present
        re_output_raw = None
        if not jadx_dir.exists() and RE_INTEGRATION and REService is not None:
            logger.info("JADX output not found — running RE pipeline on %s", apk_path)
            svc = REService(project_dir=self._project_dir)
            re_result = svc.analyze(apk_path, project_dir=self._project_dir / "reverse_engineering")
            jadx_dir  = re_result.jadx_output_dir or jadx_dir
            manifest_p= re_result.manifest_path   or manifest_p
            re_output_raw = re_result.to_scanner_dict()

        return self.run(
            apk_path=apk_path,
            re_output_raw=re_output_raw,
            jadx_dir=jadx_dir if jadx_dir.exists() else None,
            manifest_path=manifest_p if manifest_p.exists() else None,
            traffic_flows=traffic,
            frida_events=frida_ev,
        )

    def retrain_ai(self) -> None:
        """Retrain the AI model from accumulated samples."""
        logger.info("Retraining AI model...")
        self._ai_engine.retrain()
        logger.info("AI model retrained.")

    def list_past_scans(self) -> List[Dict[str, Any]]:
        """Return metadata for all past scans in this project."""
        results_dir = self._project_dir / "scanner_results"
        scans = []
        for path in sorted(results_dir.glob("*_result.json")):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                scans.append({
                    "scan_id":        data.get("scan_id"),
                    "apk_path":       data.get("apk_path"),
                    "scan_started":   data.get("scan_started"),
                    "ai_risk_label":  data.get("ai_risk_label"),
                    "findings_count": len(data.get("findings", [])),
                    "file":           str(path),
                })
            except (json.JSONDecodeError, OSError):
                pass
        return scans

    # ─── Internal helpers ─────────────────────────────────────

    @staticmethod
    def _guess_package(
        re_output: Optional[Any],
        raw: Optional[Dict[str, Any]]
    ) -> str:
        if re_output is not None and RE_INTEGRATION:
            return re_output.package_name or ""
        if raw:
            return raw.get("package_name", "")
        return ""


# ─────────────────────────────────────────────────────────────
# __init__ files
# ─────────────────────────────────────────────────────────────

def _write_inits() -> None:
    """Create __init__.py files for all scanner sub-packages."""
    base = Path(__file__).parent
    for sub in ["", "detectors", "engines", "reports", "utils"]:
        init = base / sub / "__init__.py" if sub else base / "__init__.py"
        if not init.exists():
            init.write_text('"""MobHound Scanner sub-package."""\n')


_write_inits()


# ─────────────────────────────────────────────────────────────
# CLI entry point  (python scanner_module.py <project_dir>)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, io
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    import argparse

    parser = argparse.ArgumentParser(description="MobHound Scanner Module")
    parser.add_argument("project_dir", help="MobHound project directory")
    parser.add_argument("--apk", help="Path to APK file (overrides auto-detect)")
    parser.add_argument("--jadx-dir", help="JADX output directory")
    parser.add_argument("--traffic", help="mitmproxy captured_flows.jsonl")
    parser.add_argument("--frida-events", help="Frida events JSONL file")
    parser.add_argument("--manifest", help="Path to AndroidManifest.xml")
    parser.add_argument("--retrain", action="store_true", help="Retrain AI model")
    args = parser.parse_args()

    scanner = ScannerModule(project_dir=Path(args.project_dir))

    if args.retrain:
        scanner.retrain_ai()
    elif args.apk or args.jadx_dir or args.manifest:
        apks = list((Path(args.project_dir) / "apk").glob("*.apk"))
        _apk = args.apk or (str(apks[0]) if apks else args.project_dir)
        result = scanner.run(
            apk_path=_apk,
            jadx_dir=Path(args.jadx_dir) if args.jadx_dir else None,
            manifest_path=Path(args.manifest) if args.manifest else None,
            traffic_flows=load_traffic_flows(Path(args.traffic)) if args.traffic else [],
            frida_events=load_frida_events(Path(args.frida_events)) if args.frida_events else [],
        )
        print(f"\n✅ Scan complete: {len(result.findings)} findings | Risk: {result.ai_risk_label}")
    else:
        result = scanner.run_from_project_dir()
        if result:
            print(f"\n✅ Scan complete: {len(result.findings)} findings | Risk: {result.ai_risk_label}")
