"""
MobHound - RE Backend Service
================================
Clean service layer that wraps APKReverseEngineeringPipeline.

This file provides:
  - REService  : main entry point (used by Scanner + UI)
  - REResult   : standardized output with to_scanner_dict()
  - Tool health checking
  - Config-aware paths
  - Proper error handling without crashing on missing tools

Usage:
    from re_backend_service import REService

    svc    = REService()
    result = svc.analyze("path/to/app.apk", project_dir=Path("projects/myapp"))
    print(result.package_name)
    scanner_data = result.to_scanner_dict()   # pass to ScannerModule
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("mobhound.re_service")

# Config integration
try:
    from config import config as _cfg
    _JADX_BIN    = _cfg.paths.jadx_bin
    _APKTOOL_BIN = _cfg.paths.apktool_bin
    _TOOLS_DIR   = Path(_cfg.paths.tools_dir)
except ImportError:
    _JADX_BIN    = ""
    _APKTOOL_BIN = ""
    _TOOLS_DIR   = Path(".mobhound_tools")

# Import the actual pipeline (backend module)
try:
    from reverse_engineering.apk_reverse_engineering_backend import (
        APKReverseEngineeringPipeline,
        APKReverseDependencyManager,
        StructuredREOutput,
        REFinding,
        run_apk_reverse_engineering_pipeline,
        ANDROGUARD_AVAILABLE,
    )
    RE_BACKEND_AVAILABLE = True
except ImportError as e:
    RE_BACKEND_AVAILABLE = False
    logger.warning("RE backend unavailable: %s", e)


# ─────────────────────────────────────────────────────────────
# Standardized result model
# ─────────────────────────────────────────────────────────────

@dataclass
class REFindingSimple:
    """Simplified finding for Scanner consumption."""
    finding_id:   str
    title:        str
    category:     str
    severity:     str           # Critical / High / Medium / Low / Info
    confidence:   str           # High / Medium / Low
    description:  str
    evidence:     Dict[str, Any] = field(default_factory=dict)
    affected_files: List[str]   = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class REResult:
    """
    Standardized RE analysis result.
    Compatible with both the Scanner module and the UI.
    """
    # Identity
    apk_path:       str = ""
    package_name:   str = ""
    app_name:       str = ""
    version_name:   str = ""
    version_code:   str = ""
    min_sdk:        str = ""
    target_sdk:     str = ""

    # Analysis outputs
    findings:          List[REFindingSimple] = field(default_factory=list)
    permissions:       List[str]             = field(default_factory=list)
    exported_components: List[str]           = field(default_factory=list)
    strings_of_interest: List[str]           = field(default_factory=list)
    native_libraries:  List[str]             = field(default_factory=list)
    obfuscation_score: float                 = 0.0
    is_obfuscated:     bool                  = False
    debuggable:        bool                  = False
    backup_enabled:    bool                  = True

    # Paths
    jadx_output_dir:   Optional[Path]        = None
    apktool_output_dir: Optional[Path]       = None
    manifest_path:     Optional[Path]        = None

    # Metadata
    scan_started:   str = ""
    scan_finished:  str = ""
    errors:         List[str] = field(default_factory=list)
    warnings:       List[str] = field(default_factory=list)
    raw_output:     Optional[Dict[str, Any]] = None

    def to_scanner_dict(self) -> Dict[str, Any]:
        """
        Returns a dict consumed by ScannerModule.run().
        Keys match what StaticEngine expects in manifest_data.
        """
        return {
            "apk_path":                  self.apk_path,
            "package_name":              self.package_name,
            "debuggable":                self.debuggable,
            "backup_enabled":            self.backup_enabled,
            "dangerous_permission_count": sum(
                1 for p in self.permissions
                if any(k in p for k in [
                    "READ_", "WRITE_", "RECORD_", "CAMERA",
                    "SEND_SMS", "RECEIVE_SMS", "ACCESS_FINE",
                    "PROCESS_OUTGOING", "USE_CREDENTIALS",
                ])
            ),
            "exported_component_count":  len(self.exported_components),
            "permissions":               self.permissions,
            "exported_components":       self.exported_components,
            "native_libraries":          self.native_libraries,
            "is_obfuscated":             self.is_obfuscated,
            "obfuscation_score":         self.obfuscation_score,
            "findings":                  [f.to_dict() for f in self.findings],
            "errors":                    self.errors,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["jadx_output_dir"]    = str(self.jadx_output_dir)    if self.jadx_output_dir    else None
        d["apktool_output_dir"] = str(self.apktool_output_dir) if self.apktool_output_dir else None
        d["manifest_path"]      = str(self.manifest_path)      if self.manifest_path       else None
        return d

    def save_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info("RE result saved → %s", path)


# ─────────────────────────────────────────────────────────────
# Tool health checker
# ─────────────────────────────────────────────────────────────

class REToolChecker:
    """Check and report availability of RE tools."""

    def __init__(self, tools_dir: Optional[Path] = None):
        self._tools_dir = tools_dir or _TOOLS_DIR

    def check_all(self) -> Dict[str, bool]:
        return {
            "jadx":    self._check_jadx(),
            "apktool": self._check_apktool(),
            "adb":     self._check_adb(),
        }

    def _check_jadx(self) -> bool:
        jadx = _JADX_BIN or self._find_tool("jadx")
        if not jadx:
            return False
        try:
            r = subprocess.run([jadx, "--version"], capture_output=True, timeout=5)
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _check_apktool(self) -> bool:
        apktool = _APKTOOL_BIN or self._find_tool("apktool")
        if not apktool:
            return False
        try:
            r = subprocess.run(["java", "-jar", apktool, "--version"],
                               capture_output=True, timeout=5)
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _check_adb(self) -> bool:
        try:
            r = subprocess.run(["adb", "version"], capture_output=True, timeout=5)
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _find_tool(self, name: str) -> Optional[str]:
        candidates = [
            self._tools_dir / "jadx" / "bin" / name,
            self._tools_dir / "jadx" / "bin" / f"{name}.bat",
            Path(name),
        ]
        for c in candidates:
            if c.exists():
                return str(c)
        return None


# ─────────────────────────────────────────────────────────────
# RE Service
# ─────────────────────────────────────────────────────────────

class REService:
    """
    Main reverse engineering service.
    Wraps the pipeline with clean error handling and Scanner integration.
    """

    def __init__(self, project_dir: Optional[Path] = None):
        self._project_dir  = project_dir
        self._tool_checker = REToolChecker()
        self._lock         = threading.Lock()

    # ─── Main analysis ────────────────────────────────────────

    def analyze(
        self,
        apk_path: str,
        project_dir: Optional[Path]          = None,
        runtime_feedback: Optional[Dict]     = None,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> REResult:
        """
        Run full RE analysis on an APK.

        Args:
            apk_path:          Path to the APK file.
            project_dir:       Where to store analysis output.
            runtime_feedback:  Frida/dynamic data to inject into pipeline.
            progress_callback: Called with (stage_name, percent) updates.

        Returns:
            REResult with all findings and paths for Scanner consumption.
        """
        start  = datetime.now()
        result = REResult(
            apk_path=apk_path,
            scan_started=start.isoformat(),
        )

        effective_dir = (
            project_dir or self._project_dir
            or Path("projects") / f"re_{start.strftime('%Y%m%d_%H%M%S')}"
        )
        effective_dir.mkdir(parents=True, exist_ok=True)

        if not Path(apk_path).exists():
            result.errors.append(f"APK not found: {apk_path}")
            return result

        if not RE_BACKEND_AVAILABLE:
            result.errors.append("RE backend (apk_reverse_engineering_backend) not available")
            return result

        try:
            with self._lock:
                if progress_callback:
                    progress_callback("Initializing tools", 5)

                tools_status = self._get_tools_status()

                if progress_callback:
                    progress_callback("Running RE pipeline", 15)

                pipeline = APKReverseEngineeringPipeline(
                    tools_status=tools_status,
                    project_dir=effective_dir,
                )
                raw_output: StructuredREOutput = pipeline.run(
                    apk_path=apk_path,
                    runtime_feedback=runtime_feedback or {},
                )

                if progress_callback:
                    progress_callback("Building result", 85)

                result = self._build_result(raw_output, apk_path, effective_dir)

                if progress_callback:
                    progress_callback("Saving result", 95)

                result_path = effective_dir / "re_result.json"
                result.save_json(result_path)

                if progress_callback:
                    progress_callback("Complete", 100)

        except Exception as e:
            logger.exception("RE analysis failed for %s", apk_path)
            result.errors.append(f"Pipeline error: {str(e)}")

        result.scan_finished = datetime.now().isoformat()
        return result

    def analyze_async(
        self,
        apk_path: str,
        on_complete: Callable[[REResult], None],
        on_error: Optional[Callable[[str], None]] = None,
        project_dir: Optional[Path] = None,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> threading.Thread:
        """
        Run analysis in a background thread.
        Returns the thread (already started).
        """
        def _worker():
            result = self.analyze(apk_path, project_dir, progress_callback=progress_callback)
            if result.errors and on_error:
                on_error("\n".join(result.errors))
            on_complete(result)

        t = threading.Thread(target=_worker, daemon=True, name="REServiceWorker")
        t.start()
        return t

    def check_tools(self) -> Dict[str, bool]:
        """Return tool availability dict."""
        return self._tool_checker.check_all()

    def install_tools(self, progress_callback: Optional[Callable[[str, int], None]] = None) -> Dict[str, bool]:
        """Install missing RE tools using the DependencyManager."""
        if not RE_BACKEND_AVAILABLE:
            return {}
        try:
            if progress_callback:
                progress_callback("Installing tools...", 10)
            mgr    = APKReverseDependencyManager()
            status = mgr.ensure_all_tools()
            if progress_callback:
                progress_callback("Done", 100)
            return status
        except Exception as e:
            logger.error("Tool install failed: %s", e)
            return {}

    # ─── Internal helpers ─────────────────────────────────────

    def _get_tools_status(self) -> Dict[str, Any]:
        if not RE_BACKEND_AVAILABLE:
            return {}
        try:
            mgr = APKReverseDependencyManager()
            return mgr.ensure_all_tools()
        except Exception as e:
            logger.warning("tools_status failed: %s — using empty dict", e)
            return {}

    def _build_result(
        self,
        raw: "StructuredREOutput",
        apk_path: str,
        project_dir: Path,
    ) -> REResult:
        """Convert raw StructuredREOutput → clean REResult."""
        meta = raw.metadata or {}
        result = REResult(
            apk_path=apk_path,
            package_name=meta.get("package_name", ""),
            app_name=meta.get("app_name", ""),
            version_name=meta.get("version_name", ""),
            version_code=str(meta.get("version_code", "")),
            min_sdk=str(meta.get("min_sdk", "")),
            target_sdk=str(meta.get("target_sdk", "")),
            debuggable=bool(meta.get("debuggable", False)),
            backup_enabled=bool(meta.get("backup_allowed", True)),
            errors=list(raw.errors or []),
            raw_output=raw.to_dict() if hasattr(raw, "to_dict") else {},
        )

        # Obfuscation
        obf = raw.obfuscation or {}
        result.is_obfuscated   = bool(obf.get("detected", False))
        result.obfuscation_score = float(obf.get("confidence", 0.0))

        # Permissions
        result.permissions = list(meta.get("permissions", []))

        # Exported components
        result.exported_components = list(meta.get("exported_components", []))

        # Native libs
        native = raw.native or {}
        result.native_libraries = list(native.get("libraries", []))

        # Convert findings
        result.findings = [
            self._convert_finding(f)
            for f in (raw.findings or [])
        ]

        # Paths — look for JADX and APKTool output dirs
        jadx_dir = project_dir / "jadx_output"
        if jadx_dir.exists():
            result.jadx_output_dir = jadx_dir

        apktool_dir = project_dir / "apktool_output"
        if apktool_dir.exists():
            result.apktool_output_dir = apktool_dir

        manifest_candidates = [
            project_dir / "jadx_output" / "resources" / "AndroidManifest.xml",
            project_dir / "apktool_output" / "AndroidManifest.xml",
        ]
        for m in manifest_candidates:
            if m.exists():
                result.manifest_path = m
                break

        return result

    @staticmethod
    def _convert_finding(f: "REFinding") -> REFindingSimple:
        return REFindingSimple(
            finding_id=getattr(f, "finding_id", ""),
            title=getattr(f, "title", ""),
            category=getattr(f, "category", ""),
            severity=getattr(f, "severity", "Info"),
            confidence=getattr(f, "confidence", "Low"),
            description=getattr(f, "explanation", ""),
            evidence=dict(getattr(f, "evidence", {})),
            affected_files=list(getattr(f, "execution_path", [])),
        )


# ─────────────────────────────────────────────────────────────
# Module-level singleton
# ─────────────────────────────────────────────────────────────

_default_service: Optional[REService] = None

def get_service(project_dir: Optional[Path] = None) -> REService:
    """Return (or create) the default REService singleton."""
    global _default_service
    if _default_service is None:
        _default_service = REService(project_dir=project_dir)
    return _default_service
