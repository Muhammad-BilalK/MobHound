import sys
import logging
import json
import random
import hashlib
import base64
import os
import platform
import shutil
import stat
import time
import zipfile
import urllib.request
import urllib.error
import traceback
import math
import subprocess
import threading
import re
from datetime import datetime
from dataclasses import dataclass, field, asdict
from xml.etree import ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

logger = logging.getLogger("mobhound.re_backend")
from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QPushButton, QStackedWidget, 
                               QListWidget, QListWidgetItem, QFrame, QTextEdit, 
                               QLineEdit, QComboBox, QCheckBox, QProgressBar, 
                               QTableWidget, QTableWidgetItem, QHeaderView, 
                               QTabWidget, QGroupBox, QSpinBox, QDoubleSpinBox,
                               QMessageBox, QFileDialog, QSplitter, QTreeWidget,
                               QTreeWidgetItem, QFormLayout, QScrollArea,
                               QDialog, QDialogButtonBox, QDateEdit, QTabBar,
                               QMenu, QToolBar, QStatusBar, QDockWidget,
                               QTextBrowser, QPlainTextEdit, QListView, QGridLayout,
                               QSizePolicy, QToolButton, QInputDialog,)
from PySide6.QtCore import Qt, QTimer, QSize, QThread, Signal, QSettings, QDir, QFileInfo, QRegularExpression, QRect, QPropertyAnimation, Property, QEasingCurve, QPointF                           
from PySide6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QPainter, QTextCharFormat, QSyntaxHighlighter, QAction, QPainterPath, QTextCursor

# Add Jinja2 import
try:
    from jinja2 import Environment, FileSystemLoader, Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    print("Jinja2 not available. Please install it with: pip install jinja2")

# Optional: Androguard for deep bytecode analysis
try:
    from androguard.misc import AnalyzeAPKz
    ANDROGUARD_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    ANDROGUARD_AVAILABLE = False
    AnalyzeAPK = None

# ============================================================================
# APK REVERSE ENGINEERING MODULE
# ============================================================================

APK_REVERSE_APP_NAME = "APK Reverse Engineering Studio"
APK_REVERSE_VERSION = "2.0.0"

# Config-aware paths (falls back to defaults if config unavailable)
try:
    from config import config as _re_cfg
    APK_REVERSE_APP_DIR   = Path(_re_cfg.paths.tools_dir).parent
    APK_REVERSE_TOOLS_DIR = Path(_re_cfg.paths.tools_dir)
except ImportError:
    APK_REVERSE_APP_DIR   = Path.home() / ".mobhound_apk_reverse"
    APK_REVERSE_TOOLS_DIR = APK_REVERSE_APP_DIR / "tools"

APK_REVERSE_CACHE_DIR  = APK_REVERSE_APP_DIR / "cache"
APK_REVERSE_LOGS_DIR   = APK_REVERSE_APP_DIR / "logs"
APK_REVERSE_OUTPUT_DIR = APK_REVERSE_APP_DIR / "projects"

# Tool versions
JADX_VERSION = "1.4.7"
APKTOOL_VERSION = "2.8.1"
DEX2JAR_VERSION = "2.1"

# URLs
JADX_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"
APKTOOL_URL = f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/apktool_{APKTOOL_VERSION}.jar"
DEX2JAR_URL = f"https://github.com/pxb1988/dex2jar/releases/download/v{DEX2JAR_VERSION}/dex-tools-{DEX2JAR_VERSION}.zip"

# ============================================================================
# ADVANCED REVERSE ENGINEERING PIPELINE (Standalone, Modular)
# ============================================================================

@dataclass
class RENode:
    """A generic node used in structural, control-flow, or data-flow graphs."""
    node_id: str
    node_type: str
    label: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class REEdge:
    """A typed edge connecting RENodes to express execution or data relationships."""
    src: str
    dst: str
    edge_type: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionStep:
    """One step in an execution path, with reasoning and confidence."""
    step_id: str
    description: str
    method: Optional[str] = None
    component: Optional[str] = None
    condition: Optional[str] = None
    confidence: float = 0.5
    runtime_required: bool = False


@dataclass
class ExecutionPath:
    """An ordered, analyst-friendly execution path."""
    path_id: str
    steps: List[ExecutionStep] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    exploitability_reasoning: str = ""


@dataclass
class DataFlowExplanation:
    """Explains how data moves across methods/components."""
    flow_id: str
    source: str
    sink: str
    transformations: List[str] = field(default_factory=list)
    crosses_components: bool = False
    async_edges: List[str] = field(default_factory=list)
    confidence: float = 0.5
    runtime_required: bool = False


@dataclass
class RuntimeDependency:
    """Marks unresolved items that require runtime feedback."""
    dependency_id: str
    dependency_type: str  # "string", "class", "method", "field"
    description: str
    suggested_hook: Optional[str] = None


@dataclass
class NativeLinkageNote:
    """Notes about Java<->native linkages and native logic relevance."""
    note_id: str
    jni_method: Optional[str]
    so_name: Optional[str]
    security_relevance: str
    confidence: float = 0.5


@dataclass
class REFinding:
    """A structured finding with reasoning and confidence."""
    finding_id: str
    title: str
    summary: str
    security_relevance: str
    confidence: float
    runtime_required: bool


@dataclass
class StructuredREOutput:
    """Final structured output for analyst consumption."""
    apk_path: str
    package_name: Optional[str]
    execution_paths: List[ExecutionPath] = field(default_factory=list)
    data_flows: List[DataFlowExplanation] = field(default_factory=list)
    runtime_dependencies: List[RuntimeDependency] = field(default_factory=list)
    native_linkage_notes: List[NativeLinkageNote] = field(default_factory=list)
    findings: List[REFinding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class REPipelineContext:
    """Shared context between stages to keep a deterministic, explainable pipeline."""
    apk_path: str
    work_dir: Path
    output_dir: Path
    jadx_path: Optional[str] = None
    apktool_jar: Optional[str] = None
    androguard_enabled: bool = False
    dex_files: List[Path] = field(default_factory=list)
    split_apks: List[Path] = field(default_factory=list)
    package_name: Optional[str] = None
    manifest_xml: Optional[ET.Element] = None
    kotlin_metadata: Dict[str, Any] = field(default_factory=dict)
    component_graph: Dict[str, List[str]] = field(default_factory=dict)
    call_graph: Dict[str, List[str]] = field(default_factory=dict)
    cfg_map: Dict[str, Any] = field(default_factory=dict)
    data_flow_graph: Dict[str, List[str]] = field(default_factory=dict)
    metadata_apktool_dir: Optional[Path] = None
    metadata_jadx_dir: Optional[Path] = None
    runtime_values: Dict[str, Any] = field(default_factory=dict)
    unresolved_refs: List[RuntimeDependency] = field(default_factory=list)
    native_symbols: List[NativeLinkageNote] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)

    def log(self, message: str):
        """Centralized logging to keep pipeline transparency."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")


class REPipelineStage:
    """Base class for each pipeline stage."""

    stage_name = "BaseStage"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """Execute stage logic and return updated context."""
        raise NotImplementedError


class APKNormalizationStage(REPipelineStage):
    stage_name = "APK Normalization"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """
        Normalize the APK inputs so downstream stages always operate on deterministic files.
        This is required to ensure consistent hashes, parsing order, and reliable diffs.
        """
        context.log("Normalizing APK inputs (multi-DEX, splits, deterministic order).")
        apk_path = Path(context.apk_path)
        if not apk_path.exists():
            context.log("APK path does not exist, cannot normalize.")
            return context

        context.work_dir.mkdir(parents=True, exist_ok=True)
        context.output_dir.mkdir(parents=True, exist_ok=True)

        # Detect split APKs (base + config splits) if provided as a directory.
        if apk_path.is_dir():
            split_apks = sorted(apk_path.glob("*.apk"))
            context.split_apks = split_apks
            if split_apks:
                context.log(f"Detected {len(split_apks)} split APKs.")
        else:
            context.split_apks = [apk_path]

        # Extract dex file list deterministically by filename.
        dex_files = []
        try:
            with zipfile.ZipFile(context.split_apks[0], "r") as zip_ref:
                for name in sorted(zip_ref.namelist()):
                    if name.endswith(".dex"):
                        dex_path = context.work_dir / Path(name).name
                        with open(dex_path, "wb") as f:
                            f.write(zip_ref.read(name))
                        dex_files.append(dex_path)
            context.dex_files = dex_files
            context.log(f"Collected {len(dex_files)} DEX files.")
        except Exception as exc:
            context.log(f"DEX extraction failed: {exc}")

        # Kotlin metadata awareness: detect presence of kotlin.Metadata annotation.
        context.kotlin_metadata["present"] = False
        for dex_file in context.dex_files:
            if "kotlin" in dex_file.name.lower():
                context.kotlin_metadata["present"] = True
                break

        return context


class CodeReconstructionStage(REPipelineStage):
    stage_name = "Code Reconstruction"

    def _run_apktool(self, context: REPipelineContext) -> Optional[Path]:
        """Run apktool to decode resources and smali when available."""
        if not context.apktool_jar:
            context.log("apktool jar not configured; skipping apktool decode.")
            return None
        out_dir = context.work_dir / "apktool_out"
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = ["java", "-jar", context.apktool_jar, "d", context.apk_path, "-o", str(out_dir), "-f"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            context.log("apktool decode completed.")
            return out_dir
        except Exception as exc:
            context.log(f"apktool decode failed: {exc}")
            return None

    def _run_jadx(self, context: REPipelineContext) -> Optional[Path]:
        """Run jadx to reconstruct Java/Kotlin source for analyst usability."""
        if not context.jadx_path:
            context.log("jadx not configured; skipping decompilation.")
            return None
        out_dir = context.work_dir / "jadx_out"
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = [context.jadx_path, "-d", str(out_dir), context.apk_path]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            context.log("jadx decompilation completed.")
            return out_dir
        except Exception as exc:
            context.log(f"jadx decompilation failed: {exc}")
            return None

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """
        Reconstruct code into multiple representations.
        We do this to give both smali-level fidelity and Java/Kotlin readability.
        """
        context.log("Reconstructing code with apktool and jadx.")
        context.metadata_apktool_dir = self._run_apktool(context)
        context.metadata_jadx_dir = self._run_jadx(context)
        return context


class StructuralGraphsStage(REPipelineStage):
    stage_name = "Structural Graphs"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """
        Build inter-component graph and entry points from manifest.
        This keeps execution context anchored to Android lifecycle.
        """
        context.log("Building structural graphs (components, entry points).")
        component_graph: Dict[str, List[str]] = defaultdict(list)
        try:
            with zipfile.ZipFile(context.apk_path, "r") as zip_ref:
                manifest_data = zip_ref.read("AndroidManifest.xml")
                # Note: This is a placeholder. Proper AXML parsing required.
                context.log("Manifest extracted for component discovery.")
                # Without AXML parser, we keep placeholders to avoid guessing.
        except Exception as exc:
            context.log(f"Manifest extraction failed: {exc}")

        context.component_graph = dict(component_graph)
        return context


class ControlFlowAnalysisStage(REPipelineStage):
    stage_name = "Control Flow Analysis"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """
        Construct per-method CFGs and reachability tags.
        We use androguard when available to avoid regex-only inference.
        """
        context.log("Running control flow analysis.")
        if not context.androguard_enabled or not ANDROGUARD_AVAILABLE:
            context.log("Androguard not available; CFG analysis deferred.")
            return context

        try:
            for dex_file in context.dex_files:
                apk = AnalyzeAPK(context.apk_path)
                a, d, dx = apk
                for method in d.get_methods():
                    try:
                        cfg = method.get_method().get_basic_blocks()
                        context.cfg_map[str(method)] = cfg
                    except Exception:
                        continue
            context.log(f"CFGs built for {len(context.cfg_map)} methods.")
        except Exception as exc:
            context.log(f"CFG analysis failed: {exc}")
        return context


class DataFlowSemanticsStage(REPipelineStage):
    stage_name = "Data Flow & Semantics"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """
        Build semantic data-flow relationships, including async edges.
        We avoid over-claiming when full resolution is not possible.
        """
        context.log("Building data flow and semantic relationships.")
        context.data_flow_graph = {}
        # Placeholder for taint propagation engine.
        return context


class ObfuscationReflectionStage(REPipelineStage):
    stage_name = "Obfuscation & Reflection Handling"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """
        Detect obfuscation/crypto patterns and unresolved reflection targets.
        We mark runtime dependencies instead of guessing.
        """
        context.log("Scanning for obfuscation patterns and reflection usage.")
        # Placeholder for encrypted string detection and reflection analysis.
        context.unresolved_refs.append(
            RuntimeDependency(
                dependency_id="unresolved_reflection_1",
                dependency_type="class",
                description="Reflection target unresolved statically",
                suggested_hook="frida: hook Class.forName and record arguments"
            )
        )
        return context


class NativeAwarenessStage(REPipelineStage):
    stage_name = "Native Awareness"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """
        Map JNI entry points and flag native logic that affects security.
        This ties native execution to Java entry points.
        """
        context.log("Analyzing native libraries for JNI and security logic.")
        # Placeholder for .so fingerprinting and JNI mapping.
        context.native_symbols.append(
            NativeLinkageNote(
                note_id="native_crypto_1",
                jni_method=None,
                so_name=None,
                security_relevance="Native crypto usage detected (placeholder)",
                confidence=0.3
            )
        )
        return context


class RuntimeFeedbackIntegrationStage(REPipelineStage):
    stage_name = "Runtime Feedback Integration"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """
        Integrate runtime-resolved values and re-evaluate affected graphs.
        This is designed for frida-derived data injected post-analysis.
        """
        context.log("Integrating runtime feedback into static model.")
        # Example: update unresolved refs if runtime values are provided.
        resolved = []
        for dep in context.unresolved_refs:
            key = dep.description
            if key in context.runtime_values:
                resolved.append(dep)
        for dep in resolved:
            context.unresolved_refs.remove(dep)
            context.log(f"Resolved runtime dependency: {dep.dependency_id}")
        return context


class ExploitPathConstructionStage(REPipelineStage):
    stage_name = "Exploit Path Construction"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """
        Combine weak points into execution chains with preconditions.
        This explains exploitability rather than asserting it.
        """
        context.log("Constructing exploit paths from control/data flow.")
        # Placeholder: build empty paths until full analysis is available.
        return context


class StructuredOutputStage(REPipelineStage):
    stage_name = "Structured RE Output"

    def run(self, context: REPipelineContext) -> REPipelineContext:
        """No-op stage; output is compiled in pipeline finalize step."""
        context.log("Preparing structured RE output.")
        return context


class APKReverseEngineeringPipeline:
    """
    Orchestrates the RE pipeline stages to provide transparent,
    analyst-grade structured output without guessing.
    """

    def __init__(self, apk_path: str, work_dir: Path, output_dir: Path):
        self.context = REPipelineContext(
            apk_path=apk_path,
            work_dir=work_dir,
            output_dir=output_dir,
            androguard_enabled=ANDROGUARD_AVAILABLE
        )
        self.stages: List[REPipelineStage] = [
            APKNormalizationStage(),
            CodeReconstructionStage(),
            StructuralGraphsStage(),
            ControlFlowAnalysisStage(),
            DataFlowSemanticsStage(),
            ObfuscationReflectionStage(),
            NativeAwarenessStage(),
            RuntimeFeedbackIntegrationStage(),
            ExploitPathConstructionStage(),
            StructuredOutputStage(),
        ]

    def configure_tools(self, jadx_path: Optional[str], apktool_jar: Optional[str]):
        """Configure tool locations to ensure the pipeline uses explicit toolchain."""
        self.context.jadx_path = jadx_path
        self.context.apktool_jar = apktool_jar

    def provide_runtime_feedback(self, runtime_values: Dict[str, Any]):
        """Allow external runtime values to be injected before or after run."""
        self.context.runtime_values.update(runtime_values or {})

    def run(self) -> StructuredREOutput:
        """Run the pipeline end-to-end and produce structured output."""
        for stage in self.stages:
            self.context.log(f"Stage start: {stage.stage_name}")
            self.context = stage.run(self.context)
            self.context.log(f"Stage end: {stage.stage_name}")

        output = StructuredREOutput(
            apk_path=self.context.apk_path,
            package_name=self.context.package_name,
            runtime_dependencies=list(self.context.unresolved_refs),
            native_linkage_notes=list(self.context.native_symbols),
            metadata={
                "logs": list(self.context.logs),
                "kotlin_metadata": dict(self.context.kotlin_metadata),
                "component_graph": dict(self.context.component_graph),
                "call_graph": dict(self.context.call_graph),
            }
        )
        return output

def _init_app_directories() -> None:
    """Create app directories on demand, not on import."""
    for directory in [APK_REVERSE_APP_DIR, APK_REVERSE_TOOLS_DIR,
                      APK_REVERSE_CACHE_DIR, APK_REVERSE_LOGS_DIR, APK_REVERSE_OUTPUT_DIR]:
        directory.mkdir(parents=True, exist_ok=True)


class APKReverseEngineeringPipeline:
    """Why: Orchestrates stages in a transparent, repeatable order."""

    def __init__(self, tools_status: Dict[str, Any], project_dir: Optional[Path] = None):
        self.tools_status = tools_status
        self.project_dir = project_dir or (APK_REVERSE_OUTPUT_DIR / f"re_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.stages: List[REPipelineStage] = [
            APKNormalizationStage(),
            CodeReconstructionStage(),
            StructuralGraphsStage(),
            ControlFlowStage(),
            DataFlowSemanticsStage(),
            LogicAwareSecurityStage(),
            ObfuscationReflectionStage(),
            NativeAwarenessStage(),
            RuntimeFeedbackStage(),
            ExploitPathConstructionStage(),
            StructuredOutputStage(),
        ]

    def run(self, apk_path: str, runtime_feedback: Optional[Dict[str, Any]] = None) -> StructuredREOutput:
        output = StructuredREOutput()
        ctx = REPipelineContext(
            apk_path=apk_path,
            tools_status=self.tools_status,
            project_dir=self.project_dir,
            runtime_feedback=runtime_feedback or {},
        )

        output.metadata = {
            "app_name": APK_REVERSE_APP_NAME,
            "version": APK_REVERSE_VERSION,
            "apk_path": apk_path,
            "timestamp": datetime.now().isoformat(),
            "androguard_available": ANDROGUARD_AVAILABLE,
        }

        for stage in self.stages:
            result = stage.run(ctx)
            output.stages.append(result)
            if not result.success:
                output.errors.extend(result.errors)

        # Build findings from artifacts
        output.execution_paths = ctx.artifacts.get("exploit_paths", {}).get("paths", [])
        output.data_flows = ctx.artifacts.get("data_flow", {}).get("taint_paths", [])
        output.obfuscation = ctx.artifacts.get("obfuscation", {})
        output.native = ctx.artifacts.get("native", {})
        output.runtime_feedback = ctx.runtime_feedback

        output.findings = self._build_findings(ctx)

        return output

    def _build_findings(self, ctx: REPipelineContext) -> List[REFinding]:
        findings: List[REFinding] = []

        for idx, path in enumerate(ctx.artifacts.get("exploit_paths", {}).get("paths", []), start=1):
            findings.append(REFinding(
                finding_id=f"FLOW-{idx:03d}",
                title="Source-to-sink execution chain",
                category="Data Flow",
                severity="Medium",
                confidence="Medium",
                explanation="A data flow from sensitive source to sink was observed through the call graph.",
                execution_path=path.get("execution_chain", []),
                data_flow=path.get("execution_chain", []),
                runtime_dependencies=[p for p in path.get("preconditions", []) if "runtime" in p.lower()],
                native_linkage=[l.get("method") for l in ctx.artifacts.get("native", {}).get("jni_methods", [])],
                evidence={"sink": path.get("sink")},
                preconditions=path.get("preconditions", [])
            ))

        for refl in ctx.artifacts.get("obfuscation", {}).get("reflection", []):
            findings.append(REFinding(
                finding_id=f"REFL-{len(findings)+1:03d}",
                title="Reflection requires runtime resolution",
                category="Obfuscation/Reflection",
                severity="Info",
                confidence="Low",
                explanation="Reflection call detected; target resolution depends on runtime values.",
                execution_path=[refl.get("location", "")],
                runtime_dependencies=["reflection_target"],
                evidence=refl
            ))

        return findings


def run_apk_reverse_engineering_pipeline(apk_path: str,
                                         tools_status: Optional[Dict[str, Any]] = None,
                                         runtime_feedback: Optional[Dict[str, Any]] = None) -> StructuredREOutput:
    """Why: Provides a single, explicit entry point for the RE pipeline."""
    if tools_status is None:
        tools_status = APKReverseDependencyManager().ensure_all_tools()
    pipeline = APKReverseEngineeringPipeline(tools_status=tools_status)
    return pipeline.run(apk_path=apk_path, runtime_feedback=runtime_feedback)

# ============================================================================
# END OF APK REVERSE ENGINEERING MODULE


class APKReverseDependencyManager:
    """Completely silent dependency installer and manager"""
    
    def __init__(self):
        self.system = platform.system()
        self.is_windows = self.system == "Windows"
        self.is_linux = self.system == "Linux"
        self.is_mac = self.system == "Darwin"
        self.log_file = APK_REVERSE_LOGS_DIR / "install.log"
        
    def log(self, message: str, level: str = "INFO"):
        """Log messages silently"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
    
    def download_with_progress(self, url: str, dest: Path) -> Tuple[bool, str]:
        """Download file with progress callback"""
        try:
            temp_file = dest.with_suffix('.downloading')
            
            # Set headers
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/octet-stream"
            }
            
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=180) as response:
                total_size = int(response.headers.get('content-length', 0))
                
                # Download in chunks
                chunk_size = 8192
                downloaded = 0
                
                with open(temp_file, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
            
            # Rename to final file
            if temp_file.exists():
                temp_file.rename(dest)
            
            return True, "Downloaded successfully"
            
        except urllib.error.URLError as e:
            return False, f"Network error: {str(e)}"
        except Exception as e:
            return False, f"Download failed: {str(e)}"
    
    def install_jadx_silently(self) -> Tuple[bool, str]:
        """Install JADX completely silently"""
        try:
            jadx_zip = APK_REVERSE_TOOLS_DIR / f"jadx-{JADX_VERSION}.zip"
            jadx_dir = APK_REVERSE_TOOLS_DIR / "jadx"
            
            # Download if needed
            if not jadx_zip.exists():
                self.log("Downloading JADX...")
                success, msg = self.download_with_progress(JADX_URL, jadx_zip)
                if not success:
                    return False, msg
            
            # Extract
            self.log("Extracting JADX...")
            with zipfile.ZipFile(jadx_zip, 'r') as zip_ref:
                # Clear existing directory
                if jadx_dir.exists():
                    shutil.rmtree(jadx_dir, ignore_errors=True)
                zip_ref.extractall(jadx_dir)
            
            # Find and set up executable
            for pattern in ["jadx", "jadx.bat", "jadx.sh", "jadx-gui*"]:
                for path in jadx_dir.rglob(pattern):
                    if path.is_file():
                        # Make executable on Unix systems
                        if not self.is_windows:
                            try:
                                path.chmod(path.stat().st_mode | stat.S_IEXEC)
                            except:
                                pass
                        return True, str(path)
            
            return False, "JADX executable not found"
            
        except Exception as e:
            return False, f"JADX installation failed: {str(e)}"
    
    def install_apktool_silently(self) -> Tuple[bool, str]:
        """Install apktool completely silently"""
        try:
            apktool_jar = APK_REVERSE_TOOLS_DIR / "apktool" / "apktool.jar"
            apktool_dir = apktool_jar.parent
            
            # Create directory
            apktool_dir.mkdir(parents=True, exist_ok=True)
            
            # Download if needed
            if not apktool_jar.exists():
                self.log("Downloading apktool...")
                success, msg = self.download_with_progress(APKTOOL_URL, apktool_jar)
                if not success:
                    return False, msg
            
            return True, str(apktool_jar)
            
        except Exception as e:
            return False, f"apktool installation failed: {str(e)}"
    
    def install_dex2jar_silently(self) -> Tuple[bool, str]:
        """Install dex2jar completely silently"""
        try:
            dex2jar_zip = APK_REVERSE_TOOLS_DIR / f"dex2jar-{DEX2JAR_VERSION}.zip"
            dex2jar_dir = APK_REVERSE_TOOLS_DIR / "dex2jar"
            
            # Download if needed
            if not dex2jar_zip.exists():
                self.log("Downloading dex2jar...")
                success, msg = self.download_with_progress(DEX2JAR_URL, dex2jar_zip)
                if not success:
                    return False, msg
            
            # Extract
            self.log("Extracting dex2jar...")
            with zipfile.ZipFile(dex2jar_zip, 'r') as zip_ref:
                # Clear existing directory
                if dex2jar_dir.exists():
                    shutil.rmtree(dex2jar_dir, ignore_errors=True)
                zip_ref.extractall(dex2jar_dir)
            
            # Find d2j-dex2jar script
            for pattern in ["d2j-dex2jar.sh", "d2j-dex2jar.bat", "dex2jar"]:
                for path in dex2jar_dir.rglob(pattern):
                    if path.is_file():
                        # Make executable on Unix systems
                        if not self.is_windows:
                            try:
                                path.chmod(path.stat().st_mode | stat.S_IEXEC)
                            except:
                                pass
                        return True, str(path)
            
            return False, "dex2jar executable not found"
            
        except Exception as e:
            return False, f"dex2jar installation failed: {str(e)}"
    
    def check_java(self) -> Tuple[bool, str]:
        """Check if Java is available"""
        try:
            # Try multiple Java commands
            java_commands = ["java", "java.exe"]
            
            for cmd in java_commands:
                try:
                    result = subprocess.run(
                        [cmd, "-version"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        # Parse Java version
                        lines = result.stderr.split('\n')
                        version_line = lines[0] if lines else ""
                        return True, version_line
                except:
                    continue
            
            return False, "Java not found"
            
        except Exception as e:
            return False, f"Java check failed: {str(e)}"
    
    def ensure_all_tools(self) -> Dict[str, Any]:
        """Ensure all tools are available (install if missing)"""
        tools_status = {
            "java": {"available": False, "path": None, "version": None, "error": None},
            "jadx": {"available": False, "path": None, "error": None},
            "apktool": {"available": False, "path": None, "error": None},
            "dex2jar": {"available": False, "path": None, "error": None},
            "all_ready": False
        }
        
        try:
            # Check/Install Java
            self.log("Checking Java...")
            java_ok, java_info = self.check_java()
            tools_status["java"]["available"] = java_ok
            tools_status["java"]["version"] = java_info if java_ok else None
            tools_status["java"]["error"] = None if java_ok else java_info
            
            # Check/Install JADX
            self.log("Checking JADX...")
            jadx_path = self.find_tool("jadx")
            if jadx_path:
                tools_status["jadx"]["available"] = True
                tools_status["jadx"]["path"] = jadx_path
            else:
                self.log("JADX not found, installing silently...")
                jadx_ok, jadx_result = self.install_jadx_silently()
                tools_status["jadx"]["available"] = jadx_ok
                tools_status["jadx"]["path"] = jadx_result if jadx_ok else None
                tools_status["jadx"]["error"] = None if jadx_ok else jadx_result
            
            # Check/Install apktool
            self.log("Checking apktool...")
            apktool_jar = APK_REVERSE_TOOLS_DIR / "apktool" / "apktool.jar"
            if apktool_jar.exists():
                tools_status["apktool"]["available"] = True
                tools_status["apktool"]["path"] = str(apktool_jar)
            else:
                self.log("apktool not found, installing silently...")
                apktool_ok, apktool_result = self.install_apktool_silently()
                tools_status["apktool"]["available"] = apktool_ok
                tools_status["apktool"]["path"] = apktool_result if apktool_ok else None
                tools_status["apktool"]["error"] = None if apktool_ok else apktool_result
            
            # Check/Install dex2jar
            self.log("Checking dex2jar...")
            dex2jar_path = self.find_tool("dex2jar")
            if dex2jar_path:
                tools_status["dex2jar"]["available"] = True
                tools_status["dex2jar"]["path"] = dex2jar_path
            else:
                self.log("dex2jar not found, installing silently...")
                dex2jar_ok, dex2jar_result = self.install_dex2jar_silently()
                tools_status["dex2jar"]["available"] = dex2jar_ok
                tools_status["dex2jar"]["path"] = dex2jar_result if dex2jar_ok else None
                tools_status["dex2jar"]["error"] = None if dex2jar_ok else dex2jar_result
            
            # Determine if all essential tools are ready
            essential_tools = tools_status["java"]["available"] and \
                            tools_status["jadx"]["available"] and \
                            tools_status["apktool"]["available"]
            
            tools_status["all_ready"] = essential_tools
            
            self.log(f"Tool check complete. All ready: {essential_tools}")
            return tools_status
            
        except Exception as e:
            self.log(f"Tool check failed: {str(e)}", "ERROR")
            tools_status["all_ready"] = False
            return tools_status
    
    def find_tool(self, tool_name: str) -> Optional[str]:
        """Find existing tool installation"""
        if tool_name == "apktool":
            apktool_jar = APK_REVERSE_TOOLS_DIR / "apktool" / "apktool.jar"
            return str(apktool_jar) if apktool_jar.exists() else None
        
        tool_dirs = {
            "jadx": APK_REVERSE_TOOLS_DIR / "jadx",
            "dex2jar": APK_REVERSE_TOOLS_DIR / "dex2jar"
        }
        
        if tool_name in tool_dirs:
            tool_dir = tool_dirs[tool_name]
            if tool_dir.exists():
                # Look for common executable patterns
                patterns = {
                    "jadx": ["jadx", "jadx.bat", "jadx.sh"],
                    "dex2jar": ["d2j-dex2jar.sh", "d2j-dex2jar.bat", "dex2jar"]
                }
                
                if tool_name in patterns:
                    for pattern in patterns[tool_name]:
                        for path in tool_dir.rglob(pattern):
                            if path.is_file():
                                return str(path)
        
        return None

class APKAnalyzer:
    """Pure Python APK analyzer without external dependencies"""
    
    def __init__(self):
        self.analysis_cache = {}
    
    def get_apk_info(self, apk_path: str) -> Dict[str, Any]:
        """Get basic APK information"""
        info = {
            "file_name": os.path.basename(apk_path),
            "file_path": apk_path,
            "file_size": 0,
            "md5_hash": "",
            "sha256_hash": "",
            "package_name": "unknown",
            "version_name": "1.0",
            "version_code": "1",
            "min_sdk": "21",
            "target_sdk": "30",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "certificates": [],
            "files": [],
            "file_types": {},
            "dex_files": [],
            "native_libs": [],
            "resources": [],
            "images": [],
            "raw_files": []
        }
        
        try:
            # Get file stats
            stats = os.stat(apk_path)
            info["file_size"] = stats.st_size
            info["created"] = datetime.fromtimestamp(stats.st_ctime).isoformat()
            info["modified"] = datetime.fromtimestamp(stats.st_mtime).isoformat()
            
            # Calculate hashes
            info["md5_hash"] = self.calculate_hash(apk_path, "md5")
            info["sha256_hash"] = self.calculate_hash(apk_path, "sha256")
            
            # Analyze APK contents
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Get all files
                info["files"] = apk_zip.namelist()
                
                # Categorize files
                for file_name in info["files"]:
                    ext = os.path.splitext(file_name)[1].lower()
                    
                    # Count file types
                    info["file_types"][ext] = info["file_types"].get(ext, 0) + 1
                    
                    # Categorize
                    if file_name.endswith('.dex'):
                        info["dex_files"].append(file_name)
                    elif file_name.endswith('.so'):
                        info["native_libs"].append(file_name)
                    elif file_name.endswith('.xml'):
                        info["resources"].append(file_name)
                    elif any(file_name.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.webp']):
                        info["images"].append(file_name)
                    elif file_name.startswith('META-INF/'):
                        if file_name.endswith(('.RSA', '.DSA', '.EC')):
                            info["certificates"].append(file_name)
                    else:
                        info["raw_files"].append(file_name)
                
                # Try to read AndroidManifest.xml
                if 'AndroidManifest.xml' in info["files"]:
                    try:
                        with apk_zip.open('AndroidManifest.xml') as f:
                            manifest_data = f.read()
                            # Basic parsing attempt
                            manifest_text = manifest_data.decode('utf-8', errors='ignore')
                            if '<manifest' in manifest_text.lower():
                                info["has_readable_manifest"] = True
                    except:
                        info["has_readable_manifest"] = False
            
            # Count statistics
            info["total_files"] = len(info["files"])
            info["dex_count"] = len(info["dex_files"])
            info["native_lib_count"] = len(info["native_libs"])
            info["resource_count"] = len(info["resources"])
            info["image_count"] = len(info["images"])
            info["certificate_count"] = len(info["certificates"])
            
            # Get APK icon if exists
            info["icon_path"] = self.extract_apk_icon(apk_path)
            
            return info
            
        except Exception as e:
            info["error"] = str(e)
            return info
    
    def calculate_hash(self, file_path: str, algorithm: str = "sha256") -> str:
        """Calculate file hash"""
        hash_func = getattr(hashlib, algorithm)()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def extract_apk_icon(self, apk_path: str) -> Optional[str]:
        """Extract APK icon if available"""
        try:
            icon_candidates = [
                'res/mipmap-hdpi/ic_launcher.png',
                'res/mipmap-mdpi/ic_launcher.png',
                'res/mipmap-xhdpi/ic_launcher.png',
                'res/mipmap-xxhdpi/ic_launcher.png',
                'res/mipmap-xxxhdpi/ic_launcher.png',
                'res/drawable-hdpi/ic_launcher.png',
                'res/drawable-mdpi/ic_launcher.png',
                'res/drawable/ic_launcher.png',
                'resources.arsc'
            ]
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for icon_path in icon_candidates:
                    if icon_path in apk_zip.namelist():
                        # Extract to cache
                        cache_path = APK_REVERSE_CACHE_DIR / f"icon_{os.path.basename(apk_path)}.png"
                        with apk_zip.open(icon_path) as source, open(cache_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                        return str(cache_path)
            
            return None
            
        except:
            return None

class APKToolCheckThread(QThread):
    """Thread for checking and installing tools"""
    progress_update = Signal(int, str)
    result_ready = Signal(dict)
    
    def __init__(self, dependency_manager):
        super().__init__()
        self.dependency_manager = dependency_manager
    
    def run(self):
        try:
            self.progress_update.emit(10, "Initializing...")
            time.sleep(0.5)
            
            self.progress_update.emit(20, "Checking Java...")
            time.sleep(0.3)
            
            self.progress_update.emit(40, "Checking Resources...")
            time.sleep(0.5)
            
            self.progress_update.emit(60, "Verifying installations...")
            time.sleep(0.5)
            
            # Get tool status
            tools_status = self.dependency_manager.ensure_all_tools()
            
            self.progress_update.emit(100, "Ready")
            self.result_ready.emit(tools_status)
            
        except Exception as e:
            self.result_ready.emit({"error": str(e)})

class APKAnalysisThread(QThread):
    """Thread for APK analysis"""
    progress_update = Signal(int, str, dict)
    result_ready = Signal(dict)
    error_signal = Signal(str)
    
    def __init__(self, apk_path: str, analyzer: APKAnalyzer):
        super().__init__()
        self.apk_path = apk_path
        self.analyzer = analyzer
    
    def run(self):
        try:
            self.progress_update.emit(10, "Loading APK...", {})
            time.sleep(0.1)
            
            self.progress_update.emit(30, "Analyzing structure...", {})
            apk_info = self.analyzer.get_apk_info(self.apk_path)
            
            self.progress_update.emit(60, "Processing files...", apk_info)
            time.sleep(0.2)
            
            self.progress_update.emit(90, "Finalizing...", apk_info)
            time.sleep(0.1)
            
            self.progress_update.emit(100, "Analysis complete", apk_info)
            self.result_ready.emit(apk_info)
            
        except Exception as e:
            self.error_signal.emit(str(e))

class APKDecompilationThread(QThread):
    """Thread for APK decompilation"""
    progress_update = Signal(int, str)
    result_ready = Signal(bool, str, dict)
    
    def __init__(self, apk_path: str, tools_status: dict, output_dir: Path):
        super().__init__()
        self.apk_path = apk_path
        self.tools_status = tools_status
        self.output_dir = output_dir
        self.apk_name = Path(apk_path).stem
    
    def run(self):
        try:
            results = {
                "jadx_output": None,
                "apktool_output": None,
                "dex2jar_output": None,
                "tool_runs": {},
                "validation": {},
                "success": False
            }
            
            # Create project directory
            project_dir = self.output_dir / self.apk_name
            project_dir.mkdir(parents=True, exist_ok=True)
            
            self.progress_update.emit(10, "Creating project...")
            
            # Decompile with JADX
            if self.tools_status.get("jadx", {}).get("available"):
                self.progress_update.emit(30, "Decompiling...")
                jadx_path = self.tools_status["jadx"]["path"]
                jadx_output = project_dir / "jadx_source"
                
                try:
                    if platform.system() == "Windows":
                        cmd = f'"{jadx_path}" -d "{jadx_output}" "{self.apk_path}"'
                        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=300)
                        results["tool_runs"]["jadx"] = self._command_result(result)
                        if result.returncode != 0:
                            logger.warning("JADX error: %s", result.stderr.decode(errors="replace"))
                    else:
                        result = subprocess.run([jadx_path, "-d", str(jadx_output), self.apk_path],
                                     capture_output=True, timeout=300)
                        results["tool_runs"]["jadx"] = self._command_result(result)
                        if result.returncode != 0:
                            logger.warning("JADX error: %s", result.stderr.decode(errors="replace"))
                    
                    if jadx_output.exists():
                        results["jadx_output"] = str(jadx_output)
                except Exception as e:
                    results["tool_runs"]["jadx"] = {"ok": False, "error": str(e)}
                    logger.warning("JADX error: %s", e)
            
            # Decode with apktool
            if self.tools_status.get("apktool", {}).get("available") and self.tools_status.get("java", {}).get("available"):
                self.progress_update.emit(60, "Decoding resources...")
                apktool_path = self.tools_status["apktool"]["path"]
                apktool_output = project_dir / "apktool_resources"
                
                try:
                    result = subprocess.run(
                        ["java", "-jar", apktool_path, "d", "-f", "-o", str(apktool_output), self.apk_path],
                        capture_output=True,
                        timeout=300
                    )
                    results["tool_runs"]["apktool"] = self._command_result(result)
                    if result.returncode != 0:
                        logger.warning("apktool error: %s", result.stderr.decode(errors="replace"))
                    
                    if apktool_output.exists():
                        results["apktool_output"] = str(apktool_output)
                except Exception as e:
                    results["tool_runs"]["apktool"] = {"ok": False, "error": str(e)}
                    logger.warning("apktool error: %s", e)
            
            # Convert with dex2jar
            if self.tools_status.get("dex2jar", {}).get("available"):
                self.progress_update.emit(80, "Converting DEX files to JAR...")
                dex2jar_path = self.tools_status["dex2jar"]["path"]
                dex2jar_output = project_dir / "dex2jar_output"
                dex2jar_output.mkdir(exist_ok=True)
                
                try:
                    # Extract DEX files first
                    with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                        dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]
                        
                        if dex_files:
                            for idx, dex_file in enumerate(dex_files):
                                try:
                                    # Extract DEX file
                                    temp_dex = dex2jar_output / dex_file
                                    temp_dex.parent.mkdir(parents=True, exist_ok=True)
                                    with apk_zip.open(dex_file) as source, open(temp_dex, 'wb') as target:
                                        shutil.copyfileobj(source, target)
                                    
                                    # Convert to JAR
                                    output_jar = dex2jar_output / f"{Path(dex_file).stem}.jar"
                                    
                                    # Try different command formats
                                    cmd_executed = False
                                    
                                    if platform.system() == "Windows":
                                        # Try .bat script first
                                        dex2jar_bin = Path(dex2jar_path).parent
                                        dex2jar_bat = dex2jar_bin / "d2j-dex2jar.bat"
                                        
                                        if dex2jar_bat.exists():
                                            cmd = f'"{dex2jar_bat}" "{temp_dex}" -o "{output_jar}"'
                                            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                                            results["tool_runs"][f"dex2jar:{dex_file}"] = self._command_result(result)
                                            cmd_executed = True
                                        else:
                                            # Fallback to jar command
                                            cmd = f'"{dex2jar_path}" "{temp_dex}" -o "{output_jar}"'
                                            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                                            results["tool_runs"][f"dex2jar:{dex_file}"] = self._command_result(result)
                                            cmd_executed = True
                                    else:
                                        # Unix/Linux/Mac
                                        dex2jar_bin = Path(dex2jar_path).parent
                                        dex2jar_sh = dex2jar_bin / "d2j-dex2jar.sh"
                                        
                                        if dex2jar_sh.exists():
                                            result = subprocess.run(["bash", str(dex2jar_sh), str(temp_dex), "-o", str(output_jar)],
                                                         capture_output=True, text=True, timeout=60)
                                            results["tool_runs"][f"dex2jar:{dex_file}"] = self._command_result(result)
                                            cmd_executed = True
                                        else:
                                            result = subprocess.run([dex2jar_path, str(temp_dex), "-o", str(output_jar)],
                                                         capture_output=True, text=True, timeout=60)
                                            results["tool_runs"][f"dex2jar:{dex_file}"] = self._command_result(result)
                                            cmd_executed = True
                                    
                                    if cmd_executed:
                                        if result.returncode == 0:
                                            print(f"✓ Successfully converted {dex_file} to JAR")
                                        else:
                                            error_msg = result.stderr if result.stderr else result.stdout
                                            print(f"⚠ dex2jar warning for {dex_file}: {error_msg}")
                                            # Don't fail on dex2jar error, it might still create output
                                except subprocess.TimeoutExpired:
                                    print(f"⚠ dex2jar timeout for {dex_file}")
                                except Exception as inner_e:
                                    print(f"⚠ dex2jar error for {dex_file}: {inner_e}")
                        
                        if dex2jar_output.exists():
                            jar_files = list(dex2jar_output.glob("*.jar"))
                            if jar_files:
                                results["dex2jar_output"] = str(dex2jar_output)
                                print(f"✓ Generated {len(jar_files)} JAR file(s) from DEX conversion")
                except Exception as e:
                    logger.warning("dex2jar error: %s", e)
            
            self.progress_update.emit(95, "Organizing results...")
            results["project_dir"] = str(project_dir)
            results["validation"] = self.validate_decompilation_results(results)
            results["success"] = results["validation"].get("overall_status") != "failed"
            
            self.progress_update.emit(100, "Decompilation complete")
            status = results["validation"].get("overall_status", "unknown")
            message = "Decompilation completed successfully" if status == "passed" else "Decompilation completed with validation warnings"
            self.result_ready.emit(results["success"], message, results)
            
        except Exception as e:
            self.result_ready.emit(False, f"Decompilation failed: {str(e)}", {})

    @staticmethod
    def _command_result(result) -> Dict[str, Any]:
        stdout = result.stdout.decode(errors="replace") if isinstance(result.stdout, bytes) else (result.stdout or "")
        stderr = result.stderr.decode(errors="replace") if isinstance(result.stderr, bytes) else (result.stderr or "")
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout_tail": stdout[-1000:],
            "stderr_tail": stderr[-1000:],
        }

    def validate_decompilation_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        report = {
            "overall_status": "failed",
            "tools": self._validate_tool_status(results.get("tool_runs", {})),
            "outputs": {},
            "warnings": [],
            "errors": [],
        }

        jadx_output = results.get("jadx_output")
        apktool_output = results.get("apktool_output")
        dex2jar_output = results.get("dex2jar_output")

        if jadx_output:
            report["outputs"]["jadx"] = self._validate_jadx_output(Path(jadx_output))
        else:
            report["warnings"].append("JADX did not produce an output directory.")

        if apktool_output:
            report["outputs"]["apktool"] = self._validate_apktool_output(Path(apktool_output))
        else:
            report["warnings"].append("apktool did not produce an output directory.")

        if dex2jar_output:
            report["outputs"]["dex2jar"] = self._validate_dex2jar_output(Path(dex2jar_output))
        elif self.tools_status.get("dex2jar", {}).get("available"):
            report["warnings"].append("dex2jar was available but produced no JAR output.")

        for name, output_report in report["outputs"].items():
            if not output_report.get("exists"):
                report["errors"].append(f"{name} output path does not exist.")
            elif not output_report.get("human_readable", False) and name in {"jadx", "apktool"}:
                report["warnings"].append(f"{name} output exists but readable source/resource ratio is low.")
            for warning in output_report.get("warnings", []):
                report["warnings"].append(f"{name}: {warning}")
            for error in output_report.get("errors", []):
                report["errors"].append(f"{name}: {error}")

        if not report["outputs"]:
            report["errors"].append("No decompiler output directories were produced.")

        essential_outputs = [
            output for name, output in report["outputs"].items()
            if name in {"jadx", "apktool"}
        ]
        if report["errors"]:
            report["overall_status"] = "failed"
        elif essential_outputs and all(output.get("human_readable", False) for output in essential_outputs):
            report["overall_status"] = "passed"
        else:
            report["overall_status"] = "warning"

        return report

    def _validate_tool_status(self, tool_runs: Dict[str, Any]) -> Dict[str, Any]:
        tools = {}
        for name, info in self.tools_status.items():
            if name == "all_ready" or not isinstance(info, dict):
                continue
            path = info.get("path")
            tools[name] = {
                "configured_available": bool(info.get("available")),
                "path": path,
                "path_exists": bool(path and Path(path).exists()) if name != "java" else bool(info.get("available")),
                "error": info.get("error"),
            }

        for name, run in tool_runs.items():
            tool_name = name.split(":", 1)[0]
            tools.setdefault(tool_name, {})
            runs = tools[tool_name].setdefault("runs", [])
            runs.append(run)
            tools[tool_name]["last_run_ok"] = bool(run.get("ok"))

        return tools

    def _validate_jadx_output(self, output_dir: Path) -> Dict[str, Any]:
        report = self._validate_readable_directory(output_dir, {".java", ".kt", ".xml", ".json", ".properties", ".gradle"})
        java_files = list(output_dir.rglob("*.java")) if output_dir.exists() else []
        kt_files = list(output_dir.rglob("*.kt")) if output_dir.exists() else []
        manifest_files = list(output_dir.rglob("AndroidManifest.xml")) if output_dir.exists() else []
        report["source_files"] = len(java_files) + len(kt_files)
        report["manifest_files"] = len(manifest_files)
        if report["source_files"] == 0:
            report["warnings"].append("No Java/Kotlin source files were found in JADX output.")
        return report

    def _validate_apktool_output(self, output_dir: Path) -> Dict[str, Any]:
        report = self._validate_readable_directory(output_dir, {".smali", ".xml", ".yml", ".json", ".properties"})
        smali_files = list(output_dir.rglob("*.smali")) if output_dir.exists() else []
        manifest_path = output_dir / "AndroidManifest.xml"
        report["smali_files"] = len(smali_files)
        report["manifest_present"] = manifest_path.exists()
        report["manifest_readable"] = self._is_human_readable_file(manifest_path) if manifest_path.exists() else False
        if not report["manifest_present"]:
            report["warnings"].append("AndroidManifest.xml was not found in apktool output.")
        if report["smali_files"] == 0:
            report["warnings"].append("No Smali files were found in apktool output.")
        return report

    def _validate_dex2jar_output(self, output_dir: Path) -> Dict[str, Any]:
        jars = list(output_dir.rglob("*.jar")) if output_dir.exists() else []
        return {
            "exists": output_dir.exists(),
            "file_count": len(list(output_dir.rglob("*"))) if output_dir.exists() else 0,
            "jar_files": len(jars),
            "human_readable": bool(jars),
            "warnings": [] if jars else ["No JAR files were generated."],
            "errors": [],
        }

    def _validate_readable_directory(self, output_dir: Path, text_extensions: set) -> Dict[str, Any]:
        report = {
            "exists": output_dir.exists(),
            "file_count": 0,
            "sampled_text_files": 0,
            "readable_text_files": 0,
            "readability_ratio": 0.0,
            "human_readable": False,
            "warnings": [],
            "errors": [],
        }
        if not output_dir.exists():
            report["errors"].append("Output directory is missing.")
            return report

        files = [path for path in output_dir.rglob("*") if path.is_file()]
        report["file_count"] = len(files)
        if not files:
            report["errors"].append("Output directory is empty.")
            return report

        text_candidates = [path for path in files if path.suffix.lower() in text_extensions]
        sample = text_candidates[:250]
        report["sampled_text_files"] = len(sample)
        report["readable_text_files"] = sum(1 for path in sample if self._is_human_readable_file(path))
        if sample:
            report["readability_ratio"] = round(report["readable_text_files"] / len(sample), 3)
        report["human_readable"] = report["readable_text_files"] > 0 and report["readability_ratio"] >= 0.85

        if not text_candidates:
            report["warnings"].append("No expected text-like decompiled files were found.")
        elif not report["human_readable"]:
            report["warnings"].append(
                f"Only {report['readable_text_files']}/{len(sample)} sampled text files were readable."
            )

        return report

    @staticmethod
    def _is_human_readable_file(path: Path) -> bool:
        try:
            if not path.exists() or path.stat().st_size == 0:
                return False
            with open(path, "rb") as handle:
                data = handle.read(8192)
            if b"\x00" in data:
                return False
            text = data.decode("utf-8", errors="replace")
            if not text.strip():
                return False
            replacement_ratio = text.count("\ufffd") / max(len(text), 1)
            printable_ratio = sum(1 for char in text if char.isprintable() or char in "\r\n\t") / max(len(text), 1)
            return replacement_ratio < 0.02 and printable_ratio > 0.85
        except Exception:
            return False



# ----------------------------------------------------------------------------
# Reverse Engineering Pipeline (Semantic, Modular, Analyst-Grade Output)
# ----------------------------------------------------------------------------

@dataclass
class REStageResult:
    """Why: Standardizes stage outputs for traceability and analyst trust."""
    name: str
    success: bool
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class REFinding:
    """Why: Provides structured, explainable findings without raw dumps."""
    finding_id: str
    title: str
    category: str
    severity: str
    confidence: str
    explanation: str
    execution_path: List[str] = field(default_factory=list)
    data_flow: List[str] = field(default_factory=list)
    runtime_dependencies: List[str] = field(default_factory=list)
    native_linkage: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    preconditions: List[str] = field(default_factory=list)


@dataclass
class StructuredREOutput:
    """Why: Enforces analyst-grade, transparent output for every pipeline stage."""
    metadata: Dict[str, Any] = field(default_factory=dict)
    stages: List[REStageResult] = field(default_factory=list)
    findings: List[REFinding] = field(default_factory=list)
    execution_paths: List[Dict[str, Any]] = field(default_factory=list)
    data_flows: List[Dict[str, Any]] = field(default_factory=list)
    obfuscation: Dict[str, Any] = field(default_factory=dict)
    native: Dict[str, Any] = field(default_factory=dict)
    runtime_feedback: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def to_scanner_dict(self) -> Dict[str, Any]:
        """Standardized output for Scanner module consumption."""
        meta = self.metadata or {}
        return {
            "package_name":              meta.get("package_name", ""),
            "debuggable":                bool(meta.get("debuggable", False)),
            "backup_enabled":            bool(meta.get("backup_allowed", True)),
            "dangerous_permission_count": len([
                p for p in meta.get("permissions", [])
                if any(k in p for k in ["READ_","WRITE_","RECORD_","CAMERA","SEND_SMS"])
            ]),
            "exported_component_count":  len(meta.get("exported_components", [])),
            "permissions":               list(meta.get("permissions", [])),
            "exported_components":       list(meta.get("exported_components", [])),
            "findings":                  [asdict(f) for f in (self.findings or [])],
            "errors":                    list(self.errors or []),
        }

    def save_json(self, path) -> None:
        """Save result to a JSON file."""
        from pathlib import Path as _Path
        _Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)


@dataclass
class REPipelineContext:
    """Why: Central context container ensures deterministic, debuggable flow."""
    apk_path: str
    tools_status: Dict[str, Any]
    project_dir: Path
    runtime_feedback: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class REPipelineStage:
    """Why: Forces modularity and reusability for each pipeline stage."""
    name: str = "unnamed"

    def run(self, ctx: REPipelineContext) -> REStageResult:
        raise NotImplementedError("Pipeline stages must implement run().")


class SmaliParser:
    """Why: Provides fallback accuracy when bytecode analysis is limited."""

    def parse_smali_roots(self, smali_roots: List[Path]) -> Dict[str, Any]:
        methods: Dict[str, Dict[str, Any]] = {}
        classes: List[str] = []

        for root in smali_roots:
            for smali_file in root.rglob("*.smali"):
                self._parse_smali_file(smali_file, methods, classes)

        return {
            "methods": methods,
            "classes": sorted(set(classes))
        }

    def _parse_smali_file(self, smali_file: Path, methods: Dict[str, Dict[str, Any]], classes: List[str]) -> None:
        current_class = None
        current_method = None

        try:
            with open(smali_file, "r", encoding="utf-8", errors="ignore") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.startswith(".class"):
                        parts = line.split()
                        if parts:
                            current_class = parts[-1]
                            classes.append(current_class)

                    if line.startswith(".method"):
                        parts = line.split()
                        if parts:
                            current_method = parts[-1]
                            if current_class and current_method:
                                sig = f"{current_class}->{current_method}"
                                methods.setdefault(sig, {"invokes": [], "strings": [], "opcodes": set()})
                        continue

                    if line.startswith(".end method"):
                        current_method = None
                        continue

                    if not current_method or not current_class:
                        continue

                    sig = f"{current_class}->{current_method}"
                    entry = methods.setdefault(sig, {"invokes": [], "strings": [], "opcodes": set()})

                    if line.startswith("invoke-"):
                        invoked = self._extract_invoked_method(line)
                        if invoked:
                            entry["invokes"].append(invoked)

                    if line.startswith("const-string"):
                        lit = self._extract_string_literal(line)
                        if lit is not None:
                            entry["strings"].append(lit)

                    op = line.split()[0]
                    entry["opcodes"].add(op)

        except Exception:
            return

    @staticmethod
    def _extract_invoked_method(line: str) -> Optional[str]:
        if "}," in line:
            tail = line.split("},", 1)[1].strip()
        elif "}, " in line:
            tail = line.split("}, ", 1)[1].strip()
        else:
            parts = line.split()
            tail = parts[-1] if parts else ""
        return tail if "->" in tail else None

    @staticmethod
    def _extract_string_literal(line: str) -> Optional[str]:
        if '"' not in line:
            return None
        first = line.find('"')
        last = line.rfind('"')
        if first == -1 or last == -1 or last <= first:
            return None
        return line[first + 1:last]


class APKNormalizationStage(REPipelineStage):
    """Why: Builds a deterministic, multi-DEX aware baseline for analysis."""
    name = "APK Normalization"

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {}
        errors: List[str] = []
        success = True

        try:
            apk_path = Path(ctx.apk_path)
            extracted_apks: List[str] = []

            if apk_path.suffix.lower() in {".apks", ".xapk"}:
                container_dir = ctx.project_dir / "split_container"
                container_dir.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(apk_path, "r") as zf:
                    zf.extractall(container_dir)

                candidate_apks = sorted(p for p in container_dir.rglob("*.apk"))
                if not candidate_apks:
                    raise RuntimeError("No APKs found in split container")

                extracted_apks = [str(p) for p in candidate_apks]
            else:
                extracted_apks = [str(apk_path)]

            dex_files: List[str] = []
            native_libs: List[str] = []
            resources: List[str] = []
            for apk in extracted_apks:
                with zipfile.ZipFile(apk, "r") as zf:
                    names = sorted(zf.namelist())
                    dex_files.extend([n for n in names if n.endswith(".dex")])
                    native_libs.extend([n for n in names if n.endswith(".so")])
                    resources.extend([n for n in names if n.startswith("res/")])

            dex_files = sorted(set(dex_files))
            native_libs = sorted(set(native_libs))
            resources = sorted(set(resources))

            kotlin_metadata = False
            if ANDROGUARD_AVAILABLE and extracted_apks:
                try:
                    _, _, dx = AnalyzeAPK(extracted_apks[0])
                    kotlin_metadata = any("kotlin/Metadata" in s for s in dx.get_strings())
                except Exception:
                    kotlin_metadata = False

            details = {
                "apks": extracted_apks,
                "dex_files": dex_files,
                "native_libs": native_libs,
                "resources": resources,
                "multi_dex": len(dex_files) > 1,
                "kotlin_metadata": kotlin_metadata,
                "deterministic": True
            }

            ctx.artifacts["normalization"] = details

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="APK normalized with multi-DEX awareness" if success else "APK normalization failed",
            details=details,
            errors=errors,
        )


class CodeReconstructionStage(REPipelineStage):
    """Why: Provides reconstructed code and resources for semantic analysis."""
    name = "Code Reconstruction"

    def _run_jadx(self, apk_path: str, output_dir: Path, tools_status: Dict[str, Any]) -> Optional[str]:
        if not tools_status.get("jadx", {}).get("available"):
            return None
        jadx_path = tools_status["jadx"]["path"]
        jadx_output = output_dir / "jadx_source"
        try:
            if platform.system() == "Windows":
                cmd = f'"{jadx_path}" -d "{jadx_output}" "{apk_path}"'
                subprocess.run(cmd, shell=True, capture_output=True, timeout=600)
            else:
                subprocess.run([jadx_path, "-d", str(jadx_output), apk_path], capture_output=True, timeout=600)
            return str(jadx_output) if jadx_output.exists() else None
        except Exception:
            return None

    def _run_apktool(self, apk_path: str, output_dir: Path, tools_status: Dict[str, Any]) -> Optional[str]:
        if not (tools_status.get("apktool", {}).get("available") and tools_status.get("java", {}).get("available")):
            return None
        apktool_path = tools_status["apktool"]["path"]
        apktool_output = output_dir / "apktool_resources"
        try:
            subprocess.run(
                ["java", "-jar", apktool_path, "d", "-f", "-o", str(apktool_output), apk_path],
                capture_output=True,
                timeout=600,
            )
            return str(apktool_output) if apktool_output.exists() else None
        except Exception:
            return None

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {}
        errors: List[str] = []
        success = True

        try:
            apk_path = ctx.artifacts.get("normalization", {}).get("apks", [ctx.apk_path])[0]
            output_dir = ctx.project_dir
            jadx_output = self._run_jadx(apk_path, output_dir, ctx.tools_status)
            apktool_output = self._run_apktool(apk_path, output_dir, ctx.tools_status)

            smali_index = {}
            if apktool_output:
                smali_roots = [p for p in Path(apktool_output).glob("smali*") if p.is_dir()]
                if smali_roots:
                    smali_index = SmaliParser().parse_smali_roots(smali_roots)

            details = {
                "jadx_output": jadx_output,
                "apktool_output": apktool_output,
                "used_jadx": bool(jadx_output),
                "used_apktool": bool(apktool_output),
                "smali_indexed": bool(smali_index)
            }

            ctx.artifacts["reconstruction"] = details
            if smali_index:
                ctx.artifacts["smali"] = smali_index

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Code reconstruction completed" if success else "Code reconstruction failed",
            details=details,
            errors=errors,
        )


class StructuralGraphsStage(REPipelineStage):
    """Why: Builds a component-level view and entry-point understanding."""
    name = "Structural Graphs"

    def _parse_manifest(self, manifest_path: Path) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "package": "",
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "entry_points": [],
            "intent_filters": []
        }

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            data["package"] = root.get("package", "")
            app = root.find("application")
            if app is None:
                return data

            def _get_name(elem):
                return elem.get("{http://schemas.android.com/apk/res/android}name")

            for tag, key in [("activity", "activities"), ("service", "services"), ("receiver", "receivers"), ("provider", "providers")]:
                for comp in app.findall(tag):
                    name = _get_name(comp)
                    if name:
                        data[key].append(name)

                    for intent_filter in comp.findall("intent-filter"):
                        actions = [a.get("{http://schemas.android.com/apk/res/android}name") for a in intent_filter.findall("action")]
                        categories = [c.get("{http://schemas.android.com/apk/res/android}name") for c in intent_filter.findall("category")]
                        data["intent_filters"].append({
                            "component": name,
                            "actions": [a for a in actions if a],
                            "categories": [c for c in categories if c]
                        })

                        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                            data["entry_points"].append({"component": name, "type": tag, "reason": "LAUNCHER"})
                        if "android.intent.action.BOOT_COMPLETED" in actions:
                            data["entry_points"].append({"component": name, "type": tag, "reason": "BOOT_COMPLETED"})

            data["activities"].sort()
            data["services"].sort()
            data["receivers"].sort()
            data["providers"].sort()
            data["entry_points"] = sorted(data["entry_points"], key=lambda x: x.get("component", ""))

        except Exception:
            return data

        return data

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {}
        errors: List[str] = []
        success = True

        try:
            manifest_data: Dict[str, Any] = {}
            apktool_output = ctx.artifacts.get("reconstruction", {}).get("apktool_output")
            if apktool_output:
                manifest_path = Path(apktool_output) / "AndroidManifest.xml"
                if manifest_path.exists():
                    manifest_data = self._parse_manifest(manifest_path)

            lifecycle_flows: List[Dict[str, Any]] = []
            smali_index = ctx.artifacts.get("smali", {})
            methods = smali_index.get("methods", {})
            package_name = manifest_data.get("package", "")

            component_names = (
                manifest_data.get("activities", []) +
                manifest_data.get("services", []) +
                manifest_data.get("receivers", []) +
                manifest_data.get("providers", [])
            )

            for comp in component_names:
                smali_class = self._component_to_smali(comp, package_name)
                if not smali_class:
                    continue
                lifecycle = []
                for method_sig in methods:
                    if method_sig.startswith(smali_class + "->"):
                        method_name = method_sig.split("->", 1)[1].split("(", 1)[0]
                        if method_name in {"onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy", "onStartCommand", "onReceive", "onBind"}:
                            lifecycle.append(method_name)
                if lifecycle:
                    lifecycle_flows.append({"component": comp, "methods": sorted(set(lifecycle))})

            details = {
                "components": manifest_data,
                "inter_component_graph": {
                    "nodes": (
                        manifest_data.get("activities", []) +
                        manifest_data.get("services", []) +
                        manifest_data.get("receivers", []) +
                        manifest_data.get("providers", [])
                    ),
                    "edges": manifest_data.get("intent_filters", [])
                },
                "lifecycle_flows": lifecycle_flows
            }

            ctx.artifacts["structural_graphs"] = details

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Structural graphs built" if success else "Structural graph build failed",
            details=details,
            errors=errors,
        )

    @staticmethod
    def _component_to_smali(component_name: str, package_name: str) -> Optional[str]:
        if not component_name:
            return None
        if component_name.startswith("L") and component_name.endswith(";"):
            return component_name
        if component_name.startswith(".") and package_name:
            fq = package_name + component_name
        elif "." in component_name:
            fq = component_name
        else:
            fq = f"{package_name}.{component_name}" if package_name else component_name
        return "L" + fq.replace(".", "/") + ";"


class ControlFlowStage(REPipelineStage):
    """Why: Enables path awareness beyond API presence."""
    name = "Control Flow Analysis"

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {"method_cfgs": [], "branch_aware": True}
        errors: List[str] = []
        success = True

        if not ANDROGUARD_AVAILABLE:
            return REStageResult(
                name=self.name,
                success=False,
                summary="Androguard unavailable for CFG",
                details=details,
                errors=["Androguard not installed"],
            )

        try:
            apk_path = ctx.artifacts.get("normalization", {}).get("apks", [ctx.apk_path])[0]
            _, _, dx = AnalyzeAPK(apk_path)

            for method in dx.get_methods():
                try:
                    m = method.get_method()
                    class_name = m.get_class_name()
                    if class_name.startswith("Landroid/") or class_name.startswith("Ljava/") or class_name.startswith("Lkotlin/") or class_name.startswith("Landroidx/"):
                        continue
                    blocks = list(method.get_basic_blocks()) if hasattr(method, "get_basic_blocks") else []
                    edges = []
                    branch_points = []
                    for block in blocks:
                        for child in block.childs:
                            edges.append({"from": block.name, "to": child[2].name})
                        if len(block.childs) > 1:
                            branch_points.append(block.name)
                    details["method_cfgs"].append({
                        "method": self._method_sig(m),
                        "basic_blocks": [b.name for b in blocks],
                        "edges": edges,
                        "block_count": len(blocks),
                        "branch_points": branch_points,
                        "reachability": "assumed"
                    })
                except Exception:
                    continue

            ctx.artifacts["cfg"] = details

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Control flow graphs built" if success else "Control flow analysis failed",
            details=details,
            errors=errors,
        )

    @staticmethod
    def _method_sig(method_obj) -> str:
        return f"{method_obj.get_class_name()}->{method_obj.get_name()}{method_obj.get_descriptor()}"


class DataFlowSemanticsStage(REPipelineStage):
    """Why: Tracks semantic data movement across methods and components."""
    name = "Data Flow & Semantics"

    SOURCE_APIS = {
        "Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;",
        "Landroid/telephony/TelephonyManager;->getImei()Ljava/lang/String;",
        "Landroid/location/Location;->getLatitude()D",
        "Landroid/location/Location;->getLongitude()D",
        "Landroid/accounts/AccountManager;->getAccounts()[Landroid/accounts/Account;",
        "Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
    }

    SINK_APIS = {
        "Ljava/net/HttpURLConnection;->connect()V",
        "Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;",
        "Ljava/net/Socket;->connect(Ljava/net/SocketAddress;)V",
        "Ljava/io/FileOutputStream;->write([B)V",
        "Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
    }

    TRANSFORM_APIS = {
        "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;",
        "Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;",
        "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B",
        "Ljava/util/zip/GZIPOutputStream;->write([B)V",
    }

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {
            "call_graph": {},
            "taint_paths": [],
            "transformations": {},
            "async_boundaries": [],
            "cross_component_paths": []
        }
        errors: List[str] = []
        success = True

        try:
            call_graph: Dict[str, List[str]] = defaultdict(list)
            method_calls: Dict[str, List[str]] = defaultdict(list)

            if ANDROGUARD_AVAILABLE:
                apk_path = ctx.artifacts.get("normalization", {}).get("apks", [ctx.apk_path])[0]
                _, _, dx = AnalyzeAPK(apk_path)

                for method in dx.get_methods():
                    m = method.get_method()
                    caller = self._method_sig(m)
                    for _, callee, _ in method.get_xref_to():
                        callee_sig = self._method_sig(callee)
                        call_graph[caller].append(callee_sig)
                        method_calls[caller].append(callee_sig)
            else:
                smali_index = ctx.artifacts.get("smali", {})
                for caller, info in smali_index.get("methods", {}).items():
                    for callee in info.get("invokes", []):
                        call_graph[caller].append(callee)
                        method_calls[caller].append(callee)

            if not call_graph:
                return REStageResult(
                    name=self.name,
                    success=False,
                    summary="No call graph available for data flow",
                    details=details,
                    errors=["No call graph data from Androguard or smali"],
                )

            # Identify sources, sinks, and transformations
            source_methods = {m for m, calls in method_calls.items() if any(c in self.SOURCE_APIS for c in calls)}
            sink_methods = {m for m, calls in method_calls.items() if any(c in self.SINK_APIS for c in calls)}
            for m, calls in method_calls.items():
                if any(c in self.TRANSFORM_APIS for c in calls):
                    details["transformations"][m] = [c for c in calls if c in self.TRANSFORM_APIS]

            # Async boundaries
            async_apis = {
                "Ljava/lang/Thread;->start()V",
                "Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V",
                "Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z",
                "Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z",
                "Lkotlinx/coroutines/CoroutineScope;->launch(Lkotlinx/coroutines/CoroutineContext;Lkotlinx/coroutines/CoroutineStart;Lkotlin/jvm/functions/Function2;)Lkotlinx/coroutines/Job;"
            }
            for m, calls in method_calls.items():
                if any(c in async_apis for c in calls):
                    details["async_boundaries"].append(m)

            # BFS taint propagation
            visited: Dict[str, str] = {}
            queue: List[str] = list(source_methods)
            for s in source_methods:
                visited[s] = "SOURCE"

            while queue:
                current = queue.pop(0)
                for neighbor in call_graph.get(current, []):
                    if neighbor not in visited:
                        visited[neighbor] = current
                        queue.append(neighbor)

            # Build paths to sinks
            def _reconstruct_path(sink: str) -> List[str]:
                path = [sink]
                cur = sink
                while visited.get(cur) and visited[cur] != "SOURCE":
                    cur = visited[cur]
                    path.append(cur)
                path.reverse()
                return path

            taint_paths = []
            for sink in sink_methods:
                if sink in visited:
                    taint_paths.append({
                        "sink": sink,
                        "path": _reconstruct_path(sink)
                    })

            # Cross-component propagation tagging
            components = ctx.artifacts.get("structural_graphs", {}).get("components", {})
            package_name = components.get("package", "")
            component_classes = set()
            for comp in (
                components.get("activities", []) +
                components.get("services", []) +
                components.get("receivers", []) +
                components.get("providers", [])
            ):
                smali_name = StructuralGraphsStage._component_to_smali(comp, package_name)
                if smali_name:
                    component_classes.add(smali_name)

            for path in taint_paths:
                touched = []
                for node in path.get("path", []):
                    cls = node.split("->", 1)[0]
                    if cls in component_classes:
                        touched.append(cls)
                if len(set(touched)) > 1:
                    details["cross_component_paths"].append({
                        "path": path.get("path", []),
                        "components": sorted(set(touched))
                    })

            details["call_graph"] = {k: sorted(set(v)) for k, v in call_graph.items()}
            details["taint_paths"] = taint_paths

            ctx.artifacts["data_flow"] = details

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Data flow and semantics analyzed" if success else "Data flow analysis failed",
            details=details,
            errors=errors,
        )

    @staticmethod
    def _method_sig(method_obj) -> str:
        return f"{method_obj.get_class_name()}->{method_obj.get_name()}{method_obj.get_descriptor()}"


class LogicAwareSecurityStage(REPipelineStage):
    """Why: Explains security relevance beyond raw API presence."""
    name = "Logic-Aware Security Analysis"

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {
            "auth_flows": [],
            "session_tracking": [],
            "trust_decisions": [],
            "environment_checks": []
        }
        errors: List[str] = []
        success = True

        try:
            if ANDROGUARD_AVAILABLE:
                apk_path = ctx.artifacts.get("normalization", {}).get("apks", [ctx.apk_path])[0]
                _, _, dx = AnalyzeAPK(apk_path)

                strings = set(dx.get_strings())
                if "debuggable" in strings or "BuildConfig" in strings:
                    details["trust_decisions"].append({"type": "debug_flag", "note": "Debug flags referenced"})

                root_indicators = {"/system/bin/su", "/system/xbin/su", "test-keys", "magisk"}
                if strings.intersection(root_indicators):
                    details["environment_checks"].append({"type": "root_check", "evidence": list(strings.intersection(root_indicators))})

                emulator_indicators = {"generic", "goldfish", "ranchu"}
                if strings.intersection(emulator_indicators):
                    details["environment_checks"].append({"type": "emulator_check", "evidence": list(strings.intersection(emulator_indicators))})

                # SSL pinning and trust decisions
                for method in dx.get_methods():
                    m = method.get_method()
                    sig = f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor()}"
                    for _, callee, _ in method.get_xref_to():
                        callee_sig = f"{callee.get_class_name()}->{callee.get_name()}{callee.get_descriptor()}"
                        if callee_sig in {
                            "Ljavax/net/ssl/X509TrustManager;->checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
                            "Ljavax/net/ssl/HostnameVerifier;->verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z",
                            "Lokhttp3/CertificatePinner;->check(Ljava/lang/String;Ljava/util/List;)V"
                        }:
                            details["trust_decisions"].append({
                                "type": "ssl_pinning_or_trust_logic",
                                "location": sig,
                                "callee": callee_sig
                            })

            smali_index = ctx.artifacts.get("smali", {})
            for method_sig, info in smali_index.get("methods", {}).items():
                strings = [s.lower() for s in info.get("strings", [])]
                invokes = info.get("invokes", [])

                if any(s in strings for s in ["debuggable", "buildconfig"]):
                    details["trust_decisions"].append({"type": "debug_flag", "note": "Debug flags referenced (smali)"})

                if any(s in strings for s in ["/system/bin/su", "/system/xbin/su", "test-keys", "magisk"]):
                    details["environment_checks"].append({"type": "root_check", "evidence": "smali_strings"})

                if any(s in strings for s in ["generic", "goldfish", "ranchu"]):
                    details["environment_checks"].append({"type": "emulator_check", "evidence": "smali_strings"})

                if any(word in strings for word in ["login", "signin", "authenticate", "auth"]):
                    if any(api in invokes for api in DataFlowSemanticsStage.SINK_APIS):
                        details["auth_flows"].append({
                            "location": method_sig,
                            "evidence": "login-related strings with network sink",
                            "confidence": "Medium"
                        })

                if "token" in strings or "session" in strings or "bearer" in strings:
                    if "Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;" in invokes:
                        details["session_tracking"].append({
                            "location": method_sig,
                            "evidence": "token/session stored in SharedPreferences",
                            "confidence": "Medium"
                        })
                    if any("remove" in api or "clear" in api for api in invokes):
                        details["session_tracking"].append({
                            "location": method_sig,
                            "evidence": "token/session removal/clear detected",
                            "confidence": "Low"
                        })

            ctx.artifacts["logic_security"] = details

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Logic-aware security analysis completed" if success else "Logic-aware analysis failed",
            details=details,
            errors=errors,
        )


class ObfuscationReflectionStage(REPipelineStage):
    """Why: Handles obfuscation and reflection without false certainty."""
    name = "Obfuscation & Reflection Handling"

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {
            "obfuscation": {},
            "reflection": [],
            "encrypted_strings": [],
            "dynamic_loading": [],
            "runtime_hook_suggestions": []
        }
        errors: List[str] = []
        success = True

        try:
            class_names = []
            if ANDROGUARD_AVAILABLE:
                apk_path = ctx.artifacts.get("normalization", {}).get("apks", [ctx.apk_path])[0]
                _, _, dx = AnalyzeAPK(apk_path)

                for c in dx.get_classes():
                    if hasattr(c, "get_name"):
                        name = c.get_name()
                    else:
                        name = getattr(c, "name", "")
                    if name:
                        class_names.append(name)

            short_names = [c for c in class_names if len(c.split("/")) > 0 and len(c.split("/")[-1].strip(";")) <= 2]
            entropy_scores = [self._entropy(c) for c in class_names if c]
            mean_entropy = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0.0

            details["obfuscation"] = {
                "short_class_name_ratio": (len(short_names) / len(class_names)) if class_names else 0.0,
                "mean_class_entropy": mean_entropy,
                "suspected": (len(short_names) / len(class_names) > 0.4) if class_names else False
            }

            reflection_apis = {
                "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
                "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
                "Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;",
                "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V"
            }

            crypto_apis = {
                "Ljavax/crypto/Cipher;->doFinal([B)[B",
                "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B",
                "Landroid/util/Base64;->decode([BI)[B",
            }

            if ANDROGUARD_AVAILABLE:
                for method in dx.get_methods():
                    m = method.get_method()
                    sig = f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor()}"
                    for _, callee, _ in method.get_xref_to():
                        callee_sig = f"{callee.get_class_name()}->{callee.get_name()}{callee.get_descriptor()}"
                        if callee_sig in reflection_apis:
                            details["reflection"].append({
                                "location": sig,
                                "callee": callee_sig,
                                "resolution": "runtime_required"
                            })
                        if callee_sig in crypto_apis:
                            details["encrypted_strings"].append({
                                "location": sig,
                                "callee": callee_sig,
                                "resolution": "runtime_required"
                            })

                        if "DexClassLoader" in callee_sig or "PathClassLoader" in callee_sig:
                            details["dynamic_loading"].append({
                                "location": sig,
                                "callee": callee_sig,
                                "resolution": "runtime_required"
                            })

            smali_index = ctx.artifacts.get("smali", {})
            for method_sig, info in smali_index.get("methods", {}).items():
                invokes = info.get("invokes", [])
                strings = info.get("strings", [])
                opcodes = info.get("opcodes", set())

                if any(api in invokes for api in reflection_apis):
                    candidate = self._guess_reflection_target(strings)
                    details["reflection"].append({
                        "location": method_sig,
                        "callee": "reflection",
                        "resolution": "static_candidate" if candidate else "runtime_required",
                        "candidate_target": candidate
                    })

                if "xor-int" in opcodes or "xor-int/2addr" in opcodes:
                    details["encrypted_strings"].append({
                        "location": method_sig,
                        "pattern": "xor",
                        "resolution": "runtime_required"
                    })

                if any(api in invokes for api in crypto_apis) and any("Base64" in api for api in invokes):
                    details["encrypted_strings"].append({
                        "location": method_sig,
                        "pattern": "base64_or_cipher",
                        "resolution": "runtime_required"
                    })

                if any("DexClassLoader" in api or "PathClassLoader" in api for api in invokes):
                    details["dynamic_loading"].append({
                        "location": method_sig,
                        "callee": "dynamic_class_loading",
                        "resolution": "runtime_required"
                    })

            details["runtime_hook_suggestions"] = self._build_hook_suggestions(details)

            ctx.artifacts["obfuscation"] = details

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Obfuscation and reflection analyzed" if success else "Obfuscation analysis failed",
            details=details,
            errors=errors,
        )

    @staticmethod
    def _guess_reflection_target(strings: List[str]) -> Optional[str]:
        for s in strings:
            if "/" in s or "." in s:
                if " " not in s and "(" not in s:
                    return s
        return None

    @staticmethod
    def _build_hook_suggestions(details: Dict[str, Any]) -> List[Dict[str, Any]]:
        hooks = []
        for refl in details.get("reflection", []):
            hooks.append({
                "target": refl.get("location"),
                "reason": "Resolve reflection target at runtime",
                "suggested_tool": "frida"
            })
        for dyn in details.get("dynamic_loading", []):
            hooks.append({
                "target": dyn.get("location"),
                "reason": "Capture dynamically loaded classes",
                "suggested_tool": "frida"
            })
        return hooks

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        freq = defaultdict(int)
        for ch in value:
            freq[ch] += 1
        entropy = 0.0
        length = len(value)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy


class NativeAwarenessStage(REPipelineStage):
    """Why: Links Java and native code for analyst visibility."""
    name = "Native Awareness"

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {
            "jni_methods": [],
            "libraries": [],
            "load_library_calls": [],
            "fingerprints": []
        }
        errors: List[str] = []
        success = True

        try:
            details["libraries"] = ctx.artifacts.get("normalization", {}).get("native_libs", [])

            extracted = self._extract_native_libs(ctx)
            if extracted:
                fingerprints = self._fingerprint_native_libs(extracted)
                details["fingerprints"] = fingerprints

            if ANDROGUARD_AVAILABLE:
                apk_path = ctx.artifacts.get("normalization", {}).get("apks", [ctx.apk_path])[0]
                _, _, dx = AnalyzeAPK(apk_path)

                for method in dx.get_methods():
                    m = method.get_method()
                    if "native" in m.get_access_flags_string().lower():
                        details["jni_methods"].append({
                            "method": f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor()}"
                        })

                    for _, callee, _ in method.get_xref_to():
                        callee_sig = f"{callee.get_class_name()}->{callee.get_name()}{callee.get_descriptor()}"
                        if callee_sig == "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V":
                            details["load_library_calls"].append({
                                "location": f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor()}",
                                "callee": callee_sig,
                                "note": "Library name may require runtime resolution"
                            })

            ctx.artifacts["native"] = details

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Native code awareness established" if success else "Native awareness failed",
            details=details,
            errors=errors,
        )

    @staticmethod
    def _extract_native_libs(ctx: REPipelineContext) -> List[Path]:
        extracted: List[Path] = []
        try:
            apk_path = ctx.artifacts.get("normalization", {}).get("apks", [ctx.apk_path])[0]
            out_dir = ctx.project_dir / "native_libs"
            out_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".so"):
                        target = out_dir / name.replace("/", "_")
                        with zf.open(name) as src, open(target, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        extracted.append(target)
        except Exception:
            return []
        return extracted

    @staticmethod
    def _fingerprint_native_libs(so_files: List[Path]) -> List[Dict[str, Any]]:
        fingerprints: List[Dict[str, Any]] = []
        keywords = {
            "crypto": ["AES", "RSA", "SHA", "MD5", "HMAC", "bcrypt", "scrypt"],
            "network": ["SSL", "TLS", "HTTP", "socket", "curl", "libssl"],
            "anti_debug": ["ptrace", "frida", "substrate", "xposed", "gdb", "anti_debug"]
        }

        for so in so_files:
            try:
                data = so.read_bytes()
                strings = NativeAwarenessStage._extract_ascii_strings(data)
                hits = {}
                for category, keys in keywords.items():
                    matched = [k for k in keys if any(k in s for s in strings)]
                    if matched:
                        hits[category] = matched
                if hits:
                    fingerprints.append({
                        "library": so.name,
                        "hits": hits,
                        "confidence": "Medium" if len(hits) > 1 else "Low"
                    })
            except Exception:
                continue
        return fingerprints

    @staticmethod
    def _extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
        result: List[str] = []
        buf = []
        for b in data:
            if 32 <= b < 127:
                buf.append(chr(b))
            else:
                if len(buf) >= min_len:
                    result.append("".join(buf))
                buf = []
        if len(buf) >= min_len:
            result.append("".join(buf))
        return result


class RuntimeFeedbackStage(REPipelineStage):
    """Why: Integrates runtime-resolved values back into static models."""
    name = "Runtime Feedback Integration"

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {"applied": False, "updates": {}}
        errors: List[str] = []
        success = True

        try:
            if ctx.runtime_feedback:
                details["applied"] = True
                details["updates"] = ctx.runtime_feedback
                ctx.artifacts["runtime_feedback"] = ctx.runtime_feedback

                # Update reflection resolution
                resolved = ctx.runtime_feedback.get("resolved_reflection", [])
                if resolved:
                    for item in ctx.artifacts.get("obfuscation", {}).get("reflection", []):
                        if item.get("location") in resolved:
                            item["resolution"] = "runtime_resolved"

                # Update call graph with runtime-resolved edges
                call_graph = ctx.artifacts.get("data_flow", {}).get("call_graph", {})
                for edge in ctx.runtime_feedback.get("resolved_calls", []):
                    src = edge.get("from")
                    dst = edge.get("to")
                    if src and dst:
                        call_graph.setdefault(src, []).append(dst)
                if call_graph and "data_flow" in ctx.artifacts:
                    ctx.artifacts["data_flow"]["call_graph"] = {k: sorted(set(v)) for k, v in call_graph.items()}
        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Runtime feedback applied" if success else "Runtime feedback integration failed",
            details=details,
            errors=errors,
        )


class ExploitPathConstructionStage(REPipelineStage):
    """Why: Chains weak points into explainable, actionable execution paths."""
    name = "Exploit Path Construction"

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {"paths": []}
        errors: List[str] = []
        success = True

        try:
            data_flow = ctx.artifacts.get("data_flow", {})
            taint_paths = data_flow.get("taint_paths", [])
            logic = ctx.artifacts.get("logic_security", {})
            obfuscation = ctx.artifacts.get("obfuscation", {})

            for path in taint_paths:
                preconditions = []
                if logic.get("trust_decisions"):
                    preconditions.append("Trust logic may alter reachability")
                if obfuscation.get("reflection"):
                    preconditions.append("Reflection requires runtime resolution")
                if obfuscation.get("dynamic_loading"):
                    preconditions.append("Dynamic class loading requires runtime resolution")
                if obfuscation.get("encrypted_strings"):
                    preconditions.append("Encrypted strings require runtime resolution")

                details["paths"].append({
                    "execution_chain": path.get("path", []),
                    "sink": path.get("sink"),
                    "preconditions": preconditions,
                    "reasoning": "Source-to-sink flow observed with potential transformations"
                })

            ctx.artifacts["exploit_paths"] = details

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Exploit paths constructed" if success else "Exploit path construction failed",
            details=details,
            errors=errors,
        )


class StructuredOutputStage(REPipelineStage):
    """Why: Produces analyst-grade structured output without raw dumps."""
    name = "Structured RE Output"

    def run(self, ctx: REPipelineContext) -> REStageResult:
        details: Dict[str, Any] = {"output": {}}
        errors: List[str] = []
        success = True

        try:
            data_flow = ctx.artifacts.get("data_flow", {})
            explanations = []
            for path in data_flow.get("taint_paths", []):
                explanations.append({
                    "sink": path.get("sink"),
                    "steps": path.get("path", []),
                    "transformations": [t for t in data_flow.get("transformations", {}).keys() if t in path.get("path", [])],
                    "async_boundaries": [m for m in data_flow.get("async_boundaries", []) if m in path.get("path", [])],
                    "cross_component": any(p.get("path") == path.get("path") for p in data_flow.get("cross_component_paths", []))
                })

            details["output"] = {
                "execution_paths": ctx.artifacts.get("exploit_paths", {}).get("paths", []),
                "data_flows": ctx.artifacts.get("data_flow", {}).get("taint_paths", []),
                "data_flow_explanations": explanations,
                "runtime_dependencies": ctx.artifacts.get("obfuscation", {}).get("reflection", []),
                "native_linkage": ctx.artifacts.get("native", {}).get("jni_methods", []),
                "runtime_hook_suggestions": ctx.artifacts.get("obfuscation", {}).get("runtime_hook_suggestions", []),
                "native_fingerprints": ctx.artifacts.get("native", {}).get("fingerprints", [])
            }
            ctx.artifacts["structured_output"] = details["output"]

        except Exception as exc:
            success = False
            errors.append(str(exc))

        return REStageResult(
            name=self.name,
            success=success,
            summary="Structured output prepared" if success else "Structured output failed",
            details=details,
            errors=errors,
        )


class APKReverseEngineeringPipeline:
    """Why: Orchestrates stages in a transparent, repeatable order."""

    def __init__(self, tools_status: Dict[str, Any], project_dir: Optional[Path] = None):
        self.tools_status = tools_status
        self.project_dir = project_dir or (APK_REVERSE_OUTPUT_DIR / f"re_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.stages: List[REPipelineStage] = [
            APKNormalizationStage(),
            CodeReconstructionStage(),
            StructuralGraphsStage(),
            ControlFlowStage(),
            DataFlowSemanticsStage(),
            LogicAwareSecurityStage(),
            ObfuscationReflectionStage(),
            NativeAwarenessStage(),
            RuntimeFeedbackStage(),
            ExploitPathConstructionStage(),
            StructuredOutputStage(),
        ]

    def run(self, apk_path: str, runtime_feedback: Optional[Dict[str, Any]] = None) -> StructuredREOutput:
        output = StructuredREOutput()
        ctx = REPipelineContext(
            apk_path=apk_path,
            tools_status=self.tools_status,
            project_dir=self.project_dir,
            runtime_feedback=runtime_feedback or {},
        )

        output.metadata = {
            "app_name": APK_REVERSE_APP_NAME,
            "version": APK_REVERSE_VERSION,
            "apk_path": apk_path,
            "timestamp": datetime.now().isoformat(),
            "androguard_available": ANDROGUARD_AVAILABLE,
        }

        for stage in self.stages:
            result = stage.run(ctx)
            output.stages.append(result)
            if not result.success:
                output.errors.extend(result.errors)

        # Build findings from artifacts
        output.execution_paths = ctx.artifacts.get("exploit_paths", {}).get("paths", [])
        output.data_flows = ctx.artifacts.get("data_flow", {}).get("taint_paths", [])
        output.obfuscation = ctx.artifacts.get("obfuscation", {})
        output.native = ctx.artifacts.get("native", {})
        output.runtime_feedback = ctx.runtime_feedback

        output.findings = self._build_findings(ctx)

        return output

    def _build_findings(self, ctx: REPipelineContext) -> List[REFinding]:
        findings: List[REFinding] = []

        for idx, path in enumerate(ctx.artifacts.get("exploit_paths", {}).get("paths", []), start=1):
            findings.append(REFinding(
                finding_id=f"FLOW-{idx:03d}",
                title="Source-to-sink execution chain",
                category="Data Flow",
                severity="Medium",
                confidence="Medium",
                explanation="A data flow from sensitive source to sink was observed through the call graph.",
                execution_path=path.get("execution_chain", []),
                data_flow=path.get("execution_chain", []),
                runtime_dependencies=[p for p in path.get("preconditions", []) if "runtime" in p.lower()],
                native_linkage=[l.get("method") for l in ctx.artifacts.get("native", {}).get("jni_methods", [])],
                evidence={"sink": path.get("sink")},
                preconditions=path.get("preconditions", [])
            ))

        for refl in ctx.artifacts.get("obfuscation", {}).get("reflection", []):
            findings.append(REFinding(
                finding_id=f"REFL-{len(findings)+1:03d}",
                title="Reflection requires runtime resolution",
                category="Obfuscation/Reflection",
                severity="Info",
                confidence="Low",
                explanation="Reflection call detected; target resolution depends on runtime values.",
                execution_path=[refl.get("location", "")],
                runtime_dependencies=["reflection_target"],
                evidence=refl
            ))

        return findings


def run_apk_reverse_engineering_pipeline(apk_path: str,
                                         tools_status: Optional[Dict[str, Any]] = None,
                                         runtime_feedback: Optional[Dict[str, Any]] = None) -> StructuredREOutput:
    """Why: Provides a single, explicit entry point for the RE pipeline."""
    if tools_status is None:
        tools_status = APKReverseDependencyManager().ensure_all_tools()
    pipeline = APKReverseEngineeringPipeline(tools_status=tools_status)
    return pipeline.run(apk_path=apk_path, runtime_feedback=runtime_feedback)

# ============================================================================
# END OF APK REVERSE ENGINEERING MODULE
