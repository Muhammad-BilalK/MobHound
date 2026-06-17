"""
MobHound - RE UI Threads
==========================
QThread classes for the RE module UI.
Separated from backend logic so apk_reverse_engineering_backend.py
can be imported without PySide6 in headless/CLI environments.

These threads are thin wrappers that delegate to REService.
"""

from __future__ import annotations

import platform
import subprocess
import zipfile
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from PySide6.QtCore import QThread, Signal

from reverse_engineering.re_backend_service import REService, REResult


class APKToolCheckThread(QThread):
    """Check and install RE tools in background."""
    progress_update = Signal(int, str)
    result_ready    = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._service = REService()

    def run(self):
        try:
            self.progress_update.emit(10, "Initializing...")
            self.progress_update.emit(40, "Checking tools...")
            status = self._service.check_tools()
            self.progress_update.emit(80, "Verifying installations...")
            # If tools missing, try to install
            if not all(status.values()):
                self.progress_update.emit(85, "Installing missing tools...")
                full_status = self._service.install_tools(
                    progress_callback=lambda msg, pct: self.progress_update.emit(
                        85 + int(pct * 0.14), msg
                    )
                )
                status.update(full_status)
            self.progress_update.emit(100, "Ready")
            self.result_ready.emit(status)
        except Exception as e:
            self.result_ready.emit({"error": str(e)})


class APKAnalysisThread(QThread):
    """Run full RE analysis in background."""
    progress_update = Signal(int, str)
    result_ready    = Signal(object)    # REResult
    error_signal    = Signal(str)

    def __init__(self, apk_path: str, project_dir: Optional[Path] = None, parent=None):
        super().__init__(parent)
        self._apk_path    = apk_path
        self._project_dir = project_dir
        self._service     = REService()

    def run(self):
        try:
            def _progress(stage: str, pct: int):
                self.progress_update.emit(pct, stage)

            result: REResult = self._service.analyze(
                apk_path=self._apk_path,
                project_dir=self._project_dir,
                progress_callback=_progress,
            )

            if result.errors:
                self.error_signal.emit("\n".join(result.errors))
            else:
                self.result_ready.emit(result)

        except Exception as e:
            self.error_signal.emit(str(e))


class APKDecompilationThread(QThread):
    """
    Lightweight decompilation thread (JADX + APKTool only).
    Delegates actual work to REService.analyze().
    """
    progress_update = Signal(int, str)
    result_ready    = Signal(bool, str, dict)

    def __init__(self, apk_path: str, output_dir: Path,
                 tools_status: Optional[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        self._apk_path    = apk_path
        self._output_dir  = output_dir
        self._tools_status= tools_status or {}
        self._service     = REService()

    def run(self):
        try:
            def _progress(stage: str, pct: int):
                self.progress_update.emit(pct, stage)

            project_dir = self._output_dir / Path(self._apk_path).stem
            project_dir.mkdir(parents=True, exist_ok=True)

            result: REResult = self._service.analyze(
                apk_path=self._apk_path,
                project_dir=project_dir,
                progress_callback=_progress,
            )

            results_dict = {
                "success":       not bool(result.errors),
                "project_dir":   str(project_dir),
                "jadx_output":   str(result.jadx_output_dir)    if result.jadx_output_dir    else None,
                "apktool_output":str(result.apktool_output_dir) if result.apktool_output_dir else None,
                "package_name":  result.package_name,
                "errors":        result.errors,
            }

            if result.errors:
                self.result_ready.emit(False, "; ".join(result.errors), results_dict)
            else:
                self.result_ready.emit(True, "Decompilation complete", results_dict)

        except Exception as e:
            self.result_ready.emit(False, f"Error: {e}", {})
