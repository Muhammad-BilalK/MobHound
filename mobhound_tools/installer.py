from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Optional


def get_managed_tools_dir() -> Path:
    try:
        from config import config

        return Path(config.paths.tools_dir).resolve()
    except Exception:
        return (Path.cwd() / ".mobhound_tools").resolve()


@dataclass
class ToolInstallResult:
    name: str
    available: bool
    path: Optional[str] = None
    error: Optional[str] = None


class ToolInstaller:
    PLATFORM_TOOLS_URLS = {
        "windows": "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
        "linux": "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
        "darwin": "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
    }

    def __init__(self, tools_dir: Optional[Path] = None):
        self.tools_dir = (tools_dir or get_managed_tools_dir()).resolve()
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.tools_dir / "install.log"

    def ensure_tools(self, names: Iterable[str]) -> Dict[str, ToolInstallResult]:
        return {name: self.ensure_tool(name) for name in names}

    def ensure_tool(self, name: str) -> ToolInstallResult:
        normalized = name.strip().lower()
        try:
            if normalized in {"adb", "platform-tools"}:
                return self.ensure_adb()
            if normalized in {"jadx", "apktool", "dex2jar", "reverse-engineering", "reverse_engineering"}:
                return self.ensure_reverse_engineering_tools(normalized)
            if normalized == "mitmproxy":
                return self.ensure_python_tool("mitmproxy", "mitmproxy_env", "mitmdump")
            if normalized == "frida":
                return self.ensure_python_tool("frida", "frida_env", "frida", extra_packages=["frida-tools"])
            return ToolInstallResult(normalized, False, error=f"Unknown tool: {name}")
        except Exception as exc:
            self.log(f"{normalized} install failed: {exc}", "ERROR")
            return ToolInstallResult(normalized, False, error=str(exc))

    def ensure_adb(self) -> ToolInstallResult:
        system_hit = shutil.which("adb")
        if system_hit:
            return ToolInstallResult("adb", True, system_hit)

        adb_path = self._managed_adb_candidate()
        if adb_path.exists():
            return ToolInstallResult("adb", True, str(adb_path))

        system_key = platform.system().lower()
        tools_url = self.PLATFORM_TOOLS_URLS.get(system_key)
        if not tools_url:
            return ToolInstallResult("adb", False, error=f"Unsupported OS: {platform.system()}")

        archive_path = self.tools_dir / Path(tools_url).name
        self.log(f"Downloading Android platform-tools from {tools_url}")
        self.download(tools_url, archive_path)

        try:
            with zipfile.ZipFile(archive_path, "r") as zip_file:
                zip_file.extractall(self.tools_dir)
        finally:
            archive_path.unlink(missing_ok=True)

        if not adb_path.exists():
            return ToolInstallResult("adb", False, error="platform-tools extracted, but adb was not found")

        if system_key != "windows":
            adb_path.chmod(adb_path.stat().st_mode | 0o111)

        self.save_setting("adb_path", str(adb_path))
        return ToolInstallResult("adb", True, str(adb_path))

    def ensure_reverse_engineering_tools(self, requested: str) -> ToolInstallResult:
        from reverse_engineering.apk_reverse_engineering_backend import APKReverseDependencyManager

        status = APKReverseDependencyManager().ensure_all_tools()
        if requested in {"reverse-engineering", "reverse_engineering"}:
            return ToolInstallResult(
                requested,
                bool(status.get("all_ready")),
                str(self.tools_dir) if status.get("all_ready") else None,
                None if status.get("all_ready") else "Reverse engineering tools are not ready",
            )

        tool_status = status.get(requested, {})
        return ToolInstallResult(
            requested,
            bool(tool_status.get("available")),
            tool_status.get("path"),
            tool_status.get("error"),
        )

    def ensure_python_tool(
        self,
        package: str,
        env_name: str,
        binary_name: str,
        extra_packages: Optional[Iterable[str]] = None,
    ) -> ToolInstallResult:
        system_hit = shutil.which(binary_name)
        if system_hit:
            return ToolInstallResult(package, True, system_hit)

        env_dir = self.tools_dir / env_name
        managed_hit = self._venv_tool(env_dir, binary_name)
        if managed_hit.exists():
            return ToolInstallResult(package, True, str(managed_hit))

        self.log(f"Installing {package} into {env_dir}")
        self._ensure_venv(env_dir)
        python_path = self._venv_python(env_dir)
        packages = ["pip", package, *(extra_packages or [])]
        install = subprocess.run(
            [str(python_path), "-m", "pip", "install", "--upgrade", *packages],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if install.returncode != 0:
            error = install.stderr.strip() or install.stdout.strip() or "unknown pip error"
            return ToolInstallResult(package, False, error=error)

        if not managed_hit.exists():
            return ToolInstallResult(package, False, error=f"{binary_name} was not found after install")

        self.save_setting(f"{package}_path", str(managed_hit))
        return ToolInstallResult(package, True, str(managed_hit))

    def download(self, url: str, dest: Path) -> None:
        temp_file = dest.with_suffix(dest.suffix + ".downloading")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/octet-stream",
        }
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=180) as response:
                with open(temp_file, "wb") as file_obj:
                    shutil.copyfileobj(response, file_obj)
            temp_file.replace(dest)
        except (urllib.error.URLError, OSError):
            temp_file.unlink(missing_ok=True)
            raise

    def save_setting(self, key: str, value: str) -> None:
        settings_path = self.tools_dir / "settings.json"
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8")) if settings_path.exists() else {}
        except (json.JSONDecodeError, OSError):
            data = {}
        data[key] = value
        settings_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def log(self, message: str, level: str = "INFO") -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a", encoding="utf-8") as file_obj:
            file_obj.write(f"[{timestamp}] [{level}] {message}\n")

    def _managed_adb_candidate(self) -> Path:
        adb_name = "adb.exe" if platform.system().lower() == "windows" else "adb"
        return self.tools_dir / "platform-tools" / adb_name

    def _ensure_venv(self, env_dir: Path) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "venv", str(env_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"Failed to create {env_dir}")

    def _venv_python(self, env_dir: Path) -> Path:
        if platform.system().lower() == "windows":
            return env_dir / "Scripts" / "python.exe"
        return env_dir / "bin" / "python"

    def _venv_tool(self, env_dir: Path, name: str) -> Path:
        if platform.system().lower() == "windows":
            return env_dir / "Scripts" / f"{name}.exe"
        return env_dir / "bin" / name


def ensure_tools(names: Iterable[str], tools_dir: Optional[Path] = None) -> Dict[str, ToolInstallResult]:
    return ToolInstaller(tools_dir=tools_dir).ensure_tools(names)
