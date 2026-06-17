from __future__ import annotations

import argparse
import json
import lzma
import os
import platform
import re
import socket
import shutil
import subprocess
import sys
import threading
from concurrent.futures import Future, ThreadPoolExecutor
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from mobhound_tools.installer import ToolInstaller, get_managed_tools_dir


class EmulatorConnectionError(RuntimeError):
    """Raised when emulator connection setup fails."""


class InterceptionError(RuntimeError):
    """Raised when mitmproxy interception setup fails."""


class HTTPFlowProcessor:
    """Process captured HTTP flows from mitmproxy and filter/parse them."""

    def __init__(self, capture_file: Path, callback=None):
        """
        Initialize processor for mitmproxy JSONL capture file.
        
        Args:
            capture_file: Path to mitmproxy captured_flows.jsonl
            callback: Optional callback function(flow_data) for each processed flow
        """
        self.capture_file = capture_file
        self.callback = callback
        self.last_position = 0
        self.processed_flows = set()
        
        # File types to ignore (media, styles, fonts)
        self.ignored_types = {
            ".css", ".scss", ".less",
            ".gif", ".png", ".svg", ".bmp", ".webp",
            ".jpg", ".jpeg", ".tiff",
            ".webm", ".mp4", ".mpeg", ".mov", ".avi",
            ".woff", ".woff2", ".ttf", ".eot", ".otf", ".ico",
            ".mp3", ".wav", ".aac",
        }
        
        # Hosts to block (analytics, ads, tracking)
        self.blocked_hosts = {
            "google.com", "google-analytics.com", "googletagmanager.com",
            "facebook.com", "fbcdn.net",
            "doubleclick.net",
            "amazon-adsystem.com",
            "criteo.com",
        }

    def _is_ignored_type(self, url: str) -> bool:
        """Check if URL path ends with ignored file type."""
        # Extract path from URL
        try:
            path = url.split("?")[0].split("#")[0].lower()
            for ext in self.ignored_types:
                if path.endswith(ext):
                    return True
        except Exception:
            pass
        return False

    def _is_allowed_host(self, host: str) -> bool:
        """Check if host is not in blocked list."""
        if not host:
            return False
        host_lower = host.lower()
        for blocked in self.blocked_hosts:
            if host_lower.endswith(blocked) or blocked in host_lower:
                return False
        return True

    def _extract_host_from_url(self, url: str) -> Optional[str]:
        """Extract hostname from URL/authority/connect target."""
        try:
            target = (url or "").strip()
            if not target:
                return None

            parsed = urlparse(target)
            # Covers http/https/ws/wss and any URL with a valid netloc.
            if parsed.hostname:
                return parsed.hostname

            # CONNECT-style authority form like "example.com:443"
            # (and also handles plain host values).
            authority = target.split("/", 1)[0]
            authority = authority.split("?", 1)[0].split("#", 1)[0]
            if authority.startswith("[") and "]" in authority:
                # IPv6 literal: [::1]:443 -> ::1
                return authority[1:authority.find("]")]
            if ":" in authority:
                host_part = authority.rsplit(":", 1)[0].strip()
                if host_part:
                    return host_part
            if authority:
                return authority
        except Exception:
            pass
        return None

    def process_flow(self, flow_data: Dict) -> bool:
        """
        Process a single mitmproxy flow JSON object.
        
        Returns True if flow was processed (not filtered out), False if ignored.
        """
        try:
            request = flow_data.get("request", {})
            response = flow_data.get("response", {})
            method = str(request.get("method", "GET") or "GET").upper()
            url = str(request.get("url", "") or "").strip()
            headers = request.get("headers", {}) or {}
            host_header = str(headers.get("Host", "") or headers.get("host", "") or "").strip()
            if not url and host_header:
                # For CONNECT/tunnel-like entries, URL may be empty while Host is present.
                url = host_header
            
            if not url:
                return False
            
            # Skip ignored file types for classic URL-style requests only.
            if "://" in url and self._is_ignored_type(url):
                return False
            
            error_text = str(response.get("error", "") or "").strip()

            # Extract and validate host
            host = self._extract_host_from_url(url)
            if not host and host_header:
                host = self._extract_host_from_url(host_header)
            if not host:
                return False
            # Keep failure flows even for blocked hosts; they are useful diagnostics.
            if not error_text and not self._is_allowed_host(host):
                return False
            
            # Extract app tag
            app_tag = flow_data.get("app", "")
            
            # Create unique flow identifier to avoid duplicates
            flow_id = hash((url, response.get("status_code", 0), flow_data.get("timestamp", "")))
            if flow_id in self.processed_flows:
                return False
            self.processed_flows.add(flow_id)
            
            # Normalize flow data for processing
            processed_flow = {
                "timestamp": flow_data.get("timestamp", ""),
                "app": app_tag,
                "request": {
                    "method": method,
                    "url": url,
                    "host": host,
                    "headers": headers,
                    "body": request.get("body", ""),
                },
                "response": {
                    "status_code": response.get("status_code", 0),
                    "reason": response.get("reason", ""),
                    "headers": response.get("headers", {}),
                    "body": response.get("body", ""),
                    "error": error_text,
                },
            }
            
            # Call callback if provided
            if self.callback:
                self.callback(processed_flow)
            
            return True
            
        except Exception as e:
            print(f"[HTTPFlowProcessor] Error processing flow: {e}")
            return False

    def read_new_flows(self) -> int:
        """
        Read any new flows from capture file since last read.
        
        Returns:
            Number of new flows processed
        """
        if not self.capture_file.exists():
            return 0
        
        count = 0
        try:
            with open(self.capture_file, "r", encoding="utf-8", errors="replace") as f:
                # Seek to last known position
                if self.last_position > 0:
                    f.seek(self.last_position)
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        flow_data = json.loads(line)
                        if self.process_flow(flow_data):
                            count += 1
                    except json.JSONDecodeError:
                        continue
                
                # Save new position
                self.last_position = f.tell()
        
        except Exception as e:
            print(f"[HTTPFlowProcessor] Error reading flows: {e}")
        
        return count


class HTTPProcessorThread(threading.Thread):
    """Background thread that continuously processes HTTP flows."""
    
    def __init__(self, processor: HTTPFlowProcessor, poll_interval: float = 1.0):
        """
        Initialize background processor thread.
        
        Args:
            processor: HTTPFlowProcessor instance
            poll_interval: Time in seconds between polls for new flows
        """
        super().__init__(daemon=True)
        self.processor = processor
        self.poll_interval = poll_interval
        self.running = False
        self._stop_event = threading.Event()
    
    def run(self):
        """Main thread loop - continuously monitor and process flows."""
        self.running = True
        print("[HTTPProcessorThread] Started background HTTP flow processor")
        
        try:
            while not self._stop_event.is_set():
                try:
                    count = self.processor.read_new_flows()
                    if count > 0:
                        print(f"[HTTPProcessorThread] Processed {count} new flow(s)")
                except Exception as e:
                    print(f"[HTTPProcessorThread] Error in processing loop: {e}")
                
                # Wait before next poll
                self._stop_event.wait(self.poll_interval)
        
        finally:
            self.running = False
            print("[HTTPProcessorThread] HTTP flow processor stopped")
    
    def stop(self):
        """Stop the background thread."""
        self._stop_event.set()
        self.join(timeout=5)


@dataclass
class AndroidDevice:
    serial: str
    state: str
    is_emulator: bool
    model: str = "unknown"
    manufacturer: str = "unknown"
    android_version: str = "unknown"
    abi: str = "unknown"
    qemu: str = "unknown"
    transport: str = "unknown"


@dataclass
class HealthCheckResult:
    ok: bool
    details: Dict[str, str]


@dataclass
class EmulatorConnectionResult:
    connected: bool
    adb_path: str
    serial: Optional[str] = None
    message: str = ""
    device: Optional[AndroidDevice] = None


class AndroidEmulatorConnector:
    """ADB-based connector used as the first step for dynamic analysis."""

    PLATFORM_TOOLS_URLS = {
        "windows": "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
        "linux": "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
        "darwin": "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
    }

    def __init__(
        self,
        adb_path: Optional[str] = None,
        timeout: int = 20,
        auto_download_adb: bool = True,
        managed_tools_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.auto_download_adb = auto_download_adb
        self.managed_tools_dir = managed_tools_dir or get_managed_tools_dir()
        self.tool_installer = ToolInstaller(self.managed_tools_dir)
        self.config_path = self.managed_tools_dir / "settings.json"
        self.adb_path = adb_path or self._find_adb_binary()

    def load_config(self) -> Dict[str, str]:
        if not self.config_path.exists():
            return {}
        try:
            return json.loads(self.config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def save_config(self, data: Dict[str, str]) -> None:
        self.managed_tools_dir.mkdir(parents=True, exist_ok=True)
        current = self.load_config()
        current.update(data)
        self.config_path.write_text(json.dumps(current, indent=2), encoding="utf-8")

    def _managed_adb_candidate(self) -> Path:
        adb_name = "adb.exe" if platform.system().lower() == "windows" else "adb"
        return self.managed_tools_dir / "platform-tools" / adb_name

    def _find_adb_binary(self) -> str:
        """Resolve adb binary from PATH or common Android SDK locations."""
        path_hit = shutil.which("adb")
        if path_hit:
            return path_hit

        candidates = []
        env_roots = [
            os.environ.get("ANDROID_SDK_ROOT"),
            os.environ.get("ANDROID_HOME"),
        ]
        for root in env_roots:
            if root:
                root_path = Path(root)
                candidates.append(root_path / "platform-tools" / "adb")
                candidates.append(root_path / "platform-tools" / "adb.exe")

        user_home = Path.home()
        if platform.system().lower() == "windows":
            candidates.extend(
                [
                    user_home / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe",
                    Path("C:/Android/Sdk/platform-tools/adb.exe"),
                ]
            )
        else:
            candidates.extend(
                [
                    user_home / "Android" / "Sdk" / "platform-tools" / "adb",
                    Path("/opt/android-sdk/platform-tools/adb"),
                ]
            )

        candidates.append(self._managed_adb_candidate())

        for candidate in candidates:
            if candidate.exists():
                return str(candidate)

        if self.auto_download_adb:
            result = self.tool_installer.ensure_adb()
            if result.available and result.path:
                return result.path
            raise EmulatorConnectionError(result.error or "Unable to auto-install adb.")

        raise EmulatorConnectionError("Unable to locate adb. Enable auto-download or install Android platform-tools.")

    def _download_and_install_adb(self) -> str:
        system_key = platform.system().lower()
        tools_url = self.PLATFORM_TOOLS_URLS.get(system_key)
        if not tools_url:
            raise EmulatorConnectionError(f"Unsupported OS for automatic adb setup: {platform.system()}")

        self.managed_tools_dir.mkdir(parents=True, exist_ok=True)
        archive_name = Path(tools_url).name
        archive_path = self.managed_tools_dir / archive_name

        try:
            urllib.request.urlretrieve(tools_url, archive_path)
        except (urllib.error.URLError, OSError) as exc:
            raise EmulatorConnectionError(
                f"Failed to download adb from {tools_url}. Check internet access and retry."
            ) from exc

        try:
            with zipfile.ZipFile(archive_path, "r") as zip_file:
                zip_file.extractall(self.managed_tools_dir)
        except zipfile.BadZipFile as exc:
            raise EmulatorConnectionError("Downloaded platform-tools archive is invalid or corrupted.") from exc
        finally:
            archive_path.unlink(missing_ok=True)

        adb_path = self._managed_adb_candidate()
        if not adb_path.exists():
            raise EmulatorConnectionError("platform-tools extracted, but adb binary was not found.")

        if system_key != "windows":
            adb_path.chmod(adb_path.stat().st_mode | 0o111)

        return str(adb_path)

    def _run_adb(self, args: List[str]) -> subprocess.CompletedProcess:
        command = [self.adb_path, *args]
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout,
            check=False,
        )

    def _run_adb_shell(self, serial: str, shell_args: List[str]) -> subprocess.CompletedProcess:
        return self._run_adb(["-s", serial, "shell", *shell_args])

    def start_server(self) -> None:
        result = self._run_adb(["start-server"])
        if result.returncode != 0:
            raise EmulatorConnectionError(result.stderr.strip() or "adb start-server failed")

    def connect(self, target: str) -> str:
        """Connect to an emulator endpoint such as 127.0.0.1:5555."""
        result = self._run_adb(["connect", target])
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        lowered = output.lower()

        if result.returncode == 0 and ("connected" in lowered or "already connected" in lowered):
            self.save_config({"last_target": target})
            return output

        raise EmulatorConnectionError(output or f"Unable to connect to emulator target: {target}")

    def _device_getprop_map(self, serial: str) -> Dict[str, str]:
        result = self._run_adb_shell(serial, ["getprop"])
        if result.returncode != 0:
            return {}

        props: Dict[str, str] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            match = re.match(r"^\[(.+?)\]:\s*\[(.*?)\]$", line)
            if not match:
                continue
            props[match.group(1)] = match.group(2)
        return props

    def _is_emulator_from_props(self, serial: str, props: Dict[str, str]) -> bool:
        if serial.startswith("emulator-") or serial.startswith("127.0.0.1:"):
            return True

        qemu = props.get("ro.kernel.qemu", "")
        if qemu == "1":
            return True

        hardware = (props.get("ro.hardware", "") + " " + props.get("ro.boot.hardware", "")).lower()
        return any(token in hardware for token in ["goldfish", "ranchu", "vbox", "emulator"])

    def list_devices(self, include_properties: bool = True) -> List[AndroidDevice]:
        result = self._run_adb(["devices"])
        if result.returncode != 0:
            raise EmulatorConnectionError(result.stderr.strip() or "adb devices failed")

        devices: List[AndroidDevice] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("list of devices"):
                continue

            columns = line.split()
            if len(columns) < 2:
                continue

            serial, state = columns[0], columns[1]
            props: Dict[str, str] = {}
            if include_properties and state == "device":
                props = self._device_getprop_map(serial)

            is_emulator = self._is_emulator_from_props(serial, props)
            device = AndroidDevice(
                serial=serial,
                state=state,
                is_emulator=is_emulator,
                model=props.get("ro.product.model", "unknown"),
                manufacturer=props.get("ro.product.manufacturer", "unknown"),
                android_version=props.get("ro.build.version.release", "unknown"),
                abi=props.get("ro.product.cpu.abi", "unknown"),
                qemu=props.get("ro.kernel.qemu", "unknown"),
                transport="tcp" if ":" in serial else "usb",
            )
            devices.append(device)
        return devices

    def select_emulator(self, preferred_serial: Optional[str] = None) -> Optional[AndroidDevice]:
        devices = self.list_devices(include_properties=True)
        healthy = [d for d in devices if d.state == "device"]

        if preferred_serial:
            for dev in healthy:
                if dev.serial == preferred_serial:
                    return dev
            return None

        emulators = [d for d in healthy if d.is_emulator]
        if emulators:
            return emulators[0]

        return healthy[0] if healthy else None

    def verify_shell_access(self, serial: str) -> None:
        result = self._run_adb_shell(serial, ["getprop", "ro.build.version.release"])
        if result.returncode != 0:
            raise EmulatorConnectionError(
                result.stderr.strip() or f"Connected to {serial}, but adb shell check failed"
            )

    def run_health_check(self, serial: str) -> HealthCheckResult:
        checks = {
            "device_state": self._run_adb(["-s", serial, "get-state"]),
            "shell_access": self._run_adb_shell(serial, ["echo", "mobhound_ok"]),
            "package_manager": self._run_adb_shell(serial, ["pm", "path", "android"]),
            "android_version": self._run_adb_shell(serial, ["getprop", "ro.build.version.release"]),
        }

        details: Dict[str, str] = {}
        ok = True
        for name, result in checks.items():
            output = (result.stdout or result.stderr or "").strip()
            passed = result.returncode == 0 and bool(output)
            details[name] = "OK" if passed else f"FAIL: {output or 'no output'}"
            ok = ok and passed

        return HealthCheckResult(ok=ok, details=details)

    def list_installed_packages(self, serial: str, user_only: bool = True) -> List[str]:
        cmd = ["pm", "list", "packages"]
        if user_only:
            cmd.append("-3")
        result = self._run_adb_shell(serial, cmd)
        if result.returncode != 0:
            raise EmulatorConnectionError(result.stderr.strip() or "Unable to list installed apps.")

        packages: List[str] = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            pkg = line.split("package:", 1)[1].strip()
            if pkg:
                packages.append(pkg)
        return sorted(set(packages))

    def launch_app(self, serial: str, package_name: str) -> None:
        launch = self._run_adb(
            [
                "-s",
                serial,
                "shell",
                "monkey",
                "-p",
                package_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ]
        )
        if launch.returncode != 0:
            details = launch.stderr.strip() or launch.stdout.strip() or "unknown launch failure"
            raise EmulatorConnectionError(f"Failed to launch app {package_name}: {details}")

    def force_stop_app(self, serial: str, package_name: str) -> None:
        self._run_adb(["-s", serial, "shell", "am", "force-stop", package_name])

    def install_apk(self, serial: str, apk_path: str) -> Tuple[str, Optional[str]]:
        before = set(self.list_installed_packages(serial, user_only=False))
        install = self._run_adb(["-s", serial, "install", "-r", apk_path])
        output = ((install.stdout or "") + "\n" + (install.stderr or "")).strip()
        if install.returncode != 0 or "Success" not in output:
            raise EmulatorConnectionError(output or "APK install failed.")
        after = set(self.list_installed_packages(serial, user_only=False))
        new_packages = sorted(after - before)
        detected_package = new_packages[0] if len(new_packages) == 1 else None
        return output, detected_package


class MitmProxyInterceptor:
    """Manage mitmproxy capture lifecycle and ADB proxy/certificate wiring."""

    def __init__(
        self,
        connector: AndroidEmulatorConnector,
        host: str = "127.0.0.1",
        port: int = 8080,
        auto_install_mitmproxy: bool = True,
    ):
        self.connector = connector
        self.host = host
        self.port = port
        self.auto_install_mitmproxy = auto_install_mitmproxy
        self.mitm_env_dir = self.connector.managed_tools_dir / "mitmproxy_env"
        self.mitm_bin = self._find_mitm_binary()
        self.capture_dir = self.connector.managed_tools_dir / "mitmproxy"
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.capture_file = self.capture_dir / "captured_flows.jsonl"
        self.addon_file = self.capture_dir / "capture_addon.py"
        self.process: Optional[subprocess.Popen] = None
        
        # HTTP Flow Processor for continuous analysis
        self.flow_processor: Optional[HTTPFlowProcessor] = None
        self.processor_thread: Optional[HTTPProcessorThread] = None

    def _proxy_host_for_device(self, device: AndroidDevice) -> str:
        # For adb-over-tcp devices, prefer a host IP reachable by the device.
        if ":" in device.serial:
            target_host = device.serial.split(":", 1)[0].strip()
            if target_host and target_host not in ("127.0.0.1", "localhost"):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.connect((target_host, 1))
                        routed_host_ip = sock.getsockname()[0]
                    if routed_host_ip and routed_host_ip not in ("0.0.0.0", "127.0.0.1"):
                        return routed_host_ip
                except OSError:
                    pass

            # If the ADB serial is loopback-mounted and the device is an emulator, use emulator host mapping.
            if target_host in ("127.0.0.1", "localhost"):
                if "vbox" in (device.qemu or "").lower():
                    return "10.0.3.2"
                return "10.0.2.2"

        # Android Emulator maps host loopback to 10.0.2.2 when the emulator is local.
        if device.serial.startswith("emulator-") or device.is_emulator:
            if "vbox" in (device.qemu or "").lower():
                return "10.0.3.2"
            return "10.0.2.2"

        # If the connector explicitly configured a reachable host, prefer it.
        if self.host and self.host not in ("127.0.0.1", "localhost", ""):
            return self.host

        # Fall back to a local non-loopback IP if available.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 53))
                local_ip = sock.getsockname()[0]
            if local_ip and not local_ip.startswith("127."):
                return local_ip
        except OSError:
            pass

        return self.host or "127.0.0.1"

    def _managed_mitm_candidate(self) -> Path:
        if platform.system().lower() == "windows":
            return self.mitm_env_dir / "Scripts" / "mitmdump.exe"
        return self.mitm_env_dir / "bin" / "mitmdump"

    def _managed_pip_candidate(self) -> Path:
        if platform.system().lower() == "windows":
            return self.mitm_env_dir / "Scripts" / "pip.exe"
        return self.mitm_env_dir / "bin" / "pip"

    def _managed_python_candidate(self) -> Path:
        if platform.system().lower() == "windows":
            return self.mitm_env_dir / "Scripts" / "python.exe"
        return self.mitm_env_dir / "bin" / "python"

    def _is_port_in_use(self, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex(("127.0.0.1", port)) == 0

    def _select_mitm_port(self, preferred_port: int, fallback_range: int = 5) -> int:
        if not self._is_port_in_use(preferred_port):
            return preferred_port
        for offset in range(1, fallback_range + 1):
            candidate = preferred_port + offset
            if not self._is_port_in_use(candidate):
                return candidate
        raise InterceptionError(
            f"Unable to start mitmproxy because ports {preferred_port} through {preferred_port + fallback_range} are already in use. "
            f"Stop the conflicting process or configure a different proxy port."
        )

    def _find_mitm_binary(self) -> str:
        for binary in ("mitmdump", "mitmproxy"):
            hit = shutil.which(binary)
            if hit:
                return hit

        managed = self._managed_mitm_candidate()
        if managed.exists():
            return str(managed)

        if self.auto_install_mitmproxy:
            result = self.connector.tool_installer.ensure_python_tool("mitmproxy", "mitmproxy_env", "mitmdump")
            if result.available and result.path:
                return result.path
            raise InterceptionError(result.error or "Failed to auto-install mitmproxy.")

        raise InterceptionError("mitmproxy not found. Enable auto-install or install it manually.")

    def _install_mitmproxy(self) -> str:
        self.connector.managed_tools_dir.mkdir(parents=True, exist_ok=True)

        venv_result = subprocess.run(
            [sys.executable, "-m", "venv", str(self.mitm_env_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if venv_result.returncode != 0:
            raise InterceptionError(
                venv_result.stderr.strip() or "Failed to create managed Python environment for mitmproxy."
            )

        python_path = self._managed_python_candidate()
        if not python_path.exists():
            raise InterceptionError("Managed Python was not created for mitmproxy installation.")

        install_result = subprocess.run(
            [str(python_path), "-m", "pip", "install", "--upgrade", "pip", "mitmproxy"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if install_result.returncode != 0:
            details = install_result.stderr.strip() or install_result.stdout.strip() or "unknown pip error"
            raise InterceptionError(f"Failed to auto-install mitmproxy: {details}")

        managed = self._managed_mitm_candidate()
        if not managed.exists():
            raise InterceptionError("mitmproxy installation completed, but mitmdump binary was not found.")
        return str(managed)

    def _write_addon_file(self) -> None:
        addon_code = """
import json
import os
import sys
from datetime import datetime
from mitmproxy import http

CAPTURE_PATH = os.environ.get("MOBHOUND_CAPTURE_PATH")
DEBUG_LOG = os.environ.get("MOBHOUND_DEBUG")

def _debug_log(msg):
    if DEBUG_LOG:
        try:
            with open(DEBUG_LOG, "a") as f:
                f.write(f"[mitmproxy-addon] {msg}\\n")
        except Exception:
            pass

_debug_log(f"Addon loaded. CAPTURE_PATH={CAPTURE_PATH}")

def _safe_decode(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)

def _append_flow(payload):
    if not CAPTURE_PATH:
        _debug_log("ERROR: CAPTURE_PATH not set, flow will not be saved")
        return
    try:
        with open(CAPTURE_PATH, "a", encoding="utf-8") as fp:
            fp.write(json.dumps(payload, ensure_ascii=False) + "\\n")
        _debug_log(f"Flow saved: {payload.get('request', {}).get('url', 'unknown')}")
    except Exception as e:
        _debug_log(f"Exception writing flow: {e}")

def request(flow: http.HTTPFlow):
    try:
        flow.metadata["mobhound_app"] = flow.request.headers.get("x-mobhound-app", "")
        _debug_log(f"Request: {flow.request.pretty_url} app-tag={flow.metadata.get('mobhound_app', '')}")
    except Exception as e:
        _debug_log(f"Exception in request hook: {e}")
        flow.metadata["mobhound_app"] = ""

def response(flow: http.HTTPFlow):
    _debug_log(f"Response: {flow.request.pretty_url} status={flow.response.status_code if flow.response else 'N/A'}")
    app_tag = flow.metadata.get("mobhound_app", "")
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "app": app_tag,
        "request": {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "body": _safe_decode(flow.request.content),
        },
        "response": {
            "status_code": flow.response.status_code if flow.response else 0,
            "reason": flow.response.reason if flow.response else "",
            "headers": dict(flow.response.headers) if flow.response else {},
            "body": _safe_decode(flow.response.content if flow.response else b""),
        },
    }
    _append_flow(payload)

def http_connect(flow: http.HTTPFlow):
    # Record CONNECT attempts so TLS failures are still visible in GUI.
    try:
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "app": flow.request.headers.get("x-mobhound-app", ""),
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": dict(flow.request.headers),
                "body": "",
            },
            "response": {
                "status_code": flow.response.status_code if flow.response else 0,
                "reason": flow.response.reason if flow.response else "CONNECT",
                "headers": dict(flow.response.headers) if flow.response else {},
                "body": "",
                "error": "",
            },
        }
        _append_flow(payload)
    except Exception as e:
        _debug_log(f"Exception in http_connect hook: {e}")

def error(flow: http.HTTPFlow):
    # Capture failed TLS/HTTP flows so the table isn't empty when handshake fails.
    try:
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "app": flow.request.headers.get("x-mobhound-app", ""),
            "request": {
                "method": flow.request.method if flow.request else "",
                "url": flow.request.pretty_url if flow.request else "",
                "headers": dict(flow.request.headers) if flow.request else {},
                "body": _safe_decode(flow.request.content) if flow.request else "",
            },
            "response": {
                "status_code": 0,
                "reason": "ERROR",
                "headers": {},
                "body": "",
                "error": str(flow.error) if getattr(flow, "error", None) else "unknown proxy error",
            },
        }
        _append_flow(payload)
    except Exception as e:
        _debug_log(f"Exception in error hook: {e}")
"""
        self.addon_file.write_text(addon_code.strip() + "\n", encoding="utf-8")

    def generate_ca_certificate(self) -> Path:
        # Starting mitmdump briefly initializes ~/.mitmproxy and CA files.
        # Some mitmproxy versions do not support --quit, so we run it shortly and terminate.
        proc = subprocess.Popen(
            [self.mitm_bin, "-p", str(self.port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        time.sleep(2)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        _, stderr = proc.communicate()
        cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
        if not cert_path.exists():
            details = (stderr or "").strip()
            message = "mitmproxy CA certificate was not generated."
            if details:
                message = f"{message} mitmdump error: {details}"
            raise InterceptionError(message)
        return cert_path

    def install_ca_on_device(self, serial: str, cert_path: Path) -> str:
        # Different Android builds accept different locations/extensions for cert import.
        remote_candidates = [
            "/data/local/tmp/mitmproxy-ca-cert.cer",
            "/data/local/tmp/mitmproxy-ca-cert.crt",
            "/data/local/mitmproxy-ca-cert.cer",
            "/data/local/mitmproxy-ca-cert.crt",
            "/sdcard/Download/mitmproxy-ca-cert.cer",
            "/sdcard/Download/mitmproxy-ca-cert.crt",
            "/sdcard/mitmproxy-ca-cert.cer",
            "/sdcard/mitmproxy-ca-cert.crt",
        ]
        push_errors: List[str] = []
        pushed_paths: List[str] = []

        for remote_path in remote_candidates:
            push_result = self.connector._run_adb(["-s", serial, "push", str(cert_path), remote_path])
            if push_result.returncode != 0:
                push_errors.append(f"{remote_path}: {push_result.stderr.strip() or push_result.stdout.strip() or 'push failed'}")
                continue
            # Ensure file is readable by installer
            self.connector._run_adb(["-s", serial, "shell", "chmod", "644", remote_path])
            # Some emulator builds need explicit world-readable bit.
            self.connector._run_adb(["-s", serial, "shell", "chmod", "a+r", remote_path])
            check_result = self.connector._run_adb(["-s", serial, "shell", "ls", "-l", remote_path])
            if check_result.returncode == 0:
                pushed_paths.append(remote_path)
            else:
                push_errors.append(f"{remote_path}: pushed but not readable")

        if not pushed_paths:
            detail = "; ".join(push_errors) if push_errors else "No candidate path worked."
            raise InterceptionError(f"Failed to push readable CA certificate to device. {detail}")

        launch_attempts: List[str] = []
        for remote_path in pushed_paths:
            # Try explicit cert installer first, then generic VIEW.
            intents = [
                [
                    "-s", serial, "shell", "am", "start",
                    "-n", "com.android.certinstaller/.CertInstallerMain",
                    "-a", "android.intent.action.VIEW",
                    "-d", f"file://{remote_path}",
                    "-t", "application/x-x509-ca-cert",
                ],
                [
                    "-s", serial, "shell", "am", "start",
                    "-a", "android.intent.action.VIEW",
                    "-d", f"file://{remote_path}",
                    "-t", "application/x-x509-ca-cert",
                ],
            ]
            for intent_cmd in intents:
                open_result = self.connector._run_adb(intent_cmd)
                output = ((open_result.stdout or "") + "\n" + (open_result.stderr or "")).strip()
                launch_attempts.append(f"{remote_path}: {output or 'no output'}")
                if open_result.returncode == 0 and "Error:" not in output and "Activity not started" not in output:
                    return remote_path

        detail = " | ".join(launch_attempts[-6:])
        # Launch Security settings as a final manual fallback entrypoint.
        self.connector._run_adb(
            ["-s", serial, "shell", "am", "start", "-a", "android.settings.SECURITY_SETTINGS"]
        )
        raise InterceptionError(
            "Failed to open certificate installer. Device reported file unreadable or rejected the intent. "
            "On this build, install may require manual selection from Settings > Security > Encryption & credentials > Install a certificate. "
            f"Tried paths: {', '.join(pushed_paths)}. Details: {detail}"
        )

    def set_device_proxy(self, serial: str, proxy_host: str) -> None:
        # Ensure no existing proxy first.
        self.connector._run_adb(["-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0"])
        time.sleep(0.3)
        
        # Now set the new proxy.
        set_result = self.connector._run_adb(
            ["-s", serial, "shell", "settings", "put", "global", "http_proxy", f"{proxy_host}:{self.port}"]
        )
        if set_result.returncode != 0:
            raise InterceptionError(
                f"Failed to set proxy via ADB: {set_result.stderr.strip() or 'Unknown ADB error'}"
            )

        # Verify it was actually set.
        time.sleep(0.5)
        verify_result = self.connector._run_adb(
            ["-s", serial, "shell", "settings", "get", "global", "http_proxy"]
        )
        actual_proxy = (verify_result.stdout or "").strip()
        expected_proxy = f"{proxy_host}:{self.port}"
        if actual_proxy != expected_proxy:
            # Try once more in case of timing issue.
            time.sleep(1)
            verify_result = self.connector._run_adb(
                ["-s", serial, "shell", "settings", "get", "global", "http_proxy"]
            )
            actual_proxy = (verify_result.stdout or "").strip()
        
        if actual_proxy != expected_proxy:
            raise InterceptionError(
                f"Proxy verification failed: set '{expected_proxy}' but device has '{actual_proxy or '(empty)'}'. "
                f"Device may not support http_proxy setting or network stack may be disabled."
            )

    def clear_device_proxy(self, serial: str) -> None:
        self.connector._run_adb(["-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0"])

    def verify_device_proxy(self, serial: str) -> Tuple[bool, str]:
        """Check actual proxy state on device and return detailed diagnostic."""
        verify_result = self.connector._run_adb(
            ["-s", serial, "shell", "settings", "get", "global", "http_proxy"]
        )
        actual = (verify_result.stdout or "").strip()
        if verify_result.returncode != 0:
            return False, f"ADB query failed: {verify_result.stderr.strip()}"
        if not actual or actual == ":0":
            return False, "Proxy is not set on device (value is empty or :0)"
        return True, f"Proxy is set to: {actual}"

    def verify_proxy_reachability(self, serial: str, proxy_host: str, proxy_port: int) -> Tuple[bool, str]:
        """Probe whether the emulator/device can reach the configured proxy host and port."""
        if not proxy_host or proxy_host in ("127.0.0.1", "localhost"):
            return False, "Cannot verify reachability for loopback proxy host from device."

        checks = [
            ("toybox nc", ["sh", "-c", f"toybox nc -z {proxy_host} {proxy_port}" ]),
            ("nc", ["sh", "-c", f"nc -z {proxy_host} {proxy_port}" ]),
            ("ping", ["sh", "-c", f"ping -c 1 {proxy_host}" ]),
        ]

        for label, shell_args in checks:
            result = self.connector._run_adb(["-s", serial, "shell", *shell_args])
            if result.returncode == 0:
                return True, f"Proxy host {proxy_host}:{proxy_port} is reachable using {label}."

        last_msg = (checks[-1][0] if checks else "probe").strip()
        return False, f"Proxy reachability probe failed from device to {proxy_host}:{proxy_port}. ({last_msg})"

    def get_proxy_setup_steps(self, proxy_host: str) -> List[str]:
        return [
            f"ADB command used by MobHound: settings put global http_proxy {proxy_host}:{self.port}",
            f"Manual emulator UI path: Settings > Network & internet > Wi-Fi > active network > Proxy > Manual",
            f"Manual proxy values: Hostname={proxy_host}, Port={self.port}",
            "Verify ADB proxy value with: adb shell settings get global http_proxy",
            "Disable proxy with: adb shell settings put global http_proxy :0",
        ]

    def start(self, device: AndroidDevice, callback=None) -> str:
        if self.process and self.process.poll() is None:
            if callback:
                self.start_flow_processor(callback=callback)
            return self._proxy_host_for_device(device)

        if self.process and self.process.poll() is not None:
            self.process = None

        self._write_addon_file()
        self.capture_file.write_text("", encoding="utf-8")

        # Set up debug logging for addon.
        debug_log_file = self.capture_dir / "mitmproxy_addon_debug.log"
        debug_log_file.write_text("", encoding="utf-8")

        env = os.environ.copy()
        env["MOBHOUND_CAPTURE_PATH"] = str(self.capture_file)
        env["MOBHOUND_DEBUG"] = str(debug_log_file)

        proxy_host = self._proxy_host_for_device(device)
        selected_ports = [self.port] + [self.port + i for i in range(1, 6)]
        last_error = ""

        for candidate_port in selected_ports:
            try:
                candidate_port = self._select_mitm_port(candidate_port)
            except InterceptionError as exc:
                last_error = str(exc)
                continue

            self.port = candidate_port
            self.clear_device_proxy(device.serial)
            try:
                self.set_device_proxy(device.serial, proxy_host)
            except InterceptionError as exc:
                raise InterceptionError(
                    f"Failed to set proxy for mitmproxy start on port {self.port}: {exc}"
                ) from exc

            self.process = subprocess.Popen(
                [self.mitm_bin, "-s", str(self.addon_file), "--listen-host", "0.0.0.0", "-p", str(self.port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )

            time.sleep(1)
            if self.process.poll() is None:
                # mitmproxy started successfully - start flow processor
                self.start_flow_processor(callback=callback)
                return proxy_host

            stdout, stderr = self.process.communicate()
            self.process = None
            details = (stderr or stdout or "").strip() or "mitmdump exited immediately."
            last_error = f"port {self.port}: {details}"

            if "address already in use" in details.lower() or "cannot bind" in details.lower():
                continue
            raise InterceptionError(f"Failed to start interception backend: {details}")

        raise InterceptionError(
            f"Failed to start interception backend after trying ports {selected_ports}: {last_error}"
        )

    def stop(self, serial: str) -> None:
        self.clear_device_proxy(serial)
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None
        self.stop_flow_processor()

    def start_flow_processor(self, callback=None) -> None:
        """Start background HTTP flow processor thread."""
        if self.processor_thread and self.processor_thread.running:
            print("[MitmProxyInterceptor] Flow processor already running")
            return
        
        # Create processor with optional callback
        self.flow_processor = HTTPFlowProcessor(self.capture_file, callback=callback)
        self.processor_thread = HTTPProcessorThread(self.flow_processor, poll_interval=1.0)
        self.processor_thread.start()
        print("[MitmProxyInterceptor] HTTP flow processor started")

    def stop_flow_processor(self) -> None:
        """Stop background HTTP flow processor thread."""
        if self.processor_thread and self.processor_thread.running:
            self.processor_thread.stop()
            print("[MitmProxyInterceptor] HTTP flow processor stopped")
        self.processor_thread = None
        self.flow_processor = None

    def get_flow_statistics(self) -> Dict[str, int]:
        """Get statistics about processed flows."""
        if not self.flow_processor:
            return {"total_processed": 0, "status": "processor not running"}
        
        return {
            "total_processed": len(self.flow_processor.processed_flows),
            "status": "running" if (self.processor_thread and self.processor_thread.running) else "stopped",
            "capture_file_size": self.capture_file.stat().st_size if self.capture_file.exists() else 0,
        }

    def check_backend_health(self) -> Tuple[bool, str]:
        """Check if mitmproxy backend is running and capturing."""
        if not self.process:
            return False, "mitmproxy process not initialized"
        if self.process.poll() is not None:
            return False, "mitmproxy process has exited"
        if not self.capture_file.exists():
            return False, "capture file does not exist"
        return True, "mitmproxy backend healthy"

    def get_addon_debug_log(self) -> str:
        """Retrieve addon debug log to diagnose mitmproxy issues."""
        debug_log_file = self.capture_dir / "mitmproxy_addon_debug.log"
        if not debug_log_file.exists():
            return "Debug log not available"
        try:
            return debug_log_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"Could not read debug log: {e}"

class FridaManager:
    """Manage Frida host tools and frida-server lifecycle on Android."""

    FRIDA_RELEASE_BASE = "https://github.com/frida/frida/releases/download"
    ABI_MAP = {
        "arm64-v8a": "android-arm64",
        "armeabi-v7a": "android-arm",
        "x86_64": "android-x86_64",
        "x86": "android-x86",
    }

    # Root/emulator bypass script (full hooks except SSL re-pinning)
    ROOT_EMULATOR_BYPASS_SCRIPT = r"""
Java.perform(function() {
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk", "frida-server", "frida-agent"];

    var EmulatorFiles = [
        "/dev/qemu_pipe",
        "/dev/socket/qemud",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props"
    ];

    var CustomProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1",
        "ro.kernel.qemu": "0",
        "ro.build.fingerprint": "samsung/starltexx/starlte:10/QP1A.190711.020/G960FXXSDFUG5:user/release-keys",
        "ro.product.brand": "samsung",
        "ro.product.manufacturer": "samsung",
        "ro.product.model": "SM-G960F",
        "ro.product.device": "starlte",
        "ro.hardware": "samsungexynos9810",
        "ro.product.name": "starltexx",
        "ro.serialno": "R28M30XXXX",
        "ro.build.tags": "release-keys",
        "ro.build.type": "user"
    };

    var CustomPropertiesKeys = [];

    for (var k in CustomProperties) CustomPropertiesKeys.push(k);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    var Runtime = Java.use('java.lang.Runtime');
    var NativeFile = Java.use('java.io.File');
    var String = Java.use('java.lang.String');
    var SystemProperties = Java.use('android.os.SystemProperties');
    var BufferedReader = Java.use('java.io.BufferedReader');
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    var Secure = Java.use('android.provider.Settings$Secure');
    var Build = Java.use('android.os.Build');

    Build.DEVICE.value = "starlte";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    Build.MODEL.value = "SM-G960F";
    Build.HARDWARE.value = "samsungexynos9810";
    Build.PRODUCT.value = "starltexx";
    Build.FINGERPRINT.value = "samsung/starltexx/starlte:10/QP1A.190711.020/G960FXXSDFUG5:user/release-keys";
    Build.TAGS.value = "release-keys";
    Build.SERIAL.value = "R28M30XXXX";
    Build.SUPPORTED_ABIS.value = ["armeabi-v7a", "armeabi"];
    Build.CPU_ABI.value = "armeabi-v7a";
    Build.CPU_ABI2.value = "armeabi";

    TelephonyManager.getDeviceId.overload().implementation = function() {
        send("Bypass getDeviceId");
        return "359872070XXXXXX";
    };

    if (TelephonyManager.getImei) {
        TelephonyManager.getImei.overload().implementation = function() {
            send("Bypass getImei");
            return "359872070XXXXXX";
        };
    }

    TelephonyManager.getSubscriberId.overload().implementation = function() {
        send("Bypass getSubscriberId");
        return "310260000000000";
    };

    TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
        send("Bypass getNetworkOperatorName");
        return "T-Mobile";
    };

    TelephonyManager.getSimOperatorName.overload().implementation = function() {
        send("Bypass getSimOperatorName");
        return "T-Mobile";
    };

    TelephonyManager.getPhoneType.overload().implementation = function() {
        send("Bypass getPhoneType");
        return this.PHONE_TYPE_GSM.value;
    };

    TelephonyManager.getNetworkCountryIso.overload().implementation = function() {
        send("Bypass getNetworkCountryIso");
        return "us";
    };

    TelephonyManager.getSimCountryIso.overload().implementation = function() {
        send("Bypass getSimCountryIso");
        return "us";
    };

    Secure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(contentResolver, name) {
        if (name == Secure.ANDROID_ID.value) {
            send("Bypass getString ANDROID_ID");
            return "9774d56d682e549c";
        }
        return this.getString(contentResolver, name);
    };

    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };

    NativeFile.exists.implementation = function() {
        var path = NativeFile.getAbsolutePath.call(this);
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1 || EmulatorFiles.indexOf(path) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for file: " + path);
            return false;
        } else {
            return this.exists.call(this);
        }
    };

    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    var suspiciousCommands = ["getprop", "mount", "build.prop", "id", "sh", "cat /proc/cpuinfo", "ifconfig", "ip addr"];

    function shouldBypassCommand(cmd) {
        for (var i = 0; i < suspiciousCommands.length; i++) {
            if (cmd.indexOf(suspiciousCommands[i]) != -1) {
                return true;
            }
        }
        return false;
    }

    exec1.implementation = function(cmd) {
        if (shouldBypassCommand(cmd)) {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "invalid_command";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };

    var runtimeExecOverloads = Runtime.exec.overloads || [];
    for (var oi = 0; oi < runtimeExecOverloads.length; oi++) {
        (function(overloadRef) {
            overloadRef.implementation = function() {
                var cmd = arguments[0];
                if (cmd && cmd.length !== undefined && typeof cmd !== 'string') {
                    for (var i = 0; i < cmd.length; i++) {
                        var part = String(cmd[i]);
                        if (shouldBypassCommand(part)) {
                            var fakeCmdArr = ["grep"];
                            send("Bypass " + part + " command");
                            return exec.call(this, fakeCmdArr);
                        }
                        if (part == "su") {
                            var fakeSuArr = ["invalid_command"];
                            send("Bypass su command");
                            return exec.call(this, fakeSuArr);
                        }
                    }
                } else if (typeof cmd === 'string') {
                    if (shouldBypassCommand(cmd)) {
                        var fakeCmd = "grep";
                        send("Bypass " + cmd + " command");
                        return exec.call(this, fakeCmd);
                    }
                    if (cmd == "su") {
                        var fakeSu = "invalid_command";
                        send("Bypass " + cmd + " command");
                        return exec.call(this, fakeSu);
                    }
                }
                return overloadRef.apply(this, arguments);
            };
        })(runtimeExecOverloads[oi]);
    }

    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    var get = SystemProperties.get.overload('java.lang.String');

    get.implementation = function(name) {
        if (CustomPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return CustomProperties[name];
        }
        return this.get.call(this, name);
    };

    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            var shouldFakeReturn = (RootBinaries.indexOf(path) > -1 || EmulatorFiles.indexOf(path) > -1);
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("Bypass native fopen for " + path);
            }
        },
        onLeave: function(retval) {
        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (shouldBypassCommand(cmd)) {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "invalid_command");
            }
        },
        onLeave: function(retval) {
        }
    });

    BufferedReader.readLine.overload('boolean').implementation = function() {
        var text = this.readLine.overload('boolean').call(this);
        if (text === null) {
            // do nothing
        } else {
            if (text.indexOf("ro.build.tags=test-keys") > -1) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
            var suspiciousWords = ["goldfish", "ranchu", "generic", "intel", "qemu"];
            for (var i = 0; i < suspiciousWords.length; i++) {
                if (text.indexOf(suspiciousWords[i]) > -1) {
                    send("Bypass emulator detection in file read");
                    text = "";
                    break;
                }
            }
        }
        return text;
    };

    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i++) {
            var tmp_cmd = cmd.get(i).toString();
            if (shouldBypassCommand(tmp_cmd)) {
                shouldModifyCommand = true;
                break;
            }
            if (tmp_cmd == "su") {
                shouldModifyCommand = true;
                break;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        return this.start.call(this);
    };
});
""".strip()

    # Frida detection bypass script
    FRIDA_DETECTION_BYPASS_SCRIPT = r"""
//Bypass Script

Java.perform(function () {
    console.log('[MobHound] Frida detection bypass loading (enhanced)...');

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------
    const SUSPECT_PATHS = [
        '/proc/self/maps',        // main target
        '/proc/net/unix',         // named pipe check
        '/proc/net/tcp',          // port scanner
        '/proc/self/status',      // sometimes checked
        '/proc/self/fd',          // file descriptor enumeration
        '/proc/self/mem'          // suspicious
    ];

    const SUSPECT_KEYWORDS = [
        'frida', 'gum-js-loop', 'gmain', 'linjector',
        're.frida.server', 'frida-server', 'frida-agent',
        'frida-helper', 'frida-gadget', 'frida-agent.so',
        'libfrida', 'frida-', 'FRIDA'
    ];

    const FRIDA_PORT = 27042;
    const FRIDA_PORT_HEX = '699A';  // 27042 in hex, as seen in /proc/net/tcp

    // Helper: case-insensitive test for any keyword in a string
    function containsFridaKeyword(str) {
        if (!str) return false;
        var lower = str.toLowerCase();
        for (var i = 0; i < SUSPECT_KEYWORDS.length; i++) {
            if (lower.indexOf(SUSPECT_KEYWORDS[i].toLowerCase()) !== -1) {
                return true;
            }
        }
        return false;
    }

    // Helper: build a safe replacement for a suspicious line (empty string)
    function redactLine(line) {
        if (containsFridaKeyword(line)) return '';
        // Also kill known pipe names
        if (line.indexOf('linjector') !== -1) return '';
        if (line.indexOf('frida-') !== -1) return '';
        return line;
    }

    // ------------------------------------------------------------------
    // 1. Track file descriptors that point to suspicious paths
    // ------------------------------------------------------------------
    var suspiciousFds = {};

    // Generic open/openat hook that records the fd if path matches
    function hookOpenLike(exportName, pathArgIndex) {
        var sym = Module.findExportByName('libc.so', exportName);
        if (!sym || typeof Interceptor.attach !== 'function') return false;
        try {
            Interceptor.attach(sym, {
            onEnter: function (args) {
                try {
                    var path = Memory.readCString(args[pathArgIndex]);
                    if (path && SUSPECT_PATHS.indexOf(path) !== -1) {
                        this._suspect = true;
                        this._path = path;
                    } else {
                        this._suspect = false;
                    }
                } catch (e) {
                    this._suspect = false;
                }
            },
            onLeave: function (retval) {
                var fd = retval.toInt32();
                if (this._suspect && fd !== -1) {
                    suspiciousFds[fd] = this._path;
                    console.log('[MobHound] marked FD', fd, 'for', this._path);
                }
            }
        });
            return true;
        } catch (e) {
            console.log('[MobHound] failed to hook', exportName, ':', e);
            return false;
        }
    }

    hookOpenLike('open', 0);       // open(path, flags, ...)
    hookOpenLike('openat', 1);     // openat(dirfd, path, ...)

    var fopenSym = Module.findExportByName('libc.so', 'fopen');
    if (fopenSym) {
        Interceptor.attach(fopenSym, {
            onEnter: function (args) {
                try {
                    var path = Memory.readCString(args[0]);
                    if (path && SUSPECT_PATHS.indexOf(path) !== -1) {
                        this._suspect = true;
                        this._path = path;
                    } else {
                        this._suspect = false;
                    }
                } catch (e) {
                    this._suspect = false;
                }
            },
            onLeave: function (retval) {
                // FILE* is not an fd, but we store a pointer as key
                if (this._suspect && retval && !retval.isNull()) {
                    suspiciousFds[retval.toString()] = this._path;
                    console.log('[MobHound] marked FILE*', retval, 'for', this._path);
                }
            }
        });
    }

    // ------------------------------------------------------------------
    // 2. Intercept read operations to filter content
    // ------------------------------------------------------------------
    function isSuspiciousFd(fd) {
        return suspiciousFds[fd] !== undefined;
    }

    // Hook read() - raw file descriptor read
    var readSym = Module.findExportByName('libc.so', 'read');
    if (readSym) {
        Interceptor.attach(readSym, {
            onEnter: function (args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();
            },
            onLeave: function (retval) {
                var n = retval.toInt32();
                if (n <= 0) return;
                if (!isSuspiciousFd(this.fd)) return;
                try {
                    var data = Memory.readByteArray(this.buf, n);
                    var text = '';
                    var arr = new Uint8Array(data);
                    for (var i = 0; i < arr.length; i++) text += String.fromCharCode(arr[i]);
                    var lines = text.split('\n');
                    var filtered = [];
                    for (var i = 0; i < lines.length; i++) {
                        var line = lines[i];
                        var redacted = redactLine(line);
                        if (redacted !== '') filtered.push(redacted);
                    }
                    var outText = filtered.join('\n');
                    // Pad or truncate to original length? We'll write back only up to original count.
                    var outBytes = [];
                    for (var i = 0; i < outText.length && i < n; i++) {
                        outBytes.push(outText.charCodeAt(i));
                    }
                    // Fill remaining with null to avoid leftover data
                    while (outBytes.length < n) outBytes.push(0);
                    Memory.writeByteArray(this.buf, outBytes);
                    retval.replace(ptr(outBytes.length));
                } catch (e) {
                    console.log('[MobHound] read filter error:', e);
                }
            }
        });
    }

    // Hook fread() – for FILE* streams
    var freadSym = Module.findExportByName('libc.so', 'fread');
    if (freadSym) {
        Interceptor.attach(freadSym, {
            onEnter: function (args) {
                this.stream = args[3].toString();
                this.buf = args[0];
                this.size = args[1].toInt32();
                this.nmemb = args[2].toInt32();
                this.total = this.size * this.nmemb;
            },
            onLeave: function (retval) {
                var itemsRead = retval.toInt32();
                if (itemsRead <= 0) return;
                if (!isSuspiciousFd(this.stream)) return;
                try {
                    var data = Memory.readByteArray(this.buf, this.total);
                    var text = '';
                    var arr = new Uint8Array(data);
                    for (var i = 0; i < arr.length; i++) text += String.fromCharCode(arr[i]);
                    var lines = text.split('\n');
                    var filtered = [];
                    for (var i = 0; i < lines.length; i++) {
                        var redacted = redactLine(lines[i]);
                        if (redacted !== '') filtered.push(redacted);
                    }
                    var outText = filtered.join('\n');
                    var outBytes = [];
                    for (var i = 0; i < outText.length && i < this.total; i++) {
                        outBytes.push(outText.charCodeAt(i));
                    }
                    while (outBytes.length < this.total) outBytes.push(0);
                    Memory.writeByteArray(this.buf, outBytes);
                    // Adjust return value: number of items fully read (each item of size 'size')
                    var newItems = Math.floor(outBytes.length / this.size);
                    retval.replace(ptr(newItems));
                } catch (e) {}
            }
        });
    }

    // Hook fgets() – common line‑by‑line reading
    var fgetsSym = Module.findExportByName('libc.so', 'fgets');
    if (fgetsSym) {
        Interceptor.attach(fgetsSym, {
            onEnter: function (args) {
                this.stream = args[2].toString();
                this.buf = args[0];
            },
            onLeave: function (retval) {
                if (retval.isNull()) return;
                if (!isSuspiciousFd(this.stream)) return;
                try {
                    var line = Memory.readCString(this.buf);
                    if (line) {
                        var redacted = redactLine(line);
                        if (redacted === '') {
                            // Return NULL to indicate EOF, or read next line – we choose EOF
                            retval.replace(ptr(0));
                        } else if (redacted !== line) {
                            // Write back filtered line
                            Memory.writeUtf8String(this.buf, redacted);
                        }
                    }
                } catch (e) {}
            }
        });
    }

    // ------------------------------------------------------------------
    // 3. Block connect() to Frida port
    // ------------------------------------------------------------------
    var connectSym = Module.findExportByName('libc.so', 'connect');
    if (connectSym) {
        Interceptor.attach(connectSym, {
            onEnter: function (args) {
                this._block = false;
                try {
                    var addrlen = args[2].toInt32();
                    if (addrlen >= 4) {
                        var portHi = Memory.readU8(args[1].add(2));
                        var portLo = Memory.readU8(args[1].add(3));
                        var port = (portHi << 8) | portLo;
                        if (port === FRIDA_PORT) {
                            console.log('[MobHound] blocked connect to port', FRIDA_PORT);
                            this._block = true;
                        }
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this._block) retval.replace(ptr(-1));
            }
        });
    }

    // ------------------------------------------------------------------
    // 4. Java‑layer backups (File.exists, BufferedReader, etc.)
    // ------------------------------------------------------------------
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (SUSPECT_PATHS.indexOf(path) !== -1 || containsFridaKeyword(path)) {
                console.log('[MobHound] File.exists blocked:', path);
                return false;
            }
            return this.exists();
        };
        File.listFiles.overload().implementation = function () {
            var result = this.listFiles();
            if (!result) return null;
            var filtered = [];
            for (var i = 0; i < result.length; i++) {
                var name = result[i].getName();
                if (!containsFridaKeyword(name)) filtered.push(result[i]);
            }
            return filtered;
        };
    } catch (e) {}

    try {
        var BufferedReader = Java.use('java.io.BufferedReader');
        var readLine = BufferedReader.readLine.overload();
        readLine.implementation = function () {
            var line = readLine.call(this);
            if (line === null) return null;
            var redacted = redactLine(line);
            if (redacted === '') return null;
            return redacted;
        };
    } catch (e) {}

    // Hide frida-agent from Java's library list (if any)
    try {
        var System = Java.use('java.lang.System');
        System.loadLibrary.overload('java.lang.String').implementation = function (libname) {
            if (libname.indexOf('frida') !== -1) {
                console.log('[MobHound] blocked native load of', libname);
                return;
            }
            return this.loadLibrary(libname);
        };
        System.load.overload('java.lang.String').implementation = function (path) {
            if (path.indexOf('frida') !== -1) {
                console.log('[MobHound] blocked load of', path);
                return;
            }
            return this.load(path);
        };
    } catch (e) {}

    // ------------------------------------------------------------------
    // 5. D‑Bus detection stub (optional)
    // ------------------------------------------------------------------
    var dbusLib = Module.findExportByName(null, 'dbus_bus_get');
    if (dbusLib) {
        Interceptor.attach(dbusLib, {
            onEnter: function () {
                console.log('[MobHound] D-Bus call blocked');
                // Return NULL or an error to fool the caller
            },
            onLeave: function (retval) {
                retval.replace(ptr(0));
            }
        });
    }

    // ------------------------------------------------------------------
    // 6. Hide frida-agent.so from /proc/self/maps (already handled by read filter)
    //    But extra: in‑memory module enumeration via dl_iterate_phdr
    // ------------------------------------------------------------------
    var dlIterateSym = Module.findExportByName(null, 'dl_iterate_phdr');
    if (dlIterateSym) {
        Interceptor.attach(dlIterateSym, {
            onEnter: function () {
                // We could implement a custom callback filter; for simplicity,
                // we rely on the maps filter above. This hook exists as a placeholder.
                console.log('[MobHound] dl_iterate_phdr called – maps filter active');
            }
        });
    }

    console.log('[MobHound] Enhanced Frida detection bypass fully loaded.');
});
""".strip()

    def __init__(self, connector: AndroidEmulatorConnector, auto_install_frida: bool = True, frida_port: int = 27042):
        self.connector = connector
        self.auto_install_frida = auto_install_frida
        self.frida_port = frida_port          # custom port for frida-server (e.g. 1337)
        self.frida_env_dir = self.connector.managed_tools_dir / "frida_env"
        self.frida_tools_dir = self.connector.managed_tools_dir / "frida"
        self.frida_tools_dir.mkdir(parents=True, exist_ok=True)
        self.frida_bin = self._find_or_install_frida_tool("frida")
        self.frida_ps_bin = self._find_or_install_frida_tool("frida-ps")
        self.server_process_name = "frida-server"
        self.proxy_probe_process: Optional[subprocess.Popen] = None
        self.proxy_probe_monitor: Optional[threading.Thread] = None
        self.proxy_probe_log = self.frida_tools_dir / "proxy_bypass_probe.log"

    def _venv_python(self) -> Path:
        if platform.system().lower() == "windows":
            return self.frida_env_dir / "Scripts" / "python.exe"
        return self.frida_env_dir / "bin" / "python"

    def _venv_tool(self, name: str) -> Path:
        if platform.system().lower() == "windows":
            return self.frida_env_dir / "Scripts" / f"{name}.exe"
        return self.frida_env_dir / "bin" / name

    def _find_or_install_frida_tool(self, tool_name: str) -> str:
        system_hit = shutil.which(tool_name)
        if system_hit:
            return system_hit

        managed_hit = self._venv_tool(tool_name)
        if managed_hit.exists():
            return str(managed_hit)

        if not self.auto_install_frida:
            raise InterceptionError(f"Frida tool '{tool_name}' not found. Enable auto-install or install frida-tools.")

        result = self.connector.tool_installer.ensure_python_tool(
            "frida",
            "frida_env",
            tool_name,
            extra_packages=["frida-tools"],
        )
        if not result.available:
            raise InterceptionError(result.error or f"Failed to auto-install Frida tool '{tool_name}'.")
        managed_hit = self._venv_tool(tool_name)
        if not managed_hit.exists():
            raise InterceptionError(f"Frida tool '{tool_name}' installation completed, but binary was not found.")
        return str(managed_hit)

    def _install_frida_host_tools(self) -> None:
        self.connector.managed_tools_dir.mkdir(parents=True, exist_ok=True)
        venv_result = subprocess.run(
            [sys.executable, "-m", "venv", str(self.frida_env_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if venv_result.returncode != 0:
            raise InterceptionError(venv_result.stderr.strip() or "Failed to create managed environment for Frida.")

        py = self._venv_python()
        if not py.exists():
            raise InterceptionError("Managed Python for Frida was not created.")

        install = subprocess.run(
            [str(py), "-m", "pip", "install", "--upgrade", "pip", "frida-tools", "frida"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if install.returncode != 0:
            details = install.stderr.strip() or install.stdout.strip() or "unknown pip error"
            raise InterceptionError(f"Failed to auto-install Frida tools: {details}")

    def _frida_version(self) -> str:
        result = subprocess.run(
            [self.frida_bin, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        version = (result.stdout or "").strip()
        if result.returncode != 0 or not version:
            raise InterceptionError(result.stderr.strip() or "Unable to determine Frida version.")
        return version

    def _device_abi(self, serial: str) -> str:
        abi_res = self.connector._run_adb_shell(serial, ["getprop", "ro.product.cpu.abi"])
        abi = (abi_res.stdout or "").strip()
        if abi_res.returncode != 0 or not abi:
            raise InterceptionError(abi_res.stderr.strip() or "Unable to detect device ABI for Frida server.")
        return abi

    def _download_frida_server(self, version: str, abi_tag: str) -> Path:
        server_name = f"frida-server-{version}-{abi_tag}"
        archive_name = f"{server_name}.xz"
        archive_path = self.frida_tools_dir / archive_name
        binary_path = self.frida_tools_dir / server_name

        if binary_path.exists():
            return binary_path

        url = f"{self.FRIDA_RELEASE_BASE}/{version}/{archive_name}"
        try:
            urllib.request.urlretrieve(url, archive_path)
        except (urllib.error.URLError, OSError) as exc:
            raise InterceptionError(f"Failed to download frida-server: {url}") from exc

        try:
            data = lzma.decompress(archive_path.read_bytes())
            binary_path.write_bytes(data)
        except (lzma.LZMAError, OSError) as exc:
            raise InterceptionError("Failed to unpack frida-server archive.") from exc
        finally:
            archive_path.unlink(missing_ok=True)

        if platform.system().lower() != "windows":
            binary_path.chmod(binary_path.stat().st_mode | 0o111)
        return binary_path

    def _is_frida_server_running(self, serial: str) -> bool:
        pidof = self.connector._run_adb_shell(serial, ["pidof", self.server_process_name])
        if pidof.returncode == 0 and (pidof.stdout or "").strip():
            return True
        ps = self.connector._run_adb_shell(serial, ["ps"])
        if ps.returncode != 0:
            return False
        return self.server_process_name in (ps.stdout or "")

    def _read_device_file(self, serial: str, path: str) -> str:
        result = self.connector._run_adb_shell(serial, ["cat", path])
        if result.returncode != 0:
            return ""
        return (result.stdout or "").strip()

    def setup_device_server(self, serial: str) -> str:
        abi = self._device_abi(serial)
        abi_tag = self.ABI_MAP.get(abi)
        if not abi_tag:
            raise InterceptionError(f"Unsupported ABI for Frida server: {abi}")

        version = self._frida_version()
        local_server = self._download_frida_server(version, abi_tag)

        # Kill any existing frida-server and remove old forward
        self.connector._run_adb(["-s", serial, "shell", "pkill", "-f", self.server_process_name])
        self.connector._run_adb(["-s", serial, "shell", "rm", "-f", "/data/local/tmp/frida-server.log"])
        self.connector._run_adb(["-s", serial, "forward", "--remove-all"])

        # Push frida-server
        push = self.connector._run_adb(["-s", serial, "push", str(local_server), "/data/local/tmp/frida-server"])
        if push.returncode != 0:
            raise InterceptionError(push.stderr.strip() or "Failed to push frida-server to emulator.")

        chmod = self.connector._run_adb(["-s", serial, "shell", "chmod", "755", "/data/local/tmp/frida-server"])
        if chmod.returncode != 0:
            raise InterceptionError(chmod.stderr.strip() or "Failed to chmod frida-server on emulator.")

        # ADB forward: localhost:27042 -> device:<custom_port>
        forward = self.connector._run_adb(["-s", serial, "forward", f"tcp:27042", f"tcp:{self.frida_port}"])
        if forward.returncode != 0:
            raise InterceptionError(forward.stderr.strip() or "Failed to set up ADB forward for frida-server.")

        # Start frida-server listening on custom port
        start_cmd = f"/data/local/tmp/frida-server -l 0.0.0.0:{self.frida_port} >/data/local/tmp/frida-server.log 2>&1 &"
        start = self.connector._run_adb(["-s", serial, "shell", "sh", "-c", start_cmd])
        if start.returncode != 0:
            # Some devices may require root
            start = self.connector._run_adb(["-s", serial, "shell", "su", "-c", start_cmd])

        time.sleep(2)
        if not self._is_frida_server_running(serial):
            server_log = self._read_device_file(serial, "/data/local/tmp/frida-server.log")
            hints = []
            lowered = server_log.lower()
            if "permission denied" in lowered:
                hints.append("Permission denied – try running as root (use 'su -c' manually)")
            if "not executable" in lowered or "exec format error" in lowered:
                hints.append(f"ABI mismatch: device reported {abi}, but frida-server binary is for {abi_tag}")
            if "linker" in lowered or "not found" in lowered:
                hints.append("Missing linker or libraries – emulator image may be too old")
            if "address already in use" in lowered:
                hints.append(f"Port {self.frida_port} already in use – change frida_port")
            hint_text = f" Hints: {', '.join(hints)}." if hints else ""
            detail = f"\nDevice log:\n{server_log}" if server_log else ""
            raise InterceptionError(f"frida-server did not stay running on the emulator.{hint_text}{detail}")

        # Verify connection works
        self.verify_connection(serial)
        return f"Frida server running on port {self.frida_port} (version={version}, abi={abi})."

    def verify_connection(self, serial: Optional[str] = None, retries: int = 3, retry_delay: float = 2.0) -> None:
        time.sleep(1)  # Give server time to settle
        last_exc: Optional[Exception] = None
        result = None
        for attempt in range(1, retries + 1):
            try:
                result = subprocess.run(
                    [self.frida_ps_bin, "-H", f"127.0.0.1:{self.frida_port}"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                    timeout=10,
                )
                if result.returncode == 0:
                    return  # success
                last_exc = None
            except subprocess.TimeoutExpired as exc:
                last_exc = exc
                result = None
            if attempt < retries:
                time.sleep(retry_delay)
        if last_exc is not None:
            raise InterceptionError(
                f"Frida connection check timed out after {retries} attempt(s)."
            ) from last_exc
        if result is not None and result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip() or "unknown error"
            if serial:
                # Check ADB forward and server status for clearer diagnostics.
                forward_list = self.connector._run_adb(["forward", "--list"])
                forward_output = (forward_list.stdout or "").strip()
                expected_forward = f"{serial} tcp:27042 tcp:{self.frida_port}"
                server_running = self._is_frida_server_running(serial)
                server_log = self._read_device_file(serial, "/data/local/tmp/frida-server.log")
                hints = []
                if expected_forward not in forward_output:
                    hints.append(f"ADB forward missing; expected '{expected_forward}'")
                if not server_running:
                    hints.append("frida-server is not running on device")
                if "connection closed" in stderr.lower() and server_running:
                    hints.append("frida-server accepted connection then closed it")
                if hints:
                    detail = f"\nForward list:\n{forward_output or '(empty)'}"
                    if server_log:
                        detail += f"\nfrida-server log:\n{server_log}"
                    raise InterceptionError(f"Frida connection check failed: {stderr}. {'; '.join(hints)}.{detail}")
            raise InterceptionError(f"Frida connection check failed: {stderr}")

    def start_ssl_bypass(self, package_name: str) -> subprocess.Popen:
        script_path = self.frida_tools_dir / "ssl_pinning_bypass.js"
        # Broad hooks for common Android SSL pinning paths.
        script_path.write_text(
            """
Java.perform(function () {
  function log(message) {
    console.log('[MobHound SSL] ' + message);
  }

  function tryHook(name, fn) {
    try {
      fn();
      log('hooked ' + name);
    } catch (e) {
      log('skip ' + name + ': ' + e);
    }
  }

  var TrustManagers = null;

  tryHook('SSLContext.init', function () {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'com.mobhound.TrustManager',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function (chain, authType) {},
        checkServerTrusted: function (chain, authType) {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    TrustManagers = [TrustManager.$new()];
    var init = SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;',
      '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom'
    );
    init.implementation = function (keyManager, trustManager, secureRandom) {
      log('bypass SSLContext.init');
      return init.call(this, keyManager, TrustManagers, secureRandom);
    };
  });

  tryHook('Conscrypt TrustManagerImpl', function () {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
      log('bypass TrustManagerImpl.verifyChain: ' + host);
      return untrustedChain;
    };
    TrustManagerImpl.checkTrustedRecursive.implementation = function (certs, host, clientAuth, untrustedChain, trustAnchorChain, used) {
      log('bypass TrustManagerImpl.checkTrustedRecursive: ' + host);
      return Java.use('java.util.ArrayList').$new();
    };
  });

  tryHook('OkHttp3 CertificatePinner', function () {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peerCertificates) {
      log('bypass OkHttp3 CertificatePinner.check(list): ' + host);
      return;
    };
    try {
      CertificatePinner.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (host, certificate) {
        log('bypass OkHttp3 CertificatePinner.check(cert): ' + host);
        return;
      };
    } catch (e) {}
    try {
      CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (host, certificates) {
        log('bypass OkHttp3 CertificatePinner.check(array): ' + host);
        return;
      };
    } catch (e) {}
    try {
      CertificatePinner['check$okhttp'].implementation = function (host, cleanedPeerCertificates) {
        log('bypass OkHttp3 CertificatePinner.check$okhttp: ' + host);
        return;
      };
    } catch (e) {}
  });

  tryHook('OkHttp2 CertificatePinner', function () {
    var OkHttpClient = Java.use('com.squareup.okhttp.OkHttpClient');
    var setCertificatePinner = OkHttpClient.setCertificatePinner.overload('com.squareup.okhttp.CertificatePinner');
    setCertificatePinner.implementation = function (certificatePinner) {
      log('bypass OkHttp2 OkHttpClient.setCertificatePinner');
      return setCertificatePinner.call(this, null);
    };
  });

  tryHook('OkHttp2 CertificatePinner.check', function () {
    var CertificatePinner = Java.use('com.squareup.okhttp.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peerCertificates) {
      log('bypass OkHttp2 CertificatePinner.check(list): ' + host);
      return;
    };
    try {
      CertificatePinner.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (host, certificate) {
        log('bypass OkHttp2 CertificatePinner.check(cert): ' + host);
        return;
      };
    } catch (e) {}
    try {
      CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (host, certificates) {
        log('bypass OkHttp2 CertificatePinner.check(array): ' + host);
        return;
      };
    } catch (e) {}
  });

  tryHook('OkHttp hostname verifier', function () {
    var OkHostnameVerifier = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
    OkHostnameVerifier.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (host, cert) {
      log('bypass OkHttp HostnameVerifier(cert): ' + host);
      return true;
    };
    OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (host, session) {
      log('bypass OkHttp HostnameVerifier(session): ' + host);
      return true;
    };
  });

  tryHook('HttpsURLConnection HostnameVerifier', function () {
    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    var TrustHostnameVerifier = Java.registerClass({
      name: 'com.mobhound.TrustHostnameVerifier',
      implements: [HostnameVerifier],
      methods: {
        verify: function (hostname, session) {
          log('bypass HostnameVerifier.verify: ' + hostname);
          return true;
        }
      }
    });
    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    var setDefaultHostnameVerifier = HttpsURLConnection.setDefaultHostnameVerifier.overload('javax.net.ssl.HostnameVerifier');
    setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
      log('bypass HttpsURLConnection.setDefaultHostnameVerifier');
      return setDefaultHostnameVerifier.call(this, TrustHostnameVerifier.$new());
    };
    var setHostnameVerifier = HttpsURLConnection.setHostnameVerifier.overload('javax.net.ssl.HostnameVerifier');
    setHostnameVerifier.implementation = function (hostnameVerifier) {
      log('bypass HttpsURLConnection.setHostnameVerifier');
      return setHostnameVerifier.call(this, TrustHostnameVerifier.$new());
    };
    var setSSLSocketFactory = HttpsURLConnection.setSSLSocketFactory.overload('javax.net.ssl.SSLSocketFactory');
    setSSLSocketFactory.implementation = function (sslSocketFactory) {
      log('observe HttpsURLConnection.setSSLSocketFactory');
      return setSSLSocketFactory.call(this, sslSocketFactory);
    };
  });

  tryHook('WebViewClient.onReceivedSslError', function () {
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.onReceivedSslError.overload(
      'android.webkit.WebView',
      'android.webkit.SslErrorHandler',
      'android.net.http.SslError'
    ).implementation = function (view, handler, error) {
      log('bypass WebViewClient.onReceivedSslError');
      handler.proceed();
      return;
    };
  });

  tryHook('Apache HTTP Client SSL factories', function () {
    var SSLSocketFactory = Java.use('org.apache.http.conn.ssl.SSLSocketFactory');
    SSLSocketFactory.verifyHostname.implementation = function (socket, host) {
      log('bypass Apache SSLSocketFactory.verifyHostname: ' + host);
      return;
    };
    try {
      var AllowAllHostnameVerifier = Java.use('org.apache.http.conn.ssl.AllowAllHostnameVerifier');
      AllowAllHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (host, session) {
        log('bypass Apache AllowAllHostnameVerifier.verify: ' + host);
        return true;
      };
    } catch (e) {}
  });

  tryHook('Network Security Config visibility', function () {
    var NetworkSecurityPolicy = Java.use('android.security.NetworkSecurityPolicy');
    var cleartextGlobal = NetworkSecurityPolicy.isCleartextTrafficPermitted.overload();
    cleartextGlobal.implementation = function () {
      var result = cleartextGlobal.call(this);
      log('observe NSC cleartext policy global: ' + result);
      return result;
    };
    try {
      var cleartextHost = NetworkSecurityPolicy.isCleartextTrafficPermitted.overload('java.lang.String');
      cleartextHost.implementation = function (host) {
        var result = cleartextHost.call(this, host);
        log('observe NSC cleartext policy host: ' + host + ' => ' + result);
        return result;
      };
    } catch (e) {}
  });
});
""".strip()
            + "\n",
            encoding="utf-8",
        )

        return subprocess.Popen(
            [self.frida_bin, "-H", f"127.0.0.1:{self.frida_port}", "-f", package_name, "-l", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def start_root_emulator_bypass(self, package_name: str) -> subprocess.Popen:
        script_path = self.frida_tools_dir / "root_emulator_bypass.js"
        script_path.write_text(self.ROOT_EMULATOR_BYPASS_SCRIPT, encoding="utf-8")
        return subprocess.Popen(
            [self.frida_bin, "-H", f"127.0.0.1:{self.frida_port}", "-f", package_name, "-l", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def start_frida_detection_bypass(self, package_name: str) -> subprocess.Popen:
        script_path = self.frida_tools_dir / "frida_detection_bypass.js"
        script_path.write_text(self.FRIDA_DETECTION_BYPASS_SCRIPT, encoding="utf-8")
        # Use spawn (-f) so hooks are loaded at startup.
        return subprocess.Popen(
            [
                self.frida_bin,
                "-H", f"127.0.0.1:{self.frida_port}",
                "-f", package_name,
                "-l", str(script_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def start_app_traffic_tagger(self, package_name: str, debug: bool = True) -> subprocess.Popen:
        script_path = self.frida_tools_dir / "traffic_tagger.js"
        
        # Enhanced traffic tagger with debug output and more HTTP library support
        script_content = """
// Enhanced Traffic Tagger - Debugged Version
Java.perform(function () {
  var tagValue = '__MOBHOUND_PACKAGE__';
  var tagHeader = 'X-MobHound-App';
  var hooked = [];
  var failed = [];
  var debugMode = __DEBUG_MODE__;
  
  if (debugMode) console.log('[MobHound] Starting traffic tagging for: ' + tagValue);

  function tryHook(name, callback) {
    try {
      callback();
      hooked.push(name);
      if (debugMode) console.log('[MobHound] ✓ Hooked: ' + name);
      return true;
    } catch (e) {
      failed.push(name);
      if (debugMode) console.log('[MobHound] ✗ Failed: ' + name + ' - ' + e);
      return false;
    }
  }

  // ===== OkHttp3 (Most Common) =====
  tryHook('okhttp3.Request$Builder.build()', function () {
    var Builder = Java.use('okhttp3.Request$Builder');
    var originalBuild = Builder.build;
    Builder.build.implementation = function () {
      try {
        if (debugMode) console.log('[MobHound] OkHttp3 request intercepted');
        this.header(tagHeader, tagValue);
      } catch (e) {
        if (debugMode) console.log('[MobHound] OkHttp3 header set failed: ' + e);
      }
      return originalBuild.call(this);
    };
  });

  // ===== OkHttp2 (Legacy) =====
  tryHook('okhttp.Request$Builder.build()', function () {
    var Builder = Java.use('com.squareup.okhttp.Request$Builder');
    var originalBuild = Builder.build;
    Builder.build.implementation = function () {
      try {
        if (debugMode) console.log('[MobHound] OkHttp2 request intercepted');
        this.header(tagHeader, tagValue);
      } catch (e) {
        if (debugMode) console.log('[MobHound] OkHttp2 header set failed: ' + e);
      }
      return originalBuild.call(this);
    };
  });

  // ===== URLConnection (Standard Java) =====
  tryHook('java.net.HttpURLConnection.setRequestProperty()', function () {
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    var originalSetProp = HttpURLConnection.setRequestProperty;
    HttpURLConnection.setRequestProperty.implementation = function (key, value) {
      try {
        if (debugMode && key !== tagHeader) console.log('[MobHound] URLConnection header: ' + key);
        if (key !== tagHeader) {
          this.setRequestProperty(tagHeader, tagValue);
        }
      } catch (e) {
        if (debugMode) console.log('[MobHound] URLConnection header set failed: ' + e);
      }
      return originalSetProp.call(this, key, value);
    };
  });

  // ===== HttpsURLConnection (Standard Java HTTPS) =====
  tryHook('javax.net.ssl.HttpsURLConnection.setRequestProperty()', function () {
    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    var originalSetProp = HttpsURLConnection.setRequestProperty;
    HttpsURLConnection.setRequestProperty.implementation = function (key, value) {
      try {
        if (debugMode && key !== tagHeader) console.log('[MobHound] HttpsURLConnection header: ' + key);
        if (key !== tagHeader) {
          this.setRequestProperty(tagHeader, tagValue);
        }
      } catch (e) {
        if (debugMode) console.log('[MobHound] HttpsURLConnection header set failed: ' + e);
      }
      return originalSetProp.call(this, key, value);
    };
  });

  // ===== Apache HTTP Client =====
  tryHook('org.apache.http.client.HttpClient.execute()', function () {
    var HttpClient = Java.use('org.apache.http.client.HttpClient');
    var originalExecute = HttpClient.execute;
    HttpClient.execute.overload('org.apache.http.client.methods.HttpUriRequest').implementation = function (request) {
      try {
        if (debugMode) console.log('[MobHound] Apache HttpClient intercepted');
        request.addHeader(tagHeader, tagValue);
      } catch (e) {
        if (debugMode) console.log('[MobHound] Apache HttpClient header set failed: ' + e);
      }
      return originalExecute.call(this, request);
    };
  });

  // ===== URLConnection.connect() - Lower level hook =====
  tryHook('java.net.HttpURLConnection.connect()', function () {
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    var originalConnect = HttpURLConnection.connect;
    HttpURLConnection.connect.implementation = function () {
      try {
        if (debugMode) console.log('[MobHound] HttpURLConnection.connect() intercepted');
        if (!this.getRequestProperty(tagHeader)) {
          this.setRequestProperty(tagHeader, tagValue);
        }
      } catch (e) {
        if (debugMode) console.log('[MobHound] connect() hook failed: ' + e);
      }
      return originalConnect.call(this);
    };
  });

  // ===== Volley Request Library =====
  tryHook('com.android.volley.Request', function () {
    var Request = Java.use('com.android.volley.Request');
    if (Request.getHeaders) {
      var originalGetHeaders = Request.getHeaders;
      Request.getHeaders.implementation = function () {
        try {
          if (debugMode) console.log('[MobHound] Volley request intercepted');
          var headers = originalGetHeaders.call(this);
          if (headers) {
            headers.put(tagHeader, tagValue);
          }
          return headers;
        } catch (e) {
          if (debugMode) console.log('[MobHound] Volley hook failed: ' + e);
          return originalGetHeaders.call(this);
        }
      };
    }
  });

  // ===== Report results =====
  if (debugMode) {
    console.log('[MobHound] ========================================');
    console.log('[MobHound] Traffic Tagging Report');
    console.log('[MobHound] ========================================');
    console.log('[MobHound] Successfully hooked: ' + hooked.length);
    for (var i = 0; i < hooked.length; i++) {
      console.log('[MobHound]   ✓ ' + hooked[i]);
    }
    if (failed.length > 0) {
      console.log('[MobHound] Failed to hook: ' + failed.length);
      for (var i = 0; i < failed.length; i++) {
        console.log('[MobHound]   ✗ ' + failed[i]);
      }
    }
    console.log('[MobHound] Tag Value: ' + tagValue);
    console.log('[MobHound] Ready to tag HTTP requests!');
    console.log('[MobHound] ========================================');
  }
});
"""
        
        # Replace placeholders
        script_content = script_content.replace("__MOBHOUND_PACKAGE__", package_name)
        script_content = script_content.replace("__DEBUG_MODE__", "true" if debug else "false")
        
        script_path.write_text(script_content.strip() + "\n", encoding="utf-8")

        return subprocess.Popen(
            [self.frida_bin, "-H", f"127.0.0.1:{self.frida_port}", "-f", package_name, "-l", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def diagnose_http_libraries(self, package_name: str) -> subprocess.Popen:
        """Diagnose which HTTP libraries the app is using."""
        script_path = self.frida_tools_dir / "diagnose_http.js"
        
        script_content = """
// Diagnose which HTTP libraries are available in the app
Java.perform(function () {
  var found = [];
  var missing = [];
  
  console.log('[MobHound] ========================================');
  console.log('[MobHound] HTTP Library Detection');
  console.log('[MobHound] ========================================');
  
  var libCheck = [
    'okhttp3.Request',
    'okhttp3.Request$Builder',
    'com.squareup.okhttp.Request',
    'com.squareup.okhttp.Request$Builder',
    'java.net.HttpURLConnection',
    'javax.net.ssl.HttpsURLConnection',
    'org.apache.http.client.HttpClient',
    'org.apache.http.client.methods.HttpUriRequest',
    'com.android.volley.Request',
    'retrofit2.Retrofit',
    'retrofit2.Retrofit$Builder',
    'io.ktor.client.HttpClient',
    'com.google.android.gms.common.GoogleApiAvailability',
    'okhttp3.OkHttpClient',
    'com.squareup.okhttp.OkHttpClient',
  ];
  
  for (var i = 0; i < libCheck.length; i++) {
    try {
      Java.use(libCheck[i]);
      found.push(libCheck[i]);
      console.log('[MobHound] ✓ Found: ' + libCheck[i]);
    } catch (e) {
      missing.push(libCheck[i]);
    }
  }
  
  console.log('[MobHound] ========================================');
  console.log('[MobHound] Summary:');
  console.log('[MobHound] Found: ' + found.length + ' HTTP libraries');
  console.log('[MobHound] Missing: ' + missing.length);
  console.log('[MobHound] ========================================');
  
  // Check for any HTTP activity
  try {
    var URL = Java.use('java.net.URL');
    var originalInit = URL.$init.overload('java.lang.String');
    URL.$init.overload('java.lang.String').implementation = function (spec) {
      console.log('[MobHound] URL created: ' + spec);
      return originalInit.call(this, spec);
    };
    console.log('[MobHound] URL monitoring enabled');
  } catch (e) {
    console.log('[MobHound] Could not hook URL: ' + e);
  }
});
"""
        
        script_path.write_text(script_content.strip() + "\n", encoding="utf-8")
        
        return subprocess.Popen(
            [self.frida_bin, "-H", f"127.0.0.1:{self.frida_port}", "-n", package_name, "-l", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            with log_file.open("a", encoding="utf-8", errors="replace") as fp:
                while True:
                    line = process.stdout.readline()
                    if line:
                        fp.write(line if line.endswith("\n") else f"{line}\n")
                        fp.flush()
                        continue
                    if process.poll() is not None:
                        break
                    time.sleep(0.1)
                for line in process.stdout:
                    if line:
                        fp.write(line if line.endswith("\n") else f"{line}\n")
                        fp.flush()
        except Exception:
            pass

    def _write_proxy_probe_script(self, script_path: Path) -> None:
        script_path.write_text(
            (
                "setImmediate(function () {\n"
                "  try {\n"
                "    Java.perform(function () {\n"
                "      try {\n"
                "        var Socket = Java.use('java.net.Socket');\n"
                "        console.log('[MobHound ProxyProbe] Socket class found');\n"
                "      } catch (e) {\n"
                "        console.log('[MobHound ProxyProbe] Socket class error: ' + e);\n"
                "      }\n"
                "      console.log('[MobHound ProxyProbe] Detection phase complete - app still running');\n"
                "    });\n"
                "  } catch (e) {\n"
                "    console.log('[MobHound ProxyProbe] Error during Java.perform: ' + e);\n"
                "  }\n"
                "});\n"
            ),
            encoding="utf-8",
        )

    def start_proxy_bypass_probe(self, package_name: str) -> subprocess.Popen:
        script_path = self.frida_tools_dir / "proxy_bypass_probe.js"
        self._write_proxy_probe_script(script_path)
        self.proxy_probe_log.write_text("", encoding="utf-8")
        if self.proxy_probe_process and self.proxy_probe_process.poll() is None:
            return self.proxy_probe_process

        self.proxy_probe_process = subprocess.Popen(
            [
                self.frida_bin,
                "-H",
                f"127.0.0.1:{self.frida_port}",
                "-n",
                package_name,
                "-l",
                str(script_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.proxy_probe_monitor = threading.Thread(
            target=self._monitor_proxy_probe_output,
            args=(self.proxy_probe_process, self.proxy_probe_log),
            daemon=True,
        )
        self.proxy_probe_monitor.start()
        return self.proxy_probe_process

    def stop_proxy_bypass_probe(self) -> None:
        if self.proxy_probe_process and self.proxy_probe_process.poll() is None:
            self.proxy_probe_process.terminate()
            try:
                self.proxy_probe_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proxy_probe_process.kill()
                self.proxy_probe_process.wait(timeout=2)
        self.proxy_probe_process = None
        self.proxy_probe_monitor = None

    def get_proxy_probe_log(self) -> str:
        if not self.proxy_probe_log.exists():
            return ""
        try:
            return self.proxy_probe_log.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            return ""

    def cleanup(self, serial: str) -> None:
        """Remove ADB forward and kill frida-server."""
        self.stop_proxy_bypass_probe()
        self.connector._run_adb(["-s", serial, "shell", "pkill", "-f", self.server_process_name])
        self.connector._run_adb(["forward", "--remove-all"])


def connect_to_emulator(
    target: Optional[str] = None,
    serial: Optional[str] = None,
    auto_download_adb: bool = True,
) -> EmulatorConnectionResult:
    connector = AndroidEmulatorConnector(auto_download_adb=auto_download_adb)
    connector.start_server()

    if target:
        connector.connect(target)

    selected = connector.select_emulator(preferred_serial=serial)
    if not selected:
        return EmulatorConnectionResult(
            connected=False,
            adb_path=connector.adb_path,
            message=(
                "No online Android device/emulator found. Start your emulator and retry. "
                "If needed, pass --target <IP:PORT>."
            ),
        )

    connector.verify_shell_access(selected.serial)
    connector.save_config({"last_serial": selected.serial})

    return EmulatorConnectionResult(
        connected=True,
        adb_path=connector.adb_path,
        serial=selected.serial,
        device=selected,
        message=f"Connected to emulator/device: {selected.serial}",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MobHound dynamic analysis: emulator connection bootstrap",
    )
    parser.add_argument(
        "--target",
        help="Optional host:port endpoint for adb connect (example: 127.0.0.1:5555)",
    )
    parser.add_argument(
        "--serial",
        help="Optional exact emulator/device serial to select after discovery",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Only list discovered adb devices",
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Run health check on selected serial/device",
    )
    parser.add_argument(
        "--no-auto-download-adb",
        action="store_true",
        help="Disable automatic download of adb platform-tools when adb is missing",
    )
    return parser

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    auto_download_adb = not args.no_auto_download_adb

    try:
        connector = AndroidEmulatorConnector(auto_download_adb=auto_download_adb)
        connector.start_server()

        if args.target:
            msg = connector.connect(args.target)
            if msg:
                print(msg)

        devices = connector.list_devices(include_properties=True)
        if args.list:
            if not devices:
                print("No devices found")
                return 1
            for dev in devices:
                kind = "emulator" if dev.is_emulator else "physical"
                print(
                    f"{dev.serial}\t{dev.state}\t{kind}\t{dev.model}\t"
                    f"android={dev.android_version}\tabi={dev.abi}\tqemu={dev.qemu}"
                )
            return 0

        result = connect_to_emulator(
            target=args.target,
            serial=args.serial,
            auto_download_adb=auto_download_adb,
        )

        if result.connected and result.serial:
            print(result.message)
            print(f"ADB path: {result.adb_path}")
            if args.health:
                health = connector.run_health_check(result.serial)
                print(f"Health check: {'OK' if health.ok else 'FAILED'}")
                for key, value in health.details.items():
                    print(f"  {key}: {value}")
            return 0

        print(result.message)
        return 1

    except EmulatorConnectionError as exc:
        print(f"[Connection Error] {exc}")
        return 2
    except subprocess.TimeoutExpired:
        print("[Connection Error] adb command timed out")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
