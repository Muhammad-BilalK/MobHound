"""
MobHound - Centralized Configuration System
=============================================
Single source of truth for all MobHound settings.

Usage:
    from config import config                    # global singleton
    from config import MobHoundConfig, load_config

    # Access settings
    config.frida.port
    config.scanner.min_confidence
    config.paths.tools_dir

    # Load from file
    cfg = load_config("my_project/mobhound.json")

    # Save
    config.save("mobhound.json")
"""

from __future__ import annotations

import json
import logging
import os
import platform
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mobhound.config")

# ─────────────────────────────────────────────────────────────
# Sub-configs
# ─────────────────────────────────────────────────────────────

@dataclass
class PathsConfig:
    """File system paths."""
    tools_dir:       str = ".mobhound_tools"
    frida_dir:       str = ".mobhound_tools/frida"
    jadx_bin:        str = ""          # auto-detected if empty
    apktool_bin:     str = ""
    adb_bin:         str = "adb"
    reports_dir:     str = "reports"
    logs_dir:        str = "logs"
    cache_dir:       str = "cache"
    ai_models_dir:   str = "ai_models"

    def resolve_tools_dir(self) -> Path:
        return Path(self.tools_dir).resolve()

    def resolve_frida_dir(self) -> Path:
        return Path(self.frida_dir).resolve()


@dataclass
class FridaConfig:
    """Frida runtime settings."""
    port:              int   = 27042
    host:              str   = "127.0.0.1"
    max_retries:       int   = 3
    retry_delay:       float = 2.0
    attach_timeout:    float = 10.0
    spawn_timeout:     float = 15.0
    server_startup_wait: float = 3.0
    auto_install:      bool  = True
    preferred_abi:     str   = ""      # auto-detect if empty: arm64-v8a / x86
    scripts: List[str] = field(default_factory=lambda: [
        "frida_detection_bypass.js",
        "root_emulator_bypass.js",
        "ssl_pinning_bypass.js",
        "traffic_tagger.js",
    ])

    @property
    def host_port(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class ADBConfig:
    """ADB / device settings."""
    adb_path:          str   = "adb"
    connect_timeout:   int   = 10
    command_timeout:   int   = 30
    retry_count:       int   = 3
    preferred_serial:  str   = ""     # lock to specific device
    use_tcp:           bool  = False
    tcp_host:          str   = ""
    tcp_port:          int   = 5555


@dataclass
class MitmproxyConfig:
    """Mitmproxy settings."""
    port:              int   = 8080
    host:              str   = "0.0.0.0"
    flow_file:         str   = "traffic/captured_flows.jsonl"
    cert_dir:          str   = ".mobhound_tools/mitmproxy"
    upstream_proxy:    str   = ""     # optional upstream proxy
    ignore_hosts:      List[str] = field(default_factory=list)
    startup_timeout:   float = 8.0


@dataclass
class ScannerConfig:
    """Scanner engine settings."""
    min_confidence:        float = 0.35
    max_file_size_mb:      int   = 5
    max_evidence_items:    int   = 10
    enable_static:         bool  = True
    enable_dynamic:        bool  = True
    enable_ai:             bool  = True
    enable_heuristic:      bool  = True
    enable_signature:      bool  = True
    enable_malware:        bool  = True
    report_formats:        List[str] = field(default_factory=lambda: ["json", "html", "pdf"])
    excluded_paths:        List[str] = field(default_factory=list)
    severity_threshold:    str   = "LOW"    # minimum severity to include in report
    # Max findings per detector (0 = unlimited)
    max_findings_per_detector: int = 0


@dataclass
class AIConfig:
    """AI engine settings."""
    algorithm:         str   = "random_forest"   # or "gradient_boosting"
    n_estimators:      int   = 300
    auto_bootstrap:    bool  = True    # build synthetic dataset if none exists
    auto_retrain:      bool  = False   # retrain after each scan
    min_train_samples: int   = 20
    fetch_nvd_on_train:bool  = False
    confidence_threshold: float = 0.50


@dataclass
class LoggingConfig:
    """Logging settings."""
    level:      str  = "INFO"         # DEBUG / INFO / WARNING / ERROR
    to_file:    bool = True
    to_console: bool = True
    max_bytes:  int  = 10 * 1024 * 1024   # 10 MB
    backup_count: int = 3
    format:     str  = "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"


# ─────────────────────────────────────────────────────────────
# Master config
# ─────────────────────────────────────────────────────────────

@dataclass
class MobHoundConfig:
    """Master configuration object."""
    version:    str            = "2.0.0"
    app_name:   str            = "MobHound"
    debug:      bool           = False

    paths:      PathsConfig    = field(default_factory=PathsConfig)
    frida:      FridaConfig    = field(default_factory=FridaConfig)
    adb:        ADBConfig      = field(default_factory=ADBConfig)
    mitmproxy:  MitmproxyConfig= field(default_factory=MitmproxyConfig)
    scanner:    ScannerConfig  = field(default_factory=ScannerConfig)
    ai:         AIConfig       = field(default_factory=AIConfig)
    logging:    LoggingConfig  = field(default_factory=LoggingConfig)

    # Runtime state (not serialized)
    _config_path: Optional[Path] = field(default=None, repr=False, compare=False)

    # ─── Serialization ────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("_config_path", None)
        return d

    def save(self, path: Optional[str] = None) -> Path:
        target = Path(path) if path else (self._config_path or Path("mobhound.json"))
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info("Config saved → %s", target)
        return target

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MobHoundConfig":
        cfg = cls()
        cfg.version  = data.get("version",  cfg.version)
        cfg.app_name = data.get("app_name", cfg.app_name)
        cfg.debug    = data.get("debug",    cfg.debug)

        def _merge(dc, d):
            for k, v in d.items():
                if hasattr(dc, k):
                    setattr(dc, k, v)

        if "paths"     in data: _merge(cfg.paths,     data["paths"])
        if "frida"     in data: _merge(cfg.frida,     data["frida"])
        if "adb"       in data: _merge(cfg.adb,       data["adb"])
        if "mitmproxy" in data: _merge(cfg.mitmproxy, data["mitmproxy"])
        if "scanner"   in data: _merge(cfg.scanner,   data["scanner"])
        if "ai"        in data: _merge(cfg.ai,        data["ai"])
        if "logging"   in data: _merge(cfg.logging,   data["logging"])
        return cfg

    # ─── Environment variable overrides ───────────────────────

    def apply_env_overrides(self) -> None:
        """
        Override config values from environment variables.
        Prefix: MOBHOUND_
        Examples:
            MOBHOUND_FRIDA_PORT=27043
            MOBHOUND_DEBUG=true
            MOBHOUND_SCANNER_MIN_CONFIDENCE=0.5
        """
        mapping = {
            "MOBHOUND_DEBUG":                    ("debug",                  bool),
            "MOBHOUND_FRIDA_PORT":               ("frida.port",             int),
            "MOBHOUND_FRIDA_HOST":               ("frida.host",             str),
            "MOBHOUND_FRIDA_MAX_RETRIES":        ("frida.max_retries",      int),
            "MOBHOUND_ADB_PATH":                 ("adb.adb_path",           str),
            "MOBHOUND_ADB_SERIAL":               ("adb.preferred_serial",   str),
            "MOBHOUND_MITMPROXY_PORT":           ("mitmproxy.port",         int),
            "MOBHOUND_SCANNER_MIN_CONFIDENCE":   ("scanner.min_confidence", float),
            "MOBHOUND_SCANNER_SEVERITY":         ("scanner.severity_threshold", str),
            "MOBHOUND_AI_ALGORITHM":             ("ai.algorithm",           str),
            "MOBHOUND_LOG_LEVEL":                ("logging.level",          str),
            "MOBHOUND_JADX_BIN":                 ("paths.jadx_bin",         str),
            "MOBHOUND_APKTOOL_BIN":              ("paths.apktool_bin",      str),
        }
        for env_key, (attr_path, cast) in mapping.items():
            val = os.environ.get(env_key)
            if val is None:
                continue
            try:
                parts = attr_path.split(".")
                if len(parts) == 1:
                    setattr(self, parts[0], cast(val) if cast != bool else val.lower() in ("1","true","yes"))
                else:
                    obj = getattr(self, parts[0])
                    setattr(obj, parts[1], cast(val) if cast != bool else val.lower() in ("1","true","yes"))
                logger.debug("Config override from env: %s = %s", env_key, val)
            except (ValueError, AttributeError) as e:
                logger.warning("Bad env override %s=%s: %s", env_key, val, e)

    # ─── Platform helpers ─────────────────────────────────────

    def detect_platform(self) -> str:
        return platform.system().lower()   # "windows" | "linux" | "darwin"

    def is_windows(self) -> bool:
        return self.detect_platform() == "windows"

    def setup_logging(self, log_file: Optional[Path] = None) -> None:
        """Apply logging configuration."""
        import logging.handlers
        level = getattr(logging, self.logging.level.upper(), logging.INFO)
        handlers = []

        if self.logging.to_console:
            h = logging.StreamHandler()
            h.setLevel(level)
            handlers.append(h)

        if self.logging.to_file and log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            h = logging.handlers.RotatingFileHandler(
                str(log_file),
                maxBytes=self.logging.max_bytes,
                backupCount=self.logging.backup_count,
                encoding="utf-8",
            )
            h.setLevel(level)
            handlers.append(h)

        fmt = logging.Formatter(self.logging.format)
        for h in handlers:
            h.setFormatter(fmt)

        root = logging.getLogger("mobhound")
        root.setLevel(level)
        root.handlers = handlers


# ─────────────────────────────────────────────────────────────
# Module-level functions
# ─────────────────────────────────────────────────────────────

def load_config(path: Optional[str] = None) -> MobHoundConfig:
    """
    Load config from JSON file.
    Search order:
      1. path argument
      2. MOBHOUND_CONFIG env var
      3. ./mobhound.json
      4. ~/.mobhound/config.json
      5. Default config
    """
    candidates = []
    if path:
        candidates.append(Path(path))
    env_path = os.environ.get("MOBHOUND_CONFIG")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("mobhound.json"))
    candidates.append(Path.home() / ".mobhound" / "config.json")

    for candidate in candidates:
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                cfg  = MobHoundConfig.from_dict(data)
                cfg._config_path = candidate
                cfg.apply_env_overrides()
                logger.info("Config loaded from %s", candidate)
                return cfg
            except (json.JSONDecodeError, Exception) as e:
                logger.warning("Failed to load config from %s: %s", candidate, e)

    # Default config
    cfg = MobHoundConfig()
    cfg.apply_env_overrides()
    logger.info("Using default config")
    return cfg


def save_default_config(path: str = "mobhound.json") -> Path:
    """Write a default config file to disk."""
    cfg = MobHoundConfig()
    return cfg.save(path)


# ─────────────────────────────────────────────────────────────
# Global singleton
# ─────────────────────────────────────────────────────────────

config: MobHoundConfig = load_config()
