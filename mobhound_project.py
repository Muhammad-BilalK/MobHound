from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import tempfile
import threading
import uuid
import zipfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


LOGGER = logging.getLogger("mobhound.project")

PROJECT_SCHEMA_VERSION = "1.0.0"
MOBHOUND_VERSION = "1.0.0"
PROJECT_EXTENSION = ".mh"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(name: str) -> str:
    cleaned = "".join(ch for ch in name.strip() if ch.isalnum() or ch in (" ", "-", "_")).strip()
    return cleaned or "MobHoundProject"


@dataclass
class ProjectMetadata:
    project_name: str
    project_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    schema_version: str = PROJECT_SCHEMA_VERSION
    mobhound_version: str = MOBHOUND_VERSION
    android_package_name: str = ""
    apk_hash: str = ""
    target_device: Dict[str, Any] = field(default_factory=dict)
    enabled_modules: List[str] = field(default_factory=lambda: ["reverse_engineering", "ai_scanner", "dynamic_analysis"])
    analyst_notes: str = ""
    temporary: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProjectMetadata":
        return cls(**data)


@dataclass
class ProjectSession:
    metadata: ProjectMetadata
    workspace_dir: Path
    project_file: Optional[Path]
    opened_at: str = field(default_factory=utc_now_iso)
    dirty: bool = False


class ProjectValidator:
    REQUIRED_TOP_LEVEL = [
        "project.json",
        "traffic.sqlite",
        "ai_scanner.sqlite",
        "reverse_engineering.sqlite",
        "dynamic_analysis.sqlite",
    ]

    @staticmethod
    def validate_structure(root: Path) -> None:
        for rel in ProjectValidator.REQUIRED_TOP_LEVEL:
            if not (root / rel).exists():
                raise ValueError(f"Missing required project artifact: {rel}")

    @staticmethod
    def validate_archive_path(path: Path) -> None:
        if path.suffix.lower() != PROJECT_EXTENSION:
            raise ValueError(f"Project file must use {PROJECT_EXTENSION} extension.")


class ProjectLockManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()

    @contextmanager
    def acquire(self):
        with self._lock:
            yield


class ProjectDatabase:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def initialize(self, schema_sql: Iterable[str]) -> None:
        with self._connect() as conn:
            for stmt in schema_sql:
                conn.executescript(stmt)
            conn.commit()


class DynamicAnalysisStorage(ProjectDatabase):
    SCHEMA = [
        """
        CREATE TABLE IF NOT EXISTS scan_sessions(
            id INTEGER PRIMARY KEY,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            device_serial TEXT,
            package_name TEXT
        );
        CREATE TABLE IF NOT EXISTS http_requests(
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            method TEXT,
            url TEXT,
            host TEXT,
            path TEXT,
            headers_json TEXT,
            body BLOB,
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_http_req_session_ts ON http_requests(session_id, ts);
        CREATE TABLE IF NOT EXISTS http_responses(
            id INTEGER PRIMARY KEY,
            request_id INTEGER NOT NULL UNIQUE,
            ts TEXT NOT NULL,
            status_code INTEGER,
            headers_json TEXT,
            body BLOB,
            FOREIGN KEY(request_id) REFERENCES http_requests(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS websocket_messages(
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            direction TEXT NOT NULL,
            opcode INTEGER,
            payload BLOB,
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS frida_logs(
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            level TEXT,
            message TEXT,
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS runtime_events(
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT,
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS screenshots(
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            path TEXT NOT NULL,
            note TEXT,
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS timeline(
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            module TEXT NOT NULL,
            category TEXT NOT NULL,
            ref_id INTEGER,
            details_json TEXT
        );
        """
    ]


class ReverseEngineeringStorage(ProjectDatabase):
    SCHEMA = [
        """
        CREATE TABLE IF NOT EXISTS files_analyzed(
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            file_type TEXT,
            sha256 TEXT,
            size_bytes INTEGER
        );
        CREATE TABLE IF NOT EXISTS reverse_engineering_findings(
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            severity TEXT,
            finding_type TEXT,
            location TEXT,
            summary TEXT,
            evidence TEXT
        );
        CREATE TABLE IF NOT EXISTS permissions(
            id INTEGER PRIMARY KEY,
            permission_name TEXT UNIQUE NOT NULL,
            risk TEXT,
            notes TEXT
        );
        CREATE TABLE IF NOT EXISTS hardcoded_secrets(
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            secret_type TEXT,
            location TEXT,
            masked_value TEXT,
            confidence REAL
        );
        CREATE INDEX IF NOT EXISTS idx_ref_findings_severity ON reverse_engineering_findings(severity);
        """
    ]


class AIScannerStorage(ProjectDatabase):
    SCHEMA = [
        """
        CREATE TABLE IF NOT EXISTS scan_sessions(
            id INTEGER PRIMARY KEY,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            model_name TEXT,
            model_version TEXT
        );
        CREATE TABLE IF NOT EXISTS ai_findings(
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            category TEXT,
            title TEXT,
            details TEXT,
            confidence REAL,
            recommendation TEXT,
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS risk_scores(
            id INTEGER PRIMARY KEY,
            session_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            score_name TEXT NOT NULL,
            score_value REAL NOT NULL,
            confidence REAL,
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ai_findings_session ON ai_findings(session_id);
        """
    ]


class CoreStorage(ProjectDatabase):
    SCHEMA = [
        """
        CREATE TABLE IF NOT EXISTS projects(
            id INTEGER PRIMARY KEY,
            project_uuid TEXT UNIQUE NOT NULL,
            project_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            mobhound_version TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS module_registry(
            id INTEGER PRIMARY KEY,
            module_name TEXT UNIQUE NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            configured_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings(
            id INTEGER PRIMARY KEY,
            key TEXT UNIQUE NOT NULL,
            value_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes(
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            note TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS exports(
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            export_type TEXT NOT NULL,
            file_path TEXT NOT NULL
        );
        """
    ]


class BackupManager:
    def create_backup(self, project_root: Path) -> Path:
        backups_dir = project_root / "backups"
        backups_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backups_dir / f"autosave_{stamp}.zip"
        with zipfile.ZipFile(backup_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in project_root.rglob("*"):
                if path.is_file():
                    zf.write(path, path.relative_to(project_root))
        return backup_path


class AutoSaveManager:
    def __init__(self, interval_seconds: int = 30) -> None:
        self.interval_seconds = interval_seconds
        self._timer: Optional[threading.Timer] = None

    def schedule(self, callback) -> None:
        self.cancel()
        self._timer = threading.Timer(self.interval_seconds, callback)
        self._timer.daemon = True
        self._timer.start()

    def cancel(self) -> None:
        if self._timer:
            self._timer.cancel()
            self._timer = None


class MigrationManager:
    def ensure_compatible(self, metadata: ProjectMetadata) -> None:
        if metadata.schema_version.split(".")[0] != PROJECT_SCHEMA_VERSION.split(".")[0]:
            raise ValueError(
                f"Incompatible project schema version {metadata.schema_version}; expected major {PROJECT_SCHEMA_VERSION}."
            )


class ProjectStorage:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.workspaces_dir = self.base_dir / "workspaces"
        self.workspaces_dir.mkdir(parents=True, exist_ok=True)
        self.recent_file = self.base_dir / "recent_projects.json"
        self.lock_manager = ProjectLockManager()

    def new_workspace_dir(self, project_name: str) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        workspace = self.workspaces_dir / f"{safe_name(project_name)}_{stamp}"
        workspace.mkdir(parents=True, exist_ok=False)
        return workspace

    def project_root(self, workspace_dir: Path) -> Path:
        return workspace_dir

    def write_project_json(self, root: Path, metadata: ProjectMetadata) -> None:
        tmp = root / "project.json.tmp"
        final = root / "project.json"
        tmp.write_text(json.dumps(metadata.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(final)

    def read_project_json(self, root: Path) -> ProjectMetadata:
        data = json.loads((root / "project.json").read_text(encoding="utf-8"))
        return ProjectMetadata.from_dict(data)

    def pack_to_mh(self, root: Path, output_file: Path) -> None:
        ProjectValidator.validate_archive_path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = output_file.with_suffix(output_file.suffix + ".tmp")
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in root.rglob("*"):
                if path.is_file():
                    zf.write(path, path.relative_to(root))
        tmp.replace(output_file)

    def safe_extract_mh(self, project_file: Path, dest: Path) -> None:
        with zipfile.ZipFile(project_file, "r") as zf:
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    raise ValueError(f"Unsafe zip entry detected: {member.filename}")
            zf.extractall(dest)

    def append_recent(self, project_file: Optional[Path], metadata: ProjectMetadata) -> None:
        if metadata.temporary:
            return
        rows = self.list_recent()
        entry = {
            "name": metadata.project_name,
            "project_uuid": metadata.project_uuid,
            "path": str(project_file) if project_file else "",
            "updated_at": metadata.updated_at,
        }
        rows = [r for r in rows if r.get("path") != entry["path"]]
        rows.insert(0, entry)
        self.recent_file.write_text(json.dumps(rows[:20], indent=2), encoding="utf-8")

    def list_recent(self) -> List[Dict[str, Any]]:
        if not self.recent_file.exists():
            return []
        try:
            return json.loads(self.recent_file.read_text(encoding="utf-8"))
        except Exception:
            return []


class WorkspaceManager:
    def __init__(self, storage: ProjectStorage) -> None:
        self.storage = storage
        self.backup_manager = BackupManager()
        self.autosave = AutoSaveManager()
        self.migration = MigrationManager()

    def _init_tree(self, root: Path) -> None:
        directories = [
            "apk/extracted",
            "apk/decoded",
            "dynamic_analysis/mitmproxy",
            "dynamic_analysis/frida",
            "dynamic_analysis/pcaps",
            "dynamic_analysis/logs",
            "dynamic_analysis/screenshots",
            "dynamic_analysis/runtime_dumps",
            "reverse_engineering/jadx",
            "reverse_engineering/apktool",
            "reverse_engineering/manifests",
            "reverse_engineering/smali",
            "reverse_engineering/yara",
            "reverse_engineering/extracted_strings",
            "ai_scanner/reports",
            "ai_scanner/findings",
            "ai_scanner/risk_scores",
            "ai_scanner/behavioral_analysis",
            "ai_scanner/model_outputs",
            "exports",
            "temp",
            "backups",
            "logs",
        ]
        for d in directories:
            (root / d).mkdir(parents=True, exist_ok=True)

    def _init_databases(self, root: Path, metadata: ProjectMetadata) -> None:
        CoreStorage(root / "traffic.sqlite").initialize(CoreStorage.SCHEMA)
        AIScannerStorage(root / "ai_scanner.sqlite").initialize(AIScannerStorage.SCHEMA)
        ReverseEngineeringStorage(root / "reverse_engineering.sqlite").initialize(ReverseEngineeringStorage.SCHEMA)
        DynamicAnalysisStorage(root / "dynamic_analysis.sqlite").initialize(DynamicAnalysisStorage.SCHEMA)
        CoreStorage(root / "traffic.sqlite").initialize(
            [f"INSERT OR REPLACE INTO projects(project_uuid,project_name,created_at,updated_at,schema_version,mobhound_version) VALUES('{metadata.project_uuid}','{metadata.project_name}','{metadata.created_at}','{metadata.updated_at}','{metadata.schema_version}','{metadata.mobhound_version}');"]
        )

    def create_workspace(self, metadata: ProjectMetadata) -> ProjectSession:
        root = self.storage.new_workspace_dir(metadata.project_name)
        self._init_tree(root)
        self._init_databases(root, metadata)
        self.storage.write_project_json(root, metadata)
        return ProjectSession(metadata=metadata, workspace_dir=root, project_file=None, dirty=True)

    def open_from_mh(self, project_file: Path) -> ProjectSession:
        ProjectValidator.validate_archive_path(project_file)
        if not project_file.exists():
            raise FileNotFoundError(project_file)
        workspace = self.storage.new_workspace_dir(project_file.stem)
        self.storage.safe_extract_mh(project_file, workspace)
        ProjectValidator.validate_structure(workspace)
        metadata = self.storage.read_project_json(workspace)
        self.migration.ensure_compatible(metadata)
        return ProjectSession(metadata=metadata, workspace_dir=workspace, project_file=project_file)

    def save_session(self, session: ProjectSession, output_file: Optional[Path] = None) -> Path:
        session.metadata.updated_at = utc_now_iso()
        self.storage.write_project_json(session.workspace_dir, session.metadata)
        target = output_file or session.project_file
        if target is None:
            default_name = safe_name(session.metadata.project_name) + PROJECT_EXTENSION
            target = self.storage.base_dir / "projects" / default_name
        self.storage.pack_to_mh(session.workspace_dir, target)
        session.project_file = target
        session.dirty = False
        self.storage.append_recent(target, session.metadata)
        return target

    def autosave_session(self, session: ProjectSession) -> Optional[Path]:
        if not session.dirty:
            return None
        return self.backup_manager.create_backup(session.workspace_dir)

    def close_session(self, session: ProjectSession, persist: bool = True) -> None:
        if persist and not session.metadata.temporary:
            self.save_session(session)
        self.autosave.cancel()


class ProjectManager:
    def __init__(self, base_dir: Path) -> None:
        self.storage = ProjectStorage(base_dir)
        self.workspace = WorkspaceManager(self.storage)
        self.lock = ProjectLockManager()
        self.active_session: Optional[ProjectSession] = None

    def create_project(
        self,
        project_name: str,
        project_file: Optional[Path] = None,
        temporary: bool = False,
        android_package_name: str = "",
        analyst_notes: str = "",
    ) -> ProjectSession:
        with self.lock.acquire():
            metadata = ProjectMetadata(
                project_name=safe_name(project_name),
                android_package_name=android_package_name,
                analyst_notes=analyst_notes,
                temporary=temporary,
            )
            session = self.workspace.create_workspace(metadata)
            self.active_session = session
            if project_file and not temporary:
                self.workspace.save_session(session, project_file)
            return session

    def open_project(self, project_file: Path) -> ProjectSession:
        with self.lock.acquire():
            session = self.workspace.open_from_mh(project_file)
            self.active_session = session
            self.storage.append_recent(project_file, session.metadata)
            return session

    def save_active_project(self, output_file: Optional[Path] = None) -> Optional[Path]:
        with self.lock.acquire():
            if not self.active_session:
                return None
            if self.active_session.metadata.temporary:
                if output_file is None:
                    raise ValueError("Temporary project requires explicit save path.")
                self.active_session.metadata.temporary = False
            return self.workspace.save_session(self.active_session, output_file)

    def close_active_project(self, persist: bool = True) -> None:
        with self.lock.acquire():
            if not self.active_session:
                return
            self.workspace.close_session(self.active_session, persist=persist)
            self.active_session = None

    def list_recent_projects(self) -> List[Dict[str, Any]]:
        return self.storage.list_recent()
