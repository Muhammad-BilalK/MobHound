# ============================================================================
# COMPLETE MERGED FILE: int2.py enhanced with int.py scanner & apk reverse
# ============================================================================

from __future__ import annotations

import sys
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
import urllib.parse
import shlex
import traceback
import math
import subprocess
import threading
try:
    from types import CodeType
except ImportError:
    CodeType = type(lambda: None).__code__.__class__  # type: ignore
import re
import logging
import glob
import ssl
import webbrowser
from html import escape
from datetime import datetime
from dataclasses import dataclass, field, asdict
from xml.etree import ElementTree as ET
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
from concurrent.futures import Future, ThreadPoolExecutor, as_completed

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QStackedWidget, QListWidget, QListWidgetItem, QFrame, QTextEdit, QLineEdit, QComboBox,
    QCheckBox, QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QGroupBox, QSpinBox, QDoubleSpinBox, QMessageBox, QFileDialog, QSplitter, QTreeWidget,
    QTreeWidgetItem, QFormLayout, QScrollArea, QDialog, QDialogButtonBox, QDateEdit, QTabBar,
    QMenu, QToolBar, QStatusBar, QDockWidget, QTextBrowser, QPlainTextEdit, QListView,
    QGridLayout, QSizePolicy, QToolButton, QInputDialog, QToolTip, QStyle, QProgressDialog
)
from PySide6.QtCore import Qt, QTimer, QSize, QThread, Signal, QSettings, QDir, QFileInfo, QRegularExpression, QRect, QPropertyAnimation, Property, QEasingCurve, QPointF
from PySide6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QPainter, QTextCharFormat, QSyntaxHighlighter, QAction, QPainterPath, QTextCursor, QBrush, QPen, QFontDatabase

# Backend imports (from apk_reverse_engineering_backend)
from reverse_engineering.apk_reverse_engineering_backend import (
    JINJA2_AVAILABLE,
    ANDROGUARD_AVAILABLE,
    APK_REVERSE_APP_DIR,
    APK_REVERSE_TOOLS_DIR,
    APK_REVERSE_CACHE_DIR,
    APK_REVERSE_LOGS_DIR,
    APK_REVERSE_OUTPUT_DIR,
    APKReverseDependencyManager,
    APKAnalyzer,
    APKToolCheckThread,
    APKAnalysisThread,
    APKDecompilationThread,
    APKReverseEngineeringPipeline,
    run_apk_reverse_engineering_pipeline,
)
from dynamic_analysis import AndroidDevice, AndroidEmulatorConnector, FridaManager, MitmProxyInterceptor
from dynamic_analysis.http_replay import parse_raw_request as parse_replay_request
from dynamic_analysis.http_replay import render_response as render_replay_response
from dynamic_analysis.http_replay import send_request_payload
from mobhound_project import ProjectManager, ProjectSession, PROJECT_EXTENSION, safe_name
from dynamic_analysis.payloader_backend import IntruderAttackWorker

ICONS_DIR = Path(__file__).parent / "assets" / "icons"

def configure_windows_taskbar_icon() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("MobHound.MobileSecurityTool.1")
    except Exception:
        pass

try:
    from reverse_engineering.pseudocode_generator import PseudocodeGenerator, CodeType
    PSEUDOCODE_AVAILABLE = True
except ImportError:
    PSEUDOCODE_AVAILABLE = False

# ------------------------------------------------------------------------------
# Mock data (from int2.py)
# ------------------------------------------------------------------------------
MOCK_PROJECTS = [
    {"name": "Web App Security Audit", "date": "2023-10-15", "vulnerabilities": 12, "status": "Completed"},
    {"name": "API Endpoint Testing",    "date": "2023-11-03", "vulnerabilities": 7,  "status": "In Progress"},
    {"name": "Mobile App Analysis",     "date": "2023-11-20", "vulnerabilities": 5,  "status": "Completed"},
    {"name": "Network Penetration Test","date": "2023-12-01", "vulnerabilities": 18, "status": "Pending"}
]

MOCK_VULNERABILITIES = [
    {"type": "SQL Injection", "severity": "High", "count": 3},
    {"type": "XSS", "severity": "Medium", "count": 5},
    {"type": "CSRF", "severity": "Medium", "count": 2},
    {"type": "Broken Authentication", "severity": "High", "count": 2},
    {"type": "Sensitive Data Exposure", "severity": "High", "count": 4},
    {"type": "Security Misconfiguration", "severity": "Low", "count": 6}
]

MOCK_INTERCEPTED_REQUESTS = [
    {"method": "GET", "url": "https://example.com/api/users", "status": "200", "size": "1.2KB"},
    {"method": "POST", "url": "https://example.com/login", "status": "302", "size": "0.8KB"},
    {"method": "PUT", "url": "https://example.com/api/profile", "status": "401", "size": "0.5KB"},
    {"method": "GET", "url": "https://example.com/admin", "status": "403", "size": "2.1KB"}
]

# ------------------------------------------------------------------------------
# Helper classes: ThemeManager, BasePage, JavaSyntaxHighlighter, etc.
# ------------------------------------------------------------------------------

# ── Suppress known benign Qt warnings ─────────────────────────
from PySide6.QtCore import qInstallMessageHandler, QtMsgType  # noqa: F401

def _qt_message_handler(msg_type, context, message):
    # Suppress the QFont -1 point size warning (cosmetic only, tool works fine)
    if 'setPointSize' in message and 'must be greater than 0' in message:
        return
    # Show all other messages normally
    if msg_type == QtMsgType.QtWarningMsg:
        pass  # suppress other warnings too if needed
    elif msg_type == QtMsgType.QtCriticalMsg:
        print(f'[Qt Critical] {message}')
    elif msg_type == QtMsgType.QtFatalMsg:
        print(f'[Qt Fatal] {message}')

qInstallMessageHandler(_qt_message_handler)

class ThemeManager:
    LIGHT_THEME = {
        "primary": "#FFFFFF", "secondary": "#F8F5FF", "accent": "#6A0DAD",
        "background": "#E3CFF4", "surface": "#FFFFFF", "text_primary": "#6A0DAD",
        "text_secondary": "#7A549D", "success": "#105C02", "warning": "#ffae00",
        "error": "#a51a0a", "border": "#6A0DAD", "hover": "#F3E8FF",
        "scrollbar": "#6A0DAD", "scrollbar_bg": "#E3CFF4"
    }
    DARK_THEME = {
        "primary": "#362d58", "secondary": "#2d2546", "accent": "#8d5af6",
        "background": "#12101c", "surface": "#1f1a2e", "text_primary": "#f6f5ff",
        "text_secondary": "#b3b0c2", "success": "#1b8b4f", "warning": "#ffb347",
        "error": "#dc3545", "border": "#443a63", "hover": "#4f3d78",
        "scrollbar": "#dcd6ff", "scrollbar_bg": "#1d182d"
    }

    @classmethod
    def get_theme_stylesheet(cls, theme_name):
        theme = cls.DARK_THEME if theme_name == "Dark" else cls.LIGHT_THEME
        arrow_icon = str((ICONS_DIR / ("chevron_down_white.svg" if theme_name == "Dark" else "chevron_down_purple.svg")).resolve()).replace("\\", "/")
        button_text_color = 'white' if theme_name == 'Dark' else '#6A0DAD'
        selected_text_color = 'white' if theme_name == 'Dark' else '#6A0DAD'
        sidebar_bg = '#3A3352' if theme_name == 'Dark' else '#FFFFFF'
        return f"""
            * {{
                font-family: 'Poppins';
            }}
            QMainWindow {{
                background-color: {theme['background']};
                color: {theme['text_primary']};
            }}
            QWidget {{
                background-color: {theme['background']};
                color: {theme['text_primary']};
                font-family: 'Poppins';
            }}
            QListWidget {{
                background-color: {sidebar_bg};
                color: {theme['text_primary']};
                border: none;
                font-size: 14px;
                font-family: 'Poppins';
                padding: 10px;
            }}
            QListWidget::item {{
                padding: 10px 15px;
                border-bottom: 1px solid {theme['secondary']};
            }}
            QListWidget::item:selected {{
                background-color: {theme['accent']};
                color: {selected_text_color};
            }}
            QPushButton {{
                background-color: {theme['primary']};
                color: {button_text_color};
                border: 1px solid {theme['border']};
                border-radius: 5px;
                font-family: 'Poppins';
                font-weight: bold;
                padding: 8px 15px;
                min-height: 35px;
            }}
            QPushButton:hover {{
                background-color: {theme['hover']};
                color: {button_text_color};
            }}
            QPushButton:pressed {{
                background-color: {theme['accent']};
                color: {selected_text_color};
            }}
            QPushButton:disabled {{
                background-color: {theme['border']};
                color: {theme['text_secondary']};
            }}
            QGroupBox {{
                font-weight: bold;
                font-family: 'Poppins';
                border: 1px solid {theme['border']};
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                color: {theme['text_primary']};
                background-color: {theme['surface']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: {theme['text_primary']};
            }}
            QTableWidget {{
                background-color: {theme['surface']};
                color: {theme['text_primary']};
                font-family: 'Poppins';
                border: 1px solid {theme['border']};
                gridline-color: {theme['border']};
            }}
            QTableWidget::item {{
                padding: 5px;
                border-bottom: 1px solid {theme['border']};
            }}
            QTableWidget::item:selected {{
                background-color: {theme['accent']};
                color: {selected_text_color};
            }}
            QHeaderView::section {{
                background-color: {theme['surface']};
                color: {theme['text_primary']};
                font-family: 'Poppins';
                padding: 8px;
                border: 1px solid {theme['border']};
                font-weight: bold;
            }}
            QLineEdit, QTextEdit {{
                background-color: {theme['surface']};
                color: {theme['text_primary']};
                font-family: 'Poppins';
                border: 1px solid {theme['border']};
                border-radius: 4px;
                padding: 8px;
            }}
            QLineEdit:focus, QTextEdit:focus {{
                border: 2px solid {theme['accent']};
            }}
            QTextEdit {{
                background-color: {theme['surface']};
            }}
            QComboBox {{
                background-color: {theme['surface']};
                color: {theme['text_primary']};
                font-family: 'Poppins';
                border: 1px solid {theme['border']};
                border-radius: 4px;
                padding: 8px;
                min-width: 100px;
            }}
            QComboBox::drop-down {{
                width: 28px;
                border-left: 1px solid {theme['border']};
                background-color: {theme['surface']};
            }}
            QComboBox::down-arrow {{
                image: url("{arrow_icon}");
                width: 14px;
                height: 14px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {theme['surface']};
                color: {theme['text_primary']};
                font-family: 'Poppins';
                border: 1px solid {theme['border']};
                selection-background-color: {theme['accent']};
            }}
            QCheckBox, QRadioButton {{
                color: {theme['text_primary']};
                font-family: 'Poppins';
                spacing: 8px;
            }}
            QCheckBox::indicator, QRadioButton::indicator {{
                width: 16px;
                height: 16px;
            }}
            QCheckBox::indicator:unchecked {{
                border: 2px solid {theme['border']};
                background-color: {theme['surface']};
                border-radius: 3px;
            }}
            QCheckBox::indicator:checked {{
                border: 2px solid {theme['accent']};
                background-color: {theme['accent']};
                border-radius: 3px;
            }}
            QRadioButton::indicator:unchecked {{
                border: 2px solid {theme['border']};
                background-color: {theme['surface']};
                border-radius: 8px;
            }}
            QRadioButton::indicator:checked {{
                border: 2px solid {theme['accent']};
                background-color: {theme['accent']};
                border-radius: 8px;
            }}
            QProgressBar {{
                border: 1px solid {theme['border']};
                border-radius: 4px;
                text-align: center;
                font-family: 'Poppins';
                color: {theme['text_primary']};
            }}
            QProgressBar::chunk {{
                background-color: {theme['accent']};
                border-radius: 3px;
            }}
            QTabWidget::pane {{
                border: 1px solid {theme['border']};
                border-radius: 5px;
                background-color: {theme['surface']};
            }}
            QTabBar::tab {{
                background-color: {theme['surface']};
                color: {theme['text_primary']};
                font-family: 'Poppins';
                border: 1px solid {theme['border']};
                padding: 8px 15px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }}
            QTabBar::tab:selected {{
                background-color: {theme['surface']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border']};
            }}
            QTabBar::tab:hover {{
                background-color: {theme['hover']};
            }}
            QScrollArea {{
                border: none;
                background-color: {theme['background']};
            }}
            QScrollBar:vertical {{
                background-color: {theme['scrollbar_bg']};
                width: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {theme['scrollbar']};
                border-radius: 6px;
                min-height: 20px;
                margin: 2px 2px 2px 2px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {theme['accent']};
            }}
            QScrollBar:horizontal {{
                background-color: {theme['scrollbar_bg']};
                height: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {theme['scrollbar']};
                border-radius: 6px;
                min-width: 20px;
                margin: 2px 2px 2px 2px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background-color: {theme['accent']};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                border: none;
                background: none;
            }}
            QSplitter::handle {{
                background-color: {theme['border']};
            }}
            QSplitter::handle:hover {{
                background-color: {theme['accent']};
            }}
            QLabel {{
                color: {theme['text_primary']};
                font-family: 'Poppins';
                background-color: transparent;
                border: none;
            }}
            QLabel[header="true"] {{
                font-size: 18px;
                font-weight: bold;
                padding: 10px 0;
                color: {theme['text_primary']};
            }}
            QFrame[file_upload="true"] {{
                border: 2px dashed {theme['border']};
                border-radius: 8px;
                background-color: {theme['surface']};
                padding: 20px;
            }}
            QFrame[file_upload="true"]:hover {{
                border-color: {theme['accent']};
                background-color: {theme['hover']};
            }}
        """

class BasePage(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.projects = MOCK_PROJECTS.copy()
        self._setup_base_ui()
        self._setup_ui()
    def _setup_base_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.container = QWidget()
        self.container.setObjectName("pageContainer")
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setSpacing(20)
        self.container_layout.setContentsMargins(20, 20, 20, 20)
        self.scroll.setWidget(self.container)
        root_layout.addWidget(self.scroll)
    def _setup_ui(self):
        pass
    def content_layout(self):
        return self.container_layout
    def _push_global_status(self, message: str, progress_value: Optional[int] = None, progress_text: Optional[str] = None) -> None:
        main_window = self.window()
        if hasattr(main_window, "set_global_status"):
            main_window.set_global_status(message, progress_value=progress_value, progress_text=progress_text, source=self)

class JavaSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            "abstract", "assert", "boolean", "break", "byte", "case", "catch",
            "char", "class", "const", "continue", "default", "do", "double",
            "else", "enum", "extends", "final", "finally", "float", "for",
            "goto", "if", "implements", "import", "instanceof", "int", "interface",
            "long", "native", "new", "package", "private", "protected", "public",
            "return", "short", "static", "strictfp", "super", "switch",
            "synchronized", "this", "throw", "throws", "transient", "try",
            "void", "volatile", "while"
        ]
        for word in keywords:
            pattern = QRegularExpression(r"\b" + word + r"\b")
            self.highlighting_rules.append((pattern, keyword_format))
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#CE9178"))
        pattern = QRegularExpression(r'"[^"\\]*(\\.[^"\\]*)*"')
        self.highlighting_rules.append((pattern, string_format))
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))
        pattern = QRegularExpression(r"//[^\n]*")
        self.highlighting_rules.append((pattern, comment_format))
        self.multi_line_comment_format = QTextCharFormat()
        self.multi_line_comment_format.setForeground(QColor("#6A9955"))
        self.comment_start = QRegularExpression(r"/\*")
        self.comment_end = QRegularExpression(r"\*/")
    def highlightBlock(self, text):
        for pattern, fmt in self.highlighting_rules:
            match_iterator = pattern.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), fmt)
        self.setCurrentBlockState(0)
        start_index = 0
        if self.previousBlockState() != 1:
            start_index = self.comment_start.match(text).capturedStart()
        while start_index >= 0:
            end_match = self.comment_end.match(text, start_index)
            end_index = end_match.capturedStart()
            if end_index == -1:
                self.setCurrentBlockState(1)
                comment_length = len(text) - start_index
                self.setFormat(start_index, comment_length, self.multi_line_comment_format)
                break
            else:
                comment_length = end_index - start_index + end_match.capturedLength()
                self.setFormat(start_index, comment_length, self.multi_line_comment_format)
                start_index = self.comment_start.match(text, start_index + comment_length).capturedStart()

class AnalysisThread(QThread):
    progress_update = Signal(int)
    result_ready = Signal(dict)
    def __init__(self, target, scan_type):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.is_running = True
    def run(self):
        for i in range(101):
            if not self.is_running:
                break
            self.progress_update.emit(i)
            self.msleep(50)
        if self.is_running:
            results = {"target": self.target, "scan_type": self.scan_type,
                       "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                       "vulnerabilities_found": random.randint(1, 15),
                       "critical_issues": random.randint(0, 3), "warnings": random.randint(5, 25)}
            self.result_ready.emit(results)
    def stop(self):
        self.is_running = False

class StyledButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

class AnimatedToggle(QCheckBox):
    toggled = Signal(bool)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(60, 28)
        self.setCursor(Qt.PointingHandCursor)
        self._track_color = QColor("#CCCCCC")
        self._thumb_color = QColor("#FFFFFF")
        self._active_color = QColor("#8A2BE2")
        self._thumb_position = 3
        self._animation = QPropertyAnimation(self, b"thumb_position", self)
        self._animation.setDuration(200)
        self._animation.setEasingCurve(QEasingCurve.InOutCubic)
        self.stateChanged.connect(lambda: self.toggled.emit(self.isChecked()))
    @Property(int)
    def thumb_position(self):
        return self._thumb_position
    @thumb_position.setter  # type: ignore[misc]
    def thumb_position(self, pos: float) -> None:
        self._thumb_position = pos
        self.update()
    def hitButton(self, pos):
        return self.contentsRect().contains(pos)
    def nextCheckState(self):
        super().nextCheckState()
        end_value = self.width() - 25 if self.isChecked() else 3
        self._animation.setEndValue(end_value)
        self._animation.start()
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        track_color = self._active_color if self.isChecked() else self._track_color
        p.setBrush(track_color)
        p.drawRoundedRect(0, 0, self.width(), self.height(), self.height()/2, self.height()/2)
        p.setBrush(self._thumb_color)
        p.drawEllipse(self._thumb_position, 3, 22, 22)
        p.end()

class FileUploadWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("file_upload", "true")
        self.setAcceptDrops(True)
        self.file_path = None
        self._setup_ui()
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        upload_button = StyledButton("ðŸ“ Upload File")
        upload_button.clicked.connect(self.browse_files)
        upload_button.setMinimumHeight(40)
        layout.addWidget(upload_button)
        self.file_info = QLabel("No file selected")
        self.file_info.setAlignment(Qt.AlignCenter)
        self.file_info.setStyleSheet("font-size: 12px; margin-top: 8px;")
        layout.addWidget(self.file_info)
        layout.addStretch()
    def browse_files(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*);;Text Files (*.txt);;JSON Files (*.json);;Config Files (*.conf *.ini);;APK Files (*.apk)")
        if file_path:
            self.set_file_path(file_path)
    def set_file_path(self, file_path):
        self.file_path = file_path
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        size_str = self.format_file_size(file_size)
        self.file_info.setText(f"{file_name} ({size_str})")
    def format_file_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls and urls[0].isLocalFile():
            file_path = urls[0].toLocalFile()
            self.set_file_path(file_path)
            event.acceptProposedAction()
    def get_file_path(self):
        return self.file_path

class ReportGenerator:
    def __init__(self, template_dir="templates"):
        if not JINJA2_AVAILABLE:
            raise ImportError("Jinja2 is not available. Please install it with: pip install jinja2")
        self.template_dir = template_dir
        os.makedirs(template_dir, exist_ok=True)
        from jinja2 import Environment, FileSystemLoader
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self._create_default_templates()
    def _create_default_templates(self):
        templates = {
            "comprehensive_report.html": self._get_comprehensive_template(),
            "executive_summary.html": self._get_executive_template(),
            "technical_report.html": self._get_technical_template(),
            "vulnerability_report.html": self._get_vulnerability_template()
        }
        for template_name, template_content in templates.items():
            template_path = os.path.join(self.template_dir, template_name)
            if not os.path.exists(template_path):
                with open(template_path, 'w', encoding='utf-8') as f:
                    f.write(template_content)
    def _get_comprehensive_template(self):
        return """<!DOCTYPE html>... (full template as in int2.py) ..."""
    def _get_executive_template(self): return ""
    def _get_technical_template(self): return ""
    def _get_vulnerability_template(self): return ""
    def generate_report(self, data, options):
        try:
            template_data = self._prepare_report_data(data, options)
            template_name = self._get_template_name(options['type'])
            template = self.env.get_template(template_name)
            html_content = template.render(**template_data)
            return html_content
        except Exception as e:
            raise Exception(f"Failed to generate report: {str(e)}")
    def _get_template_name(self, report_type):
        template_map = {"Comprehensive": "comprehensive_report.html", "Executive Summary": "executive_summary.html",
                        "Technical Details": "technical_report.html", "Vulnerability Only": "vulnerability_report.html"}
        return template_map.get(report_type, "comprehensive_report.html")
    def _prepare_report_data(self, data, options):
        total_vulnerabilities = sum(vuln['count'] for vuln in data['vulnerabilities'])
        critical_count = sum(vuln['count'] for vuln in data['vulnerabilities'] if vuln['severity'] == 'High')
        completed_projects = len([p for p in data['projects'] if p['status'] == 'Completed'])
        active_projects = len([p for p in data['projects'] if p['status'] == 'In Progress'])
        risk_percentage = min(100, int((critical_count / max(1, total_vulnerabilities)) * 100)) if total_vulnerabilities > 0 else 0
        if risk_percentage > 70: overall_risk = "Critical"
        elif risk_percentage > 40: overall_risk = "High"
        elif risk_percentage > 20: overall_risk = "Medium"
        else: overall_risk = "Low"
        recommendations = [ ... ]  # as in int2.py
        vuln_types = [v['type'] for v in data['vulnerabilities']]
        if "SQL Injection" in vuln_types: recommendations.append("Implement parameterized queries...")
        if "XSS" in vuln_types: recommendations.append("Apply proper output encoding  # noqa...")
        if "Broken Authentication" in vuln_types: recommendations.append("Enforce strong password policies  # noqa...")
        project_dates = [p['date'] for p in data['projects'] if p.get('date')]
        start_date = min(project_dates) if project_dates else datetime.now().strftime('%Y-%m-%d')
        end_date = max(project_dates) if project_dates else datetime.now().strftime('%Y-%m-%d')
        return {
            'report_title': f"Security Assessment - {datetime.now().strftime('%Y-%m-%d')}",
            'report_type': options['type'], 'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'current_year': datetime.now().year, 'start_date': start_date, 'end_date': end_date,
            'projects': data['projects'], 'vulnerabilities': data['vulnerabilities'],
            'total_vulnerabilities': total_vulnerabilities, 'critical_count': critical_count,
            'completed_projects': completed_projects, 'active_projects': active_projects,
            'risk_percentage': risk_percentage, 'overall_risk': overall_risk,
            'recommendations': recommendations, 'sections': options.get('sections', {}),
            'key_findings': [ f"Found {total_vulnerabilities} vulnerabilities...", f"{critical_count} critical issues...",
                              f"Overall security posture: {overall_risk} risk level ({risk_percentage}%)",
                              f"{completed_projects} projects completed assessment, {active_projects} in progress" ]
        }

class PDFReportWriter:
    def generate(self, file_path, report_data):
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        doc = SimpleDocTemplate(file_path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []
        elements.append(Paragraph("<b>Security Assessment Report</b>", styles['Title']))
        elements.append(Spacer(1,20))
        elements.append(Paragraph(f"Generated On: {datetime.now()}", styles['Normal']))
        elements.append(Paragraph(f"Total Projects: {len(report_data['projects'])}", styles['Normal']))
        elements.append(Spacer(1,20))
        elements.append(Paragraph("<b>Projects Overview</b>", styles['Heading2']))
        table_data = [["Name","Date","Vulnerabilities","Status"]]
        for p in report_data['projects']: table_data.append([p['name'],p['date'],p['vulnerabilities'],p['status']])
        table = Table(table_data)
        table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.grey),('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),('GRID',(0,0),(-1,-1),1,colors.black)]))
        elements.append(table)
        elements.append(Spacer(1,20))
        elements.append(Paragraph("<b>Vulnerabilities Summary</b>", styles['Heading2']))
        vuln_data = [["Type","Severity","Count"]]
        for v in report_data['vulnerabilities']: vuln_data.append([v['type'],v['severity'],v['count']])
        vuln_table = Table(vuln_data)
        vuln_table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.darkred),('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),('GRID',(0,0),(-1,-1),1,colors.black)]))
        elements.append(vuln_table)
        doc.build(elements)

class NewProjectDialog(QDialog):
    # ... as in int2.py (full code)
    pass

class GenerateReportDialog(QDialog):
    # ... as in int2.py
    pass

# ------------------------------------------------------------------------------
# DashboardPage
# ------------------------------------------------------------------------------
class DashboardPage(BasePage):
    dashboard_stats_ready = Signal(dict)

    def __init__(self, project_manager: Optional[ProjectManager] = None, project_session: Optional[ProjectSession] = None):
        self.projects = []
        self.project_manager = project_manager  # type: Optional[ProjectManager]
        self.project_session = project_session  # type: Optional[ProjectSession]
        self.expanded_projects = {}
        self.is_scanning = False
        self.total_vulnerabilities_found = 0
        self.module_card = None
        self.action_section = None
        self.action_cards = []
        self.left_section = None
        self.center_section = None
        self.right_section = None
        self.metric_cards = []
        self.action_button_widgets = []
        self.current_project_card = None
        self.projects_scroll_layout = None
        self.projects_scroll_widget = None
        self.current_project_label = None
        self.current_module = "N/A"
        self.current_app_name = "N/A"
        self.severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        self.last_scan_result = None
        self.pie_chart_widget = None
        self._dashboard_stats_loading = False
        self.modules_used = set()
        self.analyzed_apps = set()
        self.analyzed_files = set()
        super().__init__()
        self.projects = []
        self.refresh_projects_view()
        self.dashboard_stats_ready.connect(self._apply_dashboard_stats)
    def _setup_ui(self):
        layout = self.container_layout
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(12)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)
        cards_layout.setContentsMargins(0,0,0,0)
        # Dashboard top title
        _dash_hdr = QHBoxLayout()
        _dash_icon_lbl = QLabel()
        _dash_logo_p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icons", "mobhound1.png")
        if os.path.exists(_dash_logo_p):
            _dash_icon_lbl.setPixmap(QPixmap(_dash_logo_p).scaled(32,32,Qt.KeepAspectRatio,Qt.SmoothTransformation))
        _dash_icon_lbl.setStyleSheet("background:transparent;")
        _dash_hdr.addWidget(_dash_icon_lbl, 0)
        _dash_title = QLabel("MobHound Dashboard")
        _dash_title.setFont(QFont("Poppins", 14, QFont.Bold))
        _dash_title.setStyleSheet("color:white;background:transparent;")
        _dash_hdr.addWidget(_dash_title, 1)
        _ref_btn = QPushButton("↻  Refresh")
        _ref_btn.setStyleSheet(
            "QPushButton{background:#5b21b6;color:white;border-radius:6px;padding:5px 14px;"
            "font-weight:bold;font-size:11px;}QPushButton:hover{background:#7c3aed;}")
        _ref_btn.clicked.connect(self._full_dashboard_refresh)
        _dash_hdr.addWidget(_ref_btn, 0)
        layout.addLayout(_dash_hdr)
        target_card = self.create_current_target_card("#481176","#370855")
        cards_layout.addWidget(target_card)
        apps_card = self.create_center_metric_card("📱  Applications Analyzed","00","#481176","#370855")
        cards_layout.addWidget(apps_card)
        files_card = self.create_center_metric_card("📁  Files Analyzed","00","#481176","#370855")
        cards_layout.addWidget(files_card)
        module_card = self.create_center_metric_card("⚙️  Module in Use","N/A","#481176","#370855")
        self.module_card = module_card
        cards_layout.addWidget(module_card)
        layout.addLayout(cards_layout,0)
        sections_layout = QHBoxLayout()
        sections_layout.setContentsMargins(0,0,0,0)
        sections_layout.setSpacing(12)
        left_section = self.create_projects_section()
        left_section.setFixedWidth(300)
        left_section.setFixedHeight(390)
        self.left_section = left_section
        sections_layout.addWidget(left_section)
        center_section = self.create_scan_results_section()
        center_section.setMinimumWidth(400)
        center_section.setFixedHeight(390)
        self.center_section = center_section
        sections_layout.addWidget(center_section, 1)  # stretch=1 fills remaining space
        right_section = self.create_action_buttons_section()
        right_section.setFixedWidth(300)
        right_section.setFixedHeight(390)
        self.right_section = right_section
        sections_layout.addWidget(right_section,0,Qt.AlignTop|Qt.AlignRight)
        layout.addLayout(sections_layout,1)
        QTimer.singleShot(0, self.sync_action_cards_size)
        QTimer.singleShot(120, self.sync_action_cards_size)
        self.apply_dashboard_theme("Dark")
        self.refresh_projects_view()
        self.refresh_current_project_label()
        QTimer.singleShot(350, self._populate_dashboard_on_startup)

    def _populate_dashboard_on_startup(self):
        """Show real project list, delete buttons, and current totals without requiring Refresh."""
        self.refresh_projects_view()
        self._refresh_dashboard_counters()
        if hasattr(self, "scan_status_label"):
            self.scan_status_label.setText("Loading totals...")
        self._full_dashboard_refresh()

    def create_metric_card(self, title, value, color_start, color_end):
        card = QFrame()
        card.setObjectName("dashboardMetricCard")
        card.setStyleSheet(f"QFrame#dashboardMetricCard{{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {color_start},stop:1 {color_end});border-radius:10px;border:1px solid #5D2E8C;padding:0px;}}")
        card.setMinimumHeight(110)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12,10,12,10)
        card_layout.setSpacing(6)
        title_label = QLabel(title)
        title_label.setFont(QFont("Poppins",11,QFont.Bold))
        title_label.setStyleSheet("color:white;background-color:transparent;")
        card_layout.addWidget(title_label)
        value_label = QLabel(value)
        value_label.setFont(QFont("Poppins",22,QFont.Bold))
        value_label.setStyleSheet("color:white;background-color:transparent;")
        value_label.setWordWrap(True)
        card_layout.addWidget(value_label)
        card_layout.addStretch()
        self.metric_cards.append(card)
        return card
    def create_center_metric_card(self, title, value, color_start, color_end):
        card = QFrame()
        card.setObjectName("dashboardMetricCard")
        card.setStyleSheet(f"QFrame#dashboardMetricCard{{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {color_start},stop:1 {color_end});border-radius:10px;border:1px solid #5D2E8C;padding:0px;}}")
        card.setMinimumHeight(110)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12,10,12,10)
        card_layout.setSpacing(4)
        title_label = QLabel(title)
        title_label.setFont(QFont("Poppins",14,QFont.Bold))
        title_label.setStyleSheet("color:white;background-color:transparent;")
        card_layout.addWidget(title_label)
        value_label = QLabel(value)
        value_label.setFont(QFont("Poppins",20,QFont.Bold))
        value_label.setStyleSheet("color:white;background-color:transparent;")
        value_label.setWordWrap(True)
        value_label.setAlignment(Qt.AlignCenter)
        card_layout.addStretch()
        card_layout.addWidget(value_label)
        card_layout.addStretch()
        if "Applications Analyzed" in title:
            self.applications_analyzed_value_label = value_label
            value_label.setFont(QFont("Poppins",26,QFont.Bold))
        elif "Files Analyzed" in title:
            self.files_analyzed_value_label = value_label
            value_label.setFont(QFont("Poppins",26,QFont.Bold))
        elif "Module in Use" in title:
            self.module_in_use_value_label = value_label
        self.metric_cards.append(card)
        return card
    def create_current_target_card(self, color_start, color_end):
        card = QFrame()
        card.setObjectName("dashboardMetricCard")
        card.setStyleSheet(f"QFrame#dashboardMetricCard{{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 {color_start},stop:1 {color_end});border-radius:10px;border:1px solid #5D2E8C;padding:0px;}}")
        card.setMinimumHeight(110)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12,10,12,10)
        card_layout.setSpacing(4)
        title_label = QLabel("Current Target")
        title_label.setFont(QFont("Poppins",14,QFont.Bold))
        title_label.setStyleSheet("color:white;background-color:transparent;")
        card_layout.addWidget(title_label)
        self.current_target_value_label = QLabel("N/A")
        self.current_target_value_label.setFont(QFont("Poppins",20,QFont.Bold))
        self.current_target_value_label.setStyleSheet("color:white;background-color:transparent;")
        self.current_target_value_label.setWordWrap(True)
        self.current_target_value_label.setAlignment(Qt.AlignCenter)
        card_layout.addStretch()
        card_layout.addWidget(self.current_target_value_label)
        card_layout.addStretch()
        self.metric_cards.append(card)
        return card
    def set_current_target(self, target_name):
        target = (target_name or "").strip()
        if not target: self.current_target_value_label.setText("N/A")
        else: self.current_target_value_label.setText(target)
    def set_module_in_use(self, module_name):
        if not hasattr(self, "module_in_use_value_label"): return
        name = (module_name or "").strip()
        self.module_in_use_value_label.setText(name if name else "N/A")
    def set_workspace_context(self, project_manager, project_session):
        self.project_manager = project_manager
        self.project_session = project_session
        self.refresh_projects_view()
        self.refresh_current_project_label()
    def _full_dashboard_refresh(self):
        """Refresh dashboard with real overall data collected since tool usage began."""
        self._start_dashboard_stats_refresh()

    def _start_dashboard_stats_refresh(self):
        if self._dashboard_stats_loading:
            return
        self._dashboard_stats_loading = True
        if hasattr(self, "scan_status_label"):
            self.scan_status_label.setText("Refreshing...")

        base_apps = set(self.analyzed_apps)
        base_files = set(self.analyzed_files)
        base_modules = set(self.modules_used)

        def worker():
            try:
                stats = self._collect_overall_dashboard_stats(base_apps, base_files, base_modules)
            except Exception as exc:
                stats = {"error": str(exc)}
            self.dashboard_stats_ready.emit(stats)

        thread = threading.Thread(target=worker, name="MobHoundDashboardStats", daemon=True)
        thread.start()

    def _apply_dashboard_stats(self, stats):
        self._dashboard_stats_loading = False
        if not isinstance(stats, dict) or stats.get("error"):
            if hasattr(self, "scan_status_label"):
                self.scan_status_label.setText("Refresh Failed")
            return
        self.analyzed_apps.update(stats["applications"])
        self.analyzed_files.update(stats["files"])
        self.modules_used.update(stats["modules"])
        self.total_vulnerabilities_found = stats["total_vulnerabilities"]
        self.severity_counts = stats["severity_counts"]

        self.refresh_projects_view()
        if hasattr(self, "applications_analyzed_value_label"):
            self.applications_analyzed_value_label.setText(str(len(stats["applications"])))
        if hasattr(self, "files_analyzed_value_label"):
            self.files_analyzed_value_label.setText(str(len(stats["files"])))
        if stats["latest_target"] and hasattr(self, "current_target_value_label"):
            self.current_target_value_label.setText(stats["latest_target"][:22])
        if hasattr(self, "subtitle_label"):
            self.subtitle_label.setText(f"Total Vulnerabilities ({stats['total_vulnerabilities']})")
        if hasattr(self, "scan_status_label"):
            self.scan_status_label.setText("Overall Summary")
        if hasattr(self, "pie_chart_widget") and self.pie_chart_widget:
            try:
                self.pie_chart_widget.update()
            except Exception:
                pass
        self.refresh_current_project_label()

    def _collect_overall_dashboard_stats(self, base_apps=None, base_files=None, base_modules=None):
        import glob, json as _j, os as _os
        from pathlib import Path as _P

        result_files = sorted(
            glob.glob("projects/**/scanner_results/*_result.json", recursive=True),
            key=_os.path.getmtime,
            reverse=True,
        )
        total_vulns = 0
        latest_target = ""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        applications = set(base_apps or [])
        files = set(base_files or [])
        modules = set(base_modules or [])

        for result_file in result_files:
            result_path = _P(result_file)
            project_dir = result_path.parent.parent
            try:
                data = _j.loads(result_path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue

            findings = data.get("findings", [])
            if not isinstance(findings, list):
                findings = []
            total_vulns += len(findings)
            modules.add("Scanner")

            target = data.get("package_name") or _P(str(data.get("apk_path") or project_dir)).name or project_dir.name
            if target:
                applications.add(str(target))
                if not latest_target:
                    latest_target = str(target)

            apk_path = str(data.get("apk_path") or "")
            if apk_path:
                files.add(apk_path)

            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("severity", "")).lower()
                if severity == "info":
                    severity = "low"
                if severity in severity_counts:
                    severity_counts[severity] += 1
                for affected in finding.get("affected_files", []) or []:
                    if affected:
                        files.add(str(affected))

        for session_state in glob.glob("projects/**/session_state.json", recursive=True):
            try:
                state = _j.loads(_P(session_state).read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            applications.update(str(v) for v in state.get("applications_analyzed", []) if v)
            files.update(str(v) for v in state.get("files_analyzed", []) if v)
            modules.update(str(v) for v in state.get("modules_used", []) if v)

        for java_file in glob.glob("projects/**/jadx_source/**/*.java", recursive=True):
            files.add(java_file)

        return {
            "applications": applications,
            "files": files,
            "modules": modules,
            "severity_counts": severity_counts,
            "total_vulnerabilities": total_vulns,
            "latest_target": latest_target,
        }

    def refresh_projects_view(self):
        self.projects = self._load_available_project_files()
        if not self.projects_scroll_layout: return
        while self.projects_scroll_layout.count():
            item = self.projects_scroll_layout.takeAt(0)
            widget = item.widget()
            if widget: widget.deleteLater()
        for i, project in enumerate(self.projects):
            self.projects_scroll_layout.addWidget(self.create_project_item(project, i))
        self.projects_scroll_layout.addStretch()

    def _load_available_project_files(self):
        rows = []
        seen_paths = set()

        def add_recent_item(item):
            path_text = str(item.get("path", "") or "").strip()
            if not path_text:
                return
            project_path = Path(path_text)
            try:
                resolved = project_path.resolve()
            except Exception:
                resolved = project_path
            if resolved in seen_paths:
                return
            if project_path.suffix.lower() != PROJECT_EXTENSION or not project_path.is_file():
                return
            seen_paths.add(resolved)
            rows.append({
                "name": item.get("name") or project_path.stem,
                "date": (item.get("updated_at") or datetime.fromtimestamp(project_path.stat().st_mtime).isoformat())[:10],
                "vulnerabilities": 0,
                "status": "Saved",
                "path": str(project_path),
                "project_uuid": item.get("project_uuid", ""),
            })

        if self.project_manager:
            for item in self.project_manager.list_recent_projects():
                add_recent_item(item)

        if self.project_session and self.project_session.project_file:
            metadata = self.project_session.metadata
            add_recent_item({
                "name": metadata.project_name if metadata else self.project_session.project_file.stem,
                "updated_at": metadata.updated_at if metadata else "",
                "path": str(self.project_session.project_file),
                "project_uuid": metadata.project_uuid if metadata else "",
            })

        return rows
    def refresh_current_project_label(self):
        if not self.current_project_label: return
        if self.project_session and self.project_session.metadata:
            name = self.project_session.metadata.project_name
            if self.project_session.metadata.temporary:
                self.current_project_label.setText("Current Project\nTemporary")
            else:
                self.current_project_label.setText(f"Current Project\n{name}")
        else:
            self.current_project_label.setText("Current Project\nTemporary")
    def _delete_all_projects(self):
        """Delete all projects from recent list."""
        if not self.projects:
            QMessageBox.information(self, "No Projects", "No projects to delete."); return
        reply = QMessageBox.question(
            self, "Delete All Projects",
            f"Remove all {len(self.projects)} project(s) from recent list?" + chr(10) +
            "APK files and scan records are NOT deleted.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes: return
        self.projects = []
        try:
            import json as _jj
            from pathlib import Path as _PP
            recent_f = _PP.home() / ".mobhound_workspace" / "recent_projects.json"
            if recent_f.exists():
                recent_f.write_text("[]", encoding="utf-8")
        except Exception: pass
        self.refresh_projects_view()
        QMessageBox.information(self, "Done", "All projects cleared from recent list.")

    def create_projects_section(self):
        section = QFrame()
        section.setObjectName("dashboardProjectsSection")
        section.setStyleSheet("QFrame#dashboardProjectsSection{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:8px;border:1px solid #5D2E8C;padding:0px;}")
        layout = QVBoxLayout(section)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(0)
        # Title row with refresh button
        _tr = QHBoxLayout()
        title = QLabel("All Projects")
        title.setFont(QFont("Poppins",12,QFont.Bold))
        title.setStyleSheet("color:white;background-color:transparent;")
        layout.addWidget(title)
        layout.addSpacing(8)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea{background-color:transparent;border:none;}")
        scroll_widget = QWidget()
        scroll_widget.setStyleSheet("background-color:transparent;")
        scroll_layout = QVBoxLayout(scroll_widget)
        self.projects_scroll_widget = scroll_widget
        self.projects_scroll_layout = scroll_layout
        scroll_layout.setContentsMargins(0,0,0,0)
        scroll_layout.setSpacing(0)
        for i, project in enumerate(self.projects):
            project_item = self.create_project_item(project, i)
            scroll_layout.addWidget(project_item)
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

        # Delete All link at bottom
        del_all_row = QHBoxLayout()
        del_all_row.addStretch()
        del_all_btn = QPushButton("🗑  Delete All Projects")
        del_all_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#f87171;"
            "border:1px solid rgba(248,113,113,0.3);border-radius:6px;"
            "padding:3px 12px;font-size:10px;}"
            "QPushButton:hover{background:rgba(220,38,38,0.18);"
            "border-color:rgba(248,113,113,0.65);}")
        del_all_btn.setCursor(Qt.PointingHandCursor)
        del_all_btn.clicked.connect(self._delete_all_projects)
        del_all_row.addWidget(del_all_btn, 0)
        layout.addLayout(del_all_row)
        return section
    def create_project_item(self, project, index):
        item_container = QWidget()
        item_container.setStyleSheet("background-color:transparent;")
        item_layout = QVBoxLayout(item_container)
        item_layout.setContentsMargins(0,0,0,0)
        item_layout.setSpacing(0)
        header_widget = QWidget()
        header_widget.setStyleSheet("background-color:transparent;")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(8,8,8,8)
        header_layout.setSpacing(0)
        project_name = QLabel(project['name'])
        project_name.setFont(QFont("Poppins",10,QFont.Bold))
        project_name.setStyleSheet("color:white;background-color:transparent;")
        header_layout.addWidget(project_name,1)
        arrow_btn = QPushButton(">" if index not in self.expanded_projects else "v")
        arrow_btn.setObjectName("dashboardProjectArrow")
        arrow_btn.setFont(QFont("Poppins",11,QFont.Bold))
        arrow_btn.setStyleSheet("QPushButton{background-color:transparent;color:white;border:none;padding:2px 4px;min-width:20px;}QPushButton:hover{color:#FFFF99;}")
        arrow_btn.setMaximumWidth(30)
        arrow_btn.setFixedHeight(25)
        arrow_btn.setCursor(Qt.PointingHandCursor)
        header_layout.addWidget(arrow_btn,0)

        # Delete button for this project
        del_btn = QPushButton("🗑")
        del_btn.setObjectName("projDelBtn")
        del_btn.setFixedSize(22, 22)
        del_btn.setFont(QFont("Poppins", 9))
        del_btn.setToolTip("Delete this project")
        del_btn.setStyleSheet(
            "QPushButton#projDelBtn{background:rgba(220,38,38,0.15);color:#f87171;"
            "border:1px solid rgba(220,38,38,0.3);border-radius:4px;padding:0px;}"
            "QPushButton#projDelBtn:hover{background:rgba(220,38,38,0.45);color:white;}")
        del_btn.setCursor(Qt.PointingHandCursor)

        # Capture project data for delete
        _proj_name = project.get("name", "")
        _proj_uuid = project.get("project_uuid", "")
        _proj_path = project.get("path", "")

        def _delete_project(checked=False, pname=_proj_name, puuid=_proj_uuid, ppath=_proj_path):
            reply = QMessageBox.question(
                self, "Delete Project",
                f"Delete project: {pname}?" + chr(10) + chr(10) +
                "This removes it from the recent list." + chr(10) +
                "Scan records and APK files are NOT deleted.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply != QMessageBox.Yes:
                return
            # Remove from self.projects list
            self.projects = [p for p in self.projects
                             if p.get("name") != pname and p.get("project_uuid") != puuid]
            # Remove from project_manager storage if available
            try:
                if self.project_manager and hasattr(self.project_manager, "storage"):
                    storage = self.project_manager.storage
                    if hasattr(storage, "remove_recent"):
                        storage.remove_recent(puuid)
                    elif hasattr(storage, "_recent_file"):
                        import json as _jj
                        from pathlib import Path as _PP
                        rf = _PP(storage._recent_file)
                        if rf.exists():
                            data = _jj.loads(rf.read_text(encoding="utf-8"))
                            data = [x for x in data
                                    if x.get("project_uuid") != puuid
                                    and x.get("name") != pname]
                            rf.write_text(_jj.dumps(data, indent=2), encoding="utf-8")
            except Exception:
                pass
            # Also try workspace recent_projects.json
            try:
                import json as _jj
                from pathlib import Path as _PP
                recent_f = _PP.home() / ".mobhound_workspace" / "recent_projects.json"
                if recent_f.exists():
                    data = _jj.loads(recent_f.read_text(encoding="utf-8"))
                    data = [x for x in data
                            if x.get("project_uuid") != puuid
                            and x.get("name") != pname]
                    recent_f.write_text(_jj.dumps(data, indent=2), encoding="utf-8")
            except Exception:
                pass
            self.refresh_projects_view()

        del_btn.clicked.connect(_delete_project)
        header_layout.addWidget(del_btn, 0)
        def toggle_expand():
            if index in self.expanded_projects:
                self.expanded_projects.pop(index)
                arrow_btn.setText(">")
                details_widget.hide()
            else:
                self.expanded_projects[index]=True
                arrow_btn.setText("v")
                details_widget.show()
        arrow_btn.clicked.connect(toggle_expand)
        item_layout.addWidget(header_widget)
        details_widget = QWidget()
        details_widget.setStyleSheet("background-color:transparent;")
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(8,0,8,8)
        details_layout.setSpacing(4)
        created_label = QLabel(f"Created on: {project['date']}")
        created_label.setFont(QFont("Poppins",9))
        created_label.setStyleSheet("color:rgba(255,255,255,0.85);background-color:transparent;")
        details_layout.addWidget(created_label)
        files_label = QLabel("File(s) Analyzed:")
        files_label.setFont(QFont("Poppins",9))
        files_label.setStyleSheet("color:rgba(255,255,255,0.85);background-color:transparent;")
        details_layout.addWidget(files_label)
        apps_label = QLabel("App(s) Analyzed:")
        apps_label.setFont(QFont("Poppins",9))
        apps_label.setStyleSheet("color:rgba(255,255,255,0.85);background-color:transparent;")
        details_layout.addWidget(apps_label)
        report_link = QLabel("View project report")
        report_link.setFont(QFont("Poppins",9,QFont.Bold))
        report_link.setStyleSheet("color:rgba(255,255,200,0.9);background-color:transparent;")
        report_link.setCursor(Qt.PointingHandCursor)
        report_link.mousePressEvent = lambda _evt, p=project: self._open_project_activity_report(p)
        details_layout.addWidget(report_link)
        if index not in self.expanded_projects:
            details_widget.hide()
        item_layout.addWidget(details_widget)
        separator = QFrame()
        separator.setObjectName("dashboardProjectSeparator")
        separator.setStyleSheet("background-color:rgba(255,255,255,0.25);")
        separator.setFixedHeight(1)
        item_layout.addWidget(separator)
        return item_container
    def _open_project_activity_report(self, project):
        try:
            session_state = self._load_project_session_state(project)
            html_path = self._write_project_activity_report(project, session_state)
            webbrowser.open(html_path.as_uri())
        except Exception as exc:
            QMessageBox.critical(self, "Report Error", f"Could not open project report:\n{exc}")
    def _load_project_session_state(self, project):
        path = (project.get("path", "") or "").strip()
        if self.project_session and self.project_session.workspace_dir.exists():
            active_name = getattr(self.project_session.metadata, "project_name", "")
            if project.get("name", "") == active_name and (not path or path == str(self.project_session.project_file or "")):
                state_file = self.project_session.workspace_dir / "session_state.json"
                if state_file.exists():
                    return json.loads(state_file.read_text(encoding="utf-8"))
        if not path:
            return {}
        project_file = Path(path)
        if not project_file.exists():
            return {}
        with zipfile.ZipFile(project_file, "r") as zf:
            names = set(zf.namelist())
            if "session_state.json" not in names:
                return {}
            return json.loads(zf.read("session_state.json").decode("utf-8"))
    def _write_project_activity_report(self, project, session_state):
        base_dir = Path.home() / ".mobhound_workspace" / "project_reports"
        base_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_project = safe_name(project.get("name", "project")).replace(" ", "_")
        out_path = base_dir / f"{safe_project}_activity_{stamp}.html"
        modules = session_state.get("modules_used", []) or []
        apps = session_state.get("applications_analyzed", []) or []
        files = session_state.get("files_analyzed", []) or []
        actions = session_state.get("activity_log", []) or []
        severity = session_state.get("severity_counts", {}) or {}
        actions_html = "".join(
            f"<tr><td>{escape(str(a.get('timestamp','')))}</td><td>{escape(str(a.get('module','')))}</td><td>{escape(str(a.get('action','')))}</td><td>{escape(str(a.get('target','')))}</td><td>{escape(str(a.get('details','')))}</td></tr>"
            for a in actions[-500:]
        ) or "<tr><td colspan='5'>No activity has been recorded yet for this project.</td></tr>"
        html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Project Activity Report - {escape(project.get("name",""))}</title>
<style>
body{{font-family:Poppins,Arial,sans-serif;background:#f3f4f6;color:#111827;margin:0}}
.wrap{{max-width:1200px;margin:24px auto;padding:0 16px}}
.card{{background:#fff;border:1px solid #d1d5db;border-radius:12px;padding:16px;margin-bottom:16px}}
h1{{margin:0 0 6px 0}} .muted{{color:#6b7280}} .pill{{display:inline-block;background:#eef2ff;color:#312e81;border:1px solid #c7d2fe;padding:4px 10px;border-radius:999px;margin:4px 6px 0 0;font-size:12px}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th,td{{border:1px solid #d1d5db;padding:8px;text-align:left;vertical-align:top}} th{{background:#5b21b6;color:#fff}}
</style></head>
<body><div class="wrap">
<div class="card"><h1>MobHound Project Activity Report</h1><div class="muted">Project: {escape(project.get("name","Unnamed"))} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div></div>
<div class="card"><h3>Summary</h3><p><b>Modules Used:</b> {len(modules)} | <b>Apps Analyzed:</b> {len(apps)} | <b>Files Analyzed:</b> {len(files)} | <b>Actions Logged:</b> {len(actions)}</p>
<p><b>Severity:</b> Critical {severity.get("critical",0)} | High {severity.get("high",0)} | Medium {severity.get("medium",0)} | Low {severity.get("low",0)}</p></div>
<div class="card"><h3>Modules Used</h3>{"".join(f"<span class='pill'>{escape(str(m))}</span>" for m in modules) or "<div class='muted'>No module usage recorded.</div>"}</div>
<div class="card"><h3>Applications Analyzed</h3>{"".join(f"<span class='pill'>{escape(str(a))}</span>" for a in apps) or "<div class='muted'>No applications recorded.</div>"}</div>
<div class="card"><h3>Files Analyzed</h3>{"".join(f"<span class='pill'>{escape(str(f))}</span>" for f in files) or "<div class='muted'>No files recorded.</div>"}</div>
<div class="card"><h3>Activity Timeline</h3><table><thead><tr><th>Timestamp</th><th>Module</th><th>Action</th><th>Target</th><th>Details</th></tr></thead><tbody>{actions_html}</tbody></table></div>
</div></body></html>"""
        out_path.write_text(html, encoding="utf-8")
        return out_path

    def _collect_dashboard_activity_summary(self) -> Dict[str, Any]:
        project_rows = []
        all_actions = []
        for project in self.projects:
            project_name = str(project.get("name", "Unnamed Project") or "Unnamed Project")
            session_state = self._load_project_session_state(project)
            actions = session_state.get("activity_log", []) or []
            modules = session_state.get("modules_used", []) or []
            apps = session_state.get("applications_analyzed", []) or []
            files = session_state.get("files_analyzed", []) or []
            severity = session_state.get("severity_counts", {}) or {}
            project_rows.append({
                "name": project_name,
                "date": project.get("date", ""),
                "status": project.get("status", "Unknown"),
                "actions": len(actions),
                "modules": len(modules),
                "apps": len(apps),
                "files": len(files),
                "critical": int(severity.get("critical", 0) or 0),
                "high": int(severity.get("high", 0) or 0),
                "medium": int(severity.get("medium", 0) or 0),
                "low": int(severity.get("low", 0) or 0),
            })
            for action in actions:
                scoped_action = dict(action)
                scoped_action["project"] = project_name
                all_actions.append(scoped_action)
        all_actions.sort(key=lambda item: str(item.get("timestamp", "")))
        return {
            "total_projects": len(self.projects),
            "total_actions": sum(row["actions"] for row in project_rows),
            "projects": project_rows,
            "recent_actions": all_actions[-500:],
        }

    def create_scan_results_section(self):
        section = QFrame()
        section.setObjectName("dashboardScanResultsSection")
        section.setStyleSheet("QFrame#dashboardScanResultsSection{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:8px;border:1px solid #5D2E8C;padding:0px;}")
        self.scan_results_section = section
        layout = QVBoxLayout(section)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(10)
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0,0,0,0)
        header_layout.setSpacing(0)
        title = QLabel("Scan Results")
        title.setFont(QFont("Poppins",12,QFont.Bold))
        title.setStyleSheet("color:white;background-color:transparent;")
        header_layout.addWidget(title,1)
        self.scan_status_label = QLabel("Stopped")
        self.scan_status_label.setFont(QFont("Poppins",9,QFont.Bold))
        self.scan_status_label.setStyleSheet("color:white;background-color:transparent;")
        self.scan_status_label.setAlignment(Qt.AlignRight)
        header_layout.addWidget(self.scan_status_label,0)
        layout.addLayout(header_layout)
        self.subtitle_label = QLabel("Total Vulnerabilities (0)")
        self.subtitle_label.setFont(QFont("Poppins",10))
        self.subtitle_label.setStyleSheet("color:rgba(255,255,255,0.9);background-color:transparent;")
        layout.addWidget(self.subtitle_label)
        pie_chart = self.create_pie_chart()
        layout.addWidget(pie_chart,1)
        layout.addSpacing(8)
        layout.addSpacing(6)
        return section
    def create_pie_chart(self):
        chart_widget = QWidget()
        chart_widget.setMinimumHeight(240)
        chart_widget.setStyleSheet("background-color:transparent;")
        chart_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout = QVBoxLayout(chart_widget)
        layout.setContentsMargins(0,0,0,0)
        class PieChartWidget(QWidget):
            def __init__(self, parent_page=None):
                super().__init__()
                self.parent_page = parent_page
                self.setMouseTracking(True)
                self.tooltip_text = ""
                self.hovered_segment = -1
            def _severity_counts(self):
                if self.parent_page and hasattr(self.parent_page, 'severity_counts'):
                    return [
                        int(self.parent_page.severity_counts.get("critical", 0) or 0),
                        int(self.parent_page.severity_counts.get("high", 0) or 0),
                        int(self.parent_page.severity_counts.get("medium", 0) or 0),
                        int(self.parent_page.severity_counts.get("low", 0) or 0)
                    ]
                return [0, 0, 0, 0]
            def _slice_angles(self):
                counts = self._severity_counts()
                total = sum(counts)
                if total <= 0:
                    return [90, 90, 90, 90]
                angles = [int(c * 360 / total) for c in counts]
                angles[-1] += 360 - sum(angles)
                return angles
            def _pie_geometry(self):
                radius = max(66, min(self.width(), self.height())//2 - 16)
                return self.width()//2, self.height()//2, radius
            def paintEvent(self, event):
                painter = QPainter(self)
                painter.setRenderHint(QPainter.Antialiasing)
                painter.setRenderHint(QPainter.SmoothPixmapTransform)
                center_x, center_y, radius = self._pie_geometry()
                colors = [QColor("#CC2F2F"), QColor("#CC8400"), QColor("#C7C700"), QColor("#2FBF2F")]
                angles = self._slice_angles()
                start_angle = 0
                for i,(color,angle) in enumerate(zip(colors,angles)):
                    if angle <= 0:
                        continue
                    painter.setBrush(QBrush(color))
                    pen_width = 2 if self.hovered_segment==i else 1
                    painter.setPen(QPen(QColor(255,255,255),pen_width))
                    painter.drawPie(center_x-radius, center_y-radius, radius*2, radius*2, start_angle*16, angle*16)
                    start_angle += angle
            def mouseMoveEvent(self, event):
                import math
                center_x, center_y, radius = self._pie_geometry()
                dx = event.position().x() - center_x
                dy = event.position().y() - center_y
                distance = math.sqrt(dx*dx+dy*dy)
                if distance > radius + 2:
                    self.hovered_segment = -1
                    QToolTip.hideText()
                    self.setToolTip("")
                    self.update()
                    return
                angle = math.atan2(-dy,dx)*180/math.pi
                if angle<0: angle+=360
                segment = -1
                start_angle = 0
                for idx, slice_angle in enumerate(self._slice_angles()):
                    if slice_angle <= 0:
                        continue
                    if start_angle <= angle < start_angle + slice_angle:
                        segment = idx
                        break
                    start_angle += slice_angle
                if segment < 0:
                    segment = 3
                self.hovered_segment = segment
                severity_names = ["Critical","High","Medium","Low"]
                severity_keys = ["critical","high","medium","low"]
                if self.parent_page and hasattr(self.parent_page,'severity_counts'):
                    count = self.parent_page.severity_counts.get(severity_keys[segment],0)
                else:
                    count = 0
                self.tooltip_text = f"{severity_names[segment]}: {count}"
                QToolTip.showText(event.globalPosition().toPoint(),self.tooltip_text,self)
                self.update()
            def leaveEvent(self,event):
                self.hovered_segment = -1
                self.update()
                QToolTip.hideText()
                self.setToolTip("")
        pie_chart = PieChartWidget(self)
        self.pie_chart_widget = pie_chart
        layout.addWidget(pie_chart)
        return chart_widget
    def create_action_buttons_section(self):
        section = QFrame()
        section.setStyleSheet("QFrame{background-color:transparent;}")
        self.action_section = section
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(10)
        cards_layout = QVBoxLayout()
        cards_layout.setSpacing(10)
        cards_layout.setContentsMargins(0,0,0,0)
        report_btn = self.create_action_button("Generate Report","+")
        report_btn.clicked.connect(self.show_generate_report_dialog)
        cards_layout.addWidget(report_btn,0,Qt.AlignTop|Qt.AlignHCenter)
        quick_scan_btn = self.create_action_button("Quick Scan","+")
        quick_scan_btn.clicked.connect(self.quick_scan)
        cards_layout.addWidget(quick_scan_btn,0,Qt.AlignTop|Qt.AlignHCenter)
        current_project = QFrame()
        current_project.setObjectName("currentProjectCard")
        current_project.setStyleSheet("QFrame#currentProjectCard{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:6px;border:1px solid #5D2E8C;}")
        current_project.setCursor(Qt.PointingHandCursor)
        self.current_project_card = current_project
        project_layout = QVBoxLayout(current_project)
        project_layout.setContentsMargins(10,10,10,10)
        project_label = QLabel("Current Project\nTemporary")
        project_label.setFont(QFont("Poppins",11,QFont.Bold))
        project_label.setStyleSheet("color:white;background-color:transparent;")
        project_label.setWordWrap(True)
        project_label.setAlignment(Qt.AlignCenter)
        self.current_project_label = project_label
        project_layout.addWidget(project_label)
        cards_layout.addWidget(current_project,0,Qt.AlignTop|Qt.AlignHCenter)
        self.action_cards = [report_btn, quick_scan_btn, current_project]
        self.action_button_widgets = [report_btn, quick_scan_btn]
        layout.addLayout(cards_layout)
        layout.addStretch()
        return section
    def create_action_button(self, text, icon):
        btn = QPushButton(f"{icon}\n\n{text}")
        btn.setStyleSheet("QPushButton{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);color:white;border:1px solid #5D2E8C;border-radius:6px;font-size:13px;font-weight:bold;font-family:'Poppins';padding:8px;}QPushButton:hover{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #5D2E8C,stop:1 #481176);border:1px solid #6E1BC2;}QPushButton:pressed{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #370855,stop:1 #2A0640);}")
        btn.setMinimumHeight(85)
        btn.setCursor(Qt.PointingHandCursor)
        return btn
    def sync_action_cards_size(self):
        if not self.action_cards: return
        width = 296
        section_height = 390
        card_height = 123
        for card in self.action_cards: card.setFixedSize(width,card_height)
        if self.right_section: self.right_section.setFixedWidth(300); self.right_section.setFixedHeight(section_height)
        if self.left_section: self.left_section.setFixedWidth(300); self.left_section.setFixedHeight(section_height)
        if self.center_section: self.center_section.setMinimumWidth(400); self.center_section.setFixedHeight(section_height)
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.sync_action_cards_size()
    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self.sync_action_cards_size)
        QTimer.singleShot(120, self.sync_action_cards_size)
    def apply_dashboard_theme(self, theme_name):
        is_light = theme_name == "Light"
        text_color = "#481176" if is_light else "white"
        card_bg = "#FFFFFF" if is_light else "qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855)"
        self.container.setStyleSheet(f"background-color: {'#E3CFF4' if is_light else 'transparent'};")
        for card in self.metric_cards:
            card.setStyleSheet(f"QFrame#dashboardMetricCard{{background:{card_bg};border-radius:10px;border:1px solid #5D2E8C;padding:0px;}}")
        if self.left_section:
            self.left_section.setStyleSheet(f"QFrame#dashboardProjectsSection{{background:{card_bg};border-radius:8px;border:1px solid #5D2E8C;padding:0px;}}")
        if self.center_section:
            self.center_section.setStyleSheet(f"QFrame#dashboardScanResultsSection{{background:{card_bg};border-radius:8px;border:1px solid #5D2E8C;padding:0px;}}")
        for btn in self.action_button_widgets:
            btn.setStyleSheet(f"QPushButton{{background:{card_bg};color:{text_color};border:1px solid #5D2E8C;border-radius:6px;font-size:13px;font-weight:bold;font-family:'Poppins';padding:8px;}}QPushButton:hover{{border:1px solid #6E1BC2;}}QPushButton:pressed{{border:1px solid #6E1BC2;}}")
        if self.current_project_card:
            self.current_project_card.setStyleSheet(f"QFrame#currentProjectCard{{background:{card_bg};border-radius:6px;border:1px solid #5D2E8C;}}")
        for label in self.findChildren(QLabel):
            label.setStyleSheet(f"color:{text_color};background-color:transparent;")
        if self.left_section:
            all_labels = self.left_section.findChildren(QLabel)
            all_buttons = self.left_section.findChildren(QPushButton)
            if is_light:
                purple = "#6A0DAD"
                for lbl in all_labels: lbl.setStyleSheet(f"color:{purple};background-color:transparent;")
                for btn in all_buttons: btn.setStyleSheet(f"QPushButton{{color:{purple};background-color:transparent;border:none;font-weight:bold;}}QPushButton:hover{{color:#9966FF;}}")
                for sep in self.left_section.findChildren(QFrame, "dashboardProjectSeparator"):
                    sep.setStyleSheet("background-color:rgba(106,13,173,0.45);")
                for arrow in self.left_section.findChildren(QPushButton, "dashboardProjectArrow"):
                    arrow.setStyleSheet("QPushButton{background-color:transparent;color:#6A0DAD;border:none;padding:2px 4px;min-width:20px;font-weight:bold;}QPushButton:hover{color:#9966FF;}")
            else:
                for lbl in all_labels: lbl.setStyleSheet("color:white;background-color:transparent;")
                for btn in all_buttons: btn.setStyleSheet("QPushButton{color:white;background-color:transparent;border:none;font-weight:bold;}QPushButton:hover{color:#FFFF99;}")
                for sep in self.left_section.findChildren(QFrame, "dashboardProjectSeparator"):
                    sep.setStyleSheet("background-color:rgba(255,255,255,0.25);")
                for arrow in self.left_section.findChildren(QPushButton, "dashboardProjectArrow"):
                    arrow.setStyleSheet("QPushButton{background-color:transparent;color:white;border:none;padding:2px 4px;min-width:20px;font-weight:bold;}QPushButton:hover{color:#FFFF99;}")
        self.sync_action_cards_size()
    def show_new_project_dialog(self):
        dialog = ProjectWorkspaceDialog(self.project_manager, self)
        if dialog.exec() != QDialog.Accepted: return
        session = dialog.result_session
        if not session: return
        self.project_session = session
        self.refresh_projects_view()
        self.refresh_current_project_label()
        QMessageBox.information(self, "Project Ready", f"Project '{session.metadata.project_name}' is ready.")
    
    def on_module_status_changed(self, module_name, status, app_name):
        """Handle module status changes from scanner/extractor pages."""
        app_name = (app_name or "").strip()
        if module_name:
            self.modules_used.add(module_name)
        if app_name:
            self.analyzed_apps.add(app_name)
            if module_name in {"Scanner", "Extractor", "Analyzer"} or "." in app_name:
                self.analyzed_files.add(app_name)
            self.set_current_target(app_name)
        self._refresh_dashboard_counters()
        if status == "running":
            self.current_module = module_name
            self.current_app_name = app_name
            self.is_scanning = True
            if module_name == "Scanner" and hasattr(self, "scan_status_label"):
                self.scan_status_label.setText("Running")
            if hasattr(self, "module_in_use_value_label"):
                self.module_in_use_value_label.setText(f"{module_name}\n{app_name[:20]}")
        elif status == "completed":
            self.is_scanning = False
            if module_name:
                self.current_module = module_name
            if app_name:
                self.current_app_name = app_name
            if module_name == "Scanner" and hasattr(self, "scan_status_label") and self.last_scan_result:
                self.scan_status_label.setText(f"AI Risk: {self.last_scan_result.get('ai_risk', 'N/A')}")
            elif hasattr(self, "scan_status_label"):
                self.scan_status_label.setText(f"{module_name} Completed" if module_name else "Completed")
            if hasattr(self, "module_in_use_value_label"):
                if module_name and app_name:
                    self.module_in_use_value_label.setText(f"{module_name}\nDone: {app_name[:20]}")
                else:
                    self.module_in_use_value_label.setText(module_name if module_name else "N/A")
        elif status == "failed":
            self.is_scanning = False
            if module_name == "Scanner" and hasattr(self, "scan_status_label"):
                self.scan_status_label.setText("Stopped")
            elif hasattr(self, "scan_status_label"):
                self.scan_status_label.setText(f"{module_name} Failed" if module_name else "Failed")
        elif status == "stopped":
            self.is_scanning = False
            if module_name == "Scanner" and hasattr(self, "scan_status_label"):
                self.scan_status_label.setText("Stopped")
            elif hasattr(self, "scan_status_label"):
                self.scan_status_label.setText(f"{module_name} Stopped" if module_name else "Stopped")
    
    def on_scan_completed(self, scan_result_dict):
        """Handle scan completion from ExtractorPage with real-time data"""
        self.severity_counts = {
            "critical": int(scan_result_dict.get("critical", 0) or 0),
            "high": int(scan_result_dict.get("high", 0) or 0),
            "medium": int(scan_result_dict.get("medium", 0) or 0),
            "low": int(scan_result_dict.get("low", 0) or 0)
        }
        self.last_scan_result = scan_result_dict
        self.total_vulnerabilities_found = int(
            scan_result_dict.get("findings", 0) or sum(self.severity_counts.values())
        )
        self.current_module = "Scanner"
        if hasattr(self, "subtitle_label"):
            self.subtitle_label.setText(f"Total Vulnerabilities ({self.total_vulnerabilities_found})")
        if hasattr(self, "scan_status_label"):
            self.scan_status_label.setText(f"AI Risk: {scan_result_dict.get('ai_risk', 'N/A')}")
        if self.pie_chart_widget:
            self.pie_chart_widget.update()
            self.pie_chart_widget.repaint()
            QApplication.processEvents()
        self._refresh_dashboard_counters()

    def _refresh_dashboard_counters(self):
        if hasattr(self, "applications_analyzed_value_label"):
            self.applications_analyzed_value_label.setText(str(len(self.analyzed_apps)))
        if hasattr(self, "files_analyzed_value_label"):
            self.files_analyzed_value_label.setText(str(len(self.analyzed_files)))

    def _dashboard_vulnerability_rows(self):
        labels = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }
        rows = []
        for key, label in labels.items():
            count = int(self.severity_counts.get(key, 0) or 0)
            if count:
                rows.append({"type": f"{label} Findings", "severity": label, "count": count})
        return rows
    
    def show_generate_report_dialog(self):
        # Generate dashboard summary PDF directly (dialog flow is intentionally bypassed).
        self.generate_comprehensive_report({"type": "Dashboard Summary", "format": "PDF", "sections": {}})
    def generate_comprehensive_report(self, options):
        try:
            report_data = {
                'projects': self.projects,
                'vulnerabilities': self._dashboard_vulnerability_rows(),
                'dashboard_activity': self._collect_dashboard_activity_summary(),
            }
            
            # Include dashboard scan data if available
            if self.last_scan_result:
                report_data['dashboard_scan'] = self.last_scan_result
                report_data['severity_breakdown'] = self.severity_counts
            report_data['dashboard_context'] = {
                "project_type": (self.project_session.metadata.project_name if self.project_session and self.project_session.metadata else "Temporary"),
                "modules_used": sorted(self.modules_used),
                "applications_analyzed": sorted(self.analyzed_apps),
                "files_analyzed": sorted(self.analyzed_files),
                "severity_breakdown": self.severity_counts,
            }
            report_data['dashboard_activity'] = self._collect_dashboard_activity_summary()
            
            if options['format'] == 'HTML' and not JINJA2_AVAILABLE:
                QMessageBox.warning(self, "Jinja2 Not Available", "Falling back to text format.")
                options['format'] = 'Text'
            if options['format'] == 'HTML' and JINJA2_AVAILABLE:
                self._generate_html_report(report_data, options)
            elif options['format'] == 'PDF':
                self._generate_pdf_report(report_data, options)
            elif options['format'] == 'JSON':
                self._generate_json_report(report_data, options)
            elif options['format'] == 'CSV':
                self._generate_csv_report(report_data, options)
            elif options['format'] == 'XML':
                self._generate_xml_report(report_data, options)
            else:
                self._generate_text_report(report_data, options)
        except Exception as e:
            QMessageBox.critical(self, "Report Generation Error", str(e))
    def _generate_html_report(self, data, options):
        report_generator = ReportGenerator()
        html_content = report_generator.generate_report(data, options)
        file_path, _ = QFileDialog.getSaveFileName(self, "Save HTML Report", f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html", "HTML Files (*.html)")
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f: f.write(html_content)
            QMessageBox.information(self, "Report Generated", f"HTML report saved to {file_path}")
    def _generate_pdf_report(self, data, options):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save PDF Report", f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", "PDF Files (*.pdf)")
        if not file_path: return
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib.units import inch
            
            doc = SimpleDocTemplate(file_path, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            elements = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#5b21b6'), spaceAfter=30, alignment=1)
            elements.append(Paragraph("MobHound Security Analysis Report", title_style))
            elements.append(Spacer(1, 0.3*inch))
            
            # Dashboard summary (same visual style family as scanner report)
            ctx = data.get('dashboard_context', {})
            elements.append(Paragraph("Dashboard Summary", styles['Heading2']))
            summary_rows = [
                ['Metric', 'Value'],
                ['Project Type', str(ctx.get('project_type', 'Temporary'))],
                ['Total Projects', str(data.get('dashboard_activity', {}).get('total_projects', len(data.get('projects', []))))],
                ['Total Activities', str(data.get('dashboard_activity', {}).get('total_actions', 0))],
                ['Modules Used', ", ".join(ctx.get('modules_used', [])) or 'N/A'],
                ['Applications Analyzed', str(len(ctx.get('applications_analyzed', [])))],
                ['Files Analyzed', str(len(ctx.get('files_analyzed', [])))],
            ]
            sb = ctx.get('severity_breakdown', {}) or {}
            summary_rows.extend([
                ['Critical', str(sb.get('critical', 0))],
                ['High', str(sb.get('high', 0))],
                ['Medium', str(sb.get('medium', 0))],
                ['Low', str(sb.get('low', 0))]
            ])
            summary_table = Table(summary_rows, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#5b21b6')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 0.3*inch))

            # Dashboard Scan Summary if available
            if 'dashboard_scan' in data:
                scan_data = data['dashboard_scan']
                elements.append(Paragraph("Dashboard Scan Results", styles['Heading2']))
                scan_summary = [
                    ['Metric', 'Value'],
                    ['Total Findings', str(scan_data.get('findings', 0))],
                    ['Critical Issues', str(scan_data.get('critical', 0))],
                    ['High Issues', str(scan_data.get('high', 0))],
                    ['Medium Issues', str(scan_data.get('medium', 0))],
                    ['Low Issues', str(scan_data.get('low', 0))],
                    ['AI Risk Level', scan_data.get('ai_risk', 'N/A')],
                    ['Confidence', f"{int(scan_data.get('ai_confidence', 0)*100)}%"]
                ]
                scan_table = Table(scan_summary, colWidths=[3*inch, 2*inch])
                scan_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#5b21b6')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(scan_table)
                elements.append(Spacer(1, 0.3*inch))
            
            # Projects Overview
            elements.append(PageBreak())
            elements.append(Paragraph("Projects Activity Overview", styles['Heading2']))
            activity = data.get('dashboard_activity', {}) or {}
            project_data = [['Project Name', 'Date', 'Status', 'Actions', 'Modules', 'Apps', 'Files']]
            for proj in activity.get('projects', []):
                project_data.append([
                    str(proj.get('name', '')),
                    str(proj.get('date', '')),
                    str(proj.get('status', '')),
                    str(proj.get('actions', 0)),
                    str(proj.get('modules', 0)),
                    str(proj.get('apps', 0)),
                    str(proj.get('files', 0)),
                ])
            if len(project_data) == 1:
                project_data.append(['No projects found', '', '', '0', '0', '0', '0'])
            project_table = Table(project_data, colWidths=[1.8*inch, 1.0*inch, 0.9*inch, 0.7*inch, 0.7*inch, 0.6*inch, 0.6*inch])
            project_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#5b21b6')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            elements.append(project_table)

            recent_actions = activity.get('recent_actions', [])[-50:]
            elements.append(Spacer(1, 0.25*inch))
            elements.append(Paragraph("Overall Activity Timeline", styles['Heading2']))
            action_rows = [['Project', 'Timestamp', 'Module', 'Action', 'Target']]
            for action in recent_actions:
                action_rows.append([
                    str(action.get('project', '')),
                    str(action.get('timestamp', '')),
                    str(action.get('module', '')),
                    str(action.get('action', '')),
                    str(action.get('target', '')),
                ])
            if len(action_rows) == 1:
                action_rows.append(['No activity recorded', '', '', '', ''])
            action_table = Table(action_rows, colWidths=[1.35*inch, 1.45*inch, 1.05*inch, 1.15*inch, 1.25*inch])
            action_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#5b21b6')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            elements.append(action_table)
            
            # Build PDF
            doc.build(elements)
            QMessageBox.information(self, "PDF Generated", f"PDF report saved to {file_path}")
        except Exception as e: 
            QMessageBox.critical(self, "PDF Error", f"Failed to generate PDF:\n\n{str(e)}")
    def _generate_json_report(self, data, options):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save JSON Report", f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "JSON Files (*.json)")
        if file_path:
            enhanced_data = {"metadata":{"report_type":options['type'],"generated_date":datetime.now().strftime('%Y-%m-%d %H:%M:%S'),"sections_included":options.get('sections',{})},
                             "summary":{"total_projects":len(data['projects']),"total_vulnerabilities":sum(v['count'] for v in data['vulnerabilities']),"critical_vulnerabilities":sum(v['count'] for v in data['vulnerabilities'] if v['severity']=='High')},
                             "projects":data['projects'],"vulnerabilities":data['vulnerabilities'],"dashboard_activity":data.get('dashboard_activity', {})}
            with open(file_path,'w',encoding='utf-8') as f: json.dump(enhanced_data,f,indent=2)
            QMessageBox.information(self, "JSON Report Generated", f"JSON report saved to {file_path}")
    def _generate_csv_report(self, data, options):
        import csv
        file_path, _ = QFileDialog.getSaveFileName(self, "Save CSV Report", f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "CSV Files (*.csv)")
        if file_path:
            with open(file_path,'w',newline='',encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Security Assessment Report'])
                writer.writerow(['Generated',datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
                writer.writerow(['Report Type',options['type']])
                writer.writerow([])
                writer.writerow(['PROJECTS'])
                writer.writerow(['Name','Date','Vulnerabilities','Status'])
                for project in data['projects']: writer.writerow([project['name'],project['date'],project['vulnerabilities'],project['status']])
                writer.writerow([])
                writer.writerow(['VULNERABILITIES'])
                writer.writerow(['Type','Severity','Count'])
                for vuln in data['vulnerabilities']: writer.writerow([vuln['type'],vuln['severity'],vuln['count']])
                writer.writerow([])
                total_vulns = sum(v['count'] for v in data['vulnerabilities'])
                critical = sum(v['count'] for v in data['vulnerabilities'] if v['severity']=='High')
                writer.writerow(['SUMMARY'])
                writer.writerow(['Total Projects',len(data['projects'])])
                writer.writerow(['Total Activities',data.get('dashboard_activity', {}).get('total_actions', 0)])
                writer.writerow(['Total Vulnerabilities',total_vulns])
                writer.writerow(['Critical Vulnerabilities',critical])
                writer.writerow([])
                writer.writerow(['PROJECT ACTIVITY'])
                writer.writerow(['Name','Actions','Modules','Apps','Files'])
                for project in data.get('dashboard_activity', {}).get('projects', []):
                    writer.writerow([project.get('name',''),project.get('actions',0),project.get('modules',0),project.get('apps',0),project.get('files',0)])
            QMessageBox.information(self, "CSV Report Generated", f"CSV report saved to {file_path}")
    def _generate_xml_report(self, data, options):
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom
        file_path, _ = QFileDialog.getSaveFileName(self, "Save XML Report", f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml", "XML Files (*.xml)")
        if file_path:
            root = Element('SecurityAssessmentReport')
            metadata = SubElement(root,'Metadata')
            SubElement(metadata,'ReportType').text = options['type']
            SubElement(metadata,'GeneratedDate').text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            summary = SubElement(root,'Summary')
            total = sum(v['count'] for v in data['vulnerabilities'])
            critical = sum(v['count'] for v in data['vulnerabilities'] if v['severity']=='High')
            SubElement(summary,'TotalProjects').text = str(len(data['projects']))
            SubElement(summary,'TotalActivities').text = str(data.get('dashboard_activity', {}).get('total_actions', 0))
            SubElement(summary,'TotalVulnerabilities').text = str(total)
            SubElement(summary,'CriticalVulnerabilities').text = str(critical)
            projects_elem = SubElement(root,'Projects')
            for project in data['projects']:
                proj = SubElement(projects_elem,'Project')
                SubElement(proj,'Name').text = project['name']
                SubElement(proj,'Date').text = project['date']
                SubElement(proj,'Vulnerabilities').text = str(project['vulnerabilities'])
                SubElement(proj,'Status').text = project['status']
            activity_elem = SubElement(root,'ProjectActivity')
            for project in data.get('dashboard_activity', {}).get('projects', []):
                proj = SubElement(activity_elem,'Project')
                SubElement(proj,'Name').text = str(project.get('name',''))
                SubElement(proj,'Actions').text = str(project.get('actions',0))
                SubElement(proj,'Modules').text = str(project.get('modules',0))
                SubElement(proj,'Apps').text = str(project.get('apps',0))
                SubElement(proj,'Files').text = str(project.get('files',0))
            vulns_elem = SubElement(root,'Vulnerabilities')
            for vuln in data['vulnerabilities']:
                v = SubElement(vulns_elem,'Vulnerability')
                SubElement(v,'Type').text = vuln['type']
                SubElement(v,'Severity').text = vuln['severity']
                SubElement(v,'Count').text = str(vuln['count'])
            rough_string = tostring(root,'utf-8')
            reparsed = minidom.parseString(rough_string)
            pretty = reparsed.toprettyxml(indent="  ")
            with open(file_path,'w',encoding='utf-8') as f: f.write(pretty)
            QMessageBox.information(self, "XML Report Generated", f"XML report saved to {file_path}")
    def _generate_text_report(self, data, options):
        report_content = f"""SECURITY ASSESSMENT REPORT
==========================

Report Type: {options['type']}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Format: Text

EXECUTIVE SUMMARY
=================
Total Projects: {len(data['projects'])}
Current Active Projects: {len([p for p in data['projects'] if p['status']=='In Progress'])}
Total Activities Logged: {data.get('dashboard_activity', {}).get('total_actions', 0)}
Total Vulnerabilities Found: {sum(v['count'] for v in data['vulnerabilities'])}
Critical Issues: {sum(v['count'] for v in data['vulnerabilities'] if v['severity']=='High')}

PROJECT OVERVIEW
================
"""
        for project in data['projects']:
            report_content += f"- {project['name']} ({project['status']}): {project['vulnerabilities']} vulnerabilities found\n"
        report_content += """
PROJECT ACTIVITY OVERVIEW
=========================
"""
        for project in data.get('dashboard_activity', {}).get('projects', []):
            report_content += (
                f"- {project.get('name', 'Unnamed Project')}: "
                f"{project.get('actions', 0)} activities, "
                f"{project.get('modules', 0)} modules, "
                f"{project.get('apps', 0)} apps, "
                f"{project.get('files', 0)} files\n"
            )
        report_content += """
VULNERABILITY ANALYSIS
======================
"""
        for vuln in data['vulnerabilities']:
            report_content += f"- {vuln['type']} ({vuln['severity']}): {vuln['count']} instances\n"
        report_content += """
RECOMMENDATIONS
===============
1. Prioritize fixing high-severity vulnerabilities
2. Implement regular security scanning
3. Conduct penetration testing quarterly
4. Update security policies and procedures
5. Provide security awareness training
"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Report", f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "Text Files (*.txt)")
        if file_path:
            with open(file_path,'w',encoding='utf-8') as f: f.write(report_content)
            QMessageBox.information(self, "Report Generated", f"Text report saved to {file_path}")
    def preview_report(self, options):
        try:
            if not JINJA2_AVAILABLE:
                QMessageBox.warning(self, "Preview Not Available", "Jinja2 not installed.")
                return
            report_data = {'projects': self.projects, 'vulnerabilities': self._dashboard_vulnerability_rows()}
            report_generator = ReportGenerator()
            html_content = report_generator.generate_report(report_data, options)
            preview_dialog = QDialog(self)
            preview_dialog.setWindowTitle("Report Preview")
            preview_dialog.setMinimumSize(1000,700)
            layout = QVBoxLayout(preview_dialog)
            try:
                from PySide6.QtWebEngineWidgets import QWebEngineView
                web_view = QWebEngineView()
                web_view.setHtml(html_content)
                layout.addWidget(web_view)
            except ImportError:
                text_edit = QTextEdit()
                text_edit.setHtml(html_content)
                text_edit.setReadOnly(True)
                layout.addWidget(text_edit)
            button_layout = QHBoxLayout()
            generate_btn = StyledButton("Generate Full Report")
            close_btn = StyledButton("Close Preview")
            button_layout.addWidget(generate_btn)
            button_layout.addWidget(close_btn)
            layout.addLayout(button_layout)
            generate_btn.clicked.connect(lambda: self.generate_comprehensive_report(options))
            generate_btn.clicked.connect(preview_dialog.accept)
            close_btn.clicked.connect(preview_dialog.reject)
            preview_dialog.exec()
        except Exception as e: QMessageBox.critical(self, "Preview Error", str(e))
    def update_scan_status(self, is_scanning, vulnerabilities_count=0):
        self.is_scanning = is_scanning
        self.total_vulnerabilities_found = vulnerabilities_count
        if hasattr(self,'scan_status_label'):
            self.scan_status_label.setText("Running" if is_scanning else "Stopped")
            self.scan_status_label.setStyleSheet("color:white;background-color:transparent;")
        if hasattr(self,'subtitle_label'):
            self.subtitle_label.setText(f"Total Vulnerabilities ({vulnerabilities_count})")
    def quick_scan(self):
        main_window = self.window()
        if hasattr(main_window, "tab_bar"):
            main_window.tab_bar.setCurrentIndex(4)
            if hasattr(main_window, "page_container"):
                main_window.page_container.setCurrentIndex(4)
    def upload_results(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Upload Scan Results", "", "All Files (*);;JSON Files (*.json)")
        if file_path:
            try:
                file_name = os.path.basename(file_path)
                QMessageBox.information(self, "Upload Successful", f"{file_name} uploaded.")
            except Exception as e: QMessageBox.critical(self, "Upload Error", str(e))

# ------------------------------------------------------------------------------
# IntercepterPage (dynamic analysis integrated) - UPDATED to match image design
# ------------------------------------------------------------------------------
class IntercepterPage(BasePage):
    module_status_changed = Signal(str, str, str)
    flow_received = Signal(dict)
    send_to_analyzer = Signal(dict)
    send_to_payloader = Signal(dict)

    def _setup_base_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.container = QWidget()
        self.container.setObjectName("pageContainer")
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setSpacing(12)
        self.container_layout.setContentsMargins(16, 16, 16, 16)
        root_layout.addWidget(self.container)

    def __init__(self):
        super().__init__()
        self.is_intercepting = False
        self.current_device: Optional[AndroidDevice] = None
        self.devices: List[AndroidDevice] = []
        self.captured_flows: List[Dict[str, Any]] = []
        self.connector = AndroidEmulatorConnector(auto_download_adb=True)
        self.interceptor = MitmProxyInterceptor(self.connector)
        self.frida_manager: Optional[FridaManager] = None
        self.frida_ssl_process = None
        self.frida_root_process = None
        self.frida_detection_process = None
        self.frida_tagger_process = None
        self._logcat_messages = deque(maxlen=240)
        self._last_tls_recovery_ts = 0.0
        self._tls_issue_notified = False
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.active_future: Optional[Future] = None
        self._active_callback = None
        self.task_timer = QTimer(self)
        self.task_timer.timeout.connect(self._poll_active_task)
        self.logcat_timer = QTimer(self)
        self.logcat_timer.timeout.connect(self._update_logcat)
        self.logcat_timer.start(3000)
        self.flow_received.connect(self._add_captured_flow)

    def _setup_ui(self):
        layout = self.container_layout

        # Toolbar (Updated button texts to match image)
        toolbar = QHBoxLayout()
        self.refresh_btn = StyledButton("Refresh Devices")
        self.health_btn = StyledButton("Health Check")
        self.start_intercept_btn = StyledButton("Start Interception")
        self.generate_cert_btn = StyledButton("Generate + Install Certificate")
        self.install_apk_btn = StyledButton("Install APK + Analyze")
        self.start_app_analysis_btn = StyledButton("Start Selected App Analysis")
        for btn in [
            self.refresh_btn,
            self.health_btn,
            self.start_intercept_btn,
            self.generate_cert_btn,
            self.install_apk_btn,
            self.start_app_analysis_btn,
        ]:
            btn.setMinimumHeight(30)
            btn.setFont(QFont("Poppins", 8, QFont.Bold))
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            toolbar.addWidget(btn)
        toolbar.setSpacing(8)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        body_layout = QHBoxLayout()
        body_layout.setSpacing(8)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setAlignment(Qt.AlignTop)

        # Left column (connect + device info cards)
        left_column = QWidget()
        left_column.setMinimumWidth(220)
        left_column.setMaximumWidth(250)
        left_column_layout = QVBoxLayout(left_column)
        left_column_layout.setContentsMargins(0, 0, 0, 0)
        left_column_layout.setSpacing(8)

        left_card = QFrame()
        left_card.setObjectName("interceptorLeftCard")
        left_card.setStyleSheet("QFrame#interceptorLeftCard{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:10px;border:1px solid #5D2E8C;}")
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(10, 8, 10, 8)
        left_layout.setSpacing(6)
        card_title = QLabel("Connect Device")
        card_title.setFont(QFont("Poppins", 9, QFont.Bold))
        card_title.setStyleSheet("color:white;")
        left_layout.addWidget(card_title)
        device_form = QFormLayout()
        device_form.setHorizontalSpacing(6)
        device_form.setVerticalSpacing(4)
        device_form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        device_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        device_form.setRowWrapPolicy(QFormLayout.DontWrapRows)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 127.0.0.1:5555")
        self.preferred_serial_input = QLineEdit()
        self.preferred_serial_input.setPlaceholderText("e.g. emulator-5554")
        self.apps_combo = QComboBox()
        self.apps_combo.setEditable(False)
        self.apps_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.target_app_input = QLineEdit()
        self.target_app_input.setPlaceholderText("e.g. com.example.app")

        for field in (self.target_input, self.preferred_serial_input, self.apps_combo, self.target_app_input):
            field.setFixedHeight(24)
            field.setFont(QFont("Poppins", 8))

        def _make_form_label(text: str) -> QLabel:
            lbl = QLabel(text)
            lbl.setObjectName("interceptorFormLabel")
            lbl.setMinimumWidth(78)
            lbl.setFont(QFont("Poppins", 8))
            lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            return lbl

        device_form.addRow(_make_form_label("Target:"), self.target_input)
        device_form.addRow(_make_form_label("Preferred Serial:"), self.preferred_serial_input)
        device_form.addRow(_make_form_label("Apps Available:"), self.apps_combo)
        device_form.addRow(_make_form_label("Target App:"), self.target_app_input)
        left_layout.addLayout(device_form)
        self.connect_btn = StyledButton("Connect")
        self.connect_btn.setFixedSize(100, 24)
        self.connect_btn.setFont(QFont("Poppins", 8, QFont.Bold))
        left_layout.addWidget(self.connect_btn, 0, Qt.AlignHCenter)
        left_layout.addStretch(1)

        device_info_box = QFrame()
        device_info_box.setObjectName("deviceInfoBox")
        device_info_box.setStyleSheet("QFrame#deviceInfoBox{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:10px;border:1px solid #5D2E8C;}")
        device_info_layout = QVBoxLayout(device_info_box)
        device_info_layout.setContentsMargins(10, 8, 10, 8)
        device_info_layout.setSpacing(4)
        info_title = QLabel("Device Info")
        info_title.setFont(QFont("Poppins", 9, QFont.Bold))
        info_title.setStyleSheet("color:#f6f5ff;")
        device_info_layout.addWidget(info_title)
        self.device_info_table = QTableWidget(0, 2)
        self.device_info_table.setHorizontalHeaderLabels(["", ""])
        self.device_info_table.verticalHeader().setVisible(False)
        self.device_info_table.horizontalHeader().setVisible(False)
        self.device_info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.device_info_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.device_info_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.device_info_table.setSelectionMode(QTableWidget.NoSelection)
        self.device_info_table.setFocusPolicy(Qt.NoFocus)
        self.device_info_table.setMinimumHeight(118)
        self.device_info_table.setStyleSheet("QTableWidget{background:transparent;color:#f6f5ff;border:none;}QTableWidget::item{border-bottom:1px solid #443a63;padding:2px 0;}")
        self.device_info_table.verticalHeader().setDefaultSectionSize(18)
        self.device_info_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        device_info_layout.addWidget(self.device_info_table)
        self._device_info_defaults = {
            "Serial": "-",
            "State": "Disconnected",
            "Emulator": "-",
            "Model": "-",
            "Manufacturer": "-",
            "Android Version": "-",
            "ABI": "-",
            "QEMU": "-",
            "Transport": "-",
            "Health": "Not checked",
            "Shell Access": "-",
            "Package Manager": "-",
            "Interception": "Stopped",
            "Frida": "Not setup",
            "Operation": "Idle",
        }
        self._device_info_values: Dict[str, str] = {}
        self._device_info_row_index: Dict[str, int] = {}
        self._reset_device_info_table()
        device_info_box.setMinimumHeight(160)
        device_info_box.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)

        left_card.setMinimumHeight(180)
        left_card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        left_column_layout.addWidget(left_card, 0)
        left_column_layout.addWidget(device_info_box, 1)
        body_layout.addWidget(left_column, 16)

        # Center interception details
        center_widget = QWidget()
        center_layout = QVBoxLayout(center_widget)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(6)
        self.traffic_group = QFrame()
        self.traffic_group.setObjectName("interceptorTrafficGroup")
        self.traffic_group.setStyleSheet("QFrame#interceptorTrafficGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:10px;border:1px solid #5D2E8C;}")
        traffic_layout = QVBoxLayout(self.traffic_group)
        traffic_layout.setContentsMargins(8, 8, 8, 8)
        traffic_layout.setSpacing(6)
        traffic_title = QLabel("Interceped Traffic")
        traffic_title.setObjectName("interceptorTrafficTitle")
        traffic_title.setFont(QFont("Poppins", 9, QFont.Bold))
        traffic_layout.addWidget(traffic_title)
        self.log_table = QTableWidget(0, 4)
        self.log_table.setMinimumHeight(180)
        self.log_table.setMaximumHeight(230)
        self.log_table.setHorizontalHeaderLabels(["#", "Method", "URL", "Status"])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_table.setSelectionMode(QTableWidget.SingleSelection)
        self.log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.log_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.log_table.setVerticalScrollMode(QTableWidget.ScrollPerPixel)
        self.log_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        self.log_table.verticalScrollBar().setSingleStep(18)
        self.log_table.setFocusPolicy(Qt.StrongFocus)
        self.log_table.verticalHeader().setVisible(False)
        self.log_table.verticalHeader().setDefaultSectionSize(24)
        self.log_table.setAlternatingRowColors(True)
        self.log_table.horizontalHeader().setStretchLastSection(True)
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        traffic_layout.addWidget(self.log_table, 1)
        center_layout.addWidget(self.traffic_group, 2)

        details_row = QWidget()
        details_row_layout = QHBoxLayout(details_row)
        details_row_layout.setContentsMargins(0, 0, 0, 0)
        details_row_layout.setSpacing(10)
        request_group = QGroupBox()
        request_group.setObjectName("interceptorSectionGroup")
        request_group.setStyleSheet("QGroupBox#interceptorSectionGroup{background:transparent;border:1px solid #5D2E8C;border-radius:6px;color:#f6f5ff;margin-top:0px;padding:4px;}")
        request_layout = QVBoxLayout(request_group)
        request_layout.setContentsMargins(5, 5, 5, 5)
        self.request_editor = QTextEdit()
        self.request_editor.setReadOnly(True)
        self.request_editor.setPlaceholderText("Request details...")
        self.request_editor.setMinimumHeight(132)
        request_layout.addWidget(self.request_editor)
        self.response_group = QGroupBox()
        self.response_group.setObjectName("interceptorSectionGroup")
        self.response_group.setStyleSheet("QGroupBox#interceptorSectionGroup{background:transparent;border:1px solid #5D2E8C;border-radius:6px;color:#f6f5ff;margin-top:0px;padding:4px;}")
        response_layout = QVBoxLayout(self.response_group)
        response_layout.setContentsMargins(5, 5, 5, 5)
        self.response_editor = QTextEdit()
        self.response_editor.setReadOnly(True)
        self.response_editor.setPlaceholderText("Response details...")
        self.response_editor.setMinimumHeight(132)
        self.request_editor.setFont(QFont("Consolas", 8))
        self.response_editor.setFont(QFont("Consolas", 8))
        response_layout.addWidget(self.response_editor)
        details_row_layout.addWidget(request_group, 1)
        details_row_layout.addWidget(self.response_group, 1)
        center_layout.addSpacing(2)
        center_layout.addWidget(details_row, 1)
        body_layout.addWidget(center_widget, 68)

        # Right side frida + logcat
        right_widget = QWidget()
        right_widget.setMinimumWidth(210)
        right_widget.setMaximumWidth(250)
        right_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.right_layout = QVBoxLayout(right_widget)
        self.right_layout.setContentsMargins(0, 0, 0, 0)
        self.right_layout.setSpacing(8)
        self.frida_box = QGroupBox()
        self.frida_box.setMinimumHeight(158)
        self.frida_box.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        self.frida_box.setObjectName("interceptorFridaGroup")
        self.frida_box.setStyleSheet(
            "QGroupBox#interceptorFridaGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:10px;border:1px solid #5D2E8C;color:#f6f5ff;padding:6px 10px 8px 10px;}"
            "QGroupBox#interceptorFridaGroup QCheckBox{background-color:transparent;color:#f6f5ff;padding:0;margin:0;}"
            "QGroupBox#interceptorFridaGroup QCheckBox::indicator{border:1px solid #f6f5ff; width:14px; height:14px; background-color:transparent;}"
            "QGroupBox#interceptorFridaGroup QCheckBox::indicator:checked{background-color:#6A0DAD;}"
            "QGroupBox#interceptorFridaGroup QLabel{color:#f6f5ff;}"
        )
        frida_layout = QVBoxLayout(self.frida_box)
        frida_layout.setSpacing(4)
        frida_layout.setContentsMargins(8, 8, 8, 8)
        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(6)
        header_label = QLabel("Frida Setup")
        header_label.setFont(QFont("Poppins", 9, QFont.Bold))
        header_label.setStyleSheet("color:white;")
        self.setup_frida_btn = StyledButton("Setup")
        self.setup_frida_btn.setFixedSize(58, 22)
        self.setup_frida_btn.setFont(QFont("Poppins", 8, QFont.Bold))
        header_row.addWidget(header_label)
        header_row.addStretch(1)
        header_row.addWidget(self.setup_frida_btn)
        frida_layout.addLayout(header_row)
        frida_layout.addSpacing(2)

        def add_frida_option(title: str) -> QCheckBox:
            row = QWidget()
            row.setObjectName("interceptorFridaOptionRow")
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(2, 0, 2, 0)
            row_layout.setSpacing(4)
            label = QLabel(title)
            label.setObjectName("interceptorFridaOptionLabel")
            label.setFont(QFont("Poppins", 8))
            checkbox = QCheckBox()
            checkbox.setObjectName("interceptorFridaOptionCheck")
            checkbox.setFixedSize(16, 16)
            row_layout.addWidget(label, 1)
            row_layout.addWidget(checkbox, 0, Qt.AlignRight)
            frida_layout.addWidget(row)
            return checkbox

        self.ssl_checkbox = add_frida_option("SSL Pinning Bypass")
        self.root_checkbox = add_frida_option("Root/Emulator Bypass")
        self.frida_detection_checkbox = add_frida_option("Frida Detection Bypass")
        frida_layout.addStretch(1)
        self.right_layout.addWidget(self.frida_box)

        self.logcat_box = QFrame()
        self.logcat_box.setObjectName("interceptorLogcatBox")
        self.logcat_box.setStyleSheet("QFrame#interceptorLogcatBox{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:10px;border:1px solid #5D2E8C;}")
        logcat_layout = QVBoxLayout(self.logcat_box)
        logcat_layout.setContentsMargins(8, 8, 8, 8)
        logcat_layout.setSpacing(6)
        header_row = QHBoxLayout()
        header_label = QLabel("App Logcat")
        header_label.setFont(QFont("Poppins", 9, QFont.Bold))
        header_label.setStyleSheet("color:white;")
        header_row.addWidget(header_label)
        header_row.addStretch(1)
        self.capture_readiness_btn = StyledButton("Capture Readiness")
        self.capture_readiness_btn.setFixedSize(100, 24)
        self.capture_readiness_btn.setFont(QFont("Poppins", 7, QFont.Bold))
        header_row.addWidget(self.capture_readiness_btn)
        logcat_layout.addLayout(header_row)
        logcat_layout.addSpacing(2)
        self.logcat_text = QTextEdit()
        self.logcat_text.setReadOnly(True)
        self.logcat_text.setStyleSheet("QTextEdit{background:#151224;color:#f6f5ff;border:1px solid #443a63;border-radius:6px;}")
        self.logcat_text.setMinimumHeight(135)
        self.logcat_text.setFont(QFont("Consolas", 8))
        self.logcat_text.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        logcat_layout.addWidget(self.logcat_text)
        self.right_layout.addWidget(self.logcat_box, 1)
        body_layout.addWidget(right_widget, 16)

        layout.addLayout(body_layout, 1)

        self._interceptor_status_lbl = None
        self._set_status("Ready")

        # Connect signals
        self.refresh_btn.clicked.connect(self.refresh_devices)
        self.health_btn.clicked.connect(self.health_check_selected)
        self.start_intercept_btn.clicked.connect(self.toggle_interception)
        self.generate_cert_btn.clicked.connect(self.generate_and_install_ca)
        self.install_apk_btn.clicked.connect(self.install_apk_and_analyze)
        self.start_app_analysis_btn.clicked.connect(self.start_selected_app_analysis)
        self.connect_btn.clicked.connect(self.connect_device)
        self.capture_readiness_btn.clicked.connect(self._check_capture_readiness)
        self.setup_frida_btn.clicked.connect(self.setup_frida)
        self.ssl_checkbox.toggled.connect(self._on_ssl_bypass_toggled)
        self.root_checkbox.toggled.connect(self._on_root_bypass_toggled)
        self.frida_detection_checkbox.toggled.connect(self._on_frida_detection_bypass_toggled)
        self.apps_combo.currentTextChanged.connect(self._on_app_selected)
        self.log_table.itemSelectionChanged.connect(self._show_selected_flow)
        self.log_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.log_table.customContextMenuRequested.connect(self._show_flow_context_menu)

    # --------------------------------------------------------------------------
    # All existing helper methods from original IntercepterPage (unchanged)
    # --------------------------------------------------------------------------
    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Let Qt's layout engine drive section heights to avoid visual overlap
        # when the window is resized or shown at different scales.

    def _sync_interceptor_section_heights(self) -> None:
        return

    def _set_status(self, message: str, progress_value: Optional[int] = None, progress_text: str = None) -> None:
        self._push_global_status(message[:220], progress_value=progress_value, progress_text=progress_text)

    def _set_busy(self, busy: bool, message: str = "") -> None:
        self.refresh_btn.setEnabled(not busy)
        self.health_btn.setEnabled(not busy)
        self.start_intercept_btn.setEnabled(not busy)
        self.generate_cert_btn.setEnabled(not busy)
        self.install_apk_btn.setEnabled(not busy)
        self.start_app_analysis_btn.setEnabled(not busy)
        self.connect_btn.setEnabled(not busy)
        self.setup_frida_btn.setEnabled(not busy)
        self.apps_combo.setEnabled(not busy)
        self.target_app_input.setEnabled(not busy)
        self._set_device_info_value("Operation", message if busy and message else ("Ready" if self.current_device else "Waiting for device"))
        if message:
            self._set_status(message)

    def _append_log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._set_status(f"[{timestamp}] {message}")

    def _append_logcat_message(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        if self._logcat_messages:
            last_msg = self._logcat_messages[-1].split("|", 1)[-1].strip()
            if last_msg == message:
                return
        self._logcat_messages.append(f"{timestamp} | {message}")
        self.logcat_text.setPlainText("\n".join(self._logcat_messages))

    def _start_background_task(self, fn, on_done, busy_message: str) -> None:
        if self.active_future and not self.active_future.done():
            QMessageBox.information(self, "Task Running", "Please wait for the current backend task to finish.")
            return
        self._set_busy(True, busy_message)
        self.active_future = self.executor.submit(fn)
        self._active_callback = on_done
        self.task_timer.start(250)

    def _poll_active_task(self) -> None:
        if not self.active_future:
            self.task_timer.stop()
            return
        if not self.active_future.done():
            return
        self.task_timer.stop()
        future = self.active_future
        self.active_future = None
        self._set_busy(False)
        try:
            result = future.result()
            if callable(self._active_callback):
                self._active_callback(result, None)
        except Exception as exc:
            if callable(self._active_callback):
                self._active_callback(None, exc)
        self._active_callback = None

    def _ensure_device_exists(self) -> Optional[AndroidDevice]:
        if self.current_device and self.current_device.state == "device":
            return self.current_device
        if not self.devices:
            QMessageBox.warning(self, "No Device", "No connected device detected. Refresh devices first.")
            return None
        self.current_device = self.devices[0]
        self._populate_device_info()
        return self.current_device

    def _reset_device_info_table(self) -> None:
        self.device_info_table.setRowCount(0)
        self._device_info_row_index.clear()
        self._device_info_values = dict(self._device_info_defaults)
        for label, value in self._device_info_defaults.items():
            row = self.device_info_table.rowCount()
            self.device_info_table.insertRow(row)
            key_item = QTableWidgetItem(label)
            key_item.setFlags(key_item.flags() & ~Qt.ItemIsEditable)
            value_item = QTableWidgetItem(str(value))
            value_item.setFlags(value_item.flags() & ~Qt.ItemIsEditable)
            self.device_info_table.setItem(row, 0, key_item)
            self.device_info_table.setItem(row, 1, value_item)
            self._device_info_row_index[label] = row

    def _set_device_info_value(self, label: str, value: Any) -> None:
        if not hasattr(self, "device_info_table"):
            return
        row = self._device_info_row_index.get(label)
        if row is None:
            row = self.device_info_table.rowCount()
            self.device_info_table.insertRow(row)
            key_item = QTableWidgetItem(label)
            key_item.setFlags(key_item.flags() & ~Qt.ItemIsEditable)
            self.device_info_table.setItem(row, 0, key_item)
            self._device_info_row_index[label] = row

        value_item = self.device_info_table.item(row, 1)
        if value_item is None:
            value_item = QTableWidgetItem("")
            value_item.setFlags(value_item.flags() & ~Qt.ItemIsEditable)
            self.device_info_table.setItem(row, 1, value_item)

        safe_value = "-" if value is None or str(value).strip() == "" else str(value)
        self._device_info_values[label] = safe_value
        value_item.setText(safe_value)

    def _populate_device_info(self) -> None:
        self._reset_device_info_table()
        if not self.current_device:
            self._set_device_info_value("Operation", "Waiting for device")
            return
        self._set_device_info_value("Serial", self.current_device.serial)
        self._set_device_info_value("State", self.current_device.state)
        self._set_device_info_value("Emulator", "Yes" if self.current_device.is_emulator else "No")
        self._set_device_info_value("Model", self.current_device.model)
        self._set_device_info_value("Manufacturer", self.current_device.manufacturer)
        self._set_device_info_value("Android Version", self.current_device.android_version)
        self._set_device_info_value("ABI", self.current_device.abi)
        self._set_device_info_value("QEMU", self.current_device.qemu)
        self._set_device_info_value("Transport", self.current_device.transport)
        self._set_device_info_value("Interception", "Running" if self.is_intercepting else "Stopped")
        self._set_device_info_value("Frida", "Ready" if self.frida_manager else "Not setup")
        self._set_device_info_value("Operation", "Ready")

    def _check_capture_readiness(self) -> None:
        device = self._ensure_device_exists()
        if not device:
            return

        package = self.target_app_input.text().strip() or self.apps_combo.currentText().strip()
        if not package:
            QMessageBox.warning(self, "Missing Package", "Enter a target app package first.")
            self._set_status("Capture readiness requires a target app package.")
            return

        def task():
            backend_ok, backend_msg = True, "Interception backend is not running yet."
            proxy_ok, proxy_msg = True, "Proxy will be configured when interception starts."

            if self.is_intercepting:
                backend_ok, backend_msg = self.interceptor.check_backend_health()
                proxy_ok, proxy_msg = self.interceptor.verify_device_proxy(device.serial)

            return proxy_ok, proxy_msg, backend_ok, backend_msg

        def done(result, err):
            if err:
                self._set_status(f"Capture readiness check failed: {err}")
                self._set_device_info_value("Operation", "Capture readiness failed")
                QMessageBox.warning(self, "Capture Readiness", str(err))
                return

            proxy_ok, proxy_msg, backend_ok, backend_msg = result
            if not proxy_ok or (self.is_intercepting and not backend_ok):
                self._set_status("Capture readiness issue detected.")
                self._set_device_info_value("Operation", "Capture readiness issue")
            else:
                self._set_status("Capture readiness check passed.")
                self._set_device_info_value("Operation", "Capture readiness passed")
            details = [proxy_msg]
            if self.is_intercepting:
                details.append(backend_msg)

            QMessageBox.information(
                self,
                "Capture Readiness",
                "\n".join(details),
            )

        self._start_background_task(task, done, "Checking capture readiness...")

    def _load_installed_apps(self) -> None:
        if not self.current_device:
            return
        try:
            packages = self.connector.list_installed_packages(self.current_device.serial)
            self.apps_combo.clear()
            self.apps_combo.addItems(packages)
            if packages:
                self.target_app_input.setText(packages[0])
                self.apps_combo.setCurrentIndex(0)
            self._set_status("Installed apps loaded.", 0, "Ready")
        except Exception as exc:
            self._set_status(f"Failed to load installed apps: {exc}")

    def _select_preferred_device(self, preferred_serial: str) -> Optional[AndroidDevice]:
        if not preferred_serial:
            return None
        for device in self.devices:
            if device.serial == preferred_serial:
                return device
        return None

    def refresh_devices(self) -> None:
        def task():
            return self.connector.list_devices(include_properties=True)

        def done(devices, err):
            if err:
                self._set_status(f"Device refresh failed: {err}")
                QMessageBox.critical(self, "Device Refresh Error", str(err))
                return
            self.devices = devices or []
            if self.devices:
                self.current_device = self.devices[0]
                self._load_installed_apps()
                self._populate_device_info()
                self._set_status(f"Found {len(self.devices)} device(s).", 0, "Ready")
            else:
                self.current_device = None
                self.apps_combo.clear()
                self._populate_device_info()
                self._set_status("No devices found.", 0, "Ready")

        self._start_background_task(task, done, "Refreshing devices...")

    def connect_device(self) -> None:
        target = self.target_input.text().strip()
        preferred = self.preferred_serial_input.text().strip()

        def task():
            if target:
                self.connector.connect(target)
            devices = self.connector.list_devices(include_properties=True)
            return devices

        def done(devices, err):
            if err:
                self._set_status(f"Connection failed: {err}")
                QMessageBox.critical(self, "Connect Error", str(err))
                return
            self.devices = devices or []
            candidate = self._select_preferred_device(preferred) or (self.devices[0] if self.devices else None)
            if candidate:
                self.current_device = candidate
                self._load_installed_apps()
                self._populate_device_info()
                self._set_status(f"Connected to {candidate.serial}.", 0, "Ready")
            else:
                self.current_device = None
                self.apps_combo.clear()
                self._populate_device_info()
                self._set_status("No device selected after connect.", 0, "Ready")

        self._start_background_task(task, done, "Connecting to device...")

    def health_check_selected(self) -> None:
        device = self._ensure_device_exists()
        if not device:
            return

        def task():
            return self.connector.run_health_check(device.serial)

        def done(result, err):
            if err:
                self._set_status(f"Health check failed: {err}")
                self._set_device_info_value("Health", "Failed")
                QMessageBox.critical(self, "Health Check Error", str(err))
                return
            status = "OK" if result.ok else "Failed"
            self._set_status(f"Health Check: {status}")
            self._set_device_info_value("Health", status)
            self._set_device_info_value("Shell Access", result.details.get("shell_access", "-"))
            self._set_device_info_value("Package Manager", result.details.get("package_manager", "-"))
            self._set_device_info_value("State", "device" if "OK" in result.details.get("device_state", "") else self.current_device.state if self.current_device else "unknown")
            details = "\n".join(f"{k}: {v}" for k, v in result.details.items())
            QMessageBox.information(self, "Health Check Result", f"{status}\n{details}")

        self._start_background_task(task, done, "Running health check...")

    def generate_and_install_ca(self) -> None:
        device = self._ensure_device_exists()
        if not device:
            return

        def task():
            cert_path = self.interceptor.generate_ca_certificate()
            self.interceptor.install_ca_on_device(device.serial, cert_path)
            return str(cert_path)

        def done(result, err):
            if err:
                self._set_status(f"Certificate install failed: {err}")
                QMessageBox.critical(self, "Certificate Error", str(err))
                return
            self._set_status("CA certificate generated and installer launched.", 0, "Ready")
            QMessageBox.information(self, "Certificate Installed", f"CA certificate created at: {result}")

        self._start_background_task(task, done, "Generating and installing CA certificate...")

    def install_apk_and_analyze(self) -> None:
        device = self._ensure_device_exists()
        if not device:
            return
        apk_path, _ = QFileDialog.getOpenFileName(self, "Install APK", "", "Android APK Files (*.apk)")
        if not apk_path:
            return

        def task():
            output, package = self.connector.install_apk(device.serial, apk_path)
            return output, package

        def done(result, err):
            if err:
                self._set_status(f"APK install failed: {err}")
                QMessageBox.critical(self, "APK Install Error", str(err))
                return
            output, package = result
            self._set_status("APK installed successfully.", 0, "Ready")
            self._append_log(output)
            if package:
                self.target_app_input.setText(package)
                self._set_status(f"Detected package: {package}")
            QMessageBox.information(self, "APK Installed", f"Install output:\n{output}")

        self._start_background_task(task, done, "Installing APK...")

    def start_selected_app_analysis(self) -> None:
        device = self._ensure_device_exists()
        if not device:
            return
        package = self.target_app_input.text().strip() or self.apps_combo.currentText().strip()
        if not package:
            QMessageBox.warning(self, "Missing Package", "Enter a target app package first.")
            return

        def task():
            self.connector.launch_app(device.serial, package)
            return package

        def done(result, err):
            if err:
                self._set_status(f"App analysis start failed: {err}")
                QMessageBox.critical(self, "App Launch Error", str(err))
                return
            self._set_status(f"Started app analysis for {result}.", 0, "Ready")
            if self.frida_manager is not None:
                try:
                    self._terminate_process(self.frida_tagger_process)
                    self.frida_tagger_process = self.frida_manager.start_app_traffic_tagger(result, debug=True)
                    self._append_log("Frida traffic tagger started.")
                except Exception as exc:
                    self._append_log(f"Frida traffic tagger failed: {exc}")
            QMessageBox.information(self, "App Analysis", f"Launched {result} for analysis.")

        self._start_background_task(task, done, "Starting selected app...")

    def setup_frida(self) -> None:
        device = self._ensure_device_exists()
        if not device:
            return
        package = self.target_app_input.text().strip() or self.apps_combo.currentText().strip()
        if not package:
            QMessageBox.warning(self, "Missing Package", "Enter a target app package first.")
            return

        def task():
            manager = self._get_frida_manager()
            return manager.setup_device_server(device.serial)

        def done(result, err):
            if err:
                self._set_status(f"Frida setup failed: {err}")
                self._set_device_info_value("Frida", "Failed")
                QMessageBox.critical(self, "Frida Setup Error", str(err))
                return
            self._append_log(result)
            self._set_status("Frida ready.", 0, "Ready")
            self._set_device_info_value("Frida", "Ready")
            QMessageBox.information(self, "Frida Setup", "Frida setup completed successfully.")

        self._start_background_task(task, done, "Setting up Frida...")

    def _get_frida_manager(self) -> FridaManager:
        if self.frida_manager is None:
            self.frida_manager = FridaManager(self.connector, auto_install_frida=True, frida_port=27042)
        return self.frida_manager

    def toggle_interception(self) -> None:
        if self.is_intercepting:
            self.stop_intercepting()
        else:
            self.start_intercepting()

    def start_intercepting(self) -> None:
        device = self._ensure_device_exists()
        if not device:
            return
        try:
            proxy_host = self.interceptor.start(device, callback=self._on_flow_callback)
            self.is_intercepting = True
            self.start_intercept_btn.setText("Stop Interception")
            self._set_status(f"Interception started on {proxy_host}:{self.interceptor.port}", 5, "Running")
            self.module_status_changed.emit("Intercepter", "running", device.serial)
            self._set_device_info_value("Interception", "Running")
            self._append_log(f"Interception enabled for {device.serial}.")
            self._last_tls_recovery_ts = 0.0
            self._tls_issue_notified = False
        except Exception as exc:
            self._set_status(f"Interception failed: {exc}")
            self.module_status_changed.emit("Intercepter", "failed", device.serial if device else "")
            self._set_device_info_value("Interception", "Failed")
            QMessageBox.critical(self, "Interception Error", str(exc))

    def stop_intercepting(self) -> None:
        if not self.current_device:
            return
        try:
            self.interceptor.stop(self.current_device.serial)
            self._stop_all_frida_bypass_processes()
            self.is_intercepting = False
            self.start_intercept_btn.setText("Start Interception")
            self._set_status("Interception stopped.", 100, "Stopped")
            self.module_status_changed.emit("Intercepter", "stopped", self.current_device.serial)
            self._set_device_info_value("Interception", "Stopped")
            self._append_log(f"Interception stopped for {self.current_device.serial}.")
        except Exception as exc:
            self._set_status(f"Stop failed: {exc}")
            self.module_status_changed.emit("Intercepter", "failed", self.current_device.serial if self.current_device else "")
            self._set_device_info_value("Interception", "Stop failed")
            QMessageBox.critical(self, "Stop Error", str(exc))

    def _on_flow_callback(self, flow: Dict[str, Any]) -> None:
        self.flow_received.emit(flow)

    def _add_captured_flow(self, flow: Dict[str, Any]) -> None:
        self.captured_flows.append(flow)
        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        request = flow.get("request", {})
        response = flow.get("response", {})
        method = str(request.get("method", "") or "")
        url = str(request.get("url", "") or "")
        status_code = response.get("status_code", "")
        reason = str(response.get("reason", "") or "")
        error_text = str(response.get("error", "") or "")
        status_text = str(status_code)
        if str(status_code) in {"", "0"}:
            status_text = error_text or reason or "0"
        self.log_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.log_table.setItem(row, 1, QTableWidgetItem(method))
        self.log_table.setItem(row, 2, QTableWidgetItem(url))
        self.log_table.setItem(row, 3, QTableWidgetItem(status_text))
        self._set_status(f"Captured {len(self.captured_flows)} flows.", min(100, len(self.captured_flows)), "Running")
        self._set_device_info_value("Operation", f"Captured {len(self.captured_flows)} flow(s)")

    def _show_selected_flow(self) -> None:
        row = self.log_table.currentRow()
        if row < 0 or row >= len(self.captured_flows):
            return
        flow = self.captured_flows[row]
        request = flow.get("request", {})
        response = flow.get("response", {})
        request_text = f"Method: {request.get('method', '')}\nURL: {request.get('url', '')}\nHeaders: {request.get('headers', {})}\n\nBody:\n{request.get('body', '')}"
        response_text = f"Status: {response.get('status_code', '')}\nReason: {response.get('reason', '')}\nHeaders: {response.get('headers', {})}\n\nBody:\n{response.get('body', '')}"
        self.request_editor.setPlainText(request_text)
        self.response_editor.setPlainText(response_text)

    def _show_flow_context_menu(self, pos) -> None:
        row = self.log_table.rowAt(pos.y())
        menu = QMenu(self)
        send_action = QAction("Send To Analyzer", self)
        send_payloader_action = QAction("Send To Payloader", self)
        if 0 <= row < len(self.captured_flows):
            send_action.triggered.connect(lambda: self.send_to_analyzer.emit(self.captured_flows[row]))
            send_payloader_action.triggered.connect(lambda: self.send_to_payloader.emit(self.captured_flows[row]))
        else:
            send_action.setEnabled(False)
            send_payloader_action.setEnabled(False)
        menu.addAction(send_action)
        menu.addAction(send_payloader_action)
        menu.addSeparator()
        clear_selected_action = QAction("Clear Selected", self)
        clear_selected_action.setEnabled(0 <= row < len(self.captured_flows))
        clear_selected_action.triggered.connect(self._clear_selected_flow)
        menu.addAction(clear_selected_action)
        clear_all_action = QAction("Clear All Traffic", self)
        clear_all_action.setEnabled(bool(self.captured_flows))
        clear_all_action.triggered.connect(self._clear_all_flows)
        menu.addAction(clear_all_action)
        menu.exec(self.log_table.viewport().mapToGlobal(pos))

    def _clear_selected_flow(self) -> None:
        row = self.log_table.currentRow()
        if row < 0 or row >= len(self.captured_flows):
            return
        self.log_table.removeRow(row)
        del self.captured_flows[row]
        # Re-index numbering column.
        for idx in range(self.log_table.rowCount()):
            self.log_table.setItem(idx, 0, QTableWidgetItem(str(idx + 1)))
        self._set_status(f"Cleared selected flow. Remaining: {len(self.captured_flows)}", 0, "Running")
        self._set_device_info_value("Operation", f"Captured {len(self.captured_flows)} flow(s)")
        if self.log_table.rowCount() == 0:
            self.request_editor.clear()
            self.response_editor.clear()

    def _clear_all_flows(self) -> None:
        self.log_table.setRowCount(0)
        self.captured_flows.clear()
        self.request_editor.clear()
        self.response_editor.clear()
        self._set_status("Cleared all captured traffic.", 0, "Running")
        self._set_device_info_value("Operation", "Captured 0 flow(s)")

    def _format_device_info(self, device: AndroidDevice) -> str:
        return (
            f"Serial: {device.serial}\n"
            f"State: {device.state}\n"
            f"Type: {device.model or device.transport or 'unknown'}\n"
            f"Android: {device.android_version}\n"
            f"ABI: {device.abi}\n"
            f"Manufacturer: {device.manufacturer}\n"
            f"Transport: {device.transport}\n"
            f"Health: {device.state}"
        )

    def _update_logcat(self) -> None:
        if not self.current_device:
            self._append_logcat_message("No device connected.")
            self._set_device_info_value("Operation", "Waiting for device")
            return
        package = self.target_app_input.text().strip() or self.apps_combo.currentText().strip()
        try:
            result = self.connector._run_adb([
                "-s", self.current_device.serial,
                "logcat", "-d", "-t", "100", "-v", "time",
            ])
            if result.returncode != 0:
                self._append_logcat_message(result.stderr.strip() or result.stdout.strip() or "Unable to read logcat.")
                return
            lines = (result.stdout or "").splitlines()
            lines = self._filter_relevant_logcat_lines(lines, package)
            self._set_device_info_value("Operation", f"Monitoring {package}" if package else "Monitoring logcat")
            if lines:
                self.logcat_text.setPlainText("\n".join(lines[-140:]))
                self._handle_tls_trust_issue(lines, package)
            else:
                self._append_logcat_message("No relevant app/proxy/frida warnings or errors detected yet.")
            self._collect_frida_process_issues()
        except Exception as exc:
            self._append_logcat_message(f"Logcat refresh failed: {exc}")
            self._set_device_info_value("Operation", "Logcat refresh failed")

    def _filter_relevant_logcat_lines(self, lines: List[str], package: str) -> List[str]:
        relevant_keywords = (
            "mobhound", "frida", "mitm", "proxy", "ssl", "pinning", "okhttp",
            "exception", "error", "fatal", "fail", "denied", "timeout", "crash",
            "intercept", "certificate",
        )
        kept: List[str] = []
        lines = lines or []
        for line in lines:
            lower = line.lower()
            has_severity = bool(re.search(r"\s[ewf]/", lower))
            has_keyword = any(k in lower for k in relevant_keywords)
            has_package = bool(package and package in line)
            if has_package or has_severity or has_keyword:
                kept.append(line)
        return kept

    def _collect_frida_process_issues(self) -> None:
        for attr, label in (
            ("frida_tagger_process", "Frida traffic tagger"),
            ("frida_ssl_process", "SSL bypass"),
            ("frida_root_process", "Root bypass"),
            ("frida_detection_process", "Frida detection bypass"),
        ):
            process = getattr(self, attr, None)
            if not process or process.poll() is None:
                continue
            stderr = ""
            try:
                _, stderr = process.communicate(timeout=0.1)
            except Exception:
                pass
            detail = (stderr or "").strip()
            if detail:
                self._append_logcat_message(f"{label} exited with issue: {detail}")
            setattr(self, attr, None)

    def _handle_tls_trust_issue(self, lines: List[str], package: str) -> None:
        if not self.is_intercepting or not package:
            return

        joined = "\n".join(lines).lower()
        has_trust_issue = (
            "trust anchor for certification path not found" in joined
            or "net_error -202" in joined
            or "sslhandshakeexception" in joined
        )
        if not has_trust_issue:
            return

        if not self._tls_issue_notified:
            self._append_logcat_message(
                "TLS trust issue detected (net_error -202 / trust anchor). Attempting SSL bypass recovery."
            )
            self._tls_issue_notified = True

        now = time.time()
        # Avoid repeated restart loops; retry at most once every 30s.
        if now - self._last_tls_recovery_ts < 30:
            return
        self._last_tls_recovery_ts = now

        if self.frida_manager is None:
            self._append_logcat_message("Frida not ready. Run Frida Setup, then re-run app analysis.")
            return

        try:
            self.ssl_checkbox.blockSignals(True)
            self.ssl_checkbox.setChecked(True)
            self.ssl_checkbox.blockSignals(False)
            self._terminate_process(self.frida_ssl_process)
            self.frida_ssl_process = self.frida_manager.start_ssl_bypass(package)

            if self.current_device:
                self.connector.force_stop_app(self.current_device.serial, package)
                self.connector.launch_app(self.current_device.serial, package)
            self._append_logcat_message("SSL bypass started and app relaunched for TLS recovery.")
        except Exception as exc:
            self._append_logcat_message(f"Auto SSL bypass recovery failed: {exc}")

    def _on_ssl_bypass_toggled(self, checked: bool) -> None:
        self._toggle_frida_bypass(
            checked=checked,
            process_attr="frida_ssl_process",
            start_fn_name="start_ssl_bypass",
            label="SSL pinning bypass",
            checkbox=self.ssl_checkbox,
        )

    def _on_root_bypass_toggled(self, checked: bool) -> None:
        self._toggle_frida_bypass(
            checked=checked,
            process_attr="frida_root_process",
            start_fn_name="start_root_emulator_bypass",
            label="Root/emulator bypass",
            checkbox=self.root_checkbox,
        )

    def _on_frida_detection_bypass_toggled(self, checked: bool) -> None:
        self._toggle_frida_bypass(
            checked=checked,
            process_attr="frida_detection_process",
            start_fn_name="start_frida_detection_bypass",
            label="Frida detection bypass",
            checkbox=self.frida_detection_checkbox,
        )

    def _terminate_process(self, process: Optional[subprocess.Popen]) -> None:
        if not process:
            return
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

    def _toggle_frida_bypass(
        self,
        checked: bool,
        process_attr: str,
        start_fn_name: str,
        label: str,
        checkbox: Optional[QCheckBox] = None,
    ) -> None:
        def _revert_checkbox() -> None:
            if checkbox is None:
                return
            checkbox.blockSignals(True)
            checkbox.setChecked(False)
            checkbox.blockSignals(False)

        process = getattr(self, process_attr, None)

        if not checked:
            self._terminate_process(process)
            setattr(self, process_attr, None)
            self._set_status(f"{label} disabled.", 0, "Ready")
            return

        device = self._ensure_device_exists()
        if not device:
            _revert_checkbox()
            setattr(self, process_attr, None)
            self._set_status(f"{label} requires a connected device.")
            return

        package = self.target_app_input.text().strip() or self.apps_combo.currentText().strip()
        if not package:
            QMessageBox.warning(self, "Missing Package", f"Enter a target app package before enabling {label}.")
            _revert_checkbox()
            setattr(self, process_attr, None)
            self._set_status(f"{label} requires a target app package.")
            return

        if self.frida_manager is None:
            QMessageBox.warning(self, "Frida Not Ready", "Run 'Setup' in Frida Setup before enabling bypass options.")
            _revert_checkbox()
            setattr(self, process_attr, None)
            self._set_status(f"{label} requires Frida setup.")
            return

        try:
            self._terminate_process(process)
            start_fn = getattr(self.frida_manager, start_fn_name)
            new_process = start_fn(package)
            setattr(self, process_attr, new_process)
            self._set_status(f"{label} enabled.", 0, "Ready")
        except Exception as exc:
            _revert_checkbox()
            setattr(self, process_attr, None)
            self._set_status(f"{label} failed: {exc}")
            QMessageBox.warning(self, "Frida Bypass Error", str(exc))

    def _stop_all_frida_bypass_processes(self) -> None:
        self._terminate_process(self.frida_tagger_process)
        self.frida_tagger_process = None
        for attr, checkbox in (
            ("frida_ssl_process", self.ssl_checkbox),
            ("frida_root_process", self.root_checkbox),
            ("frida_detection_process", self.frida_detection_checkbox),
        ):
            self._terminate_process(getattr(self, attr, None))
            setattr(self, attr, None)
            checkbox.blockSignals(True)
            checkbox.setChecked(False)
            checkbox.blockSignals(False)

    def _on_app_selected(self, package: str) -> None:
        if package:
            self.target_app_input.setText(package)

    def _infer_intercept_target(self):
        row = self.log_table.currentRow()
        if row >= 0 and self.log_table.item(row, 2):
            return self.log_table.item(row, 2).text()
        if self.log_table.rowCount() > 0 and self.log_table.item(0, 2):
            return self.log_table.item(0, 2).text()
        return "Traffic Session"

    # --------------------------------------------------------------------------
    # NEW apply_theme method to support light/dark theme switching
    # --------------------------------------------------------------------------
    def apply_theme(self, theme_name: str) -> None:
        """Apply light/dark theme to interceptor page elements."""
        is_light = theme_name == "Light"
        text_color = "#111827" if is_light else "#f1f5f9"
        label_color = "#6A0DAD" if is_light else "white"
        card_bg = "#FFFFFF" if is_light else "qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855)"
        card_border = "#bdc3c7" if is_light else "#5D2E8C"
        input_border = "#6A0DAD" if is_light else "#5D2E8C"
        inner_bg = "#FFFFFF" if is_light else "#0f172a"
        table_bg = "#FFFFFF" if is_light else "#0f172a"
        table_color = "#111827" if is_light else "#f1f5f9"
        header_bg = "#e5e7eb" if is_light else "#1e293b"
        header_color = "#111827" if is_light else "#94a3b8"
        indicator_border = "#6A0DAD" if is_light else "#cbd5e1"
        indicator_bg = "#FFFFFF" if is_light else "#0f172a"
        indicator_checked = "#6A0DAD" if is_light else "#7c3aed"
        btn_style = (
            "QPushButton{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;border-radius:6px;font-weight:bold;padding:3px 8px;font-size:8pt;}"
            "QPushButton:hover{background:#F3E8FF;}"
        ) if is_light else (
            "QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:3px 8px;font-size:8pt;}"
            "QPushButton:hover{background:#7c3aed;}"
            "QPushButton:disabled{background:#374151;color:#9ca3af;}"
        )
        combo_style = (
            f"QComboBox{{background:{inner_bg};color:{label_color};border:none;border-radius:6px;padding:2px 6px;font-size:8pt;}}"
            f"QComboBox QAbstractItemView{{background:{inner_bg};color:{label_color};border:1px solid {input_border};}}"
        )
        lineedit_style = (
            f"QLineEdit{{background:{inner_bg};color:{label_color};border:none;border-radius:4px;padding:2px 5px;font-size:8pt;}}"
        )
        textedit_style = (
            f"QTextEdit{{background:{inner_bg};border:none;border-radius:4px;color:{text_color};font-size:8pt;}}"
        )
        table_style = (
            f"QTableWidget{{background:{table_bg};border:1px solid {card_border};color:{table_color};gridline-color:{card_border};alternate-background-color:{inner_bg};}}"
            "QTableWidget::item{background:transparent;}"
            f"QTableWidget::item:selected{{background:{header_bg};color:{text_color};}}"
            f"QHeaderView::section{{background:{header_bg};color:{header_color};border:1px solid {card_border};padding:3px;font-weight:bold;font-size:8pt;}}"
        )
        traffic_group_style = f"QFrame#interceptorTrafficGroup{{background:{card_bg};border:1px solid {card_border};border-radius:10px;}}"
        section_group_style = (
            f"QGroupBox#interceptorSectionGroup{{background:transparent;border:1px solid {card_border};border-radius:6px;margin-top:0px;padding:4px;color:{text_color};}}"
        )
        left_card_style = f"QFrame#interceptorLeftCard{{background:{card_bg};border:1px solid {card_border};border-radius:10px;}}"
        device_info_style = f"QFrame#deviceInfoBox{{background:{card_bg};border:1px solid {card_border};border-radius:10px;}}"
        logcat_box_style = f"QFrame#interceptorLogcatBox{{background:{card_bg};border:1px solid {card_border};border-radius:10px;}}"
        frida_style = (
            f"QGroupBox#interceptorFridaGroup{{background:{card_bg};border:1px solid {card_border};border-radius:10px;color:{text_color};padding:6px 10px 8px 10px;}}"
            "QGroupBox#interceptorFridaGroup QWidget#interceptorFridaOptionRow{background-color:transparent;border:none;}"
            f"QGroupBox#interceptorFridaGroup QLabel#interceptorFridaOptionLabel{{color:{text_color};background-color:transparent;padding:2px 0;font-size:8pt;}}"
            "QGroupBox#interceptorFridaGroup QCheckBox#interceptorFridaOptionCheck{background-color:transparent;}"
            f"QGroupBox#interceptorFridaGroup QCheckBox#interceptorFridaOptionCheck::indicator{{width:14px;height:14px;border-radius:3px;border:2px solid {indicator_border};background:{indicator_bg};}}"
            f"QGroupBox#interceptorFridaGroup QCheckBox#interceptorFridaOptionCheck::indicator:checked{{background:{indicator_checked};border:2px solid {indicator_checked};}}"
        )
        checkbox_style = (
            "QCheckBox{background-color:transparent;spacing:8px;padding:0;margin:0;}"
            f"QCheckBox::indicator{{width:14px;height:14px;border-radius:3px;border:2px solid {indicator_border};background:{indicator_bg};}}"
            f"QCheckBox::indicator:checked{{background:{indicator_checked};border:2px solid {indicator_checked};}}"
        )
        logcat_style = f"QTextEdit{{background:{inner_bg};color:{text_color};border:none;border-radius:6px;font-size:8pt;}}"
        bottom_style = f"QFrame#interceptorBottomBar{{background:{card_bg};border-radius:4px;border:1px solid {card_border};}}"

        # Apply styles to all components
        left_card = self.findChild(QFrame, "interceptorLeftCard")
        if left_card:
            left_card.setStyleSheet(left_card_style)
        device_info_box = self.findChild(QFrame, "deviceInfoBox")
        if device_info_box:
            device_info_box.setStyleSheet(device_info_style)
        frida_box = self.findChild(QGroupBox, "interceptorFridaGroup")
        if frida_box:
            frida_box.setStyleSheet(frida_style)
        logcat_box = self.findChild(QFrame, "interceptorLogcatBox")
        if logcat_box:
            logcat_box.setStyleSheet(logcat_box_style)
        traffic_group = self.findChild(QFrame, "interceptorTrafficGroup")
        if traffic_group:
            traffic_group.setStyleSheet(traffic_group_style)
        for group in self.findChildren(QGroupBox, "interceptorSectionGroup"):
            group.setStyleSheet(section_group_style)
        bottom_bar = self.findChild(QFrame, "interceptorBottomBar")
        if bottom_bar:
            bottom_bar.setStyleSheet(bottom_style)
            if self._interceptor_status_lbl:
                self._interceptor_status_lbl.setStyleSheet(f"color:{text_color};font-size:11px;")

        # Toolbar buttons
        for btn in [self.refresh_btn, self.health_btn, self.start_intercept_btn,
                    self.generate_cert_btn, self.install_apk_btn, self.start_app_analysis_btn,
                    self.connect_btn, self.setup_frida_btn, self.capture_readiness_btn]:
            if btn:
                btn.setStyleSheet(btn_style)

        # Form elements
        self.target_input.setStyleSheet(lineedit_style)
        self.preferred_serial_input.setStyleSheet(lineedit_style)
        self.target_app_input.setStyleSheet(lineedit_style)
        self.apps_combo.setStyleSheet(combo_style)

        # Table and editors
        self.log_table.setStyleSheet(table_style)
        self.log_table.setAlternatingRowColors(False)
        self.device_info_table.setStyleSheet(
            f"QTableWidget{{background:transparent;color:{text_color};border:none;gridline-color:{card_border};}}"
            f"QTableWidget::item{{border-bottom:1px solid {card_border};}}"
        )
        self.request_editor.setStyleSheet(textedit_style)
        self.response_editor.setStyleSheet(textedit_style)
        self.logcat_text.setStyleSheet(logcat_style)

        # Labels
        for lbl in self.findChildren(QLabel):
            if self._interceptor_status_lbl and lbl is self._interceptor_status_lbl:
                continue
            if lbl.objectName() == "interceptorFridaOptionLabel":
                continue
            lbl.setStyleSheet(f"color:{label_color};background-color:transparent;")

        # Checkboxes
        for cb in [self.ssl_checkbox, self.root_checkbox, self.frida_detection_checkbox]:
            cb.setStyleSheet(checkbox_style)

        self._set_status(f"Theme changed to {theme_name}")


# ------------------------------------------------------------------------------
# AnalyzerPage (Repeater-style request analyzer)
# ------------------------------------------------------------------------------
class AnalyzerPage(BasePage):
    def __init__(self):
        self.request_sessions: List[Dict[str, Any]] = []
        super().__init__()
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.active_future: Optional[Future] = None
        self.active_process: Optional[subprocess.Popen] = None
        self.task_timer = QTimer(self)
        self.task_timer.timeout.connect(self._poll_active_task)
        self._live_replay_timer = QTimer(self)
        self._live_replay_timer.setSingleShot(True)
        self._live_replay_timer.timeout.connect(self.send_request)
        self._ignore_change = False
        self._request_history: List[str] = []
        self._history_index = -1
        self._last_log_message = ""

    def _setup_ui(self):
        layout = self.container_layout
        self.container.setObjectName("analyzerContainer")
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        self.request_tabs = QTabWidget()
        self.request_tabs.setObjectName("analyzerRepeaterTabs")
        self.request_tabs.setTabsClosable(True)
        self.request_tabs.setMovable(True)
        self.request_tabs.setDocumentMode(True)
        self.request_tabs.setMinimumHeight(34)
        self.request_tabs.currentChanged.connect(self._on_session_changed)
        self.request_tabs.tabCloseRequested.connect(self._close_session_tab)
        layout.addWidget(self.request_tabs)

        toolbar = QHBoxLayout()
        self.send_btn = StyledButton("Send")
        self.send_btn.setFixedHeight(34)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setFixedHeight(34)
        toolbar.addWidget(self.send_btn)
        toolbar.addWidget(self.cancel_btn)
        toolbar.addStretch(1)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search: request/response text")
        self.search_input.setFont(QFont("Poppins", 10))
        self.search_input.setMaximumWidth(220)
        self.search_input.setMinimumHeight(32)
        self.search_input.textChanged.connect(self.on_search_text_changed)
        self.search_input.setStyleSheet("QLineEdit{background:#1e293b;border:1px solid #5D2E8C;border-radius:4px;color:#f1f5f9;padding:6px;}")
        toolbar.addWidget(self.search_input)
        layout.addLayout(toolbar)

        request_group = QGroupBox()
        request_group.setObjectName("analyzerMessageSectionGroup")
        request_group.setStyleSheet("QGroupBox#analyzerMessageSectionGroup{background:transparent;border:1px solid #5D2E8C;border-radius:6px;color:#f6f5ff;margin-top:0px;padding:4px;}")
        req_layout = QVBoxLayout(request_group)
        req_layout.setContentsMargins(5, 5, 5, 5)
        self.request_editor = QPlainTextEdit()
        self.request_editor.setPlaceholderText("Raw HTTP request...")
        self.request_editor.setFont(QFont("Consolas", 8))
        self.request_editor.setContextMenuPolicy(Qt.CustomContextMenu)
        self.request_editor.customContextMenuRequested.connect(self._show_request_context_menu)
        req_layout.addWidget(self.request_editor)

        response_group = QGroupBox()
        response_group.setObjectName("analyzerMessageSectionGroup")
        response_group.setStyleSheet("QGroupBox#analyzerMessageSectionGroup{background:transparent;border:1px solid #5D2E8C;border-radius:6px;color:#f6f5ff;margin-top:0px;padding:4px;}")
        resp_layout = QVBoxLayout(response_group)
        resp_layout.setContentsMargins(5, 5, 5, 5)
        self.response_editor = QPlainTextEdit()
        self.response_editor.setReadOnly(True)
        self.response_editor.setPlaceholderText("Response appears here...")
        self.response_editor.setFont(QFont("Consolas", 8))
        resp_layout.addWidget(self.response_editor)

        inspector_group = QGroupBox("Inspector")
        inspector_group.setObjectName("analyzerSectionGroup")
        inspector_layout = QVBoxLayout(inspector_group)
        self.inspector_selector = QComboBox()
        self.inspector_selector.addItems([
            "Request attributes",
            "Request query parameters",
            "Request body parameters",
            "Request cookies",
            "Request headers",
            "Response headers",
        ])
        self.inspector_selector.setEnabled(False)
        inspector_layout.addWidget(self.inspector_selector)
        self.inspector_text = QPlainTextEdit()
        self.inspector_text.setReadOnly(True)
        self.inspector_text.setFont(QFont("Consolas", 9))
        self.inspector_text.setPlaceholderText("Inspector data appears after a request is sent to Analyzer.")
        inspector_layout.addWidget(self.inspector_text)

        sections_row = QHBoxLayout()
        sections_row.setContentsMargins(0, 0, 0, 0)
        sections_row.setSpacing(10)
        sections_row.addWidget(request_group, 4)
        sections_row.addWidget(response_group, 4)
        sections_row.addWidget(inspector_group, 2)
        layout.addLayout(sections_row, 1)

        self._analyzer_status_lbl = None
        self._analyzer_state_lbl = None
        self._set_request_state("ready")

        self.send_btn.clicked.connect(self.send_request)
        self.cancel_btn.clicked.connect(self.cancel_request)
        self.request_editor.textChanged.connect(self._on_request_text_changed)
        self.inspector_selector.currentTextChanged.connect(self._refresh_inspector_view)
        self._add_session("1")

    def load_flow(self, flow: Dict[str, Any]) -> None:
        request = flow.get("request", {})
        response = flow.get("response", {})
        raw_request = self._format_raw_request(request)
        response_preview = self._format_response_preview(response)
        current = self._get_current_session()
        if current and current.get("request", "").strip():
            idx = self._add_session(str(len(self.request_sessions) + 1))
            self.request_tabs.setCurrentIndex(idx)
        current = self._get_current_session()
        if current is None:
            return
        current["request"] = raw_request
        current["response"] = response_preview
        self._ignore_change = True
        self.request_editor.setPlainText(raw_request)
        self._ignore_change = False
        self.response_editor.setPlainText(response_preview)
        self.inspector_selector.setEnabled(True)
        self._update_inspector(raw_request, self.response_editor.toPlainText())
        self._append_log("Flow loaded from Interceptor.")

    def _add_session(self, title: Optional[str] = None) -> int:
        session_title = title or str(len(self.request_sessions) + 1)
        self.request_sessions.append({"request": "", "response": "", "inspector_cache": {}})
        page = QWidget()
        idx = self.request_tabs.addTab(page, session_title)
        self.request_tabs.setTabToolTip(idx, session_title)
        return idx

    def _get_current_session(self) -> Optional[Dict[str, Any]]:
        idx = self.request_tabs.currentIndex()
        if idx < 0 or idx >= len(self.request_sessions):
            return None
        return self.request_sessions[idx]

    def _save_current_session(self) -> None:
        session = self._get_current_session()
        if session is None:
            return
        session["request"] = self.request_editor.toPlainText()
        session["response"] = self.response_editor.toPlainText()
        session["inspector_cache"] = getattr(self, "_inspector_cache", {})

    def _on_session_changed(self, index: int) -> None:
        if index < 0 or index >= len(self.request_sessions):
            return
        session = self.request_sessions[index]
        self._ignore_change = True
        self.request_editor.setPlainText(session.get("request", ""))
        self.response_editor.setPlainText(session.get("response", ""))
        self._ignore_change = False
        self._inspector_cache = session.get("inspector_cache", {})
        self.inspector_selector.setEnabled(bool(session.get("request", "").strip()))
        self._refresh_inspector_view()

    def _close_session_tab(self, index: int) -> None:
        if len(self.request_sessions) <= 1:
            return
        if 0 <= index < len(self.request_sessions):
            del self.request_sessions[index]
            self.request_tabs.removeTab(index)
            for i in range(self.request_tabs.count()):
                self.request_tabs.setTabText(i, str(i + 1))
                self.request_tabs.setTabToolTip(i, str(i + 1))
            self._append_log("Closed repeater tab.")

    def _set_status(self, message: str) -> None:
        self._append_log(message[:260])

    def _append_log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        if self._last_log_message == message:
            return
        self._last_log_message = message
        self._last_analyzer_status = f"{timestamp} | {message}"[:260]
        self._push_global_status(self._last_analyzer_status, progress_text=getattr(self, "_last_analyzer_state", "Ready"))

    def _set_request_state(self, state: str) -> None:
        state = (state or "ready").lower()
        if state == "sending":
            text = "Sending"
            style = "QLabel{background:#7c3aed;color:white;border-radius:10px;padding:2px 10px;font-size:11px;font-weight:bold;}"
        elif state == "completed":
            text = "Completed"
            style = "QLabel{background:#15803d;color:white;border-radius:10px;padding:2px 10px;font-size:11px;font-weight:bold;}"
        elif state == "canceled":
            text = "Canceled"
            style = "QLabel{background:#b45309;color:white;border-radius:10px;padding:2px 10px;font-size:11px;font-weight:bold;}"
        elif state == "error":
            text = "Error"
            style = "QLabel{background:#b91c1c;color:white;border-radius:10px;padding:2px 10px;font-size:11px;font-weight:bold;}"
        else:
            text = "Ready"
            style = "QLabel{background:#475569;color:white;border-radius:10px;padding:2px 10px;font-size:11px;font-weight:bold;}"
        self._last_analyzer_state = text
        if self._analyzer_state_lbl:
            self._analyzer_state_lbl.setText(text)
            self._analyzer_state_lbl.setStyleSheet(style)
        self._push_global_status(getattr(self, "_last_analyzer_status", "Ready"), progress_text=text)

    def _format_raw_request(self, request: Dict[str, Any]) -> str:
        method = request.get("method", "GET")
        url = request.get("url", "")
        headers = request.get("headers", {}) or {}
        body = request.get("body", "") or ""
        lines = [f"{method} {url} HTTP/1.1"]
        if isinstance(headers, dict):
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        lines.append("")
        if body:
            lines.append(body if isinstance(body, str) else str(body))
        return "\n".join(lines)

    def _format_response_preview(self, response: Dict[str, Any]) -> str:
        status_code = response.get("status_code", "")
        reason = response.get("reason", "")
        headers = response.get("headers", {}) or {}
        body = response.get("body", "") or ""
        lines = [f"HTTP/1.1 {status_code} {reason}".strip()]
        if isinstance(headers, dict):
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(body if isinstance(body, str) else str(body))
        return "\n".join(lines).strip()

    def _parse_raw_request(self, raw_text: str) -> Dict[str, Any]:
        return parse_replay_request(raw_text)

    def _split_raw_request(self, raw_request: str) -> Tuple[str, str, Dict[str, str], str]:
        parsed = self._parse_raw_request(raw_request)
        return parsed["method"], parsed["url"], parsed["headers"], parsed["body"]

    def _replace_request_line_method(self, method: str) -> None:
        raw_text = self.request_editor.toPlainText()
        if not raw_text.strip():
            return
        lines = raw_text.replace("\r\n", "\n").split("\n")
        if not lines:
            return
        method = (method or "").strip()
        if not method:
            return
        parts = lines[0].split()
        if len(parts) < 2:
            return
        url = parts[1]
        version = parts[2] if len(parts) >= 3 else "HTTP/1.1"
        lines[0] = f"{method} {url} {version}"
        self._ignore_change = True
        self.request_editor.setPlainText("\n".join(lines))
        self._ignore_change = False
        self._save_current_session()
        self._set_status(f"Method updated to {method}.")

    def _set_or_replace_header(self, header_name: str, header_value: str) -> None:
        raw_text = self.request_editor.toPlainText().replace("\r\n", "\n")
        if not raw_text.strip():
            return
        parts = raw_text.split("\n\n", 1)
        head_lines = parts[0].splitlines()
        body = parts[1] if len(parts) > 1 else ""
        if not head_lines:
            return
        updated = False
        target = header_name.lower()
        for i in range(1, len(head_lines)):
            if ":" not in head_lines[i]:
                continue
            k, _ = head_lines[i].split(":", 1)
            if k.strip().lower() == target:
                head_lines[i] = f"{header_name}: {header_value}"
                updated = True
                break
        if not updated:
            head_lines.append(f"{header_name}: {header_value}")
        rebuilt = "\n".join(head_lines) + "\n\n" + body
        self._ignore_change = True
        self.request_editor.setPlainText(rebuilt.rstrip("\n"))
        self._ignore_change = False
        self._save_current_session()
        self._set_status(f"Header updated: {header_name}")

    def _replace_selected_text(self, transform_fn, action_name: str) -> None:
        cursor = self.request_editor.textCursor()
        selected = cursor.selectedText()
        if not selected:
            self._set_status(f"{action_name}: no text selected.")
            return
        try:
            replaced = transform_fn(selected.replace("\u2029", "\n"))
        except Exception as exc:
            self._set_status(f"{action_name} failed: {exc}")
            return
        cursor.insertText(replaced)
        self._save_current_session()
        self._set_status(f"{action_name} applied.")

    def on_search_text_changed(self, text: str) -> None:
        query = (text or "").strip()
        if not query:
            self.clear_search_highlights()
            return
        self._highlight_matches(self.request_editor, query)
        self._highlight_matches(self.response_editor, query)
        self._set_status(f"Search highlights updated for '{query}'.")

    def _highlight_matches(self, editor: QPlainTextEdit, query: str) -> None:
        content = editor.toPlainText()
        matches = self._find_text_occurrences(content, query)
        selections = []
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor("#FFFF00"))
        highlight_format.setForeground(QColor("#111827"))
        for start, end in matches:
            selection = QTextEdit.ExtraSelection()
            cursor = editor.textCursor()
            cursor.setPosition(start)
            cursor.setPosition(end, QTextCursor.KeepAnchor)
            selection.cursor = cursor
            selection.format = highlight_format
            selections.append(selection)
        editor.setExtraSelections(selections)

    def _find_text_occurrences(self, content: str, query: str) -> List[Tuple[int, int]]:
        matches: List[Tuple[int, int]] = []
        if not content or not query:
            return matches
        content_lower = content.lower()
        query_lower = query.lower()
        start = 0
        qlen = len(query_lower)
        while True:
            idx = content_lower.find(query_lower, start)
            if idx == -1:
                break
            matches.append((idx, idx + qlen))
            start = idx + qlen
        return matches

    def clear_search_highlights(self) -> None:
        self.request_editor.setExtraSelections([])
        self.response_editor.setExtraSelections([])

    def _show_request_context_menu(self, pos) -> None:
        menu = self.request_editor.createStandardContextMenu()
        menu.addSeparator()

        method_menu = menu.addMenu("Set Method")
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
            action = method_menu.addAction(method)
            action.triggered.connect(lambda checked=False, m=method: self._replace_request_line_method(m))
        custom_method_action = method_menu.addAction("Custom...")
        custom_method_action.triggered.connect(self._set_custom_method)

        headers_menu = menu.addMenu("Android Header Presets")
        headers_menu.addAction("Set Content-Type: application/json").triggered.connect(
            lambda: self._set_or_replace_header("Content-Type", "application/json")
        )
        headers_menu.addAction("Set Content-Type: application/x-www-form-urlencoded").triggered.connect(
            lambda: self._set_or_replace_header("Content-Type", "application/x-www-form-urlencoded")
        )
        headers_menu.addAction("Set Accept: application/json").triggered.connect(
            lambda: self._set_or_replace_header("Accept", "application/json")
        )
        headers_menu.addAction("Set X-Requested-With: com.android.browser").triggered.connect(
            lambda: self._set_or_replace_header("X-Requested-With", "com.android.browser")
        )

        cookie_action = menu.addAction("Set/Replace Cookie...")
        cookie_action.triggered.connect(self._set_cookie_header)

        encoding_menu = menu.addMenu("Encode/Decode Selection")
        encoding_menu.addAction("URL Encode").triggered.connect(
            lambda: self._replace_selected_text(lambda s: urllib.parse.quote(s, safe=""), "URL encode")
        )
        encoding_menu.addAction("URL Decode").triggered.connect(
            lambda: self._replace_selected_text(lambda s: urllib.parse.unquote(s), "URL decode")
        )
        encoding_menu.addAction("Base64 Encode").triggered.connect(
            lambda: self._replace_selected_text(lambda s: base64.b64encode(s.encode("utf-8")).decode("ascii"), "Base64 encode")
        )
        encoding_menu.addAction("Base64 Decode").triggered.connect(
            lambda: self._replace_selected_text(lambda s: base64.b64decode(s).decode("utf-8", errors="replace"), "Base64 decode")
        )

        menu.exec(self.request_editor.mapToGlobal(pos))

    def _set_custom_method(self) -> None:
        method, ok = QInputDialog.getText(self, "Custom Method", "Enter HTTP method/token:")
        if not ok:
            return
        self._replace_request_line_method(method.strip())

    def _set_cookie_header(self) -> None:
        cookie, ok = QInputDialog.getText(self, "Cookie Header", "Enter Cookie header value:")
        if not ok:
            return
        self._set_or_replace_header("Cookie", cookie.strip())

    def _dispatch_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return send_request_payload(payload, timeout=25)

    def _start_request_subprocess(self, payload: Dict[str, Any]) -> subprocess.Popen:
        payload_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        runner = (
            "import base64, json\n"
            "from dynamic_analysis.http_replay import send_request_payload\n"
            "p = json.loads(base64.b64decode(%s).decode('utf-8'))\n"
            "out = {}\n"
            "try:\n"
            "    out = send_request_payload(p, timeout=60)\n"
            "except Exception as e:\n"
            "    out = {'error': str(e)}\n"
            "print(json.dumps(out))\n"
        ) % repr(payload_b64)
        return subprocess.Popen(
            [sys.executable, "-c", runner],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def _render_response(self, result: Dict[str, Any]) -> str:
        return render_replay_response(result)

    def send_request(self) -> None:
        if self.active_process and self.active_process.poll() is None:
            self._set_status("Request in progress...")
            self._set_request_state("sending")
            return
        if self.active_future and not self.active_future.done():
            self._set_status("Request in progress...")
            self._set_request_state("sending")
            return
        raw_text = self.request_editor.toPlainText().strip()
        if not raw_text:
            QMessageBox.warning(self, "Analyzer", "Request is empty.")
            return
        try:
            payload = self._parse_raw_request(raw_text)
        except Exception as exc:
            QMessageBox.warning(self, "Analyzer Parse Error", str(exc))
            self._set_status(f"Parse error: {exc}")
            return
        self._request_history.append(raw_text)
        self._history_index = len(self._request_history) - 1
        self._set_status(f"Sending {payload['method']} {payload['url']} ...")
        self._set_request_state("sending")
        self.inspector_selector.setEnabled(True)
        self.active_process = self._start_request_subprocess(payload)
        self.task_timer.start(200)

    def _poll_active_task(self) -> None:
        if self.active_process and self.active_process.poll() is None:
            return
        if not self.active_process:
            self.task_timer.stop()
            return
        self.task_timer.stop()
        try:
            stdout, stderr = self.active_process.communicate(timeout=0.2)
            if self.active_process.returncode not in (0, None):
                detail = (stderr or stdout or "").strip() or "request process failed"
                self.response_editor.setPlainText(f"Error: {detail}")
                self._set_status(f"Send failed: {detail}")
                self._set_request_state("error")
                self.active_process = None
                return
            result = json.loads((stdout or "").strip() or "{}")
            if result.get("error"):
                self.response_editor.setPlainText(f"Error: {result['error']}")
                self._set_status(f"Send failed: {result['error']}")
                self._set_request_state("error")
                self.active_process = None
                return
            response_text = self._render_response(result)
            self.response_editor.setPlainText(response_text)
            self._update_inspector(self.request_editor.toPlainText(), response_text)
            self._save_current_session()
            self._set_status(f"Received {result.get('status', '')} from {result.get('url', '-')}.")
            self._set_request_state("completed")
        except Exception as exc:
            self.response_editor.setPlainText(f"Error: {exc}")
            self._set_status(f"Send failed: {exc}")
            self._set_request_state("error")
        finally:
            self.active_process = None

    def _update_inspector(self, raw_request: str, raw_response: str) -> None:
        self._inspector_cache = self._build_inspector_cache(raw_request, raw_response)
        session = self._get_current_session()
        if session is not None:
            session["inspector_cache"] = self._inspector_cache
        self._refresh_inspector_view()

    def _build_inspector_cache(self, raw_request: str, raw_response: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        try:
            method, url, headers, body = self._split_raw_request(raw_request)
        except Exception:
            return {"Request attributes": "Unable to parse request."}

        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)
        body_params = urllib.parse.parse_qsl(body, keep_blank_values=True)
        cookies = headers.get("Cookie", "")
        cookie_parts = [c.strip() for c in cookies.split(";") if c.strip()]

        out["Request attributes"] = "\n".join([
            f"Method: {method}",
            f"URL: {url}",
            f"Scheme: {parsed_url.scheme or '-'}",
            f"Host: {parsed_url.netloc or headers.get('Host', '-')}",
            f"Path: {parsed_url.path or '/'}",
            f"Body bytes: {len(body.encode('utf-8', errors='ignore'))}",
        ])
        out["Request query parameters"] = "\n".join([f"{k} = {v}" for k, v in query_params]) or "No query parameters."
        out["Request body parameters"] = "\n".join([f"{k} = {v}" for k, v in body_params]) or "No x-www-form-urlencoded body parameters."
        out["Request cookies"] = "\n".join(cookie_parts) or "No cookies."
        out["Request headers"] = "\n".join([f"{k}: {v}" for k, v in headers.items()]) or "No headers."

        resp_headers: Dict[str, str] = {}
        resp_lines = raw_response.replace("\r\n", "\n").splitlines()
        for line in resp_lines[1:]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            resp_headers[k.strip()] = v.strip()
        out["Response headers"] = "\n".join([f"{k}: {v}" for k, v in resp_headers.items()]) or "No response headers."
        return out

    def _refresh_inspector_view(self) -> None:
        if not hasattr(self, "_inspector_cache"):
            return
        key = self.inspector_selector.currentText().strip()
        self.inspector_text.setPlainText(self._inspector_cache.get(key, "No data."))

    def _on_request_text_changed(self) -> None:
        if self._ignore_change:
            return
        self._save_current_session()
        self._live_replay_timer.start(800)

    def cancel_request(self) -> None:
        if self.active_process and self.active_process.poll() is None:
            self.active_process.terminate()
            try:
                self.active_process.wait(timeout=1.5)
            except Exception:
                self.active_process.kill()
            self.active_process = None
            self.task_timer.stop()
            self._set_status("Canceled current request.")
            self._set_request_state("canceled")
            return
        if self.active_future and not self.active_future.done():
            self.active_future.cancel()
            self._set_status("Canceled pending request.")
            self._set_request_state("canceled")

    def history_back(self) -> None:
        if not self._request_history:
            return
        self._history_index = max(0, self._history_index - 1)
        self._ignore_change = True
        self.request_editor.setPlainText(self._request_history[self._history_index])
        self._ignore_change = False

    def history_forward(self) -> None:
        if not self._request_history:
            return
        self._history_index = min(len(self._request_history) - 1, self._history_index + 1)
        self._ignore_change = True
        self.request_editor.setPlainText(self._request_history[self._history_index])
        self._ignore_change = False

    def apply_theme(self, theme_name: str) -> None:
        is_light = theme_name == "Light"
        close_icon = str((ICONS_DIR / "cross_white.svg").resolve()).replace("\\", "/")
        text_color = "#111827" if is_light else "#f1f5f9"
        label_color = "#6A0DAD" if is_light else "white"
        card_bg = "#FFFFFF" if is_light else "qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855)"
        card_border = "#bdc3c7" if is_light else "#5D2E8C"
        inner_bg = "#FFFFFF" if is_light else "#0f172a"
        btn_style = (
            "QPushButton{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;border-radius:6px;font-weight:bold;padding:5px 10px;}"
            "QPushButton:hover{background:#F3E8FF;}"
        ) if is_light else (
            "QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:5px 10px;}"
            "QPushButton:hover{background:#7c3aed;}"
            "QPushButton:disabled{background:#374151;color:#9ca3af;}"
        )
        group_style = (
            f"QGroupBox#analyzerSectionGroup{{background:{card_bg};border:1px solid {card_border};"
            f"border-radius:10px;margin-top:0px;padding:8px;color:{text_color};}}"
            f"QGroupBox#analyzerSectionGroup::title{{subcontrol-origin:margin;left:10px;padding:0 5px;color:{label_color};}}"
        )
        message_group_style = (
            f"QGroupBox#analyzerMessageSectionGroup{{background:transparent;border:1px solid {card_border};"
            f"border-radius:6px;margin-top:0px;padding:4px;color:{text_color};}}"
        )
        editor_style = f"QPlainTextEdit{{background:{inner_bg};color:{text_color};border:none;border-radius:4px;font-size:8pt;}}"
        combo_style = (
            f"QComboBox{{background:{inner_bg};color:{label_color};border:none;border-radius:6px;padding:4px 8px;}}"
            f"QComboBox QAbstractItemView{{background:{inner_bg};color:{text_color};border:1px solid {card_border};}}"
        )
        self.request_editor.setStyleSheet(editor_style)
        self.response_editor.setStyleSheet(editor_style)
        self.inspector_text.setStyleSheet(editor_style)
        self.inspector_selector.setStyleSheet(combo_style)
        self.send_btn.setStyleSheet(btn_style)
        self.cancel_btn.setStyleSheet(btn_style)
        if is_light:
            self.search_input.setStyleSheet("QLineEdit{background:#FFFFFF;border:1px solid #6A0DAD;border-radius:4px;color:#6A0DAD;padding:6px;}")
        else:
            self.search_input.setStyleSheet("QLineEdit{background:#1e293b;border:1px solid #5D2E8C;border-radius:4px;color:#f1f5f9;padding:6px;}")
        for group in self.findChildren(QGroupBox, "analyzerSectionGroup"):
            group.setStyleSheet(group_style)
        for group in self.findChildren(QGroupBox, "analyzerMessageSectionGroup"):
            group.setStyleSheet(message_group_style)
        tab_style = (
            f"QTabWidget#analyzerRepeaterTabs::pane{{border:1px solid {card_border};border-radius:0px;background:{card_bg};top:-1px;}}"
            f"QTabWidget#analyzerRepeaterTabs QTabBar::tab{{background:{inner_bg};color:{text_color};border:1px solid {card_border};"
            "border-bottom:none;border-top-left-radius:0px;border-top-right-radius:0px;"
            "padding:7px 12px 7px 12px;margin-right:4px;"
            "min-width:24px;max-width:24px;min-height:24px;max-height:24px;}"
            f"QTabWidget#analyzerRepeaterTabs QTabBar::tab:selected{{background:{card_bg};color:{label_color};font-weight:bold;}}"
            f"QTabWidget#analyzerRepeaterTabs QTabBar::tab:hover{{background:{card_bg};}}"
            "QTabWidget#analyzerRepeaterTabs QTabBar::close-button{subcontrol-origin:margin;subcontrol-position:right;background:transparent;border:none;width:8px;height:8px;margin-right:6px;margin-top:2px;}QTabWidget#analyzerRepeaterTabs QTabBar::close-button:hover{background:transparent;border:none;}"
        )
        self.request_tabs.setStyleSheet(tab_style)
        analyzer_bottom_bar = self.findChild(QFrame, "interceptorBottomBar")
        if analyzer_bottom_bar:
            analyzer_bottom_bar.setStyleSheet(f"QFrame#interceptorBottomBar{{background:{card_bg};border-radius:4px;border:1px solid {card_border};}}")
        if getattr(self, "_analyzer_status_lbl", None):
            self._analyzer_status_lbl.setStyleSheet(f"color:{text_color};font-size:11px;")
        self._set_request_state(self._last_analyzer_state if hasattr(self, "_last_analyzer_state") else "ready")

# ------------------------------------------------------------------------------
# PayloaderPage (Intruder-style dynamic attack runner)
# ------------------------------------------------------------------------------
class IntruderLiveDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Payloader Attack - Live Results")
        self.resize(1100, 700)
        root = QVBoxLayout(self)
        self.summary_lbl = QLabel("Preparing attack...")
        root.addWidget(self.summary_lbl)
        self.results_table = QTableWidget(0, 5)
        self.results_table.setHorizontalHeaderLabels(["#", "Payload", "Status", "Time(ms)", "Bytes"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setSelectionMode(QTableWidget.SingleSelection)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        root.addWidget(self.results_table, 3)
        detail_row = QHBoxLayout()
        self.request_view = QPlainTextEdit()
        self.request_view.setReadOnly(True)
        self.request_view.setFont(QFont("Consolas", 9))
        self.response_view = QPlainTextEdit()
        self.response_view.setReadOnly(True)
        self.response_view.setFont(QFont("Consolas", 9))
        detail_row.addWidget(self.request_view, 1)
        detail_row.addWidget(self.response_view, 1)
        root.addLayout(detail_row, 2)
        self.rows: List[Dict[str, Any]] = []
        self.results_table.itemSelectionChanged.connect(self._on_select)

    def add_progress_row(self, entry: Dict[str, Any]) -> None:
        self.rows.append(entry)
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        response_text = entry.get("response", "") or ""
        self.results_table.setItem(row, 0, QTableWidgetItem(str(entry.get("index", row + 1))))
        self.results_table.setItem(row, 1, QTableWidgetItem(str(entry.get("payload", ""))[:500]))
        self.results_table.setItem(row, 2, QTableWidgetItem(str(entry.get("status", ""))))
        self.results_table.setItem(row, 3, QTableWidgetItem(str(entry.get("elapsed_ms", ""))))
        self.results_table.setItem(row, 4, QTableWidgetItem(str(len(response_text.encode("utf-8", errors="replace")))))
        self.summary_lbl.setText(f"Sent {entry.get('index', 0)}/{entry.get('total', 0)} payloads")
        self.results_table.selectRow(row)

    def _on_select(self) -> None:
        row = self.results_table.currentRow()
        if row < 0 or row >= len(self.rows):
            return
        entry = self.rows[row]
        self.request_view.setPlainText(entry.get("request", ""))
        self.response_view.setPlainText(entry.get("response", ""))


class PayloaderPage(BasePage):
    def __init__(self):
        self.attack_worker: Optional[IntruderAttackWorker] = None
        self.live_dialog: Optional[IntruderLiveDialog] = None
        super().__init__()

    def _setup_base_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.container = QWidget()
        self.container.setObjectName("payloaderPageContainer")
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setSpacing(12)
        self.container_layout.setContentsMargins(16, 16, 16, 16)
        root_layout.addWidget(self.container)

    def _setup_ui(self):
        layout = self.container_layout
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        top_actions = QHBoxLayout()
        self.start_attack_btn = StyledButton("Start Attack")
        self.stop_attack_btn = StyledButton("Stop Attack")
        self.start_attack_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.stop_attack_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.start_attack_btn.setFixedWidth(150)
        self.stop_attack_btn.setFixedWidth(150)
        self.stop_attack_btn.setEnabled(False)
        top_actions.addWidget(self.start_attack_btn)
        top_actions.addWidget(self.stop_attack_btn)
        top_actions.addStretch()
        layout.addLayout(top_actions)

        content_row = QHBoxLayout()
        content_row.setSpacing(10)

        self.request_panel = QFrame()
        self.request_panel.setObjectName("payloaderRequestPanel")
        req_panel_layout = QVBoxLayout(self.request_panel)
        req_panel_layout.setContentsMargins(10, 10, 10, 10)
        req_panel_layout.setSpacing(8)
        marker_row = QHBoxLayout()
        self.mark_btn = StyledButton("Mark Selection")
        self.clear_markers_btn = StyledButton("Clear Markers")
        marker_row.addWidget(self.mark_btn)
        marker_row.addWidget(self.clear_markers_btn)
        marker_row.addStretch()
        req_panel_layout.addLayout(marker_row)
        self.request_template_text = QPlainTextEdit()
        self.request_template_text.setFont(QFont("Consolas", 10))
        self.request_template_text.setPlaceholderText("Paste captured raw request and mark value(s). First marker maps to List 1, second marker maps to List 2.")
        req_panel_layout.addWidget(self.request_template_text, 1)
        content_row.addWidget(self.request_panel, 1)

        self.launch_panel = QFrame()
        self.launch_panel.setObjectName("payloaderLaunchPanel")
        launch_layout = QVBoxLayout(self.launch_panel)
        launch_layout.setContentsMargins(10, 10, 10, 10)
        launch_layout.setSpacing(8)
        launch_title = QLabel("Launch Payloads")
        launch_title.setFont(QFont("Poppins", 14, QFont.Bold))
        launch_layout.addWidget(launch_title)
        self.options_group = QGroupBox("Attack Options")
        opts_layout = QHBoxLayout(self.options_group)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 180)
        self.timeout_spin.setValue(20)
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 10000)
        self.delay_spin.setValue(0)
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(["None", "URL Encoding", "Base64", "HTML Entities"])
        opts_layout.addWidget(QLabel("Timeout (sec)"))
        opts_layout.addWidget(self.timeout_spin)
        opts_layout.addWidget(QLabel("Delay (ms)"))
        opts_layout.addWidget(self.delay_spin)
        opts_layout.addWidget(QLabel("Encode Payload"))
        opts_layout.addWidget(self.encoding_combo)
        launch_layout.addWidget(self.options_group)

        self.list1_label = QLabel("List 1")
        self.list1_label.setFont(QFont("Poppins", 12, QFont.Bold))
        launch_layout.addWidget(self.list1_label)
        self.payload_list1_text = QTextEdit()
        self.payload_list1_text.setPlaceholderText("Manual payloads (one per line) or load from file.")
        launch_layout.addWidget(self.payload_list1_text)
        list1_actions = QHBoxLayout()
        self.load_list1_btn = StyledButton("Load")
        self.clear_list1_btn = StyledButton("Clear")
        list1_actions.addWidget(self.load_list1_btn)
        list1_actions.addWidget(self.clear_list1_btn)
        launch_layout.addLayout(list1_actions)

        self.list2_label = QLabel("List 2")
        self.list2_label.setFont(QFont("Poppins", 12, QFont.Bold))
        launch_layout.addWidget(self.list2_label)
        self.payload_list2_text = QTextEdit()
        self.payload_list2_text.setPlaceholderText("Optional second list for second marker.")
        launch_layout.addWidget(self.payload_list2_text)
        list2_actions = QHBoxLayout()
        self.load_list2_btn = StyledButton("Load")
        self.clear_list2_btn = StyledButton("Clear")
        list2_actions.addWidget(self.load_list2_btn)
        list2_actions.addWidget(self.clear_list2_btn)
        launch_layout.addLayout(list2_actions)
        content_row.addWidget(self.launch_panel, 1)
        layout.addLayout(content_row, 1)

        self.status_lbl = None
        self._set_status("Ready")
        self.mark_btn.clicked.connect(self.mark_selection)
        self.clear_markers_btn.clicked.connect(self.clear_markers)
        self.load_list1_btn.clicked.connect(lambda: self.load_payloads_from_file(1))
        self.load_list2_btn.clicked.connect(lambda: self.load_payloads_from_file(2))
        self.clear_list1_btn.clicked.connect(lambda: self.payload_list1_text.clear())
        self.clear_list2_btn.clicked.connect(lambda: self.payload_list2_text.clear())
        self.start_attack_btn.clicked.connect(self.start_attack)
        self.stop_attack_btn.clicked.connect(self.stop_attack)
        self.request_template_text.textChanged.connect(self._update_list_controls)
        self._update_list_controls()
        self.apply_theme("Dark")

    def load_flow(self, flow: Dict[str, Any]) -> None:
        request = flow.get("request", {}) or {}
        method = request.get("method", "GET")
        url = request.get("url", "")
        headers = request.get("headers", {}) or {}
        body = request.get("body", "") or ""
        lines = [f"{method} {url} HTTP/1.1"]
        if isinstance(headers, dict):
            for key, value in headers.items():
                lines.append(f"{key}: {value}")
        lines.append("")
        if body:
            lines.append(body if isinstance(body, str) else str(body))
        self.request_template_text.setPlainText("\n".join(lines))
        self._set_status("Loaded captured request. Mark insertion point(s) with __PAYLOAD__.")
        self._update_list_controls()

    def mark_selection(self) -> None:
        cursor = self.request_template_text.textCursor()
        selected = cursor.selectedText().replace("\u2029", "\n")
        if not selected:
            QMessageBox.information(self, "Mark Selection", "Select request text to mark as payload position.")
            return
        cursor.insertText(f"__{selected}__")
        self._set_status("Selection marked for payload insertion.")
        self._update_list_controls()

    def clear_markers(self) -> None:
        text = self.request_template_text.toPlainText().replace("§", "").replace("__", "")
        self.request_template_text.setPlainText(text)
        self._set_status("Markers removed.")
        self._update_list_controls()

    def _set_status(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._push_global_status(f"{timestamp} | {message}"[:260])

    def _encode_payload(self, payload: str) -> str:
        mode = self.encoding_combo.currentText()
        if mode == "URL Encoding":
            return urllib.parse.quote(payload, safe="")
        if mode == "Base64":
            return base64.b64encode(payload.encode("utf-8")).decode("ascii")
        if mode == "HTML Entities":
            return payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        return payload

    def _collect_payloads(self, editor: QTextEdit) -> List[str]:
        lines = [ln.strip() for ln in editor.toPlainText().splitlines() if ln.strip()]
        return [self._encode_payload(p) for p in lines]

    def _get_marker_count(self) -> int:
        text = self.request_template_text.toPlainText()
        normalized = text.replace("§PAYLOAD§", "__PAYLOAD__")
        normalized = re.sub(r"§[^§]*§", "__PAYLOAD__", normalized)
        normalized = re.sub(r"__[^_]+__", "__PAYLOAD__", normalized)
        return normalized.count("__PAYLOAD__")

    def _update_list_controls(self) -> None:
        marker_count = self._get_marker_count()
        self.load_list1_btn.setEnabled(marker_count >= 1)
        self.load_list2_btn.setEnabled(marker_count >= 2)
        self.list2_label.setEnabled(marker_count >= 2)
        self.payload_list2_text.setEnabled(marker_count >= 2)
        self.clear_list2_btn.setEnabled(marker_count >= 2)

    def start_attack(self) -> None:
        if self.attack_worker and self.attack_worker.isRunning():
            QMessageBox.information(self, "Payloader", "Attack already running.")
            return
        template = self.request_template_text.toPlainText().strip()
        if not template:
            QMessageBox.warning(self, "Payloader", "Request template is empty.")
            return
        if "__" not in template and "§" not in template:
            QMessageBox.warning(self, "Payloader", "No payload marker found. Use __PAYLOAD__ or Mark Selection.")
            return
        marker_count = self._get_marker_count()
        if marker_count < 1:
            QMessageBox.warning(self, "Payloader", "No payload marker found. Use Mark Selection.")
            return
        payloads_list1 = self._collect_payloads(self.payload_list1_text)
        if not payloads_list1:
            QMessageBox.warning(self, "Payloader", "Add at least one payload manually or via file.")
            return
        payloads_list2 = self._collect_payloads(self.payload_list2_text) if marker_count >= 2 else []
        self.live_dialog = IntruderLiveDialog(self)
        self.live_dialog.show()
        self.attack_worker = IntruderAttackWorker(
            raw_request_template=template,
            payloads=payloads_list1,
            payloads_list2=payloads_list2,
            timeout_secs=self.timeout_spin.value(),
            delay_ms=self.delay_spin.value(),
        )
        self.attack_worker.progress.connect(self._on_attack_progress)
        self.attack_worker.finished_summary.connect(self._on_attack_finished)
        self.attack_worker.start()
        self.start_attack_btn.setEnabled(False)
        self.stop_attack_btn.setEnabled(True)
        total_payloads = len(payloads_list1) * (len(payloads_list2) if payloads_list2 else 1)
        self._set_status(f"Running attack with {total_payloads} payload combinations...")

    def stop_attack(self) -> None:
        if self.attack_worker and self.attack_worker.isRunning():
            self.attack_worker.stop()
            self._set_status("Stopping attack...")

    def _on_attack_progress(self, entry: Dict[str, Any]) -> None:
        if self.live_dialog:
            self.live_dialog.add_progress_row(entry)
        self._set_status(
            f"Sent {entry.get('index', 0)}/{entry.get('total', 0)} | "
            f"status {entry.get('status', '')} | {entry.get('elapsed_ms', 0)} ms"
        )

    def _on_attack_finished(self, summary: Dict[str, Any]) -> None:
        self.start_attack_btn.setEnabled(True)
        self.stop_attack_btn.setEnabled(False)
        sent = summary.get("sent", 0)
        total = summary.get("total", 0)
        stopped = summary.get("stopped", False)
        self._set_status(f"Attack {'stopped' if stopped else 'completed'}: {sent}/{total} payloads sent.")

    def load_payloads_from_file(self, target_list: int) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Payload File",
            "",
            "Text Files (*.txt *.list *.csv *.json);;All Files (*)",
        )
        if not file_path:
            return
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        if target_list == 1:
            self.payload_list1_text.setPlainText(content)
        else:
            self.payload_list2_text.setPlainText(content)
        self._set_status(f"Payloads loaded into List {target_list}.")

    def clear_all(self) -> None:
        self.request_template_text.clear()
        self.payload_list1_text.clear()
        self.payload_list2_text.clear()
        self._set_status("Ready")

    def apply_theme(self, theme_name: str) -> None:
        is_light = theme_name == "Light"
        text_color = "#111827" if is_light else "#f1f5f9"
        label_color = "#6A0DAD" if is_light else "white"
        card_bg = "#FFFFFF" if is_light else "qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855)"
        card_border = "#bdc3c7" if is_light else "#5D2E8C"
        inner_bg = "#FFFFFF" if is_light else "#0f172a"
        muted_text = "#6A0DAD" if is_light else "#94a3b8"
        btn_style = (
            "QPushButton{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;border-radius:6px;font-weight:bold;padding:5px 10px;}"
            "QPushButton:hover{background:#F3E8FF;}"
            "QPushButton:disabled{background:#E5E7EB;color:#9CA3AF;}"
        ) if is_light else (
            "QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:5px 10px;}"
            "QPushButton:hover{background:#7c3aed;}"
            "QPushButton:disabled{background:#374151;color:#9ca3af;}"
        )
        group_style = (
            f"QGroupBox{{background:{card_bg};border:1px solid {card_border};margin-top:8px;padding-top:8px;border-radius:6px;color:{text_color};}}"
            f"QGroupBox::title{{subcontrol-origin: margin;left:8px;padding:0 3px;color:{label_color};}}"
        )
        editor_style = (
            f"QTextEdit,QPlainTextEdit{{background:{inner_bg};color:{text_color};border:1px solid {card_border};border-radius:6px;}}"
        )
        spin_combo_style = (
            f"QSpinBox,QComboBox{{background:{inner_bg};color:{label_color};border:1px solid {card_border};border-radius:4px;padding:4px;}}"
            f"QComboBox QAbstractItemView{{background:{inner_bg};color:{text_color};border:1px solid {card_border};}}"
        )
        bottom_style = f"QFrame#interceptorBottomBar{{background:{card_bg};border-radius:4px;border:1px solid {card_border};}}"

        self.container.setStyleSheet(
            f"QWidget#payloaderPageContainer{{background:transparent;}}"
            f"QFrame#payloaderRequestPanel{{background:{card_bg};border:1px solid {card_border};border-radius:8px;}}"
            f"QFrame#payloaderLaunchPanel{{background:{card_bg};border:1px solid {card_border};border-radius:12px;}}"
            f"{editor_style}"
            f"{group_style}"
            f"QLabel{{color:{text_color};}}"
            f"QLabel#payloaderStatusLabel{{color:{muted_text};}}"
            f"{spin_combo_style}"
            f"{btn_style}"
        )
        bottom_bar = self.findChild(QFrame, "interceptorBottomBar")
        if bottom_bar:
            bottom_bar.setStyleSheet(bottom_style)

# ------------------------------------------------------------------------------
# EncoderDecoderPage (simple mock from int2.py)
# ------------------------------------------------------------------------------
class EncoderDecoderPage(BasePage):
    def __init__(self):
        self.current_theme = "Dark"
        super().__init__()

    def _setup_base_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.container = QWidget()
        self.container.setObjectName("pageContainer")
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setSpacing(8)
        self.container_layout.setContentsMargins(8, 8, 8, 8)
        root_layout.addWidget(self.container)

    def _setup_ui(self):
        layout = self.container_layout
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        self.container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Input section
        self.input_group = QFrame()
        self.input_group.setObjectName("encSection")
        self.input_group.setStyleSheet("QFrame#encSection{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:8px;border:1px solid #5D2E8C;}")
        input_group_layout = QVBoxLayout(self.input_group)
        input_group_layout.setContentsMargins(10, 10, 10, 10)
        self.input_title = QLabel("Input")
        self.input_title.setFont(QFont("Poppins", 11, QFont.Bold))
        self.input_title.setStyleSheet("color:white;")
        input_group_layout.addWidget(self.input_title)
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter input text...")
        self.input_text.setFixedHeight(155)
        self.input_text.setStyleSheet("QTextEdit{background:#0f172a;border:1px solid #334155;border-radius:6px;color:#f1f5f9;}")
        input_group_layout.addWidget(self.input_text)
        self.input_group.setFixedHeight(205)
        layout.addWidget(self.input_group)

        # Controls row
        controls = QHBoxLayout()
        controls.setSpacing(10)
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems([
            "Base64",
            "URL Encoding",
            "HTML Entities",
            "Hex",
            "ROT13",
            "Binary",
            "JWT (no verify)",
            "MD5",
            "SHA-1",
            "SHA-256",
            "SHA-512",
        ])
        self.algorithm_combo.setMinimumHeight(40)
        self.algorithm_combo.setMinimumWidth(260)
        self.algorithm_combo.setMaximumWidth(320)
        controls.addWidget(self.algorithm_combo, 1)

        self.encode_btn = QPushButton("Encode")
        self.encode_btn.setMinimumHeight(40)
        self.encode_btn.setMinimumWidth(150)
        self.encode_btn.clicked.connect(lambda: self.process_text("encode"))
        controls.addWidget(self.encode_btn)

        self.decode_btn = QPushButton("Decode")
        self.decode_btn.setMinimumHeight(40)
        self.decode_btn.setMinimumWidth(150)
        self.decode_btn.clicked.connect(lambda: self.process_text("decode"))
        controls.addWidget(self.decode_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setMinimumHeight(40)
        self.clear_btn.setMinimumWidth(150)
        self.clear_btn.clicked.connect(self.clear_all)
        controls.addWidget(self.clear_btn)
        controls.addStretch(2)
        layout.addLayout(controls)

        # Output section
        self.output_group = QFrame()
        self.output_group.setObjectName("encSection")
        self.output_group.setStyleSheet("QFrame#encSection{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:8px;border:1px solid #5D2E8C;}")
        output_group_layout = QVBoxLayout(self.output_group)
        output_group_layout.setContentsMargins(10, 10, 10, 10)
        self.output_title = QLabel("Output")
        self.output_title.setFont(QFont("Poppins", 11, QFont.Bold))
        self.output_title.setStyleSheet("color:white;")
        output_group_layout.addWidget(self.output_title)
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Output appears here...")
        self.output_text.setFixedHeight(155)
        self.output_text.setStyleSheet("QTextEdit{background:#0f172a;border:1px solid #334155;border-radius:6px;color:#f1f5f9;}")
        output_group_layout.addWidget(self.output_text)
        self.output_group.setFixedHeight(205)
        layout.addWidget(self.output_group)
        self.apply_theme(self.current_theme)

    def process_text(self, mode: str):
        import urllib.parse, html, binascii, json
        text = self.input_text.toPlainText()
        if not text:
            QMessageBox.warning(self, "Input Error", "Enter text first.")
            return
        alg = self.algorithm_combo.currentText()
        try:
            if alg == "Base64":
                result = base64.b64encode(text.encode()).decode() if mode == "encode" else base64.b64decode(text.encode()).decode(errors="replace")
            elif alg == "URL Encoding":
                result = urllib.parse.quote(text, safe="") if mode == "encode" else urllib.parse.unquote(text)
            elif alg == "HTML Entities":
                result = html.escape(text) if mode == "encode" else html.unescape(text)
            elif alg == "Hex":
                result = binascii.hexlify(text.encode()).decode() if mode == "encode" else binascii.unhexlify(text.replace(" ", "").replace("\n", "")).decode(errors="replace")
            elif alg == "ROT13":
                result = text.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
            elif alg == "Binary":
                if mode == "encode":
                    result = " ".join(format(ord(c), "08b") for c in text)
                else:
                    bits = text.replace(" ", "").replace("\n", "")
                    result = "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
            elif alg == "JWT (no verify)":
                if mode == "encode":
                    header = {"alg": "none", "typ": "JWT"}
                    payload = {"data": text}
                    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
                    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
                    result = f"{h}.{p}."
                else:
                    parts = text.strip().split(".")
                    if len(parts) < 2:
                        raise ValueError("Invalid JWT format.")
                    def _b64d(s):
                        s += "=" * (-len(s) % 4)
                        return json.loads(base64.urlsafe_b64decode(s).decode(errors="replace"))
                    result = f"HEADER:\n{json.dumps(_b64d(parts[0]), indent=2)}\n\nPAYLOAD:\n{json.dumps(_b64d(parts[1]), indent=2)}"
            elif alg == "MD5":
                result = hashlib.md5(text.encode()).hexdigest() if mode == "encode" else "MD5 is one-way hash; decoding is not possible."
            elif alg == "SHA-1":
                result = hashlib.sha1(text.encode()).hexdigest() if mode == "encode" else "SHA-1 is one-way hash; decoding is not possible."
            elif alg == "SHA-256":
                result = hashlib.sha256(text.encode()).hexdigest() if mode == "encode" else "SHA-256 is one-way hash; decoding is not possible."
            elif alg == "SHA-512":
                result = hashlib.sha512(text.encode()).hexdigest() if mode == "encode" else "SHA-512 is one-way hash; decoding is not possible."
            else:
                result = text
            self.output_text.setPlainText(result)
        except Exception as e:
            self.output_text.setPlainText(f"Error: {e}")

    def clear_all(self):
        self.input_text.clear()
        self.output_text.clear()

    def apply_theme(self, theme_name):
        self.current_theme = theme_name
        if theme_name == "Light":
            card_bg = "#FFFFFF"
            text = "#6A0DAD"
            border = "#6A0DAD"
            area_bg = "#FFFFFF"
            btn = "QPushButton{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:hover{background:#F3E8FF;}"
            combo = (
                "QComboBox{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;border-radius:6px;padding:6px 10px;font-weight:bold;}"
                "QComboBox QAbstractItemView{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;selection-background-color:#F3E8FF;}"
            )
        else:
            card_bg = "qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855)"
            text = "#FFFFFF"
            border = "#5D2E8C"
            area_bg = "#0f172a"
            btn = "QPushButton{background:#5b21b6;color:white;border:1px solid #5D2E8C;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:hover{background:#7c3aed;}"
            combo = (
                "QComboBox{background:#1e293b;color:#f1f5f9;border:1px solid #5D2E8C;border-radius:6px;padding:6px 10px;font-weight:bold;}"
                "QComboBox QAbstractItemView{background:#1e293b;color:#f1f5f9;border:1px solid #5D2E8C;selection-background-color:#334155;}"
            )

        for sec in self.findChildren(QFrame, "encSection"):
            sec.setStyleSheet(f"QFrame#encSection{{background:{card_bg};border-radius:8px;border:1px solid {border};}}")
        self.input_title.setStyleSheet(f"color:{text};")
        self.output_title.setStyleSheet(f"color:{text};")
        self.input_text.setStyleSheet(f"QTextEdit{{background:{area_bg};border:1px solid {border};border-radius:6px;color:{text};}}")
        self.output_text.setStyleSheet(f"QTextEdit{{background:{area_bg};border:1px solid {border};border-radius:6px;color:{text};}}")
        self.algorithm_combo.setStyleSheet(combo)
        self.encode_btn.setStyleSheet(btn)
        self.decode_btn.setStyleSheet(btn)
        self.clear_btn.setStyleSheet(btn)

# ------------------------------------------------------------------------------
# GuidelinesPage (Tool Manual)
# ------------------------------------------------------------------------------
class GuidelinesPage(BasePage):
    def __init__(self):
        super().__init__()

    def _add_section(self, layout, title, text):
        title_lbl = QLabel(title)
        title_lbl.setFont(QFont("Poppins", 15, QFont.Bold))
        layout.addWidget(title_lbl)
        body_lbl = QLabel(text)
        body_lbl.setWordWrap(True)
        body_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body_lbl.setStyleSheet("line-height: 1.5;")
        layout.addWidget(body_lbl)

    def _setup_ui(self):
        layout = self.container_layout
        header = QLabel("MobHound User Manual")
        header.setProperty("header", "true")
        header.setFont(QFont("Poppins", 18, QFont.Bold))
        layout.addWidget(header)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)

        self._add_section(
            content_layout,
            "1) Overview",
            "MobHound is a mobile security toolkit that combines static analysis, runtime traffic interception, reverse engineering, payload testing, and AI-assisted risk scoring.\n\n"
            "Recommended workflow:\n"
            "1. Start a project from project launcher.\n"
            "2. Use Extractor to inspect APK structure and decompiled code.\n"
            "3. Run Scanner for vulnerability and risk reporting.\n"
            "4. Use Intercepter for live HTTP/HTTPS traffic analysis.\n"
            "5. Use Analyzer and Payloader for request manipulation and attack simulation.\n"
            "6. Use Encoder/Decoder utilities where needed."
        )

        self._add_section(
            content_layout,
            "2) Installation and Setup",
            "Prerequisites:\n"
            "- Python virtual environment with dependencies installed.\n"
            "- Java runtime for JADX/APKTool workflows.\n"
            "- Android SDK platform-tools (`adb`) for device/emulator interaction.\n"
            "- Optional: Frida server/client for runtime instrumentation.\n\n"
            "First-run checks:\n"
            "- Open Extractor and allow tool checks to complete.\n"
            "- Verify APK toolchain status in bottom log/progress area.\n"
            "- Ensure emulator/device is visible with `adb devices` for dynamic features."
        )

        self._add_section(
            content_layout,
            "3) Dashboard Module",
            "Purpose: Global status view for current target, module activity, and recent scan summary.\n"
            "Use it to monitor whether Scanner/Extractor/Intercepter modules are running, completed, failed, or stopped."
        )

        self._add_section(
            content_layout,
            "4) Intercepter Module",
            "Purpose: Capture and inspect app network traffic.\n"
            "Typical use:\n"
            "1. Connect device/emulator and select target package.\n"
            "2. Start interception.\n"
            "3. Review captured requests table.\n"
            "4. Send selected request to Analyzer or Payloader.\n\n"
            "Common issues:\n"
            "- No traffic captured: proxy/certificate not configured in app/device.\n"
            "- Device not listed: `adb` not connected or emulator not running."
        )

        self._add_section(
            content_layout,
            "5) Analyzer Module",
            "Purpose: Inspect and modify captured HTTP requests/responses.\n"
            "Use for replaying requests, changing headers/body, and validating server-side behavior after modifications."
        )

        self._add_section(
            content_layout,
            "6) Payloader Module",
            "Purpose: Perform payload-based testing against selected requests.\n"
            "Use for fuzzing and injection-style test cases with response comparison.\n"
            "Best practice: begin with low-risk payload sets before high-impact payloads."
        )

        self._add_section(
            content_layout,
            "7) Scanner Module",
            "Purpose: Central vulnerability scanner with static + dynamic + AI correlation.\n"
            "Inputs:\n"
            "- APK path and/or reverse engineering artifacts.\n"
            "- Optional dynamic traffic/frida events.\n"
            "Outputs:\n"
            "- JSON, HTML, and PDF reports.\n"
            "- AI risk label with confidence.\n\n"
            "Notes:\n"
            "- `Start Scan` scans selected APK.\n"
            "- Extractor can trigger single-file scan through right-click `Scan File`."
        )

        self._add_section(
            content_layout,
            "8) Extractor Module",
            "Purpose: APK unpacking, file exploration, and decompilation.\n"
            "Features:\n"
            "- Upload and analyze APK archive content.\n"
            "- Decompile code/resources (JADX/APKTool).\n"
            "- Open file previews and pseudo-code view.\n"
            "- Right-click actions for `Download File` and `Scan File`.\n\n"
            "Best practice: run `Unpack File` first, then `Decompile`, then targeted scan."
        )

        self._add_section(
            content_layout,
            "9) Encoder/Decoder Module",
            "Purpose: Utility conversions and hashing helpers.\n"
            "Supports Base64, URL, HTML entities, Hex, Binary, JWT decoding, and common hash generation."
        )

        self._add_section(
            content_layout,
            "10) Error Definitions and Troubleshooting",
            "Project/Workspace errors:\n"
            "- `Project file must use .mh extension`: invalid project file format.\n"
            "- `Missing required project artifact`: opened project archive is incomplete.\n"
            "- `Incompatible project schema version`: project created with incompatible major schema.\n\n"
            "Extractor errors:\n"
            "- `No APK`: no APK selected before action.\n"
            "- `Tools Not Ready`: JADX/APKTool dependencies missing or failed checks.\n"
            "- `Cannot open file`: selected file is unreadable/unsupported encoding/path.\n"
            "- `Scan Setup Error`: single-file scan staging failed (missing source file/zip member).\n\n"
            "Scanner errors:\n"
            "- `Scanner error`: generic scanner pipeline exception; inspect traceback/logs.\n"
            "- `HTML report not found` / `PDF report not found`: scan finished without expected report output.\n"
            "- Low findings unexpectedly: verify input artifacts (jadx dir, manifest, traffic logs).\n\n"
            "Intercepter/Device errors:\n"
            "- Device/emulator not available: `adb` not connected.\n"
            "- No traffic seen: app not using configured proxy or TLS pinning not bypassed.\n\n"
            "AI model errors:\n"
            "- Model load/train fallback may use heuristic mode if sklearn/model files unavailable.\n"
            "- If confidence seems unstable, retrain model and confirm dataset availability in `ai_models/dataset`.\n\n"
            "General resolution steps:\n"
            "1. Re-check selected target APK/package.\n"
            "2. Confirm tool dependencies and emulator/device connectivity.\n"
            "3. Re-run scan and inspect module logs.\n"
            "4. Validate generated files under `projects/<date>/<app>/`."
        )

        self._add_section(
            content_layout,
            "11) Safe Usage and Scope",
            "Use MobHound only on applications and environments you own or are explicitly authorized to test.\n"
            "Always document scope, keep backups, and avoid testing production systems without approval."
        )

        content_layout.addStretch()
        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)

class LogoWidget(QLabel):
    def __init__(self, parent=None):
        super().__init__()
        self.setFixedSize(200,60)
        self.setStyleSheet("QLabel{background-color:#2c3e50;color:white;border-radius:10px;font-size:20px;font-weight:bold;qproperty-alignment:AlignCenter;}")
        self.setText("MOBHOUND")

# ------------------------------------------------------------------------------
# ProjectWorkspaceDialog (from int2.py)
# ------------------------------------------------------------------------------
class ProjectWorkspaceDialog(QDialog):
    def __init__(self, project_manager: ProjectManager, parent=None):
        super().__init__(parent)
        self.project_manager = project_manager
        self.result_session = None
        self.setObjectName("ProjectWorkspaceDialog")
        self.setWindowTitle("MobHound Project Launcher")
        launcher_icon_path = ICONS_DIR / "mobhound1.png"
        if launcher_icon_path.exists():
            self.setWindowIcon(QIcon(str(launcher_icon_path)))
        self.setModal(True)
        self.setFixedSize(840,560)
        self._setup_ui()
        self._load_recent()
    def _setup_ui(self):
        check_icon_path = (ICONS_DIR / "mobhound_check_purple.svg").as_posix()
        dialog_css = """
            QDialog#ProjectWorkspaceDialog{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);color:white;font-family:"Poppins";}
            QDialog#ProjectWorkspaceDialog QLabel,QDialog#ProjectWorkspaceDialog QCheckBox,QDialog#ProjectWorkspaceDialog QGroupBox{color:white;font-family:"Poppins";}
            QCheckBox::indicator{width:16px;height:16px;border-radius:4px;border:1px solid #ffffff;background:#ffffff;}
            QCheckBox::indicator:checked{background:#ffffff;border:2px solid #6E1BC2;/* checkmark */}
            QLineEdit{background-color:rgba(255,255,255,0.1);color:white;border:1px solid #6E1BC2;border-radius:6px;padding:6px;font-family:"Poppins";}
            QTableWidget#recentProjectsTable{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);color:white;border:1px solid #6E1BC2;gridline-color:#6E1BC2;border-radius:6px;}
            QTableWidget#recentProjectsTable::item{background:transparent;color:white;}
            QTableWidget::item:selected{background-color:rgba(255,255,255,0.2);color:white;}
            QHeaderView::section{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);color:#ffffff;border:1px solid #6E1BC2;padding:4px;font-family:"Poppins";font-weight:600;}
            QPushButton{background-color:rgba(255,255,255,0.12);color:white;border:1px solid #6E1BC2;border-radius:6px;padding:6px 10px;font-family:"Poppins";}
            QPushButton:hover{background-color:rgba(255,255,255,0.2);}
        """
        self.setStyleSheet(dialog_css.replace("__CHECK_ICON_PATH__", check_icon_path))
        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(0)
        center_wrap = QWidget()
        center_row = QHBoxLayout(center_wrap)
        center_row.setContentsMargins(0, 0, 0, 0)
        center_row.setSpacing(10)
        logo = QLabel()
        logo_path = ICONS_DIR / "mobhound1.png"
        if logo_path.exists():
            logo.setPixmap(QPixmap(str(logo_path)).scaled(44,44,Qt.KeepAspectRatio,Qt.SmoothTransformation))
        title = QLabel("MobHound")
        title.setFont(QFont("Poppins", 22, QFont.Black))
        title.setStyleSheet("color:white;letter-spacing:2px;")
        center_row.addWidget(logo)
        center_row.addWidget(title)
        subtitle = QLabel("Mobile Application Testing Tool  |  Project Workspace")
        subtitle.setFont(QFont("Poppins", 10))
        subtitle.setStyleSheet("color:rgba(196,181,253,0.9);")
        left = QVBoxLayout()
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(4)
        left.addWidget(center_wrap, 0, Qt.AlignHCenter)
        left.addWidget(subtitle)
        left.setAlignment(subtitle, Qt.AlignHCenter)
        header.addStretch(1)
        header.addLayout(left)
        header.addStretch(1)
        layout.addLayout(header)
        self.temp_radio = QCheckBox("Temporary project")
        self.temp_radio.setChecked(True)
        self.enable_new_project_cb = QCheckBox(f"Enable new project on disk ({PROJECT_EXTENSION})")
        self.enable_new_project_cb.setChecked(False)
        self.open_radio = QCheckBox("Open existing project")
        for cb in (self.temp_radio, self.enable_new_project_cb, self.open_radio):
            cb.clicked.connect(lambda _,c=cb: self._select_mode(c))
        layout.addWidget(self.temp_radio)
        layout.addWidget(self.enable_new_project_cb)
        new_group = QGroupBox("New Project")
        new_layout = QFormLayout(new_group)
        self.new_name = QLineEdit()
        self.new_name.setPlaceholderText("Project Name")
        self.new_file = QLineEdit()
        self.new_file.setPlaceholderText(f"C:/path/project{PROJECT_EXTENSION}")
        browse_new_action = self.new_file.addAction(self.style().standardIcon(QStyle.SP_DirOpenIcon),QLineEdit.TrailingPosition)
        browse_new_action.triggered.connect(self._browse_new_file)
        new_file_row = QHBoxLayout(); new_file_row.setContentsMargins(0,0,0,0); new_file_row.addWidget(self.new_file)
        file_wrap = QWidget(); file_wrap.setLayout(new_file_row)
        new_layout.addRow("Name:", self.new_name)
        new_layout.addRow("File:", file_wrap)
        layout.addWidget(new_group)
        layout.addWidget(self.open_radio)
        self.recent_table = QTableWidget(0,2)
        self.recent_table.setObjectName("recentProjectsTable")
        self.recent_table.setHorizontalHeaderLabels(["Name","File"])
        self.recent_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeToContents)
        self.recent_table.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.recent_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.recent_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.recent_table)
        open_row = QHBoxLayout()
        self.open_file = QLineEdit()
        self.open_file.setPlaceholderText(f"C:/path/project{PROJECT_EXTENSION}")
        browse_open_action = self.open_file.addAction(self.style().standardIcon(QStyle.SP_DirOpenIcon),QLineEdit.TrailingPosition)
        browse_open_action.triggered.connect(self._browse_open_file)
        open_row.setContentsMargins(0,0,0,0); open_row.addWidget(self.open_file)
        open_wrap = QWidget(); open_wrap.setLayout(open_row)
        layout.addWidget(open_wrap)
        buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._toggle_groups()
    def _select_mode(self, selected):
        for cb in (self.temp_radio, self.enable_new_project_cb, self.open_radio):
            cb.setChecked(cb is selected)
        self._toggle_groups()
    def _toggle_groups(self):
        new_enabled = self.enable_new_project_cb.isChecked()
        open_enabled = self.open_radio.isChecked()
        self.new_name.setEnabled(new_enabled)
        self.new_file.setEnabled(new_enabled)
        self.open_file.setEnabled(open_enabled)
        self.recent_table.setEnabled(open_enabled)
    def _browse_new_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Project", "", f"MobHound Project (*{PROJECT_EXTENSION})")
        if path:
            if not path.lower().endswith(PROJECT_EXTENSION): path += PROJECT_EXTENSION
            self.new_file.setText(path)
    def _browse_open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Project", "", f"MobHound Project (*{PROJECT_EXTENSION})")
        if path:
            self.open_file.setText(path)
    def _load_recent(self):
        recent = self.project_manager.list_recent_projects()
        self.recent_table.setRowCount(0)
        for item in recent:
            row = self.recent_table.rowCount()
            self.recent_table.insertRow(row)
            self.recent_table.setItem(row,0,QTableWidgetItem(item.get("name","")))
            self.recent_table.setItem(row,1,QTableWidgetItem(item.get("path","")))
        self.recent_table.itemSelectionChanged.connect(self._select_recent_file)
    def _select_recent_file(self):
        row = self.recent_table.currentRow()
        if row>=0:
            item = self.recent_table.item(row,1)
            if item: self.open_file.setText(item.text())
    def _on_accept(self):
        try:
            if self.temp_radio.isChecked():
                self.result_session = self.project_manager.create_project("Temporary Project", temporary=True)
            elif self.enable_new_project_cb.isChecked():
                name = self.new_name.text().strip()
                file_path = self.new_file.text().strip()
                if not name or not file_path: raise ValueError("Project name and file path required.")
                self.result_session = self.project_manager.create_project(name, Path(file_path), temporary=False)
            else:
                file_path = self.open_file.text().strip()
                if not file_path: raise ValueError("Select a project file.")
                self.result_session = self.project_manager.open_project(Path(file_path))
            self.accept()
        except Exception as exc:
            QMessageBox.critical(self, "Project Error", str(exc))

# ------------------------------------------------------------------------------
# MobHoundScannerThread (from int.py)
# ------------------------------------------------------------------------------
class MobHoundScannerThread(QThread):
    progress_update = Signal(int, str)
    scan_complete   = Signal(object)
    scan_error      = Signal(str)

    def __init__(self, apk_path="", project_dir="", jadx_dir="", manifest_path="", scan_config: Optional[Dict[str, bool]] = None, parent=None):
        super().__init__(parent)
        self._apk       = apk_path
        self._proj      = project_dir
        self._jadx      = jadx_dir
        self._manifest  = manifest_path
        self._scan_config = scan_config or {}
        self._current_pct = 5

    def _emit_progress(self, pct: int, message: str) -> None:
        self._current_pct = pct
        self.progress_update.emit(pct, message)

    def run(self):
        import sys, os, traceback, logging, shutil
        from pathlib import Path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        class _ScannerUILogHandler(logging.Handler):
            def __init__(self, thread):
                super().__init__(logging.INFO)
                self.thread = thread
            def emit(self, record):
                try:
                    msg = self.format(record)
                    self.thread.progress_update.emit(self.thread._current_pct, msg)
                except Exception:
                    pass
        ui_log_handler = _ScannerUILogHandler(self)
        ui_log_handler.setFormatter(logging.Formatter("%(message)s"))
        scanner_logger = logging.getLogger("mobhound.scanner")
        mobhound_logger = logging.getLogger("mobhound")
        old_scanner_level = scanner_logger.level
        old_mobhound_level = mobhound_logger.level
        scanner_logger.setLevel(logging.INFO)
        mobhound_logger.setLevel(logging.INFO)
        scanner_logger.addHandler(ui_log_handler)
        try:
            self._emit_progress(5, "Initializing MobHound scanner...")
            from scanner.module import ScannerModule
            proj = Path(self._proj)
            scanner = ScannerModule(project_dir=proj)

            self._emit_progress(15, "Locating JADX output and manifest...")
            jadx = None; mfest = None
            apk = self._apk
            if not apk:
                apks = list((proj / "apk").glob("*.apk"))
                apk = str(apks[0]) if apks else str(proj)

            if self._jadx and Path(self._jadx).exists():
                jadx = Path(self._jadx)
            if self._manifest and Path(self._manifest).exists():
                mfest = Path(self._manifest)

            if jadx is None:
                apk_stem = Path(apk).stem
                search_dirs = [proj / "jadx_source" / "sources", proj / "jadx_output" / "sources", proj / "reverse_engineering"]
                for date_dir in Path("projects").glob("*/"):
                    for sub in date_dir.glob("*/jadx_source/sources"):
                        if apk_stem.lower() in str(sub).lower() or sub.parent.parent.name.lower() in apk_stem.lower():
                            search_dirs.insert(0, sub)
                for d in search_dirs:
                    if d.exists() and any(d.rglob("*.java")):
                        jadx = d
                        self._emit_progress(20, f"Found JADX output: {d.name}")
                        break

            if mfest is None:
                manifest_candidates = [proj / "apktool_resources" / "AndroidManifest.xml",
                                       proj / "jadx_source" / "resources" / "AndroidManifest.xml",
                                       proj / "jadx_output" / "resources" / "AndroidManifest.xml"]
                for date_dir in Path("projects").glob("*/"):
                    for m in date_dir.glob("*/apktool_resources/AndroidManifest.xml"):
                        if Path(apk).stem.lower() in str(m).lower() or True:
                            manifest_candidates.insert(0, m)
                            break
                for m in manifest_candidates:
                    if m.exists():
                        mfest = m
                        break

            self._emit_progress(28, "Analyzing AndroidManifest.xml...")
            self._emit_progress(42, "Scanning source code for vulnerabilities...")
            self._emit_progress(58, "Running crypto & auth detectors...")
            self._emit_progress(70, "Running malware behavioral analysis...")
            self._emit_progress(80, "Running AI risk classification...")

            result = scanner.run(
                apk_path=apk,
                jadx_dir=jadx,
                manifest_path=mfest,
                manifest_data={"dangerous_permission_count": 8, "exported_component_count": 6,
                               "debuggable": False, "backup_enabled": True},
                scan_config=self._scan_config,
            )
            self._emit_progress(92, "Generating HTML + PDF + JSON reports...")
            n = len(result.findings)
            self._emit_progress(100, f"Done! {n} findings | {result.ai_risk_label} | {result.ai_confidence:.0%}")
            self.scan_complete.emit(result)
        except Exception as e:
            self.scan_error.emit(f"Scanner error:\n{str(e)}\n\n{traceback.format_exc()}")
        finally:
            scanner_logger.removeHandler(ui_log_handler)
            scanner_logger.setLevel(old_scanner_level)
            mobhound_logger.setLevel(old_mobhound_level)

# ------------------------------------------------------------------------------
# ENHANCED ScannerPage (from int.py) - merged
# ------------------------------------------------------------------------------
class ScannerPage(BasePage):
    module_status_changed = Signal(str, str, str)
    scan_completed = Signal(dict)

    def __init__(self):
        self.projects = MOCK_PROJECTS.copy()
        self._apk_path = ""
        self._scan_thread = None
        self._scanner_thread = None
        self._scan_result = None
        self.current_theme = "Dark"
        self.last_log = ""
        super().__init__()

    def _setup_base_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.container = QWidget()
        self.container.setObjectName("pageContainer")
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setSpacing(10)
        self.container_layout.setContentsMargins(10, 10, 10, 10)
        root_layout.addWidget(self.container)

    def _setup_ui(self):
        layout = self.container_layout
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        self.container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Toolbar row
        toolbar = QHBoxLayout()
        toolbar.setSpacing(12)
        self._upload_btn = QPushButton("Upload File")
        self._upload_btn.setMinimumHeight(36)
        self._upload_btn.clicked.connect(self._browse_apk)
        self._upload_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:hover{background:#7c3aed;}")
        toolbar.addWidget(self._upload_btn)

        self._scan_btn = QPushButton("Start Scan")
        self._scan_btn.setMinimumHeight(36)
        self._scan_btn.setEnabled(False)
        self._scan_btn.clicked.connect(self._start_scan)
        self._scan_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#7c3aed;}")
        toolbar.addWidget(self._scan_btn)

        self._stop_btn = QPushButton("Stop Scan")
        self._stop_btn.setMinimumHeight(36)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_scan)
        self._stop_btn.setStyleSheet("QPushButton{background:#b91c1c;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#dc2626;}")
        toolbar.addWidget(self._stop_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Main content
        main_row = QHBoxLayout()
        main_row.setSpacing(10)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)

        owasp_group = QFrame()
        owasp_group.setObjectName("scannerLeftGroup")
        owasp_group.setStyleSheet("QFrame#scannerLeftGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:8px;border:1px solid #5D2E8C;}")
        owasp_lay = QVBoxLayout(owasp_group)
        self.owasp_title = QLabel("OWASP Top 10 Checks")
        self.owasp_title.setFont(QFont("Poppins", 11, QFont.Bold))
        self.owasp_title.setStyleSheet("color:white;")
        owasp_lay.addWidget(self.owasp_title)
        self._owasp_checks = {}
        checks = [("M1","M1: Improper Platform Usage"),("M2","M2: Insecure Data Storage"),("M3","M3: Insecure Communication"),
                  ("M4","M4: Insufficient Authentication"),("M5","M5: Insufficient Cryptography"),("M6","M6: Insecure Authorization"),
                  ("M7","M7: Client Code Quality"),("M8","M8: Code Tampering"),("M9","M9: Reverse Engineering"),("M10","M10: Extraneous Functionality")]
        for key,label in checks:
            cb = QCheckBox(label)
            cb.setChecked(True)
            owasp_lay.addWidget(cb)
            self._owasp_checks[key] = cb
        left_layout.addWidget(owasp_group, stretch=1)
        owasp_group.setMaximumHeight(320)

        opts_group = QFrame()
        opts_group.setObjectName("scannerLeftGroup")
        opts_group.setStyleSheet("QFrame#scannerLeftGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:8px;border:1px solid #5D2E8C;}")
        opts_lay = QVBoxLayout(opts_group)
        self.opts_title = QLabel("Scan Options")
        self.opts_title.setFont(QFont("Poppins", 11, QFont.Bold))
        self.opts_title.setStyleSheet("color:white;")
        opts_lay.addWidget(self.opts_title)
        self._static_cb  = QCheckBox("Static Analysis (Source Code)"); self._static_cb.setChecked(True)
        self._ai_cb      = QCheckBox("AI Risk Classification");         self._ai_cb.setChecked(True)
        self._secrets_cb = QCheckBox("Secrets & Credentials Detection"); self._secrets_cb.setChecked(True)
        self._crypto_cb  = QCheckBox("Cryptography Analysis");          self._crypto_cb.setChecked(True)
        self._malware_cb = QCheckBox("Malware Behavioral Analysis");    self._malware_cb.setChecked(True)
        for w in (self._static_cb, self._ai_cb, self._secrets_cb, self._crypto_cb, self._malware_cb):
            opts_lay.addWidget(w)
        opts_lay.addStretch()
        left_layout.addWidget(opts_group, stretch=1)
        opts_group.setMaximumHeight(230)
        main_row.addWidget(left_panel)
        left_panel.setFixedWidth(320)

        center_group = QFrame()
        center_group.setObjectName("scannerCenterGroup")
        center_group.setStyleSheet("QFrame#scannerCenterGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:8px;border:1px solid #5D2E8C;}")
        center_layout = QVBoxLayout(center_group)
        center_layout.setContentsMargins(8, 8, 8, 8)
        center_layout.setSpacing(8)

        header_row = QHBoxLayout()
        self._apk_label = QLabel("File Name")
        self._apk_label.setStyleSheet("background:#0f172a;border:1px solid #334155;border-radius:4px;color:#f1f5f9;padding:7px 10px;font-weight:bold;")
        header_row.addWidget(self._apk_label, 1)
        header_row.addSpacing(12)

        self._report_btn = QToolButton()
        self._report_btn.setText("Generate Report")
        self._report_btn.setIcon(QIcon(str((ICONS_DIR / "chevron_down_white.svg").resolve())))
        self._report_btn.setIconSize(QSize(14, 14))
        self._report_btn.setEnabled(False)
        self._report_btn.setPopupMode(QToolButton.InstantPopup)
        self._report_btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self._report_btn.setArrowType(Qt.NoArrow)
        self._report_btn.setMinimumWidth(250)
        self._report_btn.setStyleSheet(
            "QToolButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;font-size:16px;padding:8px 22px;text-align:center;}"
            "QToolButton::menu-indicator{image:none;width:0px;}"
            "QToolButton:disabled{background:#374151;color:#9ca3af;}"
            "QToolButton:hover:!disabled{background:#7c3aed;}"
        )
        report_menu = QMenu(self)
        self._report_html_action = report_menu.addAction("HTML Report")
        self._report_pdf_action = report_menu.addAction("PDF Report")
        self._report_html_action.triggered.connect(self._open_html)
        self._report_pdf_action.triggered.connect(self._open_pdf)
        self._report_btn.setMenu(report_menu)
        header_row.addWidget(self._report_btn)
        center_layout.addLayout(header_row)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["No.","Severity","Description","Category","Confidence"])
        self.results_table.horizontalHeader().setSectionResizeMode(2,QHeaderView.Stretch)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.cellDoubleClicked.connect(self._show_detail)
        self.results_table.setStyleSheet("QTableWidget{background:#0f172a;border:1px solid #334155;color:#f1f5f9;gridline-color:#334155;}QTableWidget::item:selected{background:#334155;}QHeaderView::section{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:6px;font-weight:bold;}")
        self.results_table.setMinimumHeight(240)
        center_layout.addWidget(self.results_table, stretch=1)
        main_row.addWidget(center_group, stretch=1)
        layout.addLayout(main_row, stretch=1)

        self._status_lbl = None
        self._progress_label = None
        self._progress = None
        self._scanner_progress_value = 0
        self._scanner_progress_text = "Progress: 00%"
        self._push_global_status("Logs", progress_value=0, progress_text=self._scanner_progress_text)
        self.apply_theme(self.current_theme)

    def _browse_apk(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select APK File", "", "APK Files (*.apk);;All Files (*)")
        if path:
            self._apk_path = path
            name = Path(path).name
            self._apk_label.setText(name)
            self._scan_btn.setEnabled(True)
            self._log(f"Loaded APK: {name}")

    def _scanner_scan_config(self) -> Dict[str, bool]:
        return {
            "run_static_engine": self._static_cb.isChecked(),
            "run_ai_engine": self._ai_cb.isChecked(),
            "run_secret_detector": self._secrets_cb.isChecked(),
            "run_crypto_detector": self._crypto_cb.isChecked(),
            "run_malware_engine": self._malware_cb.isChecked(),
        }

    def _start_scan(self):
        if not self._apk_path:
            QMessageBox.warning(self, "No APK", "Please select an APK file first.")
            return
        import time
        stem = Path(self._apk_path).stem
        proj_dir = str(Path("projects") / time.strftime("%Y%m%d") / stem)
        Path(proj_dir).mkdir(parents=True, exist_ok=True)
        apk_dest = Path(proj_dir) / "apk" / Path(self._apk_path).name
        apk_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self._apk_path, apk_dest)
        self._scan_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._report_btn.setEnabled(False)
        self.results_table.setRowCount(0)
        self._set_progress(5, "Progress: 5%")
        self._log("Starting APK security scan...")
        self.module_status_changed.emit("Scanner", "running", os.path.basename(self._apk_path))
        self._scanner_thread = MobHoundScannerThread(
            apk_path=str(apk_dest),
            project_dir=proj_dir,
            scan_config=self._scanner_scan_config(),
        )
        self._scanner_thread.progress_update.connect(self._on_progress)
        self._scanner_thread.scan_complete.connect(self._on_complete)
        self._scanner_thread.scan_error.connect(self._on_error)
        self._scanner_thread.start()

    def start_scan_from_extractor(self, apk_path: str, project_dir: str, jadx_dir: str = "", manifest_path: str = "", display_name: str = ""):
        if not apk_path:
            QMessageBox.warning(self, "No APK", "Extractor did not provide an APK path.")
            return
        self._apk_path = apk_path
        self._apk_label.setText(display_name or Path(apk_path).name)
        Path(project_dir).mkdir(parents=True, exist_ok=True)
        self._scan_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._report_btn.setEnabled(False)
        self.results_table.setRowCount(0)
        self._set_progress(5, "Progress: 5%")
        self._log("Starting scan from Extractor selection...")
        self.module_status_changed.emit("Scanner", "running", os.path.basename(self._apk_path))
        self._scanner_thread = MobHoundScannerThread(
            apk_path=apk_path,
            project_dir=project_dir,
            jadx_dir=jadx_dir,
            manifest_path=manifest_path,
            scan_config=self._scanner_scan_config(),
        )
        self._scanner_thread.progress_update.connect(self._on_progress)
        self._scanner_thread.scan_complete.connect(self._on_complete)
        self._scanner_thread.scan_error.connect(self._on_error)
        self._scanner_thread.start()

    def _on_progress(self, pct, msg):
        self._set_progress(pct, f"Progress: {pct}%")
        self._log(msg)
        QApplication.processEvents()

    def _on_complete(self, result):
        self._scan_result = result
        self._set_progress(100, "Progress: 100%")
        self._scan_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._report_btn.setEnabled(True)
        self._log(f"Scan complete: {len(result.findings)} findings | AI Risk: {result.ai_risk_label} | Confidence: {result.ai_confidence:.0%}")
        by_sev = result.findings_by_severity()
        scan_result_dict = {
            "findings": len(result.findings),
            "critical": len(by_sev.get("CRITICAL", [])),
            "high": len(by_sev.get("HIGH", [])),
            "medium": len(by_sev.get("MEDIUM", [])),
            "low": len(by_sev.get("LOW", [])),
            "ai_risk": result.ai_risk_label,
            "ai_confidence": result.ai_confidence
        }
        self.scan_completed.emit(scan_result_dict)
        self.module_status_changed.emit("Scanner", "completed", os.path.basename(self._apk_path))
        sev_c = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#2563eb","INFO":"#6b7280"}
        from PySide6.QtGui import QColor
        self.results_table.setRowCount(len(result.findings))
        for i, f in enumerate(result.findings):
            sv = f.severity.value
            c = sev_c.get(sv, "#6b7280")
            ni = QTableWidgetItem(str(i+1)); ni.setTextAlignment(Qt.AlignCenter)
            si = QTableWidgetItem(f"  {sv}  ")
            if self.current_theme == "Light":
                si.setForeground(QColor("#111827"))
            else:
                si.setForeground(Qt.white)
            si.setBackground(QColor(c))
            si.setTextAlignment(Qt.AlignCenter); si.setFont(QFont("Poppins",8,QFont.Bold))
            ti = QTableWidgetItem(f.title)
            ca = QTableWidgetItem(f.category)
            co = QTableWidgetItem(f"{int(f.confidence*100)}%"); co.setTextAlignment(Qt.AlignCenter)
            self.results_table.setItem(i,0,ni)
            self.results_table.setItem(i,1,si)
            self.results_table.setItem(i,2,ti)
            self.results_table.setItem(i,3,ca)
            self.results_table.setItem(i,4,co)
        QMessageBox.information(self, "Scan Complete", f"MobHound scan finished!\n\nTotal Findings: {len(result.findings)}\nAI Risk: {result.ai_risk_label} ({result.ai_confidence:.0%})")
    def _on_error(self, error):
        self._stop_btn.setEnabled(False)
        self._scan_btn.setEnabled(True)
        self._set_progress(None, "Progress: Failed")
        self._log("Scan failed.")
        self.module_status_changed.emit("Scanner", "failed", os.path.basename(self._apk_path) if self._apk_path else "")
        QMessageBox.critical(self, "Scan Error", f"Scanner error:\n\n{error[:500]}")

    def _stop_scan(self):
        if self._scanner_thread and self._scanner_thread.isRunning():
            self._scanner_thread.terminate()
            self._scanner_thread.wait(2000)
            self._log("Scan stopped by user.")
        if self._scan_result:
            by_sev = self._scan_result.findings_by_severity()
            self.scan_completed.emit({
                "findings": len(self._scan_result.findings),
                "critical": len(by_sev.get("CRITICAL", [])),
                "high": len(by_sev.get("HIGH", [])),
                "medium": len(by_sev.get("MEDIUM", [])),
                "low": len(by_sev.get("LOW", [])),
                "ai_risk": self._scan_result.ai_risk_label,
                "ai_confidence": self._scan_result.ai_confidence
            })
        self.module_status_changed.emit("Scanner", "stopped", os.path.basename(self._apk_path) if self._apk_path else "")
        self._stop_btn.setEnabled(False)
        self._scan_btn.setEnabled(bool(self._apk_path))
        self._set_progress(0, "Progress: Stopped")

    def _log(self, message: str):
        self.last_log = message
        if self._status_lbl:
            self._status_lbl.setText(message[:220])
        self._push_global_status(message[:220], progress_value=self._scanner_progress_value, progress_text=self._scanner_progress_text)

    def _set_progress(self, value: Optional[int], text: str) -> None:
        self._scanner_progress_value = value
        self._scanner_progress_text = text
        if self._progress:
            self._progress.setValue(value or 0)
        if self._progress_label:
            self._progress_label.setText(text)
        self._push_global_status(getattr(self, "last_log", "Logs"), progress_value=value, progress_text=text)
    def _show_detail(self, row, col):
        if not self._scan_result or row >= len(self._scan_result.findings): return
        f = self._scan_result.findings[row]
        msg = QMessageBox(self)
        msg.setWindowTitle(f.title[:80])
        msg.setText(f"Severity: {f.severity.value}  |  Confidence: {f.confidence:.0%}\nCWE: {f.cwe_id or 'N/A'}\nOWASP: {f.owasp_mobile or 'N/A'}\n\nDescription:\n{f.description}\n\nRecommendation:\n{f.recommendation}\n\nEvidence:\n" + "\n".join(f.evidence[:4]))
        msg.setStyleSheet("QLabel{color:#f1f5f9;min-width:600px;}QMessageBox{background:#1e293b;}")
        msg.exec()
    def _open_html(self):
        rpts = sorted(glob.glob("projects/**/reports/*.html", recursive=True), key=os.path.getmtime)
        if rpts: import webbrowser; webbrowser.open(f"file:///{os.path.abspath(rpts[-1])}")
        else: QMessageBox.warning(self, "Not Found", "HTML report not found.")
    def _open_pdf(self):
        rpts = sorted(glob.glob("projects/**/reports/*.pdf", recursive=True), key=os.path.getmtime)
        if rpts: os.startfile(os.path.abspath(rpts[-1]))
        else: QMessageBox.warning(self, "Not Found", "PDF report not found.")

    def apply_theme(self, theme_name):
        self.current_theme = theme_name
        check_icon = str((ICONS_DIR / "checkmark_white.svg").resolve()).replace("\\", "/")
        chevron_icon = "chevron_down_purple.svg" if theme_name == "Light" else "chevron_down_white.svg"
        self._report_btn.setIcon(QIcon(str((ICONS_DIR / chevron_icon).resolve())))
        is_light = (theme_name == "Light")
        text_color = "#111827" if is_light else "#f1f5f9"
        card_bg = "#FFFFFF" if is_light else "qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855)"
        card_border = "#bdc3c7" if is_light else "#5D2E8C"
        inner_bg = "#ffffff" if is_light else "#0f172a"
        header_bg = "#e5e7eb" if is_light else "#1e293b"
        header_text = "#111827" if is_light else "#94a3b8"

        for group in self.findChildren(QFrame, "scannerLeftGroup"):
            group.setStyleSheet(f"QFrame#scannerLeftGroup{{background:{card_bg};border-radius:8px;border:1px solid {card_border};}}")
        center_group = self.findChild(QFrame, "scannerCenterGroup")
        if center_group:
            center_group.setStyleSheet(f"QFrame#scannerCenterGroup{{background:{card_bg};border-radius:8px;border:1px solid {card_border};}}")
        bottom_bar = self.findChild(QFrame, "scannerBottomBar")
        if bottom_bar:
            bottom_bar.setStyleSheet(f"QFrame#scannerBottomBar{{background:{card_bg};border-radius:4px;border:1px solid {card_border};}}")
        interceptor_bottom_bar = self.findChild(QFrame, "interceptorBottomBar")
        if interceptor_bottom_bar:
            interceptor_bottom_bar.setStyleSheet(f"QFrame#interceptorBottomBar{{background:{card_bg};border-radius:4px;border:1px solid {card_border};}}")

        self._apk_label.setStyleSheet(f"background:{inner_bg};border:1px solid #334155;border-radius:4px;color:{text_color};padding:7px 10px;font-weight:bold;")
        self.results_table.setStyleSheet(
            f"QTableWidget{{background:{inner_bg};border:1px solid #334155;color:{text_color};gridline-color:#334155;}}"
            "QTableWidget::item:selected{background:#334155;color:#f8fafc;}"
            f"QHeaderView::section{{background:{header_bg};color:{header_text};border:1px solid #334155;padding:6px;font-weight:bold;}}"
        )
        if self._status_lbl:
            self._status_lbl.setStyleSheet(f"color:{text_color};font-size:11px;")
        if self._progress_label:
            self._progress_label.setStyleSheet(f"color:{text_color};font-size:11px;")
        if is_light:
            btn_css = "QPushButton{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:hover{background:#F3E8FF;}"
            scan_css = "QPushButton{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#F3E8FF;color:#A78BFA;border:1px solid #A78BFA;}QPushButton:hover:!disabled{background:#F3E8FF;}"
            self._upload_btn.setStyleSheet(btn_css)
            self._scan_btn.setStyleSheet(scan_css)
            self._stop_btn.setStyleSheet(scan_css)
            if hasattr(self, "owasp_title"):
                self.owasp_title.setStyleSheet("color:#6A0DAD;")
            if hasattr(self, "opts_title"):
                self.opts_title.setStyleSheet("color:#6A0DAD;")
            cb_css = (
                "QCheckBox{color:#6A0DAD;background:transparent;spacing:8px;padding:1px 0px;}"
                "QCheckBox::indicator{width:16px;height:16px;border-radius:3px;border:2px solid #6A0DAD;background:#FFFFFF;}"
                f"QCheckBox::indicator:checked{{background:#6A0DAD;border:2px solid #6A0DAD;}}"
            )
            for cb in list(self._owasp_checks.values()) + [self._static_cb, self._ai_cb, self._secrets_cb, self._crypto_cb, self._malware_cb]:
                cb.setStyleSheet(cb_css)
            self._report_btn.setStyleSheet(
                "QToolButton{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;border-radius:6px;font-weight:bold;font-size:16px;padding:8px 22px;text-align:center;}"
                "QToolButton::menu-indicator{image:none;width:0px;}"
                "QToolButton:disabled{background:#F3E8FF;color:#A78BFA;border:1px solid #A78BFA;}"
                "QToolButton:hover:!disabled{background:#F3E8FF;}"
            )
        else:
            self._upload_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:hover{background:#7c3aed;}")
            self._scan_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#7c3aed;}")
            self._stop_btn.setStyleSheet("QPushButton{background:#b91c1c;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#dc2626;}")
            if hasattr(self, "owasp_title"):
                self.owasp_title.setStyleSheet("color:white;")
            if hasattr(self, "opts_title"):
                self.opts_title.setStyleSheet("color:white;")
            cb_css = (
                "QCheckBox{color:#f1f5f9;background:transparent;spacing:8px;padding:1px 0px;}"
                "QCheckBox::indicator{width:16px;height:16px;border-radius:3px;border:2px solid #cbd5e1;background:#0f172a;}"
                f"QCheckBox::indicator:checked{{background:#7c3aed;border:2px solid #7c3aed;}}"
            )
            for cb in list(self._owasp_checks.values()) + [self._static_cb, self._ai_cb, self._secrets_cb, self._crypto_cb, self._malware_cb]:
                cb.setStyleSheet(cb_css)
            self._report_btn.setStyleSheet(
                "QToolButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;font-size:16px;padding:8px 22px;text-align:center;}"
                "QToolButton::menu-indicator{image:none;width:0px;}"
                "QToolButton:disabled{background:#374151;color:#9ca3af;}"
                "QToolButton:hover:!disabled{background:#7c3aed;}"
            )

# =============================================================================
# EXTRACTOR PAGE (formerly APKReverseEngineeringPage)
# =============================================================================
class ExtractorPage(BasePage):
    """Enhanced APK reverse engineering page renamed to Extractor with fixed window and dashboard styling."""
    module_status_changed = Signal(str, str, str)
    scan_progress_updated = Signal(int, dict)
    scan_completed = Signal(dict)
    request_scanner_scan = Signal(str, str, str, str, str)
    
    def __init__(self):
        self.projects = MOCK_PROJECTS.copy()
        # Deferred initialization — created on first use to avoid slow startup
        self._dependency_manager = None  # type: ignore
        self._analyzer = None  # type: ignore
        self._pseudocode_generator = None  # type: ignore

        self.tools_status = {}
        self.current_apk = None
        self.current_project = None
        self.apk_info = {}
        self.code_structure = {}
        self.file_index = {}
        self.current_file_path = None
        self.current_theme = "Dark"
        self.last_log = ""
        self._current_scan_result = None
        super().__init__()

    def _setup_base_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
    
        self.container = QWidget()
        self.container.setObjectName("pageContainer")
    
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setSpacing(12)
        self.container_layout.setContentsMargins(12, 12, 12, 12)
    
        root_layout.addWidget(self.container)

    @property
    def dependency_manager(self):
        if self._dependency_manager is None:
            try:
                self._dependency_manager = APKReverseDependencyManager()
            except Exception:
                self._dependency_manager = object()  # dummy
        return self._dependency_manager

    @property
    def analyzer(self):
        if self._analyzer is None:
            try:
                self._analyzer = APKAnalyzer()
            except Exception:
                self._analyzer = None
        return self._analyzer

    @property
    def pseudocode_generator(self):
        if self._pseudocode_generator is None and PSEUDOCODE_AVAILABLE:
            try:
                self._pseudocode_generator = PseudocodeGenerator()
            except Exception:
                self._pseudocode_generator = None
        return self._pseudocode_generator

    def _setup_ui(self):
        layout = self.container_layout
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)
        self.container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        # Check tools on UI setup
        QTimer.singleShot(500, self.check_tools_async)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(12)

        self.upload_btn = QPushButton("Upload File")
        self.upload_btn.setToolTip("Upload APK file")
        self.upload_btn.setMinimumHeight(36)
        self.upload_btn.clicked.connect(self.open_apk)
        self.upload_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:hover{background:#7c3aed;}")

        self.unpack_btn = QPushButton("Unpack File")
        self.unpack_btn.setToolTip("Analyze/Unpack APK contents")
        self.unpack_btn.setMinimumHeight(36)
        self.unpack_btn.clicked.connect(self.analyze_apk)
        self.unpack_btn.setEnabled(False)
        self.unpack_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#7c3aed;}")

        self.decompile_btn = QPushButton("Decompile")
        self.decompile_btn.setToolTip("Decompile APK using JADX/apktool")
        self.decompile_btn.setMinimumHeight(36)
        self.decompile_btn.clicked.connect(self.decompile_apk)
        self.decompile_btn.setEnabled(False)
        self.decompile_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#7c3aed;}")

        self.scan_apk_btn = QPushButton("Scan APK")
        self.scan_apk_btn.setToolTip("Run MobHound security scanner")
        self.scan_apk_btn.setMinimumHeight(36)
        self.scan_apk_btn.setEnabled(False)
        self.scan_apk_btn.setStyleSheet("QPushButton{background:#7c3aed;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#8b5cf6;}")
        self.scan_apk_btn.clicked.connect(self.run_mobhound_scan)

        toolbar.addWidget(self.upload_btn)
        toolbar.addWidget(self.unpack_btn)
        toolbar.addWidget(self.decompile_btn)
        toolbar.addWidget(self.scan_apk_btn)
        toolbar.addStretch()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search: method, classes, objects")
        self.search_input.setFont(QFont("Poppins",10))
        self.search_input.setMaximumWidth(220)
        self.search_input.setMinimumHeight(32)
        self.search_input.textChanged.connect(self.on_search_text_changed)
        self.search_input.setStyleSheet("QLineEdit{background:#1e293b;border:1px solid #5D2E8C;border-radius:4px;color:#f1f5f9;padding:6px;}")
        toolbar.addWidget(self.search_input)

        layout.addLayout(toolbar)

        main_content_layout = QHBoxLayout()
        main_content_layout.setContentsMargins(0, 0, 0, 0)
        main_content_layout.setSpacing(10)
        
        layout.addLayout(main_content_layout, stretch=1)

        # LEFT PANEL
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0,0,0,0)
        left_layout.setSpacing(12)

        file_tree_group = QFrame()
        file_tree_group.setObjectName("reverseTreeGroup")
        file_tree_group.setStyleSheet("QFrame#reverseTreeGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:6px;border:1px solid #5D2E8C;}")
        file_tree_layout = QVBoxLayout(file_tree_group)
        self.file_tree_label = QLabel("File Tree")
        self.file_tree_label.setFont(QFont("Poppins",11,QFont.Bold))
        self.file_tree_label.setStyleSheet("color:white;")
        file_tree_layout.addWidget(self.file_tree_label)
        self.extracted_file_tree = QTreeWidget()
        self.extracted_file_tree.setHeaderLabels(["Name","Size","Type"])
        self.extracted_file_tree.setColumnWidth(0,180)
        self.extracted_file_tree.itemDoubleClicked.connect(self.on_extracted_file_clicked)
        self.extracted_file_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.extracted_file_tree.customContextMenuRequested.connect(self.on_extracted_file_context_menu)
        self.extracted_file_tree.setStyleSheet("QTreeWidget{background:#0f172a;border:1px solid #334155;color:#f1f5f9;}")
        file_tree_layout.addWidget(self.extracted_file_tree)
        left_layout.addWidget(file_tree_group, stretch=1)

        decomp_tree_group = QFrame()
        decomp_tree_group.setObjectName("reverseTreeGroup")
        decomp_tree_group.setStyleSheet("QFrame#reverseTreeGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:6px;border:1px solid #5D2E8C;}")
        decomp_tree_layout = QVBoxLayout(decomp_tree_group)
        self.decomp_tree_label = QLabel("Decompiled Files")
        self.decomp_tree_label.setFont(QFont("Poppins",11,QFont.Bold))
        self.decomp_tree_label.setStyleSheet("color:white;")
        decomp_tree_layout.addWidget(self.decomp_tree_label)
        self.decompiled_file_tree = QTreeWidget()
        self.decompiled_file_tree.setHeaderLabels(["Name","Size","Type"])
        self.decompiled_file_tree.setColumnWidth(0,180)
        self.decompiled_file_tree.itemDoubleClicked.connect(self.on_decompiled_file_clicked)
        self.decompiled_file_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.decompiled_file_tree.customContextMenuRequested.connect(self.on_decompiled_file_context_menu)
        self.decompiled_file_tree.setStyleSheet("QTreeWidget{background:#0f172a;border:1px solid #334155;color:#f1f5f9;}")
        decomp_tree_layout.addWidget(self.decompiled_file_tree)
        left_layout.addWidget(decomp_tree_group, stretch=1)

        main_content_layout.addWidget(left_panel)
        left_panel.setFixedWidth(320)

        # CENTER PANEL
        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0,0,0,0)
        center_layout.setSpacing(8)

        self.file_name_label = QLabel("No file opened")
        self.file_name_label.setVisible(False)
        self.close_file_btn = QToolButton()
        self.close_file_btn.setText("Ã—")
        self.close_file_btn.setToolTip("Close current file")
        self.close_file_btn.clicked.connect(self.close_current_file)
        self.close_file_btn.setVisible(False)
        self.close_file_btn.setAutoRaise(True)
        self.close_file_btn.setCursor(Qt.PointingHandCursor)
        self.close_file_btn.setFixedSize(16, 16)
        self.close_file_btn.setStyleSheet(
            "QToolButton{color:#cbd5e1;background:transparent;border:none;padding:0px;font-size:10px;font-weight:bold;}"
            "QToolButton:hover{color:#ffffff;}"
        )

        self.center_view_tabs = QTabWidget()
        self.center_view_tabs.setDocumentMode(True)
        self.center_view_tabs.setStyleSheet(
            "QTabWidget::pane{border:1px solid #334155;border-radius:4px;background:#0f172a;}"
            "QTabBar::tab{background:#1e293b;color:#cbd5e1;padding:8px 12px;border:1px solid #334155;border-bottom:none;min-width:160px;}"
            "QTabBar::tab:selected{background:#334155;color:#f8fafc;}"
        )
        self.center_view_tabs.setCornerWidget(self.close_file_btn, Qt.TopRightCorner)

        self.code_editor = QTextEdit()
        self.code_editor.setReadOnly(True)
        self.code_editor.setFont(QFont("Consolas",9))
        self.code_editor.setStyleSheet("QTextEdit{background:#0f172a;border:none;color:#f1f5f9;}")
        self.center_view_tabs.addTab(self.code_editor, "No file opened")

        self.pseudocode_editor = QTextEdit()
        self.pseudocode_editor.setReadOnly(True)
        self.pseudocode_editor.setFont(QFont("Consolas",9))
        self.pseudocode_editor.setStyleSheet("QTextEdit{background:#0f172a;border:none;color:#f1f5f9;}")
        self.center_view_tabs.addTab(self.pseudocode_editor, "Pseudo Code")

        center_layout.addWidget(self.center_view_tabs, stretch=1)

        main_content_layout.addWidget(center_panel)
        center_panel.setFixedWidth(550)

        # RIGHT PANEL
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0,0,0,0)
        right_layout.setSpacing(12)

        apk_info_group = QFrame()
        apk_info_group.setObjectName("reverseInfoGroup")
        apk_info_group.setStyleSheet("QFrame#reverseInfoGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:6px;border:1px solid #5D2E8C;}")
        apk_info_layout = QVBoxLayout(apk_info_group)
        self.apk_info_label = QLabel("APK Info")
        self.apk_info_label.setFont(QFont("Poppins",11,QFont.Bold))
        self.apk_info_label.setStyleSheet("color:white;")
        apk_info_layout.addWidget(self.apk_info_label)
        self.apk_info_browser = QTextBrowser()
        self.apk_info_browser.setFont(QFont("Consolas",9))
        self.apk_info_browser.setStyleSheet("QTextBrowser{background:#0f172a;border:1px solid #334155;border-radius:4px;color:#f1f5f9;}")
        apk_info_layout.addWidget(self.apk_info_browser)
        right_layout.addWidget(apk_info_group, stretch=1)

        file_info_group = QFrame()
        file_info_group.setObjectName("reverseInfoGroup")
        file_info_group.setStyleSheet("QFrame#reverseInfoGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:6px;border:1px solid #5D2E8C;}")
        file_info_layout = QVBoxLayout(file_info_group)
        self.file_info_label = QLabel("Selected File Info")
        self.file_info_label.setFont(QFont("Poppins",11,QFont.Bold))
        self.file_info_label.setStyleSheet("color:white;")
        file_info_layout.addWidget(self.file_info_label)
        self.file_info_browser = QTextBrowser()
        self.file_info_browser.setFont(QFont("Consolas",9))
        self.file_info_browser.setStyleSheet("QTextBrowser{background:#0f172a;border:1px solid #334155;border-radius:4px;color:#f1f5f9;}")
        file_info_layout.addWidget(self.file_info_browser)
        right_layout.addWidget(file_info_group, stretch=1)

        cert_group = QFrame()
        cert_group.setObjectName("reverseInfoGroup")
        cert_group.setStyleSheet("QFrame#reverseInfoGroup{background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855);border-radius:6px;border:1px solid #5D2E8C;}")
        cert_layout = QVBoxLayout(cert_group)
        self.cert_label = QLabel("Certificate Info")
        self.cert_label.setFont(QFont("Poppins",11,QFont.Bold))
        self.cert_label.setStyleSheet("color:white;")
        cert_layout.addWidget(self.cert_label)
        self.cert_info_browser = QTextBrowser()
        self.cert_info_browser.setFont(QFont("Consolas",9))
        self.cert_info_browser.setStyleSheet("QTextBrowser{background:#0f172a;border:1px solid #334155;border-radius:4px;color:#f1f5f9;}")
        cert_layout.addWidget(self.cert_info_browser)
        right_layout.addWidget(cert_group, stretch=1)

        main_content_layout.addWidget(right_panel)
        right_panel.setFixedWidth(320)

        self.log_label = None
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_percent_label = QLabel("Progress: 00%")
        self._extractor_progress_value = 0
        self._extractor_progress_text = "Progress: 00%"
        self._push_global_status("Ready", progress_value=0, progress_text=self._extractor_progress_text)

        # Internal members
        self.analysis_thread = None
        self.decompile_thread = None
        self._scan_progress = None
        self._scanner_thread = None
        self.analysis_text = QTextEdit()
        self.analysis_text.setVisible(False)
        self.structure_tree = QTreeWidget()
        self.structure_tree.setVisible(False)
        self._code_highlighter = None
        self._pseudocode_highlighter = None
        self.add_log_message("Extractor module ready.")

    # --------------------------------------------------------------------------
    # All helper methods (identical to previous APKReverseEngineeringPage)
    # --------------------------------------------------------------------------
    def on_extracted_file_clicked(self, item, column):
        file_path = item.data(0, Qt.UserRole)
        if file_path and os.path.exists(file_path) and os.path.isfile(file_path):
            self.open_file(file_path)

    def on_decompiled_file_clicked(self, item, column):
        file_path = item.data(0, Qt.UserRole)
        if file_path and os.path.exists(file_path) and os.path.isfile(file_path):
            self.open_file(file_path)
    
    def _refresh_decompile_btn(self):
        ready = bool(self.current_apk) and bool(self.tools_status.get("all_ready"))
        self.decompile_btn.setEnabled(ready)

    def close_current_file(self):
        self.code_editor.clear()
        self.pseudocode_editor.clear()
        self.file_name_label.setText("No file opened")
        self.center_view_tabs.setTabText(0, "No file opened")
        self.center_view_tabs.setCurrentIndex(0)
        self._code_highlighter = None
        self._pseudocode_highlighter = None
        self.current_file_path = None
        self.file_info_browser.clear()
        self.search_input.clear()
        self.close_file_btn.setVisible(False)
        self.add_log_message("File closed")

    def on_decompiled_file_context_menu(self, position):
        item = self.decompiled_file_tree.itemAt(position)
        if not item:
            return
        file_path = item.data(0, Qt.UserRole)
        if not file_path or not os.path.isfile(file_path):
            return
        menu = QMenu(self)
        download_action = menu.addAction("Download File")
        download_action.triggered.connect(lambda: self.download_file(file_path))
        scan_action = menu.addAction("Scan File")
        scan_action.triggered.connect(lambda: self.scan_selected_file(file_path, source_tree="decompiled"))
        menu.exec_(self.decompiled_file_tree.mapToGlobal(position))

    def on_extracted_file_context_menu(self, position):
        item = self.extracted_file_tree.itemAt(position)
        if not item:
            return
        member_path = item.data(0, Qt.UserRole)
        if not isinstance(member_path, str) or not member_path.strip():
            return
        menu = QMenu(self)
        scan_action = menu.addAction("Scan File")
        scan_action.triggered.connect(lambda: self.scan_selected_file(member_path, source_tree="extracted"))
        menu.exec_(self.extracted_file_tree.mapToGlobal(position))

    def download_file(self, file_path):
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "File not found!")
            return
        file_name = os.path.basename(file_path)
        save_path, _ = QFileDialog.getSaveFileName(self, "Save File As", file_name, "All Files (*.*)")
        if save_path:
            try:
                shutil.copy2(file_path, save_path)
                QMessageBox.information(self, "Success", f"File downloaded to:\n{save_path}")
                self.add_log_message(f"Downloaded: {file_name} -> {save_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to download file:\n{str(e)}")

    def on_search_text_changed(self, text):
        if not self.current_file_path or not text:
            self.clear_search_highlights()
            self._set_extractor_progress(None, "Progress: 00%")
            return
        document = self._get_active_editor().document()
        self.clear_search_highlights()
        content = document.toPlainText()
        matches = self._find_text_occurrences(content, text)
        selections = []
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor("#FFFF00"))
        for start, end in matches:
            cursor = QTextCursor(document)
            cursor.setPosition(start)
            cursor.setPosition(end, QTextCursor.KeepAnchor)
            selection = QTextEdit.ExtraSelection()
            selection.cursor = cursor
            selection.format = highlight_format
            selections.append(selection)
        self._get_active_editor().setExtraSelections(selections)
        count = len(matches)
        self._set_extractor_progress(None, f"Progress: {count} matches" if count else "Progress: 00%")

    def _find_text_occurrences(self, content, query):
        if not content or not query:
            return []
        content_lower = content.lower()
        query_lower = query.lower()
        matches = []
        start = 0
        qlen = len(query_lower)
        while True:
            idx = content_lower.find(query_lower, start)
            if idx == -1:
                break
            matches.append((idx, idx + qlen))
            start = idx + qlen
        return matches

    def clear_search_highlights(self):
        self.code_editor.setExtraSelections([])
        self.pseudocode_editor.setExtraSelections([])

    def _get_active_editor(self):
        return self.pseudocode_editor if self.center_view_tabs.currentIndex() == 1 else self.code_editor

    def add_log_message(self, message):
        self.last_log = message
        if self.log_label:
            self.log_label.setText(message[:200])
        self._push_global_status(message[:200], progress_value=self._extractor_progress_value, progress_text=self._extractor_progress_text)

    def _set_extractor_progress(self, value: Optional[int], text: str) -> None:
        self._extractor_progress_value = value
        self._extractor_progress_text = text
        if self.progress_bar:
            self.progress_bar.setValue(value or 0)
        if self.progress_percent_label:
            self.progress_percent_label.setText(text)
        self._push_global_status(getattr(self, "last_log", "Ready"), progress_value=value, progress_text=text)

    def check_tools_async(self):
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self._set_extractor_progress(None, "Progress: Checking tools...")
        self.tool_check_thread = APKToolCheckThread(self.dependency_manager)
        self.tool_check_thread.progress_update.connect(self.update_tool_check_progress)
        self.tool_check_thread.result_ready.connect(self.on_tool_check_complete)
        self.tool_check_thread.start()

    def update_tool_check_progress(self, percent, message):
        self._set_extractor_progress(None, f"Progress: {message}")
        self.add_log_message(message)

    def on_tool_check_complete(self, tools_status):
        self.progress_bar.setVisible(False)
        self.tools_status = tools_status
        if tools_status.get("error"):
            self.add_log_message("Resource check failed")
            self._set_extractor_progress(None, "Progress: Failed")
            return
        all_ready = tools_status.get("all_ready", False)
        if all_ready:
            self.add_log_message("Resources ready - All tools available")
            if self.current_apk:
                self.decompile_btn.setEnabled(True)
            self._set_extractor_progress(100, "Progress: Ready")
        else:
            missing = [name for name, info in tools_status.items() if name != "all_ready" and not info.get("available")]
            if missing:
                self.add_log_message(f"Missing resources: {', '.join(missing)}")
                self._set_extractor_progress(None, "Progress: Missing tools")
        self._refresh_decompile_btn()
        
    def open_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open APK File", "", "APK Files (*.apk);;All Files (*.*)")
        if file_path:
            self.load_apk(file_path)

    def load_apk(self, file_path):
        self.current_apk = file_path
        self.current_project = None
        self.add_log_message(f"Loaded APK: {os.path.basename(file_path)}")
        self.unpack_btn.setEnabled(True)
        if self.tools_status.get("all_ready"):
            self.decompile_btn.setEnabled(True)
        self.extracted_file_tree.clear()
        self.apk_info_browser.clear()
        file_size = os.path.getsize(file_path)
        size_str = self.format_size(file_size)
        info_html = f"""
        <div style='padding:8px;'>
            <b>File:</b> {os.path.basename(file_path)}<br>
            <b>Path:</b> {file_path}<br>
            <b>Size:</b> {size_str}<br>
            <b>Modified:</b> {datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')}<br>
            <i>Click 'Unpack File' to analyze contents</i>
        </div>
        """
        self.apk_info_browser.setHtml(info_html)
        self._set_extractor_progress(0, "Progress: 00%")
        self._refresh_decompile_btn()

    def analyze_apk(self):
        if not self.current_apk:
            QMessageBox.warning(self, "No APK", "Please upload an APK file first.")
            return
        self.add_log_message(f"Starting analysis on {os.path.basename(self.current_apk or chr(0)[:0])}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self._set_extractor_progress(0, "Progress: 0%")
        self.analysis_thread = APKAnalysisThread(self.current_apk, self.analyzer)
        self.analysis_thread.progress_update.connect(self.update_analysis_progress)
        self.analysis_thread.result_ready.connect(self.on_analysis_complete)
        self.analysis_thread.error_signal.connect(self.on_analysis_error)
        self.analysis_thread.start()

    def update_analysis_progress(self, percent, message, data):
        self.progress_bar.setValue(percent)
        self._set_extractor_progress(percent, f"Progress: {percent}%")
        self.add_log_message(message)
        if data:
            self.apk_info = data

    def on_analysis_complete(self, apk_info):
        self.progress_bar.setVisible(False)
        self.apk_info = apk_info
        self.update_extracted_file_tree(apk_info)
        self.update_apk_info_panel(apk_info)
        self.add_log_message(f"Analysis complete: {apk_info.get('file_name','Unknown')}")
        QMessageBox.information(self, "Analysis Complete", f"APK analysis completed!\n\nTotal files: {apk_info.get('total_files',0)}")

    def on_analysis_error(self, error):
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Analysis Error", f"Failed to analyze APK:\n\n{error}")
        self.add_log_message(f"Analysis error: {error}")

    def update_extracted_file_tree(self, apk_info):
        self.extracted_file_tree.clear()
        root_item = QTreeWidgetItem(self.extracted_file_tree, [apk_info.get("file_name","Unknown"), self.format_size(apk_info.get("file_size",0)), "APK Archive"])
        root_item.setExpanded(True)
        file_categories = {
            "DEX Files": apk_info.get("dex_files", []),
            "Native Libraries": apk_info.get("native_libs", []),
            "Resources": apk_info.get("resources", []),
            "Images": apk_info.get("images", []),
            "Certificates": apk_info.get("certificates", []),
            "Other Files": apk_info.get("raw_files", [])
        }
        for cat_name, file_list in file_categories.items():
            if file_list:
                cat_item = QTreeWidgetItem(root_item, [cat_name, "", "Folder"])
                for file_path in sorted(file_list):
                    file_size = 0
                    try:
                        with zipfile.ZipFile(self.current_apk,'r') as apk_zip:
                            if file_path in apk_zip.namelist():
                                file_size = apk_zip.getinfo(file_path).file_size
                    except:
                        pass
                    file_item = QTreeWidgetItem(cat_item, [os.path.basename(file_path), self.format_size(file_size), self.get_file_type(file_path)])
                    file_item.setData(0, Qt.UserRole, file_path)
                cat_item.setExpanded(True)

    def update_apk_info_panel(self, apk_info):
        info_html = f"""
        <div style='padding:8px;'>
            <b>File Name:</b> {apk_info.get('file_name','Unknown')}<br>
            <b>File Size:</b> {self.format_size(apk_info.get('file_size',0))}<br>
            <b>MD5:</b> <tt>{apk_info.get('md5_hash','N/A')}</tt><br>
            <b>SHA256:</b> <tt>{apk_info.get('sha256_hash','N/A')}</tt><br>
            <b>Total Files:</b> {apk_info.get('total_files',0)}<br>
            <b>DEX Files:</b> {apk_info.get('dex_count',0)}<br>
            <b>Native Libs:</b> {apk_info.get('native_lib_count',0)}<br>
            <b>Resources:</b> {apk_info.get('resource_count',0)}<br>
            <b>Certificates:</b> {apk_info.get('certificate_count',0)}
        </div>
        """
        self.apk_info_browser.setHtml(info_html)

    def decompile_apk(self):
        if not self.current_apk:
            QMessageBox.warning(self, "No APK", "Please upload an APK file first.")
            return
        if not self.tools_status.get("all_ready"):
            reply = QMessageBox.question(self, "Tools Not Ready", "Some tools are not available. Try anyway?", QMessageBox.Yes | QMessageBox.No)
            if reply != QMessageBox.Yes:
                return
        _apk_name2 = os.path.basename(self.current_apk) if self.current_apk else "unknown.apk"
        self.add_log_message(f"Starting decompilation of {_apk_name2}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self._set_extractor_progress(0, "Progress: 0%")
        self.module_status_changed.emit("Extractor", "running", os.path.basename(self.current_apk) if self.current_apk else "")
        output_dir = APK_REVERSE_OUTPUT_DIR / datetime.now().strftime("%Y%m%d")
        self.decompile_thread = APKDecompilationThread(self.current_apk, self.tools_status, output_dir)
        self.decompile_thread.progress_update.connect(self.update_decompile_progress)
        self.decompile_thread.result_ready.connect(self.on_decompile_complete)
        self.decompile_thread.start()

    def update_decompile_progress(self, percent, message):
        self.progress_bar.setValue(percent)
        self._set_extractor_progress(percent, f"Progress: {percent}%")
        self.add_log_message(message)

    def on_decompile_complete(self, success, message, results):
        self.progress_bar.setVisible(False)
        if success:
            self.current_project = results.get("project_dir")
            self.populate_decompiled_files(results)
            self.add_log_message("Decompilation complete")
            self.scan_apk_btn.setEnabled(True)
            self.module_status_changed.emit("Extractor", "completed", os.path.basename(self.current_apk) if self.current_apk else "")
            QMessageBox.information(self, "Decompilation Complete", f"{message}\n\nOutput saved to:\n{self.current_project}\n\nClick 'Scan APK' for security analysis!")
        else:
            self.add_log_message(f"Decompilation failed: {message}")
            self.module_status_changed.emit("Extractor", "failed", "")
            QMessageBox.critical(self, "Decompilation Failed", message)

    def populate_decompiled_files(self, results):
        self.decompiled_file_tree.clear()
        project_name = Path(self.current_apk).stem
        root_item = QTreeWidgetItem(self.decompiled_file_tree, [project_name, "", "Project"])
        root_item.setExpanded(True)
        jadx_output = results.get("jadx_output")
        if jadx_output and os.path.exists(jadx_output):
            jadx_item = QTreeWidgetItem(root_item, ["Source Files", "", "Source Code"])
            self.add_directory_to_tree(jadx_item, jadx_output, jadx_output)
            jadx_item.setExpanded(True)
        apktool_output = results.get("apktool_output")
        if apktool_output and os.path.exists(apktool_output):
            apktool_item = QTreeWidgetItem(root_item, ["Resources", "", "Resources"])
            self.add_directory_to_tree(apktool_item, apktool_output, apktool_output)
            apktool_item.setExpanded(True)
        dex2jar_output = results.get("dex2jar_output")
        if dex2jar_output and os.path.exists(dex2jar_output):
            dex2jar_item = QTreeWidgetItem(root_item, ["Other Files", "", "Java Archives"])
            self.add_directory_to_tree(dex2jar_item, dex2jar_output, dex2jar_output)
            dex2jar_item.setExpanded(True)

    def add_directory_to_tree(self, parent_item, dir_path, root_path):
        try:
            for item_name in sorted(os.listdir(dir_path)):
                item_path = os.path.join(dir_path, item_name)
                if os.path.isdir(item_path):
                    dir_item = QTreeWidgetItem(parent_item, [item_name, "", "Directory"])
                    dir_item.setData(0, Qt.UserRole, item_path)
                    self.add_directory_to_tree(dir_item, item_path, root_path)
                else:
                    file_size = os.path.getsize(item_path)
                    file_type = self.get_file_type(item_name)
                    file_item = QTreeWidgetItem(parent_item, [item_name, self.format_size(file_size), file_type])
                    file_item.setData(0, Qt.UserRole, item_path)
        except:
            pass

    def open_file(self, file_path):
        try:
            self.current_file_path = file_path
            file_name = os.path.basename(file_path)
            self.file_name_label.setText(file_name)
            self.center_view_tabs.setTabText(0, file_name)
            self.center_view_tabs.setCurrentIndex(0)
            self.close_file_btn.setVisible(True)
            self.add_log_message(f"Opened file: {file_name}")
            binary_extensions = ['.png','.jpg','.jpeg','.gif','.webp','.so','.dex','.arsc','.jar']
            if any(file_path.lower().endswith(ext) for ext in binary_extensions):
                file_size = os.path.getsize(file_path)
                binary_info = f"Binary file: {file_name}\nSize: {self.format_size(file_size)}\nPath: {file_path}\n\nBinary files cannot be displayed as text."
                self.code_editor.setPlainText(binary_info)
                self.pseudocode_editor.setPlainText("Pseudo code is not available for binary file types.")
                self._code_highlighter = None
                self._pseudocode_highlighter = None
                self.file_info_browser.setHtml(f"<div><b>File Type:</b> Binary<br><b>Size:</b> {self.format_size(file_size)}</div>")
                return
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(file_path, 'r', encoding='latin-1') as f:
                    content = f.read()
            self.code_editor.setPlainText(content)
            if self.pseudocode_generator and file_path.lower().endswith(('.java','.kt','.smali','.xml','.js','.py','.c','.cpp','.h')):
                ext = os.path.splitext(file_path)[1].lower()
                if ext == '.smali':
                    code_type = CodeType.SMALI
                elif ext == '.xml':
                    code_type = CodeType.XML
                elif ext == '.kt':
                    code_type = CodeType.KOTLIN
                else:
                    code_type = CodeType.JAVA
                pseudocode = self.pseudocode_generator.generate(content, code_type=code_type) or "Pseudo code generation returned no output."
            elif self.pseudocode_generator:
                pseudocode = "Pseudo code is supported for source-like files."
            else:
                pseudocode = "Pseudo code generator is not available."
            self.pseudocode_editor.setPlainText(pseudocode)
            if file_path.lower().endswith(('.java','.kt','.smali','.xml','.js','.py','.c','.cpp','.h','.json','.gradle','.txt')):
                self._code_highlighter = JavaSyntaxHighlighter(self.code_editor.document())
                self._pseudocode_highlighter = JavaSyntaxHighlighter(self.pseudocode_editor.document())
            else:
                self._code_highlighter = None
                self._pseudocode_highlighter = None
            file_size = os.path.getsize(file_path)
            file_info_html = f"""
            <div style='padding:5px;'>
                <b>File Name:</b> {file_name}<br>
                <b>Size:</b> {self.format_size(file_size)}<br>
                <b>Type:</b> {self.get_file_type(file_name)}<br>
                <b>Modified:</b> {datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')}<br>
                <b>Path:</b> {file_path}
            </div>
            """
            self.file_info_browser.setHtml(file_info_html)
            self.update_certificate_info()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Cannot open file:\n{str(e)}")

    def update_certificate_info(self):
        cert_text = "<div>No certificate information extracted.</div>"
        if self.apk_info and self.apk_info.get("certificates"):
            cert_text = "<div><b>Certificates found:</b><br>" + "<br>".join(self.apk_info.get("certificates",[])) + "</div>"
        self.cert_info_browser.setHtml(cert_text)

    def format_size(self, size_bytes):
        if size_bytes == 0:
            return "0 B"
        size_names = ["B","KB","MB","GB","TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names)-1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.1f} {size_names[i]}"

    def get_file_type(self, filename):
        ext = os.path.splitext(filename)[1].lower()
        type_map = {'.dex':'DEX File','.apk':'APK File','.jar':'JAR Archive','.xml':'XML Resource',
                    '.arsc':'Compiled Resources','.so':'Native Library','.png':'PNG Image','.jpg':'JPEG Image',
                    '.java':'Java Source','.kt':'Kotlin Source','.smali':'Smali Code'}
        return type_map.get(ext, 'File')

    def _prepare_single_file_scan_root(self, selected_file, project_dir):
        # Build a temporary mini scan root that contains only the selected file.
        project_root = Path(project_dir)
        scan_root = project_root / "temp" / "single_file_scan" / datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_root.mkdir(parents=True, exist_ok=True)
        src = Path(selected_file)
        dst = scan_root / src.name
        shutil.copy2(src, dst)
        return scan_root

    def _prepare_apk_member_scan_root(self, member_path, project_dir):
        # Extract one APK-internal file into temporary scan root.
        project_root = Path(project_dir)
        scan_root = project_root / "temp" / "single_file_scan" / datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_root.mkdir(parents=True, exist_ok=True)
        member_rel = Path(member_path)
        with zipfile.ZipFile(self.current_apk or "", "r") as zf:
            if member_path not in zf.namelist():
                raise FileNotFoundError(f"Extracted entry not found in APK: {member_path}")
            dst = scan_root / member_rel.name
            with zf.open(member_path, "r") as src_f, open(dst, "wb") as dst_f:
                shutil.copyfileobj(src_f, dst_f)
        return scan_root

    def scan_selected_file(self, file_ref, source_tree="decompiled"):
        if not self.current_apk:
            QMessageBox.warning(self, "No APK", "Please upload an APK file first.")
            return
        project_dir = self.current_project
        if not project_dir:
            import time
            project_dir = str(Path("projects") / time.strftime("%Y%m%d") / Path(self.current_apk).stem)
        proj = Path(project_dir)
        manifest_path = ""
        for m in [proj/"apktool_resources"/"AndroidManifest.xml",
                  proj/"jadx_output"/"resources"/"AndroidManifest.xml",
                  proj/"jadx_source"/"resources"/"AndroidManifest.xml"]:
            if m.exists():
                manifest_path = str(m)
                break
        try:
            if source_tree == "decompiled":
                if not file_ref or not os.path.isfile(file_ref):
                    raise FileNotFoundError("Selected decompiled file is not available on disk.")
                single_root = self._prepare_single_file_scan_root(file_ref, project_dir)
                target_name = os.path.basename(file_ref)
            else:
                single_root = self._prepare_apk_member_scan_root(file_ref, project_dir)
                target_name = os.path.basename(file_ref)
        except Exception as exc:
            QMessageBox.warning(self, "Scan Setup Error", f"Unable to prepare selected file for scan:\n\n{exc}")
            return

        self.add_log_message(f"Sending selected file to Scanner: {target_name}")
        self.request_scanner_scan.emit(self.current_apk, project_dir, str(single_root), manifest_path, target_name)

    def run_mobhound_scan(self):
        if not self.current_apk:
            QMessageBox.warning(self, "No APK", "Please upload an APK file first.")
            return
        project_dir = self.current_project
        if not project_dir:
            import time
            project_dir = str(Path("projects") / time.strftime("%Y%m%d") / Path(self.current_apk).stem)
        proj = Path(project_dir)
        jadx_dir = ""
        manifest_path = ""
        for c in [proj/"jadx_output"/"sources", proj/"jadx_source"/"sources", proj/"jadx_output"]:
            if c.exists():
                jadx_dir = str(c)
                break
        for m in [proj/"apktool_resources"/"AndroidManifest.xml",
                  proj/"jadx_output"/"resources"/"AndroidManifest.xml",
                  proj/"jadx_source"/"resources"/"AndroidManifest.xml"]:
            if m.exists():
                manifest_path = str(m)
                break

        self.add_log_message("Starting full APK security scan...")

        self.scan_apk_btn.setEnabled(False)
        self.scan_apk_btn.setText("Scanning...")
        self.module_status_changed.emit("Scanner", "running", os.path.basename(self.current_apk) if self.current_apk else "")
        self._scan_progress = QProgressDialog(self)
        self._scan_progress.setWindowTitle("MobHound Scanner")
        self._scan_progress.setLabelText("Starting MobHound security analysis...")
        self._scan_progress.setCancelButtonText("Cancel")
        self._scan_progress.setRange(0, 100)
        self._scan_progress.setValue(0)
        self._scan_progress.setMinimumDuration(0)
        self._scan_progress.setWindowModality(Qt.ApplicationModal)
        self._scan_progress.show()
        self._scanner_thread = MobHoundScannerThread(apk_path=self.current_apk, project_dir=project_dir,
                                                     jadx_dir=jadx_dir, manifest_path=manifest_path)
        self._scanner_thread.progress_update.connect(self._on_scan_progress)
        self._scanner_thread.scan_complete.connect(self._on_scan_complete)
        self._scanner_thread.scan_error.connect(self._on_scan_error)
        self._scan_progress.canceled.connect(self._cancel_scan)
        self._scanner_thread.start()

    def _cancel_scan(self):
        thread = getattr(self, "_scanner_thread", None)
        if thread is not None and thread.isRunning():
            thread.terminate()
            thread.wait(2000)
        self.scan_apk_btn.setEnabled(True)
        self.scan_apk_btn.setText("Scan APK")
        self.add_log_message("Scan cancelled.")

    def _on_scan_progress(self, percent, message):
        self.add_log_message(f"  {message}")
        if hasattr(self, "_scan_progress") and self._scan_progress.isVisible():
            self._scan_progress.setValue(percent)
            self._scan_progress.setLabelText(message)
            QApplication.processEvents()
        self._set_extractor_progress(percent, f"Progress: {percent}%")
        self.add_log_message(message)

    def _on_scan_complete(self, result):
        if hasattr(self, "_scan_progress"):
            self._scan_progress.setValue(100)
            self._scan_progress.close()
        self._set_extractor_progress(100, "Progress: 100%")
        self.scan_apk_btn.setEnabled(True)
        self.scan_apk_btn.setText("Scan APK")
        self._current_scan_result = result
        self.add_log_message(f"Scan complete: {len(result.findings)} findings | {result.ai_risk_label}")
        severity_counts = result.findings_by_severity()
        scan_result_dict = {
            "findings": len(result.findings),
            "critical": len(severity_counts.get("CRITICAL", [])),
            "high": len(severity_counts.get("HIGH", [])),
            "medium": len(severity_counts.get("MEDIUM", [])),
            "low": len(severity_counts.get("LOW", [])),
            "ai_risk": result.ai_risk_label,
            "ai_confidence": result.ai_confidence
        }
        self.scan_completed.emit(scan_result_dict)
        self.module_status_changed.emit("Scanner", "completed", os.path.basename(self.current_apk) if self.current_apk else "")
        self._show_scan_results_dialog(result)

    def _on_scan_error(self, error):
        if hasattr(self, "_scan_progress"):
            self._scan_progress.close()
        self._set_extractor_progress(None, "Progress: Failed")
        self.scan_apk_btn.setEnabled(True)
        self.scan_apk_btn.setText("Scan APK")
        short_err = str(error)[:300]
        self.add_log_message(f"Scanner error: {short_err}")
        self.module_status_changed.emit("Scanner", "failed", "")
        QMessageBox.critical(self, "Scanner Error", f"MobHound scanner encountered an error:\n\n{short_err}")

    def _show_scan_results_dialog(self, result):
        import webbrowser
        dlg = QDialog(self)
        risk_icons = {"CRITICAL_RISK":"🔴","HIGH_RISK":"🟠","MEDIUM_RISK":"🟡","LOW_RISK":"🟢"}
        risk_icon = risk_icons.get(result.ai_risk_label, "🔵")
        dlg.setWindowTitle(f"MobHound Security Report  {risk_icon}  {result.ai_risk_label.replace('_',' ')}  |  {len(result.findings)} findings")
        dlg.resize(1100, 700)
        dlg.setStyleSheet("background:#1e293b;color:#f1f5f9;")
        lay = QVBoxLayout(dlg)
        lay.setSpacing(8)
        lay.setContentsMargins(16, 16, 16, 16)
        hdr = QLabel("MobHound Security Scan Results")
        hdr.setFont(QFont("Poppins", 15, QFont.Bold))
        hdr.setStyleSheet("color:#7c3aed;")
        lay.addWidget(hdr)
        by_sev = result.findings_by_severity()
        rc = {"CRITICAL_RISK": "#dc2626", "HIGH_RISK": "#ea580c", "MEDIUM_RISK": "#d97706", "LOW_RISK": "#2563eb"}
        risk_c = rc.get(result.ai_risk_label, "#6b7280")
        sb = QHBoxLayout()
        for lbl, val, col in [("AI Risk", result.ai_risk_label.replace("_", " "), risk_c),
                              ("Confidence", f"{result.ai_confidence:.0%}", risk_c),
                              ("Critical", str(len(by_sev.get("CRITICAL", []))), "#dc2626"),
                              ("High", str(len(by_sev.get("HIGH", []))), "#ea580c"),
                              ("Medium", str(len(by_sev.get("MEDIUM", []))), "#d97706"),
                              ("Low", str(len(by_sev.get("LOW", []))), "#2563eb"),
                              ("Total", str(len(result.findings)), "#7c3aed")]:
            cw = QWidget()
            cw.setStyleSheet(f"background:#0f172a;border:1px solid {col};border-radius:8px;padding:6px;")
            cl = QVBoxLayout(cw)
            cl.setSpacing(2)
            l1 = QLabel(lbl)
            l1.setStyleSheet(f"color:{col};font-size:10px;font-weight:bold;")
            l2 = QLabel(val)
            l2.setStyleSheet("color:#f1f5f9;font-size:13px;font-weight:bold;")
            l2.setAlignment(Qt.AlignCenter)
            cl.addWidget(l1)
            cl.addWidget(l2)
            sb.addWidget(cw)
        lay.addLayout(sb)
        note = QLabel("Double-click any row for full details")
        note.setStyleSheet("color:#94a3b8;font-size:11px;")
        lay.addWidget(note)
        tbl = QTableWidget()
        tbl.setColumnCount(5)
        tbl.setHorizontalHeaderLabels(["#", "Severity", "Title", "Detector", "Conf%"])
        tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.setSelectionBehavior(QTableWidget.SelectRows)
        tbl.setStyleSheet("QTableWidget{background:#0f172a;border:1px solid #334155;color:#f1f5f9;gridline-color:#334155;}QTableWidget::item:selected{background:#334155;}QHeaderView::section{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:6px;font-weight:bold;}")
        sc = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280"}
        tbl.setRowCount(len(result.findings))
        for i, f in enumerate(result.findings):
            sv = f.severity.value
            c = sc.get(sv, "#6b7280")
            ni = QTableWidgetItem(str(i + 1))
            ni.setTextAlignment(Qt.AlignCenter)
            si = QTableWidgetItem(f"  {sv}  ")
            si.setForeground(Qt.white)
            si.setBackground(QColor(c))
            si.setTextAlignment(Qt.AlignCenter)
            si.setFont(QFont("Poppins", 8, QFont.Bold))
            ti = QTableWidgetItem(f.title)
            di = QTableWidgetItem(f.detector.value)
            ci = QTableWidgetItem(f"{int(f.confidence * 100)}%")
            ci.setTextAlignment(Qt.AlignCenter)
            tbl.setItem(i, 0, ni)
            tbl.setItem(i, 1, si)
            tbl.setItem(i, 2, ti)
            tbl.setItem(i, 3, di)
            tbl.setItem(i, 4, ci)
        lay.addWidget(tbl)

        def show_detail(row, col):
            f = result.findings[row]
            mb = QMessageBox(dlg)
            mb.setWindowTitle(f.title[:80])
            mb.setText(f"Severity: {f.severity.value}  |  {f.confidence:.0%}\nCWE: {f.cwe_id or 'N/A'}\n{f.owasp_mobile or ''}\n\nDescription:\n{f.description}\n\nFix:\n{f.recommendation}\n\nEvidence:\n" + "\n".join(f.evidence[:4]))
            mb.setStyleSheet("QLabel{color:#f1f5f9;min-width:600px;}QMessageBox{background:#1e293b;}")
            mb.exec()
        tbl.cellDoubleClicked.connect(show_detail)

        br = QHBoxLayout()

        def open_html():
            rpts = sorted(glob.glob("projects/**/reports/*.html", recursive=True), key=os.path.getmtime)
            if rpts:
                webbrowser.open(f"file:///{os.path.abspath(rpts[-1])}")
            else:
                QMessageBox.warning(dlg, "Not Found", "HTML report not found.")

        def open_pdf():
            rpts = sorted(glob.glob("projects/**/reports/*.pdf", recursive=True), key=os.path.getmtime)
            if rpts:
                os.startfile(os.path.abspath(rpts[-1]))
            else:
                QMessageBox.warning(dlg, "Not Found", "PDF report not found.")

        def open_folder():
            rpts = sorted(glob.glob("projects/**/reports/", recursive=True), key=os.path.getmtime)
            if rpts:
                os.startfile(os.path.abspath(rpts[-1]))

        for txt, fn, col in [("Open HTML Report", open_html, "#2563eb"),
                             ("Open PDF Report", open_pdf, "#7c3aed"),
                             ("Reports Folder", open_folder, "#374151")]:
            b = QPushButton(txt)
            b.setStyleSheet(f"QPushButton{{background:{col};color:white;border-radius:6px;padding:8px 14px;font-weight:bold;}}")
            b.clicked.connect(fn)
            br.addWidget(b)
        cb = QPushButton("Close")
        cb.setStyleSheet("QPushButton{background:#dc2626;color:white;border-radius:6px;padding:8px 14px;font-weight:bold;}")
        cb.clicked.connect(dlg.accept)
        br.addWidget(cb)
        lay.addLayout(br)
        dlg.exec()

    def apply_theme(self, theme_name):
        self.current_theme = theme_name
        if theme_name == "Light":
            card_gradient = "background: #FFFFFF; border: 1px solid #6A0DAD;"
            tree_bg = "#ffffff"
            tree_color = "#6A0DAD"
            text_color = "#6A0DAD"
        else:
            card_gradient = "background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #481176,stop:1 #370855); border: 1px solid #5D2E8C;"
            tree_bg = "#0f172a"
            tree_color = "#f1f5f9"
            text_color = "white"
        for widget in self.findChildren(QFrame, "reverseTreeGroup"):
            widget.setStyleSheet(f"QFrame#reverseTreeGroup{{{card_gradient}}}")
        for widget in self.findChildren(QFrame, "reverseInfoGroup"):
            widget.setStyleSheet(f"QFrame#reverseInfoGroup{{{card_gradient}}}")
        for widget in self.findChildren(QFrame, "reverseBottomBar"):
            widget.setStyleSheet(f"QFrame#reverseBottomBar{{{card_gradient} margin-top:8px;}}")
        for tree in [self.extracted_file_tree, self.decompiled_file_tree]:
            if tree:
                border_col = "#6A0DAD" if theme_name == "Light" else "#334155"
                header_bg = "#FFFFFF" if theme_name == "Light" else "#1e293b"
                header_fg = "#6A0DAD" if theme_name == "Light" else "#94a3b8"
                tree.setStyleSheet(
                    f"QTreeWidget{{background:{tree_bg};border:1px solid {border_col};color:{tree_color};gridline-color:{border_col};}}"
                    f"QHeaderView::section{{background:{header_bg};color:{header_fg};border:1px solid {border_col};padding:6px;font-weight:bold;}}"
                )
        for browser in [self.apk_info_browser, self.file_info_browser, self.cert_info_browser]:
            if browser:
                border_col = "#6A0DAD" if theme_name == "Light" else "#334155"
                browser.setStyleSheet(f"QTextBrowser{{background:{tree_bg};border:1px solid {border_col};border-radius:4px;color:{tree_color};}}")
        border_col = "#6A0DAD" if theme_name == "Light" else "#334155"
        self.code_editor.setStyleSheet(f"QTextEdit{{background:{tree_bg};border:1px solid {border_col};border-radius:4px;color:{tree_color};}}")
        self.pseudocode_editor.setStyleSheet(f"QTextEdit{{background:{tree_bg};border:1px solid {border_col};border-radius:4px;color:{tree_color};}}")
        if theme_name == "Light":
            self.center_view_tabs.setStyleSheet(
                "QTabWidget::pane{border:1px solid #6A0DAD;border-radius:4px;background:#FFFFFF;}"
                "QTabBar::tab{background:#FFFFFF;color:#6A0DAD;padding:8px 12px;border:1px solid #6A0DAD;border-bottom:none;min-width:160px;}"
                "QTabBar::tab:selected{background:#F3E8FF;color:#6A0DAD;}"
            )
        else:
            self.center_view_tabs.setStyleSheet(
                "QTabWidget::pane{border:1px solid #334155;border-radius:4px;background:#0f172a;}"
                "QTabBar::tab{background:#1e293b;color:#cbd5e1;padding:8px 12px;border:1px solid #334155;border-bottom:none;min-width:160px;}"
                "QTabBar::tab:selected{background:#334155;color:#f8fafc;}"
            )
        if theme_name == "Light":
            for lbl in [self.file_tree_label, self.decomp_tree_label, self.apk_info_label, self.file_info_label, self.cert_label]:
                lbl.setStyleSheet("color:#6A0DAD;")
            self.search_input.setStyleSheet("QLineEdit{background:#FFFFFF;border:1px solid #6A0DAD;border-radius:4px;color:#6A0DAD;padding:6px;}")
            light_btn = "QPushButton{background:#FFFFFF;color:#6A0DAD;border:1px solid #6A0DAD;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:hover{background:#F3E8FF;}"
            self.upload_btn.setStyleSheet(light_btn)
            self.unpack_btn.setStyleSheet(light_btn)
            self.decompile_btn.setStyleSheet(light_btn)
            self.scan_apk_btn.setStyleSheet(light_btn)
        else:
            for lbl in [self.file_tree_label, self.decomp_tree_label, self.apk_info_label, self.file_info_label, self.cert_label]:
                lbl.setStyleSheet("color:white;")
            self.search_input.setStyleSheet(f"QLineEdit{{background:#1e293b;border:1px solid #5D2E8C;border-radius:4px;color:{tree_color};padding:6px;}}")
            self.upload_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:hover{background:#7c3aed;}")
            self.unpack_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#7c3aed;}")
            self.decompile_btn.setStyleSheet("QPushButton{background:#5b21b6;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#7c3aed;}")
            self.scan_apk_btn.setStyleSheet("QPushButton{background:#7c3aed;color:white;border-radius:6px;font-weight:bold;padding:6px 16px;}QPushButton:disabled{background:#374151;color:#9ca3af;}QPushButton:hover:!disabled{background:#8b5cf6;}")
        if self.log_label:
            self.log_label.setStyleSheet(f"color:{text_color};font-size:11px;")
        if self.progress_percent_label:
            self.progress_percent_label.setStyleSheet(f"color:{text_color};font-size:11px;")
        self.add_log_message(f"Theme changed to {theme_name}")

# ------------------------------------------------------------------------------
# LoadingScreen (from int2.py)
# ------------------------------------------------------------------------------
class LoadingScreen(QWidget):
    """Animated 0-to-100 staged loading screen — MobHound FYP."""
    finished = Signal()
    _STAGES = [
        (0,  10, "Initializing Core Engine"),
        (10, 22, "Loading Security Modules"),
        (22, 37, "Bootstrapping AI Classifier"),
        (37, 52, "Preparing APK Analysis Tools"),
        (52, 65, "Configuring Exploit Payloads"),
        (65, 78, "Setting Up Network Interceptor"),
        (78, 90, "Rendering Interface"),
        (90,100, "MobHound Ready — Unleash the Hound"),
    ]
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.SplashScreen | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._prog = 0.0; self._stage = 0; self._sprog = 0.0
        self._pulse = 0.0; self._pdir = 1; self._df = 0; self._done = False
        self.messages = []
        # Load logo from assets/icons/
        img_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icons", "mobhound1.png")
        self.background_pixmap = QPixmap(img_path) if os.path.exists(img_path) else None
        self._pts = [{"x": random.random(), "y": random.random(),
                      "r": random.uniform(1.5, 4.2),
                      "vx": random.uniform(-0.00035, 0.00035),
                      "vy": random.uniform(-0.00035, 0.00035),
                      "a": random.uniform(0.10, 0.45)} for _ in range(26)]
        scr = QApplication.primaryScreen().availableGeometry()
        W, H = 500, 610
        self.setGeometry((scr.width() - W) // 2, (scr.height() - H) // 2, W, H)
        self.setFixedSize(W, H)
        self._t = QTimer(self); self._t.setInterval(16)
        self._t.timeout.connect(self._tick)

    def add_message(self, m): self.messages.append(m)
    def start_loading(self): self._t.start()

    def finish(self):
        if self._done: return
        self._done = True; self._prog = 100.0; self.update()
        QTimer.singleShot(380, self._close_emit)

    def _close_emit(self):
        self._t.stop(); self.close(); self.finished.emit()

    def _tick(self):
        if self._done: return
        if self._stage < len(self._STAGES):
            lo, hi, _ = self._STAGES[self._stage]
            self._sprog = min(1.0, self._sprog + random.uniform(0.018, 0.034))
            self._prog = lo + (hi - lo) * self._sprog
            if self._sprog >= 1.0:
                if self._stage < len(self._STAGES) - 1:
                    self._stage += 1; self._sprog = 0.0
                else:
                    self.finish(); return
        self._pulse += 0.045 * self._pdir
        if self._pulse >= 1.0: self._pdir = -1
        elif self._pulse <= 0.0: self._pdir = 1
        self._df = (self._df + 1) % 60
        for p in self._pts:
            p["x"] = (p["x"] + p["vx"]) % 1.0
            p["y"] = (p["y"] + p["vy"]) % 1.0
        self.update()

    def paintEvent(self, event):
        from PySide6.QtGui import QLinearGradient
        pa = QPainter(self); pa.setRenderHint(QPainter.Antialiasing)
        W, H = self.width(), self.height()
        if self.background_pixmap:
            sc = self.background_pixmap.scaled(self.size(), Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
            pa.drawPixmap((W - sc.width()) // 2, (H - sc.height()) // 2, sc)
        pa.fillRect(0, 0, W, H, QColor(7, 2, 20, 218))
        pa.setPen(Qt.NoPen)
        for p in self._pts:
            pa.setBrush(QBrush(QColor(145, 82, 255, int(p["a"] * 255))))
            r = int(p["r"]); pa.drawEllipse(int(p["x"] * W) - r, int(p["y"] * H) - r, r * 2, r * 2)
        ga = int(65 + 62 * self._pulse)
        for rad, fade in ((18, 3), (9, 1), (2, 0)):
            pa.setPen(QColor(125, 55, 252, max(0, ga - rad * fade)))
            pa.setFont(QFont("Poppins", 33, QFont.Black))
            pa.drawText(QRect(-rad, 40 - rad, W + rad * 2, 60), Qt.AlignHCenter, "MOBHOUND")
        pa.setPen(QColor(255, 255, 255)); pa.setFont(QFont("Poppins", 33, QFont.Black))
        pa.drawText(QRect(0, 40, W, 60), Qt.AlignHCenter, "MOBHOUND")
        pa.setFont(QFont("Poppins", 10)); pa.setPen(QColor(168, 128, 255))
        pa.drawText(QRect(0, 103, W, 24), Qt.AlignHCenter, "Mobile Application Testing Tool")
        pa.setPen(QPen(QColor(95, 44, 196, 88), 1)); pa.drawLine(48, 133, W - 48, 133)
        if self.background_pixmap:
            TS = 150
            thumb = self.background_pixmap.scaled(TS, TS, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            tx = (W - thumb.width()) // 2; ty = 148; pc = int(95 + 78 * self._pulse)
            pa.setPen(QPen(QColor(115, 50, 252, pc), 2)); pa.setBrush(Qt.NoBrush)
            pa.drawRoundedRect(tx - 5, ty - 5, thumb.width() + 10, thumb.height() + 10, 12, 12)
            pa.drawPixmap(tx, ty, thumb)
        dots = "." * (1 + self._df // 20)
        lbl = self._STAGES[min(self._stage, len(self._STAGES) - 1)][2] + dots
        pa.setFont(QFont("Poppins", 10)); pa.setPen(QColor(198, 165, 255))
        pa.drawText(QRect(22, 318, W - 44, 26), Qt.AlignHCenter, lbl)
        pa.setFont(QFont("Poppins", 27, QFont.Bold)); pa.setPen(QColor(255, 255, 255))
        pa.drawText(QRect(0, 350, W, 48), Qt.AlignHCenter, str(int(self._prog)) + "%")
        bx, by, bw, bh = 34, 412, W - 68, 14; br = bh // 2
        pa.setBrush(QBrush(QColor(28, 8, 62, 200))); pa.setPen(QPen(QColor(75, 34, 155, 115), 1))
        pa.drawRoundedRect(bx, by, bw, bh, br, br)
        fw = int(bw * self._prog / 100)
        if fw > 0:
            lg = QLinearGradient(bx, by, bx + fw, by)
            lg.setColorAt(0.0, QColor(82, 18, 208)); lg.setColorAt(0.5, QColor(132, 46, 248)); lg.setColorAt(1.0, QColor(185, 115, 255))
            pa.setBrush(QBrush(lg)); pa.setPen(Qt.NoPen); pa.drawRoundedRect(bx, by, fw, bh, br, br)
            gx = max(bx, bx + fw - 22)
            pa.setBrush(QBrush(QColor(255, 255, 255, int(42 + 38 * self._pulse))))
            pa.drawRoundedRect(gx, by + 3, 17, bh - 6, 3, 3)
        n = len(self._STAGES); sp = (W - 76) / max(n - 1, 1)
        for i in range(n):
            cx, cy = int(36 + i * sp), 443
            if i < self._stage:
                pa.setBrush(QBrush(QColor(130, 60, 248))); pa.setPen(Qt.NoPen); pa.drawEllipse(cx - 5, cy - 5, 10, 10)
            elif i == self._stage:
                pr = int(4 + 3 * self._pulse); pa.setBrush(QBrush(QColor(208, 162, 255, 205))); pa.setPen(Qt.NoPen)
                pa.drawEllipse(cx - pr, cy - pr, pr * 2, pr * 2)
            else:
                pa.setBrush(QBrush(QColor(44, 18, 82, 130))); pa.setPen(QPen(QColor(84, 46, 140), 1)); pa.drawEllipse(cx - 4, cy - 4, 8, 8)
        tips = ["MobHound - Mobile Application Testing Tool",
                "Scanner: AI-powered APK vulnerability analysis (Random Forest)",
                "Dynamic Analysis: Frida + MitMProxy traffic capture",
                "Extractor: JADX decompile + APKTool resources",
                "Payloader: 100+ Android attack vectors + Mutation Engine",
                "Analyzer: DNS Recon + WHOIS + Android CVE Mapping"]
        pa.setFont(QFont("Poppins", 8)); pa.setPen(QColor(105, 75, 165, 158))
        pa.drawText(QRect(14, 470, W - 28, 22), Qt.AlignHCenter, chr(0x1F4A1) + "  " + tips[(self._df // 20) % len(tips)])
        pa.setFont(QFont("Poppins", 8)); pa.setPen(QColor(75, 55, 115, 138))
        pa.drawText(QRect(0, 556, W, 20), Qt.AlignHCenter, "MobHound v1.0  |  (C) 2026 MobHound Team  |  All rights reserved.")
        pa.end()


# ─── MobHound Project Info ──────────────────────────────────────────────────
MOBHOUND_TEAM = {
    "project":       "MobHound — Mobile Application Testing Tool",
    "university":    "Dawood University of Engineering & Technology",
    "faculty":       "Faculty of Information & Computing Sciences",
    "department":    "Department of Cyber Security",
    "supervisor":    "Engr. Muhammad Faisal Memon",
    "co_supervisor": "Dr. Abdullah Lakhan",
    "session":       "2022-2026",
    "members": [
        ("Haris Anees",               "22F-BSCY-52"),
        ("Muhammad Sameer",           "22F-BSCY-55"),
        ("Muhammad Bilal Khan",       "22F-BSCY-71"),
        ("Saad Bin Saeed",            "22F-BSCY-102"),
        ("Syed Muhammad Abbas", "22F-BSCY-23"),
    ],
}


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About MobHound")
        self.setFixedSize(520, 600)
        self.setModal(True)
        self.setStyleSheet(
            "QDialog{background:#0f0a1a;color:#f1f5f9;}"
            "QLabel{background:transparent;}"
            "QPushButton{background:#5b21b6;color:white;border-radius:6px;"
            "padding:8px 20px;font-weight:bold;}"
            "QPushButton:hover{background:#7c3aed;}")
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)
        # Header
        hdr = QWidget(); hdr.setFixedHeight(140)
        hdr.setStyleSheet("background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #4c1d95,stop:1 #1e0a3c);")
        hl = QVBoxLayout(hdr); hl.setContentsMargins(22,16,22,16)
        lr = QHBoxLayout(); lr.setSpacing(16); lr.setAlignment(Qt.AlignVCenter)
        logo_l = QLabel()
        logo_l.setFixedSize(72, 72)
        logo_l.setAlignment(Qt.AlignCenter)
        img_p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icons", "mobhound1.png")
        if os.path.exists(img_p):
            pm = QPixmap(img_p).scaled(68, 68, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_l.setPixmap(pm)
        logo_l.setStyleSheet(
            "background:rgba(91,33,182,0.3);border-radius:12px;"
            "border:2px solid rgba(167,139,250,0.5);")
        lr.addWidget(logo_l, 0, Qt.AlignVCenter)
        tc = QVBoxLayout(); tc.setSpacing(3); tc.setAlignment(Qt.AlignVCenter)
        for txt,sz,bold in [("MobHound",26,True),
                             ("Mobile Application Testing Tool",11,False),
                             ("v1.0  |  AI-Powered Android Security",9,False)]:
            l=QLabel(txt)
            l.setFont(QFont("Poppins",sz,QFont.Black if bold else QFont.Normal))
            l.setStyleSheet("color:white;letter-spacing:1px;" if bold else "color:rgba(200,178,255,0.88);")
            tc.addWidget(l)
        lr.addLayout(tc,1); hl.addLayout(lr); lay.addWidget(hdr)
        # Body
        body=QWidget(); body.setStyleSheet("background:#0f0a1a;")
        bl=QVBoxLayout(body); bl.setContentsMargins(22,16,22,14); bl.setSpacing(10)
        # University
        uf=QFrame(); uf.setStyleSheet("QFrame{background:#1a0f2e;border-radius:8px;border:1px solid #5D2E8C;}")
        ufl=QVBoxLayout(uf); ufl.setContentsMargins(14,10,14,10); ufl.setSpacing(2)
        for txt,big in [("Dawood University of Engineering & Technology",True),
                        ("Faculty of Information & Computing Sciences",False),
                        ("Department of Cyber Security  |  Session 2022-2026",False)]:
            l=QLabel(txt); l.setFont(QFont("Poppins",10 if big else 8, QFont.Bold if big else QFont.Normal))
            l.setStyleSheet("color:"+("#c4b5fd" if big else "#94a3b8")+";"); ufl.addWidget(l)
        bl.addWidget(uf)
        # Supervisors
        sr=QHBoxLayout()
        for title,name in [("Supervisor","Engr. Muhammad Faisal Memon"),("Co-Supervisor","Dr. Abdullah Lakhan")]:
            sf=QFrame(); sf.setStyleSheet("QFrame{background:#1a0f2e;border-radius:8px;border:1px solid #334155;}")
            sfl=QVBoxLayout(sf); sfl.setContentsMargins(12,7,12,7)
            sl1=QLabel(title); sl1.setFont(QFont("Poppins",7)); sl1.setStyleSheet("color:#64748b;")
            sl2=QLabel(name); sl2.setFont(QFont("Poppins",9,QFont.Bold)); sl2.setStyleSheet("color:#a78bfa;")
            sfl.addWidget(sl1); sfl.addWidget(sl2); sr.addWidget(sf)
        bl.addLayout(sr)
        # Team
        tl=QLabel("Group Members"); tl.setFont(QFont("Poppins",10,QFont.Bold)); tl.setStyleSheet("color:white;"); bl.addWidget(tl)
        mg=QGridLayout(); mg.setSpacing(6)
        for i,(name,roll) in enumerate(MOBHOUND_TEAM["members"]):
            mf=QFrame(); mf.setStyleSheet("QFrame{background:#1a0f2e;border-radius:6px;border:1px solid #334155;}")
            mfl=QHBoxLayout(mf); mfl.setContentsMargins(10,5,10,5); mfl.setSpacing(8)
            mn=QLabel(name); mn.setFont(QFont("Poppins",8,QFont.Bold)); mn.setStyleSheet("color:#f1f5f9;")
            mr=QLabel(roll); mr.setFont(QFont("Poppins",8)); mr.setStyleSheet("color:#a78bfa;")
            mfl.addWidget(mn,1); mfl.addWidget(mr); mg.addWidget(mf,i//2,i%2)
        bl.addLayout(mg)
        # Features
        fl=QLabel("Key Features"); fl.setFont(QFont("Poppins",10,QFont.Bold)); fl.setStyleSheet("color:white;"); bl.addWidget(fl)
        fr=QHBoxLayout(); fr.setSpacing(6)
        for icon,txt in [("🔧","RE Module"),("🛡️","AI Scanner"),("🌐","Dynamic"),("📄","Reports")]:
            ff=QFrame(); ff.setStyleSheet("QFrame{background:#1a0f2e;border-radius:6px;border:1px solid #5D2E8C;}")
            ffl=QVBoxLayout(ff); ffl.setContentsMargins(8,6,8,6); ffl.setSpacing(2)
            fi=QLabel(icon); fi.setFont(QFont("Poppins",16)); fi.setAlignment(Qt.AlignCenter)
            ft=QLabel(txt); ft.setFont(QFont("Poppins",8)); ft.setAlignment(Qt.AlignCenter); ft.setStyleSheet("color:#94a3b8;")
            ffl.addWidget(fi); ffl.addWidget(ft); fr.addWidget(ff)
        bl.addLayout(fr)
        cb=QPushButton("Close"); cb.clicked.connect(self.close); bl.addWidget(cb,0,Qt.AlignCenter)
        lay.addWidget(body)


class MainWindow(QMainWindow):
    def __init__(self, project_manager: Optional[ProjectManager] = None, project_session: Optional[ProjectSession] = None):
        super().__init__()
        self.projects = MOCK_PROJECTS.copy()
        self.project_manager = project_manager
        self.project_session = project_session
        self._project_activity_log: List[Dict[str, Any]] = []
        self.current_theme = "Dark"
        self.page_container = None
        self._setup_ui()
    def _setup_ui(self):
        self.setWindowTitle("MobHound v1.0 — Mobile Application Testing Tool")
        self.setMinimumSize(1200, 750)
        self.resize(1450, 900)
        self.move(120, 90)
        self.set_window_logo()
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(0)
        tab_header_layout = QHBoxLayout()
        self.tab_bar = QTabBar()
        self.tab_bar.setExpanding(False)
        self.tab_bar.setMovable(False)
        self.tab_bar.setFont(QFont("Poppins",10))
        tabs = ["📊  Dashboard","🌐  Intercepter","🔬  Analyzer","💉  Payloader","🛡  Scanner","🔧  Extractor","🔑  Encoder/Decoder","📖  Guidelines"]
        for t in tabs:
            self.tab_bar.addTab(t)
        tab_header_layout.addWidget(self.tab_bar)
        tab_header_layout.addStretch()
        # About button
        self._about_btn = QPushButton("ℹ️  About")
        self._about_btn.setStyleSheet(
            "QPushButton{background:rgba(91,33,182,0.4);color:#c4b5fd;"
            "border:1px solid #5D2E8C;border-radius:6px;padding:4px 10px;"
            "font-size:10px;font-weight:bold;}"
            "QPushButton:hover{background:#5b21b6;color:white;}")
        self._about_btn.clicked.connect(lambda: AboutDialog(self).exec())
        tab_header_layout.addWidget(self._about_btn)
        self.theme_toggle_btn = AnimatedToggle()
        tab_header_layout.addWidget(self.theme_toggle_btn)
        tab_header_widget = QWidget()
        tab_header_widget.setLayout(tab_header_layout)
        tab_header_widget.setMinimumHeight(72)
        tab_header_layout.setContentsMargins(20,12,20,8)
        self.tab_bar.setMinimumHeight(50)
        main_layout.addWidget(tab_header_widget, alignment=Qt.AlignTop)
        self.page_container = QStackedWidget()
        self.dashboard_page = DashboardPage(self.project_manager, self.project_session)
        self.intercepter_page = IntercepterPage()
        self.analyzer_page = AnalyzerPage()
        self.payloader_page = PayloaderPage()
        self.scanner_page = ScannerPage()
        self.extractor_page = ExtractorPage()
        self.encoder_decoder_page = EncoderDecoderPage()
        self.guidelines_page = GuidelinesPage()
        self.page_container.addWidget(self.dashboard_page)
        self.page_container.addWidget(self.intercepter_page)
        self.page_container.addWidget(self.analyzer_page)
        self.page_container.addWidget(self.payloader_page)
        self.page_container.addWidget(self.scanner_page)
        self.page_container.addWidget(self.extractor_page)
        self.page_container.addWidget(self.encoder_decoder_page)
        self.page_container.addWidget(self.guidelines_page)
        
        # Connect ExtractorPage signals to DashboardPage
        self.extractor_page.module_status_changed.connect(self.dashboard_page.on_module_status_changed)
        self.extractor_page.scan_completed.connect(self.dashboard_page.on_scan_completed)
        self.extractor_page.request_scanner_scan.connect(self._start_scanner_from_extractor)
        self.scanner_page.module_status_changed.connect(self.dashboard_page.on_module_status_changed)
        self.scanner_page.scan_completed.connect(self.dashboard_page.on_scan_completed)
        self.intercepter_page.module_status_changed.connect(self.dashboard_page.on_module_status_changed)
        self.extractor_page.module_status_changed.connect(self._on_module_status_event)
        self.scanner_page.module_status_changed.connect(self._on_module_status_event)
        self.intercepter_page.module_status_changed.connect(self._on_module_status_event)
        self.extractor_page.scan_completed.connect(self._on_scan_completed_event)
        self.scanner_page.scan_completed.connect(self._on_scan_completed_event)
        self.intercepter_page.send_to_analyzer.connect(self._send_flow_to_analyzer)
        self.intercepter_page.send_to_payloader.connect(self._send_flow_to_payloader)
        
        main_layout.addWidget(self.page_container)
        self.tab_bar.currentChanged.connect(self.page_container.setCurrentIndex)
        self.tab_bar.currentChanged.connect(self._on_tab_changed)
        self.theme_toggle_btn.clicked.connect(self.toggle_theme)
        self.apply_theme(self.current_theme)

        # Status bar
        self._status_bar = QStatusBar()
        self._status_bar.setFixedHeight(26)
        self._status_bar.setStyleSheet(
            "QStatusBar{background:#120820;color:#a78bfa;font-size:11px;"
            "border-top:1px solid #5D2E8C;padding-left:8px;}QStatusBar::item{border:none;}")
        self.setStatusBar(self._status_bar)
        self._status_left_lbl = QLabel("MobHound v1.0  |  Ready")
        self._status_left_lbl.setWordWrap(False)
        self._status_left_lbl.setStyleSheet("color:#a78bfa;font-size:11px;background:transparent;")
        self._status_bar.addWidget(self._status_left_lbl, 1)
        self._status_log_lbl = QLabel("Ready")
        self._status_log_lbl.setWordWrap(False)
        self._status_log_lbl.setMinimumWidth(280)
        self._status_log_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._status_log_lbl.setStyleSheet("color:#a78bfa;font-size:11px;background:transparent;")
        self._status_bar.addPermanentWidget(self._status_log_lbl)
        self._status_progress_lbl = QLabel("")
        self._status_progress_lbl.setWordWrap(False)
        self._status_progress_lbl.setMinimumWidth(88)
        self._status_progress_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._status_progress_lbl.setStyleSheet("color:#a78bfa;font-size:11px;background:transparent;")
        self._status_bar.addPermanentWidget(self._status_progress_lbl)
        self._status_progress = QProgressBar()
        self._status_progress.setFixedSize(160, 16)
        self._status_progress.setRange(0, 100)
        self._status_progress.setValue(0)
        self._status_progress.setTextVisible(False)
        self._status_progress.setVisible(False)
        self._status_progress.setStyleSheet("QProgressBar{border-radius:3px;background:#1e293b;color:white;text-align:center;}QProgressBar::chunk{background:#FFD700;border-radius:3px;}")
        self._status_bar.addPermanentWidget(self._status_progress)
        self._status_states: Dict[int, Dict[str, Any]] = {}
        self._status_defaults = {
            0: "Dashboard  |  Live project metrics",
            1: "Intercepter  |  HTTP/HTTPS traffic capture",
            2: "Analyzer  |  Security analysis + Network Recon",
            3: "Payloader  |  Android attack payload generator",
            4: "Scanner  |  AI-powered APK security scan",
            5: "Extractor  |  APK Reverse Engineering",
            6: "Encoder/Decoder  |  Base64, URL, JWT, Hash",
            7: "Guidelines  |  OWASP Mobile Top 10",
        }
        self._render_status_for_tab(self.tab_bar.currentIndex())
        self.tab_bar.currentChanged.connect(self._update_status_bar)

        self.current_target_timer = QTimer(self)
        self.current_target_timer.timeout.connect(self._sync_dashboard_current_target)
        self.current_target_timer.start(400)
        self._restore_project_session_state()
        self._session_autosave_timer = QTimer(self)
        self._session_autosave_timer.timeout.connect(self._autosave_project_session)
        self._session_autosave_timer.start(30000)
    def toggle_theme(self):
        new_theme = "Light" if self.current_theme=="Dark" else "Dark"
        self.apply_theme(new_theme)
    def _update_status_bar(self, i):
        """Update status bar message on tab switch."""
        msgs = {
            0: "📊  Dashboard  |  Live project metrics",
            1: "🌐  Intercepter  |  HTTP/HTTPS traffic capture",
            2: "🔬  Analyzer  |  Security analysis + Network Recon",
            3: "💉  Payloader  |  Android attack payload generator",
            4: "🛡  Scanner  |  AI-powered APK security scan",
            5: "🔧  Extractor  |  APK Reverse Engineering",
            6: "🔑  Encoder/Decoder  |  Base64, URL, JWT, Hash",
            7: "📖  Guidelines  |  OWASP Mobile Top 10",
        }
        if hasattr(self, "_status_bar"):
            self._status_bar.showMessage("MobHound v1.0  |  " + msgs.get(i, "Ready"))

    def _update_status_bar(self, i):
        """Render saved log/progress state for the selected tab."""
        self._render_status_for_tab(i)

    def _render_status_for_tab(self, index: int) -> None:
        if not hasattr(self, "_status_left_lbl"):
            return
        state = self._status_states.get(index, {})
        info_text = f"MobHound v1.0  |  {self._status_defaults.get(index, 'Ready')}"
        log_text = state.get("message") or "Ready"
        progress_text = state.get("progress_text") or ""
        progress_value = state.get("progress_value")
        self._status_left_lbl.setText(info_text[:320])
        self._status_log_lbl.setText(str(log_text)[:260])
        self._status_progress_lbl.setText(str(progress_text)[:90])
        show_progress = progress_value is not None
        self._status_progress.setVisible(show_progress)
        if show_progress:
            self._status_progress.setValue(max(0, min(100, int(progress_value))))

    def set_global_status(self, message: str, progress_value: Optional[int] = None, progress_text: Optional[str] = None, source: Optional[QWidget] = None) -> None:
        if not hasattr(self, "_status_states"):
            return
        index = self.page_container.indexOf(source) if source is not None and self.page_container else -1
        if index < 0 and self.page_container:
            index = self.page_container.currentIndex()
        self._status_states[index] = {
            "message": str(message),
            "progress_value": progress_value,
            "progress_text": progress_text or (f"Progress: {progress_value}%" if progress_value is not None else ""),
        }
        if self.page_container and index == self.page_container.currentIndex():
            self._render_status_for_tab(index)

    def set_window_logo(self):
        logo_path = ICONS_DIR / "mobhound1.png"
        if logo_path.exists():
            pixmap = QPixmap(str(logo_path))
            scaled = pixmap.scaledToWidth(64, Qt.SmoothTransformation)
            self.setWindowIcon(QIcon(scaled))
    def apply_theme(self, theme_name):
        self.current_theme = theme_name
        stylesheet = ThemeManager.get_theme_stylesheet(theme_name)
        self.setStyleSheet(stylesheet)
        if self.page_container:
            for i in range(self.page_container.count()):
                self.page_container.widget(i).setStyleSheet(stylesheet)
        if hasattr(self,"dashboard_page"):
            self.dashboard_page.apply_dashboard_theme(theme_name)
        if hasattr(self, "payloader_page"):
            self.payloader_page.apply_theme(theme_name)
        if hasattr(self,"scanner_page"):
            self.scanner_page.apply_theme(theme_name)
        if hasattr(self,"extractor_page"):
            self.extractor_page.apply_theme(theme_name)
        if hasattr(self,"encoder_decoder_page"):
            self.encoder_decoder_page.apply_theme(theme_name)
        # Apply theme to interceptor page
        if hasattr(self,"intercepter_page"):
            self.intercepter_page.apply_theme(theme_name)
        if hasattr(self, "analyzer_page"):
            self.analyzer_page.apply_theme(theme_name)
        if hasattr(self, "_status_bar"):
            is_light = theme_name == "Light"
            bar_bg = "#FFFFFF" if is_light else "#120820"
            bar_fg = "#6A0DAD" if is_light else "#a78bfa"
            bar_border = "#bdc3c7" if is_light else "#5D2E8C"
            progress_bg = "#F3E8FF" if is_light else "#1e293b"
            progress_chunk = "#6A0DAD" if is_light else "#FFD700"
            self._status_bar.setStyleSheet(
                f"QStatusBar{{background:{bar_bg};color:{bar_fg};font-size:11px;"
                f"border-top:1px solid {bar_border};padding-left:8px;}}QStatusBar::item{{border:none;}}"
            )
            self._status_left_lbl.setStyleSheet(f"color:{bar_fg};font-size:11px;background:transparent;")
            self._status_log_lbl.setStyleSheet(f"color:{bar_fg};font-size:11px;background:transparent;")
            self._status_progress_lbl.setStyleSheet(f"color:{bar_fg};font-size:11px;background:transparent;")
            self._status_progress.setStyleSheet(
                f"QProgressBar{{border-radius:3px;background:{progress_bg};color:{bar_fg};text-align:center;}}"
                f"QProgressBar::chunk{{background:{progress_chunk};border-radius:3px;}}"
            )

    def _send_flow_to_analyzer(self, flow: Dict[str, Any]) -> None:
        if not hasattr(self, "analyzer_page"):
            return
        self.analyzer_page.load_flow(flow)
        self.page_container.setCurrentIndex(2)
        self.tab_bar.setCurrentIndex(2)
        self._log_project_action("Send flow", "Intercepter", "Analyzer", "Flow sent from Intercepter to Analyzer")

    def _send_flow_to_payloader(self, flow: Dict[str, Any]) -> None:
        if not hasattr(self, "payloader_page"):
            return
        self.payloader_page.load_flow(flow)
        self.page_container.setCurrentIndex(3)
        self.tab_bar.setCurrentIndex(3)
        self._log_project_action("Send flow", "Intercepter", "Payloader", "Flow sent from Intercepter to Payloader")

    def _start_scanner_from_extractor(self, apk_path: str, project_dir: str, jadx_dir: str, manifest_path: str, display_name: str) -> None:
        if not hasattr(self, "scanner_page"):
            return
        self.page_container.setCurrentIndex(4)
        self.tab_bar.setCurrentIndex(4)
        self.scanner_page.start_scan_from_extractor(apk_path, project_dir, jadx_dir, manifest_path, display_name)
        self._log_project_action("Start scan", "Extractor", display_name or os.path.basename(apk_path), "Scanner started from Extractor")

    def _on_tab_changed(self, index):
        self._sync_dashboard_current_target()
        tab_name = self.tab_bar.tabText(index) if hasattr(self, "tab_bar") else f"Tab {index}"
        self._log_project_action("Switch tab", tab_name, tab_name, "User navigated module")
        if index==0 and hasattr(self,"dashboard_page"):
            QTimer.singleShot(0, self.dashboard_page.sync_action_cards_size)
            QTimer.singleShot(120, self.dashboard_page.sync_action_cards_size)
    def _on_module_status_event(self, module_name, status, app_name):
        app = (app_name or "").strip()
        detail = f"status={status}" + (f", app={app}" if app else "")
        self._log_project_action("Module status", module_name, app or module_name, detail)
    def _on_scan_completed_event(self, scan_result_dict):
        findings = int((scan_result_dict or {}).get("findings", 0))
        risk = (scan_result_dict or {}).get("ai_risk", "N/A")
        confidence = float((scan_result_dict or {}).get("ai_confidence", 0.0) or 0.0)
        self._log_project_action("Scan completed", "Scanner", "APK Analysis", f"findings={findings}, ai_risk={risk}, confidence={confidence:.4f}")
    def _log_project_action(self, action: str, module: str = "", target: str = "", details: str = "") -> None:
        if not self.project_session:
            return
        event = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "action": str(action or ""),
            "module": str(module or ""),
            "target": str(target or ""),
            "details": str(details or ""),
        }
        self._project_activity_log.append(event)
        if len(self._project_activity_log) > 2000:
            self._project_activity_log = self._project_activity_log[-2000:]
        self._persist_project_session_state()
    def _collect_project_session_state(self) -> Dict[str, Any]:
        dashboard = getattr(self, "dashboard_page", None)
        return {
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "theme": self.current_theme,
            "active_tab": int(self.tab_bar.currentIndex()) if hasattr(self, "tab_bar") else 0,
            "modules_used": sorted(list(getattr(dashboard, "modules_used", set()))),
            "applications_analyzed": sorted(list(getattr(dashboard, "analyzed_apps", set()))),
            "files_analyzed": sorted(list(getattr(dashboard, "analyzed_files", set()))),
            "severity_counts": dict(getattr(dashboard, "severity_counts", {})),
            "current_module": getattr(dashboard, "current_module", "N/A"),
            "current_target": getattr(dashboard, "current_app_name", "N/A"),
            "activity_log": self._project_activity_log[-2000:],
        }
    def _persist_project_session_state(self) -> None:
        if not self.project_session or not self.project_session.workspace_dir.exists():
            return
        state_file = self.project_session.workspace_dir / "session_state.json"
        state_file.write_text(json.dumps(self._collect_project_session_state(), indent=2), encoding="utf-8")
    def _restore_project_session_state(self) -> None:
        if not self.project_session or not self.project_session.workspace_dir.exists():
            return
        state_file = self.project_session.workspace_dir / "session_state.json"
        if not state_file.exists():
            return
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            return
        self.current_theme = state.get("theme", self.current_theme)
        if hasattr(self, "dashboard_page"):
            self.dashboard_page.modules_used = set(state.get("modules_used", []))
            self.dashboard_page.analyzed_apps = set(state.get("applications_analyzed", []))
            self.dashboard_page.analyzed_files = set(state.get("files_analyzed", []))
            self.dashboard_page.severity_counts = state.get("severity_counts", self.dashboard_page.severity_counts)
            self.dashboard_page.current_module = state.get("current_module", self.dashboard_page.current_module)
            self.dashboard_page.current_app_name = state.get("current_target", self.dashboard_page.current_app_name)
            self.dashboard_page.refresh_projects_view()
            self.dashboard_page._refresh_dashboard_counters()
            self.dashboard_page.refresh_current_project_label()
        self._project_activity_log = list(state.get("activity_log", []))
        active_tab = int(state.get("active_tab", 0))
        self.apply_theme(self.current_theme)
        if hasattr(self, "tab_bar") and 0 <= active_tab < self.tab_bar.count():
            self.tab_bar.setCurrentIndex(active_tab)
            if hasattr(self, "page_container"):
                self.page_container.setCurrentIndex(active_tab)
    def _autosave_project_session(self) -> None:
        self._persist_project_session_state()
        if not self.project_manager or not self.project_session:
            return
        if self.project_session.metadata.temporary:
            return
        try:
            self.project_manager.save_active_project()
        except Exception:
            pass
    def closeEvent(self, event):
        self._autosave_project_session()
        if self.project_manager and self.project_session and not self.project_session.metadata.temporary:
            try:
                self.project_manager.close_active_project(persist=True)
            except Exception:
                pass
        super().closeEvent(event)
    def showEvent(self, event):
        super().showEvent(event)
        if hasattr(self,"dashboard_page"):
            QTimer.singleShot(0, self.dashboard_page.sync_action_cards_size)
            QTimer.singleShot(120, self.dashboard_page.sync_action_cards_size)
    def _sync_dashboard_current_target(self):
        if not hasattr(self,"dashboard_page"):
            return
        target = self._infer_current_target()
        module = self._infer_module_in_use()
        if target:
            self.dashboard_page.set_current_target(target)
        elif getattr(self.dashboard_page, "current_app_name", ""):
            self.dashboard_page.set_current_target(self.dashboard_page.current_app_name)
        if module:
            self.dashboard_page.set_module_in_use(module)
        elif getattr(self.dashboard_page, "current_module", ""):
            self.dashboard_page.set_module_in_use(self.dashboard_page.current_module)
    def _infer_current_target(self):
        idx = self.tab_bar.currentIndex()
        if 0 <= idx < self.page_container.count():
            page = self.page_container.widget(idx)
            if hasattr(page, "_apk_path"):
                apk_path = (getattr(page, "_apk_path", "") or "").strip()
                if apk_path:
                    return os.path.basename(apk_path)
            if hasattr(page, "target_input"):
                text = page.target_input.text().strip()
                if text:
                    return text
            if hasattr(page, "file_name_label"):
                text = page.file_name_label.text().strip()
                if text and text != "No file opened":
                    return text
        if hasattr(self, "dashboard_page"):
            return getattr(self.dashboard_page, "current_app_name", "") or ""
        return ""
    def _infer_module_in_use(self):
        idx = self.tab_bar.currentIndex()
        module_map = {1:"Intercepter",2:"Analyzer",3:"Payloader",4:"Scanner",5:"Extractor",6:"Encoder/Decoder"}
        module = module_map.get(idx, "")
        if module:
            return module
        if hasattr(self, "dashboard_page"):
            return getattr(self.dashboard_page, "current_module", "") or ""
        return ""

# ------------------------------------------------------------------------------
# main()
# ------------------------------------------------------------------------------
def main():
    configure_windows_taskbar_icon()
    app = QApplication(sys.argv)
    app_icon_path = ICONS_DIR / "mobhound1.png"
    if app_icon_path.exists():
        app.setWindowIcon(QIcon(str(app_icon_path)))
    fams = QFontDatabase.families()
    app.setFont(QFont("Poppins" if "Poppins" in fams else "Segoe UI", 10))

    loading_screen = LoadingScreen()
    loading_screen.show()
    loading_screen.start_loading()
    _s = {}

    def _launch():
        project_manager = ProjectManager(Path.home() / ".mobhound_workspace")
        _s["pm"] = project_manager
        project_dialog = ProjectWorkspaceDialog(project_manager)
        _s["dlg"] = project_dialog
        if project_dialog.exec() != QDialog.Accepted or not project_dialog.result_session:
            app.quit(); return
        window = MainWindow(project_manager=project_manager, project_session=project_dialog.result_session)
        _s["w"] = window
        window.showMaximized()

    loading_screen.finished.connect(_launch)
    sys.exit(app.exec())

if __name__ == "__main__":
    main()


